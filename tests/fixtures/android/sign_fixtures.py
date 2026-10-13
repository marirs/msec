#!/usr/bin/env python3
"""Signs fixture APKs for msec's signing tests, independently of msec.

Python standard library for ZIP, JAR manifests, the APK Signing Block and content digests;
the system `openssl` command for keys, certificates and every signature. Nothing here shares
code with the verifier under test, so a bug cannot hide on both sides.

Usage: sign_fixtures.py <unsigned.apk> <output directory>
"""

from __future__ import annotations

import base64
import hashlib
import io
import struct
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

V2_BLOCK_ID = 0x7109871A
V3_BLOCK_ID = 0xF05368C0
PLAY_FROSTING_BLOCK_ID = 0x2146444E
DEPENDENCY_INFO_BLOCK_ID = 0x504B4453
STRIPPING_PROTECTION = 0xBEEFF00D
CHUNK = 1024 * 1024

RSA_PKCS1_SHA256, RSA_PKCS1_SHA512 = 0x0103, 0x0104
RSA_PSS_SHA256, RSA_PSS_SHA512 = 0x0101, 0x0102
ECDSA_SHA256, DSA_SHA256 = 0x0201, 0x0301


def openssl(*args: str, data: bytes | None = None) -> bytes:
    return subprocess.run(["openssl", *args], input=data, check=True, capture_output=True).stdout


class Key:
    """A key pair and self-signed certificate made by openssl."""

    def __init__(self, work: Path, name: str, kind: str, subject: str, cert_hash: str) -> None:
        self.path = work / f"{name}.key"
        if kind.startswith("rsa"):
            openssl("genrsa", "-out", str(self.path), kind[3:])
        elif kind == "ec":
            openssl("ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", str(self.path))
        elif kind == "dsa":
            openssl("dsaparam", "-genkey", "-out", str(self.path), "2048")
        self.cert_pem = work / f"{name}.pem"
        openssl("req", "-new", "-x509", "-key", str(self.path), "-subj", subject, "-days", "10950",
                f"-{cert_hash}", "-out", str(self.cert_pem))
        self.cert_der = openssl("x509", "-in", str(self.cert_pem), "-outform", "DER")
        self.public_der = openssl("pkey", "-in", str(self.path), "-pubout", "-outform", "DER")

    def sign(self, algorithm: int, data: bytes) -> bytes:
        options = {
            RSA_PKCS1_SHA256: ["-sha256"],
            RSA_PKCS1_SHA512: ["-sha512"],
            RSA_PSS_SHA256: ["-sha256", "-sigopt", "rsa_padding_mode:pss", "-sigopt", "rsa_pss_saltlen:32"],
            RSA_PSS_SHA512: ["-sha512", "-sigopt", "rsa_padding_mode:pss", "-sigopt", "rsa_pss_saltlen:64"],
            ECDSA_SHA256: ["-sha256"],
            DSA_SHA256: ["-sha256"],
        }[algorithm]
        with tempfile.NamedTemporaryFile() as message:
            message.write(data)
            message.flush()
            return openssl("dgst", *options, "-sign", str(self.path), message.name)

    def pkcs7(self, data: bytes, digest: str, signed_attributes: bool) -> bytes:
        with tempfile.NamedTemporaryFile() as message:
            message.write(data)
            message.flush()
            args = ["cms", "-sign", "-binary", "-outform", "DER", "-nosmimecap", "-in", message.name,
                    "-signer", str(self.cert_pem), "-inkey", str(self.path), "-md", digest]
            if not signed_attributes:
                args.append("-noattr")
            return openssl(*args)


# ---------------------------------------------------------------------------------------------
# v1 (JAR signing)
# ---------------------------------------------------------------------------------------------

def manifest_line(text: str) -> bytes:
    """JAR manifests wrap lines at 72 bytes, continuing with a leading space."""
    raw = text.encode()
    lines = [raw[:72]] + [b" " + raw[i:i + 71] for i in range(72, len(raw), 71)]
    return b"".join(line + b"\r\n" for line in lines)


def section(*lines: str) -> bytes:
    return b"".join(manifest_line(line) for line in lines) + b"\r\n"


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def sign_v1(apk: bytes, key: Key, hash_name: str, signed_attributes: bool, apk_signed: str | None,
            corrupt_entry: str | None = None) -> bytes:
    """Adds MANIFEST.MF, CERT.SF and the PKCS#7 block. `corrupt_entry` gets a wrong manifest
    digest (as if its content changed after signing)."""
    attribute = {"sha256": "SHA-256", "sha1": "SHA1"}[hash_name]
    digest = lambda data: hashlib.new(hash_name, data).digest()  # noqa: E731
    source = zipfile.ZipFile(io.BytesIO(apk))
    main = section("Manifest-Version: 1.0", "Created-By: msec fixtures")
    entry_sections = []
    for info in source.infolist():
        if info.is_dir():
            continue
        content = source.read(info)
        value = digest(content + b"x") if info.filename == corrupt_entry else digest(content)
        entry_sections.append((info.filename, section(f"Name: {info.filename}", f"{attribute}-Digest: {b64(value)}")))
    manifest = main + b"".join(part for _, part in entry_sections)
    sf_main = [
        "Signature-Version: 1.0",
        "Created-By: msec fixtures",
        f"{attribute}-Digest-Manifest: {b64(digest(manifest))}",
        f"{attribute}-Digest-Manifest-Main-Attributes: {b64(digest(main))}",
    ]
    if apk_signed:
        sf_main.append(f"X-Android-APK-Signed: {apk_signed}")
    sf = section(*sf_main) + b"".join(
        section(f"Name: {name}", f"{attribute}-Digest: {b64(digest(part))}") for name, part in entry_sections
    )
    block = key.pkcs7(sf, hash_name, signed_attributes)

    out = io.BytesIO()
    with zipfile.ZipFile(out, "w") as target:
        for info in source.infolist():
            target.writestr(info, source.read(info))
        for name, data in (("META-INF/MANIFEST.MF", manifest), ("META-INF/CERT.SF", sf), ("META-INF/CERT.RSA", block)):
            target.writestr(zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 0)), data, zipfile.ZIP_DEFLATED)
    return out.getvalue()


# ---------------------------------------------------------------------------------------------
# v2 / v3 (APK Signing Block)
# ---------------------------------------------------------------------------------------------

def prefixed(data: bytes) -> bytes:
    return struct.pack("<I", len(data)) + data


def sequence(items: list[bytes]) -> bytes:
    return prefixed(b"".join(prefixed(item) for item in items))


def zip_layout(apk: bytes) -> tuple[int, int, int]:
    """(central directory offset, size, end record offset); fixtures have no ZIP comment."""
    end = len(apk) - 22
    assert apk[end:end + 4] == b"PK\x05\x06"
    size, offset = struct.unpack_from("<II", apk, end + 12)
    return offset, size, end


def chunked_digest(apk: bytes, hash_name: str) -> bytes:
    offset, size, end = zip_layout(apk)
    end_record = bytearray(apk[end:])
    struct.pack_into("<I", end_record, 16, offset)
    chunks = []
    for part in (apk[:offset], apk[offset:offset + size], bytes(end_record)):
        for start in range(0, len(part), CHUNK):
            chunk = part[start:start + CHUNK]
            chunks.append(hashlib.new(hash_name, b"\xa5" + struct.pack("<I", len(chunk)) + chunk).digest())
    return hashlib.new(hash_name, b"\x5a" + struct.pack("<I", len(chunks)) + b"".join(chunks)).digest()


def scheme_block(apk: bytes, key: Key, algorithms: list[int], v3_range: tuple[int, int] | None,
                 attributes: list[bytes]) -> bytes:
    digests = []
    for algorithm in algorithms:
        hash_name = "sha512" if algorithm in (RSA_PKCS1_SHA512, RSA_PSS_SHA512) else "sha256"
        digests.append(struct.pack("<I", algorithm) + prefixed(chunked_digest(apk, hash_name)))
    signed_data = sequence(digests) + sequence([key.cert_der])
    if v3_range:
        signed_data += struct.pack("<II", *v3_range)
    signed_data += sequence(attributes)
    signatures = [struct.pack("<I", algorithm) + prefixed(key.sign(algorithm, signed_data)) for algorithm in algorithms]
    signer = prefixed(signed_data)
    if v3_range:
        signer += struct.pack("<II", *v3_range)
    signer += sequence(signatures) + prefixed(key.public_der)
    return sequence([signer])


def insert_signing_block(apk: bytes, entries: list[tuple[int, bytes]]) -> bytes:
    pairs = b"".join(struct.pack("<QI", len(value) + 4, block_id) + value for block_id, value in entries)
    size = len(pairs) + 24
    block = struct.pack("<Q", size) + pairs + struct.pack("<Q", size) + b"APK Sig Block 42"
    offset, _, end = zip_layout(apk)
    end_record = bytearray(apk[end:])
    struct.pack_into("<I", end_record, 16, offset + len(block))
    return apk[:offset] + block + apk[offset:end] + bytes(end_record)


# ---------------------------------------------------------------------------------------------

def main() -> None:
    unsigned = Path(sys.argv[1]).read_bytes()
    out = Path(sys.argv[2])
    with tempfile.TemporaryDirectory() as directory:
        work = Path(directory)
        debug = Key(work, "debug", "rsa2048", "/C=US/O=Android/CN=Android Debug", "sha256")
        release = Key(work, "release", "ec", "/C=DE/O=Example Corp/CN=Example Release", "sha256")
        legacy = Key(work, "legacy", "rsa1024", "/C=US/O=Legacy/CN=Legacy Signer", "sha1")
        big = Key(work, "big", "rsa4096", "/C=US/O=Example/CN=RSA 4096", "sha512")
        dsa = Key(work, "dsa", "dsa", "/C=US/O=Example/CN=DSA Signer", "sha256")

        # v1 (signed attributes) + v2 (PKCS#1 and PSS), debug certificate.
        v1 = sign_v1(unsigned, debug, "sha256", signed_attributes=True, apk_signed="2")
        v1v2 = insert_signing_block(v1, [(V2_BLOCK_ID, scheme_block(v1, debug, [RSA_PKCS1_SHA256, RSA_PSS_SHA256], None, []))])
        (out / "signed-v1v2-debug.apk").write_bytes(v1v2)

        # Same, with one central directory byte changed after signing ("version made by").
        tampered = bytearray(v1v2)
        offset, _, _ = zip_layout(v1v2)
        tampered[offset + 4] ^= 0x01
        (out / "signed-v1v2-tampered.apk").write_bytes(bytes(tampered))

        # v2 + v3 with ECDSA; v2 declares the v3 signature (stripping protection).
        stripping = [struct.pack("<II", STRIPPING_PROTECTION, 3)]
        v2 = scheme_block(unsigned, release, [ECDSA_SHA256], None, stripping)
        v3 = scheme_block(unsigned, release, [ECDSA_SHA256], (24, 0x7FFFFFFF), [])
        (out / "signed-v2v3-ec.apk").write_bytes(insert_signing_block(unsigned, [(V2_BLOCK_ID, v2), (V3_BLOCK_ID, v3)]))
        # The same without the v3 block: a stripped signature.
        (out / "signed-v3-stripped.apk").write_bytes(insert_signing_block(unsigned, [(V2_BLOCK_ID, v2)]))

        # v1 only, SHA-1, RSA 1024, SHA1withRSA certificate, no signed attributes.
        (out / "signed-v1-legacy.apk").write_bytes(
            sign_v1(unsigned, legacy, "sha1", signed_attributes=False, apk_signed=None)
        )
        # v1 only, with an entry whose content no longer matches its manifest digest.
        (out / "signed-v1-modified-entry.apk").write_bytes(
            sign_v1(unsigned, legacy, "sha1", signed_attributes=False, apk_signed=None, corrupt_entry="resources.arsc")
        )

        # v2 with SHA-512 (PKCS#1 and PSS) on RSA 4096, plus Play frosting and dependency info.
        v2_big = scheme_block(unsigned, big, [RSA_PKCS1_SHA512, RSA_PSS_SHA512], None, [])
        (out / "signed-v2-rsa4096.apk").write_bytes(insert_signing_block(unsigned, [
            (V2_BLOCK_ID, v2_big), (PLAY_FROSTING_BLOCK_ID, b"frosting"), (DEPENDENCY_INFO_BLOCK_ID, b"dependencies"),
        ]))

        # v2 with DSA.
        v2_dsa = scheme_block(unsigned, dsa, [DSA_SHA256], None, [])
        (out / "signed-v2-dsa.apk").write_bytes(insert_signing_block(unsigned, [(V2_BLOCK_ID, v2_dsa)]))


if __name__ == "__main__":
    main()
