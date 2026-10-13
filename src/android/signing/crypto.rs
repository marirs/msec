//! Signature algorithms of APK Signature Schemes v2/v3 and JAR signing, and verification of a
//! signature with a `SubjectPublicKeyInfo` public key. Verification only: msec never holds
//! private keys.

use sha2::{Digest, Sha256, Sha384, Sha512};
use signature::{DigestVerifier, Verifier};
use spki::{DecodePublicKey, SubjectPublicKeyInfoRef};

/// A signature algorithm, by its APK Signature Scheme ID (`apksig` `SignatureAlgorithm`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SignatureAlgorithm {
    /// 0x0101: RSASSA-PSS with SHA-256, MGF1 SHA-256, 32-byte salt.
    RsaPssSha256,
    /// 0x0102: RSASSA-PSS with SHA-512, MGF1 SHA-512, 64-byte salt.
    RsaPssSha512,
    /// 0x0103: RSASSA-PKCS1-v1_5 with SHA-256.
    RsaPkcs1Sha256,
    /// 0x0104: RSASSA-PKCS1-v1_5 with SHA-512.
    RsaPkcs1Sha512,
    /// 0x0201: ECDSA with SHA-256.
    EcdsaSha256,
    /// 0x0202: ECDSA with SHA-512.
    EcdsaSha512,
    /// 0x0301: DSA with SHA-256.
    DsaSha256,
    /// 0x0421: RSASSA-PKCS1-v1_5 with SHA-256, over a verity (Merkle tree) content digest.
    VerityRsaPkcs1Sha256,
    /// 0x0423: ECDSA with SHA-256, over a verity content digest.
    VerityEcdsaSha256,
    /// 0x0425: DSA with SHA-256, over a verity content digest.
    VerityDsaSha256,
}

/// How the APK content digest is computed for an algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ContentDigest {
    /// SHA-256 over 1 MiB chunks.
    ChunkedSha256,
    /// SHA-512 over 1 MiB chunks.
    ChunkedSha512,
    /// SHA-256 Merkle tree over 4 KiB pages (fs-verity).
    VeritySha256,
}

/// The hash used to sign.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Hash {
    /// SHA-1 (JAR signing only).
    Sha1,
    /// SHA-256.
    Sha256,
    /// SHA-384 (JAR signing only).
    Sha384,
    /// SHA-512.
    Sha512,
}

/// The signature primitive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Primitive {
    /// RSASSA-PSS.
    RsaPss,
    /// RSASSA-PKCS1-v1_5.
    RsaPkcs1,
    /// ECDSA.
    Ecdsa,
    /// DSA.
    Dsa,
}

impl SignatureAlgorithm {
    /// The algorithm for a scheme ID.
    pub fn from_id(id: u32) -> Option<Self> {
        Some(match id {
            0x0101 => Self::RsaPssSha256,
            0x0102 => Self::RsaPssSha512,
            0x0103 => Self::RsaPkcs1Sha256,
            0x0104 => Self::RsaPkcs1Sha512,
            0x0201 => Self::EcdsaSha256,
            0x0202 => Self::EcdsaSha512,
            0x0301 => Self::DsaSha256,
            0x0421 => Self::VerityRsaPkcs1Sha256,
            0x0423 => Self::VerityEcdsaSha256,
            0x0425 => Self::VerityDsaSha256,
            _ => return None,
        })
    }

    /// Human-readable name (`RSASSA-PSS with SHA-256`).
    pub fn name(self) -> &'static str {
        match self {
            Self::RsaPssSha256 => "RSASSA-PSS with SHA-256",
            Self::RsaPssSha512 => "RSASSA-PSS with SHA-512",
            Self::RsaPkcs1Sha256 => "RSASSA-PKCS1-v1_5 with SHA-256",
            Self::RsaPkcs1Sha512 => "RSASSA-PKCS1-v1_5 with SHA-512",
            Self::EcdsaSha256 => "ECDSA with SHA-256",
            Self::EcdsaSha512 => "ECDSA with SHA-512",
            Self::DsaSha256 => "DSA with SHA-256",
            Self::VerityRsaPkcs1Sha256 => "RSASSA-PKCS1-v1_5 with SHA-256 (verity)",
            Self::VerityEcdsaSha256 => "ECDSA with SHA-256 (verity)",
            Self::VerityDsaSha256 => "DSA with SHA-256 (verity)",
        }
    }

    /// How the content digest is computed.
    pub fn content_digest(self) -> ContentDigest {
        match self {
            Self::RsaPssSha512 | Self::RsaPkcs1Sha512 | Self::EcdsaSha512 => {
                ContentDigest::ChunkedSha512
            }
            Self::VerityRsaPkcs1Sha256 | Self::VerityEcdsaSha256 | Self::VerityDsaSha256 => {
                ContentDigest::VeritySha256
            }
            _ => ContentDigest::ChunkedSha256,
        }
    }

    /// Primitive and hash of the signature over the signed data.
    pub fn parts(self) -> (Primitive, Hash) {
        match self {
            Self::RsaPssSha256 => (Primitive::RsaPss, Hash::Sha256),
            Self::RsaPssSha512 => (Primitive::RsaPss, Hash::Sha512),
            Self::RsaPkcs1Sha256 | Self::VerityRsaPkcs1Sha256 => {
                (Primitive::RsaPkcs1, Hash::Sha256)
            }
            Self::RsaPkcs1Sha512 => (Primitive::RsaPkcs1, Hash::Sha512),
            Self::EcdsaSha256 | Self::VerityEcdsaSha256 => (Primitive::Ecdsa, Hash::Sha256),
            Self::EcdsaSha512 => (Primitive::Ecdsa, Hash::Sha512),
            Self::DsaSha256 | Self::VerityDsaSha256 => (Primitive::Dsa, Hash::Sha256),
        }
    }
}

/// Why a signature did not verify.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VerifyError {
    /// The public key cannot be decoded, or does not fit the primitive.
    UnsupportedKey,
    /// The signature is malformed or does not match.
    Invalid,
}

/// Verifies `signature` over `message` with a DER `SubjectPublicKeyInfo`.
pub fn verify(
    primitive: Primitive,
    hash: Hash,
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), VerifyError> {
    match primitive {
        Primitive::RsaPkcs1 => verify_rsa_pkcs1(hash, public_key, message, signature),
        Primitive::RsaPss => verify_rsa_pss(hash, public_key, message, signature),
        Primitive::Ecdsa => verify_ecdsa(hash, public_key, message, signature),
        Primitive::Dsa => verify_dsa(hash, public_key, message, signature),
    }
}

fn rsa_key(public_key: &[u8]) -> Result<rsa::RsaPublicKey, VerifyError> {
    rsa::RsaPublicKey::from_public_key_der(public_key).map_err(|_| VerifyError::UnsupportedKey)
}

fn verify_rsa_pkcs1(
    hash: Hash,
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), VerifyError> {
    use rsa::pkcs1v15::{Signature, VerifyingKey};
    let key = rsa_key(public_key)?;
    let signature = Signature::try_from(signature).map_err(|_| VerifyError::Invalid)?;
    let result = match hash {
        Hash::Sha1 => VerifyingKey::<sha1::Sha1>::new(key).verify(message, &signature),
        Hash::Sha256 => VerifyingKey::<Sha256>::new(key).verify(message, &signature),
        Hash::Sha384 => VerifyingKey::<Sha384>::new(key).verify(message, &signature),
        Hash::Sha512 => VerifyingKey::<Sha512>::new(key).verify(message, &signature),
    };
    result.map_err(|_| VerifyError::Invalid)
}

/// Android uses a salt as long as the digest, and MGF1 with the same digest.
fn verify_rsa_pss(
    hash: Hash,
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), VerifyError> {
    use rsa::pss::{Signature, VerifyingKey};
    let key = rsa_key(public_key)?;
    let signature = Signature::try_from(signature).map_err(|_| VerifyError::Invalid)?;
    let result = match hash {
        Hash::Sha256 => {
            VerifyingKey::<Sha256>::new_with_salt_len(key, 32).verify(message, &signature)
        }
        Hash::Sha512 => {
            VerifyingKey::<Sha512>::new_with_salt_len(key, 64).verify(message, &signature)
        }
        Hash::Sha1 | Hash::Sha384 => return Err(VerifyError::UnsupportedKey),
    };
    result.map_err(|_| VerifyError::Invalid)
}

/// Feeds `message` to a digest verifier.
fn digest_message<D: signature::digest::Update>(
    message: &[u8],
) -> impl Fn(&mut D) -> signature::Result<()> + '_ {
    move |digest| {
        digest.update(message);
        Ok(())
    }
}

macro_rules! verify_ecdsa_on {
    ($curve:ty, $hash:expr, $public_key:expr, $message:expr, $signature:expr) => {{
        let key = ecdsa::VerifyingKey::<$curve>::from_public_key_der($public_key)
            .map_err(|_| VerifyError::UnsupportedKey)?;
        let signature = ecdsa::der::Signature::<$curve>::from_bytes($signature)
            .map_err(|_| VerifyError::Invalid)?;
        let result = match $hash {
            Hash::Sha1 => key.verify_digest(digest_message::<sha1::Sha1>($message), &signature),
            Hash::Sha256 => key.verify_digest(digest_message::<Sha256>($message), &signature),
            Hash::Sha384 => key.verify_digest(digest_message::<Sha384>($message), &signature),
            Hash::Sha512 => key.verify_digest(digest_message::<Sha512>($message), &signature),
        };
        result.map_err(|_| VerifyError::Invalid)
    }};
}

fn verify_ecdsa(
    hash: Hash,
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), VerifyError> {
    match ec_curve(public_key) {
        Some(EcCurve::P256) => {
            verify_ecdsa_on!(p256::NistP256, hash, public_key, message, signature)
        }
        Some(EcCurve::P384) => {
            verify_ecdsa_on!(p384::NistP384, hash, public_key, message, signature)
        }
        Some(EcCurve::P521) => {
            verify_ecdsa_on!(p521::NistP521, hash, public_key, message, signature)
        }
        None => Err(VerifyError::UnsupportedKey),
    }
}

fn verify_dsa(
    hash: Hash,
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), VerifyError> {
    let info =
        SubjectPublicKeyInfoRef::try_from(public_key).map_err(|_| VerifyError::UnsupportedKey)?;
    let key = dsa::VerifyingKey::try_from(info).map_err(|_| VerifyError::UnsupportedKey)?;
    let signature = dsa::Signature::try_from(signature).map_err(|_| VerifyError::Invalid)?;
    let result = match hash {
        Hash::Sha1 => key.verify_digest(digest_message::<sha1::Sha1>(message), &signature),
        Hash::Sha256 => key.verify_digest(digest_message::<Sha256>(message), &signature),
        Hash::Sha384 => key.verify_digest(digest_message::<Sha384>(message), &signature),
        Hash::Sha512 => key.verify_digest(digest_message::<Sha512>(message), &signature),
    };
    result.map_err(|_| VerifyError::Invalid)
}

/// Named curves Android accepts for ECDSA.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EcCurve {
    /// NIST P-256 (secp256r1).
    P256,
    /// NIST P-384 (secp384r1).
    P384,
    /// NIST P-521 (secp521r1).
    P521,
}

const OID_EC_PUBLIC_KEY: &str = "1.2.840.10045.2.1";
const OID_P256: &str = "1.2.840.10045.3.1.7";
const OID_P384: &str = "1.3.132.0.34";
const OID_P521: &str = "1.3.132.0.35";

/// The named curve of an EC `SubjectPublicKeyInfo`.
pub fn ec_curve(public_key: &[u8]) -> Option<EcCurve> {
    let info = SubjectPublicKeyInfoRef::try_from(public_key).ok()?;
    if info.algorithm.oid.to_string() != OID_EC_PUBLIC_KEY {
        return None;
    }
    let curve = info
        .algorithm
        .parameters?
        .decode_as::<der::asn1::ObjectIdentifier>()
        .ok()?
        .to_string();
    match curve.as_str() {
        OID_P256 => Some(EcCurve::P256),
        OID_P384 => Some(EcCurve::P384),
        OID_P521 => Some(EcCurve::P521),
        _ => None,
    }
}

/// Hashes `data` with `hash`.
pub fn digest(hash: Hash, data: &[u8]) -> Vec<u8> {
    match hash {
        Hash::Sha1 => sha1::Sha1::digest(data).to_vec(),
        Hash::Sha256 => Sha256::digest(data).to_vec(),
        Hash::Sha384 => Sha384::digest(data).to_vec(),
        Hash::Sha512 => Sha512::digest(data).to_vec(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn algorithm_ids_round_trip_their_parts() {
        for id in [
            0x0101, 0x0102, 0x0103, 0x0104, 0x0201, 0x0202, 0x0301, 0x0421, 0x0423, 0x0425,
        ] {
            assert!(SignatureAlgorithm::from_id(id).is_some(), "0x{id:04x}");
        }
        assert_eq!(SignatureAlgorithm::from_id(0x0999), None);
        assert_eq!(
            SignatureAlgorithm::RsaPssSha512.content_digest(),
            ContentDigest::ChunkedSha512
        );
        assert_eq!(
            SignatureAlgorithm::VerityEcdsaSha256.parts(),
            (Primitive::Ecdsa, Hash::Sha256)
        );
    }

    #[test]
    fn garbage_keys_and_signatures_never_verify() {
        for primitive in [
            Primitive::RsaPkcs1,
            Primitive::RsaPss,
            Primitive::Ecdsa,
            Primitive::Dsa,
        ] {
            assert!(
                verify(
                    primitive,
                    Hash::Sha256,
                    b"not a key",
                    b"message",
                    b"signature"
                )
                .is_err()
            );
        }
    }
}
