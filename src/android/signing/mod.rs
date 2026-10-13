//! APK signing: APK Signature Scheme v2, v3 and v3.1 blocks, JAR (v1) signatures, signer
//! certificates, and full verification.
//!
//! MobSF reports which schemes are present (through `apksigner` when Java is installed) and
//! the certificate; it does not verify signatures itself. msec verifies every scheme it finds:
//! signatures over the signed data, content digests over the file, JAR manifest and entry
//! digests. APK Signature Scheme v4 lives in a separate `.idsig` file next to the APK and is out
//! of scope for a single package.

pub mod block;
pub mod certificate;
pub mod crypto;
pub mod digest;
pub mod jar;
pub mod scheme;

use std::io::{Read, Seek};

use block::{BlockKind, BlockProblem};
use certificate::CertificateInfo;
use digest::{ContentDigests, DigestProblem, content_digests};
use jar::{JarSignature, verify_jar};
use scheme::{Scheme, SchemeReport, verify_scheme};

use crate::archive::{MAX_RAW_READ, ZipArchive};

/// Everything about how an APK is signed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SigningReport {
    /// JAR signature; `None` when there is no `META-INF/*.SF`.
    pub v1: Option<JarSignature>,
    /// v2 block; `None` when absent.
    pub v2: Option<SchemeReport>,
    /// v3 block.
    pub v3: Option<SchemeReport>,
    /// v3.1 block.
    pub v31: Option<SchemeReport>,
    /// Other entries of the APK Signing Block (source stamp, Play frosting, ...).
    pub other_blocks: Vec<BlockKind>,
    /// The APK Signing Block could not be read.
    pub block_problem: Option<BlockProblem>,
}

impl SigningReport {
    /// Reads and verifies every signature of an APK.
    pub fn read<R: Read + Seek>(archive: &mut ZipArchive<R>) -> Self {
        let v1 = verify_jar(archive);
        let mut report = Self {
            v1,
            v2: None,
            v3: None,
            v31: None,
            other_blocks: Vec::new(),
            block_problem: None,
        };
        let entries = match read_signing_block(archive) {
            Some(Ok(entries)) => entries,
            Some(Err(problem)) => {
                report.block_problem = Some(problem);
                return report;
            }
            None => return report,
        };
        let schemes: Vec<(Scheme, &[u8])> = entries
            .iter()
            .filter_map(|entry| match BlockKind::from_id(entry.id) {
                BlockKind::SchemeV2 => Some((Scheme::V2, entry.value.as_slice())),
                BlockKind::SchemeV3 => Some((Scheme::V3, entry.value.as_slice())),
                BlockKind::SchemeV31 => Some((Scheme::V31, entry.value.as_slice())),
                _ => None,
            })
            .collect();
        let digests = compute_digests(archive, &schemes);
        for (scheme, value) in schemes {
            let verified = Some(verify_scheme(value, scheme, &digests));
            match scheme {
                Scheme::V2 => report.v2 = verified,
                Scheme::V3 => report.v3 = verified,
                Scheme::V31 => report.v31 = verified,
            }
        }
        report.other_blocks = entries
            .iter()
            .map(|entry| BlockKind::from_id(entry.id))
            .filter(|kind| {
                !matches!(
                    kind,
                    BlockKind::SchemeV2 | BlockKind::SchemeV3 | BlockKind::SchemeV31
                )
            })
            .collect();
        report
    }

    /// Any signature at all.
    pub fn is_signed(&self) -> bool {
        self.v1.is_some() || self.v2.is_some() || self.v3.is_some() || self.v31.is_some()
    }

    /// Scheme blocks present, in order.
    pub fn schemes(&self) -> impl Iterator<Item = &SchemeReport> {
        [&self.v2, &self.v3, &self.v31].into_iter().flatten()
    }

    /// Every present signature verifies, and there is at least one.
    pub fn verified(&self) -> bool {
        self.is_signed()
            && self.block_problem.is_none()
            && self.v1.as_ref().is_none_or(JarSignature::verified)
            && self.schemes().all(SchemeReport::verified)
    }

    /// Signer certificates across all schemes, without duplicates, strongest scheme first.
    pub fn certificates(&self) -> Vec<&CertificateInfo> {
        let from_schemes = [&self.v31, &self.v3, &self.v2]
            .into_iter()
            .flatten()
            .flat_map(|scheme| &scheme.signers)
            .filter_map(|signer| signer.certificates.first());
        let from_jar = self
            .v1
            .iter()
            .flat_map(|jar| &jar.signers)
            .filter_map(|signer| signer.certificates.first());
        let mut unique: Vec<&CertificateInfo> = Vec::new();
        for certificate in from_schemes.chain(from_jar) {
            if !unique.iter().any(|seen| seen.sha256 == certificate.sha256) {
                unique.push(certificate);
            }
        }
        unique
    }

    /// The v2 signature says a v3 signature exists, but there is none: it was stripped.
    pub fn v3_stripped(&self) -> bool {
        let declared = self
            .v2
            .iter()
            .flat_map(|v2| &v2.signers)
            .any(|signer| signer.declares_v3);
        declared && self.v3.is_none() && self.v31.is_none()
    }

    /// Which signature each Android release range checks, for an app installable from
    /// `min_sdk` and targeting `target_sdk`, and whether Android accepts it there. Android below
    /// 7.0 checks v1; 7.0–8.1 check v2, else v1; 9–12L check v3, else v2, else v1; 13+ check
    /// v3.1, else the same chain. A present but broken signature is not skipped: Android rejects
    /// the APK rather than fall back. Stripped stronger signatures (declared by the weaker one,
    /// then missing) are rejected, and Android 11+ rejects v1-only APKs targeting API 30+.
    pub fn platform_verdicts(&self, min_sdk: u32, target_sdk: u32) -> Vec<PlatformVerdict> {
        use SchemeUsed::{V1, V2, V3, V31};
        let ranges: [(u32, Option<u32>, &[SchemeUsed]); 5] = [
            (1, Some(23), &[V1]),
            (24, Some(27), &[V2, V1]),
            (28, Some(29), &[V3, V2, V1]),
            (30, Some(32), &[V3, V2, V1]),
            (33, None, &[V31, V3, V2, V1]),
        ];
        ranges
            .into_iter()
            .filter(|(_, to, _)| to.is_none_or(|to| to >= min_sdk))
            .map(|(from, to, order)| {
                let scheme = order.iter().copied().find(|scheme| self.has(*scheme));
                let rejection = match scheme {
                    None => Some(Rejection::NoSignature),
                    Some(scheme) if !self.scheme_verified(scheme) => Some(Rejection::DoesNotVerify),
                    Some(scheme) if self.stripped_for(scheme, from) => Some(Rejection::Stripped),
                    Some(SchemeUsed::V1)
                        if from >= V2_REQUIRED_FOR_TARGET
                            && target_sdk >= V2_REQUIRED_FOR_TARGET =>
                    {
                        Some(Rejection::V1NotEnoughForTarget)
                    }
                    Some(_) => None,
                };
                PlatformVerdict {
                    from_api: from.max(min_sdk),
                    to_api: to,
                    scheme,
                    rejection,
                }
            })
            .collect()
    }

    /// Android 7.0+ rejects v1 when the `.SF` declares v2/v3 that are missing; Android 9+
    /// rejects v2 when it declares a v3 signature that is missing (stripping protection).
    fn stripped_for(&self, scheme: SchemeUsed, from_api: u32) -> bool {
        match scheme {
            SchemeUsed::V1 => from_api >= 24 && self.schemes_stripped_from_v1(),
            SchemeUsed::V2 => from_api >= 28 && self.v3_stripped(),
            SchemeUsed::V3 | SchemeUsed::V31 => false,
        }
    }

    fn has(&self, scheme: SchemeUsed) -> bool {
        match scheme {
            SchemeUsed::V1 => self.v1.is_some(),
            SchemeUsed::V2 => self.v2.is_some(),
            SchemeUsed::V3 => self.v3.is_some(),
            SchemeUsed::V31 => self.v31.is_some(),
        }
    }

    fn scheme_verified(&self, scheme: SchemeUsed) -> bool {
        match scheme {
            SchemeUsed::V1 => self.v1.as_ref().is_some_and(JarSignature::verified),
            SchemeUsed::V2 => self.v2.as_ref().is_some_and(SchemeReport::verified),
            SchemeUsed::V3 => self.v3.as_ref().is_some_and(SchemeReport::verified),
            SchemeUsed::V31 => self.v31.as_ref().is_some_and(SchemeReport::verified),
        }
    }

    /// The v1 `.SF` says stronger schemes exist (`X-Android-APK-Signed`), but they are missing.
    pub fn schemes_stripped_from_v1(&self) -> bool {
        let declared: Vec<u32> = self
            .v1
            .iter()
            .flat_map(|jar| &jar.signers)
            .flat_map(|signer| signer.android_apk_signed.iter().copied())
            .collect();
        (declared.contains(&2) && self.v2.is_none()) || (declared.contains(&3) && self.v3.is_none())
    }
}

/// A scheme Android may check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SchemeUsed {
    /// JAR signing.
    V1,
    /// APK Signature Scheme v2.
    V2,
    /// APK Signature Scheme v3.
    V3,
    /// APK Signature Scheme v3.1.
    V31,
}

impl SchemeUsed {
    /// `v1`, `v2`, `v3`, `v3.1`.
    pub fn label(self) -> &'static str {
        match self {
            Self::V1 => "v1",
            Self::V2 => "v2",
            Self::V3 => "v3",
            Self::V31 => "v3.1",
        }
    }
}

/// Android 11: apps targeting it (API 30) need a v2 or later signature.
const V2_REQUIRED_FOR_TARGET: u32 = 30;

/// Why Android in a release range refuses the APK.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Rejection {
    /// No signature this range can check.
    NoSignature,
    /// The signature it checks does not verify.
    DoesNotVerify,
    /// The signature it checks declares a stronger one that is missing.
    Stripped,
    /// Only v1, and the app targets Android 11 or later.
    V1NotEnoughForTarget,
}

/// What one range of Android releases checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PlatformVerdict {
    /// First API level of the range (at least the app's minimum).
    pub from_api: u32,
    /// Last API level, `None` for "and later".
    pub to_api: Option<u32>,
    /// The scheme Android checks there; `None` when it has none to check.
    pub scheme: Option<SchemeUsed>,
    /// Why Android refuses the APK there; `None` when it accepts it.
    pub rejection: Option<Rejection>,
}

impl PlatformVerdict {
    /// Android in this range installs the APK.
    pub fn accepted(&self) -> bool {
        self.rejection.is_none()
    }
}

/// The signing block's entries; `None` when the APK has no signing block.
fn read_signing_block<R: Read + Seek>(
    archive: &mut ZipArchive<R>,
) -> Option<Result<Vec<block::BlockEntry>, BlockProblem>> {
    let range = archive.layout().apk_signing_block.clone()?;
    let length = range.end - range.start;
    if length > MAX_RAW_READ {
        return Some(Err(BlockProblem::InconsistentSize));
    }
    let bytes = archive.read_raw(range.start, length).ok()?;
    Some(block::parse(&bytes))
}

/// One pass over the file for every chunked digest any signer needs.
fn compute_digests<R: Read + Seek>(
    archive: &mut ZipArchive<R>,
    schemes: &[(Scheme, &[u8])],
) -> Result<ContentDigests, DigestProblem> {
    let (mut sha256, mut sha512) = (false, false);
    for (scheme, value) in schemes {
        let (needs_256, needs_512) = SchemeReport::needed_digests(value, *scheme);
        sha256 |= needs_256;
        sha512 |= needs_512;
    }
    content_digests(archive, sha256, sha512)
}
