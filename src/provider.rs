//! The provider that implements certval's hashing and verification interfaces against AWS-LC.

use crate::algorithm::{choose, hash, Choice};
use aws_lc_rs::signature::ParsedPublicKey;
use certval::{
    CalculateHash, PathValidationStatus, PkiEnvironment, VerifySignatureDigest,
    VerifySignatureMessage,
};
use der::asn1::BitString;
use log::debug;
use spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};

/// A [`certval`] crypto provider backed by AWS-LC.
///
/// The value holds no state: each verification parses the issuer's key, verifies, and drops the
/// key. Parsing a public key is an in-process call with no session behind it, so there is no round
/// trip for a cache to save. The same value can be registered in every role:
///
/// ```no_run
/// # use certval::PkiEnvironment;
/// # use certval_awslc::AwsLcCrypto;
/// # let mut pe = PkiEnvironment::default();
/// pe.add_calculate_hash_callback(AwsLcCrypto::new());
/// pe.add_verify_signature_message_callback(AwsLcCrypto::new());
/// pe.add_verify_signature_digest_callback(AwsLcCrypto::new());
/// ```
#[derive(Clone, Copy, Debug, Default)]
pub struct AwsLcCrypto {
    _private: (),
}

/// Parses the key a choice names. A key aws-lc-rs refuses is a refusal to judge, not a verdict, and
/// keeping the parse apart from the verification is what lets the two be told apart: aws-lc-rs
/// reports a bad signature and an unusable key with the same error.
fn parse(choice: &Choice<'_>) -> Option<ParsedPublicKey> {
    match ParsedPublicKey::new(choice.algorithm, choice.key) {
        Ok(key) => Some(key),
        Err(e) => {
            debug!("AWS-LC declined a public key: {e}");
            None
        }
    }
}

/// The verdict certval expects once a parsed key has judged a signature.
fn verdict(result: Result<(), aws_lc_rs::error::Unspecified>) -> certval::Result<()> {
    result.map_err(|_| {
        certval::Error::PathValidation(PathValidationStatus::SignatureVerificationFailure)
    })
}

impl AwsLcCrypto {
    /// Returns a provider.
    pub fn new() -> Self {
        AwsLcCrypto { _private: () }
    }

    /// Reports whether AWS-LC is running in FIPS mode, which is possible only in a build with the
    /// `fips` feature.
    ///
    /// The provider behaves the same either way, apart from the digest interface, which a `fips`
    /// build does not implement; this is for a caller whose deployment requires FIPS mode and wants
    /// to confirm it before relying on the provider.
    pub fn fips_mode_enabled() -> bool {
        aws_lc_rs::try_fips_mode().is_ok()
    }
}

impl CalculateHash for AwsLcCrypto {
    fn calculate_hash(
        &self,
        _pe: &PkiEnvironment,
        hash_alg: &AlgorithmIdentifierOwned,
        buffer_to_hash: &[u8],
    ) -> certval::Result<Vec<u8>> {
        let Some(algorithm) = hash(&hash_alg.oid) else {
            return Err(certval::Error::Unrecognized);
        };
        Ok(aws_lc_rs::digest::digest(algorithm, buffer_to_hash)
            .as_ref()
            .to_vec())
    }
}

impl VerifySignatureMessage for AwsLcCrypto {
    fn verify_signature_message(
        &self,
        _pe: &PkiEnvironment,
        message_to_verify: &[u8],
        signature: &BitString,
        signature_alg: &AlgorithmIdentifierOwned,
        spki: &SubjectPublicKeyInfoOwned,
    ) -> certval::Result<()> {
        let Some(choice) = choose(signature_alg, spki) else {
            return Err(certval::Error::Unrecognized);
        };
        let signature = signature.as_bytes().ok_or(certval::Error::ParseError)?;
        let Some(key) = parse(&choice) else {
            return Err(certval::Error::Unrecognized);
        };
        verdict(key.verify_sig(message_to_verify, signature))
    }
}

impl VerifySignatureDigest for AwsLcCrypto {
    /// Verifies a signature over a precomputed digest. Not implemented in a `fips` build, where
    /// aws-lc-rs documents it as not allowed, so every call is declined there.
    fn verify_signature_digest(
        &self,
        _pe: &PkiEnvironment,
        hash_to_verify: &[u8],
        signature: &BitString,
        signature_alg: &AlgorithmIdentifierOwned,
        spki: &SubjectPublicKeyInfoOwned,
    ) -> certval::Result<()> {
        #[cfg(feature = "fips")]
        {
            let _ = (hash_to_verify, signature, signature_alg, spki);
            Err(certval::Error::Unrecognized)
        }

        #[cfg(not(feature = "fips"))]
        {
            let Some(choice) = choose(signature_alg, spki) else {
                return Err(certval::Error::Unrecognized);
            };
            let Some(algorithm) = choice.digest else {
                return Err(certval::Error::Unrecognized);
            };
            let Ok(digest) = aws_lc_rs::digest::Digest::import_less_safe(hash_to_verify, algorithm)
            else {
                // A digest of the wrong length for the algorithm.
                return Err(certval::Error::Unrecognized);
            };
            let signature = signature.as_bytes().ok_or(certval::Error::ParseError)?;
            let Some(key) = parse(&choice) else {
                return Err(certval::Error::Unrecognized);
            };
            verdict(key.verify_digest_sig(&digest, signature))
        }
    }
}
