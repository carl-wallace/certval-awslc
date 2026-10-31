//! Choosing the aws-lc-rs verification algorithm for a signature algorithm identifier and a key.
//!
//! aws-lc-rs names each verification algorithm by every parameter at once (RSA padding, hash and the
//! key sizes it accepts; ECDSA curve and hash), so the choice depends on the key as well as on the
//! signature algorithm. Everything aws-lc-rs would refuse is declined here, before it is asked:
//! aws-lc-rs reports every failure as the same `Unspecified` error, so a key it cannot use would
//! otherwise be indistinguishable from a signature that does not verify.

use aws_lc_rs::digest;
use aws_lc_rs::signature::{self, VerificationAlgorithm};
use certval::{
    PKIXALG_ECDSA_WITH_SHA224, PKIXALG_ECDSA_WITH_SHA256, PKIXALG_ECDSA_WITH_SHA384,
    PKIXALG_ECDSA_WITH_SHA512, PKIXALG_EC_PUBLIC_KEY, PKIXALG_MGF1, PKIXALG_RSASSA_PSS,
    PKIXALG_RSA_ENCRYPTION, PKIXALG_SECP256R1, PKIXALG_SECP384R1, PKIXALG_SECP521R1, PKIXALG_SHA1,
    PKIXALG_SHA224, PKIXALG_SHA256, PKIXALG_SHA256_WITH_RSA_ENCRYPTION, PKIXALG_SHA384,
    PKIXALG_SHA384_WITH_RSA_ENCRYPTION, PKIXALG_SHA512, PKIXALG_SHA512_WITH_RSA_ENCRYPTION,
};
use const_oid::db::fips204::{ID_ML_DSA_44, ID_ML_DSA_65, ID_ML_DSA_87};
use const_oid::ObjectIdentifier;
use der::{Decode, Encode};
use spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};

/// The RSA key sizes aws-lc-rs's 2048-8192 algorithms accept. A key outside the range is declined
/// rather than rejected, since aws-lc-rs would refuse it with the same error as a bad signature.
const RSA_BITS: std::ops::RangeInclusive<usize> = 2048..=8192;

/// What a verification needs: the algorithm, the key bytes in the form aws-lc-rs takes, and, for
/// the digest interface, the hash the signature is over.
pub(crate) struct Choice<'a> {
    pub(crate) algorithm: &'static dyn VerificationAlgorithm,
    pub(crate) key: &'a [u8],
    /// `None` for an algorithm with no digest form (ML-DSA signs the message itself).
    pub(crate) digest: Option<&'static digest::Algorithm>,
}

/// Returns the digest algorithm for a hash identifier.
pub(crate) fn hash(oid: &ObjectIdentifier) -> Option<&'static digest::Algorithm> {
    match *oid {
        PKIXALG_SHA1 => Some(&digest::SHA1_FOR_LEGACY_USE_ONLY),
        PKIXALG_SHA224 => Some(&digest::SHA224),
        PKIXALG_SHA256 => Some(&digest::SHA256),
        PKIXALG_SHA384 => Some(&digest::SHA384),
        PKIXALG_SHA512 => Some(&digest::SHA512),
        _ => None,
    }
}

/// Chooses how to verify a signature made with `alg` by the key in `spki`, or `None` to decline.
pub(crate) fn choose<'a>(
    alg: &AlgorithmIdentifierOwned,
    spki: &'a SubjectPublicKeyInfoOwned,
) -> Option<Choice<'a>> {
    let key = spki.subject_public_key.as_bytes()?;
    let choice = |algorithm: &'static dyn VerificationAlgorithm, digest| {
        Some(Choice {
            algorithm,
            key,
            digest,
        })
    };

    match alg.oid {
        // aws-lc-rs has no SHA-224 RSA verification algorithm, so sha224WithRSAEncryption is left
        // to software.
        PKIXALG_SHA256_WITH_RSA_ENCRYPTION => {
            rsa_key_usable(spki, false)?;
            choice(
                &signature::RSA_PKCS1_2048_8192_SHA256,
                Some(&digest::SHA256),
            )
        }
        PKIXALG_SHA384_WITH_RSA_ENCRYPTION => {
            rsa_key_usable(spki, false)?;
            choice(
                &signature::RSA_PKCS1_2048_8192_SHA384,
                Some(&digest::SHA384),
            )
        }
        PKIXALG_SHA512_WITH_RSA_ENCRYPTION => {
            rsa_key_usable(spki, false)?;
            choice(
                &signature::RSA_PKCS1_2048_8192_SHA512,
                Some(&digest::SHA512),
            )
        }

        PKIXALG_RSASSA_PSS => {
            rsa_key_usable(spki, true)?;
            match pss_hash(alg)? {
                PKIXALG_SHA256 => {
                    choice(&signature::RSA_PSS_2048_8192_SHA256, Some(&digest::SHA256))
                }
                PKIXALG_SHA384 => {
                    choice(&signature::RSA_PSS_2048_8192_SHA384, Some(&digest::SHA384))
                }
                PKIXALG_SHA512 => {
                    choice(&signature::RSA_PSS_2048_8192_SHA512, Some(&digest::SHA512))
                }
                _ => None,
            }
        }

        PKIXALG_ECDSA_WITH_SHA224
        | PKIXALG_ECDSA_WITH_SHA256
        | PKIXALG_ECDSA_WITH_SHA384
        | PKIXALG_ECDSA_WITH_SHA512 => {
            let curve = ec_curve(spki)?;
            let algorithm: &'static dyn VerificationAlgorithm = match (curve, alg.oid) {
                (PKIXALG_SECP256R1, PKIXALG_ECDSA_WITH_SHA256) => {
                    &signature::ECDSA_P256_SHA256_ASN1
                }
                (PKIXALG_SECP256R1, PKIXALG_ECDSA_WITH_SHA384) => {
                    &signature::ECDSA_P256_SHA384_ASN1
                }
                (PKIXALG_SECP256R1, PKIXALG_ECDSA_WITH_SHA512) => {
                    &signature::ECDSA_P256_SHA512_ASN1
                }
                (PKIXALG_SECP384R1, PKIXALG_ECDSA_WITH_SHA256) => {
                    &signature::ECDSA_P384_SHA256_ASN1
                }
                (PKIXALG_SECP384R1, PKIXALG_ECDSA_WITH_SHA384) => {
                    &signature::ECDSA_P384_SHA384_ASN1
                }
                (PKIXALG_SECP384R1, PKIXALG_ECDSA_WITH_SHA512) => {
                    &signature::ECDSA_P384_SHA512_ASN1
                }
                (PKIXALG_SECP521R1, PKIXALG_ECDSA_WITH_SHA224) => {
                    &signature::ECDSA_P521_SHA224_ASN1
                }
                (PKIXALG_SECP521R1, PKIXALG_ECDSA_WITH_SHA256) => {
                    &signature::ECDSA_P521_SHA256_ASN1
                }
                (PKIXALG_SECP521R1, PKIXALG_ECDSA_WITH_SHA384) => {
                    &signature::ECDSA_P521_SHA384_ASN1
                }
                (PKIXALG_SECP521R1, PKIXALG_ECDSA_WITH_SHA512) => {
                    &signature::ECDSA_P521_SHA512_ASN1
                }
                // aws-lc-rs pairs SHA-224 with P-521 only.
                _ => return None,
            };
            let digest = match alg.oid {
                PKIXALG_ECDSA_WITH_SHA224 => &digest::SHA224,
                PKIXALG_ECDSA_WITH_SHA256 => &digest::SHA256,
                PKIXALG_ECDSA_WITH_SHA384 => &digest::SHA384,
                _ => &digest::SHA512,
            };
            choice(algorithm, Some(digest))
        }

        // A pure ML-DSA key is identified by the same object identifier as its signatures, and
        // RFC 9881 requires both to carry no parameters.
        ID_ML_DSA_44 | ID_ML_DSA_65 | ID_ML_DSA_87 => {
            if spki.algorithm.oid != alg.oid
                || spki.algorithm.parameters.is_some()
                || alg.parameters.is_some()
            {
                return None;
            }
            let algorithm: &'static dyn VerificationAlgorithm = match alg.oid {
                ID_ML_DSA_44 => &signature::ML_DSA_44,
                ID_ML_DSA_65 => &signature::ML_DSA_65,
                _ => &signature::ML_DSA_87,
            };
            choice(algorithm, None)
        }

        _ => None,
    }
}

/// Checks that `spki` holds an RSA key aws-lc-rs will accept: identified as `rsaEncryption` (or, for
/// PSS, `id-RSASSA-PSS`), with a modulus of 2048 to 8192 bits.
///
/// RFC 4055 restricts a key identified as `id-RSASSA-PSS` to PSS, and certval's software verifier
/// rejects a PKCS #1 v1.5 signature under one, so that pairing is declined and software gives the
/// verdict.
fn rsa_key_usable(spki: &SubjectPublicKeyInfoOwned, pss: bool) -> Option<()> {
    let identified_as = spki.algorithm.oid;
    if identified_as != PKIXALG_RSA_ENCRYPTION && !(pss && identified_as == PKIXALG_RSASSA_PSS) {
        return None;
    }
    let key = RsaPublicKey::from_der(spki.subject_public_key.as_bytes()?).ok()?;
    let modulus = key.modulus.as_bytes();
    let bits = modulus.len() * 8 - modulus.first().map_or(0, |b| b.leading_zeros() as usize);
    RSA_BITS.contains(&bits).then_some(())
}

/// Returns the named curve of an elliptic curve key.
fn ec_curve(spki: &SubjectPublicKeyInfoOwned) -> Option<ObjectIdentifier> {
    if spki.algorithm.oid != PKIXALG_EC_PUBLIC_KEY {
        return None;
    }
    spki.algorithm
        .parameters
        .as_ref()?
        .decode_as::<ObjectIdentifier>()
        .ok()
}

/// Returns the hash of an RSASSA-PSS algorithm identifier whose parameters aws-lc-rs can honor.
///
/// aws-lc-rs's PSS verification algorithms fix MGF1 over the message hash and a salt as long as the
/// hash, so a parameter block naming anything else, or relying on RFC 4055's SHA-1 defaults, is
/// declined and software answers.
fn pss_hash(alg: &AlgorithmIdentifierOwned) -> Option<ObjectIdentifier> {
    let encoded = alg.parameters.as_ref()?.to_der().ok()?;
    let pss = RsaPssParams::from_der(&encoded).ok()?;
    let hash = pss.hash?.oid;
    let hash_len = match hash {
        PKIXALG_SHA256 => 32,
        PKIXALG_SHA384 => 48,
        PKIXALG_SHA512 => 64,
        _ => return None,
    };
    let mask_gen = pss.mask_gen?;
    if mask_gen.oid != PKIXALG_MGF1 {
        return None;
    }
    let mgf_hash = mask_gen
        .parameters
        .as_ref()?
        .decode_as::<AlgorithmIdentifierOwned>()
        .ok()?;
    if mgf_hash.oid != hash || pss.salt_len? != hash_len || pss.trailer_field.unwrap_or(1) != 1 {
        return None;
    }
    Some(hash)
}

/// `RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }`
#[derive(der::Sequence)]
struct RsaPublicKey<'a> {
    modulus: der::asn1::UintRef<'a>,
    public_exponent: der::asn1::UintRef<'a>,
}

/// The parameter block carried by an RSASSA-PSS algorithm identifier.
#[derive(der::Sequence)]
pub(crate) struct RsaPssParams {
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT", optional = "true")]
    pub(crate) hash: Option<AlgorithmIdentifierOwned>,
    #[asn1(context_specific = "1", tag_mode = "EXPLICIT", optional = "true")]
    pub(crate) mask_gen: Option<AlgorithmIdentifierOwned>,
    #[asn1(context_specific = "2", tag_mode = "EXPLICIT", optional = "true")]
    pub(crate) salt_len: Option<u32>,
    #[asn1(context_specific = "3", tag_mode = "EXPLICIT", optional = "true")]
    pub(crate) trailer_field: Option<u32>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use certval::PKIXALG_SHA224_WITH_RSA_ENCRYPTION;
    use der::asn1::{Any, BitString, UintRef};

    fn plain(oid: ObjectIdentifier) -> AlgorithmIdentifierOwned {
        AlgorithmIdentifierOwned {
            oid,
            parameters: None,
        }
    }

    fn rsa_spki(oid: ObjectIdentifier, modulus_bytes: usize) -> SubjectPublicKeyInfoOwned {
        let mut modulus = vec![0xc5u8; modulus_bytes];
        modulus[0] = 0x80;
        let key = RsaPublicKey {
            modulus: UintRef::new(&modulus).unwrap(),
            public_exponent: UintRef::new(&[1, 0, 1]).unwrap(),
        };
        SubjectPublicKeyInfoOwned {
            algorithm: plain(oid),
            subject_public_key: BitString::from_bytes(&key.to_der().unwrap()).unwrap(),
        }
    }

    fn ec_spki(curve: ObjectIdentifier, len: usize) -> SubjectPublicKeyInfoOwned {
        let mut point = vec![0x11u8; len];
        point[0] = 0x04;
        SubjectPublicKeyInfoOwned {
            algorithm: AlgorithmIdentifierOwned {
                oid: PKIXALG_EC_PUBLIC_KEY,
                parameters: Some(Any::encode_from(&curve).unwrap()),
            },
            subject_public_key: BitString::from_bytes(&point).unwrap(),
        }
    }

    fn pss(hash: ObjectIdentifier, mgf: ObjectIdentifier, salt: u32) -> AlgorithmIdentifierOwned {
        let alg = |oid| AlgorithmIdentifierOwned {
            oid,
            parameters: Some(Any::null()),
        };
        let params = RsaPssParams {
            hash: Some(alg(hash)),
            mask_gen: Some(AlgorithmIdentifierOwned {
                oid: PKIXALG_MGF1,
                parameters: Some(Any::encode_from(&alg(mgf)).unwrap()),
            }),
            salt_len: Some(salt),
            trailer_field: None,
        };
        AlgorithmIdentifierOwned {
            oid: PKIXALG_RSASSA_PSS,
            parameters: Some(Any::encode_from(&params).unwrap()),
        }
    }

    #[test]
    fn rsa_keys_outside_2048_to_8192_bits_are_declined() {
        let alg = plain(PKIXALG_SHA256_WITH_RSA_ENCRYPTION);
        assert!(choose(&alg, &rsa_spki(PKIXALG_RSA_ENCRYPTION, 256)).is_some());
        assert!(choose(&alg, &rsa_spki(PKIXALG_RSA_ENCRYPTION, 128)).is_none());
        assert!(choose(&alg, &rsa_spki(PKIXALG_RSA_ENCRYPTION, 1025)).is_none());
    }

    #[test]
    fn sha224_rsa_is_declined() {
        let alg = plain(PKIXALG_SHA224_WITH_RSA_ENCRYPTION);
        assert!(choose(&alg, &rsa_spki(PKIXALG_RSA_ENCRYPTION, 256)).is_none());
    }

    #[test]
    fn a_pss_key_verifies_only_pss() {
        let key = rsa_spki(PKIXALG_RSASSA_PSS, 256);
        assert!(choose(&plain(PKIXALG_SHA256_WITH_RSA_ENCRYPTION), &key).is_none());
        assert!(choose(&pss(PKIXALG_SHA256, PKIXALG_SHA256, 32), &key).is_some());
    }

    #[test]
    fn pss_must_match_what_aws_lc_rs_fixes() {
        let key = rsa_spki(PKIXALG_RSA_ENCRYPTION, 256);
        assert!(choose(&pss(PKIXALG_SHA384, PKIXALG_SHA384, 48), &key).is_some());
        assert!(choose(&pss(PKIXALG_SHA256, PKIXALG_SHA256, 20), &key).is_none());
        assert!(choose(&pss(PKIXALG_SHA256, PKIXALG_SHA512, 32), &key).is_none());
        assert!(choose(&plain(PKIXALG_RSASSA_PSS), &key).is_none());
    }

    #[test]
    fn ecdsa_pairs_the_curve_and_the_hash() {
        let p256 = ec_spki(PKIXALG_SECP256R1, 65);
        assert!(choose(&plain(PKIXALG_ECDSA_WITH_SHA256), &p256).is_some());
        assert!(choose(&plain(PKIXALG_ECDSA_WITH_SHA224), &p256).is_none());
        let p521 = ec_spki(PKIXALG_SECP521R1, 133);
        assert!(choose(&plain(PKIXALG_ECDSA_WITH_SHA224), &p521).is_some());
        let brainpool = ec_spki(ObjectIdentifier::new_unwrap("1.3.36.3.3.2.8.1.1.7"), 65);
        assert!(choose(&plain(PKIXALG_ECDSA_WITH_SHA256), &brainpool).is_none());
    }

    #[test]
    fn ml_dsa_key_must_match_the_signature() {
        let key = SubjectPublicKeyInfoOwned {
            algorithm: plain(ID_ML_DSA_65),
            subject_public_key: BitString::from_bytes(&[0u8; 1952]).unwrap(),
        };
        let choice = choose(&plain(ID_ML_DSA_65), &key).unwrap();
        assert!(choice.digest.is_none());
        assert!(choose(&plain(ID_ML_DSA_44), &key).is_none());
    }

    #[test]
    fn hashes_are_mapped() {
        for oid in [
            PKIXALG_SHA1,
            PKIXALG_SHA224,
            PKIXALG_SHA256,
            PKIXALG_SHA384,
            PKIXALG_SHA512,
        ] {
            assert!(hash(&oid).is_some(), "{oid}");
        }
    }
}
