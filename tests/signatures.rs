//! Verifies RSA, RSASSA-PSS, ECDSA and ML-DSA signatures through both interfaces, and checks every
//! verdict against certval's software verifier.
//!
//! The keys and signatures come from aws-lc-rs itself, since it is the one implementation to hand
//! that signs all four. The software verifier is what keeps that from being circular: it reads the
//! same `SubjectPublicKeyInfo` the provider does, and must agree.

use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{
    EcdsaKeyPair, KeyPair, PqdsaKeyPair, RsaEncoding, RsaKeyPair, ECDSA_P256_SHA256_ASN1_SIGNING,
    ECDSA_P384_SHA384_ASN1_SIGNING, ECDSA_P521_SHA512_ASN1_SIGNING, ML_DSA_65_SIGNING,
    RSA_PKCS1_SHA256, RSA_PKCS1_SHA384, RSA_PSS_SHA256,
};
use certval::{
    calculate_hash_rust_crypto, verify_signature_message_rust_crypto, CalculateHash, Error,
    PathValidationStatus, PkiEnvironment, VerifySignatureDigest, VerifySignatureMessage,
    PKIXALG_ECDSA_WITH_SHA256, PKIXALG_ECDSA_WITH_SHA384, PKIXALG_ECDSA_WITH_SHA512,
    PKIXALG_EC_PUBLIC_KEY, PKIXALG_MGF1, PKIXALG_RSASSA_PSS, PKIXALG_RSA_ENCRYPTION,
    PKIXALG_SECP256R1, PKIXALG_SECP384R1, PKIXALG_SECP521R1, PKIXALG_SHA1, PKIXALG_SHA224,
    PKIXALG_SHA256, PKIXALG_SHA256_WITH_RSA_ENCRYPTION, PKIXALG_SHA384,
    PKIXALG_SHA384_WITH_RSA_ENCRYPTION, PKIXALG_SHA512,
};
use certval_awslc::AwsLcCrypto;
use const_oid::db::fips204::ID_ML_DSA_65;
use const_oid::ObjectIdentifier;
use der::asn1::{Any, BitString};
use spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};

const MESSAGE: &[u8] = b"a to-be-signed structure stands in here";

/// Set by the CI job that builds AWS-LC's FIPS module, so a run that is not actually in FIPS mode
/// fails rather than quietly testing the ordinary build.
const EXPECT_FIPS: &str = "CERTVAL_AWSLC_EXPECT_FIPS";

struct Case {
    spki: SubjectPublicKeyInfoOwned,
    alg: AlgorithmIdentifierOwned,
    signature: Vec<u8>,
    /// The digest the signature is over, for algorithms that have a digest form.
    digest: Option<Vec<u8>>,
}

fn pe() -> PkiEnvironment {
    let mut pe = PkiEnvironment::default();
    pe.populate_5280_pki_environment();
    pe
}

fn bits(bytes: &[u8]) -> BitString {
    BitString::from_bytes(bytes).unwrap()
}

fn plain(oid: ObjectIdentifier) -> AlgorithmIdentifierOwned {
    AlgorithmIdentifierOwned {
        oid,
        parameters: None,
    }
}

fn digest_of(alg: &'static aws_lc_rs::digest::Algorithm) -> Vec<u8> {
    aws_lc_rs::digest::digest(alg, MESSAGE).as_ref().to_vec()
}

fn rsa_spki(key: &RsaKeyPair, oid: ObjectIdentifier) -> SubjectPublicKeyInfoOwned {
    SubjectPublicKeyInfoOwned {
        algorithm: AlgorithmIdentifierOwned {
            oid,
            parameters: (oid == PKIXALG_RSA_ENCRYPTION).then(Any::null),
        },
        subject_public_key: bits(key.public_key().as_ref()),
    }
}

fn rsa_sign(key: &RsaKeyPair, encoding: &'static dyn RsaEncoding) -> Vec<u8> {
    let mut signature = vec![0u8; key.public_modulus_len()];
    key.sign(encoding, &SystemRandom::new(), MESSAGE, &mut signature)
        .unwrap();
    signature
}

fn pss_alg(hash: ObjectIdentifier, salt_len: u32) -> AlgorithmIdentifierOwned {
    #[derive(der::Sequence)]
    struct Params {
        #[asn1(context_specific = "0", tag_mode = "EXPLICIT")]
        hash: AlgorithmIdentifierOwned,
        #[asn1(context_specific = "1", tag_mode = "EXPLICIT")]
        mask_gen: AlgorithmIdentifierOwned,
        #[asn1(context_specific = "2", tag_mode = "EXPLICIT")]
        salt_len: u32,
    }
    let hash_alg = AlgorithmIdentifierOwned {
        oid: hash,
        parameters: Some(Any::null()),
    };
    let params = Params {
        hash: hash_alg.clone(),
        mask_gen: AlgorithmIdentifierOwned {
            oid: PKIXALG_MGF1,
            parameters: Some(Any::encode_from(&hash_alg).unwrap()),
        },
        salt_len,
    };
    AlgorithmIdentifierOwned {
        oid: PKIXALG_RSASSA_PSS,
        parameters: Some(Any::encode_from(&params).unwrap()),
    }
}

fn ec_case(
    signing: &'static aws_lc_rs::signature::EcdsaSigningAlgorithm,
    curve: ObjectIdentifier,
    sig_oid: ObjectIdentifier,
    digest: &'static aws_lc_rs::digest::Algorithm,
) -> Case {
    let key = EcdsaKeyPair::generate(signing).unwrap();
    let signature = key.sign(&SystemRandom::new(), MESSAGE).unwrap();
    Case {
        spki: SubjectPublicKeyInfoOwned {
            algorithm: AlgorithmIdentifierOwned {
                oid: PKIXALG_EC_PUBLIC_KEY,
                parameters: Some(Any::encode_from(&curve).unwrap()),
            },
            subject_public_key: bits(key.public_key().as_ref()),
        },
        alg: plain(sig_oid),
        signature: signature.as_ref().to_vec(),
        digest: Some(digest_of(digest)),
    }
}

/// The cases certval's software verifier also covers, so every verdict has something to agree with.
fn classic_cases() -> Vec<(&'static str, Case)> {
    use aws_lc_rs::digest::{SHA256, SHA384, SHA512};
    use aws_lc_rs::rsa::KeySize;
    let rsa2048 = RsaKeyPair::generate(KeySize::Rsa2048).unwrap();
    let rsa3072 = RsaKeyPair::generate(KeySize::Rsa3072).unwrap();
    vec![
        (
            "RSA-2048 PKCS #1 SHA-256",
            Case {
                spki: rsa_spki(&rsa2048, PKIXALG_RSA_ENCRYPTION),
                alg: plain(PKIXALG_SHA256_WITH_RSA_ENCRYPTION),
                signature: rsa_sign(&rsa2048, &RSA_PKCS1_SHA256),
                digest: Some(digest_of(&SHA256)),
            },
        ),
        (
            "RSA-3072 PKCS #1 SHA-384",
            Case {
                spki: rsa_spki(&rsa3072, PKIXALG_RSA_ENCRYPTION),
                alg: plain(PKIXALG_SHA384_WITH_RSA_ENCRYPTION),
                signature: rsa_sign(&rsa3072, &RSA_PKCS1_SHA384),
                digest: Some(digest_of(&SHA384)),
            },
        ),
        (
            "RSA-2048 PSS SHA-256",
            Case {
                spki: rsa_spki(&rsa2048, PKIXALG_RSA_ENCRYPTION),
                alg: pss_alg(PKIXALG_SHA256, 32),
                signature: rsa_sign(&rsa2048, &RSA_PSS_SHA256),
                digest: Some(digest_of(&SHA256)),
            },
        ),
        (
            "RSA-2048 PSS SHA-256 under an id-RSASSA-PSS key",
            Case {
                spki: rsa_spki(&rsa2048, PKIXALG_RSASSA_PSS),
                alg: pss_alg(PKIXALG_SHA256, 32),
                signature: rsa_sign(&rsa2048, &RSA_PSS_SHA256),
                digest: Some(digest_of(&SHA256)),
            },
        ),
        (
            "P-256",
            ec_case(
                &ECDSA_P256_SHA256_ASN1_SIGNING,
                PKIXALG_SECP256R1,
                PKIXALG_ECDSA_WITH_SHA256,
                &SHA256,
            ),
        ),
        (
            "P-384",
            ec_case(
                &ECDSA_P384_SHA384_ASN1_SIGNING,
                PKIXALG_SECP384R1,
                PKIXALG_ECDSA_WITH_SHA384,
                &SHA384,
            ),
        ),
        (
            "P-521",
            ec_case(
                &ECDSA_P521_SHA512_ASN1_SIGNING,
                PKIXALG_SECP521R1,
                PKIXALG_ECDSA_WITH_SHA512,
                &SHA512,
            ),
        ),
    ]
}

fn ml_dsa_case() -> Case {
    let key = PqdsaKeyPair::generate(&ML_DSA_65_SIGNING).unwrap();
    let mut signature = vec![0u8; ML_DSA_65_SIGNING.signature_len()];
    let len = key.sign(MESSAGE, &mut signature).unwrap();
    signature.truncate(len);
    Case {
        spki: SubjectPublicKeyInfoOwned {
            algorithm: plain(ID_ML_DSA_65),
            subject_public_key: bits(key.public_key().as_ref()),
        },
        alg: plain(ID_ML_DSA_65),
        signature,
        digest: None,
    }
}

fn is_rejection(result: &certval::Result<()>) -> bool {
    matches!(
        result,
        Err(Error::PathValidation(
            PathValidationStatus::SignatureVerificationFailure
        ))
    )
}

#[test]
fn fips_mode_is_reported() {
    let enabled = AwsLcCrypto::fips_mode_enabled();
    println!("AWS-LC FIPS mode: {enabled}");
    if std::env::var_os(EXPECT_FIPS).is_some() {
        assert!(
            enabled,
            "{EXPECT_FIPS} is set but AWS-LC is not in FIPS mode"
        );
    }
}

#[test]
fn hashes_match_software() {
    let pe = pe();
    let crypto = AwsLcCrypto::new();
    for oid in [
        PKIXALG_SHA224,
        PKIXALG_SHA256,
        PKIXALG_SHA384,
        PKIXALG_SHA512,
    ] {
        let expected = calculate_hash_rust_crypto(&pe, &plain(oid), MESSAGE).unwrap();
        let got = crypto.calculate_hash(&pe, &plain(oid), MESSAGE).unwrap();
        assert_eq!(got, expected, "{oid}");
    }
    // certval's software hash has no SHA-1, so it is checked against the FIPS 180 example,
    // SHA-1("abc").
    let sha1_abc = [
        0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a, 0xba, 0x3e, 0x25, 0x71, 0x78, 0x50, 0xc2,
        0x6c, 0x9c, 0xd0, 0xd8, 0x9d,
    ];
    let got = crypto
        .calculate_hash(&pe, &plain(PKIXALG_SHA1), b"abc")
        .unwrap();
    assert_eq!(got, sha1_abc);
}

#[test]
fn good_signatures_verify_and_software_agrees() {
    let pe = pe();
    let crypto = AwsLcCrypto::new();
    for (name, case) in classic_cases() {
        let signature = bits(&case.signature);
        let result =
            crypto.verify_signature_message(&pe, MESSAGE, &signature, &case.alg, &case.spki);
        assert!(result.is_ok(), "{name}, message: {result:?}");
        let software =
            verify_signature_message_rust_crypto(&pe, MESSAGE, &signature, &case.alg, &case.spki);
        assert!(software.is_ok(), "{name}, software: {software:?}");
    }
}

#[cfg(not(feature = "fips"))]
#[test]
fn good_signatures_verify_over_a_digest() {
    let pe = pe();
    let crypto = AwsLcCrypto::new();
    for (name, case) in classic_cases() {
        let digest = case.digest.as_deref().unwrap();
        let result = crypto.verify_signature_digest(
            &pe,
            digest,
            &bits(&case.signature),
            &case.alg,
            &case.spki,
        );
        assert!(result.is_ok(), "{name}: {result:?}");
    }
}

#[cfg(feature = "fips")]
#[test]
fn a_fips_build_declines_the_digest_interface() {
    let pe = pe();
    let crypto = AwsLcCrypto::new();
    for (name, case) in classic_cases() {
        let digest = case.digest.as_deref().unwrap();
        let result = crypto.verify_signature_digest(
            &pe,
            digest,
            &bits(&case.signature),
            &case.alg,
            &case.spki,
        );
        assert!(
            matches!(result, Err(Error::Unrecognized)),
            "{name}: {result:?}"
        );
    }
}

#[test]
fn a_changed_message_or_signature_is_a_verdict() {
    let pe = pe();
    let crypto = AwsLcCrypto::new();
    let mut cases = classic_cases();
    cases.push(("ML-DSA-65", ml_dsa_case()));
    for (name, case) in cases {
        let other = b"a different to-be-signed structure";
        let result = crypto.verify_signature_message(
            &pe,
            other,
            &bits(&case.signature),
            &case.alg,
            &case.spki,
        );
        assert!(is_rejection(&result), "{name}, changed message: {result:?}");

        let mut tampered = case.signature.clone();
        // Inside the signature value for every encoding here: the low byte of `s` for DER ECDSA,
        // the low byte of the integer for RSA, and a byte of the response for ML-DSA.
        *tampered.last_mut().unwrap() ^= 0x01;
        let result =
            crypto.verify_signature_message(&pe, MESSAGE, &bits(&tampered), &case.alg, &case.spki);
        assert!(
            is_rejection(&result),
            "{name}, changed signature: {result:?}"
        );
    }
}

#[test]
fn ml_dsa_verifies() {
    let pe = pe();
    let crypto = AwsLcCrypto::new();
    let case = ml_dsa_case();
    let signature = bits(&case.signature);
    let result = crypto.verify_signature_message(&pe, MESSAGE, &signature, &case.alg, &case.spki);
    assert!(result.is_ok(), "{result:?}");
    // ML-DSA has no digest form.
    let result = crypto.verify_signature_digest(&pe, &[0u8; 32], &signature, &case.alg, &case.spki);
    assert!(matches!(result, Err(Error::Unrecognized)), "{result:?}");

    #[cfg(feature = "pqc")]
    {
        let software = certval::verify_signature_message_rustcrypto(
            &pe, MESSAGE, &signature, &case.alg, &case.spki,
        );
        assert!(software.is_ok(), "software: {software:?}");
    }
}

#[test]
fn a_pkcs1_signature_under_a_pss_key_is_left_to_software() {
    let pe = pe();
    let crypto = AwsLcCrypto::new();
    let key = RsaKeyPair::generate(aws_lc_rs::rsa::KeySize::Rsa2048).unwrap();
    let spki = rsa_spki(&key, PKIXALG_RSASSA_PSS);
    let signature = bits(&rsa_sign(&key, &RSA_PKCS1_SHA256));
    let alg = plain(PKIXALG_SHA256_WITH_RSA_ENCRYPTION);
    let result = crypto.verify_signature_message(&pe, MESSAGE, &signature, &alg, &spki);
    assert!(matches!(result, Err(Error::Unrecognized)), "{result:?}");
    let software = verify_signature_message_rust_crypto(&pe, MESSAGE, &signature, &alg, &spki);
    assert!(is_rejection(&software), "{software:?}");
}

#[test]
fn a_key_aws_lc_cannot_parse_is_declined_not_judged() {
    let pe = pe();
    let crypto = AwsLcCrypto::new();
    // A P-256 identifier over a point that is not on the curve: aws-lc-rs refuses the key, which must
    // not read as a bad signature.
    let mut point = vec![0x11u8; 65];
    point[0] = 0x04;
    let spki = SubjectPublicKeyInfoOwned {
        algorithm: AlgorithmIdentifierOwned {
            oid: PKIXALG_EC_PUBLIC_KEY,
            parameters: Some(Any::encode_from(&PKIXALG_SECP256R1).unwrap()),
        },
        subject_public_key: bits(&point),
    };
    let result = crypto.verify_signature_message(
        &pe,
        MESSAGE,
        &bits(&[0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01]),
        &plain(PKIXALG_ECDSA_WITH_SHA256),
        &spki,
    );
    assert!(matches!(result, Err(Error::Unrecognized)), "{result:?}");
}

#[test]
fn registered_first_it_answers_and_software_agrees() {
    let mut pe = PkiEnvironment::default();
    pe.add_calculate_hash_callback(AwsLcCrypto::new());
    pe.add_verify_signature_message_callback(AwsLcCrypto::new());
    pe.add_verify_signature_digest_callback(AwsLcCrypto::new());
    pe.populate_5280_pki_environment();
    for (name, case) in classic_cases() {
        let signature = bits(&case.signature);
        assert!(
            pe.verify_signature_message(&pe, MESSAGE, &signature, &case.alg, &case.spki)
                .is_ok(),
            "{name}"
        );
    }
}
