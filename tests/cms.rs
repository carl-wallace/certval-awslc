//! CMS through this provider, crossed with certval-cms's RustCrypto software in both directions:
//! what software builds or signs, AWS-LC decrypts or verifies, with nothing to fall back to, and the
//! reverse.
//!
//! Every key transport algorithm with AES-CBC and AES-GCM content; ECDH on P-256, P-384 and P-521
//! with each KDF hash, each wrap AWS-LC offers (AES-128 and AES-256), and user keying material;
//! ML-KEM with each parameter set, KDF and wrap; and signing with RSA PKCS #1 v1.5 and RSASSA-PSS
//! and the ECDSA curve and hash pairings AWS-LC offers.

#![cfg(feature = "cms")]

use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use aws_lc_rs::kem::{DecapsulationKey, ML_KEM_1024, ML_KEM_512, ML_KEM_768};
use certval::PkiEnvironment;
use certval_awslc::{AwsLcCrypto, AwsLcRecipientKey, AwsLcSigningKey};
use certval_cms::{
    rsa_pss, AuthEnvelopedDataBuilder, CmsEnvironment, ContentEncryptionAlgorithm, DigestAlgorithm,
    EnvelopedDataBuilder, KdfAlgorithm, KemRecipient, KeyAgreeRecipient, KeyAgreementAlgorithm,
    KeyTransRecipient, KeyTransportAlgorithm, KeyWrapAlgorithm, RecipientCredential,
    SignedDataBuilder, Signer, SignerPolicy, SigningCredential, SoftwareRecipientKey,
    SoftwareSigningKey,
};
use cms::content_info::ContentInfo;
use const_oid::db::fips203::{ID_ALG_ML_KEM_1024, ID_ALG_ML_KEM_512, ID_ALG_ML_KEM_768};
use const_oid::db::rfc5912::ID_CE_SUBJECT_KEY_IDENTIFIER;
use der::{
    asn1::{BitString, OctetString, OctetStringRef},
    Decode, Encode,
};
use elliptic_curve::Generate as _;
use getrandom::SysRng;
use p256::pkcs8::{EncodePrivateKey, EncodePublicKey};
use rand_core::UnwrapErr;
use sha1::{Digest, Sha1};
use spki::{
    AlgorithmIdentifierOwned, AlgorithmIdentifierRef, SubjectPublicKeyInfoOwned,
    SubjectPublicKeyInfoRef,
};
use x509_cert::{
    builder::{profile::BuilderProfile, Builder, CertificateBuilder},
    ext::{pkix::SubjectKeyIdentifier, Extension},
    name::Name,
    serial_number::SerialNumber,
    time::Validity,
    Certificate, TbsCertificate,
};

type Rng = UnwrapErr<SysRng>;

const MESSAGE: &[u8] = b"certval-awslc, longer than one AES block so that padding is exercised";

const CONTENT: [ContentEncryptionAlgorithm; 6] = [
    ContentEncryptionAlgorithm::Aes128Cbc,
    ContentEncryptionAlgorithm::Aes192Cbc,
    ContentEncryptionAlgorithm::Aes256Cbc,
    ContentEncryptionAlgorithm::Aes128Gcm,
    ContentEncryptionAlgorithm::Aes192Gcm,
    ContentEncryptionAlgorithm::Aes256Gcm,
];

/// The key wraps AWS-LC offers.
const WRAPS: [KeyWrapAlgorithm; 2] = [KeyWrapAlgorithm::Aes128, KeyWrapAlgorithm::Aes256];

fn rng() -> Rng {
    UnwrapErr(SysRng)
}

/// RustCrypto for everything, over a PkiEnvironment of certval's software.
fn software() -> CmsEnvironment {
    let mut pe = PkiEnvironment::default();
    pe.populate_5280_pki_environment();
    let mut env = CmsEnvironment::new();
    env.populate_software();
    env.set_pki_environment(Arc::new(pe));
    env
}

/// This provider for everything, with nothing to fall back to, over a PkiEnvironment holding only
/// this provider.
fn aws_lc() -> CmsEnvironment {
    let mut pe = PkiEnvironment::default();
    pe.add_calculate_hash_callback(AwsLcCrypto::new());
    pe.add_verify_signature_message_callback(AwsLcCrypto::new());
    pe.add_verify_signature_digest_callback(AwsLcCrypto::new());
    let mut env = CmsEnvironment::new();
    env.set_pki_environment(Arc::new(pe));
    env.add_encrypt_content_callback(AwsLcCrypto::new());
    env.add_decrypt_content_callback(AwsLcCrypto::new());
    env.add_encrypt_key_transport_callback(AwsLcCrypto::new());
    env.add_encrypt_key_agreement_callback(AwsLcCrypto::new());
    env.add_encrypt_kem_callback(AwsLcCrypto::new());
    env
}

/// Issues certificates with a subject key identifier from a throwaway P-256 CA.
struct Profile;

impl BuilderProfile for Profile {
    fn get_issuer(&self, _subject: &Name) -> Name {
        Name::from_str("CN=certval-awslc test CA").unwrap()
    }
    fn get_subject(&self) -> Name {
        Name::from_str("CN=certval-awslc test").unwrap()
    }
    fn build_extensions(
        &self,
        spk: SubjectPublicKeyInfoRef<'_>,
        _issuer_spk: SubjectPublicKeyInfoRef<'_>,
        _tbs: &TbsCertificate,
    ) -> x509_cert::builder::Result<Vec<Extension>> {
        let skid = SubjectKeyIdentifier(
            OctetString::new(Sha1::digest(spk.subject_public_key.raw_bytes()).to_vec()).unwrap(),
        );
        Ok(vec![Extension {
            extn_id: ID_CE_SUBJECT_KEY_IDENTIFIER,
            critical: false,
            extn_value: OctetString::new(skid.to_der().unwrap()).unwrap(),
        }])
    }
}

fn certificate(spki: SubjectPublicKeyInfoOwned) -> Certificate {
    let ca = p256::ecdsa::SigningKey::from_slice(&[9u8; 32]).unwrap();
    CertificateBuilder::new(
        Profile,
        SerialNumber::new(&[1]).unwrap(),
        Validity::from_now(Duration::from_secs(3600)).unwrap(),
        spki,
    )
    .unwrap()
    .build::<_, p256::ecdsa::DerSignature>(&ca)
    .unwrap()
}

/// A key, its certificate, and the key as PKCS #8.
struct Key {
    cert: Certificate,
    pkcs8: Vec<u8>,
}

impl Key {
    fn rsa() -> Self {
        let key = rsa::RsaPrivateKey::new(&mut rng(), 2048).unwrap();
        let spki = key.to_public_key().to_public_key_der().unwrap();
        Self {
            cert: certificate(SubjectPublicKeyInfoOwned::from_der(spki.as_bytes()).unwrap()),
            pkcs8: key.to_pkcs8_der().unwrap().as_bytes().to_vec(),
        }
    }

    /// An ML-KEM key generated by AWS-LC, written in RFC 9935's expanded form, which AWS-LC reads.
    fn ml_kem(
        alg: &'static aws_lc_rs::kem::Algorithm<aws_lc_rs::kem::AlgorithmId>,
        oid: const_oid::ObjectIdentifier,
    ) -> Self {
        let dk = DecapsulationKey::generate(alg).unwrap();
        let ek = dk.encapsulation_key().unwrap().key_bytes().unwrap();
        let expanded = dk.key_bytes().unwrap();
        let spki = SubjectPublicKeyInfoOwned {
            algorithm: AlgorithmIdentifierOwned {
                oid,
                parameters: None,
            },
            subject_public_key: BitString::from_bytes(ek.as_ref()).unwrap(),
        };
        let expanded_form = OctetString::new(expanded.as_ref())
            .unwrap()
            .to_der()
            .unwrap();
        let pkcs8 = pkcs8::PrivateKeyInfoRef::new(
            AlgorithmIdentifierRef {
                oid,
                parameters: None,
            },
            OctetStringRef::new(&expanded_form).unwrap(),
        )
        .to_der()
        .unwrap();
        Self {
            cert: certificate(spki),
            pkcs8,
        }
    }

    fn recipient_credentials(&self) -> (AwsLcRecipientKey, SoftwareRecipientKey) {
        (
            AwsLcRecipientKey::from_pkcs8_der(self.cert.clone(), &self.pkcs8).unwrap(),
            SoftwareRecipientKey::from_pkcs8_der(self.cert.clone(), &self.pkcs8).unwrap(),
        )
    }

    fn signing_credentials(&self) -> (AwsLcSigningKey, SoftwareSigningKey) {
        (
            AwsLcSigningKey::from_pkcs8_der(self.cert.clone(), &self.pkcs8).unwrap(),
            SoftwareSigningKey::from_pkcs8_der(self.cert.clone(), &self.pkcs8).unwrap(),
        )
    }
}

macro_rules! ec_key {
    ($curve:ident) => {{
        let key = $curve::SecretKey::generate_from_rng(&mut rng());
        let spki = key.public_key().to_public_key_der().unwrap();
        Key {
            cert: certificate(SubjectPublicKeyInfoOwned::from_der(spki.as_bytes()).unwrap()),
            pkcs8: key.to_pkcs8_der().unwrap().as_bytes().to_vec(),
        }
    }};
}

fn envelop<'e>(
    env: &'e CmsEnvironment,
    alg: ContentEncryptionAlgorithm,
    recipient: impl cms::builder::RecipientInfoBuilder<Rng = Rng> + 'e,
) -> ContentInfo {
    if alg.is_authenticated() {
        AuthEnvelopedDataBuilder::new(MESSAGE, alg)
            .unwrap()
            .add_recipient(recipient)
            .build_content_info(env, &mut rng())
            .unwrap_or_else(|e| panic!("building: {e}"))
    } else {
        EnvelopedDataBuilder::new(MESSAGE, alg)
            .unwrap()
            .add_recipient(recipient)
            .build_content_info(env, &mut rng())
            .unwrap_or_else(|e| panic!("building: {e}"))
    }
}

fn assert_decrypts(
    env: &CmsEnvironment,
    ci: &ContentInfo,
    credential: &dyn RecipientCredential,
    name: &str,
) {
    let decrypted = env
        .decrypt_enveloped_data(ci, Some(credential))
        .unwrap_or_else(|e| panic!("{name}: {e}"));
    assert_eq!(decrypted.content.as_slice(), MESSAGE, "{name}");
}

#[test]
fn key_transport_with_each_algorithm_and_content_encryption() {
    let (software, platform) = (software(), aws_lc());
    let key = Key::rsa();
    let (platform_key, software_key) = key.recipient_credentials();
    for alg in [
        KeyTransportAlgorithm::RsaPkcs1v15,
        KeyTransportAlgorithm::RsaOaepSha1,
        KeyTransportAlgorithm::RsaOaepSha256,
        KeyTransportAlgorithm::RsaOaepSha384,
        KeyTransportAlgorithm::RsaOaepSha512,
    ] {
        for content in CONTENT {
            let name = format!("{alg:?} {content:?}");
            let r = KeyTransRecipient::from_certificate(&software, &key.cert, None, alg).unwrap();
            let ci = envelop(&software, content, r);
            assert_decrypts(
                &platform,
                &ci,
                &platform_key,
                &format!("software to AWS-LC, {name}"),
            );

            // AWS-LC generates GCM nonces itself for AES-128 and AES-256 only.
            if content == ContentEncryptionAlgorithm::Aes192Gcm {
                continue;
            }
            let r = KeyTransRecipient::from_certificate(&platform, &key.cert, None, alg).unwrap();
            let ci = envelop(&platform, content, r);
            assert_decrypts(
                &software,
                &ci,
                &software_key,
                &format!("AWS-LC to software, {name}"),
            );
        }
    }
}

fn key_agreement(key: Key, curve: &str) {
    let (software, platform) = (software(), aws_lc());
    let (platform_key, software_key) = key.recipient_credentials();
    for alg in [
        KeyAgreementAlgorithm::EcdhSha256,
        KeyAgreementAlgorithm::EcdhSha384,
        KeyAgreementAlgorithm::EcdhSha512,
    ] {
        for wrap in WRAPS {
            for ukm in [None, Some(b"user keying material".to_vec())] {
                let name = format!("{curve} {alg:?} {wrap:?} ukm={}", ukm.is_some());
                let r = KeyAgreeRecipient::from_certificate(
                    &software,
                    &key.cert,
                    None,
                    alg,
                    wrap,
                    ukm.clone(),
                )
                .unwrap();
                let ci = envelop(&software, ContentEncryptionAlgorithm::Aes256Gcm, r);
                assert_decrypts(
                    &platform,
                    &ci,
                    &platform_key,
                    &format!("software to AWS-LC, {name}"),
                );

                let r =
                    KeyAgreeRecipient::from_certificate(&platform, &key.cert, None, alg, wrap, ukm)
                        .unwrap();
                let ci = envelop(&platform, ContentEncryptionAlgorithm::Aes128Cbc, r);
                assert_decrypts(
                    &software,
                    &ci,
                    &software_key,
                    &format!("AWS-LC to software, {name}"),
                );
            }
        }
    }
}

#[test]
fn key_agreement_on_p256() {
    key_agreement(ec_key!(p256), "P-256");
}

#[test]
fn key_agreement_on_p384() {
    key_agreement(ec_key!(p384), "P-384");
}

#[test]
fn key_agreement_on_p521() {
    key_agreement(ec_key!(p521), "P-521");
}

#[test]
fn kem_with_each_parameter_set_kdf_and_wrap() {
    let (software, platform) = (software(), aws_lc());
    for (alg, oid, name) in [
        (&ML_KEM_512, ID_ALG_ML_KEM_512, "ML-KEM-512"),
        (&ML_KEM_768, ID_ALG_ML_KEM_768, "ML-KEM-768"),
        (&ML_KEM_1024, ID_ALG_ML_KEM_1024, "ML-KEM-1024"),
    ] {
        let key = Key::ml_kem(alg, oid);
        let (platform_key, software_key) = key.recipient_credentials();
        for kdf in [
            KdfAlgorithm::HkdfSha256,
            KdfAlgorithm::HkdfSha384,
            KdfAlgorithm::HkdfSha512,
        ] {
            for wrap in WRAPS {
                for ukm in [None, Some(b"user keying material".to_vec())] {
                    let label = format!("{name} {kdf:?} {wrap:?} ukm={}", ukm.is_some());
                    let r = KemRecipient::from_certificate(
                        &software,
                        &key.cert,
                        None,
                        kdf,
                        wrap,
                        ukm.clone(),
                    )
                    .unwrap();
                    let ci = envelop(&software, ContentEncryptionAlgorithm::Aes256Cbc, r);
                    assert_decrypts(
                        &platform,
                        &ci,
                        &platform_key,
                        &format!("software to AWS-LC, {label}"),
                    );

                    let r =
                        KemRecipient::from_certificate(&platform, &key.cert, None, kdf, wrap, ukm)
                            .unwrap();
                    let ci = envelop(&platform, ContentEncryptionAlgorithm::Aes256Gcm, r);
                    assert_decrypts(
                        &software,
                        &ci,
                        &software_key,
                        &format!("AWS-LC to software, {label}"),
                    );
                }
            }
        }
    }
}

fn assert_signs_across(
    signing: &CmsEnvironment,
    verifying: &CmsEnvironment,
    credential: &dyn SigningCredential,
    configure: impl Fn(Signer<'_>) -> Signer<'_>,
    name: &str,
) {
    let ci = SignedDataBuilder::new(MESSAGE)
        .add_signer(configure(Signer::explicit(credential)))
        .build(signing)
        .unwrap_or_else(|e| panic!("{name}: signing: {e}"))
        .content_info;
    let verified = verifying
        .verify_signed_data(&ci, None, None, SignerPolicy::All)
        .unwrap_or_else(|e| panic!("{name}: verifying: {e}"));
    assert_eq!(verified.content, MESSAGE, "{name}");
}

fn sign_both_ways(key: &Key, configure: impl Fn(Signer<'_>) -> Signer<'_> + Copy, name: &str) {
    let (software, platform) = (software(), aws_lc());
    let (platform_key, software_key) = key.signing_credentials();
    assert_signs_across(
        &platform,
        &software,
        &platform_key,
        configure,
        &format!("AWS-LC signs, software verifies: {name}"),
    );
    assert_signs_across(
        &software,
        &platform,
        &software_key,
        configure,
        &format!("software signs, AWS-LC verifies: {name}"),
    );
}

#[test]
fn rsa_pkcs1v15_and_pss_with_each_digest() {
    let key = Key::rsa();
    for digest in [
        DigestAlgorithm::Sha256,
        DigestAlgorithm::Sha384,
        DigestAlgorithm::Sha512,
    ] {
        sign_both_ways(
            &key,
            |s| s.digest(digest),
            &format!("PKCS #1 v1.5 {digest:?}"),
        );
        sign_both_ways(
            &key,
            |s| {
                s.digest(digest)
                    .signature_algorithm(rsa_pss(digest).unwrap())
            },
            &format!("PSS {digest:?}"),
        );
    }
}

#[test]
fn ecdsa_with_the_pairings_aws_lc_offers() {
    for (key, curve, digests) in [
        (ec_key!(p256), "P-256", vec![DigestAlgorithm::Sha256]),
        (ec_key!(p384), "P-384", vec![DigestAlgorithm::Sha384]),
        (
            ec_key!(p521),
            "P-521",
            vec![
                DigestAlgorithm::Sha256,
                DigestAlgorithm::Sha384,
                DigestAlgorithm::Sha512,
            ],
        ),
    ] {
        for digest in digests {
            sign_both_ways(&key, |s| s.digest(digest), &format!("{curve} {digest:?}"));
        }
    }
}

#[test]
fn aes_192_gcm_encryption_is_declined() {
    assert!(matches!(
        aws_lc().encrypt_content(ContentEncryptionAlgorithm::Aes192Gcm, MESSAGE, None),
        Err(certval_cms::Error::Unrecognized)
    ));
}
