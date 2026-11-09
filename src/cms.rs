//! The provider's implementations of certval-cms's interfaces, under the `cms` feature: content
//! encryption and decryption, RSA key transport, ECDH key agreement and ML-KEM by AWS-LC, and
//! recipient and signing credentials over AWS-LC keys.
//!
//! AWS-LC has no ANSI X9.63 KDF, so key agreement is split where certval-cms's helpers allow:
//! AWS-LC performs the ECDH, and [`wrap_with_ecdh_secret`](certval_cms::wrap_with_ecdh_secret) or
//! [`cek_from_ecdh_secret`](certval_cms::cek_from_ecdh_secret) does the rest. A KEM is performed
//! whole by AWS-LC: encapsulation or decapsulation, HKDF and key wrap. AWS-LC's key wrap offers
//! AES-128 and AES-256, so AES-192 is declined there. GCM nonces are generated inside AWS-LC, which
//! offers that for AES-128 and AES-256, so AES-192-GCM encryption is declined too; decryption takes
//! the message's nonce, for every key size.
//! As with verification, an AWS-LC error is the provider declining, except where noted.

use aws_lc_rs::aead::{self, Aad, Nonce, RandomizedNonceKey};
use aws_lc_rs::agreement::{self, EphemeralPrivateKey, PrivateKey, UnparsedPublicKey};
use aws_lc_rs::cipher::{
    self, DecryptionContext, PaddedBlockDecryptingKey, PaddedBlockEncryptingKey, UnboundCipherKey,
};
use aws_lc_rs::hkdf::{self, KeyType};
use aws_lc_rs::kem::{self, DecapsulationKey, EncapsulationKey};
use aws_lc_rs::key_wrap::{AesKek, KeyWrap};
use aws_lc_rs::rand::{self, SystemRandom};
use aws_lc_rs::rsa::{
    OaepAlgorithm, OaepPrivateDecryptingKey, OaepPublicEncryptingKey, Pkcs1PrivateDecryptingKey,
    Pkcs1PublicEncryptingKey, PrivateDecryptingKey, PublicEncryptingKey, OAEP_SHA1_MGF1SHA1,
    OAEP_SHA256_MGF1SHA256, OAEP_SHA384_MGF1SHA384, OAEP_SHA512_MGF1SHA512,
};
use aws_lc_rs::signature::{self, EcdsaKeyPair, EcdsaSigningAlgorithm, KeyPair, RsaKeyPair};
use certval_cms::{
    cek_from_ecdh_secret, content_decryption_parameters, kem_other_info, wrap_with_ecdh_secret,
    CmsEnvironment, ContentEncryptionAlgorithm, ContentEncryptionOutput, ContentParameters,
    DecryptContent, EncryptContent, EncryptKem, EncryptKeyAgreement, EncryptKeyTransport, Error,
    GcmParameters, KdfAlgorithm, KemOutput, KeyAgreeOutput, KeyAgreementAlgorithm,
    KeyTransportAlgorithm, KeyWrapAlgorithm, RecipientCredential, Result, SigningCredential,
    SigningKey,
};
use const_oid::{
    db::{
        fips203::{ID_ALG_ML_KEM_1024, ID_ALG_ML_KEM_512, ID_ALG_ML_KEM_768},
        rfc5912::{
            ECDSA_WITH_SHA_256, ECDSA_WITH_SHA_384, ECDSA_WITH_SHA_512, ID_EC_PUBLIC_KEY, ID_MGF_1,
            ID_RSASSA_PSS, ID_SHA_256, ID_SHA_384, ID_SHA_512, RSA_ENCRYPTION, SECP_256_R_1,
            SECP_384_R_1, SECP_521_R_1, SHA_256_WITH_RSA_ENCRYPTION, SHA_384_WITH_RSA_ENCRYPTION,
            SHA_512_WITH_RSA_ENCRYPTION,
        },
    },
    ObjectIdentifier,
};
use der::{
    asn1::{Any, OctetString},
    Choice, Decode, Encode, Sequence, Tag,
};
use log::{debug, trace};
use spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
use x509_cert::Certificate;
use zeroize::Zeroizing;

use crate::AwsLcCrypto;

/// Length in octets of an AES-CBC IV.
const CBC_IV_LEN: usize = 16;
/// Length in octets of the GCM tag produced for a message.
const GCM_TAG_LEN: usize = 16;

/// A key given to this provider that aws-lc-rs refused, with its reason; unlike a key met in a
/// message, the caller chose this one, so the refusal is theirs to read.
fn refused_key(e: impl core::fmt::Display) -> Error {
    Error::InvalidInput(format!("aws-lc-rs refused the key: {e}"))
}

fn declined(what: &str) -> Error {
    debug!("AWS-LC declined to {what}");
    Error::Unrecognized
}

fn content_decryption_failed() -> Error {
    Error::Crypto(String::from("content decryption failed"))
}

fn random(len: usize) -> Result<Zeroizing<Vec<u8>>> {
    let mut buf = Zeroizing::new(vec![0u8; len]);
    rand::fill(&mut buf).map_err(|_| Error::Crypto(String::from("random number generator")))?;
    Ok(buf)
}

fn cipher_algorithm(alg: ContentEncryptionAlgorithm) -> Option<&'static cipher::Algorithm> {
    match alg {
        ContentEncryptionAlgorithm::Aes128Cbc => Some(&cipher::AES_128),
        ContentEncryptionAlgorithm::Aes192Cbc => Some(&cipher::AES_192),
        ContentEncryptionAlgorithm::Aes256Cbc => Some(&cipher::AES_256),
        _ => None,
    }
}

fn aead_algorithm(alg: ContentEncryptionAlgorithm) -> Option<&'static aead::Algorithm> {
    match alg {
        ContentEncryptionAlgorithm::Aes128Gcm => Some(&aead::AES_128_GCM),
        ContentEncryptionAlgorithm::Aes192Gcm => Some(&aead::AES_192_GCM),
        ContentEncryptionAlgorithm::Aes256Gcm => Some(&aead::AES_256_GCM),
        _ => None,
    }
}

impl EncryptContent for AwsLcCrypto {
    /// AES-CBC and AES-GCM by AWS-LC, the key from AWS-LC's generator and the IV or nonce generated
    /// inside AWS-LC. AES-192-GCM, for which AWS-LC does not generate the nonce itself, is declined.
    fn encrypt_content(
        &self,
        _env: &CmsEnvironment,
        alg: ContentEncryptionAlgorithm,
        plaintext: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<ContentEncryptionOutput> {
        if aad.is_some() && !alg.is_authenticated() {
            return Err(Error::InvalidInput(String::from(
                "associated data given for an algorithm that does not authenticate",
            )));
        }
        let key = random(alg.key_len())?;
        let encrypted = if let Some(algorithm) = aead_algorithm(alg) {
            let sealing = RandomizedNonceKey::new(algorithm, &key)
                .map_err(|_| declined("make a GCM key with a nonce it generates"))?;
            let mut ciphertext = plaintext.to_vec();
            let (nonce, tag) = sealing
                .seal_in_place_separate_tag(Aad::from(aad.unwrap_or_default()), &mut ciphertext)
                .map_err(|_| Error::Crypto(String::from("content encryption failed")))?;
            let params = GcmParameters {
                nonce: OctetString::new(nonce.as_ref().as_slice())?,
                icv_len: GCM_TAG_LEN as u8,
            };
            ContentEncryptionOutput {
                ciphertext,
                key,
                algorithm: AlgorithmIdentifierOwned {
                    oid: alg.oid(),
                    parameters: Some(Any::encode_from(&params)?),
                },
                tag: Some(tag.as_ref().to_vec()),
            }
        } else if let Some(algorithm) = cipher_algorithm(alg) {
            let encrypting = UnboundCipherKey::new(algorithm, &key)
                .and_then(PaddedBlockEncryptingKey::cbc_pkcs7)
                .map_err(|_| declined("make a CBC key"))?;
            let mut ciphertext = plaintext.to_vec();
            let context = encrypting
                .encrypt(&mut ciphertext)
                .map_err(|_| Error::Crypto(String::from("content encryption failed")))?;
            let iv: &[u8] = (&context)
                .try_into()
                .map_err(|_| Error::Crypto(String::from("no IV")))?;
            ContentEncryptionOutput {
                ciphertext,
                key,
                algorithm: AlgorithmIdentifierOwned {
                    oid: alg.oid(),
                    parameters: Some(Any::new(Tag::OctetString, iv)?),
                },
                tag: None,
            }
        } else {
            return Err(Error::Unrecognized);
        };
        trace!("AWS-LC encrypted content with {alg:?}");
        Ok(encrypted)
    }
}

impl DecryptContent for AwsLcCrypto {
    /// AES-CBC and AES-GCM by AWS-LC.
    fn decrypt_content(
        &self,
        _env: &CmsEnvironment,
        alg: &AlgorithmIdentifierOwned,
        key: &[u8],
        ciphertext: &[u8],
        aad: Option<&[u8]>,
        tag: Option<&[u8]>,
    ) -> Result<Zeroizing<Vec<u8>>> {
        let (content_alg, parameters) = content_decryption_parameters(alg, key, aad, tag)?;
        let plaintext = match (parameters, tag) {
            (ContentParameters::Cbc { iv }, None) => {
                let algorithm = cipher_algorithm(content_alg).ok_or(Error::Unrecognized)?;
                let decrypting = UnboundCipherKey::new(algorithm, key)
                    .and_then(PaddedBlockDecryptingKey::cbc_pkcs7)
                    .map_err(|_| declined("make a CBC key"))?;
                let iv: [u8; CBC_IV_LEN] = iv
                    .as_slice()
                    .try_into()
                    .map_err(|_| content_decryption_failed())?;
                let mut buf = Zeroizing::new(ciphertext.to_vec());
                let plaintext = decrypting
                    .decrypt(&mut buf, DecryptionContext::Iv128(iv.into()))
                    .map_err(|_| content_decryption_failed())?
                    .to_vec();
                Zeroizing::new(plaintext)
            }
            (ContentParameters::Gcm { nonce }, Some(tag)) => {
                // The nonce is the message's, so the key takes it rather than generating one.
                let algorithm = aead_algorithm(content_alg).ok_or(Error::Unrecognized)?;
                let opening = aead::UnboundKey::new(algorithm, key)
                    .map(aead::LessSafeKey::new)
                    .map_err(|_| declined("make a GCM key"))?;
                let nonce =
                    Nonce::try_assume_unique_for_key(&nonce).map_err(|_| Error::Unrecognized)?;
                // AWS-LC opens 16-octet tags only; a shorter one RFC 5084 allows is declined, as
                // a nonce of another length is, rather than judged a bad tag.
                if tag.len() != GCM_TAG_LEN {
                    return Err(declined("open a GCM tag of another length"));
                }
                let mut buf = Zeroizing::new([ciphertext, tag].concat());
                let plaintext = opening
                    .open_in_place(nonce, Aad::from(aad.unwrap_or_default()), &mut buf)
                    .map_err(|_| content_decryption_failed())?
                    .to_vec();
                Zeroizing::new(plaintext)
            }
            _ => return Err(Error::Unrecognized),
        };
        trace!("AWS-LC decrypted content with {content_alg:?}");
        Ok(plaintext)
    }
}

/// AWS-LC's OAEP algorithm for a key transport algorithm, or `None` for RSAES-PKCS1-v1_5.
fn oaep(alg: KeyTransportAlgorithm) -> Result<Option<&'static OaepAlgorithm>> {
    match alg {
        KeyTransportAlgorithm::RsaPkcs1v15 => Ok(None),
        KeyTransportAlgorithm::RsaOaepSha1 => Ok(Some(&OAEP_SHA1_MGF1SHA1)),
        KeyTransportAlgorithm::RsaOaepSha256 => Ok(Some(&OAEP_SHA256_MGF1SHA256)),
        KeyTransportAlgorithm::RsaOaepSha384 => Ok(Some(&OAEP_SHA384_MGF1SHA384)),
        KeyTransportAlgorithm::RsaOaepSha512 => Ok(Some(&OAEP_SHA512_MGF1SHA512)),
        _ => Err(Error::Unrecognized),
    }
}

impl EncryptKeyTransport for AwsLcCrypto {
    /// RSA key transport by AWS-LC, to an `rsaEncryption` key.
    fn encrypt_key_transport(
        &self,
        _env: &CmsEnvironment,
        alg: KeyTransportAlgorithm,
        spki: &SubjectPublicKeyInfoOwned,
        cek: &[u8],
    ) -> Result<Vec<u8>> {
        if spki.algorithm.oid != RSA_ENCRYPTION {
            return Err(Error::Unrecognized);
        }
        let oaep = oaep(alg)?;
        let key = PublicEncryptingKey::from_der(&spki.to_der()?)
            .map_err(|_| declined("decode an RSA key"))?;
        let mut output = vec![0u8; key.key_size_bytes()];
        let written = match oaep {
            Some(oaep) => OaepPublicEncryptingKey::new(key)
                .and_then(|k| k.encrypt(oaep, cek, &mut output, None).map(|c| c.len())),
            None => Pkcs1PublicEncryptingKey::new(key)
                .and_then(|k| k.encrypt(cek, &mut output).map(|c| c.len())),
        }
        .map_err(|_| declined("perform key transport"))?;
        output.truncate(written);
        trace!("AWS-LC performed key transport with {alg:?}");
        Ok(output)
    }
}

/// AWS-LC's ECDH algorithm for the named curve an EC public key is on.
fn ecdh_algorithm(spki: &SubjectPublicKeyInfoOwned) -> Option<&'static agreement::Algorithm> {
    if spki.algorithm.oid != ID_EC_PUBLIC_KEY {
        return None;
    }
    let curve =
        ObjectIdentifier::from_der(&spki.algorithm.parameters.as_ref()?.to_der().ok()?).ok()?;
    match curve {
        SECP_256_R_1 => Some(&agreement::ECDH_P256),
        SECP_384_R_1 => Some(&agreement::ECDH_P384),
        SECP_521_R_1 => Some(&agreement::ECDH_P521),
        _ => None,
    }
}

impl EncryptKeyAgreement for AwsLcCrypto {
    /// Ephemeral-static ECDH on P-256, P-384 or P-521 by AWS-LC, then the X9.63 KDF and AES key
    /// wrap by certval-cms, AWS-LC having no X9.63 KDF.
    fn encrypt_key_agreement(
        &self,
        _env: &CmsEnvironment,
        alg: KeyAgreementAlgorithm,
        wrap: KeyWrapAlgorithm,
        spki: &SubjectPublicKeyInfoOwned,
        ukm: Option<&[u8]>,
        cek: &[u8],
    ) -> Result<KeyAgreeOutput> {
        let algorithm = ecdh_algorithm(spki).ok_or(Error::Unrecognized)?;
        let ephemeral = EphemeralPrivateKey::generate(algorithm, &SystemRandom::new())
            .map_err(|_| declined("generate an ephemeral key"))?;
        let ephemeral_public_key = ephemeral
            .compute_public_key()
            .map_err(|_| declined("compute an ephemeral public key"))?
            .as_ref()
            .to_vec();
        let peer = UnparsedPublicKey::new(algorithm, spki.subject_public_key.raw_bytes());
        let encrypted_key =
            agreement::agree_ephemeral(ephemeral, peer, Error::Unrecognized, |z| {
                wrap_with_ecdh_secret(alg, wrap, z, ukm, cek)
            })?;
        trace!("AWS-LC performed key agreement with {alg:?} and {wrap:?}");
        Ok(KeyAgreeOutput {
            ephemeral_public_key,
            encrypted_key,
        })
    }
}

/// AWS-LC's KEM for an ML-KEM key's algorithm.
fn kem_algorithm(oid: ObjectIdentifier) -> Option<&'static kem::Algorithm<kem::AlgorithmId>> {
    match oid {
        ID_ALG_ML_KEM_512 => Some(&kem::ML_KEM_512),
        ID_ALG_ML_KEM_768 => Some(&kem::ML_KEM_768),
        ID_ALG_ML_KEM_1024 => Some(&kem::ML_KEM_1024),
        _ => None,
    }
}

/// A length for HKDF to expand to.
struct Len(usize);

impl KeyType for Len {
    fn len(&self) -> usize {
        self.0
    }
}

/// The key-encryption key RFC 9629 derives from a KEM shared secret, by AWS-LC's HKDF with the salt
/// absent.
fn hkdf_kek(
    kdf: KdfAlgorithm,
    wrap: KeyWrapAlgorithm,
    ss: &[u8],
    ukm: Option<&[u8]>,
) -> Result<Zeroizing<Vec<u8>>> {
    let algorithm = match kdf {
        KdfAlgorithm::HkdfSha256 => hkdf::HKDF_SHA256,
        KdfAlgorithm::HkdfSha384 => hkdf::HKDF_SHA384,
        KdfAlgorithm::HkdfSha512 => hkdf::HKDF_SHA512,
        _ => return Err(Error::Unrecognized),
    };
    let info = kem_other_info(wrap, ukm)?;
    let info = [info.as_slice()];
    let mut kek = Zeroizing::new(vec![0u8; wrap.kek_len()]);
    hkdf::Salt::new(algorithm, &[])
        .extract(ss)
        .expand(&info, Len(wrap.kek_len()))
        .and_then(|okm| okm.fill(&mut kek))
        .map_err(|_| declined("derive a key-encryption key"))?;
    Ok(kek)
}

/// AWS-LC's AES key wrap cipher; AES-192 is declined.
fn aes_kek(wrap: KeyWrapAlgorithm, kek: &[u8]) -> Result<AesKek> {
    let cipher = match wrap {
        KeyWrapAlgorithm::Aes128 => &aws_lc_rs::key_wrap::AES_128,
        KeyWrapAlgorithm::Aes256 => &aws_lc_rs::key_wrap::AES_256,
        _ => return Err(Error::Unrecognized),
    };
    AesKek::new(cipher, kek).map_err(|_| declined("make a key-encryption key"))
}

impl EncryptKem for AwsLcCrypto {
    /// ML-KEM-512, -768 or -1024, HKDF and AES-128 or AES-256 key wrap, all by AWS-LC.
    fn encrypt_kem(
        &self,
        _env: &CmsEnvironment,
        kdf: KdfAlgorithm,
        wrap: KeyWrapAlgorithm,
        spki: &SubjectPublicKeyInfoOwned,
        ukm: Option<&[u8]>,
        cek: &[u8],
    ) -> Result<KemOutput> {
        let algorithm = kem_algorithm(spki.algorithm.oid).ok_or(Error::Unrecognized)?;
        let kek_cipher_check = aes_kek(wrap, &vec![0u8; wrap.kek_len()]);
        kek_cipher_check?;
        let key = EncapsulationKey::new(algorithm, spki.subject_public_key.raw_bytes())
            .map_err(|_| declined("decode an ML-KEM key"))?;
        let (ciphertext, ss) = key.encapsulate().map_err(|_| declined("encapsulate"))?;
        let kek = hkdf_kek(kdf, wrap, ss.as_ref(), ukm)?;
        let mut encrypted_key = vec![0u8; cek.len() + 8];
        let len = aes_kek(wrap, &kek)?
            .wrap(cek, &mut encrypted_key)
            .map_err(|_| Error::Crypto(String::from("key wrap failed")))?
            .len();
        encrypted_key.truncate(len);
        trace!("AWS-LC performed a KEM with {kdf:?} and {wrap:?}");
        Ok(KemOutput {
            kem_ct: ciphertext.as_ref().to_vec(),
            encrypted_key,
        })
    }
}

/// RFC 9935's ML-KEM private key: a seed, an expanded key, or both. AWS-LC takes the expanded key.
#[derive(Choice)]
enum MlKemPrivateKey {
    #[asn1(context_specific = "0", tag_mode = "IMPLICIT")]
    Seed(OctetString),
    ExpandedKey(OctetString),
    Both(MlKemBoth),
}

#[derive(Sequence)]
struct MlKemBoth {
    seed: OctetString,
    expanded_key: OctetString,
}

/// The private key an [`AwsLcRecipientKey`] holds.
enum RecipientKey {
    Rsa(PrivateDecryptingKey),
    Ec(PrivateKey),
    MlKem(DecapsulationKey<kem::AlgorithmId>),
}

/// A [`RecipientCredential`] whose private key AWS-LC holds: RSA key transport, ECDH key agreement
/// (the X9.63 KDF and key unwrap by certval-cms), and ML-KEM with HKDF and key unwrap.
pub struct AwsLcRecipientKey {
    certificate: Certificate,
    key: RecipientKey,
}

impl AwsLcRecipientKey {
    /// A credential for the PKCS #8 (RFC 5958) private key `der`, identified by `certificate`: RSA,
    /// EC on P-256, P-384 or P-521, or ML-KEM in RFC 9935's expanded or combined form, AWS-LC
    /// taking the expanded key. An ML-KEM key with only its seed is refused.
    pub fn from_pkcs8_der(certificate: Certificate, der: &[u8]) -> Result<Self> {
        let spki = certificate
            .tbs_certificate()
            .subject_public_key_info()
            .clone();
        let key = if spki.algorithm.oid == RSA_ENCRYPTION {
            RecipientKey::Rsa(PrivateDecryptingKey::from_pkcs8(der).map_err(refused_key)?)
        } else if let Some(algorithm) = ecdh_algorithm(&spki) {
            RecipientKey::Ec(PrivateKey::from_private_key_der(algorithm, der).map_err(refused_key)?)
        } else if let Some(algorithm) = kem_algorithm(spki.algorithm.oid) {
            let info = pkcs8::PrivateKeyInfoRef::from_der(der)?;
            let expanded = match MlKemPrivateKey::from_der(info.private_key.as_bytes())? {
                MlKemPrivateKey::ExpandedKey(expanded) => expanded,
                MlKemPrivateKey::Both(both) => both.expanded_key,
                MlKemPrivateKey::Seed(_) => {
                    return Err(Error::InvalidInput(String::from(
                        "an ML-KEM private key with only its seed, which AWS-LC does not take",
                    )))
                }
            };
            RecipientKey::MlKem(
                DecapsulationKey::new(algorithm, expanded.as_bytes()).map_err(refused_key)?,
            )
        } else {
            return Err(Error::Unrecognized);
        };
        Ok(Self { certificate, key })
    }
}

impl RecipientCredential for AwsLcRecipientKey {
    fn certificate(&self) -> &Certificate {
        &self.certificate
    }

    fn decrypt_key_transport(
        &self,
        _env: &CmsEnvironment,
        alg: KeyTransportAlgorithm,
        encrypted_key: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>> {
        let RecipientKey::Rsa(key) = &self.key else {
            return Err(Error::Unrecognized);
        };
        let oaep = oaep(alg)?;
        let mut output = Zeroizing::new(vec![0u8; key.key_size_bytes()]);
        let written = match oaep {
            Some(oaep) => OaepPrivateDecryptingKey::new(key.clone()).and_then(|k| {
                k.decrypt(oaep, encrypted_key, &mut output, None)
                    .map(|p| p.len())
            }),
            None => Pkcs1PrivateDecryptingKey::new(key.clone())
                .and_then(|k| k.decrypt(encrypted_key, &mut output).map(|p| p.len())),
        }
        .map_err(|_| Error::Crypto(String::from("key transport failed")))?;
        output.truncate(written);
        trace!("AWS-LC decrypted a key transport with {alg:?}");
        Ok(output)
    }

    fn decrypt_key_agreement(
        &self,
        _env: &CmsEnvironment,
        alg: KeyAgreementAlgorithm,
        wrap: KeyWrapAlgorithm,
        originator: &SubjectPublicKeyInfoOwned,
        ukm: Option<&[u8]>,
        encrypted_key: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>> {
        let RecipientKey::Ec(key) = &self.key else {
            return Err(Error::Unrecognized);
        };
        // The originator's key is on the recipient's curve, which its identifier need not name.
        let peer =
            UnparsedPublicKey::new(key.algorithm(), originator.subject_public_key.raw_bytes());
        let cek = agreement::agree(
            key,
            peer,
            Error::Crypto(String::from("key agreement failed")),
            |z| cek_from_ecdh_secret(alg, wrap, z, ukm, encrypted_key),
        )?;
        trace!("AWS-LC decrypted a key agreement with {alg:?} and {wrap:?}");
        Ok(cek)
    }

    fn decrypt_kem(
        &self,
        _env: &CmsEnvironment,
        kdf: KdfAlgorithm,
        wrap: KeyWrapAlgorithm,
        kem_ct: &[u8],
        ukm: Option<&[u8]>,
        encrypted_key: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>> {
        let RecipientKey::MlKem(key) = &self.key else {
            return Err(Error::Unrecognized);
        };
        aes_kek(wrap, &vec![0u8; wrap.kek_len()])?;
        let ss = key
            .decapsulate(kem_ct.into())
            .map_err(|_| Error::Crypto(String::from("decapsulation failed")))?;
        let kek = hkdf_kek(kdf, wrap, ss.as_ref(), ukm)?;
        let mut cek = Zeroizing::new(vec![0u8; encrypted_key.len()]);
        let len = aes_kek(wrap, &kek)?
            .unwrap(encrypted_key, &mut cek)
            .map_err(|_| Error::Crypto(String::from("key unwrap failed")))?
            .len();
        cek.truncate(len);
        trace!("AWS-LC decrypted a KEM with {kdf:?} and {wrap:?}");
        Ok(cek)
    }
}

/// The private key an [`AwsLcKey`] holds. An ECDSA key is held as PKCS #8, since AWS-LC
/// fixes the hash when the key is made.
enum SigningKeyMaterial {
    Rsa(RsaKeyPair),
    Ecdsa(Zeroizing<Vec<u8>>, ObjectIdentifier),
}

/// A [`SigningKey`] whose private key AWS-LC holds, with no certificate: e.g. a key signing its own
/// certificate request or a self-signed certificate. It signs as [`AwsLcSigningKey`] does.
pub struct AwsLcKey {
    public_key: SubjectPublicKeyInfoOwned,
    key: SigningKeyMaterial,
}

impl AwsLcKey {
    /// A key for the PKCS #8 (RFC 5958) private key `der`: RSA, or EC on P-256, P-384 or P-521.
    pub fn from_pkcs8_der(der: &[u8]) -> Result<Self> {
        let info = pkcs8::PrivateKeyInfoRef::from_der(der)?;
        let (algorithm, public, key) = match info.algorithm.oid {
            RSA_ENCRYPTION => {
                let key = RsaKeyPair::from_pkcs8(der).map_err(refused_key)?;
                let public = key.public_key().as_ref().to_vec();
                let algorithm = AlgorithmIdentifierOwned {
                    oid: RSA_ENCRYPTION,
                    parameters: Some(Any::null()),
                };
                (algorithm, public, SigningKeyMaterial::Rsa(key))
            }
            ID_EC_PUBLIC_KEY => {
                let curve = info
                    .algorithm
                    .parameters_oid()
                    .map_err(|_| Error::Unrecognized)?;
                // Any of the curve's signing algorithms decodes the key; the one used to sign is
                // chosen per signature.
                let decoding = match curve {
                    SECP_256_R_1 => &signature::ECDSA_P256_SHA256_ASN1_SIGNING,
                    SECP_384_R_1 => &signature::ECDSA_P384_SHA384_ASN1_SIGNING,
                    SECP_521_R_1 => &signature::ECDSA_P521_SHA512_ASN1_SIGNING,
                    _ => return Err(Error::Unrecognized),
                };
                let key = EcdsaKeyPair::from_pkcs8(decoding, der).map_err(refused_key)?;
                let public = key.public_key().as_ref().to_vec();
                let algorithm = AlgorithmIdentifierOwned {
                    oid: ID_EC_PUBLIC_KEY,
                    parameters: Some(Any::from(&curve)),
                };
                (
                    algorithm,
                    public,
                    SigningKeyMaterial::Ecdsa(Zeroizing::new(der.to_vec()), curve),
                )
            }
            _ => return Err(Error::Unrecognized),
        };
        Ok(Self {
            public_key: SubjectPublicKeyInfoOwned {
                algorithm,
                subject_public_key: der::asn1::BitString::from_bytes(&public)?,
            },
            key,
        })
    }

    fn sign(&self, alg: &AlgorithmIdentifierOwned, message: &[u8]) -> Result<Vec<u8>> {
        let rng = SystemRandom::new();
        let signature = match &self.key {
            SigningKeyMaterial::Rsa(key) => {
                let padding = rsa_padding(alg)?;
                let mut signature = vec![0u8; key.public_modulus_len()];
                key.sign(padding, &rng, message, &mut signature)
                    .map_err(|_| Error::Crypto(String::from("signing failed")))?;
                signature
            }
            SigningKeyMaterial::Ecdsa(pkcs8, curve) => {
                let algorithm = ecdsa_signing(*curve, alg.oid).ok_or(Error::Unrecognized)?;
                let key = EcdsaKeyPair::from_pkcs8(algorithm, pkcs8)
                    .map_err(|_| declined("decode an EC key"))?;
                key.sign(&rng, message)
                    .map_err(|_| Error::Crypto(String::from("signing failed")))?
                    .as_ref()
                    .to_vec()
            }
        };
        trace!("AWS-LC signed with {}", alg.oid);
        Ok(signature)
    }
}

impl SigningKey for AwsLcKey {
    fn public_key(&self) -> &SubjectPublicKeyInfoOwned {
        &self.public_key
    }

    fn sign_message(
        &self,
        _env: &CmsEnvironment,
        alg: &AlgorithmIdentifierOwned,
        message: &[u8],
    ) -> Result<Vec<u8>> {
        self.sign(alg, message)
    }
}

/// A [`SigningCredential`] whose private key AWS-LC holds: RSA PKCS #1 v1.5 or RSASSA-PSS (salt the
/// length of the hash) with SHA-256, -384 or -512, and ECDSA with the curve and hash pairings
/// AWS-LC offers: P-256 with SHA-256, P-384 with SHA-384, and P-521 with SHA-256, -384 or -512.
/// An [`AwsLcKey`] with its certificate.
pub struct AwsLcSigningKey {
    certificate: Certificate,
    key: AwsLcKey,
}

impl AwsLcSigningKey {
    /// A credential for the PKCS #8 (RFC 5958) private key `der`, identified by `certificate`. The
    /// key must be the private half of the certificate's public key.
    pub fn from_pkcs8_der(certificate: Certificate, der: &[u8]) -> Result<Self> {
        let key = AwsLcKey::from_pkcs8_der(der)?;
        if key.public_key != *certificate.tbs_certificate().subject_public_key_info() {
            return Err(Error::InvalidInput(String::from(
                "the private key is not the certificate's",
            )));
        }
        Ok(Self { certificate, key })
    }
}

/// AWS-LC's ECDSA signing algorithm for a curve and signature algorithm, where it offers one.
fn ecdsa_signing(
    curve: ObjectIdentifier,
    alg: ObjectIdentifier,
) -> Option<&'static EcdsaSigningAlgorithm> {
    match (curve, alg) {
        (SECP_256_R_1, ECDSA_WITH_SHA_256) => Some(&signature::ECDSA_P256_SHA256_ASN1_SIGNING),
        (SECP_384_R_1, ECDSA_WITH_SHA_384) => Some(&signature::ECDSA_P384_SHA384_ASN1_SIGNING),
        (SECP_521_R_1, ECDSA_WITH_SHA_256) => Some(&signature::ECDSA_P521_SHA256_ASN1_SIGNING),
        (SECP_521_R_1, ECDSA_WITH_SHA_384) => Some(&signature::ECDSA_P521_SHA384_ASN1_SIGNING),
        (SECP_521_R_1, ECDSA_WITH_SHA_512) => Some(&signature::ECDSA_P521_SHA512_ASN1_SIGNING),
        _ => None,
    }
}

/// AWS-LC's RSA padding for a signature algorithm: PKCS #1 v1.5, or RSASSA-PSS as this crate
/// produces it, MGF1 with the same hash and a salt the length of the hash.
fn rsa_padding(alg: &AlgorithmIdentifierOwned) -> Result<&'static dyn signature::RsaEncoding> {
    match alg.oid {
        SHA_256_WITH_RSA_ENCRYPTION => Ok(&signature::RSA_PKCS1_SHA256),
        SHA_384_WITH_RSA_ENCRYPTION => Ok(&signature::RSA_PKCS1_SHA384),
        SHA_512_WITH_RSA_ENCRYPTION => Ok(&signature::RSA_PKCS1_SHA512),
        ID_RSASSA_PSS => {
            let params = alg.parameters.as_ref().ok_or(Error::Unrecognized)?;
            let params = crate::algorithm::RsaPssParams::from_der(&params.to_der()?)?;
            // An absent hash or mask is RFC 4055's SHA-1 default, which is declined.
            let hash = params.hash.as_ref().ok_or(Error::Unrecognized)?.oid;
            let mask_gen = params.mask_gen.as_ref().ok_or(Error::Unrecognized)?;
            let mask_hash = AlgorithmIdentifierOwned::from_der(
                &mask_gen
                    .parameters
                    .as_ref()
                    .ok_or(Error::Unrecognized)?
                    .to_der()?,
            )?
            .oid;
            let (padding, len): (&'static dyn signature::RsaEncoding, u32) = match hash {
                ID_SHA_256 => (&signature::RSA_PSS_SHA256, 32),
                ID_SHA_384 => (&signature::RSA_PSS_SHA384, 48),
                ID_SHA_512 => (&signature::RSA_PSS_SHA512, 64),
                _ => return Err(Error::Unrecognized),
            };
            if mask_gen.oid != ID_MGF_1 || mask_hash != hash || params.salt_len != Some(len) {
                return Err(Error::Unrecognized);
            }
            Ok(padding)
        }
        _ => Err(Error::Unrecognized),
    }
}

impl SigningCredential for AwsLcSigningKey {
    fn certificate(&self) -> &Certificate {
        &self.certificate
    }

    fn sign_message(
        &self,
        _env: &CmsEnvironment,
        alg: &AlgorithmIdentifierOwned,
        message: &[u8],
    ) -> Result<Vec<u8>> {
        self.key.sign(alg, message)
    }
}
