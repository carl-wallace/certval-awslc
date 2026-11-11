# Changelog
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html), except that
an increase to the minimum supported Rust version is not treated as a breaking change.

## [0.1.0-rc.1]

Initial release. Calculates SHA-1/224/256/384/512 digests and verifies RSA PKCS #1 v1.5,
RSASSA-PSS, ECDSA and pure ML-DSA certificate signatures through AWS-LC (aws-lc-rs), through all
three of certval's hashing and verification interfaces. The `fips` feature builds AWS-LC's FIPS
module, where the digest interface is declined; `AwsLcCrypto::fips_mode_enabled` reports FIPS mode.

A `cms` feature, under which `AwsLcCrypto` implements certval-cms's content encryption and
decryption, key transport, key agreement and KEM interfaces: AES-128/192/256 in CBC and GCM (except
AES-192-GCM encryption), RSAES-PKCS1-v1_5 and RSAES-OAEP, ephemeral-static ECDH on P-256, P-384 and
P-521 with certval-cms's X9.63 KDF and key wrap, and ML-KEM with HKDF and AES-128/256 key wrap.
`AwsLcRecipientKey` decrypts each recipient type, and `AwsLcSigningKey` signs SignedData with RSA
and ECDSA, each with a private key AWS-LC holds; both check that the key is the certificate's.
`AwsLcKey` is the signing key without a certificate (certval-cms's `SigningKey`), e.g. to sign a
certificate request.

MSRV 1.89.
