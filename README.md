# certval-awslc

An AWS-LC crypto provider for [certval](https://github.com/carl-wallace/rust-pki). It supplies
implementations of the hashing and signature verification callbacks that a `PkiEnvironment`
dispatches through, backed by AWS-LC through aws-lc-rs. Unlike a provider for a system library, it
brings its module with it: AWS-LC is compiled into the binary, and with the `fips` feature it is
AWS-LC's FIPS module, which is how a validated module reaches a container or a Linux distribution
that ships none.

```rust
use certval::PkiEnvironment;
use certval_awslc::AwsLcCrypto;

let mut pe = PkiEnvironment::default();

// Registering before populate_5280_pki_environment puts AWS-LC ahead of the software
// implementations, so it is consulted first and software answers only what it declined.
pe.add_calculate_hash_callback(AwsLcCrypto::new());
pe.add_verify_signature_message_callback(AwsLcCrypto::new());
pe.add_verify_signature_digest_callback(AwsLcCrypto::new());

pe.populate_5280_pki_environment();
```

## Features

| Feature | Effect |
|---|---|
| `non-fips` (default) | AWS-LC's ordinary build; needs a C compiler |
| `fips` | AWS-LC's FIPS module; needs CMake and Go to build. Takes precedence when both are enabled |
| `pqc` | certval's software ML-DSA and SLH-DSA, for the tests' comparison; the provider needs nothing from it |
| `cms` | implements [certval-cms](https://github.com/carl-wallace/certval-cms)'s interfaces; see [CMS](#cms) |

For a FIPS build, `--no-default-features --features fips`. `AwsLcCrypto::fips_mode_enabled()`
reports whether AWS-LC is running in FIPS mode. The validation covers AWS-LC's C module, built as
its security policy describes, on the operating environments its certificate lists; aws-lc-rs and
this crate are outside it. Whether a given AWS-LC FIPS release is validated is a question for NIST's
CMVP list.

## Registration is additive

`PkiEnvironment` consults registered implementations in order and stops at the first verdict. The
provider reports a rejection only when AWS-LC judged a signature invalid; anything else it declines,
and a declined verification falls through to the next implementation. A caller who requires that
every verification reach AWS-LC must make the registration exclusive:

```rust
pe.populate_5280_pki_environment();
pe.clear_verify_signature_message_callbacks();
pe.clear_verify_signature_digest_callbacks();
pe.add_verify_signature_message_callback(AwsLcCrypto::new());
pe.add_verify_signature_digest_callback(AwsLcCrypto::new());
```

## Algorithm coverage

| Signature algorithm | Notes |
|---|---|
| RSA PKCS #1 v1.5, SHA-256/384/512 | keys of 2048 to 8192 bits |
| RSASSA-PSS, SHA-256/384/512 | MGF1 over the message hash, salt as long as the hash |
| ECDSA | P-256 and P-384 with SHA-256/384/512; P-521 with SHA-224/256/384/512 |
| ML-DSA-44/65/87 (pure) | message interface only |

| Hash | |
|---|---|
| SHA-1, SHA-224, SHA-256, SHA-384, SHA-512 | |

Anything else is declined, and software answers it. The deliberate declines:

- **SHA-224 RSA, and SHA-224 ECDSA on P-256 or P-384**, which aws-lc-rs has no verification
  algorithm for.
- **RSA keys outside 2048 to 8192 bits.**
- **RSASSA-PSS with parameters aws-lc-rs cannot express**: a mask other than MGF1 over the message
  hash, a salt length other than the hash length, or RFC 4055's SHA-1 defaults.
- **A PKCS #1 v1.5 signature under a key identified as `id-RSASSA-PSS`.** RFC 4055 restricts such a
  key to PSS, and certval's software verifier rejects the combination, so it gives that verdict.
- **SLH-DSA**, which AWS-LC does not offer.
- **Every digest verification in a `fips` build.** aws-lc-rs documents verifying over a precomputed
  digest as not allowed in FIPS mode.

aws-lc-rs reports every failure as the same error, so a key it cannot use would look like a
signature that does not verify. The provider keeps the two apart by declining everything above
before asking, and by parsing the key first: a key aws-lc-rs refuses is a decline, and only a
failure after a successful parse is a rejection.

## CMS

With the `cms` feature, `AwsLcCrypto` also implements certval-cms's content encryption and
decryption and its three kinds of recipient encryption, and two credentials hold an AWS-LC private
key: `AwsLcRecipientKey` decrypts and `AwsLcSigningKey` signs. Register the implementations on a
`CmsEnvironment` ahead of, or instead of, certval-cms's software:

```rust
use certval_awslc::AwsLcCrypto;
use certval_cms::CmsEnvironment;

let mut env = CmsEnvironment::new();
env.add_encrypt_content_callback(AwsLcCrypto::new());
env.add_decrypt_content_callback(AwsLcCrypto::new());
env.add_encrypt_key_transport_callback(AwsLcCrypto::new());
env.add_encrypt_key_agreement_callback(AwsLcCrypto::new());
env.add_encrypt_kem_callback(AwsLcCrypto::new());
env.populate_software();
```

| Operation | Coverage |
|---|---|
| Content encryption and decryption | AES-128/192/256 in CBC and GCM, except AES-192-GCM encryption |
| Key transport | RSAES-PKCS1-v1_5, RSAES-OAEP with SHA-1/256/384/512 |
| Key agreement | ephemeral-static ECDH on P-256, P-384 and P-521; the X9.63 KDF (SHA-256/384/512) and AES-128/256 key wrap by certval-cms |
| KEM | ML-KEM-512/768/1024 with HKDF (SHA-256/384/512) and AES-128/256 key wrap |
| Signing | RSA PKCS #1 v1.5 and RSASSA-PSS with SHA-256/384/512; ECDSA P-256 with SHA-256, P-384 with SHA-384, P-521 with SHA-256/384/512 |

What AWS-LC does not offer is declined, and the next implementation registered answers it:

- **AES-192-GCM encryption.** AWS-LC generates GCM nonces itself only for AES-128 and AES-256.
  Decryption takes the message's nonce, so it covers every key size.
- **AES-192 key wrap**, which AWS-LC's key wrap does not offer.
- **The X9.63 KDF**, which AWS-LC lacks. AWS-LC performs the ECDH, and certval-cms's
  `wrap_with_ecdh_secret` and `cek_from_ecdh_secret` derive and wrap or unwrap. The shared secret
  therefore leaves AWS-LC, unlike with the OpenSSL provider.
- **An ML-KEM private key holding only the seed.** `AwsLcRecipientKey` needs the expanded key, alone
  or with the seed (RFC 9935).
- **ML-DSA signing**, which this provider does not yet do.

## Testing

`cargo test` runs the unit tests and the signature tests with no setup. The signature tests verify
RSA, RSASSA-PSS, ECDSA and ML-DSA signatures made with aws-lc-rs, check each verdict against
certval's software verifier, and check that a changed message or signature is a rejection, not a
refusal. `CERTVAL_AWSLC_EXPECT_FIPS`, when set, makes the tests fail unless AWS-LC is in FIPS mode.

The collection tests verify certificates through the provider and compare against software. The
collections are named by environment variables; a test whose collection is not set reports that and
passes.

| Variable | Meaning |
|---|---|
| `CERTVAL_AWSLC_RSA_CERTS` | directory of RSA-signed certificates |
| `CERTVAL_AWSLC_ECDSA_CERTS` | directory of ECDSA-signed certificates |
| `CERTVAL_AWSLC_PSS_CERTS` | directory of RSASSA-PSS-signed certificates |
| `CERTVAL_AWSLC_MLDSA_CERTS` | directory of ML-DSA-signed certificates |
| `CERTVAL_AWSLC_SLHDSA_CERTS` | directories of SLH-DSA-signed certificates, separated as `PATH` is |

With the `cms` feature, the CMS tests cross the provider with certval-cms's RustCrypto software in
both directions, with nothing registered to fall back to: what software builds or signs, AWS-LC
decrypts or verifies, and the reverse. They cover every key transport algorithm with AES-CBC and
AES-GCM content, ECDH on each curve with each KDF hash and key wrap, ML-KEM with each parameter set,
KDF and key wrap, and each signing algorithm in the table above.

```sh
export EX=../rust-pki/certval/tests/examples
export CERTVAL_AWSLC_RSA_CERTS=$EX/PKITS_data_2048/certs
export CERTVAL_AWSLC_ECDSA_CERTS=$EX/PKITS_data_p256/certs
export CERTVAL_AWSLC_PSS_CERTS=$EX/rsapss
export CERTVAL_AWSLC_MLDSA_CERTS=$EX/pkits_ml_dsa_65/certs
export CERTVAL_AWSLC_SLHDSA_CERTS=$EX/pkits_slh_dsa_sha2_128f/certs

cargo test --features pqc,cms -- --nocapture
```

## Status

Run on macOS 26.6 with the ordinary build against rust-pki's PKITS collections: AWS-LC answered all
389 RSA and 388 ECDSA verifications that software accepted, in both interfaces, both RSASSA-PSS
ones, and all 394 for each of ML-DSA-44, -65 and -87, with no disagreements. SLH-DSA went to
software. With the `cms` feature, every CMS test passes with the ordinary build. The `fips` build
has not yet been run, with or without `cms`; the CI job `test-fips` is its first.

certval-cms is not on crates.io yet, so `Cargo.toml`'s `[patch.crates-io]` takes it from a
neighboring checkout (`../certval-cms`), and CI checks it out there. Both go when it publishes, and
this crate cannot publish before it does.

certval is consumed from crates.io. A commented `[patch.crates-io]` line in `Cargo.toml` redirects
the dependency to a local checkout for developing both crates together.

## License

Apache-2.0 OR MIT.
