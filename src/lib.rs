//! AWS-LC crypto provider for [`certval`].
//!
//! [`certval`] performs hashing and signature verification through callbacks registered on a
//! [`PkiEnvironment`](certval::PkiEnvironment). This crate supplies implementations of those
//! callbacks backed by AWS-LC, through aws-lc-rs. Unlike a provider for a system library, it brings
//! its module with it: AWS-LC is compiled into the binary, and with the `fips` feature it is AWS-LC's
//! FIPS module, which is how a validated module reaches a container or a distribution that ships
//! none.
//!
//! ```no_run
//! use certval::PkiEnvironment;
//! use certval_awslc::AwsLcCrypto;
//!
//! let mut pe = PkiEnvironment::default();
//!
//! // Registering before populate_5280_pki_environment puts AWS-LC ahead of the software
//! // implementations, so it is consulted first and software answers only what it declined.
//! pe.add_calculate_hash_callback(AwsLcCrypto::new());
//! pe.add_verify_signature_message_callback(AwsLcCrypto::new());
//! pe.add_verify_signature_digest_callback(AwsLcCrypto::new());
//!
//! pe.populate_5280_pki_environment();
//! ```
//!
//! # Registration is additive
//!
//! [`PkiEnvironment`](certval::PkiEnvironment) consults registered implementations in order and
//! stops at the first verdict. The provider reports a rejection only when AWS-LC judged a signature
//! invalid; anything else it declines, and a declined verification falls through to the next
//! implementation. A caller who requires that every verification reach AWS-LC must make the
//! registration exclusive by clearing the software callbacks first:
//!
//! ```no_run
//! # use certval::PkiEnvironment;
//! # use certval_awslc::AwsLcCrypto;
//! # let mut pe = PkiEnvironment::default();
//! pe.populate_5280_pki_environment();
//! pe.clear_verify_signature_message_callbacks();
//! pe.clear_verify_signature_digest_callbacks();
//! pe.add_verify_signature_message_callback(AwsLcCrypto::new());
//! pe.add_verify_signature_digest_callback(AwsLcCrypto::new());
//! ```
//!
//! # FIPS
//!
//! With the `fips` feature, aws-lc-rs builds AWS-LC's FIPS module (which needs CMake and Go), and
//! [`AwsLcCrypto::fips_mode_enabled`] reports whether it is running in FIPS mode. The validation
//! covers the C module, built as its security policy describes, on the operating environments its
//! certificate lists; aws-lc-rs and this crate are outside it.
//!
//! aws-lc-rs documents verifying a signature over a precomputed digest as not allowed in FIPS mode,
//! so a `fips` build implements no digest interface: such a verification is declined, and whatever
//! else is registered answers it.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod algorithm;
mod provider;

pub use provider::AwsLcCrypto;
