//! Verifies a collection of certificates through AWS-LC and compares the result against
//! the software implementation certval ships with.
//!
//! The collections are named by environment variables rather than carried here; see `README.md`. A
//! test whose collection is not configured reports that and passes.
//!
//! The assertion that matters in every case is **agreement**: for every certificate, the platform and
//! software must reach the same verdict. A collection assembled to exercise a path validator contains
//! signatures that are supposed to fail, and those carry as much weight here as the ones that pass.

mod common;

use certval_awslc::AwsLcCrypto;
use common::*;
use std::sync::Arc;

/// Reports what the environment has configured, so a run that covers little says so plainly rather
/// than passing quietly.
#[test]
fn harness_configuration_is_reported() {
    for var in [RSA_CERTS, ECDSA_CERTS, PSS_CERTS, MLDSA_CERTS, SLHDSA_CERTS] {
        println!("{var} = {:?}", env(var));
    }
    println!("AWS-LC FIPS mode: {}", AwsLcCrypto::fips_mode_enabled());
}

/// Runs one family through both interfaces. Returns the number of pairs the platform answered
/// itself, so the caller can tell whether it was exercised or merely bypassed.
fn run_family(family: &str, dir_var: &str) -> usize {
    let Some(dir) = env(dir_var) else {
        println!("{family}: skipped, {dir_var} is not set");
        return 0;
    };
    run_collection(family, &dir)
}

fn run_collection(family: &str, dir: &str) -> usize {
    let crypto = Arc::new(AwsLcCrypto::new());

    let certs = load_certs(dir).unwrap_or_else(|e| panic!("{family}: {e}"));
    let (pairs, capped) = pairs(&certs);
    if capped {
        println!(
            "{family}: capped at {MAX_PAIRS} pairs; {} certificates in the collection yield more",
            certs.len()
        );
    }
    assert!(
        !pairs.is_empty(),
        "{family}: {} certificates yielded no issuer/subject pairs, so nothing was verified",
        certs.len()
    );

    let envs = Environments::build(&crypto);

    let message = run_message_tests(&envs, &pairs);
    message.report(family, "message");
    assert_eq!(
        message.disagreements, 0,
        "{family}: the platform and software disagreed on {} of {} certificates in the message interface",
        message.disagreements, message.pairs
    );

    let digest = run_digest_tests(&envs, &pairs);
    digest.report(family, "digest");
    assert_eq!(
        digest.disagreements, 0,
        "{family}: the platform and software disagreed on {} of {} certificates in the digest interface",
        digest.disagreements, digest.pairs
    );

    message.module_answered + digest.module_answered
}

#[test]
fn rsa_platform_agrees_with_software() {
    run_family("RSA", RSA_CERTS);
}

#[test]
fn ecdsa_platform_agrees_with_software() {
    run_family("ECDSA", ECDSA_CERTS);
}

#[test]
fn pss_platform_agrees_with_software() {
    run_family("RSASSA-PSS", PSS_CERTS);
}

/// AWS-LC verifies ML-DSA, so the platform must answer and agree with software.
#[test]
fn ml_dsa_is_answered() {
    let answered = run_family("ML-DSA", MLDSA_CERTS);
    if env(MLDSA_CERTS).is_some() {
        assert!(answered > 0, "AWS-LC answered no ML-DSA verification");
    }
}

/// AWS-LC has no SLH-DSA, so those verifications fall through to software, and the verdicts must
/// still agree (which `run_collection` asserts). The count AWS-LC answered is not zero: rust-pki's
/// SLH-DSA trees also contain a few certificates signed with ML-DSA-44, which it does verify. The
/// variable may name several collections, separated as `PATH` is.
#[test]
fn slh_dsa_falls_through_to_software() {
    let Some(dirs) = env(SLHDSA_CERTS) else {
        println!("SLH-DSA: skipped, {SLHDSA_CERTS} is not set");
        return;
    };
    for dir in std::env::split_paths(&dirs) {
        let dir = dir.to_string_lossy().into_owned();
        run_collection(&format!("SLH-DSA ({dir})"), &dir);
    }
}

/// With an RSA or ECDSA collection pointed at, the platform must actually verify something.
/// Without this a run in which every verification quietly fell through to software would look
/// identical to a working one.
#[test]
fn platform_is_not_silently_bypassed() {
    let configured: Vec<(&str, &str)> = [("RSA", RSA_CERTS), ("ECDSA", ECDSA_CERTS)]
        .into_iter()
        .filter(|(_, v)| env(v).is_some())
        .collect();
    if configured.is_empty() {
        println!("skipped, no RSA or ECDSA collection configured");
        return;
    }
    let answered: usize = configured
        .into_iter()
        .map(|(family, v)| run_family(family, v))
        .sum();
    assert!(
        answered > 0,
        "an RSA or ECDSA collection was supplied, but the platform answered no verification at all"
    );
}
