/// A simple signature verification program.
///
/// See https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=872271 for
/// the motivation.

use std::process::exit;

use chrono::{DateTime, offset::Utc};
use clap;
use anyhow::Context;

use sequoia_openpgp as openpgp;

use crate::openpgp::{
    Cert,
    KeyHandle,
    Result,
    parse::Parse,
};
use crate::openpgp::parse::stream::{
    DetachedVerifierBuilder,
    MessageLayer,
    MessageStructure,
    VerificationHelper,
    GoodChecksum,
    VerificationError,
};
use crate::openpgp::cert::prelude::*;
use crate::openpgp::policy::StandardPolicy as P;

mod sqv_cli;

struct VHelper<'a> {
    not_before: Option<std::time::SystemTime>,
    not_after: std::time::SystemTime,

    good: usize,
    total: usize,
    threshold: usize,

    keyrings: clap::OsValues<'a>,
}

impl<'a> std::fmt::Debug for VHelper<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.debug_struct("VHelper")
            .field("not_before", &self.not_before)
            .field("not_after", &self.not_after)
            .field("good", &self.good)
            .field("total", &self.total)
            .field("threshold", &self.threshold)
            .field("keyrings", &self.keyrings)
            .finish()
    }
}

impl<'a> VHelper<'a> {
    fn new(threshold: usize,
           not_before: Option<std::time::SystemTime>,
           not_after: std::time::SystemTime,
           keyrings: clap::OsValues<'a>) -> Self {
        VHelper {
            not_before: not_before,
            not_after: not_after,
            good: 0,
            total: 0,
            threshold: threshold,
            keyrings: keyrings,
        }
    }
}

impl<'a> VerificationHelper for VHelper<'a> {
    fn get_certs(&mut self, ids: &[crate::KeyHandle]) -> Result<Vec<Cert>> {
        let mut certs = Vec::with_capacity(ids.len());

        // Load relevant keys from the keyring.
        for filename in self.keyrings.clone() {
            for cert in CertParser::from_file(filename)
                .with_context(|| format!("Failed to parse keyring {:?}",
                                         filename))?
                .unvalidated_cert_filter(|cert, _| {
                    // We don't skip keys that are valid (not revoked,
                    // alive, etc.) so that
                    cert.keys().key_handles(ids.iter()).next().is_some()
                })
            {
                certs.push(cert.with_context(|| {
                    format!("Malformed certificate in keyring {:?}", filename)
                })?);
            }
        }

        // Dedup.  To avoid cloning the certificates, we don't use
        // Vec::dedup.
        certs.sort_by(|a, b| a.fingerprint().cmp(&b.fingerprint()));
        let count = certs.len();
        let (certs, errs) = certs.into_iter().fold(
            (Vec::with_capacity(count), Vec::new()),
            |(mut certs, mut errs), a| {
                if certs.is_empty() {
                    certs.push(a);
                } else if certs[certs.len() - 1].fingerprint() == a.fingerprint() {
                    // Merge `a` into the last element.
                    match certs.pop().expect("non-empty vec").merge_public(a) {
                        Ok(cert) => certs.push(cert),
                        Err(err) => errs.push(err),
                    }
                } else {
                    certs.push(a);
                }

                (certs, errs)
            });

        if !errs.is_empty() {
            eprintln!("Error merging duplicate keys:");
            for err in errs.iter() {
                eprintln!("  {}", err);
            }
            Err(errs.into_iter().next().expect("non-empty vec"))
        } else {
            Ok(certs)
        }
    }

    fn check(&mut self, structure: MessageStructure) -> Result<()> {
        use self::VerificationError::*;

        let mut signers = Vec::with_capacity(2);
        let mut verification_err = None;

        for layer in structure.into_iter() {
            match layer {
                MessageLayer::SignatureGroup { results } =>
                    for result in results {
                        self.total += 1;
                        match result {
                            Ok(GoodChecksum { sig, ka, .. }) => {
                                match (sig.signature_creation_time(),
                                                self.not_before,
                                                self.not_after)
                                {
                                    (None, _, _) => {
                                        eprintln!("Malformed signature:");
                                        print_error_chain(&anyhow::anyhow!(
                                            "no signature creation time"));
                                    },
                                    (Some(t), Some(not_before), not_after) => {
                                        if t < not_before {
                                            eprintln!(
                                                "Signature by {:X} was created before \
                                                 the --not-before date.",
                                                ka.key().fingerprint());
                                        } else if t > not_after {
                                            eprintln!(
                                                "Signature by {:X} was created after \
                                                 the --not-after date.",
                                                ka.key().fingerprint());
                                        } else {
                                            signers.push(ka.cert().fingerprint());
                                        }
                                    }
                                    (Some(t), None, not_after) => {
                                        if t > not_after {
                                            eprintln!(
                                                "Signature by {:X} was created after \
                                                 the --not-after date.",
                                                ka.key().fingerprint());
                                        } else {
                                            signers.push(ka.cert().fingerprint());
                                        }
                                    }
                                };
                            }
                            Err(MalformedSignature { error, .. }) => {
                                eprintln!("Signature is malformed:");
                                print_error_chain(&error);
                            }
                            Err(MissingKey { sig, .. }) => {
                                let issuers = sig.get_issuers();
                                eprintln!("Missing key {:X}, which is needed to \
                                           verify signature.",
                                          issuers.first().unwrap());
                            }
                            Err(UnboundKey { cert, error, .. }) => {
                                eprintln!("Signing key on {:X} is not bound:",
                                          cert.fingerprint());
                                print_error_chain(&error);
                            }
                            Err(BadKey { ka, error, .. }) => {
                                eprintln!("Signing key on {:X} is bad:",
                                          ka.cert().fingerprint());
                                print_error_chain(&error);
                            }
                            Err(BadSignature { error, .. }) => {
                                eprintln!("Verifying signature:");
                                print_error_chain(&error);
                                if verification_err.is_none() {
                                    verification_err = Some(error)
                                }
                            }
                        }
                    }
                MessageLayer::Compression { .. } => (),
                _ => unreachable!(),
            }
        }

        // Dedup the keys so that it is not possible to exceed the
        // threshold by duplicating signatures or by using the same
        // key.
        signers.sort();
        signers.dedup();

        self.good = signers.len();
        for signer in signers {
            println!("{:X}", signer);
        }

        Ok(())
    }
}

fn print_error_chain(err: &anyhow::Error) {
    eprintln!("           {}", err);
    err.chain().skip(1).for_each(|cause| eprintln!("  because: {}", cause));
}


fn main() -> Result<()> {
    let p = &P::new();

    let matches = sqv_cli::build().get_matches();

    let verbose = matches.is_present("verbose");

    let good_threshold
        = if let Some(good_threshold) = matches.value_of("signatures") {
            match good_threshold.parse::<usize>() {
                Ok(good_threshold) => good_threshold,
                Err(err) => {
                    eprintln!("Value passed to --signatures must be numeric: \
                               {} (got: {:?}).",
                              err, good_threshold);
                    exit(2);
                },
            }
        } else {
            1
        };
    if good_threshold < 1 {
        eprintln!("Value passed to --signatures must be >= 1 (got: {:?}).",
                  good_threshold);
        exit(2);
    }

    let file = matches.value_of_os("file").expect("'file' is required");
    let sig_file = matches.value_of_os("sig-file")
        .expect("'sig-file' is required");

    let not_before: Option<std::time::SystemTime> =
        if let Some(t) = matches.value_of("not-before") {
            Some(parse_iso8601(t, chrono::NaiveTime::from_hms(0, 0, 0))
                 .context(format!("Bad value passed to --not-before: {:?}", t))?
                 .into())
        } else {
            None
        };
    let not_after: std::time::SystemTime =
        if let Some(t) = matches.value_of("not-after") {
            Some(parse_iso8601(t, chrono::NaiveTime::from_hms(23, 59, 59))
                 .context(format!("Bad value passed to --not-after: {:?}", t))?
                 .into())
        } else {
            None
        }.unwrap_or_else(std::time::SystemTime::now);

    let keyrings = matches.values_of_os("keyring")
        .expect("No keyring specified.");

    let h = VHelper::new(good_threshold, not_before, not_after, keyrings);

    let mut v =
        DetachedVerifierBuilder::from_file(sig_file)?.with_policy(p, None, h)?;
    v.verify_file(file)?;

    let h = v.into_helper();

    if verbose {
        eprintln!("{} of {} signatures are valid (threshold is: {}).",
                  h.good, h.total, good_threshold);
    }

    exit(if h.good >= good_threshold { 0 } else { 1 });
}

/// Parses the given string depicting a ISO 8601 timestamp.
fn parse_iso8601(s: &str, pad_date_with: chrono::NaiveTime)
                 -> Result<DateTime<Utc>>
{
    // If you modify this function this function, synchronize the
    // changes with the copy in sqv.rs!
    for f in &[
        "%Y-%m-%dT%H:%M:%S%#z",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%dT%H:%M%#z",
        "%Y-%m-%dT%H:%M",
        "%Y-%m-%dT%H%#z",
        "%Y-%m-%dT%H",
        "%Y%m%dT%H%M%S%#z",
        "%Y%m%dT%H%M%S",
        "%Y%m%dT%H%M%#z",
        "%Y%m%dT%H%M",
        "%Y%m%dT%H%#z",
        "%Y%m%dT%H",
    ] {
        if f.ends_with("%#z") {
            if let Ok(d) = DateTime::parse_from_str(s, *f) {
                return Ok(d.into());
            }
        } else {
            if let Ok(d) = chrono::NaiveDateTime::parse_from_str(s, *f) {
                return Ok(DateTime::from_utc(d, Utc));
            }
        }
    }
    for f in &[
        "%Y-%m-%d",
        "%Y-%m",
        "%Y-%j",
        "%Y%m%d",
        "%Y%m",
        "%Y%j",
        "%Y",
    ] {
        if let Ok(d) = chrono::NaiveDate::parse_from_str(s, *f) {
            return Ok(DateTime::from_utc(d.and_time(pad_date_with), Utc));
        }
    }
    Err(anyhow::anyhow!("Malformed ISO8601 timestamp: {}", s))
}

#[test]
fn test_parse_iso8601() {
    let z = chrono::NaiveTime::from_hms(0, 0, 0);
    parse_iso8601("2017-03-04T13:25:35Z", z).unwrap();
    parse_iso8601("2017-03-04T13:25:35+08:30", z).unwrap();
    parse_iso8601("2017-03-04T13:25:35", z).unwrap();
    parse_iso8601("2017-03-04T13:25Z", z).unwrap();
    parse_iso8601("2017-03-04T13:25", z).unwrap();
    // parse_iso8601("2017-03-04T13Z", z).unwrap(); // XXX: chrono doesn't like
    // parse_iso8601("2017-03-04T13", z).unwrap(); // ditto
    parse_iso8601("2017-03-04", z).unwrap();
    // parse_iso8601("2017-03", z).unwrap(); // ditto
    parse_iso8601("2017-031", z).unwrap();
    parse_iso8601("20170304T132535Z", z).unwrap();
    parse_iso8601("20170304T132535+0830", z).unwrap();
    parse_iso8601("20170304T132535", z).unwrap();
    parse_iso8601("20170304T1325Z", z).unwrap();
    parse_iso8601("20170304T1325", z).unwrap();
    // parse_iso8601("20170304T13Z", z).unwrap(); // ditto
    // parse_iso8601("20170304T13", z).unwrap(); // ditto
    parse_iso8601("20170304", z).unwrap();
    // parse_iso8601("201703", z).unwrap(); // ditto
    parse_iso8601("2017031", z).unwrap();
    // parse_iso8601("2017", z).unwrap(); // ditto
}
