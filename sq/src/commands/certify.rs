use std::time::{SystemTime, Duration};

use sequoia_openpgp as openpgp;
use openpgp::Result;
use openpgp::cert::prelude::*;
use openpgp::packet::prelude::*;
use openpgp::packet::signature::subpacket::NotationDataFlags;
use openpgp::parse::Parse;
use openpgp::policy::Policy;
use openpgp::serialize::Serialize;
use openpgp::types::SignatureType;

use crate::Config;
use crate::parse_duration;
use crate::SECONDS_IN_YEAR;

pub fn certify(config: Config, p: &impl Policy, m: &clap::ArgMatches)
    -> Result<()>
{
    let certifier = m.value_of("certifier").unwrap();
    let cert = m.value_of("certificate").unwrap();
    let userid = m.value_of("userid").unwrap();

    let certifier = Cert::from_file(certifier)?;
    let cert = Cert::from_file(cert)?;
    let vc = cert.with_policy(p, None)?;

    let trust_depth: u8 = m.value_of("depth")
        .map(|s| s.parse()).unwrap_or(Ok(0))?;
    let trust_amount: u8 = m.value_of("amount")
        .map(|s| s.parse()).unwrap_or(Ok(120))?;
    let regex = m.values_of("regex").map(|v| v.collect::<Vec<_>>())
        .unwrap_or(vec![]);
    if trust_depth == 0 && regex.len() > 0 {
        return Err(
            anyhow::format_err!("A regex only makes sense \
                                 if the trust depth is greater than 0"));
    }

    let local = m.is_present("local");
    let non_revocable = m.is_present("non-revocable");
    let expires = m.value_of("expires");
    let expires_in = m.value_of("expires-in");


    // Find the matching User ID.
    let mut u = None;
    for ua in vc.userids() {
        if let Ok(a_userid) = std::str::from_utf8(ua.userid().value()) {
            if a_userid == userid {
                u = Some(ua.userid());
                break;
            }
        }
    }

    let userid = if let Some(userid) = u {
        userid
    } else {
        eprintln!("User ID: '{}' not found.\nValid User IDs:", userid);
        let mut have_valid = false;
        for ua in vc.userids() {
            if let Ok(u) = std::str::from_utf8(ua.userid().value()) {
                have_valid = true;
                eprintln!("  - {}", u);
            }
        }
        if ! have_valid {
            eprintln!("  - Certificate has no valid User IDs.");
        }
        return Err(anyhow::format_err!("No matching User ID found"));
    };

    // Create the certification.
    let mut builder
        = SignatureBuilder::new(SignatureType::GenericCertification);

    if trust_depth != 0 || trust_amount != 120 {
        builder = builder.set_trust_signature(trust_depth, trust_amount)?;
    }

    for regex in regex {
        builder = builder.add_regular_expression(regex)?;
    }

    if local {
        builder = builder.set_exportable_certification(false)?;
    }

    if non_revocable {
        builder = builder.set_revocable(false)?;
    }

    match (expires, expires_in) {
        (None, None) =>
            // Default expiration.
            builder = builder.set_signature_validity_period(
                Duration::new(5 * SECONDS_IN_YEAR, 0))?,
        (Some(t), None) if t == "never" =>
            // The default is no expiration; there is nothing to do.
            (),
        (Some(t), None) => {
            let now = builder.signature_creation_time()
                .unwrap_or_else(std::time::SystemTime::now);
            let expiration = SystemTime::from(
                crate::parse_iso8601(t, chrono::NaiveTime::from_hms(0, 0, 0))?);
            let validity = expiration.duration_since(now)?;
            builder = builder.set_signature_creation_time(now)?
                .set_signature_validity_period(validity)?;
        },
        (None, Some(d)) if d == "never" =>
            // The default is no expiration; there is nothing to do.
            (),
        (None, Some(d)) => {
            let d = parse_duration(d)?;
            builder = builder.set_signature_validity_period(d)?;
        },
        (Some(_), Some(_)) => unreachable!("conflicting args"),
    }

    // Each --notation takes two values.  The iterator returns them
    // one at a time, however.
    if let Some(mut n) = m.values_of("notation") {
        while let Some(name) = n.next() {
            let value = n.next().unwrap();

            let (critical, name) = if name.len() > 0
                && Some('!') == name.chars().next()
            {
                (true, &name[1..])
            } else {
                (false, name)
            };

            builder = builder.add_notation(
                name,
                value,
                NotationDataFlags::empty().set_human_readable(),
                critical)?;
        }
    }


    // Sign it.
    let mut signer = certifier.primary_key().key().clone()
        .parts_into_secret()?.into_keypair()?;

    let certification = builder
        .sign_userid_binding(
            &mut signer,
            cert.primary_key().component(),
            userid)?;
    let cert = cert.insert_packets(certification.clone())?;
    assert!(cert.clone().into_packets().any(|p| {
        match p {
            Packet::Signature(sig) => sig == certification,
            _ => false,
        }
    }));


    // And export it.
    let mut message = crate::create_or_stdout_pgp(
        m.value_of("output"), config.force,
        m.is_present("binary"), sequoia_openpgp::armor::Kind::PublicKey)?;
    cert.serialize(&mut message)?;
    message.finalize()?;

    Ok(())
}
