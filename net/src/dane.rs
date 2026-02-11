//! DANE protocol client.
//!
//! [DANE] is a protocol for retrieving and storing OpenPGP
//! certificates in the DNS.
//!
//! [DANE]: https://datatracker.ietf.org/doc/html/rfc7929

use std::time::Duration;

use base64::{Engine as _, engine::general_purpose};

use super::email::EmailAddress;

use sequoia_openpgp::{
    self as openpgp,
    fmt,
    Cert,
    Packet,
    parse::Parse,
    serialize::SerializeInto,
    types::{HashAlgorithm, RevocationStatus},
    cert::prelude::*,
};

use super::Result;

use hickory_client::rr::{RData, RecordType};
use hickory_resolver::config::ResolverOpts;
use hickory_resolver::TokioAsyncResolver;

/// Generates a Fully Qualified Domain Name that holds the OPENPGPKEY
/// record for given `local` and `domain` parameters.
///
/// See: <https://datatracker.ietf.org/doc/html/rfc7929>
fn generate_fqdn(local: &str, domain: &str) -> Result<String> {
    let mut ctx = HashAlgorithm::SHA256.context()?.for_digest();
    ctx.update(local.as_bytes());

    let mut digest = vec![0; ctx.digest_size()];
    ctx.digest(&mut digest)?;

    Ok(format!(
        "{}._openpgpkey.{}",
        fmt::hex::encode(&digest[..28]),
        domain
    ))
}

/// Retrieves raw values for `OPENPGPKEY` records for User IDs with a
/// given e-mail address using the [DANE] protocol.
///
/// This function unconditionally validates DNSSEC records and returns
/// the found certificates only on validation success.
///
/// [DANE]: https://datatracker.ietf.org/doc/html/rfc7929
async fn get_raw(email_address: impl AsRef<str>) -> Result<Vec<Vec<u8>>> {
    let email_address = EmailAddress::from(email_address)?;
    let fqdn = generate_fqdn(&email_address.local_part, &email_address.domain)?;

    let mut opts = ResolverOpts::default();
    opts.validate = true;

    let resolver = TokioAsyncResolver::tokio(Default::default(), opts);

    let answers = resolver
        .lookup(fqdn, RecordType::OPENPGPKEY)
        .await
        .map_err(Error::NotFound)?;

    let mut bytes = vec![];

    for record in answers.iter() {
        if let RData::OPENPGPKEY(key) = record {
            bytes.push(key.public_key().into());
        }
    }

    Ok(bytes)
}

/// Retrieves certificates that contain User IDs with a given e-mail
/// address using the [DANE] protocol.
///
/// This function unconditionally validates DNSSEC records and returns
/// the found certificates only on validation success.
///
/// [DANE]: https://datatracker.ietf.org/doc/html/rfc7929
///
/// # Examples
///
/// ```no_run
/// # use sequoia_net::{Result, dane};
/// # use sequoia_openpgp::Cert;
/// # async fn f() -> Result<()> {
/// let email_address = "john@example.com";
/// let certs = dane::get(email_address).await?;
/// # Ok(())
/// # }
/// ```
pub async fn get(email_address: impl AsRef<str>) -> Result<Vec<Result<Cert>>> {
    let mut certs = vec![];

    for bytes in get_raw(email_address).await?.iter() {
        // Section 2 of RFC7929 says that a record may only contain a
        // single cert, but there may be more than one record:
        //
        //   A user that wishes to specify more than one OpenPGP key,
        //   for example, because they are transitioning to a newer
        //   stronger key, can do so by adding multiple OPENPGPKEY
        //   records.  A single OPENPGPKEY DNS record MUST only
        //   contain one OpenPGP key.
        certs.push(Cert::from_bytes(bytes));
    }

    Ok(certs)
}

/// Generates a [DANE] record for the given cert in the zonefile
/// format.
///
/// Only user IDs with email addresses in `fqdn` are considered.
///
/// If `ttl` is `None`, records are cached for three hours.
///
/// We make an effort to shrink the certificate so that it fits within
/// `size_target`.  However, this is a best-effort mechanism, and we
/// may emit larger resource records.  If `size_target` is `None`, we
/// try to shrink the certificates to 12k.
///
/// [DANE]: https://datatracker.ietf.org/doc/html/rfc7929
pub fn generate<'a, F, T, L>(cert: &ValidCert<'a>, fqdn: F, ttl: T,
                             size_target: L)
                             -> Result<Vec<String>>
where
    F: AsRef<str>,
    T: Into<Option<Duration>>,
    L: Into<Option<usize>>,
{
    generate_(cert, fqdn.as_ref(), ttl.into(), size_target.into(), false)
}

/// Generates a [DANE] record for the given cert in the zonefile
/// format.
///
/// This is like [`generate`], but uses the generic syntax for servers
/// that do not support the OPENPGPKEY RRtype.
///
/// Only user IDs with email addresses in `fqdn` are considered.
///
/// If `ttl` is `None`, records are cached for three hours.
///
/// We make an effort to shrink the certificate so that it fits within
/// `size_target`.  However, this is a best-effort mechanism, and we
/// may emit larger resource records.  If `size_target` is `None`, we
/// try to shrink the certificates to 12k.
///
/// [DANE]: https://datatracker.ietf.org/doc/html/rfc7929
pub fn generate_generic<'a, F, T, L>(cert: &ValidCert<'a>, fqdn: F, ttl: T,
                                     size_target: L)
                                     -> Result<Vec<String>>
where
    F: AsRef<str>,
    T: Into<Option<Duration>>,
    L: Into<Option<usize>>,
{
    generate_(cert, fqdn.as_ref(), ttl.into(), size_target.into(), true)
}

fn generate_<'a>(cert: &ValidCert<'a>, fqdn: &str, ttl: Option<Duration>,
                 size_target: Option<usize>, generic: bool)
                 -> Result<Vec<String>>
{
    let ttl = ttl.unwrap_or(Duration::new(3 * 60 * 60, 0));
    // This is somewhat arbitrary, but Gandi doesn't like the
    // records being larger than 16k under base64 encoding.
    let size_target = size_target.unwrap_or(16384 / 4 * 3);

    let policy = cert.policy();
    let time = cert.time();

    // First, check which UserIDs are in `domain`.
    let mut addresses: Vec<_> =
        cert.userids().filter_map(|uidb| {
            uidb.userid().email().unwrap_or(None)
                .and_then(|e| EmailAddress::from(e).ok())
                .filter(|e| e.domain == fqdn)
        })
        .collect();

    // We want to emit one record per email-address, even if multiple
    // user IDs map to that address.
    addresses.sort();
    addresses.dedup();

    // Any?
    if addresses.is_empty() {
        return Err(openpgp::Error::InvalidArgument(
            format!("Cert {} does not have a User ID in {}", cert, fqdn)
        ).into());
    }

    let mut records = Vec::new();
    for email in addresses.into_iter() {
        // Create a trimmed down view of cert, following the advice in
        // RFC7929, Section 2.1.2.  Reducing the Transferable Public
        // Key Size.

        // 1. & 2. Retain all user IDs matching the current email
        // address, no user attribute.
        let mut cert = cert.cert().clone()
            .retain_userids(
                |u| u.userid().email().unwrap_or(None)
                    .and_then(|e| EmailAddress::from(e).ok())
                    .as_ref() == Some(&email))
            .retain_user_attributes(|_| false);

        // 3a. Keep only alive subkeys.
        if cert.serialized_len() > size_target {
            cert = cert.retain_subkeys(
                |s| s.with_policy(policy, time)
                    .map(|s| s.alive().is_ok()).unwrap_or(false));
        }

        // 3b. For expired components, only keep the component and
        // revocation signatures.
        if cert.serialized_len() > size_target {
            let mut acc: Vec<Packet> = Vec::new();
            let vcert = cert.with_policy(policy, time)?;
            acc.push(vcert.primary_key().key().clone().into());
            vcert.primary_key().signatures()
                .for_each(|s| acc.push(s.clone().into()));

            for uidb in vcert.userids() {
                acc.push(uidb.userid().clone().into());
                match uidb.revocation_status() {
                    RevocationStatus::Revoked(revs) => {
                        revs.iter()
                            .for_each(|&s| acc.push(s.clone().into()));
                    },
                    RevocationStatus::CouldBe(revs) => {
                        revs.iter()
                            .for_each(|&s| acc.push(s.clone().into()));
                        uidb.signatures()
                            .for_each(|s| acc.push(s.clone().into()));
                    },
                    RevocationStatus::NotAsFarAsWeKnow => {
                        uidb.signatures()
                            .for_each(|s| acc.push(s.clone().into()));
                    },
                }
            }

            for skb in vcert.keys().subkeys() {
                acc.push(skb.key().clone().into());
                match skb.revocation_status() {
                    RevocationStatus::Revoked(revs) => {
                        revs.iter()
                            .for_each(|&s| acc.push(s.clone().into()));
                    },
                    RevocationStatus::CouldBe(revs) => {
                        revs.iter()
                            .for_each(|&s| acc.push(s.clone().into()));
                        skb.signatures()
                            .for_each(|s| acc.push(s.clone().into()));
                    },
                    RevocationStatus::NotAsFarAsWeKnow => {
                        skb.signatures()
                            .for_each(|s| acc.push(s.clone().into()));
                    },
                }
            }

            cert = Cert::from_packets(acc.into_iter())?;
        }

        // 4. Only keep the current binding signatures.
        if cert.serialized_len() > size_target {
            let mut acc: Vec<Packet> = Vec::new();
            let vcert = cert.with_policy(policy, time)?;
            acc.push(vcert.primary_key().key().clone().into());
            acc.push(vcert.primary_key().binding_signature().clone().into());
            vcert.primary_key().self_revocations()
                .chain(vcert.primary_key().other_revocations())
                .chain(vcert.primary_key().certifications())
                .for_each(|s| acc.push(s.clone().into()));

            for uidb in vcert.userids() {
                acc.push(uidb.userid().clone().into());
                acc.push(uidb.binding_signature().clone().into());
                uidb.self_revocations()
                    .chain(uidb.other_revocations())
                    .chain(uidb.certifications())
                    .for_each(|s| acc.push(s.clone().into()));
            }

            for skb in vcert.keys().subkeys() {
                acc.push(skb.key().clone().into());
                acc.push(skb.binding_signature().clone().into());
                skb.self_revocations()
                    .chain(skb.other_revocations())
                    .chain(skb.certifications())
                    .for_each(|s| acc.push(s.clone().into()));
            }

            cert = Cert::from_packets(acc.into_iter())?;
        }

        // 5. Strip third-party certifications.
        if cert.serialized_len() > size_target {
            let mut acc: Vec<Packet> = Vec::new();
            let vcert = cert.with_policy(policy, time)?;
            acc.push(vcert.primary_key().key().clone().into());
            acc.push(vcert.primary_key().binding_signature().clone().into());
            vcert.primary_key().self_revocations()
                .chain(vcert.primary_key().other_revocations())
                .for_each(|s| acc.push(s.clone().into()));

            for uidb in vcert.userids() {
                acc.push(uidb.userid().clone().into());
                acc.push(uidb.binding_signature().clone().into());
                uidb.self_revocations()
                    .chain(uidb.other_revocations())
                    .for_each(|s| acc.push(s.clone().into()));
            }

            for skb in vcert.keys().subkeys() {
                acc.push(skb.key().clone().into());
                acc.push(skb.binding_signature().clone().into());
                skb.self_revocations()
                    .chain(skb.other_revocations())
                    .for_each(|s| acc.push(s.clone().into()));
            }

            cert = Cert::from_packets(acc.into_iter())?;
        }

        let bin = cert.to_vec()?;
        if generic {
            records.push(format!(
                "; {} => {}\n{}. {} IN TYPE61 \\# {} {}",
                email,
                cert.fingerprint(),
                generate_fqdn(&email.local_part, fqdn)?,
                ttl.as_secs(),
                bin.len(),
                openpgp::fmt::hex::encode(&bin)));
        } else {
            records.push(format!(
                "; {} => {}\n{}. {} IN OPENPGPKEY {}",
                email,
                cert.fingerprint(),
                generate_fqdn(&email.local_part, fqdn)?,
                ttl.as_secs(),
                general_purpose::STANDARD.encode(&bin)));
        }
    }

    Ok(records)
}

/// Errors for this module.
#[derive(thiserror::Error, Debug)]
#[non_exhaustive]
pub enum Error {
    /// A requested cert was not found.
    #[error("Cert not found")]
    NotFound(#[from] hickory_resolver::error::ResolveError),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generating_fqdn() {
        assert_eq!(
            generate_fqdn("dkg", "debian.org").unwrap(),
            "A47CB586A51ACB93ACB9EF806F35F29131548E59E2FACD58CF6232E3._openpgpkey.debian.org"
        );
    }

    #[test]
    fn test_generating_fqdn_lower_case() {
        // Must NOT lowercase "DKG" into "dkg".
        // See: https://datatracker.ietf.org/doc/html/rfc7929#section-4
        assert_eq!(
            generate_fqdn("DKG", "DEBIAN.ORG").unwrap(),
            "46DE800073B375157AD8F4371E2713E118E3128FB1B4321ACE452F95._openpgpkey.DEBIAN.ORG"
        );
    }

    #[test]
    fn test_generate() -> Result<()> {
        let p = openpgp::policy::StandardPolicy::new();
        let (cert, _) = openpgp::cert::CertBuilder::new()
            .add_userid("dkg <dkg@debian.org>")
            .add_userid("dkg <dkg@somethingsomethinghorsesomething.org>")
            .add_transport_encryption_subkey()
            .generate()?;
        let vcert = cert.with_policy(&p, None)?;
        let records = generate(&vcert, "debian.org", None, None)?;
        assert_eq!(records.len(), 1);
        let record = &records[0];
        eprintln!("{}", record);
        assert!(record.starts_with(&format!(
            "; dkg@debian.org => {}\n\
             A47CB586A51ACB93ACB9EF806F35F29131548E59E2FACD58CF6232E3\
             ._openpgpkey.debian.org. 10800 IN OPENPGPKEY ",
            cert.fingerprint())));
        let asc = record.split(' ').last().unwrap();
        let bin = general_purpose::STANDARD.decode(&asc)?;
        let c = Cert::from_bytes(&bin)?;
        assert_eq!(c.userids().count(), 1);

        Ok(())
    }

    #[test]
    fn test_generate_aliasing() -> Result<()> {
        let p = openpgp::policy::StandardPolicy::new();
        let (cert, _) = openpgp::cert::CertBuilder::new()
            .add_userid("dkg")
            .add_userid("dkg <dkg@debian.org>")
            .add_userid("<dkg@debian.org>")
            .add_userid("dkg@debian.org")
            .add_userid("dkg <dkg@somethingsomethinghorsesomething.org>")
            .add_transport_encryption_subkey()
            .generate()?;
        let vcert = cert.with_policy(&p, None)?;
        let records = generate(&vcert, "debian.org", None, None)?;
        assert_eq!(records.len(), 1);
        let record = &records[0];
        eprintln!("{}", record);
        assert!(record.starts_with(&format!(
            "; dkg@debian.org => {}\n\
             A47CB586A51ACB93ACB9EF806F35F29131548E59E2FACD58CF6232E3\
             ._openpgpkey.debian.org. 10800 IN OPENPGPKEY ",
            cert.fingerprint())));
        let asc = record.split(' ').last().unwrap();
        let bin = general_purpose::STANDARD.decode(&asc)?;
        let c = Cert::from_bytes(&bin)?;
        assert_eq!(c.userids().count(), 3);

        Ok(())
    }

    #[test]
    fn test_generate_disjoint() -> Result<()> {
        let p = openpgp::policy::StandardPolicy::new();
        let (cert, _) = openpgp::cert::CertBuilder::new()
            .add_userid("dkg")
            .add_userid("dkg <dkg@debian.org>")
            .add_userid("dkg <evildkg@debian.org>")
            .add_userid("dkg <dkg@somethingsomethinghorsesomething.org>")
            .add_transport_encryption_subkey()
            .generate()?;
        let vcert = cert.with_policy(&p, None)?;
        let records = generate(&vcert, "debian.org", None, None)?;
        assert_eq!(records.len(), 2);
        for record in records {
            eprintln!("{}", record);
            let asc = record.split(' ').last().unwrap();
            let bin = general_purpose::STANDARD.decode(&asc)?;
            let c = Cert::from_bytes(&bin)?;
            assert_eq!(c.userids().count(), 1);
        }

        Ok(())
    }

    #[test]
    fn test_generate_generic() -> Result<()> {
        let p = openpgp::policy::StandardPolicy::new();
        let (cert, _) = openpgp::cert::CertBuilder::new()
            .add_userid("dkg <dkg@debian.org>")
            .add_transport_encryption_subkey()
            .generate()?;
        let vcert = cert.with_policy(&p, None)?;
        let records =
            generate_generic(&vcert, "debian.org", Duration::new(300, 0), None)?;
        assert_eq!(records.len(), 1);
        let record = &records[0];
        eprintln!("{}", record);
        assert!(record.starts_with(&format!(
            "; dkg@debian.org => {}\n\
             A47CB586A51ACB93ACB9EF806F35F29131548E59E2FACD58CF6232E3\
             ._openpgpkey.debian.org. 300 IN TYPE61 \\# {} ",
            cert.fingerprint(),
            cert.serialized_len())));
        let asc = record.split(' ').last().unwrap();
        let bin = openpgp::fmt::hex::decode(&asc)?;
        let c = Cert::from_bytes(&bin)?;
        assert_eq!(c.userids().count(), 1);

        Ok(())
    }
}
