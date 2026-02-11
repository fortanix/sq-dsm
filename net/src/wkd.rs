//! OpenPGP Web Key Directory client.
//!
//! A Web Key Directory is a Web service that can be queried with email
//! addresses to obtain the associated OpenPGP keys.
//!
//! It is specified in [draft-koch].
//!
//! See the [get example].
//!
//! [draft-koch]: https://datatracker.ietf.org/doc/html/draft-koch-openpgp-webkey-service
//! [get example]: get#examples
//!


// XXX: We might want to merge the 2 structs in the future and move the
// functions to methods.

use std::collections::HashMap;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::Context;

use openpgp::policy::StandardPolicy;
use sequoia_openpgp::{
    self as openpgp,
    Fingerprint,
    Cert,
    parse::Parse,
    serialize::Serialize,
    types::HashAlgorithm,
    cert::prelude::*,
};

use crate::email::EmailAddress;
use crate::Result;

/// WKD variants.
///
/// There are two variants of the URL scheme.  `Advanced` should be
/// preferred.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Variant {
    /// Advanced variant.
    ///
    /// This method uses a separate subdomain and is more flexible.
    /// This method should be preferred.
    Advanced,
    /// Direct variant.
    ///
    /// This method is deprecated.
    Direct,
}

impl Default for Variant {
    fn default() -> Self {
        Variant::Advanced
    }
}

/// Stores the parts needed to create a Web Key Directory URL.
///
/// NOTE: This is a different `Url` than [`url::Url`] (`url` crate) that is
/// actually returned with the method [to_url](Url::to_url())
#[derive(Debug, Clone)]
pub struct Url {
    domain: String,
    local_encoded: String,
    local_part: String,
}

impl fmt::Display for Url {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.build(None))
    }
}

impl Url {
    /// Returns a [`Url`] from an email address string.
    pub fn from<S: AsRef<str>>(email_address: S) -> Result<Self> {
        let email = EmailAddress::from(email_address)?;
        let local_encoded = encode_local_part(&email.local_part.to_lowercase());
        let url = Url {
            domain : email.domain,
            local_encoded,
            local_part : email.local_part,
        };
        Ok(url)
    }

    /// Returns an URL string from a [`Url`].
    pub fn build<V>(&self, variant: V) -> String
        where V: Into<Option<Variant>>
    {
        let variant = variant.into().unwrap_or_default();
        if variant == Variant::Direct {
            format!("https://{}/.well-known/openpgpkey/hu/{}?l={}",
                    self.domain, self.local_encoded, self.local_part)
        } else {
            format!("https://openpgpkey.{}/.well-known/openpgpkey/{}/hu/{}\
                    ?l={}", self.domain, self.domain, self.local_encoded,
                    self.local_part)
        }
    }

    /// Returns an [`url::Url`].
    pub fn to_url<V>(&self, variant: V) -> Result<reqwest::Url>
            where V: Into<Option<Variant>> {
        Ok(reqwest::Url::parse(self.build(variant).as_str())?)
    }

    /// Returns a [`PathBuf`].
    pub fn to_file_path<V>(&self, variant: V) -> Result<PathBuf>
        where V: Into<Option<Variant>>
    {
        // Create the directories string.
        let variant = variant.into().unwrap_or_default();
        let url = self.to_url(variant)?;
        Ok(PathBuf::from(url.path()).strip_prefix("/")?.into())
    }
}


/// Returns a 32 characters string from the local part of an email address
///
/// From [draft-koch]:
///     The so mapped local-part is hashed using the SHA-1 algorithm. The
///     resulting 160 bit digest is encoded using the Z-Base-32 method as
///     described in RFC6189, section 5.1.6. The resulting string has a
///     fixed length of 32 octets.
fn encode_local_part<S: AsRef<str>>(local_part: S) -> String {
    let local_part = local_part.as_ref();

    let mut digest = vec![0; 20];
    let mut ctx = HashAlgorithm::SHA1.context().expect("must be implemented")
        .for_digest();
    ctx.update(local_part.as_bytes());
    let _ = ctx.digest(&mut digest);

    // After z-base-32 encoding 20 bytes, it will be 32 bytes long.
    zbase32::encode(&digest[..])
}


/// Parse an HTTP response body that may contain Certs and filter them based on
/// whether they contain a userid with the given email address.
///
/// From [draft-koch]:
///
/// ```text
/// The key needs to carry a User ID packet ([RFC4880]) with that mail
/// address.
/// ```
fn parse_body<S: AsRef<str>>(body: &[u8], email_address: S)
        -> Result<Vec<Result<Cert>>> {
    let email_address = email_address.as_ref();
    // This will fail on the first packet that can not be parsed.
    let packets = CertParser::from_bytes(&body)?;
    // Collect only the correct packets.
    let certs: Vec<Result<Cert>> = packets.collect();
    if certs.is_empty() {
        return Err(crate::Error::NotFound.into());
    }

    // Collect only the Certs that contain the email in any of their userids
    let valid_certs: Vec<Result<Cert>> = certs.into_iter()
        // XXX: This filter could become a Cert method, but it adds other API
        // method to maintain
        .filter(|cert| match cert {
            Ok(cert) => cert.userids()
                .any(|uidb|
                     if let Ok(Some(a)) = uidb.userid().email() {
                         a == email_address
                     } else { false }),
            Err(_) => true,
        }).collect();
    if valid_certs.is_empty() {
        Err(crate::Error::EmailNotInUserids(email_address.into()).into())
    } else {
        Ok(valid_certs)
    }
}

/// Retrieves the Certs that contain userids with a given email address
/// from a Web Key Directory URL.
///
/// From [draft-koch]:
///
/// ```text
/// There are two variants on how to form the request URI: The advanced
/// and the direct method. Implementations MUST first try the advanced
/// method. Only if the required sub-domain does not exist, they SHOULD
/// fall back to the direct method.
///
/// [...]
///
/// The HTTP GET method MUST return the binary representation of the
/// OpenPGP key for the given mail address.
///
/// [...]
///
/// Note that the key may be revoked or expired - it is up to the
/// client to handle such conditions. To ease distribution of revoked
/// keys, a server may return revoked keys in addition to a new key.
/// The keys are returned by a single request as concatenated key
/// blocks.
/// ```
///
/// [draft-koch]: https://datatracker.ietf.org/doc/html/draft-koch-openpgp-webkey-service/#section-3.1
///
/// # Examples
///
/// ```no_run
/// # use sequoia_net::{Result, wkd};
/// # use sequoia_openpgp::Cert;
/// # async fn f() -> Result<()> {
/// let email_address = "foo@bar.baz";
/// let certs: Vec<Result<Cert>> =
///     wkd::get(&reqwest::Client::new(), &email_address).await?;
/// # Ok(())
/// # }
/// ```
// XXX: Maybe the direct method should be tried on other errors too.
// https://mailarchive.ietf.org/arch/msg/openpgp/6TxZc2dQFLKXtS0Hzmrk963EteE
pub async fn get<S: AsRef<str>>(c: &reqwest::Client, email_address: S)
                                -> Result<Vec<Result<Cert>>>
{
    let email = email_address.as_ref().to_string();
    // First, prepare URIs and client.
    let wkd_url = Url::from(&email)?;

    let advanced_uri = wkd_url.to_url(Variant::Advanced)?;
    let direct_uri = wkd_url.to_url(Variant::Direct)?;

    // First, try the Advanced Method.
    let res = if let Ok(res) = c.get(advanced_uri).send().await {
        Ok(res)
    } else {
        // Fall back to the Direct Method.
        c.get(direct_uri).send().await
    }.map_err(Error::NotFound)?;

    if res.status() == reqwest::StatusCode::OK {
        let body = res.bytes().await?;
        parse_body(&body, &email)
    } else {
        Err(crate::Error::NotFound.into())
    }
}

/// Returns all e-mail addresses from certificate's User IDs matching `domain`.
fn get_cert_domains<'a>(domain: &'a str, cert: &ValidCert<'a>) -> impl Iterator<Item = Url> + 'a
{
    cert.userids().filter_map(move |uidb| {
        uidb.userid().email().unwrap_or(None).and_then(|addr| {
            if EmailAddress::from(&addr).ok().map(|e| e.domain == domain)
                .unwrap_or(false)
            {
                Url::from(&addr).ok()
            } else {
                None
            }
        })
    })
}

/// Checks if the certificate contains a User ID for given domain.
///
/// Returns `true` if at least one of `cert`'s UserIDs contains an
/// e-mail address in the domain passed as an argument.
pub fn cert_contains_domain_userid<S>(domain: S, cert: &ValidCert) -> bool
    where S: AsRef<str>
{
    get_cert_domains(domain.as_ref(), cert).next().is_some()
}

/// Inserts a key into a Web Key Directory.
///
/// Creates a WKD hierarchy at `base_path` for `domain`, and inserts
/// the given `cert`.  If `cert` already exists in the WKD, it is
/// updated.  Any existing Certs are left in place.
///
/// # Errors
///
/// If the Cert does not have a well-formed UserID with `domain`,
/// `Error::InvalidArgument` is returned.
pub fn insert<P, S, V>(base_path: P, domain: S, variant: V,
                       cert: &Cert)
                       -> Result<()>
    where P: AsRef<Path>,
          S: AsRef<str>,
          V: Into<Option<Variant>>
{
    let base_path = base_path.as_ref();
    let domain = domain.as_ref();
    let variant = variant.into().unwrap_or_default();
    let policy = &StandardPolicy::new();
    let cert = cert.with_policy(policy, None)?;

    // First, check which UserIDs are in `domain`.
    let addresses = get_cert_domains(domain, &cert).collect::<Vec<_>>();

    // Any?
    if addresses.is_empty() {
        return Err(openpgp::Error::InvalidArgument(
            format!("Key {} does not have a User ID in {}", cert, domain)
        ).into());
    }

    // Finally, create the files.
    let mut well_known = None;
    for address in addresses.into_iter() {
        let path = base_path.join(address.to_file_path(variant)?);
        fs::create_dir_all(path.parent().expect("by construction"))?;
        let mut keyring = KeyRing::default();
        if path.is_file() {
            for t in CertParser::from_file(&path).context(
                format!("Error parsing existing file {:?}", path))?
            {
                keyring.insert(t.context(
                    format!("Malformed Cert in existing {:?}", path))?)?;
            }
        }
        keyring.insert(cert.cert().clone())?;
        let mut file = fs::File::create(&path)?;
        keyring.export(&mut file)?;

        // Keep track of the WELL_KNOWN base path.
        well_known = Some(path
                          .parent().expect("by construction")
                          .parent().expect("by construction")
                          .to_path_buf());
    }

    // Create policy file if it does not exist.
    match std::fs::OpenOptions::new().write(true).create_new(true)
        .open(well_known.expect("at least one address").join("policy"))
    {
        Err(ref e) if e.kind() == std::io::ErrorKind::AlreadyExists => (),
        r => drop(r?),
    }

    Ok(())
}

#[derive(Default)]
struct KeyRing(HashMap<Fingerprint, Cert>);

impl KeyRing {
    fn insert(&mut self, cert: Cert) -> Result<()> {
        let fp = cert.fingerprint();
        if let Some(existing) = self.0.get_mut(&fp) {
            *existing = existing.clone().merge_public(cert)?;
        } else {
            self.0.insert(fp, cert);
        }
        Ok(())
    }

    fn export(&self, o: &mut dyn std::io::Write) -> openpgp::Result<()> {
        for cert in self.0.values() {
            cert.export(o)?;
        }
        Ok(())
    }
}

/// Errors for this module.
#[derive(thiserror::Error, Debug)]
#[non_exhaustive]
pub enum Error {
    /// A requested cert was not found.
    #[error("Cert not found")]
    NotFound(#[from] reqwest::Error),
}

#[cfg(test)]
mod tests {
    use super::*;
    use self::Variant::*;

    #[test]
    fn encode_local_part_succed() {
        let encoded_part = encode_local_part("test1");
        assert_eq!("stnkabub89rpcphiz4ppbxixkwyt1pic", encoded_part);
        assert_eq!(32, encoded_part.len());
    }


    #[test]
    fn email_address_from() {
        let email_address = EmailAddress::from("test1@example.com").unwrap();
        assert_eq!(email_address.domain, "example.com");
        assert_eq!(email_address.local_part, "test1");
        assert!(EmailAddress::from("thisisnotanemailaddress").is_err());
    }

    #[test]
    fn url_roundtrip() {
        // Advanced method
        let expected_url =
            "https://openpgpkey.example.com/\
             .well-known/openpgpkey/example.com/hu/\
             stnkabub89rpcphiz4ppbxixkwyt1pic?l=test1";
        let wkd_url = Url::from("test1@example.com").unwrap();
        assert_eq!(expected_url, wkd_url.to_string());
        assert_eq!(reqwest::Url::parse(expected_url).unwrap(),
                   wkd_url.to_url(None).unwrap());
        assert_eq!(expected_url.parse::<reqwest::Url>().unwrap(),
                   wkd_url.to_url(None).unwrap());

        // Direct method
        let expected_url =
            "https://example.com/\
             .well-known/openpgpkey/hu/\
             stnkabub89rpcphiz4ppbxixkwyt1pic?l=test1";
        assert_eq!(expected_url, wkd_url.build(Direct));
        assert_eq!(reqwest::Url::parse(expected_url).unwrap(),
                   wkd_url.to_url(Direct).unwrap());
        assert_eq!(expected_url.parse::<reqwest::Url>().unwrap(),
                   wkd_url.to_url(Direct).unwrap());
    }

    #[test]
    fn url_to_file_path() {
        // Advanced method
        let expected_path =
            ".well-known/openpgpkey/example.com/hu/\
             stnkabub89rpcphiz4ppbxixkwyt1pic";
        let wkd_url = Url::from("test1@example.com").unwrap();
        assert_eq!(expected_path,
            wkd_url.to_file_path(None).unwrap().to_str().unwrap());

        // Direct method
        let expected_path =
            ".well-known/openpgpkey/hu/\
             stnkabub89rpcphiz4ppbxixkwyt1pic";
        assert_eq!(expected_path,
            wkd_url.to_file_path(Direct).unwrap().to_str().unwrap());
    }

    #[test]
    fn test_parse_body() {
        let (cert, _) = CertBuilder::new()
            .add_userid("test@example.example")
            .generate()
            .unwrap();
        let mut buffer: Vec<u8> = Vec::new();
        cert.serialize(&mut buffer).unwrap();
        let valid_certs = parse_body(&buffer, "juga@sequoia-pgp.org");
        // The userid is not in the Cert
        assert!(valid_certs.is_err());
        // XXX: add userid to the cert, instead of creating a new one
        // cert.add_userid("juga@sequoia.org");
        let (cert, _) = CertBuilder::new()
            .add_userid("test@example.example")
            .add_userid("juga@sequoia-pgp.org")
            .generate()
            .unwrap();
        cert.serialize(&mut buffer).unwrap();
        let valid_certs = parse_body(&buffer, "juga@sequoia-pgp.org");
        assert!(valid_certs.is_ok());
        assert!(valid_certs.unwrap().len() == 1);
        // XXX: Test with more Certs
    }

    #[test]
    fn wkd_generate() {
       let (cert, _) = CertBuilder::new()
            .add_userid("test1@example.example")
            .add_userid("juga@sequoia-pgp.org")
            .generate()
            .unwrap();
        let (cert2, _) = CertBuilder::new()
            .add_userid("justus@sequoia-pgp.org")
            .generate()
            .unwrap();

        let dir = tempfile::tempdir().unwrap();
        let dir_path = dir.path();
        insert(&dir_path, "sequoia-pgp.org", None, &cert).unwrap();
        insert(&dir_path, "sequoia-pgp.org", None, &cert2).unwrap();

        // justus and juga files will be generated, but not test one.
        let path = dir_path.join(
            ".well-known/openpgpkey/sequoia-pgp.org/hu\
             /jwp7xjqkdujgz5op6bpsoypg34pnrgmq");
        // Check that justus file was created
        assert!(path.is_file());
        let path = dir_path.join(
            ".well-known/openpgpkey/sequoia-pgp.org/hu\
             /7t1uqk9cwh1955776rc4z1gqf388566j");
        // Check that juga file was created.
        assert!(path.is_file());
        // Check that the file for test uid is not created.
        let path = dir_path.join(
            ".well-known/openpgpkey/example.com/hu/\
             stnkabub89rpcphiz4ppbxixkwyt1pic");
        assert!(!path.is_file());
    }

    #[test]
    fn test_get_cert_domains() -> Result<()> {
        let (cert, _) = CertBuilder::new()
             .add_userid("test1@example.example")
             .add_userid("juga@sequoia-pgp.org")
             .generate()
             .unwrap();
        let policy = &StandardPolicy::new();
        let user_ids: Vec<_> = get_cert_domains("sequoia-pgp.org", &cert.with_policy(policy, None)?)
            .map(|addr| addr.to_string())
            .collect();
        assert_eq!(user_ids, vec!["https://openpgpkey.sequoia-pgp.org/.well-known/openpgpkey/sequoia-pgp.org/hu/7t1uqk9cwh1955776rc4z1gqf388566j?l=juga"]);

        let user_ids: Vec<_> = get_cert_domains("example.example", &cert.with_policy(policy, None)?)
            .map(|addr| addr.to_string())
            .collect();
        assert_eq!(user_ids, vec!["https://openpgpkey.example.example/.well-known/openpgpkey/example.example/hu/stnkabub89rpcphiz4ppbxixkwyt1pic?l=test1"]);
        Ok(())
    }

    #[test]
    fn test_cert_contains_domain_userid() -> Result<()> {
        let (cert, _) = CertBuilder::new()
             .add_userid("test1@example.example")
             .add_userid("juga@sequoia-pgp.org")
             .generate()
             .unwrap();
        let policy = &StandardPolicy::new();
        assert!(cert_contains_domain_userid("sequoia-pgp.org", &cert.with_policy(policy, None)?));
        assert!(cert_contains_domain_userid("example.example", &cert.with_policy(policy, None)?));
        assert!(!cert_contains_domain_userid("example.org", &cert.with_policy(policy, None)?));
        Ok(())
    }
}
