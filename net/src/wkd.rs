//! OpenPGP Web Key Directory client.
//!
//! A Web Key Directory is a Web service that can be queried with email
//! addresses to obtain the associated OpenPGP keys.
//!
//! It is specified in [draft-koch].
//!
//! See the [get example].
//!
//! [draft-koch]: https://datatracker.ietf.org/doc/html/draft-koch-openpgp-webkey-service/#section-3.1
//! [get example]: get#example
//!


// XXX: We might want to merge the 2 structs in the future and move the
// functions to methods.
extern crate tempfile;
extern crate tokio_core;

use std::collections::HashMap;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

use failure::ResultExt;
use futures::{future, Future, Stream};
use hyper::{Uri, Client};
use hyper_tls::HttpsConnector;
// Hash implements the traits for Sha1
// Sha1 is used to obtain a 20 bytes digest that after zbase32 encoding can
// be used as file name
use nettle::{
    Hash, hash::insecure_do_not_use::Sha1,
};
use url;

use crate::openpgp::{
    Fingerprint,
    TPK,
};
use crate::openpgp::parse::Parse;
use crate::openpgp::serialize::Serialize;
use crate::openpgp::tpk::TPKParser;

use super::{Result, Error};

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


/// Stores the local_part and domain of an email address.
pub struct EmailAddress {
    local_part: String,
    domain: String,
}


impl EmailAddress {
    /// Returns an EmailAddress from an email address string.
    ///
    /// From [draft-koch]:
    ///
    ///```text
    /// To help with the common pattern of using capitalized names
    /// (e.g. "Joe.Doe@example.org") for mail addresses, and under the
    /// premise that almost all MTAs treat the local-part case-insensitive
    /// and that the domain-part is required to be compared
    /// case-insensitive anyway, all upper-case ASCII characters in a User
    /// ID are mapped to lowercase.  Non-ASCII characters are not changed.
    ///```
    fn from<S: AsRef<str>>(email_address: S) -> Result<Self> {
        // Ensure that is a valid email address by parsing it and return the
        // errors that it returns.
        // This is also done in hagrid.
        let email_address = email_address.as_ref();
        let v: Vec<&str> = email_address.split('@').collect();
        if v.len() != 2 {
            return Err(Error::MalformedEmail(email_address.into()).into())
        };

        // Convert to lowercase without tailoring, i.e. without taking any
        // locale into account. See:
        // https://doc.rust-lang.org/std/primitive.str.html#method.to_lowercase
        let email = EmailAddress {
            local_part: v[0].to_lowercase(),
            domain: v[1].to_lowercase()
        };
        Ok(email)
    }
}


/// Stores the parts needed to create a Web Key Directory URL.
///
/// NOTE: This is a different `Url` than [`url::Url`] (`url` crate) that is
/// actually returned with the method [to_url](#method.to_url)
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
        let local_encoded = encode_local_part(&email.local_part);
        let url = Url {
            domain : email.domain,
            local_encoded : local_encoded,
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
    pub fn to_url<V>(&self, variant: V) -> Result<url::Url>
            where V: Into<Option<Variant>> {
        let url_string = self.build(variant);
        let url_url = url::Url::parse(url_string.as_str())?;
        Ok(url_url)
    }

    /// Returns an [`hyper::Uri`].
    pub fn to_uri<V>(&self, variant: V) -> Result<Uri>
            where V: Into<Option<Variant>> {
        let url_string = self.build(variant);
        let uri = url_string.as_str().parse::<Uri>()?;
        Ok(uri)
    }

    /// Returns a [`PathBuf`].
    pub fn to_file_path<V>(&self, variant: V) -> Result<PathBuf>
        where V: Into<Option<Variant>>
    {
        // Create the directories string.
        let variant = variant.into().unwrap_or_default();
        let url = self.to_url(variant)?;
        // Can not create path_buf as:
        // let path_buf: PathBuf = [url.domain().unwrap(), url.path()]
        //    .iter().collect();
        // or:
        // let mut path_buf = PathBuf::new();
        // path_buf.push(url.domain().unwrap());
        // path_buf.push(url.path());
        // Because the domain part will disappear, dunno why.
        // url.to_file_path() would not create the directory with the domain,
        // but expect the hostname to match the domain.
        // Ignore the query part of the url, take only the domain and path.
        let string = format!("{}{}", url.domain().unwrap(), url.path());
        let path_buf = PathBuf::from(string);
        Ok(path_buf)
    }
}


/// Returns a 32 characters string from the local part of an email address
///
/// [draft-koch]:
///     The so mapped local-part is hashed using the SHA-1 algorithm. The
///     resulting 160 bit digest is encoded using the Z-Base-32 method as
///     described in [RFC6189], section 5.1.6. The resulting string has a
///     fixed length of 32 octets.
fn encode_local_part<S: AsRef<str>>(local_part: S) -> String {
    let mut hasher = Sha1::default();
    hasher.update(local_part.as_ref().as_bytes());
    // Declare and assign a 20 bytes length vector to use in hasher.result
    let mut local_hash = vec![0; 20];
    hasher.digest(&mut local_hash);
    // After z-base-32 encoding 20 bytes, it will be 32 bytes long.
    zbase32::encode_full_bytes(&local_hash[..])
}


/// Parse an HTTP response body that may contain TPKs and filter them based on
/// whether they contain a userid with the given email address.
///
/// From [draft-koch]:
///
/// ```text
/// The key needs to carry a User ID packet ([RFC4880]) with that mail
/// address.
/// ```
fn parse_body<S: AsRef<str>>(body: &[u8], email_address: S)
        -> Result<Vec<TPK>> {
    let email_address = email_address.as_ref();
    // This will fail on the first packet that can not be parsed.
    let packets = TPKParser::from_bytes(&body)?;
    // Collect only the correct packets.
    let tpks: Vec<TPK> = packets.flatten().collect();
    if tpks.is_empty() {
        return Err(Error::NotFound.into());
    }

    // Collect only the TPKs that contain the email in any of their userids
    let valid_tpks: Vec<TPK> = tpks.iter()
        // XXX: This filter could become a TPK method, but it adds other API
        // method to maintain
        .filter(|tpk| {tpk.userids()
            .any(|uidb|
                if let Ok(Some(a)) = uidb.userid().email() {
                    a == email_address
                } else { false })
        }).cloned().collect();
    if valid_tpks.is_empty() {
        Err(Error::EmailNotInUserids(email_address.into()).into())
    } else {
        Ok(valid_tpks)
    }
}


/// Retrieves the TPKs that contain userids with a given email address
/// from a Web Key Directory URL.
///
/// This function is call by [net::wkd::get](../../wkd/fn.get.html).
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
/// # Example
///
/// ```no_run
/// extern crate tokio_core;
/// use tokio_core::reactor::Core;
/// extern crate sequoia_net;
/// use sequoia_net::wkd;
///
/// let email_address = "foo@bar.baz";
/// let mut core = Core::new().unwrap();
/// let tpks = core.run(wkd::get(&email_address)).unwrap();
/// ```

// XXX: Maybe the direct method should be tried on other errors too.
// https://mailarchive.ietf.org/arch/msg/openpgp/6TxZc2dQFLKXtS0Hzmrk963EteE
pub fn get<S: AsRef<str>>(email_address: S)
                          -> impl Future<Item=Vec<TPK>, Error=failure::Error> {
    let email = email_address.as_ref().to_string();
    future::lazy(move || -> Result<_> {
        // First, prepare URIs and client.
        let wkd_url = Url::from(&email)?;

        // WKD must use TLS, so build a client for that.
        let https = HttpsConnector::new(4)?;
        let client = Client::builder().build::<_, hyper::Body>(https);

        use self::Variant::*;
        Ok((email, client, wkd_url.to_uri(Advanced)?, wkd_url.to_uri(Direct)?))
    }).and_then(|(email, client, advanced_uri, direct_uri)| {
        // First, try the Advanced Method.
        client.get(advanced_uri)
        // Fall back to the Direct Method.
            .or_else(move |_| {
                client.get(direct_uri)
            })
            .from_err()
            .map(|res| (email, res))
    }).and_then(|(email, res)| {
        // Join the response body.
        res.into_body().concat2().from_err()
            .map(|body| (email, body))
    }).and_then(|(email, body)| {
        // And parse the response.
        parse_body(&body, &email)
    })
}

/// Inserts a key into a Web Key Directory.
///
/// Creates a WKD hierarchy at `base_path` for `domain`, and inserts
/// the given `tpk`.  If `tpk` already exists in the WKD, it is
/// updated.  Any existing TPKs are left in place.
///
/// # Errors
///
/// If the TPK does not have a well-formed UserID with `domain`,
/// `Error::InvalidArgument` is returned.
pub fn insert<P, S, V>(base_path: P, domain: S, variant: V,
                       tpk: &TPK)
                       -> Result<()>
    where P: AsRef<Path>,
          S: AsRef<str>,
          V: Into<Option<Variant>>
{
    let base_path = base_path.as_ref();
    let domain = domain.as_ref();
    let variant = variant.into().unwrap_or_default();

    // First, check which UserIDs are in `domain`.
    let addresses = tpk.userids().filter_map(|uidb| {
        uidb.userid().email().unwrap_or(None).and_then(|addr| {
            if EmailAddress::from(&addr).ok().map(|e| e.domain == domain)
                .unwrap_or(false)
            {
                Url::from(&addr).ok()
            } else {
                None
            }
        })
    }).collect::<Vec<_>>();

    // Any?
    if addresses.len() == 0 {
        return Err(openpgp::Error::InvalidArgument(
            format!("Key {} does not have a UserID in {}", tpk, domain)
        ).into());
    }

    // Finally, create the files.
    for address in addresses.into_iter() {
        let path = base_path.join(address.to_file_path(variant)?);
        fs::create_dir_all(path.parent().expect("by construction"))?;
        let mut keyring = KeyRing::default();
        if path.is_file() {
            for t in TPKParser::from_file(&path).context(
                format!("Error parsing existing file {:?}", path))?
            {
                keyring.insert(t.context(
                    format!("Malformed TPK in existing {:?}", path))?)?;
            }
        }
        keyring.insert(tpk.clone())?;
        let mut file = fs::File::create(&path)?;
        keyring.export(&mut file)?;
    }

    Ok(())
}

struct KeyRing(HashMap<Fingerprint, TPK>);

impl Default for KeyRing {
    fn default() -> Self {
        Self(Default::default())
    }
}

impl KeyRing {
    fn insert(&mut self, tpk: TPK) -> Result<()> {
        let fp = tpk.fingerprint();
        if let Some(existing) = self.0.get_mut(&fp) {
            *existing = existing.clone().merge(tpk)?;
        } else {
            self.0.insert(fp, tpk);
        }
        Ok(())
    }
}

impl Serialize for KeyRing {
    fn serialize(&self, o: &mut dyn std::io::Write) -> Result<()> {
        for tpk in self.0.values() {
            tpk.serialize(o)?;
        }
        Ok(())
    }

    fn export(&self, o: &mut dyn std::io::Write) -> Result<()> {
        for tpk in self.0.values() {
            tpk.export(o)?;
        }
        Ok(())
    }
}


#[cfg(test)]
mod tests {
    use crate::openpgp::serialize::Serialize;
    use crate::openpgp::tpk::TPKBuilder;

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
        assert_eq!(expected_url, wkd_url.clone().to_string());
        assert_eq!(url::Url::parse(expected_url).unwrap(),
                   wkd_url.clone().to_url(None).unwrap());
        assert_eq!(expected_url.parse::<Uri>().unwrap(),
                   wkd_url.clone().to_uri(None).unwrap());

        // Direct method
        let expected_url =
            "https://example.com/\
             .well-known/openpgpkey/hu/\
             stnkabub89rpcphiz4ppbxixkwyt1pic?l=test1";
        assert_eq!(expected_url, wkd_url.clone().build(Direct));
        assert_eq!(url::Url::parse(expected_url).unwrap(),
                   wkd_url.clone().to_url(Direct).unwrap());
        assert_eq!(expected_url.parse::<Uri>().unwrap(),
                   wkd_url.to_uri(Direct).unwrap());
    }

    #[test]
    fn url_to_file_path() {
        // Advanced method
        let expected_path =
            "openpgpkey.example.com/\
             .well-known/openpgpkey/example.com/hu/\
             stnkabub89rpcphiz4ppbxixkwyt1pic";
        let wkd_url = Url::from("test1@example.com").unwrap();
        assert_eq!(expected_path,
            wkd_url.clone().to_file_path(None).unwrap().to_str().unwrap());

        // Direct method
        let expected_path =
            "example.com/\
             .well-known/openpgpkey/hu/\
             stnkabub89rpcphiz4ppbxixkwyt1pic";
        assert_eq!(expected_path,
            wkd_url.to_file_path(Direct).unwrap().to_str().unwrap());
    }

    #[test]
    fn test_parse_body() {
        let (tpk, _) = TPKBuilder::new()
            .add_userid("test@example.example")
            .generate()
            .unwrap();
        let mut buffer: Vec<u8> = Vec::new();
        tpk.serialize(&mut buffer).unwrap();
        let valid_tpks = parse_body(&buffer, "juga@sequoia-pgp.org");
        // The userid is not in the TPK
        assert!(valid_tpks.is_err());
        // XXX: add userid to the tpk, instead of creating a new one
        // tpk.add_userid("juga@sequoia.org");
        let (tpk, _) = TPKBuilder::new()
            .add_userid("test@example.example")
            .add_userid("juga@sequoia-pgp.org")
            .generate()
            .unwrap();
        tpk.serialize(&mut buffer).unwrap();
        let valid_tpks = parse_body(&buffer, "juga@sequoia-pgp.org");
        assert!(valid_tpks.is_ok());
        assert!(valid_tpks.unwrap().len() == 1);
        // XXX: Test with more TPKs
    }

    #[test]
    fn wkd_generate() {
       let (tpk, _) = TPKBuilder::new()
            .add_userid("test1@example.example")
            .add_userid("juga@sequoia-pgp.org")
            .generate()
            .unwrap();
        let (tpk2, _) = TPKBuilder::new()
            .add_userid("justus@sequoia-pgp.org")
            .generate()
            .unwrap();

        let dir = tempfile::tempdir().unwrap();
        let dir_path = dir.path();
        insert(&dir_path, "sequoia-pgp.org", None, &tpk).unwrap();
        insert(&dir_path, "sequoia-pgp.org", None, &tpk2).unwrap();

        // justus and juga files will be generated, but not test one.
        let path = dir_path.join(
            "openpgpkey.sequoia-pgp.org/\
             .well-known/openpgpkey/sequoia-pgp.org/hu\
             /jwp7xjqkdujgz5op6bpsoypg34pnrgmq");
        // Check that justus file was created
        assert!(path.is_file());
        let path = dir_path.join(
            "openpgpkey.sequoia-pgp.org/\
             .well-known/openpgpkey/sequoia-pgp.org/hu\
             /7t1uqk9cwh1955776rc4z1gqf388566j");
        // Check that juga file was created.
        assert!(path.is_file());
        // Check that the file for test uid is not created.
        let path = dir_path.join(
            "openpgpkey.example.com/\
             .well-known/openpgpkey/example.com/hu/\
             stnkabub89rpcphiz4ppbxixkwyt1pic");
        assert!(!path.is_file());
    }
}
