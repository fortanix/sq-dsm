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
extern crate tokio_core;

use std::fmt;

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

use crate::openpgp::TPK;
use crate::openpgp::parse::Parse;
use crate::openpgp::tpk::TPKParser;

use super::{Result, Error};


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
#[derive(Clone)]
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
    pub fn build<T>(&self, direct_method: T) -> String
            where T: Into<Option<bool>> {
        let direct_method = direct_method.into().unwrap_or(false);
        if direct_method {
            format!("https://{}/.well-known/openpgpkey/hu/{}?l={}",
                    self.domain, self.local_encoded, self.local_part)
        } else {
            format!("https://openpgpkey.{}/.well-known/openpgpkey/{}/hu/{}\
                    ?l={}", self.domain, self.domain, self.local_encoded,
                    self.local_part)
        }
    }

    /// Returns an [`url::Url`].
    pub fn to_url<T>(&self, direct_method: T) -> Result<url::Url>
            where T: Into<Option<bool>> {
        let url_string = self.build(direct_method);
        let url_url = url::Url::parse(url_string.as_str())?;
        Ok(url_url)
    }

    /// Returns an [`hyper::Uri`].
    pub fn to_uri<T>(&self, direct_method: T) -> Result<Uri>
            where T: Into<Option<bool>> {
        let url_string = self.build(direct_method);
        let uri = url_string.as_str().parse::<Uri>()?;
        Ok(uri)
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
pub(crate) fn parse_body<S: AsRef<str>>(body: &[u8], email_address: S)
        -> Result<Vec<TPK>> {
    let email_address = email_address.as_ref();
    // This will fail on the first packet that can not be parsed.
    let packets = TPKParser::from_bytes(&body)?;
    // Collect only the correct packets.
    let tpks: Vec<TPK> = packets.flatten().collect();
    // Collect only the TPKs that contain the email in any of their userids
    let valid_tpks: Vec<TPK> = tpks.iter()
        // XXX: This filter could become a TPK method, but it adds other API
        // method to maintain
        .filter(|tpk| {tpk.userids()
            .any(|uidb|
                if let Ok(Some(a)) = uidb.userid().address() {
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

        Ok((email, client, wkd_url.to_uri(false)?, wkd_url.to_uri(true)?))
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


#[cfg(test)]
mod tests {
    use crate::openpgp::serialize::Serialize;
    use crate::openpgp::tpk::TPKBuilder;

    use super::*;

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
        assert_eq!(expected_url, wkd_url.clone().build(true));
        assert_eq!(url::Url::parse(expected_url).unwrap(),
                   wkd_url.clone().to_url(true).unwrap());
        assert_eq!(expected_url.parse::<Uri>().unwrap(),
                   wkd_url.to_uri(true).unwrap());
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
}
