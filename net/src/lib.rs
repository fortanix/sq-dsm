//! Discovering and publishing OpenPGP certificates over the network.
//!
//! This crate provides access to keyservers using the [HKP] protocol,
//! and searching and publishing [Web Key Directories].
//!
//! Additionally the `pks` module exposes private key operations using
//! the [PKS][PKS] protocol.
//!
//! [HKP]: https://tools.ietf.org/html/draft-shaw-openpgp-hkp-00
//! [Web Key Directories]: https://datatracker.ietf.org/doc/html/draft-koch-openpgp-webkey-service
//! [PKS]: https://gitlab.com/wiktor/pks
//!
//! # Examples
//!
//! This example demonstrates how to fetch a certificate from the
//! default key server:
//!
//! ```no_run
//! # use sequoia_openpgp::KeyID;
//! # use sequoia_net::{KeyServer, Result};
//! # async fn f() -> Result<()> {
//! let mut ks = KeyServer::default();
//! let keyid: KeyID = "31855247603831FD".parse()?;
//! println!("{:?}", ks.get(keyid).await?);
//! # Ok(())
//! # }
//! ```
//!
//! This example demonstrates how to fetch a certificate using WKD:
//!
//! ```no_run
//! # async fn f() -> sequoia_net::Result<()> {
//! let certs = sequoia_net::wkd::get(&reqwest::Client::new(), "juliett@example.org").await?;
//! # Ok(()) }
//! ```

#![doc(html_favicon_url = "https://docs.sequoia-pgp.org/favicon.png")]
#![doc(html_logo_url = "https://docs.sequoia-pgp.org/logo.svg")]
#![warn(missing_docs)]

// Re-exports of crates that we use in our API.
pub use reqwest;
use std::fmt;
use percent_encoding::{percent_encode, AsciiSet, CONTROLS};

use reqwest::{
    StatusCode,
    Url,
};

use sequoia_openpgp::{
    self as openpgp,
    cert::{Cert, CertParser},
    KeyHandle,
    packet::UserID,
    parse::Parse,
    serialize::Serialize,
};

#[macro_use] mod macros;
pub mod dane;
pub mod pks;
mod email;
pub mod updates;
pub mod wkd;

/// <https://url.spec.whatwg.org/#fragment-percent-encode-set>
const KEYSERVER_ENCODE_SET: &AsciiSet =
    // Formerly DEFAULT_ENCODE_SET
    &CONTROLS.add(b' ').add(b'"').add(b'#').add(b'<').add(b'>').add(b'`')
    .add(b'?').add(b'{').add(b'}')
    // The SKS keyserver as of version 1.1.6 is a bit picky with
    // respect to the encoding.
    .add(b'-').add(b'+').add(b'/');


/// Network policy for Sequoia.
///
/// With this policy you can control how Sequoia accesses remote
/// systems.
#[derive(PartialEq, PartialOrd, Debug, Copy, Clone)]
pub enum Policy {
    /// Do not contact remote systems.
    Offline,

    /// Only contact remote systems using anonymization techniques
    /// like TOR.
    Anonymized,

    /// Only contact remote systems using transports offering
    /// encryption and authentication like TLS.
    Encrypted,

    /// Contact remote systems even with insecure transports.
    Insecure,
}

impl fmt::Display for Policy {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", match self {
            Policy::Offline    => "Offline",
            Policy::Anonymized => "Anonymized",
            Policy::Encrypted  => "Encrypted",
            Policy::Insecure   => "Insecure",
        })
    }
}

impl Policy {
    /// Asserts that this policy allows an action requiring policy
    /// `action`.
    pub fn assert(&self, action: Policy) -> Result<()> {
        if action > *self {
            Err(Error::PolicyViolation(action).into())
        } else {
            Ok(())
        }
    }
}

impl<'a> From<&'a Policy> for u8 {
    fn from(policy: &Policy) -> Self {
        match policy {
            Policy::Offline    => 0,
            Policy::Anonymized => 1,
            Policy::Encrypted  => 2,
            Policy::Insecure   => 3,
        }
    }
}

impl TryFrom<u8> for Policy {
    type Error = TryFromU8Error;

    fn try_from(policy: u8) -> std::result::Result<Self, Self::Error> {
        match policy {
            0 => Ok(Policy::Offline),
            1 => Ok(Policy::Anonymized),
            2 => Ok(Policy::Encrypted),
            3 => Ok(Policy::Insecure),
            n => Err(TryFromU8Error(n)),
        }
    }
}

/// Indicates errors converting `u8` to `Policy`.
#[derive(Debug)]
pub struct TryFromU8Error(u8);

impl fmt::Display for TryFromU8Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Bad network policy: {}", self.0)
    }
}

impl std::error::Error for TryFromU8Error {}

/// For accessing keyservers using HKP.
#[derive(Clone)]
pub struct KeyServer {
    client: reqwest::Client,
    /// The original URL given to the constructor.
    url: Url,
    /// The URL we use for the requests.
    request_url: Url,
}

assert_send_and_sync!(KeyServer);

impl Default for KeyServer {
    fn default() -> Self {
	Self::new("hkps://keys.openpgp.org/").unwrap()
    }
}

impl KeyServer {
    /// Returns a handle for the given URL.
    pub fn new(url: &str) -> Result<Self> {
	Self::with_client(url, reqwest::Client::new())
    }

    /// Returns a handle for the given URL with a custom `Client`.
    pub fn with_client(url: &str, client: reqwest::Client) -> Result<Self> {
        let url = reqwest::Url::parse(url)?;

        let s = url.scheme();
        match s {
            "hkp" => (),
            "hkps" => (),
            _ => return Err(Error::MalformedUrl.into()),
        }

        let request_url =
            format!("{}://{}:{}",
                    match s {"hkp" => "http", "hkps" => "https",
                             _ => unreachable!()},
                    url.host().ok_or(Error::MalformedUrl)?,
                    match s {
                        "hkp" => url.port().or(Some(11371)),
                        "hkps" => url.port().or(Some(443)),
                        _ => unreachable!(),
                    }.unwrap()).parse()?;

        Ok(KeyServer { client, url, request_url })
    }

    /// Returns the keyserver's base URL.
    pub fn url(&self) -> &reqwest::Url {
        &self.url
    }

    /// Retrieves the certificate with the given handle.
    ///
    /// # Warning
    ///
    /// Returned certificates must be mistrusted, and be carefully
    /// interpreted under a policy and trust model.
    pub async fn get<H: Into<KeyHandle>>(&self, handle: H)
                                         -> Result<Vec<Result<Cert>>>
    {
        let handle = handle.into();
        let url = self.request_url.join(
            &format!("pks/lookup?op=get&options=mr&search=0x{:X}", handle))?;

        let res = self.client.get(url).send().await?;
        match res.status() {
            StatusCode::OK => {
                let body = res.bytes().await?;
                let certs = CertParser::from_bytes(&body)?.collect();
                Ok(certs)
            }
            StatusCode::NOT_FOUND => Err(Error::NotFound.into()),
            n => Err(Error::HttpStatus(n).into()),
        }
    }

    /// Retrieves certificates containing the given `UserID`.
    ///
    /// If the given [`UserID`] does not follow the de facto
    /// conventions for userids, or it does not contain a email
    /// address, an error is returned.
    ///
    ///   [`UserID`]: sequoia_openpgp::packet::UserID
    ///
    /// # Warning
    ///
    /// Returned certificates must be mistrusted, and be carefully
    /// interpreted under a policy and trust model.
    pub async fn search<U: Into<UserID>>(&self, userid: U)
                                         -> Result<Vec<Result<Cert>>>
    {
        let userid = userid.into();
        let email = userid.email().and_then(|addr| addr.ok_or_else(||
            openpgp::Error::InvalidArgument(
                "UserID does not contain an email address".into()).into()))?;
        let url = self.request_url.join(
            &format!("pks/lookup?op=get&options=mr&search={}", email))?;

        let res = self.client.get(url).send().await?;
        match res.status() {
            StatusCode::OK => {
                Ok(CertParser::from_bytes(&res.bytes().await?)?.collect())
            },
            StatusCode::NOT_FOUND => Err(Error::NotFound.into()),
            n => Err(Error::HttpStatus(n).into()),
        }
    }

    /// Sends the given key to the server.
    pub async fn send(&self, key: &Cert) -> Result<()> {
        use sequoia_openpgp::armor::{Writer, Kind};

        let url = self.request_url.join("pks/add")?;
        let mut w =  Writer::new(Vec::new(), Kind::PublicKey)?;
        key.serialize(&mut w)?;

        let armored_blob = w.finalize()?;

        // Prepare to send url-encoded data.
        let mut post_data = b"keytext=".to_vec();
        post_data.extend_from_slice(percent_encode(&armored_blob, KEYSERVER_ENCODE_SET)
                                    .collect::<String>().as_bytes());
        let length = post_data.len();

        let res = self.client.post(url)
            .header("content-type", "application/x-www-form-urlencoded")
            .header("content-length", length.to_string())
            .body(post_data).send().await?;

        match res.status() {
            StatusCode::OK => Ok(()),
            StatusCode::NOT_FOUND => Err(Error::ProtocolViolation.into()),
            n => Err(Error::HttpStatus(n).into()),
        }
    }
}

/// Results for sequoia-net.
pub type Result<T> = ::std::result::Result<T, anyhow::Error>;

#[derive(thiserror::Error, Debug)]
/// Errors returned from the network routines.
#[non_exhaustive]
pub enum Error {
    /// The network policy was violated by the given action.
    #[error("Unmet network policy requirement: {0}")]
    PolicyViolation(Policy),
    
    /// A requested cert was not found.
    #[error("Cert not found")]
    NotFound,
    /// A given keyserver URL was malformed.
    #[error("Malformed URL; expected hkp: or hkps:")]
    MalformedUrl,
    /// The server provided malformed data.
    #[error("Malformed response from server")]
    MalformedResponse,
    /// A communication partner violated the protocol.
    #[error("Protocol violation")]
    ProtocolViolation,
    /// Encountered an unexpected low-level http status.
    #[error("server returned status {0}")]
    HttpStatus(hyper::StatusCode),
    /// A `hyper::error::UrlError` occurred.
    #[error(transparent)]
    UrlError(#[from] url::ParseError),
    /// A `http::Error` occurred.
    #[error(transparent)]
    HttpError(#[from] http::Error),
    /// A `hyper::Error` occurred.
    #[error(transparent)]
    HyperError(#[from] hyper::Error),

    /// wkd errors:
    /// An email address is malformed
    #[error("Malformed email address {0}")]
    MalformedEmail(String),

    /// An email address was not found in Cert userids.
    #[error("Email address {0} not found in Cert's userids")]
    EmailNotInUserids(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls() {
        assert!(KeyServer::new("keys.openpgp.org").is_err());
        assert!(KeyServer::new("hkp://keys.openpgp.org").is_ok());
        assert!(KeyServer::new("hkps://keys.openpgp.org").is_ok());
    }
}
