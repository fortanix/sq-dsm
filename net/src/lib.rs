//! Discovering and publishing OpenPGP certificates over the network.
//!
//! This crate provides access to keyservers using the [HKP] protocol,
//! and searching and publishing [Web Key Directories].
//!
//! [HKP]: https://tools.ietf.org/html/draft-shaw-openpgp-hkp-00
//! [Web Key Directories]: https://datatracker.ietf.org/doc/html/draft-koch-openpgp-webkey-service
//!
//! # Examples
//!
//! This example demonstrates how to fetch a certificate from the
//! default key server:
//!
//! ```no_run
//! # use sequoia_openpgp::KeyID;
//! # use sequoia_net::{KeyServer, Policy, Result};
//! # async fn f() -> Result<()> {
//! let mut ks = KeyServer::keys_openpgp_org(Policy::Encrypted)?;
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
//! let certs = sequoia_net::wkd::get("juliett@example.org").await?;
//! # Ok(()) }
//! ```

#![doc(html_favicon_url = "https://docs.sequoia-pgp.org/favicon.png")]
#![doc(html_logo_url = "https://docs.sequoia-pgp.org/logo.svg")]
#![warn(missing_docs)]

use hyper::client::{ResponseFuture, HttpConnector};
use hyper::header::{CONTENT_LENGTH, CONTENT_TYPE, HeaderValue};
use hyper::{Client, Body, StatusCode, Request};
use hyper_tls::HttpsConnector;
use native_tls::{Certificate, TlsConnector};
use percent_encoding::{percent_encode, AsciiSet, CONTROLS};

use std::convert::{From, TryFrom};
use std::fmt;
use std::io::Cursor;
use url::Url;

use sequoia_openpgp as openpgp;
use openpgp::{
    armor,
    cert::{Cert, CertParser},
    KeyHandle,
    packet::UserID,
    parse::Parse,
    serialize::Serialize,
};

pub mod updates;
pub mod wkd;

/// https://url.spec.whatwg.org/#fragment-percent-encode-set
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
            &Policy::Offline    => "Offline",
            &Policy::Anonymized => "Anonymized",
            &Policy::Encrypted  => "Encrypted",
            &Policy::Insecure   => "Insecure",
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
            &Policy::Offline    => 0,
            &Policy::Anonymized => 1,
            &Policy::Encrypted  => 2,
            &Policy::Insecure   => 3,
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
pub struct KeyServer {
    client: Box<dyn AClient>,
    uri: Url,
}

impl KeyServer {
    /// Returns a handle for the given URI.
    pub fn new(p: Policy, uri: &str) -> Result<Self> {
        let uri: Url = uri.parse()
            .or_else(|_| format!("hkps://{}", uri).parse())?;

        let client: Box<dyn AClient> = match uri.scheme() {
            "hkp" => Box::new(Client::new()),
            "hkps" => {
                Box::new(Client::builder()
                         .build(HttpsConnector::new()))
            },
            _ => return Err(Error::MalformedUri.into()),
        };

        Self::make(p, client, uri)
    }

    /// Returns a handle for the given URI.
    ///
    /// `cert` is used to authenticate the server.
    pub fn with_cert(p: Policy, uri: &str, cert: Certificate)
                     -> Result<Self> {
        let uri: Url = uri.parse()?;

        let client: Box<dyn AClient> = {
            let mut tls = TlsConnector::builder();
            tls.add_root_certificate(cert);
            let tls = tls.build()?;

            let mut http = HttpConnector::new();
            http.enforce_http(false);
            Box::new(Client::builder()
                     .build(HttpsConnector::from((http, tls.into()))))
        };

        Self::make(p, client, uri)
    }

    /// Returns a handle for keys.openpgp.org.
    ///
    /// The server at `hkps://keys.openpgp.org` distributes updates
    /// for OpenPGP certificates.  It is a good default choice.
    pub fn keys_openpgp_org(p: Policy) -> Result<Self> {
        Self::new(p, "hkps://keys.openpgp.org")
    }

    /// Common code for the above functions.
    fn make(p: Policy, client: Box<dyn AClient>, uri: Url) -> Result<Self> {
        let s = uri.scheme();
        match s {
            "hkp" => p.assert(Policy::Insecure),
            "hkps" => p.assert(Policy::Encrypted),
            _ => return Err(Error::MalformedUri.into())
        }?;
        let uri =
            format!("{}://{}:{}",
                    match s {"hkp" => "http", "hkps" => "https",
                             _ => unreachable!()},
                    uri.host().ok_or(Error::MalformedUri)?,
                    match s {
                        "hkp" => uri.port().or(Some(11371)),
                        "hkps" => uri.port().or(Some(443)),
                        _ => unreachable!(),
                    }.unwrap()).parse()?;

        Ok(KeyServer{client, uri})
    }

    /// Retrieves the certificate with the given handle.
    pub async fn get<H: Into<KeyHandle>>(&mut self, handle: H)
                                         -> Result<Cert>
    {
        // XXX: hkp can return multiple certs.  So Result<Vec<Cert>>.
        // But, what if it returns two certs, one seemingly unrelated
        // one (i.e. it doesn't pass the sanity check below).
        // Result<Vec<Result<Cert>>>?
        let handle = handle.into();
        let want_handle = handle.clone();
        let uri = self.uri.join(
            &format!("pks/lookup?op=get&options=mr&search=0x{:X}", handle))?;

        let res = self.client.do_get(uri).await?;
        match res.status() {
            StatusCode::OK => {
                let body = hyper::body::to_bytes(res.into_body()).await?;
                let r = armor::Reader::new(
                    Cursor::new(body),
                    armor::ReaderMode::Tolerant(Some(armor::Kind::PublicKey)),
                );
                let cert = Cert::from_reader(r)?;
                // XXX: This test is dodgy.  Passing it doesn't really
                // mean anything.  A malicious keyserver can attach
                // the key with the queried keyid to any certificate
                // they control.  Querying for signing-capable sukeys
                // are safe because they require a primary key binding
                // signature which the server cannot produce.
                // However, if the public key algorithm is also
                // capable of encryption (I'm looking at you, RSA),
                // then the server can simply turn it into an
                // encryption subkey.
                //
                // Returned certificates must be mistrusted, and be
                // carefully interpreted under a policy and trust
                // model.  This test doesn't provide any real
                // protection, and maybe it is better to remove it.
                // That would also help with returning multiple certs,
                // see above.
                if cert.keys().any(|ka| ka.key_handle().aliases(&want_handle)) {
                    Ok(cert)
                } else {
                    Err(Error::MismatchedKeyHandle(want_handle, cert).into())
                }
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
    ///   [`UserID`]: https://docs.sequoia-pgp.org/sequoia_openpgp/packet/struct.UserID.html
    ///
    /// Any certificates returned by the server that do not contain
    /// the email address queried for are silently discarded.
    ///
    /// # Warning
    ///
    /// Returned certificates must be mistrusted, and be carefully
    /// interpreted under a policy and trust model.
    pub async fn search<U: Into<UserID>>(&mut self, userid: U)
                                         -> Result<Vec<Cert>>
    {
        let userid = userid.into();
        let email = userid.email().and_then(|addr| addr.ok_or_else(||
            openpgp::Error::InvalidArgument(
                "UserID does not contain an email address".into()).into()))?;
        let uri = self.uri.join(
            &format!("pks/lookup?op=get&options=mr&search={}", email))?;

        let res = self.client.do_get(uri).await?;
        match res.status() {
            StatusCode::OK => {
                let body = hyper::body::to_bytes(res.into_body()).await?;
                let mut certs = Vec::new();
                for certo in CertParser::from_bytes(&body)? {
                    let cert = certo?;
                    if cert.userids().any(|uid| {
                        uid.email().ok()
                            .and_then(|addro| addro)
                            .map(|addr| addr == email)
                            .unwrap_or(false)
                    }) {
                        certs.push(cert);
                    }
                }
                Ok(certs)
            },
            StatusCode::NOT_FOUND => Err(Error::NotFound.into()),
            n => Err(Error::HttpStatus(n).into()),
        }
    }

    /// Sends the given key to the server.
    pub async fn send(&mut self, key: &Cert) -> Result<()> {
        use sequoia_openpgp::armor::{Writer, Kind};

        let uri = self.uri.join("pks/add")?;
        let mut w =  Writer::new(Vec::new(), Kind::PublicKey)?;
        key.serialize(&mut w)?;

        let armored_blob = w.finalize()?;

        // Prepare to send url-encoded data.
        let mut post_data = b"keytext=".to_vec();
        post_data.extend_from_slice(percent_encode(&armored_blob, KEYSERVER_ENCODE_SET)
                                    .collect::<String>().as_bytes());
        let length = post_data.len();

        let mut request = Request::post(url2uri(uri)).body(Body::from(post_data))?;
        request.headers_mut().insert(
            CONTENT_TYPE,
            HeaderValue::from_static("application/x-www-form-urlencoded"));
        request.headers_mut().insert(
            CONTENT_LENGTH,
            HeaderValue::from_str(&format!("{}", length))
                .expect("cannot fail: only ASCII characters"));

        let res = self.client.do_request(request).await?;
        match res.status() {
            StatusCode::OK => Ok(()),
            StatusCode::NOT_FOUND => Err(Error::ProtocolViolation.into()),
            n => Err(Error::HttpStatus(n).into()),
        }
    }
}

trait AClient {
    fn do_get(&mut self, uri: Url) -> ResponseFuture;
    fn do_request(&mut self, request: Request<Body>) -> ResponseFuture;
}

impl AClient for Client<HttpConnector> {
    fn do_get(&mut self, uri: Url) -> ResponseFuture {
        self.get(url2uri(uri))
    }
    fn do_request(&mut self, request: Request<Body>) -> ResponseFuture {
        self.request(request)
    }
}

impl AClient for Client<HttpsConnector<HttpConnector>> {
    fn do_get(&mut self, uri: Url) -> ResponseFuture {
        self.get(url2uri(uri))
    }
    fn do_request(&mut self, request: Request<Body>) -> ResponseFuture {
        self.request(request)
    }
}

pub(crate) fn url2uri(uri: Url) -> hyper::Uri {
    format!("{}", uri).parse().unwrap()
}

/// Results for sequoia-net.
pub type Result<T> = ::std::result::Result<T, anyhow::Error>;

#[derive(thiserror::Error, Debug)]
/// Errors returned from the network routines.
pub enum Error {
    /// The network policy was violated by the given action.
    #[error("Unmet network policy requirement: {0}")]
    PolicyViolation(Policy),

    /// A requested key was not found.
    #[error("Key not found")]
    NotFound,
    /// Mismatched key handle
    #[error("Mismatched key handle, expected {0}")]
    MismatchedKeyHandle(KeyHandle, Cert),
    /// A given keyserver URI was malformed.
    #[error("Malformed URI; expected hkp: or hkps:")]
    MalformedUri,
    /// The server provided malformed data.
    #[error("Malformed response from server")]
    MalformedResponse,
    /// A communication partner violated the protocol.
    #[error("Protocol violation")]
    ProtocolViolation,
    /// Encountered an unexpected low-level http status.
    #[error("Error communicating with server")]
    HttpStatus(hyper::StatusCode),
    /// A `hyper::error::UriError` occurred.
    #[error("URI Error")]
    UriError(#[from] url::ParseError),
    /// A `http::Error` occurred.
    #[error("http Error")]
    HttpError(#[from] http::Error),
    /// A `hyper::Error` occurred.
    #[error("Hyper Error")]
    HyperError(#[from] hyper::Error),
    /// A `native_tls::Error` occurred.
    #[error("TLS Error")]
    TlsError(native_tls::Error),

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

    fn ok(policy: Policy, required: Policy) {
        assert!(policy.assert(required).is_ok());
    }

    fn fail(policy: Policy, required: Policy) {
        assert!(matches!(
            policy.assert(required)
                .err().unwrap().downcast::<Error>().unwrap(),
            Error::PolicyViolation(_)));
    }

    #[test]
    fn offline() {
        let p = Policy::Offline;
        ok(p, Policy::Offline);
        fail(p, Policy::Anonymized);
        fail(p, Policy::Encrypted);
        fail(p, Policy::Insecure);
    }

    #[test]
    fn anonymized() {
        let p = Policy::Anonymized;
        ok(p, Policy::Offline);
        ok(p, Policy::Anonymized);
        fail(p, Policy::Encrypted);
        fail(p, Policy::Insecure);
    }

    #[test]
    fn encrypted() {
        let p = Policy::Encrypted;
        ok(p, Policy::Offline);
        ok(p, Policy::Anonymized);
        ok(p, Policy::Encrypted);
        fail(p, Policy::Insecure);
    }

    #[test]
    fn insecure() {
        let p = Policy::Insecure;
        ok(p, Policy::Offline);
        ok(p, Policy::Anonymized);
        ok(p, Policy::Encrypted);
        ok(p, Policy::Insecure);
    }

    #[test]
    fn uris() {
        let p = Policy::Insecure;
        assert!(KeyServer::new(p, "keys.openpgp.org").is_ok());
        assert!(KeyServer::new(p, "hkp://keys.openpgp.org").is_ok());
        assert!(KeyServer::new(p, "hkps://keys.openpgp.org").is_ok());

        let p = Policy::Encrypted;
        assert!(KeyServer::new(p, "keys.openpgp.org").is_ok());
        assert!(KeyServer::new(p, "hkp://keys.openpgp.org").is_err());
        assert!(KeyServer::new(p, "hkps://keys.openpgp.org").is_ok());
    }
}
