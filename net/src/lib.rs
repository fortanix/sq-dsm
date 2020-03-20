//! For accessing keys over the network.
//!
//! Currently, this module provides access to keyservers providing the [HKP] protocol.
//!
//! [HKP]: https://tools.ietf.org/html/draft-shaw-openpgp-hkp-00
//!
//! # Example
//!
//! We provide a very reasonable default key server backed by
//! `hkps.pool.sks-keyservers.net`, the subset of the [SKS keyserver]
//! network that uses https to protect integrity and confidentiality
//! of the communication with the client:
//!
//! [SKS keyserver]: https://www.sks-keyservers.net/overview-of-pools.php#pool_hkps
//!
//! ```no_run
//! # extern crate tokio_core;
//! # extern crate sequoia_openpgp as openpgp;
//! # extern crate sequoia_core;
//! # extern crate sequoia_net;
//! # use openpgp::KeyID;
//! # use sequoia_core::Context;
//! # use sequoia_net::{KeyServer, Result};
//! # use tokio_core::reactor::Core;
//! # fn main() { f().unwrap(); }
//! # fn f() -> Result<()> {
//! let mut core = Core::new().unwrap();
//! let ctx = Context::new()?;
//! let mut ks = KeyServer::keys_openpgp_org(&ctx)?;
//! let keyid = KeyID::from_hex("31855247603831FD").unwrap();
//! println!("{:?}", core.run(ks.get(&keyid)));
//! Ok(())
//! # }
//! ```

#![warn(missing_docs)]

extern crate sequoia_openpgp as openpgp;
extern crate sequoia_core;

extern crate futures;
extern crate http;
extern crate hyper;
extern crate hyper_tls;
extern crate native_tls;
extern crate tokio_core;
extern crate tokio_io;
extern crate percent_encoding;
extern crate url;
extern crate zbase32;

use futures::{future, Future, Stream};
use hyper::client::{ResponseFuture, HttpConnector};
use hyper::header::{CONTENT_LENGTH, CONTENT_TYPE, HeaderValue};
use hyper::{Client, Body, StatusCode, Request};
use hyper_tls::HttpsConnector;
use native_tls::{Certificate, TlsConnector};
use percent_encoding::{percent_encode, AsciiSet, CONTROLS};

use std::convert::From;
use std::io::Cursor;
use url::Url;

use crate::openpgp::Cert;
use crate::openpgp::parse::Parse;
use crate::openpgp::{KeyID, armor, serialize::Serialize};
use sequoia_core::{Context, NetworkPolicy};

pub mod wkd;

/// https://url.spec.whatwg.org/#fragment-percent-encode-set
const KEYSERVER_ENCODE_SET: &AsciiSet =
    // Formerly DEFAULT_ENCODE_SET
    &CONTROLS.add(b' ').add(b'"').add(b'#').add(b'<').add(b'>').add(b'`')
    .add(b'?').add(b'{').add(b'}')
    // The SKS keyserver as of version 1.1.6 is a bit picky with
    // respect to the encoding.
    .add(b'-').add(b'+').add(b'/');

/// For accessing keyservers using HKP.
pub struct KeyServer {
    client: Box<dyn AClient>,
    uri: Url,
}

const DNS_WORKER: usize = 4;

impl KeyServer {
    /// Returns a handle for the given URI.
    pub fn new(ctx: &Context, uri: &str) -> Result<Self> {
        let uri: Url = uri.parse()
            .or_else(|_| format!("hkps://{}", uri).parse())?;

        let client: Box<dyn AClient> = match uri.scheme() {
            "hkp" => Box::new(Client::new()),
            "hkps" => {
                Box::new(Client::builder()
                         .build(HttpsConnector::new(DNS_WORKER)?))
            },
            _ => return Err(Error::MalformedUri.into()),
        };

        Self::make(ctx, client, uri)
    }

    /// Returns a handle for the given URI.
    ///
    /// `cert` is used to authenticate the server.
    pub fn with_cert(ctx: &Context, uri: &str, cert: Certificate)
                     -> Result<Self> {
        let uri: Url = uri.parse()?;

        let client: Box<dyn AClient> = {
            let mut tls = TlsConnector::builder();
            tls.add_root_certificate(cert);
            let tls = tls.build()?;

            let mut http = HttpConnector::new(DNS_WORKER);
            http.enforce_http(false);
            Box::new(Client::builder()
                     .build(HttpsConnector::from((http, tls))))
        };

        Self::make(ctx, client, uri)
    }

    /// Returns a handle for keys.openpgp.org.
    ///
    /// The server at `hkps://keys.openpgp.org` distributes updates
    /// for OpenPGP certificates.  It is a good default choice.
    pub fn keys_openpgp_org(ctx: &Context) -> Result<Self> {
        Self::new(ctx, "hkps://keys.openpgp.org")
    }

    /// Common code for the above functions.
    fn make(ctx: &Context, client: Box<dyn AClient>, uri: Url) -> Result<Self> {
        let s = uri.scheme();
        match s {
            "hkp" => ctx.network_policy().assert(NetworkPolicy::Insecure),
            "hkps" => ctx.network_policy().assert(NetworkPolicy::Encrypted),
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

        Ok(KeyServer{client: client, uri: uri})
    }

    /// Retrieves the key with the given `keyid`.
    pub fn get(&mut self, keyid: &KeyID)
               -> Box<dyn Future<Item=Cert, Error=anyhow::Error> + 'static> {
        let keyid_want = keyid.clone();
        let uri = self.uri.join(
            &format!("pks/lookup?op=get&options=mr&search=0x{:X}", keyid));
        if let Err(e) = uri {
            // This shouldn't happen, but better safe than sorry.
            return Box::new(future::err(Error::from(e).into()));
        }

        Box::new(self.client.do_get(uri.unwrap())
                 .from_err()
                 .and_then(|res| {
                     let status = res.status();
                     res.into_body().concat2().from_err()
                         .and_then(move |body| match status {
                             StatusCode::OK => {
                                 let c = Cursor::new(body.as_ref());
                                 let r = armor::Reader::new(
                                     c,
                                     armor::ReaderMode::Tolerant(
                                         Some(armor::Kind::PublicKey)));
                                 match Cert::from_reader(r) {
                                     Ok(cert) => {
                                         if cert.keys().any(|ka| {
                                             KeyID::from(ka.fingerprint())
                                                 == keyid_want
                                         }) {
                                             future::done(Ok(cert))
                                         } else {
                                             future::err(Error::MismatchedKeyID(
                                                 keyid_want, cert).into())
                                         }
                                     },
                                     Err(e) => {
                                         future::err(e.into())
                                     }
                                 }
                             },
                             StatusCode::NOT_FOUND =>
                                 future::err(Error::NotFound.into()),
                             n => future::err(Error::HttpStatus(n).into()),
                         })
                 }))
    }

    /// Sends the given key to the server.
    pub fn send(&mut self, key: &Cert)
                -> Box<dyn Future<Item=(), Error=anyhow::Error> + 'static> {
        use crate::openpgp::armor::{Writer, Kind};

        let uri =
            match self.uri.join("pks/add") {
                Err(e) =>
                // This shouldn't happen, but better safe than sorry.
                    return Box::new(future::err(Error::from(e).into())),
                Ok(u) => u,
            };

        let mut w = match Writer::new(Vec::new(),
                                      Kind::PublicKey, &[]) {
            Ok(v) => v,
            Err(e) => return Box::new(future::err(e.into())),
        };

        if let Err(e) = key.serialize(&mut w) {
            return Box::new(future::err(e));
        }

        let armored_blob = match w.finalize() {
            Ok(v) => v,
            Err(e) => return Box::new(future::err(e.into())),
        };

        // Prepare to send url-encoded data.
        let mut post_data = b"keytext=".to_vec();
        post_data.extend_from_slice(percent_encode(&armored_blob, KEYSERVER_ENCODE_SET)
                                    .collect::<String>().as_bytes());
        let length = post_data.len();

        let mut request = match Request::post(url2uri(uri))
            .body(Body::from(post_data))
        {
            Ok(r) => r,
            Err(e) => return Box::new(future::err(Error::from(e).into())),
        };
        request.headers_mut().insert(
            CONTENT_TYPE,
            HeaderValue::from_static("application/x-www-form-urlencoded"));
        request.headers_mut().insert(
            CONTENT_LENGTH,
            HeaderValue::from_str(&format!("{}", length))
                .expect("cannot fail: only ASCII characters"));

        Box::new(self.client.do_request(request)
                 .from_err()
                 .and_then(|res| {
                     match res.status() {
                         StatusCode::OK => future::ok(()),
                         StatusCode::NOT_FOUND => future::err(Error::ProtocolViolation.into()),
                         n => future::err(Error::HttpStatus(n).into()),
                     }
                 }))
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
    /// A requested key was not found.
    #[error("Key not found")]
    NotFound,
    /// Mismatched key ID
    #[error("Mismatched key ID, expected {0}")]
    MismatchedKeyID(KeyID, Cert),
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

    #[test]
    fn uris() {
        let ctx = Context::configure()
            .network_policy(sequoia_core::NetworkPolicy::Insecure)
            .build().unwrap();

        assert!(KeyServer::new(&ctx, "keys.openpgp.org").is_ok());
        assert!(KeyServer::new(&ctx, "hkp://keys.openpgp.org").is_ok());
        assert!(KeyServer::new(&ctx, "hkps://keys.openpgp.org").is_ok());

        let ctx = Context::configure()
            .network_policy(sequoia_core::NetworkPolicy::Encrypted)
            .build().unwrap();

        assert!(KeyServer::new(&ctx, "keys.openpgp.org").is_ok());
        assert!(KeyServer::new(&ctx, "hkp://keys.openpgp.org").is_err());
        assert!(KeyServer::new(&ctx, "hkps://keys.openpgp.org").is_ok());
    }
}
