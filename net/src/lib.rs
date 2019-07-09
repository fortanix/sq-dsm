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
//! # extern crate sequoia_openpgp as openpgp;
//! # extern crate sequoia_core;
//! # extern crate sequoia_net;
//! # use openpgp::KeyID;
//! # use sequoia_core::Context;
//! # use sequoia_net::{KeyServer, Result};
//! # fn main() { f().unwrap(); }
//! # fn f() -> Result<()> {
//! let ctx = Context::new()?;
//! let mut ks = KeyServer::sks_pool(&ctx)?;
//! let keyid = KeyID::from_hex("31855247603831FD").unwrap();
//! println!("{:?}", ks.get(&keyid));
//! Ok(())
//! # }
//! ```

#![warn(missing_docs)]

extern crate sequoia_openpgp as openpgp;
extern crate sequoia_core;
extern crate sequoia_rfc2822 as rfc2822;

#[macro_use]
extern crate failure;
extern crate futures;
extern crate http;
extern crate hyper;
extern crate hyper_tls;
extern crate native_tls;
extern crate nettle;
extern crate tokio_core;
extern crate tokio_io;
#[macro_use]
extern crate percent_encoding;
extern crate url;
extern crate zbase32;

use hyper::client::{ResponseFuture, HttpConnector};
use hyper::{Client, Request, Body};
use hyper_tls::HttpsConnector;
use native_tls::Certificate;
use std::convert::From;
use tokio_core::reactor::Core;
use url::Url;

use crate::openpgp::KeyID;
use crate::openpgp::TPK;
use sequoia_core::Context;

pub mod r#async;
use crate::r#async::url2uri;
pub mod wkd;

/// For accessing keyservers using HKP.
pub struct KeyServer {
    core: Core,
    ks: r#async::KeyServer,
}

impl KeyServer {
    /// Returns a handle for the given URI.
    pub fn new(ctx: &Context, uri: &str) -> Result<Self> {
        let core = Core::new()?;
        let ks = r#async::KeyServer::new(ctx, uri)?;
        Ok(KeyServer{core: core, ks: ks})
    }

    /// Returns a handle for the given URI.
    ///
    /// `cert` is used to authenticate the server.
    pub fn with_cert(ctx: &Context, uri: &str, cert: Certificate) -> Result<Self> {
        let core = Core::new()?;
        let ks = r#async::KeyServer::with_cert(ctx, uri, cert)?;
        Ok(KeyServer{core: core, ks: ks})
    }

    /// Returns a handle for the SKS keyserver pool.
    ///
    /// The pool `hkps://hkps.pool.sks-keyservers.net` provides HKP
    /// services over https.  It is authenticated using a certificate
    /// included in this library.  It is a good default choice.
    pub fn sks_pool(ctx: &Context) -> Result<Self> {
        let uri = "hkps://hkps.pool.sks-keyservers.net";
        let cert = Certificate::from_der(
            include_bytes!("sks-keyservers.netCA.der")).unwrap();
        Self::with_cert(ctx, uri, cert)
    }

    /// Retrieves the key with the given `keyid`.
    pub fn get(&mut self, keyid: &KeyID) -> Result<TPK> {
        self.core.run(
            self.ks.get(keyid)
        )
    }

    /// Sends the given key to the server.
    pub fn send(&mut self, key: &TPK) -> Result<()> {
        self.core.run(
            self.ks.send(key)
        )
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

/// Results for sequoia-net.
pub type Result<T> = ::std::result::Result<T, failure::Error>;

#[derive(Fail, Debug)]
/// Errors returned from the network routines.
pub enum Error {
    /// A requested key was not found.
    #[fail(display = "Key not found")]
    NotFound,
    /// A given keyserver URI was malformed.
    #[fail(display = "Malformed URI; expected hkp: or hkps:")]
    MalformedUri,
    /// The server provided malformed data.
    #[fail(display = "Malformed response from server")]
    MalformedResponse,
    /// A communication partner violated the protocol.
    #[fail(display = "Protocol violation")]
    ProtocolViolation,
    /// Encountered an unexpected low-level http status.
    #[fail(display = "Error communicating with server")]
    HttpStatus(hyper::StatusCode),
    /// A `hyper::error::UriError` occurred.
    #[fail(display = "URI Error")]
    UriError(url::ParseError),
    /// A `http::Error` occurred.
    #[fail(display = "http Error")]
    HttpError(http::Error),
    /// A `hyper::Error` occurred.
    #[fail(display = "Hyper Error")]
    HyperError(hyper::Error),
    /// A `native_tls::Error` occurred.
    #[fail(display = "TLS Error")]
    TlsError(native_tls::Error),

    /// wkd errors:
    /// An email address is malformed
    #[fail(display = "Malformed email address {}", _0)]
    MalformedEmail(String),

    /// An email address was not found in TPK userids.
    #[fail(display = "Email address {} not found in TPK's userids", _0)]
    EmailNotInUserids(String),
}

impl From<http::Error> for Error {
    fn from(e: http::Error) -> Error {
        Error::HttpError(e)
    }
}

impl From<hyper::Error> for Error {
    fn from(e: hyper::Error) -> Error {
        Error::HyperError(e)
    }
}

impl From<url::ParseError> for Error {
    fn from(e: url::ParseError) -> Error {
        Error::UriError(e)
    }
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
