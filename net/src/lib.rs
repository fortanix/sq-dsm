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
//! # extern crate openpgp;
//! # extern crate sequoia_core;
//! # extern crate sequoia_net;
//! # use openpgp::types::KeyId;
//! # use sequoia_core::Context;
//! # use sequoia_net::{KeyServer, Result};
//! # fn main() { f().unwrap(); }
//! # fn f() -> Result<()> {
//! let ctx = Context::new("org.sequoia-pgp.example")?;
//! let mut ks = KeyServer::sks_pool(&ctx)?;
//! let keyid = KeyId::from_hex("31855247603831FD").unwrap();
//! println!("{:?}", ks.get(&keyid));
//! Ok(())
//! # }
//! ```

extern crate openpgp;
extern crate sequoia_core;

extern crate futures;
extern crate hyper;
extern crate hyper_tls;
extern crate native_tls;
extern crate tokio_core;
#[macro_use]
extern crate percent_encoding;

use percent_encoding::{percent_encode, DEFAULT_ENCODE_SET};
use self::futures::{Future, Stream};
use self::hyper::client::{FutureResponse, HttpConnector};
use self::hyper::header::{ContentLength, ContentType};
use self::hyper::{Client, Uri, StatusCode, Request, Method};
use self::hyper_tls::HttpsConnector;
use self::native_tls::{Certificate, TlsConnector};
use self::tokio_core::reactor::Core;
use std::convert::From;
use std::io::{Cursor, Read};
use std::io;

use sequoia_core::{Context, NetworkPolicy};
use openpgp::tpk::{self, TPK};
use openpgp::types::KeyId;
use openpgp::{Message, armor};

define_encode_set! {
    /// Encoding used for submitting keys.
    ///
    /// The SKS keyserver as of version 1.1.6 is a bit picky with
    /// respect to the encoding.
    pub KEYSERVER_ENCODE_SET = [DEFAULT_ENCODE_SET] | {'-', '+', '/' }
}

/// For accessing keyservers using HKP.
pub struct KeyServer {
    core: Core,
    client: Box<AClient>,
    uri: Uri,
}

const DNS_WORKER: usize = 4;

impl KeyServer {
    /// Returns a handle for the given URI.
    pub fn new(ctx: &Context, uri: &str) -> Result<Self> {
        let core = Core::new()?;
        let uri: Uri = uri.parse()?;

        let client: Box<AClient> = match uri.scheme() {
            Some("hkp") => Box::new(Client::new(&core.handle())),
            Some("hkps") => {
                Box::new(Client::configure()
                         .connector(HttpsConnector::new(DNS_WORKER,
                                                        &core.handle())?)
                         .build(&core.handle()))
            },
            _ => return Err(Error::MalformedUri),
        };

        Self::make(ctx, core, client, uri)
    }

    /// Returns a handle for the given URI.
    ///
    /// `cert` is used to authenticate the server.
    pub fn with_cert(ctx: &Context, uri: &str, cert: Certificate) -> Result<Self> {
        let core = Core::new()?;
        let uri: Uri = uri.parse()?;

        let client: Box<AClient> = {
            let mut ssl = TlsConnector::builder()?;
            ssl.add_root_certificate(cert)?;
            let ssl = ssl.build()?;

            let mut http = HttpConnector::new(DNS_WORKER, &core.handle());
            http.enforce_http(false);
            Box::new(Client::configure()
                     .connector(HttpsConnector::from((http, ssl)))
                     .build(&core.handle()))
        };

        Self::make(ctx, core, client, uri)
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

    /// Common code for the above functions.
    fn make(ctx: &Context, core: Core, client: Box<AClient>, uri: Uri) -> Result<Self> {
        let s = uri.scheme().ok_or(Error::MalformedUri)?;
        match s {
            "hkp" => ctx.network_policy().assert(NetworkPolicy::Insecure),
            "hkps" => ctx.network_policy().assert(NetworkPolicy::Encrypted),
            _ => unreachable!()
        }?;
        let uri =
            format!("{}://{}:{}",
                    match s {"hkp" => "http", "hkps" => "https", _ => unreachable!()},
                    uri.host().ok_or(Error::MalformedUri)?,
                    match s {
                        "hkp" => uri.port().or(Some(11371)),
                        "hkps" => uri.port().or(Some(443)),
                        _ => unreachable!(),
                    }.unwrap()).parse()?;

        Ok(KeyServer{core: core, client: client, uri: uri})
    }

    /// Retrieves the key with the given `keyid`.
    pub fn get(&mut self, keyid: &KeyId) -> Result<TPK> {
        let uri = format!("{}/pks/lookup?op=get&options=mr&search=0x{}",
                          self.uri, keyid.as_hex()).parse()?;
        let result = self.core.run(
            self.client.do_get(uri).and_then(|res| {
                let status = res.status();
                res.body().concat2().and_then(move |body| Ok((status, body)))
            }));

        let key: Result<::std::vec::Vec<u8>> = match result {
            Ok((status, body)) =>
                match status {
                    StatusCode::Ok => {
                        let mut c = Cursor::new(body.as_ref());
                        let mut r = armor::Reader::new(&mut c, armor::Kind::PublicKey);
                        let mut key = Vec::new();
                        r.read_to_end(&mut key)?;
                        Ok(key)
                    },
                    StatusCode::NotFound => Err(Error::NotFound),
                    n => Err(Error::from(n)),
                }
            Err(e) => Err(Error::HyperError(e)),
        };

        let m = Message::from_bytes(&key?)?;
        TPK::from_message(m).map_err(|e| Error::KeysError(e))
    }

    /// Sends the given key to the server.
    pub fn send(&mut self, key: &TPK) -> Result<()> {
        use openpgp::armor::{Writer, Kind};

        let uri = format!("{}/pks/add", self.uri).parse()?;
        let mut armored_blob = vec![];
        {
            let mut w = Writer::new(&mut armored_blob, Kind::PublicKey);
            key.serialize(&mut w)?;
        }

        // Prepare to send url-encoded data.
        let mut post_data = b"keytext=".to_vec();
        post_data.extend_from_slice(percent_encode(&armored_blob, KEYSERVER_ENCODE_SET)
                                    .collect::<String>().as_bytes());

        let mut request = Request::new(Method::Post, uri);
        request.headers_mut().set(ContentType::form_url_encoded());
        request.headers_mut().set(ContentLength(post_data.len() as u64));
        request.set_body(post_data);

        let result =
            self.core.run(
                self.client.do_request(request).and_then(|res| {
                    let status = res.status();
                    res.body().concat2().and_then(move |body| Ok((status, body)))
                }));

        match result {
            Ok((status, _body)) =>
                match status {
                    StatusCode::Ok => Ok(()),
                    StatusCode::NotFound => Err(Error::ProtocolViolation),
                    n => Err(Error::from(n)),
                }
            Err(e) => Err(Error::HyperError(e)),
        }
    }
}

trait AClient {
    fn do_get(&mut self, uri: Uri) -> FutureResponse;
    fn do_request(&mut self, request: Request) -> FutureResponse;
}

impl AClient for Client<HttpConnector> {
    fn do_get(&mut self, uri: Uri) -> FutureResponse {
        self.get(uri)
    }
    fn do_request(&mut self, request: Request) -> FutureResponse {
        self.request(request)
    }
}

impl AClient for Client<HttpsConnector<HttpConnector>> {
    fn do_get(&mut self, uri: Uri) -> FutureResponse {
        self.get(uri)
    }
    fn do_request(&mut self, request: Request) -> FutureResponse {
        self.request(request)
    }
}

/// Results for sequoia-net.
pub type Result<T> = ::std::result::Result<T, Error>;

/// Errors returned from the network routines.
#[derive(Debug)]
pub enum Error {
    /// A requested key was not found.
    NotFound,
    /// A given keyserver URI was malformed.
    MalformedUri,
    /// The server provided malformed data.
    MalformedResponse,
    /// A communication partner violated the protocol.
    ProtocolViolation,
    /// There was an error parsing the key.
    KeysError(tpk::Error),
    /// A `sequoia_core::Error` occured.
    CoreError(sequoia_core::Error),
    /// Encountered an unexpected low-level http status.
    HttpStatus(hyper::StatusCode),
    /// An `io::Error` occured.
    IoError(io::Error),
    /// A `hyper::error::UriError` occured.
    UriError(hyper::error::UriError),
    /// A `hyper::Error` occured.
    HyperError(hyper::Error),
    /// A `native_tls::Error` occured.
    TlsError(native_tls::Error),
}

impl From<tpk::Error> for Error {
    fn from(e: tpk::Error) -> Self {
        Error::KeysError(e)
    }
}

impl From<sequoia_core::Error> for Error {
    fn from(e: sequoia_core::Error) -> Self {
        Error::CoreError(e)
    }
}

impl From<hyper::StatusCode> for Error {
    fn from(status: hyper::StatusCode) -> Self {
        Error::HttpStatus(status)
    }
}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Error::IoError(error)
    }
}

impl From<hyper::Error> for Error {
    fn from(error: hyper::Error) -> Self {
        Error::HyperError(error)
    }
}

impl From<hyper::error::UriError> for Error {
    fn from(error: hyper::error::UriError) -> Self {
        Error::UriError(error)
    }
}

impl From<native_tls::Error> for Error {
    fn from(error: native_tls::Error) -> Self {
        Error::TlsError(error)
    }
}
