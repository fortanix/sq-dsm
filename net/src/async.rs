//! Asynchronously access keyservers.
//!
//! This module exposes the same interface, but for use within an
//! asynchronous framework.

use failure;
use futures::{future, Future, Stream};
use hyper::client::{FutureResponse, HttpConnector};
use hyper::header::{ContentLength, ContentType};
use hyper::{Client, Uri, StatusCode, Request, Method};
use hyper_tls::HttpsConnector;
use native_tls::{Certificate, TlsConnector};
use percent_encoding::{percent_encode, DEFAULT_ENCODE_SET};
use std::convert::From;
use std::io::Cursor;
use tokio_core::reactor::Handle;

use openpgp::tpk::TPK;
use openpgp::{KeyID, armor};
use sequoia_core::{Context, NetworkPolicy};

use super::{Error, Result};

define_encode_set! {
    /// Encoding used for submitting keys.
    ///
    /// The SKS keyserver as of version 1.1.6 is a bit picky with
    /// respect to the encoding.
    pub KEYSERVER_ENCODE_SET = [DEFAULT_ENCODE_SET] | {'-', '+', '/' }
}

/// For accessing keyservers using HKP.
pub struct KeyServer {
    client: Box<AClient>,
    uri: Uri,
}

const DNS_WORKER: usize = 4;

impl KeyServer {
    /// Returns a handle for the given URI.
    pub fn new(ctx: &Context, uri: &str, handle: &Handle) -> Result<Self> {
        let uri: Uri = uri.parse()?;

        let client: Box<AClient> = match uri.scheme() {
            Some("hkp") => Box::new(Client::new(handle)),
            Some("hkps") => {
                Box::new(Client::configure()
                         .connector(HttpsConnector::new(DNS_WORKER, handle)?)
                         .build(handle))
            },
            _ => return Err(Error::MalformedUri.into()),
        };

        Self::make(ctx, client, uri)
    }

    /// Returns a handle for the given URI.
    ///
    /// `cert` is used to authenticate the server.
    pub fn with_cert(ctx: &Context, uri: &str, cert: Certificate,
                     handle: &Handle) -> Result<Self> {
        let uri: Uri = uri.parse()?;

        let client: Box<AClient> = {
            let mut ssl = TlsConnector::builder()?;
            ssl.add_root_certificate(cert)?;
            let ssl = ssl.build()?;

            let mut http = HttpConnector::new(DNS_WORKER, handle);
            http.enforce_http(false);
            Box::new(Client::configure()
                     .connector(HttpsConnector::from((http, ssl)))
                     .build(handle))
        };

        Self::make(ctx, client, uri)
    }

    /// Returns a handle for the SKS keyserver pool.
    ///
    /// The pool `hkps://hkps.pool.sks-keyservers.net` provides HKP
    /// services over https.  It is authenticated using a certificate
    /// included in this library.  It is a good default choice.
    pub fn sks_pool(ctx: &Context, handle: &Handle) -> Result<Self> {
        let uri = "hkps://hkps.pool.sks-keyservers.net";
        let cert = Certificate::from_der(
            include_bytes!("sks-keyservers.netCA.der")).unwrap();
        Self::with_cert(ctx, uri, cert, handle)
    }

    /// Common code for the above functions.
    fn make(ctx: &Context, client: Box<AClient>, uri: Uri) -> Result<Self> {
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

        Ok(KeyServer{client: client, uri: uri})
    }

    /// Retrieves the key with the given `keyid`.
    pub fn get(&mut self, keyid: &KeyID)
               -> Box<Future<Item=TPK, Error=failure::Error> + 'static> {
        let uri = format!("{}/pks/lookup?op=get&options=mr&search=0x{}",
                          self.uri, keyid.to_hex()).parse();
        if let Err(e) = uri {
            // This shouldn't happen, but better safe than sorry.
            return Box::new(future::err(Error::from(e).into()));
        }

        Box::new(self.client.do_get(uri.unwrap())
                 .from_err()
                 .and_then(|res| {
                     let status = res.status();
                     res.body().concat2().from_err()
                         .and_then(move |body| match status {
                             StatusCode::Ok => {
                                 let c = Cursor::new(body.as_ref());
                                 let r = armor::Reader::new(c, armor::Kind::PublicKey);
                                 future::done(TPK::from_reader(r))
                             },
                             StatusCode::NotFound => future::err(Error::NotFound.into()),
                             n => future::err(Error::HttpStatus(n).into()),
                         })
                 }))
    }

    /// Sends the given key to the server.
    pub fn send(&mut self, key: &TPK)
                -> Box<Future<Item=(), Error=failure::Error> + 'static> {
        use openpgp::armor::{Writer, Kind};

        let uri =
            match format!("{}/pks/add", self.uri).parse() {
                Err(e) =>
                // This shouldn't happen, but better safe than sorry.
                    return Box::new(future::err(Error::from(e).into())),
                Ok(u) => u,
            };

        let mut armored_blob = vec![];
        {
            let mut w = Writer::new(&mut armored_blob, Kind::PublicKey);
            if let Err(e) = key.serialize(&mut w) {
                return Box::new(future::err(e));
            }
        }

        // Prepare to send url-encoded data.
        let mut post_data = b"keytext=".to_vec();
        post_data.extend_from_slice(percent_encode(&armored_blob, KEYSERVER_ENCODE_SET)
                                    .collect::<String>().as_bytes());

        let mut request = Request::new(Method::Post, uri);
        request.headers_mut().set(ContentType::form_url_encoded());
        request.headers_mut().set(ContentLength(post_data.len() as u64));
        request.set_body(post_data);

        Box::new(self.client.do_request(request)
                 .from_err()
                 .and_then(|res| {
                     match res.status() {
                         StatusCode::Ok => future::ok(()),
                         StatusCode::NotFound => future::err(Error::ProtocolViolation.into()),
                         n => future::err(Error::HttpStatus(n).into()),
                     }
                 }))
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
