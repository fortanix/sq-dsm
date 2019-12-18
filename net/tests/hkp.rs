extern crate futures;
extern crate http;
extern crate hyper;
extern crate rand;
extern crate tokio_core;
extern crate url;

use futures::Stream;
use futures::future::Future;
use futures::sync::oneshot;

use http::{Request, Response};
use hyper::{Server, Body};
use hyper::service::service_fn;
use hyper::{Method, StatusCode};
use rand::RngCore;
use rand::rngs::OsRng;
use std::io::Cursor;
use std::net::{SocketAddr, IpAddr, Ipv4Addr};
use std::thread;
use tokio_core::reactor::Core;

extern crate sequoia_openpgp as openpgp;
extern crate sequoia_core;
extern crate sequoia_net;

use crate::openpgp::armor::Reader;
use crate::openpgp::Cert;
use crate::openpgp::{Fingerprint, KeyID};
use crate::openpgp::parse::Parse;
use sequoia_core::{Context, NetworkPolicy};
use sequoia_net::KeyServer;

const RESPONSE: &'static str = "-----BEGIN PGP PUBLIC KEY BLOCK-----

xsBNBFoVcvoBCACykTKOJddF8SSUAfCDHk86cNTaYnjCoy72rMgWJsrMLnz/V16B
J9M7l6nrQ0JMnH2Du02A3w+kNb5q97IZ/M6NkqOOl7uqjyRGPV+XKwt0G5mN/ovg
8630BZAYS3QzavYf3tni9aikiGH+zTFX5pynTNfYRXNBof3Xfzl92yad2bIt4ITD
NfKPvHRko/tqWbclzzEn72gGVggt1/k/0dKhfsGzNogHxg4GIQ/jR/XcqbDFR3RC
/JJjnTOUPGsC1y82Xlu8udWBVn5mlDyxkad5laUpWWg17anvczEAyx4TTOVItLSu
43iPdKHSs9vMXWYID0bg913VusZ2Ofv690nDABEBAAG0JFRlc3R5IE1jVGVzdGZh
Y2UgPHRlc3R5QGV4YW1wbGUub3JnPsLAlAQTAQgAPhYhBD6Id8h3J0aSl1GJ9dA/
b4ZSJv6LBQJaFXL6AhsDBQkDwmcABQsJCAcCBhUICQoLAgQWAgMBAh4BAheAAAoJ
ENA/b4ZSJv6Lxo8H/1XMt+Nqa6e0SG/up3ypKe5nplA0p/9j/s2EIsP8S8uPUd+c
WS17XOmPwkNDmHeL3J6hzwL74NlYSLEtyf7WoOV74xAKQA9WkqaKPHCtpll8aFWA
ktQDLWTPeKuUuSlobAoRtO17ZmheSQzmm7JYt4Ahkxt3agqGT05OsaAey6nIKqpq
ArokvdHTZ7AFZeSJIWmuCoT9M1lo3LAtLnRGOhBMJ5dDIeOwflJwNBXlJVi4mDPK
+fumV0MbSPvZd1/ivFjSpQyudWWtv1R1nAK7+a4CPTGxPvAQkLtRsL/V+Q7F3BJG
jAn4QVx8p4t3NOPuNgcoZpLBE3sc4Nfs5/CphMLOwE0EWhVy+gEIALSpjYD+tuWC
rj6FGP6crQjQzVlH+7axoM1ooTwiPs4fzzt2iLw3CJyDUviM5F9ZBQTei635RsAR
a/CJTSQYAEU5yXXxhoe0OtwnuvsBSvVT7Fox3pkfNTQmwMvkEbodhfKpqBbDKCL8
f5A8Bb7aISsLf0XRHWDkHVqlz8LnOR3f44wEWiTeIxLc8S1QtwX/ExyW47oPsjs9
ShCmwfSpcngH/vGBRTO7WeI54xcAtKSm/20B/MgrUl5qFo17kUWot2C6KjuZKkHk
3WZmJwQz+6rTB11w4AXt8vKkptYQCkfat2FydGpgRO5dVg6aWNJefOJNkC7MmlzC
ZrrAK8FJ6jcAEQEAAcLAdgQYAQgAIBYhBD6Id8h3J0aSl1GJ9dA/b4ZSJv6LBQJa
FXL6AhsMAAoJENA/b4ZSJv6Lt7kH/jPr5wg8lcamuLj4lydYiLttvvTtDTlD1TL+
IfwVARB/ruoerlEDr0zX1t3DCEcvJDiZfOqJbXtHt70+7NzFXrYxfaNFmikMgSQT
XqHrMQho4qpseVOeJPWGzGOcrxCdw/ZgrWbkDlAU5KaIvk+M4wFPivjbtW2Ro2/F
J4I/ZHhJlIPmM+hUErHC103b08pBENXDQlXDma7LijH5kWhyfF2Ji7Ft0EjghBaW
AeGalQHjc5kAZu5R76Mwt06MEQ/HL1pIvufTFxkr/SzIv8Ih7Kexb0IrybmfD351
Pu1xwz57O4zo1VYf6TqHJzVC3OMvMUM2hhdecMUe5x6GorNaj6g=
=z5uK
-----END PGP PUBLIC KEY BLOCK-----
";

const FP: &'static str = "3E8877C877274692975189F5D03F6F865226FE8B";
const ID: &'static str = "D03F6F865226FE8B";

fn service(req: Request<Body>)
           -> Box<dyn Future<Item=Response<Body>, Error=hyper::Error> + Send> {
    let (parts, body) = req.into_parts();
    match (parts.method, parts.uri.path()) {
        (Method::GET, "/pks/lookup") => {
            if let Some(args) = parts.uri.query() {
                for (key, value) in url::form_urlencoded::parse(args.as_bytes()) {
                    match key.clone().into_owned().as_ref() {
                        "op" => assert_eq!(value, "get"),
                        "options" => assert_eq!(value, "mr"),
                        "search" => assert_eq!(value, "0xD03F6F865226FE8B"),
                        _ => panic!("Bad query: {}:{}", key, value),
                    }
                }
            } else {
                panic!("Expected query string");
            }

            Box::new(futures::future::ok(Response::new(Body::from(RESPONSE))))
        },
        (Method::POST, "/pks/add") => {
            Box::new(
                body.concat2()
		    .map(|b| {
                        for (key, value) in url::form_urlencoded::parse(b.as_ref()) {
                            match key.clone().into_owned().as_ref() {
                                "keytext" => {
			            let key = Cert::from_reader(
                                        Reader::new(Cursor::new(value.into_owned()),
                                                    None)).unwrap();
                                    assert_eq!(
                                        key.fingerprint(),
                                        Fingerprint::from_hex(FP)
                                            .unwrap());
                                },
                                _ => panic!("Bad post: {}:{}", key, value),
                            }
		        }

                        Response::new(Body::from("Ok"))
                    }))
        },
        _ => {
            Box::new(futures::future::ok(Response::builder()
                                         .status(StatusCode::NOT_FOUND)
                                         .body(Body::from("Not found")).unwrap()))
        },
    }
}

/// Starts a server on a random port.
///
/// Returns the address, a channel to drop() to kill the server, and
/// the thread handle to join the server thread.
fn start_server() -> SocketAddr {
    let (tx, rx) = oneshot::channel::<SocketAddr>();
    thread::spawn(move || {
        let (addr, server) = loop {
            let port = OsRng.next_u32() as u16;
            let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                                       port);
            if let Ok(s) = Server::try_bind(&addr) {
                break (addr, s);
            }
        };

        tx.send(addr).unwrap();
        hyper::rt::run(server
                       .serve(|| service_fn(service))
                       .map_err(|e| panic!("{}", e)));
    });

    let addr = rx.wait().unwrap();
    addr
}

#[test]
fn get() {
    let mut core = Core::new().unwrap();
    let ctx = Context::configure()
        .ephemeral()
        .network_policy(NetworkPolicy::Insecure)
        .build().unwrap();

    // Start server.
    let addr = start_server();

    let mut keyserver =
        KeyServer::new(&ctx, &format!("hkp://{}", addr)).unwrap();
    let keyid = KeyID::from_hex(ID).unwrap();
    let key = core.run(keyserver.get(&keyid)).unwrap();

    assert_eq!(key.fingerprint(),
               Fingerprint::from_hex(FP).unwrap());
}

#[test]
fn send() {
    let mut core = Core::new().unwrap();
    let ctx = Context::configure()
        .ephemeral()
        .network_policy(NetworkPolicy::Insecure)
        .build().unwrap();

    // Start server.
    let addr = start_server();
    eprintln!("{}", format!("hkp://{}", addr));
    let mut keyserver =
        KeyServer::new(&ctx, &format!("hkp://{}", addr)).unwrap();
    let key = Cert::from_reader(Reader::new(Cursor::new(RESPONSE),
                                           None)).unwrap();
    core.run(keyserver.send(&key)).unwrap();
}
