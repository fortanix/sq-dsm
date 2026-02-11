use bytes::Bytes;
use http_body_util::{combinators::BoxBody, BodyExt, Full};
use http::{Request, Response};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, StatusCode};
use hyper_util::rt::TokioIo;
use std::io::Cursor;
use std::net::{SocketAddr, IpAddr, Ipv4Addr};
use tokio::net::TcpListener;

use sequoia_openpgp::KeyID;
use sequoia_openpgp::armor::Reader;
use sequoia_openpgp::Cert;
use sequoia_openpgp::parse::Parse;
use sequoia_net::KeyServer;

const RESPONSE: &str = "-----BEGIN PGP PUBLIC KEY BLOCK-----

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

const FP: &str = "3E8877C877274692975189F5D03F6F865226FE8B";
const ID: &str = "D03F6F865226FE8B";

async fn service(
    req: Request<hyper::body::Incoming>,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> {
    match (req.method(), req.uri().path()) {
        (&Method::GET, "/pks/lookup") => {
            if let Some(args) = req.uri().query() {
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

            Ok(Response::new(full(RESPONSE)))
        },
        (&Method::POST, "/pks/add") => {
            let b = req.collect().await?.to_bytes();

            for (key, value) in url::form_urlencoded::parse(&b) {
                match key.clone().into_owned().as_ref() {
                    "keytext" => {
			let key = Cert::from_reader(
                            Reader::from_reader(Cursor::new(value.into_owned()),
                                        None)).unwrap();
                        assert_eq!(
                            key.fingerprint(),
                            FP.parse()
                                .unwrap());
                    },
                    _ => panic!("Bad post: {}:{}", key, value),
                }
	    }

            Ok(Response::new(full("Ok")))
        },
        _ => {
            Ok(Response::builder()
               .status(StatusCode::NOT_FOUND)
               .body(full("Not found")).unwrap())
        },
    }
}

fn full<T: Into<Bytes>>(chunk: T) -> BoxBody<Bytes, hyper::Error> {
    Full::new(chunk.into())
        .map_err(|never| match never {})
        .boxed()
}

/// Starts a server on a random port.
///
/// Returns the address, a channel to drop() to kill the server, and
/// the thread handle to join the server thread.
async fn start_server() -> anyhow::Result<SocketAddr> {
    let (addr, socket) = loop {
        let mut two_bytes = [0; 2];
        sequoia_openpgp::crypto::random(&mut two_bytes)?;
        let port: u16 = ((two_bytes[0] as u16) << 8) + (two_bytes[1] as u16);

        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port);
        if let Ok(s) = TcpListener::bind(&addr).await {
            break (addr, s);
        }
    };

    async fn server(l: TcpListener) {
        while let Ok((stream, _)) = l.accept().await {
            let io = TokioIo::new(stream);
            tokio::task::spawn(async move {
                if let Err(err) = http1::Builder::new()
                    .serve_connection(io, service_fn(service))
                    .await
                {
                    eprintln!("Error serving connection: {:?}", err);
                }
            });
        }
    }

    tokio::spawn(server(socket));

    Ok(addr)
}

#[tokio::test]
async fn get() -> anyhow::Result<()> {
    // Start server.
    let addr = start_server().await?;

    let keyserver = KeyServer::new(&format!("hkp://{}", addr))?;
    let keyid: KeyID = ID.parse()?;
    let keys = keyserver.get(keyid).await?;
    assert_eq!(keys.len(), 1);

    assert_eq!(keys[0].as_ref().unwrap().fingerprint(),
               FP.parse().unwrap());
    Ok(())
}

#[tokio::test]
async fn send() -> anyhow::Result<()> {
    // Start server.
    let addr = start_server().await?;
    eprintln!("{}", format!("hkp://{}", addr));
    let keyserver =
        KeyServer::new(&format!("hkp://{}", addr))?;
    let key = Cert::from_reader(Reader::from_reader(Cursor::new(RESPONSE), None))?;
    keyserver.send(&key).await?;

    Ok(())
}
