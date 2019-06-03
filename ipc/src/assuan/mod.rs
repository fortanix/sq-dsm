//! Assuan RPC support.

#![warn(missing_docs)]

use std::cmp;
use std::io::{Write, BufReader};
use std::mem;
use std::path::Path;

use lalrpop_util::ParseError;

use futures::{Async, Future, Stream};
use tokio::net::UnixStream;
use tokio_io::io;
use tokio_io::AsyncRead;

use Error;
use Result;

mod lexer;

// Maximum line length of the reference implementation.
const MAX_LINE_LENGTH: usize = 1000;

// Load the generated code.
lalrpop_util::lalrpop_mod!(
    #[allow(missing_docs)] grammar, "/assuan/grammar.rs");

/// A connection to an Assuan server.
pub struct Client {
    r: ResponseStream,
    w: io::WriteHalf<UnixStream>,
}

impl Client {
    /// Connects to the server.
    pub fn connect<P>(path: P)
        -> impl Future<Item = Client, Error = failure::Error>
        where P: AsRef<Path>
    {
        UnixStream::connect(path).from_err()
            .and_then(ConnectionFuture::new)
    }

    /// Sends a command to the server.
    ///
    /// Returns all server responses until the first `Response::Ok`,
    /// `Response::Error`, or `Response::Inquire`.  `Ok` and `Error`
    /// indicate success and failure.
    ///
    /// `Inquire` means that the server requires more information to
    /// complete the request.  This information may be provided using
    /// [`Connection::data()`], or the operation may be canceled using
    /// [`Connection::cancel()`].
    ///
    /// [`Connection::data()`]: #method.data
    /// [`Connection::cancel()`]: #method.cancel
    ///
    /// Note: `command` is passed as-is.  Control characters, like
    /// `%`, must be %-escaped.
    pub fn send<'a, C: 'a>(&'a mut self, command: C)
        -> impl Future<Item = Vec<Response>, Error = failure::Error> + 'a
        where C: AsRef<[u8]>
    {
        let command = command.as_ref();
        let mut c = command.to_vec();
        if ! c.ends_with(b"\n") {
            c.push(0x0a);
        }
        let w = &mut self.w;
        let r = &mut self.r;
        io::write_all(w, c).from_err()
            .and_then(move |_| ResponseFuture(r))
    }

    /// Cancels a pending operation.
    pub fn cancel<'a>(&'a mut self)
        -> impl Future<Item = Vec<Response>, Error = failure::Error> + 'a
    {
        self.send("CAN")
    }

    /// Sends data in response to an inquire.
    ///
    /// The response is either a `Response::Ok`, `Response::Error`, or
    /// another `Response::Inquire`.  `Ok` and `Error` indicate
    /// success and failure of the original operation that lead to the
    /// current inquiry.
    pub fn data<'a, C: 'a>(&'a mut self, data: C)
        -> impl Future<Item = Vec<Response>, Error = failure::Error> + 'a
        where C: AsRef<[u8]>
    {
        let mut data = data.as_ref();
        let mut request = Vec::with_capacity(data.len());
        while ! data.is_empty() {
            let line_len = 2;
            if request.len() > 0 {
                request.push(0x0a);
            }
            write!(&mut request, "D ").unwrap();
            while ! data.is_empty() && line_len < MAX_LINE_LENGTH - 3 {
                let c = data[0];
                data = &data[1..];
                match c as char {
                    '%' | '\n' | '\r' =>
                        write!(&mut request, "%{:02X}", c).unwrap(),
                    _ => request.push(c),
                }
            }
        }
        write!(&mut request, "END").unwrap();
        self.send(request)
    }
}

/// A future that will resolve to a `Client`.
struct ConnectionFuture(Option<Client>);

impl ConnectionFuture {
    fn new(c: UnixStream) -> Self {
        let (r, w) = c.split();
        Self(Some(Client { r: ResponseStream::new(BufReader::new(r)), w }))
    }
}

impl Future for ConnectionFuture {
    type Item = Client;
    type Error = failure::Error;

    fn poll(&mut self) -> std::result::Result<Async<Self::Item>, Self::Error> {
        // Consume the initial message from the server.
        match {
            let c = self.0.as_mut().expect("future polled after completion");
            ResponseFuture(&mut c.r).poll()?
        } {
            Async::Ready(r) => {
                match r.last() {
                    Some(Response::Ok { .. }) =>
                        Ok(Async::Ready(self.0.take().unwrap())),
                    Some(Response::Error { code, message }) =>
                        Err(Error::HandshakeFailed(
                            format!("Error {}: {:?}", code, message)).into()),
                    l @ Some(_) =>
                        Err(Error::HandshakeFailed(
                            format!("Unexpected server response: {:?}", l)
                        ).into()),
                    None => // XXX does that happen?
                        Err(Error::HandshakeFailed(
                            "No data received from server".into()).into()),
                }
            },
            Async::NotReady => Ok(Async::NotReady),
        }
    }
}

/// A future that will resolve to a `Vec<Response>`.
struct ResponseFuture<'a>(&'a mut ResponseStream);

impl<'a> Future for ResponseFuture<'a> {
    type Item = Vec<Response>;
    type Error = failure::Error;

    fn poll(&mut self) -> std::result::Result<Async<Self::Item>, Self::Error> {
        match self.0.poll()? {
            Async::Ready(Some(r)) => Ok(Async::Ready(r)),
            Async::Ready(None) =>
                Err(Error::ConnectionClosed(Vec::new()).into()),
            Async::NotReady => Ok(Async::NotReady),
        }
    }
}

struct ResponseStream {
    r: BufReader<io::ReadHalf<UnixStream>>, // xxx: abstract over
    buffer: Vec<u8>,
    responses: Vec<Response>,
}

impl ResponseStream {
    fn new(r: BufReader<io::ReadHalf<UnixStream>>) -> Self {
        Self { r, buffer: Vec::new(), responses: Vec::new() }
    }
}

impl Stream for ResponseStream {
    type Item = Vec<Response>;
    type Error = failure::Error;

    fn poll(&mut self) -> std::result::Result<Async<Option<Self::Item>>,
                                              Self::Error> {
        loop {
            // Try to yield a line from the buffer.  For that, try to
            // find linebreaks.
            while let Some(p) = self.buffer.iter().position(|&b| b == 0x0a) {
                let line: Vec<u8> = self.buffer.drain(..p+1).collect();
                // xxx: rtrim linebreak even more? crlf maybe?
                let r = Response::parse(&line[..line.len()-1])?;

                let done = match r {
                    // All server responses end in either OK or ERR.
                    Response::Ok { .. } | Response::Error { .. } => true,
                    // However, the server may inquire more
                    // information.  We also surrender control to the
                    // caller by yielding the responses we have seen
                    // so far, and allow her to respond to the
                    // inquiry.
                    Response::Inquire { .. } => true,
                    _ => false,
                };
                self.responses.push(r);
                if done {
                    return Ok(Async::Ready(Some(
                        mem::replace(&mut self.responses, Vec::new()))));
                }

                // We found a line, but it was not the last line in
                // this server response.  Try to find another line.
            }

            // No more linebreaks in the buffer.  We need to get more.
            // First, grow the buffer.
            let buffer_len = self.buffer.len();
            self.buffer.resize(buffer_len + MAX_LINE_LENGTH, 0);

            match self.r.poll_read(&mut self.buffer[buffer_len..])? {
                Async::Ready(n_read) if n_read == 0 => {
                    // EOF.
                    self.buffer.resize(buffer_len, 0);

                    if self.responses.is_empty() {
                        if ! self.buffer.is_empty() {
                            // Incomplete server response.
                            return Err(Error::ConnectionClosed(
                                mem::replace(&mut self.buffer, Vec::new())
                            ).into());
                        }

                        // End of stream.
                        return Ok(Async::Ready(None));
                    } else {
                        // There is an incomplete server response,
                        // yield that and let the caller figure it
                        // out.
                        return Ok(Async::Ready(Some(
                            mem::replace(&mut self.responses, Vec::new())
                        )));
                    }
                },
                Async::Ready(n_read) => {
                    self.buffer.resize(buffer_len + n_read, 0);
                    continue;
                },

                Async::NotReady => {
                    self.buffer.resize(buffer_len, 0);
                    return Ok(Async::NotReady);
                },
            }
        }
    }
}

/// Server response.
#[derive(Debug, PartialEq)]
pub enum Response {
    /// Operation successful.
    Ok {
        /// Optional human-readable message.
        message: Option<String>,
    },
    /// An error occurred.
    Error {
        /// Error code.
        ///
        /// This code is defined in `libgpg-error`.
        code: usize,
        /// Optional human-readable message.
        message: Option<String>,
    },
    /// Information about the ongoing operation.
    Status {
        /// Indicates what the status message is about.
        keyword: String,
        /// Human-readable message.
        message: String,
    },
    /// A comment for debugging purposes.
    Comment {
        /// Human-readable message.
        message: String,
    },
    /// Raw data returned to the client.
    Data {
        /// A chunk of raw data.
        ///
        /// Consecutive `Data` responses must be joined.
        partial: Vec<u8>,
    },
    /// Request for information from the client.
    Inquire {
        /// The subject of the inquiry.
        keyword: String,
        /// Optional parameters.
        parameters: Option<Vec<u8>>,
    },
}

impl Response {
    /// Parses the given response.
    pub fn parse(b: &[u8]) -> Result<Response> {
        match self::grammar::ResponseParser::new().parse(lexer::Lexer::new(b)) {
            Ok(r) => Ok(r),
            Err(err) => {
                let mut msg = Vec::new();
                writeln!(&mut msg, "Parsing: {:?}: {:?}", b, err)?;
                if let ParseError::UnrecognizedToken {
                    token: (start, _, end), ..
                } = err
                {
                    writeln!(&mut msg, "Context:")?;
                    let chars = b.iter().enumerate()
                        .filter_map(|(i, c)| {
                            if cmp::max(8, start) - 8 <= i
                                && i <= end + 8
                            {
                                Some((i, c))
                            } else {
                                None
                            }
                        });
                    for (i, c) in chars {
                        writeln!(&mut msg, "{} {} {}: {:?}",
                                 if i == start { "*" } else { " " },
                                 i,
                                 *c as char,
                                 c)?;
                    }
                }
                Err(failure::err_msg(
                    String::from_utf8_lossy(&msg).to_string()).into())
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basics() {
        assert_eq!(
            Response::parse(b"OK Pleased to meet you, process 7745")
                .unwrap(),
            Response::Ok {
                message: Some("Pleased to meet you, process 7745".into()),
            });
        assert_eq!(
            Response::parse(b"ERR 67109139 Unknown IPC command <GPG Agent>")
                .unwrap(),
            Response::Error {
                code: 67109139,
                message :Some("Unknown IPC command <GPG Agent>".into()),
            });

        let status =
          b"S KEYINFO 151BCDB0C293927B7E36660BE47F28DA8729BD19 D - - - C - - -";
        assert_eq!(
            Response::parse(status).unwrap(),
            Response::Status {
                keyword: "KEYINFO".into(),
                message:
                    "151BCDB0C293927B7E36660BE47F28DA8729BD19 D - - - C - - -"
                    .into(),
            });

        assert_eq!(
            Response::parse(b"D (7:sig-val(3:rsa(1:s1:%25%0D)))")
                .unwrap(),
            Response::Data {
                partial: b"(7:sig-val(3:rsa(1:s1:%\x0d)))".to_vec(),
            });

        assert_eq!(
            Response::parse(b"INQUIRE CIPHERTEXT")
                .unwrap(),
            Response::Inquire {
                keyword: "CIPHERTEXT".into(),
                parameters: None,
            });
    }
}
