//! Assuan RPC support.

#![warn(missing_docs)]

use std::cmp;
use std::io::Write;
use std::mem;
use std::path::Path;
use std::pin::Pin;
use std::task::{Poll, Context};

use lalrpop_util::ParseError;

use futures::{Future, Stream, StreamExt};
use tokio::io::{BufReader, ReadHalf, WriteHalf};
use tokio::io::{AsyncRead, AsyncWriteExt};

use crate::openpgp;

use crate::Error;
use crate::Result;

mod lexer;
mod socket;
use socket::IpcStream;

// Maximum line length of the reference implementation.
const MAX_LINE_LENGTH: usize = 1000;

// Load the generated code.
lalrpop_util::lalrpop_mod!(
    #[allow(clippy::all)]
    #[allow(missing_docs, unused_parens)]
    grammar,
    "/assuan/grammar.rs"
);

/// A connection to an Assuan server.
///
/// Commands may be issued using [`Connection::send`].  Note that the
/// command is sent lazily, i.e. it is only sent if you poll for the
/// responses.
///
/// [`Connection::send`]: Client::send()
///
/// `Client` implements [`Stream`] to return all server responses
/// until the first [`Response::Ok`], [`Response::Error`], or
/// [`Response::Inquire`].
///
/// [`Stream`]: #impl-Stream
///
/// [`Response::Ok`] and [`Response::Error`] indicate success and
/// failure.  [`Response::Inquire`] means that the server requires
/// more information to complete the request.  This information may be
/// provided using [`Connection::data()`], or the operation may be
/// canceled using [`Connection::cancel()`].
///
/// [`Connection::data()`]: Client::data()
/// [`Connection::cancel()`]: Client::cancel()
pub struct Client {
    r: BufReader<ReadHalf<IpcStream>>, // xxx: abstract over
    buffer: Vec<u8>,
    done: bool,
    w: WriteState,
}
assert_send_and_sync!(Client);

enum WriteState {
    Ready(WriteHalf<IpcStream>),
    Sending(Pin<Box<dyn Future<Output = Result<WriteHalf<IpcStream>>>
                    + Send + Sync>>),
    Transitioning,
    Dead,
}
assert_send_and_sync!(WriteState);

impl Client {
    /// Connects to the server.
    pub async fn connect<P>(path: P) -> Result<Client> where P: AsRef<Path> {
        let connection = socket::sock_connect(path)?;
        Ok(ConnectionFuture::new(connection).await?)
    }

    /// Lazily sends a command to the server.
    ///
    /// For the command to be actually executed, stream the responses
    /// using this objects [`Stream`] implementation.
    ///
    /// [`Stream`]: #impl-Stream
    ///
    /// The response stream ends in either a [`Response::Ok`],
    /// [`Response::Error`], or [`Response::Inquire`].  `Ok` and
    /// `Error` indicate success and failure of the current operation.
    /// `Inquire` means that the server requires more information to
    /// complete the request.  This information may be provided using
    /// [`Connection::data()`], or the operation may be canceled using
    /// [`Connection::cancel()`].
    ///
    /// [`Response::Ok`]: super::assuan::Response::Ok
    /// [`Response::Error`]: super::assuan::Response::Error
    /// [`Response::Inquire`]: super::assuan::Response::Inquire
    /// [`Connection::data()`]: Client::data()
    /// [`Connection::cancel()`]: Client::cancel()
    ///
    /// Note: `command` is passed as-is.  Control characters, like
    /// `%`, must be %-escaped.
    pub fn send<'a, C: 'a>(&'a mut self, command: C) -> Result<()>
        where C: AsRef<[u8]>
    {
        if let WriteState::Sending(_) = self.w {
            return Err(openpgp::Error::InvalidOperation(
                "Busy, poll responses first".into()).into());
        }

        self.w =
            match mem::replace(&mut self.w, WriteState::Transitioning)
        {
            WriteState::Ready(mut sink) => {
                let command = command.as_ref();
                let mut c = command.to_vec();
                if ! c.ends_with(b"\n") {
                    c.push(0x0a);
                }
                WriteState::Sending(Box::pin(async move {
                    sink.write_all(&c).await?;
                    Ok(sink)
                }))
            },
            _ => unreachable!(),
        };

        Ok(())
    }

    /// Lazily cancels a pending operation.
    ///
    /// For the command to be actually executed, stream the responses
    /// using this objects [`Stream`] implementation.
    ///
    /// [`Stream`]: #impl-Stream
    pub fn cancel(&mut self) -> Result<()> {
        self.send("CAN")
    }

    /// Lazily sends data in response to an inquire.
    ///
    /// For the command to be actually executed, stream the responses
    /// using this objects [`Stream`] implementation.
    ///
    /// [`Stream`]: #impl-Stream
    ///
    /// The response stream ends in either a [`Response::Ok`],
    /// [`Response::Error`], or another [`Response::Inquire`].  `Ok`
    /// and `Error` indicate success and failure of the original
    /// operation that lead to the current inquiry.
    ///
    /// [`Response::Ok`]: super::assuan::Response::Ok
    /// [`Response::Error`]: super::assuan::Response::Error
    /// [`Response::Inquire`]: super::assuan::Response::Inquire
    pub fn data<'a, C: 'a>(&'a mut self, data: C) -> Result<()>
        where C: AsRef<[u8]>
    {
        let mut data = data.as_ref();
        let mut request = Vec::with_capacity(data.len());
        while ! data.is_empty() {
            if !request.is_empty() {
                request.push(0x0a);
            }
            write!(&mut request, "D ").unwrap();
            let mut line_len = 2;
            while ! data.is_empty() && line_len < MAX_LINE_LENGTH - 3 {
                let c = data[0];
                data = &data[1..];
                match c as char {
                    '%' | '\n' | '\r' => {
                        line_len += 3;
                        write!(&mut request, "%{:02X}", c).unwrap();
                    },
                    _ => {
                        line_len += 1;
                        request.push(c);
                    },
                }
            }
        }
        write!(&mut request, "\nEND").unwrap();
        self.send(request)
    }
}

/// A future that will resolve to a `Client`.
struct ConnectionFuture(Option<Client>);

impl ConnectionFuture {
    fn new(c: IpcStream) -> Self {
        let (r, w) = tokio::io::split(c);
        let buffer = Vec::with_capacity(MAX_LINE_LENGTH);
        Self(Some(Client {
            r: BufReader::new(r), buffer, done: false,
            w: WriteState::Ready(w)
        }))
    }
}

impl Future for ConnectionFuture {
    type Output = Result<Client>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        // Consume the initial message from the server.
        let client: &mut Client = self.0.as_mut().expect("future polled after completion");
        let mut responses = client.by_ref().collect::<Vec<_>>();

        match Pin::new(&mut responses).poll(cx) {
            Poll::Ready(response) => {
                Poll::Ready(match response.iter().last() {
                    Some(Ok(Response::Ok { .. })) =>
                        Ok(self.0.take().unwrap()),
                    Some(Ok(Response::Error { code, message })) =>
                        Err(Error::HandshakeFailed(
                            format!("Error {}: {:?}", code, message)).into()),
                    l @ Some(_) =>
                        Err(Error::HandshakeFailed(
                            format!("Unexpected server response: {:?}", l)
                        ).into()),
                    None => // XXX does that happen?
                        Err(Error::HandshakeFailed(
                            "No data received from server".into()).into()),
                })
            },
            Poll::Pending => Poll::Pending,
        }
    }
}

impl Stream for Client {
    type Item = Result<Response>;

    /// Attempt to pull out the next value of this stream, returning
    /// None if the stream is finished.
    ///
    /// Note: It _is_ safe to call this again after the stream
    /// finished, i.e. returned `Ready(None)`.
    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        // First, handle sending of the command.
        match self.w {
            WriteState::Ready(_) =>
                (),  // Nothing to do, poll for responses below.
            WriteState::Sending(_) => {
                self.w = if let WriteState::Sending(mut f) =
                    mem::replace(&mut self.w, WriteState::Transitioning)
                {
                    match f.as_mut().poll(cx) {
                        Poll::Ready(Ok(sink)) => WriteState::Ready(sink),
                        Poll::Pending => WriteState::Sending(f),
                        Poll::Ready(Err(e)) => {
                            self.w = WriteState::Dead;
                            return Poll::Ready(Some(Err(e)));
                        },
                    }
                } else {
                    unreachable!()
                };
            },
            WriteState::Transitioning =>
                unreachable!(),
            WriteState::Dead =>
                (),  // Nothing left to do, poll for responses below.
        }

        // Recheck if we are still sending the command.
        if let WriteState::Sending(_) = self.w {
            return Poll::Pending;
        }

        // Check if the previous response was one of ok, error, or
        // inquire.
        if self.done {
            // If so, we signal end of stream here.
            self.done = false;
            return Poll::Ready(None);
        }

        // The compiler is not smart enough to figure out disjoint borrows
        // through Pin via DerefMut (which wholly borrows `self`), so unwrap it
        let Self { buffer, done, r, .. } = Pin::into_inner(self);
        let mut reader = Pin::new(r);
        loop {
            // Try to yield a line from the buffer.  For that, try to
            // find linebreaks.
            if let Some(p) = buffer.iter().position(|&b| b == 0x0a) {
                let line: Vec<u8> = buffer.drain(..p+1).collect();
                // xxx: rtrim linebreak even more? crlf maybe?
                let r = Response::parse(&line[..line.len()-1])?;
                // If this response is one of ok, error, or inquire,
                // we want to surrender control to the client next
                // time she asks for an item.
                *done = r.is_done();
                return Poll::Ready(Some(Ok(r)));
            }

            // No more linebreaks in the buffer.  We need to get more.
            // First, grow the buffer.
            let buffer_len = buffer.len();
            buffer.resize(buffer_len + MAX_LINE_LENGTH, 0);

            match reader.as_mut().poll_read(cx, &mut buffer[buffer_len..])? {
                Poll::Ready(n_read) if n_read == 0 => {
                    // EOF.
                    buffer.resize(buffer_len, 0);
                    if ! buffer.is_empty() {
                        // Incomplete server response.
                        return Poll::Ready(Some(Err(Error::ConnectionClosed(
                            buffer.clone()).into())));

                    }

                    // End of stream.
                    return Poll::Ready(None);
                },

                Poll::Ready(n_read) => {
                    buffer.resize(buffer_len + n_read, 0);
                    continue;
                },

                Poll::Pending => {
                    buffer.resize(buffer_len, 0);
                    return Poll::Pending;
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
                Err(anyhow::anyhow!(
                    String::from_utf8_lossy(&msg).to_string()))
            },
        }
    }

    /// Returns true if this message indicates success.
    pub fn is_ok(&self) -> bool {
        matches!(self, Response::Ok { .. } )
    }

    /// Returns true if this message indicates an error.
    pub fn is_err(&self) -> bool {
        matches!(self, Response::Error { .. })
    }

    /// Returns true if this message is an inquiry.
    pub fn is_inquire(&self) -> bool {
        matches!(self, Response::Inquire { .. })
    }

    /// Returns true if this response concludes the server's response.
    pub fn is_done(&self) -> bool {
        // All server responses end in either OK or ERR.
        self.is_ok() || self.is_err()
        // However, the server may inquire more
        // information.  We also surrender control to the
        // caller by yielding the responses we have seen
        // so far, and allow her to respond to the
        // inquiry.
            || self.is_inquire()
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
