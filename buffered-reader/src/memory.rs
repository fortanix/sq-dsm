use std::io;
use std::fmt;
use std::cmp;

use std::io::{Error,ErrorKind};

use super::*;

/// A `BufferedReader` specialized for reading from memory buffers.
pub struct BufferedReaderMemory<'a, C> {
    buffer: &'a [u8],
    // The next byte to read in the buffer.
    cursor: usize,

    // The user settable cookie.
    cookie: C,
}

impl<'a, C> fmt::Debug for BufferedReaderMemory<'a, C> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("BufferedReaderMemory")
            .field("buffer (bytes)", &&self.buffer.len())
            .field("cursor", &self.cursor)
            .finish()
    }
}

impl<'a> BufferedReaderMemory<'a, ()> {
    /// Instantiate a new memory-based reader.  `buffer` contains the
    /// reader's contents.
    pub fn new(buffer: &'a [u8]) -> Self {
        Self::with_cookie(buffer, ())
    }
}

impl<'a, C> BufferedReaderMemory<'a, C> {
    /// Like `new()`, but sets a cookie, which can be retrieved using
    /// the `cookie_ref` and `cookie_mut` methods, and set using
    /// the `cookie_set` method.
    pub fn with_cookie(buffer: &'a [u8], cookie: C) -> Self {
        BufferedReaderMemory {
            buffer: buffer,
            cursor: 0,
            cookie: cookie,
        }
    }

    /// Returns the number of bytes that have been consumed by this
    /// reader.
    pub fn total_out(&self) -> usize {
        return self.cursor;
    }
}

impl<'a, C> io::Read for BufferedReaderMemory<'a, C> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, io::Error> {
        let amount = cmp::min(buf.len(), self.buffer.len() - self.cursor);
        buf[0..amount].copy_from_slice(
                &self.buffer[self.cursor..self.cursor+amount]);
        self.consume(amount);
        return Ok(amount);
    }
}

impl<'a, C> BufferedReader<C> for BufferedReaderMemory<'a, C> {
    /// Return the buffer.  Ensure that it contains at least `amount`
    /// bytes.
    fn data(&mut self, _amount: usize) -> Result<&[u8], io::Error> {
        assert!(self.cursor <= self.buffer.len());
        return Ok(&self.buffer[self.cursor..]);
    }

    fn consume(&mut self, amount: usize) -> &[u8] {
        // The caller can't consume more than is buffered!
        assert!(amount <= self.buffer.len() - self.cursor,
                "Attempt to consume {} bytes, but buffer only has {} bytes!",
                amount, self.buffer.len() - self.cursor);
        self.cursor += amount;
        assert!(self.cursor <= self.buffer.len());
        return &self.buffer[self.cursor - amount..];
    }

    fn data_consume(&mut self, amount: usize) -> Result<&[u8], io::Error> {
        let amount = cmp::min(amount, self.buffer.len() - self.cursor);
        return Ok(self.consume(amount));
    }

    fn data_consume_hard(&mut self, amount: usize) -> Result<&[u8], io::Error> {
        if self.buffer.len() - self.cursor < amount {
            return Err(Error::new(ErrorKind::UnexpectedEof, "EOF"));
        }
        return Ok(self.consume(amount));
    }

    fn into_inner<'b>(self: Box<Self>) -> Option<Box<BufferedReader<C> + 'b>>
            where Self: 'b {
        None
    }

    fn cookie_set(&mut self, cookie: C) -> C {
        use std::mem;

        mem::replace(&mut self.cookie, cookie)
    }

    fn cookie_ref(&self) -> &C {
        &self.cookie
    }

    fn cookie_mut(&mut self) -> &mut C {
        &mut self.cookie
    }
}

#[test]
fn buffered_reader_memory_test () {
    let data : &[u8] = include_bytes!("buffered-reader-test.txt");
    let mut bio = BufferedReaderMemory::new(data);

    buffered_reader_test_data_check(&mut bio);
}
