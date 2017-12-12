use std::io;
use std::fmt;
use std::cmp;

use std::io::{Error,ErrorKind};

use super::*;

/// A `BufferedReader` specialized for reading from memory buffers.
pub struct BufferedReaderMemory<'a> {
    buffer: &'a [u8],
    // The next byte to read in the buffer.
    cursor: usize,
}

impl <'a> fmt::Debug for BufferedReaderMemory<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("BufferedReaderMemory")
            .field("buffer (bytes)", &&self.buffer.len())
            .field("cursor", &self.cursor)
            .finish()
    }
}

impl<'a> BufferedReaderMemory<'a> {
    pub fn new(buffer: &'a [u8]) -> BufferedReaderMemory<'a> {
        BufferedReaderMemory {
            buffer: buffer,
            cursor: 0,
        }
    }
}

impl<'a> io::Read for BufferedReaderMemory<'a> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, io::Error> {
        let amount = cmp::min(buf.len(), self.buffer.len() - self.cursor);
        buf[0..amount].copy_from_slice(
                &self.buffer[self.cursor..self.cursor+amount]);
        self.consume(amount);
        return Ok(amount);
    }
}

impl<'a> BufferedReader for BufferedReaderMemory<'a> {
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
        return Ok(self.consume(amount));
    }

    fn data_consume_hard(&mut self, amount: usize) -> Result<&[u8], io::Error> {
        if self.buffer.len() - self.cursor < amount {
            return Err(Error::new(ErrorKind::UnexpectedEof, "EOF"));
        }
        return Ok(self.consume(amount));
    }

    fn into_inner<'b>(self: Box<Self>) -> Option<Box<BufferedReader + 'b>>
            where Self: 'b {
        None
    }
}

#[test]
fn buffered_reader_memory_test () {
    let data : &[u8] = include_bytes!("buffered-reader-test.txt");
    let mut bio = BufferedReaderMemory::new(data);

    buffered_reader_test_data_check(&mut bio);
}
