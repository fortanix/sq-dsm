use std::io;
use std::fmt;
use std::cmp;

use std::io::{Error, ErrorKind};

use super::*;

/// Wraps a memory buffer.
///
/// Although it is possible to use `Generic` to wrap a
/// buffer, this implementation is optimized for a memory buffer, and
/// avoids double buffering.
pub struct Memory<'a, C> {
    buffer: &'a [u8],
    // The next byte to read in the buffer.
    cursor: usize,

    // The user settable cookie.
    cookie: C,
}

impl<'a, C> fmt::Display for Memory<'a, C> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Memory ({} of {} bytes read)",
               self.cursor, self.buffer.len())
    }
}

impl<'a, C> fmt::Debug for Memory<'a, C> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Memory")
            .field("buffer (bytes)", &&self.buffer.len())
            .field("cursor", &self.cursor)
            .finish()
    }
}

impl<'a> Memory<'a, ()> {
    /// Instantiates a new `Memory`.
    ///
    /// `buffer` contains the `Memory`'s contents.
    pub fn new(buffer: &'a [u8]) -> Self {
        Self::with_cookie(buffer, ())
    }
}

impl<'a, C> Memory<'a, C> {
    /// Like `new()`, but sets a cookie.
    ///
    /// The cookie can be retrieved using the `cookie_ref` and
    /// `cookie_mut` methods, and set using the `cookie_set` method.
    pub fn with_cookie(buffer: &'a [u8], cookie: C) -> Self {
        Memory {
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

impl<'a, C> io::Read for Memory<'a, C> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, io::Error> {
        let amount = cmp::min(buf.len(), self.buffer.len() - self.cursor);
        buf[0..amount].copy_from_slice(
                &self.buffer[self.cursor..self.cursor+amount]);
        self.consume(amount);
        return Ok(amount);
    }
}

impl<'a, C> BufferedReader<C> for Memory<'a, C> {
    fn buffer(&self) -> &[u8] {
        &self.buffer[self.cursor..]
    }

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

    fn get_mut(&mut self) -> Option<&mut dyn BufferedReader<C>> {
        None
    }

    fn get_ref(&self) -> Option<&dyn BufferedReader<C>> {
        None
    }

    fn into_inner<'b>(self: Box<Self>) -> Option<Box<dyn BufferedReader<C> + 'b>>
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

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn buffered_reader_memory_test () {
        let data : &[u8] = include_bytes!("buffered-reader-test.txt");
        let mut bio = Memory::new(data);

        buffered_reader_test_data_check(&mut bio);
    }

    // Test that buffer() returns the same data as data().
    #[test]
    fn buffer_test() {
        // Test vector.  A Memory returns all unconsumed
        // data.  So, use a relatively small buffer size.
        let size = DEFAULT_BUF_SIZE;
        let mut input = Vec::with_capacity(size);
        let mut v = 0u8;
        for _ in 0..size {
            input.push(v);
            if v == std::u8::MAX {
                v = 0;
            } else {
                v += 1;
            }
        }

        let mut reader = Memory::new(&input[..]);

        for i in 0..input.len() {
            let data = reader.data(DEFAULT_BUF_SIZE + 1).unwrap().to_vec();
            assert!(data.len() > 0);
            assert_eq!(data, reader.buffer());
            // And, we may as well check to make sure we read the
            // right data.
            assert_eq!(data, &input[i..i+data.len()]);

            // Consume one byte and see what happens.
            reader.consume(1);
        }
    }
}
