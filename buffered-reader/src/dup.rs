use std::io;
use std::fmt;
use std::cmp;

use super::*;

/// A `BufferedReader` that duplicates the underlying `BufferedReader`
/// without consuming any of the data.
///
/// Note: this will likely cause the underlying stream to buffer as
/// much data as you read.  Thus, it should only be used for peeking
/// at the underlying `BufferedReader`.
pub struct BufferedReaderDup<'a, C> {
    reader: Box<'a + BufferedReader<C>>,

    // The number of bytes that have been consumed.
    cursor: usize,

    // The user settable cookie.
    cookie: C,
}

impl<'a, C> fmt::Debug for BufferedReaderDup<'a, C> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("BufferedReaderDup")
            .field("reader", &self.reader)
            .field("cursor", &self.cursor)
            .finish()
    }
}

impl<'a> BufferedReaderDup<'a, ()> {
    /// Instantiate a new memory-based reader.  `buffer` contains the
    /// reader's contents.
    pub fn new(reader: Box<'a + BufferedReader<()>>) -> Self {
        Self::with_cookie(reader, ())
    }
}

impl<'a, C> BufferedReaderDup<'a, C> {
    /// Like `new()`, but sets a cookie, which can be retrieved using
    /// the `cookie_ref` and `cookie_mut` methods, and set using
    /// the `cookie_set` method.
    pub fn with_cookie(reader: Box<'a + BufferedReader<C>>, cookie: C) -> Self {
        BufferedReaderDup {
            reader: reader,
            cursor: 0,
            cookie: cookie,
        }
    }

    /// Returns the number of bytes that have been consumed by this
    /// reader.
    pub fn total_out(&self) -> usize {
        return self.cursor;
    }

    /// Resets the cursor to the beginning of the stream.
    pub fn rewind(&mut self) {
        self.cursor = 0;
    }
}

impl<'a, C> io::Read for BufferedReaderDup<'a, C> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, io::Error> {
        let data = self.reader.data(self.cursor + buf.len())?;
        assert!(data.len() >= self.cursor);
        let data = &data[self.cursor..];

        let amount = cmp::min(buf.len(), data.len());
        buf.copy_from_slice(&data[..amount]);

        self.cursor += amount;

        Ok(amount)
    }
}

impl<'a, C> BufferedReader<C> for BufferedReaderDup<'a, C> {
    fn buffer(&self) -> &[u8] {
        let data = self.reader.buffer();
        assert!(data.len() >= self.cursor);
        &data[self.cursor..]
    }

    fn data(&mut self, amount: usize) -> Result<&[u8], io::Error> {
        let data = self.reader.data(self.cursor + amount)?;
        assert!(data.len() >= self.cursor);
        Ok(&data[self.cursor..])
    }

    fn consume(&mut self, amount: usize) -> &[u8] {
        let data = self.reader.buffer();
        assert!(data.len() >= self.cursor + amount);
        let data = &data[self.cursor..];
        self.cursor += amount;
        data
    }

    fn data_consume(&mut self, amount: usize) -> Result<&[u8], io::Error> {
        let data = self.reader.data(self.cursor + amount)?;
        assert!(data.len() >= self.cursor);
        let data = &data[self.cursor..];
        self.cursor += cmp::min(data.len(), amount);
        Ok(data)
    }

    fn data_consume_hard(&mut self, amount: usize) -> Result<&[u8], io::Error> {
        let data = self.reader.data_hard(self.cursor + amount)?;
        assert!(data.len() >= self.cursor + amount);
        let data = &data[self.cursor..];
        self.cursor += amount;
        Ok(data)
    }

    fn get_mut(&mut self) -> Option<&mut BufferedReader<C>> {
        Some(&mut self.reader)
    }

    fn get_ref(&self) -> Option<&BufferedReader<C>> {
        Some(&self.reader)
    }

    fn into_inner<'b>(self: Box<Self>) -> Option<Box<BufferedReader<C> + 'b>>
            where Self: 'b {
        Some(self.reader)
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
        let reader = BufferedReaderMemory::new(data);
        let mut reader = BufferedReaderDup::new(Box::new(reader));

        buffered_reader_test_data_check(&mut reader);

        let consumed = reader.total_out();
        assert_eq!(consumed, data.len());

        // Since we haven't consumed the inner buffer, this should
        // still work.
        let mut reader = Box::new(reader).into_inner().unwrap();

        // Try to read consumed + 1 bytes (which shouldn't be
        // possible).
        assert_eq!(consumed, reader.data(consumed + 1).unwrap().len());

        buffered_reader_test_data_check(&mut reader);
    }

    // Test that buffer() returns the same data as data().
    #[test]
    fn buffer_test() {
        // Test vector.  A BufferedReaderDup returns all unconsumed
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

        let reader = BufferedReaderMemory::new(&input[..]);
        let mut reader = BufferedReaderDup::new(Box::new(reader));

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
