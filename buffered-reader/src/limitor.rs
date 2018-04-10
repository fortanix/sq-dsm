use std::io;
use std::cmp;

use super::*;

/// A `BufferedReaderLimitor` limits the amount of data that can be
/// read from a `BufferedReader`.
pub struct BufferedReaderLimitor<'a, C> {
    reader: Box<'a + BufferedReader<C>>,
    limit: u64,

    cookie: C,
}

impl<'a, C> fmt::Debug for BufferedReaderLimitor<'a, C> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("BufferedReaderLimitor")
            .field("limit", &self.limit)
            .field("reader", &self.reader)
            .finish()
    }
}

impl<'a> BufferedReaderLimitor<'a, ()> {
    /// Instantiate a new limitor.  `reader` is the source to wrap.
    /// `limit` is the maximum number of bytes that will be returned
    /// from the source.
    pub fn new(reader: Box<'a + BufferedReader<()>>, limit: u64) -> Self {
        Self::with_cookie(reader, limit, ())
    }
}

impl<'a, C> BufferedReaderLimitor<'a, C> {
    /// Like `new()`, but sets a cookie, which can be retrieved using
    /// the `cookie_ref` and `cookie_mut` methods, and set using
    /// the `cookie_set` method.
    pub fn with_cookie(reader: Box<'a + BufferedReader<C>>, limit: u64, cookie: C)
            -> BufferedReaderLimitor<'a, C> {
        BufferedReaderLimitor {
            reader: reader,
            limit: limit,
            cookie: cookie,
        }
    }
}

impl<'a, C> io::Read for BufferedReaderLimitor<'a, C> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, io::Error> {
        let len = cmp::min(self.limit, buf.len() as u64) as usize;
        return self.reader.read(&mut buf[0..len]);
    }
}

impl<'a, C> BufferedReader<C> for BufferedReaderLimitor<'a, C> {
    fn buffer(&self) -> &[u8] {
        let buf = self.reader.buffer();
        &buf[..cmp::min(buf.len(),
                        cmp::min(std::usize::MAX as u64,
                                 self.limit) as usize)]
    }

    /// Return the buffer.  Ensure that it contains at least `amount`
    /// bytes.
    fn data(&mut self, amount: usize) -> Result<&[u8], io::Error> {
        let amount = cmp::min(amount as u64, self.limit) as usize;
        let result = self.reader.data(amount);
        match result {
            Ok(ref buffer) =>
                if buffer.len() as u64 > self.limit {
                    return Ok(&buffer[0..self.limit as usize]);
                } else {
                    return Ok(buffer);
                },
            Err(err) => return Err(err),
        }
    }

    fn consume(&mut self, amount: usize) -> &[u8] {
        assert!(amount as u64 <= self.limit);
        self.limit -= amount as u64;
        let data = self.reader.consume(amount);
        return &data[..cmp::min(self.limit + amount as u64, data.len() as u64) as usize];
    }

    fn data_consume(&mut self, amount: usize) -> Result<&[u8], io::Error> {
        let amount = cmp::min(amount as u64, self.limit) as usize;
        let result = self.reader.data_consume(amount);
        if let Ok(ref buffer) = result {
            self.limit -= amount as u64;
            return Ok(&buffer[
                ..cmp::min(buffer.len() as u64, self.limit + amount as u64) as usize]);
        }
        return result;
    }

    fn data_consume_hard(&mut self, amount: usize) -> Result<&[u8], io::Error> {
        if amount as u64 > self.limit {
            return Err(Error::new(ErrorKind::UnexpectedEof, "EOF"));
        }
        let result = self.reader.data_consume_hard(amount);
        if let Ok(ref buffer) = result {
            self.limit -= amount as u64;
            return Ok(&buffer[
                ..cmp::min(buffer.len() as u64, self.limit + amount as u64) as usize]);
        }
        return result;
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
    fn buffered_reader_limitor_test() {
        let data : &[u8] = b"01234567890123456789";

        /* Add a single limitor.  */
        {
            let mut bio : Box<BufferedReader<()>>
                = Box::new(BufferedReaderMemory::new(data));

            bio = {
                let mut bio2 = Box::new(BufferedReaderLimitor::new(bio, 5));
                {
                    let result = bio2.data(5).unwrap();
                    assert_eq!(result.len(), 5);
                    assert_eq!(result, &b"01234"[..]);
                }
                bio2.consume(5);
                {
                    let result = bio2.data(1).unwrap();
                    assert_eq!(result.len(), 0);
                    assert_eq!(result, &b""[..]);
                }

                bio2.into_inner().unwrap()
            };

            {
                {
                    let result = bio.data(15).unwrap();
                    assert_eq!(result.len(), 15);
                    assert_eq!(result, &b"567890123456789"[..]);
                }
                bio.consume(15);
                {
                    let result = bio.data(1).unwrap();
                    assert_eq!(result.len(), 0);
                    assert_eq!(result, &b""[..]);
                }
            }
        }

        /* Try with two limitors where the first one imposes the real
         * limit.  */
        {
            let mut bio : Box<BufferedReader<()>>
                = Box::new(BufferedReaderMemory::new(data));

            bio = {
                let bio2 : Box<BufferedReader<()>>
                    = Box::new(BufferedReaderLimitor::new(bio, 5));
                // We limit to 15 bytes, but bio2 will still limit us to 5
                // bytes.
                let mut bio3 : Box<BufferedReader<()>>
                    = Box::new(BufferedReaderLimitor::new(bio2, 15));
                {
                    let result = bio3.data(100).unwrap();
                    assert_eq!(result.len(), 5);
                    assert_eq!(result, &b"01234"[..]);
                }
                bio3.consume(5);
                {
                    let result = bio3.data(1).unwrap();
                    assert_eq!(result.len(), 0);
                    assert_eq!(result, &b""[..]);
                }

                bio3.into_inner().unwrap().into_inner().unwrap()
            };

            {
                {
                    let result = bio.data(15).unwrap();
                    assert_eq!(result.len(), 15);
                    assert_eq!(result, &b"567890123456789"[..]);
                }
                bio.consume(15);
                {
                    let result = bio.data(1).unwrap();
                    assert_eq!(result.len(), 0);
                    assert_eq!(result, &b""[..]);
                }
            }
        }
    }

    // Test that buffer() returns the same data as data().
    #[test]
    fn buffer_test() {
        // Test vector.
        let size = 10 * DEFAULT_BUF_SIZE;
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

        let reader = Box::new(BufferedReaderGeneric::new(&input[..], None));
        let size = size / 2;
        let input = &input[..size];
        let mut reader = BufferedReaderLimitor::new(reader, input.len() as u64);

        // Gather some stats to make it easier to figure out whether
        // this test is working.
        let stats_count =  2 * DEFAULT_BUF_SIZE;
        let mut stats = vec![0usize; stats_count];

        for i in 0..input.len() {
            let data = reader.data(DEFAULT_BUF_SIZE + 1).unwrap().to_vec();
            assert!(data.len() > 0);
            assert_eq!(data, reader.buffer());
            // And, we may as well check to make sure we read the
            // right data.
            assert_eq!(data, &input[i..i+data.len()]);

            stats[cmp::min(data.len(), stats_count - 1)] += 1;

            // Consume one byte and see what happens.
            reader.consume(1);
        }

        if false {
            for i in 0..stats.len() {
                if stats[i] > 0 {
                    if i == stats.len() - 1 {
                        eprint!(">=");
                    }
                    eprintln!("{}: {}", i, stats[i]);
                }
            }
        }
    }
}
