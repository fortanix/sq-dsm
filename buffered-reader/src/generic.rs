use std::io;
use std::fmt;
use std::cmp;
use std::io::{Error,ErrorKind};

use super::*;

/// A generic `BufferedReader` implementation that only requires a
/// source that implements the `Read` trait.  This is sufficient when
/// reading from a file, and it even works with a `&[u8]` (but
/// `BufferedReaderMemory` is more efficient).
pub struct BufferedReaderGeneric<T: io::Read, C> {
    buffer: Option<Box<[u8]>>,
    // The next byte to read in the buffer.
    cursor: usize,
    // The preferred chunk size.  This is just a hint.
    preferred_chunk_size: usize,
    // XXX: This is pub for the decompressors.  It would be better to
    // change this to some accessor method.
    pub reader: Box<T>,
    // Whether we saw an EOF.
    saw_eof: bool,
    // The last error that we encountered, but have not yet returned.
    error: Option<io::Error>,

    // The user settable cookie.
    cookie: C,
}

impl<T: io::Read, C> fmt::Debug for BufferedReaderGeneric<T, C> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let buffered_data = if let Some(ref buffer) = self.buffer {
            buffer.len() - self.cursor
        } else {
            0
        };

        f.debug_struct("BufferedReaderGeneric")
            .field("preferred_chunk_size", &self.preferred_chunk_size)
            .field("buffer data", &buffered_data)
            .field("saw eof", &self.saw_eof)
            .field("error", &self.error)
            .finish()
    }
}

impl<T: io::Read> BufferedReaderGeneric<T, ()> {
    /// Instantiate a new generic reader.  `reader` is the source to
    /// wrap.  `preferred_chuck_size` is the preferred chuck size.  If
    /// None, then the default will be used, which is usually what you
    /// want.
    pub fn new(reader: T, preferred_chunk_size: Option<usize>) -> Self {
        Self::with_cookie(reader, preferred_chunk_size, ())
    }
}

impl<T: io::Read, C> BufferedReaderGeneric<T, C> {
    /// Like `new()`, but sets a cookie, which can be retrieved using
    /// the `cookie_ref` and `cookie_mut` methods, and set using
    /// the `cookie_set` method.
    pub fn with_cookie(
           reader: T, preferred_chunk_size: Option<usize>, cookie: C)
           -> Self {
        BufferedReaderGeneric {
            buffer: None,
            cursor: 0,
            preferred_chunk_size:
                if let Some(s) = preferred_chunk_size { s }
                else { DEFAULT_BUF_SIZE },
            reader: Box::new(reader),
            saw_eof: false,
            error: None,
            cookie: cookie,
        }
    }

    /// Return the buffer.  Ensure that it contains at least `amount`
    /// bytes.
    fn data_helper(&mut self, amount: usize, hard: bool, and_consume: bool)
                   -> Result<&[u8], io::Error> {
        // println!("BufferedReaderGeneric.data_helper(\
        //           amount: {}, hard: {}, and_consume: {} (cursor: {}, buffer: {:?})",
        //          amount, hard, and_consume,
        //          self.cursor,
        //          if let Some(ref buffer) = self.buffer { Some(buffer.len()) }
        //          else { None });


        if let Some(ref buffer) = self.buffer {
            // We have a buffer.  Make sure `cursor` is sane.
            assert!(self.cursor <= buffer.len());
        } else {
            // We don't have a buffer.  Make sure cursor is 0.
            assert_eq!(self.cursor, 0);
        }

        let amount_buffered =
            if let Some(ref buffer) = self.buffer { buffer.len() } else { 0 }
            - self.cursor;
        if !self.saw_eof && amount > amount_buffered {
            // The caller wants more data than we have readily
            // available.  Read some more.

            let capacity : usize = cmp::max(cmp::max(
                DEFAULT_BUF_SIZE,
                2 * self.preferred_chunk_size), amount);

            let mut buffer_new : Vec<u8> = vec![0u8; capacity];

            let mut amount_read = 0;
            while amount_buffered + amount_read < amount {
                match self.reader.read(&mut buffer_new
                                       [amount_buffered + amount_read..]) {
                    Ok(read) => {
                        if read == 0 {
                            // XXX: Likely EOF.
                            self.saw_eof = true;
                            break;
                        } else {
                            amount_read += read;
                            continue;
                        }
                    },
                    Err(err) => {
                        // Don't return yet, because we may have
                        // actually read something.
                        self.saw_eof = true;
                        self.error = Some(err);
                        break;
                    },
                }
            }

            if amount_read > 0 {
                // We read something.

                if let Some(ref buffer) = self.buffer {
                    // We need to copy in the old data.
                    buffer_new[0..amount_buffered]
                        .copy_from_slice(
                            &buffer[self.cursor..self.cursor + amount_buffered]);
                }

                buffer_new.truncate(amount_buffered + amount_read);
                buffer_new.shrink_to_fit();

                self.buffer = Some(buffer_new.into_boxed_slice());
                self.cursor = 0;
            }
        }

        if self.error.is_some() {
            // An error occured.  If we have enough data to fulfill
            // the caller's request, then delay returning the error.
            if let Some(ref buffer) = self.buffer {
                if amount > buffer.len() {
                    // We return an error at most once (Recall: take
                    // clears self.error).
                    return Err(self.error.take().unwrap());
                }
            }
        }

        match self.buffer {
            Some(ref buffer) => {
                let amount_buffered = buffer.len() - self.cursor;
                if hard && amount_buffered < amount {
                    return Err(Error::new(ErrorKind::UnexpectedEof, "EOF"));
                }
                if and_consume {
                    let amount_consumed = cmp::min(amount_buffered, amount);
                    self.cursor += amount_consumed;
                    assert!(self.cursor <= buffer.len());
                    return Ok(&buffer[self.cursor-amount_consumed..]);
                } else {
                    return Ok(&buffer[self.cursor..]);
                }
            },
            None if self.saw_eof => {
                return Ok(&b""[..]);
            },
            None => {
                unreachable!();
            }
        }
    }
}

impl<T: io::Read, C> io::Read for BufferedReaderGeneric<T, C> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, io::Error> {
        return buffered_reader_generic_read_impl(self, buf);
    }
}

impl<T: io::Read, C> BufferedReader<C> for BufferedReaderGeneric<T, C> {
    fn data(&mut self, amount: usize) -> Result<&[u8], io::Error> {
        return self.data_helper(amount, false, false);
    }

    fn data_hard(&mut self, amount: usize) -> Result<&[u8], io::Error> {
        return self.data_helper(amount, true, false);
    }

    fn consume(&mut self, amount: usize) -> &[u8] {
        // println!("BufferedReaderGeneric.consume({}) \
        //           (cursor: {}, buffer: {:?})",
        //          amount, self.cursor,
        //          if let Some(ref buffer) = self.buffer { Some(buffer.len()) }
        //          else { None });

        // The caller can't consume more than is buffered!
        if let Some(ref buffer) = self.buffer {
            assert!(self.cursor <= buffer.len());
            assert!(amount <= buffer.len() - self.cursor,
                    "buffer contains just {} bytes, but you are trying to \
                    consume {} bytes.  Did you forget to call data()?",
                    buffer.len() - self.cursor, amount);

            self.cursor += amount;
            return &self.buffer.as_ref().unwrap()[self.cursor - amount..];
        } else {
            assert_eq!(amount, 0);
            return &b""[..];
        }
    }

    fn data_consume(&mut self, amount: usize) -> Result<&[u8], io::Error> {
        return self.data_helper(amount, false, true);
    }

    fn data_consume_hard(&mut self, amount: usize) -> Result<&[u8], io::Error> {
        return self.data_helper(amount, true, true);
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
fn buffered_reader_generic_test() {
    // Test reading from a file.
    {
        use std::path::PathBuf;
        use std::fs::File;

        let path : PathBuf = [env!("CARGO_MANIFEST_DIR"),
                              "src", "buffered-reader-test.txt"]
            .iter().collect();
        let mut f = File::open(&path).expect(&path.to_string_lossy());
        let mut bio = BufferedReaderGeneric::new(&mut f, None);

        buffered_reader_test_data_check(&mut bio);
    }

    // Same test, but as a slice.
    {
        let mut data : &[u8] = include_bytes!("buffered-reader-test.txt");
        let mut bio = BufferedReaderGeneric::new(&mut data, None);

        buffered_reader_test_data_check(&mut bio);
    }
}
