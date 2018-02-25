//! An improved `BufRead` interface.

extern crate flate2;
extern crate bzip2;

use std::io;
use std::io::{Error,ErrorKind};
use std::cmp;
use std::fmt;

mod generic;
mod memory;
mod limitor;
mod eof;
mod decompress;

pub use self::generic::BufferedReaderGeneric;
pub use self::memory::BufferedReaderMemory;
pub use self::limitor::BufferedReaderLimitor;
pub use self::eof::BufferedReaderEOF;
pub use self::decompress::BufferedReaderDeflate;
pub use self::decompress::BufferedReaderZlib;
pub use self::decompress::BufferedReaderBzip;

// The default buffer size.
const DEFAULT_BUF_SIZE: usize = 8 * 1024;

/// A `BufferedReader` is a type of `Read`er that has an internal
/// buffer, and allows working directly from that buffer.  Like a
/// `BufRead`er, the internal buffer amortizes system calls.  And,
/// like a `BufRead`, a `BufferedReader` exposes the internal buffer
/// so that a user can work with the data in place rather than having
/// to first copy it to a local buffer.  However, unlike `BufRead`,
/// `BufferedReader` allows the caller to ensure that the internal
/// buffer has a certain amount of data.
pub trait BufferedReader<C> : io::Read + fmt::Debug {
    /// Returns a reference to the internal buffer.
    ///
    /// Note: this will return the same data as self.data(0), but it
    /// does so without mutable borrowing self.
    fn buffer(&self) -> &[u8];

    /// Return the data in the internal buffer.  Normally, the
    /// returned buffer will contain *at least* `amount` bytes worth
    /// of data.  Less data may be returned if (and only if) the end
    /// of the file is reached or an error occurs.  In these cases,
    /// any remaining data is returned.  Note: the error is not
    /// discarded, but will be returned when data is called and the
    /// internal buffer is empty.
    ///
    /// This function does not advance the cursor.  Thus, multiple
    /// calls will return the same data.  To advance the cursor, use
    /// `consume`.
    fn data(&mut self, amount: usize) -> Result<&[u8], io::Error>;

    /// Like `data`, but returns an error if there is not at least
    /// `amount` bytes available.
    fn data_hard(&mut self, amount: usize) -> Result<&[u8], io::Error> {
        let result = self.data(amount);
        if let Ok(buffer) = result {
            if buffer.len() < amount {
                return Err(Error::new(ErrorKind::UnexpectedEof, "unepxected EOF"));
            }
        }
        return result;
    }

    /// Return all of the data until EOF.  Like `data`, this does not
    /// actually consume the data that is read.
    ///
    /// In general, you shouldn't use this function as it can cause an
    /// enormous amount of buffering.  But, if you know that the
    /// amount of data is limited, this is acceptable.
    fn data_eof(&mut self) -> Result<&[u8], io::Error> {
        // Don't just read std::usize::MAX bytes at once.  The
        // implementation might try to actually allocate a buffer that
        // large!  Instead, try with increasingly larger buffers until
        // the read is (strictly) shorter than the specified size.
        let mut s = DEFAULT_BUF_SIZE;
        while s < std::usize::MAX {
            match self.data(s) {
                Ok(ref buffer) =>
                    if buffer.len() < s {
                        // We really want to do
                        //
                        //   return Ok(buffer);
                        //
                        // But, the borrower checker won't let us:
                        //
                        //  error[E0499]: cannot borrow `*self` as
                        //  mutable more than once at a time.
                        //
                        // Instead, we break out of the loop, and then
                        // call self.data(s) again.  This extra call
                        // shouldn't have any significant cost,
                        // because the buffer should already be
                        // prepared.
                        break;
                    } else {
                        s *= 2;
                    },
                Err(err) =>
                    return Err(err),
            }
        }
        return self.data(s);
    }

    /// Mark the first `amount` bytes of the internal buffer as
    /// consumed.  It is an error to call this function without having
    /// first successfully called `data` (or a related function) to
    /// buffer `amount` bytes.
    ///
    /// This function returns the data that has been consumed.
    fn consume(&mut self, amount: usize) -> &[u8];

    /// This is a convenient function that effectively combines data()
    /// and consume().
    fn data_consume(&mut self, amount: usize)
                    -> Result<&[u8], std::io::Error>;


    /// This is a convenient function that effectively combines
    /// data_hard() and consume().
    fn data_consume_hard(&mut self, amount: usize) -> Result<&[u8], io::Error>;

    /// A convenience function for reading a 16-bit unsigned integer
    /// in big endian format.
    fn read_be_u16(&mut self) -> Result<u16, std::io::Error> {
        let input = self.data_consume_hard(2)?;
        return Ok(((input[0] as u16) << 8) + (input[1] as u16));
    }

    /// A convenience function for reading a 32-bit unsigned integer
    /// in big endian format.
    fn read_be_u32(&mut self) -> Result<u32, std::io::Error> {
        let input = self.data_consume_hard(4)?;
        return Ok(((input[0] as u32) << 24) + ((input[1] as u32) << 16)
                  + ((input[2] as u32) << 8) + (input[3] as u32));
    }

    /// Reads and consumes `amount` bytes, and returns them in a
    /// caller-owned buffer.  Implementations may optimize this to
    /// avoid a copy.
    fn steal(&mut self, amount: usize) -> Result<Vec<u8>, std::io::Error> {
        let mut data = self.data_consume_hard(amount)?;
        assert!(data.len() >= amount);
        if data.len() > amount {
            data = &data[..amount];
        }
        return Ok(data.to_vec());
    }

    /// Like steal, but instead of stealing a fixed number of bytes,
    /// it steals all of the data it can.
    fn steal_eof(&mut self) -> Result<Vec<u8>, std::io::Error> {
        let len = self.data_eof()?.len();
        let data = self.steal(len)?;
        return Ok(data);
    }

    /// Like steal_eof, but instead of returning the data, the data is
    /// discarded.
    fn drop_eof(&mut self) -> Result<(), std::io::Error> {
        loop {
            match self.data_consume(DEFAULT_BUF_SIZE) {
                Ok(ref buffer) =>
                    if buffer.len() < DEFAULT_BUF_SIZE {
                        // EOF.
                        break;
                    },
                Err(err) =>
                    return Err(err),
            }
        }

        Ok(())
    }

    fn into_inner<'a>(self: Box<Self>) -> Option<Box<BufferedReader<C> + 'a>>
        where Self: 'a;

    /// Returns a mutable reference to the inner `BufferedReader`, if
    /// any.
    ///
    /// It is a very bad idea to read any data from the inner
    /// `BufferedReader`, but it can sometimes be useful to get the
    /// cookie.
    fn get_mut(&mut self) -> Option<&mut BufferedReader<C>>;

    /// Returns a reference to the inner `BufferedReader`.
    fn get_ref(&self) -> Option<&BufferedReader<C>>;

    /// Sets the `BufferedReader`'s cookie and returns the old value.
    fn cookie_set(&mut self, cookie: C) -> C;

    /// Returns a reference to the `BufferedReader`'s cookie.
    fn cookie_ref(&self) -> &C;

    /// Returns a mutable reference to the `BufferedReader`'s cookie.
    fn cookie_mut(&mut self) -> &mut C;
}

/// This function implements the `std::io::Read::read` method in terms
/// of the `data_consume` method.  We can't use the `io::std::Read`
/// interface, because the `BufferedReader` may have buffered some
/// data internally (in which case a read will not return the buffered
/// data, but the following data).  This implementation is generic.
/// When deriving a `BufferedReader`, you can include the following:
///
/// ```text
/// impl<'a, T: BufferedReader> std::io::Read for BufferedReaderXXX<'a, T> {
///     fn read(&mut self, buf: &mut [u8]) -> Result<usize, std::io::Error> {
///         return buffered_reader_generic_read_impl(self, buf);
///     }
/// }
/// ```
///
/// It would be nice if we could do:
///
/// ```text
/// impl <T: BufferedReader> std::io::Read for T { ... }
/// ```
///
/// but, alas, Rust doesn't like that ("error[E0119]: conflicting
/// implementations of trait `std::io::Read` for type `&mut _`").
pub fn buffered_reader_generic_read_impl<T: BufferedReader<C>, C>
        (bio: &mut T, buf: &mut [u8]) -> Result<usize, io::Error> {
    match bio.data_consume(buf.len()) {
        Ok(inner) => {
            let amount = cmp::min(buf.len(), inner.len());
            buf[0..amount].copy_from_slice(&inner[0..amount]);
            return Ok(amount);
        },
        Err(err) => return Err(err),
    }
}

/// Make a `Box<BufferedReader>` look like a BufferedReader.
impl <'a, C> BufferedReader<C> for Box<BufferedReader<C> + 'a> {
    fn buffer(&self) -> &[u8] {
        return self.as_ref().buffer();
    }

    fn data(&mut self, amount: usize) -> Result<&[u8], io::Error> {
        return self.as_mut().data(amount);
    }

    fn data_hard(&mut self, amount: usize) -> Result<&[u8], io::Error> {
        return self.as_mut().data_hard(amount);
    }

    fn data_eof(&mut self) -> Result<&[u8], io::Error> {
        return self.as_mut().data_eof();
    }

    fn consume(&mut self, amount: usize) -> &[u8] {
        return self.as_mut().consume(amount);
    }

    fn data_consume(&mut self, amount: usize)
                    -> Result<&[u8], std::io::Error> {
        return self.as_mut().data_consume(amount);
    }

    fn data_consume_hard(&mut self, amount: usize) -> Result<&[u8], io::Error> {
        return self.as_mut().data_consume_hard(amount);
    }

    fn read_be_u16(&mut self) -> Result<u16, std::io::Error> {
        return self.as_mut().read_be_u16();
    }

    fn read_be_u32(&mut self) -> Result<u32, std::io::Error> {
        return self.as_mut().read_be_u32();
    }

    fn steal(&mut self, amount: usize) -> Result<Vec<u8>, std::io::Error> {
        return self.as_mut().steal(amount);
    }

    fn steal_eof(&mut self) -> Result<Vec<u8>, std::io::Error> {
        return self.as_mut().steal_eof();
    }

    fn drop_eof(&mut self) -> Result<(), std::io::Error> {
        return self.as_mut().drop_eof();
    }

    fn get_mut(&mut self) -> Option<&mut BufferedReader<C>> {
        // Strip the outer box.
        self.as_mut().get_mut()
    }

    fn get_ref(&self) -> Option<&BufferedReader<C>> {
        // Strip the outer box.
        self.as_ref().get_ref()
    }

    fn into_inner<'b>(self: Box<Self>) -> Option<Box<BufferedReader<C> + 'b>>
            where Self: 'b {
        // Strip the outer box.
        (*self).into_inner()
    }

    fn cookie_set(&mut self, cookie: C) -> C {
        self.as_mut().cookie_set(cookie)
    }

    fn cookie_ref(&self) -> &C {
        self.as_ref().cookie_ref()
    }

    fn cookie_mut(&mut self) -> &mut C {
        self.as_mut().cookie_mut()
    }
}

// The file was created as follows:
//
//   for i in $(seq 0 9999); do printf "%04d\n" $i; done > buffered-reader-test.txt
#[cfg(test)]
fn buffered_reader_test_data_check<'a, T: BufferedReader<C> + 'a, C>(bio: &mut T) {
    use std::str;

    for i in 0 .. 10000 {
        let consumed = {
            // Each number is 4 bytes plus a newline character.
            let d = bio.data_hard(5);
            if d.is_err() {
                println!("Error for i == {}: {:?}", i, d);
            }
            let d = d.unwrap();
            assert!(d.len() >= 5);
            assert_eq!(format!("{:04}\n", i), str::from_utf8(&d[0..5]).unwrap());

            5
        };

        bio.consume(consumed);
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn buffered_reader_eof_test() {
        let data : &[u8] = include_bytes!("buffered-reader-test.txt");

        // Make sure data_eof works.
        {
            let mut bio = BufferedReaderMemory::new(data);
            let amount = {
                bio.data_eof().unwrap().len()
            };
            bio.consume(amount);
            assert_eq!(bio.data(1).unwrap().len(), 0);
        }

        // Try it again with a limitor.
        {
            let bio = BufferedReaderMemory::new(data);
            let mut bio2 = BufferedReaderLimitor::new(
                bio, (data.len() / 2) as u64);
            let amount = {
                bio2.data_eof().unwrap().len()
            };
            assert_eq!(amount, data.len() / 2);
            bio2.consume(amount);
            assert_eq!(bio2.data(1).unwrap().len(), 0);
        }
    }

    #[cfg(test)]
    fn buffered_reader_read_test_aux<'a, T: BufferedReader<C> + 'a, C>
        (mut bio: T, data: &[u8]) {
        let mut buffer = [0; 99];

        // Make sure the test file has more than buffer.len() bytes
        // worth of data.
        assert!(buffer.len() < data.len());

        // The number of reads we'll have to perform.
        let iters = (data.len() + buffer.len() - 1) / buffer.len();
        // Iterate more than the number of required reads to check
        // what happens when we try to read beyond the end of the
        // file.
        for i in 1..iters + 2 {
            let data_start = (i - 1) * buffer.len();

            // We don't want to just check that read works in
            // isolation.  We want to be able to mix .read and .data
            // calls.
            {
                let result = bio.data(buffer.len());
                let buffer = result.unwrap();
                if buffer.len() > 0 {
                    assert_eq!(buffer,
                               &data[data_start..data_start + buffer.len()]);
                }
            }

            // Now do the actual read.
            let result = bio.read(&mut buffer[..]);
            let got = result.unwrap();
            if got > 0 {
                assert_eq!(&buffer[0..got],
                           &data[data_start..data_start + got]);
            }

            if i > iters {
                // We should have read everything.
                assert!(got == 0);
            } else if i == iters {
                // The last read.  This may be less than buffer.len().
                // But it should include at least one byte.
                assert!(0 < got);
                assert!(got <= buffer.len());
            } else {
                assert_eq!(got, buffer.len());
            }
        }
    }

    #[test]
    fn buffered_reader_read_test() {
        let data : &[u8] = include_bytes!("buffered-reader-test.txt");

        {
            let bio = BufferedReaderMemory::new(data);
            buffered_reader_read_test_aux (bio, data);
        }

        {
            use std::path::PathBuf;
            use std::fs::File;

            let path : PathBuf = [env!("CARGO_MANIFEST_DIR"),
                                  "src",
                                  "buffered-reader-test.txt"]
                .iter().collect();

            let mut f = File::open(&path).expect(&path.to_string_lossy());
            let bio = BufferedReaderGeneric::new(&mut f, None);
            buffered_reader_read_test_aux (bio, data);
        }
    }
}
