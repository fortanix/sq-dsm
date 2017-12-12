use std;
use std::str;
use std::io;
use std::io::{Error,ErrorKind};
use std::cmp;
use std::fmt;

// The default buffer size.
const DEFAULT_BUF_SIZE: usize = 8 * 1024;

pub mod buffered_reader_decompress;
pub mod buffered_reader_partial_body;

/// A `BufferedReader` is a type of `Read`er that has an internal
/// buffer, and allows working directly from that buffer.  Like a
/// `BufRead`er, the internal buffer amortizes system calls.  And,
/// like a `BufRead`, a `BufferedReader` exposes the internal buffer
/// so that a user can work with the data in place rather than having
/// to first copy it to a local buffer.  However, unlike `BufRead`,
/// `BufferedReader` allows the caller to ensure that the internal
/// buffer has a certain amount of data.
pub trait BufferedReader : io::Read + fmt::Debug {
    /// Return the data in the internal buffer.  Normally, the
    /// returned buffer will contain *at least* `amount` bytes worth
    /// of data.  Less data may be returned if the end of the file is
    /// reached or an error occurs.  In these cases, any remaining
    /// data is returned.  Note: the error is not discarded, but will
    /// be returned when data is called and the internal buffer is
    /// empty.
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


    // This is a convenient function that effectively combines
    // data_hard() and consume().
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
    /// caller owned buffer.  Implementations may optimize this to
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

    fn into_inner<'a>(self: Box<Self>) -> Option<Box<BufferedReader + 'a>>
        where Self: 'a;
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
pub fn buffered_reader_generic_read_impl<T: BufferedReader>
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
impl <'a> BufferedReader for Box<BufferedReader + 'a> {
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

    fn into_inner<'b>(self: Box<Self>) -> Option<Box<BufferedReader + 'b>>
            where Self: 'b {
        // Strip the outer box.
        (*self).into_inner()
    }
}

/// A generic `BufferedReader` implementation that only requires a
/// source that implements the `Read` trait.  This is sufficient when
/// reading from a file, and it even works with a `&[u8]` (but
/// `BufferedReaderMemory` is more efficient).
pub struct BufferedReaderGeneric<T: io::Read> {
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
}

impl<T: io::Read> std::fmt::Debug for BufferedReaderGeneric<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
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

impl<T: io::Read> BufferedReaderGeneric<T> {
    /// Instantiate a new generic reader.  `reader` is the source to
    /// wrap.  `preferred_chuck_size` is the preferred chuck size.  If
    /// None, then the default will be used, which is usually what you
    /// want.
    pub fn new(reader: T, preferred_chunk_size: Option<usize>)
           -> BufferedReaderGeneric<T> {
        BufferedReaderGeneric {
            buffer: None,
            cursor: 0,
            preferred_chunk_size:
                if let Some(s) = preferred_chunk_size { s } else { DEFAULT_BUF_SIZE },
            reader: Box::new(reader),
            saw_eof: false,
            error: None,
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
                    DEFAULT_BUF_SIZE, 2 * self.preferred_chunk_size), amount);

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

impl<T: io::Read> io::Read for BufferedReaderGeneric<T> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, io::Error> {
        return buffered_reader_generic_read_impl(self, buf);
    }
}

impl<T: io::Read> BufferedReader for BufferedReaderGeneric<T> {
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
                    "buffer contains just {} bytes, but you are trying to 
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

    fn into_inner<'b>(self: Box<Self>) -> Option<Box<BufferedReader + 'b>>
        where Self: 'b {
        None
    }
}

// The file was created as follows:
//
//   for i in $(seq 0 9999); do printf "%04d\n" $i; done > buffered-reader-test.txt
#[cfg(test)]
fn buffered_reader_test_data_check<'a, T: BufferedReader + 'a>(bio: &mut T) {
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

#[test]
fn buffered_reader_generic_test() {
    // Test reading from a file.
    {
        use std::path::PathBuf;
        use std::fs::File;

        let path : PathBuf = [env!("CARGO_MANIFEST_DIR"),
                              "src", "buffered_reader", "buffered-reader-test.txt"]
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

/// A `BufferedReader` specialized for reading from memory buffers.
pub struct BufferedReaderMemory<'a> {
    buffer: &'a [u8],
    // The next byte to read in the buffer.
    cursor: usize,
}

impl <'a> std::fmt::Debug for BufferedReaderMemory<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
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

/// A `BufferedReaderLimitor` limits the amount of data that can be
/// read from a `BufferedReader`.
#[derive(Debug)]
pub struct BufferedReaderLimitor<T: BufferedReader> {
    reader: T,
    limit: u64,
}

impl<T: BufferedReader> BufferedReaderLimitor<T> {
    pub fn new(reader: T, limit: u64) -> BufferedReaderLimitor<T> {
        BufferedReaderLimitor {
            reader: reader,
            limit: limit,
        }
    }
}

impl<T: BufferedReader> io::Read for BufferedReaderLimitor<T> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, io::Error> {
        let len = cmp::min(self.limit, buf.len() as u64) as usize;
        return self.reader.read(&mut buf[0..len]);
    }
}

impl<T: BufferedReader> BufferedReader for BufferedReaderLimitor<T> {
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

    fn into_inner<'b>(self: Box<Self>) -> Option<Box<BufferedReader + 'b>>
            where Self: 'b {
        Some(Box::new(self.reader))
    }
}

#[test]
fn buffered_reader_limitor_test() {
    let data : &[u8] = b"01234567890123456789";

    /* Add a single limitor.  */
    {
        let mut bio : Box<BufferedReader>
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
        let mut bio : Box<BufferedReader>
            = Box::new(BufferedReaderMemory::new(data));

        bio = {
            let bio2 : Box<BufferedReader>
                = Box::new(BufferedReaderLimitor::new(bio, 5));
            // We limit to 15 bytes, but bio2 will still limit us to 5
            // bytes.
            let mut bio3 : Box<BufferedReader>
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
            let mut bio2 = BufferedReaderLimitor::new(bio, (data.len() / 2) as u64);
            let amount = {
                bio2.data_eof().unwrap().len()
            };
            assert_eq!(amount, data.len() / 2);
            bio2.consume(amount);
            assert_eq!(bio2.data(1).unwrap().len(), 0);
        }
    }

    #[cfg(test)]
    fn buffered_reader_read_test_aux<'a, T: BufferedReader + 'a>
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
                                  "src", "buffered_reader",
                                  "buffered-reader-test.txt"]
                .iter().collect();

            let mut f = File::open(&path).expect(&path.to_string_lossy());
            let bio = BufferedReaderGeneric::new(&mut f, None);
            buffered_reader_read_test_aux (bio, data);
        }
    }
}
