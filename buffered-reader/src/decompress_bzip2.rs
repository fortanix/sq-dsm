use std::io;
use std::fmt;

use bzip2::read::BzDecoder;

use super::*;


/// Decompresses the underlying `BufferedReader` using the bzip2
/// algorithm.
pub struct Bzip<R: BufferedReader<C>, C> {
    reader: Generic<BzDecoder<R>, C>,
}

impl <R: BufferedReader<()>> Bzip<R, ()> {
    /// Instantiates a new bzip decompression reader.
    ///
    /// `reader` is the source to wrap.
    pub fn new(reader: R) -> Self {
        Self::with_cookie(reader, ())
    }
}

impl <R: BufferedReader<C>, C> Bzip<R, C> {
    /// Like `new()`, but uses a cookie.
    ///
    /// The cookie can be retrieved using the `cookie_ref` and
    /// `cookie_mut` methods, and set using the `cookie_set` method.
    pub fn with_cookie(reader: R, cookie: C) -> Self {
        Bzip {
            reader: Generic::with_cookie(
                BzDecoder::new(reader), None, cookie),
        }
    }
}

impl<R: BufferedReader<C>, C> io::Read for Bzip<R, C> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, io::Error> {
        self.reader.read(buf)
    }
}

impl<R: BufferedReader<C>, C> fmt::Debug for Bzip<R, C> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Bzip")
            .field("reader", &self.get_ref().unwrap())
            .finish()
    }
}

impl<R: BufferedReader<C>, C> fmt::Display for Bzip<R, C> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Bzip")
    }
}

impl<R: BufferedReader<C>, C> BufferedReader<C> for Bzip<R, C> {
    fn buffer(&self) -> &[u8] {
        return self.reader.buffer();
    }

    fn data(&mut self, amount: usize) -> Result<&[u8], io::Error> {
        return self.reader.data(amount);
    }

    fn data_hard(&mut self, amount: usize) -> Result<&[u8], io::Error> {
        return self.reader.data_hard(amount);
    }

    fn data_eof(&mut self) -> Result<&[u8], io::Error> {
        return self.reader.data_eof();
    }

    fn consume(&mut self, amount: usize) -> &[u8] {
        return self.reader.consume(amount);
    }

    fn data_consume(&mut self, amount: usize)
                    -> Result<&[u8], io::Error> {
        return self.reader.data_consume(amount);
    }

    fn data_consume_hard(&mut self, amount: usize) -> Result<&[u8], io::Error> {
        return self.reader.data_consume_hard(amount);
    }

    fn read_be_u16(&mut self) -> Result<u16, io::Error> {
        return self.reader.read_be_u16();
    }

    fn read_be_u32(&mut self) -> Result<u32, io::Error> {
        return self.reader.read_be_u32();
    }

    fn steal(&mut self, amount: usize) -> Result<Vec<u8>, io::Error> {
        return self.reader.steal(amount);
    }

    fn steal_eof(&mut self) -> Result<Vec<u8>, io::Error> {
        return self.reader.steal_eof();
    }

    fn get_mut(&mut self) -> Option<&mut dyn BufferedReader<C>> {
        Some(self.reader.reader.get_mut())
    }

    fn get_ref(&self) -> Option<&dyn BufferedReader<C>> {
        Some(self.reader.reader.get_ref())
    }

    fn into_inner<'b>(self: Box<Self>)
            -> Option<Box<dyn BufferedReader<C> + 'b>> where Self: 'b {
        // Strip the outer box.
        Some(self.reader.reader.into_inner().as_boxed())
    }

    fn cookie_set(&mut self, cookie: C) -> C {
        self.reader.cookie_set(cookie)
    }

    fn cookie_ref(&self) -> &C {
        self.reader.cookie_ref()
    }

    fn cookie_mut(&mut self) -> &mut C {
        self.reader.cookie_mut()
    }
}
