use std::io;
use std::fmt;

use flate2::read::DeflateDecoder;
use flate2::read::ZlibDecoder;
use bzip2::read::BzDecoder;

use super::*;

pub struct BufferedReaderDeflate<R: BufferedReader<C>, C> {
    reader: BufferedReaderGeneric<DeflateDecoder<R>, C>,
}

impl <R: BufferedReader<()>> BufferedReaderDeflate<R, ()> {
    /// Instantiate a new deflate decompression reader.  `reader` is
    /// the source to wrap.
    pub fn new(reader: R) -> Self {
        Self::with_cookie(reader, ())
    }
}

impl <R: BufferedReader<C>, C> BufferedReaderDeflate<R, C> {
    /// Like `new()`, but sets a cookie, which can be retrieved using
    /// the `cookie_ref` and `cookie_mut` methods, and set using
    /// the `cookie_set` method.
    pub fn with_cookie(reader: R, cookie: C) -> Self {
        BufferedReaderDeflate {
            reader: BufferedReaderGeneric::with_cookie(
                DeflateDecoder::new(reader), None, cookie),
        }
    }
}

impl<R: BufferedReader<C>, C> io::Read for BufferedReaderDeflate<R, C> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, io::Error> {
        self.reader.read(buf)
    }
}

impl <R: BufferedReader<C>, C> fmt::Debug for BufferedReaderDeflate<R, C> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("BufferedReaderDeflate")
            .field("reader", self.reader.reader.get_ref())
            .finish()
    }
}

impl<R: BufferedReader<C>, C> BufferedReader<C>
        for BufferedReaderDeflate<R, C> {
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

    fn into_inner<'b>(self: Box<Self>)
            -> Option<Box<BufferedReader<C> + 'b>> where Self: 'b {
        // Strip the outer box.
        Some(Box::new((*self).reader.reader.into_inner()))
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

pub struct BufferedReaderZlib<R: BufferedReader<C>, C> {
    reader: BufferedReaderGeneric<ZlibDecoder<R>, C>,
}

impl <R: BufferedReader<()>> BufferedReaderZlib<R, ()> {
    /// Instantiate a new zlib decompression reader.  `reader` is
    /// the source to wrap.
    pub fn new(reader: R) -> Self {
        Self::with_cookie(reader, ())
    }
}

impl <R: BufferedReader<C>, C> BufferedReaderZlib<R, C> {
    /// Like `new()`, but sets a cookie, which can be retrieved using
    /// the `cookie_ref` and `cookie_mut` methods, and set using
    /// the `cookie_set` method.
    pub fn with_cookie(reader: R, cookie: C) -> Self {
        BufferedReaderZlib {
            reader: BufferedReaderGeneric::with_cookie(
                ZlibDecoder::new(reader), None, cookie),
        }
    }
}

impl<R: BufferedReader<C>, C> io::Read for BufferedReaderZlib<R, C> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, io::Error> {
        self.reader.read(buf)
    }
}

impl <R: BufferedReader<C>, C> fmt::Debug for BufferedReaderZlib<R, C> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("BufferedReaderZlib")
            .field("reader", self.reader.reader.get_ref())
            .finish()
    }
}

impl<R: BufferedReader<C>, C> BufferedReader<C>
        for BufferedReaderZlib<R, C> {
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

    fn into_inner<'b>(self: Box<Self>)
            -> Option<Box<BufferedReader<C> + 'b>> where Self: 'b {
        // Strip the outer box.
        Some(Box::new((*self).reader.reader.into_inner()))
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

pub struct BufferedReaderBzip<R: BufferedReader<C>, C> {
    reader: BufferedReaderGeneric<BzDecoder<R>, C>,
}

impl <R: BufferedReader<()>> BufferedReaderBzip<R, ()> {
    /// Instantiate a new bzip decompression reader.  `reader` is
    /// the source to wrap.
    pub fn new(reader: R) -> Self {
        Self::with_cookie(reader, ())
    }
}

impl <R: BufferedReader<C>, C> BufferedReaderBzip<R, C> {
    /// Like `new()`, but sets a cookie, which can be retrieved using
    /// the `cookie_ref` and `cookie_mut` methods, and set using
    /// the `cookie_set` method.
    pub fn with_cookie(reader: R, cookie: C) -> Self {
        BufferedReaderBzip {
            reader: BufferedReaderGeneric::with_cookie(
                BzDecoder::new(reader), None, cookie),
        }
    }
}

impl<R: BufferedReader<C>, C> io::Read for BufferedReaderBzip<R, C> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, io::Error> {
        self.reader.read(buf)
    }
}

impl <R: BufferedReader<C>, C> fmt::Debug for BufferedReaderBzip<R, C> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("BufferedReaderBzip")
            .field("reader", self.reader.reader.get_ref())
            .finish()
    }
}

impl<R: BufferedReader<C>, C> BufferedReader<C> for BufferedReaderBzip<R, C> {
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

    fn into_inner<'b>(self: Box<Self>)
            -> Option<Box<BufferedReader<C> + 'b>> where Self: 'b {
        // Strip the outer box.
        Some(Box::new((*self).reader.reader.into_inner()))
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

