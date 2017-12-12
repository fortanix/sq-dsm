use std::io;
use std::fmt;

use flate2::read::DeflateDecoder;
use flate2::read::ZlibDecoder;
use bzip2::read::BzDecoder;

use super::*;

pub struct BufferedReaderDeflate<R: BufferedReader> {
    reader: BufferedReaderGeneric<DeflateDecoder<R>>,
}

impl <R: BufferedReader> BufferedReaderDeflate<R> {
    pub fn new(reader: R) -> BufferedReaderDeflate<R> {
        BufferedReaderDeflate {
            reader: BufferedReaderGeneric::new(DeflateDecoder::new(reader), None)
        }
    }
}

impl<R: BufferedReader> io::Read for BufferedReaderDeflate<R> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, io::Error> {
        self.reader.read(buf)
    }
}

impl <R: BufferedReader> fmt::Debug for BufferedReaderDeflate<R> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("BufferedReaderDeflate")
            .field("reader", self.reader.reader.get_ref())
            .finish()
    }
}

impl<R: BufferedReader> BufferedReader for BufferedReaderDeflate<R> {
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

    fn into_inner<'b>(self: Box<Self>) -> Option<Box<BufferedReader + 'b>> where Self: 'b {
        // Strip the outer box.
        Some(Box::new((*self).reader.reader.into_inner()))
    }
}

pub struct BufferedReaderZlib<R: BufferedReader> {
    reader: BufferedReaderGeneric<ZlibDecoder<R>>,
}

impl <R: BufferedReader> BufferedReaderZlib<R> {
    pub fn new(reader: R) -> BufferedReaderZlib<R> {
        BufferedReaderZlib {
            reader: BufferedReaderGeneric::new(ZlibDecoder::new(reader), None)
        }
    }
}

impl<R: BufferedReader> io::Read for BufferedReaderZlib<R> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, io::Error> {
        self.reader.read(buf)
    }
}

impl <R: BufferedReader> fmt::Debug for BufferedReaderZlib<R> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("BufferedReaderZlib")
            .field("reader", self.reader.reader.get_ref())
            .finish()
    }
}

impl<R: BufferedReader> BufferedReader for BufferedReaderZlib<R> {
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

    fn into_inner<'b>(self: Box<Self>) -> Option<Box<BufferedReader + 'b>> where Self: 'b {
        // Strip the outer box.
        Some(Box::new((*self).reader.reader.into_inner()))
    }
}

pub struct BufferedReaderBzip<R: BufferedReader> {
    reader: BufferedReaderGeneric<BzDecoder<R>>,
}

impl <R: BufferedReader> BufferedReaderBzip<R> {
    pub fn new(reader: R) -> BufferedReaderBzip<R> {
        BufferedReaderBzip {
            reader: BufferedReaderGeneric::new(BzDecoder::new(reader), None)
        }
    }
}

impl<R: BufferedReader> io::Read for BufferedReaderBzip<R> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, io::Error> {
        self.reader.read(buf)
    }
}

impl <R: BufferedReader> fmt::Debug for BufferedReaderBzip<R> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("BufferedReaderBzip")
            .field("reader", self.reader.reader.get_ref())
            .finish()
    }
}

impl<R: BufferedReader> BufferedReader for BufferedReaderBzip<R> {
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

    fn into_inner<'b>(self: Box<Self>) -> Option<Box<BufferedReader + 'b>> where Self: 'b {
        // Strip the outer box.
        Some(Box::new((*self).reader.reader.into_inner()))
    }
}
