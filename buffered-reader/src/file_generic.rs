use std::fmt;
use std::fs::File;
use std::io;
use std::path::Path;

use super::*;

/// Wraps files.
///
/// This is a generic implementation that may be replaced by
/// platform-specific versions.
pub struct BufferedReaderFile<C>(BufferedReaderGeneric<File, C>);

impl<C> fmt::Display for BufferedReaderFile<C> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "BufferedReaderFile")
    }
}

impl<C> fmt::Debug for BufferedReaderFile<C> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_tuple("BufferedReaderFile")
            .field(&self.0)
            .finish()
    }
}

impl BufferedReaderFile<()> {
    /// Opens the given file.
    pub fn open<P: AsRef<Path>>(path: P) -> io::Result<Self> {
        Self::with_cookie(path, ())
    }
}

impl<C> BufferedReaderFile<C> {
    /// Like `open()`, but sets a cookie.
    pub fn with_cookie<P: AsRef<Path>>(path: P, cookie: C) -> io::Result<Self> {
        Ok(BufferedReaderFile(
            BufferedReaderGeneric::with_cookie(File::open(path)?,
                                               None,
                                               cookie)))
    }
}

impl<C> io::Read for BufferedReaderFile<C> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.read(buf)
    }
}

impl<C> BufferedReader<C> for BufferedReaderFile<C> {
    fn buffer(&self) -> &[u8] {
        self.0.buffer()
    }

    fn data(&mut self, amount: usize) -> io::Result<&[u8]> {
        self.0.data(amount)
    }

    fn data_hard(&mut self, amount: usize) -> io::Result<&[u8]> {
        self.0.data_hard(amount)
    }

    fn consume(&mut self, amount: usize) -> &[u8] {
        self.0.consume(amount)
    }

    fn data_consume(&mut self, amount: usize) -> io::Result<&[u8]> {
        self.0.data_consume(amount)
    }

    fn data_consume_hard(&mut self, amount: usize) -> io::Result<&[u8]> {
        self.0.data_consume_hard(amount)
    }

    fn get_mut(&mut self) -> Option<&mut BufferedReader<C>> {
        None
    }

    fn get_ref(&self) -> Option<&BufferedReader<C>> {
        None
    }

    fn into_inner<'b>(self: Box<Self>) -> Option<Box<BufferedReader<C> + 'b>>
        where Self: 'b {
        None
    }

    fn cookie_set(&mut self, cookie: C) -> C {
        self.0.cookie_set(cookie)
    }

    fn cookie_ref(&self) -> &C {
        self.0.cookie_ref()
    }

    fn cookie_mut(&mut self) -> &mut C {
        self.0.cookie_mut()
    }
}
