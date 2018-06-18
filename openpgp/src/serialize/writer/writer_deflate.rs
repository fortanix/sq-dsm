use flate2::Compression as FlateCompression;
use flate2::write::{DeflateEncoder, ZlibEncoder};
use std::fmt;
use std::io;

use Result;
use super::{Generic, Stack, Stackable};

/// ZIPing writer.
pub struct ZIP<'a, C> {
    inner: Generic<DeflateEncoder<Stack<'a, C>>, C>,
}

impl<'a, C> ZIP<'a, C> {
    pub fn new(inner: Stack<'a, C>, cookie: C) -> Box<Self> {
        Box::new(ZIP {
            inner: Generic::new_unboxed(
                DeflateEncoder::new(inner, FlateCompression::default()),
                cookie),
        })
    }
}

impl<'a, C:> fmt::Debug for ZIP<'a, C> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("writer::ZIP")
            .field("inner", &self.inner)
            .finish()
    }
}

impl<'a, C> io::Write for ZIP<'a, C> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.inner.write(bytes)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl<'a, C> Stackable<'a, C> for ZIP<'a, C> {
    fn into_inner(self: Box<Self>) -> Result<Option<Stack<'a, C>>> {
        let inner = self.inner.inner.finish()?;
        Ok(Some(inner))
    }
    fn pop(&mut self) -> Result<Option<Stack<'a, C>>> {
        unimplemented!()
    }
    fn mount(&mut self, _new: Stack<'a, C>) {
        unimplemented!()
    }
    fn inner_mut(&mut self) -> Option<&mut Stackable<'a, C>> {
        self.inner.inner_mut()
    }
    fn inner_ref(&self) -> Option<&Stackable<'a, C>> {
        self.inner.inner_ref()
    }
    fn cookie_set(&mut self, cookie: C) -> C {
        self.inner.cookie_set(cookie)
    }
    fn cookie_ref(&self) -> &C {
        self.inner.cookie_ref()
    }
    fn cookie_mut(&mut self) -> &mut C {
        self.inner.cookie_mut()
    }
}

/// ZLIBing writer.
pub struct ZLIB<'a, C> {
    inner: Generic<ZlibEncoder<Stack<'a, C>>, C>,
}

impl<'a, C> ZLIB<'a, C> {
    pub fn new(inner: Stack<'a, C>, cookie: C) -> Box<Self> {
        Box::new(ZLIB {
            inner: Generic::new_unboxed(
                ZlibEncoder::new(inner, FlateCompression::default()),
                cookie),
        })
    }
}

impl<'a, C:> fmt::Debug for ZLIB<'a, C> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("writer::ZLIB")
            .field("inner", &self.inner)
            .finish()
    }
}

impl<'a, C> io::Write for ZLIB<'a, C> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.inner.write(bytes)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl<'a, C> Stackable<'a, C> for ZLIB<'a, C> {
    fn into_inner(self: Box<Self>) -> Result<Option<Stack<'a, C>>> {
        let inner = self.inner.inner.finish()?;
        Ok(Some(inner))
    }
    fn pop(&mut self) -> Result<Option<Stack<'a, C>>> {
        unimplemented!()
    }
    fn mount(&mut self, _new: Stack<'a, C>) {
        unimplemented!()
    }
    fn inner_mut(&mut self) -> Option<&mut Stackable<'a, C>> {
        self.inner.inner_mut()
    }
    fn inner_ref(&self) -> Option<&Stackable<'a, C>> {
        self.inner.inner_ref()
    }
    fn cookie_set(&mut self, cookie: C) -> C {
        self.inner.cookie_set(cookie)
    }
    fn cookie_ref(&self) -> &C {
        self.inner.cookie_ref()
    }
    fn cookie_mut(&mut self) -> &mut C {
        self.inner.cookie_mut()
    }
}
