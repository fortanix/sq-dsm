use bzip2::Compression as BzCompression;
use bzip2::write::BzEncoder;
use std::fmt;
use std::io;

use Result;
use super::{Generic, Stack, Stackable};

/// BZing writer.
pub struct BZ<'a, C> {
    inner: Generic<BzEncoder<Stack<'a, C>>, C>,
}

impl<'a, C> BZ<'a, C> {
    pub fn new(inner: Stack<'a, C>, cookie: C) -> Box<Self> {
        Box::new(BZ {
            inner: Generic::new_unboxed(
                BzEncoder::new(inner, BzCompression::Default),
                cookie),
        })
    }
}

impl<'a, C:> fmt::Debug for BZ<'a, C> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("writer::BZ")
            .field("inner", &self.inner)
            .finish()
    }
}

impl<'a, C> io::Write for BZ<'a, C> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.inner.write(bytes)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl<'a, C> Stackable<'a, C> for BZ<'a, C> {
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
