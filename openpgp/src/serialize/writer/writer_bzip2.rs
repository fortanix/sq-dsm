use bzip2::Compression as BzCompression;
use bzip2::write::BzEncoder;
use std::fmt;
use std::io;

use crate::Result;
use super::{Generic, Stack, BoxStack, Stackable};

/// BZing writer.
pub struct BZ<'a, C: 'a> {
    inner: Generic<BzEncoder<BoxStack<'a, C>>, C>,
}

impl<'a, C: 'a> BZ<'a, C> {
    /// Makes a BZ compressing writer.
    pub fn new(inner: Stack<'a, C>, cookie: C) -> Stack<'a, C> {
        Stack::from(Box::new(BZ {
            inner: Generic::new_unboxed(
                BzEncoder::new(inner.into(), BzCompression::Default),
                cookie),
        }))
    }
}

impl<'a, C: 'a> fmt::Debug for BZ<'a, C> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("writer::BZ")
            .field("inner", &self.inner)
            .finish()
    }
}

impl<'a, C: 'a> io::Write for BZ<'a, C> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.inner.write(bytes)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl<'a, C: 'a> Stackable<'a, C> for BZ<'a, C> {
    fn into_inner(self: Box<Self>) -> Result<Option<BoxStack<'a, C>>> {
        let inner = self.inner.inner.finish()?;
        Ok(Some(inner))
    }
    fn pop(&mut self) -> Result<Option<BoxStack<'a, C>>> {
        unreachable!("Only implemented by Signer")
    }
    fn mount(&mut self, _new: BoxStack<'a, C>) {
        unreachable!("Only implemented by Signer")
    }
    fn inner_mut(&mut self) -> Option<&mut Stackable<'a, C>> {
        Some(self.inner.inner.get_mut())
    }
    fn inner_ref(&self) -> Option<&Stackable<'a, C>> {
        Some(self.inner.inner.get_ref())
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
    fn position(&self) -> u64 {
        self.inner.position
    }
}
