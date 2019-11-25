//! Stackable writers.

#[cfg(feature = "compression-bzip2")]
mod writer_bzip2;
#[cfg(feature = "compression-bzip2")]
pub use self::writer_bzip2::BZ;
#[cfg(feature = "compression-deflate")]
mod writer_deflate;
#[cfg(feature = "compression-deflate")]
pub use self::writer_deflate::{ZIP, ZLIB};
mod compression_common;
pub use compression_common::CompressionLevel;

use std::fmt;
use std::io;

use crate::crypto::{aead, symmetric};
use crate::types::{
    AEADAlgorithm,
    SymmetricAlgorithm,
};
use crate::{
    Result,
    crypto::SessionKey,
};

/// A stack of writers.
#[derive(Debug)]
pub struct Stack<'a, C>(BoxStack<'a, C>);

impl<'a, C> Stack<'a, C> {
    pub(crate) fn from(bs: BoxStack<'a, C>) -> Self {
        Stack(bs)
    }

    pub(crate) fn as_ref(&self) -> &BoxStack<'a, C> {
        &self.0
    }

    pub(crate) fn as_mut(&mut self) -> &mut BoxStack<'a, C> {
        &mut self.0
    }

    /// Finalizes this writer, returning the underlying writer.
    pub fn finalize_one(self) -> Result<Option<Stack<'a, C>>> {
        Ok(self.0.into_inner()?.map(|bs| Self::from(bs)))
    }

    /// Finalizes all writers, tearing down the whole stack.
    pub fn finalize(self) -> Result<()> {
        let mut stack = self;
        while let Some(s) = stack.finalize_one()? {
            stack = s;
        }
        Ok(())
    }
}

impl<'a, C> io::Write for Stack<'a, C> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}

impl<'a, C> From<Stack<'a, C>> for BoxStack<'a, C> {
    fn from(s: Stack<'a, C>) -> Self {
        s.0
    }
}

pub(crate) type BoxStack<'a, C> = Box<dyn Stackable<'a, C> + 'a>;

/// Makes a writer stackable and provides convenience functions.
pub(crate) trait Stackable<'a, C> : io::Write + fmt::Debug {
    /// Recovers the inner stackable.
    ///
    /// This can fail if the current `Stackable` has buffered data
    /// that hasn't been written to the underlying `Stackable`.
    fn into_inner(self: Box<Self>) -> Result<Option<BoxStack<'a, C>>>;

    /// Pops the stackable from the stack, detaching it.
    ///
    /// Returns the detached stack.
    ///
    /// Note: Only the Signer implements this interface.
    fn pop(&mut self) -> Result<Option<BoxStack<'a, C>>>;

    /// Sets the inner stackable.
    ///
    /// Note: Only the Signer implements this interface.
    fn mount(&mut self, new: BoxStack<'a, C>);

    /// Returns a mutable reference to the inner `Writer`, if
    /// any.
    ///
    /// It is a very bad idea to write any data from the inner
    /// `Writer`, but it can sometimes be useful to get the cookie.
    fn inner_mut(&mut self) -> Option<&mut dyn Stackable<'a, C>>;

    /// Returns a reference to the inner `Writer`.
    fn inner_ref(&self) -> Option<&dyn Stackable<'a, C>>;

    /// Sets the cookie and returns the old value.
    fn cookie_set(&mut self, cookie: C) -> C;

    /// Returns a reference to the cookie.
    fn cookie_ref(&self) -> &C;

    /// Returns a mutable reference to the cookie.
    fn cookie_mut(&mut self) -> &mut C;

    /// Returns the number of bytes written to this filter.
    fn position(&self) -> u64;

    /// Writes a byte.
    fn write_u8(&mut self, b: u8) -> io::Result<()> {
        let b : [u8; 1] = [b; 1];
        self.write_all(&b[..])
    }

    /// Writes a big endian `u16`.
    fn write_be_u16(&mut self, n: u16) -> io::Result<()> {
        let b : [u8; 2] = [ ((n >> 8) & 0xFF) as u8, (n & 0xFF) as u8 ];
        self.write_all(&b[..])
    }

    /// Writes a big endian `u32`.
    fn write_be_u32(&mut self, n: u32) -> io::Result<()> {
        let b : [u8; 4] = [ (n >> 24) as u8, ((n >> 16) & 0xFF) as u8,
                             ((n >> 8) & 0xFF) as u8, (n & 0xFF) as u8 ];
        self.write_all(&b[..])
    }
}

/// Make a `Box<Stackable>` look like a Stackable.
impl <'a, C> Stackable<'a, C> for BoxStack<'a, C> {
    fn into_inner(self: Box<Self>) -> Result<Option<BoxStack<'a, C>>> {
        (*self).into_inner()
    }
    /// Recovers the inner stackable.
    fn pop(&mut self) -> Result<Option<BoxStack<'a, C>>> {
        self.as_mut().pop()
    }
    /// Sets the inner stackable.
    fn mount(&mut self, new: BoxStack<'a, C>) {
        self.as_mut().mount(new);
    }
    fn inner_mut(&mut self) -> Option<&mut dyn Stackable<'a, C>> {
        self.as_mut().inner_mut()
    }
    fn inner_ref(&self) -> Option<&dyn Stackable<'a, C>> {
        self.as_ref().inner_ref()
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
    fn position(&self) -> u64 {
        self.as_ref().position()
    }
}

/// Maps a function over the stack of writers.
#[allow(dead_code)]
pub(crate) fn map<C, F>(head: &dyn Stackable<C>, mut fun: F)
    where F: FnMut(&dyn Stackable<C>) -> bool {
    let mut ow = Some(head);
    while let Some(w) = ow {
        if ! fun(w) {
            break;
        }
        ow = w.inner_ref()
    }
}

/// Maps a function over the stack of mutable writers.
#[allow(dead_code)]
pub(crate) fn map_mut<C, F>(head: &mut dyn Stackable<C>, mut fun: F)
    where F: FnMut(&mut dyn Stackable<C>) -> bool {
    let mut ow = Some(head);
    while let Some(w) = ow {
        if ! fun(w) {
            break;
        }
        ow = w.inner_mut()
    }
}

/// Dumps the writer stack.
#[allow(dead_code)]
pub(crate) fn dump<C>(head: &dyn Stackable<C>) {
    let mut depth = 0;
    map(head, |w| {
        eprintln!("{}: {:?}", depth, w);
        depth += 1;
        true
    });
}

/// The identity writer just relays anything written.
pub struct Identity<'a, C> {
    inner: Option<BoxStack<'a, C>>,
    cookie: C,
}

impl<'a, C: 'a> Identity<'a, C> {
    /// Makes an identity writer.
    pub fn new(inner: Stack<'a, C>, cookie: C)
                  -> Stack<'a, C> {
        Stack::from(Box::new(Self{inner: Some(inner.into()), cookie: cookie}))
    }
}

impl<'a, C> fmt::Debug for Identity<'a, C> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Identity")
            .field("inner", &self.inner)
            .finish()
    }
}

impl<'a, C> io::Write for Identity<'a, C> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let writer = self.inner.as_mut()
            .ok_or_else(|| io::Error::new(io::ErrorKind::BrokenPipe,
                                          "Writer is finalized."))?;
        writer.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        let writer = self.inner.as_mut()
            .ok_or_else(|| io::Error::new(io::ErrorKind::BrokenPipe,
                                          "Writer is finalized."))?;
        writer.flush()
    }
}

impl<'a, C> Stackable<'a, C> for Identity<'a, C> {
    /// Recovers the inner stackable.
    fn into_inner(self: Box<Self>) -> Result<Option<BoxStack<'a, C>>> {
        Ok(self.inner)
    }
    /// Recovers the inner stackable.
    fn pop(&mut self) -> Result<Option<BoxStack<'a, C>>> {
        Ok(self.inner.take())
    }
    /// Sets the inner stackable.
    fn mount(&mut self, new: BoxStack<'a, C>) {
        self.inner = Some(new);
    }
    fn inner_ref(&self) -> Option<&dyn Stackable<'a, C>> {
        if let Some(ref i) = self.inner {
            Some(i)
        } else {
            None
        }
    }
    fn inner_mut(&mut self) -> Option<&mut dyn Stackable<'a, C>> {
        if let Some(ref mut i) = self.inner {
            Some(i)
        } else {
            None
        }
    }
    fn cookie_set(&mut self, cookie: C) -> C {
        ::std::mem::replace(&mut self.cookie, cookie)
    }
    fn cookie_ref(&self) -> &C {
        &self.cookie
    }
    fn cookie_mut(&mut self) -> &mut C {
        &mut self.cookie
    }
    fn position(&self) -> u64 {
        self.inner.as_ref().map(|i| i.position()).unwrap_or(0)
    }
}

/// Generic writer wrapping `io::Write`.
pub struct Generic<W: io::Write, C> {
    inner: W,
    cookie: C,
    position: u64,
}

impl<'a, W: 'a + io::Write, C: 'a> Generic<W, C> {
    /// Wraps an `io::Write`r.
    pub fn new(inner: W, cookie: C) -> Stack<'a, C> {
        Stack::from(Box::new(Self::new_unboxed(inner.into(), cookie)))
    }

    fn new_unboxed(inner: W, cookie: C) -> Self {
        Generic {
            inner: inner,
            cookie: cookie,
            position: 0,
        }
    }
}

impl<W: io::Write, C> fmt::Debug for Generic<W, C> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("writer::Generic")
            .finish()
    }
}

impl<W: io::Write, C> io::Write for Generic<W, C> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        match self.inner.write(bytes) {
            Ok(n) => {
                self.position += n as u64;
                Ok(n)
            },
            Err(e) => Err(e),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl<'a, W: io::Write, C> Stackable<'a, C> for Generic<W, C> {
    /// Recovers the inner stackable.
    fn into_inner(self: Box<Self>) -> Result<Option<BoxStack<'a, C>>> {
        Ok(None)
    }
    /// Recovers the inner stackable.
    fn pop(&mut self) -> Result<Option<BoxStack<'a, C>>> {
        Ok(None)
    }
    /// Sets the inner stackable.
    fn mount(&mut self, _new: BoxStack<'a, C>) {
    }
    fn inner_mut(&mut self) -> Option<&mut dyn Stackable<'a, C>> {
        // If you use Generic to wrap an io::Writer, and you know that
        // the io::Writer's inner is also a Stackable, then return a
        // reference to the innermost Stackable in your
        // implementation.  See e.g. writer::ZLIB.
        None
    }
    fn inner_ref(&self) -> Option<&dyn Stackable<'a, C>> {
        // If you use Generic to wrap an io::Writer, and you know that
        // the io::Writer's inner is also a Stackable, then return a
        // reference to the innermost Stackable in your
        // implementation.  See e.g. writer::ZLIB.
        None
    }
    fn cookie_set(&mut self, cookie: C) -> C {
        ::std::mem::replace(&mut self.cookie, cookie)
    }
    fn cookie_ref(&self) -> &C {
        &self.cookie
    }
    fn cookie_mut(&mut self) -> &mut C {
        &mut self.cookie
    }
    fn position(&self) -> u64 {
        self.position
    }
}


/// Encrypting writer.
pub struct Encryptor<'a, C: 'a> {
    inner: Generic<symmetric::Encryptor<BoxStack<'a, C>>, C>,
}

impl<'a, C: 'a> Encryptor<'a, C> {
    /// Makes an encrypting writer.
    pub fn new(inner: Stack<'a, C>, cookie: C, algo: SymmetricAlgorithm,
               key: &[u8])
        -> Result<Stack<'a, C>>
    {
        Ok(Stack::from(Box::new(Encryptor {
            inner: Generic::new_unboxed(
                symmetric::Encryptor::new(algo, key, inner.into())?,
                cookie),
        })))
    }
}

impl<'a, C: 'a> fmt::Debug for Encryptor<'a, C> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("writer::Encryptor")
            .field("inner", &self.inner)
            .finish()
    }
}

impl<'a, C: 'a> io::Write for Encryptor<'a, C> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.inner.write(bytes)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl<'a, C: 'a> Stackable<'a, C> for Encryptor<'a, C> {
    fn into_inner(mut self: Box<Self>) -> Result<Option<BoxStack<'a, C>>> {
        let inner = self.inner.inner.finish()?;
        Ok(Some(inner))
    }
    fn pop(&mut self) -> Result<Option<BoxStack<'a, C>>> {
        unreachable!("Only implemented by Signer")
    }
    fn mount(&mut self, _new: BoxStack<'a, C>) {
        unreachable!("Only implemented by Signer")
    }
    fn inner_mut(&mut self) -> Option<&mut dyn Stackable<'a, C>> {
        // XXX: Unfortunately, this doesn't work due to a lifetime mismatch:
        // self.inner.inner.get_mut().map(|r| r.as_mut())
        None
    }
    fn inner_ref(&self) -> Option<&dyn Stackable<'a, C>> {
        self.inner.inner.get_ref().map(|r| r.as_ref())
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


/// AEAD encrypting writer.
pub struct AEADEncryptor<'a, C: 'a> {
    inner: Generic<aead::Encryptor<BoxStack<'a, C>>, C>,
}

impl<'a, C: 'a> AEADEncryptor<'a, C> {
    /// Makes an encrypting writer.
    pub fn new(inner: Stack<'a, C>, cookie: C,
               cipher: SymmetricAlgorithm, aead: AEADAlgorithm,
               chunk_size: usize, iv: &[u8], key: &SessionKey)
        -> Result<Stack<'a, C>>
    {
        Ok(Stack::from(Box::new(AEADEncryptor {
            inner: Generic::new_unboxed(
                aead::Encryptor::new(1, cipher, aead, chunk_size, iv, key,
                                     inner.into())?,
                cookie),
        })))
    }
}

impl<'a, C: 'a> fmt::Debug for AEADEncryptor<'a, C> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("writer::AEADEncryptor")
            .field("inner", &self.inner)
            .finish()
    }
}

impl<'a, C: 'a> io::Write for AEADEncryptor<'a, C> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.inner.write(bytes)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl<'a, C: 'a> Stackable<'a, C> for AEADEncryptor<'a, C> {
    fn into_inner(mut self: Box<Self>) -> Result<Option<BoxStack<'a, C>>> {
        let inner = self.inner.inner.finish()?;
        Ok(Some(inner))
    }
    fn pop(&mut self) -> Result<Option<BoxStack<'a, C>>> {
        unreachable!("Only implemented by Signer")
    }
    fn mount(&mut self, _new: BoxStack<'a, C>) {
        unreachable!("Only implemented by Signer")
    }
    fn inner_mut(&mut self) -> Option<&mut dyn Stackable<'a, C>> {
        // XXX: Unfortunately, this doesn't work due to a lifetime mismatch:
        // self.inner.inner.get_mut().map(|r| r.as_mut())
        None
    }
    fn inner_ref(&self) -> Option<&dyn Stackable<'a, C>> {
        self.inner.inner.get_ref().map(|r| r.as_ref())
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

#[cfg(test)]
mod test {
    use std::io::Write;
    use super::*;

    #[derive(Debug)]
    struct Cookie {
        state: &'static str,
    }

    #[test]
    fn generic_writer() {
        let mut inner = Vec::new();
        {
            let mut w = Generic::new(&mut inner, Cookie { state: "happy" });
            assert_eq!(w.as_ref().cookie_ref().state, "happy");
            dump(w.as_ref());

            w.as_mut().cookie_mut().state = "sad";
            assert_eq!(w.as_ref().cookie_ref().state, "sad");

            w.write_all(b"be happy").unwrap();
            let mut count = 0;
            map_mut(w.as_mut(), |g| {
                let new = Cookie { state: "happy" };
                let old = g.cookie_set(new);
                assert_eq!(old.state, "sad");
                count += 1;
                true
            });
            assert_eq!(count, 1);
            assert_eq!(w.as_ref().cookie_ref().state, "happy");
        }
        assert_eq!(&inner, b"be happy");
    }

    #[test]
    fn stack() {
        let mut inner = Vec::new();
        {
            let w = Generic::new(&mut inner, Cookie { state: "happy" });
            dump(w.as_ref());

            let w = Identity::new(w, Cookie { state: "happy" });
            dump(w.as_ref());

            let mut count = 0;
            map(w.as_ref(), |g| {
                assert_eq!(g.cookie_ref().state, "happy");
                count += 1;
                true
            });
            assert_eq!(count, 2);
        }
    }

}
