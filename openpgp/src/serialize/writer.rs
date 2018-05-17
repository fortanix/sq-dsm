//! Stackable writers.

use bzip2::Compression as BzCompression;
use bzip2::write::BzEncoder;
use flate2::Compression as FlateCompression;
use flate2::write::{DeflateEncoder, ZlibEncoder};
use std::fmt;
use std::io;

use symmetric;
use {
    Result,
    SymmetricAlgo,
};

/// A stack of writers.
///
/// We use trait objects as unit of composition.  This is a compiler
/// limitation, we may use impl trait in the future.
pub type Stack<'a, C> = Box<'a + Stackable<'a, C>>;

/// Makes a writer stackable and provides convenience functions.
pub trait Stackable<'a, C> : io::Write + fmt::Debug {
    /// Recovers the inner stackable.
    fn into_inner(self: Box<Self>) -> Result<Option<Stack<'a, C>>>;

    /// Pops the stackable from the stack, detaching it.
    ///
    /// Returns the detached stack.
    fn pop(&mut self) -> Result<Option<Stack<'a, C>>>;

    /// Sets the inner stackable.
    fn mount(&mut self, new: Stack<'a, C>);

    /// Returns a mutable reference to the inner `Writer`, if
    /// any.
    ///
    /// It is a very bad idea to write any data from the inner
    /// `Writer`, but it can sometimes be useful to get the cookie.
    fn inner_mut(&mut self) -> Option<&mut Stackable<'a, C>>;

    /// Returns a reference to the inner `Writer`.
    fn inner_ref(&self) -> Option<&Stackable<'a, C>>;

    /// Sets the cookie and returns the old value.
    fn cookie_set(&mut self, cookie: C) -> C;

    /// Returns a reference to the cookie.
    fn cookie_ref(&self) -> &C;

    /// Returns a mutable reference to the cookie.
    fn cookie_mut(&mut self) -> &mut C;

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
impl <'a, C> Stackable<'a, C> for Stack<'a, C> {
    fn into_inner(self: Box<Self>) -> Result<Option<Stack<'a, C>>> {
        (*self).into_inner()
    }
    /// Recovers the inner stackable.
    fn pop(&mut self) -> Result<Option<Stack<'a, C>>> {
        self.as_mut().pop()
    }
    /// Sets the inner stackable.
    fn mount(&mut self, new: Stack<'a, C>) {
        self.as_mut().mount(new);
    }
    fn inner_mut(&mut self) -> Option<&mut Stackable<'a, C>> {
        self.as_mut().inner_mut()
    }
    fn inner_ref(&self) -> Option<&Stackable<'a, C>> {
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
}

/// Maps a function over the stack of writers.
#[allow(dead_code)]
pub fn map<C, F>(head: &Stackable<C>, mut fun: F)
    where F: FnMut(&Stackable<C>) -> bool {
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
pub fn map_mut<C, F>(head: &mut Stackable<C>, mut fun: F)
    where F: FnMut(&mut Stackable<C>) -> bool {
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
pub fn dump<C>(head: &Stackable<C>) {
    let mut depth = 0;
    map(head, |w| {
        eprintln!("{}: {:?}", depth, w);
        depth += 1;
        true
    });
}

pub struct Identity<'a, C> {
    inner: Option<Stack<'a, C>>,
    cookie: C,
}

impl<'a, C: 'a> Identity<'a, C> {
    pub fn new(inner: Stack<'a, C>, cookie: C)
                  -> Stack<'a, C> {
        Box::new(Self{inner: Some(inner), cookie: cookie})
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
    fn into_inner(self: Box<Self>) -> Result<Option<Stack<'a, C>>> {
        Ok(self.inner)
    }
    /// Recovers the inner stackable.
    fn pop(&mut self) -> Result<Option<Stack<'a, C>>> {
        Ok(self.inner.take())
    }
    /// Sets the inner stackable.
    fn mount(&mut self, new: Stack<'a, C>) {
        self.inner = Some(new);
    }
    fn inner_ref(&self) -> Option<&Stackable<'a, C>> {
        if let Some(ref i) = self.inner {
            Some(i)
        } else {
            None
        }
    }
    fn inner_mut(&mut self) -> Option<&mut Stackable<'a, C>> {
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
}

/// Generic writer wrapping `io::Write`.
pub struct Generic<W: io::Write, C> {
    inner: W,
    cookie: C,
}

impl<'a, W: 'a + io::Write, C: 'a> Generic<W, C> {
    pub fn new(inner: W, cookie: C) -> Stack<'a, C> {
        Box::new(Self::new_unboxed(inner, cookie))
    }

    fn new_unboxed(inner: W, cookie: C) -> Self {
        Generic {
            inner: inner,
            cookie: cookie,
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
        self.inner.write(bytes)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl<'a, W: io::Write, C> Stackable<'a, C> for Generic<W, C> {
    /// Recovers the inner stackable.
    fn into_inner(self: Box<Self>) -> Result<Option<Stack<'a, C>>> {
        Ok(None)
    }
    /// Recovers the inner stackable.
    fn pop(&mut self) -> Result<Option<Stack<'a, C>>> {
        Ok(None)
    }
    /// Sets the inner stackable.
    fn mount(&mut self, _new: Stack<'a, C>) {
    }
    fn inner_mut(&mut self) -> Option<&mut Stackable<'a, C>> {
        None
    }
    fn inner_ref(&self) -> Option<&Stackable<'a, C>> {
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
}

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

/// Encrypting writer.
pub struct Encryptor<'a, C> {
    inner: Generic<symmetric::Encryptor<Stack<'a, C>>, C>,
}

impl<'a, C> Encryptor<'a, C> {
    pub fn new(inner: Stack<'a, C>, cookie: C, algo: SymmetricAlgo, key: &[u8])
               -> Result<Box<Self>> {
        Ok(Box::new(Encryptor {
            inner: Generic::new_unboxed(
                symmetric::Encryptor::new(algo, key, inner)?,
                cookie),
        }))
    }
}

impl<'a, C:> fmt::Debug for Encryptor<'a, C> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("writer::Encryptor")
            .field("inner", &self.inner)
            .finish()
    }
}

impl<'a, C> io::Write for Encryptor<'a, C> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.inner.write(bytes)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl<'a, C> Stackable<'a, C> for Encryptor<'a, C> {
    fn into_inner(mut self: Box<Self>) -> Result<Option<Stack<'a, C>>> {
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
            assert_eq!(w.cookie_ref().state, "happy");
            dump(&w);

            w.cookie_mut().state = "sad";
            assert_eq!(w.cookie_ref().state, "sad");

            w.write_all(b"be happy").unwrap();
            let mut count = 0;
            map_mut(&mut w, |g| {
                let new = Cookie { state: "happy" };
                let old = g.cookie_set(new);
                assert_eq!(old.state, "sad");
                count += 1;
                true
            });
            assert_eq!(count, 1);
            assert_eq!(w.cookie_ref().state, "happy");
        }
        assert_eq!(&inner, b"be happy");
    }

    #[test]
    fn stack() {
        let mut inner = Vec::new();
        {
            let w = Generic::new(&mut inner, Cookie { state: "happy" });
            dump(&w);

            let w = Identity::new(w, Cookie { state: "happy" });
            dump(&w);

            let mut count = 0;
            map(&w, |g| {
                assert_eq!(g.cookie_ref().state, "happy");
                count += 1;
                true
            });
            assert_eq!(count, 2);
        }
    }

}
