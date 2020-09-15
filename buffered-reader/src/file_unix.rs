//! A mmapping `BufferedReader` implementation for files.
//!
//! On my (Justus) system, this implementation improves the
//! performance of the statistics example by ~10% over the
//! Generic.

use libc::{c_void, size_t, mmap, munmap, PROT_READ, MAP_PRIVATE};
use std::fmt;
use std::fs;
use std::io;
use std::os::unix::io::AsRawFd;
use std::slice;
use std::path::{Path, PathBuf};
use std::ptr;

use super::*;
use crate::file_error::FileError;

// For small files, the overhead of manipulating the page table is not
// worth the gain.  This threshold has been chosen so that on my
// (Justus) system, mmaping is faster than sequentially reading.
const MMAP_THRESHOLD: u64 = 16 * 4096;

/// Wraps files using `mmap`().
///
/// This implementation tries to mmap the file, falling back to
/// just using a generic reader.
pub struct File<'a, C>(Imp<'a, C>, PathBuf);

impl<'a, C> fmt::Display for File<'a, C> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{} {:?}", self.0, self.1.display())
    }
}

impl<'a, C> fmt::Debug for File<'a, C> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_tuple("File")
            .field(&self.0)
            .field(&self.1)
            .finish()
    }
}

/// The implementation.
enum Imp<'a, C> {
    Generic(Generic<fs::File, C>),
    MMAP {
        addr: *mut c_void,
        length: size_t,
        reader: Memory<'a, C>,
    }
}

impl<'a, C> Drop for Imp<'a, C> {
    fn drop(&mut self) {
        match self {
            Imp::Generic(_) => (),
            Imp::MMAP { addr, length, .. } =>
                unsafe {
                    munmap(*addr, *length);
                },
        }
    }
}

impl<'a, C> fmt::Display for Imp<'a, C> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "File(")?;
        match self {
            Imp::Generic(_) => write!(f, "Generic")?,
            Imp::MMAP { .. } => write!(f, "Memory")?,
        };
        write!(f, ")")
    }
}

impl<'a, C> fmt::Debug for Imp<'a, C> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Imp::Generic(ref g) =>
                f.debug_tuple("Generic")
                .field(&g)
                .finish(),
            Imp::MMAP { ref addr, ref length, ref reader } =>
                f.debug_struct("MMAP")
                .field("addr", addr)
                .field("length", length)
                .field("reader", reader)
                .finish(),
        }
    }
}

impl<'a> File<'a, ()> {
    /// Opens the given file.
    pub fn open<P: AsRef<Path>>(path: P) -> io::Result<Self> {
        Self::with_cookie(path, ())
    }
}

impl<'a, C> File<'a, C> {
    /// Like `open()`, but sets a cookie.
    pub fn with_cookie<P: AsRef<Path>>(path: P, cookie: C) -> io::Result<Self> {
        let path = path.as_ref();

        // As fallback, we use a generic reader.
        let generic = |file, cookie| {
            Ok(File(
                Imp::Generic(
                    Generic::with_cookie(file, None, cookie)),
                path.into()))
        };

        let file = fs::File::open(path).map_err(|e| FileError::new(path, e))?;

        // For testing and benchmarking purposes, we use the variable
        // SEQUOIA_DONT_MMAP to turn off mmapping.
        if ::std::env::var_os("SEQUOIA_DONT_MMAP").is_some() {
            return generic(file, cookie);
        }

        let length =
            file.metadata().map_err(|e| FileError::new(path, e))?.len();

        // For small files, the overhead of manipulating the page
        // table is not worth the gain.
        if length < MMAP_THRESHOLD {
            return generic(file, cookie);
        }

        // Be nice to 32 bit systems.
        if length > usize::max_value() as u64 {
            return generic(file, cookie);
        }
        let length = length as usize;

        let fd = file.as_raw_fd();
        let addr = unsafe {
            mmap(ptr::null_mut(), length, PROT_READ, MAP_PRIVATE,
                 fd, 0)
        };
        if addr == libc::MAP_FAILED {
            return generic(file, cookie);
        }

        let slice = unsafe {
            slice::from_raw_parts(addr as *const u8, length)
        };

        Ok(File(
            Imp::MMAP {
                addr,
                length,
                reader: Memory::with_cookie(slice, cookie),
            },
            path.into(),
        ))
    }
}

impl<'a, C> io::Read for File<'a, C> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self.0 {
            Imp::Generic(ref mut reader) => reader.read(buf),
            Imp::MMAP { ref mut reader, .. } => reader.read(buf),
        }.map_err(|e| FileError::new(&self.1, e))
    }
}

impl<'a, C> BufferedReader<C> for File<'a, C> {
    fn buffer(&self) -> &[u8] {
        match self.0 {
            Imp::Generic(ref reader) => reader.buffer(),
            Imp::MMAP { ref reader, .. } => reader.buffer(),
        }
    }

    fn data(&mut self, amount: usize) -> io::Result<&[u8]> {
        let path = &self.1;
        match self.0 {
            Imp::Generic(ref mut reader) => reader.data(amount),
            Imp::MMAP { ref mut reader, .. } => reader.data(amount),
        }.map_err(|e| FileError::new(path, e))
    }

    fn data_hard(&mut self, amount: usize) -> io::Result<&[u8]> {
        let path = &self.1;
        match self.0 {
            Imp::Generic(ref mut reader) => reader.data_hard(amount),
            Imp::MMAP { ref mut reader, .. } => reader.data_hard(amount),
        }.map_err(|e| FileError::new(path, e))
    }

    fn consume(&mut self, amount: usize) -> &[u8] {
        match self.0 {
            Imp::Generic(ref mut reader) => reader.consume(amount),
            Imp::MMAP { ref mut reader, .. } => reader.consume(amount),
        }
    }

    fn data_consume(&mut self, amount: usize) -> io::Result<&[u8]> {
        let path = &self.1;
        match self.0 {
            Imp::Generic(ref mut reader) => reader.data_consume(amount),
            Imp::MMAP { ref mut reader, .. } => reader.data_consume(amount),
        }.map_err(|e| FileError::new(path, e))
    }

    fn data_consume_hard(&mut self, amount: usize) -> io::Result<&[u8]> {
        let path = &self.1;
        match self.0 {
            Imp::Generic(ref mut reader) => reader.data_consume_hard(amount),
            Imp::MMAP { ref mut reader, .. } => reader.data_consume_hard(amount),
        }.map_err(|e| FileError::new(path, e))
    }

    fn get_mut(&mut self) -> Option<&mut dyn BufferedReader<C>> {
        None
    }

    fn get_ref(&self) -> Option<&dyn BufferedReader<C>> {
        None
    }

    fn into_inner<'b>(self: Box<Self>) -> Option<Box<dyn BufferedReader<C> + 'b>>
        where Self: 'b {
        None
    }

    fn cookie_set(&mut self, cookie: C) -> C {
        match self.0 {
            Imp::Generic(ref mut reader) => reader.cookie_set(cookie),
            Imp::MMAP { ref mut reader, .. } => reader.cookie_set(cookie),
        }
    }

    fn cookie_ref(&self) -> &C {
        match self.0 {
            Imp::Generic(ref reader) => reader.cookie_ref(),
            Imp::MMAP { ref reader, .. } => reader.cookie_ref(),
        }
    }

    fn cookie_mut(&mut self) -> &mut C {
        match self.0 {
            Imp::Generic(ref mut reader) => reader.cookie_mut(),
            Imp::MMAP { ref mut reader, .. } => reader.cookie_mut(),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn error_contains_path() {
        let p = "/i/do/not/exist";
        let e = File::open(p).unwrap_err();
        assert!(e.to_string().contains(p));
    }
}
