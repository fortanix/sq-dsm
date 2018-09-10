//! A mmapping `BufferedReader` implementation for files.
//!
//! On my (Justus) system, this implementation improves the
//! performance of the statistics example by ~10% over the
//! BufferedReaderGeneric.

use libc::{c_void, size_t, mmap, munmap, PROT_READ, MAP_PRIVATE};
use std::fmt;
use std::fs::File;
use std::io;
use std::os::unix::io::AsRawFd;
use std::slice;
use std::path::Path;
use std::ptr;

use super::*;

// For small files, the overhead of manipulating the page table is not
// worth the gain.  This threshold has been chosen so that on my
// (Justus) system, mmaping is faster than sequentially reading.
const MMAP_THRESHOLD: u64 = 16 * 4096;

/// A `BufferedReader` implementation for files.
///
/// This implementation tries to mmap the file, falling back to
/// just using a generic reader.
pub struct BufferedReaderFile<'a, C>(Imp<'a, C>);

impl<'a, C> fmt::Debug for BufferedReaderFile<'a, C> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_tuple("BufferedReaderFile")
            .field(&self.0)
            .finish()
    }
}

/// The implementation.
enum Imp<'a, C> {
    Generic(BufferedReaderGeneric<File, C>),
    MMAP {
        addr: *mut c_void,
        length: size_t,
        reader: BufferedReaderMemory<'a, C>,
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

impl<'a> BufferedReaderFile<'a, ()> {
    /// Opens the given file.
    pub fn open<P: AsRef<Path>>(path: P) -> io::Result<Self> {
        Self::with_cookie(path, ())
    }
}

impl<'a, C> BufferedReaderFile<'a, C> {
    /// Like `open()`, but sets a cookie.
    pub fn with_cookie<P: AsRef<Path>>(path: P, cookie: C) -> io::Result<Self> {
        // As fallback, we use a generic reader.
        let generic = |file, cookie| {
            Ok(BufferedReaderFile(
                Imp::Generic(
                    BufferedReaderGeneric::with_cookie(file, None, cookie))))
        };

        let file = File::open(path)?;

        // For testing and benchmarking purposes, we use the variable
        // SEQUOIA_DONT_MMAP to turn off mmapping.
        if ::std::env::var_os("SEQUOIA_DONT_MMAP").is_some() {
            return generic(file, cookie);
        }

        let length = file.metadata()?.len();

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
        if addr.is_null() {
            return generic(file, cookie);
        }

        let slice = unsafe {
            slice::from_raw_parts(addr as *const u8, length)
        };

        Ok(BufferedReaderFile(
            Imp::MMAP {
                addr: addr,
                length: length,
                reader: BufferedReaderMemory::with_cookie(slice, cookie),
            }
        ))
    }
}

impl<'a, C> io::Read for BufferedReaderFile<'a, C> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self.0 {
            Imp::Generic(ref mut reader) => reader.read(buf),
            Imp::MMAP { ref mut reader, .. } => reader.read(buf),
        }
    }
}

impl<'a, C> BufferedReader<C> for BufferedReaderFile<'a, C> {
    fn buffer(&self) -> &[u8] {
        match self.0 {
            Imp::Generic(ref reader) => reader.buffer(),
            Imp::MMAP { ref reader, .. } => reader.buffer(),
        }
    }

    fn data(&mut self, amount: usize) -> io::Result<&[u8]> {
        match self.0 {
            Imp::Generic(ref mut reader) => reader.data(amount),
            Imp::MMAP { ref mut reader, .. } => reader.data(amount),
        }
    }

    fn data_hard(&mut self, amount: usize) -> io::Result<&[u8]> {
        match self.0 {
            Imp::Generic(ref mut reader) => reader.data_hard(amount),
            Imp::MMAP { ref mut reader, .. } => reader.data_hard(amount),
        }
    }

    fn consume(&mut self, amount: usize) -> &[u8] {
        match self.0 {
            Imp::Generic(ref mut reader) => reader.consume(amount),
            Imp::MMAP { ref mut reader, .. } => reader.consume(amount),
        }
    }

    fn data_consume(&mut self, amount: usize) -> io::Result<&[u8]> {
        match self.0 {
            Imp::Generic(ref mut reader) => reader.data_consume(amount),
            Imp::MMAP { ref mut reader, .. } => reader.data_consume(amount),
        }
    }

    fn data_consume_hard(&mut self, amount: usize) -> io::Result<&[u8]> {
        match self.0 {
            Imp::Generic(ref mut reader) => reader.data_consume_hard(amount),
            Imp::MMAP { ref mut reader, .. } => reader.data_consume_hard(amount),
        }
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
