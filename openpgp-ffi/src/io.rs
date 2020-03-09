//! IO primitives for Sequoia.

use std::fs::File;
use std::io::{self, Read, Write, Cursor};
use std::path::Path;
use std::slice;
use libc::{c_void, c_char, c_int, size_t, ssize_t, realloc};

#[cfg(unix)]
use std::os::unix::io::FromRawFd;

extern crate sequoia_openpgp as openpgp;

use crate::Maybe;
use crate::RefMutRaw;
use crate::MoveIntoRaw;
use crate::MoveResultIntoRaw;

/// Wraps a generic reader.
#[crate::ffi_wrapper_type(prefix = "pgp_")]
pub struct Reader(ReaderKind);

/// Specializes readers.
///
/// In some cases, we want to call functions on concrete types.  To
/// avoid nasty hacks, we have specialized variants for that.
pub(crate) enum ReaderKind {
    Generic(Box<dyn io::Read>),
    Armored(openpgp::armor::Reader<'static>),
}

impl Read for ReaderKind {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        use self::ReaderKind::*;
        match self {
            Generic(ref mut r) => r.read(buf),
            Armored(ref mut r) => r.read(buf),
        }
    }
}

/// Opens a file returning a reader.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle]
pub extern "C" fn pgp_reader_from_file(errp: Option<&mut *mut crate::error::Error>,
                                            filename: *const c_char)
                                            -> Maybe<Reader> {
    let filename = ffi_param_cstr!(filename).to_string_lossy().into_owned();
    File::open(Path::new(&filename))
        .map(|r| ReaderKind::Generic(Box::new(r)))
        .map_err(|e| ::anyhow::Error::from(e))
        .move_into_raw(errp)
}

/// Opens a file descriptor returning a reader.
#[cfg(unix)]
#[::sequoia_ffi_macros::extern_fn] #[no_mangle]
pub extern "C" fn pgp_reader_from_fd(fd: c_int)
                                          -> *mut Reader {
    ReaderKind::Generic(Box::new(unsafe {
        File::from_raw_fd(fd)
    })).move_into_raw()
}

/// Creates a reader from a buffer.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle]
pub extern "C" fn pgp_reader_from_bytes(buf: *const u8,
                                             len: size_t)
                                             -> *mut Reader {
    assert!(!buf.is_null());
    let buf = unsafe {
        slice::from_raw_parts(buf, len as usize)
    };
    ReaderKind::Generic(Box::new(Cursor::new(buf))).move_into_raw()
}

/// The callback type for the generic callback-based reader interface.
type ReaderCallbackFn = fn(*mut c_void, *const c_void, size_t) -> ssize_t;

/// Creates an reader from a callback and cookie.
///
/// This reader calls the given callback to write data.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle] pub extern "C"
fn pgp_reader_from_callback(cb: ReaderCallbackFn,
                            cookie: *mut c_void)
                            -> *mut Reader {
    let r: Box<dyn io::Read> = Box::new(ReaderCallback {
        cb, cookie,
    });
    ReaderKind::Generic(r).move_into_raw()
}

/// A generic callback-based reader implementation.
struct ReaderCallback {
    cb: ReaderCallbackFn,
    cookie: *mut c_void,
}

impl Read for ReaderCallback {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let r =
            (self.cb)(self.cookie, buf.as_mut_ptr() as *mut c_void, buf.len());
        if r < 0 {
            use std::io as stdio;
            Err(stdio::Error::new(stdio::ErrorKind::Other,
                                  "Unknown error in read callback"))
        } else {
            Ok(r as usize)
        }
    }
}

/// Reads up to `len` bytes into `buf`.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle]
pub extern "C" fn pgp_reader_read(errp: Option<&mut *mut crate::error::Error>,
                                       reader: *mut Reader,
                                       buf: *mut u8, len: size_t)
                                       -> ssize_t {
    assert!(!buf.is_null());
    let buf = unsafe {
        slice::from_raw_parts_mut(buf, len as usize)
    };
    reader.ref_mut_raw().read(buf)
        .map(|n_read| n_read as ssize_t)
        .unwrap_or_else(|e| {
            if let Some(errp) = errp {
                *errp = ::anyhow::Error::from(e).move_into_raw();
            };

            // Signal failure.
            -1
        })
}

/// Copies up to `len` bytes from `source` to `dest`.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle]
pub extern "C" fn pgp_reader_copy(errp: Option<&mut *mut crate::error::Error>,
                                       source: *mut Reader,
                                       dest: *mut Writer,
                                       len: size_t)
                                       -> ssize_t {
    let source = source.ref_mut_raw();
    let dest = dest.ref_mut_raw();

    io::copy(&mut source.take(len as u64), dest)
        .map(|n_read| n_read as ssize_t)
        .unwrap_or_else(|e| {
            if let Some(errp) = errp {
                *errp = ::anyhow::Error::from(e).move_into_raw();
            };

            // Signal failure.
            -1
        })
}

/// Reads all data from reader and discards it.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle]
pub extern "C" fn pgp_reader_discard(errp: Option<&mut *mut crate::error::Error>,
                                          reader: *mut Reader)
                                          -> ssize_t {
    let mut reader = reader.ref_mut_raw();

    io::copy(&mut reader, &mut io::sink())
        .map(|n_read| n_read as ssize_t)
        .unwrap_or_else(|e| {
            if let Some(errp) = errp {
                *errp = ::anyhow::Error::from(e).move_into_raw();
            };

            // Signal failure.
            -1
        })
}

/// Wraps a generic writer.
#[crate::ffi_wrapper_type(prefix = "pgp_")]
pub struct Writer(WriterKind);

/// Specializes writers.
///
/// In some cases, we want to call functions on concrete types.  To
/// avoid nasty hacks, we have specialized variants for that.
pub(crate) enum WriterKind {
    Generic(Box<dyn io::Write>),
    Armored(openpgp::armor::Writer<&'static mut WriterKind>),
}

impl Write for WriterKind {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        use self::WriterKind::*;
        match self {
            Generic(w) => w.write(buf),
            Armored(w) => w.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        use self::WriterKind::*;
        match self {
            Generic(ref mut w) => w.flush(),
            Armored(ref mut w) => w.flush(),
        }
    }
}


/// Opens a file returning a writer.
///
/// The file will be created if it does not exist, or be truncated
/// otherwise.  If you need more control, use `pgp_writer_from_fd`.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle] pub extern "C"
fn pgp_writer_from_file(errp: Option<&mut *mut crate::error::Error>,
                        filename: *const c_char)
                        -> Maybe<Writer> {
    let filename = ffi_param_cstr!(filename).to_string_lossy().into_owned();
    File::create(Path::new(&filename))
        .map(|w| WriterKind::Generic(Box::new(w)))
        .map_err(|e| ::anyhow::Error::from(e))
        .move_into_raw(errp)
}

/// Opens a file descriptor returning a writer.
#[cfg(unix)]
#[::sequoia_ffi_macros::extern_fn] #[no_mangle] pub extern "C"
fn pgp_writer_from_fd(fd: c_int) -> *mut Writer {
    WriterKind::Generic(Box::new(unsafe {
        File::from_raw_fd(fd)
    })).move_into_raw()
}

/// Creates a writer from a buffer.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle] pub extern "C"
fn pgp_writer_from_bytes(buf: *mut u8, len: size_t) -> *mut Writer {
    assert!(!buf.is_null());
    let buf = unsafe {
        slice::from_raw_parts_mut(buf, len as usize)
    };
    WriterKind::Generic(Box::new(Cursor::new(buf))).move_into_raw()
}

/// Creates an allocating writer.
///
/// This writer allocates memory using `malloc`, and stores the
/// pointer to the memory and the number of bytes written to the given
/// locations `buf`, and `len`.  Both must either be set to zero, or
/// reference a chunk of memory allocated using libc's heap allocator.
/// The caller is responsible to `free` it once the writer has been
/// destroyed.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle] pub extern "C"
fn pgp_writer_alloc(buf: *mut *mut c_void, len: *mut size_t)
                    -> *mut Writer {
    let buf = ffi_param_ref_mut!(buf);
    let len = ffi_param_ref_mut!(len);

    let w = WriterKind::Generic(Box::new(WriterAlloc {
        buf: buf,
        len: len,
    }));
    w.move_into_raw()
}

struct WriterAlloc {
    buf: &'static mut *mut c_void,
    len: &'static mut size_t,
}

impl Write for WriterAlloc {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let old_len = *self.len;
        let new_len = old_len + buf.len();

        let new = unsafe {
            realloc(*self.buf, new_len)
        };
        if new.is_null() {
            return Err(io::Error::new(io::ErrorKind::Other, "out of memory"));
        }

        *self.buf = new;
        *self.len = new_len;

        let sl = unsafe {
            slice::from_raw_parts_mut(new as *mut u8, new_len)
        };
        &mut sl[old_len..].copy_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        // Do nothing.
        Ok(())
    }
}

/// The callback type for the generic callback-based writer interface.
type WriterCallbackFn = fn(*mut c_void, *const c_void, size_t) -> ssize_t;

/// Creates an writer from a callback and cookie.
///
/// This writer calls the given callback to write data.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle] pub extern "C"
fn pgp_writer_from_callback(cb: WriterCallbackFn,
                            cookie: *mut c_void)
                            -> *mut Writer {
    let w = WriterKind::Generic(Box::new(WriterCallback {
        cb, cookie,
    }));
    w.move_into_raw()
}

/// A generic callback-based writer implementation.
struct WriterCallback {
    cb: WriterCallbackFn,
    cookie: *mut c_void,
}

impl Write for WriterCallback {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let r =
            (self.cb)(self.cookie, buf.as_ptr() as *const c_void, buf.len());
        if r < 0 {
            use std::io as stdio;
            Err(stdio::Error::new(stdio::ErrorKind::Other,
                                  "Unknown error in write callback"))
        } else {
            Ok(r as usize)
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        // Do nothing.
        // XXX: Should we add a callback for that?
        Ok(())
    }
}

/// Writes up to `len` bytes of `buf` into `writer`.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle] pub extern "C"
fn pgp_writer_write(errp: Option<&mut *mut crate::error::Error>,
                    writer: *mut Writer,
                    buf: *const u8, len: size_t)
                    -> ssize_t {
    assert!(!buf.is_null());
    let buf = unsafe {
        slice::from_raw_parts(buf, len as usize)
    };
    writer.ref_mut_raw().write(buf)
        .map(|n_read| n_read as ssize_t)
        .unwrap_or_else(|e| {
            if let Some(errp) = errp {
                *errp = ::anyhow::Error::from(e).move_into_raw();
            };

            // Signal failure.
            -1
        })
}
