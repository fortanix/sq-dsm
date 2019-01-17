//! IO primitives for Sequoia.

use failure;
use std::fs::File;
use std::io::{self, Read, Write, Cursor};
use std::path::Path;
use std::slice;
use libc::{uint8_t, c_void, c_char, c_int, size_t, ssize_t, realloc};

#[cfg(unix)]
use std::os::unix::io::FromRawFd;

/// Opens a file returning a reader.
#[::ffi_catch_abort] #[no_mangle]
pub extern "system" fn sq_reader_from_file(errp: Option<&mut *mut failure::Error>,
                                           filename: *const c_char)
                                           -> *mut Box<Read> {
    ffi_make_fry_from_errp!(errp);
    let filename = ffi_param_cstr!(filename).to_string_lossy().into_owned();
    ffi_try_box!(File::open(Path::new(&filename))
             .map(|r| Box::new(r))
             .map_err(|e| e.into()))
}

/// Opens a file descriptor returning a reader.
#[cfg(unix)]
#[::ffi_catch_abort] #[no_mangle]
pub extern "system" fn sq_reader_from_fd(fd: c_int)
                                         -> *mut Box<Read> {
    box_raw!(Box::new(unsafe { File::from_raw_fd(fd) }))
}

/// Creates a reader from a buffer.
#[::ffi_catch_abort] #[no_mangle]
pub extern "system" fn sq_reader_from_bytes(buf: *const uint8_t,
                                            len: size_t)
                                            -> *mut Box<Read> {
    assert!(!buf.is_null());
    let buf = unsafe {
        slice::from_raw_parts(buf, len as usize)
    };
    box_raw!(Box::new(Cursor::new(buf)))
}

/// Frees a reader.
#[::ffi_catch_abort] #[no_mangle]
pub extern "system" fn sq_reader_free(reader: Option<&mut Box<Read>>) {
    ffi_free!(reader)
}

/// Reads up to `len` bytes into `buf`.
#[::ffi_catch_abort] #[no_mangle]
pub extern "system" fn sq_reader_read(errp: Option<&mut *mut failure::Error>,
                                      reader: *mut Box<Read>,
                                      buf: *mut uint8_t, len: size_t)
                                      -> ssize_t {
    ffi_make_fry_from_errp!(errp);
    let reader = ffi_param_ref_mut!(reader);
    assert!(!buf.is_null());
    let buf = unsafe {
        slice::from_raw_parts_mut(buf, len as usize)
    };
    ffi_try_or!(reader.read(buf).map_err(|e| e.into()), -1) as ssize_t
}


/// Opens a file returning a writer.
///
/// The file will be created if it does not exist, or be truncated
/// otherwise.  If you need more control, use `sq_writer_from_fd`.
#[::ffi_catch_abort] #[no_mangle]
pub extern "system" fn sq_writer_from_file(errp: Option<&mut *mut failure::Error>,
                                           filename: *const c_char)
                                           -> *mut Box<Write> {
    ffi_make_fry_from_errp!(errp);
    let filename = ffi_param_cstr!(filename).to_string_lossy().into_owned();
    ffi_try_box!(File::create(Path::new(&filename))
             .map(|r| Box::new(r))
             .map_err(|e| e.into()))
}

/// Opens a file descriptor returning a writer.
#[cfg(unix)]
#[::ffi_catch_abort] #[no_mangle]
pub extern "system" fn sq_writer_from_fd(fd: c_int)
                                         -> *mut Box<Write> {
    box_raw!(Box::new(unsafe { File::from_raw_fd(fd) }))
}

/// Creates a writer from a buffer.
#[::ffi_catch_abort] #[no_mangle]
pub extern "system" fn sq_writer_from_bytes(buf: *mut uint8_t,
                                            len: size_t)
                                            -> *mut Box<Write> {
    assert!(!buf.is_null());
    let buf = unsafe {
        slice::from_raw_parts_mut(buf, len as usize)
    };
    box_raw!(Box::new(Cursor::new(buf)))
}

/// Creates an allocating writer.
///
/// This writer allocates memory using `malloc`, and stores the
/// pointer to the memory and the number of bytes written to the given
/// locations `buf`, and `len`.  Both must either be set to zero, or
/// reference a chunk of memory allocated using libc's heap allocator.
/// The caller is responsible to `free` it once the writer has been
/// destroyed.
#[::ffi_catch_abort] #[no_mangle]
pub extern "system" fn sq_writer_alloc(buf: *mut *mut c_void,
                                       len: *mut size_t)
                                       -> *mut Box<Write> {
    let buf = ffi_param_ref_mut!(buf);
    let len = ffi_param_ref_mut!(len);

    box_raw!(Box::new(WriterAlloc {
        buf: buf,
        len: len,
    }))
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

/// Frees a writer.
#[::ffi_catch_abort] #[no_mangle]
pub extern "system" fn sq_writer_free(writer: Option<&mut Box<Write>>) {
    ffi_free!(writer)
}

/// Writes up to `len` bytes of `buf` into `writer`.
#[::ffi_catch_abort] #[no_mangle]
pub extern "system" fn sq_writer_write(errp: Option<&mut *mut failure::Error>,
                                       writer: *mut Box<Write>,
                                       buf: *const uint8_t, len: size_t)
                                       -> ssize_t {
    ffi_make_fry_from_errp!(errp);
    let writer = ffi_param_ref_mut!(writer);
    assert!(!buf.is_null());
    let buf = unsafe {
        slice::from_raw_parts(buf, len as usize)
    };
    ffi_try_or!(writer.write(buf).map_err(|e| e.into()), -1) as ssize_t
}
