//! Contexts and errors.
//!
//! Sequoia tries to be useful for a wide variety of applications.
//! Therefore, we need you to provide a little information about the
//! context you are using Sequoia in.
//!
//! # Example
//!
//! A context with reasonable defaults can be created using
//! `sq_context_new`:
//!
//! ```c
//! sq_context_t ctx;
//!
//! ctx = sq_context_new ("org.sequoia-pgp.example");
//! ```
//!
//! A context can be configured using the builder pattern with
//! `sq_context_configure`:
//!
//! ```c
//! sq_config_t cfg;
//! sq_context_t ctx;
//!
//! cfg = sq_context_configure ("org.sequoia-pgp.example");
//! sq_config_network_policy (cfg, SQ_NETWORK_POLICY_OFFLINE);
//! ctx = sq_config_build (cfg);
//! ```

use failure;
use std::fs::File;
use std::ffi::{CString, CStr};
use std::io::{self, Read, Write, Cursor};
use std::path::Path;
use std::ptr;
use std::slice;
use libc::{uint8_t, c_void, c_char, c_int, size_t, ssize_t, realloc};

#[cfg(unix)]
use std::os::unix::io::FromRawFd;

use sequoia_core as core;
use sequoia_core::Config;

/// Wraps a Context and provides an error slot.
#[doc(hidden)]
pub struct Context {
    pub(crate) c: core::Context,
    pub(crate) e: Option<failure::Error>,
}

impl Context {
    fn new(c: core::Context) -> Self {
        Context{c: c, e: None}
    }
}

/// Returns the last error.
///
/// Returns and removes the last error from the context.
#[no_mangle]
pub extern "system" fn sq_context_last_error(ctx: Option<&mut Context>)
                                             -> *mut failure::Error {
    let ctx = ctx.expect("Context is NULL");
    maybe_box_raw!(ctx.e.take())
}

/// Frees a string returned from Sequoia.
#[no_mangle]
pub extern "system" fn sq_string_free(s: *mut c_char) {
    if ! s.is_null() {
        unsafe { drop(CString::from_raw(s)) }
    }
}

/// Creates a Context with reasonable defaults.
///
/// `domain` should uniquely identify your application, it is strongly
/// suggested to use a reversed fully qualified domain name that is
/// associated with your application.  `domain` must not be `NULL`.
///
/// Returns `NULL` on errors.  If `errp` is not `NULL`, the error is
/// stored there.
#[no_mangle]
pub extern "system" fn sq_context_new(domain: *const c_char,
                                      errp: Option<&mut *mut failure::Error>)
                                      -> *mut Context {
    assert!(! domain.is_null());
    let domain = unsafe {
        CStr::from_ptr(domain).to_string_lossy()
    };

    match core::Context::new(&domain) {
        Ok(context) =>
            box_raw!(Context::new(context)),
        Err(e) => {
            if let Some(errp) = errp {
                *errp = box_raw!(e);
            }
            ptr::null_mut()
        },
    }
}

/// Frees a context.
#[no_mangle]
pub extern "system" fn sq_context_free(context: *mut Context) {
    if context.is_null() { return }
    unsafe {
        drop(Box::from_raw(context));
    }
}

/// Creates a Context that can be configured.
///
/// `domain` should uniquely identify your application, it is strongly
/// suggested to use a reversed fully qualified domain name that is
/// associated with your application.  `domain` must not be `NULL`.
///
/// The configuration is seeded like in `sq_context_new`, but can be
/// modified.  A configuration has to be finalized using
/// `sq_config_build()` in order to turn it into a Context.
#[no_mangle]
pub extern "system" fn sq_context_configure(domain: *const c_char)
                                            -> *mut Config {
    assert!(! domain.is_null());
    let domain = unsafe {
        CStr::from_ptr(domain).to_string_lossy()
    };

    Box::into_raw(Box::new(core::Context::configure(&domain)))
}

/// Returns the domain of the context.
#[no_mangle]
pub extern "system" fn sq_context_domain(ctx: Option<&Context>) -> *const c_char {
    assert!(ctx.is_some());
    ctx.unwrap().c.domain().as_bytes().as_ptr() as *const c_char
}

/// Returns the directory containing shared state.
#[no_mangle]
pub extern "system" fn sq_context_home(ctx: Option<&Context>) -> *const c_char {
    assert!(ctx.is_some());
    ctx.unwrap().c.home().to_string_lossy().as_ptr() as *const c_char
}

/// Returns the directory containing backend servers.
#[no_mangle]
pub extern "system" fn sq_context_lib(ctx: Option<&Context>) -> *const c_char {
    assert!(ctx.is_some());
    ctx.unwrap().c.lib().to_string_lossy().as_bytes().as_ptr() as *const c_char
}

/// Returns the network policy.
#[no_mangle]
pub extern "system" fn sq_context_network_policy(ctx: Option<&Context>) -> c_int {
    assert!(ctx.is_some());
    u8::from(ctx.unwrap().c.network_policy()) as c_int
}

/// Returns the IPC policy.
#[no_mangle]
pub extern "system" fn sq_context_ipc_policy(ctx: Option<&Context>) -> c_int {
    assert!(ctx.is_some());
    u8::from(ctx.unwrap().c.ipc_policy()) as c_int
}

/// Returns whether or not this is an ephemeral context.
#[no_mangle]
pub extern "system" fn sq_context_ephemeral(ctx: Option<&Context>) -> uint8_t {
    assert!(ctx.is_some());
    if ctx.unwrap().c.ephemeral() { 1 } else { 0 }
}


/*  sequoia::Config.  */

/// Finalizes the configuration and return a `Context`.
///
/// Consumes `cfg`.  Returns `NULL` on errors. Returns `NULL` on
/// errors.  If `errp` is not `NULL`, the error is stored there.
#[no_mangle]
pub extern "system" fn sq_config_build(cfg: Option<&mut Config>,
                                       errp: Option<&mut *mut failure::Error>)
                                       -> *mut Context {
    assert!(cfg.is_some());
    let cfg = unsafe { Box::from_raw(cfg.unwrap()) };

    match cfg.build() {
        Ok(context) =>
            box_raw!(Context::new(context)),
        Err(e) => {
            if let Some(errp) = errp {
                *errp = box_raw!(e);
            }
            ptr::null_mut()
        },
    }
}

/// Sets the directory containing shared state.
#[no_mangle]
pub extern "system" fn sq_config_home(cfg: Option<&mut Config>,
                                      home: *const c_char) {
    assert!(cfg.is_some());
    assert!(! home.is_null());
    let home = unsafe {
        CStr::from_ptr(home).to_string_lossy()
    };
    cfg.unwrap().set_home(home.as_ref())
}

/// Set the directory containing backend servers.
#[no_mangle]
pub extern "system" fn sq_config_lib(cfg: Option<&mut Config>,
                                     lib: *const c_char) {
    assert!(cfg.is_some());
    assert!(! lib.is_null());
    let lib = unsafe {
        CStr::from_ptr(lib).to_string_lossy()
    };
    cfg.unwrap().set_lib(&lib.as_ref())
}

/// Sets the network policy.
#[no_mangle]
pub extern "system" fn sq_config_network_policy(cfg: Option<&mut Config>,
                                                policy: c_int) {
    assert!(cfg.is_some());
    if policy < 0 || policy > 3 {
        panic!("Bad network policy: {}", policy);
    }
    cfg.unwrap().set_network_policy((policy as u8).into());
}

/// Sets the IPC policy.
#[no_mangle]
pub extern "system" fn sq_config_ipc_policy(cfg: Option<&mut Config>,
                                            policy: c_int) {
    assert!(cfg.is_some());
    if policy < 0 || policy > 2 {
        panic!("Bad ipc policy: {}", policy);
    }
    cfg.unwrap().set_ipc_policy((policy as u8).into());
}

/// Makes this context ephemeral.
#[no_mangle]
pub extern "system" fn sq_config_ephemeral(cfg: Option<&mut Config>) {
    assert!(cfg.is_some());
    cfg.unwrap().set_ephemeral();
}

/* Reader and writer.  */

/// Opens a file returning a reader.
#[no_mangle]
pub extern "system" fn sq_reader_from_file(ctx: Option<&mut Context>,
                                           filename: *const c_char)
                                           -> *mut Box<Read> {
    let ctx = ctx.expect("Context is NULL");
    assert!(! filename.is_null());
    let filename = unsafe {
        CStr::from_ptr(filename).to_string_lossy().into_owned()
    };
    fry_box!(ctx, File::open(Path::new(&filename))
             .map(|r| Box::new(r))
             .map_err(|e| e.into()))
}

/// Opens a file descriptor returning a reader.
#[cfg(unix)]
#[no_mangle]
pub extern "system" fn sq_reader_from_fd(fd: c_int)
                                         -> *mut Box<Read> {
    box_raw!(Box::new(unsafe { File::from_raw_fd(fd) }))
}

/// Creates a reader from a buffer.
#[no_mangle]
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
#[no_mangle]
pub extern "system" fn sq_reader_free(reader: *mut Box<Read>) {
    if reader.is_null() { return }
    unsafe {
        drop(Box::from_raw(reader));
    }
}

/// Reads up to `len` bytes into `buf`.
#[no_mangle]
pub extern "system" fn sq_reader_read(ctx: Option<&mut Context>,
                                      reader: Option<&mut Box<Read>>,
                                      buf: *mut uint8_t, len: size_t)
                                      -> ssize_t {
    let ctx = ctx.expect("Context is NULL");
    let reader = reader.expect("Reader is NULL");
    assert!(!buf.is_null());
    let buf = unsafe {
        slice::from_raw_parts_mut(buf, len as usize)
    };
    fry_or!(ctx, reader.read(buf).map_err(|e| e.into()), -1) as ssize_t
}


/// Opens a file returning a writer.
///
/// The file will be created if it does not exist, or be truncated
/// otherwise.  If you need more control, use `sq_writer_from_fd`.
#[no_mangle]
pub extern "system" fn sq_writer_from_file(ctx: Option<&mut Context>,
                                           filename: *const c_char)
                                           -> *mut Box<Write> {
    let ctx = ctx.expect("Context is NULL");
    assert!(! filename.is_null());
    let filename = unsafe {
        CStr::from_ptr(filename).to_string_lossy().into_owned()
    };
    fry_box!(ctx, File::create(Path::new(&filename))
             .map(|r| Box::new(r))
             .map_err(|e| e.into()))
}

/// Opens a file descriptor returning a writer.
#[cfg(unix)]
#[no_mangle]
pub extern "system" fn sq_writer_from_fd(fd: c_int)
                                         -> *mut Box<Write> {
    box_raw!(Box::new(unsafe { File::from_raw_fd(fd) }))
}

/// Creates a writer from a buffer.
#[no_mangle]
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
#[no_mangle]
pub extern "system" fn sq_writer_alloc(buf: Option<&'static mut *mut c_void>,
                                       len: Option<&'static mut size_t>)
                                       -> *mut Box<Write> {
    let buf = buf.expect("BUF is NULL");
    let len = len.expect("LEN is NULL");

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
#[no_mangle]
pub extern "system" fn sq_writer_free(writer: *mut Box<Write>) {
    if writer.is_null() { return }
    unsafe {
        drop(Box::from_raw(writer));
    }
}

/// Writes up to `len` bytes of `buf` into `writer`.
#[no_mangle]
pub extern "system" fn sq_writer_write(ctx: Option<&mut Context>,
                                       writer: Option<&mut Box<Write>>,
                                       buf: *const uint8_t, len: size_t)
                                       -> ssize_t {
    let ctx = ctx.expect("Context is NULL");
    let writer = writer.expect("Writer is NULL");
    assert!(!buf.is_null());
    let buf = unsafe {
        slice::from_raw_parts(buf, len as usize)
    };
    fry_or!(ctx, writer.write(buf).map_err(|e| e.into()), -1) as ssize_t
}
