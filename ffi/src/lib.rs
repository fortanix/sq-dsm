//! Provides a Foreign Function Interface.
//!
//! We provide a set of functions that use C types and the C calling
//! convention.  This interfaces allows you to use Sequoia safely from
//! any other language.
//!
//! # Guarantees
//!
//! Provided that the caller obeys her side of the contract, this
//! library...
//!
//!  - will not make an invalid memory access,
//!  - will not `abort(2)`,
//!  - XXX
//!
//! # Types
//!
//! Sequoia objects are opaque objects.  They are created in
//! constructors, and must be freed when no longer needed.
//!
//! Strings must be UTF-8 encoded and zero-terminated.
//!
//! # Lifetimes
//!
//! Objects created using a context must not outlive that context.
//! Similarly, iterators must not outlive the object they are created
//! from.
//!
//! # Error handling
//!
//! Sequoia will panic if you provide bad arguments, e.g. hand a
//! `NULL` pointer to a function that does not explicitly allow this.
//!
//! Failing functions return `NULL`.  Functions that require a
//! `Context` return complex errors.  Complex errors are stored in the
//! `Context`, and can be retrieved using `sq_last_strerror`.
//!
//! # Example
//!
//! ```text
//! #include <sequoia.h>
//!
//! struct sq_context *ctx;
//! struct sq_tpk *tpk;
//!
//! ctx = sq_context_new("org.sequoia-pgp.example");
//! if (ctx == NULL)
//!   error (1, 0, "Initializing sequoia failed.");
//!
//! tpk = sq_tpk_from_bytes (ctx, buf, len);
//! if (tpk == NULL)
//!   error (1, 0, "sq_tpk_from_bytes: %s", sq_last_strerror (ctx));
//!
//! sq_tpk_dump (tpk);
//! sq_tpk_free (tpk);
//! sq_context_free (ctx);
//! ```


extern crate failure;
extern crate libc;
extern crate native_tls;
extern crate openpgp;
extern crate sequoia_core;
extern crate sequoia_net;

use std::ffi::{CString, CStr};
use std::ptr;
use std::slice;

use openpgp::tpk::TPK;
use openpgp::KeyID;
use self::libc::{uint8_t, c_char, size_t};
use self::native_tls::Certificate;
use sequoia_core as core;
use sequoia_core::Config;
use sequoia_net::KeyServer;

/// Wraps a Context and provides an error slot.
#[doc(hidden)]
pub struct Context {
    c: core::Context,
    e: Option<Box<failure::Error>>,
}

impl Context {
    fn new(c: core::Context) -> Self {
        Context{c: c, e: None}
    }
}

/// Like try! for ffi glue.
///
/// Unwraps the given expression.  On failure, stashes the error in
/// the context and returns NULL.
macro_rules! fry {
    ($ctx:expr, $expr:expr) => {
        match $expr {
            Ok(v) => v,
            Err(e) => {
                $ctx.e = Some(Box::new(e));
                return ptr::null_mut();
            },
        }
    };
}

/// Like try! for ffi glue, then box into raw pointer.
///
/// Unwraps the given expression.  On success, it boxes the value
/// and turns it into a raw pointer.  On failure, stashes the
/// error in the context and returns NULL.
macro_rules! fry_box {
    ($ctx:expr, $expr:expr) => {
        Box::into_raw(Box::new(fry!($ctx, $expr)))
    }
}

/// Returns the last error message.
///
/// The returned value must be freed with `sq_string_free`.
#[no_mangle]
pub extern "system" fn sq_last_strerror(ctx: Option<&Context>)
                                        -> *mut c_char {
    let ctx = ctx.expect("Context is NULL");
    match ctx.e {
        Some(ref e) =>
            CString::new(format!("{}", e))
            .map(|s| s.into_raw())
            .unwrap_or(CString::new("Failed to convert error into string")
                       .unwrap().into_raw()),
        None => ptr::null_mut(),
    }
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
/// Returns `NULL` on errors.
#[no_mangle]
pub extern "system" fn sq_context_new(domain: *const c_char)
                                      -> *mut Context {
    assert!(! domain.is_null());
    let domain = unsafe {
        CStr::from_ptr(domain).to_string_lossy()
    };

    if let Ok(context) = core::Context::new(&domain) {
        Box::into_raw(Box::new(Context::new(context)))
    } else {
        ptr::null_mut()
    }
}

/// Frees a context.
#[no_mangle]
pub extern "system" fn sq_context_free(context: *mut Context) {
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
pub extern "system" fn sq_context_network_policy(ctx: Option<&Context>) -> uint8_t {
    assert!(ctx.is_some());
    ctx.unwrap().c.network_policy().into()
}

/// Returns the IPC policy.
#[no_mangle]
pub extern "system" fn sq_context_ipc_policy(ctx: Option<&Context>) -> uint8_t {
    assert!(ctx.is_some());
    ctx.unwrap().c.ipc_policy().into()
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
/// Consumes `cfg`.  Returns `NULL` on errors.
#[no_mangle]
pub extern "system" fn sq_config_build(cfg: Option<&mut Config>)
                                       -> *mut Context {
    assert!(cfg.is_some());
    let cfg = unsafe { Box::from_raw(cfg.unwrap()) };

    if let Ok(context) = cfg.build() {
        Box::into_raw(Box::new(Context::new(context)))
    } else {
        ptr::null_mut()
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
                                                policy: uint8_t) {
    assert!(cfg.is_some());
    cfg.unwrap().set_network_policy(policy.into());
}

/// Sets the IPC policy.
#[no_mangle]
pub extern "system" fn sq_config_ipc_policy(cfg: Option<&mut Config>,
                                            policy: uint8_t) {
    assert!(cfg.is_some());
    cfg.unwrap().set_ipc_policy(policy.into());
}

/// Makes this context ephemeral.
#[no_mangle]
pub extern "system" fn sq_config_ephemeral(cfg: Option<&mut Config>) {
    assert!(cfg.is_some());
    cfg.unwrap().set_ephemeral();
}


/* openpgp::KeyID.  */

/// Reads a binary key ID.
#[no_mangle]
pub extern "system" fn sq_keyid_from_bytes(id: *const uint8_t) -> *mut KeyID {
    if id.is_null() { return ptr::null_mut() }
    let id = unsafe { slice::from_raw_parts(id, 8) };
    Box::into_raw(Box::new(KeyID::from_bytes(id)))
}

/// Reads a hex-encoded Key ID.
#[no_mangle]
pub extern "system" fn sq_keyid_from_hex(id: *const c_char) -> *mut KeyID {
    if id.is_null() { return ptr::null_mut() }
    let id = unsafe { CStr::from_ptr(id).to_string_lossy() };
    KeyID::from_hex(&id)
        .map(|id| Box::into_raw(Box::new(id)))
        .unwrap_or(ptr::null_mut())
}

/// Frees an `KeyID` object.
#[no_mangle]
pub extern "system" fn sq_keyid_free(keyid: *mut KeyID) {
    if keyid.is_null() { return }
    unsafe {
        drop(Box::from_raw(keyid));
    }
}


/* sequoia::keys.  */

/// Returns the first TPK found in `buf`.
///
/// `buf` must be an OpenPGP encoded message.
#[no_mangle]
pub extern "system" fn sq_tpk_from_bytes(ctx: Option<&mut Context>,
                                         b: *const uint8_t, len: size_t)
                                         -> *mut TPK {
    let ctx = ctx.expect("Context is NULL");
    assert!(!b.is_null());
    let buf = unsafe {
        slice::from_raw_parts(b, len as usize)
    };

    fry_box!(ctx, TPK::from_bytes(buf))
}

/// Frees the TPK.
#[no_mangle]
pub extern "system" fn sq_tpk_free(tpk: *mut TPK) {
    if tpk.is_null() {
        return
    }
    unsafe {
        drop(Box::from_raw(tpk));
    }
}

/// Dumps the TPK.
#[no_mangle]
pub extern "system" fn sq_tpk_dump(tpk: *mut TPK) {
    assert!(!tpk.is_null());
    unsafe {
        println!("{:?}", *tpk);
    }
}


/* sequoia::net.  */

/// Returns a handle for the given URI.
///
/// `uri` is a UTF-8 encoded value of a keyserver URI,
/// e.g. `hkps://examle.org`.
///
/// Returns `NULL` on errors.
#[no_mangle]
pub extern "system" fn sq_keyserver_new(ctx: Option<&mut Context>,
                                        uri: *const c_char) -> *mut KeyServer {
    let ctx = ctx.expect("Context is NULL");
    let uri = unsafe {
        if uri.is_null() { None } else { Some(CStr::from_ptr(uri)) }
    };

    fry_box!(ctx, KeyServer::new(&ctx.c, &uri.unwrap().to_string_lossy()))
}

/// Returns a handle for the given URI.
///
/// `uri` is a UTF-8 encoded value of a keyserver URI,
/// e.g. `hkps://examle.org`.  `cert` is a DER encoded certificate of
/// size `len` used to authenticate the server.
///
/// Returns `NULL` on errors.
pub extern "system" fn sq_keyserver_with_cert(ctx: Option<&mut Context>,
                                              uri: *const c_char,
                                              cert: *const uint8_t,
                                              len: size_t) -> *mut KeyServer {
    let ctx = ctx.expect("Context is NULL");
    let uri = unsafe {
        if uri.is_null() { None } else { Some(CStr::from_ptr(uri)) }
    };

    if uri.is_none() || cert.is_null() {
        return ptr::null_mut();
    }

    let cert = unsafe {
        slice::from_raw_parts(cert, len as usize)
    };

    let cert = fry!(ctx, Certificate::from_der(cert)
                    .map_err(|e| e.into()));
    fry_box!(ctx, KeyServer::with_cert(&ctx.c,
                                       &uri.unwrap().to_string_lossy(),
                                       cert))
}

/// Returns a handle for the SKS keyserver pool.
///
/// The pool `hkps://hkps.pool.sks-keyservers.net` provides HKP
/// services over https.  It is authenticated using a certificate
/// included in this library.  It is a good default choice.
///
/// Returns `NULL` on errors.
#[no_mangle]
pub extern "system" fn sq_keyserver_sks_pool(ctx: Option<&Context>) -> *mut KeyServer {
    if ctx.is_none() {
        return ptr::null_mut();
    }

    let ks = KeyServer::sks_pool(&ctx.unwrap().c);

    if let Ok(ks) = ks {
        Box::into_raw(Box::new(ks))
    } else {
        ptr::null_mut()
    }
}

/// Frees a keyserver object.
#[no_mangle]
pub extern "system" fn sq_keyserver_free(ks: *mut KeyServer) {
    if ks.is_null() {
        return
    }
    unsafe {
        drop(Box::from_raw(ks));
    }
}

/// Retrieves the key with the given `keyid`.
///
/// Returns `NULL` on errors.
#[no_mangle]
pub extern "system" fn sq_keyserver_get(ks: Option<&mut KeyServer>,
                                        id: Option<&KeyID>) -> *mut TPK {
    if ks.is_none() || id.is_none() {
        return ptr::null_mut();
    }

    ks.unwrap().get(id.as_ref().unwrap())
        .map(|id| Box::into_raw(Box::new(id)))
        .unwrap_or(ptr::null_mut())
}
