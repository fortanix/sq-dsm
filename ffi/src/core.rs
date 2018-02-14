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
//! ```text
//! sq_context_t ctx;
//!
//! ctx = sq_context_new ("org.sequoia-pgp.example");
//! ```
//!
//! A context can be configured using the builder pattern with
//! `sq_context_configure`:
//!
//! ```text
//! sq_config_t cfg;
//! sq_context_t ctx;
//!
//! cfg = sq_context_configure ("org.sequoia-pgp.example");
//! sq_config_network_policy (cfg, SQ_NETWORK_POLICY_OFFLINE);
//! ctx = sq_config_build (cfg);
//! ```

use failure;
use std::ffi::{CString, CStr};
use std::ptr;
use libc::{uint8_t, c_char};

use sequoia_core as core;
use sequoia_core::Config;

/// Wraps a Context and provides an error slot.
#[doc(hidden)]
pub struct Context {
    pub(crate) c: core::Context,
    pub(crate) e: Option<Box<failure::Error>>,
}

impl Context {
    fn new(c: core::Context) -> Self {
        Context{c: c, e: None}
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
