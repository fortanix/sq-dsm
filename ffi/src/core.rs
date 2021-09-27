//! Contexts and errors.
//!
//! Sequoia tries to be useful for a wide variety of applications.
//! Therefore, we need you to provide a little information about the
//! context you are using Sequoia in.
//!
//! # Examples
//!
//! A context with reasonable defaults can be created using
//! `sq_context_new`:
//!
//! ```c
//! #include <sequoia.h>
//!
//! sq_context_t ctx;
//! ctx = sq_context_new (NULL);
//!
//! /* Use Sequoia.  */
//!
//! sq_context_free (ctx);
//! ```
//!
//! A context can be configured using the builder pattern with
//! `sq_context_configure`:
//!
//! ```c
//! #include <sequoia.h>
//!
//! sq_config_t cfg;
//! sq_context_t ctx;
//!
//! cfg = sq_context_configure ();
//! sq_config_ipc_policy (cfg, SQ_IPC_POLICY_ROBUST);
//! ctx = sq_config_build (cfg, NULL);
//!
//! /* Use Sequoia.  */
//!
//! sq_context_free (ctx);
//! ```

use std::ptr;
use libc::{c_char, c_int};

use sequoia_ipc::Config;

/// Wraps a Context and provides an error slot.
#[doc(hidden)]
pub struct Context {
    pub(crate) c: sequoia_ipc::Context,
    e: *mut crate::error::Error,
}

impl Context {
    fn new(c: sequoia_ipc::Context) -> Self {
        Context{c, e: ptr::null_mut()}
    }

    pub(crate) fn errp(&mut self) -> &mut *mut crate::error::Error {
        &mut self.e
    }
}

impl Drop for Context {
    fn drop(&mut self) {
        if !self.e.is_null() {
            unsafe {
                drop(Box::from_raw(self.e));
            }
        }
    }
}

/// Returns the last error.
///
/// Returns and removes the last error from the context.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle] pub extern "C"
fn sq_context_last_error(ctx: *mut Context) -> *mut crate::error::Error {
    let ctx = ffi_param_ref_mut!(ctx);
    ::std::mem::replace(&mut ctx.e, ptr::null_mut())
}

/// Creates a Context with reasonable defaults.
///
/// Returns `NULL` on errors.  If `errp` is not `NULL`, the error is
/// stored there.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle] pub extern "C"
fn sq_context_new(errp: Option<&mut *mut crate::error::Error>)
                  -> *mut Context {
    ffi_make_fry_from_errp!(errp);
    ffi_try_box!(sequoia_ipc::Context::new().map(Context::new))
}

/// Frees a context.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle] pub extern "C"
fn sq_context_free(context: Option<&mut Context>) {
    ffi_free!(context)
}

/// Creates a Context that can be configured.
///
/// The configuration is seeded like in `sq_context_new`, but can be
/// modified.  A configuration has to be finalized using
/// `sq_config_build()` in order to turn it into a Context.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle] pub extern "C"
fn sq_context_configure() -> *mut Config {
    Box::into_raw(Box::new(sequoia_ipc::Context::configure()))
}

/// Returns the directory containing shared state.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle] pub extern "C"
fn sq_context_home(ctx: *const Context) -> *const c_char {
    let ctx = ffi_param_ref!(ctx);
    ctx.c.home().to_string_lossy().as_ptr() as *const c_char
}

/// Returns the directory containing backend servers.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle] pub extern "C"
fn sq_context_lib(ctx: *const Context) -> *const c_char {
    let ctx = ffi_param_ref!(ctx);
    ctx.c.lib().to_string_lossy().as_bytes().as_ptr() as *const c_char
}

/// Returns the IPC policy.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle] pub extern "C"
fn sq_context_ipc_policy(ctx: *const Context) -> c_int {
    let ctx = ffi_param_ref!(ctx);
    u8::from(ctx.c.ipc_policy()) as c_int
}

/// Returns whether or not this is an ephemeral context.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle] pub extern "C"
fn sq_context_ephemeral(ctx: *const Context) -> u8 {
    let ctx = ffi_param_ref!(ctx);
    if ctx.c.ephemeral() { 1 } else { 0 }
}


/*  sequoia::Config.  */

/// Finalizes the configuration and return a `Context`.
///
/// Consumes `cfg`.  Returns `NULL` on errors. Returns `NULL` on
/// errors.  If `errp` is not `NULL`, the error is stored there.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle] pub extern "C"
fn sq_config_build(cfg: *mut Config, errp: Option<&mut *mut crate::error::Error>)
                   -> *mut Context {
    ffi_make_fry_from_errp!(errp);
    let cfg = ffi_param_move!(cfg);

    ffi_try_box!(cfg.build().map(Context::new))
}

/// Sets the directory containing shared state.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle] pub extern "C"
fn sq_config_home(cfg: *mut Config, home: *const c_char) {
    let cfg = ffi_param_ref_mut!(cfg);
    let home = ffi_param_cstr!(home).to_string_lossy();
    cfg.set_home(home.as_ref());
}

/// Set the directory containing backend servers.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle] pub extern "C"
fn sq_config_lib(cfg: *mut Config, lib: *const c_char) {
    let cfg = ffi_param_ref_mut!(cfg);
    let lib = ffi_param_cstr!(lib).to_string_lossy();
    cfg.set_lib(&lib.as_ref());
}

/// Sets the IPC policy.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle] pub extern "C"
fn sq_config_ipc_policy(cfg: *mut Config, policy: c_int) {
    let cfg = ffi_param_ref_mut!(cfg);
    if policy < 0 || policy > 2 {
        panic!("Bad ipc policy: {}", policy);
    }
    cfg.set_ipc_policy((policy as u8).into());
}

/// Makes this context ephemeral.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle] pub extern "C"
fn sq_config_ephemeral(cfg: *mut Config) {
    let cfg = ffi_param_ref_mut!(cfg);
    cfg.set_ephemeral();
}

#[test]
fn test_drop_context() {
    {
        use crate::MoveIntoRaw;

        let c = sq_context_new(None);
        let ctx = ffi_param_ref_mut!(c);
        let errp = ctx.errp();
        {
            let e = anyhow::anyhow!("bad");
            *errp = e.move_into_raw();
        }
        sq_context_free(Some(ctx));
    }
}
