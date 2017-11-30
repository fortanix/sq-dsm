extern crate libc;
use self::libc::{uint8_t, c_char, size_t};

use std::ffi::CStr;
use std::ptr;
use std::slice;
use std::str;

use keys::TPK;
use openpgp;
use super::Context;

/// Create a context object.
///
/// If `home` is not `NULL`, it is used as directory containing shared
/// state and rendezvous nodes.  If `lib` is not `NULL`, it is used as
/// directory containing backend servers.  If either argument is
/// `NULL`, a reasonable default is used.
///
/// Returns `NULL` on errors.
#[no_mangle]
pub extern "system" fn sq_context_new(home: *const c_char,
                                      lib: *const c_char) -> *mut Context {
    let home = unsafe {
        if home.is_null() { None } else { Some(CStr::from_ptr(home)) }
    };
    let lib = unsafe {
        if lib.is_null() { None } else { Some(CStr::from_ptr(lib)) }
    };

    let mut pre = Context::new();

    if let Some(home) = home {
        pre = pre.home(home.to_string_lossy().as_ref());
    }
    if let Some(lib) = lib {
        pre = pre.lib(lib.to_string_lossy().as_ref());
    }

    if let Ok(context) = pre.finalize() {
        Box::into_raw(Box::new(context))
    } else {
        ptr::null_mut()
    }
}

/// Free a context.
#[no_mangle]
pub extern "system" fn sq_context_free(context: *mut Context) {
    unsafe {
        drop(Box::from_raw(context));
    }
}

#[no_mangle]
pub extern "system" fn sq_tpk_from_bytes(b: *const uint8_t, len: size_t) -> *mut TPK {
    assert!(!b.is_null());
    let bytes = unsafe {
        slice::from_raw_parts(b, len as usize)
    };
    let m = openpgp::Message::from_bytes(bytes);

    if let Some(tpk) = m.ok().and_then(|m| TPK::from_message(m)) {
        Box::into_raw(Box::new(tpk))
    } else {
        ptr::null_mut()
    }
}

#[no_mangle]
pub extern "system" fn sq_tpk_dump(tpk: *mut TPK) {
    assert!(!tpk.is_null());
    unsafe {
        println!("{:?}", *tpk);
    }
}

#[no_mangle]
pub extern "system" fn sq_tpk_free(tpk: *mut TPK) {
    if tpk.is_null() {
        return
    }
    unsafe {
        drop(Box::from_raw(tpk));
    }
}
