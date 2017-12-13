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


extern crate libc;
extern crate native_tls;
extern crate openpgp;
extern crate sequoia_core;
extern crate sequoia_net;

use std::ffi::CStr;
use std::ptr;
use std::slice;
use std::str;

use openpgp::tpk::TPK;
use openpgp::types::KeyId;
use self::libc::{uint8_t, uint64_t, c_char, size_t};
use self::native_tls::Certificate;
use sequoia_core::{Config, Context, NetworkPolicy};
use sequoia_net::KeyServer;

/*  sequoia::Context.  */

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

    if let Ok(context) = Context::new(&domain) {
        Box::into_raw(Box::new(context))
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

    Box::into_raw(Box::new(Context::configure(&domain)))
}

/// Returns the domain of the context.
#[no_mangle]
pub extern "system" fn sq_context_domain(ctx: Option<&Context>) -> *const c_char {
    assert!(ctx.is_some());
    ctx.unwrap().domain().as_bytes().as_ptr() as *const c_char
}

/// Returns the directory containing shared state.
#[no_mangle]
pub extern "system" fn sq_context_home(ctx: Option<&Context>) -> *const c_char {
    assert!(ctx.is_some());
    ctx.unwrap().home().to_string_lossy().as_ptr() as *const c_char
}

/// Returns the directory containing backend servers.
#[no_mangle]
pub extern "system" fn sq_context_lib(ctx: Option<&Context>) -> *const c_char {
    assert!(ctx.is_some());
    ctx.unwrap().lib().to_string_lossy().as_bytes().as_ptr() as *const c_char
}

/// Returns the network policy.
#[no_mangle]
pub extern "system" fn sq_context_network_policy(ctx: Option<&Context>) -> uint8_t {
    assert!(ctx.is_some());
    match ctx.unwrap().network_policy() {
        &NetworkPolicy::Offline => 0,
        &NetworkPolicy::Anonymized => 1,
        &NetworkPolicy::Encrypted => 2,
        &NetworkPolicy::Insecure => 3,
    }
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
        Box::into_raw(Box::new(context))
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
    cfg.unwrap().set_network_policy(match policy {
        0 => NetworkPolicy::Offline,
        1 => NetworkPolicy::Anonymized,
        2 => NetworkPolicy::Encrypted,
        3 => NetworkPolicy::Insecure,
        n => panic!("Bad policy: {}", n),
    });
}

/* openpgp::types.  */

/// Returns a KeyID with the given `id`.
#[no_mangle]
pub extern "system" fn sq_keyid_new(id: uint64_t) -> *mut KeyId {
    Box::into_raw(Box::new(KeyId::new(id)))
}

/// Returns a KeyID with the given `id` encoded as hexadecimal string.
#[no_mangle]
pub extern "system" fn sq_keyid_from_hex(id: *const c_char) -> *mut KeyId {
    if id.is_null() { return ptr::null_mut() }
    let id = unsafe { CStr::from_ptr(id).to_string_lossy() };
    KeyId::from_hex(&id)
        .map(|id| Box::into_raw(Box::new(id)))
        .unwrap_or(ptr::null_mut())
}

/// Frees an `KeyId` object.
#[no_mangle]
pub extern "system" fn sq_keyid_free(keyid: *mut KeyId) {
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
pub extern "system" fn sq_tpk_from_bytes(b: *const uint8_t, len: size_t) -> *mut TPK {
    assert!(!b.is_null());
    let buf = unsafe {
        slice::from_raw_parts(b, len as usize)
    };
    if let Ok(tpk) = TPK::from_bytes(buf) {
        Box::into_raw(Box::new(tpk))
    } else {
        ptr::null_mut()
    }
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
pub extern "system" fn sq_keyserver_new(ctx: Option<&Context>,
                                        uri: *const c_char) -> *mut KeyServer {
    let uri = unsafe {
        if uri.is_null() { None } else { Some(CStr::from_ptr(uri)) }
    };

    if ctx.is_none() || uri.is_none() {
        return ptr::null_mut();
    }
    let ks = KeyServer::new(ctx.unwrap(), &uri.unwrap().to_string_lossy());

    if let Ok(ks) = ks {
        Box::into_raw(Box::new(ks))
    } else {
        ptr::null_mut()
    }
}

/// Returns a handle for the given URI.
///
/// `uri` is a UTF-8 encoded value of a keyserver URI,
/// e.g. `hkps://examle.org`.  `cert` is a DER encoded certificate of
/// size `len` used to authenticate the server.
///
/// Returns `NULL` on errors.
pub extern "system" fn sq_keyserver_with_cert(ctx: Option<&Context>,
                                              uri: *const c_char,
                                              cert: *const uint8_t,
                                              len: size_t) -> *mut KeyServer {
    let uri = unsafe {
        if uri.is_null() { None } else { Some(CStr::from_ptr(uri)) }
    };

    if ctx.is_none() || uri.is_none() || cert.is_null() {
        return ptr::null_mut();
    }

    let cert = unsafe {
        slice::from_raw_parts(cert, len as usize)
    };

    let cert = Certificate::from_der(cert);
    if cert.is_err() {
        return ptr::null_mut();
    }

    let ks = KeyServer::with_cert(ctx.unwrap(),
                                  &uri.unwrap().to_string_lossy(),
                                  cert.unwrap());

    if let Ok(ks) = ks {
        Box::into_raw(Box::new(ks))
    } else {
        ptr::null_mut()
    }
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

    let ks = KeyServer::sks_pool(ctx.unwrap());

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
                                        id: Option<&KeyId>) -> *mut TPK {
    if ks.is_none() || id.is_none() {
        return ptr::null_mut();
    }

    ks.unwrap().get(id.as_ref().unwrap())
        .map(|id| Box::into_raw(Box::new(id)))
        .unwrap_or(ptr::null_mut())
}
