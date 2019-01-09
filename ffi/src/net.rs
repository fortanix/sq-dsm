//! For accessing keys over the network.
//!
//! Currently, this module provides access to keyservers providing the [HKP] protocol.
//!
//! [HKP]: https://tools.ietf.org/html/draft-shaw-openpgp-hkp-00
//!
//! # Example
//!
//! We provide a very reasonable default key server backed by
//! `hkps.pool.sks-keyservers.net`, the subset of the [SKS keyserver]
//! network that uses https to protect integrity and confidentiality
//! of the communication with the client:
//!
//! [SKS keyserver]: https://www.sks-keyservers.net/overview-of-pools.php#pool_hkps
//!
//! ```c, no-run
//! #include <sequoia.h>
//!
//! sq_context_t ctx;
//! sq_keyid_t id;
//! sq_keyserver_t ks;
//! sq_tpk_t tpk;
//!
//! ctx = sq_context_new ("org.sequoia-pgp.example", NULL);
//! ks = sq_keyserver_sks_pool (ctx);
//! id = sq_keyid_from_bytes ((uint8_t *) "\x24\x7F\x6D\xAB\xC8\x49\x14\xFE");
//! tpk = sq_keyserver_get (ctx, ks, id);
//! ```

use libc::{uint8_t, c_char, size_t};
use native_tls::Certificate;
use std::ffi::CStr;
use std::ptr;
use std::slice;

extern crate sequoia_openpgp as openpgp;

use self::openpgp::TPK;
use self::openpgp::KeyID;
use sequoia_net::KeyServer;

use super::error::Status;
use super::core::Context;

/// Returns a handle for the given URI.
///
/// `uri` is a UTF-8 encoded value of a keyserver URI,
/// e.g. `hkps://examle.org`.
///
/// Returns `NULL` on errors.
#[no_mangle]
pub extern "system" fn sq_keyserver_new(ctx: *mut Context,
                                        uri: *const c_char) -> *mut KeyServer {
    let ctx = ffi_param_ref_mut!(ctx);
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
#[no_mangle]
pub extern "system" fn sq_keyserver_with_cert(ctx: *mut Context,
                                              uri: *const c_char,
                                              cert: *const uint8_t,
                                              len: size_t) -> *mut KeyServer {
    let ctx = ffi_param_ref_mut!(ctx);
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
pub extern "system" fn sq_keyserver_sks_pool(ctx: *mut Context)
                                             -> *mut KeyServer {
    let ctx = ffi_param_ref_mut!(ctx);
    fry_box!(ctx, KeyServer::sks_pool(&ctx.c))
}

/// Frees a keyserver object.
#[no_mangle]
pub extern "system" fn sq_keyserver_free(ks: Option<&mut KeyServer>) {
    ffi_free!(ks)
}

/// Retrieves the key with the given `keyid`.
///
/// Returns `NULL` on errors.
#[no_mangle]
pub extern "system" fn sq_keyserver_get(ctx: *mut Context,
                                        ks: *mut KeyServer,
                                        id: *const KeyID)
                                        -> *mut TPK {
    let ctx = ffi_param_ref_mut!(ctx);
    let ks = ffi_param_ref_mut!(ks);
    let id = ffi_param_ref!(id);

    fry_box!(ctx, ks.get(&id))
}

/// Sends the given key to the server.
///
/// Returns != 0 on errors.
#[no_mangle]
pub extern "system" fn sq_keyserver_send(ctx: *mut Context,
                                         ks: *mut KeyServer,
                                         tpk: *const TPK)
                                         -> Status {
    let ctx = ffi_param_ref_mut!(ctx);
    let ks = ffi_param_ref_mut!(ks);
    let tpk = ffi_param_ref!(tpk);

    fry_status!(ctx, ks.send(tpk))
}
