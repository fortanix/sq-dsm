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
//! pgp_keyid_t id;
//! sq_keyserver_t ks;
//! pgp_tpk_t tpk;
//!
//! ctx = sq_context_new (NULL);
//! ks = sq_keyserver_sks_pool (ctx);
//! id = pgp_keyid_from_bytes ((uint8_t *) "\x24\x7F\x6D\xAB\xC8\x49\x14\xFE");
//! tpk = sq_keyserver_get (ctx, ks, id);
//! ```

use libc::{c_char, size_t};
use native_tls::Certificate;
use std::ptr;
use std::slice;

extern crate sequoia_openpgp as openpgp;

use sequoia_net::KeyServer;

use super::error::Status;
use super::core::Context;
use ::openpgp::keyid::KeyID;
use ::openpgp::tpk::TPK;
use ::RefRaw;
use MoveResultIntoRaw;
use Maybe;

/// Returns a handle for the given URI.
///
/// `uri` is a UTF-8 encoded value of a keyserver URI,
/// e.g. `hkps://examle.org`.
///
/// Returns `NULL` on errors.
#[::ffi_catch_abort] #[no_mangle] pub extern "C"
fn sq_keyserver_new(ctx: *mut Context, uri: *const c_char) -> *mut KeyServer {
    let ctx = ffi_param_ref_mut!(ctx);
    ffi_make_fry_from_ctx!(ctx);
    let uri = ffi_param_cstr!(uri).to_string_lossy();

    ffi_try_box!(KeyServer::new(&ctx.c, &uri))
}

/// Returns a handle for the given URI.
///
/// `uri` is a UTF-8 encoded value of a keyserver URI,
/// e.g. `hkps://examle.org`.  `cert` is a DER encoded certificate of
/// size `len` used to authenticate the server.
///
/// Returns `NULL` on errors.
#[::ffi_catch_abort] #[no_mangle] pub extern "C"
fn sq_keyserver_with_cert(ctx: *mut Context,
                          uri: *const c_char,
                          cert: *const u8,
                          len: size_t) -> *mut KeyServer {
    let ctx = ffi_param_ref_mut!(ctx);
    ffi_make_fry_from_ctx!(ctx);
    let uri = ffi_param_cstr!(uri).to_string_lossy();

    if cert.is_null() {
        return ptr::null_mut();
    }

    let cert = unsafe {
        slice::from_raw_parts(cert, len as usize)
    };

    let cert = ffi_try!(Certificate::from_der(cert)
                    .map_err(|e| ::failure::Error::from(e)));
    ffi_try_box!(KeyServer::with_cert(&ctx.c, &uri, cert))
}

/// Returns a handle for the SKS keyserver pool.
///
/// The pool `hkps://hkps.pool.sks-keyservers.net` provides HKP
/// services over https.  It is authenticated using a certificate
/// included in this library.  It is a good default choice.
///
/// Returns `NULL` on errors.
#[::ffi_catch_abort] #[no_mangle] pub extern "C"
fn sq_keyserver_sks_pool(ctx: *mut Context) -> *mut KeyServer {
    let ctx = ffi_param_ref_mut!(ctx);
    ffi_make_fry_from_ctx!(ctx);
    ffi_try_box!(KeyServer::sks_pool(&ctx.c))
}

/// Frees a keyserver object.
#[::ffi_catch_abort] #[no_mangle] pub extern "C"
fn sq_keyserver_free(ks: Option<&mut KeyServer>) {
    ffi_free!(ks)
}

/// Retrieves the key with the given `keyid`.
///
/// Returns `NULL` on errors.
#[::ffi_catch_abort] #[no_mangle] pub extern "C"
fn sq_keyserver_get(ctx: *mut Context,
                    ks: *mut KeyServer,
                    id: *const KeyID)
                    -> Maybe<TPK> {
    let ctx = ffi_param_ref_mut!(ctx);
    ffi_make_fry_from_ctx!(ctx);
    let ks = ffi_param_ref_mut!(ks);
    let id = id.ref_raw();

    ks.get(&id).move_into_raw(Some(ctx.errp()))
}

/// Sends the given key to the server.
///
/// Returns != 0 on errors.
#[::ffi_catch_abort] #[no_mangle] pub extern "C"
fn sq_keyserver_send(ctx: *mut Context,
                     ks: *mut KeyServer,
                     tpk: *const TPK)
                     -> Status {
    let ctx = ffi_param_ref_mut!(ctx);
    ffi_make_fry_from_ctx!(ctx);
    let ks = ffi_param_ref_mut!(ks);
    let tpk = tpk.ref_raw();

    ffi_try_status!(ks.send(tpk))
}
