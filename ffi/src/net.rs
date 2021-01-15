//! For accessing keys over the network.
//!
//! Currently, this module provides access to keyservers providing the [HKP] protocol.
//!
//! [HKP]: https://tools.ietf.org/html/draft-shaw-openpgp-hkp-00
//!
//! # Examples
//!
//! As reasonable default key server we provide a shortcut to use
//! [`keys.openpgp.org`]:
//!
//! [`keys.openpgp.org`]: https://keys.openpgp.org
//!
//! ```c
//! #include <sequoia.h>
//!
//! sq_context_t ctx;
//! pgp_keyid_t id;
//! sq_keyserver_t ks;
//! pgp_cert_t cert;
//!
//! ctx = sq_context_new (NULL);
//! ks = sq_keyserver_keys_openpgp_org (ctx, SQ_NETWORK_POLICY_ENCRYPTED);
//! id = pgp_keyid_from_bytes ((uint8_t *) "\x24\x7F\x6D\xAB\xC8\x49\x14\xFE");
//! cert = sq_keyserver_get (ctx, ks, id);
//!
//! pgp_cert_free (cert);
//! pgp_keyid_free (id);
//! sq_keyserver_free (ks);
//! sq_context_free (ctx);
//! ```

use libc::{c_char, size_t};
use native_tls::Certificate;
use std::convert::TryInto;
use std::ptr;
use std::slice;

use sequoia_net::{KeyServer, Policy};

use super::error::Status;
use super::core::Context;
use crate::openpgp::keyid::KeyID;
use crate::openpgp::cert::Cert;
use crate::RefRaw;
use crate::MoveResultIntoRaw;
use crate::Maybe;

/// Returns a handle for the given URI.
///
/// `uri` is a UTF-8 encoded value of a keyserver URI,
/// e.g. `hkps://examle.org`.
///
/// Returns `NULL` on errors.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle] pub extern "C"
fn sq_keyserver_new(ctx: *mut Context, policy: u8, uri: *const c_char)
                    -> *mut KeyServer {
    let ctx = ffi_param_ref_mut!(ctx);
    ffi_make_fry_from_ctx!(ctx);
    let policy: Policy = ffi_try!(policy.try_into());
    let uri = ffi_param_cstr!(uri).to_string_lossy();

    ffi_try_box!(KeyServer::new(policy, &uri))
}

/// Returns a handle for the given URI.
///
/// `uri` is a UTF-8 encoded value of a keyserver URI,
/// e.g. `hkps://examle.org`.  `cert` is a DER encoded certificate of
/// size `len` used to authenticate the server.
///
/// Returns `NULL` on errors.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle] pub extern "C"
fn sq_keyserver_with_cert(ctx: *mut Context, policy: u8,
                          uri: *const c_char,
                          cert: *const u8,
                          len: size_t) -> *mut KeyServer {
    let ctx = ffi_param_ref_mut!(ctx);
    ffi_make_fry_from_ctx!(ctx);
    let policy: Policy = ffi_try!(policy.try_into());
    let uri = ffi_param_cstr!(uri).to_string_lossy();

    if cert.is_null() {
        return ptr::null_mut();
    }

    let cert = unsafe {
        slice::from_raw_parts(cert, len as usize)
    };

    let cert = ffi_try!(Certificate::from_der(cert)
                    .map_err(|e| ::anyhow::Error::from(e)));
    ffi_try_box!(KeyServer::with_cert(policy, &uri, cert))
}

/// Returns a handle for keys.openpgp.org.
///
/// The server at `hkps://keys.openpgp.org` distributes updates for
/// OpenPGP certificates.  It is a good default choice.
///
/// Returns `NULL` on errors.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle] pub extern "C"
fn sq_keyserver_keys_openpgp_org(ctx: *mut Context, policy: u8)
                                 -> *mut KeyServer {
    let ctx = ffi_param_ref_mut!(ctx);
    ffi_make_fry_from_ctx!(ctx);
    let policy: Policy = ffi_try!(policy.try_into());
    ffi_try_box!(KeyServer::keys_openpgp_org(policy))
}

/// Frees a keyserver object.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle] pub extern "C"
fn sq_keyserver_free(ks: Option<&mut KeyServer>) {
    ffi_free!(ks)
}

/// Retrieves the key with the given `keyid`.
///
/// Returns `NULL` on errors.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle] pub extern "C"
fn sq_keyserver_get(ctx: *mut Context,
                    ks: *mut KeyServer,
                    id: *const KeyID)
                    -> Maybe<Cert> {
    let ctx = ffi_param_ref_mut!(ctx);
    ffi_make_fry_from_ctx!(ctx);
    let ks = ffi_param_ref_mut!(ks);
    let id = id.ref_raw().clone();

    let mut core = ffi_try_or!(basic_runtime(), None);
    core.block_on(ks.get(id)).move_into_raw(Some(ctx.errp()))
}

/// Sends the given key to the server.
///
/// Returns != 0 on errors.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle] pub extern "C"
fn sq_keyserver_send(ctx: *mut Context,
                     ks: *mut KeyServer,
                     cert: *const Cert)
                     -> Status {
    let ctx = ffi_param_ref_mut!(ctx);
    ffi_make_fry_from_ctx!(ctx);
    let ks = ffi_param_ref_mut!(ks);
    let cert = cert.ref_raw();

    ffi_try_status!(basic_runtime()
                    .map_err(|e| e.into())
                    .and_then(|mut rt| rt.block_on(ks.send(cert))))
}

/// Constructs a basic Tokio runtime.
fn basic_runtime() -> tokio::io::Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new()
        .basic_scheduler()
        .enable_io()
        .enable_time()
        .build()
}
