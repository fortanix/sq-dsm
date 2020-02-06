//! For storing OpenPGP certificates.
//!
//! The key store stores OpenPGP Certificates ("Certs") using an
//! arbitrary label.  Stored keys are automatically updated from
//! remote sources.  This ensures that updates like new subkeys and
//! revocations are discovered in a timely manner.
//!
//! # Security considerations
//!
//! Storing public keys potentially leaks communication partners.
//! Protecting against adversaries inspecting the local storage is out
//! of scope for Sequoia.  Please take the necessary precautions.
//!
//! Sequoia updates keys in compliance with the [network policy] used
//! to create the store.
//!
//! [network policy]: ../../sequoia_core/enum.NetworkPolicy.html
//!
//! # Example
//!
//! ```c, ignore
//! XXX
//! ```


use libc::c_char;
use std::ptr;

extern crate sequoia_openpgp as openpgp;

use sequoia_store::{
    self, Mapping, MappingIter, Binding, BundleIter, Key, KeyIter, LogIter, Store,
};

use super::error::Status;
use super::core::Context;

use crate::openpgp::fingerprint::Fingerprint;
use crate::openpgp::keyid::KeyID;
use crate::openpgp::cert::Cert;
use crate::RefRaw;
use crate::MoveIntoRaw;
use crate::MoveResultIntoRaw;
use crate::Maybe;
use crate::to_time_t;

/// Lists all mappings with the given prefix.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle] pub extern "C"
fn sq_store_list_mappings(ctx: *mut Context,
                        realm_prefix: *const c_char)
                        -> *mut MappingIter {
    let ctx = ffi_param_ref_mut!(ctx);
    ffi_make_fry_from_ctx!(ctx);
    let realm_prefix = ffi_param_cstr!(realm_prefix).to_string_lossy();

    ffi_try_box!(Mapping::list(&ctx.c, &realm_prefix))
}

/// Returns the next mapping.
///
/// Returns `NULL` on exhaustion.  If `realmp` is not `NULL`, the
/// mapping's realm is stored there.  If `namep` is not `NULL`, the
/// mapping's name is stored there.  If `policyp` is not `NULL`, the
/// mapping's network policy is stored there.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle] pub extern "C"
fn sq_mapping_iter_next(iter: *mut MappingIter,
                      realmp: Option<&mut *mut c_char>,
                      namep: Option<&mut *mut c_char>,
                      policyp: Option<&mut u8>)
                      -> *mut Mapping {
    let iter = ffi_param_ref_mut!(iter);
    match iter.next() {
        Some((realm, name, policy, mapping)) => {
            if realmp.is_some() {
                *realmp.unwrap() = ffi_return_maybe_string!(realm);
            }

            if namep.is_some() {
                *namep.unwrap() = ffi_return_maybe_string!(name);
            }

            if policyp.is_some() {
                *policyp.unwrap() = (&policy).into();
            }

            box_raw!(mapping)
        },
        None => ptr::null_mut(),
    }
}

/// Frees a sq_mapping_iter_t.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle] pub extern "C"
fn sq_mapping_iter_free(iter: Option<&mut MappingIter>) {
    ffi_free!(iter)
}

/// Lists all keys in the common key pool.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle] pub extern "C"
fn sq_store_list_keys(ctx: *mut Context) -> *mut KeyIter {
    let ctx = ffi_param_ref_mut!(ctx);
    ffi_make_fry_from_ctx!(ctx);

    ffi_try_box!(Store::list_keys(&ctx.c))
}

/// Lists all log entries.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle] pub extern "C"
fn sq_store_server_log(ctx: *mut Context) -> *mut LogIter {
    let ctx = ffi_param_ref_mut!(ctx);
    ffi_make_fry_from_ctx!(ctx);

    ffi_try_box!(Store::server_log(&ctx.c))
}

/// Returns the next key.
///
/// Returns `NULL` on exhaustion.  If `fpp` is not `NULL`, the key's
/// fingerprint is stored there.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle] pub extern "C"
fn sq_key_iter_next(iter: *mut KeyIter,
                    fpp: Option<&mut Maybe<Fingerprint>>)
                    -> *mut Key {
    let iter = ffi_param_ref_mut!(iter);
    match iter.next() {
        Some((fingerprint, key)) => {
            if fpp.is_some() {
                *fpp.unwrap() = Some(fingerprint).move_into_raw();
            }

            box_raw!(key)
        },
        None => {
            if fpp.is_some() {
                *fpp.unwrap() = None;
            }
            ptr::null_mut()
        },
    }
}

/// Frees a sq_key_iter_t.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle] pub extern "C"
fn sq_key_iter_free(iter: Option<&mut KeyIter>) {
    ffi_free!(iter)
}


/// Returns the next log entry.
///
/// Returns `NULL` on exhaustion.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle] pub extern "C"
fn sq_log_iter_next(iter: *mut LogIter) -> *mut Log {
    let iter = ffi_param_ref_mut!(iter);
    match iter.next() {
        Some(e) => {
            let (status, error) = match e.status {
                Ok(s) => (ffi_return_string!(&s), ptr::null_mut()),
                Err((s, e)) => (ffi_return_string!(&s), ffi_return_string!(&e)),
            };

            box_raw!(Log{
                timestamp: to_time_t(e.timestamp),
                mapping: maybe_box_raw!(e.mapping),
                binding: maybe_box_raw!(e.binding),
                key: maybe_box_raw!(e.key),
                slug: ffi_return_string!(&e.slug),
                status: status,
                error: error,
            })
        },
        None => ptr::null_mut(),
    }
}

/// Frees a sq_log_iter_t.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle] pub extern "C"
fn sq_log_iter_free(iter: Option<&mut LogIter>) {
    ffi_free!(iter)
}

/// Opens a mapping.
///
/// Opens a mapping with the given name.  If the mapping does not
/// exist, it is created.  Mappings are handles for objects
/// maintained by a background service.  The background service
/// associates state with this name.
///
/// The mapping updates Certs in compliance with the network policy
/// of the context that created the mapping in the first place.
/// Opening the mapping with a different network policy is
/// forbidden.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle] pub extern "C"
fn sq_mapping_open(ctx: *mut Context,
                 realm: *const c_char,
                 name: *const c_char)
                 -> *mut Mapping {
    let ctx = ffi_param_ref_mut!(ctx);
    ffi_make_fry_from_ctx!(ctx);
    let realm = ffi_param_cstr!(realm).to_string_lossy();
    let name = ffi_param_cstr!(name).to_string_lossy();

    ffi_try_box!(Mapping::open(&ctx.c, &realm, &name))
}

/// Frees a sq_mapping_t.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle] pub extern "C"
fn sq_mapping_free(mapping: Option<&mut Mapping>) {
    ffi_free!(mapping)
}

/// Adds a key identified by fingerprint to the mapping.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle] pub extern "C"
fn sq_mapping_add(ctx: *mut Context,
                mapping: *const Mapping,
                label: *const c_char,
                fingerprint: *const Fingerprint)
                -> *mut Binding {
    let ctx = ffi_param_ref_mut!(ctx);
    ffi_make_fry_from_ctx!(ctx);
    let mapping = ffi_param_ref!(mapping);
    let label = ffi_param_cstr!(label).to_string_lossy();
    let fingerprint = fingerprint.ref_raw();

    ffi_try_box!(mapping.add(&label, fingerprint))
}

/// Imports a key into the mapping.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle] pub extern "C"
fn sq_mapping_import(ctx: *mut Context,
                   mapping: *const Mapping,
                   label: *const c_char,
                   cert: *const Cert)
                   -> Maybe<Cert> {
    let ctx = ffi_param_ref_mut!(ctx);
    ffi_make_fry_from_ctx!(ctx);
    let mapping = ffi_param_ref!(mapping);
    let label = ffi_param_cstr!(label).to_string_lossy();
    let cert = cert.ref_raw();

    mapping.import(&label, cert).move_into_raw(Some(ctx.errp()))
}

/// Returns the binding for the given label.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle] pub extern "C"
fn sq_mapping_lookup(ctx: *mut Context,
                   mapping: *const Mapping,
                   label: *const c_char)
                   -> *mut Binding {
    let ctx = ffi_param_ref_mut!(ctx);
    ffi_make_fry_from_ctx!(ctx);
    let mapping = ffi_param_ref!(mapping);
    let label = ffi_param_cstr!(label).to_string_lossy();

    ffi_try_box!(mapping.lookup(&label))
}

/// Looks up a key in the common key pool by KeyID.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle] pub extern "C"
fn sq_store_lookup_by_keyid(ctx: *mut Context, keyid: *const KeyID)
    -> *mut Key
{
    let ctx = ffi_param_ref_mut!(ctx);
    ffi_make_fry_from_ctx!(ctx);
    let keyid = keyid.ref_raw();

    ffi_try_box!(Store::lookup_by_keyid(&ctx.c, keyid))
}

/// Looks up a key in the common key pool by (Sub)KeyID.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle] pub extern "C"
fn sq_store_lookup_by_subkeyid(ctx: *mut Context, keyid: *const KeyID)
    -> *mut Key
{
    let ctx = ffi_param_ref_mut!(ctx);
    ffi_make_fry_from_ctx!(ctx);
    let keyid = keyid.ref_raw();

    ffi_try_box!(Store::lookup_by_subkeyid(&ctx.c, keyid))
}

/// Deletes this mapping.
///
/// Consumes `mapping`.  Returns != 0 on error.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle] pub extern "C"
fn sq_mapping_delete(ctx: *mut Context, mapping: *mut Mapping)
                   -> Status {
    let ctx = ffi_param_ref_mut!(ctx);
    ffi_make_fry_from_ctx!(ctx);
    let mapping = ffi_param_move!(mapping);

    ffi_try_status!(mapping.delete())
}

/// Lists all bindings.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle] pub extern "C"
fn sq_mapping_iter(ctx: *mut Context, mapping: *const Mapping)
                 -> *mut BundleIter {
    let ctx = ffi_param_ref_mut!(ctx);
    ffi_make_fry_from_ctx!(ctx);
    let mapping = ffi_param_ref!(mapping);

    ffi_try_box!(mapping.iter())
}

/// Returns the next binding.
///
/// Returns `NULL` on exhaustion.  If `labelp` is not `NULL`, the
/// bindings label is mappingd there.  If `fpp` is not `NULL`, the
/// bindings fingerprint is mappingd there.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle] pub extern "C"
fn sq_binding_iter_next(iter: *mut BundleIter,
                        labelp: Option<&mut *mut c_char>,
                        fpp: Option<&mut Maybe<Fingerprint>>)
                        -> *mut Binding {
    let iter = ffi_param_ref_mut!(iter);
    match iter.next() {
        Some((label, fp, binding)) => {
            if labelp.is_some() {
                *labelp.unwrap() = ffi_return_maybe_string!(label);
            }

            if fpp.is_some() {
                *fpp.unwrap() = Some(fp).move_into_raw();
            }

            box_raw!(binding)
        },
        None => {
            if fpp.is_some() {
                *fpp.unwrap() = None;
            }
            ptr::null_mut()
        },
    }
}

/// Frees a sq_binding_iter_t.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle] pub extern "C"
fn sq_binding_iter_free(iter: Option<&mut BundleIter>) {
    ffi_free!(iter)
}

/// Lists all log entries related to this mapping.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle] pub extern "C"
fn sq_mapping_log(ctx: *mut Context, mapping: *const Mapping)
                -> *mut LogIter {
    let ctx = ffi_param_ref_mut!(ctx);
    ffi_make_fry_from_ctx!(ctx);
    let mapping = ffi_param_ref!(mapping);

    ffi_try_box!(mapping.log())
}

/// Frees a sq_binding_t.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle] pub extern "C"
fn sq_binding_free(binding: Option<&mut Binding>) {
    ffi_free!(binding)
}

/// Frees a sq_key_t.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle] pub extern "C"
fn sq_key_free(key: Option<&mut Key>) {
    ffi_free!(key)
}

/// Frees a sq_log_t.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle] pub extern "C"
fn sq_log_free(log: Option<&mut Log>) {
    if let Some(log) = log {
        let log = unsafe { Box::from_raw(log) };
        if ! log.mapping.is_null() {
            ffi_param_move!(log.mapping);
        }
        if ! log.binding.is_null() {
            ffi_param_move!(log.binding);
        }
        if ! log.key.is_null() {
            ffi_param_move!(log.key);
        }
        unsafe {
            libc::free(log.slug as *mut libc::c_void);
            libc::free(log.status as *mut libc::c_void);
            libc::free(log.error as *mut libc::c_void);
        }
        drop(log)
    }
}

/// Returns the `sq_stats_t` of this binding.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle] pub extern "C"
fn sq_binding_stats(ctx: *mut Context, binding: *const Binding)
                    -> *mut Stats {
    let ctx = ffi_param_ref_mut!(ctx);
    ffi_make_fry_from_ctx!(ctx);
    let binding = ffi_param_ref!(binding);

    box_raw!(Stats::new(ffi_try!(binding.stats())))
}

/// Returns the `sq_key_t` of this binding.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle] pub extern "C"
fn sq_binding_key(ctx: *mut Context, binding: *const Binding)
                  -> *mut Key {
    let ctx = ffi_param_ref_mut!(ctx);
    ffi_make_fry_from_ctx!(ctx);
    let binding = ffi_param_ref!(binding);

    ffi_try_box!(binding.key())
}

/// Returns the `pgp_cert_t` of this binding.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle] pub extern "C"
fn sq_binding_cert(ctx: *mut Context, binding: *const Binding)
                  -> Maybe<Cert> {
    let ctx = ffi_param_ref_mut!(ctx);
    ffi_make_fry_from_ctx!(ctx);
    let binding = ffi_param_ref!(binding);

    binding.cert().move_into_raw(Some(ctx.errp()))
}

/// Updates this binding with the given Cert.
///
/// If the new key `cert` matches the current key, i.e. they have
/// the same fingerprint, both keys are merged and normalized.
/// The returned key contains all packets known to Sequoia, and
/// should be used instead of `cert`.
///
/// If the new key does not match the current key, but carries a
/// valid signature from the current key, it replaces the current
/// key.  This provides a natural way for key rotations.
///
/// If the new key does not match the current key, and it does not
/// carry a valid signature from the current key, an
/// `Error::Conflict` is returned, and you have to resolve the
/// conflict, either by ignoring the new key, or by using
/// `sq_binding_rotate` to force a rotation.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle] pub extern "C"
fn sq_binding_import(ctx: *mut Context,
                     binding: *const Binding,
                     cert: *const Cert)
                     -> Maybe<Cert> {
    let ctx = ffi_param_ref_mut!(ctx);
    ffi_make_fry_from_ctx!(ctx);
    let binding = ffi_param_ref!(binding);
    let cert = cert.ref_raw();

    binding.import(&cert).move_into_raw(Some(ctx.errp()))
}


/// Forces a keyrotation to the given Cert.
///
/// The current key is replaced with the new key `cert`, even if
/// they do not have the same fingerprint.  If a key with the same
/// fingerprint as `cert` is already in the mapping, is merged with
/// `cert` and normalized.  The returned key contains all packets
/// known to Sequoia, and should be used instead of `cert`.
///
/// Use this function to resolve conflicts returned from
/// `sq_binding_import`.  Make sure that you have authenticated
/// `cert` properly.  How to do that depends on your thread model.
/// You could simply ask Alice to call her communication partner
/// Bob and confirm that he rotated his keys.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle] pub extern "C"
fn sq_binding_rotate(ctx: *mut Context,
                     binding: *const Binding,
                     cert: *const Cert)
                     -> Maybe<Cert> {
    let ctx = ffi_param_ref_mut!(ctx);
    ffi_make_fry_from_ctx!(ctx);
    let binding = ffi_param_ref!(binding);
    let cert = cert.ref_raw();

    binding.rotate(&cert).move_into_raw(Some(ctx.errp()))
}

/// Deletes this binding.
///
/// Consumes `binding`.  Returns != 0 on error.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle] pub extern "C"
fn sq_binding_delete(ctx: *mut Context,
                     binding: *mut Binding)
                     -> Status {
    let ctx = ffi_param_ref_mut!(ctx);
    ffi_make_fry_from_ctx!(ctx);
    let binding = ffi_param_move!(binding);

    ffi_try_status!(binding.delete())
}

/// Lists all log entries related to this binding.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle] pub extern "C"
fn sq_binding_log(ctx: *mut Context,
                  binding: *const Binding)
                  -> *mut LogIter {
    let ctx = ffi_param_ref_mut!(ctx);
    ffi_make_fry_from_ctx!(ctx);
    let binding = ffi_param_ref!(binding);

    ffi_try_box!(binding.log())
}

/// Returns the `sq_stats_t` of this key.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle] pub extern "C"
fn sq_key_stats(ctx: *mut Context,
                key: *const Key)
                -> *mut Stats {
    let ctx = ffi_param_ref_mut!(ctx);
    ffi_make_fry_from_ctx!(ctx);
    let key = ffi_param_ref!(key);

    box_raw!(Stats::new(ffi_try!(key.stats())))
}

/// Returns the `pgp_cert_t`.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle] pub extern "C"
fn sq_key_cert(ctx: *mut Context,
              key: *const Key)
              -> Maybe<Cert> {
    let ctx = ffi_param_ref_mut!(ctx);
    ffi_make_fry_from_ctx!(ctx);
    let key = ffi_param_ref!(key);

    key.cert().move_into_raw(Some(ctx.errp()))
}

/// Updates this stored key with the given Cert.
///
/// If the new key `cert` matches the current key, i.e. they have
/// the same fingerprint, both keys are merged and normalized.
/// The returned key contains all packets known to Sequoia, and
/// should be used instead of `cert`.
///
/// If the new key does not match the current key,
/// `Error::Conflict` is returned.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle] pub extern "C"
fn sq_key_import(ctx: *mut Context,
                 key: *const Key,
                 cert: *const Cert)
                 -> Maybe<Cert> {
    let ctx = ffi_param_ref_mut!(ctx);
    ffi_make_fry_from_ctx!(ctx);
    let key = ffi_param_ref!(key);
    let cert = cert.ref_raw();

    key.import(&cert).move_into_raw(Some(ctx.errp()))
}

/// Lists all log entries related to this key.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle] pub extern "C"
fn sq_key_log(ctx: *mut Context,
              key: *const Key)
              -> *mut LogIter {
    let ctx = ffi_param_ref_mut!(ctx);
    ffi_make_fry_from_ctx!(ctx);
    let key = ffi_param_ref!(key);

    ffi_try_box!(key.log())
}

/// Frees a sq_stats_t.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle] pub extern "C"
fn sq_stats_free(stats: Option<&mut Stats>) {
    ffi_free!(stats)
}

/// Counter and timestamps.
#[repr(C)]
pub struct Stamps {
    /// Counts how many times this has been used.
    pub count: u64,

    /// Records the time when this has been used first.
    pub first:  libc::time_t,

    /// Records the time when this has been used last.
    pub last: libc::time_t,
}

impl Stamps {
    fn new(s: &sequoia_store::Stamps) -> Stamps {
        Stamps{
            count: s.count as u64,
            first: to_time_t(s.first),
            last: to_time_t(s.last),
        }
    }
}

/// Statistics about bindings and stored keys.
///
/// We collect some data about binginds and stored keys.  This
/// information can be used to make informed decisions about key
/// transitions.
#[repr(C)]
pub struct Stats {
    /// Records the time this item was created.
    pub created: libc::time_t,

    /// Records the time this item was last updated.
    pub updated: libc::time_t,

    /// Records counters and timestamps of encryptions.
    pub encryption: Stamps,

    /// Records counters and timestamps of verifications.
    pub verification: Stamps,
}

impl Stats {
    fn new(s: sequoia_store::Stats) -> Stats {
        Stats {
            created: to_time_t(s.created),
            updated: to_time_t(s.updated),
            encryption: Stamps::new(&s.encryption),
            verification: Stamps::new(&s.verification),
        }
    }
}

/// Represents a log entry.
#[repr(C)]
pub struct Log {
    /// Records the time of the entry.
    pub timestamp: libc::time_t,

    /// Relates the entry to a mapping.
    ///
    /// May be `NULL`.
    pub mapping: *mut Mapping,

    /// Relates the entry to a binding.
    ///
    /// May be `NULL`.
    pub binding: *mut Binding,

    /// Relates the entry to a key.
    ///
    /// May be `NULL`.
    pub key: *mut Key,

    /// Relates the entry to some object.
    ///
    /// This is a human-readable description of what this log entry is
    /// mainly concerned with.
    pub slug: *mut c_char,

    /// Holds the log message.
    pub status: *mut c_char,

    /// Holds the error message, if any.
    ///
    /// May be `NULL`.
    pub error: *mut c_char,
}
