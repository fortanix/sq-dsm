//! For storing transferable public keys.
//!
//! The key store stores transferable public keys (TPKs) using an
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


use libc::{uint8_t, uint64_t, c_char};
use std::ptr;

extern crate sequoia_openpgp as openpgp;

use self::openpgp::TPK;
use self::openpgp::{
    Fingerprint,
    KeyID
};
use sequoia_store::{
    self, Store, StoreIter, Binding, BindingIter, Key, KeyIter, LogIter, Pool,
};

use super::error::Status;
use super::core::Context;


/// Lists all stores with the given prefix.
#[::ffi_catch_abort] #[no_mangle]
pub extern "system" fn sq_store_list_stores(ctx: *mut Context,
                                            domain_prefix: *const c_char)
                                            -> *mut StoreIter {
    let ctx = ffi_param_ref_mut!(ctx);
    ffi_make_fry_from_ctx!(ctx);
    let domain_prefix = ffi_param_cstr!(domain_prefix).to_string_lossy();

    ffi_try_box!(Store::list(&ctx.c, &domain_prefix))
}

/// Returns the next store.
///
/// Returns `NULL` on exhaustion.  If `domainp` is not `NULL`, the
/// stores domain is stored there.  If `namep` is not `NULL`, the
/// stores name is stored there.  If `policyp` is not `NULL`, the
/// stores network policy is stored there.
#[::ffi_catch_abort] #[no_mangle]
pub extern "system" fn sq_store_iter_next(iter: *mut StoreIter,
                                          domainp: Option<&mut *mut c_char>,
                                          namep: Option<&mut *mut c_char>,
                                          policyp: Option<&mut uint8_t>)
                                          -> *mut Store {
    let iter = ffi_param_ref_mut!(iter);
    match iter.next() {
        Some((domain, name, policy, store)) => {
            if domainp.is_some() {
                *domainp.unwrap() = ffi_return_maybe_string!(domain);
            }

            if namep.is_some() {
                *namep.unwrap() = ffi_return_maybe_string!(name);
            }

            if policyp.is_some() {
                *policyp.unwrap() = (&policy).into();
            }

            box_raw!(store)
        },
        None => ptr::null_mut(),
    }
}

/// Frees a sq_store_iter_t.
#[::ffi_catch_abort] #[no_mangle]
pub extern "system" fn sq_store_iter_free(iter: Option<&mut StoreIter>) {
    ffi_free!(iter)
}

/// Lists all keys in the common key pool.
#[::ffi_catch_abort] #[no_mangle]
pub extern "system" fn sq_store_list_keys(ctx: *mut Context)
                                          -> *mut KeyIter {
    let ctx = ffi_param_ref_mut!(ctx);
    ffi_make_fry_from_ctx!(ctx);

    ffi_try_box!(Store::list_keys(&ctx.c))
}

/// Lists all log entries.
#[::ffi_catch_abort] #[no_mangle]
pub extern "system" fn sq_store_server_log(ctx: *mut Context)
                                           -> *mut LogIter {
    let ctx = ffi_param_ref_mut!(ctx);
    ffi_make_fry_from_ctx!(ctx);

    ffi_try_box!(Store::server_log(&ctx.c))
}

/// Returns the next key.
///
/// Returns `NULL` on exhaustion.  If `fpp` is not `NULL`, the key's
/// fingerprint is stored there.
#[::ffi_catch_abort] #[no_mangle]
pub extern "system" fn sq_key_iter_next(iter: *mut KeyIter,
                                        fpp: Option<&mut *mut Fingerprint>)
                                        -> *mut Key {
    let iter = ffi_param_ref_mut!(iter);
    match iter.next() {
        Some((fingerprint, key)) => {
            if fpp.is_some() {
                *fpp.unwrap() = box_raw!(fingerprint);
            }

            box_raw!(key)
        },
        None => ptr::null_mut(),
    }
}

/// Frees a sq_key_iter_t.
#[::ffi_catch_abort] #[no_mangle]
pub extern "system" fn sq_key_iter_free(iter: Option<&mut KeyIter>) {
    ffi_free!(iter)
}


/// Returns the next log entry.
///
/// Returns `NULL` on exhaustion.
#[::ffi_catch_abort] #[no_mangle]
pub extern "system" fn sq_log_iter_next(iter: *mut LogIter)
                                        -> *mut Log {
    let iter = ffi_param_ref_mut!(iter);
    match iter.next() {
        Some(e) => {
            let (status, error) = match e.status {
                Ok(s) => (ffi_return_string!(&s), ptr::null_mut()),
                Err((s, e)) => (ffi_return_string!(&s), ffi_return_string!(&e)),
            };

            box_raw!(Log{
                timestamp: e.timestamp.sec as uint64_t,
                store: maybe_box_raw!(e.store),
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
#[::ffi_catch_abort] #[no_mangle]
pub extern "system" fn sq_log_iter_free(iter: Option<&mut LogIter>) {
    ffi_free!(iter)
}

/// Opens a store.
///
/// Opens a store with the given name.  If the store does not
/// exist, it is created.  Stores are handles for objects
/// maintained by a background service.  The background service
/// associates state with this name.
///
/// The store updates TPKs in compliance with the network policy
/// of the context that created the store in the first place.
/// Opening the store with a different network policy is
/// forbidden.
#[::ffi_catch_abort] #[no_mangle]
pub extern "system" fn sq_store_open(ctx: *mut Context,
                                     name: *const c_char)
                                     -> *mut Store {
    let ctx = ffi_param_ref_mut!(ctx);
    ffi_make_fry_from_ctx!(ctx);
    let name = ffi_param_cstr!(name).to_string_lossy();

    ffi_try_box!(Store::open(&ctx.c, &name))
}

/// Frees a sq_store_t.
#[::ffi_catch_abort] #[no_mangle]
pub extern "system" fn sq_store_free(store: Option<&mut Store>) {
    ffi_free!(store)
}

/// Adds a key identified by fingerprint to the store.
#[::ffi_catch_abort] #[no_mangle]
pub extern "system" fn sq_store_add(ctx: *mut Context,
                                    store: *const Store,
                                    label: *const c_char,
                                    fingerprint: *const Fingerprint)
                                    -> *mut Binding {
    let ctx = ffi_param_ref_mut!(ctx);
    ffi_make_fry_from_ctx!(ctx);
    let store = ffi_param_ref!(store);
    let label = ffi_param_cstr!(label).to_string_lossy();
    let fingerprint = ffi_param_ref!(fingerprint);

    ffi_try_box!(store.add(&label, fingerprint))
}

/// Imports a key into the store.
#[::ffi_catch_abort] #[no_mangle]
pub extern "system" fn sq_store_import(ctx: *mut Context,
                                       store: *const Store,
                                       label: *const c_char,
                                       tpk: *const TPK)
                                       -> *mut TPK {
    let ctx = ffi_param_ref_mut!(ctx);
    ffi_make_fry_from_ctx!(ctx);
    let store = ffi_param_ref!(store);
    let label = ffi_param_cstr!(label).to_string_lossy();
    let tpk = ffi_param_ref!(tpk);

    ffi_try_box!(store.import(&label, tpk))
}

/// Returns the binding for the given label.
#[::ffi_catch_abort] #[no_mangle]
pub extern "system" fn sq_store_lookup(ctx: *mut Context,
                                       store: *const Store,
                                       label: *const c_char)
                                       -> *mut Binding {
    let ctx = ffi_param_ref_mut!(ctx);
    ffi_make_fry_from_ctx!(ctx);
    let store = ffi_param_ref!(store);
    let label = ffi_param_cstr!(label).to_string_lossy();

    ffi_try_box!(store.lookup(&label))
}

/// Looks up a key in the common key pool by KeyID.
#[::ffi_catch_abort] #[no_mangle]
pub extern "system" fn sq_store_lookup_by_keyid(ctx: *mut Context,
                                                keyid: *const KeyID)
    -> *mut Key
{
    let ctx = ffi_param_ref_mut!(ctx);
    ffi_make_fry_from_ctx!(ctx);
    let keyid = ffi_param_ref!(keyid);

    ffi_try_box!(Pool::lookup_by_keyid(&ctx.c, keyid))
}

/// Looks up a key in the common key pool by (Sub)KeyID.
#[::ffi_catch_abort] #[no_mangle]
pub extern "system" fn sq_store_lookup_by_subkeyid(ctx: *mut Context,
                                                   keyid: *const KeyID)
    -> *mut Key
{
    let ctx = ffi_param_ref_mut!(ctx);
    ffi_make_fry_from_ctx!(ctx);
    let keyid = ffi_param_ref!(keyid);

    ffi_try_box!(Pool::lookup_by_subkeyid(&ctx.c, keyid))
}

/// Deletes this store.
///
/// Consumes `store`.  Returns != 0 on error.
#[::ffi_catch_abort] #[no_mangle]
pub extern "system" fn sq_store_delete(ctx: *mut Context,
                                       store: *mut Store)
                                       -> Status {
    let ctx = ffi_param_ref_mut!(ctx);
    ffi_make_fry_from_ctx!(ctx);
    let store = ffi_param_move!(store);

    ffi_try_status!(store.delete())
}

/// Lists all bindings.
#[::ffi_catch_abort] #[no_mangle]
pub extern "system" fn sq_store_iter(ctx: *mut Context,
                                     store: *const Store)
                                     -> *mut BindingIter {
    let ctx = ffi_param_ref_mut!(ctx);
    ffi_make_fry_from_ctx!(ctx);
    let store = ffi_param_ref!(store);

    ffi_try_box!(store.iter())
}

/// Returns the next binding.
///
/// Returns `NULL` on exhaustion.  If `labelp` is not `NULL`, the
/// bindings label is stored there.  If `fpp` is not `NULL`, the
/// bindings fingerprint is stored there.
#[::ffi_catch_abort] #[no_mangle]
pub extern "system" fn sq_binding_iter_next(iter: *mut BindingIter,
                                            labelp: Option<&mut *mut c_char>,
                                            fpp: Option<&mut *mut Fingerprint>)
                                            -> *mut Binding {
    let iter = ffi_param_ref_mut!(iter);
    match iter.next() {
        Some((label, fp, binding)) => {
            if labelp.is_some() {
                *labelp.unwrap() = ffi_return_maybe_string!(label);
            }

            if fpp.is_some() {
                *fpp.unwrap() = box_raw!(fp);
            }

            box_raw!(binding)
        },
        None => ptr::null_mut(),
    }
}

/// Frees a sq_binding_iter_t.
#[::ffi_catch_abort] #[no_mangle]
pub extern "system" fn sq_binding_iter_free(iter: Option<&mut BindingIter>) {
    ffi_free!(iter)
}

/// Lists all log entries related to this store.
#[::ffi_catch_abort] #[no_mangle]
pub extern "system" fn sq_store_log(ctx: *mut Context,
                                    store: *const Store)
                                    -> *mut LogIter {
    let ctx = ffi_param_ref_mut!(ctx);
    ffi_make_fry_from_ctx!(ctx);
    let store = ffi_param_ref!(store);

    ffi_try_box!(store.log())
}

/// Frees a sq_binding_t.
#[::ffi_catch_abort] #[no_mangle]
pub extern "system" fn sq_binding_free(binding: Option<&mut Binding>) {
    ffi_free!(binding)
}

/// Frees a sq_key_t.
#[::ffi_catch_abort] #[no_mangle]
pub extern "system" fn sq_key_free(key: Option<&mut Key>) {
    ffi_free!(key)
}

/// Frees a sq_log_t.
#[::ffi_catch_abort] #[no_mangle]
pub extern "system" fn sq_log_free(log: Option<&mut Log>) {
    if let Some(log) = log {
        let log = unsafe { Box::from_raw(log) };
        if ! log.store.is_null() {
            ffi_param_move!(log.store);
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
#[::ffi_catch_abort] #[no_mangle]
pub extern "system" fn sq_binding_stats(ctx: *mut Context,
                                        binding: *const Binding)
                                        -> *mut Stats {
    let ctx = ffi_param_ref_mut!(ctx);
    ffi_make_fry_from_ctx!(ctx);
    let binding = ffi_param_ref!(binding);

    box_raw!(Stats::new(ffi_try!(binding.stats())))
}

/// Returns the `sq_key_t` of this binding.
#[::ffi_catch_abort] #[no_mangle]
pub extern "system" fn sq_binding_key(ctx: *mut Context,
                                      binding: *const Binding)
                                     -> *mut Key {
    let ctx = ffi_param_ref_mut!(ctx);
    ffi_make_fry_from_ctx!(ctx);
    let binding = ffi_param_ref!(binding);

    ffi_try_box!(binding.key())
}

/// Returns the `pgp_tpk_t` of this binding.
#[::ffi_catch_abort] #[no_mangle]
pub extern "system" fn sq_binding_tpk(ctx: *mut Context,
                                      binding: *const Binding)
                                     -> *mut TPK {
    let ctx = ffi_param_ref_mut!(ctx);
    ffi_make_fry_from_ctx!(ctx);
    let binding = ffi_param_ref!(binding);

    ffi_try_box!(binding.tpk())
}

/// Updates this binding with the given TPK.
///
/// If the new key `tpk` matches the current key, i.e. they have
/// the same fingerprint, both keys are merged and normalized.
/// The returned key contains all packets known to Sequoia, and
/// should be used instead of `tpk`.
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
#[::ffi_catch_abort] #[no_mangle]
pub extern "system" fn sq_binding_import(ctx: *mut Context,
                                         binding: *const Binding,
                                         tpk: *const TPK)
                                         -> *mut TPK {
    let ctx = ffi_param_ref_mut!(ctx);
    ffi_make_fry_from_ctx!(ctx);
    let binding = ffi_param_ref!(binding);
    let tpk = ffi_param_ref!(tpk);

    ffi_try_box!(binding.import(&tpk))
}


/// Forces a keyrotation to the given TPK.
///
/// The current key is replaced with the new key `tpk`, even if
/// they do not have the same fingerprint.  If a key with the same
/// fingerprint as `tpk` is already in the store, is merged with
/// `tpk` and normalized.  The returned key contains all packets
/// known to Sequoia, and should be used instead of `tpk`.
///
/// Use this function to resolve conflicts returned from
/// `sq_binding_import`.  Make sure that you have authenticated
/// `tpk` properly.  How to do that depends on your thread model.
/// You could simply ask Alice to call her communication partner
/// Bob and confirm that he rotated his keys.
#[::ffi_catch_abort] #[no_mangle]
pub extern "system" fn sq_binding_rotate(ctx: *mut Context,
                                         binding: *const Binding,
                                         tpk: *const TPK)
                                         -> *mut TPK {
    let ctx = ffi_param_ref_mut!(ctx);
    ffi_make_fry_from_ctx!(ctx);
    let binding = ffi_param_ref!(binding);
    let tpk = ffi_param_ref!(tpk);

    ffi_try_box!(binding.rotate(&tpk))
}

/// Deletes this binding.
///
/// Consumes `binding`.  Returns != 0 on error.
#[::ffi_catch_abort] #[no_mangle]
pub extern "system" fn sq_binding_delete(ctx: *mut Context,
                                         binding: *mut Binding)
                                         -> Status {
    let ctx = ffi_param_ref_mut!(ctx);
    ffi_make_fry_from_ctx!(ctx);
    let binding = ffi_param_move!(binding);

    ffi_try_status!(binding.delete())
}

/// Lists all log entries related to this binding.
#[::ffi_catch_abort] #[no_mangle]
pub extern "system" fn sq_binding_log(ctx: *mut Context,
                                      binding: *const Binding)
                                      -> *mut LogIter {
    let ctx = ffi_param_ref_mut!(ctx);
    ffi_make_fry_from_ctx!(ctx);
    let binding = ffi_param_ref!(binding);

    ffi_try_box!(binding.log())
}

/// Returns the `sq_stats_t` of this key.
#[::ffi_catch_abort] #[no_mangle]
pub extern "system" fn sq_key_stats(ctx: *mut Context,
                                    key: *const Key)
                                    -> *mut Stats {
    let ctx = ffi_param_ref_mut!(ctx);
    ffi_make_fry_from_ctx!(ctx);
    let key = ffi_param_ref!(key);

    box_raw!(Stats::new(ffi_try!(key.stats())))
}

/// Returns the `pgp_tpk_t`.
#[::ffi_catch_abort] #[no_mangle]
pub extern "system" fn sq_key_tpk(ctx: *mut Context,
                                  key: *const Key)
                                  -> *mut TPK {
    let ctx = ffi_param_ref_mut!(ctx);
    ffi_make_fry_from_ctx!(ctx);
    let key = ffi_param_ref!(key);

    ffi_try_box!(key.tpk())
}

/// Updates this stored key with the given TPK.
///
/// If the new key `tpk` matches the current key, i.e. they have
/// the same fingerprint, both keys are merged and normalized.
/// The returned key contains all packets known to Sequoia, and
/// should be used instead of `tpk`.
///
/// If the new key does not match the current key,
/// `Error::Conflict` is returned.
#[::ffi_catch_abort] #[no_mangle]
pub extern "system" fn sq_key_import(ctx: *mut Context,
                                     key: *const Key,
                                     tpk: *const TPK)
                                     -> *mut TPK {
    let ctx = ffi_param_ref_mut!(ctx);
    ffi_make_fry_from_ctx!(ctx);
    let key = ffi_param_ref!(key);
    let tpk = ffi_param_ref!(tpk);

    ffi_try_box!(key.import(&tpk))
}

/// Lists all log entries related to this key.
#[::ffi_catch_abort] #[no_mangle]
pub extern "system" fn sq_key_log(ctx: *mut Context,
                                  key: *const Key)
                                  -> *mut LogIter {
    let ctx = ffi_param_ref_mut!(ctx);
    ffi_make_fry_from_ctx!(ctx);
    let key = ffi_param_ref!(key);

    ffi_try_box!(key.log())
}

/// Frees a sq_stats_t.
#[::ffi_catch_abort] #[no_mangle]
pub extern "system" fn sq_stats_free(stats: Option<&mut Stats>) {
    ffi_free!(stats)
}

/// Counter and timestamps.
#[repr(C)]
pub struct Stamps {
    /// Counts how many times this has been used.
    pub count: uint64_t,

    /// Records the time when this has been used first.
    pub first:  uint64_t,

    /// Records the time when this has been used last.
    pub last: uint64_t,
}

impl Stamps {
    fn new(s: &sequoia_store::Stamps) -> Stamps {
        Stamps{
            count: s.count as uint64_t,
            first: s.first.map(|t| t.sec).unwrap_or(0)
                as uint64_t,
            last: s.last.map(|t| t.sec).unwrap_or(0)
                as uint64_t,
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
    pub created: uint64_t,

    /// Records the time this item was last updated.
    pub updated: uint64_t,

    /// Records counters and timestamps of encryptions.
    pub encryption: Stamps,

    /// Records counters and timestamps of verifications.
    pub verification: Stamps,
}

impl Stats {
    fn new(s: sequoia_store::Stats) -> Stats {
        Stats {
            created: s.created.map(|t| t.sec).unwrap_or(0) as uint64_t,
            updated: s.updated.map(|t| t.sec).unwrap_or(0) as uint64_t,
            encryption: Stamps::new(&s.encryption),
            verification: Stamps::new(&s.verification),
        }
    }
}

/// Represents a log entry.
#[repr(C)]
pub struct Log {
    /// Records the time of the entry.
    pub timestamp: uint64_t,

    /// Relates the entry to a store.
    ///
    /// May be `NULL`.
    pub store: *mut Store,

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
