//! Streaming decryption and verification.
//!
//! This module provides convenient filters for decryption and
//! verification of OpenPGP messages. It is the preferred interface to
//! process OpenPGP messages. These implementations use constant
//! space.
//!
//! Wraps the streaming parsing functions, see
//! [`sequoia-openpgp::parse::stream`].
//!
//! [`sequoia-openpgp::parse::stream`]: ../../../../sequoia_openpgp/parse/stream/index.html

use std::ptr;
use libc::{c_int, c_void, time_t};

extern crate sequoia_openpgp as openpgp;

use self::openpgp::{
    cert::prelude::*,
    crypto::SessionKey,
    types::SymmetricAlgorithm,
    packet::{
        PKESK,
        SKESK,
    },
};
use self::openpgp::parse::stream::{
    self,
    DecryptionHelper,
    Decryptor,
    VerificationHelper,
    Verifier,
};

use crate::Maybe;
use crate::MoveFromRaw;
use crate::MoveIntoRaw;
use crate::MoveResultIntoRaw;
use crate::RefRaw;
use crate::RefMutRaw;
use crate::maybe_time;

use super::super::{
    error::{Error, Status},
    crypto,
    io,
    keyid,
    cert::Cert,
    packet::signature::Signature,
    packet::key::Key,
    parse::PacketParser,
    policy::Policy,
    revocation_status::RevocationStatus,
};

/// Communicates the message structure to the VerificationHelper.
#[crate::ffi_wrapper_type(prefix = "pgp_", derive = "Debug")]
pub struct MessageStructure<'a>(stream::MessageStructure<'a>);

/// Iterates over the message structure.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle] pub extern "C"
fn pgp_message_structure_iter(structure: *const MessageStructure)
                              -> *mut MessageStructureIter {
    structure.ref_raw().iter().move_into_raw()
}

/// Iterates over the message structure.
#[crate::ffi_wrapper_type(prefix = "pgp_", derive = "Iterator(MessageLayer)")]
pub struct MessageStructureIter<'a>(stream::MessageStructureIter<'a>);

/// Represents a layer of the message structure.
#[crate::ffi_wrapper_type(prefix = "pgp_", derive = "Debug")]
pub struct MessageLayer<'a>(stream::MessageLayer<'a>);

/// Returns the message layer variant.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle] pub extern "C"
fn pgp_message_layer_variant(result: *const MessageLayer)
    -> c_int
{
    use self::stream::MessageLayer::*;
    match result.ref_raw() {
        Compression { .. } => 1,
        Encryption { .. } => 2,
        SignatureGroup { .. } => 3,
    }
}

/// Decomposes a `MessageLayer::Compression`.
///
/// Returns `true` iff the given value is a
/// `MessageLayer::Compression`, and returns each of the variants
/// members if the corresponding parameter is not `NULL`.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle] pub extern "C"
fn pgp_message_layer_compression(v: *const MessageLayer,
                                 algo_r: Maybe<u8>)
                                 -> bool
{
    use self::stream::MessageLayer::*;
    if let Compression { algo } = v.ref_raw() {
        if let Some(mut p) = algo_r {
            *unsafe { p.as_mut() } = (*algo).into();
        }
        true
    } else {
        false
    }
}

/// Decomposes a `MessageLayer::Encryption`.
///
/// Returns `true` iff the given value is a
/// `MessageLayer::Encryption`, and returns each of the variants
/// members if the corresponding parameter is not `NULL`.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle] pub extern "C"
fn pgp_message_layer_encryption(v: *const MessageLayer,
                                sym_algo_r: Maybe<u8>,
                                aead_algo_r: Maybe<u8>)
                                 -> bool
{
    use self::stream::MessageLayer::*;
    if let Encryption { sym_algo, aead_algo } = v.ref_raw() {
        if let Some(mut p) = sym_algo_r {
            *unsafe { p.as_mut() } = (*sym_algo).into();
        }
        if let Some(mut p) = aead_algo_r {
            *unsafe { p.as_mut() } =
                aead_algo.map(|a| a.into()).unwrap_or(0);
        }
        true
    } else {
        false
    }
}

/// Decomposes a `MessageLayer::SignatureGroup`.
///
/// Returns `true` iff the given value is a
/// `MessageLayer::SignatureGroup`, and returns each of the variants
/// members if the corresponding parameter is not `NULL`.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle] pub extern "C"
fn pgp_message_layer_signature_group<'a>(
    v: *const MessageLayer<'a>,
    results_r: Maybe<* mut VerificationResultIter<'a>>)
    -> bool
{
    use self::stream::MessageLayer::*;
    if let SignatureGroup { results } = v.ref_raw() {
        if let Some(mut p) = results_r {
            *unsafe { p.as_mut() } = results.iter().move_into_raw();
        }
        true
    } else {
        false
    }
}

/// A message's verification results.
#[crate::ffi_wrapper_type(prefix = "pgp_", derive = "Iterator(VerificationResult)")]
pub struct VerificationResultIter<'a>(
    ::std::slice::Iter<'a, stream::VerificationResult<'a>>);

/// A message's verification results.
#[crate::ffi_wrapper_type(prefix = "pgp_", derive = "Debug")]
pub struct VerificationResult<'a>(stream::VerificationResult<'a>);

/// Returns the verification result variant.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle] pub extern "C"
fn pgp_verification_result_variant(result: *const VerificationResult)
    -> c_int
{
    use self::stream::VerificationError::*;
    match result.ref_raw() {
        Ok(_) => 0,
        Err(MalformedSignature { .. }) => 1,
        Err(MissingKey { .. }) => 2,
        Err(UnboundKey { .. }) => 3,
        Err(BadKey { .. }) => 4,
        Err(BadSignature { .. }) => 5,
    }
}

/// Decomposes a `VerificationResult::Ok(GoodChecksum)`.
///
/// Returns `true` iff the given value is a
/// `VerificationResult::Ok(GoodChecksum)`, and returns the variants
/// members in `sig_r` and the like iff `sig_r != NULL`.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle] pub extern "C"
fn pgp_verification_result_good_checksum<'a>(
    result: *const VerificationResult<'a>,
    sig_r: Maybe<*mut Signature>,
    cert_r: Maybe<*mut Cert>,
    key_r: Maybe<*mut Key>,
    binding_r: Maybe<*mut Signature>,
    revocation_status_r:
    Maybe<*mut RevocationStatus<'a>>)
    -> bool
{
    use self::stream::GoodChecksum;
    if let Ok(GoodChecksum { sig, ka }) = result.ref_raw() {
        if let Some(mut p) = sig_r {
            *unsafe { p.as_mut() } = sig.move_into_raw();
        }
        if let Some(mut p) = cert_r {
            *unsafe { p.as_mut() } = ka.cert().cert().move_into_raw();
        }
        if let Some(mut p) = key_r {
            *unsafe { p.as_mut() } = {
                let key = ka.key()
                    .parts_as_unspecified()
                    .role_as_unspecified();
                key.move_into_raw()
            };
        }
        if let Some(mut p) = binding_r {
            *unsafe { p.as_mut() } =
                ka.binding_signature().move_into_raw();
        }
        if let Some(mut p) = revocation_status_r {
            *unsafe { p.as_mut() } = ka.revoked().move_into_raw();
        }
        true
    } else {
        false
    }
}

/// Decomposes a
/// `VerificationResult::Err(VerificationError::MalformedSignature {
/// .. })`.
///
/// Returns `true` iff the given value is a
/// `VerificationResult::Err(VerificationError::MalformedSignature {
/// .. })`, and returns the variants members in `sig_r` and the like
/// iff `sig_r != NULL`.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle] pub extern "C"
fn pgp_verification_result_malformed_signature<'a>(
    result: *const VerificationResult<'a>,
    sig_r: Maybe<*mut Signature>,
    error_r: Maybe<*mut Error>)
    -> bool
{
    use self::stream::VerificationError::*;
    if let Err(MalformedSignature { sig, error }) = result.ref_raw() {
        if let Some(mut p) = sig_r {
            *unsafe { p.as_mut() } = sig.move_into_raw();
        }
        if let Some(mut p) = error_r {
            *unsafe { p.as_mut() } = error.move_into_raw();
        }
        true
    } else {
        false
    }
}

/// Decomposes a
/// `VerificationResult::Err(VerificationError::MissingKey { .. })`.
///
/// Returns `true` iff the given value is a
/// `VerificationResult::Err(VerificationError::MissingKey { .. })`,
/// and returns the variants members in `sig_r` and the like iff
/// `sig_r != NULL`.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle] pub extern "C"
fn pgp_verification_result_missing_key<'a>(
    result: *const VerificationResult<'a>,
    sig_r: Maybe<*mut Signature>)
    -> bool
{
    use self::stream::VerificationError::*;
    if let Err(MissingKey { sig }) = result.ref_raw() {
        if let Some(mut p) = sig_r {
            *unsafe { p.as_mut() } = sig.move_into_raw();
        }
        true
    } else {
        false
    }
}

/// Decomposes a
/// `VerificationResult::Err(VerificationError::UnboundKey { .. })`.
///
/// Returns `true` iff the given value is a
/// `VerificationResult::Err(VerificationError::UnboundKey { .. })`,
/// and returns the variants members in `sig_r` and the like iff
/// `sig_r != NULL`.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle] pub extern "C"
fn pgp_verification_result_unbound_key<'a>(
    result: *const VerificationResult<'a>,
    sig_r: Maybe<*mut Signature>,
    cert_r: Maybe<*mut Cert>,
    error_r: Maybe<*mut Error>)
    -> bool
{
    use self::stream::VerificationError::*;
    if let Err(UnboundKey { sig, cert, error }) = result.ref_raw() {
        if let Some(mut p) = sig_r {
            *unsafe { p.as_mut() } = sig.move_into_raw();
        }
        if let Some(mut p) = cert_r {
            *unsafe { p.as_mut() } = cert.move_into_raw();
        }
        if let Some(mut p) = error_r {
            *unsafe { p.as_mut() } = error.move_into_raw();
        }
        true
    } else {
        false
    }
}

macro_rules! make_decomposition_fn {
    ($fn_name:ident, $variant:path) => {
#[::sequoia_ffi_macros::extern_fn] #[no_mangle] pub extern "C"
fn $fn_name<'a>(
    result: *const VerificationResult<'a>,
    sig_r: Maybe<*mut Signature>,
    cert_r: Maybe<*mut Cert>,
    key_r: Maybe<*mut Key>,
    binding_r: Maybe<*mut Signature>,
    revocation_status_r:
    Maybe<*mut RevocationStatus<'a>>,
    error_r: Maybe<*mut Error>)
    -> bool
{
    use self::stream::VerificationError::*;
    if let Err($variant { sig, ka, error }) = result.ref_raw() {
        if let Some(mut p) = sig_r {
            *unsafe { p.as_mut() } = sig.move_into_raw();
        }
        if let Some(mut p) = cert_r {
            *unsafe { p.as_mut() } = ka.cert().cert().move_into_raw();
        }
        if let Some(mut p) = key_r {
            *unsafe { p.as_mut() } = {
                let key = ka.key()
                    .parts_as_unspecified()
                    .role_as_unspecified();
                key.move_into_raw()
            };
        }
        if let Some(mut p) = binding_r {
            *unsafe { p.as_mut() } =
                ka.binding_signature().move_into_raw();
        }
        if let Some(mut p) = revocation_status_r {
            *unsafe { p.as_mut() } = ka.revoked().move_into_raw();
        }
        if let Some(mut p) = error_r {
            *unsafe { p.as_mut() } = error.move_into_raw();
        }
        true
    } else {
        false
    }
}
    }
}

/// Decomposes a
/// `VerificationResult::Err(VerificationError::BadKey { .. })`.
///
/// Returns `true` iff the given value is a
/// `VerificationResult::Err(VerificationError::BadKey { .. })`,
/// and returns the variants members in `sig_r` and the like iff
/// `sig_r != NULL`.
make_decomposition_fn!(pgp_verification_result_bad_key, BadKey);

/// Decomposes a
/// `VerificationResult::Err(VerificationError::BadSignature { .. })`.
///
/// Returns `true` iff the given value is a
/// `VerificationResult::Err(VerificationError::BadSignature { .. })`,
/// and returns the variants members in `sig_r` and the like iff
/// `sig_r != NULL`.
make_decomposition_fn!(pgp_verification_result_bad_signature, BadSignature);

/// Passed as the first argument to the callbacks used by pgp_verify
/// and pgp_decrypt.
pub struct HelperCookie {
}

/// How to free the memory allocated by the callback.
type FreeCallback = fn(*mut c_void);

/// Returns the Certs corresponding to the passed KeyIDs.
///
/// If the free callback is not NULL, then it is called to free the
/// returned array of Certs.
type GetPublicKeysCallback = fn(*mut HelperCookie,
                                *const *mut keyid::KeyID, usize,
                                &mut *mut *mut Cert, *mut usize,
                                *mut FreeCallback) -> Status;

/// Inspect packets as they are decrypted.
///
/// This function is called on every packet that the decryptor
/// observes.
type InspectCallback = fn(*mut HelperCookie, *const PacketParser) -> Status;

/// Decrypts the message.
///
/// This function is called with every `PKESK` and `SKESK` found in
/// the message.  The implementation must decrypt the symmetric
/// algorithm and session key from one of the PKESK packets, the
/// SKESKs, or retrieve it from a cache, and then call the given
/// function with the symmetric algorithm and the session key.
///
/// XXX: This needlessly flattens the complex errors returned by the
/// `decrypt` function into a status.
type DecryptCallback = fn(*mut HelperCookie,
                          *const *const PKESK, usize,
                          *const *const SKESK, usize,
                          u8, // XXX SymmetricAlgorithm
                          extern "C" fn (*mut c_void, u8,
                                              *const crypto::SessionKey)
                                              -> Status,
                          *mut c_void,
                          *mut Maybe<super::super::fingerprint::Fingerprint>)
                          -> Status;

/// Process the signatures.
///
/// If the result is not Status::Success, then this aborts the
/// Verification.
type CheckCallback = fn(*mut HelperCookie,
                                  *const MessageStructure)
                                  -> Status;

// This fetches keys and computes the validity of the verification.
struct VHelper {
    inspect_cb: Option<InspectCallback>,
    get_certs_cb: GetPublicKeysCallback,
    check_signatures_cb: CheckCallback,
    cookie: *mut HelperCookie,
}

impl VHelper {
    fn new(inspect_cb: Option<InspectCallback>,
           get_certs: GetPublicKeysCallback,
           check_signatures: CheckCallback,
           cookie: *mut HelperCookie)
       -> Self
    {
        VHelper {
            inspect_cb,
            get_certs_cb: get_certs,
            check_signatures_cb: check_signatures,
            cookie,
        }
    }
}

impl VerificationHelper for VHelper {
    fn inspect(&mut self, pp: &PacketParser) -> openpgp::Result<()> {
        if let Some(cb) = self.inspect_cb {
            match cb(self.cookie, pp) {
                Status::Success => Ok(()),
                // XXX: Convert the status to an error better.
                status => Err(anyhow::anyhow!(
                    "Inspect Callback returned an error: {:?}", status).into()),
            }
        } else {
            Ok(())
        }
    }

    fn get_certs(&mut self, ids: &[openpgp::KeyHandle])
        -> Result<Vec<openpgp::Cert>, anyhow::Error>
    {
        // The size of ID is not known in C.  Convert to KeyID, and
        // move it to C.
        let ids : Vec<*mut keyid::KeyID> =
            ids.iter().map(|k| openpgp::KeyID::from(k.clone()).move_into_raw())
            .collect();

        let mut cert_refs_raw : *mut *mut Cert = ptr::null_mut();
        let mut cert_refs_raw_len = 0usize;

        let mut free : FreeCallback = |_| {};

        let result = (self.get_certs_cb)(
            self.cookie,
            ids.as_ptr(), ids.len(),
            &mut cert_refs_raw, &mut cert_refs_raw_len as *mut usize,
            &mut free);

        // Free the KeyID wrappers.
        ids.into_iter().for_each(|id| super::super::keyid::pgp_keyid_free(id));

        if result != Status::Success {
            // XXX: We need to convert the status to an error.  A
            // status contains less information, but we should do the
            // best we can.  For now, we just use
            // Error::InvalidArgument.
            return Err(openpgp::Error::InvalidArgument(
                format!("{:?}", result)).into());
        }

        // Convert the array of references to Certs to a Vec<Cert>
        // (i.e., not a Vec<&Cert>).
        let mut certs : Vec<openpgp::Cert> = Vec::with_capacity(cert_refs_raw_len);
        for i in 0..cert_refs_raw_len {
            let cert_raw = unsafe { *cert_refs_raw.offset(i as isize) };
            certs.push(cert_raw.move_from_raw());
        }

        (free)(cert_refs_raw as *mut c_void);

        Ok(certs)
    }

    fn check(&mut self, structure: stream::MessageStructure)
        -> Result<(), anyhow::Error>
    {
        let result = (self.check_signatures_cb)(self.cookie,
                                                structure.move_into_raw());
        if result != Status::Success {
            // XXX: We need to convert the status to an error.  A
            // status contains less information, but we should do the
            // best we can.  For now, we just use
            // Error::InvalidArgument.
            return Err(openpgp::Error::InvalidArgument(
                format!("{:?}", result)).into());
        }

        Ok(())
    }
}

/// Verifies an OpenPGP message.
///
/// No attempt is made to decrypt any encryption packets.  These are
/// treated as opaque containers.
///
/// # Example
///
/// ```c
/// #define _GNU_SOURCE
/// #include <assert.h>
/// #include <error.h>
/// #include <errno.h>
/// #include <stdio.h>
/// #include <stdlib.h>
/// #include <string.h>
///
/// #include <sequoia/openpgp.h>
///
/// struct verify_cookie {
///   pgp_cert_t key;
/// };
///
/// static pgp_status_t
/// get_certs_cb (void *cookie_opaque,
///                     pgp_keyid_t *keyids, size_t keyids_len,
///                     pgp_cert_t **certs, size_t *certs_len,
///                     void (**our_free)(void *))
/// {
///   /* Feed the Certs to the verifier here.  */
///   struct verify_cookie *cookie = cookie_opaque;
///   *certs = malloc (sizeof (pgp_cert_t));
///   assert (*certs);
///   *certs[0] = cookie->key;
///   *certs_len = 1;
///   *our_free = free;
///   return PGP_STATUS_SUCCESS;
/// }
///
/// static pgp_status_t
/// check_cb (void *cookie_opaque, pgp_message_structure_t structure)
/// {
///   pgp_message_structure_iter_t iter =
///     pgp_message_structure_iter (structure);
///   pgp_message_layer_t layer = pgp_message_structure_iter_next (iter);
///   assert (layer);
///   assert (pgp_message_layer_compression (layer, NULL));
///   pgp_message_layer_free (layer);
///   layer = pgp_message_structure_iter_next (iter);
///   assert (layer);
///   pgp_verification_result_iter_t results;
///   if (pgp_message_layer_signature_group (layer, &results)) {
///     pgp_verification_result_t result =
///       pgp_verification_result_iter_next (results);
///     assert (result);
///     assert (pgp_verification_result_good_checksum (result, NULL, NULL,
///                                                    NULL, NULL, NULL));
///     pgp_verification_result_free (result);
///   } else {
///     assert (! "reachable");
///   }
///   pgp_verification_result_iter_free (results);
///   pgp_message_layer_free (layer);
///   pgp_message_structure_iter_free (iter);
///   pgp_message_structure_free (structure);
///   return PGP_STATUS_SUCCESS;
/// }
///
/// int
/// main (int argc, char **argv)
/// {
///   pgp_cert_t cert;
///   pgp_reader_t source;
///   pgp_reader_t plaintext;
///   uint8_t buf[128];
///   ssize_t nread;
///   pgp_policy_t policy = pgp_standard_policy ();
///
///   cert = pgp_cert_from_file (NULL, "../openpgp/tests/data/keys/testy.pgp");
///   assert(cert);
///
///   source = pgp_reader_from_file (
///       NULL, "../openpgp/tests/data/messages/signed-1-sha256-testy.gpg");
///   assert (source);
///
///   struct verify_cookie cookie = {
///     .key = cert,  /* Move.  */
///   };
///   plaintext = pgp_verifier_new (NULL, policy, source,
///                                 get_certs_cb, check_cb, NULL,
///                                 &cookie, 1554542219);
///   assert (source);
///
///   nread = pgp_reader_read (NULL, plaintext, buf, sizeof buf);
///   assert (nread >= 42);
///   assert (
///     memcmp (buf, "A Cypherpunk's Manifesto\nby Eric Hughes\n", 40) == 0);
///
///   pgp_reader_free (plaintext);
///   pgp_reader_free (source);
///   pgp_policy_free (policy);
///   return 0;
/// }
/// ```
#[::sequoia_ffi_macros::extern_fn] #[no_mangle] pub extern "C"
fn pgp_verifier_new<'a>(errp: Option<&mut *mut crate::error::Error>,
                        policy: *const Policy,
                        input: *mut io::Reader,
                        get_certs: GetPublicKeysCallback,
                        check: CheckCallback,
                        inspect: Option<InspectCallback>,
                        cookie: *mut HelperCookie,
                        time: time_t)
                        -> Maybe<io::Reader>
{
    let policy = policy.ref_raw().as_ref();
    let helper = VHelper::new(inspect, get_certs, check, cookie);

    Verifier::from_reader(policy, input.ref_mut_raw(), helper, maybe_time(time))
        .map(|r| io::ReaderKind::Generic(Box::new(r)))
        .move_into_raw(errp)
}

/// Verifies a detached signature.
///
/// Wraps [`sequoia-openpgp::parse::stream::DetachedVerifier`].
///
///   [`sequoia-openpgp::parse::stream::DetachedVerifier`]: ../../../../sequoia_openpgp/parse/stream/struct.DetachedVerifier.html
#[crate::ffi_wrapper_type(prefix = "pgp_")]
pub struct DetachedVerifier(openpgp::parse::stream::DetachedVerifier<'static, VHelper>);

/// Verifies a detached OpenPGP signature.
///
/// # Example
///
/// ```c
/// #define _GNU_SOURCE
/// #include <assert.h>
/// #include <error.h>
/// #include <errno.h>
/// #include <stdio.h>
/// #include <stdlib.h>
/// #include <string.h>
///
/// #include <sequoia/openpgp.h>
///
/// struct verify_cookie {
///   pgp_cert_t key;
/// };
///
/// static pgp_status_t
/// get_certs_cb (void *cookie_opaque,
///                     pgp_keyid_t *keyids, size_t keyids_len,
///                     pgp_cert_t **certs, size_t *certs_len,
///                     void (**our_free)(void *))
/// {
///   /* Feed the Certs to the verifier here.  */
///   struct verify_cookie *cookie = cookie_opaque;
///   *certs = malloc (sizeof (pgp_cert_t));
///   assert (*certs);
///   *certs[0] = cookie->key;
///   *certs_len = 1;
///   *our_free = free;
///   return PGP_STATUS_SUCCESS;
/// }
///
/// static pgp_status_t
/// check_cb (void *cookie_opaque, pgp_message_structure_t structure)
/// {
///   pgp_message_structure_iter_t iter =
///     pgp_message_structure_iter (structure);
///   pgp_message_layer_t layer = pgp_message_structure_iter_next (iter);
///   assert (layer);
///   pgp_verification_result_iter_t results;
///   if (pgp_message_layer_signature_group (layer, &results)) {
///     pgp_verification_result_t result =
///       pgp_verification_result_iter_next (results);
///     assert (result);
///     assert (pgp_verification_result_good_checksum (result, NULL, NULL,
///                                                    NULL, NULL, NULL));
///     pgp_verification_result_free (result);
///   } else {
///     assert (! "reachable");
///   }
///   pgp_verification_result_iter_free (results);
///   pgp_message_layer_free (layer);
///   pgp_message_structure_iter_free (iter);
///   pgp_message_structure_free (structure);
///   return PGP_STATUS_SUCCESS;
/// }
///
/// int
/// main (int argc, char **argv)
/// {
///   pgp_status_t rc;
///   pgp_cert_t cert;
///   pgp_reader_t signature;
///   pgp_reader_t source;
///   pgp_detached_verifier_t verifier;
///   pgp_policy_t policy = pgp_standard_policy ();
///
///   cert = pgp_cert_from_file (NULL,
///     "../openpgp/tests/data/keys/emmelie-dorothea-dina-samantha-awina-ed25519.pgp");
///   assert(cert);
///
///   signature = pgp_reader_from_file (
///     NULL,
///     "../openpgp/tests/data/messages/a-cypherpunks-manifesto.txt.ed25519.sig");
///   assert (signature);
///
///   source = pgp_reader_from_file (
///     NULL, "../openpgp/tests/data/messages/a-cypherpunks-manifesto.txt");
///   assert (source);
///
///   struct verify_cookie cookie = {
///     .key = cert,  /* Move.  */
///   };
///   verifier = pgp_detached_verifier_new (NULL, policy, signature,
///     get_certs_cb, check_cb, NULL,
///     &cookie, 1554542219);
///   assert (verifier);
///
///   rc = pgp_detached_verifier_verify (NULL, verifier, source);
///   assert (rc == PGP_STATUS_SUCCESS);
///
///   pgp_detached_verifier_free (verifier);
///   pgp_reader_free (source);
///   pgp_reader_free (signature);
///   pgp_policy_free (policy);
///   return 0;
/// }
/// ```
#[::sequoia_ffi_macros::extern_fn] #[no_mangle] pub extern "C"
fn pgp_detached_verifier_new<'a>(errp: Option<&mut *mut crate::error::Error>,
                                 policy: *const Policy,
                                 signature_input: *mut io::Reader,
                                 get_certs: GetPublicKeysCallback,
                                 check: CheckCallback,
                                 inspect: Option<InspectCallback>,
                                 cookie: *mut HelperCookie,
                                 time: time_t)
                                 -> Maybe<DetachedVerifier>
{
    let policy = policy.ref_raw().as_ref();

    let helper = VHelper::new(inspect, get_certs, check, cookie);

    openpgp::parse::stream::DetachedVerifier::from_reader(
        policy, signature_input.ref_mut_raw(), helper, maybe_time(time))
        .move_into_raw(errp)
}

/// Verifies `data` using `verifier`.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle] pub extern "C"
fn pgp_detached_verifier_verify(errp: Option<&mut *mut crate::error::Error>,
                                verifier: *mut DetachedVerifier,
                                data: *mut io::Reader)
    -> Status
{
    ffi_make_fry_from_errp!(errp);
    ffi_try_or_status!(
        verifier.ref_mut_raw().verify_reader(data.ref_mut_raw()));
    Status::Success
}



struct DHelper {
    vhelper: VHelper,
    decrypt_cb: DecryptCallback,
}

impl DHelper {
    fn new(get_certs: GetPublicKeysCallback,
           decrypt: DecryptCallback,
           check: CheckCallback,
           inspect: Option<InspectCallback>,
           cookie: *mut HelperCookie)
       -> Self
    {
        DHelper {
            vhelper: VHelper::new(inspect, get_certs, check, cookie),
            decrypt_cb: decrypt,
        }
    }
}

impl VerificationHelper for DHelper {
    fn get_certs(&mut self, ids: &[openpgp::KeyHandle])
        -> Result<Vec<openpgp::Cert>, anyhow::Error>
    {
        self.vhelper.get_certs(ids)
    }

    fn check(&mut self, structure: stream::MessageStructure)
        -> Result<(), anyhow::Error>
    {
        self.vhelper.check(structure)
    }
}

impl DecryptionHelper for DHelper {
    fn decrypt<D>(&mut self, pkesks: &[PKESK], skesks: &[SKESK],
                  sym_algo: Option<SymmetricAlgorithm>,
                  mut decrypt: D)
                  -> openpgp::Result<Option<openpgp::Fingerprint>>
        where D: FnMut(SymmetricAlgorithm, &SessionKey) -> openpgp::Result<()>
    {
        let mut identity: Maybe<super::super::fingerprint::Fingerprint> = None;

        // The size of PKESK is not known in C.  Convert from an array
        // of PKESKs to an array of PKESK refs.  Likewise for SKESKs.
        //
        // XXX: .move_into_raw() once PKESK and SKESK are wrapped.
        let pkesks : Vec<*const PKESK> =
            pkesks.iter().map(|k| k as *const _).collect();
        let skesks : Vec<*const SKESK> =
            skesks.iter().map(|k| k as *const _).collect();

        // XXX: Free the wrappers once PKESK and SKESK are wrapped.
        //
        // // Free the wrappers.
        // pkesks.into_iter().for_each(|o| {
        //     super::super::packet::pkesk::pgp_pkesk_free(o) });
        // skesks.into_iter().for_each(|o| {
        //     super::super::packet::skesk::pgp_skesk_free(o) });

        extern "C" fn trampoline<D>(data: *mut c_void, algo: u8,
                                         sk: *const crypto::SessionKey)
                                         -> Status
            where D: FnMut(SymmetricAlgorithm, &SessionKey)
                           -> openpgp::Result<()>
        {
            let closure: &mut D = unsafe { &mut *(data as *mut D) };
            (*closure)(algo.into(), sk.ref_raw()).into()
        }

        let result = (self.decrypt_cb)(
            self.vhelper.cookie,
            pkesks.as_ptr(), pkesks.len(), skesks.as_ptr(), skesks.len(),
            sym_algo.map(|s| u8::from(s)).unwrap_or(0),
            trampoline::<D>,
            &mut decrypt as *mut _ as *mut c_void,
            &mut identity);
        if result != Status::Success {
            // XXX: We need to convert the status to an error.  A
            // status contains less information, but we should do the
            // best we can.  For now, we just use
            // Error::InvalidArgument.
            return Err(openpgp::Error::InvalidArgument(
                format!("{:?}", result)).into());
        }

        Ok(identity.move_from_raw())
    }
}

/// Decrypts an OpenPGP message.
///
/// The message is read from `input` and the content of the
/// `LiteralData` packet is written to output.  Note: the content is
/// written even if the message is not encrypted.  You can determine
/// whether the message was actually decrypted by recording whether
/// the get_secret_keys callback was called in the cookie.
///
/// The function takes three callbacks.  The `cookie` is passed as the
/// first parameter to each of them.
///
/// Note: all of the parameters are required; none may be NULL.
///
/// # Example
///
/// ```c
/// #define _GNU_SOURCE
/// #include <assert.h>
/// #include <error.h>
/// #include <errno.h>
/// #include <stdio.h>
/// #include <stdlib.h>
/// #include <string.h>
///
/// #include <sequoia/openpgp.h>
///
/// struct decrypt_cookie {
///   pgp_cert_t key;
///   int decrypt_called;
/// };
///
/// static pgp_status_t
/// get_certs_cb (void *cookie_raw,
///                     pgp_keyid_t *keyids, size_t keyids_len,
///                     pgp_cert_t **certs, size_t *cert_len,
///                     void (**our_free)(void *))
/// {
///   /* Feed the Certs to the verifier here.  */
///   *certs = NULL;
///   *cert_len = 0;
///   *our_free = free;
///   return PGP_STATUS_SUCCESS;
/// }
///
/// static pgp_status_t
/// check_cb (void *cookie_opaque, pgp_message_structure_t structure)
/// {
///   pgp_message_structure_iter_t iter =
///     pgp_message_structure_iter (structure);
///   pgp_message_layer_t layer = pgp_message_structure_iter_next (iter);
///   assert (layer);
///   assert (pgp_message_layer_encryption (layer, NULL, NULL));
///   pgp_message_layer_free (layer);
///   pgp_message_structure_iter_free (iter);
///   pgp_message_structure_free (structure);
///   return PGP_STATUS_SUCCESS;
/// }
///
/// static pgp_status_t
/// decrypt_cb (void *cookie_opaque,
///             pgp_pkesk_t *pkesks, size_t pkesk_count,
///             pgp_skesk_t *skesks, size_t skesk_count,
///             uint8_t sym_algo_hint,
///             pgp_decryptor_do_decrypt_cb_t *decrypt,
///             void *decrypt_cookie,
///             pgp_fingerprint_t *identity_out)
/// {
///   pgp_status_t rc;
///   pgp_error_t err;
///   struct decrypt_cookie *cookie = cookie_opaque;
///
///   assert (! cookie->decrypt_called);
///   cookie->decrypt_called = 1;
///
///   for (int i = 0; i < pkesk_count; i++) {
///     pgp_pkesk_t pkesk = pkesks[i];
///     pgp_keyid_t keyid = pgp_pkesk_recipient (pkesk);
///
///     pgp_cert_key_iter_t key_iter = pgp_cert_key_iter (cookie->key);
///     pgp_key_amalgamation_t ka;
///     pgp_key_t key = NULL;
///     while ((ka = pgp_cert_key_iter_next (key_iter))) {
///       key = pgp_key_amalgamation_key (ka);
///       pgp_keyid_t this_keyid = pgp_key_keyid (key);
///       int match = pgp_keyid_equal (this_keyid, keyid);
///       pgp_keyid_free (this_keyid);
///       if (match)
///         break;
///       pgp_key_free (key);
///       pgp_key_amalgamation_free (ka);
///     }
///     pgp_cert_key_iter_free (key_iter);
///     pgp_keyid_free (keyid);
///     if (! ka)
///       continue;
///
///     uint8_t algo;
///     uint8_t session_key[1024];
///     size_t session_key_len = sizeof session_key;
///     if (pgp_pkesk_decrypt (&err,
///                            pkesk, key, &algo,
///                            session_key, &session_key_len)) {
///       error (1, 0, "pgp_pkesk_decrypt: %s", pgp_error_to_string (err));
///     }
///     pgp_key_free (key);
///     pgp_key_amalgamation_free (ka);
///
///     pgp_session_key_t sk = pgp_session_key_from_bytes (session_key,
///                                                        session_key_len);
///     rc = decrypt (decrypt_cookie, algo, sk);
///     pgp_session_key_free (sk);
///
///     *identity_out = pgp_cert_fingerprint (cookie->key);
///     return rc;
///   }
///
///   return PGP_STATUS_UNKNOWN_ERROR;
/// }
///
/// int
/// main (int argc, char **argv)
/// {
///   pgp_cert_t cert;
///   pgp_reader_t source;
///   pgp_reader_t plaintext;
///   uint8_t buf[128];
///   ssize_t nread;
///   pgp_policy_t policy = pgp_standard_policy ();
///
///   cert = pgp_cert_from_file (
///       NULL, "../openpgp/tests/data/keys/testy-private.pgp");
///   assert(cert);
///
///   source = pgp_reader_from_file (
///       NULL, "../openpgp/tests/data/messages/encrypted-to-testy.gpg");
///   assert (source);
///
///   struct decrypt_cookie cookie = {
///     .key = cert,
///     .decrypt_called = 0,
///   };
///   plaintext = pgp_decryptor_new (NULL, policy, source,
///                                  get_certs_cb, decrypt_cb,
///                                  check_cb, NULL, &cookie, 1554542219);
///   assert (plaintext);
///
///   nread = pgp_reader_read (NULL, plaintext, buf, sizeof buf);
///   assert (nread == 13);
///   assert (memcmp (buf, "Test, 1-2-3.\n", nread) == 0);
///   assert (cookie.decrypt_called);
///
///   pgp_reader_free (plaintext);
///   pgp_reader_free (source);
///   pgp_cert_free (cert);
///   pgp_policy_free (policy);
///   return 0;
/// }
/// ```
#[::sequoia_ffi_macros::extern_fn] #[no_mangle] pub extern "C"
fn pgp_decryptor_new<'a>(errp: Option<&mut *mut crate::error::Error>,
                         policy: *const Policy,
                         input: *mut io::Reader,
                         get_certs: GetPublicKeysCallback,
                         decrypt: DecryptCallback,
                         check: CheckCallback,
                         inspect: Option<InspectCallback>,
                         cookie: *mut HelperCookie,
                         time: time_t)
                         -> Maybe<io::Reader>
{
    let policy = policy.ref_raw().as_ref();
    let helper = DHelper::new(
        get_certs, decrypt, check, inspect, cookie);

    Decryptor::from_reader(policy, input.ref_mut_raw(), helper, maybe_time(time))
        .map(|r| io::ReaderKind::Generic(Box::new(r)))
        .move_into_raw(errp)
}
