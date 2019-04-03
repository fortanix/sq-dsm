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
//! [`sequoia-openpgp::parse::stream`]: ../../../sequoia_openpgp/parse/stream/index.html

use std::ptr;
use libc::{c_int, size_t, c_void, uint8_t};

extern crate sequoia_openpgp as openpgp;
extern crate time;

use self::openpgp::{
    RevocationStatus,
    crypto::SessionKey,
    constants::SymmetricAlgorithm,
    packet::{
        PKESK,
        SKESK,
    },
};
use self::openpgp::parse::stream::{
    DecryptionHelper,
    Decryptor,
    VerificationHelper,
    VerificationResult,
    Verifier,
    DetachedVerifier,
};

use Maybe;
use MoveFromRaw;
use MoveIntoRaw;
use MoveResultIntoRaw;
use RefRaw;
use RefMutRaw;

use super::super::{
    error::Status,
    crypto,
    io,
    keyid,
    packet,
    tpk::TPK,
};

fn revocation_status_to_int(rs: &RevocationStatus) -> c_int {
    match rs {
        RevocationStatus::Revoked(_) => 0,
        RevocationStatus::CouldBe(_) => 1,
        RevocationStatus::NotAsFarAsWeKnow => 2,
    }
}

/// Returns the TPK's revocation status variant.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle]
pub extern "system" fn pgp_revocation_status_variant(
    rs: *mut RevocationStatus)
    -> c_int
{
    let rs = ffi_param_move!(rs);
    let variant = revocation_status_to_int(rs.as_ref());
    Box::into_raw(rs);
    variant
}

/// Frees a pgp_revocation_status_t.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle]
pub extern "system" fn pgp_revocation_status_free(
    rs: Option<&mut RevocationStatus>)
{
    ffi_free!(rs)
}

// Decryptor.

/// A message's verification results.
///
/// Conceptually, the verification results are an array of an array of
/// VerificationResult.  The outer array is for the verification level
/// and is indexed by the verification level.  A verification level of
/// zero corresponds to direct signatures; A verification level of 1
/// corresponds to notorizations (i.e., signatures of signatures);
/// etc.
///
/// Within each level, there can be one or more signatures.
pub struct VerificationResults<'a> {
    results: Vec<Vec<&'a VerificationResult<'a>>>,
}

/// Returns the `VerificationResult`s at level `level.
///
/// Conceptually, the verification results are an array of an array of
/// VerificationResult.  The outer array is for the verification level
/// and is indexed by the verification level.  A verification level of
/// zero corresponds to direct signatures; A verification level of 1
/// corresponds to notorizations (i.e., signatures of signatures);
/// etc.
///
/// This function returns the verification results for a particular
/// level.  The result is an array of references to
/// `VerificationResult`.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle] pub extern "system"
fn pgp_verification_results_at_level<'a>(results: *const VerificationResults<'a>,
                                         level: size_t,
                                         r: *mut *const &'a VerificationResult<'a>,
                                         r_count: *mut size_t) {
    let results = ffi_param_ref!(results);
    let r = ffi_param_ref_mut!(r);
    let r_count = ffi_param_ref_mut!(r_count);

    assert!(level < results.results.len());

    // The size of VerificationResult is not known in C.  Convert from
    // an array of VerificationResult to an array of
    // VerificationResult refs.
    *r = results.results[results.results.len() - level - 1].as_ptr();
    *r_count = results.results[results.results.len() - level - 1].len();
}

/// Returns the verification result code.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle] pub extern "system"
fn pgp_verification_result_code(result: *const VerificationResult)
    -> c_int
{
    let result = ffi_param_ref!(result);
    match result {
        VerificationResult::GoodChecksum(..) => 1,
        VerificationResult::MissingKey(_) => 2,
        VerificationResult::BadChecksum(_) => 3,
    }
}

/// Returns the verification result code.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle] pub extern "system"
fn pgp_verification_result_signature(result: *const VerificationResult)
    -> *mut packet::signature::Signature
{
    let result = ffi_param_ref!(result);
    let sig = match result {
        VerificationResult::GoodChecksum(ref sig, ..) => sig,
        VerificationResult::MissingKey(ref sig) => sig,
        VerificationResult::BadChecksum(ref sig) => sig,
    };

    sig.move_into_raw()
}

/// Returns the verification result code.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle] pub extern "system"
fn pgp_verification_result_level(result: *const VerificationResult)
    -> c_int
{
    let result = ffi_param_ref!(result);
    result.level() as c_int
}


/// Passed as the first argument to the callbacks used by pgp_verify
/// and pgp_decrypt.
pub struct HelperCookie {
}

/// How to free the memory allocated by the callback.
type FreeCallback = fn(*mut c_void);

/// Returns the TPKs corresponding to the passed KeyIDs.
///
/// If the free callback is not NULL, then it is called to free the
/// returned array of TPKs.
type GetPublicKeysCallback = fn(*mut HelperCookie,
                                *const *mut keyid::KeyID, usize,
                                &mut *mut *mut TPK, *mut usize,
                                *mut FreeCallback) -> Status;

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
                          extern "system" fn (*mut c_void, uint8_t,
                                              *const crypto::SessionKey)
                                              -> Status,
                          *mut c_void,
                          *mut Maybe<super::super::fingerprint::Fingerprint>)
                          -> Status;

/// Process the signatures.
///
/// If the result is not Status::Success, then this aborts the
/// Verification.
type CheckSignaturesCallback = fn(*mut HelperCookie,
                                  *const VerificationResults,
                                  usize) -> Status;

// This fetches keys and computes the validity of the verification.
struct VHelper {
    get_public_keys_cb: GetPublicKeysCallback,
    check_signatures_cb: CheckSignaturesCallback,
    cookie: *mut HelperCookie,
}

impl VHelper {
    fn new(get_public_keys: GetPublicKeysCallback,
           check_signatures: CheckSignaturesCallback,
           cookie: *mut HelperCookie)
       -> Self
    {
        VHelper {
            get_public_keys_cb: get_public_keys,
            check_signatures_cb: check_signatures,
            cookie: cookie,
        }
    }
}

impl VerificationHelper for VHelper {
    fn get_public_keys(&mut self, ids: &[openpgp::KeyID])
        -> Result<Vec<openpgp::TPK>, failure::Error>
    {
        // The size of KeyID is not known in C.  Convert from an array
        // of KeyIDs to an array of KeyID refs.
        let ids : Vec<*mut keyid::KeyID> =
            ids.iter().map(|k| k.move_into_raw()).collect();

        let mut tpk_refs_raw : *mut *mut TPK = ptr::null_mut();
        let mut tpk_refs_raw_len = 0usize;

        let mut free : FreeCallback = |_| {};

        let result = (self.get_public_keys_cb)(
            self.cookie,
            ids.as_ptr(), ids.len(),
            &mut tpk_refs_raw, &mut tpk_refs_raw_len as *mut usize,
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

        // Convert the array of references to TPKs to a Vec<TPK>
        // (i.e., not a Vec<&TPK>).
        let mut tpks : Vec<openpgp::TPK> = Vec::with_capacity(tpk_refs_raw_len);
        for i in 0..tpk_refs_raw_len {
            let tpk_raw = unsafe { *tpk_refs_raw.offset(i as isize) };
            tpks.push(tpk_raw.move_from_raw());
        }

        (free)(tpk_refs_raw as *mut c_void);

        Ok(tpks)
    }

    fn check(&mut self, sigs: Vec<Vec<VerificationResult>>)
        -> Result<(), failure::Error>
    {
        // The size of VerificationResult is not known in C.  Convert
        // from an array of VerificationResults to an array of
        // VerificationResult refs.
        let results = VerificationResults {
            results: sigs.iter().map(
                |r| r.iter().collect::<Vec<&VerificationResult>>()).collect()
        };

        let result = (self.check_signatures_cb)(self.cookie,
                                                &results,
                                                results.results.len());
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
///   pgp_tpk_t key;
/// };
///
/// static pgp_status_t
/// get_public_keys_cb (void *cookie_opaque,
///                     pgp_keyid_t *keyids, size_t keyids_len,
///                     pgp_tpk_t **tpks, size_t *tpks_len,
///                     void (**our_free)(void *))
/// {
///   /* Feed the TPKs to the verifier here.  */
///   struct verify_cookie *cookie = cookie_opaque;
///   *tpks = malloc (sizeof (pgp_tpk_t));
///   assert (*tpks);
///   *tpks[0] = cookie->key;
///   *tpks_len = 1;
///   *our_free = free;
///   return PGP_STATUS_SUCCESS;
/// }
///
/// static pgp_status_t
/// check_signatures_cb(void *cookie_opaque,
///                    pgp_verification_results_t results, size_t levels)
/// {
///   /* Implement your verification policy here.  */
///   assert (levels == 1);
///   pgp_verification_result_t *vrs;
///   size_t vr_count;
///   pgp_verification_results_at_level (results, 0, &vrs, &vr_count);
///   assert (vr_count == 1);
///   pgp_verification_result_code_t code = pgp_verification_result_code(vrs[0]);
///   assert (code == PGP_VERIFICATION_RESULT_CODE_GOOD_CHECKSUM);
///   return PGP_STATUS_SUCCESS;
/// }
///
/// int
/// main (int argc, char **argv)
/// {
///   pgp_tpk_t tpk;
///   pgp_reader_t source;
///   pgp_reader_t plaintext;
///   uint8_t buf[128];
///   ssize_t nread;
///
///   tpk = pgp_tpk_from_file (NULL, "../openpgp/tests/data/keys/testy.pgp");
///   assert(tpk);
///
///   source = pgp_reader_from_file (
///       NULL, "../openpgp/tests/data/messages/signed-1-sha256-testy.gpg");
///   assert (source);
///
///   struct verify_cookie cookie = {
///     .key = tpk,  /* Move.  */
///   };
///   plaintext = pgp_verifier_new (NULL, source,
///                                 get_public_keys_cb, check_signatures_cb,
///                                 &cookie);
///   assert (source);
///
///   nread = pgp_reader_read (NULL, plaintext, buf, sizeof buf);
///   assert (nread >= 42);
///   assert (
///     memcmp (buf, "A Cypherpunk's Manifesto\nby Eric Hughes\n", 40) == 0);
///
///   pgp_reader_free (plaintext);
///   pgp_reader_free (source);
///   return 0;
/// }
/// ```
#[::sequoia_ffi_macros::extern_fn] #[no_mangle] pub extern "system"
fn pgp_verifier_new<'a>(errp: Option<&mut *mut ::error::Error>,
                        input: *mut io::Reader,
                        get_public_keys: GetPublicKeysCallback,
                        check_signatures: CheckSignaturesCallback,
                        cookie: *mut HelperCookie)
                        -> Maybe<io::Reader>
{
    let helper = VHelper::new(get_public_keys, check_signatures, cookie);

    Verifier::from_reader(input.ref_mut_raw(), helper)
        .map(|r| io::ReaderKind::Generic(Box::new(r)))
        .move_into_raw(errp)
}

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
///   pgp_tpk_t key;
/// };
///
/// static pgp_status_t
/// get_public_keys_cb (void *cookie_opaque,
///                     pgp_keyid_t *keyids, size_t keyids_len,
///                     pgp_tpk_t **tpks, size_t *tpks_len,
///                     void (**our_free)(void *))
/// {
///   /* Feed the TPKs to the verifier here.  */
///   struct verify_cookie *cookie = cookie_opaque;
///   *tpks = malloc (sizeof (pgp_tpk_t));
///   assert (*tpks);
///   *tpks[0] = cookie->key;
///   *tpks_len = 1;
///   *our_free = free;
///   return PGP_STATUS_SUCCESS;
/// }
///
/// static pgp_status_t
/// check_signatures_cb(void *cookie_opaque,
///                    pgp_verification_results_t results, size_t levels)
/// {
///   /* Implement your verification policy here.  */
///   assert (levels == 1);
///   pgp_verification_result_t *vrs;
///   size_t vr_count;
///   pgp_verification_results_at_level (results, 0, &vrs, &vr_count);
///   assert (vr_count == 1);
///   pgp_verification_result_code_t code = pgp_verification_result_code(vrs[0]);
///   assert (code == PGP_VERIFICATION_RESULT_CODE_GOOD_CHECKSUM);
///   return PGP_STATUS_SUCCESS;
/// }
///
/// int
/// main (int argc, char **argv)
/// {
///   pgp_tpk_t tpk;
///   pgp_reader_t signature;
///   pgp_reader_t source;
///   pgp_reader_t plaintext;
///   uint8_t buf[128];
///   ssize_t nread;
///
///   tpk = pgp_tpk_from_file (NULL,
///     "../openpgp/tests/data/keys/emmelie-dorothea-dina-samantha-awina-ed25519.pgp");
///   assert(tpk);
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
///     .key = tpk,  /* Move.  */
///   };
///   plaintext = pgp_detached_verifier_new (NULL, signature, source,
///     get_public_keys_cb, check_signatures_cb,
///     &cookie);
///   assert (source);
///
///   nread = pgp_reader_read (NULL, plaintext, buf, sizeof buf);
///   assert (nread >= 42);
///   assert (
///     memcmp (buf, "A Cypherpunk's Manifesto\nby Eric Hughes\n", 40) == 0);
///
///   pgp_reader_free (plaintext);
///   pgp_reader_free (source);
///   pgp_reader_free (signature);
///   return 0;
/// }
/// ```
#[::sequoia_ffi_macros::extern_fn] #[no_mangle] pub extern "system"
fn pgp_detached_verifier_new<'a>(errp: Option<&mut *mut ::error::Error>,
                                 signature_input: *mut io::Reader,
                                 input: *mut io::Reader,
                                 get_public_keys: GetPublicKeysCallback,
                                 check_signatures: CheckSignaturesCallback,
                                 cookie: *mut HelperCookie)
                                 -> Maybe<io::Reader>
{
    let helper = VHelper::new(get_public_keys, check_signatures, cookie);

    DetachedVerifier::from_reader(signature_input.ref_mut_raw(),
                                  input.ref_mut_raw(), helper)
        .map(|r| io::ReaderKind::Generic(Box::new(r)))
        .move_into_raw(errp)
}


struct DHelper {
    vhelper: VHelper,
    decrypt_cb: DecryptCallback,
}

impl DHelper {
    fn new(get_public_keys: GetPublicKeysCallback,
           decrypt: DecryptCallback,
           check_signatures: CheckSignaturesCallback,
           cookie: *mut HelperCookie)
       -> Self
    {
        DHelper {
            vhelper: VHelper::new(get_public_keys, check_signatures, cookie),
            decrypt_cb: decrypt,
        }
    }
}

impl VerificationHelper for DHelper {
    fn get_public_keys(&mut self, ids: &[openpgp::KeyID])
        -> Result<Vec<openpgp::TPK>, failure::Error>
    {
        self.vhelper.get_public_keys(ids)
    }

    fn check(&mut self, sigs: Vec<Vec<VerificationResult>>)
        -> Result<(), failure::Error>
    {
        self.vhelper.check(sigs)
    }
}

impl DecryptionHelper for DHelper {
    fn decrypt<D>(&mut self, pkesks: &[PKESK], skesks: &[SKESK],
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

        extern "system" fn trampoline<D>(data: *mut c_void, algo: uint8_t,
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
///   pgp_tpk_t key;
///   int decrypt_called;
/// };
///
/// static pgp_status_t
/// get_public_keys_cb (void *cookie_raw,
///                     pgp_keyid_t *keyids, size_t keyids_len,
///                     pgp_tpk_t **tpks, size_t *tpk_len,
///                     void (**our_free)(void *))
/// {
///   /* Feed the TPKs to the verifier here.  */
///   *tpks = NULL;
///   *tpk_len = 0;
///   *our_free = free;
///   return PGP_STATUS_SUCCESS;
/// }
///
/// static pgp_status_t
/// check_signatures_cb(void *cookie_opaque,
///                     pgp_verification_results_t results, size_t levels)
/// {
///   /* Implement your verification policy here.  */
///   return PGP_STATUS_SUCCESS;
/// }
///
/// static pgp_status_t
/// decrypt_cb (void *cookie_opaque,
///             pgp_pkesk_t *pkesks, size_t pkesk_count,
///             pgp_skesk_t *skesks, size_t skesk_count,
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
///     pgp_tpk_key_iter_t key_iter = pgp_tpk_key_iter_all (cookie->key);
///     pgp_key_t key;
///     while ((key = pgp_tpk_key_iter_next (key_iter, NULL, NULL))) {
///       pgp_keyid_t this_keyid = pgp_key_keyid (key);
///       int match = pgp_keyid_equal (this_keyid, keyid);
///       pgp_keyid_free (this_keyid);
///       if (match)
///         break;
///       pgp_key_free (key);
///     }
///     pgp_tpk_key_iter_free (key_iter);
///     pgp_keyid_free (keyid);
///     if (! key)
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
///
///     pgp_session_key_t sk = pgp_session_key_from_bytes (session_key,
///                                                        session_key_len);
///     rc = decrypt (decrypt_cookie, algo, sk);
///     pgp_session_key_free (sk);
///
///     *identity_out = pgp_tpk_fingerprint (cookie->key);
///     return rc;
///   }
///
///   return PGP_STATUS_UNKNOWN_ERROR;
/// }
///
/// int
/// main (int argc, char **argv)
/// {
///   pgp_tpk_t tpk;
///   pgp_reader_t source;
///   pgp_reader_t plaintext;
///   uint8_t buf[128];
///   ssize_t nread;
///
///   tpk = pgp_tpk_from_file (
///       NULL, "../openpgp/tests/data/keys/testy-private.pgp");
///   assert(tpk);
///
///   source = pgp_reader_from_file (
///       NULL, "../openpgp/tests/data/messages/encrypted-to-testy.gpg");
///   assert (source);
///
///   struct decrypt_cookie cookie = {
///     .key = tpk,
///     .decrypt_called = 0,
///   };
///   plaintext = pgp_decryptor_new (NULL, source,
///                                  get_public_keys_cb, decrypt_cb,
///                                  check_signatures_cb, &cookie);
///   assert (plaintext);
///
///   nread = pgp_reader_read (NULL, plaintext, buf, sizeof buf);
///   assert (nread == 13);
///   assert (memcmp (buf, "Test, 1-2-3.\n", nread) == 0);
///   assert (cookie.decrypt_called);
///
///   pgp_reader_free (plaintext);
///   pgp_reader_free (source);
///   pgp_tpk_free (tpk);
///   return 0;
/// }
/// ```
#[::sequoia_ffi_macros::extern_fn] #[no_mangle] pub extern "system"
fn pgp_decryptor_new<'a>(errp: Option<&mut *mut ::error::Error>,
                         input: *mut io::Reader,
                         get_public_keys: GetPublicKeysCallback,
                         decrypt: DecryptCallback,
                         check_signatures: CheckSignaturesCallback,
                         cookie: *mut HelperCookie)
                         -> Maybe<io::Reader>
{
    let helper = DHelper::new(
        get_public_keys, decrypt, check_signatures, cookie);

    Decryptor::from_reader(input.ref_mut_raw(), helper)
        .map(|r| io::ReaderKind::Generic(Box::new(r)))
        .move_into_raw(errp)
}
