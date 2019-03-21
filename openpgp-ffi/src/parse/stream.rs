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
use std::slice;
use std::io as std_io;
use std::io::Read;
use libc::{c_int, size_t, c_void};
use failure::ResultExt;

extern crate sequoia_openpgp as openpgp;
extern crate time;

use self::openpgp::{
    RevocationStatus,
    packet::{
        PKESK,
        SKESK,
    },
};
use self::openpgp::parse::stream::{
    DecryptionHelper,
    Decryptor,
    Secret,
    VerificationHelper,
    VerificationResult,
    Verifier,
    DetachedVerifier,
};

use Maybe;
use MoveFromRaw;
use MoveIntoRaw;
use MoveResultIntoRaw;
use RefMutRaw;

use super::super::{
    error::Status,
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

// Secret.

/// Creates an pgp_secret_t from a decrypted session key.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle] pub extern "system"
fn pgp_secret_cached<'a>(algo: u8,
                         session_key: *const u8,
                         session_key_len: size_t)
   -> *mut Secret
{
    let session_key = if session_key_len > 0 {
        unsafe {
            slice::from_raw_parts(session_key, session_key_len)
        }
    } else {
        &[]
    };

    box_raw!(Secret::Cached {
        algo: algo.into(),
        session_key: session_key.to_vec().into()
    })
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
    results: Vec<Vec<&'a VerificationResult>>,
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
                                         r: *mut *const &'a VerificationResult,
                                         r_count: *mut size_t) {
    let results = ffi_param_ref!(results);
    let r = ffi_param_ref_mut!(r);
    let r_count = ffi_param_ref_mut!(r_count);

    assert!(level < results.results.len());

    // The size of VerificationResult is not known in C.  Convert from
    // an array of VerificationResult to an array of
    // VerificationResult refs.
    *r = results.results[level].as_ptr();
    *r_count = results.results[level].len();
}

/// Returns the verification result code.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle] pub extern "system"
fn pgp_verification_result_code(result: *const VerificationResult)
    -> c_int
{
    let result = ffi_param_ref!(result);
    match result {
        VerificationResult::GoodChecksum(_) => 1,
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
        VerificationResult::GoodChecksum(ref sig) => sig,
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

/// Returns a session key.
type GetSecretKeysCallback = fn(*mut HelperCookie,
                                *const &PKESK, usize,
                                *const &SKESK, usize,
                                &mut *mut Secret) -> Status;

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

fn verify_real<'a>(input: &'a mut Read,
                   dsig: Option<&mut io::ReaderKind>,
                   output: Option<&mut Box<::std::io::Write>>,
                   get_public_keys: GetPublicKeysCallback,
                   check_signatures: CheckSignaturesCallback,
                   cookie: *mut HelperCookie)
    -> Result<(), failure::Error>
{
    let h = VHelper::new(get_public_keys, check_signatures, cookie);
    let mut v = if let Some(dsig) = dsig {
        DetachedVerifier::from_reader(dsig, input, h)?
    } else {
        Verifier::from_reader(input, h)?
    };

    let r = if let Some(output) = output {
        std_io::copy(&mut v, output)
    } else {
        let mut buffer = vec![0u8; 64 * 1024];
        loop {
            match v.read(&mut buffer) {
                // EOF.
                Ok(0) => break Ok(0),
                // Some error.
                Err(err) => break Err(err),
                // Still something to read.
                Ok(_) => continue,
            }
        }
    };

    r.map_err(|e| if e.get_ref().is_some() {
        // Wrapped failure::Error.  Recover it.
        failure::Error::from_boxed_compat(e.into_inner().unwrap())
    } else {
        // Plain io::Error.
        ::failure::Error::from(e)
    }).context("Verification failed")?;

    Ok(())
}


/// Verifies an OpenPGP message.
///
/// No attempt is made to decrypt any encryption packets.  These are
/// treated as opaque containers.
///
/// Note: output may be NULL, if the output is not required.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle] pub extern "system"
fn pgp_verify<'a>(errp: Option<&mut *mut ::error::Error>,
                  input: *mut io::Reader,
                  dsig: Maybe<io::Reader>,
                  output: Maybe<io::Writer>,
                  get_public_keys: GetPublicKeysCallback,
                  check_signatures: CheckSignaturesCallback,
                  cookie: *mut HelperCookie)
    -> Status
{
    ffi_make_fry_from_errp!(errp);
    let input = input.ref_mut_raw();

    let r = verify_real(input, dsig.ref_mut_raw(), output.ref_mut_raw(),
        get_public_keys, check_signatures, cookie);

    ffi_try_status!(r)
}


struct DHelper {
    vhelper: VHelper,
    get_secret_keys_cb: GetSecretKeysCallback,
}

impl DHelper {
    fn new(get_public_keys: GetPublicKeysCallback,
           get_secret_keys: GetSecretKeysCallback,
           check_signatures: CheckSignaturesCallback,
           cookie: *mut HelperCookie)
       -> Self
    {
        DHelper {
            vhelper: VHelper::new(get_public_keys, check_signatures, cookie),
            get_secret_keys_cb: get_secret_keys,
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
    fn get_secret(&mut self, pkesks: &[&PKESK], skesks: &[&SKESK])
        -> Result<Option<Secret>, failure::Error>
    {
        let mut secret : *mut Secret = ptr::null_mut();

        let result = (self.get_secret_keys_cb)(
            self.vhelper.cookie,
            pkesks.as_ptr(), pkesks.len(), skesks.as_ptr(), skesks.len(),
            &mut secret);
        if result != Status::Success {
            // XXX: We need to convert the status to an error.  A
            // status contains less information, but we should do the
            // best we can.  For now, we just use
            // Error::InvalidArgument.
            return Err(openpgp::Error::InvalidArgument(
                format!("{:?}", result)).into());
        }

        if secret.is_null() {
            return Err(openpgp::Error::MissingSessionKey(
                "Callback did not return a session key".into()).into());
        }

        let secret = ffi_param_move!(secret);

        Ok(Some(*secret))
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
///   int get_secret_keys_called;
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
/// get_secret_keys_cb (void *cookie_opaque,
///                     pgp_pkesk_t *pkesks, size_t pkesk_count,
///                     pgp_skesk_t *skesks, size_t skesk_count,
///                     pgp_secret_t *secret)
/// {
///   pgp_error_t err;
///   struct decrypt_cookie *cookie = cookie_opaque;
///
///   /* Prevent iterations, we only have one key to offer.  */
///   if (cookie->get_secret_keys_called)
///     return PGP_STATUS_UNKNOWN_ERROR;
///   cookie->get_secret_keys_called = 1;
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
///     *secret = pgp_secret_cached (algo, session_key, session_key_len);
///     return PGP_STATUS_SUCCESS;
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
///     .get_secret_keys_called = 0,
///   };
///   plaintext = pgp_decryptor_new (NULL, source,
///                                  get_public_keys_cb, get_secret_keys_cb,
///                                  check_signatures_cb, &cookie);
///   assert (plaintext);
///
///   nread = pgp_reader_read (NULL, plaintext, buf, sizeof buf);
///   assert (nread == 13);
///   assert (memcmp (buf, "Test, 1-2-3.\n", nread) == 0);
///   assert (cookie.get_secret_keys_called);
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
                         get_secret_keys: GetSecretKeysCallback,
                         check_signatures: CheckSignaturesCallback,
                         cookie: *mut HelperCookie)
                         -> Maybe<io::Reader>
{
    let helper = DHelper::new(
        get_public_keys, get_secret_keys, check_signatures, cookie);

    Decryptor::from_reader(input.ref_mut_raw(), helper)
        .map(|r| io::ReaderKind::Generic(Box::new(r)))
        .move_into_raw(errp)
}
