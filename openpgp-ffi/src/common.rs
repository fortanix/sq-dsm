// Common code for sequoia-openpgp-ffi and sequoia-ffi.

use std::collections::hash_map::{DefaultHasher, RandomState};
use std::hash::BuildHasher;

/* Canonical free().  */

/// Transfers ownership from C to Rust, then frees the object.
///
/// NOP if called with NULL.
macro_rules! ffi_free {
    ($name:ident) => {{
        if let Some(ptr) = $name {
            unsafe {
                drop(Box::from_raw(ptr))
            }
        }
    }};
}

/* Parameter handling.  */

/// Transfers ownership from C to Rust.
///
/// # Panics
///
/// Panics if called with NULL.
macro_rules! ffi_param_move {
    ($name:expr) => {{
        if $name.is_null() {
            panic!("Parameter {} is NULL", stringify!($name));
        }
        unsafe {
            Box::from_raw($name)
        }
    }};
}

/// Transfers a reference from C to Rust.
///
/// # Panics
///
/// Panics if called with NULL.
macro_rules! ffi_param_ref {
    ($name:ident) => {{
        if $name.is_null() {
            panic!("Parameter {} is NULL", stringify!($name));
        }
        unsafe {
            &*$name
        }
    }};
}

/// Transfers a mutable reference from C to Rust.
///
/// # Panics
///
/// Panics if called with NULL.
macro_rules! ffi_param_ref_mut {
    ($name:ident) => {{
        if $name.is_null() {
            panic!("Parameter {} is NULL", stringify!($name));
        }
        unsafe {
            &mut *$name
        }
    }};
}

/// Transfers a reference to a string from C to Rust.
///
/// # Panics
///
/// Panics if called with NULL.
macro_rules! ffi_param_cstr {
    ($name:expr) => {{
        if $name.is_null() {
            panic!("Parameter {} is NULL", stringify!($name));
        }
        unsafe {
            ::std::ffi::CStr::from_ptr($name)
        }
    }};
}

/* Return value handling.  */

/// Duplicates a string similar to strndup(3).
#[allow(dead_code)]
pub(crate) fn strndup(src: &[u8]) -> Option<*mut libc::c_char> {
    if src.contains(&0) {
        return None;
    }

    let l = src.len() + 1;
    let s = unsafe {
        ::std::slice::from_raw_parts_mut(libc::malloc(l) as *mut u8, l)
    };
    &mut s[..l - 1].copy_from_slice(src);
    s[l - 1] = 0;

    Some(s.as_mut_ptr() as *mut libc::c_char)
}

/// Transfers a string from Rust to C, allocating it using malloc.
///
/// # Panics
///
/// Panics if the given string contains a 0.
macro_rules! ffi_return_string {
    ($name:expr) => {{
        let string = $name;
        let bytes: &[u8] = string.as_ref();
        ::strndup(bytes).expect(
            &format!("Returned string {} contains a 0 byte.", stringify!($name))
        )
    }};
}

/// Transfers a string from Rust to C, allocating it using malloc.
///
/// # Panics
///
/// Does *NOT* panic if the given string contains a 0, but returns
/// `NULL`.
macro_rules! ffi_return_maybe_string {
    ($name:expr) => {{
        let string = $name;
        let bytes: &[u8] = string.as_ref();
        ::strndup(bytes).unwrap_or(::std::ptr::null_mut())
    }};
}

/* Error handling with implicit error return argument.  */

/// Emits local macros for error handling that use the given context
/// to store complex errors.
macro_rules! ffi_make_fry_from_errp {
    ($errp:expr) => {
        /// Like try! for ffi glue.
        ///
        /// Evaluates the given expression.  On success, evaluate to
        /// `Status.Success`.  On failure, stashes the error in the
        /// context and evaluates to the appropriate Status code.
        #[allow(unused_macros)]
        macro_rules! ffi_try_status {
            ($expr:expr) => {
                match $expr {
                    Ok(_) => ::error::Status::Success,
                    Err(e) => {
                        use MoveIntoRaw;
                        let status = ::error::Status::from(&e);
                        if let Some(errp) = $errp {
                            *errp = e.move_into_raw();
                        }
                        status
                    },
                }
            };
        }

        /// Like try! for ffi glue.
        ///
        /// Unwraps the given expression.  On failure, stashes the
        /// error in the context and returns $or.
        #[allow(unused_macros)]
        macro_rules! ffi_try_or {
            ($expr:expr, $or:expr) => {
                match $expr {
                    Ok(v) => v,
                    Err(e) => {
                        use MoveIntoRaw;
                        if let Some(errp) = $errp {
                            *errp = e.move_into_raw();
                        }
                        return $or;
                    },
                }
            };
        }

        /// Like try! for ffi glue.
        ///
        /// Unwraps the given expression.  On failure, stashes the
        /// error in the context and returns NULL.
        #[allow(unused_macros)]
        macro_rules! ffi_try {
            ($expr:expr) => {
                ffi_try_or!($expr, ::std::ptr::null_mut())
            };
        }

        /// Like try! for ffi glue, then box into raw pointer.
        ///
        /// This is used to transfer ownership from Rust to C.
        ///
        /// Unwraps the given expression.  On success, it boxes the
        /// value and turns it into a raw pointer.  On failure,
        /// stashes the error in the context and returns NULL.
        #[allow(unused_macros)]
        macro_rules! ffi_try_box {
            ($expr:expr) => {
                Box::into_raw(Box::new(ffi_try!($expr)))
            }
        }
    }
}

/// Box, then turn into raw pointer.
///
/// This is used to transfer ownership from Rust to C.
macro_rules! box_raw {
    ($expr:expr) => {
        Box::into_raw(Box::new($expr))
    }
}

/// Box an Option<T>, then turn into raw pointer.
///
/// This is used to transfer ownership from Rust to C.
macro_rules! maybe_box_raw {
    ($expr:expr) => {
        $expr.map(|x| box_raw!(x)).unwrap_or(::std::ptr::null_mut())
    }
}


/* Support for sequoia_ffi_macros::ffi_wrapper_type-based object
 * handling.  */

/// Moves an object from C to Rust, taking ownership.
pub(crate) trait MoveFromRaw<T> {
    /// Moves this object from C to Rust, taking ownership.
    fn move_from_raw(self) -> T;
}

/// Moves a reference to an object from C to Rust.
pub(crate) trait RefRaw<T> {
    /// Moves this reference to an object from C to Rust.
    fn ref_raw(self) -> &'static T;
}

/// Moves a mutable reference to an object from C to Rust.
pub(crate) trait RefMutRaw<T> {
    /// Moves this mutable reference to an object from C to Rust.
    fn ref_mut_raw(self) -> T;
}

/// Moves an object from Rust to C, releasing ownership.
pub(crate) trait MoveIntoRaw<T> {
    /// Moves this object from Rust to C, releasing ownership.
    fn move_into_raw(self) -> T;
}

/// Moves an object from Rust to C, releasing ownership.
pub(crate) trait MoveResultIntoRaw<T> {
    /// Moves this object from Rust to C, releasing ownership.
    fn move_into_raw(self, errp: Option<&mut *mut self::error::Error>) -> T;
}

/// Indicates that a pointer may be NULL.
pub type Maybe<T> = Option<::std::ptr::NonNull<T>>;

/* Hashing support.  */

/// Builds hashers for computing hashes.
///
/// This is used to derive Hasher instances for computing hashes of
/// objects so that they can be used in hash tables by foreign code.
pub(crate) fn build_hasher() -> DefaultHasher {
    lazy_static! {
        static ref RANDOM_STATE: RandomState = RandomState::new();
    }
    RANDOM_STATE.build_hasher()
}

pub mod armor;
pub mod crypto;
pub mod error;
pub mod fingerprint;
pub mod io;
pub mod keyid;
pub mod packet;
pub mod packet_pile;
pub mod parse;
pub mod serialize;
pub mod tpk;
pub mod tsk;

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

use self::tpk::TPK;
use error::Status;

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
#[::sequoia_ffi_macros::extern_fn] #[no_mangle]
pub fn pgp_secret_cached<'a>(algo: u8,
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
#[::sequoia_ffi_macros::extern_fn] #[no_mangle]
pub fn pgp_verification_results_at_level<'a>(results: *const VerificationResults<'a>,
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
#[::sequoia_ffi_macros::extern_fn] #[no_mangle]
pub fn pgp_verification_result_code(result: *const VerificationResult)
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
#[::sequoia_ffi_macros::extern_fn] #[no_mangle]
pub fn pgp_verification_result_signature(result: *const VerificationResult)
    -> *const self::openpgp::packet::Signature
{
    let result = ffi_param_ref!(result);
    let sig = match result {
        VerificationResult::GoodChecksum(ref sig) => sig,
        VerificationResult::MissingKey(ref sig) => sig,
        VerificationResult::BadChecksum(ref sig) => sig,
    };

    sig as *const self::openpgp::packet::Signature
}

/// Returns the verification result code.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle]
pub fn pgp_verification_result_level(result: *const VerificationResult)
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
        ids.into_iter().for_each(|k| { k.move_from_raw(); });

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
#[::sequoia_ffi_macros::extern_fn] #[no_mangle]
pub fn pgp_verify<'a>(errp: Option<&mut *mut ::error::Error>,
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

// A helper function that returns a Result so that we can use ? to
// propagate errors.
fn decrypt_real<'a>(input: &'a mut io::ReaderKind,
                    output: &'a mut ::std::io::Write,
                    get_public_keys: GetPublicKeysCallback,
                    get_secret_keys: GetSecretKeysCallback,
                    check_signatures: CheckSignaturesCallback,
                    cookie: *mut HelperCookie)
    -> Result<(), failure::Error>
{
    let helper = DHelper::new(
        get_public_keys, get_secret_keys, check_signatures, cookie);

    let mut decryptor = Decryptor::from_reader(input, helper)
        .context("Decryption failed")?;

    std_io::copy(&mut decryptor, output)
        .map_err(|e| if e.get_ref().is_some() {
            // Wrapped failure::Error.  Recover it.
            failure::Error::from_boxed_compat(e.into_inner().unwrap())
        } else {
            // Plain io::Error.
            ::failure::Error::from(e)
        }).context("Decryption failed")?;

    Ok(())
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
#[::sequoia_ffi_macros::extern_fn] #[no_mangle]
pub fn pgp_decrypt<'a>(errp: Option<&mut *mut ::error::Error>,
                      input: *mut io::Reader,
                      output: *mut io::Writer,
                      get_public_keys: GetPublicKeysCallback,
                      get_secret_keys: GetSecretKeysCallback,
                      check_signatures: CheckSignaturesCallback,
                      cookie: *mut HelperCookie)
    -> Status
{
    ffi_make_fry_from_errp!(errp);
    let input = input.ref_mut_raw();
    let output = output.ref_mut_raw();

    let r = decrypt_real(input, output,
        get_public_keys, get_secret_keys, check_signatures, cookie);

    ffi_try_status!(r)
}
