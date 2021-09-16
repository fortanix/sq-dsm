//! OpenPGP packet serializer.
//!
//! Wraps the streaming packet serialization, see
//! [`sequoia-openpgp::serialize::stream`].
//!
//! [`sequoia-openpgp::serialize::stream`]: sequoia_openpgp::serialize::stream

use std::ptr;
use std::slice;
use std::io::Write;
use libc::{c_char, size_t, ssize_t};

use sequoia_openpgp as openpgp;

use self::openpgp::types::{
    SymmetricAlgorithm,
};

use crate::error::Status;
use crate::MoveFromRaw;
use crate::MoveIntoRaw;
use crate::RefRaw;
use crate::RefMutRaw;

use self::openpgp::serialize::{
    stream::{
        Message,
        ArbitraryWriter,
        Signer,
        LiteralWriter,
        Encryptor,
    },
};

use super::keyid::KeyID;
use super::packet::key::Key;
use super::cert::KeyAmalgamationIterWrapper;
use super::cert::ValidKeyAmalgamationIterWrapper;

/// Streams an OpenPGP message.
///
/// The returned `Message` does not take ownership of the
/// `Writer`; the caller must free it after destroying the
/// `Message`.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle]
pub extern "C" fn pgp_writer_stack_message
    (writer: *mut super::io::Writer)
     -> *mut Message<'static>
{
    box_raw!(Message::new(writer.ref_mut_raw()))
}

/// Writes up to `len` bytes of `buf` into `writer`.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle]
pub extern "C" fn pgp_writer_stack_write
    (errp: Option<&mut *mut crate::error::Error>,
     writer: *mut Message<'static>,
     buf: *const u8, len: size_t)
     -> ssize_t
{
    ffi_make_fry_from_errp!(errp);
    let writer = ffi_param_ref_mut!(writer);
    assert!(!buf.is_null());
    let buf = unsafe {
        slice::from_raw_parts(buf, len as usize)
    };
    ffi_try_or!(writer.write(buf).map_err(::anyhow::Error::from), -1) as ssize_t
}

/// Writes up to `len` bytes of `buf` into `writer`.
///
/// Unlike pgp_writer_stack_write, unless an error occurs, the whole
/// buffer will be written.  Also, this version automatically catches
/// EINTR.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle]
pub extern "C" fn pgp_writer_stack_write_all
    (errp: Option<&mut *mut crate::error::Error>,
     writer: *mut Message<'static>,
     buf: *const u8, len: size_t)
     -> Status
{
    ffi_make_fry_from_errp!(errp);
    let writer = ffi_param_ref_mut!(writer);
    assert!(!buf.is_null());
    let buf = unsafe {
        slice::from_raw_parts(buf, len as usize)
    };
    ffi_try_status!(writer.write_all(buf).map_err(::anyhow::Error::from))
}

/// Finalizes this writer, returning the underlying writer.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle]
pub extern "C" fn pgp_writer_stack_finalize_one
    (errp: Option<&mut *mut crate::error::Error>,
     writer: *mut Message<'static>)
     -> *mut Message<'static>
{
    ffi_make_fry_from_errp!(errp);
    if !writer.is_null() {
        let writer = ffi_param_move!(writer);
        maybe_box_raw!(ffi_try!(writer.finalize_one()))
    } else {
        ptr::null_mut()
    }
}

/// Finalizes all writers, tearing down the whole stack.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle]
pub extern "C" fn pgp_writer_stack_finalize
    (errp: Option<&mut *mut crate::error::Error>,
     writer: *mut Message<'static>)
     -> Status
{
    ffi_make_fry_from_errp!(errp);
    if !writer.is_null() {
        let writer = ffi_param_move!(writer);
        ffi_try_status!(writer.finalize())
    } else {
        Status::Success
    }
}

/// Writes an arbitrary packet.
///
/// This writer can be used to construct arbitrary OpenPGP packets.
/// The body will be written using partial length encoding, or, if the
/// body is short, using full length encoding.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle]
pub extern "C" fn pgp_arbitrary_writer_new
    (errp: Option<&mut *mut crate::error::Error>,
     inner: *mut Message<'static>,
     tag: u8)
     -> *mut Message<'static>
{
    ffi_make_fry_from_errp!(errp);
    let inner = ffi_param_move!(inner);
    ffi_try_box!(ArbitraryWriter::new(*inner, tag.into()))
}

/// Signs a packet stream.
///
/// For every signing key, a signer writes a one-pass-signature
/// packet, then hashes and emits the data stream, then for every key
/// writes a signature packet.
///
/// The signers are consumed.
///
/// The hash is performed using the algorithm specified in
/// `hash_algo`.  Pass 0 for the default (which is what you usually
/// want).
#[::sequoia_ffi_macros::extern_fn] #[no_mangle]
pub extern "C" fn pgp_signer_new
    (errp: Option<&mut *mut crate::error::Error>,
     inner: *mut Message<'static>,
     signers: *const *mut Box<dyn self::openpgp::crypto::Signer + Send + Sync>,
     signers_len: size_t,
     hash_algo: u8)
     -> *mut Message<'static>
{
    ffi_make_fry_from_errp!(errp);
    let inner = ffi_param_move!(inner);
    let signers = ffi_param_ref!(signers);
    let signers = unsafe {
        slice::from_raw_parts(signers, signers_len)
    };
    let mut signers = signers.iter().map(|s| {
        *ffi_param_move!(*s)
    }).collect::<Vec<_>>();

    let mut signer =
        Signer::new(*inner, ffi_try!(signers.pop().ok_or_else(|| {
            anyhow::anyhow!("signers is empty")
        })));
    for s in signers {
        signer = signer.add_signer(s);
    }

    if hash_algo != 0 {
        signer = ffi_try!(signer.hash_algo(hash_algo.into()));
    }

    ffi_try_box!(signer.build())
}

/// Creates a signer for a detached signature.
///
/// See `pgp_signer_new` for details.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle]
pub extern "C" fn pgp_signer_new_detached
    (errp: Option<&mut *mut crate::error::Error>,
     inner: *mut Message<'static>,
     signers: *const *mut Box<dyn self::openpgp::crypto::Signer + Send + Sync>,
     signers_len: size_t,
     hash_algo: u8)
     -> *mut Message<'static>
{
    ffi_make_fry_from_errp!(errp);
    let inner = ffi_param_move!(inner);
    let signers = ffi_param_ref!(signers);
    let signers = unsafe {
        slice::from_raw_parts(signers, signers_len)
    };
    let mut signers = signers.iter().map(|s| {
        *ffi_param_move!(*s)
    }).collect::<Vec<_>>();

    let mut signer =
        Signer::new(*inner, ffi_try!(signers.pop().ok_or_else(|| {
            anyhow::anyhow!("signers is empty")
        })));
    for s in signers {
        signer = signer.add_signer(s);
    }

    if hash_algo != 0 {
        signer = ffi_try!(signer.hash_algo(hash_algo.into()));
    }

    ffi_try_box!(signer.detached().build())
}

/// Writes a literal data packet.
///
/// The body will be written using partial length encoding, or, if the
/// body is short, using full length encoding.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle]
pub extern "C" fn pgp_literal_writer_new
    (errp: Option<&mut *mut crate::error::Error>,
     inner: *mut Message<'static>)
     -> *mut Message<'static>
{
    ffi_make_fry_from_errp!(errp);
    let inner = ffi_param_move!(inner);
    ffi_try_box!(LiteralWriter::new(*inner).build())
}

/// A recipient of an encrypted message.
///
/// Wraps [`sequoia-openpgp::serialize::stream::Recipient`].
///
/// [`sequoia-openpgp::serialize::stream::Recipient`]: sequoia_openpgp::serialize::stream::Recipient
#[crate::ffi_wrapper_type(prefix = "pgp_", derive = "Debug")]
pub struct Recipient<'a>(openpgp::serialize::stream::Recipient<'a>);

/// Creates a new recipient with an explicit recipient keyid.
///
/// Consumes `keyid`, references `key`.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle] pub extern "C"
fn pgp_recipient_new<'a>(keyid: *mut KeyID,
                         key: *const Key)
                         -> *mut Recipient<'a>
{
    openpgp::serialize::stream::Recipient::new(
        keyid.move_from_raw(),
        key.ref_raw(),
    ).move_into_raw()
}

/// Gets the KeyID.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle] pub extern "C"
fn pgp_recipient_keyid(recipient: *const Recipient) -> *mut KeyID {
    recipient.ref_raw().keyid().clone().move_into_raw()
}

/// Sets the KeyID.
///
/// Consumes `keyid`.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle] pub extern "C"
fn pgp_recipient_set_keyid(recipient: *mut *mut Recipient, keyid: *mut KeyID) {
    assert!(! recipient.is_null());
    unsafe {
        *recipient =
            (*recipient).move_from_raw()
            .set_keyid(keyid.move_from_raw())
            .move_into_raw();
    }
}

/// Collects recipients from a `pgp_cert_key_iter_t`.
///
/// Consumes the iterator.  The returned buffer must be freed using
/// libc's allocator.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle] pub extern "C"
fn pgp_recipients_from_key_iter<'a>(
    iter_wrapper: *mut KeyAmalgamationIterWrapper<'a>,
    result_len: *mut size_t)
    -> *mut *mut Recipient<'a>
{
    let mut iter_wrapper = ffi_param_move!(iter_wrapper);
    let result_len = ffi_param_ref_mut!(result_len);
    let recipients =
        iter_wrapper.iter
        .take().unwrap()
        .map(|ka| ka.key().into())
        .collect::<Vec<openpgp::serialize::stream::Recipient>>();

    let result = unsafe {
        libc::calloc(recipients.len(), std::mem::size_of::<* mut Recipient>())
            as *mut *mut Recipient
    };
    let r = unsafe {
        slice::from_raw_parts_mut(result,
                                  recipients.len())
    };
    *result_len = recipients.len();
    r.iter_mut().zip(recipients.into_iter())
        .for_each(|(r, recipient)| *r = recipient.move_into_raw());
    result
}

/// Collects recipients from a `pgp_cert_valid_key_iter_t`.
///
/// Consumes the iterator.  The returned buffer must be freed using
/// libc's allocator.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle] pub extern "C"
fn pgp_recipients_from_valid_key_iter<'a>(
    iter_wrapper: *mut ValidKeyAmalgamationIterWrapper<'a>,
    result_len: *mut size_t)
    -> *mut *mut Recipient<'a>
{
    let mut iter_wrapper = ffi_param_move!(iter_wrapper);
    let result_len = ffi_param_ref_mut!(result_len);
    let recipients =
        iter_wrapper.iter
        .take().unwrap()
        .map(|ka| ka.key().into())
        .collect::<Vec<openpgp::serialize::stream::Recipient>>();

    let result = unsafe {
        libc::calloc(recipients.len(), std::mem::size_of::<* mut Recipient>())
            as *mut *mut Recipient
    };
    let r = unsafe {
        slice::from_raw_parts_mut(result,
                                  recipients.len())
    };
    *result_len = recipients.len();
    r.iter_mut().zip(recipients.into_iter())
        .for_each(|(r, recipient)| *r = recipient.move_into_raw());
    result
}


/// Creates a new encryptor.
///
/// The stream will be encrypted using a generated session key,
/// which will be encrypted using the given passwords, and all
/// encryption-capable subkeys of the given Certs.
///
/// The recipients are consumed.
///
/// The stream is encrypted using `cipher_algo`.  Pass 0 for the
/// default (which is what you usually want).
#[::sequoia_ffi_macros::extern_fn] #[no_mangle]
pub extern "C" fn pgp_encryptor_new<'a>
    (errp: Option<&mut *mut crate::error::Error>,
     inner: *mut Message<'a>,
     passwords: Option<&*const c_char>, passwords_len: size_t,
     recipients: Option<&*mut Recipient<'a>>, recipients_len: size_t,
     cipher_algo: u8)
     -> *mut Message<'a>
{
    ffi_make_fry_from_errp!(errp);
    let inner = ffi_param_move!(inner);
    let mut passwords_ = Vec::new();
    if passwords_len > 0 {
        let passwords = passwords.expect("Passwords is NULL");
        let passwords = unsafe {
            slice::from_raw_parts(passwords, passwords_len)
        };
        for password in passwords {
            passwords_.push(ffi_param_cstr!(*password)
                            .to_bytes().to_owned());
        }
    }
    let mut recipients_ = Vec::new();
    if recipients_len > 0 {
        let recipients = recipients.expect("Recipients is NULL");
        let recipients = unsafe {
            slice::from_raw_parts(recipients, recipients_len)
        };
        for recipient in recipients {
            recipients_.push(recipient.move_from_raw());
        }
    };
    let cipher_algo : Option<SymmetricAlgorithm> = if cipher_algo == 0 {
        None
    } else {
        Some(cipher_algo.into())
    };
    if passwords_.len() + recipients_.len() == 0 {
        ffi_try!(Err(anyhow::anyhow!(
            "Neither recipient nor password given")));
    }

    let mut encryptor = Encryptor::for_recipients(*inner, recipients_)
        .add_passwords(passwords_);
    if let Some(algo) = cipher_algo {
        encryptor = encryptor.symmetric_algo(algo);
    }
    ffi_try_box!(encryptor.build())
}
