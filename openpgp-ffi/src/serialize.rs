//! OpenPGP packet serializer.
//!
//! Wraps the streaming packet serialization, see
//! [`sequoia-openpgp::serialize::stream`].
//!
//! [`sequoia-openpgp::serialize::stream`]: ../../sequoia_openpgp/serialize/stream/index.html

use std::ptr;
use std::slice;
use std::io::Write;
use libc::{uint8_t, c_char, size_t, ssize_t};

extern crate sequoia_openpgp as openpgp;
extern crate time;

use self::openpgp::{
    crypto::Password,
};
use self::openpgp::constants::{
    DataFormat,
    HashAlgorithm,
    SymmetricAlgorithm,
};

use error::Status;
use MoveFromRaw;
use RefRaw;

use self::openpgp::serialize::{
    writer,
    stream::{
        Message,
        Cookie,
        ArbitraryWriter,
        Signer,
        LiteralWriter,
        EncryptionMode,
        Encryptor,
    },
};

use super::tpk::TPK;

/// Streams an OpenPGP message.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle]
pub extern "C" fn pgp_writer_stack_message
    (writer: *mut super::io::Writer)
     -> *mut writer::Stack<'static, Cookie>
{
    box_raw!(Message::new(writer.move_from_raw()))
}

/// Writes up to `len` bytes of `buf` into `writer`.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle]
pub extern "C" fn pgp_writer_stack_write
    (errp: Option<&mut *mut ::error::Error>,
     writer: *mut writer::Stack<'static, Cookie>,
     buf: *const uint8_t, len: size_t)
     -> ssize_t
{
    ffi_make_fry_from_errp!(errp);
    let writer = ffi_param_ref_mut!(writer);
    assert!(!buf.is_null());
    let buf = unsafe {
        slice::from_raw_parts(buf, len as usize)
    };
    ffi_try_or!(writer.write(buf).map_err(|e| ::failure::Error::from(e)), -1) as ssize_t
}

/// Writes up to `len` bytes of `buf` into `writer`.
///
/// Unlike pgp_writer_stack_write, unless an error occurs, the whole
/// buffer will be written.  Also, this version automatically catches
/// EINTR.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle]
pub extern "C" fn pgp_writer_stack_write_all
    (errp: Option<&mut *mut ::error::Error>,
     writer: *mut writer::Stack<'static, Cookie>,
     buf: *const uint8_t, len: size_t)
     -> Status
{
    ffi_make_fry_from_errp!(errp);
    let writer = ffi_param_ref_mut!(writer);
    assert!(!buf.is_null());
    let buf = unsafe {
        slice::from_raw_parts(buf, len as usize)
    };
    ffi_try_status!(writer.write_all(buf).map_err(|e| ::failure::Error::from(e)))
}

/// Finalizes this writer, returning the underlying writer.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle]
pub extern "C" fn pgp_writer_stack_finalize_one
    (errp: Option<&mut *mut ::error::Error>,
     writer: *mut writer::Stack<'static, Cookie>)
     -> *mut writer::Stack<'static, Cookie>
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
    (errp: Option<&mut *mut ::error::Error>,
     writer: *mut writer::Stack<'static, Cookie>)
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
    (errp: Option<&mut *mut ::error::Error>,
     inner: *mut writer::Stack<'static, Cookie>,
     tag: uint8_t)
     -> *mut writer::Stack<'static, Cookie>
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
/// The hash is performed using the algorithm specificed in
/// `hash_algo`.  Pass 0 for the default (which is what you usually
/// want).
#[::sequoia_ffi_macros::extern_fn] #[no_mangle]
pub extern "C" fn pgp_signer_new
    (errp: Option<&mut *mut ::error::Error>,
     inner: *mut writer::Stack<'static, Cookie>,
     signers: *const *mut Box<self::openpgp::crypto::Signer>,
     signers_len: size_t,
     hash_algo: uint8_t)
     -> *mut writer::Stack<'static, Cookie>
{
    ffi_make_fry_from_errp!(errp);
    let inner = ffi_param_move!(inner);
    let signers = ffi_param_ref!(signers);
    let signers = unsafe {
        slice::from_raw_parts(signers, signers_len)
    };
    let signers = signers.into_iter().map(
        |s| -> &mut dyn self::openpgp::crypto::Signer {
            let signer = *s;
            ffi_param_ref_mut!(signer).as_mut()
        }
    ).collect();
    let hash_algo : Option<HashAlgorithm> = if hash_algo == 0 {
        None
    } else {
        Some(hash_algo.into())
    };
    ffi_try_box!(Signer::new(*inner, signers, hash_algo))
}

/// Creates a signer for a detached signature.
///
/// See `pgp_signer_new` for details.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle]
pub extern "C" fn pgp_signer_new_detached
    (errp: Option<&mut *mut ::error::Error>,
     inner: *mut writer::Stack<'static, Cookie>,
     signers: *const *mut Box<self::openpgp::crypto::Signer>,
     signers_len: size_t,
     hash_algo: uint8_t)
     -> *mut writer::Stack<'static, Cookie>
{
    ffi_make_fry_from_errp!(errp);
    let inner = ffi_param_move!(inner);
    let signers = ffi_param_ref!(signers);
    let signers = unsafe {
        slice::from_raw_parts(signers, signers_len)
    };
    let signers = signers.into_iter().map(
        |s| -> &mut dyn self::openpgp::crypto::Signer {
            let signer = *s;
            ffi_param_ref_mut!(signer).as_mut()
        }
    ).collect();
    let hash_algo : Option<HashAlgorithm> = if hash_algo == 0 {
        None
    } else {
        Some(hash_algo.into())
    };
    ffi_try_box!(Signer::detached(*inner, signers, hash_algo))
}

/// Writes a literal data packet.
///
/// The body will be written using partial length encoding, or, if the
/// body is short, using full length encoding.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle]
pub extern "C" fn pgp_literal_writer_new
    (errp: Option<&mut *mut ::error::Error>,
     inner: *mut writer::Stack<'static, Cookie>)
     -> *mut writer::Stack<'static, Cookie>
{
    ffi_make_fry_from_errp!(errp);
    let inner = ffi_param_move!(inner);
    ffi_try_box!(LiteralWriter::new(*inner,
                                     DataFormat::Binary,
                                     None,
                                     None))
}

/// Creates a new encryptor.
///
/// The stream will be encrypted using a generated session key,
/// which will be encrypted using the given passwords, and all
/// encryption-capable subkeys of the given TPKs.
///
/// The stream is encrypted using `cipher_algo`.  Pass 0 for the
/// default (which is what you usually want).
#[::sequoia_ffi_macros::extern_fn] #[no_mangle]
pub extern "C" fn pgp_encryptor_new
    (errp: Option<&mut *mut ::error::Error>,
     inner: *mut writer::Stack<'static, Cookie>,
     passwords: Option<&*const c_char>, passwords_len: size_t,
     recipients: Option<&*const TPK>, recipients_len: size_t,
     encryption_mode: uint8_t,
     cipher_algo: uint8_t)
     -> *mut writer::Stack<'static, Cookie>
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
                            .to_bytes().to_owned().into());
        }
    }
    let recipients = if recipients_len > 0 {
        let recipients = recipients.expect("Recipients is NULL");
        unsafe {
            slice::from_raw_parts(recipients, recipients_len)
        }
    } else {
        &[]
    };
    let recipients : Vec<&::sequoia_openpgp::TPK>
        = recipients.into_iter().map(|&tpk| tpk.ref_raw()).collect();
    let encryption_mode = match encryption_mode {
        0 => EncryptionMode::AtRest,
        1 => EncryptionMode::ForTransport,
        _ => panic!("Bad encryption mode: {}", encryption_mode),
    };
    let cipher_algo : Option<SymmetricAlgorithm> = if cipher_algo == 0 {
        None
    } else {
        Some(cipher_algo.into())
    };
    ffi_try_box!(Encryptor::new(*inner,
                                &passwords_.iter().collect::<Vec<&Password>>(),
                                &recipients[..],
                                encryption_mode,
                                cipher_algo))
}
