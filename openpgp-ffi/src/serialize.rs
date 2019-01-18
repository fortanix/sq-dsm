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
    TPK,
    crypto::Password,
};
use self::openpgp::constants::{
    DataFormat,
};

use error::Status;

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


/// Streams an OpenPGP message.
#[::ffi_catch_abort] #[no_mangle]
pub extern "system" fn pgp_writer_stack_message
    (writer: *mut Box<Write>)
     -> *mut writer::Stack<'static, Cookie>
{
    let writer = ffi_param_move!(writer);
    box_raw!(Message::new(writer))
}

/// Writes up to `len` bytes of `buf` into `writer`.
#[::ffi_catch_abort] #[no_mangle]
pub extern "system" fn pgp_writer_stack_write
    (errp: Option<&mut *mut failure::Error>,
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
    ffi_try_or!(writer.write(buf).map_err(|e| e.into()), -1) as ssize_t
}

/// Writes up to `len` bytes of `buf` into `writer`.
///
/// Unlike pgp_writer_stack_write, unless an error occurs, the whole
/// buffer will be written.  Also, this version automatically catches
/// EINTR.
#[::ffi_catch_abort] #[no_mangle]
pub extern "system" fn pgp_writer_stack_write_all
    (errp: Option<&mut *mut failure::Error>,
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
    ffi_try_status!(writer.write_all(buf).map_err(|e| e.into()))
}

/// Finalizes this writer, returning the underlying writer.
#[::ffi_catch_abort] #[no_mangle]
pub extern "system" fn pgp_writer_stack_finalize_one
    (errp: Option<&mut *mut failure::Error>,
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
#[::ffi_catch_abort] #[no_mangle]
pub extern "system" fn pgp_writer_stack_finalize
    (errp: Option<&mut *mut failure::Error>,
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
#[::ffi_catch_abort] #[no_mangle]
pub extern "system" fn pgp_arbitrary_writer_new
    (errp: Option<&mut *mut failure::Error>,
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
#[::ffi_catch_abort] #[no_mangle]
pub extern "system" fn pgp_signer_new
    (errp: Option<&mut *mut failure::Error>,
     inner: *mut writer::Stack<'static, Cookie>,
     signers: *const *mut Box<self::openpgp::crypto::Signer>,
     signers_len: size_t)
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
    ffi_try_box!(Signer::new(*inner, signers))
}

/// Creates a signer for a detached signature.
#[::ffi_catch_abort] #[no_mangle]
pub extern "system" fn pgp_signer_new_detached
    (errp: Option<&mut *mut failure::Error>,
     inner: *mut writer::Stack<'static, Cookie>,
     signers: *const *mut Box<self::openpgp::crypto::Signer>,
     signers_len: size_t)
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
    ffi_try_box!(Signer::detached(*inner, signers))
}

/// Writes a literal data packet.
///
/// The body will be written using partial length encoding, or, if the
/// body is short, using full length encoding.
#[::ffi_catch_abort] #[no_mangle]
pub extern "system" fn pgp_literal_writer_new
    (errp: Option<&mut *mut failure::Error>,
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
/// The stream is encrypted using AES256, regardless of any key
/// preferences.
#[::ffi_catch_abort] #[no_mangle]
pub extern "system" fn pgp_encryptor_new
    (errp: Option<&mut *mut failure::Error>,
     inner: *mut writer::Stack<'static, Cookie>,
     passwords: Option<&*const c_char>, passwords_len: size_t,
     recipients: Option<&&TPK>, recipients_len: size_t,
     encryption_mode: uint8_t)
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
    let encryption_mode = match encryption_mode {
        0 => EncryptionMode::AtRest,
        1 => EncryptionMode::ForTransport,
        _ => panic!("Bad encryption mode: {}", encryption_mode),
    };
    ffi_try_box!(Encryptor::new(*inner,
                                 &passwords_.iter().collect::<Vec<&Password>>(),
                                 &recipients,
                                 encryption_mode))
}
