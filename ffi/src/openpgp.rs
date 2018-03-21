//! XXX

use std::ffi::{CString, CStr};
use std::hash::{Hash, Hasher};
use std::ptr;
use std::slice;
use std::io::{Read, Write};
use libc::{uint8_t, uint64_t, c_char, c_int, size_t};

extern crate openpgp;

use self::openpgp::TPK;
use self::openpgp::{armor, Fingerprint, KeyID, Message};

use super::build_hasher;
use super::error::Status;
use super::core::Context;

/* sequoia::openpgp::KeyID.  */

/// Reads a binary key ID.
#[no_mangle]
pub extern "system" fn sq_keyid_from_bytes(id: *const uint8_t) -> *mut KeyID {
    assert!(!id.is_null());
    let id = unsafe { slice::from_raw_parts(id, 8) };
    Box::into_raw(Box::new(KeyID::from_bytes(id)))
}

/// Reads a hex-encoded Key ID.
#[no_mangle]
pub extern "system" fn sq_keyid_from_hex(id: *const c_char) -> *mut KeyID {
    assert!(!id.is_null());
    let id = unsafe { CStr::from_ptr(id).to_string_lossy() };
    KeyID::from_hex(&id)
        .map(|id| Box::into_raw(Box::new(id)))
        .unwrap_or(ptr::null_mut())
}

/// Frees an `KeyID` object.
#[no_mangle]
pub extern "system" fn sq_keyid_free(keyid: *mut KeyID) {
    if keyid.is_null() { return }
    unsafe {
        drop(Box::from_raw(keyid));
    }
}

/// Clones the KeyID.
#[no_mangle]
pub extern "system" fn sq_keyid_clone(id: Option<&KeyID>)
                                      -> *mut KeyID {
    let id = id.expect("KeyID is NULL");
    box_raw!(id.clone())
}

/// Hashes the KeyID.
#[no_mangle]
pub extern "system" fn sq_keyid_hash(id: Option<&KeyID>)
                                     -> uint64_t {
    let id = id.expect("KeyID is NULL");
    let mut hasher = build_hasher();
    id.hash(&mut hasher);
    hasher.finish()
}

/// Converts the KeyID to its standard representation.
#[no_mangle]
pub extern "system" fn sq_keyid_to_string(id: Option<&KeyID>)
                                          -> *mut c_char {
    let id = id.expect("KeyID is NULL");
    CString::new(id.to_string())
        .unwrap() // Errors only on internal nul bytes.
        .into_raw()
}

/// Converts the KeyID to a hexadecimal number.
#[no_mangle]
pub extern "system" fn sq_keyid_to_hex(id: Option<&KeyID>)
                                       -> *mut c_char {
    let id = id.expect("KeyID is NULL");
    CString::new(id.to_hex())
        .unwrap() // Errors only on internal nul bytes.
        .into_raw()
}

/// Compares KeyIDs.
#[no_mangle]
pub extern "system" fn sq_keyid_equal(a: Option<&KeyID>,
                                      b: Option<&KeyID>)
                                      -> bool {
    let a = a.expect("KeyID 'a' is NULL");
    let b = b.expect("KeyID 'b' is NULL");
    a == b
}


/* sequoia::openpgp::Fingerprint.  */

/// Reads a binary fingerprint.
#[no_mangle]
pub extern "system" fn sq_fingerprint_from_bytes(buf: *const uint8_t,
                                                 len: size_t)
                                                 -> *mut Fingerprint {
    assert!(!buf.is_null());
    let buf = unsafe {
        slice::from_raw_parts(buf, len as usize)
    };
    Box::into_raw(Box::new(Fingerprint::from_bytes(buf)))
}

/// Reads a hexadecimal fingerprint.
#[no_mangle]
pub extern "system" fn sq_fingerprint_from_hex(hex: *const c_char)
                                               -> *mut Fingerprint {
    assert!(!hex.is_null());
    let hex = unsafe { CStr::from_ptr(hex).to_string_lossy() };
    Fingerprint::from_hex(&hex)
        .map(|fp| Box::into_raw(Box::new(fp)))
        .unwrap_or(ptr::null_mut())
}

/// Frees a sq_fingerprint_t.
#[no_mangle]
pub extern "system" fn sq_fingerprint_free(fp: *mut Fingerprint) {
    if fp.is_null() { return }
    unsafe {
        drop(Box::from_raw(fp));
    }
}

/// Clones the Fingerprint.
#[no_mangle]
pub extern "system" fn sq_fingerprint_clone(fp: Option<&Fingerprint>)
                                            -> *mut Fingerprint {
    let fp = fp.expect("Fingerprint is NULL");
    box_raw!(fp.clone())
}

/// Hashes the Fingerprint.
#[no_mangle]
pub extern "system" fn sq_fingerprint_hash(fp: Option<&Fingerprint>)
                                           -> uint64_t {
    let fp = fp.expect("Fingerprint is NULL");
    let mut hasher = build_hasher();
    fp.hash(&mut hasher);
    hasher.finish()
}

/// Converts the fingerprint to its standard representation.
#[no_mangle]
pub extern "system" fn sq_fingerprint_to_string(fp: Option<&Fingerprint>)
                                                -> *mut c_char {
    let fp = fp.expect("Fingerprint is NULL");
    CString::new(fp.to_string())
        .unwrap() // Errors only on internal nul bytes.
        .into_raw()
}

/// Converts the fingerprint to a hexadecimal number.
#[no_mangle]
pub extern "system" fn sq_fingerprint_to_hex(fp: Option<&Fingerprint>)
                                             -> *mut c_char {
    let fp = fp.expect("Fingerprint is NULL");
    CString::new(fp.to_hex())
        .unwrap() // Errors only on internal nul bytes.
        .into_raw()
}

/// Converts the fingerprint to a key ID.
#[no_mangle]
pub extern "system" fn sq_fingerprint_to_keyid(fp: Option<&Fingerprint>)
                                               -> *mut KeyID {
    let fp = fp.expect("Fingerprint is NULL");
    Box::into_raw(Box::new(fp.to_keyid()))
}

/// Compares Fingerprints.
#[no_mangle]
pub extern "system" fn sq_fingerprint_equal(a: Option<&Fingerprint>,
                                            b: Option<&Fingerprint>)
                                            -> bool {
    let a = a.expect("Fingerprint 'a' is NULL");
    let b = b.expect("Fingerprint 'b' is NULL");
    a == b
}


/* openpgp::armor.  */

fn int_to_kind(kind: c_int) -> armor::Kind {
    match kind {
        0 => armor::Kind::Message,
        1 => armor::Kind::PublicKey,
        2 => armor::Kind::PrivateKey,
        3 => armor::Kind::SecretKey,
        4 => armor::Kind::Signature,
        5 => armor::Kind::File,
        6 => armor::Kind::Any,
        _ => panic!("Bad kind: {}", kind),
    }
}

/// Constructs a new filter for the given type of data.
///
/// A filter that strips ASCII Armor from a stream of data.
#[no_mangle]
pub extern "system" fn sq_armor_reader_new(inner: Option<&'static mut Box<Read>>,
                                           kind: c_int)
                                           -> *mut Box<Read> {
    let inner = inner.expect("Inner is NULL");
    let kind = int_to_kind(kind);

    box_raw!(Box::new(armor::Reader::new(inner, kind)))
}

/// Constructs a new filter for the given type of data.
///
/// A filter that applies ASCII Armor to the data written to it.
#[no_mangle]
pub extern "system" fn sq_armor_writer_new(inner: Option<&'static mut Box<Write>>,
                                           kind: c_int)
                                           -> *mut Box<Write> {
    let inner = inner.expect("Inner is NULL");
    let kind = int_to_kind(kind);

    box_raw!(Box::new(armor::Writer::new(inner, kind)))
}


/* openpgp::Message.  */

/// Deserializes the OpenPGP message stored in a `std::io::Read`
/// object.
///
/// Although this method is easier to use to parse an OpenPGP
/// message than a `PacketParser` or a `MessageParser`, this
/// interface buffers the whole message in memory.  Thus, the
/// caller must be certain that the *deserialized* message is not
/// too large.
///
/// Note: this interface *does* buffer the contents of packets.
#[no_mangle]
pub extern "system" fn sq_message_from_reader(ctx: Option<&mut Context>,
                                              reader: Option<&mut Box<Read>>)
                                              -> *mut Message {
    let ctx = ctx.expect("Context is NULL");
    let reader = reader.expect("Reader is NULL");
    fry_box!(ctx, Message::from_reader(reader))
}

/// Deserializes the OpenPGP message stored in the file named by
/// `filename`.
///
/// See `sq_message_from_reader` for more details and caveats.
#[no_mangle]
pub extern "system" fn sq_message_from_file(ctx: Option<&mut Context>,
                                            filename: *const c_char)
                                            -> *mut Message {
    let ctx = ctx.expect("Context is NULL");
    assert!(! filename.is_null());
    let filename = unsafe {
        CStr::from_ptr(filename).to_string_lossy().into_owned()
    };
    fry_box!(ctx, Message::from_file(&filename))
}

/// Deserializes the OpenPGP message stored in the provided buffer.
///
/// See `sq_message_from_reader` for more details and caveats.
#[no_mangle]
pub extern "system" fn sq_message_from_bytes(ctx: Option<&mut Context>,
                                             b: *const uint8_t, len: size_t)
                                             -> *mut Message {
    let ctx = ctx.expect("Context is NULL");
    assert!(!b.is_null());
    let buf = unsafe {
        slice::from_raw_parts(b, len as usize)
    };

    fry_box!(ctx, Message::from_bytes(buf))
}

/// Frees the message.
#[no_mangle]
pub extern "system" fn sq_message_free(message: *mut Message) {
    if message.is_null() {
        return
    }
    unsafe {
        drop(Box::from_raw(message));
    }
}

/// Clones the Message.
#[no_mangle]
pub extern "system" fn sq_message_clone(message: Option<&Message>)
                                        -> *mut Message {
    let message = message.expect("Message is NULL");
    box_raw!(message.clone())
}

/// Serializes the message.
#[no_mangle]
pub extern "system" fn sq_message_serialize(ctx: Option<&mut Context>,
                                            message: Option<&Message>,
                                            writer: Option<&mut Box<Write>>)
                                            -> Status {
    let ctx = ctx.expect("Context is NULL");
    let message = message.expect("Message is NULL");
    let writer = writer.expect("Writer is NULL");
    fry_status!(ctx, message.serialize(writer))
}


/* sequoia::keys.  */

/// Returns the first TPK encountered in the reader.
#[no_mangle]
pub extern "system" fn sq_tpk_from_reader(ctx: Option<&mut Context>,
                                          reader: Option<&mut Box<Read>>)
                                          -> *mut TPK {
    let ctx = ctx.expect("Context is NULL");
    let reader = reader.expect("Reader is NULL");
    fry_box!(ctx, TPK::from_reader(reader))
}

/// Returns the first TPK encountered in the file.
#[no_mangle]
pub extern "system" fn sq_tpk_from_file(ctx: Option<&mut Context>,
                                        filename: *const c_char)
                                        -> *mut TPK {
    let ctx = ctx.expect("Context is NULL");
    assert!(! filename.is_null());
    let filename = unsafe {
        CStr::from_ptr(filename).to_string_lossy().into_owned()
    };
    fry_box!(ctx, TPK::from_file(&filename))
}

/// Returns the first TPK found in `m`.
///
/// Consumes `m`.
#[no_mangle]
pub extern "system" fn sq_tpk_from_message(ctx: Option<&mut Context>,
                                           m: *mut Message)
                                           -> *mut TPK {
    let ctx = ctx.expect("Context is NULL");
    assert!(! m.is_null());
    let m = unsafe { Box::from_raw(m) };
    fry_box!(ctx, TPK::from_message(*m))
}

/// Returns the first TPK found in `buf`.
///
/// `buf` must be an OpenPGP encoded message.
#[no_mangle]
pub extern "system" fn sq_tpk_from_bytes(ctx: Option<&mut Context>,
                                         b: *const uint8_t, len: size_t)
                                         -> *mut TPK {
    let ctx = ctx.expect("Context is NULL");
    assert!(!b.is_null());
    let buf = unsafe {
        slice::from_raw_parts(b, len as usize)
    };

    fry_box!(ctx, TPK::from_bytes(buf))
}

/// Frees the TPK.
#[no_mangle]
pub extern "system" fn sq_tpk_free(tpk: *mut TPK) {
    if tpk.is_null() {
        return
    }
    unsafe {
        drop(Box::from_raw(tpk));
    }
}

/// Clones the TPK.
#[no_mangle]
pub extern "system" fn sq_tpk_clone(tpk: Option<&TPK>)
                                    -> *mut TPK {
    let tpk = tpk.expect("TPK is NULL");
    box_raw!(tpk.clone())
}

/// Compares TPKs.
#[no_mangle]
pub extern "system" fn sq_tpk_equal(a: Option<&TPK>,
                                    b: Option<&TPK>)
                                    -> bool {
    let a = a.expect("TPK 'a' is NULL");
    let b = b.expect("TPK 'b' is NULL");
    a == b
}

/// Serializes the TPK.
#[no_mangle]
pub extern "system" fn sq_tpk_serialize(ctx: Option<&mut Context>,
                                        tpk: Option<&TPK>,
                                        writer: Option<&mut Box<Write>>)
                                        -> Status {
    let ctx = ctx.expect("Context is NULL");
    let tpk = tpk.expect("TPK is NULL");
    let writer = writer.expect("Writer is NULL");
    fry_status!(ctx, tpk.serialize(writer))
}

/// Merges `other` into `tpk`.
///
/// If `other` is a different key, then nothing is merged into
/// `tpk`, but `tpk` is still canonicalized.
///
/// Consumes `tpk` and `other`.
#[no_mangle]
pub extern "system" fn sq_tpk_merge(ctx: Option<&mut Context>,
                                    tpk: *mut TPK,
                                    other: *mut TPK)
                                    -> *mut TPK {
    let ctx = ctx.expect("Context is NULL");
    assert!(! tpk.is_null());
    let tpk = unsafe { Box::from_raw(tpk) };
    assert!(! other.is_null());
    let other = unsafe { Box::from_raw(other) };
    fry_box!(ctx, tpk.merge(*other))
}

/// Dumps the TPK.
///
/// XXX Remove this.
#[no_mangle]
pub extern "system" fn sq_tpk_dump(tpk: Option<&TPK>) {
    let tpk = tpk.expect("TPK is NULL");
    println!("{:?}", *tpk);
}

/// Returns the fingerprint.
#[no_mangle]
pub extern "system" fn sq_tpk_fingerprint(tpk: Option<&TPK>)
                                          -> *mut Fingerprint {
    let tpk = tpk.expect("TPK is NULL");
    box_raw!(tpk.fingerprint())
}
