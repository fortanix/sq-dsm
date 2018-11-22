//! XXX

use failure;
use std::ffi::{CString, CStr};
use std::hash::{Hash, Hasher};
use std::mem::{size_of, forget};
use std::ptr;
use std::slice;
use std::io;
use std::io::{Read, Write};
use libc::{self, uint8_t, uint64_t, c_char, c_int, size_t, ssize_t, c_void};
use failure::ResultExt;

extern crate openpgp;

use self::openpgp::{
    armor,
    Fingerprint,
    KeyID,
    RevocationStatus,
    PacketPile,
    TPK,
    TSK,
    Packet,
    packet::{
        Signature,
        PKESK,
        SKESK,
    },
    SecretKey,
    crypto::Password,
};
use self::openpgp::tpk::{
    CipherSuite,
    TPKBuilder,
    UserIDBinding,
    UserIDBindingIter,
    KeyIter
};
use self::openpgp::packet;
use self::openpgp::parse::{PacketParserResult, PacketParser, PacketParserEOF};
use self::openpgp::parse::stream::{
    DecryptionHelper,
    Decryptor,
    Secret,
    VerificationHelper,
    VerificationResult,
    Verifier,
};
use self::openpgp::serialize::Serialize;
use self::openpgp::constants::{
    DataFormat,
    ReasonForRevocation,
};

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

/// Returns a reference to the raw Fingerprint.
///
/// This returns a reference to the internal buffer that is valid as
/// long as the fingerprint is.
#[no_mangle]
pub extern "system" fn sq_fingerprint_as_bytes(fp: Option<&Fingerprint>, fp_len: Option<&mut size_t>)
                                             -> *const uint8_t {
    let fp = fp.expect("Fingerprint is NULL");
    if let Some(p) = fp_len {
        *p = fp.as_slice().len();
    }
    fp.as_slice().as_ptr()
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

/// Represents a (key, value) pair in an armor header.
#[repr(C)]
pub struct ArmorHeader {
    key: *const c_char,
    value: *const c_char,
}

fn int_to_kind(kind: c_int) -> Option<armor::Kind> {
    match kind {
        0 => None,
        1 => Some(armor::Kind::Message),
        2 => Some(armor::Kind::PublicKey),
        3 => Some(armor::Kind::SecretKey),
        4 => Some(armor::Kind::Signature),
        5 => Some(armor::Kind::File),
        _ => panic!("Bad kind: {}", kind),
    }
}

fn kind_to_int(kind: Option<armor::Kind>) -> c_int {
    match kind {
        None => 0,
        Some(armor::Kind::Message) => 1,
        Some(armor::Kind::PublicKey) => 2,
        Some(armor::Kind::SecretKey) => 3,
        Some(armor::Kind::Signature) => 4,
        Some(armor::Kind::File) => 5,
    }
}

/// Constructs a new filter for the given type of data.
///
/// A filter that strips ASCII Armor from a stream of data.
///
/// # Example
///
/// ```c
/// #define _GNU_SOURCE
/// #include <assert.h>
/// #include <error.h>
/// #include <stdio.h>
/// #include <stdlib.h>
/// #include <string.h>
///
/// #include <sequoia.h>
///
/// const char *armored =
///   "-----BEGIN PGP ARMORED FILE-----\n"
///   "Key0: Value0\n"
///   "Key1: Value1\n"
///   "\n"
///   "SGVsbG8gd29ybGQh\n"
///   "=s4Gu\n"
///   "-----END PGP ARMORED FILE-----\n";
///
/// int
/// main (int argc, char **argv)
/// {
///   sq_error_t err;
///   sq_context_t ctx;
///   sq_reader_t bytes;
///   sq_reader_t armor;
///   sq_armor_kind_t kind;
///   char message[12];
///   sq_armor_header_t *header;
///   size_t header_len;
///
///   ctx = sq_context_new ("org.sequoia-pgp.example", &err);
///   if (ctx == NULL)
///     error (1, 0, "Initializing sequoia failed: %s",
///            sq_error_string (err));
///
///   bytes = sq_reader_from_bytes ((uint8_t *) armored, strlen (armored));
///   armor = sq_armor_reader_new (bytes, SQ_ARMOR_KIND_ANY);
///
///   header = sq_armor_reader_headers (ctx, armor, &header_len);
///   if (header == NULL)
///     {
///       err = sq_context_last_error (ctx);
///       error (1, 0, "Getting headers failed: %s",
///              sq_error_string (err));
///     }
///
///   assert (header_len == 2);
///   assert (strcmp (header[0].key, "Key0") == 0
///           && strcmp (header[0].value, "Value0") == 0);
///   assert (strcmp (header[1].key, "Key1") == 0
///           && strcmp (header[1].value, "Value1") == 0);
///   for (size_t i = 0; i < header_len; i++)
///     {
///       free (header[i].key);
///       free (header[i].value);
///     }
///   free (header);
///
///   kind = sq_armor_reader_kind (armor);
///   assert (kind == SQ_ARMOR_KIND_FILE);
///
///   if (sq_reader_read (ctx, armor, (uint8_t *) message, 12) < 0)
///     {
///       err = sq_context_last_error (ctx);
///       error (1, 0, "Reading failed: %s",
///              sq_error_string (err));
///     }
///
///   assert (memcmp (message, "Hello world!", 12) == 0);
///
///   sq_reader_free (armor);
///   sq_reader_free (bytes);
///   sq_context_free (ctx);
///   return 0;
/// }
/// ```
#[no_mangle]
pub extern "system" fn sq_armor_reader_new(inner: Option<&'static mut Box<Read>>,
                                           kind: c_int)
                                           -> *mut Box<Read> {
    let inner = inner.expect("Inner is NULL");
    let kind = int_to_kind(kind);

    box_raw!(Box::new(armor::Reader::new(inner, kind)))
}

/// Creates a `Reader` from a file.
#[no_mangle]
pub extern "system" fn sq_armor_reader_from_file(ctx: Option<&mut Context>,
                                                 filename: *const c_char,
                                                 kind: c_int)
                                                 -> *mut Box<Read> {
    let ctx = ctx.expect("Context is NULL");
    assert!(! filename.is_null());
    let filename = unsafe {
        CStr::from_ptr(filename).to_string_lossy().into_owned()
    };
    let kind = int_to_kind(kind);

    fry_box!(ctx, armor::Reader::from_file(&filename, kind)
             .map(|r| Box::new(r))
             .map_err(|e| e.into()))
}

/// Creates a `Reader` from a buffer.
#[no_mangle]
pub extern "system" fn sq_armor_reader_from_bytes(b: *const uint8_t, len: size_t,
                                                  kind: c_int)
                                                  -> *mut Box<Read> {
    assert!(!b.is_null());
    let buf = unsafe {
        slice::from_raw_parts(b, len as usize)
    };
    let kind = int_to_kind(kind);

    box_raw!(Box::new(armor::Reader::from_bytes(buf, kind)))
}

/// Returns the kind of data this reader is for.
///
/// Useful if the kind of data is not known in advance.  If the header
/// has not been encountered yet (try reading some data first!), this
/// function returns SQ_ARMOR_KIND_ANY.
///
/// # Example
///
/// See [this] example.
///
///   [this]: fn.sq_armor_reader_new.html
#[no_mangle]
pub extern "system" fn sq_armor_reader_kind(reader: *mut Box<Read>)
                                            -> c_int {
    // We need to downcast `reader`.  To do that, we need to do a
    // little dance.  We will momentarily take ownership of `reader`,
    // wrapping it in a Box again.  Then, at the end of the function,
    // we will leak it again.
    assert!(! reader.is_null());
    let reader = unsafe {
        Box::from_raw(reader as *mut Box<armor::Reader>)
    };
    let kind = kind_to_int(reader.kind());
    Box::into_raw(reader);
    kind
}

/// Returns the armored headers.
///
/// The tuples contain a key and a value.
///
/// Note: if a key occurs multiple times, then there are multiple
/// entries in the vector with the same key; values with the same
/// key are *not* combined.
///
/// The returned array and the strings in the headers have been
/// allocated with `malloc`, and the caller is responsible for freeing
/// both the array and the strings.
///
/// # Example
///
/// See [this] example.
///
///   [this]: fn.sq_armor_reader_new.html
#[no_mangle]
pub extern "system" fn sq_armor_reader_headers(ctx: Option<&mut Context>,
                                               reader: *mut Box<Read>,
                                               len: Option<&mut size_t>)
                                               -> *mut ArmorHeader {
    let ctx = ctx.expect("Context is NULL");
    assert!(! reader.is_null());
    let len = len.expect("LEN is NULL");

    // We need to downcast `reader`.  To do that, we need to do a
    // little dance.  We will momentarily take ownership of `reader`,
    // wrapping it in a Box again.  Then, at the end of the function,
    // we will leak it again.
    let mut reader = unsafe {
        Box::from_raw(reader as *mut Box<armor::Reader>)
    };

    // We need to be extra careful here in order not to keep ownership
    // of `reader` in case of errors.
    let result = match reader.headers().map_err(|e| e.into()) {
        Ok(headers) => {
            // Allocate space for the result.
            let buf = unsafe {
                libc::calloc(headers.len(), size_of::<ArmorHeader>())
                    as *mut ArmorHeader
            };
            let sl = unsafe {
                slice::from_raw_parts_mut(buf, headers.len())
            };
            for (i, (key, value)) in headers.iter().enumerate() {
                sl[i].key = strdup(key);
                sl[i].value = strdup(value);
            }

            *len = headers.len();
            buf
        },
        Err(e) => {
            ctx.e = Some(e);
            ptr::null_mut()
        },
    };

    // Release temporary ownership.
    Box::into_raw(reader);
    result
}

/// Creates a zero-terminated C string from a &str allocated using
/// malloc.
fn strdup(s: &str) -> *mut c_char {
    let b = s.as_bytes();
    let len = b.len() + 1;
    let dup = unsafe {
        libc::malloc(len) as *mut c_char
    };
    let sl = unsafe {
        slice::from_raw_parts_mut(dup as *mut uint8_t, len)
    };
    sl[..len-1].copy_from_slice(b);
    sl[len-1] = 0;
    dup
}

/// Constructs a new filter for the given type of data.
///
/// A filter that applies ASCII Armor to the data written to it.
///
/// # Example
///
/// ```c
/// #define _GNU_SOURCE
/// #include <assert.h>
/// #include <error.h>
/// #include <stdio.h>
/// #include <stdlib.h>
/// #include <string.h>
///
/// #include <sequoia.h>
///
/// int
/// main (int argc, char **argv)
/// {
///   void *buf = NULL;
///   size_t len = 0;
///   sq_writer_t alloc;
///   sq_writer_t armor;
///   sq_error_t err;
///   sq_context_t ctx;
///   char *message = "Hello world!";
///   sq_armor_header_t header[2] = {
///     { "Key0", "Value0" },
///     { "Key1", "Value1" },
///   };
///
///   ctx = sq_context_new ("org.sequoia-pgp.example", &err);
///   if (ctx == NULL)
///     error (1, 0, "Initializing sequoia failed: %s",
///            sq_error_string (err));
///
///   alloc = sq_writer_alloc (&buf, &len);
///   armor = sq_armor_writer_new (ctx, alloc, SQ_ARMOR_KIND_FILE, header, 2);
///   if (armor == NULL)
///     {
///       err = sq_context_last_error (ctx);
///       error (1, 0, "Creating armor writer failed: %s",
///              sq_error_string (err));
///     }
///
///   if (sq_writer_write (ctx, armor, (uint8_t *) message, strlen (message)) < 0)
///     {
///       err = sq_context_last_error (ctx);
///       error (1, 0, "Writing failed: %s",
///              sq_error_string (err));
///     }
///   sq_writer_free (armor);
///   sq_writer_free (alloc);
///
///   assert (len == 114);
///   assert (memcmp (buf,
///                   "-----BEGIN PGP ARMORED FILE-----\n"
///                   "Key0: Value0\n"
///                   "Key1: Value1\n"
///                   "\n"
///                   "SGVsbG8gd29ybGQh\n"
///                   "=s4Gu\n"
///                   "-----END PGP ARMORED FILE-----\n",
///                   len) == 0);
///
///   free (buf);
///   sq_context_free (ctx);
///   return 0;
/// }
/// ```
#[no_mangle]
pub extern "system" fn sq_armor_writer_new
    (ctx: Option<&mut Context>,
     inner: Option<&'static mut Box<Write>>,
     kind: c_int,
     header: Option<&ArmorHeader>,
     header_len: size_t)
     -> *mut Box<Write>
{
    let ctx = ctx.expect("Context is NULL");
    let inner = inner.expect("Inner is NULL");
    let kind = int_to_kind(kind).expect("KIND must not be SQ_ARMOR_KIND_ANY");

    let mut header_ = Vec::new();
    if header_len > 0 {
        let header = header.expect("HEADER is NULL");
        let header = unsafe {
            slice::from_raw_parts(header, header_len)
        };
        for h in header {
            assert!(! h.key.is_null());
            assert!(! h.value.is_null());
            header_.push(unsafe {
                (CStr::from_ptr(h.key).to_string_lossy(),
                 CStr::from_ptr(h.value).to_string_lossy())
            });
        }
    }

    let header: Vec<(&str, &str)> =
        header_.iter().map(|h| (h.0.as_ref(), h.1.as_ref())).collect();

    fry_box!(ctx, armor::Writer::new(inner, kind, &header)
             .map(|r| Box::new(r))
             .map_err(|e| e.into()))
}


/* openpgp::PacketPile.  */

/// Deserializes the OpenPGP message stored in a `std::io::Read`
/// object.
///
/// Although this method is easier to use to parse an OpenPGP
/// message than a `PacketParser` or a `PacketPileParser`, this
/// interface buffers the whole message in memory.  Thus, the
/// caller must be certain that the *deserialized* message is not
/// too large.
///
/// Note: this interface *does* buffer the contents of packets.
#[no_mangle]
pub extern "system" fn sq_packet_pile_from_reader(ctx: Option<&mut Context>,
                                                  reader: Option<&mut Box<Read>>)
                                                  -> *mut PacketPile {
    let ctx = ctx.expect("Context is NULL");
    let reader = reader.expect("Reader is NULL");
    fry_box!(ctx, PacketPile::from_reader(reader))
}

/// Deserializes the OpenPGP message stored in the file named by
/// `filename`.
///
/// See `sq_packet_pile_from_reader` for more details and caveats.
#[no_mangle]
pub extern "system" fn sq_packet_pile_from_file(ctx: Option<&mut Context>,
                                                filename: *const c_char)
                                                -> *mut PacketPile {
    let ctx = ctx.expect("Context is NULL");
    assert!(! filename.is_null());
    let filename = unsafe {
        CStr::from_ptr(filename).to_string_lossy().into_owned()
    };
    fry_box!(ctx, PacketPile::from_file(&filename))
}

/// Deserializes the OpenPGP message stored in the provided buffer.
///
/// See `sq_packet_pile_from_reader` for more details and caveats.
#[no_mangle]
pub extern "system" fn sq_packet_pile_from_bytes(ctx: Option<&mut Context>,
                                                 b: *const uint8_t, len: size_t)
                                                 -> *mut PacketPile {
    let ctx = ctx.expect("Context is NULL");
    assert!(!b.is_null());
    let buf = unsafe {
        slice::from_raw_parts(b, len as usize)
    };

    fry_box!(ctx, PacketPile::from_bytes(buf))
}

/// Frees the packet_pile.
#[no_mangle]
pub extern "system" fn sq_packet_pile_free(packet_pile: *mut PacketPile) {
    if packet_pile.is_null() {
        return
    }
    unsafe {
        drop(Box::from_raw(packet_pile));
    }
}

/// Clones the PacketPile.
#[no_mangle]
pub extern "system" fn sq_packet_pile_clone(packet_pile: Option<&PacketPile>)
                                            -> *mut PacketPile {
    let packet_pile = packet_pile.expect("PacketPile is NULL");
    box_raw!(packet_pile.clone())
}

/// Serializes the packet pile.
#[no_mangle]
pub extern "system" fn sq_packet_pile_serialize(ctx: Option<&mut Context>,
                                                packet_pile: Option<&PacketPile>,
                                                writer: Option<&mut Box<Write>>)
                                                -> Status {
    let ctx = ctx.expect("Context is NULL");
    let packet_pile = packet_pile.expect("PacketPile is NULL");
    let writer = writer.expect("Writer is NULL");
    fry_status!(ctx, packet_pile.serialize(writer))
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
pub extern "system" fn sq_tpk_from_packet_pile(ctx: Option<&mut Context>,
                                               m: *mut PacketPile)
                                               -> *mut TPK {
    let ctx = ctx.expect("Context is NULL");
    assert!(! m.is_null());
    let m = unsafe { Box::from_raw(m) };
    fry_box!(ctx, TPK::from_packet_pile(*m))
}

/// Returns the first TPK found in `buf`.
///
/// `buf` must be an OpenPGP-encoded TPK.
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

/// Cast the public key into a secret key that allows using the secret
/// parts of the containing keys.
#[no_mangle]
pub extern "system" fn sq_tpk_into_tsk(tpk: *mut TPK)
                                       -> *mut TSK {
    assert!(!tpk.is_null());
    let tpk = unsafe {
        Box::from_raw(tpk)
    };
    box_raw!(tpk.into_tsk())
}

/// Returns a reference to the TPK's primary key.
///
/// The tpk still owns the key.  The caller should neither modify nor
/// free the key.
#[no_mangle]
pub extern "system" fn sq_tpk_primary(tpk: Option<&TPK>)
    -> Option<&packet::Key> {
    let tpk = tpk.expect("TPK is NULL");
    Some(tpk.primary())
}

/// Returns the TPK's revocation status.
///
/// Note: this only returns whether the TPK has been revoked, and does
/// not reflect whether an individual user id, user attribute or
/// subkey has been revoked.
#[no_mangle]
pub extern "system" fn sq_tpk_revocation_status(tpk: Option<&TPK>)
                                                -> *mut RevocationStatus {
    let tpk = tpk.expect("TPK is NULL");
    box_raw!(tpk.revoked())
}

fn int_to_reason_for_revocation(code: c_int) -> ReasonForRevocation {
    match code {
        0 => ReasonForRevocation::KeyCompromised,
        1 => ReasonForRevocation::Unspecified,
        2 => ReasonForRevocation::KeySuperseded,
        3 => ReasonForRevocation::KeyCompromised,
        4 => ReasonForRevocation::KeyRetired,
        5 => ReasonForRevocation::UIDRetired,
        _ => panic!("Bad reason for revocation: {}", code),
    }
}


/// Returns a new revocation certificate for the TPK.
///
/// This function does *not* consume tpk.
#[no_mangle]
pub extern "system" fn sq_tpk_revoke (ctx: Option<&mut Context>,
                                      tpk: *mut TPK,
                                      code: c_int,
                                      reason: Option<*const c_char>)
    -> *mut packet::Signature
{
    let ctx = ctx.expect("Context is NULL");
    assert!(!tpk.is_null());
    let tpk = unsafe {
        Box::from_raw(tpk)
    };
    let code = int_to_reason_for_revocation(code);
    let reason = if let Some(reason) = reason {
        unsafe {
            CStr::from_ptr(reason).to_bytes()
        }
    } else {
        b""
    };

    fry_box!(ctx, tpk.revoke(code, reason))
}

/// Adds a revocation certificate to the tpk.
///
/// This function consumes the tpk.
#[no_mangle]
pub extern "system" fn sq_tpk_revoke_in_place (ctx: Option<&mut Context>,
                                               tpk: *mut TPK,
                                               code: c_int,
                                               reason: Option<*const c_char>)
    -> *mut TPK
{
    let ctx = ctx.expect("Context is NULL");
    assert!(!tpk.is_null());
    let tpk = unsafe {
        Box::from_raw(tpk)
    };
    let code = int_to_reason_for_revocation(code);
    let reason = if let Some(reason) = reason {
        unsafe {
            CStr::from_ptr(reason).to_bytes()
        }
    } else {
        b""
    };

    fry_box!(ctx, tpk.revoke_in_place(code, reason))
}

/// Returns whether the TPK has expired.
#[no_mangle]
pub extern "system" fn sq_tpk_expired(tpk: Option<&TPK>)
                                      -> c_int {
    let tpk = tpk.expect("TPK is NULL");

    tpk.expired() as c_int
}

/// Changes the TPK's expiration.
///
/// Expiry is when the key should expire in seconds relative to the
/// key's creation (not the current time).
///
/// This function consumes `tpk` and returns a new `TPK`.
#[no_mangle]
pub extern "system" fn sq_tpk_set_expiry(ctx: Option<&mut Context>,
                                         tpk: *mut TPK, expiry: u32)
                                         -> *mut TPK {
    let ctx = ctx.expect("CTX is NULL");
    assert!(!tpk.is_null());
    let tpk = unsafe {
        Box::from_raw(tpk)
    };

    fry_box!(ctx, tpk.set_expiry_in_seconds(expiry))
}

/// Returns whether the TPK includes any secret key material.
#[no_mangle]
pub extern "system" fn sq_tpk_is_tsk(tpk: Option<&TPK>)
                                     -> c_int {
    let tpk = tpk.expect("TPK is NULL");
    tpk.is_tsk() as c_int
}

fn revocation_status_to_int(rs: &RevocationStatus) -> c_int {
    match rs {
        RevocationStatus::Revoked(_) => 0,
        RevocationStatus::CouldBe(_) => 1,
        RevocationStatus::NotAsFarAsWeKnow => 2,
    }
}

/// Returns the TPK's revocation status variant.
#[no_mangle]
pub extern "system" fn sq_revocation_status_variant(
    rs: *mut RevocationStatus)
    -> c_int
{
    assert!(! rs.is_null());
    let rs = unsafe {
        Box::from_raw(rs as *mut RevocationStatus)
    };
    let variant = revocation_status_to_int(rs.as_ref());
    Box::into_raw(rs);
    variant
}

/// Frees a sq_revocation_status_t.
#[no_mangle]
pub extern "system" fn sq_revocation_status_free(
    rs: *mut RevocationStatus)
{
    if rs.is_null() { return };
    unsafe {
        drop(Box::from_raw(rs))
    };
}

/* UserIDBinding */

/// Returns the user id.
///
/// This function may fail and return NULL if the user id contains an
/// interior NUL byte.  We do this rather than complicate the API, as
/// there is no valid use for such user ids; they must be malicious.
///
/// The caller must free the returned value.
#[no_mangle]
pub extern "system" fn sq_user_id_binding_user_id(
    binding: Option<&UserIDBinding>)
    -> *mut c_char
{
    let binding = binding.expect("Binding is NULL");

    if let Ok(c_str) = CString::new(binding.userid().userid()) {
        c_str.into_raw()
    } else {
        ptr::null_mut()
    }
}

/* UserIDBindingIter */

/// Returns an iterator over the TPK's user id bindings.
#[no_mangle]
pub extern "system" fn sq_tpk_user_id_binding_iter(tpk: Option<&TPK>)
    -> *mut UserIDBindingIter
{
    let tpk = tpk.expect("TPK is NULL");
    box_raw!(tpk.userids())
}

/// Frees a sq_user_id_binding_iter_t.
#[no_mangle]
pub extern "system" fn sq_user_id_binding_iter_free(
    iter: *mut UserIDBindingIter)
{
    if iter.is_null() { return };
    unsafe {
        drop(Box::from_raw(iter))
    };
}

/// Returns the next `UserIDBinding`.
#[no_mangle]
pub extern "system" fn sq_user_id_binding_iter_next<'a>(
    iter: Option<&mut UserIDBindingIter<'a>>)
    -> Option<&'a UserIDBinding>
{
    let iter = iter.expect("Iterator is NULL");
    iter.next()
}

/* tpk::KeyIter. */

/// Returns an iterator over the TPK's keys.
///
/// This iterates over both the primary key and any subkeys.
#[no_mangle]
pub extern "system" fn sq_tpk_key_iter(tpk: Option<&TPK>)
    -> *mut KeyIter
{
    let tpk = tpk.expect("TPK is NULL");
    box_raw!(tpk.keys())
}

/// Frees a sq_tpk_key_iter_t.
#[no_mangle]
pub extern "system" fn sq_tpk_key_iter_free(
    iter: *mut KeyIter)
{
    if iter.is_null() { return };
    unsafe {
        drop(Box::from_raw(iter))
    };
}

/// Returns the next key.
#[no_mangle]
pub extern "system" fn sq_tpk_key_iter_next<'a>(
    iter: Option<&mut KeyIter<'a>>,
    sigo: Option<&mut *mut Option<&'a packet::Signature>>)
    -> Option<&'a packet::Key>
{
    let iter = iter.expect("Iterator is NULL");
    if let Some((sig, key)) = iter.next() {
        if let Some(ptr) = sigo {
            *ptr = box_raw!(sig);
        }

        Some(key)
    } else {
        None
    }
}

/* TPKBuilder */

/// Creates a default `sq_tpk_builder_t`.
///
/// # Example
///
/// ```c
/// #include <assert.h>
/// #include <sequoia.h>
///
/// sq_context_t ctx;
/// sq_tpk_builder_t builder;
/// sq_tpk_t tpk;
/// sq_signature_t revocation;
///
/// ctx = sq_context_new ("org.sequoia-pgp.tests", NULL);
///
/// builder = sq_tpk_builder_default ();
/// sq_tpk_builder_set_cipher_suite (&builder, SQ_TPK_CIPHER_SUITE_CV25519);
/// sq_tpk_builder_add_userid (&builder, "some@example.org");
/// sq_tpk_builder_add_signing_subkey (&builder);
/// sq_tpk_builder_add_encryption_subkey (&builder);
/// sq_tpk_builder_generate (ctx, builder, &tpk, &revocation);
/// assert (tpk);
/// assert (revocation);
/// ```
#[no_mangle]
pub extern "system" fn sq_tpk_builder_default() -> *mut TPKBuilder {
    box_raw!(TPKBuilder::default())
}

/// Generates a key compliant to [Autocrypt Level 1].
///
///   [Autocrypt Level 1]: https://autocrypt.org/level1.html
#[no_mangle]
pub extern "system" fn sq_tpk_builder_autocrypt() -> *mut TPKBuilder {
    use self::openpgp::autocrypt::Autocrypt;
    box_raw!(TPKBuilder::autocrypt(Autocrypt::V1))
}

/// Frees an `sq_tpk_builder_t`.
#[no_mangle]
pub extern "system" fn sq_tpk_builder_free(tpkb: *mut TPKBuilder)
{
    if tpkb.is_null() {
        return
    }
    unsafe {
        drop(Box::from_raw(tpkb));
    }
}

/// Sets the encryption and signature algorithms for primary and all
/// subkeys.
#[no_mangle]
pub extern "system" fn sq_tpk_builder_set_cipher_suite
    (tpkb: Option<&mut *mut TPKBuilder>, cs: c_int)
{
    use self::CipherSuite::*;
    let tpkb = tpkb.expect("TPKB is NULL");
    assert!(! tpkb.is_null());
    let tpkb_ = unsafe { Box::from_raw(*tpkb) };
    let cs = match cs {
        0 => Cv25519,
        1 => RSA3k,
        n => panic!("Bad ciphersuite: {}", n),
    };
    let tpkb_ = tpkb_.set_cipher_suite(cs);
    *tpkb = box_raw!(tpkb_);
}

/// Adds a new user ID. The first user ID added replaces the default
/// ID that is just the empty string.
#[no_mangle]
pub extern "system" fn sq_tpk_builder_add_userid
    (tpkb: Option<&mut *mut TPKBuilder>, uid: *const c_char)
{
    let tpkb = tpkb.expect("TPKB is NULL");
    assert!(!tpkb.is_null());
    let tpkb_ = unsafe { Box::from_raw(*tpkb) };
    let uid = unsafe { CStr::from_ptr(uid).to_string_lossy().to_string() };
    let tpkb_ = tpkb_.add_userid(uid.as_ref());
    *tpkb = box_raw!(tpkb_);
}

/// Adds a signing capable subkey.
#[no_mangle]
pub extern "system" fn sq_tpk_builder_add_signing_subkey
    (tpkb: Option<&mut *mut TPKBuilder>)
{
    let tpkb = tpkb.expect("TPKB is NULL");
    assert!(!tpkb.is_null());
    let tpkb_ = unsafe { Box::from_raw(*tpkb) };
    let tpkb_ = tpkb_.add_signing_subkey();
    *tpkb = box_raw!(tpkb_);
}

/// Adds an encryption capable subkey.
#[no_mangle]
pub extern "system" fn sq_tpk_builder_add_encryption_subkey
    (tpkb: Option<&mut *mut TPKBuilder>)
{
    let tpkb = tpkb.expect("TPKB is NULL");
    assert!(!tpkb.is_null());
    let tpkb_ = unsafe { Box::from_raw(*tpkb) };
    let tpkb_ = tpkb_.add_encryption_subkey();
    *tpkb = box_raw!(tpkb_);
}

/// Adds an certification capable subkey.
#[no_mangle]
pub extern "system" fn sq_tpk_builder_add_certification_subkey
    (tpkb: Option<&mut *mut TPKBuilder>)
{
    let tpkb = tpkb.expect("TPKB is NULL");
    assert!(!tpkb.is_null());
    let tpkb_ = unsafe { Box::from_raw(*tpkb) };
    let tpkb_ = tpkb_.add_certification_subkey();
    *tpkb = box_raw!(tpkb_);
}

/// Generates the actual TPK.
///
/// Consumes `tpkb`.
#[no_mangle]
pub extern "system" fn sq_tpk_builder_generate
    (ctx: Option<&mut Context>, tpkb: *mut TPKBuilder,
     tpk_out: Option<&mut *mut TPK>,
     revocation_out: Option<&mut *mut Signature>)
    -> Status
{
    let ctx = ctx.expect("CTX is NULL");
    assert!(!tpkb.is_null());
    let tpk_out = tpk_out.expect("TPK is NULL");
    let revocation_out = revocation_out.expect("REVOCATION is NULL");
    let tpkb = unsafe { Box::from_raw(tpkb) };
    match tpkb.generate() {
        Ok((tpk, revocation)) => {
            *tpk_out = box_raw!(tpk);
            *revocation_out = box_raw!(revocation);
            Status::Success
        },
        Err(e) => fry_status!(ctx, Err::<(), failure::Error>(e)),
    }
}


/* TSK */

/// Generates a new RSA 3072 bit key with UID `primary_uid`.
#[no_mangle]
pub extern "system" fn sq_tsk_new(ctx: Option<&mut Context>,
                                  primary_uid: *const c_char,
                                  tsk_out: Option<&mut *mut TSK>,
                                  revocation_out: Option<&mut *mut Signature>)
    -> Status
{
    let ctx = ctx.expect("CONTEXT is NULL");
    assert!(!primary_uid.is_null());
    let tsk_out = tsk_out.expect("TSK is NULL");
    let revocation_out = revocation_out.expect("REVOCATION is NULL");
    let primary_uid = unsafe {
        CStr::from_ptr(primary_uid)
    };
    match TSK::new(primary_uid.to_string_lossy()) {
        Ok((tsk, revocation)) => {
            *tsk_out = box_raw!(tsk);
            *revocation_out = box_raw!(revocation);
            Status::Success
        },
        Err(e) => fry_status!(ctx, Err::<(), failure::Error>(e)),
    }
}

/// Frees the TSK.
#[no_mangle]
pub extern "system" fn sq_tsk_free(tsk: *mut TSK) {
    if tsk.is_null() {
        return
    }
    unsafe {
        drop(Box::from_raw(tsk));
    }
}

/// Returns a reference to the corresponding TPK.
#[no_mangle]
pub extern "system" fn sq_tsk_tpk(tsk: Option<&TSK>)
                                  -> &TPK {
    let tsk = tsk.expect("TSK is NULL");
    tsk.tpk()
}

/// Converts the TSK into a TPK.
#[no_mangle]
pub extern "system" fn sq_tsk_into_tpk(tsk: *mut TSK)
                                       -> *mut TPK {
    let tsk = unsafe {
        Box::from_raw(tsk)
    };
    box_raw!(tsk.into_tpk())
}


/// Serializes the TSK.
#[no_mangle]
pub extern "system" fn sq_tsk_serialize(ctx: Option<&mut Context>,
                                        tsk: Option<&TSK>,
                                        writer: Option<&mut Box<Write>>)
                                        -> Status {
    let ctx = ctx.expect("Context is NULL");
    let tsk = tsk.expect("TSK is NULL");
    let writer = writer.expect("Writer is NULL");
    fry_status!(ctx, tsk.serialize(writer))
}

/* openpgp::Packet.  */

/// Frees the Packet.
#[no_mangle]
pub extern "system" fn sq_packet_free(p: *mut Packet) {
    if p.is_null() { return }
    unsafe {
        drop(Box::from_raw(p));
    }
}

/// Returns the `Packet's` corresponding OpenPGP tag.
///
/// Tags are explained in [Section 4.3 of RFC 4880].
///
///   [Section 4.3 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-4.3
#[no_mangle]
pub extern "system" fn sq_packet_tag(p: Option<&Packet>)
                                     -> uint8_t {
    let p = p.expect("Packet is NULL");
    let tag: u8 = p.tag().into();
    tag as uint8_t
}

/// Returns the parsed `Packet's` corresponding OpenPGP tag.
///
/// Returns the packets tag, but only if it was successfully
/// parsed into the corresponding packet type.  If e.g. a
/// Signature Packet uses some unsupported methods, it is parsed
/// into an `Packet::Unknown`.  `tag()` returns `SQ_TAG_SIGNATURE`,
/// whereas `kind()` returns `0`.
#[no_mangle]
pub extern "system" fn sq_packet_kind(p: Option<&Packet>)
                                      -> uint8_t {
    let p = p.expect("Packet is NULL");
    if let Some(kind) = p.kind() {
        kind.into()
    } else {
        0
    }
}

/// Returns the value of the `Signature` packet's Issuer subpacket.
///
/// If there is no Issuer subpacket, this returns NULL.  Note: if
/// there is no Issuer subpacket, but there is an IssuerFingerprint
/// subpacket, this still returns NULL.
#[no_mangle]
pub extern "system" fn sq_signature_issuer(sig: Option<&packet::Signature>)
                                           -> *mut KeyID {
    let sig = sig.expect("Signature is NULL");
    maybe_box_raw!(sig.issuer())
}

/// Returns the value of the `Signature` packet's IssuerFingerprint subpacket.
///
/// If there is no IssuerFingerprint subpacket, this returns NULL.
/// Note: if there is no IssuerFingerprint subpacket, but there is an
/// Issuer subpacket, this still returns NULL.
#[no_mangle]
pub extern "system" fn sq_signature_issuer_fingerprint(
    sig: Option<&packet::Signature>)
    -> *mut Fingerprint
{
    let sig = sig.expect("Signature is NULL");
    maybe_box_raw!(sig.issuer_fingerprint())
}


/// Computes and returns the key's fingerprint as per Section 12.2
/// of RFC 4880.
#[no_mangle]
pub extern "system" fn sq_p_key_fingerprint(key: Option<&packet::Key>)
                                            -> *mut Fingerprint {
    let key = key.expect("Key is NULL");
    box_raw!(key.fingerprint())
}

/// Computes and returns the key's key ID as per Section 12.2 of RFC
/// 4880.
#[no_mangle]
pub extern "system" fn sq_p_key_keyid(key: Option<&packet::Key>)
                                      -> *mut KeyID {
    let key = key.expect("Key is NULL");
    box_raw!(key.keyid())
}

/// Returns the key's creation time.
#[no_mangle]
pub extern "system" fn sq_p_key_creation_time(key: Option<&packet::Key>)
    -> u32
{
    let key = key.expect("Key is NULL");
    let ct = key.creation_time();

    ct.to_timespec().sec as u32
}

/// Returns the value of the User ID Packet.
///
/// The returned pointer is valid until `uid` is deallocated.  If
/// `value_len` is not `NULL`, the size of value is stored there.
#[no_mangle]
pub extern "system" fn sq_user_id_value(uid: Option<&Packet>,
                                        value_len: Option<&mut size_t>)
                                        -> *const uint8_t {
    let uid = uid.expect("UserID is NULL");
    if let &Packet::UserID(ref uid) = uid {
        if let Some(p) = value_len {
            *p = uid.userid().len();
        }
        uid.userid().as_ptr()
    } else {
        panic!("Not a UserID packet");
    }
}

/// Returns the value of the User Attribute Packet.
///
/// The returned pointer is valid until `ua` is deallocated.  If
/// `value_len` is not `NULL`, the size of value is stored there.
#[no_mangle]
pub extern "system" fn sq_user_attribute_value(ua: Option<&Packet>,
                                               value_len: Option<&mut size_t>)
                                               -> *const uint8_t {
    let ua = ua.expect("UserAttribute is NULL");
    if let &Packet::UserAttribute(ref ua) = ua {
        if let Some(p) = value_len {
            *p = ua.user_attribute().len();
        }
        ua.user_attribute().as_ptr()
    } else {
        panic!("Not a UserAttribute packet");
    }
}

/// Returns the session key.
///
/// `key` of size `key_len` must be a buffer large enough to hold the
/// session key.  If `key` is NULL, or not large enough, then the key
/// is not written to it.  Either way, `key_len` is set to the size of
/// the session key.
#[no_mangle]
pub extern "system" fn sq_skesk_decrypt(ctx: Option<&mut Context>,
                                        skesk: Option<&Packet>,
                                        password: *const uint8_t,
                                        password_len: size_t,
                                        algo: Option<&mut uint8_t>, // XXX
                                        key: *mut uint8_t,
                                        key_len: Option<&mut size_t>)
                                        -> Status {
    let ctx = ctx.expect("Context is NULL");
    let skesk = skesk.expect("SKESK is NULL");
    assert!(!password.is_null());
    let password = unsafe {
        slice::from_raw_parts(password, password_len as usize)
    };
    let algo = algo.expect("Algo is NULL");
    let key_len = key_len.expect("Key length is NULL");

    if let &Packet::SKESK(ref skesk) = skesk {
        match skesk.decrypt(&password.to_owned().into()) {
            Ok((a, k)) => {
                *algo = a.into();
                if !key.is_null() && *key_len >= k.len() {
                    unsafe {
                        ::std::ptr::copy(k.as_ptr(),
                                         key,
                                         k.len());
                    }
                }
                *key_len = k.len();
                Status::Success
            },
            Err(e) => fry_status!(ctx, Err::<(), failure::Error>(e)),
        }
    } else {
        panic!("Not a SKESK packet");
    }
}

/// Returns the PKESK's recipient.
///
/// The return value is a reference ot a `KeyID`.  The caller must not
/// modify or free it.
#[no_mangle]
pub extern "system" fn sq_pkesk_recipient(pkesk: Option<&PKESK>)
                                          -> *const KeyID {
    let pkesk = pkesk.expect("PKESK is NULL");
    pkesk.recipient()
}

/// Returns the session key.
///
/// `key` of size `key_len` must be a buffer large enough to hold the
/// session key.  If `key` is NULL, or not large enough, then the key
/// is not written to it.  Either way, `key_len` is set to the size of
/// the session key.
#[no_mangle]
pub extern "system" fn sq_pkesk_decrypt(ctx: Option<&mut Context>,
                                        pkesk: Option<&PKESK>,
                                        secret_key: Option<&packet::Key>,
                                        algo: Option<&mut uint8_t>, // XXX
                                        key: *mut uint8_t,
                                        key_len: Option<&mut size_t>)
                                        -> Status {
    let ctx = ctx.expect("Context is NULL");
    let pkesk = pkesk.expect("PKESK is NULL");
    let secret_key = secret_key.expect("SECRET_KEY is NULL");
    let algo = algo.expect("Algo is NULL");
    let key_len = key_len.expect("Key length is NULL");

    if let Some(SecretKey::Unencrypted{ mpis: ref secret_part }) = secret_key.secret() {
        match pkesk.decrypt(secret_key, secret_part) {
            Ok((a, k)) => {
                *algo = a.into();
                if !key.is_null() && *key_len >= k.len() {
                    unsafe {
                        ::std::ptr::copy(k.as_ptr(),
                                         key,
                                         k.len());
                    }
                }
                *key_len = k.len();
                Status::Success
            },
            Err(e) => fry_status!(ctx, Err::<(), failure::Error>(e)),
        }
    } else {
        // XXX: Better message.
        panic!("No secret parts");
    }
}

/* openpgp::parse.  */

/// Starts parsing OpenPGP packets stored in a `sq_reader_t`
/// object.
///
/// This function returns a `PacketParser` for the first packet in
/// the stream.
#[no_mangle]
pub extern "system" fn sq_packet_parser_from_reader<'a>
    (ctx: Option<&mut Context>, reader: Option<&'a mut Box<'a + Read>>)
     -> *mut PacketParserResult<'a> {
    let ctx = ctx.expect("Context is NULL");
    let reader = reader.expect("Reader is NULL");
    fry_box!(ctx, PacketParser::from_reader(reader))
}

/// Starts parsing OpenPGP packets stored in a file named `path`.
///
/// This function returns a `PacketParser` for the first packet in
/// the stream.
#[no_mangle]
pub extern "system" fn sq_packet_parser_from_file
    (ctx: Option<&mut Context>, filename: *const c_char)
     -> *mut PacketParserResult {
    let ctx = ctx.expect("Context is NULL");
    assert!(! filename.is_null());
    let filename = unsafe {
        CStr::from_ptr(filename).to_string_lossy().into_owned()
    };
    fry_box!(ctx, PacketParser::from_file(&filename))
}

/// Starts parsing OpenPGP packets stored in a buffer.
///
/// This function returns a `PacketParser` for the first packet in
/// the stream.
#[no_mangle]
pub extern "system" fn sq_packet_parser_from_bytes
    (ctx: Option<&mut Context>, b: *const uint8_t, len: size_t)
     -> *mut PacketParserResult {
    let ctx = ctx.expect("Context is NULL");
    assert!(!b.is_null());
    let buf = unsafe {
        slice::from_raw_parts(b, len as usize)
    };

    fry_box!(ctx, PacketParser::from_bytes(buf))
}

/// Frees the packet parser result
#[no_mangle]
pub extern "system" fn sq_packet_parser_result_free(
    ppr: *mut PacketParserResult)
{
    if ppr.is_null() { return }
    unsafe {
        drop(Box::from_raw(ppr));
    }
}

/// Frees the packet parser.
#[no_mangle]
pub extern "system" fn sq_packet_parser_free(pp: *mut PacketParser) {
    if pp.is_null() { return }
    unsafe {
        drop(Box::from_raw(pp));
    }
}

/// Frees the packet parser EOF object.
#[no_mangle]
pub extern "system" fn sq_packet_parser_eof_is_message(
    eof: Option<&PacketParserEOF>) -> bool
{
    let eof = eof.expect("EOF is NULL");

    eof.is_message()
}

/// Frees the packet parser EOF object.
#[no_mangle]
pub extern "system" fn sq_packet_parser_eof_free(eof: *mut PacketParserEOF) {
    if eof.is_null() { return }
    unsafe {
        drop(Box::from_raw(eof));
    }
}

/// Returns a reference to the packet that is being parsed.
#[no_mangle]
pub extern "system" fn sq_packet_parser_packet
    (pp: Option<&PacketParser>)
     -> *const Packet {
    let pp = pp.expect("PacketParser is NULL");
    &pp.packet
}

/// Returns the current packet's recursion depth.
///
/// A top-level packet has a recursion depth of 0.  Packets in a
/// top-level container have a recursion depth of 1, etc.
#[no_mangle]
pub extern "system" fn sq_packet_parser_recursion_depth
    (pp: Option<&PacketParser>)
     -> uint8_t {
    let pp = pp.expect("PacketParser is NULL");
    pp.recursion_depth() as u8
}

/// Finishes parsing the current packet and starts parsing the
/// following one.
///
/// This function finishes parsing the current packet.  By
/// default, any unread content is dropped.  (See
/// [`PacketParsererBuilder`] for how to configure this.)  It then
/// creates a new packet parser for the following packet.  If the
/// current packet is a container, this function does *not*
/// recurse into the container, but skips any packets it contains.
/// To recurse into the container, use the [`recurse()`] method.
///
///   [`PacketParsererBuilder`]: parse/struct.PacketParserBuilder.html
///   [`recurse()`]: #method.recurse
///
/// The return value is a tuple containing:
///
///   - A `Packet` holding the fully processed old packet;
///
///   - The old packet's recursion depth;
///
///   - A `PacketParser` holding the new packet;
///
///   - And, the recursion depth of the new packet.
///
/// A recursion depth of 0 means that the packet is a top-level
/// packet, a recursion depth of 1 means that the packet is an
/// immediate child of a top-level-packet, etc.
///
/// Since the packets are serialized in depth-first order and all
/// interior nodes are visited, we know that if the recursion
/// depth is the same, then the packets are siblings (they have a
/// common parent) and not, e.g., cousins (they have a common
/// grandparent).  This is because, if we move up the tree, the
/// only way to move back down is to first visit a new container
/// (e.g., an aunt).
///
/// Using the two positions, we can compute the change in depth as
/// new_depth - old_depth.  Thus, if the change in depth is 0, the
/// two packets are siblings.  If the value is 1, the old packet
/// is a container, and the new packet is its first child.  And,
/// if the value is -1, the new packet is contained in the old
/// packet's grandparent.  The idea is illustrated below:
///
/// ```text
///             ancestor
///             |       \
///            ...      -n
///             |
///           grandparent
///           |          \
///         parent       -1
///         |      \
///      packet    0
///         |
///         1
/// ```
///
/// Note: since this function does not automatically recurse into
/// a container, the change in depth will always be non-positive.
/// If the current container is empty, this function DOES pop that
/// container off the container stack, and returns the following
/// packet in the parent container.
///
/// The items of the tuple are returned in out-parameters.  If you do
/// not wish to receive the value, pass `NULL` as the parameter.
///
/// Consumes the given packet parser.
#[no_mangle]
pub extern "system" fn sq_packet_parser_next<'a>
    (ctx: Option<&mut Context>,
     pp: *mut PacketParser<'a>,
     old_packet: Option<&mut *mut Packet>,
     ppr: Option<&mut *mut PacketParserResult<'a>>)
     -> Status {
    let ctx = ctx.expect("Context is NULL");
    assert!(! pp.is_null());
    let pp = unsafe {
        Box::from_raw(pp)
    };

    match pp.next() {
        Ok((old_p, new_ppr)) => {
            if let Some(p) = old_packet {
                *p = box_raw!(old_p);
            }
            if let Some(p) = ppr {
                *p = box_raw!(new_ppr);
            }
            Status::Success
        },
        Err(e) => fry_status!(ctx, Err::<(), failure::Error>(e)),
    }
}

/// Finishes parsing the current packet and starts parsing the
/// next one, recursing if possible.
///
/// This method is similar to the [`next()`] method (see that
/// method for more details), but if the current packet is a
/// container (and we haven't reached the maximum recursion depth,
/// and the user hasn't started reading the packet's contents), we
/// recurse into the container, and return a `PacketParser` for
/// its first child.  Otherwise, we return the next packet in the
/// packet stream.  If this function recurses, then the new
/// packet's recursion depth will be `last_recursion_depth() + 1`;
/// because we always visit interior nodes, we can't recurse more
/// than one level at a time.
///
///   [`next()`]: #method.next
///
/// The items of the tuple are returned in out-parameters.  If you do
/// not wish to receive the value, pass `NULL` as the parameter.
///
/// Consumes the given packet parser.
#[no_mangle]
pub extern "system" fn sq_packet_parser_recurse<'a>
    (ctx: Option<&mut Context>,
     pp: *mut PacketParser<'a>,
     old_packet: Option<&mut *mut Packet>,
     ppr: Option<&mut *mut PacketParserResult<'a>>)
     -> Status {
    let ctx = ctx.expect("Context is NULL");
    assert!(! pp.is_null());
    let pp = unsafe {
        Box::from_raw(pp)
    };

    match pp.recurse() {
        Ok((old_p, new_ppr)) => {
            if let Some(p) = old_packet {
                *p = box_raw!(old_p);
            }
            if let Some(p) = ppr {
                *p = box_raw!(new_ppr);
            }
            Status::Success
        },
        Err(e) => fry_status!(ctx, Err::<(), failure::Error>(e)),
    }
}

/// Causes the PacketParser to buffer the packet's contents.
///
/// The packet's contents are stored in `packet.content`.  In
/// general, you should avoid buffering a packet's content and
/// prefer streaming its content unless you are certain that the
/// content is small.
#[no_mangle]
pub extern "system" fn sq_packet_parser_buffer_unread_content<'a>
    (ctx: Option<&mut Context>,
     pp: Option<&mut PacketParser<'a>>,
     len: Option<&mut usize>)
     -> *const uint8_t {
    let ctx = ctx.expect("Context is NULL");
    let pp = pp.expect("PacketParser is NULL");
    let len = len.expect("Length pointer is NULL");
    let buf = fry!(ctx, pp.buffer_unread_content());
    *len = buf.len();
    buf.as_ptr()
}

/// Finishes parsing the current packet.
///
/// By default, this drops any unread content.  Use, for instance,
/// `PacketParserBuild` to customize the default behavior.
#[no_mangle]
pub extern "system" fn sq_packet_parser_finish<'a>
    (ctx: Option<&mut Context>, pp: Option<&mut PacketParser<'a>>,
     packet: Option<&mut *const Packet>)
     -> Status
{
    let ctx = ctx.expect("Context is NULL");
    let pp = pp.expect("PacketParser is NULL");
    match pp.finish() {
        Ok(p) => {
            if let Some(out_p) = packet {
                *out_p = p;
            }
            Status::Success
        },
        Err(e) => {
            let status = Status::from(&e);
            ctx.e = Some(e);
            status
        },
    }
}

/// Tries to decrypt the current packet.
///
/// On success, this function pushes one or more readers onto the
/// `PacketParser`'s reader stack, and sets the packet's
/// `decrypted` flag.
///
/// If this function is called on a packet that does not contain
/// encrypted data, or some of the data was already read, then it
/// returns `Error::InvalidOperation`.
#[no_mangle]
pub extern "system" fn sq_packet_parser_decrypt<'a>
    (ctx: Option<&mut Context>,
     pp: Option<&mut PacketParser<'a>>,
     algo: uint8_t, // XXX
     key: *const uint8_t, key_len: size_t)
     -> Status {
    let ctx = ctx.expect("Context is NULL");
    let pp = pp.expect("PacketParser is NULL");
    let key = unsafe {
        slice::from_raw_parts(key, key_len as usize)
    };
    let key = key.to_owned().into();
    fry_status!(ctx, pp.decrypt((algo as u8).into(), &key))
}


/* PacketParserResult.  */

/// If the `PacketParserResult` contains a `PacketParser`, returns it,
/// otherwise, returns NULL.
///
/// If the `PacketParser` reached EOF, then the `PacketParserResult`
/// contains a `PacketParserEOF` and you should use
/// `sq_packet_parser_result_eof` to get it.
///
/// If this function returns a `PacketParser`, then it consumes the
/// `PacketParserResult` and ownership of the `PacketParser` is
/// returned to the caller, i.e., the caller is responsible for
/// ensuring that the `PacketParser` is freed.
#[no_mangle]
pub extern "system" fn sq_packet_parser_result_packet_parser<'a>
    (ppr: *mut PacketParserResult<'a>)
    -> *mut PacketParser<'a>
{
    assert!(! ppr.is_null());
    let ppr = unsafe {
        Box::from_raw(ppr)
    };

    match *ppr {
        PacketParserResult::Some(pp) => box_raw!(pp),
        PacketParserResult::EOF(_) => {
            // Don't free ppr!
            forget(ppr);
            ptr::null_mut()
        }
    }
}

/// If the `PacketParserResult` contains a `PacketParserEOF`, returns
/// it, otherwise, returns NULL.
///
/// If the `PacketParser` did not yet reach EOF, then the
/// `PacketParserResult` contains a `PacketParser` and you should use
/// `sq_packet_parser_result_packet_parser` to get it.
///
/// If this function returns a `PacketParserEOF`, then it consumes the
/// `PacketParserResult` and ownership of the `PacketParserEOF` is
/// returned to the caller, i.e., the caller is responsible for
/// ensuring that the `PacketParserEOF` is freed.
#[no_mangle]
pub extern "system" fn sq_packet_parser_result_eof<'a>
    (ppr: *mut PacketParserResult<'a>)
    -> *mut PacketParserEOF
{
    assert!(! ppr.is_null());
    let ppr = unsafe {
        Box::from_raw(ppr)
    };

    match *ppr {
        PacketParserResult::Some(_) => {
            forget(ppr);
            ptr::null_mut()
        }
        PacketParserResult::EOF(eof) => box_raw!(eof),
    }
}

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
#[no_mangle]
pub extern "system" fn sq_writer_stack_message
    (writer: *mut Box<Write>)
     -> *mut writer::Stack<'static, Cookie>
{
    assert!(!writer.is_null());
    let writer = unsafe {
        Box::from_raw(writer)
    };
    box_raw!(Message::new(writer))
}

/// Writes up to `len` bytes of `buf` into `writer`.
#[no_mangle]
pub extern "system" fn sq_writer_stack_write
    (ctx: Option<&mut Context>,
     writer: Option<&mut writer::Stack<'static, Cookie>>,
     buf: *const uint8_t, len: size_t)
     -> ssize_t
{
    let ctx = ctx.expect("Context is NULL");
    let writer = writer.expect("Writer is NULL");
    assert!(!buf.is_null());
    let buf = unsafe {
        slice::from_raw_parts(buf, len as usize)
    };
    fry_or!(ctx, writer.write(buf).map_err(|e| e.into()), -1) as ssize_t
}

/// Writes up to `len` bytes of `buf` into `writer`.
///
/// Unlike sq_writer_stack_write, unless an error occurs, the whole
/// buffer will be written.  Also, this version automatically catches
/// EINTR.
#[no_mangle]
pub extern "system" fn sq_writer_stack_write_all
    (ctx: Option<&mut Context>,
     writer: Option<&mut writer::Stack<'static, Cookie>>,
     buf: *const uint8_t, len: size_t)
     -> Status
{
    let ctx = ctx.expect("Context is NULL");
    let writer = writer.expect("Writer is NULL");
    assert!(!buf.is_null());
    let buf = unsafe {
        slice::from_raw_parts(buf, len as usize)
    };
    fry_status!(ctx, writer.write_all(buf).map_err(|e| e.into()))
}

/// Finalizes this writer, returning the underlying writer.
#[no_mangle]
pub extern "system" fn sq_writer_stack_finalize_one
    (ctx: Option<&mut Context>,
     writer: *mut writer::Stack<'static, Cookie>)
     -> *mut writer::Stack<'static, Cookie>
{
    let ctx = ctx.expect("Context is NULL");
    if !writer.is_null() {
        let writer = unsafe {
            Box::from_raw(writer)
        };
        maybe_box_raw!(fry!(ctx, writer.finalize_one()))
    } else {
        ptr::null_mut()
    }
}

/// Finalizes all writers, tearing down the whole stack.
#[no_mangle]
pub extern "system" fn sq_writer_stack_finalize
    (ctx: Option<&mut Context>,
     writer: *mut writer::Stack<'static, Cookie>)
     -> Status
{
    let ctx = ctx.expect("Context is NULL");
    if !writer.is_null() {
        let writer = unsafe {
            Box::from_raw(writer)
        };
        fry_status!(ctx, writer.finalize())
    } else {
        Status::Success
    }
}

/// Writes an arbitrary packet.
///
/// This writer can be used to construct arbitrary OpenPGP packets.
/// The body will be written using partial length encoding, or, if the
/// body is short, using full length encoding.
#[no_mangle]
pub extern "system" fn sq_arbitrary_writer_new
    (ctx: Option<&mut Context>,
     inner: *mut writer::Stack<'static, Cookie>,
     tag: uint8_t)
     -> *mut writer::Stack<'static, Cookie>
{
    let ctx = ctx.expect("Context is NULL");
    assert!(!inner.is_null());
    let inner = unsafe {
        Box::from_raw(inner)
    };
    fry_box!(ctx, ArbitraryWriter::new(*inner, tag.into()))
}

/// Signs a packet stream.
///
/// For every signing key, a signer writes a one-pass-signature
/// packet, then hashes and emits the data stream, then for every key
/// writes a signature packet.
#[no_mangle]
pub extern "system" fn sq_signer_new
    (ctx: Option<&mut Context>,
     inner: *mut writer::Stack<'static, Cookie>,
     signers: Option<&&'static TPK>, signers_len: size_t)
     -> *mut writer::Stack<'static, Cookie>
{
    let ctx = ctx.expect("Context is NULL");
    assert!(!inner.is_null());
    let inner = unsafe {
        Box::from_raw(inner)
    };
    let signers = signers.expect("Signers is NULL");
    let signers = unsafe {
        slice::from_raw_parts(signers, signers_len)
    };
    fry_box!(ctx, Signer::new(*inner, &signers))
}

/// Creates a signer for a detached signature.
#[no_mangle]
pub extern "system" fn sq_signer_new_detached
    (ctx: Option<&mut Context>,
     inner: *mut writer::Stack<'static, Cookie>,
     signers: Option<&&'static TPK>, signers_len: size_t)
     -> *mut writer::Stack<'static, Cookie>
{
    let ctx = ctx.expect("Context is NULL");
    assert!(!inner.is_null());
    let inner = unsafe {
        Box::from_raw(inner)
    };
    let signers = signers.expect("Signers is NULL");
    let signers = unsafe {
        slice::from_raw_parts(signers, signers_len)
    };
    fry_box!(ctx, Signer::detached(*inner, &signers))
}

/// Writes a literal data packet.
///
/// The body will be written using partial length encoding, or, if the
/// body is short, using full length encoding.
#[no_mangle]
pub extern "system" fn sq_literal_writer_new
    (ctx: Option<&mut Context>,
     inner: *mut writer::Stack<'static, Cookie>)
     -> *mut writer::Stack<'static, Cookie>
{
    let ctx = ctx.expect("Context is NULL");
    assert!(!inner.is_null());
    let inner = unsafe {
        Box::from_raw(inner)
    };
    fry_box!(ctx, LiteralWriter::new(*inner,
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
#[no_mangle]
pub extern "system" fn sq_encryptor_new
    (ctx: Option<&mut Context>,
     inner: *mut writer::Stack<'static, Cookie>,
     passwords: Option<&*const c_char>, passwords_len: size_t,
     recipients: Option<&&TPK>, recipients_len: size_t,
     encryption_mode: uint8_t)
     -> *mut writer::Stack<'static, Cookie>
{
    let ctx = ctx.expect("Context is NULL");
    assert!(!inner.is_null());
    let inner = unsafe {
        Box::from_raw(inner)
    };
    let mut passwords_ = Vec::new();
    if passwords_len > 0 {
        let passwords = passwords.expect("Passwords is NULL");
        let passwords = unsafe {
            slice::from_raw_parts(passwords, passwords_len)
        };
        for password in passwords {
            passwords_.push(unsafe {
                CStr::from_ptr(*password)
            }.to_bytes().to_owned().into());
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
    fry_box!(ctx, Encryptor::new(*inner,
                                 &passwords_.iter().collect::<Vec<&Password>>(),
                                 &recipients,
                                 encryption_mode))
}

// Secret.

/// Creates an sq_secret_t from a decrypted session key.
#[no_mangle]
pub fn sq_secret_cached<'a>(algo: u8,
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
#[no_mangle]
pub fn sq_verification_results_at_level<'a>(results: Option<&'a VerificationResults>,
                                            level: size_t,
                                            r: Option<&mut *const &'a VerificationResult>,
                                            r_count: Option<&mut size_t>) {
    let results = results.expect("results is NULL");
    let r = r.expect("r is NULL");
    let r_count = r_count.expect("r_count is NULL");

    assert!(level < results.results.len());

    // The size of VerificationResult is not known in C.  Convert from
    // an array of VerificationResult to an array of
    // VerificationResult refs.
    *r = results.results[level].as_ptr();
    *r_count = results.results[level].len();
}

/// Returns the verification result code.
#[no_mangle]
pub fn sq_verification_result_code(result: Option<&VerificationResult>)
    -> c_int
{
    let result = result.expect("result is NULL");
    match result {
        VerificationResult::GoodChecksum(_) => 1,
        VerificationResult::MissingKey(_) => 2,
        VerificationResult::BadChecksum(_) => 3,
    }
}

/// Returns the verification result code.
#[no_mangle]
pub fn sq_verification_result_signature(result: Option<&VerificationResult>)
    -> *const packet::Signature
{
    let result = result.expect("result is NULL");
    let sig = match result {
        VerificationResult::GoodChecksum(ref sig) => sig,
        VerificationResult::MissingKey(ref sig) => sig,
        VerificationResult::BadChecksum(ref sig) => sig,
    };

    sig as *const packet::Signature
}

/// Returns the verification result code.
#[no_mangle]
pub fn sq_verification_result_level(result: Option<&VerificationResult>)
    -> c_int
{
    let result = result.expect("result is NULL");
    result.level() as c_int
}


/// Passed as the first argument to the callbacks used by sq_verify
/// and sq_decrypt.
pub struct HelperCookie {
}

/// How to free the memory allocated by the callback.
type FreeCallback = fn(*mut c_void);

/// Returns the TPKs corresponding to the passed KeyIDs.
///
/// If the free callback is not NULL, then it is called to free the
/// returned array of TPKs.
type GetPublicKeysCallback = fn(*mut HelperCookie,
                                *const &KeyID, usize,
                                &mut *mut &mut TPK, *mut usize,
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
    fn get_public_keys(&mut self, ids: &[KeyID])
        -> Result<Vec<TPK>, failure::Error>
    {
        // The size of KeyID is not known in C.  Convert from an array
        // of KeyIDs to an array of KeyID refs.
        let ids : Vec<&KeyID> = ids.iter().collect();

        let mut tpk_refs_raw : *mut &mut TPK = ptr::null_mut();
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
        let mut tpks : Vec<TPK> = Vec::with_capacity(tpk_refs_raw_len);
        for i in 0..tpk_refs_raw_len {
            let tpk = unsafe { ptr::read(*tpk_refs_raw.offset(i as isize)) };
            tpks.push(tpk);
        }

        forget(tpk_refs_raw);
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

fn verify_real<'a>(input: &'a mut Box<'a + Read>,
                   output: Option<&'a mut Box<'a + Write>>,
                   get_public_keys: GetPublicKeysCallback,
                   check_signatures: CheckSignaturesCallback,
                   cookie: *mut HelperCookie)
    -> Result<(), failure::Error>
{
    let h = VHelper::new(get_public_keys, check_signatures, cookie);
    let mut v = Verifier::from_reader(input, h)?;

    let r = if let Some(output) = output {
        io::copy(&mut v, output)
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
        e.into()
    }).context("Verification failed")?;

    Ok(())
}


/// Verifies an OpenPGP message.
///
/// No attempt is made to decrypt any encryption packets.  These are
/// treated as opaque containers.
///
/// Note: output may be NULL, if the output is not required.
#[no_mangle]
pub fn sq_verify<'a>(ctx: Option<&mut Context>,
                     input: Option<&'a mut Box<'a + Read>>,
                     output: Option<&'a mut Box<'a + Write>>,
                     get_public_keys: GetPublicKeysCallback,
                     check_signatures: CheckSignaturesCallback,
                     cookie: *mut HelperCookie)
    -> Status
{
    let ctx = ctx.expect("Context is NULL");
    let input = input.expect("Input is NULL");

    let r = verify_real(input, output,
        get_public_keys, check_signatures, cookie);

    fry_status!(ctx, r)
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
    fn get_public_keys(&mut self, ids: &[KeyID])
        -> Result<Vec<TPK>, failure::Error>
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

        let secret = unsafe {
            Box::from_raw(secret)
        };

        Ok(Some(*secret))
    }
}

// A helper function that returns a Result so that we can use ? to
// propagate errors.
fn decrypt_real<'a>(input: &'a mut Box<'a + Read>,
                    output: &'a mut Box<'a + Write>,
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

    io::copy(&mut decryptor, output)
        .map_err(|e| if e.get_ref().is_some() {
            // Wrapped failure::Error.  Recover it.
            failure::Error::from_boxed_compat(e.into_inner().unwrap())
        } else {
            // Plain io::Error.
            e.into()
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
#[no_mangle]
pub fn sq_decrypt<'a>(ctx: Option<&mut Context>,
                      input: Option<&'a mut Box<'a + Read>>,
                      output: Option<&'a mut Box<'a + Write>>,
                      get_public_keys: GetPublicKeysCallback,
                      get_secret_keys: GetSecretKeysCallback,
                      check_signatures: CheckSignaturesCallback,
                      cookie: *mut HelperCookie)
    -> Status
{
    let ctx = ctx.expect("Context is NULL");
    let input = input.expect("Input is NULL");
    let output = output.expect("Output is NULL");

    let r = decrypt_real(input, output,
        get_public_keys, get_secret_keys, check_signatures, cookie);

    fry_status!(ctx, r)
}
