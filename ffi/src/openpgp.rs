//! XXX

use failure;
use std::ffi::{CString, CStr};
use std::hash::{Hash, Hasher};
use std::ptr;
use std::slice;
use std::io::{Read, Write};
use libc::{uint8_t, uint64_t, c_char, c_int, size_t};

extern crate openpgp;

use self::openpgp::{armor, Fingerprint, KeyID, PacketPile, TPK, Packet};
use self::openpgp::parse::{PacketParser};
use self::openpgp::serialize::Serialize;

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
        2 => armor::Kind::SecretKey,
        3 => armor::Kind::Signature,
        4 => armor::Kind::File,
        5 => armor::Kind::Any,
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

/// Computes and returns the key's fingerprint as per Section 12.2
/// of RFC 4880.
#[no_mangle]
pub extern "system" fn sq_p_key_fingerprint(key: Option<&Packet>)
                                            -> *mut Fingerprint {
    let key = key.expect("Key is NULL");
    match key {
        &Packet::PublicKey(ref key) => box_raw!(key.fingerprint()),
        &Packet::PublicSubkey(ref key) => box_raw!(key.fingerprint()),
        &Packet::SecretKey(ref key) => box_raw!(key.fingerprint()),
        &Packet::SecretSubkey(ref key) => box_raw!(key.fingerprint()),
        _ => panic!("Not a Key packet"),
    }
}

/// Computes and returns the key's key ID as per Section 12.2 of RFC
/// 4880.
#[no_mangle]
pub extern "system" fn sq_p_key_keyid(key: Option<&Packet>)
                                      -> *mut KeyID {
    let key = key.expect("Key is NULL");
    match key {
        &Packet::PublicKey(ref key) => box_raw!(key.keyid()),
        &Packet::PublicSubkey(ref key) => box_raw!(key.keyid()),
        &Packet::SecretKey(ref key) => box_raw!(key.keyid()),
        &Packet::SecretSubkey(ref key) => box_raw!(key.keyid()),
        _ => panic!("Not a Key packet"),
    }
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
            *p = uid.value.len();
        }
        uid.value.as_ptr()
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
            *p = ua.value.len();
        }
        ua.value.as_ptr()
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
        match skesk.decrypt(password) {
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

/* openpgp::parse.  */

/// Starts parsing OpenPGP packets stored in a `sq_reader_t`
/// object.
///
/// This function returns a `PacketParser` for the first packet in
/// the stream.
#[no_mangle]
pub extern "system" fn sq_packet_parser_from_reader<'a>
    (ctx: Option<&mut Context>, reader: Option<&'a mut Box<'a + Read>>)
     -> *mut PacketParser<'a> {
    let ctx = ctx.expect("Context is NULL");
    let reader = reader.expect("Reader is NULL");
    fry!(ctx, PacketParser::from_reader(reader))
        .map(|v| box_raw!(v))
        .unwrap_or(ptr::null_mut())
}

/// Starts parsing OpenPGP packets stored in a file named `path`.
///
/// This function returns a `PacketParser` for the first packet in
/// the stream.
#[no_mangle]
pub extern "system" fn sq_packet_parser_from_file
    (ctx: Option<&mut Context>, filename: *const c_char)
     -> *mut PacketParser {
    let ctx = ctx.expect("Context is NULL");
    assert!(! filename.is_null());
    let filename = unsafe {
        CStr::from_ptr(filename).to_string_lossy().into_owned()
    };
    fry!(ctx, PacketParser::from_file(&filename))
        .map(|v| box_raw!(v))
        .unwrap_or(ptr::null_mut())
}

/// Starts parsing OpenPGP packets stored in a buffer.
///
/// This function returns a `PacketParser` for the first packet in
/// the stream.
#[no_mangle]
pub extern "system" fn sq_packet_parser_from_bytes
    (ctx: Option<&mut Context>, b: *const uint8_t, len: size_t)
     -> *mut PacketParser {
    let ctx = ctx.expect("Context is NULL");
    assert!(!b.is_null());
    let buf = unsafe {
        slice::from_raw_parts(b, len as usize)
    };

    fry!(ctx, PacketParser::from_bytes(buf))
        .map(|v| box_raw!(v))
        .unwrap_or(ptr::null_mut())
}

/// Frees the packet parser.
#[no_mangle]
pub extern "system" fn sq_packet_parser_free(pp: *mut PacketParser) {
    if pp.is_null() { return }
    unsafe {
        drop(Box::from_raw(pp));
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
    pp.recursion_depth
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
     old_recursion_level: Option<&mut isize>,
     ppo: Option<&mut *mut PacketParser<'a>>,
     new_recursion_level: Option<&mut isize>)
     -> Status {
    let ctx = ctx.expect("Context is NULL");
    assert!(! pp.is_null());
    let pp = unsafe {
        Box::from_raw(pp)
    };

    match pp.next() {
        Ok((old_p, old_rl, pp, new_rl)) => {
            if let Some(p) = old_packet {
                *p = box_raw!(old_p);
            }
            if let Some(p) = old_recursion_level {
                *p = old_rl;
            }
            if let Some(p) = ppo {
                *p = maybe_box_raw!(pp);
            }
            if let Some(p) = new_recursion_level {
                *p = new_rl;
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
/// packet's position will be old_position + 1; because we always
/// visit interior nodes, we can't recurse more than one level at
/// a time.
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
     old_recursion_level: Option<&mut isize>,
     ppo: Option<&mut *mut PacketParser<'a>>,
     new_recursion_level: Option<&mut isize>)
     -> Status {
    let ctx = ctx.expect("Context is NULL");
    assert!(! pp.is_null());
    let pp = unsafe {
        Box::from_raw(pp)
    };

    match pp.recurse() {
        Ok((old_p, old_rl, pp, new_rl)) => {
            if let Some(p) = old_packet {
                *p = box_raw!(old_p);
            }
            if let Some(p) = old_recursion_level {
                *p = old_rl;
            }
            if let Some(p) = ppo {
                *p = maybe_box_raw!(pp);
            }
            if let Some(p) = new_recursion_level {
                *p = new_rl;
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
    fry_status!(ctx, pp.decrypt((algo as u8).into(), key))
}
