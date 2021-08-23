//! OpenPGP packet parser.
//!
//! Wraps [`sequoia-openpgp::parse::PacketParser`] and [related
//! functionality].
//!
//! [`sequoia-openpgp::parse::PacketParser`]: super::super::super::sequoia_openpgp::parse::PacketParser
//! [related functionality]: super::super::super::sequoia_openpgp::parse

use std::mem::forget;
use std::ptr;
use std::slice;
use libc::{c_char, c_int, size_t};

use sequoia_openpgp as openpgp;

use super::packet::{
    Packet,
};
use self::openpgp::parse::{
    Parse,
    PacketParserResult,
    PacketParser,
    PacketParserEOF,
};

use super::io::Reader;
use crate::error::Status;
use crate::MoveIntoRaw;
use crate::RefMutRaw;

pub mod stream;

/// Starts parsing OpenPGP packets stored in a `pgp_reader_t`
/// object.
///
/// This function returns a `PacketParser` for the first packet in
/// the stream.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle]
pub extern "C" fn pgp_packet_parser_from_reader<'a>
    (errp: Option<&mut *mut crate::error::Error>, reader: *mut Reader)
     -> *mut PacketParserResult<'a> {
    ffi_make_fry_from_errp!(errp);
    let reader = reader.ref_mut_raw();
    ffi_try_box!(PacketParser::from_reader(reader))
}

/// Starts parsing OpenPGP packets stored in a file named `path`.
///
/// This function returns a `PacketParser` for the first packet in
/// the stream.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle]
pub extern "C" fn pgp_packet_parser_from_file
    (errp: Option<&mut *mut crate::error::Error>, filename: *const c_char)
     -> *mut PacketParserResult<'static> {
    ffi_make_fry_from_errp!(errp);
    let filename = ffi_param_cstr!(filename).to_string_lossy().into_owned();
    ffi_try_box!(PacketParser::from_file(&filename))
}

/// Starts parsing OpenPGP packets stored in a buffer.
///
/// This function returns a `PacketParser` for the first packet in
/// the stream.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle]
pub extern "C" fn pgp_packet_parser_from_bytes
    (errp: Option<&mut *mut crate::error::Error>, b: *const u8, len: size_t)
     -> *mut PacketParserResult<'static> {
    ffi_make_fry_from_errp!(errp);
    assert!(!b.is_null());
    let buf = unsafe {
        slice::from_raw_parts(b, len as usize)
    };

    ffi_try_box!(PacketParser::from_bytes(buf))
}

/// Frees the packet parser result
#[::sequoia_ffi_macros::extern_fn] #[no_mangle]
pub extern "C" fn pgp_packet_parser_result_free(
    ppr: Option<&mut PacketParserResult>)
{
    ffi_free!(ppr)
}

/// Frees the packet parser.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle]
pub extern "C" fn pgp_packet_parser_free(pp: Option<&mut PacketParser>) {
    ffi_free!(pp)
}

/// Frees the packet parser EOF object.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle]
pub extern "C" fn pgp_packet_parser_eof_is_message(
    errp: Option<&mut *mut crate::error::Error>,
    eof: *const PacketParserEOF) -> bool
{
    ffi_make_fry_from_errp!(errp);
    let eof = ffi_param_ref!(eof);
    ffi_try_or!(eof.is_message(), false);
    true
}

/// Frees the packet parser EOF object.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle]
pub extern "C" fn pgp_packet_parser_eof_free
    (eof: Option<&mut PacketParserEOF>)
{
    ffi_free!(eof)
}

/// Returns a reference to the packet that is being parsed.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle]
pub extern "C" fn pgp_packet_parser_packet
    (pp: *const PacketParser)
     -> *const Packet {
    let pp = ffi_param_ref!(pp);
    (&pp.packet).move_into_raw()
}

/// Returns the current packet's recursion depth.
///
/// A top-level packet has a recursion depth of 0.  Packets in a
/// top-level container have a recursion depth of 1, etc.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle]
pub extern "C" fn pgp_packet_parser_recursion_depth
    (pp: *const PacketParser)
     -> u8 {
    let pp = ffi_param_ref!(pp);
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
///   [`PacketParsererBuilder`]: super::super::super::sequoia_openpgp::parse::PacketParserBuilder
///   [`recurse()`]: pgp_packet_parser_recurse()
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
#[::sequoia_ffi_macros::extern_fn] #[no_mangle]
pub extern "C" fn pgp_packet_parser_next<'a>
    (errp: Option<&mut *mut crate::error::Error>,
     pp: *mut PacketParser<'a>,
     old_packet: Option<&mut *mut Packet>,
     ppr: Option<&mut *mut PacketParserResult<'a>>)
     -> Status {
    ffi_make_fry_from_errp!(errp);
    let pp = ffi_param_move!(pp);

    match pp.next() {
        Ok((old_p, new_ppr)) => {
            if let Some(p) = old_packet {
                *p = old_p.move_into_raw();
            }
            if let Some(p) = ppr {
                *p = box_raw!(new_ppr);
            }
            Status::Success
        },
        Err(e) => ffi_try_status!(Err::<(), anyhow::Error>(e)),
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
///   [`next()`]: pgp_packet_parser_next()
///
/// The items of the tuple are returned in out-parameters.  If you do
/// not wish to receive the value, pass `NULL` as the parameter.
///
/// Consumes the given packet parser.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle]
pub extern "C" fn pgp_packet_parser_recurse<'a>
    (errp: Option<&mut *mut crate::error::Error>,
     pp: *mut PacketParser<'a>,
     old_packet: Option<&mut *mut Packet>,
     ppr: Option<&mut *mut PacketParserResult<'a>>)
     -> Status {
    ffi_make_fry_from_errp!(errp);
    let pp = ffi_param_move!(pp);

    match pp.recurse() {
        Ok((old_p, new_ppr)) => {
            if let Some(p) = old_packet {
                *p = old_p.move_into_raw();
            }
            if let Some(p) = ppr {
                *p = box_raw!(new_ppr);
            }
            Status::Success
        },
        Err(e) => ffi_try_status!(Err::<(), anyhow::Error>(e)),
    }
}

/// Causes the PacketParser to buffer the packet's contents.
///
/// The packet's contents are stored in `packet.content`.  In
/// general, you should avoid buffering a packet's content and
/// prefer streaming its content unless you are certain that the
/// content is small.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle]
pub extern "C" fn pgp_packet_parser_buffer_unread_content<'a>
    (errp: Option<&mut *mut crate::error::Error>,
     pp: *mut PacketParser<'a>,
     len: *mut usize)
     -> *const u8 {
    ffi_make_fry_from_errp!(errp);
    let pp = ffi_param_ref_mut!(pp);
    let len = ffi_param_ref_mut!(len);
    let buf = ffi_try!(pp.buffer_unread_content());
    *len = buf.len();
    buf.as_ptr()
}

/// Finishes parsing the current packet.
///
/// By default, this drops any unread content.  Use, for instance,
/// `PacketParserBuild` to customize the default behavior.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle]
pub extern "C" fn pgp_packet_parser_finish<'a>
    (errp: Option<&mut *mut crate::error::Error>, pp: *mut PacketParser<'a>,
     packet: Option<&mut *const Packet>)
     -> Status
{
    ffi_make_fry_from_errp!(errp);
    let pp = ffi_param_ref_mut!(pp);
    match pp.finish() {
        Ok(p) => {
            if let Some(out_p) = packet {
                *out_p = p.move_into_raw();
            }
            Status::Success
        },
        Err(e) => {
            let status = Status::from(&e);
            if let Some(errp) = errp {
                *errp = e.move_into_raw();
            }
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
#[::sequoia_ffi_macros::extern_fn] #[no_mangle]
pub extern "C" fn pgp_packet_parser_decrypt<'a>
    (errp: Option<&mut *mut crate::error::Error>,
     pp: *mut PacketParser<'a>,
     algo: u8, // XXX
     key: *const u8, key_len: size_t)
     -> Status {
    ffi_make_fry_from_errp!(errp);
    let pp = ffi_param_ref_mut!(pp);
    let key = unsafe {
        slice::from_raw_parts(key, key_len as usize)
    };
    let key = key.to_owned().into();
    ffi_try_status!(pp.decrypt((algo as u8).into(), &key))
}


/* PacketParserResult.  */

/// Returns the current packet's tag.
///
/// This is a convenience function to inspect the containing packet,
/// without turning the `PacketParserResult` into a `PacketParser`.
///
/// This function does not consume the ppr.
///
/// Returns 0 if the PacketParserResult does not contain a packet.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle]
pub extern "C" fn pgp_packet_parser_result_tag<'a>
    (ppr: *mut PacketParserResult<'a>)
    -> c_int
{
    let ppr = ffi_param_ref_mut!(ppr);

    let tag : u8 = match ppr {
        PacketParserResult::Some(ref pp) => pp.packet.tag().into(),
        PacketParserResult::EOF(_) => 0,
    };

    tag as c_int
}

/// If the `PacketParserResult` contains a `PacketParser`, returns it,
/// otherwise, returns NULL.
///
/// If the `PacketParser` reached EOF, then the `PacketParserResult`
/// contains a `PacketParserEOF` and you should use
/// `pgp_packet_parser_result_eof` to get it.
///
/// If this function returns a `PacketParser`, then it consumes the
/// `PacketParserResult` and ownership of the `PacketParser` is
/// returned to the caller, i.e., the caller is responsible for
/// ensuring that the `PacketParser` is freed.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle]
pub extern "C" fn pgp_packet_parser_result_packet_parser<'a>
    (ppr: *mut PacketParserResult<'a>)
    -> *mut PacketParser<'a>
{
    let ppr = ffi_param_move!(ppr);

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
/// `pgp_packet_parser_result_packet_parser` to get it.
///
/// If this function returns a `PacketParserEOF`, then it consumes the
/// `PacketParserResult` and ownership of the `PacketParserEOF` is
/// returned to the caller, i.e., the caller is responsible for
/// ensuring that the `PacketParserEOF` is freed.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle]
pub extern "C" fn pgp_packet_parser_result_eof<'a>
    (ppr: *mut PacketParserResult<'a>)
    -> *mut PacketParserEOF
{
    let ppr = ffi_param_move!(ppr);

    match *ppr {
        PacketParserResult::Some(_) => {
            forget(ppr);
            ptr::null_mut()
        }
        PacketParserResult::EOF(eof) => box_raw!(eof),
    }
}
