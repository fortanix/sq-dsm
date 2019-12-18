//! Public key, public subkey, private key and private subkey packets.
//!
//! See [Section 5.5 of RFC 4880] for details.
//!
//!   [Section 5.5 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-5.5

use libc::{c_int, time_t};

extern crate sequoia_openpgp as openpgp;
use self::openpgp::packet::key;
use super::super::fingerprint::Fingerprint;
use super::super::keyid::KeyID;

use crate::MoveFromRaw;
use crate::MoveIntoRaw;
use crate::RefRaw;

/// A local alias to appease the proc macro transformation.
type UnspecifiedKey =
    openpgp::packet::Key<key::UnspecifiedParts, key::UnspecifiedRole>;

/// Holds a public key, public subkey, private key or private subkey packet.
///
/// See [Section 5.5 of RFC 4880] for details.
///
///   [Section 5.5 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-5.5
///
/// Wraps [`sequoia-openpgp::packet::key::Key`].
///
/// [`sequoia-openpgp::packet::key::Key`]: ../../sequoia_openpgp/packet/key/struct.Key.html
#[crate::ffi_wrapper_type(prefix = "pgp_",
                     derive = "Clone, Debug, PartialEq, Parse")]
pub struct Key(UnspecifiedKey);

/// Computes and returns the key's fingerprint as per Section 12.2
/// of RFC 4880.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle] pub extern "C"
fn pgp_key_fingerprint(key: *const Key) -> *mut Fingerprint {
    key.ref_raw().fingerprint().move_into_raw()
}

/// Computes and returns the key's key ID as per Section 12.2 of RFC
/// 4880.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle] pub extern "C"
fn pgp_key_keyid(key: *const Key) -> *mut KeyID {
    key.ref_raw().keyid().move_into_raw()
}

/// Returns the key's creation time.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle] pub extern "C"
fn pgp_key_creation_time(key: *const Key) -> time_t {
    let key = key.ref_raw();
    let ct = key.creation_time();

    ct.duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs())
        .unwrap_or(0) as time_t
}

/// Returns the key's public key algorithm.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle] pub extern "C"
fn pgp_key_public_key_algo(key: *const Key) -> c_int {
    let key = key.ref_raw();
    let pk_algo : u8 = key.pk_algo().into();
    pk_algo as c_int
}

/// Returns the public key's size in bits.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle] pub extern "C"
fn pgp_key_public_key_bits(key: *const Key) -> c_int {
    key.ref_raw().mpis().bits().unwrap_or(0) as c_int
}

/// Creates a new key pair from a Key packet with an unencrypted
/// secret key.
///
/// # Errors
///
/// Fails if the secret key is missing, or encrypted.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle] pub extern "C"
fn pgp_key_into_key_pair(errp: Option<&mut *mut crate::error::Error>,
                         key: *mut Key)
                         -> *mut self::openpgp::crypto::KeyPair
{
    ffi_make_fry_from_errp!(errp);
    let key = ffi_try!(key.move_from_raw().mark_parts_secret());
    ffi_try_box!(key.into_keypair())
}
