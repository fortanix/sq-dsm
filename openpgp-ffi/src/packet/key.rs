//! Public key, public subkey, private key and private subkey packets.
//!
//! See [Section 5.5 of RFC 4880] for details.
//!
//!   [Section 5.5 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-5.5

use libc::{c_int, time_t};

extern crate sequoia_openpgp as openpgp;
use super::super::fingerprint::Fingerprint;
use super::super::keyid::KeyID;

use MoveFromRaw;
use MoveIntoRaw;
use RefRaw;

/// Holds a public key, public subkey, private key or private subkey packet.
///
/// See [Section 5.5 of RFC 4880] for details.
///
///   [Section 5.5 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-5.5
///
/// Wraps [`sequoia-openpgp::packet::key::Key`].
///
/// [`sequoia-openpgp::packet::key::Key`]: ../../sequoia_openpgp/packet/key/struct.Key.html
#[::ffi_wrapper_type(prefix = "pgp_",
                     derive = "Clone, Debug, PartialEq, Parse")]
pub struct Key(openpgp::packet::Key);

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

    ct.to_timespec().sec as time_t
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
    use self::openpgp::crypto::mpis::PublicKey::*;

    let key = key.ref_raw();
    match key.mpis() {
        RSA { e: _, n } => n.bits as c_int,
        DSA { p: _, q: _, g: _, y } => y.bits as c_int,
        Elgamal { p: _, g: _, y } => y.bits as c_int,
        EdDSA { curve: _, q } => q.bits as c_int,
        ECDSA { curve: _, q } =>  q.bits as c_int,
        ECDH { curve: _, q, hash: _, sym: _ } =>  q.bits as c_int,
        Unknown { mpis: _, rest: _ } => 0,
    }
}

/// Creates a new key pair from a Key packet with an unencrypted
/// secret key.
///
/// # Errors
///
/// Fails if the secret key is missing, or encrypted.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle] pub extern "C"
fn pgp_key_into_key_pair(errp: Option<&mut *mut ::error::Error>,
                         key: *mut Key)
                         -> *mut self::openpgp::crypto::KeyPair {
    ffi_make_fry_from_errp!(errp);
    ffi_try_box!(key.move_from_raw().into_keypair())
}
