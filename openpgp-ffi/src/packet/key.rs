//! Public key, public subkey, private key and private subkey packets.
//!
//! See [Section 5.5 of RFC 4880] for details.
//!
//!   [Section 5.5 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-5.5

use libc::{c_int, time_t, size_t};
use std::slice;

use sequoia_openpgp as openpgp;
use self::openpgp::packet::key;
use self::openpgp::crypto::Password;
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
/// Wraps [`sequoia-openpgp::packet::Key`].
///
/// [`sequoia-openpgp::packet::key::Key`]: sequoia_openpgp::packet::Key
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
    let key = ffi_try!(key.move_from_raw().parts_into_secret());
    ffi_try_box!(key.into_keypair())
}

/// Returns whether the secret key material is unencrypted.
///
/// Returns false if there is no secret key material.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle] pub extern "C"
fn pgp_key_has_unencrypted_secret(key: *const Key) -> bool
{
    let key = key.ref_raw();
    key.has_unencrypted_secret()
}

/// Decrypts the secret key material.
///
/// `password` is a byte array.  `password_len` is its length.
///
/// Returns NULL if there is no secret key material, or the password
/// is incorrect.
///
/// This function takes ownership of `key`.  On failure, `key` is
/// deallocated.
///
/// # Examples
///
/// ```c
/// #include <assert.h>
/// #include <sequoia/openpgp.h>
///
/// pgp_cert_builder_t builder;
/// pgp_cert_t cert;
/// pgp_signature_t revocation;
/// pgp_key_t encrypted_primary_key;
/// pgp_key_t primary_key;
/// pgp_key_pair_t primary_keypair;
/// const uint8_t password[] = "foobar";
/// const size_t password_len = strlen ((char *) password);
///
/// builder = pgp_cert_builder_new ();
/// pgp_cert_builder_set_cipher_suite (&builder, PGP_CERT_CIPHER_SUITE_CV25519);
/// pgp_cert_builder_set_password (&builder, password, password_len);
/// pgp_cert_builder_generate (NULL, builder, &cert, &revocation);
/// assert (cert);
/// assert (revocation);
/// pgp_signature_free (revocation);    /* Free the generated one.  */
///
/// encrypted_primary_key = pgp_cert_primary_key (cert);
/// assert(! pgp_key_has_unencrypted_secret (encrypted_primary_key));
///
/// // This will fail, because primary_key is password protected.
/// primary_keypair
///   = pgp_key_into_key_pair (NULL, pgp_key_clone (encrypted_primary_key));
/// assert(! primary_keypair);
///
/// // Try decrypting it with the wrong password.
/// primary_key
///   = pgp_key_decrypt_secret (NULL, pgp_key_clone (encrypted_primary_key),
///                             password, password_len - 1);
/// assert(! primary_key);
///
/// // If we decrypt it, then we can create a keypair.
/// primary_key
///   = pgp_key_decrypt_secret (NULL, pgp_key_clone (encrypted_primary_key),
///                             password, password_len);
/// assert(primary_key);
/// assert(pgp_key_has_unencrypted_secret (primary_key));
///
/// primary_keypair
///   = pgp_key_into_key_pair (NULL, pgp_key_clone (primary_key));
/// assert(primary_keypair);
///
/// pgp_key_pair_free(primary_keypair);
/// pgp_key_free (primary_key);
/// pgp_key_free (encrypted_primary_key);
/// pgp_cert_free (cert);
/// ```
#[::sequoia_ffi_macros::extern_fn] #[no_mangle] pub extern "C"
fn pgp_key_decrypt_secret(errp: Option<&mut *mut crate::error::Error>,
                          key: *mut Key,
                          password: *const u8, password_len: size_t)
    -> *mut Key
{
    ffi_make_fry_from_errp!(errp);
    assert!(!password.is_null());
    let password = unsafe {
        slice::from_raw_parts(password, password_len as usize)
    };
    let password: Password = password.into();
    let key = ffi_try!(key.move_from_raw().parts_into_secret());

    ffi_try!(key.decrypt_secret(&password)).parts_into_unspecified().move_into_raw()
}
