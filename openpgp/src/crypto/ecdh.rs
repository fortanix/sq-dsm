//! Elliptic Curve Diffie-Hellman.

use crate::vec_truncate;
use crate::{Error, Result};

use crate::crypto::mem::Protected;
use crate::types::HashAlgorithm;

pub use crate::crypto::backend::ecdh::{encrypt, decrypt};
pub use crate::crypto::backend::ecdh::{encrypt_shared, decrypt_shared};
pub use crate::crypto::backend::ecdh::{aes_key_wrap, aes_key_unwrap};

/// Derives a secret key for session key wrapping.
///
/// See [Section 7 of RFC 6637].
///
///   [Section 7 of RFC 6637]: https://tools.ietf.org/html/rfc6637#section-7
pub fn kdf(x: &Protected, obits: usize, hash: HashAlgorithm, param: &[u8])
           -> Result<Protected> {
    let mut hash = hash.context()?;
    if obits > hash.digest_size() {
        return Err(
            Error::InvalidArgument("Hash digest too short".into()).into());
    }

    hash.update(&[0, 0, 0, 1]);
    hash.update(x);
    hash.update(param);

    // Providing a smaller buffer will truncate the digest.
    let mut key: Protected = vec![0; obits].into();
    hash.digest(&mut key);
    Ok(key)
}

/// Pads a session key using PKCS5.
///
/// See [Section 8 of RFC 6637].
///
///   [Section 8 of RFC 6637]: https://tools.ietf.org/html/rfc6637#section-8
pub fn pkcs5_pad(sk: Protected, target_len: usize) -> Protected {
    let mut buf: Vec<u8> = unsafe {
        sk.into_vec()
    };
    let missing = target_len - buf.len();
    assert!(missing <= 0xff);
    for _ in 0..missing {
        buf.push(missing as u8);
    }
    assert_eq!(buf.len(), target_len);
    buf.into()
}

/// Removes PKCS5 padding from a session key.
///
/// See [Section 8 of RFC 6637].
///
///   [Section 8 of RFC 6637]: https://tools.ietf.org/html/rfc6637#section-8
pub fn pkcs5_unpad(sk: Protected, target_len: usize) -> Result<Protected> {
    if sk.len() > 0xff {
        return Err(Error::InvalidArgument("message too large".into()).into());
    }

    if sk.len() < target_len {
        return Err(Error::InvalidArgument("message too small".into()).into());
    }

    let mut buf: Vec<u8> = unsafe {
        sk.into_vec()
    };
    let mut good = true;
    let missing = (buf.len() - target_len) as u8;
    for &b in &buf[target_len..] {
        good = b == missing && good;
    }

    if good {
        vec_truncate(&mut buf, target_len);
        Ok(buf.into())
    } else {
        let sk: Protected = buf.into();
        drop(sk);
        Err(Error::InvalidArgument("bad padding".into()).into())
    }
}
