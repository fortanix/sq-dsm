//! Elliptic Curve Diffie-Hellman.

use Error;
use packet::Key;
use Result;
use constants::{
    Curve,
    HashAlgorithm,
    SymmetricAlgorithm,
    PublicKeyAlgorithm,
};
use mpis::{MPI, MPIs, PublicKey, SecretKey};
use nettle::{cipher, curve25519, mode, Mode, Yarrow};

/// Wraps a session key using Elliptic Curve Diffie-Hellman.
pub fn wrap_session_key(recipient: &Key, session_key: &[u8]) -> Result<MPIs> {
    if let Some(PublicKey::ECDH {
        ref curve, ref q, ref hash, ref sym
    }) = recipient.mpis {
        let mut rng = Yarrow::default();
        match curve {
            Curve::Cv25519 => {
                // Obtain the authenticated recipient public key R
                #[allow(non_snake_case)]
                let R = q.decode_point(curve)?.0;

                // Generate an ephemeral key pair {v, V=vG}
                let mut v = [0; curve25519::CURVE25519_SIZE];
                rng.random(&mut v);
                // Note: Nettle ignores the most significant and the three
                // least significant bits, therefore every value is a valid
                // secret key.

                // Compute the public key.  We need to add an encoding
                // octet in front of the key.
                #[allow(non_snake_case)]
                let mut VB = [0; 1 + curve25519::CURVE25519_SIZE];
                curve25519::mul_g(&mut VB[1..], &v)
                    .expect("buffers are of the wrong size");

                // Compute the shared point S = vR;
                #[allow(non_snake_case)]
                let mut S = [0; curve25519::CURVE25519_SIZE];
                curve25519::mul(&mut S, &v, R)
                    .expect("buffers are of the wrong size");

                // m = symm_alg_ID || session key || checksum || pkcs5_padding;
                let mut m = Vec::with_capacity(40);
                m.extend_from_slice(session_key);
                pkcs5_pad(&mut m, 40);
                // Note: We always pad up to 40 bytes to obfuscate the
                // length of the symmetric key.

                // Compute KDF input.
                let param = make_param(recipient, curve, hash, sym);

                // Z_len = the key size for the KEK_alg_ID used with AESKeyWrap
                // Compute Z = KDF( S, Z_len, Param );
                #[allow(non_snake_case)]
                let Z = kdf(&S, sym.key_size()?, *hash, &param)?;

                // Compute C = AESKeyWrap( Z, m ) as per [RFC3394]
                #[allow(non_snake_case)]
                let C = aes_key_wrap(*sym, &Z, &m)?;

                // VB = convert point V to the octet string
                VB[0] = 0x40; // Native encoding of the point.

                // Output (MPI(VB) || len(C) || C).
                Ok(MPIs::ECDHCiphertext {
                    e: MPI::new(&VB),
                    key: C.into_boxed_slice(),
                })
            },

            _ =>
                Err(Error::UnsupportedEllipticCurve(curve.clone()).into()),
        }
    } else {
        Err(Error::InvalidArgument("Expected an ECDHPublicKey".into()).into())
    }
}

/// Unwraps a session key using Elliptic Curve Diffie-Hellman.
pub fn unwrap_session_key(recipient: &Key, recipient_sec: &SecretKey,
                          ciphertext: &MPIs)
                          -> Result<Box<[u8]>> {
    if let (Some(PublicKey::ECDH {
        ref curve, ref hash, ref sym, ..
    }), SecretKey::ECDH {
        ref scalar,
    }, MPIs::ECDHCiphertext {
        ref e, ref key,
    }) = (&recipient.mpis, recipient_sec, ciphertext) {
        match curve {
            Curve::Cv25519 => {
                // Get the public part V of the ephemeral key.
                #[allow(non_snake_case)]
                let V = e.decode_point(curve)?.0;

                // Get the secret part r of our key.
                if scalar.value.len() != curve25519::CURVE25519_SIZE {
                    return Err(Error::MalformedPacket(
                        format!("Bad size of Curve25519 private key: {} \
                                 expected: {}", scalar.value.len(),
                                curve25519::CURVE25519_SIZE)).into());
                }

                // Reverse the scalar.  See
                // https://lists.gnupg.org/pipermail/gnupg-devel/2018-February/033437.html.
                let mut r_reversed = Vec::with_capacity(scalar.value.len());
                r_reversed.extend_from_slice(&scalar.value);
                &mut r_reversed.reverse();
                let r = &r_reversed;

                // Compute the shared point S = rV = rvG, where (r, R)
                // is the recipient's key pair.
                #[allow(non_snake_case)]
                let mut S = [0; curve25519::CURVE25519_SIZE];
                curve25519::mul(&mut S, r, V)
                    .expect("buffers are of the wrong size");

                // Compute KDF input.
                let param = make_param(recipient, curve, hash, sym);

                // Z_len = the key size for the KEK_alg_ID used with AESKeyWrap
                // Compute Z = KDF( S, Z_len, Param );
                #[allow(non_snake_case)]
                let Z = kdf(&S, sym.key_size()?, *hash, &param)?;

                // Compute m = AESKeyUnwrap( Z, C ) as per [RFC3394]
                let mut m = aes_key_unwrap(*sym, &Z, key)?;
                let cipher = SymmetricAlgorithm::from(m[0]);
                pkcs5_unpad(&mut m, 1 + cipher.key_size()? + 2)?;

                Ok(m.into_boxed_slice())
            },

            _ =>
                Err(Error::UnsupportedEllipticCurve(curve.clone()).into()),
        }
    } else {
        Err(Error::InvalidArgument("Expected an ECDHPublicKey".into()).into())
    }
}

fn make_param(recipient: &Key, curve: &Curve, hash: &HashAlgorithm,
              sym: &SymmetricAlgorithm) -> Vec<u8> {
    // Param = curve_OID_len || curve_OID ||
    // public_key_alg_ID || 03 || 01 || KDF_hash_ID ||
    // KEK_alg_ID for AESKeyWrap || "Anonymous Sender    " ||
    // recipient_fingerprint;
    let fp = recipient.fingerprint();

    let mut param = Vec::with_capacity(
        1 + curve.oid().len()        // Length and Curve OID,
            + 1                      // Public key algorithm ID,
            + 4                      // KDF parameters,
            + 20                     // "Anonymous Sender    ",
            + fp.as_slice().len());  // Recipients key fingerprint.

    param.push(curve.oid().len() as u8);
    param.extend_from_slice(curve.oid());
    param.push(PublicKeyAlgorithm::ECDH.into());
    param.push(3);
    param.push(1);
    param.push((*hash).into());
    param.push((*sym).into());
    param.extend_from_slice(b"Anonymous Sender    ");
    param.extend_from_slice(fp.as_slice());
    assert_eq!(param.len(),
               1 + curve.oid().len()    // Length and Curve OID,
               + 1                      // Public key algorithm ID,
               + 4                      // KDF parameters,
               + 20                     // "Anonymous Sender    ",
               + fp.as_slice().len());  // Recipients key fingerprint.

    param
}

/// Derives a secret key for session key wrapping.
///
/// See [Section 7 of RFC 6637].
///
///   [Section 7 of RFC 6637]: https://tools.ietf.org/html/rfc6637#section-7
pub fn kdf(x: &[u8], obits: usize, hash: HashAlgorithm, param: &[u8])
           -> Result<Vec<u8>> {
    let mut hash = hash.context()?;
    if obits > hash.digest_size() {
        return Err(
            Error::InvalidArgument("Hash digest too short".into()).into());
    }

    hash.update(&[0, 0, 0, 1]);
    hash.update(x);
    hash.update(param);

    // Providing a smaller buffer will truncate the digest.
    let mut key = vec![0; obits];
    hash.digest(&mut key);
    Ok(key)
}

/// Pads a session key using PKCS5.
///
/// See [Section 8 of RFC 6637].
///
///   [Section 8 of RFC 6637]: https://tools.ietf.org/html/rfc6637#section-8
pub fn pkcs5_pad(buf: &mut Vec<u8>, target_len: usize) {
    let missing = target_len - buf.len();
    assert!(missing <= 0xff);
    for _ in 0..missing {
        buf.push(missing as u8);
    }
    assert_eq!(buf.len(), target_len);
}

/// Removes PKCS5 padding from a session key.
///
/// See [Section 8 of RFC 6637].
///
///   [Section 8 of RFC 6637]: https://tools.ietf.org/html/rfc6637#section-8
pub fn pkcs5_unpad(buf: &mut Vec<u8>, target_len: usize) -> Result<()> {
    if buf.len() > 0xff {
        return Err(Error::InvalidArgument("message too large".into()).into());
    }

    if buf.len() < target_len {
        return Err(Error::InvalidArgument("message too small".into()).into());
    }

    let mut good = true;
    let missing = (buf.len() - target_len) as u8;
    for &b in &buf[target_len..] {
        good = b == missing && good;
    }

    if good {
        buf.truncate(target_len);
        Ok(())
    } else {
        Err(Error::InvalidArgument("bad padding".into()).into())
    }
}

/// Wraps a key using the AES Key Wrap Algorithm.
///
/// See [RFC 3394].
///
///  [RFC 3394]: https://tools.ietf.org/html/rfc3394
pub fn aes_key_wrap(algo: SymmetricAlgorithm, key: &[u8],
                    plaintext: &[u8])
                    -> Result<Vec<u8>> {
    use SymmetricAlgorithm::*;

    if plaintext.len() % 8 != 0 {
        return Err(Error::InvalidArgument(
            "Plaintext must be a multiple of 8".into()).into());
    }

    if key.len() != algo.key_size()? {
        return Err(Error::InvalidArgument("Bad key size".into()).into());
    }

    // We need ECB for the algorithm.  However, there is no
    // nettle::Mode:ECB, and we need nettle::Mode for polymorphism (we
    // cannot have Box<nettle::Cipher>).  To work around this, we use
    // CBC, and always use an all-zero IV.
    let mut cipher: Box<Mode> = match algo {
        AES128 => Box::new(
            mode::Cbc::<cipher::Aes128>::with_encrypt_key(key)),
        AES192 => Box::new(
            mode::Cbc::<cipher::Aes192>::with_encrypt_key(key)),
        AES256 => Box::new(
            mode::Cbc::<cipher::Aes256>::with_encrypt_key(key)),
        _ => return Err(Error::UnsupportedSymmetricAlgorithm(algo).into()),
    };

    //   Inputs:  Plaintext, n 64-bit values {P1, P2, ..., Pn}, and
    //            Key, K (the KEK).
    //   Outputs: Ciphertext, (n+1) 64-bit values {C0, C1, ..., Cn}.
    let n = plaintext.len() / 8;
    let mut ciphertext = vec![0; 8 + plaintext.len()];

    //   1) Initialize variables.
    //
    //       Set A = IV, an initial value (see 2.2.3)
    let mut a = AES_KEY_WRAP_IV;

    {
        //   For i = 1 to n
        //       R[i] = P[i]
        let r = &mut ciphertext[8..];
        r.copy_from_slice(plaintext);

        let mut b = [0; 16];
        let mut tmp = [0; 16];

        //   2) Calculate intermediate values.

        // For j = 0 to 5
        for j in 0..6 {
            // For i=1 to n
            for i in 0..n {
                // B = AES(K, A | R[i])
                write_be_u64(&mut tmp[..8], a);
                &mut tmp[8..].copy_from_slice(&r[8 * i..8 * (i + 1)]);
                let mut iv = vec![0; cipher.block_size()]; // Turn CBC into ECB.
                cipher.encrypt(&mut iv, &mut b, &tmp);

                // A = MSB(64, B) ^ t where t = (n*j)+i
                a = read_be_u64(&b[..8]) ^ ((n * j) + i + 1) as u64;
                // (Note that our i runs from 0 to n-1 instead of 1 to
                // n, hence the index shift.

                // R[i] = LSB(64, B)
                &mut r[8 * i..8 * (i + 1)].copy_from_slice(&b[8..]);
            }
        }
    }

    //   3) Output the results.
    //
    //       Set C[0] = A
    //       For i = 1 to n
    //           C[i] = R[i]
    write_be_u64(&mut ciphertext[..8], a);
    Ok(ciphertext)
}

/// Unwraps an encrypted key using the AES Key Wrap Algorithm.
///
/// See [RFC 3394].
///
///  [RFC 3394]: https://tools.ietf.org/html/rfc3394
pub fn aes_key_unwrap(algo: SymmetricAlgorithm, key: &[u8],
                      ciphertext: &[u8])
                      -> Result<Vec<u8>> {
    use SymmetricAlgorithm::*;

    if ciphertext.len() % 8 != 0 {
        return Err(Error::InvalidArgument(
            "Ciphertext must be a multiple of 8".into()).into());
    }

    if key.len() != algo.key_size()? {
        return Err(Error::InvalidArgument("Bad key size".into()).into());
    }

    // We need ECB for the algorithm.  However, there is no
    // nettle::Mode:ECB, and we need nettle::Mode for polymorphism (we
    // cannot have Box<nettle::Cipher>).  To work around this, we use
    // CBC, and always use an all-zero IV.
    let mut cipher: Box<Mode> = match algo {
        AES128 => Box::new(
            mode::Cbc::<cipher::Aes128>::with_decrypt_key(key)),
        AES192 => Box::new(
            mode::Cbc::<cipher::Aes192>::with_decrypt_key(key)),
        AES256 => Box::new(
            mode::Cbc::<cipher::Aes256>::with_decrypt_key(key)),
        _ => return Err(Error::UnsupportedSymmetricAlgorithm(algo).into()),
    };

    //   Inputs:  Ciphertext, (n+1) 64-bit values {C0, C1, ..., Cn}, and
    //            Key, K (the KEK).
    //   Outputs: Plaintext, n 64-bit values {P1, P2, ..., Pn}.
    let n = ciphertext.len() / 8 - 1;
    let mut plaintext = Vec::with_capacity(ciphertext.len() - 8);

    //   1) Initialize variables.
    //
    //       Set A = C[0]
    //       For i = 1 to n
    //           R[i] = C[i]
    let mut a = read_be_u64(&ciphertext[..8]);
    plaintext.extend_from_slice(&ciphertext[8..]);

    //   2) Calculate intermediate values.
    {
        let r = &mut plaintext;

        let mut b = [0; 16];
        let mut tmp = [0; 16];

        // For j = 5 to 0
        for j in (0..6_usize).into_iter().map(|x| 5 - x) {
            // For i = n to 1
            for i in (0..n).into_iter().map(|x| n - 1 - x) {
                // B = AES-1(K, (A ^ t) | R[i]) where t = n*j+i
                write_be_u64(&mut tmp[..8], a ^ ((n * j) + i + 1) as u64);
                &mut tmp[8..].copy_from_slice(&r[8 * i..8 * (i + 1)]);
                // (Note that our i runs from n-1 to 0 instead of n to
                // 1, hence the index shift.
                let mut iv = vec![0; cipher.block_size()]; // Turn CBC into ECB.
                cipher.decrypt(&mut iv, &mut b, &tmp);

                // A = MSB(64, B)
                a = read_be_u64(&b[..8]);

                // R[i] = LSB(64, B)
                &mut r[8 * i..8 * (i + 1)].copy_from_slice(&b[8..]);
            }
        }
    }

    //   3) Output results.
    //
    //   If A is an appropriate initial value (see 2.2.3),
    //   Then
    //       For i = 1 to n
    //           P[i] = R[i]
    //   Else
    //       Return an error
    if a == AES_KEY_WRAP_IV {
        Ok(plaintext)
    } else {
        Err(Error::InvalidArgument("Bad key".into()).into())
    }
}

const AES_KEY_WRAP_IV: u64 = 0xa6a6a6a6a6a6a6a6;

fn read_be_u64(b: &[u8]) -> u64 {
    assert_eq!(b.len(), 8);
    ((b[0] as u64) << 56) as u64
        | ((b[1] as u64) << 48)
        | ((b[2] as u64) << 40)
        | ((b[3] as u64) << 32)
        | ((b[4] as u64) << 24)
        | ((b[5] as u64) << 16)
        | ((b[6] as u64) <<  8)
        | ((b[7] as u64) <<  0)
}

fn write_be_u64(b: &mut [u8], n: u64) {
    assert_eq!(b.len(), 8);
    b[0] = (n >> 56) as u8;
    b[1] = (n >> 48) as u8;
    b[2] = (n >> 40) as u8;
    b[3] = (n >> 32) as u8;
    b[4] = (n >> 24) as u8;
    b[5] = (n >> 16) as u8;
    b[6] = (n >>  8) as u8;
    b[7] = (n >>  0) as u8;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pkcs5_padding() {
        let mut v = Vec::from(&[0, 0, 0][..]);
        pkcs5_pad(&mut v, 8);
        assert_eq!(&v, &[0, 0, 0, 5, 5, 5, 5, 5]);
        pkcs5_unpad(&mut v, 3).unwrap();
        assert_eq!(&v, &[0, 0, 0]);

        let mut v = Vec::new();
        pkcs5_pad(&mut v, 8);
        assert_eq!(&v, &[8, 8, 8, 8, 8, 8, 8, 8]);
        pkcs5_unpad(&mut v, 0).unwrap();
        assert_eq!(&v, &[]);
    }

    #[test]
    fn aes_wrapping() {
        struct Test {
            algo: SymmetricAlgorithm,
            kek: &'static [u8],
            key_data: &'static [u8],
            ciphertext: &'static [u8],
        }

        // These are the test vectors from RFC3394.
        const TESTS: &[Test] = &[
            Test {
                algo: SymmetricAlgorithm::AES128,
                kek: &[0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                       0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F],
                key_data: &[0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                            0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
                ciphertext: &[0x1F, 0xA6, 0x8B, 0x0A, 0x81, 0x12, 0xB4, 0x47,
                              0xAE, 0xF3, 0x4B, 0xD8, 0xFB, 0x5A, 0x7B, 0x82,
                              0x9D, 0x3E, 0x86, 0x23, 0x71, 0xD2, 0xCF, 0xE5],
            },
            Test {
                algo: SymmetricAlgorithm::AES192,
                kek: &[0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                       0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
                       0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17],
                key_data: &[0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                            0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
                ciphertext: &[0x96, 0x77, 0x8B, 0x25, 0xAE, 0x6C, 0xA4, 0x35,
                              0xF9, 0x2B, 0x5B, 0x97, 0xC0, 0x50, 0xAE, 0xD2,
                              0x46, 0x8A, 0xB8, 0xA1, 0x7A, 0xD8, 0x4E, 0x5D],
            },
            Test {
                algo: SymmetricAlgorithm::AES256,
                kek: &[0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                       0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
                       0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                       0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F],
                key_data: &[0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                            0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
                ciphertext: &[0x64, 0xE8, 0xC3, 0xF9, 0xCE, 0x0F, 0x5B, 0xA2,
                              0x63, 0xE9, 0x77, 0x79, 0x05, 0x81, 0x8A, 0x2A,
                              0x93, 0xC8, 0x19, 0x1E, 0x7D, 0x6E, 0x8A, 0xE7],
            },
            Test {
                algo: SymmetricAlgorithm::AES192,
                kek: &[0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                       0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
                       0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17],
                key_data: &[0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                            0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
                            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07],
                ciphertext: &[0x03, 0x1D, 0x33, 0x26, 0x4E, 0x15, 0xD3, 0x32,
                              0x68, 0xF2, 0x4E, 0xC2, 0x60, 0x74, 0x3E, 0xDC,
                              0xE1, 0xC6, 0xC7, 0xDD, 0xEE, 0x72, 0x5A, 0x93,
                              0x6B, 0xA8, 0x14, 0x91, 0x5C, 0x67, 0x62, 0xD2],
            },
            Test {
                algo: SymmetricAlgorithm::AES256,
                kek: &[0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                       0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
                       0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                       0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F],
                key_data: &[0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                            0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
                            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07],
                ciphertext: &[0xA8, 0xF9, 0xBC, 0x16, 0x12, 0xC6, 0x8B, 0x3F,
                              0xF6, 0xE6, 0xF4, 0xFB, 0xE3, 0x0E, 0x71, 0xE4,
                              0x76, 0x9C, 0x8B, 0x80, 0xA3, 0x2C, 0xB8, 0x95,
                              0x8C, 0xD5, 0xD1, 0x7D, 0x6B, 0x25, 0x4D, 0xA1],
            },
            Test {
                algo: SymmetricAlgorithm::AES256,
                kek: &[0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                       0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
                       0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                       0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F],
                key_data: &[0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                            0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
                            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                            0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F],
                ciphertext: &[0x28, 0xC9, 0xF4, 0x04, 0xC4, 0xB8, 0x10, 0xF4,
                              0xCB, 0xCC, 0xB3, 0x5C, 0xFB, 0x87, 0xF8, 0x26,
                              0x3F, 0x57, 0x86, 0xE2, 0xD8, 0x0E, 0xD3, 0x26,
                              0xCB, 0xC7, 0xF0, 0xE7, 0x1A, 0x99, 0xF4, 0x3B,
                              0xFB, 0x98, 0x8B, 0x9B, 0x7A, 0x02, 0xDD, 0x21],
            },
        ];

        for test in TESTS {
            let ciphertext = aes_key_wrap(test.algo, test.kek, test.key_data)
                .unwrap();
            assert_eq!(test.ciphertext, &ciphertext[..]);

            let key_data = aes_key_unwrap(test.algo, test.kek, &ciphertext[..])
                .unwrap();
            assert_eq!(test.key_data, &key_data[..]);
        }
    }

    quickcheck! {
        fn be_u64_roundtrip(n: u64) -> bool {
            let mut b = [0; 8];
            write_be_u64(&mut b, n);
            n == read_be_u64(&b)
        }
    }
}
