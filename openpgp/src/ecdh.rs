//! Support code for Elliptic Curve Diffie Hellman as used in OpenPGP.

use Error;
use Result;
use constants::{
    HashAlgorithm,
    SymmetricAlgorithm,
};
use nettle::{cipher, mode, Mode};

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

        let mut v = Vec::new();
        pkcs5_pad(&mut v, 8);
        assert_eq!(&v, &[8, 8, 8, 8, 8, 8, 8, 8]);
    }

    #[test]
    fn aes_wrapping() {
        struct Test {
            algo: SymmetricAlgorithm,
            kek: &'static [u8],
            key_data: &'static [u8],
            ciphertext: &'static [u8],
        }

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
