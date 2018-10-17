//! Cryptographic primitives.

use std::io::Read;
use nettle::Hash;

use constants::HashAlgorithm;
use Result;

pub(crate) mod aead;
pub(crate) mod ecdh;
mod hash;
pub mod mpis;
pub mod s2k;
pub(crate) mod symmetric;

/// Hash the specified file.
///
/// This is useful when verifying detached signatures.
pub fn hash_file<R: Read>(reader: R, algos: &[HashAlgorithm])
    -> Result<Vec<(HashAlgorithm, Box<Hash>)>>
{
    use std::mem;

    use ::parse::HashedReader;
    use ::parse::HashesFor;

    use buffered_reader::BufferedReader;
    use buffered_reader::BufferedReaderGeneric;

    let reader
        = BufferedReaderGeneric::with_cookie(
            reader, None, Default::default());

    let mut reader
        = HashedReader::new(reader, HashesFor::Signature, algos.to_vec());

    // Hash all of the data.
    reader.drop_eof()?;

    let mut hashes =
        mem::replace(&mut reader.cookie_mut().sig_group_mut().hashes,
                     Default::default());
    let hashes = hashes.drain().collect();
    Ok(hashes)
}


#[test]
fn hash_file_test() {
    use std::collections::HashMap;
    use std::fs::File;

    let expected: HashMap<HashAlgorithm, &str> = [
        (HashAlgorithm::SHA1, "7945E3DA269C25C04F9EF435A5C0F25D9662C771"),
        (HashAlgorithm::SHA512, "DDE60DB05C3958AF1E576CD006A7F3D2C343DD8C8DECE789A15D148DF90E6E0D1454DE734F8343502CA93759F22C8F6221BE35B6BDE9728BD12D289122437CB1"),
    ].iter().cloned().collect();

    let result =
        hash_file(File::open(::path_to("a-cypherpunks-manifesto.txt")).unwrap(),
                  &expected.keys().cloned().collect::<Vec<HashAlgorithm>>())
        .unwrap();

    for (algo, mut hash) in result.into_iter() {
        let mut digest = vec![0u8; hash.digest_size()];
        hash.digest(&mut digest);

        assert_eq!(*expected.get(&algo).unwrap(),
                   &::conversions::to_hex(&digest[..], false));
    }
}

