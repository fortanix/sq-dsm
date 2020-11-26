use sequoia_openpgp as openpgp;
use openpgp::packet;
use openpgp::cert::prelude::*;
use openpgp::types::{
    KeyFlags,
};

use super::{
    Autocrypt,
};

/// Generates a key compliant to
/// [Autocrypt](https://autocrypt.org/).
///
/// If no version is given the latest one is used.
///
/// The autocrypt specification requires a UserID.  However,
/// because it can be useful to add the UserID later, it is
/// permitted to be none.
pub fn cert_builder<'a, V, U>(version: V, userid: Option<U>)
                              -> CertBuilder<'a>
    where V: Into<Option<Autocrypt>>,
          U: Into<packet::UserID>
{
    let builder = CertBuilder::new()
        .set_cipher_suite(match version.into().unwrap_or_default() {
            Autocrypt::V1 => CipherSuite::RSA3k,
            Autocrypt::V1_1 => CipherSuite::Cv25519,
        })
        .set_primary_key_flags(
            KeyFlags::empty()
                .set_certification()
                .set_signing())
        .add_subkey(
            KeyFlags::empty()
                .set_transport_encryption()
                .set_storage_encryption(),
            None,
            None);

    if let Some(userid) = userid {
        builder.add_userid(userid.into())
    } else {
        builder
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use openpgp::types::PublicKeyAlgorithm;

    #[test]
    fn autocrypt_v1() {
        let (cert1, _) = cert_builder(Autocrypt::V1, Some("Foo"))
            .generate().unwrap();
        assert_eq!(cert1.primary_key().pk_algo(),
                   PublicKeyAlgorithm::RSAEncryptSign);
        assert_eq!(cert1.keys().subkeys().next().unwrap().key().pk_algo(),
                   PublicKeyAlgorithm::RSAEncryptSign);
        assert_eq!(cert1.userids().count(), 1);
    }

    #[test]
    fn autocrypt_v1_1() {
        let (cert1, _) = cert_builder(Autocrypt::V1_1, Some("Foo"))
            .generate().unwrap();
        assert_eq!(cert1.primary_key().pk_algo(),
                   PublicKeyAlgorithm::EdDSA);
        assert_eq!(cert1.keys().subkeys().next().unwrap().key().pk_algo(),
                   PublicKeyAlgorithm::ECDH);
        match cert1.keys().subkeys().next().unwrap().key().mpis() {
            openpgp::crypto::mpi::PublicKey::ECDH {
                curve: openpgp::types::Curve::Cv25519, ..
            } => (),
            m => panic!("unexpected mpi: {:?}", m),
        }
        assert_eq!(cert1.userids().count(), 1);
    }
}
