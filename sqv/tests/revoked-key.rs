extern crate assert_cli;

#[cfg(test)]
mod integration {
    use assert_cli::Assert;
    use std::path;

    #[test]
    fn valid_at_signature_ctime() {
        Assert::cargo_binary("sqv")
            .current_dir(path::Path::new("tests").join("data"))
            .with_args(
                &["--keyring",
                  &"revoked-unrevoked.key",
                  &"rev-unrev-t1-t2.sig",
                  &"msg.txt"])
            .stdout().is("7859 B79C 7312 7826 6852  15BE 8254 0C25 2B52 1ED8")
            .unwrap();
    }

    #[test]
    fn revoked_at_signature_ctime() {
        Assert::cargo_binary("sqv")
            .current_dir(path::Path::new("tests").join("data"))
            .with_args(
                &["--keyring",
                  &"revoked-unrevoked.key",
                  &"rev-unrev-t2-t3.sig",
                  &"msg.txt"])
            .fails()
            .unwrap();
    }

    #[test]
    fn valid_now() {
        Assert::cargo_binary("sqv")
            .current_dir(path::Path::new("tests").join("data"))
            .with_args(
                &["--keyring",
                  &"revoked-unrevoked.key",
                  &"rev-unrev-t3-now.sig",
                  &"msg.txt"])
            .stdout().is("7859 B79C 7312 7826 6852  15BE 8254 0C25 2B52 1ED8")
            .unwrap();
    }
}

// Code to create the data for the test cases above
// extern crate sequoia_openpgp;
// extern crate rand;
//
// #[test]
// fn create_key() {
//     use std::fs::File;
//     use sequoia_openpgp::{
//         TPK,
//         PacketPile,
//         packet::{
//             signature,
//             key::SecretKey,
//             Features,
//             KeyFlags,
//             Key,
//             Tag,
//         },
//         crypto::KeyPair,
//         serialize::Serialize,
//         constants::{
//             SignatureType,
//             HashAlgorithm,
//             PublicKeyAlgorithm,
//         }
//     };
//     use rand::{thread_rng, Rng, distributions::Open01};
//
//     let msg = b"Hello, World";
//     let t1 = time::strptime("2000-1-1", "%F").unwrap();
//     let t2 = time::strptime("2001-1-1", "%F").unwrap();
//     let t3 = time::strptime("2002-1-1", "%F").unwrap();
//     let f1: f32 = thread_rng().sample(Open01);
//     let f2: f32 = thread_rng().sample(Open01);
//     let t12 = t1 + time::Duration::days((300.0 * f1) as i64);
//     let t23 = t2 + time::Duration::days((300.0 * f2) as i64);
//     let key = Key::new(PublicKeyAlgorithm::EdDSA).unwrap();
//     let (bind1, rev, bind2, sig1, sig2, sig3) = {
//         let mpis = match key.secret() {
//             Some(SecretKey::Unencrypted{ ref mpis }) => mpis,
//             _ => unreachable!(),
//         };
//         // 1st binding sig valid from t1 on
//         let mut b = signature::Builder::new(SignatureType::DirectKey);
//         b.set_features(&Features::sequoia()).unwrap();
//         b.set_key_flags(&KeyFlags::default().set_sign(true)).unwrap();
//         b.set_signature_creation_time(t1).unwrap();
//         b.set_key_expiration_time(Some(time::Duration::weeks(10 * 52))).unwrap();
//         b.set_issuer_fingerprint(key.fingerprint()).unwrap();
//         b.set_issuer(key.fingerprint().to_keyid()).unwrap();
//         b.set_preferred_hash_algorithms(vec![HashAlgorithm::SHA512]).unwrap();
//         let bind1 = b.sign_primary_key_binding(
//             &mut KeyPair::new(key.clone(), mpis.clone()).unwrap(),
//             HashAlgorithm::SHA512).unwrap();
//
//         // Revocation sig valid from t2 on
//         b = signature::Builder::new(SignatureType::KeyRevocation);
//         b.set_signature_creation_time(t2).unwrap();
//         b.set_issuer_fingerprint(key.fingerprint()).unwrap();
//         b.set_issuer(key.fingerprint().to_keyid()).unwrap();
//         let rev = b.sign_primary_key_binding(
//             &mut KeyPair::new(key.clone(), mpis.clone()).unwrap(),
//             HashAlgorithm::SHA512).unwrap();
//
//         // 2nd binding sig valid from t3 on
//         b = signature::Builder::new(SignatureType::DirectKey);
//         b.set_features(&Features::sequoia()).unwrap();
//         b.set_key_flags(&KeyFlags::default().set_sign(true)).unwrap();
//         b.set_signature_creation_time(t3).unwrap();
//         b.set_key_expiration_time(Some(time::Duration::weeks(10 * 52))).unwrap();
//         b.set_issuer_fingerprint(key.fingerprint()).unwrap();
//         b.set_issuer(key.fingerprint().to_keyid()).unwrap();
//         b.set_preferred_hash_algorithms(vec![HashAlgorithm::SHA512]).unwrap();
//         let bind2 = b.sign_primary_key_binding(
//             &mut KeyPair::new(key.clone(), mpis.clone()).unwrap(),
//             HashAlgorithm::SHA512).unwrap();
//
//         // 1st message sig between t1 and t2
//         b = signature::Builder::new(SignatureType::Binary);
//         b.set_features(&Features::sequoia()).unwrap();
//         b.set_signature_creation_time(t12).unwrap();
//         b.set_issuer_fingerprint(key.fingerprint()).unwrap();
//         b.set_issuer(key.fingerprint().to_keyid()).unwrap();
//         let sig1 = b.sign_message(
//             &mut KeyPair::new(key.clone(), mpis.clone()).unwrap(),
//             HashAlgorithm::SHA512, msg).unwrap();
//
//         // 2nd message sig between t2 and t3
//         b = signature::Builder::new(SignatureType::Binary);
//         b.set_features(&Features::sequoia()).unwrap();
//         b.set_signature_creation_time(t23).unwrap();
//         b.set_issuer_fingerprint(key.fingerprint()).unwrap();
//         b.set_issuer(key.fingerprint().to_keyid()).unwrap();
//         let sig2 = b.sign_message(
//             &mut KeyPair::new(key.clone(), mpis.clone()).unwrap(),
//             HashAlgorithm::SHA512, msg).unwrap();
//
//         // 3rd message sig between t3 and now
//         b = signature::Builder::new(SignatureType::Binary);
//         b.set_features(&Features::sequoia()).unwrap();
//         b.set_signature_creation_time(time::now()).unwrap();
//         b.set_issuer_fingerprint(key.fingerprint()).unwrap();
//         b.set_issuer(key.fingerprint().to_keyid()).unwrap();
//         let sig3 = b.sign_message(
//             &mut KeyPair::new(key.clone(), mpis.clone()).unwrap(),
//             HashAlgorithm::SHA512, msg).unwrap();
//
//         (bind1, rev, bind2, sig1, sig2, sig3)
//     };
//     let tpk = TPK::from_packet_pile(PacketPile::from_packets(vec![
//          key.to_packet(Tag::PublicKey).unwrap(),
//          bind1.into(),
//          bind2.into(),
//          rev.into()
//     ])).unwrap();
//
//     {
//         let mut fd = File::create("key").unwrap();
//         tpk.serialize(&mut fd).unwrap();
//     }
//
//     {
//         let mut fd = File::create("sig1").unwrap();
//         sig1.serialize(&mut fd).unwrap();
//     }
//
//     {
//         let mut fd = File::create("sig2").unwrap();
//         sig2.serialize(&mut fd).unwrap();
//     }
//
//     {
//         let mut fd = File::create("sig3").unwrap();
//         sig3.serialize(&mut fd).unwrap();
//     }
// }
