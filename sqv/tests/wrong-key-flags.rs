#[cfg(test)]
mod integration {
    use assert_cli::Assert;
    use std::path;

    #[test]
    fn not_for_signing_subkey() {
        Assert::cargo_binary("sqv")
            .current_dir(path::Path::new("tests").join("data"))
            .with_args(
                &["--keyring",
                  &"no-signing-caps.key",
                  &"no-signing-caps.sig",
                  &"msg.txt"])
            .fails()
            .unwrap();
    }
}

// Code to create the data for the test cases above
// use sequoia_openpgp;
//
// #[test]
// fn create_key() {
//     use std::fs::File;
//     use sequoia_openpgp::{
//         cert::CertBuilder,
//         packet::{
//             signature,
//             key::SecretKey,
//         },
//         crypto::KeyPair,
//         serialize::Serialize,
//         types::{
//             SignatureType,
//             HashAlgorithm,
//         }
//     };
//
//     let (cert, _) = CertBuilder::default()
//         .add_userid("Testy Mc Test")
//         .add_transport_encryption_subkey()
//         .generate().unwrap();
//     let subkey = cert.subkeys().next().unwrap();
//     let key = subkey.subkey();
//     let sig = {
//         let mpis = match key.secret() {
//             Some(SecretKey::Unencrypted{ ref mpis }) => mpis,
//             _ => unreachable!(),
//         };
//         let mut b = signature::SignatureBuilder::new(SignatureType::Binary);
//         b.sign_message(
//             &mut KeyPair::new(key.clone(), mpis.clone()).unwrap(),
//             HashAlgorithm::SHA512, b"Hello, World").unwrap()
//     };
//
//     {
//         let mut fd = File::create("key").unwrap();
//         cert.serialize(&mut fd).unwrap();
//     }
//
//     {
//         let mut fd = File::create("sig").unwrap();
//         sig.serialize(&mut fd).unwrap();
//     }
// }
