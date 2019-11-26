extern crate assert_cli;

#[cfg(test)]
mod integration {
    use assert_cli::Assert;
    use std::path;

    #[test]
    fn not_signing_capable_subkey() {
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
// extern crate sequoia_openpgp;
//
// #[test]
// fn create_key() {
//     use std::fs::File;
//     use sequoia_openpgp::{
//         tpk::TPKBuilder,
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
//     let (tpk, _) = TPKBuilder::default()
//         .add_userid("Testy Mc Test")
//         .add_encryption_subkey()
//         .generate().unwrap();
//     let subkey = tpk.subkeys().next().unwrap();
//     let key = subkey.subkey();
//     let sig = {
//         let mpis = match key.secret() {
//             Some(SecretKey::Unencrypted{ ref mpis }) => mpis,
//             _ => unreachable!(),
//         };
//         let mut b = signature::Builder::new(SignatureType::Binary);
//         b.set_signature_creation_time(time::now()).unwrap();
//         b.set_issuer_fingerprint(key.fingerprint()).unwrap();
//         b.set_issuer(key.fingerprint().into()).unwrap();
//         b.sign_message(
//             &mut KeyPair::new(key.clone(), mpis.clone()).unwrap(),
//             HashAlgorithm::SHA512, b"Hello, World").unwrap()
//     };
//
//     {
//         let mut fd = File::create("key").unwrap();
//         tpk.serialize(&mut fd).unwrap();
//     }
//
//     {
//         let mut fd = File::create("sig").unwrap();
//         sig.serialize(&mut fd).unwrap();
//     }
// }
