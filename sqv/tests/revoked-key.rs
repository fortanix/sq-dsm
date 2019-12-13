extern crate assert_cli;

#[cfg(test)]
mod integration {
    use assert_cli::Assert;
    use std::path;

    #[test]
    fn not_valid_at_signature_ctime() {
        // A hard revocation is never ignored.
        Assert::cargo_binary("sqv")
            .current_dir(path::Path::new("tests").join("data"))
            .with_args(
                &["--keyring",
                  &"revoked-key-keyring.pgp",
                  &"revoked-key-sig-t1-t2.pgp",
                  &"msg.txt"])
            .fails()
            .and().stderr().contains("revoked")
            .unwrap();
    }

    #[test]
    fn revoked_at_signature_ctime() {
        Assert::cargo_binary("sqv")
            .current_dir(path::Path::new("tests").join("data"))
            .with_args(
                &["--keyring",
                  &"revoked-key-keyring.pgp",
                  &"revoked-key-sig-t2-t3.pgp",
                  &"msg.txt"])
            .fails()
            .and().stderr().contains("revoked")
            .unwrap();
    }

    #[test]
    fn unrevoked() {
        // Hard revocations are never ignored.
        Assert::cargo_binary("sqv")
            .current_dir(path::Path::new("tests").join("data"))
            .with_args(
                &["--keyring",
                  &"revoked-key-keyring.pgp",
                  &"revoked-key-sig-t3-now.pgp",
                  &"msg.txt"])
            .fails()
            .and().stderr().contains("revoked")
            .unwrap();
    }
}

// Code to create the data for the test cases above
//#[test]
#[allow(dead_code)]
fn create_key() {
    use std::fs::File;
    use sequoia_openpgp::{
        Cert,
        Packet,
        PacketPile,
        packet::{
            signature,
            Key,
            key::{
                Key4,
                PrimaryRole,
            },
        },
        serialize::Serialize,
        types::{
            Curve,
            Features,
            KeyFlags,
            SignatureType,
            HashAlgorithm,
        }
    };
    use chrono::offset::TimeZone;

    let msg = b"Hello, World";
    let t1 = chrono::offset::Utc.timestamp(946681200, 0); // 2000-01-01
    let t2 = chrono::offset::Utc.timestamp(978303600, 0); // 2001-01-01
    let t3 = chrono::offset::Utc.timestamp(1009839600, 0); // 2002-01-01
    let f1: f32 = 0.4; // Chosen by fair dice roll.
    let f2: f32 = 0.7; // Likewise.
    let t12 = t1 + chrono::Duration::days((300.0 * f1) as i64);
    let t23 = t2 + chrono::Duration::days((300.0 * f2) as i64);
    let mut key: Key<_, PrimaryRole> =
        Key4::generate_ecc(true, Curve::Ed25519).unwrap().into();
    key.set_creation_time(t1).unwrap();
    let mut signer = key.clone().into_keypair().unwrap();

    // 1st binding sig valid from t1 on
    let mut b = signature::Builder::new(SignatureType::DirectKey)
        .set_features(&Features::sequoia()).unwrap()
        .set_key_flags(&KeyFlags::default().set_signing(true)).unwrap()
        .set_signature_creation_time(t1).unwrap()
        .set_key_expiration_time(Some(std::time::Duration::new(
            20 * 52 * 7 * 24 * 60 * 60, 0))).unwrap()
        .set_issuer_fingerprint(key.fingerprint()).unwrap()
        .set_issuer(key.fingerprint().into()).unwrap()
        .set_preferred_hash_algorithms(vec![HashAlgorithm::SHA512])
        .unwrap();
    let bind1 = b.sign_primary_key_binding(&mut signer).unwrap();

    // Revocation sig valid from t2 on
    b = signature::Builder::new(SignatureType::KeyRevocation)
        .set_signature_creation_time(t2).unwrap()
        .set_issuer_fingerprint(key.fingerprint()).unwrap()
        .set_issuer(key.fingerprint().into()).unwrap();
    let rev = b.sign_primary_key_binding(&mut signer).unwrap();

    // 2nd binding sig valid from t3 on
    b = signature::Builder::new(SignatureType::DirectKey)
        .set_features(&Features::sequoia()).unwrap()
        .set_key_flags(&KeyFlags::default().set_signing(true)).unwrap()
        .set_signature_creation_time(t3).unwrap()
        .set_key_expiration_time(Some(std::time::Duration::new(
            20 * 52 * 7 * 24 * 60 * 60, 0))).unwrap()
        .set_issuer_fingerprint(key.fingerprint()).unwrap()
        .set_issuer(key.fingerprint().into()).unwrap()
        .set_preferred_hash_algorithms(vec![HashAlgorithm::SHA512])
        .unwrap();
    let bind2 = b.sign_primary_key_binding(&mut signer).unwrap();

    // 1st message sig between t1 and t2
    b = signature::Builder::new(SignatureType::Binary)
        .set_signature_creation_time(t12).unwrap()
        .set_issuer_fingerprint(key.fingerprint()).unwrap()
        .set_issuer(key.fingerprint().into()).unwrap();
    let sig1 = b.sign_message(&mut signer, msg).unwrap();

    // 2nd message sig between t2 and t3
    b = signature::Builder::new(SignatureType::Binary)
        .set_signature_creation_time(t23).unwrap()
        .set_issuer_fingerprint(key.fingerprint()).unwrap()
        .set_issuer(key.fingerprint().into()).unwrap();
    let sig2 = b.sign_message(&mut signer, msg).unwrap();

    // 3rd message sig between t3 and now
    b = signature::Builder::new(SignatureType::Binary)
        .set_signature_creation_time(std::time::SystemTime::now()).unwrap()
        .set_issuer_fingerprint(key.fingerprint()).unwrap()
        .set_issuer(key.fingerprint().into()).unwrap();
    let sig3 = b.sign_message(&mut signer, msg).unwrap();

    let cert = Cert::from_packet_pile(PacketPile::from(vec![
         key.into(),
         bind1.into(),
         bind2.into(),
         rev.into()
    ])).unwrap();

    let mut fd = File::create("revoked-key-keyring.pgp").unwrap();
    cert.serialize(&mut fd).unwrap();

    let mut fd = File::create("revoked-key-sig-t1-t2.pgp").unwrap();
    Packet::from(sig1).serialize(&mut fd).unwrap();

    let mut fd = File::create("revoked-key-sig-t2-t3.pgp").unwrap();
    Packet::from(sig2).serialize(&mut fd).unwrap();

    let mut fd = File::create("revoked-key-sig-t3-now.pgp").unwrap();
    Packet::from(sig3).serialize(&mut fd).unwrap();
}
