//! Tests revocations and binding signatures over time.
//!
//! These tests create a certificate with a signing capable primary
//! key (subkey), and revoke it later on, then re-legitimize it using
//! a new signature.  We then ask sqv to verify a signature at
//! different points in time.  Hard revocations of the key invalidate
//! the signature at any point in time, whereas in the case of soft
//! revocations, the keys can be re-legitimized.
//!
//! All tests are run in three flavors:
//!
//!  0. The primary key makes the signatures and is revoked.
//!  1. The subkey makes the signatures, primary key is revoked.
//!  2. The subkey makes the signatures and is revoked.
//!
//! As extra subtlety, we bind the subkey *after* the t1-t2 signature.
//!
//! Timeline:   v
//!             |
//!         t0 -| - Signature revoked-key-sig-t0.pgp
//!             |
//!         t1 -| - Primary key creation
//!             |
//!             | - Subkey creation
//!             |
//!             | - Signature revoked-key-sig-t1-t2.pgp
//!             |
//!             | - Subkey is bound
//!             |
//!         t2 -| - Revocation of (sub)key
//!             |
//!             | - Signature revoked-key-sig-t2-t3.pgp
//!             |
//!         t3 -| - New direct/binding signature
//!             |
//!             | - Signature revoked-key-sig-t3-now.pgp
//!             |
//!        now -|
//!             v

extern crate assert_cli;

#[cfg(test)]
mod integration {
    use assert_cli::Assert;
    use std::path;

    fn sqv(keyring: &str, sig: &str) -> Assert {
        Assert::cargo_binary("sqv")
            .current_dir(path::Path::new("tests").join("data"))
            .with_args(
                &["--trace",
                  "--keyring",
                  &format!("revoked-key-cert-{}.pgp", keyring),
                  &format!("revoked-key-sig-{}.pgp", sig),
                  "msg.txt"])
    }

    /// Tests flavor 0, primary key signs and is revoked.
    fn f0(keyring: &str, sig: &str) -> Assert {
        sqv(keyring, sig)
    }

    /// Tests flavor 1, subkey signs and primary key is revoked.
    fn f1(keyring: &str, sig: &str) -> Assert {
        sqv(keyring, &format!("{}.sk", sig))
    }

    /// Tests flavor 2, subkey signs and is revoked.
    fn f2(keyring: &str, sig: &str) -> Assert {
        sqv(&format!("{}.sk", keyring), &format!("{}.sk", sig))
    }

    /// Base case, cert is not revoked.
    #[test]
    fn not_revoked() {
        let c = "not-revoked";
        f0(c, "t0").fails().unwrap();
        f0(c, "t1-t2").unwrap();
        f0(c, "t2-t3").unwrap();
        f0(c, "t3-now").unwrap();

        f1(c, "t0").fails().unwrap();
        f1(c, "t1-t2").fails().unwrap();
        f1(c, "t2-t3").unwrap();
        f1(c, "t3-now").unwrap();

        // f2 is not used here, because we don't have any revocations.
    }

    /// The hard revocation reasons.  All signatures are invalid.
    #[test]
    fn revoked_no_subpacket() {
        let c = "revoked-no_subpacket";
        f0(c, "t0").fails().unwrap();
        f0(c, "t1-t2").fails().and().stderr().contains("revoked").unwrap();
        f0(c, "t2-t3").fails().and().stderr().contains("revoked").unwrap();
        f0(c, "t3-now").fails().and().stderr().contains("revoked").unwrap();

        f1(c, "t0").fails().unwrap();
        f1(c, "t1-t2").fails().unwrap();
        f1(c, "t2-t3").fails().and().stderr().contains("revoked").unwrap();
        f1(c, "t3-now").fails().and().stderr().contains("revoked").unwrap();

        f2(c, "t0").fails().unwrap();
        f2(c, "t1-t2").fails().unwrap();
        f2(c, "t2-t3").fails().and().stderr().contains("revoked").unwrap();
        f2(c, "t3-now").fails().and().stderr().contains("revoked").unwrap();
    }

    #[test]
    fn revoked_unspecified() {
        let c = "revoked-unspecified";
        f0(c, "t0").fails().unwrap();
        f0(c, "t1-t2").fails().and().stderr().contains("revoked").unwrap();
        f0(c, "t2-t3").fails().and().stderr().contains("revoked").unwrap();
        f0(c, "t3-now").fails().and().stderr().contains("revoked").unwrap();

        f1(c, "t0").fails().unwrap();
        f1(c, "t1-t2").fails().unwrap();
        f1(c, "t2-t3").fails().and().stderr().contains("revoked").unwrap();
        f1(c, "t3-now").fails().and().stderr().contains("revoked").unwrap();

        f2(c, "t0").fails().unwrap();
        f2(c, "t1-t2").fails().unwrap();
        f2(c, "t2-t3").fails().and().stderr().contains("revoked").unwrap();
        f2(c, "t3-now").fails().and().stderr().contains("revoked").unwrap();
    }

    #[test]
    fn revoked_compromised() {
        let c = "revoked-compromised";
        f0(c, "t0").fails().unwrap();
        f0(c, "t1-t2").fails().and().stderr().contains("revoked").unwrap();
        f0(c, "t2-t3").fails().and().stderr().contains("revoked").unwrap();
        f0(c, "t3-now").fails().and().stderr().contains("revoked").unwrap();

        f1(c, "t0").fails().unwrap();
        f1(c, "t1-t2").fails().unwrap();
        f1(c, "t2-t3").fails().and().stderr().contains("revoked").unwrap();
        f1(c, "t3-now").fails().and().stderr().contains("revoked").unwrap();

        f2(c, "t0").fails().unwrap();
        f2(c, "t1-t2").fails().unwrap();
        f2(c, "t2-t3").fails().and().stderr().contains("revoked").unwrap();
        f2(c, "t3-now").fails().and().stderr().contains("revoked").unwrap();
    }

    #[test]
    fn revoked_private() {
        let c = "revoked-private";
        f0(c, "t0").fails().unwrap();
        f0(c, "t1-t2").fails().and().stderr().contains("revoked").unwrap();
        f0(c, "t2-t3").fails().and().stderr().contains("revoked").unwrap();
        f0(c, "t3-now").fails().and().stderr().contains("revoked").unwrap();

        f1(c, "t0").fails().unwrap();
        f1(c, "t1-t2").fails().unwrap();
        f1(c, "t2-t3").fails().and().stderr().contains("revoked").unwrap();
        f1(c, "t3-now").fails().and().stderr().contains("revoked").unwrap();

        f2(c, "t0").fails().unwrap();
        f2(c, "t1-t2").fails().unwrap();
        f2(c, "t2-t3").fails().and().stderr().contains("revoked").unwrap();
        f2(c, "t3-now").fails().and().stderr().contains("revoked").unwrap();
    }

    #[test]
    fn revoked_unknown() {
        let c = "revoked-unknown";
        f0(c, "t0").fails().unwrap();
        f0(c, "t1-t2").fails().and().stderr().contains("revoked").unwrap();
        f0(c, "t2-t3").fails().and().stderr().contains("revoked").unwrap();
        f0(c, "t3-now").fails().and().stderr().contains("revoked").unwrap();

        f1(c, "t0").fails().unwrap();
        f1(c, "t1-t2").fails().unwrap();
        f1(c, "t2-t3").fails().and().stderr().contains("revoked").unwrap();
        f1(c, "t3-now").fails().and().stderr().contains("revoked").unwrap();

        f2(c, "t0").fails().unwrap();
        f2(c, "t1-t2").fails().unwrap();
        f2(c, "t2-t3").fails().and().stderr().contains("revoked").unwrap();
        f2(c, "t3-now").fails().and().stderr().contains("revoked").unwrap();
    }

    /// The soft revocation reasons.  Only the signature dated prior
    /// to the key creation and the one directly after the revocation
    /// are invalid.
    #[test]
    fn revoked_superseded() {
        let c = "revoked-superseded";
        f0(c, "t0").fails().unwrap();
        f0(c, "t1-t2").unwrap();
        f0(c, "t2-t3").fails().and().stderr().contains("revoked").unwrap();
        f0(c, "t3-now").unwrap();

        f1(c, "t0").fails().unwrap();
        f1(c, "t1-t2").fails().unwrap();
        f1(c, "t2-t3").fails().and().stderr().contains("revoked").unwrap();
        f1(c, "t3-now").unwrap();

        f2(c, "t0").fails().unwrap();
        f2(c, "t1-t2").fails().unwrap();
        f2(c, "t2-t3").fails().and().stderr().contains("revoked").unwrap();
        f2(c, "t3-now").unwrap();
    }

    #[test]
    fn revoked_key_retired() {
        let c = "revoked-key_retired";
        f0(c, "t0").fails().unwrap();
        f0(c, "t1-t2").unwrap();
        f0(c, "t2-t3").fails().and().stderr().contains("revoked").unwrap();
        f0(c, "t3-now").unwrap();

        f1(c, "t0").fails().unwrap();
        f1(c, "t1-t2").fails().unwrap();
        f1(c, "t2-t3").fails().and().stderr().contains("revoked").unwrap();
        f1(c, "t3-now").unwrap();

        f2(c, "t0").fails().unwrap();
        f2(c, "t1-t2").fails().unwrap();
        f2(c, "t2-t3").fails().and().stderr().contains("revoked").unwrap();
        f2(c, "t3-now").unwrap();
    }

    /// XXX: This is an odd one.
    #[test]
    fn revoked_uid_retired() {
        let c = "revoked-uid_retired";
        f0(c, "t0").fails().unwrap();
        f0(c, "t1-t2").unwrap();
        f0(c, "t2-t3").fails().and().stderr().contains("revoked").unwrap();
        f0(c, "t3-now").unwrap();

        f1(c, "t0").fails().unwrap();
        f1(c, "t1-t2").fails().unwrap();
        f1(c, "t2-t3").fails().and().stderr().contains("revoked").unwrap();
        f1(c, "t3-now").unwrap();

        f2(c, "t0").fails().unwrap();
        f2(c, "t1-t2").fails().unwrap();
        f2(c, "t2-t3").fails().and().stderr().contains("revoked").unwrap();
        f2(c, "t3-now").unwrap();
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
                SubordinateRole,
            },
        },
        serialize::Serialize,
        types::{
            Curve,
            Features,
            KeyFlags,
            SignatureType,
            HashAlgorithm,
            ReasonForRevocation,
        }
    };
    use chrono::offset::TimeZone;

    let msg = b"Hello, World";
    let t0 = chrono::offset::Utc.timestamp(915145200, 0); // 1999-01-01
    let t1 = chrono::offset::Utc.timestamp(946681200, 0); // 2000-01-01
    let t2 = chrono::offset::Utc.timestamp(978303600, 0); // 2001-01-01
    let t3 = chrono::offset::Utc.timestamp(1009839600, 0); // 2002-01-01
    let f1: f32 = 0.4; // Chosen by fair dice roll.
    let f2: f32 = 0.7; // Likewise.
    let t12 = t1 + chrono::Duration::days((300.0 * f1) as i64);
    let t_sk_binding = t12 + chrono::Duration::days(1);
    let t23 = t2 + chrono::Duration::days((300.0 * f2) as i64);

    // Create primary key.
    let mut key: Key<_, PrimaryRole> =
        Key4::generate_ecc(true, Curve::Ed25519).unwrap().into();
    key.set_creation_time(t1).unwrap();
    let mut signer = key.clone().into_keypair().unwrap();

    // Create subkey.
    let mut subkey: Key<_, SubordinateRole> =
        Key4::generate_ecc(true, Curve::Ed25519).unwrap().into();
    subkey.set_creation_time(t1 + chrono::Duration::days(1)).unwrap();
    let mut sk_signer = subkey.clone().into_keypair().unwrap();

    // 1st direct key signature valid from t1 on
    let mut b = signature::Builder::new(SignatureType::DirectKey)
        .set_features(&Features::sequoia()).unwrap()
        .set_key_flags(&KeyFlags::default()
                       .set_signing(true).set_certification(true)).unwrap()
        .set_signature_creation_time(t1).unwrap()
        .set_issuer_fingerprint(key.fingerprint()).unwrap()
        .set_issuer(key.fingerprint().into()).unwrap()
        .set_preferred_hash_algorithms(vec![HashAlgorithm::SHA512])
        .unwrap();
    let direct1 = b.sign_direct_key(&mut signer).unwrap();

    // 1st subkey binding signature valid from t_sk_binding on
    b = signature::Builder::new(SignatureType::SubkeyBinding)
        .set_key_flags(&KeyFlags::default().set_signing(true)).unwrap()
        .set_signature_creation_time(t_sk_binding).unwrap()
        .set_issuer_fingerprint(key.fingerprint()).unwrap()
        .set_issuer(key.fingerprint().into()).unwrap()
        .set_embedded_signature(
            signature::Builder::new(SignatureType::PrimaryKeyBinding)
                .set_signature_creation_time(t_sk_binding).unwrap()
                .set_issuer_fingerprint(subkey.fingerprint()).unwrap()
                .set_issuer(subkey.keyid()).unwrap()
                .sign_subkey_binding(&mut sk_signer, &key, &subkey).unwrap())
        .unwrap();
    let sk_bind1 = b.sign_subkey_binding(&mut signer, &key, &subkey).unwrap();

    // 2nd direct key signature valid from t3 on
    b = signature::Builder::new(SignatureType::DirectKey)
        .set_features(&Features::sequoia()).unwrap()
        .set_key_flags(&KeyFlags::default()
                       .set_signing(true).set_certification(true)).unwrap()
        .set_signature_creation_time(t3).unwrap()
        .set_issuer_fingerprint(key.fingerprint()).unwrap()
        .set_issuer(key.fingerprint().into()).unwrap()
        .set_preferred_hash_algorithms(vec![HashAlgorithm::SHA512])
        .unwrap();
    let direct2 = b.sign_direct_key(&mut signer).unwrap();

    // 2nd subkey binding signature valid from t3 on
    let mut b = signature::Builder::new(SignatureType::SubkeyBinding)
        .set_key_flags(&KeyFlags::default().set_signing(true)).unwrap()
        .set_signature_creation_time(t3).unwrap()
        .set_issuer_fingerprint(key.fingerprint()).unwrap()
        .set_issuer(key.fingerprint().into()).unwrap()
        .set_embedded_signature(
            signature::Builder::new(SignatureType::PrimaryKeyBinding)
                .set_signature_creation_time(t3).unwrap()
                .set_issuer_fingerprint(subkey.fingerprint()).unwrap()
                .set_issuer(subkey.keyid()).unwrap()
                .sign_subkey_binding(&mut sk_signer, &key, &subkey).unwrap())
        .unwrap();
    let sk_bind2 = b.sign_subkey_binding(&mut signer, &key, &subkey).unwrap();

    let cert = Cert::from_packet_pile(PacketPile::from(vec![
        key.clone().into(),
        direct1.clone().into(),
        direct2.clone().into(),
        subkey.clone().into(),
        sk_bind1.clone().into(),
        sk_bind2.clone().into(),
    ])).unwrap();
    let mut fd = File::create("revoked-key-cert-not-revoked.pgp").unwrap();
    cert.serialize(&mut fd).unwrap();

    for (slug, reason) in &[
        ("no_subpacket", None),
        ("unspecified", Some(ReasonForRevocation::Unspecified)),
        ("superseded", Some(ReasonForRevocation::KeySuperseded)),
        ("compromised", Some(ReasonForRevocation::KeyCompromised)),
        ("key_retired", Some(ReasonForRevocation::KeyRetired)),
        ("uid_retired", Some(ReasonForRevocation::UIDRetired)),
        ("private", Some(ReasonForRevocation::Private(100))),
        ("unknown", Some(ReasonForRevocation::Unknown(200))),
    ] {
        // Revocation sig valid from t2 on
        let mut b = signature::Builder::new(SignatureType::KeyRevocation)
            .set_signature_creation_time(t2).unwrap()
            .set_issuer_fingerprint(key.fingerprint()).unwrap()
            .set_issuer(key.fingerprint().into()).unwrap();

        if let Some(r) = reason {
            b = b.set_reason_for_revocation(r.clone(), r.to_string().as_bytes())
                .unwrap();
        }

        let rev = b.sign_direct_key(&mut signer).unwrap();
        let cert = Cert::from_packet_pile(PacketPile::from(vec![
            key.clone().into(),
            direct1.clone().into(),
            rev.clone().into(),
            direct2.clone().into(),
            subkey.clone().into(),
            sk_bind1.clone().into(),
            sk_bind2.clone().into(),
        ])).unwrap();

        let mut fd =
            File::create(format!("revoked-key-cert-revoked-{}.pgp", slug))
            .unwrap();
        cert.serialize(&mut fd).unwrap();

        // Again, this time we revoke the subkey.
        let mut b = signature::Builder::new(SignatureType::SubkeyRevocation)
            .set_signature_creation_time(t2).unwrap()
            .set_issuer_fingerprint(key.fingerprint()).unwrap()
            .set_issuer(key.fingerprint().into()).unwrap();

        if let Some(r) = reason {
            b = b.set_reason_for_revocation(r.clone(), r.to_string().as_bytes())
                .unwrap();
        }

        let rev = b.sign_subkey_binding(&mut signer, &key, &subkey).unwrap();
        let cert = Cert::from_packet_pile(PacketPile::from(vec![
            key.clone().into(),
            direct1.clone().into(),
            direct2.clone().into(),
            subkey.clone().into(),
            sk_bind1.clone().into(),
            rev.clone().into(),
            sk_bind2.clone().into(),
        ])).unwrap();

        let mut fd =
            File::create(format!("revoked-key-cert-revoked-{}.sk.pgp", slug))
            .unwrap();
        cert.serialize(&mut fd).unwrap();
    }

    // 0th message sig before t1
    let sig0 = signature::Builder::new(SignatureType::Binary)
        .set_signature_creation_time(t0).unwrap()
        .set_issuer_fingerprint(key.fingerprint()).unwrap()
        .set_issuer(key.fingerprint().into()).unwrap()
        .sign_message(&mut signer, msg).unwrap();
    let mut fd = File::create("revoked-key-sig-t0.pgp").unwrap();
    Packet::from(sig0).serialize(&mut fd).unwrap();

    // 0th message sig before t1, subkey
    let sig0 = signature::Builder::new(SignatureType::Binary)
        .set_signature_creation_time(t0).unwrap()
        .set_issuer_fingerprint(subkey.fingerprint()).unwrap()
        .set_issuer(subkey.fingerprint().into()).unwrap()
        .sign_message(&mut sk_signer, msg).unwrap();
    let mut fd = File::create("revoked-key-sig-t0.sk.pgp").unwrap();
    Packet::from(sig0).serialize(&mut fd).unwrap();

    // 1st message sig between t1 and t2
    b = signature::Builder::new(SignatureType::Binary)
        .set_signature_creation_time(t12).unwrap()
        .set_issuer_fingerprint(key.fingerprint()).unwrap()
        .set_issuer(key.fingerprint().into()).unwrap();
    let sig1 = b.sign_message(&mut signer, msg).unwrap();
    let mut fd = File::create("revoked-key-sig-t1-t2.pgp").unwrap();
    Packet::from(sig1).serialize(&mut fd).unwrap();

    // 1st message sig between t1 and t2, subkey
    b = signature::Builder::new(SignatureType::Binary)
        .set_signature_creation_time(t12).unwrap()
        .set_issuer_fingerprint(subkey.fingerprint()).unwrap()
        .set_issuer(subkey.fingerprint().into()).unwrap();
    let sig1 = b.sign_message(&mut sk_signer, msg).unwrap();
    let mut fd = File::create("revoked-key-sig-t1-t2.sk.pgp").unwrap();
    Packet::from(sig1).serialize(&mut fd).unwrap();

    // 2nd message sig between t2 and t3
    b = signature::Builder::new(SignatureType::Binary)
        .set_signature_creation_time(t23).unwrap()
        .set_issuer_fingerprint(key.fingerprint()).unwrap()
        .set_issuer(key.fingerprint().into()).unwrap();
    let sig2 = b.sign_message(&mut signer, msg).unwrap();
    let mut fd = File::create("revoked-key-sig-t2-t3.pgp").unwrap();
    Packet::from(sig2).serialize(&mut fd).unwrap();

    // 2nd message sig between t2 and t3, subkey
    b = signature::Builder::new(SignatureType::Binary)
        .set_signature_creation_time(t23).unwrap()
        .set_issuer_fingerprint(subkey.fingerprint()).unwrap()
        .set_issuer(subkey.fingerprint().into()).unwrap();
    let sig2 = b.sign_message(&mut sk_signer, msg).unwrap();
    let mut fd = File::create("revoked-key-sig-t2-t3.sk.pgp").unwrap();
    Packet::from(sig2).serialize(&mut fd).unwrap();

    // 3rd message sig between t3 and now
    b = signature::Builder::new(SignatureType::Binary)
        .set_signature_creation_time(std::time::SystemTime::now()).unwrap()
        .set_issuer_fingerprint(key.fingerprint()).unwrap()
        .set_issuer(key.fingerprint().into()).unwrap();
    let sig3 = b.sign_message(&mut signer, msg).unwrap();
    let mut fd = File::create("revoked-key-sig-t3-now.pgp").unwrap();
    Packet::from(sig3).serialize(&mut fd).unwrap();

    // 3rd message sig between t3 and now, subkey
    b = signature::Builder::new(SignatureType::Binary)
        .set_signature_creation_time(std::time::SystemTime::now()).unwrap()
        .set_issuer_fingerprint(subkey.fingerprint()).unwrap()
        .set_issuer(subkey.fingerprint().into()).unwrap();
    let sig3 = b.sign_message(&mut sk_signer, msg).unwrap();
    let mut fd = File::create("revoked-key-sig-t3-now.sk.pgp").unwrap();
    Packet::from(sig3).serialize(&mut fd).unwrap();
}
