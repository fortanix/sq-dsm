use std::fs;

extern crate assert_cli;
use assert_cli::Assert;
extern crate tempfile;
use tempfile::TempDir;

extern crate openpgp;
use openpgp::{Packet, PacketPile, Reader};
use openpgp::constants::SignatureType;

fn p(filename: &str) -> String {
    format!("../openpgp/tests/data/{}", filename)
}

#[test]
fn sq_sign() {
    let tmp_dir = TempDir::new().unwrap();
    let sig = tmp_dir.path().join("sig0");

    // Sign message.
    Assert::cargo_binary("sq")
        .with_args(
            &["sign",
              "--secret-key-file",
              &p("keys/dennis-simon-anton-private.pgp"),
              "--output",
              &sig.to_string_lossy(),
              &p("messages/a-cypherpunks-manifesto.txt")])
        .unwrap();

    // Check that the content is sane.
    let packets: Vec<Packet> =
        PacketPile::from_reader(Reader::from_file(&sig).unwrap())
        .unwrap().into_children().collect();
    assert_eq!(packets.len(), 3);
    if let Packet::OnePassSig(ref ops) = packets[0] {
        assert!(ops.last());
        assert_eq!(ops.sigtype(), SignatureType::Binary);
    } else {
        panic!("expected one pass signature");
    }
    if let Packet::Literal(_) = packets[1] {
        // Do nothing.
    } else {
        panic!("expected literal");
    }
    if let Packet::Signature(ref sig) = packets[2] {
        assert_eq!(sig.sigtype(), SignatureType::Binary);
    } else {
        panic!("expected signature");
    }

    let content = fs::read(&sig).unwrap();
    assert!(&content[..].starts_with(b"-----BEGIN PGP MESSAGE-----\n\n"));

    // Verify signed message.
    Assert::cargo_binary("sq")
        .with_args(
            &["verify",
              "--public-key-file",
              &p("keys/dennis-simon-anton.pgp"),
              &sig.to_string_lossy()])
        .unwrap();
}

#[test]
fn sq_sign_detached() {
    let tmp_dir = TempDir::new().unwrap();
    let sig = tmp_dir.path().join("sig0");

    // Sign detached.
    Assert::cargo_binary("sq")
        .with_args(
            &["sign",
              "--detached",
              "--secret-key-file",
              &p("keys/dennis-simon-anton-private.pgp"),
              "--output",
              &sig.to_string_lossy(),
              &p("messages/a-cypherpunks-manifesto.txt")])
        .unwrap();

    // Check that the content is sane.
    let packets: Vec<Packet> =
        PacketPile::from_reader(Reader::from_file(&sig).unwrap())
        .unwrap().into_children().collect();
    assert_eq!(packets.len(), 1);
    if let Packet::Signature(ref sig) = packets[0] {
        assert_eq!(sig.sigtype(), SignatureType::Binary);
    } else {
        panic!("expected signature");
    }

    let content = fs::read(&sig).unwrap();
    assert!(&content[..].starts_with(b"-----BEGIN PGP SIGNATURE-----\n\n"));

    // Verify detached.
    Assert::cargo_binary("sqv")
        .with_args(
            &["--keyring",
              &p("keys/dennis-simon-anton.pgp"),
              &sig.to_string_lossy(),
              &p("messages/a-cypherpunks-manifesto.txt")])
        .unwrap();
}
