use std::fs::{self, File};
use std::io;

extern crate assert_cli;
use assert_cli::Assert;
extern crate tempfile;
use tempfile::TempDir;

extern crate sequoia_openpgp as openpgp;
use crate::openpgp::{Packet, PacketPile, TPK};
use crate::openpgp::crypto::KeyPair;
use crate::openpgp::packet::key::SecretKeyMaterial;
use crate::openpgp::constants::{CompressionAlgorithm, DataFormat, SignatureType};
use crate::openpgp::parse::Parse;
use crate::openpgp::serialize::stream::{Message, Signer, Compressor, LiteralWriter};

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
            &["--home",
              &tmp_dir.path().to_string_lossy(),
              "sign",
              "--secret-key-file",
              &p("keys/dennis-simon-anton-private.pgp"),
              "--output",
              &sig.to_string_lossy(),
              &p("messages/a-cypherpunks-manifesto.txt")])
        .unwrap();

    // Check that the content is sane.
    let packets: Vec<Packet> =
        PacketPile::from_file(&sig).unwrap().into_children().collect();
    assert_eq!(packets.len(), 3);
    if let Packet::OnePassSig(ref ops) = packets[0] {
        assert!(ops.last());
        assert_eq!(ops.typ(), SignatureType::Binary);
    } else {
        panic!("expected one pass signature");
    }
    if let Packet::Literal(_) = packets[1] {
        // Do nothing.
    } else {
        panic!("expected literal");
    }
    if let Packet::Signature(ref sig) = packets[2] {
        assert_eq!(sig.typ(), SignatureType::Binary);
    } else {
        panic!("expected signature");
    }

    let content = fs::read(&sig).unwrap();
    assert!(&content[..].starts_with(b"-----BEGIN PGP MESSAGE-----\n\n"));

    // Verify signed message.
    Assert::cargo_binary("sq")
        .with_args(
            &["--home",
              &tmp_dir.path().to_string_lossy(),
              "verify",
              "--public-key-file",
              &p("keys/dennis-simon-anton.pgp"),
              &sig.to_string_lossy()])
        .unwrap();
}

#[test]
fn sq_sign_append() {
    let tmp_dir = TempDir::new().unwrap();
    let sig0 = tmp_dir.path().join("sig0");

    // Sign message.
    Assert::cargo_binary("sq")
        .with_args(
            &["--home",
              &tmp_dir.path().to_string_lossy(),
              "sign",
              "--secret-key-file",
              &p("keys/dennis-simon-anton-private.pgp"),
              "--output",
              &sig0.to_string_lossy(),
              &p("messages/a-cypherpunks-manifesto.txt")])
        .unwrap();

    // Check that the content is sane.
    let packets: Vec<Packet> =
        PacketPile::from_file(&sig0).unwrap().into_children().collect();
    assert_eq!(packets.len(), 3);
    if let Packet::OnePassSig(ref ops) = packets[0] {
        assert!(ops.last());
        assert_eq!(ops.typ(), SignatureType::Binary);
    } else {
        panic!("expected one pass signature");
    }
    if let Packet::Literal(_) = packets[1] {
        // Do nothing.
    } else {
        panic!("expected literal");
    }
    if let Packet::Signature(ref sig) = packets[2] {
        assert_eq!(sig.typ(), SignatureType::Binary);
    } else {
        panic!("expected signature");
    }

    let content = fs::read(&sig0).unwrap();
    assert!(&content[..].starts_with(b"-----BEGIN PGP MESSAGE-----\n\n"));

    // Verify signed message.
    Assert::cargo_binary("sq")
        .with_args(
            &["--home",
              &tmp_dir.path().to_string_lossy(),
              "verify",
              "--public-key-file",
              &p("keys/dennis-simon-anton.pgp"),
              &sig0.to_string_lossy()])
        .unwrap();

    // Now add a second signature with --append.
    let sig1 = tmp_dir.path().join("sig1");
    Assert::cargo_binary("sq")
        .with_args(
            &["--home",
              &tmp_dir.path().to_string_lossy(),
              "sign",
              "--append",
              "--secret-key-file",
              &p("keys/erika-corinna-daniela-simone-antonia-nistp256-private.pgp"),
              "--output",
              &sig1.to_string_lossy(),
              &sig0.to_string_lossy()])
        .unwrap();

    // Check that the content is sane.
    let packets: Vec<Packet> =
        PacketPile::from_file(&sig1).unwrap().into_children().collect();
    assert_eq!(packets.len(), 5);
    if let Packet::OnePassSig(ref ops) = packets[0] {
        assert!(! ops.last());
        assert_eq!(ops.typ(), SignatureType::Binary);
    } else {
        panic!("expected one pass signature");
    }
    if let Packet::OnePassSig(ref ops) = packets[1] {
        assert!(ops.last());
        assert_eq!(ops.typ(), SignatureType::Binary);
    } else {
        panic!("expected one pass signature");
    }
    if let Packet::Literal(_) = packets[2] {
        // Do nothing.
    } else {
        panic!("expected literal");
    }
    if let Packet::Signature(ref sig) = packets[3] {
        assert_eq!(sig.typ(), SignatureType::Binary);
        assert_eq!(sig.level(), 0);
    } else {
        panic!("expected signature");
    }
    if let Packet::Signature(ref sig) = packets[4] {
        assert_eq!(sig.typ(), SignatureType::Binary);
        assert_eq!(sig.level(), 0);
    } else {
        panic!("expected signature");
    }

    let content = fs::read(&sig1).unwrap();
    assert!(&content[..].starts_with(b"-----BEGIN PGP MESSAGE-----\n\n"));

    // Verify both signatures of the signed message.
    Assert::cargo_binary("sq")
        .with_args(
            &["--home",
              &tmp_dir.path().to_string_lossy(),
              "verify",
              "--public-key-file",
              &p("keys/dennis-simon-anton.pgp"),
              &sig1.to_string_lossy()])
        .unwrap();
    Assert::cargo_binary("sq")
        .with_args(
            &["--home",
              &tmp_dir.path().to_string_lossy(),
              "verify",
              "--public-key-file",
              &p("keys/erika-corinna-daniela-simone-antonia-nistp256.pgp"),
              &sig1.to_string_lossy()])
        .unwrap();
}

#[test]
#[allow(unreachable_code)]
fn sq_sign_append_on_compress_then_sign() {
    let tmp_dir = TempDir::new().unwrap();
    let sig0 = tmp_dir.path().join("sig0");

    // This is quite an odd scheme, so we need to create such a
    // message by foot.
    let tsk = TPK::from_file(&p("keys/dennis-simon-anton-private.pgp"))
        .unwrap();
    let key = tsk.keys_all().signing_capable().nth(0).unwrap().2;
    let sec = match key.secret() {
        Some(SecretKeyMaterial::Unencrypted(ref u)) => u.clone(),
        _ => unreachable!(),
    };
    let mut keypair = KeyPair::new(key.clone(), sec).unwrap();
    let signer = Signer::new(Message::new(File::create(&sig0).unwrap()),
                             vec![&mut keypair], None)
        .unwrap();
    let compressor = Compressor::new(signer, CompressionAlgorithm::Uncompressed)
        .unwrap();
    let mut literal = LiteralWriter::new(compressor, DataFormat::Binary, None,
                                         None)
        .unwrap();
    io::copy(
        &mut File::open(&p("messages/a-cypherpunks-manifesto.txt")).unwrap(),
        &mut literal)
        .unwrap();
    literal.finalize()
        .unwrap();

    // Check that the content is sane.
    let packets: Vec<Packet> =
        PacketPile::from_file(&sig0).unwrap().into_children().collect();
    assert_eq!(packets.len(), 3);
    if let Packet::OnePassSig(ref ops) = packets[0] {
        assert!(ops.last());
        assert_eq!(ops.typ(), SignatureType::Binary);
    } else {
        panic!("expected one pass signature");
    }
    if let Packet::CompressedData(_) = packets[1] {
        // Do nothing.
    } else {
        panic!("expected compressed data");
    }
    if let Packet::Signature(ref sig) = packets[2] {
        assert_eq!(sig.typ(), SignatureType::Binary);
    } else {
        panic!("expected signature");
    }

    // Verify signed message.
    Assert::cargo_binary("sq")
        .with_args(
            &["--home",
              &tmp_dir.path().to_string_lossy(),
              "verify",
              "--public-key-file",
              &p("keys/dennis-simon-anton.pgp"),
              &sig0.to_string_lossy()])
        .unwrap();

    // Now add a second signature with --append.
    let sig1 = tmp_dir.path().join("sig1");
    Assert::cargo_binary("sq")
        .with_args(
            &["--home",
              &tmp_dir.path().to_string_lossy(),
              "sign",
              "--append",
              "--secret-key-file",
              &p("keys/erika-corinna-daniela-simone-antonia-nistp256-private.pgp"),
              "--output",
              &sig1.to_string_lossy(),
              &sig0.to_string_lossy()])
        .fails() // XXX: Currently, this is not implemented.
        .unwrap();

    // XXX: Currently, this is not implemented in sq.
    return;

    // Check that the content is sane.
    let packets: Vec<Packet> =
        PacketPile::from_file(&sig1).unwrap().into_children().collect();
    assert_eq!(packets.len(), 5);
    if let Packet::OnePassSig(ref ops) = packets[0] {
        assert!(! ops.last());
        assert_eq!(ops.typ(), SignatureType::Binary);
    } else {
        panic!("expected one pass signature");
    }
    if let Packet::OnePassSig(ref ops) = packets[1] {
        assert!(ops.last());
        assert_eq!(ops.typ(), SignatureType::Binary);
    } else {
        panic!("expected one pass signature");
    }
    if let Packet::CompressedData(_) = packets[2] {
        // Do nothing.
    } else {
        panic!("expected compressed data");
    }
    if let Packet::Signature(ref sig) = packets[3] {
        assert_eq!(sig.typ(), SignatureType::Binary);
        assert_eq!(sig.level(), 0);
    } else {
        panic!("expected signature");
    }
    if let Packet::Signature(ref sig) = packets[4] {
        assert_eq!(sig.typ(), SignatureType::Binary);
        assert_eq!(sig.level(), 0);
    } else {
        panic!("expected signature");
    }

    let content = fs::read(&sig1).unwrap();
    assert!(&content[..].starts_with(b"-----BEGIN PGP MESSAGE-----\n\n"));

    // Verify both signatures of the signed message.
    Assert::cargo_binary("sq")
        .with_args(
            &["--home",
              &tmp_dir.path().to_string_lossy(),
              "verify",
              "--public-key-file",
              &p("keys/dennis-simon-anton.pgp"),
              &sig0.to_string_lossy()])
        .unwrap();
    Assert::cargo_binary("sq")
        .with_args(
            &["--home",
              &tmp_dir.path().to_string_lossy(),
              "verify",
              "--public-key-file",
              &p("keys/erika-corinna-daniela-simone-antonia-nistp256.pgp"),
              &sig0.to_string_lossy()])
        .unwrap();
}

#[test]
fn sq_sign_detached() {
    let tmp_dir = TempDir::new().unwrap();
    let sig = tmp_dir.path().join("sig0");

    // Sign detached.
    Assert::cargo_binary("sq")
        .with_args(
            &["--home",
              &tmp_dir.path().to_string_lossy(),
              "sign",
              "--detached",
              "--secret-key-file",
              &p("keys/dennis-simon-anton-private.pgp"),
              "--output",
              &sig.to_string_lossy(),
              &p("messages/a-cypherpunks-manifesto.txt")])
        .unwrap();

    // Check that the content is sane.
    let packets: Vec<Packet> =
        PacketPile::from_file(&sig).unwrap().into_children().collect();
    assert_eq!(packets.len(), 1);
    if let Packet::Signature(ref sig) = packets[0] {
        assert_eq!(sig.typ(), SignatureType::Binary);
    } else {
        panic!("expected signature");
    }

    let content = fs::read(&sig).unwrap();
    assert!(&content[..].starts_with(b"-----BEGIN PGP SIGNATURE-----\n\n"));

    // Verify detached.
    Assert::cargo_binary("sq")
        .with_args(
            &["--home",
              &tmp_dir.path().to_string_lossy(),
              "verify",
              "--public-key-file",
              &p("keys/dennis-simon-anton.pgp"),
              "--detached",
              &sig.to_string_lossy(),
              &p("messages/a-cypherpunks-manifesto.txt")])
        .unwrap();
}

#[test]
fn sq_sign_detached_append() {
    let tmp_dir = TempDir::new().unwrap();
    let sig = tmp_dir.path().join("sig0");

    // Sign detached.
    Assert::cargo_binary("sq")
        .with_args(
            &["--home",
              &tmp_dir.path().to_string_lossy(),
              "sign",
              "--detached",
              "--secret-key-file",
              &p("keys/dennis-simon-anton-private.pgp"),
              "--output",
              &sig.to_string_lossy(),
              &p("messages/a-cypherpunks-manifesto.txt")])
        .unwrap();

    // Check that the content is sane.
    let packets: Vec<Packet> =
        PacketPile::from_file(&sig).unwrap().into_children().collect();
    assert_eq!(packets.len(), 1);
    if let Packet::Signature(ref sig) = packets[0] {
        assert_eq!(sig.typ(), SignatureType::Binary);
    } else {
        panic!("expected signature");
    }

    let content = fs::read(&sig).unwrap();
    assert!(&content[..].starts_with(b"-----BEGIN PGP SIGNATURE-----\n\n"));

    // Verify detached.
    Assert::cargo_binary("sq")
        .with_args(
            &["--home",
              &tmp_dir.path().to_string_lossy(),
              "verify",
              "--public-key-file",
              &p("keys/dennis-simon-anton.pgp"),
              "--detached",
              &sig.to_string_lossy(),
              &p("messages/a-cypherpunks-manifesto.txt")])
        .unwrap();

    // Check that we don't blindly overwrite signatures.
    Assert::cargo_binary("sq")
        .with_args(
            &["--home",
              &tmp_dir.path().to_string_lossy(),
              "sign",
              "--detached",
              "--secret-key-file",
              &p("keys/erika-corinna-daniela-simone-antonia-nistp256-private.pgp"),
              "--output",
              &sig.to_string_lossy(),
              &p("messages/a-cypherpunks-manifesto.txt")])
        .fails()
        .unwrap();

    // Now add a second signature with --append.
    Assert::cargo_binary("sq")
        .with_args(
            &["--home",
              &tmp_dir.path().to_string_lossy(),
              "sign",
              "--detached",
              "--append",
              "--secret-key-file",
              &p("keys/erika-corinna-daniela-simone-antonia-nistp256-private.pgp"),
              "--output",
              &sig.to_string_lossy(),
              &p("messages/a-cypherpunks-manifesto.txt")])
        .unwrap();

    // Check that the content is sane.
    let packets: Vec<Packet> =
        PacketPile::from_file(&sig).unwrap().into_children().collect();
    assert_eq!(packets.len(), 2);
    if let Packet::Signature(ref sig) = packets[0] {
        assert_eq!(sig.typ(), SignatureType::Binary);
    } else {
        panic!("expected signature");
    }
    if let Packet::Signature(ref sig) = packets[1] {
        assert_eq!(sig.typ(), SignatureType::Binary);
    } else {
        panic!("expected signature");
    }

    let content = fs::read(&sig).unwrap();
    assert!(&content[..].starts_with(b"-----BEGIN PGP SIGNATURE-----\n\n"));

    // Verify both detached signatures.
    Assert::cargo_binary("sq")
        .with_args(
            &["--home",
              &tmp_dir.path().to_string_lossy(),
              "verify",
              "--public-key-file",
              &p("keys/dennis-simon-anton.pgp"),
              "--detached",
              &sig.to_string_lossy(),
              &p("messages/a-cypherpunks-manifesto.txt")])
        .unwrap();
    Assert::cargo_binary("sq")
        .with_args(
            &["--home",
              &tmp_dir.path().to_string_lossy(),
              "verify",
              "--public-key-file",
              &p("keys/erika-corinna-daniela-simone-antonia-nistp256.pgp"),
              "--detached",
              &sig.to_string_lossy(),
              &p("messages/a-cypherpunks-manifesto.txt")])
        .unwrap();

    // Finally, check that we don't truncate the file if something
    // goes wrong.
    Assert::cargo_binary("sq")
        .with_args(
            &["--home",
              &tmp_dir.path().to_string_lossy(),
              "sign",
              "--detached",
              "--append",
              "--secret-key-file",
              // Not a private key => signing will fail.
              &p("keys/erika-corinna-daniela-simone-antonia-nistp521.pgp"),
              "--output",
              &sig.to_string_lossy(),
              &p("messages/a-cypherpunks-manifesto.txt")])
        .fails()
        .unwrap();

    // Check that the content is still sane.
    let packets: Vec<Packet> =
        PacketPile::from_file(&sig).unwrap().into_children().collect();
    assert_eq!(packets.len(), 2);
    if let Packet::Signature(ref sig) = packets[0] {
        assert_eq!(sig.typ(), SignatureType::Binary);
    } else {
        panic!("expected signature");
    }
    if let Packet::Signature(ref sig) = packets[1] {
        assert_eq!(sig.typ(), SignatureType::Binary);
    } else {
        panic!("expected signature");
    }
}

// Notarizations ahead.

#[test]
fn sq_sign_append_a_notarization() {
    let tmp_dir = TempDir::new().unwrap();
    let sig0 = tmp_dir.path().join("sig0");

    // Now add a third signature with --append to a notarized message.
    Assert::cargo_binary("sq")
        .with_args(
            &["--home",
              &tmp_dir.path().to_string_lossy(),
              "sign",
              "--append",
              "--secret-key-file",
              &p("keys/erika-corinna-daniela-simone-antonia-nistp256-private.pgp"),
              "--output",
              &sig0.to_string_lossy(),
              &p("messages/signed-1-notarized-by-ed25519.pgp")])
        .unwrap();

    // Check that the content is sane.
    let packets: Vec<Packet> =
        PacketPile::from_file(&sig0).unwrap().into_children().collect();
    assert_eq!(packets.len(), 7);
    if let Packet::OnePassSig(ref ops) = packets[0] {
        assert!(! ops.last());
        assert_eq!(ops.typ(), SignatureType::Binary);
    } else {
        panic!("expected one pass signature");
    }
    if let Packet::OnePassSig(ref ops) = packets[1] {
        assert!(ops.last());
        assert_eq!(ops.typ(), SignatureType::Binary);
    } else {
        panic!("expected one pass signature");
    }
    if let Packet::OnePassSig(ref ops) = packets[2] {
        assert!(ops.last());
        assert_eq!(ops.typ(), SignatureType::Binary);
    } else {
        panic!("expected one pass signature");
    }
    if let Packet::Literal(_) = packets[3] {
        // Do nothing.
    } else {
        panic!("expected literal");
    }
    if let Packet::Signature(ref sig) = packets[4] {
        assert_eq!(sig.typ(), SignatureType::Binary);
        assert_eq!(sig.level(), 0);
    } else {
        panic!("expected signature");
    }
    if let Packet::Signature(ref sig) = packets[5] {
        assert_eq!(sig.typ(), SignatureType::Binary);
        assert_eq!(sig.level(), 1);
    } else {
        panic!("expected signature");
    }
    if let Packet::Signature(ref sig) = packets[6] {
        assert_eq!(sig.typ(), SignatureType::Binary);
        assert_eq!(sig.level(), 1);
    } else {
        panic!("expected signature");
    }

    let content = fs::read(&sig0).unwrap();
    assert!(&content[..].starts_with(b"-----BEGIN PGP MESSAGE-----\n\n"));

    // Verify both notarizations and the signature.
    Assert::cargo_binary("sq")
        .with_args(
            &["--home",
              &tmp_dir.path().to_string_lossy(),
              "verify",
              "--public-key-file",
              &p("keys/neal.pgp"),
              &sig0.to_string_lossy()])
        .unwrap();
    Assert::cargo_binary("sq")
        .with_args(
            &["--home",
              &tmp_dir.path().to_string_lossy(),
              "verify",
              "--public-key-file",
              &p("keys/emmelie-dorothea-dina-samantha-awina-ed25519.pgp"),
              &sig0.to_string_lossy()])
        .unwrap();
    Assert::cargo_binary("sq")
        .with_args(
            &["--home",
              &tmp_dir.path().to_string_lossy(),
              "verify",
              "--public-key-file",
              &p("keys/erika-corinna-daniela-simone-antonia-nistp256.pgp"),
              &sig0.to_string_lossy()])
        .unwrap();
}

#[test]
fn sq_sign_notarize() {
    let tmp_dir = TempDir::new().unwrap();
    let sig0 = tmp_dir.path().join("sig0");

    // Now add a third signature with --append to a notarized message.
    Assert::cargo_binary("sq")
        .with_args(
            &["--home",
              &tmp_dir.path().to_string_lossy(),
              "sign",
              "--notarize",
              "--secret-key-file",
              &p("keys/erika-corinna-daniela-simone-antonia-nistp256-private.pgp"),
              "--output",
              &sig0.to_string_lossy(),
              &p("messages/signed-1.gpg")])
        .unwrap();

    // Check that the content is sane.
    let packets: Vec<Packet> =
        PacketPile::from_file(&sig0).unwrap().into_children().collect();
    assert_eq!(packets.len(), 5);
    if let Packet::OnePassSig(ref ops) = packets[0] {
        assert!(ops.last());
        assert_eq!(ops.typ(), SignatureType::Binary);
    } else {
        panic!("expected one pass signature");
    }
    if let Packet::OnePassSig(ref ops) = packets[1] {
        assert!(ops.last());
        assert_eq!(ops.typ(), SignatureType::Binary);
    } else {
        panic!("expected one pass signature");
    }
    if let Packet::Literal(_) = packets[2] {
        // Do nothing.
    } else {
        panic!("expected literal");
    }
    if let Packet::Signature(ref sig) = packets[3] {
        assert_eq!(sig.typ(), SignatureType::Binary);
        assert_eq!(sig.level(), 0);
    } else {
        panic!("expected signature");
    }
    if let Packet::Signature(ref sig) = packets[4] {
        assert_eq!(sig.typ(), SignatureType::Binary);
        assert_eq!(sig.level(), 1);
    } else {
        panic!("expected signature");
    }

    let content = fs::read(&sig0).unwrap();
    assert!(&content[..].starts_with(b"-----BEGIN PGP MESSAGE-----\n\n"));

    // Verify both notarizations and the signature.
    Assert::cargo_binary("sq")
        .with_args(
            &["--home",
              &tmp_dir.path().to_string_lossy(),
              "verify",
              "--public-key-file",
              &p("keys/neal.pgp"),
              &sig0.to_string_lossy()])
        .unwrap();
    Assert::cargo_binary("sq")
        .with_args(
            &["--home",
              &tmp_dir.path().to_string_lossy(),
              "verify",
              "--public-key-file",
              &p("keys/erika-corinna-daniela-simone-antonia-nistp256.pgp"),
              &sig0.to_string_lossy()])
        .unwrap();
}

#[test]
fn sq_sign_notarize_a_notarization() {
    let tmp_dir = TempDir::new().unwrap();
    let sig0 = tmp_dir.path().join("sig0");

    // Now add a third signature with --append to a notarized message.
    Assert::cargo_binary("sq")
        .with_args(
            &["--home",
              &tmp_dir.path().to_string_lossy(),
              "sign",
              "--notarize",
              "--secret-key-file",
              &p("keys/erika-corinna-daniela-simone-antonia-nistp256-private.pgp"),
              "--output",
              &sig0.to_string_lossy(),
              &p("messages/signed-1-notarized-by-ed25519.pgp")])
        .unwrap();

    // Check that the content is sane.
    let packets: Vec<Packet> =
        PacketPile::from_file(&sig0).unwrap().into_children().collect();
    assert_eq!(packets.len(), 7);
    if let Packet::OnePassSig(ref ops) = packets[0] {
        assert!(ops.last());
        assert_eq!(ops.typ(), SignatureType::Binary);
    } else {
        panic!("expected one pass signature");
    }
    if let Packet::OnePassSig(ref ops) = packets[1] {
        assert!(ops.last());
        assert_eq!(ops.typ(), SignatureType::Binary);
    } else {
        panic!("expected one pass signature");
    }
    if let Packet::OnePassSig(ref ops) = packets[2] {
        assert!(ops.last());
        assert_eq!(ops.typ(), SignatureType::Binary);
    } else {
        panic!("expected one pass signature");
    }
    if let Packet::Literal(_) = packets[3] {
        // Do nothing.
    } else {
        panic!("expected literal");
    }
    if let Packet::Signature(ref sig) = packets[4] {
        assert_eq!(sig.typ(), SignatureType::Binary);
        assert_eq!(sig.level(), 0);
    } else {
        panic!("expected signature");
    }
    if let Packet::Signature(ref sig) = packets[5] {
        assert_eq!(sig.typ(), SignatureType::Binary);
        assert_eq!(sig.level(), 1);
    } else {
        panic!("expected signature");
    }
    if let Packet::Signature(ref sig) = packets[6] {
        assert_eq!(sig.typ(), SignatureType::Binary);
        assert_eq!(sig.level(), 2);
    } else {
        panic!("expected signature");
    }

    let content = fs::read(&sig0).unwrap();
    assert!(&content[..].starts_with(b"-----BEGIN PGP MESSAGE-----\n\n"));

    // Verify both notarizations and the signature.
    Assert::cargo_binary("sq")
        .with_args(
            &["--home",
              &tmp_dir.path().to_string_lossy(),
              "verify",
              "--public-key-file",
              &p("keys/neal.pgp"),
              &sig0.to_string_lossy()])
        .unwrap();
    Assert::cargo_binary("sq")
        .with_args(
            &["--home",
              &tmp_dir.path().to_string_lossy(),
              "verify",
              "--public-key-file",
              &p("keys/emmelie-dorothea-dina-samantha-awina-ed25519.pgp"),
              &sig0.to_string_lossy()])
        .unwrap();
    Assert::cargo_binary("sq")
        .with_args(
            &["--home",
              &tmp_dir.path().to_string_lossy(),
              "verify",
              "--public-key-file",
              &p("keys/erika-corinna-daniela-simone-antonia-nistp256.pgp"),
              &sig0.to_string_lossy()])
        .unwrap();
}
