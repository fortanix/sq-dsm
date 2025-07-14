#[cfg(test)]
mod integration {
    use std::path;
    use assert_cmd::Command;

    use sequoia_openpgp as openpgp;

    use openpgp::Fingerprint;
    use openpgp::Result;
    use openpgp::cert::prelude::*;
    use openpgp::policy::StandardPolicy;
    use openpgp::parse::Parse;
    use openpgp::types::KeyFlags;

    fn dir() -> path::PathBuf {
        path::Path::new("tests").join("data").join("keys")
    }
    fn alice() -> path::PathBuf {
        //     Fingerprint: 5CCB BA06 74EA 5162 615E  36E9 80E5 ADE9 43CA 0DC3
        // Public-key algo: EdDSA Edwards-curve Digital Signature Algorithm
        // Public-key size: 256 bits
        //      Secret key: Unencrypted
        //   Creation time: 2020-12-21 23:00:49 UTC
        //       Key flags: certification
        //
        //          Subkey: 6A3B 1EC7 6233 62BC 066E  75AB DC42 7976 95D6 24E5
        // Public-key algo: EdDSA Edwards-curve Digital Signature Algorithm
        // Public-key size: 256 bits
        //      Secret key: Unencrypted
        //   Creation time: 2020-12-21 23:00:49 UTC
        //       Key flags: signing
        //
        //          Subkey: 827E 4397 F330 7EDA 6ABD  2A6E AD9C 461D 6D2F 0982
        // Public-key algo: ECDH public key algorithm
        // Public-key size: 256 bits
        //      Secret key: Unencrypted
        //   Creation time: 2020-12-21 23:00:49 UTC
        //       Key flags: transport encryption, data-at-rest encryption
        //
        //          UserID: Alice Lovelace <alice@example.org>
        dir().join("alice-lovelace-encryption-subkey-signing-subkey-priv.pgp")
    }
    fn alice_primary() -> (Fingerprint, KeyFlags) {
        ("5CCB BA06 74EA 5162 615E  36E9 80E5 ADE9 43CA 0DC3".parse().unwrap(),
         KeyFlags::empty().set_certification())
    }
    fn alice_signing() -> (Fingerprint, KeyFlags) {
        ("6A3B 1EC7 6233 62BC 066E  75AB DC42 7976 95D6 24E5".parse().unwrap(),
         KeyFlags::empty().set_signing())
    }
    fn alice_encryption() -> (Fingerprint, KeyFlags) {
        ("827E 4397 F330 7EDA 6ABD  2A6E AD9C 461D 6D2F 0982".parse().unwrap(),
         KeyFlags::empty().set_transport_encryption().set_storage_encryption())
    }
    fn bob() -> path::PathBuf {
        //     Fingerprint: C1CF 22F6 C838 07CE 3901  6CDE 8463 B196 87EE 13BB
        // Public-key algo: EdDSA Edwards-curve Digital Signature Algorithm
        // Public-key size: 256 bits
        //      Secret key: Unencrypted
        //   Creation time: 2020-12-21 23:02:23 UTC
        //       Key flags: certification
        //
        //          UserID: Bob Babbage <bob@example.org>
        dir().join("bob-babbage-cert-only-priv.pgp")
    }
    fn bob_primary() -> (Fingerprint, KeyFlags) {
        ("C1CF 22F6 C838 07CE 3901  6CDE 8463 B196 87EE 13BB".parse().unwrap(),
         KeyFlags::empty().set_certification())
    }

    fn carol() -> path::PathBuf {
        //     Fingerprint: 0B17 34A8 2726 A5D1 D5AC  1568 1EC1 4781 FD88 09B4
        // Public-key algo: EdDSA Edwards-curve Digital Signature Algorithm
        // Public-key size: 256 bits
        //      Secret key: Unencrypted
        //   Creation time: 2020-12-22 00:02:24 UTC
        //       Key flags: certification
        //
        //          Subkey: 3D56 A424 3D5C C345 638D  FB19 05D8 B9EA DB92 A8C1
        // Public-key algo: EdDSA Edwards-curve Digital Signature Algorithm
        // Public-key size: 256 bits
        //      Secret key: Unencrypted
        //   Creation time: 2020-12-22 00:02:24 UTC
        //       Key flags: signing
        //
        //          Subkey: 1F47 6866 1260 CFFA D3DE  B630 5652 476A 8B74 5CE5
        // Public-key algo: ECDH public key algorithm
        // Public-key size: 256 bits
        //      Secret key: Unencrypted
        //   Creation time: 2020-12-22 00:02:24 UTC
        //       Key flags: transport encryption, data-at-rest encryption
        //
        //          UserID: Carol <carol@example.org>
        dir().join("carol-encryption-subkey-signing-subkey-priv.pgp")
    }
    fn carol_primary() -> (Fingerprint, KeyFlags) {
        ("0B17 34A8 2726 A5D1 D5AC  1568 1EC1 4781 FD88 09B4".parse().unwrap(),
         KeyFlags::empty().set_certification())
    }
    fn carol_signing() -> (Fingerprint, KeyFlags) {
        ("3D56 A424 3D5C C345 638D  FB19 05D8 B9EA DB92 A8C1".parse().unwrap(),
         KeyFlags::empty().set_signing())
    }
    fn carol_encryption() -> (Fingerprint, KeyFlags) {
        ("1F47 6866 1260 CFFA D3DE  B630 5652 476A 8B74 5CE5".parse().unwrap(),
         KeyFlags::empty().set_transport_encryption().set_storage_encryption())
    }

    fn check(output: &[u8],
             key_count: usize,
             keys: ((Fingerprint, KeyFlags), &[(Fingerprint, KeyFlags)]))
        -> Result<()>
    {
        let p = &StandardPolicy::new();

        let cert = Cert::from_bytes(output).unwrap();
        let vc = cert.with_policy(p, None).unwrap();

        assert_eq!(key_count, vc.keys().count());

        assert_eq!(vc.primary_key().fingerprint(), keys.0.0);
        assert_eq!(vc.primary_key().key_flags(), Some(keys.0.1));

        for (subkey, keyflags) in keys.1 {
            let mut found = false;
            for k in vc.keys().subkeys() {
                if k.fingerprint() == *subkey {
                    assert_eq!(k.key_flags().as_ref(), Some(keyflags));
                    found = true;
                    break;
                }
            }
            assert!(found);
        }

        Ok(())
    }

    #[test]
    fn adopt_encryption() -> Result<()> {
        // Adopt an encryption subkey.
        let output = Command::cargo_bin("sq")
            .unwrap()
            .args(&[
                "key", "adopt",
                bob().to_str().unwrap(),
                "--keyring", alice().to_str().unwrap(),
                "--key", &alice_encryption().0.to_hex(),
            ])
            .output()
            .expect("Failed to run command");

        assert!(
            output.status.success(),
            "Command failed: {}",
            String::from_utf8_lossy(&output.stderr),
        );

        assert!(
            check(&output.stdout, 2, (bob_primary(), &[alice_encryption()])).is_ok(),
            "check failed"
        );

        Ok(())
    }

    #[test]
    fn adopt_signing() -> Result<()> {
        // Adopt a signing subkey (subkey has secret key material).
        let output = Command::cargo_bin("sq")
            .unwrap()
            .args(&[
                "key", "adopt",
                bob().to_str().unwrap(),
                "--keyring", alice().to_str().unwrap(),
                "--key", &alice_signing().0.to_hex(),
            ])
            .output()
            .expect("Failed to run command");

        assert!(
            output.status.success(),
            "Command failed: {}",
            String::from_utf8_lossy(&output.stderr),
        );

        assert!(
            check(&output.stdout, 2, (bob_primary(), &[alice_signing()])).is_ok(),
            "check failed"
        );

        Ok(())
    }

    #[test]
    fn adopt_certification() -> Result<()> {
        // Adopt a certification subkey (subkey has secret key material).
        let output = Command::cargo_bin("sq")
            .unwrap()
            .args(&[
                "key", "adopt",
                carol().to_str().unwrap(),
                "--keyring", alice().to_str().unwrap(),
                "--key", &alice_primary().0.to_hex(),
            ])
            .output()
            .expect("Failed to run command");

        assert!(
            output.status.success(),
            "Command failed: {}",
            String::from_utf8_lossy(&output.stderr),
        );

        assert!(
            check(&output.stdout, 4, (carol_primary(), &[alice_primary()])).is_ok(),
            "check failed"
        );

        Ok(())
    }

    #[test]
    fn adopt_encryption_and_signing() -> Result<()> {
        // Adopt an encryption subkey and a signing subkey.
        let output = Command::cargo_bin("sq")
            .unwrap()
            .args(&[
                "key", "adopt",
                bob().to_str().unwrap(),
                "--keyring", alice().to_str().unwrap(),
                "--key", &alice_signing().0.to_hex(),
                "--key", &alice_encryption().0.to_hex(),
            ])
            .output()
            .expect("Failed to run command");

        assert!(
            output.status.success(),
            "Command failed: {}",
            String::from_utf8_lossy(&output.stderr),
        );

        assert!(
            check(&output.stdout, 3, (bob_primary(), &[alice_signing(), alice_encryption()])).is_ok(),
            "check failed"
        );

        Ok(())
    }

    #[test]
    fn adopt_twice() -> Result<()> {
        // Adopt the same an encryption subkey twice.
        let output = Command::cargo_bin("sq")
            .unwrap()
            .args(&[
                "key", "adopt",
                bob().to_str().unwrap(),
                "--keyring", alice().to_str().unwrap(),
                "--key", &alice_encryption().0.to_hex(),
                "--key", &alice_encryption().0.to_hex(),
            ])
            .output()
            .expect("Failed to run command");

        assert!(
            output.status.success(),
            "Command failed: {}",
            String::from_utf8_lossy(&output.stderr),
        );

        assert!(
            check(&output.stdout, 2, (bob_primary(), &[alice_encryption()])).is_ok(),
            "check failed"
        );

        Ok(())
    }

    #[test]
    fn adopt_key_appears_twice() -> Result<()> {
        // Adopt the an encryption subkey that appears twice.
        let output = Command::cargo_bin("sq")
            .unwrap()
            .args(&[
                "key", "adopt",
                bob().to_str().unwrap(),
                "--keyring", alice().to_str().unwrap(),
                "--keyring", alice().to_str().unwrap(),
                "--key", &alice_encryption().0.to_hex(),
            ])
            .output()
            .expect("Failed to run command");

        assert!(
            output.status.success(),
            "Command failed: {}",
            String::from_utf8_lossy(&output.stderr),
        );

        assert!(
            check(&output.stdout, 2, (bob_primary(), &[alice_encryption()])).is_ok(),
            "check failed"
        );

        Ok(())
    }

    #[test]
    fn adopt_own_encryption() -> Result<()> {
        // Adopt its own encryption subkey.  This should be a noop.
        let output = Command::cargo_bin("sq")
            .unwrap()
            .args(&[
                "key", "adopt",
                alice().to_str().unwrap(),
                "--keyring", alice().to_str().unwrap(),
                "--key", &alice_encryption().0.to_hex(),
            ])
            .output()
            .expect("Failed to run command");

        assert!(
            output.status.success(),
            "Command failed: {}",
            String::from_utf8_lossy(&output.stderr),
        );

        assert!(
            check(&output.stdout, 3, (alice_primary(), &[alice_encryption()])).is_ok(),
            "check failed"
        );

        Ok(())
    }

    #[test]
    fn adopt_own_primary() -> Result<()> {
        // Adopt own primary key.
        let output = Command::cargo_bin("sq")
            .unwrap()
            .args(&[
                "key", "adopt",
                bob().to_str().unwrap(),
                "--keyring", bob().to_str().unwrap(),
                "--key", &bob_primary().0.to_hex(),
            ])
            .output()
            .expect("Failed to run command");

        assert!(
            output.status.success(),
            "Command failed: {}",
            String::from_utf8_lossy(&output.stderr),
        );

        assert!(
            check(&output.stdout, 2, (bob_primary(), &[bob_primary()])).is_ok(),
            "check failed"
        );

        Ok(())
    }

    #[test]
    fn adopt_missing() -> Result<()> {
        // Adopt a key that is not present.
        Command::cargo_bin("sq")
            .unwrap()
            .args(&[
                "key", "adopt",
                bob().to_str().unwrap(),
                "--keyring", bob().to_str().unwrap(),
                "--key", "1234 5678 90AB CDEF  1234 5678 90AB CDEF",
            ])
            .assert()
            .failure(); 

        Ok(())
    }

    #[test]
    fn adopt_from_multiple() -> Result<()> {
        // Adopt from multiple certificates simultaneously.
        let output = Command::cargo_bin("sq")
            .unwrap()
            .args(&[
                "key", "adopt",
                bob().to_str().unwrap(),
                "--keyring", alice().to_str().unwrap(),
                "--key", &alice_signing().0.to_hex(),
                "--key", &alice_encryption().0.to_hex(),
                "--keyring", carol().to_str().unwrap(),
                "--key", &carol_signing().0.to_hex(),
                "--key", &carol_encryption().0.to_hex(),
            ])
            .output()
            .expect("Failed to run command");

        assert!(
            output.status.success(),
            "Command failed: {}",
            String::from_utf8_lossy(&output.stderr),
        );

        assert!(
            check(
                &output.stdout,
                5,
                (
                    bob_primary(),
                    &[
                        alice_signing(),
                        alice_encryption(),
                        carol_signing(),
                        carol_encryption()
                    ]
                )
            )
            .is_ok(),
            "check failed"
        );

        Ok(())
    }
}
