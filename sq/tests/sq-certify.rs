use std::fs::File;
use std::time::Duration;

use assert_cli::Assert;
use tempfile::TempDir;

use sequoia_openpgp as openpgp;
use openpgp::Result;
use openpgp::cert::prelude::*;
use openpgp::packet::signature::subpacket::NotationData;
use openpgp::packet::signature::subpacket::NotationDataFlags;
use openpgp::parse::Parse;
use openpgp::policy::StandardPolicy;
use openpgp::serialize::Serialize;

#[test]
fn sq_certify() -> Result<()> {
    let tmp_dir = TempDir::new().unwrap();
    let alice_pgp = tmp_dir.path().join("alice.pgp");
    let bob_pgp = tmp_dir.path().join("bob.pgp");

    let (alice, _) =
        CertBuilder::general_purpose(None, Some("alice@example.org"))
        .generate()?;
    let mut file = File::create(&alice_pgp)?;
    alice.as_tsk().serialize(&mut file)?;

    let (bob, _) =
        CertBuilder::general_purpose(None, Some("bob@example.org"))
        .generate()?;
    let mut file = File::create(&bob_pgp)?;
    bob.serialize(&mut file)?;


    // A simple certification.
    Assert::cargo_binary("sq")
        .with_args(
            &["certify",
              alice_pgp.to_str().unwrap(),
              bob_pgp.to_str().unwrap(),
              "bob@example.org",
            ])
        .stdout().satisfies(|output| {
            let p = &StandardPolicy::new();

            let cert = Cert::from_bytes(output).unwrap();
            let vc = cert.with_policy(p, None).unwrap();

            for ua in vc.userids() {
                if ua.userid().value() == b"bob@example.org" {
                    let certifications: Vec<_>
                        = ua.certifications().collect();
                    assert_eq!(certifications.len(), 1);
                    let c = certifications[0];

                    assert_eq!(c.trust_signature(), None);
                    assert_eq!(c.regular_expressions().count(), 0);
                    assert_eq!(c.revocable().unwrap_or(true), true);
                    assert_eq!(c.exportable_certification().unwrap_or(true), true);
                    // By default, we set a duration.
                    assert!(c.signature_validity_period().is_some());

                    return true;
                }
            }

            false
        },
                            "Bad certification")
        .unwrap();

    // No expiry.
    Assert::cargo_binary("sq")
        .with_args(
            &["certify",
              alice_pgp.to_str().unwrap(),
              bob_pgp.to_str().unwrap(),
              "bob@example.org",
              "--expires", "never"
            ])
        .stdout().satisfies(|output| {
            let p = &StandardPolicy::new();

            let cert = Cert::from_bytes(output).unwrap();
            let vc = cert.with_policy(p, None).unwrap();

            for ua in vc.userids() {
                if ua.userid().value() == b"bob@example.org" {
                    let certifications: Vec<_>
                        = ua.certifications().collect();
                    assert_eq!(certifications.len(), 1);
                    let c = certifications[0];

                    assert_eq!(c.trust_signature(), None);
                    assert_eq!(c.regular_expressions().count(), 0);
                    assert_eq!(c.revocable().unwrap_or(true), true);
                    assert_eq!(c.exportable_certification().unwrap_or(true), true);
                    assert!(c.signature_validity_period().is_none());

                    return true;
                }
            }

            false
        },
                            "Bad certification")
        .unwrap();

    // Have alice certify bob@example.org for 0xB0B.
    Assert::cargo_binary("sq")
        .with_args(
            &["certify",
              alice_pgp.to_str().unwrap(),
              bob_pgp.to_str().unwrap(),
              "bob@example.org",
              "--depth", "10",
              "--amount", "5",
              "--regex", "a",
              "--regex", "b",
              "--local",
              "--non-revocable",
              "--expires-in", "1d",
            ])
        .stdout().satisfies(|output| {
            let p = &StandardPolicy::new();

            let cert = Cert::from_bytes(output).unwrap();
            let vc = cert.with_policy(p, None).unwrap();

            for ua in vc.userids() {
                if ua.userid().value() == b"bob@example.org" {
                    let certifications: Vec<_>
                        = ua.certifications().collect();
                    assert_eq!(certifications.len(), 1);
                    let c = certifications[0];

                    assert_eq!(c.trust_signature(), Some((10, 5)));
                    assert_eq!(&c.regular_expressions().collect::<Vec<_>>()[..],
                               &[ b"a", b"b" ]);
                    assert_eq!(c.revocable(), Some(false));
                    assert_eq!(c.exportable_certification(), Some(false));
                    assert_eq!(c.signature_validity_period(),
                               Some(Duration::new(24 * 60 * 60, 0)));

                    return true;
                }
            }

            false
        },
                            "Bad certification")
        .unwrap();

    // It should fail if the User ID doesn't exist.
    Assert::cargo_binary("sq")
        .with_args(
            &["certify",
              alice_pgp.to_str().unwrap(),
              bob_pgp.to_str().unwrap(),
              "bob",
            ])
        .fails()
        .unwrap();

    // With a notation.
    Assert::cargo_binary("sq")
        .with_args(
            &["certify",
              "--notation", "foo", "bar",
              "--notation", "!foo", "xyzzy",
              "--notation", "hello@example.org", "1234567890",
              alice_pgp.to_str().unwrap(),
              bob_pgp.to_str().unwrap(),
              "bob@example.org",
            ])
        .stdout().satisfies(|output| {
            let p = &mut StandardPolicy::new();

            let cert = Cert::from_bytes(output).unwrap();

            // The standard policy will reject the
            // certification, because it has an unknown
            // critical notation.
            let vc = cert.with_policy(p, None).unwrap();
            for ua in vc.userids() {
                if ua.userid().value() == b"bob@example.org" {
                    let certifications: Vec<_>
                        = ua.certifications().collect();
                    assert_eq!(certifications.len(), 0);
                }
            }

            // Accept the critical notation.
            p.good_critical_notations(&["foo"]);
            let vc = cert.with_policy(p, None).unwrap();

            for ua in vc.userids() {
                if ua.userid().value() == b"bob@example.org" {
                    let certifications: Vec<_>
                        = ua.certifications().collect();
                    assert_eq!(certifications.len(), 1);

                    let c = certifications[0];

                    assert_eq!(c.trust_signature(), None);
                    assert_eq!(c.regular_expressions().count(), 0);
                    assert_eq!(c.revocable().unwrap_or(true), true);
                    assert_eq!(c.exportable_certification().unwrap_or(true), true);
                    // By default, we set a duration.
                    assert!(c.signature_validity_period().is_some());

                    let hr = NotationDataFlags::empty().set_human_readable();
                    let notations = &mut [
                        (NotationData::new("foo", "bar", hr.clone()), false),
                        (NotationData::new("foo", "xyzzy", hr.clone()), false),
                        (NotationData::new("hello@example.org", "1234567890", hr), false)
                    ];

                    for n in c.notation_data() {
                        if n.name() == "salt@notations.sequoia-pgp.org" {
                            continue;
                        }

                        for (m, found) in notations.iter_mut() {
                            if n == m {
                                assert!(!*found);
                                *found = true;
                            }
                        }
                    }
                    for (n, found) in notations.iter() {
                        assert!(found, "Missing: {:?}", n);
                    }

                    return true;
                }
            }

            false
        },
                            "Bad certification")
        .unwrap();

    Ok(())
}
