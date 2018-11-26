extern crate assert_cli;

use assert_cli::Assert;

fn p(filename: &str) -> String {
    format!("../openpgp/tests/data/{}", filename)
}

/// Asserts that duplicate signatures are properly ignored.
#[test]
fn ignore_duplicates() {
    // Duplicate is ignored, but remaining one is ok.
    Assert::cargo_binary("sqv")
        .with_args(
            &["--keyring",
              &p("keys/emmelie-dorothea-dina-samantha-awina-ed25519.pgp"),
              &p("messages/a-cypherpunks-manifesto.txt.ed25519.sig.duplicated"),
              &p("messages/a-cypherpunks-manifesto.txt")])
         .unwrap();

    // Duplicate is ignored, and fails to meet the threshold.
    Assert::cargo_binary("sqv")
        .with_args(
            &["--keyring",
              &p("keys/emmelie-dorothea-dina-samantha-awina-ed25519.pgp"),
              "--signatures=2",
              &p("messages/a-cypherpunks-manifesto.txt.ed25519.sig.duplicated"),
              &p("messages/a-cypherpunks-manifesto.txt")])
        .fails()
        .unwrap();
}
