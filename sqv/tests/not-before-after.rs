extern crate assert_cli;

#[cfg(test)]
mod integration {
    use assert_cli::Assert;

    fn p(filename: &str) -> String {
        format!("../openpgp/tests/data/{}", filename)
    }

    #[test]
    fn unconstrained() {
        Assert::cargo_binary("sqv")
            .with_args(
                &["--keyring",
                  &p("keys/emmelie-dorothea-dina-samantha-awina-ed25519.pgp"),
                  &p("messages/a-cypherpunks-manifesto.txt.ed25519.sig"),
                  &p("messages/a-cypherpunks-manifesto.txt")])
            .stdout().is("8E8C33FA4626337976D97978069C0C348DD82C19")
            .unwrap();
    }

    #[test]
    fn in_interval() {
        Assert::cargo_binary("sqv")
            .with_args(
                &["--keyring",
                  &p("keys/emmelie-dorothea-dina-samantha-awina-ed25519.pgp"),
                  "--not-before", "2018-08-14",
                  "--not-after", "2018-08-15",
                  &p("messages/a-cypherpunks-manifesto.txt.ed25519.sig"),
                  &p("messages/a-cypherpunks-manifesto.txt")])
            .stdout().is("8E8C33FA4626337976D97978069C0C348DD82C19")
            .unwrap();
    }

    #[test]
    fn before() {
        Assert::cargo_binary("sqv")
            .with_args(
                &["--keyring",
                  &p("keys/emmelie-dorothea-dina-samantha-awina-ed25519.pgp"),
                  "--not-before", "2018-08-15",
                  &p("messages/a-cypherpunks-manifesto.txt.ed25519.sig"),
                  &p("messages/a-cypherpunks-manifesto.txt")])
            .fails()
            .unwrap();
    }

    #[test]
    fn after() {
        Assert::cargo_binary("sqv")
            .with_args(
                &["--keyring",
                  &p("keys/emmelie-dorothea-dina-samantha-awina-ed25519.pgp"),
                  "--not-after", "2018-08-13",
                  &p("messages/a-cypherpunks-manifesto.txt.ed25519.sig"),
                  &p("messages/a-cypherpunks-manifesto.txt")])
            .fails()
            .unwrap();
    }
}
