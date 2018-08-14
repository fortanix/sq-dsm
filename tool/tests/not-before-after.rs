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
                &["-r",
                  &p("keys/emmelie-dorothea-dina-samantha-awina-ed25519.pgp"),
                  &p("messages/a-cypherpunks-manifesto.txt.ed25519.sig"),
                  &p("messages/a-cypherpunks-manifesto.txt")])
            .stdout().is("8E8C 33FA 4626 3379 76D9  7978 069C 0C34 8DD8 2C19")
            .unwrap();
    }

    #[test]
    fn in_interval() {
        Assert::cargo_binary("sqv")
            .with_args(
                &["-r",
                  &p("keys/emmelie-dorothea-dina-samantha-awina-ed25519.pgp"),
                  "--not-before", "2018-08-14",
                  "--not-after", "2018-08-15",
                  &p("messages/a-cypherpunks-manifesto.txt.ed25519.sig"),
                  &p("messages/a-cypherpunks-manifesto.txt")])
            .stdout().is("8E8C 33FA 4626 3379 76D9  7978 069C 0C34 8DD8 2C19")
            .unwrap();
    }

    #[test]
    fn before() {
        Assert::cargo_binary("sqv")
            .with_args(
                &["-r",
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
                &["-r",
                  &p("keys/emmelie-dorothea-dina-samantha-awina-ed25519.pgp"),
                  "--not-after", "2018-08-14",
                  &p("messages/a-cypherpunks-manifesto.txt.ed25519.sig"),
                  &p("messages/a-cypherpunks-manifesto.txt")])
            .fails()
            .unwrap();
    }
}
