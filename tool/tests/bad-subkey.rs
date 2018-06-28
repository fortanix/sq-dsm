extern crate assert_cli;

#[cfg(test)]
mod integration {
    use std::path;

    use assert_cli::Assert;

    #[test]
    fn bad_subkey() {
        Assert::cargo_binary("sqv")
            .current_dir(path::Path::new("tests").join("data"))
            .with_args(&["-r", "bad-subkey-keyring.pgp",
                         "bad-subkey.txt.sig", "bad-subkey.txt"])
            .stdout().is("8F17 7771 18A3 3DDA 9BA4  8E62 AACB 3243 6300 52D9")
            .unwrap();
    }
}
