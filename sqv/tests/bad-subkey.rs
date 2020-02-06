extern crate assert_cli;

#[cfg(test)]
mod integration {
    use std::path;

    use assert_cli::Assert;

    #[test]
    fn bad_subkey() {
        Assert::cargo_binary("sqv")
            .current_dir(path::Path::new("tests").join("data"))
            .with_args(&["--keyring", "bad-subkey-keyring.pgp",
                         "bad-subkey.txt.sig", "bad-subkey.txt"])
            .stdout().is("8F17777118A33DDA9BA48E62AACB3243630052D9")
            .unwrap();
    }
}
