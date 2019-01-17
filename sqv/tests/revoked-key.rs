extern crate assert_cli;

#[cfg(test)]
mod integration {
    use assert_cli::Assert;
    use std::path;

    #[test]
    fn valid_at_signature_ctime() {
        Assert::cargo_binary("sqv")
            .current_dir(path::Path::new("tests").join("data"))
            .with_args(
                &["--keyring",
                  &"revoked-unrevoked.key",
                  &"rev-unrev-t1-t2.sig",
                  &"rev-unrev-msg.txt"])
            .stdout().is("5EC9 FDA7 E49B 0F43 F480  2DC7 2BD6 1C89 D633 7855")
            .unwrap();
    }

    #[test]
    fn revoked_at_signature_ctime() {
        Assert::cargo_binary("sqv")
            .current_dir(path::Path::new("tests").join("data"))
            .with_args(
                &["--keyring",
                  &"revoked-unrevoked.key",
                  &"rev-unrev-t2-t3.sig",
                  &"rev-unrev-msg.txt"])
            .fails()
            .unwrap();
    }

    #[test]
    fn valid_now() {
        Assert::cargo_binary("sqv")
            .current_dir(path::Path::new("tests").join("data"))
            .with_args(
                &["--keyring",
                  &"revoked-unrevoked.key",
                  &"rev-unrev-t3-now.sig",
                  &"rev-unrev-msg.txt"])
            .stdout().is("5EC9 FDA7 E49B 0F43 F480  2DC7 2BD6 1C89 D633 7855")
            .unwrap();
    }
}
