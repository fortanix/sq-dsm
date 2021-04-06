This is a checklist for doing Sequoia releases.

  - Starting from origin/main, create a branch XXX for the release.
  - For all 'Cargo.toml's: Bump version = "XXX".
       - Only do this for non-released crates and those with changes
         relative to the last released version.
  - For all 'Cargo.toml's: Bump documentation = "https://.../XXX/...".
  - For all 'Cargo.toml's: Bump intra-workspace dependencies.
  - Update dependencies and run tests.
       - Run 'cargo update' to update the dependencies.  If some
         dependency is updated and breaks due to our MSRV, find a good
         version of that dependency and select it using e.g. 'cargo
         update -p backtrace --precise  -3.46'.
       - Run 'make check'.
       - Run 'cargo run -p sequoia-openpgp --example statistics
         --release -- ../sks-dump-*.pgp' and update
         https://sequoia-pgp.org/tmp/stats.txt .
  - Make a commit with the message "Release XXX.".
       - Push this to gitlab, and create a merge request.
  - Make a tag vXXX with the message "Release XXX." signed with an
    offline-key.
  - Make a clean clone of the repository.
  - For the following crates, cd into the directory, and do 'cargo
    publish':
       - buffered-reader
       - openpgp
       - sqv
  - In case of errors, correct them, and go back to the step creating
    the release commit.
  - Merge the branch to main by merging the merge request created in
    step 6, push the tag.
  - Make a source distribution, put it on
    https://sequoia-pgp.org/dist/, collect and merge signatures.
  - Regenerate docs.sequoia-pgp.org.
  - Announce the release.
       - IRC
       - mailing list
       - web site
