This is a checklist for doing Sequoia releases.

  1. Starting from origin/main, create a branch XXX for the release.
  1. For all 'Cargo.toml's: Bump version = "XXX".
       - Only do this for non-released crates and those with changes
         relative to the last released version.
  1. For all 'Cargo.toml's: Bump intra-workspace dependencies if necessary.
  1. Update dependencies and run tests.
       - Run 'cargo update' to update the dependencies.  If some
         dependency is updated and breaks due to our MSRV, find a good
         version of that dependency and select it using e.g. 'cargo
         update -p backtrace --precise  -3.46'.
       - Run 'make check'.
       - Run 'cargo run -p sequoia-openpgp --example statistics
         --release -- ../sks-dump-*.pgp' and update
         https://sequoia-pgp.org/tmp/stats.txt .
  1. Update manpage for sqv and sq:
      - Clone https://gitlab.com/sequoia-pgp/manpage-maker to a
        separate location.
      - Add symlinks and run as described in the manpage-maker's readme
      - Copy man-sqv/sqv.1 to sequoia/sqv/man-sqv/sqv.1
      - Copy man-sq*/*.1 to sequoia/sq/man-sq*
      - Make a commit with the message "sq, sqv: Update manpage."
  1. Make a commit with the message "component: Release XXX.".
       - Push this to gitlab, and create a merge request.
  1. Make a tag component/vXXX with the message "component: Release
     XXX." signed with an offline-key.
  1. Make a clean clone of the repository.
  1. For the crate to be published, cd into the directory, and do
     'cargo publish'.
  1. In case of errors, correct them, and go back to the step creating
     the release commit.
  1. Merge the branch to main by merging the merge request created in
     step 6, push the tag.
  1. Make a source distribution, put it on
     https://sequoia-pgp.org/dist/, collect and merge signatures.
  1. Regenerate docs.sequoia-pgp.org.
  1. Announce the release.
       - IRC
       - mailing list
       - web site
