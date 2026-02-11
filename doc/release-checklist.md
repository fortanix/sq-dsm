This is a checklist for doing releases.

1. Create a new milestone for the planned release.

1. Announce your intention to do a release on irc, and ask if anyone
   has any changes that want merged before the release, or issues that
   should be fixed.  Ask them to add them to the milestone.

1. Go to the project's repository and scan the open issues and MRs.
   If there is something relevant for the release, add it to the
   milestone.

1. Work through the milestone backlog.

1. Preparation for the actual release.

    We set some variables here that the code snippets below use.

    Select the features to use.  Leave it empty to use the default:
    ```shell
    FEATURES=""
    ```

    In projects where you need to select a specific backend, try:
    ```shell
    FEATURES="--no-default-features --features crypto-openssl"
    ```

    When building a project in a workspace, like `sequoia-openpgp`, do something like:
    ```shell
    FEATURES="-p sequoia-openpgp"
    ```

    Optionally set `CARGO_TARGET_DIR`
    ```shell
    export CARGO_TARGET_DIR=$(mktemp -d)
    ```

1. Make sure your repository is up to date:
    ```
    git fetch
    ```

1. Start from `origin/main`, and create a branch `staging`:
    ```
    git checkout -b staging origin/main
    ```

1. Update Cargo.lock, and run checks locally:

    - Use the project's exact MSRV version.  This is important when
      updating dependencies, and for `cargo publish`.
    ```
    MSRV=$(sed -nE 's/rust-version\s+=\s+"([^"]+)"/\1/p' < Cargo.toml)
    rustup default "$MSRV"
    ```

    - Update the dependencies and run the tests:

    ```
    cargo update
    cargo build --release $FEATURES && \
    cargo test --release $FEATURES && \
    cargo doc --no-deps --release $FEATURES

    git add Cargo.lock
    if [ git diff --cached --exit-code ]; then
      git commit -m "Update dependencies."
    fi
    ```

    - If some dependency is updated and breaks due to our MSRV, find a
    good version of that dependency and select it using e.g. `cargo
    update -p backtrace --precise 3.46`.

    - Audit any new indirect dependencies.

    - Check in any updates with the commit message: "Update
      Cargo.lock".

1. Check for out-of-date dependencies and see if they can be upgraded:

    ```
    cargo outdated -d 1
    editor Cargo.toml # Update version
    cargo update -p PACKAGE --precise VERSION
    cargo build --release $FEATURES && cargo test --release $FEATURES && cargo doc --no-deps --release $FEATURES
    ```

   Add a commit for each dependency or group of dependencies that is
   upgraded ("Upgrade PACKAGE").  Sometimes it is possible to upgrade
   a dependency, but not to the latest version.  Sometimes there is a
   semver change, but we don't rely on the change.  In that case, try
   using a version range:

    ```toml
    memsec = { version = ">=0.5, <0.7", default-features = false }
    ```

   Note: if specifying a lower bound, always specify an upper bound
   otherwise things may break in the future.

1. Bump the version in Cargo.toml to `XXX`.
    ```
    cargo set-version "$VERSION"
    ```

1. Bump the version in `README.md` to `XXX`, if necessary.

1. Make a commit with the message `Release XXX.` or `project: Release XXX.`.
    ```
    git commit -a -S -m "Release $VERSION."
    ```

1. Push this to gitlab as `staging`, create a merge
         request, wait for CI.
    ```
    git push origin staging
    ```

1. Make sure `cargo publish` works:

    ```
    ORIGIN=$(git remote get-url origin)
    cd $(mktemp -d)
    git clone $ORIGIN source
    cd source
    git checkout origin/staging
    cargo publish --dry-run $FEATURES
    ```

    Note: when working with workspaces and cargo <1.68, [the top-level
    `Cargo.lock` file will be
    ignored](https://github.com/rust-lang/cargo/pull/11477).  This can
    be worked around by using a newer rustc or doing something like:

    ```shell
    cp Cargo.lock openpgp
    cargo publish -p sequoia-openpgp --locked --allow-dirty
    ```

1. Wait until CI and `cargo publish --dry-run` are successful.  In
   case of errors, correct them, and go back to the step creating
   the release commit.

    ```
    if [[ "$ORIGIN" =~ ^git@([^:]+):([^/]+)/([^.]+).git$ ]]; then
      while [ $( curl -sSL "https://${BASH_REMATCH[1]}/api/v4/projects/${BASH_REMATCH[2]}%2F${BASH_REMATCH[3]}/pipelines?ref=staging&sha=$(git rev-parse HEAD)" | jq 'map(select(.status != "success")) | length == 0' ) != "true" ]; do
        echo "Pipelines still running... (or failed)"
        sleep 9
      done
    else
      echo Origin not supported
      exit 1
    fi
    ```

1. Run `cargo publish`

    ```
    cargo publish
    ```

1. Merge the merge request

1. Make a tag `vXXX` with the message `Release XXX.` or `project:
   Release XXX.`, as appropriate.  Sign it with an offline key that
   has been certified by our `openpgp-ca@sequoia-pgp.org` key:

    ```
    git tag -s -m "Release $VERSION." v$VERSION
    git verify-tag v$VERSION
    ```

1. Push the signed tag `vXXX`:

    ```
    git push origin v$VERSION
    ```

1. Announce the release.
   - IRC: #sequoia: "I released $VERSION of $PACKAGE"
   - Signed email to `announce@lists.sequoia-pgp.org`,
     `devel@lists.sequoia-pgp.org`, and optionally cc `lwn@lwn.net` if
      there are particularly interesting changes.
   - Blog post when the release contains interesting new stuff.
