#!/usr/bin/env bash

# Test all commits on this branch but the last one.
#
# Used in the all_commits ci job to ensure all commits build
# and tests pass at least for the sequoia-openpgp crate.

# Use dummy identity to make git rebase happy.
git config user.name "C.I. McTestface"
git config user.email "ci.mctestface@example.com"

# If the previous commit already is on main we're done.
git merge-base --is-ancestor HEAD~ origin/main &&
  echo "All commits tested already" &&
  exit 0

# Leave out the last commit - it has already been checked.
git checkout HEAD~
git rebase origin/main \
           --exec 'echo ===; echo ===; echo ===; git log -n 1;' \
           --exec 'cargo test -p sequoia-openpgp' &&
  echo "All commits passed tests" &&
  exit 0

# The rebase failed - probably because a test failed.
git rebase --abort; exit 1
