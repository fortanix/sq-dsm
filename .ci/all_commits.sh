#!/usr/bin/env bash

# Test all commits on this branch but the last one.
#
# Used in the all_commits ci job to ensure all commits build
# and tests pass at least for the sequoia-openpgp crate.

# Use dummy identity to make git rebase happy.
git config user.name "C.I. McTestface"
git config user.email "ci.mctestface@example.com"

# We are only interested in fast-forward merges.  If main is not an
# ancestor of HEAD, then we're not doing a fast-forward merge.
if ! git merge-base --is-ancestor origin/main HEAD
then
    echo "***"
    echo "*** WARNING: main cannot be fast-forwarded to HEAD"
    echo "***"
fi

MERGE_BASE=$(git merge-base origin/main HEAD)
if test "x$MERGE_BASE" = x
then
    echo "Failed to find a common ancestor for main and HEAD."
    exit 1
fi

# Show the commit graph from the merge base to HEAD and from the merge
# base to main.
git --no-pager log --pretty=oneline --graph \
    HEAD origin/main --boundary ^$MERGE_BASE

# If the previous commit already is on main we're done.
git merge-base --is-ancestor HEAD~ origin/main &&
  echo "All commits tested already" &&
  exit 0

# Show what we are going to check.
echo "Checking:"
git --no-pager log --pretty=oneline $MERGE_BASE..HEAD~

# Leave out the last commit - it has already been checked.
git checkout HEAD~
# Now, run cargo test on each commit.  Also fail if it leaves the tree
# dirty.
git rebase $MERGE_BASE \
           --exec 'echo ===; echo ===; echo ===; git log -n 1;' \
           --exec 'cargo test -p sequoia-openpgp' \
           --exec 'git diff --exit-code' &&
  echo "All commits passed tests" &&
  exit 0

# The rebase failed - probably because a test failed.
git rebase --abort; exit 1
