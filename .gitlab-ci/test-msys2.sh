#!/bin/bash
set -e

date
pacman --noconfirm -S --needed \
    base-devel \
    mingw-w64-x86_64-toolchain \
    mingw-w64-x86_64-bzip2 \
    mingw-w64-x86_64-nettle \
    mingw-w64-x86_64-sqlite3 \
    mingw-w64-x86_64-capnproto \
    mingw-w64-x86_64-clang
# ^^ It's worth noting that for Rust < 1.40, bindgen has problem picking up
# correct libclang. This is tested and working for clang 9 but if that
# stops for any reason (newer versions), we'd need to download a specific
# version from repo.msys2.org/mingw/x86_64/ and install it manually.

clang --version

date
# Ensure everything compiles but leave FFI tests for now
cargo check --all --all-targets
cargo test -v \
    -p buffered-reader \
    -p sequoia-ipc \
    -p sequoia-openpgp \
    -p sequoia-sqv \
    -p sequoia-autocrypt \
    -p sequoia-core \
    -p sequoia-net \
    -p sequoia-store
#   -p sequoia-ffi \
#   -p sequoia-openpgp-ffi \
