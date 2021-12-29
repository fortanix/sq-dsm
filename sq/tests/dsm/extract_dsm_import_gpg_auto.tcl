#!/usr/bin/expect

set test_script "./tests/dsm/extract_dsm_import_gpg.sh"
set ciphersuite [lindex $argv 0];
set verbosity [lindex $argv 2];
set pass "my-test-passphrase"

spawn "$test_script" "$ciphersuite" -v "$verbosity"

expect "Enter test passphrase"
send "$pass\n"
expect "password: "
send "$pass\n"
expect "password: "
send "$pass\n"
expect "Please enter password"
send "$pass\n"
expect "Please enter password"
send "$pass\n"
expect "Enter password"
send "$pass\n"

interact
