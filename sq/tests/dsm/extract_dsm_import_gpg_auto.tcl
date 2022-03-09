#!/usr/bin/expect

set test_script "./tests/dsm/extract_dsm_import_gpg.sh"
set ciphersuite [lindex $argv 1];
set verbosity [lindex $argv 3];
set pass "my-test-passphrase"

spawn "$test_script" -c "$ciphersuite" -v "$verbosity"

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
