#!/usr/bin/expect

set test_script "./tests/dsm/generate_gpg_import_dsm.sh"
set ciphersuite [lindex $argv 1];
set verbosity [lindex $argv 3];
set pass "my-test-passphrase"

spawn "$test_script" -c "$ciphersuite" -v "$verbosity"

expect "Enter test passphrase"
send "$pass\n"

expect "SUCCESS"

interact
