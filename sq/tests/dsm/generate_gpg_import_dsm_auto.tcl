#!/usr/bin/expect

set test_script "./tests/dsm/generate_gpg_import_dsm.sh"
set verbosity [lindex $argv 3];
set pass "my-test-passphrase"

spawn "$test_script" -v "$verbosity"

expect "Enter test passphrase"
send "$pass\n"

expect "Enter password*"
send "$pass\n"

expect "Please enter password to decrypt*"
send "$pass\n"

expect "Please enter password to decrypt*"
send "$pass\n"

expect "New password*"
send "$pass\n"

expect "Repeat new password*"
send "$pass\n"

expect {
    "SUCCESS" {exit 0;}
}

exit 1;
