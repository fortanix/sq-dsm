#!/bin/bash -e

sq=""
cipher_suite=""

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
# shellcheck source=./common.sh
source $SCRIPT_DIR/common.sh

data=""
create_tmp_dir data

trap 'erase_tmp_dir $data' EXIT

# ISO 8601
past="20210101T000000Z"
future_2039="20390101T000001Z"

random=$(head /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w "10" | head -n 1)

alice_past="test-key-expiration-past-$random"
alice_one_day="test-key-expiration-one-day-$random"
alice_default="test-key-expiration-default-$random"
alice_2039="test-key-expiration-2030-$random"

comm "fail to generate a key that expires in the past"
if $sq key generate --dsm-key="$alice_past" --userid="Old Key <x@x.x>" --cipher-suite="$cipher_suite" --expires="$past" > /dev/null 2>&1; then
    echo "Error: Generated successfully an expired key"
    exit 1
else
    echo "OK"
fi

# The best we can do at the moment is to check the output of 'sq inspect'
check_time() {
    key_name="$1"
    expiry_re="$2"
    inspection=$($sq key extract-cert --dsm-key="$key_name" | $sq inspect)
    count=$(echo "$inspection" | grep -c "$expiry_re" || true)
    if [[ "$count" -ne 2 ]]; then
        echo "Expected $expiry_re everywhere, got:"
        echo "$inspection"
        exit 1
    fi
}

comm "generate a key with default expiry, and check certificate"
$sq key generate --dsm-key="$alice_default" --userid="Default expiry <x@x.x>" --cipher-suite="$cipher_suite"
check_time "$alice_default" "Expiration time.* UTC (creation time + P1095DT62781S)"

comm "generate a key that expires tomorrow, and check certificate"
$sq key generate --dsm-key="$alice_one_day" --userid="One day <x@x.x>" --cipher-suite="$cipher_suite" --expires-in="1d"
check_time "$alice_one_day" "Expiration time.* UTC (creation time + P1D)"

comm "generate a key that expires in 2039, and check certificate"
$sq key generate --dsm-key="$alice_2039" --userid="Alice 2039 <x@x.x>" --cipher-suite="$cipher_suite" --expires="$future_2039"
check_time "$alice_2039" "Expiration time: 2039"
