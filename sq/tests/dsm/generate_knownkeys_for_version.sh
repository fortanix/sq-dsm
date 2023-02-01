#!/bin/bash -e

sq=""

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
source $SCRIPT_DIR/common.sh

data=""
create_tmp_dir data
echo "Data dir: $data"

trap 'erase_tmp_dir $data' EXIT

version_string=$("$sq" --version)
v=${version_string#*(sq-dsm }
v=${v%)*}

versionkeys="$SCRIPT_DIR/../data/knownkeys/sq-dsm-$v"

# Generate keys with this version

random=$(head /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w "10" | head -n 1)

array=( rsa2k rsa3k rsa4k nistp256 nistp384 nistp521 cv25519 )
for alg in "${array[@]}"
do
    dsm_name="generate-knownkeys-test-$random-$alg$"
    keyfile="$versionkeys-$alg.pgp"
    user_id="Knownkey-Test-$alg (sq-dsm $v) <xyz@xyz.xyz>"
    echo "Generating $keyfile..."
    $sq key generate --userid="$user_id" --dsm-key="$dsm_name" --cipher-suite="$alg" --dsm-exportable
    $sq key extract-dsm-secret --dsm-key="$dsm_name" > "$keyfile"
done
