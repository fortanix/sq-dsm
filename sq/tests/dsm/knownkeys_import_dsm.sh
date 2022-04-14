#!/bin/bash -e

sq=""

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
source $SCRIPT_DIR/common.sh

data=""
create_tmp_dir data
echo "Data dir: $data"

trap 'erase_tmp_dir $data' EXIT

knownkeys="$SCRIPT_DIR/../data/keys"

# Test files
message=$data/message.txt
alice_public=$data/alice.asc
alice_public_extracted=$data/alice_public_extracted.asc

comm "sq --version"
$sq --version

printf "Y el verso cae al alma como al pasto el rocío.\n" > "$message"

for f in "$knownkeys"/*; do
    comm "Knownkey:"
    echo "$f"

    comm "Key name:"
    random=$(head /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w "10" | head -n 1)
    key_name="knownkey-$random"
    echo "$key_name"

    comm "Import into DSM:"
    $sq key dsm-import --dsm-key="$key_name" < "$f"

    comm "Compare certificates"
    $sq key extract-cert --dsm-key="$key_name" > "$alice_public_extracted"
    $sq key extract-cert < "$f" > "$alice_public"
    diff "$alice_public" "$alice_public_extracted"

    comm "Signature roundtrip"
    $sq sign --dsm-key="$key_name" < "$message" | $sq verify --signer-cert="$alice_public"

    comm "Encryption roundtrip"
    $sq encrypt --recipient-cert="$alice_public_extracted" < "$message" | $sq decrypt --dsm-key="$key_name"
done
