#!/bin/bash -e

sq=""
# TODO: cipher_suite=""

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
source $SCRIPT_DIR/common.sh

data=""
create_tmp_dir data
echo "Data dir: $data"

gpg_homedir=""
create_tmp_dir gpg_homedir
echo "GPG Home: $gpg_homedir"

gpg="gpg --homedir=$gpg_homedir --trust-model always --pinentry-mode loopback"

trap 'erase_tmp_dir $data && erase_tmp_dir $gpg_homedir' EXIT

# Test files
message=$data/message.txt
alice_public=$data/alice.asc
alice_local_priv=$data/alice_local_priv.asc
alice_extracted_priv=$data/alice_extracted_priv.asc
alice_extracted_pub=$data/alice_extracted_pub.asc
signed_local=$data/message.signed_local.asc
signed_remote=$data/message.signed_remote.asc
signed_gpg=$data/message.signed_gpg.gpg

random=$(head /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w "10" | head -n 1)
alice_key_name="test-gpg-import-alice-$random"

echo "Enter test passphrase"
read -r test_passphrase

comm "sq --version"
$sq --version
comm "gpg --version"
$gpg --version

comm "Generate and export gpg key (Alice)"
$gpg --passphrase="$test_passphrase" --yes --quick-gen-key "Alice (generated with gpg) <alice@fortanix.com>"
$gpg --export-secret-keys --passphrase="$test_passphrase" > "$alice_local_priv"
$gpg --export > "$alice_public"

comm "Import gpg key into DSM"
$sq key dsm-import --dsm-key="$alice_key_name" --dsm-exportable < "$alice_local_priv"

printf "Y el verso cae al alma como al pasto el rocío.\n" > "$message"

## Signature roundtrips

comm "sign with (i) local key (ii) remote key (iii) gpg key"
$sq sign --signer-key="$alice_local_priv" "$message" > "$signed_local"
my_cat "$signed_local"
$sq sign --dsm-key="$alice_key_name" "$message" > "$signed_remote"
my_cat "$signed_remote"
$gpg --sign --passphrase="$test_passphrase" --output="$signed_gpg" "$message"
my_cat "$signed_gpg"

comm "verify with sq and gpg"
$gpg --verify "$signed_remote"
$gpg --verify "$signed_local"
$gpg --verify "$signed_gpg"
$sq verify --signer-cert="$alice_public" "$signed_remote"
$sq verify --signer-cert="$alice_public" "$signed_local"
$sq verify --signer-cert="$alice_public" "$signed_gpg"

# TODO: Encryption roundtrips

comm "Extract from dsm, check fingerprints, userID, timestamps"
$sq key extract-dsm-secret --dsm-key="$alice_key_name" > "$alice_extracted_priv"
$sq key extract-cert --dsm-key="$alice_key_name" > "$alice_extracted_pub"
# TODO: Check fingerprints, timestamps

# Import to gpg
$gpg --import "$alice_extracted_priv"
# TODO: Check error message

echo "SUCCESS"
