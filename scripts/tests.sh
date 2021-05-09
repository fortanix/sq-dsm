#!/bin/bash

sq_sdkms="cargo run --"

# tmp directory, erased on exit
create_tmp_dir() {
    eval $1="$(mktemp -d)"
    if (( $? != 0 )); then
        echo "Failed to create temporary directory"
        exit $?
    fi
}

erase_tmp_dir() {
    rm -rf $1
    if (( $? != 0 )); then
        echo "Failed to delete temporary directory: $1"
        exit $?
    fi
}


check_exit_code() {
    if (( $1 != $2 )); then
        echo "Failed: Exit code $1, expected $2"
        exit $1
    fi
    echo "    ... OK"
}

comm() {
    printf "$ $1\n"
}

my_cat() {
    head -n1 $1
}

# Parse input flags
while [ "$#" -gt 0 ]; do
  case "$1" in
    --p256) pk_algo="p256"; shift 1;;
    --p521) pk_algo="p521"; shift 1;;
    --p384) pk_algo="p384"; shift 1;;
    --rsa2048) pk_algo="rsa2048"; shift 1;;
    -*) echo "unknown option: $1" >&2; exit 1;;
    *) handle_argument "$1"; shift 1;;
  esac
done

create_tmp_dir data
create_tmp_dir keyring
gpg_flags="--homedir "$keyring" --trust-model always"

trap "erase_tmp_dir $data && erase_tmp_dir $keyring" EXIT

# Test files
message=$data/message.txt
alice_public=$data/alice.asc
encrypted=$data/message.txt.gpg
decrypted=$data/decrypted.txt
signed=$data/message.signed.asc

# Key parameters
key_name="test-script-$(head /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w ${1:-10} | head -n 1)"

comm "version"
$sq_sdkms --version
check_exit_code $? 0

comm "generate-key"
$sq_sdkms generate-key --key-name="$key_name" --user-id="Alice Lovelace <alice@openpgp.example>" --pk-algo="$pk_algo"
check_exit_code $? 0

comm "certificate"
$sq_sdkms certificate --key-name="$key_name" > "$alice_public"
check_exit_code $? 0

printf "Y el verso cae al alma como al pasto el rocío.\n" > "$message"

gpg $gpg_flags --import "$alice_public"
check_exit_code $? 0

comm "sign-detached"
$sq_sdkms sign-detached --key-name="$key_name" "$message" > "$signed"
check_exit_code $? 0

gpg $gpg_flags --verify "$signed" "$message"
check_exit_code $? 0

comm "decrypt"
gpg $gpg_flags --encrypt -r alice "$message"
check_exit_code $? 0

$sq_sdkms decrypt --key-name="$key_name" "$encrypted" > "$decrypted"
check_exit_code $? 0

printf "Checking for decryption correctness"
diff "$decrypted" "$message"
check_exit_code $? 0
