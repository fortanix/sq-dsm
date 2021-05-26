#!/bin/bash -e

sq="cargo run -- "

# tmp directory, erased on exit
create_tmp_dir() {
    eval "$1"="$(mktemp -d)"
}

erase_tmp_dir() {
    rm -rf "$1"
}

comm() {
    printf "$ %s\n" "$1"
}

# Parse input flags
while [ "$#" -gt 0 ]; do
  case "$1" in
    --p256) cipher_suite="nistp256"; shift 1;;
    --p384) cipher_suite="nistp384"; shift 1;;
    --p521) cipher_suite="nistp521"; shift 1;;
    --cv25519) cipher_suite="cv25519"; shift 1;;
    --rsa3k) cipher_suite="rsa3k"; shift 1;;
    -*) echo "unknown option: $1" >&2; exit 1;;
  esac
done

data=""
create_tmp_dir data

trap 'erase_tmp_dir $data' EXIT

# Test files
message=$data/message.txt
alice_public=$data/alice.asc
bob_sdkms=$data/bob_sdkms.asc
bob_local_priv=$data/bob_local_priv.asc
bob_local_pub=$data/bob_local_pub.asc
encrypted=$data/message.txt.gpg
decrypted=$data/decrypted.txt
signed=$data/message.signed.asc

alice_key_name="test-alice-$(head /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w "${1:-10}" | head -n 1)"
bob_key_name="test-bob-bb$(head /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w "${1:-10}" | head -n 1)"

comm "version"
$sq --version

comm "generate-keys (Alice with $cipher_suite, Bob with default)"
$sq key generate --sdkms-key="$alice_key_name" --userid="Alice Павловна Вишневская <alice@openpgp.example>" --cipher-suite="$cipher_suite"
$sq key generate --sdkms-key="$bob_key_name" --userid="Bob Сергeeвич Прокoфьев <bob@openpgp.example>"
$sq key generate --userid="Bob Сергeeвич Прокoфьев <bob@openpgp.example>" --export="$bob_local_priv"

comm "certificates"
$sq key extract-cert --sdkms-key="$alice_key_name" > "$alice_public"
$sq key extract-cert --sdkms-key="$bob_key_name" > "$bob_sdkms"
$sq key extract-cert "$bob_local_priv" > "$bob_local_pub"

printf "Y el verso cae al alma como al pasto el rocío.\n" > "$message"

comm "sign"
$sq sign --sdkms-key="$alice_key_name" "$message" > "$signed"

comm "verify"
$sq verify --signer-cert="$alice_public" "$signed"

comm "encrypt to Alice, sign with both Bob keys"
$sq encrypt --signer-sdkms-key="$bob_key_name" --signer-key="$bob_local_priv" --recipient-cert "$alice_public" "$message" --output "$encrypted"

comm "decrypt"
$sq decrypt --signer-cert="$bob_sdkms" --signer-cert="$bob_local_pub" --sdkms-key="$alice_key_name" "$encrypted" --output "$decrypted"

diff "$message" "$decrypted"
