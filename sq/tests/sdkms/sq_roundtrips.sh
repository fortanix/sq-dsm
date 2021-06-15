#!/bin/bash -e

sq="cargo run --"

# Parse input flags
if (( $# != 3 )); then
    echo "Usage: sq_roundtrips.sh [--rsa3k, --p256, -p384, --p521, --cv25519] -v <int verbosity [0, 1, 2]>"
    exit 1
fi

case "$1" in
    --p256) cipher_suite="nistp256";;
    --p384) cipher_suite="nistp384";;
    --p521) cipher_suite="nistp521";;
    --cv25519) cipher_suite="cv25519";;
    --rsa3k) cipher_suite="rsa3k";;
    *) echo "unknown option: $1" >&2; exit 1;;
esac

case "$3" in
    0|1|2) verbosity=$3;;
    *) echo "Select verbosity 0, 1, or 2" >&2; exit 1;;
esac

# tmp directory, erased on exit
create_tmp_dir() {
    eval "$1"="$(mktemp -d)"
}

erase_tmp_dir() {
    rm -rf "$1"
}

comm() {
    printf "~~~ %s ~~~\n" "$1"
}

my_cat() {
    if (( $verbosity == 1 )); then
        head -n4 $1
        echo "    [TRUNCATED OUTPUT]"
    fi
    if (( $verbosity == 2 )); then
        cat $1
    fi
}

data=""
create_tmp_dir data

trap 'erase_tmp_dir $data' EXIT

# Test files
message=$data/message.txt
alice_public=$data/alice.asc
bob_sdkms=$data/bob_sdkms.asc
bob_local_priv=$data/bob_local_priv.asc
bob_local_pub=$data/bob_local_pub.asc
encrypted_nosign=$data/message.txt.encrypted.nosign
encrypted_signed=$data/message.txt.encrypted.signed
decrypted_nosign=$data/decrypted.txt.nosign
decrypted_signed=$data/decrypted.txt.signed
signed=$data/message.signed.asc

random=$(head /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w "10" | head -n 1)
alice_key_name="test-sq-roundtrip-alice-$random"
bob_key_name="test-sq-roundtrip-bob-$random"

comm "version"
$sq --version

comm "generate-keys (Alice with $cipher_suite, Bob with default)"
$sq key generate --sdkms-key="$alice_key_name" --userid="Alice Павловна Вишневская <alice@openpgp.example>" --cipher-suite="$cipher_suite"
$sq key generate --sdkms-key="$bob_key_name" --userid="Bob Сергeeвич Прокoфьев <bob@openpgp.example>"
$sq key generate --userid="Bob Сергeeвич Прокoфьев <bob@openpgp.example>" --export="$bob_local_priv"

comm "certificate Alice"
$sq key extract-cert --sdkms-key="$alice_key_name" > "$alice_public"
my_cat "$alice_public"
comm "certificate Bob SDKMS"
$sq key extract-cert --sdkms-key="$bob_key_name" > "$bob_sdkms"
my_cat "$bob_sdkms"
comm "certificate Bob Local"
$sq key extract-cert "$bob_local_priv" > "$bob_local_pub"
my_cat "$bob_local_pub"

printf "Y el verso cae al alma como al pasto el rocío.\n" > "$message"

comm "sign"
$sq sign --sdkms-key="$alice_key_name" "$message" > "$signed"
my_cat "$signed"

comm "verify"
$sq verify --signer-cert="$alice_public" "$signed"

comm "encrypt to Alice, no signatures"
$sq encrypt --recipient-cert "$alice_public" "$message" --output "$encrypted_nosign"
my_cat "$encrypted_nosign"

comm "decrypt"
$sq decrypt --sdkms-key="$alice_key_name" "$encrypted_nosign" --output "$decrypted_nosign"

diff "$message" "$decrypted_nosign"

comm "encrypt to Alice, sign with both Bob keys"
$sq encrypt --signer-sdkms-key="$bob_key_name" --signer-key="$bob_local_priv" --recipient-cert "$alice_public" "$message" --output "$encrypted_signed"
my_cat "$encrypted_signed"

comm "decrypt"
$sq decrypt --signer-cert="$bob_sdkms" --signer-cert="$bob_local_pub" --sdkms-key="$alice_key_name" "$encrypted_signed" --output "$decrypted_signed"

diff "$message" "$decrypted_signed"
