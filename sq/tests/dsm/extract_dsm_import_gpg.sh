#!/bin/bash -e

sq="../target/debug/sq"

case "$1" in
    --p256) cipher_suite="nistp256";;
    --p384) cipher_suite="nistp384";;
    --p521) cipher_suite="nistp521";;
    --cv25519) cipher_suite="cv25519";;
    --rsa2k) cipher_suite="rsa2k";;
    --rsa3k) cipher_suite="rsa3k";;
    --rsa4k) cipher_suite="rsa4k";;
    -*) echo "unknown option: $1" >&2; exit 1;;
esac

case "$3" in
    1|2) verbosity=$3;;
    *) verbosity=0
esac

# tmp directory, erased on exit
create_tmp_dir() {
    eval "$1"="$(mktemp -d)"
}

erase_tmp_dirs() {
    rm -rf "$data" "$gpg_homedir"
}

comm() {
    printf "~~~ %s ~~~\n" "$1"
}

my_cat() {
    if [[ "$verbosity" -eq 1 ]]; then
        head -n4 "$1"
        echo "    [TRUNCATED OUTPUT]"
    fi
    if [[ "$verbosity" -eq 2 ]]; then
        cat "$1"
    fi
}

data=""
create_tmp_dir data

gpg_homedir=""
create_tmp_dir gpg_homedir

gpg="gpg --homedir=$gpg_homedir --trust-model always --pinentry-mode loopback"

trap 'erase_tmp_dirs' EXIT

# Test files
message=$data/message.txt
alice_public=$data/alice.asc
alice_local_priv=$data/alice_local_priv.asc
bob_public=$data/bob_local_pub.asc
encrypted=$data/message.txt.gpg
decrypted_remote=$data/decrypted_remote.txt
decrypted_local=$data/decrypted_local.txt
decrypted_gpg=$data/decrypted_gpg.txt
signed_local=$data/message.signed_local.asc
signed_remote=$data/message.signed_remote.asc
signed_gpg=$data/message.signed_gpg.gpg

random=$(head /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w "10" | head -n 1)
alice_key_name="test-gpg-import-alice-$random"
bob_key_name="test-gpg-import-bob-$random"

echo "Enter test passphrase"
read -r test_passphrase

comm "sq --version"
$sq --version
comm "gpg --version"
$gpg --version

comm "generate keys (Alice - exportable with $cipher_suite)"
$sq key generate --dsm-key="$alice_key_name" --dsm-exportable --userid="Alice <alice@openpgp.example>" --cipher-suite="$cipher_suite"

comm "extract Alice key and certificate"
$sq key extract-dsm-secret --dsm-key="$alice_key_name" --output="$alice_local_priv"
my_cat "$alice_local_priv"
$sq key extract-cert --dsm-key="$alice_key_name" --output="$alice_public"
my_cat "$alice_public"

comm "generate keys (Bob)"
$sq key generate --dsm-key="$bob_key_name" --userid="Bob <bob@openpgp.example>"
$sq key extract-cert --dsm-key="$bob_key_name" > "$bob_public"
my_cat "$bob_public"

comm "import keys into gpg"
$gpg --import "$alice_public"
$gpg --import --passphrase="$test_passphrase" "$alice_local_priv"
$gpg --import "$bob_public"

comm "gpg --list keys; gpg --list-secret-keys"
$gpg --list-keys
$gpg --list-secret-keys

printf "Y el verso cae al alma como al pasto el rocío.\n" > "$message"

comm "sign with (i) local key (ii) remote key and (iii) gpg-imported key"
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

comm "encrypt to Alice, sign with Bob's key"
$sq encrypt --signer-dsm-key="$bob_key_name" --recipient-cert "$alice_public" "$message" --output "$encrypted"
my_cat "$encrypted"

comm "decrypt with (i) local key (ii) SDKMS key (iii) gpg-imported key"
$sq decrypt --signer-cert="$bob_public" --recipient-key="$alice_local_priv" "$encrypted" --output "$decrypted_local"
diff "$message" "$decrypted_local"
$sq decrypt --signer-cert="$bob_public" --dsm-key="$alice_key_name" "$encrypted" --output "$decrypted_remote"
diff "$message" "$decrypted_remote"
$gpg --passphrase="test_passphrase" --output="$decrypted_gpg" --decrypt "$encrypted"
diff "$message" "$decrypted_gpg"

echo "SUCCESS"
