#!/bin/bash -e

# Parse input flags
case "$1" in
    --p256) cipher_suite="nistp256";;
    --p384) cipher_suite="nistp384";;
    --p521) cipher_suite="nistp521";;
    --cv25519) cipher_suite="cv25519";;
    --rsa3k) cipher_suite="rsa3k";;
    -*) echo "unknown option: $1" >&2; exit 1;;
esac

if (( $# != 3 )); then
    echo "Usage: extract_sdkms_import_gpg.sh --[rsa3k, p256, p384, p521, cv25519] -v <int verbosity [0, 1, 2]>"
    exit 1
fi

verbosity=$3

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

gpg_homedir=""
create_tmp_dir gpg_homedir

sq="cargo run --"
gpg="gpg --homedir=$gpg_homedir --trust-model always"

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

comm "sq --version"
$sq --version
comm "gpg --version"
$gpg --version

comm "generate keys (Alice - exportable with $cipher_suite)"
$sq key generate --sdkms-key="$alice_key_name" --sdkms-exportable --userid="Alice <alice@openpgp.example>" --cipher-suite="$cipher_suite"

comm "extract Alice key and certificate"
$sq key extract-sdkms-secret --sdkms-key="$alice_key_name" --output="$alice_local_priv"
my_cat "$alice_local_priv"
$sq key extract-cert --sdkms-key="$alice_key_name" --output="$alice_public"
my_cat "$alice_public"

comm "generate keys (Bob)"
$sq key generate --sdkms-key="$bob_key_name" --userid="Bob <bob@openpgp.example>"
$sq key extract-cert --sdkms-key="$bob_key_name" > "$bob_public"
my_cat "$bob_public"

comm "import keys into gpg"
$gpg --import "$alice_public"
$gpg --import "$alice_local_priv"
$gpg --import "$bob_public"

comm "gpg --list keys; gpg --list-secret-keys"
$gpg --list-keys
$gpg --list-secret-keys

printf "Y el verso cae al alma como al pasto el rocío.\n" > "$message"

comm "sign with (i) local key (ii) remote key and (iii) gpg-imported key"
$sq sign --signer-key="$alice_local_priv" "$message" > "$signed_local"
my_cat "$signed_local"
$sq sign --sdkms-key="$alice_key_name" "$message" > "$signed_remote"
my_cat "$signed_remote"
$gpg --output=$signed_gpg --sign "$message"
my_cat "$signed_gpg"

comm "verify with sq and gpg"
$gpg --verify "$signed_remote"
$gpg --verify "$signed_local"
$gpg --verify "$signed_gpg"
$sq verify --signer-cert="$alice_public" "$signed_remote"
$sq verify --signer-cert="$alice_public" "$signed_local"
$sq verify --signer-cert="$alice_public" "$signed_gpg"

comm "encrypt to Alice, sign with Bob's key"
$sq encrypt --signer-sdkms-key="$bob_key_name" --recipient-cert "$alice_public" "$message" --output "$encrypted"
my_cat "$encrypted"

comm "decrypt with (i) local key (ii) SDKMS key (iii) gpg-imported key"
$sq decrypt --signer-cert="$bob_public" --recipient-key="$alice_local_priv" "$encrypted" --output "$decrypted_local"
diff "$message" "$decrypted_local"
$sq decrypt --signer-cert="$bob_public" --sdkms-key="$alice_key_name" "$encrypted" --output "$decrypted_remote"
diff "$message" "$decrypted_remote"
$gpg --output="$decrypted_gpg" --decrypt "$encrypted"
diff "$message" "$decrypted_local"
