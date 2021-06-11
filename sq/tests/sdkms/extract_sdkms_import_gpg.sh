#!/bin/bash -e

# tmp directory, erased on exit
create_tmp_dir() {
    eval "$1"="$(mktemp -d)"
}

comm() {
    printf "~~~ %s ~~~\n" "$1"
}

erase_tmp_dirs() {
    rm -rf "$data" "$gpg_homedir"
}

data=""
create_tmp_dir data

gpg_homedir=""
create_tmp_dir gpg_homedir

trap 'erase_tmp_dirs' EXIT

sq="cargo run --"
gpg="gpg --homedir=$gpg_homedir --trust-model always"

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

alice_key_name="test-alice-$(head /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w "${1:-10}" | head -n 1)"
bob_key_name="test-bob-bb$(head /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w "${1:-10}" | head -n 1)"

comm "sq --version"
$sq --version
comm "gpg --version"
$gpg --version

comm "generate keys (Alice - exportable with $cipher_suite)"
$sq key generate --sdkms-key="$alice_key_name" --sdkms-exportable --userid="Alice <alice@openpgp.example>" --cipher-suite="$cipher_suite"

comm "extract Alice key and certificate"
$sq key extract-sdkms-secret --sdkms-key="$alice_key_name" --output="$alice_local_priv"
$sq key extract-cert --sdkms-key="$alice_key_name" --output="$alice_public"

comm "generate keys (Bob)"
$sq key generate --sdkms-key="$bob_key_name" --userid="Bob <bob@openpgp.example>"
$sq key extract-cert --sdkms-key="$bob_key_name" > "$bob_public"

echo $gpg_homedir
ls $gpg_homedir

comm "import keys into gpg"
$gpg --import "$alice_public"
$gpg --import "$alice_local_priv"
$gpg --import "$bob_public"

$gpg --list-keys
$gpg --list-secret-keys

printf "Y el verso cae al alma como al pasto el rocío.\n" > "$message"

comm "sign with (i) local key (ii) remote key and (iii) gpg-imported key"
$sq sign --signer-key="$alice_local_priv" "$message" > "$signed_local"
$sq sign --sdkms-key="$alice_key_name" "$message" > "$signed_remote"
$gpg --output=$signed_gpg --sign "$message"

comm "verify with sq and gpg"
$gpg --verify "$signed_remote"
$gpg --verify "$signed_local"
$gpg --verify "$signed_gpg"
$sq verify --signer-cert="$alice_public" "$signed_remote"
$sq verify --signer-cert="$alice_public" "$signed_local"
$sq verify --signer-cert="$alice_public" "$signed_gpg"

comm "encrypt to Alice, sign with Bob's key"
$sq encrypt --signer-sdkms-key="$bob_key_name" --recipient-cert "$alice_public" "$message" --output "$encrypted"

comm "decrypt with (i) local key (ii) SDKMS key (iii) gpg-imported key"
$sq decrypt --signer-cert="$bob_public" --recipient-key="$alice_local_priv" "$encrypted" --output "$decrypted_local"
diff "$message" "$decrypted_local"
$sq decrypt --signer-cert="$bob_public" --sdkms-key="$alice_key_name" "$encrypted" --output "$decrypted_remote"
diff "$message" "$decrypted_remote"
$gpg --output="$decrypted_gpg" --decrypt "$encrypted"
diff "$message" "$decrypted_local"
