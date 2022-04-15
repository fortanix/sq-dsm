#!/bin/bash -e

sq=""
cipher_suite=""
cli_auth=false # If false, api-key is passed to the CLI
apikey=

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
# shellcheck source=./common.sh
source $SCRIPT_DIR/common.sh

if [ "$cli_auth" = true ] ; then
    apikey="--api-key=$FORTANIX_API_KEY"
fi

data=""
create_tmp_dir data

trap 'erase_tmp_dir $data' EXIT

# Test files
message=$data/message.txt
alice_public=$data/alice.asc
bob_dsm=$data/bob_dsm.asc
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

comm "generate-keys (Alice with $cipher_suite, Bob with default)"
$sq key generate "$apikey" --dsm-key="$alice_key_name" --userid="Alice Павловна Вишневская <alice@openpgp.example>" --cipher-suite="$cipher_suite"
$sq key generate "$apikey" --dsm-key="$bob_key_name" --userid="Bob Сергeeвич Прокoфьев <bob@openpgp.example>"
$sq key generate "$apikey" --userid="Bob Сергeeвич Прокoфьев <bob@openpgp.example>" --export="$bob_local_priv"

comm "certificate Alice"
$sq key extract-cert "$apikey" --dsm-key="$alice_key_name" > "$alice_public"
my_cat "$alice_public"
comm "certificate Bob SDKMS"
$sq key extract-cert "$apikey" --dsm-key="$bob_key_name" > "$bob_dsm"
my_cat "$bob_dsm"
comm "certificate Bob Local"
$sq key extract-cert "$apikey" "$bob_local_priv" > "$bob_local_pub"
my_cat "$bob_local_pub"

printf "Y el verso cae al alma como al pasto el rocío.\n" > "$message"

comm "sign"
$sq sign "$apikey" --dsm-key="$alice_key_name" "$message" > "$signed"
my_cat "$signed"

comm "verify"
$sq verify --signer-cert="$alice_public" "$signed"

comm "encrypt to Alice, no signatures"
$sq encrypt --recipient-cert "$alice_public" "$message" --output "$encrypted_nosign"
my_cat "$encrypted_nosign"

comm "decrypt"
$sq decrypt "$apikey" --dsm-key="$alice_key_name" "$encrypted_nosign" --output "$decrypted_nosign"

diff "$message" "$decrypted_nosign"

comm "encrypt to Alice, sign with both Bob keys"
$sq encrypt "$apikey" --signer-dsm-key="$bob_key_name" --signer-key="$bob_local_priv" --recipient-cert "$alice_public" "$message" --output "$encrypted_signed"
my_cat "$encrypted_signed"

comm "decrypt"
$sq decrypt "$apikey" --signer-cert="$bob_dsm" --signer-cert="$bob_local_pub" --dsm-key="$alice_key_name" "$encrypted_signed" --output "$decrypted_signed"

diff "$message" "$decrypted_signed"

echo "SUCCESS"
