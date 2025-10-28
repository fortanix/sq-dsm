#!/bin/bash -e

sq=""
SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
source $SCRIPT_DIR/common.sh

random=$(head /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w "10" | head -n 1)
data=""
create_tmp_dir data
trap 'erase_tmp_dir $data' EXIT

# Test files
message=$data/message.txt

# Intial round files
initial_public_cert=$data/alice.initial.asc
initial_encrypted_message=$data/encrypted.initial.txt
initial_decrypted_message=$data/decrypted.initial.txt
initial_signed_message=$data/signed.initial.asc

# 1st round files
decrypted_old_initial_message_1=$data/decrypted.old.initial.1.txt
firstR_rotated_public_cert=$data/alice.first.asc
firstR_encrypted_message=$data/encrypted.first.txt
firstR_decrypted_message=$data/decrypted.first.txt
firstR_signed_message=$data/signed.first.asc

# 2nd round files
decrypted_old_initial_message_2=$data/decrypted.old.initial.2.txt
decrypted_old_first_message_2=$data/decrypted.old.first.2.txt
secondR_rotated_public_cert=$data/alice.second.asc
secondR_encrypted_message=$data/encrypted.second.txt
secondR_decrypted_message=$data/decrypted.second.txt
secondR_signed_message=$data/signed.second.asc

# Ensure FORTANIX_API_ENDPOINT and FORTANIX_API_KEY are set
if [ -z "$FORTANIX_API_ENDPOINT" ] || [ -z "$FORTANIX_API_KEY" ]; then
    echo "FORTANIX_API_ENDPOINT or FORTANIX_API_KEY is not set."
    exit 1
fi

## Test rotate command
printf "Y el verso cae al alma como al pasto el rocío.\n" > "$message"
array=( rsa2k rsa3k rsa4k rsa8k nistp256 nistp384 nistp521 cv25519 )
#-------------------------------------------------------------------------------------------------
for alg in "${array[@]}"
do
    # Intial tests
    
    # 1. Generate key from sq-dsm
    comm "[$alg] Generate key"
    user_id="Knownkey-Test-$alg (sq-dsm $v) <xyz@xyz.xyz>"
    dsm_name="sq-dsm-test-key-rotation-$random-$alg"
    $sq --force key generate --userid="$user_id" --dsm-key="$dsm_name" --cipher-suite="rsa2k" --dsm-exportable >/dev/null

    # 2. Extract PGP cert from the key
    comm "[$alg] Extract PGP certificate"
    $sq --force key extract-cert --dsm-key="$dsm_name" --output "$initial_public_cert"

    # 3. Encrypt & Decrypt test
    comm "[$alg] Initial Encrypt & Decrypt test"
    $sq --force encrypt --recipient-cert "$initial_public_cert" "$message" --output "$initial_encrypted_message"
    $sq --force decrypt --dsm-key="$dsm_name" "$initial_encrypted_message" --output "$initial_decrypted_message"
    diff "$message" "$initial_decrypted_message"

    # 4. Sign & Verify test
    comm "[$alg] Initial Sign & Verify test"
    $sq --force sign --dsm-key="$dsm_name" "$message" --output "$initial_signed_message"
    $sq --force verify --signer-cert="$initial_public_cert" "$initial_signed_message"

    #-------------------------------------------------------------------------------------------------
    # 5. Rotate the key & test new & old keys [1st round]
    # Fetch key-id from DSM
    comm "[$alg] First round : Rotate key"
    curl_resp=$(curl -s -k -X POST "$FORTANIX_API_ENDPOINT/crypto/v1/keys/info" \
        -H "Content-Type: application/json" \
        -H "Authorization: Basic $FORTANIX_API_KEY" \
        -d "{\"name\": \"$dsm_name\"}") 

    primary_key_id=$(echo "$curl_resp" | jq -r '.kid')
    # enter y when asked for key roatation confirmation
    $sq --force key rotate --dsm-key-id "$primary_key_id"

    # 6. Decrypt intial encrypted message on rotated key
    comm "[$alg] First round : Decrypt test"
    $sq --force decrypt --dsm-key="$dsm_name" "$initial_encrypted_message" --output "$decrypted_old_initial_message_1"
    diff "$message" "$decrypted_old_initial_message_1"

    # 7. Extract rotated PGP cert from the key
    comm "[$alg] First round : Extract Rotated PGP certificate"
    $sq --force key extract-cert --dsm-key="$dsm_name" --output "$firstR_rotated_public_cert"

    # 8. Verify previous signed message on rotated key
    comm "[$alg] First round : Verify test"
    $sq --force verify --signer-cert="$firstR_rotated_public_cert" "$initial_signed_message"

    # 9. Encrypt & Decrypt test
    comm "[$alg] First round : Rotated Encrypt & Decrypt test"
    $sq --force encrypt --recipient-cert "$firstR_rotated_public_cert" "$message" --output "$firstR_encrypted_message"
    $sq --force decrypt --dsm-key="$dsm_name" "$firstR_encrypted_message" --output "$firstR_decrypted_message"
    diff "$message" "$firstR_decrypted_message"

    # 10. Sign & Verify test
    comm "[$alg] First round : Rotated Sign & Verify test"
    $sq --force sign --dsm-key="$dsm_name" "$message" --output "$firstR_signed_message"
    $sq --force verify --signer-cert="$firstR_rotated_public_cert" "$firstR_signed_message"

    #-------------------------------------------------------------------------------------------------
    # 11. Again Rotate the key [2nd round]
    comm "[$alg] Second round : Rotate key"
    # enter y when asked for key roatation confirmation
    $sq --force key rotate --dsm-key-id "$primary_key_id"

    # 12. Decrypt initial encrypted message on rotated key
    comm "[$alg] Second round : Decrypt test"
    $sq --force decrypt --dsm-key="$dsm_name" "$initial_encrypted_message" --output "$decrypted_old_initial_message_2"
    diff "$message" "$decrypted_old_initial_message_2"

    # 13. Decrypt first round encrypted message on rotated key
    comm "[$alg] Second round : Decrypt test"
    $sq --force decrypt --dsm-key="$dsm_name" "$firstR_encrypted_message" --output "$decrypted_old_first_message_2"
    diff "$message" "$decrypted_old_first_message_2"

    # 14. Extract rotated PGP cert from the key
    comm "[$alg] Second round : Extract Rotated PGP certificate"
    $sq --force key extract-cert --dsm-key="$dsm_name" --output "$secondR_rotated_public_cert"

    # 15. Verify initial signed message on rotated key
    comm "[$alg] Second round : Verify test"
    $sq --force verify --signer-cert="$secondR_rotated_public_cert" "$initial_signed_message"

    # 16. Verify first round signed message on rotated key
    comm "[$alg] Second round : Verify test"
    $sq --force verify --signer-cert="$secondR_rotated_public_cert" "$firstR_signed_message"

    # 17. Encrypt & Decrypt test
    comm "[$alg] Second round : Rotated Encrypt & Decrypt test"
    $sq --force encrypt --recipient-cert "$secondR_rotated_public_cert" "$message" --output "$secondR_encrypted_message"
    $sq --force decrypt --dsm-key="$dsm_name" "$secondR_encrypted_message" --output "$secondR_decrypted_message"
    diff "$message" "$secondR_decrypted_message"

    # 18. Sign & Verify test
    comm "[$alg] Second round : Rotated Sign & Verify test"
    $sq --force sign --dsm-key="$dsm_name" "$message" --output "$secondR_signed_message"
    $sq --force verify --signer-cert="$secondR_rotated_public_cert" "$secondR_signed_message"

    echo -e "\n~~~ [$alg] SUCCESS ~~~ \n"
done

echo "SUCCESS"