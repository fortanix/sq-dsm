#!/bin/bash -e

sq=""

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
source $SCRIPT_DIR/common.sh

random=$(head /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w "10" | head -n 1)

# Ensure FORTANIX_API_ENDPOINT and FORTANIX_API_KEY are set
if [ -z "$FORTANIX_API_ENDPOINT" ] || [ -z "$FORTANIX_API_KEY" ]; then
    echo "FORTANIX_API_ENDPOINT or FORTANIX_API_KEY is not set."
    exit 1
fi

# Test list-dsm-groups command
# 1. Fetch no.of groups accessible to app from sq-dsm
sq_dsm_groups=$($sq key list-dsm-groups | grep -o '[0-9]\+' | tail -n1)

# 2. Fetch no.of groups accessible to app with GET API 
api_groups=$(curl -s -X GET "$FORTANIX_API_ENDPOINT/sys/v1/groups" \
    -H "Content-Type: application/json" \
    -H "Authorization: Basic $FORTANIX_API_KEY" | jq 'length')

if [[ ! $sq_dsm_groups -eq $api_groups ]]
then
	echo "No.of Groups from SQ-DSM ($sq_dsm_groups) != No.of Groups from GET API ($api_groups)"
	exit 1
fi

# Test custom-metadata in generate
# 1. Create key from sq-dsm with some dummy custom metadata
user_id="Knownkey-Test-$alg (sq-dsm $v) <xyz@xyz.xyz>"
dsm_name="sq-dsm-test-custom-metadata-$random-rsa2k"
$sq key generate --userid="$user_id" --dsm-key="$dsm_name" --key-flags="C,S,EtEr" --cipher-suite="rsa2k" --dsm-exportable --custom-metadata testkey1=testvalue1 --custom-metadata testkey2=testvalue2 >/dev/null

# Edge cases
# should not allow sq_dsm as key
if ($sq key generate --userid="$user_id" --dsm-key="$dsm_name" --key-flags="C,S,EtEr" --cipher-suite="rsa2k" --dsm-exportable --custom-metadata sq_dsm=testvalue1 --custom-metadata testkey2=testvalue2)>/dev/null 2>&1; then
    echo "Error: The command was expected to fail but succeeded.!"
fi

# Duplicate keys in given custom metadata, should fail
if ($sq key generate --userid="$user_id" --dsm-key="$dsm_name" --key-flags="C,S,EtEr" --cipher-suite="rsa2k" --dsm-exportable --custom-metadata testkey1=testvalue1 --custom-metadata testkey1=testvalue2)>/dev/null 2>&1; then
    echo "Error: The command was expected to fail but succeeded!"
fi

# 2. Fetch custom metadata from the created key
response_metadata=$(curl -s -X POST "$FORTANIX_API_ENDPOINT/crypto/v1/keys/info" \
     -H "Content-Type: application/json" \
     -H "Authorization: Basic $FORTANIX_API_KEY" \
     -d "{ \"name\": \"$dsm_name\" }" | jq -c '.custom_metadata.user_metadata')

for key in "testkey1" "testkey2"; do
    if ! echo "$response_metadata" | jq -e --arg key "$key" 'fromjson | has($key)' >/dev/null; then
        echo "Error: Missing '$key' in the custom metadata!"
        exit 1
    fi
done

# Test custom-metadata in dsm-import
# 1. Import a dummy key from sq-dsm with some dummy custom metadata
key_name="knownkey-$random"
$sq key dsm-import --dsm-key="$key_name" --custom-metadata testkey1=testvalue1 --custom-metadata testkey2=testvalue2 < "$SCRIPT_DIR/../data/knownkeys/rsa3k.pgp"

# Edge cases
# should not allow sq_dsm as key
if ($sq key dsm-import --dsm-key="$key_name" --custom-metadata sq_dsm=testvalue1 --custom-metadata testkey2=testvalue2 < "$SCRIPT_DIR/../data/knownkeys/rsa3k.pgp")>/dev/null 2>&1; then
    echo "Error: The command was expected to fail but succeeded.!"
fi

# Duplicate keys in given custom metadata, should fail
if ($sq key dsm-import --dsm-key="$key_name" --custom-metadata testkey1=testvalue1 --custom-metadata testkey1=testvalue2 < "$SCRIPT_DIR/../data/knownkeys/rsa3k.pgp")>/dev/null 2>&1; then
    echo "Error: The command was expected to fail but succeeded!"
fi

# 2. Fetch custom metadata from the created key
response_metadata=$(curl -s -X POST "$FORTANIX_API_ENDPOINT/crypto/v1/keys/info" \
     -H "Content-Type: application/json" \
     -H "Authorization: Basic $FORTANIX_API_KEY" \
     -d "{ \"name\": \"$key_name\" }" | jq -c '.custom_metadata.user_metadata')

for key in "testkey1" "testkey2"; do
    if ! echo "$response_metadata" | jq -e --arg key "$key" 'fromjson | has($key)' >/dev/null; then
        echo "Error: Missing '$key' in the custom metadata!"
        exit 1
    fi
done

echo "SUCCESS"