#!/bin/bash -e

sq=""
cipher_suite=""

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
source $SCRIPT_DIR/../dsm/common.sh

# Create a temporary directory to store generated keys
data=""
create_tmp_dir data

# Set up a trap to delete the temporary directory upon exit
trap 'erase_tmp_dir $data' EXIT

# Generate key locally with given cipher-suite
$sq key generate --userid="Bob Сергeeвич Прокoфьев <bob@openpgp.example>" --cipher-suite="$cipher_suite" --export="$data/${cipher_suite}key"
