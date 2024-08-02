#!/bin/bash -e

sq=""

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
source $SCRIPT_DIR/common.sh

random=$(head /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w "10" | head -n 1)

array=( rsa2k rsa3k rsa4k rsa8k nistp256 nistp384 nistp521 cv25519 )
for alg in "${array[@]}"
do
	dsm_name="print-key-info-test-$random-$alg"
	user_id="Knownkey-Test-$alg (sq-dsm $v) <xyz@xyz.xyz>"
	$sq key generate --userid="$user_id" --dsm-key="$dsm_name" --cipher-suite="$alg" --dsm-exportable
	$sq key info --dsm-key="$dsm_name" | awk '{print}'

    key_flags=( "C,S,EtEr" "CS,EtEr" )
    for key_flag in "${key_flags[@]}"
    do
        key_flag_for_filename=${key_flag//,/_}
        dsm_name="print-key-info-test-$key_flag_for_filename-$random-$alg"
        user_id="Knownkey-Test-$alg (sq-dsm $v) <xyz@xyz.xyz>"
        $sq key generate --userid="$user_id" --dsm-key="$dsm_name" --key-flags="$key_flag" --cipher-suite="$alg" --dsm-exportable
        $sq key info --dsm-key="$dsm_name" | awk '{print}'
    done
done

ldk_cmd_long_resp=$($sq key list-dsm-keys -l | tail -2 | head -1 | awk '{print $NF}')
ldk_cmd_short_resp=$($sq key list-dsm-keys | tail -2 | head -1 | awk '{print $NF}')

if [[ ! $ldk_cmd_short_resp -eq $ldk_cmd_short_resp ]]
then
	echo "long response objects($ldk_cmd_long_resp) != short response objects($ldk_cmd_short_resp)"
	exit 1
fi
