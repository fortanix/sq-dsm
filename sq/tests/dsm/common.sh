#!/bin/bash -e

# Script options:
#
# -c CIPHERSUITE: Select ciphersuite
# -x            : Set CLI auth via the api-key flag
# -v VERBOSITY  : Select verbosity level

export sq="../target/debug/sq"

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
    if [[ "$verbosity" -eq 1 ]]; then
        head -n4 "$1"
        echo "    [TRUNCATED OUTPUT]"
    fi
    if [[ "$verbosity" -eq 2 ]]; then
        cat "$1"
    fi
}

export cipher_suite=""
export cli_auth=false # If false, api-key is passed to the CLI
export verbosity=0

while getopts :xc:v: opt; do
    case $opt in
        x) cli_auth=true ;;
        c) cipher_suite="$OPTARG";;
        v) verbosity="$OPTARG";;
        :) echo "Missing argument for option -$OPTARG"; exit 1;;
        \?) echo "Unknown option -$OPTARG"; exit 1;;
    esac
done

if [ -z "$FORTANIX_API_ENDPOINT" ]; then
    echo "FORTANIX_API_ENDPOINT unset"
    exit 1
fi
if [ -z "$FORTANIX_API_KEY" ]; then
    echo "FORTANIX_API_KEY unset"
    exit 1
fi

