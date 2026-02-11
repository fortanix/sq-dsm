#!/bin/sh

export GNUPGHOME=`mktemp -d`

for a in rsa dsa nistp256 nistp384 nistp521 brainpoolP256r1 brainpoolP384r1 brainpoolP512r1 secp256k1
do
    gpg --batch --passphrase '' --quick-generate-key $a $a sign never
    gpg --batch --passphrase '' --armor --export-secret-key $a > $a.pgp
done
