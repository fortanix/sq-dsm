#!/bin/bash

set -e -o pipefail

if [[ -z "$@" ]]; then
    echo >&2 "You must supply a version argument!"
    exit 1
fi

PACKAGE_VERSION=$1

# sudo apt install git rustc cargo clang libclang-dev make pkg-config nettle-dev libssl-dev capnproto libsqlite3-dev cmake rpm

# copy files to debian build location
mkdir -p debian/usr/bin
mkdir -p debian/DEBIAN
install --strip -D --target-directory debian/usr/bin ../target/release/sq
mv debian/usr/bin/sq debian/usr/bin/sq-dsm

# copy files to rpm build location
mkdir -p ~/rpmbuild/{BUILD,SPECS}
install --strip -D --target-directory ~/rpmbuild/BUILD ../target/release/sq
mv ~/rpmbuild/BUILD/sq ~/rpmbuild/BUILD/sq-dsm

touch debian/control
DEPENDENCIES=`dpkg-shlibdeps -O debian/usr/bin/sq-dsm | grep -i depends | awk -F 'Depends=' '{print $2}'`
rm debian/control
RPM_DEPENDENCIES=${DEPENDENCIES//\(/}
RPM_DEPENDENCIES=${RPM_DEPENDENCIES//\)/}
sed -e "s/__DEPENDENCIES__/${DEPENDENCIES}/g" debian_control > debian/DEBIAN/control
sed -e "s/__DEPENDENCIES__/${RPM_DEPENDENCIES}/g" rpm_spec > ~/rpmbuild/SPECS/sq.spec

echo "Building deb package"
sed -i "s/__VERSION__/${PACKAGE_VERSION}/g" debian/DEBIAN/control
dpkg-deb --root-owner-group --build debian sq-dsm_${PACKAGE_VERSION}_amd64.deb
rm -rf debian

echo "Building rpm package"
sed -i "s/__VERSION__/${PACKAGE_VERSION}/g" ~/rpmbuild/SPECS/sq.spec
rpmbuild -bb ~/rpmbuild/SPECS/sq.spec
