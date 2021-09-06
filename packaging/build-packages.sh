#!/bin/bash

set -e -o pipefail

PACKAGE_VERSION=$1

# sudo apt install git rustc cargo clang libclang-dev make pkg-config nettle-dev libssl-dev capnproto libsqlite3-dev cmake rpm

# copy files to debian build location
mkdir -p debian/usr/bin
mkdir -p debian/DEBIAN
install --strip -D --target-directory debian/usr/bin ../target/release/sq
install --strip -D --target-directory debian/usr/bin ../target/release/sqv
mv debian/usr/bin/sq debian/usr/bin/sq-sdkms
mv debian/usr/bin/sqv debian/usr/bin/sqv-sdkms

# copy files to rpm build location
mkdir -p ~/rpmbuild/{BUILD,SPECS}
install --strip -D --target-directory ~/rpmbuild/BUILD ../target/release/sq
install --strip -D --target-directory ~/rpmbuild/BUILD ../target/release/sqv
mv ~/rpmbuild/BUILD/sq ~/rpmbuild/BUILD/sq-sdkms
mv ~/rpmbuild/BUILD/sqv ~/rpmbuild/BUILD/sqv-sdkms

touch debian/control
DEPENDENCIES=`dpkg-shlibdeps -O debian/usr/bin/sq-sdkms | grep -i depends | awk -F 'Depends=' '{print $2}'`
rm debian/control
RPM_DEPENDENCIES=${DEPENDENCIES//\(/}
RPM_DEPENDENCIES=${RPM_DEPENDENCIES//\)/}
sed -e "s/__DEPENDENCIES__/${DEPENDENCIES}/g" debian_control > debian/DEBIAN/control
sed -e "s/__DEPENDENCIES__/${RPM_DEPENDENCIES}/g" rpm_spec > ~/rpmbuild/SPECS/sq.spec

echo "Building deb package"
sed -i "s/__VERSION__/${PACKAGE_VERSION}/g" debian/DEBIAN/control
dpkg-deb --root-owner-group --build debian sq-sdkms_${PACKAGE_VERSION}_amd64.deb
rm -rf debian

echo "Building rpm package"
sed -i "s/__VERSION__/${PACKAGE_VERSION}/g" ~/rpmbuild/SPECS/sq.spec
rpmbuild -bb ~/rpmbuild/SPECS/sq.spec
