#!/bin/bash

set -x -e -o pipefail

apt-get update
apt-get install -y equivs devscripts dpkg-dev quilt curl apt-transport-https \
    apt-utils ssl-cert ca-certificates gnupg lsb-release debhelper git

echo "deb https://dl.bintray.com/wand/general $(lsb_release -sc) main" | tee -a /etc/apt/sources.list.d/wand.list
echo "deb https://dl.bintray.com/wand/libtrace $(lsb_release -sc) main" | tee -a /etc/apt/sources.list.d/wand.list
echo "deb https://dl.bintray.com/wand/libflowmanager $(lsb_release -sc) main" | tee -a /etc/apt/sources.list.d/wand.list
echo "deb https://dl.bintray.com/wand/libprotoident $(lsb_release -sc) main" | tee -a /etc/apt/sources.list.d/wand.list
curl --silent "https://bintray.com/user/downloadSubjectPublicKey?username=wand"\
 | apt-key add -

apt-get update
apt-get upgrade -y

rm -rf debian-package
/bin/bash bootstrap.sh
/bin/bash configure
make
make dist
mkdir debian-package
mv libtrace-bigdata-1.0.tar.gz debian-package/libtrace-bigdata_1.0.orig.tar.gz
cd debian-package
tar -xf libtrace-bigdata_1.0.orig.tar.gz
cp -r ../debian libtrace-bigdata-1.0/
cd libtrace-bigdata-1.0
debuild -us -uc
