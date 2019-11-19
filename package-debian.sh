#!/bin/bash

set -x -e -o pipefail

apt-get update
apt-get install -y devscripts curl apt-transport-https gnupg lsb-release

echo "deb https://dl.bintray.com/wand/general $(lsb_release -sc) main" | tee -a /etc/apt/sources.list.d/wand.list
echo "deb https://dl.bintray.com/wand/libtrace $(lsb_release -sc) main" | tee -a /etc/apt/sources.list.d/wand.list
echo "deb https://dl.bintray.com/wand/libflowmanager $(lsb_release -sc) main" | tee -a /etc/apt/sources.list.d/wand.list
echo "deb https://dl.bintray.com/wand/libprotoident $(lsb_release -sc) main" | tee -a /etc/apt/sources.list.d/wand.list
curl --silent "https://bintray.com/user/downloadSubjectPublicKey?username=wand"\
 | apt-key add -

apt-get update
apt-get install -y libtrace4-dev libprotoident-dev libflowmanager-dev libyaml-dev \
    libcurl4-openssl-dev doxygen graphviz librdkafka-dev autoconf libtool

./bootstrap.sh
./configure CXXFLAGS="-std=c++11" CFLAGS="-std=c99"
make
make dist
mkdir debian-package
mv libtrace-bigdata-1.0.tar.gz debian-package/libtrace-bigdata_1.0.orig.tar.gz
cd debian-package
tar -xf libtrace-bigdata_1.0.orig.tar.gz
cp -r ../debian libtrace-bigdata-1.0/
cd libtrace-bigdata-1.0
debuild -us -uc
