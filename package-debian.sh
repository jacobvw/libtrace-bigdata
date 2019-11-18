#!/bin/bash

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
debuild
