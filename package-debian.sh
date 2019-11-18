#!/bin/bash

/bin/bash bootstrap.sh
/bin/bash configure
make
make dist
mv libtrace-bigdata-1.0.tar.gz libtrace-bigdata_1.0.orig.tar.gz
tar -xf libtrace-bigdata_1.0.orig.tar.gz
cp -r debian libtrace-bigdata-1.0/
cd libtrace-bigdata-1.0
debuild
