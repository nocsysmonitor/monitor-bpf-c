#!/bin/bash

set -e

## put git commit hash info into debian control file
DEBPATH=${PWD}/debian
CPATH=${DEBPATH}/DEBIAN/control
git checkout -- $CPATH
GIT_COMMIT=$(git describe --dirty --always)
sed -i 's/GIT_COMMIT/'$GIT_COMMIT'/g' $CPATH

## Add commands to generate the execution files.
## ex: make all

## Add commands to copy output execution files to debian package
mkdir -p ${DEBPATH}/usr/local/bin
cp ${PWD}/build/* ${DEBPATH}/usr/local/bin

## generate output debian 
dpkg -b ${DEBPATH} acc-bpf.deb
dpkg -c acc-bpf.deb

