#/bin/bash
set -x
ver=$1
path_name="fido-device-onboard-rs-$ver-vendor.tar.gz"
path="${2:-$path_name}"
echo $path
cargo vendor target/vendor
# Various vendor cleanups
pushd target/vendor
# cleanup windows files
rm -rf winapi/src/*
touch winapi/src/lib.rs
rm -rf winapi-x86_64-pc-windows-gnu/lib/*
rm -rf winapi-i686-pc-windows-gnu/lib/*
rm -rf vcpkg/test-data
popd #target/vendor
tar czf $path -C target vendor