#! /bin/bash

set -x
VER=${1:-$(git rev-parse HEAD)}
shift
PLATFORMS=$*

[ -n "$PLATFORMS" ] || PLATFORMS=$(echo {x86_64,aarch64,powerpc64le,s390x}-unknown-linux-gnu)

for PLATFORM in $PLATFORMS; do
  ARGS+="--platform ${PLATFORM} "
done

# Clean vendor dir or the filterer will refuse to do the job
rm -rf vendor

# We need v0.5.7 because of RHEL rust version
cargo install --quiet cargo-vendor-filterer@0.5.7

# Use the official crate version
git apply patches/0001-Revert-chore-use-git-fork-for-aws-nitro-enclaves-cos.patch
# Filter the vendor files for the given platforms
cargo vendor-filterer ${ARGS}
# Reapply the crate patch so cargo build keeps working
git apply -R patches/0001-Revert-chore-use-git-fork-for-aws-nitro-enclaves-cos.patch

# Patch the official crate so the build works.
git apply patches/0002-fix-aws-nitro-enclaves-cose.patch
tar cJf "fido-device-onboard-rs-${VER}-vendor-patched.tar.xz" vendor/
# Remove previous patch and leave the official crate as it was.
git apply -R patches/0002-fix-aws-nitro-enclaves-cose.patch
