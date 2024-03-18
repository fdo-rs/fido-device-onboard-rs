#! /bin/bash

set -xe

PLATFORMS=$*

CARGO_CONFIG_FILE=".cargo/config.toml"
VENDOR_DIR=vendor

[ -n "$PLATFORMS" ] || PLATFORMS=$(echo {x86_64,aarch64,powerpc64le,s390x}-unknown-linux-gnu)

for PLATFORM in $PLATFORMS; do
  PLATFORM_ARGS+="--platform ${PLATFORM} "
done

# Clean vendor config and dir or the filterer will refuse to do the job
rm -rf "${VENDOR_DIR}" "${CARGO_CONFIG_FILE}"

# We need v0.5.7 because of RHEL rust version
cargo install --quiet cargo-vendor-filterer

# Filter the vendor files for the given platforms
cargo vendor-filterer ${PLATFORM_ARGS} "${VENDOR_DIR}"

cat > "${CARGO_CONFIG_FILE}" <<EOF
[source.crates-io]
replace-with = "vendored-sources"

[source.vendored-sources]
directory = "${VENDOR_DIR}"
EOF

# Patch the official crates so the build works.
for PATCH in patches/*; do
  git apply "${PATCH}"
done
