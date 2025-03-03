include /etc/os-release

PLATFORMS = $(shell (echo {x86_64,aarch64,powerpc64le,s390x}-unknown-linux-gnu))

SRCDIR ?= .
VENDOR ?= false
VERSION = $(shell (cd "$(SRCDIR)" &&  git describe --tags | sed -e 's/^v//' -e 's/-/_/g'))

#
# Generic Targets
#
# The following is a set of generic targets used across the makefile. The
# following targets are defined:
#
#     help
#         This target prints all supported targets. It is meant as
#         documentation of targets we support and might use outside of this
#         repository.
#         This is also the default target.

.PHONY: help
help:
	@echo "make [TARGETS...]"
	@echo
	@echo "This is the maintenance makefile of fido-device-onboard-rs."
	@echo "The following targets are available:"
	@echo
	@echo "    help:               Print this usage information."
	@echo "    source-tarball:     Generate source tar file in the current directory."
	@echo "    vendor-tarball:     Generate vendor tar file in the current directory."
	@echo "    vendor:             Vendor dependencies and configure cargo build accordingly."
	@echo "    rpm:                Generate RPM."
	@echo "    srpm:               Generate SRPM."
	@echo "    test:               Run the tests."
	@echo "    man:                Generate man pages."

#
# Generating sources and vendor tar files
#

SOURCE_TARBALL=fido-device-onboard-rs-$(VERSION).tar.gz

$(SOURCE_TARBALL):
	git archive --prefix=fido-device-onboard-rs-$(VERSION)/ --format=tar.gz HEAD > $(SOURCE_TARBALL)

.PHONY: source-tarball
source-tarball: $(SOURCE_TARBALL)

VENDOR_TARBALL=fido-device-onboard-rs-$(VERSION)-vendor-patched.tar.xz

$(VENDOR_TARBALL): vendor
	tar cJf $(VENDOR_TARBALL) vendor; \
	rm -rf .cargo vendor; \
	git restore Cargo.lock;

.PHONY: vendor-tarball
vendor-tarball: $(VENDOR_TARBALL)

.PHONY: vendor
vendor:
	vendor_filterer_cmd=$$(command -v cargo-vendor-filterer||:) \
	[ -z "$$vendor_filterer_cmd" ] || rm -f $${vendor_filterer_cmd}; \
	cargo install --quiet cargo-vendor-filterer@0.5.16; \
	for platform in $(PLATFORMS); do  \
		args+="--platform $${platform} "; \
	done; \
	# https://issues.redhat.com/browse/RHEL-65521 \
	args+="--exclude-crate-path idna#tests "; \
	rm -rf vendor; \
	mkdir -p .cargo; \
	cargo vendor-filterer $${args} > ./.cargo/config.toml; \
#
# Building packages
#
# The following rules build FDO packages from the current HEAD commit,
# based on the spec file in this directory. The resulting packages have the
# commit hash in their version, so that they don't get overwritten when calling
# `make rpm` again after switching to another branch.
#
# All resulting files (spec files, source rpms, rpms) are written into
# ./rpmbuild, using rpmbuild's usual directory structure.
#

SPEC_FILE=./fido-device-onboard.spec
PATCHES_DIR=./patches
PATCH_FILE_NAME=0001-use-released-aws-nitro-enclaves-cose-version.patch
PATCH_FILE=$(PATCHES_DIR)/$(PATCH_FILE_NAME)
RPM_TOP_DIR=$(CURDIR)/rpmbuild
RPMS_SPECS_DIR=$(RPM_TOP_DIR)/SPECS
RPMS_SOURCES_DIR=$(RPM_TOP_DIR)/SOURCES
RPM_SPECFILE=$(RPMS_SPECS_DIR)/fido-device-onboard-rs-$(VERSION).spec
RPM_TARBALL=$(RPMS_SOURCES_DIR)/fido-device-onboard-rs-$(VERSION).tar.gz
RPM_VENDOR_TARBALL=${RPMS_SOURCES_DIR}/$(VENDOR_TARBALL)
RPM_PATCH_FILE=$(RPMS_SOURCES_DIR)/$(PATCH_FILE_NAME)

$(RPM_SPECFILE):
	mkdir -p $(RPMS_SPECS_DIR)
	sed -e "s/^Version:.*/Version:        $(VERSION)/;" \
	    -e "s|%{url}/archive/v%{version}/||;" \
	    $(SPEC_FILE) > $(RPM_SPECFILE)
	if [ "$(ID)" = "fedora" ] && [ $(VARIANT_ID) != "eln" ]; then \
		sed -i "/Source1/d ;" $(RPM_SPECFILE); \
	fi

$(RPM_TARBALL): $(SOURCE_TARBALL) $(VENDOR_TARBALL)
	mkdir -p $(RPMS_SOURCES_DIR)
	mv $(SOURCE_TARBALL) $(RPM_TARBALL)
	mv $(VENDOR_TARBALL) $(RPM_VENDOR_TARBALL);

$(RPM_PATCH_FILE):
	cp $(PATCH_FILE) $(RPM_PATCH_FILE);

.PHONY: srpm
srpm: $(RPM_SPECFILE) $(RPM_TARBALL) $(RPM_PATCH_FILE)
	rpmbuild -bs \
		--define "_topdir $(RPM_TOP_DIR)" \
		$(RPM_SPECFILE)

.PHONY: rpm
rpm: $(RPM_SPECFILE) $(RPM_TARBALL) $(RPM_PATCH_FILE)
	sudo dnf builddep -y $(RPM_SPECFILE)
	rpmbuild -bb \
		--define "_topdir $(RPM_TOP_DIR)" \
		$(RPM_SPECFILE)

#
# Packit target
#

.PHONY: packit-create-archive
packit-create-archive: $(SOURCE_TARBALL) $(VENDOR_TARBALL)
	cp $(PATCH_FILE) .
	ls -1 $(SOURCE_TARBALL)

#
# Generating man pages
#

RST_DIR = docs-rpms
RST_MAN_DIR=$(SRCDIR)/$(RST_DIR)
RST_FILES=$(shell find $(RST_MAN_DIR) -name '*.rst')
MAN_FILES=$(addprefix ,$(RST_FILES:%.rst=%.1))

.PHONY: man
man: $(MAN_FILES)

$(RST_DIR)/%.1: $(RST_DIR)/%.rst
	rst2man $< > $@

#
# Run tests
#
SQLITE_MANUFACTURER_DATABASE_URL=/tmp/ci-manufacturer-db.sqlite
SQLITE_MANUFACTURER_MIGRATIONS_FILE=./migrations/migrations_manufacturing_server_sqlite
SQLITE_OWNER_DATABASE_URL=/tmp/ci-owner-db.sqlite
SQLITE_OWNER_MIGRATIONS_FILE=./migrations/migrations_owner_onboarding_server_sqlite
SQLITE_RENDEZVOUS_DATABASE_URL=/tmp/ci-rendezvous-db.sqlite
SQLITE_RENDEZVOUS_MIGRATIONS_FILE=./migrations/migrations_rendezvous_server_sqlite

diesel_cmd:
	[ -n "$$(command -v diesel)" ] || cargo install --force diesel_cli --no-default-features --features sqlite;

$(SQLITE_MANUFACTURER_DATABASE_URL): diesel_cmd
	diesel migration run --migration-dir $(SQLITE_MANUFACTURER_MIGRATIONS_FILE) \
	                     --database-url $(SQLITE_MANUFACTURER_DATABASE_URL)

$(SQLITE_OWNER_DATABASE_URL): diesel_cmd
	diesel migration run --migration-dir $(SQLITE_OWNER_MIGRATIONS_FILE) \
	                     --database-url $(SQLITE_OWNER_DATABASE_URL)

$(SQLITE_RENDEZVOUS_DATABASE_URL): diesel_cmd
	diesel migration run --migration-dir $(SQLITE_RENDEZVOUS_MIGRATIONS_FILE) \
	                     --database-url $(SQLITE_RENDEZVOUS_DATABASE_URL)

.PHONY: test
test: $(SQLITE_MANUFACTURER_DATABASE_URL) $(SQLITE_OWNER_DATABASE_URL) $(SQLITE_RENDEZVOUS_DATABASE_URL)
	SQLITE_MANUFACTURER_DATABASE_URL=$(SQLITE_MANUFACTURER_DATABASE_URL) \
	SQLITE_OWNER_DATABASE_URL=$(SQLITE_OWNER_DATABASE_URL) \
	SQLITE_RENDEZVOUS_DATABASE_URL=$(SQLITE_RENDEZVOUS_DATABASE_URL) \
	cargo test --workspace; \
	rm -f $(SQLITE_MANUFACTURER_DATABASE_URL) \
	      $(SQLITE_OWNER_DATABASE_URL) \
				$(SQLITE_RENDEZVOUS_DATABASE_URL);
