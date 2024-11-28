include /etc/os-release

SRCDIR ?= .
VENDOR ?= false
VERSION = $(shell (cd "$(SRCDIR)" &&  git describe --tags | sed -e 's/^v//' -e 's/-/./'))
PLATFORMS = $(shell (echo {x86_64,aarch64,powerpc64le,s390x}-unknown-linux-gnu))

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
	@echo "    source:             Generate source tar file in the current directory."
	@echo "    vendor:             Generate vendor tar file in the current directory."
	@echo "    rpm:                Generate RPM."
	@echo "    srpm:               Generate SRPM."
	@echo "    man:                Generate man pages."

#
# Generating sources and vendor tar files
#

SOURCE_TARBALL=fido-device-onboard-rs-$(VERSION).tar.gz

$(SOURCE_TARBALL):
	git archive --prefix=fido-device-onboard-rs-$(VERSION)/ --format=tar.gz HEAD > $(SOURCE_TARBALL)

.PHONY: source
source: $(SOURCE_TARBALL)

VENDOR_TARBALL=fido-device-onboard-rs-$(VERSION)-vendor.tar.xz

$(VENDOR_TARBALL):
	vendor_filterer_cmd=$$(command -v cargo-vendor-filterer||:)
	[ -z "$$vendor_filterer_cmd" ] || rm -f $${vendor_filterer_cmd}
	# We need v0.5.7 because of RHEL rust version
	cargo install --quiet cargo-vendor-filterer@0.5.7;
	for platform in $(PLATFORMS); do  \
		args+="--platform $${platform} "; \
	done
	# https://issues.redhat.com/browse/RHEL-65521
	args+="--exclude-crate-path idna#tests "
	rm -rf vendor
	cargo vendor-filterer $${args}
	tar cJf $(VENDOR_TARBALL) vendor
	rm -rf vendor

.PHONY: vendor
vendor: $(VENDOR_TARBALL)

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
RPM_TOP_DIR=$(CURDIR)/rpmbuild
RPMS_SPECS_DIR=$(RPM_TOP_DIR)/SPECS
RPMS_SOURCES_DIR=$(RPM_TOP_DIR)/SOURCES
RPM_SPECFILE=$(RPMS_SPECS_DIR)/fido-device-onboard-rs-$(VERSION).spec
RPM_TARBALL=$(RPMS_SOURCES_DIR)/fido-device-onboard-rs-$(VERSION).tar.gz
RPM_VENDOR_TARBALL=${RPMS_SOURCES_DIR}/$(VENDOR_TARBALL)

$(RPM_SPECFILE):
	mkdir -p $(RPMS_SPECS_DIR)
	sed -e "s/^Version:.*/Version:        $(VERSION)/;" \
	    -e "s|%{url}/archive/v%{version}/||;" \
	    $(SPEC_FILE) > $(RPM_SPECFILE)

$(RPM_TARBALL): $(SOURCE_TARBALL) $(VENDOR_TARBALL)
	mkdir -p $(RPMS_SOURCES_DIR)
	mv $(SOURCE_TARBALL) $(RPM_TARBALL)
	mv $(VENDOR_TARBALL) $(RPM_VENDOR_TARBALL);

.PHONY: srpm
srpm: $(RPM_SPECFILE) $(RPM_TARBALL)
	rpmbuild -bs \
		--define "_topdir $(RPM_TOP_DIR)" \
		$(RPM_SPECFILE)

.PHONY: rpm
rpm: $(RPM_SPECFILE) $(RPM_TARBALL)
	sudo dnf builddep -y $(RPM_SPECFILE)
	rpmbuild -bb \
		--define "_topdir $(RPM_TOP_DIR)" \
		$(RPM_SPECFILE)

#
# Packit target
#

.PHONY: packit-create-archive
packit-create-archive: $(SOURCE_TARBALL) $(VENDOR_TARBALL)

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
