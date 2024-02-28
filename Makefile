include /etc/os-release

SRCDIR ?= .
COMMIT = $(shell (cd "$(SRCDIR)" && git rev-parse HEAD))

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
	@echo "    rpm:                Generate RPM."
	@echo "    man:                Generate man pages."

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

RPM_SPECFILE=rpmbuild/SPECS/fido-device-onboard-rs-$(COMMIT).spec
RPM_TARBALL=rpmbuild/SOURCES/fido-device-onboard-rs-$(COMMIT).tar.gz
VENDOR_TARBALL=rpmbuild/SOURCES/fido-device-onboard-rs-$(COMMIT)-vendor-patched.tar.xz

$(RPM_SPECFILE):
	mkdir -p $(CURDIR)/rpmbuild/SPECS
	sed -e "s/^Version:.*/Version: $(COMMIT)/;" fido-device-onboard.spec > $(RPM_SPECFILE)
	if [ "$(ID)" = "fedora" ] && [ $(VARIANT_ID) != "eln" ]; then \
		sed -i "/Source1/d ; /^# See make-vendored-tarfile.sh in upstream repo/d ;" $(RPM_SPECFILE); \
	fi

$(RPM_TARBALL):
	mkdir -p $(CURDIR)/rpmbuild/SOURCES
	cp ./patches/0001-Revert-chore-use-git-fork-for-aws-nitro-enclaves-cos.patch rpmbuild/SOURCES/;
	git archive --prefix=fido-device-onboard-rs-$(COMMIT)/ --format=tar.gz HEAD > $(RPM_TARBALL)

$(VENDOR_TARBALL):
	[ "$(ID)" = "fedora" ] && [ $(VARIANT_ID) != "eln" ] || ( \
	mkdir -p $(CURDIR)/rpmbuild/SOURCES ; \
	./make-vendored-tarfile.sh $(COMMIT) ; \
	mv fido-device-onboard-rs-$(COMMIT)-vendor-patched.tar.xz rpmbuild/SOURCES ;)

.PHONY: srpm
srpm: $(RPM_SPECFILE) $(RPM_TARBALL) $(VENDOR_TARBALL)
	rpmbuild -bs \
		--define "_topdir $(CURDIR)/rpmbuild" \
		$(RPM_SPECFILE)

.PHONY: rpm
rpm: $(RPM_SPECFILE) $(RPM_TARBALL) $(VENDOR_TARBALL)
	rpmbuild -bb \
		--define "_topdir $(CURDIR)/rpmbuild" \
		$(RPM_SPECFILE)

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
