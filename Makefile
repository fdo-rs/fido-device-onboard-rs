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
	@echo "    rpm:                Generate RPM"

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
VENDOR_TARBALL=rpmbuild/SOURCES/fido-device-onboard-rs-$(COMMIT)-vendor.tar.gz

$(RPM_SPECFILE):
	mkdir -p $(CURDIR)/rpmbuild/SPECS
	(echo "%global gitversion $(COMMIT)"; git show HEAD:fido-device-onboard.spec) > $(RPM_SPECFILE)

$(RPM_TARBALL):
	mkdir -p $(CURDIR)/rpmbuild/SOURCES
	git archive --prefix=fido-device-onboard-rs-$(COMMIT)/ --format=tar.gz HEAD > $(RPM_TARBALL)

$(VENDOR_TARBALL):
	mkdir -p $(CURDIR)/rpmbuild/SOURCES
	cargo vendor target/vendor
	tar -czf $(VENDOR_TARBALL) -C target vendor

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