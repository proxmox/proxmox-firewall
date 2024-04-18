include /usr/share/dpkg/default.mk
include defines.mk

PACKAGE=proxmox-firewall
BUILDDIR ?= $(PACKAGE)-$(DEB_VERSION_UPSTREAM)
CARGO ?= cargo

DEB=$(PACKAGE)_$(DEB_VERSION_UPSTREAM_REVISION)_$(DEB_HOST_ARCH).deb
DBG_DEB=$(PACKAGE)-dbgsym_$(DEB_VERSION_UPSTREAM_REVISION)_$(DEB_HOST_ARCH).deb
DSC=$(PACKAGE)_$(DEB_VERSION_UPSTREAM_REVISION).dsc

DEBS = $(DEB) $(DBG_DEB)

ifeq ($(BUILD_MODE), release)
CARGO_BUILD_ARGS += --release
COMPILEDIR := target/release
else
COMPILEDIR := target/debug
endif


all: cargo-build

.PHONY: cargo-build
cargo-build:
	$(CARGO) build $(CARGO_BUILD_ARGS)

.PHONY: build
build: $(BUILDDIR)
$(BUILDDIR):
	rm -rf $@ $@.tmp; mkdir $@.tmp
	cp -a proxmox-firewall proxmox-nftables proxmox-ve-config debian Cargo.toml Makefile defines.mk $@.tmp/
	mv $@.tmp $@

.PHONY: deb
deb: $(DEB)
$(DBG_DEB): $(DEB)
$(DEB): $(BUILDDIR)
	cd $(BUILDDIR); dpkg-buildpackage -b -us -uc
	lintian $(DEB)

.PHONY: test
test:
	$(CARGO) test

.PHONY: dsc
dsc:
	rm -rf $(BUILDDIR) $(DSC)
	$(MAKE) $(DSC)
	lintian $(DSC)
$(DSC): $(BUILDDIR)
	cd $(BUILDDIR); dpkg-buildpackage -S -us -uc -d

sbuild: $(DSC)
	sbuild $<

.PHONY: dinstall
dinstall: $(DEB)
	dpkg -i $(DEB)

.PHONY: distclean
distclean: clean

.PHONY: clean
clean:
	$(CARGO) clean
	rm -f *.deb *.build *.buildinfo *.changes *.dsc $(PACKAGE)*.tar*
	rm -rf $(PACKAGE)-[0-9]*/
	find . -name '*~' -exec rm {} ';'
