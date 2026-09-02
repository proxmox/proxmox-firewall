include /usr/share/dpkg/default.mk

PACKAGE=proxmox-firewall-data

GITVERSION:=$(shell git rev-parse HEAD)

BUILDDIR ?= $(PACKAGE)-$(DEB_VERSION)
DSC=$(PACKAGE)_$(DEB_VERSION).dsc

PVE_DEB=$(PACKAGE)_$(DEB_VERSION_UPSTREAM_REVISION)_all.deb

DEBS=$(PVE_DEB)

all: deb
deb: $(DEBS)

.PHONY: test
test:
	prove -v tests/*.t

$(BUILDDIR):
	rm -rf $@ $@.tmp
	mkdir -p $@.tmp
	cp -a -t $@.tmp debian data generate.pl tests README.md
	echo "git clone git://git.proxmox.com/git/proxmox-firewall.git\\ngit checkout $(GITVERSION)" > $@.tmp/debian/SOURCE
	mv $@.tmp $@

$(PVE_DEB): $(BUILDDIR)
	cd $(BUILDDIR); dpkg-buildpackage -b -uc -us
	lintian $(DEBS)

dsc: $(DSC)
	$(MAKE) clean
	$(MAKE) $(DSC)
	lintian $(DSC)

$(DSC): $(BUILDDIR)
	cd $(BUILDDIR); dpkg-buildpackage -S -uc -us

sbuild: $(DSC)
	sbuild $(DSC)

.PHONY: upload
upload: UPLOAD_DIST ?= $(DEB_DISTRIBUTION)
upload: $(DEBS)
	tar cf - $(DEBS)|ssh -X repoman@repo.proxmox.com -- upload --product pve --dist $(UPLOAD_DIST)

.PHONY: distclean
distclean: clean

.PHONY: clean
clean:
	rm -rf $(BUILDDIR) $(PACKAGE)-[0-9]*/
	rm -f *.deb *.dsc *.build *.buildinfo *.changes $(PACKAGE)*.tar.*
