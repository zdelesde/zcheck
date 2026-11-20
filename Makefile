# zcheck: test, install, and build a .deb without debhelper.

PYTHON     ?= python3
PREFIX     ?= /usr
SBINDIR    := $(PREFIX)/sbin
LIBDIR     := $(PREFIX)/lib/zcheck
DOCDIR     := $(PREFIX)/share/doc/zcheck
DATADIR    := $(PREFIX)/share/zcheck
DESTDIR    ?=
MAINTAINER ?= Zac D <zdelesde@gmail.com>

VERSION := $(shell sed -n 's/^__version__ = "\(.*\)"/\1/p' lib/zcheck/__init__.py)
BUILD   := build
PKGROOT := $(BUILD)/pkgroot
DEB     := $(BUILD)/zcheck_$(VERSION)_all.deb
MODULES := $(wildcard lib/zcheck/*.py)

export PYTHONDONTWRITEBYTECODE := 1

.PHONY: all test install deb clean

all: test

test:
	$(PYTHON) -m unittest discover -s tests

install:
	install -d -m 755 $(DESTDIR)$(SBINDIR) $(DESTDIR)$(LIBDIR)/zcheck $(DESTDIR)$(DOCDIR) $(DESTDIR)$(DATADIR)
	sed 's|@LIBDIR@|$(LIBDIR)|' bin/zcheck > $(DESTDIR)$(SBINDIR)/zcheck
	chmod 755 $(DESTDIR)$(SBINDIR)/zcheck
	install -m 644 $(MODULES) $(DESTDIR)$(LIBDIR)/zcheck/
	install -m 644 README.md $(DESTDIR)$(DOCDIR)/
	install -m 644 examples/zcheck.conf $(DESTDIR)$(DATADIR)/zcheck.conf.example

deb: $(DEB)

$(DEB): test $(MODULES) bin/zcheck examples/zcheck.conf README.md packaging/control.in Makefile
	rm -rf $(PKGROOT)
	$(MAKE) --no-print-directory install DESTDIR=$(CURDIR)/$(PKGROOT) PREFIX=/usr
	install -d -m 755 $(PKGROOT)/DEBIAN
	sed -e 's|@VERSION@|$(VERSION)|' \
	    -e 's|@MAINTAINER@|$(MAINTAINER)|' \
	    -e "s|@INSTALLED_SIZE@|$$(du -sk --exclude=DEBIAN $(PKGROOT) | cut -f1)|" \
	    packaging/control.in > $(PKGROOT)/DEBIAN/control
	cd $(PKGROOT) && find . -type f ! -path './DEBIAN/*' -printf '%P\0' \
	    | LC_ALL=C sort -z | xargs -0 md5sum > DEBIAN/md5sums
	chmod 644 $(PKGROOT)/DEBIAN/control $(PKGROOT)/DEBIAN/md5sums
	dpkg-deb --root-owner-group --build $(PKGROOT) $@
	@echo "built $@"

clean:
	rm -rf $(BUILD)
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
