# $Id: Makefile 46 2019-11-15 22:31:43Z umaxx $
# Copyright (c) 2018-2019 Joerg Jung <mail@umaxx.net>
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

GO=go
INSTALL?=install
RM?=rm -f

PLATFORM!=uname
PLATFORM?=$(shell uname)

PREFIX_Darwin=/usr
PREFIX_Linux=/usr
PREFIX_OpenBSD=/usr/local
PREFIX?=$(PREFIX_$(PLATFORM))

LIBEXECDIR?=$(PREFIX)/libexec/smtpd
MANDIR_Darwin=$(PREFIX)/share/man
MANDIR_Linux=$(PREFIX)/share/man
MANDIR_OpenBSD=$(PREFIX)/man
MANDIR?=$(MANDIR_$(PLATFORM))

all: filter-clamav

filter-clamav: filter-clamav.go
	$(GO) build -x filter-clamav.go

clean:
	$(GO) clean
	$(RM) filter-clamav

install: filter-clamav
	$(INSTALL) -m0755 filter-clamav $(LIBEXECDIR)
	$(INSTALL) -m0444 filter-clamav.1 $(MANDIR)/man1

uninstall:
	$(RM) $(LIBEXECDIR)/filter-clamav $(MANDIR)/man1/filter-clamav.1

style:
	$(GO) fix filter-clamav.go
	$(GO) vet -v filter-clamav.go
	gofmt -d -s -w filter-clamav.go

.PHONY: all clean install uninstall style
