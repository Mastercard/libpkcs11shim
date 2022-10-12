 #
 # pkcs11shim : a PKCS#11 shim library
 #
 # This work is based upon OpenSC pkcs11spy (https://github.com/OpenSC/OpenSC.git)
 #
 # Copyright (C) 2020  Mastercard
 #
 # This library is free software; you can redistribute it and/or
 # modify it under the terms of the GNU Lesser General Public
 # License as published by the Free Software Foundation; either
 # version 2.1 of the License, or (at your option) any later version.
 #
 # This library is distributed in the hope that it will be useful,
 # but WITHOUT ANY WARRANTY; without even the implied warranty of
 # MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 # Lesser General Public License for more details.
 #
 # You should have received a copy of the GNU Lesser General Public
 # License along with this library; if not, write to the Free Software
 # Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 #

AM_CPPFLAGS = -I$(top_srcdir)/include -I$(top_srcdir)/include/cryptoki/published/3-00-errata-1

MAINTAINERCLEANFILES = Makefile.in

lib_LTLIBRARIES = libpkcs11shim.la

libpkcs11shim_la_SOURCES = 	pkcs11-shim.c \
				pkcs11-display.c pkcs11-display.h \
				libpkcs11.c libpkcs11.h \
				libscdl.c libscdl.h \
				deferred-printf.c deferred-printf.h \
				threadqueue.c threadqueue.h \
				shim-config.c shim-config.h \
				atfork.c atfork.h \
				pkcs11.exports

libpkcs11shim_la_LDFLAGS = $(AM_LDFLAGS) \
	-export-symbols "$(srcdir)/pkcs11.exports" \
	-module -shared -no-undefined \
	-version-info @LIBSHIM_CUR@:@LIBSHIM_REV@:@LIBSHIM_AGE@

if ENABLE_OPENSSL
libpkcs11shim_la_CFLAGS = $(LIBCRYPTO_CFLAGS)
libpkcs11shim_la_LIBADD = $(LIBCRYPTO_LIBS)
endif

