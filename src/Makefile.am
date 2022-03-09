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
				pkcs11.exports

libpkcs11shim_la_LDFLAGS = $(AM_LDFLAGS) \
	-export-symbols "$(srcdir)/pkcs11.exports" \
	-module -shared -no-undefined \
	-version-info @LIBSHIM_CUR@:@LIBSHIM_REV@:@LIBSHIM_AGE@

if ENABLE_OPENSSL
libpkcs11shim_la_CFLAGS = $(LIBCRYPTO_CFLAGS)
libpkcs11shim_la_LIBADD = $(LIBCRYPTO_LIBS)
endif

