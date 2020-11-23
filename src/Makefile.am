AM_CPPFLAGS = -I$(top_srcdir)

lib_LTLIBRARIES = libpkcs11spy.la

libpkcs11spy_la_SOURCES = 	pkcs11-spy.c \
				pkcs11-display.c pkcs11-display.h \
				libpkcs11.c libpkcs11.h \
				libscdl.c libscdl.h \
				pkcs11.exports

libpkcs11spy_la_CFLAGS = $(OPTIONAL_OPENSSL_CFLAGS)
libpkcs11spy_la_LIBADD = $(OPTIONAL_OPENSSL_LIBS)
libpkcs11spy_la_LDFLAGS = $(AM_LDFLAGS) \
	-export-symbols "$(srcdir)/pkcs11.exports" \
	-module -shared -avoid-version -no-undefined

