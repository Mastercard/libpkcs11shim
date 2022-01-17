#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.


#
# Note: autoconf-archive must be present
#

AC_PREREQ([2.71])
AC_INIT([libp11shim],[1.2.0],[eric.devolder@mastercard.com])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_SRCDIR([src/pkcs11-display.c])
AC_CONFIG_HEADERS([include/config.h])

AC_CANONICAL_BUILD
AC_CANONICAL_HOST
AC_CANONICAL_TARGET

# automake & libtool
AM_INIT_AUTOMAKE([-Wall -Werror foreign subdir-objects tar-pax])

# Checks for programs.
AC_PROG_CC

# Check if C (gnu11) flavour is supported
# this is needed for atomics, and for localtime_r() (which is not present on std=c11)
AX_CHECK_COMPILE_FLAG([-std=gnu11],
  [ CFLAGS+=" -std=gnu11"],
  [ AC_MSG_ERROR([gnu11 flavour of C language not supported.]) ])

AX_PTHREAD
AM_PROG_AR

# Libtool
LT_INIT			dnl libtool init


# Checks for libraries.

PKG_PROG_PKG_CONFIG
# RedHat-derived distros have libcrypto11, Debian-derived & FreeBSD have libcrypto instead
PKG_CHECK_MODULES([LIBCRYPTO],
		  [libcrypto11 >= 1.1.1],
		  [],
		  [ AC_MSG_WARN([libcrypto11 not found with pkg-config, trying with libcrypto])
		    PKG_CHECK_MODULES([LIBCRYPTO],
				      [libcrypto >= 1.1.1])] )


# Checks for header files.
AC_CHECK_HEADERS([inttypes.h limits.h stddef.h stdlib.h string.h sys/time.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_SIZE_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_CHECK_FUNCS([gettimeofday memset])

AC_CONFIG_FILES([Makefile
                 src/Makefile])
AC_OUTPUT
