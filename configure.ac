#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.


#
# Note: autoconf-archive must be present
#

AC_PREREQ([2.69])

# From https://stackoverflow.com/a/8735145/979318
#
# AX_DEFINE_SUBST(NAME, VALUE, DESCRIPTION)
# -----------------------------------------
AX_DEFUN([AC_DEFINE_SUBST], [
AC_DEFINE([$1], [$2], [$3])
AC_SUBST([$1], ['$2'])
])

define(VERSION_MAJOR,1)
define(VERSION_MINOR,5)
define(VERSION_FIX,0)

# Following http://web.mit.edu/gnu/doc/html/libtool.html#SEC36
define(ABI_CUR,0)
define(ABI_REV,5)
define(ABI_AGE,0)


AC_INIT([libp11shim],[VERSION_MAJOR.VERSION_MINOR.VERSION_FIX],[eric.devolder@mastercard.com])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_SRCDIR([src/pkcs11-display.c])

AC_CANONICAL_BUILD
AC_CANONICAL_HOST
AC_CANONICAL_TARGET

# automake & libtool
AM_INIT_AUTOMAKE([-Wall -Werror foreign subdir-objects tar-pax])
AM_SILENT_RULES([yes])

# Checks for programs.
AC_PROG_CC

# Check if C (gnu11) flavour is supported
# this is needed for atomics, and for localtime_r() (which is not present on std=c11)
AX_CHECK_COMPILE_FLAG([-std=gnu11],
  [ CFLAGS+=" -std=gnu11"],
  [ AC_MSG_ERROR([gnu11 flavour of C language not supported.]) ])

# Checks if the compiler provides stdatomic.h
AC_CHECK_HEADER([stdatomic.h],,[AC_MSG_ERROR(["stdatomic.h" not found with this compiler, needed to build this code. Consider using a more recent compiler.])])

AX_PTHREAD
AM_PROG_AR

# Libtool
LT_INIT			dnl libtool init


# Do we want OpenSSL? OpenSSL is needed for certificate-related printing
AC_ARG_ENABLE([openssl],
  [AS_HELP_STRING([--disable-openssl], [Disable OpenSSL support @<:@default:check@:>@])],
  [:],
  [enable_openssl=check])

# Checks for libraries.

PKG_PROG_PKG_CONFIG

# Check for OpenSSL support. Not strictly needed, just adds fancy printing for certificate objects
# RedHat-derived distros have libcrypto11, Debian-derived & FreeBSD have libcrypto instead
# macro based upon https://stackoverflow.com/a/11902931/979318

AS_IF([test "$enable_openssl" != no],
    [PKG_CHECK_MODULES([LIBCRYPTO],
        [libcrypto11 >= 1.1.1],
	[enable_openssl=yes],
	[ AC_MSG_WARN([libcrypto11 not found with pkg-config, trying with libcrypto])
	  PKG_CHECK_MODULES([LIBCRYPTO], 
              [libcrypto >= 1.1.1], 
	      [enable_openssl=yes],
	      [AC_MSG_WARN([Could not find a suitable OpenSSL library. Dropping dependencies, no support for printing certificate attributes.])
                enable_openssl=no] ) ] ) ] )

AM_CONDITIONAL([ENABLE_OPENSSL], [test "$enable_openssl" = "yes"])
AS_IF([test "$enable_openssl" = "yes" ],
      [AC_DEFINE([HAVE_OPENSSL],[1],[compile with OpenSSL])])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_SIZE_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_CHECK_FUNCS([gettimeofday memset])



# Perform substs
AC_SUBST(LIBSHIM_CUR,[ABI_CUR])
AC_SUBST(LIBSHIM_REV,[ABI_REV])
AC_SUBST(LIBSHIM_AGE,[ABI_AGE])

AC_CONFIG_HEADERS([include/config.h])
AC_CONFIG_FILES([Makefile src/Makefile])

AC_OUTPUT
