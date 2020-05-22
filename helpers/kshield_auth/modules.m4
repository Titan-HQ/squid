## Copyright (C) 1996-2016 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

# This file is supposed to run all the tests required to identify which
# configured modules are able to be built in this environment

# FIXME: de-duplicate $enable_auth_kshield list containing double entries.

#not specified. Inherit global
if test "x$enable_auth_kshield" = "x"; then
    enable_auth_kshield=$enable_auth
fi
#conflicts with global
if test "x$enable_auth_kshield" != "xno" -a "x$enable_auth" = "xno" ; then
    AC_MSG_ERROR([KSHIELD auth requested but auth disabled])
fi
#define list of modules to build
auto_auth_kshield_modules=no
if test "x$enable_auth_kshield" = "xyes" ; then
    SQUID_LOOK_FOR_MODULES([$srcdir/helpers/kshield_auth],[enable_auth_kshield])
  auto_auth_kshield_modules=yes
fi
#handle the "none" special case
if test "x$enable_auth_kshield" = "xnone" ; then
    enable_auth_kshield=""
fi

KSHIELD_AUTH_HELPERS=""
#enable_auth_kshield contains either "no" or the list of modules to be built
enable_auth_kshield="`echo $enable_auth_kshield| sed -e 's/,/ /g;s/  */ /g'`"
if test "x$enable_auth_kshield" != "xno" ; then
    AUTH_MODULES="$AUTH_MODULES kshield"
    AC_DEFINE([HAVE_AUTH_MODULE_KSHIELD],1,[KSHIELD auth module is built])
    for helper in $enable_auth_kshield; do
      dir="$srcdir/helpers/kshield_auth/$helper"

      # modules not yet converted to autoconf macros (or third party drop-in's)
      if test -f "$dir/config.test" && sh "$dir/config.test" "$squid_host_os"; then
        BUILD_HELPER="$helper"
      fi

      if test -d "$srcdir/helpers/kshield_auth/$helper"; then
        if test "$BUILD_HELPER" != "$helper"; then
          if test "x$auto_auth_kshield_modules" = "xyes"; then
            AC_MSG_NOTICE([KSHIELD auth helper $helper ... found but cannot be built])
          else
            AC_MSG_ERROR([KSHIELD auth helper $helper ... found but cannot be built])
          fi
        else
          KSHIELD_AUTH_HELPERS="$KSHIELD_AUTH_HELPERS $BUILD_HELPER"
        fi
      else
        AC_MSG_ERROR([KSHIELD auth helper $helper ... not found])
      fi
    done
fi
AC_MSG_NOTICE([KSHIELD auth helpers to be built: $KSHIELD_AUTH_HELPERS])
AM_CONDITIONAL(ENABLE_AUTH_KSHIELD, test "x$enable_auth_kshield" != "xno")
AC_SUBST(KSHIELD_AUTH_HELPERS)
