#
# Include the TEA standard macro set
#

builtin(include,tclconfig/tcl.m4)

#
# Add here whatever m4 macros you want to define for your package
#

AC_DEFUN(CHECK_FOR_RANDOM_DEVICES, [
  AC_MSG_CHECKING([TEA_PLATFORM = ${TEA_PLATFORM}])
  if test "${TEA_PLATFORM}" = "unix"; then
    AC_MSG_CHECKING([for /dev/*random devices])
    devices=""

    if test -c /dev/random ; then
      AC_DEFINE(HAVE_DEVICE_RANDOM)
      devices="${devices} random"
    fi
    if test -c /dev/urandom ; then
      AC_DEFINE(HAVE_DEVICE_URANDOM)
      devices="${devices} urandom"
    fi

    if test -n "${devices}" ; then
      AC_MSG_RESULT([found:${devices}])
    else
      AC_MSG_RESULT([failed])
    fi
  fi
])


#
# Check for SecRandomCopyBytes() __OSX_AVAILABLE_STARTING __MAC_10_7
#

AC_DEFUN(CHECK_FOR_SECRANDOMCOPYBYTES, [
  if test "${TEA_PLATFORM}" = "unix"; then
    AC_CHECK_HEADERS(Security/SecRandom.h)
    AC_CHECK_FUNCS(SecRandomCopyBytes)
  fi
])

#
# Check for getrandom()
#

AC_DEFUN(CHECK_FOR_GETRANDOM, [
  if test "${TEA_PLATFORM}" = "unix"; then
    AC_CHECK_HEADERS(linux/random.h)
    AC_CHECK_FUNCS(getrandom)
  fi
])


#
# Check for CryptGenRandom()
#

AC_DEFUN(CHECK_FOR_CRYPTGENRANDOM, [
  if test "${TEA_PLATFORM}" = "windows"; then
    AC_CHECK_HEADERS(limits.h)
    AC_CHECK_HEADERS(wincrypt.h)
    AC_CHECK_FUNCS(CryptGenRandom)
    AC_DEFINE(HAVE_CRYPTGENRANDOM)
    #Advapi32.lib
  fi
])
