/*
 * (c) 2016 Alexander Schoepe
 * (c) 2016 Joerg Mehring
 *
 * See the file "license.terms" for information on usage and redistribution
 * of this file, and for a DISCLAIMER OF ALL WARRANTIES.
 */

#include "randombytes.h"

#if defined(HAVE_DEVICE_RANDOM) || defined(HAVE_DEVICE_URANDOM)
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#ifndef _WIN32
#include <err.h>
#endif
#endif

#ifdef HAVE_SECRANDOMCOPYBYTES
#include <Security/SecRandom.h>
#endif

#ifdef HAVE_GETRANDOM
/*
 * getrandom() itself is declared in <sys/random.h> (glibc 2.25 and newer),
 * while <linux/random.h> only carries the GRND_* flags. Including just the
 * latter leaves the function implicitly declared, which is an error rather
 * than a warning as soon as the compiler defaults to C23.
 */
#ifdef HAVE_SYS_RANDOM_H
#include <sys/random.h>
#endif
#ifdef HAVE_LINUX_RANDOM_H
#include <linux/random.h>
#endif
#include <errno.h>
#endif

#ifdef HAVE_CRYPTGENRANDOM
#include <windows.h>
#include <wincrypt.h>
#pragma comment(lib, "advapi32.lib")
#endif

static int randomSource = RANDOMBYTES_SRC_DEFAULT;
#if defined(HAVE_DEVICE_RANDOM) || defined(HAVE_DEVICE_URANDOM)
static int fd = -1;
static char randomDevice[32] = RANDOMBYTES_DEV_DEFAULT;

int rb_Device(unsigned char *ptr, unsigned long long length) {
  unsigned int i = 0;
  if (fd == -1) {
    if ((fd = open(randomDevice, O_RDONLY)) == -1) {
#ifndef _WIN32
      err(1, "Error opening %s", randomDevice);
#endif
      return -1;
    }
  }
  while (length > 0) {
    i = (length > 65536)? 65536 : length;
    i = read(fd, ptr, i);
    ptr += i;
    length -= i;
  }
  return 0;
}
#endif


#ifdef HAVE_SECRANDOMCOPYBYTES
int rb_SecRandomCopyBytes (void *buffer, int length) {
  return (SecRandomCopyBytes(kSecRandomDefault, length, (uint8_t *)buffer) == 0)? 0 : -1;
}
#endif


#ifdef HAVE_GETRANDOM
int rb_GetRandom (unsigned char *ptr, unsigned long long length) {
  ssize_t i;

  while (length > 0) {
    /*
     * With GRND_RANDOM the kernel hands out at most 512 bytes per call, and
     * any call may be cut short by a signal, so one call is not enough. A
     * negative result means failure: returning success there would leave the
     * caller with an uninitialised buffer as key material.
     */
    i = getrandom(ptr, (length > 512)? 512 : (size_t)length, GRND_RANDOM);
    if (i < 0) {
      if (errno == EINTR)
	continue;
      return -1;
    }
    ptr += i;
    length -= (unsigned long long)i;
  }
  return 0;
}
#endif


#ifdef HAVE_CRYPTGENRANDOM
int rb_CryptGenRandom(unsigned char *buf, size_t size) {
  static BOOL hasCrypto;
  static HCRYPTPROV hCryptProv;

  if (hasCrypto == 0) {
    if (!CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_FULL, CRYPT_MACHINE_KEYSET|CRYPT_VERIFYCONTEXT)) {
      if (GetLastError() == NTE_BAD_KEYSET) {
        if (CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_FULL, CRYPT_NEWKEYSET|CRYPT_MACHINE_KEYSET|CRYPT_VERIFYCONTEXT)) {
          hasCrypto = 1;
        } else {
          hasCrypto = 0;
        }
      }
    } else {
      hasCrypto = 1;
    }
  }

  if (hasCrypto == 0) return -1;

  return (CryptGenRandom(hCryptProv, (DWORD)size, buf))? 0 : -1;
}
#endif

int GetRandomSource(void) {
  return randomSource;
}

int SetRandomSource(int src) {
#if defined(HAVE_DEVICE_RANDOM) || defined(HAVE_DEVICE_URANDOM)
  switch(randomSource) {
    case RANDOMBYTES_SRC_RANDOM: {
      strcpy(randomDevice, RANDOMBYTES_DEV_RANDOM);
      break;
    }
    case RANDOMBYTES_SRC_URANDOM: {
      strcpy(randomDevice, RANDOMBYTES_DEV_URANDOM);
      break;
    }
  }
  if (fd != -1) {
    close(fd);
    fd = -1;
  }
#endif
  randomSource = src;
  return 0;
}

int randombytes(unsigned char *ptr, unsigned long long length) {
  switch(randomSource) {
#if defined(HAVE_DEVICE_RANDOM) || defined(HAVE_DEVICE_URANDOM)
    case RANDOMBYTES_SRC_RANDOM:
    case RANDOMBYTES_SRC_URANDOM: {
      return rb_Device(ptr, length);
    }
#endif
#ifdef HAVE_SECRANDOMCOPYBYTES
    case RANDOMBYTES_SRC_SECRANDOMCOPYBYTES: {
      return rb_SecRandomCopyBytes(ptr, length);
    }
#endif
#ifdef HAVE_CRYPTGENRANDOM
    case RANDOMBYTES_SRC_CRYPTGENRANDOM: {
      return rb_CryptGenRandom(ptr, length);
    }
#endif
#ifdef HAVE_GETRANDOM
    case RANDOMBYTES_SRC_GETRANDOM: {
      return rb_GetRandom(ptr, length);
    }
#endif
    default: {
#ifndef _WIN32
      err(1, "Error: no random source selected");
#endif
      return -1;
    }
  }
}
