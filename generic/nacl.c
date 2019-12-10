/*
    nacl - tcl package of the public domain NaCl/TweetNaCl crypto library
           (backend license BSD-3 since May 2013; see also LICENSE.nacl)
	   https://nacl.cr.yp.to & https://tweetnacl.cr.yp.to 20140427

    NaCl: Networking and Cryptography library (pronounced "salt")

    The core NaCl development team consists of Daniel J. Bernstein (University of
    Illinois at Chicago and Technische Universiteit Eindhoven), Tanja Lange (Technische
    Universiteit Eindhoven), and Peter Schwabe (Radboud Universiteit Nijmegen).

    Copyright (C) 2016-2019 Alexander Schoepe, Bochum, DE, <alx.tcl@sowaswie.de>
    All rights reserved.

    Redistribution and use in source and binary forms, with or without modification,
    are permitted provided that the following conditions are met:

    1. Redistributions of source code must retain the above copyright notice, this
       list of conditions and the following disclaimer.
    2. Redistributions in binary form must reproduce the above copyright notice,
       this list of conditions and the following disclaimer in the documentation
       and/or other materials provided with the distribution.
    3. Neither the name of the project nor the names of its contributors may be used
       to endorse or promote products derived from this software without specific
       prior written permission.

    THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
    EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
    OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT
    SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
    INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
    TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
    BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
    CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
    ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
    SUCH DAMAGE.

    TweetNaCl: a crypto library in 100 tweets

    Introduction

    TweetNaCl is the world's first auditable high-security cryptographic library.
    TweetNaCl fits into just 100 tweets while supporting all 25 of the C NaCl functions used
    by applications. TweetNaCl is a self-contained public-domain C library, so it can easily
    be integrated into applications.

    Contributors (alphabetical order)

    Daniel J. Bernstein, University of Illinois at Chicago and Technische Universiteit Eindhoven
    Bernard van Gastel, Radboud Universiteit Nijmegen
    Wesley Janssen, Radboud Universiteit Nijmegen
    Tanja Lange, Technische Universiteit Eindhoven
    Peter Schwabe, Radboud Universiteit Nijmegen
    Sjaak Smetsers, Radboud Universiteit Nijmegen

    Acknowledgments

    This work was supported by the U.S. National Science Foundation under grant 1018836.
    "Any opinions, findings, and conclusions or recommendations expressed in this material
    are those of the author(s) and do not necessarily reflect the views of the National
    Science Foundation."

    This work was supported by the Netherlands Organisation for Scientific Research (NWO)
    under grant 639.073.005 and Veni 2013 project 13114.

    Functions supported by TweetNaCl
    --------------------------------

    Simple NaCl applications need only six high-level NaCl functions: crypto_box for
    public-key authenticated encryption; crypto_box_open for verification and decryption;
    crypto_box_keypair to create a public key in the first place; and similarly for
    signatures crypto_sign, crypto_sign_open, and crypto_sign_keypair.

    A minimalist implementation of the NaCl API would provide just these six functions.
    TweetNaCl is more ambitious, supporting all 25 of the NaCl functions listed below,
    which as mentioned earlier are all of the C NaCl functions used by applications. This
    list includes all of NaCl's "default" primitives except for crypto_auth_hmacsha512256,
    which was included in NaCl only for compatibility with standards and is superseded
    by crypto_onetimeauth.

    The Ed25519 signature system has not yet been integrated into NaCl, since the Ed25519
    software has not yet been fully audited; NaCl currently provides an older signature
    system. However, NaCl has announced that it will transition to Ed25519, so TweetNaCl
    provides Ed25519.

    crypto_box = crypto_box_curve25519xsalsa20poly1305
    crypto_box_open
    crypto_box_keypair
    crypto_box_beforenm // not implemented for calling from Tcl
    crypto_box_afternm // not implemented for calling from Tcl
    crypto_box_open_aftennm // not implemented for calling from Tcl
    crypto_core_salsa20
    crypto_core_hsalsa20 // core function
    crypto_hashblocks = crypto_hashblocks_sha512
    crypto_hash = crypto_hash_sha512
    crypto_onetimeauth = crypto_onetimeauth_poly1305
    crypto_onetimeauth_verify
    crypto_scalarmult = crypto_scalarmult_curve25519
    crypto_scalarmult_base
    crypto_secretbox = crypto_secretbox_xsalsa20poly1305
    crypto_secretbox_open
    crypto_sign = crypto_sign_ed25519
    crypto_sign_open
    crypto_sign_keypair
    crypto_stream = crypto_stream_xsalsa20
    crypto_stream_xor
    crypto_stream_salsa20
    crypto_stream_salsa20_xor
    crypto_verify_16 // not implemented for calling from Tcl
    crypto_verify_32 // not implemented for calling from Tcl

    Not implemented in TweetNaCl using NaCl's reference implementation:

    crypto_hashblocks_sha256_ref
    crypto_hash_sha256_ref
    crypto_auth_hmacsha256_ref
    crypto_auth_hmacsha256_ref_verify
    crypto_auth_hmacsha512256_ref
    crypto_auth_hmacsha512256_ref_verify

    Validation and Verification
    ---------------------------

    It is essential for cryptographic libraries to compute exactly the functions that they are
    meant to compute, and for those functions to be secure. A signature-checking library is a
    security disaster if it has a bug that accepts invalid signatures, for example, or if the
    signature system that it implements is 512-bit RSA.

    The following report specifies NaCl's default mechanism for public-key authenticated
    encryption, and along the way specifies NaCl's default mechanisms for scalar multiplication
    (Curve25519), secret-key authenticated encryption, secret-key encryption (Salsa20), and
    one-time authentication (Poly1305): (PDF) Daniel J. Bernstein, "Cryptography in NaCl", 45pp.

    The same report includes a complete step-by-step example of authenticated encryption,
    independent implementations testing each step, detailed security notes, and references to
    the relevant literature.

    The NaCl compilation scripts test known outputs of each primitive for many different message
    lengths, test consistency of different functions supported by the same primitive (for example,
    crypto_stream_xor matches crypto_stream), and test memory safety in several ways.

    *** Tests are currently limited to 4096-byte messages. ***
    This is one of several reasons that callers should
      (1) split all data into packets sent through the network;
      (2) put a small global limit on packet length; and
      (3) separately encrypt and authenticate each packet.

    From: "D. J. Bernstein" <d...@cr.yp.to> To: boring-crypto@googlegroups.com
    Subject: authenticating every packet

    There's a false alarm going around about some new Google crypto code.
    This motivates a review of some principles of boring cryptography:

     Protocol designers:
       1. Split all data into packets sent through the network.
       2. Put a small global limit on the packet length (e.g., 1024 bytes).
       3. Encrypt and authenticate each packet (with, e.g., crypto_box).

     Crypto library designers:
       1. Encrypt and authenticate a packet all at once.
       2. Don't support "update" interfaces (such as HMAC_Update).
       3. Test every small packet size (up to, e.g., 16384 bytes).

    The fundamental reason for encrypting and authenticating each packet is
    to get rid of forged data as quickly as possible. For comparison, here's
    what happens if many packets are concatenated into a large file before
    authenticators are verified:

       * A single forged packet will destroy an entire file. This is massive
	 denial-of-service amplification.

       * The protocol implementor won't want to buffer arbitrary amounts of
	 data. To avoid this he'll pass along _unverified_ data to the next
	 application layer, followed eventually by some sort of failure
	 notification. This ends up drastically increasing the amount of
	 code that has to deal with forged data.

    If a crypto library supports only one-packet-at-a-time verification and
    decryption, without any update options, then the protocol implementor
    won't be able to pass unverified data along to the next layer, and there
    will be a serious incentive for the protocol designer to authenticate
    every packet.

    Authenticating and encrypting _very_ small packets, say 53 bytes, means
    considerable overhead. But state-of-the-art cryptographic primitives
    don't have serious performance problems with, e.g., 1024-byte packets.
    (Ethernet links can physically transmit 1500-byte packets; IPv6 requires
    at least 1280; I can't remember the last time I saw an IP link imposing
    a lower limit. I think forged packets can still fool current operating
    systems into setting smaller limits, but presumably that will be fixed
    eventually.)

    Apparently Google is deploying ChaCha20 as a TLS option. The Chromium
    ChaCha20 implementation doesn't correctly encrypt input messages larger
    than 256 GB---it simply repeats the first 256 GB of keystream, whereas
    the ChaCha20 definition actually allows messages up to 1099511627776 GB.
    Fortunately, TLS splits the plaintext into "packets" of at most 16384
    bytes, and this TLS option separately handles each "packet", generating
    at most 16384 bytes of keystream for each nonce, so the bug is never
    actually triggered.

    There's a gap between the SUPERCOP/NaCl tests, which go only up to 4096
    bytes, and the TLS range of plaintext sizes, up through 16384 bytes.
    Maybe SUPERCOP should extend its tests up through 16384 bytes, just in
    case some software has a bug between 4096 bytes and 16384 bytes.

    For comparison, imagine a non-boring protocol design in which the sender
    decides how many packets to send before sending an authenticator of all
    of them and switching to the next nonce. It's easy to imagine gigabytes
    of data being sent under the same nonce ("it's just a big file download;
    no need to authenticate until the end"), and then the protocol can't
    even be _implemented_ using a simple non-updating API on a 32-bit
    machine. So the protocol implementor will demand a non-boring updating
    API, and then there's no huge obstacle to a bug being triggered after
    256 GB---which would also be quite painful to comprehensively test.

    Apparently OpenSSL is refusing to take Google's ChaCha20 TLS patches
    until the patches are modified to support an updating API. Further
    discussion of this lunacy is obviously _much_ too interesting for the
    boring-crypto mailing list. :-)

    The NaCl development team has been discussing a related issue for some
    time, namely what the "AES" primitive should actually take as input.
    Right now it's a quite traditional counter mode, generating keystream
    AES(n), AES(n+1), AES(n+2), etc., but this means that the requirements
    on n are more than just "use a new n for each message"---it would be a
    problem to start the next message with n+1, for example. We've
    considered a 32-bit counter and a 96-bit nonce, which would fit nicely
    with GCM, but this raises the question of what to do (on a 64-bit
    machine) if some non-boring protocol asks for encryption of a plaintext
    larger than 64 gigabytes. What we're leaning towards is a 64-bit counter
    and a 64-bit nonce.  
*/


#define MY_TCL_INITSTUBS "8.6"
// TWEETNACL_VERSION

#ifdef _WIN32
#include <windows.h>
#ifndef DECLSPEC_EXPORT
#define DECLSPEC_EXPORT __declspec ( dllexport )
#endif
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>

#include <tcl.h>

#include "tweetnacl.h"
#include "crypto_reference.h"
#include "randombytes.h"

#ifndef FALSE
#define FALSE 0
#define TRUE (!FALSE)
#endif

/*
   nacl::randombytes names
   nacl::randombytes source ?random|urandom|secrandomcopybytes|cryptgenrandom|default?
   nacl::randombytes lengthValue
   nacl::randombytes box ?-nonce?
   nacl::randombytes scalarmult ?-scalar|-group?
   nacl::randombytes secretbox ?-nonce|-key?
   nacl::randombytes stream ?-nonce|-key?
   nacl::randombytes auth ?-key?
   nacl::randombytes onetimeauth ?-key?
*/

static int Tnacl_RandomBytes(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
  static const char *const command[] = {
    "names", "source",
    "box", "scalarmult", "secretbox", "stream", "auth", "onetimeauth",
    NULL
  };
  enum command {
    TNACL_RANDOM_NAMES, TNACL_RANDOM_SOURCE,
    TNACL_RANDOM_BOX, TNACL_RANDOM_SCALARMULT, TNACL_RANDOM_SECRETBOX, TNACL_RANDOM_STREAM, TNACL_RANDOM_AUTH, TNACL_RANDOM_ONETIMEAUTH,
    TNACL_RANDOM_LENGTH
  } cmd;

  static const char *const source[] = {
#ifdef HAVE_DEVICE_RANDOM
    "random",
#endif
#ifdef HAVE_DEVICE_URANDOM
    "urandom",
#endif
#ifdef HAVE_SECRANDOMCOPYBYTES
    "secrandomcopybytes",
#endif
#ifdef HAVE_CRYPTGENRANDOM
    "cryptgenrandom",
#endif
#ifdef HAVE_GETRANDOM
    "getrandom",
#endif
    "default",
    NULL
  };
  enum source {
#ifdef HAVE_DEVICE_RANDOM
    TNACL_RANDOM_DEV_RANDOM,
#endif
#ifdef HAVE_DEVICE_URANDOM
    TNACL_RANDOM_DEV_URANDOM,
#endif
#ifdef HAVE_SECRANDOMCOPYBYTES
    TNACL_RANDOM_SECRANDOMCOPYBYTES,
#endif
#ifdef HAVE_CRYPTGENRANDOM
    TNACL_RANDOM_CRYPTGENRANDOM,
#endif
#ifdef HAVE_GETRANDOM
    TNACL_RANDOM_GETRANDOM,
#endif
    TNACL_RANDOM_DEFAULT
  } src;


  static const char *const enon[] = {
    "-nonce", NULL
  };
  enum enon {
    TNACL_RANDOM_NONCE_ONLY
  } optn;

  static const char *const enosg[] = {
    "-scalar", "-group", NULL
  };
  enum enosg {
    TNACL_RANDOM_SCALAR, TNACL_RANDOM_GROUP
  } optsg;

  static const char *const enonk[] = {
    "-nonce", "-key", NULL
  };
  enum enonk {
    TNACL_RANDOM_NONCE, TNACL_RANDOM_KEY
  } optnk;

  static const char *const enok[] = {
    "-key", NULL
  };
  enum ennk {
    TNACL_RANDOM_KEY_ONLY
  } optk;

  if (objc < 2) {
    Tcl_WrongNumArgs(interp, 1, objv, "?command|lengthValue? ...");
    return TCL_ERROR;
  }

  int len = 0;

  if (Tcl_GetIntFromObj(interp, objv[1], &len) == TCL_OK) {
    cmd = TNACL_RANDOM_LENGTH;
  } else {
    Tcl_ResetResult(interp);
    if (Tcl_GetIndexFromObj(interp, objv[1], command, "command", 0, (int *)&cmd) != TCL_OK) {
      return TCL_ERROR;
    }
  }

  Tcl_Obj *bObjPtr = Tcl_NewByteArrayObj(NULL, 0);
  unsigned char *b;
  int rc = -1;

  switch (cmd) {
    case TNACL_RANDOM_NAMES: {
      Tcl_Obj *lObjPtr = Tcl_NewListObj(0, NULL);
      int i;
      for (i=0; ; i++) {
        if (source[i] == NULL) break;
	Tcl_ListObjAppendElement(interp, lObjPtr, Tcl_NewStringObj(source[i], -1));
      }
      Tcl_SetObjResult(interp, lObjPtr);
      return TCL_OK;
    }

    case TNACL_RANDOM_SOURCE: {
      if (objc == 2) {
	switch (GetRandomSource()) {
#ifdef HAVE_DEVICE_RANDOM
	  case RANDOMBYTES_SRC_RANDOM: {
	    Tcl_SetObjResult(interp, Tcl_NewStringObj(source[TNACL_RANDOM_DEV_RANDOM], -1));
	    break;
	  }
#endif
#ifdef HAVE_DEVICE_URANDOM
	  case RANDOMBYTES_SRC_URANDOM: {
	    Tcl_SetObjResult(interp, Tcl_NewStringObj(source[TNACL_RANDOM_DEV_URANDOM], -1));
	    break;
	  }
#endif
#ifdef HAVE_SECRANDOMCOPYBYTES
	  case RANDOMBYTES_SRC_SECRANDOMCOPYBYTES: {
	    Tcl_SetObjResult(interp, Tcl_NewStringObj(source[TNACL_RANDOM_SECRANDOMCOPYBYTES], -1));
	    break;
	  }
#endif
#ifdef HAVE_CRYPTGENRANDOM
	  case RANDOMBYTES_SRC_CRYPTGENRANDOM: {
	    Tcl_SetObjResult(interp, Tcl_NewStringObj(source[TNACL_RANDOM_CRYPTGENRANDOM], -1));
	    break;
	  }
#endif
#ifdef HAVE_GETRANDOM
	  case RANDOMBYTES_SRC_GETRANDOM: {
	    Tcl_SetObjResult(interp, Tcl_NewStringObj(source[TNACL_RANDOM_GETRANDOM], -1));
	    break;
	  }
#endif
	}
        return TCL_OK;
      }
      if (objc != 3) {
        Tcl_WrongNumArgs(interp, 1, objv, "source ?source?");
        return TCL_ERROR;
      }
      if (Tcl_GetIndexFromObj(interp, objv[2], source, "source", 0, (int *)&src) != TCL_OK) {
	return TCL_ERROR;
      }
      switch (src) {
#ifdef HAVE_DEVICE_RANDOM
        case TNACL_RANDOM_DEV_RANDOM: {
	  SetRandomSource(RANDOMBYTES_SRC_RANDOM);
	  break;
	}
#endif
#ifdef HAVE_DEVICE_URANDOM
        case TNACL_RANDOM_DEV_URANDOM: {
	  SetRandomSource(RANDOMBYTES_SRC_URANDOM);
	  break;
	}
#endif
#ifdef HAVE_SECRANDOMCOPYBYTES
        case TNACL_RANDOM_SECRANDOMCOPYBYTES: {
	  SetRandomSource(RANDOMBYTES_SRC_SECRANDOMCOPYBYTES);
	  break;
	}
#endif
#ifdef HAVE_CRYPTGENRANDOM
        case TNACL_RANDOM_CRYPTGENRANDOM: {
	  SetRandomSource(RANDOMBYTES_SRC_CRYPTGENRANDOM);
	  break;
	}
#endif
#ifdef HAVE_GETRANDOM
        case TNACL_RANDOM_GETRANDOM: {
	  SetRandomSource(RANDOMBYTES_SRC_GETRANDOM);
	  break;
	}
#endif
	case TNACL_RANDOM_DEFAULT: {
	  SetRandomSource(RANDOMBYTES_SRC_DEFAULT);
	  break;
	}
      }
      return TCL_OK;
    }

    case TNACL_RANDOM_LENGTH: {
      if (objc != 2) {
        Tcl_WrongNumArgs(interp, 1, objv, "lengthValue");
        return TCL_ERROR;
      }
      if (Tcl_GetIntFromObj(interp, objv[1], &len) != TCL_OK) {
	return TCL_ERROR;
      }
      break;
    }

    case TNACL_RANDOM_BOX: {
      if (objc < 2 || objc > 3) {
        Tcl_WrongNumArgs(interp, 1, objv, "box ?-nonce?");
        return TCL_ERROR;
      }
      if (objc > 2) {
	if (Tcl_GetIndexFromObj(interp, objv[2], enon, "-option", 0, (int *)&optn) != TCL_OK)
	  return TCL_ERROR;
      } else {
        optn = TNACL_RANDOM_NONCE_ONLY;
      }
      switch (optn) {
        case TNACL_RANDOM_NONCE_ONLY: {
	  len = crypto_box_NONCEBYTES;
	  break;
	}
      }
      break;
    }

    case TNACL_RANDOM_SCALARMULT: {
      if (objc < 2 || objc > 3) {
        Tcl_WrongNumArgs(interp, 1, objv, "scalarmult ?-scalar|-group?");
        return TCL_ERROR;
      }
      if (objc > 2) {
	if (Tcl_GetIndexFromObj(interp, objv[2], enosg, "-option", 0, (int *)&optsg) != TCL_OK)
	  return TCL_ERROR;
      } else {
        optsg = TNACL_RANDOM_SCALAR;
      }
      switch (optsg) {
        case TNACL_RANDOM_SCALAR: {
	  len = crypto_scalarmult_BYTES;
	  break;
	}
        case TNACL_RANDOM_GROUP: {
	  len = crypto_scalarmult_SCALARBYTES;
	  break;
	}
      }
      break;
    }

    case TNACL_RANDOM_SECRETBOX:
    case TNACL_RANDOM_STREAM: {
      if (objc < 2 || objc > 3) {
        Tcl_WrongNumArgs(interp, 1, objv, "secretbox ?-nonce|-key?");
        return TCL_ERROR;
      }
      if (objc > 2) {
	if (Tcl_GetIndexFromObj(interp, objv[2], enonk, "-option", 0, (int *)&optnk) != TCL_OK)
	  return TCL_ERROR;
      } else {
        optnk = TNACL_RANDOM_NONCE;
      }
      switch (optnk) {
        case TNACL_RANDOM_NONCE: {
	  len = (cmd == TNACL_RANDOM_SECRETBOX) ? crypto_secretbox_NONCEBYTES : crypto_stream_NONCEBYTES;
	  break;
	}
        case TNACL_RANDOM_KEY: {
	  len = (cmd == TNACL_RANDOM_SECRETBOX) ? crypto_secretbox_KEYBYTES : crypto_stream_KEYBYTES;
	  break;
	}
      }
      break;
    }

    case TNACL_RANDOM_AUTH:
    case TNACL_RANDOM_ONETIMEAUTH: {
      if (objc < 2 || objc > 3) {
        Tcl_WrongNumArgs(interp, 1, objv, "auth ?-key?");
        return TCL_ERROR;
      }
      if (objc > 2) {
	if (Tcl_GetIndexFromObj(interp, objv[2], enok, "-option", 0, (int *)&optk) != TCL_OK)
	  return TCL_ERROR;
      } else {
        optk = TNACL_RANDOM_KEY_ONLY;
      }
      switch (optk) {
        case TNACL_RANDOM_KEY_ONLY: {
	  len = (cmd == TNACL_RANDOM_AUTH) ? crypto_auth_KEYBYTES : crypto_onetimeauth_KEYBYTES;
	  break;
	}
      }
      break;
    }
  }

  if (len > 0) {
    b = Tcl_SetByteArrayLength(bObjPtr, len);
    rc = randombytes(b, (unsigned long long)len);
    if (rc != 0)
      Tcl_SetByteArrayLength(bObjPtr, 0);
    Tcl_SetObjResult(interp, bObjPtr);
    return TCL_OK;
  }

  return TCL_ERROR;
}


/*
 * public-key cryptography: authenticated encryption: crypto_box
 * -------------------------------------------------------------
 * 
 * C NaCl provides a crypto_box_keypair function callable as follows:
 *
 *      #include "crypto_box.h"
 *      
 *      unsigned char pk[crypto_box_PUBLICKEYBYTES];
 *      unsigned char sk[crypto_box_SECRETKEYBYTES];
 *      
 *      crypto_box_keypair(pk,sk);
 *      
 * The crypto_box_keypair function randomly generates a secret key and a corresponding public
 * key. It puts the secret key into sk[0], sk[1], ..., sk[crypto_box_SECRETKEYBYTES-1] and puts
 * the public key into pk[0], pk[1], ..., pk[crypto_box_PUBLICKEYBYTES-1]. It then returns 0.
 * 
 * C NaCl also provides a crypto_box function callable as follows:
 * 
 *      #include "crypto_box.h"
 *      
 *      const unsigned char pk[crypto_box_PUBLICKEYBYTES];
 *      const unsigned char sk[crypto_box_SECRETKEYBYTES];
 *      const unsigned char n[crypto_box_NONCEBYTES];
 *      const unsigned char m[...]; unsigned long long mlen;
 *      unsigned char c[...];
 *      
 *      crypto_box(c,m,mlen,n,pk,sk);
 *      
 * The crypto_box function encrypts and authenticates a message m[0], ..., m[mlen-1] using the
 * sender's secret key sk[0], sk[1], ..., sk[crypto_box_SECRETKEYBYTES-1], the receiver's
 * public key pk[0], pk[1], ..., pk[crypto_box_PUBLICKEYBYTES-1], and a nonce n[0], n[1], ...,
 * n[crypto_box_NONCEBYTES-1]. The crypto_box function puts the ciphertext into c[0], c[1],
 * ..., c[mlen-1]. It then returns 0.
 * 
 * WARNING: Messages in the C NaCl API are 0-padded versions of messages in the C++ NaCl API.
 * Specifically: The caller must ensure, before calling the C NaCl crypto_box function, that
 * the first crypto_box_ZEROBYTES bytes of the message m are all 0. Typical higher-level
 * applications will work with the remaining bytes of the message; note, however, that mlen
 * counts all of the bytes, including the bytes required to be 0.
 * 
 * Similarly, ciphertexts in the C NaCl API are 0-padded versions of messages in the C++
 * NaCl API. Specifically: The crypto_box function ensures that the first crypto_box_BOXZEROBYTES
 * bytes of the ciphertext c are all 0.
 * 
 * C NaCl also provides a crypto_box_open function callable as follows:
 * 
 *      #include "crypto_box.h"
 *      
 *      const unsigned char pk[crypto_box_PUBLICKEYBYTES];
 *      const unsigned char sk[crypto_box_SECRETKEYBYTES];
 *      const unsigned char n[crypto_box_NONCEBYTES];
 *      const unsigned char c[...]; unsigned long long clen;
 *      unsigned char m[...];
 *      
 *      crypto_box_open(m,c,clen,n,pk,sk);
 *      
 * The crypto_box_open function verifies and decrypts a ciphertext c[0], ..., c[clen-1] using
 * the receiver's secret key sk[0], sk[1], ..., sk[crypto_box_SECRETKEYBYTES-1], the sender's
 * public key pk[0], pk[1], ..., pk[crypto_box_PUBLICKEYBYTES-1], and a nonce n[0], ...,
 * n[crypto_box_NONCEBYTES-1]. The crypto_box_open function puts the plaintext into m[0],
 * m[1], ..., m[clen-1]. It then returns 0.
 * 
 * If the ciphertext fails verification, crypto_box_open instead returns -1, possibly after
 * modifying m[0], m[1], etc.
 * 
 * The caller must ensure, before calling the crypto_box_open function, that the first
 * crypto_box_BOXZEROBYTES bytes of the ciphertext c are all 0. The crypto_box_open function
 * ensures (in case of success) that the first crypto_box_ZEROBYTES bytes of the plaintext
 * m are all 0.
 *
 * Security model
 * 
 * The crypto_box function is designed to meet the standard notions of privacy and third-party
 * unforgeability for a public-key authenticated-encryption scheme using nonces. For formal
 * definitions see, e.g., Jee Hea An, "Authenticated encryption in the public-key setting:
 * security notions and analyses," https://eprint.iacr.org/2001/079.
 * Distinct messages between the same {sender, receiver} set are required to have distinct
 * nonces. For example, the lexicographically smaller public key can use nonce 1 for its first
 * message to the other key, nonce 3 for its second message, nonce 5 for its third message,
 * etc., while the lexicographically larger public key uses nonce 2 for its first message to
 * the other key, nonce 4 for its second message, nonce 6 for its third message, etc. Nonces
 * are long enough that randomly generated nonces have negligible risk of collision.
 * 
 * There is no harm in having the same nonce for different messages if the {sender, receiver}
 * sets are different. This is true even if the sets overlap. For example, a sender can use
 * the same nonce for two different messages if the messages are sent to two different public keys.
 * 
 * The crypto_box function is not meant to provide non-repudiation. On the contrary: the
 * crypto_box function guarantees repudiability. A receiver can freely modify a boxed message,
 * and therefore cannot convince third parties that this particular message came from the sender.
 * The sender and receiver are nevertheless protected against forgeries by other parties. In
 * the terminology of https://groups.google.com/group/sci.crypt/msg/ec5c18b23b11d82c,
 * crypto_box uses "public-key authenticators" rather than "public-key signatures."
 * 
 * Users who want public verifiability (or receiver-assisted public verifiability) should
 * instead use signatures (or signcryption). Signature support is a high priority for NaCl;
 * a signature API will be described in subsequent NaCl documentation.
 * 
 * Selected primitive
 * 
 * crypto_box is curve25519xsalsa20poly1305, a particular combination of Curve25519, Salsa20,
 * and Poly1305 specified in "Cryptography in NaCl". This function is conjectured to meet the
 * standard notions of privacy and third-party unforgeability.
 * Alternate primitives
 * 
 * NaCl supports the following public-key message-protection functions:
 *
 * crypto_box                            BYTES
 *                                       PUBLICKEY SECRETKEY  NONCE  ZERO  BOXZERO BEFORENM
 * [TO DO:] crypto_box_nistp256aes256gcm    64        32        8     32       0      32
 * crypto_box_curve25519xsalsa20poly1305    32        32       24     32      16      32
 * 
 * For example, a user can replace crypto_box etc. with crypto_box_curve25519xsalsa20poly1305 etc.
 */

 /*
  * crypto_box = crypto_box_curve25519xsalsa20poly1305
    nacl::box info
      cipher+ 16 nonce 24 public-key 32 secret-key 32
    nacl::box keypair publicKeyVariable secretKeyVariable
    nacl::box cipherVariable messageValue nonceValue publicKeyValue secretKeyValue
    nacl::box open messageVariable cipherValue nonceValue publicKeyValue secretKeyValue
  */

static int Tnacl_Box (ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
  static const char *const command[] = {
    "info", "keypair", "open", NULL
  };
  enum command {
    TNACL_BOX_INFO, TNACL_BOX_KEYPAIR, TNACL_BOX_OPEN, TNACL_BOX
  } cmd;

  if (objc < 2) {
    Tcl_WrongNumArgs(interp, 1, objv, "?command? ...");
    return TCL_ERROR;
  }

  if (Tcl_GetIndexFromObj(interp, objv[1], command, "command", 0, (int *)&cmd) != TCL_OK)
    cmd = TNACL_BOX;

  switch (cmd) {
    case TNACL_BOX_INFO: {
      if (objc != 2) {
        Tcl_WrongNumArgs(interp, 1, objv, "info");
        return TCL_ERROR;
      }
      Tcl_Obj *lObjPtr = Tcl_NewListObj(0, NULL);
      Tcl_ListObjAppendElement(interp, lObjPtr, Tcl_NewStringObj("cipher+", -1));
      Tcl_ListObjAppendElement(interp, lObjPtr, Tcl_NewIntObj(crypto_box_BOXZEROBYTES));
      Tcl_ListObjAppendElement(interp, lObjPtr, Tcl_NewStringObj("nonce", -1));
      Tcl_ListObjAppendElement(interp, lObjPtr, Tcl_NewIntObj(crypto_box_NONCEBYTES));
      Tcl_ListObjAppendElement(interp, lObjPtr, Tcl_NewStringObj("public-key", -1));
      Tcl_ListObjAppendElement(interp, lObjPtr, Tcl_NewIntObj(crypto_box_PUBLICKEYBYTES));
      Tcl_ListObjAppendElement(interp, lObjPtr, Tcl_NewStringObj("secret-key", -1));
      Tcl_ListObjAppendElement(interp, lObjPtr, Tcl_NewIntObj(crypto_box_SECRETKEYBYTES));
      Tcl_SetObjResult(interp, lObjPtr);
      return TCL_OK;
    }

    case TNACL_BOX_KEYPAIR: {
      if (objc != 4) {
        Tcl_WrongNumArgs(interp, 1, objv, "keypair publicKeyVariable secretKeyVariable");
	//                                 1       2                 3
	return TCL_ERROR;
      }

      Tcl_Obj *pkObjPtr, *skObjPtr;
      unsigned char *pk, *sk;
      int rc;

      // 2:publicKeyVariable
      pkObjPtr = Tcl_ObjGetVar2(interp, objv[2], (Tcl_Obj*) NULL, 0);
      if (pkObjPtr == NULL)
        pkObjPtr = Tcl_NewObj();
      if (Tcl_IsShared(pkObjPtr))
        pkObjPtr = Tcl_DuplicateObj(pkObjPtr);
      pk = Tcl_SetByteArrayLength(pkObjPtr, crypto_box_PUBLICKEYBYTES);

      // 3:secretKeyVariable
      skObjPtr = Tcl_ObjGetVar2(interp, objv[3], (Tcl_Obj*) NULL, 0);
      if (skObjPtr == NULL)
	skObjPtr = Tcl_NewObj();
      if (Tcl_IsShared(skObjPtr))
	skObjPtr = Tcl_DuplicateObj(skObjPtr);
      sk = Tcl_SetByteArrayLength(skObjPtr, crypto_box_SECRETKEYBYTES);

      rc = crypto_box_keypair(pk, sk);

      if (rc == 0) {
	// 2:publicKeyVariable
	if (Tcl_ObjSetVar2(interp, objv[2], NULL, pkObjPtr, TCL_LEAVE_ERR_MSG) == NULL)
	  return TCL_ERROR;
	// 3:secretKeyVariable
	if (Tcl_ObjSetVar2(interp, objv[3], NULL, skObjPtr, TCL_LEAVE_ERR_MSG) == NULL)
	  return TCL_ERROR;
      }

      Tcl_SetObjResult(interp, Tcl_NewIntObj(rc));
      return TCL_OK;
    }

    case TNACL_BOX: {
      if (objc != 6) {
	Tcl_WrongNumArgs(interp, 1, objv, "cipherVariable messageValue nonceValue publicKeyValue secretKeyValue");
	//                                 1              2            3          4              5
	return TCL_ERROR;
      }

      Tcl_Obj *cObjPtr;
      unsigned char *c, *m, *n, *pk, *sk, *cBuf, *mBuf;
      int rc, mLen, nLen, pkLen, skLen, bufLen, outLen;

      // 1:cipherVariable
      cObjPtr = Tcl_ObjGetVar2(interp, objv[1], (Tcl_Obj*) NULL, 0);

      // 2:messageValue
      m = Tcl_GetByteArrayFromObj(objv[2], &mLen);

      // 3:nonceValue
      n = Tcl_GetByteArrayFromObj(objv[3], &nLen);
      if (nLen != crypto_box_NONCEBYTES) {
	Tcl_SetObjResult(interp, Tcl_ObjPrintf("wrong # nonce length %d bytes required", crypto_box_NONCEBYTES));
	return TCL_ERROR;
      }

      // 4:publicKeyValue
      pk = Tcl_GetByteArrayFromObj(objv[4], &pkLen);
      if (pkLen != crypto_box_PUBLICKEYBYTES) {
	Tcl_SetObjResult(interp, Tcl_ObjPrintf("wrong # public key length %d bytes required", crypto_box_PUBLICKEYBYTES));
	return TCL_ERROR;
      }

      // 5:secretKeyValue
      sk = Tcl_GetByteArrayFromObj(objv[5], &skLen);
      if (skLen != crypto_box_SECRETKEYBYTES) {
	Tcl_SetObjResult(interp, Tcl_ObjPrintf("wrong # secret key length %d bytes required", crypto_box_SECRETKEYBYTES));
	return TCL_ERROR;
      }

      bufLen = mLen + crypto_box_ZEROBYTES;
      outLen = bufLen - crypto_box_BOXZEROBYTES;
      mBuf = (unsigned char *)Tcl_Alloc(bufLen);
      memset(mBuf, 0, (size_t)crypto_box_ZEROBYTES);
      memcpy(mBuf + crypto_box_ZEROBYTES, m, mLen);

      cBuf = (unsigned char *)Tcl_Alloc(bufLen);

      rc = crypto_box(cBuf, mBuf, bufLen, n, pk, sk);

      if (rc == 0) {
	if (cObjPtr == NULL)
	  cObjPtr = Tcl_NewObj();
	if (Tcl_IsShared(cObjPtr))
	  cObjPtr = Tcl_DuplicateObj(cObjPtr);
	c = Tcl_SetByteArrayLength(cObjPtr, outLen);
	memcpy(c, cBuf + crypto_box_BOXZEROBYTES, outLen);
      }

      Tcl_Free((char *)mBuf);
      Tcl_Free((char *)cBuf);

      if (rc == 0) {
	// 1:cipherVariable
	if (Tcl_ObjSetVar2(interp, objv[1], NULL, cObjPtr, TCL_LEAVE_ERR_MSG) == NULL)
	  return TCL_ERROR;
      }

      Tcl_SetObjResult(interp, Tcl_NewIntObj(rc));
      return TCL_OK;
    }

    case TNACL_BOX_OPEN: {
      if (objc != 7) {
	Tcl_WrongNumArgs(interp, 1, objv, "open messageVariable cipherValue nonceValue publicKeyValue secretKeyValue");
	//                                 1    2               3           4          5              6
	return TCL_ERROR;
      }
      Tcl_Obj *cObjPtr;
      unsigned char *c, *m, *n, *pk, *sk, *cBuf, *mBuf;
      int rc, cLen, nLen, pkLen, skLen, bufLen, outLen;

      // 2:messageVariable
      cObjPtr = Tcl_ObjGetVar2(interp, objv[2], (Tcl_Obj*) NULL, 0);

      // 3:encrypedValue
      c = Tcl_GetByteArrayFromObj(objv[3], &cLen);

      // 4:nonceValue
      n = Tcl_GetByteArrayFromObj(objv[4], &nLen);
      if (nLen != crypto_box_NONCEBYTES) {
	Tcl_SetObjResult(interp, Tcl_ObjPrintf("wrong # nonce length %d bytes required", crypto_box_NONCEBYTES));
	return TCL_ERROR;
      }

      // 5:publicKeyValue
      pk = Tcl_GetByteArrayFromObj(objv[5], &pkLen);
      if (pkLen != crypto_box_PUBLICKEYBYTES) {
	Tcl_SetObjResult(interp, Tcl_ObjPrintf("wrong # public key length %d bytes required", crypto_box_PUBLICKEYBYTES));
	return TCL_ERROR;
      }

      // 6:secretKeyValue
      sk = Tcl_GetByteArrayFromObj(objv[6], &skLen);
      if (skLen != crypto_box_SECRETKEYBYTES) {
	Tcl_SetObjResult(interp, Tcl_ObjPrintf("wrong # secret key length %d bytes required", crypto_box_SECRETKEYBYTES));
	return TCL_ERROR;
      }

      bufLen = cLen + crypto_box_BOXZEROBYTES;
      outLen = bufLen - crypto_box_ZEROBYTES;
      cBuf = (unsigned char *)Tcl_Alloc(bufLen);
      memset(cBuf, 0, (size_t)crypto_box_BOXZEROBYTES);
      memcpy(cBuf + crypto_box_BOXZEROBYTES, c, cLen);

      mBuf = (unsigned char *)Tcl_Alloc(bufLen);

      rc = crypto_box_open(mBuf, cBuf, bufLen, n, pk, sk);

      if (rc == 0) {
	if (cObjPtr == NULL)
	  cObjPtr = Tcl_NewObj();
	if (Tcl_IsShared(cObjPtr))
	  cObjPtr = Tcl_DuplicateObj(cObjPtr);
	m = Tcl_SetByteArrayLength(cObjPtr, outLen);
	memcpy(m, mBuf + crypto_box_ZEROBYTES, outLen);
      }

      Tcl_Free((char *)cBuf);
      memset(mBuf, 0, (size_t)bufLen);
      Tcl_Free((char *)mBuf);

      if (rc == 0) {
	// 2:messageVariable
	if (Tcl_ObjSetVar2(interp, objv[2], NULL, cObjPtr, TCL_LEAVE_ERR_MSG) == NULL)
	  return TCL_ERROR;
      }

      Tcl_SetObjResult(interp, Tcl_NewIntObj(rc));
      return TCL_OK;
    }
  }
  return TCL_OK;
}


/*
 * public-key cryptography: scalar multiplication: crypto_scalarmult
 * -----------------------------------------------------------------
 * C NaCl provides a crypto_scalarmult function callable as follows:
 * 
 *      #include "crypto_scalarmult.h"
 * 
 *      const unsigned char p[crypto_scalarmult_BYTES];
 *      const unsigned char n[crypto_scalarmult_SCALARBYTES];
 *      unsigned char q[crypto_scalarmult_BYTES];
 * 
 *      crypto_scalarmult(q,n,p);
 *      
 * This function multiplies a group element p[0], ..., p[crypto_scalarmult_BYTES-1] by an
 * integer n[0], ..., n[crypto_scalarmult_SCALARBYTES-1]. It puts the resulting group element
 * into q[0], ..., q[crypto_scalarmult_BYTES-1] and returns 0.
 * 
 * C NaCl also provides a crypto_scalarmult_base function callable as follows:
 * 
 *      #include "crypto_scalarmult.h"
 * 
 *      const unsigned char n[crypto_scalarmult_SCALARBYTES];
 *      unsigned char q[crypto_scalarmult_BYTES];
 * 
 *      crypto_scalarmult_base(q,n);
 *
 * The crypto_scalarmult_base function computes the scalar product of a standard group element
 * and an integer n[0], ..., n[crypto_scalarmult_SCALARBYTES-1]. It puts the resulting group
 * element into q[0], ..., q[crypto_scalarmult_BYTES-1] and returns 0.
 * 
 * Representation of group elements
 * 
 * The correspondence between strings and group elements depends on the primitive implemented
 * by crypto_scalarmult. The correspondence is not necessarily injective in either direction,
 * but it is compatible with scalar multiplication in the group. The correspondence does not
 * necessarily include all group elements, but it does include all strings; i.e., every string
 * represents at least one group element.
 * 
 * Representation of integers
 * 
 * The correspondence between strings and integers also depends on the primitive implemented
 * by crypto_scalarmult. Every string represents at least one integer.
 * 
 * Security model
 * 
 * crypto_scalarmult is designed to be strong as a component of various well-known "hashed
 * Diffie–Hellman" applications. In particular, it is designed to make the "computational
 * Diffie–Hellman" problem (CDH) difficult with respect to the standard base.
 * crypto_scalarmult is also designed to make CDH difficult with respect to other nontrivial
 * bases. In particular, if a represented group element has small order, then it is annihilated
 * by all represented scalars. This feature allows protocols to avoid validating membership in
 * the subgroup generated by the standard base.
 * 
 * NaCl does not make any promises regarding the "decisional Diffie–Hellman" problem (DDH),
 * the "static Diffie–Hellman" problem (SDH), etc. Users are responsible for hashing group
 * elements.
 * 
 * Selected primitive
 * 
 * crypto_scalarmult is the function crypto_scalarmult_curve25519 specified in "Cryptography
 * in NaCl", Sections 2, 3, and 4. This function is conjectured to be strong. For background
 * see Bernstein, "Curve25519: new Diffie-Hellman speed records," Lecture Notes in Computer
 * Science 3958 (2006), 207–228, https://cr.yp.to/papers.html#curve25519.
 * Alternate primitives
 * 
 * NaCl supports the following scalar-multiplication functions:
 * 
 *     crypto_scalarmult                     BYTES  SCALARBYTES
 *     [TO DO:] crypto_scalarmult_nistp256     64      32
 *     crypto_scalarmult_curve25519            32      32
 * 
 * For example, a user who wants to use the Curve25519 group can replace crypto_scalarmult,
 * crypto_scalarmult_BYTES, etc. with crypto_scalarmult_curve25519,
 * crypto_scalarmult_curve25519_BYTES, etc.
 */

/*
 * crypto_scalarmult = crypto_scalarmult_curve25519
   nacl::scalarmult info
     result 32 scalar 32 group 32
   nacl::scalarmult resultVariable scalarValue groupValue
   nacl::scalarmult -base resultVariable scalarValue
   */

static int Tnacl_ScalarMult(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
  static const char *const command[] = {
    "info", "base", NULL
  };
  enum command {
    TNACL_SCALARMULT_INFO, TNACL_SCALARMULT_BASE, TNACL_SCALARMULT
  } cmd;

  if (objc < 2) {
    Tcl_WrongNumArgs(interp, 1, objv, "?command? ...");
    return TCL_ERROR;
  }

  if (Tcl_GetIndexFromObj(interp, objv[1], command, "command", 0, (int *)&cmd) != TCL_OK)
    cmd = TNACL_SCALARMULT;

  switch (cmd) {
    case TNACL_SCALARMULT_INFO: {
      if (objc != 2) {
	Tcl_WrongNumArgs(interp, 1, objv, "info");
	return TCL_ERROR;
      }
      Tcl_Obj *lObjPtr = Tcl_NewListObj(0, NULL);
      Tcl_ListObjAppendElement(interp, lObjPtr, Tcl_NewStringObj("result", -1));
      Tcl_ListObjAppendElement(interp, lObjPtr, Tcl_NewIntObj(crypto_scalarmult_BYTES));
      Tcl_ListObjAppendElement(interp, lObjPtr, Tcl_NewStringObj("scalar", -1));
      Tcl_ListObjAppendElement(interp, lObjPtr, Tcl_NewIntObj(crypto_scalarmult_SCALARBYTES));
      Tcl_ListObjAppendElement(interp, lObjPtr, Tcl_NewStringObj("group", -1));
      Tcl_ListObjAppendElement(interp, lObjPtr, Tcl_NewIntObj(crypto_scalarmult_BYTES));
      Tcl_SetObjResult(interp, lObjPtr);
      return TCL_OK;
    }

    case TNACL_SCALARMULT: {
      if (objc != 4) {
	Tcl_WrongNumArgs(interp, 1, objv, "resultVariable scalarValue groupValue");
	//                                 1              2           3
	return TCL_ERROR;
      }

      Tcl_Obj *qObjPtr;
      unsigned char *q, *n, *p;
      int rc, nLen, pLen;

      // 1:resultVariable
      qObjPtr = Tcl_ObjGetVar2(interp, objv[1], (Tcl_Obj*) NULL, 0);
      if (qObjPtr == NULL)
	qObjPtr = Tcl_NewObj();
      if (Tcl_IsShared(qObjPtr))
	qObjPtr = Tcl_DuplicateObj(qObjPtr);
      q = Tcl_SetByteArrayLength(qObjPtr, crypto_scalarmult_BYTES);

      // 2:scalarValue
      n = Tcl_GetByteArrayFromObj(objv[2], &nLen);
      if (nLen != crypto_scalarmult_SCALARBYTES) {
	Tcl_SetObjResult(interp, Tcl_ObjPrintf("wrong # scalar length %d bytes required", crypto_scalarmult_SCALARBYTES));
	return TCL_ERROR;
      }

      // 3:groupValue
      p = Tcl_GetByteArrayFromObj(objv[3], &pLen);
      if (pLen != crypto_scalarmult_BYTES) {
	Tcl_SetObjResult(interp, Tcl_ObjPrintf("wrong # group length %d bytes required", crypto_scalarmult_BYTES));
	return TCL_ERROR;
      }

      rc = crypto_scalarmult(q, n, p);

      if (rc == 0) {
	// 1:resultVariable
	if (Tcl_ObjSetVar2(interp, objv[1], NULL, qObjPtr, TCL_LEAVE_ERR_MSG) == NULL)
	  return TCL_ERROR;
      }

      Tcl_SetObjResult(interp, Tcl_NewIntObj(rc));
      return TCL_OK;
    }

    case TNACL_SCALARMULT_BASE: {
      if (objc != 4) {
	Tcl_WrongNumArgs(interp, 1, objv, "base resultVariable scalarValue");
	//                                 1    2              3
	return TCL_ERROR;
      }
      Tcl_Obj *qObjPtr;
      unsigned char *q, *n;
      int rc, nLen;

      // 2:resultVariable
      qObjPtr = Tcl_ObjGetVar2(interp, objv[2], (Tcl_Obj*) NULL, 0);
      if (qObjPtr == NULL)
	qObjPtr = Tcl_NewObj();
      if (Tcl_IsShared(qObjPtr))
	qObjPtr = Tcl_DuplicateObj(qObjPtr);
      q = Tcl_SetByteArrayLength(qObjPtr, crypto_scalarmult_BYTES);

      // 3:scalarValue
      n = Tcl_GetByteArrayFromObj(objv[3], &nLen);
      if (nLen != crypto_scalarmult_SCALARBYTES) {
	Tcl_SetObjResult(interp, Tcl_ObjPrintf("wrong # scalar length %d bytes required", crypto_scalarmult_SCALARBYTES));
	return TCL_ERROR;
      }

      rc = crypto_scalarmult_base(q, n);

      if (rc == 0) {
	// 2:messageVariable
	if (Tcl_ObjSetVar2(interp, objv[2], NULL, qObjPtr, TCL_LEAVE_ERR_MSG) == NULL)
	  return TCL_ERROR;
      }

      Tcl_SetObjResult(interp, Tcl_NewIntObj(rc));
      return TCL_OK;
    }
  }
  return TCL_OK;
}


/*
 * public-key cryptography: signatures: crypto_sign
 * ------------------------------------------------
 * C NaCl provides a crypto_sign_keypair function callable as follows:
 * 
 *      #include "crypto_sign.h"
 * 
 *      unsigned char pk[crypto_sign_PUBLICKEYBYTES];
 *      unsigned char sk[crypto_sign_SECRETKEYBYTES];
 * 
 *      crypto_sign_keypair(pk,sk);
 *      
 * The crypto_sign_keypair function randomly generates a secret key and a corresponding public
 * key. It puts the secret key into sk[0], sk[1], ..., sk[crypto_sign_SECRETKEYBYTES-1] and
 * puts the public key into pk[0], pk[1], ..., pk[crypto_sign_PUBLICKEYBYTES-1]. It then
 * returns 0.
 * 
 * C NaCl also provides a crypto_sign function callable as follows:
 * 
 *      #include "crypto_sign.h"
 * 
 *      const unsigned char sk[crypto_sign_SECRETKEYBYTES];
 *      const unsigned char m[...]; unsigned long long mlen;
 *      unsigned char sm[...]; unsigned long long smlen;
 * 
 *      crypto_sign(sm,&smlen,m,mlen,sk);
 *      
 * The crypto_sign function signs a message m[0], ..., m[mlen-1] using the signer's secret key
 * sk[0], sk[1], ..., sk[crypto_sign_SECRETKEYBYTES-1], puts the length of the signed message
 * into smlen and puts the signed message into sm[0], sm[1], ..., sm[smlen-1]. It then
 * returns 0.
 * 
 * The maximum possible length smlen is mlen+crypto_sign_BYTES. The caller must allocate at
 * least mlen+crypto_sign_BYTES bytes for sm.
 * 
 * C NaCl also provides a crypto_sign_open function callable as follows:
 * 
 *      #include "crypto_sign.h"
 * 
 *      const unsigned char pk[crypto_sign_PUBLICKEYBYTES];
 *      const unsigned char sm[...]; unsigned long long smlen;
 *      unsigned char m[...]; unsigned long long mlen;
 * 
 *      crypto_sign_open(m,&mlen,sm,smlen,pk);
 *
 * The crypto_sign_open function verifies the signature in sm[0], ..., sm[smlen-1] using the
 * signer's public key pk[0], pk[1], ..., pk[crypto_sign_PUBLICKEYBYTES-1]. The crypto_sign_open
 * function puts the length of the message into mlen and puts the message into m[0], m[1],
 * ..., m[mlen-1]. It then returns 0.
 * 
 * The maximum possible length mlen is smlen. The caller must allocate at least smlen bytes
 * for m.
 * 
 * If the signature fails verification, crypto_sign_open instead returns -1, possibly after
 * modifying m[0], m[1], etc.
 * 
 * Security model
 * 
 * The crypto_sign function is designed to meet the standard notion of unforgeability for a
 * public-key signature scheme under chosen-message attacks.
 * Selected primitive
 * 
 * crypto_sign is crypto_sign_edwards25519sha512batch, a particular combination of Curve25519
 * in Edwards form and SHA-512 into a signature scheme suitable for high-speed batch verification.
 * This function is conjectured to meet the standard notion of unforgeability under chosen-message
 * attacks.
 * 
 * Alternate primitives
 * 
 * NaCl supports the following public-key signature functions:
 * 
 *     crypto_sign                               PUBLICKEYBYTES  SECRETKEYBYTES  BYTES
 *     [TO DO:] crypto_sign_nistp256sha512ecdsa    64             64               64
 *     crypto_sign_edwards25519sha512batch         32             64               64
 * 
 * For example, a user who wants to encrypt and authenticate messages with the NIST P-256
 * curve using SHA-512 and the ECDSA algorithm can replace crypto_sign with
 * crypto_sign_nistp256sha512ecdsa.
 * 
 */

/*
 * crypto_sign = crypto_sign_ed25519
   nacl::sign info
     sign +64 nonce 24 public-key 32 secret-key 64
   nacl::sign keypair publicKeyVariable secretKeyVariable
   nacl::sign signedVariable messageValue secretKeyValue
   nacl::sign verify messageVariable signedValue publicKeyValue
 */

static int Tnacl_Sign (ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
  static const char *const command[] = {
    "info", "keypair", "verify", NULL
  };
  enum command {
    TNACL_SIGN_INFO, TNACL_SIGN_KEYPAIR, TNACL_SIGN_VERIFY, TNACL_SIGN
  } cmd;

  if (objc < 2) {
    Tcl_WrongNumArgs(interp, 1, objv, "?command? ...");
    return TCL_ERROR;
  }

  if (Tcl_GetIndexFromObj(interp, objv[1], command, "command", 0, (int *)&cmd) != TCL_OK)
    cmd = TNACL_SIGN;

  switch (cmd) {
    case TNACL_SIGN_INFO: {
      if (objc != 2) {
        Tcl_WrongNumArgs(interp, 1, objv, "info");
        return TCL_ERROR;
      }
      Tcl_Obj *lObjPtr = Tcl_NewListObj(0, NULL);
      Tcl_ListObjAppendElement(interp, lObjPtr, Tcl_NewStringObj("sign+", -1));
      Tcl_ListObjAppendElement(interp, lObjPtr, Tcl_NewIntObj(crypto_sign_BYTES));
      Tcl_ListObjAppendElement(interp, lObjPtr, Tcl_NewStringObj("public-key", -1));
      Tcl_ListObjAppendElement(interp, lObjPtr, Tcl_NewIntObj(crypto_sign_PUBLICKEYBYTES));
      Tcl_ListObjAppendElement(interp, lObjPtr, Tcl_NewStringObj("secret-key", -1));
      Tcl_ListObjAppendElement(interp, lObjPtr, Tcl_NewIntObj(crypto_sign_SECRETKEYBYTES));
      Tcl_SetObjResult(interp, lObjPtr);
      return TCL_OK;
    }

    case TNACL_SIGN_KEYPAIR: {
      if (objc != 4) {
        Tcl_WrongNumArgs(interp, 1, objv, "keypair publicKeyVariable secretKeyVariable");
	//                                 1       2                 3
	return TCL_ERROR;
      }

      Tcl_Obj *pkObjPtr, *skObjPtr;
      unsigned char *pk, *sk;
      int rc;

      // 2:publicKeyVariable
      pkObjPtr = Tcl_ObjGetVar2(interp, objv[2], (Tcl_Obj*) NULL, 0);
      if (pkObjPtr == NULL)
        pkObjPtr = Tcl_NewObj();
      if (Tcl_IsShared(pkObjPtr))
        pkObjPtr = Tcl_DuplicateObj(pkObjPtr);
      pk = Tcl_SetByteArrayLength(pkObjPtr, crypto_sign_PUBLICKEYBYTES);

      // 3:secretKeyVariable
      skObjPtr = Tcl_ObjGetVar2(interp, objv[3], (Tcl_Obj*) NULL, 0);
      if (skObjPtr == NULL)
	skObjPtr = Tcl_NewObj();
      if (Tcl_IsShared(skObjPtr))
	skObjPtr = Tcl_DuplicateObj(skObjPtr);
      sk = Tcl_SetByteArrayLength(skObjPtr, crypto_sign_SECRETKEYBYTES);

      rc = crypto_sign_keypair(pk, sk);

      if (rc == 0) {
	// 2:publicKeyVariable
	if (Tcl_ObjSetVar2(interp, objv[2], NULL, pkObjPtr, TCL_LEAVE_ERR_MSG) == NULL)
	  return TCL_ERROR;
	// 3:secretKeyVariable
	if (Tcl_ObjSetVar2(interp, objv[3], NULL, skObjPtr, TCL_LEAVE_ERR_MSG) == NULL)
	  return TCL_ERROR;
      }

      Tcl_SetObjResult(interp, Tcl_NewIntObj(rc));
      return TCL_OK;
    }

    case TNACL_SIGN: {
      if (objc != 4) {
	Tcl_WrongNumArgs(interp, 1, objv, "signedVariable messageValue secretKeyValue");
	//                                 1              2            3
	return TCL_ERROR;
      }

      Tcl_Obj *smObjPtr;
      unsigned char *sm, *m, *sk;
      int rc, smLen, mLen, skLen;

      // 1:signedVariable
      smObjPtr = Tcl_ObjGetVar2(interp, objv[1], (Tcl_Obj*) NULL, 0);
      if (smObjPtr == NULL)
	smObjPtr = Tcl_NewObj();
      if (Tcl_IsShared(smObjPtr))
	smObjPtr = Tcl_DuplicateObj(smObjPtr);

      // 2:messageValue
      m = Tcl_GetByteArrayFromObj(objv[2], &mLen);

      // 3:secretKeyValue
      sk = Tcl_GetByteArrayFromObj(objv[3], &skLen);
      if (skLen != crypto_sign_SECRETKEYBYTES) {
	Tcl_SetObjResult(interp, Tcl_ObjPrintf("wrong # secret key length %d bytes required", crypto_sign_SECRETKEYBYTES));
	return TCL_ERROR;
      }

      smLen = mLen + crypto_sign_BYTES;
      sm = Tcl_SetByteArrayLength(smObjPtr, smLen);

      rc = crypto_sign(sm, (unsigned long long *)&smLen, m, mLen, sk);

      if (rc == 0) {
	Tcl_SetByteArrayLength(smObjPtr, smLen);

	// 2:signedVariable
	if (Tcl_ObjSetVar2(interp, objv[1], NULL, smObjPtr, TCL_LEAVE_ERR_MSG) == NULL)
	  return TCL_ERROR;
      }

      Tcl_SetObjResult(interp, Tcl_NewIntObj(rc));
      return TCL_OK;
    }

    case TNACL_SIGN_VERIFY: {
      if (objc != 5 && cmd != TNACL_SIGN_KEYPAIR) {
	Tcl_WrongNumArgs(interp, 1, objv, "verify messageVariable signedValue publicKeyValue");
	//                                 1      2               3           4
	return TCL_ERROR;
      }

      Tcl_Obj *mObjPtr;
      unsigned char *sm, *m, *pk;
      int rc, smLen, mLen, pkLen;

      // 2:messageVariable
      mObjPtr = Tcl_ObjGetVar2(interp, objv[2], (Tcl_Obj*) NULL, 0);
      if (mObjPtr == NULL)
	mObjPtr = Tcl_NewObj();
      if (Tcl_IsShared(mObjPtr))
	mObjPtr = Tcl_DuplicateObj(mObjPtr);

      // 3:signedValue
      sm = Tcl_GetByteArrayFromObj(objv[3], &smLen);

      // 4:publicKeyValue
      pk = Tcl_GetByteArrayFromObj(objv[4], &pkLen);
      if (pkLen != crypto_sign_PUBLICKEYBYTES) {
	Tcl_SetObjResult(interp, Tcl_ObjPrintf("wrong # public key length %d bytes required", crypto_sign_PUBLICKEYBYTES));
	return TCL_ERROR;
      }

      mLen = smLen;
      m = Tcl_SetByteArrayLength(mObjPtr, mLen);

      rc = crypto_sign_open(m, (unsigned long long *)&mLen, sm, smLen, pk);

      if (rc == 0) {
	Tcl_SetByteArrayLength(mObjPtr, mLen);

      // 2:messageVariable
      if (Tcl_ObjSetVar2(interp, objv[2], NULL, mObjPtr, TCL_LEAVE_ERR_MSG) == NULL)
	return TCL_ERROR;
      }

      Tcl_SetObjResult(interp, Tcl_NewIntObj(rc));
      return TCL_OK;
    }
  }
  return TCL_OK;
}


/*
 * secret-key cryptography: secret-key authenticated encryption: crypto_secretbox
 * ------------------------------------------------------------------------------
 * C NaCl provides a crypto_secretbox function callable as follows:
 *
 *      #include "crypto_secretbox.h"
 * 
 *      const unsigned char k[crypto_secretbox_KEYBYTES];
 *      const unsigned char n[crypto_secretbox_NONCEBYTES];
 *      const unsigned char m[...]; unsigned long long mlen;
 *      unsigned char c[...]; unsigned long long clen;
 * 
 *      crypto_secretbox(c,m,mlen,n,k);
 *      
 * The crypto_secretbox function encrypts and authenticates a message m[0], m[1], ..., m[mlen-1]
 * using a secret key k[0], ..., k[crypto_secretbox_KEYBYTES-1] and a nonce n[0], n[1], ...,
 * n[crypto_secretbox_NONCEBYTES-1]. The crypto_secretbox function puts the ciphertext into
 * c[0], c[1], ..., c[mlen-1]. It then returns 0.
 * 
 * WARNING: Messages in the C NaCl API are 0-padded versions of messages in the C++ NaCl API.
 * Specifically: The caller must ensure, before calling the C NaCl crypto_secretbox function,
 * that the first crypto_secretbox_ZEROBYTES bytes of the message m are all 0. Typical
 * higher-level applications will work with the remaining bytes of the message; note, however,
 * that mlen counts all of the bytes, including the bytes required to be 0.
 * 
 * Similarly, ciphertexts in the C NaCl API are 0-padded versions of messages in the C++
 * NaCl API. Specifically: The crypto_secretbox function ensures that the first
 * crypto_secretbox_BOXZEROBYTES bytes of the ciphertext c are all 0.
 * 
 * C NaCl also provides a crypto_secretbox_open function callable as follows:
 * 
 *      #include "crypto_secretbox.h"
 * 
 *      const unsigned char k[crypto_secretbox_KEYBYTES];
 *      const unsigned char n[crypto_secretbox_NONCEBYTES];
 *      const unsigned char c[...]; unsigned long long clen;
 *      unsigned char m[...];
 * 
 *      crypto_secretbox_open(m,c,clen,n,k);
 *      
 * The crypto_secretbox_open function verifies and decrypts a ciphertext c[0], c[1], ...,
 * c[clen-1] using a secret key k[0], k[1], ..., k[crypto_secretbox_KEYBYTES-1] and a nonce
 * n[0], ..., n[crypto_secretbox_NONCEBYTES-1]. The crypto_secretbox_open function puts the
 * plaintext into m[0], m[1], ..., m[clen-1]. It then returns 0.
 * 
 * If the ciphertext fails verification, crypto_secretbox_open instead returns -1, possibly
 * after modifying m[0], m[1], etc.
 * 
 * The caller must ensure, before calling the crypto_secretbox_open function, that the first
 * crypto_secretbox_BOXZEROBYTES bytes of the ciphertext c are all 0. The crypto_secretbox_open
 * function ensures (in case of success) that the first crypto_secretbox_ZEROBYTES bytes of the
 * plaintext m are all 0.
 * 
 * Security model
 * 
 * The crypto_secretbox function is designed to meet the standard notions of privacy and
 * authenticity for a secret-key authenticated-encryption scheme using nonces. For formal
 * definitions see, e.g., Bellare and Namprempre, "Authenticated encryption: relations among
 * notions and analysis of the generic composition paradigm," Lecture Notes in Computer
 * Science 1976 (2000), 531–545, http://www-cse.ucsd.edu/~mihir/papers/oem.html.
 * Note that the length is not hidden. Note also that it is the caller's responsibility to
 * ensure the uniqueness of nonces—for example, by using nonce 1 for the first message, nonce
 * 2 for the second message, etc. Nonces are long enough that randomly generated nonces have
 * negligible risk of collision.
 * 
 * Selected primitive
 * 
 * crypto_secretbox is crypto_secretbox_xsalsa20poly1305, a particular combination of Salsa20
 * and Poly1305 specified in "Cryptography in NaCl". This function is conjectured to meet the
 * standard notions of privacy and authenticity.
 * 
 * Alternate primitives
 * 
 * NaCl supports the following secret-key message-protection functions:
 * 
 *     crypto_secretbox                       KEYBYTES  NONCEBYTES  ZEROBYTES  BOXZEROBYTES
 *     [TO DO:] crypto_secretbox_aes256gcm      32         8          32          0
 *     crypto_secretbox_xsalsa20poly1305        32        24          32         16
 * 
 * For example, a user who wants to encrypt and authenticate messages with AES-256-GCM can
 * replace crypto_secretbox with crypto_secretbox_aes256gcm, crypto_secretbox_KEYBYTES with
 * crypto_secretbox_aes256gcm_KEYBYTES, etc.
 * Beware that some of these primitives have 8-byte nonces. For those primitives it is no
 * longer true that randomly generated nonces have negligible risk of collision. Callers who
 * are unable to count 1,2,3,..., and who insist on using these primitives, are advised to
 * use a randomly derived key for each message.
 */

/*
 * crypto_secretbox = crypto_secretbox_xsalsa20poly1305
   nacl::secretbox info
     cipher +16 nonce 24 key 32
   nacl::secretbox cipherVariable messageValue nonceValue keyValue
   nacl::secretbox open messageVariable cipherValue nonceValue keyValue
 */

static int Tnacl_SecretBox (ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
  static const char *const command[] = {
    "info", "open", NULL
  };
  enum command {
    TNACL_SECRETBOX_INFO, TNACL_SECRETBOX_OPEN, TNACL_SECRETBOX
  } cmd;

  if (objc < 2) {
    Tcl_WrongNumArgs(interp, 1, objv, "?command? ...");
    return TCL_ERROR;
  }

  if (Tcl_GetIndexFromObj(interp, objv[1], command, "command", 0, (int *)&cmd) != TCL_OK)
    cmd = TNACL_SECRETBOX;

  switch (cmd) {
    case TNACL_SECRETBOX_INFO: {
      if (objc != 2) {
        Tcl_WrongNumArgs(interp, 1, objv, "info");
        return TCL_ERROR;
      }
      Tcl_Obj *lObjPtr = Tcl_NewListObj(0, NULL);
      Tcl_ListObjAppendElement(interp, lObjPtr, Tcl_NewStringObj("cipher+", -1));
      Tcl_ListObjAppendElement(interp, lObjPtr, Tcl_NewIntObj(crypto_secretbox_BOXZEROBYTES));
      Tcl_ListObjAppendElement(interp, lObjPtr, Tcl_NewStringObj("nonce", -1));
      Tcl_ListObjAppendElement(interp, lObjPtr, Tcl_NewIntObj(crypto_secretbox_NONCEBYTES));
      Tcl_ListObjAppendElement(interp, lObjPtr, Tcl_NewStringObj("key", -1));
      Tcl_ListObjAppendElement(interp, lObjPtr, Tcl_NewIntObj(crypto_secretbox_KEYBYTES));
      Tcl_SetObjResult(interp, lObjPtr);
      return TCL_OK;
    }

    case TNACL_SECRETBOX: {
      if (objc != 5) {
	Tcl_WrongNumArgs(interp, 1, objv, "cipherVariable messageValue nonceValue keyValue");
	//                                 1              2            3          4
	return TCL_ERROR;
      }

      Tcl_Obj *cObjPtr;
      unsigned char *c, *m, *n, *k, *cBuf, *mBuf;
      int rc, mLen, nLen, kLen, bufLen, outLen;

      // 1:cipherVariable
      cObjPtr = Tcl_ObjGetVar2(interp, objv[1], (Tcl_Obj*) NULL, 0);

      // 2:messageValue
      m = Tcl_GetByteArrayFromObj(objv[2], &mLen);

      // 3:nonceValue
      n = Tcl_GetByteArrayFromObj(objv[3], &nLen);
      if (nLen != crypto_secretbox_NONCEBYTES) {
	Tcl_SetObjResult(interp, Tcl_ObjPrintf("wrong # nonce length %d bytes required", crypto_secretbox_NONCEBYTES));
	return TCL_ERROR;
      }

      // 4:keyValue
      k = Tcl_GetByteArrayFromObj(objv[4], &kLen);
      if (kLen != crypto_secretbox_KEYBYTES) {
	Tcl_SetObjResult(interp, Tcl_ObjPrintf("wrong # key length %d bytes required", crypto_secretbox_KEYBYTES));
	return TCL_ERROR;
      }

      bufLen = mLen + crypto_secretbox_ZEROBYTES;
      outLen = bufLen - crypto_secretbox_BOXZEROBYTES;
      mBuf = (unsigned char *)Tcl_Alloc(bufLen);
      memset(mBuf, 0, (size_t)crypto_secretbox_ZEROBYTES);
      memcpy(mBuf + crypto_secretbox_ZEROBYTES, m, mLen);

      cBuf = (unsigned char *)Tcl_Alloc(bufLen);

      rc = crypto_secretbox(cBuf, mBuf, bufLen, n, k);

      if (rc == 0) {
	if (cObjPtr == NULL)
	  cObjPtr = Tcl_NewObj();
	if (Tcl_IsShared(cObjPtr))
	  cObjPtr = Tcl_DuplicateObj(cObjPtr);
	c = Tcl_SetByteArrayLength(cObjPtr, outLen);
	memcpy(c, cBuf + crypto_secretbox_BOXZEROBYTES, outLen);
      }

      Tcl_Free((char *)mBuf);
      Tcl_Free((char *)cBuf);

      if (rc == 0) {
	// 1:cipherVariable
	if (Tcl_ObjSetVar2(interp, objv[1], NULL, cObjPtr, TCL_LEAVE_ERR_MSG) == NULL)
	  return TCL_ERROR;
      }

      Tcl_SetObjResult(interp, Tcl_NewIntObj(rc));
      return TCL_OK;
    }

    case TNACL_SECRETBOX_OPEN: {
      if (objc != 6) {
	Tcl_WrongNumArgs(interp, 1, objv, "open messageVariable cipherValue nonceValue keyValue");
	//                                 1    2               3           4          5
	return TCL_ERROR;
      }
      Tcl_Obj *cObjPtr;
      unsigned char *c, *m, *n, *k, *cBuf, *mBuf;
      int rc, cLen, nLen, kLen, bufLen, outLen;

      // 2:messageVariable
      cObjPtr = Tcl_ObjGetVar2(interp, objv[2], (Tcl_Obj*) NULL, 0);

      // 3:encrypedValue
      c = Tcl_GetByteArrayFromObj(objv[3], &cLen);

      // 4:nonceValue
      n = Tcl_GetByteArrayFromObj(objv[4], &nLen);
      if (nLen != crypto_secretbox_NONCEBYTES) {
	Tcl_SetObjResult(interp, Tcl_ObjPrintf("wrong # nonce length %d bytes required", crypto_secretbox_NONCEBYTES));
	return TCL_ERROR;
      }

      // 5:keyValue
      k = Tcl_GetByteArrayFromObj(objv[5], &kLen);
      if (kLen != crypto_secretbox_KEYBYTES) {
	Tcl_SetObjResult(interp, Tcl_ObjPrintf("wrong # key length %d bytes required", crypto_secretbox_KEYBYTES));
	return TCL_ERROR;
      }

      bufLen = cLen + crypto_secretbox_BOXZEROBYTES;
      outLen = bufLen - crypto_secretbox_ZEROBYTES;
      cBuf = (unsigned char *)Tcl_Alloc(bufLen);
      memset(cBuf, 0, (size_t)crypto_secretbox_BOXZEROBYTES);
      memcpy(cBuf + crypto_secretbox_BOXZEROBYTES, c, cLen);

      mBuf = (unsigned char *)Tcl_Alloc(bufLen);

      rc = crypto_secretbox_open(mBuf, cBuf, bufLen, n, k);

      if (rc == 0) {
	if (cObjPtr == NULL)
	  cObjPtr = Tcl_NewObj();
	if (Tcl_IsShared(cObjPtr))
	  cObjPtr = Tcl_DuplicateObj(cObjPtr);
	m = Tcl_SetByteArrayLength(cObjPtr, outLen);
	memcpy(m, mBuf + crypto_secretbox_ZEROBYTES, outLen);
      }

      Tcl_Free((char *)cBuf);
      memset(mBuf, 0, (size_t)bufLen);
      Tcl_Free((char *)mBuf);

      if (rc == 0) {
	// 2:messageVariable
	if (Tcl_ObjSetVar2(interp, objv[2], NULL, cObjPtr, TCL_LEAVE_ERR_MSG) == NULL)
	  return TCL_ERROR;
      }

      Tcl_SetObjResult(interp, Tcl_NewIntObj(rc));
      return TCL_OK;
    }
  }
  return TCL_OK;
}


/*
 * secret-key cryptography: secret-key encryption: crypto_stream
 * -------------------------------------------------------------
 * 
 * C NaCl provides a crypto_stream function callable as follows:
 * 
 *      #include "crypto_stream.h"
 * 
 *      const unsigned char k[crypto_stream_KEYBYTES];
 *      const unsigned char n[crypto_stream_NONCEBYTES];
 *      unsigned char c[...]; unsigned long long clen;
 * 
 *      crypto_stream(c,clen,n,k);
 *      
 * The crypto_stream function produces a stream c[0], c[1], ..., c[clen-1] as a function of
 * a secret key k[0], k[1], ..., k[crypto_stream_KEYBYTES-1] and a nonce n[0], n[1], ...,
 * n[crypto_stream_NONCEBYTES-1]. The crypto_stream function then returns 0.
 * 
 * C NaCl also provides a crypto_stream_xor function callable as follows:
 * 
 *      #include "crypto_stream.h"
 * 
 *      const unsigned char k[crypto_stream_KEYBYTES];
 *      const unsigned char n[crypto_stream_NONCEBYTES];
 *      unsigned char m[...]; unsigned long long mlen;
 *      unsigned char c[...];
 * 
 *      crypto_stream_xor(c,m,mlen,n,k);
 *      
 * The crypto_stream_xor function encrypts a message m[0], m[1], ..., m[mlen-1] using a secret
 * key k[0], k[1], ..., k[crypto_stream_KEYBYTES-1] and a nonce n[0], n[1], ...,
 * n[crypto_stream_NONCEBYTES-1]. The crypto_stream_xor function puts the ciphertext into c[0],
 * c[1], ..., c[mlen-1]. It then returns 0.
 * 
 * The crypto_stream_xor function guarantees that the ciphertext is the plaintext xor the output
 * of crypto_stream. Consequently crypto_stream_xor can also be used to decrypt.
 *
 * Security model
 * 
 * The crypto_stream function, viewed as a function of the nonce for a uniform random key,
 * is designed to meet the standard notion of unpredictability ("PRF"). For a formal definition
 * see, e.g., Section 2.3 of Bellare, Kilian, and Rogaway, "The security of the cipher block
 * chaining message authentication code," Journal of Computer and System Sciences 61 (2000),
 * 362–399; http://www-cse.ucsd.edu/~mihir/papers/cbc.html.
 * This means that an attacker cannot distinguish this function from a uniform random function.
 * Consequently, if a series of messages is encrypted by crypto_stream_xor with a different
 * nonce for each message, the ciphertexts are indistinguishable from uniform random strings
 * of the same length.
 * 
 * Note that the length is not hidden. Note also that it is the caller's responsibility to
 * ensure the uniqueness of nonces—for example, by using nonce 1 for the first message, nonce 2
 * for the second message, etc. Nonces are long enough that randomly generated nonces have
 * negligible risk of collision.
 * 
 * NaCl does not make any promises regarding the resistance of crypto_stream to "related-key
 * attacks." It is the caller's responsibility to use proper key-derivation functions.
 * 
 * Selected primitive
 * 
 * crypto_stream is crypto_stream_xsalsa20, a particular cipher specified in "Cryptography in
 * NaCl", Section 7. This cipher is conjectured to meet the standard notion of unpredictability.
 * 
 * Alternate primitives
 * 
 * NaCl supports the following secret-key encryption functions:
 * 
 *     crypto_stream                      Primitive    KEYBYTES NONCEBYTES
 *     crypto_stream_aes128ctr            AES-128-CTR     16       16
 *     [TO DO:] crypto_stream_aes256ctr   AES-256-CTR     32       16
 *     crypto_stream_salsa208             Salsa20/8       32        8
 *     crypto_stream_salsa2012            Salsa20/12      32        8
 *     crypto_stream_salsa20              Salsa20/20      32        8
 *     crypto_stream_xsalsa20             XSalsa20/20     32       24
 * 
 * For example, a user who wants to encrypt with AES-128 can replace crypto_stream,
 * crypto_stream_KEYBYTES, etc. with crypto_stream_aes128ctr, crypto_stream_aes128ctr_KEYBYTES,
 * etc.
 * 
 * Beware that several of these primitives have 8-byte nonces. For those primitives it is no
 * longer true that randomly generated nonces have negligible risk of collision. Callers who
 * are unable to count 1,2,3,..., and who insist on using these primitives, are advised to use
 * a randomly derived key for each message.
 * 
 * Beware that the aes (AES-CTR) functions put extra requirements on the nonce: each message
 * actually uses a range of nonces (counting upwards for each 16-byte block), and these nonces
 * must not be reused for other messages. Randomly generated nonces are safe.
 */


/*
 * crypto_stream = crypto_stream_xsalsa20
   nacl::stream info
     cipher +0 nonce 24 key 32
   nacl::stream generate cipherVariable nonceValue keyValue
   nacl::stream cipherVariable messageValue nonceValue keyValue
 */

static int Tnacl_Stream (ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
  static const char *const command[] = {
    "info", "generate", NULL
  };
  enum command {
    TNACL_STREAM_INFO, TNACL_STREAM_GENERATE, TNACL_STREAM
  } cmd;

  if (objc < 2) {
    Tcl_WrongNumArgs(interp, 1, objv, "?command? ...");
    return TCL_ERROR;
  }

  if (Tcl_GetIndexFromObj(interp, objv[1], command, "command", 0, (int *)&cmd) != TCL_OK)
    cmd = TNACL_STREAM;

  switch (cmd) {
    case TNACL_STREAM_INFO: {
      if (objc != 2) {
        Tcl_WrongNumArgs(interp, 1, objv, "info");
        return TCL_ERROR;
      }
      Tcl_Obj *lObjPtr = Tcl_NewListObj(0, NULL);
      Tcl_ListObjAppendElement(interp, lObjPtr, Tcl_NewStringObj("cipher+", -1));
      Tcl_ListObjAppendElement(interp, lObjPtr, Tcl_NewIntObj(0));
      Tcl_ListObjAppendElement(interp, lObjPtr, Tcl_NewStringObj("nonce", -1));
      Tcl_ListObjAppendElement(interp, lObjPtr, Tcl_NewIntObj(crypto_stream_NONCEBYTES));
      Tcl_ListObjAppendElement(interp, lObjPtr, Tcl_NewStringObj("public-key", -1));
      Tcl_ListObjAppendElement(interp, lObjPtr, Tcl_NewIntObj(crypto_stream_KEYBYTES));
      Tcl_SetObjResult(interp, lObjPtr);
      return TCL_OK;
    }

    case TNACL_STREAM: {
      if (objc != 5) {
	Tcl_WrongNumArgs(interp, 1, objv, "cipherVariable messageValue nonceValue keyValue");
	//                                 1              2            3          4
	return TCL_ERROR;
      }

      Tcl_Obj *cObjPtr;
      unsigned char *c, *m, *n, *k;
      int rc, mLen, nLen, kLen;

      // 1:cipherVariable
      cObjPtr = Tcl_ObjGetVar2(interp, objv[1], (Tcl_Obj*) NULL, 0);
      if (cObjPtr == NULL)
	cObjPtr = Tcl_NewObj();
      if (Tcl_IsShared(cObjPtr))
	cObjPtr = Tcl_DuplicateObj(cObjPtr);

      // 2:messageValue
      m = Tcl_GetByteArrayFromObj(objv[2], &mLen);

      // 3:nonceValue
      n = Tcl_GetByteArrayFromObj(objv[3], &nLen);
      if (nLen != crypto_stream_NONCEBYTES) {
	Tcl_SetObjResult(interp, Tcl_ObjPrintf("wrong # nonce length %d bytes required", crypto_stream_NONCEBYTES));
	return TCL_ERROR;
      }

      // 4:keyValue
      k = Tcl_GetByteArrayFromObj(objv[4], &kLen);
      if (kLen != crypto_stream_KEYBYTES) {
	Tcl_SetObjResult(interp, Tcl_ObjPrintf("wrong # key length %d bytes required", crypto_stream_KEYBYTES));
	return TCL_ERROR;
      }

      c = Tcl_SetByteArrayLength(cObjPtr, mLen);

      rc = crypto_stream_xor(c, m, mLen, n, k);

      if (rc == 0) {
	// 1:cipherVariable
	if (Tcl_ObjSetVar2(interp, objv[1], NULL, cObjPtr, TCL_LEAVE_ERR_MSG) == NULL)
	  return TCL_ERROR;
      }

      Tcl_SetObjResult(interp, Tcl_NewIntObj(rc));
      return TCL_OK;
    }

    case TNACL_STREAM_GENERATE: {
      if (objc != 6) {
	Tcl_WrongNumArgs(interp, 1, objv, "generate cipherVariable lengthValue nonceValue keyValue");
	//                                 1        2              3           4          5
	return TCL_ERROR;
      }
      Tcl_Obj *cObjPtr;
      unsigned char *c, *n, *k;
      int rc, nLen, kLen;
      long len;

      // 2:cipherVariable
      cObjPtr = Tcl_ObjGetVar2(interp, objv[2], (Tcl_Obj*) NULL, 0);
      if (cObjPtr == NULL)
	cObjPtr = Tcl_NewObj();
      if (Tcl_IsShared(cObjPtr))
	cObjPtr = Tcl_DuplicateObj(cObjPtr);

      // 3:lengthValue
      if (Tcl_GetWideIntFromObj(interp, objv[3], (Tcl_WideInt *)&len) != TCL_OK) {
	return TCL_ERROR;
      }

      // 4:nonceValue
      n = Tcl_GetByteArrayFromObj(objv[4], &nLen);
      if (nLen != crypto_stream_NONCEBYTES) {
	Tcl_SetObjResult(interp, Tcl_ObjPrintf("wrong # nonce length %d bytes required", -1));
	return TCL_ERROR;
      }

      // 5:keyValue
      k = Tcl_GetByteArrayFromObj(objv[5], &kLen);
      if (kLen != crypto_stream_KEYBYTES) {
	Tcl_SetObjResult(interp, Tcl_ObjPrintf("wrong # key length %d bytes required", -1));
	return TCL_ERROR;
      }

      c = Tcl_SetByteArrayLength(cObjPtr, len);

      rc = crypto_stream(c, len, n, k);

      if (rc == 0) {
	// 2:messageVariable
	if (Tcl_ObjSetVar2(interp, objv[2], NULL, cObjPtr, TCL_LEAVE_ERR_MSG) == NULL)
	  return TCL_ERROR;
      }

      Tcl_SetObjResult(interp, Tcl_NewIntObj(rc));
      return TCL_OK;
    }
  }
  return TCL_OK;
}


/*
 * secret-key cryptography: secret-key message authentication: crypto_auth
 * -----------------------------------------------------------------------
 * C NaCl provides a crypto_auth function callable as follows:
 * 
 *      #include "crypto_auth.h"
 * 
 *      const unsigned char k[crypto_auth_KEYBYTES];
 *      const unsigned char m[...]; unsigned long long mlen;
 *      unsigned char a[crypto_auth_BYTES];
 * 
 *      crypto_auth(a,m,mlen,k);
 *      
 * The crypto_auth function authenticates a message m[0], m[1], ..., m[mlen-1] using a secret
 * key k[0], k[1], ..., k[crypto_auth_KEYBYTES-1]. The crypto_auth function puts the
 * authenticator into a[0], a[1], ..., a[crypto_auth_BYTES-1]. It then returns 0.
 * 
 * C NaCl also provides a crypto_auth_verify function callable as follows:
 * 
 *      #include "crypto_auth.h"
 * 
 *      const unsigned char k[crypto_auth_KEYBYTES];
 *      const unsigned char m[...]; unsigned long long mlen;
 *      const unsigned char a[crypto_auth_BYTES];
 * 
 *      crypto_auth_verify(a,m,mlen,k);
 *      
 * The crypto_auth_verify function returns 0 if a[0], ..., a[crypto_auth_BYTES-1] is a correct
 * authenticator of a message m[0], m[1], ..., m[mlen-1] under a secret key k[0], k[1], ...,
 * k[crypto_auth_KEYBYTES-1]. Otherwise crypto_auth_verify returns -1.
 * 
 * Security model
 * 
 * The crypto_auth function, viewed as a function of the message for a uniform random key,
 * is designed to meet the standard notion of unforgeability. This means that an attacker
 * cannot find authenticators for any messages not authenticated by the sender, even if the
 * attacker has adaptively influenced the messages authenticated by the sender. For a formal
 * definition see, e.g., Section 2.4 of Bellare, Kilian, and Rogaway, "The security of the
 * cipher block chaining message authentication code," Journal of Computer and System Sciences
 * 61 (2000), 362–399; http://www-cse.ucsd.edu/~mihir/papers/cbc.html.
 * NaCl does not make any promises regarding "strong" unforgeability; perhaps one valid
 * authenticator can be converted into another valid authenticator for the same message.
 * NaCl also does not make any promises regarding "truncated unforgeability."
 * 
 * Selected primitive
 * 
 * crypto_auth is currently an implementation of HMAC-SHA-512-256, i.e., the first 256 bits of
 * HMAC-SHA-512. HMAC-SHA-512-256 is conjectured to meet the standard notion of unforgeability.
 * 
 * Alternate primitives
 * 
 * NaCl supports the following secret-key authentication functions:
 * 
 * crypto_auth                Primitive         BYTES  KEYBYTES
 * crypto_auth_hmacsha256     HMAC_SHA-256        32     32
 * crypto_auth_hmacsha512256  HMAC_SHA-512-256    32     32
 * 
 * For example, a user can replace crypto_auth, crypto_auth_KEYBYTES, etc. with
 * crypto_auth_hmacsha256, crypto_auth_hmacsha256_KEYBYTES, etc.
 */

/*
 * crypto_auth_hmacsha256_ref, crypto_auth_hmacsha512256_ref
   nacl::auth info
     auth 32 key 32
   nacl::auth ?-hmac256|-hmac512256? authVariable messageValue keyValue
   nacl::auth verify -hmac256|-hmac512256 authValue messageValue keyValue
 */

static int Tnacl_Auth(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
  static const char *const command[] = {
    "info", "verify", NULL
  };
  enum command {
    TNACL_AUTH_INFO, TNACL_AUTH_VERIFY, TNACL_AUTH
  } cmd;

  static const char *const option[] = {
    "-hmac256", "-hmac512256", NULL
  };
  enum option {
    TNACL_AUTH_HMAC256, TNACL_AUTH_HMAC512256
  } hmac;

  if (objc < 2) {
    Tcl_WrongNumArgs(interp, 1, objv, "?command? ?-option? ...");
    return TCL_ERROR;
  }

  int idx = 1;

  if (Tcl_GetIndexFromObj(interp, objv[1], command, "command", 0, (int *)&cmd) != TCL_OK) {
    cmd = TNACL_AUTH;
  } else {
    idx++;
  }

  hmac = TNACL_AUTH_HMAC512256;

  if (objc > 2) {
    if (Tcl_GetIndexFromObj(interp, objv[idx], option, "-option", 0, (int *)&hmac) != TCL_OK) {
      hmac = TNACL_AUTH_HMAC512256;
    } else {
      idx++;
    }
  }

  switch (cmd) {
    case TNACL_AUTH_INFO: {
      if (objc != 2) {
        Tcl_WrongNumArgs(interp, 1, objv, "info");
        return TCL_ERROR;
      }
      Tcl_Obj *lObjPtr = Tcl_NewListObj(0, NULL);
      Tcl_ListObjAppendElement(interp, lObjPtr, Tcl_NewStringObj("auth", -1));
      Tcl_ListObjAppendElement(interp, lObjPtr, Tcl_NewIntObj(crypto_auth_BYTES));
      Tcl_ListObjAppendElement(interp, lObjPtr, Tcl_NewStringObj("nonce", -1));
      Tcl_ListObjAppendElement(interp, lObjPtr, Tcl_NewIntObj(crypto_auth_KEYBYTES));
      Tcl_SetObjResult(interp, lObjPtr);
      return TCL_OK;
    }

    case TNACL_AUTH: {
      if (objc != (idx + 3)) {
	Tcl_WrongNumArgs(interp, 1, objv, "?-hmac256|-hmac512256? authVariable messageValue keyValue");
	//                                 idx                    +0           +1           +2
	return TCL_ERROR;
      }

      Tcl_Obj *aObjPtr;
      unsigned char *a, *m, *k;
      int rc, mLen, kLen;

      // 0:authVariable
      aObjPtr = Tcl_ObjGetVar2(interp, objv[idx + 0], (Tcl_Obj*) NULL, 0);
      if (aObjPtr == NULL)
	aObjPtr = Tcl_NewObj();
      if (Tcl_IsShared(aObjPtr))
	aObjPtr = Tcl_DuplicateObj(aObjPtr);

      // 1:messageValue
      m = Tcl_GetByteArrayFromObj(objv[idx + 1], &mLen);

      // 2:keyValue
      k = Tcl_GetByteArrayFromObj(objv[idx + 2], &kLen);
      if (kLen != crypto_auth_KEYBYTES) {
	Tcl_SetObjResult(interp, Tcl_ObjPrintf("wrong # key length %d bytes required", crypto_auth_KEYBYTES));
	return TCL_ERROR;
      }

      a = Tcl_SetByteArrayLength(aObjPtr, crypto_auth_BYTES);

      if (hmac == TNACL_AUTH_HMAC256) {
	rc = crypto_auth_hmacsha256_ref(a, m, mLen, k);
      } else {
	rc = crypto_auth_hmacsha512256_ref(a, m, mLen, k);
      }

      if (rc == 0) {
	// 0:authVariable
	if (Tcl_ObjSetVar2(interp, objv[idx + 0], NULL, aObjPtr, TCL_LEAVE_ERR_MSG) == NULL)
	  return TCL_ERROR;
      }

      Tcl_SetObjResult(interp, Tcl_NewIntObj(rc));
      return TCL_OK;
    }

    case TNACL_AUTH_VERIFY: {
      if (objc != (idx + 3)) {
	Tcl_WrongNumArgs(interp, 1, objv, "verify ?-hmac256|-hmac512256? authValue messageValue keyValue");
	//                                 idx    idx                    +0        +1           +2
	return TCL_ERROR;
      }

      unsigned char *a, *m, *k;
      int rc, aLen, mLen, kLen;

      // 0:authValue
      a = Tcl_GetByteArrayFromObj(objv[idx + 0], &aLen);
      if (aLen != crypto_auth_BYTES) {
	Tcl_SetObjResult(interp, Tcl_ObjPrintf("wrong # auth length %d bytes required", crypto_auth_BYTES));
	return TCL_ERROR;
      }

      // 1:messageValue
      m = Tcl_GetByteArrayFromObj(objv[idx + 1], &mLen);

      // 2:keyValue
      k = Tcl_GetByteArrayFromObj(objv[idx + 2], &kLen);
      if (kLen != crypto_auth_KEYBYTES) {
	Tcl_SetObjResult(interp, Tcl_ObjPrintf("wrong # key length %d bytes required", crypto_auth_KEYBYTES));
	return TCL_ERROR;
      }

      if (hmac == TNACL_AUTH_HMAC256) {
	rc = crypto_auth_hmacsha256_ref_verify(a, m, mLen, k);
      } else {
	rc = crypto_auth_hmacsha512256_ref_verify(a, m, mLen, k);
      }

      Tcl_SetObjResult(interp, Tcl_NewIntObj(rc));
      return TCL_OK;
    }
  }
  return TCL_OK;
}


/*
 * secret-key cryptography: secret-key single-message authentication: crypto_onetimeauth
 * -------------------------------------------------------------------------------------
 *
 * C NaCl provides a crypto_onetimeauth function callable as follows:
 *      #include "crypto_onetimeauth.h"
 * 
 *      const unsigned char k[crypto_onetimeauth_KEYBYTES];
 *      const unsigned char m[...]; unsigned long long mlen;
 *      unsigned char a[crypto_onetimeauth_BYTES];
 * 
 *      crypto_onetimeauth(a,m,mlen,k);
 *      
 * The crypto_onetimeauth function authenticates a message m[0], m[1], ..., m[mlen-1] using a
 * secret key k[0], k[1], ..., k[crypto_onetimeauth_KEYBYTES-1]; puts the authenticator into
 * a[0], a[1], ..., a[crypto_onetimeauth_BYTES-1]; and returns 0.
 * 
 * C NaCl also provides a crypto_onetimeauth_verify function callable as follows:
 * 
 *      #include "crypto_onetimeauth.h"
 * 
 *      const unsigned char k[crypto_onetimeauth_KEYBYTES];
 *      const unsigned char m[...]; unsigned long long mlen;
 *      const unsigned char a[crypto_onetimeauth_BYTES];
 * 
 *      crypto_onetimeauth_verify(a,m,mlen,k);
 *      
 * This function returns 0 if a[0], a[1], ..., a[crypto_onetimeauth_BYTES-1] is a correct
 * authenticator of a message m[0], m[1], ..., m[mlen-1] under a secret key k[0], k[1], ...,
 * k[crypto_onetimeauth_KEYBYTES-1]. Otherwise crypto_onetimeauth_verify returns -1.
 * 
 * Security model
 * 
 * The crypto_onetimeauth function, viewed as a function of the message for a uniform random
 * key, is designed to meet the standard notion of unforgeability after a single message. After
 * the sender authenticates one message, an attacker cannot find authenticators for any other
 * messages.
 * The sender must not use crypto_onetimeauth to authenticate more than one message under the
 * same key. Authenticators for two messages under the same key should be expected to reveal
 * enough information to allow forgeries of authenticators on other messages.
 * 
 * Selected primitive
 * 
 * crypto_onetimeauth is crypto_onetimeauth_poly1305, an authenticator specified in "Cryptography
 * in NaCl", Section 9. This authenticator is proven to meet the standard notion of unforgeability
 * after a single message.
 * 
 * Alternate primitives
 * 
 * NaCl supports the following secret-key single-message authentication functions:
 * 
 *     crypto_onetimeauth           Primitive  BYTES  KEYBYTES
 *     crypto_onetimeauth_poly1305  Poly1305    16      32
 * 
 * For example, a user can replace crypto_onetimeauth, crypto_onetimeauth_BYTES, etc. with
 * crypto_onetimeauth_poly1305, crypto_onetimeauth_poly1305_BYTES, etc. Furthermore, users
 * willing to compromise both provability and speed can replace crypto_onetimeauth with
 * crypto_auth or with any of the crypto_auth primitives.
 */

/*
 * crypto_onetimeauth = crypto_onetimeauth_poly1305
   nacl::info
     auth 16 key 32
   nacl::onetimeauth authVariable messageValue keyValue
   nacl::onetimeauth verify authValue messageValue keyValue
 */

static int Tnacl_OneTimeAuth(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
  static const char *const command[] = {
    "info", "verify", NULL
  };
  enum command {
    TNACL_ONETIMEAUTH_INFO, TNACL_ONETIMEAUTH_VERIFY, TNACL_ONETIMEAUTH
  } cmd;

  if (objc < 2) {
    Tcl_WrongNumArgs(interp, 1, objv, "?command? ...");
    return TCL_ERROR;
  }

  if (Tcl_GetIndexFromObj(interp, objv[1], command, "command", 0, (int *)&cmd) != TCL_OK)
    cmd = TNACL_ONETIMEAUTH;

  switch (cmd) {
    case TNACL_ONETIMEAUTH_INFO: {
      if (objc != 2) {
        Tcl_WrongNumArgs(interp, 1, objv, "info");
        return TCL_ERROR;
      }
      Tcl_Obj *lObjPtr = Tcl_NewListObj(0, NULL);
      Tcl_ListObjAppendElement(interp, lObjPtr, Tcl_NewStringObj("auth", -1));
      Tcl_ListObjAppendElement(interp, lObjPtr, Tcl_NewIntObj(crypto_onetimeauth_BYTES));
      Tcl_ListObjAppendElement(interp, lObjPtr, Tcl_NewStringObj("key", -1));
      Tcl_ListObjAppendElement(interp, lObjPtr, Tcl_NewIntObj(crypto_onetimeauth_KEYBYTES));
      Tcl_SetObjResult(interp, lObjPtr);
      return TCL_OK;
    }

    case TNACL_ONETIMEAUTH: {
      if (objc != 4) {
	Tcl_WrongNumArgs(interp, 1, objv, "authVariable messageValue keyValue");
	//                                 1            2            3
	return TCL_ERROR;
      }

      Tcl_Obj *aObjPtr;
      unsigned char *a, *m, *k;
      int rc, mLen, kLen;

      // 1:authVariable
      aObjPtr = Tcl_ObjGetVar2(interp, objv[1], (Tcl_Obj*) NULL, 0);
      if (aObjPtr == NULL)
	aObjPtr = Tcl_NewObj();
      if (Tcl_IsShared(aObjPtr))
	aObjPtr = Tcl_DuplicateObj(aObjPtr);

      // 2:messageValue
      m = Tcl_GetByteArrayFromObj(objv[2], &mLen);

      // 3:keyValue
      k = Tcl_GetByteArrayFromObj(objv[3], &kLen);
      if (kLen != crypto_onetimeauth_KEYBYTES) {
	Tcl_SetObjResult(interp, Tcl_ObjPrintf("wrong # key length %d bytes required", crypto_onetimeauth_KEYBYTES));
	return TCL_ERROR;
      }

      a = Tcl_SetByteArrayLength(aObjPtr, crypto_onetimeauth_BYTES);

      rc = crypto_onetimeauth(a, m, mLen, k);

      if (rc == 0) {
	// 1:authVariable
	if (Tcl_ObjSetVar2(interp, objv[1], NULL, aObjPtr, TCL_LEAVE_ERR_MSG) == NULL)
	  return TCL_ERROR;
      }

      Tcl_SetObjResult(interp, Tcl_NewIntObj(rc));
      return TCL_OK;
    }

    case TNACL_ONETIMEAUTH_VERIFY: {
      if (objc != 5) {
	Tcl_WrongNumArgs(interp, 1, objv, "verify authValue messageValue keyValue");
	//                                 1      2         3            4
	return TCL_ERROR;
      }

      unsigned char *a, *m, *k;
      int rc, aLen, mLen, kLen;

      // 2:authValue
      a = Tcl_GetByteArrayFromObj(objv[2], &aLen);
      if (aLen != crypto_onetimeauth_BYTES) {
	Tcl_SetObjResult(interp, Tcl_ObjPrintf("wrong # auth length %d bytes required", crypto_onetimeauth_BYTES));
	return TCL_ERROR;
      }

      // 3:messageValue
      m = Tcl_GetByteArrayFromObj(objv[3], &mLen);

      // 4:keyValue
      k = Tcl_GetByteArrayFromObj(objv[4], &kLen);
      if (kLen != crypto_onetimeauth_KEYBYTES) {
	Tcl_SetObjResult(interp, Tcl_ObjPrintf("wrong # key length %d bytes required", crypto_onetimeauth_KEYBYTES));
	return TCL_ERROR;
      }

      rc = crypto_onetimeauth_verify(a, m, mLen, k);

      Tcl_SetObjResult(interp, Tcl_NewIntObj(rc));
      return TCL_OK;
    }
  }
  return TCL_OK;
}


/*
 * low-level function: hashing: crypto_hash
 * ----------------------------------------
 *
 * C NaCl provides a crypto_hash function callable as follows:
 * 
 *      #include "crypto_hash.h"
 * 
 *      const unsigned char m[...]; unsigned long long mlen;
 *      unsigned char h[crypto_hash_BYTES];
 * 
 *      crypto_hash(h,m,mlen);
 *      
 * The crypto_hash function hashes a message m[0], m[1], ..., m[mlen-1]. It puts the hash
 * into h[0], h[1], ..., h[crypto_hash_BYTES-1]. It then returns 0.
 * 
 * Security model
 * 
 * The crypto_hash function is designed to be usable as a strong component of DSA, RSA-PSS,
 * key derivation, hash-based message-authentication codes, hash-based ciphers, and various
 * other common applications. "Strong" means that the security of these applications, when
 * instantiated with crypto_hash, is the same as the security of the applications against
 * generic attacks. In particular, the crypto_hash function is designed to make finding
 * collisions difficult.
 * 
 * Selected primitive
 * 
 * crypto_hash is currently an implementation of SHA-512.
 * There has been considerable degradation of public confidence in the security conjectures
 * for many hash functions, including SHA-512. However, for the moment, there do not appear
 * to be alternatives that inspire satisfactory levels of confidence. One can hope that NIST's
 * SHA-3 competition will improve the situation.
 * 
 * Alternate primitives
 * 
 * NaCl supports the following hash functions:
 * 
 *     crypto_hash         Primitive  BYTES
 *     crypto_hash_sha256  SHA-256     32
 *     crypto_hash_sha512  SHA-512     64
 * 
 * For example, a user who wants to hash with SHA-256 can simply replace crypto_hash,
 * crypto_hash_BYTES, etc. with crypto_hash_sha256, crypto_hash_sha256_BYTES, etc.
 */

/*
 * crypto_hash_sha256_ref, crypto_hash = crypto_hash_sha512
   nacl::hash info
     sha256 32 sha512 64
   nacl::hash ?-sha256|-sha512? hashVariable messageValue
*/

static int Tnacl_Hash(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
  Tcl_Obj *hObjPtr;
  unsigned char *h, *m;
  int rc = -1, hLen = 0, mLen;

  static const char *const option[] = {
    "info", "-sha256", "-sha512", NULL
  };
  enum option {
    TNACL_HASH_INFO, TNACL_HASH_SHA256, TNACL_HASH_SHA512
  } sha;

  if (objc < 2) {
    Tcl_WrongNumArgs(interp, 1, objv, "?-option|command? ...");
    return TCL_ERROR;
  }

  int idx = 1;

  if (Tcl_GetIndexFromObj(interp, objv[1], option, "-option|command", 0, (int *)&sha) != TCL_OK) {
    sha = TNACL_HASH_SHA512;
  } else {
    idx++;
  }

  if (sha == TNACL_HASH_INFO && objc != 2) {
    Tcl_WrongNumArgs(interp, 1, objv, "info");
    return TCL_ERROR;
  }
  if (sha != TNACL_HASH_INFO && objc != (idx + 2)) {
    Tcl_WrongNumArgs(interp, 1, objv, "?-sha256|-sha512? hashVariable messageValue");
    //                                 idx               +0           +1
    return TCL_ERROR;
  }

  if (sha == TNACL_HASH_INFO) {
    if (objc != 2) {
      Tcl_WrongNumArgs(interp, 1, objv, "");
      return TCL_ERROR;
    }
    Tcl_Obj *lObjPtr = Tcl_NewListObj(0, NULL);
    Tcl_ListObjAppendElement(interp, lObjPtr, Tcl_NewStringObj("sha256", -1));
    Tcl_ListObjAppendElement(interp, lObjPtr, Tcl_NewIntObj(crypto_hash_sha256_tweet_BYTES));
    Tcl_ListObjAppendElement(interp, lObjPtr, Tcl_NewStringObj("sha512", -1));
    Tcl_ListObjAppendElement(interp, lObjPtr, Tcl_NewIntObj(crypto_hash_sha512_tweet_BYTES));
    Tcl_SetObjResult(interp, lObjPtr);
    return TCL_OK;
  }

  // 0:hashVariable
  hObjPtr = Tcl_ObjGetVar2(interp, objv[idx + 0], (Tcl_Obj*) NULL, 0);
  if (hObjPtr == NULL)
    hObjPtr = Tcl_NewObj();
  if (Tcl_IsShared(hObjPtr))
    hObjPtr = Tcl_DuplicateObj(hObjPtr);

  switch (sha) {
    case TNACL_HASH_INFO: {
      hLen = 0; // irgore, will never entered
      break;;
    }
    case TNACL_HASH_SHA256: {
      hLen = crypto_hash_sha256_tweet_BYTES;
      break;;
    }
    case TNACL_HASH_SHA512: {
      hLen = crypto_hash_sha512_tweet_BYTES;
      break;;
    }
  }
  h = Tcl_SetByteArrayLength(hObjPtr, hLen);

  // 1:messageValue
  m = Tcl_GetByteArrayFromObj(objv[idx + 1], &mLen);

  switch (sha) {
    case TNACL_HASH_INFO: {
      rc = -1; // irgore, will never entered;
      break;;
    }
    case TNACL_HASH_SHA256: {
      rc = crypto_hash_sha256_ref(h, m, mLen);
      break;;
    }
    case TNACL_HASH_SHA512: {
      rc = crypto_hash(h, m, mLen);
      break;;
    }
  }

  if (rc == 0) {
    // 1:hashVariable
    if (Tcl_ObjSetVar2(interp, objv[idx + 0], NULL, hObjPtr, TCL_LEAVE_ERR_MSG) == NULL)
      return TCL_ERROR;
  }

  Tcl_SetObjResult(interp, Tcl_NewIntObj(rc));
  return TCL_OK;
}


/*
 * low-level function: string comparison: crypto_verify
 * ----------------------------------------------------
 *
 * C NaCl provides a crypto_verify_16 function callable as follows:
 * 
 *      #include "crypto_verify_16.h"
 * 
 *      const unsigned char x[16];
 *      const unsigned char y[16];
 * 
 *      crypto_verify_16(x,y);
 *      
 * The crypto_verify_16 function returns 0 if x[0], x[1], ..., x[15] are the same as y[0],
 * y[1], ..., y[15]. Otherwise it returns -1.
 * 
 * This function is safe to use for secrets x[0], x[1], ..., x[15], y[0], y[1], ..., y[15].
 * The time taken by crypto_verify_16 is independent of the contents of x[0], x[1], ..., x[15],
 * y[0], y[1], ..., y[15]. In contrast, the standard C comparison function memcmp(x,y,16)
 * takes time that depends on the longest matching prefix of x and y, often allowing easy
 * timing attacks.
 * 
 * C NaCl also provides a similar crypto_verify_32 function.
 */

// Not implemented for calling from Tcl


static int Tnacl_Info (ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
  Tcl_SetObjResult(interp, Tcl_NewStringObj(TWEETNACL_VERSION, -1));
  Tcl_Obj *lObjPtr = Tcl_NewListObj(0, NULL);

  Tcl_ListObjAppendElement(interp, lObjPtr, Tcl_NewStringObj("NaCl", -1));
  Tcl_ListObjAppendElement(interp, lObjPtr, Tcl_NewIntObj(20110221));
  Tcl_ListObjAppendElement(interp, lObjPtr, Tcl_NewStringObj("TweetNaCl", -1));
  Tcl_ListObjAppendElement(interp, lObjPtr, Tcl_NewStringObj(TWEETNACL_VERSION, -1));

  Tcl_ListObjAppendElement(interp, lObjPtr, Tcl_NewStringObj("CONTRIBUTORS", -1));
  Tcl_Obj *clObjPtr = Tcl_NewListObj(0, NULL);
  Tcl_ListObjAppendElement(interp, clObjPtr, Tcl_NewStringObj("Daniel J. Bernstein, University of Illinois at Chicago and Technische Universiteit Eindhoven", -1));
  Tcl_ListObjAppendElement(interp, clObjPtr, Tcl_NewStringObj("Bernard van Gastel, Radboud Universiteit Nijmegen", -1));
  Tcl_ListObjAppendElement(interp, clObjPtr, Tcl_NewStringObj("Wesley Janssen, Radboud Universiteit Nijmegen", -1));
  Tcl_ListObjAppendElement(interp, clObjPtr, Tcl_NewStringObj("Tanja Lange, Technische Universiteit Eindhoven", -1));
  Tcl_ListObjAppendElement(interp, clObjPtr, Tcl_NewStringObj("Peter Schwabe, Radboud Universiteit Nijmegen", -1));
  Tcl_ListObjAppendElement(interp, clObjPtr, Tcl_NewStringObj("Sjaak Smetsers, Radboud Universiteit Nijmegen", -1));
  Tcl_ListObjAppendElement(interp, clObjPtr, Tcl_NewStringObj("Alexander Sch\xF6pe, Bochum, NW, Germany", -1));
  Tcl_ListObjAppendElement(interp, lObjPtr, clObjPtr);

  Tcl_ListObjAppendElement(interp, lObjPtr, Tcl_NewStringObj("LICENSE", -1));
  Tcl_Obj *llObjPtr = Tcl_NewListObj(0, NULL);
  Tcl_ListObjAppendElement(interp, llObjPtr, Tcl_NewStringObj("NaCl Tcl Package software is BSD 3 License.", -1));
  Tcl_ListObjAppendElement(interp, llObjPtr, Tcl_NewStringObj("All of the NaCl and TweetNaCl software is in the public domain.", -1));
  Tcl_ListObjAppendElement(interp, lObjPtr, llObjPtr);

  Tcl_ListObjAppendElement(interp, lObjPtr, Tcl_NewStringObj("crypto_box", -1));
  Tcl_ListObjAppendElement(interp, lObjPtr, Tcl_NewStringObj("crypto_box_curve25519xsalsa20poly1305", -1));
  Tcl_ListObjAppendElement(interp, lObjPtr, Tcl_NewStringObj("crypto_box_BOXZEROBYTES", -1));
  Tcl_ListObjAppendElement(interp, lObjPtr, Tcl_NewIntObj(crypto_box_BOXZEROBYTES));
  Tcl_ListObjAppendElement(interp, lObjPtr, Tcl_NewStringObj("crypto_box_ZEROBYTES", -1));
  Tcl_ListObjAppendElement(interp, lObjPtr, Tcl_NewIntObj(crypto_box_ZEROBYTES));
  Tcl_ListObjAppendElement(interp, lObjPtr, Tcl_NewStringObj("crypto_box_NONCEBYTES", -1));
  Tcl_ListObjAppendElement(interp, lObjPtr, Tcl_NewIntObj(crypto_box_NONCEBYTES));
  Tcl_ListObjAppendElement(interp, lObjPtr, Tcl_NewStringObj("crypto_box_PUBLICKEYBYTES", -1));
  Tcl_ListObjAppendElement(interp, lObjPtr, Tcl_NewIntObj(crypto_box_PUBLICKEYBYTES));
  Tcl_ListObjAppendElement(interp, lObjPtr, Tcl_NewStringObj("crypto_box_SECRETKEYBYTES", -1));
  Tcl_ListObjAppendElement(interp, lObjPtr, Tcl_NewIntObj(crypto_box_SECRETKEYBYTES));

  Tcl_ListObjAppendElement(interp, lObjPtr, Tcl_NewStringObj("crypto_scalarmult", -1));
  Tcl_ListObjAppendElement(interp, lObjPtr, Tcl_NewStringObj("crypto_scalarmult_curve25519", -1));
  Tcl_ListObjAppendElement(interp, lObjPtr, Tcl_NewStringObj("crypto_scalarmult_BYTES", -1));
  Tcl_ListObjAppendElement(interp, lObjPtr, Tcl_NewIntObj(crypto_scalarmult_BYTES));
  Tcl_ListObjAppendElement(interp, lObjPtr, Tcl_NewStringObj("crypto_scalarmult_SCALARBYTES", -1));
  Tcl_ListObjAppendElement(interp, lObjPtr, Tcl_NewIntObj(crypto_scalarmult_SCALARBYTES));

  Tcl_ListObjAppendElement(interp, lObjPtr, Tcl_NewStringObj("crypto_sign", -1));
  Tcl_ListObjAppendElement(interp, lObjPtr, Tcl_NewStringObj("crypto_sign_ed25519", -1));
  Tcl_ListObjAppendElement(interp, lObjPtr, Tcl_NewStringObj("crypto_sign_BYTES", -1));
  Tcl_ListObjAppendElement(interp, lObjPtr, Tcl_NewIntObj(crypto_sign_BYTES));
  Tcl_ListObjAppendElement(interp, lObjPtr, Tcl_NewStringObj("crypto_sign_PUBLICKEYBYTES", -1));
  Tcl_ListObjAppendElement(interp, lObjPtr, Tcl_NewIntObj(crypto_sign_PUBLICKEYBYTES));
  Tcl_ListObjAppendElement(interp, lObjPtr, Tcl_NewStringObj("crypto_sign_SECRETKEYBYTES", -1));
  Tcl_ListObjAppendElement(interp, lObjPtr, Tcl_NewIntObj(crypto_sign_SECRETKEYBYTES));

  Tcl_ListObjAppendElement(interp, lObjPtr, Tcl_NewStringObj("crypto_secretbox", -1));
  Tcl_ListObjAppendElement(interp, lObjPtr, Tcl_NewStringObj("crypto_secretbox_xsalsa20poly1305", -1));
  Tcl_ListObjAppendElement(interp, lObjPtr, Tcl_NewStringObj("crypto_secretbox_BOXZEROBYTES", -1));
  Tcl_ListObjAppendElement(interp, lObjPtr, Tcl_NewIntObj(crypto_secretbox_BOXZEROBYTES));
  Tcl_ListObjAppendElement(interp, lObjPtr, Tcl_NewStringObj("crypto_secretbox_ZEROBYTES", -1));
  Tcl_ListObjAppendElement(interp, lObjPtr, Tcl_NewIntObj(crypto_secretbox_ZEROBYTES));
  Tcl_ListObjAppendElement(interp, lObjPtr, Tcl_NewStringObj("crypto_secretbox_NONCEBYTES", -1));
  Tcl_ListObjAppendElement(interp, lObjPtr, Tcl_NewIntObj(crypto_secretbox_NONCEBYTES));
  Tcl_ListObjAppendElement(interp, lObjPtr, Tcl_NewStringObj("crypto_secretbox_KEYBYTES", -1));
  Tcl_ListObjAppendElement(interp, lObjPtr, Tcl_NewIntObj(crypto_secretbox_KEYBYTES));

  Tcl_ListObjAppendElement(interp, lObjPtr, Tcl_NewStringObj("crypto_stream", -1));
  Tcl_ListObjAppendElement(interp, lObjPtr, Tcl_NewStringObj("crypto_stream_xsalsa20", -1));
  Tcl_ListObjAppendElement(interp, lObjPtr, Tcl_NewStringObj("crypto_stream_NONCEBYTES", -1));
  Tcl_ListObjAppendElement(interp, lObjPtr, Tcl_NewIntObj(crypto_stream_NONCEBYTES));
  Tcl_ListObjAppendElement(interp, lObjPtr, Tcl_NewStringObj("crypto_stream_KEYBYTES", -1));
  Tcl_ListObjAppendElement(interp, lObjPtr, Tcl_NewIntObj(crypto_stream_KEYBYTES));

  Tcl_ListObjAppendElement(interp, lObjPtr, Tcl_NewStringObj("crypto_auth", -1));
  Tcl_ListObjAppendElement(interp, lObjPtr, Tcl_NewStringObj("crypto_auth_hmacsha256_ref crypto_auth_hmacsha512256_ref", -1));
  Tcl_ListObjAppendElement(interp, lObjPtr, Tcl_NewStringObj("crypto_auth_BYTES", -1));
  Tcl_ListObjAppendElement(interp, lObjPtr, Tcl_NewIntObj(crypto_auth_BYTES));
  Tcl_ListObjAppendElement(interp, lObjPtr, Tcl_NewStringObj("crypto_auth_KEYBYTES", -1));
  Tcl_ListObjAppendElement(interp, lObjPtr, Tcl_NewIntObj(crypto_auth_KEYBYTES));

  Tcl_ListObjAppendElement(interp, lObjPtr, Tcl_NewStringObj("crypto_onetimeauth", -1));
  Tcl_ListObjAppendElement(interp, lObjPtr, Tcl_NewStringObj("crypto_onetimeauth_poly1305", -1));
  Tcl_ListObjAppendElement(interp, lObjPtr, Tcl_NewStringObj("crypto_onetimeauth_BYTES", -1));
  Tcl_ListObjAppendElement(interp, lObjPtr, Tcl_NewIntObj(crypto_onetimeauth_BYTES));
  Tcl_ListObjAppendElement(interp, lObjPtr, Tcl_NewStringObj("crypto_onetimeauth_KEYBYTES", -1));
  Tcl_ListObjAppendElement(interp, lObjPtr, Tcl_NewIntObj(crypto_onetimeauth_KEYBYTES));

  Tcl_ListObjAppendElement(interp, lObjPtr, Tcl_NewStringObj("crypto_hash", -1));
  Tcl_ListObjAppendElement(interp, lObjPtr, Tcl_NewStringObj("crypto_hash_sha256_ref crypto_hash_sha512", -1));
  Tcl_ListObjAppendElement(interp, lObjPtr, Tcl_NewStringObj("crypto_hash_sha256_BYTES", -1));
  Tcl_ListObjAppendElement(interp, lObjPtr, Tcl_NewIntObj(crypto_hash_sha256_tweet_BYTES));
  Tcl_ListObjAppendElement(interp, lObjPtr, Tcl_NewStringObj("crypto_hash_sha512_BYTES", -1));
  Tcl_ListObjAppendElement(interp, lObjPtr, Tcl_NewIntObj(crypto_hash_sha512_tweet_BYTES));

  Tcl_SetObjResult(interp, lObjPtr);
  return TCL_OK;
}


#ifdef _WIN32
DECLSPEC_EXPORT
#endif
int Nacl_Init(Tcl_Interp *interp) {
#ifdef USE_TCL_STUBS
  if (Tcl_InitStubs(interp, MY_TCL_INITSTUBS, 0) == NULL) {
    return TCL_ERROR;
  }
#endif

  Tcl_CreateObjCommand(interp, "::nacl::randombytes", Tnacl_RandomBytes, (ClientData)NULL, (Tcl_CmdDeleteProc *)NULL);

  // public-key cryptography
  Tcl_CreateObjCommand(interp, "::nacl::box", Tnacl_Box, (ClientData)NULL, (Tcl_CmdDeleteProc *)NULL);
  Tcl_CreateObjCommand(interp, "::nacl::scalarmult", Tnacl_ScalarMult, (ClientData)NULL, (Tcl_CmdDeleteProc *)NULL);
  Tcl_CreateObjCommand(interp, "::nacl::sign", Tnacl_Sign, (ClientData)NULL, (Tcl_CmdDeleteProc *)NULL);

  // secret-key cryptography
  Tcl_CreateObjCommand(interp, "::nacl::secretbox", Tnacl_SecretBox, (ClientData)NULL, (Tcl_CmdDeleteProc *)NULL);
  Tcl_CreateObjCommand(interp, "::nacl::stream", Tnacl_Stream, (ClientData)NULL, (Tcl_CmdDeleteProc *)NULL);
  Tcl_CreateObjCommand(interp, "::nacl::auth", Tnacl_Auth, (ClientData)NULL, (Tcl_CmdDeleteProc *)NULL);
  Tcl_CreateObjCommand(interp, "::nacl::onetimeauth", Tnacl_OneTimeAuth, (ClientData)NULL, (Tcl_CmdDeleteProc *)NULL);

  // low-level functions
  Tcl_CreateObjCommand(interp, "::nacl::hash", Tnacl_Hash, (ClientData)NULL, (Tcl_CmdDeleteProc *)NULL);

  // information functions
  Tcl_CreateObjCommand(interp, "::nacl::info", Tnacl_Info, (ClientData)NULL, (Tcl_CmdDeleteProc *)NULL);

  Tcl_PkgProvide(interp, PACKAGE_NAME, PACKAGE_VERSION);
  return TCL_OK;
}

#ifdef _WIN32
DECLSPEC_EXPORT
#endif
int Nacl_SafeInit(Tcl_Interp *interp) {
  return Nacl_Init(interp);
}

