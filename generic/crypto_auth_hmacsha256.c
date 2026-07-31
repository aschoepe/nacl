/*
 * 20080913
 * D. J. Bernstein
 * Public domain.
 *
 * */

#include "tweetnacl.h"
#include "crypto_reference.h"
//#include "crypto_hashblocks_sha256.h"
//#include "crypto_auth.h"

//#define blocks crypto_hashblocks_sha256
#define blocks crypto_hashblocks_sha256_ref

typedef unsigned int uint32;

static const unsigned char iv256[32] = {
  0x6a,0x09,0xe6,0x67,
  0xbb,0x67,0xae,0x85,
  0x3c,0x6e,0xf3,0x72,
  0xa5,0x4f,0xf5,0x3a,
  0x51,0x0e,0x52,0x7f,
  0x9b,0x05,0x68,0x8c,
  0x1f,0x83,0xd9,0xab,
  0x5b,0xe0,0xcd,0x19,
} ;

/*
 * SHA-224 is SHA-256 with a different initial state and the result cut to
 * 28 bytes. FIPS 180-4 section 5.3.2.
 */

static const unsigned char iv224[32] = {
  0xc1,0x05,0x9e,0xd8,
  0x36,0x7c,0xd5,0x07,
  0x30,0x70,0xdd,0x17,
  0xf7,0x0e,0x59,0x39,
  0xff,0xc0,0x0b,0x31,
  0x68,0x58,0x15,0x11,
  0x64,0xf9,0x8f,0xa7,
  0xbe,0xfa,0x4f,0xa4,
} ;

/*
 * kpad holds the key already prepared according to RFC 2104 section 2:
 * hashed if it was longer than the block size, then zero padded to the
 * full block size of 64 bytes.
 *
 * ivp and hashlen select the hash: the SHA-256 state with 32 bytes of
 * result, or the SHA-224 state with 28. hashlen is what goes into the
 * outer block, so it also decides the length encoded at its end. outlen
 * is how much of the outer state is handed back, at most hashlen.
 */

static int hmacsha2(unsigned char *out,int outlen,const unsigned char *ivp,int hashlen,const unsigned char *in,unsigned long long inlen,const unsigned char *kpad)
{
  unsigned char h[32];
  unsigned char padded[128];
  int i;
  unsigned long long bits = 512 + (inlen << 3);
  unsigned long long obits = (64 + hashlen) << 3;

  for (i = 0;i < 32;++i) h[i] = ivp[i];

  for (i = 0;i < 64;++i) padded[i] = kpad[i] ^ 0x36;

  blocks(h,padded,64);
  blocks(h,in,inlen);
  in += inlen;
  inlen &= 63;
  in -= inlen;

  for (i = 0;i < inlen;++i) padded[i] = in[i];
  padded[inlen] = 0x80;

  if (inlen < 56) {
    for (i = inlen + 1;i < 56;++i) padded[i] = 0;
    padded[56] = bits >> 56;
    padded[57] = bits >> 48;
    padded[58] = bits >> 40;
    padded[59] = bits >> 32;
    padded[60] = bits >> 24;
    padded[61] = bits >> 16;
    padded[62] = bits >> 8;
    padded[63] = bits;
    blocks(h,padded,64);
  } else {
    for (i = inlen + 1;i < 120;++i) padded[i] = 0;
    padded[120] = bits >> 56;
    padded[121] = bits >> 48;
    padded[122] = bits >> 40;
    padded[123] = bits >> 32;
    padded[124] = bits >> 24;
    padded[125] = bits >> 16;
    padded[126] = bits >> 8;
    padded[127] = bits;
    blocks(h,padded,128);
  }

  for (i = 0;i < 64;++i) padded[i] = kpad[i] ^ 0x5c;

  /* Only hashlen bytes of the inner result exist, so the outer message is
     64 + hashlen bytes long and the padding starts right behind it. */
  for (i = 0;i < hashlen;++i) padded[64 + i] = h[i];
  padded[64 + hashlen] = 0x80;
  for (i = hashlen + 1;i < 56;++i) padded[64 + i] = 0;
  padded[64 + 56] = obits >> 56;
  padded[64 + 57] = obits >> 48;
  padded[64 + 58] = obits >> 40;
  padded[64 + 59] = obits >> 32;
  padded[64 + 60] = obits >> 24;
  padded[64 + 61] = obits >> 16;
  padded[64 + 62] = obits >> 8;
  padded[64 + 63] = obits;

  for (i = 0;i < 32;++i) h[i] = ivp[i];
  blocks(h,padded,128);

  for (i = 0;i < outlen;++i) out[i] = h[i];

  return 0;
}

/*
 * SHA-224 itself, needed for the key preparation of RFC 2104: a key longer
 * than the block size is replaced by its hash under the SAME hash the HMAC
 * uses, so HMAC-SHA-224 has to shorten with SHA-224 and not with SHA-256.
 * It lives here because this is where the initial state already is.
 */

int crypto_hash_sha224_ref(unsigned char *out,const unsigned char *in,unsigned long long inlen)
{
  unsigned char h[32];
  unsigned char padded[128];
  int i;
  unsigned long long bits = inlen << 3;

  for (i = 0;i < 32;++i) h[i] = iv224[i];

  blocks(h,in,inlen);
  in += inlen;
  inlen &= 63;
  in -= inlen;

  for (i = 0;i < inlen;++i) padded[i] = in[i];
  padded[inlen] = 0x80;

  if (inlen < 56) {
    for (i = inlen + 1;i < 56;++i) padded[i] = 0;
    padded[56] = bits >> 56;
    padded[57] = bits >> 48;
    padded[58] = bits >> 40;
    padded[59] = bits >> 32;
    padded[60] = bits >> 24;
    padded[61] = bits >> 16;
    padded[62] = bits >> 8;
    padded[63] = bits;
    blocks(h,padded,64);
  } else {
    for (i = inlen + 1;i < 120;++i) padded[i] = 0;
    padded[120] = bits >> 56;
    padded[121] = bits >> 48;
    padded[122] = bits >> 40;
    padded[123] = bits >> 32;
    padded[124] = bits >> 24;
    padded[125] = bits >> 16;
    padded[126] = bits >> 8;
    padded[127] = bits;
    blocks(h,padded,128);
  }

  for (i = 0;i < crypto_auth_hmacsha224_BYTES;++i) out[i] = h[i];

  return 0;
}

int crypto_auth_hmacsha256_ref_kpad(unsigned char *out,const unsigned char *in,unsigned long long inlen,const unsigned char *kpad)
{
  return hmacsha2(out,crypto_auth_hmacsha256_BYTES,iv256,32,in,inlen,kpad);
}

int crypto_auth_hmacsha224_ref_kpad(unsigned char *out,const unsigned char *in,unsigned long long inlen,const unsigned char *kpad)
{
  return hmacsha2(out,crypto_auth_hmacsha224_BYTES,iv224,28,in,inlen,kpad);
}

/*
 * The NaCl interface takes a key of exactly crypto_auth_KEYBYTES, which is
 * the zero padded block of the same key.
 */

int crypto_auth_hmacsha256_ref(unsigned char *out,const unsigned char *in,unsigned long long inlen,const unsigned char *k)
{
  unsigned char kpad[64];
  int i;

  for (i = 0;i < 32;++i) kpad[i] = k[i];
  for (i = 32;i < 64;++i) kpad[i] = 0;

  return crypto_auth_hmacsha256_ref_kpad(out,in,inlen,kpad);
}

//#include "crypto_verify_32.h"
//#include "crypto_auth.h"

int crypto_auth_hmacsha256_ref_kpad_verify(const unsigned char *h,const unsigned char *in,unsigned long long inlen,const unsigned char *kpad)
{
  unsigned char correct[32];
  crypto_auth_hmacsha256_ref_kpad(correct,in,inlen,kpad);
  return crypto_verify_32(h,correct);
}

/*
 * 28 bytes are covered by two overlapping crypto_verify_16, bytes 0 to 15
 * and 12 to 27. Both calls always run and the bitwise or keeps the -1 of
 * either, so the running time stays independent of where a difference is.
 */

int crypto_auth_hmacsha224_ref_kpad_verify(const unsigned char *h,const unsigned char *in,unsigned long long inlen,const unsigned char *kpad)
{
  unsigned char correct[crypto_auth_hmacsha224_BYTES];
  crypto_auth_hmacsha224_ref_kpad(correct,in,inlen,kpad);
  return crypto_verify_16(h,correct) | crypto_verify_16(h + 12,correct + 12);
}

int crypto_auth_hmacsha256_ref_verify(const unsigned char *h,const unsigned char *in,unsigned long long inlen,const unsigned char *k)
{
  unsigned char correct[32];
  crypto_auth_hmacsha256_ref(correct,in,inlen,k);
  return crypto_verify_32(h,correct);
}
