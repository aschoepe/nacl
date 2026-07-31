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

static const char iv[32] = {
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
 * kpad holds the key already prepared according to RFC 2104 section 2:
 * hashed if it was longer than the block size, then zero padded to the
 * full block size of 64 bytes.
 */

int crypto_auth_hmacsha256_ref_kpad(unsigned char *out,const unsigned char *in,unsigned long long inlen,const unsigned char *kpad)
{
  unsigned char h[32];
  unsigned char padded[128];
  int i;
  unsigned long long bits = 512 + (inlen << 3);

  for (i = 0;i < 32;++i) h[i] = iv[i];

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
  for (i = 0;i < 32;++i) padded[64 + i] = h[i];

  for (i = 0;i < 32;++i) out[i] = iv[i];

  for (i = 32;i < 64;++i) padded[64 + i] = 0;
  padded[64 + 32] = 0x80;
  padded[64 + 62] = 3;

  blocks(out,padded,128);

  return 0;
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

int crypto_auth_hmacsha256_ref_verify(const unsigned char *h,const unsigned char *in,unsigned long long inlen,const unsigned char *k)
{
  unsigned char correct[32];
  crypto_auth_hmacsha256_ref(correct,in,inlen,k);
  return crypto_verify_32(h,correct);
}
