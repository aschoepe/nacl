/*
 * 20080913
 * D. J. Bernstein
 * Public domain.
 *
 * HMAC-SHA-512 with the full 64 byte tag, and the shared core of the
 * SHA-512 based HMACs. NaCl itself only ships crypto_auth_hmacsha512256,
 * which is this computation truncated to 32 bytes; RFC 7518 HS512 and
 * RFC 4231 need the untruncated result, so the core takes the output
 * length as a parameter and crypto_auth_hmacsha512256.c calls it with 32.
 *
 * */

#include "tweetnacl.h"
#include "crypto_reference.h"

#define blocks crypto_hashblocks_sha512

typedef unsigned long long uint64;

static const unsigned char iv512[64] = {
  0x6a,0x09,0xe6,0x67,0xf3,0xbc,0xc9,0x08,
  0xbb,0x67,0xae,0x85,0x84,0xca,0xa7,0x3b,
  0x3c,0x6e,0xf3,0x72,0xfe,0x94,0xf8,0x2b,
  0xa5,0x4f,0xf5,0x3a,0x5f,0x1d,0x36,0xf1,
  0x51,0x0e,0x52,0x7f,0xad,0xe6,0x82,0xd1,
  0x9b,0x05,0x68,0x8c,0x2b,0x3e,0x6c,0x1f,
  0x1f,0x83,0xd9,0xab,0xfb,0x41,0xbd,0x6b,
  0x5b,0xe0,0xcd,0x19,0x13,0x7e,0x21,0x79
} ;

/*
 * SHA-384 is SHA-512 with a different initial state and the result cut to
 * 48 bytes. FIPS 180-4 section 5.3.4.
 */

static const unsigned char iv384[64] = {
  0xcb,0xbb,0x9d,0x5d,0xc1,0x05,0x9e,0xd8,
  0x62,0x9a,0x29,0x2a,0x36,0x7c,0xd5,0x07,
  0x91,0x59,0x01,0x5a,0x30,0x70,0xdd,0x17,
  0x15,0x2f,0xec,0xd8,0xf7,0x0e,0x59,0x39,
  0x67,0x33,0x26,0x67,0xff,0xc0,0x0b,0x31,
  0x8e,0xb4,0x4a,0x87,0x68,0x58,0x15,0x11,
  0xdb,0x0c,0x2e,0x0d,0x64,0xf9,0x8f,0xa7,
  0x47,0xb5,0x48,0x1d,0xbe,0xfa,0x4f,0xa4
} ;

/*
 * kpad holds the key already prepared according to RFC 2104 section 2:
 * hashed if it was longer than the block size, then zero padded to the
 * full block size of 128 bytes.
 *
 * ivp and hashlen select the hash: the SHA-512 state with 64 bytes of
 * result, or the SHA-384 state with 48. hashlen is what goes into the
 * outer block, so it also decides the length encoded at its end. outlen
 * is how much of the outer state is handed back, at most hashlen, which
 * is how HMAC-SHA-512-256 gets its 32 bytes.
 */

static int hmacsha5(unsigned char *out,int outlen,const unsigned char *ivp,int hashlen,const unsigned char *in,unsigned long long inlen,const unsigned char *kpad)
{
  unsigned char h[64];
  unsigned char padded[256];
  int i;
  unsigned long long bytes = 128 + inlen;
  unsigned long long obytes = 128 + hashlen;

  for (i = 0;i < 64;++i) h[i] = ivp[i];

  for (i = 0;i < 128;++i) padded[i] = kpad[i] ^ 0x36;

  blocks(h,padded,128);
  blocks(h,in,inlen);
  in += inlen;
  inlen &= 127;
  in -= inlen;

  for (i = 0;i < inlen;++i) padded[i] = in[i];
  padded[inlen] = 0x80;

  if (inlen < 112) {
    for (i = inlen + 1;i < 119;++i) padded[i] = 0;
    padded[119] = bytes >> 61;
    padded[120] = bytes >> 53;
    padded[121] = bytes >> 45;
    padded[122] = bytes >> 37;
    padded[123] = bytes >> 29;
    padded[124] = bytes >> 21;
    padded[125] = bytes >> 13;
    padded[126] = bytes >> 5;
    padded[127] = bytes << 3;
    blocks(h,padded,128);
  } else {
    for (i = inlen + 1;i < 247;++i) padded[i] = 0;
    padded[247] = bytes >> 61;
    padded[248] = bytes >> 53;
    padded[249] = bytes >> 45;
    padded[250] = bytes >> 37;
    padded[251] = bytes >> 29;
    padded[252] = bytes >> 21;
    padded[253] = bytes >> 13;
    padded[254] = bytes >> 5;
    padded[255] = bytes << 3;
    blocks(h,padded,256);
  }

  for (i = 0;i < 128;++i) padded[i] = kpad[i] ^ 0x5c;

  /* Only hashlen bytes of the inner result exist, so the outer message is
     128 + hashlen bytes long and the padding starts right behind it. */
  for (i = 0;i < hashlen;++i) padded[128 + i] = h[i];
  padded[128 + hashlen] = 0x80;
  for (i = hashlen + 1;i < 119;++i) padded[128 + i] = 0;
  padded[128 + 119] = obytes >> 61;
  padded[128 + 120] = obytes >> 53;
  padded[128 + 121] = obytes >> 45;
  padded[128 + 122] = obytes >> 37;
  padded[128 + 123] = obytes >> 29;
  padded[128 + 124] = obytes >> 21;
  padded[128 + 125] = obytes >> 13;
  padded[128 + 126] = obytes >> 5;
  padded[128 + 127] = obytes << 3;

  for (i = 0;i < 64;++i) h[i] = ivp[i];
  blocks(h,padded,256);
  for (i = 0;i < outlen;++i) out[i] = h[i];

  return 0;
}

/*
 * SHA-384 itself, needed for the key preparation of RFC 2104: a key longer
 * than the block size is replaced by its hash under the SAME hash the HMAC
 * uses, so HMAC-SHA-384 has to shorten with SHA-384 and not with SHA-512.
 * It lives here because this is where the initial state already is.
 */

int crypto_hash_sha384_ref(unsigned char *out,const unsigned char *in,unsigned long long inlen)
{
  unsigned char h[64];
  unsigned char padded[256];
  int i;
  unsigned long long bytes = inlen;

  for (i = 0;i < 64;++i) h[i] = iv384[i];

  blocks(h,in,inlen);
  in += inlen;
  inlen &= 127;
  in -= inlen;

  for (i = 0;i < inlen;++i) padded[i] = in[i];
  padded[inlen] = 0x80;

  if (inlen < 112) {
    for (i = inlen + 1;i < 119;++i) padded[i] = 0;
    padded[119] = bytes >> 61;
    padded[120] = bytes >> 53;
    padded[121] = bytes >> 45;
    padded[122] = bytes >> 37;
    padded[123] = bytes >> 29;
    padded[124] = bytes >> 21;
    padded[125] = bytes >> 13;
    padded[126] = bytes >> 5;
    padded[127] = bytes << 3;
    blocks(h,padded,128);
  } else {
    for (i = inlen + 1;i < 247;++i) padded[i] = 0;
    padded[247] = bytes >> 61;
    padded[248] = bytes >> 53;
    padded[249] = bytes >> 45;
    padded[250] = bytes >> 37;
    padded[251] = bytes >> 29;
    padded[252] = bytes >> 21;
    padded[253] = bytes >> 13;
    padded[254] = bytes >> 5;
    padded[255] = bytes << 3;
    blocks(h,padded,256);
  }

  for (i = 0;i < crypto_auth_hmacsha384_BYTES;++i) out[i] = h[i];

  return 0;
}

int crypto_auth_hmacsha512_ref_kpad_out(unsigned char *out,int outlen,const unsigned char *in,unsigned long long inlen,const unsigned char *kpad)
{
  return hmacsha5(out,outlen,iv512,64,in,inlen,kpad);
}

int crypto_auth_hmacsha512_ref_kpad(unsigned char *out,const unsigned char *in,unsigned long long inlen,const unsigned char *kpad)
{
  return crypto_auth_hmacsha512_ref_kpad_out(out,crypto_auth_hmacsha512_BYTES,in,inlen,kpad);
}

int crypto_auth_hmacsha384_ref_kpad(unsigned char *out,const unsigned char *in,unsigned long long inlen,const unsigned char *kpad)
{
  return hmacsha5(out,crypto_auth_hmacsha384_BYTES,iv384,48,in,inlen,kpad);
}

/*
 * 48 bytes split cleanly into a crypto_verify_32 and a crypto_verify_16.
 * Both calls always run and the bitwise or keeps the -1 of either, so the
 * running time does not depend on where the first difference sits.
 */

int crypto_auth_hmacsha384_ref_kpad_verify(const unsigned char *h,const unsigned char *in,unsigned long long inlen,const unsigned char *kpad)
{
  unsigned char correct[crypto_auth_hmacsha384_BYTES];
  crypto_auth_hmacsha384_ref_kpad(correct,in,inlen,kpad);
  return crypto_verify_32(h,correct) | crypto_verify_16(h + 32,correct + 32);
}

/*
 * NaCl has no interface for this primitive, so there is no key length it
 * would prescribe. The key is zero padded to the block size, which is what
 * RFC 2104 does with any key shorter than the block.
 */

int crypto_auth_hmacsha512_ref(unsigned char *out,const unsigned char *in,unsigned long long inlen,const unsigned char *k)
{
  unsigned char kpad[crypto_auth_hmacsha512_BLOCKBYTES];
  int i;

  for (i = 0;i < 32;++i) kpad[i] = k[i];
  for (i = 32;i < crypto_auth_hmacsha512_BLOCKBYTES;++i) kpad[i] = 0;

  return crypto_auth_hmacsha512_ref_kpad(out,in,inlen,kpad);
}

/*
 * crypto_verify_32 twice rather than a loop: both halves are always
 * compared, so the running time does not depend on where the first
 * differing byte sits. The bitwise or keeps the -1 of either half.
 */

int crypto_auth_hmacsha512_ref_kpad_verify(const unsigned char *h,const unsigned char *in,unsigned long long inlen,const unsigned char *kpad)
{
  unsigned char correct[crypto_auth_hmacsha512_BYTES];
  crypto_auth_hmacsha512_ref_kpad(correct,in,inlen,kpad);
  return crypto_verify_32(h,correct) | crypto_verify_32(h + 32,correct + 32);
}

int crypto_auth_hmacsha512_ref_verify(const unsigned char *h,const unsigned char *in,unsigned long long inlen,const unsigned char *k)
{
  unsigned char correct[crypto_auth_hmacsha512_BYTES];
  crypto_auth_hmacsha512_ref(correct,in,inlen,k);
  return crypto_verify_32(h,correct) | crypto_verify_32(h + 32,correct + 32);
}
