/*
 * 20080913
 * D. J. Bernstein
 * Public domain.
 *
 * HMAC-SHA-512-256, the NaCl crypto_auth primitive: HMAC-SHA-512 with the
 * tag truncated to 32 bytes. The computation itself lives in
 * crypto_auth_hmacsha512.c, which takes the tag length as a parameter, so
 * both primitives share one implementation.
 *
 * */

#include "tweetnacl.h"
#include "crypto_reference.h"

/*
 * kpad holds the key already prepared according to RFC 2104 section 2:
 * hashed if it was longer than the block size, then zero padded to the
 * full block size of 128 bytes.
 */

int crypto_auth_hmacsha512256_ref_kpad(unsigned char *out,const unsigned char *in,unsigned long long inlen,const unsigned char *kpad)
{
  return crypto_auth_hmacsha512_ref_kpad_out(out,32,in,inlen,kpad);
}

/*
 * The NaCl interface takes a key of exactly crypto_auth_KEYBYTES, which is
 * the zero padded block of the same key.
 */

int crypto_auth_hmacsha512256_ref(unsigned char *out,const unsigned char *in,unsigned long long inlen,const unsigned char *k)
{
  unsigned char kpad[crypto_auth_hmacsha512256_BLOCKBYTES];
  int i;

  for (i = 0;i < 32;++i) kpad[i] = k[i];
  for (i = 32;i < crypto_auth_hmacsha512256_BLOCKBYTES;++i) kpad[i] = 0;

  return crypto_auth_hmacsha512256_ref_kpad(out,in,inlen,kpad);
}

int crypto_auth_hmacsha512256_ref_kpad_verify(const unsigned char *h,const unsigned char *in,unsigned long long inlen,const unsigned char *kpad)
{
  unsigned char correct[32];
  crypto_auth_hmacsha512256_ref_kpad(correct,in,inlen,kpad);
  return crypto_verify_32(h,correct);
}

int crypto_auth_hmacsha512256_ref_verify(const unsigned char *h,const unsigned char *in,unsigned long long inlen,const unsigned char *k)
{
  unsigned char correct[32];
  crypto_auth_hmacsha512256_ref(correct,in,inlen,k);
  return crypto_verify_32(h,correct);
}
