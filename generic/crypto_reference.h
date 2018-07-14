
/*
 * crypto_auth_hmacsha256_ref
 * crypto_auth_hmacsha256_ref_verify
 * crypto_auth_hmacsha512256_ref
 * rypto_auth_hmacsha512256_ref_verify
 * crypto_hashblocks_sha256_ref
 * crypto_hash_sha256_ref
 *
 * are not implemented in tweetnacl.
 * include it from nacl reference implementation.
 */

extern int crypto_auth_hmacsha256_ref(unsigned char *,const unsigned char *,unsigned long long,const unsigned char *);
extern int crypto_auth_hmacsha256_ref_verify(const unsigned char *,const unsigned char *,unsigned long long,const unsigned char *);

extern int crypto_auth_hmacsha512256_ref(unsigned char *,const unsigned char *,unsigned long long,const unsigned char *);
extern int crypto_auth_hmacsha512256_ref_verify(const unsigned char *,const unsigned char *,unsigned long long,const unsigned char *);

extern int crypto_hashblocks_sha256_ref(unsigned char *statebytes,const unsigned char *in,unsigned long long inlen);
extern int crypto_hash_sha256_ref(unsigned char *out,const unsigned char *in,unsigned long long inlen);
