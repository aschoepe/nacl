
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

/*
 * HMAC-SHA-512 with the full 64 byte tag. NaCl has no such primitive -- its
 * crypto_auth is the same computation truncated to 32 bytes -- but RFC 4231
 * and RFC 7518 HS512 are defined on the untruncated result.
 */

#define crypto_auth_hmacsha512_BYTES 64

extern int crypto_auth_hmacsha512_ref(unsigned char *,const unsigned char *,unsigned long long,const unsigned char *);
extern int crypto_auth_hmacsha512_ref_verify(const unsigned char *,const unsigned char *,unsigned long long,const unsigned char *);

/*
 * The _kpad variants take the key already prepared according to RFC 2104
 * section 2, that is zero padded to the full block size of the hash:
 * 64 bytes for SHA-256, 128 bytes for SHA-512.
 */

#define crypto_auth_hmacsha256_BLOCKBYTES 64
#define crypto_auth_hmacsha512256_BLOCKBYTES 128
#define crypto_auth_hmacsha512_BLOCKBYTES 128

extern int crypto_auth_hmacsha256_ref_kpad(unsigned char *,const unsigned char *,unsigned long long,const unsigned char *);
extern int crypto_auth_hmacsha256_ref_kpad_verify(const unsigned char *,const unsigned char *,unsigned long long,const unsigned char *);

extern int crypto_auth_hmacsha512256_ref_kpad(unsigned char *,const unsigned char *,unsigned long long,const unsigned char *);
extern int crypto_auth_hmacsha512256_ref_kpad_verify(const unsigned char *,const unsigned char *,unsigned long long,const unsigned char *);

extern int crypto_auth_hmacsha512_ref_kpad(unsigned char *,const unsigned char *,unsigned long long,const unsigned char *);
extern int crypto_auth_hmacsha512_ref_kpad_verify(const unsigned char *,const unsigned char *,unsigned long long,const unsigned char *);

/*
 * The shared core of both SHA-512 based HMACs: outlen selects the tag
 * length, 64 for HMAC-SHA-512 and 32 for HMAC-SHA-512-256.
 */

extern int crypto_auth_hmacsha512_ref_kpad_out(unsigned char *,int,const unsigned char *,unsigned long long,const unsigned char *);

extern int crypto_hashblocks_sha256_ref(unsigned char *statebytes,const unsigned char *in,unsigned long long inlen);
extern int crypto_hash_sha256_ref(unsigned char *out,const unsigned char *in,unsigned long long inlen);
