---
name: nacl
description: >
  Use the Tcl `nacl` package (binding to the NaCl / TweetNaCl crypto library) for
  authenticated public-key encryption (`box`), authenticated secret-key encryption
  (`secretbox`), stream encryption (`stream`), digital signatures (`sign`), HMAC
  authentication (`auth`), Poly1305 one-time authentication (`onetimeauth`),
  Curve25519 scalar multiplication (`scalarmult`), SHA-256/SHA-512 hashing
  (`hash`), and CSPRNG byte generation (`randombytes`). Activate this skill
  whenever a user asks to encrypt, decrypt, sign, verify, MAC, hash, or generate
  random bytes from Tcl and the `nacl` package (`package require nacl`) is or
  should be loaded. All cipher primitives produce binary strings — `binary
  encode hex` / `binary decode hex` are used at the boundaries.
---

# nacl-tcl

> Long form / rationale: [references/config-secrets.md](references/config-secrets.md).

Binding for **NaCl / TweetNaCl** primitives in Tcl. Built and installed from this
repo (`libtcl9nacl1.3.dylib`, `pkgIndex.tcl`). Load with:

```tcl
package require nacl
```

## Universal calling convention

Almost every command follows the same shape:

```
nacl::<primitive> ?subcommand|-option? <outVar> <inputs...>
```

- The **output is written into a caller variable by name** (Tcl upvar style).
- The **return value is `0` on success**, non-zero on failure.
- Therefore the idiomatic pattern is:

  ```tcl
  if {[nacl::secretbox cipher $msg $nonce $key] == 0} {
      # $cipher is now the ciphertext (binary string)
  }
  ```

- All keys, nonces, ciphertexts, signatures, hashes, and MACs are **raw binary
  strings**. Convert at the edges with `binary encode hex` /
  `binary decode hex` (or base64).
- `info` on any primitive returns its byte sizes. `+N` after a label means the
  output is the message length plus N bytes of overhead.

If the user writes hex literals in their script, decode them before passing in:

```tcl
set key   [binary decode hex 1b27...8389]
set nonce [binary decode hex 6969...0b37]
```

## Picking the right primitive

| User wants to…                                              | Use                                 |
|-------------------------------------------------------------|-------------------------------------|
| Encrypt + authenticate **between two parties** (pub/sec)    | `nacl::box`                         |
| Encrypt + authenticate with a **shared symmetric key**      | `nacl::secretbox`                   |
| Encrypt-only stream cipher (no MAC — rarely what they want) | `nacl::stream`                      |
| Sign a message / verify a signature                         | `nacl::sign`                        |
| MAC a message (long-term key)                               | `nacl::auth` (HMAC-SHA-256/512-256) |
| MAC a message with a one-time key                           | `nacl::onetimeauth` (Poly1305)      |
| Hash data                                                   | `nacl::hash` (SHA-256 / SHA-512)    |
| ECDH / shared-secret derivation                             | `nacl::scalarmult`                  |
| Random key / nonce / bytes                                  | `nacl::randombytes`                 |

If a user says "encrypt" without specifying, default to **`secretbox`** for
symmetric and **`box`** for asymmetric — both are AEAD. Do *not* default to
`stream` (it provides confidentiality without integrity).

## Generating randomness (always use this — not Tcl `expr rand()`)

```tcl
nacl::randombytes names          ;# lists available sources
nacl::randombytes source urandom ;# prefer urandom where available
nacl::randombytes 32             ;# 32 random bytes
nacl::randombytes box       -nonce ;# nonce sized for box       (24 B)
nacl::randombytes secretbox -nonce ;# nonce sized for secretbox (24 B)
nacl::randombytes secretbox -key   ;# 32-byte secretbox key
nacl::randombytes stream    -nonce ;# 24 B
nacl::randombytes stream    -key   ;# 32 B
nacl::randombytes auth      -key   ;# 32 B
nacl::randombytes onetimeauth -key ;# 32 B
nacl::randombytes scalarmult -scalar ;# 32 B
nacl::randombytes scalarmult -group  ;# 32 B
```

Recommended preamble at the top of any script that needs randomness:

```tcl
if {[lsearch -exact [nacl::randombytes names] urandom] > -1} {
    nacl::randombytes source urandom
}
```

## Recipes

### 1. Public-key authenticated encryption — `nacl::box`

Algorithm: **curve25519 + xsalsa20 + poly1305**.
Sizes: pub 32, sec 32, nonce 24, ciphertext = |msg| + 16.

```tcl
package require nacl
nacl::box keypair pubA secA
nacl::box keypair pubB secB
set nonce [nacl::randombytes box -nonce]
set msg   "hello bob"

# A → B: encrypt with B's public key + A's secret key
if {[nacl::box ct $msg $nonce $pubB $secA] != 0} { error "encrypt failed" }

# B receives: decrypt with A's public key + B's secret key
if {[nacl::box open pt $ct $nonce $pubA $secB] != 0} { error "decrypt failed" }
puts $pt
```

Nonce rule: **never reuse a (key, nonce) pair**. For long-lived keypairs, draw
the nonce fresh from `nacl::randombytes box -nonce` every encryption, and send it
alongside the ciphertext.

### 2. Secret-key authenticated encryption — `nacl::secretbox`

Algorithm: **xsalsa20 + poly1305**. Sizes: key 32, nonce 24, ct = |msg| + 16.

```tcl
set key   [nacl::randombytes secretbox -key]
set nonce [nacl::randombytes secretbox -nonce]
nacl::secretbox ct $msg $nonce $key
nacl::secretbox open pt $ct $nonce $key
```

> ## TAKE THE MODULE, DON'T REBUILD IT
>
> [references/secretbox-store.tcl](references/secretbox-store.tcl) — encrypt
> secrets at rest (SMTP passwords, API keys, TOTP seeds) as a self-describing
> `enc:base64url(nonce||cipher)` blob. Tested:
> [secretbox-store-test.tcl](references/secretbox-store-test.tcl) (20 assertions,
> `tclsh8.6 secretbox-store-test.tcl`, no server, no DB).
>
> ```tcl
> source secretbox-store.tcl
> set blob [::secretbox::encrypt $plaintext $key]     ;# key = 32 raw bytes, injected
> set pt   [::secretbox::decrypt $blob $key]          ;# throws on wrong key / tampering
> ```
>
> What it already gets right: a **fresh nonce per call** (a fixed one with the
> same key repeats the keystream and voids the encryption), a **`_note` next to
> the encrypted values in the config** naming the format and the CLI tool (the
> person who finds `enc:...` in two years must not have to guess how to produce
> one), the `enc:` marker so
> plaintext and cipher can coexist in one file during a migration, base64url so
> the blob survives JSON/URL/shell unescaped, a length guard (a truncated blob
> errors instead of returning silent garbage), and `newKey` from the platform
> CSPRNG — never hand-rolled randomness.
>
> Note the calling convention it hides: `nacl::secretbox` writes its result into
> a **variable** and returns a status code — using the return value as data
> encrypts the string "0".
>
> Rationale for the storage pattern (dual-read migration, and the honest "where
> does the key live" trade-off): [references/config-secrets.md](references/config-secrets.md).

### 3. Stream cipher (no integrity) — `nacl::stream`

Sizes: key 32, nonce 24, ct = |msg|. **Two forms:**

```tcl
# XOR-style encrypt/decrypt (symmetric — same call decrypts)
nacl::stream ct  $msg $nonce $key
nacl::stream pt  $ct  $nonce $key

# Or generate a raw keystream of length matching $msg
nacl::stream generate ks $nonce $key
```

Reach for `secretbox` instead unless the user explicitly wants a raw stream.

### 4. Signatures — `nacl::sign`

Algorithm: **Ed25519**. Sizes: pub 32, sec 64, signed = |msg| + 64.

```tcl
nacl::sign keypair pub sec
nacl::sign        signed $msg    $sec   ;# attach signature
nacl::sign verify opened $signed $pub   ;# returns 0 + sets opened to $msg
```

`nacl::sign verify` produces the **original message** in the output variable
(the signature has been stripped); the boolean is the return code.

### 5. MAC — `nacl::auth`

HMAC-SHA-256 (`-hmac256`) or HMAC-SHA-512-256 (`-hmac512256`). Tag is 32 B.

```tcl
set key [nacl::randombytes auth -key]
nacl::auth -hmac512256 tag $msg $key
nacl::auth verify -hmac512256 $tag $msg $key   ;# returns 0 if valid
```

Always pass the same algorithm flag to verify as was used to generate.

**The key may have any length.** `nacl::auth` prepares it the way RFC 2104
section 2 requires: longer than the block size of the hash (64 B for
`-hmac256`, 128 B for `-hmac512256`) it is replaced by its hash, shorter it is
padded with zero bytes. So a secret that was not generated here — one the other
side chose, of whatever length — is passed in **as it is**:

```tcl
nacl::auth -hmac256 tag $msg $secret           ;# $secret in its original length
nacl::auth verify -hmac256 $tag $msg $secret
```

Padding or hashing such a secret yourself before the call produces a different
and therefore wrong tag. A key of exactly 32 B behaves as it always did.

`-hmac256` is plain HMAC-SHA-256 and is the one to pick when the other side is
not also `nacl`; `-hmac512256` is the NaCl primitive (HMAC-SHA-512 truncated to
32 B) and is the default of `nacl::auth`.

> ## TAKE THE MODULE, DON'T REBUILD IT
>
> [references/jwt-hs256.tcl](references/jwt-hs256.tcl) — verify a JSON Web Token
> signed with HS256, as one worked example of a MAC whose key comes from the
> other side. Tested:
> [jwt-hs256-test.tcl](references/jwt-hs256-test.tcl) (28 assertions,
> `tclsh8.6 jwt-hs256-test.tcl`, no server, no net).
>
> ```tcl
> source jwt-hs256.tcl
> set payload [::jwt::verify $token $secret]   ;# raw JSON, or throws
> ```
>
> What it gets right and a hand-written check usually does not: the **expected**
> algorithm is passed in and the header checked against it, never the other way
> round — deriving the check from the token is what makes `"alg":"none"` work.
> The signature length is validated before `nacl::auth verify` sees it (a short
> one would otherwise raise a Tcl error instead of being rejected), `exp`/`nbf`
> are enforced, and the secret is used at its original length.
>
> HS256 only. `-hmac512256` is HMAC-SHA-512 truncated to 32 B and is **not** the
> HS512 of RFC 7518, which wants a 64 B tag — emitting one as the other is a
> silent interoperability bug.

### 6. One-time MAC — `nacl::onetimeauth` (Poly1305)

Tag 16 B, key 32 B. **The key must be used for exactly one message** (otherwise
forgery becomes trivial). Use only when you can guarantee that.

```tcl
nacl::onetimeauth         tag  $msg $key
nacl::onetimeauth verify  $tag $msg $key
```

### 7. Hashing — `nacl::hash`

```tcl
nacl::hash -sha256 h $data   ;# 32 B
nacl::hash -sha512 h $data   ;# 64 B
puts [binary encode hex $h]
```

### 8. Scalar multiplication — `nacl::scalarmult`

Curve25519. Use to derive a shared secret from your secret + their public:

```tcl
nacl::scalarmult shared $mySec $theirPub      ;# X25519 ECDH
nacl::scalarmult base   pub    $sec           ;# pub = sec · basepoint
```

The result is a 32-byte curve point — hash it (e.g. with `nacl::hash`) before
using it as a symmetric key.

## Common mistakes to catch

- **Treating the return value as the ciphertext.** It is `0`/non-zero. The
  ciphertext lives in the variable named by `<outVar>`.
- **Forgetting `binary decode hex`** when the user pasted hex into a script —
  Tcl will otherwise pass the hex *string* as if it were the key.
- **Reusing a nonce** across two encryptions under the same key — generate a
  fresh one for every message.
- **Using `nacl::stream` and assuming it's authenticated** — it isn't. Pair it
  with `nacl::auth` or switch to `secretbox` / `box`.
- **Reusing a `onetimeauth` key** across multiple messages — that breaks the
  scheme. Use `nacl::auth` instead.
- **Mixing `-hmac256` and `-hmac512256`** between sign and verify — the verify
  will silently fail.
- **Padding or hashing a MAC key yourself** to reach 32 bytes — `nacl::auth`
  does the RFC 2104 preparation internally, so a key mangled beforehand yields a
  tag that no other implementation agrees with.
- **Comparing MAC tags with `string equal` / `eq`** — that stops at the first
  differing byte and leaks how much was right through its runtime. Use
  `nacl::auth verify`, which compares in constant time.
- **Computing key material from `expr rand()` or `clock seconds`** — always go
  through `nacl::randombytes`.

## Discoverability commands

If unsure about a primitive's parameter sizes at runtime:

```tcl
nacl::info                       ;# package + version metadata
nacl::manifest                   ;# dict: version, date, check-in, build-hash, uuid
nacl::build-info                 ;# "1.3+<check-in uuid>.clang-1700"
nacl::build-info version         ;# "1.3"    (patchlevel, commit, compiler likewise)
nacl::box info                   ;# "cipher+ 16 nonce 24 public-key 32 secret-key 32"
nacl::secretbox info             ;# "cipher+ 16 nonce 24 key 32"
nacl::sign info                  ;# "sign+ 64 public-key 32 secret-key 64"
nacl::hash info                  ;# "sha256 32 sha512 64"
nacl::auth info                  ;# "auth 32 key 32"      (key size, not a limit)
nacl::onetimeauth info           ;# "auth 16 key 32"
nacl::stream info                ;# "cipher+ 0 nonce 24 key 32"
nacl::scalarmult info            ;# "result 32 scalar 32 group 32"
```

## Reference

- Source: the `nacl` TEA-compatible Tcl extension (build from its source tree)
- Built artifact: `libtcl9nacl1.3.dylib` + `pkgIndex.tcl`
- Upstream NaCl docs: see `doc/coolnacl-20120725.pdf`,
  `doc/naclcrypto-20090310.pdf`, `doc/tweetnacl-20140917.pdf`
- Command summary: `doc/help.txt`
- Worked examples: `doc/examples.txt`
- Tests (authoritative API examples): `tests/*.test`
