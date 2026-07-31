# Encrypting config secrets with `nacl::secretbox`

Application pattern: store passwords / API keys in a JSON (or other) config
**encrypted at rest** instead of plaintext, decrypt only at the point of use.
Stack-neutral — any app using the Tcl `nacl` package.

## Scheme (proven)

- **Cipher:** `nacl::secretbox` (xsalsa20 + poly1305, authenticated). The MAC
  makes a wrong key / tampered blob **throw** instead of silently returning
  garbage.
- **Length guard before decrypting:** nonce (24) + MAC (16) = 40 bytes minimum — a shorter/truncated blob must ERROR, or `string range` silently trims garbage instead of warning.
- **Blob format:** a self-describing string, e.g. prefix `enc:` +
  `base64url(nonce(24) || cipher)`. The nonce travels with the blob, so
  decryption needs no separate nonce store.
- **Nonce:** fresh from the CSPRNG per encrypt (`nacl::randombytes secretbox
  -nonce`), never reused.
- **Key:** one 32-byte `boxKey` for all secrets of the app.
- **Runtime:** call `decrypt(blob)` right before use (DB connect, SMTP login),
  keep the plaintext as short-lived as possible, mask it in every log/debug echo.
- **Dual-read:** an `isEnc`-style check → decrypt `enc:` blobs, pass legacy
  plaintext through unchanged. Enables gradual migration.

## Helpers (sketch)

```tcl
proc encrypt {plain key} {
    set nonce [nacl::randombytes secretbox -nonce]
    nacl::secretbox ct $plain $nonce $key
    return "enc:[string map {+ - / _ = {}} [binary encode base64 $nonce$ct]]"
}
proc isEnc {v} { return [string match "enc:*" $v] }
proc decrypt {blob key} {
    set raw [binary decode base64 [string map {- + _ /} [string range $blob 4 end]]]
    set nonce [string range $raw 0 23]
    set ct    [string range $raw 24 end]
    nacl::secretbox open pt $ct $nonce $key   ;# throws on wrong key / tampering
    return $pt
}
```

Provide a CLI tool to produce blobs for the config (`encpw <plaintext>`) plus
`encpw --keygen` for a fresh key, bit-compatible with the runtime decrypt.

## Honesty: where does the key live?

The simplest variant puts the `boxKey` **in the same config file** as the
ciphertexts. That protects against: plaintext in VCS history, plaintext in
logs, accidentally sharing a config snippet, shoulder-surfing. It does **not**
protect against someone who can read the **whole file** — then the security
boundary is just **file access** (permissions, not committing the prod config).

Stronger, if the threat model needs it: keep the key **outside** the config —
env var, systemd credential, or a 0600 file outside the document root **and**
the repo. `encrypt`/`decrypt` stay identical, only the key's origin changes.

Whichever you choose, be explicit about which boundary you're relying on.
