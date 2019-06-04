# ed25519-ref10
A minimalistic rust wrapper for the ref10 implementation of Ed25519 signatures
extracted from the supercop-20190110 distribution.

## License
This crate uses a public domain implementation of Ed25519 signature scheme by
Peter Schwabe, Daniel J. Bernstein, Niels Duif, Tanja Lange, and Bo-Yin Yang.
Minimal support code was written by Ted Unangst and placed in the public domain
as well. The Rust shim is based on
[ed25519-dalek](https://github.com/dalek-cryptography/ed25519-dalek)
by isis agora lovecruft and retains the same 3-clause BSD copyright.

## Alternatives
This crate borrows a lot from
[ed25519-dalek](https://github.com/dalek-cryptography/ed25519-dalek)
which *should* be used instead of this one.
[sodiumoxide](https://github.com/sodiumoxide/sodiumoxide)
provides an alternative API to the same ref10 implementation from
[libsodium](https://github.com/jedisct1/libsodium).

## Rust compatibility
The aim is to preseve compatibility with older Rust versions (presently 1.29.2
that shipped with OpenBSD 6.4).

## OS compatibility
The support code (`crypto_api.c`) is OpenBSD specific and must be adjusted for
other systems, namely:
  - `arc4random` is used to implement `randombytes`;
  - `timingsafe_bcmp` is used to implement `crypto_verify_32`;
  - SHA512 functions from the OpenBSD libc are used to implement `crypto_hash_sha512`;

## Changes from the original implementation
While care has been taken to avoid any changes, one small function `crypto_sign_pubkey`
was added (via `pubkey.c`). The purpose of this function is to recover a public key
from a secret key that is very useful for the Rust API.
