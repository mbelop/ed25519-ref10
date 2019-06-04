// Copyright (c) 2017-2019 isis agora lovecruft. All rights reserved.
// Copyright (c) 2019 Mike Belopuhov. All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
// 1. Redistributions of source code must retain the above copyright
// notice, this list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright
// notice, this list of conditions and the following disclaimer in the
// documentation and/or other materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its
// contributors may be used to endorse or promote products derived from
// this software without specific prior written permission.

// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
// IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
// TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
// PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
// TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
// PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
// LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
// NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


extern crate libc;

use std::fmt;

use libc::{c_int, c_uchar, c_ulonglong};

pub const SECRET_KEY_LENGTH: usize = 32;
pub const PUBLIC_KEY_LENGTH: usize = 32;
pub const KEYPAIR_LENGTH: usize = SECRET_KEY_LENGTH + PUBLIC_KEY_LENGTH;
pub const SIGNATURE_LENGTH: usize = 64;

#[derive(Default)]
pub struct SecretKey(pub(crate) [u8; SECRET_KEY_LENGTH]);

impl SecretKey {
    #[inline]
    pub fn to_bytes(&self) -> [u8; SECRET_KEY_LENGTH] {
        self.0
    }

    #[inline]
    pub fn as_bytes<'a>(&'a self) -> &'a [u8; SECRET_KEY_LENGTH] {
        &self.0
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<SecretKey, SignatureError> {
        if bytes.len() != SECRET_KEY_LENGTH {
            return Err(SignatureError::BytesLengthError {
                name: "SecretKey",
                length: SECRET_KEY_LENGTH,
            });
        }
        let mut buf: [u8; SECRET_KEY_LENGTH] = [0u8; SECRET_KEY_LENGTH];
        buf.copy_from_slice(bytes);
        Ok(SecretKey(buf))
    }
}

impl AsRef<[u8]> for SecretKey {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretKey({:02x?})", &self.0[..])
    }
}

#[derive(Default)]
pub struct PublicKey(pub(crate) [u8; PUBLIC_KEY_LENGTH]);

impl PublicKey {
    #[inline]
    pub fn to_bytes(&self) -> [u8; PUBLIC_KEY_LENGTH] {
        self.0
    }

    #[inline]
    pub fn as_bytes<'a>(&'a self) -> &'a [u8; PUBLIC_KEY_LENGTH] {
        &self.0
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<PublicKey, SignatureError> {
        if bytes.len() != PUBLIC_KEY_LENGTH {
            return Err(SignatureError::BytesLengthError {
                name: "PublicKey",
                length: PUBLIC_KEY_LENGTH,
            });
        }
        let mut buf: [u8; PUBLIC_KEY_LENGTH] = [0u8; PUBLIC_KEY_LENGTH];
        buf.copy_from_slice(bytes);
        Ok(PublicKey(buf))
    }
}

impl AsRef<[u8]> for PublicKey {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PublicKey({:02x?})", &self.0[..])
    }
}

impl From<&SecretKey> for PublicKey {
    fn from(sk: &SecretKey) -> PublicKey {
        let mut pk: [u8; PUBLIC_KEY_LENGTH] = [0u8; PUBLIC_KEY_LENGTH];

        unsafe {
            assert_eq!(
                crypto_sign_pubkey(
                    &mut pk as *mut _ as *mut u8,
                    sk.as_bytes() as *const u8,
                ),
                0
            );
        }
        PublicKey(pk)
    }
}

#[derive(Debug, Default)]
pub struct Keypair {
    secret: SecretKey,
    public: PublicKey,
}

impl Keypair {
    #[inline]
    pub fn to_bytes(&self) -> [u8; KEYPAIR_LENGTH] {
        let mut buf: [u8; KEYPAIR_LENGTH] = [0u8; KEYPAIR_LENGTH];

        buf[..SECRET_KEY_LENGTH].copy_from_slice(self.secret.as_bytes());
        buf[SECRET_KEY_LENGTH..].copy_from_slice(self.public.as_bytes());
        buf
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Keypair, SignatureError> {
        if bytes.len() != KEYPAIR_LENGTH {
            return Err(SignatureError::BytesLengthError {
                name: "Keypair",
                length: KEYPAIR_LENGTH,
            });
        }

        let secret = SecretKey::from_bytes(&bytes[..SECRET_KEY_LENGTH])?;
        let public = PublicKey::from_bytes(&bytes[SECRET_KEY_LENGTH..])?;

        Ok(Keypair { secret, public })
    }

    pub fn generate() -> Result<Keypair, SignatureError> {
        let mut pk: [u8; PUBLIC_KEY_LENGTH] = [0u8; PUBLIC_KEY_LENGTH];
        let mut sk: [u8; KEYPAIR_LENGTH] = [0u8; KEYPAIR_LENGTH];

        unsafe {
            assert_eq!(
                crypto_sign_keypair(
                    &mut pk as *mut _ as *mut u8,
                    &mut sk as *mut _ as *mut u8,
                ),
                0
            );
        }

        Ok(Keypair {
            secret: SecretKey::from_bytes(&sk[..SECRET_KEY_LENGTH])?,
            public: PublicKey(pk),
        })
    }

    pub fn sign(&self, message: &[u8]) -> Signature {
        let mut sm = vec![0u8; SIGNATURE_LENGTH + message.len()];
        let mut smlen: c_ulonglong = 0;

        let sk = self.to_bytes();

        unsafe {
            assert_eq!(
                crypto_sign(
                    sm.as_mut_slice() as *mut _ as *mut u8,
                    &mut smlen as *mut _ as *mut c_ulonglong,
                    message as *const _ as *const u8,
                    message.len() as c_ulonglong,
                    &sk as *const _ as *const u8,
                ),
                0
            );
        }

        let mut s: [u8; SIGNATURE_LENGTH] = [0u8; SIGNATURE_LENGTH];
        s.copy_from_slice(&sm[..SIGNATURE_LENGTH]);
        Signature(s)
    }

    pub fn verify(
        &self,
        message: &[u8],
        signature: &Signature,
    ) -> Result<(), SignatureError> {
        let mut m = vec![0u8; SIGNATURE_LENGTH + message.len()];
        let mut mlen: c_ulonglong = 0;

        let mut sm = vec![0u8; SIGNATURE_LENGTH + message.len()];
        let smlen: c_ulonglong = SIGNATURE_LENGTH as c_ulonglong +
            message.len() as c_ulonglong;
        sm[..SIGNATURE_LENGTH].copy_from_slice(signature.as_bytes());
        sm[SIGNATURE_LENGTH..].copy_from_slice(message);

        let pk = self.public.to_bytes();

        unsafe {
            match crypto_sign_open(
                m.as_mut_slice() as *mut _ as *mut u8,
                &mut mlen as *mut _ as *mut c_ulonglong,
                sm.as_slice() as *const _ as *const u8,
                smlen,
                &pk as *const _ as *const u8,
            ) {
                0 => Ok(()),
                _ => Err(SignatureError::VerifyError),
            }
        }
    }
}

impl From<SecretKey> for Keypair {
    fn from(sk: SecretKey) -> Keypair {
        let public: PublicKey = (&sk).into();
        Keypair { secret: sk, public }
    }
}

pub struct Signature(pub(crate) [u8; SIGNATURE_LENGTH]);

impl Signature {
    #[inline]
    pub fn to_bytes(&self) -> [u8; SIGNATURE_LENGTH] {
        self.0
    }

    #[inline]
    pub fn as_bytes<'a>(&'a self) -> &'a [u8; SIGNATURE_LENGTH] {
        &self.0
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Signature, SignatureError> {
        if bytes.len() != SIGNATURE_LENGTH {
            return Err(SignatureError::BytesLengthError {
                name: "Signature",
                length: SIGNATURE_LENGTH,
            });
        }

        let mut buf: [u8; SIGNATURE_LENGTH] = [0u8; SIGNATURE_LENGTH];
        buf.copy_from_slice(bytes);
        Ok(Signature(buf))
    }
}

impl AsRef<[u8]> for Signature {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Signature({:02x?})", &self.0[..])
    }
}

#[derive(Debug)]
pub enum SignatureError {
    BytesLengthError { name: &'static str, length: usize },
    VerifyError,
}

extern "C" {
    fn crypto_sign(
        sm: *mut c_uchar,
        smlen: *mut c_ulonglong,
        m: *const c_uchar,
        mlen: c_ulonglong,
        sk: *const c_uchar,
    ) -> c_int;

    fn crypto_sign_open(
        m: *mut c_uchar,
        mlen: *mut c_ulonglong,
        sm: *const c_uchar,
        smlen: c_ulonglong,
        pk: *const c_uchar,
    ) -> c_int;

    fn crypto_sign_keypair(pk: *mut c_uchar, sk: *mut c_uchar) -> c_int;

    fn crypto_sign_pubkey(pk: *mut c_uchar, sk: *const c_uchar) -> c_int;
}
