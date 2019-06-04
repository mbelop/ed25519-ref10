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


#[cfg(test)]
extern crate hex;
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

        unsafe {
            match crypto_sign_open(
                m.as_mut_slice() as *mut _ as *mut u8,
                &mut mlen as *mut _ as *mut c_ulonglong,
                sm.as_slice() as *const _ as *const u8,
                smlen,
                self.as_bytes() as *const _ as *const u8,
            ) {
                0 => Ok(()),
                _ => Err(SignatureError::VerifyError),
            }
        }
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
        self.public.verify(message, signature)
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

impl fmt::Display for SignatureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            SignatureError::BytesLengthError { name: n, length: l } => {
                write!(f, "{} must be {} bytes in length", n, l)
            }
            SignatureError::VerifyError => {
                write!(f, "Verification equation was not satisfied")
            }
        }
    }
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

#[cfg(test)]
mod tests {
    use hex;

    use super::*;

    struct TestVec {
        sk: &'static str,
        pk: &'static str,
        ms: &'static str,
        sg: &'static str,
    }

    #[test]
    fn test_rfc8032() {
        let tests = vec![
            TestVec {
                sk: "9d61b19deffd5a60ba844af492ec2cc4\
                     4449c5697b326919703bac031cae7f60",
                pk: "d75a980182b10ab7d54bfed3c964073a\
                     0ee172f3daa62325af021a68f707511a",
                ms: "",
                sg: "e5564300c360ac729086e2cc806e828a\
                     84877f1eb8e5d974d873e06522490155\
                     5fb8821590a33bacc61e39701cf9b46b\
                     d25bf5f0595bbe24655141438e7a100b",
            },
            TestVec {
                sk: "4ccd089b28ff96da9db6c346ec114e0f\
                     5b8a319f35aba624da8cf6ed4fb8a6fb",
                pk: "3d4017c3e843895a92b70aa74d1b7ebc\
                     9c982ccf2ec4968cc0cd55f12af4660c",
                ms: "72",
                sg: "92a009a9f0d4cab8720e820b5f642540\
                     a2b27b5416503f8fb3762223ebdb69da\
                     085ac1e43e15996e458f3613d0f11d8c\
                     387b2eaeb4302aeeb00d291612bb0c00",
            },
            TestVec {
                sk: "f5e5767cf153319517630f226876b86c\
                     8160cc583bc013744c6bf255f5cc0ee5",
                pk: "278117fc144c72340f67d0f2316e8386\
                     ceffbf2b2428c9c51fef7c597f1d426e",
                ms: "08b8b2b733424243760fe426a4b54908\
                     632110a66c2f6591eabd3345e3e4eb98\
                     fa6e264bf09efe12ee50f8f54e9f77b1\
                     e355f6c50544e23fb1433ddf73be84d8\
                     79de7c0046dc4996d9e773f4bc9efe57\
                     38829adb26c81b37c93a1b270b20329d\
                     658675fc6ea534e0810a4432826bf58c\
                     941efb65d57a338bbd2e26640f89ffbc\
                     1a858efcb8550ee3a5e1998bd177e93a\
                     7363c344fe6b199ee5d02e82d522c4fe\
                     ba15452f80288a821a579116ec6dad2b\
                     3b310da903401aa62100ab5d1a36553e\
                     06203b33890cc9b832f79ef80560ccb9\
                     a39ce767967ed628c6ad573cb116dbef\
                     efd75499da96bd68a8a97b928a8bbc10\
                     3b6621fcde2beca1231d206be6cd9ec7\
                     aff6f6c94fcd7204ed3455c68c83f4a4\
                     1da4af2b74ef5c53f1d8ac70bdcb7ed1\
                     85ce81bd84359d44254d95629e9855a9\
                     4a7c1958d1f8ada5d0532ed8a5aa3fb2\
                     d17ba70eb6248e594e1a2297acbbb39d\
                     502f1a8c6eb6f1ce22b3de1a1f40cc24\
                     554119a831a9aad6079cad88425de6bd\
                     e1a9187ebb6092cf67bf2b13fd65f270\
                     88d78b7e883c8759d2c4f5c65adb7553\
                     878ad575f9fad878e80a0c9ba63bcbcc\
                     2732e69485bbc9c90bfbd62481d9089b\
                     eccf80cfe2df16a2cf65bd92dd597b07\
                     07e0917af48bbb75fed413d238f5555a\
                     7a569d80c3414a8d0859dc65a46128ba\
                     b27af87a71314f318c782b23ebfe808b\
                     82b0ce26401d2e22f04d83d1255dc51a\
                     ddd3b75a2b1ae0784504df543af8969b\
                     e3ea7082ff7fc9888c144da2af58429e\
                     c96031dbcad3dad9af0dcbaaaf268cb8\
                     fcffead94f3c7ca495e056a9b47acdb7\
                     51fb73e666c6c655ade8297297d07ad1\
                     ba5e43f1bca32301651339e22904cc8c\
                     42f58c30c04aafdb038dda0847dd988d\
                     cda6f3bfd15c4b4c4525004aa06eeff8\
                     ca61783aacec57fb3d1f92b0fe2fd1a8\
                     5f6724517b65e614ad6808d6f6ee34df\
                     f7310fdc82aebfd904b01e1dc54b2927\
                     094b2db68d6f903b68401adebf5a7e08\
                     d78ff4ef5d63653a65040cf9bfd4aca7\
                     984a74d37145986780fc0b16ac451649\
                     de6188a7dbdf191f64b5fc5e2ab47b57\
                     f7f7276cd419c17a3ca8e1b939ae49e4\
                     88acba6b965610b5480109c8b17b80e1\
                     b7b750dfc7598d5d5011fd2dcc5600a3\
                     2ef5b52a1ecc820e308aa342721aac09\
                     43bf6686b64b2579376504ccc493d97e\
                     6aed3fb0f9cd71a43dd497f01f17c0e2\
                     cb3797aa2a2f256656168e6c496afc5f\
                     b93246f6b1116398a346f1a641f3b041\
                     e989f7914f90cc2c7fff357876e506b5\
                     0d334ba77c225bc307ba537152f3f161\
                     0e4eafe595f6d9d90d11faa933a15ef1\
                     369546868a7f3a45a96768d40fd9d034\
                     12c091c6315cf4fde7cb68606937380d\
                     b2eaaa707b4c4185c32eddcdd306705e\
                     4dc1ffc872eeee475a64dfac86aba41c\
                     0618983f8741c5ef68d3a101e8a3b8ca\
                     c60c905c15fc910840b94c00a0b9d0",
                sg: "0aab4c900501b3e24d7cdf4663326a3a\
                     87df5e4843b2cbdb67cbf6e460fec350\
                     aa5371b1508f9f4528ecea23c436d94b\
                     5e8fcd4f681e30a6ac00a9704a188a03",
            },
            TestVec {
                sk: "833fe62409237b9d62ec77587520911e\
                     9a759cec1d19755b7da901b96dca3d42",
                pk: "ec172b93ad5e563bf4932c70e1245034\
                     c35467ef2efd4d64ebf819683467e2bf",
                ms: "ddaf35a193617abacc417349ae204131\
                     12e6fa4e89a97ea20a9eeee64b55d39a\
                     2192992a274fc1a836ba3c23a3feebbd\
                     454d4423643ce80e2a9ac94fa54ca49f",
                sg: "dc2a4459e7369633a52b1bf277839a00\
                     201009a3efbf3ecb69bea2186c26b589\
                     09351fc9ac90b3ecfdfbc7c66431e030\
                     3dca179c138ac17ad9bef1177331a704",
            },
        ];
        for test in tests {
            let sk = hex::decode(test.sk).unwrap();
            let pk = hex::decode(test.pk).unwrap();
            let ms = hex::decode(test.ms).unwrap_or(Vec::new());
            let sg = hex::decode(test.sg).unwrap();

            let keypair = Keypair {
                secret: SecretKey::from_bytes(&sk).unwrap(),
                public: PublicKey::from_bytes(&pk).unwrap(),
            };

            let expected = Signature::from_bytes(&sg).unwrap();

            let obtained = keypair.sign(&ms);
            assert_eq!(&expected.as_bytes()[..], &obtained.as_bytes()[..]);

            assert!(keypair.verify(&ms, &expected).is_ok());
        }
    }
}
