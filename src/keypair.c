#include <string.h>
#include "crypto_api.h"
#include "ge.h"

int crypto_sign_keypair(unsigned char *pk,unsigned char *sk)
{
  unsigned char az[64];
  ge_p3 A;

  randombytes(sk,32);
  crypto_hash_sha512(az,sk,32);
  az[0] &= 248;
  az[31] &= 63;
  az[31] |= 64;

  ge_scalarmult_base(&A,az);
  ge_p3_tobytes(pk,&A);

  memmove(sk + 32,pk,32);
  return 0;
}
