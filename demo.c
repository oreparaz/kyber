#include "kyber.h"

#include <stdio.h>
#include <string.h>

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <unistd.h>
#include <sys/syscall.h>

#define NTESTS 1000

// you need to provide this function
void rnd(uint8_t *out, size_t outlen) {

  static int fd = -1;
  ssize_t ret;

  while(fd == -1) {
    fd = open("/dev/urandom", O_RDONLY);
    if(fd == -1 && errno == EINTR)
      continue;
    else if(fd == -1)
      abort();
  }

  while(outlen > 0) {
    ret = read(fd, out, outlen);
    if(ret == -1 && errno == EINTR)
      continue;
    else if(ret == -1)
      abort();

    out += ret;
    outlen -= ret;
  }
}

static int test_keys(void)
{
  uint8_t pk[CRYPTO_PUBLICKEYBYTES];
  uint8_t sk[CRYPTO_SECRETKEYBYTES];
  uint8_t ct[CRYPTO_CIPHERTEXTBYTES];
  uint8_t key_a[CRYPTO_BYTES];
  uint8_t key_b[CRYPTO_BYTES];

  //Alice generates a public key
  crypto_kem_keypair(pk, sk, rnd);

  //Bob derives a secret key and creates a response
  crypto_kem_enc(ct, key_b, pk, rnd);

  //Alice uses Bobs response to get her shared key
  crypto_kem_dec(key_a, ct, sk);

  if (memcmp(key_a, key_b, CRYPTO_BYTES)) {
    printf("ERROR keys\n");
    return 1;
  }

  return 0;
}

static int test_invalid_sk_a(void)
{
  uint8_t pk[CRYPTO_PUBLICKEYBYTES];
  uint8_t sk[CRYPTO_SECRETKEYBYTES];
  uint8_t ct[CRYPTO_CIPHERTEXTBYTES];
  uint8_t key_a[CRYPTO_BYTES];
  uint8_t key_b[CRYPTO_BYTES];

  //Alice generates a public key
  crypto_kem_keypair(pk, sk, rnd);

  //Bob derives a secret key and creates a response
  crypto_kem_enc(ct, key_b, pk, rnd);

  //Replace secret key with random values
  rnd(sk, CRYPTO_SECRETKEYBYTES);

  //Alice uses Bobs response to get her shared key
  crypto_kem_dec(key_a, ct, sk);

  if (!memcmp(key_a, key_b, CRYPTO_BYTES)) {
    printf("ERROR invalid sk\n");
    return 1;
  }

  return 0;
}

static int test_invalid_ciphertext(void)
{
  uint8_t pk[CRYPTO_PUBLICKEYBYTES];
  uint8_t sk[CRYPTO_SECRETKEYBYTES];
  uint8_t ct[CRYPTO_CIPHERTEXTBYTES];
  uint8_t key_a[CRYPTO_BYTES];
  uint8_t key_b[CRYPTO_BYTES];
  uint8_t b;
  size_t pos;

  do {
    rnd(&b, sizeof(uint8_t));
  } while(!b);
  rnd((uint8_t *)&pos, sizeof(size_t));

  //Alice generates a public key
  crypto_kem_keypair(pk, sk, rnd);

  //Bob derives a secret key and creates a response
  crypto_kem_enc(ct, key_b, pk, rnd);

  //Change some byte in the ciphertext (i.e., encapsulated key)
  ct[pos % CRYPTO_CIPHERTEXTBYTES] ^= b;

  //Alice uses Bobs response to get her shared key
  crypto_kem_dec(key_a, ct, sk);

  if (!memcmp(key_a, key_b, CRYPTO_BYTES)) {
    printf("ERROR invalid ciphertext\n");
    return 1;
  }

  return 0;
}

static int test_kex(void)
{
  uint8_t pkb[CRYPTO_PUBLICKEYBYTES];
  uint8_t skb[CRYPTO_SECRETKEYBYTES];

  uint8_t pka[CRYPTO_PUBLICKEYBYTES];
  uint8_t ska[CRYPTO_SECRETKEYBYTES];

  uint8_t eska[CRYPTO_SECRETKEYBYTES];

  uint8_t uake_senda[KEX_UAKE_SENDABYTES];
  uint8_t uake_sendb[KEX_UAKE_SENDBBYTES];

  uint8_t ake_senda[KEX_AKE_SENDABYTES];
  uint8_t ake_sendb[KEX_AKE_SENDBBYTES];

  uint8_t tk[KEX_SSBYTES];
  uint8_t ka[KEX_SSBYTES];
  uint8_t kb[KEX_SSBYTES];
  uint8_t zero[KEX_SSBYTES];
  int i;

  for(i=0;i<KEX_SSBYTES;i++)
    zero[i] = 0;

  crypto_kem_keypair(pkb, skb, rnd); // Generate static key for Bob
  crypto_kem_keypair(pka, ska, rnd); // Generate static key for Alice

  // Perform unilaterally authenticated key exchange
  kex_uake_initA(uake_senda, tk, eska, pkb, rnd); // Run by Alice
  kex_uake_sharedB(uake_sendb, kb, uake_senda, skb, rnd); // Run by Bob
  kex_uake_sharedA(ka, uake_sendb, tk, eska); // Run by Alice

  if (memcmp(ka,kb,KEX_SSBYTES)) {
    printf("Error in UAKE\n");
    return 1;
  }

  if (!memcmp(ka,zero,KEX_SSBYTES)) {
    printf("Error: UAKE produces zero key\n");
    return 1;
  }

  // Perform mutually authenticated key exchange
  kex_ake_initA(ake_senda, tk, eska, pkb, rnd); // Run by Alice
  kex_ake_sharedB(ake_sendb, kb, ake_senda, skb, pka, rnd); // Run by Bob
  kex_ake_sharedA(ka, ake_sendb, tk, eska, ska); // Run by Alice

  if (memcmp(ka,kb,KEX_SSBYTES)) {
    printf("Error in AKE\n");
    return 1;
  }

  if (!memcmp(ka,zero,KEX_SSBYTES)) {
    printf("Error: AKE produces zero key\n");
    return 1;
  }

  printf("KEX_UAKE_SENDABYTES: %d\n",KEX_UAKE_SENDABYTES);
  printf("KEX_UAKE_SENDBBYTES: %d\n",KEX_UAKE_SENDBBYTES);

  printf("KEX_AKE_SENDABYTES: %d\n",KEX_AKE_SENDABYTES);
  printf("KEX_AKE_SENDBBYTES: %d\n",KEX_AKE_SENDBBYTES);

  return 0;
}


int main(void)
{
  unsigned int i;
  int r;

  for(i=0;i<NTESTS;i++) {
    r  = test_keys();
    r |= test_invalid_sk_a();
    r |= test_invalid_ciphertext();
    if (r) {
      return 1;
    }
  }

  printf("CRYPTO_SECRETKEYBYTES:  %d\n",CRYPTO_SECRETKEYBYTES);
  printf("CRYPTO_PUBLICKEYBYTES:  %d\n",CRYPTO_PUBLICKEYBYTES);
  printf("CRYPTO_CIPHERTEXTBYTES: %d\n",CRYPTO_CIPHERTEXTBYTES);

  r = test_kex();
  if (r) {
    return 1;
  }

  return 0;
}
