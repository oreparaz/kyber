/* DO NOT EDIT - THIS FILE WAS AUTOGENERATED */ 
/* generated on 2024-03-31T18:07:33Z         */

/* single-file ref CRYSTALS-Kyber KEM        */
/* source: https://github.com/oreparaz/kyber */


#ifndef API_H
#define API_H

#include <stdint.h>
#include <stddef.h>

#define pqcrystals_kyber512_SECRETKEYBYTES 1632
#define pqcrystals_kyber512_PUBLICKEYBYTES 800
#define pqcrystals_kyber512_CIPHERTEXTBYTES 768
#define pqcrystals_kyber512_BYTES 32

#define pqcrystals_kyber512_ref_SECRETKEYBYTES pqcrystals_kyber512_SECRETKEYBYTES
#define pqcrystals_kyber512_ref_PUBLICKEYBYTES pqcrystals_kyber512_PUBLICKEYBYTES
#define pqcrystals_kyber512_ref_CIPHERTEXTBYTES pqcrystals_kyber512_CIPHERTEXTBYTES
#define pqcrystals_kyber512_ref_BYTES pqcrystals_kyber512_BYTES

int pqcrystals_kyber512_ref_keypair(uint8_t *pk, uint8_t *sk, void (*rnd)(uint8_t *, size_t));
int pqcrystals_kyber512_ref_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk, void (*rnd)(uint8_t *, size_t));
int pqcrystals_kyber512_ref_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

#define pqcrystals_kyber512_90s_ref_SECRETKEYBYTES pqcrystals_kyber512_SECRETKEYBYTES
#define pqcrystals_kyber512_90s_ref_PUBLICKEYBYTES pqcrystals_kyber512_PUBLICKEYBYTES
#define pqcrystals_kyber512_90s_ref_CIPHERTEXTBYTES pqcrystals_kyber512_CIPHERTEXTBYTES
#define pqcrystals_kyber512_90s_ref_BYTES pqcrystals_kyber512_BYTES

int pqcrystals_kyber512_90s_ref_keypair(uint8_t *pk, uint8_t *sk, void (*rnd)(uint8_t *, size_t));
int pqcrystals_kyber512_90s_ref_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk, void (*rnd)(uint8_t *, size_t));
int pqcrystals_kyber512_90s_ref_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

#define pqcrystals_kyber768_SECRETKEYBYTES 2400
#define pqcrystals_kyber768_PUBLICKEYBYTES 1184
#define pqcrystals_kyber768_CIPHERTEXTBYTES 1088
#define pqcrystals_kyber768_BYTES 32

#define pqcrystals_kyber768_ref_SECRETKEYBYTES pqcrystals_kyber768_SECRETKEYBYTES
#define pqcrystals_kyber768_ref_PUBLICKEYBYTES pqcrystals_kyber768_PUBLICKEYBYTES
#define pqcrystals_kyber768_ref_CIPHERTEXTBYTES pqcrystals_kyber768_CIPHERTEXTBYTES
#define pqcrystals_kyber768_ref_BYTES pqcrystals_kyber768_BYTES

int pqcrystals_kyber768_ref_keypair(uint8_t *pk, uint8_t *sk, void (*rnd)(uint8_t *, size_t));
int pqcrystals_kyber768_ref_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk, void (*rnd)(uint8_t *, size_t));
int pqcrystals_kyber768_ref_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

#define pqcrystals_kyber768_90s_ref_SECRETKEYBYTES pqcrystals_kyber768_SECRETKEYBYTES
#define pqcrystals_kyber768_90s_ref_PUBLICKEYBYTES pqcrystals_kyber768_PUBLICKEYBYTES
#define pqcrystals_kyber768_90s_ref_CIPHERTEXTBYTES pqcrystals_kyber768_CIPHERTEXTBYTES
#define pqcrystals_kyber768_90s_ref_BYTES pqcrystals_kyber768_BYTES

int pqcrystals_kyber768_90s_ref_keypair(uint8_t *pk, uint8_t *sk, void (*rnd)(uint8_t *, size_t));
int pqcrystals_kyber768_90s_ref_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk, void (*rnd)(uint8_t *, size_t));
int pqcrystals_kyber768_90s_ref_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

#define pqcrystals_kyber1024_SECRETKEYBYTES 3168
#define pqcrystals_kyber1024_PUBLICKEYBYTES 1568
#define pqcrystals_kyber1024_CIPHERTEXTBYTES 1568
#define pqcrystals_kyber1024_BYTES 32

#define pqcrystals_kyber1024_ref_SECRETKEYBYTES pqcrystals_kyber1024_SECRETKEYBYTES
#define pqcrystals_kyber1024_ref_PUBLICKEYBYTES pqcrystals_kyber1024_PUBLICKEYBYTES
#define pqcrystals_kyber1024_ref_CIPHERTEXTBYTES pqcrystals_kyber1024_CIPHERTEXTBYTES
#define pqcrystals_kyber1024_ref_BYTES pqcrystals_kyber1024_BYTES

int pqcrystals_kyber1024_ref_keypair(uint8_t *pk, uint8_t *sk, void (*rnd)(uint8_t *, size_t));
int pqcrystals_kyber1024_ref_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk, void (*rnd)(uint8_t *, size_t));
int pqcrystals_kyber1024_ref_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

#define pqcrystals_kyber1024_90s_ref_SECRETKEYBYTES pqcrystals_kyber1024_SECRETKEYBYTES
#define pqcrystals_kyber1024_90s_ref_PUBLICKEYBYTES pqcrystals_kyber1024_PUBLICKEYBYTES
#define pqcrystals_kyber1024_90s_ref_CIPHERTEXTBYTES pqcrystals_kyber1024_CIPHERTEXTBYTES
#define pqcrystals_kyber1024_90s_ref_BYTES pqcrystals_kyber1024_BYTES

int pqcrystals_kyber1024_90s_ref_keypair(uint8_t *pk, uint8_t *sk, void (*rnd)(uint8_t *, size_t));
int pqcrystals_kyber1024_90s_ref_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk, void (*rnd)(uint8_t *, size_t));
int pqcrystals_kyber1024_90s_ref_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

#endif
#ifndef PARAMS_H
#define PARAMS_H

#ifndef KYBER_K
#error "need to define KYBER_K in {2,3,4}"
#endif

//#define KYBER_90S	/* Uncomment this if you want the 90S variant */

/* Don't change parameters below this line */
#if   (KYBER_K == 2)
#ifdef KYBER_90S
#define KYBER_NAMESPACE(s) pqcrystals_kyber512_90s_ref_##s
#else
#define KYBER_NAMESPACE(s) pqcrystals_kyber512_ref_##s
#endif
#elif (KYBER_K == 3)
#ifdef KYBER_90S
#define KYBER_NAMESPACE(s) pqcrystals_kyber768_90s_ref_##s
#else
#define KYBER_NAMESPACE(s) pqcrystals_kyber768_ref_##s
#endif
#elif (KYBER_K == 4)
#ifdef KYBER_90S
#define KYBER_NAMESPACE(s) pqcrystals_kyber1024_90s_ref_##s
#else
#define KYBER_NAMESPACE(s) pqcrystals_kyber1024_ref_##s
#endif
#else
#error "KYBER_K must be in {2,3,4}"
#endif

#define KYBER_N 256
#define KYBER_Q 3329

#define KYBER_SYMBYTES 32   /* size in bytes of hashes, and seeds */
#define KYBER_SSBYTES  32   /* size in bytes of shared key */

#define KYBER_POLYBYTES		384
#define KYBER_POLYVECBYTES	(KYBER_K * KYBER_POLYBYTES)

#if KYBER_K == 2
#define KYBER_ETA1 3
#define KYBER_POLYCOMPRESSEDBYTES    128
#define KYBER_POLYVECCOMPRESSEDBYTES (KYBER_K * 320)
#elif KYBER_K == 3
#define KYBER_ETA1 2
#define KYBER_POLYCOMPRESSEDBYTES    128
#define KYBER_POLYVECCOMPRESSEDBYTES (KYBER_K * 320)
#elif KYBER_K == 4
#define KYBER_ETA1 2
#define KYBER_POLYCOMPRESSEDBYTES    160
#define KYBER_POLYVECCOMPRESSEDBYTES (KYBER_K * 352)
#endif

#define KYBER_ETA2 2

#define KYBER_INDCPA_MSGBYTES       (KYBER_SYMBYTES)
#define KYBER_INDCPA_PUBLICKEYBYTES (KYBER_POLYVECBYTES + KYBER_SYMBYTES)
#define KYBER_INDCPA_SECRETKEYBYTES (KYBER_POLYVECBYTES)
#define KYBER_INDCPA_BYTES          (KYBER_POLYVECCOMPRESSEDBYTES + KYBER_POLYCOMPRESSEDBYTES)

#define KYBER_PUBLICKEYBYTES  (KYBER_INDCPA_PUBLICKEYBYTES)
/* 32 bytes of additional space to save H(pk) */
#define KYBER_SECRETKEYBYTES  (KYBER_INDCPA_SECRETKEYBYTES + KYBER_INDCPA_PUBLICKEYBYTES + 2*KYBER_SYMBYTES)
#define KYBER_CIPHERTEXTBYTES (KYBER_INDCPA_BYTES)

#endif
#ifndef KEM_H
#define KEM_H

#include <stdint.h>
#include <stddef.h>


#define CRYPTO_SECRETKEYBYTES  KYBER_SECRETKEYBYTES
#define CRYPTO_PUBLICKEYBYTES  KYBER_PUBLICKEYBYTES
#define CRYPTO_CIPHERTEXTBYTES KYBER_CIPHERTEXTBYTES
#define CRYPTO_BYTES           KYBER_SSBYTES

#if   (KYBER_K == 2)
#ifdef KYBER_90S
#define CRYPTO_ALGNAME "Kyber512-90s"
#else
#define CRYPTO_ALGNAME "Kyber512"
#endif
#elif (KYBER_K == 3)
#ifdef KYBER_90S
#define CRYPTO_ALGNAME "Kyber768-90s"
#else
#define CRYPTO_ALGNAME "Kyber768"
#endif
#elif (KYBER_K == 4)
#ifdef KYBER_90S
#define CRYPTO_ALGNAME "Kyber1024-90s"
#else
#define CRYPTO_ALGNAME "Kyber1024"
#endif
#endif

#define crypto_kem_keypair KYBER_NAMESPACE(keypair)
int crypto_kem_keypair(uint8_t *pk, uint8_t *sk, void (*rnd)(uint8_t *, size_t));

#define crypto_kem_enc KYBER_NAMESPACE(enc)
int crypto_kem_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk, void (*rnd)(uint8_t *, size_t));

#define crypto_kem_dec KYBER_NAMESPACE(dec)
int crypto_kem_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

#endif
#ifndef KEX_H
#define KEX_H

#include <stdint.h>


#define KEX_UAKE_SENDABYTES (KYBER_PUBLICKEYBYTES + KYBER_CIPHERTEXTBYTES)
#define KEX_UAKE_SENDBBYTES (KYBER_CIPHERTEXTBYTES)

#define KEX_AKE_SENDABYTES (KYBER_PUBLICKEYBYTES + KYBER_CIPHERTEXTBYTES)
#define KEX_AKE_SENDBBYTES (2*KYBER_CIPHERTEXTBYTES)

#define KEX_SSBYTES KYBER_SSBYTES

void kex_uake_initA(uint8_t *send, uint8_t *tk, uint8_t *sk, const uint8_t *pkb, void (*rnd)(uint8_t *, size_t));

void kex_uake_sharedB(uint8_t *send, uint8_t *k, const uint8_t *recv, const uint8_t *skb, void (*rnd)(uint8_t *, size_t));

void kex_uake_sharedA(uint8_t *k, const uint8_t *recv, const uint8_t *tk, const uint8_t *sk);

void kex_ake_initA(uint8_t *send, uint8_t *tk, uint8_t *sk, const uint8_t *pkb, void (*rnd)(uint8_t *, size_t));
void kex_ake_sharedB(uint8_t *send, uint8_t *k, const uint8_t *recv, const uint8_t *skb, const uint8_t *pka, void (*rnd)(uint8_t *, size_t));

void kex_ake_sharedA(uint8_t *k, const uint8_t *recv, const uint8_t *tk, const uint8_t *sk, const uint8_t *ska);

#endif
