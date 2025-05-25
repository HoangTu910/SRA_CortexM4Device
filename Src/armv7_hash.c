#include "armv7_api.h"
#include "armv7_ascon.h"
#include "armv7_permutations.h"
#include "armv7_printstate.h"

#if !ASCON_INLINE_MODE
#undef forceinline
#define forceinline
#endif

#ifdef ASCON_HASH_BYTES

#if ASCON_HASH_BYTES == 32 && ASCON_HASH_ROUNDS == 12
#define IV(i) ASCON_HASH_IV##i
#elif ASCON_HASH_BYTES == 32 && ASCON_HASH_ROUNDS == 8
#define IV(i) ASCON_HASHA_IV##i
#elif ASCON_HASH_BYTES == 0 && ASCON_HASH_ROUNDS == 12
#define IV(i) ASCON_XOF_IV##i
#elif ASCON_HASH_BYTES == 0 && ASCON_HASH_ROUNDS == 8
#define IV(i) ASCON_XOFA_IV##i
#endif

forceinline void ascon_inithash(ascon_state_t* s) {
  /* initialize */
#ifdef ASCON_PRINT_STATE
  *s = (ascon_state_t){{IV(), 0, 0, 0, 0}};
  printstate("initial value", s);
  armv7_P(s, 12);
#else
  *s = (ascon_state_t){{IV(0), IV(1), IV(2), IV(3), IV(4)}};
#endif
}

forceinline void ascon_absorb(ascon_state_t* s, const uint8_t* in,
                              uint64_t inlen) {
  /* absorb full plaintext blocks */
  while (inlen >= ASCON_HASH_RATE) {
    s->x[0] ^= LOAD(in, 8);
    armv7_P(s, ASCON_HASH_ROUNDS);
    in += ASCON_HASH_RATE;
    inlen -= ASCON_HASH_RATE;
  }
  /* absorb final plaintext block */
  s->x[0] ^= LOADBYTES(in, inlen);
  s->x[0] ^= PAD(inlen);
}

forceinline void ascon_squeeze(ascon_state_t* s, uint8_t* out,
                               uint64_t outlen) {
  /* squeeze full output blocks */
  armv7_P(s, 12);
  while (outlen > ASCON_HASH_RATE) {
    STORE(out, s->x[0], 8);
    armv7_P(s, ASCON_HASH_ROUNDS);
    out += ASCON_HASH_RATE;
    outlen -= ASCON_HASH_RATE;
  }
  /* squeeze final output block */
  STOREBYTES(out, s->x[0], outlen);
}

int armv7_ascon_xof(uint8_t* out, uint64_t outlen, const uint8_t* in,
              uint64_t inlen) {
  ascon_state_t s;
  ascon_inithash(&s);
  ascon_absorb(&s, in, inlen);
  ascon_squeeze(&s, out, outlen);
  return 0;
}

int armv7_crypto_hash(unsigned char* out, const unsigned char* in,
                unsigned long long inlen) {
  return armv7_ascon_xof(out, CRYPTO_BYTES, in, inlen);
}

void armv7_derive_session_key(uint8_t* out, uint64_t outlen,
                        const uint8_t* master_key, uint64_t master_key_len,
                        const uint8_t* aad, uint64_t aad_len,
                        uint32_t index) {
  uint8_t input[1024];
  size_t pos = 0;

  // Copy master key
  memcpy(input + pos, master_key, master_key_len);
  pos += master_key_len;

  // Copy AAD/context if available
  if (aad != NULL && aad_len > 0) {
    memcpy(input + pos, aad, aad_len);
    pos += aad_len;
  }

  // Append index (big-endian)
  input[pos++] = (index >> 24) & 0xFF;
  input[pos++] = (index >> 16) & 0xFF;
  input[pos++] = (index >> 8) & 0xFF;
  input[pos++] = index & 0xFF;

  // Derive session key using ASCON hash
  armv7_crypto_hash(out, input, pos);
}

#endif
