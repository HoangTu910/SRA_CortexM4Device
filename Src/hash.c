#include <string.h>

#include "api.h"
#include "constants.h"
#include "lendian.h"
#include "permutations.h"
#include "printstate.h"

#if ASCON_HASH_BYTES == 32 && ASCON_HASH_ROUNDS == 12
#define IV(i) ASCON_HASH_IV##i
#define PB_START_ROUND 0xf0
#elif ASCON_HASH_BYTES == 32 && ASCON_HASH_ROUNDS == 8
#define IV(i) ASCON_HASHA_IV##i
#define PB_START_ROUND 0xb4
#elif ASCON_HASH_BYTES == 0 && ASCON_HASH_ROUNDS == 12
#define IV(i) ASCON_XOF_IV##i
#define PB_START_ROUND 0xf0
#elif ASCON_HASH_BYTES == 0 && ASCON_HASH_ROUNDS == 8
#define IV(i) ASCON_XOFA_IV##i
#define PB_START_ROUND 0xb4
#endif

#define PA_START_ROUND 0xf0

int crypto_hash(unsigned char* out, const unsigned char* in,
                unsigned long long inlen) {
  ascon_state_t s = {0};
  uint32x2_t tmp;
  unsigned long len = inlen;

  // initialization
#ifdef ASCON_PRINT_STATE
  s = (ascon_state_t){{IV(), 0, 0, 0, 0}};
  printstate("initial value", &s);
  P(&s, PA_START_ROUND);
#else
  s = (ascon_state_t){{IV(0), IV(1), IV(2), IV(3), IV(4)}};
#endif

  while (len >= ASCON_HASH_RATE) {
    tmp.l = ((uint32_t*)in)[0];
    tmp.h = ((uint32_t*)in)[1];
    tmp.x = U64LE(tmp.x);
    s.w[0].h ^= tmp.h;
    s.w[0].l ^= tmp.l;

    P(&s, PB_START_ROUND);

    in += ASCON_HASH_RATE;
    len -= ASCON_HASH_RATE;
  }

  uint8_t* bytes = (uint8_t*)&tmp;
  memset(bytes, 0, sizeof tmp);
  memcpy(bytes, in, len);
  bytes[len] ^= 0x01;

  tmp.x = U64LE(tmp.x);
  s.w[0].h ^= tmp.h;
  s.w[0].l ^= tmp.l;

  P(&s, PA_START_ROUND);

  len = CRYPTO_BYTES;
  while (len > ASCON_HASH_RATE) {
    uint32x2_t tmp0 = s.w[0];
    tmp0.x = U64LE(tmp0.x);
    ((uint32_t*)out)[0] = tmp0.l;
    ((uint32_t*)out)[1] = tmp0.h;

    P(&s, PB_START_ROUND);

    out += ASCON_HASH_RATE;
    len -= ASCON_HASH_RATE;
  }

  tmp = s.w[0];
  tmp.x = U64LE(tmp.x);
  memcpy(out, bytes, len);
  return 0;
}

void derive_session_key(uint8_t* out, uint64_t outlen,
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
  crypto_hash(out, input, pos);
}

