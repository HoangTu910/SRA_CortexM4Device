#include "constants.h"
#include "encrypt.h"

int crypto_aead_encrypt(unsigned char *ciphertext, unsigned long long *ciphertext_len,
					  const unsigned char *message, unsigned long long message_len,
					  const unsigned char *associated_data, unsigned long long associated_data_len,
					  const unsigned char *nsec, const unsigned char *nonce,
					  const unsigned char *key)
{
	ascon_state_t state;
	(void)nsec;

	// set ciphertext size
	*ciphertext_len = message_len + CRYPTO_ABYTES;
	ascon_core(&state, ciphertext, message, message_len, associated_data, associated_data_len, nonce, key, ASCON_ENC);
	// get tag
	int i;
	for (i = 0; i < CRYPTO_ABYTES; ++i)
	  ciphertext[message_len + i] = *(state.b[3] + i);
	return 0;
}
