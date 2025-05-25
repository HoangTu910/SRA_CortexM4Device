/*
 * armv7_hash.h
 *
 *  Created on: May 25, 2025
 *      Author: Hii
 */

#ifndef INC_ARMV7_HASH_H_
#define INC_ARMV7_HASH_H_

void armv7_derive_session_key(uint8_t* out, uint64_t outlen,
                        const uint8_t* master_key, uint64_t master_key_len,
                        const uint8_t* aad, uint64_t aad_len,
                        uint32_t index);

#endif /* INC_ARMV7_HASH_H_ */
