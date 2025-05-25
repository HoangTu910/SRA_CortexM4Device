/*
 * Device.c
 *
 *  Created on: Aug 16, 2024
 *      Author: Hii
 */
#include "Device.h"

#define DATA_LEN 4

void xor_permute(uint8_t *array, size_t size) {
	static int seeded = 0;
	if (!seeded) {
		srand((unsigned int)time(NULL));
		seeded = 1;
	}
    uint8_t key = (uint8_t)(rand());
    for (size_t i = 0; i < size; i++) {
        array[i] ^= key;
        key = (key << 1) | (key >> 7); // Rotate key
    }
}

Frame_t construct_frame(uint8_t heart_rate, uint8_t spo2, uint8_t temperature,
                        uint8_t acceleration, uint16_t dataLen_param, uint8_t *secret_key, uint8_t *aad, uint16_t aad_length) {
    unsigned char ciphertext[DATA_LEN + ASCON_TAG_SIZE];
    unsigned long long ciphertext_len;
    unsigned char message[DATA_LEN] = {heart_rate, spo2, temperature, acceleration};
    unsigned long long message_len = DATA_LEN;
    unsigned long long associated_data_len = 5;
    unsigned char nonce[ASCON_NONCE_SIZE] = {
        0xA3, 0x5F, 0x91, 0x0D, 0xE7, 0x4C,
        0x2B, 0xD8, 0x39, 0xFA, 0x6E, 0x12,
        0xC4, 0x87, 0x5D, 0x3A
    };

    xor_permute(nonce, sizeof(nonce));

    // Construct frame
    Frame_t frame = {0};
    frame.header[0] = H1;
    frame.header[1] = H2;
    memcpy(frame.deviceId, DEVICE_ID, DEVICE_ID_SIZE);
    memcpy(frame.nonce, nonce, ASCON_NONCE_SIZE);

    // Encrypt data
    if (armv7_crypto_aead_encrypt(ciphertext, &ciphertext_len, message, message_len,
                            aad, associated_data_len, NULL, nonce, secret_key) != 0) {
        frame.header[0] = STATE_ERROR_UNKNOWN;
        return frame;
    }

    size_t encrypted_data_length = ciphertext_len;
    frame.data_length[0] = (uint8_t)(encrypted_data_length >> 8);
    frame.data_length[1] = (uint8_t)(encrypted_data_length & 0xFF);
    memcpy(frame.data_packet, ciphertext, encrypted_data_length);
    memcpy(frame.auth_tag, ciphertext + (encrypted_data_length - AUTH_TAG_SIZE), AUTH_TAG_SIZE);
    frame.trailer[0] = T1;
    frame.trailer[1] = T2;

    uint8_t *crc_start = (uint8_t *)frame.data_packet;
    uint16_t crc16 = Compute_CRC16(crc_start, encrypted_data_length);
    frame.crc[0] = (uint8_t)(crc16 >> 8);
    frame.crc[1] = (uint8_t)(crc16 & 0xFF);

    return frame;
}

uint16_t Compute_CRC16(uint8_t *bytes, int32_t BYTES_LEN) {
    uint16_t crc = 0xFFFF;
    for (int32_t i = 0; i < BYTES_LEN; i++) {
        crc ^= (uint16_t)bytes[i] << 8;
        for (uint8_t j = 0; j < 8; j++) {
            if (crc & 0x8000) {
                crc = (crc << 1) ^ 0x1021;  // CRC polynomial
            } else {
                crc <<= 1;
            }
        }
    }
    return crc;
}




