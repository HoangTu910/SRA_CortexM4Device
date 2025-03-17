/*
 * Device.c
 *
 *  Created on: Aug 16, 2024
 *      Author: Hii
 */
#include "Device.h"

#define DATA_LEN 4

Frame_t construct_frame(uint8_t heart_rate, uint8_t spo2, uint8_t temperature,
                        uint8_t acceleration, uint16_t dataLen, uint8_t *secret_key) {
    unsigned char ciphertext[DATA_LEN + ASCON_TAG_SIZE];
    unsigned long long ciphertext_len;
    unsigned char message[DATA_LEN] = {heart_rate, spo2, temperature, acceleration};
    unsigned long long message_len = DATA_LEN;
    unsigned char associated_data[ASCON_ASSOCIATED_DATALENGTH] = ASCON_ASSOCIATED_DATA;
    unsigned long long associated_data_len = ASCON_ASSOCIATED_DATALENGTH;
    unsigned char nonce[ASCON_NONCE_SIZE] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x01,
												0x02, 0x03, 0x04, 0x05, 0x01, 0x02,
												0x03, 0x04, 0x05, 0x06};
//    nonce_counter++;
//    memcpy(nonce, &nonce_counter, sizeof(nonce_counter));

//    unsigned char key[ASCON_NONCE_SIZE] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x01,
//                                           0x02, 0x03, 0x04, 0x05, 0x01, 0x02,
//                                           0x03, 0x04, 0x05, 0x06};

    // Construct frame
    Frame_t frame = {0};
    frame.header[0] = H1;
    frame.header[1] = H2;
    memcpy(frame.deviceId, DEVICE_ID, DEVICE_ID_SIZE);
    memcpy(frame.nonce, nonce, ASCON_NONCE_SIZE);
    frame.dataLenght[0] = (uint8_t)(dataLen >> 8);
    frame.dataLenght[1] = (uint8_t)(dataLen & 0xFF);

    // Encrypt data
    if (crypto_aead_encrypt(ciphertext, &ciphertext_len, message, message_len,
                            associated_data, associated_data_len, NULL, nonce, secret_key) != 0) {
        // Error handling (e.g., return an invalid frame)
        frame.header[0] = STATE_ERROR_UNKNOWN;
        return frame;
    }

    memcpy(frame.dataPacket, ciphertext, ciphertext_len);
    frame.trailer[0] = T1;
    frame.trailer[1] = T2;

    // Compute CRC over encrypted data
    uint16_t crc16 = Compute_CRC16(frame.dataPacket, ciphertext_len);
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




