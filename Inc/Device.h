/*
 * DESIoT_device.h
 *
 *  Created on: Jun 20, 2023
 *      Author: ADMIN
 */

#ifndef INC_DESIOT_DEVICE_H_
#define INC_DESIOT_DEVICE_H_

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "encrypt.h"
#include "decrypt.h"

// attributes
#define ATT_PACKED __attribute__ ((__packed__))
#define ATT_UNUSED __attribute__((__unused__))
#define ATT_WEAK __attribute__((weak))

// macros for status management
#define SET_FRAME_FAILED_STATUS(status) (status--)
#define SET_FRAME_SUCCESS_STATUS(status) (status -= 2)
#define IS_FRAME_ON_PROCESS_STATUS(status) ((status != FRAME_IDLE) && !(status % 3))
#define TIMEOUT_DURATION 2000
#define RX_BUFFER_SIZE 128
#define SECRET_KEY_SIZE 64
#define NONCE_SIZE 16
#define AAD_SIZE 2

#define H1 0xAB
#define H2 0xCD
#define T1 0xE1
#define T2 0xE2
#define ERROR_ENCRYPT 0x00

#define COMMAND_SYN 0x01
#define COMMAND_SYN_ACK 0x02
#define COMMAND_ACK 0x03

#define ERROR_COMMAND 404
#define MAX_DATA_LEN 256

#define RAW_DATA_SIZE 4

#define HEADER_SIZE 2
#define DEVICE_ID_SIZE 4
#define AAD_SIZE 5
#define SOF_SIZE 2
#define AAD_MAX_SIZE_LEN 2
#define AAD_MAX_SIZE 5
#define SECRET_KEY_MAX_SIZE_LEN 2
#define EOF_SIZE 2
#define DATA_BYTE_LENGTH 2
#define AUTH_TAG_SIZE 16
#define DATA_PACKET_SIZE RAW_DATA_SIZE + ASCON_TAG_SIZE
#define TRAILER_SIZE 2
#define CRC_SIZE 2
#define IDENTIFIER_ID_SIZE 4
#define MAX_COUNTER 1000000
#define PRIVATE_GENERATE 8

#define TOTAL_RECEIVE_KEY_FROM_ESP32 114

static const uint8_t DEVICE_ID[] = {0x01, 0x02, 0x03, 0x04};

typedef enum {
	STATE_WAIT_TRIGGER,
	STATE_COLLECT_AND_SEND,
} SystemState_t;

typedef enum {
	STATE_ERROR_UNKNOWN = 0xFF,
	STATE_ERROR_MISMATCH_DATA = 0xFA,
	STATE_ERROR_WRONG_IDENTIFIER = 0xFB,
	STATE_ERROR_HEADER_MISMATCH = 0xDA,
	STATE_ERROR_TRAILER_MISMATCH = 0xDB,
	STATE_ERROR_NONCE_MISMATCH = 0xDC,
	STATE_ERROR_INVALID_AAD_LENGTH = 0xDD,
	STATE_ERROR_INVALID_SECRET_LENGTH = 0xDE,
	STATE_ERROR_DECRYPTION_FAILED = 0xDF

} ErrorState;

#pragma pack(push, 1)  // Force byte alignment
typedef struct {
    uint8_t header[HEADER_SIZE];
    uint8_t deviceId[DEVICE_ID_SIZE];
    uint8_t nonce[ASCON_NONCE_SIZE];
    uint8_t dataLenght[DATA_BYTE_LENGTH];
    uint8_t dataPacket[DATA_PACKET_SIZE];
    uint8_t trailer[TRAILER_SIZE];
    uint8_t crc[CRC_SIZE];
} Frame_t;
#pragma pack(pop)

// CRC calculation functions
uint16_t Compute_CRC16(uint8_t *bytes, const int32_t BYTES_LEN);

//Generate random data
void generate_random_sensor_data(uint8_t *heart_rate, uint8_t *spo2, uint8_t *temperature, uint8_t *acceleration);
Frame_t construct_frame(uint8_t heart_rate, uint8_t spo2, uint8_t temperature, uint8_t acceleration, uint16_t dataLen, uint8_t *secret_key);
void benchmark_encrypt(uint8_t heart_rate, uint8_t spo2, uint8_t temperature, uint8_t acceleration, uint16_t dataLen, uint8_t *secret_key);

#endif /* INC_DESIOT_DEVICE_H_ */
