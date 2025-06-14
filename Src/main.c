/* USER CODE BEGIN Header */
/**
  ******************************************************************************
  * @file           : main.c
  * @brief          : Main program body
  ******************************************************************************
  * @attention
  *
  * Copyright (c) 2024 STMicroelectronics.
  * All rights reserved.
  *
  * This software is licensed under terms that can be found in the LICENSE file
  * in the root directory of this software component.
  * If no LICENSE file comes with this software, it is provided AS-IS.
  *
  ******************************************************************************
  */
/* USER CODE END Header */
/* Includes ------------------------------------------------------------------*/
#include "main.h"
#include "crypto.h"
#include "armv7_hash.h"
#include <stdbool.h>
/* Private includes ----------------------------------------------------------*/
/* USER CODE BEGIN Includes */
#include "Device.h"
/* USER CODE END Includes */

/* Private typedef -----------------------------------------------------------*/
/* USER CODE BEGIN PTD */
#define DATA_LEN 4
#define AES_KEY_SIZE_ 16  // 128-bit key
#define AES_BLOCK_SIZE_ 16

#define AES_GCM_KEY_SIZE      16   // 128-bit key
#define AES_GCM_IV_SIZE       12   // Standard IV size
#define AES_GCM_TAG_SIZE      16   // GCM tag size
#define AES_GCM_AD_SIZE       16   // Associated data size
#define AES_GCM_PLAINTEXT_SIZE 32  // Example plaintext size
#define ASCON_AEAD_RATE
/* USER CODE END PTD */

/* Private define ------------------------------------------------------------*/
/* USER CODE BEGIN PD */

/* USER CODE END PD */

/* Private macro -------------------------------------------------------------*/
/* USER CODE BEGIN PM */

/* USER CODE END PM */

/* Private variables ---------------------------------------------------------*/
UART_HandleTypeDef huart2;

/* USER CODE BEGIN PV */
void resetUART(UART_HandleTypeDef *huart);

/*Mocker for debugging*/
float time_encrypt_us;
float time_frame_construct_session_key_us;
float time_frame_construct_us;
float time_frame_transmit_us;
float time_encrypt_aes_us;
float time_encrypt_armv7_us;
float time_parsing_frame_us;
uint8_t debug = 10;
uint8_t debugIndex = 0;
uint16_t mocker1 = 0;
uint16_t mocker2 = 0;
int mocker3 = 0;
uint8_t mocker4 = 0;
uint8_t mocker5 = 0;
uint8_t mocker6 = 0;
uint8_t mocker7 = 0;
uint8_t mocker8 = 0;
uint8_t mocker9 = 0;
uint8_t mocker10 = 0;
/*Mocker for debugging*/

volatile uint8_t rxByteReceived = 0;
volatile uint32_t rx_index = 0;
volatile uint8_t rx_complete = 0;
uint8_t rx_buffer[TOTAL_RECEIVE_KEY_FROM_ESP32 + 1] = {0};
uint8_t secret_key[SECRET_KEY_SIZE - AUTH_TAG_SIZE];
uint8_t aad_server[AAD_SIZE];
uint16_t aad_length;
uint8_t nonce_for_decrypt[NONCE_SIZE];
uint8_t errorState = STATE_ERROR_UNKNOWN;
volatile uint8_t uart_rx_complete = 0;
SystemState_t state = STATE_WAIT_TRIGGER;
static uint16_t session_key_index = 0;
uint8_t packetType;
uint16_t dataLen = 4;
uint8_t key_aes[AES_KEY_SIZE_] = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
                              0xab, 0xf7, 0x36, 0x28, 0x3e, 0x11, 0x7a, 0xdb };

uint8_t plaintext_aes[AES_BLOCK_SIZE_] = {0x2b, 0x73, 0x15, 0x3e};
uint8_t ciphertext_aes[AES_BLOCK_SIZE_];

uint8_t aes_key[AES_GCM_KEY_SIZE] = {
    0x60, 0x3D, 0xEB, 0x10, 0x15, 0xCA, 0x71, 0xBE,
    0x2B, 0x73, 0xAE, 0xF0, 0x85, 0x7D, 0x77, 0x81
};

uint8_t iv[AES_GCM_IV_SIZE] = { 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x12, 0x34, 0x56, 0x78 };

uint8_t aad[AES_GCM_AD_SIZE] = "Auth Data 12345";
uint8_t tag[AES_GCM_TAG_SIZE];

#define MAX_SESSION_KEYS 65535
/* USER CODE END PV */

/* Private function prototypes -----------------------------------------------*/
void SystemClock_Config(void);
static void MX_GPIO_Init(void);
static void MX_USART2_UART_Init(void);
/* USER CODE BEGIN PFP */
void aes_encrypt();
void aes_gcm_encrypt();
void benchmark_encrypt_aes();
void benchmark_encrypt_armv7(uint8_t heart_rate, uint8_t spo2, uint8_t temperature, uint8_t acceleration, uint16_t dataLen, uint8_t *secret_key);
/* USER CODE END PFP */

/* Private user code ---------------------------------------------------------*/
/* USER CODE BEGIN 0 */
UART_HandleTypeDef huart2;

static void send_error(UART_HandleTypeDef* huart, uint8_t errorState) {
    HAL_UART_Transmit(huart, &errorState, 1, 100); // Giảm timeout từ HAL_MAX_DELAY xuống 100ms
}

static bool check_header(uint8_t* buffer) {
    return (buffer[0] == H1 && buffer[1] == H2);
}

static bool check_trailer(uint8_t* buffer, uint8_t pos1, uint8_t pos2) {
	mocker1 = buffer[pos1];
	mocker2 = buffer[pos2];
    return (buffer[pos1] == T1 && buffer[pos2] == T2);
}

static bool process_initial_packet(uint8_t* buffer) {
    // Calculate offsets based on UartFrameSTM32Init structure
    const size_t packet_type_offset = SOF_SIZE;  
    const size_t identifier_offset = packet_type_offset + 1; 
    const size_t data_offset = identifier_offset + IDENTIFIER_ID_SIZE; 
    
    // Check header first
    if (!check_header(buffer)) {
        send_error(&huart2, STATE_ERROR_HEADER_MISMATCH);
        return false;
    }
    
    // Verify packet type (should be 0x03 for initial packet)
    if (buffer[packet_type_offset] != 0x03) {
        send_error(&huart2, STATE_ERROR_WRONG_PACKET_TYPE);
        return false;
    }
    
    // Verify identifier
    const uint8_t expected_identifier[IDENTIFIER_ID_SIZE] = {0x01, 0x02, 0x03, 0x04};
    if (memcmp(&buffer[identifier_offset], expected_identifier, IDENTIFIER_ID_SIZE) != 0) {
        send_error(&huart2, STATE_ERROR_WRONG_IDENTIFIER);
        return false;
    }
    
    // Extract session_key_index from data field (big-endian)
    session_key_index = (uint16_t)(buffer[data_offset] << 8) | buffer[data_offset + 1];
    session_key_index--;
    // Verify EOF
    const size_t eof_offset = data_offset + AAD_MAX_SIZE;
    if (!check_trailer(buffer, eof_offset, eof_offset + EOF_SIZE - 1)) {
        send_error(&huart2, STATE_ERROR_TRAILER_MISMATCH);
        return false;
    }
    return true;
}

static bool process_trigger_packet(uint8_t* buffer, uint8_t* aad, SystemState_t* state) {
    // Check header first
    if (!check_header(buffer)) {
        send_error(&huart2, STATE_ERROR_HEADER_MISMATCH);
        return false;
    }

    // Calculate offsets based on UartFrameSTM32Trigger structure
    const size_t trigger_offset = SOF_SIZE; 
    const size_t identifier_offset = trigger_offset + 1;
    const size_t aad_len_offset = identifier_offset + IDENTIFIER_ID_SIZE;  
    const size_t aad_offset = aad_len_offset + AAD_MAX_SIZE_LEN;  
    const size_t eof_offset = aad_offset + AAD_MAX_SIZE; 

    // Extract trigger signal
    uint8_t trigger_signal = buffer[trigger_offset];

    // Verify identifier
    const uint8_t expected_identifier[IDENTIFIER_ID_SIZE] = {0x01, 0x02, 0x03, 0x04};
    if (memcmp(&buffer[identifier_offset], expected_identifier, IDENTIFIER_ID_SIZE) != 0) {
        send_error(&huart2, STATE_ERROR_WRONG_IDENTIFIER);
        return false;
    }

    // Get AAD length (little-endian)
    uint16_t aad_len = (uint16_t)buffer[aad_len_offset] |
                      ((uint16_t)buffer[aad_len_offset + 1] << 8);
    if (aad_len > AAD_MAX_SIZE) {
        send_error(&huart2, STATE_ERROR_INVALID_AAD_LENGTH);
        return false;
    }
    aad_length = aad_len;

    // Copy AAD if length > 0
    if (aad_len > 0) {
        memcpy(aad, &buffer[aad_offset], aad_len);
    }

    // Verify EOF
    if (!check_trailer(buffer, eof_offset, eof_offset + EOF_SIZE - 1)) {
        send_error(&huart2, STATE_ERROR_TRAILER_MISMATCH);
        return false;
    }

    // Process data and generate response
    *state = STATE_COLLECT_AND_SEND;

    // Generate sensor data
    uint8_t heart_rate, spo2, temperature, acceleration;
    generate_random_sensor_data(&heart_rate, &spo2, &temperature, &acceleration);

    // Prepare encryption key
    uint8_t encrypt_key[SECRET_KEY_SIZE - AUTH_TAG_SIZE];
    memcpy(encrypt_key, secret_key, SECRET_KEY_SIZE - AUTH_TAG_SIZE);

    // Benchmark encryption
    benchmark_encrypt(heart_rate, spo2, temperature, acceleration,
                     dataLen + ASCON_TAG_SIZE, encrypt_key);

    // Generate session key
    uint8_t session_key[SECRET_KEY_SIZE - AUTH_TAG_SIZE];

    // Measure session key generation time
    uint32_t start_cycles_session = DWT->CYCCNT;
    // Generate new session key
    mocker1 = session_key_index;
    // Update session key index based on packet type
    packetType == 0x01 ? ++session_key_index : session_key_index;
    armv7_derive_session_key(session_key, SECRET_KEY_SIZE - AUTH_TAG_SIZE,
                            encrypt_key, SECRET_KEY_SIZE - AUTH_TAG_SIZE,
                            aad_server, aad_length, session_key_index);
    uint32_t end_cycles_session = DWT->CYCCNT;
    time_frame_construct_session_key_us = (float)(end_cycles_session - start_cycles_session) /
                                        (SystemCoreClock / 1000000.0);
    benchmark_encrypt_aes();

    // Handle session key index overflow
    if (session_key_index >= MAX_SESSION_KEYS) {
        session_key_index = 0;
    }

    // Debug values
    mocker8 = encrypt_key[0];
    mocker9 = encrypt_key[1];

    // Construct and send response frame
    uint32_t start_cycles_f = DWT->CYCCNT;
    Frame_t frame = construct_frame(heart_rate, spo2, temperature, acceleration,
                                  dataLen + ASCON_TAG_SIZE, session_key,
                                  aad_server, aad_length);
    uint32_t end_cycles_f = DWT->CYCCNT;
    time_frame_construct_us = (float)(end_cycles_f - start_cycles_f) /
                             (SystemCoreClock / 1000000.0);

    // Transmit frame
    uint32_t start_cycles_ = DWT->CYCCNT;
    HAL_UART_Transmit(&huart2, (uint8_t*)&frame, sizeof(Frame_t), 100);
    uint32_t end_cycles_ = DWT->CYCCNT;
    time_frame_transmit_us = (float)(end_cycles_ - start_cycles_) /
                            (SystemCoreClock / 1000000.0);

    return true;
}

static bool process_key_exchange_packet(uint8_t* buffer, uint8_t* secret_key, uint8_t* aad, SystemState_t* state) {
	uint32_t start_cycles_ = DWT->CYCCNT;
	const uint8_t expected_identifier[IDENTIFIER_ID_SIZE] = {0x01, 0x02, 0x03, 0x04};
    uint8_t encrypted_secret_key[SECRET_KEY_SIZE];
    uint8_t nonce[NONCE_SIZE];
    uint8_t received_auth_tag[AUTH_TAG_SIZE];
    uint8_t preshared_key[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};

    // Calculate offsets based on the structure
    const size_t identifier_offset = SOF_SIZE + 1;
    const size_t nonce_offset = identifier_offset + IDENTIFIER_ID_SIZE;
    const size_t aad_len_offset = nonce_offset + NONCE_SIZE;
    const size_t aad_offset = aad_len_offset + AAD_MAX_SIZE_LEN;

    // Check identifier
    if (memcmp(&buffer[identifier_offset], expected_identifier, IDENTIFIER_ID_SIZE) != 0) {
        send_error(&huart2, STATE_ERROR_WRONG_IDENTIFIER);
        return false;
    }

    // Copy nonce
    memcpy(nonce, &buffer[nonce_offset], NONCE_SIZE);

    // Get AAD length (little-endian)
    uint16_t aad_len = (uint16_t)(buffer[aad_len_offset] & 0xFF) | ((uint16_t)buffer[aad_len_offset + 1] << 8);
    if (aad_len > AAD_MAX_SIZE) {
        send_error(&huart2, STATE_ERROR_INVALID_AAD_LENGTH);
        return false;
    }

    // Copy AAD
    memcpy(aad, &buffer[aad_offset], aad_len);

    // Calculate secret key length offset and get length
    const size_t secret_len_offset = aad_offset + aad_len;
    uint16_t secret_len = (uint16_t)buffer[secret_len_offset] |
                         (buffer[secret_len_offset + 1] << 8);
    mocker1 = secret_len;
    if (secret_len > SECRET_KEY_SIZE) {
        send_error(&huart2, STATE_ERROR_INVALID_SECRET_LENGTH);
        return false;
    }

    // Copy encrypted secret key and authentication tag
    const size_t secret_offset = secret_len_offset + SECRET_KEY_MAX_SIZE_LEN;
    const size_t auth_tag_offset = secret_offset + secret_len;
    memcpy(encrypted_secret_key, &buffer[secret_offset], secret_len);
    memcpy(received_auth_tag, &buffer[auth_tag_offset], AUTH_TAG_SIZE);

    // Check trailer (EOF)
    const size_t eof_offset = auth_tag_offset + AUTH_TAG_SIZE;
    if (!check_trailer(buffer, eof_offset, eof_offset + EOF_SIZE - 1)) {
        send_error(&huart2, STATE_ERROR_TRAILER_MISMATCH);
        return false;
    }
    uint32_t end_cycles_ = DWT->CYCCNT;
    time_parsing_frame_us = (float)(end_cycles_ - start_cycles_) /
            						(SystemCoreClock / 1000000.0);
    // Decrypt and verify
    unsigned long long decrypted_len;
    int result = crypto_aead_decrypt(
        secret_key,           // Output: decrypted secret key
        &decrypted_len,       // Output: length of decrypted data
		NULL,    			// Output: computed authentication tag
        encrypted_secret_key, // Input: ciphertext
        secret_len,          // Input: ciphertext length
        aad,                 // Input: additional authenticated data
        aad_len,             // Input: AAD length
        nonce,               // Input: nonce (using the parameter instead of nonce_for_decrypt)
        preshared_key        // Input: key
    );
    // Check decryption result and verify authentication tag
    if (result != 0) {
        send_error(&huart2, STATE_ERROR_DECRYPTION_FAILED);
        return false;
    }

    *state = STATE_WAIT_TRIGGER;
    return true;
}

void generate_random_sensor_data(uint8_t *heart_rate, uint8_t *spo2, uint8_t *temperature, uint8_t *acceleration) {
    static int seeded = 0;
    if (!seeded) {
        srand((unsigned int)time(NULL));
        seeded = 1;
    }
    *heart_rate = (uint8_t)(rand() % 100 + 60);
    *spo2 = (uint8_t)(rand() % 10 + 90);
    *temperature = (uint8_t)(rand() % 5 + 35);
    *acceleration = (uint8_t)(rand() % 21);
}

void benchmark_encrypt(uint8_t heart_rate, uint8_t spo2, uint8_t temperature, uint8_t acceleration, uint16_t dataLen, uint8_t *secret_key){
	unsigned char ciphertext[DATA_LEN + ASCON_TAG_SIZE];
	unsigned long long ciphertext_len;
	unsigned char message[DATA_LEN] = {heart_rate, spo2, temperature, acceleration};
	unsigned long long message_len = DATA_LEN;
	unsigned char associated_data[ASCON_ASSOCIATED_DATALENGTH] = ASCON_ASSOCIATED_DATA;
	unsigned long long associated_data_len = ASCON_ASSOCIATED_DATALENGTH;
	unsigned char nonce[ASCON_NONCE_SIZE] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x01,
												0x02, 0x03, 0x04, 0x05, 0x01, 0x02,
												0x03, 0x04, 0x05, 0x06};
	uint32_t start_cycles = DWT->CYCCNT;
	armv7_crypto_aead_encrypt(ciphertext, &ciphertext_len, message, message_len, associated_data, associated_data_len, NULL, nonce, secret_key);
	uint32_t end_cycles = DWT->CYCCNT;
	uint32_t cycles = end_cycles - start_cycles;
	time_encrypt_us = (float)cycles / (SystemCoreClock / 1000000.0);
}

void benchmark_encrypt_aes(){
	uint32_t start_cycles = DWT->CYCCNT;
	aes_gcm_encrypt();
	uint32_t end_cycles = DWT->CYCCNT;
	uint32_t cycles = end_cycles - start_cycles;
	time_encrypt_aes_us = (float)cycles / (SystemCoreClock / 1000000.0);
}

void benchmark_encrypt_armv7(uint8_t heart_rate, uint8_t spo2, uint8_t temperature, uint8_t acceleration, uint16_t dataLen, uint8_t *secret_key){

	unsigned char ciphertext[DATA_LEN + ASCON_TAG_SIZE];
	unsigned long long ciphertext_len;
	unsigned char message[DATA_LEN] = {heart_rate, spo2, temperature, acceleration};
	unsigned long long message_len = DATA_LEN;
	unsigned char nonce[ASCON_NONCE_SIZE] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x01,
													0x02, 0x03, 0x04, 0x05, 0x01, 0x02,
													0x03, 0x04, 0x05, 0x06};
	unsigned char associated_data[ASCON_ASSOCIATED_DATALENGTH] = ASCON_ASSOCIATED_DATA;
	unsigned long long associated_data_len = ASCON_ASSOCIATED_DATALENGTH;
	uint32_t start_cycles = DWT->CYCCNT;
	armv7_crypto_aead_encrypt(ciphertext, ciphertext_len, message, message_len, associated_data, associated_data_len, NULL, nonce, secret_key);
	uint32_t end_cycles = DWT->CYCCNT;
	uint32_t cycles = end_cycles - start_cycles;
	time_encrypt_armv7_us = (float)cycles / (SystemCoreClock / 1000000.0);
}

void resetUART(UART_HandleTypeDef *huart) {
  HAL_UART_DeInit(huart);
  HAL_UART_Init(huart);
}
/* USER CODE END 0 */

/**
  * @brief  The application entry point.
  * @retval int
  */
int main(void)
{
  /* USER CODE BEGIN 1 */

  /* USER CODE END 1 */

  /* MCU Configuration--------------------------------------------------------*/

  /* Reset of all peripherals, Initializes the Flash interface and the Systick. */
  HAL_Init();

  /* USER CODE BEGIN Init */
  MX_USART2_UART_Init();

  /* USER CODE END Init */
  /* Configure the system clock */
  SystemClock_Config();

  /* USER CODE BEGIN SysInit */

  /* USER CODE END SysInit */

  /* Initialize all configured peripherals */
  MX_GPIO_Init();
  MX_USART2_UART_Init();
  enable_dwt();
  HAL_UART_Receive_IT(&huart2, rx_buffer, TOTAL_RECEIVE_KEY_FROM_ESP32);
  /* USER CODE BEGIN 2 */
  /* USER CODE END 2 */

  /* Infinite loop */
  /* USER CODE BEGIN WHILE */
  while (1)
  {
    /* USER CODE END WHILE */

    /* USER CODE BEGIN 3 */
	  #ifdef OPTIMIZE
		  HAL_SuspendTick();
		  HAL_PWR_EnterSLEEPMode(PWR_MAINREGULATOR_ON, PWR_SLEEPENTRY_WFI);
		  HAL_ResumeTick();
	  #endif
	  if(rx_complete) {
		  rx_complete = 0;
		  mocker6 = rx_buffer[0];
		  if (huart2.ErrorCode != HAL_UART_ERROR_NONE) {
			mocker10 = 1;
			resetUART(&huart2);
			memset(rx_buffer, 0, TOTAL_RECEIVE_KEY_FROM_ESP32);
		  }
		  uint32_t start_cycles = DWT->CYCCNT;
		  if (!check_header(rx_buffer)) {
			  send_error(&huart2, STATE_ERROR_HEADER_MISMATCH);
			  HAL_UART_Receive_IT(&huart2, rx_buffer, TOTAL_RECEIVE_KEY_FROM_ESP32);
			  continue;
		  }
		  packetType = rx_buffer[2];
		  mocker7 = packetType;
		  if (packetType == 0x01 || packetType == 0x04) {
			  process_trigger_packet(rx_buffer, aad_server, &state);
		  }
		  else if(packetType == 0x02){
			  process_key_exchange_packet(rx_buffer, secret_key, aad_server, &state);
		  }
		  else {
			  mocker10 = 10;
			  process_initial_packet(rx_buffer);
		  }
	  }
  }
  /* USER CODE END 3 */
}

/**
  * @brief System Clock Configuration
  * @retval None
  */
void SystemClock_Config(void)
{
  RCC_OscInitTypeDef RCC_OscInitStruct = {0};
  RCC_ClkInitTypeDef RCC_ClkInitStruct = {0};

  /** Configure the main internal regulator output voltage
  */
  __HAL_RCC_PWR_CLK_ENABLE();
  __HAL_PWR_VOLTAGESCALING_CONFIG(PWR_REGULATOR_VOLTAGE_SCALE1);

  /** Initializes the RCC Oscillators according to the specified parameters
  * in the RCC_OscInitTypeDef structure.
  */
  RCC_OscInitStruct.OscillatorType = RCC_OSCILLATORTYPE_HSI;
  RCC_OscInitStruct.HSIState = RCC_HSI_ON;
  RCC_OscInitStruct.HSICalibrationValue = RCC_HSICALIBRATION_DEFAULT;
  RCC_OscInitStruct.PLL.PLLState = RCC_PLL_NONE;
  if (HAL_RCC_OscConfig(&RCC_OscInitStruct) != HAL_OK)
  {
    Error_Handler();
  }

  /** Initializes the CPU, AHB and APB buses clocks
  */
  RCC_ClkInitStruct.ClockType = RCC_CLOCKTYPE_HCLK|RCC_CLOCKTYPE_SYSCLK
                              |RCC_CLOCKTYPE_PCLK1|RCC_CLOCKTYPE_PCLK2;
  RCC_ClkInitStruct.SYSCLKSource = RCC_SYSCLKSOURCE_HSI;
  RCC_ClkInitStruct.AHBCLKDivider = RCC_SYSCLK_DIV1;
  RCC_ClkInitStruct.APB1CLKDivider = RCC_HCLK_DIV1;
  RCC_ClkInitStruct.APB2CLKDivider = RCC_HCLK_DIV1;

  if (HAL_RCC_ClockConfig(&RCC_ClkInitStruct, FLASH_LATENCY_0) != HAL_OK)
  {
    Error_Handler();
  }
}

/**
  * @brief USART2 Initialization Function
  * @param None
  * @retval None
  */
static void MX_USART2_UART_Init(void)
{

  /* USER CODE BEGIN USART2_Init 0 */

  /* USER CODE END USART2_Init 0 */

  /* USER CODE BEGIN USART2_Init 1 */

  /* USER CODE END USART2_Init 1 */
  huart2.Instance = USART2;
  huart2.Init.BaudRate = 115200;
  huart2.Init.WordLength = UART_WORDLENGTH_8B;
  huart2.Init.StopBits = UART_STOPBITS_1;
  huart2.Init.Parity = UART_PARITY_NONE;
  huart2.Init.Mode = UART_MODE_TX_RX;
  huart2.Init.HwFlowCtl = UART_HWCONTROL_NONE;
  huart2.Init.OverSampling = UART_OVERSAMPLING_16;
  if (HAL_UART_Init(&huart2) != HAL_OK)
  {
    Error_Handler();
  }
  __HAL_UART_ENABLE_IT(&huart2, UART_IT_RXNE);
  HAL_NVIC_SetPriority(USART2_IRQn, 0, 0);
  HAL_NVIC_EnableIRQ(USART2_IRQn);
  /* USER CODE BEGIN USART2_Init 2 */

  /* USER CODE END USART2_Init 2 */
}

/**
  * @brief GPIO Initialization Function
  * @param None
  * @retval None
  */
static void MX_GPIO_Init(void)
{
/* USER CODE BEGIN MX_GPIO_Init_1 */
/* USER CODE END MX_GPIO_Init_1 */
	GPIO_InitTypeDef GPIO_InitStruct = {0};
  /* GPIO Ports Clock Enable */
  __HAL_RCC_GPIOA_CLK_ENABLE();

  // Cấu hình PA3 (USART2_RX) với pull-up
  GPIO_InitStruct.Pin = GPIO_PIN_3;
  GPIO_InitStruct.Mode = GPIO_MODE_AF_PP;
  GPIO_InitStruct.Pull = GPIO_PULLUP;
  GPIO_InitStruct.Speed = GPIO_SPEED_FREQ_VERY_HIGH;
  GPIO_InitStruct.Alternate = GPIO_AF7_USART2;
  HAL_GPIO_Init(GPIOA, &GPIO_InitStruct);

  // Cấu hình PA2 (USART2_TX) nếu cần
  GPIO_InitStruct.Pin = GPIO_PIN_2;
  GPIO_InitStruct.Mode = GPIO_MODE_AF_PP;
  GPIO_InitStruct.Pull = GPIO_NOPULL;
  GPIO_InitStruct.Speed = GPIO_SPEED_FREQ_VERY_HIGH;
  GPIO_InitStruct.Alternate = GPIO_AF7_USART2;
  HAL_GPIO_Init(GPIOA, &GPIO_InitStruct);

/* USER CODE BEGIN MX_GPIO_Init_2 */
/* USER CODE END MX_GPIO_Init_2 */
}

/* USER CODE BEGIN 4 */
void enable_dwt(void) {
    CoreDebug->DEMCR |= CoreDebug_DEMCR_TRCENA_Msk; // Enable trace
    DWT->CTRL |= DWT_CTRL_CYCCNTENA_Msk;           // Enable cycle counter
    DWT->CYCCNT = 0;                               // Reset counter
}

void aes_encrypt()
{
    AESECBctx_stt AESctx;
    uint32_t error_status;

    // Initialize the AES context
    AESctx.mFlags = E_SK_DEFAULT;
    AESctx.mKeySize = CRL_AES128_KEY;
    AESctx.mIvSize = 0; // ECB mode doesn't use IV

    // Initialize AES encryption
    error_status = AES_ECB_Encrypt_Init(&AESctx, key_aes, NULL);
    if (error_status != AES_SUCCESS) {
        while (1); // Handle error
    }

    // Encrypt the data
    uint32_t output_size = 0;
    error_status = AES_ECB_Encrypt_Append(&AESctx,
                                          (int8_t *)plaintext_aes,
                                          AES_BLOCK_SIZE_,
                                          (int8_t *)ciphertext_aes,
                                          &output_size);
    if (error_status != AES_SUCCESS) {
        while (1); // Handle error
    }

    // Finalize encryption
    error_status = AES_ECB_Encrypt_Finish(&AESctx, (uint8_t *)(ciphertext_aes + output_size), &output_size);
    if (error_status != AES_SUCCESS) {
        while (1); // Handle error
    }
    mocker10 = error_status;
}

void aes_gcm_encrypt()
{
    AESGCMctx_stt AESctx;
    uint32_t error_status;
    uint32_t output_size = 0;

    // Initialize the AES-GCM context
    AESctx.mFlags = E_SK_DEFAULT;
    AESctx.mKeySize = CRL_AES128_KEY;
    AESctx.mIvSize = AES_GCM_IV_SIZE;
    AESctx.mTagSize = AES_GCM_TAG_SIZE;
    AESctx.mAADsize = AES_GCM_AD_SIZE;
    AESctx.mPayloadSize = AES_GCM_PLAINTEXT_SIZE;

    // Initialize AES-GCM Encryption
    error_status = AES_GCM_Encrypt_Init(&AESctx, aes_key, iv);
    if (error_status != AES_SUCCESS) {
        while (1); // Handle error
    }

    // Add Associated Data (AAD)
    error_status = AES_GCM_Header_Append(&AESctx, aad, AES_GCM_AD_SIZE);
    if (error_status != AES_SUCCESS) {
        while (1); // Handle error
    }

    // Encrypt plaintext
    error_status = AES_GCM_Encrypt_Append(&AESctx, plaintext_aes, AES_GCM_PLAINTEXT_SIZE, ciphertext_aes, &output_size);
    if (error_status != AES_SUCCESS) {
        while (1); // Handle error
    }

    // Finalize encryption and get the authentication tag
    error_status = AES_GCM_Encrypt_Finish(&AESctx, tag, &output_size);
    if (error_status != AES_SUCCESS) {
        while (1); // Handle error
    }
}

void HAL_UART_RxCpltCallback(UART_HandleTypeDef *huart) {
	if (huart->Instance == USART2){
		rx_complete = 1;
		HAL_UART_Receive_IT(&huart2, rx_buffer, TOTAL_RECEIVE_KEY_FROM_ESP32);
	}
}

/* USER CODE END 4 */

/**
  * @brief  This function is executed in case of error occurrence.
  * @retval None
  */
void Error_Handler(void)
{
  /* USER CODE BEGIN Error_Handler_Debug */
  /* User can add his own implementation to report the HAL error return state */
  __disable_irq();
  while (1)
  {
  }
  /* USER CODE END Error_Handler_Debug */
}

#ifdef  USE_FULL_ASSERT
/**
  * @brief  Reports the name of the source file and the source line number
  *         where the assert_param error has occurred.
  * @param  file: pointer to the source file name
  * @param  line: assert_param error line source number
  * @retval None
  */
void assert_failed(uint8_t *file, uint32_t line)
{
  /* USER CODE BEGIN 6 */
  /* User can add his own implementation to report the file name and line number,
     ex: printf("Wrong parameters value: file %s on line %d\r\n", file, line) */
  /* USER CODE END 6 */
}
#endif /* USE_FULL_ASSERT */
