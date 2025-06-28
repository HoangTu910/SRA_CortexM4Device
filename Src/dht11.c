#include "dht11.h"

extern TIM_HandleTypeDef htim1;

// Micro delay function (~1 us resolution)
void delay_us(uint16_t us) {
    uint32_t start = __HAL_TIM_GET_COUNTER(&htim1);
    while ((__HAL_TIM_GET_COUNTER(&htim1) - start) < us);
}

// Change pin to output
void DHT11_SetPinOutput(void) {
    GPIO_InitTypeDef GPIO_InitStruct = {0};
    GPIO_InitStruct.Pin = DHT11_PIN;
    GPIO_InitStruct.Mode = GPIO_MODE_OUTPUT_PP;
    GPIO_InitStruct.Pull = GPIO_NOPULL;
    GPIO_InitStruct.Speed = GPIO_SPEED_FREQ_LOW;
    HAL_GPIO_Init(DHT11_PORT, &GPIO_InitStruct);
}

// Change pin to input
void DHT11_SetPinInput(void) {
    GPIO_InitTypeDef GPIO_InitStruct = {0};
    GPIO_InitStruct.Pin = DHT11_PIN;
    GPIO_InitStruct.Mode = GPIO_MODE_INPUT;
    GPIO_InitStruct.Pull = GPIO_NOPULL;
    HAL_GPIO_Init(DHT11_PORT, &GPIO_InitStruct);
}

// Send start signal to DHT11
void DHT11_Start(void) {
    DHT11_SetPinOutput();
    HAL_GPIO_WritePin(DHT11_PORT, DHT11_PIN, GPIO_PIN_RESET);
    HAL_Delay(18); 
    HAL_GPIO_WritePin(DHT11_PORT, DHT11_PIN, GPIO_PIN_SET);
    delay_us(20);
    DHT11_SetPinInput();
}

// Wait for response
uint8_t DHT11_CheckResponse(void) {
    delay_us(40);
    if (!HAL_GPIO_ReadPin(DHT11_PORT, DHT11_PIN)) {
        delay_us(80);
        if (HAL_GPIO_ReadPin(DHT11_PORT, DHT11_PIN)) {
            delay_us(80);
            return 1;
        }
    }
    return 0;
}

// Read one byte from DHT11
uint8_t DHT11_ReadByte(void) {
    uint8_t i, byte = 0;
    for (i = 0; i < 8; i++) {
        while (!HAL_GPIO_ReadPin(DHT11_PORT, DHT11_PIN)); // chờ lên mức 1
        delay_us(40);
        if (HAL_GPIO_ReadPin(DHT11_PORT, DHT11_PIN)) {
            byte |= (1 << (7 - i));
        }
        while (HAL_GPIO_ReadPin(DHT11_PORT, DHT11_PIN)); // chờ về 0
    }
    return byte;
}

// Public function to read DHT11
uint8_t DHT11_Read(uint8_t *temperature, uint8_t *humidity) {
    uint8_t rh_int, rh_dec, temp_int, temp_dec, checksum;

    DHT11_Start();
    if (DHT11_CheckResponse()) {
        rh_int    = DHT11_ReadByte();
        rh_dec    = DHT11_ReadByte();
        temp_int  = DHT11_ReadByte();
        temp_dec  = DHT11_ReadByte();
        checksum  = DHT11_ReadByte();

        if ((rh_int + rh_dec + temp_int + temp_dec) == checksum) {
            *temperature = temp_int;
            *humidity = rh_int;
            return 1; // Success
        }
    }
    return 0; // Failed
}
