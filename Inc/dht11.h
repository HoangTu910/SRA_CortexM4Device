#ifndef __DHT11_H__
#define __DHT11_H__

#include "stm32f4xx_hal.h"
#include <stdint.h>

// Define DHT11 pin & port
#define DHT11_PORT GPIOC
#define DHT11_PIN  GPIO_PIN_1

void DHT11_Init(void);
uint8_t DHT11_Read(uint8_t *temperature, uint8_t *humidity);

#endif
