/******************************************************************************************************************
Huong dan su dung:
- Su dung thu vien HAL
- Khoi tao bien DHT : DHT_Name DHT1;
- Khoi tao chan DHT:
	DHT_Init(&DHT1, DHT11, &htim4, DHT_GPIO_Port, DHT_Pin);
- Su dung cac ham phai truyen dia chi cua DHT do: 
	DHT_ReadTempHum(&DHT1);
******************************************************************************************************************/
#include "DHT.h"
//************************** Low Level Layer ********************************************************//
#include "delay_timer.h"

extern mocker1;
extern mocker2;
extern mocker3;

#define DHT_TIMEOUT_THRESHOLD 500

static void DHT_DelayInit(DHT_Name* DHT)
{
	DELAY_TIM_Init(DHT->Timer);
}
static void DHT_DelayUs(DHT_Name* DHT, uint16_t Time)
{
	DELAY_TIM_Us(DHT->Timer, Time);
}

static void DHT_SetPinOut(DHT_Name* DHT)
{
	GPIO_InitTypeDef GPIO_InitStruct = {0};
	GPIO_InitStruct.Pin = DHT->Pin;
	GPIO_InitStruct.Mode = GPIO_MODE_OUTPUT_PP;
	GPIO_InitStruct.Speed = GPIO_SPEED_FREQ_LOW;
	HAL_GPIO_Init(DHT->PORT, &GPIO_InitStruct);
}
static void DHT_SetPinIn(DHT_Name* DHT)
{
	GPIO_InitTypeDef GPIO_InitStruct = {0};
	GPIO_InitStruct.Pin = DHT->Pin;
	GPIO_InitStruct.Mode = GPIO_MODE_INPUT;
	GPIO_InitStruct.Pull = GPIO_PULLUP;
	HAL_GPIO_Init(DHT->PORT, &GPIO_InitStruct);
}
static void DHT_WritePin(DHT_Name* DHT, uint8_t Value)
{
	HAL_GPIO_WritePin(DHT->PORT, DHT->Pin, Value);
}
static uint8_t DHT_ReadPin(DHT_Name* DHT)
{
	uint8_t Value;
	Value =  HAL_GPIO_ReadPin(DHT->PORT, DHT->Pin);
	mocker3 = Value;
	return Value;
}
//********************************* Middle level Layer ****************************************************//
static uint8_t DHT_Start(DHT_Name* DHT)
{
    uint8_t Response = 0;
    DHT_SetPinOut(DHT);
    DHT_WritePin(DHT, 0);
    DHT_DelayUs(DHT, DHT->Type); 
    DHT_SetPinIn(DHT);
    DHT_DelayUs(DHT, 40); 

    uint32_t timeout = 0;
    while(DHT_ReadPin(DHT))
    {
        if (++timeout > DHT_TIMEOUT_THRESHOLD) return 0; 
    }

    // Wait for DHT to pull pin high (Response 2)
    timeout = 0; // Reset timeout
    while(!DHT_ReadPin(DHT)) // While pin is LOW
    {
        if (++timeout > DHT_TIMEOUT_THRESHOLD) return 0;
    }

    // Wait for DHT to pull pin low again (End of response)
    timeout = 0; // Reset timeout
    while(DHT_ReadPin(DHT)) // While pin is HIGH
    {
        if (++timeout > DHT_TIMEOUT_THRESHOLD) return 0; 
    }

    Response = 1; // Indicate success

    return Response; // Return 1 for success, 0 for failure
}
static uint8_t DHT_Read(DHT_Name* DHT)
{
    uint8_t Value = 0;
    DHT_SetPinIn(DHT);
    for(int i = 0; i<8; i++)
    {
        uint32_t timeout = 0;
        while(!DHT_ReadPin(DHT)) {
            if (++timeout > 1000) return 0;
        }
        
        DHT_DelayUs(DHT, 30); 
        
        if(DHT_ReadPin(DHT)) 
        {
            Value |= (1 << (7 - i));
        }

        timeout = 0; 
        while(DHT_ReadPin(DHT)) {
            if (++timeout > DHT_TIMEOUT_THRESHOLD) return 0; // Timeout
        }
    }
    return Value; // Trả về byte đọc được
}

//************************** High Level Layer ********************************************************//
void DHT_Init(DHT_Name* DHT, uint8_t DHT_Type, TIM_HandleTypeDef* Timer, GPIO_TypeDef* DH_PORT, uint16_t DH_Pin)
{
	if(DHT_Type == DHT11)
	{
		DHT->Type = DHT11_STARTTIME;
	}
	else if(DHT_Type == DHT22)
	{
		DHT->Type = DHT22_STARTTIME;
	}
	DHT->PORT = DH_PORT;
	DHT->Pin = DH_Pin;
	DHT->Timer = Timer;
	DHT_DelayInit(DHT);
}

uint8_t DHT_ReadTempHum(DHT_Name* DHT)
{
	uint8_t Temp1, Temp2, RH1, RH2;
	uint16_t Temp, Humi, SUM = 0;
	DHT_Start(DHT);
	RH1 = DHT_Read(DHT);
	RH2 = DHT_Read(DHT);
	Temp1 = DHT_Read(DHT);
	Temp2 = DHT_Read(DHT);
	SUM = DHT_Read(DHT);
	Temp = (Temp1<<8)|Temp2;
	Humi = (RH1<<8)|RH2;
	DHT->Temp = (float)(Temp/10.0);
	DHT->Humi = (float)(Humi/10.0);
	return SUM;
}
