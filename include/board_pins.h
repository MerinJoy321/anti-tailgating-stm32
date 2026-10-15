/* TrustGate - Blue Pill pin map. Change here only. */
#ifndef BOARD_PINS_H
#define BOARD_PINS_H
#include "stm32f1xx_hal.h"

/* RC522 on SPI1: SCK=PA5, MISO=PA6, MOSI=PA7 (fixed by hardware) */
#define RC522_NSS_PORT   GPIOA
#define RC522_NSS_PIN    GPIO_PIN_4      /* RC522 "SDA" pin */
#define RC522_RST_PORT   GPIOB
#define RC522_RST_PIN    GPIO_PIN_0

/* IR obstacle modules. IR1 = OUTSIDE of door, IR2 = INSIDE. Module OUT is LOW when beam is blocked. */
#define IR1_PORT         GPIOB
#define IR1_PIN          GPIO_PIN_12
#define IR2_PORT         GPIOB
#define IR2_PIN          GPIO_PIN_13
#define IR_ACTIVE_LEVEL  0

/* SG90 servo signal: PA1 = TIM2_CH2 */
#define SERVO_PORT       GPIOA
#define SERVO_PIN        GPIO_PIN_1

/* Buzzer. 1 = passive buzzer driven with a 500 Hz square wave, 0 = active buzzer driven DC */
#define BUZZER_PASSIVE   0
#define BUZZER_PORT      GPIOB
#define BUZZER_PIN       GPIO_PIN_14

/* Status LEDs (each through a 330 ohm resistor to GND) and the on-board LED (active low) */
#define LED_GREEN_PORT   GPIOB
#define LED_GREEN_PIN    GPIO_PIN_8
#define LED_RED_PORT     GPIOB
#define LED_RED_PIN      GPIO_PIN_9
#define LED_BOARD_PORT   GPIOC
#define LED_BOARD_PIN    GPIO_PIN_13

/* UART to laptop: USART1 PA9 (TX) / PA10 (RX), 115200 8N1 */
#define TG_UART_BAUD     115200
#endif
