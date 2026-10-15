/* SECURE WORLD hardware: IR sensors, servo (TIM2_CH2 on PA1), buzzer, cycle counter. */
#include "stm32f1xx_hal.h"
#include "secure_hw.h"
#include "../include/board_pins.h"
#include "../include/tg_policy.h"

static TIM_HandleTypeDef s_tim2;

uint32_t hw_now_ms(void) { return HAL_GetTick(); }
/* Mask only priority-15 (SysTick) so the UART RX interrupt (priority 1) is never blocked and no byte is lost. */
uint32_t hw_irq_save(void) { uint32_t o = __get_BASEPRI(); if (o == 0u || o > 0xF0u) __set_BASEPRI(0xF0u); return o; }
void     hw_irq_restore(uint32_t o) { __set_BASEPRI(o); }

uint8_t hw_reset_cause(void)
{
    uint32_t c = RCC->CSR; uint8_t r = 0;
    if (c & (RCC_CSR_IWDGRSTF | RCC_CSR_WWDGRSTF)) r = 1;
    else if (c & RCC_CSR_PORRSTF) r = 3;
    else if (c & RCC_CSR_SFTRSTF) r = 4;
    else if (c & RCC_CSR_PINRSTF) r = 2;
    RCC->CSR |= RCC_CSR_RMVF;
    return r;
}
uint32_t hw_cycles(void) { return DWT->CYCCNT; }
uint32_t hw_cycles_per_us(void) { uint32_t f = SystemCoreClock / 1000000u; return f ? f : 1u; }

void hw_ir_read(bool *b1, bool *b2)
{
    *b1 = (HAL_GPIO_ReadPin(IR1_PORT, IR1_PIN) == (IR_ACTIVE_LEVEL ? GPIO_PIN_SET : GPIO_PIN_RESET));
    *b2 = (HAL_GPIO_ReadPin(IR2_PORT, IR2_PIN) == (IR_ACTIVE_LEVEL ? GPIO_PIN_SET : GPIO_PIN_RESET));
}

void hw_servo_set_us(uint16_t us) { __HAL_TIM_SET_COMPARE(&s_tim2, TIM_CHANNEL_2, us); }
uint16_t hw_servo_get_us(void)    { return (uint16_t)__HAL_TIM_GET_COMPARE(&s_tim2, TIM_CHANNEL_2); }

void hw_buzzer(bool on)
{
#if BUZZER_PASSIVE
    static uint8_t phase;
    if (on) { phase ^= 1; HAL_GPIO_WritePin(BUZZER_PORT, BUZZER_PIN, phase ? GPIO_PIN_SET : GPIO_PIN_RESET); }
    else HAL_GPIO_WritePin(BUZZER_PORT, BUZZER_PIN, GPIO_PIN_RESET);
#else
    HAL_GPIO_WritePin(BUZZER_PORT, BUZZER_PIN, on ? GPIO_PIN_SET : GPIO_PIN_RESET);
#endif
}

void hw_init(void)
{
    __HAL_RCC_GPIOA_CLK_ENABLE(); __HAL_RCC_GPIOB_CLK_ENABLE(); __HAL_RCC_TIM2_CLK_ENABLE();
    GPIO_InitTypeDef g = {0};

    g.Pin = IR1_PIN | IR2_PIN; g.Mode = GPIO_MODE_INPUT; g.Pull = GPIO_PULLUP;
    HAL_GPIO_Init(IR1_PORT, &g);

    g.Pin = BUZZER_PIN; g.Mode = GPIO_MODE_OUTPUT_PP; g.Pull = GPIO_NOPULL; g.Speed = GPIO_SPEED_FREQ_LOW;
    HAL_GPIO_WritePin(BUZZER_PORT, BUZZER_PIN, GPIO_PIN_RESET);
    HAL_GPIO_Init(BUZZER_PORT, &g);

    g.Pin = SERVO_PIN; g.Mode = GPIO_MODE_AF_PP; g.Speed = GPIO_SPEED_FREQ_MEDIUM;
    HAL_GPIO_Init(SERVO_PORT, &g);

    /* TIM2 clock = 2 x PCLK1 when APB1 prescaler != 1 (72 MHz on the PLL path) */
    uint32_t tclk = HAL_RCC_GetPCLK1Freq();
    if ((RCC->CFGR & RCC_CFGR_PPRE1) != RCC_CFGR_PPRE1_DIV1) tclk *= 2u;
    s_tim2.Instance = TIM2;
    s_tim2.Init.Prescaler = tclk / 1000000u - 1u;          /* 1 MHz tick => compare value == microseconds */
    s_tim2.Init.CounterMode = TIM_COUNTERMODE_UP;
    s_tim2.Init.Period = 19999u;                           /* 20 ms = 50 Hz */
    s_tim2.Init.ClockDivision = TIM_CLOCKDIVISION_DIV1;
    s_tim2.Init.AutoReloadPreload = TIM_AUTORELOAD_PRELOAD_ENABLE;
    HAL_TIM_PWM_Init(&s_tim2);
    TIM_OC_InitTypeDef oc = {0};
    oc.OCMode = TIM_OCMODE_PWM1; oc.Pulse = SERVO_LOCK_US_DEFAULT; oc.OCPolarity = TIM_OCPOLARITY_HIGH; oc.OCFastMode = TIM_OCFAST_DISABLE;
    HAL_TIM_PWM_ConfigChannel(&s_tim2, &oc, TIM_CHANNEL_2);
    HAL_TIM_PWM_Start(&s_tim2, TIM_CHANNEL_2);

    CoreDebug->DEMCR |= CoreDebug_DEMCR_TRCENA_Msk;        /* DWT cycle counter for latency stats */
    DWT->CYCCNT = 0; DWT->CTRL |= DWT_CTRL_CYCCNTENA_Msk;
}
