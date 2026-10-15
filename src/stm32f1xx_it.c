#include "stm32f1xx_hal.h"
#include "secure_api.h"

void SysTick_Handler(void)
{
    HAL_IncTick();
    secure_tick_1ms();            /* IR sampling, passage logic, timers, actuators: runs every 1 ms */
}
void NMI_Handler(void) { for (;;) {} }
void HardFault_Handler(void) { for (;;) {} }
void MemManage_Handler(void) { for (;;) {} }
void BusFault_Handler(void) { for (;;) {} }
void UsageFault_Handler(void) { for (;;) {} }
void SVC_Handler(void) {}
void DebugMon_Handler(void) {}
void PendSV_Handler(void) {}
