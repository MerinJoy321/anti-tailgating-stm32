/* Hardware abstraction used by the secure core (target: secure_hw.c, host tests: test/hw_stub.c) */
#ifndef SECURE_HW_H
#define SECURE_HW_H
#include <stdint.h>
#include <stdbool.h>
void     hw_init(void);
uint32_t hw_now_ms(void);
uint32_t hw_irq_save(void);
void     hw_irq_restore(uint32_t primask);
void     hw_ir_read(bool *blocked1, bool *blocked2);
void     hw_servo_set_us(uint16_t us);
uint16_t hw_servo_get_us(void);          /* reads the live PWM compare register */
void     hw_buzzer(bool on);
uint32_t hw_cycles(void);
uint32_t hw_cycles_per_us(void);
uint8_t  hw_reset_cause(void);           /* 0 unknown, 1 watchdog, 2 pin, 3 power-on, 4 software */
#endif
