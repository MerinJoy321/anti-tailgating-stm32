/* Host stub of the hardware layer so the secure core can be unit-tested on a PC. */
#include "../secure/secure_hw.h"
uint32_t g_now = 5000; bool g_a, g_b, g_buz; uint16_t g_servo;
void     hw_init(void) {}
uint32_t hw_now_ms(void) { return g_now; }
uint32_t hw_irq_save(void) { return 0; }
void     hw_irq_restore(uint32_t p) { (void)p; }
void     hw_ir_read(bool *a, bool *b) { *a = g_a; *b = g_b; }
void     hw_servo_set_us(uint16_t us) { g_servo = us; }
uint16_t hw_servo_get_us(void) { return g_servo; }
void     hw_buzzer(bool on) { g_buz = on; }
uint32_t hw_cycles(void) { static uint32_t c; return c += 720; }
uint32_t hw_cycles_per_us(void) { return 72; }
uint8_t  hw_reset_cause(void) { return 3; }
