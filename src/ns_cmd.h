#ifndef NS_CMD_H
#define NS_CMD_H
#include <stdint.h>
#include <stdbool.h>
void ns_uart_init(void);
void ns_printf(const char *fmt, ...);
void ns_boot_banner(bool rc_ok, uint8_t rc_version);
void ns_poll(void);          /* RX commands, event stream, periodic status */
#endif
