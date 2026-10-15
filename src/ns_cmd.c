/* NON-SECURE world: UART link to the laptop dashboard. Only uses secure_api.h. */
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "stm32f1xx_hal.h"
#include "board_pins.h"
#include "secure_api.h"
#include "ns_cmd.h"

static UART_HandleTypeDef huart1;
static volatile uint8_t rxbuf[128];
static volatile uint8_t rx_head, rx_tail;
static char line[64]; static uint8_t line_len;
static uint32_t ns_seq, t_status, t_stats, t_timereq;

void HAL_UART_MspInit(UART_HandleTypeDef *h)
{
    if (h->Instance != USART1) return;
    __HAL_RCC_USART1_CLK_ENABLE(); __HAL_RCC_GPIOA_CLK_ENABLE();
    GPIO_InitTypeDef g = {0};
    g.Pin = GPIO_PIN_9; g.Mode = GPIO_MODE_AF_PP; g.Speed = GPIO_SPEED_FREQ_HIGH; HAL_GPIO_Init(GPIOA, &g);
    g.Pin = GPIO_PIN_10; g.Mode = GPIO_MODE_INPUT; g.Pull = GPIO_NOPULL; HAL_GPIO_Init(GPIOA, &g);
    HAL_NVIC_SetPriority(USART1_IRQn, 1, 0);
    HAL_NVIC_EnableIRQ(USART1_IRQn);
}

void USART1_IRQHandler(void)
{
    uint32_t sr = USART1->SR;
    if (sr & (USART_SR_RXNE | USART_SR_ORE)) {
        uint8_t c = (uint8_t)USART1->DR;                  /* reading SR then DR clears RXNE/ORE */
        uint8_t nh = (uint8_t)((rx_head + 1u) % sizeof rxbuf);
        if (nh != rx_tail) { rxbuf[rx_head] = c; rx_head = nh; }
    }
}

void ns_uart_init(void)
{
    huart1.Instance = USART1; huart1.Init.BaudRate = TG_UART_BAUD; huart1.Init.WordLength = UART_WORDLENGTH_8B;
    huart1.Init.StopBits = UART_STOPBITS_1; huart1.Init.Parity = UART_PARITY_NONE; huart1.Init.Mode = UART_MODE_TX_RX;
    huart1.Init.HwFlowCtl = UART_HWCONTROL_NONE; huart1.Init.OverSampling = UART_OVERSAMPLING_16;
    HAL_UART_Init(&huart1);
    USART1->CR1 |= USART_CR1_RXNEIE;
}

void ns_printf(const char *fmt, ...)
{
    char buf[160]; va_list ap; va_start(ap, fmt);
    int n = vsnprintf(buf, sizeof buf, fmt, ap); va_end(ap);
    if (n > 0) HAL_UART_Transmit(&huart1, (uint8_t *)buf, (uint16_t)(n < (int)sizeof buf ? n : (int)sizeof buf - 1), 100);
}

void ns_boot_banner(bool rc_ok, uint8_t v)
{
    ns_printf("\r\nBOOT,TrustGate,%s,rc522=%s,ver=0x%02X,sysclk=%lu\r\n", TG_FW_VERSION, rc_ok ? "ok" : "FAIL", v, (unsigned long)SystemCoreClock);
}

static void print_status(void)
{
    tg_status_t s; get_access_status(&s);
    ns_printf("ST,%lu,%c,%u,%u,%u,%u,%u,%u,%u%u,%u\r\n", (unsigned long)HAL_GetTick(), s.door_unlocked ? 'U' : 'L', s.grant_active,
              s.inside_count, s.lockout_remaining_s, s.alarm_active, s.time_valid, s.admin_remaining_s, s.ir1, s.ir2, s.tamper_lockdown);
}

static void print_stats(void)
{
    tg_stats_t x; get_security_statistics(&x);
    ns_printf("SX,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu\r\n",
              (unsigned long)x.taps, (unsigned long)x.granted, (unsigned long)x.denied, (unsigned long)x.entries, (unsigned long)x.exits,
              (unsigned long)x.tailgates, (unsigned long)x.unauth_passages, (unsigned long)x.antipassback, (unsigned long)x.dir_mismatch,
              (unsigned long)x.lockouts, (unsigned long)x.api_violations, (unsigned long)x.tamper, (unsigned long)x.aborts,
              (unsigned long)x.group_suspect, (unsigned long)x.decision_us_last, (unsigned long)x.decision_us_max);
}

static void pump_events(void)
{
    uint32_t next = secure_log_next_seq();
    if ((int32_t)(next - ns_seq) > TG_LOG_N) ns_seq = next - TG_LOG_N;
    if ((int32_t)(ns_seq - next) > 0) ns_seq = next;
    while (ns_seq != next) {
        tg_event_t e;
        if (secure_log_read(ns_seq, &e)) {
            char d = ',';
            ns_printf("EV,%lu,%lu,%lu,%s,%d,%02X%02X%02X%02X%c%u\r\n", (unsigned long)ns_seq, (unsigned long)e.tick_ms, (unsigned long)e.epoch,
                      secure_event_name(e.type), e.user, e.uid[0], e.uid[1], e.uid[2], e.uid[3], d, e.arg);
        }
        ns_seq++;
    }
}

#ifdef TG_ATTACK_DEMO
extern const char *ns_attack_run(int which);
#endif

static void handle_line(char *l)
{
    if (!strcmp(l, "PING")) ns_printf("OK PONG\r\n");
    else if (!strncmp(l, "TIME ", 5)) ns_printf(secure_set_time((uint32_t)strtoul(l + 5, 0, 10)) ? "OK TIME\r\n" : "ERR TIME refused\r\n");
    else if (!strcmp(l, "STATUS")) print_status();
    else if (!strcmp(l, "STATS")) print_stats();
    else if (!strcmp(l, "LOG")) { uint32_t n = secure_log_next_seq(); ns_seq = n > TG_LOG_N ? n - TG_LOG_N : 0; ns_printf("OK LOG\r\n"); }
    else if (!strcmp(l, "UNLOCKOUT")) ns_printf(secure_admin_clear_lockout() ? "OK UNLOCKOUT\r\n" : "ERR need admin session\r\n");
    else if (!strcmp(l, "ACK")) ns_printf(secure_admin_ack_alarm() ? "OK ACK\r\n" : "ERR need admin session\r\n");
    else if (!strncmp(l, "CAL ", 4)) {
        char *e; unsigned long a = strtoul(l + 4, &e, 10), b = strtoul(e, 0, 10);
        ns_printf(secure_admin_set_servo((uint16_t)a, (uint16_t)b) ? "OK CAL\r\n" : "ERR CAL refused\r\n");
    }
    else if (!strncmp(l, "PROBE ", 6)) { secure_api_probe((uint8_t)atoi(l + 6)); ns_printf("OK PROBE refused by secure boundary\r\n"); }
#ifdef TG_ATTACK_DEMO
    else if (!strncmp(l, "ATTACK ", 7)) ns_printf("OK ATTACK %s\r\n", ns_attack_run(atoi(l + 7)));
#endif
    else ns_printf("ERR unknown command\r\n");
}

void ns_poll(void)
{
    while (rx_tail != rx_head) {
        char c = (char)rxbuf[rx_tail]; rx_tail = (uint8_t)((rx_tail + 1u) % sizeof rxbuf);
        if (c == '\r' || c == '\n') { if (line_len) { line[line_len] = 0; handle_line(line); line_len = 0; } }
        else if (line_len < sizeof line - 1) line[line_len++] = c;
        else line_len = 0;
    }
    pump_events();
    uint32_t now = HAL_GetTick();
    if ((int32_t)(now - t_status) >= 0) { t_status = now + 1000; print_status(); }
    if ((int32_t)(now - t_stats) >= 0)  { t_stats = now + 5000; print_stats(); }
    if ((int32_t)(now - t_timereq) >= 0) {
        t_timereq = now + 5000;
        tg_status_t s; get_access_status(&s);
        if (!s.time_valid) ns_printf("TIME?\r\n");
    }
}
