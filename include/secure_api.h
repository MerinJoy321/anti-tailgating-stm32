/* TrustGate - the ONLY header the Non-Secure world may include.
 * Everything behind these calls (credentials, policy, state, log, actuators)
 * lives in secure/ and is not visible to non-secure sources.               */
#ifndef SECURE_API_H
#define SECURE_API_H
#include <stdint.h>
#include <stdbool.h>
#include "tg_policy.h"

typedef enum { TG_DIR_IN = 0, TG_DIR_OUT = 1, TG_DIR_ANY = 2 } tg_dir_t;   /* ANY: user's side unknown (after a reset) */

typedef enum {
    TG_GRANT = 0,
    TG_DENY_UNKNOWN_CARD,
    TG_DENY_DISABLED,
    TG_DENY_TIME,
    TG_DENY_UNSYNCED_CLOCK,
    TG_DENY_LOCKOUT,
    TG_DENY_BUSY,
    TG_DENY_TAMPER,
    TG_DENY_COUNT
} tg_decision_t;

typedef enum {
    EV_BOOT = 1, EV_ACCESS_GRANTED, EV_ACCESS_DENIED, EV_ENTRY_OK, EV_EXIT_OK,
    EV_TAILGATE, EV_UNAUTH_PASSAGE, EV_ANTIPASSBACK, EV_DIR_MISMATCH,
    EV_LOCKOUT_START, EV_LOCKOUT_END, EV_GRANT_TIMEOUT, EV_PASSAGE_ABORT,
    EV_GROUP_SUSPECT, EV_SENSOR_STUCK, EV_API_VIOLATION, EV_TAMPER,
    EV_ADMIN_SESSION, EV_TIME_SET, EV_CONFIG, EV_ALARM_ACK,
    EV_TYPE_COUNT
} tg_event_type_t;

typedef struct {            /* 16 bytes */
    uint32_t tick_ms;
    uint32_t epoch;         /* local epoch seconds, 0 if clock unsynced */
    uint8_t  uid[4];
    uint8_t  type;          /* tg_event_type_t */
    int8_t   user;          /* credential index or -1 */
    uint16_t arg;           /* meaning depends on type (reason, direction, duration ms ...) */
} tg_event_t;

typedef struct {
    uint8_t  door_unlocked, grant_active, inside_count, alarm_active;
    uint8_t  time_valid, tamper_lockdown, admin_session, ir1, ir2;
    uint16_t lockout_remaining_s, admin_remaining_s;
} tg_status_t;

typedef struct {
    uint32_t taps, granted, denied, entries, exits, tailgates, unauth_passages,
             antipassback, dir_mismatch, lockouts, api_violations, tamper,
             aborts, group_suspect, decision_us_last, decision_us_max;
} tg_stats_t;

/* lifecycle */
void secure_init(void);
void secure_tick_1ms(void);                       /* call from SysTick */

/* credential / policy API (names follow the project slides) */
int8_t        secure_authenticate(const uint8_t uid[4]);      /* index or -1, no side effects */
tg_decision_t secure_check_permission(int8_t user);            /* role/time/state check, no side effects */
tg_decision_t secure_authorize_entry(const uint8_t uid[4]);    /* the only call that can grant/unlock */

/* read-only views */
void     get_access_status(tg_status_t *out);
void     get_security_statistics(tg_stats_t *out);
uint32_t secure_log_next_seq(void);
bool     secure_log_read(uint32_t seq, tg_event_t *out);       /* false if overwritten / not yet written */
const char *secure_event_name(uint8_t type);
const char *secure_decision_name(uint8_t d);

/* gated calls: refused + logged as EV_API_VIOLATION unless an admin session is open
 * (secure_set_time is also accepted while the clock has never been set)        */
bool secure_set_time(uint32_t local_epoch);
bool secure_admin_clear_lockout(void);
bool secure_admin_ack_alarm(void);
bool secure_admin_set_servo(uint16_t lock_us, uint16_t unlock_us);

/* Demonstration of the blocked calls from the slides. Always refused and logged.
 * which: 1=read_credentials 2=direct_unlatch 3=reset_security_state 4=delete_logs */
bool secure_api_probe(uint8_t which);

#endif
