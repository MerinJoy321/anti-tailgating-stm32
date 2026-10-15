/* SECURE-WORLD PRIVATE HEADER. Non-secure sources must never include this.
 * (The attack demo in src/ns_attack.c includes it on purpose to model an attacker who has the source.) */
#ifndef SECURE_INTERNAL_H
#define SECURE_INTERNAL_H
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include "../include/secure_api.h"
#include "provisioned_cards.h"

#define TG_MAGIC 0x54475354u   /* 'TGST' */
#define TG_UNKNOWN 2           /* inside[] value: side unknown (after reset); 0 = outside, 1 = inside */

typedef struct {
    uint32_t magic;
    uint8_t  inside[TG_MAX_USERS];
    uint8_t  enabled[TG_MAX_USERS];
    uint8_t  grant_active; int8_t grant_user; uint8_t grant_dir; uint8_t door_unlocked;
    uint32_t grant_deadline;
    uint32_t watch_until;  uint8_t watch_dir; int8_t watch_user; uint8_t tamper_lockdown; uint8_t time_valid;
    uint32_t relock_at;                 /* 0 = no pending relock */
    uint32_t lockdown_until;
    uint32_t fail_window_start; uint8_t fail_count; uint8_t pad0[3];
    uint32_t lockout_until;             /* 0 = not locked out */
    uint32_t admin_until;               /* 0 = no admin session */
    uint32_t epoch_base, tick_base;
    uint32_t alarm_until;               /* 0 = no alarm */
    uint16_t servo_lock_us, servo_unlock_us;
    uint32_t log_seq;
    tg_event_t log[TG_LOG_N];
    tg_stats_t stats;
    uint32_t hash;                      /* MUST stay last: integrity seal over everything above */
} tg_state_t;

/* FNV-1a integrity seal. Detects accidental / naive corruption only: it is not a MAC, and an
 * attacker who can run code in the same address space can recompute it (see attack demo 2). */
static inline uint32_t tg_state_hash(const tg_state_t *s)
{
    const uint8_t *p = (const uint8_t *)s;
    uint32_t h = 2166136261u;
    for (size_t i = 0; i < offsetof(tg_state_t, hash); i++) { h ^= p[i]; h *= 16777619u; }
    return h;
}
#endif
