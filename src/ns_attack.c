/* ATTACK DEMO (only built with -DTG_ATTACK_DEMO). Models a compromised NON-SECURE world that has
 * the secure source code. The Blue Pill's STM32F103 has no MPU / TrustZone, so nothing in hardware
 * stops this code from touching secure RAM or the actuator registers. Used for the report's
 * "where software isolation ends" experiments. */
#ifdef TG_ATTACK_DEMO
#include "stm32f1xx_hal.h"
#include "../secure/secure_internal.h"

static tg_state_t *find_state(void)
{
    for (uint32_t a = 0x20000000u; a + sizeof(tg_state_t) <= 0x20005000u; a += 4u) {
        tg_state_t *s = (tg_state_t *)a;
        if (s->magic == TG_MAGIC && tg_state_hash(s) == s->hash) return s;
    }
    return 0;
}

const char *ns_attack_run(int which)
{
    switch (which) {
    case 1: { tg_state_t *s = find_state(); if (!s) return "state not found";
              s->door_unlocked = 1;                                   /* forge unlock, leave seal stale */
              return "forged door_unlocked without re-sealing (expect TAMPER + lockdown)"; }
    case 2: { tg_state_t *s = find_state(); if (!s) return "state not found";
              s->door_unlocked = 1; s->relock_at = 0; s->hash = tg_state_hash(s);   /* forge + recompute seal */
              return "forged door_unlocked AND re-sealed (expect: door opens, NO event)"; }
    case 3: TIM2->CCR2 = SERVO_UNLOCK_US_DEFAULT;                     /* bypass the API, drive the actuator */
            return "wrote TIM2->CCR2 directly (expect TAMPER arg=2, register restored)";
    default: return "unknown attack (1,2,3)";
    }
}
#endif
