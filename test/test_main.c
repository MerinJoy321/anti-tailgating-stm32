#include <stdio.h>
#include <string.h>
#include "../secure/secure_internal.h"
#include "../secure/secure_hw.h"

extern uint32_t g_now; extern bool g_a, g_b, g_buz; extern uint16_t g_servo;
tg_state_t *tg_test_state(void);

static int fails, checks;
#define CHECK(c, msg) do { checks++; if (!(c)) { fails++; printf("  FAIL: %s  (line %d)\n", msg, __LINE__); } else printf("  ok:   %s\n", msg); } while (0)

static void adv(uint32_t ms) { while (ms--) { g_now++; secure_tick_1ms(); } }
static uint32_t mk_epoch(int y, int m, int d, int hh, int mm)
{
    y -= m <= 2; int era = y / 400, yoe = y - era * 400, doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
    int doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; long days = era * 146097L + doe - 719468;
    return (uint32_t)(days * 86400L + hh * 3600 + mm * 60);
}
static const uint32_t WED_10 = 0, SUN_10 = 0;
static void fresh(uint32_t epoch)
{
    g_a = g_b = false; g_servo = 0; secure_init(); adv(50);
    if (epoch) secure_set_time(epoch);
}
static tg_decision_t tap(int idx) { return secure_authorize_entry(TG_CARDS[idx].uid); }
static void walk_in(void)  { g_a = 1; adv(150); g_b = 1; adv(150); g_a = 0; adv(150); g_b = 0; adv(150); }
static void walk_out(void) { g_b = 1; adv(150); g_a = 1; adv(150); g_b = 0; adv(150); g_a = 0; adv(150); }
static int count_ev(int type)
{
    int n = 0; uint32_t end = secure_log_next_seq(); tg_event_t e;
    for (uint32_t s = end > TG_LOG_N ? end - TG_LOG_N : 0; s < end; s++) if (secure_log_read(s, &e) && e.type == type) n++;
    return n;
}
static int last_arg(int type)
{
    int v = -1; uint32_t end = secure_log_next_seq(); tg_event_t e;
    for (uint32_t s = end > TG_LOG_N ? end - TG_LOG_N : 0; s < end; s++) if (secure_log_read(s, &e) && e.type == type) v = e.arg;
    return v;
}
static tg_status_t st(void) { tg_status_t s; get_access_status(&s); return s; }

int main(void)
{
    (void)WED_10; (void)SUN_10;
    uint32_t WED = mk_epoch(2026, 10, 14, 10, 0);
    printf("T01 clock unsynced: staff denied, admin granted\n");
    fresh(0);
    CHECK(tap(1) == TG_DENY_UNSYNCED_CLOCK, "staff denied while clock unsynced");
    adv(1000); CHECK(tap(0) == TG_GRANT, "admin granted while clock unsynced");

    printf("T02 normal entry\n");
    fresh(WED);
    CHECK(tap(1) == TG_GRANT, "staff granted Wed 10:00");
    CHECK(st().door_unlocked == 1 && g_servo == SERVO_UNLOCK_US_DEFAULT, "servo unlocked");
    walk_in();
    CHECK(count_ev(EV_ENTRY_OK) == 1 && st().inside_count == 1, "ENTRY_OK logged, 1 inside");
    CHECK(count_ev(EV_TAILGATE) == 0 && count_ev(EV_UNAUTH_PASSAGE) == 0, "no alarms");
    adv(1300); CHECK(g_servo == SERVO_LOCK_US_DEFAULT && !st().door_unlocked, "relocked after passage");

    printf("T03 normal exit\n");
    adv(3500); CHECK(tap(1) == TG_GRANT, "same staff taps to exit"); walk_out();
    CHECK(count_ev(EV_EXIT_OK) == 1 && st().inside_count == 0, "EXIT_OK logged, 0 inside");

    printf("T04 tailgating (two people, one tap)\n");
    fresh(WED); tap(1); walk_in(); adv(300); walk_in();
    CHECK(count_ev(EV_ENTRY_OK) == 1 && count_ev(EV_TAILGATE) == 1, "1 ENTRY_OK + 1 TAILGATE");
    CHECK(st().alarm_active == 1 && !st().door_unlocked, "alarm on, latch locked");

    printf("T05 tailgating with overlapping beams (A never clears between people)\n");
    fresh(WED); tap(1);
    g_a = 1; adv(150); g_b = 1; adv(350); g_b = 0; adv(200); g_b = 1; adv(200); g_a = 0; adv(200); g_b = 0; adv(300);
    CHECK(count_ev(EV_ENTRY_OK) == 1 && count_ev(EV_TAILGATE) == 1, "overlap case still counted as 2 people");

    printf("T06 shoulder-to-shoulder (limit of two beams)\n");
    fresh(WED); tap(1);
    g_a = 1; adv(150); g_b = 1; adv(2000); g_a = 0; g_b = 0; adv(300);
    CHECK(count_ev(EV_ENTRY_OK) == 1 && count_ev(EV_TAILGATE) == 0, "counted as ONE passage (known limit)");
    CHECK(count_ev(EV_GROUP_SUSPECT) == 1, "flagged only by long-blockage heuristic");

    printf("T07 unauthorised passage, no tap\n");
    fresh(WED); walk_in();
    CHECK(count_ev(EV_UNAUTH_PASSAGE) == 1 && st().alarm_active, "UNAUTH_PASSAGE + alarm");

    printf("T08 anti-passback (card handed back outside)\n");
    fresh(WED); tap(1); walk_in(); adv(4000);
    CHECK(tap(1) == TG_GRANT, "same card taps again (expects exit)");
    walk_in();
    CHECK(count_ev(EV_ANTIPASSBACK) == 1 && st().inside_count == 1, "ANTIPASSBACK logged, state unchanged");

    printf("T09 wrong direction\n");
    fresh(WED); tap(1); walk_in(); adv(3500); tap(1); walk_out(); adv(3500);   /* now known OUTSIDE */
    tap(1); walk_out();
    CHECK(count_ev(EV_DIR_MISMATCH) == 1, "DIR_MISMATCH logged (outside user walked out)");

    printf("T09b unknown side after reset: either direction accepted, side learned\n");
    fresh(WED); tap(1); walk_out();
    CHECK(count_ev(EV_EXIT_OK) == 1 && count_ev(EV_DIR_MISMATCH) == 0 && count_ev(EV_ANTIPASSBACK) == 0, "no false alarm after reboot");
    adv(3500); tap(1); walk_out();
    CHECK(count_ev(EV_DIR_MISMATCH) == 1, "side is known afterwards (second walk-out is a mismatch)");

    printf("T10 lockout after 3 failures, admin override\n");
    fresh(WED); uint8_t bad[4] = {1, 2, 3, 4};
    for (int i = 0; i < 3; i++) { secure_authorize_entry(bad); adv(200); }
    CHECK(count_ev(EV_LOCKOUT_START) == 1, "LOCKOUT_START after 3 unknown cards");
    CHECK(tap(1) == TG_DENY_LOCKOUT, "valid staff denied during lockout");
    CHECK(tap(0) == TG_GRANT && count_ev(EV_LOCKOUT_END) == 1, "admin card cleared lockout");
    fresh(WED); for (int i = 0; i < 3; i++) { secure_authorize_entry(bad); adv(200); }
    adv(LOCKOUT_MS + 100);
    CHECK(count_ev(EV_LOCKOUT_END) == 1 && tap(1) == TG_GRANT, "lockout expires by itself");

    printf("T11 time windows\n");
    fresh(mk_epoch(2026, 10, 11, 10, 0));   /* Sunday */
    CHECK(tap(1) == TG_DENY_TIME, "staff denied on Sunday");
    fresh(mk_epoch(2026, 10, 14, 20, 30));
    CHECK(tap(1) == TG_DENY_TIME, "staff denied Wed 20:30");
    CHECK(tap(0) == TG_GRANT, "admin allowed any time");
    fresh(mk_epoch(2026, 10, 14, 9, 0));
    CHECK(tap(3) == TG_DENY_TIME, "guest denied 09:00 (window 10-16)");

    printf("T12 grant timeout and aborted approach\n");
    fresh(WED); tap(1); adv(GRANT_TIMEOUT_MS + 50);
    CHECK(count_ev(EV_GRANT_TIMEOUT) == 1 && !st().door_unlocked, "grant expires, relocked");
    fresh(WED); tap(1); g_a = 1; adv(100); g_a = 0; adv(3000);
    CHECK(count_ev(EV_PASSAGE_ABORT) == 1 && st().grant_active, "single-beam poke = ABORT, grant kept");

    printf("T12b standing in the beams when the grant expires\n");
    fresh(WED); tap(1); adv(5800); g_a = 1; adv(300); g_b = 1; adv(300); g_a = 0; adv(200); g_b = 0; adv(300);
    CHECK(count_ev(EV_ENTRY_OK) == 1 && count_ev(EV_UNAUTH_PASSAGE) == 0 && count_ev(EV_GRANT_TIMEOUT) == 0, "late walker accepted, no false alarm");

    printf("T13 busy: second tap while a grant is pending\n");
    fresh(WED); tap(1);
    CHECK(tap(2) == TG_DENY_BUSY, "second card denied BUSY");

    printf("T14 API gating\n");
    fresh(WED);
    CHECK(!secure_admin_clear_lockout() && count_ev(EV_API_VIOLATION) == 1, "clear_lockout w/o admin session refused + logged");
    adv(1100); CHECK(!secure_set_time(mk_epoch(2026, 1, 1, 0, 0)) && count_ev(EV_API_VIOLATION) == 2, "time change w/o admin refused (clock already set)");
    adv(1100); CHECK(!secure_api_probe(4) && last_arg(EV_API_VIOLATION) == 0x104, "delete_logs probe refused + logged");
    for (int i = 0; i < 200; i++) secure_api_probe(1);
    tg_stats_t x; get_security_statistics(&x);
    CHECK(x.api_violations >= 200 && count_ev(EV_API_VIOLATION) <= 3, "violation flood counted but cannot flush the log");
    tap(0);
    CHECK(secure_admin_clear_lockout() && secure_set_time(mk_epoch(2026, 10, 14, 11, 0)), "with admin session: accepted");

    printf("T15 tamper: naive state corruption (no re-seal)\n");
    fresh(WED); tg_state_t *s = tg_test_state();
    s->door_unlocked = 1; adv(20);
    CHECK(count_ev(EV_TAMPER) == 1 && g_servo == SERVO_LOCK_US_DEFAULT, "detected, state reset, latch locked");
    CHECK(tap(1) == TG_DENY_TAMPER, "lockdown denies taps");

    printf("T16 tamper: direct servo register write\n");
    fresh(WED); g_servo = SERVO_UNLOCK_US_DEFAULT; adv(20);
    CHECK(count_ev(EV_TAMPER) == 1 && last_arg(EV_TAMPER) == 2 && g_servo == SERVO_LOCK_US_DEFAULT, "detected + register restored");

    printf("T17 LIMIT: attacker who recomputes the seal\n");
    fresh(WED); s = tg_test_state(); s->door_unlocked = 1; s->hash = tg_state_hash(s); adv(20);
    CHECK(count_ev(EV_TAMPER) == 0 && g_servo == SERVO_UNLOCK_US_DEFAULT, "NOT detected: door opened silently (software isolation limit)");

    printf("\n%d checks, %d failed\n", checks, fails);
    return fails ? 1 : 0;
}
