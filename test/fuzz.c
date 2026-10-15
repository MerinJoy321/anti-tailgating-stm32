/* Randomised soak test of the secure core: random people, noise, taps, admin calls and reboots,
 * with safety/liveness invariants checked after EVERY millisecond. Usage: fuzz <seed> <millis> [quiet] */
#include <stdio.h>
#include <stdlib.h>
#include "../secure/secure_internal.h"
#include "../secure/secure_hw.h"
extern uint32_t g_now; extern bool g_a, g_b; extern uint16_t g_servo;
tg_state_t *tg_test_state(void);

static uint32_t rs;
static uint32_t rnd(void) { rs ^= rs << 13; rs ^= rs >> 17; rs ^= rs << 5; return rs; }
static uint32_t R(uint32_t lo, uint32_t hi) { return lo + rnd() % (hi - lo + 1); }

typedef struct { uint8_t s; uint32_t t0, t1; } iv_t;
static iv_t iv[256]; static int niv;
static void add(uint8_t s, uint32_t t0, uint32_t d) { if (niv < 256) iv[niv++] = (iv_t){s, t0, t0 + d}; }

static void spawn(uint32_t t)
{
    switch (rnd() % 8) {
    case 0: case 1: { uint32_t d = R(250, 600), o = R(60, 250); uint8_t f = rnd() & 1;   /* one person, in or out */
                      add(f, t, d); add(!f, t + o, d); break; }
    case 2: { uint32_t gap = R(0, 900), d = R(250, 500), o = R(60, 200); uint8_t f = rnd() & 1;  /* two people in a row */
              add(f, t, d); add(!f, t + o, d); add(f, t + d + gap, d); add(!f, t + d + gap + o, d); break; }
    case 3: add(rnd() & 1, t, R(5, 3000)); break;                       /* single-beam poke */
    case 4: for (int i = 0; i < 4; i++) add(rnd() & 1, t + R(0, 80), R(1, 30)); break;   /* electrical noise */
    case 5: { uint32_t d = R(500, 5000); add(0, t, d); add(1, t, d); break; }           /* group / loiterer */
    case 6: for (int i = 0; i < 5; i++) add(rnd() & 1, t + R(0, 2000), R(1, 700)); break; /* garbage */
    default: { uint32_t d = R(200, 500), o = R(0, 50); add(1, t, d); add(0, t + o, d); }  /* fast crosser */
    }
}

static int bad;
#define INV(c, msg) do { if (!(c)) { if (bad++ < 5) printf("INVARIANT BROKEN @%u: %s\n", g_now, msg); } } while (0)

int main(int argc, char **argv)
{
    rs = argc > 1 ? (uint32_t)atoi(argv[1]) * 2654435761u + 1 : 1;
    uint32_t N = argc > 2 ? (uint32_t)atoll(argv[2]) : 1000000;
    bool quiet = argc > 3 && atoi(argv[3]);   /* quiet: rare random traffic, working hours, mostly valid cards */
    uint32_t spawn_div = quiet ? 60000u : 1500u;
    g_a = g_b = false; g_servo = 0; secure_init();
    secure_set_time(quiet ? 1760436000u + R(0, 6u * 3600u) : 1760000000u + R(0, 86400u * 14));   /* quiet: a Wednesday 10:00-16:00 */
    uint32_t last_grant = 0; bool have_grant = false, reboots = 0 * 1;
    uint32_t seq_prev = 0, unlocked_taps = 0, reb = 0, taps = 0, grants = 0;
    tg_state_t *S = tg_test_state();

    for (uint32_t i = 0; i < N; i++) {
        uint32_t t = ++g_now;
        if (rnd() % spawn_div == 0) spawn(t);
        if (rnd() % 400000 == 0) add(rnd() & 1, t, R(8000, 40000));              /* stuck / misaligned beam */
        if (rnd() % 3000 == 0) {
            uint8_t uid[4]; int k = quiet ? (rnd() % 20 ? (int)(rnd() % TG_CARD_COUNT) : 5) : (int)(rnd() % 6);
            if (k < TG_CARD_COUNT) for (int j = 0; j < 4; j++) uid[j] = TG_CARDS[k].uid[j];
            else for (int j = 0; j < 4; j++) uid[j] = (uint8_t)rnd();
            taps++;
            if (secure_authorize_entry(uid) == TG_GRANT) {
                have_grant = true; last_grant = g_now; grants++;
                if (rnd() % 10 < (quiet ? 6u : 8u)) {                                   /* the card holder (and sometimes a follower) walks */
                    uint32_t at = t + R(100, 5500), d = R(250, 600), o = R(60, 250); uint8_t f = rnd() & 1;
                    add(f, at, d); add(!f, at + o, d);
                    if (rnd() % 10 < 4) { uint32_t g = R(0, 900); add(f, at + d + g, d); add(!f, at + d + g + o, d); }
                }
            }
        }
        if (rnd() % 150000 == 0) switch (rnd() % 5) {
            case 0: secure_admin_clear_lockout(); break; case 1: secure_admin_ack_alarm(); break;
            case 2: secure_set_time(1760000000u + R(0, 86400u * 14)); break; case 3: secure_api_probe((uint8_t)R(1, 4)); break;
            default: secure_admin_set_servo((uint16_t)R(300, 2700), (uint16_t)R(300, 2700));
        }
        if (rnd() % 400000 == 0) { g_servo = 0; secure_init(); have_grant = false; seq_prev = 0; reb++; }   /* power glitch / watchdog */

        bool a = false, b = false;
        for (int k = 0; k < niv; ) { if (t >= iv[k].t1) iv[k] = iv[--niv]; else { if (t >= iv[k].t0) { if (iv[k].s) b = true; else a = true; } k++; } }
        g_a = a; g_b = b;
        secure_tick_1ms();

        /* ---- invariants ---- */
        INV(S->magic == TG_MAGIC && tg_state_hash(S) == S->hash, "seal valid after every tick");
        INV(S->stats.tamper == 0, "no tamper without an attacker");
        INV(!S->door_unlocked || S->grant_active || S->relock_at, "unlocked => a grant or a pending relock exists");
        INV(!S->grant_active || (S->door_unlocked && S->grant_user >= 0 && S->grant_user < TG_CARD_COUNT), "grant => unlocked, valid user");
        INV(g_servo == (S->door_unlocked ? S->servo_unlock_us : S->servo_lock_us), "servo follows secure state");
        INV(!S->door_unlocked || (have_grant && (uint32_t)(g_now - last_grant) <= GRANT_TIMEOUT_MS + 3000u + RELOCK_AFTER_PASS_MS + 100u),
            "door never open without a recent valid tap, never open too long");
        for (int u = 0; u < TG_MAX_USERS; u++) INV(S->inside[u] <= 2, "inside value legal");
        INV(S->log_seq >= seq_prev, "log sequence monotonic"); seq_prev = S->log_seq;
        INV(S->stats.entries + S->stats.exits <= S->stats.granted, "every entry/exit consumed a grant");
        INV(S->stats.granted + S->stats.denied == S->stats.taps, "every tap is granted or denied");
        INV(S->fail_count < MAX_FAILS, "fail counter bounded");
        if (S->door_unlocked) unlocked_taps++;
    }
    tg_stats_t x; get_security_statistics(&x);
    printf("%s seed=%s ms=%u taps=%u grants=%u reboots=%u | entries=%u exits=%u tailgates=%u unauth=%u passback=%u mismatch=%u lockouts=%u groups=%u aborts=%u | %s\n",
           quiet ? "quiet" : "dense", argc > 1 ? argv[1] : "1", N, taps, grants, reb, x.entries, x.exits, x.tailgates, x.unauth_passages, x.antipassback,
           x.dir_mismatch, x.lockouts, x.group_suspect, x.aborts, bad ? "FAILED" : "all invariants held");
    return bad ? 1 : 0;
}
