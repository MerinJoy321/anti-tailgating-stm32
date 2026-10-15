/* TrustGate SECURE WORLD core: authentication, policy, anti-passback, lockout,
 * anti-tailgating decisions, event log, statistics, actuator authority.
 * All state is file-static: the only symbols exported are the functions in secure_api.h. */
#include <string.h>
#include "secure_internal.h"
#include "secure_hw.h"
#include "secure_passage.h"

static tg_state_t s_state;
#define S s_state
static passage_t  s_pass;
static volatile bool s_ready;
static bool     s_dirty;
static uint32_t s_last_verify_ms, s_last_servo_tamper_ms;
static bool     s_servo_tamper_seen;
static uint16_t s_servo_cmd;          /* last pulse width WE commanded (0 = none yet) */
static uint32_t s_us_last, s_us_max;  /* decision latency, kept outside the sealed state */
static uint32_t s_last_viol_ms; static bool s_viol_seen;
static uint8_t  s_beep_pat;
static uint32_t s_beep_start;

enum { BEEP_NONE = 0, BEEP_GRANT, BEEP_DENY, BEEP_WARN };
static const uint16_t PAT_GRANT[] = { 120, 0 };
static const uint16_t PAT_DENY[]  = { 90, 90, 90, 90, 90, 0 };
static const uint16_t PAT_WARN[]  = { 300, 0 };
static const uint16_t *const PATS[] = { 0, PAT_GRANT, PAT_DENY, PAT_WARN };

static const char *const EV_NAMES[EV_TYPE_COUNT] = {
    [0] = "NONE", [EV_BOOT] = "BOOT", [EV_ACCESS_GRANTED] = "ACCESS_GRANTED", [EV_ACCESS_DENIED] = "ACCESS_DENIED",
    [EV_ENTRY_OK] = "ENTRY_OK", [EV_EXIT_OK] = "EXIT_OK", [EV_TAILGATE] = "TAILGATE",
    [EV_UNAUTH_PASSAGE] = "UNAUTH_PASSAGE", [EV_ANTIPASSBACK] = "ANTIPASSBACK", [EV_DIR_MISMATCH] = "DIR_MISMATCH",
    [EV_LOCKOUT_START] = "LOCKOUT_START", [EV_LOCKOUT_END] = "LOCKOUT_END", [EV_GRANT_TIMEOUT] = "GRANT_TIMEOUT",
    [EV_PASSAGE_ABORT] = "PASSAGE_ABORT", [EV_GROUP_SUSPECT] = "GROUP_SUSPECT", [EV_SENSOR_STUCK] = "SENSOR_STUCK",
    [EV_API_VIOLATION] = "API_VIOLATION", [EV_TAMPER] = "TAMPER", [EV_ADMIN_SESSION] = "ADMIN_SESSION",
    [EV_TIME_SET] = "TIME_SET", [EV_CONFIG] = "CONFIG", [EV_ALARM_ACK] = "ALARM_ACK",
};
static const char *const DEC_NAMES[TG_DENY_COUNT] = {
    "GRANT", "UNKNOWN_CARD", "DISABLED", "OUTSIDE_TIME_WINDOW", "CLOCK_UNSYNCED", "LOCKOUT", "BUSY", "TAMPER_LOCKDOWN"
};

/* ---------------------------------------------------------------- helpers */
static inline bool reached(uint32_t now, uint32_t t) { return (int32_t)(now - t) >= 0; }
static inline bool active_until(uint32_t now, uint32_t t) { return t != 0 && !reached(now, t); }
static inline uint32_t epoch_now(uint32_t now) { return S.epoch_base + (now - S.tick_base) / 1000u; }
static inline void seal(void)   { S.hash = tg_state_hash(&S); s_dirty = false; }

static void state_defaults(uint32_t keep_seq)
{
    memset(&S, 0, sizeof S);
    S.magic = TG_MAGIC;
    for (int i = 0; i < TG_MAX_USERS; i++) { S.enabled[i] = i < TG_CARD_COUNT; S.inside[i] = TG_UNKNOWN; }
    S.servo_lock_us = SERVO_LOCK_US_DEFAULT;
    S.servo_unlock_us = SERVO_UNLOCK_US_DEFAULT;
    S.log_seq = keep_seq;
}

static void log_event(uint8_t type, int8_t user, const uint8_t *uid, uint16_t arg)
{
    uint32_t now = hw_now_ms();
    tg_event_t *e = &S.log[S.log_seq % TG_LOG_N];
    memset(e, 0, sizeof *e);
    e->tick_ms = now;
    e->epoch = S.time_valid ? epoch_now(now) : 0;
    if (uid) memcpy(e->uid, uid, 4);
    else if (user >= 0 && user < TG_CARD_COUNT) memcpy(e->uid, TG_CARDS[user].uid, 4);
    e->type = type; e->user = user; e->arg = arg;
    S.log_seq++;
    s_dirty = true;
}

static void raise_alarm(uint32_t ms)
{
    uint32_t until = hw_now_ms() + ms;
    if (!active_until(hw_now_ms(), S.alarm_until) || (int32_t)(until - S.alarm_until) > 0) S.alarm_until = until ? until : 1;
    s_dirty = true;
}

static void beep(uint8_t pat) { s_beep_pat = pat; s_beep_start = hw_now_ms(); }

static bool beep_is_on(uint32_t now)
{
    if (!s_beep_pat) return false;
    const uint16_t *seg = PATS[s_beep_pat];
    uint32_t t = now - s_beep_start, acc = 0;
    for (int i = 0; seg[i]; i++) { acc += seg[i]; if (t < acc) return (i % 2) == 0; }
    s_beep_pat = BEEP_NONE;
    return false;
}

/* push the secure state to the actuators; call after every state change.
 * Also detects a servo compare register that was changed behind our back. */
static void apply_hw(void)
{
    uint32_t now = hw_now_ms();
    uint16_t live = hw_servo_get_us();
    uint16_t want = S.door_unlocked ? S.servo_unlock_us : S.servo_lock_us;
    if (s_servo_cmd && live != s_servo_cmd) {
        if (!s_servo_tamper_seen || (uint32_t)(now - s_last_servo_tamper_ms) >= 2000u) {
            s_servo_tamper_seen = true; s_last_servo_tamper_ms = now;
            S.stats.tamper++; log_event(EV_TAMPER, -1, NULL, 2); raise_alarm(ALARM_TAMPER_MS);
        }
        live = 0;                                       /* force rewrite */
    }
    if (live != want) hw_servo_set_us(want);
    s_servo_cmd = want;
    bool on = active_until(now, S.alarm_until) ? ((now % 600u) < 400u) : beep_is_on(now);
    hw_buzzer(on);
}

static void do_tamper(uint16_t source)
{
    uint32_t seq = S.log_seq, now = hw_now_ms();
    state_defaults(seq);
    S.tamper_lockdown = 1;
    S.lockdown_until = now + TAMPER_LOCKDOWN_MS;
    S.stats.tamper++;
    log_event(EV_TAMPER, -1, NULL, source);
    raise_alarm(ALARM_TAMPER_MS);
    memset(&s_pass, 0, sizeof s_pass);
    bool a, b; hw_ir_read(&a, &b); passage_init(&s_pass, a, b, now);
    s_servo_cmd = 0;                                    /* tamper already reported */
    apply_hw();
    seal();
}

static bool verify_state(uint16_t source)
{
    if (S.magic == TG_MAGIC && tg_state_hash(&S) == S.hash) return true;
    do_tamper(source);
    return false;
}

static bool time_rule_ok(uint8_t role, uint32_t now)
{
    uint32_t e = epoch_now(now), day = e / 86400u;
    uint8_t wd = (uint8_t)((day + 4u) % 7u);           /* 1970-01-01 was a Thursday; 0 = Sunday */
    uint16_t min = (uint16_t)((e % 86400u) / 60u);
    const tg_rule_t *r = &TG_RULES[role];
    return ((r->days >> wd) & 1u) && min >= r->start_min && min < r->end_min;
}

static bool admin_session_open(uint32_t now) { return active_until(now, S.admin_until); }

static void api_violation(uint16_t code)
{
    uint32_t now = hw_now_ms();
    S.stats.api_violations++;
    /* rate-limited log: a flood of refused calls must not evict real security events from the ring */
    if (!s_viol_seen || (uint32_t)(now - s_last_viol_ms) >= 1000u) { s_viol_seen = true; s_last_viol_ms = now; log_event(EV_API_VIOLATION, -1, NULL, code); }
    beep(BEEP_DENY);
    s_dirty = true;
}

static uint8_t inside_count(void)
{
    uint8_t n = 0;
    for (int i = 0; i < TG_CARD_COUNT && i < TG_MAX_USERS; i++) n += (S.inside[i] == 1);
    return n;
}

/* ---------------------------------------------------------------- policy API */
int8_t secure_authenticate(const uint8_t uid[4])
{
    for (int i = 0; i < TG_CARD_COUNT && i < TG_MAX_USERS; i++)
        if (memcmp(TG_CARDS[i].uid, uid, 4) == 0) return (int8_t)i;
    return -1;
}

static tg_decision_t check_permission_locked(int8_t user, uint32_t now)
{
    if (S.tamper_lockdown) return TG_DENY_TAMPER;
    if (user < 0 || user >= TG_CARD_COUNT || user >= TG_MAX_USERS) return TG_DENY_UNKNOWN_CARD;
    if (!S.enabled[user]) return TG_DENY_DISABLED;
    uint8_t role = TG_CARDS[user].role;
    if (role != TG_ROLE_ADMIN) {
        if (active_until(now, S.lockout_until)) return TG_DENY_LOCKOUT;
        if (!S.time_valid) return TG_REQUIRE_CLOCK_SYNC ? TG_DENY_UNSYNCED_CLOCK : TG_GRANT;
        if (!time_rule_ok(role, now)) return TG_DENY_TIME;
    }
    return TG_GRANT;
}

tg_decision_t secure_check_permission(int8_t user)
{
    uint32_t p = hw_irq_save();
    verify_state(1);
    tg_decision_t d = check_permission_locked(user, hw_now_ms());
    if (s_dirty) seal();
    hw_irq_restore(p);
    return d;
}

tg_decision_t secure_authorize_entry(const uint8_t uid[4])
{
    uint32_t p = hw_irq_save();
    uint32_t c0 = hw_cycles();
    verify_state(1);
    uint32_t now = hw_now_ms();
    S.stats.taps++;

    int8_t user = secure_authenticate(uid);
    tg_decision_t d;
    if (S.tamper_lockdown) d = TG_DENY_TAMPER;
    else if (S.grant_active) d = TG_DENY_BUSY;
    else d = check_permission_locked(user, now);

    if (d == TG_GRANT) {
        bool admin = TG_CARDS[user].role == TG_ROLE_ADMIN;
        if (admin) {
            if (active_until(now, S.lockout_until)) { S.lockout_until = 0; S.fail_count = 0; log_event(EV_LOCKOUT_END, user, NULL, 1); }
            S.admin_until = now + ADMIN_SESSION_MS;
            log_event(EV_ADMIN_SESSION, user, NULL, 0);
        }
        S.fail_count = 0;
        S.grant_active = 1; S.grant_user = user;
        S.grant_dir = S.inside[user] == TG_UNKNOWN ? TG_DIR_ANY : (S.inside[user] ? TG_DIR_OUT : TG_DIR_IN);
        S.grant_deadline = now + GRANT_TIMEOUT_MS;
        S.door_unlocked = 1; S.relock_at = 0;
        S.stats.granted++;
        log_event(EV_ACCESS_GRANTED, user, uid, S.grant_dir);
        beep(BEEP_GRANT);
    } else {
        S.stats.denied++;
        log_event(EV_ACCESS_DENIED, user, uid, (uint16_t)d);
        beep(BEEP_DENY);
        bool counts = (d == TG_DENY_UNKNOWN_CARD || d == TG_DENY_DISABLED || d == TG_DENY_TIME || d == TG_DENY_UNSYNCED_CLOCK);
        if (counts) {
            if (S.fail_count == 0 || (uint32_t)(now - S.fail_window_start) > FAIL_WINDOW_MS) { S.fail_count = 0; S.fail_window_start = now; }
            if (++S.fail_count >= MAX_FAILS) {
                S.lockout_until = now + LOCKOUT_MS; S.fail_count = 0;
                S.stats.lockouts++;
                log_event(EV_LOCKOUT_START, -1, NULL, (uint16_t)(LOCKOUT_MS / 1000));
                raise_alarm(ALARM_LOCKOUT_MS);
            }
        }
    }
    apply_hw();
    seal();
    s_us_last = (hw_cycles() - c0) / hw_cycles_per_us();
    if (s_us_last > s_us_max) s_us_max = s_us_last;
    hw_irq_restore(p);
    return d;
}

/* ---------------------------------------------------------------- passage handling */
static void on_passage(uint8_t dir, uint32_t now)
{
    if (S.grant_active) {
        int8_t u = S.grant_user;
        if (S.grant_dir == TG_DIR_ANY || dir == S.grant_dir) {
            S.inside[u] = (dir == TG_DIR_IN) ? 1 : 0;
            if (dir == TG_DIR_IN) { S.stats.entries++; log_event(EV_ENTRY_OK, u, NULL, 0); }
            else                  { S.stats.exits++;   log_event(EV_EXIT_OK, u, NULL, 0); }
            S.grant_active = 0;
            S.watch_until = now + TAILGATE_WATCH_MS; S.watch_dir = dir; S.watch_user = u;
            S.relock_at = now + RELOCK_AFTER_PASS_MS;
        } else {
            if (S.grant_dir == TG_DIR_OUT) {        /* card of a person who is already inside used to enter again */
                S.stats.antipassback++; log_event(EV_ANTIPASSBACK, u, NULL, 0);
            } else {
                S.stats.dir_mismatch++; log_event(EV_DIR_MISMATCH, u, NULL, 0);
            }
            S.grant_active = 0; S.door_unlocked = 0; S.relock_at = 0;
            raise_alarm(ALARM_UNAUTH_MS);
        }
        return;
    }
    if (active_until(now, S.watch_until) && dir == S.watch_dir) {
        S.stats.tailgates++;
        log_event(EV_TAILGATE, S.watch_user, NULL, dir);
        raise_alarm(ALARM_TAILGATE_MS);
    } else {
        S.stats.unauth_passages++;
        log_event(EV_UNAUTH_PASSAGE, -1, NULL, dir);
        raise_alarm(ALARM_UNAUTH_MS);
    }
    S.door_unlocked = 0; S.relock_at = 0;               /* never leave the latch open after a violation */
}

/* ---------------------------------------------------------------- 1 ms tick */
void secure_tick_1ms(void)
{
    if (!s_ready) return;
    uint32_t now = hw_now_ms();
    bool a, b;
    hw_ir_read(&a, &b);

    if ((uint32_t)(now - s_last_verify_ms) >= 8u) {
        s_last_verify_ms = now;
        if (!verify_state(3)) return;
    }

    pass_event_t ev[4];
    uint8_t n = passage_step(&s_pass, a, b, now, ev);
    for (uint8_t i = 0; i < n; i++) {
        switch (ev[i].kind) {
        case PE_IN:  on_passage(TG_DIR_IN, now);  break;
        case PE_OUT: on_passage(TG_DIR_OUT, now); break;
        case PE_ABORT: S.stats.aborts++; if (S.grant_active) log_event(EV_PASSAGE_ABORT, S.grant_user, NULL, ev[i].arg); s_dirty = true; break;
        case PE_LONG: S.stats.group_suspect++; log_event(EV_GROUP_SUSPECT, -1, NULL, ev[i].arg); raise_alarm(ALARM_WARN_MS); break;
        case PE_STUCK: log_event(EV_SENSOR_STUCK, -1, NULL, 0); raise_alarm(ALARM_WARN_MS); break;
        }
    }

    if (S.grant_active && reached(now, S.grant_deadline) && (!s_pass.any || reached(now, S.grant_deadline + 3000u))) {
        S.grant_active = 0; S.door_unlocked = 0; S.relock_at = 0;
        log_event(EV_GRANT_TIMEOUT, S.grant_user, NULL, 0);
    }
    if (S.relock_at && reached(now, S.relock_at)) { S.door_unlocked = 0; S.relock_at = 0; s_dirty = true; }
    if (S.lockout_until && reached(now, S.lockout_until)) { S.lockout_until = 0; log_event(EV_LOCKOUT_END, -1, NULL, 0); }
    if (S.tamper_lockdown && reached(now, S.lockdown_until)) { S.tamper_lockdown = 0; s_dirty = true; }
    if (S.alarm_until && reached(now, S.alarm_until)) { S.alarm_until = 0; s_dirty = true; }
    if (S.admin_until && reached(now, S.admin_until)) { S.admin_until = 0; s_dirty = true; }
    if (S.watch_until && reached(now, S.watch_until)) { S.watch_until = 0; s_dirty = true; }
    if (S.time_valid && (uint32_t)(now - S.tick_base) >= 3600000u) { S.epoch_base += 3600u; S.tick_base += 3600000u; s_dirty = true; }

    apply_hw();
    if (s_dirty) seal();
}

/* ---------------------------------------------------------------- init & views */
void secure_init(void)
{
    hw_init();
    s_servo_cmd = 0; s_servo_tamper_seen = false; s_beep_pat = BEEP_NONE; s_us_last = s_us_max = 0; s_viol_seen = false;
    state_defaults(0);
    bool a, b; hw_ir_read(&a, &b);
    passage_init(&s_pass, a, b, hw_now_ms());
    log_event(EV_BOOT, -1, NULL, hw_reset_cause());
    apply_hw();
    seal();
    s_last_verify_ms = hw_now_ms();
    s_ready = true;
}

void get_access_status(tg_status_t *o)
{
    uint32_t p = hw_irq_save(), now = hw_now_ms();
    verify_state(1);
    memset(o, 0, sizeof *o);
    o->door_unlocked = S.door_unlocked; o->grant_active = S.grant_active;
    o->inside_count = inside_count();
    o->alarm_active = active_until(now, S.alarm_until);
    o->time_valid = S.time_valid; o->tamper_lockdown = S.tamper_lockdown;
    o->admin_session = admin_session_open(now);
    o->admin_remaining_s = o->admin_session ? (uint16_t)((S.admin_until - now) / 1000u) : 0;
    o->lockout_remaining_s = active_until(now, S.lockout_until) ? (uint16_t)((S.lockout_until - now) / 1000u) : 0;
    bool a, b; hw_ir_read(&a, &b); o->ir1 = a; o->ir2 = b;
    if (s_dirty) seal();
    hw_irq_restore(p);
}

void get_security_statistics(tg_stats_t *o)
{
    uint32_t p = hw_irq_save();
    verify_state(1);
    *o = S.stats; o->decision_us_last = s_us_last; o->decision_us_max = s_us_max;
    if (s_dirty) seal();
    hw_irq_restore(p);
}

uint32_t secure_log_next_seq(void) { uint32_t p = hw_irq_save(); uint32_t s = S.log_seq; hw_irq_restore(p); return s; }

bool secure_log_read(uint32_t seq, tg_event_t *o)
{
    uint32_t p = hw_irq_save();
    bool ok = (seq < S.log_seq) && ((S.log_seq - seq) <= TG_LOG_N);
    if (ok) *o = S.log[seq % TG_LOG_N];
    hw_irq_restore(p);
    return ok;
}

const char *secure_event_name(uint8_t t)   { return (t < EV_TYPE_COUNT && EV_NAMES[t]) ? EV_NAMES[t] : "?"; }
const char *secure_decision_name(uint8_t d) { return d < TG_DENY_COUNT ? DEC_NAMES[d] : "?"; }

/* ---------------------------------------------------------------- gated calls */
bool secure_set_time(uint32_t local_epoch)
{
    uint32_t p = hw_irq_save(), now = hw_now_ms();
    verify_state(1);
    bool ok = false;
    if (local_epoch >= 1700000000u && (!S.time_valid || admin_session_open(now))) {
        S.epoch_base = local_epoch; S.tick_base = now; S.time_valid = 1;
        log_event(EV_TIME_SET, -1, NULL, 0);
        ok = true;
    } else api_violation(0x10);
    seal();
    hw_irq_restore(p);
    return ok;
}

bool secure_admin_clear_lockout(void)
{
    uint32_t p = hw_irq_save(), now = hw_now_ms();
    verify_state(1);
    bool ok = admin_session_open(now);
    if (ok) { S.lockout_until = 0; S.fail_count = 0; log_event(EV_LOCKOUT_END, -1, NULL, 2); }
    else api_violation(0x11);
    seal();
    hw_irq_restore(p);
    return ok;
}

bool secure_admin_ack_alarm(void)
{
    uint32_t p = hw_irq_save(), now = hw_now_ms();
    verify_state(1);
    bool ok = admin_session_open(now);
    if (ok) { S.alarm_until = 0; log_event(EV_ALARM_ACK, -1, NULL, 0); apply_hw(); }
    else api_violation(0x12);
    seal();
    hw_irq_restore(p);
    return ok;
}

bool secure_admin_set_servo(uint16_t lock_us, uint16_t unlock_us)
{
    uint32_t p = hw_irq_save(), now = hw_now_ms();
    verify_state(1);
    bool ok = admin_session_open(now) && lock_us >= 400 && lock_us <= 2600 && unlock_us >= 400 && unlock_us <= 2600 && lock_us != unlock_us;
    if (ok) { S.servo_lock_us = lock_us; S.servo_unlock_us = unlock_us; log_event(EV_CONFIG, -1, NULL, 1); apply_hw(); }
    else api_violation(0x13);
    seal();
    hw_irq_restore(p);
    return ok;
}

bool secure_api_probe(uint8_t which)
{
    uint32_t p = hw_irq_save();
    verify_state(1);
    api_violation((uint16_t)(0x100u + which));
    seal();
    hw_irq_restore(p);
    return false;
}

#ifdef TG_HOST_TEST
tg_state_t *tg_test_state(void) { return &s_state; }
#endif
