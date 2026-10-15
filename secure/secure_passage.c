#include "secure_passage.h"
#include "../include/tg_policy.h"

void passage_init(passage_t *p, bool ra, bool rb, uint32_t now)
{
    *p = (passage_t){0};
    p->a = ra; p->b = rb;
    p->any = ra || rb;
    p->any_since = now;
}

static void push(pass_event_t *o, uint8_t *n, uint8_t kind, uint16_t arg)
{
    if (*n < 4) { o[*n].kind = kind; o[*n].arg = arg; (*n)++; }
}

static bool rearm_blocked(bool has, uint32_t fall, uint32_t now)
{
    return has && (uint32_t)(now - fall) < IR_REARM_MS;
}

static void emit_in(passage_t *p, uint32_t now, pass_event_t *o, uint8_t *n)
{
    p->pend_a = false;
    p->b_owned_in = true;
    if (p->has_last_in && (uint32_t)(now - p->last_in) < PASS_MIN_GAP_MS) return; /* too close: same person */
    p->has_last_in = true; p->last_in = now;
    push(o, n, PE_IN, 0);
}

static void emit_out(passage_t *p, uint32_t now, pass_event_t *o, uint8_t *n)
{
    p->pend_b = false;
    p->a_owned_out = true;
    if (p->has_last_out && (uint32_t)(now - p->last_out) < PASS_MIN_GAP_MS) return;
    p->has_last_out = true; p->last_out = now;
    push(o, n, PE_OUT, 0);
}

uint8_t passage_step(passage_t *p, bool ra, bool rb, uint32_t now, pass_event_t out[4])
{
    uint8_t n = 0;
    bool edge_a = false, edge_b = false;

    if (ra != p->a) { if (++p->ca >= IR_DEBOUNCE_MS) { p->a = ra; p->ca = 0; edge_a = true; } } else p->ca = 0;
    if (rb != p->b) { if (++p->cb >= IR_DEBOUNCE_MS) { p->b = rb; p->cb = 0; edge_b = true; } } else p->cb = 0;

    if (edge_a) {
        if (p->a) {                                   /* A rising */
            if (!rearm_blocked(p->has_fall_a, p->fall_a, now)) {
                if ((p->b && !p->b_owned_in) || (!p->b && p->pend_b)) emit_out(p, now, out, &n);
                else { p->pend_a = true; p->pend_a_ms = now; }
            }
        } else { p->has_fall_a = true; p->fall_a = now; p->a_owned_out = false; }
    }
    if (edge_b) {
        if (p->b) {                                   /* B rising */
            if (!rearm_blocked(p->has_fall_b, p->fall_b, now)) {
                if ((p->a && !p->a_owned_out) || (!p->a && p->pend_a)) emit_in(p, now, out, &n);
                else { p->pend_b = true; p->pend_b_ms = now; }
            }
        } else { p->has_fall_b = true; p->fall_b = now; p->b_owned_in = false; }
    }

    if (p->pend_a && (uint32_t)(now - p->pend_a_ms) > PENDING_TIMEOUT_MS) { p->pend_a = false; push(out, &n, PE_ABORT, 1); }
    if (p->pend_b && (uint32_t)(now - p->pend_b_ms) > PENDING_TIMEOUT_MS) { p->pend_b = false; push(out, &n, PE_ABORT, 2); }

    bool any = p->a || p->b;
    if (any && !p->any) { p->any_since = now; p->stuck_sent = false; }
    if (!any && p->any) {
        uint32_t d = now - p->any_since;
        if (d > LONG_PASS_MS) push(out, &n, PE_LONG, d > 65535u ? 65535u : (uint16_t)d);
    }
    if (any && !p->stuck_sent && (uint32_t)(now - p->any_since) > STUCK_MS) { p->stuck_sent = true; push(out, &n, PE_STUCK, 0); }
    p->any = any;
    return n;
}
