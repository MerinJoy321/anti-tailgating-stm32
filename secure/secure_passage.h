/* Pure-logic two-beam passage tracker (no hardware access, unit-testable on a PC).
 * Sensor 1 (IR1) is on the OUTSIDE, sensor 2 (IR2) on the INSIDE of the doorway.
 * IR1 then IR2 = IN, IR2 then IR1 = OUT.  Call passage_step() once per millisecond. */
#ifndef SECURE_PASSAGE_H
#define SECURE_PASSAGE_H
#include <stdint.h>
#include <stdbool.h>

typedef enum { PE_NONE = 0, PE_IN, PE_OUT, PE_ABORT, PE_LONG, PE_STUCK } pe_kind_t;
typedef struct { uint8_t kind; uint16_t arg; } pass_event_t;

typedef struct {
    bool a, b;                         /* debounced "beam blocked" */
    uint8_t ca, cb;                    /* debounce counters        */
    bool has_fall_a, has_fall_b; uint32_t fall_a, fall_b;
    bool pend_a, pend_b; uint32_t pend_a_ms, pend_b_ms;
    bool a_owned_out, b_owned_in;      /* current blockage already attributed to a counted person */
    bool has_last_in, has_last_out; uint32_t last_in, last_out;
    bool any; uint32_t any_since; bool stuck_sent;
} passage_t;

void    passage_init(passage_t *p, bool raw_a, bool raw_b, uint32_t now);
uint8_t passage_step(passage_t *p, bool raw_a, bool raw_b, uint32_t now, pass_event_t out[4]);
#endif
