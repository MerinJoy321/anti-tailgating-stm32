/* SECURE credential store (compile-time provisioned, lives in flash).
 * Replace the UIDs below with your cards' UIDs. A denied tap prints the UID
 * on the serial line / dashboard (event ACCESS_DENIED, reason UNKNOWN_CARD). */
#ifndef PROVISIONED_CARDS_H
#define PROVISIONED_CARDS_H
#include <stdint.h>
#include "../include/tg_policy.h"

typedef enum { TG_ROLE_ADMIN = 0, TG_ROLE_STAFF = 1, TG_ROLE_GUEST = 2, TG_ROLE_COUNT } tg_role_t;
typedef struct { uint8_t uid[4]; uint8_t role; } tg_card_t;

static const tg_card_t TG_CARDS[] = {
    { {0xDE, 0xAD, 0xBE, 0x01}, TG_ROLE_ADMIN },   /* <- replace with your admin card UID  */
    { {0xDE, 0xAD, 0xBE, 0x02}, TG_ROLE_STAFF },   /* <- staff card                         */
    { {0xDE, 0xAD, 0xBE, 0x03}, TG_ROLE_STAFF },   /* <- second staff card (tailgate demo)  */
    { {0xDE, 0xAD, 0xBE, 0x04}, TG_ROLE_GUEST },   /* <- guest card                         */
};
#define TG_CARD_COUNT ((int)(sizeof(TG_CARDS) / sizeof(TG_CARDS[0])))

/* Role time rules: days bitmask (bit0=Sunday ... bit6=Saturday), minutes of day [start,end) */
typedef struct { uint8_t days; uint16_t start_min, end_min; } tg_rule_t;
static const tg_rule_t TG_RULES[TG_ROLE_COUNT] = {
    [TG_ROLE_ADMIN] = { 0x7F,    0, 1440 },   /* any time                  */
    [TG_ROLE_STAFF] = { 0x3E,  480, 1080 },   /* Mon-Fri 08:00-18:00       */
    [TG_ROLE_GUEST] = { 0x3E,  600,  960 },   /* Mon-Fri 10:00-16:00       */
};
#endif
