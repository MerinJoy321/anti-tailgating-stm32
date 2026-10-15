/* TrustGate - tunable policy and timing constants (pure C, no HAL). */
#ifndef TG_POLICY_H
#define TG_POLICY_H

#define TG_FW_VERSION          "1.0.0"
#define TG_LOG_N               64      /* secure event ring buffer entries      */
#define TG_MAX_USERS           8       /* credential table capacity             */

/* ---- passage (IR) tracking, all in milliseconds ---- */
#define IR_DEBOUNCE_MS         20      /* sensor must be stable this long       */
#define IR_REARM_MS            120     /* ignore re-trigger of same beam (noise)*/
#define PASS_MIN_GAP_MS        350     /* min spacing of two same-direction people */
#define PENDING_TIMEOUT_MS     2500    /* single-beam trigger that never completes */
#define LONG_PASS_MS           1500    /* beams blocked this long => group suspect */
#define STUCK_MS               30000   /* beam blocked this long => sensor fault */

/* ---- access policy ---- */
#define GRANT_TIMEOUT_MS       6000    /* walk through within this after a tap  */
#define RELOCK_AFTER_PASS_MS   1200    /* relock this long after a valid passage*/
#define TAILGATE_WATCH_MS      3000    /* a 2nd same-direction passage in this window = tailgate */
#define MAX_FAILS              3       /* denied taps inside FAIL_WINDOW_MS ...  */
#define FAIL_WINDOW_MS         30000
#define LOCKOUT_MS             30000   /* ... trigger this lockout              */
#define ADMIN_SESSION_MS       30000   /* admin card tap opens an admin session */
#define TAMPER_LOCKDOWN_MS     20000
#define TG_REQUIRE_CLOCK_SYNC  1       /* non-admin denied while clock unsynced */

/* ---- alarms ---- */
#define ALARM_TAILGATE_MS      6000
#define ALARM_UNAUTH_MS        8000
#define ALARM_LOCKOUT_MS       6000
#define ALARM_TAMPER_MS        10000
#define ALARM_WARN_MS          1500

/* ---- servo (SG90) pulse widths in microseconds; calibrate with CAL cmd ---- */
#define SERVO_LOCK_US_DEFAULT   700
#define SERVO_UNLOCK_US_DEFAULT 1700

#endif
