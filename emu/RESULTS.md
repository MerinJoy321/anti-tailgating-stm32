# Emulated test results

Real `build/trustgate.bin` on the emulated Blue Pill (see README section 10).

## boot  (17/17)

- PASS banner prints rc522=ok, ver, sysclk=72 MHz
- PASS boot event reports power-on reset (cause 3)
- PASS firmware asks the dashboard for time (TIME?)
- PASS RCC: SYSCLK 72 MHz, APB1 36 MHz (<=36), APB2 72 MHz
- PASS FLASH latency = 2 wait states at 72 MHz, prefetch on
- PASS servo pin PA1 carries 50 Hz PWM (period 20 ms)
- PASS servo boots in the LOCKED position (pulse 0.7 ms)
- PASS UART: BRR gives 115200 baud within 1 %
- PASS SysTick prio 15, USART1 prio 1, 4 preempt bits (BASEPRI scheme valid)
- PASS SysTick ticks at 1 kHz (HAL tick tracks real time)
- PASS IWDG running, timeout ~1 s at LSI 40 kHz
- PASS status says door LOCKED, 0 inside, no alarm
- PASS RAM budget on a 10 KB part: 2208 B static + 984 B peak stack of 10240 B
- PASS only the power-on reset happened (no watchdog)
- PASS no faults/errors
- PASS no clock-off / wiring / SPI-mode warnings
- PASS no unmodelled register accesses

## reader  (11/11)

- PASS unknown card held 3 s -> exactly ONE ACCESS_DENIED with its UID
- PASS door stays locked
- PASS card removed and presented again -> a second tap is counted
- PASS third fail inside 30 s -> LOCKOUT_START
- PASS 7-byte UID card: no access event, no lockout, no crash
- PASS ... and the firmware warns about the unsupported card
- PASS two cards in the field: collision, no access granted
- PASS one card removed: remaining card is read normally
- PASS no faults/errors
- PASS no clock-off / wiring / SPI-mode warnings
- PASS no unmodelled register accesses

## entry_exit  (12/12)

- PASS staff tap -> ACCESS_GRANTED, passage -> ENTRY_OK (in that order)
- PASS grant direction learned as 'any' after reset (arg 2)
- PASS servo physically unlocks after the tap (latency 71 ms)
- PASS servo relocks 1.2 s after the passage is confirmed (ENTRY_OK)
- PASS status: 1 person inside, door locked, no alarm
- PASS no alarm / buzzer alarm pattern during a legitimate entry
- PASS same card again -> grant 'OUT' (arg 1) -> EXIT_OK
- PASS status: 0 inside after the exit
- PASS door was never open without a tap: open intervals == 2
- PASS no faults/errors
- PASS no clock-off / wiring / SPI-mode warnings
- PASS no unmodelled register accesses

## tailgate  (11/11)

- PASS second person 0.7 s behind -> TAILGATE event
- PASS door relocked right after the tailgate
- PASS buzzer toggles during the alarm (>=6 transitions)
- PASS alarm shows in the 1 Hz status for ~6 s (6 reports), then clears by itself
- PASS walk-through with no tap -> UNAUTH_PASSAGE
- PASS ... and the door never opened for it
- PASS follower 3.5 s later (outside the tailgate window) -> UNAUTH_PASSAGE
- PASS follower gap sweep (ms after first person clears; negative = beams overlap): {-120: 'merged', 100: 'TAILGATE', 250: 'TAILGATE', 400: 'TAILGATE', 600: 'TAILGATE', 1000: 'TAILGATE'}
- PASS no faults/errors
- PASS no clock-off / wiring / SPI-mode warnings
- PASS no unmodelled register accesses

## passback  (5/5)

- PASS inside user's card used to enter again -> ANTIPASSBACK
- PASS outside user's tap + someone walking OUT -> DIR_MISMATCH
- PASS no faults/errors
- PASS no clock-off / wiring / SPI-mode warnings
- PASS no unmodelled register accesses

## policy  (17/17)

- PASS 3 unknown cards in 30 s -> LOCKOUT_START (30 s)
- PASS valid staff card during lockout -> denied (LOCKOUT)
- PASS admin card ends the lockout and opens an admin session
- PASS lockout ends by itself after 30 s
- PASS ... and the staff card works again
- PASS second tap while a grant is pending -> BUSY, not counted as a failure
- PASS tap but nobody walks: GRANT_TIMEOUT after ~6 s and door relocks, no alarm
- PASS ... door was open ~6 s, not longer
- PASS staff on Saturday -> denied (time window)
- PASS staff at 07:59 Wed -> denied (time window)
- PASS guest at 09:00 Wed -> denied (time window)
- PASS clock rolls over 08:00 -> staff now granted
- PASS admin works any time (Saturday)
- PASS clock never synced -> staff denied (UNSYNCED_CLOCK)
- PASS no faults/errors
- PASS no clock-off / wiring / SPI-mode warnings
- PASS no unmodelled register accesses

## api  (15/15)

- PASS ACK / UNLOCKOUT / CAL refused without an admin session (violations logged, rate-limited)
- PASS the refused CAL did not move the servo
- PASS admin card opens a session (ADMIN_SESSION)
- PASS CAL accepted in an admin session
- PASS new lock position reaches the servo pin (900 us)
- PASS TIME refused once the clock is synced and no admin session is open
- PASS PROBE: secure boundary refuses the call
- PASS production build has NO attack commands (ATTACK -> unknown command)
- PASS STATUS answers in the documented format
- PASS ATTACK 1 (naive tamper) is detected -> TAMPER event, door stays locked
- PASS ATTACK 3 (direct servo write) is detected -> TAMPER event, door stays locked
- PASS ATTACK 2 (forged unlock with recomputed seal) opens silently -- documented limit
- PASS no faults/errors
- PASS no clock-off / wiring / SPI-mode warnings
- PASS no unmodelled register accesses

## uart  (7/7)

- PASS 150 PING commands at 50/s while events print (+ one 200-char junk line) -> 150 replies
- PASS ... while a card event was being printed
- PASS no USART overrun (ORE) left pending
- PASS event sequence numbers contiguous
- PASS no faults/errors
- PASS no clock-off / wiring / SPI-mode warnings
- PASS no unmodelled register accesses

## ir  (8/8)

- PASS 40 glitches of 8 ms (< 20 ms debounce) -> no event, door locked
- PASS sensor recovers: normal entry works afterwards
- PASS beam stuck blocked > 30 s -> SENSOR_STUCK warning
- PASS ... and the system works again once the beam is freed
- PASS beams blocked > 1.5 s -> GROUP_SUSPECT warning
- PASS no faults/errors
- PASS no clock-off / wiring / SPI-mode warnings
- PASS no unmodelled register accesses

## reset  (12/12)

- PASS person is inside before the crash
- PASS watchdog resets a hung main loop
- PASS ... within ~1 s of the hang (1.00 s)
- PASS boot event carries reset cause 1 (watchdog)
- PASS door is locked again after the reset
- PASS first exit after the reset is accepted (side 'unknown'), NO false alarm
- PASS watchdog also recovers a total freeze (PRIMASK set)
- PASS power cycle while unlocked: boots LOCKED (was open: True)
- PASS NRST button -> boot cause 2
- PASS no faults/errors
- PASS no clock-off / wiring / SPI-mode warnings
- PASS no unmodelled register accesses

## hw_variants  (18/18)

- PASS no RC522 wired: banner says rc522=FAIL, firmware keeps running
- PASS ... and still detects an unauthorised passage
- PASS clone RC522 version byte 0x88 accepted and reads cards
- PASS clone RC522 version byte 0x12 accepted and reads cards
- PASS clone RC522 version byte 0x91 accepted and reads cards
- PASS RC522 reading 0x00 (miswired) -> rc522=FAIL
- PASS RC522 reading 0xFF (miswired) -> rc522=FAIL
- PASS slow RC522 oscillator start-up (45 ms) still initialises
- PASS crystal dead: falls back to 8 MHz HSI and says so
- PASS ... UART baud still within 3 % and a full entry works at 8 MHz
- PASS ... servo PWM still 20 ms period at 8 MHz
- PASS LSI 30 kHz: watchdog never trips; min margin 1.33 s
- PASS LSI 60 kHz: watchdog never trips; min margin 0.67 s
- PASS with the real 10 ms RC522 timeout (no emulator shortcut): entry works
- PASS 35 % of RC522 frames lost: every presentation still yields exactly one grant (3/3)
- PASS no faults/errors
- PASS no clock-off / wiring / SPI-mode warnings
- PASS no unmodelled register accesses

## recovery  (10/10)

- PASS reader works before the glitch
- PASS RC522 reset by a supply glitch: reader recovers by itself (card works 4 s later)
- PASS RC522 not answering at boot: banner says FAIL
- PASS RC522 wire fixed after boot: reader comes up without a power cycle
- PASS ... and the firmware reports RC522_RECOVERED
- PASS RC522 permanently absent: status keeps its 1 Hz cadence (max gap 1.05 s), no watchdog reset, no warning spam
- PASS ... still detects an unauthorised passage
- PASS no faults/errors
- PASS no clock-off / wiring / SPI-mode warnings
- PASS no unmodelled register accesses

## people  (7/7)

- PASS 45 legitimate passages with random speed/body width: 45 clean, no false alarm
- PASS people counter equals the number the test left inside (3)
- PASS slow walker caught by the 6 s expiry is still let through (ENTRY_OK, no alarm)
- PASS walker 1.5 s AFTER the grant expired -> GRANT_TIMEOUT then UNAUTH_PASSAGE
- PASS no faults/errors
- PASS no clock-off / wiring / SPI-mode warnings
- PASS no unmodelled register accesses

## reset_storm  (3/3)

- PASS 30 random resets (many in the middle of RC522 init): next boot is clean
- PASS ... and a full entry works afterwards
- PASS no faults, door locked

## bigger_chip  (2/2)

- PASS same binary on a 64 KB-flash / 20 KB-RAM clone (C8/CB): entry works
- PASS same binary on a 128 KB-flash / 20 KB-RAM clone (C8/CB): entry works

## soak  (9/9)

- PASS soak 150 s sim: 15 actions, 14 grants, 2 alarms
- PASS INVARIANT door open only after a grant, never longer than 6.0 s (limit 12)
- PASS INVARIANT no watchdog reset, no fault, no stack imbalance
- PASS INVARIANT event log has no gaps
- PASS peak stack 1016 B of 7520 B free RAM (>= 2x headroom)
- PASS status block still sane at the end
- PASS no faults/errors
- PASS no clock-off / wiring / SPI-mode warnings
- PASS no unmodelled register accesses

## dashboard_e2e  (14/14)

- PASS dashboard connects to the board over the (virtual) serial port and syncs the clock
- PASS web UI state lists every device event, in order (13 events)
- PASS status + statistics blocks arrive and parse (taps=5, tailgates=1)
- PASS clean start: events before the first tap are exactly BOOT, TIME_SET (no false API_VIOLATION push)
- PASS phone push fired for TAILGATE (urgent) and LOCKOUT_START (high)
- PASS watchdog reset reaches the phone (BOOT, high) and the clock is re-synced without a false violation
- PASS exactly 3 pushes, none for routine events (grants, entries, plain denials)
- PASS push text carries the plain-language reason
- PASS web command whitelist: STATS/PING accepted (200), CAL / ATTACK refused (403)
- PASS dashboard reports pushes sent = 3
- PASS CSV log has one row per event (13 rows)
- PASS both ends agree on the byte stream: dashboard saw no garbled lines
- PASS dashboard log has no traceback
- PASS device-side faults during the run: none
