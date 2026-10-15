# TrustGate: Test Plan, Measurements and Isolation Analysis

**Group 9, Microcontroller Project. Prepared 13 October 2026.**

This document turns the project goals (*"measure security and system performance through defined attack and access tests"*, *"compare software isolation with hardware TrustZone"*, *"determine the boundary of what low-cost software security can protect"*) into runnable tests with expected results, a measurement procedure, and an honest analysis. Result columns are blank on purpose: fill them in on the real board.

---

## 1. What is already verified, and what is not

| Layer | Evidence | What it does NOT prove |
|---|---|---|
| **Secure-core logic (PC build)** | 41 deterministic tests; randomised soak of 48 million simulated milliseconds (8 seeds, dense and quiet traffic) under address and undefined-behaviour sanitizers, with 12 safety and liveness invariants checked every millisecond | Real sensors, real timing jitter |
| **Test strength** | 7 deliberately planted bugs; 6 caught by the soak, the 7th (tamper check disabled) caught by the unit tests. One planted bug survived the first soak and exposed a blind spot (traffic too dense), which was then fixed | That bugs of a kind nobody thought of are absent |
| **Firmware binary (emulator)** | 178 recorded checks on the real firmware image running in an emulated Cortex-M3 with modelled peripherals; all 16 sections re-run independently with no failures; end-to-end test with the real dashboard passed 14/14 | The emulator was written from the same datasheets by the same side as the firmware. A shared misunderstanding of the RC522, the clone chip or the clock tree would not be caught |
| **Build boundary** | Script checks that non-secure objects only reference the public API symbols | Anything at run time (see section 5) |
| **Real hardware** | Nothing yet | Everything in sections 2 to 4 below |

**Sizes (from the build):** about 19.8 KB flash, about 2.2 KB static RAM, about 1 KB peak stack (peak stack measured in the emulator).

---

## 2. Access tests (run on the real board)

**Precondition for all:** cards provisioned in `secure/provisioned_cards.h`, dashboard running, clock synced (dashboard shows "synced"), laptop clock inside staff hours (Mon to Fri, 08:00 to 18:00) unless the test says otherwise. Events appear in the dashboard feed and the CSV log.

| ID | Procedure | Expected result | Result | Pass/Fail |
|---|---|---|---|---|
| **A1** | Power on | Banner shows `rc522=ok` and `sysclk=72000000`; `BOOT` event with cause power-on | | |
| **A2** | Block each IR beam by hand | Dashboard beam indicators follow each beam; `ST` line IR field changes between `00`, `10`, `01`, `11` | | |
| **A3** | Staff card tap, walk in (IR1 then IR2) | `ACCESS_GRANTED`, `ENTRY_OK`, servo unlocks, relocks about 1.2 s after the passage, no alarm | | |
| **A4** | Same card tap, walk out | `ACCESS_GRANTED` (exit expected), `EXIT_OK` | | |
| **A5** | Unknown card | `ACCESS_DENIED` reason `UNKNOWN_CARD` with its UID, door stays locked, three-beep buzzer | | |
| **A6** | Three unknown taps within 30 s, then staff card, then admin card | `LOCKOUT_START` (30 s); staff denied `LOCKOUT`; admin card ends lockout (`LOCKOUT_END`) | | |
| **A7** | Guest card at 09:00 (window 10:00 to 16:00), or any staff card on Sunday | `ACCESS_DENIED` reason `OUTSIDE_TIME_WINDOW`. To change the time: change the laptop clock, then reset the board (it asks for time at boot) | | |
| **A8** | Tap, do not walk | `GRANT_TIMEOUT` after 6 s, door relocks | | |
| **A9** | Walk through with no tap | `UNAUTH_PASSAGE`, 8 s alarm, door never unlocks, push notification | | |
| **A10** | One tap, two people in single file 0.3 s, 0.6 s, 1.0 s apart | `ENTRY_OK` then `TAILGATE`, alarm, push notification | | |
| **A11** | Passback: person enters; hands the card to a person outside; that person taps and walks in | Tap grants an exit (user is inside), passage is inward: `ANTIPASSBACK` | | |
| **A12** | Known-outside user taps and walks out | `DIR_MISMATCH` | | |
| **A13** | Power-cycle the board with a person inside, then that person taps and exits | No false alarm: after a reset the first passage is accepted in either direction and the side is learned | | |
| **A14** | Unplug and replug the RC522 3.3 V wire | `WARN RC522_LOST` then `RC522_RECOVERED` within a few seconds, taps work again | | |

---

## 3. Attack tests

> **Build Note:** Build with `make EXTRA=-DTG_ATTACK_DEMO` for B4 to B6 only. Use the normal build for everything else.

| ID | Attack | Expected result | Class | Result |
|---|---|---|---|---|
| **B1** | Card with a copied UID (needs a UID-changeable "magic" card) | Accepted as the real user | NOT stopped (design limit, section 5.3) | |
| **B2** | `PROBE 1` to `PROBE 4` (read credentials, direct unlatch, reset state, delete logs) | Refused, `API_VIOLATION` logged (rate-limited to one log line per second, all counted) | Blocked | |
| **B3** | `ACK`, `UNLOCKOUT`, `CAL 700 1700` without a recent admin card tap; `TIME n` after the clock is synced | `ERR`, `API_VIOLATION` logged | Blocked | |
| **B4** | `ATTACK 1`: forge secure state without recomputing the integrity seal | `TAMPER` event, 20 s lockdown, door locked, alarm | Detected | |
| **B5** | `ATTACK 3`: write the servo PWM register directly | `TAMPER` (argument 2), register restored within about 1 ms | Detected | |
| **B6** | `ATTACK 2`: forge state and recompute the seal | Door opens, no event, no alarm | NOT detected (the isolation limit, section 5.2) | |
| **B7** | Cover IR1 with tape for 40 s | `SENSOR_STUCK` warning after 30 s; observe what tailgate detection does while the beam is blocked | Degrades (sensing is fail-open) | |
| **B8** | Pull power while the door is unlocked | Board restarts with the door locked | Fails safe | |
| **B9** | Close the dashboard or unplug the laptop, then cause a tailgate | Local buzzer and LEDs still alarm; no phone push | Alert path depends on the laptop | |

---

## 4. Performance and accuracy measurements

### 4.1 Decision latency (on-chip)
After at least 50 taps send `STATS`. Record `decision_us_last` and `decision_us_max` (measured with the Cortex-M3 cycle counter around the whole decision, including the integrity re-seal). Report the maximum, not only the last value.

### 4.2 Tap-to-unlock latency
Film the servo and the card at 240 frames per second (phone slow motion). Count frames from the beep to the first servo movement. The command is issued within the same millisecond as the decision; the visible delay is mechanical.

### 4.3 Detection accuracy
Run at least 30 trials per scenario with several different people, same door, same sensor spacing (about 10 cm along the walking direction, chest height). Compute detection rate and false-alarm rate.

| Scenario | Trials | Correct outcome | Correct | Wrong | Rate |
|---|---|---|---|---|---|
| One person in, own tap | 30 | `ENTRY_OK`, no alarm | | | |
| One person out, own tap | 30 | `EXIT_OK`, no alarm | | | |
| Tailgater 0.3 s behind | 30 | `TAILGATE` | | | |
| Tailgater 0.6 s behind | 30 | `TAILGATE` | | | |
| Tailgater 1.0 s behind | 30 | `TAILGATE` | | | |
| Two people shoulder to shoulder | 30 | `TAILGATE` (expected to be missed) | | | |
| Person turns back at the door | 30 | no entry recorded | | | |

*For reference, the emulator's gap sweep (a model, not hardware) detected a follower at 100 ms to 1000 ms after the first person cleared the beams, and merged two people whose bodies overlapped the beams. Compare your measured results with that model and explain any difference.*

### 4.4 Alert latency
Cause 10 tailgates. Stopwatch from the passage to the ntfy notification on the phone. Report median and worst case. This depends on the laptop, the network and the ntfy server, so state the network used.

### 4.5 Soak
Leave the system powered for at least one hour with the dashboard connected. Count `BOOT` events other than the first: any `BOOT` with cause `WATCHDOG` is a failure to investigate. Check that the event feed has no gaps.

---

## 5. Isolation analysis: software Secure/Non-Secure versus TrustZone

### 5.1 What TrustGate's software separation does
- Credentials, policy, state, log and actuator control live in separate source files with file-local state. The only exported symbols are the 16 API functions; a build script fails if non-secure code references anything else.
- Only one call can grant access and unlock (`secure_authorize_entry`). Privileged operations need a recent admin card tap; refused attempts are counted and logged.
- The secure state carries an integrity seal checked every 8 ms and on every API call. The servo compare register is checked against what the secure side last commanded.
- Critical sections mask only the lowest-priority interrupt, so the UART interrupt keeps running.

**This defends against:** honest but buggy non-secure code, accidental corruption, naive tampering, and misuse of the public API.

### 5.2 Where it stops
The Blue Pill's STM32F103 core has no hardware memory protection that this firmware can use. The Cortex-M3 MPU is optional in the core; a 2019 mailing-list comparison of ST datasheets found a memory-protection section in the XL-density F103 overview but none in the medium-density (C8/CB) one, and an ST staff answer says STM32 parts of this class do not include an MPU. Confirm this in your own STM32F103x8/xB datasheet (section 2.3, Overview) before quoting it; this report states it as strongly indicated, not as read from the silicon. The earlier statement "the F103 has no MPU" was too broad: it applies to the medium-density part on your board.

**Consequence, demonstrated by B6:** code running in the non-secure side shares the address space with the secure side. If it knows the layout and the seal algorithm it can rewrite secure state and recompute the seal, and the secure side cannot tell. The integrity seal is an error-detection code, not a cryptographic check, and nothing outside the same chip holds a key.

### 5.3 Credential weakness unrelated to isolation
The system identifies a card by its UID only. On genuine MIFARE Classic cards the UID is read-only, but UID-changeable "magic" cards are sold for a few euros and the Crypto1 cipher of the Classic family is documented as broken (Radboud University, 2008; later card-only attacks). So a cloned UID passes (test B1). Mitigations in order of effort: sector authentication (still weak on Classic), a challenge-response card family such as DESFire, or a second factor such as a PIN.

### 5.4 What TrustZone for Cortex-M changes
TrustZone for Armv8-M exists on Cortex-M23 and Cortex-M33 parts, not on Cortex-M3. It adds Secure and Non-secure processor states, where the state follows the address the code is fetched from. Memory is attributed by the SAU and the implementation's IDAU as Secure, Non-secure, or Non-secure-callable (NSC). Non-secure code cannot read or write secure memory or execute secure code; it can only enter the secure side by branching into an NSC region at an SG (secure gateway) instruction. Any other access raises a `SecureFault`. Stack pointers and some core registers are banked per state. Peripherals can be assigned to the secure side, so a non-secure program cannot write the servo timer or read the credential store. A DMA engine programmed from the non-secure side can still reach secure memory unless the silicon filters it, so the part's DMA security attributes matter.

| Threat | TrustGate on STM32F103 (measured) | TrustZone-M part (expected, not measured by this project) |
|---|---|---|
| **Non-secure code calls an undocumented secure function** | Blocked at build time only; at run time a hostile program can jump anywhere | Only SG entry points in the NSC region are reachable |
| **Non-secure code reads or writes secure RAM** | Allowed by hardware; detected only if the seal is not recomputed (B4 versus B6) | `SecureFault` |
| **Non-secure code writes the actuator timer or GPIO** | Allowed; detected after the fact for the servo register (B5) | Peripheral assigned to the secure side, write faults |
| **Seal recomputed by attacker** | Undetected (B6) | Not applicable: access never succeeds |
| **Cloned card UID** | Accepted (B1) | Accepted: separate problem, needs a better credential |
| **Laptop compromised** | Push alerts can be suppressed; local alarm still works (B9) | Same |

### 5.5 Porting estimate (not done, not measured)
Because `secure_api.h` is already narrow, a port to a TrustZone-capable board would keep `secure/` and the non-secure sources largely as they are. The work would be: split into two projects; replace the 16 API calls with NSC veneers; configure SAU and peripheral security attributions so the servo timer, IR pins, buzzer and credential flash belong to the secure side; remove the integrity seal and the register check (the hardware makes them unnecessary). A transition between states on a Cortex-M33 is reported to cost on the order of tens of cycles; since the decision happens once per card tap, this is negligible here. Treat this paragraph as a plan, not a result.

### 5.6 Conclusion to state in the report
Software-defined separation on a Cortex-M3 with no memory protection gives a real, testable improvement against bugs and naive attacks, and it keeps the security logic small and auditable. It does not give isolation against a hostile program in the same address space: test B6 is the concrete demonstration, and the boundary is exactly there. Anything that must hold against compromised non-secure code needs a hardware boundary (TrustZone on M23/M33, or at minimum an MPU-based partition on a part that has one), and anything involving cloned credentials needs a stronger card technology independent of the isolation question.

---

## 6. Known limits to disclose
- Shoulder-to-shoulder walking is counted as one person; it is flagged only if both beams stay blocked longer than 1.5 s.
- Event log, inside/outside state and clock are RAM only; a reset forgets them (the state is relearned safely, the log is lost).
- Cards are compiled in; there is no runtime enrollment.
- Sensing is fail-open: a covered or misaligned beam stops passage detection (B7).
- Timing constants (`IR_REARM_MS`, `PASS_MIN_GAP_MS`, `LONG_PASS_MS`) need tuning on the real door.
- No tests so far cover real RC522 range, real IR sensitivity, servo torque, or whether the clone chip accepts the UART bootloader.

---

## 7. Sources
- Gnuk-users mailing list, *"Utilizing Memory Protection Unit on STM32?"*, February 2019 (datasheet comparison): [lists.gnupg.org/pipermail/gnuk-users/2019-February/000180.html](https://lists.gnupg.org/pipermail/gnuk-users/2019-February/000180.html) and [000181.html](https://lists.gnupg.org/pipermail/gnuk-users/2019-February/000181.html)
- ST Community, *"MPU"* (answer that STM32 does not include an MPU): [community.st.com/stm32-mcus-products-25/mpu-115747](https://community.st.com/stm32-mcus-products-25/mpu-115747)
- Silicon Labs docs, *"TrustZone Basics"*: [docs.silabs.com/btmesh/9.0.2/series2-trustzone/02-r-basic](https://docs.silabs.com/btmesh/9.0.2/series2-trustzone/02-r-basic)
- Mete Balci, *"Demystifying a very simple TrustZone enabled program on ARM Cortex-M33"*: [metebalci.com/blog/hello-trustzone/](https://metebalci.com/blog/hello-trustzone/)
- NXP application note AN13156 (TrustZone Cortex-M33, SAU, IDAU, NSC, SG): [nxp.com/docs/en/application-note/AN13156.pdf](https://nxp.com/docs/en/application-note/AN13156.pdf)
- AC6 Formation, *"TrustZone on Cortex-M: isolation, TF-M and what PSA really guarantees"* (DMA caveat, transition cost order of magnitude): [ac6-formation.com/en/articles/trustzone-cortex-m-isolation-tfm](https://ac6-formation.com/en/articles/trustzone-cortex-m-isolation-tfm)
- Radboud University Nijmegen press release on the MIFARE Classic flaw, 12 March 2008: [sos.cs.ru.nl/applications/rfid/pressrelease.en.html](https://sos.cs.ru.nl/applications/rfid/pressrelease.en.html)
- Almeida, *"Hacking MIFARE Classic Cards"*, Black Hat Arsenal 2014 (UID-changeable cards, Crypto1): [blackhat.com/docs/sp-14/materials/arsenal/sp-14-Almeida-Hacking-MIFARE-Classic-Cards-Slides.pdf](https://blackhat.com/docs/sp-14/materials/arsenal/sp-14-Almeida-Hacking-MIFARE-Classic-Cards-Slides.pdf)
- Mifare security survey, MECO 2023: [crypto.fit.cvut.cz/sites/default/files/publications/fulltexts/MECO_2023_FinalVersion_36_0.pdf](https://crypto.fit.cvut.cz/sites/default/files/publications/fulltexts/MECO_2023_FinalVersion_36_0.pdf)
