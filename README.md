# TrustGate firmware + dashboard

STM32F103 Blue Pill, RC522, 2x IR, SG90, buzzer, LEDs, UART to laptop, ntfy push.

## 0. Parts checklist
Have (invoice): Blue Pill clone STM32F103**C8**T6 / HK32F103C8T6 (nominally 64 KB flash / 20 KB RAM; clones do not always have what the label says), RC522 + card + fob, 2x IR obstacle module, breadboard, jumpers (10 F-F, 20 M-F), 5x 330 R, LEDs, 5 V 2 A USB charger, servo.
Still to get: **USB-TTL adapter, 3.3 V logic** (CP2102 / CH340 / FT232: the only way to flash and to talk to the dashboard), **active buzzer 3-5 V**, a micro-USB cable for the Blue Pill, **470 uF electrolytic (>= 10 V)** for the servo, header pins soldered on the RC522 if they came loose in the bag (a pressed-in header is the classic "works only sometimes"). Optional: ST-Link V2, only if the clone chip does not answer the UART bootloader.

## 1. Wiring (3.3 V logic everywhere except the servo)
| Part | Pin | Blue Pill |
|---|---|---|
| RC522 | 3.3V, GND | 3V3, GND  (**never 5 V**) |
| RC522 | SDA/SS, SCK, MOSI, MISO, RST | PA4, PA5, PA7, PA6, PB0 (IRQ unused) |
| IR1 (outside beam) | VCC, GND, OUT | 3V3, GND, PB12 |
| IR2 (inside beam) | VCC, GND, OUT | 3V3, GND, PB13 |
| SG90 | red, brown, orange | 5V, GND, PA1 |
| Buzzer (active, 3.3 V ok) | +, - | PB14, GND |
| Green LED | PB8 -> 330R -> LED -> GND | |
| Red LED | PB9 -> 330R -> LED -> GND | |
| USB-TTL adapter (3.3 V) | GND, TX, RX | GND, PA10, PA9 (TX/RX crossed). **Do not connect its VCC** |

Power: USB charger -> Blue Pill micro-USB. All grounds common.
Put a 470 uF (or any 220-1000 uF) electrolytic across the servo's 5V/GND next to the servo: servo start-up current can brown-out the board. A reset shows up on the dashboard as BOOT with the reset cause.
Sensor placement: both beams chest height, ~10 cm apart along the walking direction. IR1 outside, IR2 inside.

## 2. Set your cards
Edit `secure/provisioned_cards.h` (UIDs + roles). Unknown taps show their UID in the dashboard (ACCESS_DENIED / UNKNOWN_CARD).

## 3. Build
The linker script (`STM32F103_32K_10K.ld`) is sized for the smallest F103 variant (C6: 32 KB flash / 10 KB RAM) as a safe floor, because a clone can carry less memory than its label claims; a real C8 simply has headroom. The firmware needs ~20 KB flash and ~2.2 KB static RAM. Do not use a 20 KB-RAM script: on a 10 KB part the stack would start in memory that does not exist and the board would be dead at power-up.
```
git clone --depth 1 https://github.com/STMicroelectronics/STM32CubeF1.git
cd STM32CubeF1/Drivers && rm -rf STM32F1xx_HAL_Driver CMSIS/Device/ST/STM32F1xx
git clone --depth 1 https://github.com/STMicroelectronics/stm32f1xx-hal-driver.git STM32F1xx_HAL_Driver
git clone --depth 1 https://github.com/STMicroelectronics/cmsis-device-f1.git CMSIS/Device/ST/STM32F1xx
cd ../../trustgate
make CUBE=../STM32CubeF1          # needs arm-none-eabi-gcc and make
make test                          # host unit tests (41 checks)
make fuzz                          # 48 M simulated ms of random traffic, invariants + ASAN/UBSAN
make boundary CUBE=../STM32CubeF1
```
Result: ~19.8 KB flash, ~2.2 KB static RAM (+ ~1 KB peak stack).

## 4. Flash (USB-TTL, no ST-Link)
BOOT0 jumper -> 1, press RESET, then `make flash PORT=COM5` (needs stm32flash), BOOT0 -> 0, RESET.

## 5. Dashboard
```
pip install pyserial requests
python tools/dashboard.py --port COM5 --ntfy-topic trustgate-<long-random-string>
```
Open http://127.0.0.1:8080. Install the ntfy app on the admin phone and subscribe to the same topic.
Optional: copy `tools/users.json.example` to `users.json` with your UIDs. The dashboard answers the board's `TIME?` request (at boot and every 5 s until synced); the clock is needed for the staff/guest time windows.

## 6. Calibrate the servo
Tap the admin card (opens a 30 s admin session), then send `CAL <lock_us> <unlock_us>` over serial (default 700 1700). Put final values in `include/tg_policy.h`.

## 7. Serial commands
PING, TIME n, STATUS, STATS, LOG, ACK*, UNLOCKOUT*, CAL a b*, PROBE 1..4  (* = needs admin session)

## 8. Attack experiments
Build with `EXTRA=-DTG_ATTACK_DEMO`; commands `ATTACK 1|2|3`:
1. Corrupt secure state, no re-seal -> TAMPER + lockdown (detected)
2. Corrupt + recompute seal -> door opens, nothing logged (NOT detected: no MPU on F103)
3. Write TIM2->CCR2 directly -> TAMPER arg 2, register restored
`PROBE 1..4` shows the slide's blocked calls being refused and logged.

## 9. Behaviour guarantees (checked by `make test` / `make fuzz`)
- The latch is only open while a valid grant or its short relock timer exists, and never longer than ~10 s after a valid tap.
- Reset (power glitch, watchdog) always comes back LOCKED. Sides (inside/outside) are unknown after a reset, so the first passage of each user is accepted in either direction and then learned: no false alarms after a reboot.
- A hang of the main loop or of SysTick triggers the ~1 s hardware watchdog; the dashboard pushes "WATCHDOG RESET".
- Refused-call floods are counted but rate-limited in the log so they cannot push real events out.
- The RC522 is re-checked once a second and re-initialised if it was reset by a supply dip or was not wired at boot (`WARN,RC522_RECOVERED` / `RC522_LOST`).
- Not covered by any test: real RC522 / IR range / servo torque / the clone chip's UART bootloader. That needs the hardware.

## 10. Test without hardware (firmware emulator)
```
pip install unicorn pyserial requests          # plus arm-none-eabi-gcc, then: make CUBE=../STM32CubeF1
python3 emu/suite.py                            # ~7 min, 160+ checks on the REAL build/trustgate.bin
python3 emu/e2e_dashboard.py                    # real tools/dashboard.py <-> emulated board <-> mock ntfy, ~1 min
```
Linux or WSL (needs `gcc` for a 10-line helper, `emu/tg_hook.c`, built automatically). `emu/tgemu.py` runs the firmware image on an emulated Cortex-M3 with the STM32F103 peripherals (RCC, GPIO, SPI1, USART1, TIM2, IWDG, SysTick/NVIC) and a board model (RC522 + Mifare card, IR beams, servo signal, buzzer, LEDs, host UART). It is written from the reference manual and datasheets, so it checks the firmware's init, pin setup, driver sequences, interrupt logic and policy, not analogue behaviour. Results: `emu/results.json`, `emu/RESULTS.md`.
