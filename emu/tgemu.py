#!/usr/bin/env python3
"""tgemu - run the REAL TrustGate firmware image (build/trustgate.bin) on an emulated Blue Pill.

Cortex-M3 core: Unicorn (QEMU TCG). RCC, FLASH, GPIO, AFIO, SPI1, USART1, TIM2, IWDG, SysTick/NVIC/SCB/DWT and the
board (RC522 + Mifare card, 2 IR modules, SG90 signal, buzzer, LEDs, host UART) are written here from the reference
manual / datasheets. It is a stand-in, not silicon: it proves the firmware's init, driver sequences, interrupt logic
and pin configuration against a model, it cannot prove analogue behaviour (IR range, servo torque, brown-out).
"""
import struct, subprocess, random, heapq, collections, ctypes, os
from unicorn import *
from unicorn.arm_const import *

FLASH, SRAM, TRAMP, PAGE = 0x08000000, 0x20000000, 0x1FFFF000, 0x1000
CPI, MAX_SPAN = 1.5, 0.25e-3        # never run the CPU more than 250 us without re-checking peripherals/events
CYC_PER_BYTE = CPI / 2.75           # ~2.75 bytes per Thumb-2 instruction on average
_HERE = os.path.dirname(os.path.abspath(__file__))
if not os.path.exists(os.path.join(_HERE, "tg_hook.so")):
    subprocess.check_call(["gcc", "-O2", "-shared", "-fPIC", "-o", os.path.join(_HERE, "tg_hook.so"), os.path.join(_HERE, "tg_hook.c")])
_hook = ctypes.CDLL(os.path.join(_HERE, "tg_hook.so"))
_hook.tg_used.restype = ctypes.c_uint64; _hook.tg_budget.argtypes = [ctypes.c_uint64]
# exception-return stub (assembled from tramp.s): unstack r0-r3,r12,lr,pc,flags in guest code
TRAMP_CODE = bytes.fromhex("0798069941f00101079180f3008800980199029a039bddf810c0ddf814e007b000bd")


def crc_a(data):
    crc = 0x6363
    for b in data:
        b ^= crc & 0xFF
        b = (b ^ (b << 4)) & 0xFF
        crc = ((crc >> 8) ^ (b << 8) ^ (b << 3) ^ (b >> 4)) & 0xFFFF
    return bytes([crc & 0xFF, crc >> 8])


def load_symbols(elf):
    out = subprocess.run(["arm-none-eabi-nm", "-n", elf], capture_output=True, text=True).stdout
    syms = {}
    for ln in out.splitlines():
        p = ln.split()
        if len(p) == 3:
            syms[p[2]] = int(p[0], 16)
    return syms


class Periph:
    size, gate, base = 0x400, None, 0
    def __init__(s, sim): s.sim = sim; s.reset()
    def reset(s): pass
    def rd(s, r): return 0
    def peek(s, r): return s.rd(r)
    def wr(s, r, v): pass
    def next_time(s): return None


# --------------------------------------------------------------------------------------------- RCC / FLASH
class RCC(Periph):
    base = 0x40021000
    def __init__(s, sim): s.flags = 0; super().__init__(sim)
    def reset(s):
        s.hsion, s.hseon, s.pllon, s.hsebyp, s.csson, s.trim = 1, 0, 0, 0, 0, 0x10
        s.cfgr, s.cir, s.ahbenr, s.apb2enr, s.apb1enr, s.bdcr = 0, 0, 0x14, 0, 0, 0
        s.lsion, s.lsi_at, s.hse_at, s.pll_at = 0, None, None, None
        s.sws, s.sw_to, s.sws_at = 0, 0, None
    def clk_on(s, bus, bit): return (getattr(s, bus + "enr") >> bit) & 1
    def hse_rdy(s): return bool(s.hseon and s.sim.hse_ok and s.hse_at is not None and s.sim.t >= s.hse_at)
    def pll_rdy(s):
        if not s.pllon or s.pll_at is None or s.sim.t < s.pll_at: return False
        return (not (s.cfgr >> 16) & 1) or s.hse_rdy()
    def lsi_rdy(s): return bool(s.lsion and s.lsi_at is not None and s.sim.t >= s.lsi_at)
    def force_lsi(s):
        if not s.lsion: s.lsion = 1; s.lsi_at = s.sim.t + 100e-6
    def _sync(s):
        if s.sws_at is not None and s.sim.t >= s.sws_at:
            ok = {0: True, 1: s.hse_rdy(), 2: s.pll_rdy()}.get(s.sw_to, False)
            if ok:
                if s.sw_to != s.sws:
                    s.sws = s.sw_to; s.sim.on_clock_change()
                s.sws_at = None
    def sysclk(s):
        s._sync()
        if s.sws == 0: return 8_000_000
        if s.sws == 1: return s.sim.hse_hz
        src = (s.sim.hse_hz // (2 if (s.cfgr >> 17) & 1 else 1)) if (s.cfgr >> 16) & 1 else 4_000_000
        return src * min(((s.cfgr >> 18) & 0xF) + 2, 16)
    def hclk(s):
        h = (s.cfgr >> 4) & 0xF
        return s.sysclk() // (1 if h < 8 else (2, 4, 8, 16, 64, 128, 256, 512)[h - 8])
    def pclk(s, n):
        f = (s.cfgr >> (8 if n == 1 else 11)) & 7
        div = 1 if f < 4 else (2, 4, 8, 16)[f - 4]
        return s.hclk() // div, div
    def tim_clk(s, n): p, d = s.pclk(n); return p * (1 if d == 1 else 2)
    def rd(s, r):
        s._sync()
        if r == 0x00:
            v = s.hsion | (2 if (s.hsion or s.sws == 0) else 0) | (s.trim << 3) | (0x8C << 8)
            if s.hseon: v |= 1 << 16
            if s.hse_rdy(): v |= 1 << 17
            v |= (s.hsebyp << 18) | (s.csson << 19)
            if s.pllon: v |= 1 << 24
            if s.pll_rdy(): v |= 1 << 25
            return v
        if r == 0x04: return (s.cfgr & ~0xC) | (s.sws << 2)
        if r == 0x08: return s.cir
        if r == 0x14: return s.ahbenr
        if r == 0x18: return s.apb2enr
        if r == 0x1C: return s.apb1enr
        if r == 0x20: return s.bdcr
        if r == 0x24: return s.lsion | (2 if s.lsi_rdy() else 0) | s.flags
        return 0
    def wr(s, r, v):
        s._sync(); t = s.sim.t
        if r == 0x00:
            if ((v >> 16) & 1) and not s.hseon: s.hse_at = t + 0.002
            if not (v >> 16) & 1: s.hse_at = None
            s.hseon = (v >> 16) & 1; s.hsebyp = (v >> 18) & 1; s.csson = (v >> 19) & 1
            if ((v >> 24) & 1) and not s.pllon: s.pll_at = t + 150e-6
            if not (v >> 24) & 1: s.pll_at = None
            s.pllon = (v >> 24) & 1
            if (v & 1) or s.sws != 0: s.hsion = v & 1
            s.trim = (v >> 3) & 0x1F
        elif r == 0x04:
            s.cfgr = v & ~0xC; s.sw_to = v & 3; s.sws_at = t + 4e-6
        elif r == 0x08: s.cir = v
        elif r == 0x14: s.ahbenr = v
        elif r == 0x18: s.apb2enr = v
        elif r == 0x1C: s.apb1enr = v
        elif r == 0x20: s.bdcr = v
        elif r == 0x24:
            s.lsion = v & 1
            if s.lsion and s.lsi_at is None: s.lsi_at = t + 100e-6
            if v & (1 << 24): s.flags = 0
    def next_time(s):
        c = [x for x in (s.hse_at, s.pll_at, s.sws_at, s.lsi_at) if x is not None and x > s.sim.t]
        return min(c) if c else None


class FLASHIF(Periph):
    base = 0x40022000
    def reset(s): s.lat, s.hlf, s.pre = 0, 0, 1
    def rd(s, r):
        if r == 0: return s.lat | (s.hlf << 3) | (s.pre << 4) | (s.pre << 5)
        return {0x10: 0x80, 0x1C: 0x03FFFFFC}.get(r, 0)
    def wr(s, r, v):
        if r == 0: s.lat, s.hlf, s.pre = v & 7, (v >> 3) & 1, (v >> 4) & 1


# --------------------------------------------------------------------------------------------- GPIO / AFIO
class GPIO(Periph):
    def __init__(s, sim, port, base, bit): s.port, s.base, s.gate = port, base, ("apb2", bit); super().__init__(sim)
    def reset(s): s.crl = s.crh = 0x44444444; s.odr = 0
    def cfg(s, p):
        n = ((s.crh if p >= 8 else s.crl) >> (4 * (p % 8))) & 0xF
        return n & 3, n >> 2
    def kind(s, p):
        m, c = s.cfg(p)
        if m == 0: return ("in_analog", "in_float", "in_pull", "in_res")[c]
        return ("out_pp", "out_od", "af_pp", "af_od")[c]
    def out_level(s, p):
        m, c = s.cfg(p)
        if m == 0: return None
        if c < 2: return (s.odr >> p) & 1
        return s.sim.af_level(s.port, p)
    def idr(s):
        v = 0
        for p in range(16):
            m, c = s.cfg(p)
            if m == 0:
                if c == 0: lvl = 0
                else:
                    lvl = s.sim.board.pin_in(s.port, p)
                    if lvl is None: lvl = ((s.odr >> p) & 1) if c == 2 else 0
            else: lvl = s.out_level(p)
            v |= (lvl & 1) << p
        return v
    def rd(s, r):
        return {0x00: s.crl, 0x04: s.crh, 0x0C: s.odr}.get(r) if r in (0, 4, 0x0C) else (s.idr() if r == 8 else 0)
    def wr(s, r, v):
        if r in (0x00, 0x04):
            cur = s.crl if r == 0 else s.crh; base = 0 if r == 0 else 8
            pins = [base + i for i in range(8) if ((cur ^ v) >> (4 * i)) & 0xF]
            old = {p: s.out_level(p) for p in pins}
            if r == 0: s.crl = v & 0xFFFFFFFF
            else: s.crh = v & 0xFFFFFFFF
        else:
            if r == 0x0C: new = v & 0xFFFF
            elif r == 0x10: new = (s.odr & ~((v >> 16) & 0xFFFF) | (v & 0xFFFF)) & 0xFFFF
            elif r == 0x14: new = s.odr & ~(v & 0xFFFF)
            else: return
            diff = new ^ s.odr
            if not diff: return
            pins = [p for p in range(16) if (diff >> p) & 1]
            old = {p: s.out_level(p) for p in pins}; s.odr = new
        for p in pins:
            n = s.out_level(p)
            if n != old[p]: s.sim.board.pin_out(s.port, p, n)


class AFIO(Periph):
    base, gate = 0x40010000, ("apb2", 0)
    def reset(s): s.regs = {}
    def rd(s, r): return s.regs.get(r, 0)
    def wr(s, r, v): s.regs[r] = v
    @property
    def mapr(s): return s.regs.get(4, 0)


# --------------------------------------------------------------------------------------------- SPI1
class SPI(Periph):
    base, gate = 0x40013000, ("apb2", 12)
    def reset(s): s.cr1 = s.cr2 = s.dr = 0; s.sr = 0x02; s.crcpr = 7; s.ovr_seq = False
    def rd(s, r):
        if r == 0x00: return s.cr1
        if r == 0x04: return s.cr2
        if r == 0x08:
            v = s.sr
            if s.ovr_seq: s.sr &= ~0x40; s.ovr_seq = False
            return v
        if r == 0x0C: s.sr &= ~1; s.ovr_seq = True; return s.dr
        return s.crcpr if r == 0x10 else 0
    def peek(s, r): return s.dr if r == 0x0C else (s.sr if r == 8 else s.rd(r))
    def _modf(s):
        if (s.cr1 & 0x04) and (s.cr1 & 0x200) and not (s.cr1 & 0x100):     # master, SSM=1, SSI=0 -> NSS seen low
            s.sr |= 0x20; s.cr1 &= ~0x44                                    # MODF: MSTR and SPE cleared by hardware
    def wr(s, r, v):
        if r == 0x00: s.cr1 = v & 0xFFFF; s._modf()
        elif r == 0x04: s.cr2 = v
        elif r == 0x0C:
            if not (s.cr1 & 0x40) or not (s.cr1 & 0x04): return
            rx = s.sim.board.spi_xfer(v & (0xFFFF if s.cr1 & 0x800 else 0xFF), s)
            if s.sr & 1: s.sr |= 0x40
            else: s.dr = rx; s.sr |= 1


# --------------------------------------------------------------------------------------------- USART1
class USART(Periph):
    base, gate = 0x40013800, ("apb2", 14)
    def reset(s):
        s.cr1 = s.cr2 = s.cr3 = s.brr = s.gtpr = 0
        s.rxne = s.ore = False; s.dr = 0; s.sr_seen = False
        s.pending, s.shift_until = None, 0.0
        s.rxq = collections.deque()
    def baud(s):
        d = (s.brr >> 4) + (s.brr & 15) / 16
        return s.sim.rcc.pclk(2)[0] / (16 * d) if d else 0
    def baud_ok(s): b = s.baud(); return b > 0 and abs(b / 115200 - 1) < 0.03
    def _tx(s):
        if s.pending is not None and s.sim.t >= s.shift_until:
            s._shift(s.pending, s.shift_until); s.pending = None
    def _shift(s, byte, start):
        b = s.baud(); s.shift_until = start + (10.0 / b if b else 0)
        s.sim.board.uart_tx(byte, s.shift_until, s.baud_ok())
    def _rx(s):
        t = s.sim.t
        while s.rxq and s.rxq[0][0] <= t:
            _, b = s.rxq.popleft()
            if not (s.cr1 & 0x2000) or not (s.cr1 & 4): continue                     # UE and RE
            if s.sim.gpio["A"].cfg(10)[0] != 0: continue                               # PA10 must be an input
            if not s.baud_ok(): b = s.sim.rng.randrange(256)
            if s.rxne: s.ore = True
            else: s.dr, s.rxne = b, True
    def txe(s): s._tx(); return s.pending is None
    def tc(s): s._tx(); return s.pending is None and s.sim.t >= s.shift_until
    def feed(s, data):
        b = s.baud() or 115200.0; t = max(s.sim.t, s.rxq[-1][0] + 10.0 / b if s.rxq else s.sim.t)
        for x in data: s.rxq.append((t, x)); t += 10.0 / 115200
    def irq_level(s):
        s._rx(); s._tx()
        if not (s.cr1 & 0x2000): return False
        return bool(((s.cr1 & 0x20) and (s.rxne or s.ore)) or ((s.cr1 & 0x80) and s.txe()) or ((s.cr1 & 0x40) and s.tc()))
    def rd(s, r):
        s._rx(); s._tx()
        if r == 0x00:
            s.sr_seen = True
            return (0x20 if s.rxne else 0) | (0x08 if s.ore else 0) | (0x40 if s.tc() else 0) | (0x80 if s.txe() else 0)
        if r == 0x04:
            v = s.dr; s.rxne = False
            if s.sr_seen: s.ore = False
            s.sr_seen = False; return v
        return {0x08: s.brr, 0x0C: s.cr1, 0x10: s.cr2, 0x14: s.cr3, 0x18: s.gtpr}.get(r, 0)
    def peek(s, r): return s.dr if r == 4 else s.rd(r) if r != 0 else 0
    def wr(s, r, v):
        s._rx(); s._tx()
        if r == 0x04:
            if not (s.cr1 & 0x2000) or not (s.cr1 & 8): s.sim.warn("USART1 DR written while UE/TE off"); return
            if s.pending is not None: s.sim.warn("USART1 DR written while TXE=0 (byte lost)"); return
            if s.sim.t >= s.shift_until: s._shift(v & 0xFF, s.sim.t)
            else: s.pending = v & 0xFF
        elif r == 0x08: s.brr = v & 0xFFFF
        elif r == 0x0C: s.cr1 = v & 0xFFFF
        elif r == 0x10: s.cr2 = v
        elif r == 0x14: s.cr3 = v
        elif r == 0x18: s.gtpr = v
    def next_time(s):
        c = [x for x in ((s.rxq[0][0] if s.rxq else None), (s.shift_until if (s.pending is not None or s.shift_until > s.sim.t) else None)) if x is not None and x > s.sim.t]
        return min(c) if c else None


# --------------------------------------------------------------------------------------------- TIM2
class TIM(Periph):
    base, gate = 0x40000000, ("apb1", 0)
    def reset(s):
        s.cr1 = s.cr2 = s.smcr = s.dier = s.sr = s.ccmr1 = s.ccmr2 = s.ccer = s.psc = s.arr = s.t0 = 0
        s.ccr = [0] * 4; s.a_psc = s.a_arr = 0; s.a_ccr = [0] * 4; s.run_t0 = 0.0
    def _f(s): return max(s.sim.rcc.tim_clk(1), 1)
    def _period(s): return (s.a_arr + 1) * (s.a_psc + 1) / s._f()
    def _sync(s):
        if s.cr1 & 1:
            p = s._period()
            if p > 0 and s.sim.t - s.run_t0 >= p:
                s.a_psc, s.a_arr = s.psc, s.arr
                s.a_ccr = list(s.ccr)
                s.run_t0 += int((s.sim.t - s.run_t0) / p) * p
                s.sr |= 1
    def pwm(s, ch):
        s._sync()
        if not (s.cr1 & 1) or not (s.ccer >> (4 * (ch - 1))) & 1: return None
        ocm = ((s.ccmr1 if ch <= 2 else s.ccmr2) >> (4 + 8 * ((ch - 1) & 1))) & 7
        if ocm not in (6, 7): return None
        tick = (s.a_psc + 1) / s._f()
        return dict(period=(s.a_arr + 1) * tick, pulse=s.a_ccr[ch - 1] * tick, pol=(s.ccer >> (4 * (ch - 1) + 1)) & 1, ocm=ocm)
    def rd(s, r):
        s._sync()
        regs = {0x00: s.cr1, 0x04: s.cr2, 0x08: s.smcr, 0x0C: s.dier, 0x10: s.sr, 0x18: s.ccmr1, 0x1C: s.ccmr2, 0x20: s.ccer, 0x28: s.psc, 0x2C: s.arr}
        if r in regs: return regs[r]
        if r == 0x24:
            if not (s.cr1 & 1): return s.t0
            return int(((s.sim.t - s.run_t0) * s._f() / (s.a_psc + 1)) % (s.a_arr + 1))
        if 0x34 <= r <= 0x40: return s.ccr[(r - 0x34) // 4]
        return 0
    def wr(s, r, v):
        s._sync(); v &= 0xFFFF
        if r == 0x00:
            if (v & 1) and not (s.cr1 & 1): s.run_t0 = s.sim.t
            s.cr1 = v
        elif r == 0x04: s.cr2 = v
        elif r == 0x08: s.smcr = v
        elif r == 0x0C: s.dier = v
        elif r == 0x10: s.sr &= v
        elif r == 0x14:
            if v & 1: s.a_psc, s.a_arr, s.a_ccr, s.run_t0, s.sr = s.psc, s.arr, list(s.ccr), s.sim.t, s.sr | 1
        elif r == 0x18: s.ccmr1 = v
        elif r == 0x1C: s.ccmr2 = v
        elif r == 0x20: s.ccer = v
        elif r == 0x28: s.psc = v
        elif r == 0x2C:
            s.arr = v
            if not (s.cr1 & 0x80): s.a_arr = v
        elif 0x34 <= r <= 0x40:
            i = (r - 0x34) // 4; s.ccr[i] = v
            if not ((s.ccmr1 if i < 2 else s.ccmr2) >> (3 + 8 * (i & 1))) & 1: s.a_ccr[i] = v     # OCxPE=0: immediate


# --------------------------------------------------------------------------------------------- IWDG
class IWDG(Periph):
    base = 0x40003000
    def reset(s): s.running, s.pr, s.rlr, s.pr_e, s.rlr_e, s.acc, s.rt, s.sync_at = False, 0, 0xFFF, 0, 0xFFF, False, 0.0, None
    def lsi(s): return s.sim.lsi_hz
    def expiry(s): return s.rt + (s.rlr_e + 1) * (4 << s.pr_e) / s.lsi() if s.running else None
    def _sy(s):
        if s.sync_at is not None and s.sim.t >= s.sync_at: s.pr_e, s.rlr_e, s.sync_at = s.pr, s.rlr, None
    def rd(s, r):
        s._sy()
        if r == 0x0C: return 3 if s.sync_at is not None else 0
        return {0x04: s.pr, 0x08: s.rlr}.get(r, 0)
    def wr(s, r, v):
        s._sy(); v &= 0xFFFF
        if r == 0x00:
            if v == 0xCCCC: s.running = True; s.rt = s.sim.t; s.sim.rcc.force_lsi()
            elif v == 0x5555: s.acc = True
            elif v == 0xAAAA: s.rt = s.sim.t
            else: s.acc = False
        elif r in (4, 8) and s.acc:
            if r == 4: s.pr = v & 7
            else: s.rlr = v & 0xFFF
            s.sync_at = s.sim.t + 6.0 / s.lsi()
    def next_time(s):
        c = [x for x in (s.expiry(), s.sync_at) if x is not None and x > s.sim.t]
        return min(c) if c else None


# --------------------------------------------------------------------------------------------- core: SysTick / NVIC / SCB / DWT
class SCS(Periph):
    base, size = 0xE000E000, 0x1000
    def reset(s):
        s.st_ctrl = s.st_load = 0; s.st_t0, s.st_done, s.st_cf, s.st_pend, s.pendsv = 0.0, 0, False, False, False
        s.en = s.pend = 0; s.ipr = bytearray(240); s.shp = bytearray(12)
        s.vtor = s.scr = s.ccr = s.cfsr = s.hfsr = s.demcr = 0; s.grp = 0
    def _f(s): return max(s.sim.hclk() / (1 if s.st_ctrl & 4 else 8), 1)
    def _per(s): return (s.st_load + 1) / s._f()
    def poll(s):
        if s.st_ctrl & 1:
            n = int((s.sim.t - s.st_t0) / s._per())
            if n > s.st_done:
                s.st_done = n; s.st_cf = True
                if s.st_ctrl & 2: s.st_pend = True
    def cands(s):
        s.poll(); out = []
        if s.st_pend: out.append((s.shp[11], 15))
        if s.pendsv: out.append((s.shp[10], 14))
        m = s.pend & s.en
        while m:
            low = m & -m; i = low.bit_length() - 1; out.append((s.ipr[i], 16 + i)); m ^= low
        return out
    def next_time(s):
        return s.st_t0 + (s.st_done + 1) * s._per() if s.st_ctrl & 1 else None
    def rd(s, r):
        if r == 0x10:
            s.poll(); v = s.st_ctrl | (0x10000 if s.st_cf else 0); s.st_cf = False; return v
        if r == 0x14: return s.st_load
        if r == 0x18:
            if not s.st_ctrl & 1: return 0
            return int(s.st_load - ((s.sim.t - s.st_t0) * s._f()) % (s.st_load + 1))
        if r == 0x1C: return 0xC0000000 | 9000
        if 0x100 <= r < 0x120: return (s.en >> (32 * ((r - 0x100) // 4))) & 0xFFFFFFFF
        if 0x180 <= r < 0x1A0: return (s.en >> (32 * ((r - 0x180) // 4))) & 0xFFFFFFFF
        if 0x200 <= r < 0x220 or 0x280 <= r < 0x2A0: return (s.pend >> (32 * (((r - 0x200) & 0x7F) // 4))) & 0xFFFFFFFF
        if 0x300 <= r < 0x320: return 0
        if 0x400 <= r < 0x4F0: return int.from_bytes(s.ipr[r - 0x400:r - 0x400 + 4], "little")
        if r == 0xD00: return 0x411FC231
        if r == 0xD04:
            s.poll(); a = s.sim.active
            return (a[-1].exc if a else 0) | ((1 << 26) if s.st_pend else 0) | ((1 << 28) if s.pendsv else 0)
        if r == 0xD08: return s.vtor
        if r == 0xD0C: return 0xFA050000 | (s.grp << 8)
        if r == 0xD10: return s.scr
        if r == 0xD14: return s.ccr
        if 0xD18 <= r <= 0xD20: return int.from_bytes(s.shp[r - 0xD18:r - 0xD18 + 4], "little")
        if r == 0xD28: return s.cfsr
        if r == 0xD2C: return s.hfsr
        if r == 0xDFC: return s.demcr
        return 0
    def peek(s, r): return s.rd(r) if r != 0x10 else s.st_ctrl
    def wr(s, r, v):
        if r == 0x10:
            s.poll(); old = s.st_ctrl
            s.st_ctrl = v & 7
            if (v & 1) and not (old & 1): s.st_t0, s.st_done = s.sim.t, 0
        elif r == 0x14: s.poll(); s.st_load = v & 0xFFFFFF; s.st_done = int((s.sim.t - s.st_t0) / s._per())
        elif r == 0x18: s.poll(); s.st_t0, s.st_done, s.st_cf = s.sim.t, 0, False
        elif 0x100 <= r < 0x120: s.en |= (v & 0xFFFFFFFF) << (32 * ((r - 0x100) // 4))
        elif 0x180 <= r < 0x1A0: s.en &= ~((v & 0xFFFFFFFF) << (32 * ((r - 0x180) // 4)))
        elif 0x200 <= r < 0x220: s.pend |= (v & 0xFFFFFFFF) << (32 * ((r - 0x200) // 4))
        elif 0x280 <= r < 0x2A0: s.pend &= ~((v & 0xFFFFFFFF) << (32 * ((r - 0x280) // 4)))
        elif 0x400 <= r < 0x4F0:
            for i in range(4): s.ipr[r - 0x400 + i] = (v >> (8 * i)) & 0xF0           # 4 priority bits implemented
        elif r == 0xD04:
            if v & (1 << 26): s.st_pend = True
            if v & (1 << 25): s.st_pend = False
            if v & (1 << 28): s.pendsv = True
            if v & (1 << 27): s.pendsv = False
        elif r == 0xD08: s.vtor = v & 0xFFFFFF80
        elif r == 0xD0C:
            if (v >> 16) == 0x5FA:
                s.grp = (v >> 8) & 7
                if v & 4: s.sim.sched_at(s.sim.t, lambda: s.sim.reset("soft"))
        elif r == 0xD10: s.scr = v
        elif r == 0xD14:
            s.ccr = v
            if v & 0x200: s.sim.warn("CCR.STKALIGN set: 8-byte exception stacking not modelled")
        elif 0xD18 <= r <= 0xD20:
            for i in range(4): s.shp[r - 0xD18 + i] = (v >> (8 * i)) & 0xF0
        elif r == 0xDFC: s.demcr = v


class DWT(Periph):
    base, size = 0xE0001000, 0x1000
    def reset(s): s.ctrl, s.off = 0, 0
    def _cyc(s): return int(s.sim.t * s.sim.hclk())
    def rd(s, r):
        if r == 0: return s.ctrl | 0x40000000
        if r == 4: return (s._cyc() - s.off) & 0xFFFFFFFF if (s.ctrl & 1 and s.sim.scs.demcr >> 24 & 1) else 0
        return 0
    def wr(s, r, v):
        if r == 0: s.ctrl = v & 1
        elif r == 4: s.off = s._cyc() - v


class DBGMCU(Periph):
    base, size = 0xE0042000, 0x1000
    def rd(s, r): return 0x20036410 if r == 0 else 0


# --------------------------------------------------------------------------------------------- RC522 + Mifare card
class Card:
    def __init__(s, uid, sak=0x08, atqa=b"\x04\x00"):
        s.uid, s.sak, s.atqa, s.state, s.t_ready = bytes(uid), sak, atqa, "IDLE", 0.0
    def cl1(s):
        c = (b"\x88" + s.uid[:3]) if len(s.uid) == 7 else s.uid[:4]
        b = 0
        for x in c: b ^= x
        return c + bytes([b])
    def handle(s, d, nbits):
        d = bytes(d)
        if nbits == 7 and len(d) == 1:
            if d[0] == 0x26 and s.state == "IDLE" or d[0] == 0x52 and s.state in ("IDLE", "HALT"):
                s.state = "READY"; return s.atqa
            if s.state in ("READY", "ACTIVE"): s.state = "IDLE"
            return None
        if s.state == "READY" and len(d) >= 2 and d[0] == 0x93:
            if d[1] == 0x20 and len(d) == 2: return s.cl1()
            if d[1] == 0x70 and len(d) == 9 and d[2:7] == s.cl1() and crc_a(d[:7]) == d[7:9]:
                sak = 0x04 if len(s.uid) == 7 else s.sak
                if sak == s.sak: s.state = "ACTIVE"
                return bytes([sak]) + crc_a(bytes([sak]))
            s.state = "IDLE"; return None
        if s.state == "ACTIVE" and len(d) == 4 and d[0] == 0x50 and d[1] == 0 and crc_a(d[:2]) == d[2:4]:
            s.state = "HALT"; return None
        if s.state in ("READY", "ACTIVE"): s.state = "IDLE"
        return None


class RC522:
    def __init__(s, sim, version=0x92, present=True, start_s=0.02, drop=0.0, fast_timeout=True):
        s.sim, s.version, s.present, s.start_s, s.drop, s.fast_timeout = sim, version, present, start_s, drop, fast_timeout
        s.cards, s.nss, s.rst = [], 1, 1
        s.ev, s._n, s.txn, s.bad_mode = [], 0, 0, False
        s.ready_at = start_s; s.hard_reset()
    def hard_reset(s):
        r = s.reg = [0] * 64
        r[0x01], r[0x02], r[0x04], r[0x07], r[0x0B], r[0x0C], r[0x0E], r[0x11] = 0x20, 0x80, 0x14, 0x21, 0x08, 0x10, 0x80, 0x3F
        r[0x14], r[0x16], r[0x17], r[0x18], r[0x19], r[0x26], r[0x27], r[0x28], r[0x29] = 0x80, 0x10, 0x84, 0x84, 0x4D, 0x48, 0x88, 0x20, 0x20
        s.fifo, s.cmd, s.pd_until, s.timer_gen = [], 0, 0.0, 0
        s.ev.clear(); s.crc = (0, 0); s.crc_ready = False
    def _sched(s, t, kind, *a): s._n += 1; heapq.heappush(s.ev, (t, s._n, kind, a))
    def next_time(s):
        return s.ev[0][0] if s.ev else None
    def set_rst(s, lvl):
        if lvl == s.rst: return
        s.rst = lvl
        if not lvl: s.hard_reset(); s.ready_at = float("inf")
        else: s.ready_at = s.sim.t + s.start_s
    def set_nss(s, lvl): s.nss = lvl; s.txn = 0
    def update(s):
        t = s.sim.t; r = s.reg
        while s.ev and s.ev[0][0] <= t:
            _, _, k, a = heapq.heappop(s.ev)
            if k == "tx_done": r[0x04] |= 0x40
            elif k == "timer":
                if a[0] == s.timer_gen: r[0x04] |= 0x01
            elif k == "crc":
                s.crc = a[0]; r[0x05] |= 0x04; s.crc_ready = True
                if s.cmd == 0x03: s.cmd = 0; r[0x04] |= 0x10
            elif k == "rx" and s.cmd == 0x0C:
                data, err = a[0]; s.fifo += list(data)[:64 - len(s.fifo)]; r[0x0C] = r[0x0C] & ~7
                r[0x06] |= err; r[0x04] |= 0x20 | 0x10 | (0x02 if err else 0); s.cmd = 0
            elif k == "reset_done":
                pass
    # ----- register file
    def reg_rd(s, a):
        r = s.reg
        if a == 0x37: return s.version
        if a == 0x09: return s.fifo.pop(0) if s.fifo else 0
        if a == 0x0A: return len(s.fifo) & 0x7F
        if a == 0x01: return (r[0x01] & 0x20) | (0x10 if s.sim.t < s.pd_until or r[0x01] & 0x10 else 0) | s.cmd
        if a == 0x07:
            n = len(s.fifo); return (0x20 if s.crc_ready else 0) | (0x01 if n <= r[0x0B] & 0x3F else 0) | (0x02 if n >= 64 - (r[0x0B] & 0x3F) else 0) | (0x80 if s.timer_run() else 0)
        if a == 0x21: return s.crc[0] >> 8
        if a == 0x22: return s.crc[0] & 0xFF
        return r[a]
    def timer_run(s): return any(k == "timer" and a[0] == s.timer_gen for _, _, k, a in s.ev)
    def reg_wr(s, a, v):
        r = s.reg
        if s.sim.t < s.pd_until and a != 0x01: return                                # oscillator not up yet: writes ignored
        if a == 0x01:
            if s.sim.t < s.pd_until: return
            r[0x01] = v & 0x30; c = v & 0x0F
            if c == 0x0F:
                keep = s.version; s.hard_reset(); s.pd_until = s.sim.t + 0.005; s.version = keep; return
            s.ev = [e for e in s.ev if e[2] not in ("rx", "crc")]; heapq.heapify(s.ev); s.cmd = 0
            if c != 0: r[0x06] = 0                                              # ErrorReg flags are cleared when a new command starts
            if c == 0x03:
                s.cmd = 3; s.crc_ready = False; r[0x05] &= ~0x04
                pre = (0x0000, 0x6363, 0xA671, 0xFFFF)[r[0x11] & 3]; d = bytes(s.fifo); s.fifo = []
                crc = pre
                for b in d:
                    b ^= crc & 0xFF; b = (b ^ (b << 4)) & 0xFF; crc = ((crc >> 8) ^ (b << 8) ^ (b << 3) ^ (b >> 4)) & 0xFFFF
                s._sched(s.sim.t + 25e-6 + len(d) * 5e-6, "crc", (crc,))
            elif c == 0x0C:
                s.cmd = 0x0C
                if r[0x0D] & 0x80: s._transmit()
            elif c != 0:
                r[0x04] |= 0x10
        elif a == 0x04: r[a] = (r[a] | (v & 0x7F)) if v & 0x80 else (r[a] & ~(v & 0x7F))
        elif a == 0x05:
            r[a] = (r[a] | (v & 0x7F)) if v & 0x80 else (r[a] & ~(v & 0x7F))
            if not r[0x05] & 4: s.crc_ready = False
        elif a == 0x06: pass
        elif a == 0x09:
            if len(s.fifo) >= 64: r[0x06] |= 0x10
            else: s.fifo.append(v)
        elif a == 0x0A:
            if v & 0x80: s.fifo = []; r[0x06] &= ~0x10
        elif a == 0x0D:
            r[a] = v
            if (v & 0x80) and s.cmd == 0x0C: s._transmit()
        elif a in (0x37, 0x21, 0x22): pass
        else: r[a] = v
    def _transmit(s):
        r, t = s.reg, s.sim.t
        data = bytes(s.fifo); s.fifo = []; last = r[0x0D] & 7; r[0x0D] &= 0x7F
        nbits = len(data) * 8 - ((8 - last) % 8 if last else 0)
        t_tx = t + (nbits + len(data)) / 106e3
        s._sched(t_tx, "tx_done")
        out = []
        if (r[0x14] & 3) == 3 and not (r[0x01] & 0x10) and s.cards and s.sim.rng.random() >= s.drop:
            out = [x for x in (c.handle(data, nbits) for c in s.cards if t >= c.t_ready) if x is not None]
        if r[0x2A] & 0x80:
            pre = ((r[0x2A] & 0x0F) << 8) | r[0x2B]; rel = (r[0x2C] << 8) | r[0x2D]
            per = rel * (2 * pre + 1) / 13.56e6
            if not out and s.fast_timeout: per = min(per, 0.3e-3)       # nobody can answer: the long timeout only wastes emulator time
            s.timer_gen += 1; s._sched(t_tx + per, "timer", s.timer_gen)
        if out:
            err = 0
            if len(set(out)) > 1: err = 0x08; out = [out[0][:2]]
            s._sched(t_tx + 91e-6 + (len(out[0]) * 9) / 106e3, "rx", (out[0], err))
    def spi_byte(s, tx, cpol, cpha, lsb, fclk):
        sim = s.sim; s.update()
        if not s.present: return 0x00
        if cpol or cpha or lsb or fclk > 10e6:
            if not s.bad_mode: sim.warn("RC522: SPI mode/clock outside spec (needs CPOL0 CPHA0 MSB-first <=10 MHz)"); s.bad_mode = True
            return sim.rng.randrange(256)
        if s.nss or sim.t < s.ready_at: return 0x00
        i = s.txn; s.txn += 1
        if i == 0:
            s.cur = tx
            if tx & 1: sim.warn("RC522: address byte with bit0 set")
            return 0
        a, rw = (s.cur >> 1) & 0x3F, s.cur >> 7
        if i == 1:
            if rw: return s.reg_rd(a)
            s.reg_wr(a, tx); return 0
        return 0


# --------------------------------------------------------------------------------------------- board
class Board:
    def __init__(s, sim, **rc):
        s.sim, s.ir = sim, [False, False]
        s.rc = RC522(sim, **rc)
        s.buz = s.led = None; s.buz_log = []; s.led_log = {"G": [], "R": [], "B": []}
        s.uart_bytes = bytearray(); s.lines = []; s._cur = bytearray(); s.once = set()
    def pin_in(s, port, pin):
        if port == "B" and pin in (12, 13): return 0 if s.ir[pin - 12] else 1
        return None
    def pin_out(s, port, pin, lvl):
        t = s.sim.t; on = 1 if lvl else 0
        if (port, pin) == ("A", 4): s.rc.set_nss(1 if lvl is None else lvl)
        elif (port, pin) == ("B", 0): s.rc.set_rst(1 if lvl is None else lvl)
        elif (port, pin) == ("B", 14): s.buz_log.append((t, on)); s.buz = on
        elif (port, pin) == ("B", 8): s.led_log["G"].append((t, on))
        elif (port, pin) == ("B", 9): s.led_log["R"].append((t, on))
        elif (port, pin) == ("C", 13): s.led_log["B"].append((t, on))
    def led(s, k): l = s.led_log[k]; return l[-1][1] if l else 0
    def present(s, uid, **kw):
        c = Card(uid, **kw); c.t_ready = s.sim.t + 0.005; s.rc.cards.append(c); return c
    def remove(s, c):
        if c in s.rc.cards: s.rc.cards.remove(c)
    def mcu_reset(s):
        s.rc.set_nss(1); s.rc.set_rst(1); s._cur = bytearray()
        for k in ("G", "R", "B"): s.led_log[k].append((s.sim.t, 0))
        s.buz_log.append((s.sim.t, 0)); s.buz = 0
    def spi_xfer(s, tx, spi):
        sim = s.sim; a = sim.gpio["A"]; probs = []
        if sim.afio.mapr & 1: probs.append("SPI1 remapped")
        if a.kind(5) != "af_pp": probs.append("PA5 (SCK) is not AF push-pull")
        if a.kind(7) != "af_pp": probs.append("PA7 (MOSI) is not AF push-pull")
        if a.kind(6) not in ("in_float", "in_pull"): probs.append("PA6 (MISO) is not an input")
        if probs:
            for p in probs:
                if p not in s.once: s.once.add(p); sim.warn("SPI wiring: " + p)
            return 0x00
        cr1 = spi.cr1
        return s.rc.spi_byte(tx & 0xFF, (cr1 >> 1) & 1, cr1 & 1, (cr1 >> 7) & 1, sim.rcc.pclk(2)[0] / (2 << ((cr1 >> 3) & 7)))
    def uart_tx(s, byte, t, ok):
        a = s.sim.gpio["A"]
        if a.kind(9) != "af_pp": return
        if not ok: byte = s.sim.rng.randrange(256)
        s.uart_bytes.append(byte)
        if byte == 10:
            s.lines.append((t, s._cur.decode("latin1").strip())); s._cur = bytearray()
        else: s._cur.append(byte)
    def servo(s):
        """what the SG90 signal pin PA1 actually carries: dict(period, pulse) or None"""
        sim = s.sim
        if (sim.afio.mapr >> 8) & 3 or not sim.rcc.clk_on("apb2", 2): return None
        if sim.gpio["A"].kind(1) != "af_pp": return None
        return sim.tim2.pwm(2)


# --------------------------------------------------------------------------------------------- the simulator
class Act:
    __slots__ = ("exc", "prio", "sp")
    def __init__(s, e, p, sp): s.exc, s.prio, s.sp = e, p, sp


class Sim:
    def __init__(s, binpath, elfpath, flash_kb=32, ram_kb=10, lsi_hz=40000, hse_ok=True, hse_hz=8_000_000, seed=1, cpi=CPI, **rc522):
        s.rng = random.Random(seed); s.t = 0.0; s.cpi = cpi; s.cyc_per_byte = cpi / 2.75
        s.lsi_hz, s.hse_ok, s.hse_hz = lsi_hz, hse_ok, hse_hz
        s.warns, s.faults, s.errors, s.unmod, s.resets = [], [], [], collections.Counter(), []
        s.sched, s._n, s.active, s.locked_up = [], 0, [], False
        s.syms = load_symbols(elfpath); s._sorted = sorted((a, n) for n, a in s.syms.items() if n and not n.startswith("$"))
        img = open(binpath, "rb").read(); s.img = img
        s.flash_bytes, s.ram_bytes = flash_kb * 1024, ram_kb * 1024
        if len(img) > s.flash_bytes: raise ValueError("image %d B does not fit %d KB flash" % (len(img), flash_kb))
        uc = s.uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB | UC_MODE_MCLASS); uc.ctl_set_cpu_model(UC_CPU_ARM_CORTEX_M3)
        for base in (FLASH, 0):
            uc.mem_map(base, s.flash_bytes, UC_PROT_READ | UC_PROT_EXEC); uc.mem_write(base, img)
        pages = (s.ram_bytes + PAGE - 1) // PAGE * PAGE
        uc.mem_map(SRAM, pages, UC_PROT_READ | UC_PROT_WRITE)
        if pages > s.ram_bytes: uc.hook_add(UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE, s._tail, None, SRAM + s.ram_bytes, SRAM + pages - 1)
        uc.mem_map(TRAMP, PAGE, UC_PROT_READ | UC_PROT_EXEC); uc.mem_write(TRAMP, TRAMP_CODE)
        uc.hook_add(UC_HOOK_CODE, s._tramp, None, TRAMP, TRAMP)
        from unicorn.unicorn_py3.unicorn import uclib, uc_hook_h
        _hook.tg_init(ctypes.cast(uclib.uc_emu_stop, ctypes.c_void_p))
        s._hh = uc_hook_h()
        if uclib.uc_hook_add(uc._uch, ctypes.byref(s._hh), UC_HOOK_BLOCK, ctypes.cast(_hook.tg_blk, ctypes.c_void_p), None, 1, 0): raise RuntimeError("block hook failed")
        s.rcc, s.flashif, s.afio, s.spi1, s.usart1, s.tim2, s.iwdg = RCC(s), FLASHIF(s), AFIO(s), SPI(s), USART(s), TIM(s), IWDG(s)
        s.gpio = {p: GPIO(s, p, b, bit) for p, (b, bit) in {"A": (0x40010800, 2), "B": (0x40010C00, 3), "C": (0x40011000, 4), "D": (0x40011400, 5)}.items()}
        s.scs, s.dwt, s.dbg = SCS(s), DWT(s), DBGMCU(s)
        s.periphs = [s.rcc, s.flashif, s.afio, s.spi1, s.usart1, s.tim2, s.iwdg, s.scs, s.dwt, s.dbg] + list(s.gpio.values())
        s.pmap = {}
        for p in s.periphs:
            for k in range(p.size >> 10): s.pmap[(p.base >> 10) + k] = p
        for base, size in ((0x40000000, 0x8000), (0x40010000, 0x4000), (0x40020000, 0x4000), (0xE000E000, 0x1000), (0xE0001000, 0x1000), (0xE0042000, 0x1000)):
            uc.mmio_map(base, size, s._mrd, base, s._mwr, base)
        uc.mmio_map(0x42000000, 0x2000000, s._bbrd, 0, s._bbwr, 0)
        s.board = Board(s, **rc522)
        s.reset("por")
    # ---- helpers
    def hclk(s): return s.rcc.hclk()
    def warn(s, m):
        if not any(m == w[1] for w in s.warns[-50:]): s.warns.append((s.t, m))
    def af_level(s, port, pin): return 1
    def sym_at(s, a):
        best = None
        for ad, n in s._sorted:
            if ad <= a: best = (ad, n)
            else: break
        return "%s+0x%x" % (best[1], a - best[0]) if best else hex(a)
    def read32(s, a): return struct.unpack("<I", s.uc.mem_read(a, 4))[0]
    def sched_at(s, t, fn): s._n += 1; heapq.heappush(s.sched, (t, s._n, fn))
    def after(s, dt, fn): s.sched_at(s.t + dt, fn)
    def on_clock_change(s):
        hz = s.rcc.hclk(); need = 0 if hz <= 24_000_000 else 1 if hz <= 48_000_000 else 2
        if s.flashif.lat < need:
            s.faults.append((s.t, "FLASH latency %d too low for HCLK %d MHz (needs %d): core would misread flash" % (s.flashif.lat, hz // 10**6, need))); s.locked_up = True
    # ---- MMIO plumbing
    def _unm(s, a, k): s.unmod[(a & ~3, k)] += 1
    def _mrd(s, uc, off, size, base):
        try:
            a = base + off; p = s.pmap.get(a >> 10)
            if p is None: s._unm(a, "r"); return 0
            if p.gate and not s.rcc.clk_on(*p.gate): s.warn("%s read while its clock is off (reads 0)" % type(p).__name__ + ("" if p.__class__ is not GPIO else p.port)); return 0
            return (p.rd((a & ~3) - p.base) >> ((a & 3) * 8)) & ((1 << (8 * size)) - 1)
        except Exception as e: s.errors.append("rd %x: %r" % (base + off, e)); uc.emu_stop(); return 0
    def _mwr(s, uc, off, size, val, base):
        try:
            a = base + off; p = s.pmap.get(a >> 10)
            if p is None: s._unm(a, "w"); return
            if p.gate and not s.rcc.clk_on(*p.gate): s.warn("%s written while its clock is off (write ignored)" % type(p).__name__ + ("" if p.__class__ is not GPIO else p.port)); return
            r = (a & ~3) - p.base
            if size == 4: p.wr(r, val & 0xFFFFFFFF)
            else:
                sh = (a & 3) * 8; m = ((1 << (8 * size)) - 1) << sh
                p.wr(r, (p.peek(r) & ~m) | ((val << sh) & m))
        except Exception as e: s.errors.append("wr %x: %r" % (base + off, e)); uc.emu_stop()
    def _bbrd(s, uc, off, size, base):                      # Cortex-M3 peripheral bit-band alias (HAL uses it for PLLON etc.)
        ba = 0x40000000 + (off >> 5); bit = (ba & 3) * 8 + ((off >> 2) & 7)
        return (s._mrd(uc, ba & ~3, 4, 0) >> bit) & 1
    def _bbwr(s, uc, off, size, val, base):
        ba = 0x40000000 + (off >> 5); bit = (ba & 3) * 8 + ((off >> 2) & 7); w = ba & ~3; p = s.pmap.get(w >> 10)
        if p is None: s._unm(w, "w"); return
        old = p.peek(w - p.base)
        s._mwr(uc, w, 4, (old | (1 << bit)) if val & 1 else (old & ~(1 << bit)), 0)
    def _tail(s, uc, access, addr, size, value, ud):
        s.faults.append((s.t, "access to 0x%08x beyond the %d KB of SRAM (pc=%s)" % (addr, s.ram_bytes // 1024, s.sym_at(uc.reg_read(UC_ARM_REG_PC)))))
        s.locked_up = True; uc.emu_stop()
    # ---- reset
    def reset(s, kind):
        s.resets.append((s.t, kind)); r = s.rcc
        bits = {"por": (1 << 27) | (1 << 26), "iwdg": (1 << 29) | (1 << 26), "soft": (1 << 28) | (1 << 26), "pin": 1 << 26}[kind]
        r.flags = bits if kind == "por" else (r.flags | bits)
        if kind == "por": s.uc.mem_write(SRAM, b"\xA5" * (s.ram_bytes))
        flags = r.flags
        for p in s.periphs: p.reset()
        r.flags = flags
        s.active, s.locked_up = [], False
        s.board.mcu_reset()
        uc = s.uc; img = s.img
        for reg in (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3, UC_ARM_REG_R4, UC_ARM_REG_R5, UC_ARM_REG_R6, UC_ARM_REG_R7, UC_ARM_REG_R8, UC_ARM_REG_R9, UC_ARM_REG_R10, UC_ARM_REG_R11, UC_ARM_REG_R12, UC_ARM_REG_LR):
            uc.reg_write(reg, 0)
        uc.reg_write(UC_ARM_REG_PRIMASK, 0); uc.reg_write(UC_ARM_REG_BASEPRI, 0); uc.reg_write(UC_ARM_REG_FAULTMASK, 0); uc.reg_write(UC_ARM_REG_CONTROL, 0)
        uc.reg_write(UC_ARM_REG_SP, struct.unpack_from("<I", img, 0)[0] & ~3); uc.reg_write(UC_ARM_REG_PC, struct.unpack_from("<I", img, 4)[0] & ~1)
    # ---- exceptions
    def _tramp(s, uc, addr, size, ud):
        if not s.active: s.warn("exception return with no active exception"); return
        a = s.active.pop()
        sp = uc.reg_read(UC_ARM_REG_SP)
        if sp != a.sp: s.warn("stack imbalance in handler of exception %d (sp=%x expected %x)" % (a.exc, sp, a.sp))
        s._relevel()
    def _relevel(s):
        if not any(a.exc == 53 for a in s.active) and s.usart1.irq_level(): s.scs.pend |= 1 << 37
    def _enter(s, exc, prio):
        uc = s.uc; g = 0
        while uc.reg_read(UC_ARM_REG_XPSR) & 0x0600FC00 and g < 8:                    # never stack inside an IT block
            try: uc.emu_start(uc.reg_read(UC_ARM_REG_PC) | 1, 0xFFFFFFFE, count=1)
            except UcError: break
            g += 1
        sp = uc.reg_read(UC_ARM_REG_SP) - 32
        pc = uc.reg_read(UC_ARM_REG_PC)
        fr = struct.pack("<8I", *[uc.reg_read(x) for x in (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3, UC_ARM_REG_R12, UC_ARM_REG_LR)], pc, uc.reg_read(UC_ARM_REG_XPSR))
        try: uc.mem_write(sp, fr)
        except UcError: s.faults.append((s.t, "lockup: cannot stack exception %d (sp=%x)" % (exc, sp + 32))); s.locked_up = True; return
        uc.reg_write(UC_ARM_REG_SP, sp); uc.reg_write(UC_ARM_REG_LR, TRAMP | 1)
        h = s.read32(s.scs.vtor + 4 * exc)
        uc.reg_write(UC_ARM_REG_PC, h & ~1)
        s.active.append(Act(exc, prio, sp))
        if exc == 15: s.scs.st_pend = False
        elif exc == 14: s.scs.pendsv = False
        elif exc >= 16: s.scs.pend &= ~(1 << (exc - 16))
    def _deliver(s):
        sc = s.scs; s._relevel()
        if any(a.prio < 0 for a in s.active): return
        c = sc.cands()
        if not c: return
        prio, exc = min(c)
        grp = sc.grp + 1
        run = min([a.prio >> grp for a in s.active if a.prio >= 0] or [1 << 9])
        if (prio >> grp) >= run: return
        uc = s.uc
        if uc.reg_read(UC_ARM_REG_PRIMASK): return
        bp = uc.reg_read(UC_ARM_REG_BASEPRI)
        if bp and prio >= bp: return
        s._enter(exc, prio)
    def _fault(s, e):
        uc = s.uc; pc = uc.reg_read(UC_ARM_REG_PC)
        s.faults.append((s.t, "%s at %s" % (e, s.sym_at(pc))))
        if any(a.exc == 3 for a in s.active): s.locked_up = True; return
        s._enter(3, -1)
    # ---- run loop
    def _next(s, t_end):
        c = [t_end]
        if s.sched: c.append(s.sched[0][0])
        for o in (s.scs, s.usart1, s.rcc, s.iwdg, s.board.rc):
            n = o.next_time()
            if n is not None and n > s.t: c.append(n)
        return min(c)
    def run_until(s, t_end):
        uc = s.uc
        while s.t < t_end:
            while s.sched and s.sched[0][0] <= s.t + 1e-12: heapq.heappop(s.sched)[2]()
            s.board.rc.update(); s.rcc._sync()
            e = s.iwdg.expiry()
            if e is not None and s.t >= e: s.reset("iwdg"); continue
            if not s.locked_up: s._deliver()
            if s.errors: raise RuntimeError(s.errors[0])
            nxt = s._next(t_end); hz = s.hclk()
            if s.locked_up:
                s.t = max(nxt, s.t + 1e-6); continue
            _hook.tg_budget(max(150, int(min(nxt - s.t, MAX_SPAN) * hz / s.cyc_per_byte) + 1))
            try: uc.emu_start(uc.reg_read(UC_ARM_REG_PC) | 1, 0xFFFFFFFE)
            except UcError as ex: s._fault(ex)
            s.t += max(_hook.tg_used(), 20) * s.cyc_per_byte / hz
    def run(s, ms): s.run_until(s.t + ms / 1000.0)
    # ---- host-side helpers
    def send(s, text): s.usart1.feed((text + "\n").encode())
    def lines_since(s, i): return s.board.lines[i:]
    def stack_low_water(s):
        end = s.syms.get("_end", s.syms.get("end", 0)); top = SRAM + s.ram_bytes
        mem = bytes(s.uc.mem_read(end, top - end))
        i = 0
        while i + 4 <= len(mem) and mem[i:i + 4] == b"\xA5\xA5\xA5\xA5": i += 4
        return top - (end + i), end
