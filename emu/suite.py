#!/usr/bin/env python3
"""TrustGate firmware-in-the-loop suite: the REAL build/trustgate.bin runs on the emulated Blue Pill (tgemu.py).
usage: python3 emu/suite.py [test ...]      (no args = everything)      results -> emu/results.json
"""
import sys, os, time, calendar, json, random
HERE = os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0, HERE)
from tgemu import *

ROOT = os.path.dirname(HERE)
BIN, ELF = ROOT + "/build/trustgate.bin", ROOT + "/build/trustgate.elf"
EP = lambda y, mo, d, h, mi, s=0: calendar.timegm((y, mo, d, h, mi, s))
WED10, SAT10 = EP(2026, 10, 14, 10, 0), EP(2026, 10, 17, 10, 0)
STAFF, STAFF2, ADMIN, GUEST, UNKNOWN = "DEADBE02", "DEADBE03", "DEADBE01", "DEADBE04", "11223344"
UNLOCK_US = 1.2e-3                      # SG90 pulse above this = unlocked (lock 0.7 ms / unlock 1.7 ms defaults)
RESULTS, CUR = [], [""]


def chk(name, ok, detail=""):
    RESULTS.append((CUR[0], name, bool(ok), str(detail)))
    print("  %s  %-62s %s" % ("PASS" if ok else "FAIL", name, detail), flush=True)


class Rig:
    def __init__(self, cpi=4.0, sync=WED10, boot=True, build=None, chip=(32, 10), **kw):
        kw = {k.replace("rc522_", ""): v for k, v in kw.items()}
        self.s = Sim((build or ROOT + "/build") + "/trustgate.bin", (build or ROOT + "/build") + "/trustgate.elf", flash_kb=chip[0], ram_kb=chip[1], cpi=cpi, **kw)      # the invoice chip: 32 KB flash / 10 KB RAM
        self.seen, self.evs, self.sts, self.other, self.tl = 0, [], [], [], []
        self.s.sched_at(0.0, self._sample)
        if boot:
            self.until(lambda: any(l.startswith("BOOT,") for _, l in self.s.board.lines), 1.0)
            if sync: self.sync(sync)
    # ---- plumbing
    def _sample(self):
        sv = self.s.board.servo()
        self.tl.append((self.s.t, None if sv is None else sv["pulse"]))
        self.s.after(0.002, self._sample)
    def pump(self):
        L = self.s.board.lines
        while self.seen < len(L):
            t, ln = L[self.seen]; self.seen += 1
            p = ln.split(",")
            try:
                if p[0] == "EV" and len(p) == 8: self.evs.append(dict(t=t, seq=int(p[1]), tick=int(p[2]), name=p[4], user=int(p[5]), uid=p[6], arg=int(p[7])))
                elif p[0] == "ST" and len(p) == 11: self.sts.append((t, dict(tick=int(p[1]), door=p[2], grant=int(p[3]), inside=int(p[4]), lock=int(p[5]), alarm=int(p[6]), tv=int(p[7]), admin=int(p[8]), ir=p[9], tamper=int(p[10]))))
                elif ln: self.other.append((t, ln))
            except ValueError: self.other.append((t, ln))
    def run(self, ms): self.s.run(ms); self.pump()
    def until(self, cond, timeout_s, step_ms=5):
        end = self.s.t + timeout_s
        while self.s.t < end:
            self.s.run(step_ms); self.pump()
            if cond(): return True
        return cond()
    def sync(self, epoch):
        self.s.send("TIME %d" % epoch); self.run(60)
    def cmd(self, text, wait_ms=60):
        n = len(self.other); self.s.send(text); self.run(wait_ms)
        return [l for _, l in self.other[n:]]
    def names(self, since=0): return [e["name"] for e in self.evs[since:]]
    def find(self, name, since=0): return [e for e in self.evs[since:] if e["name"] == name]
    # ---- the world
    def tap(self, uid, hold_ms=900):
        c = self.s.board.present(bytes.fromhex(uid)); self.s.after(hold_ms / 1000, lambda: self.s.board.remove(c)); return self.s.t
    def beam(self, i, blocked, at_ms): self.s.after(at_ms / 1000, lambda: self.s.board.ir.__setitem__(i, blocked))
    def walk(self, direction, at_ms=0, off=150, hold=300):
        a, b = (0, 1) if direction == "in" else (1, 0)
        self.beam(a, True, at_ms); self.beam(b, True, at_ms + off); self.beam(a, False, at_ms + hold); self.beam(b, False, at_ms + hold + off)
        return at_ms + hold + off
    def servo(self): sv = self.s.board.servo(); return None if sv is None else sv["pulse"]
    def unlocked(self): p = self.servo(); return p is not None and p > UNLOCK_US
    def open_intervals(self):
        out, t0 = [], None
        for t, p in self.tl:
            u = p is not None and p > UNLOCK_US
            if u and t0 is None: t0 = t
            if not u and t0 is not None: out.append((t0, t)); t0 = None
        if t0 is not None: out.append((t0, self.s.t))
        return out
    def first_unlock_after(self, t):
        for tt, p in self.tl:
            if tt >= t and p is not None and p > UNLOCK_US: return tt
    def first_lock_after(self, t):
        for tt, p in self.tl:
            if tt >= t and p is not None and p <= UNLOCK_US: return tt
    def hygiene(self, label=""):
        s = self.s
        chk("no faults/errors" + label, not s.faults and not s.errors, (s.faults + s.errors)[:2])
        chk("no clock-off / wiring / SPI-mode warnings" + label, not s.warns, s.warns[:3])
        chk("no unmodelled register accesses" + label, not s.unmod, dict(list(s.unmod.items())[:4]))


def new(name):
    CUR[0] = name; print("\n[%s]" % name, flush=True)


# =========================================================================================== tests
def t_boot():
    new("boot")
    r = Rig(sync=None); s = r.s
    ln = [l for _, l in s.board.lines if l]
    chk("banner prints rc522=ok, ver, sysclk=72 MHz", ln and ln[0] == "BOOT,TrustGate,1.0.0,rc522=ok,ver=0x92,sysclk=72000000", ln[:1])
    r.run(1500)
    boot = r.find("BOOT")
    chk("boot event reports power-on reset (cause 3)", boot and boot[0]["arg"] == 3, boot[:1])
    chk("firmware asks the dashboard for time (TIME?)", any(l == "TIME?" for _, l in r.other))
    chk("RCC: SYSCLK 72 MHz, APB1 36 MHz (<=36), APB2 72 MHz", (s.rcc.sysclk(), s.rcc.pclk(1)[0], s.rcc.pclk(2)[0]) == (72_000_000, 36_000_000, 72_000_000), (s.rcc.sysclk(), s.rcc.pclk(1), s.rcc.pclk(2)))
    chk("FLASH latency = 2 wait states at 72 MHz, prefetch on", s.flashif.lat == 2 and s.flashif.pre == 1, (s.flashif.lat, s.flashif.pre))
    sv = s.board.servo()
    chk("servo pin PA1 carries 50 Hz PWM (period 20 ms)", sv and abs(sv["period"] - 0.02) < 1e-4, sv)
    chk("servo boots in the LOCKED position (pulse 0.7 ms)", sv and abs(sv["pulse"] - 0.0007) < 3e-5, sv)
    chk("UART: BRR gives 115200 baud within 1 %", abs(s.usart1.baud() / 115200 - 1) < 0.01, "%.0f baud" % s.usart1.baud())
    chk("SysTick prio 15, USART1 prio 1, 4 preempt bits (BASEPRI scheme valid)", (s.scs.shp[11], s.scs.ipr[37], s.scs.grp) == (0xF0, 0x10, 3), (s.scs.shp[11], s.scs.ipr[37], s.scs.grp))
    chk("SysTick ticks at 1 kHz (HAL tick tracks real time)", r.sts and abs(r.sts[-1][1]["tick"] - r.sts[-1][0] * 1000) < 25, r.sts[-1:] and (r.sts[-1][1]["tick"], round(r.sts[-1][0] * 1000)))
    iw = s.iwdg
    chk("IWDG running, timeout ~1 s at LSI 40 kHz", iw.running and abs((iw.rlr_e + 1) * (4 << iw.pr_e) / 40000 - 1.0) < 0.05, "%.3f s" % ((iw.rlr_e + 1) * (4 << iw.pr_e) / 40000))
    chk("status says door LOCKED, 0 inside, no alarm", r.sts and r.sts[-1][1]["door"] == "L" and r.sts[-1][1]["inside"] == 0 and r.sts[-1][1]["alarm"] == 0, r.sts[-1:])
    lw, end = s.stack_low_water()
    chk("RAM budget on a 10 KB part: %d B static + %d B peak stack of %d B" % (end - SRAM, lw, 10240), (end - SRAM) + lw + 512 < 10240 * 0.7, "free %d B" % (10240 - (end - SRAM) - lw))
    chk("only the power-on reset happened (no watchdog)", [k for _, k in s.resets] == ["por"], s.resets)
    r.hygiene()


def t_reader():
    new("reader")
    r = Rig(); s = r.s; n0 = len(r.evs)
    r.tap(UNKNOWN, hold_ms=3000); r.run(3600)
    d = r.find("ACCESS_DENIED", n0)
    chk("unknown card held 3 s -> exactly ONE ACCESS_DENIED with its UID", len(d) == 1 and d[0]["uid"] == UNKNOWN and d[0]["arg"] == 1, d)
    chk("door stays locked", not any(p and p > UNLOCK_US for _, p in r.tl))
    r.run(1200); r.tap(UNKNOWN, hold_ms=1200); r.run(2000)
    chk("card removed and presented again -> a second tap is counted", len(r.find("ACCESS_DENIED", n0)) == 2, r.names(n0))
    r.tap(UNKNOWN, hold_ms=1200); r.run(2000)
    chk("third fail inside 30 s -> LOCKOUT_START", len(r.find("LOCKOUT_START", n0)) == 1, r.names(n0))
    # 7-byte UID card: must be rejected cleanly (driver supports 4-byte UIDs)
    r2 = Rig(); r2.s.board.present(bytes.fromhex("04112233445566")); r2.run(2500)
    chk("7-byte UID card: no access event, no lockout, no crash", not r2.find("ACCESS_GRANTED") and not r2.find("ACCESS_DENIED") and not r2.find("LOCKOUT_START"), r2.names())
    chk("... and the firmware warns about the unsupported card", any("WARN" in l for _, l in r2.other), [l for _, l in r2.other][-2:])
    # two cards at once -> collision, then one removed
    r3 = Rig(); a = r3.s.board.present(bytes.fromhex(STAFF)); b = r3.s.board.present(bytes.fromhex(STAFF2)); r3.run(1500)
    chk("two cards in the field: collision, no access granted", not r3.find("ACCESS_GRANTED"), r3.names())
    r3.s.board.remove(b); r3.run(1500)
    chk("one card removed: remaining card is read normally", len(r3.find("ACCESS_GRANTED")) == 1, r3.names())
    r.hygiene()


def t_entry_exit():
    new("entry_exit")
    r = Rig(); s = r.s; n0 = len(r.evs)
    t_tap = r.tap(STAFF, hold_ms=1500); t_walk = r.s.t + 0.5
    end = r.walk("in", at_ms=500); r.run(end + 2500)
    nm = r.names(n0)
    chk("staff tap -> ACCESS_GRANTED, passage -> ENTRY_OK (in that order)", nm[:2] == ["ACCESS_GRANTED", "ENTRY_OK"], nm)
    g = r.find("ACCESS_GRANTED", n0)[0]
    chk("grant direction learned as 'any' after reset (arg 2)", g["arg"] == 2, g)
    tu = r.first_unlock_after(t_tap)
    chk("servo physically unlocks after the tap (latency %.0f ms)" % ((tu - t_tap) * 1000 if tu else -1), tu is not None and tu - t_tap < 0.25, tu and "%.0f ms" % ((tu - t_tap) * 1000))
    ok_ev = r.find("ENTRY_OK", n0)[0]["t"]; tl = r.first_lock_after(ok_ev - 0.05)
    chk("servo relocks 1.2 s after the passage is confirmed (ENTRY_OK)", tl is not None and 1.0 < tl - ok_ev < 1.4, tl and "%.2f s after ENTRY_OK" % (tl - ok_ev))
    chk("status: 1 person inside, door locked, no alarm", r.sts[-1][1]["inside"] == 1 and r.sts[-1][1]["door"] == "L" and r.sts[-1][1]["alarm"] == 0, r.sts[-1][1])
    chk("no alarm / buzzer alarm pattern during a legitimate entry", not any(e["name"] in ("TAILGATE", "UNAUTH_PASSAGE") for e in r.evs[n0:]))
    # same card again = exit
    n1 = len(r.evs); r.tap(STAFF, hold_ms=1500); end = r.walk("out", at_ms=500); r.run(end + 2500)
    nm = r.names(n1)
    chk("same card again -> grant 'OUT' (arg 1) -> EXIT_OK", nm[:2] == ["ACCESS_GRANTED", "EXIT_OK"] and r.find("ACCESS_GRANTED", n1)[0]["arg"] == 1, nm)
    chk("status: 0 inside after the exit", r.sts[-1][1]["inside"] == 0, r.sts[-1][1])
    chk("door was never open without a tap: open intervals == 2", len(r.open_intervals()) == 2, [(round(a, 2), round(b, 2)) for a, b in r.open_intervals()])
    r.hygiene()


def t_tailgate():
    new("tailgate")
    r = Rig(); s = r.s; n0 = len(r.evs)
    r.tap(STAFF, hold_ms=1500); end = r.walk("in", at_ms=500); t_end = s.t + end / 1000
    r.walk("in", at_ms=end + 700)                     # second person right behind, no tap
    r.run(end + 700 + 700 + 1200)
    tg = r.find("TAILGATE", n0)
    chk("second person 0.7 s behind -> TAILGATE event", len(tg) == 1, r.names(n0))
    t_alarm = tg[0]["t"] if tg else 0
    chk("door relocked right after the tailgate", r.first_lock_after(t_alarm - 0.05) is not None and r.first_lock_after(t_alarm - 0.05) - t_alarm < 0.15, r.first_lock_after(t_alarm - 0.05))
    buz = [(t, v) for t, v in s.board.buz_log if t > t_alarm - 0.1]
    chk("buzzer toggles during the alarm (>=6 transitions)", len(buz) >= 6, len(buz))
    r.run(7000)
    na = sum(1 for t, st in r.sts if st["alarm"] == 1 and t > t_alarm)
    chk("alarm shows in the 1 Hz status for ~6 s (%d reports), then clears by itself" % na, 4 <= na <= 7 and r.sts[-1][1]["alarm"] == 0, [(round(t, 1), st["alarm"]) for t, st in r.sts[-9:]])
    # unauthorised: no tap at all
    n1 = len(r.evs); r.run(4000); niv = len(r.open_intervals()); r.walk("in", at_ms=0); r.run(1500)
    chk("walk-through with no tap -> UNAUTH_PASSAGE", len(r.find("UNAUTH_PASSAGE", n1)) == 1, r.names(n1))
    chk("... and the door never opened for it", len(r.open_intervals()) == niv, niv)
    # late follower (after watch window)
    r2 = Rig(); r2.tap(STAFF, hold_ms=1500); e2 = r2.walk("in", at_ms=500); r2.run(e2 + 200)
    r2.run(3300); r2.walk("in", at_ms=0); r2.run(1500)
    chk("follower 3.5 s later (outside the tailgate window) -> UNAUTH_PASSAGE", len(r2.find("UNAUTH_PASSAGE")) == 1 and not r2.find("TAILGATE"), r2.names())
    # how close behind can a second person be and still be caught?  (documented limit: shoulder-to-shoulder = one person)
    res = {}
    for gap in (-120, 100, 250, 400, 600, 1000):
        rg = Rig(); rg.tap(STAFF, hold_ms=1500); e = rg.walk("in", at_ms=500); rg.walk("in", at_ms=e + gap); rg.run(e + gap + 2500)
        res[gap] = "TAILGATE" if rg.find("TAILGATE") else ("merged" if not rg.find("UNAUTH_PASSAGE") else "UNAUTH")
    chk("follower gap sweep (ms after first person clears; negative = beams overlap): %s" % res, all(res[g] == "TAILGATE" for g in (100, 250, 400, 600, 1000)), res)
    r.hygiene()


def t_passback():
    new("passback")
    r = Rig(); n0 = len(r.evs)
    r.tap(STAFF, hold_ms=1500); e = r.walk("in", at_ms=500); r.run(e + 3500)
    n1 = len(r.evs); r.tap(STAFF, hold_ms=1500); r.walk("in", at_ms=500); r.run(3000)             # card of someone inside, used to walk IN again
    chk("inside user's card used to enter again -> ANTIPASSBACK", len(r.find("ANTIPASSBACK", n1)) == 1, r.names(n1))
    r2 = Rig(); r2.tap(STAFF, hold_ms=1500); e = r2.walk("in", at_ms=500); r2.run(e + 3500)
    r2.tap(STAFF, hold_ms=1500); e = r2.walk("out", at_ms=500); r2.run(e + 3500)
    n1 = len(r2.evs); r2.tap(STAFF, hold_ms=1500); r2.walk("out", at_ms=500); r2.run(3000)        # outside user taps (IN expected) but a person leaves
    chk("outside user's tap + someone walking OUT -> DIR_MISMATCH", len(r2.find("DIR_MISMATCH", n1)) == 1, r2.names(n1))
    r.hygiene()


def t_policy():
    new("policy")
    r = Rig(); n0 = len(r.evs)
    for _ in range(3): r.tap(UNKNOWN, hold_ms=800); r.run(1700)
    chk("3 unknown cards in 30 s -> LOCKOUT_START (30 s)", len(r.find("LOCKOUT_START", n0)) == 1 and r.find("LOCKOUT_START", n0)[0]["arg"] == 30, r.names(n0))
    n1 = len(r.evs); r.tap(STAFF, hold_ms=1000); r.run(1800)
    d = r.find("ACCESS_DENIED", n1)
    chk("valid staff card during lockout -> denied (LOCKOUT)", len(d) == 1 and d[0]["arg"] == 5 and not r.unlocked(), d)
    n2 = len(r.evs); r.tap(ADMIN, hold_ms=1000); r.run(1800)
    chk("admin card ends the lockout and opens an admin session", [e for e in r.names(n2)][:3] == ["LOCKOUT_END", "ADMIN_SESSION", "ACCESS_GRANTED"] or {"LOCKOUT_END", "ADMIN_SESSION"} <= set(r.names(n2)), r.names(n2))
    # lockout expiry on its own
    r2 = Rig()
    for _ in range(3): r2.tap(UNKNOWN, hold_ms=800); r2.run(1700)
    n = len(r2.evs); r2.run(31000)
    chk("lockout ends by itself after 30 s", any(e["name"] == "LOCKOUT_END" and e["arg"] == 0 for e in r2.evs[n:]), r2.names(n))
    n = len(r2.evs); r2.tap(STAFF, hold_ms=1000); r2.run(1500)
    chk("... and the staff card works again", "ACCESS_GRANTED" in r2.names(n), r2.names(n))
    # busy
    r3 = Rig(); r3.tap(STAFF, hold_ms=800); r3.run(1000); n = len(r3.evs); r3.tap(STAFF2, hold_ms=800); r3.run(1500)
    d = r3.find("ACCESS_DENIED", n)
    chk("second tap while a grant is pending -> BUSY, not counted as a failure", len(d) == 1 and d[0]["arg"] == 6 and not r3.find("LOCKOUT_START"), d)
    # grant timeout
    r4 = Rig(); r4.tap(STAFF, hold_ms=800); t0 = r4.s.t; r4.run(7500)
    chk("tap but nobody walks: GRANT_TIMEOUT after ~6 s and door relocks, no alarm", len(r4.find("GRANT_TIMEOUT")) == 1 and not r4.unlocked() and r4.sts[-1][1]["alarm"] == 0, r4.names())
    iv = r4.open_intervals(); chk("... door was open ~6 s, not longer", len(iv) == 1 and 5.7 < iv[0][1] - iv[0][0] < 6.6, [(round(a, 2), round(b, 2)) for a, b in iv])
    # time windows
    for label, ep, uid, expect in (("staff on Saturday", SAT10, STAFF, 3), ("staff at 07:59 Wed", EP(2026, 10, 14, 7, 59, 0), STAFF, 3), ("guest at 09:00 Wed", EP(2026, 10, 14, 9, 0), GUEST, 3)):
        rr = Rig(sync=ep); n = len(rr.evs); rr.tap(uid, hold_ms=1000); rr.run(1500)
        d = rr.find("ACCESS_DENIED", n); chk("%s -> denied (time window)" % label, len(d) == 1 and d[0]["arg"] == expect, d)
    rr = Rig(sync=EP(2026, 10, 14, 7, 59, 55)); rr.run(6500); n = len(rr.evs); rr.tap(STAFF, hold_ms=1000); rr.run(1500)
    chk("clock rolls over 08:00 -> staff now granted", "ACCESS_GRANTED" in rr.names(n), rr.names(n))
    rr = Rig(sync=SAT10); n = len(rr.evs); rr.tap(ADMIN, hold_ms=1000); rr.run(1500)
    chk("admin works any time (Saturday)", "ACCESS_GRANTED" in rr.names(n), rr.names(n))
    rr = Rig(sync=None); n = len(rr.evs); rr.tap(STAFF, hold_ms=1000); rr.run(1500)
    d = rr.find("ACCESS_DENIED", n); chk("clock never synced -> staff denied (UNSYNCED_CLOCK)", len(d) == 1 and d[0]["arg"] == 4, d)
    r.hygiene()


def t_api():
    new("api")
    r = Rig(); n = len(r.evs)
    a = r.cmd("ACK"); b = r.cmd("UNLOCKOUT"); c = r.cmd("CAL 900 1900")
    chk("ACK / UNLOCKOUT / CAL refused without an admin session (violations logged, rate-limited)", all("ERR" in x[0] for x in (a, b, c)) and len(r.find("API_VIOLATION", n)) >= 1, (a, b, c, r.names(n)))
    chk("the refused CAL did not move the servo", abs(r.servo() - 0.0007) < 3e-5, r.servo())
    r.tap(ADMIN, hold_ms=1000); r.run(1200)
    chk("admin card opens a session (ADMIN_SESSION)", len(r.find("ADMIN_SESSION")) == 1, r.names())
    c = r.cmd("CAL 900 1900", 300)
    chk("CAL accepted in an admin session", c and "OK CAL" in c[0], c)
    r.run(7000)
    chk("new lock position reaches the servo pin (900 us)", abs(r.servo() - 0.0009) < 3e-5, r.servo())
    rt = Rig(); tm = rt.cmd("TIME 1000"); chk("TIME refused once the clock is synced and no admin session is open", tm and "ERR" in tm[0], tm)
    p = r.cmd("PROBE 0"); chk("PROBE: secure boundary refuses the call", p and "refused" in p[0], p)
    rr = Rig(); out = rr.cmd("ATTACK 1"); chk("production build has NO attack commands (ATTACK -> unknown command)", out and "unknown" in out[0], out)
    s = r.cmd("STATUS"); chk("STATUS answers in the documented format", r.sts and r.sts[-1][1]["tv"] == 1, s)
    # attacks (documented software-isolation limits)
    for k, label, expect in ((1, "naive tamper", "TAMPER"), (3, "direct servo write", "TAMPER")):
        rr = Rig(build="/tmp/tg_attack/build"); n = len(rr.evs); out = rr.cmd("ATTACK %d" % k, 400); rr.run(800)
        chk("ATTACK %d (%s) is detected -> TAMPER event, door stays locked" % (k, label), len(rr.find(expect, n)) >= 1 and not rr.unlocked(), (out, rr.names(n)))
    rr = Rig(build="/tmp/tg_attack/build"); n = len(rr.evs); out = rr.cmd("ATTACK 2", 400); rr.run(800)
    chk("ATTACK 2 (forged unlock with recomputed seal) opens silently -- documented limit", rr.unlocked() and not rr.find("ACCESS_GRANTED", n), (out, rr.names(n), rr.unlocked()))
    r.hygiene()


def t_uart():
    new("uart")
    r = Rig(); n = len(r.other)
    for i in range(150): r.s.after(0.02 * i, lambda: r.s.send("PING"))          # one command every 20 ms for 3 s
    r.s.after(1.0, lambda: r.s.send("X" * 200)); r.tap(STAFF, hold_ms=900); r.run(6000)
    pongs = sum(1 for _, l in r.other[n:] if l == "OK PONG")
    chk("150 PING commands at 50/s while events print (+ one 200-char junk line) -> 150 replies", pongs == 150, pongs)
    chk("... while a card event was being printed", "ACCESS_GRANTED" in r.names(), r.names())
    chk("no USART overrun (ORE) left pending", not r.s.usart1.ore)
    seqs = [e["seq"] for e in r.evs]; chk("event sequence numbers contiguous", seqs == list(range(seqs[0], seqs[0] + len(seqs))), seqs)
    r.hygiene()


def t_ir():
    new("ir")
    r = Rig(); n = len(r.evs)
    for i in range(40): r.beam(i & 1, True, 100 + i * 150); r.beam(i & 1, False, 108 + i * 150)       # 8 ms glitches, alternating beams
    r.run(7000)
    chk("40 glitches of 8 ms (< 20 ms debounce) -> no event, door locked", not [e for e in r.evs[n:] if e["name"] not in ("BOOT",)] and not r.unlocked(), r.names(n))
    r.beam(0, True, 0); r.run(1700); r.beam(0, False, 0); r.run(500)
    # a single beam held 2 s then released, then a normal visit
    n = len(r.evs); r.tap(STAFF, hold_ms=1000); e = r.walk("in", at_ms=300); r.run(e + 2500)
    chk("sensor recovers: normal entry works afterwards", r.names(n)[:2] == ["ACCESS_GRANTED", "ENTRY_OK"], r.names(n))
    rr = Rig(); n = len(rr.evs); rr.beam(0, True, 100); rr.run(31500)
    chk("beam stuck blocked > 30 s -> SENSOR_STUCK warning", len(rr.find("SENSOR_STUCK", n)) == 1, rr.names(n))
    rr.beam(0, False, 0); rr.run(500); n = len(rr.evs); rr.tap(STAFF, hold_ms=1000); e = rr.walk("in", at_ms=300); rr.run(e + 2500)
    chk("... and the system works again once the beam is freed", rr.names(n)[:2] == ["ACCESS_GRANTED", "ENTRY_OK"], rr.names(n))
    # two people standing in the doorway: beams blocked > 1.5 s
    r5 = Rig(); r5.tap(STAFF, hold_ms=800); r5.beam(0, True, 400); r5.beam(1, True, 500); r5.beam(0, False, 2300); r5.beam(1, False, 2400); r5.run(5000)
    chk("beams blocked > 1.5 s -> GROUP_SUSPECT warning", len(r5.find("GROUP_SUSPECT")) >= 1, r5.names())
    r.hygiene()


def t_reset():
    new("reset")
    r = Rig(); s = r.s
    r.tap(STAFF, hold_ms=1500); e = r.walk("in", at_ms=500); r.run(e + 2500)
    chk("person is inside before the crash", r.sts[-1][1]["inside"] == 1, r.sts[-1][1])
    t_hang = s.t
    s.uc.reg_write(UC_ARM_REG_PC, s.syms["HardFault_Handler"] & ~1)           # main loop stuck (interrupts still running)
    r.run(2500)
    chk("watchdog resets a hung main loop", [k for _, k in s.resets][-1] == "iwdg", s.resets)
    t_rst = [t for t, k in s.resets if k == "iwdg"]
    chk("... within ~1 s of the hang (%.2f s)" % ((t_rst[0] - t_hang) if t_rst else -1), t_rst and 0.6 < t_rst[0] - t_hang < 1.3, t_rst)
    b = r.find("BOOT"); chk("boot event carries reset cause 1 (watchdog)", len(b) == 2 and b[1]["arg"] == 1, b)
    chk("door is locked again after the reset", not r.unlocked() and r.sts[-1][1]["door"] == "L", r.servo())
    r.sync(WED10); n = len(r.evs); r.tap(STAFF, hold_ms=1500); e = r.walk("out", at_ms=500); r.run(e + 2500)
    chk("first exit after the reset is accepted (side 'unknown'), NO false alarm", r.names(n)[:2] == ["ACCESS_GRANTED", "EXIT_OK"] and not r.find("ANTIPASSBACK", n) and not r.find("DIR_MISMATCH", n), r.names(n))
    # complete freeze: interrupts masked too
    r2 = Rig(); r2.s.uc.reg_write(UC_ARM_REG_PC, r2.s.syms["HardFault_Handler"] & ~1); r2.s.uc.reg_write(UC_ARM_REG_PRIMASK, 1); r2.run(2500)
    chk("watchdog also recovers a total freeze (PRIMASK set)", [k for _, k in r2.s.resets][-1] == "iwdg" and len(r2.find("BOOT")) == 2, r2.s.resets)
    # power cut while the door is open
    r3 = Rig(); r3.tap(STAFF, hold_ms=800); r3.run(1500); was = r3.unlocked()
    r3.s.reset("por"); r3.run(800)
    chk("power cycle while unlocked: boots LOCKED (was open: %s)" % was, was and not r3.unlocked(), r3.servo())
    # reset button
    r3.s.reset("pin"); r3.run(800); b = r3.find("BOOT"); chk("NRST button -> boot cause 2", b[-1]["arg"] == 2, b[-1])
    r.hygiene()


def t_hardware_variants():
    new("hw_variants")
    r = Rig(sync=None, rc522_present=False); r.run(1500)
    chk("no RC522 wired: banner says rc522=FAIL, firmware keeps running", any(l.startswith("BOOT") and "rc522=FAIL" in l for _, l in r.s.board.lines) and r.sts, [l for _, l in r.s.board.lines][:1])
    r.sync(WED10); n = len(r.evs); r.walk("in", at_ms=100); r.run(1500)
    chk("... and still detects an unauthorised passage", "UNAUTH_PASSAGE" in r.names(n), r.names(n))
    for ver in (0x88, 0x12, 0x91):
        rr = Rig(rc522_version=ver); b = [l for _, l in rr.s.board.lines if l.startswith("BOOT")]
        rr.tap(STAFF, hold_ms=1000); rr.run(1500)
        chk("clone RC522 version byte 0x%02X accepted and reads cards" % ver, b and "rc522=ok" in b[0] and "ACCESS_GRANTED" in rr.names(), b)
    for ver in (0x00, 0xFF):
        rr = Rig(rc522_version=ver, sync=None); b = [l for _, l in rr.s.board.lines if l.startswith("BOOT")]
        chk("RC522 reading 0x%02X (miswired) -> rc522=FAIL" % ver, b and "rc522=FAIL" in b[0], b)
    rr = Rig(rc522_start_s=0.045); b = [l for _, l in rr.s.board.lines if l.startswith("BOOT")]
    chk("slow RC522 oscillator start-up (45 ms) still initialises", b and "rc522=ok" in b[0], b)
    rr = Rig(hse_ok=False); b = [l for _, l in rr.s.board.lines if l.startswith("BOOT")]
    chk("crystal dead: falls back to 8 MHz HSI and says so", b and "sysclk=8000000" in b[0], b)
    n = len(rr.evs); rr.tap(STAFF, hold_ms=1500); e = rr.walk("in", at_ms=500); rr.run(e + 2500)
    chk("... UART baud still within 3 % and a full entry works at 8 MHz", abs(rr.s.usart1.baud() / 115200 - 1) < 0.03 and rr.names(n)[:2] == ["ACCESS_GRANTED", "ENTRY_OK"], (round(rr.s.usart1.baud()), rr.names(n)))
    sv = rr.s.board.servo(); chk("... servo PWM still 20 ms period at 8 MHz", sv and abs(sv["period"] - 0.02) < 2e-4, sv)
    for lsi in (30000, 60000):
        rr = Rig(lsi_hz=lsi); rr.tap(STAFF, hold_ms=1500); e = rr.walk("in", at_ms=500)
        worst = 9.0
        for _ in range(60):
            rr.run(100); ex = rr.s.iwdg.expiry(); worst = min(worst, ex - rr.s.t) if ex else worst
        chk("LSI %d kHz: watchdog never trips; min margin %.2f s" % (lsi // 1000, worst), [k for _, k in rr.s.resets] == ["por"] and worst > 0.3, rr.s.resets)
    rr = Rig(rc522_present=True, fast_timeout=False); rr.tap(STAFF, hold_ms=1500); e = rr.walk("in", at_ms=500); rr.run(e + 3000)
    chk("with the real 10 ms RC522 timeout (no emulator shortcut): entry works", rr.names()[-3:-1] == ["ACCESS_GRANTED", "ENTRY_OK"] or "ENTRY_OK" in rr.names(), rr.names())
    rr = Rig(drop=0.35); n = len(rr.evs)
    for i in range(3): rr.tap((STAFF, STAFF2, GUEST)[i], hold_ms=1500); e = rr.walk("in", at_ms=800); rr.run(e + 4000)
    chk("35 %% of RC522 frames lost: every presentation still yields exactly one grant (%d/3)" % len(rr.find("ACCESS_GRANTED", n)), len(rr.find("ACCESS_GRANTED", n)) == 3 and not rr.find("LOCKOUT_START"), rr.names(n))
    r.hygiene()


def t_recovery():
    new("recovery")
    r = Rig(); s = r.s; rc = s.board.rc
    r.tap(STAFF, 900); e = r.walk("in", at_ms=400); r.run(e + 2500)
    chk("reader works before the glitch", r.names()[-2:] == ["ACCESS_GRANTED", "ENTRY_OK"], r.names())
    def glitch(): rc.hard_reset(); rc.ready_at = s.t + 0.02              # supply dip resets the RC522: registers lost, antenna off
    s.after(0.05, glitch); r.run(4000)
    n = len(r.evs); r.tap(STAFF2, 1200); r.run(2500)
    chk("RC522 reset by a supply glitch: reader recovers by itself (card works 4 s later)", "ACCESS_GRANTED" in r.names(n), r.names(n))
    r2 = Rig(rc522_present=False); r2.run(500)
    chk("RC522 not answering at boot: banner says FAIL", any("rc522=FAIL" in l for _, l in r2.s.board.lines))
    r2.s.board.rc.present = True; r2.run(3500); r2.tap(STAFF, 1200); r2.run(2000)
    chk("RC522 wire fixed after boot: reader comes up without a power cycle", "ACCESS_GRANTED" in r2.names(), r2.names())
    chk("... and the firmware reports RC522_RECOVERED", any("RC522_RECOVERED" in l for _, l in r2.other), [l for _, l in r2.other][-3:])
    r3 = Rig(rc522_present=False); r3.run(24000)
    gaps = [b[0] - a[0] for a, b in zip(r3.sts, r3.sts[1:])]
    chk("RC522 permanently absent: status keeps its 1 Hz cadence (max gap %.2f s), no watchdog reset, no warning spam" % max(gaps), max(gaps) < 1.3 and [k for _, k in r3.s.resets] == ["por"] and sum(1 for _, l in r3.other if l.startswith("WARN")) <= 1, (max(gaps), r3.s.resets))
    r3.walk("in", at_ms=100); r3.run(1500)
    chk("... still detects an unauthorised passage", "UNAUTH_PASSAGE" in r3.names(), r3.names())
    r.hygiene()


def t_people(n_walks=45, seed=11):
    new("people")
    rnd = random.Random(seed); r = Rig(cpi=6.0, seed=3); cards = [STAFF, STAFF2, GUEST]; inside = {c: False for c in cards}; fails, ok = [], 0
    for i in range(n_walks):
        c = rnd.choice(cards); d = "out" if inside[c] else "in"
        off = rnd.randint(40, 450)
        hold = rnd.randint(120, max(off - 20, 121)) if (off >= 160 and rnd.random() < 0.3) else rnd.randint(max(off + 80, 150), 900)   # 30 %: beams never overlap (fast / thin walker)
        n = len(r.evs); r.tap(c, 1200); end = r.walk(d, at_ms=rnd.randint(250, 3000), off=off, hold=hold); r.run(end + 2700)
        nm = r.names(n)
        if nm == ["ACCESS_GRANTED", "ENTRY_OK" if d == "in" else "EXIT_OK"]: ok += 1; inside[c] = not inside[c]
        else: fails.append((i, d, "off=%d hold=%d" % (off, hold), nm))
    chk("%d legitimate passages with random speed/body width: %d clean, no false alarm" % (n_walks, ok), not fails, fails[:3])
    last = r.sts[-1][1]; chk("people counter equals the number the test left inside (%d)" % sum(inside.values()), last["inside"] == sum(inside.values()), last)
    # slow walker: first beam crossed just before the 6 s grant expires, second one after it
    r2 = Rig(); r2.tap(STAFF, 800); r2.walk("in", at_ms=5850, off=500, hold=900); r2.run(9000)
    chk("slow walker caught by the 6 s expiry is still let through (ENTRY_OK, no alarm)", r2.names()[-2:] == ["ACCESS_GRANTED", "ENTRY_OK"] and "UNAUTH_PASSAGE" not in r2.names(), r2.names())
    r3 = Rig(); r3.tap(STAFF, 800); r3.walk("in", at_ms=7500); r3.run(10000)
    chk("walker 1.5 s AFTER the grant expired -> GRANT_TIMEOUT then UNAUTH_PASSAGE", r3.names()[-3:] == ["ACCESS_GRANTED", "GRANT_TIMEOUT", "UNAUTH_PASSAGE"], r3.names())
    r.hygiene()


def t_reset_storm():
    new("reset_storm")
    rnd = random.Random(5); r = Rig(); s = r.s; slow = []
    for i in range(30):
        s.reset(rnd.choice(["por", "pin", "soft"])); r.run(rnd.randint(1, 350))
    s.reset("por"); n0 = sum(1 for _, l in s.board.lines if l.startswith("BOOT,")); r.run(900)
    chk("30 random resets (many in the middle of RC522 init): next boot is clean", sum(1 for _, l in s.board.lines if l.startswith("BOOT,")) == n0 + 1 and any("rc522=ok" in l for _, l in s.board.lines[-6:]), [l for _, l in s.board.lines if l][-2:])
    r.sync(WED10); n = len(r.evs); r.tap(STAFF, 1200); e = r.walk("in", at_ms=500); r.run(e + 2500)
    chk("... and a full entry works afterwards", r.names(n)[:2] == ["ACCESS_GRANTED", "ENTRY_OK"], r.names(n))
    chk("no faults, door locked", not s.faults and not s.errors and not r.unlocked(), (s.faults[:1], s.errors[:1]))


def t_bigger_chip():
    new("bigger_chip")
    for fk, rk in ((64, 20), (128, 20)):
        rr = Rig(chip=(fk, rk)); rr.tap(STAFF, 1200); e = rr.walk("in", at_ms=500); rr.run(e + 2500)
        chk("same binary on a %d KB-flash / %d KB-RAM clone (C8/CB): entry works" % (fk, rk), rr.names()[-2:] == ["ACCESS_GRANTED", "ENTRY_OK"] and not rr.s.faults, rr.names())


def t_soak(seconds=150, seed=7):
    new("soak")
    rnd = random.Random(seed); r = Rig(cpi=6.0, seed=seed); s = r.s; n0 = len(r.evs)
    cards = [STAFF, STAFF2, GUEST]
    t = 0.0; log = []
    while t < seconds:
        k = rnd.choice(["in", "out", "tail", "unauth", "bad", "tapnowalk", "noise", "uart", "in", "out"])
        d = rnd.choice(cards)
        if k in ("in", "out"): r.tap(d, 1200); r.walk(k, at_ms=rnd.randint(300, 1500))
        elif k == "tail":
            r.tap(d, 1200); e = r.walk("in", at_ms=500); r.walk("in", at_ms=e + rnd.randint(450, 2500))
        elif k == "unauth": r.walk(rnd.choice(["in", "out"]), at_ms=200)
        elif k == "bad": r.tap(UNKNOWN, 1000)
        elif k == "tapnowalk": r.tap(d, 800)
        elif k == "noise":
            for _ in range(8):
                i, at = rnd.randint(0, 1), rnd.randint(0, 4000); r.beam(i, True, at); r.beam(i, False, at + rnd.randint(2, 15))
        elif k == "uart":
            for c in ("STATUS", "STATS", "PING", "ACK"): s.send(c)
        log.append((round(t, 1), k)); gap = rnd.uniform(9.0, 13.0); r.run(gap * 1000); t += gap
    r.run(9000)
    grants = [e["t"] for e in r.evs[n0:] if e["name"] == "ACCESS_GRANTED"]
    bad, worst = [], 0.0
    for a, b in r.open_intervals():
        g = [x for x in grants if x <= a + 0.1]
        if not g: bad.append((round(a, 2), round(b, 2), "open with no grant")); continue
        worst = max(worst, b - g[-1])
        if b - g[-1] > 12.0: bad.append((round(a, 2), round(b, 2), "open too long"))
    chk("soak %d s sim: %d actions, %d grants, %d alarms" % (seconds, len(log), len(grants), len([e for e in r.evs if e["name"] in ("TAILGATE", "UNAUTH_PASSAGE")])), True)
    chk("INVARIANT door open only after a grant, never longer than %.1f s (limit 12)" % worst, not bad, bad[:3])
    chk("INVARIANT no watchdog reset, no fault, no stack imbalance", [k for _, k in s.resets] == ["por"] and not s.faults and not s.warns, (s.resets, s.faults[:1], s.warns[:2]))
    seqs = [e["seq"] for e in r.evs]; chk("INVARIANT event log has no gaps", seqs == list(range(seqs[0], seqs[0] + len(seqs))), seqs[:5])
    lw, end = s.stack_low_water(); free = SRAM + s.ram_bytes - end
    chk("peak stack %d B of %d B free RAM (>= 2x headroom)" % (lw, free - 512), lw * 2 < free - 512, lw)
    last = r.sts[-1][1]; chk("status block still sane at the end", last["door"] in "LU" and 0 <= last["inside"] <= 4, last)
    r.hygiene()


def save():
    rp = os.path.join(HERE, "results.json")                       # merge by test name so the suite can be run in pieces
    old = [x for x in (json.load(open(rp)) if os.path.exists(rp) else []) if x[0] not in {y[0] for y in RESULTS}]
    json.dump(old + [list(x) for x in RESULTS], open(rp, "w"), indent=1)


TESTS = [t_boot, t_reader, t_entry_exit, t_tailgate, t_passback, t_policy, t_api, t_uart, t_ir, t_reset, t_hardware_variants, t_recovery, t_people, t_reset_storm, t_bigger_chip, t_soak]

if __name__ == "__main__":
    if sys.argv[1:] == ["--md"]:
        R = json.load(open(os.path.join(HERE, "results.json"))); out = ["# Emulated test results", "", "Real `build/trustgate.bin` on the emulated Blue Pill (see README section 10).", ""]
        for t in dict.fromkeys(x[0] for x in R):
            rs = [x for x in R if x[0] == t]; out += ["## %s  (%d/%d)" % (t, sum(1 for x in rs if x[2]), len(rs)), ""] + ["- %s %s" % ("PASS" if o else "**FAIL**", n) for _, n, o, _ in rs] + [""]
        open(os.path.join(HERE, "RESULTS.md"), "w").write("\n".join(out)); print("RESULTS.md written"); sys.exit(0)
    if sys.argv[1:] == ["--summary"]:
        R = json.load(open(os.path.join(HERE, "results.json"))); tests = []
        for t, n, o, d in R:
            if t not in tests: tests.append(t)
        for t in tests: rs = [x for x in R if x[0] == t]; print("%-14s %3d/%-3d %s" % (t, sum(1 for x in rs if x[2]), len(rs), "" if all(x[2] for x in rs) else "FAILED"))
        print("TOTAL %d/%d" % (sum(1 for x in R if x[2]), len(R))); sys.exit(0)
    want = sys.argv[1:]; t0 = time.time()
    for fn in TESTS:
        if want and fn.__name__[2:] not in want and fn.__name__ not in want: continue
        t1 = time.time()
        try: fn()
        except Exception as e:
            import traceback; traceback.print_exc(); chk("test crashed: %r" % e, False)
        print("  (%.1f s wall)" % (time.time() - t1), flush=True)
    ok = sum(1 for x in RESULTS if x[2]); print("\n==== %d/%d checks passed in %.0f s ====" % (ok, len(RESULTS), time.time() - t0))
    save()
    for t, n, o, d in RESULTS:
        if not o: print("FAILED [%s] %s  %s" % (t, n, d))
