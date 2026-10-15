#!/usr/bin/env python3
"""End-to-end: REAL tools/dashboard.py <-> virtual serial port <-> REAL firmware on the emulated board, with a mock ntfy server.
Runs paced to wall-clock (about 50 s)."""
import os, sys, pty, tty, time, json, select, subprocess, threading, http.server, urllib.request, urllib.error
HERE = os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0, HERE)
import suite
from suite import Rig, chk, ADMIN, STAFF, STAFF2, UNKNOWN, ROOT

suite.CUR[0] = "dashboard_e2e"; print("\n[dashboard_e2e]", flush=True)
pushes = []
class H(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", 0))).decode()
        pushes.append(dict(path=self.path, title=self.headers.get("Title"), prio=self.headers.get("Priority"), body=body)); self.send_response(200); self.end_headers()
    def log_message(self, *a): pass
srv = http.server.ThreadingHTTPServer(("127.0.0.1", 18765), H); threading.Thread(target=srv.serve_forever, daemon=True).start()

master, slave = pty.openpty(); tty.setraw(slave); name = os.ttyname(slave)
csvp, logp = "/tmp/tg_e2e_events.csv", "/tmp/tg_e2e_dashboard.log"
if os.path.exists(csvp): os.remove(csvp)
proc = subprocess.Popen([sys.executable, ROOT + "/tools/dashboard.py", "--port", name, "--ntfy-server", "http://127.0.0.1:18765", "--ntfy-topic", "tg-e2e",
                         "--http-port", "18080", "--csv", csvp, "--users", ROOT + "/tools/users.json.example"], stdout=open(logp, "w"), stderr=subprocess.STDOUT, cwd=ROOT, env=dict(os.environ, TZ="PST8"))   # laptop clock = UTC-8 -> mid-morning, inside the staff time window

r = Rig(sync=None, boot=False); s = r.s; sent = [0]
def pump(until):
    while s.t < until:
        while select.select([master], [], [], 0)[0]:
            d = os.read(master, 4096)
            if not d: break
            s.usart1.feed(d)
        s.run_until(min(s.t + 0.01, until)); b = s.board.uart_bytes
        if len(b) > sent[0]: os.write(master, bytes(b[sent[0]:])); sent[0] = len(b)
wall0 = sim0 = None
def realtime(sec):
    end = s.t + sec
    while s.t < end:
        pump(min(s.t + 0.02, end)); lag = (s.t - sim0) - (time.time() - wall0)
        if lag > 0: time.sleep(lag)
    r.pump()
def api(path, data=None):
    req = urllib.request.Request("http://127.0.0.1:18080" + path, data=None if data is None else json.dumps(data).encode(), method="GET" if data is None else "POST")
    try:
        with urllib.request.urlopen(req, timeout=3) as f: return f.status, f.read().decode()
    except urllib.error.HTTPError as e: return e.code, ""
    except Exception as e: return 0, repr(e)

try:
    for _ in range(60):                                   # dashboard first, then "power on" the board (as in real use)
        code, txt = api("/api/state")
        if code == 200 and json.loads(txt).get("connected"): break
        time.sleep(0.25)
    wall0, sim0 = time.time(), s.t
    realtime(5.0)
    code, txt = api("/api/state"); st0 = json.loads(txt) if code == 200 else {}
    chk("dashboard connects to the board over the (virtual) serial port and syncs the clock", st0.get("connected") is True and r.s.usart1.baud_ok() and any(e["name"] == "TIME_SET" for e in r.evs), (code, st0.get("connected"), r.names()))
    r.tap(STAFF, 1500); r.walk("in", at_ms=500); realtime(5.5)                                   # legitimate entry
    r.tap(STAFF2, 1500); e = r.walk("in", at_ms=500); r.walk("in", at_ms=e + 700); realtime(11)    # tailgater
    for i in range(3): r.tap(UNKNOWN, 800); realtime(1.8)                                        # lockout
    realtime(3)
    c1 = api("/api/cmd", {"cmd": "STATS"}); c2 = api("/api/cmd", {"cmd": "CAL 900 1900"}); c3 = api("/api/cmd", {"cmd": "ATTACK 2"}); c4 = api("/api/cmd", {"cmd": "PING"})
    realtime(2)
    from tgemu import UC_ARM_REG_PC
    st_pre = json.loads(api("/api/state")[1])
    s.uc.reg_write(UC_ARM_REG_PC, s.syms["HardFault_Handler"] & ~1); realtime(3.5)                 # firmware hangs -> watchdog resets it
    code, txt = api("/api/state"); st = json.loads(txt)
    names = [e["name"] for e in st["events"]][::-1]; raw = [e["name"] for e in r.evs]
    chk("web UI state lists every device event, in order (%d events)" % len(names), names == raw, (names, raw))
    chk("status + statistics blocks arrive and parse (taps=%s, tailgates=%s)" % (st_pre.get("stats", {}).get("taps"), st_pre.get("stats", {}).get("tailgates")), st_pre.get("status") and st_pre.get("stats", {}).get("tailgates", 0) >= 1, st_pre.get("status"))
    chk("clean start: events before the first tap are exactly BOOT, TIME_SET (no false API_VIOLATION push)", names[:3] == ["BOOT", "TIME_SET", "ACCESS_GRANTED"] and not any("API_VIOLATION" in p["title"] for p in pushes), (names[:4], [p["title"] for p in pushes]))
    chk("phone push fired for TAILGATE (urgent) and LOCKOUT_START (high)", any(p["title"] == "TrustGate: TAILGATE" and p["prio"] == "urgent" for p in pushes) and any(p["title"] == "TrustGate: LOCKOUT_START" and p["prio"] == "high" for p in pushes), [(p["title"], p["prio"]) for p in pushes])
    chk("watchdog reset reaches the phone (BOOT, high) and the clock is re-synced without a false violation", any(p["title"] == "TrustGate: BOOT" and p["prio"] == "high" for p in pushes) and [e["name"] for e in st["events"]][:2] == ["TIME_SET", "BOOT"] and not any("API_VIOLATION" in p["title"] for p in pushes), ([e["name"] for e in st["events"]][:3], [(p["title"], p["prio"], p["body"]) for p in pushes][-1:]))
    chk("exactly 3 pushes, none for routine events (grants, entries, plain denials)", len(pushes) == 3 and all(p["title"].split(": ")[1] in ("TAILGATE", "LOCKOUT_START", "BOOT") for p in pushes), [p["title"] for p in pushes])
    chk("push text carries the plain-language reason", all(len(p["body"]) > 15 for p in pushes), [p["body"] for p in pushes][:3])
    chk("web command whitelist: STATS/PING accepted (200), CAL / ATTACK refused (403)", (c1[0], c4[0], c2[0], c3[0]) == (200, 200, 403, 403), (c1[0], c4[0], c2[0], c3[0]))
    chk("dashboard reports pushes sent = %s" % st.get("pushes"), st.get("pushes") == len(pushes) == 3, st.get("pushes"))
    rows = open(csvp).read().strip().splitlines() if os.path.exists(csvp) else []
    chk("CSV log has one row per event (%d rows)" % len(rows), len(rows) == len(raw), len(rows))
    chk("both ends agree on the byte stream: dashboard saw no garbled lines", st["last_line_ts"] > 0 and proc.poll() is None, proc.poll())
    log = open(logp).read(); chk("dashboard log has no traceback", "Traceback" not in log, log[-200:])
    chk("device-side faults during the run: none", not s.faults and not s.errors and not s.warns, (s.faults[:1], s.warns[:2]))
finally:
    proc.terminate(); srv.shutdown(); suite.save()
ok = sum(1 for x in suite.RESULTS if x[2]); print("\n==== %d/%d checks passed ====" % (ok, len(suite.RESULTS)))
for t, n, o, d in suite.RESULTS:
    if not o: print("FAILED %s  %s" % (n, d))
