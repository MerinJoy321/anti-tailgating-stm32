#!/usr/bin/env python3
"""TrustGate laptop dashboard: serial monitor + web UI + ntfy push alerts.

  pip install pyserial requests
  python dashboard.py --port COM5 --ntfy-topic trustgate-YOURSECRET
  open http://127.0.0.1:8080

This program is part of the NON-SECURE world. It can display, relay and request, but every
privileged action is still decided by the firmware's secure side (admin card session required).
Local alarm (buzzer/LED) is driven by the secure firmware and does not depend on this laptop;
the push notification does."""
import argparse, collections, csv, json, queue, threading, time, sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

try:
    import requests
except ImportError:
    requests = None

DENY = ["GRANT", "UNKNOWN_CARD", "DISABLED", "OUTSIDE_TIME_WINDOW", "CLOCK_UNSYNCED", "LOCKOUT", "BUSY", "TAMPER_LOCKDOWN"]
# event -> (severity, push priority)  severity: info / warn / alarm
SEVERITY = {
    "TAILGATE": "alarm", "UNAUTH_PASSAGE": "alarm", "ANTIPASSBACK": "alarm", "DIR_MISMATCH": "alarm",
    "LOCKOUT_START": "alarm", "TAMPER": "alarm", "API_VIOLATION": "alarm",
    "GROUP_SUSPECT": "warn", "SENSOR_STUCK": "warn", "ACCESS_DENIED": "warn", "GRANT_TIMEOUT": "info",
}
PUSH = {"TAILGATE": "urgent", "UNAUTH_PASSAGE": "urgent", "ANTIPASSBACK": "high", "DIR_MISMATCH": "high",
        "LOCKOUT_START": "high", "TAMPER": "urgent", "API_VIOLATION": "high", "GROUP_SUSPECT": "default", "SENSOR_STUCK": "default"}
STAT_KEYS = ["taps", "granted", "denied", "entries", "exits", "tailgates", "unauth_passages", "antipassback", "dir_mismatch",
             "lockouts", "api_violations", "tamper", "aborts", "group_suspect", "decision_us_last", "decision_us_max"]
CMD_WHITELIST = {"PING", "STATUS", "STATS", "LOG", "ACK", "UNLOCKOUT"}

lock = threading.Lock()
state = {"connected": False, "port": "", "boot": "", "status": {}, "stats": {}, "events": collections.deque(maxlen=300),
         "seen": set(), "last_line_ts": 0.0, "pushes": 0}
tx_q: "queue.Queue[str]" = queue.Queue()
push_q: "queue.Queue[tuple]" = queue.Queue()
users = {}
args = None
csv_writer = csv_file = None


def local_epoch():
    return int(time.time()) + time.localtime().tm_gmtoff


def describe(ev):
    n, a = ev["name"], ev["arg"]
    who = users.get(ev["uid"], ev["uid"]) if ev["uid"] != "00000000" else ""
    if n == "ACCESS_DENIED": return f"{who or ev['uid']} denied: {DENY[a] if a < len(DENY) else a}"
    if n == "ACCESS_GRANTED": return f"{who} granted ({['ENTRY', 'EXIT', 'either direction: side unknown after reset'][a] if a < 3 else a} expected)"
    if n == "BOOT": return {0: "boot", 1: "WATCHDOG RESET: firmware hung or faulted", 2: "reset pin", 3: "power-on", 4: "software reset"}.get(a, "boot")
    if n in ("ENTRY_OK", "EXIT_OK"): return f"{who} {'entered' if n == 'ENTRY_OK' else 'exited'}"
    if n == "TAILGATE": return f"second person followed {who} ({'out' if a else 'in'})"
    if n == "UNAUTH_PASSAGE": return f"passage with no valid tap ({'out' if a else 'in'})"
    if n == "ANTIPASSBACK": return f"card of {who} (already inside) used to enter again"
    if n == "DIR_MISMATCH": return f"{who} passed in the opposite direction to the granted one"
    if n == "LOCKOUT_START": return f"lockout for {a} s after repeated failures"
    if n == "GROUP_SUSPECT": return f"beams blocked {a} ms: possible group / loitering"
    if n == "TAMPER": return {1: "secure state corrupted", 3: "secure state corrupted (periodic check)", 2: "servo register written outside secure code"}.get(a, f"integrity fault {a}")
    if n == "API_VIOLATION": return f"refused call code 0x{a:X}"
    if n == "PASSAGE_ABORT": return f"approach aborted (sensor {a})"
    return who


def handle_line(line):
    line = line.strip()
    if not line: return
    state["last_line_ts"] = time.time()
    p = line.split(",")
    try:
        if p[0] == "BOOT":
            state["boot"] = line; state["seen"].clear()          # the firmware asks "TIME?" itself (boot + every 5 s while unsynced)
        elif line == "TIME?":
            tx_q.put(f"TIME {local_epoch()}")
        elif p[0] == "WARN" and len(p) > 1:
            print(f"[device] {line}")
            if p[1] == "RC522_LOST": push_q.put(({"name": "RC522_LOST", "text": "card reader stopped answering (supply dip or loose wire)"}, "high"))
        elif p[0] == "ST" and len(p) >= 11:
            state["status"] = {"tick": int(p[1]), "door": p[2], "grant": int(p[3]), "inside": int(p[4]), "lockout_s": int(p[5]),
                               "alarm": int(p[6]), "time_valid": int(p[7]), "admin_s": int(p[8]), "ir1": int(p[9][0]),
                               "ir2": int(p[9][1]), "tamper_lockdown": int(p[10])}
        elif p[0] == "SX" and len(p) == 17:
            state["stats"] = dict(zip(STAT_KEYS, map(int, p[1:])))
        elif p[0] == "EV" and len(p) >= 8:
            seq = int(p[1])
            if seq in state["seen"]: return
            state["seen"].add(seq)
            ev = {"seq": seq, "tick": int(p[2]), "epoch": int(p[3]), "name": p[4], "user": int(p[5]), "uid": p[6], "arg": int(p[7])}
            ev["wall"] = time.strftime("%H:%M:%S")
            ev["sev"] = SEVERITY.get(ev["name"], "info"); ev["text"] = describe(ev)
            state["events"].appendleft(ev)
            if csv_writer:
                csv_writer.writerow([time.strftime("%Y-%m-%d %H:%M:%S"), seq, ev["tick"], ev["name"], ev["user"], ev["uid"], ev["arg"], ev["text"]])
                csv_file.flush()                                   # audit log must survive a laptop crash / kill
            cur = state["status"].get("tick")
            fresh = cur is None or (cur - ev["tick"]) < 60000
            if ev["name"] == "BOOT" and ev["arg"] == 1: ev["sev"] = "alarm"; push_q.put((ev, "high"))   # watchdog reset = device fault
            elif ev["name"] in PUSH and fresh: push_q.put((ev, PUSH[ev["name"]]))
    except (ValueError, IndexError):
        pass


def serial_thread():
    import serial
    while True:
        try:
            s = serial.Serial(args.port, args.baud, timeout=0.2)
            with lock: state["connected"] = True; state["port"] = args.port
            print(f"[serial] connected to {args.port}")
            buf = b""                                              # no TIME here: a synced board would refuse it and log a false API_VIOLATION
            while True:
                while not tx_q.empty():
                    s.write((tx_q.get() + "\n").encode())
                data = s.read(256)
                if data:
                    buf += data
                    while b"\n" in buf:
                        ln, buf = buf.split(b"\n", 1)
                        with lock: handle_line(ln.decode(errors="replace"))
        except Exception as e:
            with lock: state["connected"] = False
            print(f"[serial] {e}; retrying in 2 s")
            time.sleep(2)


def replay_thread(path):
    with lock: state["connected"] = True; state["port"] = f"replay:{path}"
    for ln in open(path):
        with lock: handle_line(ln)
        time.sleep(0.15)


def push_thread():
    while True:
        ev, prio = push_q.get()
        title = f"TrustGate: {ev['name']}"
        body = ev["text"] or ev["name"]
        print(f"[push:{prio}] {title} - {body}")
        if not args.ntfy_topic or requests is None: continue
        try:
            requests.post(f"{args.ntfy_server.rstrip('/')}/{args.ntfy_topic}", data=body.encode("utf-8"), timeout=8,
                          headers={"Title": title, "Priority": prio, "Tags": "rotating_light,lock"})
            with lock: state["pushes"] += 1
        except Exception as e:
            print(f"[push] failed: {e}")


PAGE = r"""<!doctype html><meta charset=utf-8><title>TrustGate</title>
<style>
:root{--bg:#0f1318;--card:#171d25;--ink:#e6edf3;--mut:#8b98a5;--ok:#3fb950;--warn:#d29922;--bad:#f85149;--line:#2a323d}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:14px/1.45 system-ui,Segoe UI,sans-serif;padding:16px}
h1{font-size:18px;margin:0 0 12px}h1 span{color:var(--mut);font-weight:400;font-size:13px;margin-left:8px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px;margin-bottom:14px}
.c{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:10px 12px}.c b{display:block;font-size:11px;color:var(--mut);text-transform:uppercase;letter-spacing:.05em}
.c div{font-size:20px;margin-top:2px}.ok{color:var(--ok)}.warn{color:var(--warn)}.bad{color:var(--bad)}
.row{display:grid;grid-template-columns:2fr 1fr;gap:14px}@media(max-width:900px){.row{grid-template-columns:1fr}}
table{width:100%;border-collapse:collapse}td,th{padding:5px 8px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top}th{color:var(--mut);font-weight:500;font-size:12px}
tr.alarm td:nth-child(3){color:var(--bad);font-weight:600}tr.warn td:nth-child(3){color:var(--warn)}
button{background:#21262d;color:var(--ink);border:1px solid var(--line);border-radius:6px;padding:6px 10px;cursor:pointer;margin:0 6px 6px 0}button:hover{border-color:var(--mut)}
.beam{display:inline-block;width:12px;height:12px;border-radius:50%;background:#2a323d;margin-right:4px}.beam.on{background:var(--bad)}
small{color:var(--mut)}#msg{margin-left:6px;color:var(--mut)}
</style>
<h1>TrustGate <span id=conn></span></h1>
<div class=grid id=cards></div>
<div style="margin-bottom:12px">
<button onclick="cmd('ACK')">Acknowledge alarm</button><button onclick="cmd('UNLOCKOUT')">Clear lockout</button>
<button onclick="cmd('STATS')">Refresh stats</button><button onclick="cmd('LOG')">Load device log</button>
<small>ACK / Clear lockout need an open admin session: tap the admin card first.</small><span id=msg></span></div>
<div class=row>
<div class=c style="padding:0;overflow:auto;max-height:60vh"><table><thead><tr><th>Time</th><th>#</th><th>Event</th><th>Detail</th></tr></thead><tbody id=ev></tbody></table></div>
<div class=c><b>Statistics</b><table id=stats></table></div></div>
<script>
const $=id=>document.getElementById(id);
async function cmd(c){const r=await fetch('/api/cmd',{method:'POST',body:JSON.stringify({cmd:c})});$('msg').textContent=r.ok?'sent '+c:'refused';}
function card(t,v,cls){return `<div class=c><b>${t}</b><div class="${cls||''}">${v}</div></div>`}
async function tick(){
 try{const s=await (await fetch('/api/state')).json(), st=s.status||{};
 $('conn').textContent=(s.connected?'connected ':'DISCONNECTED ')+s.port+(s.boot?' | '+s.boot:'');
 $('cards').innerHTML=
  card('Door',st.door=='U'?'UNLOCKED':'LOCKED',st.door=='U'?'warn':'ok')+
  card('Grant pending',st.grant?'yes':'no')+
  card('Inside',st.inside??'-')+
  card('Alarm',st.alarm?'ACTIVE':'quiet',st.alarm?'bad':'ok')+
  card('Lockout',st.lockout_s?st.lockout_s+' s':'none',st.lockout_s?'bad':'ok')+
  card('Tamper lockdown',st.tamper_lockdown?'YES':'no',st.tamper_lockdown?'bad':'ok')+
  card('Clock',st.time_valid?'synced':'NOT synced',st.time_valid?'ok':'warn')+
  card('Admin session',st.admin_s?st.admin_s+' s':'closed')+
  card('Beams',`<span class="beam ${st.ir1?'on':''}"></span>IR1 <span class="beam ${st.ir2?'on':''}"></span>IR2`)+
  card('Push sent',s.pushes);
 $('ev').innerHTML=s.events.map(e=>`<tr class=${e.sev}><td>${e.wall}</td><td>${e.seq}</td><td>${e.name}</td><td>${e.text}</td></tr>`).join('');
 const x=s.stats||{};$('stats').innerHTML=Object.keys(x).map(k=>`<tr><td>${k}</td><td>${x[k]}</td></tr>`).join('');
 }catch(e){$('conn').textContent='dashboard server unreachable'}}
setInterval(tick,700);tick();
</script>"""


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a): pass

    def _send(self, code, body, ctype="application/json"):
        b = body if isinstance(body, bytes) else body.encode()
        self.send_response(code); self.send_header("Content-Type", ctype); self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)

    def do_GET(self):
        if self.path == "/": return self._send(200, PAGE, "text/html; charset=utf-8")
        if self.path == "/api/state":
            with lock:
                snap = {k: (list(v) if isinstance(v, collections.deque) else v) for k, v in state.items() if k != "seen"}
            return self._send(200, json.dumps(snap))
        self._send(404, "{}")

    def do_POST(self):
        if self.path != "/api/cmd": return self._send(404, "{}")
        try:
            c = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))))["cmd"]
        except Exception:
            return self._send(400, "{}")
        if c not in CMD_WHITELIST: return self._send(403, "{}")
        tx_q.put(c); self._send(200, "{}")


def main():
    global args, users, csv_writer, csv_file
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", help="serial port, e.g. COM5 or /dev/ttyUSB0")
    ap.add_argument("--baud", type=int, default=115200)
    ap.add_argument("--ntfy-topic", default="", help="ntfy topic name (use a long random one; topics on ntfy.sh are public by name)")
    ap.add_argument("--ntfy-server", default="https://ntfy.sh")
    ap.add_argument("--http-port", type=int, default=8080)
    ap.add_argument("--users", default="users.json", help='optional {"UIDHEX": "Name"} map')
    ap.add_argument("--csv", default="trustgate_events.csv")
    ap.add_argument("--replay", help="feed a saved text file of device lines instead of a serial port (demo/testing)")
    args = ap.parse_args()
    if not args.port and not args.replay: ap.error("--port or --replay required")
    try: users = json.load(open(args.users))
    except Exception: users = {}
    f = csv_file = open(args.csv, "a", newline="", encoding="utf-8"); csv_writer = csv.writer(f)
    threading.Thread(target=push_thread, daemon=True).start()
    if args.replay: threading.Thread(target=replay_thread, args=(args.replay,), daemon=True).start()
    else:
        try: import serial  # noqa
        except ImportError: sys.exit("pip install pyserial")
        threading.Thread(target=serial_thread, daemon=True).start()
    srv = ThreadingHTTPServer(("127.0.0.1", args.http_port), Handler)
    print(f"dashboard on http://127.0.0.1:{args.http_port}  (ntfy: {args.ntfy_topic or 'disabled'})")
    try: srv.serve_forever()
    except KeyboardInterrupt: pass


if __name__ == "__main__":
    main()
