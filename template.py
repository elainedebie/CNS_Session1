"""
collision_solve.py - SecureBank: twee geldige betalingen met dezelfde
afgekapte-SHA-256 fingerprint (birthday/rho-aanval op een te korte hash).

Werkt met weinig geheugen (Floyd/rho) i.p.v. een enorme tabel, dus ook
langere afkaplengtes lukken binnen de minuut-limiet van de timestamp.

Stappen:
 1) verbind, lees de bannertijd -> geldige timestamp binnen de vorige minuut
 2) stuur twee geldige records, lees de fingerprints -> meet afkaplengte N
 3) rho-aanval: varieer 'reference' tot twee records dezelfde fp[:N] hebben
 4) stuur die twee in -> flag
"""
import socket, json, hashlib, re, time
from datetime import datetime, timezone, timedelta

HOST, PORT = "cns-test.idlab.uantwerpen.be", 50003

def canonicalize(p):
    return json.dumps(p, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
def sha_full(p):
    return hashlib.sha256(canonicalize(p)).hexdigest()
def record(ref, ts):
    return {"reference": ref, "from_account": "SIM-AAA", "to_account": "SIM-BBB",
            "amount": 10, "currency": "EUR", "timestamp": ts}

def connect_banner():
    s = socket.create_connection((HOST, PORT), timeout=10); s.settimeout(6)
    time.sleep(0.3)
    try: banner = s.recv(8192)
    except Exception: banner = b""
    bt = banner.decode(errors="replace")
    m = re.search(r"Current time:\s*([0-9T:.\+\-]+)", bt)
    srv = datetime.fromisoformat(m.group(1)) if m else datetime.now(timezone.utc)
    offset = srv - datetime.now(timezone.utc)
    return s, bt, offset

def fresh_ts(offset, back=3):
    return (datetime.now(timezone.utc) + offset - timedelta(seconds=back)).isoformat()

def send_two(s, r1, r2):
    s.sendall((json.dumps(r1) + "\n" + json.dumps(r2) + "\n").encode())
    data = b""
    try:
        while True:
            c = s.recv(4096)
            if not c: break
            data += c
    except Exception: pass
    return data.decode(errors="replace")

def measure_N(offset):
    s, _, _ = connect_banner()
    ts = fresh_ts(offset)
    r1, r2 = record("measure-1", ts), record("measure-2", ts)
    resp = send_two(s, r1, r2); s.close()
    print("meet-antwoord:", resp.strip()[:300])
    for fp in re.findall(r"\b[0-9a-f]{4,63}\b", resp):
        for r in (r1, r2):
            if sha_full(r).startswith(fp):
                print(f"  fp {fp} = sha256(canonical)[:{len(fp)}] -> N={len(fp)} hex")
                return len(fp)
    return None

def rho(ts, N, x0=1):
    """Floyd-botsing op f(x)=truncate(sha256(record(col-x)))[:N], O(1) geheugen."""
    prefix = b'{"amount":10,"currency":"EUR","from_account":"SIM-AAA","reference":"col-'
    suffix = ('","timestamp":"%s","to_account":"SIM-BBB"}' % ts).encode()
    base = hashlib.sha256(); base.update(prefix)
    def f(x):
        h = base.copy(); h.update(str(x).encode()); h.update(suffix)
        return int(h.hexdigest()[:N], 16)
    t = f(x0); h = f(f(x0))
    while t != h: t = f(t); h = f(f(h))
    t = x0; pt = ph = None
    while t != h:
        pt, ph = t, h; t = f(t); h = f(h)
    return f"col-{pt}", f"col-{ph}"   # twee refs met dezelfde fp[:N]

if __name__ == "__main__":
    s0, banner, offset = connect_banner(); s0.close()
    print(banner.strip()[:400], "\n")
    N = measure_N(offset)
    if not N:
        raise SystemExit("Kon N niet bepalen; bekijk het meet-antwoord.")
    ts = fresh_ts(offset, back=3)
    print(f"\nZoek botsing op {N} hex ({N*4} bits), timestamp {ts} ...")
    t0 = time.time()
    ra, rb = rho(ts, N)
    r1, r2 = record(ra, ts), record(rb, ts)
    assert ra != rb and sha_full(r1)[:N] == sha_full(r2)[:N]
    print(f"BOTSING in {time.time()-t0:.1f}s: {ra} en {rb} -> fp {sha_full(r1)[:N]}")
    s, _, _ = connect_banner()
    print("\nSERVER-ANTWOORD:\n" + send_two(s, r1, r2)); s.close()