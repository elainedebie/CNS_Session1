"""
measure_N.py - meet de afkaplengte N en bevestig de hash.
Stuurt twee geldige records, vergelijkt de teruggegeven fingerprint met de
lokaal berekende SHA-256 (en MD5/SHA1) om N en de hashsoort te bepalen.
"""
import socket, json, re, time, hashlib
from datetime import datetime, timezone, timedelta

HOST, PORT = "cns-test.idlab.uantwerpen.be", 50003

def canon(p): return json.dumps(p, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
def rec(ref, ts): return {"reference": ref, "from_account": "SIM-AAA", "to_account": "SIM-BBB",
                          "amount": 10, "currency": "EUR", "timestamp": ts}

s = socket.create_connection((HOST, PORT), timeout=10); s.settimeout(6)
time.sleep(0.3); banner = s.recv(8192).decode(errors="replace")
m = re.search(r"Current time:\s*([0-9T:.\+\-]+)", banner)
srv = datetime.fromisoformat(m.group(1)) if m else datetime.now(timezone.utc)
ts = (srv - timedelta(seconds=3)).isoformat()

r1, r2 = rec("meet-1", ts), rec("meet-2", ts)
s.sendall((json.dumps(r1) + "\n" + json.dumps(r2) + "\n").encode())
time.sleep(0.5); resp = s.recv(8192).decode(errors="replace"); s.close()
print("ANTWOORD:\n", resp.strip(), "\n")

hashes = {"sha256": hashlib.sha256, "md5": hashlib.md5, "sha1": hashlib.sha1, "sha512": hashlib.sha512}
for fp in re.findall(r"\b[0-9a-f]{4,127}\b", resp):
    for r in (r1, r2):
        for naam, hfn in hashes.items():
            full = hfn(canon(r)).hexdigest()
            if full.startswith(fp) and len(fp) < len(full):
                print(f">>> fingerprint {fp}  =  {naam}(canonical)[:{len(fp)}]   =>   N = {len(fp)} hex")