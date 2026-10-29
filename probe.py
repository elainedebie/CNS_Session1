# probe.py -- stuurt twee geldige records en toont wat de server terugstuurt
import socket, json, time

def canonicalize(p):
    return json.dumps(p, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()

def rec(ref):
    return {"reference": ref, "from_account": "SIM-AAA", "to_account": "SIM-BBB",
            "amount": 10, "currency": "EUR", "timestamp": "2026-10-28T12:00:00Z"}

r1 = rec("probe-1"); r2 = rec("probe-2")
line1 = json.dumps(r1); line2 = json.dumps(r2)
print("VERSTUURD record1 canonical:", canonicalize(r1).decode())

s = socket.create_connection(("cns-test.idlab.uantwerpen.be", 50003), timeout=10)
s.settimeout(6)
try:
    time.sleep(0.3)
    print("BANNER:", s.recv(4096).decode(errors="replace"))
except Exception as e:
    print("geen banner:", e)

s.sendall((line1 + "\n" + line2 + "\n").encode())
data = b""
try:
    while True:
        c = s.recv(4096)
        if not c: break
        data += c
except Exception:
    pass
print("ANTWOORD:\n" + data.decode(errors="replace"))
s.close()