"""
secure_bank_solve.py - stream-cipher malleability-exploit (SecureBank / Salsa20).

Zwakte: stream cipher (C = P XOR keystream) + geen integriteit (geen MAC).
Ken je de plaintext, dan forge je elke transactie van dezelfde lengte - zonder
sleutel - door de ciphertext te XOR-en. De nonce stuur je gewoon mee terug.

Volledige aanpak, in één run:
 1) verbind, lees de pending blob (nonce + ciphertext)
 2) gebruik de BEKENDE plaintext (achterhaald door de blob 1x ongewijzigd in te
    sturen -> "Transfer of 10 EUR to bob")
 3) recover keystream = ct XOR bekende_pt
 4) forge: nieuwe_ct = keystream XOR gewenste_pt
 5) stuur nonce + nieuwe_ct in -> flag
"""
import socket, re, json

HOST, PORT = "cns-test.idlab.uantwerpen.be", 50001
NONCE_LEN = 8   # Salsa20

# --- VUL IN: wat je weet en wat je wil (zelfde lengte!) ---
KNOWN   = b'{"from":"alice","to":"bob","amount":"000010"}'   # amount 10, 6-teken-veld
DESIRED = b'{"from":"alice","to":"bob","amount":"999999"}'   # betaal bob een berg geld
assert len(KNOWN) == len(DESIRED)

def recv_until(s, marker, limit=8192):
    data = b""
    s.settimeout(6)
    try:
        while marker not in data and len(data) < limit:
            c = s.recv(4096)
            if not c: break
            data += c
    except Exception:
        pass
    return data.decode(errors="replace")

s = socket.create_connection((HOST, PORT), timeout=10)
banner = recv_until(s, b"Submit the transaction")
print(banner)

m = re.search(r"\b([0-9a-f]{40,})\b", banner)      # de pending blob (hex)
blob = bytes.fromhex(m.group(1))
nonce, ct = blob[:NONCE_LEN], blob[NONCE_LEN:]
print("nonce:", nonce.hex(), "| plaintext-lengte:", len(ct))

keystream = bytes(c ^ k for c, k in zip(ct, KNOWN))           # stap 3
forged_ct = bytes(ks ^ d for ks, d in zip(keystream, DESIRED))  # stap 4
forged = (nonce + forged_ct).hex()
print("forged blob:", forged)

s.sendall((forged + "\n").encode())                           # stap 5
print(recv_until(s, b"}", limit=16384))                       # flag (cns{...})
s.close()