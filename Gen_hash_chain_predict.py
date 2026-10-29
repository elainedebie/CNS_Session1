"""
hash_chain_predict.py - voorspel de volgende code(s) van een hash-gebaseerde reeks.

PATROON (Space Race): de server toont een CURRENT CODE en vraagt de volgende.
De code wordt voorspelbaar gegenereerd. Dit script herkent de 3 gangbare vormen
en berekent de volgende code(s). Geen geheim in de generator = kraakbaar.

HERKENDE VORMEN
  1) KETTING   : next   = HASH(huidige)          (huidige als bytes of als hex-tekst)
  2) TELLER    : code_k = HASH(teller + k)        (oplopende teller, gehasht)
  3) KETTING+k : next   = HASH(huidige + teller)  (vorige code plus een teller erbij)

GEBRUIK
  python3 hash_chain_predict.py verify code1 code2 code3 ...   # 1x: vind het patroon
  python3 hash_chain_predict.py <huidige_code_hex> [stappen]   # voorspel
  python3 hash_chain_predict.py                                # interactief

Tip: verzamel enkele opeenvolgende codes (verbind een paar keer opnieuw) en draai
eerst 'verify'. Dat zegt welke vorm + welke hash het is; daarna voorspel je.
"""
import sys, hashlib

HASHES = {
    "sha256": hashlib.sha256, "sha1": hashlib.sha1,
    "md5": hashlib.md5, "sha512": hashlib.sha512,
}
def H(hname, b): return HASHES[hname](b).hexdigest()

# hoe gaat de HUIDIGE code de hash in (vorm 1 en 3)
def as_bytes(code): return bytes.fromhex(code)
def as_ascii(code): return code.encode()
INPUTS = {"bytes": as_bytes, "ascii": as_ascii}

# hoe gaat een TELLER de hash in (vorm 2 en 3)
COUNTER_ENC = {
    "str":  lambda n: str(n).encode(),
    "be4":  lambda n: n.to_bytes(4, "big"),
    "be8":  lambda n: n.to_bytes(8, "big"),
    "le4":  lambda n: n.to_bytes(4, "little"),
}
MAXN = 2_000_000   # hoever we een teller brute-forcen


# ---------- vorm 1: pure ketting ----------
def chain_next(code, hname, iname):
    return H(hname, INPUTS[iname](code))

def find_chain(codes):
    for hn in HASHES:
        for inm in INPUTS:
            try:
                if all(chain_next(codes[i], hn, inm) == codes[i+1]
                       for i in range(len(codes)-1)):
                    return (hn, inm)
            except Exception:
                pass
    return None


# ---------- vorm 3: ketting + teller ----------
def find_chain_counter(codes):
    for hn in HASHES:
        for inm in INPUTS:
            for cenc, cfn in COUNTER_ENC.items():
                # zoek start-teller zodat alle overgangen kloppen
                for start in range(0, 4096):
                    try:
                        ok = all(H(hn, INPUTS[inm](codes[i]) + cfn(start+i)) == codes[i+1]
                                 for i in range(len(codes)-1))
                    except Exception:
                        ok = False
                    if ok:
                        return (hn, inm, cenc, start + (len(codes)-1))
    return None


# ---------- vorm 2: hash van een oplopende teller ----------
def find_counter(codes):
    for hn in HASHES:
        for cenc, cfn in COUNTER_ENC.items():
            # vind n zodat HASH(n)==codes[0], dan check de rest
            for n in range(0, MAXN):
                if H(hn, cfn(n)) == codes[0]:
                    if all(H(hn, cfn(n+i)) == codes[i] for i in range(len(codes))):
                        return (hn, cenc, n + len(codes))  # volgende teller
                    break
    return None


def verify(codes):
    r = find_chain(codes)
    if r:
        print(f"VORM 1 (ketting): next = {r[0]}( {r[1]} van huidige )")
        return ("chain", *r)
    r = find_chain_counter(codes)
    if r:
        print(f"VORM 3 (ketting+teller): next = {r[0]}( {r[1]} van huidige + teller ), "
              f"tellervorm {r[2]}, volgende teller = {r[3]}")
        return ("chain_counter", *r)
    r = find_counter(codes)
    if r:
        print(f"VORM 2 (teller): code = {r[0]}( teller[{r[1]}] ), volgende teller = {r[2]}")
        return ("counter", *r)
    print("Geen match. Mogelijk een PRNG achter de hash (zie Replanting-aanpak) "
          "of een geheim (HMAC) -> niet voorspelbaar uit codes alleen.")
    return None


def predict(info, last_code, steps):
    """Geef 'steps' volgende codes op basis van wat verify vond."""
    kind = info[0]
    out = []
    if kind == "chain":
        _, hn, inm = info
        c = last_code
        for _ in range(steps):
            c = chain_next(c, hn, inm); out.append(c)
    elif kind == "chain_counter":
        _, hn, inm, cenc, nextn = info
        c = last_code; n = nextn
        for _ in range(steps):
            c = H(hn, INPUTS[inm](c) + COUNTER_ENC[cenc](n)); n += 1; out.append(c)
    elif kind == "counter":
        _, hn, cenc, nextn = info
        n = nextn
        for _ in range(steps):
            out.append(H(hn, COUNTER_ENC[cenc](n))); n += 1
    return out


if __name__ == "__main__":
    a = sys.argv[1:]
    if a and a[0] == "verify":
        verify([c.strip() for c in a[1:]])
    else:
        if a:
            code = a[0]; n = int(a[1]) if len(a) > 1 else 1
        else:
            code = input("Huidige code (hex): ").strip()
            n = int(input("Hoeveel stappen vooruit [1]: ") or "1")
        # zonder verify gaan we uit van de standaard-ketting sha256(bytes)
        info = ("chain", "sha256", "bytes")
        res = predict(info, code, n)
        for i, c in enumerate(res, 1):
            print(f"{i}: {c}")
        print("\n>>> antwoord (stap", n, "):", res[-1])
        print("(verondersteld: sha256-ketting. Twijfel? Draai eerst 'verify' met meerdere codes.)")