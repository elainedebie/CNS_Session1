"""
hash_chain_predict.py - voorspel de volgende code(s) van een hash-ketting.

PATROON (Space Race): de server toont een CURRENT CODE en vraagt de volgende.
Elke code is de hash van de vorige:  next = HASH(bytes van de huidige code).
Wie één code ziet, kan dus alle volgende berekenen -> geen geheim = kraakbaar.

GEBRUIK
  python3 hash_chain_predict.py <huidige_code_hex> [stappen_vooruit]
      bv. python3 hash_chain_predict.py 0ce2ec65...  4
  python3 hash_chain_predict.py           # vraagt alles interactief

EERST HET PATROON CHECKEN (doe dit 1x per opgave):
  Verbind een paar keer opnieuw, verzamel enkele opeenvolgende codes, en plak ze
  bij 'verify'. Het script zegt dan welke hash + welke invoervorm de ketting volgt.
      python3 hash_chain_predict.py verify code1 code2 code3 ...
"""
import sys, hashlib

# hash-functies om te proberen (voeg toe wat de cursus noemt)
HASHES = {
    "sha256": lambda b: hashlib.sha256(b).hexdigest(),
    "sha1":   lambda b: hashlib.sha1(b).hexdigest(),
    "md5":    lambda b: hashlib.md5(b).hexdigest(),
    "sha512": lambda b: hashlib.sha512(b).hexdigest(),
}
# invoervormen: hoe gaat de huidige code de hash in?
def as_bytes(code):  return bytes.fromhex(code)      # bytes van de hex
def as_ascii(code):  return code.encode()            # de hex-tekst zelf
INPUTS = {"bytes": as_bytes, "ascii": as_ascii}


def step(code, hname, iname):
    return HASHES[hname](INPUTS[iname](code))


def verify(codes):
    """Zoek welke (hash, invoervorm) de gegeven opeenvolgende codes verbindt."""
    for hname in HASHES:
        for iname in INPUTS:
            try:
                ok = all(step(codes[i], hname, iname) == codes[i+1]
                         for i in range(len(codes)-1))
            except Exception:
                ok = False
            if ok:
                print(f"GEVONDEN: next = {hname}( {iname} van huidige )")
                return hname, iname
    print("Geen match. Misschien geen pure ketting (teller/tijd/PRNG achter de hash?).")
    return None, None


def predict(code, n, hname="sha256", iname="bytes"):
    out = []
    for _ in range(n):
        code = step(code, hname, iname)
        out.append(code)
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
        for i, c in enumerate(predict(code, n), 1):
            print(f"{i}: {c}")
        print("\n>>> antwoord (stap", n, "):", predict(code, n)[-1])