"""
key_guess.py — raad een zwakke/voorspelbare sleutel voor DES, 3DES of AES.

Examenpatroon: de sleutel is geen willekeur maar een hint uit de opgave
(een namespace, naam, woord...) aangevuld tot de juiste lengte.
Dit script bouwt een handvol logische sleutels uit die hint en probeert
ze in ECB en CBC. Komt er 'cns{' uit, dan heb je de flag.

GEBRUIK
  python3 key_guess.py IOTDEV 74eb40cf03b8...        # hint + ciphertext(hex)
  python3 key_guess.py IOTDEV 74eb40cf... 0011..ff   # idem + IV uit de opgave
  python3 key_guess.py                               # vraagt het zelf (IV mag leeg)

Werkt niks? Lees de TODO's onderaan: daar pas je 'm aan voor varianten.
"""
import sys
from Crypto.Cipher import DES, DES3, AES

# ---- input ophalen (argument of gewoon vragen) ----
if len(sys.argv) >= 3:
    hint, ct_hex = sys.argv[1], sys.argv[2]
    iv_hex = sys.argv[3] if len(sys.argv) >= 4 else ""
else:
    hint = input("Hint (bv. IOTDEV): ").strip()
    ct_hex = input("Ciphertext (hex): ").strip()
    iv_hex = input("IV in hex (leeg laten als er geen is): ").strip()
hint = hint.encode()
ct = bytes.fromhex("".join(ct_hex.split()))
iv = bytes.fromhex("".join(iv_hex.split())) if iv_hex else None

FLAG = b"cns{"            # waar we naar zoeken (pas aan als jouw flag anders begint)


def leesbaar(b):
    return sum(32 <= c < 127 for c in b) / len(b) > 0.9


def kandidaten(h, lengte):
    """Maak sleutels van exact 'lengte' bytes uit de hint h."""
    ruw = []
    for pad in [b"\x00", b" ", b"0", b"1", b"X", b"\xff", h[-1:]]:
        ruw.append(h + pad * lengte)        # IOTDEV00000...
    ruw.append(h * lengte)                   # IOTDEVIOTDEV...
    ruw.append(h.lower() * lengte)
    for i in range(1000):                    # IOTDEV0 ... IOTDEV999
        ruw.append(h + str(i).encode())
    # alles op de juiste lengte knippen, duplicaten eruit
    uniek, gezien = [], set()
    for k in ruw:
        k = k[:lengte]
        if len(k) == lengte and k not in gezien:
            gezien.add(k)
            uniek.append(k)
    return uniek


# (naam, module, toegelaten sleutellengtes, blokgrootte)
ALGS = [
    ("DES",  DES,  [8],          8),
    ("3DES", DES3, [16, 24],     8),
    ("AES",  AES,  [16, 24, 32], 16),
]

for naam, mod, lengtes, blok in ALGS:
    for L in lengtes:
        for k in kandidaten(hint, L):
            if len(ct) % blok:              # ciphertext past niet bij dit blok
                continue
            # IV uit de opgave meenemen als die er is; anders CBC met nul-IV proberen
            cbc_iv = iv if iv is not None else b"\x00" * blok
            for modus, maak in [
                ("ECB", lambda: mod.new(k, mod.MODE_ECB)),
                (f"CBC iv={cbc_iv.hex()}", lambda: mod.new(k, mod.MODE_CBC, cbc_iv)),
            ]:
                try:
                    pt = maak().decrypt(ct)
                except ValueError:
                    continue
                if FLAG in pt or leesbaar(pt):
                    print(f"{naam:4} {modus:9} key={k!r:22} -> {pt!r}")

# ---------------------------------------------------------------------------
# TODO voor varianten op het examen:
#   * Andere flag-prefix?        -> pas FLAG hierboven aan.
#   * IV staat in de opgave?     -> geef 'm als 3e argument mee, of vul 'm in bij de vraag.
#   * Sleutel = woord + jaartal? -> zit al in kandidaten() via de 0..999-lus.
#   * Heel andere sleutelvorm?   -> voeg 'm toe in kandidaten() (ruw.append(...)).
# ---------------------------------------------------------------------------