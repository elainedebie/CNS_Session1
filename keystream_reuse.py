"""
keystream_reuse.py — solver voor HERGEBRUIKTE keystream (vraagt alles zelf).

Werkt voor elke cipher die neerkomt op  C = P XOR keystream  met dezelfde
keystream twee keer gebruikt: AES-CTR met herhaalde nonce, RC4/ChaCha met
herhaalde key+nonce, een zelfgemaakte LCG-stream... De generator maakt niet
uit — je valt de XOR aan.

GEBRUIK
  python3 keystream_reuse.py          # en beantwoord de vragen (plak de teksten)

WAT VUL JE WAAR IN?  (zie ook "HERKENNEN" onderaan)
  - Bekende plaintext : de tekst waarvan je WEET wat er staat
                        (publiek bericht, status, known_message.txt). Ken je
                        die niet? Laat leeg -> het script gaat naar crib-modus.
  - Ciphertext van die bekende plaintext : de hex die bij díe tekst hoort.
  - Doel-ciphertext   : de hex die je wil kraken (bevat de flag).
"""


def vraag_hex(label):
    s = input(label).strip()
    return bytes.fromhex("".join(s.split()))


def xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def printbaar(b):
    return all(32 <= c < 127 or c in (9, 10, 13) for c in b)


print("=== keystream-reuse solver ===")
print("Heb je een BEKENDE plaintext? Plak 'm. Zo niet: druk gewoon Enter.\n")
pt = input("Bekende plaintext (tekst): ").encode()

if pt:
    # ---- scenario A: known plaintext ----
    ck = vraag_hex("Ciphertext van die bekende plaintext (hex): ")
    cf = vraag_hex("Doel-ciphertext met de flag (hex): ")

    ks = xor(pt, ck)                       # keystream
    bruikbaar = min(len(ks), len(cf))
    flag = xor(cf[:bruikbaar], ks[:bruikbaar])

    print("\nkeystream beschikbaar :", len(ks), "bytes")
    print("doel-ciphertext       :", len(cf), "bytes")
    print("ONTSLEUTELD           :", flag)
    if len(cf) > len(ks):
        print(f"\n!! {len(cf)-len(ks)} bytes te weinig keystream: bekende plaintext is te kort.")
        print("   -> zoek een langere bekende plaintext, of val de generator zelf aan.")
else:
    # ---- scenario B: geen plaintext, crib dragging ----
    print("\nGeen plaintext -> crib-modus. Ik schuif een gok-woord over C1 XOR C2.")
    c1 = vraag_hex("Ciphertext 1 (hex): ")
    c2 = vraag_hex("Ciphertext 2 (hex): ")
    crib = (input("Vermoed woord/crib [cns{]: ").strip() or "cns{").encode()

    x = xor(c1, c2)                        # = P1 XOR P2
    print(f"\nP1 XOR P2 is {len(x)} bytes. Treffers voor crib {crib!r}:\n")
    gevonden = False
    for i in range(len(x) - len(crib) + 1):
        r = xor(x[i:i + len(crib)], crib)  # = het andere bericht op positie i
        if printbaar(r):
            print(f"  pos {i:3}: {r!r}")
            gevonden = True
    if not gevonden:
        print("  (niets leesbaars — probeer een andere crib, bv. ' the ', 'flag', 'cns{')")
    print("\nLeesbaar fragment = stuk van het ANDERE bericht. Zo puzzel je beide uit.")

# ===========================================================================
# HERKENNEN — is dit de juiste aanval, en wat vul ik waar in?
#
#   Kies deze aanval als:
#     * de opgave "nonce", "IV", "keystream", "stream cipher" of "CTR" noemt;
#     * je TWEE ciphertexts krijgt met de hint "zelfde sleutel/nonce",
#       "same configuration", "reused nonce";
#     * (vaak) er een bekend/publiek bericht bijzit.
#
#   Wat is wat?
#     bekende plaintext        = de tekst die je ZEKER kent (known_message.txt,
#                                "STATUS: SERVER ONLINE", een vaste header...).
#     ciphertext van die tekst = de .hex die bij dat bekende bericht hoort.
#     doel-ciphertext          = de .hex die de flag bevat (meestal "flag" in de naam).
#
#   Twijfel je welke ciphertext bij de bekende tekst hoort? Ze zijn ongeveer
#   even lang als die tekst. De flag-ciphertext is vaak korter.
#
#   Snelle bevestiging: C1 XOR C2 na XOR met een gok-woord (deels) leesbaar? Ja = reuse.
#
#   Flag langer dan je keystream? Je ziet maar een deel. Zoek een langere bekende
#   plaintext, of (bij een zelfgemaakte PRNG) val die generator zelf aan.
# ===========================================================================