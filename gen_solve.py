#!/usr/bin/env python3
"""
Generieke LCG stream-cipher recovery.

Pas de PARAMETERS aan op basis van cipher.py.
"""

# ===== PARAMETERS =====
A        = 1664525
C        = 1013904223
M        = 2**32
SHIFT    = 16          # output = (state >> SHIFT) & MASK
WIDTH    = 8           # aantal bits per output-stap
POST_UPDATE = False     # True: state = next(state); out = extract(state)
                       # False: out = extract(state); state = next(state)
MAX_BRUTE_BITS = 26    # veiligheidsgrens; boven 26 bits → z3 of C
# ======================

MASK = (1 << WIDTH) - 1



def recover_keystream(known_ks, verbose=False):
    """
    known_ks: lijst integers, elk in [0, 2^WIDTH).
    Retourneert (state_at_first_output, MOD_HIGH).

    MOD_HIGH = 2^(SHIFT+WIDTH) is genoeg om alle toekomstige
    outputs te voorspellen (hogere bits doen niet mee).
    """
    MOD_HIGH = 1 << (SHIFT + WIDTH)
    A_ = A % MOD_HIGH
    C_ = C % MOD_HIGH

    if SHIFT > MAX_BRUTE_BITS:
        raise ValueError(
            f"SHIFT={SHIFT} te groot voor brute force. Gebruik z3."
        )

    first = known_ks[0]
    found = 0

    for low in range(1 << SHIFT):
        st = (first << SHIFT) | low
        ok = True
        for k in known_ks:
            if ((st >> SHIFT) & MASK) != k:
                ok = False
                break
            st = (A_ * st + C_) % MOD_HIGH
        if ok:
            found += 1
            if verbose:
                print(f"[+] kandidaat: 0x{(first << SHIFT) | low:06x}")
            if found > 1:
                print("[!] meerdere kandidaten — meer known bytes nodig")
            return ((first << SHIFT) | low), MOD_HIGH

    raise ValueError("Geen consistente state gevonden")


def generate_keystream(state, length, MOD_HIGH):
    A_ = A % MOD_HIGH
    C_ = C % MOD_HIGH
    out = []
    st = state
    for _ in range(length):
        out.append((st >> SHIFT) & MASK)
        st = (A_ * st + C_) % MOD_HIGH
    return out


def solve(public_ct_hex, known_pt, secret_ct_hex):
    pub_ct = bytes.fromhex(public_ct_hex)
    sec_ct = bytes.fromhex(secret_ct_hex)

    # Stap 1: keystream recoveren
    known_ks = [c ^ p for c, p in zip(pub_ct, known_pt)]

    # Stap 2: LCG-state recoveren
    state, MOD_HIGH = recover_keystream(known_ks, verbose=True)

    # Stap 3: keystream verlengen en secret decrypten
    ks = generate_keystream(state, len(sec_ct), MOD_HIGH)
    pt = bytes(c ^ k for c, k in zip(sec_ct, ks))
    return pt


if __name__ == "__main__":
    flag = solve(
        "63483b1647e269d4dc",
        b"STATUS OK",
        "5372093974dd28fca63607d0bc",
    )
    print(flag.decode(errors="replace"))