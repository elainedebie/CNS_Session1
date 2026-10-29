#!/usr/bin/env python3
"""
Solver voor de stream-cipher reuse opgave.

Werking:
1. Herstel de keystream met known plaintext: K = C_public XOR P_public.
2. Herstel de LCG-state modulo 2^24 met brute-force over de onbekende 16 bits.
3. Genereer de keystream verder en decrypt secret.txt.
"""

A = 1103515245
C = 12345
MASK24 = (1 << 24) - 1

# Uit public.txt
public_ct = bytes.fromhex(
    "22135cc0b9daa9e717f98a998e6ee5e92655e1a88f"
)
known_pt = b"STATUS: SERVER ONLINE"

# Uit secret.txt
secret_ct = bytes.fromhex(
    "12296eef9eece6b42dd2bf90aa63b6d21a7cc98b95c78b4b01d833d628a941b82fb65176b4ed3c3f64"
)


def recover_known_keystream(ciphertext, plaintext):
    """K = C XOR P voor de bekende plaintext."""
    return bytes(c ^ p for c, p in zip(ciphertext, plaintext))


def next_state24(state):
    """LCG-state modulo 2^24."""
    return (A * state + C) & MASK24


def recover_state24(keystream):
    """
    Herstel de LCG-state modulo 2^24.

    De keystream-byte is (state >> 16) & 0xff.
    De bovenste 8 bits van de 24-bit state zijn dus bekend.
    De onderste 16 bits brute-forcen we.
    """
    first_byte = keystream[0]

    for low16 in range(1 << 16):
        state = (first_byte << 16) | low16
        st = state
        ok = True

        for k in keystream:
            if ((st >> 16) & 0xff) != k:
                ok = False
                break
            st = next_state24(st)

        if ok:
            return state

    raise ValueError("Geen geldige LCG-state gevonden")


def generate_keystream_from_state(state, length):
    """
    Genereer keystream vanaf een state waarvan de eerste output
    al de eerste keystream-byte is.
    """
    out = bytearray()
    st = state

    for _ in range(length):
        out.append((st >> 16) & 0xff)
        st = next_state24(st)

    return bytes(out)


def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def main():
    known_ks = recover_known_keystream(public_ct, known_pt)

    print("[+] Bekende keystream:")
    print(known_ks.hex())

    state = recover_state24(known_ks)
    print(f"[+] Herstelde state mod 2^24: 0x{state:06x}")

    secret_ks = generate_keystream_from_state(state, len(secret_ct))

    flag = xor_bytes(secret_ct, secret_ks)

    print("[+] Flag:")
    print(flag.decode(errors="replace"))


if __name__ == "__main__":
    main()