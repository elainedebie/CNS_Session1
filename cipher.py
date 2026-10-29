"""
Encryption module.

This module implements a custom stream cipher.
"""

# LCG parameters
A = 1103515245
C = 12345
M = 2**31


def next_state(state):
    """Generate the next PRNG state."""
    return (A * state + C) % M
# M is hier 2**31 dus 31 bits breed

def generate_keystream(seed, length):
    """Generate a pseudorandom keystream."""
    state = seed
    keystream = bytearray()
    # Staat r24 na r25 dan POST_UPDATE = False
    for _ in range(length):
        state = next_state(state)               # A
        keystream.append((state >> 16) & 0xff)  # B
    # Shift = 16 en width = 0xff = 2^8 dus 8
    return bytes(keystream)

# 0x1     → 1 bit
# 0x3     → 2 bits
# 0xf     → 4 bits (nibble)
# 0xff    → 8 bits (byte)
# 0xffff  → 16 bits (word)
# 0xffffffff → 32 bits
# State & = shift=0
# state >> N & A
# N = shift  A = 2^8 dus 8

def encrypt(plaintext, seed):
    """Encrypt plaintext using XOR."""
    keystream = generate_keystream(seed, len(plaintext))
    return bytes(
        p ^ k for p, k in zip(plaintext, keystream)
    )


def decrypt(ciphertext, seed):
    """Decrypt ciphertext using XOR."""
    return encrypt(ciphertext, seed)
