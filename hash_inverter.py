"""
invert_hash_blocks.py - omkeerbare "hash"-opgaven oplossen met kant-en-klare blokjes.

IDEE: een ronde = een lijstje stappen. Elk veelvoorkomend stapje staat hieronder
als een paar (forward, inverse). Je bouwt de ronde na met deze blokjes, en de
inverter draait alles automatisch achterstevoren + verifieert.

WERKWIJZE op het examen:
  1. Lees de ronde in de opgave.
  2. Zet 'm hieronder in ROUND samen uit de blokjes (zelfde volgorde als de opgave).
  3. Vul ROUNDS en de hash in. Run. Check dat 'klopt: True'.

Herken je een stap die hier niet staat? Schrijf 'm zelf als (forward, inverse)
volgens hetzelfde patroon. De regel: inverse doet exact de stap ongedaan.
"""

MASK = 0xff  # werk je met grotere woorden? zet op 0xffff / 0xffffffff


# ======================================================================
# BLOKJES:  elk is (forward, inverse).  Beide krijgen (state: bytearray, rnd: int).
# Ze passen state ter plaatse aan. 'rnd' is het rondenummer (voor ronde-afhankelijke
# constanten). key()-blokjes nemen een parameter en geven zo'n paar terug.
# ======================================================================

def rol(x, n, bits=8):
    n %= bits
    return ((x << n) | (x >> (bits - n))) & ((1 << bits) - 1)

def ror(x, n, bits=8):
    return rol(x, (bits - (n % bits)) % bits, bits)


# --- XOR met een constante die van (rnd, i) afhangt --------------------
def xor_const(const_fn):
    """const_fn(rnd, i) -> byte.  Bv. lambda r,i:(r*41+i*17)&0xff"""
    def fwd(s, rnd):
        for i in range(len(s)): s[i] ^= const_fn(rnd, i) & MASK
    def inv(s, rnd):
        for i in range(len(s)): s[i] ^= const_fn(rnd, i) & MASK   # XOR is eigen inverse
    return (fwd, inv)

# --- optellen (mod 2^n) met een constante ------------------------------
def add_const(const_fn):
    def fwd(s, rnd):
        for i in range(len(s)): s[i] = (s[i] + const_fn(rnd, i)) & MASK
    def inv(s, rnd):
        for i in range(len(s)): s[i] = (s[i] - const_fn(rnd, i)) & MASK
    return (fwd, inv)

# --- bits roteren met een hoeveelheid die van (rnd, i) afhangt --- state[i] = rol(state[i], (i * 2 + 1) & 7)----------
def rotate(amount_fn):
    """amount_fn(rnd, i) -> aantal bits links.  Bv. lambda r,i:(r+i)&7"""
    def fwd(s, rnd):
        for i in range(len(s)): s[i] = rol(s[i], amount_fn(rnd, i))
    def inv(s, rnd):
        for i in range(len(s)): s[i] = ror(s[i], amount_fn(rnd, i))
    return (fwd, inv)

# --- XOR-chain vooruit:  state[i] ^= state[i-1]  (links -> rechts) ------
def xor_chain_fwd():
    def fwd(s, rnd):
        for i in range(1, len(s)): s[i] ^= s[i-1]
    def inv(s, rnd):
        for i in range(len(s)-1, 0, -1): s[i] ^= s[i-1]   # rechts -> links!
    return (fwd, inv)

# --- XOR-chain achteruit:  state[i] ^= state[i+1]  (rechts -> links) ----
def xor_chain_bwd():
    def fwd(s, rnd):
        for i in range(len(s)-2, -1, -1): s[i] ^= s[i+1]
    def inv(s, rnd):
        for i in range(len(s)-1): s[i] ^= s[i+1]
    return (fwd, inv)

# --- hele lijst k plaatsen naar links roteren --------------------------
def roll_list(k=1):
    def fwd(s, rnd):
        kk = k % len(s); s[:] = s[kk:] + s[:kk]
    def inv(s, rnd):
        kk = k % len(s); s[:] = s[-kk:] + s[:-kk] if kk else s
    return (fwd, inv)

# --- bytes paarsgewijs/omgekeerd/geswapt --- state = state[::-1] -------------------------------
def reverse_list():
    def fwd(s, rnd): s.reverse()
    def inv(s, rnd): s.reverse()
    return (fwd, inv)

def swap_pairs():
    """verwissel (0,1),(2,3),...  eigen inverse"""
    def op(s, rnd):
        for i in range(0, len(s)-1, 2): s[i], s[i+1] = s[i+1], s[i]
    return (op, op)


# ======================================================================
# STEL HIER DE RONDE SAMEN  (zelfde volgorde als in de opgave)
# Voorbeeld = de opgeloste "Better Hash".
# ======================================================================
ROUNDS = 8
ROUND = [
    xor_const(lambda r, i: (r*7 + i*3) & 0xff),   # state[i] = (state[i] + (rnd * 7 + i * 3)) & 0xff
    rotate(lambda r, i: (r + 2*i + 1) & 7),               # state[i] = rol(state[i], (i * 2 + 1) & 7)
    xor_chain_bwd(),                                # state[i] ^= state[i + 1]
    reverse_list(),                                   # state = state[::-1]
]
# ======================================================================


def forward(data):
    s = bytearray(data)
    for rnd in range(ROUNDS):
        for fwd, _ in ROUND:
            fwd(s, rnd)
    return s.hex()

def invert(hash_hex):
    s = bytearray.fromhex(hash_hex)
    for rnd in reversed(range(ROUNDS)):             # rondes achterstevoren
        for fwd, inv in reversed(ROUND):            # stappen achterstevoren
            inv(s, rnd)
    return bytes(s)


if __name__ == "__main__":
    import sys
    H = sys.argv[1] if len(sys.argv) > 1 else input("Hash (hex): ").strip()
    cand = invert(H)
    print("kandidaat:", cand)
    print("klopt    :", forward(cand) == H)