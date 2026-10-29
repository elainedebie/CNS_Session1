# Spiekkaart: codepatroon → blokje

Zoek in de ronde elke regel op en vervang 'm door het blokje rechts.
Zet de blokjes in `ROUND` in **dezelfde volgorde als de code** (boven → beneden).

---

## 1. Werkt de regel op ÉÉN byte (`state[i]`) of op de HELE lijst (`state`)?

Dat is de eerste splitsing. Regels met `state[i] = ...` of `state[i] ^= ...`
zitten binnen een `for i`-lus en bewerken elke byte. Regels met `state = ...`
bewerken de hele lijst in één keer.

---

## 2. Per-byte regels (`state[i] ...`)

| Code in de opgave | Blokje | Let op |
|---|---|---|
| `state[i] ^= <formule met rnd,i>` | `xor_const(lambda r,i: <formule>)` | `^=` met een vaste formule (geen buur) |
| `state[i] = (state[i] + <formule>) & 0xff` | `add_const(lambda r,i: <formule>)` | `+` → optellen |
| `state[i] = (state[i] - <formule>) & 0xff` | `add_const(lambda r,i: -(<formule>))` | `-` → optellen met minteken |
| `state[i] = rol(state[i], <formule>)` | `rotate(lambda r,i: <formule>)` | rotatie links |
| `state[i] = ror(state[i], <formule>)` | `rotate(lambda r,i: -(<formule>))` | rotatie rechts = negatief |
| `state[i] ^= state[i-1]` | `xor_chain_fwd()` | buur **links**, lus loopt 1→eind |
| `state[i] ^= state[i+1]` | `xor_chain_bwd()` | buur **rechts**, lus loopt eind→0 |

**De lambda is letterlijk kopiëren.** Staat er `(rnd*7 + i*3)`, dan schrijf je
`lambda r,i: r*7 + i*3`. `rnd` wordt `r`, `i` blijft `i`. De `& 0xff` mag je
weglaten in de lambda (het blokje maskeert zelf), maar fout doet 'ie niet.

---

## 3. Hele-lijst regels (`state = ...`)

| Code in de opgave | Blokje |
|---|---|
| `state = state[1:] + state[:1]` | `roll_list(1)` (1 naar links) |
| `state = state[k:] + state[:k]` | `roll_list(k)` |
| `state = state[-1:] + state[:-1]` | `roll_list(-1)` (1 naar rechts) |
| `state = state[::-1]` | `reverse_list()` |
| `state.reverse()` | `reverse_list()` |
| byte-paren `(0,1),(2,3)` wisselen | `swap_pairs()` |

---

## 4. Rondes tellen → `ROUNDS`

De **buitenste** lus telt de rondes:
`for rnd in range(6):` → `ROUNDS = 6`.

De `for i`-lussen binnenin hoef je NIET over te nemen — die zitten al in de
per-byte blokjes.

---

## 5. Herkennings-trucjes

- **`^=` met een getal/formule** → `xor_const`. **`^=` met `state[...]`** → een chain.
- **Buur links (`i-1`)** hoort bij een lus `for i in range(1, len)` (voorwaarts).
  **Buur rechts (`i+1`)** hoort bij `for i in range(len-2, -1, -1)` (achterwaarts).
  Je hoeft de lusrichting niet zelf te regelen; kies gewoon `_fwd` of `_bwd`.
- **`+`/`-`** = `add_const`. **`^`** = XOR. **`rol`/`ror`/`<<`/`>>`** = `rotate`.
- Twijfel? Vul in, run, kijk naar `klopt:`. `False` = verkeerd blokje of
  verkeerde volgorde. Wissel/herorden tot `True`.

---

## 6. Mini-voorbeeld (Better Hash)

```python
for rnd in range(8):                              ROUNDS = 8
    for i in range(len(state)):
        state[i] ^= (rnd*41 + i*17) & 0xff        xor_const(lambda r,i: r*41 + i*17)
        state[i] = rol(state[i], (rnd+i) & 7)     rotate(lambda r,i: (r+i) & 7)
    for i in range(1, len(state)):
        state[i] ^= state[i-1]                    xor_chain_fwd()
    state = state[1:] + state[:1]                 roll_list(1)
```