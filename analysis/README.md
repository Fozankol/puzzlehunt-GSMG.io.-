# GSMG.io 5 BTC puzzle — Cosmic Duality analysis

Reproducible, evidence-first notes on the **final / unsolved** part of the
puzzle (SalPhaseIon → Cosmic Duality). Everything here can be re-run:

```bash
pip install pycryptodome
python3 analysis/scripts/salphaseion_decode.py     # verified text decodes
python3 analysis/scripts/debunk_fake_solution.py   # debunk circulating "solution"
python3 analysis/scripts/attack_blobs.py           # systematic (negative) key search
```

## TL;DR

* The Cosmic Duality stage is **genuinely unsolved.** No public key/route
  produces meaningful plaintext from the blob.
* The widely-circulated "solution" (jackdevs66/`GSMG5_CDuality`, the issue
  **#82** "reproducibility audit", and downstream `issue #91 / chain4 / 39
  blocks / 1H..1B addresses` work) is built on a **coincidental decryption**
  that yields random bytes. See [`scripts/debunk_fake_solution.py`](scripts/debunk_fake_solution.py).
* Do **not** invest more effort in anything derived from the 1327-byte
  artifact `SHA256=4f7a1e4e…c081`. It is noise.

## What is actually verified

### SalPhaseIon textual decodes (deterministic, reproducible)

`scripts/salphaseion_decode.py` reproduces, with no guessing:

| part | method | result |
|------|--------|--------|
| p1 | `a`/`b` run → bits (a=0,b=1) → ASCII | `matrixsumlist` |
| p2 | `a`/`b` run → bits → ASCII | `enter` |
| p3 | `z`-segment, a..i=1..9 o=0 → decimal → hex → ASCII | `lastwordsbeforearchichoice` |
| p4 | same as p3 | `thispassword` |

Inline plaintext in the same stream: **"our first hint is your last command"**.

### The two real OpenSSL `Salted__` ciphertexts

| blob | file | ciphertext | salt |
|------|------|-----------|------|
| Cosmic Duality | [`data/cosmic_duality.txt`](data/cosmic_duality.txt) | 1328 bytes | `2d3f6fe06dc950e6` |
| SalPhaseIon inner | [`data/salphaseion_inner_blob.txt`](data/salphaseion_inner_blob.txt) | 80 bytes | `3ab585348552415d` |

Both base64-decode to `Salted__` + 8-byte salt + AES block-aligned ciphertext.
Both remain **undecrypted to meaningful output**.

### Official 2023-02-23 hint (decoded reverse-binary)

```
yellow blue primes matrix sumlist last words before archichoice yinyang
we wont give away thepassword its in front of your eyes but youre
not seeing it very last step is a true give away promised
```

This is the strongest steer toward the real Cosmic Duality password
ingredients: `yellow`, `blue`, `primes`, `matrixsumlist`,
`lastwordsbeforearchichoice`, `yinyang`, `thepassword`.

## Why the circulating "solution" is fake

`scripts/debunk_fake_solution.py` (output is reproducible):

1. It **reproduces** the claimed artifact exactly
   (`SHA256 = 4f7a1e4e…c081`, 1327 bytes) — so the arithmetic is real.
2. That output is **statistically random**: printable-ASCII ratio ≈ 0.41,
   Shannon entropy ≈ 7.87 / 8.0. A correct OpenSSL decryption of a meaningful
   payload does not look like this.
3. The claim's only "validation" is *valid PKCS#7 padding*, but **~1/256 of
   arbitrary keys also pass that test** (measured: ~0.4%). Two of the seven
   passwords (`p5`, `p7`) were simply guessed until the padding happened to
   validate. Padding + a fixed hash is **not** evidence of a solution.

Consequence: issue **#82**, **#88**, **#91**, the `chain4` layer, the
"39 blocks → 12 addresses (7×1H / 5×1B)" structure, and the recovered
`1Hby7BY…` / `1Bwq9PK…` prefixes are all artifacts of scanning these random
bytes. (In random data a base58 P2PKH prefix is fixed by the first ~16 bytes
of a window, so "reproducing" a vanity prefix is expected and meaningless.)
A maintainer on #82 bluntly called the thread *"AI slop"* — consistent with
this analysis.

## Open, grounded leads (not yet tried to exhaustion)

These are the directions worth real effort, all anchored to **real** hints
rather than the fake artifact:

1. **Quantify "yellow has a number and so does blue"** (2020-01-14 "Roses are
   White but often Red" hint + Phase-0 colour mapping) and fold those numbers
   into a password with the 2023-hint ingredients.
2. **`matrixsumlist` literally**: the puzzle image is a grid; compute row/column
   sums of the colour matrix and test those numbers/orderings as key material.
3. **The "prime part"** (confirmed important by the creator, 2021-03-01 &
   2023-01-09): identify which numeric component is prime and how it indexes.
4. **SalPhaseIon inner 80-byte blob** is the smaller, fully-known target — if
   its true password is recoverable it likely yields the Cosmic Duality key.
5. Re-derive everything **independently of `4f7a1e…`** — treat any result that
   depends on that artifact as invalid.

## Files

```
analysis/
├── data/
│   ├── cosmic_duality.txt            # real Cosmic Duality OpenSSL blob (base64)
│   ├── salphaseion_inner_blob.txt    # real SalPhaseIon inner AES blob (base64)
│   └── salphaseion_text.txt          # raw SalPhaseIon symbol stream
└── scripts/
    ├── salphaseion_decode.py         # reproduce the 4 verified text decodes
    ├── debunk_fake_solution.py       # reproduce + debunk the circulating "solution"
    └── attack_blobs.py               # systematic, meaningfulness-scored key search
```
