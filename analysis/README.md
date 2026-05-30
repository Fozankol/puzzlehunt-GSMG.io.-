# GSMG.io 5 BTC puzzle — Cosmic Duality analysis

> **Status: the final stage (SalPhaseIon → Cosmic Duality) is genuinely
> unsolved.** This folder contains *reproducible, evidence-first* notes that
> (a) verify exactly what the public data does and does not pin down, (b) debunk
> the circulating "solution" that most issues/submodules are built on, and
> (c) record the grounded searches already tried so nobody repeats them.

Every claim below is backed by a script you can re-run. Nothing here depends on
guessed tokens or on the fake artifact.

## Contents

- [Quick start](#quick-start)
- [Where Cosmic Duality sits](#where-cosmic-duality-sits)
- [What is actually verified](#what-is-actually-verified)
- [The real blocker: only 4 of 7 tokens exist in the data](#the-real-blocker-only-4-of-7-tokens-exist-in-the-data)
- [Why the circulating "solution" is fake](#why-the-circulating-solution-is-fake)
- [Searches performed (all negative, all grounded)](#searches-performed-all-negative-all-grounded)
- [The intended construction (architect speech)](#the-intended-construction-architect-speech)
- [Open leads for future solvers](#open-leads-for-future-solvers)
- [File map](#file-map)

## Quick start

```bash
pip install pycryptodome
python3 analysis/scripts/salphaseion_decode.py     # the 4 verified text decodes
python3 analysis/scripts/salphaseion_segments.py   # full stream segmentation
python3 analysis/scripts/debunk_fake_solution.py   # debunk the circulating "solution"
python3 analysis/scripts/attack_blobs.py           # grounded key search   (negative)
python3 analysis/scripts/combo_attack.py           # 30k+ combo-method scan (negative)
python3 analysis/scripts/matrix_analysis.py        # puzzle.png matrix numbers
```

## Where Cosmic Duality sits

The puzzle's earlier phases (0–3.2, Decentraland, SalPhaseIon) are publicly
solved; their walkthroughs live in [`../gsmgio-pr16/`](../gsmgio-pr16). The path
to the end is:

```
puzzle.png (Phase 0) ─▶ … ─▶ Phase 3.2 AES ─▶ Decentraland ("HASHTHETEXT")
   ─▶ sha256(phase-1 image text) = gsmg.io/89727c59…f6a32  (the SalPhaseIon page)
   ─▶ SalPhaseIon symbol stream ──▶ Cosmic Duality blob  ◀── WE ARE HERE
```

The SalPhaseIon page holds two plain-text blocks: the **symbol stream** (which
encodes the password tokens) and the **Cosmic Duality** OpenSSL ciphertext.

## What is actually verified

### The two real OpenSSL `Salted__` ciphertexts

| blob | file | ciphertext | salt |
|------|------|-----------|------|
| Cosmic Duality | [`data/cosmic_duality.txt`](data/cosmic_duality.txt) | 1328 bytes | `2d3f6fe06dc950e6` |
| SalPhaseIon inner | [`data/salphaseion_inner_blob.txt`](data/salphaseion_inner_blob.txt) | 80 bytes | `3ab585348552415d` |

Both base64-decode to `Salted__` + 8-byte salt + AES-block-aligned ciphertext.
Both remain **undecrypted to meaningful output**.

### Provenance — our data matches the archived original byte-for-byte

The SalPhaseIon page is preserved in the Wayback Machine (snapshot
`20230601222752` of `gsmg.io/89727c59…f6a32`). Fetching the original HTML shows
it is just two plain `<textarea>` elements — **no CSS colours, spans, comments,
or any hidden HTML channel.** Our `data/` files reproduce it exactly:

- Cosmic Duality = 1792 base64 chars ✔
- symbol stream = 1075 tokens ✔
- inner blob embedded in the stream ✔

> ⚠️ The colour-coded SalPhaseIon grid in
> `../gsmgio-pr16/salphaseion-assets/SalPhaselonCosmicDuality.png` is a community
> **annotation**, not original puzzle data — the canonical symbols are
> single-colour text. The "yellow/blue have a number" hint refers to the Phase-0
> `puzzle.png` matrix (*"go back to the first puzzle piece"*), not to this grid.

### SalPhaseIon textual decodes (deterministic)

[`scripts/salphaseion_decode.py`](scripts/salphaseion_decode.py) reproduces,
with no guessing:

| part | method | result |
|------|--------|--------|
| p1 | `a`/`b` run → bits (a=0, b=1) → ASCII | `matrixsumlist` |
| p2 | `a`/`b` run → bits → ASCII | `enter` |
| p3 | `z`-segment, a..i=1..9 / o=0 → decimal → hex → ASCII | `lastwordsbeforearchichoice` |
| p4 | same as p3 | `thispassword` |

Inline plaintext in the same stream: **"our first hint is your last command"**
(the "last command" being Decentraland's `HASHTHETEXT`), plus a trailing
fragment that reads **"…ans too"**.

### Official 2023-02-23 hint (decoded reverse-binary)

```
yellow blue primes matrix sumlist last words before archichoice yinyang
we wont give away thepassword its in front of your eyes but youre
not seeing it very last step is a true give away promised
```

Strongest steer toward the password ingredients: `yellow`, `blue`, `primes`,
`matrixsumlist`, `lastwordsbeforearchichoice`, `yinyang`, `thepassword` — and a
promise that the **very last step** will be given away separately (it has not
been, publicly).

## The real blocker: only 4 of 7 tokens exist in the data

[`scripts/salphaseion_segments.py`](scripts/salphaseion_segments.py) segments
the **entire** 1075-token stream on its `z` separators and decodes each segment
with its correct alphabet:

```
seg0 [0:765]   AB-binary -> 'matrixsumlist'   (only the 104-bit a/b run decodes;
                                                surrounding c..i tokens are noise)
seg1 [766:829] decimal   -> 'lastwordsbeforearchichoice'
seg2 [830:859] decimal   -> 'thispassword'
seg3 [860:958] free-text -> "…our first hint is your last command" + base64(inner blob, 1/2)
seg4 [959:..]  AB-binary -> 'enter' + base64(inner blob, 2/2) + tail "…ans too"
```

So the stream **deterministically** yields exactly **four** tokens
(`matrixsumlist`, `enter`, `lastwordsbeforearchichoice`, `thispassword`) plus
**two free-text phrases**. **Tokens p5/p6/p7 are not encoded anywhere in the
data.**

This single fact explains the whole stalemate: every public "solution" has to
*invent* p5–p7, and they all invent different ones (see below). Recovering the
**intended** p5–p7 — or the routing that makes them unnecessary — is the actual
unsolved step.

## Why the circulating "solution" is fake

[`scripts/debunk_fake_solution.py`](scripts/debunk_fake_solution.py) (output
reproducible):

1. It **reproduces the claimed artifact exactly** — XOR of seven SHA-256 token
   hashes → key → AES-256-CBC → `SHA256 = 4f7a1e4e…c081`, 1327 bytes. The
   arithmetic is real, so the artifact is genuine…
2. …but that output is **statistically random**: printable-ASCII ratio ≈ 0.41,
   Shannon entropy ≈ 7.87 / 8.0. A correct OpenSSL decryption of a meaningful
   payload never looks like this.
3. The claim's only "validation" is *valid PKCS#7 padding* — yet **~1 in 256
   arbitrary keys also pass that test** (measured ≈ 0.4 %). The "hidden"
   passwords were simply guessed until padding happened to validate. Padding +
   a self-hash is **not** evidence of a solve.

**Consequence:** issues **#82 / #88 / #91**, the `chain4` layer, the
"39 blocks → 12 addresses (7×1H / 5×1B)" structure, and the recovered
`1Hby7BY…` / `1Bwq9PK…` prefixes are all patterns found in random bytes. (In
random data a base58 P2PKH prefix is fixed by the first ~16 bytes of a window,
so "reproducing" a vanity prefix is expected and meaningless.) A maintainer on
#82 called the thread *"AI slop"* — consistent with this analysis.

### The competing "solutions" contradict each other

The clearest proof they are guesses: they cannot agree on the tokens **or** the
resulting key.

| source | p6 / p7 tokens | claimed "master key" |
|--------|----------------|----------------------|
| jackdevs66 `GSMG5_CDuality` | `yourlastcommand` / `secondanswer` | `a795de11…e50735` |
| upstream issue **#69** | `sha256` / `theone` | `818af53d…bb402` |

Both XOR seven SHA-256 token hashes, both "validate" only via PKCS#7 padding,
both yield random bytes — yet produce **different** keys. If either were the
real route, the tokens would be forced, not interchangeable.

## Searches performed (all negative, all grounded)

### Combination-method brute force

[`scripts/combo_attack.py`](scripts/combo_attack.py) accepts that the 7 tokens
are roughly right and brute-forces the **combination method**, scoring the
*plaintext* for meaningfulness (entropy < 5, printable > 0.85, nested
`Salted__`, or a WIF-like base58 key) — **not** padding:

- all `7!` token **orderings** × 6 separators, used as the OpenSSL password;
- **XOR** of the SHA-256 digests, as a hex password and as a raw key;
- **chained** `sha256(k + token)` derivations;
- each via MD5 *and* SHA-256 `EVP_BytesToKey`, AES-256 **CBC** and **ECB**.

> **30,644 decryptions → 0 meaningful.**

### Single-key / grounded-key search

[`scripts/attack_blobs.py`](scripts/attack_blobs.py) — meaningfulness-scored
search over both real blobs using grounded candidates (the verified tokens,
2023-hint words, matrix-derived numbers, key sizes 32/24/16, CBC/CTR/ECB). No
meaningful output on either blob.

### The Phase-0 matrix numbers

[`scripts/matrix_analysis.py`](scripts/matrix_analysis.py) works the
"matrix sumlist" / "yellow & blue have a number" hints deterministically:

- 14×14 grid, colour counts: **white=86, black=86, blue=15, yellow=9**.
- yellow/blue cells along the counter-clockwise spiral (24 cells):
  `bbbbybbbyybbbbybbyybyyby` → bits `16203154` (y=0,b=1) or `574061` (y=1,b=0).
- row sum list `[10,12,9,8,10,12,9,8,11,13,10,9,11,11]`,
  col sum list `[9,12,11,11,9,9,9,10,8,11,14,9,9,12]`
  (colour values white=0,black=1,blue=2,yellow=3).
- No colour assignment over `{0,1,2,3,5,7}` makes the sum list all-prime, so a
  naive "prime sum" reading does not hold — the prime role is more subtle.

These numbers were tried as key material (words, counts 9/15, the 24-bit spiral
values, the sum sequences) against both blobs: no hit.

## The intended construction (architect speech)

The Phase 3.2 "architect" text describes the end as a **multi-layer** problem,
not a single password:

> "…reinserting the **prime basics**, after which you will be required to select
> from over **twenty-three ciphers**, **sixteen encryptions** and/or **seven
> intertwined passwords** to find the actual private key. note that also
> **brute forcing might be required**."

So Cosmic Duality is a ~16-layer nested construction over 7 intertwined
passwords, with brute force expected. This is *why* naive single-password
attempts correctly return nothing — and why recovering the real routing (not
more guessing) is the path forward.

## Open leads for future solvers

Directions anchored to **real** hints (all single-layer variants below were
tried and produced nothing — they remain open at the multi-layer level):

1. **Recover the genuine p5/p6/p7.** They are not in the stream, so they must
   come from an external source the two free-text phrases point to
   ("our first hint is your last command" / "…ans too") or from a future
   official hint. This is the true bottleneck.
2. **Model the nested layering.** Treat decryption output as the next
   `Salted__` layer's input and search layer sequencing, rather than expecting
   plaintext in one shot.
3. **Attack the inner 80-byte blob first** — it is the smallest fully-known
   target; its password would be concrete next-step material.
4. **Fold the matrix numbers / prime structure** into the routing rather than
   into a flat password.
5. **Ignore anything derived from `4f7a1e…`** — it is noise by construction.

## File map

```
analysis/
├── data/
│   ├── cosmic_duality.txt            # real Cosmic Duality OpenSSL blob (base64)
│   ├── salphaseion_inner_blob.txt    # real SalPhaseIon inner AES blob (base64)
│   └── salphaseion_text.txt          # raw SalPhaseIon symbol stream (1075 tokens)
└── scripts/
    ├── salphaseion_decode.py         # the 4 verified text decodes
    ├── salphaseion_segments.py       # full stream segmentation: only 4 tokens are pinned
    ├── debunk_fake_solution.py       # reproduce + debunk the circulating "solution"
    ├── attack_blobs.py               # grounded, meaningfulness-scored key search
    ├── combo_attack.py               # 30k+ combination-method scan over the 7 tokens
    └── matrix_analysis.py            # 14x14 puzzle.png matrix: counts, sums, spiral bits
```
