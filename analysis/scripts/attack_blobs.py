#!/usr/bin/env python3
"""Systematic (so far NEGATIVE) password search over the two real OpenSSL blobs.

Targets the genuinely-unsolved ciphertexts:
  * Cosmic Duality blob           (data/cosmic_duality.txt,        1328-byte ct)
  * SalPhaseIon inner AES blob    (data/salphaseion_inner_blob.txt,  80-byte ct)

For every candidate password it tries EVP_BytesToKey with MD5 and SHA-256,
key sizes 256/192/128, and CBC/CTR/ECB, then scores the output for
*meaningfulness* (printable ratio, Shannon entropy) instead of merely
checking PKCS#7 padding (which is a 1/256 coincidence — see
debunk_fake_solution.py).

The candidate set is grounded in REAL puzzle material:
  * the 4 verified SalPhaseIon decodes + their permutations,
  * every historical phase password/answer,
  * the words from the official 2023-02-23 binary hint.

As of this writing NOTHING produces meaningful output: the correct key/route
for both blobs is still unknown. This script exists so future work does not
re-run the same dead ends. Add candidates to CANDIDATES and re-run.

Run:  python3 analysis/scripts/attack_blobs.py
"""
import base64
import hashlib
import itertools
import math
from collections import Counter
from pathlib import Path

from Crypto.Cipher import AES
from Crypto.Util import Counter as CTRCounter

DATA = Path(__file__).resolve().parents[1] / "data"

VERIFIED_PARTS = ["matrixsumlist", "enter", "lastwordsbeforearchichoice", "thispassword"]

HISTORICAL = [
    "theseedisplanted",
    "theflowerblossomsthroughwhatseemstobeaconcretesurface",
    "causality", "Safenet", "Luna", "HSM", "causalitySafenetLunaHSM",
    "jacquefresco", "giveitjustonesecond", "heisenbergsuncertaintyprinciple",
    "jacquefrescogiveitjustonesecondheisenbergsuncertaintyprinciple",
    "thematrixhasyou", "followthewhiterabbit", "hashthetext",
    "yourlastcommand", "secondanswer",
]

HINT_2023 = ["yellow", "blue", "primes", "matrixsumlist",
             "lastwordsbeforearchichoice", "yinyang", "thepassword"]


def build_candidates() -> list[str]:
    cands = set(HISTORICAL) | set(HINT_2023) | set(VERIFIED_PARTS)
    for r in range(1, len(VERIFIED_PARTS) + 1):
        for c in itertools.permutations(VERIFIED_PARTS, r):
            cands.add("".join(c))
    cands.add("yellowblueprimesmatrixsumlistlastwordsbeforearchichoiceyinyang")
    cands.add("yellow blue primes matrix sumlist last words before archichoice yinyang")
    return sorted(cands)


def evp(password: bytes, salt: bytes, md: str, klen: int, ivlen: int = 16):
    d, prev = b"", b""
    while len(d) < klen + ivlen:
        prev = hashlib.new(md, prev + password + salt).digest()
        d += prev
    return d[:klen], d[klen:klen + ivlen]


def decrypt(key, iv, ct, mode):
    if mode == "cbc":
        return AES.new(key, AES.MODE_CBC, iv).decrypt(ct)
    if mode == "ecb":
        return AES.new(key, AES.MODE_ECB).decrypt(ct)
    ctr = CTRCounter.new(128, initial_value=int.from_bytes(iv, "big"))
    return AES.new(key, AES.MODE_CTR, counter=ctr).decrypt(ct)


def entropy(b: bytes) -> float:
    if not b:
        return 8.0
    n = len(b)
    return -sum((c / n) * math.log2(c / n) for c in Counter(b).values())


def printable_ratio(b: bytes) -> float:
    return sum(1 for c in b if 9 <= c <= 13 or 32 <= c <= 126) / len(b) if b else 0.0


def load_blob(name: str):
    raw = base64.b64decode(DATA.joinpath(name).read_text().replace("\n", "").strip())
    assert raw[:8] == b"Salted__"
    return raw[8:16], raw[16:]


def attack(label: str, name: str, candidates: list[str]) -> int:
    salt, ct = load_blob(name)
    print(f"\n=== {label}: {len(ct)}-byte ciphertext, salt {salt.hex()} ===")
    hits = 0
    for w in candidates:
        for variant in {w, w.lower()}:
            for md in ("md5", "sha256"):
                for klen in (32, 24, 16):
                    key, iv = evp(variant.encode(), salt, md, klen)
                    for mode in ("cbc", "ctr", "ecb"):
                        pt = decrypt(key, iv, ct, mode)
                        if printable_ratio(pt) > 0.85 or entropy(pt) < 5.0:
                            hits += 1
                            print(f"  CANDIDATE {variant!r} {md} k{klen} {mode}: "
                                  f"pr={printable_ratio(pt):.2f} ent={entropy(pt):.2f} -> {pt[:48]!r}")
    if hits == 0:
        print("  no meaningful output (all combinations look random) — UNSOLVED")
    return hits


def main() -> None:
    cands = build_candidates()
    print(f"candidate passwords: {len(cands)}")
    attack("Cosmic Duality", "cosmic_duality.txt", cands)
    attack("SalPhaseIon inner blob", "salphaseion_inner_blob.txt", cands)


if __name__ == "__main__":
    main()
