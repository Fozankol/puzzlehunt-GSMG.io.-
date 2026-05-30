#!/usr/bin/env python3
"""Reproducible debunk of the circulating "Cosmic Duality solution".

Several 2025-2026 repos / GitHub issues (jackdevs66/GSMG5_CDuality, the
issue #82 "reproducibility audit", etc.) claim to have decrypted the Cosmic
Duality blob. They all converge on the same 1327-byte artifact with
SHA-256 = 4f7a1e4efe4bf6c5581e32505c019657cb7b030e90232d33f011aca6a5e9c081.

The claimed method:
  * take 7 "SalPhaseIon passwords" (two of which, p5 and p7, are GUESSED),
  * XOR their 7 SHA-256 digests -> 32-byte value,
  * use those 32 raw bytes as the OpenSSL password (EVP_BytesToKey, MD5),
  * AES-256-CBC decrypt -> "valid PKCS#7 padding" => declared solved.

This script shows the claim is a coincidence, not a solution:
  1. It reproduces the exact 4f7a1e... artifact (so the math checks out), and
  2. shows the output is high-entropy random bytes (NOT meaningful plaintext),
  3. shows ~1/256 of ARBITRARY keys also yield "valid PKCS#7 padding",
     so the padding test proves nothing.

Run:  python3 analysis/scripts/debunk_fake_solution.py
"""
import base64
import hashlib
import math
import os
from collections import Counter
from pathlib import Path

from Crypto.Cipher import AES

DATA = Path(__file__).resolve().parents[1] / "data" / "cosmic_duality.txt"

CLAIMED_PASSWORDS = [
    "matrixsumlist",            # p1 (verified decode)
    "enter",                    # p2 (verified decode)
    "lastwordsbeforearchichoice",  # p3 (verified decode)
    "thispassword",             # p4 (verified decode)
    "matrixsumlist",            # p5 (GUESSED to fit padding)
    "yourlastcommand",          # p6 (interpretation of inline phrase)
    "secondanswer",             # p7 (GUESSED to fit padding)
]
CLAIMED_HASH = "4f7a1e4efe4bf6c5581e32505c019657cb7b030e90232d33f011aca6a5e9c081"


def evp_bytes_to_key(password: bytes, salt: bytes, klen: int, ivlen: int) -> tuple[bytes, bytes]:
    d, prev = b"", b""
    while len(d) < klen + ivlen:
        prev = hashlib.md5(prev + password + salt).digest()
        d += prev
    return d[:klen], d[klen:klen + ivlen]


def entropy(b: bytes) -> float:
    if not b:
        return 0.0
    n = len(b)
    return -sum((c / n) * math.log2(c / n) for c in Counter(b).values())


def printable_ratio(b: bytes) -> float:
    return sum(1 for c in b if 9 <= c <= 13 or 32 <= c <= 126) / len(b) if b else 0.0


def main() -> None:
    raw = base64.b64decode(DATA.read_text().replace("\n", "").strip())
    salt, ct = raw[8:16], raw[16:]

    # 1) reproduce the claimed artifact
    digests = [hashlib.sha256(p.encode()).digest() for p in CLAIMED_PASSWORDS]
    x = bytearray(digests[0])
    for h in digests[1:]:
        for i, b in enumerate(h):
            x[i] ^= b
    # jackdevs66 uses these 32 RAW bytes as the OpenSSL password (not the hex string)
    password = bytes(x)
    key, iv = evp_bytes_to_key(password, salt, 32, 16)
    pt = AES.new(key, AES.MODE_CBC, iv).decrypt(ct)
    pad = pt[-1]
    pt_unpadded = pt[:-pad]
    digest = hashlib.sha256(pt_unpadded).hexdigest()

    print("== Reproducing the circulating claim ==")
    print("output length        :", len(pt_unpadded))
    print("output SHA-256        :", digest)
    print("matches claimed hash  :", digest == CLAIMED_HASH)
    print("printable ASCII ratio :", round(printable_ratio(pt_unpadded), 3))
    print("Shannon entropy (bits):", round(entropy(pt_unpadded), 3), "/ 8.0  (>7.9 == random)")
    print("first 32 bytes (hex)  :", pt_unpadded[:32].hex())
    print()
    print("=> The 'plaintext' is indistinguishable from random bytes.")
    print("   A correct OpenSSL decryption of a meaningful payload would not look like this,")
    print("   and p5/p7 were chosen specifically because they happen to give valid padding.")
    print()

    # 2) show valid PKCS#7 padding is a ~1/256 coincidence
    N, valid = 30000, 0
    for _ in range(N):
        k, v = evp_bytes_to_key(os.urandom(16).hex().encode(), salt, 32, 16)
        d = AES.new(k, AES.MODE_CBC, v).decrypt(ct)
        p = d[-1]
        if 1 <= p <= 16 and d[-p:] == bytes([p]) * p:
            valid += 1
    print("== 'valid padding' is not evidence ==")
    print(f"random keys with VALID PKCS#7 padding: {valid}/{N} = {valid / N:.4f}")
    print(f"expected by chance                    : ~{1/256:.4f}")
    print("=> 'valid padding + a fixed hash' proves nothing; it is a coincidence.")


if __name__ == "__main__":
    main()
