#!/usr/bin/env python3
"""Grounded attack on the Cosmic Duality blob using the *instruction-token*
reading of the SalPhaseIon decodes.

Premise (new): the four verified stream tokens are not literal passwords but
INSTRUCTIONS describing how to build the password, matching the 2023-02-23 hint
which enumerates seven ingredients in order:

    yellow  blue  primes  matrixsumlist  lastwordsbeforearchichoice  yinyang  thepassword

Each ingredient is resolved to its real value:
  * yellow / blue        -> the Phase-0 matrix colour counts (9 / 15) or the words
  * primes               -> 2,3,5,7 / the word
  * matrixsumlist        -> the literal row/col SUM LIST digit strings from puzzle.png
  * lastwordsbeforearchichoice -> the architect monologue's closing words
                            ("...i really hope you're the one ciao bella o")
  * yinyang              -> the word (matrix is 86 white / 86 black = balanced)
  * thepassword          -> thepassword / thispassword (the un-given final token)

It then tries the two construction families that the puzzle is known to use:
  A) concatenation (in hint order, several separators) as the OpenSSL password;
  B) XOR of the seven SHA-256 ingredient digests (the mechanism every public
     "solution" uses) -> key, several IV conventions.

Scoring is by *meaningfulness* (Shannon entropy / printable ratio / nested
`Salted__`), and every low-entropy candidate is checked with the DEFINITIVE
oracle in btc_oracle.py (does it yield a known GSMG private key?).

Result on the public data: 0 meaningful, 0 oracle hits. Documented so this
avenue is not re-explored blindly.

Run:  python3 analysis/scripts/grounded_attack.py
"""
import base64, hashlib, itertools, math
from collections import Counter
from pathlib import Path
from Crypto.Cipher import AES
import btc_oracle

DATA = Path(__file__).resolve().parents[1] / "data"

def load(name):
    raw = base64.b64decode(open(DATA / name).read().replace("\n", "").strip())
    assert raw[:8] == b"Salted__"
    return raw[8:16], raw[16:]

SALT_C, CT_C = load("cosmic_duality.txt")

# Phase-0 matrix (puzzle.png), transcribed in gsmgio-pr16/phase0.ipynb
M = """00110b0010110y
11b1001110b011
1101110b001001
0110b000011101
0b1000110y0110
100110y010y011
100b1100010y00
b11000000010y0
00011b0111110b
11b111y0110001
1101000y011011
11110010b01100
0b0111010y0110
01b0110110b011""".split("\n")

def sum_strings():
    out = set()
    for mp in ({"0":0,"1":1,"b":2,"y":3}, {"0":0,"1":1,"b":1,"y":0}):
        rows = [sum(mp[c] for c in r) for r in M]
        cols = [sum(mp[M[i][j]] for i in range(14)) for j in range(14)]
        for seq in (rows, cols, rows + cols):
            out.add("".join(map(str, seq)))
    return sorted(out)

ARCH = ["ireallyhopeyouretheone", "theone", "youretheone", "ciaobella",
        "ciaobellao", "lastwordsbeforearchichoice"]
ING = [
    ["yellow", "9"],
    ["blue", "15"],
    ["primes", "2357", "prime"],
    ["matrixsumlist"] + sum_strings(),
    ARCH,
    ["yinyang"],
    ["thepassword", "thispassword", "enter"],
]

def evp(pw, salt, md="md5", kl=32, il=16):
    d, p = b"", b""
    while len(d) < kl + il:
        p = hashlib.new(md, p + pw + salt).digest(); d += p
    return d[:kl], d[kl:kl + il]

def entropy(b):
    n = len(b)
    return -sum((c/n)*math.log2(c/n) for c in Counter(b).values()) if b else 8.0

def printable(b):
    return sum(1 for c in b if 9 <= c <= 13 or 32 <= c <= 126)/len(b) if b else 0.0

def meaningful(pt):
    return entropy(pt) < 5.0 or printable(pt) > 0.85 or b"Salted__" in pt

def xor_digests(tokens):
    x = bytearray(32)
    for t in tokens:
        h = hashlib.sha256(t.encode()).digest()
        for i in range(32):
            x[i] ^= h[i]
    return bytes(x)

def main():
    btc_oracle.selftest()
    n = meaning = oracle = 0
    candidates = []

    # Family A: concatenation as OpenSSL password
    for sep in ("", "\n", " ", "-"):
        for combo in itertools.product(*ING):
            pw = sep.join(combo).encode()
            for md in ("md5", "sha256"):
                k, iv = evp(pw, SALT_C, md)
                pt = AES.new(k, AES.MODE_CBC, iv).decrypt(CT_C)
                n += 1
                if meaningful(pt):
                    meaning += 1; candidates.append(pt)

    # Family B: XOR of seven SHA-256 ingredient digests
    for combo in itertools.product(*ING):
        xk = xor_digests(combo)
        for md in ("md5", "sha256"):
            k, iv = evp(xk, SALT_C, md)            # 32 raw bytes as password
            pt = AES.new(k, AES.MODE_CBC, iv).decrypt(CT_C); n += 1
            if meaningful(pt): meaning += 1; candidates.append(pt)
        for iv in (b"\x00"*16, hashlib.md5(xk + SALT_C).digest()):  # raw key
            pt = AES.new(xk, AES.MODE_CBC, iv).decrypt(CT_C); n += 1
            if meaningful(pt): meaning += 1; candidates.append(pt)

    # Definitive validation: run the BTC oracle on every meaningful candidate
    for pt in candidates:
        if btc_oracle.check_bytes(pt):
            oracle += 1
            print("ORACLE HIT:", btc_oracle.check_bytes(pt), pt[:48])

    print(f"\n{n} decryptions; {meaning} meaningful by entropy/printable; "
          f"{oracle} oracle hits.")
    print("Result: the instruction-token reading does not solve Cosmic Duality "
          "on the public data." if oracle == 0 else "SOLVED?!")

if __name__ == "__main__":
    main()
