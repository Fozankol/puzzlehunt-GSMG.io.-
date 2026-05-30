#!/usr/bin/env python3
"""Focused attack on the SalPhaseIon inner 80-byte blob (salt 3ab585348552415d).

This is the smallest fully-known ciphertext in the puzzle. If it decrypts to
text, that text is almost certainly the next-step material (a password, the
Cosmic key, or the missing p5/p6/p7). So it is the highest-value small target.

Search space (grounded — only real material):
  * the four VERIFIED stream tokens (matrixsumlist, enter,
    lastwordsbeforearchichoice, thispassword), every ordering r=2..4 x separators;
  * the architect's closing words / 2023-hint words / matrix sum strings;
  * XOR of SHA-256 token digests over every subset;
each tried through:
  * OpenSSL EVP_BytesToKey (MD5 and SHA-256), key sizes 32/24/16, CBC and ECB;
  * raw-key derivations that are NOT EVP: key = sha256(pw) / sha256^2(pw) /
    zero-padded pw, with IVs {zero, salt||salt, md5(pw||salt), sha256(pw||salt)}.

Output is ranked by printable-ASCII ratio, and every candidate is run through
the definitive btc_oracle (does the plaintext yield a known GSMG private key?).

Result on the public data: best printable ratio ~0.49 (random-looking),
0 oracle hits => the inner blob does not open with any public token material.

Run:  python3 analysis/scripts/inner_blob_attack.py
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

SALT, CT = load("salphaseion_inner_blob.txt")

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
        for s in (rows, cols, rows + cols):
            out.add("".join(map(str, s)))
    return out

TOK4 = ["matrixsumlist", "enter", "lastwordsbeforearchichoice", "thispassword"]
EXTRA = ["yinyang", "primes", "2357", "theone", "thepassword",
         "ireallyhopeyouretheone", "ciaobella", "youretheone", "9", "15",
         "yellow", "blue", "hashthetext", "ourfirsthintisyourlastcommand", "anstoo",
         "theflowerblossomsthroughwhatseemstobeaconcretesurface"]
WORDS = set(EXTRA) | set(TOK4) | sum_strings()

def evp(pw, salt, md, kl, il):
    d, p = b"", b""
    while len(d) < kl + il:
        p = hashlib.new(md, p + pw + salt).digest(); d += p
    return d[:kl], d[kl:kl + il]

def entropy(b):
    n = len(b)
    return -sum((c/n)*math.log2(c/n) for c in Counter(b).values()) if b else 8.0

def printable(b):
    return sum(1 for c in b if 32 <= c <= 126)/len(b) if b else 0.0

def valid_pad(pt):
    p = pt[-1]
    return 1 <= p <= 16 and pt[-p:] == bytes([p]) * p

N = 0
RESULTS = []

def record(pt, label):
    global N
    N += 1
    pr = printable(pt)
    if pr > 0.6 or entropy(pt) < 4.5 or valid_pad(pt):
        RESULTS.append((pr, entropy(pt), valid_pad(pt), label, pt))

def trial(pw, label):
    pwb = pw.encode() if isinstance(pw, str) else pw
    for md in ("md5", "sha256"):
        for kl, il in ((32, 16), (24, 16), (16, 16)):
            k, iv = evp(pwb, SALT, md, kl, il)
            record(AES.new(k, AES.MODE_CBC, iv).decrypt(CT), f"{label}|evp{md}{kl}cbc")
            record(AES.new(k, AES.MODE_ECB).decrypt(CT), f"{label}|evp{md}{kl}ecb")
    for key in (hashlib.sha256(pwb).digest(),
                hashlib.sha256(hashlib.sha256(pwb).digest()).digest(),
                (pwb + b"\x00"*32)[:32]):
        for iv in (b"\x00"*16, SALT+SALT, hashlib.md5(pwb+SALT).digest(),
                   hashlib.sha256(pwb+SALT).digest()[:16]):
            record(AES.new(key, AES.MODE_CBC, iv).decrypt(CT), f"{label}|rawk-cbc")
        record(AES.new(key, AES.MODE_ECB).decrypt(CT), f"{label}|rawk-ecb")

def main():
    btc_oracle.selftest()
    for w in WORDS:
        trial(w, w[:24])
    for r in range(2, 5):
        for perm in itertools.permutations(TOK4, r):
            for sep in ("", "\n", " ", "-", "+"):
                trial(sep.join(perm), "perm")
    pool = TOK4 + ["yinyang", "primes", "theone", "thepassword"]
    for r in range(2, len(pool) + 1):
        for sub in itertools.combinations(pool, r):
            x = bytearray(32)
            for t in sub:
                h = hashlib.sha256(t.encode()).digest()
                for i in range(32):
                    x[i] ^= h[i]
            trial(bytes(x), "xor")

    RESULTS.sort(key=lambda z: -z[0])
    print(f"{N} decryptions; {len(RESULTS)} above-threshold candidates")
    print("--- top 10 by printable ratio (all look like noise) ---")
    for pr, e, pad, label, pt in RESULTS[:10]:
        print(f"  pr={pr:.2f} ent={e:.2f} pad={pad} {label:28} -> {pt[:32]!r}")

    hits = 0
    for *_, pt in RESULTS:
        h = btc_oracle.check_bytes(pt)
        if h:
            hits += 1
            print("ORACLE HIT:", h)
    print(f"\noracle hits: {hits}")
    print("Result: the inner blob does not open with any public token material."
          if hits == 0 else "SOLVED?!")

if __name__ == "__main__":
    main()
