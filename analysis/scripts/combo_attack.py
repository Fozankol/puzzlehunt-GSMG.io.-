#!/usr/bin/env python3
"""Bounded brute-force over *combination methods* for the 7 SalPhaseIon passwords.

Every public "solution" agrees the final stage uses 7 textual tokens but then
*guesses* how they combine (jackdevs66: XOR of 7 SHA-256 -> MD5 EVP; issue #69:
a different XOR with different tokens). Each guess is "validated" only by PKCS#7
padding, which ~1/256 of arbitrary keys satisfy. Here we instead enumerate the
plausible combination methods and score the *plaintext* for meaningfulness
(low entropy / high printable ratio / nested `Salted__` / WIF-like keys).

Result: across 30k+ derivations (orderings, separators, XOR, hash-chains, raw
key vs OpenSSL password, MD5/SHA256, CBC/ECB) nothing is meaningful — so either
the token set (p5/p6/p7 are guessed) or the routing is still wrong.

Run:  python3 analysis/scripts/combo_attack.py
"""
import base64, hashlib, itertools, math, os
from collections import Counter
from Crypto.Cipher import AES

DATA = os.path.join(os.path.dirname(__file__), '..', 'data')

def load_blob(path):
    b64 = open(path).read().strip().replace('\n', '')
    raw = base64.b64decode(b64 + '=' * (-len(b64) % 4))
    assert raw[:8] == b'Salted__', raw[:8]
    return raw[8:16], raw[16:]

SALT, CT = load_blob(os.path.join(DATA, 'cosmic_duality.txt'))

# Token set per jackdevs66 README (p5 duplicates p1; p6/p7 are that repo's guess).
PARTS = ['matrixsumlist', 'enter', 'lastwordsbeforearchichoice', 'thispassword',
         'matrixsumlist', 'yourlastcommand', 'secondanswer']

def evp(pw, salt, md, klen=32, ivlen=16):
    d = b''; prev = b''
    while len(d) < klen + ivlen:
        prev = hashlib.new(md, prev + pw + salt).digest(); d += prev
    return d[:klen], d[klen:klen + ivlen]

def ent(b):
    if not b: return 8.0
    n = len(b); return -sum((c / n) * math.log2(c / n) for c in Counter(b).values())

def printable_ratio(b):
    return sum(1 for c in b if 9 <= c <= 13 or 32 <= c <= 126) / len(b) if b else 0

B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

def score(pt):
    s = 0; why = []
    e = ent(pt); pr = printable_ratio(pt)
    if e < 5.0: s += 3; why.append(f'lowent{e:.2f}')
    if pr > 0.85: s += 3; why.append(f'print{pr:.2f}')
    if b'Salted__' in pt: s += 10; why.append('SALTED')
    for tok in pt.decode('latin1').replace('\x00', ' ').split():
        if 50 <= len(tok) <= 53 and tok[0] in '5KL' and all(c in B58 for c in tok):
            s += 8; why.append('WIF?' + tok[:6])
    return s, e, pr, why

def candidates():
    seen = set()
    perms = set(itertools.permutations(PARTS))
    for perm in perms:
        for sep in ['', '\n', ' ', ':', '|', ',']:
            pw = sep.join(perm).encode()
            if pw in seen: continue
            seen.add(pw)
            yield ('concat', pw, None, pw)            # OpenSSL password (EVP)
    xor = bytearray(32)
    for p in PARTS:
        d = hashlib.sha256(p.encode()).digest()
        for i in range(32): xor[i] ^= d[i]
    yield ('xor-hexpw', None, None, bytes(xor).hex().encode())  # jackdevs method
    yield ('xor-rawkey', bytes(xor), b'\x00' * 16, None)
    for perm in list(perms)[:200]:                    # chained sha256
        k = b''
        for p in perm: k = hashlib.sha256(k + p.encode()).digest()
        yield ('chain', k, b'\x00' * 16, None)

def decrypt(label, material, iv, as_pw):
    out = []
    if as_pw is not None:
        for md in ('md5', 'sha256'):
            key, iv2 = evp(as_pw, SALT, md)
            out.append((f'{label}/{md}', AES.new(key, AES.MODE_CBC, iv2).decrypt(CT)))
    else:
        out.append((f'{label}/rawcbc', AES.new(material, AES.MODE_CBC, iv).decrypt(CT)))
        out.append((f'{label}/rawecb', AES.new(material, AES.MODE_ECB).decrypt(CT)))
    return out

def main():
    best = []; n = 0
    for label, material, iv, as_pw in candidates():
        for lbl, pt in decrypt(label, material, iv, as_pw):
            n += 1
            s, e, pr, why = score(pt)
            if s >= 3:
                best.append((s, e, pr, lbl, why, pt[:48]))
    best.sort(key=lambda x: -x[0])
    print(f'decryptions tried: {n}')
    print(f'candidates scoring >= 3: {len(best)}')
    for s, e, pr, lbl, why, head in best[:30]:
        print(f's={s} ent={e:.2f} pr={pr:.2f} {lbl} {why} head={head!r}')
    if not best:
        print('NONE meaningful -> token set and/or combination routing still unknown')

if __name__ == '__main__':
    main()
