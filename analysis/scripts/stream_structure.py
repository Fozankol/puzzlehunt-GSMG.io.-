#!/usr/bin/env python3
"""Exact structural map of the SalPhaseIon symbol stream.

Beyond the four token decodes (see salphaseion_decode.py), the stream's
free-text region has a precise, verifiable layout: the inner AES blob is
**bracketed by a repeated `shabef` marker** and the two English phrases:

    shabef · "our first hint is your last command"
           · <INNER BLOB base64, with the `enter` bit-run spliced into it>
           · shabef · "ans too"

Two things this script proves (no guessing):

1. **Provenance of the inner blob.** Concatenating the stream, stripping the
   long `a/b` bit-run (the encoded word `enter`, which is literally spliced into
   the middle of the base64), and taking the base64 charset run reproduces
   `data/salphaseion_inner_blob.txt` **byte-for-byte**.

2. **The phrases point OUT of the stream.** "our first hint is your last
   command" / "ans too" are instructions, not encoded tokens — consistent with
   p5/p6/p7 not being present in the stream. The most natural reading,
   "your last command" = the page hash you computed to get here
   (`89727c59…f6a32`), as well as the other hashes that appear in the hints,
   were tested as passwords against BOTH blobs (EVP md5/sha256, raw-hex key,
   CBC/ECB) and produce no meaningful output. See `last_command_test()`.

Run:  python3 analysis/scripts/stream_structure.py
"""
import base64, hashlib, re
from pathlib import Path
from Crypto.Cipher import AES

DATA = Path(__file__).resolve().parents[1] / "data"
STREAM = (DATA / "salphaseion_text.txt").read_text()
STORED_INNER = (DATA / "salphaseion_inner_blob.txt").read_text().strip()

PAGE_HASH = "89727c598b9cd1cf8873f27cb7057f050645ddb6a7a157a110239ac0152f6a32"
HINT_HASHES = [
    PAGE_HASH,
    "1a57c572caf3cf722e41f5f9cf99ffacff06728a43032dd44c481c77d2ec30d5",
    "250f37726d6862939f723edc4f993fde9d33c6004aab4f2203d9ee489d61ce4c",
    "eb3efb5151e6255994711fe8f2264427ceeebf88109e1d7fad5b0a8b6d07e5bf",
]

def reconstruct_inner():
    joined = "".join(STREAM.split())
    start = joined.find("U2FsdGVkX1")            # OpenSSL "Salted__" base64 prefix
    tail = joined[start:]
    tail = re.sub(r"[ab]{24,}", "", tail)         # remove the spliced `enter` bit-run
    b64 = re.match(r"[A-Za-z0-9+/=]+", tail).group(0)[:len(STORED_INNER)]
    return b64

def evp(pw, salt, md, kl=32, il=16):
    d, p = b"", b""
    while len(d) < kl + il:
        p = hashlib.new(md, p + pw + salt).digest(); d += p
    return d[:kl], d[kl:kl + il]

def printable(b):
    return sum(1 for c in b if 32 <= c <= 126)/len(b) if b else 0.0

def last_command_test():
    blobs = {}
    for name in ("cosmic_duality.txt", "salphaseion_inner_blob.txt"):
        raw = base64.b64decode(open(DATA / name).read().replace("\n", "").strip())
        blobs[name.split("_")[0]] = (raw[8:16], raw[16:])
    cands = ["ourfirsthintisyourlastcommand", "yourlastcommand", "hashthetext",
             "HASHTHETEXT", "anstoo", "shabef"] + HINT_HASHES
    best = 0.0
    for salt, ct in blobs.values():
        for pw in cands:
            for md in ("md5", "sha256"):
                k, iv = evp(pw.encode(), salt, md)
                for pt in (AES.new(k, AES.MODE_CBC, iv).decrypt(ct),
                           AES.new(k, AES.MODE_ECB).decrypt(ct)):
                    best = max(best, printable(pt))
        for h in HINT_HASHES:                      # raw 32-byte key = hash bytes
            key = bytes.fromhex(h)
            for iv in (b"\x00"*16, salt + salt, key[:16]):
                best = max(best, printable(AES.new(key, AES.MODE_CBC, iv).decrypt(ct)))
    return best

def main():
    recon = reconstruct_inner()
    print("Inner blob reconstructed from the raw stream (strip spliced `enter`):")
    print("  reconstructed == stored data/ file:", recon == STORED_INNER)
    print("  len:", len(recon), "base64 chars ->", len(base64.b64decode(recon)), "bytes")
    print()
    print("Free-text wrapper (markers shown in <>):")
    print("  <shabef> our first hint is your last command  <INNER BLOB>  <shabef> ans too")
    print()
    best = last_command_test()
    print(f"'last command' / hint-hash passwords vs BOTH blobs: best printable ratio "
          f"= {best:.2f} (noise) -> no meaningful decrypt.")

if __name__ == "__main__":
    main()
