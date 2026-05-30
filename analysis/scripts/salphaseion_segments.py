#!/usr/bin/env python3
"""Full, rigorous segmentation of the SalPhaseIon symbol stream.

This makes explicit *exactly* how much the stream deterministically yields,
which is the crux of why the final stage is stuck: every public "solution"
needs 7 password tokens, but the stream only pins down **four** tokens plus
**two** free-text English phrases. Tokens p5/p6/p7 are therefore unconstrained
by the data — which is why jackdevs66 (`yourlastcommand`/`secondanswer`) and
upstream issue #69 (`sha256`/`theone`) "derive" different tokens and different
master keys, each validated only by PKCS#7 padding.

Run:  python3 analysis/scripts/salphaseion_segments.py
"""
import binascii, os
from pathlib import Path

DATA = Path(__file__).resolve().parents[1] / "data" / "salphaseion_text.txt"
TRANS = str.maketrans("abcdefghio", "1234567890")


def dec_segment(seg):
    """a..i=1..9, o=0 -> big decimal -> hex -> bytes."""
    d = "".join(seg).translate(TRANS)
    try:
        h = hex(int(d))[2:]
        if len(h) % 2:
            h = "0" + h
        return binascii.unhexlify(h).decode("latin-1")
    except Exception:
        return ""


def ab_to_ascii(seq):
    bits = "".join("0" if c == "a" else "1" for c in seq if c in "ab")
    return "".join(chr(int(bits[i:i + 8], 2)) for i in range(0, len(bits) - 7, 8))


def printable(s):
    return "".join(c if 32 <= ord(c) < 127 else "." for c in s)


def main():
    toks = DATA.read_text().split()
    zpos = [i for i, t in enumerate(toks) if t == "z"]
    bounds = [-1] + zpos + [len(toks)]
    print(f"{len(toks)} tokens, 'z' separators at {zpos}\n")

    for k in range(len(bounds) - 1):
        a, b = bounds[k] + 1, bounds[k + 1]
        seg = toks[a:b]
        chars = set("".join(seg))
        kind = []
        if chars <= set("abcdefghio"):
            d = dec_segment(seg)
            if d and all(32 <= ord(c) < 127 for c in d):
                kind.append(f"decimal->'{d}'")
        runs, cur = [], []
        for t in seg + ["#"]:
            if t in ("a", "b"):
                cur.append(t)
            else:
                if len(cur) >= 24:
                    kind.append(f"AB-binary->'{ab_to_ascii(cur)}'")
                cur = []
        eng = "".join(t for t in seg if len(t) == 1 and t.isalpha())
        print(f"seg{k} [{a}:{b}] len={len(seg)}")
        for x in kind:
            print(f"    {x}")
        if not kind:
            print(f"    free-text/base64: {printable(eng)[:80]}")
        print()

    print("Deterministic yield: p1=matrixsumlist, p2=enter,")
    print("p3=lastwordsbeforearchichoice, p4=thispassword,")
    print("phrase='our first hint is your last command', tail='...ans too'.")
    print("p5/p6/p7 are NOT pinned by the stream -> the real blocker.")


if __name__ == "__main__":
    main()
