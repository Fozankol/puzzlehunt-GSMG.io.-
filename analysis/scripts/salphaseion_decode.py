#!/usr/bin/env python3
"""Reproduce the VERIFIED textual decodes of the SalPhaseIon page.

These four results are the publicly-agreed, deterministic decodes of the
SalPhaseIon symbol stream. Run from anywhere:

    python3 analysis/scripts/salphaseion_decode.py

Expected output:
    matrixsumlist
    enter
    lastwordsbeforearchichoice
    thispassword
"""
import binascii
from pathlib import Path

DATA = Path(__file__).resolve().parents[1] / "data" / "salphaseion_text.txt"


def ab_to_ascii(seq: str) -> str:
    bits = "".join("0" if c == "a" else "1" for c in seq)
    return "".join(chr(int(bits[i:i + 8], 2)) for i in range(0, len(bits) - 7, 8))


def main() -> None:
    toks = DATA.read_text(encoding="utf-8").split()

    # 1) maximal runs that contain only 'a'/'b'  ->  a=0,b=1, 8 bits/byte -> ASCII
    runs, cur = [], []
    for t in toks + ["#"]:
        if t in ("a", "b"):
            cur.append(t)
        else:
            if len(cur) >= 24:
                runs.append("".join(cur))
            cur = []
    print("# AB binary blocks (a=0, b=1):")
    for r in runs:
        print("   ", ab_to_ascii(r))

    # 2) 'z'-separated segments over alphabet a..i + o
    #    map a..i=1..9, o=0 -> read as decimal -> hex -> ASCII
    segs, seg = [], []
    for t in toks + ["z"]:
        if t == "z":
            if seg:
                segs.append(seg)
            seg = []
        elif t in "abcdefghio":
            seg.append(t)
        else:
            seg = []  # any non-alphabet token breaks the segment
    trans = str.maketrans("abcdefghio", "1234567890")
    print("# z-separated a..i/o segments (a..i=1..9, o=0 -> hex -> ASCII):")
    for s in segs:
        dec = "".join(s).translate(trans)
        try:
            h = hex(int(dec))[2:]
            if len(h) % 2:
                h = "0" + h
            txt = binascii.unhexlify(h).decode("latin-1")
        except Exception:
            continue
        # only print the long, clearly-meaningful words
        if len(txt) >= 5 and all(32 <= ord(c) < 127 for c in txt):
            print("   ", txt)


if __name__ == "__main__":
    main()
