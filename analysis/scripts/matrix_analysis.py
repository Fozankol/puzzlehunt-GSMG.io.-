#!/usr/bin/env python3
"""Reproducible analysis of the original 14x14 puzzle matrix (puzzle.png).

Grounded in the real hints:
  * 2020-01-14 ("Roses are White but often Red. Yellow has a number and so
    does Blue. Go back to the first puzzle piece."),
  * 2021-03-01 ("which primes 2,3,5,7 ... You are at the prime part"),
  * 2023-02-23 (decodes to "yellow blue primes matrix sumlist last words
    before archichoice yinyang ...").

The matrix uses 4 cell colours: white(0), black(1), blue(b), yellow(y).
In Phase 0 the ASCII decode fixes b=1, y=0. This script tabulates the colour
counts, the yellow/blue bit-sequences, and the row/column "sum lists" under
candidate numeric assignments (incl. primes 2,3,5,7), so the "matrix sumlist"
and "yellow/blue have a number" hints can be explored deterministically.

Run:  python3 analysis/scripts/matrix_analysis.py
"""
import itertools
from collections import Counter

# 14x14 grid transcribed in Phase 0 (gsmgio-pr16/phase0.ipynb)
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

ORDER = [  # Phase 0 counter-clockwise peel: left, bottom, right, top
    ("left",   lambda a: ([r[0] for r in a], [r[1:] for r in a])),
    ("bottom", lambda a: (list(a[-1]), a[:-1])),
    ("right",  lambda a: (list(reversed([r[-1] for r in a])), [r[:-1] for r in a])),
    ("top",    lambda a: (list(reversed(a[0])), a[1:])),
]


def spiral(matrix):
    L = [list(r) for r in matrix]
    out = []
    while L and L[0]:
        for _, fn in ORDER:
            t, L = fn(L)
            out.extend(t)
            if not L or not L[0]:
                break
    return "".join(out)


def is_prime(n):
    if n < 2:
        return False
    return all(n % i for i in range(2, int(n ** 0.5) + 1))


def sums(white, black, blue, yellow):
    val = {"0": white, "1": black, "b": blue, "y": yellow}
    rows = [sum(val[c] for c in row) for row in M]
    cols = [sum(val[M[r][c]] for r in range(14)) for c in range(14)]
    return rows, cols


def main():
    assert len(M) == 14 and all(len(r) == 14 for r in M)
    flat = "".join(M)
    print("colour counts:", dict(Counter(flat)))  # white==black==86, blue=15, yellow=9

    sp = spiral(M)
    yb = "".join(c for c in sp if c in "yb")
    print("yellow/blue in spiral order :", yb, f"({len(yb)} cells)")
    for ym, bm, lab in (("0", "1", "y=0,b=1"), ("1", "0", "y=1,b=0")):
        bits = yb.replace("y", ym).replace("b", bm)
        print(f"   {lab}: {bits} = {int(bits, 2)}")

    print("\nrow/col sum lists for candidate colour values:")
    for w, k, bl, y in [(0, 1, 2, 3), (0, 1, 3, 2), (0, 1, 5, 7), (0, 1, 7, 5)]:
        r, c = sums(w, k, bl, y)
        print(f"  white={w} black={k} blue={bl} yellow={y}")
        print(f"     rows={r}")
        print(f"     cols={c}")

    print("\nsearching colour assignments over {0,1,2,3,5,7} for all-prime sum lists...")
    n = 0
    for w, k, bl, y in itertools.product([0, 1, 2, 3, 5, 7], repeat=4):
        if len({w, k, bl, y}) < 4:
            continue
        r, c = sums(w, k, bl, y)
        if all(map(is_prime, r)) or all(map(is_prime, c)):
            n += 1
            print("   HIT", (w, k, bl, y), "rows", r, "cols", c)
    print("   all-prime assignments found:", n, "(none => simple prime-sum reading does not hold)")


if __name__ == "__main__":
    main()
