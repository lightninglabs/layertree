#!/usr/bin/env python3
"""Measurement experiment: what does a radix-4 (or radix-8) dense Merkle-sum
level cost in the FULL tier, compared with the radix-2 `level_dense()`?

Run from the repository root:

    python3 tools/experiments/radix4.py

Radix-r node format (experiment only, not in the spec):

    H_node_r(c_0 || ... || c_{r-1}),   c_i = hash_i || enc64(sum_i)   (41 bytes)
    sum = sum_i sum_i

For r = 2 this is exactly the spec 5.3 node, so the radix-2 baseline runs the
unmodified `level_dense()` through the same harness. Note the child encoding
is 41 bytes (32 + the 9-byte enc64), so a radix-4 preimage is 164 bytes.

In the generated level, `X` is the concatenation of the r-1 siblings in
child order, `k = 41 * dir` is the byte offset of the accumulator child, and
`L`, `R` are X split at k.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import layertree_ref as lt  # noqa: E402
import layertree_scripts as ls  # noqa: E402
from script_sim import Interp, ScriptError, assemble, num_encode  # noqa: E402
from test_scripts import ALLOWED_OPCODES  # noqa: E402

CH = 41                                   # bytes of one child: hash || enc64(sum)


# --------------------------------------------------------------------------
# The macro
# --------------------------------------------------------------------------
def mul41():
    """[d] -> [41*d] using only adds: 41 d = d + 8 d + 32 d.  14 bytes."""
    return (["OP_DUP"] +                                   # d d
            ["OP_DUP", "OP_ADD"] * 3 +                     # d 8d
            ["OP_DUP"] + ["OP_DUP", "OP_ADD"] * 2 +        # d 8d 32d
            ["OP_ADD", "OP_ADD"])                          # 41d


def level_r_dense(r=4):
    """Radix-r dense level, both accumulators.

    Stack: dir s_0 .. s_{r-2} T oh os nh ns -> T oh' os' nh' ns'
    dir is the accumulator's child index 0..r-1 (minimal number); s_i are the
    r-1 siblings (41 bytes each) in child order.  dir >= r behaves as r-1
    (LEFT/SUBSTR clamp), which yields the same preimage as dir = r-1, so no
    range check is needed.
    """
    n = r - 1
    size = CH * n
    t = [(r + 4), "OP_ROLL"] * r                           # T oh os nh ns dir s_0..s_{n-1}
    # Size-check every sibling, push its raw le64 sum on the alt stack and
    # concatenate them in child order into X.
    chk = ["OP_SIZE", CH, "OP_EQUALVERIFY", "OP_DUP", 32, 8, "OP_SUBSTR", "OP_TOALTSTACK"]
    t += chk                                               # ... s_0 .. s_{n-1}    | ss_{n-1}
    for _ in range(n - 1):
        t += ["OP_SWAP"] + chk + ["OP_SWAP", "OP_CAT"]     # ... s_0 .. (s_j||Y)   | .. ss_j
    t += ["OP_FROMALTSTACK"] + ["OP_FROMALTSTACK", "OP_ADD"] * (n - 1)  # ... dir X st
    t += [ls.TWO64]                                        # ... dir X st Q     (Q = 2^64, pushed once)
    t += [3, "OP_ROLL"] + mul41()                          # ... X st Q k
    t += [3, "OP_PICK", "OP_OVER", "OP_LEFT"]              # ... X st Q k L
    t += [4, "OP_ROLL", "OP_ROT", size, "OP_SUBSTR"]       # T oh os nh ns st Q L R

    def acc(sum_d, hash_d, tdepth):
        return (
            [sum_d, "OP_PICK", "OP_DUP", 5, "OP_PICK", "OP_ADD",
             "OP_TOALTSTACK",                              # ... L R s        | s' = s + st
             3, "OP_PICK", "OP_ADD",                       # ... L R enc      enc = s + 2^64 = enc64(s)
             hash_d, "OP_PICK", "OP_SWAP", "OP_CAT",       # ... L R c        c = h||enc
             2, "OP_PICK", "OP_SWAP", "OP_CAT",            # ... L R (L||c)
             "OP_OVER", "OP_CAT",                          # ... L R (L||c||R)
             tdepth, "OP_PICK", "OP_SWAP", "OP_CAT", "OP_SHA256",  # ... L R h'
             "OP_TOALTSTACK"])                             #                  | s' h'
    # stack depths (from top) with L R on top: R0 L1 Q2 st3 ns4 nh5 os6 oh7 T8
    t += acc(6, 8, 9)                                      # old: os' oh' on alt
    t += acc(4, 6, 9)                                      # new: ns' nh' on alt
    t += ["OP_2DROP"] * 4                                  # T
    t += ["OP_FROMALTSTACK"] * 4 + ["OP_2SWAP"]            # T nh' ns' oh' os' -> T oh' os' nh' ns'
    return t


def level4_dense():
    return level_r_dense(4)


# --------------------------------------------------------------------------
# Reference radix-r Merkle-sum tree
# --------------------------------------------------------------------------
def child(n):
    return n[0] + lt.enc64(n[1])


def node_r(children):
    return (lt.tagged_hash(lt.TAG_NODE, b"".join(child(c) for c in children)),
            sum(c[1] for c in children))


_empty = {}


def empty_r(r, h):
    if h == 0:
        return lt.EMPTY_NODE
    if (r, h) not in _empty:
        e = empty_r(r, h - 1)
        _empty[(r, h)] = node_r([e] * r)
    return _empty[(r, h)]


class TreeR:
    def __init__(self, r, depth):
        self.r, self.depth, self.leaves = r, depth, {}

    def sub(self, h, idx):
        lo, hi = idx * self.r ** h, (idx + 1) * self.r ** h
        if not any(lo <= s < hi for s in self.leaves):
            return empty_r(self.r, h)
        if h == 0:
            return self.leaves[idx].node()
        return node_r([self.sub(h - 1, idx * self.r + i) for i in range(self.r)])

    def root(self):
        return self.sub(self.depth, 0)

    def path(self, slot):
        """[(dir, [siblings in child order])] bottom-up."""
        out, idx = [], slot
        for h in range(self.depth):
            d = idx % self.r
            base = idx - d
            out.append((d, [self.sub(h, base + i) for i in range(self.r) if i != d]))
            idx //= self.r
        return out


def mk_leaves(t, slots):
    for i, s in enumerate(slots):
        k = lt.sha256(b"k%d" % s)
        t.leaves[s] = lt.Leaf(1000 + 37 * i, k, k, k, 1000, nonce=s)


# --------------------------------------------------------------------------
# Harness
# --------------------------------------------------------------------------
def witness(path, tweak=None):
    """Witness stack bottom..top: deepest level first; per level dir, s_0.."""
    items = []
    for lvl, (d, sibs) in reversed(list(enumerate(path))):
        sibs = [child(s) for s in sibs]
        dd = d
        if tweak:
            dd, sibs = tweak(lvl, dd, sibs)
        items += [num_encode(dd)] + sibs
    return items


def run(t, slot, level_fn, tweak=None):
    """Fold the leaf at `slot` (old acc = leaf, new acc = empty) through all
    levels, then verify in-script that the accumulators equal the reference
    roots: the old root with the leaf, the new root with the slot emptied.
    Raises ScriptError on any mismatch.  Returns the interpreter."""
    leaf = t.leaves[slot]
    t2 = TreeR(t.r, t.depth)
    t2.leaves = {s: v for s, v in t.leaves.items() if s != slot}
    (want_oh, want_os), (want_nh, want_ns) = t.root(), t2.root()
    items = witness(t.path(slot), tweak)
    stack = items + [ls.NODE_PREFIX, leaf.hash(), num_encode(leaf.amount),
                     lt.EMPTY_LEAF_HASH, b""]
    tail = [want_ns, "OP_NUMEQUALVERIFY", want_nh, "OP_EQUALVERIFY",   # T oh' os'
            want_os, "OP_NUMEQUALVERIFY", want_oh, "OP_EQUALVERIFY",   # T
            "OP_1"]                                                    # (T is left below)
    # The simulator wants exactly one item left: drop T under a constant true.
    tail += ["OP_SWAP", "OP_DROP"]
    it = Interp(None, mode="c2")
    it.run(assemble(level_fn() * t.depth + tail), stack)
    return it


def check_case(r, depth, slots, slot, level_fn, results):
    name = f"r={r} D={depth} slot={slot}"
    t = TreeR(r, depth)
    mk_leaves(t, slots)

    def ok(label, cond):
        results.append((f"{name} {label}", cond))

    try:
        run(t, slot, level_fn)
        good = True
    except ScriptError as e:
        print("positive failed:", e)
        good = False
    ok("positive: old and new root equal the reference roots", good)

    def rejected(tweak):
        try:
            run(t, slot, level_fn, tweak)
        except ScriptError:
            return True
        return False

    ok("negative: wrong direction (level 0)",
       rejected(lambda l, d, s: ((d + 1) % r, s) if l == 0 else (d, s)))
    ok("negative: wrong direction (top level)",
       rejected(lambda l, d, s: ((d + 1) % r, s) if l == depth - 1 else (d, s)))

    def bump_sum(l, d, s):
        if l == 1 % depth:
            s = list(s)
            s[-1] = s[-1][:32] + bytes([s[-1][32] ^ 1]) + s[-1][33:]
        return d, s
    ok("negative: tampered sibling sum", rejected(bump_sum))

    def bump_hash(l, d, s):
        if l == 0:
            s = list(s)
            s[0] = bytes([s[0][0] ^ 1]) + s[0][1:]
        return d, s
    ok("negative: tampered sibling hash", rejected(bump_hash))

    def short(l, d, s):
        if l == 0:
            s = list(s)
            s[0] = s[0][:-1]
        return d, s
    ok("negative: 40-byte sibling", rejected(short))


def level_fn_for(r):
    return ls.level_dense if r == 2 else (lambda: level_r_dense(r))


def main():
    results = []
    toks = level_r_dense(4) + level_r_dense(8)
    bad = {t for t in toks if isinstance(t, str)} - ALLOWED_OPCODES
    results.append(("opcodes within ALLOWED_OPCODES", not bad))

    S3 = [3, 17, 18, 40, 63]
    for r, depth, slots, slot in [(2, 4, [0, 5, 6, 13], 5), (2, 4, [0, 5, 6, 13], 13),
                                  (4, 2, [0, 5, 6, 13], 5), (4, 2, [0, 5, 6, 13], 13),
                                  (4, 3, S3, 18), (4, 3, S3, 63), (4, 3, S3, 3),
                                  (8, 2, [0, 9, 33, 63], 33), (8, 2, [0, 9, 33, 63], 63)]:
        check_case(r, depth, slots, slot, level_fn_for(r), results)

    print("| radix | script B/level | witness data B/level | dir B (avg) | items/level | varops/level |")
    print("|---|---|---|---|---|---|")
    meas = {}
    for r in (2, 4, 8):
        fn = level_fn_for(r)
        sb = len(assemble(fn()))
        wd = CH * (r - 1)
        t = TreeR(r, 3 if r < 8 else 2)
        mk_leaves(t, [1, 2])
        it = run(t, 1, fn)
        meas[r] = (sb, wd, it.cost / t.depth)
        print(f"| {r} | {sb} | {wd} | {(r - 1) / r:.3f} | {r} | {it.cost / t.depth:.0f} |")

    base_s, base_w = 2101 - 16 * 88, 902 - 16 * 41
    print(f"\nEXIT_1 at 65,536 leaves; base script {base_s}, base witness {base_w}"
          " (EXIT_1 D=16 dense minus 16 levels)")
    print("| shape | script B | witness data B |")
    print("|---|---|---|")
    for label, parts in [("radix 2 x16", [(2, 16)]), ("radix 4 x8", [(4, 8)]),
                         ("radix 8 x6 (covers 2^18)", [(8, 6)]),
                         ("radix 8 x5 + radix 2 x1", [(8, 5), (2, 1)])]:
        s = base_s + sum(meas[r][0] * n for r, n in parts)
        w = base_w + sum(meas[r][1] * n for r, n in parts)
        print(f"| {label} | {s} | {w} |")

    print()
    nfail = 0
    for label, good in results:
        if not good:
            nfail += 1
            print("FAIL:", label)
    print(f"{len(results) - nfail}/{len(results)} checks passed")
    return 1 if nfail else 0


if __name__ == "__main__":
    sys.exit(main())
