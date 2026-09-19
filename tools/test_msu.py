#!/usr/bin/env python3
"""Tests for the HYPOTHETICAL OP_MERKLESUMUPDATE measurement (issue #3 part 2).

Two layers:

* Opcode-level unit tests: proof round-trips against the reference tree
  (full-sibling and compressed), the empty-sibling compression, the
  guard (a default interpreter refuses the opcode), and the negatives
  (wrong position bit, wrong bitmap, empty sibling supplied explicitly,
  overflow, leftover bytes, depth bounds).
* Script-level tests for tools/layertree_msu.py: EXIT_1 (owner, evict,
  terminal) and JOIN_0 over dense D=4/16 and sparse D=8/32, with the
  negatives that matter for the measurement (stale root, forged leaf,
  payout above the leaf, payout above the tree total, missing operator
  signature, evict before the lease).

The measurement numbers land in design/native-opcodes.md; nothing here
is part of any tier, of the golden vectors, or of the spec.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import layertree_ref as lt  # noqa: E402
import layertree_msu as U  # noqa: E402
from script_sim import (Interp, ScriptError, TxContext, assemble, pubkey_x,  # noqa: E402
                        schnorr_sign)

FAILS = 0
CHECKS = 0
P2WPKH = b"\x00\x14" + bytes(20)


def check(cond, msg):
    global FAILS, CHECKS
    CHECKS += 1
    if not cond:
        FAILS += 1
        print("FAIL:", msg)


def expect_fail(fn, msg):
    global FAILS, CHECKS
    CHECKS += 1
    try:
        fn()
    except ScriptError:
        return
    FAILS += 1
    print(f"FAIL: expected failure: {msg}")


def sk(label):
    return lt.sha256(label.encode())


def mk_leaf(label, amount, evictor=None, evict_after=0, nonce=None, seq=0):
    if nonce is None:
        nonce = int.from_bytes(lt.sha256(label.encode())[:4], "little")
    return lt.Leaf(amount, pubkey_x(sk(label + "-exit")), pubkey_x(sk(label + "-owner")),
                   evictor if evictor else lt.NUMS_X, evict_after, nonce, seq)


def n40(node):
    return node[0] + node[1].to_bytes(8, "little")


def build_proof(tree, slot, depth, height=0):
    """The opcode's compressed proof for `slot` (height h subtree paths for
    JOIN_h): siblings only where the sibling node is not the empty node
    of its level."""
    path = tree.path(slot, height=height)
    pos_int = 0
    for k, (bit, sib) in enumerate(path):
        pos_int |= (bit & 1) << k
    bm_int = 0
    supplied = []
    for k, (bit, sib) in enumerate(path):
        if sib != lt.empty_node(height + k):
            bm_int |= 1 << k
            supplied.append((k, sib))
    supplied.sort(key=lambda ks: -ks[0])
    n = depth - height
    pw = bytes([n]) + pos_int.to_bytes((n + 7) // 8, "big") + bm_int.to_bytes((n + 7) // 8, "big")
    for k, sib in supplied:
        pw += sib[0] + sib[1].to_bytes(8, "little")
    return pw


# ------------------------------------------------------------- unit tests --

def test_opcode():
    ctx = TxContext([(1, P2WPKH)], [])
    tree = lt.Tree(4)
    a = mk_leaf("a", 10_000); b = mk_leaf("b", 20_000)
    tree.leaves = {0: a, 1: b}
    root = tree.root()
    t2 = lt.Tree(4); t2.leaves = {0: a}
    r2 = t2.root()
    # full-sibling proof for slot 1 (all four supplied)
    path = tree.path(1)
    pos_int = 0
    for k, (bit, sib) in enumerate(path):
        pos_int |= (bit & 1) << k
    bm_full = 0b1111
    sibs_deep_first = [path[3][1], path[2][1], path[1][1], path[0][1]]
    proof = bytes([4]) + pos_int.to_bytes(1, "big") + bm_full.to_bytes(1, "big")
    for s in sibs_deep_first:
        proof += s[0] + s[1].to_bytes(8, "little")
    script = assemble([proof, n40(b.node()), n40(lt.empty_node(0)),
                       "OP_MERKLESUMUPDATE", "OP_2DROP", "OP_1"])
    captured = {}
    orig = Interp.op_msu

    def spy(self, pop, pushv):
        stack = []

        def push_capture(v):
            stack.append(bytes(v))
        new_n = pop(); old_n = pop(); prf = pop()
        fake = [prf, old_n, new_n]

        def pop2():
            return fake.pop()
        orig(self, pop2, push_capture)
        captured["old"], captured["new"] = stack[0], stack[1]
        pushv(stack[0]); pushv(stack[1])
    Interp.op_msu = spy
    it = Interp(ctx, mode="c2", hypothetical=True)
    it.run(script, [])
    Interp.op_msu = orig
    check(captured["old"] == n40(root), "unit: full proof folds the true old root")
    check(captured["new"] == n40(r2), "unit: full proof folds the true new root")

    # compressed proof: supply only non-empty siblings (the sparse case)
    proof_c = build_proof(tree, 1, 4)
    it = Interp(ctx, mode="c2", hypothetical=True)
    it.run(assemble([proof_c, n40(b.node()), n40(lt.empty_node(0)),
                     "OP_MERKLESUMUPDATE", "OP_2DROP", "OP_1"]), [])
    check(True, "unit: compressed proof runs")

    # verification degeneracy: new == old
    it = Interp(ctx, mode="c2", hypothetical=True)
    it.run(assemble([proof_c, n40(b.node()), n40(b.node()),
                     "OP_MERKLESUMUPDATE", "OP_2DROP", "OP_1"]), [])
    check(True, "unit: new == old degenerates to verification")

    # the guard: a default interpreter refuses the opcode
    expect_fail(lambda: Interp(ctx, mode="c2").run(
        assemble([proof_c, n40(b.node()), n40(lt.empty_node(0)),
                  "OP_MERKLESUMUPDATE", "OP_2DROP", "OP_1"]), []),
        "guard: default interpreter refuses MSU")

    # wrong position bit: fold a leaf at the wrong slot -> wrong old root
    # (the script-level stale-root negative covers the observable failure;
    # here the unit check is that the fold DIFFERS)
    wrong_pos = bytes([4]) + (pos_int ^ 1).to_bytes(1, "big") + bm_full.to_bytes(1, "big")
    for s in sibs_deep_first:
        wrong_pos += s[0] + s[1].to_bytes(8, "little")
    captured.clear()
    Interp.op_msu = spy
    it = Interp(ctx, mode="c2", hypothetical=True)
    it.run(assemble([wrong_pos, n40(b.node()), n40(lt.empty_node(0)),
                     "OP_MERKLESUMUPDATE", "OP_2DROP", "OP_1"]), [])
    Interp.op_msu = orig
    check(captured["old"] != n40(root), "unit: wrong position bit folds a different root")

    # wrong bitmap (claims a sibling that is not supplied)
    bad_bm = bytes([4]) + pos_int.to_bytes(1, "big") + (0b0011).to_bytes(1, "big") + proof[-40:]
    expect_fail(lambda: Interp(ctx, mode="c2", hypothetical=True).run(
        assemble([bad_bm, n40(b.node()), n40(lt.empty_node(0)),
                  "OP_MERKLESUMUPDATE", "OP_2DROP", "OP_1"]), []),
        "unit: bitmap/sibling count mismatch")

    # empty sibling supplied explicitly (bitmap bit set, bytes are E_k):
    # allowed by the encoding; the fold is the same. Supplying garbage
    # bytes of the right length must change the root (stale-root covered
    # at the script level).
    # leftover bytes
    expect_fail(lambda: Interp(ctx, mode="c2", hypothetical=True).run(
        assemble([proof_c + b"junk", n40(b.node()), n40(lt.empty_node(0)),
                  "OP_MERKLESUMUPDATE", "OP_2DROP", "OP_1"]), []),
        "unit: leftover proof bytes")
    # depth bounds
    for d in (0, 65):
        bad = bytes([d]) + bytes(8) + bytes(8) + bytes(40)
        expect_fail(lambda d=d: Interp(ctx, mode="c2", hypothetical=True).run(
            assemble([bad, n40(b.node()), n40(lt.empty_node(0)),
                      "OP_MERKLESUMUPDATE", "OP_2DROP", "OP_1"]), []),
            f"unit: depth {d} rejected")
    # overflow: sums past 2^64 at level 0
    h = bytes(32)
    old_node = h + (2**64 - 1).to_bytes(8, "little")
    new_node = h + (2**64 - 1).to_bytes(8, "little")
    sib = h + (2).to_bytes(8, "little")
    ovf = bytes([1]) + (0).to_bytes(1, "big") + (1).to_bytes(1, "big") + sib
    expect_fail(lambda: Interp(ctx, mode="c2", hypothetical=True).run(
        assemble([ovf, old_node, new_node, "OP_MERKLESUMUPDATE", "OP_2DROP", "OP_1"]), []),
        "unit: sum overflow rejected")


# ----------------------------------------------------------- script tests --

class MsuWorld:
    def __init__(self, depth, profile, script="EXIT_1"):
        self.depth, self.profile = depth, profile == "S"
        self.op_sk = sk("operator"); self.op_pk = pubkey_x(self.op_sk)
        gen = U.exit_script_msu(depth) if script == "EXIT_1" else U.join_script_msu(depth, self.op_pk)
        self.name = script
        self.compiled = assemble(gen)
        self.m = lt.taptree_root([lt.tapleaf_hash(self.compiled)])
        self.tree = lt.Tree(depth)

    def slot(self, leaf, want=None):
        return leaf.position(self.depth) if self.profile else want

    def spk(self, root):
        return lt.tree_spk_ccv(root[0], self.m)

    def ctx(self, outputs, extra_in, locktime=0):
        root = self.tree.root()
        return TxContext([(root[1], self.spk(root)), extra_in], outputs, locktime=locktime,
                          internal_key=lt.ccv_internal_key(root[0]), taptree_root=self.m)

    def run(self, wit, ctx):
        it = Interp(ctx, mode="c2", hypothetical=True)
        it.run(self.compiled, wit)
        return it

    def clone(self):
        t = lt.Tree(self.depth); t.leaves = dict(self.tree.leaves); return t


def test_scripts(depth, profile):
    """EXIT_1 and JOIN_0 over one world; returns the measured sizes."""
    sizes = {}

    # ---------------- EXIT_1 ----------------
    w = MsuWorld(depth, profile, "EXIT_1")
    alice = mk_leaf("alice", 50_000)
    bob = mk_leaf("bob", 125_000, w.op_pk, 800_000)
    s_a, s_b = w.slot(alice, 0), w.slot(bob, 5)
    w.tree.leaves = {s_a: alice, s_b: bob}
    root = w.tree.root()
    t1 = w.clone(); del t1.leaves[s_b]
    r1 = t1.root()
    outputs = [(r1[1], w.spk(r1)), (bob.amount, lt.p2tr_spk(bob.exit_key)), (400, P2WPKH)]
    ctx = w.ctx(outputs, (5_000, P2WPKH))
    sig = schnorr_sign(ctx.sighash(), sk("bob-owner"))
    proof = build_proof(w.tree, s_b, depth)
    wit = [proof, bob.serialize(), sig, b""]
    it = w.run(wit, ctx)
    sizes["EXIT_1 (owner)"] = (len(w.compiled), sum(len(x) for x in wit), it.cost)

    # stale root: prove a leaf in a DIFFERENT tree than the input commits to
    other = w.clone(); del other.leaves[s_a]
    other_root = other.root()
    ctx_mis = TxContext([(other_root[1], w.spk(other_root)), (5_000, P2WPKH)], outputs,
                        internal_key=lt.ccv_internal_key(other_root[0]), taptree_root=w.m)
    sig_mis = schnorr_sign(ctx_mis.sighash(), sk("bob-owner"))
    expect_fail(lambda: w.run([proof, bob.serialize(), sig_mis, b""], ctx_mis),
                "exit: input commits to a different root")

    # forged leaf (payout above the leaf's amount, caught by the byte compare)
    fake = bob.with_amount_seq(bob.amount + 1, 0)
    ctx_f = TxContext([(root[1], w.spk(root)), (5_000, P2WPKH)],
                      [(r1[1] - 1, w.spk(r1)), (bob.amount + 1, lt.p2tr_spk(bob.exit_key))],
                      internal_key=lt.ccv_internal_key(root[0]), taptree_root=w.m)
    sig_f = schnorr_sign(ctx_f.sighash(), sk("bob-owner"))
    expect_fail(lambda: w.run([proof, fake.serialize(), sig_f, b""], ctx_f),
                "exit: forged leaf amount")

    # payout above the leaf but below the tree total: the exact byte compare
    bad = list(outputs); bad[1] = (bob.amount + 1, lt.p2tr_spk(bob.exit_key))
    ctx_b = w.ctx(bad, (5_001, P2WPKH))
    sig_b = schnorr_sign(ctx_b.sighash(), sk("bob-owner"))
    expect_fail(lambda: w.run([proof, bob.serialize(), sig_b, b""], ctx_b),
                "exit: payout above the leaf")

    # payout above the tree total: the CCV residual check
    bad = list(outputs); bad[1] = (root[1] + 1, lt.p2tr_spk(bob.exit_key))
    ctx_t = w.ctx(bad, (5_000, P2WPKH))
    sig_t = schnorr_sign(ctx_t.sighash(), sk("bob-owner"))
    expect_fail(lambda: w.run([proof, bob.serialize(), sig_t, b""], ctx_t),
                "exit: payout above the tree total")

    # wrong owner key
    sig_w = schnorr_sign(ctx.sighash(), sk("alice-owner"))
    expect_fail(lambda: w.run([proof, bob.serialize(), sig_w, b""], ctx),
                "exit: wrong owner key")

    # evict
    ctx_e = w.ctx([(r1[1], w.spk(r1)), (bob.amount, lt.p2tr_spk(bob.exit_key))],
                  (5_000, P2WPKH), locktime=900_000)
    esig = schnorr_sign(ctx_e.sighash(), w.op_sk)
    it = w.run([proof, bob.serialize(), esig, b"\x01"], ctx_e)
    sizes["EXIT_1 (evict)"] = (len(w.compiled),
                               len(proof) + 116 + 64 + 1, it.cost)
    # evict before the lease
    ctx_early = w.ctx([(r1[1], w.spk(r1)), (bob.amount, lt.p2tr_spk(bob.exit_key))],
                      (5_000, P2WPKH), locktime=799_999)
    esig2 = schnorr_sign(ctx_early.sighash(), w.op_sk)
    expect_fail(lambda: w.run([proof, bob.serialize(), esig2, b"\x01"], ctx_early),
                "exit: evict before the lease")
    # owner key may not evict
    sig_o = schnorr_sign(ctx_e.sighash(), sk("bob-owner"))
    expect_fail(lambda: w.run([proof, bob.serialize(), sig_o, b"\x01"], ctx_e),
                "exit: owner key may not evict")

    # terminal exit (a solo tree drains to E_D)
    solo = mk_leaf("solo", 77_000)
    main_tree = w.clone()
    w.tree = lt.Tree(depth); w.tree.leaves = {w.slot(solo, 2): solo}
    root_s = w.tree.root()
    t_s = lt.Tree(depth)
    r_s = t_s.root()   # empty tree: the terminal state
    proof_s = build_proof(w.tree, w.slot(solo, 2), depth)
    outputs_s = [(600, P2WPKH), (solo.amount, lt.p2tr_spk(solo.exit_key))]
    ctx_s = w.ctx(outputs_s, (1_000, P2WPKH))
    ssig = schnorr_sign(ctx_s.sighash(), sk("solo-owner"))
    it = w.run([proof_s, solo.serialize(), ssig, b""], ctx_s)
    sizes["EXIT_1 (terminal)"] = (len(w.compiled),
                                  len(proof_s) + 116 + 64, it.cost)
    w.tree = main_tree

    # ---------------- JOIN_0 ----------------
    wj = MsuWorld(depth, profile, "JOIN_0")
    wj.tree.leaves = {wj.slot(alice, 0): alice}
    root_j = wj.tree.root()
    carol = mk_leaf("carol", 60_000)
    slot_c = wj.slot(carol, 5)
    if slot_c in wj.tree.leaves:
        slot_c = (slot_c + 1) % (1 << depth)
    t3 = wj.clone(); t3.leaves[slot_c] = carol
    r3 = t3.root()
    proof_j = build_proof(wj.tree, slot_c, depth)
    outputs_j = [(r3[1], wj.spk(r3)), (900, P2WPKH)]
    ctx_j = wj.ctx(outputs_j, (carol.amount + 2_000, P2WPKH))
    osig = schnorr_sign(ctx_j.sighash(), wj.op_sk)
    wj.compiled = assemble(U.join_script_msu(depth, wj.op_pk))
    wj.m = lt.taptree_root([lt.tapleaf_hash(wj.compiled)])
    # rebuild ctx with the join's own m (the two scripts differ)
    ctx_j = TxContext([(root_j[1], wj.spk(root_j)), (carol.amount + 2_000, P2WPKH)],
                      outputs_j, internal_key=lt.ccv_internal_key(root_j[0]), taptree_root=wj.m)
    osig = schnorr_sign(ctx_j.sighash(), wj.op_sk)
    it = wj.run([proof_j, carol.serialize(), osig], ctx_j)
    sizes["JOIN_0"] = (len(wj.compiled), len(proof_j) + 116 + 64, it.cost)
    # join without the operator
    usig = schnorr_sign(ctx_j.sighash(), sk("carol-owner"))
    expect_fail(lambda: wj.run([proof_j, carol.serialize(), usig], ctx_j),
                "join: without the operator signature")
    # join at an occupied position: carol's proof folds old node E_0 over a
    # slot that is actually occupied; the old root then mismatches.
    dup = mk_leaf("dup", 1_000)
    slot_dup = slot_c
    wj.tree.leaves[slot_dup] = dup   # occupied now
    root_o = wj.tree.root()
    ctx_o = TxContext([(root_o[1], wj.spk(root_o)), (carol.amount + 2_000, P2WPKH)],
                      outputs_j, internal_key=lt.ccv_internal_key(root_o[0]), taptree_root=wj.m)
    osig_o = schnorr_sign(ctx_o.sighash(), wj.op_sk)
    expect_fail(lambda: wj.run([proof_j, carol.serialize(), osig_o], ctx_o),
                "join: over an occupied position")
    return sizes


def main():
    global FAILS, CHECKS
    print("OP_MERKLESUMUPDATE (HYPOTHETICAL measurement; never a tier)")
    test_opcode()
    print(f"  opcode units: {CHECKS} checks so far")
    all_sizes = {}
    for depth, profile in ((4, "D"), (16, "D"), (8, "S"), (32, "S")):
        before = CHECKS
        sizes = test_scripts(depth, profile)
        all_sizes[(profile, depth)] = sizes
        print(f"  {profile}/{depth}: {CHECKS - before} checks")
    print("\nMeasured (script / witness bytes, varops):")
    for (profile, depth), sizes in all_sizes.items():
        for k, (sl, wl, cost) in sizes.items():
            print(f"  {profile}/{depth:2} {k:20} {sl:5} {wl:5} {cost}")
    print(f"\n{CHECKS} checks, {FAILS} failures")
    return 1 if FAILS else 0


if __name__ == "__main__":
    sys.exit(main())
