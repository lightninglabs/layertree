#!/usr/bin/env python3
"""End-to-end execution of the LayerTree scripts in the simulator."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import layertree_ref as lt  # noqa: E402
import layertree_scripts as ls  # noqa: E402
from script_sim import (Interp, ScriptError, TxContext, assemble, pubkey_x,  # noqa: E402
                        schnorr_sign)

FAILS = 0
CHECKS = 0


def check(cond, msg):
    global FAILS, CHECKS
    CHECKS += 1
    if not cond:
        FAILS += 1
        print("FAIL:", msg)


def expect_fail(fn, msg):
    try:
        fn()
    except ScriptError:
        check(True, msg)
        return
    check(False, f"expected failure: {msg}")


def sk(label):
    return lt.sha256(label.encode())


def sc_bytes(node):
    return node[0] + lt.le64(node[1])


def path_witness(path):
    """Witness items for a path, bottom..top: dir_{D-1} sc_{D-1} ... dir_0 sc_0."""
    items = []
    for d, sib in reversed(path):
        items.append(b"\x01" if d else b"")
        items.append(sc_bytes(sib))
    return items


class World:
    def __init__(self, depth, join_heights=(0, 2)):
        self.depth = depth
        self.op_sk = sk("operator")
        self.op_pk = pubkey_x(self.op_sk)
        self.scripts = ls.all_scripts(depth, self.op_pk, join_heights)
        self.compiled = {k: assemble(v) for k, v in self.scripts.items()}
        self.leaf_hashes = [lt.tapleaf_hash(s) for s in self.compiled.values()]
        self.m = lt.taptree_root(self.leaf_hashes)
        self.tree = lt.Tree(depth)

    def spk(self, root=None):
        root = root or self.tree.root()
        return lt.tree_spk(root[0], self.m)

    def run(self, name, witness, ctx, budget=None):
        it = Interp(ctx, budget)
        it.run(self.compiled[name], witness)
        return it

    def ctx(self, outputs, extra_in=None, locktime=0):
        root = self.tree.root()
        inputs = [(root[1], self.spk(root))]
        if extra_in:
            inputs.append(extra_in)
        return TxContext(inputs, outputs, locktime=locktime)


def mk_leaf(label, amount, evictor=None, evict_after=0, seq=0):
    return lt.Leaf(amount, pubkey_x(sk(label + "-exit")), pubkey_x(sk(label + "-owner")),
                   evictor if evictor else lt.NUMS_X, evict_after, seq)


def test_all(depth, verbose=True):
    w = World(depth)
    alice = mk_leaf("alice", 50_000)
    bob = mk_leaf("bob", 125_000, evictor=w.op_pk, evict_after=800_000)
    w.tree.leaves = {0: alice, 5: bob, (1 << depth) - 1: mk_leaf("operator", 1_000_000)}
    costs = {}

    # ---------------- EXIT (owner) ----------------
    root = w.tree.root()
    path = w.tree.path(5)
    new_tree = lt.Tree(depth); new_tree.leaves = {k: v for k, v in w.tree.leaves.items() if k != 5}
    new_root = new_tree.root()
    fee = 1_000
    outputs = [(new_root[1], w.spk(new_root)), (bob.amount - fee, lt.p2tr_spk(bob.exit_key)), (49_000, b"\x00\x14" + bytes(20))]
    ctx = w.ctx(outputs, extra_in=(50_000, b"\x00\x14" + bytes(20)))
    sig = schnorr_sign(ctx.sighash(), sk("bob-owner"))
    wit = path_witness(path) + [bob.serialize(), sig, b"", root[0], w.m]
    it = w.run("EXIT_1", wit, ctx)
    costs["EXIT_1 (owner)"] = (it, len(w.compiled["EXIT_1"]), sum(len(x) for x in wit))
    check(True, "exit owner ok")

    # negative: wrong m (attacker-controlled taptree) must fail
    expect_fail(lambda: w.run("EXIT_1", wit[:-1] + [lt.sha256(b"evil")], ctx), "wrong merkle root")
    # negative: overpay exit output
    bad = list(outputs); bad[1] = (bob.amount + 1, lt.p2tr_spk(bob.exit_key))
    ctx2 = w.ctx(bad, extra_in=(50_000, b"\x00\x14" + bytes(20)))
    sig2 = schnorr_sign(ctx2.sighash(), sk("bob-owner"))
    expect_fail(lambda: w.run("EXIT_1", path_witness(path) + [bob.serialize(), sig2, b"", root[0], w.m], ctx2), "exit output too large")
    # negative: tree output amount not reduced
    bad = list(outputs); bad[0] = (root[1], w.spk(new_root))
    ctx3 = w.ctx(bad, extra_in=(200_000, b"\x00\x14" + bytes(20)))
    sig3 = schnorr_sign(ctx3.sighash(), sk("bob-owner"))
    expect_fail(lambda: w.run("EXIT_1", path_witness(path) + [bob.serialize(), sig3, b"", root[0], w.m], ctx3), "tree amount not conserved")
    # negative: wrong signer
    sig4 = schnorr_sign(ctx.sighash(), sk("alice-owner"))
    expect_fail(lambda: w.run("EXIT_1", path_witness(path) + [bob.serialize(), sig4, b"", root[0], w.m], ctx), "wrong owner key")
    # negative: proof for a different leaf content
    fake = bob.with_amount_seq(bob.amount + 1, 0)
    expect_fail(lambda: w.run("EXIT_1", path_witness(path) + [fake.serialize(), sig, b"", root[0], w.m], ctx), "forged leaf amount")
    # negative: new tree spk built from wrong root
    bad = list(outputs); bad[0] = (new_root[1], w.spk(root))
    ctx5 = w.ctx(bad, extra_in=(50_000, b"\x00\x14" + bytes(20)))
    sig5 = schnorr_sign(ctx5.sighash(), sk("bob-owner"))
    expect_fail(lambda: w.run("EXIT_1", path_witness(path) + [bob.serialize(), sig5, b"", root[0], w.m], ctx5), "stale root in output")

    # ---------------- EXIT (evict) ----------------
    outputs_e = [(new_root[1], w.spk(new_root)), (bob.amount, lt.p2tr_spk(bob.exit_key))]
    ctx_e = w.ctx(outputs_e, extra_in=(5_000, b"\x00\x14" + bytes(20)), locktime=800_000)
    esig = schnorr_sign(ctx_e.sighash(), w.op_sk)
    wit_e = path_witness(path) + [bob.serialize(), esig, b"\x01", root[0], w.m]
    it = w.run("EXIT_1", wit_e, ctx_e)
    costs["EXIT_1 (evict)"] = (it, len(w.compiled["EXIT_1"]), sum(len(x) for x in wit_e))
    ctx_early = w.ctx(outputs_e, extra_in=(5_000, b"\x00\x14" + bytes(20)), locktime=799_999)
    esig2 = schnorr_sign(ctx_early.sighash(), w.op_sk)
    expect_fail(lambda: w.run("EXIT_1", path_witness(path) + [bob.serialize(), esig2, b"\x01", root[0], w.m], ctx_early), "evict before evict_after")
    outputs_e2 = [(new_root[1], w.spk(new_root)), (bob.amount - 1, lt.p2tr_spk(bob.exit_key))]
    ctx_e2 = w.ctx(outputs_e2, extra_in=(5_000, b"\x00\x14" + bytes(20)), locktime=800_000)
    esig3 = schnorr_sign(ctx_e2.sighash(), w.op_sk)
    expect_fail(lambda: w.run("EXIT_1", path_witness(path) + [bob.serialize(), esig3, b"\x01", root[0], w.m], ctx_e2), "evictor may not shortchange")
    # alice has NUMS evictor: eviction impossible
    apath = w.tree.path(0)
    t_a = lt.Tree(depth); t_a.leaves = {k: v for k, v in w.tree.leaves.items() if k != 0}
    outputs_a = [(t_a.root()[1], w.spk(t_a.root())), (alice.amount, lt.p2tr_spk(alice.exit_key))]
    ctx_a = w.ctx(outputs_a, extra_in=(5_000, b"\x00\x14" + bytes(20)))
    asig = schnorr_sign(ctx_a.sighash(), w.op_sk)
    expect_fail(lambda: w.run("EXIT_1", path_witness(apath) + [alice.serialize(), asig, b"\x01", root[0], w.m], ctx_a), "NUMS evictor")

    # commit the exit of bob
    w.tree = new_tree

    # ---------------- JOIN (height 2 subtree, 4 slots) ----------------
    root = w.tree.root()
    carol, dave = mk_leaf("carol", 30_000, w.op_pk, 900_000), mk_leaf("dave", 70_000, w.op_pk, 900_000)
    h, idx = 2, 2
    jpath = w.tree.path(idx << h, height=h)
    t2 = lt.Tree(depth); t2.leaves = dict(w.tree.leaves)
    lt.apply_join(t2, h, idx, {0: carol, 3: dave})
    new_node, r2 = t2.subtree(h, idx), t2.root()
    outputs = [(r2[1], w.spk(r2)), (900, b"\x00\x14" + bytes(20))]
    ctx = w.ctx(outputs, extra_in=(new_node[1] + 2_000, b"\x00\x14" + bytes(20)))
    osig = schnorr_sign(ctx.sighash(), w.op_sk)
    wit = path_witness(jpath) + [new_node[0], lt.le64(new_node[1]), osig, root[0], w.m]
    it = w.run("JOIN_2", wit, ctx)
    costs["JOIN_2"] = (it, len(w.compiled["JOIN_2"]), sum(len(x) for x in wit))
    # negative: joining over an occupied position (slot 0 region) fails
    jpath_bad = w.tree.path(0, height=h)
    expect_fail(lambda: w.run("JOIN_2", path_witness(jpath_bad) + [new_node[0], lt.le64(new_node[1]), osig, root[0], w.m], ctx), "join over occupied subtree")
    # negative: underfunded tree output
    bad = [(r2[1] - 1, w.spk(r2))]
    ctxb = w.ctx(bad, extra_in=(new_node[1] + 2_000, b"\x00\x14" + bytes(20)))
    osigb = schnorr_sign(ctxb.sighash(), w.op_sk)
    expect_fail(lambda: w.run("JOIN_2", path_witness(jpath) + [new_node[0], lt.le64(new_node[1]), osigb, root[0], w.m], ctxb), "join underfunded")
    # negative: not signed by operator
    usig = schnorr_sign(ctx.sighash(), sk("alice-owner"))
    expect_fail(lambda: w.run("JOIN_2", path_witness(jpath) + [new_node[0], lt.le64(new_node[1]), usig, root[0], w.m], ctx), "join without operator")
    w.tree = t2

    # single-leaf JOIN_0
    root = w.tree.root()
    erin = mk_leaf("erin", 12_345, w.op_pk, 900_000)
    slot = 9
    jpath0 = w.tree.path(slot)
    t3 = lt.Tree(depth); t3.leaves = dict(w.tree.leaves); t3.leaves[slot] = erin
    r3 = t3.root()
    ctx = w.ctx([(r3[1], w.spk(r3))], extra_in=(erin.amount + 500, b"\x00\x14" + bytes(20)))
    osig = schnorr_sign(ctx.sighash(), w.op_sk)
    wit = path_witness(jpath0) + [erin.hash(), lt.le64(erin.amount), osig, root[0], w.m]
    it = w.run("JOIN_0", wit, ctx)
    costs["JOIN_0"] = (it, len(w.compiled["JOIN_0"]), sum(len(x) for x in wit))
    w.tree = t3

    # ---------------- UPDATE (alice 50k -> 80k, seq 1) ----------------
    root = w.tree.root()
    upath = w.tree.path(0)
    alice2 = alice.with_amount_seq(80_000, 1)
    t4 = lt.Tree(depth); t4.leaves = dict(w.tree.leaves); t4.leaves[0] = alice2
    r4 = t4.root()
    ctx = w.ctx([(r4[1], w.spk(r4))], extra_in=(30_000 + 700, b"\x00\x14" + bytes(20)))
    osig = schnorr_sign(ctx.sighash(), w.op_sk)
    asig = schnorr_sign(ctx.sighash(), sk("alice-owner"))
    wit = path_witness(upath) + [alice.serialize(), alice2.serialize(), asig, osig, root[0], w.m]
    it = w.run("UPDATE", wit, ctx)
    costs["UPDATE"] = (it, len(w.compiled["UPDATE"]), sum(len(x) for x in wit))
    expect_fail(lambda: w.run("UPDATE", path_witness(upath) + [alice.serialize(), alice2.serialize(), osig, osig, root[0], w.m], ctx), "update without owner")
    w.tree = t4

    # ---------------- CLAIM (voucher from operator leaf to frank) ----------------
    root = w.tree.root()
    src_slot, claim_slot = (1 << depth) - 1, 3
    src = w.tree.leaves[src_slot]
    frank = mk_leaf("frank", 40_000, w.op_pk, 900_000)
    spath = w.tree.path(src_slot)
    t5 = lt.Tree(depth); t5.leaves = dict(w.tree.leaves)
    lt.apply_claim(t5, src_slot, claim_slot, frank)
    cpath = t5.path(claim_slot)
    r5 = t5.root()
    check(r5[1] == root[1], "claim conserves sum")
    ctx = w.ctx([(r5[1], w.spk(r5))], extra_in=(600, b"\x00\x14" + bytes(20)))
    vmsg = lt.voucher_msg(w.m, src, frank)
    vsig = schnorr_sign(vmsg, sk("operator-owner"))
    wit = path_witness(cpath) + path_witness(spath) + [src.serialize(), frank.serialize(), vsig, root[0], w.m]
    it = w.run("CLAIM", wit, ctx)
    costs["CLAIM"] = (it, len(w.compiled["CLAIM"]), sum(len(x) for x in wit))
    # negative: replay after the source leaf changed (seq/amount) fails
    t6 = lt.Tree(depth); t6.leaves = dict(t5.leaves)
    frank2 = mk_leaf("frank2", 40_000, w.op_pk, 900_000)
    spath2 = t5.path(src_slot)
    lt.apply_claim(t6, src_slot, 4, frank2)
    cpath2 = t6.path(4)
    ctx6 = TxContext([(r5[1], w.spk(r5)), (600, b"\x00\x14" + bytes(20))], [(t6.root()[1], w.spk(t6.root()))])
    expect_fail(lambda: w.run("CLAIM", path_witness(cpath2) + path_witness(spath2) + [src.serialize(), frank2.serialize(), vsig, r5[0], w.m], ctx6), "voucher replay / wrong leaf")
    # negative: over-claim
    greedy = mk_leaf("greedy", src.amount + 1, w.op_pk, 900_000)
    gsig = schnorr_sign(lt.voucher_msg(w.m, src, greedy), sk("operator-owner"))
    expect_fail(lambda: w.run("CLAIM", path_witness(cpath) + path_witness(spath) + [src.serialize(), greedy.serialize(), gsig, root[0], w.m], ctx), "over-claim underflow")
    # negative: voucher signed by the wrong owner
    bsig = schnorr_sign(vmsg, sk("bob-owner"))
    expect_fail(lambda: w.run("CLAIM", path_witness(cpath) + path_witness(spath) + [src.serialize(), frank.serialize(), bsig, root[0], w.m], ctx), "voucher wrong signer")

    if verbose:
        print(f"\nD={depth}  taptree leaves={len(w.compiled)}  m={w.m.hex()}")
        print(f"{'transition':18} {'script B':>9} {'witness B':>10} {'varops':>10} {'sigops':>6} {'maxdepth':>8}")
        for k, (it, sl, wl) in costs.items():
            print(f"{k:18} {sl:9} {wl:10} {it.cost:10} {it.sigchecks:6} {it.max_depth:8}")
    return costs, w


if __name__ == "__main__":
    for d in (4, 16):
        test_all(d)
    print(f"\n{CHECKS} checks, {FAILS} failures")
    sys.exit(1 if FAILS else 0)
