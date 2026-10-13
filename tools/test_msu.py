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
* The pending-leaf receive (spec 0.14.0) under CCV + MSU: CLAIM^m and
  CLAIM^hm, RECLAIM_1, the reclaim form of REWRITE_h^x at h = 1, 2, 4, 6
  and the landing leaf's EXIT_1, with the negatives of the FULL tier's
  test_merge, test_reclaim and test_pending_rewrite, and the
  whole-transaction vbytes at N = 2^16, 2^20 and 2^32 members.

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


def build_proof(tree, slot, depth, height=0, level_empties=False):
    """The opcode's canonical compressed proof for the node at `height` over
    `slot`: a sibling is omitted only where it equals the opcode's own
    empty node for that proof level, E_k with k counted from the start of
    the proof. The opcode's chain starts at E_0 whatever height the
    folded node has (tools/script_sim.py op_msu), so a height-h proof
    (h >= 1) must supply its empty siblings, E_{h+k}, explicitly; only a
    start-height field in the proof would let them compress
    (design/native-opcodes.md, the pending-leaf receive). level_empties=True
    omits E_{h+k} instead, the encoding such a field would allow, which the
    opcode as specified folds to the wrong root (a negative below)."""
    path = tree.path(slot, height=height)
    pos_int = 0
    for k, (bit, sib) in enumerate(path):
        pos_int |= (bit & 1) << k
    bm_int = 0
    supplied = []
    for k, (bit, sib) in enumerate(path):
        if sib != lt.empty_node(height + k if level_empties else k):
            bm_int |= 1 << k
            supplied.append((k, sib))
    supplied.sort(key=lambda ks: ks[0])     # deepest level (k = 0) first
    n = depth - height
    pw = bytes([n]) + pos_int.to_bytes((n + 7) // 8, "big") + bm_int.to_bytes((n + 7) // 8, "big")
    for k, sib in supplied:
        pw += sib[0] + sib[1].to_bytes(8, "little")
    return pw


# ------------------------------------------------------------- unit tests --

def test_opcode():
    ctx = TxContext([(1, P2WPKH)], [])
    a = mk_leaf("a", 10_000); b = mk_leaf("b", 20_000)
    # a tree in which every sibling on slot 1's path is non-empty, so the
    # canonical proof supplies all four
    others = {2: mk_leaf("c", 1_000), 4: mk_leaf("d", 2_000), 8: mk_leaf("e", 3_000)}
    tree = lt.Tree(4)
    tree.leaves = {0: a, 1: b, **others}
    root = tree.root()
    t2 = lt.Tree(4); t2.leaves = {0: a, **others}
    r2 = t2.root()
    path = tree.path(1)
    check(all(sib != lt.empty_node(k) for k, (_, sib) in enumerate(path)),
          "unit: fixture has no empty sibling on the path")
    pos_int = 0
    for k, (bit, sib) in enumerate(path):
        pos_int |= (bit & 1) << k
    bm_full = 0b1111
    sibs_deep_first = [path[0][1], path[1][1], path[2][1], path[3][1]]   # level 0 first
    check(build_proof(tree, 1, 4) == bytes([4]) + pos_int.to_bytes(1, "big") + bm_full.to_bytes(1, "big") +
          b"".join(n40(x) for x in sibs_deep_first),
          "unit: build_proof emits siblings deepest level first")
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

    # compressed proof: supply only non-empty siblings (the sparse case),
    # on a tree where three of the four siblings are empty
    small = lt.Tree(4); small.leaves = {0: a, 1: b}
    proof_c = build_proof(small, 1, 4)
    check(len(proof_c) == 3 + 40, "unit: compressed proof carries one sibling")
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
    # rejected, so the encoding is canonical and a relay cannot inflate a
    # spender's witness by un-compressing its proof.
    spath = small.path(1)
    uncompressed = bytes([4]) + pos_int.to_bytes(1, "big") + bm_full.to_bytes(1, "big") + \
        b"".join(n40(sib) for _, sib in spath)
    expect_fail(lambda: Interp(ctx, mode="c2", hypothetical=True).run(
        assemble([uncompressed, n40(b.node()), n40(lt.empty_node(0)),
                  "OP_MERKLESUMUPDATE", "OP_2DROP", "OP_1"]), []),
        "unit: empty sibling supplied explicitly")
    # bitmap or position bits above the depth: rejected (canonical)
    for bad in (bytes([4]) + bytes([pos_int | 0x10]) + proof_c[2:],
                bytes([4]) + proof_c[1:2] + bytes([proof_c[2] | 0x80]) + proof_c[3:]):
        expect_fail(lambda bad=bad: Interp(ctx, mode="c2", hypothetical=True).run(
            assemble([bad, n40(b.node()), n40(lt.empty_node(0)),
                      "OP_MERKLESUMUPDATE", "OP_2DROP", "OP_1"]), []),
            "unit: position or bitmap bit above the depth")
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


# ------------------------------------------------ the pending-leaf receive --
# Spec 0.14.0 (7.5.4, 7.9 rule 8, 7.11; design/pending-receive.md) under
# CCV + MSU: CLAIM^m and CLAIM^hm, RECLAIM_1, the reclaim form of
# REWRITE_h^x at h = 1, 2, 4, 6, and the landing leaf's EXIT_1, all in one
# taptree. The positives and negatives mirror tools/test_scripts.py's
# test_merge, test_reclaim and test_pending_rewrite.

RECLAIM_SK = sk("operator-reclaim")
PENDING_TREE_ID = lt.sha256(b"msu-pending-tree")
REWRITE_HEIGHTS = (1, 2, 4, 6)


def _nonce(label):
    return int.from_bytes(lt.sha256(label.encode())[:4], "little")


class PendingMsu:
    """A dense tree carrying the pending-leaf receive under CCV + MSU."""

    def __init__(self, depth, heights=REWRITE_HEIGHTS):
        self.depth = depth
        self.rk = pubkey_x(RECLAIM_SK)
        self.op_sk = sk("operator")
        self.op_pk = pubkey_x(self.op_sk)
        gens = {"EXIT_1": U.exit_script_msu(depth),
                "RECLAIM_1": U.reclaim_script_msu(depth, self.rk),
                "CLAIM_M": U.merge_script_msu(depth, PENDING_TREE_ID, False, self.rk),
                "CLAIM_HM": U.merge_script_msu(depth, PENDING_TREE_ID, True, self.rk)}
        for h in heights:
            gens[f"REWRITE_XR_{h}"] = U.rewrite_script_msu(depth, h, self.op_pk, True, self.rk)
        self.gens = gens
        self.compiled = {n: assemble(g) for n, g in gens.items()}
        self.m = lt.taptree_root([lt.tapleaf_hash(c) for c in self.compiled.values()])
        self.tree = lt.Tree(depth)

    def spk(self, root):
        return lt.tree_spk_ccv(root[0], self.m)

    def ctx(self, outputs, extra_in=(600, P2WPKH), locktime=0, root=None):
        root = root or self.tree.root()
        return TxContext([(root[1], self.spk(root)), extra_in], outputs, locktime=locktime,
                         internal_key=lt.ccv_internal_key(root[0]), taptree_root=self.m)

    def run(self, name, wit, ctx):
        ctx.ccv_reset()
        it = Interp(ctx, mode="c2", hypothetical=True)
        it.run(self.compiled[name], wit)
        return it

    def clone(self):
        t = lt.Tree(self.depth)
        t.leaves = dict(self.tree.leaves)
        return t

    def pending(self, amount, deadline, label="P", rcpt="rcpt", seq=0):
        """P: owned by the operator, paid to the recipient, reclaimable."""
        return lt.Leaf(amount, pubkey_x(sk(rcpt + "-exit")), pubkey_x(sk("operator-owner")),
                       self.rk, deadline, _nonce(label), seq)

    def landing(self, amount, label="L", rcpt="rcpt", lease=900_000, owner=None, evictor=None, seq=0):
        """L: owned and exited by the recipient, evictable after a long lease."""
        ek = pubkey_x(sk(rcpt + "-exit"))
        return lt.Leaf(amount, ek, owner or ek, evictor or self.op_pk, lease, _nonce(label), seq)

    def landing_other_exit(self, amount, rcpt="rcpt"):
        """A leaf owned by the recipient's exit key whose own exit key is
        someone else's: not a valid merge or R3 target (7.5.4 rule 2, 7.9
        rule 8)."""
        return lt.Leaf(amount, pubkey_x(sk("stranger-exit")), pubkey_x(sk(rcpt + "-exit")),
                       self.op_pk, 900_000, _nonce("Lx"), 0)

    def fillers(self):
        """Members outside the pairs under test, so that some siblings above
        the pair or cohort are occupied."""
        return {0: mk_leaf("alice", 50_000), 9: mk_leaf("carol", 40_000),
                (1 << self.depth) - 3: mk_leaf("dave", 30_000)}


def _merge_case(pw, p_slot, l_slot, P, L, X, preimage=None, signer="operator-owner", flag=None,
                msg_target=None, msg_x=None, out0_delta=0):
    pw.tree.leaves = {p_slot: P, l_slot: L, **pw.fillers()}
    t1 = pw.clone()
    d = X - L.amount
    t1.leaves[l_slot] = L.with_amount_seq(max(X, 0), L.seq)
    if P.amount - d > 0:
        t1.leaves[p_slot] = P.with_amount_seq(P.amount - d, P.seq)
    else:
        t1.leaves.pop(p_slot, None)
    r1 = t1.root()
    ctx = pw.ctx([(r1[1] + out0_delta, pw.spk(r1))])
    ph = lt.sha256(preimage) if preimage is not None else None
    msg = lt.voucher_m_msg(PENDING_TREE_ID, P, msg_target or L, msg_x if msg_x is not None else X, ph)
    vsig = schnorr_sign(msg, sk(signer))
    left, right = (P, L) if p_slot % 2 == 0 else (L, P)
    f = flag if flag is not None else (b"\x01" if p_slot % 2 == 0 else b"")
    proof = build_proof(pw.tree, min(p_slot, l_slot), pw.depth, height=1)
    wit = [proof, left.serialize(), right.serialize(), f, lt.le64(X), vsig]
    if preimage is not None:
        wit.append(preimage)
    return wit, ctx, t1


def test_merge_msu(pw):
    """CLAIM^m and CLAIM^hm under CCV + MSU; returns the measured sizes."""
    pre = lt.sha256(b"receive-preimage")
    P = pw.pending(20_000, 700_000)
    L = pw.landing(10_000)
    wit, ctx, t1 = _merge_case(pw, 2, 3, P, L, 13_000, pre)
    it = pw.run("CLAIM_HM", wit, ctx)
    check(t1.leaves[3].amount == 13_000 and t1.leaves[2].amount == 17_000,
          "msu CLAIM^hm: target raised to X, source lowered by the difference")
    sizes = {"CLAIM_HM": (len(pw.compiled["CLAIM_HM"]), wit, it.cost)}
    pw.run("CLAIM_HM", *_merge_case(pw, 5, 4, P, L, 13_000, pre)[:2])
    check(True, "msu CLAIM^hm with the source on the right of the pair")
    wit_m, ctx_m, _ = _merge_case(pw, 2, 3, P, L, 12_500)
    it_m = pw.run("CLAIM_M", wit_m, ctx_m)
    sizes["CLAIM_M"] = (len(pw.compiled["CLAIM_M"]), wit_m, it_m.cost)
    _, _, t_d = _merge_case(pw, 2, 3, P, L, 30_000)
    pw.run("CLAIM_M", *_merge_case(pw, 2, 3, P, L, 30_000)[:2])
    check(2 not in t_d.leaves, "msu CLAIM^m draining the source leaves E_0")
    # replay and ordering: target levels are absolute
    raised, lowered = L.with_amount_seq(13_000, L.seq), P.with_amount_seq(17_000, P.seq)
    expect_fail(lambda: pw.run("CLAIM_HM", *_merge_case(pw, 2, 3, lowered, raised, 13_000, pre)[:2]),
                "msu CLAIM^hm replayed after the target reached X")
    pw.run("CLAIM_HM", *_merge_case(pw, 2, 3, P.with_amount_seq(19_000, 0),
                                    L.with_amount_seq(11_000, 0), 13_000, pre)[:2])
    check(True, "msu CLAIM^hm newer target after an older one moves only the difference")
    # the DUST_MIN headroom survives any top-up
    roomy = pw.pending(3_000 + lt.DUST_MIN, 700_000)
    for extra in (0, 1, 50_000):
        pw.run("CLAIM_HM", *_merge_case(pw, 2, 3, roomy.with_amount_seq(roomy.amount + extra, 0),
                                        L, 13_000, pre)[:2])
    check(True, "msu CLAIM^hm with DUST_MIN of headroom redeems after any top-up")

    # negatives, one per rule
    expect_fail(lambda: pw.run("CLAIM_HM", wit[:-1] + [lt.sha256(b"x")], ctx),
                "msu CLAIM^hm wrong preimage")
    expect_fail(lambda: pw.run("CLAIM_HM", wit[:-1] + [pre[:31]], ctx),
                "msu CLAIM^hm preimage not 32 bytes")
    expect_fail(lambda: pw.run("CLAIM_HM", *_merge_case(pw, 2, 3, P, L, 13_000, pre, signer="rcpt-exit")[:2]),
                "msu CLAIM^hm voucher not by the source owner")
    plain = _merge_case(pw, 2, 3, P, L, 13_000)[0]
    expect_fail(lambda: pw.run("CLAIM_HM", plain + [pre], ctx),
                "msu CLAIM^hm with a plain merge voucher")
    expect_fail(lambda: pw.run("CLAIM_M", wit[:-1], ctx),
                "msu CLAIM^m with a hash-locked merge voucher")
    stranger = pw.landing(10_000, owner=pubkey_x(sk("operator-owner")))
    expect_fail(lambda: pw.run("CLAIM_M", *_merge_case(pw, 2, 3, P, stranger, 13_000)[:2]),
                "msu CLAIM^m into a sibling the source's exit key does not own")
    other_exit = pw.landing_other_exit(10_000)
    expect_fail(lambda: pw.run("CLAIM_M", *_merge_case(pw, 2, 3, P, other_exit, 13_000)[:2]),
                "msu CLAIM^m into a sibling owned by the exit key but with another exit key")
    flagged = pw.landing(10_000, evictor=pw.rk)
    expect_fail(lambda: pw.run("CLAIM_M", *_merge_case(pw, 2, 3, P, flagged, 13_000)[:2]),
                "msu CLAIM^m into a reclaimable target")
    final_t = pw.landing(10_000, seq=0xFFFFFFFF)
    expect_fail(lambda: pw.run("CLAIM_M", *_merge_case(pw, 2, 3, P, final_t, 13_000)[:2]),
                "msu CLAIM^m into a SEQ_FINAL target")
    expect_fail(lambda: pw.run("CLAIM_M", *_merge_case(pw, 2, 3, P, L, 10_000)[:2]),
                "msu CLAIM^m with X not above the target's amount")
    expect_fail(lambda: pw.run("CLAIM_M", *_merge_case(pw, 2, 3, P, L, 30_001)[:2]),
                "msu CLAIM^m drawing more than the source holds")
    expect_fail(lambda: pw.run("CLAIM_M", *_merge_case(pw, 2, 3, P, L, 29_800)[:2]),
                "msu CLAIM^m leaving a sub-dust residual")
    expect_fail(lambda: pw.run("CLAIM_M", *_merge_case(pw, 2, 3, P, L, 13_000, flag=b"")[:2]),
                "msu CLAIM^m with the source flag pointing at the target")
    expect_fail(lambda: pw.run("CLAIM_M", *_merge_case(pw, 2, 3, P, L, 13_000, msg_x=14_000)[:2]),
                "msu CLAIM^m with X other than the signed target")
    expect_fail(lambda: pw.run("CLAIM_M", *_merge_case(pw, 2, 3, P, L, 13_000, out0_delta=-1)[:2]),
                "msu CLAIM^m with output 0 short")
    expect_fail(lambda: pw.run("CLAIM_M", *_merge_case(pw, 2, 3, P, L, 13_000, out0_delta=1)[:2]),
                "msu CLAIM^m with output 0 long")
    # stale root: the proof is for a tree the input does not commit to
    w_st, _, t_st = _merge_case(pw, 2, 3, P, L, 13_000)
    other = pw.clone()
    del other.leaves[9]
    r_st = t_st.root()
    expect_fail(lambda: pw.run("CLAIM_M", w_st, pw.ctx([(r_st[1], pw.spk(r_st))], root=other.root())),
                "msu CLAIM^m against a different committed root")
    # the opcode's empty chain starts at E_0: a height-1 proof that omits its
    # empty siblings E_{1+k} folds to the wrong root, so the pair's proof
    # supplies them (the start-height note in design/native-opcodes.md)
    w_lv, ctx_lv, _ = _merge_case(pw, 2, 3, P, L, 13_000)
    w_lv[0] = build_proof(pw.tree, 2, pw.depth, height=1, level_empties=True)
    check(len(w_lv[0]) < len(wit[0]), "msu height-1 proof: omitting E_{1+k} would shorten it")
    expect_fail(lambda: pw.run("CLAIM_M", w_lv, ctx_lv),
                "msu height-1 proof omitting E_{1+k}: the opcode folds E_k instead")
    return sizes


def _reclaim_case(pw, leaf, slot, locktime=700_000, signer=RECLAIM_SK, out0_delta=0, solo=False):
    pw.tree.leaves = {slot: leaf} if solo else {2: pw.pending(20_000, 700_000), 3: pw.landing(10_000),
                                                 **pw.fillers()}
    pw.tree.leaves[slot] = leaf
    t1 = pw.clone()
    del t1.leaves[slot]
    r1 = t1.root()
    outs = [(5_000, P2WPKH)] if solo else [(r1[1] + out0_delta, pw.spk(r1)), (leaf.amount, P2WPKH)]
    ctx = pw.ctx(outs, locktime=locktime)
    sig = schnorr_sign(ctx.sighash(), signer)
    return [build_proof(pw.tree, slot, pw.depth), leaf.serialize(), sig], ctx


def test_reclaim_msu(pw):
    """RECLAIM_1 under CCV + MSU: no payout, output 0 the residual."""
    P = pw.pending(20_000, 700_000)
    wit, ctx = _reclaim_case(pw, P, 2)
    it = pw.run("RECLAIM_1", wit, ctx)
    check(True, "msu RECLAIM_1 after the deadline, value free for the transaction")
    sizes = {"RECLAIM_1": (len(pw.compiled["RECLAIM_1"]), wit, it.cost)}
    pw.run("RECLAIM_1", *_reclaim_case(pw, P, 2, solo=True))
    check(True, "msu RECLAIM_1 of the last leaf is terminal")
    expect_fail(lambda: pw.run("RECLAIM_1", *_reclaim_case(pw, P, 2, locktime=699_999)),
                "msu RECLAIM_1 before the deadline")
    expect_fail(lambda: pw.run("RECLAIM_1", *_reclaim_case(pw, P, 2, signer=pw.op_sk)),
                "msu RECLAIM_1 signed by OPERATOR_KEY, not RECLAIM_KEY")
    expect_fail(lambda: pw.run("RECLAIM_1", *_reclaim_case(pw, P, 2, out0_delta=-1)),
                "msu RECLAIM_1 with output 0 short")
    expect_fail(lambda: pw.run("RECLAIM_1", *_reclaim_case(pw, P, 2, out0_delta=1)),
                "msu RECLAIM_1 with output 0 long")
    plain = mk_leaf("bob", 20_000, pw.op_pk, 600_000)
    expect_fail(lambda: pw.run("RECLAIM_1", *_reclaim_case(pw, plain, 6)),
                "msu RECLAIM_1 of a leaf whose evictor is not RECLAIM_KEY")
    expect_fail(lambda: pw.run("RECLAIM_1", *_reclaim_case(pw, pw.landing(10_000), 3, locktime=900_000)),
                "msu RECLAIM_1 of the landing leaf")
    return sizes


def _rewrite_case(pw, h, base, old, new, locktime=0, sign=(), payouts=(), flag=None, out0_delta=0):
    """A REWRITE_XR_h over positions base..base+2^h-1 under CCV + MSU.
    `sign` lists offsets that carry the owner's and the exit key's
    signatures (labels from the leaf's recipient), `payouts` the outputs
    1.. the rewrite's exits pay."""
    n = 1 << h
    leaves = {base + i: lf for i, lf in old.items() if lf}
    leaves.update(pw.fillers())
    pw.tree.leaves = leaves
    root = pw.tree.root()
    t1 = pw.clone()
    for i in range(n):
        if new.get(i):
            t1.leaves[base + i] = new[i]
        else:
            t1.leaves.pop(base + i, None)
    r1 = t1.root()
    paid = sum(a for a, _ in payouts)
    freed = root[1] - r1[1] - paid
    outputs = [(r1[1] + out0_delta, pw.spk(r1))] + list(payouts) + [(max(freed, 0) + 1_000, P2WPKH)]
    ctx = TxContext([(root[1], pw.spk(root)), (5_000 + max(-freed, 0), P2WPKH)], outputs, locktime=locktime,
                    internal_key=lt.ccv_internal_key(root[0]), taptree_root=pw.m)
    sig_op = schnorr_sign(ctx.sighash(), pw.op_sk)
    blocks = []
    for i in reversed(range(n)):
        o, nw = old.get(i), new.get(i)
        if i in sign:
            blocks.append(schnorr_sign(ctx.sighash(), sign[i][1]))   # xsig by the exit key
            blocks.append(schnorr_sign(ctx.sighash(), sign[i][0]))   # sig by the owner
        if o is not None and nw is not None and o.serialize() == nw.serialize():
            blocks.append(REWRITE_SAME)
        else:
            blocks.append(nw.serialize() if nw else b"")
        blocks.append(o.serialize() if o else b"")
    if flag is None:
        flag = b"\x01" if freed > 0 else b""
    wit = [flag, build_proof(pw.tree, base, pw.depth, height=h)] + blocks + [sig_op]
    return wit, ctx


REWRITE_SAME = b"\x01"


def _cohort(pw, h, T, label=""):
    """Every pair of a height-h cohort active: P_i at 2i, L_i at 2i+1, one
    recipient per pair."""
    old = {}
    for i in range(1 << (h - 1)):
        r = f"rcpt{label}{i}"
        old[2 * i] = pw.pending(20_000 + i, T, label=f"P{label}{i}", rcpt=r)
        old[2 * i + 1] = pw.landing(10_000 + i, label=f"L{label}{i}", rcpt=r)
    return old


def test_rewrite_msu(pw):
    """The reclaim form of REWRITE_h^x under CCV + MSU: positives and the
    negatives of test_pending_rewrite at h = 1, then a window settlement
    (every pair transfers, then every pair rolls) at every measured
    height. Returns the measured sizes per height."""
    T = 700_000
    P, L = pw.pending(20_000, T), pw.landing(10_000)
    name = "REWRITE_XR_1"
    run = lambda *a, **kw: pw.run(name, *_rewrite_case(pw, 1, 2, *a, **kw))   # noqa: E731
    run({0: P, 1: L}, {0: P.with_amount_seq(13_000, 0), 1: L.with_amount_seq(17_000, 0)})
    check(True, "msu R3 transfer P -> L, operator only, before the deadline")
    expect_fail(lambda: run({0: P, 1: L}, {0: P.with_amount_seq(13_000, 0), 1: L.with_amount_seq(16_999, 0)}),
                "msu R3 unbalanced: the landing leaf raised by less than the transfer")
    expect_fail(lambda: run({0: P, 1: L}, {0: P.with_amount_seq(13_000, 0), 1: L.with_amount_seq(17_001, 0)}),
                "msu R3 unbalanced: the landing leaf raised by more than the transfer")
    expect_fail(lambda: run({0: P, 1: L}, {0: P.with_amount_seq(13_000, 0), 1: L}),
                "msu R3 with the landing leaf unchanged")
    other = pw.landing(10_000, owner=pubkey_x(sk("operator-owner")))
    expect_fail(lambda: run({0: P, 1: other}, {0: P.with_amount_seq(13_000, 0), 1: other.with_amount_seq(17_000, 0)}),
                "msu R3 into a sibling the pending leaf's exit key does not own")
    ox = pw.landing_other_exit(10_000)
    expect_fail(lambda: run({0: P, 1: ox}, {0: P.with_amount_seq(13_000, 0), 1: ox.with_amount_seq(17_000, 0)}),
                "msu R3 into a sibling owned by the exit key but with another exit key")
    flagged = pw.landing(10_000, evictor=pw.rk)
    expect_fail(lambda: run({0: P, 1: flagged}, {0: P.with_amount_seq(13_000, 0), 1: flagged.with_amount_seq(17_000, 0)}),
                "msu R3 into a reclaimable sibling")
    # R1: reclaim after the deadline, emptied with no payout (deduct), or rolled
    run({0: P, 1: L}, {0: None, 1: L}, locktime=T)
    check(True, "msu R1 reclaim after the deadline, no payout")
    expect_fail(lambda: run({0: P, 1: L}, {0: None, 1: L}, locktime=T, flag=b""),
                "msu R1 reclaim with output 0 in the assign mode")
    expect_fail(lambda: run({0: P, 1: L}, {0: None, 1: L}, locktime=T, flag=b"\x02"),
                "msu rewrite with a non-minimal mode flag")
    expect_fail(lambda: run({0: P, 1: L}, {0: None, 1: L}, locktime=T, out0_delta=-1),
                "msu R1 reclaim with output 0 short")
    P2 = pw.pending(25_000, T + 1_008, label="P2")
    run({0: P, 1: L}, {0: P2, 1: L}, locktime=T)
    check(True, "msu R1 roll: the expired pending leaf replaced by the next window's")
    expect_fail(lambda: run({0: P, 1: L}, {0: P2, 1: L}, locktime=T, flag=b"\x01"),
                "msu R1 roll that adds value, with output 0 in the deduct mode")
    expect_fail(lambda: run({0: P, 1: L}, {0: None, 1: L}, locktime=T - 1),
                "msu R1 reclaim before the deadline")
    expect_fail(lambda: run({0: P, 1: L}, {0: P2, 1: L}, locktime=T - 1),
                "msu R1 roll before the deadline")
    run({0: P, 1: L}, {0: P.with_amount_seq(25_000, 0), 1: L})
    check(True, "msu top-up of the pending leaf, operator only")
    A = mk_leaf("c0", 20_000, pw.op_pk, 600_000)
    B = mk_leaf("c1", 10_000, pw.op_pk, 600_000)
    expect_fail(lambda: run({0: A, 1: B}, {0: None, 1: B}, locktime=T),
                "msu emptying an ordinary leaf with no signature")
    expect_fail(lambda: run({0: L, 1: P}, {0: None, 1: P}, locktime=900_000),
                "msu reclaiming the landing leaf")
    expect_fail(lambda: run({0: A, 1: B}, {0: A.with_amount_seq(13_000, 0), 1: B.with_amount_seq(17_000, 0)}),
                "msu R3 from an ordinary leaf")
    # an ordinary signed exit through the same script: the DEDUCT payout
    run({0: A, 1: B}, {0: None, 1: B}, sign={0: (sk("c0-owner"), sk("c0-exit"))},
        payouts=[(A.amount, lt.p2tr_spk(A.exit_key))])
    check(True, "msu rewrite exit of an ordinary leaf, owner and exit key, paid by DEDUCT")
    expect_fail(lambda: run({0: A, 1: B}, {0: None, 1: B}, sign={0: (sk("c0-owner"), sk("c0-exit"))},
                            payouts=[(A.amount - 1, lt.p2tr_spk(A.exit_key))]),
                "msu rewrite exit paying less than the leaf")
    # stale root
    w_st, ctx_st = _rewrite_case(pw, 1, 2, {0: P, 1: L}, {0: P.with_amount_seq(13_000, 0), 1: L.with_amount_seq(17_000, 0)})
    w_st[1] = build_proof(pw.tree, 6, pw.depth, height=1)
    expect_fail(lambda: pw.run(name, w_st, ctx_st), "msu rewrite folded at another position")

    # the window settlement with every pair of the cohort active
    sizes = {}
    for h in REWRITE_HEIGHTS:
        base = 1 << h if (1 << (h + 1)) <= (1 << pw.depth) - 3 else 0
        old = _cohort(pw, h, T)
        settle = {i: lf.with_amount_seq(lf.amount + (3_000 if i % 2 else -3_000), 0) for i, lf in old.items()}
        wit_t, ctx_t = _rewrite_case(pw, h, base, old, settle)
        it_t = pw.run(f"REWRITE_XR_{h}", wit_t, ctx_t)
        check(True, f"msu REWRITE_XR_{h}: every pair transfers (R3), operator only")
        roll = {i: (pw.pending(25_000 + i, T + 1_008, label=f"P'{i}", rcpt=f"rcpt{i // 2}") if i % 2 == 0 else lf)
                for i, lf in settle.items()}
        wit_r, ctx_r = _rewrite_case(pw, h, base, settle, roll, locktime=T)
        it_r = pw.run(f"REWRITE_XR_{h}", wit_r, ctx_r)
        check(True, f"msu REWRITE_XR_{h}: every pair rolls its pending leaf (R1), operator only")
        sizes[h] = {"script": len(pw.compiled[f"REWRITE_XR_{h}"]),
                    "script_r": len(assemble(U.rewrite_script_msu(pw.depth, h, pw.op_pk, False, pw.rk))),
                    "transfer": (wit_t, it_t.cost), "roll": (wit_r, it_r.cost)}
    return sizes


def test_landing_exit_msu(pw):
    """The recipient's EXIT_1 of its landing leaf after a merge, in the same
    taptree: the existing EXIT_1 under CCV + MSU."""
    P, L = pw.pending(20_000, 700_000), pw.landing(13_000)
    pw.tree.leaves = {2: P.with_amount_seq(17_000, 0), 3: L, **pw.fillers()}
    t1 = pw.clone()
    del t1.leaves[3]
    r1 = t1.root()
    ctx = pw.ctx([(r1[1], pw.spk(r1)), (L.amount, lt.p2tr_spk(L.exit_key))])
    sig = schnorr_sign(ctx.sighash(), sk("rcpt-exit"))
    wit = [build_proof(pw.tree, 3, pw.depth), L.serialize(), sig, b""]
    it = pw.run("EXIT_1", wit, ctx)
    check(True, "msu EXIT_1 of the landing leaf by the recipient")
    expect_fail(lambda: pw.run("EXIT_1", wit[:2] + [schnorr_sign(ctx.sighash(), sk("operator-owner")), b""], ctx),
                "msu EXIT_1 of the landing leaf by the operator")
    return {"EXIT_1": (len(pw.compiled["EXIT_1"]), wit, it.cost)}


def pending_cost_model(merge, reclaim, rewrite, exit_):
    """Whole-transaction vbytes for the pending-leaf receive under CCV + MSU
    in a key-addressed tree of N = 2^k members (design/native-opcodes.md).

    Scripts and every witness element but the proof are measured above;
    the proof of a height-h node is the opcode's encoding at depth 64 with
    k - h occupied siblings (proof_bytes(64 - h, k - h)), the scaling
    page's model. Payouts: one for the exit, none for the rest."""
    def rest(wit):
        return sum(len(x) for x in wit[1:])          # everything but the proof

    def rest_rw(wit):
        return sum(len(x) for x in wit) - len(wit[1])

    rows = []
    for k in (16, 20, 32):
        row = {"k": k}
        for name, (script, wit, _) in merge.items():
            row[name] = U.tx_vbytes(script, U.proof_bytes(U.MODEL_DEPTH - 1, k - 1) + rest(wit), 0)
        script, wit, _ = reclaim["RECLAIM_1"]
        row["RECLAIM_1"] = U.tx_vbytes(script, U.proof_bytes(U.MODEL_DEPTH, k) + rest(wit), 0)
        script, wit, _ = exit_["EXIT_1"]
        row["EXIT_1"] = U.tx_vbytes(script, U.proof_bytes(U.MODEL_DEPTH, k) + rest(wit), 1)
        for h, r in rewrite.items():
            pairs = 1 << (h - 1)
            prf = U.proof_bytes(U.MODEL_DEPTH - h, k - h)
            vt = U.tx_vbytes(r["script"], prf + rest_rw(r["transfer"][0]), 0)
            vr = U.tx_vbytes(r["script"], prf + rest_rw(r["roll"][0]), 0)
            row[f"R_{h}"] = (vt, vr, (vt + vr) / pairs)
        rows.append(row)
    return rows


# ------------------------------------------------------------ quarantine --

def test_quarantine():
    """The hypothetical opcode must stay out of every real tier: absent from
    each tier's allowed-opcode set, from every script the tier generators
    emit (which is what spec/golden.json is built from), and from every
    compiled script in spec/golden.json; and the default interpreter
    refuses it (test_opcode's guard check)."""
    import json
    import test_scripts as TS
    import test_mid as TM
    import test_min as TN
    import test_ccv as TC
    import layertree_scripts as F
    import layertree_mid as M
    import layertree_min as N
    import layertree_ccv as CV
    from script_sim import disassemble
    for name, ops in (("FULL", TS.ALLOWED_OPCODES), ("FULL minimal", TS.MINIMAL_OPCODES),
                      ("MID", TM.MID_OPCODES), ("MIN", TN.MIN_OPCODES),
                      ("CCV 0xC2", TC.ALLOWED), ("CCV 0xC0", TC.C0_OPCODES)):
        check(U.MSU not in ops, f"quarantine: {name} allowed set excludes OP_MERKLESUMUPDATE")
    key = pubkey_x(lt.sha256(b"operator"))
    tid = TS.TREE_ID
    sets = [F.all_scripts(4, key, (0, 2), (1, 2), "D", (2,), tid), F.all_scripts(8, key, (0,), (1,), "S", (2,), tid),
            M.all_scripts(4, key, False, tree_id=tid), M.all_scripts(8, key, True, tree_id=tid),
            {"EXIT_1": N.exit_script(4), "SPLIT": N.split_script(4)},
            CV.all_scripts_ccv(4, key, (0, 2), (1, 2), "D", (2,)), CV.all_scripts_ccv(8, key, (0,), (1,), "S", (2,)),
            CV.all_scripts_ccv(4, key, (0, 2), (1, 2), "D", (2,), numeric="c0"),
            # the pending-leaf receive's FULL set (RECLAIM_1, CLAIM^m/^hm, REWRITE_XR_h)
            TS.PendingWorld(4).opts.at_depth(4)]
    hits = [n for d in sets for n, toks in d.items() if U.MSU in toks]
    check(not hits, f"quarantine: no tier generator emits OP_MERKLESUMUPDATE {hits}")
    golden = json.load(open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "spec", "golden.json")))
    bad = [k for k, v in golden["scripts"].items()
           if "OP_MERKLESUMUPDATE" in disassemble(bytes.fromhex(v["hex"]))]
    check(not bad, f"quarantine: no golden script contains OP_MERKLESUMUPDATE {bad}")


def main():
    global FAILS, CHECKS
    print("OP_MERKLESUMUPDATE (HYPOTHETICAL measurement; never a tier)")
    test_opcode()
    print(f"  opcode units: {CHECKS} checks so far")
    before = CHECKS
    test_quarantine()
    print(f"  quarantine: {CHECKS - before} checks")
    all_sizes = {}
    for depth, profile in ((4, "D"), (16, "D"), (8, "S"), (32, "S")):
        before = CHECKS
        sizes = test_scripts(depth, profile)
        all_sizes[(profile, depth)] = sizes
        print(f"  {profile}/{depth}: {CHECKS - before} checks")
    before = CHECKS
    pw = PendingMsu(8)
    merge = test_merge_msu(pw)
    reclaim = test_reclaim_msu(pw)
    rewrite = test_rewrite_msu(pw)
    exit_ = test_landing_exit_msu(pw)
    print(f"  pending-leaf receive D/8: {CHECKS - before} checks")
    print("\nMeasured (script / witness bytes, varops):")
    for (profile, depth), sizes in all_sizes.items():
        for k, (sl, wl, cost) in sizes.items():
            print(f"  {profile}/{depth:2} {k:20} {sl:5} {wl:5} {cost}")
    print("\nPending-leaf receive, D/8 (script B; witness B = proof + rest; varops):")
    for name, (sl, wit, cost) in {**merge, **reclaim, **exit_}.items():
        print(f"  {name:18} {sl:6} {sum(len(x) for x in wit):6} = {len(wit[0]):4} + "
              f"{sum(len(x) for x in wit[1:]):4}  {cost}")
    for h, r in rewrite.items():
        for sc in ("transfer", "roll"):
            wit, cost = r[sc]
            print(f"  REWRITE_XR_{h} {sc:8} {r['script']:6} {sum(len(x) for x in wit):6} = {len(wit[1]):4} + "
                  f"{sum(len(x) for x in wit) - len(wit[1]):5}  {cost}   (REWRITE_R_{h} {r['script_r']} B)")
    print("\nPending-leaf receive, whole-transaction vB at N = 2^k, key-addressed depth 64")
    print("(proof of a height-h node: k - h siblings; settlement per pair = (transfer + roll) / pairs):")
    rows = pending_cost_model(merge, reclaim, rewrite, exit_)
    print(f"  {'':24}" + "".join(f"{'k=' + str(r['k']):>12}" for r in rows))
    for name in ("CLAIM_HM", "CLAIM_M", "RECLAIM_1", "EXIT_1"):
        print(f"  {name:24}" + "".join(f"{r[name]:>12,}" for r in rows))
    for h in rewrite:
        print(f"  {'REWRITE_XR_' + str(h) + ' transfer tx':24}" + "".join(f"{r[f'R_{h}'][0]:>12,}" for r in rows))
        print(f"  {'REWRITE_XR_' + str(h) + ' roll tx':24}" + "".join(f"{r[f'R_{h}'][1]:>12,}" for r in rows))
        print(f"  {'  settlement per pair':24}" + "".join(f"{r[f'R_{h}'][2]:>12,.1f}" for r in rows))
    print(f"\n{CHECKS} checks, {FAILS} failures")
    return 1 if FAILS else 0


if __name__ == "__main__":
    sys.exit(main())
