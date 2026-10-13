#!/usr/bin/env python3
"""End-to-end execution of the LayerTree CCV-tier scripts (both profiles).

Mirrors tools/test_scripts.py: same leaves, same negative cases (retargeted
to what CCV actually checks), plus CCV-specific negatives:

* output 0 with a wrong taptree (a P2TR to the correct CCV key for `nh`
  but tweaked by another taptree) must fail;
* output 0 with the FULL-tier key (H_state binding) must fail;
* a payout to a script other than P2TR(exit_key) must fail;
* output 0 above or below ns must fail (assign-mode floor plus the
  numeric equality);
* two tree inputs in one transaction (test_two_trees): the assign-mode
  floor accumulates across inputs, so two copies of a tree state cannot
  share one output 0, and a payout output cannot be deducted twice;
* the BIP-443 amount rules the tier relies on, pinned one by one against
  the opcode itself (test_a6_pins, spec 4.1 [A-6]);
* the tree-creation variants UPDATE^x (both numerics) and SPLIT (0xC2);
* the pending-leaf receive (CLAIM^m, CLAIM^hm, RECLAIM_1 and the reclaim
  form of REWRITE_h) in both numerics, including the output-0 mode that
  lets a reclaim free its value;
* the same output-0 mode flag on UPDATE, UPDATE^x and every form of
  REWRITE_h (test_update_flag_ccv, test_rewrite_flag_ccv): a net decrease
  spends under DEDUCT, an increase or equal sum under assign, and the other
  flag, an out-of-range flag and a misplaced output 0 each fail.

Prints the check count and a size/cost table like the other suites.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import layertree_ref as lt  # noqa: E402
import layertree_scripts as ls  # noqa: E402
import layertree_ccv as C  # noqa: E402
import layertree_mid as M  # noqa: E402
import test_scripts as TS  # noqa: E402  (the rewrite cohort plan of 7.9's tests)
from script_sim import (Interp, ScriptError, TxContext, assemble, pubkey_x,  # noqa: E402
                        schnorr_sign)

FAILS = 0
CHECKS = 0
P2WPKH = b"\x00\x14" + bytes(20)
# le32(0x81000001) is `01 00 00 81`, the minimal CScriptNum -16,777,217; with
# its empty PADZ pad it is the claim lease only NONNEG keeps out of the carve
# compare (test_mid.NEG_LEASE_EA).
NEG_LEASE_EA = (b"\x01\x00\x00\x81", b"", bytes(4))

BIP342_OPS = {"OP_0", "OP_1", "OP_2DROP", "OP_2DUP", "OP_2SWAP", "OP_ABS", "OP_ADD", "OP_1ADD",
              "OP_BOOLAND",
              "OP_CHECKLOCKTIMEVERIFY", "OP_CHECKSIGVERIFY", "OP_CHECKSIG", "OP_DROP",
              "OP_DUP", "OP_ELSE", "OP_ENDIF", "OP_EQUAL", "OP_EQUALVERIFY",
              "OP_FROMALTSTACK", "OP_IF", "OP_LESSTHANOREQUAL", "OP_NIP", "OP_NOT",
              "OP_NOTIF", "OP_NUMEQUAL", "OP_NUMEQUALVERIFY", "OP_OVER", "OP_PICK",
              "OP_ROLL", "OP_ROT", "OP_SHA256", "OP_SIZE", "OP_SUB", "OP_SWAP",
              "OP_TOALTSTACK", "OP_TUCK", "OP_VERIFY", "OP_0NOTEQUAL"}
BIP441_OPS = {"OP_CAT", "OP_SUBSTR", "OP_LEFT", "OP_RIGHT", "OP_AND", "OP_DOWNSHIFT"}
OPTX_OPS = {"OP_TX"}
CCV_OPS = {"OP_CHECKCONTRACTVERIFY"}
ALLOWED = BIP342_OPS | BIP441_OPS | OPTX_OPS | CCV_OPS


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


def sc_bytes(node):
    return node[0] + lt.enc64(node[1])


class World:
    def __init__(self, depth, profile, join_heights=(0, 2), exit_ks=(1, 2)):
        self.depth, self.profile = depth, profile
        self.op_sk = sk("operator")
        self.op_pk = pubkey_x(self.op_sk)
        self.scripts = C.all_scripts_ccv(depth, self.op_pk, join_heights, exit_ks, profile)
        for name, toks in self.scripts.items():
            bad = {t for t in toks if isinstance(t, str)} - ALLOWED
            check(not bad, f"{name}: opcodes outside the CCV candidate set: {sorted(bad)}")
        self.compiled = {k: assemble(v) for k, v in self.scripts.items()}
        self.m = lt.taptree_root([lt.tapleaf_hash(c) for c in self.compiled.values()])
        self.tree = lt.Tree(depth)

    def slot(self, leaf, want=None):
        return leaf.position(self.depth) if self.profile == "S" else want

    def path_witness(self, path, height=0):
        items = []
        if self.profile == "D":
            for d, sib in reversed(path):
                items += [b"\x01" if d else b"", sc_bytes(sib)]
        else:
            for _, sc in reversed(lt.compress_path(path, height)):
                items.append(sc)
        return items

    def spk(self, root=None):
        root = root or self.tree.root()
        return lt.tree_spk_ccv(root[0], self.m)

    def ctx(self, outputs, extra_in=None, locktime=0, root=None):
        """A TxContext for spending the tree input as input 0. internal_key
        and taptree_root are what a validating node would hand the script:
        the input's taproot internal key (here the CCV state key of the
        root) and the taptree Merkle root m."""
        root = root or self.tree.root()
        inputs = [(root[1], self.spk(root))]
        if extra_in:
            inputs.append(extra_in)
        return TxContext(inputs, outputs, locktime=locktime,
                         internal_key=lt.ccv_internal_key(root[0]),
                         taptree_root=self.m)

    def run(self, name, witness, ctx):
        it = Interp(ctx)
        it.run(self.compiled[name], witness)
        return it

    def clone(self):
        t = lt.Tree(self.depth)
        t.leaves = dict(self.tree.leaves)
        return t


def run_fresh(w, name, wit, ctx):
    """Run one script with the transaction-wide CCV state (BIP-443's amount
    accumulators) reset, so that a context reused across runs does not
    carry one run's assigned amounts into the next."""
    ctx.ccv_reset()
    return w.run(name, wit, ctx)


def mk_leaf(label, amount, evictor=None, evict_after=0, nonce=None, seq=0):
    if nonce is None:
        nonce = int.from_bytes(lt.sha256(label.encode())[:4], "little")
    return lt.Leaf(amount, pubkey_x(sk(label + "-exit")), pubkey_x(sk(label + "-owner")),
                   evictor if evictor else lt.NUMS_X, evict_after, nonce, seq)


def carve_of(src, label, amount):
    """A leaf carved out of src: it keeps src's evictor_key and evict_after
    (spec 7.5 rule 5)."""
    return mk_leaf(label, amount, src.evictor_key, src.evict_after)


def test_all(depth, profile, verbose=True):
    w = World(depth, profile)
    D = depth
    costs = {}

    def record(name, it, wit):
        costs[name] = (it, len(w.compiled[name.split(" ")[0]]), sum(len(x) for x in wit))

    alice = mk_leaf("alice", 50_000)
    bob = mk_leaf("bob", 125_000, evictor=w.op_pk, evict_after=800_000)
    oper = mk_leaf("operator", 1_000_000)
    s_alice, s_bob, s_oper = w.slot(alice, 0), w.slot(bob, 5), w.slot(oper, (1 << D) - 1)
    w.tree.leaves = {s_alice: alice, s_bob: bob, s_oper: oper}

    # ---------------- EXIT_1 owner ----------------
    root = w.tree.root()
    path = w.tree.path(s_bob)
    t1 = w.clone(); del t1.leaves[s_bob]
    r1 = t1.root()
    fee = 1_000
    outputs = [(r1[1], w.spk(r1)), (bob.amount, lt.p2tr_spk(bob.exit_key)), (49_000 - fee, P2WPKH)]
    ctx = w.ctx(outputs, extra_in=(50_000, P2WPKH))
    sig = schnorr_sign(ctx.sighash(), sk("bob-owner"))
    wit = w.path_witness(path) + [bob.serialize(), sig, b""]
    record("EXIT_1 (owner)", w.run("EXIT_1", wit, ctx), wit)
    # CCV: out1 DEDUCTs bob's amount from the tree input's residual, out0
    # is assigned the rest (the floor) and must equal ns (the equality).

    # CCV-specific negatives -------------------------------------------------
    # output 0 tweaked by a wrong taptree: correct key for nh, other tree.
    bad = list(outputs)
    bad[0] = (r1[1], lt.tree_spk_ccv(r1[0], lt.sha256(b"wrong-taptree")))
    ctxw = w.ctx(bad, extra_in=(50_000, P2WPKH))
    sigw = schnorr_sign(ctxw.sighash(), sk("bob-owner"))
    expect_fail(lambda: w.run("EXIT_1", w.path_witness(path) + [bob.serialize(), sigw, b""], ctxw),
                "output 0 under a wrong taptree")

    # output 0 with the FULL-tier (H_state) binding: must fail under CCV.
    bad = list(outputs)
    bad[0] = (r1[1], lt.tree_spk(r1[0], w.m))
    ctxf = w.ctx(bad, extra_in=(50_000, P2WPKH))
    sigf = schnorr_sign(ctxf.sighash(), sk("bob-owner"))
    expect_fail(lambda: w.run("EXIT_1", w.path_witness(path) + [bob.serialize(), sigf, b""], ctxf),
                "output 0 with FULL-tier key")

    # payout to a script other than P2TR(exit_key): key-path P2TR to a
    # tweaked exit key must fail (data tweak applied to the payout).
    bad = list(outputs)
    bad[1] = (bob.amount, lt.tree_spk_ccv(bob.exit_key, w.m))
    ctxp = w.ctx(bad, extra_in=(50_000, P2WPKH))
    sigp = schnorr_sign(ctxp.sighash(), sk("bob-owner"))
    expect_fail(lambda: w.run("EXIT_1", w.path_witness(path) + [bob.serialize(), sigp, b""], ctxp),
                "payout output is a tweaked key, not the bare exit key")

    # underfunded output 0 (amount < ns): DEDUCT passes but equality fails.
    bad = list(outputs)
    bad[0] = (r1[1] - 1_000, w.spk(r1))
    ctxu = w.ctx(bad, extra_in=(50_000 + 1_000, P2WPKH))
    sigu = schnorr_sign(ctxu.sighash(), sk("bob-owner"))
    expect_fail(lambda: w.run("EXIT_1", w.path_witness(path) + [bob.serialize(), sigu, b""], ctxu),
                "output 0 underfunded (amount < ns)")

    # a larger fee input with its excess returned as change: the free
    # outputs are unconstrained, output 0 still equals ns exactly.
    over = list(outputs)
    over[2] = (49_000 + 5_000, P2WPKH)
    ctxo = w.ctx(over, extra_in=(50_000 + 5_000, P2WPKH))
    sigo = schnorr_sign(ctxo.sighash(), sk("bob-owner"))
    wito = w.path_witness(path) + [bob.serialize(), sigo, b""]
    try:
        w.run("EXIT_1", wito, ctxo)
        check(True, "EXIT_1 with a larger fee input and change")
    except ScriptError as e:
        check(False, f"EXIT_1 with a larger fee input and change: {str(e)[:70]}")

    # but an output 0 larger than ns is rejected even when funded.
    bad = list(outputs)
    bad[0] = (r1[1] + 5_000, w.spk(r1))
    ctxo2 = w.ctx(bad, extra_in=(50_000 + 5_000, P2WPKH))
    sigo2 = schnorr_sign(ctxo2.sighash(), sk("bob-owner"))
    expect_fail(lambda: w.run("EXIT_1", w.path_witness(path) + [bob.serialize(), sigo2, b""], ctxo2),
                "output 0 overfunded (amount > ns rejected)")

    # original negatives that CCV still enforces --------------------------------
    fake = bob.with_amount_seq(bob.amount + 1, 0)
    expect_fail(lambda: w.run("EXIT_1", w.path_witness(path) + [fake.serialize(), sig, b""], ctx),
                "forged leaf amount (payout > leaf)")
    sig4 = schnorr_sign(ctx.sighash(), sk("alice-owner"))
    expect_fail(lambda: w.run("EXIT_1", w.path_witness(path) + [bob.serialize(), sig4, b""], ctx),
                "wrong owner key")
    # payout above the leaf but below the tree total: the CCV DEDUCT call
    # succeeds (the residual covers it) and the exact-payout equality
    # rejects it (spec 7.2 rule 6; the CCV tier's only payout mode).
    bad = list(outputs)
    bad[1] = (bob.amount + 1, lt.p2tr_spk(bob.exit_key))
    ctx2 = w.ctx(bad, extra_in=(50_000, P2WPKH)); sig2 = schnorr_sign(ctx2.sighash(), sk("bob-owner"))
    expect_fail(lambda: w.run("EXIT_1", w.path_witness(path) + [bob.serialize(), sig2, b""], ctx2),
                "payout > leaf (rejected by the equality, not the residual)")
    # payout above the entire tree input's residual: the DEDUCT call itself
    # fails ("residual below deducted amount") before any comparison runs.
    bad = list(outputs)
    bad[1] = (root[1] + 1, lt.p2tr_spk(bob.exit_key))
    ctx3 = w.ctx(bad, extra_in=(50_000, P2WPKH)); sig3 = schnorr_sign(ctx3.sighash(), sk("bob-owner"))
    expect_fail(lambda: w.run("EXIT_1", w.path_witness(path) + [bob.serialize(), sig3, b""], ctx3),
                "payout > tree total (rejected by the CCV residual check)")

    # wrong root in witness: the fold produces oh != the input's committed
    # root; CHECK_INPUT fails. (Forged sibling path.)
    bad_t = w.clone(); del bad_t.leaves[s_alice]
    bad_root = bad_t.root()
    bad_path = w.tree.path(s_oper)
    # use a path proving s_oper is in the tree, but the input commits to root
    # of the full tree: fold of removing s_oper gives r_oper; input's oh is
    # root of full tree -> CHECK_INPUT must fail.
    t_oper = w.clone(); del t_oper.leaves[s_oper]
    r_oper = t_oper.root()
    ctx_bad = w.ctx([(r_oper[1], w.spk(r_oper)), (oper.amount - fee, lt.p2tr_spk(oper.exit_key))],
                    extra_in=(50_000, P2WPKH))
    sig_bad = schnorr_sign(ctx_bad.sighash(), sk("oper-owner"))
    # witness claims removal of s_oper, but the input's committed root is
    # `root` (full tree). CHECK_INPUT data = fold result oh = r_oper[0]... no:
    # fold over the path of s_oper in the CURRENT tree gives root[0], fine.
    # Forged case: witness path for s_oper but a wrong sibling -> oh mismatch.
    wit_bad = w.path_witness(w.tree.path(s_oper)) + [oper.serialize(), sig_bad, b""]
    # ctx's input commits to root (full tree): valid. make ctx commit to a
    # different tree to force oh mismatch:
    other = w.clone(); del other.leaves[s_alice]
    other_root = other.root()
    ctx_mis = TxContext([(other_root[1], w.spk(other_root)), (50_000, P2WPKH)],
                        [(r_oper[1], w.spk(r_oper)), (oper.amount - fee, lt.p2tr_spk(oper.exit_key))],
                        internal_key=lt.ccv_internal_key(other_root[0]), taptree_root=w.m)
    sig_mis = schnorr_sign(ctx_mis.sighash(), sk("oper-owner"))
    expect_fail(lambda: w.run("EXIT_1",
                              w.path_witness(w.tree.path(s_oper)) + [oper.serialize(), sig_mis, b""],
                              ctx_mis),
                "CHECK_INPUT: input commits to a different root than the proof folds to")

    w.tree = t1

    # ---------------- EXIT_1 evict ----------------
    # bob was removed by the owner exit; restore the original tree first.
    w.tree.leaves[s_bob] = bob
    root = w.tree.root()
    path = w.tree.path(s_bob)
    t1b = w.clone(); del t1b.leaves[s_bob]
    r1b = t1b.root()
    outputs = [(r1b[1], w.spk(r1b)), (bob.amount, lt.p2tr_spk(bob.exit_key))]
    ctx = w.ctx(outputs, locktime=900_000)
    esig = schnorr_sign(ctx.sighash(), w.op_sk)
    wit_e = w.path_witness(path) + [bob.serialize(), esig, b"\x01"]
    record("EXIT_1 (evict)", w.run("EXIT_1", wit_e, ctx), wit_e)
    expect_fail(lambda: w.run("EXIT_1", w.path_witness(path) + [bob.serialize(), esig, b"\x01"],
                              w.ctx(outputs, locktime=100)),
                "evict before evict_after")
    sig_2 = schnorr_sign(ctx.sighash(), sk("bob-owner"))
    expect_fail(lambda: w.run("EXIT_1", w.path_witness(path) + [bob.serialize(), sig_2, b"\x01"], ctx),
                "owner key may not evict")
    bad = list(outputs)
    bad[1] = (bob.amount - 1, lt.p2tr_spk(bob.exit_key))
    ctx_e2 = w.ctx(bad, locktime=900_000)
    esig3 = schnorr_sign(ctx_e2.sighash(), w.op_sk)
    expect_fail(lambda: w.run("EXIT_1", w.path_witness(path) + [bob.serialize(), esig3, b"\x01"], ctx_e2),
                "evictor may not shortchange")
    w.tree = t1b

    # ---------------- terminal exit (separate tiny tree) ----------------
    main_tree = w.clone()          # keep the flow's leaves intact
    solo = mk_leaf("solo", 77_000)
    tiny = lt.Tree(D); tiny.leaves = {w.slot(solo, 2): solo}
    w.tree = tiny
    root = w.tree.root()
    spath = w.tree.path(w.slot(solo, 2))
    outputs = [(600, P2WPKH), (solo.amount, lt.p2tr_spk(solo.exit_key))]
    ctx = w.ctx(outputs, extra_in=(1_000, P2WPKH))
    ssig = schnorr_sign(ctx.sighash(), sk("solo-owner"))
    wit = w.path_witness(spath) + [solo.serialize(), ssig, b""]
    record("EXIT_1 (terminal)", w.run("EXIT_1", wit, ctx), wit)
    w.tree = main_tree
    root = w.tree.root()

    # ---------------- JOIN (dense: subtree h=2; sparse: single leaf) ------
    root = w.tree.root()
    carol = mk_leaf("carol", 60_000)
    dave = mk_leaf("dave", 45_000, w.op_pk, 900_000)
    if profile == "D" and D >= 4:
        h, idx = 2, 2
        jpath = w.tree.path(idx << h, height=h)
        t2 = w.clone(); lt.apply_join(t2, h, idx, {0: carol, 3: dave})
        new_node, r2 = t2.subtree(h, idx), t2.root()
        outputs = [(r2[1], w.spk(r2)), (900, P2WPKH)]
        ctx = w.ctx(outputs, extra_in=(new_node[1] + 2_000, P2WPKH))
        osig = schnorr_sign(ctx.sighash(), w.op_sk)
        wit = w.path_witness(jpath, h) + [new_node[0], lt.le64(new_node[1]), osig]
        record("JOIN_2", w.run("JOIN_2", wit, ctx), wit)
        jpath_bad = w.tree.path(0, height=h)
        expect_fail(lambda: w.run("JOIN_2", w.path_witness(jpath_bad, h) + [new_node[0], lt.le64(new_node[1]), osig], ctx),
                    "join over occupied subtree")
        bad = [(r2[1] - 1, w.spk(r2))]
        ctxb = w.ctx(bad, extra_in=(new_node[1] + 2_000, P2WPKH)); osigb = schnorr_sign(ctxb.sighash(), w.op_sk)
        expect_fail(lambda: w.run("JOIN_2", w.path_witness(jpath, h) + [new_node[0], lt.le64(new_node[1]), osigb], ctxb),
                    "join underfunded (out0 < ns)")
        usig = schnorr_sign(ctx.sighash(), sk("alice-owner"))
        expect_fail(lambda: w.run("JOIN_2", w.path_witness(jpath, h) + [new_node[0], lt.le64(new_node[1]), usig], ctx),
                    "join without operator")
        w.tree = t2
        s_carol, s_dave = (idx << h), (idx << h) + 3
    else:
        for lf in (carol, dave):
            root = w.tree.root()
            slot = w.slot(lf)
            jpath = w.tree.path(slot)
            t2 = w.clone(); t2.leaves[slot] = lf
            r2 = t2.root()
            ctx = w.ctx([(r2[1], w.spk(r2))], extra_in=(lf.amount + 500, P2WPKH))
            osig = schnorr_sign(ctx.sighash(), w.op_sk)
            wit = w.path_witness(jpath) + [lf.serialize(), osig]
            record("JOIN_0", w.run("JOIN_0", wit, ctx), wit)
            w.tree = t2
        s_carol, s_dave = w.slot(carol), w.slot(dave)
        root = w.tree.root()
        erin = mk_leaf("erin", 12_345, w.op_pk, 900_000)
        s_erin = w.slot(erin, 9)
        jpath0 = w.tree.path(s_erin)
        t3 = w.clone(); t3.leaves[s_erin] = erin
        r3 = t3.root()
        ctx = w.ctx([(r3[1], w.spk(r3))], extra_in=(erin.amount + 500, P2WPKH))
        osig = schnorr_sign(ctx.sighash(), w.op_sk)
        wit = w.path_witness(jpath0) + [erin.serialize(), osig]
        record("JOIN_0", w.run("JOIN_0", wit, ctx), wit)
        usig = schnorr_sign(ctx.sighash(), sk("erin-owner"))
        expect_fail(lambda: w.run("JOIN_0", w.path_witness(jpath0) + [erin.serialize(), usig], ctx),
                    "join without operator")
        w.tree = t3

    # ---------------- JOINK_2 ----------------
    root = w.tree.root()
    hank = mk_leaf("hank", 9_000, w.op_pk, 900_000)
    ivy = mk_leaf("ivy", 11_000, w.op_pk, 900_000)
    if profile == "S":
        while w.slot(hank) in w.tree.leaves:
            hank = mk_leaf("hank", 9_000, w.op_pk, 900_000, nonce=hank.nonce + 1)
        while w.slot(ivy) in w.tree.leaves or w.slot(ivy) == w.slot(hank):
            ivy = mk_leaf("ivy", 11_000, w.op_pk, 900_000, nonce=ivy.nonce + 1)
        s_hank, s_ivy = w.slot(hank), w.slot(ivy)
    else:
        s_hank, s_ivy = w.slot(hank, 12), w.slot(ivy, 13)
    tj = w.clone()
    path_h = tj.path(s_hank); tj.leaves[s_hank] = hank
    path_i = tj.path(s_ivy); tj.leaves[s_ivy] = ivy
    rj = tj.root()
    ctx = w.ctx([(rj[1], w.spk(rj))], extra_in=(hank.amount + ivy.amount + 700, P2WPKH))
    osig = schnorr_sign(ctx.sighash(), w.op_sk)
    if profile == "D":
        b1 = w.path_witness(path_h) + [hank.hash(), lt.le64(hank.amount)]
        b2 = w.path_witness(path_i) + [ivy.hash(), lt.le64(ivy.amount)]
        b2_stale = w.path_witness(w.tree.path(s_ivy)) + [ivy.hash(), lt.le64(ivy.amount)]
    else:
        b1 = w.path_witness(path_h) + [hank.serialize()]
        b2 = w.path_witness(path_i) + [ivy.serialize()]
        b2_stale = w.path_witness(w.tree.path(s_ivy)) + [ivy.serialize()]
    wit = b2 + b1 + [osig]
    record("JOINK_2", w.run("JOINK_2", wit, ctx), wit)
    expect_fail(lambda: w.run("JOINK_2", b2_stale + b1 + [osig], ctx), "JOINK_2 stale second path")
    ctxu = w.ctx([(rj[1] - 1, w.spk(rj))], extra_in=(hank.amount + ivy.amount + 700, P2WPKH))
    osigu = schnorr_sign(ctxu.sighash(), w.op_sk)
    expect_fail(lambda: w.run("JOINK_2", b2 + b1 + [osigu], ctxu), "JOINK_2 underfunded")
    w.tree = tj

    # ---------------- UPDATE ----------------
    root = w.tree.root()
    upath = w.tree.path(s_alice)
    alice2 = alice.with_amount_seq(80_000, 1)
    t4 = w.clone(); t4.leaves[s_alice] = alice2
    r4 = t4.root()
    ctx = w.ctx([(r4[1], w.spk(r4))], extra_in=(30_700, P2WPKH))
    osig = schnorr_sign(ctx.sighash(), w.op_sk)
    asig = schnorr_sign(ctx.sighash(), sk("alice-owner"))
    wit = [b""] + w.path_witness(upath) + [alice.serialize(), alice2.serialize(), asig, osig]   # flag: assign
    record("UPDATE", w.run("UPDATE", wit, ctx), wit)
    expect_fail(lambda: w.run("UPDATE", [b""] + w.path_witness(upath) + [alice.serialize(), alice2.serialize(), osig, osig], ctx),
                "update without owner")
    w.tree = t4

    # ---------------- EXIT_2 (carol owner + dave evict) ----------------
    if "EXIT_2" in w.compiled:
        root = w.tree.root()
        t7 = w.clone()
        path_c = t7.path(s_carol); del t7.leaves[s_carol]
        path_d = t7.path(s_dave); del t7.leaves[s_dave]
        r7 = t7.root()
        outputs = [(r7[1], w.spk(r7)), (carol.amount, lt.p2tr_spk(carol.exit_key)),
                   (dave.amount, lt.p2tr_spk(dave.exit_key))]
        ctx = w.ctx(outputs, extra_in=(5_000, P2WPKH), locktime=900_000)
        csig = schnorr_sign(ctx.sighash(), sk("carol-owner")); dsig = schnorr_sign(ctx.sighash(), w.op_sk)
        block2 = w.path_witness(path_d) + [dave.serialize(), dsig, b"\x01"]
        block1 = w.path_witness(path_c) + [carol.serialize(), csig, b""]
        wit = block2 + block1
        record("EXIT_2", w.run("EXIT_2", wit, ctx), wit)
        expect_fail(lambda: w.run("EXIT_2", w.path_witness(w.tree.path(s_dave)) + [dave.serialize(), dsig, b"\x01"] + block1, ctx),
                    "EXIT_2 stale second path")
        w.tree = t7

    # ---------------- EVICT_SUBTREE_h (dense only) ----------------
    if profile == "D" and "EVICT_SUBTREE_1" in w.compiled and D >= 4:
        root = w.tree.root()
        h = 1
        idx = s_dave >> h
        t8 = w.clone()
        wl = [w.tree.leaves.get((idx << h) + j) for j in range(1 << h)]
        for j in range(1 << h):
            if (idx << h) + j in t8.leaves:
                del t8.leaves[(idx << h) + j]
        r8 = t8.root()
        outs = [(r8[1], w.spk(r8))]
        for l in wl:
            if l is None:
                outs.append((0, P2WPKH))
            else:
                outs.append((l.amount, lt.p2tr_spk(l.exit_key)))
        ctx = w.ctx(outs, locktime=900_000)
        sig_e = schnorr_sign(ctx.sighash(), w.op_sk)
        spath = w.tree.path(idx << h, height=h)
        wit = []
        for d, sib in reversed(spath):
            wit += [b"\x01" if d else b"", sc_bytes(sib)]
        for l in reversed(wl):
            wit.append(l.serialize() if l else b"")
        wit += [sig_e]
        try:
            it = w.run("EVICT_SUBTREE_1", wit, ctx)
            record("EVICT_SUBTREE_1", it, wit)
        except ScriptError as e:
            check(False, f"EVICT_SUBTREE_1 positive: {str(e)[:70]}")

    if verbose:
        print(f"  CCV {profile} D={D}: {CHECKS} checks so far")
    return costs


# ------------------------------------------------- [A-6] BIP-443 pins --

def test_a6_pins():
    """Pin the BIP-443 rules the CCV tier relies on (spec 4.1 [A-6]),
    one direct opcode test per rule, against the pseudocode of
    bitcoin/bips commit 24e96e87. Each script is
    <data> <index> <pk> <taptree> <mode> CCV ... OP_1, with bare keys
    (data and taptree empty) so the scriptPubKey part is trivial and the
    amount bookkeeping is what is under test."""
    K = [pubkey_x(sk(f"pin-{i}")) for i in range(4)]
    spk = [lt.p2tr_spk(k) for k in K]

    def call(idx, key, mode, data=b"", taptree=b""):
        return [data, idx, key, taptree, mode, "OP_CHECKCONTRACTVERIFY"]

    def run(ctx, toks, index=0):
        ctx.input_index = index
        Interp(ctx).run(assemble(toks + ["OP_1"]), [])

    def ok(fn, msg):
        try:
            fn()
            check(True, msg)
        except ScriptError as e:
            check(False, f"{msg}: {str(e)[:70]}")

    # default mode: the output must carry at least the input's residual.
    ok(lambda: run(TxContext([(1_000, P2WPKH)], [(1_000, spk[0])]), call(0, K[0], 0)),
       "A-6: default mode, output == residual")
    expect_fail(lambda: run(TxContext([(1_000, P2WPKH)], [(999, spk[0])]), call(0, K[0], 0)),
                "A-6: default mode, output below residual")

    # default mode accumulates across inputs (shared per-output minimum).
    def accumulate(out_amt):
        ctx = TxContext([(1_000, P2WPKH), (500, P2WPKH)], [(out_amt, spk[0])])
        run(ctx, call(0, K[0], 0), 0)
        run(ctx, call(0, K[0], 0), 1)
    ok(lambda: accumulate(1_500), "A-6: two inputs assign to one output, output == sum")
    expect_fail(lambda: accumulate(1_499), "A-6: two inputs assign to one output, output below sum")

    # deduct: subtracts from the residual; the next default sees what is left.
    def deduct_then_assign(out0):
        ctx = TxContext([(1_000, P2WPKH)], [(out0, spk[0]), (300, spk[1])])
        run(ctx, call(1, K[1], 2) + call(0, K[0], 0))
    ok(lambda: deduct_then_assign(700), "A-6: deduct reduces the residual the default mode assigns")
    ok(lambda: deduct_then_assign(10_000), "A-6: the default mode is a floor, not an equality")
    expect_fail(lambda: deduct_then_assign(699), "A-6: default floor after deduct")
    expect_fail(lambda: run(TxContext([(1_000, P2WPKH)], [(1_001, spk[0])]), call(0, K[0], 2)),
                "A-6: deduct above the residual")

    # an output checked with deduct may not be checked again, in any order,
    # by the same input or another one.
    expect_fail(lambda: run(TxContext([(1_000, P2WPKH)], [(300, spk[0])]),
                            call(0, K[0], 2) + call(0, K[0], 0)),
                "A-6: deduct then default on one output")
    # the second input has residual to spare, so only the mixing rule
    # can reject its deduct.
    def default_then_deduct():
        ctx = TxContext([(1_000, P2WPKH), (2_000, P2WPKH)], [(1_000, spk[0])])
        run(ctx, call(0, K[0], 0), 0)
        run(ctx, call(0, K[0], 2), 1)
    expect_fail(default_then_deduct, "A-6: default then deduct on one output")

    def deduct_twice():
        ctx = TxContext([(1_000, P2WPKH), (1_000, P2WPKH)], [(300, spk[0])])
        run(ctx, call(0, K[0], 2), 0)
        run(ctx, call(0, K[0], 2), 1)
    expect_fail(deduct_twice, "A-6: two inputs deduct the same output")

    # a residual left unassigned is not checked (it is fee).
    ok(lambda: run(TxContext([(1_000, P2WPKH)], [(300, spk[0])]), call(0, K[0], 2)),
       "A-6: unassigned residual is accepted")

    # CHECK_INPUT does not touch the residual.
    def input_then_assign(out_amt):
        ctx = TxContext([(1_000, spk[2])], [(out_amt, spk[0])])
        run(ctx, call(C.MINUS1, K[2], C.MINUS1) + call(0, K[0], 0))
    ok(lambda: input_then_assign(1_000), "A-6: CHECK_INPUT leaves the residual whole")
    expect_fail(lambda: input_then_assign(999), "A-6: CHECK_INPUT leaves the residual whole (floor)")

    # ignore mode: no amount bookkeeping at all.
    ok(lambda: run(TxContext([(1_000, P2WPKH)], [(1, spk[0])]), call(0, K[0], 1)),
       "A-6: ignore mode checks no amount")

    # an undefined mode makes the script succeed whatever follows.
    ok(lambda: Interp(TxContext([(1, P2WPKH)], [(1, P2WPKH)])).run(
        assemble(call(0, K[0], 3) + ["OP_0", "OP_VERIFY"]), []),
       "A-6: undefined mode is OP_SUCCESS")

    # empty pk is NUMS, empty data applies no tweak.
    ok(lambda: run(TxContext([(1, P2WPKH)], [(1, lt.p2tr_spk(lt.NUMS_X))]), call(0, b"", 1)),
       "A-6: empty pk is the BIP-341 NUMS key, empty data no tweak")

    # data tweak: sha256(pk || data), untagged; the tree key matches.
    root = lt.sha256(b"pin-root")
    ok(lambda: run(TxContext([(1, P2WPKH)], [(1, lt.p2tr_spk(lt.ccv_internal_key(root)))]),
                   call(0, b"", 1, data=root)),
       "A-6: data tweak is NUMS + sha256(NUMS || data)*G")
    expect_fail(lambda: run(TxContext([(1, P2WPKH)], [(1, lt.p2tr_spk(lt.NUMS_X))]),
                            call(0, b"", 1, data=root)),
                "A-6: non-empty data must tweak")


# ------------------------------------------------- two tree inputs --

def test_two_trees(depth, profile):
    """Two tree inputs in one transaction. Every CCV call names "the
    current input", so the question is whether two inputs carrying the same
    tree state (same root, same taptree, hence the same scriptPubKey) can
    be spent together so that one output 0 satisfies both scripts. The
    assign-mode floor accumulates across inputs (A-6), so output 0 would
    have to carry both inputs' residuals while equalling one ns; and a
    payout output cannot be deducted by both. Each script passes alone in
    the same transaction; the second input fails. Two trees with different
    states cannot meet at all: each requires output 0 to be its own
    successor."""
    w = World(depth, profile)
    alice = mk_leaf("alice", 50_000)
    bob = mk_leaf("bob", 125_000)
    s_a, s_b = w.slot(alice, 0), w.slot(bob, 5)
    w.tree.leaves = {s_a: alice, s_b: bob}
    root = w.tree.root()
    tree_in = (root[1], w.spk(root))

    def mkctx(outputs, extra):
        return TxContext([tree_in, tree_in, extra], outputs,
                         internal_key=lt.ccv_internal_key(root[0]), taptree_root=w.m)

    def run_input(ctx, name, wit_of, index):
        ctx.input_index = index
        return w.run(name, wit_of(ctx), ctx)

    # (1) UPDATE on both copies: one output 0 for 2 * os.
    upath = w.tree.path(s_a)
    alice2 = alice.with_amount_seq(80_000, 1)
    t1 = w.clone(); t1.leaves[s_a] = alice2; r1 = t1.root()
    ctx = mkctx([(r1[1], w.spk(r1))], (30_700, P2WPKH))

    def uwit(c):
        return [b""] + w.path_witness(upath) + [alice.serialize(), alice2.serialize(),
                                        schnorr_sign(c.sighash(), sk("alice-owner")),
                                        schnorr_sign(c.sighash(), w.op_sk)]
    try:
        run_input(ctx, "UPDATE", uwit, 0)
        check(True, "two trees: the first copy's UPDATE passes on its own")
    except ScriptError as e:
        check(False, f"two trees: first UPDATE: {str(e)[:70]}")
    expect_fail(lambda: run_input(ctx, "UPDATE", uwit, 1),
                "two trees: a second copy cannot share output 0 (assign floor accumulates)")

    # (2) EXIT_1 of the same leaf from both copies: one payout, two deducts.
    path = w.tree.path(s_b)
    t2 = w.clone(); del t2.leaves[s_b]; r2 = t2.root()
    ctx = mkctx([(r2[1], w.spk(r2)), (bob.amount, lt.p2tr_spk(bob.exit_key))], (1_000, P2WPKH))

    def ewit(c):
        return w.path_witness(path) + [bob.serialize(), schnorr_sign(c.sighash(), sk("bob-owner")), b""]
    try:
        run_input(ctx, "EXIT_1", ewit, 0)
        check(True, "two trees: the first copy's EXIT_1 passes on its own")
    except ScriptError as e:
        check(False, f"two trees: first EXIT_1: {str(e)[:70]}")
    expect_fail(lambda: run_input(ctx, "EXIT_1", ewit, 1),
                "two trees: one payout output cannot be deducted by both copies")


# ------------------------------------------- tree-creation variants --

def test_update_x_ccv(depth, profile):
    """UPDATE^x (spec 7.4 rule 5) under CCV (0xC2): UPDATE plus a
    signature by old_leaf.exit_key. Swapped into the taptree as UPDATE_X,
    as in the FULL suite."""
    w = World(depth, profile)
    toks = C.update_script_ccv(depth, w.op_pk, profile, exit_consent=True)
    bad = {t for t in toks if isinstance(t, str)} - ALLOWED
    check(not bad, f"UPDATE_X: opcodes outside the CCV candidate set: {sorted(bad)}")
    w.compiled = dict(w.compiled); w.compiled["UPDATE_X"] = assemble(toks)
    w.m = lt.taptree_root([lt.tapleaf_hash(c) for c in w.compiled.values()])
    alice = mk_leaf("alice", 50_000)
    oper = mk_leaf("operator", 1_000_000)
    others = [mk_leaf(n, a) for n, a in (("bob", 125_000), ("carol", 30_000),
                                         ("dave", 70_000), ("erin", 15_000))]
    s_alice = w.slot(alice, 0)
    w.tree.leaves = {s_alice: alice, w.slot(oper, (1 << depth) - 1): oper}
    for i, lf in enumerate(others):
        w.tree.leaves[w.slot(lf, i + 1)] = lf
    upath = w.tree.path(s_alice)
    alice2 = alice.with_amount_seq(80_000, 1)
    t1 = w.clone(); t1.leaves[s_alice] = alice2; r1 = t1.root()
    ctx = w.ctx([(r1[1], w.spk(r1))], extra_in=(30_700, P2WPKH))
    osig = schnorr_sign(ctx.sighash(), w.op_sk)
    asig = schnorr_sign(ctx.sighash(), sk("alice-owner"))
    xsig = schnorr_sign(ctx.sighash(), sk("alice-exit"))
    block = [b""] + w.path_witness(upath) + [alice.serialize(), alice2.serialize()]
    wit = block + [asig, osig, xsig]
    it = None
    try:
        it = w.run("UPDATE_X", wit, ctx)
        check(True, "UPDATE^x with owner, operator and exit signatures")
    except ScriptError as e:
        check(False, f"UPDATE^x positive: {str(e)[:70]}")
    expect_fail(lambda: w.run("UPDATE_X", block + [asig, osig, asig], ctx), "UPDATE^x exit_sig by the wrong key")
    expect_fail(lambda: w.run("UPDATE_X", block + [asig, osig, bytes(64)], ctx), "UPDATE^x garbage exit_sig")
    expect_fail(lambda: w.run("UPDATE_X", block + [asig, osig], ctx), "UPDATE^x missing exit_sig")
    expect_fail(lambda: w.run("UPDATE_X", block + [osig, osig, xsig], ctx), "UPDATE^x without the owner signature")
    # a net decrease spends under the DEDUCT flag (spec 4.6), not under assign
    alice3 = alice.with_amount_seq(20_000, 1)
    t3 = w.clone(); t3.leaves[s_alice] = alice3; r3 = t3.root()
    ctx3 = w.ctx([(r3[1], w.spk(r3))], extra_in=(700, P2WPKH))
    sigs3 = [schnorr_sign(ctx3.sighash(), k) for k in (sk("alice-owner"), w.op_sk, sk("alice-exit"))]
    dec = w.path_witness(upath) + [alice.serialize(), alice3.serialize()] + sigs3
    try:
        run_fresh(w, "UPDATE_X", [b"\x01"] + dec, ctx3)
        check(True, "UPDATE^x: a net decrease spends under the DEDUCT flag")
    except ScriptError as e:
        check(False, f"UPDATE^x decrease positive: {str(e)[:70]}")
    expect_fail(lambda: run_fresh(w, "UPDATE_X", [b""] + dec, ctx3), "UPDATE^x: a net decrease under the assign flag")
    return it, len(w.compiled["UPDATE_X"]), sum(len(x) for x in wit)


def test_split_ccv(depth, profile):
    """SPLIT (spec 7.5.2) under CCV (0xC2): the carve authorised by the
    source owner's transaction signature. Mirrors test_scripts.test_split,
    with the stale-root case expressed as CCV sees it (the input commits
    to a root the proofs do not fold to)."""
    w = World(depth, profile)
    toks = C.split_script_ccv(depth, profile)
    bad = {t for t in toks if isinstance(t, str)} - ALLOWED
    check(not bad, f"SPLIT: opcodes outside the CCV candidate set: {sorted(bad)}")
    w.compiled = dict(w.compiled); w.compiled["SPLIT"] = assemble(toks)
    w.m = lt.taptree_root([lt.tapleaf_hash(c) for c in w.compiled.values()])
    alice = mk_leaf("alice", 500_000)
    oper = mk_leaf("operator", 1_000_000)
    s_alice, s_oper = w.slot(alice, 0), w.slot(oper, (1 << depth) - 1)
    w.tree.leaves = {s_alice: alice, s_oper: oper}
    root = w.tree.root()
    bob = carve_of(alice, "bob", 200_000)
    s_bob = w.slot(bob, 3)
    spath = w.tree.path(s_alice)
    t1 = w.clone(); lt.apply_claim(t1, s_alice, s_bob, bob)
    cpath = t1.path(s_bob); r1 = t1.root()
    check(r1[1] == root[1], "SPLIT conserves sum")
    ctx = w.ctx([(r1[1], w.spk(r1))], extra_in=(600, P2WPKH))
    asig = schnorr_sign(ctx.sighash(), sk("alice-owner"))
    head = w.path_witness(cpath) + w.path_witness(spath) + [alice.serialize(), bob.serialize()]
    it = None
    try:
        it = w.run("SPLIT", head + [asig], ctx)
        check(True, "SPLIT authorised by the source owner's transaction signature")
    except ScriptError as e:
        check(False, f"SPLIT positive: {str(e)[:70]}")
    expect_fail(lambda: w.run("SPLIT", head + [schnorr_sign(ctx.sighash(), w.op_sk)], ctx),
                "SPLIT signed by the operator, not the owner")
    expect_fail(lambda: w.run("SPLIT", head + [schnorr_sign(ctx.sighash(), sk("bob-owner"))], ctx),
                "SPLIT signed by the recipient")
    expect_fail(lambda: w.run("SPLIT", head + [bytes(64)], ctx), "SPLIT garbage signature")
    vsig = schnorr_sign(lt.voucher_msg(w.m, alice, bob), sk("alice-owner"))
    expect_fail(lambda: w.run("SPLIT", head + [vsig], ctx),
                "SPLIT with a voucher signature instead of a transaction signature")
    greedy = carve_of(alice, "greedy", alice.amount + 1)
    expect_fail(lambda: w.run("SPLIT", w.path_witness(cpath) + w.path_witness(spath) +
                              [alice.serialize(), greedy.serialize(), asig], ctx),
                "SPLIT over-split underflow")
    # 7.5 rule 5: another evictor key, a later evict_after
    for label, lf in (("another evictor key", mk_leaf("escape", 200_000, w.op_pk, alice.evict_after)),
                      ("a later evict_after", mk_leaf("later", 200_000, None, alice.evict_after + 1))):
        t_e = w.clone(); t_e.leaves[s_alice] = alice.with_amount_seq(alice.amount - lf.amount, alice.seq + 1)
        s_e = w.slot(lf, 3); cp_e = t_e.path(s_e); t_e.leaves[s_e] = lf; r_e = t_e.root()
        ctx_e = w.ctx([(r_e[1], w.spk(r_e))], extra_in=(600, P2WPKH))
        expect_fail(lambda: w.run("SPLIT", w.path_witness(cp_e) + w.path_witness(spath) +
                                  [alice.serialize(), lf.serialize(), schnorr_sign(ctx_e.sighash(), sk("alice-owner"))], ctx_e),
                    f"SPLIT into a leaf with {label} than its source")
    occupied = w.tree.path(s_oper)
    expect_fail(lambda: w.run("SPLIT", w.path_witness(occupied) + w.path_witness(spath) +
                              [alice.serialize(), bob.serialize(), asig], ctx),
                "SPLIT into an occupied position")

    # 7.5 rule 6: the new leaf is at least DUST_MIN and the residual is zero
    # (the source position becomes E_0) or at least DUST_MIN
    def carve(lf):
        t_c = w.clone(); s_c = w.slot(lf, 3)
        if lf.amount == alice.amount:
            del t_c.leaves[s_alice]
        else:
            t_c.leaves[s_alice] = alice.with_amount_seq(alice.amount - lf.amount, alice.seq + 1)
        cp_c = t_c.path(s_c); t_c.leaves[s_c] = lf; r_c = t_c.root()
        ctx_c = w.ctx([(r_c[1], w.spk(r_c))], extra_in=(600, P2WPKH))
        return (w.path_witness(cp_c) + w.path_witness(spath) +
                [alice.serialize(), lf.serialize(), schnorr_sign(ctx_c.sighash(), sk("alice-owner"))]), ctx_c
    for label, amt in (("one satoshi", 1), ("zero satoshis", 0), ("a one-satoshi residual", alice.amount - 1)):
        wit_d, ctx_d = carve(carve_of(alice, f"dust{amt}", amt))
        expect_fail(lambda: w.run("SPLIT", wit_d, ctx_d), f"SPLIT of {label} (7.5 rule 6)")
    for label, amt in (("exactly DUST_MIN", lt.DUST_MIN), ("the whole balance", alice.amount)):
        wit_d, ctx_d = carve(carve_of(alice, f"ok{amt}", amt))
        w.run("SPLIT", wit_d, ctx_d)
        check(True, f"SPLIT of {label} succeeds")
    # output 0 must still equal ns (= os: a SPLIT moves no value).
    ctxu = w.ctx([(r1[1] - 1, w.spk(r1))], extra_in=(600, P2WPKH))
    expect_fail(lambda: w.run("SPLIT", head + [schnorr_sign(ctxu.sighash(), sk("alice-owner"))], ctxu),
                "SPLIT with output 0 below ns")
    # stale root: the input commits to the post-split root r1, the proofs
    # fold to the pre-split root; CHECK_INPUT fails.
    ctxs = TxContext([(r1[1], w.spk(r1)), (600, P2WPKH)], [(r1[1], w.spk(r1))],
                     internal_key=lt.ccv_internal_key(r1[0]), taptree_root=w.m)
    expect_fail(lambda: w.run("SPLIT", head + [schnorr_sign(ctxs.sighash(), sk("alice-owner"))], ctxs),
                "SPLIT against a stale root")
    return it, len(w.compiled["SPLIT"]), sum(len(x) for x in head + [asig])

# ----------------------------------------------------------- 0xC0 numerics --

C0_OPCODES = (BIP342_OPS | BIP441_OPS - {"OP_SUBSTR", "OP_LEFT", "OP_RIGHT", "OP_AND", "OP_DOWNSHIFT"}
              | OPTX_OPS | CCV_OPS | {"OP_CAT", "OP_GREATERTHANOREQUAL"})


class WorldC0:
    """The CCV tier under tapleaf 0xC0 numerics: MID's witness shapes minus
    r and m, the same CCV binding as the c2 tier."""

    def __init__(self, depth, profile):
        self.depth, self.sparse = depth, profile == "S"
        self.op_sk = sk("operator"); self.op_pk = pubkey_x(self.op_sk)
        self.scripts = C.all_scripts_ccv(depth, self.op_pk, (0, 2), (1, 2), profile, (2,),
                                         numeric="c0")
        for name, toks in self.scripts.items():
            bad = {t for t in toks if isinstance(t, str)} - C0_OPCODES
            check(not bad, f"c0 {name}: opcodes outside the c0 CCV set: {sorted(bad)}")
        self.compiled = {k: assemble(v, mode="c0") for k, v in self.scripts.items()}
        self.m = lt.taptree_root([lt.tapleaf_hash(c, 0xc0) for c in self.compiled.values()])
        self.tree = lt.Tree(depth)

    def slot(self, leaf, want=None):
        return M.position(leaf, self.depth) if self.sparse else want

    def pos(self, leaf):
        return M.w_pos(leaf) if self.sparse else []

    def pads_for(self, total):
        return list(M.pad(total))

    def spk(self, root):
        return lt.tree_spk_ccv(root[0], self.m)

    def ctx(self, outputs, extra_in, locktime=0):
        root = self.tree.root()
        return TxContext([(root[1], self.spk(root)), extra_in], outputs, locktime=locktime,
                         internal_key=lt.ccv_internal_key(root[0]), taptree_root=self.m)

    def run(self, name, wit, ctx):
        it = Interp(ctx, mode="c0")
        it.run(self.compiled[name], wit)
        return it

    def clone(self):
        t = lt.Tree(self.depth); t.leaves = dict(self.tree.leaves); return t


def test_c0(depth, profile):
    """The c0-numerics CCV suite: the c2 scenarios over MID's witnesses."""
    S = profile == "S"
    w = WorldC0(depth, profile)
    costs = {}

    def mk(label, amount, evictor=None, evict_after=0, nonce=None, seq=0):
        if nonce is None:
            nonce = int.from_bytes(lt.sha256(label.encode())[:4], "little")
        lf = lt.Leaf(amount, pubkey_x(sk(label + "-exit")), pubkey_x(sk(label + "-owner")),
                     evictor if evictor else lt.NUMS_X, evict_after, nonce, seq)
        while S and not M.pos_ok(lf):
            lf.nonce = (lf.nonce + 1) & 0xffffffff
        return lf

    def exit_witness(leaf, slot, sig, is_evict, root, new_total):
        path = w.tree.path(slot)
        # bottom..top: [zf wf] [zi wi] [levels] [pos] leaf(10)+pads sig is_evict
        return (list(M.pad(new_total)) + w.pads_for(root[1]) +
                M.w_levels(path, leaf.node(), lt.empty_node(0), S) +
                w.pos(leaf) + M.w_leaf_exit(leaf) + [sig, is_evict])

    alice = mk("alice", 50_000)
    bob = mk("bob", 125_000, w.op_pk, 800_000)
    oper = mk("operator", 1_000_000)
    s_a, s_b, s_o = w.slot(alice, 0), w.slot(bob, 5), w.slot(oper, (1 << depth) - 1)
    w.tree.leaves = {s_a: alice, s_b: bob, s_o: oper}

    # EXIT_1 owner (exact payout)
    root = w.tree.root()
    t1 = w.clone(); del t1.leaves[s_b]; r1 = t1.root()
    outputs = [(r1[1], w.spk(r1)), (bob.amount, lt.p2tr_spk(bob.exit_key)), (400, P2WPKH)]
    ctx = w.ctx(outputs, (5_000, P2WPKH))
    sig = schnorr_sign(ctx.sighash(), sk("bob-owner"))
    wit = exit_witness(bob, s_b, sig, b"", root, r1[1])
    it = w.run("EXIT_1", wit, ctx)
    costs["EXIT_1 (owner, c0)"] = (it, len(w.compiled["EXIT_1"]), sum(len(x) for x in wit))
    # negatives: inexact payout, forged leaf, wrong taptree on output 0.
    bad = list(outputs); bad[1] = (bob.amount - 1, lt.p2tr_spk(bob.exit_key))
    ctxb = w.ctx(bad, (5_000, P2WPKH)); sigb = schnorr_sign(ctxb.sighash(), sk("bob-owner"))
    expect_fail(lambda: w.run("EXIT_1", exit_witness(bob, s_b, sigb, b"", root, r1[1]), ctxb),
                "c0: inexact payout")
    fake = bob.with_amount_seq(bob.amount + 1, 0)
    expect_fail(lambda: w.run("EXIT_1", exit_witness(fake, s_b, sig, b"", root, r1[1]), ctx),
                "c0: forged leaf")
    badt = list(outputs); badt[0] = (r1[1], lt.tree_spk_ccv(r1[0], lt.sha256(b"other-tree")))
    ctxt = w.ctx(badt, (5_000, P2WPKH)); sigt = schnorr_sign(ctxt.sighash(), sk("bob-owner"))
    expect_fail(lambda: w.run("EXIT_1", exit_witness(bob, s_b, sigt, b"", root, r1[1]), ctxt),
                "c0: output 0 under a wrong taptree")

    # EXIT_1 evict
    ctx_e = w.ctx(outputs[:2], (5_000, P2WPKH), locktime=800_000)
    esig = schnorr_sign(ctx_e.sighash(), w.op_sk)
    wit_e = exit_witness(bob, s_b, esig, b"\x01", root, r1[1])
    it = w.run("EXIT_1", wit_e, ctx_e)
    costs["EXIT_1 (evict, c0)"] = (it, len(w.compiled["EXIT_1"]), sum(len(x) for x in wit_e))
    ctx_early = w.ctx(outputs[:2], (5_000, P2WPKH), locktime=799_999)
    esig2 = schnorr_sign(ctx_early.sighash(), w.op_sk)
    expect_fail(lambda: w.run("EXIT_1", exit_witness(bob, s_b, esig2, b"\x01", root, r1[1]), ctx_early),
                "c0: early evict")
    w.tree = t1

    # terminal exit on a solo tree
    solo = mk("solo", 77_000)
    main_tree = w.clone()
    w.tree = lt.Tree(depth); w.tree.leaves = {w.slot(solo, 2): solo}
    root = w.tree.root()
    spath = w.tree.path(w.slot(solo, 2))
    outputs = [(600, P2WPKH), (solo.amount, lt.p2tr_spk(solo.exit_key))]
    ctx = w.ctx(outputs, (1_000, P2WPKH))
    ssig = schnorr_sign(ctx.sighash(), sk("solo-owner"))
    wit = (list(M.pad(solo.amount)) + w.pads_for(root[1]) +
           M.w_levels(spath, solo.node(), lt.empty_node(0), S) +
           w.pos(solo) + M.w_leaf_exit(solo) + [ssig, b""])
    it = w.run("EXIT_1", wit, ctx)
    costs["EXIT_1 (terminal, c0)"] = (it, len(w.compiled["EXIT_1"]), sum(len(x) for x in wit))
    w.tree = main_tree
    root = w.tree.root()

    # JOIN (dense: subtree h=2; sparse: single leaf)
    carol = mk("carol", 60_000, w.op_pk, 900_000)
    dave = mk("dave", 45_000, w.op_pk, 900_000)
    if not S and depth >= 4:
        h, idx = 2, 2
        jpath = w.tree.path(idx << h, height=h)
        t2 = w.clone(); lt.apply_join(t2, h, idx, {0: carol, 3: dave})
        new_node, r2 = t2.subtree(h, idx), t2.root()
        ctx = w.ctx([(r2[1], w.spk(r2)), (900, P2WPKH)], (new_node[1] + 2_000, P2WPKH))
        osig = schnorr_sign(ctx.sighash(), w.op_sk)
        wit = (list(M.pad(r2[1])) + w.pads_for(root[1]) +
               M.w_levels(jpath, lt.empty_node(h), new_node, False, h) +
               [new_node[0], M.scriptnum(new_node[1]), osig])
        it = w.run("JOIN_2", wit, ctx)
        costs["JOIN_2 (c0)"] = (it, len(w.compiled["JOIN_2"]), sum(len(x) for x in wit))
        usig = schnorr_sign(ctx.sighash(), sk("alice-owner"))
        expect_fail(lambda: w.run("JOIN_2", wit[:-1] + [usig], ctx), "c0: join without operator")
        w.tree = t2
        s_carol, s_dave = (idx << h), (idx << h) + 3
    else:
        for lf in (carol, dave):
            root = w.tree.root()
            slot = w.slot(lf, 3)
            jpath = w.tree.path(slot)
            t2 = w.clone(); t2.leaves[slot] = lf
            r2 = t2.root()
            ctx = w.ctx([(r2[1], w.spk(r2))], (lf.amount + 500, P2WPKH))
            osig = schnorr_sign(ctx.sighash(), w.op_sk)
            wit = (list(M.pad(r2[1])) + w.pads_for(root[1]) +
                   M.w_levels(jpath, lt.empty_node(0), lf.node(), True) +
                   w.pos(lf) + M.w_leaf(lf) + [osig])
            it = w.run("JOIN_0", wit, ctx)
            costs["JOIN_0 (c0)"] = (it, len(w.compiled["JOIN_0"]), sum(len(x) for x in wit))
            w.tree = t2
        s_carol, s_dave = w.slot(carol), w.slot(dave)

    # UPDATE
    root = w.tree.root()
    upath = w.tree.path(s_a)
    alice2 = alice.with_amount_seq(80_000, 1)
    t4 = w.clone(); t4.leaves[s_a] = alice2
    r4 = t4.root()
    ctx = w.ctx([(r4[1], w.spk(r4))], (30_700, P2WPKH))
    osig = schnorr_sign(ctx.sighash(), w.op_sk)
    asig = schnorr_sign(ctx.sighash(), sk("alice-owner"))
    wit = ([b""] + list(M.pad(r4[1])) + w.pads_for(root[1]) +      # the mode flag (assign) below the pads
           M.w_levels(upath, alice.node(), alice2.node(), S) +
           w.pos(alice) + M.w_leaf(alice) + M.w_leaf(alice2) + [asig, osig])
    it = w.run("UPDATE", wit, ctx)
    costs["UPDATE (c0)"] = (it, len(w.compiled["UPDATE"]), sum(len(x) for x in wit))
    expect_fail(lambda: w.run("UPDATE", wit[:-1] + [osig], ctx), "c0: update without owner")

    # UPDATE^x (exit-key consent, spec 7.4 rule 5), swapped into the
    # taptree as UPDATE_X for this step only.
    saved = (dict(w.compiled), w.m)
    xs = C._update_script_ccv0(depth, w.op_pk, S, exit_consent=True)
    bad = {t for t in xs if isinstance(t, str)} - C0_OPCODES
    check(not bad, f"c0 UPDATE_X: opcodes outside the c0 CCV set: {sorted(bad)}")
    w.compiled["UPDATE_X"] = assemble(xs, mode="c0")
    w.m = lt.taptree_root([lt.tapleaf_hash(c, 0xc0) for c in w.compiled.values()])
    ctx = w.ctx([(r4[1], w.spk(r4))], (30_700, P2WPKH))
    osig = schnorr_sign(ctx.sighash(), w.op_sk)
    asig = schnorr_sign(ctx.sighash(), sk("alice-owner"))
    xsig = schnorr_sign(ctx.sighash(), sk("alice-exit"))
    block = ([b""] + list(M.pad(r4[1])) + w.pads_for(root[1]) +
             M.w_levels(upath, alice.node(), alice2.node(), S) +
             w.pos(alice) + M.w_leaf(alice) + M.w_leaf(alice2))
    try:
        it = w.run("UPDATE_X", block + [asig, osig, xsig], ctx)
        check(True, "c0: UPDATE^x with owner, operator and exit signatures")
        costs["UPDATE_X (c0)"] = (it, len(w.compiled["UPDATE_X"]),
                                  sum(len(x) for x in block + [asig, osig, xsig]))
    except ScriptError as e:
        check(False, f"c0: UPDATE^x positive: {str(e)[:70]}")
    expect_fail(lambda: w.run("UPDATE_X", block + [asig, osig, asig], ctx), "c0: UPDATE^x exit_sig by the wrong key")
    expect_fail(lambda: w.run("UPDATE_X", block + [asig, osig], ctx), "c0: UPDATE^x missing exit_sig")
    # a net decrease spends under the DEDUCT flag (spec 4.6), not under assign
    alice3 = alice.with_amount_seq(20_000, 1)
    t3 = w.clone(); t3.leaves[s_a] = alice3; r3 = t3.root()
    ctx3 = w.ctx([(r3[1], w.spk(r3))], (700, P2WPKH))
    sigs3 = [schnorr_sign(ctx3.sighash(), k) for k in (sk("alice-owner"), w.op_sk, sk("alice-exit"))]
    dec = (list(M.pad(r3[1])) + w.pads_for(root[1]) + M.w_levels(upath, alice.node(), alice3.node(), S) +
           w.pos(alice) + M.w_leaf(alice) + M.w_leaf(alice3) + sigs3)
    try:
        run_fresh(w, "UPDATE_X", [b"\x01"] + dec, ctx3)
        check(True, "c0: UPDATE^x: a net decrease spends under the DEDUCT flag")
    except ScriptError as e:
        check(False, f"c0: UPDATE^x decrease positive: {str(e)[:70]}")
    expect_fail(lambda: run_fresh(w, "UPDATE_X", [b""] + dec, ctx3), "c0: UPDATE^x: a net decrease under the assign flag")
    w.compiled, w.m = saved
    w.tree = t4

    # EXIT_2 (carol owner + dave evict)
    if "EXIT_2" in w.compiled:
        root = w.tree.root()
        t7 = w.clone()
        path_c = t7.path(s_carol); del t7.leaves[s_carol]
        path_d = t7.path(s_dave); del t7.leaves[s_dave]
        r7 = t7.root()
        outputs = [(r7[1], w.spk(r7)), (carol.amount, lt.p2tr_spk(carol.exit_key)),
                   (dave.amount, lt.p2tr_spk(dave.exit_key))]
        ctx = w.ctx(outputs, (5_000, P2WPKH), locktime=900_000)
        csig = schnorr_sign(ctx.sighash(), sk("carol-owner"))
        dsig = schnorr_sign(ctx.sighash(), w.op_sk)
        b2 = (M.w_levels(path_d, dave.node(), lt.empty_node(0), S) +
              w.pos(dave) + M.w_leaf_exit(dave) + [dsig, b"\x01"])
        b1 = (w.pads_for(root[1]) + M.w_levels(path_c, carol.node(), lt.empty_node(0), S) +
              w.pos(carol) + M.w_leaf_exit(carol) + [csig, b""])
        wit = list(M.pad(r7[1])) + b2 + b1
        it = w.run("EXIT_2", wit, ctx)
        costs["EXIT_2 (c0)"] = (it, len(w.compiled["EXIT_2"]), sum(len(x) for x in wit))
        stale = (M.w_levels(w.tree.path(s_dave), dave.node(), lt.empty_node(0), S) +
                 w.pos(dave) + M.w_leaf_exit(dave) + [dsig, b"\x01"])
        expect_fail(lambda: w.run("EXIT_2", list(M.pad(r7[1])) + stale + b1, ctx),
                    "c0: EXIT_2 stale second path")
    return costs


def test_evict_subtree_ccv(depth, height, numeric="c2", full=False):
    """EVICT_SUBTREE_h (spec 7.7) under CCV, mirroring
    test_scripts.test_evict_subtree: the same cohort (every fifth
    position already exited, or every position occupied with full=True)
    and the same negatives, plus the CCV-specific ones (output 0 under a
    wrong taptree, a payout to a tweaked key). In 0xC2 the witness is
    FULL's minus r and m; in 0xC0 it is the MID sweep's minus r and m.
    Returns (interp, script bytes, witness) for the positive run."""
    c0 = numeric == "c0"
    name = f"EVICT_SUBTREE_{height}"
    if c0:
        w = WorldC0(depth, "D")
        toks = C._evict_subtree_script_ccv0(depth, height, w.op_pk)
        allowed, mode, lv = C0_OPCODES, "c0", 0xc0
    else:
        w = World(depth, "D")
        toks = C.evict_subtree_script_ccv(depth, height, w.op_pk)
        allowed, mode, lv = ALLOWED, "c2", 0xc2
    bad = {t for t in toks if isinstance(t, str)} - allowed
    check(not bad, f"{numeric} {name}: opcodes outside the CCV set: {sorted(bad)}")
    w.compiled = dict(w.compiled); w.compiled[name] = assemble(toks, mode=mode)
    w.m = lt.taptree_root([lt.tapleaf_hash(c, lv) for c in w.compiled.values()])
    n = 1 << height
    idx = 1
    base = idx << height
    cohort = {base + i: mk_leaf(f"c{i}", 10_000 + 7 * i, w.op_pk, 800_000)
              for i in range(n) if full or i % 5 != 3}
    w.tree.leaves = dict(cohort)
    w.tree.leaves[0] = mk_leaf("alice", 50_000)
    w.tree.leaves[(1 << depth) - 1] = mk_leaf("operator", 1_000_000)

    def sweep_outputs(tree, spk_of=None):
        rest = lt.Tree(depth)
        rest.leaves = {p: l for p, l in tree.leaves.items() if not base <= p < base + n}
        r = rest.root()
        return [(r[1], (spk_of or w.spk)(r))] + [
            (tree.leaves[base + i].amount, lt.p2tr_spk(tree.leaves[base + i].exit_key))
            for i in range(n) if base + i in tree.leaves]

    def body(tree):
        if c0:
            return M.w_evict_subtree(tree, depth, height, idx)
        wit = []
        for d, sib in reversed(tree.path(base, height=height)):
            wit += [b"\x01" if d else b"", sc_bytes(sib)]
        return wit + [tree.leaves[base + i].serialize() if base + i in tree.leaves else b""
                      for i in reversed(range(n))]

    def run(outs, locktime=800_000, tree=None, signer=None):
        saved = w.tree
        if tree is not None:
            w.tree = tree
        try:
            ctx = w.ctx(outs, (5_000, P2WPKH), locktime=locktime)
            wit = body(w.tree) + [schnorr_sign(ctx.sighash(), signer or w.op_sk)]
            return w.run(name, wit, ctx), wit
        finally:
            w.tree = saved
    outputs = sweep_outputs(w.tree) + [(400, P2WPKH)]
    it, wit = None, []
    try:
        it, wit = run(outputs)
        check(True, f"{numeric}: {name} sweeps {len(cohort)} leaves")
    except ScriptError as e:
        check(False, f"{numeric}: {name} positive: {str(e)[:90]}")
    tag = f"{numeric}: {name}"
    expect_fail(lambda: run(outputs, locktime=799_999), f"{tag} before lease expiry")
    short = list(outputs); short[1] = (outputs[1][0] - 1, outputs[1][1])
    expect_fail(lambda: run(short), f"{tag} shortchanges a leaf")
    t_n = w.clone()
    t_n.leaves[next((base + i for i in range(n) if base + i not in cohort), base)] = mk_leaf("stubborn", 5_000)
    expect_fail(lambda: run(sweep_outputs(t_n), tree=t_n), f"{tag} with a non-evictable leaf")
    expect_fail(lambda: run(outputs, signer=sk("alice-owner")), f"{tag} without the operator signature")
    wrong = sweep_outputs(w.tree, lambda r: lt.tree_spk_ccv(r[0], lt.sha256(b"wrong-taptree"))) + [(400, P2WPKH)]
    expect_fail(lambda: run(wrong), f"{tag} output 0 under a wrong taptree")
    tweaked = list(outputs)
    first = cohort[min(cohort)]
    tweaked[1] = (first.amount, lt.tree_spk_ccv(first.exit_key, w.m))
    expect_fail(lambda: run(tweaked), f"{tag} payout to a tweaked exit key")
    return it, len(w.compiled[name]), sum(len(x) for x in wit)


def test_split_ccv0(depth, profile):
    """SPLIT (spec 7.5.2) under the CCV tier's 0xC0 numerics: MID's carve
    witness minus r and m. Mirrors test_mid.test_split and
    test_split_ccv."""
    S = profile == "S"
    w = WorldC0(depth, profile)
    toks = C._split_script_ccv0(depth, S)
    bad = {t for t in toks if isinstance(t, str)} - C0_OPCODES
    check(not bad, f"c0 SPLIT: opcodes outside the c0 CCV set: {sorted(bad)}")
    w.compiled = dict(w.compiled); w.compiled["SPLIT"] = assemble(toks, mode="c0")
    w.m = lt.taptree_root([lt.tapleaf_hash(c, 0xc0) for c in w.compiled.values()])

    def mk(label, amount, evictor=None, evict_after=0):
        lf = mk_leaf(label, amount, evictor, evict_after)
        while S and not M.pos_ok(lf):
            lf.nonce = (lf.nonce + 1) & 0xffffffff
        return lf
    alice = mk("alice", 500_000)
    oper = mk("operator", 1_000_000)
    s_a, s_o = w.slot(alice, 0), w.slot(oper, (1 << depth) - 1)
    w.tree.leaves = {s_a: alice, s_o: oper}
    root = w.tree.root()
    bob = mk("bob", 200_000, alice.evictor_key, alice.evict_after)
    s_b = w.slot(bob, 3)
    spath = w.tree.path(s_a)
    t1 = w.clone(); lt.apply_claim(t1, s_a, s_b, bob)
    src2 = t1.leaves[s_a]
    r1 = t1.root()
    check(r1[1] == root[1], "c0: SPLIT conserves sum")

    def head(new, s_new, cnode, amt_new, claim_ea=None):
        t = w.clone(); t.leaves[s_a] = src2; t.leaves[s_new] = new
        ex = M.w_carve_extras(alice, new, amt_new=amt_new, claim_ea=claim_ea)
        return (list(M.pad(t.root()[1])) + M.w_levels(t.path(s_new), lt.EMPTY_NODE, new.node(), S) +
                w.pos(new) + w.pads_for(root[1]) + M.w_levels(spath, alice.node(), cnode, S) +
                w.pos(alice) + M.w_leaf(alice) + M.w_leaf(new) + ex)
    ctx = w.ctx([(r1[1], w.spk(r1))], (600, P2WPKH))
    asig = schnorr_sign(ctx.sighash(), sk("alice-owner"))
    h0 = head(bob, s_b, src2.node(), alice.amount - bob.amount)
    it = None
    try:
        it = w.run("SPLIT", h0 + [asig], ctx)
        check(True, "c0: SPLIT authorised by the source owner")
    except ScriptError as e:
        check(False, f"c0: SPLIT positive: {str(e)[:70]}")
    expect_fail(lambda: w.run("SPLIT", h0 + [schnorr_sign(ctx.sighash(), w.op_sk)], ctx),
                "c0: SPLIT signed by the operator")
    expect_fail(lambda: w.run("SPLIT", h0 + [schnorr_sign(ctx.sighash(), sk("bob-owner"))], ctx),
                "c0: SPLIT signed by the recipient")
    expect_fail(lambda: w.run("SPLIT", h0 + [bytes(64)], ctx), "c0: SPLIT garbage signature")
    vsig = schnorr_sign(lt.voucher_msg(w.m, alice, bob), sk("alice-owner"))
    expect_fail(lambda: w.run("SPLIT", h0 + [vsig], ctx), "c0: SPLIT with a voucher signature")
    greedy = mk("greedy", alice.amount + 1, alice.evictor_key, alice.evict_after)
    expect_fail(lambda: w.run("SPLIT", head(greedy, w.slot(greedy, 3), src2.node(), 0) + [asig], ctx),
                "c0: SPLIT over-split underflow")
    # 7.5 rule 5: another evictor key, a later evict_after
    for label, lf in (("another evictor key", mk("escape", 200_000, w.op_pk, alice.evict_after)),
                      ("a later evict_after", mk("later", 200_000, None, alice.evict_after + 1))):
        s_e = w.slot(lf, 3)
        t_e = w.clone(); t_e.leaves[s_a] = src2; t_e.leaves[s_e] = lf; r_e = t_e.root()
        ctx_e = w.ctx([(r_e[1], w.spk(r_e))], (600, P2WPKH))
        expect_fail(lambda: w.run("SPLIT", head(lf, s_e, src2.node(), alice.amount - lf.amount) +
                                  [schnorr_sign(ctx_e.sighash(), sk("alice-owner"))], ctx_e),
                    f"c0: SPLIT into a leaf with {label} than its source")
    # NONNEG on the claim lease (7.5 rule 5, 10.6): `01 00 00 81` is a
    # negative CScriptNum with an empty pad, which the compare alone would
    # accept against alice's lease of 0.
    planted = mk("planted", 200_000, alice.evictor_key, 0)
    planted.evict_after = 0x81000001
    s_p = w.slot(planted, 3)
    t_p = w.clone(); t_p.leaves[s_a] = src2; t_p.leaves[s_p] = planted; r_p = t_p.root()
    ctx_p = w.ctx([(r_p[1], w.spk(r_p))], (600, P2WPKH))
    expect_fail(lambda: w.run("SPLIT", head(planted, s_p, src2.node(), alice.amount - planted.amount, claim_ea=NEG_LEASE_EA) +
                              [schnorr_sign(ctx_p.sighash(), sk("alice-owner"))], ctx_p),
                "c0: SPLIT into a leaf with evict_after 01 00 00 81 (a negative CScriptNum lease)")
    if not S:
        occ = mk("bob", 200_000, alice.evictor_key, alice.evict_after)
        expect_fail(lambda: w.run("SPLIT", head(occ, s_o, src2.node(), alice.amount - occ.amount) + [asig], ctx),
                    "c0: SPLIT into an occupied position")

    # 7.5 rule 6: the new leaf is at least DUST_MIN and the residual is zero
    # (the source position becomes E_0) or at least DUST_MIN
    def carve(lf):
        amt_new = alice.amount - lf.amount
        t_c = w.clone(); s_c = w.slot(lf, 3)
        if amt_new == 0:
            del t_c.leaves[s_a]; cnode = lt.EMPTY_NODE
        else:
            src_c = alice.with_amount_seq(amt_new, alice.seq + 1); t_c.leaves[s_a] = src_c; cnode = src_c.node()
        cp_c = t_c.path(s_c); t_c.leaves[s_c] = lf; r_c = t_c.root()
        ctx_c = w.ctx([(r_c[1], w.spk(r_c))], (600, P2WPKH))
        return (list(M.pad(r_c[1])) + M.w_levels(cp_c, lt.EMPTY_NODE, lf.node(), S) + w.pos(lf) +
                w.pads_for(root[1]) + M.w_levels(spath, alice.node(), cnode, S) + w.pos(alice) +
                M.w_leaf(alice) + M.w_leaf(lf) + M.w_carve_extras(alice, lf, amt_new=amt_new) +
                [schnorr_sign(ctx_c.sighash(), sk("alice-owner"))]), ctx_c
    for label, amt in (("one satoshi", 1), ("zero satoshis", 0), ("a one-satoshi residual", alice.amount - 1)):
        wit_d, ctx_d = carve(mk(f"dust{amt}", amt, alice.evictor_key, alice.evict_after))
        expect_fail(lambda: w.run("SPLIT", wit_d, ctx_d), f"c0: SPLIT of {label} (7.5 rule 6)")
    for label, amt in (("exactly DUST_MIN", lt.DUST_MIN), ("the whole balance", alice.amount)):
        wit_d, ctx_d = carve(mk(f"ok{amt}", amt, alice.evictor_key, alice.evict_after))
        w.run("SPLIT", wit_d, ctx_d)
        check(True, f"c0: SPLIT of {label} succeeds")
    ctxu = w.ctx([(r1[1] - 1, w.spk(r1))], (600, P2WPKH))
    expect_fail(lambda: w.run("SPLIT", h0 + [schnorr_sign(ctxu.sighash(), sk("alice-owner"))], ctxu),
                "c0: SPLIT with output 0 below ns")
    ctxs = TxContext([(r1[1], w.spk(r1)), (600, P2WPKH)], [(r1[1], w.spk(r1))],
                     internal_key=lt.ccv_internal_key(r1[0]), taptree_root=w.m)
    expect_fail(lambda: w.run("SPLIT", h0 + [schnorr_sign(ctxs.sighash(), sk("alice-owner"))], ctxs),
                "c0: SPLIT against a stale root")
    mallory = mk("mallory", bob.amount, alice.evictor_key, alice.evict_after)
    s_m = w.slot(mallory, 3)
    tm = w.clone(); lt.apply_claim(tm, s_a, s_m, mallory); rm = tm.root()
    ctx_m = w.ctx([(rm[1], w.spk(rm))], (600, P2WPKH))
    expect_fail(lambda: w.run("SPLIT", head(mallory, s_m, src2.node(), alice.amount - mallory.amount) + [asig], ctx_m),
                "c0: SPLIT recipient swapped under the owner's signature")
    return it, len(w.compiled["SPLIT"]), sum(len(x) for x in h0 + [asig])


CSFS_OPS = {"OP_CHECKSIGFROMSTACK"}
TREE_ID = lt.tree_id(lt.sha256(b"creation-txid"), 0)


def test_claim_ccv(depth, profile, numeric="c2", hashlock=False):
    """CLAIM (7.5) and CLAIM^h (7.5.1) under CCV with the voucher message
    over tree_id of 6.2 / 7.5, in either numerics. Mirrors the FULL
    suite's voucher negatives: replay of a redeemed voucher, a voucher
    reused for another claim leaf, over-claim, wrong signer, and for
    CLAIM^h a wrong, short or absent preimage and the cross-form
    signatures; plus the CCV-specific ones: a voucher signed for another
    tree_id, a FULL-style voucher over m, and output 0 below ns.
    The script is swapped into the taptree as CLAIM or CLAIM_H, a
    tree-creation parameter as in the other tiers."""
    S = profile == "S"
    c0 = numeric == "c0"
    name = "CLAIM_H" if hashlock else "CLAIM"
    if c0:
        w = WorldC0(depth, profile)
        toks = C._claim_script_ccv0(depth, TREE_ID, S, hashlock)
        allowed, mode, lv = C0_OPCODES | CSFS_OPS, "c0", 0xc0
    else:
        w = World(depth, profile)
        toks = C.claim_script_ccv(depth, TREE_ID, profile, hashlock)
        allowed, mode, lv = ALLOWED | CSFS_OPS, "c2", 0xc2
    tag = f"{numeric} {profile}/{depth}: {name}"
    bad = {t for t in toks if isinstance(t, str)} - allowed
    check(not bad, f"{tag}: opcodes outside the CCV set plus CSFS: {sorted(bad)}")
    w.compiled = dict(w.compiled); w.compiled[name] = assemble(toks, mode=mode)
    w.m = lt.taptree_root([lt.tapleaf_hash(c, lv) for c in w.compiled.values()])

    def mk(label, amount, evictor=None, evict_after=0):
        lf = mk_leaf(label, amount, evictor, evict_after)
        while c0 and S and not M.pos_ok(lf):
            lf.nonce = (lf.nonce + 1) & 0xffffffff
        return lf
    alice = mk("alice", 50_000)
    oper = mk("operator", 1_000_000)
    s_a, s_o = w.slot(alice, 0), w.slot(oper, (1 << depth) - 1)
    w.tree.leaves = {s_a: alice, s_o: oper}
    root = w.tree.root()
    src = oper
    frank = mk("frank", 40_000, src.evictor_key, src.evict_after)
    s_f = w.slot(frank, 3)
    spath = w.tree.path(s_o)
    t1 = w.clone(); lt.apply_claim(t1, s_o, s_f, frank)
    src2 = t1.leaves[s_o]
    r1 = t1.root()
    preimage = lt.sha256(b"payment-preimage")
    phash = lt.sha256(preimage) if hashlock else None

    def head(tree, source, claim, s_src, s_claim, claim_ea=None):
        """Witness below the voucher signature for claiming `claim` out of
        `source` in `tree`, presenting s_claim as empty; claim_ea is passed
        to w_carve_extras."""
        t = lt.Tree(depth); t.leaves = dict(tree.leaves)
        amt_new = source.amount - claim.amount
        t.leaves[s_src] = source.with_amount_seq(max(amt_new, 0), source.seq + 1)
        if amt_new <= 0:
            del t.leaves[s_src]
        new_src_node = t.leaves[s_src].node() if s_src in t.leaves else lt.EMPTY_NODE
        sp = tree.path(s_src)
        t.leaves[s_claim] = claim
        cp = t.path(s_claim)
        if not c0:
            return w.path_witness(cp) + w.path_witness(sp) + [source.serialize(), claim.serialize()]
        ex = M.w_carve_extras(source, claim, amt_new=max(amt_new, 0), claim_ea=claim_ea)
        return (list(M.pad(t.root()[1])) + M.w_levels(cp, lt.EMPTY_NODE, claim.node(), S) + w.pos(claim) +
                w.pads_for(tree.root()[1]) + M.w_levels(sp, source.node(), new_src_node, S) + w.pos(source) +
                M.w_leaf(source) + M.w_leaf(claim) + ex)

    def vsig(tid, source, claim, key="operator-owner", ph=phash):
        msg = (lt.voucher_msg(tid, source, claim) if ph is None
               else lt.voucher_h_msg(tid, source, claim, ph))
        return schnorr_sign(msg, sk(key))

    def tail(sig, pre=preimage):
        return [sig] + ([pre] if hashlock and pre is not None else [])

    ctx = w.ctx([(r1[1], w.spk(r1))], (600, P2WPKH))
    h0 = head(w.tree, src, frank, s_o, s_f)
    good = vsig(TREE_ID, src, frank)
    it = None
    try:
        it = w.run(name, h0 + tail(good), ctx)
        check(True, f"{tag} redeemed")
    except ScriptError as e:
        check(False, f"{tag} positive: {str(e)[:90]}")
    # replay: the redeemed voucher against the post-claim tree (the source
    # leaf now carries seq + 1, so the signed source no longer exists).
    saved = w.tree
    w.tree = t1
    frank2 = mk("frank2", 40_000, src.evictor_key, src.evict_after)
    s_f2 = w.slot(frank2, 6)
    t2 = w.clone(); lt.apply_claim(t2, s_o, s_f2, frank2); r2 = t2.root()
    ctx_r = w.ctx([(r2[1], w.spk(r2))], (600, P2WPKH))
    expect_fail(lambda: w.run(name, head(t1, src2, frank2, s_o, s_f2) + tail(vsig(TREE_ID, src, frank2)), ctx_r),
                f"{tag} replay against the advanced source")
    expect_fail(lambda: w.run(name, head(t1, src2, frank, s_o, s_f2 if S else s_f2) + tail(good), ctx_r),
                f"{tag} redeemed voucher replayed")
    w.tree = saved
    # a voucher reused for a different claim leaf
    other = mk("other", 40_000, src.evictor_key, src.evict_after)
    s_x = w.slot(other, 3)
    tx_ = w.clone(); lt.apply_claim(tx_, s_o, s_x, other); rx = tx_.root()
    ctx_x = w.ctx([(rx[1], w.spk(rx))], (600, P2WPKH))
    expect_fail(lambda: w.run(name, head(w.tree, src, other, s_o, s_x) + tail(good), ctx_x),
                f"{tag} voucher reused for a different claim leaf")
    # over-claim
    greedy = mk("greedy", src.amount + 1, src.evictor_key, src.evict_after)
    s_g = w.slot(greedy, 3)
    expect_fail(lambda: w.run(name, head(w.tree, src, greedy, s_o, s_g) + tail(vsig(TREE_ID, src, greedy)), ctx),
                f"{tag} over-claim")
    # 7.5 rule 5: another evictor key, a later evict_after
    for label, lf in (("another evictor key", mk("escape", 40_000, w.op_pk, src.evict_after)),
                      ("a later evict_after", mk("later", 40_000, None, src.evict_after + 1))):
        s_e = w.slot(lf, 3)
        t_e = w.clone(); lt.apply_update(t_e, s_o, src.with_amount_seq(src.amount - lf.amount, src.seq + 1))
        t_e.leaves[s_e] = lf; r_e = t_e.root()
        ctx_e = w.ctx([(r_e[1], w.spk(r_e))], (600, P2WPKH))
        expect_fail(lambda: w.run(name, head(w.tree, src, lf, s_o, s_e) + tail(vsig(TREE_ID, src, lf)), ctx_e),
                    f"{tag} claim of a leaf with {label} than its source")
    if c0:
        # NONNEG on the claim lease (7.5 rule 5, 10.6): `01 00 00 81` is a
        # negative CScriptNum with an empty pad, which the compare alone
        # would accept against the source's lease of 0.
        planted = mk("planted", 40_000, src.evictor_key, 0)
        planted.evict_after = 0x81000001
        s_p = w.slot(planted, 3)
        t_p = w.clone(); lt.apply_update(t_p, s_o, src.with_amount_seq(src.amount - planted.amount, src.seq + 1))
        t_p.leaves[s_p] = planted; r_p = t_p.root()
        ctx_p = w.ctx([(r_p[1], w.spk(r_p))], (600, P2WPKH))
        expect_fail(lambda: w.run(name, head(w.tree, src, planted, s_o, s_p, claim_ea=NEG_LEASE_EA) +
                                  tail(vsig(TREE_ID, src, planted)), ctx_p),
                    f"{tag} claim of a leaf with evict_after 01 00 00 81 (a negative CScriptNum lease)")
    # 7.5 rule 6: a sub-dust claim leaf or residual fails; exactly DUST_MIN passes
    for label, amt in (("one satoshi", 1), ("zero satoshis", 0), ("a one-satoshi residual", src.amount - 1)):
        lf = mk(f"dust{amt}", amt, src.evictor_key, src.evict_after)
        s_d = w.slot(lf, 3)
        t_d = w.clone(); lt.apply_claim(t_d, s_o, s_d, lf); r_d = t_d.root()
        ctx_d = w.ctx([(r_d[1], w.spk(r_d))], (600, P2WPKH))
        expect_fail(lambda: w.run(name, head(w.tree, src, lf, s_o, s_d) + tail(vsig(TREE_ID, src, lf)), ctx_d),
                    f"{tag} claim of {label} (7.5 rule 6)")
    floor = mk("floor", lt.DUST_MIN, src.evictor_key, src.evict_after)
    s_fl = w.slot(floor, 3)
    t_f = w.clone(); lt.apply_claim(t_f, s_o, s_fl, floor); r_f = t_f.root()
    ctx_f = w.ctx([(r_f[1], w.spk(r_f))], (600, P2WPKH))
    w.run(name, head(w.tree, src, floor, s_o, s_fl) + tail(vsig(TREE_ID, src, floor)), ctx_f)
    check(True, f"{tag} claim of exactly DUST_MIN succeeds")
    # wrong signer, other tree_id, FULL-style voucher over m
    expect_fail(lambda: w.run(name, h0 + tail(vsig(TREE_ID, src, frank, "alice-owner")), ctx),
                f"{tag} wrong signer")
    other_tid = lt.tree_id(lt.sha256(b"creation-txid"), 1)
    expect_fail(lambda: w.run(name, h0 + tail(vsig(other_tid, src, frank)), ctx),
                f"{tag} voucher signed for another tree_id")
    expect_fail(lambda: w.run(name, h0 + tail(vsig(w.m, src, frank)), ctx),
                f"{tag} voucher over m (the FULL message)")
    ctx_u = w.ctx([(r1[1] - 1, w.spk(r1))], (600, P2WPKH))
    expect_fail(lambda: w.run(name, h0 + tail(good), ctx_u), f"{tag} output 0 below ns")
    # 7.5: the voucher binds the source body, not its amount, so a voucher
    # signed before an amount-only top-up of the source redeems against
    # the topped-up leaf, for its own amount or for more than the balance
    # at issuance; an over-claim against the new balance and any other
    # field change fail
    topped = src.with_amount_seq(src.amount + 500, src.seq)
    t_up = w.clone(); t_up.leaves[s_o] = topped
    w.tree = t_up
    for label, lf in (("the voucher's amount", frank),
                      ("more than the balance at issuance", mk("bigger", src.amount + 100, src.evictor_key, src.evict_after))):
        s_c = w.slot(lf, 3)
        t_c = w.clone(); lt.apply_claim(t_c, s_o, s_c, lf); r_c = t_c.root()
        ctx_c = w.ctx([(r_c[1], w.spk(r_c))], (600, P2WPKH))
        w.run(name, head(t_up, topped, lf, s_o, s_c) + tail(vsig(TREE_ID, src, lf)), ctx_c)
        check(True, f"{tag} a voucher signed before an amount-only top-up redeems {label} afterwards")
    over = mk("over", topped.amount + 1, src.evictor_key, src.evict_after)
    s_ov = w.slot(over, 3)
    expect_fail(lambda: w.run(name, head(t_up, topped, over, s_o, s_ov) + tail(vsig(TREE_ID, src, over)), ctx),
                f"{tag} over-claim against the topped-up balance")
    w.tree = saved
    for label, lf in (("exit_key", lt.Leaf(src.amount, pubkey_x(sk("other-exit")), src.owner_key, src.evictor_key, src.evict_after, src.nonce, src.seq)),
                      ("evictor_key", lt.Leaf(src.amount, src.exit_key, src.owner_key, w.op_pk, src.evict_after, src.nonce, src.seq)),
                      ("evict_after", lt.Leaf(src.amount, src.exit_key, src.owner_key, src.evictor_key, src.evict_after + 1, src.nonce, src.seq)),
                      ("seq", src.with_amount_seq(src.amount, src.seq + 1))):
        t_x = w.clone(); t_x.leaves[s_o] = lf
        expect_fail(lambda: w.run(name, head(t_x, lf, frank, s_o, s_f) + tail(good), ctx),
                    f"{tag} a voucher against a source whose {label} changed")
    if hashlock:
        expect_fail(lambda: w.run(name, h0 + tail(good, lt.sha256(b"wrong")), ctx), f"{tag} wrong preimage")
        expect_fail(lambda: w.run(name, h0 + tail(good, preimage[:31]), ctx), f"{tag} preimage not 32 bytes")
        expect_fail(lambda: w.run(name, h0 + [good], ctx), f"{tag} absent preimage")
        expect_fail(lambda: w.run(name, h0 + tail(vsig(TREE_ID, src, frank, ph=None)), ctx),
                    f"{tag} plain voucher under the hash lock")
    else:
        hsig = schnorr_sign(lt.voucher_h_msg(TREE_ID, src, frank, lt.sha256(preimage)), sk("operator-owner"))
        expect_fail(lambda: w.run(name, h0 + [hsig], ctx), f"{tag} hash-locked voucher under plain CLAIM")
    wit = h0 + tail(good)
    return it, len(w.compiled[name]), sum(len(x) for x in wit)


def test_claim_x_ccv(depth, profile, numeric="c2", hashlock=False):
    """CLAIM^x and CLAIM^hx (7.5.3) under CCV in either numerics, the FULL
    suite's test_claim_x: the dedicated credit leaf of 10.3, whose owner is
    the operator and whose exit key is the recipient's. The recipient's
    redemption with the voucher and its exit-key signature succeeds; an
    exit_sig by the operator, a garbage or absent exit_sig, a witness
    without the voucher, a transaction signature in place of the voucher,
    a voucher by the wrong signer or for another tree_id, an over-claim,
    the redeemed voucher replayed, the operator draining the leaf with a
    voucher to itself and, under the hash lock, a wrong preimage all fail;
    the plain CLAIM rejects the CLAIM^x witness. The script is swapped into
    the taptree as CLAIM_X or CLAIM_HX, a tree-creation parameter."""
    S = profile == "S"
    c0 = numeric == "c0"
    name = "CLAIM_HX" if hashlock else "CLAIM_X"
    if c0:
        w = WorldC0(depth, profile)
        toks = C._claim_script_ccv0(depth, TREE_ID, S, hashlock, exit_consent=True)
        plain = C._claim_script_ccv0(depth, TREE_ID, S, hashlock)
        allowed, mode, lv, over = C0_OPCODES | CSFS_OPS, "c0", 0xc0, 4
    else:
        w = World(depth, profile)
        toks = C.claim_script_ccv(depth, TREE_ID, profile, hashlock, exit_consent=True)
        plain = C.claim_script_ccv(depth, TREE_ID, profile, hashlock)
        allowed, mode, lv, over = ALLOWED | CSFS_OPS, "c2", 0xc2, 7
    tag = f"{numeric} {profile}/{depth}: {name}"
    bad = {t for t in toks if isinstance(t, str)} - allowed
    check(not bad, f"{tag}: opcodes outside the CCV set plus CSFS: {sorted(bad)}")
    w.compiled = dict(w.compiled)
    w.compiled[name] = assemble(toks, mode=mode)
    w.compiled["CLAIM_H" if hashlock else "CLAIM"] = assemble(plain, mode=mode)
    check(len(w.compiled[name]) - len(w.compiled["CLAIM_H" if hashlock else "CLAIM"]) == over,
          f"{tag} is {over} bytes over its plain form")
    w.m = lt.taptree_root([lt.tapleaf_hash(c, lv) for c in w.compiled.values()])

    def mk(label, amount, evictor=None, evict_after=0):
        lf = mk_leaf(label, amount, evictor, evict_after)
        while c0 and S and not M.pos_ok(lf):
            lf.nonce = (lf.nonce + 1) & 0xffffffff
        return lf
    credit = lt.Leaf(1_000_000, pubkey_x(sk("recipient-exit")), w.op_pk, lt.NUMS_X, 0,
                     int.from_bytes(lt.sha256(b"credit")[:4], "little"), 0)
    while c0 and S and not M.pos_ok(credit):
        credit.nonce = (credit.nonce + 1) & 0xffffffff
    alice = mk("alice", 50_000)
    s_credit, s_alice = w.slot(credit, (1 << depth) - 1), w.slot(alice, 0)
    w.tree.leaves = {s_credit: credit, s_alice: alice}
    root = w.tree.root()
    preimage = lt.sha256(b"credit-preimage")
    phash = lt.sha256(preimage) if hashlock else None

    def head(tree, source, claim, s_src, s_claim):
        """Witness below the voucher signature for claiming `claim` out of
        `source` in `tree`, presenting s_claim as empty; returns it with
        the post-claim tree."""
        t = lt.Tree(depth); t.leaves = dict(tree.leaves)
        amt_new = source.amount - claim.amount
        t.leaves[s_src] = source.with_amount_seq(max(amt_new, 0), source.seq + 1)
        if amt_new <= 0:
            del t.leaves[s_src]
        new_src_node = t.leaves[s_src].node() if s_src in t.leaves else lt.EMPTY_NODE
        sp = tree.path(s_src)
        t.leaves[s_claim] = claim
        cp = t.path(s_claim)
        if not c0:
            return w.path_witness(cp) + w.path_witness(sp) + [source.serialize(), claim.serialize()], t
        ex = M.w_carve_extras(source, claim, amt_new=max(amt_new, 0))
        return (list(M.pad(t.root()[1])) + M.w_levels(cp, lt.EMPTY_NODE, claim.node(), S) + w.pos(claim) +
                w.pads_for(tree.root()[1]) + M.w_levels(sp, source.node(), new_src_node, S) + w.pos(source) +
                M.w_leaf(source) + M.w_leaf(claim) + ex), t

    def vsig(tid, source, claim, key="operator", ph=phash):
        msg = (lt.voucher_msg(tid, source, claim) if ph is None
               else lt.voucher_h_msg(tid, source, claim, ph))
        return schnorr_sign(msg, sk(key))

    def tail(sig, pre=preimage):
        return [sig] + ([pre] if hashlock and pre is not None else [])

    claim = mk("recipient", 40_000, credit.evictor_key, credit.evict_after)
    s_claim = w.slot(claim, 3)
    h0, t1 = head(w.tree, credit, claim, s_credit, s_claim)
    r1 = t1.root()
    check(r1[1] == root[1], f"{tag} conserves the sum")
    ctx = w.ctx([(r1[1], w.spk(r1))], (600, P2WPKH))
    good = vsig(TREE_ID, credit, claim)
    xsig = schnorr_sign(ctx.sighash(), sk("recipient-exit"))
    it = None
    try:
        it = w.run(name, h0 + tail(good) + [xsig], ctx)
        check(True, f"{tag} redeemed with the voucher and the exit-key signature")
    except ScriptError as e:
        check(False, f"{tag} positive: {str(e)[:120]}")
    osig = schnorr_sign(ctx.sighash(), w.op_sk)
    expect_fail(lambda: w.run(name, h0 + tail(good) + [osig], ctx),
                f"{tag} exit_sig by the wrong key (the operator, who owns the leaf)")
    expect_fail(lambda: w.run(name, h0 + tail(good) + [bytes(64)], ctx), f"{tag} garbage exit_sig")
    expect_fail(lambda: w.run(name, h0 + tail(good), ctx), f"{tag} missing exit_sig")
    expect_fail(lambda: w.run("CLAIM_H" if hashlock else "CLAIM", h0 + tail(good) + [xsig], ctx),
                f"{tag} the plain form with the exit-consent witness")
    expect_fail(lambda: w.run(name, h0 + ([preimage] if hashlock else []) + [xsig], ctx),
                f"{tag} without the voucher")
    expect_fail(lambda: w.run(name, h0 + tail(osig) + [xsig], ctx),
                f"{tag} with a transaction signature in place of the voucher")
    expect_fail(lambda: w.run(name, h0 + tail(vsig(TREE_ID, credit, claim, "alice-owner")) + [xsig], ctx),
                f"{tag} voucher by the wrong signer")
    other_tid = lt.tree_id(lt.sha256(b"creation-txid"), 1)
    expect_fail(lambda: w.run(name, h0 + tail(vsig(other_tid, credit, claim)) + [xsig], ctx),
                f"{tag} voucher signed for another tree_id")
    expect_fail(lambda: w.run(name, h0 + tail(vsig(w.m, credit, claim)) + [xsig], ctx),
                f"{tag} voucher over m")
    greedy = mk("greedy", credit.amount + 1, credit.evictor_key, credit.evict_after)
    s_g = w.slot(greedy, 3)
    hg, tg = head(w.tree, credit, greedy, s_credit, s_g)
    ctx_g = w.ctx([(tg.root()[1], w.spk(tg.root()))], (600, P2WPKH))
    expect_fail(lambda: w.run(name, hg + tail(vsig(TREE_ID, credit, greedy)) +
                              [schnorr_sign(ctx_g.sighash(), sk("recipient-exit"))], ctx_g),
                f"{tag} over-claim")
    # replay against the advanced source
    saved = w.tree
    w.tree = t1
    credit2 = t1.leaves[s_credit]
    s_c2 = w.slot(mk("recipient2", 40_000, credit.evictor_key, credit.evict_after), 6)
    hr, tr = head(t1, credit2, claim, s_credit, s_c2)
    ctx_r = w.ctx([(tr.root()[1], w.spk(tr.root()))], (600, P2WPKH))
    expect_fail(lambda: w.run(name, hr + tail(good) + [schnorr_sign(ctx_r.sighash(), sk("recipient-exit"))], ctx_r),
                f"{tag} redeemed voucher replayed against the advanced source")
    w.tree = saved
    # the operator cannot drain the credit leaf; the recipient's consent lets the same drain through
    drain = mk("operator-drain", credit.amount, credit.evictor_key, credit.evict_after)
    s_drain = w.slot(drain, 6)
    hd, td = head(w.tree, credit, drain, s_credit, s_drain)
    ctx_d = w.ctx([(td.root()[1], w.spk(td.root()))], (600, P2WPKH))
    dsig = vsig(TREE_ID, credit, drain)
    expect_fail(lambda: w.run(name, hd + tail(dsig) + [schnorr_sign(ctx_d.sighash(), w.op_sk)], ctx_d),
                f"{tag} the operator draining the credit leaf with a voucher to itself")
    w.run(name, hd + tail(dsig) + [schnorr_sign(ctx_d.sighash(), sk("recipient-exit"))], ctx_d)
    check(True, f"{tag} the same drain with the recipient's exit-key signature")
    if hashlock:
        expect_fail(lambda: w.run(name, h0 + tail(good, lt.sha256(b"wrong")) + [xsig], ctx), f"{tag} wrong preimage")
        expect_fail(lambda: w.run(name, h0 + tail(good, preimage[:31]) + [xsig], ctx), f"{tag} preimage not 32 bytes")
        expect_fail(lambda: w.run(name, h0 + tail(vsig(TREE_ID, credit, claim, ph=None)) + [xsig], ctx),
                    f"{tag} plain voucher under the hash lock")
    else:
        hsig = schnorr_sign(lt.voucher_h_msg(TREE_ID, credit, claim, lt.sha256(preimage)), w.op_sk)
        expect_fail(lambda: w.run(name, h0 + [hsig, preimage, xsig], ctx),
                    f"{tag} with a hash-locked voucher and its preimage")
    wit = h0 + tail(good) + [xsig]
    return it, len(w.compiled[name]), sum(len(x) for x in wit)


def test_carve_rules_ccv(depth, numeric="c2"):
    """The carve rule (spec 7.5 rule 5) against the CCV cohort sweep in
    either numerics, as test_scripts.test_carve_rules: a cohort member's
    SPLIT of dust with a NUMS evictor or a later lease into the cohort's
    empty position fails, dust that keeps the member's terms lands and is
    swept by EVICT_SUBTREE_2, and a member the operator admitted with a
    NUMS evictor can still block the sweep (10.8)."""
    c0 = numeric == "c0"
    height = 2
    if c0:
        w = WorldC0(depth, "D")
        w.compiled = dict(w.compiled)
        w.compiled["SPLIT"] = assemble(C._split_script_ccv0(depth, False), mode="c0")
        w.compiled["EVICT_SUBTREE_2"] = assemble(C._evict_subtree_script_ccv0(depth, height, w.op_pk), mode="c0")
        w.m = lt.taptree_root([lt.tapleaf_hash(c, 0xc0) for c in w.compiled.values()])
    else:
        w = World(depth, "D")
        w.compiled = dict(w.compiled)
        w.compiled["SPLIT"] = assemble(C.split_script_ccv(depth, "D"))
        w.compiled["EVICT_SUBTREE_2"] = assemble(C.evict_subtree_script_ccv(depth, height, w.op_pk))
        w.m = lt.taptree_root([lt.tapleaf_hash(c) for c in w.compiled.values()])
    tag = f"{numeric} D/{depth}"
    n, base = 1 << height, 1 << height
    cohort = {base + i: mk_leaf(f"c{i}", 10_000 + 7 * i, w.op_pk, 800_000) for i in range(n - 1)}
    empty = base + n - 1
    alice = mk_leaf("alice", 50_000)

    def reset():
        w.tree = lt.Tree(depth); w.tree.leaves = dict(cohort); w.tree.leaves[0] = alice
        w.tree.leaves[(1 << depth) - 1] = mk_leaf("operator", 1_000_000)

    def path_w(path):
        return [x for d, sib in reversed(path) for x in ((b"\x01" if d else b""), sc_bytes(sib))]

    def split(src, s_src, new, signer):
        root = w.tree.root()
        src2 = src.with_amount_seq(src.amount - new.amount, src.seq + 1)
        t = w.clone(); t.leaves[s_src] = src2
        cpath = t.path(empty); t.leaves[empty] = new
        spath = w.tree.path(s_src)
        ctx = w.ctx([(t.root()[1], w.spk(t.root()))], (600, P2WPKH))
        if c0:
            wit = (list(M.pad(t.root()[1])) + M.w_levels(cpath, lt.EMPTY_NODE, new.node(), False) +
                   w.pads_for(root[1]) + M.w_levels(spath, src.node(), src2.node(), False) +
                   M.w_leaf(src) + M.w_leaf(new) + M.w_carve_extras(src, new))
        else:
            wit = path_w(cpath) + path_w(spath) + [src.serialize(), new.serialize()]
        return t, wit + [schnorr_sign(ctx.sighash(), sk(signer))], ctx

    def sweep(expect_ok, msg):
        rest = w.clone()
        for p in range(base, base + n):
            del rest.leaves[p]
        outs = [(rest.root()[1], w.spk(rest.root()))]
        outs += [(w.tree.leaves[p].amount, lt.p2tr_spk(w.tree.leaves[p].exit_key)) for p in range(base, base + n)]
        ctx = w.ctx(outs + [(400, P2WPKH)], (5_000, P2WPKH), locktime=800_000)
        if c0:
            body = M.w_evict_subtree(w.tree, depth, height, 1)
        else:
            body = path_w(w.tree.path(base, height=height)) + [w.tree.leaves[p].serialize() for p in reversed(range(base, base + n))]
        wit = body + [schnorr_sign(ctx.sighash(), w.op_sk)]
        if expect_ok:
            w.run("EVICT_SUBTREE_2", wit, ctx); check(True, msg)
        else:
            expect_fail(lambda: w.run("EVICT_SUBTREE_2", wit, ctx), msg)

    reset()
    member, s_member = cohort[base], base
    for label, dust in (("a NUMS evictor", mk_leaf("dust", lt.DUST_MIN)),
                        ("a later evict_after", mk_leaf("dust", lt.DUST_MIN, w.op_pk, 800_001))):
        _, wit, ctx = split(member, s_member, dust, "c0-owner")
        expect_fail(lambda: w.run("SPLIT", wit, ctx), f"{tag}: cohort member plants dust with {label}")
    t1, wit, ctx = split(member, s_member, carve_of(member, "dust", lt.DUST_MIN), "c0-owner")
    w.run("SPLIT", wit, ctx)
    check(True, f"{tag}: a carve that keeps the member's evictor and lease lands in the cohort")
    w.tree = t1
    sweep(True, f"{tag}: EVICT_SUBTREE_2 sweeps the cohort including the carved dust leaf")
    reset()
    t2, wit, ctx = split(alice, 0, carve_of(alice, "dust", lt.DUST_MIN), "alice-owner")
    w.run("SPLIT", wit, ctx)
    w.tree = t2
    sweep(False, f"{tag}: a non-evictable member's NUMS dust still blocks the sweep (10.8)")


def test_detach_ccv(depth, height, numeric="c2"):
    """DETACH_h (spec 7.10) under CCV in either numerics, mirroring
    test_scripts.test_detach: the detach succeeds and conserves the total
    across the two tree outputs, a member's old path truncated to its
    lower h levels is the detached tree's own path, an EXIT_1 from the
    detached tree succeeds with it, and (in 0xC2) a voucher issued in the
    parent redeems in the child, which inherits tree_id. Negatives: output
    1 under the wrong m_h, output 1 under the FULL-tier key, output 1
    shortchanged or overfunded, a missing operator signature, output 0
    keeping the subtree, an inflated subtree sum, the two tree outputs
    swapped, and (0xC0) a malformed sum pad.

    7.10 rule 3: the parent is created with CLAIM and UPDATE^x on top of
    the reference set, so m_h is that option set at depth h and differs
    from the reference set's m_h, under which the detach fails."""
    c0 = numeric == "c0"
    name = f"DETACH_{height}"
    tag = f"{numeric}: {name} D={depth}"
    opts = C.CCVTreeOptions(pubkey_x(sk("operator")), numeric, "D", TREE_ID, join_heights=(0, 2),
                            exit_ks=(1, 2), claim=True, update_x=True, detach_heights=(height,))
    if c0:
        w = WorldC0(depth, "D")
        allowed, mode, lv = C0_OPCODES | CSFS_OPS, "c0", 0xc0
    else:
        w = World(depth, "D")
        allowed, mode, lv = ALLOWED | CSFS_OPS, "c2", 0xc2
    w.scripts = opts.at_depth(depth)
    for nm, toks in w.scripts.items():
        bad = {t for t in toks if isinstance(t, str)} - allowed
        check(not bad, f"{tag}: {nm} opcodes outside the CCV set: {sorted(bad)}")
    w.compiled = {k: assemble(v, mode=mode) for k, v in w.scripts.items()}
    w.m = lt.taptree_root([lt.tapleaf_hash(c, lv) for c in w.compiled.values()])
    check(name in w.compiled and "CLAIM" in w.compiled and "UPDATE_X" in w.compiled,
          f"{tag}: the parent's option set carries DETACH_h, CLAIM and UPDATE^x")
    m_h = opts.taptree_root(height)
    ref_m_h = C.detached_taptree_root_ccv(height, w.op_pk, numeric)
    check(m_h != ref_m_h, f"{tag}: m_h from the parent's options differs from the reference set's m_h")
    check(C.detached_taptree_root_ccv(height, w.op_pk, numeric, opts) == m_h,
          f"{tag}: detached_taptree_root_ccv with the parent's options is the parent's set at depth h")
    n, base = 1 << height, 1 << height
    cohort = {base + i: mk_leaf(f"c{i}", 10_000 + 7 * i, w.op_pk, 800_000) for i in range(n) if i % 5 != 3}
    w.tree.leaves = dict(cohort)
    w.tree.leaves[0] = mk_leaf("alice", 50_000)
    w.tree.leaves[(1 << depth) - 1] = mk_leaf("operator", 1_000_000)
    root = w.tree.root()
    node = w.tree.subtree(height, 1)                      # (R_h, sum_h)
    path = w.tree.path(base, height=height)
    t1 = w.clone()
    for p_ in cohort:
        del t1.leaves[p_]
    r1 = t1.root()
    spk1 = lt.tree_spk_ccv(node[0], m_h)

    def body(nd=node, tree=None):
        tree = tree or w.tree
        if not c0:
            return w.path_witness(path, height) + [nd[0], lt.le64(nd[1])]
        return (list(M.pad(r1[1])) + w.pads_for(tree.root()[1]) +
                M.w_levels(path, nd, lt.empty_node(height), False, height) +
                [nd[0], M.scriptnum(nd[1]), *M.pad(nd[1])])

    def run(outs, extra=5_000, signer=None, nd=node, mutate=None):
        ctx = w.ctx(outs, (extra, P2WPKH))
        wit = body(nd)
        if mutate:
            wit = mutate(wit)
        return w.run(name, wit + [schnorr_sign(ctx.sighash(), signer or w.op_sk)], ctx)
    outputs = [(r1[1], w.spk(r1)), (node[1], spk1), (400, P2WPKH)]
    it = None
    try:
        it = run(outputs)
        check(True, f"{tag} detaches {len(cohort)} leaves into their own tree output")
    except ScriptError as e:
        check(False, f"{tag} positive: {str(e)[:120]}")
    check(r1[1] + node[1] == root[1], f"{tag} conserves the total across two tree outputs")
    # negatives
    expect_fail(lambda: run([outputs[0], (node[1], lt.tree_spk_ccv(node[0], ref_m_h)), outputs[2]]),
                f"{tag} output 1 under an m_h that drops the parent's options")
    expect_fail(lambda: run([outputs[0], (node[1], lt.tree_spk_ccv(node[0], w.m)), outputs[2]]),
                f"{tag} output 1 under the parent's own taptree")
    expect_fail(lambda: run([outputs[0], (node[1], lt.tree_spk(node[0], m_h)), outputs[2]]),
                f"{tag} output 1 under the FULL-tier key")
    expect_fail(lambda: run([outputs[0], (node[1] - 1, spk1), outputs[2]]), f"{tag} output 1 shortchanged")
    expect_fail(lambda: run([outputs[0], (node[1] + 1, spk1), outputs[2]], extra=6_000), f"{tag} output 1 overfunded")
    expect_fail(lambda: run(outputs, signer=sk("alice-owner")), f"{tag} without the operator signature")
    expect_fail(lambda: run([(root[1], w.spk(root)), (node[1], spk1), outputs[2]], extra=node[1] + 5_000),
                f"{tag} subtree not emptied in output 0 (new node not E_h)")
    expect_fail(lambda: run([outputs[0], (node[1] + 1, spk1), outputs[2]], extra=6_000, nd=(node[0], node[1] + 1)),
                f"{tag} inflated subtree sum")
    expect_fail(lambda: run([outputs[1], outputs[0], outputs[2]]), f"{tag} the two tree outputs swapped")
    if c0:
        def swap_pad(wit):
            b = list(wit); b[-2], b[-1] = b[-2] + b"\x00", b[-1][1:]
            return b
        expect_fail(lambda: run(outputs, mutate=swap_pad), f"{tag} malformed sum pad")

    # the detached tree: the same options at depth h
    w2 = WorldC0(height, "D") if c0 else World(height, "D")
    w2.scripts = opts.at_depth(height)
    w2.compiled = {k: assemble(v, mode=mode) for k, v in w2.scripts.items()}
    w2.m = lt.taptree_root([lt.tapleaf_hash(c, lv) for c in w2.compiled.values()])
    check(w2.m == m_h, f"{tag}: the detached tree's identifier is the parent's options compiled at depth h")
    check(list(w2.compiled) == ["EXIT_1", "EXIT_2", "JOIN_0", "JOIN_2", "JOINK_2", "UPDATE_X",
                                "EVICT_SUBTREE_1", "EVICT_SUBTREE_2", "CLAIM"],
          f"{tag}: the detached tree carries the parent's set less the heights that do not fit")
    w2.tree.leaves = {p_ - base: lf for p_, lf in cohort.items()}
    check(w2.tree.root() == node, f"{tag}: the detached tree's root is the detached node")
    victim = base + 2
    lf = cohort[victim]
    short = w.tree.path(victim)[:height]
    check(lt.fold(lf.node(), short) == node, f"{tag}: old path truncated to h levels verifies in the detached tree")
    check(short == w2.tree.path(victim - base), f"{tag}: the truncated path is the detached tree's own path")
    t2 = w2.clone(); del t2.leaves[victim - base]; r2 = t2.root()
    ctx2 = TxContext([(node[1], spk1), (5_000, P2WPKH)],
                     [(r2[1], w2.spk(r2)), (lf.amount, lt.p2tr_spk(lf.exit_key))],
                     internal_key=lt.ccv_internal_key(node[0]), taptree_root=m_h)
    sig2 = schnorr_sign(ctx2.sighash(), sk(f"c{victim - base}-owner"))
    if c0:
        wit2 = (list(M.pad(r2[1])) + list(M.pad(node[1])) + M.w_levels(short, lf.node(), lt.EMPTY_NODE, False) +
                M.w_leaf_exit(lf) + [sig2, b""])
    else:
        wit2 = w2.path_witness(short) + [lf.serialize(), sig2, b""]
    it2 = w2.run("EXIT_1", wit2, ctx2)
    check(True, f"{tag}: EXIT_1 from the detached depth-{height} tree with the truncated path")
    if not c0:
        # a voucher issued while the source leaf sat in the parent redeems in
        # the detached tree: it inherits tree_id (7.10 rule 3) and its CLAIM
        # carries the same constant, so no reissue after a detach (9.6)
        issuer = max(cohort)
        src = cohort[issuer]
        holder = mk_leaf("holder", 3_000, w.op_pk, 800_000)
        vsig = schnorr_sign(lt.voucher_msg(TREE_ID, src, holder), sk(f"c{issuer - base}-owner"))
        s_holder = next(i for i in range(n) if i not in w2.tree.leaves)
        t3 = w2.clone(); lt.apply_claim(t3, issuer - base, s_holder, holder); r3 = t3.root()
        ctx3 = TxContext([(node[1], spk1), (600, P2WPKH)], [(r3[1], w2.spk(r3))],
                         internal_key=lt.ccv_internal_key(node[0]), taptree_root=m_h)
        w2.run("CLAIM", w2.path_witness(t3.path(s_holder)) + w2.path_witness(w2.tree.path(issuer - base)) +
               [src.serialize(), holder.serialize(), vsig], ctx3)
        check(True, f"{tag}: a voucher issued in the parent redeems in the detached tree")
    wit = body() + [bytes(64)]
    return it, len(w.compiled[name]), sum(len(x) for x in wit)


def _needs_owner_sig_ccv(old, new, numeric):
    """Spec 7.9 rule 3 under the numerics' SEQ_FINAL (FULL's 0xFFFFFFFF in
    0xC2, MID's 0x7FFFFFFF in 0xC0), computed independently of the script."""
    seq_final = M.SEQ_FINAL if numeric == "c0" else ls.SEQ_FINAL
    if old is None or (new is not None and old.serialize() == new.serialize()):
        return False
    if (new is not None and new.serialize()[8:] == old.serialize()[8:] and new.amount >= old.amount
            and old.seq != seq_final):
        return False
    return True


def mode_flag(in_amount, old, new, n):
    """The output-0 mode flag of a CCV rewrite or update (spec 4.6),
    computed independently of the script and of the Go builder: 0x01
    (DEDUCT) exactly when the new sum is below the input's amount less the
    exit payouts of 7.9 rule 5, empty (assign) otherwise."""
    payouts = sum(old[i].amount for i in range(n) if old.get(i) and new.get(i) is None)
    new_sum = (in_amount - sum(lf.amount for lf in old.values() if lf)
               + sum(lf.amount for lf in new.values() if lf))
    return b"\x01" if new_sum < in_amount - payouts else b""


def _rewrite_blocks_c2(old, new, sigs, n, marker=True):
    """The position blocks of the 0xC2 REWRITE_h witness (bottom..top):
    block_{n-1} .. block_0, block_i = [xsig_i] [sig_i] new_i old_i, with
    the one-byte marker for an unchanged leaf's new element unless
    marker=False (FULL's layout, 8.9)."""
    items = []
    for i in reversed(range(n)):
        o, nw = old[i], new[i]
        items += list(reversed(sigs.get(i, [])))                # xsig below sig
        if marker and o is not None and nw is not None and o.serialize() == nw.serialize():
            items.append(ls.REWRITE_SAME)
        else:
            items.append(nw.serialize() if nw else b"")
        items.append(o.serialize() if o else b"")
    return items


def _plan_ccv(w, height, scenario):
    """test_scripts._rewrite_plan's scenarios plus four for the output-0
    mode flag (spec 4.6): every position occupied, and "decrease" lowers
    position 0 by 3,000 (owner-signed), "offset" lowers it by 300 and raises
    position 1 by 500 (net increase, assign), "exit_up" exits position 0 and
    raises position 1 by 500 (the exit's payout is deducted from the
    residual, the sum is still above it: assign) and "exit_down" exits
    position 0 and lowers position 1 by 3,000 (DEDUCT)."""
    if scenario not in ("decrease", "offset", "exit_up", "exit_down"):
        return TS._rewrite_plan(w, height, scenario)
    base, old, _ = TS._rewrite_plan(w, height, "update")
    new = dict(old)

    def by(i, d):
        return old[i].with_amount_seq(old[i].amount + d, old[i].seq)
    if scenario == "decrease":
        new[0] = by(0, -3_000)
    elif scenario == "offset":
        new[0], new[1] = by(0, -300), by(1, 500)
    elif scenario == "exit_up":
        new[0], new[1] = None, by(1, 500)
    else:
        new[0], new[1] = None, by(1, -3_000)
    return base, old, new


def rewrite_case_ccv(depth, height, numeric="c2", scenario="mixed", exit_consent=False):
    """Build a CCV REWRITE_h spend in either numerics for one of
    test_scripts._rewrite_plan's scenarios. Returns a dict with the world,
    the plan, the context, the positive witness and a `witness(old, new,
    ctx, ...)` builder, so the negatives can rebuild the witness from a
    mutated plan. The script is compiled through CCVTreeOptions, which
    carries rewrite_heights and rewrite_x as FULL's TreeOptions does."""
    c0 = numeric == "c0"
    name = f"REWRITE_X_{height}" if exit_consent else f"REWRITE_{height}"
    if c0:
        w = WorldC0(depth, "D")
        toks = C._rewrite_script_ccv0(depth, height, w.op_pk, exit_consent)
        allowed, mode, lv = C0_OPCODES, "c0", 0xc0
    else:
        w = World(depth, "D")
        toks = C.rewrite_script_ccv(depth, height, w.op_pk, exit_consent)
        allowed, mode, lv = ALLOWED, "c2", 0xc2
    tag = f"{numeric}: {name} D={depth}"
    bad = {t for t in toks if isinstance(t, str)} - allowed
    check(not bad, f"{tag} opcodes outside the CCV set: {sorted(bad)}")
    opts = C.CCVTreeOptions(w.op_pk, numeric, "D", rewrite_heights=(height,), rewrite_x=exit_consent)
    check(assemble(opts.at_depth(depth)[name], mode=mode) == assemble(toks, mode=mode),
          f"{tag} CCVTreeOptions compiles {name}")
    script = assemble(toks, mode=mode)
    w.compiled = dict(w.compiled); w.compiled[name] = script
    w.m = lt.taptree_root([lt.tapleaf_hash(c, lv) for c in w.compiled.values()])
    base, old, new = _plan_ccv(w, height, scenario)
    idx = base >> height
    w.tree.leaves = {base + i: lf for i, lf in old.items() if lf}
    w.tree.leaves[0] = mk_leaf("alice", 50_000)
    w.tree.leaves[(1 << depth) - 1] = mk_leaf("operator", 1_000_000)
    n = 1 << height

    def outputs_for(old_, new_, tree=None):
        tree = tree or w.tree
        t1 = lt.Tree(depth); t1.leaves = dict(tree.leaves)
        for i, lf in new_.items():
            if lf:
                t1.leaves[base + i] = lf
            else:
                t1.leaves.pop(base + i, None)
        r1 = t1.root()
        outs = [(r1[1], w.spk(r1))]
        for i in range(n):
            if old_[i] and new_[i] is None:
                outs.append((old_[i].amount, lt.p2tr_spk(old_[i].exit_key)))
        return outs + [(400, P2WPKH)], r1[1] - tree.root()[1]

    def witness(old_, new_, ctx, signer_op=None, sign=True, tree=None, marker=True, path_tree=None, flag=None):
        """The whole witness for the plan (old_, new_) on `tree` (the
        current tree by default): under 0xC2 FULL's layout minus r and m,
        under 0xC0 MID's minus r and m. path_tree supplies the path (and
        the pads) from another tree, for the stale-path case. flag is the
        output-0 mode flag at the very bottom (spec 4.6); by default the
        one the rules call for, DEDUCT exactly when the new sum is below
        the input's amount less the exit payouts."""
        tree = tree or w.tree
        if flag is None:
            flag = mode_flag(tree.root()[1], old_, new_, n)
        sigs = {}
        for i in range(n):
            if sign and _needs_owner_sig_ccv(old_[i], new_[i], numeric):
                sigs[i] = [schnorr_sign(ctx.sighash(), sk(f"c{i}-owner"))]
                if exit_consent:
                    sigs[i].append(schnorr_sign(ctx.sighash(), sk(f"c{i}-exit")))
        sig_op = schnorr_sign(ctx.sighash(), signer_op or w.op_sk)
        if c0:
            body = M.w_rewrite(path_tree or tree, depth, height, idx, new_, sigs, marker)
        else:
            path = (path_tree or tree).path(base, height=height)
            body = w.path_witness(path, height) + _rewrite_blocks_c2(old_, new_, sigs, n, marker)
        return [flag] + body + [sig_op], sigs

    outputs, delta = outputs_for(old, new)
    ctx = w.ctx(outputs, (max(delta, 0) + 5_000, P2WPKH))
    wit, sigs = witness(old, new, ctx)
    return dict(name=name, tag=tag, w=w, script=script, wit=wit, ctx=ctx, base=base, idx=idx, old=old, new=new,
                sigs=sigs, outputs=outputs, delta=delta, outputs_for=outputs_for, witness=witness, c0=c0)


def test_rewrite_ccv(depth, height, numeric="c2", exit_consent=False, scenario="mixed"):
    """REWRITE_h (spec 7.9) under CCV in either numerics, mirroring
    test_scripts.test_rewrite and test_mid.test_rewrite on the same mixed
    cohort: the positives (the rewrite, the unchanged leaf supplied once
    as the marker or twice in full), the negatives of every rule (a
    changed leaf without its owner's signature, a key rotation disguised
    as an amount increase, an operator-only amount decrease or exit-key
    change, a SEQ_FINAL leaf raised by one satoshi, a spurious signature,
    a shortchanged or misdirected exit, an exit without its owner, a
    missing operator signature, output 0 off by one either way, a stale
    path, a forged old leaf, an occupied position presented as empty, the
    marker misused three ways), the CCV-specific ones (output 0 under a
    wrong taptree or the FULL-tier key, a payout to a tweaked exit key)
    and under 0xC0 MID's (a leaf whose amount field and number disagree,
    a malformed node pad) plus the exemption's independence from the
    other numerics' SEQ_FINAL. Returns (interp, script bytes, witness);
    interp and witness are None when the 0xC0 witness exceeds the
    1,000-element stack limit, in which case the run is checked to fail
    at that limit, as the MID suite does (spec 4.5)."""
    c = rewrite_case_ccv(depth, height, numeric, scenario, exit_consent)
    w, name, tag, ctx, wit, outputs = c["w"], c["name"], c["tag"], c["ctx"], c["wit"], c["outputs"]
    old, new, sigs, base, delta, c0 = c["old"], c["new"], c["sigs"], c["base"], c["delta"], c["c0"]
    outputs_for, witness = c["outputs_for"], c["witness"]
    n = 1 << height
    root = w.tree.root()
    same = M.REWRITE_SAME if c0 else ls.REWRITE_SAME
    if c0 and len(wit) + 4 > 1000:
        # The pre-pass peaks four above the witness (spec 4.5); the rejection
        # must come from the stack size limit itself.
        try:
            w.run(name, wit, ctx)
            check(False, f"{tag} ({scenario}) with {len(wit)} witness elements ran past the 1,000-element stack limit")
        except ScriptError as e:
            check("stack size limit" in str(e),
                  f"{tag} ({scenario}) with {len(wit)} witness elements is rejected by the stack size limit: {str(e)[:60]}")
        return None, c["script"], None
    it = None
    try:
        it = w.run(name, wit, ctx)
        check(True, f"{tag}: {scenario} rewrite of {n} positions")
    except ScriptError as e:
        check(False, f"{tag} positive: {str(e)[:120]}")
        return None, c["script"], wit
    check(outputs[0][0] == root[1] + delta, f"{tag} output 0 is S + (sum new - sum old)")
    if scenario != "mixed":
        return it, c["script"], wit

    def run_plan(old_, new_, tree=None, sign=True, signer_op=None, mutate=None, outs=None, marker=True,
                 path_tree=None, extra=None):
        tree = tree or w.tree
        o, d = outputs_for(old_, new_, tree)
        o = outs or o
        saved = w.tree
        w.tree = tree
        try:
            ctx_ = w.ctx(o, (extra if extra is not None else max(d, 0) + 5_000, P2WPKH))
            wit_, sigs_ = witness(old_, new_, ctx_, signer_op, sign, tree, marker, path_tree)
        finally:
            w.tree = saved
        if mutate:
            wit_ = mutate(wit_, sigs_, ctx_)
        return w.run(name, wit_, ctx_)

    # the unchanged position: published once with the marker, or twice in
    # full, which the script also accepts
    i_same = next(i for i in range(n) if old[i] and new[i] and old[i].serialize() == new[i].serialize())
    check(wit.count(same) >= 1, f"{tag} the unchanged position's new element is the one-byte marker")
    run_plan(old, new, marker=False)
    check(True, f"{tag} an unchanged leaf supplied twice in full also passes")

    def slot_items(leaf):
        return M.w_rewrite_slot(leaf) if c0 else [leaf.serialize()]

    def replace_slot(leaf, with_items):
        """Replace the first occurrence of `leaf`'s slot in the witness."""
        slot = slot_items(leaf)

        def mut(wit_, sigs_, ctx_):
            at = next(j for j in range(len(wit_) - len(slot) + 1) if wit_[j:j + len(slot)] == slot)
            return wit_[:at] + with_items + wit_[at + len(slot):]
        return mut
    # the marker as the old element is a one-element old leaf; in place of a
    # changed leaf it hides nothing, since the fold then sees the old leaf
    expect_fail(lambda: run_plan(old, new, mutate=replace_slot(old[i_same], [same])), f"{tag} the marker as an old element")
    i_chg = next(i for i in range(n) if old[i] and new[i] and old[i].serialize() != new[i].serialize())
    expect_fail(lambda: run_plan(old, new, mutate=replace_slot(new[i_chg], [same])),
                f"{tag} the marker in place of a changed leaf")
    if not c0:
        expect_fail(lambda: run_plan(old, new, mutate=replace_slot(new[i_chg], [b"\x01\x01"])), f"{tag} a 2-byte new element")
    # rule 3: a changed leaf without its owner's signature
    i_rot = next(i for i in range(n) if old[i] and new[i] and _needs_owner_sig_ccv(old[i], new[i], numeric))

    def drop_sig(i):
        def mut(wit_, sigs_, ctx_):
            wit_ = list(wit_)
            del wit_[wit_.index(sigs_[i][0])]
            if exit_consent:
                del wit_[wit_.index(sigs_[i][1])]
            return wit_
        return mut
    expect_fail(lambda: run_plan(old, new, mutate=drop_sig(i_rot)), f"{tag} changed leaf without the owner signature")
    # rule 3: a key rotation disguised as an amount-only increase
    i_inc = next(i for i in range(n) if old[i] and new[i] and not _needs_owner_sig_ccv(old[i], new[i], numeric)
                 and new[i].amount > old[i].amount)
    lf = old[i_inc]
    disguised = dict(new)
    disguised[i_inc] = lt.Leaf(lf.amount + 500, lf.exit_key, pubkey_x(sk("mallory")), lf.evictor_key,
                               lf.evict_after, lf.nonce, lf.seq)
    expect_fail(lambda: run_plan(old, disguised, mutate=drop_sig(i_inc)), f"{tag} key rotation disguised as an amount increase")
    run_plan(old, disguised)
    check(True, f"{tag} the same rotation with the owner's signature succeeds")
    # rule 3: the operator alone cannot decrease an amount or change a
    # non-amount field (here the exit key, with an increase)
    decreased = dict(new); decreased[i_inc] = lf.with_amount_seq(lf.amount - 1, lf.seq)
    expect_fail(lambda: run_plan(old, decreased, mutate=drop_sig(i_inc)), f"{tag} amount decrease without the owner signature")
    rekeyed = dict(new); rekeyed[i_inc] = lt.Leaf(lf.amount + 500, pubkey_x(sk("mallory")), lf.owner_key,
                                                 lf.evictor_key, lf.evict_after, lf.nonce, lf.seq)
    expect_fail(lambda: run_plan(old, rekeyed, mutate=drop_sig(i_inc)), f"{tag} exit-key change without the owner signature")
    # rule 3: the exemption stops at the numerics' SEQ_FINAL (0xFFFFFFFF
    # under 0xC2, 0x7FFFFFFF under 0xC0): raising such a leaf by 1 sat
    # needs the owner's signature too; the other numerics' marker is an
    # ordinary seq here, so the exemption applies
    seq_final, other_final = (M.SEQ_FINAL, ls.SEQ_FINAL) if c0 else (ls.SEQ_FINAL, M.SEQ_FINAL)
    t_f = w.clone()
    final_old, final_new = dict(old), dict(new)
    final_old[i_inc] = lf.with_amount_seq(lf.amount, seq_final)
    final_new[i_inc] = lf.with_amount_seq(lf.amount + 1, seq_final)
    t_f.leaves[base + i_inc] = final_old[i_inc]
    expect_fail(lambda: run_plan(final_old, final_new, tree=t_f, mutate=drop_sig(i_inc)),
                f"{tag} SEQ_FINAL leaf raised by 1 sat without the owner signature")
    run_plan(final_old, final_new, tree=t_f)
    check(True, f"{tag} the same raise with the owner's signature succeeds")
    t_g = w.clone()
    g_old, g_new = dict(old), dict(new)
    g_old[i_inc] = lf.with_amount_seq(lf.amount, other_final)
    g_new[i_inc] = lf.with_amount_seq(lf.amount + 1, other_final)
    t_g.leaves[base + i_inc] = g_old[i_inc]
    run_plan(g_old, g_new, tree=t_g)
    check(True, f"{tag} a seq of {other_final:#x} is not this numerics' SEQ_FINAL: the amount-only exemption applies")

    # rule 3: a spurious signature where none is due is consumed as the next element
    def add_sig(wit_, sigs_, ctx_):
        wit_ = list(wit_)
        at = wit_.index(sigs_[i_rot][0])
        wit_.insert(at, schnorr_sign(ctx_.sighash(), sk(f"c{i_inc}-owner")))
        return wit_
    expect_fail(lambda: run_plan(old, new, mutate=add_sig), f"{tag} spurious signature on an exempt position")
    # rule 5: a shortchanged exit payout, one paid to the wrong key, one paid
    # to the exit key under a taptree (CCV checks a bare P2TR), and an exit
    # without its owner's signature
    i_exit = next(i for i in range(n) if old[i] and new[i] is None)
    k = 1 + sum(1 for i in range(i_exit) if old[i] and new[i] is None)
    outs_s = list(outputs); outs_s[k] = (outs_s[k][0] - 1, outs_s[k][1])
    expect_fail(lambda: run_plan(old, new, outs=outs_s), f"{tag} shortchanged exit payout")
    outs_k = list(outputs); outs_k[k] = (outs_k[k][0], lt.p2tr_spk(pubkey_x(sk("mallory"))))
    expect_fail(lambda: run_plan(old, new, outs=outs_k), f"{tag} exit paid to the wrong key")
    outs_t = list(outputs); outs_t[k] = (outs_t[k][0], lt.tree_spk_ccv(old[i_exit].exit_key, w.m))
    expect_fail(lambda: run_plan(old, new, outs=outs_t), f"{tag} exit paid to a tweaked exit key")
    expect_fail(lambda: run_plan(old, new, mutate=drop_sig(i_exit)), f"{tag} exit without the owner signature")
    # rule 4: no operator signature
    expect_fail(lambda: run_plan(old, new, signer_op=sk("alice-owner")), f"{tag} without the operator signature")
    # rule 6: output 0 not conserved (under and over), and the CCV binding
    # of output 0: a wrong taptree, the FULL-tier key
    for off in (-1, +1):
        outs_u = list(outputs); outs_u[0] = (outs_u[0][0] + off, outs_u[0][1])
        expect_fail(lambda: run_plan(old, new, outs=outs_u, extra=max(delta, 0) + 5_000 + max(off, 0)),
                    f"{tag} output 0 off by {off:+d}")
    t1 = w.clone()
    for i, x in new.items():
        if x:
            t1.leaves[base + i] = x
        else:
            t1.leaves.pop(base + i, None)
    r1 = t1.root()
    outs_w = list(outputs); outs_w[0] = (outs_w[0][0], lt.tree_spk_ccv(r1[0], lt.sha256(b"wrong-taptree")))
    expect_fail(lambda: run_plan(old, new, outs=outs_w), f"{tag} output 0 under a wrong taptree")
    outs_f = list(outputs); outs_f[0] = (outs_f[0][0], lt.tree_spk(r1[0], w.m))
    expect_fail(lambda: run_plan(old, new, outs=outs_f), f"{tag} output 0 with the FULL-tier key")
    # rule 1: a stale path (from a change elsewhere in the tree), a forged
    # old leaf and an occupied position presented as empty
    t_s = w.clone(); t_s.leaves[0] = mk_leaf("alice", 51_000)
    expect_fail(lambda: run_plan(old, new, path_tree=t_s), f"{tag} stale path")
    forged = dict(old); forged[i_rot] = old[i_rot].with_amount_seq(old[i_rot].amount + 1, old[i_rot].seq)
    t_forged = w.clone(); t_forged.leaves[base + i_rot] = forged[i_rot]

    def forge(wit_, sigs_, ctx_):
        return witness(forged, new, ctx_, None, True, t_forged)[0]
    expect_fail(lambda: run_plan(old, new, mutate=forge), f"{tag} forged old leaf")
    hidden = dict(old); hidden[i_rot] = None
    t_h = w.clone(); del t_h.leaves[base + i_rot]

    def hide(wit_, sigs_, ctx_):
        return witness(hidden, new, ctx_, None, True, t_h)[0]
    expect_fail(lambda: run_plan(old, new, mutate=hide), f"{tag} presents an occupied position as empty")
    if c0:
        # MID-specific: the amount field and its number disagree in an old leaf
        def bad_amount(wit_, sigs_, ctx_):
            wit_ = list(wit_)
            at = len(wit_) - 1 - 1 - 3            # position 0's old slot: sig_op, flag, then wa za amt_num
            assert wit_[at] == M.scriptnum(old[0].amount)
            wit_[at] = M.scriptnum(old[0].amount + 256)
            return wit_
        expect_fail(lambda: run_plan(old, new, mutate=bad_amount), f"{tag} old leaf amount field and number disagree")
        if height >= 2:
            at = 1 + 4 + M.LEVEL_WITNESS * (depth - height)      # the last-consumed pad pair (the first node's new sum)

            def swap_pad(wit_, sigs_, ctx_):
                b = list(wit_); b[at], b[at + 1] = b[at] + b"\x00", b[at + 1][1:]
                return b
            expect_fail(lambda: run_plan(old, new, mutate=swap_pad), f"{tag} with a malformed node pad")
    if exit_consent:
        # rule 7: the exit key of a changed leaf must sign too
        def drop_x(wit_, sigs_, ctx_):
            wit_ = list(wit_); del wit_[wit_.index(sigs_[i_rot][1])]; return wit_
        expect_fail(lambda: run_plan(old, new, mutate=drop_x), f"{tag} changed leaf without the exit-key signature")

        def wrong_x(wit_, sigs_, ctx_):
            wit_ = list(wit_); wit_[wit_.index(sigs_[i_rot][1])] = sigs_[i_rot][0]; return wit_
        expect_fail(lambda: run_plan(old, new, mutate=wrong_x), f"{tag} exit-key signature by the owner key")
    return it, c["script"], wit


def test_rewrite_flag_ccv(depth, height, numeric="c2", exit_consent=False):
    """The output-0 mode flag of the plain REWRITE_h and REWRITE_h^x under
    CCV (spec 4.6, 7.9 rule 6): a net decrease is spendable. Four plans
    (_plan_ccv): a net decrease and an exit with a decrease need DEDUCT; an
    offset (one leaf down, another up, the sum up) and an exit with an
    increase need assign. Each passes under its flag, the decrease with the
    freed value paid to another output; under the other flag, under a flag
    other than empty or 0x01, and with output 0 one satoshi off its new sum
    (the amount equality out0 == ns pins it in both modes) each fails."""
    n = 1 << height
    for scenario, want in (("decrease", b"\x01"), ("offset", b""), ("exit_up", b""), ("exit_down", b"\x01")):
        c = rewrite_case_ccv(depth, height, numeric, scenario, exit_consent)
        w, name, ctx, wit, outputs = c["w"], c["name"], c["ctx"], c["wit"], c["outputs"]
        old, new, witness, delta = c["old"], c["new"], c["witness"], c["delta"]
        tag = f"{c['tag']} ({scenario})"
        check(wit[0] == want, f"{tag}: the mode flag is {'DEDUCT' if want else 'assign'}")
        try:
            run_fresh(w, name, wit, ctx)
            check(True, f"{tag}: spends under the {'DEDUCT' if want else 'assign'} flag")
        except ScriptError as e:
            check(False, f"{tag} positive: {str(e)[:100]}")
            continue
        for bad in (b"\x01" if not want else b"", b"\x02", b"\x00"):
            expect_fail(lambda: run_fresh(w, name, [bad] + wit[1:], ctx), f"{tag}: flag {bad.hex() or 'empty'}")
        extra = (max(delta, 0) + 5_000, P2WPKH)
        for off in (-1, +1):
            outs = list(outputs); outs[0] = (outs[0][0] + off, outs[0][1])
            ctx2 = w.ctx(outs, extra)
            expect_fail(lambda: run_fresh(w, name, witness(old, new, ctx2)[0], ctx2), f"{tag}: output 0 off by {off:+d}")
        if want:
            payouts = sum(old[i].amount for i in range(n) if old.get(i) and new.get(i) is None)
            freed = -delta - payouts
            outs = list(outputs) + [(freed, P2WPKH)]
            ctx2 = w.ctx(outs, extra)
            try:
                run_fresh(w, name, witness(old, new, ctx2)[0], ctx2)
                check(True, f"{tag}: the freed {freed} sat go to another output")
            except ScriptError as e:
                check(False, f"{tag} freed value to another output: {str(e)[:100]}")
            # the owner's signature on the decreased leaf is still required
            expect_fail(lambda: run_fresh(w, name, witness(old, new, ctx, sign=False)[0], ctx), f"{tag}: without the owner signatures")


def test_update_flag_ccv(depth, profile="D", numeric="c2"):
    """The output-0 mode flag of UPDATE under CCV (spec 4.6, 7.4): an
    owner-signed decrease of the leaf's amount is spendable under DEDUCT,
    with the freed value paid to another output or to the fee; it fails under
    the assign flag, under a flag other than empty or 0x01, without the
    owner's signature and with output 0 off its new sum. An increase funded
    by another input and a decrease-free update (seq only) use assign and
    fail under DEDUCT."""
    c0 = numeric == "c0"
    sparse = profile == "S"
    w = WorldC0(depth, profile) if c0 else World(depth, profile)
    tag = f"{numeric}: UPDATE {profile}/{depth}"

    def mk(label, amount):
        lf = mk_leaf(label, amount)
        while c0 and sparse and not M.pos_ok(lf):
            lf.nonce = (lf.nonce + 1) & 0xffffffff
        return lf
    alice, bob, oper = mk("alice", 50_000), mk("bob", 125_000), mk("operator", 1_000_000)
    s_a, s_b, s_o = w.slot(alice, 0), w.slot(bob, 5), w.slot(oper, (1 << depth) - 1)
    w.tree.leaves = {s_a: alice, s_b: bob, s_o: oper}
    root = w.tree.root()
    upath = w.tree.path(s_a)

    def spend(new_leaf, flag, off=0, outs_extra=(), extra=None, owner="alice-owner"):
        t1 = w.clone(); t1.leaves[s_a] = new_leaf; r1 = t1.root()
        outs = [(r1[1] + off, w.spk(r1))] + list(outs_extra)
        ctx = w.ctx(outs, extra or ((500, P2WPKH) if c0 else None))   # WorldC0 always has a second input
        osig = schnorr_sign(ctx.sighash(), w.op_sk)
        asig = schnorr_sign(ctx.sighash(), sk(owner))
        if c0:
            wit = ([flag] + list(M.pad(r1[1])) + w.pads_for(root[1]) +
                   M.w_levels(upath, alice.node(), new_leaf.node(), sparse) +
                   w.pos(alice) + M.w_leaf(alice) + M.w_leaf(new_leaf) + [asig, osig])
        else:
            wit = [flag] + w.path_witness(upath) + [alice.serialize(), new_leaf.serialize(), asig, osig]
        return w.run("UPDATE", wit, ctx)

    def ok(fn, msg):
        try:
            fn()
            check(True, f"{tag}: {msg}")
        except ScriptError as e:
            check(False, f"{tag}: {msg}: {str(e)[:100]}")

    down = alice.with_amount_seq(20_000, 1)
    ok(lambda: spend(down, b"\x01"), "a decrease of 30,000 spends under DEDUCT, the freed value to the fee")
    ok(lambda: spend(down, b"\x01", outs_extra=[(29_500, P2WPKH)]), "the decrease's freed value paid to another output")
    expect_fail(lambda: spend(down, b""), f"{tag}: a decrease under the assign flag")
    for bad in (b"\x02", b"\x00"):
        expect_fail(lambda: spend(down, bad), f"{tag}: a decrease under flag {bad.hex()}")
    expect_fail(lambda: spend(down, b"\x01", owner="operator"), f"{tag}: a decrease without the owner's signature")
    for off in (-1, +1):
        expect_fail(lambda: spend(down, b"\x01", off=off), f"{tag}: a decrease with output 0 off by {off:+d}")
    up = alice.with_amount_seq(80_000, 1)
    ok(lambda: spend(up, b"", extra=(30_700, P2WPKH)), "an increase funded by another input spends under assign")
    expect_fail(lambda: spend(up, b"\x01", extra=(30_700, P2WPKH)), f"{tag}: an increase under DEDUCT")
    same = alice.with_amount_seq(50_000, 1)
    ok(lambda: spend(same, b""), "an update that keeps the amount spends under assign")


def test_rewrite_negative_amount_ccv0(depth):
    """NONNEG in the 0xC0 REWRITE_h (spec 4.5, 10.6): a joined leaf whose
    amount is 2^31 + 2^24, supplied as the negative CScriptNum its le32
    is, with every accumulator above it encoded the same signed way (the
    MID suite's levels_signed), so that the only check standing between
    a leaf that claims 2^31 sat more than the tree holds and output 0 is
    the NONNEG on the new slot's amount number. A height-1 rewrite at
    depth `depth` joins the leaf beside an unchanged one."""
    import test_mid as TM
    w = WorldC0(depth, "D")
    name = "REWRITE_1"
    w.compiled = dict(w.compiled); w.compiled[name] = assemble(C._rewrite_script_ccv0(depth, 1, w.op_pk), mode="c0")
    w.m = lt.taptree_root([lt.tapleaf_hash(c, 0xc0) for c in w.compiled.values()])
    base, idx = 2, 1
    keeper = mk_leaf("keeper", 20_000, w.op_pk, 800_000)
    w.tree.leaves = {0: mk_leaf("alice", 50_000), base + 1: keeper, (1 << depth) - 1: mk_leaf("operator", 100_000_000)}
    root = w.tree.root()
    S = root[1]
    BIG = (1 << 31) + (1 << 24)
    NEG = TM.snum(-(1 << 24))
    assert NEG[0] == lt.le32(BIG)
    big = TM.big_leaf("big", BIG, w.op_pk, 900_000, 7)
    # the new subtree node as the script computes it: H_node over the two
    # leaf nodes (le64(BIG) is what the slot's amt8 says), sum read signed
    new_hash = lt.node_hash(big.node(), keeper.node())
    new_sum = keeper.amount - (1 << 24)
    old_node = w.tree.subtree(1, idx)
    path = w.tree.path(base, height=1)
    r1 = TM.fold_signed(new_hash, new_sum, path)
    check(r1[1] == S - (1 << 24), "c0: the signed fold of the rewritten subtree reaches S - 2^24")
    ctx = w.ctx([(r1[1], w.spk(r1)), (400, P2WPKH)], (5_000, P2WPKH))
    # the DEDUCT flag: the sum falls by 2^24 + the join, so only NONNEG stands in the way
    wit = ([b"\x01"] + list(M.pad(r1[1])) + list(M.pad(S)) + TM.levels_signed(path, old_node[1], new_sum) +
           [M.REWRITE_SAME] + M.w_rewrite_slot(keeper) +                     # position 1: unchanged
           TM.leaf10_signed(big, NEG) + [b"\x01", b""] +                      # position 0: the big leaf joins E_0
           [schnorr_sign(ctx.sighash(), w.op_sk)])
    expect_fail(lambda: w.run(name, wit, ctx), f"c0: {name} D={depth} joins a leaf of 2^31 + 2^24 sat as a negative amount (NONNEG)")


def test_voucher_topup_ccv(depth, numeric="c2"):
    """CCV: vouchers and exit authorisations survive an amount-only
    REWRITE_h (spec 7.5, 7.2 rule 7, 7.9 rule 3), the FULL and MID suites'
    test_voucher_topup in either numerics. A tree created with CLAIM,
    EXIT_K^t and REWRITE_2 (CCVTreeOptions): the operator tops up a cohort
    with its signature alone, then a voucher and a tower authorisation
    signed before the rewrite redeem and exit against the topped-up
    leaves, the voucher for its own amount, for more than the balance at
    issuance and for the whole balance at issuance; an over-claim against
    the new balance, a payout of the old amount and a whole-balance
    voucher after a sub-dust top-up (7.5 rule 6) fail."""
    c0 = numeric == "c0"
    tag = f"{numeric}: top-up D={depth}"
    opts = C.CCVTreeOptions(pubkey_x(sk("operator")), numeric, "D", TREE_ID, join_heights=(0, 2),
                            exit_ks=(1, 2), tower=True, claim=True, rewrite_heights=(2,))
    if c0:
        w = WorldC0(depth, "D")
        allowed, mode, lv = C0_OPCODES | CSFS_OPS, "c0", 0xc0
    else:
        w = World(depth, "D")
        allowed, mode, lv = ALLOWED | CSFS_OPS, "c2", 0xc2
    w.scripts = opts.at_depth(depth)
    for nm, toks in w.scripts.items():
        bad = {t for t in toks if isinstance(t, str)} - allowed
        check(not bad, f"{tag}: {nm} opcodes outside the CCV set: {sorted(bad)}")
    w.compiled = {k: assemble(v, mode=mode) for k, v in w.scripts.items()}
    w.m = lt.taptree_root([lt.tapleaf_hash(c, lv) for c in w.compiled.values()])
    check("REWRITE_2" in w.compiled and "CLAIM" in w.compiled, f"{tag}: the option set carries REWRITE_2 and CLAIM")
    base, old, new = TS._rewrite_plan(w, 2, "topup")
    idx = base >> 2
    w.tree.leaves = {base + i: lf for i, lf in old.items()}
    w.tree.leaves[0] = mk_leaf("alice", 50_000)
    w.tree.leaves[(1 << depth) - 1] = mk_leaf("operator", 1_000_000)
    root = w.tree.root()
    path = w.tree.path(base, height=2)
    # signed before the rewrite, against the leaves as they stand
    src = old[3]
    holder = carve_of(src, "holder", 4_000)
    vsig = schnorr_sign(lt.voucher_msg(TREE_ID, src, holder), sk("c3-owner"))
    auth = schnorr_sign(lt.exit_auth_msg(TREE_ID, old[1]), sk("c1-owner"))
    t1 = w.clone()
    for i, lf in new.items():
        t1.leaves[base + i] = lf
    r1 = t1.root()
    delta = r1[1] - root[1]
    ctx = w.ctx([(r1[1], w.spk(r1)), (400, P2WPKH)], (delta + 5_000, P2WPKH))
    if c0:
        body = M.w_rewrite(w.tree, depth, 2, idx, new, {}, True)
    else:
        body = w.path_witness(path, 2) + _rewrite_blocks_c2(old, new, {}, 4)
    w.run("REWRITE_2", [b""] + body + [schnorr_sign(ctx.sighash(), w.op_sk)], ctx)
    check(True, f"{tag}: REWRITE_2, the operator tops up every leaf of the cohort alone")
    w.tree = t1
    s_src = base + 3
    topped = new[3]
    check(topped.body() == src.body() and topped.amount == src.amount + 500, f"{tag}: the top-up changed the amount and nothing else")

    def claim_after(lf, sig, tree=None, src_leaf=None):
        tree = tree or w.tree
        src_leaf = src_leaf or topped
        s_c = 2
        t2 = lt.Tree(depth); t2.leaves = dict(tree.leaves)
        amt_new = src_leaf.amount - lf.amount
        if amt_new > 0:
            t2.leaves[s_src] = src_leaf.with_amount_seq(amt_new, src_leaf.seq + 1)
        else:
            del t2.leaves[s_src]
        new_src = t2.leaves[s_src].node() if s_src in t2.leaves else lt.EMPTY_NODE
        spath = tree.path(s_src)
        t2.leaves[s_c] = lf
        r2 = t2.root()
        ctx2 = TxContext([(tree.root()[1], w.spk(tree.root())), (600, P2WPKH)], [(r2[1], w.spk(r2))],
                         internal_key=lt.ccv_internal_key(tree.root()[0]), taptree_root=w.m)
        if c0:
            wit = (list(M.pad(r2[1])) + M.w_levels(t2.path(s_c), lt.EMPTY_NODE, lf.node(), False) +
                   list(M.pad(tree.root()[1])) + M.w_levels(spath, src_leaf.node(), new_src, False) +
                   M.w_leaf(src_leaf) + M.w_leaf(lf) + M.w_carve_extras(src_leaf, lf, amt_new=max(amt_new, 0)) + [sig])
        else:
            wit = w.path_witness(t2.path(s_c)) + w.path_witness(spath) + [src_leaf.serialize(), lf.serialize(), sig]
        return wit, ctx2

    w.run("CLAIM", *claim_after(holder, vsig))
    check(True, f"{tag}: CLAIM, a voucher signed before the top-up redeems against the topped-up leaf")
    bigger = carve_of(src, "bigger", src.amount + 100)
    w.run("CLAIM", *claim_after(bigger, schnorr_sign(lt.voucher_msg(TREE_ID, src, bigger), sk("c3-owner"))))
    check(True, f"{tag}: CLAIM, after the top-up a voucher may draw more than the balance at issuance")
    whole = carve_of(src, "whole", src.amount)
    wsig = schnorr_sign(lt.voucher_msg(TREE_ID, src, whole), sk("c3-owner"))
    w.run("CLAIM", *claim_after(whole, wsig))
    check(True, f"{tag}: CLAIM, a whole-balance voucher redeems after a top-up of at least DUST_MIN")
    over = carve_of(src, "over", topped.amount + 1)
    expect_fail(lambda: w.run("CLAIM", *claim_after(over, schnorr_sign(lt.voucher_msg(TREE_ID, src, over), sk("c3-owner")))),
                f"{tag}: CLAIM, over-claim against the topped-up balance")
    sub = src.with_amount_seq(src.amount + 1, src.seq)
    t_sub = w.clone(); t_sub.leaves[s_src] = sub
    expect_fail(lambda: w.run("CLAIM", *claim_after(whole, wsig, tree=t_sub, src_leaf=sub)),
                f"{tag}: CLAIM, a whole-balance voucher after a top-up below DUST_MIN (7.5 rule 6)")
    # the tower exits the other leaf for its new amount on the old authorisation
    s_b = base + 1
    up1 = new[1]
    t5 = w.clone(); del t5.leaves[s_b]; r5 = t5.root()
    path_b = w.tree.path(s_b)
    if c0:
        below = (list(M.pad(r5[1])) + list(M.pad(r1[1])) + M.w_levels(path_b, up1.node(), lt.EMPTY_NODE, False) +
                 M.w_leaf_exit(up1))
    else:
        below = w.path_witness(path_b) + [up1.serialize()]
    ctx5 = w.ctx([(r5[1], w.spk(r5)), (up1.amount, lt.p2tr_spk(up1.exit_key))], (5_000, P2WPKH))
    w.run("EXIT_1", below + [auth, b""], ctx5)
    check(True, f"{tag}: EXIT_1^t, an authorisation signed before the top-up exits the topped-up leaf for its new amount")
    ctx6 = w.ctx([(r5[1], w.spk(r5)), (old[1].amount, lt.p2tr_spk(up1.exit_key))], (5_000, P2WPKH))
    expect_fail(lambda: w.run("EXIT_1", below + [auth, b""], ctx6), f"{tag}: EXIT_1^t, the exit after a top-up pays the amount at signing")


def test_credit_topup_ccv(depth, numeric="c2"):
    """CCV: the dedicated credit leaf end to end (spec 7.5.3, 7.9 rules 3
    and 7, 10.3) in either numerics, the MID suite's test_credit_topup.
    The tree carries UPDATE^x, CLAIM^x and REWRITE_2^x and no plain
    REWRITE_2 (7.9 rule 7). The operator (owner of the credit leaf) issues
    cumulative vouchers to the recipient (its exit key), then tops the
    leaf up by an amount-only REWRITE_2^x with no signature but its own;
    the recipient still redeems the vouchers signed before the top-up
    with CLAIM^x, one for more than the balance at issuance, the operator
    can redeem none of them and cannot move the exit key alone."""
    c0 = numeric == "c0"
    tag = f"{numeric}: credit leaf D={depth}"
    opts = C.CCVTreeOptions(pubkey_x(sk("operator")), numeric, "D", TREE_ID, join_heights=(0, 2),
                            exit_ks=(1, 2), update_x=True, claim_x=True, rewrite_heights=(2,), rewrite_x=True)
    if c0:
        w = WorldC0(depth, "D")
        allowed, mode, lv = C0_OPCODES | CSFS_OPS, "c0", 0xc0
    else:
        w = World(depth, "D")
        allowed, mode, lv = ALLOWED | CSFS_OPS, "c2", 0xc2
    w.scripts = opts.at_depth(depth)
    check("REWRITE_X_2" in w.scripts and "CLAIM_X" in w.scripts and "UPDATE_X" in w.scripts and "CLAIM" not in w.scripts,
          f"{tag}: the option set carries UPDATE^x, CLAIM^x and REWRITE_2^x and no plain CLAIM")
    del w.scripts["REWRITE_2"]                    # a tree with CLAIM^x carries REWRITE_h^x in its place (7.9 rule 7)
    for nm, toks in w.scripts.items():
        bad = {t for t in toks if isinstance(t, str)} - allowed
        check(not bad, f"{tag}: {nm} opcodes outside the CCV set: {sorted(bad)}")
    w.compiled = {k: assemble(v, mode=mode) for k, v in w.scripts.items()}
    w.m = lt.taptree_root([lt.tapleaf_hash(c, lv) for c in w.compiled.values()])
    base, idx = 4, 1
    credit = lt.Leaf(10_000, pubkey_x(sk("recipient-exit")), w.op_pk, w.op_pk, 800_000,
                     int.from_bytes(lt.sha256(b"credit")[:4], "little"), 0)
    old = {0: credit}
    for i in (1, 2, 3):
        old[i] = mk_leaf(f"c{i}", 10_000 + 7 * i, w.op_pk, 800_000)
    w.tree.leaves = {base + i: lf for i, lf in old.items()}
    w.tree.leaves[0] = mk_leaf("alice", 50_000)
    w.tree.leaves[(1 << depth) - 1] = mk_leaf("operator", 1_000_000)
    root = w.tree.root()
    path = w.tree.path(base, height=2)
    s_credit = base
    v1 = carve_of(credit, "holder1", 4_000)
    v2 = carve_of(credit, "holder2", 10_100)
    sig1 = schnorr_sign(lt.voucher_msg(TREE_ID, credit, v1), w.op_sk)
    sig2 = schnorr_sign(lt.voucher_msg(TREE_ID, credit, v2), w.op_sk)
    topped = credit.with_amount_seq(credit.amount + 500, credit.seq)
    new = {0: topped, 1: old[1], 2: old[2], 3: old[3]}
    t1 = w.clone(); t1.leaves[s_credit] = topped; r1 = t1.root()

    def rewrite(new_, ctx_, sigs):
        if c0:
            body = M.w_rewrite(w.tree, depth, 2, idx, new_, sigs, True)
        else:
            body = w.path_witness(path, 2) + _rewrite_blocks_c2(old, new_, sigs, 4)
        return w.run("REWRITE_X_2", [b""] + body + [schnorr_sign(ctx_.sighash(), w.op_sk)], ctx_)
    ctx = w.ctx([(r1[1], w.spk(r1))], (500 + 5_000, P2WPKH))
    rewrite(new, ctx, {})
    check(True, f"{tag}: REWRITE_2^x, the operator tops up the credit leaf with its signature alone")
    rotated = lt.Leaf(topped.amount, pubkey_x(sk("operator-exit")), credit.owner_key, credit.evictor_key,
                      credit.evict_after, credit.nonce, credit.seq)
    t_r = w.clone(); t_r.leaves[s_credit] = rotated; r_r = t_r.root()
    ctx_r = w.ctx([(r_r[1], w.spk(r_r))], (500 + 5_000, P2WPKH))
    new_r = dict(new); new_r[0] = rotated
    expect_fail(lambda: rewrite(new_r, ctx_r, {0: [schnorr_sign(ctx_r.sighash(), w.op_sk)]}),
                f"{tag}: REWRITE_2^x, the operator cannot move the credit leaf's exit key without the recipient")
    w.tree = t1

    def claim_x(lf, vsig, xkey, src=topped, s_c=2):
        t2 = w.clone()
        amt_new = max(src.amount - lf.amount, 0)
        if amt_new > 0:
            t2.leaves[s_credit] = src.with_amount_seq(amt_new, src.seq + 1)
        else:
            del t2.leaves[s_credit]
        new_src = t2.leaves[s_credit].node() if s_credit in t2.leaves else lt.EMPTY_NODE
        t2.leaves[s_c] = lf
        r2 = t2.root()
        ctx2 = w.ctx([(r2[1], w.spk(r2))], (600, P2WPKH))
        if c0:
            wit = (list(M.pad(r2[1])) + M.w_levels(t2.path(s_c), lt.EMPTY_NODE, lf.node(), False) +
                   list(M.pad(w.tree.root()[1])) + M.w_levels(w.tree.path(s_credit), src.node(), new_src, False) +
                   M.w_leaf(src) + M.w_leaf(lf) + M.w_carve_extras(src, lf, amt_new=amt_new))
        else:
            wit = w.path_witness(t2.path(s_c)) + w.path_witness(w.tree.path(s_credit)) + [src.serialize(), lf.serialize()]
        return wit + [vsig, schnorr_sign(ctx2.sighash(), xkey)], ctx2, t2

    expect_fail(lambda: w.run("CLAIM_X", *claim_x(v1, sig1, w.op_sk)[:2]),
                f"{tag}: CLAIM^x, the operator cannot redeem its own voucher against the credit leaf")
    wit, ctx2, t2 = claim_x(v2, sig2, sk("recipient-exit"))
    expect_fail(lambda: w.run("CLAIM_X", wit[:-1], ctx2), f"{tag}: CLAIM^x without the recipient's signature")
    w.run("CLAIM_X", wit, ctx2)
    check(True, f"{tag}: CLAIM^x, the recipient redeems the latest cumulative voucher, signed before the top-up, "
                "for more than the balance at issuance")
    w.tree = t2
    expect_fail(lambda: w.run("CLAIM_X", *claim_x(v1, sig1, sk("recipient-exit"), src=t2.leaves[s_credit], s_c=3)[:2]),
                f"{tag}: CLAIM^x, the earlier cumulative voucher is void once the later one has redeemed")


def test_audit_negatives_ccv(depth):
    """Negative cases from the byte-level audit (design/audit/script.md).

    c2: output 0 over-funded by one sat (the assign-mode floor is only a
    lower bound; the OP_TX equality is what pins it), the tree output and
    the payout swapped, and a payout to a taproot output whose key is the
    exit key under a taptree (CCV with an empty taptree operand is a bare
    key). c0: the NONNEG check of the MID encoding (4.5, 10.6): `JOIN_2`
    with `new_sum` of 2^31 + 2^24, the negative CScriptNum -2^24, and
    output 0 at S - 2^24, is rejected."""
    from test_mid import fold_signed, levels_signed, snum
    w = World(depth, "D")
    alice = mk_leaf("alice", 50_000)
    bob = mk_leaf("bob", 125_000, evictor=w.op_pk, evict_after=800_000)
    w.tree.leaves = {0: alice, 5: bob}
    root = w.tree.root()
    path = w.tree.path(5)
    t1 = w.clone(); del t1.leaves[5]; r1 = t1.root()
    outputs = [(r1[1], w.spk(r1)), (bob.amount, lt.p2tr_spk(bob.exit_key))]

    def go(outs, extra_in=(5_000, P2WPKH)):
        ctx = w.ctx(outs, extra_in=extra_in)
        sig = schnorr_sign(ctx.sighash(), sk("bob-owner"))
        return w.run("EXIT_1", w.path_witness(path) + [bob.serialize(), sig, b""], ctx)
    go(outputs)
    expect_fail(lambda: go([(r1[1] + 1, w.spk(r1)), outputs[1]], (6_000, P2WPKH)), "ccv: output 0 over-funded by one sat")
    expect_fail(lambda: go([outputs[1], outputs[0]]), "ccv: tree output and payout swapped")
    expect_fail(lambda: go([outputs[0], (bob.amount, lt.tree_spk(root[0], w.m))]), "ccv: payout to the exit key under a taptree")

    w0 = WorldC0(depth, "D")
    oper = lt.Leaf(100_000_000, pubkey_x(sk("operator-exit")), pubkey_x(sk("operator-owner")), lt.NUMS_X, 0, 7, 0)
    w0.tree.leaves = {0: alice, (1 << depth) - 1: oper}
    root0 = w0.tree.root()
    S = root0[1]
    h, idx = 2, 2
    jpath = w0.tree.path(idx << h, height=h)
    fake_hash = lt.sha256(b"operator's subtree")
    r2 = fold_signed(fake_hash, -(1 << 24), jpath)
    out0 = S - (1 << 24)
    check(r2[1] == out0, "c0: the signed fold of the joined subtree reaches S - 2^24")
    ctx = w0.ctx([(out0, w0.spk(r2))], (5_000, P2WPKH))
    osig = schnorr_sign(ctx.sighash(), w0.op_sk)
    neg = snum(-(1 << 24))[0]
    check(neg == lt.le32((1 << 31) + (1 << 24)), "c0: le32(2^31 + 2^24) is the CScriptNum -2^24")
    wit = (list(M.pad(out0)) + list(M.pad(S)) + levels_signed(jpath, 0, -(1 << 24)) + [fake_hash, neg, osig])
    expect_fail(lambda: w0.run("JOIN_2", wit, ctx), "c0: JOIN_2 with new_sum = 2^31 + 2^24 (a negative CScriptNum)")


def test_exit_tower_ccv(depth, profile, numeric="c2"):
    """EXIT_K^t (spec 7.2 rule 7) under CCV in either numerics: the owner
    branch takes an off-chain signature over H_exit(tree_id || leaf),
    checked by OP_CHECKSIGFROMSTACK (the tier's second CSFS user after
    CLAIM), in place of a transaction signature. The FULL suite's
    scenario: a tower exits on the authorisation with its own fee input,
    rebuilds it against a new root after a competing spend, and the voucher
    tag, another tree_id, a changed leaf, a transaction signature, an empty
    element and an inexact payout all fail; the evict branch is unchanged;
    EXIT_2^t runs on two authorisations, or one and an eviction. Swapped
    into the taptree as EXIT_1 and EXIT_2 through CCVTreeOptions
    (tower=True), a tree-creation parameter kept by a detached child."""
    S = profile == "S"
    c0 = numeric == "c0"
    tag = f"{numeric} {profile}/{depth}: EXIT^t"
    opts = C.CCVTreeOptions(pubkey_x(sk("operator")), numeric, profile, TREE_ID, (0, 2), (1, 2), (2,), (1, 2),
                            tower=True)
    scripts = opts.at_depth(depth)
    if c0:
        w = WorldC0(depth, profile)
        gen = lambda k: C._exit_script_ccv0(depth, k, S, tower=True, tree_id=TREE_ID)  # noqa: E731
        allowed, mode, lv = C0_OPCODES | CSFS_OPS, "c0", 0xc0
    else:
        w = World(depth, profile)
        gen = lambda k: C.exit_script_ccv(depth, k, profile, tower=True, tree_id=TREE_ID)  # noqa: E731
        allowed, mode, lv = ALLOWED | CSFS_OPS, "c2", 0xc2
    w.compiled = dict(w.compiled)
    for k in (1, 2):
        toks = scripts[f"EXIT_{k}"]
        bad = {t for t in toks if isinstance(t, str)} - allowed
        check(not bad, f"{tag}: EXIT_{k}^t opcodes outside the CCV set plus CSFS: {sorted(bad)}")
        check(assemble(toks, mode=mode) == assemble(gen(k), mode=mode), f"{tag}: CCVTreeOptions compiles EXIT_{k}^t")
        w.compiled[f"EXIT_{k}"] = assemble(toks, mode=mode)
    check("OP_CHECKSIGFROMSTACK" in scripts["EXIT_1"], f"{tag}: the authorisation is checked with OP_CHECKSIGFROMSTACK")
    check(w.compiled["EXIT_1"] != assemble(C.all_scripts_ccv(depth, w.op_pk, (0, 2), (1, 2), profile, (2,), numeric)["EXIT_1"], mode=mode),
          f"{tag}: EXIT_1^t differs from EXIT_1")
    if not S and depth > 2:
        check(assemble(opts.at_depth(2)["EXIT_1"], mode=mode) == assemble(
            C._exit_script_ccv0(2, 1, False, tower=True, tree_id=TREE_ID) if c0
            else C.exit_script_ccv(2, 1, "D", tower=True, tree_id=TREE_ID), mode=mode),
            f"{tag}: a detached child keeps EXIT_1^t (7.10 rule 3)")
    w.m = lt.taptree_root([lt.tapleaf_hash(c, lv) for c in w.compiled.values()])
    script = w.compiled["EXIT_1"]

    def mk(label, amount, evictor=None, evict_after=0):
        lf = mk_leaf(label, amount, evictor, evict_after)
        while c0 and S and not M.pos_ok(lf):
            lf.nonce = (lf.nonce + 1) & 0xffffffff
        return lf
    alice = mk("alice", 50_000)
    bob = mk("bob", 125_000, w.op_pk, 800_000)
    oper = mk("operator", 1_000_000)
    s_a, s_b, s_o = w.slot(alice, 0), w.slot(bob, 5), w.slot(oper, (1 << depth) - 1)
    base = {s_a: alice, s_b: bob, s_o: oper}
    auth = schnorr_sign(lt.exit_auth_msg(TREE_ID, bob), sk("bob-owner"))
    other_tid = lt.tree_id(lt.sha256(b"another-tree"), 0)

    def block(path, leaf, sig, is_evict, root=None, new_total=None, first=True):
        """One exit block for `leaf`; under c0 the first block carries the
        input-amount pad and the whole witness starts with the output pad."""
        if not c0:
            return w.path_witness(path) + [leaf.serialize(), sig, is_evict]
        items = M.w_levels(path, leaf.node(), lt.EMPTY_NODE, S) + w.pos(leaf) + M.w_leaf_exit(leaf) + [sig, is_evict]
        return (w.pads_for(root[1]) if first else []) + items

    def exit_tx(leaves, leaf, slot, amount=None, locktime=0):
        """The tower's exit of `leaf`: the context (a fee input of the
        tower's own, an exact payout unless `amount` says otherwise), the
        witness prefix and suffix around the authorisation, and the root."""
        w.tree = lt.Tree(depth); w.tree.leaves = dict(leaves)
        root = w.tree.root()
        path = w.tree.path(slot)
        t1 = w.clone(); del t1.leaves[slot]; r1 = t1.root()
        pay = leaf.amount if amount is None else amount
        outs = [(r1[1], w.spk(r1)), (pay, lt.p2tr_spk(leaf.exit_key))]
        ctx = w.ctx(outs, (5_000, P2WPKH), locktime=locktime)
        head = list(M.pad(r1[1])) if c0 else []

        def wit(sig, is_evict=b""):
            return head + block(path, leaf, sig, is_evict, root, r1[1])
        return ctx, wit, root

    ctx, wit, root = exit_tx(base, bob, s_b)
    it = w.run("EXIT_1", wit(auth), ctx)
    check(True, f"{tag}: a tower exits the leaf on the owner's authorisation")
    sizes = (it, len(script), sum(len(x) for x in wit(auth)))
    expect_fail(lambda: w.run("EXIT_1", wit(schnorr_sign(ctx.sighash(), sk("bob-owner"))), ctx),
                f"{tag}: a transaction signature is not an authorisation")
    expect_fail(lambda: w.run("EXIT_1", wit(b""), ctx), f"{tag}: empty authorisation")
    voucher_tagged = schnorr_sign(lt.tagged_hash(lt.TAG_VOUCHER, TREE_ID + bob.serialize()), sk("bob-owner"))
    expect_fail(lambda: w.run("EXIT_1", wit(voucher_tagged), ctx), f"{tag}: an authorisation under the voucher tag")
    expect_fail(lambda: w.run("EXIT_1", wit(schnorr_sign(lt.exit_auth_msg(other_tid, bob), sk("bob-owner"))), ctx),
                f"{tag}: an authorisation for another tree_id")
    expect_fail(lambda: w.run("EXIT_1", wit(schnorr_sign(lt.exit_auth_msg(TREE_ID, bob), sk("alice-owner"))), ctx),
                f"{tag}: an authorisation by another owner")
    ctx_lo, wit_lo, _ = exit_tx(base, bob, s_b, amount=bob.amount - 1)
    expect_fail(lambda: w.run("EXIT_1", wit_lo(auth), ctx_lo), f"{tag}: payout below the amount")
    ctx_hi, wit_hi, _ = exit_tx(base, bob, s_b, amount=bob.amount + 1)
    expect_fail(lambda: w.run("EXIT_1", wit_hi(auth), ctx_hi), f"{tag}: payout above the amount")
    after = dict(base); del after[s_a]
    ctx2, wit2, _ = exit_tx(after, bob, s_b)
    w.run("EXIT_1", wit2(auth), ctx2)
    check(True, f"{tag}: the authorisation is rebuilt against a new root after a competing spend")
    bob2 = bob.with_amount_seq(bob.amount, 1)
    changed = dict(base); changed[s_b] = bob2
    ctx3, wit3, _ = exit_tx(changed, bob2, s_b)
    expect_fail(lambda: w.run("EXIT_1", wit3(auth), ctx3), f"{tag}: an authorisation for the leaf before it changed")
    w.run("EXIT_1", wit3(schnorr_sign(lt.exit_auth_msg(TREE_ID, bob2), sk("bob-owner"))), ctx3)
    check(True, f"{tag}: a fresh authorisation over the changed leaf")
    # an amount-only top-up leaves the authorisation valid; the exit pays the new amount
    bob_up = bob.with_amount_seq(bob.amount + 500, bob.seq)
    up = dict(base); up[s_b] = bob_up
    ctx4, wit4, _ = exit_tx(up, bob_up, s_b)
    w.run("EXIT_1", wit4(auth), ctx4)
    check(True, f"{tag}: the authorisation survives an amount-only top-up of the leaf")
    ctx4o, wit4o, _ = exit_tx(up, bob_up, s_b, amount=bob.amount)
    expect_fail(lambda: w.run("EXIT_1", wit4o(auth), ctx4o), f"{tag}: the exit after a top-up pays the amount at signing")
    for label, lf in (("exit_key", lt.Leaf(bob.amount, pubkey_x(sk("other-exit")), bob.owner_key, bob.evictor_key, bob.evict_after, bob.nonce, bob.seq)),
                      ("evictor_key", lt.Leaf(bob.amount, bob.exit_key, bob.owner_key, lt.NUMS_X, bob.evict_after, bob.nonce, bob.seq)),
                      ("evict_after", lt.Leaf(bob.amount, bob.exit_key, bob.owner_key, bob.evictor_key, bob.evict_after + 1, bob.nonce, bob.seq))):
        chg = dict(base); chg[s_b] = lf
        ctx5, wit5, _ = exit_tx(chg, lf, s_b)
        expect_fail(lambda: w.run("EXIT_1", wit5(auth), ctx5), f"{tag}: an authorisation for the leaf before its {label} changed")
    ctx_e, wit_e, _ = exit_tx(base, bob, s_b, locktime=800_000)
    w.run("EXIT_1", wit_e(schnorr_sign(ctx_e.sighash(), w.op_sk), b"\x01"), ctx_e)
    check(True, f"{tag}: eviction")
    expect_fail(lambda: w.run("EXIT_1", wit_e(auth, b"\x01"), ctx_e), f"{tag}: a stack authorisation in the evict branch")
    ctx_early, wit_early, _ = exit_tx(base, bob, s_b, locktime=799_999)
    expect_fail(lambda: w.run("EXIT_1", wit_early(schnorr_sign(ctx_early.sighash(), w.op_sk), b"\x01"), ctx_early),
                f"{tag}: eviction before the lease")
    # EXIT_2^t: two authorisations, then one authorisation and an eviction
    w.tree = lt.Tree(depth); w.tree.leaves = dict(base)
    root = w.tree.root()
    t7 = w.clone()
    path_a = t7.path(s_a); del t7.leaves[s_a]
    path_b = t7.path(s_b); del t7.leaves[s_b]
    r7 = t7.root()
    auth_a = schnorr_sign(lt.exit_auth_msg(TREE_ID, alice), sk("alice-owner"))
    outs = [(r7[1], w.spk(r7)), (alice.amount, lt.p2tr_spk(alice.exit_key)), (bob.amount, lt.p2tr_spk(bob.exit_key))]
    head = list(M.pad(r7[1])) if c0 else []
    b1 = block(path_a, alice, auth_a, b"", root, r7[1], first=True)

    def two(sig_b, is_evict_b=b""):
        return head + block(path_b, bob, sig_b, is_evict_b, root, r7[1], first=False) + b1
    ctx7 = w.ctx(outs, (5_000, P2WPKH))
    w.run("EXIT_2", two(auth), ctx7)
    check(True, f"{tag}: EXIT_2^t, two authorisations")
    expect_fail(lambda: w.run("EXIT_2", two(auth_a), ctx7), f"{tag}: EXIT_2^t, alice's authorisation presented for bob")
    ctx8 = w.ctx(outs, (5_000, P2WPKH), locktime=800_000)
    w.run("EXIT_2", two(schnorr_sign(ctx8.sighash(), w.op_sk), b"\x01"), ctx8)
    check(True, f"{tag}: EXIT_2^t, one authorisation and one eviction")
    return sizes


# ------------------------------------------ pending-leaf receive (7.5.4, 7.9 rule 8, 7.11) --

RECLAIM_SK = sk("operator-reclaim")



class PendingWorldCCV:
    """test_scripts.PendingWorld under CCV in either numerics: a dense tree
    naming RECLAIM_KEY and carrying RECLAIM_1, CLAIM^m, CLAIM^hm, CLAIM^x,
    UPDATE^x and the reclaim-form rewrite at heights 1 and 2 (REWRITE_R_h
    and REWRITE_XR_h), compiled through CCVTreeOptions."""

    def __init__(self, depth, numeric="c2", rewrite_heights=(1, 2)):
        self.depth, self.numeric, self.c0 = depth, numeric, numeric == "c0"
        self.mode, lv = ("c0", 0xc0) if self.c0 else ("c2", 0xc2)
        self.w = WorldC0(depth, "D") if self.c0 else World(depth, "D")
        self.rk = pubkey_x(RECLAIM_SK)
        self.opts = C.CCVTreeOptions(self.w.op_pk, numeric, "D", TREE_ID, exit_ks=(1,), update_x=True,
                                     claim_x=True, rewrite_heights=rewrite_heights, rewrite_x=True,
                                     reclaim_key=self.rk, claim_m=True, claim_hm=True)
        scripts = self.opts.at_depth(depth)
        allowed = (C0_OPCODES if self.c0 else ALLOWED) | CSFS_OPS
        for name, toks in scripts.items():
            bad = {t for t in toks if isinstance(t, str)} - allowed
            check(not bad, f"{numeric} {name}: opcodes outside the CCV set plus CSFS: {sorted(bad)}")
        self.w.scripts = scripts
        self.w.compiled = {k: assemble(v, mode=self.mode) for k, v in scripts.items()}
        self.w.m = lt.taptree_root([lt.tapleaf_hash(c, lv) for c in self.w.compiled.values()])
        self.rcpt = pubkey_x(sk("rcpt-exit"))
        self.seq_final = M.SEQ_FINAL if self.c0 else ls.SEQ_FINAL

    def pending(self, amount, deadline, label="P", seq=0):
        """P: owned by the operator, paid to the recipient, reclaimable at `deadline`."""
        return lt.Leaf(amount, self.rcpt, pubkey_x(sk("operator-owner")), self.rk, deadline,
                       int.from_bytes(lt.sha256(label.encode())[:4], "little"), seq)

    def landing(self, amount, label="L", lease=900_000, owner=None, evictor=None, seq=0):
        """L: owned and exited by the recipient, evictable by the operator after a long lease."""
        return lt.Leaf(amount, self.rcpt, owner or self.rcpt, evictor or self.w.op_pk, lease,
                       int.from_bytes(lt.sha256(label.encode())[:4], "little"), seq)


def _merge_case_ccv(pw, p_slot, l_slot, P, L, X, preimage=None, signer="operator-owner", flag=None,
                    tree_id=TREE_ID, msg_target=None, msg_x=None, out0=None):
    """A CLAIM^m (or CLAIM^hm with a preimage) redemption against the pair,
    in the world's numerics: (witness, ctx, new tree). Under 0xC2 the
    witness is FULL's minus r and m; under 0xC0 _merge_script_ccv0's."""
    w = pw.w
    w.tree.leaves = {p_slot: P, l_slot: L, 0: mk_leaf("alice", 50_000)}
    root = w.tree.root()
    t1 = w.clone()
    try:
        lt.apply_merge(t1, p_slot, l_slot, X)
    except AssertionError:
        # an invalid merge, for a negative: what the transaction would claim
        d = X - L.amount
        t1.leaves[l_slot] = L.with_amount_seq(max(X, 0), L.seq)
        if P.amount - d > 0:
            t1.leaves[p_slot] = P.with_amount_seq(P.amount - d, P.seq)
        else:
            t1.leaves.pop(p_slot, None)
    r1 = t1.root()
    ctx = w.ctx([(r1[1] if out0 is None else out0, w.spk(r1))], (600, P2WPKH))
    ph = lt.sha256(preimage) if preimage is not None else None
    msg = lt.voucher_m_msg(tree_id, P, msg_target or L, msg_x if msg_x is not None else X, ph)
    vsig = schnorr_sign(msg, sk(signer))
    f = flag if flag is not None else (b"\x01" if p_slot % 2 == 0 else b"")
    lo = min(p_slot, l_slot)
    path = w.tree.path(lo, height=1)
    if pw.c0:
        res = P.amount - (X - L.amount)
        wit = (list(M.pad(r1[1])) + list(M.pad(root[1])) +
               M.w_levels(path, w.tree.subtree(1, lo >> 1), t1.subtree(1, lo >> 1), False, 1) +
               [f] + list(M.pad(max(res, 0))) + [M.scriptnum(X)] + list(M.pad(X)) +
               M.w_leaf(P) + M.w_leaf(L) + [vsig])
    else:
        left, right = (P, L) if p_slot % 2 == 0 else (L, P)
        wit = w.path_witness(path, 1) + [left.serialize(), right.serialize(), f, lt.le64(X), vsig]
    if preimage is not None:
        wit.append(preimage)
    return wit, ctx, t1


def test_merge_ccv(depth, numeric="c2", verbose=True):
    """CLAIM^m and CLAIM^hm (7.5.4) under CCV, mirroring
    test_scripts.test_merge: the target raised to an absolute X from either
    side of the pair, a drained source, replay and ordering of targets, a
    negative per rule (voucher, preimage, cross-form, ownership,
    reclaimable or final target or source, X not above the target, an
    over-draw, a sub-dust residual, the side flag, the encoding of X, a
    message over another X, output 0 short), the exact-fit funding hole and
    the DUST_MIN headroom that closes it, and the CCV binding of output 0."""
    pw = PendingWorldCCV(depth, numeric)
    w = pw.w
    tag = f"{numeric} D={depth}"
    pre = lt.sha256(b"receive-preimage")
    P = pw.pending(20_000, 700_000)
    L = pw.landing(10_000)
    wit, ctx, t1 = _merge_case_ccv(pw, 2, 3, P, L, 13_000, pre)
    it = None
    try:
        it = w.run("CLAIM_HM", wit, ctx)
        check(t1.leaves[3].amount == 13_000 and t1.leaves[2].amount == 17_000 and t1.leaves[2].seq == P.seq,
              f"{tag} CLAIM^hm: target raised to X, source lowered by the difference, source seq unchanged")
    except ScriptError as e:
        check(False, f"{tag} CLAIM^hm positive: {str(e)[:120]}")
    hm_size, hm_wit = len(w.compiled["CLAIM_HM"]), sum(len(x) for x in wit)

    def ok(fn, msg):
        try:
            fn()
            check(True, msg)
        except ScriptError as e:
            check(False, f"{msg}: {str(e)[:120]}")

    def case(*a, **k):
        return _merge_case_ccv(pw, *a, **k)[:2]
    ok(lambda: w.run("CLAIM_HM", *case(5, 4, P, L, 13_000, pre)), f"{tag} CLAIM^hm with the source on the right")
    ok(lambda: w.run("CLAIM_M", *case(2, 3, P, L, 12_500)), f"{tag} CLAIM^m raises the target with no preimage")
    wit_d, ctx_d, t_d = _merge_case_ccv(pw, 2, 3, P, L, 30_000)
    ok(lambda: w.run("CLAIM_M", wit_d, ctx_d), f"{tag} CLAIM^m draining the source")
    check(2 not in t_d.leaves, f"{tag} CLAIM^m draining the source leaves E_0")
    ok(lambda: w.run("CLAIM_M", *case(5, 4, P, L, 30_000)), f"{tag} CLAIM^m draining a right-hand source")

    # replay and ordering: target levels are absolute
    raised = L.with_amount_seq(13_000, L.seq)
    lowered = P.with_amount_seq(17_000, P.seq)
    expect_fail(lambda: w.run("CLAIM_HM", *case(2, 3, lowered, raised, 13_000, pre)),
                f"{tag} CLAIM^hm replayed after the target reached X")
    expect_fail(lambda: w.run("CLAIM_HM", *case(2, 3, lowered, raised, 11_000, pre)),
                f"{tag} CLAIM^hm older, smaller target after a larger one")
    ok(lambda: w.run("CLAIM_HM", *case(2, 3, P.with_amount_seq(19_000, 0), L.with_amount_seq(11_000, 0), 13_000, pre)),
       f"{tag} CLAIM^hm newer target after an older one moves only the difference")

    # negatives, one per rule
    expect_fail(lambda: w.run("CLAIM_HM", wit[:-1] + [lt.sha256(b"x")], ctx), f"{tag} CLAIM^hm wrong preimage")
    expect_fail(lambda: w.run("CLAIM_HM", wit[:-1] + [pre[:31]], ctx), f"{tag} CLAIM^hm preimage not 32 bytes")
    expect_fail(lambda: w.run("CLAIM_HM", *case(2, 3, P, L, 13_000, pre, signer="rcpt-exit")),
                f"{tag} CLAIM^hm voucher not by the source owner")
    expect_fail(lambda: w.run("CLAIM_M", *case(2, 3, P, L, 13_000, tree_id=w.m)),
                f"{tag} CLAIM^m voucher over m instead of tree_id")
    plain, ctx_p = case(2, 3, P, L, 13_000)
    expect_fail(lambda: w.run("CLAIM_HM", plain + [pre], ctx_p), f"{tag} CLAIM^hm with a plain merge voucher")
    expect_fail(lambda: w.run("CLAIM_M", wit[:-1], ctx), f"{tag} CLAIM^m with a hash-locked merge voucher")
    stranger = pw.landing(10_000, owner=pubkey_x(sk("operator-owner")))
    expect_fail(lambda: w.run("CLAIM_M", *case(2, 3, P, stranger, 13_000)),
                f"{tag} CLAIM^m into a sibling the source's exit key does not own")
    elsewhere = lt.Leaf(10_000, pubkey_x(sk("mallory-exit")), pw.rcpt, w.op_pk, 900_000, 77, 0)
    expect_fail(lambda: w.run("CLAIM_M", *case(2, 3, P, elsewhere, 13_000)),
                f"{tag} CLAIM^m into a sibling owned by the source's exit key but exiting elsewhere")
    flagged = pw.landing(10_000, evictor=pw.rk)
    expect_fail(lambda: w.run("CLAIM_M", *case(2, 3, P, flagged, 13_000)), f"{tag} CLAIM^m into a reclaimable target")
    final_t = pw.landing(10_000, seq=pw.seq_final)
    expect_fail(lambda: w.run("CLAIM_M", *case(2, 3, P, final_t, 13_000)), f"{tag} CLAIM^m into a SEQ_FINAL target")
    final_s = pw.pending(20_000, 700_000, seq=pw.seq_final)
    expect_fail(lambda: w.run("CLAIM_M", *case(2, 3, final_s, L, 13_000)), f"{tag} CLAIM^m from a SEQ_FINAL source")
    expect_fail(lambda: w.run("CLAIM_M", *case(2, 3, P, L, 10_000)), f"{tag} CLAIM^m with X not above the target's amount")
    expect_fail(lambda: w.run("CLAIM_M", *case(2, 3, P, L, 30_001)), f"{tag} CLAIM^m drawing more than the source holds")
    expect_fail(lambda: w.run("CLAIM_M", *case(2, 3, P, L, 29_800)), f"{tag} CLAIM^m leaving a sub-dust residual")
    ok(lambda: w.run("CLAIM_M", *case(2, 3, P, L, 30_000 - lt.DUST_MIN)), f"{tag} CLAIM^m leaving exactly DUST_MIN")
    expect_fail(lambda: w.run("CLAIM_M", *case(2, 3, P, L, 13_000, flag=b"")),
                f"{tag} CLAIM^m with the source flag pointing at the target")
    expect_fail(lambda: w.run("CLAIM_M", *case(2, 3, P, L, 13_000, flag=b"\x02")),
                f"{tag} CLAIM^m with a source flag other than empty or 0x01")
    wit_x, ctx_x = case(2, 3, P, L, 13_000)
    if pw.c0:
        # X_num sits under zX wX, the src block, the tgt block and vsig
        at = len(wit_x) - 1 - 2 * M.LEAF_WITNESS - 3
        assert wit_x[at] == M.scriptnum(13_000)
        expect_fail(lambda: w.run("CLAIM_M", wit_x[:at] + [M.scriptnum(13_000 + 65_536)] + wit_x[at + 1:], ctx_x),
                    f"{tag} CLAIM^m with X's number and its pad giving another le64(X)")
        expect_fail(lambda: w.run("CLAIM_M", wit_x[:at] + [M.scriptnum(13_000), b"", bytes(4)] + wit_x[at + 3:], ctx_x),
                    f"{tag} CLAIM^m with a malformed pad on X")
    else:
        at = len(wit_x) - 2
        expect_fail(lambda: w.run("CLAIM_M", wit_x[:at] + [lt.le64(13_000)[:7]] + wit_x[at + 1:], ctx_x),
                    f"{tag} CLAIM^m with a 7-byte X")
    expect_fail(lambda: w.run("CLAIM_M", *case(2, 3, P, L, 13_000, msg_x=14_000)),
                f"{tag} CLAIM^m with X other than the signed target")
    expect_fail(lambda: w.run("CLAIM_M", *case(2, 3, P, L, 13_000, msg_target=L.with_amount_seq(L.amount, L.seq + 1))),
                f"{tag} CLAIM^m voucher naming another target body")
    r_o = _merge_case_ccv(pw, 2, 3, P, L, 13_000)[2].root()
    expect_fail(lambda: w.run("CLAIM_M", *case(2, 3, P, L, 13_000, out0=r_o[1] - 1)), f"{tag} CLAIM^m with output 0 short")
    expect_fail(lambda: w.run("CLAIM_M", *case(2, 3, P, L, 13_000, out0=r_o[1] + 1)), f"{tag} CLAIM^m with output 0 above ns")
    wit_t, ctx_t, t_t = _merge_case_ccv(pw, 2, 3, P, L, 13_000)
    ctx_t.outputs[0] = (ctx_t.outputs[0][0], lt.tree_spk_ccv(t_t.root()[0], lt.sha256(b"wrong-taptree")))
    expect_fail(lambda: w.run("CLAIM_M", wit_t, ctx_t), f"{tag} CLAIM^m with output 0 under a wrong taptree")

    # the exact-fit funding hole and the DUST_MIN headroom
    tight = pw.pending(3_000, 700_000)
    ok(lambda: w.run("CLAIM_HM", *case(2, 3, tight, L, 13_000, pre)), f"{tag} CLAIM^hm draining an exactly funded pending leaf")
    expect_fail(lambda: w.run("CLAIM_HM", *case(2, 3, tight.with_amount_seq(3_001, 0), L, 13_000, pre)),
                f"{tag} CLAIM^hm blocked by a one-satoshi top-up of an exactly funded pending leaf")
    roomy = pw.pending(3_000 + lt.DUST_MIN, 700_000)
    for extra in (0, 1, 50_000):
        ok(lambda: w.run("CLAIM_HM", *case(2, 3, roomy.with_amount_seq(roomy.amount + extra, 0), L, 13_000, pre)),
           f"{tag} CLAIM^hm with DUST_MIN of headroom redeems after a top-up of {extra}")
    if verbose:
        print(f"    CLAIM^m {tag}: script {len(w.compiled['CLAIM_M'])} B; CLAIM^hm script {hm_size} B, "
              f"witness {hm_wit} B ({len(wit)} elements), varops {it.cost if it else '-'}")
    return hm_size, hm_wit


def test_reclaim_ccv(depth, numeric="c2", verbose=True):
    """RECLAIM_1 (7.11) under CCV, mirroring test_scripts.test_reclaim: the
    reclaim after the deadline with the leaf's value going to another
    output, and its negatives (before the deadline, the wrong key, output
    0 short or above ns, a leaf whose evictor is not RECLAIM_KEY, the
    landing leaf). The CCV amount rule: output 0 is checked in the DEDUCT
    mode, so the reclaimed value is unassigned and free; the same body
    with the assign mode of every other transition fails the spend, and a
    second copy of the tree state cannot reuse output 0."""
    pw = PendingWorldCCV(depth, numeric)
    w, c0 = pw.w, pw.c0
    tag = f"{numeric} D={depth}"
    P = pw.pending(20_000, 700_000)
    w.tree.leaves = {2: P, 3: pw.landing(10_000), 0: mk_leaf("alice", 50_000)}
    base_leaves = dict(w.tree.leaves)

    def spend(leaf=P, locktime=700_000, signer=RECLAIM_SK, out0=None, name="RECLAIM_1", ea=None,
              outs_extra=((20_000, P2WPKH),), extra_in=(600, P2WPKH), run=True, spk0=None):
        slot = next(k for k, v in w.tree.leaves.items() if v is leaf)
        rt = w.tree.root()
        t = w.clone(); del t.leaves[slot]
        rn = t.root()
        ctx = w.ctx([(rn[1] if out0 is None else out0, spk0 or w.spk(rn))] + list(outs_extra), extra_in,
                    locktime=locktime)
        sig = schnorr_sign(ctx.sighash(), signer)
        p = w.tree.path(slot)
        if c0:
            e = leaf.evict_after if ea is None else ea
            wit = (list(M.pad(rn[1])) + list(M.pad(rt[1])) + M.w_levels(p, leaf.node(), lt.EMPTY_NODE) +
                   M.w_leaf(leaf) + [M.scriptnum(e), *M.pad(e), sig])
        else:
            wit = w.path_witness(p) + [leaf.serialize(), sig]
        if not run:
            return wit, ctx
        return w.run(name, wit, ctx)

    it = None
    try:
        it = spend()
        check(True, f"{tag} RECLAIM_1 after the deadline, value free for the transaction")
    except ScriptError as e:
        check(False, f"{tag} RECLAIM_1 positive: {str(e)[:120]}")
    wit, _ = spend(run=False)
    size, wsize = len(w.compiled["RECLAIM_1"]), sum(len(x) for x in wit)
    try:
        spend(outs_extra=(), extra_in=(600, P2WPKH))
        check(True, f"{tag} RECLAIM_1 with the reclaimed value left entirely to the fee")
    except ScriptError as e:
        check(False, f"{tag} RECLAIM_1 value to fee: {str(e)[:120]}")
    expect_fail(lambda: spend(locktime=699_999), f"{tag} RECLAIM_1 before the deadline")
    expect_fail(lambda: spend(signer=sk("operator")), f"{tag} RECLAIM_1 signed by OPERATOR_KEY, not RECLAIM_KEY")
    t_n = w.clone(); del t_n.leaves[2]
    rn = t_n.root()
    expect_fail(lambda: spend(out0=rn[1] - 1), f"{tag} RECLAIM_1 with output 0 short")
    expect_fail(lambda: spend(out0=rn[1] + 1, extra_in=(5_000, P2WPKH)), f"{tag} RECLAIM_1 with output 0 above ns")
    expect_fail(lambda: spend(spk0=lt.tree_spk_ccv(rn[0], lt.sha256(b"wrong-taptree"))),
                f"{tag} RECLAIM_1 with output 0 under a wrong taptree")
    if c0:
        expect_fail(lambda: spend(locktime=699_999, ea=699_999),
                    f"{tag} RECLAIM_1 with an evict_after number other than the leaf's")
    plain = mk_leaf("bob", 20_000, w.op_pk, 600_000)
    w.tree.leaves[6] = plain
    expect_fail(lambda: spend(leaf=plain, locktime=700_000), f"{tag} RECLAIM_1 of a leaf whose evictor is not RECLAIM_KEY")
    w.tree.leaves = dict(base_leaves)
    L = w.tree.leaves[3]
    expect_fail(lambda: spend(leaf=L, locktime=900_000), f"{tag} RECLAIM_1 of the landing leaf")
    # the amount rule: the same body with output 0 in the assign mode
    # cannot free the leaf's value, since the floor is the whole input
    toks = w.scripts["RECLAIM_1"]
    if c0:
        fin2 = C._final_ccv0(depth, mode=2)
        assign = toks[:-len(fin2)] + C._final_ccv0(depth)
    else:
        fin2 = C.final_ccv(depth, mode=2)
        assign = toks[:-len(fin2)] + C.final_ccv(depth)
    check(toks[-len(fin2):] == fin2, f"{tag} RECLAIM_1 ends in the DEDUCT-mode output check")
    w.compiled = dict(w.compiled); w.compiled["RECLAIM_ASSIGN"] = assemble(assign, mode=pw.mode)
    expect_fail(lambda: spend(name="RECLAIM_ASSIGN"),
                f"{tag} RECLAIM_1's body with an assign-mode output 0 cannot free the reclaimed value")
    # two copies of the tree state in one transaction: the second DEDUCT of
    # output 0 fails (spec 4.1 [A-6])
    wit2, ctx2 = spend(run=False)
    rt = w.tree.root()
    ctx2.inputs = [ctx2.inputs[0], ctx2.inputs[0], ctx2.inputs[1]]
    ctx2.sequences = [0xfffffffd] * 3
    ctx2.prevouts = [ctx2.prevouts[0], (lt.sha256(b"copy"), 7), ctx2.prevouts[1]]
    ctx2.ccv_reset()
    sig2 = schnorr_sign(ctx2.sighash(), RECLAIM_SK)
    wit2 = wit2[:-1] + [sig2]
    try:
        w.run("RECLAIM_1", wit2, ctx2)
        check(True, f"{tag} RECLAIM_1: the first copy passes on its own")
    except ScriptError as e:
        check(False, f"{tag} RECLAIM_1 first copy: {str(e)[:100]}")

    def second():
        ctx2.input_index = 1
        return w.run("RECLAIM_1", wit2[:-1] + [schnorr_sign(ctx2.sighash(), RECLAIM_SK)], ctx2)
    expect_fail(second, f"{tag} RECLAIM_1: a second copy of the state cannot deduct output 0 again")
    if verbose:
        print(f"    RECLAIM_1 {tag}: script {size} B, witness {wsize} B ({len(wit)} elements), "
              f"varops {it.cost if it else '-'}")
    return size, wsize


def test_reclaim_sparse_ccv(depth, numeric="c2"):
    """RECLAIM_1 (7.11) in the sparse profile, which FULL's option set
    also carries: the reclaim after the deadline, and before it."""
    c0 = numeric == "c0"
    w = WorldC0(depth, "S") if c0 else World(depth, "S")
    rk = pubkey_x(RECLAIM_SK)
    opts = C.CCVTreeOptions(w.op_pk, numeric, "S", TREE_ID, reclaim_key=rk)
    mode, lv = ("c0", 0xc0) if c0 else ("c2", 0xc2)
    w.compiled = {k: assemble(v, mode=mode) for k, v in opts.at_depth(depth).items()}
    w.m = lt.taptree_root([lt.tapleaf_hash(c, lv) for c in w.compiled.values()])
    tag = f"{numeric} S/{depth}"
    P = lt.Leaf(20_000, pubkey_x(sk("rcpt-exit")), pubkey_x(sk("operator-owner")), rk, 700_000, 5, 0)
    while c0 and not M.pos_ok(P, depth):
        P.nonce += 1
    alice = mk_leaf("alice", 50_000)
    while c0 and not M.pos_ok(alice, depth):
        alice.nonce += 1
    s_p, s_a = w.slot(P), w.slot(alice)
    w.tree.leaves = {s_p: P, s_a: alice}

    def spend(locktime):
        rt = w.tree.root()
        t = w.clone(); del t.leaves[s_p]
        rn = t.root()
        ctx = w.ctx([(rn[1], w.spk(rn)), (20_000, P2WPKH)], (600, P2WPKH), locktime=locktime)
        sig = schnorr_sign(ctx.sighash(), RECLAIM_SK)
        p = w.tree.path(s_p)
        if c0:
            wit = (list(M.pad(rn[1])) + list(M.pad(rt[1])) + M.w_levels(p, P.node(), lt.EMPTY_NODE, True) +
                   w.pos(P) + M.w_leaf(P) + [M.scriptnum(P.evict_after), *M.pad(P.evict_after), sig])
        else:
            wit = w.path_witness(p) + [P.serialize(), sig]
        return w.run("RECLAIM_1", wit, ctx)
    try:
        spend(700_000)
        check(True, f"{tag} RECLAIM_1 after the deadline")
    except ScriptError as e:
        check(False, f"{tag} RECLAIM_1 positive: {str(e)[:120]}")
    expect_fail(lambda: spend(699_999), f"{tag} RECLAIM_1 before the deadline")


def _r1_due(pw, i, o, nw):
    """Whether position i (even = the left of a pair) of the reclaim-form
    rewrite takes R1, so that its 0xC0 block carries ea_num ze we:
    a changed reclaimable leaf that is neither rule 3's amount-only
    increase nor, on the left, an R3 transfer."""
    if o is None or o.evictor_key != pw.rk or (nw is not None and o.serialize() == nw.serialize()):
        return False
    same = nw is not None and nw.serialize()[8:] == o.serialize()[8:]
    if same and nw.amount >= o.amount and o.seq != pw.seq_final:
        return False
    if i % 2 == 0 and same and nw.amount < o.amount:
        return False
    return True


def _pending_rewrite_ccv(pw, name, base, height, old, new, locktime=0, sign=(), flag=None, tamper=None,
                         extra_leaves=None, run=True, ea=None):
    """Run REWRITE_R_h / REWRITE_XR_h over positions base..base+2^h-1 in
    the world's numerics (test_scripts._pending_rewrite's scenario). flag is
    the output-0 mode flag (DEDUCT, 0x01, when the rewrite frees value;
    assign, empty, otherwise); `ea` overrides the evict_after number of
    0xC0 R1 blocks."""
    w = pw.w
    n = 1 << height
    leaves = {base + i: lf for i, lf in old.items() if lf}
    leaves[0] = mk_leaf("alice", 50_000)
    leaves.update(extra_leaves or {})
    w.tree.leaves = leaves
    root = w.tree.root()
    t1 = w.clone()
    for i in range(n):
        if new[i]:
            t1.leaves[base + i] = new[i]
        else:
            t1.leaves.pop(base + i, None)
    r1 = t1.root()
    freed = root[1] - r1[1]
    outputs = [(r1[1], w.spk(r1)), (max(freed, 0) + 1_000, P2WPKH)]
    ctx = w.ctx(outputs, (5_000 + max(-freed, 0), P2WPKH), locktime=locktime)
    sig_op = schnorr_sign(ctx.sighash(), w.op_sk)
    if flag is None:
        flag = b"\x01" if freed > 0 else b""
    extras = {}
    for i in range(n):
        if i in sign:
            sg = [schnorr_sign(ctx.sighash(), sk("operator-owner"))]
            if "X" in name:
                sg.append(schnorr_sign(ctx.sighash(), sk("rcpt-exit")))
            extras[i] = sg
        elif pw.c0 and _r1_due(pw, i, old[i], new[i]):
            e = old[i].evict_after if ea is None else ea
            extras[i] = list(reversed([M.scriptnum(e), *M.pad(e)]))   # w_rewrite reverses a block's extras
    if pw.c0:
        body = M.w_rewrite(w.tree, pw.depth, height, base >> height, new, extras)
    else:
        path = w.tree.path(base, height=height)
        body = w.path_witness(path, height) + _rewrite_blocks_c2(old, new, extras, n)
    wit = [flag] + body + [sig_op]
    if tamper:
        wit = tamper(wit)
    if not run:
        return wit, ctx
    return w.run(name, wit, ctx)


def test_pending_rewrite_ccv(depth, numeric="c2", verbose=True):
    """The reclaim form of REWRITE_h (7.9 rule 8) under CCV, mirroring
    test_scripts.test_pending_rewrite: an R3 settlement with the operator's
    signature alone and its negatives, an R1 reclaim and roll after the
    deadline and before it, a top-up of the pending leaf, every way of
    reaching a leaf that is not reclaimable, and a two-pair rewrite. The
    CCV-specific cases are the output-0 mode flag: a reclaim under the
    assign mode and a funded roll under DEDUCT both fail, as does a flag
    other than empty or 0x01; under 0xC0 an R1 block with another
    evict_after number fails, and so does a marker on the right of a
    recorded transfer."""
    pw = PendingWorldCCV(depth, numeric)
    tag = f"{numeric} D={depth}"
    T = 700_000
    P, L = pw.pending(20_000, T), pw.landing(10_000)

    def ok(fn, msg):
        try:
            fn()
            check(True, msg)
        except ScriptError as e:
            check(False, f"{msg}: {str(e)[:120]}")

    def run(*a, **k):
        return _pending_rewrite_ccv(pw, *a, **k)
    for name in ("REWRITE_R_1", "REWRITE_XR_1"):
        t = f"{tag} {name}"
        settle = {0: P.with_amount_seq(13_000, 0), 1: L.with_amount_seq(17_000, 0)}
        ok(lambda: run(name, 2, 1, {0: P, 1: L}, settle), f"{t} R3 transfer P -> L, operator only, before the deadline")
        ok(lambda: run(name, 2, 1, {0: P, 1: L}, settle, flag=b"\x01"), f"{t} R3 transfer under the DEDUCT flag")
        expect_fail(lambda: run(name, 2, 1, {0: P, 1: L}, {0: P.with_amount_seq(13_000, 0), 1: L.with_amount_seq(16_999, 0)}),
                    f"{t} R3 with the landing leaf raised by less than the transfer")
        expect_fail(lambda: run(name, 2, 1, {0: P, 1: L}, {0: P.with_amount_seq(13_000, 0), 1: L}),
                    f"{t} R3 with the landing leaf unchanged")
        other = pw.landing(10_000, owner=pubkey_x(sk("operator-owner")))
        expect_fail(lambda: run(name, 2, 1, {0: P, 1: other}, {0: P.with_amount_seq(13_000, 0), 1: other.with_amount_seq(17_000, 0)}),
                    f"{t} R3 into a sibling the pending leaf's exit key does not own")
        away = lt.Leaf(10_000, pubkey_x(sk("mallory-exit")), pw.rcpt, pw.w.op_pk, 900_000, 77, 0)
        expect_fail(lambda: run(name, 2, 1, {0: P, 1: away},
                                {0: P.with_amount_seq(13_000, 0), 1: away.with_amount_seq(17_000, 0)}),
                    f"{t} R3 into a sibling owned by the pending leaf's exit key but exiting elsewhere")
        flagged = pw.landing(10_000, evictor=pw.rk)
        expect_fail(lambda: run(name, 2, 1, {0: P, 1: flagged}, {0: P.with_amount_seq(13_000, 0), 1: flagged.with_amount_seq(17_000, 0)}),
                    f"{t} R3 into a reclaimable sibling")
        expect_fail(lambda: run(name, 4, 1, {0: L, 1: P}, {0: L.with_amount_seq(17_000, 0), 1: P.with_amount_seq(13_000, 0)}),
                    f"{t} R3 with the pending leaf on the right")
        rekeyed = lt.Leaf(17_000, L.exit_key, L.owner_key, L.evictor_key, L.evict_after + 1, L.nonce, L.seq)
        expect_fail(lambda: run(name, 2, 1, {0: P, 1: L}, {0: P.with_amount_seq(13_000, 0), 1: rekeyed}),
                    f"{t} R3 with the landing leaf changed beyond its amount")
        # R1: reclaim after the deadline, emptied with no payout, or rolled
        ok(lambda: run(name, 2, 1, {0: P, 1: L}, {0: None, 1: L}, locktime=T), f"{t} R1 reclaim after the deadline, no payout")
        P2 = pw.pending(25_000, T + 1_008, label="P2")
        ok(lambda: run(name, 2, 1, {0: P, 1: L}, {0: P2, 1: L}, locktime=T), f"{t} R1 roll: the expired pending leaf replaced by the next window's")
        P3 = pw.pending(15_000, T + 1_008, label="P3")
        ok(lambda: run(name, 2, 1, {0: P, 1: L}, {0: P3, 1: L}, locktime=T), f"{t} R1 roll to a smaller pending leaf, the difference freed")
        expect_fail(lambda: run(name, 2, 1, {0: P, 1: L}, {0: None, 1: L}, locktime=T - 1), f"{t} R1 reclaim before the deadline")
        expect_fail(lambda: run(name, 2, 1, {0: P, 1: L}, {0: P2, 1: L}, locktime=T - 1), f"{t} R1 roll before the deadline")
        # the CCV output-0 mode: a reclaim needs DEDUCT, a funded roll assign
        expect_fail(lambda: run(name, 2, 1, {0: P, 1: L}, {0: None, 1: L}, locktime=T, flag=b""),
                    f"{t} R1 reclaim with output 0 in the assign mode")
        expect_fail(lambda: run(name, 2, 1, {0: P, 1: L}, {0: P2, 1: L}, locktime=T, flag=b"\x01"),
                    f"{t} R1 roll that adds value with output 0 in the DEDUCT mode")
        expect_fail(lambda: run(name, 2, 1, {0: P, 1: L}, {0: None, 1: L}, locktime=T, flag=b"\x02"),
                    f"{t} R1 reclaim with a mode flag other than empty or 0x01")
        if pw.c0:
            expect_fail(lambda: run(name, 2, 1, {0: P, 1: L}, {0: None, 1: L}, locktime=T - 1, ea=T - 1),
                        f"{t} R1 with an evict_after number other than the leaf's")
        # an amount-only top-up of the pending leaf is still rule 3's
        ok(lambda: run(name, 2, 1, {0: P, 1: L}, {0: P.with_amount_seq(25_000, 0), 1: L}), f"{t} top-up of the pending leaf, operator only")
        # nothing reaches a leaf that is not reclaimable
        A = mk_leaf("c0", 20_000, pw.w.op_pk, 600_000)
        B = mk_leaf("c1", 10_000, pw.w.op_pk, 600_000)
        expect_fail(lambda: run(name, 2, 1, {0: A, 1: B}, {0: None, 1: B}, locktime=T),
                    f"{t} emptying an ordinary leaf with no signature")
        expect_fail(lambda: run(name, 2, 1, {0: L, 1: P}, {0: None, 1: P}, locktime=900_000),
                    f"{t} reclaiming the landing leaf")
        expect_fail(lambda: run(name, 2, 1, {0: A, 1: B}, {0: A.with_amount_seq(13_000, 0), 1: B.with_amount_seq(17_000, 0)}),
                    f"{t} R3 from an ordinary leaf")
        if pw.c0:
            # a recorded transfer cannot meet the right position's marker
            def marker_right(wit):
                b = list(wit)
                slot = M.w_rewrite_slot(L.with_amount_seq(17_000, 0))
                at = next(j for j in range(len(b)) if b[j:j + len(slot)] == slot)
                return b[:at] + [M.REWRITE_SAME] + b[at + len(slot):]
            expect_fail(lambda: run(name, 2, 1, {0: P, 1: L}, settle, tamper=marker_right),
                        f"{t} R3 transfer with the landing leaf presented as unchanged")
    # two pairs in one rewrite: one settles, the other reclaims and rolls
    P_b, L_b = pw.pending(9_000, T, label="Pb"), pw.landing(4_000, label="Lb")
    it = None
    try:
        it = run("REWRITE_XR_2", 4, 2, {0: P, 1: L, 2: P_b, 3: L_b},
                 {0: P.with_amount_seq(13_000, 0), 1: L.with_amount_seq(17_000, 0),
                  2: pw.pending(9_000, T + 1_008, label="Pb2"), 3: L_b}, locktime=T)
        check(True, f"{tag} REWRITE_XR_2: a settlement and a roll in one rewrite, operator only")
    except ScriptError as e:
        check(False, f"{tag} REWRITE_XR_2 positive: {str(e)[:120]}")
    expect_fail(lambda: run("REWRITE_XR_2", 4, 2, {0: P, 1: L, 2: P_b, 3: L_b},
                            {0: P.with_amount_seq(13_000, 0), 1: L,
                             2: P_b, 3: L_b.with_amount_seq(11_000, 0)}),
                f"{tag} REWRITE_XR_2: a transfer absorbed by the other pair's landing leaf")
    s1 = len(pw.w.compiled["REWRITE_XR_1"])
    s2 = len(pw.w.compiled["REWRITE_XR_2"])
    if verbose:
        print(f"    REWRITE_XR_h {tag}: h=1 {s1} B, h=2 {s2} B, varops {it.cost if it else '-'}")
    return s1, s2


def _settlement_cohort(pw, height, reclaim=False):
    """A full cohort for the reclaim-form rewrite at height h: 2^(h-1)
    pairs (P_i, L_i), each settling 7,000 sat from P_i into L_i (R3), or
    with reclaim, each P_i reclaimed (R1, emptied) and L_i unchanged."""
    n = 1 << height
    old, new = {}, {}
    for j in range(n // 2):
        P = pw.pending(20_000, 700_000, label=f"P{j}")
        L = pw.landing(10_000, label=f"L{j}")
        old[2 * j], old[2 * j + 1] = P, L
        if reclaim:
            new[2 * j], new[2 * j + 1] = None, L
        else:
            new[2 * j], new[2 * j + 1] = P.with_amount_seq(13_000, 0), L.with_amount_seq(17_000, 0)
    return old, new


def test_pending_rewrite_cohort_ccv(depth, height, numeric="c2", reclaim=False, verbose=True):
    """REWRITE_XR_h over a full cohort of pairs at height h (D = depth):
    every pair settles by R3, or with reclaim every pending leaf is
    reclaimed by R1. Returns (script bytes, witness bytes, elements), or
    under 0xC0 checks that a witness over the 1,000-element stack limit
    is rejected by that limit and returns None for the witness."""
    pw = PendingWorldCCV(depth, numeric, rewrite_heights=(height,))
    w = pw.w
    name = f"REWRITE_XR_{height}"
    tag = f"{numeric} D={depth} {name} ({'reclaim' if reclaim else 'settle'})"
    old, new = _settlement_cohort(pw, height, reclaim)
    base = 1 << height
    wit, ctx = _pending_rewrite_ccv(pw, name, base, height, old, new, locktime=700_000, run=False)
    size = len(w.compiled[name])
    if pw.c0 and len(wit) + 6 > 1000:
        try:
            w.run(name, wit, ctx)
            check(False, f"{tag} with {len(wit)} witness elements ran past the 1,000-element stack limit")
        except ScriptError as e:
            check("stack size limit" in str(e), f"{tag} with {len(wit)} witness elements is rejected by the stack size limit: {str(e)[:60]}")
        if verbose:
            print(f"    {tag}: script {size} B, witness of {len(wit)} elements over the stack limit")
        return size, None, len(wit)
    it = None
    try:
        it = w.run(name, wit, ctx)
        check(True, f"{tag}: {1 << height} positions")
    except ScriptError as e:
        check(False, f"{tag} positive: {str(e)[:120]}")
    wsize = sum(len(x) for x in wit)
    if verbose:
        n = 1 << height
        print(f"    {tag}: script {size} B, witness {wsize} B ({len(wit)} elements); "
              f"per position {size / n:.0f} + {wsize / n:.0f} B, varops {it.cost if it else '-'}")
    return size, wsize, len(wit)


def main():
    global FAILS, CHECKS
    print("CCV tier (BIP-443 OP_CHECKCONTRACTVERIFY)")
    before = CHECKS
    test_a6_pins()
    print(f"  [A-6] BIP-443 pins: {CHECKS - before} checks")
    for depth, profile in ((4, "D"), (16, "D"), (8, "S"), (32, "S")):
        before = CHECKS
        test_all(depth, profile)
        test_two_trees(depth, profile)
        print(f"  {profile}/{depth} (c2): {CHECKS - before} checks")
    for depth, profile in ((4, "D"), (16, "D"), (8, "S")):
        before = CHECKS
        test_update_x_ccv(depth, profile)
        test_split_ccv(depth, profile)
        print(f"  {profile}/{depth} (c2) UPDATE^x, SPLIT: {CHECKS - before} checks")
    # EXIT_K^t (spec 7.2 rule 7) in both numerics.
    for numeric, cases in (("c2", ((4, "D"), (16, "D"), (8, "S"))),
                           ("c0", ((4, "D"), (16, "D"), (31, "S")))):
        for depth, profile in cases:
            before = CHECKS
            test_exit_tower_ccv(depth, profile, numeric)
            print(f"  {profile}/{depth} ({numeric}) EXIT^t: {CHECKS - before} checks")
    # EVICT_SUBTREE_h with real cohorts in both numerics (spec 7.7).
    for numeric in ("c2", "c0"):
        before = CHECKS
        for depth, h in ((4, 1), (4, 2), (16, 2), (16, 4), (16, 6)):
            test_evict_subtree_ccv(depth, h, numeric)
        print(f"  D (EVICT_SUBTREE, {numeric}): {CHECKS - before} checks")
    # 0xC0 numerics: dense D=4/16; sparse D=31 (MID's D <= 31 limit, spec 4.5).
    for depth, profile in ((4, "D"), (16, "D"), (31, "S")):
        before = CHECKS
        try:
            test_c0(depth, profile)
        except Exception as e:
            check(False, f"c0 {profile}/{depth}: {str(e)[:80]}")
        print(f"  {profile}/{depth} (c0): {CHECKS - before} checks")
    for depth, profile in ((4, "D"), (16, "D"), (31, "S")):
        before = CHECKS
        test_split_ccv0(depth, profile)
        print(f"  {profile}/{depth} (c0) SPLIT: {CHECKS - before} checks")
    # The carve rule of 7.5 rule 5 against the cohort sweep, both numerics.
    for numeric in ("c2", "c0"):
        before = CHECKS
        test_carve_rules_ccv(16, numeric)
        print(f"  D/16 ({numeric}) carve rules: {CHECKS - before} checks")
    # CLAIM and CLAIM^h with the tree_id voucher message (spec 4.6, 9.6).
    for numeric, cases in (("c2", ((4, "D"), (16, "D"), (8, "S"), (32, "S"))),
                           ("c0", ((4, "D"), (16, "D"), (31, "S")))):
        for depth, profile in cases:
            before = CHECKS
            test_claim_ccv(depth, profile, numeric)
            test_claim_ccv(depth, profile, numeric, hashlock=True)
            test_claim_x_ccv(depth, profile, numeric)
            test_claim_x_ccv(depth, profile, numeric, hashlock=True)
            print(f"  {profile}/{depth} ({numeric}) CLAIM, CLAIM^h, CLAIM^x, CLAIM^hx: {CHECKS - before} checks")
    # DETACH_h in both numerics (spec 7.10): the detach, the detached tree,
    # and the parent's options compiled at depth h (rule 3).
    for numeric in ("c2", "c0"):
        before = CHECKS
        for depth, h in ((8, 2), (16, 8)):
            test_detach_ccv(depth, h, numeric)
        print(f"  D (DETACH, {numeric}): {CHECKS - before} checks")
    # REWRITE_h and REWRITE_h^x in both numerics (spec 7.9): the mixed cohort
    # at h = 2 and 4, the top-ups that vouchers and authorisations survive,
    # and the credit leaf; under 0xC0 the full 32-position cohort at h = 5
    # (the largest that fits the stack limit) and the h = 6 rejection.
    for numeric in ("c2", "c0"):
        before = CHECKS
        for depth, h, x in ((4, 2, False), (16, 2, False), (16, 4, False), (16, 4, True)):
            test_rewrite_ccv(depth, h, numeric, exit_consent=x)
        # The output-0 mode flag of the plain forms (spec 4.6): a net
        # decrease spends under DEDUCT, an increase or equal sum under assign.
        for h in (1, 2):
            for x in (False, True):
                test_rewrite_flag_ccv(16, h, numeric, x)
        for depth, profile in ((4, "D"), (16, "D"), (8, "S") if numeric == "c2" else (31, "S")):
            test_update_flag_ccv(depth, profile, numeric)
        if numeric == "c0":
            for scenario in ("update", "exit"):
                test_rewrite_ccv(16, 5, "c0", scenario=scenario)
            test_rewrite_ccv(16, 6, "c0", scenario="update")      # over the 1,000-element limit
            test_rewrite_negative_amount_ccv0(4)
        else:
            for scenario in ("update", "exit"):
                test_rewrite_ccv(16, 6, "c2", scenario=scenario)   # no stack bound under 0xC2
        test_voucher_topup_ccv(16, numeric)
        test_credit_topup_ccv(16, numeric)
        print(f"  D (REWRITE, {numeric}): {CHECKS - before} checks")
    # The pending-leaf receive (6.2, 7.5.4, 7.9 rule 8, 7.11) in both
    # numerics: CLAIM^m / CLAIM^hm, RECLAIM_1 (both profiles), the reclaim
    # form of the rewrite at h = 1, 2, and full cohorts of pairs at D = 16
    # (under 0xC0 h = 5 is the largest that fits the stack limit).
    print("  pending-leaf receive (sizes at D = 16):")
    for numeric in ("c2", "c0"):
        before = CHECKS
        for depth in (4, 16):
            test_merge_ccv(depth, numeric, verbose=depth == 16)
            test_reclaim_ccv(depth, numeric, verbose=depth == 16)
            test_pending_rewrite_ccv(depth, numeric, verbose=depth == 16)
        test_reclaim_sparse_ccv(31 if numeric == "c0" else 8, numeric)
        heights = (2, 4, 6) if numeric == "c2" else (2, 4, 5, 6)
        for h in heights:
            for reclaim in (False, True):
                test_pending_rewrite_cohort_ccv(16, h, numeric, reclaim)
        print(f"  D ({numeric}) CLAIM^m, CLAIM^hm, RECLAIM_1, REWRITE_R_h, REWRITE_XR_h: {CHECKS - before} checks")
    before = CHECKS
    test_audit_negatives_ccv(8)
    print(f"  D/8 audit negatives (c2, c0): {CHECKS - before} checks")
    print(f"\n{CHECKS} checks, {FAILS} failures")
    return 1 if FAILS else 0


if __name__ == "__main__":
    sys.exit(main())
