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
* the tree-creation variants UPDATE^x (both numerics) and SPLIT (0xC2).

Prints the check count and a size/cost table like the other suites.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import layertree_ref as lt  # noqa: E402
import layertree_scripts as ls  # noqa: E402
import layertree_ccv as C  # noqa: E402
import layertree_mid as M  # noqa: E402
from script_sim import (Interp, ScriptError, TxContext, assemble, pubkey_x,  # noqa: E402
                        schnorr_sign)

FAILS = 0
CHECKS = 0
P2WPKH = b"\x00\x14" + bytes(20)

BIP342_OPS = {"OP_0", "OP_1", "OP_2DROP", "OP_2DUP", "OP_2SWAP", "OP_ADD", "OP_1ADD",
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


def mk_leaf(label, amount, evictor=None, evict_after=0, nonce=None, seq=0):
    if nonce is None:
        nonce = int.from_bytes(lt.sha256(label.encode())[:4], "little")
    return lt.Leaf(amount, pubkey_x(sk(label + "-exit")), pubkey_x(sk(label + "-owner")),
                   evictor if evictor else lt.NUMS_X, evict_after, nonce, seq)


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
    wit = w.path_witness(upath) + [alice.serialize(), alice2.serialize(), asig, osig]
    record("UPDATE", w.run("UPDATE", wit, ctx), wit)
    expect_fail(lambda: w.run("UPDATE", w.path_witness(upath) + [alice.serialize(), alice2.serialize(), osig, osig], ctx),
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
        return w.path_witness(upath) + [alice.serialize(), alice2.serialize(),
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
    block = w.path_witness(upath) + [alice.serialize(), alice2.serialize()]
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
    bob = mk_leaf("bob", 200_000, w.op_pk, 900_000)
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
    greedy = mk_leaf("greedy", alice.amount + 1, w.op_pk, 900_000)
    expect_fail(lambda: w.run("SPLIT", w.path_witness(cpath) + w.path_witness(spath) +
                              [alice.serialize(), greedy.serialize(), asig], ctx),
                "SPLIT over-split underflow")
    occupied = w.tree.path(s_oper)
    expect_fail(lambda: w.run("SPLIT", w.path_witness(occupied) + w.path_witness(spath) +
                              [alice.serialize(), bob.serialize(), asig], ctx),
                "SPLIT into an occupied position")
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
    wit = (list(M.pad(r4[1])) + w.pads_for(root[1]) +
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
    block = (list(M.pad(r4[1])) + w.pads_for(root[1]) +
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
    bob = mk("bob", 200_000, w.op_pk, 900_000)
    s_b = w.slot(bob, 3)
    spath = w.tree.path(s_a)
    t1 = w.clone(); lt.apply_claim(t1, s_a, s_b, bob)
    src2 = t1.leaves[s_a]
    r1 = t1.root()
    check(r1[1] == root[1], "c0: SPLIT conserves sum")

    def head(new, s_new, cnode, amt_new):
        t = w.clone(); t.leaves[s_a] = src2; t.leaves[s_new] = new
        ex = ([M.scriptnum(alice.seq)] + list(M.pad(alice.seq)) + list(M.pad(alice.seq + 1)) +
              list(M.pad(amt_new)))
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
    greedy = mk("greedy", alice.amount + 1, w.op_pk, 900_000)
    expect_fail(lambda: w.run("SPLIT", head(greedy, w.slot(greedy, 3), src2.node(), 0) + [asig], ctx),
                "c0: SPLIT over-split underflow")
    if not S:
        occ = mk("bob", 200_000, w.op_pk, 900_000)
        expect_fail(lambda: w.run("SPLIT", head(occ, s_o, src2.node(), alice.amount - occ.amount) + [asig], ctx),
                    "c0: SPLIT into an occupied position")
    ctxu = w.ctx([(r1[1] - 1, w.spk(r1))], (600, P2WPKH))
    expect_fail(lambda: w.run("SPLIT", h0 + [schnorr_sign(ctxu.sighash(), sk("alice-owner"))], ctxu),
                "c0: SPLIT with output 0 below ns")
    ctxs = TxContext([(r1[1], w.spk(r1)), (600, P2WPKH)], [(r1[1], w.spk(r1))],
                     internal_key=lt.ccv_internal_key(r1[0]), taptree_root=w.m)
    expect_fail(lambda: w.run("SPLIT", h0 + [schnorr_sign(ctxs.sighash(), sk("alice-owner"))], ctxs),
                "c0: SPLIT against a stale root")
    mallory = mk("mallory", bob.amount, w.op_pk, 900_000)
    s_m = w.slot(mallory, 3)
    tm = w.clone(); lt.apply_claim(tm, s_a, s_m, mallory); rm = tm.root()
    ctx_m = w.ctx([(rm[1], w.spk(rm))], (600, P2WPKH))
    expect_fail(lambda: w.run("SPLIT", head(mallory, s_m, src2.node(), alice.amount - mallory.amount) + [asig], ctx_m),
                "c0: SPLIT recipient swapped under the owner's signature")
    return it, len(w.compiled["SPLIT"]), sum(len(x) for x in h0 + [asig])


CSFS_OPS = {"OP_CHECKSIGFROMSTACK"}
TREE_ID = C.tree_id(lt.sha256(b"creation-txid"), 0)


def test_claim_ccv(depth, profile, numeric="c2", hashlock=False):
    """CLAIM (7.5) and CLAIM^h (7.5.1) under CCV with the tree_id-bound
    voucher message of 4.6 / 9.6, in either numerics. Mirrors the FULL
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
    frank = mk("frank", 40_000, w.op_pk, 900_000)
    s_f = w.slot(frank, 3)
    spath = w.tree.path(s_o)
    t1 = w.clone(); lt.apply_claim(t1, s_o, s_f, frank)
    src2 = t1.leaves[s_o]
    r1 = t1.root()
    preimage = lt.sha256(b"payment-preimage")
    phash = lt.sha256(preimage) if hashlock else None

    def head(tree, source, claim, s_src, s_claim):
        """Witness below the voucher signature for claiming `claim` out of
        `source` in `tree`, presenting s_claim as empty."""
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
        ex = ([M.scriptnum(source.seq)] + list(M.pad(source.seq)) + list(M.pad(source.seq + 1)) +
              list(M.pad(max(amt_new, 0))))
        return (list(M.pad(t.root()[1])) + M.w_levels(cp, lt.EMPTY_NODE, claim.node(), S) + w.pos(claim) +
                w.pads_for(tree.root()[1]) + M.w_levels(sp, source.node(), new_src_node, S) + w.pos(source) +
                M.w_leaf(source) + M.w_leaf(claim) + ex)

    def vsig(tid, source, claim, key="operator-owner", ph=phash):
        return schnorr_sign(C.voucher_msg_ccv(tid, source, claim, ph), sk(key))

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
    frank2 = mk("frank2", 40_000, w.op_pk, 900_000)
    s_f2 = w.slot(frank2, 6)
    t2 = w.clone(); lt.apply_claim(t2, s_o, s_f2, frank2); r2 = t2.root()
    ctx_r = w.ctx([(r2[1], w.spk(r2))], (600, P2WPKH))
    expect_fail(lambda: w.run(name, head(t1, src2, frank2, s_o, s_f2) + tail(vsig(TREE_ID, src, frank2)), ctx_r),
                f"{tag} replay against the advanced source")
    expect_fail(lambda: w.run(name, head(t1, src2, frank, s_o, s_f2 if S else s_f2) + tail(good), ctx_r),
                f"{tag} redeemed voucher replayed")
    w.tree = saved
    # a voucher reused for a different claim leaf
    other = mk("other", 40_000, w.op_pk, 900_000)
    s_x = w.slot(other, 3)
    tx_ = w.clone(); lt.apply_claim(tx_, s_o, s_x, other); rx = tx_.root()
    ctx_x = w.ctx([(rx[1], w.spk(rx))], (600, P2WPKH))
    expect_fail(lambda: w.run(name, head(w.tree, src, other, s_o, s_x) + tail(good), ctx_x),
                f"{tag} voucher reused for a different claim leaf")
    # over-claim
    greedy = mk("greedy", src.amount + 1, w.op_pk, 900_000)
    s_g = w.slot(greedy, 3)
    expect_fail(lambda: w.run(name, head(w.tree, src, greedy, s_o, s_g) + tail(vsig(TREE_ID, src, greedy)), ctx),
                f"{tag} over-claim")
    # wrong signer, other tree_id, FULL-style voucher over m
    expect_fail(lambda: w.run(name, h0 + tail(vsig(TREE_ID, src, frank, "alice-owner")), ctx),
                f"{tag} wrong signer")
    other_tid = C.tree_id(lt.sha256(b"creation-txid"), 1)
    expect_fail(lambda: w.run(name, h0 + tail(vsig(other_tid, src, frank)), ctx),
                f"{tag} voucher signed for another tree_id")
    expect_fail(lambda: w.run(name, h0 + tail(vsig(w.m, src, frank)), ctx),
                f"{tag} voucher over m (the FULL message)")
    ctx_u = w.ctx([(r1[1] - 1, w.spk(r1))], (600, P2WPKH))
    expect_fail(lambda: w.run(name, h0 + tail(good), ctx_u), f"{tag} output 0 below ns")
    if hashlock:
        expect_fail(lambda: w.run(name, h0 + tail(good, lt.sha256(b"wrong")), ctx), f"{tag} wrong preimage")
        expect_fail(lambda: w.run(name, h0 + tail(good, preimage[:31]), ctx), f"{tag} preimage not 32 bytes")
        expect_fail(lambda: w.run(name, h0 + [good], ctx), f"{tag} absent preimage")
        expect_fail(lambda: w.run(name, h0 + tail(vsig(TREE_ID, src, frank, ph=None)), ctx),
                    f"{tag} plain voucher under the hash lock")
    else:
        hsig = schnorr_sign(C.voucher_msg_ccv(TREE_ID, src, frank, lt.sha256(preimage)), sk("operator-owner"))
        expect_fail(lambda: w.run(name, h0 + [hsig], ctx), f"{tag} hash-locked voucher under plain CLAIM")
    wit = h0 + tail(good)
    return it, len(w.compiled[name]), sum(len(x) for x in wit)


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
    # CLAIM and CLAIM^h with the tree_id voucher message (spec 4.6, 9.6).
    for numeric, cases in (("c2", ((4, "D"), (16, "D"), (8, "S"), (32, "S"))),
                           ("c0", ((4, "D"), (16, "D"), (31, "S")))):
        for depth, profile in cases:
            before = CHECKS
            test_claim_ccv(depth, profile, numeric)
            test_claim_ccv(depth, profile, numeric, hashlock=True)
            print(f"  {profile}/{depth} ({numeric}) CLAIM, CLAIM^h: {CHECKS - before} checks")
    print(f"\n{CHECKS} checks, {FAILS} failures")
    return 1 if FAILS else 0


if __name__ == "__main__":
    sys.exit(main())
