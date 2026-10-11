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
# le32(0x81000001) is `01 00 00 81`, the minimal CScriptNum -16,777,217; with
# its empty PADZ pad it is the claim lease only NONNEG keeps out of the carve
# compare (test_mid.NEG_LEASE_EA).
NEG_LEASE_EA = (b"\x01\x00\x00\x81", b"", bytes(4))

BIP342_OPS = {"OP_0", "OP_1", "OP_2DROP", "OP_2DUP", "OP_2SWAP", "OP_ABS", "OP_ADD", "OP_1ADD",
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
            print(f"  {profile}/{depth} ({numeric}) CLAIM, CLAIM^h: {CHECKS - before} checks")
    # DETACH_h in both numerics (spec 7.10): the detach, the detached tree,
    # and the parent's options compiled at depth h (rule 3).
    for numeric in ("c2", "c0"):
        before = CHECKS
        for depth, h in ((8, 2), (16, 8)):
            test_detach_ccv(depth, h, numeric)
        print(f"  D (DETACH, {numeric}): {CHECKS - before} checks")
    before = CHECKS
    test_audit_negatives_ccv(8)
    print(f"  D/8 audit negatives (c2, c0): {CHECKS - before} checks")
    print(f"\n{CHECKS} checks, {FAILS} failures")
    return 1 if FAILS else 0


if __name__ == "__main__":
    sys.exit(main())
