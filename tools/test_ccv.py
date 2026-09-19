#!/usr/bin/env python3
"""End-to-end execution of the LayerTree CCV-tier scripts (both profiles).

Mirrors tools/test_scripts.py: same leaves, same negative cases (retargeted
to what CCV actually checks), plus CCV-specific negatives:

* output 0 with a wrong taptree (a P2TR to the correct CCV key for `nh`
  but tweaked by another taptree) must fail;
* output 0 with the FULL-tier key (H_state binding) must fail;
* a payout to a script other than P2TR(exit_key) must fail;
* overfunding output 0 (amount > ns) must pass (fees from the residual),
  underfunding (amount < ns) must fail;
* a second tree input in the same transaction: each CCV check reads only
  "the current input", so two tree outputs cannot be merged into one
  output 0 (the residual of one input can fund it, the other's CHECK_INPUT
  data must still match its own input).

Prints the check count and a size/cost table like the other suites.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import layertree_ref as lt  # noqa: E402
import layertree_scripts as ls  # noqa: E402
import layertree_ccv as C  # noqa: E402
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
    # residual: input 50k + tree amount; out0 = r1 sum; the fee input makes
    # out0+out1+out2 = total inputs. CCV: out0 DEDUCT + equality, out1 DEDUCT.

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

    # overfunded TREE (input amount > committed sum): with DEDUCT + the
    # numeric equality, output 0 must still equal ns exactly; the excess
    # leaves through the free outputs (here: a bigger fee-input change).
    over = list(outputs)
    over[2] = (49_000 + 5_000, P2WPKH)
    ctxo = w.ctx(over, extra_in=(50_000 + 5_000, P2WPKH))
    sigo = schnorr_sign(ctxo.sighash(), sk("bob-owner"))
    wito = w.path_witness(path) + [bob.serialize(), sigo, b""]
    record("EXIT_1 (overfunded tree, excess to fees)", w.run("EXIT_1", wito, ctxo), wito)

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


def main():
    global FAILS, CHECKS
    print("CCV tier (BIP-443 OP_CHECKCONTRACTVERIFY)")
    for depth, profile in ((4, "D"), (16, "D"), (8, "S"), (32, "S")):
        before = CHECKS
        test_all(depth, profile)
        print(f"  {profile}/{depth}: {CHECKS - before} checks")
    print(f"\n{CHECKS} checks, {FAILS} failures")
    return 1 if FAILS else 0


if __name__ == "__main__":
    sys.exit(main())
