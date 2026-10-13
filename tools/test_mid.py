#!/usr/bin/env python3
"""End-to-end tests for the MID tier scripts (tapleaf 0xC0 semantics)."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import layertree_ref as lt  # noqa: E402
import layertree_mid as M  # noqa: E402
import layertree_scripts as F  # noqa: E402
from script_sim import Interp, ScriptError, TxContext, assemble, pubkey_x, schnorr_sign  # noqa: E402
from test_scripts import BIP342_OPS, TREE_ID, sk, check, expect_fail, P2WPKH  # noqa: E402
import test_scripts as TS  # noqa: E402

MID_OPCODES = BIP342_OPS | M.EXTRA_OPCODES | {"OP_BOOLOR", "OP_GREATERTHANOREQUAL"}


def mk_leaf(label, amount, evictor=None, evict_after=0, nonce=None, seq=0, sparse=False):
    if nonce is None:
        nonce = int.from_bytes(lt.sha256(label.encode())[:4], "little")
    lf = lt.Leaf(amount, pubkey_x(sk(label + "-exit")), pubkey_x(sk(label + "-owner")),
                 evictor if evictor else lt.NUMS_X, evict_after, nonce, seq)
    while sparse and not M.pos_ok(lf):
        lf = lf.with_amount_seq(lf.amount, lf.seq); lf.nonce = (lf.nonce + 1) & 0xffffffff
    return lf


def carve_of(src, label, amount, sparse=False):
    """A leaf carved out of src: it keeps src's evictor_key and evict_after
    (spec 7.5 rule 5)."""
    return mk_leaf(label, amount, src.evictor_key, src.evict_after, sparse=sparse)


class MidWorld:
    def __init__(self, depth, sparse, tree_id=TREE_ID):
        self.depth, self.sparse = depth, sparse
        self.op_sk = sk("operator"); self.op_pk = pubkey_x(self.op_sk)
        self.tree_id = tree_id
        self.scripts = M.all_scripts(depth, self.op_pk, sparse, tree_id=tree_id)
        for name, toks in self.scripts.items():
            bad = {t for t in toks if isinstance(t, str)} - MID_OPCODES
            check(not bad, f"MID {name}: opcodes outside the MID set: {sorted(bad)}")
        self.compiled = {k: assemble(v, mode="c0") for k, v in self.scripts.items()}
        self.m = lt.taptree_root([lt.tapleaf_hash(c, 0xc0) for c in self.compiled.values()])
        self.tree = lt.Tree(depth)

    def slot(self, leaf, want):
        return M.position(leaf, self.depth) if self.sparse else want

    def spk(self, root):
        return lt.tree_spk(root[0], self.m)

    def ctx(self, outputs, extra_in, locktime=0):
        root = self.tree.root()
        return TxContext([(root[1], self.spk(root)), extra_in], outputs, locktime=locktime)

    def run(self, name, wit, ctx):
        it = Interp(ctx, mode="c0")
        it.run(self.compiled[name], wit)
        return it

    def clone(self):
        t = lt.Tree(self.depth); t.leaves = dict(self.tree.leaves); return t

    def pos(self, leaf):
        return M.w_pos(leaf) if self.sparse else []

    def pads_for(self, total):
        """[zi wi] for check_old: pad of the OLD root sum (== input amount)."""
        return list(M.pad(total))


def test_mid(depth, sparse, verbose=True):
    w = MidWorld(depth, sparse)
    costs = {}
    S = sparse
    alice = mk_leaf("alice", 50_000, sparse=S)
    bob = mk_leaf("bob", 125_000, w.op_pk, 800_000, sparse=S)
    oper = mk_leaf("operator", 1_000_000, sparse=S)
    s_a, s_b, s_o = w.slot(alice, 0), w.slot(bob, 5), w.slot(oper, (1 << depth) - 1)
    w.tree.leaves = {s_a: alice, s_b: bob, s_o: oper}

    def exit_witness(leaf, slot, sig, is_evict, root, new_total):
        path = w.tree.path(slot)
        # witness bottom..top: [zf wf] [levels] [zi wi] [pos] leaf(10) sig is_evict r m
        return (list(M.pad(new_total)) + w.pads_for(root[1]) + M.w_levels(path, leaf.node(), lt.EMPTY_NODE, S) +
                w.pos(leaf) + M.w_leaf_exit(leaf) + [sig, is_evict, root[0], w.m])

    # ---------------- EXIT_1 owner (exact payout) ----------------
    root = w.tree.root()
    t1 = w.clone(); del t1.leaves[s_b]; r1 = t1.root()
    outputs = [(r1[1], w.spk(r1)), (bob.amount, lt.p2tr_spk(bob.exit_key)), (400, P2WPKH)]
    ctx = w.ctx(outputs, (5_000, P2WPKH))
    sig = schnorr_sign(ctx.sighash(), sk("bob-owner"))
    wit = exit_witness(bob, s_b, sig, b"", root, r1[1])
    it = w.run("EXIT_1", wit, ctx)
    costs["EXIT_1 (owner)"] = (it, len(w.compiled["EXIT_1"]), sum(len(x) for x in wit))
    # negatives
    expect_fail(lambda: w.run("EXIT_1", wit[:-1] + [lt.sha256(b"evil")], ctx), "mid: wrong m")
    bad = list(outputs); bad[1] = (bob.amount - 1, lt.p2tr_spk(bob.exit_key))
    ctxb = w.ctx(bad, (5_000, P2WPKH)); sigb = schnorr_sign(ctxb.sighash(), sk("bob-owner"))
    expect_fail(lambda: w.run("EXIT_1", exit_witness(bob, s_b, sigb, b"", root, r1[1]), ctxb), "mid: inexact payout")
    fake = bob.with_amount_seq(bob.amount + 1, 0)
    expect_fail(lambda: w.run("EXIT_1", exit_witness(fake, s_b, sig, b"", root, r1[1]), ctx), "mid: forged leaf")
    # wrong pad (claims a different numeric amount than the field)
    wbad = list(wit); i_amt = len(wit) - 4 - 6   # amt_num position
    wbad[i_amt] = M.scriptnum(bob.amount + 256); 
    expect_fail(lambda: w.run("EXIT_1", wbad, ctx), "mid: amount field/number mismatch")
    # ---------------- EXIT_1 evict ----------------
    ctx_e = w.ctx(outputs[:2], (5_000, P2WPKH), locktime=800_000)
    esig = schnorr_sign(ctx_e.sighash(), w.op_sk)
    wit_e = exit_witness(bob, s_b, esig, b"\x01", root, r1[1])
    it = w.run("EXIT_1", wit_e, ctx_e)
    costs["EXIT_1 (evict)"] = (it, len(w.compiled["EXIT_1"]), sum(len(x) for x in wit_e))
    ctx_early = w.ctx(outputs[:2], (5_000, P2WPKH), locktime=799_999)
    esig2 = schnorr_sign(ctx_early.sighash(), w.op_sk)
    expect_fail(lambda: w.run("EXIT_1", exit_witness(bob, s_b, esig2, b"\x01", root, r1[1]), ctx_early), "mid: early evict")
    w.tree = t1

    # ---------------- JOIN ----------------
    carol = mk_leaf("carol", 30_000, w.op_pk, 900_000, sparse=S)
    dave = mk_leaf("dave", 70_000, w.op_pk, 900_000, sparse=S)
    root = w.tree.root()
    if not S:
        h, idx = 2, 2
        jpath = w.tree.path(idx << h, height=h)
        t2 = w.clone(); lt.apply_join(t2, h, idx, {0: carol, 3: dave})
        node, r2 = t2.subtree(h, idx), t2.root()
        ctx = w.ctx([(r2[1], w.spk(r2))], (node[1] + 700, P2WPKH))
        osig = schnorr_sign(ctx.sighash(), w.op_sk)
        wit = (list(M.pad(r2[1])) + w.pads_for(root[1]) + M.w_levels(jpath, lt.empty_node(h), node, False, h) +
               [node[0], M.scriptnum(node[1]), osig, root[0], w.m])
        it = w.run("JOIN_2", wit, ctx)
        costs["JOIN_2"] = (it, len(w.compiled["JOIN_2"]), sum(len(x) for x in wit))
        ctxu = w.ctx([(r2[1] - 1, w.spk(r2))], (node[1] + 700, P2WPKH)); osigu = schnorr_sign(ctxu.sighash(), w.op_sk)
        expect_fail(lambda: w.run("JOIN_2", wit[:-3] + [osigu, root[0], w.m], ctxu), "mid: join underfunded")
        # negative: join into an occupied position (alice sits in subtree 0)
        jpath_bad = w.tree.path(0, height=h)
        expect_fail(lambda: w.run("JOIN_2", list(M.pad(r2[1])) + w.pads_for(root[1]) +
                                  M.w_levels(jpath_bad, lt.empty_node(h), node, False, h) +
                                  [node[0], M.scriptnum(node[1]), osig, root[0], w.m], ctx), "mid: join over occupied subtree")
        # negative: no valid operator signature (wrong key, then garbage)
        usig = schnorr_sign(ctx.sighash(), sk("alice-owner"))
        expect_fail(lambda: w.run("JOIN_2", wit[:-3] + [usig, root[0], w.m], ctx), "mid: join without operator (wrong key)")
        expect_fail(lambda: w.run("JOIN_2", wit[:-3] + [b"\x01" * 64, root[0], w.m], ctx), "mid: join without operator (garbage sig)")
        w.tree = t2
        s_c, s_d = idx << h, (idx << h) + 3
    else:
        for lf in (carol, dave):
            root = w.tree.root(); slot = w.slot(lf, None)
            jpath = w.tree.path(slot); t2 = w.clone(); t2.leaves[slot] = lf; r2 = t2.root()
            ctx = w.ctx([(r2[1], w.spk(r2))], (lf.amount + 500, P2WPKH))
            osig = schnorr_sign(ctx.sighash(), w.op_sk)
            wit = (list(M.pad(r2[1])) + w.pads_for(root[1]) + M.w_levels(jpath, lt.EMPTY_NODE, lf.node(), True) +
                   w.pos(lf) + M.w_leaf(lf) + [osig, root[0], w.m])
            it = w.run("JOIN_0", wit, ctx)
            costs["JOIN_0"] = (it, len(w.compiled["JOIN_0"]), sum(len(x) for x in wit))
            w.tree = t2
        s_c, s_d = w.slot(carol, None), w.slot(dave, None)

    # ---------------- JOINK_2 ----------------
    root = w.tree.root()
    hank = mk_leaf("hank", 9_000, w.op_pk, 900_000, sparse=S); ivy = mk_leaf("ivy", 11_000, w.op_pk, 900_000, sparse=S)
    s_h, s_i = w.slot(hank, 12), w.slot(ivy, 13)
    tj = w.clone(); ph = tj.path(s_h); tj.leaves[s_h] = hank; pi = tj.path(s_i); tj.leaves[s_i] = ivy; rj = tj.root()
    r_mid = lt.fold(hank.node(), ph)
    ctx = w.ctx([(rj[1], w.spk(rj))], (hank.amount + ivy.amount + 700, P2WPKH))
    osig = schnorr_sign(ctx.sighash(), w.op_sk)
    if not S:
        b1 = w.pads_for(root[1]) + M.w_levels(ph, lt.EMPTY_NODE, hank.node(), False) + [hank.hash(), M.scriptnum(hank.amount)]
        b2 = M.w_levels(pi, lt.EMPTY_NODE, ivy.node(), False) + [ivy.hash(), M.scriptnum(ivy.amount)]
    else:
        b1 = w.pads_for(root[1]) + M.w_levels(ph, lt.EMPTY_NODE, hank.node(), True) + w.pos(hank) + M.w_leaf(hank)
        b2 = M.w_levels(pi, lt.EMPTY_NODE, ivy.node(), True) + w.pos(ivy) + M.w_leaf(ivy)
    wit = list(M.pad(rj[1])) + b2 + b1 + [osig, root[0], w.m]
    # negative: the second path is stale (taken before the first step's insert)
    if not S:
        b2_stale = M.w_levels(w.tree.path(s_i), lt.EMPTY_NODE, ivy.node(), False) + [ivy.hash(), M.scriptnum(ivy.amount)]
    else:
        b2_stale = M.w_levels(w.tree.path(s_i), lt.EMPTY_NODE, ivy.node(), True) + w.pos(ivy) + M.w_leaf(ivy)
    expect_fail(lambda: w.run("JOINK_2", list(M.pad(rj[1])) + b2_stale + b1 + [osig, root[0], w.m], ctx), "mid: JOINK_2 stale second path")
    it = w.run("JOINK_2", wit, ctx)
    costs["JOINK_2"] = (it, len(w.compiled["JOINK_2"]), sum(len(x) for x in wit))
    w.tree = tj

    # ---------------- UPDATE ----------------
    root = w.tree.root()
    upath = w.tree.path(s_a)
    alice2 = alice.with_amount_seq(80_000, 1)
    t4 = w.clone(); t4.leaves[s_a] = alice2; r4 = t4.root()
    ctx = w.ctx([(r4[1], w.spk(r4))], (30_700, P2WPKH))
    osig = schnorr_sign(ctx.sighash(), w.op_sk); asig = schnorr_sign(ctx.sighash(), sk("alice-owner"))
    wit = (list(M.pad(r4[1])) + w.pads_for(root[1]) + M.w_levels(upath, alice.node(), alice2.node(), S) + w.pos(alice) +
           M.w_leaf(alice) + M.w_leaf(alice2) + [asig, osig, root[0], w.m])
    it = w.run("UPDATE", wit, ctx)
    costs["UPDATE"] = (it, len(w.compiled["UPDATE"]), sum(len(x) for x in wit))
    expect_fail(lambda: w.run("UPDATE", wit[:-4] + [osig, osig, root[0], w.m], ctx), "mid: update without owner")
    w.tree = t4

    # ---------------- CLAIM ----------------
    root = w.tree.root()
    src = w.tree.leaves[s_o]
    frank = carve_of(src, "frank", 40_000, sparse=S)
    s_f = w.slot(frank, 3)
    spath = w.tree.path(s_o)
    t5 = w.clone(); lt.apply_claim(t5, s_o, s_f, frank)
    src2 = t5.leaves[s_o]
    r1_ = lt.fold(src2.node(), spath)
    cpath = t5.path(s_f); r5 = t5.root()
    ctx = w.ctx([(r5[1], w.spk(r5))], (600, P2WPKH))
    vsig = schnorr_sign(lt.voucher_msg(w.tree_id, src, frank), sk("operator-owner"))
    extras = M.w_carve_extras(src, frank)
    wit = (list(M.pad(r5[1])) + M.w_levels(cpath, lt.EMPTY_NODE, frank.node(), S) + w.pos(frank) +
           w.pads_for(root[1]) + M.w_levels(spath, src.node(), src2.node(), S) + w.pos(src) +
           M.w_leaf(src) + M.w_leaf(frank) + extras + [vsig, root[0], w.m])
    it = w.run("CLAIM", wit, ctx)
    costs["CLAIM"] = (it, len(w.compiled["CLAIM"]), sum(len(x) for x in wit))
    greedy = carve_of(src, "greedy", src.amount + 1, sparse=S)
    gsig = schnorr_sign(lt.voucher_msg(w.tree_id, src, greedy), sk("operator-owner"))
    bad_extras = M.w_carve_extras(src, greedy, amt_new=0)
    expect_fail(lambda: w.run("CLAIM", list(M.pad(r5[1])) + M.w_levels(cpath, lt.EMPTY_NODE, greedy.node(), S) + w.pos(greedy) +
                w.pads_for(root[1]) + M.w_levels(spath, src.node(), src2.node(), S) + w.pos(src) +
                M.w_leaf(src) + M.w_leaf(greedy) + bad_extras + [gsig, root[0], w.m], ctx), "mid: over-claim")
    # 7.5 rule 5: another evictor key or a later evict_after than the source's
    for label, lf in (("another evictor key", mk_leaf("escape", 40_000, w.op_pk, src.evict_after, sparse=S)),
                      ("a later evict_after", mk_leaf("later", 40_000, None, src.evict_after + 1, sparse=S))):
        t_e = w.clone(); t_e.leaves[s_o] = src.with_amount_seq(src.amount - lf.amount, src.seq + 1)
        s_e = w.slot(lf, 3); cp_e = t_e.path(s_e); t_e.leaves[s_e] = lf; r_e = t_e.root()
        ctx_e = w.ctx([(r_e[1], w.spk(r_e))], (600, P2WPKH))
        esig = schnorr_sign(lt.voucher_msg(w.tree_id, src, lf), sk("operator-owner"))
        expect_fail(lambda: w.run("CLAIM", list(M.pad(r_e[1])) + M.w_levels(cp_e, lt.EMPTY_NODE, lf.node(), S) + w.pos(lf) +
                    w.pads_for(root[1]) + M.w_levels(spath, src.node(), src2.node(), S) + w.pos(src) +
                    M.w_leaf(src) + M.w_leaf(lf) + M.w_carve_extras(src, lf) + [esig, root[0], w.m], ctx_e),
                    f"mid: CLAIM of a leaf with {label} than its source")
    # 7.5 rule 6: a sub-dust claim leaf or residual fails; exactly DUST_MIN passes
    def claim_wit(lf):
        amt_new = src.amount - lf.amount
        t_c = w.clone(); s_c = w.slot(lf, 3)
        src_c = src.with_amount_seq(amt_new, src.seq + 1); t_c.leaves[s_o] = src_c
        cp_c = t_c.path(s_c); t_c.leaves[s_c] = lf; r_c = t_c.root()
        ctx_c = w.ctx([(r_c[1], w.spk(r_c))], (600, P2WPKH))
        return (list(M.pad(r_c[1])) + M.w_levels(cp_c, lt.EMPTY_NODE, lf.node(), S) + w.pos(lf) +
                w.pads_for(root[1]) + M.w_levels(spath, src.node(), src_c.node(), S) + w.pos(src) +
                M.w_leaf(src) + M.w_leaf(lf) + M.w_carve_extras(src, lf, amt_new=amt_new) +
                [schnorr_sign(lt.voucher_msg(w.tree_id, src, lf), sk("operator-owner")), root[0], w.m]), ctx_c
    for label, amt in (("one satoshi", 1), ("zero satoshis", 0), ("a one-satoshi residual", src.amount - 1)):
        wit_d, ctx_d = claim_wit(carve_of(src, f"dust{amt}", amt, sparse=S))
        expect_fail(lambda: w.run("CLAIM", wit_d, ctx_d), f"mid: CLAIM of {label} (7.5 rule 6)")
    wit_d, ctx_d = claim_wit(carve_of(src, "floor", lt.DUST_MIN, sparse=S))
    w.run("CLAIM", wit_d, ctx_d)
    check(True, "mid: CLAIM of exactly DUST_MIN succeeds")
    head = wit[:-3]
    expect_fail(lambda: w.run("CLAIM", head + [schnorr_sign(lt.voucher_msg(w.tree_id, src, frank), sk("bob-owner")), root[0], w.m], ctx),
                "mid: voucher wrong signer")
    other_tid = lt.tree_id(lt.sha256(b"creation-txid"), 1)
    expect_fail(lambda: w.run("CLAIM", head + [schnorr_sign(lt.voucher_msg(other_tid, src, frank), sk("operator-owner")), root[0], w.m], ctx),
                "mid: voucher signed for another tree_id")
    expect_fail(lambda: w.run("CLAIM", head + [schnorr_sign(lt.voucher_msg(w.m, src, frank), sk("operator-owner")), root[0], w.m], ctx),
                "mid: voucher over m instead of tree_id")
    # 7.5: the voucher binds the source body, not its amount, so a voucher
    # signed before an amount-only top-up redeems against the topped-up
    # leaf, for its own amount or for more than the balance at issuance;
    # an over-claim against the new balance and any other field change fail
    topped = src.with_amount_seq(src.amount + 500, src.seq)
    t_up = w.clone(); t_up.leaves[s_o] = topped
    saved_tree = w.tree
    for label, lf in (("the voucher's amount", frank),
                      ("more than the balance at issuance", carve_of(src, "bigger", src.amount + 100, sparse=S))):
        w.tree = t_up
        s_c = w.slot(lf, 3)
        t_c = w.clone(); lt.apply_claim(t_c, s_o, s_c, lf)
        src_c = t_c.leaves[s_o]; r_c = t_c.root()
        ctx_c = w.ctx([(r_c[1], w.spk(r_c))], (600, P2WPKH))
        wit_c = (list(M.pad(r_c[1])) + M.w_levels(t_c.path(s_c), lt.EMPTY_NODE, lf.node(), S) + w.pos(lf) +
                 w.pads_for(t_up.root()[1]) + M.w_levels(t_up.path(s_o), topped.node(), src_c.node(), S) + w.pos(topped) +
                 M.w_leaf(topped) + M.w_leaf(lf) + M.w_carve_extras(topped, lf) +
                 [schnorr_sign(lt.voucher_msg(w.tree_id, src, lf), sk("operator-owner")), t_up.root()[0], w.m])
        w.run("CLAIM", wit_c, ctx_c)
        check(True, f"mid: a voucher signed before an amount-only top-up redeems {label} afterwards")
    w.tree = t_up
    over = carve_of(src, "over", topped.amount + 1, sparse=S)
    expect_fail(lambda: w.run("CLAIM", list(M.pad(r5[1])) + M.w_levels(cpath, lt.EMPTY_NODE, over.node(), S) + w.pos(over) +
                w.pads_for(t_up.root()[1]) + M.w_levels(t_up.path(s_o), topped.node(), src2.node(), S) + w.pos(topped) +
                M.w_leaf(topped) + M.w_leaf(over) + M.w_carve_extras(topped, over, amt_new=0) +
                [schnorr_sign(lt.voucher_msg(w.tree_id, src, over), sk("operator-owner")), t_up.root()[0], w.m],
                w.ctx([(r5[1], w.spk(r5))], (600, P2WPKH))), "mid: over-claim against the topped-up balance")
    w.tree = saved_tree
    for label, lf in (("exit_key", lt.Leaf(src.amount, pubkey_x(sk("other-exit")), src.owner_key, src.evictor_key, src.evict_after, src.nonce, src.seq)),
                      ("evictor_key", lt.Leaf(src.amount, src.exit_key, src.owner_key, w.op_pk, src.evict_after, src.nonce, src.seq)),
                      ("evict_after", lt.Leaf(src.amount, src.exit_key, src.owner_key, src.evictor_key, src.evict_after + 1, src.nonce, src.seq)),
                      ("seq", src.with_amount_seq(src.amount, src.seq + 1))):
        # the voucher check runs before any fold, so only the source block
        # needs replacing: the signature over the old body does not verify
        wit_x = (list(M.pad(r5[1])) + M.w_levels(cpath, lt.EMPTY_NODE, frank.node(), S) + w.pos(frank) +
                 w.pads_for(root[1]) + M.w_levels(spath, src.node(), src2.node(), S) + w.pos(src) +
                 M.w_leaf(lf) + M.w_leaf(frank) + extras + [vsig, root[0], w.m])
        expect_fail(lambda: w.run("CLAIM", wit_x, ctx), f"mid: a voucher against a source whose {label} changed")
    w.tree = t5

    # ---------------- SEQ_FINAL marker (spec 5.2 / 7.5; Appendix C.6.5) ----------------
    # In MID the CLAIM seq check is a CScriptNum: 0x7FFFFFFF + 1 = 2^31 needs 5 bytes and
    # fails PADZ, so 0x7FFFFFFF is the non-claimable marker. 0xFFFFFFFF is NOT a marker
    # here: it is the minimal encoding of -2^31+1, whose successor still fits 4 bytes.
    def claim_wit(src, src_seq_num, seq1_num, claim, s_src, s_claim):
        w.tree.leaves = {s_alice: w.tree.leaves[s_alice], s_src: src}
        root = w.tree.root()
        spath = w.tree.path(s_src)
        t = w.clone()
        t.leaves[s_src] = src.with_amount_seq(src.amount - claim.amount, int.from_bytes((seq1_num + bytes(4))[:4], "little"))
        t.leaves[s_claim] = claim
        src2 = t.leaves[s_src]
        cpath = t.path(s_claim); r = t.root()
        ctx = w.ctx([(r[1], w.spk(r))], (600, P2WPKH))
        vsig = schnorr_sign(lt.voucher_msg(w.tree_id, src, claim), sk("chan-src-owner"))
        pad_of = lambda x: (bytes(4 - len(x)), bytes(len(x))) if len(x) <= 4 else (b"", bytes(4))
        extras = ([src_seq_num] + list(pad_of(src_seq_num)) + list(pad_of(seq1_num)) + list(M.pad(src.amount - claim.amount)) +
                  [M.scriptnum(src.evict_after)] + list(M.pad(src.evict_after)) +
                  [M.scriptnum(claim.evict_after)] + list(M.pad(claim.evict_after)))
        wit = (list(M.pad(r[1])) + M.w_levels(cpath, lt.EMPTY_NODE, claim.node(), S) + w.pos(claim) +
               w.pads_for(root[1]) + M.w_levels(spath, src.node(), src2.node(), S) + w.pos(src) +
               M.w_leaf(src) + M.w_leaf(claim) + extras + [vsig, root[0], w.m])
        return wit, ctx
    s_alice = w.slot(alice, 0)
    for seq, seq_num, seq1_num, claimable in (
            (0x7FFFFFFF, b"\xff\xff\xff\x7f", b"\x00\x00\x00\x80\x00", False),
            (0x7FFFFFFE, b"\xfe\xff\xff\x7f", b"\xff\xff\xff\x7f", True),
            (0xFFFFFFFF, b"\xff\xff\xff\xff", b"\xfe\xff\xff\xff", True)):
        src = mk_leaf("chan-src", 1_000_000, seq=seq, sparse=S)
        s_src = w.slot(src, (1 << depth) - 1)
        claim = carve_of(src, "claimant", 40_000, sparse=S)
        s_claim = w.slot(claim, 3)
        wit, ctx = claim_wit(src, seq_num, seq1_num, claim, s_src, s_claim)
        if claimable:
            w.run("CLAIM", wit, ctx)
            check(True, f"mid: CLAIM with seq {seq:#x} succeeds")
        else:
            expect_fail(lambda: w.run("CLAIM", wit, ctx), f"mid: CLAIM against SEQ_FINAL {seq:#x} must fail")

    if verbose:
        print(f"\nMID profile={'S' if S else 'D'} D={depth} taptree leaves={len(w.compiled)}")
        for k, (it, sl, wl) in costs.items():
            print(f"{k:16} script {sl:6}  witness {wl:5}  maxdepth {it.max_depth}")
    return costs, w


def snum(n):
    """A signed CScriptNum with its PADZ pad: (x, z, w), size(x) + size(z) == 4."""
    from script_sim import scriptnum_encode
    x = scriptnum_encode(n)
    assert len(x) <= 4
    return x, bytes(4 - len(x)), bytes(len(x))


def signed_read(v):
    """What a four-byte le32(v) is as a CScriptNum: sign-magnitude, so a
    value with its top bit set reads as -(v - 2^31)."""
    return v if v < (1 << 31) else -(v - (1 << 31))


def fold_signed(h, acc, path):
    """The fold as LEVEL_MID computes it when the accumulator is a signed
    CScriptNum: the node's sum bytes are x || z || 00000000 || 01 with x the
    sign-magnitude encoding of acc, and a sibling's committed sum enters
    the accumulator as signed_read of its le32."""
    for d, sib in path:
        x, z, _ = snum(acc)
        me = h + x + z + bytes(4) + b"\x01"
        sb = sib[0] + lt.enc64(sib[1])
        h = lt.tagged_hash(lt.TAG_NODE, (sb + me) if d else (me + sb))
        acc += signed_read(sib[1])
    return h, acc


def levels_signed(path, old_sum, new_sum):
    """Level items (bottom..top) for signed accumulators; a sibling whose
    sum is 2^31 or more is supplied as the negative number its le32 is."""
    per = []
    os_, ns = old_sum, new_sum
    for k, (d, sib) in enumerate(path):
        ss, zs, ws = snum(signed_read(sib[1]))
        _, zn, wn = snum(ns)
        _, zo, wo = snum(os_)
        per.append([zo, wo, zn, wn, b"\x01" if d else b"", sib[0], ss, zs, ws])
        os_ += signed_read(sib[1]); ns += signed_read(sib[1])
    items = []
    for lv in reversed(per):
        items += lv
    return items


def leaf10_signed(leaf, amt_num):
    """A ten-element leaf whose amount number is supplied as given."""
    b = leaf.serialize()
    x, z, w = amt_num
    return [b[0:8], b[8:40], b[40:72], b[72:104], b[104:108], b[108:112], b[112:116], x, z, w]


def big_leaf(label, amount, evictor, evict_after, nonce):
    """A Leaf whose amount bypasses the constructor's range checks."""
    lf = lt.Leaf(1, pubkey_x(sk(label + "-exit")), pubkey_x(sk(label + "-owner")), evictor, 0, nonce, 0)
    lf.amount, lf.evict_after = amount, evict_after
    return lf


def test_sign_rules(depth, verbose=True):
    """NONNEG (spec 4.5, 10.6): CScriptNum is sign-magnitude, so a four-byte
    number with its top bit set is negative. 2^31 + 2^24 is le32
    `00 00 00 81`, a minimal CScriptNum equal to -2^24, and without the
    check it passes PADZ as the le32 of 2^31 + 2^24 while entering every
    accumulator as -2^24. Each case below commits a sum of 2^31 + 2^24 to
    the tree while the script's arithmetic sees -2^24, and expects the
    witness-supplied number to be rejected at the site it enters:

    * `JOIN_2`: `new_sum` (the dense join block), output 0 at S - 2^24;
    * `JOIN_0`: a leaf amount (`LEAF_JOIN`), output 0 at S - 2^24;
    * `SPLIT`: the claim leaf's amount (`LEAF_JOIN`), so the source gains
      2^24 with output 0 unchanged;
    * `EXIT_1`: a sibling sum (`LEVEL_MID`), with a tree whose root was
      folded the way the script would fold it.

    `evict_after` and `seq` are not sums and keep their PADZ-only
    treatment; the last case checks that a leaf whose `evict_after` is
    2^31 + 2^24 (negative as a CScriptNum) cannot be evicted at any lock
    time, which is BIP-65's negative-operand rule."""
    w = MidWorld(depth, False)
    alice = mk_leaf("alice", 50_000)
    oper = mk_leaf("operator", 100_000_000)
    w.tree.leaves = {0: alice, (1 << depth) - 1: oper}
    root = w.tree.root()
    S = root[1]
    BIG = (1 << 31) + (1 << 24)
    NEG = snum(-(1 << 24))
    assert NEG[0] == b"\x00\x00\x00\x81" and NEG[0] == lt.le32(BIG)
    out0 = S - (1 << 24)

    # JOIN_2: a subtree whose committed sum is BIG
    h, idx = 2, 2
    jpath = w.tree.path(idx << h, height=h)
    fake_hash = lt.sha256(b"operator's subtree")
    r2 = fold_signed(fake_hash, -(1 << 24), jpath)
    check(r2[1] == out0, "mid: the signed fold of the joined subtree reaches S - 2^24")
    ctx = w.ctx([(out0, w.spk(r2))], (5_000, P2WPKH))
    osig = schnorr_sign(ctx.sighash(), w.op_sk)
    wit = (list(M.pad(out0)) + list(M.pad(S)) + levels_signed(jpath, 0, -(1 << 24)) +
           [fake_hash, NEG[0], osig, root[0], w.m])
    expect_fail(lambda: w.run("JOIN_2", wit, ctx), "mid: JOIN_2 with new_sum = 2^31 + 2^24 (a negative CScriptNum)")

    # JOIN_0: a leaf of amount BIG
    big = big_leaf("big", BIG, w.op_pk, 900_000, 7)
    jpath0 = w.tree.path(9)
    r3 = fold_signed(big.hash(), -(1 << 24), jpath0)
    ctx3 = w.ctx([(out0, w.spk(r3))], (5_000, P2WPKH))
    osig3 = schnorr_sign(ctx3.sighash(), w.op_sk)
    wit3 = (list(M.pad(out0)) + list(M.pad(S)) + levels_signed(jpath0, 0, -(1 << 24)) +
            [big.hash(), NEG[0], osig3, root[0], w.m])
    expect_fail(lambda: w.run("JOIN_0", wit3, ctx3), "mid: JOIN_0 with a leaf amount of 2^31 + 2^24")

    # SPLIT: a claim leaf of amount BIG, so the source gains 2^24
    w.compiled = dict(w.compiled); w.compiled["SPLIT"] = assemble(M.split_script(depth, False), mode="c0")
    w.m = lt.taptree_root([lt.tapleaf_hash(c, 0xc0) for c in w.compiled.values()])
    root = w.tree.root()
    claim = big_leaf("claim", BIG, alice.evictor_key, alice.evict_after, 11)
    amt_new = alice.amount + (1 << 24)
    src2 = alice.with_amount_seq(amt_new, alice.seq + 1)
    spath = w.tree.path(0)
    t1 = w.clone(); t1.leaves[0] = src2
    cpath = t1.path(3)
    r1 = fold_signed(claim.hash(), -(1 << 24), cpath)
    check(r1[1] == S, "mid: the signed carve conserves the script's total while the source gains 2^24")
    ctxs = w.ctx([(S, w.spk(r1))], (600, P2WPKH))
    asig = schnorr_sign(ctxs.sighash(), sk("alice-owner"))
    extras = ([M.scriptnum(alice.seq)] + list(M.pad(alice.seq)) + list(M.pad(alice.seq + 1)) + list(M.pad(amt_new)) +
              [M.scriptnum(alice.evict_after)] + list(M.pad(alice.evict_after)) +
              [M.scriptnum(claim.evict_after)] + list(M.pad(claim.evict_after)))
    wits = (list(M.pad(S)) + levels_signed(cpath, 0, -(1 << 24)) +
            list(M.pad(S)) + M.w_levels(spath, alice.node(), src2.node(), False) +
            M.w_leaf(alice) + leaf10_signed(claim, NEG) + extras + [asig, root[0], w.m])
    expect_fail(lambda: w.run("SPLIT", wits, ctxs), "mid: SPLIT with a claim leaf amount of 2^31 + 2^24")

    # EXIT_1: a sibling whose committed sum is BIG, in a tree folded as the script folds
    bob = mk_leaf("bob", 20_000_000)
    sib = (lt.sha256(b"a node of sum 2^31 + 2^24"), BIG)
    path = [(1, sib)] + [(0, lt.empty_node(k)) for k in range(1, depth)]
    r_old = fold_signed(bob.hash(), bob.amount, path)
    r_new = fold_signed(lt.EMPTY_LEAF_HASH, 0, path)
    S_old = r_old[1]
    check(S_old == bob.amount - (1 << 24), "mid: the signed fold reads the sibling as -2^24")
    out_new = int.from_bytes(snum(r_new[1])[0] + snum(r_new[1])[1] + bytes(4), "little")
    ctx_e = TxContext([(S_old, w.spk(r_old)), (5_000, P2WPKH)],
                      [(out_new, w.spk(r_new)), (bob.amount, lt.p2tr_spk(bob.exit_key))])
    sig_e = schnorr_sign(ctx_e.sighash(), sk("bob-owner"))
    wit_e = (list(snum(r_new[1])[1:]) + list(M.pad(S_old)) + levels_signed(path, bob.amount, 0) +
             M.w_leaf_exit(bob) + [sig_e, b"", r_old[0], w.m])
    expect_fail(lambda: w.run("EXIT_1", wit_e, ctx_e), "mid: EXIT_1 with a sibling sum of 2^31 + 2^24")

    # evict_after of 2^31 + 2^24: a negative CLTV operand fails (BIP-65)
    w2 = MidWorld(depth, False)
    late = big_leaf("late", 125_000, w2.op_pk, BIG, 3)
    w2.tree.leaves = {0: alice, 5: late}
    root2 = w2.tree.root()
    path2 = w2.tree.path(5)
    t2 = w2.clone(); del t2.leaves[5]; r2_ = t2.root()
    ctx_l = w2.ctx([(r2_[1], w2.spk(r2_)), (late.amount, lt.p2tr_spk(late.exit_key))], (5_000, P2WPKH), locktime=0)
    esig = schnorr_sign(ctx_l.sighash(), w2.op_sk)
    wit_l = (list(M.pad(r2_[1])) + list(M.pad(root2[1])) + M.w_levels(path2, late.node(), lt.EMPTY_NODE, False) +
             M.w_leaf(late) + [NEG[0], NEG[1], NEG[2], esig, b"\x01", root2[0], w2.m])
    expect_fail(lambda: w2.run("EXIT_1", wit_l, ctx_l), "mid: eviction with evict_after = 2^31 + 2^24 (negative CLTV operand)")
    if verbose:
        print(f"MID sign rules D={depth}: negative sums rejected at LEVEL_MID, LEAF_JOIN and the join block; negative CLTV operand rejected")


# le32(0x81000001) is `01 00 00 81`, the minimal CScriptNum -16,777,217: as an
# evict_after field it passes PADZ with an empty pad (NEG_LEASE_EA is the
# number with that pad), so only NONNEG keeps it out of the carve compare.
NEG_LEASE = b"\x01\x00\x00\x81"
NEG_LEASE_EA = (NEG_LEASE, b"", bytes(4))
MAX_LEASE = 499_999_999


def test_carve_lease_sign(depth, verbose=True):
    """NONNEG on the carve rule's claim lease (spec 7.5 rule 5, 10.6). A
    claim leaf whose evict_after field is `01 00 00 81` is the negative
    CScriptNum -16,777,217 with an empty PADZ pad, so the lease compare
    alone accepts it against any source lease, and the leaf it plants keeps
    the operator as evictor while BIP-65 rejects its eviction for good.
    CLAIM and SPLIT of such a leaf fail at NONNEG; a carve at the largest
    valid height (499,999,999, 5.2) succeeds, so the check is not
    over-tight; and the planted leaf's eviction is shown to fail at any
    lock time."""
    w = MidWorld(depth, False)
    w.compiled = dict(w.compiled); w.compiled["SPLIT"] = assemble(M.split_script(depth, False), mode="c0")
    w.m = lt.taptree_root([lt.tapleaf_hash(c, 0xc0) for c in w.compiled.values()])
    alice = mk_leaf("alice", 500_000, w.op_pk, MAX_LEASE)
    oper = mk_leaf("operator", 1_000_000)
    s_a, s_c, s_o = 0, 3, (1 << depth) - 1
    w.tree.leaves = {s_a: alice, s_o: oper}
    root = w.tree.root()
    spath = w.tree.path(s_a)

    def carve(name, lf, claim_ea=None):
        """A CLAIM or SPLIT of lf out of alice's leaf into s_c: (runner, new tree)."""
        src2 = alice.with_amount_seq(alice.amount - lf.amount, alice.seq + 1)
        t1 = w.clone(); t1.leaves[s_a] = src2; t1.leaves[s_c] = lf; r1 = t1.root()
        ctx = w.ctx([(r1[1], w.spk(r1))], (600, P2WPKH))
        auth = (schnorr_sign(ctx.sighash(), sk("alice-owner")) if name == "SPLIT"
                else schnorr_sign(lt.voucher_msg(w.tree_id, alice, lf), sk("alice-owner")))
        wit = (list(M.pad(r1[1])) + M.w_levels(t1.path(s_c), lt.EMPTY_NODE, lf.node(), False) +
               list(M.pad(root[1])) + M.w_levels(spath, alice.node(), src2.node(), False) +
               M.w_leaf(alice) + M.w_leaf(lf) + M.w_carve_extras(alice, lf, claim_ea=claim_ea) +
               [auth, root[0], w.m])
        return (lambda: w.run(name, wit, ctx)), t1

    planted = big_leaf("planted", 200_000, alice.evictor_key, 0x81000001, 5)
    assert planted.serialize()[104:108] == NEG_LEASE
    for name in ("CLAIM", "SPLIT"):
        run, _ = carve(name, carve_of(alice, "edge", 200_000))
        run()
        check(True, f"mid: {name} of a leaf with evict_after 499,999,999 off a source at the same lease succeeds")
        run, t1 = carve(name, planted, claim_ea=NEG_LEASE_EA)
        expect_fail(run, f"mid: {name} of a leaf with evict_after 01 00 00 81 (a negative CScriptNum lease)")
    # The leaf such a carve would plant cannot be evicted: OP_CHECKLOCKTIMEVERIFY
    # rejects the negative operand whatever the lock time (BIP-65).
    w.tree = t1; root1 = t1.root()
    t2 = w.clone(); del t2.leaves[s_c]; r2 = t2.root()
    for lock in (0, MAX_LEASE):
        ctx_e = w.ctx([(r2[1], w.spk(r2)), (planted.amount, lt.p2tr_spk(planted.exit_key))], (5_000, P2WPKH), locktime=lock)
        esig = schnorr_sign(ctx_e.sighash(), w.op_sk)
        wit_e = (list(M.pad(r2[1])) + list(M.pad(root1[1])) + M.w_levels(t1.path(s_c), planted.node(), lt.EMPTY_NODE, False) +
                 M.w_leaf(planted) + list(NEG_LEASE_EA) + [esig, b"\x01", root1[0], w.m])
        expect_fail(lambda: w.run("EXIT_1", wit_e, ctx_e),
                    f"mid: eviction of the planted leaf at lock time {lock:,} (negative CLTV operand)")
    if verbose:
        print(f"MID carve lease sign D={depth}: a negative claim lease rejected at NONNEG under CLAIM and SPLIT; "
              f"its eviction would fail at any lock time")


def test_update_x(depth, sparse, verbose=True):
    """MID UPDATE^x (spec 7.4 rule 5): UPDATE plus a signature by old.ek.

    The variant is a tree-creation parameter, so it is swapped into the
    taptree under the name UPDATE_X and m is recomputed.
    """
    w = MidWorld(depth, sparse)
    S = sparse
    toks = M.update_script(depth, w.op_pk, sparse, exit_consent=True)
    bad = {t for t in toks if isinstance(t, str)} - MID_OPCODES
    check(not bad, f"MID UPDATE_X: opcodes outside the MID set: {sorted(bad)}")
    script = assemble(toks, mode="c0")
    w.compiled = dict(w.compiled); w.compiled["UPDATE_X"] = script
    w.m = lt.taptree_root([lt.tapleaf_hash(c, 0xc0) for c in w.compiled.values()])
    # six leaves, as the sparse witness sizes elsewhere are measured
    alice = mk_leaf("alice", 50_000, sparse=S)
    oper = mk_leaf("operator", 1_000_000, sparse=S)
    others = [mk_leaf(n, a, sparse=S) for n, a in (("bob", 125_000), ("carol", 30_000),
                                                   ("dave", 70_000), ("erin", 15_000))]
    s_a, s_o = w.slot(alice, 0), w.slot(oper, (1 << depth) - 1)
    w.tree.leaves = {s_a: alice, s_o: oper}
    for i, lf in enumerate(others):
        w.tree.leaves[w.slot(lf, i + 1)] = lf
    root = w.tree.root()
    upath = w.tree.path(s_a)
    alice2 = alice.with_amount_seq(80_000, 1)
    t1 = w.clone(); t1.leaves[s_a] = alice2; r1 = t1.root()
    ctx = w.ctx([(r1[1], w.spk(r1))], (30_700, P2WPKH))
    osig = schnorr_sign(ctx.sighash(), w.op_sk)
    asig = schnorr_sign(ctx.sighash(), sk("alice-owner"))
    xsig = schnorr_sign(ctx.sighash(), sk("alice-exit"))
    block = (list(M.pad(r1[1])) + w.pads_for(root[1]) +
             M.w_levels(upath, alice.node(), alice2.node(), S) + w.pos(alice) +
             M.w_leaf(alice) + M.w_leaf(alice2))
    wit = block + [asig, osig, xsig, root[0], w.m]
    it = w.run("UPDATE_X", wit, ctx)
    check(True, "mid: UPDATE^x with owner, operator and exit signatures")
    # negatives
    expect_fail(lambda: w.run("UPDATE_X", block + [asig, osig, asig, root[0], w.m], ctx), "mid: UPDATE^x exit_sig by the wrong key")
    expect_fail(lambda: w.run("UPDATE_X", block + [asig, osig, bytes(64), root[0], w.m], ctx), "mid: UPDATE^x garbage exit_sig")
    expect_fail(lambda: w.run("UPDATE_X", block + [asig, osig, root[0], w.m], ctx), "mid: UPDATE^x missing exit_sig")
    expect_fail(lambda: w.run("UPDATE_X", block + [osig, osig, xsig, root[0], w.m], ctx), "mid: UPDATE^x without the owner signature")
    if verbose:
        plain = len(assemble(M.update_script(depth, w.op_pk, sparse), mode="c0"))
        print(f"MID UPDATE^x {'S' if S else 'D'} D={depth}: script {len(script)} B "
              f"(UPDATE {plain} B), witness {sum(len(x) for x in wit)} B")
    return it, len(script), sum(len(x) for x in wit)


def test_claim_h(depth, sparse, verbose=True):
    """MID CLAIM^h (spec 7.5.1): CLAIM whose voucher also commits to a payment hash.

    Swapped into the taptree as CLAIM_H, like UPDATE_X: it is a tree-creation
    parameter, not part of the reference script set.
    """
    w = MidWorld(depth, sparse)
    S = sparse
    toks = M.claim_script(depth, w.tree_id, sparse, hashlock=True)
    bad = {t for t in toks if isinstance(t, str)} - MID_OPCODES
    check(not bad, f"MID CLAIM_H: opcodes outside the MID set: {sorted(bad)}")
    script = assemble(toks, mode="c0")
    w.compiled = dict(w.compiled); w.compiled["CLAIM_H"] = script
    w.m = lt.taptree_root([lt.tapleaf_hash(c, 0xc0) for c in w.compiled.values()])
    alice = mk_leaf("alice", 50_000, sparse=S)
    oper = mk_leaf("operator", 1_000_000, sparse=S)
    s_a, s_o = w.slot(alice, 0), w.slot(oper, (1 << depth) - 1)
    w.tree.leaves = {s_a: alice, s_o: oper}
    root = w.tree.root()
    src = w.tree.leaves[s_o]

    preimage = lt.sha256(b"payment-preimage")
    payment_hash = lt.sha256(preimage)
    hodl = carve_of(src, "hodl", 40_000, sparse=S)
    s_h = w.slot(hodl, 3)
    spath = w.tree.path(s_o)
    t1 = w.clone(); lt.apply_claim(t1, s_o, s_h, hodl)
    src2 = t1.leaves[s_o]
    cpath = t1.path(s_h); r1 = t1.root()
    ctx = w.ctx([(r1[1], w.spk(r1))], (600, P2WPKH))
    hsig = schnorr_sign(lt.voucher_h_msg(w.tree_id, src, hodl, payment_hash), sk("operator-owner"))
    extras = M.w_carve_extras(src, hodl)
    head = (list(M.pad(r1[1])) + M.w_levels(cpath, lt.EMPTY_NODE, hodl.node(), S) + w.pos(hodl) +
            w.pads_for(root[1]) + M.w_levels(spath, src.node(), src2.node(), S) + w.pos(src) +
            M.w_leaf(src) + M.w_leaf(hodl) + extras)
    wit = head + [hsig, preimage, root[0], w.m]
    it = w.run("CLAIM_H", wit, ctx)
    check(True, "mid: CLAIM^h redeemed with the correct preimage")
    # negatives
    expect_fail(lambda: w.run("CLAIM_H", head + [hsig, lt.sha256(b"wrong"), root[0], w.m], ctx),
                "mid: CLAIM^h wrong preimage")
    expect_fail(lambda: w.run("CLAIM_H", head + [hsig, preimage[:31], root[0], w.m], ctx),
                "mid: CLAIM^h preimage not 32 bytes")
    plain_sig = schnorr_sign(lt.voucher_msg(w.tree_id, src, hodl), sk("operator-owner"))
    expect_fail(lambda: w.run("CLAIM_H", head + [plain_sig, preimage, root[0], w.m], ctx),
                "mid: CLAIM^h with a plain voucher signature")
    expect_fail(lambda: w.run("CLAIM", head + [hsig, root[0], w.m], ctx),
                "mid: plain CLAIM with a hash-locked voucher signature")
    bsig = schnorr_sign(lt.voucher_h_msg(w.tree_id, src, hodl, payment_hash), sk("alice-owner"))
    expect_fail(lambda: w.run("CLAIM_H", head + [bsig, preimage, root[0], w.m], ctx),
                "mid: CLAIM^h voucher wrong signer")
    other_tid = lt.tree_id(lt.sha256(b"creation-txid"), 1)
    expect_fail(lambda: w.run("CLAIM_H", head + [schnorr_sign(lt.voucher_h_msg(other_tid, src, hodl, payment_hash), sk("operator-owner")), preimage, root[0], w.m], ctx),
                "mid: CLAIM^h voucher signed for another tree_id")
    expect_fail(lambda: w.run("CLAIM_H", head + [schnorr_sign(lt.voucher_h_msg(w.m, src, hodl, payment_hash), sk("operator-owner")), preimage, root[0], w.m], ctx),
                "mid: CLAIM^h voucher over m instead of tree_id")
    if verbose:
        plain = len(assemble(M.claim_script(depth, w.tree_id, sparse), mode="c0"))
        print(f"MID CLAIM^h {'S' if S else 'D'} D={depth}: script {len(script)} B "
              f"(CLAIM {plain} B), witness {sum(len(x) for x in wit)} B")
    return it, len(script), sum(len(x) for x in wit)


def test_split(depth, sparse, verbose=True):
    """MID SPLIT (spec 7.5.2): CLAIM authorised by the owner's transaction
    signature. Swapped into the taptree as SPLIT, like UPDATE_X and CLAIM_H."""
    w = MidWorld(depth, sparse)
    S = sparse
    toks = M.split_script(depth, sparse)
    bad = {t for t in toks if isinstance(t, str)} - MID_OPCODES
    check(not bad, f"MID SPLIT: opcodes outside the MID set: {sorted(bad)}")
    check("OP_CHECKSIGFROMSTACK" not in toks, "mid: SPLIT needs no OP_CHECKSIGFROMSTACK")
    script = assemble(toks, mode="c0")
    w.compiled = dict(w.compiled); w.compiled["SPLIT"] = script
    w.m = lt.taptree_root([lt.tapleaf_hash(c, 0xc0) for c in w.compiled.values()])
    alice = mk_leaf("alice", 500_000, sparse=S)
    oper = mk_leaf("operator", 1_000_000, sparse=S)
    s_a, s_o = w.slot(alice, 0), w.slot(oper, (1 << depth) - 1)
    w.tree.leaves = {s_a: alice, s_o: oper}
    root = w.tree.root()

    bob = carve_of(alice, "bob", 200_000, sparse=S)
    s_b = w.slot(bob, 3)
    spath = w.tree.path(s_a)
    t1 = w.clone(); lt.apply_claim(t1, s_a, s_b, bob)
    src2 = t1.leaves[s_a]
    cpath = t1.path(s_b); r1 = t1.root()
    ctx = w.ctx([(r1[1], w.spk(r1))], (600, P2WPKH))
    asig = schnorr_sign(ctx.sighash(), sk("alice-owner"))
    extras = M.w_carve_extras(alice, bob)
    head = (list(M.pad(r1[1])) + M.w_levels(cpath, lt.EMPTY_NODE, bob.node(), S) + w.pos(bob) +
            w.pads_for(root[1]) + M.w_levels(spath, alice.node(), src2.node(), S) + w.pos(alice) +
            M.w_leaf(alice) + M.w_leaf(bob) + extras)
    wit = head + [asig, root[0], w.m]
    it = w.run("SPLIT", wit, ctx)
    check(True, "mid: SPLIT authorised by the source owner")
    # negatives
    expect_fail(lambda: w.run("SPLIT", head + [schnorr_sign(ctx.sighash(), w.op_sk), root[0], w.m], ctx),
                "mid: SPLIT signed by the operator")
    expect_fail(lambda: w.run("SPLIT", head + [bytes(64), root[0], w.m], ctx),
                "mid: SPLIT garbage signature")
    vsig = schnorr_sign(lt.voucher_msg(w.tree_id, alice, bob), sk("alice-owner"))
    expect_fail(lambda: w.run("SPLIT", head + [vsig, root[0], w.m], ctx),
                "mid: SPLIT with a voucher signature")
    expect_fail(lambda: w.run("SPLIT", head + [asig, r1[0], w.m], ctx),
                "mid: SPLIT against a stale root")
    expect_fail(lambda: w.run("SPLIT", head + [schnorr_sign(ctx.sighash(), sk("bob-owner")), root[0], w.m], ctx),
                "mid: SPLIT signed by the recipient")

    def carve_head(new, s_new, cnode, amt_new):
        """Witness below the signature for a SPLIT of `new` into s_new,
        presenting s_new as empty; cnode is the source's claimed new node."""
        t = w.clone(); t.leaves[s_a] = src2; t.leaves[s_new] = new
        ex = M.w_carve_extras(alice, new, amt_new=amt_new)
        return (list(M.pad(t.root()[1])) + M.w_levels(t.path(s_new), lt.EMPTY_NODE, new.node(), S) + w.pos(new) +
                w.pads_for(root[1]) + M.w_levels(spath, alice.node(), cnode, S) + w.pos(alice) +
                M.w_leaf(alice) + M.w_leaf(new) + ex)
    greedy = carve_of(alice, "greedy", alice.amount + 1, sparse=S)
    expect_fail(lambda: w.run("SPLIT", carve_head(greedy, w.slot(greedy, 3), src2.node(), 0) +
                              [asig, root[0], w.m], ctx), "mid: SPLIT over-split underflow")

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
                [schnorr_sign(ctx_c.sighash(), sk("alice-owner")), root[0], w.m]), ctx_c
    for label, amt in (("one satoshi", 1), ("zero satoshis", 0), ("a one-satoshi residual", alice.amount - 1)):
        wit_d, ctx_d = carve(carve_of(alice, f"dust{amt}", amt, sparse=S))
        expect_fail(lambda: w.run("SPLIT", wit_d, ctx_d), f"mid: SPLIT of {label} (7.5 rule 6)")
    for label, amt in (("exactly DUST_MIN", lt.DUST_MIN), ("the whole balance", alice.amount)):
        wit_d, ctx_d = carve(carve_of(alice, f"ok{amt}", amt, sparse=S))
        w.run("SPLIT", wit_d, ctx_d)
        check(True, f"mid: SPLIT of {label} succeeds")
    # 7.5 rule 5 under SPLIT: another evictor key, a later evict_after
    for label, lf in (("another evictor key", mk_leaf("escape", 200_000, w.op_pk, alice.evict_after, sparse=S)),
                      ("a later evict_after", mk_leaf("later", 200_000, None, alice.evict_after + 1, sparse=S))):
        t_e = w.clone(); t_e.leaves[s_a] = src2; s_e = w.slot(lf, 3); t_e.leaves[s_e] = lf; r_e = t_e.root()
        ctx_e = w.ctx([(r_e[1], w.spk(r_e))], (600, P2WPKH))
        expect_fail(lambda: w.run("SPLIT", carve_head(lf, s_e, src2.node(), alice.amount - lf.amount) +
                                  [schnorr_sign(ctx_e.sighash(), sk("alice-owner")), root[0], w.m], ctx_e),
                    f"mid: SPLIT into a leaf with {label} than its source")
    if not S:   # in the sparse profile the destination is derived from the leaf
        occ = carve_of(alice, "bob", 200_000)
        expect_fail(lambda: w.run("SPLIT", carve_head(occ, s_o, src2.node(), alice.amount - occ.amount) +
                                  [asig, root[0], w.m], ctx), "mid: SPLIT into an occupied position")
    # the signature binds the recipient through output 0 (7.5.2, 10.7)
    mallory = carve_of(alice, "mallory", bob.amount, sparse=S)
    s_m = w.slot(mallory, 3)
    tm = w.clone(); lt.apply_claim(tm, s_a, s_m, mallory); rm = tm.root()
    ctx_m = w.ctx([(rm[1], w.spk(rm))], (600, P2WPKH))
    head_m = carve_head(mallory, s_m, src2.node(), alice.amount - mallory.amount)
    w.run("SPLIT", head_m + [schnorr_sign(ctx_m.sighash(), sk("alice-owner")), root[0], w.m], ctx_m)
    expect_fail(lambda: w.run("SPLIT", head_m + [asig, root[0], w.m], ctx_m),
                "mid: SPLIT recipient swapped under the owner's signature")
    if verbose:
        claim = len(assemble(M.claim_script(depth, w.tree_id, sparse), mode="c0"))
        print(f"MID SPLIT {'S' if S else 'D'} D={depth}: script {len(script)} B "
              f"(CLAIM {claim} B, saves {claim - len(script)}), witness {sum(len(x) for x in wit)} B")
    return it, len(script), sum(len(x) for x in wit)


def test_carve_rules(depth, verbose=True):
    """The carve rule (spec 7.5 rule 5) against the MID cohort sweep, as
    test_scripts.test_carve_rules: a cohort member's SPLIT of dust with a
    NUMS evictor or a later lease into the cohort's empty position fails,
    dust that keeps the member's terms lands and is swept, and a member the
    operator admitted with a NUMS evictor can still block the sweep (10.8)."""
    w = MidWorld(depth, False)
    height = 2
    w.compiled = dict(w.compiled)
    w.compiled["SPLIT"] = assemble(M.split_script(depth, False), mode="c0")
    w.compiled["EVICT_SUBTREE_2"] = assemble(M.evict_subtree_script(depth, height, w.op_pk), mode="c0")
    w.m = lt.taptree_root([lt.tapleaf_hash(c, 0xc0) for c in w.compiled.values()])
    n, base = 1 << height, 1 << height
    cohort = {base + i: mk_leaf(f"c{i}", 10_000 + 7 * i, w.op_pk, 800_000) for i in range(n - 1)}
    empty = base + n - 1
    alice = mk_leaf("alice", 50_000)

    def reset():
        w.tree = lt.Tree(depth); w.tree.leaves = dict(cohort); w.tree.leaves[0] = alice
        w.tree.leaves[(1 << depth) - 1] = mk_leaf("operator", 1_000_000)
        return w.tree.root()

    def split(src, s_src, new, signer):
        root = w.tree.root()
        src2 = src.with_amount_seq(src.amount - new.amount, src.seq + 1)
        t = w.clone(); t.leaves[s_src] = src2
        cpath = t.path(empty); t.leaves[empty] = new
        spath = w.tree.path(s_src)
        ctx = w.ctx([(t.root()[1], w.spk(t.root()))], (600, P2WPKH))
        wit = (list(M.pad(t.root()[1])) + M.w_levels(cpath, lt.EMPTY_NODE, new.node(), False) +
               w.pads_for(root[1]) + M.w_levels(spath, src.node(), src2.node(), False) +
               M.w_leaf(src) + M.w_leaf(new) + M.w_carve_extras(src, new) +
               [schnorr_sign(ctx.sighash(), sk(signer)), root[0], w.m])
        return t, wit, ctx

    def sweep(expect_ok, msg):
        rest = w.clone()
        for p in range(base, base + n):
            del rest.leaves[p]
        outs = [(rest.root()[1], w.spk(rest.root()))]
        outs += [(w.tree.leaves[p].amount, lt.p2tr_spk(w.tree.leaves[p].exit_key)) for p in range(base, base + n)]
        ctx = w.ctx(outs + [(400, P2WPKH)], (5_000, P2WPKH), locktime=800_000)
        wit = M.w_evict_subtree(w.tree, depth, height, 1) + [schnorr_sign(ctx.sighash(), w.op_sk), w.tree.root()[0], w.m]
        if expect_ok:
            w.run("EVICT_SUBTREE_2", wit, ctx); check(True, msg)
        else:
            expect_fail(lambda: w.run("EVICT_SUBTREE_2", wit, ctx), msg)

    reset()
    member, s_member = cohort[base], base
    for label, dust in (("a NUMS evictor", mk_leaf("dust", lt.DUST_MIN)),
                        ("a later evict_after", mk_leaf("dust", lt.DUST_MIN, w.op_pk, 800_001))):
        _, wit, ctx = split(member, s_member, dust, "c0-owner")
        expect_fail(lambda: w.run("SPLIT", wit, ctx), f"mid: cohort member plants dust with {label}")
    t1, wit, ctx = split(member, s_member, carve_of(member, "dust", lt.DUST_MIN), "c0-owner")
    w.run("SPLIT", wit, ctx)
    check(True, "mid: a carve that keeps the member's evictor and lease lands in the cohort")
    w.tree = t1
    sweep(True, "mid: EVICT_SUBTREE_2 sweeps the cohort including the carved dust leaf")
    reset()
    t2, wit, ctx = split(alice, 0, carve_of(alice, "dust", lt.DUST_MIN), "alice-owner")
    w.run("SPLIT", wit, ctx)
    w.tree = t2
    sweep(False, "mid: a non-evictable member's NUMS dust still blocks the sweep (10.8)")
    if verbose:
        print(f"MID carve rules D={depth}: dust with another evictor or a later lease rejected, "
              f"inherited dust swept with the cohort")


def test_evict_subtree(depth, height, verbose=True, full=False):
    """MID EVICT_SUBTREE_h (spec 7.7): the cohort sweep. Mirrors
    test_scripts.test_evict_subtree (same cohort, same negatives) over the
    MID witness. full=True occupies every position of the subtree instead
    of FULL's pattern, in which every fifth position has already exited.

    Returns (interp, script, witness); interp and witness are None when the
    full witness exceeds the 1,000-element initial stack limit, in which
    case the run is checked to fail."""
    w = MidWorld(depth, False)
    toks = M.evict_subtree_script(depth, height, w.op_pk)
    bad = {t for t in toks if isinstance(t, str)} - MID_OPCODES
    check(not bad, f"MID EVICT_SUBTREE_{height}: opcodes outside the MID set: {sorted(bad)}")
    name = f"EVICT_SUBTREE_{height}"
    script = assemble(toks, mode="c0")
    w.compiled = dict(w.compiled); w.compiled[name] = script
    w.m = lt.taptree_root([lt.tapleaf_hash(c, 0xc0) for c in w.compiled.values()])
    n = 1 << height
    idx = 1
    base = idx << height
    cohort = {}
    for i in range(n):
        if i % 5 == 3 and not full:
            continue
        cohort[base + i] = mk_leaf(f"c{i}", 10_000 + 7 * i, w.op_pk, 800_000)
    w.tree.leaves = dict(cohort)
    w.tree.leaves[0] = mk_leaf("alice", 50_000)
    w.tree.leaves[(1 << depth) - 1] = mk_leaf("operator", 1_000_000)

    def sweep_outputs(tree):
        rest = lt.Tree(depth)
        rest.leaves = {p: l for p, l in tree.leaves.items() if not base <= p < base + n}
        r = rest.root()
        return [(r[1], w.spk(r))] + [(tree.leaves[base + i].amount, lt.p2tr_spk(tree.leaves[base + i].exit_key))
                                     for i in range(n) if base + i in tree.leaves]
    outputs = sweep_outputs(w.tree) + [(400, P2WPKH)]

    def run(outs, locktime=800_000, tree=None, mutate=None, signer=None, m=None):
        saved = w.tree
        if tree is not None:
            w.tree = tree
        try:
            ctx = w.ctx(outs, (5_000, P2WPKH), locktime=locktime)
            body = M.w_evict_subtree(w.tree, depth, height, idx)
            if mutate:
                body = mutate(body)
            sig = schnorr_sign(ctx.sighash(), signer or w.op_sk)
            wit = body + [sig, w.tree.root()[0], m or w.m]
            return w.run(name, wit, ctx), wit
        finally:
            w.tree = saved
    if len(M.w_evict_subtree(w.tree, depth, height, idx)) + 3 + 3 > 1000:
        # BIP-342 caps stack plus altstack at 1,000 elements after every
        # opcode; the witness is the body, sig r m, and the prologue pushes
        # three more before anything is consumed (spec 4.5).
        # The rejection must come from the stack size limit itself.
        try:
            run(outputs)
            check(False, f"mid: {name} with {len(cohort)} of {n} positions occupied ran past the 1,000-element stack limit")
        except ScriptError as e:
            check("stack size limit" in str(e),
                  f"mid: {name} with {len(cohort)} of {n} positions occupied is rejected by the stack size limit: {str(e)[:60]}")
        if verbose:
            print(f"MID EVICT_SUBTREE_{height} D={depth}: {len(cohort)} of {n} positions, script {len(script)} B, "
                  f"witness over the 1,000-element limit (rejected)")
        return None, script, None
    it, wit = None, []
    try:
        it, wit = run(outputs)
        check(True, f"mid: {name} sweeps {len(cohort)} leaves")
    except ScriptError as e:
        check(False, f"mid: {name} positive: {str(e)[:90]}")
    # negatives, as in the FULL suite
    expect_fail(lambda: run(outputs, locktime=799_999), f"mid: {name} before lease expiry")
    bad_out = list(outputs); bad_out[1] = (outputs[1][0] - 1, outputs[1][1])
    expect_fail(lambda: run(bad_out), f"mid: {name} shortchanges a leaf")
    t_n = w.clone()
    free = next((base + i for i in range(n) if base + i not in cohort), base)
    t_n.leaves[free] = mk_leaf("stubborn", 5_000)   # NUMS evictor
    expect_fail(lambda: run(sweep_outputs(t_n), tree=t_n), f"mid: {name} with a non-evictable leaf")
    # MID-specific: the witness cannot hide a leaf, malform a node pad,
    # skip the operator or name another m.
    hide = lambda body: body[:-M.EVICT_SLOT_WITNESS] + [b""]   # position 0 presented as empty
    expect_fail(lambda: run(outputs[:1] + outputs[2:], mutate=hide),
                f"mid: {name} presents an occupied position as empty")
    if height >= 2:
        at = 4 + M.LEVEL_WITNESS * (depth - height)            # the last-consumed node pad pair

        def swap_pad(body):
            # move one zero byte from the filler into the pad: z || w is
            # still 00000000, but size(x) + size(z) is now 5.
            b = list(body); b[at], b[at + 1] = b[at] + b"\x00", b[at + 1][1:]
            return b
        expect_fail(lambda: run(outputs, mutate=swap_pad), f"mid: {name} with a malformed node pad")
    expect_fail(lambda: run(outputs, signer=sk("alice-owner")), f"mid: {name} without the operator signature")
    expect_fail(lambda: run(outputs, m=lt.sha256(b"evil")), f"mid: {name} with a wrong m")
    if verbose:
        print(f"MID EVICT_SUBTREE_{height} D={depth}: {len(cohort)} of {n} positions, script {len(script)} B, "
              f"witness {sum(len(x) for x in wit)} B ({len(wit)} elements), maxdepth {it.max_depth if it else '-'}")
    return it, script, wit


def _needs_owner_sig_mid(old, new):
    """Spec 7.9 rule 3 under MID's SEQ_FINAL (0x7FFFFFFF), computed
    independently of the script."""
    if old is None or (new is not None and old.serialize() == new.serialize()):
        return False
    if (new is not None and new.serialize()[8:] == old.serialize()[8:] and new.amount >= old.amount
            and old.seq != M.SEQ_FINAL):
        return False
    return True


def rewrite_case_mid(depth, height, scenario="mixed", exit_consent=False, plan=None):
    """Build a MID REWRITE_h spend for one of test_scripts._rewrite_plan's
    scenarios. Returns a dict with the world, the plan, the context and a
    `witness(old, new, ctx, signer_op, sign)` builder, so the negatives can
    rebuild the witness from a mutated plan."""
    name = f"REWRITE_X_{height}" if exit_consent else f"REWRITE_{height}"
    w = MidWorld(depth, False)
    toks = M.rewrite_script(depth, height, w.op_pk, exit_consent)
    bad = {t for t in toks if isinstance(t, str)} - MID_OPCODES
    check(not bad, f"MID {name}: opcodes outside the MID set: {sorted(bad)}")
    script = assemble(toks, mode="c0")
    w.compiled = dict(w.compiled); w.compiled[name] = script
    w.m = lt.taptree_root([lt.tapleaf_hash(c, 0xc0) for c in w.compiled.values()])
    base, old, new = plan or TS._rewrite_plan(w, height, scenario)
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

    def witness(old_, new_, ctx, signer_op=None, sign=True, tree=None, m=None, marker=True, **kw):
        tree = tree or w.tree
        sigs = {}
        for i in range(n):
            if sign and _needs_owner_sig_mid(old_[i], new_[i]):
                sigs[i] = [schnorr_sign(ctx.sighash(), sk(f"c{i}-owner"))]
                if exit_consent:
                    sigs[i].append(schnorr_sign(ctx.sighash(), sk(f"c{i}-exit")))
        body = M.w_rewrite(tree, depth, height, idx, new_, sigs, marker, **kw)
        sig_op = schnorr_sign(ctx.sighash(), signer_op or w.op_sk)
        return body + [sig_op, tree.root()[0], m or w.m], sigs

    outputs, delta = outputs_for(old, new)
    ctx = w.ctx(outputs, (max(delta, 0) + 5_000, P2WPKH))
    wit, sigs = witness(old, new, ctx)
    return dict(name=name, w=w, script=script, wit=wit, ctx=ctx, base=base, idx=idx, old=old, new=new,
                sigs=sigs, outputs=outputs, delta=delta, outputs_for=outputs_for, witness=witness)


def test_rewrite(depth, height, exit_consent=False, verbose=True, scenario="mixed"):
    """MID REWRITE_h (spec 7.9): the cohort rewrite over the MID witness,
    mirroring test_scripts.test_rewrite (same mixed cohort, same negatives)
    plus the MID-specific ones (a malformed node pad, a wrong m, a leaf
    whose amount field and number disagree). Returns (interp, script,
    witness); interp and witness are None when the witness exceeds the
    1,000-element stack limit, in which case the run is checked to fail."""
    c = rewrite_case_mid(depth, height, scenario, exit_consent)
    w, name, ctx, wit, outputs = c["w"], c["name"], c["ctx"], c["wit"], c["outputs"]
    old, new, sigs, base, delta = c["old"], c["new"], c["sigs"], c["base"], c["delta"]
    outputs_for, witness = c["outputs_for"], c["witness"]
    n = 1 << height
    root = w.tree.root()
    # BIP-342 caps stack plus altstack at 1,000 elements after every opcode;
    # the pre-pass peaks four above the witness (NONNEG's two copies over the
    # picked amount while idx, L and Z are parked), see spec 4.5.
    if len(wit) + 4 > 1000:
        # The rejection must come from the stack size limit itself, so that
        # a generator bug on this shape cannot pass as "over the limit".
        try:
            w.run(name, wit, ctx)
            check(False, f"mid: {name} ({scenario}) with {len(wit)} witness elements ran past the 1,000-element stack limit")
        except ScriptError as e:
            check("stack size limit" in str(e),
                  f"mid: {name} ({scenario}) with {len(wit)} witness elements is rejected by the stack size limit: {str(e)[:60]}")
        if verbose:
            print(f"MID {name} D={depth} ({scenario}): {n} positions, script {len(c['script'])} B, "
                  f"witness {len(wit)} elements, over the 1,000-element limit (rejected)")
        return None, c["script"], None
    it = None
    try:
        it = w.run(name, wit, ctx)
        check(True, f"mid: {name} D={depth}: {scenario} rewrite of {n} positions")
    except ScriptError as e:
        check(False, f"mid: {name} positive: {str(e)[:120]}")
        return None, c["script"], wit
    check(outputs[0][0] == root[1] + delta, f"mid: {name} output 0 is S + (sum new - sum old)")
    if scenario != "mixed":
        if verbose:
            print(f"MID {name} D={depth} ({scenario}): {n} positions, {len(sigs)} owner signatures, "
                  f"script {len(c['script'])} B, witness {sum(len(x) for x in wit)} B ({len(wit)} elements), "
                  f"maxdepth {it.max_depth}")
        return it, c["script"], wit

    def run_plan(old_, new_, tree=None, sign=True, signer_op=None, m=None, mutate=None, outs=None, marker=True):
        tree = tree or w.tree
        o, d = outputs_for(old_, new_, tree)
        o = outs or o
        ctx_ = w.ctx(o, (max(d, 0) + 5_000, P2WPKH)) if tree is w.tree else \
            TxContext([(tree.root()[1], w.spk(tree.root())), (max(d, 0) + 5_000, P2WPKH)], o)
        wit_, sigs_ = witness(old_, new_, ctx_, signer_op, sign, tree, m, marker)
        if mutate:
            wit_ = mutate(wit_, sigs_, ctx_)
        return w.run(name, wit_, ctx_)

    # the unchanged position: its new slot is the one-byte marker, or a full
    # second copy, which the script also accepts
    i_same = next(i for i in range(n) if old[i] and new[i] and old[i].serialize() == new[i].serialize())
    check(wit.count(M.REWRITE_SAME) >= 1, f"mid: {name} the unchanged position's new slot is the one-byte marker")
    run_plan(old, new, marker=False)
    check(True, f"mid: {name} an unchanged leaf supplied twice in full also passes")

    def slot_to_marker(leaf):
        """Replace the eleven-element slot of `leaf` in the witness with the marker."""
        slot = M.w_rewrite_slot(leaf)

        def mut(wit_, sigs_, ctx_):
            at = next(j for j in range(len(wit_) - len(slot) + 1) if wit_[j:j + len(slot)] == slot)
            return wit_[:at] + [M.REWRITE_SAME] + wit_[at + len(slot):]
        return mut
    # a marker as the old slot is a leaf of one element; a marker in place
    # of a changed leaf hides nothing, since the fold then sees the old leaf
    expect_fail(lambda: run_plan(old, new, mutate=slot_to_marker(old[i_same])), f"mid: {name} the marker as an old slot")
    i_chg = next(i for i in range(n) if old[i] and new[i] and old[i].serialize() != new[i].serialize())
    expect_fail(lambda: run_plan(old, new, mutate=slot_to_marker(new[i_chg])), f"mid: {name} the marker in place of a changed leaf")
    # rule 3: a changed leaf without its owner's signature
    i_rot = next(i for i in range(n) if old[i] and new[i] and _needs_owner_sig_mid(old[i], new[i]))

    def drop_sig(i):
        def mut(wit_, sigs_, ctx_):
            wit_ = list(wit_)
            del wit_[wit_.index(sigs_[i][0])]
            if exit_consent:
                del wit_[wit_.index(sigs_[i][1])]
            return wit_
        return mut
    expect_fail(lambda: run_plan(old, new, mutate=drop_sig(i_rot)), f"mid: {name} changed leaf without the owner signature")
    # rule 3: a key rotation disguised as an amount-only increase
    i_inc = next(i for i in range(n) if old[i] and new[i] and not _needs_owner_sig_mid(old[i], new[i])
                 and new[i].amount > old[i].amount)
    lf = old[i_inc]
    disguised = dict(new)
    disguised[i_inc] = lt.Leaf(lf.amount + 500, lf.exit_key, pubkey_x(sk("mallory")), lf.evictor_key,
                               lf.evict_after, lf.nonce, lf.seq)
    expect_fail(lambda: run_plan(old, disguised, mutate=drop_sig(i_inc)), f"mid: {name} key rotation disguised as an amount increase")
    run_plan(old, disguised)
    check(True, f"mid: {name} the same rotation with the owner's signature succeeds")
    # rule 3: an amount decrease and an exit-key change without a signature
    decreased = dict(new); decreased[i_inc] = lf.with_amount_seq(lf.amount - 1, lf.seq)
    expect_fail(lambda: run_plan(old, decreased, mutate=drop_sig(i_inc)), f"mid: {name} amount decrease without the owner signature")
    rekeyed = dict(new); rekeyed[i_inc] = lt.Leaf(lf.amount + 500, pubkey_x(sk("mallory")), lf.owner_key,
                                                 lf.evictor_key, lf.evict_after, lf.nonce, lf.seq)
    expect_fail(lambda: run_plan(old, rekeyed, mutate=drop_sig(i_inc)), f"mid: {name} exit-key change without the owner signature")
    # rule 3: the exemption stops at a SEQ_FINAL leaf (0x7FFFFFFF in MID):
    # raising its amount by 1 sat needs the owner's signature too
    t_f = w.clone()
    final_old, final_new = dict(old), dict(new)
    final_old[i_inc] = lf.with_amount_seq(lf.amount, M.SEQ_FINAL)
    final_new[i_inc] = lf.with_amount_seq(lf.amount + 1, M.SEQ_FINAL)
    t_f.leaves[base + i_inc] = final_old[i_inc]
    expect_fail(lambda: run_plan(final_old, final_new, tree=t_f, mutate=drop_sig(i_inc)),
                f"mid: {name} SEQ_FINAL leaf raised by 1 sat without the owner signature")
    run_plan(final_old, final_new, tree=t_f)
    check(True, f"mid: {name} the same raise with the owner's signature succeeds")
    # FULL's SEQ_FINAL (0xFFFFFFFF) is not the MID marker: the exemption applies there
    t_g = w.clone()
    g_old, g_new = dict(old), dict(new)
    g_old[i_inc] = lf.with_amount_seq(lf.amount, 0xFFFFFFFF)
    g_new[i_inc] = lf.with_amount_seq(lf.amount + 1, 0xFFFFFFFF)
    t_g.leaves[base + i_inc] = g_old[i_inc]
    run_plan(g_old, g_new, tree=t_g)
    check(True, f"mid: {name} a seq of 0xFFFFFFFF is not MID's SEQ_FINAL: the amount-only exemption applies")
    # rule 3: a spurious signature where none is due is consumed as the next element
    def add_sig(wit_, sigs_, ctx_):
        wit_ = list(wit_)
        at = wit_.index(sigs_[i_rot][0])
        wit_.insert(at, schnorr_sign(ctx_.sighash(), sk(f"c{i_inc}-owner")))
        return wit_
    expect_fail(lambda: run_plan(old, new, mutate=add_sig), f"mid: {name} spurious signature on an exempt position")
    # rule 5: a shortchanged exit payout, and one paid to the wrong key
    i_exit = next(i for i in range(n) if old[i] and new[i] is None)
    k = 1 + sum(1 for i in range(i_exit) if old[i] and new[i] is None)
    outs_s = list(outputs); outs_s[k] = (outs_s[k][0] - 1, outs_s[k][1])
    expect_fail(lambda: run_plan(old, new, outs=outs_s), f"mid: {name} shortchanged exit payout")
    outs_k = list(outputs); outs_k[k] = (outs_k[k][0], lt.p2tr_spk(pubkey_x(sk("mallory"))))
    expect_fail(lambda: run_plan(old, new, outs=outs_k), f"mid: {name} exit paid to the wrong key")
    # rule 5: an exit without its owner's signature
    expect_fail(lambda: run_plan(old, new, mutate=drop_sig(i_exit)), f"mid: {name} exit without the owner signature")
    # rule 4: no operator signature
    expect_fail(lambda: run_plan(old, new, signer_op=sk("alice-owner")), f"mid: {name} without the operator signature")
    # rule 6: output 0 not conserved (under and over)
    for off in (-1, +1):
        outs_u = list(outputs); outs_u[0] = (outs_u[0][0] + off, outs_u[0][1])
        expect_fail(lambda: run_plan(old, new, outs=outs_u), f"mid: {name} output 0 off by {off:+d}")
    # rule 1: a stale path and a forged old leaf
    t_s = w.clone(); t_s.leaves[0] = mk_leaf("alice", 51_000)

    def stale_path(wit_, sigs_, ctx_):
        good = M.w_rewrite(w.tree, depth, height, c["idx"], new, sigs_)
        stale = M.w_rewrite(t_s, depth, height, c["idx"], new, sigs_)
        return stale + wit_[len(good):]
    expect_fail(lambda: run_plan(old, new, mutate=stale_path), f"mid: {name} stale path")
    forged = dict(old); forged[i_rot] = old[i_rot].with_amount_seq(old[i_rot].amount + 1, old[i_rot].seq)
    t_forged = w.clone(); t_forged.leaves[base + i_rot] = forged[i_rot]

    def forge(wit_, sigs_, ctx_):
        return M.w_rewrite(t_forged, depth, height, c["idx"], new, sigs_) + wit_[-3:]
    expect_fail(lambda: run_plan(old, new, mutate=forge), f"mid: {name} forged old leaf")
    # MID-specific: the amount field and its number disagree in an old leaf
    def bad_amount(wit_, sigs_, ctx_):
        wit_ = list(wit_)
        at = len(wit_) - 3 - 1 - 3            # position 0's old slot: flag, then wa za amt_num
        assert wit_[at] == M.scriptnum(old[0].amount)
        wit_[at] = M.scriptnum(old[0].amount + 256)
        return wit_
    expect_fail(lambda: run_plan(old, new, mutate=bad_amount), f"mid: {name} old leaf amount field and number disagree")
    # MID-specific: a malformed node pad, a wrong m, an occupied position presented as empty
    if height >= 2:
        at = 4 + M.LEVEL_WITNESS * (depth - height)      # the last-consumed pad pair (the first node's new sum)

        def swap_pad(wit_, sigs_, ctx_):
            b = list(wit_); b[at], b[at + 1] = b[at] + b"\x00", b[at + 1][1:]
            return b
        expect_fail(lambda: run_plan(old, new, mutate=swap_pad), f"mid: {name} with a malformed node pad")
    expect_fail(lambda: run_plan(old, new, m=lt.sha256(b"evil")), f"mid: {name} with a wrong m")
    hidden = dict(old); hidden[i_rot] = None
    t_h = w.clone(); del t_h.leaves[base + i_rot]

    def hide(wit_, sigs_, ctx_):
        return M.w_rewrite(t_h, depth, height, c["idx"], new, sigs_) + wit_[-3:]
    expect_fail(lambda: run_plan(old, new, mutate=hide), f"mid: {name} presents an occupied position as empty")
    if exit_consent:
        # rule 7: the exit key of a changed leaf must sign too
        def drop_x(wit_, sigs_, ctx_):
            wit_ = list(wit_); del wit_[wit_.index(sigs_[i_rot][1])]; return wit_
        expect_fail(lambda: run_plan(old, new, mutate=drop_x), f"mid: {name} changed leaf without the exit-key signature")

        def wrong_x(wit_, sigs_, ctx_):
            wit_ = list(wit_); wit_[wit_.index(sigs_[i_rot][1])] = sigs_[i_rot][0]; return wit_
        expect_fail(lambda: run_plan(old, new, mutate=wrong_x), f"mid: {name} exit-key signature by the owner key")
    if verbose:
        print(f"MID {name} D={depth} ({scenario}): {n} positions, {len(sigs)} owner signatures, "
              f"script {len(c['script'])} B, witness {sum(len(x) for x in wit)} B ({len(wit)} elements), "
              f"maxdepth {it.max_depth}")
    return it, c["script"], wit


def test_rewrite_amount_only(depth, height, exit_consent=False, verbose=True):
    """The amount-only new slot of the MID REWRITE_h (spec 7.9, 8.9):
    `amt_num za wa 0x03`, four elements in place of a leaf slot's eleven.
    Over test_scripts' "ao" plan (an amount raised with no signature, an
    amount lowered with the owner's, an unchanged leaf and an empty position
    left empty) it passes and saves seven elements per amount-only
    position. The rules are the ones the full slot meets: an unsigned
    decrease, a SEQ_FINAL raise without its owner, a forged amount, a
    negative or non-minimal number, a malformed pad, a missing element, any
    other flag, an amount-only slot against an empty old slot and the
    amount-only form as an old slot all fail."""
    c = rewrite_case_mid(depth, height, "ao", exit_consent)
    w, name, ctx, outputs = c["w"], c["name"], c["ctx"], c["outputs"]
    old, new, delta, witness = c["old"], c["new"], c["delta"], c["witness"]
    n = 1 << height
    tag = f"mid: {name} D={depth} amount-only"
    n_ao = sum(1 for i in range(n) if M.amount_only(old[i], new[i]))
    i_up = next(i for i in range(n) if M.amount_only(old[i], new[i]) and new[i].amount > old[i].amount)
    i_down = next(i for i in range(n) if M.amount_only(old[i], new[i]) and new[i].amount < old[i].amount)
    i_empty = next(i for i in range(n) if old[i] is None and new[i] is None)
    wit_full = c["wit"]
    wit_ao, sigs = witness(old, new, ctx, amounts=True)
    it = w.run(name, wit_ao, ctx)
    check(True, f"{tag}: the plan with {n_ao} amount-only positions passes")
    check(len(wit_full) - len(wit_ao) == 7 * n_ao, f"{tag}: seven elements saved per amount-only position")
    check(sum(len(x) for x in wit_full) - sum(len(x) for x in wit_ao) > 100 * n_ao,
          f"{tag}: over 100 witness bytes saved per amount-only position")
    check(i_up not in sigs and i_down in sigs, f"{tag}: the raise needs no signature and the decrease the owner's")

    def run(old_=None, new_=None, ctx_=None, **kw):
        old_, new_ = old_ or old, new_ or new
        ctx_ = ctx_ or ctx
        wit_, _ = witness(old_, new_, ctx_, **kw)
        return w.run(name, wit_, ctx_)
    # an unsigned decrease
    wit_nosig = list(wit_ao)
    for x in sigs[i_down]:
        del wit_nosig[wit_nosig.index(x)]
    expect_fail(lambda: w.run(name, wit_nosig, ctx), f"{tag}: unsigned decrease")
    # a forged amount: the fold and output 0 are built for another one
    forged = dict(new)
    forged[i_up] = old[i_up].with_amount_seq(old[i_up].amount + 501, old[i_up].seq)
    expect_fail(lambda: run(new_=forged, amounts=True), f"{tag}: an amount other than the one output 0 commits")
    # the slot's elements: a negative number, a non-minimal one, a malformed
    # pad, a missing element and another flag
    a = new[i_up].amount

    def slot(items):
        return {"raw_new": {i_up: items}, "amounts": True}
    neg = [b"\x00\x00\x00\x81", b"", bytes(4), M.REWRITE_AMOUNT]
    expect_fail(lambda: run(**slot(neg)), f"{tag}: a negative amount (NONNEG)")
    x = M.scriptnum(a) + b"\x00"
    nonmin = [x, bytes(4 - len(x)), bytes(len(x)), M.REWRITE_AMOUNT]
    expect_fail(lambda: run(**slot(nonmin)), f"{tag}: a non-minimal amount")
    z, wv = M.pad(a)
    expect_fail(lambda: run(**slot([M.scriptnum(a), z + b"\x01", wv, M.REWRITE_AMOUNT])),
                f"{tag}: a pad that is not zero")
    expect_fail(lambda: run(**slot([M.scriptnum(a), z, M.REWRITE_AMOUNT])), f"{tag}: a missing element")
    expect_fail(lambda: run(**slot([M.scriptnum(a), z, wv, b"\x04"])), f"{tag}: the flag 0x04")
    # an amount-only slot against an empty old slot, and as an old slot
    expect_fail(lambda: run(raw_new={i_empty: M.w_amount_slot(a)}, amounts=True),
                f"{tag}: an amount-only slot against an empty old slot")
    expect_fail(lambda: run(raw_old={i_up: M.w_amount_slot(old[i_up].amount)}, amounts=True),
                f"{tag}: an amount-only old slot")
    # a SEQ_FINAL leaf raised by one satoshi: the owner signs, or it fails
    lf = old[i_up]
    f_old, f_new = dict(old), dict(new)
    f_old[i_up] = lf.with_amount_seq(lf.amount, M.SEQ_FINAL)
    f_new[i_up] = lf.with_amount_seq(lf.amount + 1, M.SEQ_FINAL)
    cf = rewrite_case_mid(depth, height, exit_consent=exit_consent, plan=(c["base"], f_old, f_new))
    wf, ctxf = cf["w"], cf["ctx"]
    wit_f, sigs_f = cf["witness"](f_old, f_new, ctxf, amounts=True)
    wf.run(cf["name"], wit_f, ctxf)
    check(True, f"{tag}: a SEQ_FINAL raise passes with the owner's signature")
    bare = list(wit_f)
    for sig in sigs_f[i_up]:
        del bare[bare.index(sig)]
    expect_fail(lambda: wf.run(cf["name"], bare, ctxf), f"{tag}: a SEQ_FINAL raise without the owner's signature")
    # an amount-only decrease beside an exit
    x_new = dict(new)
    x_new[i_up] = None
    cx = rewrite_case_mid(depth, height, exit_consent=exit_consent, plan=(c["base"], dict(old), x_new))
    wit_x, _ = cx["witness"](dict(old), x_new, cx["ctx"], amounts=True)
    cx["w"].run(cx["name"], wit_x, cx["ctx"])
    check(True, f"{tag}: an amount-only decrease beside an exit")
    if verbose:
        print(f"MID {name} D={depth} amount-only: {n} positions, {n_ao} amount-only, witness "
              f"{sum(len(x) for x in wit_ao)} B ({len(wit_ao)} elements) against {sum(len(x) for x in wit_full)} B "
              f"({len(wit_full)}), maxdepth {it.max_depth}")
    return it


def test_voucher_topup(depth, verbose=True):
    """MID: vouchers and exit authorisations survive an amount-only
    REWRITE_h (spec 7.5, 7.2 rule 7, 7.9 rule 3), the FULL suite's
    test_voucher_topup over the seven-element leaf: the operator tops up a
    cohort with its signature alone, then a voucher and a tower
    authorisation signed before the rewrite redeem and exit against the
    topped-up leaves, the voucher for its own amount, for more than the
    balance at issuance and for the whole balance at issuance; an
    over-claim against the new balance, a payout of the old amount and a
    whole-balance voucher after a sub-dust top-up (7.5 rule 6) fail."""
    w = MidWorld(depth, False)
    w.compiled = dict(w.compiled)
    w.compiled["REWRITE_2"] = assemble(M.rewrite_script(depth, 2, w.op_pk), mode="c0")
    w.compiled["EXIT_1"] = assemble(M.exit_script(depth, 1, False, tower=True, tree_id=TREE_ID), mode="c0")
    w.m = lt.taptree_root([lt.tapleaf_hash(c, 0xc0) for c in w.compiled.values()])
    base, old, new = TS._rewrite_plan(w, 2, "topup")
    idx = base >> 2
    w.tree.leaves = {base + i: lf for i, lf in old.items()}
    w.tree.leaves[0] = mk_leaf("alice", 50_000)
    w.tree.leaves[(1 << depth) - 1] = mk_leaf("operator", 1_000_000)
    root = w.tree.root()
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
    body = M.w_rewrite(w.tree, depth, 2, idx, new, {}, True)
    w.run("REWRITE_2", body + [schnorr_sign(ctx.sighash(), w.op_sk), root[0], w.m], ctx)
    check(True, f"mid: REWRITE_2 D={depth}, the operator tops up every leaf of the cohort alone")
    w.tree = t1
    s_src = base + 3
    topped = new[3]
    check(topped.body() == src.body() and topped.amount == src.amount + 500, "mid: the top-up changed the amount and nothing else")

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
        ctx2 = TxContext([(tree.root()[1], w.spk(tree.root())), (600, P2WPKH)], [(r2[1], w.spk(r2))])
        return (list(M.pad(r2[1])) + M.w_levels(t2.path(s_c), lt.EMPTY_NODE, lf.node(), False) +
                w.pads_for(tree.root()[1]) + M.w_levels(spath, src_leaf.node(), new_src, False) +
                M.w_leaf(src_leaf) + M.w_leaf(lf) + M.w_carve_extras(src_leaf, lf, amt_new=max(amt_new, 0)) +
                [sig, tree.root()[0], w.m]), ctx2

    w.run("CLAIM", *claim_after(holder, vsig))
    check(True, "mid: CLAIM, a voucher signed before the top-up redeems against the topped-up leaf")
    bigger = carve_of(src, "bigger", src.amount + 100)
    w.run("CLAIM", *claim_after(bigger, schnorr_sign(lt.voucher_msg(TREE_ID, src, bigger), sk("c3-owner"))))
    check(True, "mid: CLAIM, after the top-up a voucher may draw more than the balance at issuance")
    whole = carve_of(src, "whole", src.amount)
    wsig = schnorr_sign(lt.voucher_msg(TREE_ID, src, whole), sk("c3-owner"))
    w.run("CLAIM", *claim_after(whole, wsig))
    check(True, "mid: CLAIM, a whole-balance voucher redeems after a top-up of at least DUST_MIN")
    over = carve_of(src, "over", topped.amount + 1)
    expect_fail(lambda: w.run("CLAIM", *claim_after(over, schnorr_sign(lt.voucher_msg(TREE_ID, src, over), sk("c3-owner")))),
                "mid: CLAIM, over-claim against the topped-up balance")
    sub = src.with_amount_seq(src.amount + 1, src.seq)
    t_sub = w.clone(); t_sub.leaves[s_src] = sub
    expect_fail(lambda: w.run("CLAIM", *claim_after(whole, wsig, tree=t_sub, src_leaf=sub)),
                "mid: CLAIM, a whole-balance voucher after a top-up below DUST_MIN (7.5 rule 6)")
    s_b = base + 1
    up1 = new[1]
    t5 = w.clone(); del t5.leaves[s_b]; r5 = t5.root()
    path_b = w.tree.path(s_b)
    below = (list(M.pad(r5[1])) + w.pads_for(r1[1]) + M.w_levels(path_b, up1.node(), lt.EMPTY_NODE, False) +
             M.w_leaf_exit(up1))
    ctx5 = w.ctx([(r5[1], w.spk(r5)), (up1.amount, lt.p2tr_spk(up1.exit_key))], (5_000, P2WPKH))
    w.run("EXIT_1", below + [auth, b"", r1[0], w.m], ctx5)
    check(True, "mid: EXIT_1^t, an authorisation signed before the top-up exits the topped-up leaf for its new amount")
    ctx6 = w.ctx([(r5[1], w.spk(r5)), (old[1].amount, lt.p2tr_spk(up1.exit_key))], (5_000, P2WPKH))
    expect_fail(lambda: w.run("EXIT_1", below + [auth, b"", r1[0], w.m], ctx6),
                "mid: EXIT_1^t, the exit after a top-up pays the amount at signing")
    if verbose:
        print(f"mid: voucher top-up D={depth}, REWRITE_2 by the operator alone, then CLAIM and EXIT_1^t on the pre-top-up signatures")


def test_exit_tower(depth, sparse, verbose=True):
    """MID EXIT_K^t (spec 7.2 rule 7): the owner branch takes an off-chain
    signature over H_exit(tree_id || leaf), checked by
    OP_CHECKSIGFROMSTACK over the leaf rejoined from its seven field
    elements, in place of a transaction signature. The FULL suite's
    scenario: a tower exits on the authorisation with its own fee input,
    rebuilds it against a new root after a competing spend, and the voucher
    tag, another tree_id, a changed leaf, a transaction signature, an empty
    element and an inexact payout all fail; the evict branch is unchanged;
    EXIT_2^t runs on two authorisations, or one and an eviction. Swapped
    into the taptree as EXIT_1 and EXIT_2, a tree-creation parameter."""
    w = MidWorld(depth, sparse)
    S = sparse
    toks = {k: M.exit_script(depth, k, sparse, tower=True, tree_id=TREE_ID) for k in (1, 2)}
    for k, t in toks.items():
        bad = {x for x in t if isinstance(x, str)} - MID_OPCODES
        check(not bad, f"MID EXIT_{k}^t: opcodes outside the MID set: {sorted(bad)}")
    check("OP_CHECKSIGFROMSTACK" in toks[1], "mid: EXIT_1^t checks the authorisation with OP_CHECKSIGFROMSTACK")
    w.compiled = dict(w.compiled)
    for k, t in toks.items():
        w.compiled[f"EXIT_{k}"] = assemble(t, mode="c0")
    w.m = lt.taptree_root([lt.tapleaf_hash(c, 0xc0) for c in w.compiled.values()])
    script = w.compiled["EXIT_1"]
    alice = mk_leaf("alice", 50_000, sparse=S)
    bob = mk_leaf("bob", 125_000, w.op_pk, 800_000, sparse=S)
    oper = mk_leaf("operator", 1_000_000, sparse=S)
    s_a, s_b, s_o = w.slot(alice, 0), w.slot(bob, 5), w.slot(oper, (1 << depth) - 1)
    base = {s_a: alice, s_b: bob, s_o: oper}
    auth = schnorr_sign(lt.exit_auth_msg(TREE_ID, bob), sk("bob-owner"))
    other_tid = lt.tree_id(lt.sha256(b"another-tree"), 0)

    def exit_tx(leaves, leaf, slot, amount=None, locktime=0):
        """The tower's exit of `leaf` from a tree holding `leaves`: the
        context (a fee input of the tower's own, the payout exact unless
        `amount` says otherwise) and the witness below the authorisation."""
        w.tree = lt.Tree(depth); w.tree.leaves = dict(leaves)
        root = w.tree.root()
        path = w.tree.path(slot)
        t1 = w.clone(); del t1.leaves[slot]; r1 = t1.root()
        pay = leaf.amount if amount is None else amount
        ctx = w.ctx([(r1[1], w.spk(r1)), (pay, lt.p2tr_spk(leaf.exit_key))], (5_000, P2WPKH), locktime=locktime)
        below = (list(M.pad(r1[1])) + w.pads_for(root[1]) + M.w_levels(path, leaf.node(), lt.EMPTY_NODE, S) +
                 w.pos(leaf) + M.w_leaf_exit(leaf))
        return ctx, below, root

    ctx, below, root = exit_tx(base, bob, s_b)
    wit = below + [auth, b"", root[0], w.m]
    it = w.run("EXIT_1", wit, ctx)
    check(True, "mid: EXIT_1^t, a tower exits the leaf on the owner's authorisation")
    sizes = (it, len(script), sum(len(x) for x in wit))
    expect_fail(lambda: w.run("EXIT_1", below + [schnorr_sign(ctx.sighash(), sk("bob-owner")), b"", root[0], w.m], ctx),
                "mid: EXIT_1^t, a transaction signature is not an authorisation")
    expect_fail(lambda: w.run("EXIT_1", below + [b"", b"", root[0], w.m], ctx), "mid: EXIT_1^t, empty authorisation")
    voucher_tagged = schnorr_sign(lt.tagged_hash(lt.TAG_VOUCHER, TREE_ID + bob.serialize()), sk("bob-owner"))
    expect_fail(lambda: w.run("EXIT_1", below + [voucher_tagged, b"", root[0], w.m], ctx),
                "mid: EXIT_1^t, an authorisation under the voucher tag")
    expect_fail(lambda: w.run("EXIT_1", below + [schnorr_sign(lt.exit_auth_msg(other_tid, bob), sk("bob-owner")), b"", root[0], w.m], ctx),
                "mid: EXIT_1^t, an authorisation for another tree_id")
    expect_fail(lambda: w.run("EXIT_1", below + [schnorr_sign(lt.exit_auth_msg(TREE_ID, bob), sk("alice-owner")), b"", root[0], w.m], ctx),
                "mid: EXIT_1^t, an authorisation by another owner")
    ctx_lo, below_lo, root_lo = exit_tx(base, bob, s_b, amount=bob.amount - 1)
    expect_fail(lambda: w.run("EXIT_1", below_lo + [auth, b"", root_lo[0], w.m], ctx_lo), "mid: EXIT_1^t, payout below the amount")
    ctx_hi, below_hi, root_hi = exit_tx(base, bob, s_b, amount=bob.amount + 1)
    expect_fail(lambda: w.run("EXIT_1", below_hi + [auth, b"", root_hi[0], w.m], ctx_hi), "mid: EXIT_1^t, payout above the amount")
    # a competing spend (alice exits) confirms first: the same authorisation against the new root
    after = dict(base); del after[s_a]
    ctx2, below2, root2 = exit_tx(after, bob, s_b)
    w.run("EXIT_1", below2 + [auth, b"", root2[0], w.m], ctx2)
    check(True, "mid: EXIT_1^t, the authorisation is rebuilt against a new root after a competing spend")
    # the leaf changed (seq advanced): the authorisation is void until re-issued
    bob2 = bob.with_amount_seq(bob.amount, 1)
    changed = dict(base); changed[s_b] = bob2
    ctx3, below3, root3 = exit_tx(changed, bob2, s_b)
    expect_fail(lambda: w.run("EXIT_1", below3 + [auth, b"", root3[0], w.m], ctx3),
                "mid: EXIT_1^t, an authorisation for the leaf before it changed")
    w.run("EXIT_1", below3 + [schnorr_sign(lt.exit_auth_msg(TREE_ID, bob2), sk("bob-owner")), b"", root3[0], w.m], ctx3)
    check(True, "mid: EXIT_1^t, a fresh authorisation over the changed leaf")
    # an amount-only top-up leaves the authorisation valid; the exit pays the new amount
    bob_up = bob.with_amount_seq(bob.amount + 500, bob.seq)
    up = dict(base); up[s_b] = bob_up
    ctx4, below4, root4 = exit_tx(up, bob_up, s_b)
    w.run("EXIT_1", below4 + [auth, b"", root4[0], w.m], ctx4)
    check(True, "mid: EXIT_1^t, the authorisation survives an amount-only top-up of the leaf")
    ctx4o, below4o, root4o = exit_tx(up, bob_up, s_b, amount=bob.amount)
    expect_fail(lambda: w.run("EXIT_1", below4o + [auth, b"", root4o[0], w.m], ctx4o),
                "mid: EXIT_1^t, the exit after a top-up pays the amount at signing")
    for label, lf in (("exit_key", lt.Leaf(bob.amount, pubkey_x(sk("other-exit")), bob.owner_key, bob.evictor_key, bob.evict_after, bob.nonce, bob.seq)),
                      ("evictor_key", lt.Leaf(bob.amount, bob.exit_key, bob.owner_key, lt.NUMS_X, bob.evict_after, bob.nonce, bob.seq)),
                      ("evict_after", lt.Leaf(bob.amount, bob.exit_key, bob.owner_key, bob.evictor_key, bob.evict_after + 1, bob.nonce, bob.seq))):
        chg = dict(base); chg[s_b] = lf
        ctx5, below5, root5 = exit_tx(chg, lf, s_b)
        expect_fail(lambda: w.run("EXIT_1", below5 + [auth, b"", root5[0], w.m], ctx5),
                    f"mid: EXIT_1^t, an authorisation for the leaf before its {label} changed")
    # the evict branch is unchanged
    ctx_e, below_e, root_e = exit_tx(base, bob, s_b, locktime=800_000)
    w.run("EXIT_1", below_e + [schnorr_sign(ctx_e.sighash(), w.op_sk), b"\x01", root_e[0], w.m], ctx_e)
    check(True, "mid: EXIT_1^t, eviction")
    expect_fail(lambda: w.run("EXIT_1", below_e + [auth, b"\x01", root_e[0], w.m], ctx_e),
                "mid: EXIT_1^t, a stack authorisation in the evict branch")
    ctx_early, below_early, root_early = exit_tx(base, bob, s_b, locktime=799_999)
    expect_fail(lambda: w.run("EXIT_1", below_early + [schnorr_sign(ctx_early.sighash(), w.op_sk), b"\x01", root_early[0], w.m], ctx_early),
                "mid: EXIT_1^t, eviction before the lease")
    # EXIT_2^t: two authorisations, then one authorisation and an eviction
    w.tree = lt.Tree(depth); w.tree.leaves = dict(base)
    root = w.tree.root()
    t7 = w.clone()
    path_a = t7.path(s_a); del t7.leaves[s_a]
    path_b = t7.path(s_b); del t7.leaves[s_b]
    r7 = t7.root()
    auth_a = schnorr_sign(lt.exit_auth_msg(TREE_ID, alice), sk("alice-owner"))
    outs = [(r7[1], w.spk(r7)), (alice.amount, lt.p2tr_spk(alice.exit_key)), (bob.amount, lt.p2tr_spk(bob.exit_key))]
    ctx7 = w.ctx(outs, (5_000, P2WPKH))
    b2 = M.w_levels(path_b, bob.node(), lt.EMPTY_NODE, S) + w.pos(bob) + M.w_leaf_exit(bob)
    b1 = (w.pads_for(root[1]) + M.w_levels(path_a, alice.node(), lt.EMPTY_NODE, S) + w.pos(alice) +
          M.w_leaf_exit(alice) + [auth_a, b""])
    w.run("EXIT_2", list(M.pad(r7[1])) + b2 + [auth, b""] + b1 + [root[0], w.m], ctx7)
    check(True, "mid: EXIT_2^t, two authorisations")
    expect_fail(lambda: w.run("EXIT_2", list(M.pad(r7[1])) + b2 + [auth_a, b""] + b1 + [root[0], w.m], ctx7),
                "mid: EXIT_2^t, alice's authorisation presented for bob")
    ctx8 = w.ctx(outs, (5_000, P2WPKH), locktime=800_000)
    w.run("EXIT_2", list(M.pad(r7[1])) + b2 + [schnorr_sign(ctx8.sighash(), w.op_sk), b"\x01"] + b1 + [root[0], w.m], ctx8)
    check(True, "mid: EXIT_2^t, one authorisation and one eviction")
    if verbose:
        plain = len(assemble(M.exit_script(depth, 1, sparse), mode="c0"))
        print(f"MID EXIT_1^t {'S' if S else 'D'} D={depth}: script {len(script)} B (EXIT_1 {plain} B), "
              f"witness {sizes[2]} B")
    return sizes


def test_claim_x(depth, sparse, hashlock=False, verbose=True):
    """MID CLAIM^x and CLAIM^hx (spec 7.5.3): CLAIM / CLAIM^h plus a
    signature over the transaction by the source leaf's exit_key, the FULL
    suite's test_claim_x over the seven-element leaf.

    The scenario is the dedicated credit leaf of 10.3: the operator owns
    the source leaf (owner_key) and the recipient holds its exit_key. The
    recipient's own redemptions carry the exit signature for free, and the
    operator cannot carve the leaf, not even with a voucher it signed to
    itself, because it does not hold the exit key. The variant is a
    tree-creation parameter, swapped into the taptree as CLAIM_X (CLAIM_HX)
    with m recomputed."""
    name = "CLAIM_HX" if hashlock else "CLAIM_X"
    w = MidWorld(depth, sparse)
    S = sparse
    toks = M.claim_script(depth, w.tree_id, sparse, hashlock=hashlock, exit_consent=True)
    bad = {t for t in toks if isinstance(t, str)} - MID_OPCODES
    check(not bad, f"MID {name}: opcodes outside the MID set: {sorted(bad)}")
    script = assemble(toks, mode="c0")
    plain = assemble(M.claim_script(depth, w.tree_id, sparse, hashlock=hashlock), mode="c0")
    check(len(script) - len(plain) == 4, f"mid: {name} is four bytes over its plain form, as UPDATE^x over UPDATE")
    w.compiled = dict(w.compiled); w.compiled[name] = script
    w.m = lt.taptree_root([lt.tapleaf_hash(c, 0xc0) for c in w.compiled.values()])
    # credit leaf: the operator is the owner (issuer), the recipient holds the exit key
    credit = lt.Leaf(1_000_000, pubkey_x(sk("recipient-exit")), w.op_pk, lt.NUMS_X, 0,
                     int.from_bytes(lt.sha256(b"credit")[:4], "little"), 0)
    while S and not M.pos_ok(credit):
        credit.nonce = (credit.nonce + 1) & 0xffffffff
    alice = mk_leaf("alice", 50_000, sparse=S)
    s_credit, s_alice = w.slot(credit, (1 << depth) - 1), w.slot(alice, 0)
    w.tree.leaves = {s_credit: credit, s_alice: alice}
    root = w.tree.root()
    preimage = lt.sha256(b"credit-preimage")
    phash = lt.sha256(preimage) if hashlock else None

    def voucher(src, claim, key=None):
        msg = (lt.voucher_msg(w.tree_id, src, claim) if phash is None
               else lt.voucher_h_msg(w.tree_id, src, claim, phash))
        return schnorr_sign(msg, key or w.op_sk)

    def head(tree, src, claim, s_src, s_claim):
        """Witness below the voucher signature for claiming `claim` out of
        `src` in `tree`, with s_claim presented as empty."""
        t = lt.Tree(depth); t.leaves = dict(tree.leaves)
        amt_new = src.amount - claim.amount
        if amt_new > 0:
            t.leaves[s_src] = src.with_amount_seq(amt_new, src.seq + 1)
        else:
            del t.leaves[s_src]
        new_src = t.leaves[s_src].node() if s_src in t.leaves else lt.EMPTY_NODE
        t.leaves[s_claim] = claim
        return (list(M.pad(t.root()[1])) + M.w_levels(t.path(s_claim), lt.EMPTY_NODE, claim.node(), S) + w.pos(claim) +
                w.pads_for(tree.root()[1]) + M.w_levels(tree.path(s_src), src.node(), new_src, S) + w.pos(src) +
                M.w_leaf(src) + M.w_leaf(claim) + M.w_carve_extras(src, claim, amt_new=max(amt_new, 0))), t

    def tail(vsig, pre=preimage):
        return [vsig] + ([pre] if hashlock and pre is not None else [])

    # the recipient redeems the cumulative voucher into its own claim leaf
    claim = carve_of(credit, "recipient", 40_000, sparse=S)
    s_claim = w.slot(claim, 3)
    h0, t1 = head(w.tree, credit, claim, s_credit, s_claim)
    r1 = t1.root()
    check(r1[1] == root[1], f"mid: {name} conserves the sum")
    ctx = w.ctx([(r1[1], w.spk(r1))], (600, P2WPKH))
    vsig = voucher(credit, claim)
    xsig = schnorr_sign(ctx.sighash(), sk("recipient-exit"))
    wit = h0 + tail(vsig) + [xsig, root[0], w.m]
    it = w.run(name, wit, ctx)
    check(True, f"mid: {name} redeemed with the voucher and the exit-key signature")

    # negatives: the exit signature
    osig = schnorr_sign(ctx.sighash(), w.op_sk)
    expect_fail(lambda: w.run(name, h0 + tail(vsig) + [osig, root[0], w.m], ctx),
                f"mid: {name} exit_sig by the wrong key (the operator, who owns the leaf)")
    expect_fail(lambda: w.run(name, h0 + tail(vsig) + [bytes(64), root[0], w.m], ctx), f"mid: {name} garbage exit_sig")
    expect_fail(lambda: w.run(name, h0 + tail(vsig) + [root[0], w.m], ctx), f"mid: {name} missing exit_sig")
    expect_fail(lambda: w.run("CLAIM", h0 + tail(vsig) + [xsig, root[0], w.m], ctx),
                f"mid: plain CLAIM with the {name} witness")
    # the voucher is still required: no voucher, or a transaction signature in its place
    expect_fail(lambda: w.run(name, h0 + ([preimage] if hashlock else []) + [xsig, root[0], w.m], ctx),
                f"mid: {name} without the voucher")
    expect_fail(lambda: w.run(name, h0 + tail(osig) + [xsig, root[0], w.m], ctx),
                f"mid: {name} with a transaction signature in place of the voucher")
    expect_fail(lambda: w.run(name, h0 + tail(voucher(credit, claim, sk("alice-owner"))) + [xsig, root[0], w.m], ctx),
                f"mid: {name} voucher by the wrong signer")
    other_tid = lt.tree_id(lt.sha256(b"creation-txid"), 1)
    expect_fail(lambda: w.run(name, h0 + [schnorr_sign(
        lt.voucher_msg(other_tid, credit, claim) if phash is None else lt.voucher_h_msg(other_tid, credit, claim, phash),
        w.op_sk)] + ([preimage] if hashlock else []) + [xsig, root[0], w.m], ctx),
        f"mid: {name} voucher signed for another tree_id")
    # over-claim
    greedy = carve_of(credit, "greedy", credit.amount + 1, sparse=S)
    s_g = w.slot(greedy, 3)
    hg, tg = head(w.tree, credit, greedy, s_credit, s_g)
    ctx_g = w.ctx([(tg.root()[1], w.spk(tg.root()))], (600, P2WPKH))
    expect_fail(lambda: w.run(name, hg + tail(voucher(credit, greedy)) +
                              [schnorr_sign(ctx_g.sighash(), sk("recipient-exit")), root[0], w.m], ctx_g),
                f"mid: {name} over-claim")
    # replay: the redeemed voucher against the advanced source
    saved = w.tree
    w.tree = t1
    credit2 = t1.leaves[s_credit]
    claim2 = carve_of(credit, "recipient2", 40_000, sparse=S)
    s_c2 = w.slot(claim2, 6)
    hr, tr = head(t1, credit2, claim, s_credit, s_c2)
    ctx_r = w.ctx([(tr.root()[1], w.spk(tr.root()))], (600, P2WPKH))
    expect_fail(lambda: w.run(name, hr + tail(vsig) + [schnorr_sign(ctx_r.sighash(), sk("recipient-exit")), r1[0], w.m], ctx_r),
                f"mid: {name} redeemed voucher replayed against the advanced source")
    w.tree = saved
    # the operator cannot drain the credit leaf: its own voucher and its own
    # transaction signature are not the exit key; the recipient's consent
    # lets the same drain through
    drain = carve_of(credit, "operator-drain", credit.amount, sparse=S)
    s_drain = w.slot(drain, 6)
    hd, td = head(w.tree, credit, drain, s_credit, s_drain)
    ctx_d = w.ctx([(td.root()[1], w.spk(td.root()))], (600, P2WPKH))
    dsig = voucher(credit, drain)
    expect_fail(lambda: w.run(name, hd + tail(dsig) + [schnorr_sign(ctx_d.sighash(), w.op_sk), root[0], w.m], ctx_d),
                f"mid: {name} the operator draining the credit leaf with a voucher to itself")
    w.run(name, hd + tail(dsig) + [schnorr_sign(ctx_d.sighash(), sk("recipient-exit")), root[0], w.m], ctx_d)
    check(True, f"mid: {name} the same drain with the recipient's exit-key signature")
    if hashlock:
        expect_fail(lambda: w.run(name, h0 + tail(vsig, lt.sha256(b"wrong")) + [xsig, root[0], w.m], ctx),
                    f"mid: {name} wrong preimage")
        expect_fail(lambda: w.run(name, h0 + tail(vsig, preimage[:31]) + [xsig, root[0], w.m], ctx),
                    f"mid: {name} preimage not 32 bytes")
        expect_fail(lambda: w.run(name, h0 + [schnorr_sign(lt.voucher_msg(w.tree_id, credit, claim), w.op_sk), preimage, xsig, root[0], w.m], ctx),
                    f"mid: {name} plain voucher under the hash lock")
    else:
        hsig = schnorr_sign(lt.voucher_h_msg(w.tree_id, credit, claim, lt.sha256(preimage)), w.op_sk)
        expect_fail(lambda: w.run(name, h0 + [hsig, preimage, xsig, root[0], w.m], ctx),
                    f"mid: {name} with a hash-locked voucher and its preimage")
    if verbose:
        print(f"MID {name} {'S' if S else 'D'} D={depth}: script {len(script)} B "
              f"(plain {len(plain)} B), witness {sum(len(x) for x in wit)} B, maxdepth {it.max_depth}")
    return it, len(script), sum(len(x) for x in wit)


def test_credit_topup(depth, verbose=True):
    """MID: the dedicated credit leaf end to end (spec 7.5.3, 7.9 rules 3
    and 7, 10.3). The tree carries UPDATE^x, CLAIM^x and REWRITE_2^x. The
    operator (owner of the credit leaf) issues cumulative vouchers to the
    recipient (its exit key), then tops the leaf up by an amount-only
    REWRITE_2^x with no signature but its own; the recipient still redeems
    the vouchers signed before the top-up with CLAIM^x, one for more than
    the balance at issuance, and the operator can redeem none of them."""
    w = MidWorld(depth, False)
    w.compiled = dict(w.compiled)
    del w.compiled["UPDATE"]                      # a tree with CLAIM^x carries UPDATE^x and REWRITE_h^x (7.9 rule 7)
    del w.compiled["CLAIM"]                       # and CLAIM^x in place of CLAIM, or the issuer could carve the leaf
    w.compiled["UPDATE_X"] = assemble(M.update_script(depth, w.op_pk, False, exit_consent=True), mode="c0")
    w.compiled["CLAIM_X"] = assemble(M.claim_script(depth, TREE_ID, False, exit_consent=True), mode="c0")
    w.compiled["REWRITE_X_2"] = assemble(M.rewrite_script(depth, 2, w.op_pk, exit_consent=True), mode="c0")
    w.m = lt.taptree_root([lt.tapleaf_hash(c, 0xc0) for c in w.compiled.values()])
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
    s_credit = base
    # two cumulative vouchers, the second for more than the leaf holds now
    v1 = carve_of(credit, "holder1", 4_000)
    v2 = carve_of(credit, "holder2", 10_100)
    sig1 = schnorr_sign(lt.voucher_msg(TREE_ID, credit, v1), w.op_sk)
    sig2 = schnorr_sign(lt.voucher_msg(TREE_ID, credit, v2), w.op_sk)
    # the top-up: amount only, every other position unchanged, no owner or exit signatures
    topped = credit.with_amount_seq(credit.amount + 500, credit.seq)
    new = {0: topped, 1: old[1], 2: old[2], 3: old[3]}
    t1 = w.clone(); t1.leaves[s_credit] = topped; r1 = t1.root()
    ctx = w.ctx([(r1[1], w.spk(r1))], (500 + 5_000, P2WPKH))
    body = M.w_rewrite(w.tree, depth, 2, idx, new, {}, True)
    w.run("REWRITE_X_2", body + [schnorr_sign(ctx.sighash(), w.op_sk), root[0], w.m], ctx)
    check(True, f"mid: REWRITE_2^x D={depth}, the operator tops up the credit leaf with its signature alone")
    # a top-up that also rotates the exit key needs the recipient
    rotated = lt.Leaf(topped.amount, pubkey_x(sk("operator-exit")), credit.owner_key, credit.evictor_key,
                      credit.evict_after, credit.nonce, credit.seq)
    t_r = w.clone(); t_r.leaves[s_credit] = rotated; r_r = t_r.root()
    ctx_r = w.ctx([(r_r[1], w.spk(r_r))], (500 + 5_000, P2WPKH))
    new_r = dict(new); new_r[0] = rotated
    expect_fail(lambda: w.run("REWRITE_X_2", M.w_rewrite(w.tree, depth, 2, idx, new_r, {0: [schnorr_sign(ctx_r.sighash(), w.op_sk)]}, True) +
                              [schnorr_sign(ctx_r.sighash(), w.op_sk), root[0], w.m], ctx_r),
                "mid: REWRITE_2^x, the operator cannot move the credit leaf's exit key without the recipient")
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
        wit = (list(M.pad(r2[1])) + M.w_levels(t2.path(s_c), lt.EMPTY_NODE, lf.node(), False) +
               w.pads_for(w.tree.root()[1]) + M.w_levels(w.tree.path(s_credit), src.node(), new_src, False) +
               M.w_leaf(src) + M.w_leaf(lf) + M.w_carve_extras(src, lf, amt_new=amt_new) +
               [vsig, schnorr_sign(ctx2.sighash(), xkey), w.tree.root()[0], w.m])
        return wit, ctx2, t2

    expect_fail(lambda: w.run("CLAIM_X", *claim_x(v1, sig1, w.op_sk)[:2]),
                "mid: CLAIM^x, the operator cannot redeem its own voucher against the credit leaf")
    wit, ctx2, t2 = claim_x(v2, sig2, sk("recipient-exit"))
    expect_fail(lambda: w.run("CLAIM_X", wit[:-3] + wit[-2:], ctx2), "mid: CLAIM^x without the recipient's signature")
    w.run("CLAIM_X", wit, ctx2)
    check(True, "mid: CLAIM^x, the recipient redeems the latest cumulative voucher, signed before the top-up, "
                "for more than the balance at issuance")
    # the earlier cumulative voucher is superseded: the source's seq has advanced
    w.tree = t2
    expect_fail(lambda: w.run("CLAIM_X", *claim_x(v1, sig1, sk("recipient-exit"), src=t2.leaves[s_credit], s_c=3)[:2]),
                "mid: CLAIM^x, the earlier cumulative voucher is void once the later one has redeemed")
    if verbose:
        print(f"mid: credit leaf D={depth}: REWRITE_2^x top-up by the operator alone, then CLAIM^x by the recipient on the pre-top-up vouchers")


def test_detach(depth, height, verbose=True):
    """MID DETACH_h (spec 7.10), the FULL and CCV suites' detach over MID
    numerics: the detach succeeds and conserves the total across the two
    tree outputs, a member's old path truncated to its lower h levels is
    the detached tree's own path, an EXIT_1 from the detached tree succeeds
    with it, and a voucher issued in the parent redeems in the child, which
    inherits tree_id. 7.10 rule 3: the parent is created with CLAIM and
    UPDATE^x on top of the reference set, so m_h is that option set at
    depth h and differs from the reference set's, under which the detach
    fails. Negatives: output 1 under the reference set's m_h, under the
    parent's own taptree, under the CCV key, under the m_h of a tree with
    another tree_id, shortchanged or overfunded, a missing operator
    signature, output 0 keeping the subtree, an inflated subtree sum, the
    two tree outputs swapped, a malformed sum pad, a 31-byte R_h and a
    forged path over a non-empty subtree."""
    name = f"DETACH_{height}"
    tag = f"mid: {name} D={depth}"
    w = MidWorld(depth, False)
    opts = M.TreeOptions(w.op_pk, TREE_ID, join_heights=(0, 2), exit_ks=(1, 2), claim=True, update_x=True,
                         detach_heights=(height,))
    w.scripts = opts.at_depth(depth)
    for nm, toks in w.scripts.items():
        bad = {t for t in toks if isinstance(t, str)} - MID_OPCODES
        check(not bad, f"{tag}: {nm} opcodes outside the MID set: {sorted(bad)}")
    w.compiled = {k: assemble(v, mode="c0") for k, v in w.scripts.items()}
    w.m = lt.taptree_root([lt.tapleaf_hash(c, 0xc0) for c in w.compiled.values()])
    check(name in w.compiled and "CLAIM" in w.compiled and "UPDATE_X" in w.compiled,
          f"{tag}: the parent's option set carries DETACH_h, CLAIM and UPDATE^x")
    m_h = opts.taptree_root(height)
    ref_m_h = M.detached_taptree_root(height, w.op_pk, TREE_ID)
    check(m_h != ref_m_h, f"{tag}: m_h from the parent's options differs from the reference set's m_h")
    check(M.detached_taptree_root(height, w.op_pk, TREE_ID, opts) == m_h,
          f"{tag}: detached_taptree_root with the parent's options is the parent's set at depth h")
    other_tid = lt.tree_id(lt.sha256(b"creation-txid"), 1)
    m_h_other = M.TreeOptions(w.op_pk, other_tid, join_heights=(0, 2), exit_ks=(1, 2), claim=True, update_x=True,
                              detach_heights=(height,)).taptree_root(height)
    check(m_h_other != m_h, f"{tag}: a child under another tree_id has another m_h (CLAIM carries the constant)")
    n, base = 1 << height, 1 << height
    cohort = {base + i: mk_leaf(f"c{i}", 10_000 + 7 * i, w.op_pk, 800_000) for i in range(n) if i % 5 != 3}
    w.tree.leaves = dict(cohort)
    w.tree.leaves[0] = mk_leaf("alice", 50_000)
    w.tree.leaves[(1 << depth) - 1] = mk_leaf("operator", 1_000_000)
    root = w.tree.root()
    node = w.tree.subtree(height, 1)                      # (R_h, sum_h)
    t1 = w.clone()
    for p_ in cohort:
        del t1.leaves[p_]
    r1 = t1.root()
    spk1 = lt.tree_spk(node[0], m_h)

    def run(outs, extra=5_000, signer=None, nd=None, mutate=None, tree=None):
        tree = tree or w.tree
        ctx = w.ctx(outs, (extra, P2WPKH))
        wit = M.w_detach(tree, depth, height, 1, node=nd)
        if mutate:
            wit = mutate(wit)
        return w.run(name, wit + [schnorr_sign(ctx.sighash(), signer or w.op_sk), root[0], w.m], ctx)
    outputs = [(r1[1], w.spk(r1)), (node[1], spk1), (400, P2WPKH)]
    it = run(outputs)
    check(True, f"{tag} detaches {len(cohort)} leaves into their own tree output")
    check(r1[1] + node[1] == root[1], f"{tag} conserves the total across two tree outputs")
    # negatives
    expect_fail(lambda: run([outputs[0], (node[1], lt.tree_spk(node[0], ref_m_h)), outputs[2]]),
                f"{tag} output 1 under an m_h that drops the parent's options")
    expect_fail(lambda: run([outputs[0], (node[1], lt.tree_spk(node[0], w.m)), outputs[2]]),
                f"{tag} output 1 under the parent's own taptree")
    expect_fail(lambda: run([outputs[0], (node[1], lt.tree_spk_ccv(node[0], m_h)), outputs[2]]),
                f"{tag} output 1 under the CCV-tier key")
    expect_fail(lambda: run([outputs[0], (node[1], lt.tree_spk(node[0], m_h_other)), outputs[2]]),
                f"{tag} output 1 under the m_h of a child that does not inherit tree_id")
    expect_fail(lambda: run([outputs[0], (node[1] - 1, spk1), outputs[2]]), f"{tag} output 1 shortchanged")
    expect_fail(lambda: run([outputs[0], (node[1] + 1, spk1), outputs[2]], extra=6_000), f"{tag} output 1 overfunded")
    expect_fail(lambda: run(outputs, signer=sk("alice-owner")), f"{tag} without the operator signature")
    expect_fail(lambda: run([(root[1], w.spk(root)), (node[1], spk1), outputs[2]], extra=node[1] + 5_000),
                f"{tag} subtree not emptied in output 0 (new node not E_h)")
    expect_fail(lambda: run([(r1[1] + 1, w.spk(r1)), (node[1], spk1), outputs[2]], extra=6_000),
                f"{tag} the host remainder off by one")
    expect_fail(lambda: run([outputs[0], (node[1] + 1, spk1), outputs[2]], extra=6_000, nd=(node[0], node[1] + 1)),
                f"{tag} inflated subtree sum")
    expect_fail(lambda: run([outputs[1], outputs[0], outputs[2]]), f"{tag} the two tree outputs swapped")

    def swap_pad(wit):
        b = list(wit); b[-2], b[-1] = b[-2] + b"\x00", b[-1][1:]
        return b
    expect_fail(lambda: run(outputs, mutate=swap_pad), f"{tag} malformed sum pad")

    def short_root(wit):
        b = list(wit); b[-4] = b[-4][:31]
        return b
    expect_fail(lambda: run(outputs, mutate=short_root), f"{tag} a 31-byte R_h")
    # Same amount, different key: the sums still fold to the input amount,
    # so only the root-hash compare can reject it.
    forged = w.clone(); forged.leaves[0] = mk_leaf("mallory", 50_000)
    expect_fail(lambda: run(outputs, tree=forged), f"{tag} a forged path over the non-empty subtree")

    # the detached tree: the same options at depth h
    w2 = MidWorld(height, False)
    w2.scripts = opts.at_depth(height)
    w2.compiled = {k: assemble(v, mode="c0") for k, v in w2.scripts.items()}
    w2.m = lt.taptree_root([lt.tapleaf_hash(c, 0xc0) for c in w2.compiled.values()])
    check(w2.m == m_h, f"{tag}: the detached tree's identifier is the parent's options compiled at depth h")
    check(list(w2.compiled) == ["EXIT_1", "EXIT_2", "JOIN_0", "JOIN_2", "JOINK_2", "UPDATE_X", "CLAIM"],
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
                     [(r2[1], w2.spk(r2)), (lf.amount, lt.p2tr_spk(lf.exit_key))])
    sig2 = schnorr_sign(ctx2.sighash(), sk(f"c{victim - base}-owner"))
    it2 = w2.run("EXIT_1", list(M.pad(r2[1])) + list(M.pad(node[1])) + M.w_levels(short, lf.node(), lt.EMPTY_NODE, False) +
                 M.w_leaf_exit(lf) + [sig2, b"", node[0], m_h], ctx2)
    check(True, f"{tag}: EXIT_1 from the detached depth-{height} tree with the truncated path")
    # a voucher issued while the source leaf sat in the parent redeems in
    # the detached tree: it inherits tree_id (7.10 rule 3) and its CLAIM
    # carries the same constant, so no reissue after a detach (9.6)
    issuer = max(cohort)
    src = cohort[issuer]
    holder = mk_leaf("holder", 3_000, w.op_pk, 800_000)
    vsig = schnorr_sign(lt.voucher_msg(TREE_ID, src, holder), sk(f"c{issuer - base}-owner"))
    s_holder = next(i for i in range(n) if i not in w2.tree.leaves)
    t3 = w2.clone(); lt.apply_claim(t3, issuer - base, s_holder, holder); r3 = t3.root()
    ctx3 = TxContext([(node[1], spk1), (600, P2WPKH)], [(r3[1], w2.spk(r3))])
    w2.run("CLAIM", list(M.pad(r3[1])) + M.w_levels(t3.path(s_holder), lt.EMPTY_NODE, holder.node(), False) +
           list(M.pad(node[1])) + M.w_levels(w2.tree.path(issuer - base), src.node(), t3.leaves[issuer - base].node(), False) +
           M.w_leaf(src) + M.w_leaf(holder) + M.w_carve_extras(src, holder) + [vsig, node[0], m_h], ctx3)
    check(True, f"{tag}: a voucher issued in the parent redeems in the detached tree")
    wit = M.w_detach(w.tree, depth, height, 1) + [bytes(64), root[0], w.m]
    if verbose:
        print(f"MID {name} D={depth}: script {len(w.compiled[name])} B, witness {sum(len(x) for x in wit)} B, "
              f"{len(wit)} elements, maxdepth {it.max_depth}; EXIT_1 from the detached tree: "
              f"script {len(w2.compiled['EXIT_1'])} B, maxdepth {it2.max_depth}")
    return it, len(w.compiled[name]), sum(len(x) for x in wit)


RECLAIM_SK = sk("operator-reclaim")


class PendingMidWorld:
    """A MID tree carrying the pending-leaf receive (design/pending-receive.md),
    as test_scripts.PendingWorld is for FULL: RECLAIM_KEY, RECLAIM_1,
    CLAIM^m, CLAIM^hm, CLAIM^x and the reclaim-form REWRITE_h^x at heights 1
    and 2, beside UPDATE^x and EXIT_1. Dense unless sparse, where only
    RECLAIM_1 of the receive applies."""

    def __init__(self, depth, sparse=False):
        self.depth = depth
        self.rk = pubkey_x(RECLAIM_SK)
        self.w = MidWorld(depth, sparse)
        op_pk = self.w.op_pk
        self.opts = M.TreeOptions(op_pk, TREE_ID, sparse=sparse, exit_ks=(1,), update_x=True, claim=False,
                                  claim_x=True, rewrite_heights=(1, 2), rewrite_x=True,
                                  reclaim_key=self.rk, claim_m=True, claim_hm=True)
        scripts = self.opts.at_depth(depth)
        for name, toks in scripts.items():
            bad = {t for t in toks if isinstance(t, str)} - MID_OPCODES
            check(not bad, f"MID {name}: opcodes outside the MID set: {sorted(bad)}")
        self.w.scripts = scripts
        self.w.compiled = {k: assemble(v, mode="c0") for k, v in scripts.items()}
        self.w.m = self.opts.taptree_root(depth)
        self.rcpt = pubkey_x(sk("rcpt-exit"))
        self.sparse = sparse

    def _nonce(self, label):
        return int.from_bytes(lt.sha256(label.encode())[:4], "little")

    def _grind(self, lf):
        while self.sparse and not M.pos_ok(lf, self.depth):
            lf.nonce = (lf.nonce + 1) & 0xffffffff
        return lf

    def pending(self, amount, deadline, label="P", seq=0):
        """P: owned by the operator, paid to the recipient, reclaimable at `deadline`."""
        return self._grind(lt.Leaf(amount, self.rcpt, pubkey_x(sk("operator-owner")), self.rk, deadline,
                                   self._nonce(label), seq))

    def landing(self, amount, label="L", lease=900_000, owner=None, evictor=None, seq=0):
        """L: owned and exited by the recipient, evictable by the operator after a long lease."""
        return self._grind(lt.Leaf(amount, self.rcpt, owner or self.rcpt, evictor or self.w.op_pk, lease,
                                   self._nonce(label), seq))


def _merge_case_mid(pw, s_slot, t_slot, P, L, X, preimage=None, signer="operator-owner", flag=None,
                    tree_id=TREE_ID, msg_target=None, msg_x=None, mutate=None):
    """A MID CLAIM^m (or CLAIM^hm with a preimage) redemption against the
    pair, as test_scripts._merge_case: returns (witness, ctx, new tree)."""
    w = pw.w
    w.tree.leaves = {s_slot: P, t_slot: L, 0: mk_leaf("alice", 50_000)}
    root = w.tree.root()
    t1 = w.clone()
    try:
        lt.apply_merge(t1, s_slot, t_slot, X)
    except AssertionError:
        # an invalid merge, for a negative: the tree the transaction claims
        d = X - L.amount
        t1.leaves[t_slot] = L.with_amount_seq(X, L.seq)
        if P.amount - d > 0:
            t1.leaves[s_slot] = P.with_amount_seq(P.amount - d, P.seq)
        else:
            t1.leaves.pop(s_slot, None)
    r1 = t1.root()
    ctx = w.ctx([(r1[1], w.spk(r1))], (600, P2WPKH))
    ph = lt.sha256(preimage) if preimage is not None else None
    msg = lt.voucher_m_msg(tree_id, P, msg_target or L, msg_x if msg_x is not None else X, ph)
    body = M.w_merge(w.tree, pw.depth, s_slot, t_slot, X, t1)
    if flag is not None:
        body[len(body) - 26] = flag
    if mutate:
        body = mutate(body)
    wit = body + [schnorr_sign(msg, sk(signer))]
    if preimage is not None:
        wit.append(preimage)
    return wit + [root[0], w.m], ctx, t1


def test_merge_mid(depth, verbose=True):
    """MID CLAIM^m and CLAIM^hm (7.5.4), mirroring test_scripts.test_merge."""
    pw = PendingMidWorld(depth)
    w = pw.w
    pre = lt.sha256(b"receive-preimage")
    P = pw.pending(20_000, 700_000)
    L = pw.landing(10_000)
    wit, ctx, t1 = _merge_case_mid(pw, 2, 3, P, L, 13_000, pre)
    it = w.run("CLAIM_HM", wit, ctx)
    check(t1.leaves[3].amount == 13_000 and t1.leaves[2].amount == 17_000 and t1.leaves[2].seq == P.seq,
          "mid: CLAIM^hm target raised to X, source lowered by the difference, source seq unchanged")
    hm_size, hm_wit = len(w.compiled["CLAIM_HM"]), sum(len(x) for x in wit)
    w.run("CLAIM_HM", *_merge_case_mid(pw, 5, 4, P, L, 13_000, pre)[:2])
    check(True, "mid: CLAIM^hm with the source on the right of the pair")
    w.run("CLAIM_M", *_merge_case_mid(pw, 2, 3, P, L, 12_500)[:2])
    check(True, "mid: CLAIM^m raises the target with no preimage")
    m_size = len(w.compiled["CLAIM_M"])
    _, _, t_d = _merge_case_mid(pw, 2, 3, P, L, 30_000)
    w.run("CLAIM_M", *_merge_case_mid(pw, 2, 3, P, L, 30_000)[:2])
    check(2 not in t_d.leaves, "mid: CLAIM^m draining the source leaves E_0")
    w.run("CLAIM_M", *_merge_case_mid(pw, 2, 3, P, L, 30_000 - lt.DUST_MIN)[:2])
    check(True, "mid: CLAIM^m leaving exactly DUST_MIN in the source")

    # replay and ordering: target levels are absolute
    raised = L.with_amount_seq(13_000, L.seq)
    lowered = P.with_amount_seq(17_000, P.seq)
    expect_fail(lambda: w.run("CLAIM_HM", *_merge_case_mid(pw, 2, 3, lowered, raised, 13_000, pre)[:2]),
                "mid: CLAIM^hm replayed after the target reached X")
    expect_fail(lambda: w.run("CLAIM_HM", *_merge_case_mid(pw, 2, 3, lowered, raised, 11_000, pre)[:2]),
                "mid: CLAIM^hm older, smaller target after a larger one")
    w.run("CLAIM_HM", *_merge_case_mid(pw, 2, 3, P.with_amount_seq(19_000, 0),
                                       L.with_amount_seq(11_000, 0), 13_000, pre)[:2])
    check(True, "mid: CLAIM^hm newer target after an older one moves only the difference")

    # negatives, one per rule
    expect_fail(lambda: w.run("CLAIM_HM", wit[:-3] + [lt.sha256(b"x")] + wit[-2:], ctx),
                "mid: CLAIM^hm wrong preimage")
    expect_fail(lambda: w.run("CLAIM_HM", wit[:-3] + [pre[:31]] + wit[-2:], ctx),
                "mid: CLAIM^hm preimage not 32 bytes")
    expect_fail(lambda: w.run("CLAIM_HM", *_merge_case_mid(pw, 2, 3, P, L, 13_000, pre, signer="rcpt-exit")[:2]),
                "mid: CLAIM^hm voucher not by the source owner")
    expect_fail(lambda: w.run("CLAIM_M", *_merge_case_mid(pw, 2, 3, P, L, 13_000, tree_id=w.m)[:2]),
                "mid: CLAIM^m voucher over m instead of tree_id")
    plain = _merge_case_mid(pw, 2, 3, P, L, 13_000)[0]
    expect_fail(lambda: w.run("CLAIM_HM", plain[:-2] + [pre] + plain[-2:], ctx),
                "mid: CLAIM^hm with a plain merge voucher")
    expect_fail(lambda: w.run("CLAIM_M", wit[:-3] + wit[-2:], ctx),
                "mid: CLAIM^m with a hash-locked merge voucher")
    carve_sig = schnorr_sign(lt.voucher_msg(TREE_ID, P, L), sk("operator-owner"))
    expect_fail(lambda: w.run("CLAIM_M", plain[:-3] + [carve_sig] + plain[-2:], ctx),
                "mid: CLAIM^m with a carve voucher over the same pair")
    stranger = pw.landing(10_000, owner=pubkey_x(sk("operator-owner")))
    expect_fail(lambda: w.run("CLAIM_M", *_merge_case_mid(pw, 2, 3, P, stranger, 13_000)[:2]),
                "mid: CLAIM^m into a sibling the source's exit key does not own")
    elsewhere = lt.Leaf(10_000, pubkey_x(sk("mallory-exit")), pw.rcpt, pw.w.op_pk, 900_000, pw._nonce("L"), 0)
    expect_fail(lambda: w.run("CLAIM_M", *_merge_case_mid(pw, 2, 3, P, elsewhere, 13_000)[:2]),
                "mid: CLAIM^m into a sibling owned by the source's exit key but exiting to another key")
    flagged = pw.landing(10_000, evictor=pw.rk)
    expect_fail(lambda: w.run("CLAIM_M", *_merge_case_mid(pw, 2, 3, P, flagged, 13_000)[:2]),
                "mid: CLAIM^m into a reclaimable target")
    final_t = pw.landing(10_000, seq=M.SEQ_FINAL)
    expect_fail(lambda: w.run("CLAIM_M", *_merge_case_mid(pw, 2, 3, P, final_t, 13_000)[:2]),
                "mid: CLAIM^m into a SEQ_FINAL (0x7FFFFFFF) target")
    final_s = pw.pending(20_000, 700_000, seq=M.SEQ_FINAL)
    expect_fail(lambda: w.run("CLAIM_M", *_merge_case_mid(pw, 2, 3, final_s, L, 13_000)[:2]),
                "mid: CLAIM^m from a SEQ_FINAL (0x7FFFFFFF) source")
    full_final = pw.landing(10_000, seq=0xFFFFFFFF)
    w.run("CLAIM_M", *_merge_case_mid(pw, 2, 3, P, full_final, 13_000)[:2])
    check(True, "mid: a target seq of 0xFFFFFFFF is not MID's SEQ_FINAL: the merge applies")
    expect_fail(lambda: w.run("CLAIM_M", *_merge_case_mid(pw, 2, 3, P, L, 10_000)[:2]),
                "mid: CLAIM^m with X not above the target's amount")
    expect_fail(lambda: w.run("CLAIM_M", *_merge_case_mid(pw, 2, 3, P, L, 30_001)[:2]),
                "mid: CLAIM^m drawing more than the source holds")
    expect_fail(lambda: w.run("CLAIM_M", *_merge_case_mid(pw, 2, 3, P, L, 29_800)[:2]),
                "mid: CLAIM^m leaving a sub-dust residual")
    expect_fail(lambda: w.run("CLAIM_M", *_merge_case_mid(pw, 2, 3, P, L, 13_000, flag=b"")[:2]),
                "mid: CLAIM^m with the source flag pointing at the target")
    expect_fail(lambda: w.run("CLAIM_M", *_merge_case_mid(pw, 2, 3, P, L, 13_000, msg_x=14_000)[:2]),
                "mid: CLAIM^m with X other than the signed target")
    expect_fail(lambda: w.run("CLAIM_M", *_merge_case_mid(pw, 2, 3, P, L, 13_000, msg_target=pw.landing(10_000, label="L-other"))[:2]),
                "mid: CLAIM^m with a voucher naming another target body")
    # MID numerics: X and the residual arrive as numbers with PADZ pads

    def bad_x_pad(b):
        b = list(b); i = len(b) - 20 - 2            # zx
        b[i], b[i + 1] = b[i] + b"\x00", b[i + 1][1:]
        return b
    expect_fail(lambda: w.run("CLAIM_M", *_merge_case_mid(pw, 2, 3, P, L, 13_000, mutate=bad_x_pad)[:2]),
                "mid: CLAIM^m with a malformed pad for X")

    def neg_x(b):
        b = list(b); i = len(b) - 20 - 3            # xn: a minimal four-byte negative number, no pad
        b[i], b[i + 1], b[i + 2] = NEG_X.to_bytes(4, "little"), b"", bytes(4)
        return b
    # the voucher signs le64 of the same four bytes, so only the sign of X fails
    NEG_X = 0x810032C8
    expect_fail(lambda: w.run("CLAIM_M", *_merge_case_mid(pw, 2, 3, P, L, 13_000, mutate=neg_x, msg_x=NEG_X)[:2]),
                "mid: CLAIM^m with X a negative number")

    def bad_res_pad(b):
        b = list(b); i = len(b) - 20 - 5            # zr
        b[i], b[i + 1] = b[i][1:], b[i + 1] + b"\x00"
        return b
    expect_fail(lambda: w.run("CLAIM_M", *_merge_case_mid(pw, 2, 3, P, L, 13_000, mutate=bad_res_pad)[:2]),
                "mid: CLAIM^m with a malformed pad for the residual")

    def bad_amt(b):
        b = list(b); i = len(b) - 3                 # T.amt_num
        b[i] = M.scriptnum(L.amount + 256)
        return b
    expect_fail(lambda: w.run("CLAIM_M", *_merge_case_mid(pw, 2, 3, P, L, 13_000, mutate=bad_amt)[:2]),
                "mid: CLAIM^m with the target's amount field and number disagreeing")
    wit_o, _, t_o = _merge_case_mid(pw, 2, 3, P, L, 13_000)
    r_o = t_o.root()
    expect_fail(lambda: w.run("CLAIM_M", wit_o, w.ctx([(r_o[1] - 1, w.spk(r_o))], (600, P2WPKH))),
                "mid: CLAIM^m with output 0 short")
    expect_fail(lambda: w.run("CLAIM_M", wit_o[:-1] + [lt.sha256(b"evil")], w.ctx([(r_o[1], w.spk(r_o))], (600, P2WPKH))),
                "mid: CLAIM^m with a wrong m")

    # the exact-fit funding hole and the DUST_MIN headroom that closes it
    tight = pw.pending(3_000, 700_000)
    w.run("CLAIM_HM", *_merge_case_mid(pw, 2, 3, tight, L, 13_000, pre)[:2])
    check(True, "mid: CLAIM^hm draining an exactly funded pending leaf")
    expect_fail(lambda: w.run("CLAIM_HM", *_merge_case_mid(pw, 2, 3, tight.with_amount_seq(3_001, 0), L, 13_000, pre)[:2]),
                "mid: CLAIM^hm blocked by a one-satoshi top-up of an exactly funded pending leaf")
    roomy = pw.pending(3_000 + lt.DUST_MIN, 700_000)
    for extra in (0, 1, 50_000):
        w.run("CLAIM_HM", *_merge_case_mid(pw, 2, 3, roomy.with_amount_seq(roomy.amount + extra, 0), L, 13_000, pre)[:2])
    check(True, "mid: CLAIM^hm with DUST_MIN of headroom redeems after any top-up")
    if verbose:
        print(f"MID CLAIM^m D={depth}: script {m_size} B; CLAIM^hm script {hm_size} B, witness {hm_wit} B "
              f"({len(wit)} elements), maxdepth {it.max_depth}")
    return hm_size, hm_wit


def test_reclaim_mid(depth, sparse=False, verbose=True):
    """MID RECLAIM_1 (7.11), mirroring test_scripts.test_reclaim."""
    pw = PendingMidWorld(depth, sparse)
    w = pw.w
    S = sparse
    P = pw.pending(20_000, 700_000)
    Lf = pw.landing(10_000)
    alice = mk_leaf("alice", 50_000, sparse=S)
    sp, sl, sa = w.slot(P, 2), w.slot(Lf, 3), w.slot(alice, 0)
    w.tree.leaves = {sp: P, sl: Lf, sa: alice}

    def spend(leaf=P, locktime=700_000, signer=RECLAIM_SK, out0=None, ea=None):
        slot = next(k for k, v in w.tree.leaves.items() if v is leaf)
        root = w.tree.root()
        t = w.clone(); del t.leaves[slot]
        rn = t.root()
        ctx = TxContext([(root[1], w.spk(root)), (600, P2WPKH)],
                        [(out0 if out0 is not None else rn[1], w.spk(rn)), (20_000, P2WPKH)], locktime=locktime)
        sig = schnorr_sign(ctx.sighash(), signer)
        items = M.w_leaf_exit(leaf)
        if ea is not None:
            items = items[:-3] + list(ea)
        wit = (list(M.pad(rn[1])) + w.pads_for(root[1]) +
               M.w_levels(w.tree.path(slot), leaf.node(), lt.EMPTY_NODE, S) + w.pos(leaf) +
               items + [sig, root[0], w.m])
        return w.run("RECLAIM_1", wit, ctx), wit
    it, wit = spend()
    check(True, f"mid: RECLAIM_1 {'S' if S else 'D'} after the deadline, value free for the transaction")
    expect_fail(lambda: spend(locktime=699_999), "mid: RECLAIM_1 before the deadline")
    expect_fail(lambda: spend(signer=sk("operator")), "mid: RECLAIM_1 signed by OPERATOR_KEY, not RECLAIM_KEY")
    expect_fail(lambda: spend(out0=w.clone().root()[1] - P.amount - 1), "mid: RECLAIM_1 with output 0 short")
    # the lock-time number must match the leaf's field: an earlier number
    # with the field's pad, and the field's number with a malformed pad
    expect_fail(lambda: spend(locktime=600_000, ea=(M.scriptnum(600_000),) + M.pad(600_000)),
                "mid: RECLAIM_1 with an evict_after number below the leaf's field")
    z, wpad = M.pad(700_000)
    expect_fail(lambda: spend(ea=(M.scriptnum(700_000), z + b"\x00", wpad[1:])),
                "mid: RECLAIM_1 with a malformed evict_after pad")
    plain = mk_leaf("bob", 20_000, w.op_pk, 600_000, sparse=S)
    w.tree.leaves[w.slot(plain, 6)] = plain
    expect_fail(lambda: spend(leaf=plain, locktime=700_000), "mid: RECLAIM_1 of a leaf whose evictor is not RECLAIM_KEY")
    del w.tree.leaves[w.slot(plain, 6)]
    expect_fail(lambda: spend(leaf=Lf, locktime=900_000), "mid: RECLAIM_1 of the landing leaf")
    if verbose:
        print(f"MID RECLAIM_1 {'S' if S else 'D'} D={depth}: script {len(w.compiled['RECLAIM_1'])} B, "
              f"witness {sum(len(x) for x in wit)} B ({len(wit)} elements), maxdepth {it.max_depth}")
    return len(w.compiled["RECLAIM_1"]), sum(len(x) for x in wit)


def _pending_rewrite_mid(pw, name, base, height, old, new, locktime=0, sign=(), reclaim=(), mutate=None,
                         extra=None, amounts=False):
    """Run a MID REWRITE_R_h / REWRITE_XR_h over positions base..base+2^h-1,
    as test_scripts._pending_rewrite. `sign` lists the offsets that carry
    an owner signature by operator-owner (and under ^x an exit-key one by
    rcpt-exit), or maps them to the owner's key label; `reclaim` the
    offsets that carry the R1 items (w_reclaim of the old leaf); `extra`
    puts further leaves in the tree outside the subtree; amounts writes a
    new leaf that differs from its old one in the amount alone as the
    amount-only slot. Returns (interp, witness)."""
    w = pw.w
    n = 1 << height
    leaves = {base + i: lf for i, lf in old.items() if lf}
    leaves[0] = mk_leaf("alice", 50_000)
    leaves.update(extra or {})
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
    ctx = TxContext([(root[1], w.spk(root)), (5_000 + max(-freed, 0), P2WPKH)],
                    [(r1[1], w.spk(r1)), (max(freed, 0) + 1_000, P2WPKH)], locktime=locktime)
    items = {}
    for i in range(n):
        if i in sign:
            items[i] = [schnorr_sign(ctx.sighash(), sk(sign[i] if isinstance(sign, dict) else "operator-owner"))]
            if "X" in name:
                items[i].append(schnorr_sign(ctx.sighash(), sk("rcpt-exit")))
        elif i in reclaim:
            items[i] = M.w_reclaim(old[i])
    wit = M.w_rewrite(w.tree, pw.depth, height, base >> height, {i: new[i] for i in range(n)}, items,
                      amounts=amounts)
    wit += [schnorr_sign(ctx.sighash(), w.op_sk), root[0], w.m]
    if mutate:
        wit = mutate(wit)
    return w.run(name, wit, ctx), wit


def test_pending_rewrite_mid(depth, verbose=True):
    """The MID reclaim-form rewrite (7.9 rule 8), mirroring
    test_scripts.test_pending_rewrite: a non-interactive settlement (R3),
    a reclaim and roll after the deadline (R1), and the negatives that keep
    both away from every other leaf."""
    pw = PendingMidWorld(depth)
    T = 700_000
    P, L = pw.pending(20_000, T), pw.landing(10_000)
    run = _pending_rewrite_mid
    for name in ("REWRITE_R_1", "REWRITE_XR_1"):
        run(pw, name, 2, 1, {0: P, 1: L}, {0: P.with_amount_seq(13_000, 0), 1: L.with_amount_seq(17_000, 0)})
        check(True, f"mid: {name} R3 transfer P -> L, operator only, before the deadline")
        run(pw, name, 2, 1, {0: P, 1: L}, {0: P.with_amount_seq(13_000, 0), 1: L.with_amount_seq(17_000, 0)},
            amounts=True)
        check(True, f"mid: {name} R3 transfer with two amount-only slots")
        expect_fail(lambda: run(pw, name, 2, 1, {0: P, 1: L},
                                {0: P.with_amount_seq(13_000, 0), 1: L.with_amount_seq(16_999, 0)}, amounts=True),
                    f"mid: {name} R3 with amount-only slots raising the landing leaf by less than the transfer")
        expect_fail(lambda: run(pw, name, 4, 1, {0: L, 1: P},
                                {0: L.with_amount_seq(17_000, 0), 1: P.with_amount_seq(13_000, 0)}, amounts=True),
                    f"mid: {name} R3 with amount-only slots and the pending leaf on the right")
        expect_fail(lambda: run(pw, name, 2, 1, {0: P, 1: L},
                                {0: P.with_amount_seq(13_000, 0), 1: L.with_amount_seq(16_999, 0)}),
                    f"mid: {name} R3 with the landing leaf raised by less than the transfer")
        expect_fail(lambda: run(pw, name, 2, 1, {0: P, 1: L},
                                {0: P.with_amount_seq(13_000, 0), 1: L.with_amount_seq(17_001, 0)}),
                    f"mid: {name} R3 with the landing leaf raised by more than the transfer")
        expect_fail(lambda: run(pw, name, 2, 1, {0: P, 1: L}, {0: P.with_amount_seq(13_000, 0), 1: L}),
                    f"mid: {name} R3 with the landing leaf unchanged (marker)")
        other = pw.landing(10_000, owner=pubkey_x(sk("operator-owner")))
        expect_fail(lambda: run(pw, name, 2, 1, {0: P, 1: other},
                                {0: P.with_amount_seq(13_000, 0), 1: other.with_amount_seq(17_000, 0)}),
                    f"mid: {name} R3 into a sibling the pending leaf's exit key does not own")
        elsewhere = lt.Leaf(10_000, pubkey_x(sk("mallory-exit")), pw.rcpt, pw.w.op_pk, 900_000, pw._nonce("L"), 0)
        expect_fail(lambda: run(pw, name, 2, 1, {0: P, 1: elsewhere},
                                {0: P.with_amount_seq(13_000, 0), 1: elsewhere.with_amount_seq(17_000, 0)}),
                    f"mid: {name} R3 into a sibling owned by the pending leaf's exit key but exiting to another key")
        flagged = pw.landing(10_000, evictor=pw.rk)
        expect_fail(lambda: run(pw, name, 2, 1, {0: P, 1: flagged},
                                {0: P.with_amount_seq(13_000, 0), 1: flagged.with_amount_seq(17_000, 0)}),
                    f"mid: {name} R3 into a reclaimable sibling")
        rekeyed = lt.Leaf(17_000, L.exit_key, L.owner_key, L.evictor_key, L.evict_after + 1, L.nonce, L.seq)
        expect_fail(lambda: run(pw, name, 2, 1, {0: P, 1: L}, {0: P.with_amount_seq(13_000, 0), 1: rekeyed}),
                    f"mid: {name} R3 into a sibling whose body changes")
        expect_fail(lambda: run(pw, name, 4, 1, {0: L, 1: P},
                                {0: L.with_amount_seq(17_000, 0), 1: P.with_amount_seq(13_000, 0)},
                                reclaim=(1,)),
                    f"mid: {name} R3 with the pending leaf on the right (R1 before the deadline)")
        expect_fail(lambda: run(pw, name, 4, 1, {0: L, 1: P},
                                {0: L.with_amount_seq(17_000, 0), 1: P.with_amount_seq(13_000, 0)}),
                    f"mid: {name} R3 with the pending leaf on the right (no R1 items)")
        # R1: reclaim after the deadline, emptied with no payout, or rolled
        run(pw, name, 2, 1, {0: P, 1: L}, {0: None, 1: L}, locktime=T, reclaim=(0,))
        check(True, f"mid: {name} R1 reclaim after the deadline, no payout")
        run(pw, name, 4, 1, {0: L, 1: P}, {0: L, 1: None}, locktime=T, reclaim=(1,))
        check(True, f"mid: {name} R1 reclaim of a pending leaf on the right")
        P2 = pw.pending(25_000, T + 1_008, label="P2")
        run(pw, name, 2, 1, {0: P, 1: L}, {0: P2, 1: L}, locktime=T, reclaim=(0,))
        check(True, f"mid: {name} R1 roll: the expired pending leaf replaced by the next window's")
        expect_fail(lambda: run(pw, name, 2, 1, {0: P, 1: L}, {0: None, 1: L}, locktime=T - 1, reclaim=(0,)),
                    f"mid: {name} R1 reclaim before the deadline")
        expect_fail(lambda: run(pw, name, 2, 1, {0: P, 1: L}, {0: P2, 1: L}, locktime=T - 1, reclaim=(0,)),
                    f"mid: {name} R1 roll before the deadline")

        def early_ea(wit):
            # the R1 items claim an earlier deadline than the leaf's field
            wit = list(wit); i = wit.index(M.scriptnum(T))
            wit[i] = M.scriptnum(T - 100)
            return wit
        expect_fail(lambda: run(pw, name, 2, 1, {0: P, 1: L}, {0: None, 1: L}, locktime=T - 100,
                                reclaim=(0,), mutate=early_ea),
                    f"mid: {name} R1 with an evict_after number below the leaf's field")
        # an amount-only top-up of the pending leaf is still rule 3's
        run(pw, name, 2, 1, {0: P, 1: L}, {0: P.with_amount_seq(25_000, 0), 1: L})
        check(True, f"mid: {name} top-up of the pending leaf, operator only")
        run(pw, name, 2, 1, {0: P, 1: L}, {0: P.with_amount_seq(25_000, 0), 1: L}, amounts=True)
        check(True, f"mid: {name} top-up of the pending leaf as an amount-only slot")
        # an owner-signed change of the landing leaf still works as rule 3
        run(pw, name, 2, 1, {0: P, 1: L}, {0: P, 1: L.with_amount_seq(9_000, 1)}, sign={1: "rcpt-exit"})
        check(True, f"mid: {name} a signed change of the landing leaf beside an unchanged pending leaf")
        # nothing reaches a leaf that is not reclaimable
        A = mk_leaf("c0", 20_000, pw.w.op_pk, 600_000)
        B = mk_leaf("c1", 10_000, pw.w.op_pk, 600_000)
        expect_fail(lambda: run(pw, name, 2, 1, {0: A, 1: B}, {0: None, 1: B}, locktime=T, reclaim=(0,)),
                    f"mid: {name} emptying an ordinary leaf with R1 items in place of a signature")
        expect_fail(lambda: run(pw, name, 2, 1, {0: L, 1: P}, {0: None, 1: P}, locktime=900_000, reclaim=(0,)),
                    f"mid: {name} reclaiming the landing leaf")
        expect_fail(lambda: run(pw, name, 2, 1, {0: A, 1: B},
                                {0: A.with_amount_seq(13_000, 0), 1: B.with_amount_seq(17_000, 0)}),
                    f"mid: {name} R3 from an ordinary leaf")
        expect_fail(lambda: run(pw, name, 2, 1, {0: A, 1: B},
                                {0: A.with_amount_seq(13_000, 0), 1: B.with_amount_seq(17_000, 0)}, amounts=True),
                    f"mid: {name} R3 from an ordinary leaf with amount-only slots")
    # two pairs in one rewrite: one settles, the other reclaims and rolls
    P_b, L_b = pw.pending(9_000, T, label="Pb"), pw.landing(4_000, label="Lb")
    it, wit = run(pw, "REWRITE_XR_2", 4, 2, {0: P, 1: L, 2: P_b, 3: L_b},
                  {0: P.with_amount_seq(13_000, 0), 1: L.with_amount_seq(17_000, 0),
                   2: pw.pending(9_000, T + 1_008, label="Pb2"), 3: L_b}, locktime=T, reclaim=(2,))
    check(True, "mid: REWRITE_XR_2 a settlement and a roll in one rewrite, operator only")
    run(pw, "REWRITE_XR_2", 4, 2, {0: P, 1: L, 2: P_b, 3: L_b},
        {0: P.with_amount_seq(13_000, 0), 1: L.with_amount_seq(17_000, 0),
         2: pw.pending(9_000, T + 1_008, label="Pb2"), 3: L_b}, locktime=T, reclaim=(2,), amounts=True)
    check(True, "mid: REWRITE_XR_2 the same settlement and roll with amount-only slots")
    # a transfer record does not leak into the next pair: pair one settles,
    # pair two is unchanged (both markers), so its right step must see (0, 0)
    run(pw, "REWRITE_XR_2", 4, 2, {0: P, 1: L, 2: P_b, 3: L_b},
        {0: P.with_amount_seq(13_000, 0), 1: L.with_amount_seq(17_000, 0), 2: P_b, 3: L_b})
    check(True, "mid: REWRITE_XR_2 a settlement beside an unchanged pair: the record is reset")
    expect_fail(lambda: run(pw, "REWRITE_XR_2", 4, 2, {0: P, 1: L, 2: P_b, 3: L_b},
                            {0: P.with_amount_seq(13_000, 0), 1: L, 2: P_b,
                             3: L_b.with_amount_seq(L_b.amount + 7_000, 0)}),
                "mid: REWRITE_XR_2 a transfer whose own right sibling does not absorb it")
    s1, s2 = len(pw.w.compiled["REWRITE_XR_1"]), len(pw.w.compiled["REWRITE_XR_2"])
    if verbose:
        plain = len(assemble(M.rewrite_script(depth, 2, pw.w.op_pk, exit_consent=True), mode="c0"))
        print(f"MID REWRITE_XR_h D={depth}: h=1 {s1} B, h=2 {s2} B (REWRITE_X_2 {plain} B); "
              f"h=2 settle+roll witness {sum(len(x) for x in wit)} B ({len(wit)} elements), maxdepth {it.max_depth}")
    return s1, s2


def pending_rewrite_full_mid(depth, height, scenario="settle", verbose=True, amounts=False):
    """A full reclaim-form REWRITE_XR_h: every position occupied, each pair
    a pending leaf and its landing leaf. scenario "settle" transfers in
    every pair (R3), "roll" rolls every pending leaf after its deadline
    (R1). Returns the interpreter or None when the 1,000-element stack
    limit rejects it, which is checked to be the failure. With amounts every
    amount-only change is the four-element slot."""
    pw = PendingMidWorld(depth)
    name = f"REWRITE_XR_{height}"
    if name not in pw.w.compiled:
        toks = M.rewrite_script(depth, height, pw.w.op_pk, exit_consent=True, reclaim_key=pw.rk)
        pw.w.compiled[name] = assemble(toks, mode="c0")
        pw.w.m = lt.taptree_root([lt.tapleaf_hash(c, 0xc0) for c in pw.w.compiled.values()])
    T = 700_000
    n = 1 << height
    old, new, rec = {}, {}, []
    for j in range(n // 2):
        P = pw.pending(20_000, T, label=f"P{j}")
        L = pw.landing(10_000, label=f"L{j}")
        old[2 * j], old[2 * j + 1] = P, L
        if scenario == "settle":
            new[2 * j], new[2 * j + 1] = P.with_amount_seq(13_000, 0), L.with_amount_seq(17_000, 0)
        else:
            new[2 * j], new[2 * j + 1] = pw.pending(21_000, T + 1_008, label=f"Q{j}"), L
            rec.append(2 * j)
    base = 1 << height          # the subtree at index 1
    try:
        it, wit = _pending_rewrite_mid(pw, name, base, height, old, new, locktime=T, reclaim=rec, amounts=amounts)
    except ScriptError as e:
        check("stack size limit" in str(e), f"mid: {name} full {scenario}: rejected only by the stack limit: {str(e)[:60]}")
        if verbose:
            print(f"MID {name} D={depth} full {scenario}: over the 1,000-element stack limit (rejected), "
                  f"script {len(pw.w.compiled[name])} B")
        return None
    check(True, f"mid: {name} D={depth} full {scenario} of {n} positions")
    if verbose:
        print(f"MID {name} D={depth} full {scenario}: script {len(pw.w.compiled[name])} B, "
              f"witness {sum(len(x) for x in wit)} B ({len(wit)} elements), maxdepth {it.max_depth}")
    return it


if __name__ == "__main__":
    test_mid(16, False)
    test_mid(31, True)
    test_sign_rules(16)
    test_carve_lease_sign(16)
    test_update_x(16, False)
    test_update_x(31, True)
    test_exit_tower(16, False)
    test_exit_tower(31, True)
    test_voucher_topup(16)
    test_claim_h(16, False)
    test_claim_h(31, True)
    for hl in (False, True):
        test_claim_x(16, False, hashlock=hl)
        test_claim_x(31, True, hashlock=hl)
    test_credit_topup(16)
    for d, h in ((8, 2), (16, 2), (16, 8)):
        test_detach(d, h)
    test_split(16, False)
    test_split(31, True)
    test_carve_rules(16)
    for h in (2, 4, 6):
        test_evict_subtree(16, h)
    for h in (5, 6):   # every position occupied: h = 6 exceeds the stack limit (spec 4.5)
        test_evict_subtree(16, h, full=True)
    for h in (2, 4):
        test_rewrite(16, h)
    test_rewrite(16, 4, exit_consent=True)
    for d, h, x in ((4, 2, False), (16, 4, False), (16, 4, True)):
        test_rewrite_amount_only(d, h, x)
    for scenario in ("update", "exit"):   # every position occupied at h = 5 fits the stack limit
        test_rewrite(16, 5, scenario=scenario)
    for scenario in ("mixed", "exit"):    # h = 6 does not, at the suite's occupancies (spec 4.5)
        test_rewrite(16, 6, scenario=scenario)
    for d in (4, 16):
        test_merge_mid(d)
        test_reclaim_mid(d)
        test_pending_rewrite_mid(d)
    test_reclaim_mid(31, sparse=True)
    for h in (4, 5, 6):   # the reclaim form, every position occupied (spec 4.5)
        for scenario in ("settle", "roll"):
            pending_rewrite_full_mid(16, h, scenario)
    for h in (5, 6):      # the same cohorts with amount-only slots: what fits the stack limit
        pending_rewrite_full_mid(16, h, "settle", amounts=True)
    print(f"\n{TS.CHECKS} checks, {TS.FAILS} failures")
    sys.exit(1 if TS.FAILS else 0)
