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
        expect_fail(lambda: run(outputs),
                    f"mid: {name} with {len(cohort)} of {n} positions occupied exceeds 1,000 stack elements")
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


def rewrite_case_mid(depth, height, scenario="mixed", exit_consent=False):
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
    base, old, new = TS._rewrite_plan(w, height, scenario)
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

    def witness(old_, new_, ctx, signer_op=None, sign=True, tree=None, m=None, marker=True):
        tree = tree or w.tree
        sigs = {}
        for i in range(n):
            if sign and _needs_owner_sig_mid(old_[i], new_[i]):
                sigs[i] = [schnorr_sign(ctx.sighash(), sk(f"c{i}-owner"))]
                if exit_consent:
                    sigs[i].append(schnorr_sign(ctx.sighash(), sk(f"c{i}-exit")))
        body = M.w_rewrite(tree, depth, height, idx, new_, sigs, marker)
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
        expect_fail(lambda: w.run(name, wit, ctx),
                    f"mid: {name} ({scenario}) with {len(wit)} witness elements exceeds 1,000 stack elements")
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


if __name__ == "__main__":
    test_mid(16, False)
    test_mid(31, True)
    test_sign_rules(16)
    test_carve_lease_sign(16)
    test_update_x(16, False)
    test_update_x(31, True)
    test_exit_tower(16, False)
    test_exit_tower(31, True)
    test_claim_h(16, False)
    test_claim_h(31, True)
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
    for scenario in ("update", "exit"):   # every position occupied at h = 5 fits the stack limit
        test_rewrite(16, 5, scenario=scenario)
    for scenario in ("mixed", "exit"):    # h = 6 does not, at the suite's occupancies (spec 4.5)
        test_rewrite(16, 6, scenario=scenario)
    print(f"\n{TS.CHECKS} checks, {TS.FAILS} failures")
    sys.exit(1 if TS.FAILS else 0)
