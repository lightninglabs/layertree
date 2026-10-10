#!/usr/bin/env python3
"""End-to-end tests for the MID tier scripts (tapleaf 0xC0 semantics)."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import layertree_ref as lt  # noqa: E402
import layertree_mid as M  # noqa: E402
import layertree_scripts as F  # noqa: E402
from script_sim import Interp, ScriptError, TxContext, assemble, pubkey_x, schnorr_sign  # noqa: E402
from test_scripts import BIP342_OPS, sk, check, expect_fail, P2WPKH  # noqa: E402
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


class MidWorld:
    def __init__(self, depth, sparse):
        self.depth, self.sparse = depth, sparse
        self.op_sk = sk("operator"); self.op_pk = pubkey_x(self.op_sk)
        self.scripts = M.all_scripts(depth, self.op_pk, sparse)
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
    frank = mk_leaf("frank", 40_000, w.op_pk, 900_000, sparse=S)
    s_f = w.slot(frank, 3)
    spath = w.tree.path(s_o)
    t5 = w.clone(); lt.apply_claim(t5, s_o, s_f, frank)
    src2 = t5.leaves[s_o]
    r1_ = lt.fold(src2.node(), spath)
    cpath = t5.path(s_f); r5 = t5.root()
    ctx = w.ctx([(r5[1], w.spk(r5))], (600, P2WPKH))
    vsig = schnorr_sign(lt.voucher_msg(w.m, src, frank), sk("operator-owner"))
    extras = [M.scriptnum(src.seq)] + list(M.pad(src.seq)) + list(M.pad(src.seq + 1)) + list(M.pad(src.amount - frank.amount))
    wit = (list(M.pad(r5[1])) + M.w_levels(cpath, lt.EMPTY_NODE, frank.node(), S) + w.pos(frank) +
           w.pads_for(root[1]) + M.w_levels(spath, src.node(), src2.node(), S) + w.pos(src) +
           M.w_leaf(src) + M.w_leaf(frank) + extras + [vsig, root[0], w.m])
    it = w.run("CLAIM", wit, ctx)
    costs["CLAIM"] = (it, len(w.compiled["CLAIM"]), sum(len(x) for x in wit))
    greedy = mk_leaf("greedy", src.amount + 1, w.op_pk, 900_000, sparse=S)
    gsig = schnorr_sign(lt.voucher_msg(w.m, src, greedy), sk("operator-owner"))
    bad_extras = extras[:-2] + list(M.pad(0))
    expect_fail(lambda: w.run("CLAIM", list(M.pad(r5[1])) + M.w_levels(cpath, lt.EMPTY_NODE, greedy.node(), S) + w.pos(greedy) +
                w.pads_for(root[1]) + M.w_levels(spath, src.node(), src2.node(), S) + w.pos(src) +
                M.w_leaf(src) + M.w_leaf(greedy) + bad_extras + [gsig, root[0], w.m], ctx), "mid: over-claim")
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
        vsig = schnorr_sign(lt.voucher_msg(w.m, src, claim), sk("chan-src-owner"))
        pad_of = lambda x: (bytes(4 - len(x)), bytes(len(x))) if len(x) <= 4 else (b"", bytes(4))
        extras = [src_seq_num] + list(pad_of(src_seq_num)) + list(pad_of(seq1_num)) + list(M.pad(src.amount - claim.amount))
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
        claim = mk_leaf("claimant", 40_000, w.op_pk, 900_000, sparse=S)
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
    toks = M.claim_script(depth, sparse, hashlock=True)
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
    hodl = mk_leaf("hodl", 40_000, w.op_pk, 900_000, sparse=S)
    s_h = w.slot(hodl, 3)
    spath = w.tree.path(s_o)
    t1 = w.clone(); lt.apply_claim(t1, s_o, s_h, hodl)
    src2 = t1.leaves[s_o]
    cpath = t1.path(s_h); r1 = t1.root()
    ctx = w.ctx([(r1[1], w.spk(r1))], (600, P2WPKH))
    hsig = schnorr_sign(lt.voucher_h_msg(w.m, src, hodl, payment_hash), sk("operator-owner"))
    extras = [M.scriptnum(src.seq)] + list(M.pad(src.seq)) + list(M.pad(src.seq + 1)) + list(M.pad(src.amount - hodl.amount))
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
    plain_sig = schnorr_sign(lt.voucher_msg(w.m, src, hodl), sk("operator-owner"))
    expect_fail(lambda: w.run("CLAIM_H", head + [plain_sig, preimage, root[0], w.m], ctx),
                "mid: CLAIM^h with a plain voucher signature")
    expect_fail(lambda: w.run("CLAIM", head + [hsig, root[0], w.m], ctx),
                "mid: plain CLAIM with a hash-locked voucher signature")
    bsig = schnorr_sign(lt.voucher_h_msg(w.m, src, hodl, payment_hash), sk("alice-owner"))
    expect_fail(lambda: w.run("CLAIM_H", head + [bsig, preimage, root[0], w.m], ctx),
                "mid: CLAIM^h voucher wrong signer")
    if verbose:
        plain = len(assemble(M.claim_script(depth, sparse), mode="c0"))
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

    bob = mk_leaf("bob", 200_000, w.op_pk, 900_000, sparse=S)
    s_b = w.slot(bob, 3)
    spath = w.tree.path(s_a)
    t1 = w.clone(); lt.apply_claim(t1, s_a, s_b, bob)
    src2 = t1.leaves[s_a]
    cpath = t1.path(s_b); r1 = t1.root()
    ctx = w.ctx([(r1[1], w.spk(r1))], (600, P2WPKH))
    asig = schnorr_sign(ctx.sighash(), sk("alice-owner"))
    extras = ([M.scriptnum(alice.seq)] + list(M.pad(alice.seq)) + list(M.pad(alice.seq + 1)) +
              list(M.pad(alice.amount - bob.amount)))
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
    vsig = schnorr_sign(lt.voucher_msg(w.m, alice, bob), sk("alice-owner"))
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
        ex = ([M.scriptnum(alice.seq)] + list(M.pad(alice.seq)) + list(M.pad(alice.seq + 1)) +
              list(M.pad(amt_new)))
        return (list(M.pad(t.root()[1])) + M.w_levels(t.path(s_new), lt.EMPTY_NODE, new.node(), S) + w.pos(new) +
                w.pads_for(root[1]) + M.w_levels(spath, alice.node(), cnode, S) + w.pos(alice) +
                M.w_leaf(alice) + M.w_leaf(new) + ex)
    greedy = mk_leaf("greedy", alice.amount + 1, w.op_pk, 900_000, sparse=S)
    expect_fail(lambda: w.run("SPLIT", carve_head(greedy, w.slot(greedy, 3), src2.node(), 0) +
                              [asig, root[0], w.m], ctx), "mid: SPLIT over-split underflow")
    if not S:   # in the sparse profile the destination is derived from the leaf
        occ = mk_leaf("bob", 200_000, w.op_pk, 900_000)
        expect_fail(lambda: w.run("SPLIT", carve_head(occ, s_o, src2.node(), alice.amount - occ.amount) +
                                  [asig, root[0], w.m], ctx), "mid: SPLIT into an occupied position")
    # the signature binds the recipient through output 0 (7.5.2, 10.7)
    mallory = mk_leaf("mallory", bob.amount, w.op_pk, 900_000, sparse=S)
    s_m = w.slot(mallory, 3)
    tm = w.clone(); lt.apply_claim(tm, s_a, s_m, mallory); rm = tm.root()
    ctx_m = w.ctx([(rm[1], w.spk(rm))], (600, P2WPKH))
    head_m = carve_head(mallory, s_m, src2.node(), alice.amount - mallory.amount)
    w.run("SPLIT", head_m + [schnorr_sign(ctx_m.sighash(), sk("alice-owner")), root[0], w.m], ctx_m)
    expect_fail(lambda: w.run("SPLIT", head_m + [asig, root[0], w.m], ctx_m),
                "mid: SPLIT recipient swapped under the owner's signature")
    if verbose:
        claim = len(assemble(M.claim_script(depth, sparse), mode="c0"))
        print(f"MID SPLIT {'S' if S else 'D'} D={depth}: script {len(script)} B "
              f"(CLAIM {claim} B, saves {claim - len(script)}), witness {sum(len(x) for x in wit)} B")
    return it, len(script), sum(len(x) for x in wit)


if __name__ == "__main__":
    test_mid(16, False)
    test_mid(31, True)
    test_update_x(16, False)
    test_update_x(31, True)
    test_claim_h(16, False)
    test_claim_h(31, True)
    test_split(16, False)
    test_split(31, True)
    print(f"\n{TS.CHECKS} checks, {TS.FAILS} failures")
    sys.exit(1 if TS.FAILS else 0)
