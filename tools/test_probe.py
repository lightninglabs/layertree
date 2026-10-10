#!/usr/bin/env python3
"""Byte-level probes against the LayerTree scripts (audit scratch file).

Each probe takes a passing case from the suites, mutates one thing, and
reports whether the mutated witness still verifies. A probe prints
ACCEPT or REJECT; the audit notes say which outcome the rules require.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import layertree_ref as lt  # noqa: E402
import layertree_scripts as ls  # noqa: E402
import layertree_mid as M  # noqa: E402
import layertree_ccv as C  # noqa: E402
import layertree_min as N  # noqa: E402
from script_sim import Interp, ScriptError, TxContext, assemble, pubkey_x, schnorr_sign  # noqa: E402
import test_scripts as TS  # noqa: E402
from test_scripts import World, mk_leaf, carve_of, sk, sc_bytes, P2WPKH  # noqa: E402
from test_mid import MidWorld  # noqa: E402
import test_mid as TM  # noqa: E402

RESULTS = []


def probe(label, fn, want):
    """want: 'reject' or 'accept' (what the rules of spec 7 require)."""
    try:
        fn()
        got = "accept"
        err = ""
    except ScriptError as e:
        got = "reject"
        err = str(e)[:100]
    flag = "ok " if got == want else "!!!"
    RESULTS.append((flag, label, got, err))
    print(f"{flag} {label}: {got.upper()}  {err}")


def raw_leaf(amount, exit_key, owner_key, evictor_key, evict_after, nonce=0, seq=0):
    """A Leaf whose fields bypass the constructor's range asserts."""
    lf = lt.Leaf(1, exit_key, owner_key, evictor_key, 0, nonce, seq)
    lf.amount, lf.evict_after = amount, evict_after
    return lf


# =========================================================== MID tier =====

def snum(n):
    """CScriptNum (signed) with a PADZ pad: (x, z, w)."""
    from script_sim import scriptnum_encode
    x = scriptnum_encode(n)
    assert len(x) <= 4
    return x, bytes(4 - len(x)), bytes(len(x))



def fold_signed(h, acc, path):
    """The fold as the MID level computes it when the accumulator is a
    signed CScriptNum: the node's sum bytes are x || z || 00000000 01 with x
    the sign-magnitude encoding. Honest siblings keep enc64."""
    from script_sim import scriptnum_encode
    for d, sib in path:
        x = scriptnum_encode(acc)
        enc = x + bytes(4 - len(x)) + bytes(4) + b"\x01"
        me = h + enc
        sb = sib[0] + lt.enc64(sib[1])
        h = lt.tagged_hash(lt.TAG_NODE, (sb + me) if d else (me + sb))
        acc += sib[1]
    return h, acc

def levels_signed(path, old_sum, new_sum):
    """MID level items with signed accumulators (the sibling sums are honest)."""
    per = []
    os_, ns = old_sum, new_sum
    for k, (d, sib) in enumerate(path):
        zs, ws = M.pad(sib[1])
        _, zn, wn = snum(ns)
        _, zo, wo = snum(os_)
        per.append([zo, wo, zn, wn, b"\x01" if d else b"", sib[0], M.scriptnum(sib[1]), zs, ws])
        os_ += sib[1]; ns += sib[1]
    items = []
    for lv in reversed(per):
        items += lv
    return items


def probe_mid_negative_sums(depth=16):
    """CScriptNum sign-magnitude: a four-byte number with the top bit set
    is negative. 2^31 + 2^24 is le32 `00 00 00 81`, a minimal CScriptNum
    equal to -2^24, so a committed sum of 2^31 + 2^24 enters the
    accumulators as -2^24."""
    w = MidWorld(depth, False)
    alice = TM.mk_leaf("alice", 50_000)
    oper = TM.mk_leaf("operator", 100_000_000)
    w.tree.leaves = {0: alice, (1 << depth) - 1: oper}
    root = w.tree.root()
    S = root[1]
    BIG = (1 << 31) + (1 << 24)          # le32 = 00 00 00 81, CScriptNum -2^24
    NEG = b"\x00\x00\x00\x81"

    # --- JOIN_2: graft a subtree whose committed sum is BIG; output 0 = S - 2^24
    h, idx = 2, 2
    jpath = w.tree.path(idx << h, height=h)
    fake_hash = lt.sha256(b"operator's subtree")
    node = (fake_hash, BIG)
    r2 = fold_signed(fake_hash, -(1 << 24), jpath)
    out0 = S - (1 << 24)
    assert r2[1] == out0
    ctx = w.ctx([(out0, w.spk(r2))], (5_000, P2WPKH))
    osig = schnorr_sign(ctx.sighash(), w.op_sk)
    items = levels_signed(jpath, 0, -(1 << 24))
    # final pad: ns ends at S - 2^24 (positive)
    wit = list(M.pad(out0)) + list(M.pad(S)) + items + [fake_hash, NEG, osig, root[0], w.m]
    probe(f"MID JOIN_2 D={depth}: committed subtree sum 2^31+2^24, output 0 = S - 2^24", lambda: w.run("JOIN_2", wit, ctx), "reject")

    # --- JOIN_0 dense: single leaf with amount BIG
    big = raw_leaf(BIG, pubkey_x(sk("big-exit")), pubkey_x(sk("big-owner")), w.op_pk, 900_000, 7)
    s_big = 9
    jpath0 = w.tree.path(s_big)
    r3 = fold_signed(big.hash(), -(1 << 24), jpath0)
    ctx3 = w.ctx([(out0, w.spk(r3))], (5_000, P2WPKH))
    osig3 = schnorr_sign(ctx3.sighash(), w.op_sk)
    items = levels_signed(jpath0, 0, -(1 << 24))
    b = big.serialize()
    leaf10 = [b[0:8], b[8:40], b[40:72], b[72:104], b[104:108], b[108:112], b[112:116], NEG, b"", bytes(4)]
    wit3 = list(M.pad(out0)) + list(M.pad(S)) + items + [big.hash(), NEG, osig3, root[0], w.m]
    probe(f"MID JOIN_0 D={depth}: leaf amount 2^31+2^24 as new_sum, output 0 = S - 2^24", lambda: w.run("JOIN_0", wit3, ctx3), "reject")

    # --- SPLIT: claim leaf amount BIG -> the source *gains* 2^24 with output 0 = S
    w.compiled = dict(w.compiled); w.compiled["SPLIT"] = assemble(M.split_script(depth, False), mode="c0")
    w.m = lt.taptree_root([lt.tapleaf_hash(c, 0xc0) for c in w.compiled.values()])
    root = w.tree.root()
    claim = raw_leaf(BIG, pubkey_x(sk("claim-exit")), pubkey_x(sk("claim-owner")), alice.evictor_key, alice.evict_after, 11)
    amt_new = alice.amount + (1 << 24)
    src2 = alice.with_amount_seq(amt_new, alice.seq + 1)
    spath = w.tree.path(0)
    t1 = w.clone(); t1.leaves[0] = src2
    cpath = t1.path(3); t1.leaves[3] = claim
    r1 = fold_signed(claim.hash(), -(1 << 24), cpath)
    assert r1[1] == S
    # the committed total is S + 2^31 + 2^25; the script's ns is S
    ctxs = w.ctx([(S, w.spk(r1))], (600, P2WPKH))
    asig = schnorr_sign(ctxs.sighash(), sk("alice-owner"))
    cb = claim.serialize()
    claim10 = [cb[0:8], cb[8:40], cb[40:72], cb[72:104], cb[104:108], cb[108:112], cb[112:116], NEG, b"", bytes(4)]
    extras = ([M.scriptnum(alice.seq)] + list(M.pad(alice.seq)) + list(M.pad(alice.seq + 1)) + list(M.pad(amt_new)) +
              [M.scriptnum(alice.evict_after)] + list(M.pad(alice.evict_after)) +
              [M.scriptnum(claim.evict_after)] + list(M.pad(claim.evict_after)))

    wits = (list(M.pad(S)) + levels_signed(cpath, 0, -(1 << 24)) +
            list(M.pad(S)) + M.w_levels(spath, alice.node(), src2.node(), False) +
            M.w_leaf(alice) + claim10 + extras + [asig, root[0], w.m])
    probe(f"MID SPLIT D={depth}: claim leaf amount 2^31+2^24, source gains 2^24, output 0 = S", lambda: w.run("SPLIT", wits, ctxs), "reject")

    # --- a sibling sum presented as negative in an EXIT, after the JOIN_2 above landed
    w.tree.leaves[(idx << h)] = None   # placeholder so path() sees the subtree as occupied
    del w.tree.leaves[(idx << h)]


def probe_mid_pads(depth=16):
    """PADZ pads: non-zero bytes and wrong splits must fail (already-enforced check)."""
    w = MidWorld(depth, False)
    alice = TM.mk_leaf("alice", 50_000)
    bob = TM.mk_leaf("bob", 125_000, w.op_pk, 800_000)
    w.tree.leaves = {0: alice, 5: bob}
    root = w.tree.root()
    path = w.tree.path(5)
    t1 = w.clone(); del t1.leaves[5]; r1 = t1.root()
    outputs = [(r1[1], w.spk(r1)), (bob.amount, lt.p2tr_spk(bob.exit_key))]
    ctx = w.ctx(outputs, (5_000, P2WPKH))
    sig = schnorr_sign(ctx.sighash(), sk("bob-owner"))

    def wit(mut=None):
        items = (list(M.pad(r1[1])) + list(M.pad(root[1])) + M.w_levels(path, bob.node(), lt.EMPTY_NODE, False) +
                 M.w_leaf_exit(bob) + [sig, b"", root[0], w.m])
        return mut(items) if mut else items
    probe("MID EXIT_1 control", lambda: w.run("EXIT_1", wit(), ctx), "accept")
    # amount pad: z with a non-zero byte
    i_z = len(wit()) - 4 - 3 - 1  # za
    def nz(items):
        b = list(items); b[i_z] = b"\x01" + b[i_z][1:]; return b
    probe("MID EXIT_1: amount pad z with a non-zero byte", lambda: w.run("EXIT_1", wit(nz), ctx), "reject")
    def wrong_split(items):
        b = list(items); b[i_z] = b[i_z] + b"\x00"; b[i_z + 1] = b[i_z + 1][1:]; return b
    probe("MID EXIT_1: amount pad moved one byte from w to z", lambda: w.run("EXIT_1", wit(wrong_split), ctx), "reject")
    # amount as non-minimal number: 125000 = c8 e8 01 -> c8 e8 01 00 with z = ""
    i_amt = i_z - 1
    def nonmin(items):
        b = list(items); b[i_amt] = b[i_amt] + b"\x00"; b[i_z] = b[i_z][1:]; b[i_z + 1] = b[i_z + 1] + b"\x00"; return b
    probe("MID EXIT_1: amount number non-minimal (trailing 00)", lambda: w.run("EXIT_1", wit(nonmin), ctx), "reject")
    # a sibling's sum pad from a level: move a zero from ws to zs
    lvl0 = 4  # first level block starts after the four root pads
    def sib_split(items):
        b = list(items); b[lvl0 + 7] = b[lvl0 + 7] + b"\x00"; b[lvl0 + 8] = b[lvl0 + 8][1:]; return b
    probe("MID EXIT_1: sibling sum pad wrong split", lambda: w.run("EXIT_1", wit(sib_split), ctx), "reject")
    # sibling sum negative zero (00 00 00 80, non-minimal under MINIMALDATA)
    def negzero(items):
        b = list(items); b[lvl0 + 6] = b"\x00\x00\x00\x80"; b[lvl0 + 7] = b""; b[lvl0 + 8] = bytes(4); return b
    probe("MID EXIT_1: sibling sum encoded as negative zero (policy MINIMALDATA)", lambda: w.run("EXIT_1", wit(negzero), ctx), "reject")


def probe_mid_cltv_negative(depth=16):
    """A leaf with evict_after >= 2^31 has a negative minimal CScriptNum;
    BIP-65 fails on a negative operand, the simulator must too."""
    w = MidWorld(depth, False)
    ea = (1 << 31) + (1 << 24)
    bob = raw_leaf(125_000, pubkey_x(sk("bob-exit")), pubkey_x(sk("bob-owner")), w.op_pk, ea, 3)
    alice = TM.mk_leaf("alice", 50_000)
    w.tree.leaves = {0: alice, 5: bob}
    root = w.tree.root()
    path = w.tree.path(5)
    t1 = w.clone(); del t1.leaves[5]; r1 = t1.root()
    ctx = w.ctx([(r1[1], w.spk(r1)), (bob.amount, lt.p2tr_spk(bob.exit_key))], (5_000, P2WPKH), locktime=0)
    esig = schnorr_sign(ctx.sighash(), w.op_sk)
    wit = (list(M.pad(r1[1])) + list(M.pad(root[1])) + M.w_levels(path, bob.node(), lt.EMPTY_NODE, False) +
           M.w_leaf(bob) + [b"\x00\x00\x00\x81", b"", bytes(4), esig, b"\x01", root[0], w.m])
    probe("MID EXIT_1 evict: evict_after 2^31+2^24 (negative CScriptNum) at locktime 0", lambda: w.run("EXIT_1", wit, ctx), "reject")


def probe_mid_sparse_depth(depth):
    """MID sparse at D < 31: the teardown compares the D-bit accumulator with
    the full 32-bit pos_lo, so a nonce that passes pos_ok but has bits set
    at or above D is rejected although 5.4 places the leaf at the low D bits."""
    w = MidWorld(depth, True)
    lf = TM.mk_leaf("solo", 50_000, sparse=True)
    plo = int.from_bytes(lt.tagged_hash(lt.TAG_POS, lf.owner_key + lt.le32(lf.nonce))[:4], "little")
    print(f"    D={depth}: pos_lo = {plo:#x}, position = {M.position(lf, depth):#x}, pos_lo < 2^D: {plo < (1 << depth)}")
    w.tree.leaves = {}
    root = w.tree.root()
    slot = M.position(lf, depth)
    jpath = w.tree.path(slot)
    t2 = w.clone(); t2.leaves[slot] = lf; r2 = t2.root()
    ctx = w.ctx([(r2[1], w.spk(r2))], (lf.amount + 500, P2WPKH))
    osig = schnorr_sign(ctx.sighash(), w.op_sk)
    wit = (list(M.pad(r2[1])) + list(M.pad(root[1])) + M.w_levels(jpath, lt.EMPTY_NODE, lf.node(), True) +
           M.w_pos(lf) + M.w_leaf(lf) + [osig, root[0], w.m])
    probe(f"MID sparse JOIN_0 D={depth} with a pos_ok nonce", lambda: w.run("JOIN_0", wit, ctx), "accept")


# ========================================================== FULL tier =====

def probe_full_sparse_explicit_empty(depth=8):
    w = World(depth, "S")
    bob = mk_leaf("bob", 125_000)
    alice = mk_leaf("alice", 50_000)
    w.tree.leaves = {w.slot(bob): bob, w.slot(alice): alice}
    root = w.tree.root()
    s_bob = w.slot(bob)
    path = w.tree.path(s_bob)
    t1 = w.clone(); del t1.leaves[s_bob]; r1 = t1.root()
    ctx = w.ctx([(r1[1], w.spk(r1)), (bob.amount - 1_000, lt.p2tr_spk(bob.exit_key))], extra_in=(5_000, P2WPKH))
    sig = schnorr_sign(ctx.sighash(), sk("bob-owner"))
    pw = w.path_witness(path)
    probe("FULL sparse EXIT_1 control", lambda: w.run("EXIT_1", pw + [bob.serialize(), sig, b"", root[0], w.m], ctx), "accept")
    # replace every empty sibling by its explicit 41-byte E_k || ENC0
    explicit = []
    for k, (d, sib) in enumerate(reversed(path)):
        lvl = depth - 1 - k
        explicit.append(sc_bytes(lt.empty_node(lvl)) if sib == lt.empty_node(lvl) else pw[k])
    n_explicit = sum(1 for x in pw if x == b"")
    probe(f"FULL sparse EXIT_1: {n_explicit} empty siblings supplied explicitly as E_k||ENC0 (5.5 says MAY be empty)",
          lambda: w.run("EXIT_1", explicit + [bob.serialize(), sig, b"", root[0], w.m], ctx), "accept")


def probe_full_exit_variants(depth=4):
    w = World(depth, "D")
    alice = mk_leaf("alice", 50_000)
    bob = mk_leaf("bob", 125_000, evictor=w.op_pk, evict_after=800_000)
    w.tree.leaves = {0: alice, 5: bob}
    root = w.tree.root()
    path = w.tree.path(5)
    t1 = w.clone(); del t1.leaves[5]; r1 = t1.root()
    outputs = [(r1[1], w.spk(r1)), (bob.amount - 1_000, lt.p2tr_spk(bob.exit_key))]
    ctx = w.ctx(outputs, extra_in=(5_000, P2WPKH))
    sig = schnorr_sign(ctx.sighash(), sk("bob-owner"))
    pw = w.path_witness(path)
    base = lambda leaf=bob.serialize(), s=sig, ev=b"": pw + [leaf, s, ev, root[0], w.m]
    probe("FULL EXIT_1 control", lambda: w.run("EXIT_1", base(), ctx), "accept")
    probe("FULL EXIT_1: is_evict = 0x02 (MINIMALIF)", lambda: w.run("EXIT_1", base(ev=b"\x02"), ctx), "reject")
    probe("FULL EXIT_1: leaf of 115 bytes", lambda: w.run("EXIT_1", base(leaf=bob.serialize()[:115]), ctx), "reject")
    probe("FULL EXIT_1: leaf of 117 bytes", lambda: w.run("EXIT_1", base(leaf=bob.serialize() + b"\x00"), ctx), "reject")
    # sibling sc of 40 / 42 bytes, and sc with byte 40 != 0x01
    for mut, label in ((lambda sc: sc[:40], "40-byte sc"), (lambda sc: sc + b"\x00", "42-byte sc"),
                       (lambda sc: sc[:40] + b"\x02", "sc with enc64 suffix 0x02")):
        pw2 = list(pw); pw2[1] = mut(pw2[1])
        probe(f"FULL EXIT_1: {label} at the top level", lambda: w.run("EXIT_1", pw2 + [bob.serialize(), sig, b"", root[0], w.m], ctx), "reject")
    # a dir element of 0x02 / a 1-byte 0x00
    for dv, label in ((b"\x02", "dir = 0x02"), (b"\x00", "dir = 0x00 (non-minimal false)")):
        pw3 = list(pw); pw3[0] = dv
        probe(f"FULL EXIT_1: {label}", lambda: w.run("EXIT_1", pw3 + [bob.serialize(), sig, b"", root[0], w.m], ctx), "reject")
    # surplus on an exact-payout tree
    exact = assemble(ls.exit_script(depth, 1, "D", exact=True))
    w2 = World(depth, "D"); w2.compiled = dict(w2.compiled); w2.compiled["EXIT_1"] = exact
    w2.m = lt.taptree_root([lt.tapleaf_hash(c) for c in w2.compiled.values()])
    w2.tree.leaves = {0: alice, 5: bob}
    ctx_s = w2.ctx([(r1[1], w2.spk(r1)), (bob.amount + 1, lt.p2tr_spk(bob.exit_key))], extra_in=(5_000, P2WPKH))
    sig_s = schnorr_sign(ctx_s.sighash(), sk("bob-owner"))
    probe("FULL EXIT_1^=: owner payout one sat over leaf.amount", lambda: w2.run("EXIT_1", w2.path_witness(path) + [bob.serialize(), sig_s, b"", root[0], w2.m], ctx_s), "reject")
    # zero-value owner payout on the plain variant
    ctx_z = w.ctx([(r1[1], w.spk(r1)), (0, lt.p2tr_spk(bob.exit_key))], extra_in=(5_000, P2WPKH))
    sig_z = schnorr_sign(ctx_z.sighash(), sk("bob-owner"))
    probe("FULL EXIT_1: owner payout of 0 (rule 3 allows <=)", lambda: w.run("EXIT_1", base(s=sig_z), ctx_z), "accept")
    # EXIT_2 naming the same position twice
    t2 = w.clone(); del t2.leaves[5]
    path2 = t2.path(5)
    outs2 = [(r1[1], w.spk(r1)), (bob.amount, lt.p2tr_spk(bob.exit_key)), (bob.amount, lt.p2tr_spk(bob.exit_key))]
    ctx2 = w.ctx(outs2, extra_in=(5_000, P2WPKH))
    s2 = schnorr_sign(ctx2.sighash(), sk("bob-owner"))
    wit2 = w.path_witness(path2) + [bob.serialize(), s2, b""] + w.path_witness(path) + [bob.serialize(), s2, b""] + [root[0], w.m]
    probe("FULL EXIT_2: the same position in both steps", lambda: w.run("EXIT_2", wit2, ctx2), "reject")
    # payout to a different output index than the one the script names
    outs3 = [(r1[1], w.spk(r1)), (400, P2WPKH), (bob.amount - 1_000, lt.p2tr_spk(bob.exit_key))]
    ctx3 = w.ctx(outs3, extra_in=(5_000, P2WPKH))
    s3 = schnorr_sign(ctx3.sighash(), sk("bob-owner"))
    probe("FULL EXIT_1: payout at output 2 instead of 1", lambda: w.run("EXIT_1", base(s=s3), ctx3), "reject")


def probe_full_small_depths():
    for depth in (1, 2):
        w = World(depth, "D", join_heights=(0,), exit_ks=(1,))
        alice = mk_leaf("alice", 50_000)
        w.tree.leaves = {0: alice}
        root = w.tree.root()
        # JOIN_0 of bob into slot 1
        bob = mk_leaf("bob", 30_000, w.op_pk, 900_000)
        jpath = w.tree.path(1)
        t2 = w.clone(); t2.leaves[1] = bob; r2 = t2.root()
        ctx = w.ctx([(r2[1], w.spk(r2))], extra_in=(bob.amount + 500, P2WPKH))
        osig = schnorr_sign(ctx.sighash(), w.op_sk)
        probe(f"FULL D={depth} JOIN_0", lambda: w.run("JOIN_0", w.path_witness(jpath) + [bob.hash(), lt.le64(bob.amount), osig, root[0], w.m], ctx), "accept")
        w.tree = t2; root = w.tree.root()
        # CLAIM out of alice into the remaining empty slot (D=2) or a drained source (D=1)
        src = alice
        if depth == 2:
            frank = carve_of(src, "frank", 20_000); s_f = 3
        else:
            frank = carve_of(src, "frank", src.amount); s_f = 0      # drain and re-use the slot
        spath = w.tree.path(0)
        t5 = w.clone(); lt.apply_claim(t5, 0, s_f, frank) if depth == 2 else None
        if depth == 1:
            del t5.leaves[0]; t5.leaves[0] = frank
        cpath = (t5.path(s_f) if depth == 2 else lt.Tree(depth).path(0))
        if depth == 1:
            tt = w.clone(); del tt.leaves[0]; cpath = tt.path(0)
        r5 = t5.root()
        ctx5 = w.ctx([(r5[1], w.spk(r5))], extra_in=(600, P2WPKH))
        vsig = schnorr_sign(lt.voucher_msg(w.tree_id, src, frank), sk("alice-owner"))
        probe(f"FULL D={depth} CLAIM", lambda: w.run("CLAIM", w.path_witness(cpath) + w.path_witness(spath) + [src.serialize(), frank.serialize(), vsig, root[0], w.m], ctx5), "accept")
        # terminal EXIT of bob then of the rest
        w.tree = t5; root = w.tree.root()
        path = w.tree.path(1)
        t6 = w.clone(); del t6.leaves[1]; r6 = t6.root()
        ctx6 = w.ctx([(r6[1], w.spk(r6)), (bob.amount, lt.p2tr_spk(bob.exit_key))], extra_in=(500, P2WPKH))
        s6 = schnorr_sign(ctx6.sighash(), sk("bob-owner"))
        probe(f"FULL D={depth} EXIT_1 (non-terminal)", lambda: w.run("EXIT_1", w.path_witness(path) + [bob.serialize(), s6, b"", root[0], w.m], ctx6), "accept")


def probe_full_claim_edges(depth=4):
    w = World(depth, "D")
    alice = mk_leaf("alice", 50_000)
    oper = mk_leaf("operator", 1_000_000)
    w.tree.leaves = {0: alice, 15: oper}
    root = w.tree.root()
    # claim leaf identical to the source: drain and re-insert elsewhere
    spath = w.tree.path(15)
    t1 = w.clone(); del t1.leaves[15]
    cpath = t1.path(3); t1.leaves[3] = oper; r1 = t1.root()
    ctx = w.ctx([(r1[1], w.spk(r1))], extra_in=(600, P2WPKH))
    vsig = schnorr_sign(lt.voucher_msg(w.tree_id, oper, oper), sk("operator-owner"))
    probe("FULL CLAIM: claim_leaf == source_leaf (moves the leaf, keeps seq)", lambda: w.run("CLAIM", w.path_witness(cpath) + w.path_witness(spath) + [oper.serialize(), oper.serialize(), vsig, root[0], w.m], ctx), "accept")
    # ... and the same voucher again against the new position
    w.tree = t1; root = w.tree.root()
    spath2 = w.tree.path(3)
    t2 = w.clone(); del t2.leaves[3]
    cpath2 = t2.path(15); t2.leaves[15] = oper; r2 = t2.root()
    ctx2 = w.ctx([(r2[1], w.spk(r2))], extra_in=(600, P2WPKH))
    probe("FULL CLAIM: the same voucher replayed against the moved leaf", lambda: w.run("CLAIM", w.path_witness(cpath2) + w.path_witness(spath2) + [oper.serialize(), oper.serialize(), vsig, root[0], w.m], ctx2), "accept")
    # claim leaf with amount 0
    w.tree = t2; root = w.tree.root()
    zero = carve_of(oper, "zero", 0)
    spath3 = w.tree.path(15)
    t3 = w.clone(); lt.apply_claim(t3, 15, 3, zero); cpath3 = t3.path(3); r3 = t3.root()
    ctx3 = w.ctx([(r3[1], w.spk(r3))], extra_in=(600, P2WPKH))
    zsig = schnorr_sign(lt.voucher_msg(w.tree_id, oper, zero), sk("operator-owner"))
    probe("FULL CLAIM: claim leaf of amount 0 (7.8: harmless)", lambda: w.run("CLAIM", w.path_witness(cpath3) + w.path_witness(spath3) + [oper.serialize(), zero.serialize(), zsig, root[0], w.m], ctx3), "accept")
    # claim leaf with the same (owner, nonce) as the source: two leaves, one voucher each (5.2 forbids; script?)
    twin = lt.Leaf(10_000, oper.exit_key, oper.owner_key, oper.evictor_key, oper.evict_after, oper.nonce, 0)
    t4 = w.clone(); lt.apply_claim(t4, 15, 5, twin); cpath4 = t4.path(5); r4 = t4.root()
    ctx4 = w.ctx([(r4[1], w.spk(r4))], extra_in=(600, P2WPKH))
    tsig = schnorr_sign(lt.voucher_msg(w.tree_id, oper, twin), sk("operator-owner"))
    probe("FULL CLAIM: claim leaf with the source's (owner_key, nonce) (5.2 forbids, script does not check)", lambda: w.run("CLAIM", w.path_witness(cpath4) + w.path_witness(spath3) + [oper.serialize(), twin.serialize(), tsig, root[0], w.m], ctx4), "accept")
    # seq = SEQ_FINAL - 1 claimable; a seq field of 0xFFFFFFFF rejected (tested); evict_after equal (carve_of) accepted
    fin = mk_leaf("fin", 100_000, seq=0xFFFFFFFE)
    w.tree.leaves[7] = fin; root = w.tree.root()
    c = carve_of(fin, "c", 1_000)
    sp = w.tree.path(7); t5 = w.clone(); lt.apply_claim(t5, 7, 9, c); cp = t5.path(9); r5 = t5.root()
    ctx5 = w.ctx([(r5[1], w.spk(r5))], extra_in=(600, P2WPKH))
    csig = schnorr_sign(lt.voucher_msg(w.tree_id, fin, c), sk("fin-owner"))
    probe("FULL CLAIM: source seq = SEQ_FINAL - 1", lambda: w.run("CLAIM", w.path_witness(cp) + w.path_witness(sp) + [fin.serialize(), c.serialize(), csig, root[0], w.m], ctx5), "accept")
    # a non-minimal seq field (raw 01 00 00 00) increments correctly
    one = mk_leaf("one", 100_000, seq=1)
    w.tree.leaves[8] = one; root = w.tree.root()
    c1 = carve_of(one, "c1", 1_000)
    sp = w.tree.path(8); t6 = w.clone(); lt.apply_claim(t6, 8, 10, c1); cp = t6.path(10); r6 = t6.root()
    ctx6 = w.ctx([(r6[1], w.spk(r6))], extra_in=(600, P2WPKH))
    s1 = schnorr_sign(lt.voucher_msg(w.tree_id, one, c1), sk("one-owner"))
    probe("FULL CLAIM: source seq = 1 (raw field 01 00 00 00 is a non-minimal number)", lambda: w.run("CLAIM", w.path_witness(cp) + w.path_witness(sp) + [one.serialize(), c1.serialize(), s1, root[0], w.m], ctx6), "accept")
    # claim.amount == src.amount drains; claim.amount == src.amount + 0 with evict_after equal: tested. Surplus: tested.


def probe_full_rewrite(depth=8, height=2):
    c = TS.rewrite_case(depth, height, "mixed")
    w, name, ctx, root, path, base = c["w"], c["name"], c["ctx"], c["root"], c["path"], c["base"]
    old, new = c["old"], c["new"]
    n = 1 << height

    def run_with(old_, new_, outs=None, sign=True, extra_sig_at=None, strip_sig_at=None):
        t = w.clone()
        for i, x in new_.items():
            if x:
                t.leaves[base + i] = x
            else:
                t.leaves.pop(base + i, None)
        outs = outs or ([(t.root()[1], w.spk(t.root()))] + [(old_[i].amount, lt.p2tr_spk(old_[i].exit_key)) for i in range(n) if old_[i] and new_[i] is None] + [(400, P2WPKH)])
        delta = t.root()[1] - root[1]
        ctx_ = w.ctx(outs, extra_in=(max(delta, 0) + 5_000, P2WPKH))
        so = schnorr_sign(ctx_.sighash(), w.op_sk)
        wit, sigs = TS._rewrite_witness(w, height, path, old_, new_, ctx_, root, so, False, sign)
        if extra_sig_at is not None:
            # insert an owner signature for a position that needs none, directly below its new element
            i = extra_sig_at
            pos = wit.index(new_[i].serialize() if new_[i] else b"")
            wit = wit[:pos] + [schnorr_sign(ctx_.sighash(), sk(f"c{i}-owner"))] + wit[pos:]
        if strip_sig_at is not None:
            s = sigs[strip_sig_at][0]
            wit = [x for x in wit if x != s]
        return w.run(name, wit, ctx_)
    probe(f"{name} control", lambda: run_with(old, new), "accept")
    print("    plan:", {i: ("E" if old[i] is None else "L") + "->" + ("E" if new[i] is None else "L") + (" sig" if TS._needs_owner_sig(old[i], new[i]) else "") for i in range(n)})
    i_leaf = next(i for i in range(n) if old[i] and new[i] and old[i].serialize() == new[i].serialize())
    # (a) exit key change only, no signature
    lf = old[i_leaf]
    nk = dict(new); nk[i_leaf] = lt.Leaf(lf.amount, pubkey_x(sk("mallory-exit")), lf.owner_key, lf.evictor_key, lf.evict_after, lf.nonce, lf.seq)
    probe(f"{name}: exit_key changed at an unchanged position, no owner sig", lambda: run_with(old, nk, sign=False), "reject")
    probe(f"{name}: exit_key changed with the owner's sig", lambda: run_with(old, nk, sign=True), "accept")
    # (b) amount decrease, everything else equal, no sig
    nd = dict(new); nd[i_leaf] = lf.with_amount_seq(lf.amount - 1, lf.seq)
    probe(f"{name}: amount decreased by 1 at a position, no owner sig", lambda: run_with(old, nd, sign=False), "reject")
    # (c) amount increase plus nonce change, no sig
    nn = dict(new); nn[i_leaf] = lt.Leaf(lf.amount + 1, lf.exit_key, lf.owner_key, lf.evictor_key, lf.evict_after, lf.nonce + 1, lf.seq)
    probe(f"{name}: amount increase with a nonce change, no owner sig", lambda: run_with(old, nn, sign=False), "reject")
    # (d) amount increase with seq change, no sig
    ns_ = dict(new); ns_[i_leaf] = lf.with_amount_seq(lf.amount + 1, lf.seq + 1)
    probe(f"{name}: amount increase with a seq change, no owner sig", lambda: run_with(old, ns_, sign=False), "reject")
    # (e) a signature supplied for an unchanged position
    probe(f"{name}: a spurious owner sig under an unchanged position", lambda: run_with(old, new, extra_sig_at=i_leaf), "reject")
    # (f) a join position (E_0 -> leaf) given a signature
    i_join = next((i for i in range(n) if old[i] is None and new[i]), None)
    if i_join is not None:
        probe(f"{name}: a spurious sig under a join position", lambda: run_with(old, new, extra_sig_at=i_join), "reject")
    # (g) old and new swapped at an exit position: becomes a join of the old leaf, exit payout output left over -> output mismatch
    i_exit = next(i for i in range(n) if old[i] and new[i] is None)
    sw_old, sw_new = dict(old), dict(new)
    sw_old[i_exit], sw_new[i_exit] = None, old[i_exit]
    probe(f"{name}: old/new swapped at an exit position (presents the tree as if the leaf were absent)", lambda: run_with(sw_old, sw_new), "reject")
    # (h) exit of a leaf whose payout goes to the owner key instead of the exit key
    outs = [(c["r1"][1], w.spk(c["r1"]))]
    for i in range(n):
        if old[i] and new[i] is None:
            outs.append((old[i].amount, lt.p2tr_spk(old[i].owner_key)))
    outs.append((400, P2WPKH))
    probe(f"{name}: exit payouts to the owner key", lambda: run_with(old, new, outs=outs), "reject")
    # (i) an element of 1 byte as an old element
    def one_byte():
        t = w.clone()
        wit = list(c["wit"])
        pos = wit.index(old[i_leaf].serialize())
        wit[pos] = b"\x01"
        return w.run(name, wit, ctx)
    probe(f"{name}: a 1-byte old element", one_byte, "reject")
    # (j) old element the same leaf but with amount+1 and new unchanged -> the old subtree differs: stale
    fo = dict(old); fo[i_leaf] = lf.with_amount_seq(lf.amount + 1, lf.seq)
    fn = dict(new); fn[i_leaf] = fo[i_leaf]
    probe(f"{name}: forged old leaf (amount+1) with new == old", lambda: run_with(fo, fn), "reject")


def probe_full_evict_subtree(depth=8, height=2):
    w = World(depth, "D")
    script = assemble(ls.evict_subtree_script(depth, height, w.op_pk))
    name = f"EVICT_SUBTREE_{height}"
    w.compiled = dict(w.compiled); w.compiled[name] = script
    w.m = lt.taptree_root([lt.tapleaf_hash(c) for c in w.compiled.values()])
    n, base = 1 << height, 1 << height
    cohort = {base + i: mk_leaf(f"c{i}", 10_000 + 7 * i, w.op_pk, 800_000) for i in range(n) if i != 2}
    w.tree.leaves = dict(cohort); w.tree.leaves[0] = mk_leaf("alice", 50_000)
    root = w.tree.root()
    path = w.tree.path(base, height=height)
    t1 = w.clone()
    for p in cohort:
        del t1.leaves[p]
    r1 = t1.root()

    def run(leaves_rev, outs, locktime=800_000):
        ctx = w.ctx(outs, extra_in=(5_000, P2WPKH), locktime=locktime)
        sig = schnorr_sign(ctx.sighash(), w.op_sk)
        return w.run(name, w.path_witness(path, height) + leaves_rev + [sig, root[0], w.m], ctx)
    present = [base + i for i in range(n) if base + i in cohort]
    outs = [(r1[1], w.spk(r1))] + [(cohort[p].amount, lt.p2tr_spk(cohort[p].exit_key)) for p in present] + [(400, P2WPKH)]
    lr = [cohort[base + i].serialize() if base + i in cohort else b"" for i in reversed(range(n))]
    probe(f"{name} control", lambda: run(lr, outs), "accept")
    hide = list(lr); hide[-1] = b""     # position 0 presented as empty
    probe(f"{name}: an occupied position presented as empty", lambda: run(hide, [outs[0]] + outs[2:]), "reject")
    swap = list(lr); swap[-1], swap[-2] = swap[-2], swap[-1]
    probe(f"{name}: two leaves presented in swapped positions", lambda: run(swap, outs), "reject")
    outs_sw = [outs[0], outs[2], outs[1]] + outs[3:]
    probe(f"{name}: payouts in the wrong order", lambda: run(lr, outs_sw), "reject")
    # an empty position supplied as E_0's 116 zero bytes
    ez = list(lr); ez[n - 1 - 2] = bytes(116)
    probe(f"{name}: empty position supplied as 116 zero bytes", lambda: run(ez, outs), "reject")
    # evict_after exactly equal to nLockTime
    probe(f"{name}: nLockTime == evict_after", lambda: run(lr, outs, locktime=800_000), "accept")
    probe(f"{name}: nLockTime == evict_after - 1", lambda: run(lr, outs, locktime=799_999), "reject")


def probe_full_join_detach(depth=8):
    w = World(depth, "D", join_heights=(0, 2))
    alice = mk_leaf("alice", 50_000)
    w.tree.leaves = {0: alice}
    root = w.tree.root()
    h, idx = 2, 2
    jpath = w.tree.path(idx << h, height=h)
    carol = mk_leaf("carol", 30_000, w.op_pk, 900_000)
    t2 = w.clone(); lt.apply_join(t2, h, idx, {0: carol})
    node, r2 = t2.subtree(h, idx), t2.root()
    ctx = w.ctx([(r2[1], w.spk(r2))], extra_in=(node[1] + 2_000, P2WPKH))
    osig = schnorr_sign(ctx.sighash(), w.op_sk)
    pw = w.path_witness(jpath, h)
    probe("FULL JOIN_2 control", lambda: w.run("JOIN_2", pw + [node[0], lt.le64(node[1]), osig, root[0], w.m], ctx), "accept")
    probe("FULL JOIN_2: new_sum of 7 bytes", lambda: w.run("JOIN_2", pw + [node[0], lt.le64(node[1])[:7], osig, root[0], w.m], ctx), "reject")
    probe("FULL JOIN_2: new_sum of 9 bytes", lambda: w.run("JOIN_2", pw + [node[0], lt.le64(node[1]) + b"\x00", osig, root[0], w.m], ctx), "reject")
    probe("FULL JOIN_2: new_hash of 31 bytes", lambda: w.run("JOIN_2", pw + [node[0][:31], lt.le64(node[1]), osig, root[0], w.m], ctx), "reject")
    # JOIN of E_h with a non-zero sum (bogus node) is operator-funded and harmless
    bog = (lt.empty_node(h)[0], 1_000)
    rb = lt.fold(bog, jpath)
    ctxb = w.ctx([(rb[1], w.spk(rb))], extra_in=(5_000, P2WPKH)); sb = schnorr_sign(ctxb.sighash(), w.op_sk)
    probe("FULL JOIN_2: new node (E_h, 1000) funded by the operator (7.3 rule 4: contents unconstrained)", lambda: w.run("JOIN_2", pw + [bog[0], lt.le64(bog[1]), sb, root[0], w.m], ctxb), "accept")
    # amount at 2^63 and 2^64-1 as a joined sum
    for big in (1 << 53, 1 << 63, (1 << 64) - 1):
        nb = (node[0], big)
        r = lt.fold(nb, jpath)
        if r[1] >= 1 << 64:
            print(f"    (join sum {big:#x}: total >= 2^64, le64 cannot express output 0)")
            continue
        cx = w.ctx([(r[1], w.spk(r))], extra_in=(big + 5_000, P2WPKH)); sg = schnorr_sign(cx.sighash(), w.op_sk)
        probe(f"FULL JOIN_2: new_sum = {big:#x}", lambda: w.run("JOIN_2", pw + [nb[0], lt.le64(nb[1]), sg, root[0], w.m], cx), "accept")


def probe_ccv(depth=4):
    import test_ccv as TC
    w = TC.World(depth, "D")
    alice = TC.mk_leaf("alice", 50_000)
    bob = TC.mk_leaf("bob", 125_000, evictor=w.op_pk, evict_after=800_000)
    w.tree.leaves = {0: alice, 5: bob}
    root = w.tree.root()
    path = w.tree.path(5)
    t1 = w.clone(); del t1.leaves[5]; r1 = t1.root()
    outputs = [(r1[1], w.spk(r1)), (bob.amount, lt.p2tr_spk(bob.exit_key))]

    def go(outs, extra_in=(5_000, P2WPKH)):
        ctx = w.ctx(outs, extra_in=extra_in)
        sig = schnorr_sign(ctx.sighash(), sk("bob-owner"))
        return w.run("EXIT_1", w.path_witness(path) + [bob.serialize(), sig, b""], ctx)
    probe("CCV EXIT_1 control", lambda: go(outputs), "accept")
    probe("CCV EXIT_1: output 0 over-funded by 1", lambda: go([(r1[1] + 1, w.spk(r1)), outputs[1]], (6_000, P2WPKH)), "reject")
    probe("CCV EXIT_1: output 0 under-funded by 1", lambda: go([(r1[1] - 1, w.spk(r1)), outputs[1]]), "reject")
    probe("CCV EXIT_1: payout to a taproot output with a taptree over exit_key", lambda: go([outputs[0], (bob.amount, lt.tree_spk(root[0], w.m))]), "reject")
    probe("CCV EXIT_1: tree output and payout swapped", lambda: go([outputs[1], outputs[0]]), "reject")
    probe("CCV EXIT_1: payout one sat short", lambda: go([outputs[0], (bob.amount - 1, lt.p2tr_spk(bob.exit_key))]), "reject")
    probe("CCV EXIT_1: output 0 under the parent key without the taptree (tweak-less)", lambda: go([(r1[1], lt.p2tr_spk(lt.ccv_internal_key(r1[0]))), outputs[1]]), "reject")


def probe_min(depth=4):
    import test_min as TN
    # reuse test_min's construction to get a passing witness, then mutate raw pieces
    toks = N.exit_script(depth)
    script = assemble(toks, "c0")
    leaf_hash = lt.tapleaf_hash(script, 0xc0)
    m = lt.taptree_root([leaf_hash, lt.sha256(b"other leaf")])
    op_sk = sk("operator"); op_pk = pubkey_x(op_sk)
    alice = TM.mk_leaf("alice", 50_000)
    bob = TM.mk_leaf("bob", 125_000, op_pk, 800_000)
    tree = lt.Tree(depth); tree.leaves = {0: alice, 5: bob}
    root = tree.root()
    t1 = lt.Tree(depth); t1.leaves = {0: alice}; r1 = t1.root()
    path = tree.path(5)

    def make_ctx(n_in=2, extra=((400, P2WPKH),)):
        outs = [(r1[1], lt.tree_spk(r1[0], m)), (bob.amount, lt.p2tr_spk(bob.exit_key))] + list(extra)
        ins = [(root[1], lt.tree_spk(root[0], m))] + [(5_000 + i, P2WPKH) for i in range(n_in - 1)]
        return TxContext(ins, outs, tapleaf_hash=leaf_hash)

    def mutate(ctx, i):
        ctx.sequences[1] = 0xfffffffd - i

    def pieces(ctx, e31):
        amts = b"".join(a.to_bytes(8, "little") for a, _ in ctx.inputs[1:])
        spks = b"".join(lt.compact_size(len(s)) + s for _, s in ctx.inputs[1:])
        extra = b"".join(a.to_bytes(8, "little") + lt.compact_size(len(spk)) + spk for a, spk in ctx.outputs[2:])
        return [e31, ctx.sha_sequences(), ctx.tapleaf_hash, ctx.sha_prevouts(),
                ctx.version.to_bytes(4, "little"), ctx.locktime.to_bytes(4, "little"), spks, amts, extra]

    def witness(ctx, raw, sig):
        return (raw + list(M.pad(r1[1])) + list(M.pad(root[1])) + M.w_levels(path, bob.node(), lt.EMPTY_NODE, False) +
                M.w_leaf_exit(bob) + [sig, b"", root[0], m])

    def run(ctx, wit):
        it = Interp(ctx, mode="c0"); it.run(script, wit); return it
    ctx = make_ctx()
    e31, _ = N.grind(ctx, mutate)
    sig = schnorr_sign(ctx.sighash(), sk("bob-owner"))
    raw = pieces(ctx, e31)
    probe("MIN EXIT_1 control", lambda: run(ctx, witness(ctx, raw, sig)), "accept")
    # shift one byte between ver and lock: same concatenation
    r2 = list(raw); r2[4], r2[5] = r2[4] + r2[5][:1], r2[5][1:]
    probe("MIN EXIT_1: ver/lock boundary shifted (same bytes)", lambda: run(ctx, witness(ctx, r2, sig)), "accept")
    # three inputs: amt_in1 and spk_in1 carry two inputs' worth
    ctx3 = make_ctx(n_in=3)
    e31_3, _ = N.grind(ctx3, mutate)
    sig3 = schnorr_sign(ctx3.sighash(), sk("bob-owner"))
    probe("MIN EXIT_1: three inputs (raw pieces concatenated)", lambda: run(ctx3, witness(ctx3, pieces(ctx3, e31_3), sig3)), "accept")
    # each raw piece substituted
    for i, label in enumerate(("e31", "sha_seqs", "tapleaf", "sha_prevouts", "ver", "lock", "spk_in1", "amt_in1", "extra_outs")):
        r3 = list(raw); r3[i] = lt.sha256(label.encode())[:len(r3[i])] if r3[i] else b"\x01"
        probe(f"MIN EXIT_1: raw piece {label} substituted", lambda: run(ctx, witness(ctx, r3, sig)), "reject")
    # the tree input's amount and spk are constructive: a tx whose input 0 is a different tree output
    ctx_x = make_ctx()
    ctx_x.inputs[0] = (root[1] + 1, ctx_x.inputs[0][1])
    e31x, _ = N.grind(ctx_x, mutate); sigx = schnorr_sign(ctx_x.sighash(), sk("bob-owner"))
    probe("MIN EXIT_1: input 0 amount one sat above the folded sum", lambda: run(ctx_x, witness(ctx_x, pieces(ctx_x, e31x), sigx)), "reject")


if __name__ == "__main__":
    which = sys.argv[1:] or ["all"]
    def on(k):
        return "all" in which or k in which
    if on("midneg"):
        probe_mid_negative_sums()
    if on("midpad"):
        probe_mid_pads()
    if on("midcltv"):
        probe_mid_cltv_negative()
    if on("midsparse"):
        for d in (28, 31):
            probe_mid_sparse_depth(d)
    if on("sparse"):
        probe_full_sparse_explicit_empty()
    if on("exit"):
        probe_full_exit_variants()
    if on("small"):
        probe_full_small_depths()
    if on("claim"):
        probe_full_claim_edges()
    if on("rewrite"):
        probe_full_rewrite()
    if on("evict"):
        probe_full_evict_subtree()
    if on("join"):
        probe_full_join_detach()
    if on("ccv"):
        probe_ccv()
    if on("min"):
        probe_min()
    bad = [r for r in RESULTS if r[0] == "!!!"]
    print(f"\n{len(RESULTS)} probes, {len(bad)} unexpected outcomes")
    for r in bad:
        print("  ", r[1], "->", r[2], r[3])
