#!/usr/bin/env python3
"""End-to-end execution of the LayerTree scripts in the simulator (both profiles)."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import layertree_ref as lt  # noqa: E402
import layertree_scripts as ls  # noqa: E402
from script_sim import (Interp, ScriptError, TxContext, assemble, pubkey_x,  # noqa: E402
                        schnorr_sign)

FAILS = 0
CHECKS = 0
P2WPKH = b"\x00\x14" + bytes(20)
# The tree_id every suite's trees are created with (spec 6.2): the
# RECOMMENDED derivation over a placeholder creation outpoint. The golden
# vectors and the Go tests use the same value.
TREE_ID = lt.tree_id(lt.sha256(b"creation-txid"), 0)

# Design constraint (spec section 4.4): scripts compose ONLY existing candidate
# opcodes. Any opcode outside this inventory is a test failure.
BIP342_OPS = {"OP_0", "OP_1", "OP_2DROP", "OP_2DUP", "OP_2SWAP", "OP_ABS", "OP_ADD", "OP_1ADD",
              "OP_CHECKLOCKTIMEVERIFY", "OP_CHECKSIGVERIFY", "OP_CHECKSIG", "OP_DROP",
              "OP_DUP", "OP_ELSE", "OP_ENDIF", "OP_EQUAL", "OP_EQUALVERIFY",
              "OP_FROMALTSTACK", "OP_IF", "OP_LESSTHANOREQUAL", "OP_NIP", "OP_NOT",
              "OP_NOTIF", "OP_NUMEQUAL", "OP_NUMEQUALVERIFY", "OP_OVER", "OP_PICK",
              "OP_ROLL", "OP_ROT", "OP_SHA256", "OP_SIZE", "OP_SUB", "OP_SWAP",
              "OP_TOALTSTACK", "OP_TUCK", "OP_VERIFY", "OP_0NOTEQUAL", "OP_BOOLAND"}
BIP441_OPS = {"OP_CAT", "OP_SUBSTR", "OP_LEFT", "OP_RIGHT", "OP_AND", "OP_DOWNSHIFT"}
OPTX_OPS = {"OP_TX"}
BIP348_OPS = {"OP_CHECKSIGFROMSTACK"}
ECOPS_OPS = {"OP_EC_POINT_ADD", "OP_EC_POINT_MUL", "OP_EC_POINT_X_COORD"}
ALLOWED_OPCODES = BIP342_OPS | BIP441_OPS | OPTX_OPS | BIP348_OPS | ECOPS_OPS
MINIMAL_OPCODES = BIP342_OPS | {"OP_CAT"} | OPTX_OPS | {"OP_TWEAKADD"}


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
    def __init__(self, depth, profile, join_heights=(0, 2), exit_ks=(1, 2), tree_id=TREE_ID, scripts=None):
        """A tree of the reference set, or of the script set `scripts`
        (a TreeOptions.at_depth result) when one is given."""
        self.depth, self.profile = depth, profile
        self.op_sk = sk("operator")
        self.op_pk = pubkey_x(self.op_sk)
        self.tree_id = tree_id
        self.scripts = scripts if scripts is not None else ls.all_scripts(
            depth, self.op_pk, join_heights, exit_ks, profile, tree_id=tree_id)
        for name, toks in self.scripts.items():
            bad = {t for t in toks if isinstance(t, str)} - ALLOWED_OPCODES
            check(not bad, f"{name}: opcodes outside the candidate set: {sorted(bad)}")
        self.compiled = {k: assemble(v) for k, v in self.scripts.items()}
        self.m = lt.taptree_root([lt.tapleaf_hash(c) for c in self.compiled.values()])
        self.tree = lt.Tree(depth)

    # -- helpers -----------------------------------------------------------
    def slot(self, leaf, want=None):
        return leaf.position(self.depth) if self.profile == "S" else want

    def path_witness(self, path, height=0):
        """Witness items for a path, bottom..top (level D-1 first)."""
        items = []
        if self.profile == "D":
            for d, sib in reversed(path):
                items += [b"\x01" if d else b"", sc_bytes(sib)]
        elif ls.COMPRESSION["S"] == "bitmap":
            _, nodes = lt.path_bitmap(path, height)
            items += list(reversed(nodes))          # level D-1 first
        else:
            for _, sc in reversed(lt.compress_path(path, height)):
                items.append(sc)
        return items

    def bm(self, path, height=0):
        """Bitmap witness element(s): [bm] for bitmap compression, [] otherwise."""
        if self.profile == "S" and ls.COMPRESSION["S"] == "bitmap":
            return [lt.path_bitmap(path, height)[0]]
        return []

    def spk(self, root=None):
        root = root or self.tree.root()
        return lt.tree_spk(root[0], self.m)

    def run(self, name, witness, ctx):
        it = Interp(ctx)
        it.run(self.compiled[name], witness)
        return it

    def ctx(self, outputs, extra_in=None, locktime=0):
        root = self.tree.root()
        inputs = [(root[1], self.spk(root))]
        if extra_in:
            inputs.append(extra_in)
        return TxContext(inputs, outputs, locktime=locktime)

    def clone(self):
        t = lt.Tree(self.depth)
        t.leaves = dict(self.tree.leaves)
        return t


def mk_leaf(label, amount, evictor=None, evict_after=0, nonce=None, seq=0):
    if nonce is None:
        nonce = int.from_bytes(lt.sha256(label.encode())[:4], "little")
    return lt.Leaf(amount, pubkey_x(sk(label + "-exit")), pubkey_x(sk(label + "-owner")),
                   evictor if evictor else lt.NUMS_X, evict_after, nonce, seq)


def carve_of(src, label, amount, nonce=None):
    """A leaf carved out of src by CLAIM or SPLIT: it keeps src's evictor_key
    and evict_after, as spec 7.5 rule 5 requires."""
    return mk_leaf(label, amount, src.evictor_key, src.evict_after, nonce)


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
    outputs = [(r1[1], w.spk(r1)), (bob.amount - fee, lt.p2tr_spk(bob.exit_key)), (49_000, P2WPKH)]
    ctx = w.ctx(outputs, extra_in=(50_000, P2WPKH))
    sig = schnorr_sign(ctx.sighash(), sk("bob-owner"))
    wit = w.path_witness(path) + w.bm(path) + [bob.serialize(), sig, b"", root[0], w.m]
    record("EXIT_1 (owner)", w.run("EXIT_1", wit, ctx), wit)

    expect_fail(lambda: w.run("EXIT_1", wit[:-1] + [lt.sha256(b"evil")], ctx), "wrong merkle root")
    bad = list(outputs); bad[1] = (bob.amount + 1, lt.p2tr_spk(bob.exit_key))
    ctx2 = w.ctx(bad, extra_in=(50_000, P2WPKH)); sig2 = schnorr_sign(ctx2.sighash(), sk("bob-owner"))
    expect_fail(lambda: w.run("EXIT_1", w.path_witness(path) + w.bm(path) + [bob.serialize(), sig2, b"", root[0], w.m], ctx2), "exit output too large")
    bad = list(outputs); bad[0] = (root[1], w.spk(r1))
    ctx3 = w.ctx(bad, extra_in=(200_000, P2WPKH)); sig3 = schnorr_sign(ctx3.sighash(), sk("bob-owner"))
    expect_fail(lambda: w.run("EXIT_1", w.path_witness(path) + w.bm(path) + [bob.serialize(), sig3, b"", root[0], w.m], ctx3), "tree amount not conserved")
    sig4 = schnorr_sign(ctx.sighash(), sk("alice-owner"))
    expect_fail(lambda: w.run("EXIT_1", w.path_witness(path) + w.bm(path) + [bob.serialize(), sig4, b"", root[0], w.m], ctx), "wrong owner key")
    fake = bob.with_amount_seq(bob.amount + 1, 0)
    expect_fail(lambda: w.run("EXIT_1", w.path_witness(path) + w.bm(path) + [fake.serialize(), sig, b"", root[0], w.m], ctx), "forged leaf amount")
    bad = list(outputs); bad[0] = (r1[1], w.spk(root))
    ctx5 = w.ctx(bad, extra_in=(50_000, P2WPKH)); sig5 = schnorr_sign(ctx5.sighash(), sk("bob-owner"))
    expect_fail(lambda: w.run("EXIT_1", w.path_witness(path) + w.bm(path) + [bob.serialize(), sig5, b"", root[0], w.m], ctx5), "stale root in output")
    if profile == "S":
        # a non-empty sc supplied where the sibling is empty (or vice versa) must fail
        wrong = list(w.path_witness(path))
        wrong[0] = sc_bytes(lt.empty_node(D - 1)) if wrong[0] == b"" else b""
        expect_fail(lambda: w.run("EXIT_1", wrong + [bob.serialize(), sig, b"", root[0], w.m], ctx), "sparse: explicit empty sibling")

    # ---------------- EXIT_1 evict ----------------
    outputs_e = [(r1[1], w.spk(r1)), (bob.amount, lt.p2tr_spk(bob.exit_key))]
    ctx_e = w.ctx(outputs_e, extra_in=(5_000, P2WPKH), locktime=800_000)
    esig = schnorr_sign(ctx_e.sighash(), w.op_sk)
    wit_e = w.path_witness(path) + w.bm(path) + [bob.serialize(), esig, b"\x01", root[0], w.m]
    record("EXIT_1 (evict)", w.run("EXIT_1", wit_e, ctx_e), wit_e)
    ctx_early = w.ctx(outputs_e, extra_in=(5_000, P2WPKH), locktime=799_999)
    esig2 = schnorr_sign(ctx_early.sighash(), w.op_sk)
    expect_fail(lambda: w.run("EXIT_1", w.path_witness(path) + w.bm(path) + [bob.serialize(), esig2, b"\x01", root[0], w.m], ctx_early), "evict before evict_after")
    outputs_e2 = [(r1[1], w.spk(r1)), (bob.amount - 1, lt.p2tr_spk(bob.exit_key))]
    ctx_e2 = w.ctx(outputs_e2, extra_in=(5_000, P2WPKH), locktime=800_000)
    esig3 = schnorr_sign(ctx_e2.sighash(), w.op_sk)
    expect_fail(lambda: w.run("EXIT_1", w.path_witness(path) + w.bm(path) + [bob.serialize(), esig3, b"\x01", root[0], w.m], ctx_e2), "evictor may not shortchange")
    apath = w.tree.path(s_alice)
    t_a = w.clone(); del t_a.leaves[s_alice]
    outputs_a = [(t_a.root()[1], w.spk(t_a.root())), (alice.amount, lt.p2tr_spk(alice.exit_key))]
    ctx_a = w.ctx(outputs_a, extra_in=(5_000, P2WPKH))
    asig = schnorr_sign(ctx_a.sighash(), w.op_sk)
    expect_fail(lambda: w.run("EXIT_1", w.path_witness(apath) + w.bm(apath) + [alice.serialize(), asig, b"\x01", root[0], w.m], ctx_a), "NUMS evictor")
    w.tree = t1

    # ---------------- JOIN ----------------
    carol = mk_leaf("carol", 30_000, w.op_pk, 900_000)
    dave = mk_leaf("dave", 70_000, w.op_pk, 900_000)
    root = w.tree.root()
    if profile == "D":
        h, idx = 2, 2
        jpath = w.tree.path(idx << h, height=h)
        t2 = w.clone(); lt.apply_join(t2, h, idx, {0: carol, 3: dave})
        new_node, r2 = t2.subtree(h, idx), t2.root()
        outputs = [(r2[1], w.spk(r2)), (900, P2WPKH)]
        ctx = w.ctx(outputs, extra_in=(new_node[1] + 2_000, P2WPKH))
        osig = schnorr_sign(ctx.sighash(), w.op_sk)
        wit = w.path_witness(jpath, h) + [new_node[0], lt.le64(new_node[1]), osig, root[0], w.m]
        record("JOIN_2", w.run("JOIN_2", wit, ctx), wit)
        jpath_bad = w.tree.path(0, height=h)
        expect_fail(lambda: w.run("JOIN_2", w.path_witness(jpath_bad, h) + [new_node[0], lt.le64(new_node[1]), osig, root[0], w.m], ctx), "join over occupied subtree")
        bad = [(r2[1] - 1, w.spk(r2))]
        ctxb = w.ctx(bad, extra_in=(new_node[1] + 2_000, P2WPKH)); osigb = schnorr_sign(ctxb.sighash(), w.op_sk)
        expect_fail(lambda: w.run("JOIN_2", w.path_witness(jpath, h) + [new_node[0], lt.le64(new_node[1]), osigb, root[0], w.m], ctxb), "join underfunded")
        usig = schnorr_sign(ctx.sighash(), sk("alice-owner"))
        expect_fail(lambda: w.run("JOIN_2", w.path_witness(jpath, h) + [new_node[0], lt.le64(new_node[1]), usig, root[0], w.m], ctx), "join without operator")
        w.tree = t2
        s_carol, s_dave = (idx << h), (idx << h) + 3
    else:
        # sparse: two single-leaf joins
        for lf in (carol, dave):
            root = w.tree.root()
            slot = w.slot(lf)
            jpath = w.tree.path(slot)
            t2 = w.clone(); t2.leaves[slot] = lf
            r2 = t2.root()
            ctx = w.ctx([(r2[1], w.spk(r2))], extra_in=(lf.amount + 500, P2WPKH))
            osig = schnorr_sign(ctx.sighash(), w.op_sk)
            wit = w.path_witness(jpath) + w.bm(jpath) + [lf.serialize(), osig, root[0], w.m]
            record("JOIN_0", w.run("JOIN_0", wit, ctx), wit)
            w.tree = t2
        s_carol, s_dave = w.slot(carol), w.slot(dave)
        # negative: join at an occupied derived position (same owner+nonce as alice)
        root = w.tree.root()
        dup = lt.Leaf(1_000, alice.exit_key, alice.owner_key, alice.evictor_key, 0, alice.nonce, 0)
        slot = w.slot(dup)
        check(slot == s_alice, "duplicate (owner, nonce) derives the same position")
        jpath = w.tree.path(slot)
        t_bad = w.clone(); t_bad.leaves[slot] = dup
        ctx = w.ctx([(t_bad.root()[1], w.spk(t_bad.root()))], extra_in=(2_000, P2WPKH))
        osig = schnorr_sign(ctx.sighash(), w.op_sk)
        expect_fail(lambda: w.run("JOIN_0", w.path_witness(jpath) + w.bm(jpath) + [dup.serialize(), osig, root[0], w.m], ctx), "sparse join over occupied position")
        usig = schnorr_sign(ctx.sighash(), sk("alice-owner"))
        expect_fail(lambda: w.run("JOIN_0", w.path_witness(jpath) + w.bm(jpath) + [dup.serialize(), usig, root[0], w.m], ctx), "join without operator")

    # single-leaf JOIN_0 (both profiles)
    root = w.tree.root()
    erin = mk_leaf("erin", 12_345, w.op_pk, 900_000)
    s_erin = w.slot(erin, 9)
    jpath0 = w.tree.path(s_erin)
    t3 = w.clone(); t3.leaves[s_erin] = erin
    r3 = t3.root()
    ctx = w.ctx([(r3[1], w.spk(r3))], extra_in=(erin.amount + 500, P2WPKH))
    osig = schnorr_sign(ctx.sighash(), w.op_sk)
    if profile == "D":
        wit = w.path_witness(jpath0) + [erin.hash(), lt.le64(erin.amount), osig, root[0], w.m]
    else:
        wit = w.path_witness(jpath0) + w.bm(jpath0) + [erin.serialize(), osig, root[0], w.m]
    record("JOIN_0", w.run("JOIN_0", wit, ctx), wit)
    w.tree = t3

    if profile == "S" and ls.COMPRESSION["S"] == "bitmap":
        # bitmap compression is implemented for the single-path scripts only
        if verbose:
            print(f"\nprofile=S/bitmap D={depth}")
            for k, (it, sl, wl) in costs.items():
                print(f"{k:18} {sl:9} {wl:10} {it.cost:10}")
        return costs, w

    # ---------------- JOINK_2: two single-leaf joins in one tx ----------------
    root = w.tree.root()
    def free_leaf(label, amount, want, taken):
        """Like a real joiner: retry the nonce until the derived position is free."""
        lf = mk_leaf(label, amount, w.op_pk, 900_000)
        while profile == "S" and (w.slot(lf) in w.tree.leaves or w.slot(lf) in taken):
            lf = mk_leaf(label, amount, w.op_pk, 900_000, nonce=lf.nonce + 1)
        return lf, w.slot(lf, want)
    hank, s_hank = free_leaf("hank", 9_000, 12, set())
    ivy, s_ivy = free_leaf("ivy", 11_000, 13, {s_hank})
    tj = w.clone()
    path_h = tj.path(s_hank); tj.leaves[s_hank] = hank
    path_i = tj.path(s_ivy); tj.leaves[s_ivy] = ivy       # path after hank inserted
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
    wit = b2 + b1 + [osig, root[0], w.m]
    record("JOINK_2", w.run("JOINK_2", wit, ctx), wit)
    expect_fail(lambda: w.run("JOINK_2", b2_stale + b1 + [osig, root[0], w.m], ctx), "JOINK_2 stale second path")
    ctxu = w.ctx([(rj[1] - 1, w.spk(rj))], extra_in=(hank.amount + ivy.amount + 700, P2WPKH))
    osigu = schnorr_sign(ctxu.sighash(), w.op_sk)
    expect_fail(lambda: w.run("JOINK_2", b2 + b1 + [osigu, root[0], w.m], ctxu), "JOINK_2 underfunded")
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
    wit = w.path_witness(upath) + w.bm(upath) + [alice.serialize(), alice2.serialize(), asig, osig, root[0], w.m]
    record("UPDATE", w.run("UPDATE", wit, ctx), wit)
    expect_fail(lambda: w.run("UPDATE", w.path_witness(upath) + w.bm(upath) + [alice.serialize(), alice2.serialize(), osig, osig, root[0], w.m], ctx), "update without owner")
    if profile == "S":
        moved = lt.Leaf(80_000, alice.exit_key, alice.owner_key, alice.evictor_key, 0, alice.nonce + 1, 1)
        t_m = w.clone(); del t_m.leaves[s_alice]; t_m.leaves[w.slot(moved)] = moved
        ctxm = w.ctx([(t_m.root()[1], w.spk(t_m.root()))], extra_in=(30_700, P2WPKH))
        osm = schnorr_sign(ctxm.sighash(), w.op_sk); asm_ = schnorr_sign(ctxm.sighash(), sk("alice-owner"))
        expect_fail(lambda: w.run("UPDATE", w.path_witness(upath) + w.bm(upath) + [alice.serialize(), moved.serialize(), asm_, osm, root[0], w.m], ctxm), "sparse update changing position")
    w.tree = t4

    # ---------------- CLAIM ----------------
    root = w.tree.root()
    src = w.tree.leaves[s_oper]
    frank = carve_of(src, "frank", 40_000)
    s_frank = w.slot(frank, 3)
    spath = w.tree.path(s_oper)
    t5 = w.clone(); lt.apply_claim(t5, s_oper, s_frank, frank)
    cpath = t5.path(s_frank)
    r5 = t5.root()
    check(r5[1] == root[1], "claim conserves sum")
    ctx = w.ctx([(r5[1], w.spk(r5))], extra_in=(600, P2WPKH))
    vmsg = lt.voucher_msg(w.tree_id, src, frank)
    vsig = schnorr_sign(vmsg, sk("operator-owner"))
    wit = w.path_witness(cpath) + w.path_witness(spath) + w.bm(spath) + [src.serialize()] + w.bm(cpath) + [frank.serialize(), vsig, root[0], w.m]
    record("CLAIM", w.run("CLAIM", wit, ctx), wit)
    # replay after the source leaf changed
    frank2 = carve_of(src, "frank2", 40_000)
    s_frank2 = w.slot(frank2, 4)
    t6 = lt.Tree(D); t6.leaves = dict(t5.leaves)
    spath2 = t5.path(s_oper)
    lt.apply_claim(t6, s_oper, s_frank2, frank2)
    cpath2 = t6.path(s_frank2)
    ctx6 = TxContext([(r5[1], w.spk(r5)), (600, P2WPKH)], [(t6.root()[1], w.spk(t6.root()))])
    expect_fail(lambda: w.run("CLAIM", w.path_witness(cpath2) + w.path_witness(spath2) + w.bm(spath2) + [src.serialize()] + w.bm(cpath2) + [frank2.serialize(), vsig, r5[0], w.m], ctx6), "voucher replay / wrong leaf")
    greedy = carve_of(src, "greedy", src.amount + 1)
    gsig = schnorr_sign(lt.voucher_msg(w.tree_id, src, greedy), sk("operator-owner"))
    expect_fail(lambda: w.run("CLAIM", w.path_witness(cpath) + w.path_witness(spath) + w.bm(spath) + [src.serialize()] + w.bm(cpath) + [greedy.serialize(), gsig, root[0], w.m], ctx), "over-claim underflow")
    # 7.5 rule 5: the claim leaf keeps the source's evictor and lease. The
    # source has a NUMS evictor and evict_after 0, so a claim naming the
    # operator, or any later evict_after, fails even under a valid voucher.
    for label, lf in (("another evictor key", mk_leaf("escape", 40_000, w.op_pk, src.evict_after)),
                      ("a later evict_after", mk_leaf("later", 40_000, None, src.evict_after + 1))):
        esig = schnorr_sign(lt.voucher_msg(w.tree_id, src, lf), sk("operator-owner"))
        t_e = w.clone(); t_e.leaves[s_oper] = src.with_amount_seq(src.amount - lf.amount, src.seq + 1)
        s_e = w.slot(lf, 3); t_e.leaves[s_e] = lf
        ctx_e = w.ctx([(t_e.root()[1], w.spk(t_e.root()))], extra_in=(600, P2WPKH))
        expect_fail(lambda: w.run("CLAIM", w.path_witness(t_e.path(s_e)) + w.path_witness(spath) + w.bm(spath) + [src.serialize()] + w.bm(t_e.path(s_e)) + [lf.serialize(), esig, root[0], w.m], ctx_e),
                    f"CLAIM of a leaf with {label} than its source")
    # 7.5 rule 6: the claim leaf is at least DUST_MIN and the residual is
    # zero or at least DUST_MIN, so a sub-dust leaf, which no standard
    # transaction can remove, cannot be planted by a voucher
    for label, lf in (("one satoshi", carve_of(src, "dust1", 1)), ("zero satoshis", carve_of(src, "dust0", 0)),
                      ("a one-satoshi residual", carve_of(src, "dustr", src.amount - 1))):
        dsig = schnorr_sign(lt.voucher_msg(w.tree_id, src, lf), sk("operator-owner"))
        t_d = w.clone(); s_d = w.slot(lf, 3); lt.apply_claim(t_d, s_oper, s_d, lf)
        ctx_d = w.ctx([(t_d.root()[1], w.spk(t_d.root()))], extra_in=(600, P2WPKH))
        expect_fail(lambda: w.run("CLAIM", w.path_witness(t_d.path(s_d)) + w.path_witness(spath) + w.bm(spath) + [src.serialize()] + w.bm(t_d.path(s_d)) + [lf.serialize(), dsig, root[0], w.m], ctx_d),
                    f"CLAIM of {label} (7.5 rule 6)")
    floor = carve_of(src, "floor", lt.DUST_MIN)
    t_f = w.clone(); s_fl = w.slot(floor, 3); lt.apply_claim(t_f, s_oper, s_fl, floor)
    ctx_f = w.ctx([(t_f.root()[1], w.spk(t_f.root()))], extra_in=(600, P2WPKH))
    w.run("CLAIM", w.path_witness(t_f.path(s_fl)) + w.path_witness(spath) + w.bm(spath) + [src.serialize()] + w.bm(t_f.path(s_fl)) +
          [floor.serialize(), schnorr_sign(lt.voucher_msg(w.tree_id, src, floor), sk("operator-owner")), root[0], w.m], ctx_f)
    check(True, "CLAIM of exactly DUST_MIN succeeds")
    bsig = schnorr_sign(vmsg, sk("bob-owner"))
    expect_fail(lambda: w.run("CLAIM", w.path_witness(cpath) + w.path_witness(spath) + w.bm(spath) + [src.serialize()] + w.bm(cpath) + [frank.serialize(), bsig, root[0], w.m], ctx), "voucher wrong signer")
    # the voucher binds this tree's tree_id (6.2, 7.5): one signed for a
    # tree created at another outpoint, or over m as the pre-0.10.0 message
    # did, fails as a bad signature even against identical leaf bytes
    other_tid = lt.tree_id(lt.sha256(b"creation-txid"), 1)
    osig = schnorr_sign(lt.voucher_msg(other_tid, src, frank), sk("operator-owner"))
    expect_fail(lambda: w.run("CLAIM", w.path_witness(cpath) + w.path_witness(spath) + w.bm(spath) + [src.serialize()] + w.bm(cpath) + [frank.serialize(), osig, root[0], w.m], ctx), "voucher signed for another tree_id")
    msig = schnorr_sign(lt.voucher_msg(w.m, src, frank), sk("operator-owner"))
    expect_fail(lambda: w.run("CLAIM", w.path_witness(cpath) + w.path_witness(spath) + w.bm(spath) + [src.serialize()] + w.bm(cpath) + [frank.serialize(), msig, root[0], w.m], ctx), "voucher over m instead of tree_id")
    # 7.5: the voucher binds the source leaf without its amount, so an
    # amount-only increase of the source (what REWRITE_h rule 3 lets the
    # operator write alone) leaves it redeemable, against the leaf's
    # current amount; any other field change voids it.
    topped = src.with_amount_seq(src.amount + 500, src.seq)
    t_up = w.clone(); t_up.leaves[s_oper] = topped
    for label, lf in (("the voucher's amount", frank),
                      ("more than the balance at issuance", carve_of(src, "bigger", src.amount + 100))):
        s_c = w.slot(lf, 3)
        t_c = lt.Tree(D); t_c.leaves = dict(t_up.leaves); lt.apply_claim(t_c, s_oper, s_c, lf)
        r_c = t_c.root()
        ctx_c = TxContext([(t_up.root()[1], w.spk(t_up.root())), (600, P2WPKH)], [(r_c[1], w.spk(r_c))])
        csig = schnorr_sign(lt.voucher_msg(w.tree_id, src, lf), sk("operator-owner"))
        w.run("CLAIM", w.path_witness(t_c.path(s_c)) + w.path_witness(t_up.path(s_oper)) + w.bm(t_up.path(s_oper)) + [topped.serialize()] +
              w.bm(t_c.path(s_c)) + [lf.serialize(), csig, t_up.root()[0], w.m], ctx_c)
        check(True, f"CLAIM: a voucher signed before an amount-only top-up redeems {label} afterwards")
    over = carve_of(src, "over", topped.amount + 1)
    osig2 = schnorr_sign(lt.voucher_msg(w.tree_id, src, over), sk("operator-owner"))
    expect_fail(lambda: w.run("CLAIM", w.path_witness(cpath) + w.path_witness(t_up.path(s_oper)) + w.bm(t_up.path(s_oper)) + [topped.serialize()] +
                w.bm(cpath) + [over.serialize(), osig2, t_up.root()[0], w.m],
                TxContext([(t_up.root()[1], w.spk(t_up.root())), (600, P2WPKH)], [(r5[1], w.spk(r5))])),
                "CLAIM: over-claim against the topped-up balance")
    for label, lf in (("exit_key", lt.Leaf(src.amount, pubkey_x(sk("other-exit")), src.owner_key, src.evictor_key, src.evict_after, src.nonce, src.seq)),
                      ("owner_key", lt.Leaf(src.amount, src.exit_key, pubkey_x(sk("other-owner")), src.evictor_key, src.evict_after, src.nonce, src.seq)),
                      ("evictor_key", lt.Leaf(src.amount, src.exit_key, src.owner_key, w.op_pk, src.evict_after, src.nonce, src.seq)),
                      ("evict_after", lt.Leaf(src.amount, src.exit_key, src.owner_key, src.evictor_key, src.evict_after + 1, src.nonce, src.seq)),
                      ("nonce", lt.Leaf(src.amount, src.exit_key, src.owner_key, src.evictor_key, src.evict_after, src.nonce + 1, src.seq)),
                      ("seq", src.with_amount_seq(src.amount, src.seq + 1))):
        # the voucher check runs before any path is folded, so the rest of
        # the witness can stay as it is: the signature over the old body
        # does not verify against the changed leaf
        expect_fail(lambda: w.run("CLAIM", w.path_witness(cpath) + w.path_witness(spath) + w.bm(spath) + [lf.serialize()] + w.bm(cpath) + [frank.serialize(), vsig, root[0], w.m], ctx),
                    f"CLAIM: a voucher against a source whose {label} changed")
    w.tree = t5

    # ---------------- EXIT_2: carol (owner) + dave (evict) ----------------
    root = w.tree.root()
    t7 = w.clone()
    path_c = t7.path(s_carol); del t7.leaves[s_carol]
    path_d = t7.path(s_dave); del t7.leaves[s_dave]
    r7 = t7.root()
    outputs = [(r7[1], w.spk(r7)), (carol.amount - 300, lt.p2tr_spk(carol.exit_key)), (dave.amount, lt.p2tr_spk(dave.exit_key))]
    ctx = w.ctx(outputs, extra_in=(5_000, P2WPKH), locktime=900_000)
    csig = schnorr_sign(ctx.sighash(), sk("carol-owner")); dsig = schnorr_sign(ctx.sighash(), w.op_sk)
    block2 = w.path_witness(path_d) + w.bm(path_d) + [dave.serialize(), dsig, b"\x01"]
    block1 = w.path_witness(path_c) + w.bm(path_c) + [carol.serialize(), csig, b""]
    wit = block2 + block1 + [root[0], w.m]
    record("EXIT_2", w.run("EXIT_2", wit, ctx), wit)
    stale_d = w.tree.path(s_dave)
    expect_fail(lambda: w.run("EXIT_2", w.path_witness(stale_d) + w.bm(stale_d) + [dave.serialize(), dsig, b"\x01"] + block1 + [root[0], w.m], ctx), "EXIT_2 stale second path")
    bad = list(outputs); bad[2] = (dave.amount - 1, lt.p2tr_spk(dave.exit_key))
    ctxb = w.ctx(bad, extra_in=(5_000, P2WPKH), locktime=900_000)
    csb = schnorr_sign(ctxb.sighash(), sk("carol-owner")); dsb = schnorr_sign(ctxb.sighash(), w.op_sk)
    expect_fail(lambda: w.run("EXIT_2", w.path_witness(path_d) + w.bm(path_d) + [dave.serialize(), dsb, b"\x01"] + w.path_witness(path_c) + w.bm(path_c) + [carol.serialize(), csb, b""] + [root[0], w.m], ctxb), "EXIT_2 evictee shortchanged")
    w.tree = t7

    # ---------------- CLAIM draining the source -> E_0 ----------------
    root = w.tree.root()
    src2 = w.tree.leaves[s_erin]
    gina = carve_of(src2, "gina", src2.amount)
    s_gina = w.slot(gina, 6)
    spath2 = w.tree.path(s_erin)
    t8 = w.clone(); del t8.leaves[s_erin]
    cpath_g = t8.path(s_gina); t8.leaves[s_gina] = gina
    r8 = t8.root()
    ctx = w.ctx([(r8[1], w.spk(r8))], extra_in=(600, P2WPKH))
    gsig = schnorr_sign(lt.voucher_msg(w.tree_id, src2, gina), sk("erin-owner"))
    wit = w.path_witness(cpath_g) + w.path_witness(spath2) + w.bm(spath2) + [src2.serialize()] + w.bm(cpath_g) + [gina.serialize(), gsig, root[0], w.m]
    w.run("CLAIM", wit, ctx)
    check(True, "claim full drain -> empty position")
    w.tree = t8

    # ---------------- terminal exit ----------------
    solo = mk_leaf("solo", 77_000)
    tiny = lt.Tree(D); tiny.leaves = {w.slot(solo, 2): solo}
    w.tree = tiny
    root = w.tree.root()
    spath = w.tree.path(w.slot(solo, 2))
    outputs = [(600, P2WPKH), (solo.amount - 400, lt.p2tr_spk(solo.exit_key))]
    ctx = w.ctx(outputs, extra_in=(1_000, P2WPKH))
    ssig = schnorr_sign(ctx.sighash(), sk("solo-owner"))
    it = w.run("EXIT_1", w.path_witness(spath) + w.bm(spath) + [solo.serialize(), ssig, b"", root[0], w.m], ctx)
    costs["EXIT_1 (terminal)"] = (it, len(w.compiled["EXIT_1"]), 0)
    w.tree = t8
    root = w.tree.root()
    apath = w.tree.path(s_alice)
    outputs = [(600, P2WPKH), (alice2.amount, lt.p2tr_spk(alice2.exit_key))]
    ctx = w.ctx(outputs, extra_in=(1_000, P2WPKH))
    asig = schnorr_sign(ctx.sighash(), sk("alice-owner"))
    expect_fail(lambda: w.run("EXIT_1", w.path_witness(apath) + w.bm(apath) + [alice2.serialize(), asig, b"", root[0], w.m], ctx), "non-terminal exit with unconstrained output 0")

    if verbose:
        print(f"\nprofile={profile} D={depth}  taptree leaves={len(w.compiled)}  m={w.m.hex()[:16]}…")
        print(f"{'transition':18} {'script B':>9} {'witness B':>10} {'varops':>10} {'sigops':>6} {'maxdepth':>8}")
        for k, (it, sl, wl) in costs.items():
            print(f"{k:18} {sl:9} {wl:10} {it.cost:10} {it.sigchecks:6} {it.max_depth:8}")
    return costs, w


def test_minimal(depth, verbose=True):
    """EXIT_1 built from the minimal inventory (spec 4.5)."""
    toks = ls.exit_script_min(depth)
    bad = {t for t in toks if isinstance(t, str)} - MINIMAL_OPCODES
    check(not bad, f"minimal EXIT_1 uses non-minimal opcodes: {sorted(bad)}")
    script = assemble(toks)
    w = World(depth, "D")
    # taptree: replace EXIT_1 by the minimal script so m is consistent
    w.compiled = dict(w.compiled); w.compiled["EXIT_1"] = script
    w.m = lt.taptree_root([lt.tapleaf_hash(c) for c in w.compiled.values()])
    alice = mk_leaf("alice", 50_000)
    bob = mk_leaf("bob", 125_000, evictor=w.op_pk, evict_after=800_000)
    w.tree.leaves = {0: alice, 5: bob, (1 << depth) - 1: mk_leaf("operator", 1_000_000)}
    root = w.tree.root()
    path = w.tree.path(5)
    t1 = w.clone(); del t1.leaves[5]; r1 = t1.root()

    def fields(lf):
        b = lf.serialize()
        return [b[0:8], b[8:40], b[40:72], b[72:104], b[104:108], b[108:112], b[112:116]]

    def pw(path):
        items = []
        for d, sib in reversed(path):
            items += [b"\x01" if d else b"", sib[0], lt.le64(sib[1])]
        return items

    outputs = [(r1[1], w.spk(r1)), (bob.amount - 1_000, lt.p2tr_spk(bob.exit_key)), (49_000, P2WPKH)]
    ctx = w.ctx(outputs, extra_in=(50_000, P2WPKH))
    sig = schnorr_sign(ctx.sighash(), sk("bob-owner"))
    wit = pw(path) + fields(bob) + [sig, b"", root[0], w.m]
    it = w.run("EXIT_1", wit, ctx)
    # evict
    outputs_e = [(r1[1], w.spk(r1)), (bob.amount, lt.p2tr_spk(bob.exit_key))]
    ctx_e = w.ctx(outputs_e, extra_in=(5_000, P2WPKH), locktime=800_000)
    esig = schnorr_sign(ctx_e.sighash(), w.op_sk)
    w.run("EXIT_1", pw(path) + fields(bob) + [esig, b"\x01", root[0], w.m], ctx_e)
    # negatives
    expect_fail(lambda: w.run("EXIT_1", wit[:-1] + [lt.sha256(b"evil")], ctx), "min: wrong m")
    bad = list(outputs); bad[1] = (bob.amount + 1, lt.p2tr_spk(bob.exit_key))
    ctx2 = w.ctx(bad, extra_in=(50_000, P2WPKH)); sig2 = schnorr_sign(ctx2.sighash(), sk("bob-owner"))
    expect_fail(lambda: w.run("EXIT_1", pw(path) + fields(bob) + [sig2, b"", root[0], w.m], ctx2), "min: overpay")
    f = fields(bob); f[0] = lt.le64(bob.amount + 1)
    expect_fail(lambda: w.run("EXIT_1", pw(path) + f + [sig, b"", root[0], w.m], ctx), "min: forged amount")
    f = fields(bob); f[2], f[3] = f[2][1:], f[2][:1] + f[3]   # shift a field boundary
    expect_fail(lambda: w.run("EXIT_1", pw(path) + f + [sig, b"", root[0], w.m], ctx), "min: shifted field boundary")
    ctx_early = w.ctx(outputs_e, extra_in=(5_000, P2WPKH), locktime=799_999)
    esig2 = schnorr_sign(ctx_early.sighash(), w.op_sk)
    expect_fail(lambda: w.run("EXIT_1", pw(path) + fields(bob) + [esig2, b"\x01", root[0], w.m], ctx_early), "min: early evict")
    if verbose:
        print(f"\nminimal-inventory EXIT_1 D={depth}: script {len(script)} B, witness {sum(len(x) for x in wit)} B, varops {it.cost}")
    return script, wit, it


def test_sibling_sum_binding(depth, profile, verbose=True):
    """Regression test for taproot-assets-private issue 112 (sibling-sum binding).

    A proof element carries a sibling's hash and its declared sum. If the
    parent hash did not commit to the children's sums, a prover could keep a
    sibling's hash and inflate its sum, and the fold would reach the right
    root hash with a wrong total. LayerTree's node format excludes this:
    `H_node(lh || enc64(ls) || rh || enc64(rs))` hashes both sums into the
    parent, so a sibling whose sum is altered produces a different parent
    hash at that level and the fold cannot reach `r` (spec 5.3, 10.2).

    The test must not be satisfied by the amount checks alone. `CHECK_OLD`
    compares the folded old sum with input 0's amount, which an inflated
    sibling would also fail, so each forged proof is paired with a
    transaction whose input 0 carries the forged total and whose output 0
    commits to the forged new root. Under a sum-blind node hash that
    transaction would validate; here it must fail at every level, in both
    profiles, and an explicitly supplied empty sibling with a non-zero sum
    (the sparse profile's version of the forgery) must fail as well.
    """
    w = World(depth, profile)
    bob = mk_leaf("bob", 125_000)
    others = [mk_leaf(n, a) for n, a in (("alice", 50_000), ("carol", 30_000), ("dave", 70_000),
                                         ("erin", 15_000), ("operator", 1_000_000))]
    s_bob = w.slot(bob, 5)
    w.tree.leaves = {s_bob: bob}
    for i, lf in enumerate(others):
        w.tree.leaves[w.slot(lf, [0, 3, 9, 12, (1 << depth) - 1][i])] = lf
    root = w.tree.root()
    S = root[1]
    path = w.tree.path(s_bob)
    t1 = w.clone(); del t1.leaves[s_bob]
    r1 = t1.root()

    def spend(forged, S_in):
        """Witness and transaction for an owner exit of bob against `forged`,
        with input 0 carrying S_in and output 0 the forged new root."""
        new_root = lt.fold(lt.EMPTY_NODE, forged)
        ctx = TxContext([(S_in, w.spk(root)), (50_000, P2WPKH)],
                        [(new_root[1], w.spk(new_root)), (bob.amount - 1_000, lt.p2tr_spk(bob.exit_key))])
        sig = schnorr_sign(ctx.sighash(), sk("bob-owner"))
        return w.path_witness(forged) + w.bm(forged) + [bob.serialize(), sig, b"", root[0], w.m], ctx

    # control: the honest proof under the same harness succeeds
    wit, ctx = spend(path, S)
    w.run("EXIT_1", wit, ctx)
    check(lt.fold(lt.EMPTY_NODE, path) == r1, "sibling-sum control: honest fold reaches r1")
    n_levels = 0
    for k, (d, sib) in enumerate(path):
        for delta in (+1, -1):
            if sib[1] + delta < 0:
                continue
            forged = list(path)
            forged[k] = (d, (sib[0], sib[1] + delta))
            # the forgery is arithmetically consistent: only the hash binding is left
            check(lt.fold(bob.node(), forged)[1] == S + delta, f"level {k}: forged total is S{delta:+d}")
            check(lt.fold(bob.node(), forged)[0] != root[0], f"level {k}: forged fold misses r (sums are hashed)")
            wit, ctx = spend(forged, S + delta)
            expect_fail(lambda: w.run("EXIT_1", wit, ctx),
                        f"{profile} D={depth} level {k}: sibling hash kept, sum {delta:+d} (issue 112)")
            n_levels += 1
    if verbose:
        print(f"sibling-sum binding {profile} D={depth}: {n_levels} forged proofs rejected")


def test_evict_subtree(depth, height, verbose=True):
    """Cohort sweep: evict every leaf of an aligned subtree in one spend."""
    w = World(depth, "D")
    script = assemble(ls.evict_subtree_script(depth, height, w.op_pk))
    bad = {t for t in ls.evict_subtree_script(depth, height, w.op_pk) if isinstance(t, str)} - ALLOWED_OPCODES
    check(not bad, f"EVICT_SUBTREE uses non-candidate opcodes: {sorted(bad)}")
    w.compiled = dict(w.compiled); w.compiled[f"EVICT_SUBTREE_{height}"] = script
    w.m = lt.taptree_root([lt.tapleaf_hash(c) for c in w.compiled.values()])
    n = 1 << height
    base = 1 << height                        # subtree index 1 -> positions [n, 2n)
    cohort = {}
    for i in range(n):
        if i % 5 == 3:                        # some positions already exited
            continue
        cohort[base + i] = mk_leaf(f"c{i}", 10_000 + 7 * i, w.op_pk, 800_000)
    w.tree.leaves = dict(cohort)
    w.tree.leaves[0] = mk_leaf("alice", 50_000)
    w.tree.leaves[(1 << depth) - 1] = mk_leaf("operator", 1_000_000)
    root = w.tree.root()
    path = w.tree.path(base, height=height)
    t1 = w.clone()
    for p in cohort:
        del t1.leaves[p]
    r1 = t1.root()
    outputs = [(r1[1], w.spk(r1))]
    for i in range(n):
        if base + i in cohort:
            lf = cohort[base + i]
            outputs.append((lf.amount, lt.p2tr_spk(lf.exit_key)))
    outputs.append((400, P2WPKH))
    ctx = w.ctx(outputs, extra_in=(5_000, P2WPKH), locktime=800_000)
    sig = schnorr_sign(ctx.sighash(), w.op_sk)
    leaves_rev = [cohort[base + i].serialize() if base + i in cohort else b"" for i in reversed(range(n))]
    wit = w.path_witness(path, height) + leaves_rev + [sig, root[0], w.m]
    it = w.run(f"EVICT_SUBTREE_{height}", wit, ctx)
    # negatives
    ctx_e = w.ctx(outputs, extra_in=(5_000, P2WPKH), locktime=799_999)
    sig_e = schnorr_sign(ctx_e.sighash(), w.op_sk)
    expect_fail(lambda: w.run(f"EVICT_SUBTREE_{height}", w.path_witness(path, height) + leaves_rev + [sig_e, root[0], w.m], ctx_e), "subtree sweep before lease expiry")
    bad_out = list(outputs); bad_out[1] = (outputs[1][0] - 1, outputs[1][1])
    ctx_b = w.ctx(bad_out, extra_in=(5_000, P2WPKH), locktime=800_000)
    sig_b = schnorr_sign(ctx_b.sighash(), w.op_sk)
    expect_fail(lambda: w.run(f"EVICT_SUBTREE_{height}", w.path_witness(path, height) + leaves_rev + [sig_b, root[0], w.m], ctx_b), "subtree sweep shortchanges a leaf")
    # a leaf with a NUMS evictor blocks the sweep
    t_n = w.clone(); stubborn = mk_leaf("stubborn", 5_000)   # NUMS evictor
    free = next(base + i for i in range(n) if base + i not in cohort)
    t_n.leaves[free] = stubborn; w.tree = t_n
    root_n = w.tree.root()
    lr = [w.tree.leaves[base + i].serialize() if base + i in w.tree.leaves else b"" for i in reversed(range(n))]
    outs_n = [(t1.root()[1], w.spk(t1.root()))] + [(w.tree.leaves[base + i].amount, lt.p2tr_spk(w.tree.leaves[base + i].exit_key)) for i in range(n) if base + i in w.tree.leaves]
    ctx_n = w.ctx(outs_n, extra_in=(5_000, P2WPKH), locktime=800_000)
    sig_n = schnorr_sign(ctx_n.sighash(), w.op_sk)
    expect_fail(lambda: w.run(f"EVICT_SUBTREE_{height}", w.path_witness(w.tree.path(base, height=height), height) + lr + [sig_n, root_n[0], w.m], ctx_n), "subtree sweep with a non-evictable leaf")
    if verbose:
        k_evict = len(assemble(ls.exit_script(depth, n, "D")))
        print(f"\nEVICT_SUBTREE_{height} D={depth}: {len(cohort)} leaves, script {len(script)} B, witness {sum(len(x) for x in wit)} B, varops {it.cost}, sigops {it.sigchecks};  EXIT_{n} script would be {k_evict} B")
    return script, wit, it





def _rewrite_plan(w, height, scenario):
    """Old and new elements for every position of an aligned height-h subtree.

    Returns (base, old, new): old and new map offset -> Leaf or None (empty).
    The scenarios are "mixed" (exits, an unchanged leaf, a key rotation, an
    amount-only increase, a payer, a lease renewal, a join into an empty
    position and an empty position left alone, in rotation), "update" (every
    position occupied and every leaf's key rotated), "exit" (every
    position occupied and every leaf leaving) and "topup" (every position
    occupied and every leaf's amount raised by 500, the operator's top-up
    of a cohort under 7.9 rule 3, which needs no owner signature).
    """
    n = 1 << height
    base = 1 << height                          # subtree index 1
    old, new = {}, {}
    for i in range(n):
        lf = mk_leaf(f"c{i}", 10_000 + 7 * i, w.op_pk, 800_000)
        rotated = lt.Leaf(lf.amount, lf.exit_key, pubkey_x(sk(f"c{i}-owner2")), lf.evictor_key,
                          lf.evict_after, lf.nonce, lf.seq)
        if scenario == "update":
            old[i], new[i] = lf, rotated
            continue
        if scenario == "topup":
            old[i], new[i] = lf, lf.with_amount_seq(lf.amount + 500, lf.seq)
            continue
        if scenario == "exit":
            old[i], new[i] = lf, None
            continue
        if i % 7 == 6:                           # empty position
            old[i] = None
            new[i] = mk_leaf(f"j{i}", 5_000 + i, w.op_pk, 900_000) if i % 2 == 0 else None
            continue
        old[i] = lf
        kind = i % 6
        if kind == 0:
            new[i] = None                                      # exit
        elif kind == 1:
            new[i] = lf                                        # unchanged
        elif kind == 2:
            new[i] = rotated                                   # key rotation
        elif kind == 3:
            new[i] = lf.with_amount_seq(lf.amount + 500, lf.seq)   # amount-only increase
        elif kind == 4:
            new[i] = lf.with_amount_seq(lf.amount - 300, lf.seq)   # payer
        else:
            new[i] = lt.Leaf(lf.amount, lf.exit_key, lf.owner_key, lf.evictor_key,
                             900_000, lf.nonce, lf.seq)        # lease renewal
    return base, old, new


def _needs_owner_sig(old, new):
    """Spec 7.9 rule 3, computed independently of the script."""
    if old is None or old == new or (new is not None and old.serialize() == new.serialize()):
        return False
    if (new is not None and new.serialize()[8:] == old.serialize()[8:] and new.amount >= old.amount
            and old.seq != ls.SEQ_FINAL):
        return False
    return True


def _rewrite_witness(w, height, path, old, new, ctx, root, sig_op, exit_consent, sign=True, marker=True):
    """Witness (bottom..top) for REWRITE_h: path, blocks for position 2^h-1 .. 0, sig_op, r, m.
    Returns (witness, signatures) where signatures maps offset -> [sig, xsig].
    With marker, an unchanged leaf's new element is the one-byte marker
    REWRITE_SAME (7.9); without it, a second copy of the leaf."""
    n = 1 << height
    sigs = {}
    blocks = []
    for i in reversed(range(n)):
        o, nw = old[i], new[i]
        block = []
        if _needs_owner_sig(o, nw) and sign:
            s = [schnorr_sign(ctx.sighash(), sk(f"c{i}-owner"))]
            if exit_consent:
                s.append(schnorr_sign(ctx.sighash(), sk(f"c{i}-exit")))
            sigs[i] = s
            block += list(reversed(s))           # xsig below sig
        if marker and o is not None and nw is not None and o.serialize() == nw.serialize():
            block.append(ls.REWRITE_SAME)
        else:
            block.append(nw.serialize() if nw else b"")
        block.append(o.serialize() if o else b"")
        blocks += block
    return w.path_witness(path, height) + blocks + [sig_op, root[0], w.m], sigs


def rewrite_case(depth, height, scenario="mixed", exit_consent=False):
    """Build a REWRITE_h spend for a scenario. Returns a dict with the world,
    script, witness, context, plan and the signatures, for tests and sizing."""
    name = f"REWRITE_X_{height}" if exit_consent else f"REWRITE_{height}"
    w = World(depth, "D")
    toks = ls.rewrite_script(depth, height, w.op_pk, exit_consent)
    bad = {t for t in toks if isinstance(t, str)} - ALLOWED_OPCODES
    check(not bad, f"{name} uses non-candidate opcodes: {sorted(bad)}")
    script = assemble(toks)
    w.compiled = dict(w.compiled); w.compiled[name] = script
    w.m = lt.taptree_root([lt.tapleaf_hash(c) for c in w.compiled.values()])
    base, old, new = _rewrite_plan(w, height, scenario)
    w.tree.leaves = {base + i: lf for i, lf in old.items() if lf}
    w.tree.leaves[0] = mk_leaf("alice", 50_000)
    w.tree.leaves[(1 << depth) - 1] = mk_leaf("operator", 1_000_000)
    root = w.tree.root()
    path = w.tree.path(base, height=height)
    t1 = w.clone()
    for i, lf in new.items():
        if lf:
            t1.leaves[base + i] = lf
        else:
            t1.leaves.pop(base + i, None)
    r1 = t1.root()
    delta = r1[1] - root[1]
    outputs = [(r1[1], w.spk(r1))]
    for i in range(1 << height):
        if old[i] and new[i] is None:
            outputs.append((old[i].amount, lt.p2tr_spk(old[i].exit_key)))
    outputs.append((400, P2WPKH))
    ctx = w.ctx(outputs, extra_in=(max(delta, 0) + 5_000, P2WPKH))
    sig_op = schnorr_sign(ctx.sighash(), w.op_sk)
    wit, sigs = _rewrite_witness(w, height, path, old, new, ctx, root, sig_op, exit_consent)
    return dict(name=name, w=w, script=script, wit=wit, ctx=ctx, root=root, r1=r1, t1=t1,
                path=path, base=base, old=old, new=new, sigs=sigs, sig_op=sig_op,
                outputs=outputs, delta=delta)


def test_rewrite(depth, height, exit_consent=False, verbose=True):
    """REWRITE_h (spec 7.9): rewrite a cohort's aligned subtree in one spend,
    with the mixed scenario of _rewrite_plan. Negatives target each rule."""
    c = rewrite_case(depth, height, "mixed", exit_consent)
    w, name, ctx, root, wit = c["w"], c["name"], c["ctx"], c["root"], c["wit"]
    old, new, sigs, path, base = c["old"], c["new"], c["sigs"], c["path"], c["base"]
    n = 1 << height
    it = w.run(name, wit, ctx)
    check(True, f"{name} D={depth}: mixed rewrite of {n} positions")
    check(c["ctx"].outputs[0][0] == root[1] + c["delta"], f"{name} output 0 is S + (sum new - sum old)")

    def rebuild(old_, new_, ctx_=ctx, path_=path, root_=root, sig_op_=None, sign=True, marker=True):
        so = sig_op_ if sig_op_ is not None else schnorr_sign(ctx_.sighash(), w.op_sk)
        return _rewrite_witness(w, height, path_, old_, new_, ctx_, root_, so, exit_consent, sign, marker)[0]

    # the unchanged position: published once with the marker (the witness
    # above), or twice as a full copy, which the script also accepts
    i_same = next(i for i in range(n) if old[i] and new[i] and old[i].serialize() == new[i].serialize())
    check(wit.count(ls.REWRITE_SAME) >= 1, f"{name} the unchanged position's new element is the one-byte marker")
    w.run(name, rebuild(old, new, marker=False), ctx)
    check(True, f"{name} an unchanged leaf supplied twice in full also passes")
    # the marker cannot stand in for a change: as the old element it is a
    # 1-byte old leaf, and a 2-byte new element is neither marker nor leaf
    wit_mo = list(wit)
    wit_mo[wit_mo.index(old[i_same].serialize())] = ls.REWRITE_SAME
    expect_fail(lambda: w.run(name, wit_mo, ctx), f"{name} the marker as an old element")
    wit_2b = list(wit)
    wit_2b[wit_2b.index(old[i_same].serialize()) - 1] = b"\x01\x01"
    expect_fail(lambda: w.run(name, wit_2b, ctx), f"{name} a 2-byte new element")
    # the marker under a changed position hides nothing: the fold still sees
    # the old leaf, so output 0 built for the change fails
    wit_mc = list(wit)
    wit_mc[wit_mc.index(old[i_rot_m := next(i for i in range(n) if old[i] and new[i] and old[i].serialize() != new[i].serialize())].serialize()) - 1] = ls.REWRITE_SAME
    expect_fail(lambda: w.run(name, wit_mc, ctx), f"{name} the marker in place of a changed leaf")

    # rule 3: a changed leaf without its owner's signature
    i_rot = next(i for i in range(n) if old[i] and new[i] and _needs_owner_sig(old[i], new[i]))
    wit_nosig = list(wit)
    pos = wit_nosig.index(sigs[i_rot][0])
    del wit_nosig[pos]
    expect_fail(lambda: w.run(name, wit_nosig, ctx), f"{name} changed leaf without the owner signature")
    # rule 3: a key rotation disguised as an amount-only increase (no signature)
    i_inc = next(i for i in range(n) if old[i] and new[i] and not _needs_owner_sig(old[i], new[i])
                 and new[i].amount > old[i].amount)
    disguised = dict(new)
    lf = old[i_inc]
    disguised[i_inc] = lt.Leaf(lf.amount + 500, lf.exit_key, pubkey_x(sk("mallory")), lf.evictor_key,
                               lf.evict_after, lf.nonce, lf.seq)
    t_d = w.clone()
    t_d.leaves[base + i_inc] = disguised[i_inc]
    for i, x in new.items():
        if i != i_inc:
            if x:
                t_d.leaves[base + i] = x
            else:
                t_d.leaves.pop(base + i, None)
    outs_d = [(t_d.root()[1], w.spk(t_d.root()))] + c["outputs"][1:]
    ctx_d = w.ctx(outs_d, extra_in=(max(c["delta"], 0) + 5_000, P2WPKH))
    wit_d = rebuild(old, disguised, ctx_d)
    # the witness builder would sign it (the rule says so); strip that signature to attempt the disguise
    sig_d = schnorr_sign(ctx_d.sighash(), sk(f"c{i_inc}-owner"))
    wit_d_nosig = [x for x in wit_d if x != sig_d and not (exit_consent and x == schnorr_sign(ctx_d.sighash(), sk(f"c{i_inc}-exit")))]
    expect_fail(lambda: w.run(name, wit_d_nosig, ctx_d), f"{name} key rotation disguised as an amount increase")
    w.run(name, wit_d, ctx_d)
    check(True, f"{name} the same rotation with the owner's signature succeeds")
    # rule 3: the exemption does not reach a SEQ_FINAL leaf (a channel leaf,
    # 5.2): raising its amount by 1 sat needs the owner's signature too
    final_old, final_new = dict(old), dict(new)
    final_old[i_inc] = lf.with_amount_seq(lf.amount, ls.SEQ_FINAL)
    final_new[i_inc] = lf.with_amount_seq(lf.amount + 1, ls.SEQ_FINAL)
    saved = dict(w.tree.leaves)
    w.tree.leaves[base + i_inc] = final_old[i_inc]
    root_f = w.tree.root()
    t_f = w.clone()
    for i, x in final_new.items():
        if x:
            t_f.leaves[base + i] = x
        else:
            t_f.leaves.pop(base + i, None)
    outs_f = [(t_f.root()[1], w.spk(t_f.root()))] + c["outputs"][1:]
    ctx_f = w.ctx(outs_f, extra_in=(max(c["delta"], 0) + 5_000, P2WPKH))
    wit_f = rebuild(final_old, final_new, ctx_f, root_=root_f)
    sig_f = schnorr_sign(ctx_f.sighash(), sk(f"c{i_inc}-owner"))
    wit_f_nosig = [x for x in wit_f if x != sig_f and not (exit_consent and x == schnorr_sign(ctx_f.sighash(), sk(f"c{i_inc}-exit")))]
    expect_fail(lambda: w.run(name, wit_f_nosig, ctx_f), f"{name} SEQ_FINAL leaf raised by 1 sat without the owner signature")
    w.run(name, wit_f, ctx_f)
    check(True, f"{name} the same raise with the owner's signature succeeds")
    w.tree.leaves = saved
    # rule 5: a shortchanged exit payout, and one paid to the wrong key
    i_exit = next(i for i in range(n) if old[i] and new[i] is None)
    k = 1 + sum(1 for i in range(i_exit) if old[i] and new[i] is None)
    outs_s = list(c["outputs"]); outs_s[k] = (outs_s[k][0] - 1, outs_s[k][1])
    ctx_s = w.ctx(outs_s, extra_in=(max(c["delta"], 0) + 5_000, P2WPKH))
    expect_fail(lambda: w.run(name, rebuild(old, new, ctx_s), ctx_s), f"{name} shortchanged exit payout")
    outs_k = list(c["outputs"]); outs_k[k] = (outs_k[k][0], lt.p2tr_spk(pubkey_x(sk("mallory"))))
    ctx_k = w.ctx(outs_k, extra_in=(max(c["delta"], 0) + 5_000, P2WPKH))
    expect_fail(lambda: w.run(name, rebuild(old, new, ctx_k), ctx_k), f"{name} exit paid to the wrong key")
    # rule 4: no operator signature
    expect_fail(lambda: w.run(name, rebuild(old, new, sig_op_=schnorr_sign(ctx.sighash(), sk("alice-owner"))), ctx),
                f"{name} without the operator signature")
    # rule 6: output 0 not conserved (under and over)
    for off in (-1, +1):
        outs_u = list(c["outputs"]); outs_u[0] = (outs_u[0][0] + off, outs_u[0][1])
        ctx_u = w.ctx(outs_u, extra_in=(max(c["delta"], 0) + 5_000, P2WPKH))
        expect_fail(lambda: w.run(name, rebuild(old, new, ctx_u), ctx_u), f"{name} output 0 off by {off:+d}")
    # rule 1: a stale path (a rewrite leaves the subtree's own path unchanged,
    # so the stale one comes from a change elsewhere in the tree) and a forged old leaf
    t_s = w.clone(); t_s.leaves[0] = mk_leaf("alice", 51_000)
    stale = t_s.path(base, height=height)
    expect_fail(lambda: w.run(name, rebuild(old, new, path_=stale), ctx), f"{name} stale path")
    forged = dict(old)
    forged[i_rot] = old[i_rot].with_amount_seq(old[i_rot].amount + 1, old[i_rot].seq)
    expect_fail(lambda: w.run(name, rebuild(forged, new), ctx), f"{name} forged old leaf")
    if exit_consent:
        # rule 7: the exit key of a changed leaf must sign too
        wit_nox = list(wit)
        del wit_nox[wit_nox.index(sigs[i_rot][1])]
        expect_fail(lambda: w.run(name, wit_nox, ctx), f"{name} changed leaf without the exit-key signature")
        wit_wx = list(wit)
        wit_wx[wit_wx.index(sigs[i_rot][1])] = sigs[i_rot][0]
        expect_fail(lambda: w.run(name, wit_wx, ctx), f"{name} exit-key signature by the owner key")
    if verbose:
        n_sig = len(sigs)
        print(f"{name} D={depth}: {n} positions, {n_sig} owner signatures, script {len(c['script'])} B, "
              f"witness {sum(len(x) for x in wit)} B, varops {it.cost}, sigops {it.sigchecks}, maxdepth {it.max_depth}")
    return it, len(c["script"]), sum(len(x) for x in wit)


def test_voucher_topup(depth, verbose=True):
    """Vouchers and exit authorisations survive an amount-only REWRITE_h
    (spec 7.5, 7.2 rule 7, 7.9 rule 3): both messages bind the source leaf
    without its amount, so the operator's top-up of a cohort, which needs
    no owner signature, voids neither. A tree with CLAIM, EXIT_K^t and
    REWRITE_2: a voucher and an authorisation are signed against two
    leaves of the cohort, the operator rewrites the cohort raising every
    amount by 500 with its signature alone, and afterwards the voucher
    redeems against the topped-up leaf (for its own amount, for more than
    the balance at issuance, and for the whole balance at issuance, whose
    residual is now the top-up) and the tower exits the other leaf for its
    new amount on the old authorisation. An over-claim against the new
    balance, a payout of the old amount, and a whole-balance voucher
    after a top-up below DUST_MIN (7.5 rule 6: the residual it leaves is
    sub-dust) all fail."""
    opts = ls.TreeOptions(pubkey_x(sk("operator")), TREE_ID, profile="D", join_heights=(0, 2),
                          exit_ks=(1, 2), tower=True, rewrite_heights=(2,))
    w = World(depth, "D", scripts=opts.at_depth(depth))
    D = depth
    base, old, new = _rewrite_plan(w, 2, "topup")
    w.tree.leaves = {base + i: lf for i, lf in old.items()}
    w.tree.leaves[0] = mk_leaf("alice", 50_000)
    w.tree.leaves[(1 << D) - 1] = mk_leaf("operator", 1_000_000)
    root = w.tree.root()
    path = w.tree.path(base, height=2)
    # signed before the rewrite, against the leaves as they stand
    src = old[3]
    holder = carve_of(src, "holder", 4_000)
    vsig = schnorr_sign(lt.voucher_msg(TREE_ID, src, holder), sk("c3-owner"))
    auth = schnorr_sign(lt.exit_auth_msg(TREE_ID, old[1]), sk("c1-owner"))
    # the operator's rewrite: every position an amount-only increase
    t1 = w.clone()
    for i, lf in new.items():
        t1.leaves[base + i] = lf
    r1 = t1.root()
    delta = r1[1] - root[1]
    ctx = w.ctx([(r1[1], w.spk(r1)), (400, P2WPKH)], extra_in=(delta + 5_000, P2WPKH))
    sig_op = schnorr_sign(ctx.sighash(), w.op_sk)
    wit, sigs = _rewrite_witness(w, 2, path, old, new, ctx, root, sig_op, False)
    check(not sigs, "REWRITE_2 top-up: no owner signs (7.9 rule 3)")
    w.run("REWRITE_2", wit, ctx)
    check(True, f"REWRITE_2 D={depth}: the operator tops up every leaf of the cohort alone")
    w.tree = t1
    # the voucher redeems against the topped-up leaf
    s_src = base + 3
    topped = new[3]
    check(topped.amount == src.amount + 500 and topped.body() == src.body(), "the top-up changed the amount and nothing else")

    def claim_after(lf, sig, tree=None, src_leaf=None):
        tree = tree or w.tree
        src_leaf = src_leaf or topped
        s_c = w.slot(lf, 2)
        t2 = lt.Tree(D); t2.leaves = dict(tree.leaves)
        amt_new = src_leaf.amount - lf.amount
        if amt_new > 0:
            t2.leaves[s_src] = src_leaf.with_amount_seq(amt_new, src_leaf.seq + 1)
        else:
            del t2.leaves[s_src]
        t2.leaves[s_c] = lf
        r2 = t2.root()
        ctx2 = TxContext([(tree.root()[1], w.spk(tree.root())), (600, P2WPKH)], [(r2[1], w.spk(r2))])
        return (w.path_witness(t2.path(s_c)) + w.path_witness(tree.path(s_src)) +
                [src_leaf.serialize(), lf.serialize(), sig, tree.root()[0], w.m]), ctx2

    wit2, ctx2 = claim_after(holder, vsig)
    w.run("CLAIM", wit2, ctx2)
    check(True, "CLAIM: a voucher signed before the top-up redeems against the topped-up leaf")
    bigger = carve_of(src, "bigger", src.amount + 100)
    wit3, ctx3 = claim_after(bigger, schnorr_sign(lt.voucher_msg(TREE_ID, src, bigger), sk("c3-owner")))
    w.run("CLAIM", wit3, ctx3)
    check(True, "CLAIM: after the top-up a voucher may draw more than the balance at issuance")
    whole = carve_of(src, "whole", src.amount)
    wsig = schnorr_sign(lt.voucher_msg(TREE_ID, src, whole), sk("c3-owner"))
    wit4, ctx4 = claim_after(whole, wsig)
    w.run("CLAIM", wit4, ctx4)
    check(True, "CLAIM: a whole-balance voucher redeems after a top-up of at least DUST_MIN (the residual is the top-up)")
    over = carve_of(src, "over", topped.amount + 1)
    expect_fail(lambda: w.run("CLAIM", *claim_after(over, schnorr_sign(lt.voucher_msg(TREE_ID, src, over), sk("c3-owner")))),
                "CLAIM: over-claim against the topped-up balance")
    # 7.5 rule 6 is the one check a top-up can trip: a whole-balance voucher
    # against a leaf topped up by less than DUST_MIN leaves a sub-dust
    # residual, so it is blocked until the residual reaches the floor
    sub = src.with_amount_seq(src.amount + 1, src.seq)
    t_sub = lt.Tree(D); t_sub.leaves = dict(w.tree.leaves); t_sub.leaves[s_src] = sub
    expect_fail(lambda: w.run("CLAIM", *claim_after(whole, wsig, tree=t_sub, src_leaf=sub)),
                "CLAIM: a whole-balance voucher after a top-up below DUST_MIN (7.5 rule 6)")
    # the tower exits the topped-up leaf on the authorisation signed before
    s_b = base + 1
    up1 = new[1]
    t5 = w.clone(); lt.apply_exit(t5, s_b); r5 = t5.root()
    ctx5 = w.ctx([(r5[1], w.spk(r5)), (up1.amount, lt.p2tr_spk(up1.exit_key))], extra_in=(600, P2WPKH))
    w.run("EXIT_1", w.path_witness(w.tree.path(s_b)) + [up1.serialize(), auth, b"", r1[0], w.m], ctx5)
    check(True, "EXIT_1^t: an authorisation signed before the top-up exits the topped-up leaf for its new amount")
    ctx6 = w.ctx([(r5[1], w.spk(r5)), (old[1].amount, lt.p2tr_spk(up1.exit_key))], extra_in=(600, P2WPKH))
    expect_fail(lambda: w.run("EXIT_1", w.path_witness(w.tree.path(s_b)) + [up1.serialize(), auth, b"", r1[0], w.m], ctx6),
                "EXIT_1^t: the exit after a top-up pays the amount at signing")
    if verbose:
        print(f"voucher top-up D={depth}: REWRITE_2 by the operator alone, then CLAIM and EXIT_1^t on the pre-top-up signatures")


def rewrite_sizes(depth, height):
    """Measured sizes of REWRITE_h at one depth and height for the design
    note: the three scenarios of _rewrite_plan plus the per-position script
    share. Returns a dict of figures; prints a table."""
    out = {}
    for scenario in ("mixed", "update", "exit"):
        c = rewrite_case(depth, height, scenario)
        it = c["w"].run(c["name"], c["wit"], c["ctx"])
        n_changed = sum(1 for i in c["old"] if (c["old"][i] is not None or c["new"][i] is not None)
                        and (c["old"][i] is None or c["new"][i] is None or
                             c["old"][i].serialize() != c["new"][i].serialize()))
        n_exit = sum(1 for i in c["old"] if c["old"][i] and c["new"][i] is None)
        wl = sum(len(x) for x in c["wit"])
        out[scenario] = dict(script=len(c["script"]), witness=wl, changed=n_changed, exits=n_exit,
                             sigs=len(c["sigs"]), varops=it.cost, sigops=it.sigchecks)
    # per-position script share: everything the positions add over the fixed part
    fixed = len(assemble(ls.prologue() + [bytes(32), "OP_CHECKSIGVERIFY", "OP_1", "OP_TOALTSTACK",
                                          lt.EMPTY_LEAF_HASH, ls.LEAF_PREFIX, ls.NODE_PREFIX,
                                          "OP_FROMALTSTACK", "OP_DROP", 6, "OP_ROLL", "OP_DROP", 5, "OP_ROLL", "OP_DROP"] +
                         ls.levels("D", depth, height) + ls.check_old_root_from_alt("D") + ls.final_output(depth)))
    out["fixed_script"] = fixed
    out["per_position_script"] = (out["mixed"]["script"] - fixed) / (1 << height)
    return out


def test_detach(depth, height, verbose=True):
    """DETACH_h (spec 7.10): move an aligned subtree into a tree output of its own.

    The detached cohort is a LayerTree of depth h under m_h; a member's old
    path truncated to its lower h levels is its proof there, and an EXIT_1
    from the detached tree succeeds with it.
    """
    w = World(depth, "D")
    m_h = ls.detached_taptree_root(height, w.op_pk, w.tree_id)
    toks = ls.detach_script(depth, height, w.op_pk, m_h)
    bad = {t for t in toks if isinstance(t, str)} - ALLOWED_OPCODES
    name = f"DETACH_{height}"
    check(not bad, f"{name} uses non-candidate opcodes: {sorted(bad)}")
    script = assemble(toks)
    w.compiled = dict(w.compiled); w.compiled[name] = script
    w.m = lt.taptree_root([lt.tapleaf_hash(c) for c in w.compiled.values()])
    n = 1 << height
    base = 1 << height
    cohort = {base + i: mk_leaf(f"c{i}", 10_000 + 7 * i, w.op_pk, 800_000) for i in range(n) if i % 5 != 3}
    w.tree.leaves = dict(cohort)
    w.tree.leaves[0] = mk_leaf("alice", 50_000)
    w.tree.leaves[(1 << depth) - 1] = mk_leaf("operator", 1_000_000)
    root = w.tree.root()
    node = w.tree.subtree(height, 1)                      # (R_h, sum_h)
    path = w.tree.path(base, height=height)
    t1 = w.clone()
    for p in cohort:
        del t1.leaves[p]
    r1 = t1.root()
    spk1 = lt.tree_spk(node[0], m_h)
    outputs = [(r1[1], w.spk(r1)), (node[1], spk1), (400, P2WPKH)]
    ctx = w.ctx(outputs, extra_in=(5_000, P2WPKH))
    sig = schnorr_sign(ctx.sighash(), w.op_sk)
    wit = w.path_witness(path, height) + [node[0], lt.le64(node[1]), sig, root[0], w.m]
    it = w.run(name, wit, ctx)
    check(r1[1] + node[1] == root[1], f"{name} conserves the total across two tree outputs")

    # negatives
    bad_m = lt.tree_spk(node[0], w.m)                      # output 1 under the parent's taptree, not m_h
    ctx_m = w.ctx([(r1[1], w.spk(r1)), (node[1], bad_m), (400, P2WPKH)], extra_in=(5_000, P2WPKH))
    expect_fail(lambda: w.run(name, wit[:-3] + [schnorr_sign(ctx_m.sighash(), w.op_sk), root[0], w.m], ctx_m),
                f"{name} output 1 under the wrong m_h")
    ctx_s = w.ctx([(r1[1], w.spk(r1)), (node[1] - 1, spk1), (400, P2WPKH)], extra_in=(5_000, P2WPKH))
    expect_fail(lambda: w.run(name, wit[:-3] + [schnorr_sign(ctx_s.sighash(), w.op_sk), root[0], w.m], ctx_s),
                f"{name} output 1 shortchanged")
    expect_fail(lambda: w.run(name, wit[:-3] + [schnorr_sign(ctx.sighash(), sk("alice-owner")), root[0], w.m], ctx),
                f"{name} without the operator signature")
    ctx_n = w.ctx([(root[1], w.spk(root)), (node[1], spk1), (400, P2WPKH)], extra_in=(node[1] + 5_000, P2WPKH))
    expect_fail(lambda: w.run(name, wit[:-3] + [schnorr_sign(ctx_n.sighash(), w.op_sk), root[0], w.m], ctx_n),
                f"{name} subtree not emptied in output 0 (new node not E_h)")
    fake = (node[0], node[1] + 1)
    ctx_f = w.ctx([(r1[1], w.spk(r1)), (fake[1], spk1), (400, P2WPKH)], extra_in=(5_000, P2WPKH))
    expect_fail(lambda: w.run(name, w.path_witness(path, height) + [fake[0], lt.le64(fake[1]),
                              schnorr_sign(ctx_f.sighash(), w.op_sk), root[0], w.m], ctx_f),
                f"{name} inflated subtree sum")

    # the detached tree: a member's old path truncated to its lower h levels is its proof
    w2 = World(height, "D", join_heights=(0,), exit_ks=(1, 2))
    check(w2.m == m_h, "m_h is the tree identifier of the reference set at depth h")
    w2.tree.leaves = {p - base: lf for p, lf in cohort.items()}
    check(w2.tree.root() == node, "the detached tree's root is the detached node")
    victim = base + 2
    full_path = w.tree.path(victim)
    short = full_path[:height]
    check(lt.fold(cohort[victim].node(), short) == node, "old path truncated to h levels verifies in the detached tree")
    check(short == w2.tree.path(victim - base), "the truncated path is the detached tree's own path")
    t2 = w2.clone(); del t2.leaves[victim - base]; r2 = t2.root()
    lf = cohort[victim]
    ctx2 = TxContext([(node[1], spk1), (5_000, P2WPKH)],
                     [(r2[1], w2.spk(r2)), (lf.amount - 300, lt.p2tr_spk(lf.exit_key))])
    sig2 = schnorr_sign(ctx2.sighash(), sk(f"c{victim - base}-owner"))
    it2 = w2.run("EXIT_1", w2.path_witness(short) + [lf.serialize(), sig2, b"", node[0], m_h], ctx2)
    check(True, f"EXIT_1 from the detached depth-{height} tree with the truncated path")
    # a voucher issued while the source leaf sat in the parent redeems in
    # the detached tree: the detached tree inherits tree_id (7.10 rule 3),
    # and the voucher never bound m, so no reissue after a detach (9.6)
    check(w2.tree_id == w.tree_id, "the detached tree inherits the parent's tree_id")
    issuer = max(cohort)
    src = cohort[issuer]
    vsig = schnorr_sign(lt.voucher_msg(w.tree_id, src, mk_leaf("holder", 3_000, w.op_pk, 800_000)),
                        sk(f"c{issuer - base}-owner"))
    holder = mk_leaf("holder", 3_000, w.op_pk, 800_000)
    s_holder = next(i for i in range(n) if i not in w2.tree.leaves)
    t3 = w2.clone(); lt.apply_claim(t3, issuer - base, s_holder, holder); r3 = t3.root()
    ctx3 = TxContext([(node[1], spk1), (600, P2WPKH)], [(r3[1], w2.spk(r3))])
    w2.run("CLAIM", w2.path_witness(t3.path(s_holder)) + w2.path_witness(w2.tree.path(issuer - base)) +
           [src.serialize(), holder.serialize(), vsig, node[0], m_h], ctx3)
    check(True, "a voucher issued in the parent redeems in the detached tree")
    if verbose:
        print(f"{name} D={depth}: script {len(script)} B, witness {sum(len(x) for x in wit)} B, varops {it.cost}; "
              f"EXIT_1 from the detached tree: script {len(w2.compiled['EXIT_1'])} B, varops {it2.cost}")
    return it, len(script), sum(len(x) for x in wit)


def test_detach_options(depth, height, verbose=True):
    """DETACH_h under a parent created with options (spec 7.10 rule 3): the
    child is the parent's option set compiled at depth h, so a cohort keeps
    its rules when it is detached.

    The parent hosts channel leaves (Appendix C): EXIT_1^= (C.6.1), CLAIM^h
    (9.6.2) and DETACH_h. The detach succeeds with output 1 under m_h
    compiled from those options, fails with output 1 under the reference
    set's m_h (which drops the options), and in the detached tree a channel
    leaf's EXIT_1^= pays its capacity exactly and rejects a shortfall.
    """
    op_pk = pubkey_x(sk("operator"))
    host = ls.TreeOptions(op_pk, TREE_ID, exact=True, claim_h=True, detach_heights=(height,))
    w = World(depth, "D", scripts=host.at_depth(depth))
    name = f"DETACH_{height}"
    check(name in w.compiled and "CLAIM_H" in w.compiled, "the parent's option set carries DETACH_h and CLAIM^h")
    m_h = host.taptree_root(height)
    ref_m_h = ls.detached_taptree_root(height, op_pk, TREE_ID)
    check(m_h != ref_m_h, "m_h from the parent's options differs from the reference set's m_h")
    check(ls.detached_taptree_root(height, op_pk, TREE_ID, host) == m_h,
          "detached_taptree_root with the parent's options is the parent's set at depth h")
    n, base = 1 << height, 1 << height
    # channel leaves: evictable by the operator at any time, non-claimable (9.8)
    cohort = {base + i: mk_leaf(f"c{i}", 10_000 + 7 * i, w.op_pk, 0, seq=0xFFFFFFFF) for i in range(n) if i % 5 != 3}
    w.tree.leaves = dict(cohort)
    w.tree.leaves[0] = mk_leaf("alice", 50_000)
    w.tree.leaves[(1 << depth) - 1] = mk_leaf("operator", 1_000_000)
    root = w.tree.root()
    node = w.tree.subtree(height, 1)
    path = w.tree.path(base, height=height)
    t1 = w.clone()
    for p in cohort:
        del t1.leaves[p]
    r1 = t1.root()
    spk1 = lt.tree_spk(node[0], m_h)
    ctx = w.ctx([(r1[1], w.spk(r1)), (node[1], spk1), (400, P2WPKH)], extra_in=(5_000, P2WPKH))
    head = w.path_witness(path, height) + [node[0], lt.le64(node[1])]
    w.run(name, head + [schnorr_sign(ctx.sighash(), w.op_sk), root[0], w.m], ctx)
    check(True, f"{name} under the parent's options (exact payouts, CLAIM^h)")
    # the parent's DETACH_h rejects a child under an m_h that drops its options
    ctx_r = w.ctx([(r1[1], w.spk(r1)), (node[1], lt.tree_spk(node[0], ref_m_h)), (400, P2WPKH)], extra_in=(5_000, P2WPKH))
    expect_fail(lambda: w.run(name, head + [schnorr_sign(ctx_r.sighash(), w.op_sk), root[0], w.m], ctx_r),
                f"{name} with output 1 under an m_h that drops the parent's options")

    # the detached tree: the same options at depth h
    w2 = World(height, "D", scripts=host.at_depth(height))
    check(w2.m == m_h, "the detached tree's identifier is the parent's options compiled at depth h")
    check(list(w2.compiled) == ["EXIT_1", "EXIT_2", "JOIN_0", "JOINK_2", "UPDATE", "CLAIM", "CLAIM_H"],
          "the detached tree carries the parent's set less the heights that do not fit")
    w2.tree.leaves = {p - base: lf for p, lf in cohort.items()}
    check(w2.tree.root() == node, "the detached tree's root is the detached node")
    victim = base + 1
    lf = cohort[victim]
    short = w.tree.path(victim)[:height]
    t2 = w2.clone(); del t2.leaves[victim - base]; r2 = t2.root()
    ctx2 = TxContext([(node[1], spk1), (5_000, P2WPKH)],
                     [(r2[1], w2.spk(r2)), (lf.amount, lt.p2tr_spk(lf.exit_key))])
    sig2 = schnorr_sign(ctx2.sighash(), sk(f"c{victim - base}-owner"))
    w2.run("EXIT_1", w2.path_witness(short) + [lf.serialize(), sig2, b"", node[0], m_h], ctx2)
    check(True, "a channel leaf's EXIT_1^= from the detached tree pays its capacity exactly")
    ctx3 = TxContext([(node[1], spk1), (5_000, P2WPKH)],
                     [(r2[1], w2.spk(r2)), (lf.amount - 300, lt.p2tr_spk(lf.exit_key))])
    sig3 = schnorr_sign(ctx3.sighash(), sk(f"c{victim - base}-owner"))
    expect_fail(lambda: w2.run("EXIT_1", w2.path_witness(short) + [lf.serialize(), sig3, b"", node[0], m_h], ctx3),
                "EXIT_1^= in the detached tree rejects an owner shortfall, as the parent's did")
    if verbose:
        print(f"{name} D={depth} under options: child set {list(w2.compiled)}, m_h differs from the reference set's")


def test_update_x(depth, profile, verbose=True):
    """UPDATE^x (spec 7.4 rule 5): UPDATE plus a signature by old_leaf.exit_key.

    The variant is a tree-creation parameter, so it is swapped into the
    taptree under the name UPDATE_X and m is recomputed.
    """
    w = World(depth, profile)
    toks = ls.update_script(depth, w.op_pk, profile, exit_consent=True)
    bad = {t for t in toks if isinstance(t, str)} - ALLOWED_OPCODES
    check(not bad, f"UPDATE_X uses non-candidate opcodes: {sorted(bad)}")
    script = assemble(toks)
    w.compiled = dict(w.compiled); w.compiled["UPDATE_X"] = script
    w.m = lt.taptree_root([lt.tapleaf_hash(c) for c in w.compiled.values()])
    # six leaves, as the sparse witness sizes elsewhere are measured
    alice = mk_leaf("alice", 50_000)
    oper = mk_leaf("operator", 1_000_000)
    others = [mk_leaf(n, a) for n, a in (("bob", 125_000), ("carol", 30_000),
                                         ("dave", 70_000), ("erin", 15_000))]
    s_alice, s_oper = w.slot(alice, 0), w.slot(oper, (1 << depth) - 1)
    w.tree.leaves = {s_alice: alice, s_oper: oper}
    for i, lf in enumerate(others):
        w.tree.leaves[w.slot(lf, i + 1)] = lf
    root = w.tree.root()
    upath = w.tree.path(s_alice)
    alice2 = alice.with_amount_seq(80_000, 1)
    t1 = w.clone(); t1.leaves[s_alice] = alice2; r1 = t1.root()
    ctx = w.ctx([(r1[1], w.spk(r1))], extra_in=(30_700, P2WPKH))
    osig = schnorr_sign(ctx.sighash(), w.op_sk)
    asig = schnorr_sign(ctx.sighash(), sk("alice-owner"))
    xsig = schnorr_sign(ctx.sighash(), sk("alice-exit"))
    block = w.path_witness(upath) + w.bm(upath) + [alice.serialize(), alice2.serialize()]
    wit = block + [asig, osig, xsig, root[0], w.m]
    it = w.run("UPDATE_X", wit, ctx)
    check(True, "UPDATE^x with owner, operator and exit signatures")
    # negatives
    wrong = schnorr_sign(ctx.sighash(), sk("alice-owner"))
    expect_fail(lambda: w.run("UPDATE_X", block + [asig, osig, wrong, root[0], w.m], ctx), "UPDATE^x exit_sig by the wrong key")
    expect_fail(lambda: w.run("UPDATE_X", block + [asig, osig, bytes(64), root[0], w.m], ctx), "UPDATE^x garbage exit_sig")
    expect_fail(lambda: w.run("UPDATE_X", block + [asig, osig, root[0], w.m], ctx), "UPDATE^x missing exit_sig")
    expect_fail(lambda: w.run("UPDATE_X", block + [osig, osig, xsig, root[0], w.m], ctx), "UPDATE^x without the owner signature")
    if verbose:
        plain = len(assemble(ls.update_script(depth, w.op_pk, profile)))
        print(f"UPDATE^x {profile} D={depth}: script {len(script)} B (UPDATE {plain} B), witness {sum(len(x) for x in wit)} B")
    return it, len(script), sum(len(x) for x in wit)


def test_channel_rules(depth, verbose=True):
    """Tree-layer rules that channel leaves rely on (spec 5.2, 7.2 rule 6, 7.5; Appendix C.6).

    1. SEQ_FINAL = 0xFFFFFFFF makes a leaf non-claimable in FULL: seq + 1 is a
       5-byte BIP-441 number, rejected by the OP_SIZE 4 check in CLAIM.
       0xFFFFFFFE (one below) and 0x7FFFFFFF (the MID marker) stay claimable.
    2. The exact-payout EXIT_K^= variant rejects an owner exit paying less than
       leaf.amount and accepts one paying exactly leaf.amount; eviction is unchanged.
    """
    w = World(depth, "D")
    D = depth
    alice = mk_leaf("alice", 50_000)
    s_alice = 0
    for seq, claimable in ((0xFFFFFFFF, False), (0xFFFFFFFE, True), (0x7FFFFFFF, True)):
        src = mk_leaf("chan-src", 1_000_000, seq=seq)
        s_src = (1 << D) - 1
        w.tree.leaves = {s_alice: alice, s_src: src}
        root = w.tree.root()
        claim = carve_of(src, "claimant", 40_000)
        s_claim = 3
        spath = w.tree.path(s_src)
        t5 = w.clone()
        t5.leaves[s_src] = src.with_amount_seq(src.amount - claim.amount, (seq + 1) & 0xffffffff)
        t5.leaves[s_claim] = claim
        cpath = t5.path(s_claim)
        r5 = t5.root()
        ctx = w.ctx([(r5[1], w.spk(r5))], extra_in=(600, P2WPKH))
        vsig = schnorr_sign(lt.voucher_msg(w.tree_id, src, claim), sk("chan-src-owner"))
        wit = w.path_witness(cpath) + w.path_witness(spath) + [src.serialize(), claim.serialize(), vsig, root[0], w.m]
        if claimable:
            w.run("CLAIM", wit, ctx)
            check(True, f"CLAIM with seq {seq:#x} succeeds")
        else:
            expect_fail(lambda: w.run("CLAIM", wit, ctx), f"CLAIM against SEQ_FINAL {seq:#x} must fail")

    # exact-payout variant: swap EXIT_1 for EXIT_1^= (a different taptree, hence a different m)
    exact = assemble(ls.exit_script(depth, 1, "D", exact=True))
    w.compiled = dict(w.compiled); w.compiled["EXIT_1"] = exact
    w.m = lt.taptree_root([lt.tapleaf_hash(c) for c in w.compiled.values()])
    bob = mk_leaf("bob", 125_000, evictor=w.op_pk, evict_after=800_000)
    s_bob = 5
    w.tree.leaves = {s_alice: alice, s_bob: bob}
    root = w.tree.root()
    path = w.tree.path(s_bob)
    t1 = w.clone(); lt.apply_exit(t1, s_bob); r1 = t1.root()
    # owner exit paying exactly leaf.amount (fees from a second input)
    ctx = w.ctx([(r1[1], w.spk(r1)), (bob.amount, lt.p2tr_spk(bob.exit_key))], extra_in=(600, P2WPKH))
    sig = schnorr_sign(ctx.sighash(), sk("bob-owner"))
    w.run("EXIT_1", w.path_witness(path) + [bob.serialize(), sig, b"", root[0], w.m], ctx)
    check(True, "EXIT_1^= exact owner payout")
    # owner exit paying less than leaf.amount (the FULL fee-from-payout option) is rejected
    ctx2 = w.ctx([(r1[1], w.spk(r1)), (bob.amount - 500, lt.p2tr_spk(bob.exit_key))])
    sig2 = schnorr_sign(ctx2.sighash(), sk("bob-owner"))
    expect_fail(lambda: w.run("EXIT_1", w.path_witness(path) + [bob.serialize(), sig2, b"", root[0], w.m], ctx2), "EXIT_1^= owner shortfall")
    # eviction still requires the exact amount and the lock time
    ctx_e = w.ctx([(r1[1], w.spk(r1)), (bob.amount, lt.p2tr_spk(bob.exit_key))], extra_in=(600, P2WPKH), locktime=800_000)
    esig = schnorr_sign(ctx_e.sighash(), w.op_sk)
    w.run("EXIT_1", w.path_witness(path) + [bob.serialize(), esig, b"\x01", root[0], w.m], ctx_e)
    check(True, "EXIT_1^= eviction")
    if verbose:
        print(f"channel rules D={depth}: EXIT_1^= script {len(exact)} B (EXIT_1 {len(assemble(ls.exit_script(depth, 1, 'D')))} B)")


def test_claim_h(depth, profile, verbose=True):
    """CLAIM^h (spec 7.5.1): CLAIM whose voucher also commits to a payment hash.

    The redeemer supplies a 32-byte preimage; the script hashes it into the
    signed message, so a wrong preimage fails as a bad signature. The variant
    is a tree-creation parameter, so it is swapped into the taptree under the
    name CLAIM_H and m is recomputed.
    """
    w = World(depth, profile)
    toks = ls.claim_script(depth, w.tree_id, profile, hashlock=True)
    bad = {t for t in toks if isinstance(t, str)} - ALLOWED_OPCODES
    check(not bad, f"CLAIM_H uses non-candidate opcodes: {sorted(bad)}")
    script = assemble(toks)
    w.compiled = dict(w.compiled); w.compiled["CLAIM_H"] = script
    w.m = lt.taptree_root([lt.tapleaf_hash(c) for c in w.compiled.values()])
    oper = mk_leaf("operator", 1_000_000)
    alice = mk_leaf("alice", 50_000)
    s_oper, s_alice = w.slot(oper, (1 << depth) - 1), w.slot(alice, 0)
    w.tree.leaves = {s_oper: oper, s_alice: alice}
    root = w.tree.root()
    src = w.tree.leaves[s_oper]

    preimage = lt.sha256(b"payment-preimage")
    payment_hash = lt.sha256(preimage)
    hodl = carve_of(src, "hodl", 40_000)
    s_hodl = w.slot(hodl, 3)
    spath = w.tree.path(s_oper)
    t1 = w.clone(); lt.apply_claim(t1, s_oper, s_hodl, hodl)
    cpath = t1.path(s_hodl); r1 = t1.root()
    check(r1[1] == root[1], "CLAIM^h conserves sum")
    ctx = w.ctx([(r1[1], w.spk(r1))], extra_in=(600, P2WPKH))
    hmsg = lt.voucher_h_msg(w.tree_id, src, hodl, payment_hash)
    hsig = schnorr_sign(hmsg, sk("operator-owner"))
    head = w.path_witness(cpath) + w.path_witness(spath) + w.bm(spath) + [src.serialize()] + w.bm(cpath) + [hodl.serialize()]
    wit = head + [hsig, preimage, root[0], w.m]
    it = w.run("CLAIM_H", wit, ctx)
    check(True, "CLAIM^h redeemed with the correct preimage")

    # negatives
    expect_fail(lambda: w.run("CLAIM_H", head + [hsig, lt.sha256(b"wrong"), root[0], w.m], ctx),
                "CLAIM^h wrong preimage")
    expect_fail(lambda: w.run("CLAIM_H", head + [hsig, preimage[:31], root[0], w.m], ctx),
                "CLAIM^h preimage not 32 bytes")
    expect_fail(lambda: w.run("CLAIM_H", head + [hsig, root[0], w.m], ctx),
                "CLAIM^h missing preimage")
    # a plain voucher for the same carve must not redeem under the hash lock,
    # and the hash-locked voucher must not redeem as a plain CLAIM: separate tags
    plain_sig = schnorr_sign(lt.voucher_msg(w.tree_id, src, hodl), sk("operator-owner"))
    expect_fail(lambda: w.run("CLAIM_H", head + [plain_sig, preimage, root[0], w.m], ctx),
                "CLAIM^h with a plain voucher signature")
    expect_fail(lambda: w.run("CLAIM", head + [hsig, root[0], w.m], ctx),
                "plain CLAIM with a hash-locked voucher signature")
    # the payment hash is bound to this carve: another claim leaf needs its own voucher
    other = carve_of(src, "other", 40_000)
    expect_fail(lambda: w.run("CLAIM_H", w.path_witness(cpath) + w.path_witness(spath) + w.bm(spath) +
                              [src.serialize()] + w.bm(cpath) + [other.serialize(), hsig, preimage, root[0], w.m], ctx),
                "CLAIM^h voucher reused for a different claim leaf")
    greedy = carve_of(src, "greedy", src.amount + 1)
    gsig = schnorr_sign(lt.voucher_h_msg(w.tree_id, src, greedy, payment_hash), sk("operator-owner"))
    expect_fail(lambda: w.run("CLAIM_H", w.path_witness(cpath) + w.path_witness(spath) + w.bm(spath) +
                              [src.serialize()] + w.bm(cpath) + [greedy.serialize(), gsig, preimage, root[0], w.m], ctx),
                "CLAIM^h over-claim underflow")
    bsig = schnorr_sign(hmsg, sk("bob-owner"))
    expect_fail(lambda: w.run("CLAIM_H", head + [bsig, preimage, root[0], w.m], ctx),
                "CLAIM^h voucher wrong signer")
    other_tid = lt.tree_id(lt.sha256(b"creation-txid"), 1)
    osig = schnorr_sign(lt.voucher_h_msg(other_tid, src, hodl, payment_hash), sk("operator-owner"))
    expect_fail(lambda: w.run("CLAIM_H", head + [osig, preimage, root[0], w.m], ctx),
                "CLAIM^h voucher signed for another tree_id")
    msig = schnorr_sign(lt.voucher_h_msg(w.m, src, hodl, payment_hash), sk("operator-owner"))
    expect_fail(lambda: w.run("CLAIM_H", head + [msig, preimage, root[0], w.m], ctx),
                "CLAIM^h voucher over m instead of tree_id")
    if verbose:
        plain = len(assemble(ls.claim_script(depth, w.tree_id, profile)))
        print(f"CLAIM^h {profile} D={depth}: script {len(script)} B (CLAIM {plain} B), witness {sum(len(x) for x in wit)} B, varops {it.cost}")
    return it, len(script), sum(len(x) for x in wit)


def test_claim_x(depth, profile, hashlock=False, verbose=True):
    """CLAIM^x and CLAIM^hx (spec 7.5.3): CLAIM / CLAIM^h plus a signature
    over the transaction by the source leaf's exit_key.

    The scenario is the dedicated credit leaf of 10.3: the operator owns the
    source leaf (owner_key) and the recipient holds its exit_key. Under
    CLAIM^x the recipient's own redemptions carry the exit signature for
    free, and the operator cannot carve the leaf, not even with a voucher it
    signed to itself, because it does not hold the exit key. The variant is a
    tree-creation parameter and is swapped into the taptree under the name
    CLAIM_X (CLAIM_HX); m is recomputed.
    """
    name = "CLAIM_HX" if hashlock else "CLAIM_X"
    w = World(depth, profile)
    toks = ls.claim_script(depth, w.tree_id, profile, hashlock=hashlock, exit_consent=True)
    bad = {t for t in toks if isinstance(t, str)} - ALLOWED_OPCODES
    check(not bad, f"{name} uses non-candidate opcodes: {sorted(bad)}")
    script = assemble(toks)
    plain = assemble(ls.claim_script(depth, w.tree_id, profile, hashlock=hashlock))
    check(len(script) - len(plain) == 7, f"{name} is seven bytes over its plain form")
    w.compiled = dict(w.compiled); w.compiled[name] = script
    w.m = lt.taptree_root([lt.tapleaf_hash(c) for c in w.compiled.values()])
    # credit leaf: the operator is the owner (issuer), the recipient holds the exit key
    credit = lt.Leaf(1_000_000, pubkey_x(sk("recipient-exit")), w.op_pk, lt.NUMS_X, 0,
                     int.from_bytes(lt.sha256(b"credit")[:4], "little"), 0)
    alice = mk_leaf("alice", 50_000)
    s_credit, s_alice = w.slot(credit, (1 << depth) - 1), w.slot(alice, 0)
    w.tree.leaves = {s_credit: credit, s_alice: alice}
    root = w.tree.root()

    # the recipient redeems the cumulative voucher into its own claim leaf
    claim = carve_of(credit, "recipient", 40_000)
    s_claim = w.slot(claim, 3)
    spath = w.tree.path(s_credit)
    t1 = w.clone(); lt.apply_claim(t1, s_credit, s_claim, claim)
    cpath = t1.path(s_claim); r1 = t1.root()
    check(r1[1] == root[1], f"{name} conserves sum")
    ctx = w.ctx([(r1[1], w.spk(r1))], extra_in=(600, P2WPKH))
    preimage = lt.sha256(b"credit-preimage")
    if hashlock:
        vsig = schnorr_sign(lt.voucher_h_msg(w.tree_id, credit, claim, lt.sha256(preimage)), w.op_sk)
    else:
        vsig = schnorr_sign(lt.voucher_msg(w.tree_id, credit, claim), w.op_sk)
    xsig = schnorr_sign(ctx.sighash(), sk("recipient-exit"))
    head = (w.path_witness(cpath) + w.path_witness(spath) + w.bm(spath) + [credit.serialize()] +
            w.bm(cpath) + [claim.serialize(), vsig] + ([preimage] if hashlock else []))
    wit = head + [xsig, root[0], w.m]
    it = w.run(name, wit, ctx)
    check(True, f"{name} redeemed with the voucher and the exit-key signature")

    # negatives
    osig = schnorr_sign(ctx.sighash(), w.op_sk)
    expect_fail(lambda: w.run(name, head + [osig, root[0], w.m], ctx),
                f"{name} exit_sig by the wrong key (the operator, who owns the leaf)")
    expect_fail(lambda: w.run(name, head + [bytes(64), root[0], w.m], ctx), f"{name} garbage exit_sig")
    expect_fail(lambda: w.run(name, head + [root[0], w.m], ctx), f"{name} missing exit_sig")
    vpos = len(head) - (2 if hashlock else 1)          # index of vsig in head
    novoucher = head[:vpos] + head[vpos + 1:]
    expect_fail(lambda: w.run(name, novoucher + [xsig, root[0], w.m], ctx), f"{name} without the voucher")
    txsig = head[:vpos] + [osig] + head[vpos + 1:]      # a transaction signature is not a voucher
    expect_fail(lambda: w.run(name, txsig + [xsig, root[0], w.m], ctx),
                f"{name} with a transaction signature in place of the voucher")
    # the operator cannot drain the credit leaf: its own voucher and its own
    # transaction signature are not the exit key
    drain = carve_of(credit, "operator-drain", credit.amount)
    s_drain = w.slot(drain, 6)
    t2 = w.clone(); lt.apply_claim(t2, s_credit, s_drain, drain)
    cpath2 = t2.path(s_drain); r2 = t2.root()
    ctx2 = w.ctx([(r2[1], w.spk(r2))], extra_in=(600, P2WPKH))
    if hashlock:
        dsig = schnorr_sign(lt.voucher_h_msg(w.tree_id, credit, drain, lt.sha256(preimage)), w.op_sk)
    else:
        dsig = schnorr_sign(lt.voucher_msg(w.tree_id, credit, drain), w.op_sk)
    expect_fail(lambda: w.run(name, w.path_witness(cpath2) + w.path_witness(spath) + w.bm(spath) +
                              [credit.serialize()] + w.bm(cpath2) + [drain.serialize(), dsig] +
                              ([preimage] if hashlock else []) +
                              [schnorr_sign(ctx2.sighash(), w.op_sk), root[0], w.m], ctx2),
                f"{name} operator draining the credit leaf without the recipient")
    if hashlock:
        expect_fail(lambda: w.run(name, head[:-1] + [lt.sha256(b"wrong"), xsig, root[0], w.m], ctx),
                    f"{name} wrong preimage")
    if verbose:
        print(f"{name} {profile} D={depth}: script {len(script)} B (plain {len(plain)} B), "
              f"witness {sum(len(x) for x in wit)} B, varops {it.cost}")
    return it, len(script), sum(len(x) for x in wit)


def test_split(depth, profile, verbose=True):
    """SPLIT (spec 7.5.2): CLAIM authorised by the owner's transaction
    signature instead of a voucher.

    Same two steps as CLAIM, so the interesting cases are the authorisation
    boundary: only the source leaf's owner may split it, and a voucher
    signature must not stand in for a transaction signature.
    """
    w = World(depth, profile)
    toks = ls.split_script(depth, profile)
    bad = {t for t in toks if isinstance(t, str)} - ALLOWED_OPCODES
    check(not bad, f"SPLIT uses non-candidate opcodes: {sorted(bad)}")
    check("OP_CHECKSIGFROMSTACK" not in toks, "SPLIT needs no OP_CHECKSIGFROMSTACK")
    script = assemble(toks)
    w.compiled = dict(w.compiled); w.compiled["SPLIT"] = script
    w.m = lt.taptree_root([lt.tapleaf_hash(c) for c in w.compiled.values()])
    alice = mk_leaf("alice", 500_000)
    oper = mk_leaf("operator", 1_000_000)
    s_alice, s_oper = w.slot(alice, 0), w.slot(oper, (1 << depth) - 1)
    w.tree.leaves = {s_alice: alice, s_oper: oper}
    root = w.tree.root()

    # alice splits 200_000 off her own leaf to a new leaf for bob
    bob = carve_of(alice, "bob", 200_000)
    s_bob = w.slot(bob, 3)
    spath = w.tree.path(s_alice)
    t1 = w.clone(); lt.apply_claim(t1, s_alice, s_bob, bob)
    cpath = t1.path(s_bob); r1 = t1.root()
    check(r1[1] == root[1], "SPLIT conserves sum")
    ctx = w.ctx([(r1[1], w.spk(r1))], extra_in=(600, P2WPKH))
    asig = schnorr_sign(ctx.sighash(), sk("alice-owner"))
    head = (w.path_witness(cpath) + w.path_witness(spath) + w.bm(spath) + [alice.serialize()] +
            w.bm(cpath) + [bob.serialize()])
    it = w.run("SPLIT", head + [asig, root[0], w.m], ctx)
    check(True, "SPLIT authorised by the source owner's transaction signature")

    # negatives
    expect_fail(lambda: w.run("SPLIT", head + [schnorr_sign(ctx.sighash(), w.op_sk), root[0], w.m], ctx),
                "SPLIT signed by the operator, not the owner")
    expect_fail(lambda: w.run("SPLIT", head + [schnorr_sign(ctx.sighash(), sk("bob-owner")), root[0], w.m], ctx),
                "SPLIT signed by the recipient")
    expect_fail(lambda: w.run("SPLIT", head + [bytes(64), root[0], w.m], ctx), "SPLIT garbage signature")
    # a voucher signature is over a message, not the transaction: it must not pass
    vsig = schnorr_sign(lt.voucher_msg(w.tree_id, alice, bob), sk("alice-owner"))
    expect_fail(lambda: w.run("SPLIT", head + [vsig, root[0], w.m], ctx),
                "SPLIT with a voucher signature instead of a transaction signature")
    # 7.5 rule 5 holds for SPLIT as for CLAIM: the owner cannot carve its
    # balance into a leaf with another evictor or a later lease
    for label, lf in (("another evictor key", mk_leaf("escape", 200_000, w.op_pk, alice.evict_after)),
                      ("a later evict_after", mk_leaf("later", 200_000, None, alice.evict_after + 1))):
        t_e = w.clone(); lt.apply_update(t_e, s_alice, alice.with_amount_seq(alice.amount - lf.amount, alice.seq + 1))
        s_e = w.slot(lf, 3); t_e.leaves[s_e] = lf
        ctx_e = w.ctx([(t_e.root()[1], w.spk(t_e.root()))], extra_in=(600, P2WPKH))
        expect_fail(lambda: w.run("SPLIT", w.path_witness(t_e.path(s_e)) + w.path_witness(spath) + w.bm(spath) +
                                  [alice.serialize()] + w.bm(t_e.path(s_e)) +
                                  [lf.serialize(), schnorr_sign(ctx_e.sighash(), sk("alice-owner")), root[0], w.m], ctx_e),
                    f"SPLIT into a leaf with {label} than its source")
    # over-split: the new leaf exceeds the source
    greedy = carve_of(alice, "greedy", alice.amount + 1)
    t2 = w.clone()
    expect_fail(lambda: w.run("SPLIT", w.path_witness(cpath) + w.path_witness(spath) + w.bm(spath) +
                              [alice.serialize()] + w.bm(cpath) + [greedy.serialize(), asig, root[0], w.m], ctx),
                "SPLIT over-split underflow")

    # 7.5 rule 6: the new leaf is at least DUST_MIN and the residual is zero
    # (the source position becomes E_0) or at least DUST_MIN
    def carve(lf):
        """A correct SPLIT witness and context for carving lf out of alice's leaf."""
        t = w.clone(); s_n = w.slot(lf, 3)
        if lf.amount == alice.amount:
            del t.leaves[s_alice]
        else:
            lt.apply_update(t, s_alice, alice.with_amount_seq(alice.amount - lf.amount, alice.seq + 1))
        cp = t.path(s_n); t.leaves[s_n] = lf
        ctx_c = w.ctx([(t.root()[1], w.spk(t.root()))], extra_in=(600, P2WPKH))
        return (w.path_witness(cp) + w.path_witness(spath) + w.bm(spath) + [alice.serialize()] + w.bm(cp) +
                [lf.serialize(), schnorr_sign(ctx_c.sighash(), sk("alice-owner")), root[0], w.m]), ctx_c
    for label, amt in (("one satoshi", 1), ("zero satoshis", 0), ("a one-satoshi residual", alice.amount - 1)):
        wit_d, ctx_d = carve(carve_of(alice, f"dust{amt}", amt))
        expect_fail(lambda: w.run("SPLIT", wit_d, ctx_d), f"SPLIT of {label} (7.5 rule 6)")
    for label, amt in (("exactly DUST_MIN", lt.DUST_MIN), ("the whole balance", alice.amount)):
        wit_d, ctx_d = carve(carve_of(alice, f"ok{amt}", amt))
        w.run("SPLIT", wit_d, ctx_d)
        check(True, f"SPLIT of {label} succeeds")
    # destination already occupied: prove the claim step against a non-empty slot
    occupied = w.tree.path(s_oper)
    expect_fail(lambda: w.run("SPLIT", w.path_witness(occupied) + w.path_witness(spath) + w.bm(spath) +
                              [alice.serialize()] + w.bm(occupied) + [bob.serialize(), asig, root[0], w.m], ctx),
                "SPLIT into an occupied position")
    # stale root
    expect_fail(lambda: w.run("SPLIT", head + [asig, r1[0], w.m], ctx), "SPLIT against a stale root")
    # the owner's signature covers output 0, which is the only place the new
    # leaf reaches it: a relayer cannot swap in its own leaf (7.5.2, 10.7)
    mallory = carve_of(alice, "mallory", bob.amount)
    s_mal = w.slot(mallory, 3)
    tm = w.clone(); lt.apply_claim(tm, s_alice, s_mal, mallory); rm = tm.root()
    ctx_m = w.ctx([(rm[1], w.spk(rm))], extra_in=(600, P2WPKH))
    head_m = (w.path_witness(tm.path(s_mal)) + w.path_witness(spath) + w.bm(spath) + [alice.serialize()] +
              w.bm(tm.path(s_mal)) + [mallory.serialize()])
    w.run("SPLIT", head_m + [schnorr_sign(ctx_m.sighash(), sk("alice-owner")), root[0], w.m], ctx_m)
    expect_fail(lambda: w.run("SPLIT", head_m + [asig, root[0], w.m], ctx_m),
                "SPLIT recipient swapped under the owner's signature")
    if verbose:
        claim = len(assemble(ls.claim_script(depth, w.tree_id, profile)))
        print(f"SPLIT {profile} D={depth}: script {len(script)} B (CLAIM {claim} B, saves {claim - len(script)}), "
              f"witness {sum(len(x) for x in head) + 64 + 64} B, varops {it.cost}")
    return it, len(script), sum(len(x) for x in head + [asig, root[0], w.m])


def test_carve_rules(depth, verbose=True):
    """The carve rule of spec 7.5 rule 5 against the cohort sweep (7.7).

    A member of an evictable cohort cannot plant a non-evictable leaf in
    an empty position of the cohort by SPLIT (the finding 9 attack of
    paper/reviews/crypto.md): a NUMS evictor or a later lease fails. A
    carve that keeps the member's terms lands there and is swept with the
    cohort by EVICT_SUBTREE_2. The rule is per balance, not per tree: a
    leaf the operator admitted with a NUMS evictor can still carve a NUMS
    leaf into the cohort and block the sweep, which 10.8 states. The
    planted leaf is DUST_MIN, the smallest 7.5 rule 6 admits.
    """
    w = World(depth, "D")
    height = 2
    w.compiled = dict(w.compiled)
    w.compiled["SPLIT"] = assemble(ls.split_script(depth, "D"))
    w.compiled["EVICT_SUBTREE_2"] = assemble(ls.evict_subtree_script(depth, height, w.op_pk))
    w.m = lt.taptree_root([lt.tapleaf_hash(c) for c in w.compiled.values()])
    n, base = 1 << height, 1 << height                   # subtree index 1: positions 4..7
    cohort = {base + i: mk_leaf(f"c{i}", 10_000 + 7 * i, w.op_pk, 800_000) for i in range(n - 1)}
    empty = base + n - 1
    alice = mk_leaf("alice", 50_000)                     # admitted non-evictable
    w.tree.leaves = dict(cohort); w.tree.leaves[0] = alice
    w.tree.leaves[(1 << depth) - 1] = mk_leaf("operator", 1_000_000)
    root = w.tree.root()

    def split(src, s_src, new, signer):
        """A SPLIT of `new` off `src` into the cohort's empty position."""
        t = w.clone(); lt.apply_update(t, s_src, src.with_amount_seq(src.amount - new.amount, src.seq + 1))
        cpath = t.path(empty); t.leaves[empty] = new
        ctx = w.ctx([(t.root()[1], w.spk(t.root()))], extra_in=(600, P2WPKH))
        wit = (w.path_witness(cpath) + w.path_witness(w.tree.path(s_src)) + [src.serialize(), new.serialize(),
               schnorr_sign(ctx.sighash(), sk(signer)), root[0], w.m])
        return t, wit, ctx

    member, s_member = cohort[base], base
    for label, dust in (("a NUMS evictor", mk_leaf("dust", lt.DUST_MIN)),
                        ("a later evict_after", mk_leaf("dust", lt.DUST_MIN, w.op_pk, 800_001))):
        _, wit, ctx = split(member, s_member, dust, "c0-owner")
        expect_fail(lambda: w.run("SPLIT", wit, ctx), f"cohort member plants dust with {label}")
    dust = carve_of(member, "dust", lt.DUST_MIN)
    t1, wit, ctx = split(member, s_member, dust, "c0-owner")
    w.run("SPLIT", wit, ctx)
    check(True, "a carve that keeps the member's evictor and lease lands in the cohort")

    # the sweep still covers the whole cohort, dust included
    w.tree = t1
    root1 = w.tree.root()
    rest = w.clone()
    for p in range(base, base + n):
        del rest.leaves[p]
    outs = [(rest.root()[1], w.spk(rest.root()))]
    outs += [(w.tree.leaves[p].amount, lt.p2tr_spk(w.tree.leaves[p].exit_key)) for p in range(base, base + n)]
    ctx_s = w.ctx(outs + [(400, P2WPKH)], extra_in=(5_000, P2WPKH), locktime=800_000)
    leaves_rev = [w.tree.leaves[p].serialize() for p in reversed(range(base, base + n))]
    w.run("EVICT_SUBTREE_2", w.path_witness(w.tree.path(base, height=height), height) + leaves_rev +
          [schnorr_sign(ctx_s.sighash(), w.op_sk), root1[0], w.m], ctx_s)
    check(True, "EVICT_SUBTREE_2 sweeps the cohort including the carved dust leaf")

    # the residual 10.8 names: a non-evictable member's dust blocks the sweep
    w.tree = lt.Tree(depth); w.tree.leaves = dict(cohort); w.tree.leaves[0] = alice
    w.tree.leaves[(1 << depth) - 1] = mk_leaf("operator", 1_000_000)
    root = w.tree.root()
    nums_dust = carve_of(alice, "dust", lt.DUST_MIN)
    t2, wit, ctx = split(alice, 0, nums_dust, "alice-owner")
    w.run("SPLIT", wit, ctx)
    w.tree = t2
    rest = w.clone()
    for p in range(base, base + n):
        del rest.leaves[p]
    outs = [(rest.root()[1], w.spk(rest.root()))]
    outs += [(w.tree.leaves[p].amount, lt.p2tr_spk(w.tree.leaves[p].exit_key)) for p in range(base, base + n)]
    ctx_b = w.ctx(outs + [(400, P2WPKH)], extra_in=(5_000, P2WPKH), locktime=800_000)
    leaves_rev = [w.tree.leaves[p].serialize() for p in reversed(range(base, base + n))]
    expect_fail(lambda: w.run("EVICT_SUBTREE_2", w.path_witness(w.tree.path(base, height=height), height) + leaves_rev +
                              [schnorr_sign(ctx_b.sighash(), w.op_sk), w.tree.root()[0], w.m], ctx_b),
                "a non-evictable member's NUMS dust still blocks the sweep (10.8)")
    if verbose:
        print(f"carve rules D={depth}: dust with another evictor or a later lease rejected, "
              f"inherited dust swept with the cohort")


def test_swap(depth, verbose=True):
    """One payment hash settling both legs of a swap (spec 13.9).

    The tree leg is a hash-locked voucher (7.5.1) redeemed with `CLAIM^h`;
    the channel leg is an `HTLC_SUCCESS` output of a channel-leaf settlement
    transaction (Appendix C.4.1). The point of the test is that a single
    32-byte preimage satisfies both, which is what makes the exchange
    atomic: whichever leg is resolved first publishes the preimage, and the
    other leg can then be resolved with it.
    """
    w = World(depth, "D")
    toks = ls.claim_script(depth, w.tree_id, "D", hashlock=True)
    w.compiled = dict(w.compiled); w.compiled["CLAIM_H"] = assemble(toks)
    w.m = lt.taptree_root([lt.tapleaf_hash(c) for c in w.compiled.values()])
    oper = mk_leaf("operator", 1_000_000)
    alice = mk_leaf("alice", 50_000)
    s_oper, s_alice = w.slot(oper, (1 << depth) - 1), w.slot(alice, 0)
    w.tree.leaves = {s_oper: oper, s_alice: alice}

    # One secret for both legs.
    preimage = lt.sha256(b"swap-preimage")
    payment_hash = lt.sha256(preimage)

    # ---- channel leg: HTLC_SUCCESS and HTLC_TIMEOUT (C.4.1) ----
    y_sk, y_pk = sk("htlc-claim"), pubkey_x(sk("htlc-claim"))
    x_sk, x_pk = sk("htlc-offer"), pubkey_x(sk("htlc-offer"))
    cltv = 900_000
    succ = ls.htlc_success_script(payment_hash, y_pk)
    tmo = ls.htlc_timeout_script(cltv, x_pk)
    for name, t in (("HTLC_SUCCESS", succ), ("HTLC_TIMEOUT", tmo)):
        bad = {x for x in t if isinstance(x, str)} - ALLOWED_OPCODES
        check(not bad, f"{name} uses non-candidate opcodes: {sorted(bad)}")
    succ_c, tmo_c = assemble(succ), assemble(tmo)
    check(len(succ_c) == 73, f"HTLC_SUCCESS is 73 bytes (C.4.1), got {len(succ_c)}")
    check(len(tmo_c) == 40, f"HTLC_TIMEOUT is 40 bytes (C.4.1), got {len(tmo_c)}")

    # a settlement-spending transaction; the HTLC output is input 0
    htlc_ctx = TxContext([(30_000, lt.p2tr_spk(y_pk))], [(29_000, lt.p2tr_spk(y_pk))])
    ysig = schnorr_sign(htlc_ctx.sighash(), y_sk)
    Interp(htlc_ctx).run(succ_c, [ysig, preimage])
    check(True, "HTLC_SUCCESS resolved with the shared preimage")
    expect_fail(lambda: Interp(htlc_ctx).run(succ_c, [ysig, lt.sha256(b"wrong")]),
                "HTLC_SUCCESS wrong preimage")
    expect_fail(lambda: Interp(htlc_ctx).run(succ_c, [ysig, preimage[:31]]),
                "HTLC_SUCCESS preimage not 32 bytes")
    expect_fail(lambda: Interp(htlc_ctx).run(succ_c, [schnorr_sign(htlc_ctx.sighash(), x_sk), preimage]),
                "HTLC_SUCCESS claimed by the offerer")
    early = TxContext([(30_000, lt.p2tr_spk(x_pk))], [(29_000, lt.p2tr_spk(x_pk))], locktime=cltv - 1)
    expect_fail(lambda: Interp(early).run(tmo_c, [schnorr_sign(early.sighash(), x_sk)]),
                "HTLC_TIMEOUT before cltv_expiry")
    late = TxContext([(30_000, lt.p2tr_spk(x_pk))], [(29_000, lt.p2tr_spk(x_pk))], locktime=cltv)
    Interp(late).run(tmo_c, [schnorr_sign(late.sighash(), x_sk)])
    check(True, "HTLC_TIMEOUT at cltv_expiry")
    expect_fail(lambda: Interp(late).run(tmo_c, [schnorr_sign(late.sighash(), y_sk)]),
                "HTLC_TIMEOUT claimed by the recipient")

    # ---- tree leg: the same preimage redeems the voucher ----
    root = w.tree.root()
    src = w.tree.leaves[s_oper]
    bought = carve_of(src, "bought", 40_000)
    s_bought = w.slot(bought, 3)
    spath = w.tree.path(s_oper)
    t1 = w.clone(); lt.apply_claim(t1, s_oper, s_bought, bought)
    cpath = t1.path(s_bought); r1 = t1.root()
    ctx = w.ctx([(r1[1], w.spk(r1))], extra_in=(600, P2WPKH))
    hsig = schnorr_sign(lt.voucher_h_msg(w.tree_id, src, bought, payment_hash), sk("operator-owner"))
    head = (w.path_witness(cpath) + w.path_witness(spath) + w.bm(spath) + [src.serialize()] +
            w.bm(cpath) + [bought.serialize()])
    w.run("CLAIM_H", head + [hsig, preimage, root[0], w.m], ctx)
    check(True, "CLAIM^h redeemed with the same preimage")
    expect_fail(lambda: w.run("CLAIM_H", head + [hsig, lt.sha256(b"wrong"), root[0], w.m], ctx),
                "CLAIM^h rejects the preimage of a different hash")

    # ---- the property the swap rests on ----
    check(lt.sha256(preimage) == payment_hash,
          "one 32-byte preimage hashes to the payment hash both legs name")
    check(succ_c[succ_c.index(payment_hash):][:32] == payment_hash,
          "HTLC_SUCCESS commits to the same payment hash the voucher signed")
    if verbose:
        print(f"swap D={depth}: HTLC_SUCCESS {len(succ_c)} B, HTLC_TIMEOUT {len(tmo_c)} B, "
              f"CLAIM^h script {len(w.compiled['CLAIM_H'])} B; one preimage settles both legs")


def test_audit_negatives(depth, verbose=True):
    """Negative cases the byte-level audit (design/audit/script.md) found no
    test for. Each targets one rule of section 7 or one encoding check of
    section 8 by mutating a single element of a passing witness or one
    field of a passing transaction.

    EXIT: a non-minimal `is_evict` or `dir` (MINIMALIF), a leaf or sibling
    of the wrong length, a sibling whose `enc64` suffix is not 0x01, a
    payout at the wrong output index, two `EXIT_2` steps naming the same
    position (7.6), and an owner payout one sat over `leaf.amount` under
    `EXIT_1^=` (7.2 rule 6). JOIN: `new_hash` and `new_sum` of the wrong
    length. REWRITE_2 (7.9 rule 3): an `exit_key` change, an amount
    decrease, and an amount increase paired with a nonce change, each
    without the owner's signature; a spurious signature under an unchanged
    position; old and new elements swapped at an exit position; a 1-byte
    old element. EVICT_SUBTREE_2 (7.7): an occupied position presented as
    empty, two leaves in swapped positions, payouts in the wrong order and
    an empty position supplied as 116 zero bytes."""
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
    tail = [bob.serialize(), sig, b"", root[0], w.m]
    w.run("EXIT_1", pw + tail, ctx)
    expect_fail(lambda: w.run("EXIT_1", pw + [bob.serialize(), sig, b"\x02", root[0], w.m], ctx), "EXIT_1 is_evict = 0x02 (MINIMALIF)")
    expect_fail(lambda: w.run("EXIT_1", pw + [bob.serialize()[:115], sig, b"", root[0], w.m], ctx), "EXIT_1 leaf of 115 bytes")
    expect_fail(lambda: w.run("EXIT_1", pw + [bob.serialize() + b"\x00", sig, b"", root[0], w.m], ctx), "EXIT_1 leaf of 117 bytes")
    for mut, label in ((lambda sc: sc[:40], "40-byte sibling"), (lambda sc: sc + b"\x00", "42-byte sibling"),
                       (lambda sc: sc[:40] + b"\x02", "sibling with enc64 suffix 0x02")):
        pw2 = list(pw); pw2[1] = mut(pw2[1])
        expect_fail(lambda: w.run("EXIT_1", pw2 + tail, ctx), f"EXIT_1 {label}")
    for dv, label in ((b"\x02", "0x02"), (b"\x00", "0x00")):
        pw3 = list(pw); pw3[0] = dv
        expect_fail(lambda: w.run("EXIT_1", pw3 + tail, ctx), f"EXIT_1 dir = {label} (MINIMALIF)")
    outs3 = [(r1[1], w.spk(r1)), (400, P2WPKH), (bob.amount - 1_000, lt.p2tr_spk(bob.exit_key))]
    ctx3 = w.ctx(outs3, extra_in=(5_000, P2WPKH))
    expect_fail(lambda: w.run("EXIT_1", pw + [bob.serialize(), schnorr_sign(ctx3.sighash(), sk("bob-owner")), b"", root[0], w.m], ctx3),
                "EXIT_1 payout at output 2 instead of 1")
    # EXIT_2 naming the same position twice (7.6): the second step finds E_0
    outs2 = [(r1[1], w.spk(r1)), (bob.amount, lt.p2tr_spk(bob.exit_key)), (bob.amount, lt.p2tr_spk(bob.exit_key))]
    ctx2 = w.ctx(outs2, extra_in=(5_000, P2WPKH))
    s2 = schnorr_sign(ctx2.sighash(), sk("bob-owner"))
    expect_fail(lambda: w.run("EXIT_2", w.path_witness(t1.path(5)) + [bob.serialize(), s2, b""] + pw + [bob.serialize(), s2, b""] + [root[0], w.m], ctx2),
                "EXIT_2 the same position in both steps")
    # EXIT_1^= with a surplus
    exact = assemble(ls.exit_script(depth, 1, "D", exact=True))
    w2 = World(depth, "D"); w2.compiled = dict(w2.compiled); w2.compiled["EXIT_1"] = exact
    w2.m = lt.taptree_root([lt.tapleaf_hash(c) for c in w2.compiled.values()])
    w2.tree.leaves = {0: alice, 5: bob}
    ctx_s = w2.ctx([(r1[1], w2.spk(r1)), (bob.amount + 1, lt.p2tr_spk(bob.exit_key))], extra_in=(5_000, P2WPKH))
    expect_fail(lambda: w2.run("EXIT_1", w2.path_witness(path) + [bob.serialize(), schnorr_sign(ctx_s.sighash(), sk("bob-owner")), b"", root[0], w2.m], ctx_s),
                "EXIT_1^= owner payout one sat over leaf.amount")

    # JOIN_2: new_hash and new_sum of the wrong length
    w3 = World(depth, "D", join_heights=(0, 2))
    w3.tree.leaves = {0: alice}
    root3 = w3.tree.root()
    h, idx = 2, 2
    jpath = w3.tree.path(idx << h, height=h)
    carol = mk_leaf("carol", 30_000, w3.op_pk, 900_000)
    t2 = w3.clone(); lt.apply_join(t2, h, idx, {0: carol})
    node, r2 = t2.subtree(h, idx), t2.root()
    ctxj = w3.ctx([(r2[1], w3.spk(r2))], extra_in=(node[1] + 2_000, P2WPKH))
    osig = schnorr_sign(ctxj.sighash(), w3.op_sk)
    pwj = w3.path_witness(jpath, h)
    w3.run("JOIN_2", pwj + [node[0], lt.le64(node[1]), osig, root3[0], w3.m], ctxj)
    expect_fail(lambda: w3.run("JOIN_2", pwj + [node[0], lt.le64(node[1])[:7], osig, root3[0], w3.m], ctxj), "JOIN_2 new_sum of 7 bytes")
    expect_fail(lambda: w3.run("JOIN_2", pwj + [node[0], lt.le64(node[1]) + b"\x00", osig, root3[0], w3.m], ctxj), "JOIN_2 new_sum of 9 bytes")
    expect_fail(lambda: w3.run("JOIN_2", pwj + [node[0][:31], lt.le64(node[1]), osig, root3[0], w3.m], ctxj), "JOIN_2 new_hash of 31 bytes")

    # REWRITE_2 (7.9 rule 3): changes that need the owner's signature, without it
    c = rewrite_case(depth, 2, "mixed")
    wr, name, path_r, base, old, new, rootr = c["w"], c["name"], c["path"], c["base"], c["old"], c["new"], c["root"]
    n = 4

    def run_rewrite(old_, new_, outs=None, sign=True, extra_sig_at=None):
        t = wr.clone()
        for i, x in new_.items():
            if x:
                t.leaves[base + i] = x
            else:
                t.leaves.pop(base + i, None)
        outs = outs or ([(t.root()[1], wr.spk(t.root()))] +
                        [(old_[i].amount, lt.p2tr_spk(old_[i].exit_key)) for i in range(n) if old_[i] and new_[i] is None] + [(400, P2WPKH)])
        delta = t.root()[1] - rootr[1]
        ctx_ = wr.ctx(outs, extra_in=(max(delta, 0) + 5_000, P2WPKH))
        wit, _ = _rewrite_witness(wr, 2, path_r, old_, new_, ctx_, rootr, schnorr_sign(ctx_.sighash(), wr.op_sk), False, sign)
        if extra_sig_at is not None:
            pos = wit.index(old_[extra_sig_at].serialize()) - 1       # below the position's new element
            wit = wit[:pos] + [schnorr_sign(ctx_.sighash(), sk(f"c{extra_sig_at}-owner"))] + wit[pos:]
        return wr.run(name, wit, ctx_)
    i_same = next(i for i in range(n) if old[i] and new[i] and old[i].serialize() == new[i].serialize())
    lf = old[i_same]
    nk = dict(new); nk[i_same] = lt.Leaf(lf.amount, pubkey_x(sk("mallory-exit")), lf.owner_key, lf.evictor_key, lf.evict_after, lf.nonce, lf.seq)
    expect_fail(lambda: run_rewrite(old, nk, sign=False), f"{name} exit_key changed without the owner signature")
    run_rewrite(old, nk, sign=True)
    check(True, f"{name} exit_key changed with the owner signature")
    nd = dict(new); nd[i_same] = lf.with_amount_seq(lf.amount - 1, lf.seq)
    expect_fail(lambda: run_rewrite(old, nd, sign=False), f"{name} amount decreased without the owner signature")
    nn = dict(new); nn[i_same] = lt.Leaf(lf.amount + 1, lf.exit_key, lf.owner_key, lf.evictor_key, lf.evict_after, lf.nonce + 1, lf.seq)
    expect_fail(lambda: run_rewrite(old, nn, sign=False), f"{name} amount increase with a nonce change, no owner signature")
    expect_fail(lambda: run_rewrite(old, new, extra_sig_at=i_same), f"{name} spurious signature under an unchanged position")
    i_exit = next(i for i in range(n) if old[i] and new[i] is None)
    sw_old, sw_new = dict(old), dict(new)
    sw_old[i_exit], sw_new[i_exit] = None, old[i_exit]
    expect_fail(lambda: run_rewrite(sw_old, sw_new), f"{name} old and new elements swapped at an exit position")

    def one_byte():
        wit = list(c["wit"]); wit[wit.index(lf.serialize())] = ls.REWRITE_SAME
        return wr.run(name, wit, c["ctx"])
    expect_fail(one_byte, f"{name} a 1-byte old element (the marker is for the new element only)")

    # EVICT_SUBTREE_2 (7.7): positions and payouts out of order, an empty slot as 116 zero bytes
    we = World(depth, "D")
    ename = "EVICT_SUBTREE_2"
    we.compiled = dict(we.compiled); we.compiled[ename] = assemble(ls.evict_subtree_script(depth, 2, we.op_pk))
    we.m = lt.taptree_root([lt.tapleaf_hash(x) for x in we.compiled.values()])
    cohort = {4 + i: mk_leaf(f"c{i}", 10_000 + 7 * i, we.op_pk, 800_000) for i in range(4) if i != 2}
    we.tree.leaves = dict(cohort); we.tree.leaves[0] = alice
    roote = we.tree.root()
    pathe = we.tree.path(4, height=2)
    te = we.clone()
    for p_ in cohort:
        del te.leaves[p_]
    re_ = te.root()

    def run_evict(leaves_rev, outs):
        ctx_ = we.ctx(outs, extra_in=(5_000, P2WPKH), locktime=800_000)
        return we.run(ename, we.path_witness(pathe, 2) + leaves_rev + [schnorr_sign(ctx_.sighash(), we.op_sk), roote[0], we.m], ctx_)
    present = [4 + i for i in range(4) if 4 + i in cohort]
    outs_e = [(re_[1], we.spk(re_))] + [(cohort[p_].amount, lt.p2tr_spk(cohort[p_].exit_key)) for p_ in present] + [(400, P2WPKH)]
    lr = [cohort[4 + i].serialize() if 4 + i in cohort else b"" for i in reversed(range(4))]
    run_evict(lr, outs_e)
    hide = list(lr); hide[-1] = b""
    expect_fail(lambda: run_evict(hide, [outs_e[0]] + outs_e[2:]), f"{ename} an occupied position presented as empty")
    swap = list(lr); swap[-1], swap[-2] = swap[-2], swap[-1]
    expect_fail(lambda: run_evict(swap, outs_e), f"{ename} two leaves in swapped positions")
    expect_fail(lambda: run_evict(lr, [outs_e[0], outs_e[2], outs_e[1]] + outs_e[3:]), f"{ename} payouts in the wrong order")
    ez = list(lr); ez[1] = bytes(116)
    expect_fail(lambda: run_evict(ez, outs_e), f"{ename} an empty position supplied as 116 zero bytes")
    if verbose:
        print(f"audit negatives D={depth}: EXIT, JOIN, REWRITE_2 and EVICT_SUBTREE_2 mutations rejected")


def test_exit_tower(depth, profile, verbose=True):
    """EXIT_K^t (spec 7.2 rule 7): the exact-payout exit whose owner branch
    takes an off-chain BIP-340 signature over H_exit(tree_id || leaf),
    checked by OP_CHECKSIGFROMSTACK, in place of a transaction signature.

    A tower, not the owner, builds and broadcasts the exit with its own fee
    input; the same authorisation is rebuilt against a new root after a
    competing spend; an authorisation under the voucher tag, for another
    tree_id, for a changed leaf (seq advanced), a transaction signature or
    an empty element in the owner branch, and a payout below or above the
    amount all fail; the evict branch still takes the evictor's transaction
    signature under the lock time, and rejects a stack authorisation; and
    EXIT_2^t runs on two authorisations, or one and an eviction. The
    variant is a tree-creation parameter (TreeOptions tower=True), which
    implies exact payouts and is kept by a detached child (7.10 rule 3).
    """
    opts = ls.TreeOptions(pubkey_x(sk("operator")), TREE_ID, profile=profile,
                          join_heights=(0, 2), exit_ks=(1, 2), tower=True)
    check(opts.exact, "EXIT^t implies exact payouts")
    scripts = opts.at_depth(depth)
    w = World(depth, profile, scripts=scripts)
    tower = w.compiled["EXIT_1"]
    check(tower == assemble(ls.exit_script(depth, 1, profile, tower=True, tree_id=TREE_ID)),
          "TreeOptions compiles EXIT_1^t")
    check(tower != assemble(ls.exit_script(depth, 1, profile, exact=True)), "EXIT_1^t differs from EXIT_1^=")
    check("OP_CHECKSIGFROMSTACK" in scripts["EXIT_1"], "EXIT_1^t checks the authorisation with OP_CHECKSIGFROMSTACK")
    if profile == "D" and depth > 2:
        child = opts.at_depth(2)["EXIT_1"]
        check(assemble(child) == assemble(ls.exit_script(2, 1, "D", tower=True, tree_id=TREE_ID)),
              "a detached child keeps EXIT_1^t (7.10 rule 3)")
    D = depth
    alice = mk_leaf("alice", 50_000)
    bob = mk_leaf("bob", 125_000, evictor=w.op_pk, evict_after=800_000)
    oper = mk_leaf("operator", 1_000_000)
    s_alice, s_bob, s_oper = w.slot(alice, 0), w.slot(bob, 5), w.slot(oper, (1 << D) - 1)
    w.tree.leaves = {s_alice: alice, s_bob: bob, s_oper: oper}
    other_tid = lt.tree_id(lt.sha256(b"another-tree"), 0)
    auth = schnorr_sign(lt.exit_auth_msg(TREE_ID, bob), sk("bob-owner"))

    def exit_tx(tree, leaf, slot, amount=None, locktime=0):
        """The tower's exit of `leaf` from `tree`: a context paying the leaf
        exactly from a fee input of the tower's own, and the witness below
        the authorisation."""
        root = tree.root()
        path = tree.path(slot)
        t1 = lt.Tree(D); t1.leaves = dict(tree.leaves); lt.apply_exit(t1, slot); r1 = t1.root()
        w.tree = tree
        ctx = w.ctx([(r1[1], w.spk(r1)), (leaf.amount if amount is None else amount, lt.p2tr_spk(leaf.exit_key))],
                    extra_in=(600, P2WPKH), locktime=locktime)
        return ctx, w.path_witness(path), root, t1

    # the tower broadcasts with the owner's authorisation and its own fee input
    tree0 = w.clone()
    ctx, pw, root, t1 = exit_tx(tree0, bob, s_bob)
    wit = pw + [bob.serialize(), auth, b"", root[0], w.m]
    it = w.run("EXIT_1", wit, ctx)
    check(True, "EXIT_1^t: a tower exits the leaf on the owner's authorisation")
    sizes = (it, len(tower), sum(len(x) for x in wit))
    # negatives against the same transaction
    expect_fail(lambda: w.run("EXIT_1", pw + [bob.serialize(), schnorr_sign(ctx.sighash(), sk("bob-owner")), b"", root[0], w.m], ctx),
                "EXIT_1^t: a transaction signature is not an authorisation")
    expect_fail(lambda: w.run("EXIT_1", pw + [bob.serialize(), b"", b"", root[0], w.m], ctx),
                "EXIT_1^t: empty authorisation")
    voucher_tagged = schnorr_sign(lt.tagged_hash(lt.TAG_VOUCHER, TREE_ID + bob.serialize()), sk("bob-owner"))
    expect_fail(lambda: w.run("EXIT_1", pw + [bob.serialize(), voucher_tagged, b"", root[0], w.m], ctx),
                "EXIT_1^t: an authorisation under the voucher tag")
    expect_fail(lambda: w.run("EXIT_1", pw + [bob.serialize(), schnorr_sign(lt.exit_auth_msg(other_tid, bob), sk("bob-owner")), b"", root[0], w.m], ctx),
                "EXIT_1^t: an authorisation for another tree_id")
    expect_fail(lambda: w.run("EXIT_1", pw + [bob.serialize(), schnorr_sign(lt.exit_auth_msg(TREE_ID, bob), sk("alice-owner")), b"", root[0], w.m], ctx),
                "EXIT_1^t: an authorisation by another owner")
    # a payout below or above the amount: the variant is exact-payout only
    ctx_lo, pw_lo, root_lo, _ = exit_tx(tree0, bob, s_bob, amount=bob.amount - 500)
    expect_fail(lambda: w.run("EXIT_1", pw_lo + [bob.serialize(), auth, b"", root_lo[0], w.m], ctx_lo),
                "EXIT_1^t: payout below the amount")
    ctx_hi, pw_hi, root_hi, _ = exit_tx(tree0, bob, s_bob, amount=bob.amount + 1)
    expect_fail(lambda: w.run("EXIT_1", pw_hi + [bob.serialize(), auth, b"", root_hi[0], w.m], ctx_hi),
                "EXIT_1^t: payout above the amount")
    # a competing spend confirms first (alice exits): the tower rebuilds
    # the same authorisation against the new root
    tree2 = w.clone(); lt.apply_exit(tree2, s_alice)
    ctx2, pw2, root2, t3 = exit_tx(tree2, bob, s_bob)
    w.run("EXIT_1", pw2 + [bob.serialize(), auth, b"", root2[0], w.m], ctx2)
    check(True, "EXIT_1^t: the authorisation is rebuilt against a new root after a competing spend")
    # the leaf changed (seq advanced by an UPDATE): the authorisation is void
    bob2 = bob.with_amount_seq(bob.amount, 1)
    tree3 = lt.Tree(D); tree3.leaves = {s_alice: alice, s_bob: bob2, s_oper: oper}
    ctx3, pw3, root3, _ = exit_tx(tree3, bob2, s_bob)
    expect_fail(lambda: w.run("EXIT_1", pw3 + [bob2.serialize(), auth, b"", root3[0], w.m], ctx3),
                "EXIT_1^t: an authorisation for the leaf before it changed")
    auth2 = schnorr_sign(lt.exit_auth_msg(TREE_ID, bob2), sk("bob-owner"))
    w.run("EXIT_1", pw3 + [bob2.serialize(), auth2, b"", root3[0], w.m], ctx3)
    check(True, "EXIT_1^t: a fresh authorisation over the changed leaf")
    # an amount-only increase (REWRITE_h rule 3, the operator alone) leaves
    # the authorisation valid: the message binds the leaf without its
    # amount, and the exit pays the leaf's current amount, not the old one
    bob_up = bob.with_amount_seq(bob.amount + 500, bob.seq)
    tree4 = lt.Tree(D); tree4.leaves = {s_alice: alice, s_bob: bob_up, s_oper: oper}
    ctx4, pw4, root4, _ = exit_tx(tree4, bob_up, s_bob)
    w.run("EXIT_1", pw4 + [bob_up.serialize(), auth, b"", root4[0], w.m], ctx4)
    check(True, "EXIT_1^t: the authorisation survives an amount-only top-up of the leaf")
    ctx4o, pw4o, root4o, _ = exit_tx(tree4, bob_up, s_bob, amount=bob.amount)
    expect_fail(lambda: w.run("EXIT_1", pw4o + [bob_up.serialize(), auth, b"", root4o[0], w.m], ctx4o),
                "EXIT_1^t: the exit after a top-up pays the amount at signing")
    for label, lf in (("exit_key", lt.Leaf(bob.amount, pubkey_x(sk("other-exit")), bob.owner_key, bob.evictor_key, bob.evict_after, bob.nonce, bob.seq)),
                      ("evictor_key", lt.Leaf(bob.amount, bob.exit_key, bob.owner_key, lt.NUMS_X, bob.evict_after, bob.nonce, bob.seq)),
                      ("evict_after", lt.Leaf(bob.amount, bob.exit_key, bob.owner_key, bob.evictor_key, bob.evict_after + 1, bob.nonce, bob.seq)),
                      ("nonce", lt.Leaf(bob.amount, bob.exit_key, bob.owner_key, bob.evictor_key, bob.evict_after, bob.nonce + 1, bob.seq))):
        s_c = w.slot(lf, 5)
        tree5 = lt.Tree(D); tree5.leaves = {s_alice: alice, s_c: lf, s_oper: oper}
        ctx5, pw5, root5, _ = exit_tx(tree5, lf, s_c)
        expect_fail(lambda: w.run("EXIT_1", pw5 + [lf.serialize(), auth, b"", root5[0], w.m], ctx5),
                    f"EXIT_1^t: an authorisation for the leaf before its {label} changed")
    # the evict branch is unchanged: the evictor signs the transaction under the lock time
    ctx_e, pw_e, root_e, _ = exit_tx(tree0, bob, s_bob, locktime=800_000)
    esig = schnorr_sign(ctx_e.sighash(), w.op_sk)
    w.run("EXIT_1", pw_e + [bob.serialize(), esig, b"\x01", root_e[0], w.m], ctx_e)
    check(True, "EXIT_1^t: eviction")
    expect_fail(lambda: w.run("EXIT_1", pw_e + [bob.serialize(), auth, b"\x01", root_e[0], w.m], ctx_e),
                "EXIT_1^t: a stack authorisation in the evict branch")
    ctx_early, pw_early, root_early, _ = exit_tx(tree0, bob, s_bob, locktime=799_999)
    expect_fail(lambda: w.run("EXIT_1", pw_early + [bob.serialize(), schnorr_sign(ctx_early.sighash(), w.op_sk), b"\x01", root_early[0], w.m], ctx_early),
                "EXIT_1^t: eviction before the lease")
    # EXIT_2^t: two authorisations, then one authorisation and an eviction
    w.tree = w.clone(); w.tree.leaves = dict(tree0.leaves)
    root = w.tree.root()
    t7 = w.clone()
    path_a = t7.path(s_alice); del t7.leaves[s_alice]
    path_b = t7.path(s_bob); del t7.leaves[s_bob]
    r7 = t7.root()
    auth_a = schnorr_sign(lt.exit_auth_msg(TREE_ID, alice), sk("alice-owner"))
    outs = [(r7[1], w.spk(r7)), (alice.amount, lt.p2tr_spk(alice.exit_key)), (bob.amount, lt.p2tr_spk(bob.exit_key))]
    ctx7 = w.ctx(outs, extra_in=(600, P2WPKH))
    block2 = w.path_witness(path_b) + [bob.serialize(), auth, b""]
    block1 = w.path_witness(path_a) + [alice.serialize(), auth_a, b""]
    w.run("EXIT_2", block2 + block1 + [root[0], w.m], ctx7)
    check(True, "EXIT_2^t: two authorisations, anyone assembles the transaction")
    expect_fail(lambda: w.run("EXIT_2", block2 + w.path_witness(path_a) + [alice.serialize(), auth, b""] + [root[0], w.m], ctx7),
                "EXIT_2^t: bob's authorisation presented for alice")
    ctx8 = w.ctx(outs, extra_in=(600, P2WPKH), locktime=800_000)
    esig8 = schnorr_sign(ctx8.sighash(), w.op_sk)
    w.run("EXIT_2", w.path_witness(path_b) + [bob.serialize(), esig8, b"\x01"] + block1 + [root[0], w.m], ctx8)
    check(True, "EXIT_2^t: one authorisation and one eviction")
    if verbose:
        plain = len(assemble(ls.exit_script(depth, 1, profile)))
        exact = len(assemble(ls.exit_script(depth, 1, profile, exact=True)))
        print(f"EXIT_1^t {profile} D={depth}: script {len(tower)} B (EXIT_1 {plain} B, EXIT_1^= {exact} B), "
              f"witness {sizes[2]} B")
    return sizes


RECLAIM_SK = sk("operator-reclaim")


class PendingWorld:
    """A dense tree carrying the pending-leaf receive (design/pending-receive.md):
    RECLAIM_KEY, RECLAIM_1, CLAIM^m, CLAIM^hm, CLAIM^x and the R1/R3 rewrite at
    heights 1 and 2, in the credit-leaf configuration (UPDATE^x, exact exits,
    REWRITE_h^x)."""

    def __init__(self, depth):
        self.depth = depth
        self.rk = pubkey_x(RECLAIM_SK)
        op_pk = pubkey_x(sk("operator"))
        self.opts = ls.TreeOptions(op_pk, TREE_ID, exit_ks=(1,), exact=True, update_x=True,
                                   claim=False, claim_x=True, rewrite_heights=(1, 2), rewrite_x=True,
                                   reclaim_key=self.rk, claim_m=True, claim_hm=True)
        self.w = World(depth, "D", scripts=self.opts.at_depth(depth))
        self.rcpt = pubkey_x(sk("rcpt-exit"))

    def pending(self, amount, deadline, label="P", seq=0):
        """P: owned by the operator, paid to the recipient, reclaimable at `deadline`."""
        return lt.Leaf(amount, self.rcpt, pubkey_x(sk("operator-owner")), self.rk, deadline,
                       int.from_bytes(lt.sha256(label.encode())[:4], "little"), seq)

    def landing(self, amount, label="L", lease=900_000, owner=None, evictor=None, seq=0):
        """L: owned and exited by the recipient, evictable by the operator after a long lease."""
        return lt.Leaf(amount, self.rcpt, owner or self.rcpt, evictor or self.w.op_pk, lease,
                       int.from_bytes(lt.sha256(label.encode())[:4], "little"), seq)


def _merge_case(pw, p_slot, l_slot, P, L, X, preimage=None, signer="operator-owner", flag=None,
                tree_id=TREE_ID, msg_target=None, msg_x=None):
    """Build a CLAIM^m (or CLAIM^hm with a preimage) redemption against the pair."""
    w = pw.w
    w.tree.leaves = {p_slot: P, l_slot: L, 0: mk_leaf("alice", 50_000)}
    root = w.tree.root()
    t1 = w.clone()
    try:
        lt.apply_merge(t1, p_slot, l_slot, X)
    except AssertionError:
        # an invalid merge, for a negative: build what the transaction would
        # claim (target at X, source lowered or emptied, amounts clamped)
        d = X - L.amount
        t1.leaves[l_slot] = L.with_amount_seq(max(X, 0), L.seq)
        if P.amount - d > 0:
            t1.leaves[p_slot] = P.with_amount_seq(P.amount - d, P.seq)
        else:
            t1.leaves.pop(p_slot, None)
    r1 = t1.root()
    ctx = w.ctx([(r1[1], w.spk(r1))], extra_in=(600, P2WPKH))
    ph = lt.sha256(preimage) if preimage is not None else None
    msg = lt.voucher_m_msg(tree_id, P, msg_target or L, msg_x if msg_x is not None else X, ph)
    vsig = schnorr_sign(msg, sk(signer))
    left, right = (P, L) if p_slot % 2 == 0 else (L, P)
    f = flag if flag is not None else (b"\x01" if p_slot % 2 == 0 else b"")
    path = w.tree.path(min(p_slot, l_slot), height=1)
    wit = w.path_witness(path, 1) + [left.serialize(), right.serialize(), f, lt.le64(X), vsig]
    if preimage is not None:
        wit.append(preimage)
    return wit + [root[0], w.m], ctx, t1


def test_merge(depth, verbose=True):
    """CLAIM^m and CLAIM^hm (design/pending-receive.md R2): raise the source's
    sibling, owned by the source's exit key, to an absolute amount."""
    pw = PendingWorld(depth)
    w = pw.w
    pre = lt.sha256(b"receive-preimage")
    P = pw.pending(20_000, 700_000)
    L = pw.landing(10_000)
    # hash-locked: raise L from 10,000 to 13,000, source on the left
    wit, ctx, t1 = _merge_case(pw, 2, 3, P, L, 13_000, pre)
    it = w.run("CLAIM_HM", wit, ctx)
    check(t1.leaves[3].amount == 13_000 and t1.leaves[2].amount == 17_000 and t1.leaves[2].seq == P.seq,
          "CLAIM^hm: target raised to X, source lowered by the difference, source seq unchanged")
    hm_size, hm_wit = len(w.compiled["CLAIM_HM"]), sum(len(x) for x in wit)
    # source on the right
    wit_r, ctx_r, _ = _merge_case(pw, 5, 4, P, L, 13_000, pre)
    w.run("CLAIM_HM", wit_r, ctx_r)
    check(True, "CLAIM^hm with the source on the right of the pair")
    # plain merge
    wit_m, ctx_m, _ = _merge_case(pw, 2, 3, P, L, 12_500)
    w.run("CLAIM_M", wit_m, ctx_m)
    check(True, "CLAIM^m raises the target with no preimage")
    m_size = len(w.compiled["CLAIM_M"])
    # draining the source makes its position E_0
    wit_d, ctx_d, t_d = _merge_case(pw, 2, 3, P, L, 30_000)
    w.run("CLAIM_M", wit_d, ctx_d)
    check(2 not in t_d.leaves, "CLAIM^m draining the source leaves E_0")

    # replay and ordering: target levels are absolute
    raised = L.with_amount_seq(13_000, L.seq)
    lowered = P.with_amount_seq(17_000, P.seq)
    expect_fail(lambda: w.run("CLAIM_HM", *_merge_case(pw, 2, 3, lowered, raised, 13_000, pre)[:2]),
                "CLAIM^hm replayed after the target reached X")
    expect_fail(lambda: w.run("CLAIM_HM", *_merge_case(pw, 2, 3, lowered, raised, 11_000, pre)[:2]),
                "CLAIM^hm older, smaller target after a larger one")
    w.run("CLAIM_HM", *_merge_case(pw, 2, 3, P.with_amount_seq(19_000, 0),
                                   L.with_amount_seq(11_000, 0), 13_000, pre)[:2])
    check(True, "CLAIM^hm newer target after an older one moves only the difference")

    # negatives, one per rule
    expect_fail(lambda: w.run("CLAIM_HM", wit[:-3] + [lt.sha256(b"x")] + wit[-2:], ctx),
                "CLAIM^hm wrong preimage")
    expect_fail(lambda: w.run("CLAIM_HM", wit[:-3] + [pre[:31]] + wit[-2:], ctx),
                "CLAIM^hm preimage not 32 bytes")
    expect_fail(lambda: w.run("CLAIM_HM", *_merge_case(pw, 2, 3, P, L, 13_000, pre, signer="rcpt-exit")[:2]),
                "CLAIM^hm voucher not by the source owner")
    expect_fail(lambda: w.run("CLAIM_M", *_merge_case(pw, 2, 3, P, L, 13_000, tree_id=w.m)[:2]),
                "CLAIM^m voucher over m instead of tree_id")
    plain = _merge_case(pw, 2, 3, P, L, 13_000)[0]
    expect_fail(lambda: w.run("CLAIM_HM", plain[:-2] + [pre] + plain[-2:], ctx),
                "CLAIM^hm with a plain merge voucher")
    expect_fail(lambda: w.run("CLAIM_M", wit[:-3] + wit[-2:], ctx),
                "CLAIM^m with a hash-locked merge voucher")
    stranger = pw.landing(10_000, owner=pubkey_x(sk("operator-owner")))
    expect_fail(lambda: w.run("CLAIM_M", *_merge_case(pw, 2, 3, P, stranger, 13_000)[:2]),
                "CLAIM^m into a sibling the source's exit key does not own")
    flagged = pw.landing(10_000, evictor=pw.rk)
    expect_fail(lambda: w.run("CLAIM_M", *_merge_case(pw, 2, 3, P, flagged, 13_000)[:2]),
                "CLAIM^m into a reclaimable target")
    final_t = pw.landing(10_000, seq=ls.SEQ_FINAL)
    expect_fail(lambda: w.run("CLAIM_M", *_merge_case(pw, 2, 3, P, final_t, 13_000)[:2]),
                "CLAIM^m into a SEQ_FINAL target")
    final_s = pw.pending(20_000, 700_000, seq=ls.SEQ_FINAL)
    expect_fail(lambda: w.run("CLAIM_M", *_merge_case(pw, 2, 3, final_s, L, 13_000)[:2]),
                "CLAIM^m from a SEQ_FINAL source")
    expect_fail(lambda: w.run("CLAIM_M", *_merge_case(pw, 2, 3, P, L, 10_000)[:2]),
                "CLAIM^m with X not above the target's amount")
    expect_fail(lambda: w.run("CLAIM_M", *_merge_case(pw, 2, 3, P, L, 30_001)[:2]),
                "CLAIM^m drawing more than the source holds")
    expect_fail(lambda: w.run("CLAIM_M", *_merge_case(pw, 2, 3, P, L, 29_800)[:2]),
                "CLAIM^m leaving a sub-dust residual")
    expect_fail(lambda: w.run("CLAIM_M", *_merge_case(pw, 2, 3, P, L, 13_000, flag=b"")[:2]),
                "CLAIM^m with the source flag pointing at the target")
    wit_x, ctx_x, _ = _merge_case(pw, 2, 3, P, L, 13_000)
    expect_fail(lambda: w.run("CLAIM_M", wit_x[:-4] + [lt.le64(13_000)[:7]] + wit_x[-3:], ctx_x),
                "CLAIM^m with a 7-byte X")
    expect_fail(lambda: w.run("CLAIM_M", *_merge_case(pw, 2, 3, P, L, 13_000, msg_x=14_000)[:2]),
                "CLAIM^m with X other than the signed target")
    wit_o, _, t_o = _merge_case(pw, 2, 3, P, L, 13_000)
    r_o = t_o.root()
    expect_fail(lambda: w.run("CLAIM_M", wit_o, w.ctx([(r_o[1] - 1, w.spk(r_o))], extra_in=(600, P2WPKH))),
                "CLAIM^m with output 0 short")

    # the exact-fit funding hole: a one-satoshi top-up leaves a sub-dust
    # residual and blocks the voucher; DUST_MIN of headroom survives any top-up
    tight = pw.pending(3_000, 700_000)
    w.run("CLAIM_HM", *_merge_case(pw, 2, 3, tight, L, 13_000, pre)[:2])
    check(True, "CLAIM^hm draining an exactly funded pending leaf")
    expect_fail(lambda: w.run("CLAIM_HM", *_merge_case(pw, 2, 3, tight.with_amount_seq(3_001, 0), L, 13_000, pre)[:2]),
                "CLAIM^hm blocked by a one-satoshi top-up of an exactly funded pending leaf")
    roomy = pw.pending(3_000 + lt.DUST_MIN, 700_000)
    for extra in (0, 1, 50_000):
        w.run("CLAIM_HM", *_merge_case(pw, 2, 3, roomy.with_amount_seq(roomy.amount + extra, 0), L, 13_000, pre)[:2])
    check(True, "CLAIM^hm with DUST_MIN of headroom redeems after any top-up")
    if verbose:
        print(f"CLAIM^m D={depth}: script {m_size} B; CLAIM^hm script {hm_size} B, witness {hm_wit} B, varops {it.cost}")
    return hm_size, hm_wit


def test_reclaim(depth, verbose=True):
    """RECLAIM_1 (R1): remove a reclaimable leaf after its deadline, no payout."""
    pw = PendingWorld(depth)
    w = pw.w
    P = pw.pending(20_000, 700_000)
    w.tree.leaves = {2: P, 3: pw.landing(10_000), 0: mk_leaf("alice", 50_000)}
    root = w.tree.root()
    path = w.tree.path(2)
    t1 = w.clone(); del t1.leaves[2]
    r1 = t1.root()

    def spend(leaf=P, locktime=700_000, signer=RECLAIM_SK, out0=None, tree=None):
        tr = tree or w.tree
        rt = tr.root()
        t = lt.Tree(depth); t.leaves = dict(tr.leaves); slot = next(k for k, v in t.leaves.items() if v is leaf)
        p = tr.path(slot)
        del t.leaves[slot]
        rn = t.root()
        ctx = TxContext([(rt[1], lt.tree_spk(rt[0], w.m)), (600, P2WPKH)],
                        [(out0 if out0 is not None else rn[1], w.spk(rn)), (20_000, P2WPKH)], locktime=locktime)
        sig = schnorr_sign(ctx.sighash(), signer)
        return w.run("RECLAIM_1", w.path_witness(p) + [leaf.serialize(), sig, rt[0], w.m], ctx)

    it = spend()
    check(True, "RECLAIM_1 after the deadline, value free for the transaction")
    expect_fail(lambda: spend(locktime=699_999), "RECLAIM_1 before the deadline")
    expect_fail(lambda: spend(signer=sk("operator")), "RECLAIM_1 signed by OPERATOR_KEY, not RECLAIM_KEY")
    expect_fail(lambda: spend(out0=r1[1] - 1), "RECLAIM_1 with output 0 short")
    plain = mk_leaf("bob", 20_000, w.op_pk, 600_000)
    w.tree.leaves[6] = plain
    expect_fail(lambda: spend(leaf=plain, locktime=700_000), "RECLAIM_1 of a leaf whose evictor is not RECLAIM_KEY")
    del w.tree.leaves[6]
    L = w.tree.leaves[3]
    expect_fail(lambda: spend(leaf=L, locktime=900_000), "RECLAIM_1 of the landing leaf")
    if verbose:
        print(f"RECLAIM_1 D={depth}: script {len(w.compiled['RECLAIM_1'])} B, varops {it.cost}")
    return len(w.compiled["RECLAIM_1"])


def _pending_rewrite(pw, name, base, height, old, new, locktime=0, sign=(), tamper=None):
    """Run a REWRITE_R_h / REWRITE_XR_h over positions base..base+2^h-1.
    `sign` lists offsets that carry an owner signature (and, under ^x, an
    exit-key signature); returns the interpreter."""
    w = pw.w
    n = 1 << height
    leaves = {base + i: lf for i, lf in old.items() if lf}
    leaves[0] = mk_leaf("alice", 50_000)
    w.tree.leaves = leaves
    root = w.tree.root()
    path = w.tree.path(base, height=height)
    t1 = w.clone()
    for i in range(n):
        if new[i]:
            t1.leaves[base + i] = new[i]
        else:
            t1.leaves.pop(base + i, None)
    r1 = t1.root()
    freed = root[1] - r1[1]
    outputs = [(r1[1], w.spk(r1)), (max(freed, 0) + 1_000, P2WPKH)]
    ctx = TxContext([(root[1], w.spk(root)), (5_000 + max(-freed, 0), P2WPKH)], outputs, locktime=locktime)
    sig_op = schnorr_sign(ctx.sighash(), w.op_sk)
    blocks = []
    for i in reversed(range(n)):
        o, nw = old[i], new[i]
        if i in sign:
            if "X" in name:
                blocks.append(schnorr_sign(ctx.sighash(), sk("rcpt-exit")))
            blocks.append(schnorr_sign(ctx.sighash(), sk("operator-owner")))
        if o is not None and nw is not None and o.serialize() == nw.serialize():
            blocks.append(ls.REWRITE_SAME)
        else:
            blocks.append(nw.serialize() if nw else b"")
        blocks.append(o.serialize() if o else b"")
    wit = w.path_witness(path, height) + blocks + [sig_op, root[0], w.m]
    if tamper:
        wit = tamper(wit)
    return w.run(name, wit, ctx)


def test_pending_rewrite(depth, verbose=True):
    """The R1/R3 rewrite: a non-interactive window settlement (R3), a reclaim
    and roll of the pending leaf after its deadline (R1), and the negatives
    that keep both away from every other leaf."""
    pw = PendingWorld(depth)
    T = 700_000
    P, L = pw.pending(20_000, T), pw.landing(10_000)
    for name in ("REWRITE_R_1", "REWRITE_XR_1"):
        # R3: settle 7,000 from P into L with the operator's signature alone
        _pending_rewrite(pw, name, 2, 1, {0: P, 1: L},
                         {0: P.with_amount_seq(13_000, 0), 1: L.with_amount_seq(17_000, 0)})
        check(True, f"{name} R3 transfer P -> L, operator only, before the deadline")
        expect_fail(lambda: _pending_rewrite(pw, name, 2, 1, {0: P, 1: L},
                                             {0: P.with_amount_seq(13_000, 0), 1: L.with_amount_seq(16_999, 0)}),
                    f"{name} R3 with the landing leaf raised by less than the transfer")
        expect_fail(lambda: _pending_rewrite(pw, name, 2, 1, {0: P, 1: L},
                                             {0: P.with_amount_seq(13_000, 0), 1: L}),
                    f"{name} R3 with the landing leaf unchanged")
        other = pw.landing(10_000, owner=pubkey_x(sk("operator-owner")))
        expect_fail(lambda: _pending_rewrite(pw, name, 2, 1, {0: P, 1: other},
                                             {0: P.with_amount_seq(13_000, 0), 1: other.with_amount_seq(17_000, 0)}),
                    f"{name} R3 into a sibling the pending leaf's exit key does not own")
        flagged = pw.landing(10_000, evictor=pw.rk)
        expect_fail(lambda: _pending_rewrite(pw, name, 2, 1, {0: P, 1: flagged},
                                             {0: P.with_amount_seq(13_000, 0), 1: flagged.with_amount_seq(17_000, 0)}),
                    f"{name} R3 into a reclaimable sibling")
        expect_fail(lambda: _pending_rewrite(pw, name, 4, 1, {0: L, 1: P},
                                             {0: L.with_amount_seq(17_000, 0), 1: P.with_amount_seq(13_000, 0)}),
                    f"{name} R3 with the pending leaf on the right")
        # R1: reclaim after the deadline, emptied with no payout, or rolled
        _pending_rewrite(pw, name, 2, 1, {0: P, 1: L}, {0: None, 1: L}, locktime=T)
        check(True, f"{name} R1 reclaim after the deadline, no payout")
        P2 = pw.pending(25_000, T + 1_008, label="P2")
        _pending_rewrite(pw, name, 2, 1, {0: P, 1: L}, {0: P2, 1: L}, locktime=T)
        check(True, f"{name} R1 roll: the expired pending leaf replaced by the next window's")
        expect_fail(lambda: _pending_rewrite(pw, name, 2, 1, {0: P, 1: L}, {0: None, 1: L}, locktime=T - 1),
                    f"{name} R1 reclaim before the deadline")
        expect_fail(lambda: _pending_rewrite(pw, name, 2, 1, {0: P, 1: L}, {0: P2, 1: L}, locktime=T - 1),
                    f"{name} R1 roll before the deadline")
        # an amount-only top-up of the pending leaf is still rule 3's
        _pending_rewrite(pw, name, 2, 1, {0: P, 1: L}, {0: P.with_amount_seq(25_000, 0), 1: L})
        check(True, f"{name} top-up of the pending leaf, operator only")
        # nothing reaches a leaf that is not reclaimable
        A = mk_leaf("c0", 20_000, pw.w.op_pk, 600_000)
        B = mk_leaf("c1", 10_000, pw.w.op_pk, 600_000)
        expect_fail(lambda: _pending_rewrite(pw, name, 2, 1, {0: A, 1: B}, {0: None, 1: B}, locktime=T),
                    f"{name} emptying an ordinary leaf with no signature")
        expect_fail(lambda: _pending_rewrite(pw, name, 2, 1, {0: L, 1: P}, {0: None, 1: P}, locktime=900_000),
                    f"{name} reclaiming the landing leaf")
        expect_fail(lambda: _pending_rewrite(pw, name, 2, 1, {0: A, 1: B},
                                             {0: A.with_amount_seq(13_000, 0), 1: B.with_amount_seq(17_000, 0)}),
                    f"{name} R3 from an ordinary leaf")
    # two pairs in one rewrite: one settles, the other reclaims and rolls
    P_b, L_b = pw.pending(9_000, T, label="Pb"), pw.landing(4_000, label="Lb")
    it = _pending_rewrite(pw, "REWRITE_XR_2", 4, 2, {0: P, 1: L, 2: P_b, 3: L_b},
                          {0: P.with_amount_seq(13_000, 0), 1: L.with_amount_seq(17_000, 0),
                           2: pw.pending(9_000, T + 1_008, label="Pb2"), 3: L_b}, locktime=T)
    check(True, "REWRITE_XR_2: a settlement and a roll in one rewrite, operator only")
    s1 = len(pw.w.compiled["REWRITE_XR_1"])
    s2 = len(pw.w.compiled["REWRITE_XR_2"])
    if verbose:
        plain = len(assemble(ls.rewrite_script(depth, 2, pw.w.op_pk, exit_consent=True)))
        print(f"REWRITE_XR_h D={depth}: h=1 {s1} B, h=2 {s2} B (REWRITE_X_2 {plain} B), varops {it.cost}")
    return s1, s2


if __name__ == "__main__" and "--subtree" in sys.argv:
    for d, h in ((16, 2), (16, 4), (16, 6)):
        test_evict_subtree(d, h)
        test_rewrite(d, h)
    test_detach(16, 8)
    print(f"\n{CHECKS} checks, {FAILS} failures")


if __name__ == "__main__" and "--rewrite" in sys.argv:
    # Measured sizes for design/batching.md: REWRITE_h at D = 16 for the
    # three scenarios, with the per-position script share.
    for h in (2, 4, 6):
        r = rewrite_sizes(16, h)
        n = 1 << h
        print(f"\nREWRITE_{h} D=16 ({n} positions): fixed script {r['fixed_script']} B, "
              f"per position {r['per_position_script']:.1f} B")
        for sc in ("mixed", "update", "exit"):
            x = r[sc]
            wu = x["script"] + x["witness"] + 129
            print(f"  {sc:7} script {x['script']:6} B  witness {x['witness']:5} B  changed {x['changed']:3} "
                  f"exits {x['exits']:3} sigs {x['sigs']:3}  witness WU {wu:6}  varops {x['varops']}")
    sys.exit(1 if FAILS else 0)


if __name__ == "__main__" and "--subtree" not in sys.argv and "--rewrite" not in sys.argv:
    for d, h in ((16, 2), (16, 4)):
        test_evict_subtree(d, h)
        test_rewrite(d, h)
    test_rewrite(16, 4, exit_consent=True)
    test_detach(16, 8)
    test_detach_options(8, 2)
    test_detach_options(16, 8)
    for d in (4, 16):
        test_minimal(d)
        test_channel_rules(d)
        test_swap(d)
    for prof, d in (("D", 4), ("D", 16), ("S", 8), ("S", 32)):
        test_sibling_sum_binding(d, prof)
    for prof, d in (("D", 4), ("D", 16), ("S", 8)):
        test_update_x(d, prof)
        test_exit_tower(d, prof)
        test_claim_h(d, prof)
        test_claim_x(d, prof)
        test_claim_x(d, prof, hashlock=True)
        test_split(d, prof)
    for d in (4, 16):
        test_carve_rules(d)
        test_voucher_topup(d)
        test_merge(d)
        test_reclaim(d)
        test_pending_rewrite(d)
    test_audit_negatives(8)
    for prof, depths in (("D", (4, 16)), ("S", (8, 32))):
        for d in depths:
            test_all(d, prof)
    ls.COMPRESSION["S"] = "bitmap"
    for d in (8, 32):
        test_all(d, "S")
    ls.COMPRESSION["S"] = "empty"
    print(f"\n{CHECKS} checks, {FAILS} failures")
    sys.exit(1 if FAILS else 0)
