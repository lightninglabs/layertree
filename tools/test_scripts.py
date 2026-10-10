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

# Design constraint (spec section 4.4): scripts compose ONLY existing candidate
# opcodes. Any opcode outside this inventory is a test failure.
BIP342_OPS = {"OP_0", "OP_1", "OP_2DROP", "OP_2DUP", "OP_2SWAP", "OP_ADD", "OP_1ADD",
              "OP_CHECKLOCKTIMEVERIFY", "OP_CHECKSIGVERIFY", "OP_CHECKSIG", "OP_DROP",
              "OP_DUP", "OP_ELSE", "OP_ENDIF", "OP_EQUAL", "OP_EQUALVERIFY",
              "OP_FROMALTSTACK", "OP_IF", "OP_LESSTHANOREQUAL", "OP_NIP", "OP_NOT",
              "OP_NOTIF", "OP_NUMEQUAL", "OP_NUMEQUALVERIFY", "OP_OVER", "OP_PICK",
              "OP_ROLL", "OP_ROT", "OP_SHA256", "OP_SIZE", "OP_SUB", "OP_SWAP",
              "OP_TOALTSTACK", "OP_TUCK", "OP_VERIFY", "OP_0NOTEQUAL"}
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
    def __init__(self, depth, profile, join_heights=(0, 2), exit_ks=(1, 2)):
        self.depth, self.profile = depth, profile
        self.op_sk = sk("operator")
        self.op_pk = pubkey_x(self.op_sk)
        self.scripts = ls.all_scripts(depth, self.op_pk, join_heights, exit_ks, profile)
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
    frank = mk_leaf("frank", 40_000, w.op_pk, 900_000)
    s_frank = w.slot(frank, 3)
    spath = w.tree.path(s_oper)
    t5 = w.clone(); lt.apply_claim(t5, s_oper, s_frank, frank)
    cpath = t5.path(s_frank)
    r5 = t5.root()
    check(r5[1] == root[1], "claim conserves sum")
    ctx = w.ctx([(r5[1], w.spk(r5))], extra_in=(600, P2WPKH))
    vmsg = lt.voucher_msg(w.m, src, frank)
    vsig = schnorr_sign(vmsg, sk("operator-owner"))
    wit = w.path_witness(cpath) + w.path_witness(spath) + w.bm(spath) + [src.serialize()] + w.bm(cpath) + [frank.serialize(), vsig, root[0], w.m]
    record("CLAIM", w.run("CLAIM", wit, ctx), wit)
    # replay after the source leaf changed
    frank2 = mk_leaf("frank2", 40_000, w.op_pk, 900_000)
    s_frank2 = w.slot(frank2, 4)
    t6 = lt.Tree(D); t6.leaves = dict(t5.leaves)
    spath2 = t5.path(s_oper)
    lt.apply_claim(t6, s_oper, s_frank2, frank2)
    cpath2 = t6.path(s_frank2)
    ctx6 = TxContext([(r5[1], w.spk(r5)), (600, P2WPKH)], [(t6.root()[1], w.spk(t6.root()))])
    expect_fail(lambda: w.run("CLAIM", w.path_witness(cpath2) + w.path_witness(spath2) + w.bm(spath2) + [src.serialize()] + w.bm(cpath2) + [frank2.serialize(), vsig, r5[0], w.m], ctx6), "voucher replay / wrong leaf")
    greedy = mk_leaf("greedy", src.amount + 1, w.op_pk, 900_000)
    gsig = schnorr_sign(lt.voucher_msg(w.m, src, greedy), sk("operator-owner"))
    expect_fail(lambda: w.run("CLAIM", w.path_witness(cpath) + w.path_witness(spath) + w.bm(spath) + [src.serialize()] + w.bm(cpath) + [greedy.serialize(), gsig, root[0], w.m], ctx), "over-claim underflow")
    bsig = schnorr_sign(vmsg, sk("bob-owner"))
    expect_fail(lambda: w.run("CLAIM", w.path_witness(cpath) + w.path_witness(spath) + w.bm(spath) + [src.serialize()] + w.bm(cpath) + [frank.serialize(), bsig, root[0], w.m], ctx), "voucher wrong signer")
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
    gina = mk_leaf("gina", src2.amount, w.op_pk, 900_000)
    s_gina = w.slot(gina, 6)
    spath2 = w.tree.path(s_erin)
    t8 = w.clone(); del t8.leaves[s_erin]
    cpath_g = t8.path(s_gina); t8.leaves[s_gina] = gina
    r8 = t8.root()
    ctx = w.ctx([(r8[1], w.spk(r8))], extra_in=(600, P2WPKH))
    gsig = schnorr_sign(lt.voucher_msg(w.m, src2, gina), sk("erin-owner"))
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
        claim = mk_leaf("claimant", 40_000, w.op_pk, 900_000)
        s_claim = 3
        spath = w.tree.path(s_src)
        t5 = w.clone()
        t5.leaves[s_src] = src.with_amount_seq(src.amount - claim.amount, (seq + 1) & 0xffffffff)
        t5.leaves[s_claim] = claim
        cpath = t5.path(s_claim)
        r5 = t5.root()
        ctx = w.ctx([(r5[1], w.spk(r5))], extra_in=(600, P2WPKH))
        vsig = schnorr_sign(lt.voucher_msg(w.m, src, claim), sk("chan-src-owner"))
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
    toks = ls.claim_script(depth, profile, hashlock=True)
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
    hodl = mk_leaf("hodl", 40_000, w.op_pk, 900_000)
    s_hodl = w.slot(hodl, 3)
    spath = w.tree.path(s_oper)
    t1 = w.clone(); lt.apply_claim(t1, s_oper, s_hodl, hodl)
    cpath = t1.path(s_hodl); r1 = t1.root()
    check(r1[1] == root[1], "CLAIM^h conserves sum")
    ctx = w.ctx([(r1[1], w.spk(r1))], extra_in=(600, P2WPKH))
    hmsg = lt.voucher_h_msg(w.m, src, hodl, payment_hash)
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
    plain_sig = schnorr_sign(lt.voucher_msg(w.m, src, hodl), sk("operator-owner"))
    expect_fail(lambda: w.run("CLAIM_H", head + [plain_sig, preimage, root[0], w.m], ctx),
                "CLAIM^h with a plain voucher signature")
    expect_fail(lambda: w.run("CLAIM", head + [hsig, root[0], w.m], ctx),
                "plain CLAIM with a hash-locked voucher signature")
    # the payment hash is bound to this carve: another claim leaf needs its own voucher
    other = mk_leaf("other", 40_000, w.op_pk, 900_000)
    expect_fail(lambda: w.run("CLAIM_H", w.path_witness(cpath) + w.path_witness(spath) + w.bm(spath) +
                              [src.serialize()] + w.bm(cpath) + [other.serialize(), hsig, preimage, root[0], w.m], ctx),
                "CLAIM^h voucher reused for a different claim leaf")
    greedy = mk_leaf("greedy", src.amount + 1, w.op_pk, 900_000)
    gsig = schnorr_sign(lt.voucher_h_msg(w.m, src, greedy, payment_hash), sk("operator-owner"))
    expect_fail(lambda: w.run("CLAIM_H", w.path_witness(cpath) + w.path_witness(spath) + w.bm(spath) +
                              [src.serialize()] + w.bm(cpath) + [greedy.serialize(), gsig, preimage, root[0], w.m], ctx),
                "CLAIM^h over-claim underflow")
    bsig = schnorr_sign(hmsg, sk("bob-owner"))
    expect_fail(lambda: w.run("CLAIM_H", head + [bsig, preimage, root[0], w.m], ctx),
                "CLAIM^h voucher wrong signer")
    if verbose:
        plain = len(assemble(ls.claim_script(depth, profile)))
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
    toks = ls.claim_script(depth, profile, hashlock=hashlock, exit_consent=True)
    bad = {t for t in toks if isinstance(t, str)} - ALLOWED_OPCODES
    check(not bad, f"{name} uses non-candidate opcodes: {sorted(bad)}")
    script = assemble(toks)
    plain = assemble(ls.claim_script(depth, profile, hashlock=hashlock))
    check(len(script) - len(plain) == 8, f"{name} is eight bytes over its plain form")
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
    claim = mk_leaf("recipient", 40_000, w.op_pk, 900_000)
    s_claim = w.slot(claim, 3)
    spath = w.tree.path(s_credit)
    t1 = w.clone(); lt.apply_claim(t1, s_credit, s_claim, claim)
    cpath = t1.path(s_claim); r1 = t1.root()
    check(r1[1] == root[1], f"{name} conserves sum")
    ctx = w.ctx([(r1[1], w.spk(r1))], extra_in=(600, P2WPKH))
    preimage = lt.sha256(b"credit-preimage")
    if hashlock:
        vsig = schnorr_sign(lt.voucher_h_msg(w.m, credit, claim, lt.sha256(preimage)), w.op_sk)
    else:
        vsig = schnorr_sign(lt.voucher_msg(w.m, credit, claim), w.op_sk)
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
    drain = mk_leaf("operator-drain", credit.amount, w.op_pk, 900_000)
    s_drain = w.slot(drain, 6)
    t2 = w.clone(); lt.apply_claim(t2, s_credit, s_drain, drain)
    cpath2 = t2.path(s_drain); r2 = t2.root()
    ctx2 = w.ctx([(r2[1], w.spk(r2))], extra_in=(600, P2WPKH))
    if hashlock:
        dsig = schnorr_sign(lt.voucher_h_msg(w.m, credit, drain, lt.sha256(preimage)), w.op_sk)
    else:
        dsig = schnorr_sign(lt.voucher_msg(w.m, credit, drain), w.op_sk)
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
    bob = mk_leaf("bob", 200_000, w.op_pk, 900_000)
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
    vsig = schnorr_sign(lt.voucher_msg(w.m, alice, bob), sk("alice-owner"))
    expect_fail(lambda: w.run("SPLIT", head + [vsig, root[0], w.m], ctx),
                "SPLIT with a voucher signature instead of a transaction signature")
    # over-split: the new leaf exceeds the source
    greedy = mk_leaf("greedy", alice.amount + 1, w.op_pk, 900_000)
    t2 = w.clone()
    expect_fail(lambda: w.run("SPLIT", w.path_witness(cpath) + w.path_witness(spath) + w.bm(spath) +
                              [alice.serialize()] + w.bm(cpath) + [greedy.serialize(), asig, root[0], w.m], ctx),
                "SPLIT over-split underflow")
    # destination already occupied: prove the claim step against a non-empty slot
    occupied = w.tree.path(s_oper)
    expect_fail(lambda: w.run("SPLIT", w.path_witness(occupied) + w.path_witness(spath) + w.bm(spath) +
                              [alice.serialize()] + w.bm(occupied) + [bob.serialize(), asig, root[0], w.m], ctx),
                "SPLIT into an occupied position")
    # stale root
    expect_fail(lambda: w.run("SPLIT", head + [asig, r1[0], w.m], ctx), "SPLIT against a stale root")
    # the owner's signature covers output 0, which is the only place the new
    # leaf reaches it: a relayer cannot swap in its own leaf (7.5.2, 10.7)
    mallory = mk_leaf("mallory", bob.amount, w.op_pk, 900_000)
    s_mal = w.slot(mallory, 3)
    tm = w.clone(); lt.apply_claim(tm, s_alice, s_mal, mallory); rm = tm.root()
    ctx_m = w.ctx([(rm[1], w.spk(rm))], extra_in=(600, P2WPKH))
    head_m = (w.path_witness(tm.path(s_mal)) + w.path_witness(spath) + w.bm(spath) + [alice.serialize()] +
              w.bm(tm.path(s_mal)) + [mallory.serialize()])
    w.run("SPLIT", head_m + [schnorr_sign(ctx_m.sighash(), sk("alice-owner")), root[0], w.m], ctx_m)
    expect_fail(lambda: w.run("SPLIT", head_m + [asig, root[0], w.m], ctx_m),
                "SPLIT recipient swapped under the owner's signature")
    if verbose:
        claim = len(assemble(ls.claim_script(depth, profile)))
        print(f"SPLIT {profile} D={depth}: script {len(script)} B (CLAIM {claim} B, saves {claim - len(script)}), "
              f"witness {sum(len(x) for x in head) + 64 + 64} B, varops {it.cost}")
    return it, len(script), sum(len(x) for x in head + [asig, root[0], w.m])


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
    toks = ls.claim_script(depth, "D", hashlock=True)
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
    bought = mk_leaf("bought", 40_000, w.op_pk, 900_000)
    s_bought = w.slot(bought, 3)
    spath = w.tree.path(s_oper)
    t1 = w.clone(); lt.apply_claim(t1, s_oper, s_bought, bought)
    cpath = t1.path(s_bought); r1 = t1.root()
    ctx = w.ctx([(r1[1], w.spk(r1))], extra_in=(600, P2WPKH))
    hsig = schnorr_sign(lt.voucher_h_msg(w.m, src, bought, payment_hash), sk("operator-owner"))
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


if __name__ == "__main__" and "--subtree" in sys.argv:
    for d, h in ((16, 2), (16, 4), (16, 6)):
        test_evict_subtree(d, h)
    print(f"\n{CHECKS} checks, {FAILS} failures")


if __name__ == "__main__" and "--subtree" not in sys.argv:
    for d, h in ((16, 2), (16, 4)):
        test_evict_subtree(d, h)
    for d in (4, 16):
        test_minimal(d)
        test_channel_rules(d)
        test_swap(d)
    for prof, d in (("D", 4), ("D", 16), ("S", 8), ("S", 32)):
        test_sibling_sum_binding(d, prof)
    for prof, d in (("D", 4), ("D", 16), ("S", 8)):
        test_update_x(d, prof)
        test_claim_h(d, prof)
        test_claim_x(d, prof)
        test_claim_x(d, prof, hashlock=True)
        test_split(d, prof)
    for prof, depths in (("D", (4, 16)), ("S", (8, 32))):
        for d in depths:
            test_all(d, prof)
    ls.COMPRESSION["S"] = "bitmap"
    for d in (8, 32):
        test_all(d, "S")
    ls.COMPRESSION["S"] = "empty"
    print(f"\n{CHECKS} checks, {FAILS} failures")
    sys.exit(1 if FAILS else 0)
