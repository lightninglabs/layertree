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





if __name__ == "__main__" and "--subtree" in sys.argv:
    for d, h in ((16, 2), (16, 4), (16, 6)):
        test_evict_subtree(d, h)
    print(f"\n{CHECKS} checks, {FAILS} failures")


if __name__ == "__main__" and "--subtree" not in sys.argv:
    for d, h in ((16, 2), (16, 4)):
        test_evict_subtree(d, h)
    for d in (4, 16):
        test_minimal(d)
    for prof, depths in (("D", (4, 16)), ("S", (8, 32))):
        for d in depths:
            test_all(d, prof)
    ls.COMPRESSION["S"] = "bitmap"
    for d in (8, 32):
        test_all(d, "S")
    ls.COMPRESSION["S"] = "empty"
    print(f"\n{CHECKS} checks, {FAILS} failures")
    sys.exit(1 if FAILS else 0)
