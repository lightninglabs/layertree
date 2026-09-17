#!/usr/bin/env python3
"""End-to-end test of the MIN tier EXIT_1 (0xC0 + OP_CAT + OP_TWEAKADD only)."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import layertree_ref as lt  # noqa: E402
import layertree_mid as M  # noqa: E402
import layertree_min as N  # noqa: E402
import test_scripts as TS  # noqa: E402
from script_sim import Interp, ScriptError, TxContext, assemble, pubkey_x, schnorr_sign  # noqa: E402
from test_scripts import BIP342_OPS, sk, check, expect_fail, P2WPKH  # noqa: E402
from test_mid import mk_leaf  # noqa: E402

MIN_OPCODES = BIP342_OPS | N.EXTRA_OPCODES | {"OP_BOOLOR", "OP_GREATERTHANOREQUAL"}


def test_min(depth, verbose=True):
    toks = N.exit_script(depth)
    bad = {t for t in toks if isinstance(t, str)} - MIN_OPCODES
    check(not bad, f"MIN EXIT_1 uses opcodes outside the MIN set: {sorted(bad)}")
    script = assemble(toks, "c0")
    leaf_hash = lt.tapleaf_hash(script, 0xc0)
    # taptree: this script plus a dummy sibling so m is non-trivial
    m = lt.taptree_root([leaf_hash, lt.sha256(b"other leaf")])
    op_sk = sk("operator"); op_pk = pubkey_x(op_sk)
    alice = mk_leaf("alice", 50_000)
    bob = mk_leaf("bob", 125_000, op_pk, 800_000)
    oper = mk_leaf("operator", 1_000_000)
    tree = lt.Tree(depth); tree.leaves = {0: alice, 5: bob, (1 << depth) - 1: oper}
    root = tree.root()
    t1 = lt.Tree(depth); t1.leaves = {k: v for k, v in tree.leaves.items() if k != 5}
    r1 = t1.root()
    path = tree.path(5)

    def make_ctx(payout, locktime=0, extra=((400, P2WPKH),)):
        outs = [(r1[1], lt.tree_spk(r1[0], m)), (payout, lt.p2tr_spk(bob.exit_key))] + list(extra)
        return TxContext([(root[1], lt.tree_spk(root[0], m)), (5_000, P2WPKH)], outs,
                         locktime=locktime, tapleaf_hash=leaf_hash)

    def mutate(ctx, i):
        ctx.sequences[1] = 0xfffffffd - i

    def witness(ctx, leaf, sig, is_evict, e31):
        return (N.raw_pieces(ctx, e31) + list(M.pad(r1[1])) + list(M.pad(root[1])) +
                M.w_levels(path, leaf.node(), lt.EMPTY_NODE, False) + M.w_leaf_exit(leaf) +
                [sig, is_evict, root[0], m])

    def run(ctx, wit):
        it = Interp(ctx, mode="c0")
        it.run(script, wit)
        return it

    # owner exit
    ctx = make_ctx(bob.amount)
    e31, tries = N.grind(ctx, mutate)
    sig = schnorr_sign(ctx.sighash(), sk("bob-owner"))
    wit = witness(ctx, bob, sig, b"", e31)
    it = run(ctx, wit)
    # eviction
    ctx_e = make_ctx(bob.amount, locktime=800_000, extra=())
    e31e, tries_e = N.grind(ctx_e, mutate)
    esig = schnorr_sign(ctx_e.sighash(), op_sk)
    run(ctx_e, witness(ctx_e, bob, esig, b"\x01", e31e))
    # negatives
    ctx_b = make_ctx(bob.amount - 1)                      # tx pays less than the leaf says
    e31b, _ = N.grind(ctx_b, mutate); sigb = schnorr_sign(ctx_b.sighash(), sk("bob-owner"))
    expect_fail(lambda: run(ctx_b, witness(ctx_b, bob, sigb, b"", e31b)), "min: payout mismatch")
    ctx_t = make_ctx(bob.amount)                          # tree output underfunded
    ctx_t.outputs[0] = (r1[1] - 1, ctx_t.outputs[0][1])
    e31t, _ = N.grind(ctx_t, mutate); sigt = schnorr_sign(ctx_t.sighash(), sk("bob-owner"))
    expect_fail(lambda: run(ctx_t, witness(ctx_t, bob, sigt, b"", e31t)), "min: tree output underfunded")
    fake = bob.with_amount_seq(bob.amount + 1, 0)
    expect_fail(lambda: run(ctx, witness(ctx, fake, sig, b"", e31)), "min: forged leaf")
    wbad = list(wit); wbad[-1] = lt.sha256(b"evil")
    expect_fail(lambda: run(ctx, wbad), "min: wrong m")
    wbad = list(wit); wbad[0] = bytes(31)                 # wrong e31
    expect_fail(lambda: run(ctx, wbad), "min: wrong e31")
    ctx_early = make_ctx(bob.amount, locktime=799_999, extra=())
    e31x, _ = N.grind(ctx_early, mutate); esx = schnorr_sign(ctx_early.sighash(), op_sk)
    expect_fail(lambda: run(ctx_early, witness(ctx_early, bob, esx, b"\x01", e31x)), "min: early evict")
    if verbose:
        print(f"MIN EXIT_1 D={depth}: script {len(script)} B, witness {sum(len(x) for x in wit)} B, "
              f"grind attempts {tries}/{tries_e}, maxdepth {it.max_depth}")
    return script, wit, it


if __name__ == "__main__":
    test_min(16)
    print(f"\n{TS.CHECKS} checks, {TS.FAILS} failures")
    sys.exit(1 if TS.FAILS else 0)
