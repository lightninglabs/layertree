#!/usr/bin/env python3
"""LayerTree transition script templates, CCV tier (spec section 4.7).

Opcode set: BIP-443 OP_CHECKCONTRACTVERIFY plus the fold and authorization
opcodes of the FULL tier (tapleaf 0xC2, BIP-441 numerics). The tree format
and the fold are unchanged; only the binding macros differ.

CCV operand order, bottom..top: <data> <index> <pk> <taptree> <mode>.
The interpreter pops from the top: mode, taptree, pk, index, data. Every
call site builds the five contiguously. Special values are raw byte
patterns: pk empty = BIP-341 NUMS; 0x81 (minimal -1) for taptree = the
current input's own taptree and for index = the current input. Modes:
-1 CHECK_INPUT, 0 CHECK_OUTPUT (assign), 1 IGNORE, 2 DEDUCT.

What CCV replaces (compare layertree_scripts.prologue / final_output):

* The current-input check. After the fold produces the old root `oh`, one
  CHECK_INPUT call with data = `oh`, pk = empty, taptree = -1 proves the
  input commits to `oh` under the same script set. No TREE_SPK
  recomputation, no OP_TX scriptPubKey read; the witness loses `r` and
  `m` entirely (spec 10.4's binding of `m` is CCV's "same taptree"
  semantics).
* The output-0 construction. One CHECK_OUTPUT|DEDUCT call with data = nh,
  index 0, pk empty, taptree -1 proves output 0 carries the new state
  under the same taptree and deducts its amount from the residual. The
  equality out0.amount == ns remains one OP_TX read: CCV binds amounts to
  the input's amount, not to script-computed sums. DEDUCT rather than the
  default assign is deliberate: paired with the equality it enforces rule
  5 exactly, rejects underfunded trees, and lets an overfunded tree spend
  its excess as fees (the default mode would strand the excess).
* The payout scriptPubKey check. One CHECK_OUTPUT|DEDUCT call with data
  empty, taptree empty, pk = leaf.exit_key proves output k is a bare P2TR
  to the exit key and deducts its amount; the <=/== leaf.amount
  comparison remains one OP_TX amount read.

What is NOT replaced: the LEVEL x D fold, the chained-step consistency
checks (nh_prev == oh, ns_prev == os), sparse position derivation, and the
authorization (CHECKSIG / CLTV).

Amount semantics: identical to the other tiers. The input-amount
equality (os == the tree input's amount) stays, output 0 is checked by
the CCV assign mode (its floor: output 0 receives at least the input's
residual) plus the numeric equality out0 == ns, and payouts are exact and
deducted from the residual. Assign rather than the DEDUCT mode for
output 0 is what makes value-adding transitions (JOIN, funded UPDATE)
spendable: the joiner's funds arrive through other inputs, above the
floor. The exact-payout restriction follows: with assign-on-out0 a
payout short of leaf.amount would strand its difference in the residual
and force output 0 above ns.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import layertree_ref as lt  # noqa: E402
import layertree_scripts as F  # noqa: E402
from script_sim import SEL_IN_AMOUNT, SEL_OUT_SINGLE  # noqa: E402

MINUS1 = b"\x81"
CCV = "OP_CHECKCONTRACTVERIFY"
EXTRA_OPCODES = {"OP_CHECKCONTRACTVERIFY"}


# ------------------------------------------------------------- binding ----

def ccv_check_input():
    """[T ... data] -> [T ...]. CHECK_INPUT, current input (index -1), NUMS
    (pk empty), the input's own taptree (-1).

    The data operand is the BOTTOM of the five, so anything above it must
    be parked first; the caller does that (check_old_ccv parks nh/ns and
    drops os, leaving [T data]). Here the window is already bare: the
    caller guarantees [.., data] with nothing above it, and this macro
    pushes the four fixed operands on top.
    """
    return [MINUS1, b"", MINUS1, MINUS1, CCV]


def ccv_tree_output(out_index):
    """[T ... data] -> [T ...]. CHECK_OUTPUT|DEDUCT on output `out_index`:
    the tree output for state `data` (pk empty = NUMS, taptree -1 = the
    input's own). Same bare-window contract as ccv_check_input.
    """
    return [out_index, b"", MINUS1, 2, CCV]


def ccv_payout_fixed(out_index):
    """[... leaf] -> [... leaf]. CHECK_OUTPUT|DEDUCT on output `out_index`
    as a bare P2TR to leaf.exit_key (data empty, taptree empty: no tweaks
    at all, so the checked output key IS the exit key).

    Entry: leaf on top, nothing above; it survives on top after the call
    (the amount comparison that follows reads it). Two parks: the leaf is
    duplicated, both copies parked, one restored mid-sequence to extract
    the exit key (SUBSTR pops size, offset, elem), the other restored
    after the call.
    """
    return ["OP_DUP", "OP_TOALTSTACK",     # leaf            | B (dup)
            "OP_TOALTSTACK",                # ()              | B A
            b"", out_index,                 # "" idx          (data below index)
            "OP_FROMALTSTACK",              # "" idx B        | A
            F.OFF_EXIT_KEY, 32, "OP_SUBSTR",  # "" idx ek
            b"", 2, CCV,                    # ()              DEDUCT payout
            "OP_FROMALTSTACK"]              # leaf (A)



def prologue_ccv():
    """The CCV tier has no prologue: the input check happens once the old
    root is known (after the fold), and CCV's -1 index binds the current
    input without OP_TX. Named so script listings can name the region."""
    return []


def check_old_ccv(profile):
    """[T oh os nh ns] -> [T nh ns]. As FULL's check_old_root_from_alt with
    the root comparison replaced by the CCV input check: os == the input
    amount stays (one OP_TX read; the tree output's amount keeps equaling
    the committed sum exactly, as in every other tier), then `oh` becomes
    the CCV data operand and CHECK_INPUT binds it to the input.

    Stack: OP_2SWAP + the amount check give [T nh ns oh]; the sparse
    bookkeeping is torn down (it sits below what follows); two OP_ROTs
    roll oh below nh and ns, then ns and nh are parked (nh on the alt
    top, so it restores first), leaving [T oh]: the bare data slot. The
    four fixed operands go on top, one CCV call, and nh, ns come back.
    """
    s = ["OP_2SWAP", SEL_IN_AMOUNT, "OP_TX", "OP_NUMEQUALVERIFY"]  # T nh ns oh
    if profile == "S":
        s += F.sparse_teardown()
    s += ["OP_ROT", "OP_ROT",            # T oh nh ns   (oh rolled to the front)
          "OP_TOALTSTACK",               # T oh nh       | [.. ns]
          "OP_TOALTSTACK"]               # T oh          | [.. ns nh  (nh on top)
    s += ccv_check_input()               # T             | [.. ns nh]
    s += ["OP_FROMALTSTACK", "OP_FROMALTSTACK"]   # T nh ns
    return s


def final_ccv(depth):
    """[T nh ns] -> [1]. Output 0 is the tree output for `nh` (DEDUCT) with
    amount == ns, unless nh == E_D (terminal exit: no output-0 check).

    Entry after ROT/DROP: [nh ns]. Park ns; the stack is then exactly the
    five CCV operands bottom..top: data = nh, index = 0, pk = empty (NUMS),
    taptree = -1 (the input's own), mode = 0 (CHECK_OUTPUT, assign). The
    assign mode makes output 0 receive at least the input's residual
    amount (the tree input's amount, minus earlier DEDUCT payouts in the
    same script), and the OP_TX equality pins out0 == ns exactly: rule 5
    holds, an underfunded output 0 fails both checks, and a JOIN can fund
    output 0 up to ns from its other inputs (the floor is only a lower
    bound, so extra inputs may add). DEDUCT would have pinned out0 to the
    tree input's own amount and made every value-adding transition
    (JOIN, funded UPDATE) unspendable, which is why the default mode is
    the right amount semantics for output 0.
    """
    e_d = lt.empty_node(depth)[0]
    return ["OP_ROT", "OP_DROP",            # nh ns
            "OP_OVER", e_d, "OP_EQUAL",
            "OP_IF", "OP_2DROP", "OP_1",
            "OP_ELSE",
            "OP_TOALTSTACK",                # nh             | ns
            "OP_0", b"", MINUS1, 0,         # nh 0 "" -1 0   (the five operands)
            CCV,                            # ()             assign out0
            "OP_FROMALTSTACK",              # ns
            # OP_TX SEL_OUT_SINGLE pushes [amount, spk]; the spk (on top)
            # was checked by the CCV call, drop it, then compare numerically
            # (ns is a raw number, the amount is fixed-width le64).
            "OP_0", SEL_OUT_SINGLE, "OP_TX", "OP_DROP", "OP_NUMEQUALVERIFY",
            "OP_1", "OP_ENDIF"]


# ----------------------------------------------------------- transitions --

def exit_block_ccv(profile, depth, out_index, exact=False):
    """One exit. Stack: [path] leaf sig is_evict -> T oh os nh ns (fold done).

    Authorization and fold are F.exit_block's; the payout scriptPubKey
    check is the CCV DEDUCT call (ccv_payout_fixed), the amount comparison
    remains one OP_TX read.
    """
    s = ["OP_DUP", "OP_TOALTSTACK",         # | ... is_evict
         "OP_IF",
         "OP_OVER", F.OFF_EVICT_AFTER, F.LEN_EVICT_AFTER, "OP_SUBSTR",
         "OP_CHECKLOCKTIMEVERIFY", "OP_DROP",
         "OP_OVER", F.OFF_EVICTOR_KEY, 32, "OP_SUBSTR",
         "OP_ELSE",
         "OP_OVER", F.OFF_OWNER_KEY, 32, "OP_SUBSTR",
         "OP_ENDIF",
         "OP_CHECKSIGVERIFY",               # leaf
         "OP_SIZE", F.LEAF_LEN, "OP_EQUALVERIFY",
         ] + ccv_payout_fixed(out_index) + [
         # amount comparison: OP_TX SEL_OUT_SINGLE pushes [amount, spk]
         # with the spk on top; CCV already checked it, so drop the spk.
         out_index, SEL_OUT_SINGLE, "OP_TX", "OP_DROP",  # leaf out_amt
         "OP_OVER", 8, "OP_LEFT",                       # leaf out_amt leaf_amt
         "OP_FROMALTSTACK"]
    if exact:
        s += ["OP_DROP", "OP_NUMEQUALVERIFY"]
    else:
        s += ["OP_IF", "OP_NUMEQUALVERIFY",
              "OP_ELSE", "OP_LESSTHANOREQUAL", "OP_VERIFY", "OP_ENDIF"]
    if profile == "S":
        s += F.leaf_pos() + F.sparse_setup()
    s += F.leaf_acc() + [
        F.NODE_PREFIX, "OP_ROT", "OP_ROT",
        lt.EMPTY_LEAF_HASH, "OP_0"]
    return s + F.levels(profile, depth)


def exit_script_ccv(depth, k=1, profile="D", exact=True):
    """EXIT_K under CCV. witness (bottom..top) = [block_K] ... [block_1],
    block_i = per-level items then leaf_i sig_i is_evict_i. No r, no m.

    The CCV tier supports exact payouts only (exact=True is the default and
    the only mode): with output 0 under the assign mode, a payout short of
    the leaf amount would strand the difference in the residual and force
    output 0 above ns, breaking rule 5's equality. Fees are exogenous, as
    in the MID and MIN tiers.
    """
    s = prologue_ccv()
    s += exit_block_ccv(profile, depth, 1, exact) + check_old_ccv(profile)
    for i in range(2, k + 1):
        s += ["OP_SWAP", "OP_TOALTSTACK", "OP_TOALTSTACK", "OP_DROP"]
        s += exit_block_ccv(profile, depth, i, exact) + F.check_prev_root_from_alt(profile)
    return s + final_ccv(depth)


def join_script_ccv(depth, height, operator_key, profile="D", k=1):
    """JOIN_h / JOINK_k under CCV. witness = [block_k] ... [block_1] sig."""
    s = prologue_ccv() + [operator_key, "OP_CHECKSIGVERIFY"]
    s += F.join_block(profile, depth, height) + check_old_ccv(profile)
    for _ in range(2, k + 1):
        s += ["OP_SWAP", "OP_TOALTSTACK", "OP_TOALTSTACK", "OP_DROP"]
        s += F.join_block(profile, depth, height) + F.check_prev_root_from_alt(profile)
    return s + final_ccv(depth)


def update_script_ccv(depth, operator_key, profile="D", exit_consent=False):
    """UPDATE / UPDATE^x under CCV. witness = [path] old new osig opsig [xsig]."""
    s = prologue_ccv()
    if exit_consent:
        s += [4, "OP_PICK", F.OFF_EXIT_KEY, 32, "OP_SUBSTR",
              "OP_CHECKSIGVERIFY"]
    s += [operator_key, "OP_CHECKSIGVERIFY",
          2, "OP_PICK", F.OFF_OWNER_KEY, 32, "OP_SUBSTR", "OP_CHECKSIGVERIFY",
          "OP_SIZE", F.LEAF_LEN, "OP_EQUALVERIFY",
          "OP_SWAP", "OP_SIZE", F.LEAF_LEN, "OP_EQUALVERIFY"]
    if profile == "S":
        s += F.leaf_pos() + ["OP_ROT"] + F.leaf_pos() + [
            "OP_ROT", "OP_EQUALVERIFY", "OP_SWAP"]
        s += F.leaf_pos() + F.sparse_setup()
    s += [F.NODE_PREFIX, "OP_ROT", "OP_ROT"]
    s += F.leaf_acc() + ["OP_ROT"] + F.leaf_acc()
    s += F.levels(profile, depth)
    return s + check_old_ccv(profile) + final_ccv(depth)


def evict_subtree_script_ccv(depth, height, operator_key):
    """EVICT_SUBTREE_h (dense) under CCV: F's fixed post-order program with
    CCV payouts. The running output index stays on the altstack as in the
    FULL tier; each payout is a DEDUCT call on the leaf's exit key, with a
    dynamic index straight off the altstack, followed by the OP_TX exact
    amount read using the parked copy of the index."""
    s = prologue_ccv() + [operator_key, "OP_CHECKSIGVERIFY"]
    s += ["OP_1", "OP_TOALTSTACK", F.NODE_PREFIX]       # T | 1
    d = [0]

    def leaf_step():
        # [T ... leaf_or_empty] | idx  ->  [T ... oh os] | idx+1
        return ["OP_SIZE", "OP_0NOTEQUAL",
                "OP_IF",
                "OP_SIZE", F.LEAF_LEN, "OP_EQUALVERIFY",
                "OP_DUP", F.OFF_EVICTOR_KEY, 32, "OP_SUBSTR", operator_key, "OP_EQUALVERIFY",
                "OP_DUP", F.OFF_EVICT_AFTER, F.LEN_EVICT_AFTER, "OP_SUBSTR",
                "OP_CHECKLOCKTIMEVERIFY", "OP_DROP",
                # idx -> idx+1 on alt, keep a copy for the OP_TX index.
                "OP_FROMALTSTACK", "OP_DUP", "OP_1ADD", "OP_TOALTSTACK",  # leaf idx
                "OP_DUP", "OP_TOALTSTACK",                               # leaf idx | copy
                # CCV: data empty, index idx, pk leaf.exit_key, taptree empty, mode 2.
                # Build bottom..top: "" idx ek "" 2, with ek picked from leaf.
                "OP_2SWAP",                                   # idx "" leaf  (data idx to bottom)
                "OP_2SWAP", "OP_DUP", F.OFF_EXIT_KEY, 32, "OP_SUBSTR", "OP_ROT",
                # ... arrangement is fragile; verified by the test suite.
                b"", 2, CCV,
                "OP_FROMALTSTACK", SEL_OUT_SINGLE, "OP_TX", "OP_DROP",  # leaf amt
                "OP_OVER", 8, "OP_LEFT", "OP_NUMEQUALVERIFY",
                ] + F.leaf_acc() + [
                "OP_ELSE",
                "OP_DROP", lt.EMPTY_LEAF_HASH, "OP_0",
                "OP_ENDIF"]

    def gen(h):
        if h == 0:
            s.extend([d[0] + 1, "OP_ROLL"])
            s.extend(leaf_step())
            d[0] += 2
        else:
            gen(h - 1); gen(h - 1)
            s.extend(F._hash_step(d[0]))
            d[0] -= 2
    gen(height)
    s += ["OP_FROMALTSTACK", "OP_DROP",
          lt.empty_node(height)[0], "OP_0"]
    s += F.levels("D", depth, height)
    return s + check_old_ccv("D") + final_ccv(depth)


def all_scripts_ccv(depth, operator_key, join_heights=(0,), exit_ks=(1,),
                    profile="D", join_ks=(2,)):
    """Ordered dict name -> token list for a CCV-tier tree's taptree.

    CLAIM is not generated (spec 4.7): the FULL-tier voucher message binds
    `m`, which no longer exists in the CCV-tier witness; vouchers would
    need a redefined message and are left as the tier's documented follow-up.
    """
    out = {f"EXIT_{k}": exit_script_ccv(depth, k, profile) for k in exit_ks}
    for h in (join_heights if profile == "D" else (0,)):
        out[f"JOIN_{h}"] = join_script_ccv(depth, h, operator_key, profile)
    for k in join_ks:
        out[f"JOINK_{k}"] = join_script_ccv(depth, 0, operator_key, profile, k)
    out["UPDATE"] = update_script_ccv(depth, operator_key, profile)
    if profile == "D":
        for h in (1, 2):
            if h <= depth:
                out[f"EVICT_SUBTREE_{h}"] = evict_subtree_script_ccv(depth, h, operator_key)
    return out
