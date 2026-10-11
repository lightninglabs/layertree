#!/usr/bin/env python3
"""LayerTree transition script templates, CCV tier (spec section 4.6).

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
* The output-0 construction. One CHECK_OUTPUT call in the default
  (assign) mode with data = nh, index 0, pk empty, taptree -1 proves
  output 0 carries the new state under the same taptree and assigns the
  input's residual to it as a floor. The equality out0.amount == ns
  remains one OP_TX read: CCV binds amounts to the input's amount, not to
  script-computed sums.
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
    """[T ... data] -> [T ...]. CHECK_OUTPUT in the default (assign) mode
    on output `out_index`: the tree output for state `data` (pk empty =
    NUMS, taptree -1 = the input's own). Same bare-window contract as
    ccv_check_input. final_ccv inlines exactly these operands; this
    function names them for the listings.
    """
    return [out_index, b"", MINUS1, 0, CCV]


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

def exit_block_ccv(profile, depth, out_index, exact=False, tower=False, tree_id=None):
    """One exit. Stack: [path] leaf sig is_evict -> T oh os nh ns (fold done).

    Authorization and fold are F.exit_block's (F.exit_auth, with
    tower=True the EXIT_K^t authorisation of 7.2 rule 7 over tree_id, the
    tier's second OP_CHECKSIGFROMSTACK user after CLAIM); the payout
    scriptPubKey check is the CCV DEDUCT call (ccv_payout_fixed), the
    amount comparison remains one OP_TX read.
    """
    if tower:
        exact = True
    s = F.exit_auth(tower, tree_id) + [     # leaf
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


def exit_script_ccv(depth, k=1, profile="D", exact=True, tower=False, tree_id=None):
    """EXIT_K under CCV. witness (bottom..top) = [block_K] ... [block_1],
    block_i = per-level items then leaf_i sig_i is_evict_i. No r, no m.

    The CCV tier supports exact payouts only (exact=True is the default and
    the only mode): with output 0 under the assign mode, a payout short of
    the leaf amount would strand the difference in the residual and force
    output 0 above ns, breaking rule 5's equality. Fees are exogenous, as
    in the MID and MIN tiers. tower=True is EXIT_K^t (spec 7.2 rule 7):
    the owner branch takes the off-chain authorisation over tree_id, a
    constant of the script, in place of a transaction signature.
    """
    assert not tower or tree_id is not None
    s = prologue_ccv()
    s += exit_block_ccv(profile, depth, 1, exact, tower, tree_id) + check_old_ccv(profile)
    for i in range(2, k + 1):
        s += ["OP_SWAP", "OP_TOALTSTACK", "OP_TOALTSTACK", "OP_DROP"]
        s += exit_block_ccv(profile, depth, i, exact, tower, tree_id) + F.check_prev_root_from_alt(profile)
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


def split_script_ccv(depth, profile="D", dust_min=lt.DUST_MIN):
    """SPLIT (spec 7.5.2) under CCV: the owner-authorised carve.

    Witness (bottom..top): [claim path] [source path] src_leaf new_leaf
    owner_sig. No r, no m. SPLIT authorises with an ordinary transaction
    signature by src.owner_key, so nothing in it signs `m`, and it carries
    over from the FULL tier unchanged except for the binding: F's
    _carve_body with the parked root replaced by CHECK_INPUT on the first
    step's old root, and FINAL by final_ccv. CLAIM and CLAIM^h share the
    body (_carve_body_ccv) with the voucher check over the tree's tree_id
    in place of the signature (claim_script_ccv, spec 7.5).

    The two steps, the seq increment, the drained-source rule and
    conservation are F._carve_body's, token for token, apart from the
    altstack bookkeeping for r and m.
    """
    return prologue_ccv() + [
        2, "OP_PICK", F.OFF_OWNER_KEY, 32, "OP_SUBSTR",     # src claim sig owner_key
        "OP_CHECKSIGVERIFY"] + _carve_body_ccv(depth, profile, dust_min)


# ------------------------------------------------- vouchers: tree_id --
# Every tier's voucher binds the tree's tree_id (spec 6.2, 7.5), a 32-byte
# constant of the CLAIM scripts, so the CCV tier shares the voucher check
# of the FULL tier (0xC2) and of the MID tier (0xC0) token for token. The
# CCV witness carries no r and no m, which is what makes the shared check
# possible: nothing in it ever needed m.
tree_id = lt.tree_id


def claim_script_ccv(depth, tid, profile="D", hashlock=False, dust_min=lt.DUST_MIN):
    """CLAIM (7.5) or CLAIM^h (7.5.1) under CCV (0xC2).

    Witness (bottom..top): [claim path] [source path] src_leaf claim_leaf
    voucher_sig [preimage]. No r, no m. The voucher check is the FULL
    tier's (F.voucher_auth) over the tree's tree_id; the rest is SPLIT's
    body.
    """
    s = prologue_ccv()
    if hashlock:
        s += ["OP_SIZE", 32, "OP_EQUALVERIFY", "OP_SHA256",
              "OP_TOALTSTACK"]                              # src claim vsig     | phash
    return s + F.voucher_auth(tid, hashlock) + _carve_body_ccv(depth, profile, dust_min)


def _carve_body_ccv(depth, profile, dust_min=lt.DUST_MIN):
    """[src claim] -> [1], after the authorisation: F._carve_body's two
    steps bound by CHECK_INPUT and final_ccv. Shared by SPLIT, CLAIM and
    CLAIM^h under 0xC2."""
    s = F.carve_leaf_rules(dust_min) + [                   # src claim
        # new_src = le64(src.amt - claim.amt) || src[8:112] || le32(src.seq + 1)
        "OP_OVER", 8, "OP_LEFT", "OP_OVER", 8, "OP_LEFT", "OP_SUB"] + F.LE64 + [
        2, "OP_PICK", F.OFF_EXIT_KEY, F.OFF_SEQ - F.OFF_EXIT_KEY, "OP_SUBSTR", "OP_CAT",
        2, "OP_PICK", F.OFF_SEQ, F.LEN_SEQ, "OP_SUBSTR", "OP_1ADD",
        "OP_SIZE", 4, "OP_LESSTHANOREQUAL", "OP_VERIFY"] + F.PAD4 + ["OP_CAT",  # src claim new_src
        # park claim_leaf: alt = claim
        "OP_SWAP", "OP_TOALTSTACK"]                         # src new_src | claim
    if profile == "S":
        s += ["OP_OVER"] + F.leaf_pos() + ["OP_NIP"] + F.sparse_setup()  # | claim pos E_0
    s += [F.NODE_PREFIX, "OP_ROT", "OP_ROT",                # T src new_src
          "OP_SWAP"] + F.leaf_acc() + [                     # T new_src oh os
          "OP_ROT"] + F.leaf_acc()                          # T oh os nh ns
    s += F.drain_rule(dust_min)                             # drained -> E_0, else ns >= DUST_MIN
    s += F.levels(profile, depth)
    s += check_old_ccv(profile)                             # T nh1 ns1 | claim
    s += ["OP_FROMALTSTACK",                                # T nh1 ns1 claim
          2, "OP_ROLL", 2, "OP_ROLL",                       # T claim nh1 ns1
          "OP_SWAP", "OP_TOALTSTACK", "OP_TOALTSTACK"]      # T claim | nh1 ns1
    if profile == "S":
        s += F.leaf_pos() + F.sparse_setup()                # T claim | nh1 ns1 pos E_0
    s += F.leaf_acc() + [                                   # T ch cs
          lt.EMPTY_LEAF_HASH, "OP_0", "OP_2SWAP"]           # T E_0 0 ch cs
    s += F.levels(profile, depth)
    s += F.check_prev_root_from_alt(profile)                # T nh2 ns2
    return s + final_ccv(depth)


def leaf_step_ccv(operator_key):
    """One leaf of the EVICT_SUBTREE post-order program under CCV:
    [T ... leaf_or_empty] | idx -> [T ... oh os] | idx+1. The payout is a
    DEDUCT call on the leaf's exit key at the dynamic output index."""
    return ["OP_SIZE", "OP_0NOTEQUAL",
            "OP_IF",
            "OP_SIZE", F.LEAF_LEN, "OP_EQUALVERIFY",
            "OP_DUP", F.OFF_EVICTOR_KEY, 32, "OP_SUBSTR", operator_key, "OP_EQUALVERIFY",
            "OP_DUP", F.OFF_EVICT_AFTER, F.LEN_EVICT_AFTER, "OP_SUBSTR",
            "OP_CHECKLOCKTIMEVERIFY", "OP_DROP",
            # idx -> idx+1 on alt, keep a copy for the OP_TX index.
            "OP_FROMALTSTACK", "OP_DUP", "OP_1ADD", "OP_TOALTSTACK",  # leaf idx       | idx'
            "OP_DUP", "OP_TOALTSTACK",                               # leaf idx       | idx' idx
            # CCV: data empty, index idx, pk leaf.exit_key, taptree empty, mode 2.
            b"", "OP_SWAP",                                          # leaf "" idx
            2, "OP_PICK", F.OFF_EXIT_KEY, 32, "OP_SUBSTR",           # leaf "" idx ek
            b"", 2, CCV,                                             # leaf           DEDUCT payout
            "OP_FROMALTSTACK", SEL_OUT_SINGLE, "OP_TX", "OP_DROP",  # leaf amt      | idx'
            "OP_OVER", 8, "OP_LEFT", "OP_NUMEQUALVERIFY",
            ] + F.leaf_acc() + [
            "OP_ELSE",
            "OP_DROP", lt.EMPTY_LEAF_HASH, "OP_0",
            "OP_ENDIF"]


def evict_subtree_script_ccv(depth, height, operator_key):
    """EVICT_SUBTREE_h (dense) under CCV: F's fixed post-order program with
    CCV payouts. The running output index stays on the altstack as in the
    FULL tier; each payout is a DEDUCT call on the leaf's exit key, with a
    dynamic index straight off the altstack, followed by the OP_TX exact
    amount read using the parked copy of the index."""
    s = prologue_ccv() + [operator_key, "OP_CHECKSIGVERIFY"]
    s += ["OP_1", "OP_TOALTSTACK", F.NODE_PREFIX]       # T | 1
    d = [0]
    leaf_step = lambda: leaf_step_ccv(operator_key)

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


# ------------------------------------------------------- 0xC0 numerics --
# The c0 variant is MID's machinery (tools/layertree_mid.py) with the
# three key-binding regions replaced by CCV calls; the fold, the PADZ
# padding, the seven-element leaf and the sparse position accumulator are
# MID's, reused verbatim. Sparse c0 trees are limited to D <= 31, as MID
# is (the teardown compares the folded accumulator with the 32-bit
# pos_lo; spec 4.5).
import layertree_mid as M  # noqa: E402  (imported here to keep c2 imports lean)


def _check_old_ccv0(sparse):
    """MID's check_old with the root comparison replaced by CHECK_INPUT.

    MID's check_old leaves [.., nh, ns, oh] with oh bare on top after the
    input-amount equality (and the sparse teardown); its trailing
    FROMALTSTACK/EQUALVERIFY compared a parked witness root, which the
    CCV tier does not carry. The four CCV operands go on top of oh, and
    the call consumes all five.
    """
    return M.check_old(sparse)[:-2] + ccv_check_input()


def _final_ccv0(depth):
    """MID's final with output 0's spk check replaced by the CCV assign
    call and the amount compared as bytes (le64(ns) vs the OP_TX amount).

    Entry [zf wf T nh ns] (zf wf: the final pads, as in MID). Terminal
    exits drop the pads; the assign-mode floor plus the byte equality
    keep rule 5 exactly as in the c2 tier.
    """
    e_d = lt.empty_node(depth)[0]
    return (["OP_ROT", "OP_DROP",
             "OP_OVER", e_d, "OP_EQUAL",
             "OP_IF", "OP_2DROP", "OP_2DROP", "OP_1",
             "OP_ELSE"] + M.roll(3, 2) + M.le64() +    # nh le64(ns)
            ["OP_TOALTSTACK",                          # nh            | le64(ns)
             # CCV: data = nh, index 0, pk empty, taptree -1, mode assign.
             "OP_0", b"", MINUS1, 0, CCV,
             "OP_FROMALTSTACK",                        # le64(ns)
             "OP_0", SEL_OUT_SINGLE, "OP_TX", "OP_DROP", "OP_EQUALVERIFY",
             "OP_1", "OP_ENDIF"])


def _pay_ccv0(out_index):
    """The exit-block payout under c0: replaces MID's 13-token spk check
    (OP_TX read + P2TR_PREFIX CAT EQUALVERIFY) with the CCV DEDUCT call
    on the leaf's exit-key element (MID's leaf travels as ten elements
    with ek seven deep under the OP_TX pair) plus the exact amount
    compare. is_evict is parked by the block's opening DUP/TOALTSTACK and
    is popped by the trailing FROMALTSTACK/DROP as in MID.
    """
    return [out_index, SEL_OUT_SINGLE, "OP_TX", "OP_DROP",   # leaf10 amt1
            "OP_TOALTSTACK",                                  # leaf10 | amt1
            b"", out_index,                                   # data index
            10, "OP_PICK",                                   # ek element (pk slot)
            b"", 2, CCV,                                      # taptree, mode DEDUCT
            "OP_FROMALTSTACK",                                # leaf10 amt1
            10, "OP_PICK", "OP_EQUALVERIFY",                  # amt1 == leaf amt8
            "OP_FROMALTSTACK", "OP_DROP"]                     # leaf10 (is_evict gone)


def _exit_block_ccv0(sparse, depth, out_index, tower=False, tree_id=None):
    """MID's exit block with the payout spk check replaced by _pay_ccv0.
    Exact payouts only, as in the whole tier. tower=True is EXIT_K^t (spec
    7.2 rule 7) with MID's tower_auth."""
    s = M.exit_auth(tower, tree_id)                           # leaf(10)
    s += _pay_ccv0(out_index)                                 # leaf(10)
    s += M.leaf_join() + M.tagged(F.LEAF_PREFIX) + ["OP_FROMALTSTACK"]  # oh os
    if sparse:
        s += M.roll(5, 4) + M.sparse_setup()
    s += [F.NODE_PREFIX, "OP_ROT", "OP_ROT", lt.EMPTY_LEAF_HASH, "OP_0"]
    return s + M.levels(sparse, depth)


def _exit_script_ccv0(depth, k=1, sparse=False, tower=False, tree_id=None):
    """EXIT_K under c0: MID's chained-block structure, first block checked
    by _check_old_ccv0, chained blocks by M.check_prev, then _final_ccv0.

    Witness layout: MID's minus r and m, i.e. bottom..top
    [zf wf] + [chained blocks: levels + leaf10 + ea_num ze we sig is_evict]
    + [first block: zi wi + levels + leaf10 + ea_num ze we sig is_evict].
    tower=True is EXIT_K^t (spec 7.2 rule 7) over tree_id.
    """
    assert not tower or tree_id is not None
    s = _exit_block_ccv0(sparse, depth, 1, tower, tree_id) + _check_old_ccv0(sparse)
    for i in range(2, k + 1):
        s += ["OP_SWAP", "OP_TOALTSTACK", "OP_TOALTSTACK", "OP_DROP"]
        s += _exit_block_ccv0(sparse, depth, i, tower, tree_id) + M.check_prev(sparse)
    return s + _final_ccv0(depth)


def _join_script_ccv0(depth, height, operator_key, sparse=False, k=1):
    s = [operator_key, "OP_CHECKSIGVERIFY"]
    s += M.join_block(sparse, depth, height) + _check_old_ccv0(sparse)
    for _ in range(2, k + 1):
        s += ["OP_SWAP", "OP_TOALTSTACK", "OP_TOALTSTACK", "OP_DROP"]
        s += M.join_block(sparse, depth, height) + M.check_prev(sparse)
    return s + _final_ccv0(depth)


def _update_script_ccv0(depth, operator_key, sparse=False, exit_consent=False):
    """UPDATE / UPDATE^x under c0: MID's update with the same two checks
    replaced. MID's witness order minus r and m."""
    s = []
    if exit_consent:
        s += [21, "OP_PICK", "OP_CHECKSIGVERIFY"]
    s += [operator_key, "OP_CHECKSIGVERIFY", 18, "OP_PICK", "OP_CHECKSIGVERIFY"]
    if sparse:
        s += [8, "OP_PICK", 19, "OP_PICK", "OP_EQUALVERIFY",
              5, "OP_PICK", 16, "OP_PICK", "OP_EQUALVERIFY"]
    s += M.leaf_join() + ["OP_TOALTSTACK"]
    s += M.leaf_join() + M.tagged(F.LEAF_PREFIX)
    s += ["OP_FROMALTSTACK", "OP_FROMALTSTACK", "OP_FROMALTSTACK",
          "OP_SWAP"] + M.tagged(F.LEAF_PREFIX) + ["OP_SWAP"]
    if sparse:
        s += M.roll(7, 4) + M.sparse_setup()
    s += [F.NODE_PREFIX] + M.roll(4, 4)
    s += M.levels(sparse, depth)
    return s + _check_old_ccv0(sparse) + _final_ccv0(depth)


def _pay_evict_ccv0():
    """The EVICT_SUBTREE payout under c0, in place of M._evict_pay:
    [leaf(10) idx] | .. idx' -> [leaf(10)]. A CHECK_OUTPUT|DEDUCT call on
    the leaf's exit-key element at the dynamic output index, then the exact
    amount compare against the amount field with one OP_TX read."""
    return ["OP_DUP", "OP_TOALTSTACK",                       # leaf(10) idx    | .. idx' idx
            b"", "OP_SWAP",                                  # leaf(10) "" idx
            10, "OP_PICK",                                   # leaf(10) "" idx ek
            b"", 2, CCV,                                     # leaf(10)        DEDUCT payout
            "OP_FROMALTSTACK", SEL_OUT_SINGLE, "OP_TX", "OP_DROP",   # leaf(10) amt
            10, "OP_PICK", "OP_EQUALVERIFY"]                 # leaf(10)   (exact payout)


def _evict_subtree_script_ccv0(depth, height, operator_key):
    """EVICT_SUBTREE_h (dense) under c0: the MID tier's element-based sweep
    (M.evict_body: a pre-pass of leaf steps in position order, then a
    mirrored post-order hash pass) with the payout check replaced by a CCV
    DEDUCT call and the two bindings by CHECK_INPUT and the assign-mode
    output check. Witness: MID's minus r and m."""
    s = [operator_key, "OP_CHECKSIGVERIFY"]
    s += M.evict_body(height, operator_key, _pay_evict_ccv0())      # T oh os E_h 0
    s += M.levels(False, depth, height)
    return s + _check_old_ccv0(False) + _final_ccv0(depth)


def _split_script_ccv0(depth, sparse=False, dust_min=lt.DUST_MIN):
    """SPLIT (7.5.2) under c0: MID's carve with the owner's transaction
    signature, no r and no m. Witness: MID's SPLIT witness minus r and m,
    so src.ok is M.CARVE_OWNER_DEPTH deep under the signature. MID's
    carve_source runs with alt_r=False, CHECK_INPUT replaces the
    parked-root comparison of step 1, and _final_ccv0 replaces FINAL."""
    s = [M.CARVE_OWNER_DEPTH, "OP_PICK", "OP_CHECKSIGVERIFY"]         # src(10) claim(10) extras(13)
    return s + _carve_body_ccv0(depth, sparse, dust_min)


def _claim_script_ccv0(depth, tid, sparse=False, hashlock=False, dust_min=lt.DUST_MIN):
    """CLAIM / CLAIM^h under c0: MID's carve witness minus r and m, with the
    MID tier's voucher check (M.voucher_auth) over the tree's tree_id.

    Witness (bottom..top): MID's CLAIM witness up to vsig, then [preimage];
    no r, no m."""
    s = []
    if hashlock:
        s += ["OP_SIZE", 32, "OP_EQUALVERIFY", "OP_SHA256",
              "OP_TOALTSTACK"]                                       # ... extras(7) vsig  | phash
    return s + M.voucher_auth(tid, hashlock) + _carve_body_ccv0(depth, sparse, dust_min)


def _carve_body_ccv0(depth, sparse, dust_min=lt.DUST_MIN):
    """[src(10) claim(10) extras(7)] -> [1]: MID's two carve steps bound by
    CCV. Shared by SPLIT, CLAIM and CLAIM^h under c0."""
    s = M.carve_source(depth, sparse, alt_r=False, dust_min=dust_min)   # T oh os nh ns  | claim_leaf amt_c
    s += _check_old_ccv0(sparse)                                     # T nh1 ns1
    s += ["OP_FROMALTSTACK", "OP_FROMALTSTACK"]                      # T nh1 ns1 amt_c claim_leaf
    return s + M.carve_claim(depth, sparse) + _final_ccv0(depth)


# ------------------------------------------------------ DETACH_h (7.10) --
# FULL's DETACH_h (8.10) with the second output check as a CCV call: output
# 1 is checked by CHECK_OUTPUT in the DEDUCT mode with data = R_h, the NUMS
# key and the taptree m_h, so it is the CCV tree output of a depth-h tree
# at root R_h under the detached option set, and its amount is deducted
# from the residual that output 0 then receives; the exact equality with
# sum_h is one OP_TX read, as every amount check in this tier is. The old
# node (R_h, sum_h) folds up the path, the new node is E_h.

def detach_script_ccv(depth, height, operator_key, m_h):
    """DETACH_h (7.10) under CCV (0xC2).

    witness (bottom..top) = [dir sc]*(D-h) R_h sum_h8 sig. No r, no m. m_h
    is the parent's option set compiled at depth h (7.10 rule 3), from
    detached_taptree_root_ccv or CCVTreeOptions.taptree_root."""
    assert len(m_h) == 32
    e_h = lt.empty_node(height)[0]
    s = prologue_ccv() + [operator_key, "OP_CHECKSIGVERIFY"]        # R_h sum8
    s += ["OP_SIZE", 8, "OP_EQUALVERIFY",
          "OP_OVER", "OP_SIZE", 32, "OP_EQUALVERIFY", "OP_DROP",     # R_h sum8
          # output 1: CHECK_OUTPUT|DEDUCT, data R_h, index 1, pk empty (NUMS), taptree m_h
          "OP_OVER", 1, b"", m_h, 2, CCV,                            # R_h sum8
          1, SEL_OUT_SINGLE, "OP_TX", "OP_DROP",                     # R_h sum8 amt1
          "OP_OVER", "OP_NUMEQUALVERIFY",                            # R_h sum8          (output 1 pays sum_h exactly)
          F.NODE_PREFIX, "OP_ROT", "OP_ROT",                         # T R_h sum8
          e_h, "OP_0"]                                               # T R_h sum8 E_h 0
    s += F.levels("D", depth, height)
    return s + check_old_ccv("D") + final_ccv(depth)


def _detach_script_ccv0(depth, height, operator_key, m_h):
    """DETACH_h (7.10) under the CCV tier's 0xC0 numerics.

    witness (bottom..top) = zf wf zi wi [levels h..D-1 (MID)] R_h sum_num
    zs ws sig: the subtree sum arrives as a minimal number with its PADZ
    pad, as every number does in this encoding; NONNEG keeps it
    non-negative before it enters the fold, and le64 of it is compared
    with output 1's amount as bytes."""
    assert len(m_h) == 32
    e_h = lt.empty_node(height)[0]
    s = [operator_key, "OP_CHECKSIGVERIFY"]                          # R_h sum zs ws
    s += [2, "OP_PICK"] + M.nonneg() + ["OP_TOALTSTACK"]              # R_h sum zs ws     | sum
    s += M.le64()                                                     # R_h le64(sum)
    s += ["OP_OVER", "OP_SIZE", 32, "OP_EQUALVERIFY", "OP_DROP",      # R_h le64
          "OP_OVER", 1, b"", m_h, 2, CCV,                             # R_h le64          (output 1 under m_h, DEDUCT)
          1, SEL_OUT_SINGLE, "OP_TX", "OP_DROP", "OP_EQUALVERIFY",    # R_h               (amt1 == le64(sum_h))
          "OP_FROMALTSTACK",                                          # R_h sum
          F.NODE_PREFIX, "OP_ROT", "OP_ROT", e_h, "OP_0"]             # T R_h sum E_h 0
    s += M.levels(False, depth, height)
    return s + _check_old_ccv0(False) + _final_ccv0(depth)


class CCVTreeOptions:
    """A CCV tree's creation parameters other than its depth (spec 6.2,
    4.6), as F.TreeOptions is for FULL: the numerics ("c2" or "c0"), the
    profile, OPERATOR_KEY, tree_id, DUST_MIN, the JOIN heights, EXIT_K
    sizes, JOINK sizes and sweep heights, and the variants a CCV taptree
    may carry: the tower-delegable exit EXIT_K^t (7.2 rule 7, in place of
    EXIT_K; it needs tree_id), UPDATE^x (in place of UPDATE), CLAIM and
    CLAIM^h (which
    need tree_id), SPLIT and DETACH_h. at_depth(D) compiles the set for a
    tree of depth D, which is what the parent's taptree is built from and
    what a DETACH_h child MUST be built from at depth h (7.10 rule 3).
    Heights that do not fit the depth are dropped. The defaults are
    all_scripts_ccv's: EXIT_1, JOIN_0, JOINK_2, UPDATE and the sweeps at
    heights 1 and 2."""

    def __init__(self, operator_key, numeric="c2", profile="D", tree_id=None, join_heights=(0,),
                 exit_ks=(1,), join_ks=(2,), evict_heights=(1, 2), tower=False, update_x=False, claim=False,
                 claim_h=False, split=False, detach_heights=(), dust_min=lt.DUST_MIN):
        assert numeric in ("c2", "c0")
        assert not tower or tree_id is not None
        self.operator_key, self.numeric, self.profile, self.tree_id = operator_key, numeric, profile, tree_id
        self.join_heights, self.exit_ks, self.join_ks = tuple(join_heights), tuple(exit_ks), tuple(join_ks)
        self.evict_heights, self.tower, self.update_x = tuple(evict_heights), tower, update_x
        self.claim, self.claim_h, self.split = claim, claim_h, split
        self.detach_heights, self.dust_min = tuple(detach_heights), dust_min

    def at_depth(self, depth):
        """Ordered dict name -> token list: the set compiled for depth `depth`,
        the reference members in all_scripts_ccv's order, then the variants
        in a fixed order."""
        op, prof, c0 = self.operator_key, self.profile, self.numeric == "c0"
        sparse = prof == "S"
        out = all_scripts_ccv(depth, op, self.join_heights, self.exit_ks, prof, self.join_ks,
                              self.numeric, self.evict_heights)
        if self.tower:
            # EXIT_K^t replaces EXIT_K in place, so the set keeps its order.
            for k in self.exit_ks:
                out[f"EXIT_{k}"] = (_exit_script_ccv0(depth, k, sparse, tower=True, tree_id=self.tree_id) if c0
                                    else exit_script_ccv(depth, k, prof, tower=True, tree_id=self.tree_id))
        if self.update_x:
            upd_x = (_update_script_ccv0(depth, op, sparse, exit_consent=True) if c0
                     else update_script_ccv(depth, op, prof, exit_consent=True))
            out = {("UPDATE_X" if k == "UPDATE" else k): (upd_x if k == "UPDATE" else v) for k, v in out.items()}
        for name, hl, on in (("CLAIM", False, self.claim), ("CLAIM_H", True, self.claim_h)):
            if on:
                out[name] = (_claim_script_ccv0(depth, self.tree_id, sparse, hl, self.dust_min) if c0
                             else claim_script_ccv(depth, self.tree_id, prof, hl, self.dust_min))
        if self.split:
            out["SPLIT"] = (_split_script_ccv0(depth, sparse, self.dust_min) if c0
                            else split_script_ccv(depth, prof, self.dust_min))
        if prof == "D":
            for h in self.detach_heights:
                if h < depth:
                    m_h = self.taptree_root(h)
                    out[f"DETACH_{h}"] = (_detach_script_ccv0(depth, h, op, m_h) if c0
                                          else detach_script_ccv(depth, h, op, m_h))
        return out

    def taptree_root(self, depth):
        """The tree identifier m of a CCV tree of depth `depth` created with
        these options (6.2); for a DETACH_h child this is m_h."""
        from script_sim import assemble
        version = 0xc0 if self.numeric == "c0" else 0xc2
        return lt.taptree_root([lt.tapleaf_hash(assemble(t, self.numeric), version)
                                for t in self.at_depth(depth).values()])


def detached_taptree_root_ccv(height, operator_key, numeric="c2", options=None):
    """m_h for DETACH_h under CCV (7.10 rule 3): the parent's option set
    compiled for depth h in the parent's numerics. With no options this is
    all_scripts_ccv's set (EXIT_1, JOIN_0, JOINK_2, UPDATE, EVICT_SUBTREE_1
    and _2); a parent created with more passes its CCVTreeOptions."""
    if options is None:
        options = CCVTreeOptions(operator_key, numeric)
    assert options.operator_key == operator_key and options.numeric == numeric
    return options.taptree_root(height)


def all_scripts_ccv(depth, operator_key, join_heights=(0,), exit_ks=(1,),
                    profile="D", join_ks=(2,), numeric="c2", evict_heights=(1, 2)):
    """Ordered dict name -> token list for a CCV-tier tree's taptree.

    CLAIM and CLAIM^h are not generated here: they take the tree's
    tree_id (claim_script_ccv, _claim_script_ccv0), and they are the only
    CCV scripts that need OP_CHECKSIGFROMSTACK. A tree adds them at
    creation, as it does SPLIT, UPDATE^x and DETACH_h (CCVTreeOptions).
    """
    c0 = numeric == "c0"
    if c0:
        sparse = profile == "S"
        out = {f"EXIT_{k}": _exit_script_ccv0(depth, k, sparse) for k in exit_ks}
        for h in (join_heights if profile == "D" else (0,)):
            if h <= depth:
                out[f"JOIN_{h}"] = _join_script_ccv0(depth, h, operator_key, sparse)
        for k in join_ks:
            out[f"JOINK_{k}"] = _join_script_ccv0(depth, 0, operator_key, sparse, k)
        out["UPDATE"] = _update_script_ccv0(depth, operator_key, sparse)
        if profile == "D":
            for h in evict_heights:
                if h <= depth:
                    out[f"EVICT_SUBTREE_{h}"] = _evict_subtree_script_ccv0(depth, h, operator_key)
        return out
    out = {f"EXIT_{k}": exit_script_ccv(depth, k, profile) for k in exit_ks}
    for h in (join_heights if profile == "D" else (0,)):
        if h <= depth:
            out[f"JOIN_{h}"] = join_script_ccv(depth, h, operator_key, profile)
    for k in join_ks:
        out[f"JOINK_{k}"] = join_script_ccv(depth, 0, operator_key, profile, k)
    out["UPDATE"] = update_script_ccv(depth, operator_key, profile)
    if profile == "D":
        for h in evict_heights:
            if h <= depth:
                out[f"EVICT_SUBTREE_{h}"] = evict_subtree_script_ccv(depth, h, operator_key)
    return out
