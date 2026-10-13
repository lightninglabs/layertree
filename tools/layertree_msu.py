#!/usr/bin/env python3
"""LayerTree scripts under CCV + OP_MERKLESUMUPDATE (HYPOTHETICAL).

This module is a MEASUREMENT, not a tier (issue #3 part 2): it compiles
the transitions against BIP-443 OP_CHECKCONTRACTVERIFY plus the
hypothetical OP_MERKLESUMUPDATE of the simulator (tools/script_sim.py,
hypothetical=True), to quantify what a native state-machine opcode would
buy over the RISC opcode set. It is never part of any tier's
all_scripts(), of the golden taptree, or of any allowed-opcode set; the
simulator refuses OP_MERKLESUMUPDATE unless the interpreter is
constructed with hypothetical=True, so a real-tier script can never
reach it by accident.

The scripts follow the issue's sketch, in tapleaf 0xC2 numerics (the
splice opcodes make the byte surgery readable; a c0 encoding would add
the MID tier's per-element leaf machinery without changing the
conclusions):

* No arithmetic anywhere. The leaf's amount field is le64 in its first
  8 bytes, MSU nodes and roots carry raw le64 sums, and OP_TX returns
  amounts as 8-byte strings: every amount check is a byte comparison
  (OP_EQUALVERIFY). PADZ, the CScriptNum 4-byte limit and the 2^31 sat
  cap do not exist in these scripts.
* One MSU call per transition replaces the D unrolled LEVEL macros: the
  witness supplies the compressed proof (one sibling per non-empty
  level, deepest level first, bitmap-marked, canonical), and the opcode folds the old
  and new node over the same path in one pass.
* The binding is the CCV tier's (tools/layertree_ccv.py): CHECK_INPUT
  binds the old root to the input under the input's own taptree,
  CHECK_OUTPUT (assign) commits output 0 to the new root with the
  residual amount, CHECK_OUTPUT|DEDUCT constrains a payout to a bare
  P2TR of the leaf's exit key. No r, no m in any witness; fees are
  exogenous and payouts exact, as in the CCV tier.

The CCV state key commits to the 32-byte root HASH, so the 40-byte MSU
root nodes are spliced to their hash before every CCV call, and to
their sum before every byte comparison.

Witness per exit block (bottom..top): proof, leaf, sig, is_evict.
Proof encoding (the opcode's, tools/script_sim.py op_msu): depth ||
position (big-endian, MSB = the top level) || bitmap (bit k = a
supplied sibling at level k) || supplied siblings, deepest level first.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import layertree_ref as lt  # noqa: E402
import layertree_ccv as C  # noqa: E402
from script_sim import SEL_OUT_SINGLE  # noqa: E402

MINUS1 = b"\x81"
CCV = "OP_CHECKCONTRACTVERIFY"
MSU = "OP_MERKLESUMUPDATE"

# The opcode inventory this measurement is allowed to use. It is NOT a
# subset any real tier checks against; it exists so tools/test_msu.py can
# assert the scripts use nothing beyond BIP-342 basics plus these.
EXTRA_OPCODES = {CCV, MSU, "OP_CAT", "OP_LEFT", "OP_SUBSTR", "OP_TX",
                 "OP_SHA256", "OP_CHECKLOCKTIMEVERIFY", "OP_CHECKSIGVERIFY"}

OFF_EVICTOR_KEY = C.F.OFF_EVICTOR_KEY
OFF_OWNER_KEY = C.F.OFF_OWNER_KEY
OFF_EVICT_AFTER, LEN_EVICT_AFTER = C.F.OFF_EVICT_AFTER, C.F.LEN_EVICT_AFTER
LEAF_LEN = C.F.LEAF_LEN
TAG_LEAF_PREFIX = lt.tag_prefix(lt.TAG_LEAF)
E0_NODE = bytes(40)   # E_0 as a 40-byte node: zero hash, zero sum


def node_from_leaf():
    """[proof leaf] -> [proof node40], the leaf parked on the altstack.

    node40 = H_leaf(leaf) || le64(leaf.amount); the leaf's first 8 bytes
    ARE the le64 amount, so the node is the tagged hash of the leaf
    concatenated with the leaf's own 8-byte prefix. Traced sequence from
    [proof leaf]:
      DUP TOALT            -> [proof leaf]       | leaf
      DUP 8 LEFT TOALT     -> [proof leaf]      | amt8 leaf
      TAG SWAP CAT SHA256  -> [proof Hleaf]     | amt8 leaf
      FROMALT              -> [proof Hleaf amt8] | leaf
      CAT                  -> [proof node40]     | leaf
    """
    return ["OP_DUP", "OP_TOALTSTACK",
            "OP_DUP", 8, "OP_LEFT", "OP_TOALTSTACK",
            TAG_LEAF_PREFIX, "OP_SWAP", "OP_CAT", "OP_SHA256",
            "OP_FROMALTSTACK", "OP_CAT"]


def ccv_input_on_old_root():
    """[old40 new40] -> [new40]. CHECK_INPUT on the old root's HASH,
    keeping the new root parked. Traced from [old40 new40]:
      TOALT                     -> [old40]     | new40
      32 LEFT                   -> [oldhash]   | new40
      -1 "" -1 -1 CCV           -> []           | new40   (input check)
    (the new root stays parked; the caller pops it when needed)
    """
    return ["OP_TOALTSTACK",
            32, "OP_LEFT",
            MINUS1, b"", MINUS1, MINUS1, CCV]


def ccv_output0_on_new_root(depth):
    """[] (new40 parked on the alt by ccv_input_on_old_root) -> [].

    The assign-mode output-0 check on the new root's HASH, the amount
    byte-compare, and the terminal branch: when the new root is E_D (the
    tree drained), output 0 is unconstrained and both checks are skipped,
    as in every tier (spec 7.8). Traced (new40 is on the altstack):
      FROMALT                  -> [new40]
      DUP TOALT                -> [new40]        | copy
      32 LEFT                  -> [newhash]     | copy
      DUP <E_D hash> EQUAL     -> [newhash is_terminal]
      IF                       -> [newhash]     (TERMINAL: skip out0)
        DROP                   -> []
        FROMALT DROP           -> []              (drop the copy)
      ELSE                     -> [newhash]     (non-terminal)
        OP_0 "" -1 0 CCV       -> []              (assign out0)
        FROMALT                -> [copy]
        32 8 SUBSTR            -> [sum8]
        OP_0 SEL_OUT_SINGLE OP_TX OP_DROP EQUALVERIFY -> []
      ENDIF
    """
    e_d_hash = lt.empty_node(depth)[0]
    return ["OP_FROMALTSTACK",                      # new40
            "OP_DUP", "OP_TOALTSTACK",              # new40 | copy
            32, "OP_LEFT",                          # newhash | copy
            "OP_DUP", e_d_hash, "OP_EQUAL",
            "OP_IF",
            "OP_DROP",                              # newhash (terminal)
            "OP_FROMALTSTACK", "OP_DROP",           # drop the copy
            "OP_ELSE",
            "OP_0", b"", MINUS1, 0, CCV,           # assign out0 on newhash
            "OP_FROMALTSTACK",                     # copy
            32, 8, "OP_SUBSTR",                     # sum8
            "OP_0", SEL_OUT_SINGLE, "OP_TX", "OP_DROP", "OP_EQUALVERIFY",
            "OP_ENDIF"]


def exit_block_msu(depth, out_index):
    """One exit. Entry stack: [... proof leaf sig is_evict] (is_evict on
    top); traced step by step:
      DUP TOALT                  park is_evict
      IF evict: CLTV + evictor key; ELSE owner key; ENDIF CHECKSIGVERIFY
                                 -> [.. proof leaf]
      node_from_leaf             -> [.. proof node40]  alt [is_evict, leaf]
      PUSH E0                    -> [.. proof node40 E0]
      MSU                        -> [.. old40 new40]
      ccv_input_on_old_root      -> []                 alt [is_evict, leaf, new40]
      FROMALT, FROMALT, SWAP, TOALT -> [.. leaf]      alt [is_evict, new40]
      ccv_payout_fixed(k)        -> [.. leaf]         (DEDUCT on exit_key;
                                 BEFORE the assign so the assign's floor
                                 is the residual net of the payout)
      k SEL_OUT_SINGLE OP_TX DROP -> [.. leaf amt_k]
      OVER 8 LEFT EQUALVERIFY DROP -> []              (exact payout, bytes)
      ccv_output0_on_new_root(d) -> []                (out0 committed)
      FROMALT DROP, OP_1         -> [1]                (drop is_evict)
    """
    return (["OP_DUP", "OP_TOALTSTACK",
             "OP_IF",
             "OP_OVER", OFF_EVICT_AFTER, LEN_EVICT_AFTER, "OP_SUBSTR",
             "OP_CHECKLOCKTIMEVERIFY", "OP_DROP",
             "OP_OVER", OFF_EVICTOR_KEY, 32, "OP_SUBSTR",
             "OP_ELSE",
             "OP_OVER", OFF_OWNER_KEY, 32, "OP_SUBSTR",
             "OP_ENDIF",
             "OP_CHECKSIGVERIFY",
             ] + node_from_leaf() + [E0_NODE, MSU]
            + ccv_input_on_old_root()
            + ["OP_FROMALTSTACK", "OP_FROMALTSTACK",     # new40, leaf out
               "OP_SWAP", "OP_TOALTSTACK"]              # [.. leaf] | new40
            + C.ccv_payout_fixed(out_index)
            + [out_index, SEL_OUT_SINGLE, "OP_TX", "OP_DROP",
               "OP_OVER", 8, "OP_LEFT", "OP_EQUALVERIFY",
               "OP_DROP",                                 # the spent leaf
               ] + ccv_output0_on_new_root(depth)
            + ["OP_FROMALTSTACK", "OP_DROP", "OP_1"])


def exit_script_msu(depth, k=1):
    """EXIT_K under CCV + MSU: k sequential exits paying outputs 1..K.

    Each block folds independently from its leaf over its own path to
    the same committed old root (every CHECK_INPUT reads the same
    current input), so the blocks run in any order; for k > 1 each
    block's fold is against the ORIGINAL tree, so the new root each
    block commits is the tree minus ITS leaf only, and the last block's
    commitment is what lands on output 0. A true multi-exit needs one
    MSU call whose old/new node lists cover all k leaves (multiproofs,
    sketched in the design note as the opcode's natural extension); the
    measurement uses k = 1.
    """
    if k != 1:
        raise NotImplementedError("EXIT_K under MSU needs multiproof support")
    return exit_block_msu(depth, 1)


def join_script_msu(depth, operator_key):
    """JOIN_0 under CCV + MSU (single leaf; the position derivation and
    the empty-sibling compression live inside the opcode's proof, so the
    script is the same for both profiles). witness:
    [new_leaf_proof new_leaf sig].

    The joiner's leaf is grafted at its (possibly empty) position: the
    old node is E_0, the new node is the leaf's node, both fold over
    the same path. Traced from [proof leaf sig]:
      CHECKSIGVERIFY (operator)  -> [proof leaf]
      SIZE LEAF_LEN EQUALVERIFY
      node_from_leaf             -> [proof node40]   alt [leaf]
      PUSH E0, SWAP              -> [proof E0 node40]
      MSU                        -> [old40 new40]
      ccv_input_on_old_root      -> []               alt [leaf, new40]
      ccv_output0_on_new_root   -> []               (out0 committed)
      FROMALT DROP, OP_1         -> [1]              (drop the parked leaf)
    """
    return ([operator_key, "OP_CHECKSIGVERIFY",
             "OP_SIZE", LEAF_LEN, "OP_EQUALVERIFY",
             ] + node_from_leaf() + [
             E0_NODE,                                # proof node40 E0
             "OP_SWAP",                             # proof E0 node40
             MSU,                                   # old40 new40
             ] + ccv_input_on_old_root()
            + ccv_output0_on_new_root(depth)
            + ["OP_FROMALTSTACK", "OP_DROP", "OP_1"])  # drop the parked leaf


# ---------------------------------------------------------------------------
# The pending-leaf receive under CCV + MSU (spec 0.14.0: 7.5.4 CLAIM^m and
# CLAIM^hm, 7.9 rule 8, 7.11 RECLAIM_1; design/pending-receive.md). The
# rules are the FULL tier's (tools/layertree_scripts.py merge_script,
# reclaim_script, the reclaim form of _rewrite_step), token for token where
# they read leaves; what changes is the fold (one MSU call from the
# transition's node, at height 1 for the merge's pair and height h for the
# rewrite's subtree) and the binding (CCV, as above).
#
# Two of these transitions move value out of the tree without a payout
# (RECLAIM_1 and the rewrite's reclaims), which the assign mode on output 0
# cannot express: assign makes output 0 at least the input's residual. A
# reclaim therefore checks output 0 in the DEDUCT mode, which caps output 0
# at the residual and leaves the rest of the input free for the
# transaction, with the exact amount still pinned by the byte compare. The
# rewrite, whose net change can have either sign, takes the mode from a
# witness flag (empty = assign, 0x01 = deduct). Either mode is safe under
# the byte compare: the flag only picks which BIP-443 bound the spender
# relies on, and a wrong pick fails.
# ---------------------------------------------------------------------------
NODE_PREFIX = C.F.NODE_PREFIX
LEAF_PREFIX = C.F.LEAF_PREFIX
OFF_EXIT_KEY = C.F.OFF_EXIT_KEY
LEAF_BODY = C.F.LEAF_BODY
LE64 = C.F.LE64
SEQ_FINAL_BYTES = C.F.SEQ_FINAL_BYTES
ZERO8 = bytes(8)
EXTRA_OPCODES |= {"OP_CHECKSIGFROMSTACK", "OP_RIGHT"}


def leaf40():
    """[leaf] -> [node40] = H_leaf(leaf) || leaf[0:8] (the le64 amount).
      DUP 8 LEFT SWAP           -> [amt8 leaf]
      TAG SWAP CAT SHA256       -> [amt8 Hleaf]
      SWAP CAT                  -> [node40]
    """
    return ["OP_DUP", 8, "OP_LEFT", "OP_SWAP",
            LEAF_PREFIX, "OP_SWAP", "OP_CAT", "OP_SHA256",
            "OP_SWAP", "OP_CAT"]


def leaf40_pick():
    """[.. LP leaf] -> [.. LP node40]: leaf40 with the TAG_LEAF prefix
    hoisted (LP directly below the leaf), 10 bytes in place of 75."""
    return ["OP_DUP", 8, "OP_LEFT", "OP_SWAP",                # LP amt8 leaf
            2, "OP_PICK", "OP_SWAP", "OP_CAT", "OP_SHA256",   # LP amt8 Hleaf
            "OP_SWAP", "OP_CAT"]                              # LP node40


def pair_node_pick(k):
    """[.. NP .. l40 r40] -> [.. NP .. p40], the parent of two 40-byte
    nodes (spec 5.3): H_node(l.hash || enc64(l.sum) || r.hash ||
    enc64(r.sum)) || le64(l.sum + r.sum), with the TAG_NODE prefix NP
    hoisted: NP sits k deep once the two children have become their
    preimage. A 40-byte node followed by 0x01 IS hash || enc64(sum), so
    the preimage is l40 || 01 || r40 || 01. The sum needs one OP_ADD; it
    stays below 2^64 because both children are in a committed tree (the
    old pair) or carry the old pair's total (the new pair, conservation).
      OVER 32 8 SUBSTR OVER 32 8 SUBSTR ADD LE64 TOALT   -> [l r]      | s8
      SWAP 01 CAT SWAP 01 CAT CAT                        -> [l01r01]
      k PICK SWAP CAT SHA256 FROMALT CAT                 -> [p40]
    """
    return (["OP_OVER", 32, 8, "OP_SUBSTR", "OP_OVER", 32, 8, "OP_SUBSTR", "OP_ADD"]
            + LE64 + ["OP_TOALTSTACK",
                      "OP_SWAP", b"\x01", "OP_CAT", "OP_SWAP", b"\x01", "OP_CAT", "OP_CAT",
                      k, "OP_PICK", "OP_SWAP", "OP_CAT", "OP_SHA256",
                      "OP_FROMALTSTACK", "OP_CAT"])


# [] -> [E_0 as a 40-byte node]: 40 zero bytes from one 8-byte push.
E0_BUILD = [ZERO8, "OP_DUP", "OP_DUP", "OP_CAT", "OP_DUP", "OP_CAT", "OP_CAT"]


def drain40(dust_min=lt.DUST_MIN):
    """[n40] -> [n40']: the drained-source rule of 7.5 rule 2 with the
    floor of rule 6 on a 40-byte node. A zero sum makes the node E_0 (40
    zero bytes, built from the zero sum itself); any other sum is at least
    DUST_MIN.
      DUP 32 8 SUBSTR DUP ZERO8 EQUAL     -> [n40 s8 is_zero]
      IF NIP DUP DUP CAT DUP CAT CAT      -> [E0]      (s8 is 8 zero bytes)
      ELSE DUST_MIN SWAP <= VERIFY        -> [n40]
    """
    return ["OP_DUP", 32, 8, "OP_SUBSTR", "OP_DUP", ZERO8, "OP_EQUAL",
            "OP_IF", "OP_NIP"] + E0_BUILD[1:] + [
            "OP_ELSE", dust_min, "OP_SWAP", "OP_LESSTHANOREQUAL", "OP_VERIFY",
            "OP_ENDIF"]


def ccv_output0(depth, mode, terminal=True):
    """[] with new40 parked on the alt -> []: output 0 commits to the new
    root's hash under the input's taptree, in CCV `mode`, and its amount
    equals the root's sum (byte compare). mode is 0 (assign), 2 (deduct)
    or "stack", meaning the caller left the mode number on the main stack.
    With terminal=True a new root of E_D leaves output 0 unconstrained
    (7.8); the merge cannot drain the tree and omits the branch.
      FROMALT DUP TOALT 32 LEFT       -> [(mode) newhash]  | copy
      [DUP <E_D> EQUAL IF (mode) DROP FROMALT DROP ELSE]
      0 "" -1 <mode> CCV              -> []                | copy
      FROMALT 32 8 SUBSTR             -> [sum8]
      0 SEL_OUT_SINGLE TX DROP EQUALVERIFY
      [ENDIF]
    """
    on_stack = mode == "stack"
    s = ["OP_FROMALTSTACK", "OP_DUP", "OP_TOALTSTACK", 32, "OP_LEFT"]
    if terminal:
        s += ["OP_DUP", lt.empty_node(depth)[0], "OP_EQUAL",
              "OP_IF", "OP_2DROP" if on_stack else "OP_DROP",
              "OP_FROMALTSTACK", "OP_DROP",
              "OP_ELSE"]
    s += ["OP_0", b"", MINUS1, 4, "OP_ROLL"] if on_stack else ["OP_0", b"", MINUS1, mode]
    s += [CCV, "OP_FROMALTSTACK", 32, 8, "OP_SUBSTR",
          "OP_0", SEL_OUT_SINGLE, "OP_TX", "OP_DROP", "OP_EQUALVERIFY"]
    if terminal:
        s += ["OP_ENDIF"]
    return s


def merge_script_msu(depth, tree_id, hashlock=False, reclaim_key=None, dust_min=lt.DUST_MIN):
    """CLAIM^m (7.5.4), or CLAIM^hm with hashlock, under CCV + MSU.

    witness (bottom..top) = proof left right src_is_left X vsig [preimage]

    proof is the opcode's compressed proof of the pair node at height 1
    (depth byte D - 1). Everything up to the two new leaves is FULL's
    merge_script: the voucher over H_voucher_m(tree_id || body(S) ||
    body(T) || X [|| SHA256(preimage)]) by S.owner_key, T.owner_key ==
    S.exit_key, neither leaf at SEQ_FINAL, T not reclaimable, d = X -
    T.amount >= 1, a residual of zero (S becomes E_0) or at least
    DUST_MIN. Then the four leaves become 40-byte nodes, the old and new
    pair nodes are hashed in script, and one MSU call folds both over the
    pair's path. CHECK_INPUT binds the old root; output 0 is assigned the
    new root (the merge conserves the pair's total, so output 0 equals
    the input).
    """
    assert len(tree_id) == 32 and depth >= 2
    s = []
    if hashlock:
        s += ["OP_SIZE", 32, "OP_EQUALVERIFY", "OP_SHA256", "OP_TOALTSTACK"]    # .. v | ph
    s += [2, "OP_ROLL", "OP_DUP", "OP_TOALTSTACK",                       # p L R X v f | [ph] f
          "OP_NOTIF", "OP_2SWAP", "OP_SWAP", "OP_2SWAP", "OP_ENDIF",     # p S T X v
          3, "OP_PICK", "OP_SIZE", LEAF_LEN, "OP_EQUALVERIFY", "OP_DROP",
          2, "OP_PICK", "OP_SIZE", LEAF_LEN, "OP_EQUALVERIFY", "OP_DROP",
          "OP_OVER", "OP_SIZE", 8, "OP_EQUALVERIFY", "OP_DROP",          # p S T X v (sizes)
          3, "OP_PICK"] + LEAF_BODY + [3, "OP_PICK"] + LEAF_BODY + ["OP_CAT",
          2, "OP_PICK", "OP_CAT", tree_id, "OP_SWAP", "OP_CAT"]          # p S T X v (tid||bS||bT||X)
    if hashlock:
        s += ["OP_FROMALTSTACK", "OP_FROMALTSTACK", "OP_SWAP", "OP_TOALTSTACK",  # .. ph | f
              "OP_CAT"]
    s += C.F.tagged(C.F.VOUCHER_HM_PREFIX if hashlock else C.F.VOUCHER_M_PREFIX) + [
          4, "OP_PICK", OFF_OWNER_KEY, 32, "OP_SUBSTR",
          "OP_CHECKSIGFROMSTACK", "OP_VERIFY",                           # p S T X
          "OP_OVER", OFF_OWNER_KEY, 32, "OP_SUBSTR",
          3, "OP_PICK", OFF_EXIT_KEY, 32, "OP_SUBSTR", "OP_EQUALVERIFY",  # T.owner == S.exit
          "OP_OVER", OFF_EXIT_KEY, 32, "OP_SUBSTR",
          3, "OP_PICK", OFF_EXIT_KEY, 32, "OP_SUBSTR", "OP_EQUALVERIFY",  # T.exit == S.exit
          "OP_OVER", 4, "OP_RIGHT", SEQ_FINAL_BYTES, "OP_EQUAL", "OP_NOT", "OP_VERIFY",
          2, "OP_PICK", 4, "OP_RIGHT", SEQ_FINAL_BYTES, "OP_EQUAL", "OP_NOT", "OP_VERIFY"]
    if reclaim_key is not None:
        s += ["OP_OVER", OFF_EVICTOR_KEY, 32, "OP_SUBSTR", reclaim_key,
              "OP_EQUAL", "OP_NOT", "OP_VERIFY"]                         # T not reclaimable
    s += ["OP_DUP", 2, "OP_PICK", 8, "OP_LEFT", "OP_SUB",                # p S T X d
          "OP_1", "OP_OVER", "OP_LESSTHANOREQUAL", "OP_VERIFY",          # d >= 1
          3, "OP_PICK", 8, "OP_LEFT", "OP_SWAP", "OP_SUB",               # p S T X res
          "OP_0", "OP_OVER", "OP_LESSTHANOREQUAL", "OP_VERIFY",          # res >= 0
          ] + LE64 + [3, "OP_PICK"] + LEAF_BODY + ["OP_CAT",             # p S T X nS
          "OP_SWAP", 2, "OP_PICK"] + LEAF_BODY + ["OP_CAT"]              # p S T nS nT
    # The four leaves become nodes under one hoisted TAG_LEAF prefix (LP),
    # each parked as it is made: | f nT40 nS40 oT40.
    s += [LEAF_PREFIX,                                                   # p S T nS nT LP
          "OP_SWAP"] + leaf40_pick() + ["OP_TOALTSTACK",                 # p S T nS LP   | f nT40
          "OP_SWAP"] + leaf40_pick() + drain40(dust_min) + ["OP_TOALTSTACK",  # p S T LP | .. nS40
          "OP_SWAP"] + leaf40_pick() + ["OP_TOALTSTACK",                 # p S LP        | .. oT40
          "OP_SWAP"] + leaf40_pick() + ["OP_NIP",                        # p oS40
          NODE_PREFIX, "OP_SWAP",                                        # p NP oS40
          "OP_FROMALTSTACK", "OP_FROMALTSTACK", "OP_FROMALTSTACK",       # p NP oS oT nS nT  | f
          "OP_FROMALTSTACK",
          "OP_NOTIF", "OP_SWAP", "OP_2SWAP", "OP_SWAP", "OP_2SWAP", "OP_ENDIF"]  # p NP oL oR nL nR
    s += pair_node_pick(3) + ["OP_TOALTSTACK"]                           # p NP oL oR    | nP
    s += pair_node_pick(1) + ["OP_NIP", "OP_FROMALTSTACK",               # p oP nP
                              MSU]                                       # old40 new40
    return s + ccv_input_on_old_root() + ccv_output0(depth, 0, terminal=False) + ["OP_1"]


def reclaim_script_msu(depth, reclaim_key):
    """RECLAIM_1 (7.11) under CCV + MSU. witness (bottom..top) = proof leaf sig.

    FULL's reclaim_script with the fold and binding replaced: the leaf's
    evictor_key is RECLAIM_KEY (the extracted key is the one the signature
    is checked against, so the constant is pushed once), the lock time is
    at least evict_after, the new node is E_0, and output 0 carries the
    new root with the residual sum under DEDUCT: the leaf's value is free
    for the transaction and no output is constrained for it. A reclaim of
    the last leaf is terminal.
      OVER 72 32 SUBSTR DUP <RK> EQUALVERIFY  -> [p leaf sig rk]
      2 PICK 104 4 SUBSTR CLTV DROP
      CHECKSIGVERIFY                          -> [p leaf]
      leaf40 E0_BUILD MSU                     -> [old40 new40]
    """
    assert len(reclaim_key) == 32
    return (["OP_OVER", OFF_EVICTOR_KEY, 32, "OP_SUBSTR", "OP_DUP", reclaim_key, "OP_EQUALVERIFY",
             2, "OP_PICK", OFF_EVICT_AFTER, LEN_EVICT_AFTER, "OP_SUBSTR",
             "OP_CHECKLOCKTIMEVERIFY", "OP_DROP",
             "OP_CHECKSIGVERIFY"]
            + leaf40() + E0_BUILD + [MSU]
            + ccv_input_on_old_root() + ccv_output0(depth, 2) + ["OP_1"])


def _transfer_absorb_msu(reclaim_key):
    """FULL's _transfer_absorb with the rule 8 exit-key match: after
    old.owner_key == key (the reclaimable leaf's exit key), also
    old.exit_key == key. Stack there: [old new key delta].
      3 PICK 8 32 SUBSTR 2 PICK EQUALVERIFY      (old.exit == key)
    """
    full = C.F._transfer_absorb(reclaim_key)
    owner_check = [OFF_OWNER_KEY, 32, "OP_SUBSTR", 2, "OP_PICK", "OP_EQUALVERIFY"]
    i = next(j for j in range(len(full)) if full[j:j + len(owner_check)] == owner_check) + len(owner_check)
    return full[:i] + [3, "OP_PICK", OFF_EXIT_KEY, 32, "OP_SUBSTR", 2, "OP_PICK", "OP_EQUALVERIFY"] + full[i:]


def _rewrite_step_msu(d, exit_consent, pay, reclaim_key, side):
    """FULL's _rewrite_step; with reclaim_key, a right step takes
    _transfer_absorb_msu in place of FULL's absorb (spliced, so every
    other token, and every depth, is FULL's)."""
    step = C.F._rewrite_step(d, exit_consent, pay, reclaim_key=reclaim_key, side=side)
    if reclaim_key is None or side != "R":
        return step
    old = C.F._transfer_absorb(reclaim_key)
    i = next(j for j in range(len(step)) if step[j:j + len(old)] == old)
    return step[:i] + _transfer_absorb_msu(reclaim_key) + step[i + len(old):]


def rewrite_script_msu(depth, height, operator_key, exit_consent=True, reclaim_key=None):
    """REWRITE_h (7.9), with reclaim_key the reclaim form of rule 8, under
    CCV + MSU. exit_consent=True is REWRITE_h^x, the form a credit-leaf tree
    carries (design/pending-receive.md).

    witness (bottom..top) = deduct proof block_{2^h-1} .. block_0 sig_op,
    block_i as in FULL (8.9). The post-order machine is FULL's
    (_rewrite_step with the reclaim rules and the transfer record, and
    _hash_step2), with the CCV tier's DEDUCT payout; it leaves [T oh os nh
    ns], the old and new subtree nodes. These become 40-byte nodes, one MSU
    call folds both from height h (depth byte D - h), CHECK_INPUT binds the
    old root, and output 0 is checked in the mode the bottom flag `deduct`
    selects (empty = assign, for a rewrite whose net change is an increase
    or zero; 0x01 = deduct, for one that frees value, as a reclaim does).
    """
    assert 1 <= height < depth
    pay = C._rewrite_pay_ccv()
    s = [operator_key, "OP_CHECKSIGVERIFY",                           # f p ...blocks
         "OP_1", "OP_TOALTSTACK",                                     #   | idx
         lt.EMPTY_LEAF_HASH, LEAF_PREFIX, NODE_PREFIX]                # Z L T
    d = [0]
    pos = [0]

    def gen(h):
        if h == 0:
            side = "L" if pos[0] % 2 == 0 else "R"
            s.extend(_rewrite_step_msu(d[0], exit_consent, pay, reclaim_key, side))
            pos[0] += 1
            d[0] += 4
        else:
            gen(h - 1)
            gen(h - 1)
            s.extend(C.F._hash_step2(d[0]))
            d[0] -= 4
    gen(height)                                                       # f p Z L T oh os nh ns | idx
    s += ["OP_FROMALTSTACK", "OP_DROP",
          6, "OP_ROLL", "OP_DROP", 5, "OP_ROLL", "OP_DROP"]           # f p T oh os nh ns
    s += LE64 + ["OP_CAT", "OP_TOALTSTACK"]                           # f p T oh os | nh40
    s += LE64 + ["OP_CAT", "OP_FROMALTSTACK", "OP_ROT", "OP_DROP",    # f p oh40 nh40
                 MSU]                                                 # f old40 new40
    s += ccv_input_on_old_root()                                      # f | new40
    s += ["OP_IF", 2, "OP_ELSE", "OP_0", "OP_ENDIF"]                  # mode
    return s + ccv_output0(depth, "stack") + ["OP_1"]


# ------------------------------------------------------------ cost model --
# The spec's fee model (section 11, spec/fee-analysis.md): a transaction's
# weight is its script, witness and a 129-byte control block (1 WU each)
# plus a 946 WU exogenous-fee skeleton that includes one payout output;
# each further payout adds 172 WU and a transaction with no payout drops
# the one included. vbytes = ceil(weight / 4), once per transaction;
# witness length prefixes are excluded, as everywhere in the spec.
SKELETON_WU = 946
PAYOUT_WU = 172
CONTROL_BLOCK = 129
MODEL_DEPTH = 64


def proof_bytes(levels, siblings):
    """The opcode's proof: depth byte, position and bitmap of ceil(levels/8)
    bytes each, one 40-byte node per supplied sibling."""
    return 1 + 2 * ((levels + 7) // 8) + 40 * siblings


def tx_vbytes(script, witness, payouts):
    """vbytes of one transaction under the fee model above."""
    wu = SKELETON_WU + PAYOUT_WU * (payouts - 1) + CONTROL_BLOCK + script + witness
    return -(-wu // 4)
