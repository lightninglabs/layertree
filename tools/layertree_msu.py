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
