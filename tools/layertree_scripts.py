#!/usr/bin/env python3
"""LayerTree transition script templates (spec section 8).

Each template is a list of assembler tokens (see script_sim.assemble):
strings are opcodes, ints are minimally-encoded numbers, bytes are data.
The macros mirror the stack diagrams in the spec exactly; run
tools/test_scripts.py to execute them against the reference tree.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import layertree_ref as lt  # noqa: E402
from script_sim import (SEL_CURR_INPUT, SEL_IN_AMOUNT, SEL_IN_SPK,  # noqa: E402
                        SEL_OUT_SINGLE)

LEAF_PREFIX = lt.tag_prefix(lt.TAG_LEAF)
NODE_PREFIX = lt.tag_prefix(lt.TAG_NODE)
STATE_PREFIX = lt.tag_prefix(lt.TAG_STATE)
VOUCHER_PREFIX = lt.tag_prefix(lt.TAG_VOUCHER)
TAPTWEAK_PREFIX = lt.tag_prefix(lt.TAG_TAPTWEAK)
NUMS33 = lt.compress(lt.NUMS)
ZERO8 = bytes(8)
P2TR_PREFIX = bytes([0x51, 0x20])

# Leaf field offsets (spec section 5.2).
OFF_AMOUNT, LEN_AMOUNT = 0, 8
OFF_EXIT_KEY = 8
OFF_OWNER_KEY = 40
OFF_EVICTOR_KEY = 72
OFF_EVICT_AFTER, LEN_EVICT_AFTER = 104, 4
OFF_SEQ, LEN_SEQ = 108, 8
LEAF_LEN = lt.LEAF_LEN

# Names for the disassembler.
CONST_NAMES = {
    LEAF_PREFIX: "<TAG_LEAF>", NODE_PREFIX: "<TAG_NODE>", STATE_PREFIX: "<TAG_STATE>",
    VOUCHER_PREFIX: "<TAG_VOUCHER>", TAPTWEAK_PREFIX: "<TAG_TAPTWEAK>",
    NUMS33: "<NUMS>", ZERO8: "<ZERO8>", P2TR_PREFIX: "<0x5120>",
    lt.EMPTY_LEAF_HASH: "<EMPTY_LEAF>", bytes([0x02]): "<0x02>",
}


def tagged(prefix):
    """[msg] -> [tagged_hash]"""
    return [prefix, "OP_SWAP", "OP_CAT", "OP_SHA256"]


PAD8 = [ZERO8, "OP_CAT", 8, "OP_LEFT"]  # [n] -> [le64(n)]   (n < 2^64)


def tree_spk():
    """[root_hash m] -> [scriptPubKey of the tree output committing to root_hash]"""
    return (["OP_SWAP"] + tagged(STATE_PREFIX) +            # m t
            ["OP_ECSCALARMUL", NUMS33, "OP_ECPOINTADD",      # m P
             32, "OP_RIGHT",                                 # m Px
             "OP_TUCK", "OP_SWAP", "OP_CAT"] +               # Px (Px||m)
            tagged(TAPTWEAK_PREFIX) +                        # Px t2
            ["OP_ECSCALARMUL",                               # Px t2G
             "OP_SWAP", bytes([0x02]), "OP_SWAP", "OP_CAT",  # t2G (02||Px)
             "OP_ECPOINTADD", 32, "OP_RIGHT",                # Qx
             P2TR_PREFIX, "OP_SWAP", "OP_CAT"])              # spk


def leaf_acc():
    """[leaf] -> [H_leaf(leaf) amount]"""
    return ["OP_DUP", 8, "OP_LEFT", "OP_SWAP"] + tagged(LEAF_PREFIX) + ["OP_SWAP"]


def prologue():
    """Common prologue: current input is #0; (root, m) match the input spk.

    Witness top: ... root m.  Leaves alt = [m root] (root on top) and
    removes root, m from the main stack.
    """
    return ([SEL_CURR_INPUT, "OP_TX", "OP_0", "OP_NUMEQUALVERIFY",
             "OP_2DUP"] + tree_spk() +
            [SEL_IN_SPK, "OP_TX", "OP_EQUALVERIFY",
             "OP_TOALTSTACK", "OP_TOALTSTACK"])


def level():
    """One merkle-sum level for both accumulators.

    Stack: dir sc T oh os nh ns  ->  T oh' os' nh' ns'
    (dir, sc are the witness items for this level, below T.)
    """
    return [
        6, "OP_ROLL", 6, "OP_ROLL",                    # T oh os nh ns dir sc
        "OP_SIZE", 40, "OP_EQUALVERIFY",
        "OP_DUP", 8, "OP_RIGHT",                       # ... dir sc ss8
        "OP_DUP", "OP_TOALTSTACK",
        3, "OP_ROLL", "OP_TUCK", "OP_ADD",             # T oh os nh dir sc ns ns'
        "OP_TOALTSTACK"] + PAD8 + [                    # T oh os nh dir sc ns8
        3, "OP_ROLL", "OP_SWAP", "OP_CAT",             # T oh os dir sc nc
        "OP_OVER", "OP_SWAP", 3, "OP_PICK",            # T oh os dir sc sc nc dir
        "OP_NOTIF", "OP_SWAP", "OP_ENDIF", "OP_CAT",   # T oh os dir sc pre_n
        5, "OP_PICK", "OP_SWAP", "OP_CAT", "OP_SHA256",  # T oh os dir sc nh'
        "OP_TOALTSTACK",
        "OP_FROMALTSTACK", "OP_FROMALTSTACK", "OP_FROMALTSTACK",  # T oh os dir sc nh' ns' ss8
        5, "OP_ROLL", "OP_TUCK", "OP_ADD",             # T oh dir sc nh' ns' os os'
        "OP_TOALTSTACK"] + PAD8 + [                    # T oh dir sc nh' ns' os8
        5, "OP_ROLL", "OP_SWAP", "OP_CAT",             # T dir sc nh' ns' oc
        3, "OP_ROLL", "OP_SWAP", 4, "OP_ROLL",         # T nh' ns' sc oc dir
        "OP_NOTIF", "OP_SWAP", "OP_ENDIF", "OP_CAT",   # T nh' ns' pre_o
        3, "OP_PICK", "OP_SWAP", "OP_CAT", "OP_SHA256",  # T nh' ns' oh'
        "OP_FROMALTSTACK", "OP_2SWAP",                 # T oh' os' nh' ns'
    ]


def check_old_root_from_alt():
    """[T oh os nh ns] -> [T nh ns]; requires os == input amount, oh == alt root."""
    return ["OP_2SWAP", SEL_IN_AMOUNT, "OP_TX", "OP_NUMEQUALVERIFY",
            "OP_FROMALTSTACK", "OP_EQUALVERIFY"]


def final_output():
    """[T nh ns] (alt: m) -> [1]; output 0 must be (ns, tree_spk(nh, m))."""
    return (["OP_ROT", "OP_DROP", "OP_SWAP", "OP_FROMALTSTACK"] + tree_spk() +
            ["OP_0", SEL_OUT_SINGLE, "OP_TX", "OP_ROT", "OP_EQUALVERIFY",
             "OP_NUMEQUAL"])


def exit_script(depth):
    """EXIT_1: witness (bottom..top) = [dir sc]*D leaf sig is_evict root m."""
    s = prologue()                                       # leaf sig is_evict
    s += ["OP_DUP", "OP_TOALTSTACK",                     # alt: m root is_evict
          "OP_IF",
          "OP_OVER", OFF_EVICT_AFTER, LEN_EVICT_AFTER, "OP_SUBSTR",
          "OP_CHECKLOCKTIMEVERIFY", "OP_DROP",
          "OP_OVER", OFF_EVICTOR_KEY, 32, "OP_SUBSTR",
          "OP_ELSE",
          "OP_OVER", OFF_OWNER_KEY, 32, "OP_SUBSTR",
          "OP_ENDIF",
          "OP_CHECKSIGVERIFY",                           # leaf
          "OP_SIZE", LEAF_LEN, "OP_EQUALVERIFY",
          1, SEL_OUT_SINGLE, "OP_TX",                    # leaf out_amt out_spk
          P2TR_PREFIX, 3, "OP_PICK", OFF_EXIT_KEY, 32, "OP_SUBSTR", "OP_CAT",
          "OP_EQUALVERIFY",                              # leaf out_amt
          "OP_OVER", 8, "OP_LEFT",                       # leaf out_amt leaf_amt
          "OP_FROMALTSTACK",                             # ... is_evict
          "OP_IF", "OP_NUMEQUALVERIFY",
          "OP_ELSE", "OP_LESSTHANOREQUAL", "OP_VERIFY", "OP_ENDIF",  # leaf
          ] + leaf_acc() + [                             # oh os
          NODE_PREFIX, "OP_ROT", "OP_ROT",               # T oh os
          lt.EMPTY_LEAF_HASH, "OP_0"]                    # T oh os nh ns
    for _ in range(depth):
        s += level()
    return s + check_old_root_from_alt() + final_output()


def join_script(depth, height, operator_key):
    """JOIN_h: insert a subtree at height h (path length depth-h).

    witness = [dir sc]*(depth-h) new_h new_s8 sig root m
    """
    e_h = lt.empty_node(height)[0]
    s = prologue()                                       # new_h new_s8 sig
    s += [operator_key, "OP_CHECKSIGVERIFY",             # new_h new_s8
          "OP_SIZE", 8, "OP_EQUALVERIFY",
          "OP_OVER", "OP_SIZE", 32, "OP_EQUALVERIFY", "OP_DROP",
          NODE_PREFIX, "OP_ROT", "OP_ROT",               # T new_h new_s8
          e_h, "OP_0", "OP_2SWAP"]                       # T E_h 0 new_h new_s8
    for _ in range(depth - height):
        s += level()
    return s + check_old_root_from_alt() + final_output()


def update_script(depth, operator_key):
    """UPDATE: witness = [dir sc]*D old_leaf new_leaf owner_sig op_sig root m"""
    s = prologue()                                       # old new osig opsig
    s += [operator_key, "OP_CHECKSIGVERIFY",             # old new osig
          2, "OP_PICK", OFF_OWNER_KEY, 32, "OP_SUBSTR", "OP_CHECKSIGVERIFY",  # old new
          "OP_SIZE", LEAF_LEN, "OP_EQUALVERIFY",
          "OP_SWAP", "OP_SIZE", LEAF_LEN, "OP_EQUALVERIFY",  # new old
          NODE_PREFIX, "OP_ROT", "OP_ROT",               # T new old
          ] + leaf_acc() + [                             # T new oh os
          "OP_ROT"] + leaf_acc()                         # T oh os nh ns
    for _ in range(depth):
        s += level()
    return s + check_old_root_from_alt() + final_output()


def claim_script(depth):
    """CLAIM: witness = [dir sc]*D (claim slot path, applied second)
                       [dir sc]*D (source leaf path, applied first)
                       src_leaf claim_leaf voucher_sig root m
    """
    s = [SEL_CURR_INPUT, "OP_TX", "OP_0", "OP_NUMEQUALVERIFY",
         "OP_2DUP"] + tree_spk() + [SEL_IN_SPK, "OP_TX", "OP_EQUALVERIFY",
         "OP_DUP", "OP_TOALTSTACK", "OP_SWAP", "OP_TOALTSTACK"]  # src claim vsig m ; alt: m root
    s += [3, "OP_PICK", 3, "OP_PICK", "OP_CAT", "OP_CAT"]        # src claim vsig (m||src||claim)
    s += tagged(VOUCHER_PREFIX)                                  # src claim vsig msg
    s += [3, "OP_PICK", OFF_OWNER_KEY, 32, "OP_SUBSTR",
          "OP_CHECKSIGFROMSTACK", "OP_VERIFY",                   # src claim
          "OP_SIZE", LEAF_LEN, "OP_EQUALVERIFY",
          "OP_SWAP", "OP_SIZE", LEAF_LEN, "OP_EQUALVERIFY", "OP_SWAP",  # src claim
          # new_src = le64(src.amt - claim.amt) || src[8:108] || le64(src.seq + 1)
          "OP_OVER", 8, "OP_LEFT", "OP_OVER", 8, "OP_LEFT", "OP_SUB"] + PAD8 + [
          2, "OP_PICK", OFF_EXIT_KEY, OFF_SEQ - OFF_EXIT_KEY, "OP_SUBSTR", "OP_CAT",
          2, "OP_PICK", OFF_SEQ, LEN_SEQ, "OP_SUBSTR", "OP_1ADD"] + PAD8 + ["OP_CAT",  # src claim new_src
          # park claim_leaf on the altstack underneath root: alt = m claim root
          "OP_FROMALTSTACK", "OP_ROT", "OP_TOALTSTACK", "OP_TOALTSTACK",  # src new_src
          NODE_PREFIX, "OP_ROT", "OP_ROT",                       # T src new_src
          "OP_SWAP"] + leaf_acc() + [                            # T new_src oh os
          "OP_ROT"] + leaf_acc()                                 # T oh os nh ns
    for _ in range(depth):
        s += level()
    s += check_old_root_from_alt()                               # T nh1 ns1 ; alt: m claim
    s += ["OP_FROMALTSTACK"] + leaf_acc() + [                    # T nh1 ns1 ch cs
          "OP_2SWAP", "OP_TOALTSTACK", "OP_TOALTSTACK",          # T ch cs ; alt: m ns1 nh1
          lt.EMPTY_LEAF_HASH, "OP_0", "OP_2SWAP"]                # T EMPTY 0 ch cs
    for _ in range(depth):
        s += level()
    s += ["OP_2SWAP",                                            # T nh2 ns2 oh2 os2
          "OP_FROMALTSTACK", "OP_ROT", "OP_EQUALVERIFY",         # T nh2 ns2 os2   (oh2 == nh1)
          "OP_FROMALTSTACK", "OP_NUMEQUALVERIFY"]                # T nh2 ns2       (os2 == ns1)
    return s + final_output()


def all_scripts(depth, operator_key, join_heights=(0,)):
    """Return ordered dict name -> token list for a tree's taptree."""
    out = {"EXIT_1": exit_script(depth)}
    for h in join_heights:
        out[f"JOIN_{h}"] = join_script(depth, h, operator_key)
    out["UPDATE"] = update_script(depth, operator_key)
    out["CLAIM"] = claim_script(depth)
    return out
