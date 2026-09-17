#!/usr/bin/env python3
"""LayerTree transition script templates (spec section 8).

Two profiles share every macro except how a proof level obtains its
direction bit and sibling:

* dense  ("D"): positions are operator-assigned; the witness supplies
  `dir sc` per level.
* sparse ("S"): positions are derived from the leaf (H_pos(owner_key||nonce));
  the witness supplies only `sc` per level, with the empty string standing
  for an empty sibling (compressed proof). The script derives each
  direction bit and computes the empty node for each level itself.

Each template is a list of assembler tokens (see script_sim.assemble):
strings are opcodes, ints are minimally-encoded numbers, bytes are data.
Run tools/test_scripts.py to execute them against the reference tree.
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
POS_PREFIX = lt.tag_prefix(lt.TAG_POS)
TAPTWEAK_PREFIX = lt.tag_prefix(lt.TAG_TAPTWEAK)
NUMS33 = lt.compress(lt.NUMS)
ZERO8 = bytes(8)
ZERO4 = bytes(4)
P2TR_PREFIX = bytes([0x51, 0x20])

# Leaf field offsets (spec section 5.2).
OFF_AMOUNT, LEN_AMOUNT = 0, 8
OFF_EXIT_KEY = 8
OFF_OWNER_KEY = 40
OFF_EVICTOR_KEY = 72
OFF_EVICT_AFTER, LEN_EVICT_AFTER = 104, 4
OFF_NONCE, LEN_NONCE = 108, 4
OFF_SEQ, LEN_SEQ = 112, 4
LEAF_LEN = lt.LEAF_LEN

CONST_NAMES = {
    LEAF_PREFIX: "<TAG_LEAF>", NODE_PREFIX: "<TAG_NODE>", STATE_PREFIX: "<TAG_STATE>",
    VOUCHER_PREFIX: "<TAG_VOUCHER>", POS_PREFIX: "<TAG_POS>",
    TAPTWEAK_PREFIX: "<TAG_TAPTWEAK>", NUMS33: "<NUMS>", ZERO8: "<ZERO8>",
    ZERO4: "<ZERO4>", P2TR_PREFIX: "<0x5120>", lt.EMPTY_LEAF_HASH: "<EMPTY_LEAF>",
    bytes([0x02]): "<0x02>",
}


def tagged(prefix):
    """[msg] -> [tagged_hash]"""
    return [prefix, "OP_SWAP", "OP_CAT", "OP_SHA256"]


PAD8 = [ZERO8, "OP_CAT", 8, "OP_LEFT"]  # [n] -> [le64(n)]   (n < 2^64)
PAD4 = [ZERO4, "OP_CAT", 4, "OP_LEFT"]  # [n] -> [le32(n)]   (n < 2^32)


def tree_spk():
    """[root_hash m] -> [scriptPubKey of the tree output committing to root_hash]

    Uses OP_EC_POINT_MUL ([point scalar], empty point = G), OP_EC_POINT_ADD
    and OP_EC_POINT_X_COORD from the EC ops draft BIP.
    """
    return (["OP_SWAP"] + tagged(STATE_PREFIX) +            # m t
            ["OP_0", "OP_SWAP", "OP_EC_POINT_MUL",           # m tG
             NUMS33, "OP_EC_POINT_ADD",                      # m P
             "OP_EC_POINT_X_COORD",                          # m x(P)
             "OP_TUCK", "OP_SWAP", "OP_CAT"] +               # x(P) (x(P)||m)
            tagged(TAPTWEAK_PREFIX) +                        # x(P) t2
            ["OP_0", "OP_SWAP", "OP_EC_POINT_MUL",           # x(P) t2G
             "OP_SWAP", bytes([0x02]), "OP_SWAP", "OP_CAT",  # t2G (02||x(P))
             "OP_EC_POINT_ADD", "OP_EC_POINT_X_COORD",       # x(Q)
             P2TR_PREFIX, "OP_SWAP", "OP_CAT"])              # spk


def leaf_acc():
    """[leaf] -> [H_leaf(leaf) amount]"""
    return ["OP_DUP", 8, "OP_LEFT", "OP_SWAP"] + tagged(LEAF_PREFIX) + ["OP_SWAP"]


def leaf_pos():
    """[leaf] -> [leaf pos_hash]   pos_hash = H_pos(owner_key || nonce)"""
    return ["OP_DUP", OFF_OWNER_KEY, 32, "OP_SUBSTR",
            "OP_OVER", OFF_NONCE, LEN_NONCE, "OP_SUBSTR", "OP_CAT"] + tagged(POS_PREFIX)


def prologue():
    """Common prologue: current input is #0; (root, m) match the input spk.

    Witness top: ... root m.  Leaves alt = [m root] (root on top) and
    removes root, m from the main stack.
    """
    return ([SEL_CURR_INPUT, "OP_TX", "OP_0", "OP_NUMEQUALVERIFY",
             "OP_2DUP"] + tree_spk() +
            [SEL_IN_SPK, "OP_TX", "OP_EQUALVERIFY",
             "OP_TOALTSTACK", "OP_TOALTSTACK"])


def level_body():
    """Shared per-level body. Stack: T oh os nh ns dir sc -> T oh' os' nh' ns'"""
    return [
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


def level_dense():
    """Dense profile. Stack: dir sc T oh os nh ns -> T oh' os' nh' ns'"""
    return [6, "OP_ROLL", 6, "OP_ROLL"] + level_body()


def level_sparse(k):
    """Sparse profile, level k. Stack: sc T oh os nh ns | ... pos E_k
    -> T oh' os' nh' ns' | ... pos E_{k+1}

    `sc` empty means "sibling is the empty node of this level".
    """
    return ([5, "OP_ROLL",                              # T oh os nh ns sc
             "OP_FROMALTSTACK",                         # ... sc E            | pos
             "OP_SWAP", "OP_SIZE", "OP_0NOTEQUAL",
             "OP_NOTIF", "OP_DROP", "OP_DUP", ZERO8, "OP_CAT", "OP_ENDIF",  # ... E sc
             "OP_SWAP", ZERO8, "OP_CAT", "OP_DUP", "OP_CAT",  # ... sc (E||0||E||0)
             6, "OP_PICK", "OP_SWAP", "OP_CAT", "OP_SHA256",  # ... sc E'
             "OP_FROMALTSTACK",                         # ... sc E' pos       |
             "OP_DUP", "OP_TOALTSTACK",                 #                     | pos
             "OP_SWAP", "OP_TOALTSTACK",                # ... sc pos          | pos E'
             k, "OP_DOWNSHIFT", bytes([1]), "OP_AND", "OP_0NOTEQUAL",  # ... sc dir
             "OP_SWAP"]                                 # T oh os nh ns dir sc
            + level_body())


def levels(profile, depth, height=0):
    out = []
    for k in range(height, depth):
        out += level_dense() if profile == "D" else level_sparse(k)
    return out


def sparse_setup():
    """Sparse: stack [leaf ...pos_hash on top] -> alt gets pos E_0. [pos] -> []"""
    return ["OP_TOALTSTACK", lt.EMPTY_LEAF_HASH, "OP_TOALTSTACK"]


def sparse_teardown():
    """Drop pos and E_D from the altstack (they sit above m / m r)."""
    return ["OP_FROMALTSTACK", "OP_DROP", "OP_FROMALTSTACK", "OP_DROP"]


def check_old_root_from_alt(profile):
    """[T oh os nh ns] -> [T nh ns]; requires os == input amount, oh == alt root."""
    return (["OP_2SWAP", SEL_IN_AMOUNT, "OP_TX", "OP_NUMEQUALVERIFY"] +
            (sparse_teardown() if profile == "S" else []) +
            ["OP_FROMALTSTACK", "OP_EQUALVERIFY"])


def check_prev_root_from_alt(profile):
    """[T oh os nh ns] | ... nh_prev ns_prev -> [T nh ns]; chained steps."""
    return (["OP_2SWAP"] + (sparse_teardown() if profile == "S" else []) +
            ["OP_FROMALTSTACK", "OP_NUMEQUALVERIFY",
             "OP_FROMALTSTACK", "OP_EQUALVERIFY"])


def final_output(depth):
    """[T nh ns] (alt: m) -> [1]; output 0 is (ns, tree_spk(nh, m)) unless nh == E_D."""
    e_d = lt.empty_node(depth)[0]
    return (["OP_ROT", "OP_DROP",
             "OP_OVER", e_d, "OP_EQUAL",
             "OP_IF", "OP_2DROP", "OP_FROMALTSTACK", "OP_DROP", "OP_1",
             "OP_ELSE", "OP_SWAP", "OP_FROMALTSTACK"] + tree_spk() +
            ["OP_0", SEL_OUT_SINGLE, "OP_TX", "OP_ROT", "OP_EQUALVERIFY",
             "OP_NUMEQUAL", "OP_ENDIF"])


def exit_block(profile, depth, out_index):
    """One exit. Stack: [path] leaf sig is_evict | ... -> T oh os nh ns (after levels)."""
    s = ["OP_DUP", "OP_TOALTSTACK",                     # | ... is_evict
         "OP_IF",
         "OP_OVER", OFF_EVICT_AFTER, LEN_EVICT_AFTER, "OP_SUBSTR",
         "OP_CHECKLOCKTIMEVERIFY", "OP_DROP",
         "OP_OVER", OFF_EVICTOR_KEY, 32, "OP_SUBSTR",
         "OP_ELSE",
         "OP_OVER", OFF_OWNER_KEY, 32, "OP_SUBSTR",
         "OP_ENDIF",
         "OP_CHECKSIGVERIFY",                           # leaf
         "OP_SIZE", LEAF_LEN, "OP_EQUALVERIFY",
         out_index, SEL_OUT_SINGLE, "OP_TX",            # leaf out_amt out_spk
         P2TR_PREFIX, 3, "OP_PICK", OFF_EXIT_KEY, 32, "OP_SUBSTR", "OP_CAT",
         "OP_EQUALVERIFY",                              # leaf out_amt
         "OP_OVER", 8, "OP_LEFT",                       # leaf out_amt leaf_amt
         "OP_FROMALTSTACK",                             # ... is_evict
         "OP_IF", "OP_NUMEQUALVERIFY",
         "OP_ELSE", "OP_LESSTHANOREQUAL", "OP_VERIFY", "OP_ENDIF"]  # leaf
    if profile == "S":
        s += leaf_pos() + sparse_setup()                # leaf              | pos E_0
    s += leaf_acc() + [                                 # oh os
         NODE_PREFIX, "OP_ROT", "OP_ROT",               # T oh os
         lt.EMPTY_LEAF_HASH, "OP_0"]                    # T oh os nh ns
    return s + levels(profile, depth)


def exit_script(depth, k=1, profile="D"):
    """EXIT_K: K sequential exits paying outputs 1..K.

    witness (bottom..top) = [block_K] ... [block_1] root m
    block_i = [dir sc]*D (dense) or [sc]*D (sparse), then leaf_i sig_i is_evict_i
    """
    s = prologue()
    s += exit_block(profile, depth, 1) + check_old_root_from_alt(profile)   # T nh ns | m
    for i in range(2, k + 1):
        s += ["OP_SWAP", "OP_TOALTSTACK", "OP_TOALTSTACK", "OP_DROP"]  # | m nh ns
        s += exit_block(profile, depth, i) + check_prev_root_from_alt(profile)
    return s + final_output(depth)


def join_script(depth, height, operator_key, profile="D"):
    """JOIN_h (dense: any height; sparse: height 0 only, single leaf).

    dense:  witness = [dir sc]*(D-h) new_hash new_sum8 sig root m
    sparse: witness = [sc]*D leaf sig root m
    """
    s = prologue()
    if profile == "D":
        e_h = lt.empty_node(height)[0]
        s += [operator_key, "OP_CHECKSIGVERIFY",         # new_h new_s8
              "OP_SIZE", 8, "OP_EQUALVERIFY",
              "OP_OVER", "OP_SIZE", 32, "OP_EQUALVERIFY", "OP_DROP",
              NODE_PREFIX, "OP_ROT", "OP_ROT",           # T new_h new_s8
              e_h, "OP_0", "OP_2SWAP"]                   # T E_h 0 new_h new_s8
        s += levels("D", depth, height)
    else:
        assert height == 0
        s += [operator_key, "OP_CHECKSIGVERIFY",         # leaf
              "OP_SIZE", LEAF_LEN, "OP_EQUALVERIFY"]
        s += leaf_pos() + sparse_setup()                 # leaf               | pos E_0
        s += leaf_acc() + [NODE_PREFIX, "OP_ROT", "OP_ROT",  # T nh ns
              lt.EMPTY_LEAF_HASH, "OP_0", "OP_2SWAP"]    # T E_0 0 nh ns
        s += levels("S", depth)
    return s + check_old_root_from_alt(profile) + final_output(depth)


def update_script(depth, operator_key, profile="D"):
    """UPDATE: witness = [path] old_leaf new_leaf owner_sig op_sig root m"""
    s = prologue()                                       # old new osig opsig | m r
    s += [operator_key, "OP_CHECKSIGVERIFY",             # old new osig
          2, "OP_PICK", OFF_OWNER_KEY, 32, "OP_SUBSTR", "OP_CHECKSIGVERIFY",  # old new
          "OP_SIZE", LEAF_LEN, "OP_EQUALVERIFY",
          "OP_SWAP", "OP_SIZE", LEAF_LEN, "OP_EQUALVERIFY"]  # new old
    if profile == "S":
        # both leaves must derive the same position
        s += leaf_pos() + ["OP_ROT"] + leaf_pos() + ["OP_ROT", "OP_EQUALVERIFY", "OP_SWAP"]  # new old  (pos on alt below)
        # stack now: new old ; re-derive pos for the alt from old
        s += leaf_pos() + sparse_setup()                 # new old            | pos E_0
    s += [NODE_PREFIX, "OP_ROT", "OP_ROT"]               # T new old
    s += leaf_acc() + [                                  # T new oh os
          "OP_ROT"] + leaf_acc()                         # T oh os nh ns
    s += levels(profile, depth)
    return s + check_old_root_from_alt(profile) + final_output(depth)


def claim_script(depth, profile="D"):
    """CLAIM: witness = [claim path] [source path] src_leaf claim_leaf voucher_sig root m"""
    s = [SEL_CURR_INPUT, "OP_TX", "OP_0", "OP_NUMEQUALVERIFY",
         "OP_2DUP"] + tree_spk() + [SEL_IN_SPK, "OP_TX", "OP_EQUALVERIFY",
         "OP_DUP", "OP_TOALTSTACK", "OP_SWAP", "OP_TOALTSTACK"]  # src claim vsig m | m r
    s += [3, "OP_PICK", 3, "OP_PICK", "OP_CAT", "OP_CAT"]        # src claim vsig (m||src||claim)
    s += tagged(VOUCHER_PREFIX)                                  # src claim vsig msg
    s += [3, "OP_PICK", OFF_OWNER_KEY, 32, "OP_SUBSTR",
          "OP_CHECKSIGFROMSTACK", "OP_VERIFY",                   # src claim
          "OP_SIZE", LEAF_LEN, "OP_EQUALVERIFY",
          "OP_SWAP", "OP_SIZE", LEAF_LEN, "OP_EQUALVERIFY", "OP_SWAP",  # src claim
          # new_src = le64(src.amt - claim.amt) || src[8:112] || le32(src.seq + 1)
          "OP_OVER", 8, "OP_LEFT", "OP_OVER", 8, "OP_LEFT", "OP_SUB"] + PAD8 + [
          2, "OP_PICK", OFF_EXIT_KEY, OFF_SEQ - OFF_EXIT_KEY, "OP_SUBSTR", "OP_CAT",
          2, "OP_PICK", OFF_SEQ, LEN_SEQ, "OP_SUBSTR", "OP_1ADD",
          "OP_SIZE", 4, "OP_LESSTHANOREQUAL", "OP_VERIFY"] + PAD4 + ["OP_CAT",  # src claim new_src
          # park claim_leaf on the altstack underneath root: alt = m claim root
          "OP_FROMALTSTACK", "OP_ROT", "OP_TOALTSTACK", "OP_TOALTSTACK"]  # src new_src
    if profile == "S":
        s += ["OP_OVER"] + leaf_pos() + ["OP_NIP"] + sparse_setup()  # src new_src | .. pos E_0
    s += [NODE_PREFIX, "OP_ROT", "OP_ROT",                       # T src new_src
          "OP_SWAP"] + leaf_acc() + [                            # T new_src oh os
          "OP_ROT"] + leaf_acc() + [                             # T oh os nh ns
          "OP_DUP", "OP_NOT", "OP_IF", "OP_SWAP", "OP_DROP",
          lt.EMPTY_LEAF_HASH, "OP_SWAP", "OP_ENDIF"]             # drained -> E_0
    s += levels(profile, depth)
    s += check_old_root_from_alt(profile)                        # T nh1 ns1 | m claim
    s += ["OP_FROMALTSTACK",                                     # T nh1 ns1 claim
          2, "OP_ROLL", 2, "OP_ROLL",                            # T claim nh1 ns1
          "OP_SWAP", "OP_TOALTSTACK", "OP_TOALTSTACK"]           # T claim | m nh1 ns1
    if profile == "S":
        s += leaf_pos() + sparse_setup()                         # T claim | m nh1 ns1 pos E_0
    s += leaf_acc() + [                                          # T ch cs
          lt.EMPTY_LEAF_HASH, "OP_0", "OP_2SWAP"]                # T E_0 0 ch cs
    s += levels(profile, depth)
    s += check_prev_root_from_alt(profile)                       # T nh2 ns2 | m
    return s + final_output(depth)


def all_scripts(depth, operator_key, join_heights=(0,), exit_ks=(1,), profile="D"):
    """Return ordered dict name -> token list for a tree's taptree."""
    out = {f"EXIT_{k}": exit_script(depth, k, profile) for k in exit_ks}
    for h in (join_heights if profile == "D" else (0,)):
        out[f"JOIN_{h}"] = join_script(depth, h, operator_key, profile)
    out["UPDATE"] = update_script(depth, operator_key, profile)
    out["CLAIM"] = claim_script(depth, profile)
    return out
