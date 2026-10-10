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
VOUCHER_H_PREFIX = lt.tag_prefix(lt.TAG_VOUCHER_H)
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
    VOUCHER_PREFIX: "<TAG_VOUCHER>", VOUCHER_H_PREFIX: "<TAG_VOUCHER_H>",
    POS_PREFIX: "<TAG_POS>",
    TAPTWEAK_PREFIX: "<TAG_TAPTWEAK>", NUMS33: "<NUMS>", ZERO8: "<ZERO8>",
    ZERO4: "<ZERO4>", P2TR_PREFIX: "<0x5120>", lt.EMPTY_LEAF_HASH: "<EMPTY_LEAF>",
    (1 << 64).to_bytes(9, "little"): "<2^64>", lt.enc64(0): "<ENC0>",
    bytes([0x02]): "<0x02>",
}


def tagged(prefix):
    """[msg] -> [tagged_hash]"""
    return [prefix, "OP_SWAP", "OP_CAT", "OP_SHA256"]


TWO64 = (1 << 64).to_bytes(9, "little")   # minimal encoding of 2^64
ENC0 = lt.enc64(0)                           # 9-byte encoding of a zero sum
PAD8 = [TWO64, "OP_ADD"]                     # [n] -> [enc64(n)] = le64(n)||01   (n < 2^64)
LE64 = PAD8 + [8, "OP_LEFT"]                 # [n] -> [le64(n)]  (leaf amount field)
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
        "OP_SIZE", 41, "OP_EQUALVERIFY",
        "OP_DUP", 32, 8, "OP_SUBSTR",                  # ... dir sc ss8   (raw le64, usable as a number)
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
    """Sparse profile, level k, "empty-element" compression.
    Stack: sc T oh os nh ns | ... pos E_k  ->  T oh' os' nh' ns' | ... pos E_{k+1}

    `sc` empty means "sibling is the empty node of this level".
    """
    return ([5, "OP_ROLL",                              # T oh os nh ns sc
             "OP_FROMALTSTACK",                         # ... sc E            | pos
             "OP_SWAP", "OP_SIZE", "OP_0NOTEQUAL",
             "OP_NOTIF", "OP_DROP", "OP_DUP", ENC0, "OP_CAT", "OP_ENDIF",  # ... E sc
             "OP_SWAP", ENC0, "OP_CAT", "OP_DUP", "OP_CAT",   # ... sc (E||0||E||0)
             6, "OP_PICK", "OP_SWAP", "OP_CAT", "OP_SHA256",  # ... sc E'
             "OP_FROMALTSTACK",                         # ... sc E' pos       |
             "OP_DUP", "OP_TOALTSTACK",                 #                     | pos
             "OP_SWAP", "OP_TOALTSTACK",                # ... sc pos          | pos E'
             k, "OP_DOWNSHIFT", bytes([1]), "OP_AND", "OP_0NOTEQUAL",  # ... sc dir
             "OP_SWAP"]                                 # T oh os nh ns dir sc
            + level_body())


def level_sparse_bitmap(k):
    """Sparse profile, level k, MS-SMT-style bitmap compression.
    Stack: [sc] T oh os nh ns | ... pos bm E_k  ->  T oh' os' nh' ns' | ... pos bm E_{k+1}

    Bit k of `bm` set means "sibling at level k is empty; no witness element".
    Otherwise the 40-byte sibling is the next witness element.
    """
    return (["OP_FROMALTSTACK", "OP_FROMALTSTACK", "OP_FROMALTSTACK",  # T oh os nh ns E bm pos
             "OP_DUP", k, "OP_DOWNSHIFT", bytes([1]), "OP_AND", "OP_0NOTEQUAL",  # ... E bm pos dir
             "OP_SWAP", "OP_TOALTSTACK",                             # ... E bm dir   | pos
             "OP_OVER", k, "OP_DOWNSHIFT", bytes([1]), "OP_AND", "OP_0NOTEQUAL",  # ... E bm dir empty?
             "OP_IF", 2, "OP_PICK", ENC0, "OP_CAT",                 # ... E bm dir (E||0)
             "OP_ELSE", 8, "OP_ROLL", "OP_ENDIF",                    # ... E bm dir sc
             3, "OP_ROLL", ENC0, "OP_CAT", "OP_DUP", "OP_CAT",      # ... bm dir sc (E||0||E||0)
             8, "OP_PICK", "OP_SWAP", "OP_CAT", "OP_SHA256",         # ... bm dir sc E'
             3, "OP_ROLL", "OP_TOALTSTACK", "OP_TOALTSTACK"]         # T oh os nh ns dir sc | pos bm E'
            + level_body())


# Module-level switch for the sparse profile's proof compression:
#   "empty"  : empty siblings are zero-length witness elements (default)
#   "bitmap" : MS-SMT-style bitmap; implemented for EXIT_K and JOIN_0 only,
#              as a measured comparison (see spec section 5.5).
COMPRESSION = {"S": "empty"}


def levels(profile, depth, height=0):
    out = []
    for k in range(height, depth):
        if profile == "D":
            out += level_dense()
        elif COMPRESSION["S"] == "bitmap":
            out += level_sparse_bitmap(k)
        else:
            out += level_sparse(k)
    return out


def sparse_setup():
    """Sparse: [pos_hash] -> [] ; alt gets pos [bm] E_0.

    With bitmap compression the witness supplies the bitmap as the element
    directly below the leaf; it is expected on top of the stack under pos.
    """
    if COMPRESSION["S"] == "bitmap":
        # stack: bm leaf pos -> leaf ; alt: pos bm E_0   (single-path scripts only)
        return ["OP_ROT", "OP_SWAP", "OP_TOALTSTACK", "OP_TOALTSTACK",
                lt.EMPTY_LEAF_HASH, "OP_TOALTSTACK"]
    return ["OP_TOALTSTACK", lt.EMPTY_LEAF_HASH, "OP_TOALTSTACK"]


def sparse_teardown():
    """Drop the sparse bookkeeping from the altstack (above m / m r)."""
    n = 3 if COMPRESSION["S"] == "bitmap" else 2
    return ["OP_FROMALTSTACK", "OP_DROP"] * n


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


def exit_block(profile, depth, out_index, exact=False):
    """One exit. Stack: [path] leaf sig is_evict | ... -> T oh os nh ns (after levels).

    exact=True is the EXIT_K^= variant (spec 7.2 rule 6): the payout must
    equal leaf.amount for owner exits as well as evictions, which trees
    hosting channel leaves use (Appendix C.6.1)."""
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
         "OP_FROMALTSTACK"]                             # ... is_evict
    if exact:
        s += ["OP_DROP", "OP_NUMEQUALVERIFY"]           # leaf   (exact for both)
    else:
        s += ["OP_IF", "OP_NUMEQUALVERIFY",
              "OP_ELSE", "OP_LESSTHANOREQUAL", "OP_VERIFY", "OP_ENDIF"]  # leaf
    if profile == "S":
        s += leaf_pos() + sparse_setup()                # leaf              | pos E_0
    s += leaf_acc() + [                                 # oh os
         NODE_PREFIX, "OP_ROT", "OP_ROT",               # T oh os
         lt.EMPTY_LEAF_HASH, "OP_0"]                    # T oh os nh ns
    return s + levels(profile, depth)


def exit_script(depth, k=1, profile="D", exact=False):
    """EXIT_K: K sequential exits paying outputs 1..K.

    witness (bottom..top) = [block_K] ... [block_1] root m
    block_i = [dir sc]*D (dense) or [sc]*D (sparse), then leaf_i sig_i is_evict_i
    exact=True selects the exact-payout variant (spec 7.2 rule 6).
    """
    s = prologue()
    s += exit_block(profile, depth, 1, exact) + check_old_root_from_alt(profile)   # T nh ns | m
    for i in range(2, k + 1):
        s += ["OP_SWAP", "OP_TOALTSTACK", "OP_TOALTSTACK", "OP_DROP"]  # | m nh ns
        s += exit_block(profile, depth, i, exact) + check_prev_root_from_alt(profile)
    return s + final_output(depth)


def join_block(profile, depth, height):
    """One join step. Stack (dense): [path] new_hash new_sum8 -> T oh os nh ns after levels.
    Stack (sparse, height 0): [sc*D] leaf -> T oh os nh ns after levels."""
    if profile == "D":
        e_h = lt.empty_node(height)[0]
        s = ["OP_SIZE", 8, "OP_EQUALVERIFY",
             "OP_OVER", "OP_SIZE", 32, "OP_EQUALVERIFY", "OP_DROP",
             NODE_PREFIX, "OP_ROT", "OP_ROT",           # T new_h new_s8
             e_h, "OP_0", "OP_2SWAP"]                   # T E_h 0 new_h new_s8
        return s + levels("D", depth, height)
    assert height == 0
    s = ["OP_SIZE", LEAF_LEN, "OP_EQUALVERIFY"]
    s += leaf_pos() + sparse_setup()                    # leaf               | pos E_0
    s += leaf_acc() + [NODE_PREFIX, "OP_ROT", "OP_ROT",  # T nh ns
          lt.EMPTY_LEAF_HASH, "OP_0", "OP_2SWAP"]       # T E_0 0 nh ns
    return s + levels("S", depth)


def join_script(depth, height, operator_key, profile="D", k=1):
    """JOIN_h (k = 1): graft one subtree of height h (dense) or insert one leaf
    (sparse, h = 0).  JOINK_k (h = 0): k sequential single-leaf insertions.

    witness (bottom..top) = [block_k] ... [block_1] sig root m
      dense block  = [dir sc]*(D-h) new_hash new_sum8
      sparse block = [sc]*D leaf
    """
    s = prologue()                                       # ... sig | m r
    s += [operator_key, "OP_CHECKSIGVERIFY"]
    s += join_block(profile, depth, height) + check_old_root_from_alt(profile)
    for _ in range(2, k + 1):
        s += ["OP_SWAP", "OP_TOALTSTACK", "OP_TOALTSTACK", "OP_DROP"]  # | m nh ns
        s += join_block(profile, depth, height) + check_prev_root_from_alt(profile)
    return s + final_output(depth)


def update_script(depth, operator_key, profile="D", exit_consent=False):
    """UPDATE: witness = [path] old_leaf new_leaf owner_sig op_sig root m

    exit_consent=True is the UPDATE^x variant (spec 7.4 rule 5): the witness
    carries one more signature directly above op_sig,
    [path] old_leaf new_leaf owner_sig op_sig exit_sig root m,
    which MUST be valid over the same transaction by old_leaf.exit_key.
    """
    s = prologue()                                       # old new osig opsig [xsig] | m r
    if exit_consent:
        s += [4, "OP_PICK", OFF_EXIT_KEY, 32, "OP_SUBSTR",
              "OP_CHECKSIGVERIFY"]                       # old new osig opsig
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


def claim_script(depth, profile="D", hashlock=False, exit_consent=False):
    """CLAIM (spec 7.5), or CLAIM^h (7.5.1) with hashlock=True.

    Witness: [claim path] [source path] src_leaf claim_leaf voucher_sig
    [preimage] [exit_sig] root m. With hashlock=True the witness carries a
    32-byte preimage below root and the signed message gains SHA256(preimage)
    as a fourth field under a separate tag. The script never compares the
    payment hash to a witness copy: it computes it from the preimage and
    feeds it to the message, so a wrong preimage fails as a bad signature.

    exit_consent=True is the CLAIM^x variant (spec 7.5.3): the element
    directly below root is one more signature, exit_sig, which MUST be valid
    over the transaction by src_leaf.exit_key, exactly as UPDATE^x (7.4 rule
    5) adds exit-key consent to UPDATE. Both flags together give CLAIM^hx.
    """
    return _carve_script(depth, profile, "hashlock" if hashlock else "voucher",
                         exit_consent)


def split_script(depth, profile="D"):
    """SPLIT (spec 7.5.2): CLAIM authorised by the owner's transaction
    signature instead of a voucher.

    Witness: [claim path] [source path] src_leaf new_leaf owner_sig root m.
    The steps, the seq increment, the drained-source rule and conservation
    are exactly CLAIM's; only the authorisation differs, which is why this
    shares CLAIM's body. It needs no OP_CHECKSIGFROMSTACK, so unlike CLAIM
    it is not barred from the MIN tier on opcode grounds.
    """
    return _carve_script(depth, profile, "owner")


def _carve_script(depth, profile, auth, exit_consent=False):
    """Shared body of CLAIM, CLAIM^h and SPLIT: carve a new leaf out of an
    existing one. `auth` selects the authorisation and nothing else.

    exit_consent=True (CLAIM^x, CLAIM^hx; spec 7.5.3) consumes one more
    witness element, exit_sig, directly below root, before anything else:
    it is lifted over the spare copy of m and checked against
    src_leaf.exit_key, so every stack depth below is as in the plain form.
    Eight bytes over the plain script in either form: UPDATE^x's seven plus
    the OP_SWAP that moves the signature above m.
    """
    assert auth in ("voucher", "hashlock", "owner")
    hashlock = auth == "hashlock"
    s = [SEL_CURR_INPUT, "OP_TX", "OP_0", "OP_NUMEQUALVERIFY",
         "OP_2DUP"] + tree_spk() + [SEL_IN_SPK, "OP_TX", "OP_EQUALVERIFY",
         "OP_DUP", "OP_TOALTSTACK", "OP_SWAP", "OP_TOALTSTACK"]  # src claim sig [pre] [xsig] m | m r
    if exit_consent:
        # src is 4 deep under xsig (5 with the preimage in between)
        s += ["OP_SWAP", 5 if hashlock else 4, "OP_PICK",
              OFF_EXIT_KEY, 32, "OP_SUBSTR", "OP_CHECKSIGVERIFY"]  # src claim sig [pre] m
    if auth == "owner":
        # the owner signs the transaction, so no message is rebuilt; drop the
        # spare copy of m and check the signature against src.owner_key
        s += ["OP_DROP",                                         # src claim sig
              2, "OP_PICK", OFF_OWNER_KEY, 32, "OP_SUBSTR",      # src claim sig owner_key
              "OP_CHECKSIGVERIFY"]                               # src claim
        return s + _carve_body(depth, profile)
    if hashlock:
        # park SHA256(preimage) on the altstack so every depth below is as in CLAIM
        s += ["OP_SWAP", "OP_SIZE", 32, "OP_EQUALVERIFY", "OP_SHA256",
              "OP_TOALTSTACK"]                                   # src claim vsig m | m r phash
    s += [3, "OP_PICK", 3, "OP_PICK", "OP_CAT", "OP_CAT"]        # src claim vsig (m||src||claim)
    if hashlock:
        s += ["OP_FROMALTSTACK", "OP_CAT"]                       # ... (m||src||claim||phash)
    s += tagged(VOUCHER_H_PREFIX if hashlock else VOUCHER_PREFIX)  # src claim vsig msg
    s += [3, "OP_PICK", OFF_OWNER_KEY, 32, "OP_SUBSTR",
          "OP_CHECKSIGFROMSTACK", "OP_VERIFY"]                   # src claim
    return s + _carve_body(depth, profile)


def _carve_body(depth, profile):
    """Everything after the authorisation check: both steps and FINAL.
    Stack on entry: src claim ; altstack: m r."""
    s = ["OP_SIZE", LEAF_LEN, "OP_EQUALVERIFY",
          "OP_SWAP", "OP_SIZE", LEAF_LEN, "OP_EQUALVERIFY", "OP_SWAP",  # src claim
          # new_src = le64(src.amt - claim.amt) || src[8:112] || le32(src.seq + 1)
          "OP_OVER", 8, "OP_LEFT", "OP_OVER", 8, "OP_LEFT", "OP_SUB"] + LE64 + [
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


# ---------------------------------------------------------------------------
# Channel-leaf HTLC outputs (Appendix C.4.1). These are not covenants and not
# part of a tree's taptree: they are the two leaves of an HTLC output in a
# settlement transaction, resolved by one ordinary transaction at spend time
# (C.4.2). They live here because spec 13.9 composes an HTLC_SUCCESS with a
# hash-locked voucher (7.5.1) over one payment hash, and the preimage
# discipline has to be identical on both legs for that to work.
# ---------------------------------------------------------------------------

def htlc_success_script(payment_hash, claim_key):
    """HTLC_SUCCESS (C.4.1). Witness: <claim_sig> <preimage>.

    The 32-byte size check is the same one CLAIM^h applies (7.5.1), which is
    what lets one preimage settle both legs of a swap.
    """
    assert len(payment_hash) == 32 and len(claim_key) == 32
    return ["OP_SIZE", 32, "OP_EQUALVERIFY", "OP_SHA256",
            payment_hash, "OP_EQUALVERIFY",
            claim_key, "OP_CHECKSIG"]


def htlc_timeout_script(cltv_expiry, claim_key):
    """HTLC_TIMEOUT (C.4.1). Witness: <claim_sig>."""
    assert len(claim_key) == 32
    return [cltv_expiry, "OP_CHECKLOCKTIMEVERIFY", "OP_DROP",
            claim_key, "OP_CHECKSIG"]


def all_scripts(depth, operator_key, join_heights=(0,), exit_ks=(1,), profile="D", join_ks=(2,)):
    """Return ordered dict name -> token list for a tree's taptree."""
    out = {f"EXIT_{k}": exit_script(depth, k, profile) for k in exit_ks}
    for h in (join_heights if profile == "D" else (0,)):
        out[f"JOIN_{h}"] = join_script(depth, h, operator_key, profile)
    for k in join_ks:
        out[f"JOINK_{k}"] = join_script(depth, 0, operator_key, profile, k)
    out["UPDATE"] = update_script(depth, operator_key, profile)
    out["CLAIM"] = claim_script(depth, profile)
    return out


# ---------------------------------------------------------------------------
# Minimal opcode inventory variant (spec section 4.5): BIP-342 base ops,
# BIP-441 numeric semantics, OP_CAT, OP_TX and BIP-449 OP_TWEAKADD only.
# No OP_SUBSTR/LEFT/RIGHT (fields arrive separately and are re-joined with
# OP_CAT under OP_SIZE checks), no padding opcode (PAD8 is `2^64 OP_ADD`),
# no EC point opcodes (OP_TWEAKADD does both taproot-style tweaks).
# ---------------------------------------------------------------------------
NUMS_X = lt.NUMS_X
CONST_NAMES[NUMS_X] = "<NUMS_X>"


def tree_spk_min():
    """[r m] -> [spk]   using OP_TWEAKADD ([tweak32 pubkey32] -> x(P + t*G))."""
    return (["OP_SWAP"] + tagged(STATE_PREFIX) +            # m t
            [NUMS_X, "OP_TWEAKADD",                          # m x(P)
             "OP_TUCK", "OP_SWAP", "OP_CAT"] +               # x(P) (x(P)||m)
            tagged(TAPTWEAK_PREFIX) +                        # x(P) t2
            ["OP_SWAP", "OP_TWEAKADD",                       # x(Q)
             P2TR_PREFIX, "OP_SWAP", "OP_CAT"])              # spk


def level_min():
    """Dense level with the sibling as two elements. Stack:
    dir sh ss8 T oh os nh ns  ->  T oh' os' nh' ns'
    """
    return [
        7, "OP_ROLL", 7, "OP_ROLL", 7, "OP_ROLL",      # T oh os nh ns dir sh ss8
        "OP_SIZE", 8, "OP_EQUALVERIFY",
        "OP_OVER", "OP_SIZE", 32, "OP_EQUALVERIFY", "OP_DROP",
        "OP_DUP", "OP_TOALTSTACK",                     # | ss8
        "OP_SWAP", "OP_OVER"] + PAD8 + ["OP_CAT",      # ... dir ss8 sc      (sc = sh||enc64(ss))
        "OP_SWAP",                                     # T oh os nh ns dir sc ss8
        3, "OP_ROLL", "OP_TUCK", "OP_ADD",             # T oh os nh dir sc ns ns'
        "OP_TOALTSTACK"] + PAD8 + [                    # T oh os nh dir sc ns9
        3, "OP_ROLL", "OP_SWAP", "OP_CAT",             # T oh os dir sc nc
        "OP_OVER", "OP_SWAP", 3, "OP_PICK",
        "OP_NOTIF", "OP_SWAP", "OP_ENDIF", "OP_CAT",   # T oh os dir sc pre_n
        5, "OP_PICK", "OP_SWAP", "OP_CAT", "OP_SHA256",
        "OP_TOALTSTACK",
        "OP_FROMALTSTACK", "OP_FROMALTSTACK", "OP_FROMALTSTACK",  # T oh os dir sc nh' ns' ss8
        5, "OP_ROLL", "OP_TUCK", "OP_ADD",             # T oh dir sc nh' ns' os os'
        "OP_TOALTSTACK"] + PAD8 + [
        5, "OP_ROLL", "OP_SWAP", "OP_CAT",             # T dir sc nh' ns' oc
        3, "OP_ROLL", "OP_SWAP", 4, "OP_ROLL",
        "OP_NOTIF", "OP_SWAP", "OP_ENDIF", "OP_CAT",
        3, "OP_PICK", "OP_SWAP", "OP_CAT", "OP_SHA256",
        "OP_FROMALTSTACK", "OP_2SWAP",
    ]


def exit_script_min(depth):
    """EXIT_1 with the minimal inventory.

    witness (bottom..top) = [dir sh ss8]*D  amount8 exit_key owner_key
                            evictor_key evict_after4 nonce4 seq4  sig is_evict  r m
    """
    e_d = lt.empty_node(depth)[0]
    s = [SEL_CURR_INPUT, "OP_TX", "OP_0", "OP_NUMEQUALVERIFY",
         "OP_2DUP"] + tree_spk_min() + [SEL_IN_SPK, "OP_TX", "OP_EQUALVERIFY",
         "OP_TOALTSTACK", "OP_TOALTSTACK"]                    # ...fields sig is_evict | m r
    s += ["OP_DUP", "OP_TOALTSTACK",                          # | m r is_evict
          "OP_IF",                                             # amt ek ok evk ea nonce seq sig
          3, "OP_PICK", "OP_CHECKLOCKTIMEVERIFY", "OP_DROP",
          4, "OP_PICK",                                        # ... sig evk
          "OP_ELSE",
          5, "OP_PICK",                                        # ... sig ok
          "OP_ENDIF",
          "OP_CHECKSIGVERIFY",                                 # amt ek ok evk ea nonce seq
          # field sizes
          "OP_SIZE", 4, "OP_EQUALVERIFY",                      # seq
          "OP_OVER", "OP_SIZE", 4, "OP_EQUALVERIFY", "OP_DROP",  # nonce
          2, "OP_PICK", "OP_SIZE", 4, "OP_EQUALVERIFY", "OP_DROP",  # ea
          3, "OP_PICK", "OP_SIZE", 32, "OP_EQUALVERIFY", "OP_DROP",  # evk
          4, "OP_PICK", "OP_SIZE", 32, "OP_EQUALVERIFY", "OP_DROP",  # ok
          5, "OP_PICK", "OP_SIZE", 32, "OP_EQUALVERIFY", "OP_DROP",  # ek
          6, "OP_PICK", "OP_SIZE", 8, "OP_EQUALVERIFY", "OP_DROP",   # amt
          # keep amount and exit_key, join the rest
          6, "OP_PICK", "OP_TOALTSTACK", 5, "OP_PICK", "OP_TOALTSTACK",  # | m r is_evict amt ek
          "OP_CAT", "OP_CAT", "OP_CAT", "OP_CAT", "OP_CAT", "OP_CAT",   # leaf
          ] + tagged(LEAF_PREFIX) + [                          # oh
          # payout output 1
          1, SEL_OUT_SINGLE, "OP_TX",                          # oh amt1 spk1
          P2TR_PREFIX, "OP_FROMALTSTACK", "OP_CAT", "OP_EQUALVERIFY",  # oh amt1     | m r is_evict amt
          "OP_FROMALTSTACK", "OP_FROMALTSTACK",                 # oh amt1 amt is_evict | m r
          ]
    # want (amt1 == amt) if evicting, else (amt1 <= amt)
    s += ["OP_IF", "OP_2DUP", "OP_NUMEQUALVERIFY",
          "OP_ELSE", "OP_2DUP", "OP_LESSTHANOREQUAL", "OP_VERIFY", "OP_ENDIF",  # oh amt1 amt
          "OP_NIP",                                             # oh os        | m r
          NODE_PREFIX, "OP_ROT", "OP_ROT",                      # T oh os
          lt.EMPTY_LEAF_HASH, "OP_0"]                           # T oh os nh ns
    for _ in range(depth):
        s += level_min()
    s += ["OP_2SWAP", SEL_IN_AMOUNT, "OP_TX", "OP_NUMEQUALVERIFY",
          "OP_FROMALTSTACK", "OP_EQUALVERIFY",                  # T nh ns | m
          "OP_ROT", "OP_DROP",
          "OP_OVER", e_d, "OP_EQUAL",
          "OP_IF", "OP_2DROP", "OP_FROMALTSTACK", "OP_DROP", "OP_1",
          "OP_ELSE", "OP_SWAP", "OP_FROMALTSTACK"] + tree_spk_min() + [
          "OP_0", SEL_OUT_SINGLE, "OP_TX", "OP_ROT", "OP_EQUALVERIFY",
          "OP_NUMEQUAL", "OP_ENDIF"]
    return s


# ---------------------------------------------------------------------------
# Shape-specialised multiproof: EVICT_SUBTREE_h (dense profile).
#
# Sweeps every leaf of an aligned subtree of height h whose leaves name
# OPERATOR_KEY as evictor and whose evict_after has passed. The subtree's
# 2^h - 1 internal hashes are computed once (a fixed post-order program),
# the new node is the constant E_h, and one operator signature covers the
# transaction. Positions that are already empty are supplied as an empty
# witness element and produce no payout. Payouts fill outputs 1.. in leaf
# order; the running output index lives on the altstack so OP_TX can take
# it dynamically.
# ---------------------------------------------------------------------------
def _leaf_step(operator_key):
    """[T ... leaf_or_empty] | .. m r idx  ->  [T ... oh os] | .. m r idx'"""
    return ["OP_SIZE", "OP_0NOTEQUAL",
            "OP_IF",
            "OP_SIZE", LEAF_LEN, "OP_EQUALVERIFY",
            "OP_DUP", OFF_EVICTOR_KEY, 32, "OP_SUBSTR", operator_key, "OP_EQUALVERIFY",
            "OP_DUP", OFF_EVICT_AFTER, LEN_EVICT_AFTER, "OP_SUBSTR",
            "OP_CHECKLOCKTIMEVERIFY", "OP_DROP",
            "OP_FROMALTSTACK", "OP_DUP", "OP_1ADD", "OP_TOALTSTACK",   # leaf idx
            SEL_OUT_SINGLE, "OP_TX",                                    # leaf amt spk
            P2TR_PREFIX, 3, "OP_PICK", OFF_EXIT_KEY, 32, "OP_SUBSTR", "OP_CAT",
            "OP_EQUALVERIFY",                                           # leaf amt
            "OP_OVER", 8, "OP_LEFT", "OP_NUMEQUALVERIFY",               # leaf   (exact payout)
            ] + leaf_acc() + [                                          # oh os
            "OP_ELSE",
            "OP_DROP", lt.EMPTY_LEAF_HASH, "OP_0",                      # E_0
            "OP_ENDIF"]


def _hash_step(t_depth):
    """[T ... lh ls rh rs] -> [T ... ph ps]; T is t_depth elements below rs."""
    return [2, "OP_PICK", "OP_OVER", "OP_ADD", "OP_TOALTSTACK",         # lh ls rh rs | ps
            ] + PAD8 + ["OP_CAT",                                       # lh ls rc
            "OP_SWAP"] + PAD8 + ["OP_ROT", "OP_SWAP", "OP_CAT",          # rc (lh||ls9)
            "OP_SWAP", "OP_CAT",                                        # pre
            t_depth - 3, "OP_PICK", "OP_SWAP", "OP_CAT", "OP_SHA256",    # ph
            "OP_FROMALTSTACK"]                                          # ph ps


def evict_subtree_script(depth, height, operator_key):
    """witness (bottom..top) = [dir sc]*(D-h)  leaf_{2^h-1} ... leaf_0  sig  r  m
    (leaf_0 on top; each leaf element is 116 bytes or empty)."""
    s = prologue() + [operator_key, "OP_CHECKSIGVERIFY"]     # ...leaves | m r
    s += ["OP_1", "OP_TOALTSTACK", NODE_PREFIX]               # T          | m r 1
    # fixed post-order program over a complete tree of height h; `d` tracks
    # the number of machine elements above T so PICK depths are static.
    d = [0]
    def gen(h):
        if h == 0:
            # the next leaf sits below T and the machine stack: roll it up
            s.extend([d[0] + 1, "OP_ROLL"])
            s.extend(_leaf_step(operator_key))
            d[0] += 2
        else:
            gen(h - 1); gen(h - 1)
            s.extend(_hash_step(d[0]))
            d[0] -= 2
    gen(height)                                              # T oh os   | m r idx
    s += ["OP_FROMALTSTACK", "OP_DROP",                      # drop idx
          lt.empty_node(height)[0], "OP_0"]                  # T oh os E_h 0
    s += levels("D", depth, height)
    return s + check_old_root_from_alt("D") + final_output(depth)
