#!/usr/bin/env python3
"""LayerTree scripts, MID tier (spec section 4.6).

Opcode set: BIP-342 tapscript with leaf-version-0xC0 semantics (CScriptNum
with 4-byte operands, 520-byte elements, MINIMALIF, MINIMALDATA policy) plus
OP_CAT (BIP-347), OP_TX (draft; assumed available in 0xC0),
OP_CHECKSIGFROMSTACK (BIP-348) and OP_TWEAKADD (BIP-449).

No OP_SUBSTR/LEFT/RIGHT, no bit or shift opcodes, no EC point opcodes and
no arbitrary-precision arithmetic. Consequences, all handled here:

* Leaves travel as seven separate witness elements and are re-joined with
  OP_CAT under OP_SIZE checks. The leaf *format* is unchanged.
* A script number x (0 <= x < 2^31) is converted to le32(x) with the PADZ
  gadget: the witness supplies a zero pad z and a filler w with
  z||w == 00000000 and size(x)+size(z) == 4. Sums keep the FULL tier's
  enc64 encoding, so the tree format is tier independent.
* Every sum in a MID tree MUST be below 2^31 satoshis.
* Payouts are exact (8-byte comparison with OP_TX); no fee-from-payout.
* Sparse positions: direction bits are witness items folded into an
  accumulator that must equal pos_lo, the first 4 bytes of H_pos, which the
  witness supplies split as pos_lo || pos_hi. The nonce is chosen so that
  pos_lo is a minimal positive CScriptNum (top bit clear, last byte
  non-zero). D <= 31.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import layertree_ref as lt  # noqa: E402
import layertree_scripts as F  # noqa: E402
from script_sim import SEL_CURR_INPUT, SEL_IN_AMOUNT, SEL_IN_SPK, SEL_OUT_SINGLE  # noqa: E402

ZERO4 = bytes(4)
ENC64_SUFFIX = bytes(4) + b"\x01"
MAX_SUM = (1 << 31) - 1
EXTRA_OPCODES = {"OP_CAT", "OP_TX", "OP_CHECKSIGFROMSTACK", "OP_TWEAKADD"}


def tagged(prefix):
    return [prefix, "OP_SWAP", "OP_CAT", "OP_SHA256"]


def padz():
    """[x z w] -> [le32(x)]"""
    return ["OP_OVER", "OP_SWAP", "OP_CAT", ZERO4, "OP_EQUALVERIFY",       # x z
            "OP_SIZE", "OP_ROT", "OP_SIZE", "OP_ROT", "OP_ADD", 4, "OP_NUMEQUALVERIFY",  # z x
            "OP_SWAP", "OP_CAT"]                                            # x||z


def enc64():
    return padz() + [ENC64_SUFFIX, "OP_CAT"]


def le64():
    return padz() + [ZERO4, "OP_CAT"]


def roll(n, times=1):
    return [n, "OP_ROLL"] * times


def prologue():
    return ([SEL_CURR_INPUT, "OP_TX", "OP_0", "OP_NUMEQUALVERIFY",
             "OP_2DUP"] + F.tree_spk_min() + [SEL_IN_SPK, "OP_TX", "OP_EQUALVERIFY",
             "OP_TOALTSTACK", "OP_TOALTSTACK"])


# ---------------------------------------------------------------- levels --
# Witness per level (bottom..top): zo wo zn wn dir sh ss zs ws
LEVEL_WITNESS = 9


def level(sparse):
    """[9 witness] T oh os nh ns -> T oh' os' nh' ns'
    sparse: alt .. plo acc pw E_k -> .. plo acc' pw' E_{k+1}"""
    s = roll(13, LEVEL_WITNESS)                         # T oh os nh ns zo wo zn wn dir sh ss zs ws
    if sparse:
        s += roll(3)                                    # ... dir ss zs ws sh
        s += ["OP_FROMALTSTACK",                        # ... sh E                 | plo acc pw
              "OP_SWAP", "OP_SIZE", "OP_0NOTEQUAL",
              "OP_NOTIF", "OP_DROP", "OP_DUP", "OP_ENDIF",   # ... E sh'
              "OP_SWAP", F.ENC0, "OP_CAT", "OP_DUP", "OP_CAT",
              F.NODE_PREFIX, "OP_SWAP", "OP_CAT", "OP_SHA256",  # ... sh' E'
              "OP_FROMALTSTACK", "OP_FROMALTSTACK",     # ... sh' E' pw acc        | plo
              7, "OP_PICK",                             # ... sh' E' pw acc dir   (dir: acc0 pw1 E'2 sh'3 ws4 zs5 ss6 dir7)
              "OP_IF", "OP_OVER", "OP_ADD", "OP_ENDIF",   # ... sh' E' pw acc'
              "OP_SWAP", "OP_DUP", "OP_ADD",              # ... sh' E' acc' pw'
              "OP_SWAP", "OP_TOALTSTACK", "OP_TOALTSTACK",  # ... sh' E'             | plo acc' pw'
              "OP_TOALTSTACK"]                            # ... dir ss zs ws sh'    | plo acc' pw' E'
        s += roll(3, 3)                                  # ... dir sh' ss zs ws
    # sibling: sc = sh || enc64(ss); keep ss
    s += [2, "OP_PICK", "OP_TOALTSTACK"] + enc64() + ["OP_CAT", "OP_FROMALTSTACK"]   # ... zo wo zn wn dir sc ss
    # new accumulator
    s += [7, "OP_PICK", "OP_OVER", "OP_ADD", "OP_TOALTSTACK"]     # | .. ns'
    s += roll(7) + roll(5, 2)                            # T oh os nh zo wo dir sc ss ns zn wn
    s += enc64()                                         # T oh os nh zo wo dir sc ss enc(ns)
    s += roll(6) + ["OP_SWAP", "OP_CAT"]                 # T oh os zo wo dir sc ss nc
    s += [2, "OP_PICK", "OP_SWAP", 4, "OP_PICK",
          "OP_NOTIF", "OP_SWAP", "OP_ENDIF", "OP_CAT",   # ... dir sc ss pre_n
          8, "OP_PICK", "OP_SWAP", "OP_CAT", "OP_SHA256", "OP_TOALTSTACK"]   # | .. ns' nh'
    # old accumulator
    s += [5, "OP_PICK", "OP_OVER", "OP_ADD", "OP_TOALTSTACK", "OP_DROP"]     # T oh os zo wo dir sc | .. ns' nh' os'
    s += roll(4) + roll(4, 2)                            # T oh dir sc os zo wo
    s += enc64()                                         # T oh dir sc enc(os)
    s += roll(3) + ["OP_SWAP", "OP_CAT", "OP_ROT",       # T sc oc dir
          "OP_NOTIF", "OP_SWAP", "OP_ENDIF", "OP_CAT",   # T pre_o
          "OP_OVER", "OP_SWAP", "OP_CAT", "OP_SHA256",   # T oh'
          "OP_FROMALTSTACK", "OP_FROMALTSTACK", "OP_FROMALTSTACK"]   # T oh' os' nh' ns'
    return s


def levels(sparse, depth, height=0):
    out = []
    for _ in range(height, depth):
        out += level(sparse)
    return out


# ----------------------------------------------------------- sparse pos --
def sparse_setup():
    """[ok nonce plo phi] -> [] ; alt += plo 0 1 E_0"""
    return (["OP_2SWAP", "OP_CAT"] + tagged(F.POS_PREFIX) +      # plo phi H
            ["OP_ROT", "OP_DUP", "OP_TOALTSTACK",                 # phi H plo        | plo
             "OP_SIZE", 4, "OP_EQUALVERIFY",
             "OP_ROT", "OP_CAT", "OP_EQUALVERIFY",                # (plo||phi == H)
             "OP_0", "OP_TOALTSTACK", "OP_1", "OP_TOALTSTACK",
             lt.EMPTY_LEAF_HASH, "OP_TOALTSTACK"])


def sparse_teardown():
    return ["OP_FROMALTSTACK", "OP_DROP", "OP_FROMALTSTACK", "OP_DROP",
            "OP_FROMALTSTACK", "OP_FROMALTSTACK", "OP_NUMEQUALVERIFY"]


# ----------------------------------------------------------- root checks --
def check_old(sparse):
    """[zi wi] T oh os nh ns | .. r [sparse] -> T nh ns | ..  (zi wi: pad for os)"""
    s = ["OP_2SWAP"] + roll(6, 2)                        # T nh ns oh os zi wi
    s += le64() + [SEL_IN_AMOUNT, "OP_TX", "OP_EQUALVERIFY"]   # T nh ns oh
    if sparse:
        s += sparse_teardown()
    return s + ["OP_FROMALTSTACK", "OP_EQUALVERIFY"]


def check_prev(sparse):
    s = ["OP_2SWAP"]
    if sparse:
        s += sparse_teardown()
    return s + ["OP_FROMALTSTACK", "OP_NUMEQUALVERIFY", "OP_FROMALTSTACK", "OP_EQUALVERIFY"]


def final(depth):
    """[zf wf] T nh ns | m -> [1]"""
    e_d = lt.empty_node(depth)[0]
    return (["OP_ROT", "OP_DROP",                        # zf wf nh ns
             "OP_OVER", e_d, "OP_EQUAL",
             "OP_IF", "OP_2DROP", "OP_2DROP", "OP_FROMALTSTACK", "OP_DROP", "OP_1",
             "OP_ELSE"] + roll(3, 2) + le64() +          # nh le64(ns)
            ["OP_SWAP", "OP_FROMALTSTACK"] + F.tree_spk_min() +   # le64(ns) spk'
            ["OP_0", SEL_OUT_SINGLE, "OP_TX", "OP_ROT", "OP_EQUALVERIFY", "OP_EQUAL",
             "OP_ENDIF"])


# ------------------------------------------------------------------ leaf --
# Leaf witness (bottom..top): amt8 ek ok evk ea nonce seq amt_num za wa
LEAF_WITNESS = 10
FIELD_SIZES = [(0, 4), (1, 4), (2, 4), (3, 32), (4, 32), (5, 32), (6, 8)]  # (depth after pads consumed, size)


def leaf_join():
    """[amt8 ek ok evk ea nonce seq amt_num za wa] -> [leaf] | .. amt_num"""
    s = [2, "OP_PICK", "OP_TOALTSTACK"]
    s += le64() + [7, "OP_PICK", "OP_EQUALVERIFY"]       # amt8 ek ok evk ea nonce seq
    for d, size in FIELD_SIZES:
        s += ([d, "OP_PICK"] if d else ["OP_DUP"]) + ["OP_SIZE", size, "OP_EQUALVERIFY", "OP_DROP"]
    return s + ["OP_CAT"] * 6


def exit_block_full(sparse, depth, out_index):
    """Complete exit block: -> T oh os nh ns after levels.
    Exit leaf witness: leaf(10) ea_num ze we sig is_evict  (ea_num: minimal evict_after)."""
    s = ["OP_DUP", "OP_TOALTSTACK", "OP_IF",
         3, "OP_PICK", "OP_CHECKLOCKTIMEVERIFY", "OP_DROP",      # ea_num is a minimal number
         10, "OP_PICK", "OP_CHECKSIGVERIFY"] + padz() + [        # leaf(10) le32(ea_num)
         6, "OP_PICK", "OP_EQUALVERIFY",                        # le32(ea_num) == ea field
         "OP_ELSE", 11, "OP_PICK", "OP_CHECKSIGVERIFY", "OP_2DROP", "OP_DROP",
         "OP_ENDIF",                                            # leaf(10)
         out_index, SEL_OUT_SINGLE, "OP_TX",
         F.P2TR_PREFIX, 11, "OP_PICK", "OP_CAT", "OP_EQUALVERIFY",
         10, "OP_PICK", "OP_EQUALVERIFY",
         "OP_FROMALTSTACK", "OP_DROP"]
    s += leaf_join() + tagged(F.LEAF_PREFIX) + ["OP_FROMALTSTACK"]   # oh os
    if sparse:
        s += roll(5, 4) + sparse_setup()                 # oh os   (ok nonce plo phi were below oh)
    s += [F.NODE_PREFIX, "OP_ROT", "OP_ROT", lt.EMPTY_LEAF_HASH, "OP_0"]
    return s + levels(sparse, depth)


def exit_script(depth, k=1, sparse=False):
    s = prologue()
    s += exit_block_full(sparse, depth, 1) + check_old(sparse)
    for i in range(2, k + 1):
        s += ["OP_SWAP", "OP_TOALTSTACK", "OP_TOALTSTACK", "OP_DROP"]
        s += exit_block_full(sparse, depth, i) + check_prev(sparse)
    return s + final(depth)


def join_block(sparse, depth, height):
    if not sparse:
        e_h = lt.empty_node(height)[0]
        s = ["OP_OVER", "OP_SIZE", 32, "OP_EQUALVERIFY", "OP_DROP",      # new_hash new_sum
             F.NODE_PREFIX, "OP_ROT", "OP_ROT", e_h, "OP_0", "OP_2SWAP"]  # T E_h 0 new_hash new_sum
        return s + levels(False, depth, height)
    s = leaf_join() + tagged(F.LEAF_PREFIX) + ["OP_FROMALTSTACK"]   # nh ns
    s += roll(5, 4) + sparse_setup()
    s += [F.NODE_PREFIX, "OP_ROT", "OP_ROT", lt.EMPTY_LEAF_HASH, "OP_0", "OP_2SWAP"]
    return s + levels(True, depth)


def join_script(depth, height, operator_key, sparse=False, k=1):
    s = prologue() + [operator_key, "OP_CHECKSIGVERIFY"]
    s += join_block(sparse, depth, height) + check_old(sparse)
    for _ in range(2, k + 1):
        s += ["OP_SWAP", "OP_TOALTSTACK", "OP_TOALTSTACK", "OP_DROP"]
        s += join_block(sparse, depth, height) + check_prev(sparse)
    return s + final(depth)


def update_script(depth, operator_key, sparse=False, exit_consent=False):
    """witness: [levels] [zi wi] [sparse: ok nonce plo phi] old(10) new(10) osig opsig r m

    exit_consent=True is the UPDATE^x variant (spec 7.4 rule 5): one more
    signature sits directly above opsig and MUST be valid over the same
    transaction by old.ek, the exit key of the old leaf.
    """
    s = prologue()
    if exit_consent:
        s += [21, "OP_PICK", "OP_CHECKSIGVERIFY"]        # old(10) new(10) osig opsig
    s += [operator_key, "OP_CHECKSIGVERIFY", 18, "OP_PICK", "OP_CHECKSIGVERIFY"]  # old(10) new(10)
    if sparse:
        s += [8, "OP_PICK", 19, "OP_PICK", "OP_EQUALVERIFY",   # new.ok == old.ok
              5, "OP_PICK", 16, "OP_PICK", "OP_EQUALVERIFY"]   # new.nonce == old.nonce
    s += leaf_join() + ["OP_TOALTSTACK"]                       # old(10)      | amt_new new_leaf
    s += leaf_join() + tagged(F.LEAF_PREFIX)                   # oh           | amt_new new_leaf amt_old
    s += ["OP_FROMALTSTACK", "OP_FROMALTSTACK", "OP_FROMALTSTACK",   # oh os new_leaf amt_new
          "OP_SWAP"] + tagged(F.LEAF_PREFIX) + ["OP_SWAP"]     # oh os nh ns
    if sparse:
        s += roll(7, 4) + sparse_setup()
    s += [F.NODE_PREFIX] + roll(4, 4)                          # T oh os nh ns
    s += levels(sparse, depth)
    return s + check_old(sparse) + final(depth)


def claim_script(depth, sparse=False, hashlock=False):
    """witness (bottom..top):
       [claim levels] [zi2 wi2? no] [sparse claim: ck cnonce cplo cphi]
       [src levels] [zi wi] [sparse src: sk snonce splo sphi]
       src(10) claim(10) seq_num zq0 wq0 zq1 wq1 zs2 ws2 vsig [preimage] r m
       ... final pad zf wf sits below the claim levels.

    hashlock=True is CLAIM^h (spec 7.5.1): a 32-byte preimage sits between
    vsig and r, and SHA256(preimage) is appended to the signed message under
    a separate tag. The preimage is hashed straight into the message, so a
    wrong one fails as a bad signature."""
    s = [SEL_CURR_INPUT, "OP_TX", "OP_0", "OP_NUMEQUALVERIFY",
         "OP_2DUP"] + F.tree_spk_min() + [SEL_IN_SPK, "OP_TX", "OP_EQUALVERIFY",
         "OP_DUP", "OP_TOALTSTACK", "OP_SWAP", "OP_TOALTSTACK"]       # ... extras(7) vsig [pre] m | m r
    if hashlock:
        # park SHA256(preimage) on the altstack: every pick depth below is as in CLAIM
        s += ["OP_SWAP", "OP_SIZE", 32, "OP_EQUALVERIFY", "OP_SHA256",
              "OP_TOALTSTACK"]                                        # ... vsig m | m r phash
    # voucher message m || src_leaf || claim_leaf [|| phash]
    s += [28, "OP_PICK"] * 7 + ["OP_CAT"] * 6                        # ... vsig m src_leaf
    s += [19, "OP_PICK"] * 7 + ["OP_CAT"] * 6                        # ... vsig m src_leaf claim_leaf
    s += [2, "OP_PICK", "OP_ROT", "OP_ROT", "OP_CAT", "OP_CAT"]      # ... vsig m (m||src||claim)
    if hashlock:
        s += ["OP_FROMALTSTACK", "OP_CAT"]                           # ... (m||src||claim||phash)
    s += tagged(F.VOUCHER_H_PREFIX if hashlock else F.VOUCHER_PREFIX)  # ... vsig m msg
    s += ["OP_ROT", "OP_SWAP",                                       # ... m vsig msg
          27, "OP_PICK",                                             # ... m vsig msg src.ok
          "OP_CHECKSIGFROMSTACK", "OP_VERIFY", "OP_DROP"]            # src(10) claim(10) extras(7)
    # seq consistency: le32(seq_num) == src.seq ; consumes zq0 wq0
    s += [20, "OP_PICK", 7, "OP_PICK"] + roll(7, 2) + padz() + ["OP_EQUALVERIFY"]   # extras -> seq_num zq1 wq1 zs2 ws2
    s += ["OP_TOALTSTACK"] * 5                                       # src(10) claim(10) | m r ws2 zs2 wq1 zq1 seq_num
    s += leaf_join() + ["OP_TOALTSTACK"]                             # src(10)           | .. seq_num amt_c claim_leaf
    s += [8, "OP_PICK"] * 5 + ["OP_CAT"] * 4 + ["OP_TOALTSTACK"]     # src(10)           | .. claim_leaf mid
    s += leaf_join() + tagged(F.LEAF_PREFIX)                         # oh                | .. mid amt_s
    s += ["OP_FROMALTSTACK", "OP_DUP", "OP_FROMALTSTACK",            # oh amt_s amt_s mid
          "OP_FROMALTSTACK", "OP_FROMALTSTACK"]                      # oh amt_s amt_s mid claim_leaf amt_c
    s += ["OP_FROMALTSTACK"] * 5                                     # ... amt_c seq_num zq1 wq1 zs2 ws2   | m r
    s += ["OP_FROMALTSTACK", 7, "OP_PICK", "OP_TOALTSTACK", 6, "OP_PICK", "OP_TOALTSTACK", "OP_TOALTSTACK"]  # | m claim_leaf amt_c r
    s += roll(6) + ["OP_DROP"]                                       # oh amt_s amt_s mid amt_c seq_num zq1 wq1 zs2 ws2
    s += roll(7) + roll(6) + ["OP_SUB",                              # oh amt_s mid seq_num zq1 wq1 zs2 ws2 amt_new
          "OP_DUP", "OP_0", "OP_GREATERTHANOREQUAL", "OP_VERIFY",
          "OP_DUP"] + roll(3, 2) + le64()                            # oh amt_s mid seq_num zq1 wq1 amt_new le64
    s += roll(4) + ["OP_1ADD"] + roll(4, 2) + padz()                 # oh amt_s mid amt_new le64 le32(seq+1)
    s += roll(3) + ["OP_SWAP", "OP_CAT", "OP_CAT"]                   # oh amt_s amt_new new_src
    s += tagged(F.LEAF_PREFIX) + ["OP_SWAP"]                         # oh os nh ns
    s += ["OP_DUP", "OP_NOT", "OP_IF", "OP_SWAP", "OP_DROP", lt.EMPTY_LEAF_HASH, "OP_SWAP", "OP_ENDIF"]
    if sparse:
        s += roll(7, 4) + sparse_setup()
    s += [F.NODE_PREFIX] + roll(4, 4)                                # T oh os nh ns
    s += levels(sparse, depth) + check_old(sparse)                   # T nh1 ns1        | m claim_leaf amt_c
    s += ["OP_FROMALTSTACK", "OP_FROMALTSTACK"] + tagged(F.LEAF_PREFIX) + ["OP_SWAP",   # T nh1 ns1 ch cs
          "OP_2SWAP", "OP_SWAP", "OP_TOALTSTACK", "OP_TOALTSTACK"]   # T ch cs          | m nh1 ns1
    if sparse:
        s += roll(6, 4) + sparse_setup()
    s += [lt.EMPTY_LEAF_HASH, "OP_0", "OP_2SWAP"]                    # T E_0 0 ch cs
    s += levels(sparse, depth) + check_prev(sparse)                  # T nh2 ns2
    return s + final(depth)


def all_scripts(depth, operator_key, sparse=False, join_heights=(0, 2), exit_ks=(1, 2), join_ks=(2,)):
    out = {f"EXIT_{k}": exit_script(depth, k, sparse) for k in exit_ks}
    for h in (join_heights if not sparse else (0,)):
        out[f"JOIN_{h}"] = join_script(depth, h, operator_key, sparse)
    for k in join_ks:
        out[f"JOINK_{k}"] = join_script(depth, 0, operator_key, sparse, k)
    out["UPDATE"] = update_script(depth, operator_key, sparse)
    out["CLAIM"] = claim_script(depth, sparse)
    return out


# ------------------------------------------------------- witness helpers --
def scriptnum(n):
    """CScriptNum minimal encoding for 0 <= n < 2^31."""
    assert 0 <= n <= MAX_SUM
    if n == 0:
        return b""
    b = n.to_bytes((n.bit_length() + 7) // 8, "little")
    if b[-1] & 0x80:
        b += b"\x00"
    return b


def pad(n):
    """(z, w) such that scriptnum(n)||z == le32(n) and z||w == 00000000."""
    k = 4 - len(scriptnum(n))
    return bytes(k), bytes(4 - k)


def w_leaf(leaf):
    b = leaf.serialize()
    z, w = pad(leaf.amount)
    return [b[0:8], b[8:40], b[40:72], b[72:104], b[104:108], b[108:112], b[112:116],
            scriptnum(leaf.amount), z, w]


def w_leaf_exit(leaf):
    """Exit witness: leaf(10) + minimal evict_after with its pad."""
    return w_leaf(leaf) + [scriptnum(leaf.evict_after), *pad(leaf.evict_after)]


def w_levels(path, old_node, new_node, sparse=False, height=0):
    """Witness items for all levels, bottom..top (level D-1 first).
    Needs the accumulator sums at each level to size the pads."""
    per_level = []
    oh, os_ = old_node
    nh, ns = new_node
    for k, (d, sib) in enumerate(path):
        sh = sib[0]
        if sparse and sib == lt.empty_node(height + k):
            sh = b""
        zs, ws = pad(sib[1]); zn, wn = pad(ns); zo, wo = pad(os_)
        per_level.append([zo, wo, zn, wn, b"\x01" if d else b"", sh, scriptnum(sib[1]), zs, ws])
        os_ += sib[1]; ns += sib[1]
    items = []
    for lv in reversed(per_level):
        items += lv
    return items


def w_pos(leaf):
    """Sparse position items: ok nonce plo phi (nonce must make plo minimal positive)."""
    h = lt.tagged_hash(lt.TAG_POS, leaf.owner_key + lt.le32(leaf.nonce))
    return [leaf.owner_key, lt.le32(leaf.nonce), h[:4], h[4:]]


def pos_ok(leaf):
    h = lt.tagged_hash(lt.TAG_POS, leaf.owner_key + lt.le32(leaf.nonce))
    return (h[3] & 0x80) == 0 and h[3] != 0


def position(leaf, depth):
    h = lt.tagged_hash(lt.TAG_POS, leaf.owner_key + lt.le32(leaf.nonce))
    return int.from_bytes(h[:4], "little") & ((1 << depth) - 1)
