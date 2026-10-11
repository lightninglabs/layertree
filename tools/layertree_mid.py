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
* Every sum in a MID tree MUST be below 2^31 satoshis. CScriptNum is
  sign-magnitude, so a four-byte number with its top bit set is negative
  and would pass PADZ as the le32 of a value in [2^31, 2^32): the
  NONNEG check (`OP_DUP OP_DUP OP_ABS OP_EQUALVERIFY`) rejects it wherever a
  witness-supplied number enters a sum (a sibling sum, a leaf amount, a
  joined sum). Everything else that is summed is derived from those.
* Payouts are exact (8-byte comparison with OP_TX); no fee-from-payout.
* Sparse positions: direction bits are witness items folded into an
  accumulator that must equal pos_lo, the first 4 bytes of H_pos, which the
  witness supplies split as pos_lo || pos_hi. The nonce is chosen so that
  pos_lo is a minimal positive CScriptNum (top bit clear, last byte
  non-zero) below 2^D, since the D-bit accumulator is compared with all
  32 bits of pos_lo: 25 <= D <= 31, and below D = 31 the nonce needs
  2^(31-D) times the grinding (pos_ok).
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


def nonneg():
    """[x] -> [x], failing unless x is a minimal non-negative CScriptNum.

    OP_ABS re-encodes |x| minimally, so the comparison also rejects a
    negative zero (00 00 00 80) and any non-minimal encoding whatever the
    MINIMALDATA policy; the check is consensus-grade."""
    return ["OP_DUP", "OP_DUP", "OP_ABS", "OP_EQUALVERIFY"]


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
    # sibling: sc = sh || enc64(ss); keep ss, which must be non-negative
    s += [2, "OP_PICK"] + nonneg() + ["OP_TOALTSTACK"] + enc64() + ["OP_CAT", "OP_FROMALTSTACK"]   # ... zo wo zn wn dir sc ss
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
    """[amt8 ek ok evk ea nonce seq amt_num za wa] -> [leaf] | .. amt_num

    amt_num must be a non-negative number: le64(amt_num) == amt8 alone
    would accept a leaf amount in [2^31, 2^32) as the negative number its
    le32 encodes."""
    s = [2, "OP_PICK"] + nonneg() + ["OP_TOALTSTACK"]
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
        s = nonneg() + ["OP_OVER", "OP_SIZE", 32, "OP_EQUALVERIFY", "OP_DROP",   # new_hash new_sum  (new_sum >= 0)
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


def claim_script(depth, tree_id, sparse=False, hashlock=False, dust_min=lt.DUST_MIN):
    """CLAIM (7.5) or CLAIM^h (7.5.1); see _carve_script. tree_id is the
    tree's 32-byte voucher binding (6.2), a constant of the script, and
    dust_min its DUST_MIN (7.5 rule 6)."""
    return _carve_script(depth, sparse, "hashlock" if hashlock else "voucher", tree_id, dust_min)


def split_script(depth, sparse=False, dust_min=lt.DUST_MIN):
    """SPLIT (7.5.2): CLAIM with the owner's transaction signature in place
    of a voucher. Needs no OP_CHECKSIGFROMSTACK."""
    return _carve_script(depth, sparse, "owner", dust_min=dust_min)


# The carve witness holds, below the authorisation element, src(10)
# claim(10) and thirteen extras: seq_num zq0 wq0 (the source seq and its
# pad), zq1 wq1 (the pad of seq + 1), zs2 ws2 (the pad of the new source
# amount), then sea zse wse cea zce wce (the minimal evict_after of the
# source and of the claim leaf, each with its pad; carve_rules). src.ok,
# the third field of the source block, therefore sits 31 deep under the
# authorisation element.
CARVE_EXTRAS = 13
CARVE_OWNER_DEPTH = 31


def voucher_auth(tree_id, hashlock=False):
    """The voucher check of CLAIM and CLAIM^h under 0xC0 numerics (spec 7.5
    rule 1, 7.5.1 rule 1), shared with the CCV tier's 0xC0 scripts:
    [src(10) claim(10) extras(13) vsig] -> [src(10) claim(10) extras(13)],
    with SHA256(preimage) parked on the altstack beforehand under hashlock.

    The message H_voucher(tree_id || src || claim) is assembled from the
    seven leaf fields of each leaf block by fourteen OP_PICKs; src's fields
    sit 33 deep under vsig, claim's 24 once src_leaf is on the stack, and
    src.ok (the third field) 32 deep once the message replaces the copies.
    """
    assert len(tree_id) == 32
    s = [33, "OP_PICK"] * 7 + ["OP_CAT"] * 6                        # ... vsig src_leaf
    s += [24, "OP_PICK"] * 7 + ["OP_CAT"] * 6                       # ... vsig src_leaf claim_leaf
    s += ["OP_CAT", tree_id, "OP_SWAP", "OP_CAT"]                   # ... vsig (tree_id||src||claim)
    if hashlock:
        s += ["OP_FROMALTSTACK", "OP_CAT"]                          # ... (tree_id||src||claim||phash)
    s += tagged(F.VOUCHER_H_PREFIX if hashlock else F.VOUCHER_PREFIX)   # ... vsig msg
    return s + [32, "OP_PICK", "OP_CHECKSIGFROMSTACK", "OP_VERIFY"]  # src(10) claim(10) extras(13)


def _carve_script(depth, sparse=False, auth="voucher", tree_id=None, dust_min=lt.DUST_MIN):
    """witness (bottom..top):
       zf wf [claim levels] [sparse claim: ck cnonce cplo cphi]
       zi wi [src levels] [sparse src: sk snonce splo sphi]
       src(10) claim(10) seq_num zq0 wq0 zq1 wq1 zs2 ws2
       sea zse wse cea zce wce vsig [preimage] r m
       zf wf pad the final sum, zi wi the input amount; pads sit below
       levels. sea and cea are the minimal evict_after of the source and of
       the claim leaf with their PADZ pads (carve_rules; w_carve_extras
       builds the thirteen extras).

    auth selects the authorisation and nothing else: "voucher" is CLAIM,
    "hashlock" is CLAIM^h (a 32-byte preimage sits between vsig and r and
    SHA256(preimage) is appended to the signed message under a separate
    tag), "owner" is SPLIT (the witness carries a transaction signature in
    place of the voucher)."""
    assert auth in ("voucher", "hashlock", "owner")
    hashlock = auth == "hashlock"
    s = prologue()                                                   # ... extras(7) vsig [pre] | m r
    if auth == "owner":
        # SPLIT (7.5.2): the owner signs the transaction, so no message is
        # rebuilt. src.ok sits CARVE_OWNER_DEPTH deep, since the witness
        # holds src(10) claim(10) extras(13) below the signature and the
        # owner key is the third field of the source leaf block.
        s += [CARVE_OWNER_DEPTH, "OP_PICK",                          # ... osig src.ok
              "OP_CHECKSIGVERIFY"]                                   # src(10) claim(10) extras(13)
    else:
        if hashlock:
            # park SHA256(preimage) on the altstack: every pick depth below is as in CLAIM
            s += ["OP_SIZE", 32, "OP_EQUALVERIFY", "OP_SHA256",
                  "OP_TOALTSTACK"]                                    # ... vsig | m r phash
        s += voucher_auth(tree_id, hashlock)                         # src(10) claim(10) extras(13)
    s += carve_source(depth, sparse, dust_min=dust_min) + check_old(sparse)   # T nh1 ns1  | m claim_leaf amt_c
    s += ["OP_FROMALTSTACK", "OP_FROMALTSTACK"]                      # T nh1 ns1 amt_c claim_leaf
    return s + carve_claim(depth, sparse) + final(depth)


def carve_rules(dust_min=lt.DUST_MIN):
    """The carve rules of spec 7.5 rules 5 and 6 under 0xC0 numerics:
    [src(10) claim(10) extras(7) sea zse wse cea zce wce] -> [src(10) claim(10) extras(7)].

    The claim leaf's evictor_key must equal the source's (the fourth field
    of each block, 19 and 30 deep), and its evict_after must be no later
    than the source's. The raw le32 fields are not numbers under
    CScriptNum, so, as EXIT_1 does for the lock time, the witness supplies
    each evict_after as a minimal number with a PADZ pad; the pad is
    checked against the leaf's own field and the two numbers compared.
    The claim amount is already a number (the block's amt_num, which
    LEAF_JOIN binds to the amount field), so the DUST_MIN floor of rule 6
    is one comparison against the constant."""
    return ([19, "OP_PICK", 30, "OP_PICK", "OP_EQUALVERIFY",         # claim.evk == src.evk
             2, "OP_PICK", "OP_TOALTSTACK"] + padz() +               # ... sea zse wse le32(cea)   | cea
            [16, "OP_PICK", "OP_EQUALVERIFY",                        # le32(cea) == claim.ea
             2, "OP_PICK", "OP_TOALTSTACK"] + padz() +               # ... le32(sea)               | cea sea
            [23, "OP_PICK", "OP_EQUALVERIFY",                        # le32(sea) == src.ea
             "OP_FROMALTSTACK", "OP_FROMALTSTACK",                   # ... sea cea
             "OP_GREATERTHANOREQUAL", "OP_VERIFY",                   # src(10) claim(10) extras(7)
             dust_min, 10, "OP_PICK", "OP_LESSTHANOREQUAL", "OP_VERIFY"])     # DUST_MIN <= claim.amt_num


def carve_source(depth, sparse=False, alt_r=True, dust_min=lt.DUST_MIN):
    """Step 1 of CLAIM, CLAIM^h and SPLIT, after the authorisation check.
    Stack on entry: src(10) claim(10) extras(13) ; altstack: .. m r.
    On exit: T oh os nh ns over the source path ; altstack: .. m claim_leaf amt_c r.
    Shared with the MIN tier, which differs only in how the result is bound
    to the transaction, and with the CCV tier's 0xC0 numerics, which carry
    no r (alt_r=False: the altstack holds .. claim_leaf amt_c on exit)."""
    s = carve_rules(dust_min)                                        # src(10) claim(10) extras(7)
    # seq consistency: le32(seq_num) == src.seq ; consumes zq0 wq0
    s += [20, "OP_PICK", 7, "OP_PICK"] + roll(7, 2) + padz() + ["OP_EQUALVERIFY"]   # extras -> seq_num zq1 wq1 zs2 ws2
    s += ["OP_TOALTSTACK"] * 5                                       # src(10) claim(10) | m r ws2 zs2 wq1 zq1 seq_num
    s += leaf_join() + ["OP_TOALTSTACK"]                             # src(10)           | .. seq_num amt_c claim_leaf
    s += [8, "OP_PICK"] * 5 + ["OP_CAT"] * 4 + ["OP_TOALTSTACK"]     # src(10)           | .. claim_leaf mid
    s += leaf_join() + tagged(F.LEAF_PREFIX)                         # oh                | .. mid amt_s
    s += ["OP_FROMALTSTACK", "OP_DUP", "OP_FROMALTSTACK",            # oh amt_s amt_s mid
          "OP_FROMALTSTACK", "OP_FROMALTSTACK"]                      # oh amt_s amt_s mid claim_leaf amt_c
    s += ["OP_FROMALTSTACK"] * 5                                     # ... amt_c seq_num zq1 wq1 zs2 ws2   | m r
    if alt_r:
        s += ["OP_FROMALTSTACK", 7, "OP_PICK", "OP_TOALTSTACK", 6, "OP_PICK", "OP_TOALTSTACK", "OP_TOALTSTACK"]  # | m claim_leaf amt_c r
    else:
        s += [6, "OP_PICK", "OP_TOALTSTACK", 5, "OP_PICK", "OP_TOALTSTACK"]   # | claim_leaf amt_c
    s += roll(6) + ["OP_DROP"]                                       # oh amt_s amt_s mid amt_c seq_num zq1 wq1 zs2 ws2
    s += roll(7) + roll(6) + ["OP_SUB",                              # oh amt_s mid seq_num zq1 wq1 zs2 ws2 amt_new
          "OP_DUP", "OP_0", "OP_GREATERTHANOREQUAL", "OP_VERIFY",
          "OP_DUP"] + roll(3, 2) + le64()                            # oh amt_s mid seq_num zq1 wq1 amt_new le64
    s += roll(4) + ["OP_1ADD"] + roll(4, 2) + padz()                 # oh amt_s mid amt_new le64 le32(seq+1)
    s += roll(3) + ["OP_SWAP", "OP_CAT", "OP_CAT"]                   # oh amt_s amt_new new_src
    s += tagged(F.LEAF_PREFIX) + ["OP_SWAP"]                         # oh os nh ns
    s += F.drain_rule(dust_min)                                      # drained -> E_0, else ns >= DUST_MIN
    if sparse:
        s += roll(7, 4) + sparse_setup()
    s += [F.NODE_PREFIX] + roll(4, 4)                                # T oh os nh ns
    return s + levels(sparse, depth)                                 # T oh os nh ns


def carve_claim(depth, sparse=False):
    """Step 2: the new leaf into an empty position, proven against the root
    step 1 produced. Stack on entry: T nh1 ns1 amt_c claim_leaf ;
    altstack: .. nh1 ns1 pushed here and consumed by check_prev.
    On exit: T nh2 ns2."""
    s = tagged(F.LEAF_PREFIX) + ["OP_SWAP",                          # T nh1 ns1 ch cs
         "OP_2SWAP", "OP_SWAP", "OP_TOALTSTACK", "OP_TOALTSTACK"]    # T ch cs          | .. nh1 ns1
    if sparse:
        s += roll(6, 4) + sparse_setup()
    s += [lt.EMPTY_LEAF_HASH, "OP_0", "OP_2SWAP"]                    # T E_0 0 ch cs
    return s + levels(sparse, depth) + check_prev(sparse)            # T nh2 ns2


# ------------------------------------------------- EVICT_SUBTREE_h (7.7) --
# The FULL tier's post-order fold (section 8.7) under MID numerics. FULL
# rolls each 116-byte leaf up from below T as it reaches it; a MID leaf is
# thirteen witness elements, and rolling them past the machine stack would
# cost about 40 bytes per leaf. The leaf steps are therefore hoisted into a
# pre-pass that runs at the top of the stack, in position order (so the
# payout outputs are numbered exactly as in FULL), and parks each node on
# the altstack as the pair (sc, s): sc = hash || enc64(sum), the 41-byte
# form a parent hashes, s the sum as a number. A leaf's enc64 is its own
# amount field plus 0x01, so leaves need no extra pad. The hash pass then
# pops the pairs back (last position first) and combines them in mirrored
# post-order; each internal node below the subtree root needs enc64 of its
# sum, which takes one PADZ pad pair from the witness.
#
# Slot witness, bottom..top: a present leaf is leaf(10) ea_num ze we 0x01;
# an empty position is one empty element (MINIMALIF makes the flag exact).
EVICT_SLOT_WITNESS = LEAF_WITNESS + 4
E0_SC = lt.EMPTY_LEAF_HASH + lt.enc64(0)


def _evict_pay():
    """The payout check of _evict_leaf_step: [leaf(10) idx] -> [leaf(10)],
    output idx pays exactly leaf.amount to P2TR(leaf.exit_key). The CCV
    tier's 0xC0 numerics substitute a CHECK_OUTPUT|DEDUCT call here."""
    return [SEL_OUT_SINGLE, "OP_TX",                                 # leaf(10) amt spk
            F.P2TR_PREFIX, 11, "OP_PICK", "OP_CAT", "OP_EQUALVERIFY",  # leaf(10) amt
            10, "OP_PICK", "OP_EQUALVERIFY"]                         # leaf(10)   (exact payout)


def _evict_leaf_step(operator_key, pay=None):
    """[.. slot idx] | .. -> [.. idx'] | .. s sc   (idx' = idx + 1 if paid)"""
    return (["OP_SWAP", "OP_IF",                                     # leaf(10) ea_num ze we idx
             "OP_TOALTSTACK",                                        # leaf(10) ea_num ze we       | .. idx
             2, "OP_PICK", "OP_CHECKLOCKTIMEVERIFY", "OP_DROP"] + padz() + [   # leaf(10) le32(ea_num)
             6, "OP_PICK", "OP_EQUALVERIFY",                         # leaf(10)   (ea field matches)
             6, "OP_PICK", operator_key, "OP_EQUALVERIFY",           # evictor_key == OPERATOR_KEY
             "OP_FROMALTSTACK", "OP_DUP", "OP_1ADD", "OP_TOALTSTACK"]  # leaf(10) idx      | .. idx'
            + (pay if pay is not None else _evict_pay()) +           # leaf(10)
            [9, "OP_PICK", b"\x01", "OP_CAT", "OP_TOALTSTACK"]       # leaf(10)          | .. idx' enc
            + leaf_join() + tagged(F.LEAF_PREFIX) +                  # lh                | .. idx' enc s
            ["OP_FROMALTSTACK", "OP_FROMALTSTACK",                   # lh s enc
             "OP_ROT", "OP_SWAP", "OP_CAT",                          # s sc
             "OP_FROMALTSTACK",                                      # s sc idx'
             "OP_ROT", "OP_TOALTSTACK", "OP_SWAP", "OP_TOALTSTACK",  # idx'              | .. s sc
             "OP_ELSE",                                              # idx
             "OP_0", "OP_TOALTSTACK", E0_SC, "OP_TOALTSTACK",        # idx               | .. 0 E_0.sc
             "OP_ENDIF"])


def _evict_hash_step(t, root):
    """[T .. Rsc Rs Lsc Ls] -> [T .. psc ps] (or [T .. ph ps] at the root).
    t is the number of elements above T on entry; a non-root step takes
    its pad pair [z w] from directly below T."""
    s = [2, "OP_ROLL", "OP_ADD", "OP_TOALTSTACK",                    # Rsc Lsc            | .. ps
         "OP_SWAP", "OP_CAT",                                        # (Lsc||Rsc)
         t - 3, "OP_PICK", "OP_SWAP", "OP_CAT", "OP_SHA256",          # ph
         "OP_FROMALTSTACK"]                                          # ph ps
    if not root:
        s += ["OP_DUP"] + roll(t + 1, 2) + enc64()                   # ph ps enc(ps)
        s += ["OP_ROT", "OP_SWAP", "OP_CAT", "OP_SWAP"]              # psc ps
    return s


def evict_subtree_pad_nodes(height):
    """The internal nodes below the subtree root, as (k, i) = (height,
    index within the subtree), in the order the hash pass consumes their
    pads. The witness lists the pad pairs in reverse of this order, so the
    first one consumed sits directly below T."""
    out = []

    def visit(k, i):
        if k == 0:
            return
        visit(k - 1, 2 * i + 1)
        visit(k - 1, 2 * i)
        if k < height:
            out.append((k, i))
    visit(height, 0)
    return out


def evict_subtree_script(depth, height, operator_key):
    """EVICT_SUBTREE_h (7.7, dense) in the MID tier.

    witness (bottom..top):
      zf wf zi wi [levels h..D-1] [pad pairs, see evict_subtree_pad_nodes]
      slot_{2^h-1} .. slot_0 sig r m
    """
    assert 1 <= height <= depth
    s = prologue() + [operator_key, "OP_CHECKSIGVERIFY"]             # .. slots            | m r
    s += evict_body(height, operator_key)                            # T oh os E_h 0       | m r
    s += levels(False, depth, height)
    return s + check_old(False) + final(depth)


def evict_body(height, operator_key, pay=None):
    """The tier-independent middle of EVICT_SUBTREE_h after the operator's
    signature: [.. slots] -> [T oh os E_h 0]. Shared with the CCV tier's
    0xC0 numerics, which pass their own payout check as `pay`."""
    s = ["OP_1"]                                                     # .. slots idx
    for _ in range(1 << height):
        s += _evict_leaf_step(operator_key, pay)                     # .. idx'             | .. (s sc)*
    s += ["OP_DROP", F.NODE_PREFIX]                                  # T
    t = [0]

    def gen(k, root):
        if k == 0:
            s.extend(["OP_FROMALTSTACK", "OP_FROMALTSTACK"])         # T .. sc s
            t[0] += 2
            return
        gen(k - 1, False)                                            # right child first
        gen(k - 1, False)
        s.extend(_evict_hash_step(t[0], root))
        t[0] -= 2
    gen(height, True)                                                # T oh os
    return s + [lt.empty_node(height)[0], "OP_0"]                    # T oh os E_h 0


def w_evict_slot(leaf):
    """Witness items for one EVICT_SUBTREE position (bottom..top)."""
    if leaf is None:
        return [b""]
    return w_leaf_exit(leaf) + [b"\x01"]


def w_evict_subtree(tree, depth, height, idx):
    """Everything EVICT_SUBTREE_h consumes below sig r m, for the subtree
    `idx` of `tree`: final pads, input-amount pads, levels, node pads and
    slots. Mirrors evict_subtree_script's witness layout."""
    base = idx << height
    t1 = lt.Tree(depth)
    t1.leaves = {p: l for p, l in tree.leaves.items() if not base <= p < base + (1 << height)}
    root, r1 = tree.root(), t1.root()
    old = tree.subtree(height, idx)
    path = tree.path(base, height=height)
    items = list(pad(r1[1])) + list(pad(root[1]))
    items += w_levels(path, old, lt.empty_node(height), False, height)
    for k, i in reversed(evict_subtree_pad_nodes(height)):
        items += list(pad(tree.subtree(k, (idx << (height - k)) + i)[1]))
    for j in reversed(range(1 << height)):
        items += w_evict_slot(tree.leaves.get(base + j))
    return items


# ------------------------------------------------------- REWRITE_h (7.9) --
# The FULL tier's cohort rewrite (section 8.9) under MID numerics, built
# like the MID sweep: a pre-pass at the top of the stack converts every
# position in order, and a hash pass folds the parked nodes in mirrored
# post-order. Each position carries two slots, the old element and the new
# element, each a MID leaf (ten elements plus a presence flag) or one empty
# element. The pre-pass reduces each slot to a canonical form built from
# the leaf's own fields before they are re-joined, so the rules of 7.9
# need no OP_SUBSTR: the old slot becomes [amt8 rest ek ok fin amt] and
# the new slot [amt8 rest amt], where rest is leaf[8:] (the six fields
# after the amount, CAT-joined), fin is whether seq == SEQ_FINAL, and amt
# is the amount as a number. "Unchanged" is rest and amt8 equal, "amount
# only" is rest equal; the owner key, exit key and amount field of the old
# leaf are then on hand for the signature and the payout.
#
# The TAG_LEAF prefix (L) and E_0's 41-byte node (Z) are hoisted: they
# travel with the output index as [idx L Z] on top of the remaining
# witness, parked on the altstack while a position's slots are reduced
# and picked by the node conversion. Inline they would cost about 210
# bytes per position. Each position parks (ns, nsc, os, osc) on the
# altstack; the hash pass pops them four at a time, old pair below new as
# the hash step leaves them, and runs the sweep's HASH_STEP twice per
# internal node, the old pair first, each taking its PADZ pad pair from
# directly below T.
#
# MID's SEQ_FINAL is 0x7FFFFFFF (spec 4.5): the raw seq field of the old
# leaf is compared with the constant as bytes.
#
# An unchanged position publishes its leaf once: the new slot may be the
# single one-byte element REWRITE_SAME (0x02 here, since 0x01 is a slot's
# presence flag), and the step then converts the old slot's node twice.
SEQ_FINAL = 0x7FFFFFFF
SEQ_FINAL_BYTES = lt.le32(SEQ_FINAL)
REWRITE_SLOT_WITNESS = LEAF_WITNESS + 1
REWRITE_SAME = b"\x02"


def _leaf_join_old():
    """[amt8 ek ok evk ea nonce seq amt_num za wa] -> [amt8 rest ek ok fin amt]

    LEAF_JOIN with the fields the rewrite rules need kept beside the
    re-joined rest: copies of ek and ok, fin = (seq == SEQ_FINAL) and the
    amount as a (non-negative) number. rest is ek||ok||evk||ea||nonce||seq,
    so amt8||rest is the leaf."""
    s = [2, "OP_PICK"] + nonneg() + ["OP_TOALTSTACK"]                          # ... amt_num za wa    | amt
    s += le64() + [7, "OP_PICK", "OP_EQUALVERIFY"]                             # amt8 ek ok evk ea nonce seq
    for d, size in FIELD_SIZES:
        s += ([d, "OP_PICK"] if d else ["OP_DUP"]) + ["OP_SIZE", size, "OP_EQUALVERIFY", "OP_DROP"]
    s += ["OP_DUP", SEQ_FINAL_BYTES, "OP_EQUAL", "OP_TOALTSTACK"]              # | amt fin
    s += [5, "OP_PICK", 5, "OP_PICK", "OP_TOALTSTACK", "OP_TOALTSTACK"]        # | amt fin ok ek
    s += ["OP_CAT"] * 5                                                        # amt8 rest
    return s + ["OP_FROMALTSTACK"] * 4                                         # amt8 rest ek ok fin amt


def _leaf_join_new():
    """[amt8 ek ok evk ea nonce seq amt_num za wa] -> [amt8 rest amt]"""
    s = [2, "OP_PICK"] + nonneg() + ["OP_TOALTSTACK"]
    s += le64() + [7, "OP_PICK", "OP_EQUALVERIFY"]
    for d, size in FIELD_SIZES:
        s += ([d, "OP_PICK"] if d else ["OP_DUP"]) + ["OP_SIZE", size, "OP_EQUALVERIFY", "OP_DROP"]
    return s + ["OP_CAT"] * 5 + ["OP_FROMALTSTACK"]                            # amt8 rest amt


def _rewrite_owner_auth(exit_consent):
    """[sig C_new(3) C_old(6)] -> [C_new(3) C_old(6)]: the next witness element,
    nine deep, is a signature by old.ok; under ^x one more by old.ek."""
    s = [9, "OP_ROLL", 3, "OP_PICK", "OP_CHECKSIGVERIFY"]
    if exit_consent:
        s += [9, "OP_ROLL", 4, "OP_PICK", "OP_CHECKSIGVERIFY"]
    return s


def _rewrite_pay():
    """[C_new(3) C_old(6)] | .. idx -> [C_new(3) C_old(6)] | .. idx+1: output idx
    pays exactly old.amt8 to P2TR(old.ek) (7.9 rule 5)."""
    return ["OP_FROMALTSTACK", "OP_DUP", "OP_1ADD", "OP_TOALTSTACK",           # .. idx
            SEL_OUT_SINGLE, "OP_TX",                                           # .. amt spk
            F.P2TR_PREFIX, 6, "OP_PICK", "OP_CAT", "OP_EQUALVERIFY",           # .. amt
            6, "OP_PICK", "OP_EQUALVERIFY"]                                    # C_new C_old


def _rewrite_conv():
    """[idx L Z amt8 rest] -> [idx L Z sc]: a leaf's 41-byte node
    H_leaf(amt8||rest) || amt8 || 01, or Z for the empty element."""
    return ["OP_SIZE", "OP_0NOTEQUAL", "OP_IF",
            "OP_2DUP", "OP_CAT",                                               # idx L Z amt8 rest leaf
            4, "OP_PICK", "OP_SWAP", "OP_CAT", "OP_SHA256",                    # idx L Z amt8 rest lh
            "OP_NIP", "OP_SWAP", b"\x01", "OP_CAT", "OP_CAT",                  # idx L Z sc
            "OP_ELSE", "OP_2DROP", "OP_DUP",                                   # idx L Z Z
            "OP_ENDIF"]


def _rewrite_step(exit_consent):
    """One position of the pre-pass:
    [.. {xsig} {sig} new_slot old_slot idx L Z] | .. -> [.. idx' L Z] | .. ns nsc os osc

    A slot is leaf(10) 0x01 or one empty element, and the new slot may be
    the one-byte marker REWRITE_SAME, in which case the old slot's node is
    parked twice and nothing else happens (7.9: unchanged). Otherwise the
    old slot is reduced first, parked, then the new slot; with both
    canonical forms on the stack (new below old) the step applies 7.9
    rules 3 and 5 and converts both to nodes. Depths in the decision
    block, from the top: amt_o 0, fin 1, ok 2, ek 3, rest_o 4, amt8_o 5,
    amt_n 6, rest_n 7, amt8_n 8, and the next witness element 9."""
    s = ["OP_TOALTSTACK"] * 3                                                  # .. new_slot old_slot   | .. Z L idx
    s += ["OP_IF"] + _leaf_join_old() + ["OP_ELSE"] + ["OP_0"] * 6 + ["OP_ENDIF"]   # .. new_slot C_old(6)
    s += [6, "OP_PICK", REWRITE_SAME, "OP_EQUAL", "OP_IF",                     # -- the marker: new = old --
          6, "OP_ROLL", "OP_DROP",                                             # .. C_old(6)
          "OP_TOALTSTACK", "OP_2DROP", "OP_DROP", "OP_FROMALTSTACK",           # .. amt8 rest amt
          "OP_FROMALTSTACK", "OP_FROMALTSTACK", "OP_FROMALTSTACK"]             # .. amt8 rest amt idx L Z
    s += roll(5, 2) + _rewrite_conv()                                          # .. amt idx L Z sc
    s += roll(4) + ["OP_2DUP"] + ["OP_TOALTSTACK"] * 4                         # .. idx L Z              | .. ns nsc os osc
    s += ["OP_ELSE"]                                                           # -- a leaf or empty --
    s += ["OP_TOALTSTACK"] * 6                                                 # .. new_slot            | .. Z L idx C_old
    s += ["OP_IF"] + _leaf_join_new() + ["OP_ELSE"] + ["OP_0"] * 3 + ["OP_ENDIF"]   # .. C_new(3)
    s += ["OP_FROMALTSTACK"] * 6                                               # .. C_new(3) C_old(6)   | .. Z L idx
    s += [4, "OP_PICK", 8, "OP_PICK", "OP_EQUAL",                              # same_rest
          6, "OP_PICK", 10, "OP_PICK", "OP_EQUAL",                             # same_amt8
          "OP_BOOLAND", "OP_NOTIF",                                            # -- changed --
          4, "OP_PICK", "OP_SIZE", "OP_NIP", "OP_0NOTEQUAL", "OP_IF",          # -- old is a leaf --
          7, "OP_PICK", "OP_SIZE", "OP_NIP", "OP_0NOTEQUAL", "OP_IF",          # -- new is a leaf: rewrite --
          4, "OP_PICK", 8, "OP_PICK", "OP_EQUAL",                              # same_rest
          "OP_OVER", 8, "OP_PICK", "OP_LESSTHANOREQUAL", "OP_BOOLAND",         # .. and amt_o <= amt_n
          2, "OP_PICK", "OP_NOT", "OP_BOOLAND",                                # .. and seq != SEQ_FINAL
          "OP_NOTIF"] + _rewrite_owner_auth(exit_consent) + ["OP_ENDIF",
          "OP_ELSE"] + _rewrite_owner_auth(exit_consent) + _rewrite_pay() + [  # -- new is empty: exit --
          "OP_ENDIF",
          "OP_ENDIF",                                                          # (old empty: a join, operator only)
          "OP_ENDIF"]                                                          # (unchanged)
    s += ["OP_TOALTSTACK", "OP_2DROP", "OP_DROP", "OP_FROMALTSTACK"]           # .. amt8_n rest_n amt_n amt8_o rest_o amt_o
    s += ["OP_FROMALTSTACK"] * 3                                               # .. amt8_n rest_n amt_n amt8_o rest_o amt_o idx L Z
    s += roll(8, 2) + _rewrite_conv()                                          # .. amt_n amt8_o rest_o amt_o idx L Z nsc
    s += roll(7) + ["OP_TOALTSTACK", "OP_TOALTSTACK"]                          # .. amt8_o rest_o amt_o idx L Z   | .. ns nsc
    s += roll(5, 2) + _rewrite_conv()                                          # .. amt_o idx L Z osc
    s += roll(4) + ["OP_TOALTSTACK", "OP_TOALTSTACK"]                          # .. idx L Z                       | .. ns nsc os osc
    return s + ["OP_ENDIF"]


def _rewrite_hash_step2(t, root):
    """[T .. Rosc Ros Rnsc Rns Losc Los Lnsc Lns] -> [T .. posc pos pnsc pns]
    (or [T .. poh pos pnh pns] at the root): the sweep's HASH_STEP on the
    old pair, then on the new pair, with FULL's HASH_STEP2 shuffles. The
    leaf pops and the step's output share one layout (old pair below new),
    so the step composes at every height. t is the number of elements
    above T on entry; each non-root step takes a pad pair from directly
    below T, so the old node's pair sits above the new node's in the
    witness."""
    return (["OP_2SWAP"] + roll(7, 2) + ["OP_2SWAP"] +                         # Rnsc Rns Lnsc Lns Rosc Ros Losc Los
            _evict_hash_step(t, root) +                                        # Rnsc Rns Lnsc Lns posc pos
            ["OP_2SWAP"] + roll(5, 2) + ["OP_2SWAP"] +                         # posc pos Rnsc Rns Lnsc Lns
            _evict_hash_step(t - 2, root))                                     # posc pos pnsc pns


def rewrite_script(depth, height, operator_key, exit_consent=False):
    """REWRITE_h (7.9, dense) in the MID tier, or REWRITE_h^x with exit_consent.

    witness (bottom..top):
      zf wf zi wi [levels h..D-1] [pad pairs: for each internal node in
      reverse consumption order, the new sum's pair then the old sum's]
      block_{2^h-1} .. block_0 sig_op r m
      block_i = [xsig_i] [sig_i] new_slot_i old_slot_i, a slot being leaf(10)
      0x01 or one empty element, and new_slot_i may be the one-byte marker
      REWRITE_SAME for an unchanged position; sig_i only where 7.9 rule 3
      requires it, xsig_i only under ^x and only where sig_i is present.
    """
    assert 1 <= height <= depth
    s = prologue() + [operator_key, "OP_CHECKSIGVERIFY"]                       # .. blocks            | m r
    s += ["OP_1", F.LEAF_PREFIX, E0_SC]                                        # .. blocks idx L Z
    for _ in range(1 << height):
        s += _rewrite_step(exit_consent)                                       # .. idx' L Z          | m r (ns nsc os osc)*
    s += ["OP_2DROP", "OP_DROP", F.NODE_PREFIX]                                # T
    t = [0]

    def gen(k, root):
        if k == 0:
            s.extend(["OP_FROMALTSTACK"] * 4)                                  # T .. osc os nsc ns
            t[0] += 4
            return
        gen(k - 1, False)                                                      # right child first
        gen(k - 1, False)
        s.extend(_rewrite_hash_step2(t[0], root))
        t[0] -= 4
    gen(height, True)                                                          # T oh os nh ns
    s += levels(False, depth, height)
    return s + check_old(False) + final(depth)


def w_rewrite_slot(leaf):
    """Witness items for one REWRITE slot (bottom..top)."""
    if leaf is None:
        return [b""]
    return w_leaf(leaf) + [b"\x01"]


def w_rewrite(tree, depth, height, idx, new, sigs, marker=True):
    """Everything MID REWRITE_h consumes below sig_op r m, for the subtree
    `idx` of `tree`: final pads, input-amount pads, levels, node pads and
    the position blocks. `new` maps offset -> Leaf or None (the new
    element of every position); `sigs` maps offset -> [sig] or [sig, xsig]
    for the positions that carry one. With marker, an unchanged leaf's new
    slot is the one-byte REWRITE_SAME; without it, a second copy of the
    leaf. Mirrors rewrite_script's layout."""
    n = 1 << height
    base = idx << height
    t1 = lt.Tree(depth)
    t1.leaves = {p: l for p, l in tree.leaves.items() if not base <= p < base + n}
    for i, lf in new.items():
        if lf is not None:
            t1.leaves[base + i] = lf
    root, r1 = tree.root(), t1.root()
    old_node, new_node = tree.subtree(height, idx), t1.subtree(height, idx)
    path = tree.path(base, height=height)
    items = list(pad(r1[1])) + list(pad(root[1]))
    items += w_levels(path, old_node, new_node, False, height)
    for k, i in reversed(evict_subtree_pad_nodes(height)):
        sub = (idx << (height - k)) + i
        items += list(pad(t1.subtree(k, sub)[1])) + list(pad(tree.subtree(k, sub)[1]))
    for j in reversed(range(n)):
        items += list(reversed(sigs.get(j, [])))                               # xsig below sig
        o, nw = tree.leaves.get(base + j), new.get(j)
        if marker and o is not None and nw is not None and o.serialize() == nw.serialize():
            items.append(REWRITE_SAME)
        else:
            items += w_rewrite_slot(nw)
        items += w_rewrite_slot(o)
    return items


def all_scripts(depth, operator_key, sparse=False, join_heights=(0, 2), exit_ks=(1, 2), join_ks=(2,),
                tree_id=None, dust_min=lt.DUST_MIN):
    """The reference script set (spec 6.2) under MID; tree_id is the
    tree's voucher binding, a constant of CLAIM, and dust_min its DUST_MIN."""
    out = {f"EXIT_{k}": exit_script(depth, k, sparse) for k in exit_ks}
    for h in (join_heights if not sparse else (0,)):
        out[f"JOIN_{h}"] = join_script(depth, h, operator_key, sparse)
    for k in join_ks:
        out[f"JOINK_{k}"] = join_script(depth, 0, operator_key, sparse, k)
    out["UPDATE"] = update_script(depth, operator_key, sparse)
    out["CLAIM"] = claim_script(depth, tree_id, sparse, dust_min=dust_min)
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


def w_carve_extras(src, claim, amt_new=None):
    """The thirteen carve extras (bottom..top): the source seq as a number
    with its pad, the pad of seq + 1, the pad of the new source amount, and
    the minimal evict_after of the source and of the claim leaf with their
    pads (carve_rules). amt_new defaults to src.amount - claim.amount."""
    if amt_new is None:
        amt_new = src.amount - claim.amount
    return ([scriptnum(src.seq)] + list(pad(src.seq)) + list(pad(src.seq + 1)) + list(pad(amt_new)) +
            [scriptnum(src.evict_after)] + list(pad(src.evict_after)) +
            [scriptnum(claim.evict_after)] + list(pad(claim.evict_after)))


def w_pos(leaf):
    """Sparse position items: ok nonce plo phi (nonce must make plo minimal positive)."""
    h = lt.tagged_hash(lt.TAG_POS, leaf.owner_key + lt.le32(leaf.nonce))
    return [leaf.owner_key, lt.le32(leaf.nonce), h[:4], h[4:]]


def pos_ok(leaf, depth=31):
    """Whether the leaf's nonce is usable in a MID sparse tree of `depth`:
    pos_lo must be a minimal positive four-byte CScriptNum (top bit clear,
    last byte non-zero), and since the script compares the D-bit direction
    accumulator with all 32 bits of pos_lo, pos_lo must be below 2^depth.
    With the last byte non-zero that needs depth >= 25; at depth 31 the
    two conditions coincide (spec 4.5)."""
    h = lt.tagged_hash(lt.TAG_POS, leaf.owner_key + lt.le32(leaf.nonce))
    return (h[3] & 0x80) == 0 and h[3] != 0 and int.from_bytes(h[:4], "little") < (1 << depth)


def position(leaf, depth):
    h = lt.tagged_hash(lt.TAG_POS, leaf.owner_key + lt.le32(leaf.nonce))
    return int.from_bytes(h[:4], "little") & ((1 << depth) - 1)
