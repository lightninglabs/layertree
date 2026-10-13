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
  joined sum) or a comparison with a leaf field (the claim leaf's
  evict_after in the carve rule). Everything else that is summed is
  derived from those.
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


def tower_auth(tree_id):
    """The owner branch of EXIT_K^t under 0xC0 numerics (spec 7.2 rule 7),
    shared with the CCV tier's 0xC0 scripts: [leaf(10) ea_num ze we sig]
    -> [leaf(10) ea_num ze we], where sig MUST be a BIP-340 signature by
    the leaf's owner_key over H_exit(tree_id || body(leaf)), checked with
    OP_CHECKSIGFROMSTACK. The leaf body (the six fields after amt8, spec
    5.2) is rejoined from its field elements, each 12 deep under sig, as
    voucher_auth does for CLAIM; amt8 is left out, so an amount-only
    increase by REWRITE_h rule 3 leaves the authorisation valid. ok (the
    third field) sits 12 deep once the message replaces the copies."""
    assert len(tree_id) == 32
    s = [12, "OP_PICK"] * 6 + ["OP_CAT"] * 5                        # ... sig body
    s += [tree_id, "OP_SWAP", "OP_CAT"] + tagged(F.EXIT_PREFIX)     # ... sig msg
    return s + [12, "OP_PICK", "OP_CHECKSIGFROMSTACK", "OP_VERIFY"]  # leaf(10) ea_num ze we


def exit_auth(tower=False, tree_id=None):
    """The authorisation of one MID exit block:
    [leaf(10) ea_num ze we sig is_evict] -> [leaf(10)], with is_evict
    parked on the altstack. Eviction: a transaction signature by evk under
    the lock time, ea_num checked against the ea field by PADZ. Owner: a
    transaction signature by ok, or with tower=True (EXIT_K^t, spec 7.2
    rule 7) the off-chain authorisation of tower_auth."""
    s = ["OP_DUP", "OP_TOALTSTACK", "OP_IF",
         3, "OP_PICK", "OP_CHECKLOCKTIMEVERIFY", "OP_DROP",      # ea_num is a minimal number
         10, "OP_PICK", "OP_CHECKSIGVERIFY"] + padz() + [        # leaf(10) le32(ea_num)
         6, "OP_PICK", "OP_EQUALVERIFY",                        # le32(ea_num) == ea field
         "OP_ELSE"]
    if tower:
        s += tower_auth(tree_id)                                # leaf(10) ea_num ze we
    else:
        s += [11, "OP_PICK", "OP_CHECKSIGVERIFY"]               # leaf(10) ea_num ze we
    return s + ["OP_2DROP", "OP_DROP", "OP_ENDIF"]              # leaf(10)


def exit_block_full(sparse, depth, out_index, tower=False, tree_id=None):
    """Complete exit block: -> T oh os nh ns after levels.
    Exit leaf witness: leaf(10) ea_num ze we sig is_evict  (ea_num: minimal evict_after).
    tower=True is EXIT_K^t (spec 7.2 rule 7); MID payouts are exact already."""
    s = exit_auth(tower, tree_id) + [                           # leaf(10)
         out_index, SEL_OUT_SINGLE, "OP_TX",
         F.P2TR_PREFIX, 11, "OP_PICK", "OP_CAT", "OP_EQUALVERIFY",
         10, "OP_PICK", "OP_EQUALVERIFY",
         "OP_FROMALTSTACK", "OP_DROP"]
    s += leaf_join() + tagged(F.LEAF_PREFIX) + ["OP_FROMALTSTACK"]   # oh os
    if sparse:
        s += roll(5, 4) + sparse_setup()                 # oh os   (ok nonce plo phi were below oh)
    s += [F.NODE_PREFIX, "OP_ROT", "OP_ROT", lt.EMPTY_LEAF_HASH, "OP_0"]
    return s + levels(sparse, depth)


def exit_script(depth, k=1, sparse=False, tower=False, tree_id=None):
    """EXIT_K under MID; tower=True is EXIT_K^t (spec 7.2 rule 7), whose
    owner branch takes the off-chain authorisation over tree_id, a
    constant of the script, in place of a transaction signature."""
    assert not tower or tree_id is not None
    s = prologue()
    s += exit_block_full(sparse, depth, 1, tower, tree_id) + check_old(sparse)
    for i in range(2, k + 1):
        s += ["OP_SWAP", "OP_TOALTSTACK", "OP_TOALTSTACK", "OP_DROP"]
        s += exit_block_full(sparse, depth, i, tower, tree_id) + check_prev(sparse)
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


def claim_script(depth, tree_id, sparse=False, hashlock=False, dust_min=lt.DUST_MIN,
                 exit_consent=False):
    """CLAIM (7.5) or CLAIM^h (7.5.1); see _carve_script. tree_id is the
    tree's 32-byte voucher binding (6.2), a constant of the script, and
    dust_min its DUST_MIN (7.5 rule 6).

    exit_consent=True is the CLAIM^x variant (spec 7.5.3), or CLAIM^hx
    with hashlock: the element directly below r is one more signature,
    exit_sig, which MUST be valid over the transaction by the source
    leaf's exit_key, exactly as UPDATE^x (7.4 rule 5) adds exit-key
    consent to UPDATE. The exit key is the second field of the source
    block, CARVE_EXIT_DEPTH deep under the signature (one deeper with the
    preimage in between), so the check is one OP_PICK and one
    OP_CHECKSIGVERIFY before anything else, four bytes over the plain
    form as UPDATE^x over UPDATE in this tier."""
    return _carve_script(depth, sparse, "hashlock" if hashlock else "voucher", tree_id, dust_min,
                         exit_consent)


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
# authorisation element, and src.ek, the second field, 32 deep; under
# CLAIM^x the voucher signature sits between the exit signature and the
# blocks, so the exit key is one deeper again (CARVE_EXIT_DEPTH), and the
# preimage of CLAIM^hx adds one more.
CARVE_EXTRAS = 13
CARVE_OWNER_DEPTH = 31
CARVE_EXIT_DEPTH = 33


def voucher_auth(tree_id, hashlock=False):
    """The voucher check of CLAIM and CLAIM^h under 0xC0 numerics (spec 7.5
    rule 1, 7.5.1 rule 1), shared with the CCV tier's 0xC0 scripts:
    [src(10) claim(10) extras(13) vsig] -> [src(10) claim(10) extras(13)],
    with SHA256(preimage) parked on the altstack beforehand under hashlock.

    The message H_voucher(tree_id || body(src) || claim) is assembled from
    the leaf fields of each block by thirteen OP_PICKs: the six fields of
    the source body (everything after amt8, spec 5.2) sit 32 deep under
    vsig, the seven of the claim leaf 24 deep once the body is on the
    stack, and src.ok (the third field) 32 deep once the message replaces
    the copies. The source amount is left out of the message, so an
    amount-only increase by REWRITE_h rule 3 does not void an outstanding
    voucher; carve_source still checks the claim against the current
    amount, and seq keeps the voucher single-use.
    """
    assert len(tree_id) == 32
    s = [32, "OP_PICK"] * 6 + ["OP_CAT"] * 5                        # ... vsig src_body
    s += [24, "OP_PICK"] * 7 + ["OP_CAT"] * 6                       # ... vsig src_body claim_leaf
    s += ["OP_CAT", tree_id, "OP_SWAP", "OP_CAT"]                   # ... vsig (tree_id||body||claim)
    if hashlock:
        s += ["OP_FROMALTSTACK", "OP_CAT"]                          # ... (tree_id||body||claim||phash)
    s += tagged(F.VOUCHER_H_PREFIX if hashlock else F.VOUCHER_PREFIX)   # ... vsig msg
    return s + [32, "OP_PICK", "OP_CHECKSIGFROMSTACK", "OP_VERIFY"]  # src(10) claim(10) extras(13)


def _carve_script(depth, sparse=False, auth="voucher", tree_id=None, dust_min=lt.DUST_MIN,
                  exit_consent=False):
    """witness (bottom..top):
       zf wf [claim levels] [sparse claim: ck cnonce cplo cphi]
       zi wi [src levels] [sparse src: sk snonce splo sphi]
       src(10) claim(10) seq_num zq0 wq0 zq1 wq1 zs2 ws2
       sea zse wse cea zce wce vsig [preimage] [xsig] r m
       zf wf pad the final sum, zi wi the input amount; pads sit below
       levels. sea and cea are the minimal evict_after of the source and of
       the claim leaf with their PADZ pads (carve_rules; w_carve_extras
       builds the thirteen extras).

    auth selects the authorisation and nothing else: "voucher" is CLAIM,
    "hashlock" is CLAIM^h (a 32-byte preimage sits between vsig and r and
    SHA256(preimage) is appended to the signed message under a separate
    tag), "owner" is SPLIT (the witness carries a transaction signature in
    place of the voucher). exit_consent (CLAIM^x, CLAIM^hx; spec 7.5.3)
    consumes one more element, xsig, directly below r, before anything
    else, checked against the source block's exit-key element, so every
    stack depth below is as in the plain form."""
    assert auth in ("voucher", "hashlock", "owner")
    assert not (exit_consent and auth == "owner")
    hashlock = auth == "hashlock"
    s = prologue()                                                   # ... extras(7) vsig [pre] [xsig] | m r
    if exit_consent:
        s += [CARVE_EXIT_DEPTH + (1 if hashlock else 0), "OP_PICK",  # ... vsig [pre] xsig src.ek
              "OP_CHECKSIGVERIFY"]                                   # ... extras(7) vsig [pre]
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
    The claim leaf's number is NONNEG-checked first: a claim field of
    `01 00 00 81` is the minimal CScriptNum -16,777,217 with an empty pad,
    which the compare would accept against any source lease, planting a
    leaf whose eviction fails OP_CHECKLOCKTIMEVERIFY for good (10.6). The
    source's number needs no check: its field is already in the tree,
    and with the claim side checked no carve can write a negative one.
    The claim amount is already a number (the block's amt_num, which
    LEAF_JOIN binds to the amount field), so the DUST_MIN floor of rule 6
    is one comparison against the constant."""
    return ([19, "OP_PICK", 30, "OP_PICK", "OP_EQUALVERIFY",         # claim.evk == src.evk
             2, "OP_PICK", "OP_TOALTSTACK"] + padz() +               # ... sea zse wse le32(cea)   | cea
            [16, "OP_PICK", "OP_EQUALVERIFY",                        # le32(cea) == claim.ea
             2, "OP_PICK", "OP_TOALTSTACK"] + padz() +               # ... le32(sea)               | cea sea
            [23, "OP_PICK", "OP_EQUALVERIFY",                        # le32(sea) == src.ea
             "OP_FROMALTSTACK", "OP_FROMALTSTACK"] + nonneg() +      # ... sea cea   (cea >= 0)
            ["OP_GREATERTHANOREQUAL", "OP_VERIFY",                   # src(10) claim(10) extras(7)
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


# ------------------------------------- pending-leaf receive (7.5.4, 7.11) --
# FULL's merge claim CLAIM^m / CLAIM^hm and RECLAIM_1 under MID numerics
# (design/pending-receive.md R1, R2). A tree that carries them names
# RECLAIM_KEY at creation; a leaf is reclaimable when its evictor_key is
# RECLAIM_KEY.
def _sc(a, r, l):
    """Push a leaf's 41-byte node H_leaf(amt8||rest) || amt8 || 01 built
    from copies: amt8 at depth a, rest at depth r, the TAG_LEAF prefix at
    depth l. Nothing is consumed."""
    return [a, "OP_PICK", r + 1, "OP_PICK", "OP_CAT",
            l + 1, "OP_PICK", "OP_SWAP", "OP_CAT", "OP_SHA256",
            a + 1, "OP_PICK", b"\x01", "OP_CAT", "OP_CAT"]


def merge_script(depth, tree_id, hashlock=False, reclaim_key=None, dust_min=lt.DUST_MIN):
    """CLAIM^m (7.5.4), or CLAIM^hm with hashlock=True, in the MID tier:
    raise the source's sibling to an absolute amount X, taking the
    difference from the source. Dense profile only.

    witness (bottom..top):
      zf wf zi wi [levels 1..D-1] f zr wr xn zx wx S(10) T(10) vsig [preimage] r m

    S and T are the source and target leaf blocks of an aligned pair, its
    node proven at height 1, and f (empty or 0x01) is src_is_left: the
    blocks arrive source first whatever their positions, and f orders them
    in the pair's node. X arrives as the minimal number xn with its PADZ
    pad (zx wx), and zr wr pad the source's residual. The voucher is a
    signature by S.owner_key over H_voucher_m(tree_id || body(S) ||
    body(T) || le64(X) [|| SHA256(preimage)]), the FULL message byte for
    byte, checked with OP_CHECKSIGFROMSTACK. The script requires
    T.owner_key == S.exit_key and T.exit_key == S.exit_key, neither seq
    at MID's SEQ_FINAL, T not
    reclaimable (when the tree names a RECLAIM_KEY), d = X - T.amount >= 1
    and a residual S.amount - d of zero (the source position becomes E_0)
    or at least DUST_MIN. The source keeps its body, seq included, and the
    target changes in its amount only. The pair's sum is unchanged, so it
    is computed once, as residual + X.

    xn needs no NONNEG check: a negative xn makes d negative, which rule 3
    rejects, and le64(xn) is what the voucher signs whatever its sign."""
    assert len(tree_id) == 32 and depth >= 1
    hl = 1 if hashlock else 0
    s = prologue()                                                   # .. S(10) T(10) vsig [pre]  | m r
    if hashlock:
        s += ["OP_SIZE", 32, "OP_EQUALVERIFY", "OP_SHA256"]          # .. vsig ph
    s += [23 + hl, "OP_PICK"] * 3 + le64() + ["OP_DUP", "OP_TOALTSTACK"]   # .. vsig [ph] X8   | m r X8
    if hashlock:
        s += ["OP_SWAP", "OP_CAT"]                                   # .. vsig (X8||ph)
    s += [20, "OP_PICK"] * 6 + ["OP_CAT"] * 5                        # .. vsig sfx body(S)
    s += [11, "OP_PICK"] * 6 + ["OP_CAT"] * 6                        # .. vsig sfx (body(S)||body(T))
    s += ["OP_SWAP", "OP_CAT", tree_id, "OP_SWAP", "OP_CAT"]          # .. vsig (tree_id||bS||bT||X8[||ph])
    s += tagged(F.VOUCHER_HM_PREFIX if hashlock else F.VOUCHER_M_PREFIX)
    s += [19, "OP_PICK", "OP_CHECKSIGFROMSTACK", "OP_VERIFY"]         # f zr wr xn zx wx S(10) T(10)
    # rule 2: the target belongs and exits to the source's exit key, neither leaf is final
    s += [7, "OP_PICK", 19, "OP_PICK", "OP_EQUALVERIFY",             # T.ok == S.ek
          8, "OP_PICK", 19, "OP_PICK", "OP_EQUALVERIFY",             # T.ek == S.ek
          3, "OP_PICK", SEQ_FINAL_BYTES, "OP_EQUAL", "OP_NOT", "OP_VERIFY",    # T.seq != SEQ_FINAL
          13, "OP_PICK", SEQ_FINAL_BYTES, "OP_EQUAL", "OP_NOT", "OP_VERIFY"]   # S.seq != SEQ_FINAL
    if reclaim_key is not None:
        s += [6, "OP_PICK", reclaim_key, "OP_EQUAL", "OP_NOT", "OP_VERIFY"]   # T not reclaimable
    s += _leaf_join_new() + ["OP_TOALTSTACK"] * 3                    # f zr wr xn zx wx S(10)   | .. X8 T.amt T.rest T.amt8
    s += _leaf_join_new() + ["OP_FROMALTSTACK"] * 3                  # .. S.amt8 S.rest S.amt T.amt8 T.rest T.amt
    # rule 3: d = X - T.amount >= 1, residual 0 or >= DUST_MIN
    s += [8, "OP_PICK", "OP_SWAP", "OP_SUB",                          # .. S.amt T.amt8 T.rest d
          "OP_DUP", "OP_1", "OP_GREATERTHANOREQUAL", "OP_VERIFY",
          3, "OP_ROLL", "OP_SWAP", "OP_SUB",                          # .. S.amt8 S.rest T.amt8 T.rest res
          "OP_DUP", 10, "OP_PICK", 10, "OP_PICK"] + le64() + [        # .. res le64(res)
          F.LEAF_PREFIX, "OP_FROMALTSTACK"]                           # .. res le64r L X8
    # depths: X8 0, L 1, le64r 2, res 3, T.rest 4, T.amt8 5, S.rest 6, S.amt8 7,
    # wx 8, zx 9, xn 10, wr 11, zr 12, f 13
    s += _sc(0, 4, 1)                                                 # .. nT
    s += [4, "OP_PICK", "OP_0NOTEQUAL", "OP_IF",
          dust_min, 5, "OP_PICK", "OP_LESSTHANOREQUAL", "OP_VERIFY"] + _sc(3, 7, 2) + [
          "OP_ELSE", E0_SC, "OP_ENDIF"]                               # .. nT nS   (drained: E_0)
    s += _sc(7, 6, 3) + _sc(10, 9, 4)                                 # .. nT nS oT oS
    s += [17, "OP_PICK", "OP_IF", "OP_SWAP", "OP_ENDIF", "OP_CAT", "OP_TOALTSTACK",   # | .. pre_old
          15, "OP_PICK", "OP_IF", "OP_SWAP", "OP_ENDIF", "OP_CAT",                    # .. pre_new
          4, "OP_PICK", 12, "OP_PICK", "OP_ADD",                      # .. pre_new sum   (res + X)
          "OP_TOALTSTACK", "OP_TOALTSTACK"] + ["OP_2DROP"] * 7 + [    # | m r pre_old sum pre_new
          F.NODE_PREFIX, "OP_FROMALTSTACK", "OP_OVER", "OP_SWAP", "OP_CAT", "OP_SHA256",   # T nh
          "OP_FROMALTSTACK", "OP_FROMALTSTACK",                       # T nh sum pre_old
          3, "OP_PICK", "OP_SWAP", "OP_CAT", "OP_SHA256",             # T nh sum oh
          "OP_SWAP", "OP_ROT", "OP_OVER"]                             # T oh os nh ns
    s += levels(False, depth, 1)
    return s + check_old(False) + final(depth)


def reclaim_script(depth, reclaim_key, sparse=False):
    """RECLAIM_1 (7.11) in the MID tier: the operator removes a reclaimable
    leaf after its deadline with no payout.

    witness (bottom..top) = zf wf zi wi [levels] [sparse: ok nonce plo phi]
                            leaf(10) ea_num ze we sig r m

    The leaf's evictor_key MUST be RECLAIM_KEY, the lock time at least its
    evict_after (ea_num, the field as a minimal number with its PADZ pad,
    as EXIT_1's eviction branch takes it) and sig a transaction signature
    by RECLAIM_KEY. The new node is E_0; output 0 carries S - leaf.amount
    and nothing else is constrained. It is EXIT_1's eviction branch with
    the payout check removed and RECLAIM_KEY in place of the leaf's own
    evictor key."""
    assert len(reclaim_key) == 32
    s = prologue() + [reclaim_key, "OP_CHECKSIGVERIFY",               # leaf(10) ea_num ze we
                      2, "OP_PICK", "OP_CHECKLOCKTIMEVERIFY", "OP_DROP"] + padz() + [
                      6, "OP_PICK", "OP_EQUALVERIFY",                  # leaf(10)   (le32(ea_num) == ea)
                      6, "OP_PICK", reclaim_key, "OP_EQUALVERIFY"]     # evictor_key == RECLAIM_KEY
    s += leaf_join() + tagged(F.LEAF_PREFIX) + ["OP_FROMALTSTACK"]   # oh os
    if sparse:
        s += roll(5, 4) + sparse_setup()
    s += [F.NODE_PREFIX, "OP_ROT", "OP_ROT", lt.EMPTY_LEAF_HASH, "OP_0"]
    return s + levels(sparse, depth) + check_old(sparse) + final(depth)


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


def _leaf_join_old(reclaim_key=None):
    """[amt8 ek ok evk ea nonce seq amt_num za wa] -> [amt8 rest ek ok fin amt]

    LEAF_JOIN with the fields the rewrite rules need kept beside the
    re-joined rest: copies of ek and ok, fin = (seq == SEQ_FINAL) and the
    amount as a (non-negative) number. rest is ek||ok||evk||ea||nonce||seq,
    so amt8||rest is the leaf.

    With reclaim_key (the reclaim form, 7.9 rule 8) two more items sit
    below amt8, the raw ea field and isR = (evk == RECLAIM_KEY):
    [ea isR amt8 rest ek ok fin amt], so every depth of the plain form's
    six items is unchanged."""
    s = [2, "OP_PICK"] + nonneg() + ["OP_TOALTSTACK"]                          # ... amt_num za wa    | amt
    s += le64() + [7, "OP_PICK", "OP_EQUALVERIFY"]                             # amt8 ek ok evk ea nonce seq
    for d, size in FIELD_SIZES:
        s += ([d, "OP_PICK"] if d else ["OP_DUP"]) + ["OP_SIZE", size, "OP_EQUALVERIFY", "OP_DROP"]
    s += ["OP_DUP", SEQ_FINAL_BYTES, "OP_EQUAL", "OP_TOALTSTACK"]              # | amt fin
    s += [5, "OP_PICK", 5, "OP_PICK", "OP_TOALTSTACK", "OP_TOALTSTACK"]        # | amt fin ok ek
    if reclaim_key is not None:
        s += [3, "OP_PICK", reclaim_key, "OP_EQUAL", "OP_TOALTSTACK",          # | .. ek isR
              2, "OP_PICK", "OP_TOALTSTACK"]                                   # | .. ek isR ea
    s += ["OP_CAT"] * 5                                                        # amt8 rest
    if reclaim_key is not None:
        s += ["OP_FROMALTSTACK", "OP_FROMALTSTACK", "OP_2SWAP"]                # ea isR amt8 rest
    return s + ["OP_FROMALTSTACK"] * 4                                         # [ea isR] amt8 rest ek ok fin amt


def _leaf_join_new():
    """[amt8 ek ok evk ea nonce seq amt_num za wa] -> [amt8 rest amt]"""
    s = [2, "OP_PICK"] + nonneg() + ["OP_TOALTSTACK"]
    s += le64() + [7, "OP_PICK", "OP_EQUALVERIFY"]
    for d, size in FIELD_SIZES:
        s += ([d, "OP_PICK"] if d else ["OP_DUP"]) + ["OP_SIZE", size, "OP_EQUALVERIFY", "OP_DROP"]
    return s + ["OP_CAT"] * 5 + ["OP_FROMALTSTACK"]                            # amt8 rest amt


def _rewrite_owner_auth(exit_consent, k=0):
    """[sig C_new(3) C_old(6)] -> [C_new(3) C_old(6)]: the next witness element,
    nine deep, is a signature by old.ok; under ^x one more by old.ek. k is
    the number of extra C_old items (2 in the reclaim form)."""
    s = [9 + k, "OP_ROLL", 3, "OP_PICK", "OP_CHECKSIGVERIFY"]
    if exit_consent:
        s += [9 + k, "OP_ROLL", 4, "OP_PICK", "OP_CHECKSIGVERIFY"]
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


def _rewrite_r1():
    """[.. we ze ea_num C_new(3) C_old(8)] -> [.. C_new(3) C_old(8)]: R1 inside
    the reclaim-form rewrite (7.9 rule 8). The old leaf's deadline has
    passed: the next three witness elements are its evict_after as a
    minimal number with its PADZ pad, checked against the raw ea field
    (C_old's deepest item) and against the lock time. No signature, and no
    payout when the position is emptied."""
    return ([11, "OP_ROLL", 12, "OP_ROLL", 13, "OP_ROLL"] +                   # .. C_old ea_num ze we
            [2, "OP_PICK", "OP_CHECKLOCKTIMEVERIFY", "OP_DROP"] + padz() +     # .. C_old le32(ea_num)
            [8, "OP_PICK", "OP_EQUALVERIFY"])


def _rewrite_step(exit_consent, pay=None, reclaim_key=None, side=None):
    """One position of the pre-pass:
    [.. {xsig} {sig} new_slot old_slot idx L Z] | .. -> [.. idx' L Z] | .. ns nsc os osc

    A slot is leaf(10) 0x01 or one empty element, and the new slot may be
    the one-byte marker REWRITE_SAME, in which case the old slot's node is
    parked twice and nothing else happens (7.9: unchanged). Otherwise the
    old slot is reduced first, parked, then the new slot; with both
    canonical forms on the stack (new below old) the step applies 7.9
    rules 3 and 5 and converts both to nodes. Depths in the decision
    block, from the top: amt_o 0, fin 1, ok 2, ek 3, rest_o 4, amt8_o 5,
    amt_n 6, rest_n 7, amt8_n 8, and the next witness element 9. `pay` is
    the exit payout check, _rewrite_pay's by default; the CCV tier's 0xC0
    numerics pass their own.

    With reclaim_key (the reclaim form, 7.9 rule 8, as FULL's
    _rewrite_step) C_old carries [ea isR] below its six items, so the new
    items and the next witness element sit two deeper, and the machine is
    [idx delta key L Z]: (delta, key) is the transfer record a left step
    (side "L", even position) leaves for its right sibling (side "R"),
    (old.amount - new.amount, old.exit_key) for an R3 transfer and (0, 0)
    otherwise; a right step checks it (its old leaf owned by and exiting to
    key, not reclaimable, raised by exactly delta) and resets it to (0, 0). idx stays
    the altstack's top while the machine is parked, so `pay` is unchanged.
    A changed position whose old leaf is reclaimable takes no owner
    signature: an amount-only increase passes as rule 3, a left decrease
    with the body unchanged is a transfer its right sibling must absorb,
    and any other change is R1 (_rewrite_r1)."""
    if pay is None:
        pay = _rewrite_pay()
    r = reclaim_key is not None
    k = 2 if r else 0                        # extra C_old items
    mc = 5 if r else 3                       # machine size
    s = ["OP_TOALTSTACK"] * mc                                                 # .. new_slot old_slot   | .. machine
    s += ["OP_IF"] + _leaf_join_old(reclaim_key) + ["OP_ELSE"] + ["OP_0"] * (6 + k) + ["OP_ENDIF"]   # .. new_slot C_old
    s += [6 + k, "OP_PICK", REWRITE_SAME, "OP_EQUAL", "OP_IF",                 # -- the marker: new = old --
          6 + k, "OP_ROLL", "OP_DROP",                                         # .. C_old
          "OP_TOALTSTACK", "OP_2DROP", "OP_DROP"]                              # .. [ea isR] amt8 rest
    if r:
        s += ["OP_2SWAP", "OP_2DROP"]                                          # .. amt8 rest
    s += ["OP_FROMALTSTACK"]                                                   # .. amt8 rest amt
    s += ["OP_FROMALTSTACK"] * mc                                              # .. amt8 rest amt idx [delta key] L Z
    if r and side == "R":
        s += [3, "OP_PICK", "OP_NOT", "OP_VERIFY"]                             # no transfer into an unchanged leaf
    s += roll(5 + k, 2) + _rewrite_conv()                                      # .. amt machine sc
    s += roll(4 + k) + ["OP_2DUP"] + ["OP_TOALTSTACK"] * 4                     # .. machine              | .. ns nsc os osc
    s += ["OP_ELSE"]                                                           # -- a leaf or empty --
    s += ["OP_TOALTSTACK"] * (6 + k)                                           # .. new_slot            | .. machine C_old
    s += ["OP_IF"] + _leaf_join_new() + ["OP_ELSE"] + ["OP_0"] * 3 + ["OP_ENDIF"]   # .. C_new(3)
    s += ["OP_FROMALTSTACK"] * (6 + k)                                         # .. C_new(3) C_old      | .. machine
    old_rules = ([7 + k, "OP_PICK", "OP_SIZE", "OP_NIP", "OP_0NOTEQUAL", "OP_IF",      # -- new is a leaf: rewrite --
                  4, "OP_PICK", 8 + k, "OP_PICK", "OP_EQUAL",                          # same_rest
                  "OP_OVER", 8 + k, "OP_PICK", "OP_LESSTHANOREQUAL", "OP_BOOLAND",     # .. and amt_o <= amt_n
                  2, "OP_PICK", "OP_NOT", "OP_BOOLAND",                                # .. and seq != SEQ_FINAL
                  "OP_NOTIF"] + _rewrite_owner_auth(exit_consent, k) + ["OP_ENDIF",
                  "OP_ELSE"] + _rewrite_owner_auth(exit_consent, k) + pay + [          # -- new is empty: exit --
                  "OP_ENDIF"])
    if not r:
        leaf_rules = old_rules
    else:
        r1 = _rewrite_r1()
        if side == "L":   # an R3 transfer (body unchanged, amount lowered) passes here
            decrease = ([4, "OP_PICK", 10, "OP_PICK", "OP_EQUAL",
                         "OP_OVER", 10, "OP_PICK", "OP_LESSTHANOREQUAL", "OP_NOT", "OP_BOOLAND",
                         "OP_NOTIF"] + r1 + ["OP_ENDIF"])
        else:
            decrease = r1
        leaf_rules = ([6, "OP_PICK", "OP_IF",                                          # -- old is reclaimable --
                       9, "OP_PICK", "OP_SIZE", "OP_NIP", "OP_0NOTEQUAL", "OP_IF",      # new is a leaf
                       4, "OP_PICK", 10, "OP_PICK", "OP_EQUAL",
                       "OP_OVER", 10, "OP_PICK", "OP_LESSTHANOREQUAL", "OP_BOOLAND",
                       2, "OP_PICK", "OP_NOT", "OP_BOOLAND",                            # rule 3's exemption
                       "OP_NOTIF"] + decrease + ["OP_ENDIF",
                       "OP_ELSE"] + r1 + ["OP_ENDIF",                                   # emptied: reclaimed, no payout
                       "OP_ELSE"] + old_rules + ["OP_ENDIF"])
    s += [4, "OP_PICK", 8 + k, "OP_PICK", "OP_EQUAL",                          # same_rest
          6, "OP_PICK", 10 + k, "OP_PICK", "OP_EQUAL",                         # same_amt8
          "OP_BOOLAND", "OP_NOTIF",                                            # -- changed --
          4, "OP_PICK", "OP_SIZE", "OP_NIP", "OP_0NOTEQUAL", "OP_IF"]          # -- old is a leaf --
    s += leaf_rules + [
          "OP_ENDIF",                                                          # (old empty: a join, operator only)
          "OP_ENDIF"]                                                          # (unchanged)
    if r:
        # the transfer record; depths with [idx delta key] popped: key 0,
        # delta 1, idx 2, amt_o 3, fin 4, ok 5, ek 6, rest_o 7, amt8_o 8,
        # isR 9, ea 10, amt_n 11, rest_n 12, amt8_n 13
        s += ["OP_FROMALTSTACK"] * 3
        if side == "L":
            s += ["OP_2DROP",                                                  # .. idx
                  7, "OP_PICK",                                                # isR
                  6, "OP_PICK", 12, "OP_PICK", "OP_EQUAL", "OP_BOOLAND",       # .. and same_rest
                  2, "OP_PICK", 11, "OP_PICK", "OP_LESSTHANOREQUAL", "OP_NOT", "OP_BOOLAND",   # .. and amt_o > amt_n
                  "OP_IF", "OP_OVER", 10, "OP_PICK", "OP_SUB",                 # .. idx delta'
                  5, "OP_PICK",                                                # .. idx delta' key'
                  "OP_ELSE", "OP_0", "OP_0", "OP_ENDIF"]
        else:
            s += ["OP_OVER", "OP_0NOTEQUAL", "OP_IF",
                  "OP_DUP", 6, "OP_PICK", "OP_EQUALVERIFY",                    # old.ok == key
                  "OP_DUP", 7, "OP_PICK", "OP_EQUALVERIFY",                    # old.ek == key
                  9, "OP_PICK", "OP_NOT", "OP_VERIFY",                         # old not reclaimable
                  7, "OP_PICK", 13, "OP_PICK", "OP_EQUALVERIFY",               # same_rest
                  11, "OP_PICK", 4, "OP_PICK", "OP_SUB", 2, "OP_PICK", "OP_NUMEQUALVERIFY",   # amt_n - amt_o == delta
                  "OP_ENDIF", "OP_2DROP", "OP_0", "OP_0"]                      # .. idx 0 0
        s += ["OP_TOALTSTACK"] * 3
    s += ["OP_TOALTSTACK", "OP_2DROP", "OP_DROP"]                              # .. C_new [ea isR] amt8_o rest_o
    if r:
        s += ["OP_2SWAP", "OP_2DROP"]                                          # .. C_new amt8_o rest_o
    s += ["OP_FROMALTSTACK"]                                                   # .. C_new amt8_o rest_o amt_o
    s += ["OP_FROMALTSTACK"] * mc                                              # .. amt8_n rest_n amt_n amt8_o rest_o amt_o machine
    s += roll(8 + k, 2) + _rewrite_conv()                                      # .. amt_n amt8_o rest_o amt_o machine nsc
    s += roll(7 + k) + ["OP_TOALTSTACK", "OP_TOALTSTACK"]                      # .. amt8_o rest_o amt_o machine   | .. ns nsc
    s += roll(5 + k, 2) + _rewrite_conv()                                      # .. amt_o machine osc
    s += roll(4 + k) + ["OP_TOALTSTACK", "OP_TOALTSTACK"]                      # .. machine                       | .. ns nsc os osc
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


def rewrite_script(depth, height, operator_key, exit_consent=False, reclaim_key=None):
    """REWRITE_h (7.9, dense) in the MID tier, or REWRITE_h^x with exit_consent.

    witness (bottom..top):
      zf wf zi wi [levels h..D-1] [pad pairs: for each internal node in
      reverse consumption order, the new sum's pair then the old sum's]
      block_{2^h-1} .. block_0 sig_op r m
      block_i = [xsig_i] [sig_i] new_slot_i old_slot_i, a slot being leaf(10)
      0x01 or one empty element, and new_slot_i may be the one-byte marker
      REWRITE_SAME for an unchanged position; sig_i only where 7.9 rule 3
      requires it, xsig_i only under ^x and only where sig_i is present.

    With reclaim_key this is the reclaim form (7.9 rule 8; REWRITE_R_h,
    REWRITE_XR_h), h >= 1: a position that takes R1 carries, in place of
    its signatures, the old leaf's evict_after as we ze ea_num (w_reclaim).
    """
    assert 1 <= height <= depth
    s = prologue() + [operator_key, "OP_CHECKSIGVERIFY"]                       # .. blocks            | m r
    s += rewrite_body(height, exit_consent, reclaim_key=reclaim_key)           # T oh os nh ns        | m r
    s += levels(False, depth, height)
    return s + check_old(False) + final(depth)


def rewrite_body(height, exit_consent, pay=None, reclaim_key=None):
    """The tier-independent middle of REWRITE_h after the operator's
    signature: [.. blocks] -> [T oh os nh ns], the pre-pass over every
    position and the mirrored post-order hash pass. Shared with the CCV
    tier's 0xC0 numerics, which pass their own exit payout check as
    `pay`, as evict_body is for the sweep. reclaim_key compiles the
    reclaim form (7.9 rule 8), whose machine carries the transfer record."""
    r = reclaim_key is not None
    s = ["OP_1"] + (["OP_0", "OP_0"] if r else []) + [F.LEAF_PREFIX, E0_SC]    # .. blocks idx [0 0] L Z
    for i in range(1 << height):
        s += _rewrite_step(exit_consent, pay, reclaim_key, "L" if i % 2 == 0 else "R")
    s += ["OP_2DROP", "OP_2DROP", "OP_DROP"] if r else ["OP_2DROP", "OP_DROP"]
    s += [F.NODE_PREFIX]                                                       # T
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
    return s


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


# -------------------------------------------------------- DETACH_h (7.10) --
# FULL's DETACH_h (8.10) under MID numerics: the subtree root R_h and its
# sum are the old node, E_h the new one, and output 1 is the MID tree
# output of a depth-h tree at R_h under m_h, recomputed with TREE_SPK_MIN
# as the prologue recomputes the input's. The sum arrives as a minimal
# number with its PADZ pad, NONNEG keeps it non-negative before it enters
# the fold, and le64 of it is compared with output 1's amount as bytes, as
# every MID payout is. m_h is the parent's option set compiled at depth h
# (7.10 rule 3), from detached_taptree_root or TreeOptions.taptree_root
# below. The witness shrinks with h (9(D - h) + 11 elements below sig r m),
# so the 1,000-element stack limit that caps the MID sweep and rewrite
# binds nothing here.

def detach_script(depth, height, operator_key, m_h):
    """DETACH_h (7.10, dense) in the MID tier.

    witness (bottom..top) = zf wf zi wi [levels h..D-1] R_h sum_num zs ws sig r m
    """
    assert len(m_h) == 32
    assert 1 <= height < depth
    e_h = lt.empty_node(height)[0]
    s = prologue() + [operator_key, "OP_CHECKSIGVERIFY"]             # R_h sum zs ws     | m r
    s += [2, "OP_PICK"] + nonneg() + ["OP_TOALTSTACK"]                # R_h sum zs ws     | m r sum
    s += le64()                                                       # R_h le64(sum)
    s += ["OP_OVER", "OP_SIZE", 32, "OP_EQUALVERIFY", "OP_DROP",      # R_h le64
          "OP_OVER", m_h] + F.tree_spk_min() + [                      # R_h le64 spk1     (TREE_SPK_MIN(R_h, m_h))
          "OP_1", SEL_OUT_SINGLE, "OP_TX",                            # R_h le64 spk1 amt1 spk1'
          "OP_ROT", "OP_EQUALVERIFY",                                 # R_h le64 amt1
          "OP_EQUALVERIFY",                                           # R_h               (amt1 == le64(sum_h), bytes)
          "OP_FROMALTSTACK",                                          # R_h sum
          F.NODE_PREFIX, "OP_ROT", "OP_ROT", e_h, "OP_0"]             # T R_h sum E_h 0
    s += levels(False, depth, height)
    return s + check_old(False) + final(depth)


def w_detach(tree, depth, height, idx, node=None):
    """Everything MID DETACH_h consumes below sig r m, for the subtree `idx`
    of `tree`: final pads, input-amount pads, levels and the subtree node
    as R_h plus its sum as a minimal number with its pad. `node` replaces
    the subtree's real (hash, sum) for tests that present a forged one."""
    base = idx << height
    t1 = lt.Tree(depth)
    t1.leaves = {p: l for p, l in tree.leaves.items() if not base <= p < base + (1 << height)}
    root, r1 = tree.root(), t1.root()
    old = node if node is not None else tree.subtree(height, idx)
    path = tree.path(base, height=height)
    items = list(pad(r1[1])) + list(pad(root[1]))
    items += w_levels(path, old, lt.empty_node(height), False, height)
    return items + [old[0], scriptnum(old[1]), *pad(old[1])]


class TreeOptions:
    """A MID tree's creation parameters other than its depth (spec 6.2),
    as layertree_scripts.TreeOptions is for FULL: the profile,
    OPERATOR_KEY, tree_id, DUST_MIN, the JOIN heights, EXIT_K sizes and
    JOINK sizes, and the variants a MID taptree may carry (7.6): the
    tower-delegable exit EXIT_K^t (7.2 rule 7, in place of EXIT_K; MID
    payouts are exact already), UPDATE^x (7.4 rule 5, in place of UPDATE),
    the four CLAIM forms (7.5, 7.5.1, 7.5.3), SPLIT (7.5.2),
    EVICT_SUBTREE_h (7.7), REWRITE_h and REWRITE_h^x (7.9) and DETACH_h
    (7.10). at_depth(D) compiles the set for a tree of depth D, which is
    what the parent's taptree is built from and what a DETACH_h child MUST
    be built from at depth h (7.10 rule 3). Heights that do not fit the
    depth are dropped.

    The defaults are the reference set of 6.2 at FULL's heights and sizes:
    EXIT_1, EXIT_2, JOIN_0, JOINK_2, UPDATE, CLAIM."""

    def __init__(self, operator_key, tree_id, sparse=False, join_heights=(0,), exit_ks=(1, 2),
                 join_ks=(2,), tower=False, update_x=False, claim=True, claim_h=False,
                 claim_x=False, claim_hx=False, split=False, evict_heights=(),
                 rewrite_heights=(), rewrite_x=False, detach_heights=(), dust_min=lt.DUST_MIN,
                 reclaim_key=None, claim_m=False, claim_hm=False):
        self.operator_key, self.tree_id, self.sparse = operator_key, tree_id, sparse
        self.dust_min = dust_min
        self.join_heights, self.exit_ks, self.join_ks = tuple(join_heights), tuple(exit_ks), tuple(join_ks)
        self.tower, self.update_x = tower, update_x
        self.claim, self.claim_h, self.claim_x, self.claim_hx = claim, claim_h, claim_x, claim_hx
        self.split = split
        self.evict_heights, self.rewrite_heights = tuple(evict_heights), tuple(rewrite_heights)
        self.rewrite_x, self.detach_heights = rewrite_x, tuple(detach_heights)
        # The pending-leaf receive (design/pending-receive.md), as FULL's
        # options: RECLAIM_KEY adds RECLAIM_1 and compiles every REWRITE_h
        # in its reclaim form (REWRITE_R_h, REWRITE_XR_h); claim_m and
        # claim_hm add the merge claims (dense profile).
        self.reclaim_key, self.claim_m, self.claim_hm = reclaim_key, claim_m, claim_hm

    def at_depth(self, depth):
        """Ordered dict name -> token list: the set compiled for depth `depth`,
        the reference members first in all_scripts' order, then the
        variants in FULL's fixed order, so the taptree root is a function
        of the options and the depth alone."""
        op, sp = self.operator_key, self.sparse
        out = {f"EXIT_{k}": exit_script(depth, k, sp, tower=self.tower, tree_id=self.tree_id)
               for k in self.exit_ks}
        for h in (self.join_heights if not sp else (0,)):
            if h <= depth:
                out[f"JOIN_{h}"] = join_script(depth, h, op, sp)
        for k in self.join_ks:
            out[f"JOINK_{k}"] = join_script(depth, 0, op, sp, k)
        out["UPDATE_X" if self.update_x else "UPDATE"] = update_script(depth, op, sp, exit_consent=self.update_x)
        for name, hl, xc, on in (("CLAIM", False, False, self.claim), ("CLAIM_H", True, False, self.claim_h),
                                 ("CLAIM_X", False, True, self.claim_x), ("CLAIM_HX", True, True, self.claim_hx)):
            if on:
                out[name] = claim_script(depth, self.tree_id, sp, hashlock=hl, dust_min=self.dust_min,
                                         exit_consent=xc)
        if self.split:
            out["SPLIT"] = split_script(depth, sp, dust_min=self.dust_min)
        rk = self.reclaim_key
        if rk is not None:
            out["RECLAIM_1"] = reclaim_script(depth, rk, sp)
        if not sp:
            for name, hl, on in (("CLAIM_M", False, self.claim_m), ("CLAIM_HM", True, self.claim_hm)):
                if on:
                    out[name] = merge_script(depth, self.tree_id, hashlock=hl, reclaim_key=rk,
                                             dust_min=self.dust_min)
            for h in self.evict_heights:
                if h <= depth:
                    out[f"EVICT_SUBTREE_{h}"] = evict_subtree_script(depth, h, op)
            r = "R" if rk is not None else ""
            for h in self.rewrite_heights:
                if h <= depth:
                    out[f"REWRITE_{r}{'_' if r else ''}{h}"] = rewrite_script(depth, h, op, reclaim_key=rk)
                    if self.rewrite_x:
                        out[f"REWRITE_X{r}_{h}"] = rewrite_script(depth, h, op, exit_consent=True,
                                                                 reclaim_key=rk)
            for h in self.detach_heights:
                if h < depth:
                    out[f"DETACH_{h}"] = detach_script(depth, h, op, self.taptree_root(h))
        return out

    def taptree_root(self, depth):
        """The tree identifier m of a MID tree of depth `depth` created with
        these options (6.2); for a DETACH_h child this is m_h."""
        from script_sim import assemble
        return lt.taptree_root([lt.tapleaf_hash(assemble(t, "c0"), 0xc0) for t in self.at_depth(depth).values()])


def detached_taptree_root(height, operator_key, tree_id, options=None):
    """m_h for DETACH_h under MID (spec 7.10 rule 3): the parent's option
    set compiled for depth h with the same OPERATOR_KEY and tree_id. With
    no options this is the reference set of 6.2 (EXIT_1, EXIT_2, JOIN_0,
    JOINK_2, UPDATE, CLAIM) in this tier."""
    if options is None:
        options = TreeOptions(operator_key, tree_id)
    assert options.operator_key == operator_key and options.tree_id == tree_id
    return options.taptree_root(height)


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


def w_carve_extras(src, claim, amt_new=None, claim_ea=None):
    """The thirteen carve extras (bottom..top): the source seq as a number
    with its pad, the pad of seq + 1, the pad of the new source amount, and
    the minimal evict_after of the source and of the claim leaf with their
    pads (carve_rules). amt_new defaults to src.amount - claim.amount;
    claim_ea, a (number, z, w) triple, replaces the claim leaf's three
    items, for tests that present a field outside the number range."""
    if amt_new is None:
        amt_new = src.amount - claim.amount
    if claim_ea is None:
        claim_ea = (scriptnum(claim.evict_after),) + pad(claim.evict_after)
    return ([scriptnum(src.seq)] + list(pad(src.seq)) + list(pad(src.seq + 1)) + list(pad(amt_new)) +
            [scriptnum(src.evict_after)] + list(pad(src.evict_after)) + list(claim_ea))


def w_reclaim(leaf):
    """The three items an R1 position of the reclaim-form rewrite consumes,
    in consumption order (w_rewrite reverses them as it does signatures):
    the old leaf's evict_after as a minimal number, then its PADZ pad."""
    return [scriptnum(leaf.evict_after), *pad(leaf.evict_after)]


def w_merge(tree, depth, src_slot, tgt_slot, x, t1=None):
    """Everything MID CLAIM^m / CLAIM^hm consumes below vsig [preimage] r m:
    final pads, input-amount pads, levels from height 1, the flag, the
    residual's pad, X with its pad, and the source and target blocks. t1
    is the tree after the merge, lt.apply_merge's by default; a test of an
    invalid merge passes the tree its transaction claims."""
    assert src_slot ^ 1 == tgt_slot
    src, tgt = tree.leaves[src_slot], tree.leaves[tgt_slot]
    if t1 is None:
        t1 = lt.Tree(depth); t1.leaves = dict(tree.leaves)
        lt.apply_merge(t1, src_slot, tgt_slot, x)
    base = min(src_slot, tgt_slot)
    root, r1 = tree.root(), t1.root()
    res = src.amount - (x - tgt.amount)
    # a negative residual (an invalid merge, for a test) gets the pad of
    # its own encoding, so the script reaches the rule that rejects it
    from script_sim import scriptnum_encode
    res_pad = pad(res) if res >= 0 else (bytes(4 - len(scriptnum_encode(res))), bytes(len(scriptnum_encode(res))))
    items = list(pad(r1[1])) + list(pad(root[1]))
    items += w_levels(tree.path(base, height=1), tree.subtree(1, base >> 1), t1.subtree(1, base >> 1),
                      False, 1)
    items += [b"\x01" if src_slot % 2 == 0 else b"", *res_pad, scriptnum(x), *pad(x)]
    return items + w_leaf(src) + w_leaf(tgt)


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
