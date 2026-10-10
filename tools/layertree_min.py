#!/usr/bin/env python3
"""LayerTree scripts, MIN tier (spec section 4.5): BIP-342 tapscript
(0xC0 semantics) + OP_CAT + OP_TWEAKADD. No OP_TX, no OP_CHECKSIGFROMSTACK.

Introspection is *constructive*: the script assembles the BIP-341 signature
message of the spending transaction from values it has derived (the tree
input's scriptPubKey and amount, the new tree output, the payout) and raw
witness pieces for everything it does not constrain (other inputs, extra
outputs, prevouts, sequences, version, lock time, tapleaf hash). It then
demands a Schnorr signature under the generator G with nonce G, whose only
valid s is e + 1, and checks it with OP_CHECKSIG. Since OP_CHECKSIG signs
the *real* transaction, the assembled message must equal the real one, so
every constrained field is enforced.

Without arbitrary-precision arithmetic, e + 1 is formed by grinding: the
spender varies a free field (e.g. the fee input's nSequence) until the last
byte of e is 0x00, and supplies e[0:31]; the script checks e31||00 == e and
uses G.x || e31 || 01 as the signature. Expected 256 attempts.

Shape is fixed per script: exactly two inputs (the tree output and one fee
input) and outputs [tree', payout, <raw extra outputs>] for EXIT_1, or
[tree', <raw extra outputs>] for SPLIT. EXIT_1 and SPLIT for the dense
profile are provided; other transitions follow the same construction
(spec 4.5). Vouchers (CLAIM) are impossible without OP_CHECKSIGFROMSTACK;
SPLIT, which authorises the same carve with a transaction signature, is not.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import layertree_ref as lt  # noqa: E402
import layertree_scripts as F  # noqa: E402
import layertree_mid as M  # noqa: E402

G_X = lt.xonly(lt.G)
TAPSIGHASH_PREFIX = lt.tag_prefix("TapSighash")
CHALLENGE_PREFIX = lt.tag_prefix("BIP0340/challenge")
EXTRA_OPCODES = {"OP_CAT", "OP_TWEAKADD"}

# raw introspection witness pieces (bottom..top at the very bottom of the witness)
# order: e31 sha_seqs tapleaf sha_prevouts ver lock spk_in1_ser amt_in1 extra_outs
RAW = 9


def roll(n, times=1):
    return [n, "OP_ROLL"] * times


def exit_script(depth):
    """witness (bottom..top):
       e31 sha_seqs tapleaf sha_prevouts ver lock spk_in1_ser amt_in1 extra_outs
       zf wf zi wi [levels: 9 each] leaf(10) ea_num ze we sig is_evict r m"""
    s = ["OP_2DUP"] + F.tree_spk_min() + ["OP_TOALTSTACK",          # r m        | spk0
         "OP_TOALTSTACK", "OP_TOALTSTACK"]                         #            | spk0 m r
    # authorisation (as MID, but is_evict need not be kept)
    s += ["OP_IF",
          3, "OP_PICK", "OP_CHECKLOCKTIMEVERIFY", "OP_DROP",
          10, "OP_PICK", "OP_CHECKSIGVERIFY"] + M.padz() + [6, "OP_PICK", "OP_EQUALVERIFY",
          "OP_ELSE", 11, "OP_PICK", "OP_CHECKSIGVERIFY", "OP_2DROP", "OP_DROP",
          "OP_ENDIF"]                                              # leaf(10)
    # payout serialisation out1 = amt8 || 0x22 || 0x5120 || ek  -> alt
    s += [9, "OP_PICK", bytes([0x22, 0x51, 0x20]), "OP_CAT", 9, "OP_PICK", "OP_CAT", "OP_TOALTSTACK"]   # | spk0 m r out1
    s += M.leaf_join() + M.tagged(F.LEAF_PREFIX) + ["OP_FROMALTSTACK"]   # oh os      | spk0 m r out1
    s += [F.NODE_PREFIX, "OP_ROT", "OP_ROT", lt.EMPTY_LEAF_HASH, "OP_0"]  # T oh os E 0
    s += M.levels(False, depth)                                      # T oh os nh ns
    # ---- constructive sighash ----
    s += ["OP_2SWAP"] + roll(6, 2) + M.le64()                        # T nh ns oh S8
    s += ["OP_FROMALTSTACK", "OP_FROMALTSTACK",                      # T nh ns oh S8 out1 r   | spk0 m
          3, "OP_ROLL", "OP_EQUALVERIFY",                            # T nh ns S8 out1
          4, "OP_ROLL", "OP_DROP"]                                   # nh ns S8 out1
    # stack below: raw9 zf wf ; bring zf wf and pad ns
    s += ["OP_ROT"] + roll(5, 2) + M.le64()                          # nh S8 out1 le64(ns)
    s += [3, "OP_ROLL", "OP_FROMALTSTACK"] + F.tree_spk_min()        # S8 out1 le64(ns) spk0'   | spk0
    s += [bytes([0x22]), "OP_SWAP", "OP_CAT", "OP_CAT",              # S8 out1 out0_ser
          "OP_SWAP", "OP_CAT"]                                       # S8 outs01
    return s + sighash_tail()


def sighash_tail():
    """Constructive introspection, shared by every MIN script.
    Stack on entry: raw(9) S8 outs, where S8 is le64 of the tree input's
    amount and outs the serialisation of the constrained leading outputs ;
    altstack: .. spk0, the tree input's scriptPubKey. Ends in the OP_CHECKSIG
    under G that forces the assembled message to be the real one."""
    # raw pieces are now directly below: e31 tapleaf sha_seqs sha_prevouts ver lock spk_in1 amt_in1 extra_outs
    s = [2, "OP_ROLL", "OP_CAT", "OP_SHA256"]                        # S8 sha_outputs
    s += [2, "OP_ROLL", "OP_ROT", "OP_SWAP", "OP_CAT", "OP_SHA256"]  # sha_outputs sha_amounts   (S8||amt_in1)
    s += ["OP_FROMALTSTACK", bytes([0x22]), "OP_SWAP", "OP_CAT",     # ... (22||spk0)
          3, "OP_ROLL", "OP_CAT", "OP_SHA256"]                       # sha_outputs sha_amounts sha_spks
    # message: 00 00 ver lock sha_prevouts sha_amounts sha_spks sha_seqs sha_outputs 02 00000000 tapleaf 00 ffffffff
    s += [3, "OP_ROLL", 4, "OP_ROLL",                                # sha_out sha_amt sha_spk lock ver
          bytes([0, 0]), "OP_SWAP", "OP_CAT", "OP_SWAP", "OP_CAT",   # sha_out sha_amt sha_spk (0000||ver||lock)
          4, "OP_ROLL", "OP_CAT",                                    # sha_out sha_amt sha_spk (..||sha_prevouts)
          "OP_ROT", "OP_CAT", "OP_SWAP", "OP_CAT",                   # sha_out (..||sha_amt||sha_spk)
          3, "OP_ROLL", "OP_CAT", "OP_SWAP", "OP_CAT",               # (..||sha_seqs||sha_out)
          bytes([0x02, 0, 0, 0, 0]), "OP_CAT",
          "OP_SWAP", "OP_CAT",                                       # (..||tapleaf)
          bytes([0x00, 0xff, 0xff, 0xff, 0xff]), "OP_CAT"]           # msg
    s += M.tagged(TAPSIGHASH_PREFIX)                                 # sighash
    s += [G_X + G_X, "OP_SWAP", "OP_CAT"] + M.tagged(CHALLENGE_PREFIX)   # e31 e
    s += ["OP_OVER", bytes([0]), "OP_CAT", "OP_EQUALVERIFY",         # e31        (e31||00 == e)
          G_X, "OP_SWAP", "OP_CAT", bytes([1]), "OP_CAT",            # sig = Gx||e31||01
          G_X, "OP_CHECKSIG"]
    return s


def split_script(depth):
    """SPLIT (spec 7.5.2), dense: CLAIM authorised by the owner's transaction
    signature. The authorisation and both steps are the MID tier's
    (layertree_mid.carve_source and carve_claim); what changes is how the
    result is bound to the transaction. Where MID reads the input's script
    and amount and the tree output with OP_TX, this assembles them into the
    signature message, as EXIT_1 does.

    witness (bottom..top):
       e31 sha_seqs tapleaf sha_prevouts ver lock spk_in1_ser amt_in1 extra_outs
       zf wf [claim levels] zi wi [src levels]
       src(10) new(10) seq_num zq0 wq0 zq1 wq1 zs2 ws2 sea zse wse cea zce wce osig r m
    (the thirteen extras of M.w_carve_extras). Outputs are [tree', <raw
    extra outputs>]: a SPLIT pays nothing out."""
    s = ["OP_2DUP"] + F.tree_spk_min() + ["OP_TOALTSTACK",          # .. osig r m       | spk0
         "OP_DUP", "OP_TOALTSTACK", "OP_SWAP", "OP_TOALTSTACK",     # .. osig m         | spk0 m r
         "OP_DROP", M.CARVE_OWNER_DEPTH, "OP_PICK", "OP_CHECKSIGVERIFY"]   # src(10) new(10) extras(13)
    s += M.carve_source(depth)                                       # T oh os nh ns     | spk0 m new amt_c r
    # as MID check_old, but the input amount is kept for the message
    s += ["OP_2SWAP"] + roll(6, 2) + M.le64()                        # T nh ns oh S8
    s += ["OP_SWAP", "OP_FROMALTSTACK", "OP_EQUALVERIFY",            # T nh ns S8        | spk0 m new amt_c
          "OP_FROMALTSTACK", "OP_FROMALTSTACK", "OP_ROT", "OP_TOALTSTACK"]   # T nh ns amt_c new | spk0 m S8
    s += M.carve_claim(depth)                                        # T nh2 ns2
    # out0 = le64(ns2) || 0x22 || TREE_SPK(nh2, m)
    s += ["OP_ROT", "OP_DROP"] + roll(3, 2) + M.le64()               # nh2 le64(ns2)
    s += ["OP_SWAP", "OP_FROMALTSTACK", "OP_FROMALTSTACK",           # le64(ns2) nh2 S8 m | spk0
          "OP_ROT", "OP_SWAP"] + F.tree_spk_min()                    # le64(ns2) S8 spk0'
    s += [bytes([0x22]), "OP_SWAP", "OP_CAT", "OP_ROT", "OP_SWAP", "OP_CAT"]   # S8 out0
    return s + sighash_tail()


def grind(ctx, mutate, tries=100_000):
    """Vary the transaction with `mutate(ctx, i)` until the challenge e has a
    trailing zero byte. Returns (e31, attempts)."""
    for i in range(tries):
        mutate(ctx, i)
        e = lt.tagged_hash("BIP0340/challenge", G_X + G_X + ctx.sighash())
        if e[-1] == 0:
            return e[:31], i + 1
    raise RuntimeError("grinding failed")


def raw_pieces(ctx, e31, fixed_outputs=2):
    """The nine raw introspection elements, bottom..top. `fixed_outputs` is
    how many leading outputs the script builds itself: two for EXIT_1
    (tree', payout), one for SPLIT (tree')."""
    assert len(ctx.inputs) == 2
    a1, spk1 = ctx.inputs[1]
    extra = b"".join(a.to_bytes(8, "little") + lt.compact_size(len(spk)) + spk
                     for a, spk in ctx.outputs[fixed_outputs:])
    return [e31, ctx.sha_sequences(), ctx.tapleaf_hash, ctx.sha_prevouts(),
            ctx.version.to_bytes(4, "little"), ctx.locktime.to_bytes(4, "little"),
            lt.compact_size(len(spk1)) + spk1, a1.to_bytes(8, "little"), extra]
