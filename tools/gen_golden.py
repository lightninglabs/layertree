#!/usr/bin/env python3
"""Golden vectors for cross-checking the Go implementation against Python.

Writes spec/golden.json with: compiled scripts (hex) per tier/profile/depth,
taptree roots, a BIP-341 sighash vector for a concrete transaction, and the
tree-output scriptPubKey for the example tree.
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import layertree_ref as lt  # noqa: E402
import layertree_scripts as F  # noqa: E402
import layertree_mid as M  # noqa: E402
import layertree_min as N  # noqa: E402
from script_sim import TxContext, assemble, pubkey_x  # noqa: E402

OP_KEY = pubkey_x(lt.sha256(b"operator"))
# RECLAIM_KEY (6.2) of the pending-leaf receive entries below.
RECLAIM_KEY = pubkey_x(lt.sha256(b"operator-reclaim"))
# Every tier's vouchers bind the tree's tree_id (spec 6.2, 7.5), a constant
# of the CLAIM scripts; the vector fixes the RECOMMENDED derivation over a
# placeholder creation outpoint and every CLAIM below is built over it.
TXID = lt.sha256(b"creation-txid")
TREE_ID = lt.tree_id(TXID, 0)
out = {"operator_key": OP_KEY.hex(), "tree_id": {"txid": TXID.hex(), "vout": 0, "tree_id": TREE_ID.hex()},
       "scripts": {}}


def add(tier, profile, depth, name, toks, mode):
    script = assemble(toks, mode)
    out["scripts"][f"{tier}/{profile}/D{depth}/{name}"] = {
        "hex": script.hex(), "leaf_version": 0xc2 if mode == "c2" else 0xc0,
        "tapleaf_hash": lt.tapleaf_hash(script, 0xc2 if mode == "c2" else 0xc0).hex()}


for name, toks in F.all_scripts(4, OP_KEY, (0, 2), (1, 2), "D", (2,), TREE_ID).items():
    add("FULL", "D", 4, name, toks, "c2")
add("FULL", "D", 4, "EVICT_SUBTREE_2", F.evict_subtree_script(4, 2, OP_KEY), "c2")
add("FULL", "D", 16, "EXIT_1", F.exit_script(16, 1, "D"), "c2")
for name, toks in F.all_scripts(8, OP_KEY, (0,), (1,), "S", (2,), TREE_ID).items():
    add("FULL", "S", 8, name, toks, "c2")
for name, toks in M.all_scripts(4, OP_KEY, False, join_heights=(0, 2), exit_ks=(1,), join_ks=(2,), tree_id=TREE_ID).items():
    add("MID", "D", 4, name, toks, "c0")
for name, toks in M.all_scripts(8, OP_KEY, True, exit_ks=(1,), join_ks=(2,), tree_id=TREE_ID).items():
    add("MID", "S", 8, name, toks, "c0")
for h in (1, 2):
    add("MID", "D", 4, f"EVICT_SUBTREE_{h}", M.evict_subtree_script(4, h, OP_KEY), "c0")
add("MIN", "D", 4, "EXIT_1", N.exit_script(4), "c0")
import layertree_ccv as CV  # noqa: E402
for name, toks in CV.all_scripts_ccv(4, OP_KEY, (0, 2), (1, 2), "D", (2,)).items():
    add("CCV", "D", 4, name, toks, "c2")
add("CCV", "D", 4, "EVICT_SUBTREE_2", CV.evict_subtree_script_ccv(4, 2, OP_KEY), "c2")
add("CCV", "D", 16, "EXIT_1", CV.exit_script_ccv(16, 1, "D"), "c2")
for name, toks in CV.all_scripts_ccv(8, OP_KEY, (0,), (1,), "S", (2,)).items():
    add("CCV", "S", 8, name, toks, "c2")
add("CCV", "S", 8, "UPDATE_X", CV.update_script_ccv(8, OP_KEY, "S", exit_consent=True), "c2")
# The CCV tier under 0xC0 numerics (MID encoding), keyed CCV0 so that the
# 0xC2 keys above keep one assembler mode.
for h in (1, 2):
    add("CCV0", "D", 4, f"EVICT_SUBTREE_{h}", CV._evict_subtree_script_ccv0(4, h, OP_KEY), "c0")
add("CCV0", "D", 4, "SPLIT", CV._split_script_ccv0(4, False), "c0")
add("CCV0", "S", 8, "SPLIT", CV._split_script_ccv0(8, True), "c0")
for hl, nm in ((False, "CLAIM"), (True, "CLAIM_H")):
    add("CCV", "D", 4, nm, CV.claim_script_ccv(4, TREE_ID, "D", hl), "c2")
    add("CCV", "S", 8, nm, CV.claim_script_ccv(8, TREE_ID, "S", hl), "c2")
    add("CCV0", "D", 4, nm, CV._claim_script_ccv0(4, TREE_ID, False, hl), "c0")
    add("CCV0", "S", 8, nm, CV._claim_script_ccv0(8, TREE_ID, True, hl), "c0")
for hl, nm in ((False, "CLAIM_X"), (True, "CLAIM_HX")):
    # CLAIM^x and CLAIM^hx (7.5.3) in both numerics.
    add("CCV", "D", 4, nm, CV.claim_script_ccv(4, TREE_ID, "D", hl, exit_consent=True), "c2")
    add("CCV", "S", 8, nm, CV.claim_script_ccv(8, TREE_ID, "S", hl, exit_consent=True), "c2")
    add("CCV0", "D", 4, nm, CV._claim_script_ccv0(4, TREE_ID, False, hl, exit_consent=True), "c0")
    add("CCV0", "S", 8, nm, CV._claim_script_ccv0(8, TREE_ID, True, hl, exit_consent=True), "c0")
add("CCV", "D", 4, "UPDATE_X", CV.update_script_ccv(4, OP_KEY, "D", exit_consent=True), "c2")
# The 0xC0 reference set itself (EXIT_K, JOIN_h, JOINK_K, UPDATE), so that the
# Go ports a CCV0 DETACH_h's m_h is built from are checked one by one.
for name, toks in CV.all_scripts_ccv(4, OP_KEY, (0, 2), (1, 2), "D", (2,), "c0").items():
    if not name.startswith("EVICT_SUBTREE_"):
        add("CCV0", "D", 4, name, toks, "c0")
for name, toks in CV.all_scripts_ccv(8, OP_KEY, (0,), (1,), "S", (2,), "c0").items():
    add("CCV0", "S", 8, name, toks, "c0")
add("CCV0", "D", 4, "UPDATE_X", CV._update_script_ccv0(4, OP_KEY, False, exit_consent=True), "c0")
# DETACH_2 (7.10) in both numerics, over the reference option set at depth 2.
add("CCV", "D", 4, "DETACH_2", CV.detach_script_ccv(4, 2, OP_KEY, CV.detached_taptree_root_ccv(2, OP_KEY, "c2")), "c2")
add("CCV0", "D", 4, "DETACH_2", CV._detach_script_ccv0(4, 2, OP_KEY, CV.detached_taptree_root_ccv(2, OP_KEY, "c0")), "c0")
# REWRITE_2 and REWRITE_2^x (7.9) in both numerics.
add("CCV", "D", 4, "REWRITE_2", CV.rewrite_script_ccv(4, 2, OP_KEY), "c2")
add("CCV", "D", 4, "REWRITE_X_2", CV.rewrite_script_ccv(4, 2, OP_KEY, exit_consent=True), "c2")
add("CCV0", "D", 4, "REWRITE_2", CV._rewrite_script_ccv0(4, 2, OP_KEY), "c0")
add("CCV0", "D", 4, "REWRITE_X_2", CV._rewrite_script_ccv0(4, 2, OP_KEY, exit_consent=True), "c0")

# Tree-creation variants: UPDATE^x, the exit-consent UPDATE (spec 7.4 rule 5),
# CLAIM^h the hash-locked voucher (7.5.1), SPLIT the owner-authorised
# carve (7.5.2), CLAIM^x / CLAIM^hx the exit-consent carves (7.5.3), the
# cohort rewrite REWRITE_h and its ^x form (7.9) and DETACH_h (7.10).
# None is part of the reference taptree, so all are added after the sets
# above and excluded from taptree_full_d4 below.
VARIANTS = ("UPDATE_X", "CLAIM_H", "SPLIT", "CLAIM_X", "CLAIM_HX",
            "REWRITE_2", "REWRITE_X_2", "DETACH_2", "EXIT_1_EXACT", "DETACH_2_HOST",
            "EXIT_1_TOWER", "EXIT_2_TOWER",
            "CLAIM_M", "CLAIM_HM", "RECLAIM_1", "REWRITE_R_2", "REWRITE_XR_2")
add("FULL", "D", 4, "UPDATE_X", F.update_script(4, OP_KEY, "D", exit_consent=True), "c2")
add("FULL", "S", 8, "UPDATE_X", F.update_script(8, OP_KEY, "S", exit_consent=True), "c2")
add("MID", "D", 4, "UPDATE_X", M.update_script(4, OP_KEY, False, exit_consent=True), "c0")
add("MID", "S", 8, "UPDATE_X", M.update_script(8, OP_KEY, True, exit_consent=True), "c0")
add("FULL", "D", 4, "CLAIM_H", F.claim_script(4, TREE_ID, "D", hashlock=True), "c2")
add("FULL", "S", 8, "CLAIM_H", F.claim_script(8, TREE_ID, "S", hashlock=True), "c2")
add("MID", "D", 4, "CLAIM_H", M.claim_script(4, TREE_ID, False, hashlock=True), "c0")
add("MID", "S", 8, "CLAIM_H", M.claim_script(8, TREE_ID, True, hashlock=True), "c0")
add("FULL", "D", 4, "SPLIT", F.split_script(4, "D"), "c2")
add("FULL", "S", 8, "SPLIT", F.split_script(8, "S"), "c2")
add("MID", "D", 4, "SPLIT", M.split_script(4, False), "c0")
add("MID", "S", 8, "SPLIT", M.split_script(8, True), "c0")
add("MIN", "D", 4, "SPLIT", N.split_script(4), "c0")
add("CCV", "D", 4, "SPLIT", CV.split_script_ccv(4, "D"), "c2")
add("CCV", "S", 8, "SPLIT", CV.split_script_ccv(8, "S"), "c2")
add("FULL", "D", 4, "CLAIM_X", F.claim_script(4, TREE_ID, "D", exit_consent=True), "c2")
add("FULL", "S", 8, "CLAIM_X", F.claim_script(8, TREE_ID, "S", exit_consent=True), "c2")
add("FULL", "D", 4, "CLAIM_HX", F.claim_script(4, TREE_ID, "D", hashlock=True, exit_consent=True), "c2")
add("FULL", "S", 8, "CLAIM_HX", F.claim_script(8, TREE_ID, "S", hashlock=True, exit_consent=True), "c2")
add("MID", "D", 4, "CLAIM_X", M.claim_script(4, TREE_ID, False, exit_consent=True), "c0")
add("MID", "S", 8, "CLAIM_X", M.claim_script(8, TREE_ID, True, exit_consent=True), "c0")
add("MID", "D", 4, "CLAIM_HX", M.claim_script(4, TREE_ID, False, hashlock=True, exit_consent=True), "c0")
add("MID", "S", 8, "CLAIM_HX", M.claim_script(8, TREE_ID, True, hashlock=True, exit_consent=True), "c0")
add("FULL", "D", 4, "REWRITE_2", F.rewrite_script(4, 2, OP_KEY), "c2")
add("FULL", "D", 4, "REWRITE_X_2", F.rewrite_script(4, 2, OP_KEY, exit_consent=True), "c2")
add("MID", "D", 4, "REWRITE_2", M.rewrite_script(4, 2, OP_KEY), "c0")
add("MID", "D", 4, "REWRITE_X_2", M.rewrite_script(4, 2, OP_KEY, exit_consent=True), "c0")
# The pending-leaf receive in FULL (spec 0.14.0): CLAIM^m and CLAIM^hm
# (7.5.4), RECLAIM_1 (7.11) and the reclaim form of REWRITE_h and
# REWRITE_h^x (7.9 rule 8), all in a tree that names RECLAIM_KEY.
add("FULL", "D", 4, "CLAIM_M", F.merge_script(4, TREE_ID, reclaim_key=RECLAIM_KEY), "c2")
add("FULL", "D", 4, "CLAIM_HM", F.merge_script(4, TREE_ID, hashlock=True, reclaim_key=RECLAIM_KEY), "c2")
add("FULL", "D", 4, "RECLAIM_1", F.reclaim_script(4, RECLAIM_KEY, "D"), "c2")
add("FULL", "S", 8, "RECLAIM_1", F.reclaim_script(8, RECLAIM_KEY, "S"), "c2")
add("FULL", "D", 4, "REWRITE_R_2", F.rewrite_script(4, 2, OP_KEY, reclaim_key=RECLAIM_KEY), "c2")
add("FULL", "D", 4, "REWRITE_XR_2", F.rewrite_script(4, 2, OP_KEY, exit_consent=True, reclaim_key=RECLAIM_KEY), "c2")
add("FULL", "D", 4, "DETACH_2", F.detach_script(4, 2, OP_KEY, F.detached_taptree_root(2, OP_KEY, TREE_ID)), "c2")
# EXIT_1^= (7.2 rule 6) and the DETACH_2 of a channel-hosting parent (exact
# payouts, CLAIM^h, DETACH_2): its m_h is that option set compiled at depth
# 2 (7.10 rule 3), which the Go FullTreeOptions must reproduce.
add("FULL", "D", 4, "EXIT_1_EXACT", F.exit_script(4, 1, "D", exact=True), "c2")
HOST = F.TreeOptions(OP_KEY, TREE_ID, exact=True, claim_h=True, detach_heights=(2,))
add("FULL", "D", 4, "DETACH_2_HOST", F.detach_script(4, 2, OP_KEY, F.detached_taptree_root(2, OP_KEY, TREE_ID, HOST)), "c2")
# DETACH_2 under MID (7.10, 8.10): over the reference option set at depth 2,
# and over a channel-hosting parent (EXIT_K^t, CLAIM^h, DETACH_2), whose m_h
# the Go MidTreeOptions must reproduce.
add("MID", "D", 4, "DETACH_2", M.detach_script(4, 2, OP_KEY, M.detached_taptree_root(2, OP_KEY, TREE_ID)), "c0")
MID_HOST = M.TreeOptions(OP_KEY, TREE_ID, tower=True, claim_h=True, detach_heights=(2,))
add("MID", "D", 4, "DETACH_2_HOST", M.detach_script(4, 2, OP_KEY, M.detached_taptree_root(2, OP_KEY, TREE_ID, MID_HOST)), "c0")
# EXIT_K^t (7.2 rule 7), the tower-delegable exit, in every tier that has
# OP_CHECKSIGFROMSTACK (FULL, MID, CCV in both numerics), over the same
# tree_id as CLAIM; a constant of the script, as there.
add("FULL", "D", 4, "EXIT_1_TOWER", F.exit_script(4, 1, "D", tower=True, tree_id=TREE_ID), "c2")
add("FULL", "D", 4, "EXIT_2_TOWER", F.exit_script(4, 2, "D", tower=True, tree_id=TREE_ID), "c2")
add("FULL", "S", 8, "EXIT_1_TOWER", F.exit_script(8, 1, "S", tower=True, tree_id=TREE_ID), "c2")
add("MID", "D", 4, "EXIT_1_TOWER", M.exit_script(4, 1, False, tower=True, tree_id=TREE_ID), "c0")
add("MID", "S", 8, "EXIT_1_TOWER", M.exit_script(8, 1, True, tower=True, tree_id=TREE_ID), "c0")
add("CCV", "D", 4, "EXIT_1_TOWER", CV.exit_script_ccv(4, 1, "D", tower=True, tree_id=TREE_ID), "c2")
add("CCV", "S", 8, "EXIT_1_TOWER", CV.exit_script_ccv(8, 1, "S", tower=True, tree_id=TREE_ID), "c2")
add("CCV0", "D", 4, "EXIT_1_TOWER", CV._exit_script_ccv0(4, 1, False, tower=True, tree_id=TREE_ID), "c0")
add("CCV0", "S", 8, "EXIT_1_TOWER", CV._exit_script_ccv0(8, 1, True, tower=True, tree_id=TREE_ID), "c0")

# ---- MID: the pending-leaf receive (7.5.4, 7.9 rule 8, 7.11) ----
# CLAIM^m and CLAIM^hm (dense only), RECLAIM_1 in both profiles, and the
# reclaim form of REWRITE_2 and REWRITE_2^x, all over RECLAIM_KEY below.
# Tree-creation variants, so out of taptree_full_d4 (the names are added
# to VARIANTS here as well as by the FULL block; duplicates are harmless).
VARIANTS = VARIANTS + ("CLAIM_M", "CLAIM_HM", "RECLAIM_1", "REWRITE_R_2", "REWRITE_XR_2")
MID_RECLAIM_KEY = pubkey_x(lt.sha256(b"operator-reclaim"))
add("MID", "D", 4, "CLAIM_M", M.merge_script(4, TREE_ID, reclaim_key=MID_RECLAIM_KEY), "c0")
add("MID", "D", 4, "CLAIM_HM", M.merge_script(4, TREE_ID, hashlock=True, reclaim_key=MID_RECLAIM_KEY), "c0")
add("MID", "D", 4, "RECLAIM_1", M.reclaim_script(4, MID_RECLAIM_KEY), "c0")
add("MID", "S", 8, "RECLAIM_1", M.reclaim_script(8, MID_RECLAIM_KEY, sparse=True), "c0")
add("MID", "D", 4, "REWRITE_R_2", M.rewrite_script(4, 2, OP_KEY, reclaim_key=MID_RECLAIM_KEY), "c0")
add("MID", "D", 4, "REWRITE_XR_2", M.rewrite_script(4, 2, OP_KEY, exit_consent=True,
                                                    reclaim_key=MID_RECLAIM_KEY), "c0")
# ---- end MID pending-leaf receive ----
# The pending-leaf receive under CCV, both numerics (6.2, 7.5.4, 7.9 rule 8,
# 7.11): CLAIM^m and CLAIM^hm over the tree_id above, RECLAIM_1 and the
# reclaim form of REWRITE_2 and REWRITE_2^x, over RECLAIM_KEY; tree-creation
# variants whose names VARIANTS already carries for FULL.
for _tier, _mode, _merge, _reclaim, _rewrite in (
        ("CCV", "c2", CV.merge_script_ccv, lambda d, s: CV.reclaim_script_ccv(d, RECLAIM_KEY, "S" if s else "D"),
         lambda x: CV.rewrite_script_ccv(4, 2, OP_KEY, exit_consent=x, reclaim_key=RECLAIM_KEY)),
        ("CCV0", "c0", CV._merge_script_ccv0, lambda d, s: CV._reclaim_script_ccv0(d, RECLAIM_KEY, s),
         lambda x: CV._rewrite_script_r_ccv0(4, 2, OP_KEY, RECLAIM_KEY, exit_consent=x))):
    add(_tier, "D", 4, "CLAIM_M", _merge(4, TREE_ID, False, RECLAIM_KEY), _mode)
    add(_tier, "D", 4, "CLAIM_HM", _merge(4, TREE_ID, True, RECLAIM_KEY), _mode)
    add(_tier, "D", 4, "RECLAIM_1", _reclaim(4, False), _mode)
    add(_tier, "S", 8, "RECLAIM_1", _reclaim(8, True), _mode)
    add(_tier, "D", 4, "REWRITE_R_2", _rewrite(False), _mode)
    add(_tier, "D", 4, "REWRITE_XR_2", _rewrite(True), _mode)
out["reclaim_key"] = RECLAIM_KEY.hex()

# taptree root for the FULL/D/D4 script set, in insertion order
scripts = [bytes.fromhex(v["hex"]) for k, v in out["scripts"].items()
           if k.startswith("FULL/D/D4/") and not k.rsplit("/", 1)[1] in VARIANTS]
out["taptree_full_d4"] = {"leaf_hashes": [lt.tapleaf_hash(s).hex() for s in scripts],
                          "merkle_root": lt.taptree_root([lt.tapleaf_hash(s) for s in scripts]).hex()}

# sighash vector: 2 inputs, 3 outputs, script-path spend of input 0
root_hash = bytes.fromhex("832c706c54d0e0751ff32edf2242820cad9bf2e1af4aa41204bf61036b0dc0b0")
m = out["taptree_full_d4"]["merkle_root"]
spk0 = lt.tree_spk(root_hash, bytes.fromhex(m))
ctx = TxContext([(1_175_000, spk0), (50_000, bytes.fromhex("0014") + bytes(20))],
                [(1_050_000, lt.tree_spk(lt.sha256(b"new root"), bytes.fromhex(m))),
                 (124_000, lt.p2tr_spk(lt.sha256(b"exit key x"))), (49_000, bytes.fromhex("0014") + bytes(20))],
                locktime=800_000, sequences=[0xfffffffd, 0xfffffffe],
                prevouts=[(lt.sha256(b"prev0"), 1), (lt.sha256(b"prev1"), 0)],
                tapleaf_hash=bytes.fromhex(out["scripts"]["FULL/D/D4/EXIT_1"]["tapleaf_hash"]))
out["sighash_vector"] = {
    "version": ctx.version, "locktime": ctx.locktime,
    "inputs": [{"txid": t.hex(), "vout": v, "amount": a, "scriptPubKey": s.hex(), "sequence": q}
               for (t, v), (a, s), q in zip(ctx.prevouts, ctx.inputs, ctx.sequences)],
    "outputs": [{"amount": a, "scriptPubKey": s.hex()} for a, s in ctx.outputs],
    "input_index": 0, "tapleaf_hash": ctx.tapleaf_hash.hex(),
    "sighash_msg": ctx.sighash_msg().hex(), "sighash": ctx.sighash().hex(),
    "note": "txid is the internal byte order hash as serialized in the prevout",
}
out["tree_spk_vector"] = {"root_hash": root_hash.hex(), "merkle_root": m,
                          "internal_key": lt.internal_key(root_hash).hex(), "scriptPubKey": spk0.hex()}

# Channel leaves (Appendix C): the C.2.2 context, the C.3 scripts in both
# tapleaf versions, the C.4.1 HTLC leaves, the funding and update output
# keys, and the [C-A1] collations with their signed messages.
# chan_id binds the host tree's tree_id (C.2.2, spec 6.2), the same
# constant the vouchers above bind, so this section no longer moves with
# the D4 merkle root.
import layertree_chan as CH  # noqa: E402
_p = pubkey_x(lt.sha256(b"P_chan"))
_owner = pubkey_x(lt.sha256(b"alice-owner"))
_ch = CH.Channel(TREE_ID, _owner, 7, _p, 1_000_000, 0, 144)
_ph, _yk, _xk = lt.sha256(b"htlc-preimage"), pubkey_x(lt.sha256(b"V-claim")), pubkey_x(lt.sha256(b"U-claim"))
_n = 5
chan = {"params": {"tree_id": TREE_ID.hex(), "owner_key": _owner.hex(), "nonce": 7, "p_chan": _p.hex(),
                   "capacity": 1_000_000, "epoch": 0, "csv_delay": 144, "state": _n,
                   "payment_hash": _ph.hex(), "htlc_claim_key": _yk.hex(), "htlc_refund_key": _xk.hex(),
                   "cltv_expiry": 800_400},
        "chan_id": _ch.chan_id.hex(), "ctx_upd": _ch.ctx_upd.hex(), "ctx_set": _ch.ctx_set.hex(),
        "scripts": {}}
for _mode in ("c2", "c0"):
    _v = 0xc2 if _mode == "c2" else 0xc0
    for _name, _toks in (("UPD_F", CH.upd_f_script(_ch.ctx_upd, _p)),
                         ("REBIND_%d" % _n, CH.rebind_script(_n, _ch.ctx_upd, _p)),
                         ("SETTLE", CH.settle_script(144, _ch.ctx_set, _p)),
                         ("HTLC_SUCCESS", CH.htlc_success_script(_ph, _yk)),
                         ("HTLC_TIMEOUT", CH.htlc_timeout_script(800_400, _xk))):
        _s = assemble(_toks, _mode)
        chan["scripts"][f"{_mode.upper()}/{_name}"] = {"hex": _s.hex(), "leaf_version": _v,
                                                        "tapleaf_hash": lt.tapleaf_hash(_s, _v).hex()}
chan["exit_key"] = _ch.exit_key.hex()
chan["update_output_spk"] = _ch.update_output(_n).spk.hex()
_htlc = CH.htlc_output(_p, _ph, 800_400, _xk, _yk)
_ut = _ch.update_tx(_n)
_st = _ch.settle_tx(_n, _ch.settle_outputs(600_000, 340_000, _owner, _yk, [(60_000, _htlc)]))
for _label, _tx, _sel, _msg in (("update", _ut, CH.SEL_CHAN_UPD, CH.msg_upd(_ch.ctx_upd, _ut)),
                                ("settle", _st, CH.SEL_CHAN_SET, CH.msg_set(_ch.ctx_set, _st))):
    chan[_label + "_tx"] = {
        "version": _tx.version, "locktime": _tx.locktime, "sequence": _tx.sequences[0],
        "spent_amount": _tx.inputs[0][0], "spent_spk": _tx.inputs[0][1].hex(),
        "outputs": [{"amount": a, "scriptPubKey": s.hex()} for a, s in _tx.outputs],
        "selector": _sel, "collation": CH.collate(_tx, _sel).hex(), "msg": _msg.hex()}
out["chan"] = chan

path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "spec", "golden.json")
with open(path, "w") as f:
    json.dump(out, f, indent=1)
print("wrote", path, len(out["scripts"]), "scripts")
