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
out = {"operator_key": OP_KEY.hex(), "scripts": {}}


def add(tier, profile, depth, name, toks, mode):
    script = assemble(toks, mode)
    out["scripts"][f"{tier}/{profile}/D{depth}/{name}"] = {
        "hex": script.hex(), "leaf_version": 0xc2 if mode == "c2" else 0xc0,
        "tapleaf_hash": lt.tapleaf_hash(script, 0xc2 if mode == "c2" else 0xc0).hex()}


for name, toks in F.all_scripts(4, OP_KEY, (0, 2), (1, 2), "D", (2,)).items():
    add("FULL", "D", 4, name, toks, "c2")
add("FULL", "D", 4, "EVICT_SUBTREE_2", F.evict_subtree_script(4, 2, OP_KEY), "c2")
add("FULL", "D", 16, "EXIT_1", F.exit_script(16, 1, "D"), "c2")
for name, toks in F.all_scripts(8, OP_KEY, (0,), (1,), "S", (2,)).items():
    add("FULL", "S", 8, name, toks, "c2")
for name, toks in M.all_scripts(4, OP_KEY, False, join_heights=(0, 2), exit_ks=(1,), join_ks=(2,)).items():
    add("MID", "D", 4, name, toks, "c0")
for name, toks in M.all_scripts(8, OP_KEY, True, exit_ks=(1,), join_ks=(2,)).items():
    add("MID", "S", 8, name, toks, "c0")
add("MIN", "D", 4, "EXIT_1", N.exit_script(4), "c0")
import layertree_ccv as CV  # noqa: E402
for name, toks in CV.all_scripts_ccv(4, OP_KEY, (0, 2), (1, 2), "D", (2,)).items():
    add("CCV", "D", 4, name, toks, "c2")
add("CCV", "D", 4, "EVICT_SUBTREE_2", CV.evict_subtree_script_ccv(4, 2, OP_KEY), "c2")
add("CCV", "D", 16, "EXIT_1", CV.exit_script_ccv(16, 1, "D"), "c2")
for name, toks in CV.all_scripts_ccv(8, OP_KEY, (0,), (1,), "S", (2,)).items():
    add("CCV", "S", 8, name, toks, "c2")
add("CCV", "S", 8, "UPDATE_X", CV.update_script_ccv(8, OP_KEY, "S", exit_consent=True), "c2")
add("CCV", "D", 4, "UPDATE_X", CV.update_script_ccv(4, OP_KEY, "D", exit_consent=True), "c2")

# Tree-creation variants: UPDATE^x, the exit-consent UPDATE (spec 7.4 rule 5),
# CLAIM^h the hash-locked voucher (7.5.1), and SPLIT the owner-authorised
# carve (7.5.2). None is part of the reference taptree, so all are added
# after the sets above and excluded from taptree_full_d4 below.
VARIANTS = ("UPDATE_X", "CLAIM_H", "SPLIT")
add("FULL", "D", 4, "UPDATE_X", F.update_script(4, OP_KEY, "D", exit_consent=True), "c2")
add("FULL", "S", 8, "UPDATE_X", F.update_script(8, OP_KEY, "S", exit_consent=True), "c2")
add("MID", "D", 4, "UPDATE_X", M.update_script(4, OP_KEY, False, exit_consent=True), "c0")
add("MID", "S", 8, "UPDATE_X", M.update_script(8, OP_KEY, True, exit_consent=True), "c0")
add("FULL", "D", 4, "CLAIM_H", F.claim_script(4, "D", hashlock=True), "c2")
add("FULL", "S", 8, "CLAIM_H", F.claim_script(8, "S", hashlock=True), "c2")
add("MID", "D", 4, "CLAIM_H", M.claim_script(4, False, hashlock=True), "c0")
add("MID", "S", 8, "CLAIM_H", M.claim_script(8, True, hashlock=True), "c0")
add("FULL", "D", 4, "SPLIT", F.split_script(4, "D"), "c2")
add("FULL", "S", 8, "SPLIT", F.split_script(8, "S"), "c2")
add("MID", "D", 4, "SPLIT", M.split_script(4, False), "c0")
add("MID", "S", 8, "SPLIT", M.split_script(8, True), "c0")

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
path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "spec", "golden.json")
with open(path, "w") as f:
    json.dump(out, f, indent=1)
print("wrote", path, len(out["scripts"]), "scripts")
