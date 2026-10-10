#!/usr/bin/env python3
"""Generate annotated script listings and the size table for the spec."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import layertree_ref as lt  # noqa: E402
import layertree_scripts as ls  # noqa: E402
from script_sim import assemble, disassemble, pubkey_x  # noqa: E402
import test_scripts  # noqa: E402
import test_mid  # noqa: E402
import test_min  # noqa: E402
import layertree_mid as LM  # noqa: E402
import layertree_min as LN  # noqa: E402

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "spec", "scripts")
os.makedirs(OUT, exist_ok=True)

OP_KEY = pubkey_x(lt.sha256(b"operator"))
names = dict(ls.CONST_NAMES)
names[OP_KEY] = "<OPERATOR_KEY>"
for h in range(0, 33):
    names[lt.empty_node(h)[0]] = f"<EMPTY_{h}>"


def listing(name, tokens):
    mode = "c0" if ("MID" in name or "MIN" in name or "PADZ" in name) else "c2"
    script = assemble(tokens, mode)
    words = disassemble(script, names)
    lines = [f"# {name}: {len(script)} bytes", ""]
    line = ""
    for w in words:
        if len(line) + len(w) + 1 > 78:
            lines.append(line.rstrip())
            line = ""
        line += w + " "
    lines.append(line.rstrip())
    return "\n".join(lines) + "\n"


D = 4
for name, toks in ls.all_scripts(D, OP_KEY, (0, 2), (1, 2), "D").items():
    with open(os.path.join(OUT, f"{name}_D{D}.txt"), "w") as f:
        f.write(listing(f"{name} (dense, D={D})", toks))
for name, toks in ls.all_scripts(8, OP_KEY, (0,), (1,), "S").items():
    with open(os.path.join(OUT, f"{name}_S8.txt"), "w") as f:
        f.write(listing(f"{name} (sparse, D=8)", toks))
# Tree-creation variants (spec 7.4 rule 5, 7.5.1); not part of all_scripts().
with open(os.path.join(OUT, f"UPDATE_X_D{D}.txt"), "w") as f:
    f.write(listing(f"UPDATE_X (exit-key consent, dense, D={D})",
                    ls.update_script(D, OP_KEY, "D", exit_consent=True)))
with open(os.path.join(OUT, f"CLAIM_H_D{D}.txt"), "w") as f:
    f.write(listing(f"CLAIM_H (hash-locked voucher, dense, D={D})",
                    ls.claim_script(D, "D", hashlock=True)))
with open(os.path.join(OUT, f"SPLIT_D{D}.txt"), "w") as f:
    f.write(listing(f"SPLIT (owner-authorised carve, dense, D={D})",
                    ls.split_script(D, "D")))
with open(os.path.join(OUT, f"CLAIM_X_D{D}.txt"), "w") as f:
    f.write(listing(f"CLAIM_X (exit-key consent, dense, D={D})",
                    ls.claim_script(D, "D", exit_consent=True)))
with open(os.path.join(OUT, "LEVEL.txt"), "w") as f:
    f.write(listing("LEVEL (dense): one merkle-sum level, both accumulators", ls.level_dense()))
    f.write("\n")
    f.write(listing("LEVEL_S (sparse, k=5): derives dir from pos, computes E_k", ls.level_sparse(5)))
with open(os.path.join(OUT, "TREE_SPK.txt"), "w") as f:
    f.write(listing("TREE_SPK macro ([root m] -> [scriptPubKey])", ls.tree_spk()))

rows = []
for prof, depths in (("D", (8, 12, 16, 20)), ("S", (32, 64, 256))):
    for d in depths:
        costs, w = test_scripts.test_all(d, prof, verbose=False)
        for k, (it, sl, wl) in costs.items():
            cb = 33 + 32 * 3  # control block for the 8-leaf reference set (depth 3)
            rows.append((prof, d, k, sl, wl, cb, sl + wl + cb, it.cost, it.sigchecks))
for prof, d in (("D", 16), ("S", 32)):
    it, sl, wl = test_scripts.test_update_x(d, prof, verbose=False)
    rows.append((prof, d, "UPDATE_X", sl, wl, 129, sl + wl + 129, it.cost, it.sigchecks))
for prof, d in (("D", 16), ("S", 32)):
    it, sl, wl = test_scripts.test_claim_h(d, prof, verbose=False)
    rows.append((prof, d, "CLAIM_H", sl, wl, 129, sl + wl + 129, it.cost, it.sigchecks))
for prof, d in (("D", 16), ("S", 32)):
    it, sl, wl = test_scripts.test_split(d, prof, verbose=False)
    rows.append((prof, d, "SPLIT", sl, wl, 129, sl + wl + 129, it.cost, it.sigchecks))
for prof, d in (("D", 16), ("S", 32)):
    for hl, name in ((False, "CLAIM_X"), (True, "CLAIM_HX")):
        it, sl, wl = test_scripts.test_claim_x(d, prof, hashlock=hl, verbose=False)
        rows.append((prof, d, name, sl, wl, 129, sl + wl + 129, it.cost, it.sigchecks))
ls.COMPRESSION["S"] = "bitmap"
for d in (32, 64):
    costs, w = test_scripts.test_all(d, "S", verbose=False)
    for k, (it, sl, wl) in costs.items():
        if k.startswith("EXIT_1 (owner)") or k in ("JOIN_0", "JOINK_2"):
            rows.append(("S/bitmap", d, k, sl, wl, 129, sl + wl + 129, it.cost, it.sigchecks))
ls.COMPRESSION["S"] = "empty"
for d in (8, 16):
    script, wit, it = test_scripts.test_minimal(d, verbose=False)
    rows.append(("D/minimal", d, "EXIT_1 (owner)", len(script), sum(len(x) for x in wit), 129,
                 len(script) + sum(len(x) for x in wit) + 129, it.cost, it.sigchecks))
with open(os.path.join(OUT, "LEVEL.txt"), "a") as f:
    f.write("\n")
    f.write(listing("LEVEL_MIN (minimal inventory): sibling as two elements, CAT-only padding", ls.level_min()))
with open(os.path.join(OUT, "TREE_SPK.txt"), "a") as f:
    f.write("\n")
    f.write(listing("TREE_SPK_MIN (BIP-449 OP_TWEAKADD)", ls.tree_spk_min()))
with open(os.path.join(OUT, "EXIT_1_MIN_D4.txt"), "w") as f:
    f.write(listing("EXIT_1 (minimal inventory, dense, D=4)", ls.exit_script_min(4)))
for d, h in ((16, 2), (16, 4), (16, 6), (20, 8)):
    script, wit, it = test_scripts.test_evict_subtree(d, h, verbose=False)
    n = 1 << h
    rows.append(("D/subtree", d, f"EVICT_SUBTREE_{h} ({n} positions)", len(script), sum(len(x) for x in wit), 129,
                 len(script) + sum(len(x) for x in wit) + 129, it.cost, it.sigchecks))
    rows.append(("D", d, f"EXIT_{n} (evictions, for comparison)", len(assemble(ls.exit_script(d, n, "D"))),
                 "-", 129, "-", "-", n))
with open(os.path.join(OUT, "EVICT_SUBTREE_2_D8.txt"), "w") as f:
    f.write(listing("EVICT_SUBTREE_2 (dense, D=8): cohort sweep of a 4-position subtree", ls.evict_subtree_script(8, 2, OP_KEY)))
# ---- opcode tiers: MID (0xC0 + CAT + OP_TX + CSFS + TWEAKADD) and MIN (0xC0 + CAT + TWEAKADD)
for d, sparse in ((16, False), (31, True)):
    costs, w = test_mid.test_mid(d, sparse, verbose=False)
    for k, (it, sl, wl) in costs.items():
        rows.append(("MID/" + ("S" if sparse else "D"), d, k, sl, wl, 129, sl + wl + 129, "n/a (0xC0)", it.sigchecks))
for d, sparse in ((16, False), (31, True)):
    it, sl, wl = test_mid.test_update_x(d, sparse, verbose=False)
    rows.append(("MID/" + ("S" if sparse else "D"), d, "UPDATE_X", sl, wl, 129,
                 sl + wl + 129, "n/a (0xC0)", it.sigchecks))
for d, sparse in ((16, False), (31, True)):
    it, sl, wl = test_mid.test_claim_h(d, sparse, verbose=False)
    rows.append(("MID/" + ("S" if sparse else "D"), d, "CLAIM_H", sl, wl, 129,
                 sl + wl + 129, "n/a (0xC0)", it.sigchecks))
for d, sparse in ((16, False), (31, True)):
    it, sl, wl = test_mid.test_split(d, sparse, verbose=False)
    rows.append(("MID/" + ("S" if sparse else "D"), d, "SPLIT", sl, wl, 129,
                 sl + wl + 129, "n/a (0xC0)", it.sigchecks))
script, wit, it = test_min.test_min(16, verbose=False)
rows.append(("MIN/D", 16, "EXIT_1 (owner)", len(script), sum(len(x) for x in wit), 129,
             len(script) + sum(len(x) for x in wit) + 129, "n/a (0xC0)", it.sigchecks))
script, wit, it = test_min.test_split(16, verbose=False)
rows.append(("MIN/D", 16, "SPLIT", len(script), sum(len(x) for x in wit), 129,
             len(script) + sum(len(x) for x in wit) + 129, "n/a (0xC0)", it.sigchecks))
for name, toks in LM.all_scripts(4, OP_KEY, False, join_heights=(0, 2), exit_ks=(1,), join_ks=(2,)).items():
    with open(os.path.join(OUT, f"MID_{name}_D4.txt"), "w") as f:
        f.write(listing(f"{name} (MID tier, dense, D=4)", toks))
with open(os.path.join(OUT, "MID_UPDATE_X_D4.txt"), "w") as f:
    f.write(listing("UPDATE_X (MID tier, dense, D=4)",
                    LM.update_script(4, OP_KEY, False, exit_consent=True)))
with open(os.path.join(OUT, "MID_CLAIM_H_D4.txt"), "w") as f:
    f.write(listing("CLAIM_H (MID tier, hash-locked voucher, dense, D=4)",
                    LM.claim_script(4, False, hashlock=True)))
with open(os.path.join(OUT, "MID_SPLIT_D4.txt"), "w") as f:
    f.write(listing("SPLIT (MID tier, owner-authorised carve, dense, D=4)",
                    LM.split_script(4, False)))
with open(os.path.join(OUT, "MIN_EXIT_1_D4.txt"), "w") as f:
    f.write(listing("EXIT_1 (MIN tier, dense, D=4)", LN.exit_script(4)))
with open(os.path.join(OUT, "MIN_SPLIT_D4.txt"), "w") as f:
    f.write(listing("SPLIT (MIN tier, owner-authorised carve, dense, D=4)", LN.split_script(4)))
with open(os.path.join(OUT, "LEVEL.txt"), "a") as f:
    f.write("\n")
    f.write(listing("LEVEL_MID (dense): PADZ gadgets, sibling as hash + number", LM.level(False)))
    f.write("\n")
    f.write(listing("PADZ gadget: [x z w] -> [le32(x)]", LM.padz()))

# ---- CCV tier (BIP-443 OP_CHECKCONTRACTVERIFY; spec 4.6) ----
import layertree_ccv as CV  # noqa: E402
import test_ccv  # noqa: E402
for d, prof in ((16, "D"), (32, "S")):
    costs = test_ccv.test_all(d, prof, verbose=False)
    for k, (it, sl, wl) in costs.items():
        rows.append(("CCV/" + prof, d, k, sl, wl, 129, sl + wl + 129, it.cost, it.sigchecks))
    for k, fn in (("UPDATE_X", test_ccv.test_update_x_ccv), ("SPLIT", test_ccv.test_split_ccv)):
        it, sl, wl = fn(d, prof)
        rows.append(("CCV/" + prof, d, k, sl, wl, 129, sl + wl + 129, it.cost, it.sigchecks))
for d, prof in ((16, "D"), (31, "S")):
    costs = test_ccv.test_c0(d, prof)
    for k, (it, sl, wl) in costs.items():
        rows.append(("CCV-c0/" + prof, d, k, sl, wl, 129, sl + wl + 129, "n/a (0xC0)", it.sigchecks))
for name, toks in CV.all_scripts_ccv(4, OP_KEY, (0, 2), (1, 2), "D", (2,)).items():
    with open(os.path.join(OUT, f"CCV_{name}_D4.txt"), "w") as f:
        f.write(listing(f"{name} (CCV tier, dense, D=4)", toks))
for name, toks in CV.all_scripts_ccv(8, OP_KEY, (0,), (1,), "S", (2,)).items():
    with open(os.path.join(OUT, f"CCV_{name}_S8.txt"), "w") as f:
        f.write(listing(f"{name} (CCV tier, sparse, D=8)", toks))
with open(os.path.join(OUT, "CCV_UPDATE_X_D4.txt"), "w") as f:
    f.write(listing("UPDATE_X (CCV tier, dense, D=4)",
                    CV.update_script_ccv(4, OP_KEY, "D", exit_consent=True)))
with open(os.path.join(OUT, "CCV_SPLIT_D4.txt"), "w") as f:
    f.write(listing("SPLIT (CCV tier, owner-authorised carve, dense, D=4)",
                    CV.split_script_ccv(4, "D")))
with open(os.path.join(OUT, "CCV_LEVEL.txt"), "w") as f:
    f.write(listing("CCV_CHECK_INPUT macro ([data] -> []): BIP-443 CHECK_INPUT on the current input", CV.ccv_check_input()))
    f.write("\n")
    f.write(listing("CCV_TREE_OUTPUT macro ([data] -> []): BIP-443 CHECK_OUTPUT assign on output 0", CV.ccv_tree_output(0)))
    f.write("\n")
    f.write(listing("CCV_PAYOUT macro ([leaf] -> [leaf]): BIP-443 CHECK_OUTPUT|DEDUCT on the exit key", CV.ccv_payout_fixed(1)))

with open(os.path.join(OUT, "sizes.md"), "w") as f:
    f.write("Witness data for the sparse profile is measured on a 6-leaf tree (compressed proofs);\n")
    f.write("add 41 bytes per additional non-empty sibling (about log2 N in total).\n\n")
    f.write("| profile | D | transition | script (B) | witness data (B) | control block (B) | total witness (WU) | varops used | sigops |\n")
    f.write("|---|---|---|---|---|---|---|---|---|\n")
    for r in rows:
        f.write("| " + " | ".join(str(x) for x in r) + " |\n")
print("wrote listings; test failures:", test_scripts.FAILS)
