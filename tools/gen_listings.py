#!/usr/bin/env python3
"""Generate annotated script listings and the size table for the spec."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import layertree_ref as lt  # noqa: E402
import layertree_scripts as ls  # noqa: E402
from script_sim import assemble, disassemble, pubkey_x  # noqa: E402
import test_scripts  # noqa: E402

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "spec", "scripts")
os.makedirs(OUT, exist_ok=True)

OP_KEY = pubkey_x(lt.sha256(b"operator"))
names = dict(ls.CONST_NAMES)
names[OP_KEY] = "<OPERATOR_KEY>"
for h in range(0, 33):
    names[lt.empty_node(h)[0]] = f"<EMPTY_{h}>"


def listing(name, tokens):
    script = assemble(tokens)
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
            cb = 33 + 32 * 3  # control block for a 5-6 leaf taptree (depth 3)
            rows.append((prof, d, k, sl, wl, cb, sl + wl + cb, it.cost, it.sigchecks))
ls.COMPRESSION["S"] = "bitmap"
for d in (32, 64):
    costs, w = test_scripts.test_all(d, "S", verbose=False)
    for k, (it, sl, wl) in costs.items():
        if k.startswith("EXIT_1 (owner)") or k == "JOIN_0":
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
with open(os.path.join(OUT, "sizes.md"), "w") as f:
    f.write("Witness data for the sparse profile is measured on a 6-leaf tree (compressed proofs);\n")
    f.write("add 40 bytes per additional non-empty sibling (about log2 N in total).\n\n")
    f.write("| profile | D | transition | script (WU) | witness data (WU) | control block (WU) | total witness (WU) | varops used | sigops |\n")
    f.write("|---|---|---|---|---|---|---|---|---|\n")
    for r in rows:
        f.write("| " + " | ".join(str(x) for x in r) + " |\n")
print("wrote listings; test failures:", test_scripts.FAILS)
