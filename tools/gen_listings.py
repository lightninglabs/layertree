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
for name, toks in ls.all_scripts(D, OP_KEY, (0, 2), (1, 2)).items():
    with open(os.path.join(OUT, f"{name}_D{D}.txt"), "w") as f:
        f.write(listing(f"{name} (D={D})", toks))
with open(os.path.join(OUT, "LEVEL.txt"), "w") as f:
    f.write(listing("LEVEL macro (one merkle-sum level, both accumulators)", ls.level()))
with open(os.path.join(OUT, "TREE_SPK.txt"), "w") as f:
    f.write(listing("TREE_SPK macro ([root m] -> [scriptPubKey])", ls.tree_spk()))

rows = []
for d in (8, 12, 16, 20):
    costs, w = test_scripts.test_all(d, verbose=False)
    for k, (it, sl, wl) in costs.items():
        cb = 33 + 32 * 3  # control block for a 5-leaf taptree (depth 3)
        rows.append((d, k, sl, wl, cb, sl + wl + cb, it.cost, it.sigchecks))
with open(os.path.join(OUT, "sizes.md"), "w") as f:
    f.write("| D | transition | script (WU) | witness data (WU) | control block (WU) | total witness (WU) | varops used | sigops |\n")
    f.write("|---|---|---|---|---|---|---|---|\n")
    for r in rows:
        f.write("| " + " | ".join(str(x) for x in r) + " |\n")
print("wrote listings; test failures:", test_scripts.FAILS)
