#!/usr/bin/env python3
"""Structured script listings: every script collapsed into named macro calls.

Tapscript has no subroutines, so the compiled scripts of spec/scripts/ are
long flat opcode streams. The generators, however, build every script from
a small set of Python helpers (TREE_SPK, LEVEL, CHECK_OLD, FINAL, PADZ, ...).
This tool recovers that structure after the fact: it disassembles each
compiled script into tokens, greedily matches the token sequences of the
known macros (longest first), and prints one macro call per line with the
remaining raw opcodes wrapped between them. Each tier gets a MACROS file
with every macro's expansion (itself collapsed against the other macros).

The collapse is verified: expanding the structured listing must reproduce
the original token sequence exactly, so the structured and flat listings
describe the same bytes.

Outputs: spec/scripts/structured/<script>.txt and MACROS_{FULL,MID,MIN}.txt.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import layertree_ref as lt  # noqa: E402
import layertree_scripts as F  # noqa: E402
import layertree_mid as M  # noqa: E402
import layertree_min as N  # noqa: E402
from script_sim import assemble, disassemble, pubkey_x  # noqa: E402

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "spec", "scripts", "structured")
os.makedirs(OUT, exist_ok=True)

OP_KEY = pubkey_x(lt.sha256(b"operator"))
NAMES = dict(F.CONST_NAMES)
NAMES[OP_KEY] = "<OPERATOR_KEY>"
NAMES[N.TAPSIGHASH_PREFIX] = "<TAG_TAPSIGHASH>"
NAMES[N.CHALLENGE_PREFIX] = "<TAG_CHALLENGE>"
NAMES[N.G_X] = "<G_X>"
NAMES[N.G_X + N.G_X] = "<G_X||G_X>"
NAMES[M.ENC64_SUFFIX] = "<00000000_01>"
for h in range(0, 65):
    NAMES[lt.empty_node(h)[0]] = f"<EMPTY_{h}>"

WIDTH = 78


def words(tokens, mode):
    return tuple(disassemble(assemble(tokens, mode), NAMES))


# ---------------------------------------------------------------- macro tables
def full_macros():
    t = []
    for tag, pre in (("LEAF", F.LEAF_PREFIX), ("NODE", F.NODE_PREFIX), ("STATE", F.STATE_PREFIX),
                     ("VOUCHER", F.VOUCHER_PREFIX), ("POS", F.POS_PREFIX), ("TAPTWEAK", F.TAPTWEAK_PREFIX)):
        t.append((f"TAGGED({tag})", F.tagged(pre)))
    t += [("PAD8", F.PAD8), ("LE64", F.LE64), ("PAD4", F.PAD4),
          ("TREE_SPK", F.tree_spk()), ("TREE_SPK_MIN", F.tree_spk_min()),
          ("LEAF_ACC", F.leaf_acc()), ("LEAF_POS", F.leaf_pos()),
          ("PROLOGUE", F.prologue()),
          ("LEVEL", F.level_dense()), ("LEVEL_MIN", F.level_min()),
          ("SPARSE_SETUP", F.sparse_setup()), ("SPARSE_TEARDOWN", F.sparse_teardown()),
          ("CHECK_OLD", F.check_old_root_from_alt("D")), ("CHECK_OLD_S", F.check_old_root_from_alt("S")),
          ("CHECK_PREV", F.check_prev_root_from_alt("D")), ("CHECK_PREV_S", F.check_prev_root_from_alt("S")),
          ("LEAF_STEP", F._leaf_step(OP_KEY))]
    t += [(f"LEVEL_S({k})", F.level_sparse(k)) for k in range(0, 64)]
    t += [("FINAL", F.final_output(d)) for d in (4, 8, 12, 16, 20, 32, 64)]
    t += [(f"HASH_STEP({k})", F._hash_step(k)) for k in range(3, 64)]
    return [(n, words(x, "c2")) for n, x in t]


def mid_macros():
    t = []
    for tag, pre in (("LEAF", F.LEAF_PREFIX), ("NODE", F.NODE_PREFIX), ("STATE", F.STATE_PREFIX),
                     ("VOUCHER", F.VOUCHER_PREFIX), ("POS", F.POS_PREFIX), ("TAPTWEAK", F.TAPTWEAK_PREFIX)):
        t.append((f"TAGGED({tag})", M.tagged(pre)))
    t += [("PADZ", M.padz()), ("ENC64", M.enc64()), ("LE64", M.le64()),
          ("TREE_SPK_MIN", F.tree_spk_min()), ("PROLOGUE", M.prologue()),
          ("LEVEL_MID", M.level(False)), ("LEVEL_MID_S", M.level(True)),
          ("SPARSE_SETUP", M.sparse_setup()), ("SPARSE_TEARDOWN", M.sparse_teardown()),
          ("CHECK_OLD", M.check_old(False)), ("CHECK_OLD_S", M.check_old(True)),
          ("CHECK_PREV", M.check_prev(False)), ("CHECK_PREV_S", M.check_prev(True)),
          ("LEAF_JOIN", M.leaf_join())]
    t += [("FINAL", M.final(d)) for d in (4, 8, 16, 31, 32)]
    return [(n, words(x, "c0")) for n, x in t]


def min_macros():
    t = []
    for tag, pre in (("LEAF", F.LEAF_PREFIX), ("NODE", F.NODE_PREFIX), ("STATE", F.STATE_PREFIX),
                     ("TAPTWEAK", F.TAPTWEAK_PREFIX), ("TAPSIGHASH", N.TAPSIGHASH_PREFIX),
                     ("CHALLENGE", N.CHALLENGE_PREFIX)):
        t.append((f"TAGGED({tag})", M.tagged(pre)))
    t += [("PADZ", M.padz()), ("LE64", M.le64()), ("TREE_SPK_MIN", F.tree_spk_min()),
          ("LEVEL_MID", M.level(False)), ("LEAF_JOIN", M.leaf_join())]
    return [(n, words(x, "c0")) for n, x in t]


# ------------------------------------------------------------------ collapse
def collapse(ws, macros, exclude=None):
    """Greedy longest-match of macro token sequences over the token tuple.
    Returns a list of items: ("macro", name) or ("raw", [tokens])."""
    table = sorted(((n, m) for n, m in macros if n != exclude and len(m) > 0),
                   key=lambda nm: -len(nm[1]))
    out, i, raw = [], 0, []
    while i < len(ws):
        hit = None
        for name, m in table:
            if ws[i:i + len(m)] == m:
                hit = (name, len(m))
                break
        if hit:
            if raw:
                out.append(("raw", raw)); raw = []
            out.append(("macro", hit[0], ws[i:i + hit[1]]))
            i += hit[1]
        else:
            raw.append(ws[i]); i += 1
    if raw:
        out.append(("raw", raw))
    return out


def expand(items, macros):
    ws = []
    for it in items:
        ws += list(it[2]) if it[0] == "macro" else it[1]
    return tuple(ws)


def render(items):
    """Macro calls one per line, runs of identical calls as 'NAME xN', descending
    LEVEL_S(k) runs as a range, raw opcodes wrapped at WIDTH with indentation."""
    lines, i = [], 0
    while i < len(items):
        kind, v = items[i][0], items[i][1]
        if kind == "raw":
            line = ""
            for w in v:
                if len(line) + len(w) + 1 > WIDTH:
                    lines.append(line.rstrip()); line = "  "
                line += w + " "
            lines.append(line.rstrip())
            i += 1
            continue
        # macro: count repeats
        j = i
        while j < len(items) and items[j][0] == "macro" and items[j][1] == v:
            j += 1
        if j - i > 1:
            lines.append(f"{v}  x{j - i}")
            i = j
            continue
        # ascending or descending LEVEL_S(k) run
        if v.startswith("LEVEL_S("):
            k0 = int(v[8:-1])
            for step in (1, -1):
                j = i + 1; k = k0 + step
                while j < len(items) and items[j][0] == "macro" and items[j][1] == f"LEVEL_S({k})":
                    j += 1; k += step
                if j - i > 1:
                    last = k - step
                    lines.append(f"LEVEL_S(k)  for k = {k0} {'to' if step == 1 else 'down to'} {last}")
                    break
            else:
                j = i
            if j > i:
                i = j
                continue
        lines.append(v)
        i += 1
    return lines


def structured(title, tokens, mode, macros):
    ws = words(tokens, mode)
    items = collapse(ws, macros)
    assert expand(items, macros) == ws, f"collapse does not round-trip: {title}"
    size = len(assemble(tokens, mode))
    tier = "FULL" if mode == "c2" else ("MIN" if "MIN tier" in title else "MID")
    head = [f"# {title}: {size} bytes",
            f"# macros in CAPITALS are defined in MACROS_{tier}.txt; raw opcodes are wrapped and indented", ""]
    return "\n".join(head + render(items)) + "\n"


def macro_file(tier, macros, notes):
    # de-duplicate parametrised families for the definitions file
    seen, lines = set(), [f"# Macro definitions, {tier} tier. Each expansion is itself collapsed",
                         "# against the other macros; a macro never contains itself.", ""]
    for name, ws in macros:
        key = name.split("(")[0] if name.startswith(("LEVEL_S(", "HASH_STEP(")) else name
        if key in seen:
            continue
        seen.add(key)
        shown = name
        if key == "LEVEL_S":
            shown = "LEVEL_S(k)   [shown for k = 0; <EMPTY_k> and the bit index vary with k]"
        if key == "HASH_STEP":
            shown = "HASH_STEP(t)   [shown for t = 3; the OP_PICK depth is t-3]"
        if key == "FINAL":
            shown = "FINAL   [shown for D = 4; <EMPTY_D> is the empty root of the tree's depth]"
        items = collapse(ws, macros, exclude=name)
        lines.append(f"## {shown}" + (f"   ({notes[key]})" if key in notes else ""))
        lines += render(items)
        lines.append("")
    return "\n".join(lines) + "\n"


FULL = full_macros()
MID = mid_macros()
MIN = min_macros()

NOTES_FULL = {
    "TAGGED": "[msg] -> [H_tag(msg)]",
    "PAD8": "[n] -> [enc64(n)]: minimal encoding of n + 2^64 is le64(n)||01",
    "LE64": "[n] -> [le64(n)]",
    "PAD4": "[n] -> [le32(n)]",
    "TREE_SPK": "[r m] -> [TREE_SPK(r, m)] with EC ops",
    "TREE_SPK_MIN": "[r m] -> [TREE_SPK(r, m)] with OP_TWEAKADD",
    "LEAF_ACC": "[leaf] -> [H_leaf(leaf) amount]",
    "LEAF_POS": "[leaf] -> [leaf H_pos(owner_key||nonce)]",
    "PROLOGUE": "input is #0; (r, m) match the input scriptPubKey; alt <- m r",
    "LEVEL": "dense level: dir sc T oh os nh ns -> T oh' os' nh' ns'",
    "LEVEL_S": "sparse level k: sc T oh os nh ns | pos E_k -> T oh' os' nh' ns' | pos E_k+1",
    "LEVEL_MIN": "dense level without splice opcodes: sibling as two elements",
    "SPARSE_SETUP": "[pos_hash] -> [] ; alt <- pos E_0",
    "SPARSE_TEARDOWN": "drop pos and E_k from the alt stack",
    "CHECK_OLD": "os == input 0 amount, oh == r (from alt)",
    "CHECK_OLD_S": "CHECK_OLD with the sparse teardown",
    "CHECK_PREV": "os == ns_prev, oh == nh_prev (from alt); chained steps",
    "CHECK_PREV_S": "CHECK_PREV with the sparse teardown",
    "FINAL": "output 0 is (ns, TREE_SPK(nh, m)) unless nh == E_D",
    "LEAF_STEP": "cohort sweep: one leaf or empty -> its node, paying the next output",
    "HASH_STEP": "cohort sweep: two child nodes -> parent node",
}
NOTES_MID = {
    "TAGGED": "[msg] -> [H_tag(msg)]",
    "PADZ": "[x z w] -> [le32(x)]: z||w == 00000000 and size(x)+size(z) == 4",
    "ENC64": "[x z w] -> [enc64(x)]",
    "LE64": "[x z w] -> [le64(x)]",
    "TREE_SPK_MIN": "[r m] -> [TREE_SPK(r, m)] with OP_TWEAKADD",
    "PROLOGUE": "input is #0; (r, m) match the input scriptPubKey; alt <- m r",
    "LEVEL_MID": "dense level with PADZ gadgets",
    "LEVEL_MID_S": "sparse level: dir folded into the position accumulator",
    "SPARSE_SETUP": "[ok nonce plo phi] -> [] ; alt <- plo 0 1 E_0",
    "SPARSE_TEARDOWN": "check the accumulated position against plo; drop bookkeeping",
    "CHECK_OLD": "os (padded) == input 0 amount, oh == r",
    "CHECK_OLD_S": "CHECK_OLD with the sparse teardown",
    "CHECK_PREV": "os == ns_prev, oh == nh_prev; chained steps",
    "CHECK_PREV_S": "CHECK_PREV with the sparse teardown",
    "FINAL": "output 0 is (le64(ns), TREE_SPK(nh, m)) unless nh == E_D",
    "LEAF_JOIN": "[amt8 ek ok evk ea nonce seq amt_num za wa] -> [leaf] | amt_num",
}

with open(os.path.join(OUT, "MACROS_FULL.txt"), "w") as f:
    f.write(macro_file("FULL", FULL, NOTES_FULL))
with open(os.path.join(OUT, "MACROS_MID.txt"), "w") as f:
    f.write(macro_file("MID", MID, NOTES_MID))
with open(os.path.join(OUT, "MACROS_MIN.txt"), "w") as f:
    f.write(macro_file("MIN", MIN, {k: v for k, v in NOTES_MID.items() if k in dict(MIN) or k in ("TAGGED",)}))

D = 4
for name, toks in F.all_scripts(D, OP_KEY, (0, 2), (1, 2), "D").items():
    open(os.path.join(OUT, f"{name}_D{D}.txt"), "w").write(structured(f"{name} (dense, D={D})", toks, "c2", FULL))
open(os.path.join(OUT, f"UPDATE_X_D{D}.txt"), "w").write(
    structured(f"UPDATE_X (exit-key consent, dense, D={D})", F.update_script(D, OP_KEY, "D", exit_consent=True), "c2", FULL))
for name, toks in F.all_scripts(8, OP_KEY, (0,), (1,), "S").items():
    open(os.path.join(OUT, f"{name}_S8.txt"), "w").write(structured(f"{name} (sparse, D=8)", toks, "c2", FULL))
open(os.path.join(OUT, "EVICT_SUBTREE_2_D8.txt"), "w").write(
    structured("EVICT_SUBTREE_2 (dense, D=8): cohort sweep of a 4-position subtree",
               F.evict_subtree_script(8, 2, OP_KEY), "c2", FULL))
open(os.path.join(OUT, "EXIT_1_MIN_D4.txt"), "w").write(
    structured("EXIT_1 (minimal inventory, dense, D=4)", F.exit_script_min(D), "c2", FULL))
for name, toks in M.all_scripts(D, OP_KEY, False).items():
    open(os.path.join(OUT, f"MID_{name}_D{D}.txt"), "w").write(structured(f"{name} (MID tier, dense, D={D})", toks, "c0", MID))
open(os.path.join(OUT, f"MID_UPDATE_X_D{D}.txt"), "w").write(
    structured(f"UPDATE_X (MID tier, exit-key consent, dense, D={D})", M.update_script(D, OP_KEY, False, exit_consent=True), "c0", MID))
open(os.path.join(OUT, f"MIN_EXIT_1_D{D}.txt"), "w").write(
    structured(f"EXIT_1 (MIN tier, dense, D={D})", N.exit_script(D), "c0", MIN))
print("wrote", len(os.listdir(OUT)), "structured listings to", os.path.relpath(OUT))
