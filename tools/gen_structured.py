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
import layertree_ccv as CV  # noqa: E402
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
NAMES[M.E0_SC] = "<E_0.sc>"
TREE_ID = lt.tree_id(lt.sha256(b"creation-txid"), 0)   # the suites' tree_id (spec 6.2)
NAMES[TREE_ID] = "<TREE_ID>"
for h in range(0, 65):
    NAMES[lt.empty_node(h)[0]] = f"<EMPTY_{h}>"

WIDTH = 78


def words(tokens, mode):
    return tuple(disassemble(assemble(tokens, mode), NAMES))


# ---------------------------------------------------------------- macro tables
def full_macros():
    t = []
    for tag, pre in (("LEAF", F.LEAF_PREFIX), ("NODE", F.NODE_PREFIX), ("STATE", F.STATE_PREFIX),
                     ("VOUCHER", F.VOUCHER_PREFIX), ("EXIT", F.EXIT_PREFIX), ("POS", F.POS_PREFIX),
                     ("TAPTWEAK", F.TAPTWEAK_PREFIX)):
        t.append((f"TAGGED({tag})", F.tagged(pre)))
    t += [("PAD8", F.PAD8), ("LE64", F.LE64), ("PAD4", F.PAD4),
          ("TREE_SPK", F.tree_spk()), ("TREE_SPK_MIN", F.tree_spk_min()),
          ("LEAF_ACC", F.leaf_acc()), ("LEAF_POS", F.leaf_pos()),
          ("PROLOGUE", F.prologue()), ("CARVE_RULES", F.carve_leaf_rules()),
          ("DRAIN_RULE", F.drain_rule()), ("LEAF_BODY", F.LEAF_BODY),
          ("TOWER_AUTH", F.tower_auth(TREE_ID)),
          ("LEVEL", F.level_dense()), ("LEVEL_MIN", F.level_min()),
          ("SPARSE_SETUP", F.sparse_setup()), ("SPARSE_TEARDOWN", F.sparse_teardown()),
          ("CHECK_OLD", F.check_old_root_from_alt("D")), ("CHECK_OLD_S", F.check_old_root_from_alt("S")),
          ("CHECK_PREV", F.check_prev_root_from_alt("D")), ("CHECK_PREV_S", F.check_prev_root_from_alt("S")),
          ("LEAF_STEP", F._leaf_step(OP_KEY))]
    t += [(f"LEVEL_S({k})", F.level_sparse(k)) for k in range(0, 64)]
    t += [("FINAL", F.final_output(d)) for d in (4, 8, 12, 16, 20, 32, 64)]
    t += [(f"HASH_STEP({k})", F._hash_step(k)) for k in range(3, 64)]
    # REWRITE_h: the per-position step and the double hash step, both
    # parametrised by the machine depth d (a multiple of 4).
    t += [(f"REWRITE_STEP({d})", F._rewrite_step(d, False)) for d in range(0, 64, 4)]
    t += [(f"REWRITE_STEP_X({d})", F._rewrite_step(d, True)) for d in range(0, 64, 4)]
    t += [(f"HASH_STEP2({d})", F._hash_step2(d)) for d in range(8, 68, 4)]
    t += [(f"ELEM_NODE({d})", F._elem_node(d + 4, d + 3)) for d in range(0, 64)]
    t += [(f"OWNER_AUTH({d})", F._owner_auth(d + 5, False)) for d in range(0, 64, 4)]
    t += [(f"OWNER_AUTH_X({d})", F._owner_auth(d + 5, True)) for d in range(0, 64, 4)]
    return [(n, words(x, "c2")) for n, x in t]


PARAM_FAMILIES = ("LEVEL_S(", "HASH_STEP(", "HASH_STEP2(", "REWRITE_STEP(", "REWRITE_STEP_X(",
                  "OWNER_AUTH(", "OWNER_AUTH_X(", "ELEM_NODE(", "REWRITE_HASH_STEP2(", "REWRITE_HASH_ROOT2(")


def mid_macros():
    t = []
    for tag, pre in (("LEAF", F.LEAF_PREFIX), ("NODE", F.NODE_PREFIX), ("STATE", F.STATE_PREFIX),
                     ("VOUCHER", F.VOUCHER_PREFIX), ("EXIT", F.EXIT_PREFIX), ("POS", F.POS_PREFIX),
                     ("TAPTWEAK", F.TAPTWEAK_PREFIX)):
        t.append((f"TAGGED({tag})", M.tagged(pre)))
    t += [("TOWER_AUTH_MID", M.tower_auth(TREE_ID))]
    t += [("NONNEG", M.nonneg()), ("PADZ", M.padz()), ("ENC64", M.enc64()), ("LE64", M.le64()),
          ("TREE_SPK_MIN", F.tree_spk_min()), ("PROLOGUE", M.prologue()),
          ("LEVEL_MID", M.level(False)), ("LEVEL_MID_S", M.level(True)),
          ("SPARSE_SETUP", M.sparse_setup()), ("SPARSE_TEARDOWN", M.sparse_teardown()),
          ("CHECK_OLD", M.check_old(False)), ("CHECK_OLD_S", M.check_old(True)),
          ("CHECK_PREV", M.check_prev(False)), ("CHECK_PREV_S", M.check_prev(True)),
          ("LEAF_JOIN", M.leaf_join()), ("CARVE_RULES", M.carve_rules()),
          ("DRAIN_RULE", F.drain_rule())]
    t += [("FINAL", M.final(d)) for d in (4, 8, 16, 31, 32)]
    t += [("EVICT_LEAF_STEP", M._evict_leaf_step(OP_KEY))]
    t += [(f"EVICT_HASH_STEP({k})", M._evict_hash_step(k, False)) for k in range(4, 40)]
    t += [(f"EVICT_HASH_ROOT({k})", M._evict_hash_step(k, True)) for k in range(4, 6)]
    # REWRITE_h (8.9 under MID): the slot joins, the per-position step and
    # the double hash step; the step is one token sequence whatever the
    # position, since the pre-pass runs at the top of the stack.
    t += [("LEAF_JOIN_OLD", M._leaf_join_old()), ("LEAF_JOIN_NEW", M._leaf_join_new()),
          ("REWRITE_CONV", M._rewrite_conv()), ("REWRITE_PAY", M._rewrite_pay()),
          ("OWNER_AUTH_MID", M._rewrite_owner_auth(False)), ("OWNER_AUTH_MID_X", M._rewrite_owner_auth(True)),
          ("REWRITE_STEP_MID", M._rewrite_step(False)), ("REWRITE_STEP_MID_X", M._rewrite_step(True))]
    t += [(f"REWRITE_HASH_STEP2({k})", M._rewrite_hash_step2(k, False)) for k in range(8, 40, 4)]
    t += [(f"REWRITE_HASH_ROOT2({k})", M._rewrite_hash_step2(k, True)) for k in range(8, 12, 4)]
    return [(n, words(x, "c0")) for n, x in t]


def ccv_macros():
    t = []
    for tag, pre in (("LEAF", F.LEAF_PREFIX), ("NODE", F.NODE_PREFIX), ("POS", F.POS_PREFIX),
                     ("TAPTWEAK", F.TAPTWEAK_PREFIX), ("VOUCHER", F.VOUCHER_PREFIX),
                     ("VOUCHER_H", F.VOUCHER_H_PREFIX), ("EXIT", F.EXIT_PREFIX)):
        t.append((f"TAGGED({tag})", F.tagged(pre)))
    t += [("LEAF_BODY", F.LEAF_BODY), ("TOWER_AUTH", F.tower_auth(TREE_ID)),
          ("CCV_CHECK_INPUT", CV.ccv_check_input()),
          ("CCV_PAYOUT(1)", CV.ccv_payout_fixed(1)),
          ("CCV_PAYOUT(2)", CV.ccv_payout_fixed(2)),
          ("LEAF_ACC", F.leaf_acc()), ("LEAF_POS", F.leaf_pos()),
          ("LEVEL", F.level_dense()),
          ("SPARSE_SETUP", F.sparse_setup()), ("SPARSE_TEARDOWN", F.sparse_teardown()),
          ("CHECK_PREV", F.check_prev_root_from_alt("D")), ("CHECK_PREV_S", F.check_prev_root_from_alt("S")),
          ("CHECK_OLD", CV.check_old_ccv("D")), ("CHECK_OLD_S", CV.check_old_ccv("S")),
          ("PROLOGUE_CCV", CV.prologue_ccv()), ("CARVE_RULES", F.carve_leaf_rules()),
          ("DRAIN_RULE", F.drain_rule())]
    t += [(f"LEVEL_S({k})", F.level_sparse(k)) for k in range(0, 64)]
    t += [("FINAL", CV.final_ccv(d)) for d in (4, 8, 12, 16, 20, 32)]
    t += [("LEVEL_MIN", F.level_min()), ("LEAF_STEP", CV.leaf_step_ccv(OP_KEY))]
    return [(n, words(x, "c2")) for n, x in t]


def min_macros():
    t = []
    for tag, pre in (("LEAF", F.LEAF_PREFIX), ("NODE", F.NODE_PREFIX), ("STATE", F.STATE_PREFIX),
                     ("TAPTWEAK", F.TAPTWEAK_PREFIX), ("TAPSIGHASH", N.TAPSIGHASH_PREFIX),
                     ("CHALLENGE", N.CHALLENGE_PREFIX)):
        t.append((f"TAGGED({tag})", M.tagged(pre)))
    t += [("NONNEG", M.nonneg()), ("PADZ", M.padz()), ("LE64", M.le64()), ("TREE_SPK_MIN", F.tree_spk_min()),
          ("LEVEL_MID", M.level(False)), ("LEAF_JOIN", M.leaf_join()),
          ("CARVE_RULES", M.carve_rules()), ("DRAIN_RULE", F.drain_rule())]
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
    tier = ("CCV" if "CCV tier" in title else
            "FULL" if mode == "c2" else
            ("MIN" if "MIN tier" in title else "MID"))
    head = [f"# {title}: {size} bytes",
            f"# macros in CAPITALS are defined in MACROS_{tier}.txt; raw opcodes are wrapped and indented", ""]
    return "\n".join(head + render(items)) + "\n"


def macro_file(tier, macros, notes):
    # de-duplicate parametrised families for the definitions file
    seen, lines = set(), [f"# Macro definitions, {tier} tier. Each expansion is itself collapsed",
                         "# against the other macros; a macro never contains itself.", ""]
    for name, ws in macros:
        key = name.split("(")[0] if name.startswith(PARAM_FAMILIES) else name
        if key in seen:
            continue
        seen.add(key)
        shown = name
        if key == "LEVEL_S":
            shown = "LEVEL_S(k)   [shown for k = 0; <EMPTY_k> and the bit index vary with k]"
        if key == "HASH_STEP":
            shown = "HASH_STEP(t)   [shown for t = 3; the OP_PICK depth is t-3]"
        if key == "HASH_STEP2":
            shown = "HASH_STEP2(d)   [shown for d = 8; the HASH_STEP pick depths are d-3 and d-5]"
        if key in ("REWRITE_STEP", "REWRITE_STEP_X"):
            shown = f"{key}(d)   [shown for d = 0; the OP_ROLL depths are d+3, d+4 and d+5, the picks d+3 to d+5]"
        if key in ("OWNER_AUTH", "OWNER_AUTH_X"):
            shown = f"{key}(d)   [shown for d = 0; the OP_ROLL depth is d+5]"
        if key == "ELEM_NODE":
            shown = "ELEM_NODE(d)   [shown for d = 0; picks L at d+4 and Z at d+3 for the old element, one deeper for the new]"
        if key == "FINAL":
            shown = "FINAL   [shown for D = 4; <EMPTY_D> is the empty root of the tree's depth]"
        if key in ("REWRITE_HASH_STEP2", "REWRITE_HASH_ROOT2"):
            shown = f"{key}(t)   [shown for t = 8; the EVICT_HASH_STEP depths are t and t-2]"
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
    "CARVE_RULES": "[src claim] -> [src claim]: both 116 bytes, claim.evictor_key == src.evictor_key, claim.evict_after <= src.evict_after (7.5 rule 5), claim.amount >= DUST_MIN (7.5 rule 6)",
    "DRAIN_RULE": "[.. nh ns] -> [.. nh' ns]: a zero residual makes the new node E_0, any other is at least DUST_MIN (7.5 rules 2 and 6)",
    "PAD8": "[n] -> [enc64(n)]: minimal encoding of n + 2^64 is le64(n)||01",
    "LE64": "[n] -> [le64(n)]",
    "PAD4": "[n] -> [le32(n)]",
    "LEAF_BODY": "[leaf] -> [body]: the 108 bytes after the amount field (5.2), what vouchers and exit authorisations bind (7.5, 7.2 rule 7)",
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
    "ELEM_NODE": "[elem] -> [h s]: a leaf's node, or E_0 for the empty element; picks the hoisted TAG_LEAF prefix (L) and E_0 (Z)",
    "OWNER_AUTH": "cohort rewrite: the next witness element is a signature by old.owner_key",
    "OWNER_AUTH_X": "OWNER_AUTH plus a signature by old.exit_key (REWRITE_h^x)",
    "REWRITE_STEP": "cohort rewrite: old and new elements of one position -> oh os nh ns, with 7.9 rules 3 and 5",
    "REWRITE_STEP_X": "REWRITE_STEP with OWNER_AUTH_X",
    "HASH_STEP2": "cohort rewrite: two old and two new child nodes -> old and new parent nodes",
    "TOWER_AUTH": "[leaf sig] -> [leaf]: sig is a BIP-340 signature by leaf.owner_key over H_exit(tree_id || body(leaf)), the leaf without its amount (LEAF_BODY), checked by OP_CHECKSIGFROMSTACK (EXIT_K^t, 7.2 rule 7)",
}
NOTES_MID = {
    "TAGGED": "[msg] -> [H_tag(msg)]",
    "CARVE_RULES": "[src(10) claim(10) extras(7) sea zse wse cea zce wce] -> [src(10) claim(10) extras(7)]: claim.evk == src.evk and claim.evict_after <= src.evict_after, each evict_after a minimal number checked against its field by PADZ (7.5 rule 5), and claim.amt_num >= DUST_MIN (rule 6)",
    "DRAIN_RULE": "[.. nh ns] -> [.. nh' ns]: a zero residual makes the new node E_0, any other is at least DUST_MIN (7.5 rules 2 and 6)",
    "NONNEG": "[x] -> [x]: x == |x|, a minimal non-negative CScriptNum (rejects a negative, a negative zero and a non-minimal encoding)",
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
    "EVICT_LEAF_STEP": "cohort sweep pre-pass: [slot idx] -> [idx'] | s sc, paying the next output",
    "EVICT_HASH_STEP": "cohort sweep: [Rsc Rs Lsc Ls] -> [psc ps], one PADZ pad pair from below T",
    "EVICT_HASH_ROOT": "cohort sweep: [Rsc Rs Lsc Ls] -> [oh os] at the subtree root",
    "LEAF_JOIN_OLD": "cohort rewrite: [amt8 ek ok evk ea nonce seq amt_num za wa] -> [amt8 rest ek ok fin amt], fin = (seq == SEQ_FINAL)",
    "LEAF_JOIN_NEW": "cohort rewrite: [amt8 ek ok evk ea nonce seq amt_num za wa] -> [amt8 rest amt]",
    "REWRITE_CONV": "cohort rewrite: [idx L Z amt8 rest] -> [idx L Z sc], a leaf's 41-byte node or Z (E_0) for the empty element",
    "REWRITE_PAY": "cohort rewrite: output idx pays exactly old.amt8 to P2TR(old.ek), idx advances (7.9 rule 5)",
    "OWNER_AUTH_MID": "cohort rewrite: the next witness element (nine deep) is a signature by old.ok",
    "OWNER_AUTH_MID_X": "OWNER_AUTH_MID plus a signature by old.ek (REWRITE_h^x)",
    "REWRITE_STEP_MID": "cohort rewrite pre-pass: [new_slot old_slot idx L Z] -> [idx' L Z] | ns nsc os osc, with 7.9 rules 3 and 5",
    "REWRITE_STEP_MID_X": "REWRITE_STEP_MID with OWNER_AUTH_MID_X",
    "REWRITE_HASH_STEP2": "cohort rewrite: [Rosc Ros Rnsc Rns Losc Los Lnsc Lns] -> [posc pos pnsc pns], two pad pairs from below T",
    "REWRITE_HASH_ROOT2": "cohort rewrite: the same at the subtree root, -> [oh os nh ns]",
    "TOWER_AUTH_MID": "[leaf(10) ea_num ze we sig] -> [leaf(10) ea_num ze we]: sig is a BIP-340 signature by ok over H_exit(tree_id || body(leaf)), the leaf body rejoined from its six fields after amt8, checked by OP_CHECKSIGFROMSTACK (EXIT_K^t, 7.2 rule 7)",
}

CCV = ccv_macros()
NOTES_CCV = {
    "CARVE_RULES": "[src claim] -> [src claim]: both 116 bytes, claim.evictor_key == src.evictor_key, claim.evict_after <= src.evict_after (7.5 rule 5), claim.amount >= DUST_MIN (7.5 rule 6)",
    "DRAIN_RULE": "[.. nh ns] -> [.. nh' ns]: a zero residual makes the new node E_0, any other is at least DUST_MIN (7.5 rules 2 and 6)",
    "CCV_CHECK_INPUT": "BIP-443 CHECK_INPUT: [data] -> [], binds the old root to the current input under its own taptree",
    "CCV_PAYOUT": "BIP-443 CHECK_OUTPUT|DEDUCT: bare P2TR to leaf.exit_key, deducts from the residual",
    "CHECK_OLD": "the input-amount equality plus one CCV_CHECK_INPUT on the folded old root",
    "FINAL": "output 0 is the CCV assign-mode tree output with amount == ns, unless nh == E_D",
    "PROLOGUE_CCV": "empty: CCV's -1 index binds the current input without OP_TX",
    "LEAF_BODY": "[leaf] -> [body]: the 108 bytes after the amount field (5.2), what vouchers and exit authorisations bind (7.5, 7.2 rule 7)",
    "TOWER_AUTH": "[leaf sig] -> [leaf]: sig is a BIP-340 signature by leaf.owner_key over H_exit(tree_id || body(leaf)), the leaf without its amount (LEAF_BODY), checked by OP_CHECKSIGFROMSTACK (EXIT_K^t, 7.2 rule 7)",
}
with open(os.path.join(OUT, "MACROS_FULL.txt"), "w") as f:
    f.write(macro_file("FULL", FULL, NOTES_FULL))
with open(os.path.join(OUT, "MACROS_MID.txt"), "w") as f:
    f.write(macro_file("MID", MID, NOTES_MID))
with open(os.path.join(OUT, "MACROS_CCV.txt"), "w") as f:
    f.write(macro_file("CCV", CCV, NOTES_CCV))
with open(os.path.join(OUT, "MACROS_MIN.txt"), "w") as f:
    f.write(macro_file("MIN", MIN, {k: v for k, v in NOTES_MID.items() if k in dict(MIN) or k in ("TAGGED",)}))

D = 4
for name, toks in F.all_scripts(D, OP_KEY, (0, 2), (1, 2), "D", tree_id=TREE_ID).items():
    open(os.path.join(OUT, f"{name}_D{D}.txt"), "w").write(structured(f"{name} (dense, D={D})", toks, "c2", FULL))
open(os.path.join(OUT, f"UPDATE_X_D{D}.txt"), "w").write(
    structured(f"UPDATE_X (exit-key consent, dense, D={D})", F.update_script(D, OP_KEY, "D", exit_consent=True), "c2", FULL))
open(os.path.join(OUT, f"CLAIM_H_D{D}.txt"), "w").write(
    structured(f"CLAIM_H (hash-locked voucher, dense, D={D})", F.claim_script(D, TREE_ID, "D", hashlock=True), "c2", FULL))
open(os.path.join(OUT, f"SPLIT_D{D}.txt"), "w").write(
    structured(f"SPLIT (owner-authorised carve, dense, D={D})", F.split_script(D, "D"), "c2", FULL))
open(os.path.join(OUT, f"CLAIM_X_D{D}.txt"), "w").write(
    structured(f"CLAIM_X (exit-key consent, dense, D={D})", F.claim_script(D, TREE_ID, "D", exit_consent=True), "c2", FULL))
# EXIT_K^t (7.2 rule 7), the tower-delegable exit, in the three tiers that carry it.
open(os.path.join(OUT, f"EXIT_1_TOWER_D{D}.txt"), "w").write(
    structured(f"EXIT_1_TOWER (tower-delegable exit, dense, D={D})",
               F.exit_script(D, 1, "D", tower=True, tree_id=TREE_ID), "c2", FULL))
open(os.path.join(OUT, f"MID_EXIT_1_TOWER_D{D}.txt"), "w").write(
    structured(f"EXIT_1_TOWER (MID tier, tower-delegable exit, dense, D={D})",
               M.exit_script(D, 1, False, tower=True, tree_id=TREE_ID), "c0", MID))
open(os.path.join(OUT, f"CCV_EXIT_1_TOWER_D{D}.txt"), "w").write(
    structured(f"EXIT_1_TOWER (CCV tier, tower-delegable exit, dense, D={D})",
               CV.exit_script_ccv(D, 1, "D", tower=True, tree_id=TREE_ID), "c2", CCV))
open(os.path.join(OUT, f"CCV0_EXIT_1_TOWER_D{D}.txt"), "w").write(
    structured(f"EXIT_1_TOWER (CCV with 0xC0 numerics, in MID macros, dense, D={D})",
               CV._exit_script_ccv0(D, 1, False, tower=True, tree_id=TREE_ID), "c0", MID))
for name, toks in F.all_scripts(8, OP_KEY, (0,), (1,), "S", tree_id=TREE_ID).items():
    open(os.path.join(OUT, f"{name}_S8.txt"), "w").write(structured(f"{name} (sparse, D=8)", toks, "c2", FULL))
open(os.path.join(OUT, "EVICT_SUBTREE_2_D8.txt"), "w").write(
    structured("EVICT_SUBTREE_2 (dense, D=8): cohort sweep of a 4-position subtree",
               F.evict_subtree_script(8, 2, OP_KEY), "c2", FULL))
open(os.path.join(OUT, "REWRITE_2_D8.txt"), "w").write(
    structured("REWRITE_2 (dense, D=8): cohort rewrite of a 4-position subtree",
               F.rewrite_script(8, 2, OP_KEY), "c2", FULL))
open(os.path.join(OUT, "DETACH_2_D8.txt"), "w").write(
    structured("DETACH_2 (dense, D=8): detach a 4-position subtree into its own tree output",
               F.detach_script(8, 2, OP_KEY, F.detached_taptree_root(2, OP_KEY, TREE_ID)), "c2", FULL))
open(os.path.join(OUT, "CCV_DETACH_2_D8.txt"), "w").write(
    structured("DETACH_2 (CCV tier, dense, D=8): detach a 4-position subtree into its own tree output",
               CV.detach_script_ccv(8, 2, OP_KEY, CV.detached_taptree_root_ccv(2, OP_KEY, "c2")), "c2", CCV))
open(os.path.join(OUT, "EXIT_1_MIN_D4.txt"), "w").write(
    structured("EXIT_1 (minimal inventory, dense, D=4)", F.exit_script_min(D), "c2", FULL))
for name, toks in M.all_scripts(D, OP_KEY, False, tree_id=TREE_ID).items():
    open(os.path.join(OUT, f"MID_{name}_D{D}.txt"), "w").write(structured(f"{name} (MID tier, dense, D={D})", toks, "c0", MID))
open(os.path.join(OUT, f"MID_UPDATE_X_D{D}.txt"), "w").write(
    structured(f"UPDATE_X (MID tier, exit-key consent, dense, D={D})", M.update_script(D, OP_KEY, False, exit_consent=True), "c0", MID))
open(os.path.join(OUT, f"MID_CLAIM_H_D{D}.txt"), "w").write(
    structured(f"CLAIM_H (MID tier, hash-locked voucher, dense, D={D})", M.claim_script(D, TREE_ID, False, hashlock=True), "c0", MID))
open(os.path.join(OUT, f"MID_SPLIT_D{D}.txt"), "w").write(
    structured(f"SPLIT (MID tier, owner-authorised carve, dense, D={D})", M.split_script(D, False), "c0", MID))
open(os.path.join(OUT, f"MID_EVICT_SUBTREE_2_D{D}.txt"), "w").write(
    structured(f"EVICT_SUBTREE_2 (MID tier, cohort sweep of a 4-position subtree, dense, D={D})",
               M.evict_subtree_script(D, 2, OP_KEY), "c0", MID))
open(os.path.join(OUT, f"MID_REWRITE_2_D{D}.txt"), "w").write(
    structured(f"REWRITE_2 (MID tier, cohort rewrite of a 4-position subtree, dense, D={D})",
               M.rewrite_script(D, 2, OP_KEY), "c0", MID))
open(os.path.join(OUT, f"MIN_EXIT_1_D{D}.txt"), "w").write(
    structured(f"EXIT_1 (MIN tier, dense, D={D})", N.exit_script(D), "c0", MIN))
open(os.path.join(OUT, f"MIN_SPLIT_D{D}.txt"), "w").write(
    structured(f"SPLIT (MIN tier, owner-authorised carve, dense, D={D})", N.split_script(D), "c0", MIN))
for name, toks in CV.all_scripts_ccv(D, OP_KEY, (0, 2), (1, 2), "D", (2,)).items():
    open(os.path.join(OUT, f"CCV_{name}_D{D}.txt"), "w").write(structured(f"{name} (CCV tier, dense, D={D})", toks, "c2", CCV))
open(os.path.join(OUT, f"CCV_UPDATE_X_D{D}.txt"), "w").write(
    structured(f"UPDATE_X (CCV tier, exit-key consent, dense, D={D})", CV.update_script_ccv(D, OP_KEY, "D", exit_consent=True), "c2", CCV))
open(os.path.join(OUT, f"CCV_SPLIT_D{D}.txt"), "w").write(
    structured(f"SPLIT (CCV tier, owner-authorised carve, dense, D={D})", CV.split_script_ccv(D, "D"), "c2", CCV))
for hl, nm in ((False, "CLAIM"), (True, "CLAIM_H")):
    open(os.path.join(OUT, f"CCV_{nm}_D{D}.txt"), "w").write(
        structured(f"{nm} (CCV tier, dense, D={D})",
                   CV.claim_script_ccv(D, TREE_ID, "D", hl), "c2", CCV))
    open(os.path.join(OUT, f"CCV0_{nm}_D{D}.txt"), "w").write(
        structured(f"{nm} (CCV with 0xC0 numerics, in MID macros, dense, D={D})",
                   CV._claim_script_ccv0(D, TREE_ID, False, hl), "c0", MID))
open(os.path.join(OUT, f"CCV0_SPLIT_D{D}.txt"), "w").write(
    structured(f"SPLIT (CCV with 0xC0 numerics, in MID macros, dense, D={D})",
               CV._split_script_ccv0(D, False), "c0", MID))
open(os.path.join(OUT, f"CCV0_EVICT_SUBTREE_2_D{D}.txt"), "w").write(
    structured(f"EVICT_SUBTREE_2 (CCV with 0xC0 numerics, in MID macros, dense, D={D})",
               CV._evict_subtree_script_ccv0(D, 2, OP_KEY), "c0", MID))
for name, toks in CV.all_scripts_ccv(8, OP_KEY, (0,), (1,), "S", (2,)).items():
    open(os.path.join(OUT, f"CCV_{name}_S8.txt"), "w").write(structured(f"{name} (CCV tier, sparse, D=8)", toks, "c2", CCV))
print("wrote", len(os.listdir(OUT)), "structured listings to", os.path.relpath(OUT))
