#!/usr/bin/env python3
"""
fee_analysis.py -- on-chain exit economics for LayerTree.

Dependency-free (stdlib only). Parses spec/scripts/sizes.md for measured
script/witness/control-block weights, adds the transaction skeleton
(spec section 11 / spec/layertree.md section 11), and reports:

  * total transaction weight, vbytes and fee (sat) at a set of fee rates,
    for a representative set of transitions (FULL/MID/MIN tiers, dense and
    sparse profiles, EXIT_1/EXIT_2/EVICT_SUBTREE_h);
  * comparison points: a plain P2TR->P2TR transaction, and an Ark/CTV-style
    unilateral exit from a radix-2 tree;
  * break-even balance (the leaf amount at which the fee equals 1%/5%/10%
    of the balance) at each fee rate;
  * the minimum economical leaf size (fee >= balance is a wash), including
    the 330 sat P2TR dust floor;
  * the vbyte/fee saving of the FULL-tier endogenous fee model (paying the
    fee out of the payout, dropping the separate fee input and its change
    output) versus the exogenous (separate fee input) model.

Run: python3 tools/fee_analysis.py
Output: Markdown to stdout. spec/fee-analysis.md pastes this output.
"""

import math
import os
import re

SIZES_MD = os.path.join(os.path.dirname(__file__), "..", "spec", "scripts", "sizes.md")

FEE_RATES = [1, 2, 5, 10, 25, 50, 100, 250]  # sat/vB
BREAKEVEN_PCTS = [0.01, 0.05, 0.10]
DUST_LIMIT_SAT = 330  # P2TR dust limit (spec section 11 / task context)

# ---------------------------------------------------------------------------
# Transaction skeleton (spec/layertree.md section 11).
#
#   tree input            41 vB   (non-witness)
#   fee input (P2WPKH)    41 vB   (non-witness) + 108 WU witness
#   tree output            43 vB   (non-witness)
#   payout output (each)   43 vB   (non-witness)
#   change output          31 vB   (non-witness)
#   version/locktime/etc.  10 vB   (non-witness)
#   marker + flag                     2 WU        (witness)
#
# Non-witness bytes cost 4 WU each; witness bytes cost 1 WU each.
# ---------------------------------------------------------------------------

TREE_INPUT_VB = 41
FEE_INPUT_VB = 41
FEE_INPUT_WITNESS_WU = 108
TREE_OUTPUT_VB = 43
PAYOUT_OUTPUT_VB = 43
CHANGE_OUTPUT_VB = 31
OVERHEAD_VB = 10
MARKER_FLAG_WU = 2


def vb_to_wu(vb):
    return vb * 4


# Exogenous model: a separate P2WPKH fee input pays the fee, and its
# leftover comes back as a change output. K=1 payout baseline.
SKELETON_EXO_WU = (
    vb_to_wu(TREE_INPUT_VB)
    + vb_to_wu(FEE_INPUT_VB)
    + vb_to_wu(TREE_OUTPUT_VB)
    + vb_to_wu(PAYOUT_OUTPUT_VB)
    + vb_to_wu(CHANGE_OUTPUT_VB)
    + vb_to_wu(OVERHEAD_VB)
    + FEE_INPUT_WITNESS_WU
    + MARKER_FLAG_WU
)

# Endogenous model (FULL tier only, owner exit): the fee is taken out of
# the payout itself (output 1's amount is set below leaf.amount, spec 7.2
# rule 3 / 9.3). No fee input, no change output.
SKELETON_ENDO_WU = (
    vb_to_wu(TREE_INPUT_VB)
    + vb_to_wu(TREE_OUTPUT_VB)
    + vb_to_wu(PAYOUT_OUTPUT_VB)
    + vb_to_wu(OVERHEAD_VB)
    + MARKER_FLAG_WU
)

EXTRA_PAYOUT_WU = vb_to_wu(PAYOUT_OUTPUT_VB)  # each payout beyond the first


# ---------------------------------------------------------------------------
# Parse spec/scripts/sizes.md
# ---------------------------------------------------------------------------

def parse_sizes_md(path=SIZES_MD):
    rows = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line.startswith("|"):
                continue
            cells = [c.strip() for c in line.strip("|").split("|")]
            if len(cells) != 9:
                continue
            if cells[0] == "profile":
                continue
            if set(cells[1]) <= set("-: "):
                continue  # separator row
            profile, d, transition = cells[0], cells[1], cells[2]
            try:
                d_val = int(d)
            except ValueError:
                continue

            def to_int(x):
                x = x.strip()
                if x in ("-", "", "n/a", "n/a (0xC0)"):
                    return None
                try:
                    return int(x)
                except ValueError:
                    return None

            script_wu = to_int(cells[3])
            witness_wu = to_int(cells[4])
            cb_wu = to_int(cells[5])
            total_witness_wu = to_int(cells[6])
            varops = to_int(cells[7])
            sigops = to_int(cells[8])
            rows.append(dict(
                profile=profile, D=d_val, transition=transition,
                script_wu=script_wu, witness_wu=witness_wu, cb_wu=cb_wu,
                total_witness_wu=total_witness_wu, varops=varops, sigops=sigops,
            ))
    return rows


def find_row(rows, profile, d, transition_prefix):
    for r in rows:
        if r["profile"] == profile and r["D"] == d and r["transition"].startswith(transition_prefix):
            return r
    raise KeyError(f"no row for profile={profile} D={d} transition~={transition_prefix!r}")


# ---------------------------------------------------------------------------
# Weight / fee helpers
# ---------------------------------------------------------------------------

def tx_weight_wu(total_witness_wu, k_payouts=1, endogenous=False):
    base = SKELETON_ENDO_WU if endogenous else SKELETON_EXO_WU
    return base + (k_payouts - 1) * EXTRA_PAYOUT_WU + total_witness_wu


def weight_to_vbytes(weight_wu):
    return math.ceil(weight_wu / 4)


def fee_at_rates(vbytes, rates=FEE_RATES):
    return {r: vbytes * r for r in rates}


def breakeven_balances(fee_sat, pcts=BREAKEVEN_PCTS):
    return {p: math.ceil(fee_sat / p) for p in pcts}


def min_economical_leaf(fee_sat, endogenous=False, dust=DUST_LIMIT_SAT):
    """Smallest leaf amount for which the exit is not a pure loss and the
    payout output clears the dust limit."""
    if endogenous:
        # output = leaf - fee must be > dust  =>  leaf > fee + dust
        return fee_sat + dust + 1
    else:
        # output = leaf (unchanged); leaf must clear dust AND exceed the
        # fee it costs to recover it (otherwise the exit nets negative
        # value even though fees are paid from elsewhere).
        return max(fee_sat, dust) + 1


# ---------------------------------------------------------------------------
# Markdown rendering helpers
# ---------------------------------------------------------------------------

def md_table(headers, rows):
    out = []
    out.append("| " + " | ".join(headers) + " |")
    out.append("|" + "|".join(["---"] * len(headers)) + "|")
    for row in rows:
        out.append("| " + " | ".join(str(c) for c in row) + " |")
    return "\n".join(out)


def fmt_sat(n):
    return f"{n:,}"


# ---------------------------------------------------------------------------
# Report sections
# ---------------------------------------------------------------------------

def section_skeleton():
    lines = []
    lines.append("## Transaction skeleton assumed\n")
    lines.append(
        "Non-witness bytes cost 4 WU each, witness bytes cost 1 WU each, "
        "vbytes = weight / 4 (rounded up).\n"
    )
    rows = [
        ("tree input", f"{TREE_INPUT_VB} vB", "-", f"{vb_to_wu(TREE_INPUT_VB)} WU"),
        ("fee input (P2WPKH)", f"{FEE_INPUT_VB} vB", f"{FEE_INPUT_WITNESS_WU} WU",
         f"{vb_to_wu(FEE_INPUT_VB) + FEE_INPUT_WITNESS_WU} WU"),
        ("tree output", f"{TREE_OUTPUT_VB} vB", "-", f"{vb_to_wu(TREE_OUTPUT_VB)} WU"),
        ("payout output (1st)", f"{PAYOUT_OUTPUT_VB} vB", "-", f"{vb_to_wu(PAYOUT_OUTPUT_VB)} WU"),
        ("change output", f"{CHANGE_OUTPUT_VB} vB", "-", f"{vb_to_wu(CHANGE_OUTPUT_VB)} WU"),
        ("version/locktime/counts", f"{OVERHEAD_VB} vB", "-", f"{vb_to_wu(OVERHEAD_VB)} WU"),
        ("marker + flag", "-", f"{MARKER_FLAG_WU} WU", f"{MARKER_FLAG_WU} WU"),
    ]
    lines.append(md_table(["component", "non-witness", "witness", "weight"], rows))
    lines.append("")
    lines.append(f"Exogenous skeleton total (K=1 payout): **{SKELETON_EXO_WU} WU** "
                  f"(≈ {weight_to_vbytes(SKELETON_EXO_WU)} vB before adding the transition's own witness).")
    lines.append(f"Endogenous skeleton total (K=1 payout, FULL-tier owner exit, no fee input/change): "
                  f"**{SKELETON_ENDO_WU} WU** (≈ {weight_to_vbytes(SKELETON_ENDO_WU)} vB).")
    lines.append(f"Each extra payout output beyond the first adds **{EXTRA_PAYOUT_WU} WU** (43 vB).")
    lines.append("")
    return "\n".join(lines)


def row_report(label, row, k_payouts=1, endogenous=False):
    weight = tx_weight_wu(row["total_witness_wu"], k_payouts=k_payouts, endogenous=endogenous)
    vbytes = weight_to_vbytes(weight)
    fees = fee_at_rates(vbytes)
    return dict(label=label, row=row, k_payouts=k_payouts, endogenous=endogenous,
                weight=weight, vbytes=vbytes, fees=fees)


def section_main_table(reports):
    lines = ["## Weight, vbytes and fee by fee rate\n"]
    headers = ["case", "total witness (WU)", "tx weight (WU)", "vbytes"] + [f"{r} sat/vB" for r in FEE_RATES]
    rows = []
    for rep in reports:
        row = [
            rep["label"],
            rep["row"]["total_witness_wu"],
            rep["weight"],
            rep["vbytes"],
        ] + [fmt_sat(rep["fees"][r]) for r in FEE_RATES]
        rows.append(row)
    lines.append(md_table(headers, rows))
    lines.append("")
    return "\n".join(lines)


def section_exit2_marginal(rows):
    exit1 = find_row(rows, "D", 16, "EXIT_1 (owner)")
    exit2 = find_row(rows, "D", 16, "EXIT_2")
    r1 = row_report("EXIT_1, D=16 dense (1 payout)", exit1, k_payouts=1)
    r2 = row_report("EXIT_2, D=16 dense (2 payouts)", exit2, k_payouts=2)
    marginal_weight = r2["weight"] - r1["weight"]
    marginal_vbytes = weight_to_vbytes(marginal_weight) if marginal_weight >= 0 else -weight_to_vbytes(-marginal_weight)
    marginal_fees = fee_at_rates(marginal_vbytes)

    lines = ["## EXIT_2: marginal cost of a second exit in the same transaction\n"]
    lines.append(section_main_table([r1, r2]).split("\n", 2)[2])  # reuse table body without heading
    lines.append("")
    lines.append(
        f"Second exit, marginal: **{exit2['total_witness_wu'] - exit1['total_witness_wu']} WU** of witness "
        f"+ {EXTRA_PAYOUT_WU} WU for its payout output = **{marginal_weight} WU** "
        f"(≈ {marginal_vbytes} vB) on top of a standalone EXIT_1, versus "
        f"{r1['weight']} WU (≈ {r1['vbytes']} vB) for a separate EXIT_1 transaction."
    )
    headers = ["", "marginal weight (WU)", "marginal vbytes"] + [f"{r} sat/vB" for r in FEE_RATES]
    row = ["second exit (marginal)", marginal_weight, marginal_vbytes] + [fmt_sat(marginal_fees[r]) for r in FEE_RATES]
    lines.append("")
    lines.append(md_table(headers, [row]))
    lines.append("")
    return "\n".join(lines), r1, r2


def section_evict(rows):
    lines = ["## EVICT_SUBTREE_h: cohort sweep, per-leaf cost\n"]
    specs = [
        ("EVICT_SUBTREE_4", 16, "EVICT_SUBTREE_4", 13),
        ("EVICT_SUBTREE_6", 16, "EVICT_SUBTREE_6", 51),
    ]
    reports = []
    for label, d, prefix, leaves in specs:
        row = find_row(rows, "D/subtree", d, prefix)
        rep = row_report(f"{label}, D={d} ({leaves} leaves swept)", row, k_payouts=leaves)
        rep["leaves"] = leaves
        reports.append(rep)

    headers = ["case", "leaves swept", "tx weight (WU)", "vbytes", "vbytes/leaf"] + [f"{r} sat/vB (per leaf)" for r in FEE_RATES]
    body = []
    for rep in reports:
        per_leaf_vbytes = rep["vbytes"] / rep["leaves"]
        per_leaf_fees = {r: rep["fees"][r] / rep["leaves"] for r in FEE_RATES}
        body.append([
            rep["label"], rep["leaves"], rep["weight"], rep["vbytes"],
            f"{per_leaf_vbytes:.1f}",
        ] + [f"{per_leaf_fees[r]:.2f}" for r in FEE_RATES])
    lines.append(md_table(headers, body))
    lines.append("")
    lines.append(
        "For comparison, sequential single-leaf `EXIT_1` transactions at D=16 dense cost "
        f"{find_row(rows, 'D', 16, 'EXIT_1 (owner)')['total_witness_wu']} WU of witness *each*, "
        "i.e. a full standalone transaction (skeleton + witness) per leaf; see the main table above."
    )
    lines.append("")
    return "\n".join(lines), reports


def section_comparisons():
    lines = ["## Comparison points\n"]
    lines.append(
        "**(a) Plain P2TR -> P2TR transaction.** Floor cost of any on-chain "
        "movement: ~111 vB (1 input, 2 outputs, key-path spend), independent of "
        "any tree.\n"
    )
    plain_vbytes = 111
    plain_fees = fee_at_rates(plain_vbytes)
    lines.append(md_table(
        ["case", "vbytes"] + [f"{r} sat/vB" for r in FEE_RATES],
        [["plain P2TR -> P2TR", plain_vbytes] + [fmt_sat(plain_fees[r]) for r in FEE_RATES]],
    ))
    lines.append("")
    lines.append(
        "**(b) Ark/CTV-style unilateral exit from a radix-2 tree of `2^D` leaves.** "
        "Modelled as `D` transactions of ~600 WU (150 vB) each, walking the tree "
        "down to the leaf, plus one leaf-claim transaction assumed to cost the "
        "same as a plain P2TR spend (~111 vB; this is an explicit modelling "
        "assumption, not a measurement). Total vbytes = `D * 150 + 111`.\n"
    )
    ark_rows = []
    for d in [8, 12, 16, 20, 24, 32]:
        v = d * 150 + plain_vbytes
        fees = fee_at_rates(v)
        ark_rows.append([f"D={d} ({2**d:,} leaves)", d, v] + [fmt_sat(fees[r]) for r in FEE_RATES])
    lines.append(md_table(
        ["case", "D (txs)", "vbytes"] + [f"{r} sat/vB" for r in FEE_RATES],
        ark_rows,
    ))
    lines.append("")
    return "\n".join(lines), plain_vbytes, ark_rows


def section_breakeven(reports):
    lines = ["## Break-even balance: fee as % of leaf amount\n"]
    lines.append(
        "For each case and fee rate, the leaf amount (balance) at which the "
        "fee equals 1%, 5% or 10% of the balance. Larger balances cost a "
        "smaller *fraction* to exit at the same fee rate; smaller balances "
        "cost a larger fraction.\n"
    )
    for rep in reports:
        lines.append(f"**{rep['label']}** ({rep['vbytes']} vbytes)\n")
        headers = ["fee rate (sat/vB)", "fee (sat)"] + [f"balance @ {int(p*100)}%" for p in BREAKEVEN_PCTS]
        body = []
        for r in FEE_RATES:
            fee = rep["fees"][r]
            be = breakeven_balances(fee)
            body.append([r, fmt_sat(fee)] + [fmt_sat(be[p]) for p in BREAKEVEN_PCTS])
        lines.append(md_table(headers, body))
        lines.append("")
    return "\n".join(lines)


def section_min_leaf(exo_rep, endo_rep):
    lines = ["## Minimum economical leaf size\n"]
    lines.append(
        f"Below this leaf amount the exit is a net loss (fee >= balance) or "
        f"the payout output cannot clear the P2TR dust limit ({DUST_LIMIT_SAT} sat). "
        "Exogenous: leaf pays out in full, fee comes from elsewhere, so the "
        "floor is `max(fee, dust) + 1`. Endogenous (FULL-tier owner exit "
        "only): fee is deducted from the payout, so the floor is "
        "`fee + dust + 1`, using the endogenous transaction's own (smaller) "
        "vbytes.\n"
    )
    lines.append(f"**{exo_rep['label']}**: {exo_rep['vbytes']} vbytes. "
                 f"**{endo_rep['label']}**: {endo_rep['vbytes']} vbytes.\n")
    headers = ["fee rate (sat/vB)", "exo fee (sat)", "min leaf, exogenous",
               "endo fee (sat)", "min leaf, endogenous"]
    body = []
    for r in FEE_RATES:
        exo_fee = exo_rep["fees"][r]
        endo_fee = endo_rep["fees"][r]
        body.append([
            r, fmt_sat(exo_fee),
            fmt_sat(min_economical_leaf(exo_fee, endogenous=False)),
            fmt_sat(endo_fee),
            fmt_sat(min_economical_leaf(endo_fee, endogenous=True)),
        ])
    lines.append(md_table(headers, body))
    lines.append("")
    return "\n".join(lines)


def section_endogenous(rows):
    lines = ["## Endogenous vs. exogenous fees (FULL tier owner exit)\n"]
    lines.append(
        "FULL-tier owners MAY pay the exit fee out of the payout itself "
        "(output 1's amount set below `leaf.amount`, spec 7.2 rule 3 / 9.3), "
        "instead of adding a separate fee input. This drops the fee input "
        "(41 vB + 27 vB witness, i.e. 41 vB non-witness + 108 WU witness) "
        "and the change output it would otherwise need (31 vB).\n"
    )
    exit1 = find_row(rows, "D", 16, "EXIT_1 (owner)")
    exo = row_report("FULL D=16, exogenous (separate fee input + change)", exit1, endogenous=False)
    endo = row_report("FULL D=16, endogenous (fee from payout)", exit1, endogenous=True)
    saved_wu = exo["weight"] - endo["weight"]
    saved_vb = exo["vbytes"] - endo["vbytes"]
    lines.append(section_main_table([exo, endo]).split("\n", 2)[2])
    lines.append("")
    lines.append(
        f"Saving: **{saved_wu} WU** (≈ **{saved_vb} vbytes**) per exit, "
        f"a {saved_vb / exo['vbytes'] * 100:.1f}% reduction in this example. "
        "The saving is the same in absolute vbytes for every profile/tier/D, "
        "since it comes entirely from dropping the fee input and change "
        "output, not from the transition script itself."
    )
    lines.append("")
    return "\n".join(lines), exo, endo


def main():
    rows = parse_sizes_md()

    out = []
    out.append("# LayerTree exit fee analysis (generated by tools/fee_analysis.py)\n")
    out.append(section_skeleton())

    reports = []
    reports.append(row_report("FULL dense EXIT_1, D=8", find_row(rows, "D", 8, "EXIT_1 (owner)")))
    reports.append(row_report("FULL dense EXIT_1, D=12", find_row(rows, "D", 12, "EXIT_1 (owner)")))
    reports.append(row_report("FULL dense EXIT_1, D=16", find_row(rows, "D", 16, "EXIT_1 (owner)")))
    reports.append(row_report("FULL dense EXIT_1, D=20", find_row(rows, "D", 20, "EXIT_1 (owner)")))
    reports.append(row_report("FULL sparse EXIT_1, D=32 (six leaves)", find_row(rows, "S", 32, "EXIT_1 (owner)")))
    reports.append(row_report("FULL sparse EXIT_1, D=32 (2^16 members)", find_row(rows, "S/65536", 32, "EXIT_1 (owner)")))
    reports.append(row_report("FULL sparse EXIT_1, D=64 (six leaves)", find_row(rows, "S", 64, "EXIT_1 (owner)")))
    reports.append(row_report("MID dense EXIT_1, D=16", find_row(rows, "MID/D", 16, "EXIT_1 (owner)")))
    reports.append(row_report("MIN dense EXIT_1, D=16", find_row(rows, "MIN/D", 16, "EXIT_1 (owner)")))

    out.append(section_main_table(reports))

    exit2_section, exit1_d16, exit2_d16 = section_exit2_marginal(rows)
    out.append(exit2_section)

    evict_section, evict_reports = section_evict(rows)
    out.append(evict_section)

    comp_section, plain_vbytes, ark_rows = section_comparisons()
    out.append(comp_section)

    # break-even and minimum-leaf tables: use the headline dense rows plus
    # sparse D=32 plus the two EVICT_SUBTREE cases (per-leaf) plus the plain
    # P2TR floor.
    be_reports = [reports[0], reports[2], reports[3], reports[4], reports[5]]  # D=8,16,20 dense; D=32 sparse, six leaves and 2^16 members
    out.append(section_breakeven(be_reports))

    endo_section, exo_rep, endo_rep = section_endogenous(rows)

    out.append(section_min_leaf(exo_rep, endo_rep))  # FULL D=16 dense, the headline case

    out.append(endo_section)

    print("\n".join(out))


if __name__ == "__main__":
    main()
