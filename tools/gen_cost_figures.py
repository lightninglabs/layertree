#!/usr/bin/env python3
"""Generate the cost figures under design/figures/ with matplotlib.

This generator needs matplotlib (3.10 was used) and is not part of the CI
matrix; the rest of the repository's tools are dependency-free. Run it from
the repository root:

    python3 tools/gen_cost_figures.py [--png-dir DIR] [--pdf-dir DIR]

The SVG output is deterministic (no dates, a fixed hash salt, text kept as
text), so a re-run leaves the files byte-identical. With --png-dir, a 2x
PNG twin of each figure is also written there for inspection. With
--pdf-dir, a PDF twin of each figure is written there for the paper
(paper/figures); it carries no creation date or producer string, so it is
deterministic too.
"""

import argparse
import os

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.lines import Line2D  # noqa: E402
from matplotlib.patches import Patch  # noqa: E402
from matplotlib.ticker import NullLocator  # noqa: E402

# ---------------------------------------------------------------------------
# Data. Every number is a measured or derived vbyte count taken from the
# sources named next to it; nothing here is computed from the simulator at
# run time, so a changed measurement must be edited here by hand.
# ---------------------------------------------------------------------------

# Exit anatomy. Source: spec/scripts/sizes.md and spec/fee-analysis.md for
# the FULL, MID and MIN rows (fee analysis model: 946 WU skeleton, one
# payout); the CCV row is the PR #6 size table and the OP_MERKLESUMUPDATE
# row is the PR #7 size table (a hypothetical native opcode). Each tuple is
# (label, witness, script, total). The skeleton (236.5 vB) and control
# block (32.25 vB) are identical in every LayerTree row.
SKELETON_VB = 236.5
CONTROL_VB = 32.25
EXIT_ROWS = [
    ("FULL dense D=16", 225.5, 525.25, 1020),
    ("FULL dense D=8", 143.5, 349.25, 762),
    ("FULL sparse D=32", 81.5, 1286.75, 1637),
    ("MID dense D=16", 244.5, 841.75, 1355),
    ("MIN dense D=16", 293.75, 910.0, 1473),
    ("CCV tier 0xC2 D=16 (PR #6)", 209.5, 429.0, 908),
    ("CCV + native OP_MERKLESUMUPDATE (PR #7, hypothetical)",
     56.25, 63.0, 388),
]
# Reference exits from spec/fee-analysis.md: a bare P2TR key-path spend
# (1 in, 1 out) and an Ark / CTV-model transaction-tree exit at depth 16.
BARE_SPEND_VB = 111
TREE_EXIT_VB = 2511

# Exit amortisation, vB per leaf removed in one transaction against the
# batch size. "Owner exits" is measured (spec/fee-analysis.md, one and two
# leaves); the cohort rewrite exits are the measured REWRITE_2/4/6 with
# every position leaving, priced by the fee analysis model with one 43 vB
# payout per leaf (364, 200 and 162 vB per leaf at 4, 16 and 64
# positions, spec 11's table; the serialised transactions are in
# spec/scripts/weights.md); the operator sweeps are the measured
# EVICT_SUBTREE_4/6/8 sizes divided by the leaves they remove (13, 51
# and 205: every fifth position of the measured cohorts is empty),
# spec/scripts/sizes.md, with the same model.
OWNER_EXITS = [(1, 1020), (2, 842)]
REWRITE_EXITS = [(4, 364), (16, 200), (64, 162)]
OPERATOR_SWEEPS = [(13, 203), (51, 158), (205, 147)]
# The sweeps at D = 16 only, h = 2, 4 and 6 (3, 13 and 51 leaves swept),
# for the cohort figure; EVICT_SUBTREE_2 is 3,889 WU of witness, 1,295 vB.
SWEEPS_D16 = [(3, 432), (13, 203), (51, 158)]
SECOND_EXIT_VB = 665  # marginal second exit in EXIT_2, spec/fee-analysis.md.
BATCH_OUTPUT_VB = 43  # one P2TR output inside a batch transaction.

# Join amortisation, vB per member admitted. Dense JOIN_h admits 2^h
# members at depth D=16; the script walks D-h levels, so each point is
# extrapolated from the JOIN_2 rows of spec/scripts/sizes.md at 88 script
# and 41 witness bytes per level (JOIN_0 and JOIN_2 at D=16 are measured
# directly). Sparse JOIN_0 and JOINK_2 at D=32 are measured in
# spec/scripts/sizes.md. The on-chain batch line is derived: 43 vB per
# P2TR output plus 68.5 vB of shared transaction overhead (version,
# locktime, counts and one input) divided by the batch size N. The
# Lightning open is a one-input, two-output P2TR funding transaction
# (about 154 vB), not a figure from the spec.
JOIN_DENSE = [(1, 980), (4, 229), (16, 53), (64, 12.3), (256, 2.8),
              (1024, 0.64), (4096, 0.145)]
JOIN_SPARSE = [(1, 1644), (2, 1432)]
BATCH_OVERHEAD_VB = 68.5
LN_OPEN_VB = 154

# Lifetime bytes per member, entry plus exit (vB), derived by summing the
# entry and exit figures above for each scenario; the assumptions are
# listed in design/cost-comparison.md. Lightning in the last scenario is a
# batched open of 43 plus a simple taproot channel's force close of 530
# (a 240 vB commitment, its 152 vB anchor child and a 138 vB sweep, as
# derived in paper/appendix-channels.tex and paper/full-cost.tex). The
# order within a scenario is fixed: dense, sparse, Lightning, Ark, bare
# on-chain.
LIFETIME_GROUPS = [
    ("Enters in a batch, never exits alone", [3, 1644, 197, 86, 154]),
    ("Enters in a batch, exits in a batch", [162, 3108, 197, 86, 154]),
    ("Enters in a batch, exits alone", [1023, 3281, 573, 2554, 154]),
]

# ---------------------------------------------------------------------------
# Style constants and helpers. Figures are 760 px wide at 100 dpi, so one
# pixel is 0.72 pt; PX converts a pixel size to the points matplotlib wants.
# ---------------------------------------------------------------------------

WIDTH = 760
PX = 0.72
SURFACE = "#fcfcfb"
INK = "#0b0b0b"
INK2 = "#52514e"
INK3 = "#898781"
GRID = "#e1e0d9"
BASE = "#c3c2b7"
BLUE = "#2a78d6"
BLUE_LIGHT = "#86b6ef"
ORANGE = "#eb6834"
AQUA = "#1baf7a"
GRAY = "#898781"
RAMP = ["#86b6ef", "#5598e7", "#2a78d6", "#184f95"]
OUT_DIR = os.path.join("design", "figures")
PDF_DIR = None  # set from --pdf-dir in main().

matplotlib.rcParams.update({
    "svg.fonttype": "none",
    "svg.hashsalt": "layertree",
    "font.family": "sans-serif",
    "font.sans-serif": ["Helvetica Neue", "Helvetica", "Arial",
                        "DejaVu Sans"],
    "font.size": 12 * PX,
    "text.color": INK,
    "axes.edgecolor": BASE,
    "axes.labelcolor": INK3,
    "xtick.color": INK3,
    "ytick.color": INK3,
    "xtick.labelsize": 11 * PX,
    "ytick.labelsize": 11 * PX,
    "axes.linewidth": 1 * PX,
    "figure.facecolor": SURFACE,
    "axes.facecolor": SURFACE,
    "savefig.facecolor": SURFACE,
    "pdf.fonttype": 42,
})


def fmt(v):
    """Plain number with thousands commas and no trailing zeros."""
    if abs(v - round(v)) < 1e-9:
        return "{:,}".format(int(round(v)))
    if v < 1:
        return ("%.3f" % v).rstrip("0").rstrip(".")
    return ("%.2f" % v).rstrip("0").rstrip(".")


class Fig:
    """A figure with a header, a legend and one plot axes placed in px."""

    def __init__(self, height, title, subtitle):
        self.W, self.H = WIDTH, height
        self.fig = plt.figure(figsize=(WIDTH / 100.0, height / 100.0),
                              dpi=100, facecolor=SURFACE)
        self.text(24, 28, title, 13, INK, weight="semibold")
        self.text(24, 46, subtitle, 11, INK2)

    def text(self, x, y, s, size, color, ha="left", weight="normal"):
        self.fig.text(x / self.W, 1 - y / self.H, s, fontsize=size * PX,
                      color=color, ha=ha, va="baseline", weight=weight)

    def axes(self, left, top, right, bottom):
        ax = self.fig.add_axes([left / self.W, 1 - bottom / self.H,
                                (right - left) / self.W,
                                (bottom - top) / self.H])
        ax.set_facecolor(SURFACE)
        for s in ("top", "right"):
            ax.spines[s].set_visible(False)
        for s in ("left", "bottom"):
            ax.spines[s].set_color(BASE)
        ax.tick_params(length=0, pad=6)
        ax.set_axisbelow(True)
        self.left, self.right, self.top, self.bottom = (left, right, top,
                                                        bottom)
        return ax

    def legend(self, handles, labels, y, ncol=1, x=24):
        self.fig.legend(
            handles, labels, loc="upper left", ncol=ncol, frameon=False,
            bbox_to_anchor=(x / self.W, 1 - (y - 12) / self.H),
            fontsize=12 * PX, labelcolor=INK, handlelength=1.6,
            handletextpad=0.6, columnspacing=1.8, borderpad=0,
            labelspacing=0.5, borderaxespad=0)

    def save(self, name, png_dir):
        os.makedirs(OUT_DIR, exist_ok=True)
        self.fig.savefig(os.path.join(OUT_DIR, name), format="svg",
                         metadata={"Date": None, "Creator": None},
                         facecolor=SURFACE)
        if png_dir:
            self.fig.savefig(os.path.join(png_dir, name[:-4] + ".png"),
                             dpi=200, facecolor=SURFACE)
        if PDF_DIR:
            self.fig.savefig(os.path.join(PDF_DIR, name[:-4] + ".pdf"),
                             format="pdf", facecolor=SURFACE,
                             metadata={"Creator": None, "Producer": None,
                                       "CreationDate": None})
        plt.close(self.fig)


def hgrid(ax):
    ax.grid(axis="y", color=GRID, linewidth=1 * PX, linestyle="-")


def vgrid(ax):
    ax.grid(axis="x", color=GRID, linewidth=1 * PX, linestyle="-")


def log_x(ax, ticks, lo, hi):
    ax.set_xscale("log")
    ax.set_xlim(lo, hi)
    ax.set_xticks(ticks)
    ax.set_xticklabels([fmt(t) for t in ticks])
    ax.xaxis.set_minor_locator(NullLocator())


def line_handle(color, hollow=False, marker=True, lw=2):
    return Line2D([0], [0], color=color, lw=lw * PX,
                  marker="o" if marker else None, markersize=9 * PX,
                  markerfacecolor="white" if hollow else color,
                  markeredgecolor=color if hollow else SURFACE,
                  markeredgewidth=2 * PX, solid_joinstyle="round")


def series(ax, pts, color, hollow=False, line=True, z=3):
    xs = [p[0] for p in pts]
    ys = [p[1] for p in pts]
    if line:
        ax.plot(xs, ys, color=color, lw=2 * PX, solid_joinstyle="round",
                solid_capstyle="round", zorder=z)
    ax.plot(xs, ys, linestyle="none", marker="o", markersize=9 * PX,
            markerfacecolor="white" if hollow else color,
            markeredgecolor=color if hollow else SURFACE,
            markeredgewidth=2 * PX, zorder=z + 1, clip_on=False)


def label(ax, x, y, s, dx, dy, ha="left", size=12, color=INK):
    ax.annotate(s, (x, y), xytext=(dx, dy), textcoords="offset points",
                ha=ha, va="center", fontsize=size * PX, color=color,
                annotation_clip=False)


# ---------------------------------------------------------------------------
# Figure 1: exit anatomy.
# ---------------------------------------------------------------------------

def fig_exit_anatomy(png_dir):
    rows = [("bare P2TR spend, 1 in 1 out", None, GRAY, BARE_SPEND_VB)]
    for r in sorted(EXIT_ROWS, key=lambda r: r[3]):
        rows.append((r[0], r, None, r[3]))
    rows.append(("transaction-tree exit, D=16 (Ark / CTV model)", None,
                 ORANGE, TREE_EXIT_VB))
    nrows, rh, bt = len(rows), 28, 20
    left, right, top = 372, 706, 100
    bottom = top + rh * nrows
    f = Fig(bottom + 56, "What one unilateral exit costs, by variant",
            "vbytes per transaction, fee analysis model: 946 WU skeleton, "
            "one payout, dense D=16 unless noted")
    ax = f.axes(left, top, right, bottom)
    xmax = 2600.0
    ax.set_xlim(0, xmax)
    ax.set_ylim(nrows - 0.5, -0.5)
    ax.set_xticks(range(0, 2501, 500))
    ax.set_xticklabels([fmt(t) for t in range(0, 2501, 500)])
    ax.set_yticks(range(nrows))
    ax.set_yticklabels([r[0] for r in rows], fontsize=12 * PX, color=INK)
    ax.spines["bottom"].set_visible(False)
    vgrid(ax)
    gap = 2.0 * xmax / (right - left)
    h = float(bt) / rh
    for i, (_, seg, color, total) in enumerate(rows):
        if seg is None:
            ax.barh(i, total, height=h, color=color, linewidth=0)
        else:
            x = 0.0
            vals = [SKELETON_VB, CONTROL_VB, seg[1], seg[2]]
            for j, v in enumerate(vals):
                w = v - (gap if j < 3 else 0)
                ax.barh(i, w, left=x, height=h, color=RAMP[j], linewidth=0)
                x += v
        label(ax, total, i, fmt(total), 4, 0)
    f.legend([Patch(color=c) for c in RAMP + [GRAY, ORANGE]],
             ["skeleton", "control block", "witness data", "script",
              "bare on-chain reference", "transaction-tree exit"], 68,
             ncol=6)
    f.text(right, bottom + 36, "vbytes", 11, INK3, ha="right")
    f.text(24, bottom + 50, "Skeleton and control block are 236.5 and "
           "32.25 vB in every LayerTree row.", 11, INK2)
    f.save("exit-anatomy.svg", png_dir)


# ---------------------------------------------------------------------------
# Figure 2: exit amortisation.
# ---------------------------------------------------------------------------

def fig_exit_amortisation(png_dir):
    f = Fig(420, "Cost per leaf falls with batch size, and who has to "
            "cooperate", "vbytes per leaf removed, against leaves removed "
            "in one transaction (log scale)")
    ax = f.axes(64, 128, 590, 366)
    log_x(ax, [1, 2, 4, 8, 16, 32, 64, 128, 256], 1, 300)
    ax.set_ylim(0, 1100)
    ax.set_yticks(range(0, 1001, 200))
    ax.set_yticklabels([fmt(t) for t in range(0, 1001, 200)])
    ax.spines["left"].set_visible(False)
    vgrid(ax)
    hgrid(ax)
    for v, s in ((BARE_SPEND_VB, "bare P2TR spend 111"),
                 (BATCH_OUTPUT_VB, "one output in a batch tx 43")):
        ax.axhline(v, color=BASE, lw=1 * PX, zorder=2)
        ax.annotate(s, (1, v), xycoords=("axes fraction", "data"),
                    xytext=(8, 0), textcoords="offset points", va="center",
                    fontsize=11 * PX, color=INK3, annotation_clip=False)
    ax.text(0.99, 0.985, "transaction-tree exit: 2,511 per leaf "
            "(off scale)", transform=ax.transAxes, ha="right", va="top",
            fontsize=12 * PX, color=INK2,
            bbox={"facecolor": SURFACE, "edgecolor": "none", "pad": 2})
    series(ax, OPERATOR_SWEEPS, AQUA)
    series(ax, REWRITE_EXITS, BLUE, hollow=True, line=False)
    series(ax, OWNER_EXITS, BLUE)
    label(ax, 1, 1020, "1,020", 10, 0)
    label(ax, 2, 842, "842", 10, 0)
    label(ax, 13, 203, "203", -10, -9, ha="right")
    label(ax, 205, 147, "147", 0, 12, ha="center")
    f.legend([line_handle(BLUE), line_handle(BLUE, hollow=True),
              line_handle(AQUA)],
             ["Owner exits, measured",
              "Cohort rewrite exits REWRITE_h, measured (spec 7.9)",
              "Operator sweeps, measured (EVICT_SUBTREE_4/6/8)"], 68)
    f.text(590, 366 + 36, "leaves removed in one transaction", 11, INK3,
           ha="right")
    f.text(64, 118, "vB per leaf", 11, INK3)
    f.save("exit-amortisation.svg", png_dir)


# ---------------------------------------------------------------------------
# Figure 3: join amortisation.
# ---------------------------------------------------------------------------

def fig_join_amortisation(png_dir):
    f = Fig(450, "Entry cost per member: a dense graft admits a cohort "
            "for one price", "vbytes per member admitted, against members "
            "admitted in one transaction (log-log)")
    ax = f.axes(64, 144, 650, 396)
    log_x(ax, [1, 4, 16, 64, 256, 1024, 4096], 1, 4096)
    ax.set_yscale("log")
    ax.set_ylim(0.1, 2000)
    yt = [0.1, 1, 10, 100, 1000]
    ax.set_yticks(yt)
    ax.set_yticklabels([fmt(t) for t in yt])
    ax.yaxis.set_minor_locator(NullLocator())
    ax.spines["left"].set_visible(False)
    vgrid(ax)
    hgrid(ax)
    ax.axhline(LN_OPEN_VB, color=AQUA, lw=1.5 * PX, zorder=2)
    xs = [p[0] for p in JOIN_DENSE]
    ax.plot(xs, [BATCH_OUTPUT_VB + BATCH_OVERHEAD_VB / x for x in xs],
            color=GRAY, lw=2 * PX, solid_joinstyle="round", zorder=3)
    series(ax, JOIN_SPARSE, BLUE_LIGHT)
    series(ax, JOIN_DENSE, BLUE)
    label(ax, 1, 1644, "1,644 (sparse)", 10, 8)
    label(ax, 1, 980, "980", 4, -14, ha="center")
    label(ax, 4096, 0.145, "0.145", 10, 0)
    f.legend([line_handle(BLUE), line_handle(BLUE_LIGHT),
              line_handle(GRAY, marker=False),
              line_handle(AQUA, marker=False, lw=1.5)],
             ["Dense JOIN_h, D=16 (2^h members)",
              "Sparse JOIN_0 / JOINK_2, D=32",
              "One output in an on-chain batch",
              "Lightning channel open, own transaction"], 68, ncol=2)
    f.text(650, 396 + 36, "members admitted in one transaction", 11, INK3,
           ha="right")
    f.text(650, 132, "vB per member", 11, INK3, ha="right")
    f.save("join-amortisation.svg", png_dir)


# ---------------------------------------------------------------------------
# Figure 4: lifetime bytes.
# ---------------------------------------------------------------------------

def fig_lifetime(png_dir):
    systems = [("LayerTree dense D=16", BLUE),
               ("LayerTree sparse D=32", BLUE_LIGHT),
               ("Lightning channel", AQUA),
               ("Ark round tree, D=16", ORANGE),
               ("Bare on-chain UTXO", GRAY)]
    bt, gap, gtitle, ggap = 16, 2, 20, 16
    gh = gtitle + len(systems) * bt + (len(systems) - 1) * gap
    top = 120
    ngroups = len(LIFETIME_GROUPS)
    plot_h = ngroups * gh + (ngroups - 1) * ggap
    bottom = top + plot_h
    f = Fig(bottom + 56, "Lifetime on-chain bytes per member, entry plus "
            "exit", "vbytes per member over the whole life of the "
            "position, fee analysis model, one payout")
    ax = f.axes(40, top, 680, bottom)
    ax.set_xlim(0, 3500)
    ax.set_ylim(plot_h, 0)  # Pixel units, top to bottom.
    ax.set_yticks([])
    ax.set_xticks(range(0, 3501, 500))
    ax.set_xticklabels([fmt(t) for t in range(0, 3501, 500)])
    ax.spines["bottom"].set_visible(False)
    vgrid(ax)
    for g, (title, vals) in enumerate(LIFETIME_GROUPS):
        y0 = g * (gh + ggap)
        ax.text(0, y0 + 12, title, fontsize=12 * PX, color=INK,
                weight="semibold", va="baseline", ha="left")
        for i, v in enumerate(vals):
            yc = y0 + gtitle + i * (bt + gap) + bt / 2.0
            ax.barh(yc, v, height=bt, color=systems[i][1], linewidth=0)
            label(ax, v, yc, fmt(v), 4, 0, size=11)
    f.legend([Patch(color=c) for _, c in systems], [s for s, _ in systems],
             68, ncol=3)
    f.text(680, bottom + 36, "vbytes", 11, INK3, ha="right")
    f.save("lifetime.svg", png_dir)


# ---------------------------------------------------------------------------
# Figure 5: EXIT_1 bytes by profile and depth.
# ---------------------------------------------------------------------------

# Raw bytes (not vbytes) of one EXIT_1 leaf script and its witness, FULL
# tier, from spec/scripts/sizes.md. Each tuple is (label, script, witness);
# the dense rows are drawn first, then a gap, then the sparse rows.
PROFILE_DENSE = [
    ("dense D=8", 1397, 574),
    ("dense D=12", 1749, 738),
    ("dense D=16, 65k slots", 2101, 902),
    ("dense D=20", 2453, 1066),
]
PROFILE_SPARSE = [
    ("sparse D=32", 5147, 326),
    ("sparse D=32, bitmap proofs", 5423, 330),
    ("sparse D=64", 9499, 326),
    ("sparse D=64, bitmap proofs", 10063, 334),
]


def fig_exit_profiles(png_dir):
    bt, pitch, ggap = 20, 28, 18
    nd, ns = len(PROFILE_DENSE), len(PROFILE_SPARSE)
    top = 100
    plot_h = (nd + ns) * pitch + ggap
    bottom = top + plot_h
    f = Fig(bottom + 62, "Dense proofs are small scripts; sparse proofs "
            "are small witnesses", "EXIT_1 bytes by profile and depth, "
            "FULL tier (spec/scripts/sizes.md)")
    ax = f.axes(200, top, 560, bottom)
    ax.set_xlim(0, 11000)
    ax.set_ylim(plot_h, 0)  # Pixel units, top to bottom.
    ax.set_xticks(range(0, 11001, 2000))
    ax.set_xticklabels([fmt(t) for t in range(0, 11001, 2000)])
    ax.spines["bottom"].set_visible(False)
    vgrid(ax)
    gap = 2.0 * 11000 / 360.0
    ys, names = [], []
    for k, (name, scr, wit) in enumerate(PROFILE_DENSE + PROFILE_SPARSE):
        yc = k * pitch + pitch / 2.0 + (ggap if k >= nd else 0)
        ys.append(yc)
        names.append(name)
        ax.barh(yc, scr - gap, height=bt, color=RAMP[3], linewidth=0)
        ax.barh(yc, wit, left=scr, height=bt, color=RAMP[2], linewidth=0)
        label(ax, scr + wit, yc, "%s (witness %s)" % (fmt(scr + wit),
                                                     fmt(wit)), 4, 0,
              size=11)
    ax.set_yticks(ys)
    ax.set_yticklabels(names, fontsize=12 * PX, color=INK)
    sep = nd * pitch + ggap / 2.0
    ax.axhline(sep, color=BASE, lw=1 * PX, zorder=1)
    f.legend([Patch(color=RAMP[3]), Patch(color=RAMP[2])],
             ["script", "witness data"], 68, ncol=2)
    f.text(560, bottom + 34, "bytes", 11, INK3, ha="right")
    f.text(24, bottom + 52, "sparse D=256: 35,611 script and 285 "
           "witness, off scale", 11, INK2)
    f.save("exit-profiles.svg", png_dir)


# ---------------------------------------------------------------------------
# Figure 6: cost of one level.
# ---------------------------------------------------------------------------

# Bytes per level of the unrolled path as (label, script, witness), from
# spec/scripts/sizes.md.
LEVEL_COSTS = [
    ("dense LEVEL", 88, 41),
    ("sparse LEVEL_S,\nempty sibling", 135, 1),
    ("sparse LEVEL_S,\noccupied sibling", 135, 41),
    ("MID dense LEVEL", 156, 46),
    ("minimal-inventory\nLEVEL_MIN", 105, 41),
]


def fig_level_cost(png_dir):
    top, bottom, left, right = 118, 340, 64, 720
    f = Fig(bottom + 76, "What one level costs", "bytes per level of the "
            "unrolled path; the script is paid at every level, the "
            "witness only for the siblings supplied")
    ax = f.axes(left, top, right, bottom)
    pw = right - left
    ax.set_xlim(0, pw)
    ax.set_ylim(0, 170)
    ax.set_yticks(range(0, 161, 20))
    ax.set_yticklabels([fmt(t) for t in range(0, 161, 20)])
    ax.spines["left"].set_visible(False)
    hgrid(ax)
    cw = 22
    gw = pw / float(len(LEVEL_COSTS))
    cx = []
    for g, (name, scr, wit) in enumerate(LEVEL_COSTS):
        c = gw * (g + 0.5)
        cx.append(c)
        for off, v, col in ((-cw / 2.0 - 1, scr, RAMP[3]),
                            (cw / 2.0 + 1, wit, RAMP[2])):
            ax.bar(c + off, v, width=cw, color=col, linewidth=0)
            ax.annotate(fmt(v), (c + off, v), xytext=(0, 4),
                        textcoords="offset points", ha="center",
                        va="bottom", fontsize=12 * PX, color=INK)
    ax.set_xticks(cx)
    ax.set_xticklabels([r[0] for r in LEVEL_COSTS], fontsize=11 * PX,
                       color=INK2, linespacing=1.3)
    f.legend([Patch(color=RAMP[3]), Patch(color=RAMP[2])],
             ["script", "witness"], 68, ncol=2)
    f.text(left, top - 10, "bytes per level", 11, INK3)
    f.save("level-cost.svg", png_dir)


# ---------------------------------------------------------------------------
# Figure 7: radix trade-off.
# ---------------------------------------------------------------------------

# Raw bytes of one EXIT_1 proving against 65,536 slots (2^18 for radix 8),
# as (label, script, witness, is_estimate). Radix 4 and 8 are measured by
# tools/experiments/radix4.py in the FULL simulator; radix 2 and sparse
# D=32 are from spec/scripts/sizes.md; the sparse radix 4 and 16 rows are
# estimates.
RADIX_DENSE = [
    ("dense, radix 2, 16 levels (measured)", 2101, 902, False),
    ("dense, radix 4, 8 levels (measured)", 1861, 1230, False),
    ("dense, radix 8, 6 levels (measured; 2^18 slots)", 1983, 1968, False),
]
RADIX_SPARSE = [
    ("sparse D=32, radix 2, 32 levels (measured)", 5147, 326, False),
    ("sparse D=32, radix 4, 16 levels (estimate)", 3707, 342, True),
    ("sparse D=32, radix 16, 8 levels (estimate)", 4587, 414, True),
]
RADIX_EST = ("#5598e7", "#86b6ef")


def fig_radix(png_dir):
    bt, pitch, ggap = 20, 28, 18
    nd, ns = len(RADIX_DENSE), len(RADIX_SPARSE)
    top = 118
    plot_h = (nd + ns) * pitch + ggap
    bottom = top + plot_h
    left, right = 340, 640
    f = Fig(bottom + 62, "A higher radix trades script for witness, and "
            "loses on the dense tree", "EXIT_1 bytes at 65,536 slots; "
            "radix 4 and 8 measured by tools/experiments/radix4.py in "
            "the FULL simulator")
    ax = f.axes(left, top, right, bottom)
    ax.set_xlim(0, 6000)
    ax.set_ylim(plot_h, 0)  # Pixel units, top to bottom.
    ax.set_xticks(range(0, 6001, 1000))
    ax.set_xticklabels([fmt(t) for t in range(0, 6001, 1000)])
    ax.spines["bottom"].set_visible(False)
    vgrid(ax)
    gap = 2.0 * 6000 / float(right - left)
    ys, names = [], []
    for k, (name, scr, wit, est) in enumerate(RADIX_DENSE + RADIX_SPARSE):
        yc = k * pitch + pitch / 2.0 + (ggap if k >= nd else 0)
        ys.append(yc)
        names.append(name)
        cs, cw = RADIX_EST if est else (RAMP[3], RAMP[2])
        ax.barh(yc, scr - gap, height=bt, color=cs, linewidth=0)
        ax.barh(yc, wit, left=scr, height=bt, color=cw, linewidth=0)
        label(ax, scr + wit, yc, "%s (witness %s)" % (fmt(scr + wit),
                                                     fmt(wit)), 4, 0,
              size=11)
    ax.set_yticks(ys)
    ax.set_yticklabels(names, fontsize=12 * PX, color=INK)
    ax.axhline(nd * pitch + ggap / 2.0, color=BASE, lw=1 * PX, zorder=1)
    f.legend([Patch(color=RAMP[3]), Patch(color=RAMP[2]),
              Patch(color=RADIX_EST[0]), Patch(color=RADIX_EST[1])],
             ["script", "witness data", "script (estimate)",
              "witness (estimate)"], 68, ncol=4)
    f.text(right, bottom + 34, "bytes", 11, INK3, ha="right")
    f.text(24, bottom + 52, "per level: radix 2 is 88 script and 41 "
           "witness bytes, radix 4 is 146 and 123, radix 8 is 215 and "
           "287", 11, INK2)
    f.save("radix.svg", png_dir)


# ---------------------------------------------------------------------------
# Figure 8: batching shapes.
# ---------------------------------------------------------------------------

# The batching shapes share the axes of the exit-amortisation figure. The
# cohort rewrite point is the measured REWRITE_6 with every key rotated
# (148 vB per changed leaf) and the detach point is an EXIT_1 at depth 8
# after a DETACH_8 (780 vB once); the depth-8 EXIT_1 is 762 vB by the
# fee analysis model (spec 11's table rounds it to 765). The other series
# reuse the constants above.
COHORT_REWRITE = [(64, 148)]
DETACH_EXIT = [(256, 762)]
VIOLET = "#4a3aa7"


def fig_batching_shapes(png_dir):
    top, bottom = 178, 416
    f = Fig(bottom + 56, "Batch shapes, measured", "vbytes per leaf against leaves handled in "
            "one transaction, dense D=16, fee analysis model")
    ax = f.axes(64, top, 590, bottom)
    log_x(ax, [1, 2, 4, 8, 16, 32, 64, 128, 256], 1, 300)
    ax.set_ylim(0, 1100)
    ax.set_yticks(range(0, 1001, 200))
    ax.set_yticklabels([fmt(t) for t in range(0, 1001, 200)])
    ax.spines["left"].set_visible(False)
    vgrid(ax)
    hgrid(ax)
    for v, s in ((BARE_SPEND_VB, "bare P2TR spend 111"),
                 (BATCH_OUTPUT_VB, "one output in a batch tx 43")):
        ax.axhline(v, color=BASE, lw=1 * PX, zorder=2)
        ax.annotate(s, (1, v), xycoords=("axes fraction", "data"),
                    xytext=(8, 0), textcoords="offset points", va="center",
                    fontsize=11 * PX, color=INK3, annotation_clip=False)
    series(ax, OPERATOR_SWEEPS, AQUA)
    series(ax, REWRITE_EXITS, BLUE, hollow=True, line=False)
    series(ax, OWNER_EXITS, BLUE)
    series(ax, COHORT_REWRITE, ORANGE, hollow=True, line=False)
    series(ax, DETACH_EXIT, VIOLET, hollow=True, line=False)
    label(ax, 1, 1020, "1,020", 10, 0)
    label(ax, 64, 158, "158", 0, 12, ha="center")
    label(ax, 64, 144, "144", 10, -4)
    label(ax, 256, 762, "762", 0, 12, ha="center")
    label(ax, 205, 147, "147", 0, 12, ha="center")
    f.legend([line_handle(BLUE), line_handle(BLUE, hollow=True),
              line_handle(AQUA),
              line_handle(ORANGE, hollow=True, marker=True),
              line_handle(VIOLET, hollow=True)],
             ["Owner exits EXIT_K, measured",
              "Cohort rewrite REWRITE_h, every leaf exits, measured",
              "Operator sweep EVICT_SUBTREE_h, measured",
              "Cohort rewrite REWRITE_h, per changed leaf, measured",
              "Detach a height-8 subtree, then exit alone at depth 8, "
              "measured"], 68)
    f.text(590, bottom + 36, "leaves handled in one transaction", 11,
           INK3, ha="right")
    f.text(64, top - 10, "vB per leaf", 11, INK3)
    f.save("batching-shapes.svg", png_dir)


# ---------------------------------------------------------------------------
# Figure 9: per-leaf cost against cohort size.
# ---------------------------------------------------------------------------

def fig_cohort_cost(png_dir):
    top, bottom = 150, 400
    f = Fig(bottom + 56, "Leaving together: per-leaf cost against cohort "
            "size", "vbytes per leaf removed, dense D=16, fee analysis "
            "model with one 43 vB payout per leaf")
    ax = f.axes(64, top, 590, bottom)
    log_x(ax, [1, 2, 4, 8, 16, 32, 64], 1, 80)
    ax.set_ylim(0, 1100)
    ax.set_yticks(range(0, 1001, 200))
    ax.set_yticklabels([fmt(t) for t in range(0, 1001, 200)])
    ax.spines["left"].set_visible(False)
    vgrid(ax)
    hgrid(ax)
    for v, s in ((SECOND_EXIT_VB, "each further exit in EXIT_K 665"),
                 (BARE_SPEND_VB, "bare P2TR spend 111")):
        ax.axhline(v, color=BASE, lw=1 * PX, zorder=2)
        ax.annotate(s, (1, v), xycoords=("axes fraction", "data"),
                    xytext=(8, 0), textcoords="offset points", va="center",
                    fontsize=11 * PX, color=INK3, annotation_clip=False)
    series(ax, OWNER_EXITS, GRAY)
    series(ax, SWEEPS_D16, AQUA)
    series(ax, REWRITE_EXITS, BLUE)
    label(ax, 1, 1020, "1,020", 10, 0)
    label(ax, 2, 842, "842", 10, 4)
    label(ax, 3, 432, "432", -10, 0, ha="right")
    label(ax, 4, 359, "359", 10, 4)
    label(ax, 13, 203, "203", -10, -6, ha="right")
    label(ax, 16, 195, "195", 10, 6)
    label(ax, 64, 158, "158", 0, 12, ha="center")
    f.legend([line_handle(GRAY), line_handle(BLUE), line_handle(AQUA)],
             ["EXIT_1 alone, then EXIT_2 (each owner carries its own "
              "path)",
              "REWRITE_2/4/6, every position exits (owners sign, no "
              "lease needed)",
              "EVICT_SUBTREE_2/4/6, every fifth position empty "
              "(operator, leases)"], 68)
    f.text(590, bottom + 36, "leaves removed in one transaction", 11,
           INK3, ha="right")
    f.text(64, top - 10, "vB per leaf", 11, INK3)
    f.save("cohort-cost.svg", png_dir)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--png-dir", help="also write 2x PNG twins here")
    ap.add_argument("--pdf-dir", help="also write PDF twins here")
    args = ap.parse_args()
    if args.png_dir:
        os.makedirs(args.png_dir, exist_ok=True)
    if args.pdf_dir:
        global PDF_DIR
        PDF_DIR = args.pdf_dir
        os.makedirs(PDF_DIR, exist_ok=True)
    fig_exit_anatomy(args.png_dir)
    fig_exit_amortisation(args.png_dir)
    fig_join_amortisation(args.png_dir)
    fig_lifetime(args.png_dir)
    fig_exit_profiles(args.png_dir)
    fig_level_cost(args.png_dir)
    fig_radix(args.png_dir)
    fig_batching_shapes(args.png_dir)
    fig_cohort_cost(args.png_dir)


if __name__ == "__main__":
    main()
