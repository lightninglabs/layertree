#!/usr/bin/env python3
"""Measure the exact weight of real LayerTree transactions.

The size figures of spec 11, spec/scripts/sizes.md, spec/fee-analysis.md
and the paper use a model: script bytes + witness data bytes + a 129-byte
control block + a 946 WU skeleton, with vB = ceil(WU / 4). The model
leaves out the witness serialisation overhead (the CompactSize item count
of the tree input's witness and one CompactSize length prefix per item,
including the script and the control block), and it assumes one fixed
skeleton whatever outputs a transition actually creates.

This tool runs the simulator's own witness builders (the test suites of
every tier), captures the witness stack and the transaction context of
every successful script run, serialises the whole transaction as Bitcoin
Core and btcd do (version, marker and flag, inputs, outputs, witness
stacks with CompactSize prefixes, locktime) and reports its exact weight
next to the model's figure. Inputs other than the tree input carry a
stub witness of the right size: 108 WU for P2WPKH (a 72-byte signature
and a 33-byte key, the model's fee input) and 66 WU for a P2TR key-path
spend. The tree input's control block is 129 bytes (the eight-leaf
reference set of spec 6.2), as in the model.

Run from the repository root:

    python3 tools/measure_weight.py

It writes spec/scripts/weights.md. Do not run it concurrently with the
other generators (gen_listings.py, gen_golden.py): it runs the same test
suites.
"""

import contextlib
import io
import math
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import layertree_ref as lt  # noqa: E402
import script_sim  # noqa: E402
from script_sim import Interp  # noqa: E402

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "spec",
                   "scripts", "weights.md")

CONTROL_BLOCK = 129          # 33 + 32 * 3: eight tapleaves (spec 6.2, 11).
SKELETON_WU = 946            # spec/fee-analysis.md, one payout.
P2WPKH_WITNESS_WU = 108      # count, 72-byte signature, 33-byte key.
P2TR_KEYPATH_WITNESS_WU = 66  # count, 64-byte signature.

# --------------------------------------------------------------------------
# Capture: wrap Interp.run so that every successful run leaves its script,
# its initial witness stack and a snapshot of its transaction on the
# interpreter object the test returns.
# --------------------------------------------------------------------------

CAPTURES = []
_orig_run = Interp.run


def _snapshot(ctx):
    return dict(version=ctx.version, locktime=ctx.locktime,
                inputs=list(ctx.inputs), outputs=list(ctx.outputs),
                sequences=list(ctx.sequences), prevouts=list(ctx.prevouts),
                index=ctx.input_index)


def _capturing_run(self, script, stack):
    items = list(stack)
    tx = _snapshot(self.ctx) if self.ctx is not None else None
    result = _orig_run(self, script, stack)
    self.mw = (bytes(script), items, tx)
    CAPTURES.append(self)
    return result


Interp.run = _capturing_run
script_sim.Interp.run = _capturing_run

# The test modules import Interp from script_sim; the patch is on the class,
# so they see it whatever the import order.
import test_scripts  # noqa: E402
import test_mid  # noqa: E402
import test_min  # noqa: E402
import test_ccv  # noqa: E402

cs = lt.compact_size


def is_p2wpkh(spk):
    return len(spk) == 22 and spk[:2] == b"\x00\x14"


def is_p2tr(spk):
    return len(spk) == 34 and spk[:2] == b"\x51\x20"


def serialise(tx, script, items):
    """Return (stripped bytes, full bytes) of the transaction."""
    ins, outs = tx["inputs"], tx["outputs"]
    body_in = cs(len(ins))
    for (txid, vout), seq in zip(tx["prevouts"], tx["sequences"]):
        body_in += txid + vout.to_bytes(4, "little") + cs(0) + seq.to_bytes(4, "little")
    body_out = cs(len(outs))
    for amount, spk in outs:
        body_out += amount.to_bytes(8, "little") + cs(len(spk)) + spk
    version = tx["version"].to_bytes(4, "little")
    locktime = tx["locktime"].to_bytes(4, "little")
    witness = b""
    for i, (_, spk) in enumerate(ins):
        if i == tx["index"]:
            stack = items + [script, bytes(CONTROL_BLOCK)]
            witness += cs(len(stack)) + b"".join(cs(len(x)) + x for x in stack)
        elif is_p2wpkh(spk):
            witness += cs(2) + cs(72) + bytes(72) + cs(33) + bytes(33)
        elif is_p2tr(spk):
            witness += cs(1) + cs(64) + bytes(64)
        else:
            raise ValueError("no witness stub for scriptPubKey %s" % spk.hex())
    stripped = version + body_in + body_out + locktime
    full = version + b"\x00\x01" + body_in + body_out + witness + locktime
    return stripped, full


def prefix_overhead(script, items):
    """Witness bytes the model omits: the item count and every length prefix."""
    stack = items + [script, bytes(CONTROL_BLOCK)]
    return len(cs(len(stack))) + sum(len(cs(len(x))) for x in stack)


def vb(wu):
    return int(math.ceil(wu / 4.0))


def shape(tx):
    def kind(spk):
        return "P2WPKH" if is_p2wpkh(spk) else "P2TR" if is_p2tr(spk) else "other"
    return "%d in / %d out (%d P2TR, %d P2WPKH)" % (
        len(tx["inputs"]), len(tx["outputs"]),
        sum(1 for _, s in tx["outputs"] if is_p2tr(s)),
        sum(1 for _, s in tx["outputs"] if is_p2wpkh(s)))


ROWS = []


def measure(tier, d, name, it, sl, wl, leaves=None):
    script, items, tx = it.mw
    assert len(script) == sl, (name, len(script), sl)
    wl_real = sum(len(x) for x in items)
    stripped, full = serialise(tx, script, items)
    weight = 3 * len(stripped) + len(full)
    model_wu = sl + wl + CONTROL_BLOCK + SKELETON_WU
    pre = prefix_overhead(script, items)
    # The tree input's witness exactly as the model counts it, plus the
    # prefixes, on the 946 WU skeleton: what the model would say if it
    # counted the prefixes.
    model_pre_wu = sl + wl_real + CONTROL_BLOCK + SKELETON_WU + pre
    skel_delta = weight - model_pre_wu
    note = shape(tx)
    if wl_real != wl:
        note += "; witness data %d B, model row says %d" % (wl_real, wl)
    ROWS.append(dict(tier=tier, d=d, name=name, sl=sl, wl=wl, wl_real=wl_real,
                     items=len(items) + 2, model_wu=model_wu, model_vb=vb(model_wu),
                     pre=pre, model_pre_vb=vb(sl + wl + CONTROL_BLOCK + SKELETON_WU + pre),
                     skel=skel_delta, wu=weight, vb=vb(weight),
                     dvb=vb(weight) - vb(model_wu), note=note, leaves=leaves))


@contextlib.contextmanager
def quiet():
    with contextlib.redirect_stdout(io.StringIO()):
        yield


def run_full():
    for d, prof in ((16, "D"), (32, "S")):
        tier = "FULL/" + prof
        with quiet():
            costs, _ = test_scripts.test_all(d, prof, verbose=False)
        for k, (it, sl, wl) in costs.items():
            measure(tier, d, k, it, sl, wl)
        for k, fn in (("UPDATE_X", test_scripts.test_update_x),
                      ("CLAIM_H", test_scripts.test_claim_h),
                      ("SPLIT", test_scripts.test_split)):
            with quiet():
                it, sl, wl = fn(d, prof, verbose=False)
            measure(tier, d, k, it, sl, wl)
    for h in (2, 4, 6):
        with quiet():
            script, wit, it = test_scripts.test_evict_subtree(16, h, verbose=False)
        n = sum(1 for i in range(1 << h) if i % 5 != 3)
        measure("FULL/D", 16, "EVICT_SUBTREE_%d (%d swept)" % (h, n), it,
                len(script), sum(len(x) for x in wit), leaves=n)
    for h in (2, 4, 6):
        for scenario in ("exit", "update", "mixed"):
            with quiet():
                c = test_scripts.rewrite_case(16, h, scenario)
                it = c["w"].run(c["name"], c["wit"], c["ctx"])
            changed = sum(1 for i in c["old"]
                          if (c["old"][i] is not None or c["new"][i] is not None)
                          and (c["old"][i] is None or c["new"][i] is None or
                               c["old"][i].serialize() != c["new"][i].serialize()))
            measure("FULL/D", 16, "REWRITE_%d (%s, %d changed)" % (h, scenario, changed), it,
                    len(c["script"]), sum(len(x) for x in c["wit"]), leaves=changed)
    start = len(CAPTURES)
    with quiet():
        it, sl, wl = test_scripts.test_detach(16, 8, verbose=False)
    measure("FULL/D", 16, "DETACH_8", it, sl, wl)
    # The EXIT_1 from the detached depth-8 tree is the next successful run.
    after = [c for c in CAPTURES[start:] if c is not it]
    ex = after[0]
    measure("FULL/D", 8, "EXIT_1 from the detached tree (owner)", ex, len(ex.mw[0]),
            sum(len(x) for x in ex.mw[1]))


def run_mid():
    for d, sparse in ((16, False), (31, True)):
        tier = "MID/" + ("S" if sparse else "D")
        with quiet():
            costs, _ = test_mid.test_mid(d, sparse, verbose=False)
        for k, (it, sl, wl) in costs.items():
            measure(tier, d, k, it, sl, wl)
        for k, fn in (("UPDATE_X", test_mid.test_update_x),
                      ("CLAIM_H", test_mid.test_claim_h),
                      ("SPLIT", test_mid.test_split)):
            with quiet():
                it, sl, wl = fn(d, sparse, verbose=False)
            measure(tier, d, k, it, sl, wl)
        for hl in (False, True):
            with quiet():
                it, sl, wl = test_mid.test_claim_x(d, sparse, hashlock=hl, verbose=False)
            measure(tier, d, "CLAIM_HX" if hl else "CLAIM_X", it, sl, wl)
    for h in (2, 4, 6):
        with quiet():
            it, script, wit = test_mid.test_evict_subtree(16, h, verbose=False)
        measure("MID/D", 16, "EVICT_SUBTREE_%d" % h, it, len(script),
                sum(len(x) for x in wit))
    start = len(CAPTURES)
    with quiet():
        it, sl, wl = test_mid.test_detach(16, 8, verbose=False)
    measure("MID/D", 16, "DETACH_8", it, sl, wl)
    # The EXIT_1 from the detached depth-8 tree is the next successful run.
    ex = [c for c in CAPTURES[start:] if c is not it][0]
    measure("MID/D", 8, "EXIT_1 from the detached tree (owner)", ex, len(ex.mw[0]),
            sum(len(x) for x in ex.mw[1]))


def run_min():
    for k, fn in (("EXIT_1 (owner)", test_min.test_min), ("SPLIT", test_min.test_split)):
        with quiet():
            script, wit, it = fn(16, verbose=False)
        measure("MIN/D", 16, k, it, len(script), sum(len(x) for x in wit))


def run_ccv():
    for d, prof in ((16, "D"), (32, "S")):
        tier = "CCV/" + prof
        with quiet():
            costs = test_ccv.test_all(d, prof, verbose=False)
        for k, (it, sl, wl) in costs.items():
            measure(tier, d, k, it, sl, wl)
        for k, fn in (("UPDATE_X", test_ccv.test_update_x_ccv),
                      ("SPLIT", test_ccv.test_split_ccv)):
            with quiet():
                it, sl, wl = fn(d, prof)
            measure(tier, d, k, it, sl, wl)
        for hl in (False, True):
            with quiet():
                it, sl, wl = test_ccv.test_claim_ccv(d, prof, "c2", hl)
            measure(tier, d, "CLAIM_H" if hl else "CLAIM", it, sl, wl)
        for hl in (False, True):
            with quiet():
                it, sl, wl = test_ccv.test_claim_x_ccv(d, prof, "c2", hl)
            measure(tier, d, "CLAIM_HX" if hl else "CLAIM_X", it, sl, wl)
    # The cohort rewrite (7.9) in both numerics, on the FULL rows' cohorts:
    # 0xC2 at h = 2, 4, 6 and 0xC0 at h = 2, 4 and the full 32-position
    # cohort at h = 5, the largest the stack limit admits (spec 4.5).
    for numeric, tier, heights in (("c2", "CCV/D", (2, 4, 6)), ("c0", "CCV-c0/D", (2, 4, 5))):
        for h in heights:
            for scenario in ("exit", "update", "mixed"):
                if numeric == "c0" and h == 5 and scenario == "mixed":
                    continue
                with quiet():
                    c = test_ccv.rewrite_case_ccv(16, h, numeric, scenario)
                    it = c["w"].run(c["name"], c["wit"], c["ctx"])
                changed = sum(1 for i in c["old"]
                              if (c["old"][i] is not None or c["new"][i] is not None)
                              and (c["old"][i] is None or c["new"][i] is None or
                                   c["old"][i].serialize() != c["new"][i].serialize()))
                measure(tier, 16, "REWRITE_%d (%s, %d changed)" % (h, scenario, changed), it,
                        len(c["script"]), sum(len(x) for x in c["wit"]), leaves=changed)


def write(path):
    lines = []
    lines.append("# Measured transaction weights\n")
    lines.append("Generated by `tools/measure_weight.py`; do not edit by hand. "
                 "Regenerate from the repository root with:\n")
    lines.append("```\npython3 tools/measure_weight.py\n```\n")
    lines.append(
        "Each row runs the simulator's own witness builder for the transition "
        "(the test suites `tools/test_scripts.py`, `test_mid.py`, `test_min.py` "
        "and `test_ccv.py`), captures the witness stack and the transaction of "
        "the successful script run, and serialises the whole transaction as "
        "Bitcoin Core and btcd do: version, marker and flag, inputs, outputs, "
        "one witness stack per input with a CompactSize item count and a "
        "CompactSize length prefix per item, locktime. Weight is "
        "`3 * stripped size + total size`, and vB = ceil(weight / 4). The "
        "tree input's witness is the captured stack, then the script, then a "
        "129-byte control block (the eight-leaf reference set of spec 6.2). "
        "Other inputs carry a stub witness of the right size: 108 WU for a "
        "P2WPKH fee input (a 72-byte signature and a 33-byte key, as in the "
        "model) and 66 WU for a P2TR key-path spend.\n")
    lines.append(
        "The model column is the figure of spec 11, `spec/scripts/sizes.md` and "
        "`spec/fee-analysis.md`: script + witness data + 129 + 946 WU, which "
        "omits the witness length prefixes and assumes one skeleton (a tree "
        "input, a P2WPKH fee input, a tree output, one P2TR payout and a "
        "P2WPKH change output). Columns:\n")
    lines.append(
        "* **prefixes**: the tree input's CompactSize item count plus one "
        "length prefix per item, script and control block included (1 byte "
        "for an item under 253 bytes, 3 bytes up to 65,535). This is the "
        "exact amount the model leaves out of the tree input's witness.\n"
        "* **model + prefixes**: the model with the prefixes added, on the "
        "model's 946 WU skeleton.\n"
        "* **skeleton delta**: the measured weight minus the model with the "
        "prefixes added, that is, how far the transaction the test actually "
        "builds differs from the 946 WU skeleton (more payout outputs, no "
        "change output, no fee input). It is zero when the test's "
        "transaction has exactly the model's shape.\n"
        "* **shape**: inputs and outputs of the measured transaction.\n")
    lines.append(
        "The difference column is measured minus model. For a row whose shape is "
        "the model's (2 in / 3 out, one P2TR payout and a P2WPKH change) it is "
        "the prefixes alone; elsewhere it also carries the skeleton delta, and a "
        "row whose test transaction has no payout or no change measures below "
        "the model.\n")
    lines.append("| tier/profile | D | transition | script (B) | witness data (B) | items | "
                 "model (WU) | model (vB) | prefixes (WU) | model + prefixes (vB) | "
                 "skeleton delta (WU) | "
                 "measured (WU) | measured (vB) | difference (vB) | shape |")
    lines.append("|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|")
    for r in ROWS:
        lines.append("| %s | %d | %s | %d | %d | %d | %d | %d | %d | %d | %d | %d | %d | %+d | %s |" % (
            r["tier"], r["d"], r["name"], r["sl"], r["wl"], r["items"], r["model_wu"],
            r["model_vb"], r["pre"], r["model_pre_vb"], r["skel"], r["wu"], r["vb"], r["dvb"], r["note"]))
    lines.append("")
    lines.append("## Per-exit prefix overhead, EXIT_1 (owner), dense D = 16\n")
    lines.append("The witness length prefixes the model omits, for one `EXIT_1` "
                 "spend in each tier; the measured transaction has exactly the "
                 "model's skeleton, so this is the whole difference. The FULL "
                 "and CCV witnesses carry about 40 items, two per level; the MID "
                 "and MIN witnesses carry each level's sibling as several "
                 "elements (a hash, a minimal number and its `PADZ` pads), "
                 "over 160 items, so their overhead is about four times "
                 "larger.\n")
    lines.append("| tier | items | prefixes (WU) | prefixes (vB) | model (vB) | measured (vB) |")
    lines.append("|---|---|---|---|---|---|")
    for r in ROWS:
        if r["d"] == 16 and r["name"] == "EXIT_1 (owner)":
            lines.append("| %s | %d | %d | %.2f | %d | %d |" % (
                r["tier"].split("/")[0], r["items"], r["pre"], r["pre"] / 4.0,
                r["model_vb"], r["vb"]))
    lines.append("")
    lines.append("## Cohort transitions per leaf, dense D = 16\n")
    lines.append("The measured transaction divided by the leaves that leave "
                 "or change (`EVICT_SUBTREE_h`: leaves swept, every one paid "
                 "its own P2TR output; `REWRITE_h`: leaves changed, each "
                 "exiting leaf paid its own output). The model per-leaf "
                 "figure adds 172 WU for each payout beyond the first, as "
                 "`spec/fee-analysis.md` does.\n")
    lines.append("| transition | leaves | measured (vB) | measured per leaf (vB) | "
                 "model per leaf (vB) |")
    lines.append("|---|---|---|---|---|")
    for r in ROWS:
        if r["leaves"]:
            p2tr_out = int(r["note"].split("(")[1].split(" P2TR")[0])
            extra = max(p2tr_out - 2, 0)    # beyond the tree output and one payout
            model = vb(r["model_wu"] + 172 * extra)
            lines.append("| %s | %d | %d | %.1f | %.1f |" % (
                r["name"], r["leaves"], r["vb"], r["vb"] / float(r["leaves"]),
                model / float(r["leaves"])))
    lines.append("")
    with open(path, "w") as f:
        f.write("\n".join(lines))


def main():
    run_full()
    run_mid()
    run_min()
    run_ccv()
    fails = (test_scripts.FAILS + getattr(test_mid, "FAILS", 0) +
             getattr(test_min, "FAILS", 0) + getattr(test_ccv, "FAILS", 0))
    if fails:
        sys.exit("test failures while measuring: %d" % fails)
    write(OUT)
    for r in ROWS:
        if r["name"] == "EXIT_1 (owner)":
            print("%-6s D=%-3d %-16s model %5d vB  measured %5d vB  diff %+d vB  "
                  "prefixes %d WU" % (r["tier"], r["d"], r["name"], r["model_vb"],
                                      r["vb"], r["dvb"], r["pre"]))
    print("wrote", os.path.relpath(OUT))


if __name__ == "__main__":
    main()
