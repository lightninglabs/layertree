#!/usr/bin/env python3
"""Replay a LAYERTREE_TXN_DUMP file through the simulator.

`go test ./txn -run TestTransitionsEndToEnd` with LAYERTREE_TXN_DUMP=<file>
writes every Go-built transition as JSON: the transaction, the revealed
script with its tapleaf version and hash, the input's taproot internal key
and taptree root, and the signed witness stack. For each case this script
rebuilds the simulator's TxContext, recomputes the BIP-341 sighash and
executes the witness against the script with Interp in the mode the leaf
version selects ("c2" for 0xC2 leaves, "c0" for 0xC0). The internal key
and taptree root are what a validating node hands a CCV script for its -1
operands; the other tiers' scripts never read them. It prints the Go map
entries for txn/pins_test.go's pythonSighash and exits non-zero if any
witness fails or any digest disagrees with the one Go computed, so the
pins are always the simulator's own digests.

    python3 tools/replay_txn_dump.py dump.json
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from script_sim import Interp, ScriptError, TxContext  # noqa: E402


def main(path):
    cases = json.load(open(path))
    failures = 0
    per_tier = {}
    for c in cases:
        inputs = [(i["amount"], bytes.fromhex(i["scriptPubKey"])) for i in c["inputs"]]
        prevouts = [(bytes.fromhex(i["txid"]), i["vout"]) for i in c["inputs"]]
        seqs = [i["sequence"] for i in c["inputs"]]
        outputs = [(o["amount"], bytes.fromhex(o["scriptPubKey"])) for o in c["outputs"]]
        internal_key = bytes.fromhex(c["internal_key"]) if c.get("internal_key") else None
        taptree_root = bytes.fromhex(c["taptree_root"]) if c.get("taptree_root") else None
        ctx = TxContext(inputs, outputs, locktime=c["locktime"], sequences=seqs,
                        prevouts=prevouts, version=c["version"],
                        tapleaf_hash=bytes.fromhex(c["tapleaf_hash"]),
                        internal_key=internal_key, taptree_root=taptree_root)
        mode = "c0" if c["leaf_version"] == 0xc0 else "c2"
        digest = ctx.sighash().hex()
        status = "ok"
        if digest != c["sighash"]:
            status = f"sighash differs from Go's {c['sighash']}"
            failures += 1
        try:
            Interp(ctx, mode=mode).run(bytes.fromhex(c["script"]), [bytes.fromhex(x) for x in c["stack"]])
        except ScriptError as e:
            status = f"script failed: {e}"
            failures += 1
        tier = c.get("tier", c["name"].split("/")[0])
        per_tier[tier] = per_tier.get(tier, 0) + 1
        print(f'\t"{c["name"]}": "{digest}",  # {status}' if status != "ok"
              else f'\t"{c["name"]}": "{digest}",')
    tiers = ", ".join(f"{k} {v}" for k, v in sorted(per_tier.items()))
    print(f"{len(cases)} cases ({tiers}), {failures} failures", file=sys.stderr)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
