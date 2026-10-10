#!/usr/bin/env python3
"""Replay a LAYERTREE_TXN_DUMP file through the simulator.

`go test ./txn -run TestTransitionsEndToEnd` with LAYERTREE_TXN_DUMP=<file>
writes every Go-built transition as JSON: the transaction, the revealed
script, its tapleaf hash and the signed witness stack. For each case this
script rebuilds the simulator's TxContext, recomputes the BIP-341 sighash
and executes the witness against the script with Interp in 0xC2 mode. It
prints the Go map entries for txn/transitions_test.go's pythonSighash and
exits non-zero if any witness fails or any digest disagrees with the one
Go computed, so the pins are always the simulator's own digests.

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
    for c in cases:
        inputs = [(i["amount"], bytes.fromhex(i["scriptPubKey"])) for i in c["inputs"]]
        prevouts = [(bytes.fromhex(i["txid"]), i["vout"]) for i in c["inputs"]]
        seqs = [i["sequence"] for i in c["inputs"]]
        outputs = [(o["amount"], bytes.fromhex(o["scriptPubKey"])) for o in c["outputs"]]
        ctx = TxContext(inputs, outputs, locktime=c["locktime"], sequences=seqs,
                        prevouts=prevouts, version=c["version"],
                        tapleaf_hash=bytes.fromhex(c["tapleaf_hash"]))
        digest = ctx.sighash().hex()
        status = "ok"
        if digest != c["sighash"]:
            status = f"sighash differs from Go's {c['sighash']}"
            failures += 1
        try:
            Interp(ctx).run(bytes.fromhex(c["script"]), [bytes.fromhex(x) for x in c["stack"]])
        except ScriptError as e:
            status = f"script failed: {e}"
            failures += 1
        print(f'\t"{c["name"]}": "{digest}",  # {status}' if status != "ok"
              else f'\t"{c["name"]}": "{digest}",')
    print(f"{len(cases)} cases, {failures} failures", file=sys.stderr)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
