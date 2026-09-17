# LayerTree

A Bitcoin scaling construction: one UTXO holds the pooled balances of many
participants, an off-chain Merkle-sum tree commits to ownership, and
covenants (Great Script Restoration + `OP_TX` + `OP_CHECKSIGFROMSTACK` +
EC opcodes) enforce every state transition. Any participant can exit, and
the operator can evict any expired participant, in **one transaction whose
size is independent of the number of participants**. Two tree profiles are
specified: a dense operator-allocated tree, and a key-addressed sparse
Merkle-sum tree with compressed proofs. LayerTree proposes no opcodes of its
own; it composes the existing candidates listed in spec section 4.3, and the
test suite fails if a script uses anything else.

## Contents

| Path | What |
|---|---|
| [`spec/layertree.md`](spec/layertree.md) | The specification (RFC 2119 language) |
| [`spec/test-vectors.json`](spec/test-vectors.json) | Generated test vectors |
| [`spec/scripts/`](spec/scripts/) | Annotated script listings and the measured size table |
| [`design/review.md`](design/review.md) | Scrutiny of the original sketch and the resulting design decisions |
| [`design/unified-batching.md`](design/unified-batching.md) | The essay in which LayerTree was first described |
| [`design/layertree.md`](design/layertree.md) | Raw design sketch (verbatim) |
| [`notes.md`](notes.md) | Notes distilled from the working vault |
| [`tools/`](tools/) | Reference implementation, script templates, simulator, tests |

## Go implementation

The module `github.com/roasbeef/layertree` (this repository) implements the
specification in Go on top of `btcsuite/btcd`, `lightningnetwork/lnd` and
`lightninglabs/taproot-assets`:

| Package | Contents |
|---|---|
| `tree` | leaves, merkle-sum tree, paths, proof compression, taproot binding of roots to the tree output |
| `script` | transition script generators for the FULL, MID and MIN opcode tiers, byte-checked against `spec/golden.json` |
| `txn` | transaction construction, witness assembly, BIP-341 sighash and Schnorr signing |
| `msg` | TLV-encoded off-chain messages: compressed proofs, vouchers, join offers |

```
go build ./... && go test ./...
```

The Python tools remain the executable reference because they include a
simulator for the candidate opcodes; the Go code is cross-checked against
vectors the Python emits (`spec/test-vectors.json`, `spec/golden.json`).

## Running the reference code

```
python3 tools/layertree_ref.py     # regenerate spec/test-vectors.json
python3 tools/test_scripts.py      # execute all scripts, both profiles
python3 tools/test_mid.py          # MID tier (0xC0 numerics), both profiles
python3 tools/test_min.py          # MIN tier EXIT_1 with sighash grinding
python3 tools/gen_listings.py      # regenerate spec/scripts/
python3 tools/gen_golden.py        # regenerate spec/golden.json for the Go tests
```

No dependencies beyond the Python 3 standard library.

## Consensus dependencies

- [BIP-0440](https://github.com/bitcoin/bips/blob/60f5b33b0a7be3cf09b933d97b78071d684db7d1/bip-0440.mediawiki) — varops budget
- [BIP-0441](https://github.com/bitcoin/bips/blob/60f5b33b0a7be3cf09b933d97b78071d684db7d1/bip-0441.mediawiki) — restoration of disabled script (tapleaf 0xC2)
- [OP_TX and "New Opcodes for Tapscript v2" drafts](https://github.com/rustyrussell/bips/pull/1) — introspection, `OP_CHECKSIGFROMSTACK`, `OP_ECSCALARMUL`, `OP_ECPOINTADD`
- [BIP-0348](https://github.com/bitcoin/bips/blob/master/bip-0348.md) — `OP_CHECKSIGFROMSTACK`
- [BIP-0449](https://github.com/bitcoin/bips/blob/master/bip-0449.md) — `OP_TWEAKADD` (used only by the minimal-inventory variant, spec section 4.4)
- [Elliptic Curve Operations for Bitcoin Script](https://github.com/Roasbeef/bips/blob/ec-ops-bip/bips-ec-ops.md) (draft, PR bitcoin/bips#1945) — `OP_EC_POINT_ADD`, `OP_EC_POINT_MUL`, `OP_EC_POINT_NEGATE`, `OP_EC_POINT_X_COORD`
