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
| [`CONCEPTS.md`](CONCEPTS.md) | High-level explainer: the problem, the core ideas, what the design does and does not promise, how payments work, and what is proved versus tested. Start here. |
| [`spec/channel-leaves.md`](spec/channel-leaves.md) | Appendix C: payment channels hosted in leaves (rebindable `OP_TX` + CSFS commitments, LN-Symmetry state machine, HTLC routing) |
| [`spec/fee-analysis.md`](spec/fee-analysis.md) | Exit and eviction costs at fee rates from 1 to 250 sat/vB |
| [`spec/test-vectors.json`](spec/test-vectors.json) | Generated test vectors |
| [`spec/scripts/`](spec/scripts/) | Annotated script listings and the measured size table |
| [`paper/`](paper/) | LaTeX paper (LNCS format): ideal functionality, abstract protocol, opcode tiers, UC security theorem with Lean-cited lemmas, channel composition, measurements; `paper/main.pdf` is the built copy, stamped with its git revision |
| [`formal/`](formal/README.md) | Lean 4 formalisation of the tree and covenant rules: conservation, proof soundness, payability, encodings (core library only, `lake build`) |
| [`design/review.md`](design/review.md) | Scrutiny of the original sketch and the resulting design decisions |
| [`design/cost-comparison.md`](design/cost-comparison.md) | Where LayerTree wins and where it does not: exit, entry and lifetime bytes against bare UTXOs, Lightning and transaction trees, with generated figures |
| [`design/profiles.md`](design/profiles.md) | Dense or sparse: what the two profiles share, where the sparse bytes go, and what a higher radix would change, with a measured radix-4 level |
| [`design/batching.md`](design/batching.md) | Batching: what a batch costs, the owner multiproof, the cohort rewrite and detaching a subtree into its own output |
| [`design/receive.md`](design/receive.md) | Receiving over Lightning into a tree: cumulative hash-locked vouchers against an Ark client's out-of-round payments and credits |
| [`design/unified-batching.md`](design/unified-batching.md) | The essay in which LayerTree was first described |
| [`design/layertree.md`](design/layertree.md) | Raw design sketch (verbatim) |
| [`notes.md`](notes.md) | Notes distilled from the working vault |
| [`brain.md`](brain.md) | Running brain dump: where every piece stands, what is in flight, what is next |
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
python3 tools/gen_structured.py    # regenerate spec/scripts/structured/ (macro-collapsed)
python3 tools/gen_golden.py        # regenerate spec/golden.json for the Go tests
```

No dependencies beyond the Python 3 standard library.

## Paper

`paper/main.tex` is a conference-style write-up in Springer LNCS format
(the Financial Cryptography template) using `cryptocode`, `tikz` and
`pgfplots`. It presents the system interface first: the ideal
functionality (section 3), the abstract protocol and its covenant
predicates (4), the three opcode tiers as realisations (5), a UC security
theorem whose lemmas cite the Lean theorems inline (6, proof in
Appendix A), and channel leaves as a composition result (7). Build with
`cd paper && make`, which stamps the PDF with the git revision it was
built from (`paper/version.tex`, shown under the author name and in the
running footer); it needs a TeX Live with `llncs` (bundled in the
directory), `cryptocode`, `pgfplots` and the `cm-super` fonts. Every
number in the paper is taken from `spec/scripts/sizes.md` and
`spec/fee-analysis.md`.

## Formal model

`formal/` is a Lean 4 development (no Mathlib) that proves the security
argument of spec section 10.2 for the abstract transition rules: every
accepted transition conserves the tree sum, only removes leaves that are
really there, and every leaf holder can always build an accepted exit.
`formal/README.md` lists the theorems, the hash assumptions and what is
deliberately left to the executable tests.

```
cd formal && lake build
```

## Consensus dependencies

- [BIP-0440](https://github.com/bitcoin/bips/blob/60f5b33b0a7be3cf09b933d97b78071d684db7d1/bip-0440.mediawiki) — varops budget
- [BIP-0441](https://github.com/bitcoin/bips/blob/60f5b33b0a7be3cf09b933d97b78071d684db7d1/bip-0441.mediawiki) — restoration of disabled script (tapleaf 0xC2)
- [OP_TX and "New Opcodes for Tapscript v2" drafts](https://github.com/rustyrussell/bips/pull/1) — introspection, `OP_CHECKSIGFROMSTACK`, `OP_ECSCALARMUL`, `OP_ECPOINTADD`
- [BIP-0348](https://github.com/bitcoin/bips/blob/master/bip-0348.md) — `OP_CHECKSIGFROMSTACK`
- [BIP-0449](https://github.com/bitcoin/bips/blob/master/bip-0449.md) — `OP_TWEAKADD` (used only by the minimal-inventory variant, spec section 4.4)
- [Elliptic Curve Operations for Bitcoin Script](https://github.com/Roasbeef/bips/blob/ec-ops-bip/bips-ec-ops.md) (draft, PR bitcoin/bips#1945) — `OP_EC_POINT_ADD`, `OP_EC_POINT_MUL`, `OP_EC_POINT_NEGATE`, `OP_EC_POINT_X_COORD`
