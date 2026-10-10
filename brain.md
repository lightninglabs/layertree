# brain.md

A running brain dump: what LayerTree is trying to do, where every piece
stands, what is in flight, what is next, and what is undecided. Update it
whenever the answer to "where are we" changes. `design/status.md` is the
formal hand-off with the decision log; this file is the informal one.

Last updated 2026-10-09, main at 74d6526 (all four PRs merged, spec 0.8.5, PDF rebuilt).

## What we are trying to do

Show that one shared UTXO plus an off-chain Merkle-sum tree plus
tapscript covenants gives a shared-UTXO system whose unilateral exit is
one transaction with no timelock, no presigning and no expiry, that is
cheaper to leave than Ark round trees and channel factories, that admits
and evicts whole cohorts for one price, and that hosts Lightning
channels and vouchers so that value moves off-chain and the chain sees
only membership changes and exits. Prove the tree rules in Lean, prove
the scripts by execution against a simulator, mirror them byte-exactly
in Go, and write it up for Financial Cryptography.

The one-line defence against "why not a bare UTXO": entry is near free in
bulk, activity is free off-chain, and the insurance (unilateral exit) is
one transaction; the price is that exercising the insurance alone costs
about ten times a bare spend. `design/cost-comparison.md` is the argument
with numbers.

## Where things stand

| Area | State |
|---|---|
| Spec | 0.8.5 on main: #8, #10, #6 and #7 merged (swap rules in 9.6.2; SPLIT in all four tiers; 11.1 script-set cost; the CCV tier in 4.6; the hypothetical opcode quarantined), then the editorial pass (dense is the default profile in 1, 5.4 and 11; 10.1 trust table lists grafting; 9.2 off-chain buyer checks; 4.5 says the MIN dashes mean not built). |
| Python simulator | 425 / 125 / 31 / 309 checks on main (FULL / MID / MIN / CCV); 61 for the hypothetical opcode, outside every tier. |
| Go | 56 golden scripts byte-exact (FULL, MID, MIN, CCV); EXIT_1 built and signed end to end; other transitions have witness assemblers only. |
| Lean | Builds clean, no sorry; covers tree binding, conservation, payability, JOIN, UPDATE, CLAIM. Not covered: EVICT_SUBTREE, terminal exit, sparse positions, anything about scripts or timing. |
| Paper | 15 body pages (References on page 16), 44 pages with appendices, PDF stamped 52ec594 and current. Still says "three opcode tiers" in the intro and section titles although the tier table carries CCV; the two-version build and the reviewer-profile pass are queued (see below). |
| Design pages | `design/cost-comparison.md`, `design/tree-comparison.md`, `design/receive.md`, `design/batching.md`, `design/graft.md` (grafting and its trust model), all with generated figures from `tools/gen_cost_figures.py` (matplotlib, deterministic SVG). |
| Experiments | `tools/experiments/radix4.py`: radix-4 and radix-8 dense levels measured; radix 2 wins on the dense tree. |
| PR stack | Empty. #8 (72e9846), #10 (54d094f), #6 (f23f193) and #7 (3ef8128) all merged. |

## In flight right now

- Zoom-out discussion with the owner on the batching open questions and
  on what is not implemented, before any new build starts.
- TeX works on this machine (see `layertree-tex-build` in memory):
  `PATH=$HOME/bin:/Library/TeX/texbin:$PATH make` in paper/.

## Next, in order

1. Done: all PRs merged, counts and version reconciled (0.8.5), matrix
   green, PDF rebuilt at 52ec594.
2. Paper, two versions from one source, then a review pass by Opus
   agents acting as reviewer profiles (FC programme-committee style:
   a cryptographer on the UC argument, a Bitcoin protocol engineer on
   the scripts and assumptions, a systems reviewer on the measurements
   and comparisons), each producing findings the writer agent then
   addresses, as `paper/review.md` and `paper/review-response.md` did
   for the first draft. Fix the "three opcode tiers" wording while at
   it. A `\fullversion` toggle like the
   existing `\anontrue`: the short build keeps the FC body under the
   limit and sends the rest to appendices; the full build lifts the limit
   to roughly 25 to 30 body pages and pulls the functionality proof, the
   Lean treatment, channel leaves, the cost comparison, the profile
   analysis, the receive case and the batching shapes into the body.
   Makefile targets `main.pdf` and `main-full.pdf`, both stamped. Build
   order stays: sources first, then make, then commit PDFs with
   version.tex.
3. Done: the editorial pass landed as 52ec594 (spec 0.8.5).
3b. Done: MID join negatives landed (125 MID checks).
4. Build `REWRITE_h`, the cohort rewrite with per-leaf signatures
   (owner's call: build it). FULL tier first, MID stated as unsupported
   for the sweep's reason. Generator from the `EVICT_SUBTREE_h` post-order
   fold, tests, golden (a tree-creation variant, excluded from the D4
   root), Go mirror, spec 7.9 and 8.x, 4.5 row, Lean `Rewrite` step and
   theorem, status. Then `EXIT_SUBTREE_h` and `DETACH_h` the same way;
   `DETACH_h` needs a two-output Lean step.
5. Sibling-pair `CLAIM`: source and claim slot under one path, about
   1,130 vbytes instead of 1,652 for the credit-leaf case; and a voucher
   bound to a compiled tree identifier instead of `m`, so the CCV tier can
   carry `CLAIM` (`design/receive.md`).
6. `CLAIM^x`: a `CLAIM` variant requiring the source leaf's exit-key
   signature at redemption, seven bytes like `UPDATE^x`. It is what makes
   a dedicated credit leaf trust-free (`design/receive.md`).
7. Regression test named after taproot-assets-private#112 (sibling-sum
   binding), even though the node format already excludes it; deferred
   only because changing the check count ripples through the PR stack.
8. The older open list from `design/status.md`: P model (issue #1), Go
   builders for every transition, channel-leaf TLV messages, regtest
   harness, verified interpreter.

## Decisions taken today (not yet in status.md)

- Radix 2 stays for the dense tree; measured, not estimated.
- The sparse profile is demoted, not deleted (owner's call, 2026-10-09):
  dense is the default and the recommendation; sparse stays specified,
  generated and tested as the key-addressed option and the measured
  comparison, and leaves the headline rows of the tier matrix and the
  paper. The spec, CONCEPTS, README and paper wording changes are queued
  for after the PR merges because they touch the 4.5 matrix (patch bump
  to 0.8.3).
- Cost pages compare against bare UTXOs, Lightning and Ark on lifetime
  bytes per member with stated assumptions; the paper will inherit those
  tables.
- Receiving over Lightning is modelled as a cumulative hash-locked
  voucher against a dedicated credit leaf, one-way, no contest window;
  two-way traffic stays on channel leaves.
- Workers add commits only; no rebases on the stack until it is merged.

## Open questions

- Should `chan_id` exclude `m` so that a `DETACH_h` does not invalidate
  channel-leaf states? Argued yes in `design/batching.md`; not decided.
- A `SLASH` transition that pays an operator bond leaf to anyone
  presenting two conflicting vouchers (over-issuance proof) for the
  shared bond-leaf model; voiding has no compact proof and is handled by
  `CLAIM^x` instead (`design/receive.md`).
- Who authorises `DETACH_h`: operator only, or a cohort parameter at
  graft time?
- Is the MIN tier worth extending beyond EXIT_1 (SPLIT is the first
  candidate), or is MIN an existence proof and nothing more?
- The leaf hash could be restructured so an exit publishes 72 bytes
  instead of 116 (exit key, amount, hash of the rest); about 11 vbytes
  per leaf in every shape. Format change; needs its own page.
- Paper length for the full version: "not too far" past 18 pages. Target
  25 to 30 body pages.

## Pointers

- Conventions and gotchas: `CLAUDE.md` (identical to `AGENTS.md`).
- Spec: `spec/layertree.md`; channel leaves: `spec/channel-leaves.md`.
- Numbers: `spec/scripts/sizes.md`, `spec/fee-analysis.md`.
- Proofs: `formal/README.md`.
- Findings and decision log: `design/review.md`, `design/status.md`.
- Issues: #1 P model, #3 native primitives (#6, #7), #9 SPLIT (#10).
