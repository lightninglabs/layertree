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

Six workers, each in its own worktree, partitioned by file so they can be
integrated one at a time (each commits on its branch, never pushes; the
orchestrator merges into main, regenerates golden and listings, runs the
matrix, resolves the shared count lines in 4.5, 14, CLAUDE.md, status):

- A (Fable): FULL tier `CLAIM^x`, the issue-112 regression test,
  `REWRITE_h` with the leaf-to-`E_0` payout rule (spec 7.9), `DETACH_h`
  (spec 7.10, 10.5 throughput note); spec to 0.9.0. Owns
  `layertree_scripts.py`, `test_scripts.py`, `script/full.go`,
  `spec/layertree.md`.
- B (Opus): MID `EVICT_SUBTREE_h`; CCV `0xC0` `SPLIT` and sweep; CCV
  `CLAIM`/`CLAIM^h` via a per-tree `tree_id` constant in the voucher
  message (CCV-only, with a recommendation on unifying). Owns the MID and
  CCV generators and tests, `script/mid.go`, `script/ccv.go`, 4.6.
- C (Fable): Lean steps for the sweep, the terminal exit, sparse
  positions, `REWRITE_h` and a two-output `DETACH_h`. Owns `formal/`.
- D (Opus): Go end-to-end build, sign and verify for every transition in
  `txn/`. Owns `txn/`.
- E (Opus): Appendix C executable (`tools/layertree_chan.py`,
  `tools/test_chan.py`, `script/chan.go`), TLV channel messages in
  `msg/`, Appendix C test section. Owns `spec/channel-leaves.md`, `msg/`.
- G (Opus): paper four-tier wording, `\fullversion` toggle with
  `main.pdf` and `main-full.pdf`, design-page content lifted into the
  full version. Owns `paper/`, `tools/gen_cost_figures.py`. Reviewer
  profiles run after the builds land.

Landed so far: C (Lean, 1ce6521) and D (Go end-to-end, 42 cases plus 15
refusals; the sighash vectors were pinned from a scratch replay of the
simulator and `LAYERTREE_TXN_DUMP` writes the cases as JSON). Follow-ups
from D for the reconciliation commit: `script/full.go` lacks the
exact-payout `EXIT_1^=` variant, so Go cannot build it end to end; spec
7.8 says only `EXIT` can produce `E_D` but a sweep with `h = D` does too
(7.7 rule 4 allows it); a committed replay script under `tools/` would
make the pinned sighashes reproducible.

G (paper) landed at 8c76568: four tiers throughout, `\iffullversion`
keyed on the job name, `make` builds `main.pdf` (44 pages, References
on 16) and `main-full.pdf` (50 pages, References on 31, body about 30.6
pages, slightly over target), new full-only sections 12 to 16 from the
design pages, PDF twins of the figures under `paper/figures/`. Number
discrepancies G found, for the reconciliation commit: CCV `EXIT_1`
908 vB from sizes.md (2,683 WU) versus spec 11's row 925 vB (2,741 WU);
second exit 664 (cost-comparison.md) versus 665 (paper, fee-analysis);
batching figure's detach point labelled 765 versus 762 in the text;
tree-comparison.md's "bitmap saves 28 witness bytes" versus sizes.md's
330 against 326 (G left the claim out of the paper).

E (Appendix C) landed at 7b06456: `tools/test_chan.py` 149 checks on a
block-height chain model (open, uncontested close, contest, deadlines
of C.4.4 and the 9.6.2 swap played block by block), `script/chan.go`
byte-exact under the `chan` golden key, TLV channel messages in
`msg/chan.go`, Appendix C 0.3.0 with C.12 and four measured corrections
(SETTLE_n 79 bytes under 0xC2; HTLC sweeps 155 and 138 vB, not 146 and
130, because the HTLC output has two leaves; the C.4.4 bound has two
blocks of margin; MID channels carry at most seven HTLCs per state
because of the 520-byte element limit). For the reconciliation commit:
spec 9.6.2's closing paragraph still says the deadline reasoning has no
end-to-end test; point it at `tools/test_chan.py`. The paper's C.5.4
numbers (146/130) need the corrected sweep sizes too.

Integration order when they report: C (no overlap), D (no overlap), E,
A, B (A and B both touch 4.5, 14, golden.json), then a numbers
reconciliation commit, then G, then the reviewer pass on the paper.

Out of this round, by size, and said so to the owner: the P model
(issue #1), a regtest harness (needs the opcodes in a node), and a
verified tapscript interpreter.

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

## Decided 2026-10-09 (owner), recorded in status.md 11 to 16

- `REWRITE_h` subsumes `EXIT_SUBTREE_h` via the leaf-to-`E_0` payout rule.
- `DETACH_h` is operator-authorised. `chan_id` keeps `m`: a detach does
  not invalidate channel states, because `chan_id` is a constant in the
  channel scripts behind `exit_key`, not re-derived from the spent tree.
  Only vouchers need reissue after a detach.
- `SLASH` bond: issue #11, not built now.
- MIN stays an existence proof; the 116-byte leaf stays.

## Open questions

- Paper length for the full version: "not too far" past 18 pages. Target
  25 to 30 body pages.
- One voucher message for every tier (bound to a tree identifier instead
  of `m`) would let CCV carry `CLAIM` and make vouchers survive a detach;
  the CCV worker builds it CCV-only first and reports whether unifying
  is worth the golden churn.

## Pointers

- Conventions and gotchas: `CLAUDE.md` (identical to `AGENTS.md`).
- Spec: `spec/layertree.md`; channel leaves: `spec/channel-leaves.md`.
- Numbers: `spec/scripts/sizes.md`, `spec/fee-analysis.md`.
- Proofs: `formal/README.md`.
- Findings and decision log: `design/review.md`, `design/status.md`.
- Issues: #1 P model (open), #11 SLASH bond (open); #3 and #9 closed by #6, #7 and #10.
