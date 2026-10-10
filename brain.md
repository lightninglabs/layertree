# brain.md

A running brain dump: what LayerTree is trying to do, where every piece
stands, what is in flight, what is next, and what is undecided. Update it
whenever the answer to "where are we" changes. `design/status.md` is the
formal hand-off with the decision log; this file is the informal one.

Last updated 2026-10-09, after the six-worker round landed (spec 0.9.0, Appendix C 0.3.0).

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
| Spec | 0.9.0 on main: everything from the PR stack plus `CLAIM^x`/`CLAIM^hx` (7.5.3), `REWRITE_h` and `REWRITE_h^x` (7.9), `DETACH_h` (7.10), MID `EVICT_SUBTREE_h`, CCV `SPLIT` and sweep under `0xC0`, CCV `CLAIM`/`CLAIM^h` over a per-tree `tree_id` (4.6, 9.6), 7.8 listing every draining transition, 10.5 sharding note, 9.6.2 pointing at the channel suite. Appendix C 0.3.0 with C.12. |
| Python simulator | 852 / 198 / 31 / 798 checks (FULL / MID / MIN / CCV), 149 channel-leaf checks (`test_chan.py`), 61 for the hypothetical opcode outside every tier. |
| Go | 77 golden scripts byte-exact (FULL incl. CLAIM^x/REWRITE/DETACH, MID incl. sweep, CCV both numerics incl. CLAIM, channel scripts); `txn/` builds, signs and verifies every FULL transition end to end (42 cases, each witness also run through the Python simulator); TLV channel messages in `msg/`. |
| Lean | Builds clean, no sorry, 31 audited theorems: tree binding, conservation, payability, JOIN, UPDATE, CLAIM, the sweep, terminal exit, sparse positions, `REWRITE_h`, `DETACH_h` (including truncated-path reuse). Not covered: scripts or timing. |
| Paper | Two versions from one source (`make` builds `main.pdf`, 44 pages with References on 16, and `main-full.pdf`, 50 pages with References on 31); four tiers throughout; full-only sections 12 to 16 from the design pages. Numbers predate the build round and need the reconciliation listed below, then the reviewer pass. |
| Design pages | `design/cost-comparison.md`, `design/tree-comparison.md`, `design/receive.md`, `design/batching.md`, `design/graft.md` (grafting and its trust model), all with generated figures from `tools/gen_cost_figures.py` (matplotlib, deterministic SVG). |
| Experiments | `tools/experiments/radix4.py`: radix-4 and radix-8 dense levels measured; radix 2 wins on the dense tree. |
| PR stack | Empty. #8 (72e9846), #10 (54d094f), #6 (f23f193) and #7 (3ef8128) all merged. |

## In flight right now

- Paper review round: three Opus reviewers (cryptographer on the UC
  argument, Bitcoin protocol engineer on scripts and assumptions,
  systems reviewer on measurements and writing) each write
  `paper/reviews/{crypto,protocol,systems}.md` in their own worktrees;
  the orchestrator merges the three files, then an Opus writer answers
  them in `paper/review-response.md` style, fixes the paper, rebuilds
  both PDFs. The paper is reconciled with spec 0.9.0 (cb81f99): short
  version 64 pages with References on 16, full version 70 pages with
  References on 33 (body about 32.8 pages, two over the target; the
  writer may move something to an appendix).
- All six build workers (A to G) landed on main; the matrix is green
  on the combined tree (852 / 198 / 31 / 798 / 149 / 61, golden and
  listings clean, Go ok, Lean rc 0).
- Reconciliation landed with the last merge: spec 11 CCV rows recomputed
  from sizes.md (908 vB dense, not 925); 9.6.2 points at the channel
  suite; 6.2 lists `tree_id`; second exit is 665 everywhere; the bitmap
  claim in tree-comparison.md now states the measured 330 against 326;
  receive.md and review.md say CCV carries `CLAIM` via `tree_id`;
  CONCEPTS carries the built shapes and the new counts; the batching
  figure's detach label is 762.

## Next, in order

1. Paper review round (in flight, above); after it, the response pass
   and a rebuild; then trim the full version back to about 30 body
   pages if the reviewers do not already force cuts.
2. Owner decision: adopt `tree_id` in every tier (status.md open work 8).
   Pro: vouchers survive a detach, one voucher message. Cost: every
   FULL/MID `CLAIM` script changes bytes and the frozen
   `taptree_full_d4.merkle_root` moves.
3. Cohort transitions beyond FULL (status.md open work 9): MID
   `REWRITE_STEP`, CCV `DETACH_h` second output, the one-byte "unchanged"
   marker for `REWRITE_h` (about 29 vB per unchanged position).
4. Go: the exact-payout `EXIT_1^=` script in `script/full.go`, and a
   committed replay script under `tools/` for the pinned sighashes
   (`LAYERTREE_TXN_DUMP`).
5. Sibling-pair `CLAIM` (about 1,130 vB, still an estimate); `SLASH`
   bond (issue #11) if the shared bond-leaf model is wanted.
6. Projects of their own, not started: P model (#1), regtest harness,
   verified tapscript interpreter.

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
- Worker reports from the gap-closing round are summarised in the commit
  messages of the six merges on 2026-10-09.
