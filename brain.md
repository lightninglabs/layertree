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
| Spec | 0.10.0 on main: `tree_id` in every tier (6.2, 9.6), carve rule 7.5 rule 5, `DETACH_h` option inheritance 7.10 rule 3, plus everything from the PR stack and `CLAIM^x`/`CLAIM^hx` (7.5.3), `REWRITE_h` and `REWRITE_h^x` (7.9), `DETACH_h` (7.10), MID `EVICT_SUBTREE_h`, CCV `SPLIT` and sweep under `0xC0`, CCV `CLAIM`/`CLAIM^h`, 7.8 listing every draining transition, 10.5 sharding note, 9.6.2 pointing at the channel suite. Appendix C 0.3.0 with C.12. |
| Python simulator | 956 / 228 / 35 / 864 checks (FULL / MID / MIN / CCV), 149 channel-leaf checks (`test_chan.py`), 61 for the hypothetical opcode outside every tier. |
| Go | 79 golden scripts byte-exact (FULL incl. CLAIM^x/REWRITE/DETACH/EXIT_1^=/DETACH_2_HOST, MID incl. sweep, CCV both numerics incl. CLAIM, channel scripts); `txn/` builds, signs and verifies every FULL transition end to end (42 cases, each witness also run through the Python simulator, `tools/replay_txn_dump.py` re-derives the pins); TLV channel messages in `msg/`. |
| Lean | Builds clean, no sorry, 32 audited theorems (`claim_evictable` added): tree binding, conservation, payability, JOIN, UPDATE, CLAIM, the sweep, terminal exit, sparse positions, `REWRITE_h`, `DETACH_h` (including truncated-path reuse). Not covered: scripts or timing. |
| Paper | Two versions from one source (`make` builds `main.pdf`, 35 pages, body ends on 15 with References at the top of 16 and no slack, and `main-full.pdf`, 74 pages with References on 29); four tiers throughout; round-two review response landed; 0.10.0 CLAIM figures in (0d8c0bd, PDFs 0580c8b). Open: citations to verify, one overfull bibliography line, trimming the full version. |
| Design pages | `design/cost-comparison.md`, `design/tree-comparison.md`, `design/receive.md`, `design/batching.md`, `design/graft.md` (grafting and its trust model), all with generated figures from `tools/gen_cost_figures.py` (matplotlib, deterministic SVG). |
| Experiments | `tools/experiments/radix4.py`: radix-4 and radix-8 dense levels measured; radix 2 wins on the dense tree. |
| PR stack | Empty. #8 (72e9846), #10 (54d094f), #6 (f23f193) and #7 (3ef8128) all merged. |

## In flight right now

- Explainer website track (owner's request 2026-10-10), all under
  `site/`, static with no build step: an Opus builder writes the site
  (landing page with the takeaway and a step-through "life of a tree"
  animation; `site/components/` pages for state-machine, join, exit,
  payment, swap, evict, batching, tiers; one ES-module animation engine
  `site/js/tree-anim.js`; tokens in `site/css/tokens.css`; prose under
  the technical-writing skill; a dedicated state-machine page on
  commit-root-then-assert as a general pattern for UTXO scaling and
  richer on-chain state machines). Three Sonnet identity explorations
  under `site/identity/{editorial,schematic,approachable}/` each with a
  README, logo and wordmark SVGs, `tokens.css` with the shared variable
  names, a `sample.html`, and a palette validation. The owner picks an
  identity; then its `tokens.css` and logo replace the placeholders.
  Landed 2026-10-10: the site (d22de96, nine pages, one engine) and all
  three explorations. The owner chose B (schematic: drafting grid, IBM
  Plex, vermilion, datasheet cards) with the warmth of C (cream surfaces,
  softer shapes) folded in; landed 2026-10-10 (merge 186edae: warm
  schematic tokens, IBM Plex via Google Fonts with system fallbacks,
  logomark in `site/assets/`, orthogonal-bus tree drawing, FIG. n
  captions, palette validated in both modes). The payment and batching
  pages now describe `tree_id` (0d8c0bd). Not yet checked: animations
  mid-play, `prefers-reduced-motion`, `file://` opening; long table
  captions scroll with the table on narrow screens. Later: GitHub Pages
  deployment.
- Paper round two landed (merge of 800a245): every finding of the three
  reviews answered in `paper/review-response.md`; the liveness bound is
  now assumption [C] with parameters kappa (chain limit) and beta
  (competing spends confirmed ahead of an honest one), Delta(q) =
  Delta_L(ceil((beta+q)/kappa)+1); the functionality is a partial tree
  with adversarial REVEAL and a VOUCH interface; Theorem 5 excludes
  REWRITE_h and DETACH_h; Theorem 6 is Conjecture 1; new
  `appendix-assumptions.tex`; REWRITE per-leaf corrected to 359/195/158;
  joins and carves no longer charged a payout (JOIN_2 872, UPDATE 1,030,
  CLAIM 1,599, SPLIT 1,577); Lightning baseline derived (force close
  530, lifetime about 680). Short version 35 pages, body ends on page
  15 with References at the top of 16 and no slack; full 73 pages,
  References on 29. `% TODO(0.10.0 sizes)` comments mark where the rule
  worker's sizes go. Citations the writer could not pin down: TLUV and
  OP_EVICT posts (no URL), Poelstra's CAT and Schnorr Tricks (no URL),
  the arkd URL and bolts PR #995 came from memory; verify before
  submission. One overfull line in the bibliography.
- Handed off by the paper writer, to fold into the spec pass: 10.1
  "cannot delay" and a DETACH line; 10.5 and C.9.5 liveness as [C];
  11 witness prefixes, 129 WU per level, sweep rows, "near D = 5",
  REWRITE column; 9.6.1/9.6.2 drop "atomic"; 10.10 40-byte element
  claim; 4.1 EC-ops operand order and draft pin; fee-analysis leaf
  count. Tools: serialised-weight measurement, MIN extra_outs split per
  output, a numbers.tex generator, REWRITE figures in gen_cost_figures.
  Formal: path-maintenance lemma, exit key in ExitBlock, CCVTweak
  docstring. Design: relative lock on value-neutral transitions (P1c),
  outpoint-independent exit authorisation for towers (P8), Lightning
  figures in cost-comparison, REWRITE figures in batching.
- Spec 0.10.0 landed 2026-10-10 (merge 9045d24, follow-up 0d8c0bd,
  PDFs 0580c8b): `tree_id` in every tier (6.2 creation parameter, the
  RECOMMENDED derivation hashes the outpoint spent by input 0 of the
  creation transaction, since the tree's own outpoint is circular),
  carve rule 7.5 rule 5 (claim leaf keeps the source's `evictor_key`,
  `evict_after` no later; residual: a NUMS-evictor leaf can still carve
  NUMS dust, 10.8), `DETACH_h` 7.10 rule 3 (`m_h` compiled from the
  parent's option set; `TreeOptions` / `FullTreeOptions`). D4 golden
  root moved once to eff4a173...; `sighash_vector`, `tree_spk_vector`
  and `chan.*` moved with it. Counts now FULL 956, MID 228, MIN 35, CCV
  864, chan 149, MSU 61; Lean audit adds `claim_evictable`.
  `tools/replay_txn_dump.py` re-derives the Go sighash pins. CLAIM at
  D = 16 is 3,859 / 1,690 (1,656 vB; 1,614 in the paper's no-payout
  model), CLAIM^h 1,624, MIN SPLIT 6,501 bytes. No workers in flight.
- Paper review round done: `paper/reviews/{crypto,protocol,systems}.md`
  on main (727afa3). Verdicts: cryptographer weak reject (Lean holds
  up; the UC liveness bound Delta(N) does not follow from the model, the
  functionality's opaque slots are too coarse for the simulator, plus
  twelve fixable items); protocol engineer weak reject (same liveness
  problem; "only proposals already made" overstated; prior art TLUV,
  CoinPool OP_MERKLESUB, OP_EVICT missing; the s = e + 1 trick is
  Poelstra 2021; vB figures omit witness length prefixes); systems weak
  accept conditional (forty headline numbers re-derive; the fee model is
  stated three ways; baselines unsourced; short body spills onto page
  16; 29-row inconsistency table). An Opus writer is answering all
  three in `paper/review-response.md` round two and fixing the paper.
- Spec-level findings from the reviews, queued for a spec worker after
  the rule worker lands (same files): 10.5's liveness bound must be
  restated as an explicit policy assumption (competing spends per
  block), with the BIP-125 citation for kappa replaced and cluster
  mempool noted; 11's fee model must state that witness item prefixes
  are excluded (about 10 to 14 vB per exit) or fold them in, and "131 WU
  per level" is 129 by the data; 11's sweep rows (165/116 per leaf) and
  break-even "near D = 5" disagree with sizes.md's model (203/158);
  "input 0" is false for CCV; the BIP-443 commit should be pinned in 4.1;
  self-funded cohort joins are a signing round (9.2 wording); CLAIM^h is
  a hash-locked cheque, not an atomic swap, where 9.6.1 overclaims;
  MIN's raw extra_outs element can exceed the 80-byte 0xC0 witness-item
  policy limit (8.x note); the 220-block HTLC budget at G_exit = 72 fits
  about 1,775 leaves (C.4.4 should tie G_exit to N).
- The radix experiment crashed at HEAD after the channel-leaf simulator
  change (CCV per-input init with no context); fixed in 727afa3.
- `tree_id` in every tier (Fable worker, spec 0.10.0): the voucher
  message binds a per-lineage `tree_id` constant instead of `m` in FULL
  and MID as it already does in CCV; a detached child inherits it, so
  vouchers survive a detach. Owner's decision 2026-10-10, prompted by the
  cryptographer's finding 6 (`m` names a rule set, so two trees with the
  same parameters share it and vouchers replay). The frozen D4 golden
  root moves once, by design.
- Same worker, approved 2026-10-10: the carve constraint (a claim leaf's
  `evictor_key` MUST equal the source's and its `evict_after` MUST be no
  later, every tier, so `SPLIT` and a self-issued `CLAIM` cannot escape
  eviction or block a cohort sweep with a dust leaf; cryptographer's
  finding 9) and the `DETACH_h` creation rule (`m_h` MUST be compiled
  with the parent's options so detached channel leaves keep exact
  payouts; finding 7).
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

1. Spec follow-up pass for the review hand-offs (list under "Handed off
   by the paper writer" above): 10.1, 10.5/C.9.5 liveness as [C], 11
   witness prefixes and sweep rows, 9.6.1/9.6.2 "atomic", 10.10, 4.1,
   fee-analysis leaf count; then the tools, formal and design items.
2. Paper: verify the citations the writer could not pin down, fix the
   overfull bibliography line, trim the full version toward 30 body
   pages. Owner decisions outstanding: relative lock on value-neutral
   transitions (P1c), outpoint-independent exit authorisation (P8).
3. Cohort transitions beyond FULL (status.md open work 9): MID
   `REWRITE_STEP`, CCV `DETACH_h` second output, the one-byte "unchanged"
   marker for `REWRITE_h` (about 29 vB per unchanged position).
4. Site: GitHub Pages deployment; check animations mid-play, reduced
   motion and `file://`; narrow-screen table captions.
5. Sibling-pair `CLAIM` (about 1,130 vB, still an estimate); `SLASH`
   bond (issue #11) if the shared bond-leaf model is wanted.
6. Projects of their own, not started: P model (#1), regtest harness,
   verified tapscript interpreter.

## Decided 2026-10-09 (owner), recorded in status.md 11 to 16

- `REWRITE_h` subsumes `EXIT_SUBTREE_h` via the leaf-to-`E_0` payout rule.
- `DETACH_h` is operator-authorised. `chan_id` keeps `m`: a detach does
  not invalidate channel states, because `chan_id` is a constant in the
  channel scripts behind `exit_key`, not re-derived from the spent tree.
  Vouchers survive a detach too since 0.10.0 (`tree_id` is inherited).
- `SLASH` bond: issue #11, not built now.
- MIN stays an existence proof; the 116-byte leaf stays.

## Open questions

- Paper length for the full version: "not too far" past 18 pages. Target
  25 to 30 body pages.

## Pointers

- Conventions and gotchas: `CLAUDE.md` (identical to `AGENTS.md`).
- Spec: `spec/layertree.md`; channel leaves: `spec/channel-leaves.md`.
- Numbers: `spec/scripts/sizes.md`, `spec/fee-analysis.md`.
- Proofs: `formal/README.md`.
- Findings and decision log: `design/review.md`, `design/status.md`.
- Issues: #1 P model (open), #11 SLASH bond (open); #3 and #9 closed by #6, #7 and #10.
- Worker reports from the gap-closing round are summarised in the commit
  messages of the six merges on 2026-10-09.
