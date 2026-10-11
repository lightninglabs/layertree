# brain.md

A running brain dump: what LayerTree is trying to do, where every piece
stands, what is in flight, what is next, and what is undecided. Update it
whenever the answer to "where are we" changes. `design/status.md` is the
formal hand-off with the decision log; this file is the informal one.

Last updated 2026-10-10 (late), after open work 9 landed (spec 0.12.0, Appendix C 0.5.0) and the evening round's audits and fixes.

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
| Spec | 0.12.1 on main: `EXIT_K^t`, the tower-delegable exit (7.2 rule 7, FULL/MID/CCV, status.md decision 26); 0.12.0: MID `REWRITE_h`/`REWRITE_h^x` (0.11.1), CCV `DETACH_h` in both numerics, the one-byte unchanged marker for `REWRITE_h` (0.12.0, FULL and MID; 92 vB per unchanged position); 0.11.0: `NONNEG` after every `0xC0` sum, `DUST_MIN` creation parameter and 7.5 rule 6 on every carve, `REWRITE_h`'s amount-only exemption stops at `SEQ_FINAL` (7.9 rule 3), 7.9 rule 7 a MUST beside `UPDATE^x`/`CLAIM^x` (status.md decision 22); 0.10.x: `tree_id` in every tier (6.2, 9.6), carve rule 7.5 rule 5, `DETACH_h` option inheritance 7.10 rule 3, plus everything from the PR stack and `CLAIM^x`/`CLAIM^hx` (7.5.3), `REWRITE_h` and `REWRITE_h^x` (7.9), `DETACH_h` (7.10), MID `EVICT_SUBTREE_h`, CCV `SPLIT` and sweep under `0xC0`, CCV `CLAIM`/`CLAIM^h`, 7.8 listing every draining transition, 10.5 sharding note, 9.6.2 pointing at the channel suite. Appendix C 0.3.0 with C.12. |
| Python simulator | 1,154 / 466 / 55 / 1,344 checks (FULL / MID / MIN / CCV), 220 channel-leaf checks (`test_chan.py`), 61 for the hypothetical opcode outside every tier. |
| Go | 103 golden scripts byte-exact (FULL incl. CLAIM^x/REWRITE/DETACH/EXIT_1^=/DETACH_2_HOST, MID incl. sweep and REWRITE, CCV both numerics incl. DETACH and the 0xC0 ports incl. CLAIM, channel scripts); `txn/` builds, signs and verifies every FULL transition end to end (48 cases, each witness also run through the Python simulator, `tools/replay_txn_dump.py` re-derives the pins); TLV channel messages in `msg/`. |
| Lean | Builds clean, no sorry, 60 audited theorems (about 3,400 lines): binding, conservation, payability, every transition, path maintenance, PADZ encoding, trace-level invariants over reachable states (`Trace.lean`: ledger, dust floor, evictability, chain_state), voucher non-replay and detach survival (`Voucher.lean`), multi-exit rewrite conservation, the 0.11.0 rules. README lists where the model is weaker than the spec. Not covered: scripts or timing. |
| Paper | Two versions from one source, two audiences (status.md decision 23). `main.pdf` (18 pages, body ends on 15, References on 16) is the developer paper: how it works, every operation in a member's order, vouchers as a section, trust model, tiers, a short "what is proved", channels, evaluation, related work. `main-full.pdf` (74 pages, References on 29) keeps the functionality-first body and the proofs. Shared text in `paper/body-*.tex`, developer body in `paper/short-*.tex`. Open: the short version still carries the "Ideal Functionality" title (owner's call), the repository citation needs a public URL, trim the full version toward 30 body pages. |
| Design pages | `design/cost-comparison.md`, `design/tree-comparison.md`, `design/receive.md`, `design/batching.md`, `design/graft.md` (grafting and its trust model), `design/interactivity.md` (who must be online for each operation, synchronous steps, against Ark, factories, pools and channels), all with generated figures from `tools/gen_cost_figures.py` (matplotlib, deterministic SVG). |
| Experiments | `tools/experiments/radix4.py`: radix-4 and radix-8 dense levels measured; radix 2 wins on the dense tree. |
| PR stack | Empty. #8 (72e9846), #10 (54d094f), #6 (f23f193) and #7 (3ef8128) all merged. |

## In flight right now

- Review round (owner's order 2026-10-10 late: 1, then 4, then 2): (1) a
  Fable adversarial pass over main 8e6e511..318d941 (the whole day:
  spec 0.11.0 to 0.12.1, Appendix C 0.4.0 to 0.5.1, the Go fixes, the
  interactivity page, the developer paper), report only; the
  orchestrator verifies each finding, fixes confirmed highs with
  regression tests, records the rest. Then (4) a developer-profile
  review of the short paper (`paper/reviews/`), then (2) MID DETACH_h
  and CLAIM^x outside FULL.

  STATE 2026-10-11 (early). main at 71d977d, pushed; site republished
  (Litbucket version 6). Landed since the handoff: spec 0.13.0 / Appendix
  C 0.5.2 (vouchers and EXIT^t bind body(leaf) = leaf[8:116], F48 fixed,
  decision 28, D4 root aa2ba1ff..., Lean 61), the developer-review paper
  round (findings 1 to 15, Appendix C implementer's notes, round three in
  review-response.md), a report-only review of that round and its fixes,
  and the spec hand-offs (10.3/9.6 Ark comparison, 11.2 serialised
  premiums, C.4.4 cites lnd's 80). Counts 1,244 / 519 / 57 / 1,481 / 220
  / 61; 103 golden scripts; txn 54 cases. Short paper: body ends p15,
  References p16; full: References p30. Open for the owner: (a) the
  residual of F48, a top-up below DUST_MIN blocks (not voids) a
  whole-balance voucher; the fix is a DUST_MIN floor on 7.9 rule 3's
  amount-only increase; (b) the public repository URL for refs.bib (the
  repo moved to lightninglabs/layertree, still private). Next: item 2,
  MID DETACH_h and CLAIM^x / CLAIM^hx in MID and CCV (status.md open
  work 9).

- Round of 2026-10-10 (evening), owner's "execute 1-4, no GitHub pages,
  refine papers": (a) Opus paper worker in a worktree: new title for
  both versions, "LayerTree: A Shared Bitcoin UTXO with an O(1)
  Unilateral Exit" (owner: drop "Ideal Functionality", lean on the O(1)
  exit), overfull boxes, numbers against 0.11.0, read-through of both
  versions; sources only, orchestrator rebuilds PDFs. Repository URL
  still pending (owner). (b) Fable security-auditor in a worktree: Go
  audit of tree/, script/, txn/, msg/ to design/audit/go.md, no fixes.
  (c) Fable rule worker in a worktree: open work 9, MID REWRITE_h, CCV
  DETACH_h, then the one-byte unchanged marker if time; spec 0.11.1 or
  0.12.0; golden moves (not the D4 root). (d) Opus second opinion on the
  four decision points (B6 chan_id binds m or tree_id; P1c relative lock
  on value-neutral transitions; P8 prevout-independent exit
  authorisation; MIN extra_outs split per output); escalate to Fable
  where the orchestrator and Opus disagree or confidence is low, then
  report to the owner and execute. Merge order: (c) first (golden), then
  (a) (paper only; reconcile REWRITE sizes if the marker landed), (b) is
  a report. No GitHub Pages deployment (owner).
  (a) landed (merge 56c2a1b, PDFs in the next commit): title
  "LayerTree: A Shared Bitcoin UTXO with an O(1) Unilateral Exit" in
  both versions, zero overfull boxes, five figures corrected. Spec-side
  leftovers from its audit, to fix once (c) lands (it owns spec 11):
  spec 11's MID sweep prose says 4,097 / 7,865 / 23,873 / 13,149 B
  where sizes.md and 4.5 say 4,169 / 7,977 / 24,169 / 13,321; the sparse
  second exit is about 4,996 WU not 4,950; 4.5's MID premium "about 55%
  / 80%" measures 60% / 83% on EXIT_1; spec 11, fee-analysis.md and
  cost-comparison.md:394 describe the sweeps as "three of every sixteen
  positions empty" but test_scripts.py empties every fifth (51 of 256),
  so the D = 20 sweep is 205 leaves at 146 vB, not 206 at 147
  (gen_cost_figures OPERATOR_SWEEPS carries (206, 147)). Paper rows the
  owner may want: the lifetime table's sparse row mixes a six-leaf
  JOIN_0 (1,601) with the 2^16 exit estimate (1,781; the join at that
  size would be about 1,744).
  (c) landed (merge 611e49d): all three items, spec 0.12.0; counts FULL
  1,069 / MID 413 / MIN 55 / CCV 1,160; golden gained MID REWRITE and
  CCV DETACH and 0xC0 CCV keys, D4 root unmoved; per-leaf figures now
  364 / 200 / 162 (exits), 148 (update), 92 (unchanged), 138 (changed),
  151 (exiting); still FULL only: MID DETACH_h and CLAIM^x outside FULL.
  (b) landed (design/audit/go.md, F37 to F45) and its fixes (G1 to G8
  partial, channel caps and G7); F45 (DUST_MIN as a Go parameter) open.
  EXIT^t landed (merge b73120b, spec 0.12.1, Appendix C 0.5.1; 103
  golden scripts, 48 txn cases, counts 1,154 / 466 / 55 / 1,344 / 220 /
  61); F45 landed (DUST_MIN a Go parameter, merge e772637); paper and
  PDFs rebuilt at 49fc278; site republished (Litbucket version 3). The
  evening round is complete. Next: an adversarial review pass over the
  day's changes (spec 0.11.0 to 0.12.1, Appendix C 0.4.0 to 0.5.1, the Go
  fixes, the developer paper) before anything goes to reviewers; still
  FULL only: MID DETACH_h and CLAIM^x outside FULL (status.md open work).
  Decided (orchestrator + Opus second opinion, Fable check on Q3):
  B6: chan_id binds tree_id (Appendix C 0.5.0; Fable rule worker
  running, owns layertree_chan.py, test_chan.py, chan Go, chan golden,
  channel-leaves.md, review F35, status decision 24). P1c: declined; the
  first adversarial spend per block already invalidates the honest exit,
  chaining adds no delay, descendant pinning drives kappa to 1, so the
  lock removes nothing and costs throughput; [C] stays a stated fee
  auction (record as status decision 25). P8: build EXIT^t as an
  exact-payout creation variant in FULL, MID and CCV (not MIN, no CSFS):
  owner authorisation is a BIP-340 signature checked by CSFS over
  H_tag("LayerTree/exit", tree_id || leaf) in place of the transaction
  signature; evict branch unchanged; one authorisation per leaf in
  EXIT_K; survives DETACH_h (tree_id inherited); reference set of 6.2
  untouched so the D4 root does not move. Spec text: a published
  authorisation is a bearer exit right until the leaf changes (void by
  UPDATE or self-SPLIT); 9.2: MUST NOT re-join with a (owner_key, nonce,
  seq) held before, fresh nonce RECOMMENDED; a tower refreshes after an
  amount-only REWRITE changes a plain leaf; Appendix C: MUST NOT give
  the authorisation to the counterparty of a leased leaf, SHOULD only to
  the tower holding (update_n, settle_n); cooperative exit becomes one
  message; paper "needs nobody else's signature"; interactivity.md
  lifetime row. Lean: ExitBlock.authorised is abstract, doc comment
  only. Worker starts after (c) lands (shared generators); record as
  decision 26. Q4 MIN extra_outs: leave 8.11's note (decision 27).

- Paper restructure landed 2026-10-10 (merge of the writer's branch at
  a1a493f, PDFs in the commit after): see the Paper row above. The
  writer's corrections to the full version's receive section (settle
  first, finite lease, CLAIM^x 1,635 vB, 147 per leaf) came with it.

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
  model), CLAIM^h 1,624, MIN SPLIT 6,501 bytes.
- Round of 2026-10-10 (owner away for a few hours; "autonomously
  iterate, strengthen the Lean proof system, find other issues to make
  it airtight"), six workers in isolated worktrees, commit but never
  push, file-partitioned: (A, Fable) spec follow-up pass 0.10.1 in
  spec/*.md for the review hand-offs; (B, Fable) Lean strengthening in
  formal/ (trace-level invariants, voucher non-replay, DETACH/REWRITE,
  PADZ and sparse encoding, "not covered" list); (C1, Fable,
  security-auditor) protocol-level adversarial audit to
  design/audit/protocol.md; (C2, Fable) script-level witness-mutation
  audit to design/audit/script.md, may fix confirmed generator bugs
  with golden/listings/Go; (D, Opus) paper: counts 956/228/35/864, 79
  golden, `\LeanTheoremCount` macro, citations verified by web search,
  overfull bib line, trim the full version toward 30 body pages; (E,
  Opus) tools/measure_weight.py and spec/scripts/weights.md (exact
  serialised vB with prefixes), REWRITE/sweep/exit per-leaf figure in
  gen_cost_figures and batching.md, Lightning baseline in
  cost-comparison.md. Merge order when they report: C2 first (golden
  may move), then A, B, E, D; the orchestrator fixes shared count
  lines, the Lean theorem count in the paper macro, status.md and
  CLAUDE.md, builds the PDFs, pushes after each merge. After the round:
  triage the audits, spawn fix workers for confirmed findings, then open
  work 9 (cohort transitions beyond FULL).
  E landed first (merge of 0649248, PDF twins 007392b). Its findings,
  forwarded to A and D: prefix overhead per EXIT_1 is 10.5 / 10.0 vB in
  FULL / CCV but 42.5 / 44.75 in MID / MIN; spec 11 REWRITE table and
  depth-8 EXIT_1 (765) disagree with the model (359/195/158, 144, 762);
  spec 11 sweep rows mix bases; paper UPDATE 1,030 vs 1,073, graft 614
  vs 657, sparse lifetime row. Still to fix by the orchestrator after
  C2 lands: sizes.md's `EXIT_1 (terminal)` rows report 0 witness bytes
  (test_scripts.py records 0; real witness 901 B dense, 244 B sparse).
  D landed (merge a65dbab, PDFs c34145f): counts and a
  `\LeanTheoremCount` macro (32, update when B lands), every refs.bib
  URL verified (OP_EVICT is ZmnSCPxj's; CoinPool is Naumenko and Riard;
  bolts #995 is the simple taproot channels extension BOLT), SuperScalar
  URL overfull fixed, full version 73 pages with References on 29 (the
  31-page listings appendix is the bulk), short body still ends p15.
  Unresolved: the repository citation points at the private
  lightninglabs/layertree, needs a public URL before submission. A
  landed (merge of 9e106d7 plus 3d53c5f): spec 0.10.1 / Appendix C
  0.3.1, decision 21 in status.md; kappa now says Bitcoin Core 31.0
  replaced the 25 chain limits with a 64 cluster limit. Owner items
  from A: keep the SHOULD shard/detach guidance in 10.5 (kept); split
  MIN extra_outs per output (open, 8.11).
  C1 landed (design/audit/protocol.md, merge of ce1b85f): eight
  confirmed findings A1 to A8. Triage: A1 (REWRITE_h rule 3's
  amount-only exemption lets the operator raise a SEQ_FINAL channel
  leaf above capacity, making the pre-signed update non-standard under
  ephemeral anchors; fix: exemption excludes seq = SEQ_FINAL) and A2
  (0 or sub-dust claim leaves block sweeps and grafts for good; fix:
  DUST_MIN creation parameter, 7.5 rule 6, same floor on UPDATE if
  owner-only) are real and cheap: a Fable rule worker is landing both
  as spec 0.11.0 (no formal/ edits; the Lean worker was messaged the
  hypotheses). A3 to A8 are text (REWRITE_h^x MUST beside UPDATE^x and
  CLAIM^x; voucher holders check the source lease; a full-cohort detach
  strands partial vouchers; NUMS-evictor credit leaves are squat tokens;
  in-place renewal blocks the sweep; member-funded grafts need an anchor
  for CPFP): an Opus text worker is applying them to 9, 10, C.4/C.6.6/
  C.9, receive.md, graft.md and recording F22 to F29 in review.md.
  Merge order: rule worker, then text worker (both touch spec, different
  sections), then B, then C2 if it changed generators (or C2 first if
  it lands before the rule worker).
  Landed since: text worker (merge a0c6b62, F22 to F29 in review.md)
  and the Lean worker (merge before 8246e07; paper macro
  `\LeanTheoremCount` is 60). Lean worker's spec notes (self-voucher
  replay is a no-op, 5.2 uniqueness is the non-replay hypothesis) were
  sent to the rule worker for 7.5 and 5.2; 10.3's "seq only advances"
  is a bookkeeping rule, not a covenant property: fix in 10.3 after the
  rule worker lands. Paper rebuild pending the rule worker (sizes).
  C2 landed (merge 4531729, design/audit/script.md, tools/test_probe.py
  kept): one real bug, MID/MIN/CCV-0xC0 accepted negative CScriptNum
  sums (sign-magnitude `00 00 00 81` passes PADZ as 2^31+2^24; JOIN
  new_sum, JOIN_0 amount and SPLIT claim amount could be short or rich
  by 2^24); fixed with NONNEG (OP_DUP OP_DUP OP_ABS OP_EQUALVERIFY, +4 B
  per level, MID EXIT_1 D=16 3,367 B, 1,355 vB, +33% over FULL), plus a
  simulator negative-CLTV fix and MID sparse 25 <= D <= 31. Counts now
  FULL 1,017, MID 250, MIN 47, CCV 886. Spec header is 0.11.0 (shared
  with the rule worker's changes). Stale after merge, fix once
  weights.md is regenerated: fee-analysis.md:38, spec 11 measured rows
  (MID 1,381/1,338), CONCEPTS.md MID 1,338. The rule worker was told to
  merge main first and recompute golden/counts once.
  Matrix green on the merged tree (1,017/250/47/886/149/61, Go, Lean
  60); weights.md regenerated (MID EXIT_1 1,355 model / 1,398 measured,
  MIN 1,473 / 1,518); spec 11, fee-analysis, CONCEPTS and the paper
  carry the new MID/MIN sizes; PDFs rebuilt at ab41a93 (532a9a6).
  Still in flight: the A1/A2 rule worker (spec 0.11.0 DUST_MIN and the
  REWRITE SEQ_FINAL exclusion; also carries 7.5.3/7.9 rule 7/5.2
  wording and receive.md's floor). Started: a channel-leaf audit
  (Appendix C, swaps, receive, DETACH/REWRITE with channels) writing
  design/audit/channels.md only. Landed (merge of f72fffa): B1
  settlement outputs below 330 sat make two dust outputs with the
  ephemeral anchor, non-standard (rule: C.3.4 dust floor, trimmed value
  to the anchor, reference + Go validation + test); B2 receive.md's flow
  inverts 9.6.2 rule 1 (text: operator settles the inbound HTLC first,
  then a plain CLAIM^x voucher); B3 unissued credit-leaf capital is the
  recipient's on every unilateral path (text); B4 stale-state
  publication one per block eats C.4.4's margin (rule: budget term);
  B5 = A1 (in flight); B6 chan_id binds m, audit recommends tree_id
  (owner decision, decision 13 said keep m; no attack found); B7 text
  (C.6.2, C.7). An Opus text worker is doing B2, B3, B7, C.5.6 and
  F30 to F36. After the A1/A2 rule worker lands: a Fable channel rule
  worker for B1, B4, the C.6/C.9 test-coverage list, Appendix C 0.4.0.
  Text worker landed (merge of 82cad6a, F30 to F36; swap page rule 5
  and CLAIM^x figures fixed in 7913268). The channel rule worker
  (Fable) is running now, in parallel with the A1/A2 rule worker; it
  owns C.3/C.4/C.9, layertree_chan.py, test_chan.py, chan Go and
  review.md F30/F33/F34 status lines. Owner decision pending: B6 chan_id
  binds m (decision 13) versus tree_id (audit recommendation).

## HANDOFF 2026-10-10 (rate limit killed both rule workers; owner moving agents)

Main was at 4b2dd70 plus the handoff commit. Two worker branches held
unmerged work. Both were killed by the session spend limit, not by errors.

1. LANDED 2026-10-10 (merge d14d61d and the reconciliation commit after
   it): full matrix green on the merged tree (1,054 / 268 / 55 / 972 /
   149 / 61, Go, gofmt, Lean exit 0, golden/listings/structured/
   fee-analysis regenerate clean); every owed item below was already on
   the branch; REWRITE per-leaf figures moved to 362 / 198 / 161 (exits)
   and 147 (update), 120 per unchanged position, CLAIM 1,660 / CLAIM^h
   1,670 / CLAIM^x 1,678 vB at D = 16, and were fixed in batching.md,
   cost-comparison.md, graft.md, receive.md, CONCEPTS, the site, the
   paper (both versions, counts, Table batch, the full-batching figure)
   and gen_cost_figures; review.md F22/F23/F24/F34 fixed; status.md
   decision 22. Original item: Branch `worktree-agent-a12aa50d8c1e7f647`, worktree
   `.claude/worktrees/agent-a12aa50d8c1e7f647`, tree clean, three
   commits on top of main: `4de18b3` (A1: REWRITE_h keeps the owner
   signature on SEQ_FINAL leaves, every tier, Go, golden, tests),
   `5ed0e92` (A2: DUST_MIN creation parameter floors every carve,
   spec 0.11.0, tools, Go), `c3ed282` (weights.md regenerated). It had
   merged main twice (last at a31b246) and was in its final full-matrix
   run when it died; the report never arrived. To land: merge the
   branch, run the whole matrix (regen golden/listings/structured one
   at a time, all six suites, Go, gofmt, `cd formal && lake build`
   exit 0), check CLAUDE.md = AGENTS.md and the 4.5/14 count lines, then
   push. Still owed from its brief and never confirmed done: 7.9 rule 7
   SHOULD -> MUST beside UPDATE^x/CLAIM^x; 7.5.3 cross-reference to
   "REWRITE_h^x or no REWRITE_h" and its NUMS example -> finite lease;
   7.5's self-voucher replay sentence (claim leaf equal to source
   replays as a no-op, theorem `self_voucher_fixed`); 5.2 (owner_key,
   nonce) uniqueness cross-referenced from 7.5's replay paragraph;
   receive.md redemption floor (DUST_MIN); C.2.4 "merely burns" sentence;
   DUST_MIN floor on UPDATE if owner-only. Grep the branch for each
   before redoing it. Then update review.md F22/F23 to fixed, status.md
   decision 22 (0.11.0: NONNEG, DUST_MIN, REWRITE SEQ_FINAL exclusion),
   rebuild the paper (sizes change again for CLAIM/SPLIT), push.
2. LANDED 2026-10-10 (merge 58ee31d plus the completion commit after
   it): Appendix C 0.4.0 text for B1 (C.3.4 `DUST_CHAN`, anchor carries the
   trimmed value, C.5.5) and B4 (`beta_chan` in the C.4.4 bound, C.5.5
   reserve, C.9.6 replacement), `cltv_budget_spec(beta_chan)`, new
   test_chan cases (stale updates k = 2 / 3 / bound+3, C.6.3/C.6.4
   lease and NUMS evictor, C.5.2/C.6.7 epoch and renewal, chan_id on
   owner_key and csv_delay): 210 checks; C.12, counts, status.md row,
   review.md F30/F33 fixed. Go side was already on the branch. Original
   item: Branch `worktree-agent-aaa2f4093b7c67fba`, worktree
   `.claude/worktrees/agent-aaa2f4093b7c67fba`: one WIP commit on top of
   main with B1 (settlement dust floor in `settle_outputs` and Go
   `StateProposal.Validate`, msg/chan.go, tests) and B4 tests; its last
   words were "Go side is green. Now the spec text for B1 (C.3.4) and
   B4 (C.4.4, C.9.6)", so the Appendix C text, the 0.4.0 bump, the C.6/
   C.9 coverage tests, the CheckDeadline evict_after fix, the swap
   fixture fix, the test_chan count in CLAUDE.md/AGENTS.md and review.md
   F30/F33/F34 statuses are NOT done. Resume by reading its diff
   (`git diff main...worktree-agent-aaa2f4093b7c67fba`), finishing the
   brief in brain.md's channel-audit bullet above and design/audit/
   channels.md, running `python3 tools/test_chan.py` and Go, then merge
   after branch 1 (both touch test_chan.py and golden chan section).
3. Owner decisions pending: B6 chan_id binds m (decision 13) or tree_id;
   10.5 SHOULD shard/detach kept; MIN extra_outs split per output
   (8.11); the protocol review's P1c and P8 proposals; the repository
   citation in refs.bib needs a public URL before submission.
4. After both land: full matrix, paper rebuild (both PDFs, short body
   must still end on page 15), site tiers/payment pages re-check, memory
   file `layertree-autonomous-round` update, then open work 9 (cohort
   transitions beyond FULL) and a Go/txn builder audit as the next
   round.
5. Mail watcher: re-arm `substrate watch --session-id <id> --project
   /Users/roasbeef/gocode/src/github.com/roasbeef/layertree --timeout
   25m` in the background on every wake.
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

1. Paper: merge the developer-facing short version when the writer
   reports, rebuild both PDFs, check the short body ends by page 15.
   Then: the repository citation in refs.bib needs a public URL; trim
   the full version toward 30 body pages. Owner decisions outstanding:
   relative lock on value-neutral transitions (P1c),
   outpoint-independent exit authorisation (P8, now building as EXIT^t), B6 (done: `chan_id` binds `tree_id`)
   or `tree_id`, MIN `extra_outs` split per output (8.11).
2. Next audit round: a Go/`txn` builder audit; re-run the protocol and
   script audits against 0.11.0 (A1 to A8 and the script findings are
   all fixed or recorded; `design/audit/` holds the three reports).
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
- `DETACH_h` is operator-authorised. `chan_id` kept `m` until 2026-10-10,
  when it was rebound to `tree_id` (Appendix C 0.5.0, status.md decision
  24); the original reasoning: a detach does
  not invalidate channel states, because `chan_id` is a constant in the
  channel scripts behind `exit_key`, not re-derived from the spent tree.
  Vouchers survive a detach too since 0.10.0 (`tree_id` is inherited).
- `SLASH` bond: issue #11, not built now.
- MIN stays an existence proof; the 116-byte leaf stays.

## Open questions

- Paper length for the full version: "not too far" past 18 pages. Target
  25 to 30 body pages.

## Pointers

- Site, published: https://layertree.lightning.wiki/ (Litbucket, team
  `labs`, slug `layertree`; bundle = root redirect + `site/` + `spec/` +
  `design/` + `formal/README.md`, built and pushed by the orchestrator's
  scratch script `publish-site.sh`, run from the owner's terminal because
  the harness classifier blocks the upload from the agent shell).
  Republish after every site change that lands on main; each publish
  appends a version and moves the team link.

- Conventions and gotchas: `CLAUDE.md` (identical to `AGENTS.md`).
- Spec: `spec/layertree.md`; channel leaves: `spec/channel-leaves.md`.
- Numbers: `spec/scripts/sizes.md`, `spec/fee-analysis.md`.
- Proofs: `formal/README.md`.
- Findings and decision log: `design/review.md`, `design/status.md`.
- Issues: #1 P model (open), #11 SLASH bond (open); #3 and #9 closed by #6, #7 and #10.
- Worker reports from the gap-closing round are summarised in the commit
  messages of the six merges on 2026-10-09.
