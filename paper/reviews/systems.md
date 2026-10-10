# Review: systems and evaluation profile

Paper: "LayerTree: A Shared Bitcoin UTXO as an Ideal Functionality, and Its
Realisation with Covenants", `paper/main.pdf` (short) and
`paper/main-full.pdf` (full), both stamped 6d2c114 (2026-10-09).

Reviewer profile: measurement sections, evaluation methodology,
reproducibility, consistency of numbers, fairness of baselines, writing.

## Summary verdict

The evaluation is better grounded than most covenant papers: I re-derived
about forty figures from `spec/scripts/sizes.md` and the 946 WU skeleton
of `tools/fee_analysis.py`, and the headline numbers (762 / 891 / 1,020 /
1,149 vB, MID 1,338, MIN 1,456, CCV 908, marginal second exit 665, sweeps
203 and 158 vB per leaf, JOIN_h, UPDATE 1,073, CLAIM 1,642, DETACH 780)
reproduce exactly. I also re-ran the suites: 852 FULL, 198 MID, 31 MIN, 798
CCV, 149 channel and 61 hypothetical-opcode checks pass and match the
paper, as do the 77 golden scripts and the 42 Go end-to-end cases. The
problems lie in what surrounds those numbers. The short body never says what
a "vB" figure contains; the transaction model lives only in Appendix E. Measured
witness sizes leave out serialisation overhead. Several derived figures
are slightly wrong because the model is applied unevenly (REWRITE double
counts a payout, sparse figures mix N = 6 and N = 2^16, one sweep point is
at the wrong depth). The baselines are uneven: the Lightning numbers
contradict each other, and Ark is a radix-2 model at a 65,536-member round. The two versions
describe the transaction-tree model as biased in opposite directions. The
paper gives the reader no way to regenerate any number, and one table in the
full version cannot be regenerated at HEAD. The body also runs onto page 16.
None of this threatens the design. I would score the evaluation as a weak
accept conditional on the major items below, most of which are a day's
work.

## Findings

### 1. The short version's body runs onto page 16 (major)

- **Location:** `main.pdf` pages 15 and 16. Section 10 (Discussion) and Section 11
  (Conclusion) fill the top two thirds of page 16, and References start
  below them.
- **Claim:** `paper/review-response.md` says "Body 15 pages (References at
  the top of page 16)".
- **Problem:** This meets the project's own rule that References begin on
  page 16 or earlier. It does not meet a literal reading of FC's rule, 15
  LNCS pages excluding references and appendices. The body is about 15.6
  pages, a chair could desk-reject on that, and the response file now
  misstates the layout.
- **Resolution:** Cut about 25 lines from the body. Figure 3 has a large
  empty legend block and an empty band under its right panel (page 15).
  The CCV paragraph of Section 5 repeats Table 2's last two rows verbatim.
  The Section 8 "Batching, joins and cohorts" paragraph could become a
  four-row table. Afterwards, update `review-response.md`.

### 2. The transaction model behind every vB figure appears only in an appendix, and is stated inconsistently (major)

- **Location:** Short body Section 8 (main.tex 925 to 1015); Appendix E
  Table 3 caption ("adds a fee input, change and overhead (≈ 950 WU)");
  Appendix E.4 ("946 WU for one payout plus 172 WU per additional payout;
  vB = ⌈WU/4⌉"); full Section 12, first paragraph.
- **Problem:** The abstract, the contributions and Section 8 quote 1,020 vB
  without saying that it includes a P2WPKH fee input, a P2WPKH change
  output, a P2TR payout and an eight-leaf control block. A reader of the
  15-page body cannot tell whether 1,020 is a witness, a script or a
  transaction. The model is stated three times in three forms: ≈950 WU,
  946 WU, and in the full version "fee input, change, tree output, one P2TR
  payout", which omits the tree input. One rule is not applied
  consistently. The Appendix E.4 fee table lists the sweep rows at 203 and
  158 vB but prices them at 202.9 and 157.98 vB (2,029 rather than 2,030 at
  10 sat/vB, and 7,899 and 39,495 rather than 7,900 and 39,500). The same
  skeleton also charges a 43 vB payout output to transitions that have
  none (JOIN_h, JOINK, CLAIM, SPLIT, REWRITE in its update scenario), which
  overstates them by 43 vB. That is conservative, but the paper should say
  so.
- **Resolution:** Put one sentence in the Section 8 body that defines the
  skeleton (inputs, outputs, script types) and the rounding. Refer to it
  from Table 3 and E.4. Price every fee-table row as the tabulated vB times
  the rate. State that joins and claims carry a phantom payout output, or
  drop it.

### 3. Measured witness sizes leave out serialisation overhead (major)

- **Location:** `tools/gen_listings.py` lines 80 to 157. The witness size is
  `sum(len(x) for x in wit)` and the total is script + witness + 129. The
  paper's Section 4.1 says each level costs "41 bytes of witness".
  `spec/layertree.md` Section 11 says each level costs "131 WU (88 script +
  41 path + 2 length prefixes)".
- **Problem:** A segwit witness also serialises an item count and a
  compact-size length before every element, and a 2,101-byte script needs a
  3-byte prefix. The dense path supplies a direction element per level, and
  its data byte (0 or 1 bytes) also counts. The measured totals grow by
  exactly 129 WU per level (`sizes.md`: 3,132 - 2,616 = 516 over four
  levels), so the spec's "131 WU including prefixes" is not what was
  measured. For a dense D = 16 EXIT_1 I estimate the missing bytes at 40 to
  55 WU, about 10 to 14 vB (1 to 1.4%). The error is systematic and small,
  but it affects every headline number. The repository also has a better
  instrument than the simulator: the Go builder already "builds, signs and
  verifies every FULL transition".
- **Resolution:** Measure the serialised witness, or better, report
  `vsize` for the transactions the Go builder in `txn/` produces for EXIT_1
  at D = 8 to 20, and check them against the model. Fix the spec's "2
  length prefixes" sentence to match whichever number is reported.

### 4. The transaction-tree and Ark baseline is presented in opposite directions in the two versions, at an unrealistic round size (major)

- **Location:** Short Section 8, "Comparison with transaction trees"
  (main.tex 935 to 948). Full Section 12, "Exit" paragraph (full-cost.tex
  55 to 60), Table 3 "Lifetime" (full-cost.tex 85 to 101) and Figure 5.
- **Claims:**
  - Short version: "Two corrections work against LayerTree: a radix-4 tree
    ... roughly 1,870 vB ... and the interior of a transaction tree is
    shared."
  - Full version: "the model flatters it by ignoring the leaf's timelock
    and the separate fee of each of its 16 transactions", and the Ark row
    "still beats an Ark round tree there by a factor of 2.5".
- **Problem:** The short version argues that the model favours LayerTree,
  while the full version (which drops the short version's paragraph)
  argues that it favours the tree. The full version's lifetime table and
  Figure 5 then use only the radix-2, unamortised 2,511 vB figure. Neither
  version brings in round size. An Ark unroll is D_Ark transactions, where
  D_Ark is log2 of the round's VTXO count, not LayerTree's D = 16. A round
  of 128 VTXOs gives 7 × 150 + 111 = 1,161 vB, which is level with
  LayerTree's 1,020. Two inputs are unsourced. The "about 220 vB" per
  radix-4 level and the 1,870 vB that follows from it appear nowhere in the
  repository (I grepped `spec/`, `design/` and `tools/`). The "150 vB per
  transaction" figure cites only "spec 11". Finally, `spec/layertree.md`
  Section 11 still says the break-even is "near D = 5" and "about 2.4×",
  while the paper says near D = 3, which is the correct value.
- **Resolution:** Use one sensitivity table in both versions, covering
  radix 2 and 4, isolated and amortised exits, and the round size N_Ark,
  with every cell sourced. Derive the 150 and 220 vB per-transaction
  figures from a stated transaction shape (inputs, outputs, script-path
  witness), or measure them on a deployed Ark implementation, which
  chooses its own radix. In the full version, replace "beats Ark by a
  factor of 2.5" with the range over N_Ark. Fix spec Section 11 to match.

### 5. The Lightning baseline is unsourced and internally impossible, and is priced unlike the channel leaf (major)

- **Location:** Full Table 3 caption (full-cost.tex 85): "a Lightning force
  close is a 130 vB commitment and a 110 vB sweep". Full Section 12: "about
  154 vB for a channel opened in its own transaction".
  `design/cost-comparison.md` uses a 154 vB cooperative close. Appendix D
  (appendix-channels.tex): "roughly 280 vB for a Lightning channel's
  funding transaction plus force close".
- **Problem:** A commitment transaction spends the same 2-of-2 funding
  output as a cooperative close and has at least as many outputs, so it
  cannot be smaller than the 154 vB cooperative close in the same model.
  BOLT 3 gives a commitment weight of 724 WU without anchors (181 vB) and
  1,124 WU with anchors (281 vB). A simple-taproot commitment with two
  balance outputs and two anchors is about 240 vB. The channel-leaf force
  close (1,681 vB, Appendix D) includes two 152 vB anchor-spending children,
  but the Lightning baseline includes none, even though anchor channels
  need one to confirm at the current feerate. The "about 13 times" ratio in
  `design/cost-comparison.md` comes from 1,681 / 130. None of these figures
  cites a source (`tools/gen_cost_figures.py` says of LN_OPEN_VB: "not a
  figure from the spec").
- **Resolution:** Cite BOLT 3 or the simple-taproot-channels draft and
  derive commitment, sweep and CPFP-child sizes for one named channel type.
  Price both constructions with or without fee-bumping children, not one
  of each. Recompute the 283 / 197 lifetime entries and the 1,681 vs 280
  comparison.

### 6. Full version: the native-opcode "floor" row is measured at a different population (major)

- **Location:** Full Figure 5 and Section 12, "Exit" (full-cost.tex 54 to
  57): "at 388 vB, approximates the floor for any design that verifies a
  proof in script: the proof itself, about 10 vB per level, is still
  published".
- **Problem:** The row's witness is 56.25 vB (225 B). A dense D = 16 path is
  16 × 41 = 656 B (164 vB) on its own. According to
  `design/native-opcodes.md` (lines 105 to 123), the 225 B is a
  bitmap-compressed proof measured with a few occupied siblings, so its
  size follows log2 N for the test tree, not D = 16 at 2^16 members. Every
  other row in Figure 5 is a full dense path or is labelled as N = 6. At
  2^16 members the row would be roughly 388 + 41 × (16 - k0) / 4 vB, about
  520 to 540 vB. That changes the "floor" conclusion and the 3.7× ratio
  quoted in the design note.
- **Resolution:** Label the row with its profile and population, or
  re-measure it at N = 2^16. Reword "floor" to name the N it assumes.

### 7. The entry and "moving value" comparisons in the full version are not like for like (major)

- **Location:** full-cost.tex 77 to 81 and Table 3 (lifetime).
- **Claims:**
  - "Value moves off-chain instead: ... or by SPLIT: for 1,000 members
    moving value 1,000 times each, about 1 kvB for one graft against 111
    MvB as bare UTXOs (estimate)."
  - LayerTree dense entry: 3 vB per member, against 43 vB for every other
    row.
- **Problem:** SPLIT is an on-chain tree transition (Table 1; about 1,620
  vB at D = 16 from `sizes.md` 5,531 WU). Attributing the 1 kvB figure to
  it is wrong. The comparison also sets an off-chain scheme against
  on-chain bare UTXOs, when the obvious baseline is Lightning or Ark, which
  `design/cost-comparison.md` itself puts at about 300 kvB and 90 kvB.
  Separately, the 3 vB entry is the operator-funded graft, in which members
  buy their balance off-chain and the money's on-chain arrival is not
  counted. The other rows pay for their own output. The member-funded
  figure (about 61 vB, full Table 5) is the comparable one.
- **Resolution:** Remove SPLIT from that sentence. Compare against Lightning
  and Ark, and keep bare UTXOs as a floor. In the lifetime table, either
  use the member-funded entry or add a row for it, and say which
  assumption each row makes.

### 8. REWRITE_h per-leaf figures double count one payout (minor)

- **Location:** full-batching.tex 47 to 50, full-cost.tex 66, full Figure 6,
  and short Section 8 ("Owners leaving by REWRITE_h pay 370, 198 and 159 vB
  each"). The source is `spec/layertree.md` Section 11's REWRITE table.
- **Problem:** Applying the paper's own model (946 WU including one payout,
  plus 172 WU per further payout) to spec Section 11's exit-scenario
  sizes:
  - REWRITE_2: 2,731 + 1,423 + 129 + 946 + 3 × 172 = 5,745 WU, so 1,437
    vB, 359 per leaf.
  - REWRITE_4: 12,492 WU, so 195 per leaf.
  - REWRITE_6: 40,414 WU, so 158 per leaf.

  The published 370 / 198 / 159 are reproduced exactly by charging 172 WU
  for every one of the K payouts on top of the skeleton's built-in payout.
  As a result, "the last within one vbyte of the operator's sweep" should
  read "equal to".
- **Resolution:** Recompute with 172 × (K - 1). Update spec Section 11,
  `design/batching.md`, `tools/gen_cost_figures.py` and both versions of
  the paper.

### 9. Sparse-profile figures mix populations, and the witness formula has the wrong intercept (minor)

- **Location:**
  - Short Section 4.1 (main.tex 416 to 417): "at 1.8 to 2.7 times the dense
    per-exit cost (Table 3)".
  - Table 3 caption: "Sparse witness is 326 + 41 log2 N bytes".
  - Full Section 13: "1.6 to 2.7 times", and "about 860 bytes of witness
    and 1,800 vB at 2^16".
  - Full Table 3 (lifetime), Figure 5 and Table 5 use the N = 6 figures.
- **Problem:** `sizes.md` measures 326 B at N = 6, that is, with about 2.6
  non-empty siblings already included. "326 + 41 log2 N" therefore predicts
  432 B at N = 6, which contradicts the measurement it came from, and it
  overstates the witness at 2^16 by about 100 B. The full version's 860 B
  uses a different intercept, and 860 B gives 1,771 vB, not 1,800. The
  short version's "1.8 to 2.7" combines the N = 2^16 low end (1,800 /
  1,020 = 1.76) with the N = 6 high end (2,725 / 1,020 = 2.67). At N =
  2^16 the D = 64 ratio is 2,890 / 1,020 = 2.83. The response to the
  earlier review says "The N = 6 figure survives only in the fee appendix,
  labelled", which is no longer true of the full version.
- **Resolution:** Measure the sparse exit at N = 2^16 directly; the
  simulator can build the tree. Otherwise state the formula as
  (326 - 41 k0) + 41 log2 N with the k0 of the measured leaf. Use one
  population everywhere, or label every N = 6 figure.

### 10. The control-block assumption does not match the shapes the paper prices (minor)

- **Location:** Table 3 caption ("a 129-byte control block for the
  eight-leaf reference script set"). `spec/fee-analysis.md` caveats say
  "5-6 leaves, 129 WU". `review-response.md` K says "five-leaf taptree".
- **Problem:** The reference set (spec 11.1) is EXIT_1, EXIT_2, JOIN_0,
  JOIN_2, JOINK_2, UPDATE, CLAIM and EVICT_SUBTREE_2. The paper's figures
  also use EVICT_SUBTREE_4 and EVICT_SUBTREE_6, REWRITE_2/4/6, DETACH_8,
  CLAIM^h, SPLIT, UPDATE^x and JOIN_8/10, which a deployment needs in the
  same taptree. That makes at least 16 leaves (+8 vB on every spend) or 32
  (+16 vB). The paper quotes 1,020 vB for a tree that cannot run the
  sweeps quoted next to it. The three documents also give three different
  leaf counts.
- **Resolution:** Price everything with the taptree a deployment carrying
  those shapes would need, or state the 8 vB-per-doubling sensitivity in
  the body next to 1,020. Reconcile the leaf count in
  `spec/fee-analysis.md` and the response file.

### 11. Figure 6 and full Section 12 present a D = 20 measurement as D = 16 (minor)

- **Location:** full-batching.tex 98 ("(206,147)"). Figure 6 caption: "Batch
  shapes at D = 16 ... all measured". full-cost.tex 63 to 64: "203, 158 and
  147 vB per leaf for 13, 51 and 206 leaves".
- **Problem:** The 206-leaf point is `sizes.md`'s EVICT_SUBTREE_8 at D = 20
  (84,772 WU). The effect on the number is tiny, but the caption is wrong.
  `design/batching.md` gives "about 147 for 200". Also, the DETACH_8 point
  plots a per-exit cost against "leaves handled in one transaction", which
  is not what x = 256 means for it.
- **Resolution:** Measure EVICT_SUBTREE_8 at D = 16 or label the point
  D = 20. Move the detach point to an inset, or annotate it rather than
  plotting it on the shared x-axis.

### 12. The batching cost decomposition does not add up (minor)

- **Location:** full-batching.tex 7 to 13 and 119 to 124.
- **Claim:** "fixed part ... about 470 vB ... about 32 vB per shared level
  ... about 100 to 120 vB per leaf touched". Also, "a leaf that leaves costs
  its bytes, its signature and its output, about 100 vB, in every shape".
- **Problem:** 470 + 16 × 32 + 100 = 1,082 vB, against the measured 1,020
  for EXIT_1. The same section's measured marginal cost of an exiting
  position in REWRITE_6 is 147 vB (spec Section 11), and the sweep is 158
  per leaf. "About 100 in every shape" is not what was measured.
- **Resolution:** Derive the three parts from the EXIT_1 and EXIT_2
  measurements so that they sum to 1,020. Quote the measured 147 vB as the
  per-leaf floor.

### 13. Marginal and average batch costs are used interchangeably (minor)

- **Location:** Contribution 6 (main.tex 243), "665 vB per batched exit";
  Figure 3 right, "batch of 2: 842".
- **Problem:** 665 is the marginal cost of the second exit, computed as
  ⌈(2,485 + 172) / 4⌉. The per-exit cost of a two-exit batch is 842. Also,
  1,020 + 665 = 1,685, which is not 2 × 842 = 1,684, because the marginal
  figure is rounded separately.
- **Resolution:** Write "665 vB for each further exit in a batch". Compute
  the marginal figure as vB(EXIT_2) - vB(EXIT_1) = 664, or say how it is
  rounded.

### 14. "Tier matters more than depth" is contradicted by the numbers beside it (minor)

- **Location:** main.tex 929 to 930.
- **Problem:** The preceding sentence says depth 8 to 20 raises the cost by
  51%. MID and MIN add 31% and 43%. Over the plotted range, depth matters
  more.
- **Resolution:** Say what is meant, for example "one tier step costs as
  much as 10 to 14 levels of depth".

### 15. The figures are hard to read at LNCS size (minor)

- **Location:** `main.pdf` page 15 (Figure 3); `main-full.pdf` page 25
  (Figure 5) and page 29 (Figure 6).
- **Problems:**
  - Figure 3, right panel: the "1,020" bar label runs into the frame, the
    rotated tick labels collide ("single", "batch of 2"), and the ymax of
    1,150 crowds the tallest bar.
  - Figure 3, left panel: MID, MIN and CCV are single points whose pin
    labels sit far from their markers (the MID label lies on the
    transaction-tree line near D = 12). The triangle, diamond and pentagon
    markers cannot be told apart in print at 1.8 pt. The four-row legend
    uses more space than the plot. The model line carries the same markers
    as measured data.
  - Figure 5: segments in four close greys on 5 pt bars. The control-block
    and skeleton segments are a few pixels wide, the "388" label overlaps
    its bar, and the reference-line labels are \tiny.
  - Figure 6: there are no labels for 1,020, 842, 203, 158 or 147, while
    198, 159 and 145 are labelled. The cluster at x = 64 overlaps, and the
    REWRITE line crosses the "bare P2TR spend 111" annotation.
- **Resolution:**
  - Figure 3: raise the right panel's ymax to 1,200 and use horizontal
    category labels or a table.
  - Figure 3, left: label MID, MIN and CCV directly beside the markers and
    drop them from the legend. Draw the model line without markers.
  - Figure 5: use hatching or a colour-blind-safe palette that survives
    greyscale, and widen the bars to 8 pt.
  - Figure 6: label every point or none, and move the annotation.

### 16. Reproducibility: the paper names no commands, the figures are hand-copied, and one table no longer regenerates (major)

- **Location:** The whole paper. The only pointer is the repository
  citation (`refs.bib` layertreerepo). There is no mention of
  `tools/test_scripts.py`, `gen_listings.py`, `fee_analysis.py` or the Go
  tests.
- **Problems:**
  - All pgfplots coordinates and table cells are literal numbers. The
    figure generator `tools/gen_cost_figures.py` states that "nothing here
    is computed from the simulator at run time, so a changed measurement
    must be edited here by hand". It needs matplotlib, is outside CI, and
    does not feed the paper. Findings 8, 9, 11 and 12 come from this
    hand-copying.
  - `python3 tools/experiments/radix4.py`, the source of full Table 4 and
    its "55 checks", fails at HEAD with `AttributeError: 'NoneType' object
    has no attribute 'ccv_input_init'` (`tools/script_sim.py` line 437). The
    CCV change to the simulator broke it, so the radix table cannot be
    regenerated.
  - The REWRITE exit and update sizes come from `test_scripts.py --rewrite`,
    which is not among the commands in the repository's `CLAUDE.md` and
    `AGENTS.md`.
  - Those files list check counts of 425 / 120 / 31 / 309, while the suites
    print 852 / 198 / 31 / 798, as the paper says. They also omit
    `test_chan.py` (149) and `test_msu.py` (61).
  - `spec/layertree.md` Section 11, which the full version cites as the
    source ("spec 11"), contradicts the paper in several places: sweeps at
    "≈ 165 per leaf" and "≈ 116 per leaf" in its main table, and 580 and
    445 WU in its sweep table, against the paper's 203 and 158; "breaks
    even near D = 5"; "about twice" for sparse; "about twelve times" for
    D = 256.
- **Resolution:**
  - Add a short "Artefact" paragraph naming the commands, the revision and
    the expected check counts.
  - Have one script turn `sizes.md` into a `numbers.tex` of macros (and
    pgfplots tables) that both versions of the paper `\input`, so that no
    number is typed by hand.
  - Fix `radix4.py` and run it in CI.
  - Update the command list and check counts in `CLAUDE.md` and `AGENTS.md`.
  - Bring spec Section 11 into line with `spec/fee-analysis.md` and the
    paper.

### 17. Related work misses the closest lines of prior work (major)

- **Location:** Section 9 (main.tex 1027 to 1062); Table 4.
- **Problem:** "The tree is data, not transactions, and exit is one proof
  against a committed root" is the central move. FC reviewers will know it
  from:
  - Bitcoin payment-pool proposals that already target one-transaction
    unilateral withdrawal from a shared output: OP_TAPLEAF_UPDATE_VERIFY
    (Towns, 2021), OP_MERKLESUB as discussed for CoinPool, and OP_EVICT.
  - Plasma and rollup forced-exit mechanisms on Ethereum, which commit
    balances as a Merkle root and exit by proof.
  - Proofs of liabilities, whose Merkle-sum trees had exactly the
    sum-inflation flaw that the full version's "one node format"
    paragraph fixes. See, for example, Ji and Chalkias, Generalized Proof
    of Liabilities (CCS 2021), and Chalkias, Chatzigiannis and Ji, "Broken
    Proofs of Solvency" (FC 2022 workshops).

  Table 4's CoinPool column ("O(log N) txs", "CTV or APO") needs a citation,
  because the CoinPool discussion is precisely about single-transaction
  withdrawal opcodes. Deployed Ark implementations exist and should be the
  Ark baseline (finding 4).
- **Resolution:** Add a paragraph on these three lines of work. Say what
  LayerTree adds: no new opcode, a UC statement, eviction and grafting.
  Source every Table 4 cell.

### 18. The novelty claim for the generator-key signature trick is likely wrong (major)

- **Location:** main.tex 1061 to 1062: "We know of no prior use of a
  generator-key signature with s = e + 1 to make a script's sighash
  reconstruction binding."
- **Problem:** This appears to be the construction in Poelstra's "CAT and
  Schnorr Tricks" posts (2021). There, the public key and nonce are both G,
  so s = 1 + e, and the spender grinds the transaction so that the
  challenge has a fixed last byte. CAT-based vault prototypes have since
  used it. The ECDSA analogue (OP_PUSH_TX, with private key 1 and k = 1)
  has been used on BCH and BSV since about 2019. Claiming it as novel will
  cost credibility with exactly the reviewers who know the area.
- **Resolution:** Cite the prior constructions and restate the
  contribution narrowly, for example the field-by-field enforcement table
  and its use as the sole introspection in a tier with a UC argument.

### 19. Liveness and channel-hub claims do not carry their parameters (minor)

- **Location:**
  - Abstract (main.tex 152 to 153): "so a hub of N channels occupies one
    output".
  - Section 3 (main.tex 351 to 360): "(25 under today's policy [bip125])"
    and "10,000 channel leaves need about 400 blocks".
  - Section 7 (main.tex 863 to 868): G_exit = 72.
  - Appendix A, "Liveness": "the ancestor limit, 25 transactions".
- **Problems:**
  - The 25-transaction limit is Bitcoin Core mempool policy, not BIP-125
    (RBF).
  - Section 3 calls it a descendant limit and Appendix A an ancestor limit.
  - "About 400 blocks" assumes Δ_L = 1, which is never stated.
  - G_exit = 72 is not tied to an N. Under the paper's own Δ(N) with
    Δ_L = 1 it corresponds to about 1,775 leaves, so the roughly
    220-block budget holds only for hubs of that size.
  - The abstract's hub claim omits that dependence.
- **Resolution:**
  - Cite the policy and the Bitcoin Core version it applies to, and say
    what cluster mempool changes, given that it may have shipped by
    submission time.
  - Use one term for the limit.
  - State Δ_L and the N behind G_exit = 72.
  - Qualify the abstract with "sized by exit throughput".

### 20. Acronyms and symbols are used before they are defined (minor)

- **Location (short body):**
  - WU is never expanded.
  - HTLC (Section 7) is not expanded.
  - CSFS (Table 2) is never expanded.
  - CTV first appears in Section 9 without expansion; the introduction
    writes OP_CHECKTEMPLATEVERIFY.
  - G_sweep (main.tex 864) is defined only in Appendix D.
  - csv_delay and cltv_expiry_delta are used without a one-line meaning.
  - Table 2's "Vouchers/channels/shape" row uses "shape free/fixed",
    which is never explained.
  - "The three options above" (main.tex 554) is ambiguous.
  - "0xC0 tiers use one to three of the BIP-342 sigop budget" is missing
    its noun.
  - "(design notes)" (main.tex 1084) is not a citation.
- **Location (appendices and full version):** GSR, APO and CTV in Table 4;
  TLV in Appendix D; "spec 5.4", "spec 11" and "spec 13.4" in the full
  version, with no bibliography entry or path.
- **Resolution:** Expand each term on first use. Cite the repository with a
  file path where the paper points into the spec or the design notes.

### 21. The short Section 8 packs fourteen numbers into prose in two units (minor)

- **Location:** main.tex 997 to 1008.
- **Problem:**
  - "2,713 WU of witness" and "about 5,000 WU per leaf" sit next to vB
    figures for the same kind of operation. The full version's Table 5
    gives the sparse join as 1,432 to 1,644 vB per member at the
    transaction level, while the short version gives 5,000 WU of witness.
    The basis changes between versions.
  - The "58 vB" member funding input is a P2TR input, but the skeleton's
    fee input is P2WPKH at 68 vB (`tools/fee_analysis.py`: 41 vB + 108 WU).
- **Resolution:** Put the paragraph in a small table in vB per member at
  the transaction level, and use one input type throughout the model (or
  say why two are used).

### 22. Most of the short submission is appendix, and part of it is dangling (minor)

- **Location:** `main.pdf` pages 18 to 64: 47 pages of appendix behind a
  15-page body, including 31 pages of macro-collapsed listings (Appendix F).
  Appendix F.5 calls itself "The intermediate data point of §5", but the
  short Section 5 never presents that data point (the D/minimal row,
  3,393 WU).
- **Problem:** FC reviewers are not obliged to read appendices. The one
  appendix an evaluation reviewer needs (E, the model and the raw sizes)
  is buried among listings that belong in the artefact.
- **Resolution:** Drop Appendix F from the submission and cite the
  artefact. Move E's model sentence into the body (finding 2). Either
  mention the minimal-inventory point in Section 5 or drop F.5's sentence.

### 23. The evaluation leaves out costs a systems reader expects (minor)

- **Location:** Section 8; the earlier internal review's items K.4 and K.6
  are still open.
- **Problem:** There is no validation-time measurement of a 16 kB sweep or
  a 2.5M-varops exit; the Go implementation makes this cheap. There is no
  empirical feerate distribution, although the fee appendix tells
  operators to size cohorts by "the fee-rate tail they intend to survive".
  The off-chain side is not costed at all: every member must follow every
  spend to keep its path current, about 1 kB of witness per transition,
  and the operator stores the full tree.
- **Resolution:**
  - Add one wall-clock row per tier from the Go verifier.
  - Add a percentile table of block feerates over a stated window.
  - Add a sentence or two on member bandwidth per transition, or state
    explicitly that it is out of scope.

### 24. Small issues (nit)

- **Table 3, "total (WU)":** The column holds witness weight, not
  transaction weight. Rename it.
- **"0xC0 tiers" and varops (main.tex 1013 to 1015):** "2.5 to 4.7% in the
  sparse" uses the D = 256 row, which the short version never shows. Over
  its tabulated D = 32 and 64 rows the range is 3.6 to 4.7%.
- **Table 4:** The LayerTree "Opcodes" row lists only FULL's set, but the
  paper's point is that CCV and MIN need less.
- **Mannered phrases:** "The design is hostage to proposals", "This is the
  design's honest weak spot" and "The voucher is insurance" should say what
  they mean literally.
- **`review-response.md`:** It describes an older state in several places:
  the title ("Single-Transaction Exit and Eviction"), MID coverage ("all
  but the cohort sweep"; MID now compiles the sweep), References at the
  top of page 16, and N = 6 confined to the fee appendix. Add a dated note
  saying which revision each table refers to.

## Number inconsistencies

| # | Location | Paper value | Source value | Source |
|---|---|---|---|---|
| 1 | main.tex 416 to 417 (short Section 4.1) | sparse 1.8 to 2.7 × dense | 1.76 (N = 2^16, D = 32) to 2.83 (N = 2^16, D = 64); 2.7 holds only at N = 6 | Table 3 (≈1,800, ≈2,890 vB); `spec/fee-analysis.md` (2,725 vB at N = 6) |
| 2 | full-profiles.tex 43 | 1.6 to 2.7 × | N = 6 basis (1,637 and 2,725 vs 1,020); short version says 1.8 to 2.7 | `spec/fee-analysis.md` |
| 3 | appendix-eval.tex 10, 21 (Table 3) | sparse witness 326 + 41 log2 N | 326 B measured at N = 6, already including about 2.6 siblings; the formula gives 432 at N = 6 | `spec/scripts/sizes.md` header and S/32 row |
| 4 | full-profiles.tex 31 to 32 | ≈860 B witness, 1,800 vB at 2^16 | 860 B gives (5,147 + 860 + 129 + 946) / 4 = 1,771 vB; Table 3's formula gives 982 B and 1,802 vB | Table 3; `sizes.md` |
| 5 | full-profiles.tex 41 | D = 256 "about twelve times dense" | script 35,611 / 2,101 = 16.9 ×; transaction 9,243 / 1,020 = 9.1 × (N = 6) or ≈9,410 / 1,020 = 9.2 × | `sizes.md` S/256 row; `spec/layertree.md` Section 11 |
| 6 | full-profiles.tex 74 | radix 4 "net loss of about 3%" | 1,042 / 1,020 = +2.2% | full Table 4 (same file) |
| 7 | full-batching.tex 47 to 50; full-cost.tex 66; Figure 6; main.tex 1005 to 1006 | REWRITE_2/4/6 exit: 370, 198, 159 vB per leaf | 359, 195, 158 under the stated model (946 WU + 172 × (K - 1)) | spec Section 11 REWRITE table; `tools/fee_analysis.py` |
| 8 | full-batching.tex 49 | REWRITE_6 "within one vbyte" of the sweep | equal (158 vs 158) after row 7's correction | as row 7 |
| 9 | full-batching.tex 98; Figure 6 caption; full-cost.tex 63 to 64 | 147 vB per leaf for 206 leaves "at D = 16" | measured at D = 20 (EVICT_SUBTREE_8, 84,772 WU) | `sizes.md` D/subtree 20 row |
| 10 | full-batching.tex 7 to 13 | 470 fixed + 32 per level + 100 to 120 per leaf | sums to 1,082 to 1,102 for one exit; measured 1,020 | `spec/fee-analysis.md` |
| 11 | full-batching.tex 119 to 124 | a leaving leaf costs "about 100 vB, in every shape" | 147 vB marginal per exiting position (REWRITE_6); 158 per leaf (sweep) | spec Section 11 |
| 12 | main.tex 243 (contribution 6) | "665 vB per batched exit" | 665 is the marginal second exit; per exit in EXIT_2 is 842 | `spec/fee-analysis.md`; Figure 3 right |
| 13 | Figure 3 right; main.tex 998 | 842 average and 665 marginal | 1,020 + 665 = 1,685, not 2 × 842 = 1,684 (separate rounding) | `spec/fee-analysis.md` (EXIT_2: 1,684 vB) |
| 14 | appendix-eval.tex 125 to 126 (fee table) | 203 vB → 2,029 sat at 10 sat/vB; 158 → 7,899 at 50, 39,495 at 250 | 203 × 10 = 2,030; 158 × 50 = 7,900; 158 × 250 = 39,500 (fees taken from unrounded 202.9 and 157.98) | `spec/fee-analysis.md` sweep table |
| 15 | appendix-eval.tex 10 (Table 3 caption) | skeleton ≈950 WU | 946 WU | appendix E.4; `tools/fee_analysis.py` |
| 16 | main.tex 1001; full-graft.tex 43 | member funding input 58 vB | the model's fee input is P2WPKH: 41 vB + 108 WU = 68 vB | `tools/fee_analysis.py`; `spec/fee-analysis.md` |
| 17 | appendix-eval.tex 10 | eight-leaf reference set | "5-6 leaves" | `spec/fee-analysis.md` caveats; `review-response.md` K ("five-leaf") |
| 18 | main.tex 408 to 410 (41 B witness per level) | 129 WU per level in the measurements | "131 WU (88 script + 41 path + 2 length prefixes)" | `spec/layertree.md` Section 11; `sizes.md` deltas give 129 |
| 19 | main.tex 937 to 938 | transaction tree crosses near D = 3; LayerTree ≈60% smaller at D = 16 | "breaks even near D = 5" and "about 2.4× cheaper" | `spec/layertree.md` Section 11 |
| 20 | main.tex 1003 to 1004; Figure 3 | sweeps 203 and 158 vB per leaf | "≈ 165 per leaf", "≈ 116 per leaf" (main table); 580 and 445 WU per leaf (sweep table) | `spec/layertree.md` Section 11 (internally inconsistent; the paper agrees with `fee-analysis.md`) |
| 21 | main.tex 416 to 420; main.tex 931 | sparse ≈1.8 × dense | "about twice" | `spec/layertree.md` Section 11 |
| 22 | full-cost.tex 85 (Table 3 caption) | Lightning commitment 130 vB | at least the 154 vB cooperative close in the same model; BOLT 3: 181 vB (no anchors), 281 vB (anchors) | `design/cost-comparison.md`; BOLT 3 |
| 23 | full-cost.tex 54 to 57; Figure 5 | native opcode 388 vB, presented as a D = 16 floor with "about 10 vB per level" of proof | witness 225 B (56 vB) is a small-population compressed proof; a D = 16 path alone is 656 B (164 vB) | `design/native-opcodes.md` lines 105 to 123 |
| 24 | full-cost.tex 79 to 81 | SPLIT as off-chain value movement, "about 1 kvB" | SPLIT is an on-chain transition, about 1,620 vB each (5,531 WU) | `sizes.md` D/16 SPLIT row |
| 25 | full-profiles.tex 53 (Table 4 caption) | radix experiment, "55 checks" | `tools/experiments/radix4.py` fails at HEAD (AttributeError at `script_sim.py:437`) | `tools/experiments/radix4.py` |
| 26 | main.tex 1013 to 1014 | sparse varops 2.5 to 4.7% | 2.5% is D = 256 (not in the short version); tabulated D = 32 and 64 give 4.7% and 3.6% | spec Section 10.10; `sizes.md` |
| 27 | `review-response.md` "Length" row | References at the top of page 16 | References begin mid-page 16, after Sections 10 and 11 | `main.pdf` page 16 |
| 28 | `CLAUDE.md` / `AGENTS.md` "Running everything" | check counts 425 / 120 / 31 / 309 | suites print 852 / 198 / 31 / 798, as the paper says | `tools/test_*.py` output at HEAD |
| 29 | `design/batching.md` ("about 147 for 200") | 206 leaves in the paper | 206 | `tools/gen_cost_figures.py` OPERATOR_SWEEPS |
