# Review: "LayerTree: Constant-Size Exit and Eviction from a Shared Bitcoin UTXO"

**Venue:** Financial Cryptography and Data Security (FC), full paper
**Reviewer:** PC member
**Artefacts consulted:** `spec/layertree.md` (4.4, 4.5, 6, 7, 10, 11), `spec/channel-leaves.md`,
`spec/fee-analysis.md`, `spec/scripts/sizes.md`, `formal/README.md`, `formal/LayerTree/*.lean`,
`design/review.md`, `tools/layertree_min.py`, `paper/appendix-lean.tex` (present in the source
tree but *not* `\input` by `main.tex`).

---

## 1. Summary

The paper proposes LayerTree, a scheme in which many users share a single Bitcoin UTXO whose
scriptPubKey commits, through a data-tweaked taproot internal key, to the root of an off-chain
binary Merkle-sum tree of per-user leaves (balance, exit key, owner key, evictor key, lease height,
nonce, sequence). Instead of pre-signed or template-committed *transaction* trees, state transitions
are enforced by tapscript covenants that recompute the root from a witness-supplied sibling path,
check it against the committed root, recompute the successor root with the leaf replaced, and
constrain output 0 to recreate the tree output under the new root and total (plus payout outputs).
Seven transitions are specified (EXIT, EXIT_K, JOIN_h, JOINK_K, UPDATE, CLAIM/vouchers,
EVICT_SUBTREE_h) in a dense operator-assigned profile and a key-addressed sparse (MS-SMT) profile.
Each is claimed to be realised in three opcode tiers — FULL (tapleaf `0xC2`, `OP_TX`, CSFS, EC point
ops), MID (`0xC0` + `OP_CAT` + `OP_TX` + CSFS + `OP_TWEAKADD`) and MIN (`0xC0` + `OP_CAT` +
`OP_TWEAKADD`) — where MIN replaces introspection by *constructing* the BIP-341 sighash message in
script and verifying it with a generator-key signature whose only solution is `s = e + 1`. A further
section hosts eltoo-style Lightning channels inside leaves via an `ANYPREVOUT` emulation built from
`OP_TX` + CSFS. Security is argued in an idealised-hash model with five theorems mechanised in
Lean 4, and the evaluation reports measured sizes (1,020 vB for a `D = 16` unilateral exit), batched
and cohort costs (665 vB marginal, 158 vB/leaf), fee tables, and a comparison against a `150D + 111`
vB model of an Ark/CTV transaction tree.

---

## 2. Strengths

* **The core idea is genuinely new in this literature and is well chosen.** Replacing a tree of
  transactions with a tree of *data* verified inside one script converts an `O(log N)`-transaction
  exit into a one-transaction exit whose witness grows by ~32 vB per level. The consequences the
  paper draws out (no pre-signing, no shared-output expiry, operator eviction, subtree grafting,
  cohort sweeps) are the right consequences and are individually well motivated.
* **The artefact is unusually strong for this venue.** A tapscript simulator for opcodes that do not
  exist yet, with BIP-440 varops accounting and a real BIP-341 sighash; a Go implementation compared
  byte-for-byte against 30 golden vectors (`spec/golden.json` does have exactly 30 script entries);
  338 executable checks (272 + 59 + 7, confirmed); and a Lean development that builds without
  Mathlib. I checked every Lean identifier cited in §7 (`enc64_eq_minimal`, `serializeLeaf_inj`,
  `serializeNode_inj`, `minimalLE_two_pow_32_length`, `scriptNum_neg_max31_succ`, `root_inj`,
  `fold_sound`, `Steps.sum`, `ExitK.no_inflation`, `ExitK.exact_conservation`, `join_sound`,
  `update_sound`, `claim_sound`, `payable`, `Steps.sound`, `witness_root_binds`) — **all sixteen
  exist with those exact names and the statements match the informal renderings**. "About 1,300
  lines" is accurate (1,274 over `formal/LayerTree/*.lean`); `formal/README.md`'s "about 900 lines"
  is the stale one.
* **The tiering discipline is a real contribution.** Most covenant papers assert "this needs `OP_CAT`
  and introspection"; this one measures the cost of each dependency. The MIN-tier trick
  (constructive introspection via a generator-key signature) is, as far as I know, new in this exact
  form and is a result worth publishing on its own.
* **Honest about the central weakness.** §7 ("Concurrency") and §10 ("Exit serialisation") do not
  hide that everything funnels through one UTXO. That is more candour than the comparison targets
  usually show.
* **The mechanisation earned its keep,** which is rare. The grounded-node distinction (Theorem 5 and
  the paragraph after it) is a real finding produced by the proof effort, not decoration, and the
  `CLAIM` drained-source observation likewise.

---

## 3. Weaknesses and concerns

Ordered by severity. **A**–**E** I consider blocking for acceptance in the current form; **F**–**M**
are substantive but repairable; **N**–**T** are presentation.

### A. "Every transition is implemented in three tiers" is not true; MIN implements exactly one script

This is the paper's headline structural claim and it does not survive contact with the artefact.

* §1, Contribution 2: *"Every transition is implemented against the full candidate set, against a
  `0xC0`-only subset, and against the minimum we could find"*.
* §5, opening: *"Every transition of \S\ref{sec:transitions} is realised three times, against three
  opcode sets (Table 1)"*.

`tools/layertree_min.py` defines exactly one script generator, `exit_script(depth)` — dense-profile
`EXIT_1` only — and its docstring says so: *"EXIT_1 for the dense profile is provided; other
transitions follow the same construction"*. The MIN suite is 7 checks and `spec/scripts/sizes.md` has
a single MIN row. MID likewise has no `EVICT_SUBTREE_h` (its rows are `EXIT_1`, `JOIN_2`, `JOINK_2`,
`UPDATE`, `CLAIM`, `UPDATE_X`), and the spec's own tier matrix (4.5) records that MIN has no
`UPDATE`, no `UPDATE^x`, no `CLAIM`, no terminal exits, no sparse profile and no channel leaves.
Table 1 reproduces two of those exclusions, leaving the impression that MIN is a complete realisation
minus vouchers. It is one script.

The consequence is not cosmetic: §5.3 concludes *"The result is a precise minimality statement:
BIP-342 tapscript plus `OP_CAT` plus one point-tweak opcode realise the covenant."* What is
demonstrated is that they realise *a single-leaf dense exit at `D = 16`*. Whether `EVICT_SUBTREE_6`
(16 kB of script in FULL) or the sparse profile fit in MIN at all — under 4-byte `CScriptNum`
arithmetic, a fixed two-input shape and a message reconstruction per transition — is exactly the
question a minimality claim must answer, and the big scripts are where it is least obvious.

**Fix.** (i) Restate Contribution 2 and §5's opening as "FULL realises every transition; MID realises
all but `EVICT_SUBTREE_h`; MIN realises `EXIT_1` in the dense profile, which we argue is the
load-bearing case". (ii) Add a coverage column or footnote to Table 1 listing, per tier, which
scripts exist and how many checks cover them. (iii) Either implement `JOIN_0` and one
`EVICT_SUBTREE_h` in MIN, or state plainly that MIN's generalisation is argued, not measured, and
give the projected sizes. (iv) Soften "precise minimality statement": no lower bound is proved
anywhere (the `OP_CAT`-is-irreducible argument in spec 4.4 is an argument about `OP_PAIRCOMMIT`, not
a theorem), so the honest phrasing is "an upper bound on the opcode set required".

### B. The theorems do not imply G1–G5 as stated, and the invariant they need has no base case in the paper

§3 states five goals; §7 offers five theorems; the paper never spells out the gap, and there are
three real ones.

1. **Payability needs "the on-chain root is the root of a real tree", and the paper never establishes
   it.** `payable` is stated *for a tree*: `theorem payable (t : Tree d) (p : Pos d 0) (l : Leaf)
   (hl : t.get p = some l)`. The on-chain object is a 32-byte root, not a tree. Theorem 5
   (`Steps.sound`) propagates the invariant across grounded transitions — but the induction has no
   base case in the paper. The base case is tree *creation*, and spec 6.5 is explicit that nothing
   enforces it: *"A tree is created by any transaction paying `TREE_SPK(r_0, m)` with amount equal
   to the sum of `r_0`"* — any funding transaction may pay any amount to any root. If `amount ≠
   root.sum` at creation the tree is bricked (the first `CHECK_OLD` fails) and no theorem notices.
   Interestingly, the *unused* `appendix-lean.tex` in the source tree contains precisely the missing
   subsection ("How the Invariant Is Established and Maintained"), which is further evidence that the
   body needs it. **Fix:** add a one-paragraph proposition to §7: "Invariant. The tree output's
   scriptPubKey commits to the root of a tree whose total is the output amount. Base case: creation,
   which the covenant does not enforce and which every member MUST check before funding (§4.2).
   Step: Theorem 5 plus the `CHECK_OLD` rule of Fig. 2." Then state Theorem 4 as conditional on it.
2. **G1 as worded is false under ungrounded grafts.** G1: *"the tree output's amount is always the
   sum of the leaf balances committed by its root"*. Theorem 3 conserves the *sum field* in the
   nodes, unconditionally; under a graft with no preimage there are no leaf balances under that node
   at all, so the amount is not the sum of any leaf balances. The paper knows this (the paragraph
   after Theorem 5, and §10) but G1 is never corrected. **Fix:** reword G1 as "no transition creates
   value: the committed root sum equals the output amount, and payouts are funded by removed leaf
   *sums*", and add "and, under the grounded invariant, the root sum is the sum of real leaf
   balances".
3. **G2 says "can always construct an accepted exit"; three facts in this paper contradict
   "always".** (a) *Acceptance* is a consensus/policy predicate, and the correspondence between the
   Lean rules and the bytecode is by execution, not proof (§7 says so). (b) Mempool descendant policy
   bounds the tree to ~25 exits per block (§7, §10), so exit is eventual, not always available.
   (c) Economics: at `D = 16` a leaf below ~1,021 sat cannot exit at 1 sat/vB, and in MID and MIN
   payouts are *exact* (spec 4.5: "Payout amount: exact for both"), so the member must own an outside
   UTXO for the fee — the endogenous-fee option is FULL-only. **Fix:** qualify G2 ("given a fee
   source and a payout above dust, and subject to the contention bound of §7") and add the per-tier
   payout-rule row from spec 4.5 to Table 1: its omission hides a semantic, not merely a size,
   difference between tiers.
4. **G3, G4, G5 have no theorems at all.** §7 carries authorisation and lock times as "opaque
   propositions" — defensible, but it means eviction (G3), the difference the paper claims over Ark
   and timeout trees, is entirely outside the verified perimeter. Say so next to the goal list, not
   only in §7's last paragraph.

### C. The MIN-tier argument is correct but under-stated, and the paper omits the conditions it relies on

I worked through `tools/layertree_min.py` against the text of §5.3. **The `s = e + 1` construction is
sound**, and I want to say so clearly before listing what is missing: `lift_x(G_x) = G` (G has even
y), `R = lift_x(G_x) = G`, so verification computes `s·G − e·P = (e+1)G − eG = G`, whose x-coordinate
is `G_x` and whose y is even, so the check passes. The script's grinding (`e31 || 00 == e`, then
`s = e31 || 01`) is a correct way to add one without arbitrary-precision arithmetic. I also checked
the reconstructed message against BIP-341: the script pins epoch `0x00`, hash type `0x00`
(SIGHASH_DEFAULT), `spend_type = 0x02` (hence *no annex*), `input_index = 0`, key version `0x00` and
codeseparator position `0xffffffff`, and builds `sha_amounts` from exactly two 8-byte amounts —
which is how "two inputs" is actually enforced. All of this is right.

What §5.3 does not say, and should:

1. **This "signature" authorises nothing.** No secret key is used; anyone can compute it. Binding
   comes entirely from collision resistance of the TapSighash and BIP-340/challenge tagged hashes:
   a spender who found `msg' ≠ msg_real` with `H(G_x‖G_x‖msg') ≡ H(G_x‖G_x‖msg_real) (mod n)` would
   break the covenant. *"Because `OP_CHECKSIG` hashes the real transaction, the constructed message
   must equal the real one"* asserts the conclusion; the reason belongs in the text, since this is
   the one place a *new* cryptographic assumption enters and it is not in the Lean model.
2. **"The verification equation … has the unique solution `s = e + 1`"** — unique *modulo `n`*, and
   `e` is the challenge reduced mod `n` while the script uses the raw 32-byte hash. They coincide as
   scalars, but the signature fails to parse if the raw hash is `≥ n − 1` (probability ≈ 2⁻¹²⁸,
   requiring a re-grind). One clause.
3. **The grinding field is the fee input's `nSequence`, which is not free.** It interacts with BIP-68
   relative timelocks and BIP-125 RBF signalling, it must be fixed *before* the fee input is signed,
   and **any fee bump requires re-grinding and re-signing** — on a transaction §7 says is in
   contention for a single UTXO. State the `nSequence` range used, and that CPFP via a free extra
   output, not RBF, is the intended bump path.
4. **"This costs 256 hashes on average"** is the expected number of *trials* (geometric, p = 1/256);
   each trial recomputes `sha_sequences`, the tagged sighash and the tagged challenge, ~5 SHA-256
   compressions, so ~1,300 hashes. Trivial either way, but the paper is precise everywhere else.
5. **What the script guarantees should be stated as a list**, because it is the interesting part:
   input 0 is the tree output with amount `S` and `scriptPubKey = TreeSPK(r, m)`; exactly two inputs;
   no annex on input 0; outputs 0 and 1 fixed; outputs ≥ 2 free; version, locktime, prevouts and
   sequences free but self-consistent. Half a column turns a trick into a specification.

### D. The Ark/CTV comparison is the paper's headline number and the model is stacked

The `150D + 111` vB model appears in the abstract (*"about 2.5× less than unrolling an Ark- or
CTV-style tree of the same size"*), in Table 2's rightmost column, in Fig. 4's legend and in §8. The
per-transaction figure (~150 vB for a 1-in-2-out taproot script-path node spend) is defensible. The
*model* around it is not, in four ways, and only the last is disclosed:

1. **Radix.** Real CTV/Ark trees are not radix-2; radix-4 halves the levels and the choice is free to
   the designer. Include at least a radix-4 line.
2. **Amortisation of the interior.** The model charges every exiting user the full `D × 150`, but
   interior transactions are *shared*: once one user has published the path, the marginal cost for
   any other user under that branch is one transaction. Under mass exit — where this comparison
   matters most — the Ark/CTV per-user cost collapses toward ~150 vB, against LayerTree's 1,020 vB
   standalone or 665 vB marginal. The paper makes exactly this batching argument for itself; it
   should make it for the comparator.
3. **The sparse row is not like-for-like at all.** Table 2's `sparse, 32` row puts LayerTree's
   1,637 vB next to 4,911 vB, i.e. against an Ark tree of 2³² *leaves*. A sparse LayerTree with
   65,536 *members* should be compared with an Ark tree of 65,536 leaves (2,511 vB), against which it
   is *more* expensive, not 3× cheaper. Comparing address space with membership is the single most
   misleading number in the paper. **Fix:** index by occupancy `N`, not `D`, and drop the `D = 64`
   row.
4. **Latency and the opcode premium are priced at zero**, though `spec/fee-analysis.md` notes both
   ("prices vbytes only and does not price that latency"; "LayerTree's advantage requires the larger
   FULL-tier opcode set"). Neither caveat reached the abstract or §8.

Separately, **"LayerTree breaks even near `D = 5`" (§8) does not follow from the paper's own model.**
With LayerTree at `504 + 32.25·D` vB (fitted to the paper's own 762/891/1,020/1,149) and Ark at
`150D + 111`, the crossing is at `D ≈ 3.3`, not 5. (Spec 11 makes the same claim in weight units:
`2000 + 130D` vs `600D + 444` also gives `D ≈ 3.3`.) The error is conservative, but it is an error.

**Minimum fix:** say "modelled" in the abstract, replace Table 2's Ark column with a small sensitivity
table (radix 2 / radix 4 × isolated / amortised), index by `N`, and correct the break-even.

### E. Sparse-profile numbers are measured on a six-leaf tree, and the paper does not say so

`spec/scripts/sizes.md` opens with: *"Witness data for the sparse profile is measured on a 6-leaf
tree (compressed proofs); add 40 bytes per additional non-empty sibling (about log2 N in total)."*
Spec 11 accordingly reports the sparse `D = 32` exit as **≈1,800 vB at `N = 65k`**. The paper's
Table 2 reports **1,637 vB** — the `N = 6` figure — and §8 concludes *"The sparse profile at `D = 32`
costs 1.6× the dense profile at `D = 16`"*. At a realistic `N` it is ~1.76×, which is what §4.1 of the
same paper says (*"about twice the per-exit cost of the dense profile"*). So the paper contradicts
itself (1.6× in §8, "about twice" in §4.1) and the table takes the favourable reading of an
unstated parameter. The sentence *"witness data is nearly constant in `D` because empty siblings are
elided"* is true and worth keeping, but it must be accompanied by "witness data grows with `log₂ N`",
which is the property that actually matters. **Fix:** report sparse rows at `N = 2^16` (and, if you
like, at `N = 6` as a floor), and state the `326 + 41·log₂N` formula in the caption.

### F. The varops figure for the sparse profile appears to be wrong by 3–5×

§8 ("Fees"): *"Varops usage is 6 to 8% of the BIP-440 budget in the dense profile and 8 to 25% in the
sparse profile"*. Spec 4.1 fixes the budget as `10,000 × weight`. Using the measured varops of
`spec/scripts/sizes.md` and the transaction weights of `spec/fee-analysis.md`:

| case | varops | tx weight | budget | fraction |
|---|---|---|---|---|
| dense `D = 8` | 2.33 M | 3,046 | 30.5 M | 7.6 % |
| dense `D = 16` | 2.48 M | 4,078 | 40.8 M | 6.1 % |
| dense `D = 20` | 2.56 M | 4,594 | 45.9 M | 5.6 % |
| sparse `D = 32` | 3.07 M | 6,548 | 65.5 M | **4.7 %** |
| sparse `D = 64` | 3.97 M | 10,900 | 109 M | **3.6 %** |
| sparse `D = 256` | 9.30 M | ~37,630 | ~376 M | **2.5 %** |

The dense range checks out (5.6–7.6 % ≈ "6 to 8%"). The sparse range does not: it is 2.5–4.7 %, and
the fraction *falls* with depth because the budget is proportional to weight and the sparse scripts
are enormous. The "25%" looks like `9.3 M / 40 M`, i.e. the 256-level tree's varops divided by the
`D = 16` dense transaction's budget. (Spec 10.10's "still under a quarter of budget" has the same
smell.) This is worth fixing carefully because it is the only evidence offered that the design fits
inside BIP-440, and the correct numbers are *better* for the paper. **Fix:** recompute and, while
you are there, give varops as a fraction of budget per tier (MID/MIN are `0xC0`, where the relevant
limit is the sigops/validation-weight budget instead — currently "n/a" in `sizes.md` and unaddressed
in the paper).

### G. The 25-descendant claim: roughly right, stated too confidently, and it misses the real attack

§7: *"Default mempool policy (25 descendants) bounds uncooperative exits to about 25 per confirmed
tree output, i.e. per block."* The arithmetic is fine (25 × 1,020 vB = 25.5 kvB, well inside the
101 kvB descendant-size limit, so the count limit binds). Four problems:

1. It is *policy*, not consensus, and the policy is changing: cluster mempool replaces
   ancestor/descendant limits with cluster-size limits, and TRUC/v3 (BIP-431, cited here for the
   channel anchors) allows 1 ancestor/1 descendant. Without "under today's defaults", the number
   dates the paper.
2. The limit counts the transaction itself (24 chained descendants), and it interacts with the
   ancestor limit once fee inputs are unconfirmed.
3. **The pinning attack is not discussed.** In a chain of exits off one tree output, one low-feerate
   exit early in the chain caps the effective feerate of everything behind it, and the only remedy is
   to conflict-replace it — which under BIP-125 rules 3/4 means paying for the whole descendant set.
   One member can stall every other member's exit cheaply. *"Conflicts resolve by fee"* is too glib
   for what the paper itself calls its defining constraint.
4. *"at most one confirms per tree per block position"* — "per block position" is unparseable.

Also, the bound is stated for *uncooperative exits* but applies to *everything*: joins, updates and
evictions share the output, so a tree under mass exit cannot onboard and the operator's sweeps
compete with the exits.

### H. Channel leaves: the HTLC budget derivation in the paper omits its dominant term

§6: *"The deadline budget an HTLC needs is the time to materialise the funding output (one tree
transaction), one block for the update transaction, the dispute delay and the sweep: roughly 220
blocks with a 144-block delay"*. As listed, that is 1 + 1 + 144 + 1 ≈ 147, not 220. The appendix's
actual formula (`spec/channel-leaves.md` C.4.4) is

```
cltv_expiry_delta >= G_exit + 1 + 1 + csv_delay + 1 + G_sweep
```

with **`G_exit = 72`**, *"the time to get an `EXIT_1` confirmed including contention for the tree
output"*. The missing term is the whole point — the budget is 220 rather than 147 precisely because
of the single-UTXO contention of §7, which ties this section to the paper's central limitation. As
written, a reader cannot reproduce 220 and cannot see the connection. **Fix:** give the formula and
name `G_exit`; and note that `G_exit` is itself a function of tree size under the 25/block bound,
so the budget is not a constant but grows with `N` — which is the sharpest version of the argument
the paper wants to make in §10.

Three further points on §6:

* **"No script data need be retained" is narrower than it sounds.** A responder still needs the
  per-channel context (`m`, leaf identity, channel key, capacity, splice epoch, `S_0`) and,
  decisively, the counterparty's rebindable signature for the latest state and the settlement
  balances. What is saved relative to CTV-based LN-Symmetry is the per-state *script/template*, not
  the per-state signature; qualify the related-work sentence the same way.
* **The `ANYPREVOUT` emulation looks sound but does not cover the input amount.** `REBIND_n`'s blob
  is version, lock time, the current input's sequence, the number of inputs and all outputs;
  `SETTLE_n`'s adds the input amount and spk. An update output holding *more* than the capacity (an
  over-payment to `P2TR(exit_key)`, or a splice not reflected in the context) burns the excess to
  fees. Rule (i) closes the main path, but say why committing to the amount in `REBIND` is
  unnecessary rather than leaving it to the reader.
* **The "13×" force-close comparison is one-sided.** ≈1,680 vB against "a Lightning force close"
  (~130 vB) omits Lightning's funding transaction (~110–150 vB), which is exactly the cost LayerTree
  avoids. The lifetime on-chain footprint (1,680 vs ~280) is more honest and still a 6× gap.

### I. Overclaims in the title and abstract relative to what is shown

* **"Constant-Size Exit" (title) / "one transaction whose size is independent of `N`" (abstract).**
  It is not. The exit is a *constant number of transactions* whose size is `O(log N)` — the paper's
  own §1 says so correctly (*"exit is `O(1)` transactions and `O(D)` bytes"*), and §8 measures
  32 vB/level. Two sentences later the abstract gives "1,020 virtual bytes for a tree of 65,536
  positions", which only makes sense if size depends on `N`. **Fix:** "Constant-Transaction Exit", or
  "one transaction of `O(log N)` bytes"; in the abstract, "whose size grows with the *depth* of the
  tree, not with the number of transactions in a path" (which is §1's own good formulation).
* **"unconditional payability" (abstract).** This directly contradicts Contribution 4 on the same
  page (*"exits are guaranteed only under grafted nodes that have preimages"*) and Theorem 5. What is
  unconditional is *conservation*. **Fix:** "we prove conservation unconditionally, and payability
  under a grounded-tree invariant".
* **"about 2.5× less than unrolling an Ark- or CTV-style tree"** — no indication that this is a model
  (see D); also "2.5× less" is not idiomatic ("2.5× smaller", "60% cheaper").
* **"whole cohorts are added or swept in one constant-shape transaction (158 virtual bytes per
  evicted leaf)"** — 158 vB/leaf is one point (`EVICT_SUBTREE_6`, 51 leaves, `D = 16`, 3 of 16
  positions empty); the per-leaf cost is a function of `h` and occupancy (203 vB at `h = 4`,
  ~1,300 WU/leaf at `h = 2`). Give the range or the parameters.
* **§5.3: "`EXIT_1` costs 3,572 bytes at `D = 16`, 43% more than FULL."** 3,572 is *script* bytes
  against FULL's 2,101 = **+70%**; the 43% is the *transaction* figure (1,456 vs 1,020 vB). As
  written the sentence is wrong on its own terms. Similarly, *"worth between 260 and 1,470 witness
  units per exit"* mixes measures: 260 WU is a total-witness delta (3,393 − 3,132) while 1,470 is a
  script-only delta (3,572 − 2,101); MIN's total-witness delta is 1,744 WU.

### J. Missing related work

For a paper whose contribution is partly "what does this cost in opcodes", the related-work section
is thin (nine citations of systems). The following are, in my view, required:

* **CoinPool** (Riard, Naumenko, Rubin). The closest prior art by far: a shared UTXO with per-user
  balances and unilateral withdrawal. Its absence is the most conspicuous gap in §9.
* **Ark's actual exit path.** The paper models Ark as "unroll the branch" without describing VTXO
  expiry, the exit timelock, out-of-round payments, or the difference between *pre-signed* Ark and
  **covenant Ark / clArk** (CTV or CCV based), which removes the interactive round the paper credits
  Ark with requiring (Table 3, "Interactive signing: round members"). Table 3 compares LayerTree to
  the 2023 pre-signed Ark, not to what Ark is today.
* **"Timeout trees" vs "Spacechains"**, **Superscalar**, and **channel factories with eltoo /
  "Lightning without pre-signed transactions"**: §6 sits squarely in this lineage and cites only
  `eltoo` and `lnsymmetry`.
* **Elements/Liquid** — the most important omission for the *tiering* argument: Liquid has shipped
  `OP_CAT`, `OP_CHECKSIGFROMSTACK` and a transaction-introspection opcode suite for years, so a
  reader will immediately ask whether MID (or FULL) is deployable there today, turning "hostage to
  proposals" (§10) into "implementable now, on a sidechain". Either answer is interesting; silence
  is not. **Simplicity** (also on Liquid) is the natural foil to the three-tier framing.
* **`OP_VAULT` / BIP-345** (introspection + recreate-the-output covenant); and **BIP-347 `OP_CAT`** —
  the abstract claims `OP_CAT` plus one tweak opcode suffice and the bibliography **cites no CAT
  proposal at all** (BIP-340, 341, 342, 348, 349, 440, 441, 443, 449, 118, 119, 431, 327 — no 347).
* **MS-SMT/Taproot Assets proofs** are cited (`mssmt`) for the data structure only; the proof
  *compression* of the sparse profile has prior art there and in Utreexo-style accumulators.
* Minor: `bip349` and `gsrquartet` appear in `refs.bib` but are never cited in `main.tex`.

### K. The evaluation omits measurements an FC reviewer expects

1. **On-chain footprint for joins.** Exits are measured exhaustively, joins in one sentence:
   *"a dense `JOIN_h` adds any number of members for a constant ≈2,000 WU"* — but (a) `JOIN_2` at
   `D = 16` measures 2,713 WU of witness and `JOIN_0` 2,972, so "≈2,000" is rounded down by a third;
   and (b) **the funding inputs are not counted.** Spec 12 says joins are self-funded ("Operator
   liquidity: none required"), so grafting 256 members needs up to 256 inputs ≈ 58 vB each ≈
   14.8 kvB, an order of magnitude more than the script. Against Ark, whose round transaction
   onboards everyone at once, this is the comparison that matters for a hub, and Table 3's "Batch
   add: 1 tx, any subtree" vs "per round" does not distinguish the two. Add a per-member on-chain
   onboarding cost, with and without operator pre-funding.
2. **Sparse witness at realistic `N`** (see E).
3. **Varops/validation budget per tier** (see F), including what replaces varops in `0xC0`.
4. **A real fee-rate distribution.** The tables sweep 1–250 sat/vB uniformly; a reviewer wants the
   empirical distribution (say, two years of block feerates) to see how often a 1,020 vB exit is
   affordable at a given leaf size, and how often a 51-leaf sweep is economical.
   `spec/fee-analysis.md` already tells operators to pick a "90th-percentile rate seen in the last
   year" — compute it.
5. **Control-block size.** Table 2's 129 bytes assumes a *five-leaf* taptree (spec 11), while §4.2
   says the taptree holds "one leaf per supported transition script" and §4.3 describes at least nine
   plus variants and multiple `h` values. A 16-leaf taptree costs 193 bytes and moves every number in
   Table 2. State the assumed script set and show the sensitivity.
6. **No validation-cost or CPU measurement**, only sizes. For ~2.5 M varops and 16 tagged hashes per
   exit, a wall-clock figure from the Go implementation is cheap and pre-empts the "is this even
   relayable" objection.

### L. Is the paper self-contained without the repository? Not quite

There is not a single LayerTree script listing in the paper — only the two 4-line channel leaves of
Fig. 3. A reader cannot check "88 bytes per level", cannot see how `CHECK_OLD` reads the input
amount, cannot see the `PADZ` gadget that §5.2 says is "almost all" of the MID premium, and above all
cannot see the MIN sighash reconstruction, which is the paper's most novel single artefact. Fig. 2's
pseudocode is the right level for the rules, but at least one concrete listing (annotated `LEVEL`, and
the MIN message assembly) is needed for the paper to stand alone. See §5 of this review.

### M. Smaller technical gaps

* **`TreeSPK` injectivity is asserted, not reduced.** §7 says it "follows from the discrete logarithm
  assumption and collision resistance of `H_state` and the taproot tweak hash". The reduction is one
  line and worth writing, because the real map is
  `r ↦ x(lift_x(x(NUMS + H_state(r)·G)) + H_TapTweak(·)·G)` and the two `x(·)` projections collapse
  `±P` — exactly where injectivity arguments go wrong. §4.2's formula silently drops the `lift_x`
  normalisation that spec 6.3 has.
* **`H_state`, `H_pos`, `H_voucher` are never said to be tagged hashes** (only `H_leaf`/`H_node` are,
  §4.1), yet domain separation across all of them is load-bearing: a voucher message must not be
  confusable with a node preimage.
* **A tree output can only ever be spent as input 0**, since every script checks input 0's
  scriptPubKey — so two trees can never be merged or spent atomically. One sentence in §10.
* **Reorganisations** are in the spec (10.11) and absent from the paper. A reorganised-out `JOIN`
  invalidates every member's path; for a design whose safety story is "members keep their paths",
  that deserves a line in §7's data-availability paragraph.
* **`EXIT_K` authorisation**: §4.3 says each exit is "authorised independently", but all `K`
  signatures cover the same transaction, so every exiter must sign the final transaction including
  the others' payouts — batching needs a coordination round that the paper's "no interactive
  signing" framing disclaims elsewhere.

### N. Presentation

* **Length.** The compiled body is ~17 pages plus references. FC's limit is 15 LNCS pages excluding
  references and appendices; this needs real cutting (see §5 of this review for what to move).
* **`fold` direction is never defined.** §4.1 says `fold(n, π)` "combines a node `n` with a path `π`
  level by level"; Fig. 1 then writes `π = [(R,(h_0,s_0)), (L, E_0)]` for a leaf at depth 2, i.e.
  **root-first**, while the witness format is leaf-first and the Lean model is root-first (the
  artefact's CLAUDE.md flags this as a standing source of confusion). Also, the `dir` bit's meaning
  ("the side the *proved* node is on", not the side of the sibling) is never stated. Define both.
* **Undefined notation.** `le_64`/`le_32` are used in the leaf record before `enc_64` defines
  anything (`\lesf` is never expanded); `S_0` in §6 ("lock time `S_0 + n`") is never defined;
  `csv_delay`, `SEL_CHAN_UPD`, `SEL_CHAN_SET` and `ctx_upd`/`ctx_set` appear in Fig. 3 before or
  without definition; `E_h` is defined (§4.1, good) but `E_D` is then used as a *node* in Fig. 2 and
  as a *root* in §4.3.
* **Internal inconsistency**: §4.1 "about twice the per-exit cost of the dense profile" vs §8 "1.6×"
  (see E); Table 1's `EXIT_1` numbers are script/witness bytes while §8's percentages are transaction
  vB, and the paper switches between the two without warning (see I).
* **Figures.** Fig. 4 left has two single-point series (MID, MIN) whose markers will be hard to
  distinguish in print; draw them as dashed lines with the known per-level slope. Fig. 4 right's `x`
  labels are rotated 30° and abbreviate `EVICT_SUBTREE` to `ES` only in the caption. Fig. 1's caption
  carries four distinct claims and does a paragraph's work. The LaTeX log shows four overfull
  `\hbox`es, the worst 28.5 pt (≈ 1 cm past the margin) around line 853.
* **`main.pdf` is a 22-page build that `\input`s `appendix-lean.tex`, which the current `main.tex`
  does not** — source and PDF are not the same document. (`appendix-lean.tex` also uses `lstlisting`
  while `main.tex` does not load `listings`, so re-adding it as-is will not compile.)
* **Anonymity.** The paper carries the author's name, affiliation, email and a non-anonymous artefact
  link. If the venue's anonymity requirement applies, this is a desk-reject risk independent of
  content.
* Typos/wording: "2.5× less"; "Tier costs more than depth" (§8) reads as a sentence fragment;
  "Working the construction through exposed places where the tree rules were too lenient" (§6);
  "It is roughly 13× a Lightning force close" (missing "the cost of"); "at most one confirms per tree
  per block position" (§7).

---

## 4. Questions for the authors

* Does the MIN tier support `JOIN`, `UPDATE` or `EVICT_SUBTREE_h` at all? If `EVICT_SUBTREE_6` needs
  16 kB of script in FULL, does its MIN version fit under standardness and the 4-byte `CScriptNum`
  constraints? If not, what is the actual minimal opcode set for a *complete* tier?
* What `nSequence` range does the MIN grinder use, and how does it avoid imposing a BIP-68 relative
  timelock or disabling RBF signalling? After grinding, is the exit fee-bumpable at all except by
  CPFP through a free extra output?
* In the MIN tier, what happens if the raw challenge hash exceeds `n − 1`? (I assume re-grind; please
  confirm the script cannot be made to accept a malleated `s`.)
* Who verifies at tree creation that the funding output's amount equals `root.sum` and that `r_0` is
  a real tree? What is the failure mode if it is not — a bricked tree, or something worse?
* In MID and MIN, payouts are exact, so an exiting member needs an outside UTXO for the fee. Is that
  right, and does it not weaken G2 for exactly the tiers most likely to be deployable?
* Table 2 assumes a five-leaf taptree (129-byte control block). Which five scripts? A tree offering
  `EXIT_1`, `EXIT_2`, `EXIT^=`, `JOIN_0`, `JOIN_8`, `JOINK_2`, `UPDATE`, `UPDATE^x`, `CLAIM` and two
  `EVICT_SUBTREE_h` needs a deeper taptree; how much does that move the headline 1,020 vB?
* What is the per-member on-chain cost of joining, counting funding inputs, against an Ark round?
* What prevents one member from stalling every other member's exit by pinning the descendant chain
  off the tree output with a single low-feerate exit?
* Does the design work on Liquid/Elements today (`OP_CAT`, CSFS and introspection are live there)?
  If so, why is that not the headline deployment story?
* Can a malicious joiner grind a nonce so that `H_pos(owner_key ‖ nonce)` collides with a *target*
  member's sparse position, denying them a slot or forcing repeated operator retries?
* For channel leaves, why does `REBIND_n` not commit to the input amount, given that `SETTLE_n` does?
* Must a long-offline member process every spend of the tree output since it joined to rebuild its
  path, and what is the bandwidth of that at ~25 transitions per block?

---

## 5. Suggested additions

### 5.1 Yes: an appendix on the Lean formalisation — and you have already written it

The single best addition is an appendix expanding §7. Notably, `paper/appendix-lean.tex` already
exists in the artefact and is *not* included by `main.tex`; the stale `main.pdf` shows it runs about
three pages. Having read it, I would include it essentially as-is, with three additions:

1. **Keep** (it is good): the `Tree`/`Pos`/`fold` definitions, the `HashModel` class verbatim, the
   verbatim statements of `fold_pathSub`, `fold_setSub`, `root_inj`, `fold_sound`, `Step.sound`,
   `Steps.sum`, `Steps.sound`, `payable`, `ExitK.*`, `join_sound`, `claim_sound`, the
   "root-first vs leaf-first" note, and the axiom-audit statement.
2. **Promote to the body**: the subsection "How the Invariant Is Established and Maintained" — the
   answer to weakness **B**, which belongs in §7 where the reader forms an opinion about G1 and G2.
3. **Add**: (a) a per-module line-count/effort table (1,274 lines, seven modules) saying which proofs
   were hard; (b) an "assumption ledger" mapping each `HashModel` field and the `BindingModel`
   hypothesis to the concrete assumption it stands for and the theorems that use it — `fold_sound`
   being the *only* consumer of the hash axioms is a selling point; (c) a paragraph on what the
   verified interpreter promised in §10 would cost; (d) fix the mismatch between `formal/README.md`
   ("about 900 lines"; axiom line showing only `propext, Quot.sound`) and `Axioms.lean` (which
   expects `Classical.choice` too).

Budget: 3 pages, and it is the cheapest way to convert "we mechanised it" from a claim into evidence.

### 5.2 A second appendix with two script listings

One page: the annotated FULL `LEVEL` macro (88 bytes, so it fits) plus the `CHECK_OLD`/`FINAL`
fragments, and the MIN message-assembly fragment with the BIP-341 field order marked. This is what
makes the paper checkable without the repository (weakness **L**) and it is where the design's
craft actually lives.

### 5.3 What to move out to make room

* **§8's fee paragraph and the `EXIT_2`/cohort prose** → an appendix table; the body needs only
  "1,020 vB, 665 vB marginal, 158 vB/leaf in cohorts, ~1% of a 0.01 BTC balance at 10 sat/vB".
* **§4.3's `CLAIM`/voucher paragraph** → appendix. Vouchers are optional, absent from MIN, and
  complicate the security story (`seq`, replay, `SEQ_FINAL`, and rule (ii) of §6).
* **§6 (Channel leaves)** → halve it. Keep the rebindable-commitment idea, the three tree-layer rules
  and the deadline formula; move Fig. 3, the state-machine details and the force-close table to an
  appendix. §6 is a second paper compressed into two pages and is where the claims are least
  supported (no channel-leaf scripts appear in the tier tables or the check counts).
* **Table 1** can lose three rows (numerics, leaf-on-stack, sum limit) to a sentence, making room for
  the coverage column weakness **A** asks for.

---

## 6. Scores

**Overall recommendation: weak reject.** (A revision that fixes the tier-coverage claim, the
abstract/title overclaims, the Ark and sparse comparisons, and the varops figure, and that folds in
the Lean appendix, would be a weak accept or better from me; the underlying work deserves to be
published.)

**Reviewer confidence: 4/5.** I verified the construction against the specification, checked
sixteen of sixteen theorem-to-Lean-name mappings and about twenty numbers against
`spec/scripts/sizes.md` and `spec/fee-analysis.md`, and traced the MIN-tier script opcode by opcode.
I did not run the Lean build or the Go tests, and I am not an expert on current mempool cluster
policy.

**One-line justification:** A genuinely novel and carefully engineered construction with an
exceptional artefact, let down by a headline claim about three-tier coverage that the code does not
support, a title and abstract that overstate constant-size and "unconditional" payability, a
comparison model tilted toward the proposal, at least one wrong measured figure (sparse varops) and
a related-work section missing its nearest neighbour (CoinPool) and the one platform where these
opcodes already exist (Liquid/Elements).
