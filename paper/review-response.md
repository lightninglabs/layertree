# Response to the internal review

`review.md` is a simulated FC programme-committee review of the first draft
(commit `e648971`). This file records what the revision changed for each
item, so the two can be read together.

| Item | Change |
|---|---|
| A. "Every transition in three tiers" | Contribution 2, the opening of section 5 and Table 1 now state coverage per tier: FULL all, MID all but the cohort sweep, MIN the dense single-leaf exit only. Table 1 gained rows for transitions realised, executable checks and the owner-payout rule. Section 5.3 claims an upper bound and says explicitly that no lower bound is proved and that the largest scripts are untested in MIN. |
| B. Theorems vs goals, invariant base case | Section 7 gained the paragraph "Establishing and maintaining the invariant" (base case at creation, step by Theorem 4, what an ungrounded graft does). G1 and G2 are reworded; the goals section states that G3 to G5 are by construction and outside the verified perimeter. The abstract says conservation is unconditional and payability holds under the real-tree invariant. |
| C. MIN tier conditions | Section 5.3 states that the generator-key signature authorises nothing and rests on collision resistance of the sighash and challenge hashes (outside the Lean model), that s = e + 1 is unique mod n with a re-grind when e exceeds n minus 1, that grinding uses the fee input's sequence within the range that neither imposes a BIP-68 lock nor disables BIP-125 signalling, that fee bumping is by a child, and lists what the script guarantees. Appendix B gives the message layout field by field. |
| D. Comparison model | The abstract says "under a simple model" and "about 60% smaller". Section 8 has a dedicated paragraph naming the model, correcting the break-even to D of about 3, adding the radix-4 figure and the amortisation argument (under mass exit the transaction tree can be cheaper than the batched exit), and noting that latency and the opcode premium are not priced. Table 2 marks the column as a model, restricts it to dense rows and says why it does not apply to sparse rows. |
| E. Sparse numbers at N = 6 | Table 2 sparse rows now give the witness formula 326 + 41 log2 N and the vB at N = 2^16 (about 1,800 and 2,890). Section 8 says 1.8 times; section 4.1 says 1.8 to 2.7 times. The N = 6 figure survives only in the fee appendix, labelled. |
| F. Varops fractions | Corrected to 5.6 to 7.7% dense and 2.5 to 4.7% sparse, falling with depth; the spec's sections 10.10 and 11 were fixed to match. The 0xC0 tiers are noted as falling under the sigop budget. |
| G. Descendant bound and pinning | Section 7 states the bound as today's default policy, notes cluster mempool, applies it to all transitions, and describes the pinning attack and mitigations. "Per block position" is gone. |
| H. HTLC budget, channel claims | Section 6 gives the formula with G_exit = 72 and notes G_exit grows with tree size. "No script data need be retained" is qualified (context and latest signature are still needed). The paper says why REBIND does not commit the input amount. Appendix C compares lifetime footprints (about 1,680 vs about 280 vB). |
| I. Title and abstract | Title is now "Single-Transaction Exit and Eviction". The abstract says the size grows with depth, gives 158 to 203 vB per leaf with cohort sizes, and drops "unconditional payability". Section 5.3 gives 70% (script) and 43% (transaction) separately and uses consistent witness-unit deltas (260 and 1,744). |
| J. Related work | Added CoinPool, covenant Ark, SuperScalar, Elements/Liquid, Simplicity, OP_VAULT (BIP-345), OP_CAT (BIP-347), BIP-125 and cluster mempool; removed uncited entries. Liquid is discussed as a deployment target for the MID tier in sections 2, 5.2, 9 and 10. |
| K. Evaluation gaps | Section 8 gives JOIN_2 and JOIN_0 witness sizes and the funding-input cost of onboarding; Table 2's caption states the five-leaf taptree assumption and the sensitivity (8 vB per doubling of the script set). Sparse rows are at realistic N. A fee-rate distribution and CPU measurements are not added and remain future work. |
| L. Self-containment | Appendix B lists the 88-byte LEVEL macro, CHECK_OLD and FINAL, the PADZ gadget and the MIN message layout, and carries the step pseudocode figure. |
| M. Smaller gaps | TreeSPK injectivity is reduced to the discrete logarithm of NUMS and hash collisions in Appendix A (with lift_x in the section 4.2 formula); all hashes are stated to be tagged; the input-0-only consequence, reorganisations and the EXIT_K coordination point are stated. |
| N. Presentation | Body is 15 pages plus references and appendices. The fold direction and the meaning of the direction bit are defined in section 4.1; le64/le32, S_0, csv_delay and E_D are defined before use; MID and MIN points on Figure 4 are labelled; an anonymity switch (`\anontrue`) is in the preamble. |

Not adopted: implementing further MIN-tier transitions (stated as open work instead), and the empirical fee-rate distribution.

## The functionality-first restructure (issue #4)

The second revision reorders the paper around an ideal functionality and
a UC theorem; it changes no measured number. Section numbers below are
the new ones.

| Topic | Change |
|---|---|
| Presentation order | Section 3 is now the ideal functionality F_LT[D, profile, pk_op, exact, Delta] (Figure 1): state, the interfaces CREATE, JOIN, EXIT, EVICT, UPDATE, CLAIM, SWEEP and READ with caller, preconditions and effects, what the adversary may influence (scheduling within Delta(N), refusing joins, grafting opaque subtrees), and G1 to G5 restated as readings of the figure. Section 4 is the abstract protocol: tree, tree output, the step predicate and one covenant predicate per interface (Table 1), and the behaviour of honest parties. Section 5 realises the predicates per tier and points at the CCV tier and a native Merkle-sum opcode as further realisations. |
| Opaque subtrees | The real-tree invariant's failure case is now a state of the functionality (an opaque slot whose value is frozen, never stolen) rather than a caveat on a theorem; the honest member's pre-funding check is the party behaviour that keeps an honest member out of that state. |
| Delta(N) | The contention bound (25-descendant package limit) is stated in section 3 as the liveness parameter of the functionality, Delta(N) = Delta_L (ceil(N / kappa) + 1), and reused by the UC theorem and the HTLC budget. Pinning is stated as outside the ledger model. |
| Security | Section 6.1 keeps the tree-level theorems (binding, conservation, payability, real-tree invariant) and shows the Lean statement of each inline in a `leansig` block, so a reader can go from the lemma to `formal/LayerTree/*.lean` without the appendix. Section 6.2 states Theorem 5: for each tier, Pi_tau UC-realises F_LT restricted to the interfaces the tier compiles, in the hybrid model with G_ledger[Pred_tau], G_clock and F_sig, in the idealised hash model, with the simulator sketched in the body and the hybrids in Appendix A. The paragraph "What the theorem leaves out" names the bytecode gap, pinning and cheap eviction. |
| Channel leaves | Section 7 states the channel protocol in the F_LT-hybrid model, the three tree-layer rules as composition preconditions, and Theorem 6 as a sketch following Generalized Channels; the HTLC deadline argument under Delta(N) is left open. |
| Appendices | A is the UC proof (hybrid world, simulator, hybrids, per-tier remarks, composition for channel leaves); B Lean; C script listings; D channel scripts and costs; E measurements (Table 3, moved from the body), vouchers and fee tables; F complete structured listings. |
| Versioning | `paper/Makefile` writes `version.tex` from git before every build (hash, commit date, `git describe --dirty`, clean/dirty against `paper/`, `spec/`, `formal/`, `tools/` excluding the PDF itself); the author block shows "Draft (commit <hash>)" and the running footer the describe string. `version.tex` is committed alongside `main.pdf`. |
| Bibliography | Added Canetti (UC), GUC, Badertscher et al. (composable ledger), Katz et al. (clock), Canetti (F_sig), Generalized Channels, PERUN state channels, Kiayias and Litos. |
| Length | Body 15 pages (References at the top of page 16); the size table moved to Appendix E and the MIN tier's grinding details to Appendix C to make room. |

## Round two: the programme-committee reviews (2026-10-10)

Three reviews of the version stamped `6d2c114` (sources at `cb81f99`):
`reviews/crypto.md` (cryptographer, UC argument; weak reject),
`reviews/protocol.md` (Bitcoin protocol engineer; weak reject) and
`reviews/systems.md` (measurements and writing; weak accept,
conditional). Each finding is listed under its reviewer's number with
what changed, or why it did not, or the item it was handed off to.
Section numbers are those of the revised short version (`main.pdf`);
the full version (`main-full.pdf`) has the same body sections plus the
five full-only sections. "Handed off" names an item outside `paper/`
(spec, tools, formal, design) that the paper now describes as open or
as a spec 0.10.0 rule.

**Dated note on the tables above.** The round-one table describes the
draft at `e648971` and the restructure table the version at `6d2c114`.
Several of their statements are no longer true of the current text:
the title is no longer "Single-Transaction Exit and Eviction"; MID now
compiles the cohort sweep; the short version's References no longer
sit "at the top of page 16"; the N = 6 sparse figure is labelled
wherever it appears and is no longer confined to the fee appendix; the
control block is for an eight-leaf, not a five-leaf, taptree; and
Delta(N) is replaced (below). They are kept as a record, not as a
description of the current paper.

### The liveness bound (crypto 1, protocol 1 and 2, systems 19)

All three reviewers are right: the count "at most N - 1 competing
transitions" is false, because `SPLIT`, a self-issued voucher, `UPDATE`
and `JOIN` let one corrupt member or the operator produce competing
spends without removing a leaf, and kappa is mempool policy that the
ledger model does not contain. We did not try to prove a bound. The
revision narrows the claim to what the model supports:

* Section 3, "The liveness bound", now states an explicit contention
  assumption [C] with two named parameters that the paper does not
  derive: kappa, the number of spends of one tree output that can
  confirm in one block (a policy quantity: 25 under Bitcoin Core's
  ancestor and descendant count limits, cited to Bitcoin Core policy
  rather than BIP-125; a per-cluster limit under cluster mempool; as
  low as 1 when a participant attaches descendants to its payout), and
  beta, the number of conflicting spends the adversary gets confirmed
  ahead of a pending honest transition (bounded only by the adversary's
  fee budget against the honest bid). Under [C] an honest transition
  with q honest transitions queued ahead of it takes effect within
  Delta(q) = Delta_L (ceil((beta + q) / kappa) + 1). Nothing depends
  on N, which a corrupt operator controls.
* G2 now reads: no other party can prevent an exit except by outbidding
  it; the time bound holds under [C]. Without a bound on beta,
  unilateral exit is a fee auction, and the section says so.
* Theorem 5 is stated under assumption [C] with that Delta. Appendix A,
  "Liveness", is rewritten: the simulator schedules an honest call
  within Delta(q) because, under [C], the real transaction confirms by
  then; nothing else is claimed.
* One term, "chain limit", replaces "ancestor limit" and "descendant
  limit" (crypto 16, systems 19).
* The 10,000-leaf example is now a cooperative-case drain time with
  Delta_L = 1 and kappa = 25 stated (systems 19), and section 10 says
  what cluster mempool changes.
* Handed off (spec): spec 10.1's "cannot ... delay any other leaf" and
  10.5's 25-descendant throughput statement must be restated the same
  way. Protocol 1's option (c), a relative lock on transitions that
  remove no value so that only removals can chain, is recorded in
  section 10 as a design option and handed off to `design/` (it is a
  rule change in every tier).

### Cryptographer (`reviews/crypto.md`)

1. **Delta(N) not implied by the hybrid.** Fixed as above (section 3,
   Theorem 5, Appendix A "Liveness").
2. **Opaque slots too coarse.** Fixed in the functionality. Figure 1's
   state is now a *partial* tree: a node at any height may be opaque (a
   hash and a sum), and an opaque node may have known nodes below it
   (the path of a leaf someone has shown). A new adversarial interface
   `REVEAL(p, n_L, n_R)` refines an opaque node into two children whose
   parent it is; `EXIT` and `EVICT` require only that the leaf at p is
   known. Run (a): the simulator reveals the honest member's path from
   the member's own state, so its exit is accepted in both worlds. Run
   (b): when a valid witness proves a leaf inside an opaque region, the
   simulator first calls `REVEAL` along the witness path, then the
   interface. Run (c): `Coll` is redefined against the simulator's
   partial tree (a witness whose fold contradicts a node the simulator
   knows), and the simulator then holds two preimages of one digest, so
   extraction works from its view. The path-level fact the honest member
   needs (a step at another position leaves a verified path valid once
   its siblings are updated from the step's witness) is stated as
   Lemma 3 and proved on paper in Appendix A from the injectivity of
   H_node. It is **not** mechanised; handed off to `formal/` as a
   path-maintenance lemma. The caption no longer says opaque slots are
   "never exited"; value under an opaque node that is never revealed is
   frozen.
3. **Creation proviso.** Fixed: `CREATE` is handled like `JOIN`. An
   adversarial creation whose tree the simulator cannot obtain yields an
   opaque root, refined by `REVEAL`; honest members verify before
   funding (section 4.4). The proviso is gone from Theorem 5.
4. **Taproot binding, same-sign case.** Fixed. Appendix B, "Binding to
   the Output", now gives the cancellation the reviewer derived: for two
   NUMS-derived internal keys of the same sign the NUMS term cancels,
   and a collision is a collision of the composed map
   (r, m) -> H_state(r) + s H_TapTweak(x(P_r) || m), which we assume hard
   in the random-oracle model, as BIP-341's own binding argument does.
   The discrete-logarithm reduction is kept only for the opposite-sign
   cases. The ledger rows for `treeSpk_inj` and the CCV pair now say
   "ROM", and the CCV sentence says "decomposed into two stage
   assumptions", not "built rather than assumed". Section 6.1 says the
   same in one sentence. Handed off (formal): the docstring of
   `CCVTweak` in `formal/LayerTree/Binding.lean`.
5. **MIN binding inside F_sig.** Fixed. Appendix A's hybrid world now
   exempts the generator-key `CHECKSIG` from `F_sig`: it is real BIP-340
   verification. Its binding (if the check accepts with s = e(msg_c) + 1
   then the real BIP-341 message equals msg_c, except for a collision in
   TapSighash or the challenge hash) is an assumption, [MIN] in the new
   assumptions table of section 5, cited by H_2; it is not argued inside
   the signature hybrid.
6. **Vouchers carry no session identifier; no voucher interface.**
   Fixed. Figure 1 has a new interface `VOUCH(p, l_c)` from the owner of
   the leaf at p; `F_LT` records outstanding vouchers per instance and
   `CLAIM` consumes one. The voucher message binds a per-lineage
   `tree_id` in every tier, which is the spec 0.10.0 rule (a tree and
   the cohorts detached from it share it; separate creations do not),
   so cross-instance replay is excluded in FULL and MID as in CCV.
   Section 4.3 and Appendix E describe the rule without sizes; the `CLAIM`
   sizes it changes carry a `TODO(0.10.0 sizes)` comment in the source.
7. **DETACH_h and REWRITE_h outside the functionality.** We chose to
   exclude them. Theorem 5 is stated for trees whose taptree carries
   neither, and section 6.2 says so; the abstract's interface list never
   named them. Both remain covered by their tree-level Lean theorems
   (`rewrite_sound`, `detach_sound`), and nothing more is claimed.
   Appendix A's "The detach" paragraph and the `REWRITE_h` mapping in
   simulator step 3, which claimed coverage, are removed. The rule that
   `m_h` is compiled with the parent's creation options (so a detached
   channel leaf keeps exact payouts) is a spec 0.10.0 rule and is
   described in the full version's batching section; with the
   per-lineage `tree_id` a detach no longer voids outstanding vouchers.
   Handed off (spec): `DETACH_h` in the trust table of spec 10.1.
8. **CLAIM on a drained source.** Fixed in Figure 1: the source slot
   becomes empty when the claim takes its whole amount, otherwise the
   reduced leaf with seq + 1, matching `claimedSource` in Lean and spec
   7.5 rule 2.
9. **Carves escape eviction.** The spec 0.10.0 carve constraint (the
   claim leaf's `evictor_key` equals the source's and its `evict_after`
   is no later, in every tier) closes it. Figure 1's `CLAIM` carries the
   constraint as a precondition, G3 therefore holds per balance, and
   section 4.3 names the rule; the full version's cohort discussion no
   longer suggests a member can block a sweep with a carved dust leaf.
   Sizes for `SPLIT`, `CLAIM` and `CLAIM^h` are marked
   `TODO(0.10.0 sizes)`.
10. **Who builds honest transactions.** Fixed: the functionality is
    protocol-aware, as in Generalized Channels. `EXIT(p, v, f)` and
    `EVICT(p, f)` take a fee coin f that the caller controls; `F_LT`
    constructs the transaction of Figure 2 and submits it; the simulator
    only schedules. This is stated once, in the opening of Appendix A;
    the contradicting "Functionality events" paragraph is replaced.
11. **Payout destinations.** Fixed in the text: the proof sketch no
    longer attributes destinations to Theorem 3. Section 6.1 and
    Appendix B, "What Is Not Proved", list destination binding (output k
    pays P2TR(l_k.exit_key); `EVICT` pays the exit key, not the evictor)
    among the facts established by execution only. Handed off (formal):
    the exit key in `ExitBlock`.
12. **Theorem 6.** Relabelled "Conjecture 1", stated under [C], with its
    proof obligations listed (the three conditions, the deadline
    argument under [C], rebinding of pre-signed states across tree
    transitions). The budget is instantiated consistently: with
    Delta_L = 1, beta = 0 and kappa = 25, G_exit = 72 lets about 1,775
    channel leaves close in one window; section 7 states the sizing rule
    in the form beta + q <= 71 kappa (spec C.9.5's leaves / kappa <
    cltv_expiry_delta - csv_delay - 3 - G_sweep at beta = 0) and says
    larger hubs shard; the 10,000-leaf example of section 3 is a
    cooperative drain time (400 blocks), outside that budget.
13. **Page limit; no invariant in the body.** The short body now ends
    on page 15 (see "Length"). Section 6.2 states the simulation
    invariant as Claim 1 ("after each ledger event, F_LT's partial tree
    has the committed root and agrees with every honest party's leaf and
    path"), and Appendix A proves it by case on the predicate rather than
    in one paragraph.
14. **Restricted functionality and assumption ledger.** Fixed. Section
    6.2 defines F_LT|tau by profile, the heights and batch sizes compiled
    into m, the 2^31-sat cap of MID and MIN, MID's 54-position sweep
    bound, MIN's interfaces (dense `EXIT_1` and `SPLIT` only, no terminal
    exit) and the sparse profile's lack of grafting; "any D and profile"
    is gone. The assumption ledger (Appendix B) gained rows for compiler
    correctness, opcode semantics (the section 5 table), the contention
    assumption [C], the ROM for taproot binding and TapSighash collision
    resistance for MIN, and a sentence on the bounded-sum bridge from the
    hash axioms to the encodings.
15. **Theorem 4 stronger than Lean; H_3 cites Step.sound.** Fixed.
    `Step.sound` is now Lemma 2 in the body (a step is a subtree
    replacement); Theorem 4 states only that the final root is the root
    of a tree of the same depth, as `Steps.sound` does; H_3 cites Lemma 2
    for each step.
16. **Nits.** Lemma 1 cites `scriptNum_two_pow_31_length` for the
    positive fact; the abstract says "one transaction per cohort"; one
    term for the chain limit; Appendix B reports the axiom audit as the
    build prints it, without the stated rule.

### Protocol engineer (`reviews/protocol.md`)

1. **Delta(N) false.** Fixed as above. The fee-auction reading (option
   a) is what the revised G2 states; option (c) is handed off.
2. **kappa: wrong number, citation and owner.** Fixed in sections 3 and
   10: cited to Bitcoin Core's policy limits, not BIP-125; cluster
   mempool stated; descendants attached to payouts or change named as a
   pinning vector next to the low-feerate ancestor; TRUC (BIP-431) noted
   as unusable for transitions, since it caps an unconfirmed chain at
   two; throughput stated as a cooperative-case number. Handed off
   (spec): the same in spec 10.5 and C.9.5.
3. **"Only proposals already made" overstated.** Fixed. A compact
   assumptions table (in section 5 of the full version; Table 4 in
   Appendix C of the short one, cited from section 5) mirrors spec 4.1's
   [A-1] to [A-6] plus [MIN] and [C]: which proposal each tier's opcodes come from, the leaf version
   each is defined for against the one the tier assumes, the opcode
   number collisions (0xbd for `OP_TX` and `OP_EC_POINT_NEGATE`, 0xbb for
   CCV and `OP_EC_POINT_ADD`) and the simulator's placeholders, and the
   BIP-443 commit the CCV tier pins (`24e96e87`). The abstract and the
   introduction now say the opcodes are proposed ones, some assumed in a
   leaf version their proposal does not define, and section 5 says which
   tier needs what: MIN is the tier closest to the proposals as written
   (BIP-347's `OP_CAT` plus BIP-449's `OP_TWEAKADD`, both defined for
   tapleaf 0xC0, confirmed in a later pass), MID and CCV in 0xC0 need `OP_TX`
   where its draft does not define it, CCV in 0xC2 needs BIP-443 there,
   and FULL needs two drafts whose opcode numbers collide. The
   EC-ops draft's authorship is disclosed in section 1 (omitted under
   `\anontrue`). [A-1]'s dependency (FULL compares 8-byte `OP_TX`
   amounts numerically, which BIP-441's numerics must accept) is in the
   table. `optx` is cited as a draft on a personal fork, which it is;
   BIP-449 is cited at `bip-0449.md` in the bips repository.
4. **Prior art; false novelty claim.** Fixed. Related work cites
   `OP_TAPLEAF_UPDATE_VERIFY` (Towns, bitcoin-dev, 2021), CoinPool's
   `OP_MERKLESUB` withdrawal, `OP_EVICT` (ZmnSCPxj, bitcoin-dev, 2022),
   and Poelstra's "CAT and Schnorr Tricks I" (2021) for the s = e + 1
   generator-key signature; the novelty sentence is replaced by "the MIN
   tier applies it", with what is new in the use. The introduction's
   "every deployed or proposed approach" is narrowed to the
   transaction-tree family and says TLUV and `OP_MERKLESUB` target
   one-transaction withdrawal. Table 5's CoinPool column no longer says
   "O(log N) txs, CTV or APO". The StarkWare vault prototype is not
   cited: we could not pin a reference precisely enough.
5. **Self-funded cohort joins need a signing round.** Fixed. The
   abstract and G4 say the covenant needs only the operator's
   signature; sections 4.4 and 8 say that a self-funded graft needs
   every funder to sign one transaction after the cohort is fixed (an
   abort-and-retry round, as in an Ark round or a coinjoin), and that an
   operator-funded graft avoids it by fronting the liquidity. Table 5's
   "interactive signing" row distinguishes the two.
6. **vB figures omit witness length prefixes.** Stated, not re-measured.
   Section 8's model paragraph says the figures count script, witness
   elements and control block but exclude the witness item count and the
   per-item length prefixes, about 10 to 14 vB on a dense D = 16 exit,
   applied the same way to every row including the transaction-tree
   baseline. Every caption uses 946 WU. Handed off (tools, spec):
   measure serialised weight with the Go builder, and spec 11's "131 WU
   per level", which the data put at 129.
7. **220-block budget and the hub.** Fixed in section 7: the sizing rule
   is in the body with its maximum (about 1,775 channel leaves for
   G_exit = 72 at Delta_L = 1, beta = 0, kappa = 25); the D = 16
   force-close costs are costs at that occupancy; against an operator
   counterparty the budget holds only if the member can outbid the
   operator's competing spends, which is [C]; MID's seven-HTLC limit and
   the 2^31-sat cap are in section 7. The abstract says the hub is sized
   by exit throughput.
8. **Exits cannot be pre-signed or delegated.** Stated in section 4.4:
   the owner's signature commits to the tree outpoint, so the owner key
   must be online for every rebuild and fee bump. The prevout-independent
   CSFS authorisation the reviewer sketches is recorded in section 10 as
   a design option and handed off to `design/`.
9. **CLAIM^h is a cheque, not an HTLC.** Fixed in Appendix E: "a
   hash-locked voucher, a cheque", with the race stated (the issuer can
   void it with a conflicting `EXIT` or `SPLIT` until the redemption
   confirms, and the redeemer bears that risk). Handed off (spec): drop
   "atomic" from spec 9.6.1 and 9.6.2.
10. **MIN grinding details; 80-byte witness items.** Fixed in Appendix C:
    the grinding range (a fee-input nSequence that sets no BIP-68 lock
    and keeps replacement signalling), re-grinding and re-signing on
    every replacement, CPFP as the bump path, and the 80-byte
    standardness limit on `0xC0` witness items, which one P2TR change
    plus a P2A anchor fits and two P2TR change outputs do not. Section 8
    says the simulator models consensus limits, not standardness. Handed
    off (tools, spec): split `extra_outs` per output.
11. **Comparison fairness.** Fixed. Table 5 has a deployed-Ark column
    (pre-signed MuSig2 round trees, no soft fork) next to covenant Ark,
    and a "member position expiry" row (LayerTree: a per-leaf lease whose
    renewal needs the operator; eviction pays the member at the
    operator's fee). "No expiry" is now "no expiry of the shared output"
    in G5, the conclusion and the table. The transaction-tree model's
    parameters are derived from a stated transaction shape and shown
    across round sizes and radix 2 and 4 (Appendix E; systems 4). A
    measurement on a deployed Ark implementation is not added.
12. **Smaller inconsistencies.** "Two trees cannot be spent atomically"
    is qualified (FULL, MID and MIN read input 0; CCV's tree input may
    sit at any index). The BIP-443 commit is cited in the assumptions
    table, with the remark that CCV's conservation rests on its `OP_TX`
    equalities, so a BIP-443 change can only make honest spends fail.
    Handed off (spec): spec 11's sweep rows and break-even, 10.5's "per
    block position", 10.10's "no element exceeds 40 bytes", and the
    EC-ops operand-order wording in 4.1.

### Systems (`reviews/systems.md`)

1. **Body on page 16.** Fixed; see "Length".
2. **Transaction model only in an appendix.** Fixed. Section 8 opens
   with one paragraph stating the model: script, witness elements and a
   129-byte control block as measured, plus a 946 WU skeleton (tree
   input, P2WPKH fee input, tree output, one P2TR payout, P2WPKH change,
   version, lock time and counts) and 172 WU per further payout,
   vB = ceil(WU/4), witness length prefixes and item count excluded.
   Table 3 and the fee appendix refer to it. Joins, claims, splits and
   updates are no longer charged for a payout they lack (172 WU less):
   `JOIN_2` 872, `UPDATE` 1,030, `CLAIM` 1,599, `CLAIM^h` 1,609 and
   `SPLIT` 1,577 vB (the last three marked `TODO(0.10.0 sizes)`). The fee
   table prices every row as the tabulated vB times the rate.
3. **Serialisation overhead.** As protocol 6: stated with its size;
   re-measurement handed off.
4. **Ark baseline in opposite directions, at one round size.** Fixed.
   Both versions use one sensitivity table (Table 7, Appendix E, in
   both; section 8 and the full version's section 11 cite it): radix 2
   and 4, isolated and amortised exit, round sizes 2^8, 2^12 and 2^16,
   every cell derived
   from a stated shape (a level is one key-path P2TR input and r P2TR
   outputs, 68 + 43r vB, rounded to 150 vB at radix 2 as before; the
   claim is a plain P2TR spend, 111 vB; anchors and their children
   omitted, which favours the tree). The unsourced radix-4 figure
   (1,870 vB) is replaced by 2,031 vB from that shape. The full
   version's "beats Ark by a factor of 2.5" is replaced by the range
   over round sizes. Handed off (spec): spec 11's "near D = 5".
5. **Lightning baseline unsourced.** Fixed for one named channel type,
   simple taproot channels (bolts PR #995): commitment 240 vB (MuSig2
   key-path input, two balance outputs, two anchors), to_local sweep
   138 vB, anchor child 152 vB priced as the channel leaf's are,
   cooperative close 154 vB, each derived from its stated shape. Both
   constructions are now priced with their fee-bumping children. The
   lifetime table and the channel-leaf comparison are recomputed (force
   close 530 vB against the channel leaf's 1,681 vB; lifetime about 680
   against about 1,680). Handed off (design): the "about 13 times" of
   `design/cost-comparison.md`.
6. **Native-opcode floor at another population.** Fixed: the row is
   labelled as measured on the six-leaf tree with a bitmap-compressed
   proof, and the text gives the estimate at 2^16 members (about
   530 vB) instead of calling 388 vB a floor.
7. **Entry and moving value not like for like.** Fixed: the `SPLIT`
   sentence is removed (`SPLIT` is an on-chain transition); moving value
   is compared with Lightning and Ark; the lifetime table has both the
   operator-funded and the member-funded dense entry, with the
   assumption of each row stated.
8. **REWRITE_h double counts a payout.** Checked against `sizes.md`,
   spec 11 and `tools/fee_analysis.py`: the 946 WU skeleton already
   includes one payout, so K exits add 172 (K - 1) WU. The reviewer is
   right. The figures are now 359, 195 and 158 vB per leaf for
   `REWRITE_2`, `_4` and `_6`, and the rotation case is 144 vB per leaf
   (no payout); "within one vbyte of the sweep" now reads "equal to".
   Handed off (spec, design, tools): spec 11's REWRITE table,
   `design/batching.md`, `tools/gen_cost_figures.py`.
9. **Sparse figures mix populations.** Fixed. The witness is now
   244 + 41k bytes for k non-empty siblings (k = 2 on the measured
   six-leaf tree, hence 326 B; k is about log2 N), giving about 900 B,
   1,780 vB at D = 32 and 2,870 vB at D = 64 for N = 2^16, so 1.7 to
   2.8 times dense in both versions; every N = 6 figure is labelled.
10. **Control block against the shapes priced.** Fixed: section 8 says
    the figures use the eight-leaf reference set and that a deployment
    carrying the sweeps, rewrites, detach and variants needs 16 to 32
    leaves, +8 to +16 vB on every spend. Handed off (spec):
    `spec/fee-analysis.md`'s "5-6 leaves".
11. **The 206-leaf point is at D = 20.** Fixed: labelled D = 20 in the
    caption and the text; the detach point is an annotation, not a point
    on the shared axis.
12. **Batching decomposition does not add up.** Fixed: derived from the
    measured `EXIT_1` and `EXIT_2`: about 355 vB fixed, 32 vB per level,
    about 148 vB per leaf, which sum to 1,020; the "about 100 vB in every
    shape" sentence now quotes the measured 147 to 158 vB.
13. **Marginal and average used interchangeably.** Fixed: "665 vB for a
    second exit in the same transaction", with the rounding stated (its
    marginal weight is rounded up on its own, so 1,020 + 665 is one more
    than `EXIT_2`'s 1,684), and 842 only where an average is meant.
14. **"Tier matters more than depth".** Replaced by "one tier step
    costs as much as 10 (MID) to 14 (MIN) levels of depth".
15. **Figures hard to read.** Figure 3: the right panel is replaced by
    the batch-shapes table of section 8, and the remaining panel labels
    MID, MIN and CCV beside their markers, without legend entries, puts
    the legend beside the plot and draws the model line without
    markers. Figure 5 (full): patterned fills, 8 pt bars,
    labels clear of the bars. Figure 6 (full): every point labelled, the
    bare-spend annotation moved.
16. **Reproducibility.** Fixed in part. Section 8 has an "Artefact"
    paragraph naming the commands that regenerate every number (the
    suites and their check counts, `gen_listings.py`, `fee_analysis.py`,
    `test_scripts.py --rewrite`, `tools/experiments/radix4.py`, the Go
    tests, `lake build`) and the revision stamp. `radix4.py` runs at HEAD
    (fixed in `727afa3`; 55/55 checks, re-run for this revision). The
    counts in `CLAUDE.md`/`AGENTS.md` were already corrected. Not done:
    a `numbers.tex` of macros generated from `sizes.md` (handed off,
    tools), and spec 11 (handed off, spec).
17. **Related work misses the closest lines.** Fixed as protocol 4, plus
    one sentence on Plasma forced exits and one on proofs of liabilities
    (Ji and Chalkias, CCS 2021; Chalkias, Chatzigiannis and Ji, FC 2022
    workshops), whose Merkle-sum trees had the sum-inflation flaw that
    hashing each child's sum avoids.
18. **Generator-key novelty claim.** Fixed as protocol 4; the ECDSA
    analogue (`OP_PUSH_TX` on Bitcoin Cash) is mentioned without a
    citation, as we could not pin a primary source.
19. **Liveness and hub parameters.** Fixed as above: policy cited, one
    term, Delta_L stated, the N behind G_exit = 72 stated, the abstract
    qualified.
20. **Acronyms.** WU, HTLC, CSFS, CTV, APO, GSR, TLV, G_sweep, csv_delay
    and cltv_expiry_delta are expanded or defined on first use; Table 2's
    "shape" row is explained in its caption; "the three options above"
    names them; the sigop sentence has its noun; "(design notes)" and the
    full version's "spec 5.4", "spec 11" and "spec 13.4" cite the
    repository with a file path.
21. **Fourteen numbers in prose.** Fixed: a table in section 8 (Table 3
    of the short version) gives the batching, join and sweep figures in vB per member at the transaction
    level, on one model. The member funding input is a P2TR key-path
    input (58 vB), stated as such next to the skeleton's P2WPKH fee
    input.
22. **Most of the submission is appendix.** Appendix F (the 31 pages of
    structured listings) is dropped from the short submission and kept
    in the full version, with the artefact cited. Appendix F's
    "intermediate data point" is now mentioned in section 5 (the
    minimal-inventory exit, 2,378 B of script).
23. **Costs a systems reader expects.** Validation time and a feerate
    distribution are not added (still future work, as in round one).
    Section 8 now states the off-chain cost: a member follows every
    spend of the tree output, about 1 kB of witness per transition, and
    the operator stores the whole tree.
24. **Nits.** The measured-sizes table's column is "witness (WU)"; the
    sparse varops range is 3.6 to 4.7% over the tabulated depths (in
    Appendix E of the short version, section 8 of the full); Table 5's opcode row
    lists each LayerTree tier; "hostage to proposals", "honest weak spot"
    and "The voucher is insurance" are rewritten literally; this file
    carries the dated note above.

**Number table (systems).** Rows 1 to 4: systems 9. Row 5: the D = 256
sparse exit is "about 17 times the dense script and 9 times the
transaction". Row 6: radix 4 is "about 2% larger". Rows 7 and 8:
systems 8. Row 9: systems 11. Rows 10 and 11: systems 12. Rows 12 and
13: systems 13. Row 14: systems 2. Row 15: 946 everywhere. Row 16:
systems 21. Row 17: the paper says eight leaves; `spec/fee-analysis.md`
handed off. Row 18: the paper's 41 bytes of witness per level is
consistent with 129 WU; spec 11 handed off. Rows 19 to 21: spec 11
handed off. Row 22: systems 5. Row 23: systems 6. Row 24: systems 7.
Row 25: fixed in `727afa3`. Row 26: systems 24. Row 27: this file.
Row 28: already fixed in `CLAUDE.md`. Row 29: `design/batching.md`
handed off.

### Length

Short version (`main.pdf`, 35 pages): the body ends at the foot of
page 15 and References start at the top of page 16, checked with
`pdftotext -layout` page by page. Full version (`main-full.pdf`, 73
pages): References start on page 29, so the body is under 29 pages.

What moved or was cut in the short version to make room for the new
material (the partial-tree functionality, assumption [C], Lemmas 2 and
3, Claim 1, the model paragraph, the batch table and the artefact
paragraph): the inline Lean signature blocks of section 6.1 (now shown
in the full version only, where they were previously absent; Appendix B
has the statements in both); the proof sketch of Theorem 1 (full version
only); the assumptions table (Appendix C); the fees and varops paragraph
(Appendix E); Figure 3's right panel (replaced by the batch table); the
long comparison paragraph of section 8 (shortened; the sensitivity table
is Appendix E's Table 7); Appendix F (full version only). The rest is
tighter prose throughout: the contributions list, background, sections
4, 5 and 7, related work, discussion and conclusion. In the full
version the Lean development moved from a body section to Appendix B,
as in the short one.

### Handed off, by owner

* **spec**: 10.1 trust table ("cannot delay", `DETACH_h` and its voucher
  effect); 10.5 and C.9.5 (liveness as assumption [C], the policy
  citation, cluster mempool, cooperative-case throughput); 11 (witness
  prefixes, 131 against 129 WU, sweep rows 165/116, "near D = 5",
  "about twice", "about twelve times", the REWRITE per-leaf column);
  9.6.1 and 9.6.2 ("atomic"); 10.10 (40-byte elements); 4.1 (EC-ops
  operand order, pin the draft revision); `fee-analysis.md` (leaf
  count).
* **tools**: serialised-weight measurement; `extra_outs` per output in
  MIN; a `numbers.tex` generator; the REWRITE figures of
  `gen_cost_figures.py`.
* **formal**: path-maintenance lemma (crypto 2); the exit key in
  `ExitBlock` (crypto 11); the `CCVTweak` docstring (crypto 4).
* **design**: a relative lock on transitions that remove no value
  (protocol 1c); prevout-independent exit authorisation for delegation
  (protocol 8); the Lightning figures of `cost-comparison.md` and the
  REWRITE figures of `batching.md` (systems 5, 8).

## Round three: developer review (2026-10-10)

`reviews/developer.md` reads the short version stamped `dce2c57`
(sources at `e16ce55`) as a wallet, node and tower implementer would,
against spec 0.12.1, and asks for a major revision: fifteen findings and
a closing list of eight things a developer would want added. Each
finding is listed under the reviewer's number with what changed.
Section, table and appendix numbers are those of the revised short
version (`main.pdf`); where the full version (`main-full.pdf`) shares
the text or had the same error, it changed too. The new Appendix C,
"Implementer's Notes", is short-version only and carries most of the
additions the body had no room for.

1. **The operator voids vouchers and tower authorisations by a
   one-satoshi top-up.** Resolved by a rule change, not by text. The
   owner took option (a): from spec 0.13.0, `H_voucher` and `H_exit`
   bind the source leaf without its `amount`, so an amount-only increase
   under `REWRITE_h` or `REWRITE_h^x` voids no voucher and no `EXIT_K^t`
   authorisation. Single use still comes from `seq`, which every
   redemption advances, and the covenant's sum check still stops a
   voucher drawing more than the source holds. The paper is written to
   that rule: section 5.1 defines the message over `tree_id`, the source
   leaf without its amount and the claim leaf, Figure 2 and its caption
   show it, "Single use" says why a top-up voids nothing, and the credit
   leaf of 5.3 now says that voiding needs a *bound* field to change and
   that the operator's one solo change touches none, so the one-way
   property holds as stated. Section 4.4 says the tower authorisation is
   a bearer right "until a field other than the amount changes". In the
   full version the functionality (Figure 1: `CLAIM` now requires `T[p]`
   to equal the vouched leaf in every field but the amount), the
   predicate prose, the honest-party paragraph, the discussion and the
   voucher appendix say the same. The script sizes of `CLAIM`, `CLAIM^h`,
   `CLAIM^x` and `EXIT_K^t` are left at their 0.12 values until the spec
   change is measured (see "Handed off").
2. **Lightning receive costs something on-chain, and who holds the
   preimage.** Section 5.5 says the flow is FULL only (`CLAIM^x`), that
   the operator draws the preimage so the payer's receipt proves the
   operator was paid (the full version adds that a recipient who wants
   its own receipt pre-shares preimages, which bounds offline receipt),
   and that a voucher draws only what the credit leaf holds: pre-funded
   capital the operator recovers only with the recipient's consent, or
   top-ups of about 122 vB a credit leaf in a cohort `REWRITE_h^x`,
   which after finding 1 void nothing. The abstract now reads "into a
   funded credit leaf (FULL tier), cost nothing on-chain per payment"
   and drops "never expire". Table 12's pay-off-chain cell names the
   operator for Lightning receive. Appendix C.3 gives the flow as a
   seven-step sequence with each step's failure mode, the preimage
   choice included.
3. **Unilateral recourse needs a fee coin.** Section 5.5 says the
   `CLAIM^x` fallback and the exact exit that follows are paid from a
   confirmed coin of the recipient's, 2,655 vB or about 26,550 sat at
   10 sat/vB, below which the fallback costs more than it recovers.
   Section 6, "What a member does", requires a confirmed fee coin for
   every unilateral path; section 9 requires it of both channel-leaf
   parties, with the HTLC-proportional reserve of spec C.5.5. Appendix
   C.4 says which operations need an external input (every carve, the
   exact exit and every channel-leaf transaction; only FULL's
   fee-from-payout exit does not) and gives each path's fee at 2, 10 and
   50 sat/vB (Table 15), with spec 11.2's 10% rule. The suggested
   fee-from-claim `CLAIM` variant is a rule change and is handed off.
4. **Recompute `m`; tree creation.** Section 3.2 now says that
   `TreeSPK` hides the scripts, so a member, a voucher holder and a tower
   recompute `m` from the published parameters and reject any taptree
   with a leaf outside the expected set (spec 9.1). Section 6's custody
   sentence is qualified by that check. Appendix C.1, "Creating and
   Recognising a Tree", lists the parameters, gives the recommended
   `tree_id` derivation from the creation transaction's input-0 outpoint
   (and why a chosen constant or the tree's own outpoint will not do),
   says the input must be fixed before compiling, and covers the seed
   leaf (spec 6.2, 6.5).
5. **Channel-leaf deadline.** Section 9's formula is now spec C.4.4's,
   `G_exit + 1 + beta_chan + 1 + csv_delay + 1 + G_sweep`, with one
   clause on what a stale update costs the counterparty (about 313 vB a
   block), which delta binds in each direction (the invoice's
   `min_final_cltv_expiry_delta` for a receiving leaf, the hub's delta on
   the leaf-facing hop for a paying one), and the fee reserve. The "40 to
   80" range is replaced by lnd's default of 80, which we checked in
   `chainreg/chainregistry.go` at v0.18.4-beta and cite; we could not
   check the other implementations' defaults against a source we can
   cite, so the reviewer's 34 to 144 range is not quoted.
6. **Vouchers against Ark out-of-round payments.** The opening of
   section 5 is rewritten: an Ark transfer is undone only if sender and
   server collude, a voucher by its issuer alone or by the source's
   evictor after the lease, until its redemption confirms; in exchange a
   redeemed voucher is a leaf whose eviction pays its holder on-chain,
   where an expired round forfeits to the operator, and the credit leaf
   removes the issuer's voiding for payments from the operator. After
   finding 1 the operator's top-up is no longer a voiding party. Spec
   10.3's sentence is outside `paper/` and is handed off.
7. **Lease renewal is not priced.** Section 4.5 gives both renewal paths
   and their costs (an `UPDATE` and a whole-balance `SPLIT`, 2,616 vB,
   or 148 vB a member in a cohort `REWRITE_6` that every renewing member
   signs, an absent one keeping the old lease). Table 7 gains a renewal
   row and its rewrite row is relabelled; Table 10's caption says the
   sweep applies only to expired leases aligned per cohort and that
   renewals are not included; Table 11's "leases are optional" now reads
   "a lease is the price of the cheap batch exit"; Table 8's Ark row says
   that rounds and refreshes are not priced (its 86 kvB contains none),
   and the LayerTree row that renewals are not; B.8 gives the renewal
   cost. Appendix C.6 gives the per-period cost (148 to 2,616 vB a
   member) and what a member sees when its lease passes. A per-period
   line for Ark at a stated VTXO lifetime is not added: the paper has no
   measured refresh cost to put in it.
8. **State, reorgs and messages.** New Appendix C. C.2 has the state
   table the review asks for (Table 14: member, voucher holder, tower,
   operator; what each stores, backs up and derives from each spend),
   the grafted member's subtree path as the one backup that matters
   (spec 10.9), how a non-member holder gets the source's path, the
   reorganisation rules (rollback by `(txid, r)`, rebuild against the
   surviving root, a reorged `CLAIM^h` returned to the issuer's
   discretion, waiting for confirmation depth before paying for a graft)
   and the TLV codecs in `msg/`. C.3 is the receive sequence, C.4 the fee
   reserves and break-even fees. On the per-operation card: we judge
   that section 4 serves, since it gives each operation's authoriser,
   what its witness proves and what the outputs must be; C's preamble
   adds the pointers it lacked (witness order in spec 8, the `txn/`
   builders and signers, and what a co-signer verifies in spec 9.2, 9.5
   and 9.6).
9. **Nonce discipline and source uniqueness.** One sentence each:
   section 4.4 says that rejoining a tree of the lineage with an owner
   key, nonce and `seq` held before revives every `EXIT^t` authorisation
   for that leaf, so a wallet draws a fresh nonce at every join (spec
   9.2); section 5.1 says that in the dense profile an issuer checks for
   a duplicate of its source leaf before signing, since one voucher
   would redeem against both (spec 10.3).
10. **The chain limit.** Section 6 says the figures use kappa = 25, the
    lowest limit relay peers may enforce (spec 10.5), and gives the
    drain at 64 (157 blocks for 10,000 leaves). The full version's
    liveness paragraph says the same. Appendix B.2 now says that
    uncoordinated exits chain only if each exiter rebuilds on the
    previous unconfirmed one, or a tower or the operator holding `EXIT^t`
    authorisations builds them in sequence, that otherwise they
    conflict, and that the worst case is set by beta; B.8's "worst case"
    wording is corrected to match.
11. **Labels and sums.** Section 9's force-close sentence compares
    1,681 vB with 684 vB for a simple taproot channel's open and force
    close together, saying that the leaf's exit creates the funding
    output. Table 10's batch cells are 161 and 219 (3 or 61 plus the
    158 vB sweep), matching the caption, and the lifetime figure's dense
    batch bar, drawn by `tools/gen_cost_figures.py`, was corrected to
    161 with it. Table 10's online column reads "owner" with a note that
    nobody is needed under `EXIT^t`, matching Table 11.
12. **Trust table.** Table 1 now says that anyone holding an `EXIT^t`
    authorisation can exit that leaf and that nobody else can trigger an
    owner's exit; that an owner can carve into any empty position, a
    later lease than a cohort's delaying its sweep (the owner's "cannot"
    cell is narrowed to changing another leaf); and that the operator
    cannot change the taptree, or *unilaterally* a lease or a detached
    cohort. Section 6's custody sentence names the evictor's signature
    after the lease (paying the leaf in full) beside the owner's and the
    operator's. The amount-only rewrite needs no mention after finding 1:
    it only adds value, which the sentence already covers.
13. **`P2TR(exit_key)`.** Section 3.1 defines `P2TR(k)` as `OP_1 <k>`,
    so `exit_key` is the payout's output key itself, and says a
    single-key wallet supplies its tweaked BIP-86 output key.
14. **Serialised premiums.** Table 2's last row gives model and
    serialised sizes for every tier (1,020 / 1,030, 1,355 / 1,398,
    1,473 / 1,518, 908 / 918), and section 10 gives both premiums: MID
    +33% on the model and +36% serialised, MIN +44% and +47%. The full
    version's MIN paragraph does the same.
15. **Nits.** Table 2's native-opcode figure now points at Appendix B.1
    (the discussion section in the full version). Figure 4's "PR #6" and
    "PR #7" labels come from `tools/gen_cost_figures.py`, outside
    `paper/`, so the caption now says what they name and the generator
    change is handed off. Section 9 cites BIP-431 for version-3
    transactions and a new entry, Bitcoin Core's `ephemeral_policy.h` at
    v31.1, for the ephemeral anchor, in both versions. Section 4's
    opening says payouts are exact except for FULL's fee-from-payout
    exit. Section 4.3's fragment now reads "It exists in FULL and MID,
    whose stack limit holds a full cohort only to h = 5." `JOIN_8`'s
    679 vB is called an estimate in 4.1, Table 7 (whose caption now says
    it is the measured `JOIN_0` at D = 8, as the full version's graft
    table already did) and Appendix B.3. The abstract no longer says
    "never expire". Section 6 says a member must be online to exit
    unless a tower holds its `EXIT^t` authorisation.

**The closing list.** (1) Per-operation card: section 4 plus the
pointers in Appendix C's preamble, as above. (2) Creating and
recognising a tree: section 3.2 and Appendix C.1. (3) State table:
Appendix C.2. (4) Fee reserve and break-even: Appendix C.4. (5) The
receive flow as a message sequence: Appendix C.3. (6) Channel leaves as
an implementer meets them: Appendix C.7 (a new channel type, nothing to
announce, reached through the counterparty, what its tower holds, the
splice as one `UPDATE^x` at 1,048 vB) with the `beta_chan` budget in
section 9; a byte comparison against a Lightning splice transaction is
not given, since the paper has no measured figure for one. (7) Lease
policy: Appendix C.6. (8) Mempool behaviour: Appendix C.5 (replacement
or a child from change or a pay-to-anchor output, why transitions cannot
be TRUC, rebuilding after a competing transition, and CPFP for a
multi-funder graft).

### Length

Short version (`main.pdf`, 33 pages): the body ends on page 15 and
References start at the top of page 16, checked with `pdftotext -layout`
page by page; no overfull boxes and no unresolved references. To pay for
the body additions, the short version now has its own, shorter forms of
the receive-flow and settlement paragraphs (the long forms remain in the
full version, and the detail is in Appendix C.3), a tighter "What Is
Proved", a shorter introduction sentence on the tiers, tighter `JOINK_K`,
`SPLIT`, cumulative-voucher, hash-lock and voucher-cost paragraphs, the
Liquid and Simplicity sentences of related work moved to the full
version (the Liquid prototype now sits in the future-work line), and a
one-sentence conclusion. Full version (`main-full.pdf`, 78 pages):
References start on page 30, one page later than before, from the
channel-budget, receive and voucher text it shares.

### Handed off, by owner

* **spec**: 0.13.0 (finding 1, in progress); 10.3's Ark sentence and
  9.6's informative paragraph (finding 6); 11.2's +33% and +44%, which
  could give the serialised premiums too (finding 14); C.4.4's "~40
  typical on the public network" (finding 5).
* **tools**: drop the PR numbers from the `exit-anatomy` labels
  (`gen_cost_figures.py`); new
  sizes for `CLAIM`, `CLAIM^h`, `CLAIM^x` and `EXIT_K^t` once 0.13.0
  lands, which move 1,617, 1,627, 1,635, 2,655 (and its fee row in
  Table 15), 1,046 and "107 bytes" in the paper.
* **design**: a fee-from-claim `CLAIM` variant for recipients with no
  fee coin (finding 3), a rule change in every voucher tier.
