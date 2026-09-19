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
| Versioning | `paper/Makefile` writes `version.tex` from git before every build (hash, commit date, `git describe --dirty`, clean/dirty against `paper/`, `spec/`, `formal/`, `tools/` excluding the PDF itself); the title footnote and the running footer show it. `version.tex` is committed alongside `main.pdf`. |
| Bibliography | Added Canetti (UC), GUC, Badertscher et al. (composable ledger), Katz et al. (clock), Canetti (F_sig), Generalized Channels, PERUN state channels, Kiayias and Litos. |
| Length | Body 15 pages (References at the top of page 16); the size table moved to Appendix E and the MIN tier's grinding details to Appendix C to make room. |
