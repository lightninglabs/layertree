# Review: "LayerTree: A Shared Bitcoin UTXO as an Ideal Functionality, and Its Realisation with Covenants"

**Venue:** Financial Cryptography and Data Security (FC), full paper
**Reviewer profile:** UC security of off-chain protocols (channels, factories, Ark-style constructions), formal verification
**Version reviewed:** `paper/main.tex` at `cb81f99` and its appendices and `full-*.tex`; `paper/main.pdf` read with `pdftotext -layout`; `formal/LayerTree/*.lean`; `spec/layertree.md` sections 3, 7 and 10. Points settled in `paper/review.md` and `paper/review-response.md` are not repeated unless the fix is inadequate.

## Summary verdict

The tree-level mechanisation is genuine and well scoped: every Lean name the paper cites exists, the inline signatures match the development (`root_inj`, `fold_sound`, `fold_setSub`, `Steps.sum`, `ExitK.no_inflation`, `payable`, `Steps.sound`, `join_sound`, the cohort theorems and the encoding facts), and the split between "conserves unconditionally" and "payable under the real-tree invariant" is honest and useful. The composable layer does not yet carry the weight the abstract puts on it. Two problems block the UC claim as stated. First, the liveness bound Delta(N) does not follow from the hybrid: a single corrupt member can generate unboundedly many valid conflicting spends with `SPLIT` or a self-issued voucher, the bound uses a mempool constant the ledger model does not have, and N is under adversarial control. Second, the functionality's notion of an opaque slot is too coarse for the simulator to work: it cannot represent an honest member inside a partly withheld graft, nor a withheld graft whose leaves the adversary later reveals and exits. Several further gaps are each fixable: the FULL and CCV taproot-binding reduction is wrong in one case, the MIN tier's binding is incompatible with the F_sig idealisation it claims, vouchers carry no session identifier in FULL and MID, `DETACH_h` and `REWRITE_h` sit outside the functionality, the functionality's `CLAIM` disagrees with the spec and Lean on a drained source, the carve transitions let an owner escape eviction, and Theorem 6 is a theorem in name only. Recommendation: **weak reject**. The paper would be acceptable with a corrected functionality (opaque nodes at any height plus a reveal, a voucher interface, a detach interface), a liveness statement backed by a named ledger assumption, a fixed binding reduction, and Theorem 6 relabelled.

## Findings

### 1. The liveness bound Delta(N) is not implied by the hybrid model (blocking)

**Location.** `main.tex` section 3, paragraph "The liveness bound" (lines 351 to 361); Theorem 5 (lines 782 to 790); `appendix-uc.tex` paragraph "Liveness" (lines 127 to 137); `spec/layertree.md` 10.1 (the operator "cannot ... delay any other leaf") and 10.5.

**Claim.** "an honest exit competes for the tree output with at most N - 1 other transitions ... an adversary who front-runs maximally therefore delays the honest transaction by at most ceil(N/kappa) confirmations", hence Delta(N) = Delta_L (ceil(N/kappa) + 1).

**Why it is a problem.** The count "at most N - 1 other transitions" is false. Nothing bounds the number of valid spends an adversary can make. With an honest operator, one corrupt member with one leaf can `SPLIT` its whole balance from position p to an empty q (spec 7.5.2: the drained source becomes `E_0`), then from q back to p, indefinitely; a self-addressed voucher and `CLAIM` does the same, and `SPLIT` is in every tier, including MIN. With a corrupt operator, `JOIN` and `UPDATE` of its own leaves are unbounded too. Each such spend invalidates the honest exit, whose path must then be rebuilt. The Badertscher et al. ledger guarantees inclusion within Delta_L of a transaction that stays valid; it says nothing about a transaction invalidated by a conflicting spend that the adversary orders first, so in the stated hybrid an honest `EXIT` can be starved forever. The parameter kappa is a mempool-policy constant (descendant limit) that `G_ledger` does not model, and the appendix calls it the "ancestor limit" while the body calls it a descendant limit. Finally, N is the current membership, which a corrupt operator raises toward 2^D by grafting, so a bound in N is not a parameter fixed at the functionality's creation. G2, the HTLC budget of section 7 and Theorem 6 all inherit this gap.

**What would resolve it.** Pick one and state it in the theorem: (a) add a named ledger assumption (for example, "of two conflicting transactions the one paying the higher absolute fee and feerate is included, and honest parties out-bid", or a fee-aware ledger), state Delta as a function of that and of 2^D rather than N, and add it to the assumption ledger; or (b) weaken `F_LT` so that the adversary may delay `EXIT` and `EVICT` without bound, and restate G2 as "no other party can prevent an exit except by outbidding it for every block", which is the honest content; or (c) change the predicates (for example, constrain the claim position and the claim leaf so a carve cannot be undone in the next block) and prove a bound. Whichever is chosen, reconcile spec 10.1's "cannot ... delay any other leaf".

### 2. Opaque slots are too coarse for the simulator; the paper's own honest-member check produces states the functionality cannot express (blocking)

**Location.** Figure 1 (`main.tex` lines 324 to 334, state and `JOIN`, caption "never exited"); "What the functionality promises" (lines 338 to 349, "an honest member is never opaque"); proof sketch of Theorem 5 (lines 809 to 811); `appendix-uc.tex` "Ungrounded grafts" (lines 88 to 94) and `H_2` (lines 103 to 108).

**Claim.** `F_LT` slots are "empty, a leaf, or opaque(s): a subtree of sum s never shown"; `JOIN` sets "T[p] := u ... or opaque(sum u) if A withholds it"; opaque subtrees "can be swept or replaced but never exited".

**Why it is a problem.** Three concrete runs break the simulation.
(a) A corrupt operator grafts a cohort containing one honest member and withholds the rest. The honest member verifies its own path inside the graft (section 4.4) and funds. The simulator knows that one leaf and its path, which consists of sibling nodes of every height below h, but not a preimage of the whole node, so by the figure it must mark the whole slot opaque. The environment then tells the honest member to exit. In the real world the exit succeeds (a valid fold is all the predicate needs); in the ideal world `F_LT` rejects `EXIT` on an opaque slot. The environment distinguishes.
(b) A corrupt operator grafts a subtree it knows and withholds it from the simulator (which runs `A` as a black box and cannot extract it), then later exits one of its leaves with a valid path. The figure says opaque slots are never exited, but the transaction is on the global ledger in both worlds, so the simulator cannot keep `F_LT`'s tree in step with the chain.
(c) The abort event `Coll` is defined against "the honest tree", which the simulator does not know inside opaque regions, so it cannot detect or extract a collision there; the reduction "in the standard way" (appendix A, lines 34 to 37) needs an extractor that works from the simulator's view.
The Lean side has the matching gap: `payable` and `Steps.sound` are stated for a `Tree d`, while the honest member in (a) holds only a path into an ungrounded node. What it needs is a path-level statement: a member whose leaf folds to the current root can still fold after any valid step at another position, using the siblings that step's witness reveals.

**What would resolve it.** Let the functionality's state be a partial tree whose nodes at any height may be opaque, with known leaves allowed under opaque siblings; add an adversarial `REVEAL(p, u)` that refines an opaque node to a subtree whose root matches; make `EXIT` require only that the leaf is known. In Lean, prove a path-maintenance lemma (two paths that fold to the same root agree above their divergence point, and folding one step's new node updates the other path) so that payability for a member with a verified path does not depend on the real-tree invariant. Redefine `Coll` relative to the simulator's partial tree.

### 3. The creation proviso of Theorem 5 constrains the adversary (major)

**Location.** Theorem 5, `main.tex` lines 788 to 789 ("provided the tree is created with a real tree T_0 whose sum is the funded amount"); proof sketch lines 811 to 812.

**Claim.** "Creation is the base case the covenant cannot enforce, hence the proviso."

**Why it is a problem.** The theorem allows a static corrupt operator, and with a corrupt operator `CREATE` is an adversarial action. A UC statement must hold for every adversary; a hypothesis on what the adversary does at creation is not a precondition of the theorem but a restriction of the class of adversaries, which UC does not allow. The paper already has the right tool for this: `JOIN` with an ungrounded node becomes an opaque slot.

**What would resolve it.** Treat `CREATE` exactly like `JOIN`: an adversarial creation with an unknown `T_0` yields an opaque root (refined by `REVEAL`, finding 2), and honest members verify before funding. Drop the proviso.

### 4. The taproot-binding reduction is wrong for distinct internal keys, in FULL and in CCV (major)

**Location.** `appendix-lean.tex` "Binding to the Output" (lines 286 to 308); assumption ledger rows for `treeSpk_inj`, `CCVTweak.dataTweak_inj` and `tapTweak_inj` (lines 239 to 240); `main.tex` lines 766 to 771; `formal/LayerTree/Binding.lean` docstring of `CCVTweak`; `appendix-uc.tex` lines 155 to 158.

**Claim.** A collision of `TreeSpk` yields "distinct internal keys with Q = +-Q', again a linear relation in NUMS and G solvable for the discrete logarithm of NUMS"; for CCV "the map is built rather than assumed".

**Why it is a problem.** Write P_r = s(NUMS + h G) with s in {+1, -1}, h = H_state(r), and Q = P_r + t G with t = H_TapTweak(x(P_r) || m). For two inputs with the same sign s and distinct internal keys, Q = Q' gives s(h - h') G = (t' - t) G: NUMS cancels, and what remains is h + s t = h' + s t' mod n, a collision of the composed function (r, m) -> H_state(r) + s H_TapTweak(x(P_r) || m). That is neither a discrete logarithm of NUMS nor a collision of either hash. It is hard in the random-oracle model, which is how BIP-341's own binding argument goes, but the stated reduction to DL plus collision resistance does not exist. The CCV case is identical: `tapTweak_inj` is assumed jointly in the internal key and m, and for two NUMS-derived keys the same cancellation occurs. "Built rather than assumed" is therefore a two-line composition of two assumed injectivities, one of which carries the whole taproot argument.

**What would resolve it.** State the assumption as what it is: binding of the taproot commitment in the random-oracle model (cite a proof of taproot binding, or prove the composed-function collision bound in the ROM), keep the DL-of-NUMS reduction for the opposite-sign cases, and correct the two ledger rows and the sentence in `main.tex`. Tone down "built rather than assumed" to "decomposed into two stage assumptions".

### 5. The MIN tier's binding argument cannot be made inside the F_sig hybrid the theorem uses (major)

**Location.** `appendix-uc.tex` hybrid world (lines 28 to 31: "every CHECKSIG and CHECKSIGFROMSTACK in the scripts is a call to its verification interface") and per-tier remarks (lines 143 to 150); `main.tex` section 5, "MIN" (lines 604 to 631).

**Claim.** In MIN, `CHECK_OLD` and `FINAL` are enforced through the constructive signature check; `H_2` "also aborts on a collision in those hashes".

**Why it is a problem.** MIN's binding rests on the concrete Schnorr verification equation for public key G and nonce G: s G = (1 + e) G has the unique solution s = e + 1, so verification succeeds only if the real message equals the constructed one. Under `F_sig`, verification for a key with no honest registered signer (G has none; everyone knows its discrete log) is decided by the adversary, so an idealised `CHECKSIG` under G binds nothing and the MIN covenant collapses. The per-tier remark adds a hash-collision abort but leaves the `F_sig` idealisation in place, which removes exactly the algebra the tier relies on.

**What would resolve it.** Exempt the generator-key check from `F_sig`: model that one `CHECKSIG` with real BIP-340 verification, and state a lemma: if `CHECKSIG(G_x || s, G_x)` accepts on the real transaction and s = e(msg_c) + 1 with msg_c the script-constructed message, then the real BIP-341 message equals msg_c, except with probability bounded by collisions in TapSighash and the challenge hash. Cite it in `H_2` for MIN.

### 6. Vouchers carry no session identifier in FULL and MID, so instances of F_LT are not independent (major)

**Location.** `appendix-uc.tex` lines 159 to 162 ("cross-tree replay is excluded as m excludes it"); Figure 1 `CLAIM`; spec 6.2 ("Two tree outputs with the same m follow identical rules and differ only in state"), 10.3 ("A voucher commits to m, so it cannot be replayed in another tree") and 7.10 (vouchers reissued under `m_h`).

**Claim.** Binding `m` excludes cross-tree replay; the CCV `tree_id` excludes it "as m excludes it".

**Why it is a problem.** `m` identifies a rule set, not a tree: two trees by the same operator with the same depth, profile and script set have the same `m`, and every cohort detached from one parent at height h shares `m_h`. A voucher signs `H_voucher(m || src || claim)`. Uniqueness of `(owner_key, nonce)` is required only within a tree (spec 5.2), owner keys are reused across trees in practice, and in the dense profile the creator chooses the nonce. An environment that has one honest owner hold the same 116-byte leaf in two instances and issue one voucher lets the adversary redeem it in both; in the ideal world only one instance received a `CLAIM`. Under `F_sig` the signed message must contain the session identifier, and it does not. The paper's own composition uses several instances (`DETACH_h` "continues as two instances", channel leaves across trees), so this matters for the theorem as stated. Separately, `F_LT` has no interface by which an honest owner issues a voucher at all: `CLAIM` refers to "a voucher ... signed by the owner" that the functionality never produced or recorded.

**What would resolve it.** Bind a per-instance identifier in FULL and MID vouchers as CCV already does (the creation outpoint, spec 4.6's `tree_id` derivation), or make the honest-party protocol forbid identical source leaves across all trees that share `m` and state that rule in the theorem. Add `VOUCH(p, l_c)` (and the hash-locked form) to `F_LT`, recording outstanding vouchers per instance, with `CLAIM` consuming them.

### 7. DETACH_h and REWRITE_h are outside the functionality, and DETACH changes members' rules without their consent (major)

**Location.** `appendix-uc.tex` "The detach" (lines 164 to 170) and simulator step 3 (lines 67 to 70); `main.tex` lines 527 to 530 and Theorem 5 ("for each tier ... any D and profile"); spec 7.9, 7.10 and 10.1.

**Claim.** "A tree whose taptree carries it is covered up to the detach; afterwards ... the simulation continues as two instances of F_LT." A `REWRITE_h` is "one call per changed position (EXIT, JOIN, UPDATE) taking effect together".

**Why it is a problem.** For DETACH: a UC functionality cannot split into two instances mid-execution unless it is defined to; the members' calls addressed to the parent's session identifier have nowhere to go, so Theorem 5 is simply not established for any FULL tree whose taptree carries `DETACH_h`. The detach is operator-only (spec 7.10 rule 4) and moves the cohort under `m_h`, a different rule set. The reference `m_h` (`EXIT_1`, `EXIT_2`, `JOIN_0`, `JOINK_2`, `UPDATE`, `CLAIM`) carries non-exact `EXIT_1`, so detaching a cohort of channel leaves from an exact-payout tree silently breaks composition condition (i) of section 7, contrary to spec 7.10's "channel leaves ... are unaffected". DETACH also voids every outstanding voucher in the cohort (they bind `m`), which is an operator power over other members that the trust table in spec 10.1 ("cannot move ... any other leaf") does not list. Lean's `detach_sound` deliberately leaves `m_h` out of the step, so none of this is in the proved perimeter. For REWRITE: `F_LT` has no atomic mixed batch (only `EXIT_K`), and REWRITE's authorisation is not the composite of the interfaces it is mapped to: spec 7.9 rule 3 lets a leaf's amount rise without the owner's signature, which `UPDATE` (owner and operator jointly) does not allow, and a "JOIN of a published leaf" inside REWRITE is not the functionality's `JOIN` call.

**What would resolve it.** Either exclude `DETACH_h` and `REWRITE_h` from Theorem 5's scope explicitly (and say so in the abstract's interface list), or add `DETACH(p, h)` to `F_LT`, defined to spawn a child instance with session identifier derived from the parent and with parameters fixed by `m_h`, plus a creation-time requirement that `m_h` preserve `exact` and the other parameters channel leaves depend on; and add `REWRITE(p, h, u)` with rule 3's per-position authorisation. Add DETACH and its voucher effect to the trust table.

### 8. The functionality's CLAIM disagrees with the spec and the Lean model on a drained source (major)

**Location.** Figure 1, `CLAIM` (`main.tex` line 330); lines 756 to 759 ("the claim position need only be empty after the source step, which is harmless"); `formal/LayerTree/Transitions.lean` `claimedSource` and `claim_sound`; spec 7.5 rule 2.

**Claim.** `F_LT` sets `T[p] := l` "with amount a - l_c.a and seq + 1" and requires `T[q]` empty afterwards.

**Why it is a problem.** In the spec and in Lean, a source drained to zero becomes `E_0`; in the figure it becomes a zero-amount leaf. The two trees have different roots, so after a full-balance `CLAIM` or `SPLIT` the simulator cannot keep `F_LT`'s tree equal to the real one, which `H_3` needs. The figure also forbids q = p after draining (the slot holds a leaf), while the real predicate accepts it.

**What would resolve it.** Change the figure to "set T[p] := empty if l_c.a = a, else l with amount a - l_c.a and seq + 1", matching `claimedSource`.

### 9. The carve transitions let an owner escape eviction and block cohort sweeps, which G3 and the trust model do not say (major)

**Location.** Figure 1 `CLAIM` (no constraint on `l_c`); G3 (`main.tex` lines 341 to 342); "What the theorem leaves out" (lines 824 to 827, "members who want a hard guarantee buy it with a future lease height"); the comparison table in Appendix E (`tab:compare`), row "Evict one leaf: 1 tx after lease"; `tools/layertree_scripts.py` `_carve_body` (the claim leaf is checked for length only); `full-graft.tex` "one leaf with a NUMS evictor ... blocks the sweep of its subtree".

**Claim.** The evictor can remove a leaf after its lease (G3); the operator sweeps expired cohorts cheaply; `UPDATE` needs the operator's signature, so lease fields do not change unilaterally.

**Why it is a problem.** `SPLIT` (owner signature only) and `CLAIM` with a self-signed voucher accept any 116-byte claim leaf. An owner facing eviction moves its whole balance into a fresh leaf with `evictor_key = NUMS` or a far-future `evict_after`, possibly in its own drained position; the operator's lease is then unenforceable. Worse, a member can carve a one-satoshi leaf with a NUMS evictor into an empty slot inside any aligned cohort and so prevent `EVICT_SUBTREE_h` on that cohort for good, forcing the operator back to single evictions at about 1,020 vB each instead of 158 to 203. G3 holds per leaf but not per balance, and the paper's description of eviction as an operator capability overstates it in any tree whose taptree carries a carve.

**What would resolve it.** Either constrain the claim leaf in the predicate (its `evictor_key` equal to the source's and its `evict_after` no later), which is a few bytes of `SUBSTR`/`EQUALVERIFY`, or state the escape explicitly in G3, the trust table (spec 10.1) and the sweep discussion, and recommend omitting carves from trees that rely on eviction.

### 10. Who produces honest transactions in the ideal world, and with whose fee input, is left inconsistent (major)

**Location.** `appendix-uc.tex` introduction (lines 6 to 9: "the ideal functionality itself has access to the global ledger and posts the transactions that move coins") against "Functionality events" (lines 81 to 86: "S constructs the corresponding real transaction ... and submits it"); section 4.4 (`main.tex` line 541, honest exits carry "a fee input"); Table 2 (exact payouts in MID, MIN and CCV).

**Claim.** "F_LT's payouts are the ledger outputs of that transaction, so the two worlds agree on the ledger."

**Why it is a problem.** The two descriptions are different proof strategies. If the simulator builds the honest exit, it needs the honest party's fee input, which is a coin outside the tree on a global ledger whose key the simulator does not hold; in the exact-payout tiers there is no other way to pay the fee. If `F_LT` posts the transaction, the functionality must be protocol-aware (as in Generalized Channels) and must take the fee input as an argument. `H_3`'s "identical transaction by transaction" also needs the real and simulated exits to agree on fee input, change and feerate, which `EXIT(p, v)` does not determine.

**What would resolve it.** Commit to the protocol-aware functionality of Generalized Channels: `EXIT(p, v, fee)` where `fee` names a ledger coin and change the caller controls, `F_LT` constructs and posts the transaction, and the simulator only schedules. Remove the contradicting paragraph.

### 11. Payout destinations are an effect, not authorisation, and are outside the proof while the sketch attributes them to Theorem 3 (major)

**Location.** Proof sketch of Theorem 5 (`main.tex` lines 803 to 805: "Theorem 3 that the amounts the functionality pays are the transaction's outputs"); `appendix-uc.tex` `H_3` (lines 116 to 118); `appendix-lean.tex` "What Is Not Proved" (lines 330 to 331: "the transaction structure beyond amounts are authorisation-side facts"); `Transitions.lean` `ExitBlock` (no exit key).

**Claim.** Conservation gives that the payouts in both worlds agree.

**Why it is a problem.** `Steps.sum` and `ExitK.no_inflation` are statements about sums. That output k pays `P2TR(l_k.exit_key)`, and that an `EVICT` pays the leaf's exit key and not the evictor, is the safety content of G2 and G3, and it is a property of the effect, not of who may act. The Lean `ExitBlock` has no exit key at all (the `Payout` structure in `Cohort.lean` has one, but only the cohort theorems use it), so this is checked by test only. Classifying it as "authorisation-side" hides it from the "proved versus tested" line.

**What would resolve it.** Add the payout destination to `ExitBlock` and state `ExitK` with outputs as `(key, amount)` pairs equal to `(leaf.exitKey, payout)` in order, as `Rewrite` already does via `Payout`; or list destination binding explicitly among the facts established by execution only.

### 12. Theorem 6 is stated as a theorem but is explicitly unproved, and its budget instantiation contradicts the liveness example (major)

**Location.** Theorem 6 (`main.tex` lines 887 to 892, "Composition, sketch"); lines 893 to 897 ("are not proved"); `appendix-uc.tex` lines 186 to 190 ("leave the full channel-level proof ... to future work"); section 7 budget (lines 863 to 868, G_exit = 72); section 3 (line 360, 10,000 leaves need about 400 blocks).

**Claim.** The channel-leaf protocol realises `F_chan` with closing bound Delta(N) + 3 + csv_delay.

**Why it is a problem.** A numbered theorem whose proof is deferred to future work, and whose central step (the HTLC deadline argument under Delta(N)) is described as exercised in a simulator and "not proved", would be rejected as a theorem by any UC reviewer. Its numbers also disagree: G_exit = 72 with Delta_L = 1 corresponds to roughly 72 times 25, about 1,800 members, while section 3's example of 10,000 channel leaves needs about 400 blocks and so blows the 220-block budget. Finding 1 makes Delta(N) itself unsupported.

**What would resolve it.** Relabel it "Conjecture" or "Proposition (informal)", list the proof obligations (the three conditions, the deadline argument, the rebinding of pre-signed states across tree transitions), and state the maximum N per tree that the 220-block budget allows at a stated Delta_L.

### 13. The short version runs over the page limit, and its body carries a sketch of a sketch (major)

**Location.** `main.pdf`, page 16 (sections 10 and 11 precede "References" on that page); `review-response.md` ("Body 15 pages (References at the top of page 16)"); `main.tex` lines 792 to 815 and `appendix-uc.tex` `H_3`.

**Claim.** The body fits FC's 15 LNCS pages; the body proof sketch plus Appendix A make the argument complete.

**Why it is a problem.** Page 16 of the short version carries the Discussion and Conclusion before the references, so the body is over the limit, a desk-reject risk. On substance, the body's sketch defers the hybrids to Appendix A, but Appendix A's `H_3` is itself one paragraph that asserts the state equality for "every accepted spend" by citing `Step.sound`. A reviewer who reads only the body (FC reviewers are not obliged to read appendices) sees no stated simulation invariant at all.

**What would resolve it.** Cut about two-thirds of a page from the body. State in the body, as a numbered claim, the invariant the simulator maintains ("after each ledger event, `F_LT`'s partial tree has the committed root and agrees with every honest party's leaf and path"), and prove it by case on the predicate in Appendix A rather than in one paragraph.

### 14. The restricted functionality and the assumption ledger are underspecified (minor)

**Location.** `main.tex` lines 775 to 790 (`F_LT|_tau`, "for each tier tau and any D and profile"); Table 2; `appendix-lean.tex` assumption ledger (lines 226 to 252); `Hash.lean` `HashModel`.

**Claim.** `F_LT|_tau` is the functionality "restricted to the interfaces tau realises ... with exact forced in MID, MIN and CCV"; the ledger lists "every hypothesis outside Lean's logic".

**Why it is a problem.** Restriction by interface is not enough: MIN is dense-only and realises only `EXIT_1` and `SPLIT` (no `JOIN`, `UPDATE`, `CLAIM` or `SWEEP`, and no terminal exit); MID caps a tree at 2^31 satoshis and its sweep at 54 occupied positions; the sparse profile cannot graft; and only the `h` and `K` values compiled into `m` exist. Without these, `F_LT|_tau` accepts calls the real protocol cannot serve, and "any D and profile" overclaims for MIN. The ledger omits hypotheses the theorem uses: that the bytecode implements `Pred_tau` (the theorem parameterises the ledger by the predicate, which quietly assumes compiler correctness), that the opcodes are deployed with the drafted semantics, the ledger fee assumption that finding 1 needs, the ROM for taproot binding (finding 4), and TapSighash collision resistance for MIN (mentioned in prose only). `hLeaf_inj` and `hNode_inj` are quantified over all leaves and all `Nat` sums, while `serializeLeaf_inj` and `serializeNode_inj` hold only for well-formed leaves and sums below 2^64; the bridge (every sum on a verified path is at most the input amount, and the 41-byte size check bounds sibling sums) is true but not stated.

**What would resolve it.** Define `F_LT|_tau` by profile, heights, batch sizes, amount cap and per-interface limits. Add ledger rows for compiler correctness, opcode semantics, the fee assumption, the ROM and TapSighash collision resistance, and a sentence on the bounded-sum bridge from the axioms to the encodings.

### 15. Theorem 4's statement is stronger than the cited Lean theorem, and H_3 cites a lemma the body never states (minor)

**Location.** Theorem 4 (`main.tex` lines 737 to 744: "namely the initial tree with each step's subtree replaced") and its `leansig` block; `appendix-uc.tex` line 113 ("Theorem 4 (`Step.sound`)").

**Claim.** The final root is "the initial tree with each step's subtree replaced".

**Why it is a problem.** `Steps.sound` concludes only `exists t' : Tree d, t'.root = r'`. The "namely" clause is true by the proof but is not in the statement, and `H_3` needs exactly that clause for multi-step transitions (`EXIT_K`, `CLAIM`, the sweep). `H_3` cites `Step.sound`, the single-step lemma, as Theorem 4, which is `Steps.sound`.

**What would resolve it.** Strengthen `Steps.sound` to return the tree explicitly (as a fold of `setSub` over the steps' positions), or state `Step.sound` as its own lemma in the body and cite it by its number.

### 16. Small citation and wording points (nit)

* `main.tex` line 881: condition (ii) cites Lemma 1 for "0x7FFFFFFF ... whose successor does not fit in four bytes" under `CScriptNum`, but Lemma 1 states only the negative fact (`scriptNum_neg_max31_succ`). The positive fact is `scriptNum_two_pow_31_length`, which is in the axiom audit; add it to Lemma 1's statement and citation list.
* `main.tex` line 139: "whole cohorts are added or swept in one constant-shape transaction". A sweep publishes all 2^h leaves and pays one output per leaf, so its size grows with the cohort; say "one transaction per cohort".
* `appendix-uc.tex` line 130 says "the ancestor limit"; `main.tex` line 353 says "unconfirmed descendants". Use one.
* `appendix-lean.tex` lines 9 to 12: the axiom audit's dependence on `Classical.choice` is attributed to theorems "that case on a `Bool` or on `Steps`"; the file's own header says all three standard axioms are expected for each. Report what `lake build` prints rather than a rule.
