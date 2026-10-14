# Status and hand-off

Last updated 2026-10-14 (spec 0.15.2, Appendix C 0.5.2, paper v0.1).

## Where things stand

| Area | State |
|---|---|
| Base spec `spec/layertree.md` | Complete for the design as scoped: tree format, two profiles (dense, sparse), taproot binding, transitions EXIT_K / EXIT_K^= / JOIN_h / JOINK_K / UPDATE / UPDATE^x / CLAIM / EVICT_SUBTREE_h / terminal, three opcode tiers, reference scripts, off-chain protocol, security, cost, comparison, extensions, test vectors. |
| Cohort transitions (0.9.0) | `CLAIM^x` and `CLAIM^hx` (7.5.3, the dedicated credit leaf of `design/receive.md`), `REWRITE_h` with its `^x` form (7.9, `design/batching.md` Shape 2 with the exit rule) and `DETACH_h` (7.10, Shape 3) are built in the FULL tier only: generator, tests, golden vectors, Go mirror, listings. Measured at `D = 16`: `REWRITE_6` 18,236 B of script, about 151 vB per changed leaf and 165 per exiting one (spec 0.15.1); `DETACH_8` 1,548 / 497 B, exits at 765 vB afterwards. Since 0.11.1 `REWRITE_h` and `REWRITE_h^x` also exist in MID (`REWRITE_4` 11,556 / 4,436 B on the mixed cohort; a full cohort fits the 1,000-element stack limit up to `h = 5`), since 0.12.0 an unchanged position publishes its leaf once (the one-byte marker of 7.9, 95 vB per unchanged position in FULL since 0.15.0, 92 before the amount-only element and 120 before the marker), and `DETACH_h` in CCV, both numerics (`DETACH_8` 973 / 433 B under `0xC2`, 1,628 / 470 under `0xC0`; `CCVTreeOptions` compiles `m_h` from the parent's set). Since 0.13.1 `CLAIM^x` and `CLAIM^hx` exist in MID (`CLAIM^x` 6,530 / 1,901 B at `D = 16`, 4 bytes over `CLAIM`) and in CCV in both numerics (3,497 / 1,690 under `0xC2`, 7 bytes over `CLAIM`; 6,160 / 1,837 under `0xC0`), and `DETACH_h` in MID (`DETACH_8` 2,174 / 534 B: `TREE_SPK_MIN` for output 1 and a `PADZ` sum; the witness shrinks with `h`, 86 elements at the peak, so no stack cap; `layertree_mid.TreeOptions` compiles `m_h`). Since 0.13.2 `REWRITE_h` and `REWRITE_h^x` exist in CCV in both numerics (spec 4.6, 8.9): FULL's machine under `0xC2` and MID's under `0xC0`, each with the exit payout as one `CHECK_OUTPUT|DEDUCT` call and the two bindings as in every CCV transition; `REWRITE_4` on the mixed cohort at `D = 16` measures 5,471 / 4,035 B under `0xC2` (FULL 5,784 / 4,099) and 11,260 / 4,372 under `0xC0` (MID 11,556 / 4,436), figures that include the 0.15.0 amount-only element; the `0xC0` form shares MID's stack bound (`h ≤ 5` at any occupancy, 965 elements at the peak of a full 32-position rewrite; `h = 6` rejected); `CCVTreeOptions` carries `rewrite_heights` and `rewrite_x`, as the Go `CCVTreeOptions` does. MIN: no (no `CLAIM`; the detach and the rewrite are not built). Lean: `rewrite_sound`, `rewrite_exit_conservation`, `detach_sound` and `detach_member_payable` in `Cohort.lean`. |
| Appendix C channel leaves | Complete, 0.5.0: rebindable OP_TX + CSFS commitments, LN-Symmetry state machine, HTLCs and routing, lifecycle, tier analysis, comparison, security; 0.4.0 adds the settlement dust floor `DUST_CHAN` (C.3.4, trimmed value to the anchor) and the `beta_chan` stale-update term of the C.4.4 budget with the fee-reserve and replacement rules of C.5.5 and C.9.6 (channel audit B1, B4); 0.5.0 binds `chan_id` to `tree_id` in place of `m` (C.2.2, B6, decision 24; zero bytes of script). All C.10 recommendations adopted by the base spec. Executable (C.12): `tools/layertree_chan.py` generates `UPD_F` / `REBIND_n` / `SETTLE_n`, and `tools/test_chan.py` (220 checks) runs the state machine on a chain model with BIP-65 / BIP-68, from a tree exit through contest, settlement and HTLC sweeps, in both tapleaf versions, plus the C.4.4 / 9.6.2 deadlines as block sequences. Go mirror `script/chan.go` byte-exact against the golden `chan` section; TLV messages in `msg/chan.go`. Measured: `SETTLE_n` is 79 B under 0xC2 (80 under 0xC0), HTLC sweeps 155 / 138 vB (the old table missed the 65-byte control block), the C.4.4 bound has two blocks of margin, and a MID channel carries at most seven HTLC outputs per state beside two balances, eight beside one (520-byte collation). |
| Pending-leaf receive (0.14.0) | The atomic Lightning receive of `design/pending-receive.md`, three rule changes and no new opcode. R1: `RECLAIM_KEY` (6.2) and `RECLAIM_1` (7.11), the operator removes an expired reclaimable leaf with no payout. R2: `CLAIM^m` and `CLAIM^hm` (7.5.4), a hash-locked voucher that raises the source's sibling to an absolute target, which must be owned by and exit to the source's exit key. R3: the reclaim form of `REWRITE_h` (7.9 rule 8), a batch settlement from a pending leaf into its sibling with the operator's signature alone. Obligations in 9.6.3. Built in FULL, MID and CCV (both numerics): generators, simulator tests, golden vectors, Go mirror and `txn` builders replayed through the simulator; MIN cannot (no CSFS, no `CLAIM`). Lean: `Merge`, `Reclaim`, rule 8 and `Receive.lean` and `Trace.lean` bring the audit to 72 theorems (`merge_sound`, `reclaim_sound`, `rewrite_transfer_sound`, `merge_no_overpay`, `Reachable.exit_value`). Design: `design/pending-receive.md`, `design/towers.md`, `design/interactivity.md` ("Receiving without a round"), `design/receive.md` ("Closing the settle gap"). The site's payments page and the paper (full-version receive section, implementation appendix step 8, Lean appendix) describe it. The numbers pass of 2026-10-13 brought the check counts, sizes and the scaling and tier tables up to date. A window settles a pair for 966, 624 or 547 vB at 4, 16 and 64 positions under CCV with the hypothetical Merkle-sum opcode (1,105 vB without R3), after the amount-only element and the CCV mode flag of decision 30. |
| Fee analysis | `spec/fee-analysis.md` and `tools/fee_analysis.py`, 1 to 250 sat/vB. |
| Python reference and simulator | 1,610 + 1,391 + 57 + 4,295 checks pass (FULL, MID, MIN, CCV), plus 220 for the channel leaves and 133 for the hypothetical opcode outside every tier. Every script uses only its tier's allowed opcode set. |
| Tower-delegable exit `EXIT_K^t` (0.12.1) | 7.2 rule 7, decision 26: the exact-payout exit whose owner branch checks an off-chain signature over `H_exit(tree_id \|\| body(leaf))` (the leaf without its amount since 0.13.0, decision 28) with `OP_CHECKSIGFROMSTACK`, so a tower builds and rebuilds the exit with the owner offline, an amount-only top-up of the leaf does not void it, and a cooperative exit is one message. FULL, MID and CCV (both numerics); MIN cannot (no CSFS). Measured `EXIT_1^t` at `D = 16`: FULL 2,207 B beside `EXIT_1` 2,101 and `EXIT_1^=` 2,097; MID 3,488 beside 3,367; CCV 1,826 beside 1,716 (`0xC0` 3,123 beside 3,002). `TreeOptions` / `CCVTreeOptions` and the Go `FullTreeOptions` / `CCVTreeOptions` carry it as `tower`; `txn.BuildExit` takes the authorisation in `ExitStep.Auth` (`SignExitAuth`), replayed through the simulator. The D4 golden root did not move (variants are excluded from the reference set). Lean: `ExitBlock.authorised` stays abstract, its doc comment names both authorisations. |
| Go implementation | `tree`, `script`, `txn`, `msg`; all 145 golden scripts byte-exact (since 0.13.2 the CCV `REWRITE_2` and `REWRITE_X_2` in both numerics; since 0.13.1 the MID `CLAIM^x`/`CLAIM^hx`, `DETACH_2` and `DETACH_2_HOST` and the CCV `CLAIM^x`/`CLAIM^hx` in both numerics, with `MidTreeOptions` as the MID counterpart of `FullTreeOptions`); BIP-341 sighash equality with the simulator. `txn` builds, signs and verifies every transition of every tier end to end against the tier's real taptree and tree output (`TREE_SPK(r, m)`, or `TREE_SPK_CCV` with the data-tweaked NUMS key under CCV): one builder per transition, written once against a `Tier` value read off the tree's option set (`txn.Options`, satisfied by `FullTreeOptions`, `MidTreeOptions`, the new `MinTreeOptions` and `CCVTreeOptions`), which fixes the leaf version, the numerics, the witness encoding (116-byte records and le64, or field elements and minimal numbers with `PADZ` pads), whether the stack ends in `r m` or the covenant binds the output with CCV, the MIN tier's ground nSequence and raw introspection pieces, and `SEQ_FINAL`. FULL: `EXIT_1` (owner, eviction, exact, tower, tower after an amount-only top-up), `EXIT_2`, the terminal exit, `JOIN_0`, `JOIN_2`, `JOINK_2`, `UPDATE`, `UPDATE^x`, the four `CLAIM` forms (partial, draining, after a top-up), `SPLIT`, `EVICT_SUBTREE_2/4`, `REWRITE_2` (mixed, every owner rotated, the mass exit, the operator's top-up), `REWRITE_2^x` and `DETACH_2` (which returns the child as a `TreeState` under `m_h`), 105 cases (with the pending-leaf receive of 0.14.0 and the amount-only top-ups and mode flags of 0.15); MID the same set at dense D = 4, 16 and sparse D = 31, 104 cases; MIN `EXIT_1` and `SPLIT`, 8; CCV the same set as MID, 104 under `0xC2` and 106 under `0xC0`; 427 in all, each pinned to the simulator's sighash (`txn/pins_test.go`) and run through `script_sim.Interp` by `tools/replay_txn_dump.py`, which CI executes. 156 negatives the builders refuse before signing, among them a 64-position `REWRITE_6` at D = 16 past the 1,000-element bound of 4.5 in MID and under CCV `0xC0`. `tree.Leaf.Body` is what `VoucherMsg`, `VoucherHMsg` and `ExitAuthMsg` bind (0.13.0). |
| Lean model | `formal/` (about 4,500 lines): sections 5 (including sparse positions), 7 (including `EVICT_SUBTREE_h` and the terminal branch), 10.2, the encodings, the cohort shapes `REWRITE_h` and `DETACH_h` of `design/batching.md` (`Cohort.lean`), the trace layer (`Trace.lean`), vouchers (`Voucher.lean`) and the pending-leaf receive (`Receive.lean`, merges and reclaims in `Cohort.lean`, rule 8); 72 audited theorems; axiom audit clean; no `sorry`. |
| P model | Design note `design/p-model.md` and GitHub issue #1. Not started. |
| Paper | `paper/`: functionality-first LNCS paper (ideal functionality, abstract protocol, four opcode tiers FULL/MID/MIN/CCV, UC theorem, channel composition), built in two versions from one source by an `\iffullversion` switch keyed on the job name. Revised for the second review round (`paper/reviews/{crypto,protocol,systems}.md`, answered item by item in `paper/review-response.md`): the liveness bound Delta(N) is replaced by an explicit contention assumption [C] (kappa, beta; Delta(q) = Delta_L(ceil((beta+q)/kappa)+1)); the functionality is a partial tree with opaque nodes at any height, `REVEAL`, `VOUCH`, creation as a join, a protocol-aware `EXIT(p, v, f)`; Lemma 2 (`Step.sound`), a paper-only path-maintenance Lemma 3 (Lean item handed off), Claim 1 (simulation invariant, proved by case in Appendix A); Theorem 5 excludes `REWRITE_h`/`DETACH_h`, uses the ROM for same-sign taproot binding and [MIN] for the generator-key check; Theorem 6 is Conjecture 1; a deployment-assumptions table mirrors spec 4.1's [A-1] to [A-6]; prior art (TLUV, `OP_MERKLESUB`, `OP_EVICT`, Poelstra's CAT/Schnorr tricks, Plasma, proofs of liabilities) added; one stated fee model with corrected derived figures (REWRITE 359/195/158, joins and carves without a phantom payout, sparse 244 + 41k). Spec 0.10.0 rules (`tree_id` in every tier, the carve constraint, `m_h` with the parent's options) are described without sizes; `TODO(0.10.0 sizes)` marks the `CLAIM`, `CLAIM^h` and `SPLIT` figures to update. `main.pdf` (FC submission) built from the 2026-10-13 sources is 40 pages with its appendices, References beginning on page 15 (the body, with the predicate boxes, the algorithms and the composition figure, ends there); `main-full.pdf` is 100 pages, References on page 45: the UC proof and the channel scripts lifted into the body with inline Lean signatures, the Lean development an appendix, plus the five full-only sections. The committed PDFs are rebuilt from the owner's terminal after the sources are final. Spec, tools, formal and design items the reviews raised are listed under "Handed off" in the response. |
| CCV tier (issue #3, part 1) | Complete: simulator `OP_CHECKCONTRACTVERIFY` per BIP-443 ([A-6], amount rules pinned to bips commit `24e96e87` and tested one by one), `tools/layertree_ccv.py` both profiles and both numerics (exact payouts; `UPDATE^x`, `SPLIT`, `EVICT_SUBTREE_h`, `CLAIM` and `CLAIM^h`, and since 0.13.1 `CLAIM^x` and `CLAIM^hx`, in both numerics, the `0xC0` sweep being MID's element-based one; vouchers bind a per-tree `tree_id` constant in place of `m`, 4.6 / 9.6, and `CLAIM` is the tier's only `OP_CHECKSIGFROMSTACK` user), `tools/test_ccv.py` 4,295 checks including two tree inputs in one transaction, Go mirror `script/ccv.go` byte-exact against the CCV and CCV0 golden keys, Lean `CCVTweak.binding` (a second `BindingModel`), spec 0.8.4 (4.3 inventory row, 4.5 CCV column, 4.6, 6.3 `TREE_SPK_CCV`, 10.4 note, 11 cost rows, 14 tests), F19. Measured dense D=16 EXIT_1: 1,716 / 838 B script / witness vs FULL's 2,101 / 902, no EC-ops dependency; 0xC0 dense EXIT_1 3,002 / 914. The `0xC2` sweep's leaf step passed the whole leaf to CCV as its key; the old test swept only empty positions, and real cohorts now exercise it in both numerics. Measured `CLAIM` dense D=16: 3,490 / 1,626 (`0xC2`), 6,156 / 1,773 (`0xC0`). Adopted in every tier by decision 18 (spec 0.10.0, open work item 8). |
| Hypothetical `OP_MERKLESUMUPDATE` (issue #3, part 2) | Measurement only, never a tier: `design/native-opcodes.md`, simulator `op_msu` behind `hypothetical=True` (canonical proofs: siblings leaf-first, explicitly supplied empty siblings and bits above the depth rejected), `tools/layertree_msu.py` (CCV + MSU, `EXIT_K`, `JOIN_0`), `tools/test_msu.py` 133 checks (the pending-leaf receive scripts among them) including a quarantine test (absent from every tier's allowed set, every tier generator and every golden script). Measured `EXIT_1` 252 B of script at every depth and profile. |

## Decision log

Decisions taken during the design, with the reason, so they are not
re-litigated by accident. Details are in `design/review.md` (F-numbers).

1. **Exit does not need the operator's voucher** (F1). The covenant
   enforces the root, so exits are unilateral; vouchers survive only as
   `CLAIM` for off-chain payments.
2. **Sums at every node** (F3, F6). Makes "the operator cannot steal" a
   theorem (`formal/`: `Steps.sum`, `fold_sound`) instead of a trust
   assumption on the operator's arithmetic.
3. **Taptree root `m` comes from the witness and is verified against the
   input scriptPubKey** (F4). It cannot be hard-coded (circular), and it
   must be bound or the witness could name another script set (10.4,
   `formal/LayerTree/Binding.lean`).
4. **Two profiles, not one** (F2, F12). The sparse MS-SMT is verifiable in
   script and kept at depth 32 to 64 with empty-element compression; the
   dense operator-assigned tree costs about half per exit and supports
   subtree grafting. Bitmap compression was measured and is documented but
   not the default on-chain encoding. Since 2026-10-09 dense is the
   default and the recommendation (spec 5.4); sparse is demoted, not
   deleted: still specified, generated and tested as the key-addressed
   option, with the measured comparison in `design/tree-comparison.md`.
5. **Fixed-shape multiproofs** (F15). `EXIT_K`, `JOINK_K`,
   `EVICT_SUBTREE_h` are different taptree leaves with unrolled loops;
   witness-flag-driven shapes do not reduce script size.
6. **Three tiers** (F13, F16; there are four since the CCV tier of
   issue #3, part 1, which this entry predates). FULL is the recommended target; MID is the
   `0xC0`-only fallback assuming `OP_TX` is available there ([A-5]); MIN is
   the existence proof that CAT + TWEAKADD suffice for the covenant.
7. **EC ops aligned to the author's draft BIP** (F11): `[scalar][point]`
   operand order, empty vector = G, 33-byte points.
8. **Channel leaves use LN-Symmetry, not penalties** (Appendix C.3.1), and
   exact payouts, `SEQ_FINAL`, `evict_after = 0` for routing leaves, and
   `UPDATE^x` for user-to-user leaves (F17).
9. **Formalisation split by layer**: Lean for the covenant and tree (the
   claims are theorems about hash trees), P for the off-chain protocol (the
   failures are interleavings). Tapscript bytecode is verified by
   execution, not proof.
10. **Radix 2 stays** (2026-10-09). A radix-4 dense level was built and
    measured (`tools/experiments/radix4.py`): 146 bytes of script and 123
    of witness against 88 and 41, a net loss at every depth; radix 8 is
    worse. Spec 13.2 carries the numbers.
11. **MIN stays an existence proof** (2026-10-09). `EXIT_1` and `SPLIT`
    are built and measured; `JOIN`, `UPDATE`, `EXIT_K` and the sweep are
    argued (spec 4.5 says the dashes mean not built, not impossible) and
    will not be built. A MIN tree is created with its whole membership.
12. **The 116-byte leaf stays** (2026-10-09). Publishing 72 bytes per
    exit (exit key, amount, hash of the rest) would save about 11 vbytes
    per leaf in every shape, under one percent of a solo exit, for a
    format change that touches Lean, Go and every golden vector. Not
    worth it.
13. **`chan_id` keeps `m`** (2026-10-09). The question was whether a
    `DETACH_h` would invalidate channel states. It does not: `chan_id` is
    a constant in the channel scripts behind the leaf's `exit_key`, and
    a detach leaves leaf bytes unchanged. `m` stays as a free domain
    separator that makes `P_chan` reuse across trees harmless
    (`design/batching.md`, Shape 3).
    *Addendum 2026-10-10 (decision 24).* The conclusion stands: a detach
    does not invalidate channel states, because `chan_id` is a constant
    behind `exit_key`. The domain separator is now `tree_id`, not `m`,
    since `m` names a rule set that two trees can share and a detached
    tree's root is `m_h` while its `tree_id` is inherited.
14. **`DETACH_h` is the operator's** (2026-10-09), like `JOIN_h`; a
    per-cohort flag at graft time would be a format change for no gain.
15. **`REWRITE_h` subsumes `EXIT_SUBTREE_h`** (2026-10-09). A position
    that goes from a leaf to `E_0` must pay the leaf to its exit key, so
    one script per height is a mass exit, a cohort join, a batched
    update and an intra-cohort settlement. 13.4's owner multiproof is
    not built separately.
16. **A slashable operator bond** for voucher equivocation is tracked as
    issue #11, not built: it reaches over-issuance only, and the
    dedicated credit leaf with `CLAIM^x` removes the need.
17. **Paper is functionality first** (issue #4). The reader meets the
    ideal functionality (interfaces, adversarial influence, the liveness
    bound as a function of tree size), then the covenant predicates, then
    the tiers as realisations, then one UC theorem whose lemmas cite the
    Lean theorems inline. The tree-output binding stays in the abstract
    protocol because every tier needs it; how it is recomputed is per
    tier. The PDF is stamped with the git revision it describes.
18. **Vouchers bind `tree_id` in every tier** (2026-10-10, spec 0.10.0;
    `paper/reviews/crypto.md` finding 6). `m` names a rule set, not a
    tree: two trees with the same depth, profile, operator key and script
    set share it, so a FULL or MID voucher over `m` verified in both
    against identical source-leaf bytes. `tree_id` is now a creation
    parameter of 6.2 (unique per lineage, RECOMMENDED
    `H_tag("LayerTree/tree-id", txid || le32(vout))` over the outpoint
    input 0 of the creation transaction spends), a constant of every
    `CLAIM` script and the value every voucher binds; a tree created by
    `DETACH_h` inherits it, so vouchers survive a detach and 9.6's
    reissue rule is gone. Cost: 32 bytes per FULL `CLAIM`, 25 per MID
    `CLAIM`, and `taptree_full_d4.merkle_root` moved once.
19. **Carves inherit the lease** (2026-10-10, spec 0.10.0, 7.5 rule 5;
    `paper/reviews/crypto.md` finding 9, `design/review.md` F20). A
    `CLAIM` or `SPLIT` leaf keeps the source's `evictor_key` and a lease
    no later than the source's, so eviction holds per balance and a
    member of an evictable cohort cannot block its sweep with planted
    dust. Two field comparisons in every tier (25 bytes under `0xC2`, 60
    under `0xC0` with six more witness elements), two hypotheses of the
    Lean `Claim` relation (`claim_evictable`), a builder check in Go. The
    residual, a leaf admitted as non-evictable carving dust of the same
    terms, is stated in 10.8 and tested, not hidden.
20. **A detached cohort keeps its rules** (2026-10-10, spec 0.10.0, 7.10
    rule 3; `paper/reviews/crypto.md` finding 7, `design/review.md` F21).
    `m_h` was the reference set compiled at depth `h`, which dropped
    `EXIT_K^=` and every other creation option, so detaching a cohort of
    channel leaves silently broke C.6.1. Now `m_h` MUST be the parent's
    option set (`TreeOptions`, `FullTreeOptions`) compiled at depth `h`,
    the same `tree_id` and `OPERATOR_KEY` included; the 10.1 trust table
    says what a detach can and cannot do. Go gained the exact-payout
    `EXIT_K^=` generator it needed for this, which closes that part of
    open item 4.
21. **Editorial pass 0.10.1** (2026-10-10, no rule change; Appendix C
    0.3.1). The three paper reviews' spec-level items: exit latency is
    the explicit contention assumption [C] in 10.5 and C.9.5 with
    `kappa` (spends of one output confirming per block, a relay policy
    parameter) and `beta` (adversarial spends confirmed ahead),
    `Delta(q) = Delta_L (ceil((beta + q)/kappa) + 1)`, and C.4.4 ties
    `G_exit` to the leaf count; section 11 states one cost model (946 WU
    skeleton, 172 per further payout, 774 without a payout, vB =
    ceil(WU/4), witness prefixes excluded and measured per tier in
    `spec/scripts/weights.md`) and recomputes the sweep, rewrite and
    sparse rows on it (UPDATE 1,030, depth-8 exit 762, break-even near
    D = 3); 4.1 pins the EC-ops draft (commit `8df28249`, operands
    written top of stack first) and BIP-443 (`24e96e87`); 9.6 calls a
    hash-locked voucher a cheque and the pairing an ordered exchange,
    not atomic; 9.2 says a self-funded graft is a signing round; 10.10
    carries measured element sizes and new 8.11 the 80-byte policy cap
    on MIN's `extra_outs`; 10.1 bounds "cannot delay" by [C]. Open from
    the pass: split MIN's `extra_outs` per output (8.11).

22. **Rule change 0.11.0** (2026-10-10; Appendix C 0.4.0). Three script
    rules from the audits under `design/audit/`. `NONNEG` (`OP_DUP OP_DUP
    OP_ABS OP_EQUALVERIFY`) follows every `PADZ` sum in the `0xC0` tiers,
    so a sign-magnitude negative such as `00 00 00 81` cannot pass as a
    four-byte amount (script audit; 4 bytes per level). `DUST_MIN` is a
    creation parameter (6.2, RECOMMENDED 330 sat) that 7.5 rule 6 applies
    to every carve's claim leaf and to a non-zero residual, in every tier,
    so no member can plant a sub-dust leaf that blocks its cohort's sweep
    and every graft over it (protocol audit A2, F23; 15 bytes under
    `0xC2`, 14 under `0xC0`). `REWRITE_h`'s amount-only exemption (7.9
    rule 3) stops at a `SEQ_FINAL` leaf, so the operator alone cannot
    raise a channel leaf's capacity and strand its pre-signed states at
    the relay layer (A1, F22, F34; 11 bytes per position). 7.9 rule 7 is a
    MUST in trees that carry `UPDATE^x` or `CLAIM^x` (A3, F24). `JOIN`,
    `UPDATE` and `REWRITE_h` carry no dust floor because the operator
    signs each of them (7.8). Counts: FULL 1,054, MID 268, MIN 55, CCV
    972.

23. **Two audiences, two versions** (2026-10-10). The short paper
    (`paper/main.pdf`, the 15-page FC body) is written for developers and
    enthusiasts: how the system works, every major operation described
    in a digestible block ordered by a member's life in the tree, the
    flows, the trust model, the opcode packages, prior work, and the
    voucher system (cumulative vouchers advancing `seq`, credit leaves,
    hash-locked cheques, the receive flow) as a section of its own; Lean
    and the UC result appear in a short "what is proved" section with a
    pointer to the full version. The full version (`main-full.pdf`) keeps
    the functionality-first body of decision 17 with the simulator, the
    proofs and the Lean signatures. One source, `\iffullversion` at
    section granularity, shared text factored into files both include.

24. **`chan_id` binds `tree_id`, not `m`** (2026-10-10, Appendix C 0.5.0;
    `design/audit/channels.md` B6, F35; amends decision 13). C.2.2 claimed
    that binding `m` stops a state signed for one tree from being replayed
    in another, but `m` names a rule set that every tree created with the
    same parameters shares (6.2), and after a `DETACH_h` the leaf sits
    under `m_h` while its scripts carry the parent's `m`. `tree_id` is
    unique per lineage by construction and inherited by a detached tree,
    and vouchers already bind it for the same reason (decision 18). The
    `chan_id` formula, C.9.1's MUST list, 9.8 and 7.10 of the base spec,
    the Python reference, the Go `ChanParams` and `ChanOpen` (the field was
    already named `TreeID`) and the `chan` golden vectors moved; the
    channel scripts did not change by a byte, and the `chan` vectors no
    longer derive from the D4 root. No attack was found before the change;
    the fix makes the stated binding true and stable across the lineage.
    Counts: chan 220.

25. **No relative lock on value-neutral transitions** (2026-10-10; the
    paper reviews' P1c, declined). The first adversarial spend per block
    already invalidates the honest exit, chaining adds no delay,
    descendant pinning drives `kappa` to 1, so a relative lock on `SPLIT`
    and self-`CLAIM` would remove nothing and cost throughput. [C] stays a
    stated fee auction (10.5).

26. **Tower-delegable exit `EXIT_K^t`** (2026-10-10, spec 0.12.1, 7.2
    rule 7; the paper reviews' P8, landed). A tree-creation variant of
    the exact-payout exit in FULL, MID and CCV (both numerics; MIN has no
    `OP_CHECKSIGFROMSTACK`): the owner branch checks a BIP-340 signature
    over `H_exit(tree_id || leaf)` with `OP_CHECKSIGFROMSTACK` in place of
    the transaction signature, under a tag of its own so that neither an
    authorisation nor a voucher can serve as the other. Everything else
    the predicate fixes already, so the signature need not cover the
    transaction: a tower builds the exit with its own fee input and
    rebuilds it against a new root when outbid, with the owner offline;
    one authorisation per leaf in `EXIT_K`, and anyone assembles the
    transaction; `tree_id` is inherited across `DETACH_h`, so an
    authorisation survives one, by design. Consequences written into the
    spec: a published authorisation is a bearer exit right until the leaf
    changes (an owner who stays after an outbid exit MUST void it by
    `UPDATE` or self-`SPLIT`); 9.2 forbids re-joining with an
    `(owner_key, nonce, seq)` the lineage has held (a fresh nonce
    RECOMMENDED); a tower refreshes after an amount-only `REWRITE_h`
    changes a plain leaf (9.7); a cooperative exit is one message (9.3);
    Appendix C 0.5.1: never to the counterparty of a leased leaf (C.6.4),
    to the state-holding tower only (C.9.3). The reference set of 6.2 is
    untouched, so the D4 golden root did not move. Cost: 107 bytes over
    `EXIT_K^=` per step under `0xC2`, 124 under `0xC0`. Counts: FULL
    1,154, MID 466, CCV 1,344; Go `txn` 48 cases.

28. **Vouchers and exit authorisations bind the leaf without its
    amount** (2026-10-10, spec 0.13.0, 7.5, 7.5.1, 7.2 rule 7; the
    developer review's finding 1, F48). `H_voucher`, `H_voucher_h` and
    `H_exit` sign `body(leaf)`, the 108 bytes after the amount field, in
    place of the whole 116-byte leaf, in every tier that has them (FULL,
    MID, CCV both numerics). Before, `REWRITE_h` rule 3's amount-only
    exemption let the operator void every outstanding voucher and tower
    authorisation against a leaf by topping it up one satoshi, with no
    unilateral remedy on a credit leaf; the amount binding was not
    load-bearing, since single use comes from `seq` and over-redemption
    from the script's check of the claim against the current amount.
    Now a voucher or authorisation survives a top-up (the exit pays the
    raised amount, the voucher redeems against it) and dies on any other
    change. Honest residual (10.3): a whole-balance voucher is blocked,
    not voided, by a top-up below `DUST_MIN`, since the residual it
    would leave fails 7.5 rule 6; 9.6 has issuers top up by at least
    `DUST_MIN`. Cost: `0xC2` scripts gain 3 bytes (`108 OP_RIGHT`),
    `0xC0` scripts lose 4 (`CLAIM`, `CLAIM^h`) or 3 (`EXIT_1^t`), one
    pick and one cat fewer. The D4 golden root moved (`CLAIM` is in the
    reference set) from `6dea666e…` to `aa2ba1ff…`; the `chan` section
    did not. Lean: `Leaf.Body`, `Voucher.src : Leaf.Body`,
    `voucher_no_replay` restated over bodies (strictly stronger),
    `voucher_survives_topup` added with the rule 6 proviso, 61 audited
    theorems. Tests: a top-up through a real `REWRITE_2` followed by
    `CLAIM` and `EXIT_1^t` on pre-top-up signatures in FULL and MID,
    state-level top-up positives and changed-field negatives in every
    tier, Go `txn` cases `CLAIM topped` and `EXIT_1 tower topped`
    replayed through the simulator.

27. **MIN `extra_outs` stays as 8.11 describes it** (2026-10-10; the
    reviews' Q4). The MIN tier's raw extra outputs stay one witness
    element, not one per output; 8.11's note stands and no split is
    specified.

29. **The pending-leaf receive** (2026-10-12, spec 0.14.0, 6.2, 7.5.4,
    7.9 rule 8, 7.11, 9.6.3; `design/pending-receive.md`). The
    settle-first credit leaf leaves one payment of trust between settling
    and signing, and the earlier ways to close it failed (a recipient
    preimage with a plain hash-locked voucher cannot be retired; an
    expiring voucher voids the settled balance with the payment in
    flight). The construction is an HTLC that lives in the tree: a
    receive pair of a pending leaf `P` (operator-owned, exit key the
    recipient's, evictor `RECLAIM_KEY`, deadline `T`) and the recipient's
    own landing leaf `L`. R1 lets the operator reclaim `P` after `T`; R2
    is a hash-locked merge voucher that raises `L` to an absolute level
    and voids nothing, so replays and older vouchers move nothing; R3 is
    a reclaim-form `REWRITE_h` that settles a window for many recipients
    with the operator's signature alone. Merge targets and transfer
    siblings must share the source's exit key (spec 7.5.4 rule 2,
    7.9 rule 8): the Lean model showed that owner-only equality let value
    leave a key's exits and let two leaves merge into each other across
    keys. The operator MUST advance `L`'s `seq` in any decrease it
    co-signs, which the scripts do not check (9.6.3). MIN has no
    CSFS and no `CLAIM`, so it does not carry the receive. R1 to R3 live
    in the reference tree's option sets, not in the base set of 6.2, so
    the D4 golden root did not move. Lean: 72 audited theorems.
    An adversarial review of the first draft and a second pass over its
    fixes preceded the build (`design/pending-receive.md`, *Review*).

30. **The CCV mode flag and the amount-only element** (2026-10-13, spec
    0.14.1 to 0.15.1; 4.6, 7.9, 8.9). Two follow-ups to decision 29,
    approved by the owner. (a) Plain CCV `UPDATE`, `UPDATE^x`,
    `REWRITE_h`, `REWRITE_h^x` and the reclaim forms committed output 0 in
    the assign mode, which forces it to carry at least the input's
    residual, so a net decrease that the other tiers leave free (7.4,
    7.9 rule 6) was not spendable under CCV. They now take the output-0
    mode from one witness flag, the bottom element: `0x01` for `DEDUCT`
    exactly when value is freed, empty for assign otherwise. `MINIMALIF`
    rejects any other value and either choice is safe, because the
    `out0.amount == ns` read pins output 0 in both modes; a builder
    derives the flag from the net change (`rules.ccvModeFlag`). Exits,
    joins, claims and the rest keep the assign mode. (b) An 8-byte
    amount-only new element in 7.9 (flag `0x03`) in place of a
    republished 116-byte leaf, for a position that changes in its amount
    alone: a top-up, a payment between members, an R3 settlement. It takes
    54 vB per pair off the settlement transfer and puts 14 vB back across
    the two transactions (the roll publishes the same, longer script):
    587 to 547 vB per pair at 64 positions, 1,006 to 966 at 4 and 664 to
    624 at 16. The `REWRITE_2/4/6` mixed cohorts at `D = 16` became 2,843 /
    1,528, 5,784 / 4,099 and 18,236 / 14,104 B of script / witness in
    FULL. **The `0xC0` caveat.** Under `0xC2` numerics the element
    costs 10 bytes of script a position and saves 108 of witness, so it
    pays once about a tenth of the positions change in their amount
    alone. Under `0xC0` numerics (MID and CCV0) the same encoding costs
    65 bytes of script a position (69 in the reclaim forms) against 116
    bytes of witness saved, so it pays only when more than about 56% of
    the positions are amount-only; a pending settlement's transfer
    clears that bar, its roll does not, and the pair's two rewrites come
    out slightly behind there. The element is part of 7.9 in every tier
    that has `REWRITE_h`, so MID and CCV0 pay its script in every
    position of every rewrite whether or not the position uses it; 8.9
    states the break-even. Suites: 1,594 /
    1,391 / 57 / 4,295 checks; 427 replayed witnesses; the golden D4
    root did not move.
31. **Review fixes to the numbers and the `OP_RIGHT` reading** (2026-10-14,
    spec 0.15.2; 4.1, 4.5, 4.6, 7.2, 7.7, 7.11, 8.9, 11). No rule changed.
    (a) 4.1 item 3 now states the `OP_RIGHT` edges that the `R1` reclaim
    branch and `REWRITE_STEP` rely on (`n = 0` gives the empty string,
    `n >= size` gives the string unchanged; `OP_LEFT` is the mirror), and
    the simulator's `n = 0` case, which returned the whole string, is
    fixed. (b) The CCV0 `REWRITE_h` witness is one element shorter than
    MID's, not two, because of the mode flag: the `h = 6` bound is
    `10(p_o + p_n - u) - 7a + s <= 524` and the peak of the full
    32-position rewrite is 965 elements; the CCV0 reclaim-form settlement
    is 929 / 705 elements at `h = 5` and 1,752 / 1,304 at `h = 6`.
    (c) "input 0's `nSequence`" became "the tree input's `nSequence`" in
    7.2, 7.7 and 7.11. (d) The sparse `EXIT_1` is now also measured on a
    tree of 65,536 real leaves (`test_exit_sparse_large`, the `S/65536`
    row of `spec/scripts/sizes.md`): 16 occupied siblings, 900 witness
    bytes, 1,781 vB at `D = 32` against 1,637 on the six-leaf tree.
    (e) The `c0: update without owner` negative of `tools/test_ccv.py`
    ran a witness equal to the positive one and failed only on the
    leaked BIP-443 accumulators; it now drops the owner signature on a
    fresh context. Suites: 1,610 / 1,391 / 57 / 4,295 checks; the golden
    D4 root did not move.

## Assumptions that could change the design

Listed in spec 4.1 as [A-1]..[A-5], Appendix C.11 as [C-A1]..[C-A4]. The
ones most likely to move:

* **[A-5]** `OP_TX` in tapleaf `0xC0`. If it is `0xC2`-only, the MID tier
  collapses to MIN for introspection and channel leaves need FULL.
* **`OP_TX` selector values and collated layout** (spec 8.1, C.2.1). The
  draft may renumber; every selector is a named constant in
  `tools/layertree_scripts.py` and `script/asm.go`.
* **EC ops opcode numbers and cost units** track the draft BIP; the
  `TREE_SPK` macro is the only consumer.
* **TRUC ephemeral anchors** ([C-A2]) for zero-fee channel transactions.

## Open work, in rough priority

0. **Atomic receive** (`design/pending-receive.md`). R1, R2 and R3 landed
   as spec 0.14.0 in FULL, MID and CCV (decision 29), and the two
   follow-ups landed as 0.15.0 and 0.14.1 to 0.15.1 (decision 30). The
   numbers pass of 2026-10-13 is done. Nothing from the receive round is
   open in the repository; `design/towers.md` collects the tower roles.

1. **P model** of the off-chain protocol (issue #1, `design/p-model.md`).
   Start with the covenant oracle and its differential harness against
   `tools/layertree_ref.py`; that step decides whether the rest is worth
   doing.
2. **Verified link from rules to bytecode.** The Lean model stops at the
   rules of section 7. A verified interpreter for the tapscript subset
   (BIP-441 numerics, `OP_TX`, CSFS) would close the gap the simulator now
   covers. Large, separate project.
3. **Regtest harness.** The 25-descendant exit throughput figure (10.5,
   C.9.5) and the TRUC anchor assumptions should be confirmed against a
   node once the opcodes exist in a test build (e.g. an Inquisition or
   custom signet).
4. **Go: what the builders still lack.** `txn/` has one builder per
   transition for every tier (`txn/transitions.go`, `txn/cohort.go`,
   `txn/tier.go`, `txn/min.go`) and a shared signer (`txn/spend.go`);
   every transition each tier carries has an end-to-end case replayed
   through the simulator, the CCV `REWRITE_h` of 0.13.2 included (it
   needed no builder code: the CCV body is FULL's or MID's without `r m`),
   and CI runs the replay. The builders refuse what the `0xC0` scripts
   would reject at the stack limit (a `REWRITE_h` or sweep whose witness
   plus the script's peak passes 1,000 elements). Still open: Go cannot
   execute the covenant, so the simulator remains the check of what the
   scripts accept; the Go side checks what the builders refuse.
   The MIN tier's `MinTreeOptions` names no `OPERATOR_KEY`, since its
   two scripts read every key out of the leaf.
5. **Off-chain message set.** `msg/` covers proofs, vouchers, join
   offers and, since Appendix C 0.3.0, the channel-leaf messages
   (`ChanOpen`, `StateProposal`, `StateSig` with the C.3.6 order check,
   HTLC add / fulfil / fail, `RebindAnnounce`, `SpliceProposal`). Still
   open: a message-type registry and framing shared by all of them, and
   the MuSig2 session itself (nonce handling is carried as opaque bytes).
6. **Channel leaves beyond the reference.** The update machine, the HTLC
   outputs and the deadlines of C.4.4 and 9.6.2 are now exercised
   (C.12). Not modelled: the P2A fee children and TRUC package relay
   ([C-A2]), PTLCs, and pre-signed second-stage HTLC transactions
   (C.2.5). 9.6.2's closing paragraph points at `tools/test_chan.py`,
   which also runs the stale-update, lease, evictor and epoch cases of
   Appendix C 0.4.0 (C.12).
7. **Aggregate node keys** (13.5) deliberately left out; would reintroduce
   interactive signing. MuSig2 adaptor signatures (`notes.md`) are likewise
   out of the base protocol: an off-chain concern for channel leaves and
   swaps, tracked here only so the note in `notes.md` has a home.
8. **`tree_id` for every tier.** Done (decision 18, spec 0.10.0): every
   tier's vouchers bind `tree_id`, the child of a `DETACH_h` inherits it,
   and the FULL/MID `CLAIM` golden keys, `taptree_full_d4.merkle_root`,
   the voucher vectors and the Go voucher helpers moved with it.
9. **Cohort transitions beyond FULL.** Done for every tier that can
   carry them (spec 0.13.1). `REWRITE_h` and `REWRITE_h^x` exist in FULL
   and, since 0.11.1, in MID (an element-based `REWRITE_STEP` that
   decides 7.9 rules 3 and 5 from the leaf's fields before they are
   re-joined; the stack limit caps a full cohort at `h = 5`, 4.5).
   `DETACH_h` exists in FULL, since 0.11.1 in CCV in both numerics
   (output 1 is one `CHECK_OUTPUT|DEDUCT` call under `m_h`, 4.6) and
   since 0.13.1 in MID (output 1 by `TREE_SPK_MIN` under `m_h` and a
   `PADZ` sum, 8.10; `DETACH_8` 2,174 / 534 B at `D = 16`, 250 bytes over
   the MID `JOIN_h`; the witness shrinks with `h`, so the stack limit
   binds nothing). `CLAIM^x` and `CLAIM^hx` exist in FULL and since
   0.13.1 in MID and in CCV in both numerics (4 bytes over the plain
   form under `0xC0`, 7 under `0xC2`, 8.6.3), with the credit-leaf
   scenario of 10.3 run end to end in MID (`test_credit_topup`: an
   amount-only `REWRITE_2^x` by the operator, then `CLAIM^x` by the
   recipient on the vouchers signed before it). Each tier has an option
   set `m_h` is compiled from (`TreeOptions`, `layertree_mid.TreeOptions`,
   `CCVTreeOptions`; Go `FullTreeOptions`, `MidTreeOptions`,
   `CCVTreeOptions`). Since 0.13.2 `REWRITE_h` and `REWRITE_h^x` exist
   in CCV too, in both numerics (4.6, 8.9): FULL's machine under `0xC2`
   and MID's under `0xC0`, the exit payout one `CHECK_OUTPUT|DEDUCT`
   call (4 bytes over the P2TR compare), the fixed part 377 / 360 bytes
   shorter, per-leaf costs within a few vB of FULL's and MID's
   (`REWRITE_6` exit 164, update 150 under `0xC2`; `REWRITE_5` exit 262,
   update 249 under `0xC0`, as of 0.15.1, where MID's `h ≤ 5` stack cap holds with one
   element to spare against MID, the mode flag taking the other of `r`, `m`); tested in `tools/test_ccv.py` on the FULL suite's
   cohort with every rule's negative in both numerics, the top-up that
   vouchers and `EXIT_K^t` authorisations survive, the credit leaf and a
   `NONNEG` case; golden `CCV/D/D4` and `CCV0/D/D4` `REWRITE_2` and
   `REWRITE_X_2`, Go `CCVRewriteScript` / `CCV0RewriteScript`,
   `CCVTreeOptions.RewriteHeights` / `RewriteX`. What remains is outside
   the tiers' reach: MIN has no `CLAIM`, no second tree output in its
   fixed shape and no rewrite (the `txn` builders cover every tier, open
   work 4). The Lean model states
   `REWRITE_h` as one step over a published subtree pair and `DETACH_h`'s
   second output directly (`Cohort.lean`); it does not model tiers, so
   none of this touched it. The one-byte "unchanged" marker for
   `REWRITE_h` landed in 0.12.0 (FULL and MID, 7.9, 8.9): an unchanged
   position publishes its leaf once and costs about 92 vB in FULL
   instead of 120, 95 since the amount-only element of 0.15.0
   (`design/batching.md`).

## How to resume

1. Read `CLAUDE.md`, then `spec/layertree.md` sections 3, 4.5, 7 and 10.2,
   then `formal/README.md`.
2. Run the full check matrix from `CLAUDE.md` and confirm the counts match
   the ones in spec section 14.
3. Pick from the open work above; for anything that touches a transition
   rule, change the Lean model first and let the build tell you what the
   rule change implies.
