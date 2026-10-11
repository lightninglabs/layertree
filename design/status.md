# Status and hand-off

Last updated 2026-10-10 (spec 0.11.0, Appendix C 0.5.0, paper v0.1).

## Where things stand

| Area | State |
|---|---|
| Base spec `spec/layertree.md` | Complete for the design as scoped: tree format, two profiles (dense, sparse), taproot binding, transitions EXIT_K / EXIT_K^= / JOIN_h / JOINK_K / UPDATE / UPDATE^x / CLAIM / EVICT_SUBTREE_h / terminal, three opcode tiers, reference scripts, off-chain protocol, security, cost, comparison, extensions, test vectors. |
| Cohort transitions (0.9.0) | `CLAIM^x` and `CLAIM^hx` (7.5.3, the dedicated credit leaf of `design/receive.md`), `REWRITE_h` with its `^x` form (7.9, `design/batching.md` Shape 2 with the exit rule) and `DETACH_h` (7.10, Shape 3) are built in the FULL tier only: generator, tests, golden vectors, Go mirror, listings. Measured at `D = 16`: `REWRITE_6` 17,148 B of script, about 147 vB per changed leaf; `DETACH_8` 1,548 / 497 B, exits at 765 vB afterwards. Since 0.11.1 `REWRITE_h` and `REWRITE_h^x` also exist in MID (`REWRITE_4` 10,516 / 4,436 B on the mixed cohort; a full cohort fits the 1,000-element stack limit up to `h = 5`), since 0.12.0 an unchanged position publishes its leaf once (the one-byte marker of 7.9, 92 vB per unchanged position in FULL against 120 before), and `DETACH_h` in CCV, both numerics (`DETACH_8` 973 / 433 B under `0xC2`, 1,628 / 470 under `0xC0`; `CCVTreeOptions` compiles `m_h` from the parent's set). `DETACH_h` in MID, `CLAIM^x` in MID and CCV: not implemented; MIN: no. Lean: `rewrite_sound`, `rewrite_exit_conservation`, `detach_sound` and `detach_member_payable` in `Cohort.lean`. |
| Appendix C channel leaves | Complete, 0.5.0: rebindable OP_TX + CSFS commitments, LN-Symmetry state machine, HTLCs and routing, lifecycle, tier analysis, comparison, security; 0.4.0 adds the settlement dust floor `DUST_CHAN` (C.3.4, trimmed value to the anchor) and the `beta_chan` stale-update term of the C.4.4 budget with the fee-reserve and replacement rules of C.5.5 and C.9.6 (channel audit B1, B4); 0.5.0 binds `chan_id` to `tree_id` in place of `m` (C.2.2, B6, decision 24; zero bytes of script). All C.10 recommendations adopted by the base spec. Executable (C.12): `tools/layertree_chan.py` generates `UPD_F` / `REBIND_n` / `SETTLE_n`, and `tools/test_chan.py` (220 checks) runs the state machine on a chain model with BIP-65 / BIP-68, from a tree exit through contest, settlement and HTLC sweeps, in both tapleaf versions, plus the C.4.4 / 9.6.2 deadlines as block sequences. Go mirror `script/chan.go` byte-exact against the golden `chan` section; TLV messages in `msg/chan.go`. Measured: `SETTLE_n` is 79 B under 0xC2 (80 under 0xC0), HTLC sweeps 155 / 138 vB (the old table missed the 65-byte control block), the C.4.4 bound has two blocks of margin, and a MID channel carries at most seven HTLC outputs per state beside two balances, eight beside one (520-byte collation). |
| Fee analysis | `spec/fee-analysis.md` and `tools/fee_analysis.py`, 1 to 250 sat/vB. |
| Python reference and simulator | 1,069 + 413 + 55 + 1,160 checks pass (FULL, MID, MIN, CCV), plus 61 for the hypothetical opcode outside every tier. Every script uses only its tier's allowed opcode set. |
| Go implementation | `tree`, `script`, `txn`, `msg`; all 94 golden scripts byte-exact; BIP-341 sighash equality with the simulator. `txn` builds, signs and verifies every FULL transition end to end against the real taptree (control block opening `TREE_SPK(r, m)`): `EXIT_1` (owner, eviction), `EXIT_2`, the terminal exit, `JOIN_0`, `JOINK_2`, `UPDATE`, `UPDATE^x`, `CLAIM` (partial and draining), `CLAIM^h` and `SPLIT` at dense D = 4, 16 and sparse D = 8, `JOIN_2` and `EVICT_SUBTREE_2/4` at dense D = 4, 16; 45 cases, each pinned to the simulator's sighash and executed once by `script_sim.Interp`. |
| Lean model | `formal/`: sections 5 (including sparse positions), 7 (including `EVICT_SUBTREE_h` and the terminal branch), 10.2, the encodings, and the cohort shapes `REWRITE_h` and `DETACH_h` of `design/batching.md` (`Cohort.lean`); axiom audit clean; no `sorry`. |
| P model | Design note `design/p-model.md` and GitHub issue #1. Not started. |
| Paper | `paper/`: functionality-first LNCS paper (ideal functionality, abstract protocol, four opcode tiers FULL/MID/MIN/CCV, UC theorem, channel composition), built in two versions from one source by an `\iffullversion` switch keyed on the job name. Revised for the second review round (`paper/reviews/{crypto,protocol,systems}.md`, answered item by item in `paper/review-response.md`): the liveness bound Delta(N) is replaced by an explicit contention assumption [C] (kappa, beta; Delta(q) = Delta_L(ceil((beta+q)/kappa)+1)); the functionality is a partial tree with opaque nodes at any height, `REVEAL`, `VOUCH`, creation as a join, a protocol-aware `EXIT(p, v, f)`; Lemma 2 (`Step.sound`), a paper-only path-maintenance Lemma 3 (Lean item handed off), Claim 1 (simulation invariant, proved by case in Appendix A); Theorem 5 excludes `REWRITE_h`/`DETACH_h`, uses the ROM for same-sign taproot binding and [MIN] for the generator-key check; Theorem 6 is Conjecture 1; a deployment-assumptions table mirrors spec 4.1's [A-1] to [A-6]; prior art (TLUV, `OP_MERKLESUB`, `OP_EVICT`, Poelstra's CAT/Schnorr tricks, Plasma, proofs of liabilities) added; one stated fee model with corrected derived figures (REWRITE 359/195/158, joins and carves without a phantom payout, sparse 244 + 41k). Spec 0.10.0 rules (`tree_id` in every tier, the carve constraint, `m_h` with the parent's options) are described without sizes; `TODO(0.10.0 sizes)` marks the `CLAIM`, `CLAIM^h` and `SPLIT` figures to update. `main.pdf` (FC submission) is 35 pages, body ending on page 15 with References at the top of page 16, appendices A to E (Appendix F listings now full version only). `main-full.pdf` is 73 pages, References on page 29: the UC proof and the channel scripts lifted into the body with inline Lean signatures, the Lean development an appendix, plus the five full-only sections. Both PDFs stamped 761188b. Spec, tools, formal and design items the reviews raised are listed under "Handed off" in the response. |
| CCV tier (issue #3, part 1) | Complete: simulator `OP_CHECKCONTRACTVERIFY` per BIP-443 ([A-6], amount rules pinned to bips commit `24e96e87` and tested one by one), `tools/layertree_ccv.py` both profiles and both numerics (exact payouts; `UPDATE^x`, `SPLIT`, `EVICT_SUBTREE_h`, `CLAIM` and `CLAIM^h` in both numerics, the `0xC0` sweep being MID's element-based one; vouchers bind a per-tree `tree_id` constant in place of `m`, 4.6 / 9.6, and `CLAIM` is the tier's only `OP_CHECKSIGFROMSTACK` user), `tools/test_ccv.py` 798 checks including two tree inputs in one transaction, Go mirror `script/ccv.go` byte-exact against the CCV and CCV0 golden keys, Lean `CCVTweak.binding` (a second `BindingModel`), spec 0.8.4 (4.3 inventory row, 4.5 CCV column, 4.6, 6.3 `TREE_SPK_CCV`, 10.4 note, 11 cost rows, 14 tests), F19. Measured dense D=16 EXIT_1: 1,716 / 838 B script / witness vs FULL's 2,101 / 902, no EC-ops dependency; 0xC0 dense EXIT_1 2,934 / 914. The `0xC2` sweep's leaf step passed the whole leaf to CCV as its key; the old test swept only empty positions, and real cohorts now exercise it in both numerics. Measured `CLAIM` dense D=16: 3,447 / 1,626 (`0xC2`), 5,946 / 1,765 (`0xC0`). Adopted in every tier by decision 18 (spec 0.10.0, open work item 8). |
| Hypothetical `OP_MERKLESUMUPDATE` (issue #3, part 2) | Measurement only, never a tier: `design/native-opcodes.md`, simulator `op_msu` behind `hypothetical=True` (canonical proofs: siblings leaf-first, explicitly supplied empty siblings and bits above the depth rejected), `tools/layertree_msu.py` (CCV + MSU, `EXIT_K`, `JOIN_0`), `tools/test_msu.py` 61 checks including a quarantine test (absent from every tier's allowed set, every tier generator and every golden script). Measured `EXIT_1` 252 B of script at every depth and profile. |

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
6. **Three tiers** (F13, F16). FULL is the recommended target; MID is the
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

25. **No relative lock on value-neutral transitions** (2026-10-10, P1c
    declined). The protocol review's option (c), `OP_1
    OP_CHECKSEQUENCEVERIFY` on `CLAIM`, `SPLIT`, `UPDATE` and `JOIN` so
    that only removals could chain within a block, does not remove the
    failure mode it targets: the first adversarial spend confirmed in a
    block already invalidates the honest exit, so chaining adds no delay,
    and descendant pinning on any free output drives `kappa` to 1 without
    any tree transition. It would cost 3 bytes per script in every tier,
    halve cooperative throughput of value-neutral operations and add a
    confirmed/unconfirmed distinction to the Lean trace model. 10.5 keeps
    [C] as a stated fee auction. Orchestrator and an Opus second opinion
    agreed.
26. **`EXIT^t`, a tower-delegable exit** (2026-10-10, P8 adopted as a
    creation variant). In FULL, MID and CCV (MIN has no CSFS) the owner's
    authorisation is a BIP-340 signature over
    `H_tag("LayerTree/exit", tree_id || leaf)`, checked by
    `OP_CHECKSIGFROMSTACK` in place of the transaction signature, exact
    payout only, evict branch unchanged, one authorisation per leaf in
    `EXIT_K`, valid in a detached child. Whoever holds it can build and
    fee the exit at any time and rebuild it after a competing spend, so
    an owner need not be online through contention. Rules that come with
    it: a published authorisation is a bearer exit right until the leaf
    changes (void it by `UPDATE` or a self-`SPLIT`); an owner MUST NOT
    re-join with an `(owner_key, nonce, seq)` it has held before; a tower
    refreshes after an amount-only `REWRITE_h` changes a plain leaf;
    Appendix C: never give it to the counterparty of a leased leaf. The
    reference set of 6.2 is untouched. Decided with an Opus second opinion
    and a Fable check; building next.
27. **MIN `extra_outs` stays one element** (2026-10-10). 8.11's note
    stands: MIN is an existence proof, one change output plus an anchor
    fits the 80-byte policy limit, and splitting the element would move
    the MIN generator, Go mirror and vectors for a relay-policy limit on a
    tier nobody deploys.

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
4. **Go: what the FULL builders still lack.** `txn/` has one builder per
   FULL transition and a shared signer (`txn/transitions.go`,
   `txn/spend.go`). Still open: `EXIT_K^=` has a Go generator
   (`script.FullExitExactScript`) but no end-to-end case, since the
   builders pick scripts by name and `BuildExit` does not know which
   form the taptree carries; the MID, MIN
   and CCV tiers have no builders (their witness layouts differ from
   FULL's, with leaf fields passed separately and `PADZ` pads under the
   `0xC0` numerics); and Go cannot execute the covenant.
   `tools/replay_txn_dump.py` replays a `LAYERTREE_TXN_DUMP` file
   through `script_sim.Interp` and prints the sighash pins of
   `txn/transitions_test.go`; wiring it into CI would make the run a
   standing check rather than the step of each pin refresh.
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
9. **Cohort transitions beyond FULL.** `REWRITE_h` and `REWRITE_h^x`
   exist in FULL and, since 0.11.1, in MID (an element-based
   `REWRITE_STEP` that decides 7.9 rules 3 and 5 from the leaf's fields
   before they are re-joined; generator, tests, golden, Go, listings; the
   stack limit caps a full cohort at `h = 5`, 4.5). `DETACH_h` exists in
   FULL and, since 0.11.1, in CCV in both numerics (output 1 is one
   `CHECK_OUTPUT|DEDUCT` call under `m_h`, 4.6; `CCVTreeOptions` is the
   CCV option set `m_h` is compiled from). Still FULL only: `DETACH_h` in
   MID (needs the `TREE_SPK_MIN` recomputation for output 1, about 150
   bytes, and a `PADZ` sum like the CCV `0xC0` form) and `CLAIM^x`, which
   under CCV waits on the voucher-message redefinition `CLAIM` itself
   needs. The Lean model
   states `REWRITE_h` as one step over a published subtree pair and
   `DETACH_h`'s second output directly (`Cohort.lean`); it does not model
   tiers, so the MID rewrite and the CCV detach need no change there. The
   one-byte "unchanged" marker for `REWRITE_h` landed in 0.12.0 (FULL and
   MID, 7.9, 8.9): an unchanged position publishes its leaf once and
   costs about 92 vB in FULL instead of 120 (`design/batching.md`).

## How to resume

1. Read `CLAUDE.md`, then `spec/layertree.md` sections 3, 4.5, 7 and 10.2,
   then `formal/README.md`.
2. Run the full check matrix from `CLAUDE.md` and confirm the counts match
   the ones in spec section 14.
3. Pick from the open work above; for anything that touches a transition
   rule, change the Lean model first and let the build tell you what the
   rule change implies.
