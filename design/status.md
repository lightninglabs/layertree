# Status and hand-off

Last updated 2026-10-09 (spec 0.8.5, Appendix C 0.2.0, paper v0.1).

## Where things stand

| Area | State |
|---|---|
| Base spec `spec/layertree.md` | Complete for the design as scoped: tree format, two profiles (dense, sparse), taproot binding, transitions EXIT_K / EXIT_K^= / JOIN_h / JOINK_K / UPDATE / UPDATE^x / CLAIM / EVICT_SUBTREE_h / terminal, three opcode tiers, reference scripts, off-chain protocol, security, cost, comparison, extensions, test vectors. |
| Appendix C channel leaves | Complete: rebindable OP_TX + CSFS commitments, LN-Symmetry state machine, HTLCs and routing, lifecycle, tier analysis, comparison, security. All C.10 recommendations adopted by the base spec. |
| Fee analysis | `spec/fee-analysis.md` and `tools/fee_analysis.py`, 1 to 250 sat/vB. |
| Python reference and simulator | 425 + 120 + 31 + 309 checks pass (FULL, MID, MIN, CCV), plus 61 for the hypothetical opcode outside every tier. Every script uses only its tier's allowed opcode set. |
| Go implementation | `tree`, `script`, `txn`, `msg`; all 56 golden scripts byte-exact; BIP-341 sighash equality with the simulator; end-to-end EXIT_1 build/sign/verify. |
| Lean model | `formal/`: sections 5, 7, 10.2 and the encodings; axiom audit clean; no `sorry`. |
| P model | Design note `design/p-model.md` and GitHub issue #1. Not started. |
| Paper | `paper/`: functionality-first LNCS paper (ideal functionality, abstract protocol, tiers, UC theorem with inline Lean signatures, channel composition), 15 body pages, six appendices, PDF stamped with its git revision (issue #4). The CCV tier of issue #3 is measured in the paper's tier table and section 5; the hypothetical native Merkle-sum opcode of issue #3 part 2 has one clearly labelled paragraph in the discussion. |
| CCV tier (issue #3, part 1) | Complete: simulator `OP_CHECKCONTRACTVERIFY` per BIP-443 ([A-6], amount rules pinned to bips commit `24e96e87` and tested one by one), `tools/layertree_ccv.py` both profiles and both numerics (exact payouts; `UPDATE^x` in both numerics, `SPLIT` in `0xC2`; no `CLAIM` / `CLAIM^h` pending a voucher-message redefinition), `tools/test_ccv.py` 309 checks including two tree inputs in one transaction, Go mirror `script/ccv.go` byte-exact against 17 golden keys, Lean `CCVTweak.binding` (a second `BindingModel`), spec 0.8.4 (4.3 inventory row, 4.5 CCV column, 4.6, 6.3 `TREE_SPK_CCV`, 10.4 note, 11 cost rows, 14 tests), F19. Measured dense D=16 EXIT_1: 1,716 / 838 B script / witness vs FULL's 2,101 / 902, no EC-ops dependency; 0xC0 dense EXIT_1 2,934 / 914. Open: `CLAIM` under CCV, `SPLIT` and `EVICT_SUBTREE_h` under 0xC0. |
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
11. **Paper is functionality first** (issue #4). The reader meets the
    ideal functionality (interfaces, adversarial influence, the liveness
    bound as a function of tree size), then the covenant predicates, then
    the tiers as realisations, then one UC theorem whose lemmas cite the
    Lean theorems inline. The tree-output binding stays in the abstract
    protocol because every tier needs it; how it is recomputed is per
    tier. The PDF is stamped with the git revision it describes.

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
4. **Go: transaction builders for every transition.** `txn/` builds and
   signs EXIT_1 end to end; JOIN, UPDATE, CLAIM and EVICT_SUBTREE have
   witness assemblers but no end-to-end sign-and-verify test yet.
5. **Off-chain message set.** `msg/` covers proofs, vouchers and join
   offers; channel-leaf messages (C.2, C.3 signing rounds) are unspecified
   as TLV.
6. **Channel-leaf scripts beyond the HTLC outputs.** The voucher/HTLC swap
   of 13.9 is specified in 9.6.2 and tested: `HTLC_SUCCESS` and
   `HTLC_TIMEOUT` (C.4.1) are implemented and one preimage settles them
   together with a `CLAIM^h`. What is still absent is the rest of Appendix
   C in executable form, the `REBIND_n` and `SETTLE_n` update machine, so
   the deadline reasoning of 9.6.2 and C.4.4 is argued rather than
   exercised. The Go side carries no Appendix C scripts at all.
7. **The rest of the MIN tier.** MIN realises the dense `EXIT_1` and, since
   issue #9, the dense `SPLIT` (spec 8.6.2): 6,441 bytes of script and
   2,010 of witness at `D = 16`, the MID carve with the `OP_TX` reads
   replaced by the constructive signature message. `JOIN`, `UPDATE`,
   `EVICT_SUBTREE_h`, `EXIT_K` and the sparse profile follow the same
   construction but are argued, not measured.
8. **Aggregate node keys** (13.5) deliberately left out; would reintroduce
   interactive signing. MuSig2 adaptor signatures (`notes.md`) are likewise
   out of the base protocol: an off-chain concern for channel leaves and
   swaps, tracked here only so the note in `notes.md` has a home.

## How to resume

1. Read `CLAUDE.md`, then `spec/layertree.md` sections 3, 4.5, 7 and 10.2,
   then `formal/README.md`.
2. Run the full check matrix from `CLAUDE.md` and confirm the counts match
   the ones in spec section 14.
3. Pick from the open work above; for anything that touches a transition
   rule, change the Lean model first and let the build tell you what the
   rule change implies.
