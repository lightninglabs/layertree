# LayerTree design review

This note records the scrutiny of the original LayerTree sketch
(`design/layertree.md`, and "A Path To Constant Space Exit" in
`design/unified-batching.md`) against the Great Script Restoration opcode set
(BIP-440, BIP-441, the `OP_TX` draft, `OP_CHECKSIGFROMSTACK`,
`OP_ECSCALARMUL`, `OP_ECPOINTADD`), and the decisions that shaped
`spec/layertree.md`. Numbers refer to spec sections.

## 1. What the sketch got right

* Keep the tree off-chain and commit to it from one output; verify a Merkle
  proof *against the output* so exit is one message. This is the core idea
  and it holds up.
* Use a sum tree so that the commitment is auditable against the output
  value. This turns out to be more than an audit aid (finding 3).
* "On-chain state machines that transition on signed events" is the right
  mental model; it becomes the `CLAIM` transition.
* The opcode wish-list (CSFS, CAT, EC add/mul) was essentially correct. GSR
  supplies CAT/SUBSTR/big integers; the quartet supplies introspection,
  CSFS and the EC ops.

## 2. Findings and changes

### F1. The exit voucher is redundant, and harmful, once the covenant enforces the root

The sketch has the user present an operator-signed voucher *and* a Merkle
proof. If the covenant verifies the proof against the committed root and
pays exactly the leaf amount, the voucher adds no security: the leaf's
presence in the root is already the operator's commitment. What the voucher
does add is a *dependency on the operator at exit time*. A voucher that is
lost, or never issued, blocks the exit. Requiring it would let the operator
censor withdrawals, contradicting the goal.

Two further observations:

* Something must stop third parties from forcing a user on-chain. The
  natural authoriser is the leaf owner, by a signature over the spending
  transaction. So exit = proof + owner signature (spec 7.2).
* The voucher's real value is for balances *not yet in the on-chain root*
  (a recipient the operator has promised to include). That is an off-chain
  payment instrument, and it can be made independently redeemable if the
  covenant lets a voucher carve a new leaf out of an existing funded leaf.
  That is `CLAIM` (spec 7.5). The source leaf changes on redemption, so a
  voucher is single-use without any nonce registry; a `seq` field prevents
  revival if a balance returns to a previous value.

### F2. The MS-SMT *can* be verified in script; the question is what depth to pay for

An earlier draft of this review claimed a 256-level sparse tree "cannot" be
verified by loop-free script. That was wrong, and the author pushed back on
it. Script has no loops, so each proof level is unrolled, but each level is
a fixed 130–140 bytes of script; nothing stops unrolling 256 of them. The
sparse profile of the spec does exactly this, with compressed proofs
(empty siblings are a zero-length witness element and the script computes
`E_k` itself) and with the direction bits *derived* from the leaf rather than
supplied. Measured cost per exit (`spec/scripts/sizes.md`; figures after the `enc64` change of F13):

| tree | levels | script | witness | total (WU) |
|---|---|---|---|---|
| dense, operator-assigned | 16 | 2,101 | 902 | 3,132 |
| sparse, key-addressed | 32 | 5,147 | ≈ 326 + 41·log2 N | ≈ 6,260 |
| sparse, key-addressed | 64 | 9,499 | ≈ 326 + 41·log2 N | ≈ 10,610 |
| sparse, full 256-bit keys | 256 | 35,611 | ≈ 285 + 41·log2 N | ≈ 36,680 |

So the honest statement is: a 256-level SMT costs about 9 kvB per exit,
roughly twelve times the dense tree; a *truncated* key-addressed SMT of 32
levels costs about twice the dense tree and keeps the properties that made
the MS-SMT attractive:

* positions are a function of `(owner_key, nonce)`, so nobody allocates
  slots, the root is history-independent (auditable from the leaf set
  alone), and duplicate leaves are impossible by construction, which removes
  the uniqueness requirement F10 needed for vouchers;
* non-inclusion is an inclusion proof of `E_0` at the derived position, so
  joins need no coordination on positions.

Truncation to 32 bits is safe because a collision only means a join must
retry with a new nonce (the position is occupied), and an adversary cannot
occupy positions without the operator's `JOIN` signature. What the sparse
profile gives up is subtree grafting (`JOIN_h` for `h > 0`), since derived
positions are not contiguous.

The spec therefore defines both profiles; the reference scripts share every
macro except the per-level prologue. The 256-level variant is not given its
own profile: it buys nothing over 32–64 levels except the ability to use a
raw 256-bit key as the position, which a tagged hash of `(owner_key, nonce)`
provides more cheaply.

### F3. Sums at every node make "the operator cannot steal" a theorem

If node hashes commit to the children's sums and the verifier recomputes
every sum along the path, then any set of leaves with verifying proofs sums
to at most the root sum (spec 10.2). Combined with the covenant rule that the
tree output's amount equals the recomputed root sum at every transition, the
output can always pay every provable leaf. Without per-node sums the same
guarantee needs every participant to audit the entire tree at every join.
Per-node sums also let a `JOIN` graft an operator-built subtree in constant
size: the covenant only checks that the graft is funded; each member checks
their own path's consistency before signing (spec 9.2), which by the theorem
is enough for their own safety.

### F4. State carry needs the taptree root, which cannot be hard-coded

To recreate the tree output, the script must recompute
`P2TR(internal_key(r'), m)`. Writing `m` into the scripts is circular (the
scripts are the taptree). Options considered:

* `OP_TX INPUT_WITNESS` to read the control block and recompute `m` from
  the running script's own bytes: works but needs `OP_BYTEREV` and
  lexicographic comparisons for each taptree level.
* `OP_INTERNALKEY` to bind `r` only, and trust `m` from the witness: fatal.
  A spender could recreate the output under their own taptree and drain it
  (spec 10.4).
* Take `m` from the witness and verify `TREE_SPK(r, m)` against the spent
  scriptPubKey with `OP_TX`: two EC scalar multiplications and two point
  additions, ~200 bytes, no self-reference. Chosen (spec 6.4, 8.2).

A pleasant side effect: `m` is the tree identifier, and `OP_INTERNALKEY`
becomes unnecessary.

### F5. Eviction is as important as exit

Timeout-tree and Ark designs fail the *operator* when one participant is
unresponsive: the whole tree must be published to reclaim capital. With the
covenant, the operator can remove one leaf in constant size, paying it out
in full, after a per-leaf lease height (`evict_after`, spec 7.2 rule 4). This
replaces whole-UTXO expiry with per-leaf leases renewable by a cooperative
`UPDATE`. It is also exactly the "force close" right a channel counterparty
needs for channel leaves.

### F6. Amount conservation must not trust the operator's arithmetic

Rather than tracking deltas, every script recomputes the total from the
path and requires (a) the recomputed *old* total to equal the spent amount
and (b) the recomputed *new* total to equal output 0's amount. Fees are
therefore exogenous, except that an owner-authorised exit may take fees from
its own payout (spec 7.2 rule 3). Evictors cannot.

### F7. Position 0, output 0

Two tree outputs spent in one transaction would both claim output 0.
Requiring the tree input at index 0 (`OP_TX CURR_INPUT_NUMBER`) removes the
ambiguity and costs three bytes. Tree merges are out of scope.

### F8. Encodings

* GSR numbers are little-endian, minimal, unsigned. Sums are hashed as
  fixed 8-byte little-endian (`PAD8`), not the MS-SMT's big-endian, to avoid
  `OP_BYTEREV`. Truncation by `PAD8` is harmless because the final sum is
  compared to an 8-byte transaction amount (spec 10.6).
* Leaves are fixed 116 bytes so fields are extracted with constant
  `OP_SUBSTR` offsets and no length-prefix parsing.
* Directions use `MINIMALIF` encodings so `OP_NOTIF` consumes them directly.
* Sibling nodes travel as one 40-byte element; the script splits the sum
  with `OP_RIGHT`.

### F9. Concurrency is the honest weak spot

Every transition contends for one UTXO. Exits conflict with the operator's
batches and vice versa; BIP-125 makes the replacement cost bounded but
non-zero (spec 10.5). Cooperative exits and anchor outputs mitigate; a
sharded deployment (several trees) bounds blast radius. This is inherent to
any single-UTXO design and is noted rather than solved.

### F11. Aligning with the EC ops draft BIP

The first draft of the spec assumed `OP_ECSCALARMUL`/`OP_ECPOINTADD` from
the GSR "new opcodes" list, whose semantics are unspecified. The author's own
draft, "Elliptic Curve Operations for Bitcoin Script"
(`Roasbeef/bips`, branch `ec-ops-bip`, PR bitcoin/bips#1945), does specify
them: `OP_EC_POINT_ADD` (0xbb), `OP_EC_POINT_MUL` (0xbc, `[point scalar]`
with the empty vector standing for `G`, scalars 32-byte big-endian reduced
mod `n`), `OP_EC_POINT_NEGATE` (0xbd) and `OP_EC_POINT_X_COORD` (0xbe);
33-byte compressed points throughout; infinity as the empty vector; costs
of 10/30/5/1 sigops units. The simulator, the scripts and spec section 4
now follow that document. Two consequences:

* `TREE_SPK` costs `2×30 + 2×10 + 2×1 = 82` sigops units (820,000 varops)
  rather than four signature checks; exits now use about 6% of the varops
  budget instead of 12%.
* `OP_EC_POINT_X_COORD` replaces `32 OP_RIGHT` and validates the point.

Two nits in that draft surfaced while aligning: its "Computing a Taproot
Tweak" example pushes `<tweak> <empty_vector>` before `OP_EC_POINT_MUL`,
which puts the point on top, whereas the execution rules and `reference.py`
pop the scalar first; and its opcode numbers collide with `OP_TX`'s draft
(0xbd) and BIP-443 (0xbb). The simulator parks `OP_TX` at 0xbf as a
placeholder.

### F10. Second-pass findings

A re-read of the draft spec against the scripts found four gaps, all now
closed and tested:

* **Hash types.** An owner exit only bounds the payout from above, so a
  signature with `SIGHASH_NONE`/`SINGLE` would let a relayer lower the
  payout and pocket the difference as fee. Exit signatures must commit to
  all outputs (spec 7.2, 10.7).
* **Empty tree.** When the last leaf exits, the recreated tree output would
  carry 0 sats: consensus-valid, non-standard, and pointless. `FINAL` now
  recognises `r' = E_D` and leaves output 0 unconstrained (spec 7.7).
* **Fully drained `CLAIM` source.** A voucher for the whole balance would
  leave a zero-amount leaf. The script now substitutes `E_0` (spec 7.5).
* **Duplicate leaves and vouchers.** A voucher binds the source leaf by
  content, so two byte-identical leaves would let one voucher be redeemed
  twice. The leaf now carries a creation-time `nonce` separate from the
  `seq` that `CLAIM` increments; uniqueness of `(owner_key, nonce)` is a
  requirement on creators in the dense profile and structural in the sparse
  profile, where it defines the position (spec 5.2, 10.3).

`EXIT_K` was also implemented rather than merely described, to confirm the
composition rule (spec 7.6): step `i` proves against the root produced by
step `i − 1`, and the test suite checks that a stale second path fails.

### F12. Proof compression: empty elements beat the bitmap on-chain

The MS-SMT BIP compresses proofs with a bitmap of empty levels. Both that
encoding and a simpler one (an empty sibling is a zero-length witness
element; the script tests `OP_SIZE`) were implemented for the sparse
profile and measured. The bitmap costs 276 more bytes of script at `D = 32`
and 564 at `D = 64`, because each level must extract a bit and conditionally
`OP_ROLL`, and saves only `D − ceil(D/8)` witness bytes. The spec keeps the
empty-element form on-chain and recommends the bitmap as the off-chain wire
format (spec 5.5).

### F13. The irreducible opcode set

Asked what the smallest sufficient subset of the candidate opcodes is, the
answer (spec 4.4) is: BIP-342 tapscript, BIP-441 numeric semantics,
`OP_CAT`, and one EC tweak primitive (BIP-449 `OP_TWEAKADD` is enough, and
cheaper than the general EC ops for this use). Everything else is
convenience: field extraction is replaced by witness-supplied fields under
`OP_SIZE` checks re-joined with `OP_CAT`; fixed-width padding by adding
`2^64` (which is why node hashes now use the 9-byte `enc64` encoding); bit
extraction by an `OP_IF`/`OP_ADD` accumulator checked against a `CAT`-split
hash; and `OP_TX` by the `OP_CHECKSIG`-with-generator trick at a large
witness cost. `OP_CHECKSIGFROMSTACK` cannot be emulated and is needed only
for vouchers. A minimal-inventory `EXIT_1` is implemented and tested; it
costs 13% more script than the full-inventory one.

### F14. Batched joins, and the 16M-leaf comparison

Joins batch by the same sequential composition as exits: `JOINK_K` verifies
`K` single-leaf insertions in one script under one operator signature, each
against the root the previous step produced. Measured (`spec 11`): a second
join costs about 2.2 kWU dense at `D = 16` and 4.9 kWU sparse at `D = 32`,
against 3.9 and 6.6 kWU for a standalone transaction. So the earlier remark
that onboarding 16M users into a sparse tree needs 16M transactions was
wrong as stated; it needs 16M path verifications, which can be packed into
as few transactions as the varops budget and relay policy allow. The total
byte cost is what does not change: about 5 kWU per leaf in the sparse
profile against a constant 2 kWU per graft of any size in the dense
profile, because derived positions are not contiguous and cannot be grafted.

For a tree of 2^24 leaves, per exit: dense `D = 24` about 5.1 kWU, sparse
`D = 32` about 7.5 kWU (at that density 25 of 32 sibling levels are
non-empty, so compression buys little). For onboarding: 2^24 × 5 kWU
≈ 80 GWU sparse versus 65,536 grafts of 256 leaves ≈ 0.13 GWU dense. Use the
dense profile, or shard into dense trees of depth 16–20, for anything at
that scale; the sparse profile is for key-addressed trees that grow leaf by
leaf. A hybrid, dense subtrees hung at derived positions of a shallow sparse
top, would give bulk joins with key-addressed sharding and is noted but not
designed.

### F15. Multiproofs: fix the shape, not the flags

Asked whether multi-path verification could cut the hashing, the useful
distinction turned out to be between runtime-shaped and script-shaped
multiproofs. A general verifier for any `K` positions is a stack machine
(push sibling / hash top two) driven by witness flags; script can run it
with the machine on the altstack, but every unrolled step carries both
branches, so it saves witness and varops and not script, and script is the
cost that matters. A verifier whose shape is fixed by the taptree leaf is
straight-line code with static stack depths: the internal nodes of the
union are hashed once, no flags, no duplicated branches. Since the operator
assigns positions in the dense profile, the natural shape is an aligned
subtree, and the natural use is a *cohort*: graft a batch with a common
lease into one subtree, sweep it with `EVICT_SUBTREE_h` when the lease
expires. Measured at `D = 16`: a 64-position sweep is 16.1 kB of script
against 105.8 kB for 64 sequential evictions, about 0.45 kWU per leaf. The
`POSTORDER` generator is a template for other shapes. Together with
grafting this gives constant-shape add and remove for whole cohorts, which
is the operational model the essay's "unified batching" was reaching for.

### F16. Three tiers, one format

Every transition now exists in three opcode tiers (spec 4.5): FULL (GSR
`0xC2` + `OP_TX` + CSFS + EC ops), MID (`0xC0` + `OP_CAT` + `OP_TX` + CSFS +
`OP_TWEAKADD`) and MIN (`0xC0` + `OP_CAT` + `OP_TWEAKADD`). The tree format
is shared, which required one trick worth recording: `0xC0` has no way to
widen a script number to a fixed 8 bytes, so the MID/MIN scripts take a
witness-supplied zero pad and prove it correct with `OP_CAT` and `OP_SIZE`
(`PADZ`). Two other `0xC0` facts shaped the tiers: 4-byte operands cap
every sum at 2^31 − 1 sat, and `MINIMALDATA` policy forbids using raw
little-endian fields (`evict_after`, `pos_lo`) as numbers, so those arrive
as minimal numbers with a pad, and sparse nonces are ground until `pos_lo`
is minimal. MIN's introspection is constructive: the script builds the
BIP-341 sighash message from derived values and raw witness pieces and
checks a generator-key signature with `s = e + 1`, formed by grinding a free
field until `e` ends in `0x00`. The simulator now computes the real BIP-341
message so this is tested end to end, and the same message is what
`txscript.CalcTapscriptSignaturehash` produces, which the Go implementation
uses for cross-checking.

### F17. Channels in leaves need three tree-layer rules

Layering Lightning channels on the tree (`spec/channel-leaves.md`) works
in the FULL and MID tiers because `OP_TX` with `COLLATE` plus
`OP_CHECKSIGFROMSTACK` gives a signature over everything except the prevout,
so commitment transactions can be signed before the funding output exists
and rebound to whichever payout index the exit lands on. Working it through
exposed three places where the *tree* rules were too lenient for a leaf
whose balance is not the owner's alone:

* the FULL owner exit may pay less than `leaf.amount`; for a channel leaf
  that is theft of the counterparty's balance, so 7.2 gained the
  exact-payout variant `EXIT_K^=` (a tree-creation parameter, four bytes
  shorter, visible in `m`);
* `CLAIM` lets the owner carve value out of any leaf with a lone signature;
  the `seq + 1` size check already makes one value of `seq` unclaimable, and
  that is now the deliberate, tested `SEQ_FINAL` marker. It is
  tier-specific (`0xFFFFFFFF` in FULL, `0x7FFFFFFF` in MID) because
  `CScriptNum` reads `0xFFFFFFFF` as a negative number whose successor
  fits, which the MID tests demonstrate;
* `evict_after` was described as a lease, but for a channel it is the
  height before which the counterparty cannot enforce anything on-chain, so
  routing channel leaves need `evict_after = 0`.

Two honest limits stand: MIN cannot host channels (its constructive sighash
necessarily commits to the prevout), and the shared UTXO serialises
force-closes at about 25 per block, which is now a sizing rule in 10.5.

### F18. What the Lean model made precise

Formalising sections 5, 7 and 10.2 in Lean (`formal/`) confirmed the
security argument and sharpened three points:

* The covenant conserves *sums* unconditionally (`Steps.sum` needs no
  assumption about the nodes it is shown), but it guarantees *exits* only
  under grounded nodes: a `JOIN_h` graft whose `(new_hash, new_sum)` has
  no preimage tree freezes the grafted value forever. The covenant protects
  the sum; the joiners' off-chain path check (9.2) protects membership.
  That MUST was already in the spec; the proof shows it is load-bearing.
* `CLAIM` requires the claim position to be empty *after* the source step,
  not before, so a source drained to zero may serve as the claim position
  in the same transaction. Harmless, and now stated.
* The `SEQ_FINAL` split between tiers is a theorem, not a test artefact:
  `minimalLE (2^32)` has five bytes while the `CScriptNum` of `−(2^31−1)`
  is `ff ff ff ff` with a four-byte successor.

The model is parametric in an idealised hash (injectivity plus tag
separation) and a `TREE_SPK` injectivity hypothesis; the tapscript bytecode
is deliberately outside it and stays covered by the simulator, the golden
vectors and the Go cross-checks.

### F19. The CCV tier: what changed and what did not

BIP-443 `OP_CHECKCONTRACTVERIFY` (issue #3) replaces every taproot-key
binding of the FULL tier with a native opcode call, in a fourth
tree-creation choice (spec 4.6). What changed:

* The state key is the BIP-443 data tweak of `NUMS` by the root hash
  (untagged `sha256(NUMS || r)`, then the ordinary TapTweak), so a CCV
  tree and a FULL tree with the same root have different scriptPubKeys;
  the tier is a tree-creation parameter, and `tools/layertree_ref.py`
  grows `ccv_internal_key` / `tree_spk_ccv` beside the originals.
* `r` and `m` leave the witness entirely: `CHECK_INPUT` with the `-1`
  taptree operand binds the old root to the input under the input's own
  script set, which is 10.4's whole argument made a opcode semantic
  (F4's conclusion, native).
* The EC ops draft and `OP_TWEAKADD` drop out of the tier's dependency
  list. Measured at dense `D = 16`: `EXIT_1` 1,716 / 838 bytes of
  script / witness (FULL: 2,101 / 902), `JOIN_2` 1,456 / 679, `UPDATE`
  1,752 / 1,016.

What did not change, and why:

* **Amount reads remain necessary.** CCV ties amounts to the input's
  amount, not to script-computed values, so a sum tree still needs one
  `OP_TX` read per constrained amount: `out0.amount == ns` (rule 5),
  `payout == leaf.amount`. CCV removes the key arithmetic, not the
  introspection.
* **The input-amount equality stays.** The first cut of the tier dropped
  `os == input amount`, planning to lean on the opcode's residual
  bookkeeping; execution showed that keeping it costs one `OP_TX` read
  and makes the tier's amount semantics identical to every other tier,
  so it was restored.
* **Output 0 uses the assign mode, not DEDUCT.** DEDUCT would pin
  output 0 to the tree input's own amount and make every value-adding
  transition (a JOIN, a funded UPDATE) unspendable: the residual of the
  tree input alone cannot cover the new root's sum. The assign mode's
  floor plus the numeric equality keeps rule 5 exact and lets the
  joiner's funds arrive above the floor.
* **Payouts are exact.** With assign-on-output-0, a payout short of
  `leaf.amount` strands its difference in the residual and forces
  output 0 above `ns`, breaking rule 5; so the tier takes the MID/MIN
  trade (exact payouts, exogenous fees) rather than FULL's
  fee-from-payout option.
* **CLAIM and CLAIM^h bind a `tree_id` instead of `m`.** The voucher
  message of the other tiers bound `m`, which the CCV witness does not
  carry and which BIP-443 exposes only as an operand special value,
  never as a stack item. Dropping `m` alone would let a voucher replay
  across two trees sharing an owner key, so the CCV tier's vouchers bound
  a per-tree constant `tree_id` baked into the scripts. The paper review
  (`paper/reviews/crypto.md`, finding 6) then showed that `m` never did
  the job in FULL and MID either: it names a rule set, which two trees
  with the same parameters share, so a voucher over `m` verified in both
  against identical source-leaf bytes. Since spec 0.10.0 every tier binds
  `tree_id` (6.2, 7.5): a creation parameter, unique per lineage, carried
  by every `CLAIM` script as a constant and inherited across a
  `DETACH_h`, so vouchers survive a detach. The CCV scripts now share the
  FULL and MID voucher checks token for token. `CLAIM` and `CLAIM^h` are
  the only CCV scripts that need `OP_CHECKSIGFROMSTACK`, so they are
  tree-creation options like `SPLIT`. `CLAIM^h` signs the same message
  plus the payment hash.
* **SPLIT is in.** It is authorised by the source owner's transaction
  signature, which commits to the spent scriptPubKey without naming `m`,
  so the FULL carve body carries over with only the binding swapped:
  dense `D = 16` 3,338 / 1,610 against FULL's 3,728 / 1,674. A CCV tree
  thus keeps member-to-member payment without vouchers. `UPDATE^x` is
  measured in both numerics (dense `D = 16` 1,759 / 1,080 in `0xC2`).
* **Two tree inputs cannot share output 0.** Every call names the current
  input, so two trees in different states cannot meet; two inputs with
  the same state are stopped by BIP-443's per-output minimum, which
  accumulates both residuals while `out0 == ns` allows only one. The
  BIP-443 amount rules this depends on are pinned in spec 4.1 [A-6]
  against a named commit of the BIP and tested one by one.
* The fold, the chained-step consistency checks, sparse position
  derivation and the authorisation are the FULL tier's, byte for byte;
  the Lean model's `Binding.lean` builds the CCV state key as
  `CCVTweak.binding`, a second `BindingModel` whose injectivity is
  proved from the two tweak stages (data tweak, then TapTweak).

## 3. Things deliberately left out

* Aggregate per-node keys for cooperative subtree replacement (spec 13.5):
  reintroduces the interactive signing round the design is trying to avoid.
* Hash-locked vouchers and swap flows (spec 13.6): judged at the time to
  belong with the liquidity-marketplace design in the notes rather than the
  base protocol. Reversed later: they are now specified and implemented as
  `CLAIM^h` (spec 7.5.1, 9.6.1, 10.3), which cost 8 bytes of script over
  `CLAIM` and no new opcode.
* MuSig2 adaptor signatures (from `design/layertree.md`): an off-chain
  concern for channel leaves and swaps; nothing in the base protocol needs
  them.

## 4. Validation

*This section records the state at the time of the review. The suites have
grown since; `design/status.md` and spec section 14 carry the current
counts, and the check totals below are historical.*

`tools/test_scripts.py` executes all four scripts against a reference tree
at depths 4 and 16 (dense) and 8 and 32 (sparse) in a simulator of the required opcode subset, with 208
checks including the negative cases that matter for the findings above:
attacker-chosen `m` (F4), forged leaf amount and stale root (F3), unconserved
tree amount (F6), join over an occupied position and underfunded join,
eviction before the lease height and evictor shortchange (F5), voucher
replay after source change and over-claim (F1). All pass. The simulator is
not consensus code; the assumptions about the EC opcodes are listed in
spec 4.1.
