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

### F20. Carves inherit the lease

The paper review (`paper/reviews/crypto.md`, finding 9) found that
`SPLIT` and a self-issued `CLAIM` accepted any 116-byte claim leaf, which
made eviction a property of a leaf rather than of a balance: an owner
facing eviction could move its whole balance into a fresh leaf with a
`NUMS` evictor or a far `evict_after`, and any member could carve a
one-satoshi `NUMS` leaf into an empty position of a cohort and block
`EVICT_SUBTREE_h` on it for good, at about 1,020 vB per single eviction
instead of 158 to 203 per leaf swept.

Spec 0.10.0 adds 7.5 rule 5: the claim leaf's `evictor_key` MUST equal
the source's and its `evict_after` MUST be no later. It is two field
comparisons in every tier (25 bytes under `0xC2`; 60 under `0xC0`, where
the raw `le32` fields are not numbers and the witness supplies each
`evict_after` as a minimal number with a `PADZ` pad, as `EXIT_1` already
does for the lock time), a `claim_evictable` theorem in Lean, and a
builder check in Go. What it does not reach is a leaf the operator
admitted as non-evictable: that leaf can still carve dust of the same
terms into any empty position, and the suites check that it can, so the
residual stated in 10.8 (admit such leaves only where a blocked sweep is
acceptable, and prefer a finite lease to `NUMS`) is a tested claim rather
than a hope. A dedicated credit leaf with a `NUMS` evictor (10.3,
`design/receive.md`) is unaffected: its carves inherit the `NUMS`
evictor, which is what the recipient wants.

### F21. A detached cohort keeps its rules

`DETACH_h` compiled `m_h` from the reference set at depth `h`, which has
no `EXIT_K^=`, no `UPDATE^x`, no `CLAIM^h` and no sweeps, so a cohort of
channel leaves lost its exact-payout exit the moment it was detached and
Appendix C.6.1 stopped holding, contrary to 7.10's "channel leaves are
unaffected" (`paper/reviews/crypto.md`, finding 7). The option set a tree
is created with is now explicit (`TreeOptions` in
`tools/layertree_scripts.py`, `FullTreeOptions` in `script/full.go`), and
7.10 rule 3 says `m_h` MUST be that set compiled at depth `h`, the same
`tree_id` and `OPERATOR_KEY` included, dropping only the heights that do
not fit. The test builds a channel-hosting parent, detaches a cohort of
channel leaves, checks that the child's identifier is the parent's set at
depth `h`, that an `EXIT_1^=` from the child pays exactly and rejects a
shortfall, and that the parent's `DETACH_h` rejects output 1 under the
reference set's `m_h`. The 10.1 trust table gained the line the review
asked for: the operator can move a cohort to its own output and cannot
change its rules, keys or balances by doing so.

### F22. `REWRITE_h`'s amount-only exemption reaches channel leaves

The protocol audit (`design/audit/protocol.md`, A1) found that 7.9 rule 3
lets the operator alone raise any leaf's `amount`, including a channel
leaf's above the capacity its signed states commit to, after which every
pre-signed update pays a nonzero fee beside a zero-value ephemeral
anchor and no default node relays it. It is reachable in any tree that
carries `REWRITE_h` or `REWRITE_h^x` and hosts channel leaves in a
cohort, at 1 sat per leaf. The fix is a script rule: the exemption does
not apply when `old_i.seq = SEQ_FINAL`, with C.2.4's "merely burns"
sentence corrected. Status: fixed (spec 0.11.0: 7.9 rule 3 and the
8.9 listing, every tier's `REWRITE_STEP`, the Go mirror and the golden
vectors, with the probe as a `test_rewrite` negative and the signed raise
as a positive).

### F23. Sub-dust carves squat a slot for good

`CLAIM` and `SPLIT` accept a claim leaf of 0 or 1 sat, and every
transition that removes a leaf must pay it exactly to a P2TR output, so a
leaf below 330 sat can never be removed by a standard transaction: it
blocks its cohort's sweep and every graft over it (audit A2). Any member
can do it with one `SPLIT`, and a small honest redemption does it by
accident. The fix is a script rule in 7.5, a `DUST_MIN` floor on the
claim amount and on a nonzero residual. Status: fixed (spec 0.11.0:
`DUST_MIN` in 6.2 and 7.5 rule 6, `CARVE_RULES` and `DRAIN_RULE` in
every tier and both numerics, the Go mirror and the golden vectors, with
the 0, 1 and residual-1 probes as negatives in every suite).

### F24. Plain `REWRITE_h` reopens credit-leaf and channel voiding

10.3's credit-leaf checklist and C.6.6's `UPDATE^x` protection both
missed that plain `REWRITE_h` asks only for the owner's and the
operator's signatures, so the issuer of a credit leaf, or the owner and
operator of a user-to-user channel leaf, can rewrite it down and void
what the `^x` variants protect (audit A3). It is reachable in any tree
that follows the spec's recommendations and adds `REWRITE_h` for
batching. Fixed in text: 10.3 now lists `REWRITE_h^x` in place of
`REWRITE_h`, or no `REWRITE_h`, and has the recipient check `m`; C.6.6
and C.9.7 require the counterparty to verify from `m` that no plain
`REWRITE_h` is present; `design/receive.md` says the same. 7.5.3's
reference to the checklist, and 7.9 rule 7 becoming a MUST in trees
that carry `UPDATE^x` or `CLAIM^x`, landed with the spec 0.11.0 rule
change.

### F25. Eviction voids vouchers

A voucher binds its source leaf's bytes, so the evictor's `EXIT` or a
cohort sweep voids every outstanding voucher against the leaves it
removes, although the issuer broke no rule, and a holder who paid for
one is left with the issuer's goodwill (audit A4). It is reachable
whenever a voucher is issued against a leaf whose lease can pass before
redemption confirms. No script fix exists. Fixed in text: 9.6 states it
and has the recipient read the source's evictor and lease and treat a
voucher whose lease can pass within `Delta(q)` of 10.5 as unsecured;
9.6.1's flow and a new 9.6.2 rule 5 put the same check before the swap
counterparty pays; 10.3 and 10.8 add eviction and sweeps to the events
that void vouchers.

### F26. Partial vouchers need an empty position the operator controls

A partial-balance voucher places its claim leaf in an empty position
(7.5 rule 3), and the operator controls empty positions through
`JOIN_0` and `DETACH_h`, so it can detach a cohort full and hold every
partial voucher against it unredeemable (audit A5). Reachable by the
operator at the cost of a detach and some joins. Fixed in text: 7.10
and the operator row of 10.1 say so, and 9.6 has the recipient prefer a
full-balance voucher or verify an empty position in the source's
cohort. The structural fix, a `CLAIM` that credits a leaf the recipient
already holds, is recorded as 13 item 11 and is not specified.

### F27. `NUMS`-evictor credit leaves are squat tokens

A voucher binds the claim leaf's bytes and not its position, so the
holder of any voucher against a `NUMS`-evictor leaf chooses where its
carve lands and can block any cohort's sweep for good; 10.3 and
`design/receive.md` recommended exactly that evictor for credit leaves
(audit A6). Reachable by every voucher recipient of such an issuer, at
no extra cost. Fixed in text: 10.3 and `design/receive.md` now say a
credit leaf SHOULD carry a finite lease with the operator as evictor,
which costs the recipient nothing because eviction pays the whole
balance to its exit key, and 10.8 says the redeemer chooses the slot
and operators SHOULD keep cohorts full or detached. This narrows F20's
closing remark about credit leaves.

### F28. One later lease holds up a cohort sweep

9.4 said renewed members "are not swept", but 7.7 rule 2 needs a lock
time of at least every leaf's `evict_after`, so a leaf renewed in place
holds up its whole cohort's sweep until the new lease, and a member of a
later-lease cohort can carve a leaf on its own terms into an earlier
cohort's gap, which 7.5 rule 5 permits (audit A7). The renewal half is a
spec inconsistency; the carve half costs the attacker one `SPLIT`.
Fixed in text: 9.4 is corrected and has renewal relocate the leaf into
a cohort whose lease matches, with leases aligned per cohort and cohorts
kept full or detached; 10.8 and `design/graft.md` match. A sweep
variant that passes unexpired positions through is left for later.

### F29. Member-funded grafts cannot be fee-bumped by replacement

Every funder of a member-funded graft signs with `SIGHASH_DEFAULT`, so
raising its fee by replacement needs every funder to sign again (audit
A8). Cost and liveness only. Fixed in text: 9.2 says such a graft
SHOULD carry an operator change output or a P2A anchor so it can be
bumped by CPFP, and `design/graft.md` notes the same.

### F30. A settlement with a sub-dust output is not relayable

`settle_n` is zero-fee with a zero-value P2A anchor, so any further
output below 330 sat gives it two dust outputs, which no default node
relays, and the reference signs exactly that at state 1 of every
single-funded channel (`b_V = 0`); either party can leave the channel
in such a state by paying the other below dust or offering a sub-dust
HTLC, and the capacity is then locked at `U_n` at the relay layer
(`design/audit/channels.md`, B1). Reachable by the counterparty at no
cost, and by default at opening. The fix is a rule in C.3.4: every
non-anchor settlement output MUST be at least the dust threshold, and
trimmed value goes to the anchor; `settle_outputs` and
`StateProposal.Validate` enforce it. Status: fixed (Appendix C 0.4.0:
`DUST_CHAN` in C.3.4, the trimmed value carried by the anchor, C.5.5;
`settle_outputs`, `ChanOpen.DustChan` and `StateProposal.Validate`, with
the single-funded state 1, a 329-sat balance and a 200-sat HTLC as cases
in `test_chan.py` and `msg/chan_test.go`).

### F31. The receive flow inverted 9.6.2 rule 1

`design/receive.md`, 10.3 and the site's payment page had the recipient
hold the preimage and the operator issue a hash-locked voucher before
the inbound HTLC settled, which is the ordering 9.6.2 rule 1 forbids; on
the recommended credit leaf the operator cannot advance `seq`, so a
voucher whose HTLC failed stays redeemable for good
(`design/audit/channels.md`, B2). Reachable by any wallet user with a
credit leaf, at no cost, once per failed receive. Fixed in text: 10.3
now has the issuer obtain the preimage and settle the inbound HTLC
before it issues or reissues the cumulative voucher, which is a plain
voucher under `CLAIM^x`, and keeps the hash-locked form for the 9.6.2
ordering; `design/receive.md` (the instrument, the cost table and the
closing section) and `site/components/payment.html` (the credit-leaf
caption and prose) follow, and `site/components/swap.html` no longer
says receiving uses the hash lock.

### F32. A credit leaf's unissued capacity belongs to the recipient

`EXIT^=` and eviction pay a credit leaf's whole amount to the
recipient's exit key and `UPDATE^x` needs that key, so capital the
operator has not vouched for is recoverable only with the recipient's
consent; `design/receive.md` told the operator to fund a credit leaf
like an inbound channel (`design/audit/channels.md`, B3). Reachable by
the recipient doing nothing. Fixed in text: 10.3 says the issuer SHOULD
fund a credit leaf only with what it has vouched for or is about to,
and SHOULD top it up by an amount-only `REWRITE_h^x` or an `UPDATE^x`
the recipient signs; `design/receive.md` replaces the inbound-channel
analogy and adds the top-up to its cost table; the payment page says
the same.

### F33. Stale updates delay a channel's settlement past the C.4.4 budget

An `update_m` binds to `U_j` for any `j < m`, so a counterparty holding
old states can confirm them one per block ahead of the honest update,
and C.4.4's two blocks of margin absorb two; at the spec bound a third
lets the offerer's timeout sweep become final before the payee's claim
(`design/audit/channels.md`, B4). Reachable by the HTLC offerer at about
313 vB per block of delay, against an honest party who can outbid in
the mempool. The fix adds a `beta_chan` term to the C.4.4 budget and a
fee-reserve and replacement rule to C.4.4, C.5.5 and C.9.6. Status: fixed
(Appendix C 0.4.0: `beta_chan` in the C.4.4 bound and
`cltv_budget_spec`, the reserve rule in C.5.5, replacement in C.9.6;
`test_chan.py` runs two and three stale updates at the bound and three
at the bound with `beta_chan = 3`).

### F34. F22's fix had reached the Lean model only

The spec header already read 0.11.0 and `formal/LayerTree/Cohort.lean`
excludes `seq = SEQ_FINAL` from `REWRITE_h`'s amount-only exemption, but
7.9 rule 3 and `_rewrite_step` were unchanged, so the operator could
still raise a channel leaf's amount alone at 1 sat per leaf; the probe
was accepted with no owner signature (`design/audit/channels.md`, B5).
Reachable as F22. The fix is F22's script rule in 7.9 rule 3, the
generators, the Go mirror and the golden vectors, with the probe as a
`test_rewrite` negative, and F22's status naming which layers carry it.
Status: fixed with F22 (spec 0.11.0, Appendix C 0.4.0).

### F35. `chan_id` binds `m`, which is not unique to a tree

C.2.2 says binding `m` stops a state signed for one tree from being
replayed in another, but 6.2 has two trees with the same parameters
share `m`, and a `DETACH_h` moves the leaf under `m_h`, so the
identifier in the channel scripts stops matching its tree
(`design/audit/channels.md`, B6). No attacker was found: a replay needs
someone to fund a duplicate leaf, and C.9.1 and 5.2 carry the binding in
practice. The audit recommends binding `tree_id`, as 7.5 does for
vouchers, at no script cost. Status: fixed (owner decision 2026-10-10,
`design/status.md` decision 24, Appendix C 0.5.0). `chan_id` binds
`tree_id` in C.2.2 and C.9.1 (text, with 9.8 and 7.10 of the base spec
following); in the Python reference (`tools/layertree_chan.py`, with the
C.12 negatives moved from `m` to `tree_id` and a positive on two
`CLAIM`-free trees that share `m`); in the Go `ChanParams` and `ChanOpen`,
whose `TreeID` field now carries what its name says; and in the `chan`
golden vectors, which derive from the golden `tree_id` rather than the D4
root. Zero bytes of script changed.

### F36. Two Appendix C sentences a counterparty relies on were wrong

C.6.2 said a compromised `owner_key` costs only a force-close, but in a
lenient tree 7.2 rule 3 accepts a zero payout and the key takes the
whole capacity; C.7's CCV row said a CCV tree has no `CLAIM`, though
`CLAIM` and `CLAIM^h` are CCV scripts since 0.10.0 (4.6), so a reader
would skip the `SEQ_FINAL` check (`design/audit/channels.md`, B7).
Reachable by the holder of a stolen `owner_key` in a lenient tree, and
by an owner whose counterparty trusted C.7. Fixed in text: C.6.2 states
the lenient-tree consequence and that a channel-hosting tree SHOULD use
`EXIT^=`; C.7's CCV row applies C.6.5 as FULL does, with each numerics'
`SEQ_FINAL`. The audit's other text item, naming the offerer's deadline
in C.5.6, is fixed with it.

### F37. The Go fold wraps at 2^64, so a Go member can be sold a leaf nobody can pay

`tree.Parent` added sums in `uint64`, so a sibling node of sum
`2^64 - a + 330` folded with a leaf of amount `a` to a parent of sum 330,
and `msg.Proof.Verify` and `JoinOffer.VerifyMember`, the Go form of 9.2
step 3(c), accepted the path where the Python reference raises and every
script rejects the later spend (`design/audit/go.md`, G1). Reachable by a
malicious operator selling an operator-funded leaf to a member who pays
off-chain after the verification 9.2 tells it to run; the member loses
the payment and the leaf can never exit. Fixed: `tree.Fold` returns an
error on carry (`tree.AddSum`, `bits.Add64`) and `msg.decodeNode`
rejects any node sum of 2^51 or more (`tree.MaxSum`); regression tests
`TestFoldRejectsOverflow`, `TestVerifyMemberRejectsWrappedSum`,
`TestDecodeNodeRejectsLargeSum`. The golden scripts are untouched, since
the generators fold no sums.

### F38. The Go join verification never looked at the unsigned transaction

`JoinOffer.VerifyMember` checked the leaf and both paths but not 9.2 step
3(d): output 0 is `TREE_SPK(r', m)` with amount `S + new_sum`, so a
self-funding member could sign an offer whose transaction paid output 0
anywhere (G2). Fixed: the offer's `UnsignedTx` is deserialised and output
0 compared against the recomputed root and sum; the offer carries no
spent output, so step 3(a) stays with the caller and the doc comment says
so. Regression test `TestVerifyMemberChecksOutput0`.

### F39. Every Go message decoder allocated from the untrusted length

The `msg` decoders used `tlv.Stream.Decode` without a record cap and
`DVarBytes` allocated the declared length, so a ten-byte stream claiming
2^62 bytes panicked and one claiming 2^31 allocated two gigabytes before
failing (G3). Reachable by any peer that sends a message. Fixed:
`boundedVarBytes` rejects a declared length over its cap before
allocating, `decodeLimited` wraps each message in an `io.LimitReader`,
and `JoinOffer.Decode` no longer uses `DecodeWithParsedTypes`, which
allocated for unknown types too; the channel decoders followed through
`decodeChan`, with caps per record and a 2,322-HTLC ceiling from the
100,000-vB standardness limit. Regression tests
`TestDecodeRejectsOversizedRecords` and
`TestChanDecodeRejectsOversizedRecords`.

### F40. The Go exit builder accepted a fee in an exact-payout tree

`FullTreeOptions{Exact: true}` compiled `EXIT_K^=` under the name
`EXIT_K`, and `BuildExit` with a fee built, signed and verified a
transaction the script rejects (G4), which is exactly the channel-hosting
configuration. Fixed: `TreeState` carries the options it was compiled
with (`NewTreeState` compiles the taptree from them, so `m` and `tree_id`
agree with the options by construction) and `BuildExit` refuses a fee
under `Exact`; three exact-exit positives replay through the simulator
(45 `txn` cases).

### F41. Four more inputs the Go builders accepted and the scripts reject

A timestamp-range lock time on an eviction or sweep, a claim whose
voucher does not verify, a claim position outside the tree, and leaves
that fail 5.2 (G5). Fixed in the builders with one negative each in
`TestBuilderRejects`; two pre-existing sweep negatives that failed on a
missing script rather than on their rule now fail on the rule.

### F42. `PosLoMinimal` ignored the depth

The MID sparse scripts require `pos_lo < 2^D` as well as a minimal
encoding; the Go helper checked only the encoding, accepting about 44,000
of 100,000 nonces at `D = 28` that the Python `pos_ok` rejects (G6).
Fixed: `PosLoMinimal(depth)`, pinned against the Python rule.

### F43. Three validation edges in the Go channel messages

`SettleCollationLen` counts both balances when one is trimmed, so a valid
eight-HTLC single-balance state is refused under `0xC0`;
`RebindAnnounce.Decode` lets the state number wrap past `ChanStateBase`;
no decoder requires its mandatory fields (G7). Low. Fixed:
`SettleCollationLen` counts `70 + 43` per output the settlement carries
(C.7's `156 + 43h` is the two-balance case; an eight-HTLC single-balance
state is 457 bytes and accepted under `0xC0`), `RebindAnnounce.Decode`
rejects a state outside `1..ChanMaxState`, and every channel decoder
names the first mandatory record it lacks. Tests
`TestChanDecodeRequiresMandatoryRecords`, `TestRebindAnnounceStateRange`
and the eight- and nine-HTLC single-balance cases in
`TestChanMessageValidation`.

### F44. One Go field named two identifiers

`TreeID` held `m` in `ChanParams`, `ChanOpen` and `JoinOffer` and
`tree_id` in `Voucher` and `TreeState` (G8). Fixed: `chan_id` now binds
`tree_id` (F35), so the channel fields hold what they say; `JoinOffer`'s
field is `TaptreeRoot` (wire format unchanged); `TreeState.TreeID` is tied
to the compiled `CLAIM` constant through `NewTreeState`.

### F45. `DUST_MIN` is a constant in Go

The Go generators and `buildCarve` fix `DUST_MIN` at 330 where the Python
takes `dust_min`, so a tree created with a higher floor cannot be built
or mirrored (G9). Low, a gap rather than a bug. Fixed: `FullTreeOptions`
and `CCVTreeOptions` carry `DustMin` (zero means the RECOMMENDED 330),
the MID and MIN generators take it as an argument as the Python does,
`buildCarve` reads the tree's floor from its options, and
`TestCarveDustMinMatchesPython` pins carve scripts at a floor of 1,000
against the Python generator in every tier and numerics.

### F46. The `0xC0` carve rule compared leases as signed numbers

7.5 rule 5's lease check in the `0xC0` tiers (`carve_rules` in
`tools/layertree_mid.py`, shared by MID `CLAIM`/`CLAIM^h`/`SPLIT`, MIN
`SPLIT` and both CCV `0xC0` carves, and its Go mirror) bound each
`evict_after` to a minimal number with `PADZ` and compared them with
`OP_GREATERTHANOREQUAL`, a signed comparison, so a claim leaf whose field
is `01 00 00 81` (a negative `CScriptNum`, a valid pad) passed against any
source lease. The leaf keeps the operator as evictor but can never be
evicted: the evict branches run `OP_CHECKLOCKTIMEVERIFY` on that number
and CLTV fails on a negative operand (the adversarial review of
2026-10-10, probe at `D = 16` under MID `SPLIT`). Reachable by any member
of a `0xC0` tree with a carve, at the cost of one `SPLIT`; it is the squat
7.5 rule 5 was added to prevent (F19). FULL compares unsigned 4-byte
numbers and is unaffected; the Python `Leaf` and the Lean model admit no
such lease, so the hole was in the scripts only. 10.6's sentence that
`evict_after` needs no `NONNEG` because CLTV fails on a negative operand
was true for eviction and false for the comparison. Fix: `NONNEG` on the
claim leaf's lease number before the compare (4 bytes), in every `0xC0`
carve and the Go mirror, with the negative in each suite and 10.6 and 4.5
amended. Status: fix in flight (spec 0.12.2).

### F47. The Go join verification did not check the subtree path's height

`msg.JoinOffer.VerifyMember` folded the member's leaf through its subtree
path and the graft path without requiring the subtree path to have the
graft's height, so an operator could offer a bare leaf grafted at height
2 over a real `E_2`: `JOIN_2` accepts it (the script checks the slot and
the sum, not the node's shape) and the leaf then sits two levels short of
the depth every transition consumes, so it can never leave the tree
(review of 2026-10-10, Go probe at depth 8). Griefing of a self-funding
member who ran 9.2 step 3 as written; the operator gains nothing. Fix: the
verifier requires a nil subtree path only at height 0 and otherwise a
subtree path of exactly `h` levels, with a negative test; 9.2 step 3(c)
says the same. Status: fix in flight.

The same review found six low items, all text or test tightening: 7.2
rule 7's voiding remedy must name a leaf that differs (a byte-identical
self-`SPLIT` revives the authorisation) and a `SEQ_FINAL` leaf's owner
can only exit; 4.1 should state `OP_RIGHT` keeps the last `n` bytes; 7.9
and 8.9 should say any one-byte new element is the FULL marker, as the
code does; the `h = 6` MID rewrite negatives should assert the stack-limit
message; `Voucher.Verify` verifies over the voucher's own `tree_id`; and
the channel `StateProposal` carries post-trim outputs where the Python
`settle_outputs` trims. All in the same fix.

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
