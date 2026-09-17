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

## 3. Things deliberately left out

* Aggregate per-node keys for cooperative subtree replacement (spec 13.4):
  reintroduces the interactive signing round the design is trying to avoid.
* Hash-locked vouchers and swap flows (spec 13.5): straightforward on top of
  `CLAIM`, but they belong with the liquidity-marketplace design in the
  notes, not the base protocol.
* Channel-leaf commitment format (spec 9.8): only the requirement
  (rebindable commitments) is stated.
* MuSig2 adaptor signatures (from `design/layertree.md`): an off-chain
  concern for channel leaves and swaps; nothing in the base protocol needs
  them.

## 4. Validation

`tools/test_scripts.py` executes all four scripts against a reference tree
at depths 4 and 16 (dense) and 8 and 32 (sparse) in a simulator of the required opcode subset, with 186
checks including the negative cases that matter for the findings above:
attacker-chosen `m` (F4), forged leaf amount and stale root (F3), unconserved
tree amount (F6), join over an occupied position and underfunded join,
eviction before the lease height and evictor shortchange (F5), voucher
replay after source change and over-claim (F1). All pass. The simulator is
not consensus code; the assumptions about the EC opcodes are listed in
spec 4.1.
