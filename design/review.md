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

### F2. A 256-level sparse tree cannot be verified by loop-free script

Script has no iteration, so each proof level is unrolled. The MS-SMT's 256
levels (even with compressed empty-sibling bitmaps, which require 256
empty-hash constants or 256 unrolled hashes) are impractical. A dense tree of
fixed depth `D` (8–24) with operator-assigned positions gives a proof of
exactly `D` levels, and "prove this position is empty" is an ordinary
inclusion proof of the empty node, so joins need no non-inclusion proof at
all. History independence, the MS-SMT's other property, is not needed: the
operator allocates positions.

Measured cost per level is 88 bytes of script plus 40 bytes of proof
(spec 8.2, 11).

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
  twice. `seq` is now a creation-time nonce and uniqueness is a requirement
  on leaf creators and voucher issuers (spec 5.2, 10.3). Binding the
  position in the voucher instead would cost a per-level index accumulator
  in `LEVEL`; the requirement is cheaper and sufficient.

`EXIT_K` was also implemented rather than merely described, to confirm the
composition rule (spec 7.6): step `i` proves against the root produced by
step `i − 1`, and the test suite checks that a stale second path fails.

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
at depths 4 and 16 in a simulator of the required opcode subset, with 44
checks including the negative cases that matter for the findings above:
attacker-chosen `m` (F4), forged leaf amount and stale root (F3), unconserved
tree amount (F6), join over an occupied position and underfunded join,
eviction before the lease height and evictor shortchange (F5), voucher
replay after source change and over-claim (F1). All pass. The simulator is
not consensus code; the assumptions about the EC opcodes are listed in
spec 4.1.
