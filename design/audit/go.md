# Go implementation audit: `tree/`, `script/`, `txn/`, `msg/`

*An adversarial pass over the Go packages at `main` fb74f16, against
`spec/layertree.md` 0.11.0, `spec/channel-leaves.md` 0.4.0 and the Python
reference under `tools/`. The question asked of every function was: can
a caller who trusts it be made to accept, build or sign something the
spec or the scripts reject, and can a peer who sends it bytes make it
fail. Findings of `design/audit/protocol.md`, `script.md` and
`channels.md` are taken as settled. Every finding below was confirmed by
a probe: a throwaway Go test in the package (described under each
finding, not committed, since each asserts the bug) or a Python run
against `tools/`; where a builder produced a transaction, the signed
witness was replayed through the simulator with
`tools/replay_txn_dump.py`, which is the same harness the 42 positive
cases use. Section numbers without a prefix are the spec's; `C.x` is
Appendix C.*

Two facts about the code recur. First, every sum in `tree/` is a Go
`uint64` and `tree.Parent` adds with wraparound, where the Python
reference's `le64` raises on any value outside `[0, 2^64)` and the FULL
scripts add BIP-441 numbers of unbounded size. Second, `msg/` decodes
with lnd's `tlv.Stream.Decode`, the non-P2P entry point, which enforces
canonical ordering and uniqueness of types but applies neither the
65,535-byte `MaxRecordSize` nor any presence check for mandatory
records.

## What the Go code gets right

The generators are byte-exact with the Python ones beyond the golden
set. A sweep of 323 scripts, every FULL, MID, MIN, CCV and channel
generator at depths 3, 5, 12, 16, 20, 25, 28, 31 and 32, sparse and
dense, heights 1 to 3 for `EVICT_SUBTREE_h`, `REWRITE_h`, `REWRITE_h^x`
and `DETACH_h` (with `m_h` from the reference options), `EXIT_3`,
`JOINK_3`, every `CLAIM` form, `csv_delay` in {1, 16, 17, 127, 128, 255,
256, 32767, 32768, 65535}, `REBIND_n` for `n` in {0, 1, 255, 65535, 2^24,
`MAX_STATE`} and `HTLC_TIMEOUT` at fifteen `cltv_expiry` values that
cross every `CScriptNum` width, under both tapleaf versions, printed `0
byte differences`. `EncodeNumC0`, `EncodeNumC2` and `pushData` agree with
`scriptnum_encode`, `num_encode` and `push`. `ChanCollate` emits the
fields in the simulator's order and is pinned by the golden `collation`
and `msg` of both channel transactions. The signature hash is computed
twice (`txscript` and by hand) and both agree with the simulator on all
42 cases; input 0 and the leaf version are fixed by construction
(`Spend.Sign` signs input 0, `TapscriptSpend` refuses a control block
whose leaf version differs from the script's and verifies the taproot
commitment against the spent output). The carve builder enforces 7.5
rules 2, 5 and 6 and the `SEQ_FINAL` rule of 5.2; the exit and sweep
builders enforce the evictor key, the lock-time floor and exact payouts
on eviction. `SigningRound` is C.3.6 to the letter.

## Ranked findings

### G1. `tree.Parent` wraps at 2^64, so `JoinOffer.VerifyMember` and `Proof.Verify` accept a grafted subtree that hides a 1 BTC leaf behind 330 sat

**Claim.** `tree.Parent` computes `left.Sum + right.Sum` in `uint64`, so a
sibling node whose sum is `2^64 - a + s` folds with a leaf of amount `a`
to a parent of sum `s`; `msg.Proof.Verify` and
`JoinOffer.VerifyMember`, the Go form of 9.2 step 3(c) ("recomputing
every sum"), accept the path, where the Python reference raises and the
FULL scripts reject every later spend of that leaf.

**Attacker.** The operator, grafting with its own funds (9.2's
operator-funded mode, `design/graft.md`) and selling the leaf to a
member who pays off-chain after verifying the confirmed graft, which is
exactly the flow 9.2's last paragraph tells that member to follow.

**Path.** The operator builds `JOIN_1` of a two-position subtree: the
member's leaf, amount `a = 100,000,000`, and a sibling `(sha256("fake"),
2^64 - a + 330)`. `tree.Parent` gives the subtree root sum 330, the
operator funds 330 sat, and the covenant accepts: 7.3 rule 4 puts no
requirement on the contents of the grafted node, and the witness
carries only `(new_hash, new_sum = 330)`. The member's `JoinOffer`
carries the leaf, the one-level subtree path and the graft path.
`VerifyMember` folds the leaf through the fake sibling (sum wraps to
330), through the graft path, and finds the total consistent. Probe
(`msg`, D = 4):

```
sibling sum 18446744073609551946 (2^64 - a + s); Go Parent sum = 330 (wrapped)
VerifyMember: err=<nil> newRoot.Sum=1000330 (member leaf 100000000 sat, tree holds 1000330)
```

The same leaf, path and wrapped root handed to the Python side:

```
reference fold: REJECTED, sum out of range
simulator EXIT_1: REJECTED, NUMEQUALVERIFY failed: 18446744073710551946 != 1000330
```

The reference's `le64` refuses to encode the overflowed parent, and the
simulator's `EXIT_1` folds to `2^64 + 1,000,330` where the input holds
`1,000,330`, so the member's leaf is provable to Go and to nobody else.
Once the member has paid, the leaf can never exit, be evicted, swept or
rewritten (every one of those folds the same path), and the operator is
out 330 sat. The dense-profile `Proof.Verify` is the only sum check a
Go member has.

**Severity.** Direct loss of whatever the member paid off-chain for the
leaf, bounded only by the operator's credibility. It needs a malicious
operator, which is the one adversary 9.2 step 3 and 10.2 are written
against ("a leaf whose path does not recompute consistently is not
provable and its owner was never in the tree; section 9.2 step 3(c)
requires members to detect this before funding"), and the Go member
cannot detect it.

**Existing mitigation.** None in Go. `tree.Leaf.Validate` bounds a leaf's
own amount below 2^51 but is never called, and sibling sums arrive as
raw `le64` in `decodeNode`. The Python `Leaf`, `le64` and `fold` reject
the path; the scripts reject every spend. The Lean model's sums are
unbounded naturals.

**Fix.** Two independent checks, both cheap. In `msg.decodeNode`, reject
a sum of 2^51 or more: 5.2 bounds every leaf below 2^51, the total of
any real tree is below 2.1·10^15 < 2^51, and the tree output's amount is
a `CAmount`, so no honest node sum reaches 2^51. In `tree.Parent` (or a
checked `Fold` the verifiers use), detect the carry with `bits.Add64`
and fail; `Proof.Verify` and `VerifyMember` then return an error. Test:
the probe above as a negative in `msg`, plus a `tree` test that `Fold`
over a wrapping path fails.

### G2. `JoinOffer.VerifyMember` does not look at the unsigned transaction, so 9.2 step 3(d) is performed nowhere in Go

**Claim.** `VerifyMember` is documented as "the message-local checks of
spec 9.2 step 3" and returns the post-graft root, but it never decodes
`UnsignedTx`; the one check that makes a self-funding member's input
safe, that output 0 is `TREE_SPK(r', m)` with amount `S + new_sum`, is
not made by it or by anything else in the package, although the message
carries the transaction and `m` is the function's argument.

**Attacker.** The operator, towards a member who funds its own leaf
(9.2 step 3(f), the self-funded cohort of 9.2's informative paragraph).

**Path.** The operator sends a correct leaf, correct paths and a correct
`NewNode`, with an `UnsignedTx` whose output 0 pays `S + new_sum` to the
operator's own key. Probe (`msg`): an offer whose `UnsignedTx` has one
input and one output of 1,050,000 sat to a P2WPKH:

```
VerifyMember with output 0 paying a P2WPKH: err=<nil>
```

A member that signs its input after a nil error has signed a plain
payment to the operator. 9.2 says a member's funds are safe "by
construction" because "the only transaction that can spend `U`'s input
is one whose output 0 commits to a root containing `U`'s leaf"; that
construction is the check (d), which the Go member skips. The doc
comment excludes "anything that requires external state, such as the
unsigned tx actually matching the chain", which is true of step 3(a)
(input 0 is an unspent output, needs the chain) but not of 3(d), which
needs only `r'`, `m` and the bytes already in the message.

**Severity.** Direct loss of the member's funding input. Requires a
malicious operator and a member that treats `VerifyMember` as the
step-3 check its name and comment describe.

**Existing mitigation.** The comment says the transaction is not
checked. Nothing offers the check.

**Fix.** `VerifyMember` decodes `UnsignedTx` (a `wire.MsgTx`; fail if it
does not parse or is empty), and requires output 0 to be
`tree.ScriptPubKey(newRoot.Hash, expectedM)` with value
`int64(newRoot.Sum)`, which is `S + new_sum` by the sum check already
made. Optionally take the tree outpoint and require input 0 to spend
it. Step 3(a)'s chain lookup stays with the caller and the comment says
so. Test: the probe as a negative, and the two existing positive cases
given a real `Builder`-produced transaction instead of the placeholder
bytes.

### G3. Every `msg` decoder allocates from the untrusted record length

**Claim.** `msg` decodes with `tlv.Stream.Decode`, which is lnd's non-P2P
path and skips the `MaxRecordSize` check (`stream.go`: `if p2p && length
> MaxRecordSize`), and every variable-length field uses `tlv.DVarBytes`,
which is `make([]byte, l)` with the declared length; a ten-byte message
makes the decoder allocate whatever it says.

**Attacker.** Any peer that can deliver a message to the decoder: a
channel counterparty (`StateProposal`, `StateSig`, `HtlcAdd`,
`HtlcFail`, `SpliceProposal`), an operator or a member (`JoinOffer`,
`Proof`, `Voucher`), a watchtower's client (`RebindAnnounce`).

**Path.** A stream of one record, type 4, BigSize length `0xff || 2^62`,
no payload. Probe (`msg`):

```
StateProposal.Decode: PANIC runtime error: makeslice: len out of range
Proof.Decode (type 4 = nodes): PANIC runtime error: makeslice: len out of range
HtlcFail.Decode (type 2 = reason): PANIC runtime error: makeslice: len out of range
StateProposal.Decode len 2^31: err=unexpected EOF
```

The first three are a crash of the receiving process unless every call
site recovers. The fourth shows the other half: a length of 2^31
allocates two gigabytes before `io.ReadFull` notices the stream is
short, and a few such messages in flight exhaust a small host. Every
`varBytes` record is reachable this way: `TypeJoinSubtreePath`,
`TypeJoinGraftPath`, `TypeJoinUnsignedTx`, `TypeProofBitmap`,
`TypeProofNodes`, `TypeStateHtlcs`, `TypeSigNextNonce`,
`TypeHtlcFailReason`, `TypeRebindOutpoint`, `TypeRebindBoundTx`.

**Severity.** Remote crash or memory exhaustion of an operator,
counterparty or tower by one message; no funds move, but a tower or a
counterparty taken offline at the wrong moment is the C.4.4 budget
spent for it.

**Existing mitigation.** None. The round-trip tests feed only
well-formed streams.

**Fix.** Wrap every `Decode` reader in `io.LimitReader` sized to the
message's legitimate maximum, and give each dynamic record an explicit
cap in a custom decoder (a `varBytesMax(typ, b, max)`): 66 bytes for a
MuSig2 nonce, 36 for an outpoint, `53 * maxHTLCs` for the HTLC list,
`41 * 256` for proof nodes, and for the two transaction records
(`UnsignedTx`, `BoundTx`) the 400 kB of `MAX_STANDARD_TX_WEIGHT`, which
a large graft can approach, so `DecodeP2P`'s flat 65,535 is not the
right cap for those two. Test: the probe streams as negatives for every
message type.

### G4. `BuildExit` builds, signs and verifies an owner exit with a fee in a tree whose exits are `EXIT_K^=`

**Claim.** `FullTreeOptions{Exact: true}` compiles the exact-payout
scripts of 7.2 rule 6 under the same names `EXIT_K` as the inexact ones,
and `BuildExit` looks scripts up by name, so with `Fee > 0` it produces,
signs and `Verify`s a transaction whose payout is `leaf.amount - fee`
and which the revealed `EXIT_1^=` rejects.

**Attacker.** Nobody external; the victim is the owner running the
builder, and the trees affected are the ones 7.2 rule 6 and C.6.1 say
SHOULD or MUST be exact, which are the trees hosting channel leaves.

**Path.** Probe (`txn`, D = 4, options `Exact: true`, `BuildExit` of
bob's leaf with `Fee: 1_000`):

```
exact tree, owner exit with fee: builder ACCEPTED, signed and verified
replay: script failed: NUMEQUALVERIFY failed: 124000 != 125000
```

`ExitStep.Fee`'s comment says it "must be zero ... for a tree with
exact-payout `EXIT_K^=` scripts", and nothing checks it. An owner whose
software passes its usual fee builds an exit that no node accepts; for
a channel leaf that exit is the first step of a force close, whose
budget C.4.4 counts in blocks.

**Severity.** No loss and no attacker; a delay of the one transaction
that must not be delayed, in the tree type where it matters, with a
misleading `Verify` success.

**Existing mitigation.** The comment. `TestBuilderRejects` has no
exact-payout case; the 42 end-to-end cases use the reference (inexact)
set.

**Fix.** Make the variant visible to the builder: either `TreeState`
carries the tree's `FullTreeOptions` (which also gives `UpdateX`,
`DustMin` and the `CLAIM` forms a home) and `BuildExit` refuses `Fee >
0` when `Exact` is set, or `TapLeaf` records the variant it was compiled
from. Test: the probe as a `TestBuilderRejects` case, and a positive
exact exit with `Fee: 0` replayed through the simulator.

### G5. Four more inputs the builders accept and the scripts reject: a timestamp lock time on an eviction, an unchecked voucher, a claim position outside the tree, and leaves that fail 5.2

**Claim.** `BuildExit` and `BuildEvictSubtree` compare `opts.LockTime`
with `evict_after` as integers; `BuildClaim` and `BuildClaimH` never
verify the voucher they are handed; `buildCarve` never range-checks
`claimPos`; no builder calls `tree.Leaf.Validate`. Each produces a
signed, `Verify`-clean transaction, and the simulator rejects the first
three.

**Attacker.** None; the owner, redeemer or operator running the builder
is the party harmed, by a transaction that cannot confirm.

**Path.** Probes (`txn`, D = 4), each `builder ACCEPTED, signed and
verified`, then the replay:

* eviction with `LockTime: 1_000_000_000` against `evict_after =
  800,000`: `script failed: CLTV not satisfied`. 10.6: "eviction
  transactions MUST use height-based `nLockTime`"; `OP_CHECKLOCKTIMEVERIFY`
  fails when the operand and `nLockTime` are of different types, which
  `lockTime < leaf.EvictAfter` does not model.
* `CLAIM` with a voucher signed by alice's key over the operator's
  source leaf: `script failed: CSFS failed`. The builder trusts the
  64 bytes it is given; a redeemer holding a voucher from the wrong
  issuer, or over a different `tree_id`, learns this only on chain.
* `CLAIM` into position `2^4 + 3` of a depth-4 tree: `script failed:
  NUMEQUALVERIFY failed: 0 != 1135000`. `tree.Tree.Root` covers
  positions `[0, 2^D)` and ignores the leaf, so output 0 recreates the
  tree without it while the claim path folds it in; the builder reports
  a new root sum of 1,135,000 that is not what the transaction pays.
  `BuildJoin`, `BuildJoinK` and `BuildEvictSubtree` do range-check.
* `JOIN_0` of a leaf with `amount = 0` and `owner_key = 0x00..00` (no
  `lift_x`): builder accepted and the simulator accepted too, as 7.3
  rule 4 says it must; the leaf violates two MUSTs of 5.2 and is
  unspendable and unsweepable except by a non-standard transaction
  (7.8). 10.7: "operators SHOULD validate all leaf keys before
  grafting". `Leaf.Validate` exists for this and has no caller.

**Severity.** A failed broadcast and a confusing `Verify` success in
the first three; a permanently stuck leaf of the operator's own making
in the fourth.

**Existing mitigation.** `TestBuilderRejects` covers the lock-time
floor, fee on eviction, empty and occupied positions, under-funding, the
carve rules and the sparse position; not these.

**Fix.** `BuildExit` and `BuildEvictSubtree` reject `opts.LockTime >=
500_000_000` when any step evicts. `BuildClaim` and `BuildClaimH` verify
the voucher with `schnorr` over `tree.VoucherMsg(st.TreeID, src, claim)`
(or the `H` form with `sha256(preimage)`). `buildCarve` rejects
`claimPos >= 1 << depth`. Every builder that writes a leaf (`BuildJoin`,
`BuildJoinK`, `buildUpdate`, `buildCarve`) calls `Leaf.Validate` on it.
Tests: four `TestBuilderRejects` cases.

### G6. `tree.Leaf.PosLoMinimal` ignores the depth the MID sparse scripts compare against

**Claim.** `PosLoMinimal` checks that the first four bytes of `H_pos`
are a minimal positive `CScriptNum` (`h[3] & 0x80 == 0 && h[3] != 0`)
and nothing else; `SPARSE_TEARDOWN` compares the `D`-bit direction
accumulator with all 32 bits of `pos_lo` (`design/audit/script.md`,
"MID sparse trees need `25 <= D <= 31`"), so `pos_lo` must also be below
`2^D`, which the reference's `pos_ok(leaf, depth)` checks and the Go
helper does not.

**Attacker.** None; a joiner that grinds nonces with the Go helper in a
MID sparse tree below `D = 31` produces leaves the script cannot place.

**Path.** 100,000 nonces over one owner key, both predicates:

```
D=25: Go PosLoMinimal accepts 49891, pos_ok accepts 358, Go-only 49533
D=28: Go PosLoMinimal accepts 49891, pos_ok accepts 5893, Go-only 43998
D=30: Go PosLoMinimal accepts 49891, pos_ok accepts 24981, Go-only 24910
D=31: Go PosLoMinimal accepts 49891, pos_ok accepts 49891, Go-only 0
```

At `D = 28` the helper approves eight of every nine nonces the script
rejects. The MID generators themselves match the Python (the sweep
covers `MID/S` at 25, 28 and 31), so this is the helper, not the script.

**Severity.** A failed join or claim in a MID sparse tree, found on
chain.

**Existing mitigation.** The comment cites 4.5, which since the script
audit says `25 <= D <= 31` and states the bound; the code predates it.

**Fix.** `PosLoMinimal(depth int)` adds `binary.LittleEndian.Uint32(h[:4])
< 1 << depth` and rejects `depth < 25 || depth > 31`; when MID builders
exist, `TreeState.checkPos` calls it. Test: the divergent nonce 0 at
`D = 28` as a negative.

### G7. Three edges in `msg` validation: an omitted balance is still counted in the 0xC0 collation bound, `RebindAnnounce` lets the state number wrap, and no decoder requires its mandatory fields

**Claim.** (a) `StateProposal.SettleCollationLen` is `156 + 43h`, which
assumes two balance outputs; a state with one balance omitted (C.3.4,
the single-funded state 1) collates to `113 + 43h`, so an eight-HTLC
state that fits `SETTLE_n`'s 488 bytes is rejected under `0xC0`. (b)
`RebindAnnounce.Decode` checks `tx.LockTime == ChanStateBase +
a.StateNum` in `uint32` without bounding `StateNum`, so a state number
of `2^32 - S + 5` wraps to lock time 5 and passes. (c) Every decoder
uses `Decode`, not `DecodeWithParsedTypes`, so a stream missing a
mandatory record decodes to the zero value.

**Attacker.** (a) none, over-rejection. (b) a counterparty announcing to
a watchtower that keys on `StateNum`. (c) a peer sending truncated
messages.

**Path.** Probes (`msg`):

```
8-HTLC single-balance state under 0xC0: settlement collation of 500 bytes exceeds 488 (Go collation 500)
RebindAnnounce state 3794967301 with lock time 5: err=<nil>
ChanOpen.Decode(empty): err=<nil>; Validate: msg: csv_delay out of range
HtlcAdd.Decode(empty): err=<nil> amount=0
```

For (c), `Validate` catches the zero `ChanOpen` (and `StateProposal`,
whose state 0 is rejected; `StateSig`, whose nonce length is checked;
`RebindAnnounce`, whose outpoint length is checked), but `HtlcAdd`,
`HtlcFulfill`, `HtlcFail`, `SpliceProposal` and `Voucher` have no
presence check at all and an `HtlcAdd` with no amount, hash or expiry
is a well-formed message to the caller.

**Severity.** (a) a valid state refused, which is conservative; (b)
and (c) a tower or a state machine fed a zero or wrapped field it did
not expect; the signatures and `Validate` stop money moving.

**Existing mitigation.** `Validate` where it exists; MuSig2 for the
bound transactions.

**Fix.** (a) count `43` per non-zero balance: `70 + 43*(nonzero
balances) + 43*h`, and test the eight-HTLC single-balance state as a
positive under `0xC0`. (b) reject `StateNum > script.ChanMaxState` in
`RebindAnnounce.Decode` (and in `StateProposal.Validate`, which already
does). (c) `decodeStream` uses `DecodeWithParsedTypes` and takes the
set of required types; every message lists its mandatory records.

### G8. `TreeID` names two different things, and the voucher binding is not tied to the compiled script

**Claim.** `script.ChanParams.TreeID`, `msg.ChanOpen.TreeID` and
`msg.JoinOffer.TreeID` hold `m`, the taptree root (their comments say
so; C.2.2 and decision 13 bind `chan_id` to `m`); `msg.Voucher.TreeID`,
`txn.TreeState.TreeID` and `tree.TreeID` hold `tree_id` of 6.2, a
different 32-byte value. `txn.ClaimWitness`'s comment still says the
voucher signs `tree.VoucherMsg(m, source, claim)`. `TreeState.TreeID`
is what `SignVoucher` signs over, while the `tree_id` the `CLAIM` script
checks is whatever constant the taptree was compiled with; nothing ties
the two, so a `TreeState` built with the wrong `TreeID` signs vouchers
the tree rejects.

**Attacker.** None; a reader or integrator who passes `m` where
`tree_id` is wanted, or the reverse, and learns on chain.

**Path.** By inspection. Since 0.10.0 moved vouchers from `m` to
`tree_id` the two names coexist with one field name.

**Severity.** Text and API; a wrong voucher binding fails closed.

**Existing mitigation.** The comments on each field.

**Fix.** Rename the three `m` fields to `M` (or `TaptreeRoot`) and fix
the `ClaimWitness` comment. Have `TreeState` derive `TreeID` from its
options (G4's fix) or check it against the compiled `CLAIM` leaf.

### G9. `DUST_MIN` is a constant in Go, so a tree created with a higher floor cannot be built or mirrored

**Claim.** 6.2 makes `DUST_MIN` a tree-creation parameter and says
operators "MAY set it higher"; the Python generators take `dust_min`
and the Go generators (`fullCarveLeafRules`, `fullDrainRule`,
`midCarveRules`, their CCV forms) and `txn.buildCarve` use
`tree.DustMin` with no parameter.

**Attacker.** None; a limitation.

**Path.** By inspection; `FullTreeOptions` has no `DustMin` field, so
such a tree's `m` cannot be reproduced in Go and `buildCarve` would
accept a 330 sat claim that the tree's scripts reject.

**Severity.** Coverage.

**Existing mitigation.** The RECOMMENDED value is the only one the suites
use.

**Fix.** A `DustMin uint64` on `FullTreeOptions` (zero meaning
`tree.DustMin`), threaded to the carve generators and read by
`buildCarve` through `TreeState`. Test: the golden scripts regenerate
unchanged at 330; one `CLAIM` at `dust_min = 1000` compared with the
Python.

## Considered and rejected

Each item names the claim examined and why it does not stand.

* **A sighash over the wrong input index or leaf version.** `Spend.Sign`
  and `Spend.Verify` hash input 0; `Builder.Tx` puts the tree at input 0
  unconditionally; `TapLeaf.Version` comes from `script.ModeC2`;
  `TapscriptSpend` rejects a control block whose leaf version differs
  from the script's and runs `VerifyTaprootLeafCommitment` against the
  spent output; `TapleafHash` hashes the version byte as given, which
  `TestSighashLeafVersions` pins. CCV's "tree input at any index" has no
  Go builder.
* **`SIGHASH_DEFAULT` only.** 7.2 rule 3 allows `SIGHASH_ALL` with or
  without `ANYONECANPAY`; Go signs the subset the spec recommends for
  `JOIN` and `UPDATE` and allows for `EXIT`.
* **The wrapped tree of G1 on chain.** Every spend of a position under
  the inconsistent node folds it with exact arithmetic and fails
  (`CHECK_OLD`, as the probe shows, or the `PAD8` preimage one level
  up), so the covenant is sound; G1 is a verifier bug, and the member's
  money leaves off-chain, not through the tree.
* **`Spend.Verify` indexing `s.Stack[slot.Index]` without a bounds
  check.** `Spend` values come only from the builders, which size the
  slots from the stacks they built.
* **`TreeState.Input()` casting the root sum to `int64`.** A sum of
  2^63 needs 2^12 leaves at the 5.2 maximum; no such tree exists on
  chain, and `Builder.Tx` rejects a negative output 0.
* **A claim into the position the source just drained.** `buildCarve`
  allows `claimPos == srcPos` when the residual is zero; 7.5's
  informative paragraph (`self_voucher_fixed`) says the script does
  too, and the Python `apply_claim` asserting otherwise is a test
  helper's shortcut, not a rule.
* **A zero payout under plain `EXIT_1`.** `BuildExit` allows `Fee ==
  leaf.Amount`; 7.2 rule 3 allows it and `script.md` records that the
  script accepts it; the dust consequence is the owner's.
* **`Proof.Path` recomputing `EmptyNode` per level.** `Depth` and
  `Height` are `uint8`, so the worst case is about 32,000 hashes per
  proof; not a resource issue.
* **Duplicate or unordered TLV types.** lnd's `Stream.Decode` returns
  `ErrStreamNotCanonical` for both; unknown types are skipped, which
  is the intended extensibility.
* **`SigningRound` order.** `Send(update)` requires the counterparty's
  settle signature, exactly C.3.6's MUST NOT; `Receive(update)` further
  requires both settle signatures, which is stricter and harmless.
  `match` checks the role before it indexes, so no panic.
* **`CheckDeadline` arithmetic.** Computed in `uint64`; the C.4.4 and
  C.6.4 rule (`cltv_expiry >= max(height, evict_after) + budget`) is
  what the code says.
* **`StateProposal.Anchor` and `Validate` overflow.** `Anchor` checks
  the carry on every addition; `Validate` rejects `^uint64(0)` (the
  suite tests it).
* **`SpliceProposal.Apply` at epoch `2^32 - 1`.** Wraps to 0; needs
  four billion splices.
* **`ChanCollate` supporting only `INPUTSELECT_CURRENT`.** Channel
  transactions have one input (C.2.3); the field order matches the
  simulator's `collate` and the golden `collation` of both templates.
* **Number encodings and pushes outside the golden set.** The 323-script
  sweep covers every `CScriptNum` width change (`csv_delay` 127/128,
  255/256, 32767/32768; `cltv_expiry` across 2^7, 2^15, 2^16, 2^23,
  2^24 and the height boundary; `REBIND_n` at `MAX_STATE`, whose
  five-byte operand `OP_CHECKLOCKTIMEVERIFY` accepts) under both
  tapleaf versions, with no difference.
* **`MidLevelsWitness` pads.** The pads are sized for the accumulator
  before the sibling is added, which is the sum the node hash encodes;
  the generator's `PADZ` consumes exactly that. Consistent with the
  Python witness builder, though not run through the simulator (see
  the gaps).
* **A trimmed HTLC cannot be expressed in `StateProposal`.** The Go
  proposal lists settlement outputs, not ledger balances (its comment
  says so); a trimmed HTLC is omitted and its value is `Anchor()`'s,
  which is what `settle_outputs` does.
* **`TapscriptSpend` skipping its commitment check when the prevout is
  unknown.** A sanity check; `Spend.Sign` always passes the builder's
  `PrevOuts`, and `Verify` runs the check unconditionally.
* **`decodeHtlcs` accepting duplicate HTLC ids.** Bookkeeping between
  the two parties; the settlement outputs are what the signatures
  commit to.
* **`tree.Tree` positions as `uint64` and `Proof.Depth` as `uint8`.**
  The dense range 8 to 24 and the sparse range 32 to 64 fit; `D = 256`
  (5.4, "valid") does not, which is a stated limit rather than a bug.
  Noted under gaps.

## Coverage gaps

* **No builders for `REWRITE_h`, `REWRITE_h^x`, `DETACH_h`, `CLAIM^x`,
  `CLAIM^hx` or `EXIT_K^=`, and none for MID, MIN or CCV.** The brief's
  question about 7.9 rule 3's `SEQ_FINAL` exclusion has no builder to
  ask it of; the exclusion lives in `fullRewriteStep`, which the sweep
  confirms matches the Python at four depths and three heights, and in
  the Python suite's negatives. A `BuildRewrite` would have to compute
  which positions need `sig_i` and `xsig_i`, which is where a Go
  implementation would get rule 3 wrong.
* **No negative replay.** `tools/replay_txn_dump.py` runs the 42
  positive cases; nothing checks that a transaction `TestBuilderRejects`
  refuses would also fail the script, nor that the builders refuse
  everything the script does (G4, G5). A second dump of
  builder-accepted transactions that the simulator must reject would
  have caught both.
* **No hostile-input tests in `msg`.** The tests are round trips and
  `Validate` cases on well-formed values; no truncated stream, no
  oversized length, no out-of-range sum, no transaction in `UnsignedTx`
  (the two `JoinOffer` tests use the bytes `"unsigned-tx-placeholder"`).
  A Go fuzz target over each `Decode` would have found G3 in seconds.
* **The MID witness helpers are checked against hand-written vectors
  only.** `MidLeafWitness`, `MidLeafExitWitness`, `MidLevelsWitness` and
  `MidPosWitness` have no simulator run; the pads in
  `TestMidLevelsWitness` are all one byte, so a pad sized for the wrong
  accumulator would pass it.
* **`tree.Leaf.Validate` has no callers** (G5).
* **Depth limits.** `tree.Tree` positions are `uint64` and
  `msg.Proof.Depth` is `uint8`; a sparse tree of `D = 256` cannot be
  represented, and `Leaf.Position(depth >= 64)` returns the low 64 bits.
  `BuildJoin` and `BuildEvictSubtree` shift by `cur.Depth - height`
  without a guard for `Depth >= 64`.
* **`DUST_MIN` fixed at 330** (G9).
* **`JoinOffer` carries one 32-byte identifier.** A member must check
  both `m` (which rules) and `tree_id` (which voucher binding); the
  message has a field for one of them (G8).

## What each finding should become

| Finding | Code | Test | Text |
|---|---|---|---|
| G1 sum wraparound in `Parent`/`Fold` | `msg.decodeNode` rejects sums of 2^51 or more; `tree.Fold` detects the carry and the verifiers fail on it | the probe offer as a `msg` negative; a `tree` test that a wrapping path fails | 10.2: note that an implementation's sums must be checked arithmetic, not machine words |
| G2 `VerifyMember` ignores `UnsignedTx` | decode the transaction and require output 0 to be `TREE_SPK(r', m)` with amount `S + new_sum`; fail on an empty or unparseable field | the probe as a negative; positives built with `txn.Builder` | the doc comment: which of 9.2 step 3's items it performs |
| G3 unbounded TLV allocation | `io.LimitReader` per message and a per-record cap for every dynamic record; 400 kB for the two transaction records | the three panicking streams and the 2^31 stream as negatives for every message type; a fuzz target per `Decode` | none |
| G4 fee on an exact-payout exit | `TreeState` carries the tree's `FullTreeOptions`; `BuildExit` rejects `Fee > 0` under `Exact` | `TestBuilderRejects` case; an exact positive replayed in the simulator | `ExitStep.Fee` comment becomes a check |
| G5 lock-time type, voucher, position, 5.2 | reject timestamp lock times on evictions; verify vouchers in `BuildClaim`/`BuildClaimH`; range-check `claimPos`; call `Leaf.Validate` in every leaf-writing builder | four `TestBuilderRejects` cases | none |
| G6 `PosLoMinimal` without depth | `PosLoMinimal(depth)` adds `pos_lo < 2^depth` and the 25 to 31 range | nonce 0 at `D = 28` as a negative | the comment cites the 4.5 bound |
| G7 collation count, state wrap, mandatory fields | `70 + 43*(nonzero balances) + 43h`; `StateNum <= ChanMaxState` in `RebindAnnounce.Decode`; `DecodeWithParsedTypes` with required-type sets | eight-HTLC single-balance positive under `0xC0`; wrapped state negative; empty-stream negatives | none |
| G8 `TreeID` naming | rename the `m` fields; fix the `ClaimWitness` comment; derive or check `TreeState.TreeID` | none | field comments |
| G9 `DUST_MIN` constant | `DustMin` on `FullTreeOptions`, threaded to the carve generators and `buildCarve` | golden unchanged at 330; one `CLAIM` at 1000 against the Python | none |
