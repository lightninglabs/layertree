# LayerTree, explained

*A high-level tour of the design. The normative document is
[`spec/layertree.md`](spec/layertree.md); the paper in [`paper/`](paper/)
is the academic write-up. This file is the version you would read first.*

## The problem: everyone shares one coin, but leaving is expensive

Bitcoin's scaling constraint is not really about payments. It is about
**ownership**. Every distinct owner wants their own unspent output, and
outputs are the scarce resource. So the obvious move is to let many people
share one output, and the hard part is what happens when one of them wants
to leave.

Every shared-UTXO design in the wild answers that question the same way.
Channel factories, CoinPool, Ark, timeout trees, covenant trees built on
`OP_CHECKTEMPLATEVERIFY` or `OP_CHECKCONTRACTVERIFY`: the shared output is
the root of a **tree of transactions**. To leave on your own, you publish
the path from the root down to your leaf. That is `O(log N)` transactions,
each paying a fee, each waiting for a confirmation. The interior of that
tree has to exist in advance, either as transactions every member signed
while online, or as covenant templates fixed at creation. And when the tree
expires, reclaiming the funds of one unresponsive member means putting the
whole thing on-chain.

You pay for the sharing at exactly the moment you most need it to be cheap.

## The idea: make the tree data, not transactions

LayerTree keeps the tree, but the tree never becomes transactions. It is a
**Merkle-sum tree of balances** that lives entirely off-chain, and a single
on-chain output commits to its root.

To leave, you do not publish a path of transactions. You present your leaf
and its Merkle proof **to the output itself**. The spending script:

1. recomputes the root from your leaf and your proof,
2. checks that it matches the root the output committed to,
3. recomputes the root a second time with your leaf removed,
4. and forces the transaction to recreate the shared output under that new
   root, paying you your balance.

One transaction. No pre-signing. Nobody else's signature. The cost grows
with the *depth* of the tree, at about 32 virtual bytes per level, rather
than with a path of transactions. At depth 16, which is 65,536 slots, a
unilateral exit is about 1,020 virtual bytes.

That is the whole idea. Everything below is a consequence of it.

## Five concepts that make it work

### 1. State lives in the output's address

A taproot output's address is derived from an internal public key and a
tree of spending scripts. LayerTree derives the internal key from the
Merkle root:

```
P = lift_x( NUMS + H_state(root) * G )
```

`NUMS` is a point nobody knows the discrete log of, so there is no key-path
spend and every spend must reveal and satisfy a script. But the *address*
now encodes the tree's state. Change one balance and the output's address
changes.

This is the trick that turns an output into a state machine. The scripts do
not need to store the state; they receive the claimed root in the witness,
recompute the address from it, and compare against the output actually
being spent. If the spender lies about the root, the addresses do not
match and the script fails.

The scripts also bind the *script set* the same way, because the address
commits to both. Without that, a spender could recreate the shared output
under rules of their own choosing, which would be the whole game.

### 2. The tree carries sums, not just hashes

Each node is a pair: a hash and an amount. A parent's amount is the sum of
its children's. So the root does not just commit to *which* leaves exist,
it commits to *how much they add up to*, and the output's satoshi value is
required to equal that.

This is what makes theft structurally impossible rather than merely
forbidden. A script cannot see the whole tree; it sees one leaf and one
path. But because sums travel up the path alongside hashes, a script that
verifies your proof has also verified your leaf's contribution to the
total. Every transition recomputes the root twice, once before and once
after, and the difference between the two sums is exactly what may leave
the output.

An operator who wants to steal from you would have to produce a different
tree with the same root.

### 3. Your proof is your authorisation

The original sketch for this design had the operator sign a **voucher**
that you presented in order to exit. The review threw that out, and the
reasoning is worth keeping, because it is the heart of the security model.

Once the covenant checks your proof against the committed root, the
operator's signature adds nothing. Your leaf's presence in the root *is*
the operator's commitment; they agreed to it when they signed the
transition that put it there. What a required voucher *would* add is a
dependency on the operator at exit time, and therefore a way for them to
censor you by declining to issue one.

So exits are authorised by the leaf owner's own signature over the spending
transaction, and the operator holds no key over anyone's funds. They can
add members, co-sign cooperative changes, and evict members whose lease has
run out. They cannot take a satoshi or stop you leaving.

### 4. The interface is small

Everything the shared output can do fits on one page:

| Interface | Who | What it does |
|---|---|---|
| `JOIN` | operator | Grafts a new member, or a whole prebuilt subtree, into an empty slot |
| `EXIT` | leaf owner | Removes your leaf, pays your balance to your exit key |
| `EVICT` | evictor, after the lease height | Removes an expired leaf, paying the owner exactly |
| `UPDATE` | owner and operator | Rewrites a leaf in place: resize, renew the lease, rotate keys |
| `CLAIM` | anyone holding a voucher | Carves a new leaf out of an existing one |
| `SPLIT` | a leaf owner | The same carve, authorised by signing the transaction rather than a voucher; needs no signature-over-stack-data opcode, so it exists in all three tiers, including MIN |
| `SWEEP` (`EVICT_SUBTREE_h` in the spec) | evictor | Removes a whole expired cohort in one transaction |

They are all the same machine underneath. Every one of them is a sequence
of **steps**, and a step is: prove an old node against the current root,
then fold a new node up the same path to get the next root. An exit is one
step replacing a leaf with emptiness. A join is one step replacing
emptiness with a subtree. A batched exit of five members is five steps
chained, each proving against the root the last one produced. The script
for a five-way exit is the script for a one-way exit with the loop body
repeated, because tapscript has no loops and everything is unrolled.

A tree has one of two shapes, and **dense is the default**. In the dense
profile the operator assigns slots in order, so 65,536 members need depth
16, and cohorts can be grafted and swept as aligned subtrees. The sparse
profile places each leaf at a position hashed from its owner's key, which
removes the operator from slot assignment and gives proofs that a key is
absent. It is kept as a secondary option for key-addressed registries, and
it costs 1.6 to 2.7 times as much: random positions need about twice the
depth to avoid collisions, and each sparse level is a heavier script. It
cannot graft or sweep cohorts. The rest of this file describes the dense
profile.

That unrolling happens twice over, and the second one is easy to miss.
Inside a script, the fold over the tree's depth is one copy of the level
macro per level, which is why script size grows linearly with depth. Across
scripts, every batch size is *different bytes* and therefore a different
leaf of the taptree: a tree that supports exits of one and two, joins at
two heights and a cohort sweep is carrying six scripts, not three. Revealing
one leaf costs a Merkle path to it, so each doubling of the script set adds
eight virtual bytes to every spend of every kind. That is cheap against a
1,020 vB exit, and it is the reason the set is chosen at creation rather
than grown later: the taptree root is the tree's identity.

### 5. Removal can be cheaper in bulk than one at a time

Because the covenant is verifying *data* rather than executing
transactions, it can take shortcuts a transaction tree cannot. `SWEEP`
takes one path down to an aligned subtree plus all the leaves beneath it,
recomputes the subtree root once, checks every lease, and pays every leaf.
Hashing the interior once instead of once per leaf means the per-leaf cost
*falls* as the cohort grows:

| Removal | Cost per leaf removed |
|---|---|
| One exit alone | 1,020 vB |
| Two exits batched | 842 vB |
| Cohort sweep, 13 leaves | 203 vB |
| Cohort sweep, 51 leaves | 158 vB |

The same asymmetry works on the way in. A graft walks only the levels
above the slot it fills, so a bigger cohort is a cheaper transaction: at
depth 16, one member costs 980 vB, 256 members 722 vB, and 1,024 members
657 vB. The covenant does not look inside the grafted subtree, which is why
the whole cohort is one price. Each cohort height is its own script. The
reference taptree carries only the single-member and four-member grafts,
and a deployment that wants larger cohorts compiles those heights in when
it creates the tree.

## What it deliberately does not promise

A design is only as honest as its list of non-guarantees.

**Nobody has to let you in.** `JOIN` needs the operator. A member who is
never admitted has lost nothing, but there is no liveness guarantee for
joining.

**Grafting is safe for the members already there.** A graft needs only the
operator's signature, and it can only fill a slot that was empty, so no
existing leaf can be moved, shrunk or rewritten by one. The party at risk
is a funder who pays before verifying. A funder who signs an input to the
graft transaction has verified by signing, because the signature commits to
the output that holds the new root. A buyer who pays off-chain verifies the
confirmed root first. An operator that funds its own leaves, or grafts a bad
node into its own part of a cohort, freezes only its own money. The trust
model and funding costs are in [`design/graft.md`](design/graft.md).

**Grafted subtrees might be opaque.** When the operator grafts a subtree,
the covenant sees only its root hash and its claimed sum. It cannot look
inside. If the operator grafts a node with no real tree behind it, no value
is created, because the sums still balance. But nothing under that node can
ever be proved, so the value is **frozen**. The protection is procedural
and it is mandatory: verify your own path inside a subtree before you fund
a join. The formal model made this precise, and it is the one place where
the proofs have a hypothesis the covenant cannot enforce.

**Everything funnels through one output.** Every transition spends and
recreates the same UTXO, so unconfirmed transitions form a chain. Bitcoin's
default policy allows about 25 unconfirmed descendants, which puts a hard
ceiling on how fast a tree can be dissolved against its will. The limit
counts transactions, not leaves, so a batch counts once: a sweep of 51
leaves is one transaction. The worst case is strangers exiting one at a
time. Detaching a cohort into an output of its own, which
[`design/batching.md`](design/batching.md) proposes but the spec does not
yet define, would give each cohort its own chain and its own limit. The single chain
also exposes the tree to fee pinning: one cheap transition early in the queue
caps the fee rate of everything behind it. Trees should be sized by exit
throughput, not by how many slots the depth allows. This is the design's
real weak spot, and splitting a deployment into several trees is the only
structural answer.

**Eviction is cheap, which cuts both ways.** At about 160 vB per leaf, an
operator can clear expired members very cheaply. That is good for
reclaiming dead weight and it also makes griefing cheap. Members who want a
hard guarantee buy it with a lease far in the future.

## Paying each other

The tree is a custody and settlement layer. It is not, by itself, a
payment rail, and three different mechanisms fill that gap.

**Channels inside leaves are the real answer.** Make a leaf's exit key a
2-of-2 between the owner and the operator, and that leaf can host a
Lightning channel that exists only off-chain. Its funding output does not
exist yet; it materialises at the payout of whatever transition eventually
removes the leaf. Payments between two such leaves are ordinary HTLC
forwards through the operator, and **nothing touches the tree**: no spend,
no proof, no transition, no fee. A tree of N channel leaves is a Lightning
hub with a one-UTXO on-chain footprint, reachable from the public network
because the operator can forward between a channel leaf and an ordinary
channel with identical hash and timelock arithmetic.

The price is patience. A force close has to get an exit confirmed first,
and that exit competes with every other transition for the single output,
so HTLC deadlines need roughly 220 blocks of headroom against 40 to 80 on
the public network.

**Vouchers push value to people who are not in the tree yet.** A leaf owner
signs a message saying "carve this new leaf out of mine". The holder
redeems it against the output with `CLAIM`, which is two steps in one
transaction: shrink the source leaf, then place the new leaf in an empty
slot. The total never changes. It is single-use for free, because the first
step mutates the source leaf, so the signed message can never verify
again.

Two honest caveats. The covenant prevents over-*redemption*, not
over-*issuance*: nothing stops someone signing more vouchers than their
balance covers, so a voucher is credit until it is redeemed. And
redemption is an on-chain transition carrying two full Merkle paths, so it
costs more than an exit does.

**Hash-locked vouchers make the exchange atomic.** Put a payment hash in
the voucher message and require the preimage to redeem it, and a voucher
becomes an HTLC. Now you can sell tree balance for Lightning sats, or buy a
leaf with Lightning sats while holding no on-chain Bitcoin at all, with
neither side able to take the other's money and walk. The script cost of
the hash lock is nine bytes and no new opcode, because the preimage is
hashed straight into the signed message rather than compared against a
copy: a wrong preimage produces an invalid signature.

There is still no on-chain deadline, and there cannot be. Script can
require that something not happen before a height, never that it happen
before one, and the value backing a voucher never leaves the source leaf,
so there is nothing to refund. Deadlines live in the other leg of the swap.
An issuer retires an unredeemed voucher by bumping the source leaf's
counter.

**The wallet case is a credit leaf plus cumulative vouchers.** A user with
no on-chain funds who wants to receive over Lightning can be given a credit
leaf dedicated to them, funded by the operator. Each receive is a Lightning
payment to the operator, which reissues one hash-locked voucher for the
running total against the same claim leaf. That costs no on-chain bytes per
payment, has no minimum amount and never expires, and the recipient can
redeem the latest voucher alone if the operator stops cooperating. One gap
remains. With plain `CLAIM` the operator can issue itself a voucher against
the credit leaf and drain it, voiding the recipient's. A trust-free version
needs a `CLAIM^x` variant that also requires a signature from the source
leaf's exit key, which is the recipient; it is not yet in the spec. The
structure is one-way on purpose. If the recipient could also spend from the
credit, an older and larger voucher would be a stale state, and refuting
it needs a contest window, which is what the channel leaf provides.
Receiving suits the credit leaf and two-way traffic suits the channel leaf.
See [`design/receive.md`](design/receive.md).

That asymmetry is the whole subtlety of swapping a voucher against a
channel HTLC, and the two legs are built to fit: both require a preimage of
exactly 32 bytes, so one secret settles both. But the HTLC has a deadline
the chain enforces and the voucher does not, which fixes the order of
play. The preimage has to be generated by whoever the HTLC pays, because
revealing it is how they collect, and the voucher has to be the second leg
to resolve. Put the deadline-free leg first and the HTLC can expire while
the voucher sits unredeemed. Arranged correctly, the channel leg settles
off-chain by exchanging the secret and only the voucher is ever redeemed,
so the whole swap costs one transaction.

## What it costs, honestly

The shared output is not cheaper than a bare UTXO on every operation, and
the claim here is narrower. Sharing moves its cost out of steady state and
into the exit. The full argument, with the figures behind every number
below, is in [`design/cost-comparison.md`](design/cost-comparison.md).

**One exit alone is expensive.** At depth 16 a unilateral exit is 1,020 vB
in the FULL tier, against 111 vB for a bare spend and 2,511 vB to
unroll a transaction-tree branch of the same size. The MID and MIN tiers
cost 1,338 and 1,456 vB. That is the price of the proof, and it is a
constant: it does not grow with the number of members.

**Per-leaf cost falls with batch size.** Owners who exit together each
still carry a full path, so two batched exits average 842 vB. The
operator's sweep shares one path across a subtree and costs 203 vB per leaf
for 13 leaves and 158 vB per leaf for 51, but it works only on leaves
that accepted a lease. The owner-side equivalent, a multiproof that lets
members of one subtree exit under one shared path, is specified but not
built; its estimates are 222 vB per leaf for 13 owners and 177 vB for 51.

**Entry is almost free in bulk.** In a cohort graft each member's share is
under one vB at a thousand members, against 43 vB for one output in an
on-chain batch. That holds when the operator funds the graft and members
buy their balances off-chain. When each member funds their own leaf,
every member adds an input of about 58 vB and most of the saving is gone.

**Moving value is free.** It happens off-chain, in channel leaves or by
voucher. Rewriting a leaf on-chain costs 1,073 vB, so the design only
works if payments do not do that.

The fair comparison is lifetime bytes per member, entry plus exit, and it
depends on how the member leaves:

| vB per member, entering in a batch | Never exits alone | Exits in a batch | Exits alone |
|---|---|---|---|
| LayerTree, dense | 3 | 161 | 1,023 |
| Lightning channel | 197 | 197 | 283 |
| Ark round tree | 86 | 86 | 2,554 |
| Bare UTXO | 154 | 154 | 154 |

A member who never exits alone, because they hold a lease and are swept or
sell their balance by voucher, pays almost nothing. A member who exits
alone pays for the proof and loses to Lightning and the bare UTXO, though
not to Ark, whose unilateral exit is 2.5 times as large and also needs a
timelock and a refresh before the round expires. The assumptions behind
each cell are stated on the cost page.

## The opcodes this needs, and how few they are

None of this runs on Bitcoin today. It needs covenant capabilities that
have been proposed but not activated, and a deliberate part of the work was
measuring exactly how much of the proposed menu is actually required. So
every transition is implemented three times, against three shrinking
opcode sets.

**FULL** uses a new tapleaf version that restores the string and arithmetic
opcodes disabled in 2010, plus transaction introspection, signature checks
over stack data, and elliptic-curve arithmetic. Everything works and it is
the cheapest.

**MID** drops to today's tapscript semantics with only `OP_CAT`,
introspection, stack signature checks and a point-tweak opcode. Four-byte
arithmetic means leaves arrive as separate fields and get stitched back
together, and sums need padding gadgets. Everything but the cohort sweep
works, at about 31% more cost. Liquid has most of these opcodes today.

**MIN** is the interesting one: `OP_CAT` and a single point-tweak opcode,
and nothing else beyond standard tapscript. There is no introspection
opcode at all, so the script cannot read the transaction it is in. The
covenant needs to.

The way out is that `OP_CHECKSIG` *does* see the transaction. So the script
**builds the signature message itself** from the values it wants to
constrain, hashes it, and then verifies a signature over it under the
generator point `G` with nonce `G`. For that key and that nonce the
verification equation collapses to a single solution the script can compute
directly, so the signature is free to produce and authorises nothing. What
it provides is *binding*: `OP_CHECKSIG` hashes the real transaction, so the
check passes only if the message the script constructed equals the real
one. Every field the script pinned down is thereby enforced. Introspection,
recovered from a signature check.

It costs 43% more than FULL and it does only the single-leaf exit and
`SPLIT`, the owner-signed carve that pays another member, so it is an upper
bound rather than a recommendation: the load-bearing operation
needs `OP_CAT` and one point-tweak opcode. No lower bound is claimed.

## What is proved and what is merely tested

The rules of the state machine are mechanised in Lean 4, about 1,300 lines
with no external libraries. The theorems say: roots bind trees, so a node
that verifies against the root really is the node at that position; sums
are conserved by every valid sequence of steps, unconditionally; and any
leaf holder can always construct an accepted exit, conditional on the
tree's root really being a tree's root.

That conditional is the honest part. Conservation needs no assumption at
all. Payability needs the real-tree invariant, which creation and grafting
have to establish off-chain. Writing the proofs is what forced that
distinction into the open; the informal argument had blurred it.

What Lean does *not* cover is the bytecode. The link from rules to script
is execution, not proof: a tapscript simulator runs every compiled script
against a reference tree with negative cases for every rule, and a Go
implementation regenerates the same scripts byte-for-byte against golden
vectors and agrees with the simulator on the signature hash.

| Layer | How it is checked |
|---|---|
| State machine rules | Lean 4 theorems, no `sorry`, axiom-audited |
| Compiled scripts | 576 executable checks across three tiers (425 FULL, 120 MID, 31 MIN), positive and negative |
| Python against Go | 39 byte-exact golden scripts, shared signature-hash vector |
| Composable security | A universal-composability argument, with the Lean theorems as its extraction lemmas |

## Where to read more

| Document | What is in it |
|---|---|
| [`spec/layertree.md`](spec/layertree.md) | The normative specification: data structures, transitions, scripts, security |
| [`spec/channel-leaves.md`](spec/channel-leaves.md) | Appendix C: Lightning channels hosted in leaves |
| [`paper/main.pdf`](paper/) | The academic write-up: ideal functionality, protocol, tiers, security proof |
| [`formal/`](formal/) | The Lean 4 development and a guide to what it does and does not prove |
| [`design/review.md`](design/review.md) | The design review that shaped the construction, finding by finding |
| [`design/status.md`](design/status.md) | Current state, decision log, and open work |
| [`design/cost-comparison.md`](design/cost-comparison.md) | Where LayerTree wins and loses on bytes, against a bare UTXO, Lightning and Ark |
| [`design/tree-comparison.md`](design/tree-comparison.md) | Dense against sparse profiles, measured, and what a higher radix would change |
| [`design/batching.md`](design/batching.md) | How a transition's cost is shared across leaves: what exists and three proposed shapes |
| [`design/graft.md`](design/graft.md) | How a cohort joins, who trusts whom, and what a graft costs by funding mode |
| [`design/receive.md`](design/receive.md) | Receiving over Lightning into a credit leaf, and the one script variant it needs |
