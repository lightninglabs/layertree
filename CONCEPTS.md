# LayerTree, end to end

*The engineer's tour of the whole system: what it is, how the pieces fit,
what each party can and can't do, what it costs, and where the code lives.
Read this first. The normative rules are in
[`spec/layertree.md`](spec/layertree.md), and the reading list at the
bottom points at the deeper notes.*

## What it is

LayerTree is a non-custodial layer on top of Bitcoin. Many users share a
single on-chain output (UTXO), and the balances inside it live in an
off-chain Merkle-sum tree that the output commits to. An operator runs the
tree: it admits members, co-signs changes, and forwards Lightning payments
for members whose leaves host channels. It holds no key over anyone's
money.

The property everything else is built around: any member can leave on
their own, at any time, in **one transaction of constant size**, without
asking the operator or any other member. At depth 16 (65,536 members) that
exit is about 1,020 vB; at depth 20 (about a million) it is about 1,150 vB.
Nothing expires, nothing has to be refreshed, and nobody has to come
online by a deadline to keep their funds.

The catch is that it needs a covenant soft fork. The scripts use opcodes
that are proposed but not active (`OP_CAT` at minimum, see "Opcodes and
tiers" below). Everything here is a design, a spec, and a reference
implementation that runs in a tapscript simulator with those opcodes
switched on.

## The problem it solves

Bitcoin's scarce resource is outputs, not payments. Every distinct owner
wants their own UTXO, so the obvious scaling move is to let many owners
share one, and the hard part is what happens when one of them wants out.

Every shared-UTXO design in the wild answers that the same way. Channel
factories, Ark, timeout trees, and covenant trees built on
`OP_CHECKTEMPLATEVERIFY` or `OP_CHECKCONTRACTVERIFY` all make the shared
output the root of a **tree of transactions**. To leave alone, you
publish the branch from the root down to your leaf: `O(log N)`
transactions, each paying a fee and waiting for a confirmation. The
interior of that tree has to exist ahead of time, either pre-signed by
members who were online, or fixed as covenant templates at creation. And
in the designs that expire, every member has to move their funds out
before the deadline or lose them to whoever holds the timeout path.

So you pay the most for the sharing at exactly the moment you need it to
be cheap.

## The core idea: the tree is data, not transactions

LayerTree keeps a tree, but the tree never becomes transactions. It's a
Merkle-sum tree of balances, held off-chain, and one taproot output
commits to its root.

To leave, you hand your leaf and its Merkle proof **to the output
itself**. The spending script:

1. recomputes the root from your leaf and your proof,
2. checks it against the root the output commits to,
3. recomputes the root again with your leaf replaced by an empty one,
4. and requires the transaction to recreate the shared output under the
   new root, with your balance paid to your key in another output.

One transaction, no pre-signed paths, nobody else's signature. Cost grows
with the *depth* of the tree, roughly 32 vB per level, rather than with a
chain of transactions. Everything below is a consequence of that one
move.

## The data model

### Leaves

A leaf is a fixed 116-byte record (spec 5.2):

| Field | Bytes | What it's for |
|---|---|---|
| `amount` | 8 | the balance, in satoshis |
| `exit_key` | 32 | where an exit or eviction pays, as `P2TR(exit_key)` |
| `owner_key` | 32 | authorises exits, updates and vouchers |
| `evictor_key` | 32 | may remove the leaf once the lease is up |
| `evict_after` | 4 | the lease: block height after which eviction is allowed |
| `nonce` | 4 | with `owner_key`, identifies the leaf |
| `seq` | 4 | bumped by every carve against the leaf, which is what makes vouchers single-use |

`exit_key` is separate from `owner_key` on purpose. A hot key can
authorise while the money lands on a cold key, and a channel leaf can name
its future funding output there.

Leases are optional. A member who never wants to be evicted sets
`evictor_key` to an unspendable point. A member who does accept a lease
loses nothing if it's enforced: eviction pays the full balance to their
`exit_key`, the same output a voluntary exit would. Accepting a lease is
what lets the operator sweep a whole cohort cheaply (more on that below).

### Nodes carry sums

Every node is a pair `(hash, sum)`. A parent is

```
(H_node(lh || enc64(ls) || rh || enc64(rs)),  ls + rs)
```

so the root commits not just to *which* leaves exist but to *how much
they add up to*, and the output's value must equal the root's sum. A
script only ever sees one leaf and one path, but because every sum on
the path is hashed into its parent, verifying your proof also verifies your
contribution to the total. Each transition recomputes the root twice,
before and after, and the difference between the two sums is exactly what
may leave the output. Taking more than that would mean finding a different
tree with the same root.

### Dense and sparse

A tree has a fixed depth `D` and one of two profiles, chosen at creation.

**Dense** is the default. The operator assigns positions in order, so
65,536 members need depth 16, and cohorts can be grafted in and swept out
as aligned subtrees. Everything in this document assumes dense unless it
says otherwise.

**Sparse** places a leaf at a position hashed from its `owner_key` and
`nonce`. That takes the operator out of slot assignment and gives proofs
that a key is *absent*, which is what a key-addressed registry wants. It
needs about twice the depth to avoid collisions and each level is a
heavier script, so an exit costs 1.7 to 2.8 times as much, and it can't
graft or sweep cohorts. [`design/tree-comparison.md`](design/tree-comparison.md)
has the measurements.

## The shared output

### State lives in the address

A taproot address is derived from an internal key and a tree of scripts.
LayerTree derives the internal key from the Merkle root (spec 6):

```
P             = lift_x( NUMS + H_state(root)·G )
TREE_SPK(r,m) = P2TR( P tweaked by m )        # m = taptree root of the script set
```

`NUMS` is a point with no known discrete log, so there's no key-path
spend: every spend reveals and satisfies a script. But the address now
encodes the state. Change one balance and the address changes.

That's what turns an output into a state machine. The scripts don't store
state. They take the claimed root and `m` from the witness, recompute
`TREE_SPK(root, m)`, and compare it with the output being spent. Lie
about the root and the comparison fails. The same check binds `m`, so a
spender can't recreate the shared output under rules of their own
choosing, and the new output must be `TREE_SPK(new_root, m)` with the
same script set.

Two more creation parameters matter. `tree_id` is a unique per-tree
constant (by default a hash of the funding outpoint) that vouchers and
channel IDs bind, so a signature for one tree can't be replayed in
another tree built with identical parameters. `DUST_MIN` (330 sat by
default) is the smallest leaf a carve may create, so nobody can plant a
dust leaf that blocks a cohort sweep.

### One machine: the step

Every transition is a sequence of **steps**. A step proves an old node
against the current root, then folds a new node up the same path to get
the next root. An exit is one step that replaces a leaf with `E_0`, the
empty node. A join is one step that replaces an empty subtree with a
populated one. Two batched exits are two steps chained, the second
proving against the root the first produced.

Tapscript has no loops, so everything is unrolled twice over. Inside a
script, the fold over depth is one copy of the level code per level,
which is why script size grows linearly with `D`. Across scripts, each
transition shape and batch size is different bytes and therefore its own
leaf of the taptree. Revealing a script costs a Merkle path to it, so each
doubling of the script set adds 8 vB to every spend. The set is fixed at
creation because `m`, its root, is part of the tree's address.

## The transitions

The full menu, spec section 7:

| Transition | Who signs | What it does |
|---|---|---|
| `EXIT_K` | each leaf owner | removes `K` leaves, paying each to its `exit_key` |
| `EXIT_K^=` | each leaf owner | the same, with the payout exactly the leaf amount (used by channel leaves) |
| `EXIT_K^t` | anyone holding the owner's earlier authorisation | the exact-payout exit, authorised by an off-chain signature, so a tower can build it while the owner is offline |
| eviction | the evictor, after `evict_after` | removes one expired leaf, paying it in full to `exit_key` |
| `EVICT_SUBTREE_h` | the evictor | sweeps an expired aligned cohort of `2^h` positions in one transaction |
| `JOIN_h` | the operator | grafts a prebuilt subtree of height `h` into an empty slot |
| `JOINK_K` | the operator | `K` single-leaf joins in one transaction |
| `UPDATE` | owner and operator | rewrites a leaf in place: resize, renew the lease, rotate keys |
| `UPDATE^x` | owner, operator and exit key | the same, for leaves whose balance isn't the owner's alone (channels, credit leaves) |
| `CLAIM` and its forms | anyone holding a voucher | carves a new leaf out of an existing one, two steps in one transaction |
| `SPLIT` | the leaf owner | the same carve, authorised by signing the transaction instead of a voucher |
| `REWRITE_h` | the operator, plus each owner whose leaf changes | publishes a cohort subtree before and after; any mix of exits, joins, key rotations and balance moves in one transaction |
| `DETACH_h` | the operator | moves an aligned cohort into its own tree output, with the parent's rules and `tree_id` |
| `RECLAIM_1` | the operator, after a deadline | removes an expired pending leaf from the receive flow, with no payout |

The rules all reduce to a few checks: the old root binds to the input,
the new root binds to output 0, the sums balance, the right key signed,
and any payout is to `P2TR(exit_key)` for at least (or exactly) the leaf
amount.

## A member's life

### Joining

The operator builds the new members' subtree off-chain, each member checks
their own leaf and path inside it, and the operator grafts it in with
`JOIN_h`. The covenant only sees the subtree's root hash and sum, so a
graft is cheap: a walk over the levels above the slot, whatever the
cohort's size. At depth 16 one member costs 937 vB, 256 members 679 vB
in total, 1,024 members 614 vB.

A graft can only fill an empty slot, so it can't touch any existing leaf.
The one rule a joiner has to follow is to **verify your own path inside
the subtree before funding the join**: a subtree root with no real tree
behind it creates no value (the sums still balance) but freezes whatever
was put under it. A funder who signs an input to the graft transaction
verifies by signing, since the signature commits to the output carrying
the new root. [`design/graft.md`](design/graft.md) covers funding modes
and who trusts whom.

Joining is the one operation the operator can refuse. A user who is
never admitted has lost nothing.

### Living in the tree

Steady state costs nothing on-chain. Payments happen off-chain, in channel
leaves or by voucher (next section). Rewriting a leaf on-chain with
`UPDATE` costs 1,030 vB, so the design only works if ordinary payments
don't do that, and they don't.

The member, or a tower acting for them, keeps their path current as other
transitions change the root (spec 9.7). That needs data, not
signatures. Every transition's witness publishes the paths it touched, so
a member can update their own path from the chain alone, and someone who
falls behind can catch up the same way.

### Leaving

There are four ways out, from cheapest per member to most expensive:

- **Swept or rewritten with a cohort.** An operator sweep of an expired
  cohort costs 158 to 203 vB per leaf. Owners who leave together through
  `REWRITE_h` pay about 165 vB each.
- **Cooperatively.** The member asks; the operator folds the exit into its
  next transition (spec 9.3). One message.
- **Batched with other exits.** Two owners in one `EXIT_2` average 842 vB.
- **Alone.** One `EXIT_1`, 1,020 vB at depth 16, any time, no one else
  involved.

There are no forced timeouts. A member who never accepted a lease can sit
in the tree indefinitely and leave whenever they like.

### Who has to be online

Most operations have no round at all. Exits, eviction, sweeps, voucher
redemption and detaches are built and broadcast by one party from data
it already holds. `UPDATE` is one exchange of plain Schnorr signatures
between owner and operator, with no nonce round. A voucher is one message
in one direction. The joining round is the only place several parties
coordinate, and only the joiners and the operator take part.

A plain exit can't be pre-signed and left with someone, because the
owner's signature commits to the tree outpoint, which every transition
changes. Trees created with `EXIT_K^t` fix that: the owner signs
`H_exit(tree_id || body(leaf))` once, off-chain, and whoever holds it can
build the exit against whatever root is current, and rebuild it when
outbid. The authorisation is a bearer right until the leaf changes in
anything other than its amount, but it can only ever pay the leaf to its
own `exit_key`.

That last point is the general rule for delegation. Every instrument a
tower holds pays a fixed output that belongs to the member: an exit pays
`P2TR(exit_key)`, a voucher pays its claim leaf, a channel state pays the
balances both sides signed. A tower chooses *when* and at what fee, never
*where* the money goes. [`design/interactivity.md`](design/interactivity.md)
works through every operation, and [`design/towers.md`](design/towers.md)
covers the agents.

## Payments and Lightning

The tree is a custody and settlement layer, not a payment rail. Three
mechanisms move value inside it.

### Channel leaves

Make a leaf's `exit_key` a 2-of-2 between the owner and the operator, and
that leaf hosts a Lightning channel that exists only off-chain. The
channel's funding output doesn't exist yet: it appears at the payout of
whatever transition eventually removes the leaf. Payments between channel
leaves are ordinary HTLC forwards through the operator and **don't touch
the tree**: no spend, no proof, no fee. A tree of `N` channel leaves is a
Lightning node with a one-UTXO footprint, and it's reachable from the
public network because the operator forwards between a channel leaf and
a regular channel with the same hash and timelock arithmetic.

The channels use LN-Symmetry (rebindable `OP_TX` plus
`OP_CHECKSIGFROMSTACK` commitments) rather than penalty transactions,
which is spec Appendix C ([`spec/channel-leaves.md`](spec/channel-leaves.md)).
The price is patience on a force close: the exit has to confirm first,
and it competes with every other transition for the shared output, so
HTLC deadlines need about 220 blocks of headroom against 40 to 80 on the
public network.

### Vouchers

A leaf owner signs "carve this new leaf out of mine", and the holder
redeems it with `CLAIM`: shrink the source leaf, place the new one in an
empty slot, total unchanged. The first step bumps the source's `seq`, so
the same voucher can never verify again. The voucher signs the leaf
*without its amount*, so an operator top-up of the source doesn't void
outstanding vouchers; any other change to the leaf does.

The covenant prevents over-*redemption*, not over-*issuance*: nothing
stops someone signing more vouchers than their balance covers. A voucher
is credit until it's claimed, and redeeming it is an on-chain carve with
two paths, so it costs more than an exit.

Put a payment hash in the voucher and require the preimage, and it
becomes a cheque: `CLAIM^h`. Now you can sell tree balance for Lightning
sats or buy into the tree with Lightning sats and no on-chain coins,
swapping one secret across both legs. The hash lock is 8 bytes of script
and no new opcode, because the preimage is hashed straight into the
signed message: a wrong preimage gives an invalid signature. There's no
on-chain deadline on a voucher (script can say "not before", never "not
after"), so the deadline lives in the Lightning leg, and the HTLC side
has to resolve first.

### Receiving over Lightning

The wallet case: a user with no on-chain coins wants to receive over
Lightning and end up with a balance they can leave with alone. The
operator gives them a credit leaf, and each incoming payment is answered
with a cumulative hash-locked voucher for the running total. No bytes
on-chain per payment, no minimum, no expiry, and the recipient can redeem
the latest voucher by themselves. `CLAIM^x` adds a signature from the
credit leaf's `exit_key` (the recipient) so the operator can't drain the
credit leaf by vouching to itself. [`design/receive.md`](design/receive.md)
has the analysis.

That leaves one payment of trust between the operator settling the HTLC
and signing the voucher. The pending-leaf receive closes it: a pending leaf
owned by the operator but exiting to the recipient, a merge voucher
(`CLAIM^m`) that lifts the recipient's own leaf to an absolute target,
reclaimable by the operator only after a deadline (`RECLAIM_1`), and a
batch settlement of a whole window in one `REWRITE_h`. It's an HTLC that
lives in the tree. [`design/pending-receive.md`](design/pending-receive.md)
walks the flows.

## Trust and failure modes

The operator **can**: refuse to admit someone; evict a leaf whose lease
has run out (paying it in full); refuse to co-sign an `UPDATE`; choose the
order and fees of its own transitions.

The operator **cannot**: move, shrink or rewrite a member's leaf without
the owner's signature; stop an exit; redirect an exit or eviction payout;
create value. Those are covenant rules, and the Lean model proves the
corresponding properties of the state machine.

The rest of the trust model is in three places:

- **Grafts are opaque.** Verify your own path before funding a join, as
  above. This is the one hypothesis in the proofs the covenant can't
  enforce.
- **Vouchers are credit until claimed.** Over-issuance isn't prevented;
  the credit leaf with `CLAIM^x` removes the issue for the receive case.
- **Eviction is cheap.** At about 160 vB per leaf, clearing expired
  members is cheap, which also makes griefing cheap. Members who want a
  hard guarantee pick a far lease or none.

### Throughput: the one-output chain

Every transition spends and recreates the same UTXO, so unconfirmed
transitions form one chain. Relay policy caps that chain (25 descendants
before Bitcoin Core 31.0, the cluster limit of 64 since), so a tree can
process about `kappa` transitions per block, around 25 to 64. The limit
counts transactions, not leaves: a sweep of 51 leaves is one transaction.
The worst case is a mass exit where strangers leave one at a time, and
an adversary can also pin the chain with a cheap early transition. The
spec states this as an explicit contention assumption `[C]` with
`Delta(q) = Delta_L (ceil((beta + q)/kappa) + 1)` (spec 10.5).

The structural answers are batching (a cohort of 64 exits in one
`REWRITE_h`) and `DETACH_h`, which moves a cohort into its own output with
its own chain, its own `kappa`, and shorter exits afterwards. In practice
trees should be sized by how fast they need to be able to drain, not by
how many slots the depth allows.

## What it costs

Sharing moves cost out of steady state and into the exit. The FULL
column is measured in the simulator over real transactions at depth 16
(65,536 members); [`design/cost-comparison.md`](design/cost-comparison.md)
has the derivations. The last column is CCV plus the hypothetical
`OP_MERKLESUMUPDATE` of [`design/native-opcodes.md`](design/native-opcodes.md),
measured at 65,536 members: one opcode that verifies a Merkle-sum path
and computes the new root, in place of the unrolled fold. It's a
measurement of where the floor is, not a tier anything depends on.

| Operation | FULL | CCV + `OP_MERKLESUMUPDATE` |
|---|---|---|
| Exit alone, 65,536 members | 1,020 vB (MID 1,355, MIN 1,473, CCV 908) | 541 vB |
| Exit alone, ~1M members | about 1,150 vB | 581 vB |
| Each doubling of the membership | about 32 vB | about 10 vB |
| Two exits batched | 842 vB each | not measured |
| Cohort sweep, 13 / 51 leaves | 203 / 158 vB per leaf | 176 / 153 vB per leaf |
| `REWRITE_h` of 64, everyone exits | about 165 vB per leaf | not measured |
| `REWRITE_h` of 64, every key rotated | about 151 vB per leaf | 147 vB per leaf |
| `REWRITE_h` of 64, every balance topped up | about 108 vB per leaf | 104 vB per leaf |
| `REWRITE_h`, position left unchanged | about 95 vB | not measured |
| `UPDATE` | 1,030 vB | 527 vB |
| `DETACH_h` of a 256-member cohort | about 780 vB (621 under CCV) | not measured |
| Graft of 1 / 256 / 1,024 members | 937 / 679 / 614 vB in total | 495 / 365 / 345 vB in total |
| A payment | 0 (off-chain) | 0 (off-chain) |

The per-leaf cost of removal falls as the cohort grows, because the
interior of the subtree is hashed once rather than once per leaf. The
opcode roughly halves every single-path operation, since the script stops
growing with depth and each level of witness shrinks to one 40-byte
sibling. It barely moves the cohort operations, whose cost is the leaves
they publish rather than the path.

The per-operation table doesn't say which design is cheaper overall,
because the designs spend their bytes at different points: Lightning pays
to open, Ark pays every round, LayerTree pays to leave. So the fair
comparison is **lifetime bytes per member**: the on-chain vbytes that
one member's whole stay costs, from getting in to getting out, with
shared transactions split evenly among the members they serve.

Every row below assumes the member enters in a batch. For Lightning, Ark
and a bare UTXO that's one 43 vB output in a shared transaction; for
LayerTree it's a 1/256 share of a 256-member graft (679 vB / 256, about
3 vB). The columns then vary only how the member leaves:

- **Never exits alone.** The cheapest way out. In LayerTree that's selling
  the balance off-chain by voucher or over Lightning, so the member adds
  nothing past their entry share. In Lightning it's a cooperative close
  (154 vB), in Ark a cooperative exit in a round.
- **Exits in a batch.** In LayerTree, the 51-leaf cohort sweep (158 vB
  per leaf), which requires the member to have accepted a lease.
- **Exits alone.** The unilateral path: LayerTree's `EXIT_1`, a Lightning
  force close (commitment, anchor child and sweep, 530 vB), or Ark's
  2,511 vB unroll of its branch of the round tree.

| | Never exits alone | Exits in a batch | Exits alone |
|---|---|---|---|
| LayerTree, dense | 3 | 161 | 1,023 |
| Lightning channel | 197 | 197 | 573 |
| Ark round tree | 86 | 86 | 2,554 |
| Bare UTXO | 154 | 154 | 154 |

A bare UTXO is received once and spent once, the same 154 vB however
its owner leaves. LayerTree beats it, and every other row, in the first
two columns, and loses to Lightning and the bare UTXO in the third. A
member who stays until swept or sells out off-chain pays almost nothing;
a member who insists on leaving alone pays for the proof.

Against Ark specifically: a LayerTree exit is one transaction against
Ark's 16-level branch plus a claim (2,511 vB at the same size), with no
expiry, no refresh, and no operator liquidity locked up for refreshes. Ark
wins on running today with no soft fork, on cheap cooperative entry and
exit (about 43 vB), and on parallel exits, which unroll independently
rather than queueing on one output.

## Opcodes and tiers

Every transition is built against four opcode sets, so the cost of each
proposal is measured rather than argued:

| Tier | Opcodes | Exit at depth 16 | Notes |
|---|---|---|---|
| FULL | tapleaf `0xC2` (BIP-441 restored opcodes), `OP_TX`, `OP_CHECKSIGFROMSTACK`, EC point ops | 1,020 vB | every transition; the reference |
| MID | tapleaf `0xC0` with `OP_CAT`, `OP_TX`, `OP_CHECKSIGFROMSTACK`, `OP_TWEAKADD` | 1,355 vB | every transition; 4-byte arithmetic, so sums under 2^31 sat and cohort rewrites of at most 32 full positions |
| MIN | `OP_CAT` and `OP_TWEAKADD` only | 1,473 vB | exit and `SPLIT`; the existence proof |
| CCV | `OP_CHECKCONTRACTVERIFY` (BIP-443) and `OP_TX` | 908 vB | every MID transition; the cheapest exit |

MIN is the interesting one. It has no introspection opcode, so the script
can't read the transaction it's in. But `OP_CHECKSIG` does see the
transaction. So the script builds the BIP-341 signature message itself
from the fields it wants to pin, hashes it, and checks a signature over
it under the generator `G` with nonce `G`. For that key and nonce the
signature is something the script can compute, so it authorises nothing;
what it buys is *binding*, because `OP_CHECKSIG` hashes the real
transaction and passes only if it matches the message the script built.
The upshot is that a one-transaction exit needs only `OP_CAT` and one
point-tweak opcode.

A template-only set like BIP 448 (`OP_TEMPLATEHASH`,
`OP_CHECKSIGFROMSTACK`, `OP_INTERNALKEY`) isn't enough, because it has no
`OP_CAT`. The script has to concatenate leaf bytes and sibling hashes to
recompute the path, add up the sums, and put a *new* root, computed at
spend time, into the next output's key. A template commits to outputs
fixed in advance, and using `OP_CHECKSIGFROMSTACK` to approve a new
template brings back a signer.

For a sense of the floor: a single hypothetical Merkle-sum-update opcode,
measured in the simulator and kept out of every tier, would make an exit
541 vB at 65,536 members with 252 bytes of script at any depth
([`design/native-opcodes.md`](design/native-opcodes.md)).

## How it's verified

| Layer | Check |
|---|---|
| State-machine rules | Lean 4, about 4,500 lines, 72 theorems, no `sorry`, axiom-audited |
| Compiled scripts | 7,353 simulator checks across the four tiers (1,610 FULL, 1,391 MID, 57 MIN, 4,295 CCV), each rule with targeted negatives, plus 220 for channel leaves |
| Python against Go | 145 byte-exact golden scripts and a shared BIP-341 sighash vector |
| Go transactions | 427 Go-built witnesses replayed through the simulator |
| Composable security | a UC argument in the full paper, with the Lean theorems as its lemmas |

The Lean model proves the rules: a node that verifies against a root
really is the node at that position, every valid sequence of steps
conserves the sum, and any leaf holder can always build an accepted exit,
given that the root really is a tree's root (which is what "verify your
path before funding a join" guarantees). The scripts are checked by
execution, not proof: the simulator runs every compiled script against a
reference tree, including a negative case for each rule.

## Where the code lives

| Path | What's there |
|---|---|
| `tools/` | The Python reference and tapscript simulator: `layertree_ref.py` (tree, vectors), `layertree_scripts.py` (FULL), `layertree_mid.py`, `layertree_min.py`, `layertree_ccv.py`, `layertree_chan.py` (channel leaves), `script_sim.py`, and a `test_*.py` per tier |
| `tree/` | Go: leaves, Merkle-sum nodes, dense and sparse trees, paths and proof compression (`tree.go`), and the taproot binding (`taproot.go`, with BIP-341's `NUMS` as `NUMSHex`) |
| `script/` | Go: the script generators per tier (`full.go`, `mid.go`, `min.go`, `ccv.go`, `chan.go`), byte-exact against `spec/golden.json` |
| `txn/` | Go: one transaction builder per transition, the tier selected from the tree's options (`tier.go`), witness assembly and BIP-341 signing |
| `msg/` | Go: off-chain TLV messages, proofs, vouchers, join and channel messages |
| `formal/` | The Lean 4 model |
| `paper/` | The paper, short and full versions |

Go can build and sign every transition but can't execute the scripts,
since no Bitcoin node has these opcodes. `tools/replay_txn_dump.py` is
what closes that loop. `CLAUDE.md` has the full command matrix.

## Further reading

The spec and paper:

- [`spec/layertree.md`](spec/layertree.md): the normative specification.
- [`spec/channel-leaves.md`](spec/channel-leaves.md): Appendix C, Lightning channels in leaves.
- [`spec/fee-analysis.md`](spec/fee-analysis.md): fees from 1 to 250 sat/vB.
- [The paper](https://layertree.tech/paper/main.pdf), and the
  [full version](https://layertree.tech/paper/main-full.pdf) with the UC
  proof and the Lean appendix.
- [`formal/README.md`](formal/README.md): what the Lean model proves.

Design notes, by topic:

- [`design/interactivity.md`](design/interactivity.md): who has to be online for each operation, and how that compares with the alternatives.
- [`design/receive.md`](design/receive.md): receiving over Lightning into a credit leaf.
- [`design/pending-receive.md`](design/pending-receive.md): the atomic receive with pending leaves.
- [`design/towers.md`](design/towers.md): what an agent acting for an offline member holds and can do.
- [`design/batching.md`](design/batching.md): how `REWRITE_h` and `DETACH_h` share one path across a cohort.
- [`design/graft.md`](design/graft.md): how a cohort joins, who trusts whom, funding costs.
- [`design/cost-comparison.md`](design/cost-comparison.md): bytes against a bare UTXO, Lightning and Ark.
- [`design/tree-comparison.md`](design/tree-comparison.md): dense against sparse, and why the radix stays 2.
- [`design/native-opcodes.md`](design/native-opcodes.md): the CCV tier and the hypothetical Merkle-sum opcode.
- [`design/review.md`](design/review.md): the review that shaped the construction, finding by finding.
- [`design/status.md`](design/status.md): current state and the decision log.

The explainer site at [layertree.tech](https://layertree.tech) walks the
same material with interactive diagrams.
