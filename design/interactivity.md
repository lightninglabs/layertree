# Interactivity: who has to be online, and when

*An informative page on the synchronous steps of the protocol: for each
operation, who must be present at the same time, who signs, and what
happens when someone is away. The rules are spec 7 (covenant), 9
(off-chain protocol), 10.1 (trust model), 10.5 (liveness) and Appendix C
(channel leaves). The comparison draws on spec 12, `design/cost-comparison.md`
and `design/batching.md`.*

Shared-UTXO designs pay for the sharing in rounds. A channel factory
needs every member's signature on every state. An Ark round needs every
participant online in a window, and the round restarts if one drops. A
pre-signed tree needs everyone at creation and everyone again at expiry.
LayerTree's bet is that a covenant checking a Merkle-sum proof replaces
most of those rounds: the chain verifies that a leaf is in the tree, so no
other member has to vouch for it by signing. This page says exactly where
that bet holds, where a round comes back, and how the result compares
with the alternatives.

We count in two units. A **signature** is one party's consent to one
transaction. A **synchronous step** is a point where one party cannot
proceed until another answers: a message exchange, not a broadcast. An
operation with zero synchronous steps is one a party can complete from
its own state and the chain, with nobody else awake. Plain BIP-340
signatures over the transaction need no nonce exchange, so two parties
signing the same template is one exchange (one sends the template, the
other returns a signature), not a round. MuSig2 is different: its nonce
and partial-signature phases are two exchanges between every pair of
signers, and they must complete before the first signature exists.

## The three kinds of operation

**Alone.** `EXIT_K`, eviction, `EVICT_SUBTREE_h`, `CLAIM` in every form,
and `DETACH_h` are built, signed and broadcast by one party from data it
already holds: its leaf, its sibling path, the current root and `m`. The
member exiting needs the operator for nothing; the operator evicting
needs the member for nothing; a voucher holder redeeming needs neither
the issuer nor the operator. Zero synchronous steps. The only liveness
these demand is the actor's own, and 10.5's rule that an exit must be
rebuilt if a competing spend confirms first: the owner's signature
commits to the tree outpoint, which every transition changes, so a plain
exit cannot be pre-signed and left with a tower. A tree created with
`EXIT_K^t` (spec 7.2 rule 7, the paper's P8) changes that: the owner
signs `(tree_id, leaf)` once, off-chain, and whoever holds the signature
builds the exact-payout exit against whatever root is current, and
rebuilds it when outbid, with the owner offline.

**Two parties, one exchange.** `UPDATE` (and `UPDATE^x`) carries two
plain Schnorr signatures over the same transaction, the owner's and the
operator's (7.4 rule 2), so either side drafts the transaction, the
other returns a signature, and whoever holds both broadcasts. One
exchange, in either order, with no nonce round. Voucher issuance is one
message in one direction: the issuer signs `(tree_id, source_leaf,
claim_leaf)` and hands it over; the recipient verifies the source leaf
against the chain on its own (9.6) and never has to answer. A
cooperative exit request (9.3) is the same shape as an `UPDATE`: the
owner asks, the operator folds the exit into its next transition.
`UPDATE^x` adds a third signer, the exit key, whose holder (a channel
counterparty or a credit leaf's recipient) returns one more signature on
the same template.

**A round.** Three operations need several parties' signatures on one
transaction, and the signatures are only good for that transaction.

A *self-funded* `JOIN_h` is a signing round among the funders (9.2). The
operator fixes the cohort, builds the subtree and sends each joiner the
unsigned transaction with its leaf and both paths. Each joiner checks
that its leaf folds to the grafted node, that the slot folds as empty to
the current root and that output 0 commits to the new root, then signs
its own input with `SIGHASH_DEFAULT`. Because every signature commits
to output 0, and output 0 commits to a subtree holding every new leaf,
the cohort must be fixed before anyone signs, and a joiner who withdraws
or changes its leaf invalidates every other signature. The operator then
rebuilds and collects again: the abort-and-retry exposure of a coinjoin
or an Ark round. The covenant itself needs only the operator's signature
(7.3 rule 2); the round is the price of members funding their own leaves
on-chain in the same transaction. An *operator-funded* graft has no
round at all: the operator fronts the value, signs alone, and each
member pays off-chain after checking its path against the confirmed
root, or ahead of time through a hash-locked voucher that the covenant
enforces (9.6.1, `design/graft.md`).

`REWRITE_h` collects one plain signature from the owner of every leaf
that changes, plus the operator's (7.9 rule 3). Signatures arrive in any
order over any channel, so there is no nonce round, but all of them bind
the same old and new subtree, so a change to either after the first
signature invalidates it. Three rules keep the round small. A leaf that
only gains amount needs no signature, so a payment within the cohort
needs only the payer's (the exception stops at a `SEQ_FINAL` leaf, whose
capacity its channel states fix). A leaf nobody signs for passes
through unchanged, so members who are away are not in the round and are
not harmed by it. And every removed leaf is paid exactly its amount, so
an owner's signature consents to its own change and nothing more. A
rewrite that fails to gather its signatures leaves the old state
standing; nothing expires.

Opening a *channel leaf* is a two-party round before the join (C.5.1,
C.3.6). The parties agree the capacity, balances, `csv_delay` and
`evict_after`, derive `chan_id` and the funding key `P_chan`, exchange
MuSig2 signatures for `settle_1` and then `update_1`, and only then does
the user sign its input to the `JOIN`. That ordering is what makes the
leaf safe to create: a leaf whose exit key nobody can spend unilaterally
must never exist. MuSig2 makes each state two exchanges (nonces, then
partial signatures), as in any taproot channel; the tree adds no
exchange of its own, and the operator's `JOIN` signature follows once.

## Per operation

| Operation | Who signs | Synchronous steps | Who must be online at the same time | If a party is away |
|---|---|---|---|---|
| `EXIT_K` | the owner (each owner, for `K > 1`) | 0 (one exchange among the `K` owners for a joint exit) | the exiter | nothing changes; the leaf waits |
| `EXIT_K^t` (7.2 rule 7) | the owner, once, in advance (one off-chain signature per leaf) | 0 | nobody; the holder of the authorisation builds, and anyone may assemble `K` of them | a tower exits and rebuilds for the owner; the owner voids a stale authorisation by changing the leaf |
| Eviction by `EXIT` | the evictor | 0 | the evictor, after the lease | the member is paid in full without acting |
| `EVICT_SUBTREE_h` | the operator | 0 | the operator, after every lease in the cohort | members are paid in full; one unexpired lease delays the sweep (9.4) |
| `DETACH_h` | the operator | 0 | the operator | members need no new data; their old path cut to `h` levels is their proof |
| `CLAIM`, `CLAIM^h`, `CLAIM^x` | nobody on the transaction (the voucher is the authorisation); `CLAIM^x` adds the exit key, held by the redeemer | 0 | the holder | the issuer is not consulted; the operator is not consulted |
| Voucher issuance | the issuer, off-chain | 0 (one message, no reply needed) | the issuer | the recipient verifies alone and can redeem alone |
| `SPLIT` | the payer | 0 | the payer | the payee receives a leaf it can exit later |
| `UPDATE`, `UPDATE^x` | owner and operator (and the exit key) | 1 exchange | both at the time of signing, not at broadcast | the leaf keeps its old terms; a lease still runs out |
| Cooperative exit | owner and operator | 1 exchange | both, briefly | the owner exits alone at any time |
| `JOIN_h`, operator-funded | the operator | 0 on-chain; off-chain payment after the graft confirms, or a hash-locked voucher before | the operator | a member who has not paid holds a leaf it did not pay for; the operator carries the credit |
| `JOIN_h`, self-funded | the operator and every funder | 1 round among the funders (abort and retry) | every funder, before the operator broadcasts | the round restarts without them |
| `REWRITE_h` | the operator and every owner whose leaf changes | signatures gathered asynchronously; a change to the set restarts them | the owners who change | an unchanged leaf passes through; the member need not be present |
| Channel leaf open | both channel parties (MuSig2), then the operator | 2 exchanges per state, before the join | both parties, then the operator | no leaf is created (the user does not sign its input) |
| Channel leaf update | both channel parties (MuSig2) | 2 exchanges per state | both parties | the state stands; either party can force-close |
| Channel leaf close | the party closing, then both for the state machine | 0 to start (`EXIT` or eviction), then the pre-signed chain | the closer; a watchtower can finish (C.9.3) | the counterparty's balance is paid by the pre-signed settlement |

The column that matters for a hub is the fourth. Across the whole
table, the only party who must be online for *another* member's
operation is the operator, and only for `UPDATE`, a cooperative exit and
a graft; and the operator can refuse but cannot delay beyond the fee
contention of 10.5. No member is ever needed for another member's exit,
join, payment or eviction. That is what the covenant buys: in a factory
every member is in every round, and in LayerTree a member is in a round
only when its own leaf changes or it funds its own entry.

## Why most operations have no round

The covenant checks a proof where other designs check a signature set.
A leaf's inclusion is proven by its sibling path against the committed
root, and 10.2 shows that any set of leaves whose paths verify sums to at
most the root, so one member's safety depends on its own path alone and
on nobody else's conduct. Adding leaves needs only the operator's
signature because a graft can fill only positions that were empty
(`join_sound`); it cannot touch an existing leaf, so existing members
have nothing to consent to. Removing a leaf pays it exactly, so the
member removed has nothing to lose and nothing to sign. The operations
that do need a member's signature are exactly the ones that change that
member's leaf: its own exit, its own update, its own share of a rewrite.

Rounds come back in two places, and both are chosen rather than forced.
Members who fund their own leaves on-chain in one transaction sign one
transaction together; the alternative, paying the operator off-chain
against a confirmed graft or a hash-locked voucher, trades the round for
a credit relationship with the operator, which `design/graft.md` lays
out. And a cohort that settles many balances at once in `REWRITE_h`
needs each changed owner's signature on the same transaction, because
consent is per leaf and there is no aggregate key to speak for the
cohort. Spec 13.5 considers storing a MuSig2 aggregate of the cohort's
owner keys in each node so that one signature could replace a subtree,
and sets it aside for this reason: the aggregate would need interactive
nonce coordination among the whole cohort for every rewrite, which is
the Ark round the design is trying not to have. Per-leaf signatures cost
16 vB each (spec 11) and no coordination.

## Liveness over a member's lifetime

Being in the tree asks nothing of a member until it wants something. A
member need not come online for anyone else's join, exit or sweep; its
path changes when the tree does, and it recovers the new path from the
witnesses of the spends it missed (9.7), so an absent member can
reconstruct its state from the chain alone. There is no round to attend
and no refresh before an expiry: the shared output never expires, and
the only clock on a leaf is its own lease, which the operator can let
run out and which ends with the member paid in full to its exit key.
A member who wants a longer guarantee asks for a later lease at entry or
an `UPDATE` before it runs out.

Three things do need the member's presence. To exit it must be online,
build the transaction against the current root and sign; if a competing
spend confirms first it rebuilds (10.5's bound `Delta(q)` says how long
that can take under assumption [C]). To redeem a voucher it must act
before the issuer advances `seq`, so a voucher holder is online when it
learns the preimage of a swap (9.6.2 rule 4) and treats a voucher whose
source lease could pass before a redemption confirms as unsecured (9.6).
And a channel leaf is a channel: both parties follow the state machine,
and a watchtower can answer stale states on their behalf (C.9.3), with
the same `cltv_expiry_delta` discipline as any routing node plus the
exit's own confirmation time (C.4.4).

| | LayerTree leaf | LayerTree channel leaf | Lightning channel | Ark VTXO |
|---|---|---|---|---|
| To receive | online for nothing; a voucher arrives as one message | online for the HTLC | online for the HTLC | online for the round, or trust the server's out-of-round payment until the next round |
| To exit | online once, to build and sign; under `EXIT_K^t` online once to sign in advance, a tower builds and rebuilds | online once to exit, then the pre-signed update chain, a tower can finish; under `EXIT_K^t` the tower can also start it | a tower can publish the commitment | online before the round expires, then `O(log N)` transactions |
| Before an expiry | nothing; the lease ends with the member paid | nothing | nothing | refresh every round or lose the funds to the server |
| For other members' operations | never | never | n/a | in every round that includes you |

## Compared with the alternatives

The table of spec 12 scores exits in transactions; this one scores the
same designs in who has to be awake.

| | Join | Pay off-chain | Settle balances on-chain | Exit | Evict a member | Expiry |
|---|---|---|---|---|---|---|
| **LayerTree** | operator alone (operator-funded), or one round among the funders (self-funded) | one message (voucher) or a two-party channel update | `UPDATE`: one exchange; `REWRITE_h`: the changed owners' signatures | alone | operator alone, after the lease, paying the member | none |
| **Lightning channel** | two parties, MuSig2 or 2-of-2 | two parties | two parties | alone (force close) | n/a | none |
| **Channel factory** | all `N` sign | two parties within a channel | all `N` sign every factory state | publish the pre-signed tree, `O(log N)` transactions | no | none, but every change needs everyone |
| **Ark, pre-signed rounds** | all round participants sign the round tree with the server, in a window; a dropout restarts the round | out-of-round: server co-signs, trusted until the next round | the next round, with everyone | alone, `O(log N)` pre-signed transactions plus a timelock | no; the round expires | every round (weeks); refresh or forfeit |
| **Ark, covenant (CTV)** | funders sign their inputs; the tree needs no signatures | as above | the next round | alone, `O(log N)` template transactions | no; the round expires | every round |
| **Timeout tree** | all sign at creation (or CTV templates) | channels inside | a new tree | alone, `O(log N)` transactions | no; the tree expires | per tree; the operator reclaims what is left |
| **Payment pool (TLUV, CoinPool, OP_EVICT)** | all participants sign the new pool state | within the pool, all sign | all sign | alone, one transaction | `OP_EVICT`: the remaining participants sign the member out | none |
| **CTV or CCV tree (MATT)** | operator builds the template tree; no signatures | varies | a new tree | alone, `O(log N)` transactions | no | per design |

Three columns carry the argument.

*Join.* Every pre-signed design needs the whole set present at creation,
because the interior is signatures. Covenant trees remove the signatures
but keep the shape: a member still exits by publishing `O(log N)`
transactions. LayerTree's graft needs the operator alone, and when
members fund themselves the round is among the joiners only, never the
existing members, who do not even learn of it until the next spend.

*Settle balances on-chain.* An Ark round settles every participant's new
balance in one transaction at the price of everyone being online in the
window and the round expiring; a factory does the same at the price of
`N` signatures for every change. `REWRITE_h` settles a cohort's balances
in one transaction with only the members whose leaves change signing,
unchanged members asleep, and no expiry if the signatures never arrive.
`design/batching.md` has the sizes: about 147 vB per changed leaf at
`h = 6`, against 1,030 vB for an `UPDATE` each.

*Exit and expiry.* Every design in the table lets a member leave alone,
but all of them except the pools make the member publish a path of
transactions, and the round-based ones make the member come back before
an expiry or lose the position. A LayerTree member exits in one
transaction, with no timelock, and never has to come back for an
expiry: the only clock is a lease it agreed to, and the lease ends with
its money paid to it. The pools match the one-transaction exit, but each
with a purpose-built opcode and with every change to the pool signed by
every participant; LayerTree takes the change-side interactivity to one
party, the operator, and pays for it with the operator's eviction right
and its control of empty positions (10.1).

## What the operator can and cannot do with its position

The operator is the one party present in most exchanges, so its
absence is the case to check. If the operator vanishes, every member
can still exit alone, every voucher holder can still redeem, and every
channel leaf can still be force-closed by either party; what stops is
growth (no grafts), cooperative change (no `UPDATE`, no `REWRITE_h`) and
the retirement of settled vouchers, so issuers keep their liabilities
until they exit. If the operator is present and hostile, it can refuse
to co-sign and contend for the tree output by fee, which [C] bounds, and
it can fill a cohort's empty positions so that partial-balance vouchers
have nowhere to land (9.6, 10.1); it cannot move, reduce or delay a
leaf, change the taptree, or change a lease without the owner. A member
who has made no promise to anyone else loses nothing to an operator's
absence but the chance to cooperate.

## What is left out, and why

MuSig2 aggregate node keys (13.5) would let one signature replace a
subtree and would give Ark-style round updates for a whole cohort; they
would also make every cohort update an interactive nonce round among the
cohort, and they are deliberately out of the base protocol. Adaptor
signatures for swaps and channels are an off-chain concern of Appendix C
and `notes.md`, not of the tree. The pre-signable exit (P8) was a
proposal from the paper's reviews; it landed as `EXIT_K^t` (spec 7.2
rule 7, 0.12.1) and moved the exit from "online once" to "a tower can do
it", the one change on this page that altered a row of the lifetime
table. A relative lock on value-neutral transitions (P1c) was declined:
the first adversarial spend per block already invalidates an honest exit,
so the lock would remove nothing and cost throughput.

## Pointers

- Rules: spec 7.2 to 7.10 (who signs each transition), 9.2 (the joining
  round), 9.3 and 9.4 (exit and eviction), 9.6 (vouchers), 10.1 (trust
  model), 10.5 (liveness and [C]), 13.5 (aggregate keys, set aside).
- Channel leaves: Appendix C.3.6 (signing order), C.5.1 (opening before
  the join), C.4.4 (deadlines), C.9.3 (watchtowers).
- Costs of the shapes compared here: `design/batching.md`,
  `design/cost-comparison.md` (time and liveness table),
  `design/graft.md` (who carries what risk in a graft).
