# Intro

In the past, to contextualize the business opportunities we saw w.r.t LN, we
coined the adage: squeeze out more transactions per byte. In other words, we
can benefit from allowing our customers to increase the batching coefficient
either on, or off-chain. One good example of this is multi-channel Loop In. If
a user has N channels, and runs out of available outbound bandwidth for them,
they can:

  1. Close out those N channels in N transactions, then open up N more
     channels. Naively this takes 2N transactions (N to close and N to open).
     With a bit of optimization (batched channel opening), this can be reduced
     to N + 1 transactions (single batched txn to re-open them all).

  2. Use Loop In to do a single transaction on-chain, which can allow them to
     replenish all N channels with a single on-chain transaction.

Compared with Option 1, Option 2 is _much_ more chain efficient. It's possible
to amortize the cost even further, by having users collaborate on that initial
transaction. With this extra layer of batching N users, each having M channels
can do a single on-chain transaction to replenish M*N channels offchain.

In this post I want to motivate a broadening of the batching adage described
above. The goal is to extend the model from squeezing more transactions per
byte to: maximizing the amount of _economic activity_ per byte.

Before we dive head first into this model, let's take a quick detail to explore
the extent of what's possible with on-chain batching.

# The Batching Holy Grail

What's the holy grail of batching? The majestic 1-input-1-output transaction.
This is the smallest possible transaction on can make that still represents
useful economic activity. Creating such a transaction is easy enough, the hard
party is figuring out a workable access model to enable N (where N is
potentially rather large) to interact with the output. So what exactly are our
options here?

## Naive Multi-Sig

If we just put all N users into the output, and create a multi-sig of all of
them, then we have an initially workable solution. This can work pretty well
until you start to grow the size of N. Growing the size of N means more
signatures that need to be obtained, and with that a greater on-chain cost as
each signature consumes witness space (sigs + keys).

## Musig2 Aggregate Signatures

By reaching for musig2, we're able to further scale this solution, as we'll
only have a single signature and key on chain. However, we still run into
issues w.r.t interaction: in order to update this shared output, we need _all_
parties to be online long enough to sign for the new state. If we have nested
transactions from this single output, then all those transactions also need to
be-resigned each time.

## SIGHASH_NOINPUT

If we add SIGHASH_NOINPUT to the mix, then we can further reduce the number of
signatures that need to be obtained, as we're able to re-use the signatures of
this nested transaction set. To see why, we need to make the observation that
SIGHASH_NOINPUT doesn't sign the txid portion of the prev out. This means that
as long as the script is the same, the signature can be re-used.

This benefit has a tradeoff: namely that you now need to worry about signature
replays. We'll return to the issue of replays layer, but for practical
purposes, just don't re-use scripts in multi-party settings and you're good.

## CTV

With all of the above, we only need to set up the tree once per cohort, and
those signatures can be re-used if the cohort doesn't change. However, we still
have the issue of the signatures for the root output.

With CTV, we can just eliminate those signatures altogether, as we pre-commit
to a set of fixed spending paths ahead of time. In this case, we'll ensure that
the root output can only be spent ti something like a fan-out output, or any
other output that advances the state machine we're trying to set up.

A shortcoming of CTV is that we can't make dynamic state transition decision.
This is due to the design of CTV: in order to arrive at the template hash, you
need to pre-compute the entire computation DAG ahead of time.

The interaction to make a new output also still exists. The amount of messages
we need to exchange has been reduced, but as we increase N, we still incur over
head per batch and per user.

## The Ark Trick

The one little trick that Ark introduced was: don't try to get everyone to
exchange params for a new batch, just create a new batch, and have the old one
expire. In other words, just make a new UTXO, and have the old one explode.
Everyone needs to either jump to the new UTXO, or exit the old one in time.
This introduces a new liveness assumption, and also velocity scaling capital
requirements, but serves to side step some other problems.

In order to create a new batch, you now only need to involve those that want to
do something new in that batch, or are joining for the first time. In practice,
you're able to reduce the critical factor of N for new batches.

With this, you don't quite get a 1-in-1-out however. Instead you need an output
for the Ark state, then another for something they call a connector tree. For
any new entrants joining, you also need inputs to add them to a new instance.
Similarly if people are doing the co-op exit, you gain additional outputs for
all of them.

One observation I had last year is that you actually don't need the connector
tree at all. As we'll touch on below, the connector tree adds additional write
amplification when you go on-chain uncooperatively. In place of that, we can
just use adapter signatures! There's no sort of strong reveal ordering
requirement here.

Connectors work by creating a signed transaction with one of the inputs not yet
existing on-chain. Once that output exist, the dependent transaction can be
broadcast.

Adapter signatures can fill that same role. This time, the initiation
transaction just reveals a secret via an adapter, then the dependent
transaction can use that adapter to create a valid transaction. This little
trick also makes any of the dependent transactions smaller as they have one
less input.

## Pocket Universes

Another option to achieve the slimmest possible batching transaction is the
Pocket Universe concept. For this option, we truly do have a single output and
input. The inputs/outputs are a TAP commitment, where the leaves of the tree
hold all the user balances. The orchestrator can't _steal_ funds as they don't
have the private keys, but they _can_ omit leaves all together.

Without additional on-chain introspection capabilities, the best security model
here is something similar to Liquid: a large-ish threshold signature. It'll
take all the parties colluding to censor an output.

One promising observation is that: it's possible to prove that you were in
state N, but not state N+1. Using that fact, it seems feasible that we can
construct a sort of fraud proof to allow users to exit in the face of
censorship.

# On-Chain Transaction Amplification

Databases have a concept of _write_ amplification: at times to update a single
key-value, additional I/O write traffic must also hit the disk. One example is
the popular LSM tree structure that powers LevelDB. Updating a key doesn't
update the primary database. Instead, it writes to a log that the key was
updated. Later on once this log gets too large, the db needs to compact the log
by actually committing all the updates to disk. This is a form of write
amplification: updating one key eventually leads to many other updates.

Popular on-chain batching constructs also have a similar form of amplification,
in the form of on-chain transaction amplification. If you have some sort of
nested or tree structure, in order to forcibly exit, a user needs to broadcast
additional transactions to get on the chain.

Typically these transactions are structured in a tree, so you "only" need to
broadcast log(n) transactions to exit. If you increase the fan out factor, then
you can also further reduce the final amt, by going with a higher radix in the
tree.

This helps, but only on the surface: each transaction means a new on-chain fee
-- who will pay the cost to exit? If the cost to aggregate cost to exit is
greater than the amount you hold in the system, then it's uneconomical to exit,
as if you do so, you'll siphon most of your funds away to fees.

If timelocks are involved, then this adds additional pressure as funds can
potentially be lost if the entire tree can't be manifested in time.

## A Path To Constant Space Exit

To address this issue, I've come up with a path to achieve constant sized exit
from such systems.

In this line of solutions, the tree still exists, but it's now purely an
off-chain construct. We have a single output with the sum of all user balances,
along with an off-chain tree that commits to the set of user balances.

To join the system, you do a normal PSBT flow to spend your input into the
current shared state. You then work with the orchestrator to obtain a _signed
voucher_. This voucher is your ticket to exiting the system. Once you obtain
this signed voucher, and verify your new leaf in the tree, you sign off on your
input.

In order to exit, you present that signed voucher to the _output_ directly. You
also need a merkle proof of the tree of user balances. The contract executes

the following logic:
  * Verify that the voucher was signed by the relevant key(s).
  * Verify that the merkle proof is valid, based on the prior committed user
    balance tree.
  * Verify that the pubkey included in the voucher is the same as the leaf.
  * Verify that the created output is exactly that leaf amt, and pays to a P2TR
    derived from that pubkey.
  * Verify that the change output commits to the user balances tree, with no
    changes, other than the leaf is missing.

Assuming the above is possible, then the user is able to exit by sending just a
single message to the contract. The contract can even accept multiple voucher
exit requests in a batch, and process them all in a single transaction.

An MS-SMT tree is a perfect data structure for the user balance tree as:

  * It commits to the root value of all balances. Which makes it easy to audit
    that more vouchers than the output can handle haven't been issued.
  * You can use exclusion proofs to verify that only the user balance changed,
    and nothing else.

AFAICT, the approach above, code name "LayerTree" is possible given the
following updates:

  * CSFS to be able to verify the signature on the signed vouchers.
  * OP_CAT to be able to reconstruct the signed voucher from inputs (verify the
    balance and pubkey fields.
  * OP_EC_ADD+OP_EC_MUL to be able to verify that tapscript tree contains the
    user balance commitment.

A big mental model shift that this line of technique relies on is: on-chain
state machines that can transition between states using signed events. In the
case of LayerTree, the signed event is the voucher. Note that we're no longer
using OP_CHECKSIG in the normal manner.

Returning back to replays, in order to generalize this model, we also need to
handle replay protection. We can do this if we embed a nonce in the the
contract. With each step, the nonce must increment, this prevents a 3rd
party from replaying a public signed event.

IMO, this is the endgame of how Bitcoin contracts should look like. It embraces
a functional model where you provide the state, the next input, and then output
the state, and some optional additional outputs. The `protofsm` package in lnd
is an example of this model, but in a normal programming context.

## Interim Solutions

Without future soft forks, the next best path is to simply: partition the
state, and leverage the existing tools at our disposal. For each instance of the
state (the shared output), you don't like N get very large. You then use normal
adapter sig or HTLCs to sync changes between a given partition.

For the state that isn't in a partition (no level of nesting), one can utilize
normal MIMO batching techniques to cut down on space.

# Applications of Unified Batching

Now that we know what the unified batching concept is (the holy grail), a
pertinent question is: well what can we actually do with it?

The answer to that is: pretty much anything! The introduction of Taproot Assets
means that we can express new types of financial contracts/interactions using
normal Bitcoin transactions. In addition to the normal transactional flows, we
can also batch and aggregate higher level financial primitives, all
manifested as Bitcion UTXOs.

Further, we can:

  * Unify the on-chain footprint of the new account-based Loop Variants
    (Static Loop In + Loop Out Reservations).

  * Facilitate direct on-chain swaps for stablecoins between participants.

  * Enable on-chain atomic novation for DLC based contracts.

  * Allow for mostly off-chain (via a unified on-chain footprint) direct
    account to account Bitcoin and stablecoin transfers.

  * Enable off-chain channel funding (again anchoring w/ a single on-chain
    transaction). Depending on the implementation, these channels by need to
    have a finite lifetime.

  * Create channel liquidity pools that allow parties to redistribute channel
    liquidity off-chain (via an on-chain anchor tx) amongst their set of users.

  * Alleviate the velocity based capital requirements of Ark by constructing a
    type of zero coupon bond to allow 3rd party funding (this deserves a post
    of its own!).

# Unified Batching from the Ground Up

Stuff like LayerTree is nice, but a soft fork isn't guaranteed in the next few
years, nor every really (as much as I would prefer otherwise!). So how can we
incrementally build towards this concept?

A starting point is the past posts on this ML re "Loop as a Preferred CLM
Account Holder", and the "Generalized Transaction Batching" posts.

## Accounts as UTXO Deltas

The Pool mode is to give each user an account, then continually spend that
account in new batches, which serves to refresh the expiry period of a given
account along the way.

One issue with this is that if we keep restricting users to a single UTXO per
account, then 3rd party funding isn't possible. By 3rd party funding, I mean
the ability to give out an address, then have someone send to that as normal to
add more funds to your account. This can work for normal addresses, and also
TAP addresses.

The solution here is straight forward: we allow multiple UTXOs to exit per
account, but require that they're _all_ spent down in each batch to consolidate
UTXOs to reduce further batch costs (more inputs in a batch, the more expensive
it is).

The next step from there is to optionally enable transfers into and out of the
accounts in a non-batcher manner. If a user isn't sending to anyone else that
has an account, then we can improve UX (less waiting for a complete batch) by
allowing them to be spent by themselves. If enough parties are online, then we
can also just batch these operations as normal.

## Account Based Loop

Next, we turn to lifting Loop into this account based model. The good news is
that with Static Loop In and Loop Out Reservations, we're already part of the
way there. With these variants a user has an account that can be used to fund
Loop Ins, or is funded by us, and gives them easier access to Loop Out.

A related concept here is the concept of the "SwapDK", which is essentially an
account based bridge to the LN for select users. With this users function
purely using an account, and don't even run an LN node themselves. Any
transfers into and out of the account a bridged via Loop.

The issue with this is that in times of high on-chain fees, updating the
account can be uneconomical. However, if we can achieve a sufficient level of
batching, then the concept is more generally feasible.

If the Loop In accounts are nested purely off-chain, then there's no marginal
cost (other than the on-chain anchor) for ends. The same goes for Loop Out, as
long as the user has use for the funds within the account system.

Similar to the post above, as part of this change, Loop would start to use the
Pool backend as an orchestration backend. A Loop In and Out become just another
order to the Pool auctioneer. If batching fails for w/e reason, then things
call back to the normal singular flows (depending on the batch instantiations).

From a user's PoV, there's just a unified liquidity service, and the backend
microservice boundaries are opaque.

## Maximizing Batching Across Cohorts

What a propose is effectively optimistic batching, without global unified
state, as we need covenants to make that truly shine.

Without covenants, we can leverage tools like transaction cut-through for
chained off-chain batches.

Given a sufficient adequately online cohort, we can leverage tools such as the
HyperLoop concept, effectively a batch-within-the-batch. Taking things a step
further, given an external co-signer, we can achieve off-chain channel funding
outside the Ark setting (assumption re not double signing). For TAP-specific
channels, a Pocket Universe can be used to further compress the on-chain
footprint.

## Sharded Ark State

As mentioned above, w/o additional soft forks, you want to ideally keep N very
small. Likely well below the 100's. To mitigate this fragmentation, normal
adapter signatures and HTLCs can be used to swap between instances.

The downside of Ark in general is the additional liveness assumptions. If
another co-signer also operates the Ark, then they can be a balancing force to
ensure that even if users aren't online, if they didn't make the jump to the
next batch, then they're still properly refunded. You can think of this as the
Good Guy Greg operating mode, where a 3rd party serves to keep the operator in
check.

## Incremental LayerTree

In another post (as this one is already rather long), I'll paint a picture of how
with each new additional softfork, the LayerTree system can be incrementally
instantiated.
