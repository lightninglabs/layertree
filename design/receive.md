# Receiving over Lightning into a tree

*An informative analysis of the wallet case: a user with no on-chain
funds receives a Lightning payment and wants a balance they can leave with
on their own. It compares what an Ark client does today with what the
tree offers, and it names one small script variant the trust-free version
needs. Costs follow the model of `design/cost-comparison.md`.*

## The case

A self-custodial Ark wallet such as Wavelength receives a Lightning
payment through a swap server. If the amount clears the operator's VTXO
floor, the server funds a virtual HTLC and the user ends up with a VTXO:
an out-of-round output that the operator co-signs, that exits through the
round's transaction tree, and that expires with the round. If the amount
is below the floor, the server books a credit in its own ledger instead,
and the credit becomes a VTXO only once enough has accumulated. The user
trusts the operator in both cases: for a VTXO until the next round, and
for a credit entirely, because a ledger row has no on-chain claim behind
it.

The question is whether LayerTree can take the same payment with less
trust and fewer bytes. It can, and the instrument is already in the spec.

## The instrument: a cumulative hash-locked voucher

A hash-locked voucher (`CLAIM^h`, spec 7.5.1) is the operator's signature
over a message that names a source leaf the operator owns, a claim leaf
for the recipient, and a payment hash. Anyone holding the voucher and the
32-byte preimage can redeem it on-chain without the operator, and the
covenant moves the amount from the source leaf to the new claim leaf. The
preimage discipline is the one Lightning uses, so one secret settles both
a Lightning HTLC and the voucher.

A single receive therefore runs as follows, with the roles that 9.6.2
requires. The recipient generates the preimage and issues the invoice,
because the recipient is the party the payment ultimately pays. The
payer's HTLC arrives at the operator's Lightning node. The operator issues
the recipient a voucher for the amount under that hash. The recipient
hands the preimage to the operator, which settles the HTLC toward the
payer. Nothing reaches the chain. The recipient now holds a redeemable claim
on the tree, and the operator has been paid.

Repeated receives do not accumulate as separate vouchers, because every
redemption advances the source leaf's `seq` and voids the others (7.5 and
9.6). They accumulate as one cumulative voucher that the operator
reissues at each receive for the running total, against the same claim
leaf. The recipient keeps the latest, and the latest is the only one worth
redeeming because it is the largest. That is the "signed sequence number,
highest wins" structure, and in this direction it needs no contest
window: only the recipient can redeem, and the recipient never prefers an
older, smaller state.

Most vouchers are never redeemed on-chain, and it is worth saying what
"settled off-chain" means, because the voucher is the recipient's
insurance rather than their normal path. Spec 9.6 gives the issuer two
ways to discharge a voucher: the recipient redeems it with `CLAIM`, or
the issuer includes the claim leaf in the tree by other means, a `JOIN`
of that leaf in the next cohort graft or an `UPDATE`, and the recipient
verifies the leaf's inclusion against the confirmed root. Once the leaf
is in the tree the voucher has done its job; the issuer then retires it
by advancing the source leaf's `seq`, with the recipient's consent under
`CLAIM^x`, so that the same credit cannot be claimed twice. In the wallet
case the operator batches this: every so often it grafts a cohort of
leaves for the recipients whose credit has accumulated, at about one
vbyte per recipient, and the recipients' vouchers are replaced by leaves
they can exit from alone. The on-chain `CLAIM^h` is what the recipient
does if the operator stops cooperating, and the fact that it exists is
what makes the off-chain settlement safe to accept.

## What it costs

| | Ark client today | Tree with cumulative vouchers |
|---|---|---|
| On-chain bytes per receive | 0 | 0 |
| Minimum receivable amount | the VTXO floor; below it, a ledger credit | none beyond dust at redemption; sub-floor amounts accumulate in the voucher |
| Entry for the user | boarding transaction, or a share of a round | share of a cohort graft, about 1 vbyte, plus the operator's funding |
| Cooperative settlement | VTXO in the next round | operator grafts the recipient's leaf in the next cohort and retires the voucher, about 1 vbyte |
| Unilateral settlement | unroll the round tree, about 2,511 vbytes at `D = 16`, then a timelock | one `CLAIM^h`, 1,652 vbytes at `D = 16` today, about 1,130 with a sibling-pair claim (below), no timelock |
| Expiry | the round; funds must be refreshed | none; the voucher stays redeemable until `seq` advances |
| Liveness required of the user | refresh before expiry | none |

The redemption cost is the economic floor. At 10 sat/vB a `CLAIM^h`
costs about 16,500 sat, so a recipient would not redeem a small balance
alone; they would let it accumulate, have the operator graft it as a leaf
in a cohort, or redeem it straight into a channel leaf whose exit key is a
2-of-2 and pay onward over Lightning from there.

The entry row deserves its own paragraph, because it is where the design
is cheapest. A dense graft (`JOIN_h`) admits a whole cohort for the cost
of the levels above its subtree, about 657 vbytes for 1,024 slots at
`D = 16`, and the covenant requires only that the slot was empty and the
new sum is funded. When the operator funds the graft from one of its own
inputs, the whole cohort costs that one input, which the fee model already
counts as the fee input, and the members need no on-chain funds at all: each buys their
balance off-chain, paying a Lightning invoice whose preimage unlocks a
hash-locked voucher for their leaf, or simply receiving into the credit
leaf described above. A user who has never held a UTXO is in the tree for
well under one vbyte of their own. When each member instead funds their
own leaf, every member adds an input to the graft transaction, and the
saving against an on-chain batch shrinks to the output side.

Is a graft safe when only the operator signs it? Yes, for everyone who
holds a leaf already, because a graft can only fill an empty slot; the
Lean theorem `join_sound` says exactly that. The party at risk is a
funder, because the covenant does not read the grafted subtree, and the
protection is that nobody funds before verifying their own path: a member
who contributes an input checks the transaction before signing it, and a
member who buys in off-chain checks the confirmed root before paying or
pays through a hash-locked voucher. `design/graft.md` gives the full
trust model, the funding modes and their costs.

## Making redemption cheaper

The 1,652 vbytes is the FULL tier at `D = 16` with no help, and it is
large for a structural reason: a `CLAIM^h` proves two positions, the
source leaf and the claim slot, so it carries two full paths of sixteen
unrolled levels each, two leaves, the voucher signature and the preimage.
The CCV tier of PR #6 does not reduce it today, because that tier drops
`CLAIM` altogether: the voucher message binds the taptree root `m`, and
the CCV witness no longer carries `m`.

The largest saving needs no new opcode. A credit leaf dedicated to one
recipient can have its sibling slot reserved for that recipient's claim
leaf, so the source and the claim sit under one path and share fifteen
of the sixteen levels. A `CLAIM` variant that folds the sibling pair
under a single path (the "sibling pairs" shape of spec 13.4) costs about
1,130 vbytes on the measured parts, a third less, and it suits the
credit leaf exactly because the operator chose the slot. Three further
cuts stack on it: binding the voucher to a tree identifier compiled into
the script instead of `m`, which would let the CCV tier carry `CLAIM` and
take roughly another fifth off; the `OP_MULTI OP_CAT` level and the
`OP_INTERNALKEY` fast path of spec 13.3 and 13.8, perhaps 150 vbytes
more; and a native Merkle-sum opcode, which would put the redemption
near 500 vbytes. None of these is built; the sibling-pair `CLAIM` is the
one this page recommends building first.

## What the user trusts

The covenant stops the operator from redeeming more than the source leaf
holds and from paying the voucher to anyone but the recipient. It does not
stop two things (10.3): over-issuance, where the operator signs vouchers
against one leaf for more than the leaf holds, and voiding, where the
operator advances the source leaf's `seq` before the recipient redeems.

Over-issuance disappears when the source leaf is dedicated to the
recipient: one credit leaf per user, funded by the operator at graft time
with the inbound capacity it is willing to extend, the way a Lightning
service provider funds an inbound channel. Every voucher against that leaf
goes to the same recipient, so there is nobody else to over-issue to, and
the recipient can watch the leaf's amount in the tree.

Voiding is the harder one, and the spec's own answer is a race: redeem
promptly, within the contention bound of 10.5. For the credit leaf to be
trust-free the operator must be unable to change it without the
recipient. Three of the operator's moves are already covered by existing
tree-creation parameters. With `UPDATE^x` (7.4 rule 5) the operator
cannot rewrite the leaf without a signature from its exit key, which is
the recipient's. With `EXIT^=` (7.2 rule 6) an exit of the leaf pays its
whole amount to the exit key, so the operator leaving the leaf only pays
the recipient more than it owed. An evictor key of NUMS removes eviction.
The fourth move is not covered: the operator can issue itself a voucher
against the credit leaf and redeem it with plain `CLAIM`, which needs no
consent from anyone. That drains the leaf and voids the recipient's
voucher in one transaction.

The fix is the same seven bytes `UPDATE^x` added to `UPDATE`: a `CLAIM^x`
variant whose redemption requires a signature over the transaction by the
source leaf's exit key, alongside the voucher. The recipient is that key,
so the recipient's own redemptions carry it for free, and the operator
cannot redeem against the leaf at all. With `UPDATE^x`, `EXIT^=` and
`CLAIM^x` in the taptree, a credit leaf's balance can only grow or be
paid to its recipient, and the recipient's exposure is the operator's
liveness: nothing worse than a provider that stops issuing. This variant
is not in the spec and would follow the `UPDATE^x` checklist: generator,
tests, golden vectors, Go mirror, tier matrix row. The Lean model is
unaffected, since `Claim` takes an opaque authorisation.

## Why it is one-way

The same structure does not give a one-shot two-way channel, and the
reason is worth stating because it is the usual one. Once the recipient
can also spend from the credit, an older voucher for a larger amount is a
stale state in the spender's hands. Nothing invalidates it except an
advance of `seq`, which the operator cannot perform under `CLAIM^x` and
`UPDATE^x`, or a newer state that the script prefers, which needs a window
in which the counterparty can present it. Every bidirectional channel
design pays for that window somewhere: Lightning with revocation and a
CSV delay, LN-Symmetry with a rebind period, and the channel leaf of
Appendix C with its `csv_delay`. A cumulative voucher avoids the window
only because value flows one way.

So the wallet case has two instruments, and they compose. For receiving,
a credit leaf with cumulative hash-locked vouchers: zero bytes per
payment, no floor, no expiry, no liveness, and with `CLAIM^x` no trust in
the operator beyond its continuing to issue. For spending and for two-way
traffic, a channel leaf: ordinary HTLC forwards through the operator, a
force close of about 1,681 vbytes over about 146 blocks, and a watchtower
for stale states. A user can start on the first and move to the second by
redeeming the voucher into a leaf whose exit key is the channel's 2-of-2,
which is one transaction and the only one that ever reaches the chain.

## What is settled and what is not

The voucher leg, the HTLC leg and their shared preimage are specified and
tested (7.5.1, 9.6.1, 9.6.2, `test_swap` on PR #8). The ordering rules of
9.6.2 apply unchanged: the recipient generates the preimage, the voucher
resolves second, and the operator must not advance `seq` while an HTLC on
the hash is in flight. The dedicated credit leaf is a deployment choice
within the current rules. `CLAIM^x` is the one addition this page proposes,
and until it exists the credit line carries the voiding race of 10.3,
which is the same trust an Ark out-of-round payment carries until its
next round, but with a consensus-enforced claim behind it rather than a
ledger entry.
