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

## The instrument: a cumulative voucher

A voucher (`CLAIM`, spec 7.5) is the operator's signature over a message
that names a source leaf the operator owns and a claim leaf for the
recipient. Anyone holding the voucher can redeem it on-chain without the
operator, and the covenant moves the amount from the source leaf to the
new claim leaf. Against a dedicated credit leaf the voucher is redeemed
under `CLAIM^x` (spec 7.5.3, below), which also takes the recipient's
exit-key signature; the voucher itself is the same plain message.

A single receive runs as follows. The invoice names a payment hash whose
preimage the operator holds when the payer's HTLC arrives: either the
operator draws the preimage and issues the invoice on the recipient's
behalf, or the recipient draws it and hands it to the operator. The
payer's HTLC arrives at the operator's Lightning node, which is the last
hop, so the HTLC pays the operator. The operator MUST hold the preimage
and settle that inbound HTLC before it issues or reissues the voucher.
Once it has been paid, it issues the recipient a plain voucher for the
new running total. Nothing reaches the chain. The recipient now holds a
redeemable claim on the tree, and the operator has been paid.

The order is the point, and an earlier draft of this page had it
backwards. That draft had the recipient keep the preimage and the
operator issue a hash-locked voucher (`CLAIM^h`, 7.5.1) under it before
the HTLC settled. The preimage then came from the party the voucher
pays, which is the ordering 9.6.2 rule 1 forbids, and on a credit leaf
it gave the recipient a free option: withhold the preimage, let the
inbound HTLC expire and be failed back to the payer, and redeem the
voucher later anyway. The issuer of a hash-locked voucher retires it by
advancing the source leaf's `seq` (9.6.1), and the credit-leaf
configuration below removes every way for the operator to do that, so
each failed receive would have been a voucher the operator could never
void (`design/audit/channels.md`, B2). Settling first means the operator
only ever vouches for money it already holds. The recipient's exposure
is the one payment between the operator settling and the operator
issuing, against the operator's honesty: a provider that takes the
payment and stops issuing, which is the exposure this page accepts
below. The hash-locked form keeps its place where 9.6.2 puts it, with
the issuer drawing the preimage and the HTLC paying the issuer, as when
a member buys a leaf with off-chain funds (9.6.1).

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
they can exit from alone. The graft itself does not retire the vouchers:
each credit leaf's `seq` must still advance, which today is one `UPDATE`
per credit leaf (1,073 vbytes at `D = 16`), or about 133 vbytes per
recipient (149 under `^x`) when the cohort rewrite `REWRITE_h` of spec
7.9 advances a whole subtree of credit leaves in one transaction. Until a
voucher is retired the operator, not the recipient, carries the risk of
paying twice (`design/graft.md`). The on-chain `CLAIM^x` is what the recipient
does if the operator stops cooperating, and the fact that it exists is
what makes the off-chain settlement safe to accept.

## What it costs

| | Ark client today | Tree with cumulative vouchers |
|---|---|---|
| On-chain bytes per receive | 0 | 0 |
| Minimum receivable amount | the VTXO floor; below it, a ledger credit | none on what can be received; `DUST_MIN` (spec 6.2, 7.5 rule 6, 330 sat recommended) on what can be redeemed, so sub-floor amounts accumulate in the voucher until they reach it |
| Entry for the user | boarding transaction, or a share of a round | share of a cohort graft, about 1 vbyte, plus the operator's funding |
| Funding the receive capacity | none on-chain: the swap server funds the VTXO or books a ledger credit | the operator tops up each credit leaf as credit accrues, by amount-only `REWRITE_h^x`, about 120 vbytes per position batched per cohort; capacity funded ahead of the vouchers is the recipient's on every unilateral path |
| Cooperative settlement | VTXO in the next round | operator grafts the recipient's leaf in the next cohort (about 1 vbyte) and retires the voucher by advancing the credit leaf's `seq`: one `UPDATE` per credit leaf, 1,073 vbytes, or about 133 per recipient with `REWRITE_h` (spec 7.9, `design/batching.md`) |
| Unilateral settlement | unroll the round tree, about 2,511 vbytes at `D = 16`, then a timelock | one `CLAIM^x`, about 1,678 vbytes at `D = 16` today, about 1,130 with a sibling-pair claim (below), no timelock |
| Expiry | the round; funds must be refreshed | none; the voucher stays redeemable until `seq` advances |
| Liveness required of the user | refresh before expiry | none |

The redemption cost is the economic floor, and `DUST_MIN` is the hard
one: a voucher whose amount is below it cannot be carved at all, and one
that would leave less than `DUST_MIN` behind in the source leaf cannot be
carved either unless it drains the leaf (spec 7.5 rule 6), because a leaf
below the dust threshold could never be removed by a standard
transaction. Small receives therefore accumulate in the cumulative
voucher until they reach the floor, and the issuer keeps a credit leaf's
balance clear of the residual case. At 10 sat/vB a `CLAIM^x` costs about
16,800 sat, so a recipient would not redeem a small balance alone even
once it is redeemable; they would let it accumulate, have the operator
graft it as a leaf in a cohort, or redeem it straight into a channel
leaf whose exit key is a 2-of-2 and pay onward over Lightning from
there.

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

The roughly 1,678 vbytes is the FULL tier at `D = 16` with no help, and
it is large for a structural reason: a `CLAIM^x` proves two positions,
the source leaf and the claim slot, so it carries two full paths of
sixteen unrolled levels each, two leaves, the voucher signature and the
exit-key signature. A hash-locked `CLAIM^h` carries the preimage in place
of the exit-key signature and measures 1,670 vbytes.

The CCV tier reduces it a little: with `r` and `m` gone from the
witness it carries `CLAIM^h` at 3,495 bytes of script and 1,658 of
witness at `D = 16`, 1,557 vbytes against the FULL tier's 1,670.

The largest saving needs no new opcode. A credit leaf dedicated to one
recipient can have its sibling slot reserved for that recipient's claim
leaf, so the source and the claim sit under one path and share fifteen
of the sixteen levels. A `CLAIM` variant that folds the sibling pair
under a single path (the "sibling pairs" shape of spec 13.4) costs about
1,130 vbytes on the measured parts, a third less, and it suits the
credit leaf exactly because the operator chose the slot. Two further
cuts stack on it: the `OP_MULTI OP_CAT` level and the `OP_INTERNALKEY`
fast path of spec 13.3 and 13.8, perhaps 150 vbytes more; and a native
Merkle-sum opcode, which would put the redemption near 500 vbytes.
Neither is built; the sibling-pair `CLAIM` is the one this page
recommends building first. (Binding the voucher to a tree identifier
compiled into the script instead of `m`, the third cut an earlier draft
listed, is now the rule in every tier: spec 6.2 and 7.5.)

## What the user trusts

The covenant stops the operator from redeeming more than the source leaf
holds and from paying the voucher to anyone but the recipient. It does not
stop two things (10.3): over-issuance, where the operator signs vouchers
against one leaf for more than the leaf holds, and voiding, where the
operator advances the source leaf's `seq` before the recipient redeems.

Over-issuance disappears when the source leaf is dedicated to the
recipient: one credit leaf per user, funded by the operator. Every voucher
against that leaf goes to the same recipient, so there is nobody else to
over-issue to, and the recipient can watch the leaf's amount in the tree.

The funding is where the comparison with a Lightning service provider
funding an inbound channel fails. A credit leaf's whole amount is the
recipient's on every path the operator can take alone: `EXIT^=` and
eviction pay all of it to the recipient's exit key, and `UPDATE^x`
cannot shrink it without the recipient's signature. The part the
operator has not vouched for is therefore recoverable only with the
recipient's consent, and a recipient who prefers to wait collects it on
the first removal the operator starts (`design/audit/channels.md`, B3).
An inbound channel returns its unused side to the provider at close; a
credit leaf does not. The operator should therefore fund a credit leaf
only with what it has already vouched for or is about to, and top it up
as credit accrues rather than pre-fund an allocation. The top-up is an
amount-only increase under `REWRITE_h^x`, which needs only the
operator's signature (7.9 rule 3; the 0.11.0 exemption still allows it
for any leaf whose `seq` is not `SEQ_FINAL`, which a credit leaf's is
not), at about 120 vbytes per position when a cohort of credit leaves is
topped up in one rewrite; or an `UPDATE^x` the recipient co-signs.

Voiding is the harder one, and the spec's own answer is a race: redeem
promptly, within the contention bound of 10.5. For the credit leaf to be
trust-free the operator must be unable to change it without the
recipient. Three of the operator's moves are already covered by existing
tree-creation parameters. With `UPDATE^x` (7.4 rule 5) the operator
cannot rewrite the leaf without a signature from its exit key, which is
the recipient's. With `EXIT^=` (7.2 rule 6) an exit of the leaf pays its
whole amount to the exit key, so the operator leaving the leaf only pays
the recipient more than it owed. Eviction is not a voiding move either:
it pays the whole balance to the exit key, the recipient's, so it pays
the recipient at least what any voucher would. A credit leaf should
therefore carry a finite lease long enough for its purpose, with the
operator as evictor, and not a NUMS evictor as an earlier draft of this
page suggested (spec 10.3, 10.8). A voucher binds the claim leaf's bytes
and not its position, so the recipient chooses the empty position its
claim lands in, and under spec 7.5 rule 5 the claim inherits the source's
evictor. Against a NUMS-evictor credit leaf every voucher is then a
leaf that can be placed in an empty slot of any cohort and never swept;
against a leased one the claim expires with the credit leaf. The
operator should also keep cohort subtrees full or detach them: a full
subtree has no empty slot for a claim, and a detached cohort can be
carved into only by its own members (`design/audit/protocol.md`, A6).
The fourth move is not covered: the operator can issue itself a voucher
against the credit leaf and redeem it with plain `CLAIM`, which needs no
consent from anyone. That drains the leaf and voids the recipient's
voucher in one transaction.

The fix is the addition `UPDATE^x` made to `UPDATE`: a `CLAIM^x` variant
whose redemption requires a signature over the transaction by the source
leaf's exit key, alongside the voucher. The recipient is that key, so the
recipient's own redemptions carry it for free, and the operator cannot
redeem against the leaf at all. With `UPDATE^x`, `EXIT^=` and `CLAIM^x`
in the taptree, and with `REWRITE_h^x` in place of the cohort rewrite
`REWRITE_h` or no rewrite at all, a credit leaf's balance can only grow
or be paid to its recipient, and the recipient's exposure is the
operator's liveness:
nothing worse than a provider that stops issuing. The variant is now spec
7.5.3, with `CLAIM^hx` as the same addition to the hash-locked form; it
measures 7 bytes over `CLAIM` in the FULL tier, as `UPDATE^x` over
`UPDATE`, and 64 bytes of witness, and `tools/test_scripts.py`
exercises the credit-leaf scenario directly: the operator's own voucher
plus its own transaction signature fails. The Lean model is unaffected,
since `Claim` takes an opaque authorisation.

The rewrite matters because plain `REWRITE_h` (spec 7.9) asks for the
owner's and the operator's signatures and nothing else, and the operator
is both for a credit leaf: it could rewrite the leaf down to 1 sat and
keep the rest, which voids the recipient's voucher as surely as a
`CLAIM` would. `REWRITE_h^x` (7.9 rule 7) adds the exit-key signature,
as `UPDATE^x` does. A recipient MUST check from `m` that the taptree
carries no plain `REWRITE_h` before it treats a credit leaf as
trust-free (spec 10.3; `design/audit/protocol.md`, A3).

## A bond against equivocation

A bond that the operator forfeits on misbehaviour reaches one of the two
risks and not the other, and the line between them is whether the
misbehaviour has a compact proof.

Over-issuance is equivocation, and equivocation is provable. Two
vouchers signed by the same key against the same source leaf, byte for
byte and at the same `seq`, whose claim amounts sum to more than the
leaf holds, are a self-contained fraud proof; so is a single voucher
whose claim exceeds its own source leaf's amount. A `SLASH` transition
could check that in script with two `OP_CHECKSIGFROMSTACK` verifications
over the voucher messages and an amount comparison, and pay the
operator's bond leaf to whoever presents the proof, at about the cost of
a `CLAIM`. The vouchers bind `m`, so a proof from another tree does not
verify here, and nobody can forge the operator's signature, so a false
slash is impossible. This is what makes the shared bond-leaf model of
9.6, one operator leaf backing vouchers to many recipients, an honest
instrument rather than a promise. Its limit is sizing: a bond is claimed
once, so it is a deterrent and first-victim insurance, not full
coverage of every outstanding voucher.

Voiding has no compact proof, so no bond reaches it. A `seq` advance on
the source leaf looks the same in script whether another recipient
redeemed a legitimate voucher, after which the issuer must reissue and
a failure to reissue is an absence nothing can prove, or the operator
rewrote the leaf itself. Proving that the operator authorised a spend
which replaced the leaf by something other than the holder's claim
would mean reconstructing another transaction's sighash in script,
hundreds of bytes and a large witness, to catch what the seven bytes of
`CLAIM^x` prevent outright. For the dedicated credit leaf the right
design removes the capability. A dedicated leaf also turns over-issuance
into a recipient-side check, because every voucher against that leaf
goes to the same recipient, who verifies the leaf's amount in the tree
before accepting.

So the two models pair with two remedies: a slashable bond for the
shared bond leaf, where equivocation is the risk; and `CLAIM^x` with
`UPDATE^x`, `EXIT^=` and a finite lease for the dedicated credit leaf,
where nothing is left to slash.

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
a credit leaf with cumulative vouchers issued after each payment settles: zero bytes per
payment, no floor, no expiry, no liveness, and with `CLAIM^x` no trust in
the operator beyond its continuing to issue. For spending and for two-way
traffic, a channel leaf: ordinary HTLC forwards through the operator, a
force close of about 1,681 vbytes over about 146 blocks, and a watchtower
for stale states. A user can start on the first and move to the second by
redeeming the voucher into a leaf whose exit key is the channel's 2-of-2,
which is one transaction and the only one that ever reaches the chain.

## What is settled and what is not

The receive flow needs no hash lock: the operator settles the inbound
HTLC first and then issues a plain voucher, so the Lightning leg and the
voucher are never open at the same time on the same hash. The hash-locked
swap of 9.6.2 (7.5.1, 9.6.1, `test_swap` on PR #8) is a different flow,
in which the issuer draws the preimage and is the party the HTLC pays;
its ordering rules do not describe a receive. The dedicated credit leaf is a deployment choice
within the current rules, and `CLAIM^x`, the one addition this page
proposed, is now spec 7.5.3 in the FULL tier. A credit line in a tree
whose taptree carries it, with `UPDATE^x` and `EXIT^=`, without `SPLIT`
and without a plain `REWRITE_h`, no longer carries the voiding race of
10.3; one in a tree
without it carries the same trust an Ark out-of-round payment carries
until its next round, but with a consensus-enforced claim behind it
rather than a ledger entry.
