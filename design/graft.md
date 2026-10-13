# Grafting: how a cohort joins, and whom it trusts

*An informative page on `JOIN_h`, the transition that adds members to a
tree, and on who has to trust whom when it runs. Costs follow the model
of `design/cost-comparison.md`: the measured sizes in
`spec/scripts/sizes.md` plus the skeleton of `spec/fee-analysis.md` (774 weight units for a
transition with no payout, such as a join). Section numbers refer to `spec/layertree.md`.*

## What a graft is

A dense tree of depth `D` has `2^D` positions, and the node at height `h`
and index `i` covers the `2^h` positions from `i·2^h` (5.4). When every
one of those positions is empty, the node is the constant `E_h`. `JOIN_h`
replaces such an empty node with a node `(R_h, sum_h)` that the operator
built off-chain from a batch of new leaves, and it recreates the tree
output with `sum_h` more in it (7.3). The witness carries the sibling path
from height `h` to the root, the new node's hash and sum, the operator's
signature, `r` and `m`. Nothing below height `h` appears on-chain.

The script walks only the `D - h` levels above the slot, at about 32
vbytes a level, so a bigger cohort is a cheaper transaction. At `D = 16`
a single leaf (`JOIN_0`) costs 937 vbytes, four (`JOIN_2`) cost 872, 256
(`JOIN_8`) cost 679, and 1,024 (`JOIN_10`) cost 614. The script for
`JOIN_h` depends only on `D - h`, so `JOIN_8` at `D = 16` has the same
script as the measured `JOIN_0` at `D = 8`, and the witness differs by at
most a byte of direction bits per level. Each height is its own tapleaf,
and the operator fixes the set of heights at tree creation (6.2, 9.1). The
reference taptree carries `JOIN_0` and `JOIN_2`; a deployment that wants
256-member cohorts compiles `JOIN_8`. A slot of height `h` takes any
cohort of up to `2^h` members, since unused positions inside the subtree
are `E_0`.

`JOINK_K` is the other batching form: `K` single-leaf joins in one
transaction under one operator signature, each proving its empty position
against the root the previous step produced (7.6). Each step pays a full
`D`-level path, so a second join at `D = 16` saves only the skeleton and
costs about 557 vbytes (11). `JOINK_K` is the batching form of the
sparse profile, which cannot graft. A sparse leaf's position is a hash of its owner key and
nonce, so a cohort's leaves land at unrelated positions and never fill an
aligned subtree together. The sparse profile therefore has `JOIN_0` only,
at 1,601 vbytes for one leaf at `D = 32`, and `JOINK_2` brings that to
1,411 per leaf (`design/tree-comparison.md`).

## What the covenant checks, and what it does not

`JOIN_h` enforces three rules (7.3). The old node at the slot is `E_h`, so
every position in the slot was empty. Output 0's amount is `S + sum_h`,
where `S` is the input amount, so the new sum is funded by other inputs
and no value is created. And the operator signed the transaction. The
script also fixes output 0's scriptPubKey to `TREE_SPK(r', m)` with `r'`
the fold of the new node over the same path, as for every transition
(7.1).

Rule 4 states what is left out. The covenant does not read inside the
grafted subtree. It sees a 32-byte hash and an eight-byte sum, and it
cannot tell a real tree of 256 leaves from 32 random bytes. That is what
makes the graft constant-size, and it is the source of every trust
question on this page.

The consequences are precise, and the Lean model states them as
`join_sound` (`formal/LayerTree/Transitions.lean`). A valid join
identifies a position `p` of height `h` whose subtree was empty, output 0
equals the old sum plus `sum_h`, and for any tree `u` whose root is the
grafted node, the new root is the old tree with `u` placed at `p`. Every
other position keeps its contents. So a graft cannot move, shrink or
rewrite an existing leaf, and the paths of existing members stay valid
after one sibling update that they compute from the witness (9.7).

If the grafted node has no preimage, nothing below it can ever be proven,
so no `EXIT`, `UPDATE`, `CLAIM` or sweep can touch it. The value `sum_h`
stays in the tree output for good. That value is exactly what the graft
added, and nothing else in the tree is affected: every other leaf remains
payable, because the conservation argument of 10.2 holds whether or not a
sibling node has a preimage. Design review F18 records this as the one
place where the proofs carry a hypothesis the covenant cannot enforce: the
covenant protects the sum, and the joiners protect their membership. A
frozen node also means the tree can never reach the empty root `E_D`, so
the terminal exit of 7.8 is never available to the last real member.

## Who carries what risk

| Party | Can | Cannot | What protects them |
|---|---|---|---|
| Operator | fill an empty aligned slot with any node it signs and funds; choose positions, heights and lease terms | graft over an occupied position; graft without funding `sum_h`; move, shrink or rewrite an existing leaf; freeze value it or its funders did not put in | 7.3 rules 1 to 3, `join_sound` |
| Operator, griefing | graft opaque or zero-sum nodes into empty slots | affect any existing leaf | each such graft costs it a transaction fee, the value it grafts and the slots it fills |
| Member funding with an input | check the whole transaction before signing | have the input spent into any other transaction | its `SIGHASH_DEFAULT` signature commits to output 0, so to `r'` (9.2) |
| Member buying in off-chain | check the confirmed graft before paying, or pay through a `CLAIM^h` voucher | be made to pay for a leaf that is not in the tree, if they check | path verification against the confirmed root; the voucher's covenant-enforced redemption |
| Operator funding its own leaves | freeze only its own money with a bad graft | change anything for the other members of the cohort | 10.2: each member's safety depends only on their own path |
| Existing member | nothing; they need not be online | be harmed by a graft | `join_sound`: only positions that held `E_h` change |
| Anyone else | relay a signed graft | create one | the operator signature, tested as "join without operator" |

The operator's only power is to fill empty slots, and it pays for each
fill. An opaque node costs it a graft transaction and freezes whatever sum
it claims. A node with sum zero and a hash other than `E_h` freezes no
value but uses up `2^h` positions for good, and since only the operator
can fill positions, wasting them limits only its own tree.

A member who contributes an input checks the unsigned transaction as
9.2 step 3 lists: the slot folds as `E_h` to the current root, their leaf
folds to `(R_h, sum_h)` with every sum recomputed, and output 0 commits to
the new root for `S + sum_h`. They then sign with a hash type that commits
to every output, and the signature is their sign-off: the only transaction
that can spend their input is one whose output 0 commits to a root
containing their leaf. They need not check anyone else's leaf. By 10.2, any set of
leaves whose paths verify sums to at most the root, so a co-member's bad
leaf cannot make a good one unpayable.

A member who pays off-chain has nothing to sign on-chain. They wait for
the graft to confirm, check the same path from their leaf to the confirmed
`r'`, and then pay over Lightning. Paying first means trusting the
operator to graft. The alternative is a hash-locked voucher (7.5.1, 9.6.1)
against a funded source leaf the operator already holds in the tree: the
member pays an invoice whose preimage lets them redeem the voucher with
`CLAIM^h`, which the covenant enforces. A voucher carries the residual
risks of 10.3, over-issuance and voiding by an advance of the source
leaf's `seq`, and `design/receive.md` gives the credit-leaf design that
narrows them.

So, do all parties need to sign for a graft to be safe? No. Existing
members never sign and take no risk, because a graft only fills positions
that were empty. The operator signs because it is the only party allowed
to add leaves. The only parties who need assurance are those who put money
in, and they get it in one of two ways: by signing an input to a
transaction they have checked, or by checking the confirmed result before
paying.

## Funding a graft and what it costs

The covenant does not say where `sum_h` comes from, which leaves three
ways to fund a cohort.

In an **operator-funded** graft the operator supplies `sum_h` from its own
input. The members hold no on-chain funds; each buys a balance by paying
the operator over Lightning after the graft confirms, or through a
`CLAIM^h` voucher, or receives into a credit leaf as in
`design/receive.md`. The operator carries the credit risk of a member who
never pays, which is a risk to the operator and not to the other members.
The member's own on-chain cost is their share of one transaction.

In a **member-funded** graft each member adds an input to the graft
transaction and signs it, as 9.2 describes. Each input is about 58 vbytes
for a P2TR key-path spend, plus 43 for a change output if the member needs
one. The transaction cannot be broadcast until every member has signed,
so one absent member stalls the cohort and the operator rebuilds it
without them. This is a liveness cost, not a safety one: an unsigned or
unbroadcast graft leaves each member's input theirs. The same signatures
fix the fee: raising it by replacement needs every member to sign again,
so spec 9.2 has a member-funded graft carry an operator change output or
a P2A anchor, which the operator can spend in a child to bump the fee
without a new round (`design/audit/protocol.md`, A8).

A **mixed** graft has the operator fund some leaves and members fund
others. By 10.2 this changes nothing for anyone: each member's safety
rests on their own path, and an operator that grafts a bad node into its
own part of the cohort freezes only its own money.

![Entry cost per member against cohort size](figures/join-amortisation.svg)

| Graft at `D = 16` unless noted | Members | Transaction vbytes | Per member, operator-funded | Per member, member-funded |
|---|---|---|---|---|
| `JOIN_0` | 1 | 937 | 937 | about 995 |
| `JOIN_2` | 4 | 872 | 218 | about 280 |
| `JOIN_4` | 16 | 808 | 51 | about 110 |
| `JOIN_6` | 64 | 743 | 11.6 | about 70 |
| `JOIN_8` | 256 | 679 | 2.7 | about 61 |
| `JOIN_10` | 1,024 | 614 | 0.60 | about 59 |
| Sparse `JOIN_0`, `D = 32` | 1 | 1,601 | 1,601 | about 1,660 |
| Sparse `JOINK_2`, `D = 32` | 2 | 2,821 | 1,411 | about 1,470 |
| One P2TR output in an on-chain batch | | | 43 | |
| Channel open in its own transaction | | | 154 | |

The `JOIN_0` and `JOIN_2` rows at `D = 16` are measured. The others use
the measured row with the same number of levels: `JOIN_4` is `JOIN_0` at
`D = 12`, `JOIN_6` is `JOIN_2` at `D = 12`, `JOIN_8` is `JOIN_0` at
`D = 8`, and `JOIN_10` is `JOIN_2` at `D = 8`. The skeleton of 774 weight
units (spec 11, a transition with no payout) already contains one fee
input and a change output, so the operator's funding input is inside the
transaction figure. The
member-funded column adds 58 vbytes per member and leaves change out.

An operator-funded cohort of 256 costs each member under three vbytes,
against 43 for an output in an on-chain batch. A member-funded cohort
costs about 61, so the saving against an on-chain batch is gone: members
who bring their own coins pay for their inputs whatever they join. The
graft is cheapest when the entry money moves off-chain.

## Designing a cohort

The operator chooses the slot, and that choice is what later batching
depends on. Grafting members into one aligned subtree places them under a
common path, and every batch shape in `design/batching.md` works on an
aligned subtree: the cohort sweep `EVICT_SUBTREE_h` (7.7), the owner
multiproof `EXIT_SUBTREE_h` of 13.4, the cohort rewrite `REWRITE_h`, and
`DETACH_h`, which moves the subtree into its own tree output. Members
placed at scattered positions share only the few levels near the root and
batch with nobody.

A cohort should share a lease. The sweep removes every leaf in its subtree
in one transaction, about 158 vbytes per leaf for 51 leaves, but only if
every leaf has the operator as `evictor_key` and an `evict_after` that has
passed (7.7). One leaf with a NUMS evictor or a later lease blocks the
sweep of its whole subtree. The operator should therefore put members
with the same lease terms in the same cohort, and members who want no
lease in a cohort of their own. Filling a gap inside a cohort's subtree
later with `JOIN_0` is allowed, since the gap is `E_0`, but a joiner on
different terms blocks the cohort's sweep. So does a member renewed in
place by `UPDATE`, until its new lease passes, and so does a leaf carved
into a gap by a member of a later-lease cohort, which 7.5 rule 5 allows
because the carve inherits the carver's lease. Spec 9.4 therefore has
renewal move the member into a cohort with the new lease, and has the
operator keep cohort subtrees full or detached
(`design/audit/protocol.md`, A7).

The subtree rewrite of `design/batching.md` is itself a graft that
publishes its leaves. Its witness carries every position of the subtree,
old and new, and the script folds the new leaves to the new node. A
position that goes from `E_0` to a funded leaf is a join, and because the
leaves are in the witness, the new node is grounded by construction: the
Lean model's grounding hypothesis holds without any member's check. A
cohort joined that way pays for every leaf it publishes, an estimated 60
vbytes or more per leaf against under three for a 256-member `JOIN_8`, in
exchange for not needing the 9.2 obligation.
`JOIN_h` makes the opposite trade.

## Grafting as settlement

A graft is also how off-chain credit becomes leaves that members can exit
alone. Section 9.6 lets the issuer of a voucher discharge it in two ways:
the recipient redeems it with `CLAIM`, or the issuer includes the claim
leaf in the tree by other means and the recipient verifies its inclusion.
An operator holding outstanding vouchers from Lightning receives can put
every recipient's claim leaf into the next cohort, and each recipient
checks their path against the confirmed root as an off-chain buyer does.
That settles a batch of credit at about one vbyte per recipient for a
cohort of a thousand, against 1,670 vbytes for one `CLAIM^h` redemption at
`D = 16`.

The graft does not void the vouchers it settles. A voucher stays
redeemable until its source leaf's `seq` advances (7.5), so a recipient
holding both a grafted leaf and the voucher could be paid twice, and the
operator must retire the voucher by advancing `seq`. When one bond leaf
backs many vouchers, one `UPDATE` of that leaf retires them all and the
operator reissues the ones not yet settled. When each recipient has a
dedicated credit leaf, as `design/receive.md` recommends, retiring is one
`UPDATE` per leaf, 1,030 vbytes each at `D = 16`, unless the leaves sit in
one subtree and a rewrite advances them together. Until the voucher is
retired, the operator carries the double-payment risk, not the recipient.

## What is proven and what is tested

The Lean model proves `join_sound`: the slot was empty, output 0 is
`S + sum_h`, and a grounded graft yields the old tree with the subtree
inserted, after which every leaf in it is payable by the `payable`
theorem. `Steps.sum` conserves sums with no assumption about the grafted
node, and `Steps.sound` needs each new node to be grounded, which is the
hypothesis the joiners supply. `formal/README.md` lists both.

The tests check the rules by running the scripts. The FULL suite
(`tools/test_scripts.py`) rejects a dense `JOIN_2` over an occupied
subtree, an underfunded `JOIN_2` whose output 0 is one satoshi short, a
`JOIN_2` signed by a member's key instead of the operator's, a sparse
`JOIN_0` at a position that already holds a leaf, a `JOINK_2` whose second
path was computed against the old root, and an underfunded `JOINK_2`. The
MID suite (`tools/test_mid.py`) rejects an underfunded `JOIN_2`, and
`spec/golden.json` pins the FULL and MID join scripts that the Go code
reproduces byte for byte. The MIN tier has no join script yet; its
generator builds `EXIT_1` and `SPLIT` only.

The obligation of 9.2, that each member verifies their own path before
funding, is procedural, and no script can enforce it, because the script
never sees the subtree. The covenant guarantees that a bad graft freezes
only the value it brings; only the member can check that their leaf is
inside that value.

## Worked example: 256 members at `D = 16`

An operator runs a dense tree at `D = 16` whose taptree includes
`JOIN_8`. To keep eight tapleaves and the 129-byte control block it
compiles `JOIN_8` in place of `JOIN_2`; adding it as a ninth leaf instead
would cost every spend 8 more vbytes (11.1). It admits 256 members with
100,000 satoshis each, a common `evict_after` a year out, and itself as
evictor. It builds the height-8 subtree from the 256 leaves and gets
`(R_8, 25,600,000)`. It picks the empty slot `(8, 37)`, which covers
positions 9,472 to 9,727.

The graft transaction has two inputs and two outputs.

| | Contents | Size |
|---|---|---|
| Input 0 | the tree output, amount `S`, spent by the `JOIN_8` tapleaf | 41 vbytes, plus the witness |
| Witness | 8 direction bits and siblings, `R_8`, `le64(25,600,000)`, the operator's signature, `r`, `m`; script; control block | 1,313 bytes of script, about 500 of witness data, 129 of control block |
| Input 1 | the operator's P2TR coin of 26,000,000 sat | about 58 vbytes |
| Output 0 | `TREE_SPK(r', m)` for `S + 25,600,000` | 43 vbytes |
| Output 1 | the operator's change | 43 vbytes |

Under the fee model the transaction is 679 vbytes; built exactly as in the
table, with a P2TR funding input and P2TR change and no payout, it is
about 680. At 10 sat/vB that is about 6,800 satoshis, under 27 per member.

The operator sends each member their leaf, the 8 siblings inside the
subtree, the 8 siblings above it, and the transaction id. Once the
transaction has the member's usual number of confirmations (10.11), the
member checks four things: the leaf's fields are as agreed (amount, their
own owner and exit keys, the operator as evictor, the lease); the leaf
folds over the subtree path to `(R_8, 25,600,000)` with every sum
recomputed; that node folds over the upper path to the root `r'`; and the
confirmed output 0 is `TREE_SPK(r', m)` for the tree's known `m`, with an
amount equal to the sum in `r'`. Then they pay 100,000 satoshis over Lightning, or redeem
a hash-locked voucher they already paid for. They keep the 116-byte leaf,
16 siblings of 41 bytes and the transaction id, under one kilobyte, and
update it from each later transition's witness (9.7).

The tree's existing members did nothing and are unaffected. Had the
operator grafted a node with no tree behind it, every member's check
would fail, nobody would pay, and the operator would have frozen 25.6
million of its own satoshis. A member-funded version of the same cohort
would carry 256 more inputs, about 14,800 vbytes, and would wait for all
256 signatures before broadcast.
