# Atomic receive with pending leaves

*A design exploration, not a specification. It asks whether a recipient
can receive a Lightning payment into a tree atomically, with no window in
which the operator holds the payment and the recipient holds nothing
enforceable, and what that costs. It proposes two rule changes and one
optional optimisation, none of them a new opcode, and prices the result
against the settle-first credit leaf of `design/receive.md` and the
channel leaf of Appendix C. Section numbers refer to
`spec/layertree.md`.*

## The gap

`design/receive.md` settles first. The payer's HTLC reaches the operator,
the operator learns the preimage and settles it, and only then signs the
recipient a cumulative voucher for the new running total against the
recipient's credit leaf. Every step after that is trust-free: the credit
leaf's balance can only grow or be paid to the recipient (10.3). The step
before it is not. Between settling and signing, the operator holds the
payment and the recipient holds nothing, so a provider that takes one
payment and stops issuing keeps it. The exposure is bounded, one payment,
and it asks nothing of the recipient, but it is trust.

Closing it means the recipient must hold something enforceable *before*
it releases the preimage, and the operator must be able to get its money
back if the preimage never comes. The second half is a deadline, which is
where the earlier attempts ran aground.

## What was tried, and why it failed

**The recipient's preimage and a hash-locked voucher.** The first draft
of `design/receive.md` had the recipient draw the preimage and the
operator issue a `CLAIM^hx` voucher under its hash before the HTLC
settled. The voucher was enforceable before the reveal, which is the
right shape, but nothing could retire it. If the recipient withheld the
preimage, the inbound HTLC expired and was failed back to the payer, and
the recipient could still redeem the voucher later by publishing the
preimage on-chain. On a credit leaf every transition that would advance
`seq` needs the recipient's exit key, so the operator had no way to void
the voucher. Each failed receive was a free option against the operator's
leaf (`design/audit/channels.md`, B2). The fix was to settle first, which
moved the risk to the recipient.

**An expiring voucher.** The natural repair is a voucher that dies at a
deadline. Bitcoin cannot make a transaction invalid after a height: a
script can demand `nLockTime` at least some value, never at most, because
a transaction with a low lock time stays valid forever and must survive a
reorganisation. What can be built is the timeout branch of an HTLC, a
path that lets the operator void the voucher after a deadline, racing a
redemption that must land first. The covenant can only check a deadline
it can see, and vouchers are off-chain, so the deadline has to live in
the source leaf. With one cumulative voucher per credit leaf, a void at
the deadline voids the settled balance along with the payment in flight,
and the recipient's exposure grows from one payment to its whole credit.
That is where `design/receive.md` left it.

The observation that unlocks it is to keep the payments in flight apart
from the settled balance, so that the deadline applies only to value that
is genuinely conditional.

## Is this eltoo?

The cumulative voucher is already the eltoo pattern in one direction:
signed states with a sequence, highest wins. It needs no contest window
because only the recipient can redeem and the recipient never prefers an
older, smaller state. The operator signing an off-chain spend of a leaf
to the recipient *is* a voucher; there is nothing more native to reach
for.

What a voucher cannot express is a conditional payment, and that is not
a sequencing problem. While a payment is in flight the recipient holds
"this amount is yours if you show the preimage". If the payment fails,
the operator needs "it is mine again". In any two-party state machine,
eltoo included, the operator gets the second only with the recipient's
signature, and the recipient will not sign away a payment it might still
claim. A channel solves this the way every channel does: the conditional
payment is an HTLC output whose timeout branch reverts it unilaterally
after `cltv_expiry`. A channel leaf (Appendix C) is that construction
inside a tree, with a contest window because value flows both ways.

So the construction below is an HTLC that lives in the tree as a leaf.
Its success branch is a hash-locked voucher the recipient can redeem; its
timeout branch is an operator-only reclaim after a deadline written in
the leaf. It is one-way, so it needs no contest window and no channel
state. It needs a deadline because a conditional payment always does.


## The construction

Each recipient holds a **receive pair**, two sibling positions:

| Slot | Leaf | `owner_key` | `exit_key` | `evictor_key`, `evict_after` | Role |
|---|---|---|---|---|---|
| left | `P`, the pending leaf | operator | recipient | operator, deadline `T` | payments in flight, one window |
| right | `L`, the landing leaf | recipient | recipient | operator, a lease well past `T` | settled balance; the recipient's own leaf |

`P` carries the protection of 10.3's credit leaf, so the tree carries the
credit-leaf configuration: `CLAIM^x`, `UPDATE^x`, `EXIT^=`, `REWRITE_h^x`,
and no plain `CLAIM`, `CLAIM^h`, `SPLIT` or `REWRITE_h`. Under it the
operator, as `P`'s owner, can change `P` alone only by an amount-only
increase, and `EXIT^=` and eviction pay `P` to the recipient. `P` differs
from a credit leaf in one way: it is marked **reclaimable**, so that after
its deadline the operator can take it back without paying the exit key.

`L` is the recipient's own leaf, owned and exited by the recipient. That
is deliberate. Every voucher below binds `L`'s body, so whoever can remove
`L` can void them, and the recipient is the only party that can exit a
leaf it owns. The operator can still evict `L` after its lease, which
would void the vouchers the same way, so `L`'s lease must run well past
every deadline the recipient relies on (*One receive*, step 3). An
operator-owned `L`, the credit leaf of 10.3, would not do: the operator
could exit it with its own signature, pay the recipient what `L` already
held, and reclaim the payment in flight at the deadline.

A recipient that wants payments in flight across a deadline holds two
pairs with staggered deadlines. Each pair has its own `L`, so the two
voucher chains never target the same leaf (see *Concurrency*). A
recipient with one pair settles first, as in `design/receive.md`, for an
invoice that arrives too close to its deadline, and while the pair is
being rolled.

### R1. Reclaimable leaves

A leaf is reclaimable when the top bit of its `nonce` is set. After
`evict_after`, if its `evictor_key` is `OPERATOR_KEY` and its `seq` is not
`SEQ_FINAL`, the operator alone MAY remove it with no payout (the value
becomes the free decrease of 7.9 rule 6) or replace it with a new leaf.
The single form is an `EXIT` variant whose evict branch omits rule 4's
payout for a reclaimable leaf. The batch form is a `REWRITE_h` in which an
expired reclaimable position needs `sig_op` and nothing else and pays
nothing when emptied. Before the deadline a reclaimable leaf behaves as
any other leaf. An ordinary eviction still pays the exit key; the
operator simply has no reason to use it. The `SEQ_FINAL` exclusion keeps
R1 away from channel leaves, as 7.9 rule 3's exemption is kept away from
them.

The flag is in the leaf, not the position, so the party it can harm
checks it before accepting the leaf. The recipient checks that `L` is
unflagged and `P` is flagged; a joiner checks its own leaf (9.2); a
voucher recipient adds "the claim leaf is unflagged" to 9.6's list; a
channel-leaf counterparty adds it to C.9.7's. Nobody can set the flag on a
leaf they do not sign for, since `nonce` changes only by a transition the
leaf's owner signs, and every carve writes the claim leaf its issuer
signed.

### R2. Merge claim into the sibling (`CLAIM^m`, `CLAIM^hm`)

A carve whose second step raises the source's sibling instead of filling
an empty position, to a stated level. The voucher message is

```
H_voucher_m( tree_id || body(source) || body(target) || X )
```

with a payment hash appended in the hash-locked form, as 7.5.1 does. The
script requires that the target

* is the leaf at the source's sibling position,
* is owned by the source's exit key (`target.owner_key = source.exit_key`)
  and has the same exit key,
* is unflagged, not at `SEQ_FINAL`, and holds less than `X`.

It raises the target to exactly `X`, lowers the source by the same `d = X
− target.amount`, leaves the source's residual at zero or at least
`DUST_MIN` (7.5 rule 6), and does not advance the source's `seq`. No
consent is needed from anyone but the voucher's signer.

Each condition closes a specific path for the operator, and the target
form makes replay harmless.

* **Only into the recipient's own leaf.** Without the owner condition the
  operator could graft a leaf of its own with the recipient's exit key,
  merge `P` into it and hold the value hostage, since every path out of
  that leaf would need both keys. With it, any leaf the operator could
  merge into is one the recipient can exit alone.
* **Only into the sibling.** Without the position condition the operator
  could still graft a recipient-owned leaf elsewhere and merge into it
  just enough of `P` that the recipient's voucher underflows, then reclaim
  the rest: the recipient would have been paid the part the operator
  chose to move and not the payment in flight. The sibling is `L`, which
  only the recipient can remove before its lease.
* **Never voids anything.** The source's body does not change, so every
  outstanding voucher against it stays valid, and an operator that merges
  a voucher it signed itself has only paid the recipient.
* **Replay is harmless.** Once the target holds `X` the voucher moves
  nothing (`d` must be positive). An older, smaller voucher is a no-op
  after a larger one, and redeeming the larger after the smaller moves
  only the difference.
* **No empty position, and one path.** A partial carve needs an empty
  position, whose supply the operator controls (9.6, 10.1). A merge
  lands on the sibling, and the two steps share every level above the
  pair: about 1,130 vbytes for a redemption at `D = 16`, the sibling-pair
  estimate of `design/receive.md`, against about 1,680 for a two-path
  `CLAIM^x`.

The target binds `L`'s body, so a change to `L` other than its amount
voids the vouchers against it. The recipient's own carve or exit of `L`
does that; a recipient relying on outstanding pending vouchers should
leave `L` alone until they settle, or ask for them to be reissued. An
amount-only top-up of `L` changes nothing and moves `L` toward every
target. The converse needs a rule, as 9.6 has for vouchers: a decrease of
`L` that leaves its body unchanged would let a merge voucher whose target
was already reached move value again, so the operator MUST advance `L`'s
`seq` in any decrease it co-signs. Every such decrease needs the
recipient's signature as `L`'s owner, so skipping the advance takes both
parties, and only the operator loses by it.

R2 is useful without R1. A settle-first credit leaf whose sibling is a
recipient-owned leaf can take its vouchers as merges: no empty position,
the cheaper sibling-pair redemption, and vouchers a tower can redeem
with no key of the recipient's.

### R3. Batched transfer (optional)

A `REWRITE_h` in which a reclaimable position's amount falls and its
sibling, owned by the reclaimable leaf's exit key, rises by the same
amount, both amount-only, needs `sig_op` and nothing else. It is R2's
second step without a voucher, and it moves value only toward the
recipient for the same reasons. Without R3 every window's settlement is a
merge claim, about 1,130 vbytes; with it a cohort of recipients settles
in one rewrite at a few hundred vbytes each.

R1 to R3 are script variants in FULL, MID and CCV (MIN has no
`OP_CHECKSIGFROMSTACK` and no `CLAIM`), tree-creation parameters visible
in `m`, and none needs an opcode outside its tier's set.

## The flows

Write `R` for the recipient, `O` for the operator, `(P, L)` for a pair,
`L₀` for `L`'s amount at the start of the window and `S` for what `R` has
settled into this pair in the window so far. The instruments are:

* `V_k`, a **hash-locked merge voucher** against `P` with target `X_k =
  L₀ + S + a_k` under `H_k`, signed by `O` as `P`'s owner, where `a_k` is
  the payment in flight.
* `U`, an **unlocked merge voucher** against `P` with target `L₀ + S`,
  which `O` may sign for itself at any time. It is what `O` redeems to
  settle a window without R3.

### One receive

1. `R` draws a preimage, puts `H_k` in an invoice, and the payer's HTLC
   reaches `O`, the last hop, with expiry `E`.
2. `O` checks that `P`'s deadline `T` satisfies the timing rule below and
   that `P` holds at least `S + a_k`, with any residual zero or at least
   `DUST_MIN`, topping `P` up by an amount-only increase if not (operator
   alone, 7.9 rule 3; neither `P`'s vouchers nor `R`'s targets bind its
   amount).
3. `O` signs `V_k` and sends it. `R` checks it against the confirmed
   tree: `P` is reclaimable and is `L`'s sibling, `L` is `R`'s own and
   unflagged, `X_k` is `L₀ + S + a_k`, `T` leaves the redemption time
   *Timing* asks for, and `L`'s lease runs past `T + Delta(q)`.
4. `R` releases the preimage and hands `V_k` and the preimage to its
   tower.
5. `O` settles the inbound HTLC. Nothing reaches the chain.

From step 3, `R` can redeem `V_k` on-chain with the preimage it drew and
raise `L` to `X_k`, and the operator cannot stop it before `T`. Carving
`P` by voucher needs `R`'s exit key (`CLAIM^x`), as do `UPDATE^x` and
`REWRITE_h^x`; `EXIT^=` and eviction pay `P` to `R`; a merge can only
raise `L`; a top-up only makes room; and `L` can be removed before its
lease only by `R`. Before step 4 the operator has signed nothing it can
lose: `V_k` needs a preimage only `R` has, and publishing it on-chain
hands it to `O`.

### Window close

Before `T − G_claim`, `O` raises `L` to `L₀ + S`, either by redeeming `U`
or, under R3, in one rewrite across every recipient settling that window.
`R`'s vouchers stay valid but now move only what is still in flight above
the new level. After `T`, `O` reclaims `P` under R1, replacing it with
the pending leaf for a later window in the same rewrite, and takes back
the unspent funding. `O` MUST keep any HTLC whose voucher is outstanding
open until its reclaim of `P` has confirmed, and only then fail it
upstream: until then `R` can still redeem the voucher and publish the
preimage, and an HTLC already failed back would leave `O` paying for a
payment it never received. This is 9.6.2 rule 3's ordering.

`R` or its tower checks one thing per window: that `L` holds at least
`L₀ + S`, confirmed, by `T − G_claim`. If not, it redeems the latest
`V_k` with the preimage, raising `L` to `X_k`. That is the whole of the
recipient's liveness requirement, and the tower needs nothing from `R`
to meet it.

### When something goes wrong

| Case | What happens | Who loses |
|---|---|---|
| `R` withholds the preimage and does nothing | `O` reclaims `P` after `T`, and once the reclaim confirms, fails the HTLC before `E` | nobody; the payer is refunded |
| `R` withholds, then redeems `V_k` late | the redemption publishes the preimage; `O` still holds the HTLC and settles it, which *Timing* guarantees happens before `E` | nobody |
| `O` settles and never raises `L` | the tower redeems `V_k` before `T` | nobody; the tower pays the redemption fee |
| `O` vanishes | as above; `R` then exits `L` itself, since it owns it | nobody |
| `O` tries to void `V_k` before `T` | every change to `P` but a merge, a top-up or a payout to `R` needs `R`'s exit key, and only `R` can remove `L` before its lease | no path exists |
| `O` evicts `L` after its lease | `L` is paid to `R` in full, and `V_k` is void | `R`, if it accepted a voucher whose `T + Delta(q)` passed `L`'s lease; step 3 forbids it |
| `O` grafts another leaf and merges into it | R2 merges only into the sibling, owned by `R` | no path exists |
| `O` redeems an older, smaller voucher | `L` rises to the older target; `V_k` still raises it the rest of the way | nobody |
| `R` redeems `V_k` after `L` reached `X_k` | the merge would move nothing and fails | no path exists |
| `R` releases two preimages on one pair before a combined voucher | each voucher covers the settled total plus its own payment, so redeeming one leaves the other short | `R`; see *Concurrency* |

### Concurrency

Targets are absolute levels of one leaf, so the voucher chain of a pair
is sequential. A recipient releases one preimage at a time per pair: a
second payment may arrive while the first is in flight, with a voucher
targeting `L₀ + S + a_{k+1}` that excludes the unsettled `a_k`, since
including it would hand `R` that payment without its preimage. Once `R`
reveals either, `O` reissues the other on top of the new settled total,
and `R` reveals it only then. The cost is a round trip per payment, not
a transaction. A recipient that needs real parallelism, or coverage
across its deadline, holds more pairs; each pair's chain is independent
because each targets its own `L`.

## Timing

Write `t` for the height at which the HTLC arrives, `E` for its expiry,
`T` for the pending leaf's deadline, and `G_claim` and `G_reclaim` for
the time to confirm a redemption or a reclaim under the contention bound
`Delta(q)` of 10.5. Two constraints hold.

The recipient must be able to redeem before the reclaim becomes valid, so
a voucher is acceptable only when

```
T − t  ≥  G_claim + ε
```

The operator must be able to settle the HTLC from a preimage published by
a late redemption, which can confirm as late as the reclaim does, so

```
E  ≥  T + G_reclaim + G_settle
```

With windows of length `W`, a payment lands on a pair whose deadline is
between `G_claim` and `G_claim + W` away, so the invoice's final-hop
expiry delta must be at least

```
min_final_cltv_expiry_delta  ≥  W + G_claim + G_reclaim + G_settle
```

At low contention, with the three confirmation terms at 6 blocks each and
a one-day window, that is about 162 blocks. At C.4.4's conservative
`G_exit = 72` for both claim and reclaim it is about 300 blocks, two
days. BOLT 11's default final delta is 18 blocks, so the invoice must ask
for more; routing nodes commonly cap an HTLC's total expiry at 2,016
blocks, which leaves room. The long expiry costs the payer only when
something fails: in the normal flow the HTLC settles in seconds, as soon
as the recipient releases the preimage.

The contention bound cuts both ways. A recipient that loses the race to
`T` loses the payment, and a recipient that can delay the operator's
reclaim past `T + G_reclaim` by outbidding it can redeem after the HTLC
has expired. Both are the `beta` of 10.5's assumption [C], which every
deadline in the design rests on, the channel leaf's included; `G_reclaim`
must count the conflicting spends the operator is prepared to outbid.

## Cost

Per payment the on-chain cost is zero, as in the settle-first design. The
cost moves to the window: for each pair that settled anything, one
transfer and one roll of its pending leaf.

| Per active pair per window | Without R3 | With R3 (estimate) |
|---|---|---|
| Raise `L` by the settled total | one merge claim, about 1,130 vB | two amount-only positions, about 245 vB |
| Reclaim the expired pending leaf and write the next | one rewrite position, about 130 vB | the same, about 130 vB |
| Total | about 1,260 vB | about 375 vB |

The R3 figures are estimates. Spec 11 measures `REWRITE_h` at 148 vbytes
per changed leaf with its signature at `h = 6`, and `design/receive.md`
prices an amount-only position at about 122 vbytes without one; neither
is a measurement of R3's step. A pair with nothing settled in a window
needs no transfer, and the cost is per window, not per payment, so a
merchant receiving many payments a day pays what a wallet receiving one
does.

| | Settle-first credit leaf | Pending pairs | Channel leaf (Appendix C) |
|---|---|---|---|
| Atomic | no: one payment exposed between settling and vouching | yes | yes |
| On-chain bytes per payment | 0 | 0 | 0 |
| On-chain bytes per window | 0 | about 375 vB with R3, 1,260 without | 0 |
| Recipient liveness | none | a check per window, delegable to a tower that holds no key | a tower for stale states, always |
| Final-hop expiry | any | at least `W` plus three confirmation times | at least C.4.4's budget, about 220 blocks |
| Operator capital | what it has vouched for | the window's expected receipts, reclaimed at the deadline | the channel's inbound capacity |
| Unilateral settlement | `CLAIM^x`, about 1,680 vB | merge claim, about 1,130 vB | `EXIT` plus the update chain, about 1,680 vB over about 146 blocks |
| Rule changes | none | R1 and R2; R3 optional | none |
| Spends | no; receive only | no; receive only | yes |

At 10 sat/vB a window costs a pair about 3,750 sat with R3. Against an
exposure of one payment, that is worth paying for large receives and for
recipients with many receives per window, and not for a wallet taking
small payments now and then, which is better served by settling first.
The two compose: a tree carrying R1 and R2 can run both, and the
recipient chooses per invoice.

## What it does not fix

* **Spending.** A pending pair receives. Paying out still goes through a
  channel leaf or a voucher the operator issues, as in
  `design/receive.md`.
* **Contention.** See *Timing*: the deadlines hold only under [C].
* **The first invoice.** A recipient needs its pair in the tree before an
  atomic receive. Its first payment can settle first while the pair is
  written.
* **Operator capital.** The operator funds each pending leaf with the
  window's expected receipts, locked until the deadline. Unlike surplus
  in a credit leaf (`design/audit/channels.md`, B3) it comes back, which
  is the point of R1.

## Formal and test obligations

The Lean model takes authorisation as an opaque proposition, so R2
changes only what `Claim` writes: a merge is a step whose second node is
an amount-only increase of the source's sibling, and its soundness is
`claim_sound` with that step replaced. Its distinctive property needs a
statement of its own: no sequence of merges moves more into the target
than the largest target signed, which is what makes replay harmless. R1
needs a statement that a reclaim removes only a flagged, non-final leaf
past its deadline and leaves every other position alone, and a trace
invariant that no unflagged leaf's value reaches the operator without
its exit key. R3 is `rewrite_sound` with a different authorisation
predicate. The test obligations follow the cases table: a negative for
every row whose outcome is "no path exists", the smaller-voucher row as a
positive, and the timing rule, including the reclaim-before-fail order,
exercised block by block on `tools/test_chan.py`'s chain model, as
9.6.2's deadlines are.

## Review

An adversarial review of the first version found three ways for the
operator to defeat it, each now closed above. The target was an
operator-owned credit leaf, which the operator could exit alone, voiding
every voucher before reclaiming the payment in flight; `L` is now the
recipient's. A merge could target any leaf with the recipient's exit
key, so the operator could graft one and drain `P` into it; the target
is now the recipient-owned sibling. And two pending leaves targeting one
credit leaf paid the larger of two payments, not their sum; each pending
leaf now has its own landing leaf. The same pass found the
reclaim-before-fail ordering of *Window close* and the two-sided
contention note of *Timing*.

## Recommendation

Build R2 first. It is small, a different second step and a target
compare, and it improves the settle-first design on its own: no empty
position, a cheaper sibling-pair redemption, and vouchers a tower can
redeem without the recipient's key. Then decide R1 against the cost
table. It is the one change that gives the operator a new power, a
reclaim, and it is what turns a voucher into an HTLC. R3 is an
optimisation, worth its script once a deployment settles more than a few
pairs a window.
