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

Each recipient has an aligned group of four positions:

| Slot | Leaf | `owner_key` | `exit_key` | `evictor_key`, `evict_after` | Role |
|---|---|---|---|---|---|
| 0 | `C`, the credit leaf | operator | recipient | operator, a long lease | settled balance; the credit leaf of 10.3 |
| 1 | `P_a`, a pending leaf | operator | recipient | operator, deadline `T_a` | payments in flight, one window |
| 2 | `P_b`, a pending leaf | operator | recipient | operator, deadline `T_b` | the next window, staggered |
| 3 | empty | | | | spare |

`C` is the credit leaf exactly as 10.3 defines it, and the tree carries
the credit-leaf configuration: `CLAIM^x`, `UPDATE^x`, `EXIT^=`,
`REWRITE_h^x`, and no plain `CLAIM`, `CLAIM^h`, `SPLIT` or `REWRITE_h`. A
pending leaf is a credit leaf with one difference: it is marked
**reclaimable**, so that after its deadline the operator can take it back
without paying the exit key. Everything that protects `C` protects a
pending leaf until then.

Two pending leaves are alive at once because a payment arriving close to
one deadline needs the next (see *Timing*). Each lives for about two
window lengths and is replaced as it expires.

### R1. Reclaimable leaves

A leaf is reclaimable when the top bit of its `nonce` is set. After
`evict_after`, if its `evictor_key` is `OPERATOR_KEY`, the operator alone
MAY remove it with no payout (the value becomes the free decrease of 7.9
rule 6) or replace it with a new leaf. The single form is an `EXIT`
variant whose evict branch omits rule 4's payout for a reclaimable leaf.
The batch form is a `REWRITE_h` in which an expired reclaimable position
needs `sig_op` and nothing else and pays nothing when emptied. Before the
deadline a reclaimable leaf behaves as any other leaf, so the `^x`
variants still require the recipient's exit key for every change but an
amount-only increase. An ordinary eviction still pays the exit key; the
operator simply has no reason to use it.

The flag is in the leaf, not the position, so the party it can harm
checks it before accepting the leaf: a recipient checks that `C` is
unflagged, and a joiner checks its own leaf (9.2). Nobody can set it on a
leaf they do not sign for, since `nonce` changes only by a transition the
leaf's owner signs. A position-based flag, a designated subtree compiled
into the script, would also work for slightly less script, but the leaf
flag lets pending leaves sit beside the credit leaves they feed.

### R2. Merge claim to a target (`CLAIM^m`, `CLAIM^hm`)

A carve whose second step raises an existing leaf instead of filling an
empty position, to a stated level. The voucher message is

```
H_voucher_m( tree_id || body(source) || body(target) || X )
```

with a payment hash appended in the hash-locked form, as 7.5.1 does. The
script requires the target to have the source's `exit_key`, to be
unflagged and not at `SEQ_FINAL`, and to hold less than `X`. It raises the
target to exactly `X` and lowers the source by the same `d = X −
target.amount`, leaving the source's residual at zero or at least
`DUST_MIN` (7.5 rule 6). It does not advance the source's `seq`.

Three properties follow, and they are the reason for the target form.

* **A merge never voids anything.** The source's body does not change, so
  every outstanding voucher against it stays valid. A merge can only move
  value from the recipient's pending leaf to the recipient's credit leaf,
  so no consent is needed: an operator that merges a voucher it signed
  itself has paid the recipient, and a merge is bearer-redeemable by a
  tower holding the voucher and, for the hash-locked form, the preimage.
* **Replay is harmless.** Once the target holds `X`, the voucher moves
  nothing (`d` must be positive). A smaller, older voucher is a no-op
  after a larger one, and redeeming the larger after the smaller moves
  only the difference. Two vouchers never pay the same value twice.
* **No empty position is needed.** A partial carve needs one, and the
  operator controls their supply (9.6, 10.1): an operator that filled the
  recipient's group before the deadline would leave a hash-locked voucher
  nowhere to land and then reclaim. A merge lands on `C`. Because `C` and
  the pending leaves share a group, the two steps share every level above
  it: about 1,130 vbytes for a redemption at `D = 16`, the sibling-pair
  estimate of `design/receive.md`, against about 1,680 for a two-path
  `CLAIM^x`.

The target binds `C`'s body, so a change to `C` other than its amount
voids the merge vouchers against it. The recipient's own withdrawal from
`C` by `CLAIM^x` advances `C`'s `seq` and does exactly that; a recipient
relying on outstanding pending vouchers should withdraw after they settle,
or ask for them to be reissued. An amount-only top-up of `C` changes
nothing, and moves `C` toward every target. The converse needs a rule, as
9.6 has for vouchers: a *decrease* of `C` that leaves its body unchanged
would let a merge voucher whose target was already reached move value
again, so the operator MUST advance `C`'s `seq` in any decrease it
co-signs (an `UPDATE^x` or `REWRITE_h^x` paying out of `C`). Both also
need the recipient's key, so skipping the advance takes the operator's
signature, and only the operator loses by it.

R2 is useful without R1. A settle-first credit leaf can merge into a leaf
the recipient owns instead of carving a new one, which removes its
empty-position dependence and makes its vouchers tower-redeemable.

### R3. Batched transfer (optional)

A `REWRITE_h` in which a reclaimable position's amount falls and an
unflagged position in the same group with the same `exit_key` rises by
the same amount, both amount-only, needs `sig_op` and nothing else. Like a
merge it can only move value toward the recipient, so it needs no
consent. Without R3 every window's settlement is a merge claim, about
1,130 vbytes; with it a cohort of recipients settles in one rewrite at a
few hundred vbytes each.

R1 to R3 are script variants in FULL, MID and CCV (MIN has no
`OP_CHECKSIGFROMSTACK` and no `CLAIM`), tree-creation parameters visible
in `m`, and none needs an opcode outside its tier's set.

## The flows

Write `R` for the recipient, `O` for the operator, `P` for the current
pending leaf, `C₀` for `C`'s amount at the start of the window and `S` for
what `R` has settled in the window so far. The instruments are:

* `V_k`, a **hash-locked merge voucher** against `P` with target `X_k =
  C₀ + S + a_k` under `H_k`, signed by `O` as `P`'s owner, where `a_k` is
  the payment in flight.
* `U`, an **unlocked merge voucher** against `P` with target `C₀ + S`,
  which `O` may sign for itself at any time. It is what `O` redeems to
  settle a window without R3.

### One receive

1. `R` draws a preimage, puts `H_k` in an invoice, and the payer's HTLC
   reaches `O`, the last hop, with expiry `E`.
2. `O` checks that `P`'s deadline `T` satisfies the timing rule below and
   that `P` holds at least `S + a_k` plus `DUST_MIN` of headroom, topping
   it up by an amount-only increase if not (operator alone, 7.9 rule 3;
   neither `P`'s vouchers nor `R`'s targets bind its amount).
3. `O` signs `V_k` and sends it. `R` checks it against the confirmed
   tree: `P` is reclaimable and in `R`'s group, `C` is unflagged and is the
   target, `X_k` is `C₀ + S + a_k`, and `T` leaves the redemption time
   *Timing* asks for.
4. `R` releases the preimage and hands `V_k` and the preimage to its
   tower.
5. `O` settles the inbound HTLC. Nothing reaches the chain.

From step 3, `R` can redeem `V_k` on-chain with the preimage it drew and
raise `C` to `X_k`. The operator cannot stop it before `T`: carving `P`
any other way needs `R`'s exit key (`CLAIM^x`), as do `UPDATE^x` and
`REWRITE_h^x`; `EXIT^=` and eviction pay `P` to `R`; a merge only raises
`C`; and a top-up only makes room. Before step 4 the operator has signed
nothing it can lose: `V_k` needs a preimage only `R` has, and publishing
it on-chain hands it to `O`.

### Window close

Before `T − G_claim`, `O` raises `C` to `C₀ + S`, either by redeeming `U`
or, under R3, in one rewrite across every recipient settling that window.
`R`'s vouchers stay valid but now move only what is still in flight above
the new level. After `T`, `O` reclaims `P` under R1, replacing it with the
pending leaf for a later window in the same rewrite, and takes back the
unspent funding.

`R` or its tower checks one thing per window: that `C` holds at least
`C₀ + S`, confirmed, by `T − G_claim`. If not, it redeems the latest
`V_k` with the preimage, raising `C` to `X_k`. That is the whole of the
recipient's liveness requirement, and the tower needs nothing from `R` to
meet it.

### When something goes wrong

| Case | What happens | Who loses |
|---|---|---|
| `R` withholds the preimage and does nothing | `O` fails the HTLC before `E`; at `T` it reclaims `P` | nobody; the payer is refunded |
| `R` withholds, then redeems `V_k` late | the redemption publishes the preimage; `O` settles the HTLC from it, which *Timing* guarantees happens before `E` | nobody |
| `O` settles and never raises `C` | the tower redeems `V_k` before `T` | `O` pays nothing more; `R`'s tower pays the redemption fee |
| `O` vanishes | as above; `R` then exits `C` itself, or a tower does with an `EXIT^t` authorisation for `C` (7.2 rule 7), which survives top-ups | nobody |
| `O` tries to void `V_k` before `T` | every change to `P` but a merge, a top-up or a payout to `R` needs `R`'s exit key | no path exists |
| `O` redeems an old, smaller voucher | `C` rises to the older target; `V_k` still raises it the rest of the way | nobody |
| `O` fills the group's empty slot | a merge needs no slot | nothing |
| `R` redeems `V_k` after `C` reached `X_k` | the merge would move nothing and fails | no path exists |
| `R` releases two preimages before a combined voucher | each voucher covers the settled total plus its own payment, so redeeming one leaves the other's amount short | `R`; see *Concurrency* |

### Concurrency

A recipient releases one preimage at a time per pending leaf. A second
payment may arrive while the first is in flight; its voucher targets
`C₀ + S + a_{k+1}`, excluding the unsettled `a_k`, since including it
would hand `R` that payment without its preimage. Once `R` reveals either,
`O` reissues the other on top of the new settled total, and `R` reveals
it only then. The cost is a round trip per payment, not a transaction. A
recipient that needs real parallelism holds more pending leaves, each
with its own target chain.

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

With windows of length `W` and two staggered pending leaves, a payment
lands on a leaf whose deadline is between `G_claim` and `G_claim + W`
away, so the invoice's final-hop expiry delta must be at least

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

## Cost

Per payment the on-chain cost is zero, as in the settle-first design. The
cost moves to the window: for each recipient that settled anything, one
transfer and one roll of its pending leaf.

| Per active recipient per window | Without R3 | With R3 (estimate) |
|---|---|---|
| Raise `C` by the settled total | one merge claim, about 1,130 vB | two amount-only positions, about 245 vB |
| Reclaim the expired pending leaf and write the next | one rewrite position, about 130 vB | the same, about 130 vB |
| Total | about 1,260 vB | about 375 vB |

The R3 figures are estimates from the measured `REWRITE_h` positions (122
vbytes per amount-only change and 148 per signed change at `h = 6`, spec
11), not measurements. A recipient with nothing settled in a window needs
no transfer, and the cost is per window, not per payment, so a merchant
receiving many payments a day pays what a wallet receiving one does.

| | Settle-first credit leaf | Pending leaves | Channel leaf (Appendix C) |
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

At 10 sat/vB a window costs a recipient about 3,750 sat with R3. Against
an exposure of one payment, that is worth paying for large receives and
for recipients with many receives per window, and not for a wallet taking
small payments now and then, which is better served by settling first.
The two compose: a tree carrying R1 and R2 can run both, and the
recipient chooses per invoice.

## What it does not fix

* **Spending.** A pending leaf receives. Paying out still goes through a
  channel leaf or a voucher the operator issues, as in
  `design/receive.md`.
* **The deadline's contention assumption.** `G_claim` and `G_reclaim` are
  `Delta(q)` of 10.5, so a recipient whose redemption is outbid past `T`
  loses the race. Every deadline in the design rests on the same bound,
  the channel leaf's included.
* **The first invoice.** A recipient needs its pending leaves in the tree
  before an atomic receive, which is a rewrite position each. Its first
  payment can settle first while they are written.
* **Operator capital.** The operator funds each pending leaf with the
  window's expected receipts, locked until the deadline. Unlike surplus
  in a credit leaf (`design/audit/channels.md`, B3) it comes back, which
  is the point of R1.

## Formal and test obligations

The Lean model takes authorisation as an opaque proposition, so R2
changes only what `Claim` writes: a merge is a step whose second node is
an amount-only increase of a leaf with the source's exit key, and its
soundness is `claim_sound` with that step replaced. Its distinctive
property needs a statement of its own: no sequence of merges moves more
into the target than the largest target signed, which is what makes
replay harmless. R1 needs a statement that a reclaim removes only a
flagged leaf past its deadline and leaves every other position alone, and
a trace invariant that no unflagged leaf's value reaches the operator
without its exit key. R3 is `rewrite_sound` with a different
authorisation predicate. The test obligations follow the cases table: a
negative for every row whose outcome is "no path exists", the
smaller-voucher row as a positive, and the timing rule exercised block by
block on `tools/test_chan.py`'s chain model, as 9.6.2's deadlines are.

## Recommendation

Build R2 first. It is small, a different second step and a target compare,
and it improves the settle-first design on its own: no empty position, a
cheaper sibling-pair redemption, and vouchers a tower can redeem without
the recipient's key. Then decide R1 against the cost table. It is the one
change that gives the operator a new power, a reclaim, and it is what turns
a voucher into an HTLC. R3 is an optimisation, worth its script once a
deployment settles more than a few recipients a window.
