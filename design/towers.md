# Towers

*An informative note on the agents that act for an offline member: what
they hold, what each job needs from the scripts, what a tower can and
cannot do with what it holds, and which of the jobs exist in the spec
today. Section numbers refer to `spec/layertree.md`; `C.` numbers to
`spec/channel-leaves.md`.*

## What a tower is here

A tower is a party that holds enough of a member's data to act for it
while the member is offline, and nothing that lets it act against it. In
Lightning a watchtower holds data to punish or override a stale channel
state. A LayerTree member has more to delegate: starting an exit, keeping
a path current, redeeming a voucher before a deadline, and the channel
duties when the leaf hosts a channel.

The design rule that makes this safe is the same in every case. Every
instrument a tower holds pays a fixed output that belongs to the member:
an exit pays `P2TR(exit_key)` in full (7.2 rules 2 and 6), a voucher pays
its claim leaf or, under the merge claim of `design/pending-receive.md`,
the member's own leaf, and a channel state pays the balances both parties
signed. A tower can choose *when* such an instrument is used, and at what
fee. It cannot choose *where* the money goes. That is the property to
check before adding a new delegable instrument, and it is why the spec
calls the delegable ones bearer rights rather than secrets.

## The jobs

| Job | What the tower holds | Specified | Deadline it serves |
|---|---|---|---|
| Keep the member's path current | the leaf, its path, the chain | yes (9.7) | none; it is what every other job builds on |
| Start a unilateral exit | an `EXIT_K^t` authorisation (7.2 rule 7) and a funded UTXO | yes, in trees created with `EXIT_K^t` | the member's own, or a lease |
| Answer a stale channel state | `update_n`, `settle_n`, signatures, a fee source (C.9.3) | yes | `csv_delay` |
| Redeem a plain voucher | the voucher and the source's path | yes: `CLAIM` and `CLAIM^h` need no signature beyond the voucher's | the source's lease (9.6) |
| Redeem a credit-leaf voucher | today, nothing it can use alone | no: `CLAIM^x` needs a signature over the transaction by the recipient's key | none on a credit leaf |
| Redeem a pending-leaf voucher | the merge voucher and the preimage | proposed (`design/pending-receive.md`, R2) | the pending leaf's deadline |
| Bump fees and outbid conflicts | a funded UTXO and a fee policy | yes (10.5, C.9.6) | the contention bound `Delta(q)` |

### Keeping the path current

Every transition publishes the paths it uses, and a member's path for the
next root differs from the last in at most one sibling, derivable from
the witness (9.7; the Lean theorem `path_maintenance`). A tower follows
the chain of spends of the tree output and updates the path. It has one
complication a channel watchtower does not: the tree output's
scriptPubKey changes with every transition, since it commits to the new
root, so a light tower cannot match a fixed scriptPubKey with BIP-158
filters. It follows the outpoint chain instead, which needs every spend
of the tree output, or asks the operator for the current path and checks
it against the confirmed root.

The tower also tracks the leaf's bytes, not only its path. An amount-only
top-up under 7.9 rule 3 changes the leaf without the owner (9.7), and
every instrument below that pays the leaf's amount pays the new one.

### Starting an exit

In a tree created with `EXIT_K^t`, the owner signs once, off-chain, over
`H_exit(tree_id || body(leaf))`, the leaf without its amount (7.2 rule
7). The tower builds the exact-payout exit from its own fee input
whenever it needs to, rebuilds it against the new root if a competing
spend confirms first, and needs nothing more from the owner. The
authorisation survives top-ups and is voided by any other change to the
leaf, which the owner signs and so can replace.

The authorisation is a bearer exit right, so the owner gives it to one
tower and never to a counterparty that a lease is meant to hold off
(C.6.4). Its misuse is bounded: a forced exit of the owner's own funds,
paid in full, at a time and fee the holder chooses. That ends a lease or
a channel the owner wanted to keep, which is a real harm but not a theft.
An owner who stays in the tree after an exit built on an authorisation
was outbid MUST change the leaf to void it (7.2 rule 7), and nobody may
graft back a leaf with an `(owner_key, nonce, seq)` the lineage has
held, since that would revive an old authorisation (9.2).

### Channel duties

A channel-leaf tower is a LN-Symmetry watchtower (C.9.3). It holds the
latest `update_n` and `settle_n` with their signatures and a funded UTXO
for the anchor children, matches the funding output's scriptPubKey, which
does not change, and publishes the latest state over any stale one. It
keeps only the latest state, one constant-size message per update, and
it cannot steal, since the transactions pay the same outputs whoever
broadcasts them. With an `EXIT_K^t` authorisation the same tower can
start the close, not only finish it: it publishes the leaf's exit, then
the update and settlement on the funding output the exit creates. Its
deadlines are C.4.4's, with the exit's contention included.

### Redeeming vouchers

A plain voucher is already delegable. `CLAIM` and `CLAIM^h` check the
issuer's signature and, for the hash-locked form, a preimage, and nothing
signed by the redeemer, so anyone holding the voucher can redeem it, and
the claim leaf the voucher names is the one written. The tower picks the
empty position and pays the fee.

A credit-leaf voucher is not. `CLAIM^x` adds a signature over the
transaction by the source's exit key, the recipient's, which is what
stops the operator redeeming vouchers against the leaf for itself
(7.5.3). A tower would need a fresh signature from the recipient for
every transaction it builds, so the recipient must be online. This rarely
matters for a settle-first credit leaf, whose vouchers have no deadline,
but it would for any voucher that has one.

The merge claim of `design/pending-receive.md` (R2) removes the need.
Its voucher raises the source's sibling, a leaf the recipient owns, to a
target, so it can move value only into a leaf the recipient alone can
exit, needs no consent from anyone, and a tower can redeem it. That is
the delegation the pending-leaf receive depends on: before each window's
deadline the tower checks that the operator has raised the recipient's
landing leaf by the settled total, and if not, redeems the latest
hash-locked merge voucher with the preimage the recipient handed it. The tower holds no key of the
recipient's.

An earlier version of the pending-leaf design made consent delegable
instead, with the recipient signing each voucher's message with its exit
key under a tag of its own, checked by `OP_CHECKSIGFROMSTACK` as
`EXIT_K^t` checks its authorisation. That works for a tower, but a carve
that advances the source's `seq` lets the operator redeem an older,
smaller voucher and void the newer one, so it needs the merge's target
semantics anyway. The target form is simpler and covers both. The
review of that design (`design/pending-receive.md`, *Review*) also
showed why the target must be the recipient's own sibling and not any
leaf with its exit key: a target the operator can exit, or graft, is a
target it can use to void or drain the voucher.

### Fees and contention

Exact-payout exits (7.2 rule 6, required for `EXIT_K^t`) and every carve
pay fees exogenously, so a tower needs its own funded UTXO, and channel
transactions need anchor children (C.5.5, C.9.6). Its real adversary is
contention: every transition spends the same tree output, so the tower's
transaction can be displaced by any conflicting spend that confirms first
and must be rebuilt against the new root. Under the contention assumption
[C] of 10.5 that takes at most `Delta(q)` blocks, provided the tower is
prepared to outbid the conflicting spends `beta` counts. Every deadline
above is set against that bound, and a tower's fee policy is what makes
the bound hold in practice.

## What a tower learns

A tower learns the member's leaf, so its balance, keys and lease, its
position, and for a channel leaf the channel's balances and HTLCs. A
member who uses several towers for redundancy multiplies that, and a
bearer authorisation held by several towers multiplies the griefing
surface. Splitting jobs across towers helps only where the jobs need
different data: a voucher-redemption tower needs the voucher and the
paths, not the exit authorisation.

## What is specified and what is not

Path maintenance (9.7), `EXIT_K^t` (7.2 rule 7) with its tower rules
(9.3, C.9.3), the channel-leaf watchtower (C.9.3) and plain voucher
redemption are specified, built in FULL, MID and CCV, and tested:
`tools/test_scripts.py` exits a leaf on an off-chain authorisation and
rebuilds it after a competing spend, and `tools/test_chan.py` runs the
channel deadlines block by block. The merge claim that would make
credit-leaf and pending-leaf vouchers delegable is a proposal
(`design/pending-receive.md`). Not designed at all: a tower protocol
(registration, payment, the message that hands over an authorisation or
a voucher), and an incentive for towers beyond being paid by the member.
The P model of `design/p-model.md` includes a watchtower machine with a
configurable lag, which is the place to check the deadlines against
adversarial timing once it exists.
