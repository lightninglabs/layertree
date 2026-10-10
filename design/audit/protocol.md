# Protocol audit: ways the scheme as specified can lose, lock or grief

*An adversarial pass over `spec/layertree.md` 0.10.0 and
`spec/channel-leaves.md` 0.3.0 at `main` 2b3d347. The question asked of
every transition was: who can make money leave the wrong way, stay where
it should not, or cost somebody else more than it costs them. Findings
F1 to F21 of `design/review.md` and the items of `paper/reviews/*.md`
are taken as settled and are not repeated unless the stated mitigation
fails. Every claim that the simulator can test was run in it; the probe
script is throwaway and not committed, and each finding says what it
ran and what the simulator answered. Policy claims are checked against
Bitcoin Core `master` as of this audit: `src/policy/policy.cpp`
(`GetDustThreshold`, `IsStandardTx`), `src/policy/policy.h`
(`MAX_DUST_OUTPUTS_PER_TX = 1`, `MAX_STANDARD_TAPSCRIPT_STACK_ITEM_SIZE
= 80`, `DEFAULT_DESCENDANT_LIMIT = 25`, `DEFAULT_CLUSTER_LIMIT = 64`) and
`src/policy/ephemeral_policy.cpp` (`PreCheckEphemeralTx`,
`CheckEphemeralSpends`). Section numbers without a prefix are the
spec's; `C.x` is Appendix C.*

Two policy facts recur below and are stated once. A P2TR output is dust
below 330 sat: `GetDustThreshold` prices a 43-byte output plus a 67-byte
input at the default `DUST_RELAY_TX_FEE` of 3000 sat/kvB, which is 110
bytes and 330 sat. A standard transaction may carry at most one dust
output, and that one only as ephemeral dust: the transaction must pay
zero fee (`PreCheckEphemeralTx`: "tx with dust output must be 0-fee")
and a child in the same package must spend the dust
(`CheckEphemeralSpends`). A transaction that pays any fee and has any
dust output, or that has two dust outputs, is rejected with reason
`dust` by every default node. Consensus does not care; a miner can
include such a transaction directly.

## Ranked findings

### A1. `REWRITE_h`'s amount-only exemption lets the operator change a channel leaf's capacity, which makes the channel's pre-signed update transactions non-standard

**Claim.** 7.9 rule 3 exempts from the owner's signature any position
whose new leaf differs from the old only by a larger `amount`, so the
operator alone can raise a channel leaf's `amount` above the capacity
`C` its signed states commit to, after which every `update_n` pays a
nonzero fee with a zero-value anchor and no default node will relay it.

**Attacker.** The operator, holding `OPERATOR_KEY` and a funding input,
in a tree whose taptree carries `REWRITE_h` or `REWRITE_h^x` and hosts
channel leaves in an aligned subtree (the cohort layout 9.4 and C.5.1
recommend). The channel counterparty is normally the operator, so the
attacker is the party on the other side of the channel.

**Path.** A channel leaf `L` sits at position `p` of a height-`h`
subtree: `amount = C`, `seq = SEQ_FINAL`, `evict_after = 0`, evictor the
operator (C.1.1, C.6.3, C.6.4). The operator builds `REWRITE_h` with
old element `L` and new element `L'` equal to `L` in every field but
`amount = C + 1`, supplies no `sig_p` (and under `^x` no `xsig_p`,
since 7.9 rule 7 asks for one only where rule 3 asks for `sig_p`),
signs `sig_op`, and funds the extra satoshi from its own input. The
simulator accepts it: a `REWRITE_2` at `D = 4` with one position
holding a `SEQ_FINAL` leaf raised by 1 sat ran with zero owner
signatures consumed. The same transaction raises every channel leaf in
the cohort at once, at about 117 vB per position (11) and 1 sat each.

Now the owner force-closes. `EXIT_1^=` pays `C + 1` to
`P2TR(exit_key)`. `update_n` is a `nVersion 3` transaction with one
input (`NUM_INPUTS = 1` is committed, C.2.3), outputs of `C` to `U_n`
and `0` to a P2A anchor, and `SEL_CHAN_UPD` commits every output
amount and script (C.3.3). Bound to the `C + 1` funding output it pays
a fee of 1 sat and carries a zero-value anchor, which is dust (the P2A
threshold is 240 sat, C.5.5). `PreCheckEphemeralTx` rejects it. The
owner cannot add an input, change an output or drop the anchor without
a new signature from the operator. The funds sit in the 2-of-2 until a
miner takes the transaction out of band or the operator signs a
key-path close on its terms. The operator is stuck the same way, which
is the point: it chose to be.

**Severity.** Lock at the relay layer of every channel the operator
targets, at a cost of one transaction and 1 sat per leaf; a ransom
position against the counterparty's own customers. It needs no owner
and no third party. Consensus validity is intact, so a sufficiently
motivated owner can pay a miner directly, which is why this is a lock
and not a loss.

**Existing mitigation.** C.1.1 item 2 ("`amount` MUST equal `C`") binds
the two parties, and C.2.4 argues that attaching an update to an input
worth more than `C` "merely burns the difference to fees, at the
expense of the party that does it". Both are true by consensus and
false by policy once [C-A2]'s zero-value ephemeral anchor is used.
`UPDATE^x` (7.4 rule 5) and `SEQ_FINAL` (5.2) do not reach
`REWRITE_h`, and 7.9 rule 7's `^x` form inherits the exemption
unchanged. The descending-value anchor variant of C.5.5 is not affected
(its updates already pay a fee), but it is the one the appendix
recommends against.

**Fix.** 7.9 rule 3: the exemption MUST NOT apply when
`old_i.seq = SEQ_FINAL`. 5.2 already assigns that marker to "any leaf
whose `amount` is not the owner's alone", which is exactly the class
the exemption must not touch, so no new field or flag is needed. In
`_rewrite_step` it is one `OP_SUBSTR` of the `seq` field, one
`OP_EQUAL` against the tier's `SEQ_FINAL` constant and an `OP_IF`
inside the existing exemption branch, about 12 bytes per position.
Tests: the probe above as a negative; the suite's existing
"amount-only increase" case as the positive on a plain leaf. Text: fix
C.2.4's "merely burns" sentence to say that under ephemeral anchors a
larger input makes the update non-standard.

### A2. Zero-amount and sub-dust carve leaves cannot be evicted or swept by a standard transaction, so any member can occupy any empty slot for good

**Claim.** `CLAIM` and `SPLIT` accept a claim leaf of any amount,
including 0 and 1 sat, and every transition that removes a leaf must pay
it exactly to a P2TR output, so a leaf below 330 sat is one that no
default node will relay the removal of: it blocks `EVICT_SUBTREE_h` on
its cohort and `JOIN_h` on every subtree containing it for the life of
the tree.

**Attacker.** Any leaf owner, in any tier: `SPLIT` is in all four, and a
self-signed voucher with `CLAIM` does the same. The attacker controls
the claim leaf's amount and, in the dense profile, its position.

**Path.** Cohort A occupies positions 4 to 6 of the height-2 subtree at
index 1 (lease 800,000, evictor the operator); position 7 is empty.
Alice, a member elsewhere, signs a `SPLIT` of a 1-sat leaf (or a 0-sat
leaf) with her own evictor and lease, as 7.5 rule 5 requires, into
position 7. The simulator accepts both. Cohort A's lease expires; the
operator builds `EVICT_SUBTREE_2`. The simulator accepts the sweep only
with a payout output of exactly 1 sat (or 0 sat) to the squatter's exit
key, outputs `[10000, 10007, 10014, 1]`, and rejects the same sweep
with that payout omitted. That transaction pays a fee and has a dust
output, so it is not standard; a zero-fee version would need a package
child that spends the 1-sat output, which only the squatter can sign.
The same holds for `EXIT_K` and for a `REWRITE_h` exit of that
position, and the sub-dust leaf can never be exited by its owner
either, which does not matter to a griefer. `JOIN_2` over the subtree
fails by rule (the old node is not `E_2`), and the tree can never
reach `E_D`, so 7.8's terminal exit is gone for the last real member.

The attacker does not even need an empty slot. A cohort member who
`SPLIT`s all but 1 sat of its own leaf into a fresh leaf elsewhere
leaves a 1-sat residual in its cohort position with the operator as
evictor, and the cohort's sweep is blocked the same way. The honest
version happens by itself: `design/receive.md` redeems small Lightning
receives into leaves, and a 200-sat redemption is a leaf the operator
can never sweep.

**Severity.** Grief, permanent under default policy, available to every
member at the cost of one `SPLIT` (about 1,620 vB at `D = 16`) and at
most 1 sat. The operator's remedies are to sweep the `h` sibling
subtrees around the squat (`h` transactions instead of one, if those
heights are compiled in), to detach the rest, or to pay a miner.

**Existing mitigation.** 7.5 rule 5 (F20) makes the squat inherit the
source's evictor and lease, which makes it evictable in principle;
policy, not script, is what stops its removal, and rule 5 does not look
at the amount. 5.2 says `amount` MUST be greater than 0, and 7.8 says
the scripts do not enforce it and calls zero leaves "harmless to the
total but useless", which misses that they block sweeps and grafts.
11.2's "dust is never the binding constraint" is about the exiting
member's fee, not about whether the removal is relayable.

**Fix.** A rule in 7.5 (a new rule 6, inherited by 7.5.1 to 7.5.3):
`claim_leaf.amount` MUST be at least `DUST_MIN`, and the source's
residual amount MUST be either 0 (the position becomes `E_0`) or at
least `DUST_MIN`, where `DUST_MIN` is a tree-creation parameter with
RECOMMENDED value 330 sat; operators who size cohorts by 11.2 may set
it higher. In `carve_leaf_rules` this is one comparison of the claim
amount against a constant and one more of the residual inside the
existing drained-source branch, about 15 bytes under `0xC2` and
somewhat more under `0xC0`, where the amounts are already numbers.
Tests: the two probe splits as negatives in all four tiers; Lean:
two hypotheses on `Claim`. Text: 7.8 should say zero and sub-dust
leaves block sweeps and grafts; `design/receive.md` should state the
redemption floor. `JOIN` and `REWRITE_h` joins need no rule, since the
operator signs them and squats only its own tree.

### A3. A tree that carries plain `REWRITE_h` reopens the credit-leaf voiding path that 10.3 says is closed, and the user-to-user channel splice that C.6.6 says `UPDATE^x` closes

**Claim.** 10.3 argues that with `CLAIM^x`, `UPDATE^x`, `EXIT^=` and a
`NUMS` evictor "only `SPLIT` remains" as a way for the issuer to change
a credit leaf, but a plain `REWRITE_h` lets the operator rewrite that
leaf with its own owner signature and its operator signature, and
neither 10.3, 7.5.3, C.6.6, C.9.7 nor `design/receive.md` mentions it.

**Attacker.** The operator, as owner of a credit leaf, in a tree created
by following 10.3's checklist and adding `REWRITE_h` for batching.
Likewise the owner and operator of a user-to-user channel leaf (C.6.6)
in a tree with `UPDATE^x` and plain `REWRITE_h`.

**Path.** Credit leaf `L` (owner the operator, `exit_key` the
recipient's, `NUMS` evictor) at position `p` of a cohort subtree; the
recipient holds a cumulative voucher for `x`. The operator builds
`REWRITE_h` with old element `L` and new element `L'` of amount 1 and
`seq + 1`, signs `sig_p` with its own owner key and `sig_op`, and
takes `L.amount - 1` as the free decrease of 7.9 rule 6. Rule 3 asks
for exactly those two signatures. The suite's `REWRITE_4` "payer"
case is this shape, so no new probe was needed. The voucher is void
(its source bytes no longer exist) and the recipient's `x` is gone.
For the channel case, the same transaction with the owner's signature
splices a user-to-user leaf down and strands the counterparty's
balance, which is the C.6.6 attack `UPDATE^x` was added to stop.

**Severity.** Loss, bounded by the outstanding credit or the
counterparty's channel balance; it needs a tree that is conformant and
follows the spec's own recommendations.

**Existing mitigation.** 7.9 rule 7 defines `REWRITE_h^x` and says a
tree that uses `UPDATE^x` SHOULD use it. The consumers of that rule do
not know about it: C.9.7 says the fourth property "is now verifiable
from `m`" by the presence of `UPDATE^x`, which is false when a plain
`REWRITE_h` sits beside it.

**Fix.** Text only. 7.9 rule 7: MUST, not SHOULD, whenever the taptree
carries `UPDATE^x` or `CLAIM^x`. 10.3 and 7.5.3: add "`REWRITE_h^x` in
place of `REWRITE_h`, or no `REWRITE_h`" to the credit-leaf list.
C.6.6 and C.9.7: the counterparty MUST verify from `m` that no plain
`REWRITE_h` is present. `design/receive.md`: same. A test that runs the
credit-leaf scenario under `REWRITE_h^x` and shows the drain failing
without the exit key would pin it.

### A4. Eviction and cohort sweeps void every outstanding voucher against the removed leaves, and holders are not told to look at the source lease

**Claim.** A voucher binds the source leaf's bytes, so any transition
that removes the source voids it; 10.3 lists only the issuer's own
actions, but the evictor's `EXIT` and the operator's `EVICT_SUBTREE_h`
do the same to vouchers the issuer never touched, and a holder who has
already paid for one has nothing left but the issuer's goodwill.

**Attacker.** The evictor of the source leaf, usually the operator,
once the source's `evict_after` has passed or when it is 0. No
collusion with the issuer is needed, though an issuer who sets a short
lease and lets it run is the natural beneficiary.

**Path.** Member A (lease 800,000, evictor the operator) issues a
hash-locked voucher to B and offers a Lightning invoice on the same
hash (9.6.1's canonical flow). B pays, learns the preimage, and starts
its `CLAIM^h`, which waits behind the tree output's queue (10.5). At
height 800,000 the operator evicts A, or sweeps A's cohort: an
`EXIT_1` with `is_evict` paying A's full balance to A's exit key. The
suite's "voucher replay / wrong leaf" negative is now B's situation: no
state contains A's leaf, so B's redemption fails forever. A was paid on
both legs without doing anything 9.6.2 rule 3 forbids; A can only pay
B back by another route, and nothing on-chain makes it.

**Severity.** Loss for the holder, bounded by the voucher amount. No
script fix exists: the balance has left the tree.

**Existing mitigation.** 9.6 has the recipient check that the source
leaf is in the tree, not when it may stop being. 10.8 says eviction
"cannot shortchange or redirect", which is true of the leaf and not of
the claims on it. 9.6.2 rule 4 tells the holder to redeem promptly,
which helps only if the lease is not already due.

**Fix.** Policy, in 9.6 and 9.6.2: a recipient MUST treat a voucher
whose source leaf's `evict_after` is at or below the current height,
or will be before the holder can expect a redemption to confirm under
the bound of 10.5, as unsecured credit, and SHOULD require an issuer's
lease to run past the swap's own deadline plus that bound. 10.3 and
10.8: add eviction and sweeps to the list of events that void
vouchers. An operator that issues against its own bond leaf SHOULD
give it a `NUMS` evictor or a far lease, which `design/receive.md`
already does for credit leaves.

### A5. Partial-balance vouchers need an empty slot, and the operator can take every empty slot away from a detached cohort

**Claim.** 7.5 rule 3 places the claim leaf in a position that is empty
after the source step, which a full-balance voucher satisfies with the
drained source position (F18) and a partial one does not; the
operator controls slot supply through `JOIN_0` and `DETACH_h`, so it
can make every partial voucher against a cohort unredeemable without
touching any leaf, which the `^x` variants cannot prevent.

**Attacker.** The operator. In a small tree, any member with a `SPLIT`
budget of one transaction per empty slot (after A2's fix, 330 sat
each).

**Path.** A credit leaf `L` for recipient B sits in a height-8 cohort.
The operator fills the cohort's empty positions with 1-sat leaves of
its own by `JOIN_0` (operator-signed, about 980 vB each, or none at all
if the cohort was grafted full) and then `DETACH_8` moves the cohort
into a child tree of 256 positions, all occupied. B's cumulative voucher
is for less than `L.amount`, so step 1 leaves `L'` at `p` and step 2
needs an `E_0` somewhere in the child, which the "join over an occupied
position" negative of the suite shows does not exist. B waits for a
member of the child to exit; the operator refills each freed slot by
`JOIN_0` before B's redemption can land. Under `CLAIM^x`, `UPDATE^x`
and `EXIT^=` the operator cannot alter `L`, and it does not need to.

**Severity.** Lock of the voucher instrument for as long as the operator
keeps the child full; the value stays in the issuer's leaf, so for a
credit leaf this is the voiding power 10.3 says the recipient no longer
carries, in a slower form. Cost to the operator: one detach plus
however many 1-sat joins.

**Existing mitigation.** None. 7.10 and 10.1 present `DETACH_h` as
something that "only shortens every member's path".

**Fix.** The smallest change is text: 10.1's trust table and 7.10
should say the operator can delay redemption of partial vouchers
against a cohort by detaching it full, and 9.6 should tell holders of
partial vouchers against leaves in a detachable tree to redeem before
the cohort is detached or accept that risk. The structural fix is a
`CLAIM` form whose second step is an amount-only increase of a leaf the
recipient already holds, named by the voucher, rather than the creation
of a new one; it needs no empty slot, reuses the exemption test of
`_rewrite_step`, and would also be the natural shape for the
sibling-pair claim `design/receive.md` proposes. That is new script
work and belongs with that proposal.

### A6. The redeemer picks the claim slot, so every voucher against a `NUMS`-evictor leaf is a permanent squat token for any cohort

**Claim.** A voucher binds the claim leaf's bytes and not its position,
so the holder of a voucher issued against a credit leaf with a `NUMS`
evictor, which is the configuration 10.3 and `design/receive.md`
recommend, can redeem it into an empty position of any cohort and
block that cohort's sweep for good.

**Attacker.** Any voucher recipient of such an issuer, which in the
receive design is every wallet user; the issuer itself by `SPLIT` is
the residual F20 already records.

**Path.** A credit leaf with a `NUMS` evictor at position 0 issues a
5,000-sat voucher. The simulator redeems the same `voucher_sig` either
at position 7, inside cohort A's height-2 subtree, or at position 9
outside it; both are accepted. After the position-7 redemption cohort
A's `EVICT_SUBTREE_2` fails on the evictor check, and nothing but the
squatter's own `EXIT` can ever clear the slot. The squatter paid
nothing it would not have paid to redeem anyway.

**Severity.** Grief, permanent, free to the attacker; the operator's
loss is the cohort sweep (158 to 203 vB per leaf) for individual
evictions at about 1,020 vB each, or `h` sweeps of the sibling
subtrees.

**Existing mitigation.** 7.5 rule 5 holds as written: the carve inherits
its source's terms. 10.8 frames the residual as "a leaf the operator
admitted as non-evictable" carving into cohorts, and says to prefer a
finite lease. The gap is that the recipient, not the admitted leaf's
owner, is who places the leaf, and that the spec's own credit-leaf
design makes `NUMS` the recommended evictor.

**Fix.** Text in 10.3, 10.8 and `design/receive.md`: a credit leaf
SHOULD carry a finite lease long enough for its purpose rather than
`NUMS`, so that its carves expire with it; an operator that relies on
sweeps SHOULD keep cohort subtrees full or detach them, since a
detached child can only be squatted by its own members. The
sibling-pair claim, if built, pins the claim position next to the
source and removes the slot choice for credit leaves entirely.

### A7. One unexpired leaf blocks a cohort's sweep: in-place lease renewal, and a carve by a member of a later-lease cohort

**Claim.** 7.7 rule 2 requires `nLockTime` to be at least the
`evict_after` of every non-empty position, so a single renewed leaf
holds up the sweep of its whole cohort until the renewal expires, which
contradicts 9.4's "members who renew ... are not swept"; and 7.5 rule 5
permits a member whose own lease is later to carve a leaf with that
later lease into an earlier cohort's empty slot, delaying that cohort's
sweep by the difference.

**Attacker.** For renewal, nobody: the operator co-signs the `UPDATE`
and so consents, but 9.4 tells it the wrong consequence. For the carve,
any member whose lease is later than the target cohort's, at the cost
of one `SPLIT` and a `DUST_MIN` leaf it gets back when its own lease
expires.

**Path.** Cohort A at positions 4 to 6, lease 800,000. Renewal: position
5 is renewed to 900,000 by `UPDATE`; the simulator rejects the sweep at
`nLockTime` 800,000 and 899,999 and accepts it at 900,000. Carve:
Mallory at position 8 (lease 900,000, operator evictor) `SPLIT`s a
330-sat leaf with her terms into position 7; the simulator accepts the
split, rejects cohort A's sweep at 800,000 and accepts it at 900,000.
Since cohorts have staggered leases, every later cohort can do this to
every earlier one, repeatedly.

**Severity.** Grief and cost: the operator's capital stays in the tree
for up to the attacker's lease, or it pays single evictions. Low cost
to the attacker. The renewal half is a spec inconsistency rather than
an attack.

**Existing mitigation.** 7.5 rule 5 bounds the delay by the attacker's
own lease, so it is not permanent as the `NUMS` case is. 9.4's advice
to require `evictor_key = OPERATOR_KEY` for cohort members does not
address leases.

**Fix.** Text: 9.4 should say a renewed leaf blocks its cohort's sweep
until the renewal expires, and that operators SHOULD renew by moving
the member (an `EXIT^=` and a `JOIN_0` into a cohort with the new
lease, or a `REWRITE_h` of the cohort) rather than in place. Policy:
keep cohort subtrees full or detach them. If the delay matters in
practice, a sweep variant that passes unexpired or foreign-evictor
positions through unchanged is `REWRITE_h`'s fold with a different
per-position rule, at about 117 vB per kept position; the probes above
are its tests.

### A8. A member-funded graft cannot be fee-bumped by replacement without every funder signing again

**Claim.** 9.2 has every funder sign with `SIGHASH_DEFAULT`, so the
operator cannot raise the graft's fee by replacement once the cohort
has signed, and 9.2 does not say to leave a bump path.

**Attacker.** Nobody in particular; fee conditions, or a competing exit
that the graft must outbid under 10.5.

**Path.** A 256-member self-funded `JOIN_8` is signed at 2 sat/vB; fees
rise; a replacement needs 256 new signatures, which is the
coordination round the protocol review already costs. CPFP works only
if the transaction has an output somebody can spend: the operator's
change, or a P2A anchor, which 4.7 permits at any index above the
payouts.

**Severity.** Cost and liveness only.

**Existing mitigation.** 4.7 notes anchor compatibility; 10.5 says
operators "SHOULD use anchor outputs". 9.2 does not.

**Fix.** A sentence in 9.2: a graft with more than one funder SHOULD
carry an operator change output or a P2A anchor, and funders SHOULD
expect fee bumping by CPFP rather than replacement.

## Considered and rejected

Each item names the claim examined and the reason it does not stand, so
the owner need not re-examine it.

* **MID numerics: presenting an amount or sibling sum as a negative
  `CScriptNum` (for example the 129-sat field `81 00 00 00 00 00 00 00`
  as `0x81`, which is `-1`).** The hash preimages are the raw bytes, so
  a misparse leaves every leaf and sibling hash intact and changes only
  the running sum, which must equal the input amount at the root and
  must regenerate the honest `enc64` bytes at every parent through
  `PADZ`, whose padding is injective on the number. A misparsed input
  cannot be compensated by another, since every misparse makes the
  number smaller. The simulator rejects the probe at the `PADZ` size
  check before any of that is reached.
* **Flipping `is_evict` when a leaf's owner and evictor keys coincide.**
  The signature validates in both branches; the eviction branch only
  adds a lock-time check and tightens the payout to equality. The
  witness is not covered by the txid, so a relayer gains nothing and
  can break nothing.
* **Unsigned witness elements in general (`PADZ` pads, proof siblings,
  `dir` bits, MIN's `extra_outs` and `e31`).** Every one is either
  fixed by the committed root, by `MINIMALIF`, by the pad's size
  relation, or by the generator-key `CHECKSIG` against the real
  transaction. Malleating any of them fails the script or leaves the
  transaction identical; the txid never moves.
* **`CLAIM` carries no transaction signature.** The transaction body,
  including the claim position chosen through output 0, is bound only
  by the redeemer's fee input, which signs with a hash type of its
  choosing. A redeemer using `SIGHASH_NONE` on its fee input lets a
  relayer move its own claim leaf to another empty slot or redirect its
  own change. Nobody else is affected.
* **`SIGHASH_ALL|ANYONECANPAY` on exit signatures as a package-pinning
  surface.** A relayer could rebuild the exit with its own fee input
  behind a low-feerate unconfirmed parent, but BIP-125 rule 2 (Core's
  `HasNoNewUnconfirmed`) forbids a replacement from spending
  unconfirmed inputs the original did not, and with a confirmed input
  the relayer is only paying the owner's fee. 10.7's "harmless" stands.
* **Duplicating a victim's leaf by `SPLIT` so one of its vouchers
  redeems twice, or recreating a historical leaf by `UPDATE` or
  `REWRITE_h` to revive retired vouchers.** The duplicate is funded by
  whoever creates it and owned by the victim's key; the extra
  redemption and the residual come out of the creator's money. A
  byte-identical channel leaf pays the channel's two parties from the
  copier's funds (`design/batching.md` says this already).
* **`tree_id` reuse across trees, or a reorganisation of the creation
  transaction.** A voucher replays across trees only against identical
  source bytes, which only the issuer or a funder can put there, at
  their own expense. A reorganised creation either comes back with the
  same `tree_id` and parameters, which is the same tree, or never
  exists, which 10.11 covers.
* **The terminal branch (`FINAL` compares `nh` with `E_D.hash` and not
  `ns` with 0).** Reaching `E_D.hash` with a nonzero sum is a collision
  in `H_node`.
* **`DETACH_h` of an empty or sub-dust subtree, or `JOIN_h` of a
  zero-sum or opaque node.** Operator-signed, operator-funded, and
  harmful only to the operator's own tree (F18). The child inherits the
  option set (F21) and its leaves byte for byte.
* **Operator key compromise.** The attacker can evict expired leaves
  (paying them in full), graft with its own money, detach, and co-sign
  what owners also sign. With A1 fixed it cannot change any balance
  downward. The design's "no custody" claim survives key loss, which is
  worth stating in 10.1.
* **The lease boundary and an `EXIT` racing an `EVICT` of the same
  leaf.** Both pay the same exit key; under `EXIT^=` the same amount;
  under the FULL fee option the owner's version pays the owner less, by
  the owner's choice. The CLTV semantics make an eviction minable at
  `evict_after + 1`, which is the lease as described.
* **An operator stalling a renewal until expiry and then evicting.**
  That is what a lease means; the eviction pays in full and 9.4 already
  says operators SHOULD offer renewal.
* **Reorganisations of each transition.** Every transition spends a
  specific outpoint and is re-broadcastable as long as its inputs
  exist; channel states rebind by construction; the one race that
  matters, a `CLAIM^h` reorganised out after the preimage is public, is
  9.6.2 rule 4.
* **Script and witness growth against policy limits.** Tapscript has no
  script-size limit; the largest measured shape (`EVICT_SUBTREE_8` at
  `D = 20`, about 85 kWU) is a quarter of `MAX_STANDARD_TX_WEIGHT`; the
  `0xC0` tiers keep every witness item under the 80-byte policy limit
  except MIN's `extra_outs`, which `paper/reviews/protocol.md` item 10
  already records; the MID stack bound is in 4.5.
* **CCV's tree input at any index.** Two tree inputs cannot share
  output 0 (4.6, `test_two_trees`); a tree input beside unrelated inputs
  is the ordinary fee-input case.
* **Position exhaustion by members in a full-size tree.** At `D = 16`
  filling 65,536 slots by `SPLIT` costs over 100 MvB; the feasible form
  is the operator's, A5.
* **An old cumulative voucher leaking to a third party, who redeems it
  to void the newer ones.** Under `CLAIM^x` the recipient's exit key
  must sign, so a leaked voucher is inert; under plain `CLAIM^h` the
  issuer already holds every old voucher and preimage, which is the
  operator-drain case `design/receive.md` closes with `CLAIM^x`.
* **Data availability after an `UPDATE`, `CLAIM`, `REWRITE_h` or
  `DETACH_h`.** Each witness publishes everything a member needs to
  advance its path (9.7); the only off-chain dependency is the
  join-time subtree path, which 10.9 already requires members to back
  up.
* **Items already in the prior reviews, not re-examined:** unbounded
  conflicting transitions and the liveness bound, the descendant and
  cluster limits and their adversarial consumption, TRUC being
  unavailable to transitions, the self-funded cohort signing round,
  exits that cannot be pre-signed, the `CLAIM^h` issuer race, MIN's
  `extra_outs`, the 2^31 MID cap, the seven-HTLC MID limit, and the
  220-block budget's dependence on `N`.

## What each finding should become

| Finding | Spec rule | Test | Policy or text |
|---|---|---|---|
| A1 `REWRITE_h` exemption on `SEQ_FINAL` leaves | 7.9 rule 3 exception excludes `seq = SEQ_FINAL`; about 12 bytes in `_rewrite_step` | negative: raise a `SEQ_FINAL` leaf without a signature; positive: plain leaf | C.2.4: a larger input makes ephemeral-anchor updates non-standard |
| A2 dust and zero carves | 7.5 rule 6 `DUST_MIN` on the claim amount and the residual; Lean hypotheses on `Claim` | the two splits as negatives in all tiers | 7.8, 11.2 and `design/receive.md` on sweepability |
| A3 plain `REWRITE_h` beside `UPDATE^x` and `CLAIM^x` | 7.9 rule 7 becomes MUST in those trees | credit leaf under `REWRITE_h^x`: drain fails without the exit key | 10.3, 7.5.3, C.6.6, C.9.7, `design/receive.md` |
| A4 eviction voids vouchers | none possible | none useful | 9.6, 9.6.2, 10.3, 10.8: lease check for holders |
| A5 slot supply and partial vouchers | later: a claim form that credits an existing leaf | later | 7.10, 10.1 trust table, 9.6 |
| A6 `NUMS` credit leaves as squat tokens | none | the position-free redemption as a documented case | 10.3, 10.8, `design/receive.md`: finite leases, full or detached cohorts |
| A7 unexpired leaves block sweeps | optional keep-variant of `EVICT_SUBTREE_h` | the renewal and cross-cohort probes | 9.4 correction, renew by relocation |
| A8 graft fee bumping | none | none | 9.2: anchor or change output, CPFP not RBF |
