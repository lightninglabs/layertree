# Review: Bitcoin and Lightning developer profile

**Paper:** "LayerTree: A Shared Bitcoin UTXO with an O(1) Unilateral Exit",
`paper/main.pdf` (short version), title page "Draft (commit dce2c57)",
2026-10-10; read with the `paper/*.tex` sources at `e16ce55`, against
`spec/layertree.md` 0.12.1 (the version in the tree; no 0.12.2 exists yet),
`spec/channel-leaves.md`, `spec/scripts/sizes.md`, `spec/scripts/weights.md`,
`spec/fee-analysis.md` and `design/*.md`.
**Reviewer profile:** wallet and node implementer who has shipped taproot
and Lightning code, reads BIPs and BOLTs, has run a routing node, and has
watched Ark, channel factories and covenant proposals go by. The question
throughout is whether I could build a wallet, an operator or a tower from
this text, and whether the costs and comparisons are the ones I would see
on mainnet.
**Scope:** the round-two items recorded in `paper/review-response.md`
(liveness assumption [C], kappa and cluster mempool, the deployment
assumptions table, prior art, the self-funded signing round, witness
prefixes, the hub budget, pre-signed exits, cheques, MIN grinding, the
Ark and Lightning baselines) are treated as settled and are not repeated
unless the fix left a developer-visible gap.

## Summary verdict

This is the first version of the paper I could hand to an implementer as
an orientation document. Section 4 walks the operations in the order a
member meets them and says, for each, who signs and what the chain sees;
every vB figure I recomputed from `sizes.md` and the 946 WU skeleton
reproduces; the assumptions table states the opcode status honestly; and
the trust table is close to what the scripts enforce. The construction
is sound where I tested it.

Three things stop me from building the part of it the abstract sells
hardest, the voucher system and Lightning receive. (1) The voucher trust
statement is wrong in a way the reference code confirms: `REWRITE_h`'s
amount-only exemption (spec 7.9 rule 3, carried into `REWRITE_h^x` by
rule 7) lets the operator alone raise any non-`SEQ_FINAL` leaf by one
satoshi. Every voucher binds its source leaf's bytes and every tower
authorisation binds the leaf, so the operator alone can void every
outstanding voucher (plain, hash-locked or credit-leaf) and every tower
exit authorisation in the tree. On a credit leaf this freezes the
recipient's whole balance, with no deadline. Section 5.3's "every
transition that could change it needs the exit key" is false. (2)
Receiving over Lightning is free on-chain only if the operator pre-funds
capital it can recover only with the recipient's consent; otherwise it
is an on-chain top-up per receive batch, and it is FULL-only. (3) Every
unilateral recourse the paper describes, from `CLAIM^x` for "a user with
no on-chain funds" to a channel-leaf force close, needs an external
on-chain fee UTXO that the paper never mentions, and below roughly
27,000 sat at 10 sat/vB it does not pay for itself.

The rest is what a developer needs and cannot find. Nothing says to
recompute `m` from the published parameters before trusting a tree
output, though custody rests on that check. Nothing covers creation,
what each party stores, reorganisations or the wire messages that exist
in `msg/`. The channel-leaf deadline drops the stale-update term the
spec added after the last round. The comparison tables price no lease
renewal while crediting the lease-dependent sweep. **Recommendation:
major revision.** Finding 1 needs a design decision (I suggest the
smallest one below); the rest is text, and most of it is already in the
spec.

## Findings

### 1. The operator alone can void any voucher and any tower authorisation by raising the source leaf's amount

**Severity:** blocking.
**Location:** §5.3, "The dedicated credit leaf" and "What the Holder
Trusts"; §5.4 rule (3); §5.5; §4.4, `EXIT^t_K` ("an owner signs once in
advance and a tower does the rest"); Table 1, operator row; Appendix
B.6. Spec 7.9 rules 3, 4 and 7, 10.3, 9.7.
**Claim:** "Voiding needs the leaf to change, and every transition that
could change it needs the exit key: CLAIMx, UPDATEx and REWRITExh by
rule [...]. The balance can only grow or pay its recipient, whose
remaining exposure is the issuer's liveness." And, for ordinary
vouchers, the holder "extends credit to the issuer".
**Problem.** A voucher signs `H_voucher(tree_id || l_src || l_claim)`
over the full 116-byte source leaf, amount included (§5.1, spec 7.5), and
an `EXIT^t` authorisation signs `H_exit(tree_id || leaf)` (spec 9.3).
Spec 7.9 rule 3 exempts from every owner signature a position whose new
leaf equals the old one in every field but a larger `amount`, unless
`seq = SEQ_FINAL`; rule 4 then needs only `sig_op`. Rule 7 adds the exit
key's signature only "for every position for which rule 3 requires
`sig_i`", so the exemption survives in `REWRITE_h^x`. The reference
tests exercise exactly this: `_needs_owner_sig` in
`tools/test_scripts.py` returns false for an amount-only increase, and
the `REWRITE_X_h` cases run the "mixed" scenario, which includes one,
with no signature on that position.
Three consequences follow.
- **Credit leaf.** A credit leaf cannot be `SEQ_FINAL`, because `CLAIM^x`
  must advance its `seq`. The operator, which owns it, tops it up by one
  satoshi with `sig_op` alone. The recipient's latest voucher no longer
  matches `l_src`. The recipient holds no owner key, so `EXIT^=`,
  `UPDATE^x` and `CLAIM^x` are closed to it without the operator, and
  eviction is the operator's option, not its obligation. The balance is
  then frozen until the operator chooses to exit or evict the leaf, with
  no deadline. Nothing is stolen, since every operator path still pays
  the recipient, but "redeems its latest voucher alone" (§5.5) is no
  longer true. The spec repeats the false sentence in 10.3 and, two
  paragraphs later, recommends the very top-up that triggers it as the
  normal way to fund the leaf.
- **Ordinary vouchers.** In any tree carrying a plain `REWRITE_h`, the
  operator can void a voucher issued by any member by gifting the source
  leaf one satoshi. The holder therefore trusts the issuer *and* the
  operator, not the issuer alone. This matters most in the §5.4 swap: a
  holder who has paid the HTLC can have its `CLAIM^h` voided by the
  operator even if the issuer keeps rule (3).
- **Tower exits.** The operator, the party a tower most often defends
  against, can void every `EXIT^t` authorisation it likes, one
  rewrite per cohort, just before contesting an exit. Spec 9.7 admits
  this for towers ("SHOULD obtain a fresh one from the owner when the
  leaf changes"). The paper does not, and that undoes "the owner need not
  be online".
**Resolution.** Decide which property is wanted, then make the text
match it.
- (a) The smallest change: have `H_voucher` and `H_exit` bind the source
  leaf with its `amount` field omitted (or zeroed). Single use still
  comes from `seq`, over-redemption is still stopped by the underflow
  check, and spec 9.6 already obliges an issuer to rebuild its vouchers
  after any `UPDATE`, so nothing relies on the amount being bound. A
  top-up then voids nothing. Check `voucher_no_replay` in the Lean model
  against the narrower message.
- (b) Alternatively, remove the amount-only exemption whenever the tree
  carries `CLAIM^x` or `EXIT^t`. Top-ups then need the owner's
  signature, and the recipient's exit-key signature in `REWRITE_h^x`.
  The trust-free receive configuration then needs the recipient online
  at each top-up, or a pre-funded leaf.
- (c) Failing either, state the property: the operator can void any
  voucher or tower authorisation at the cost of one rewrite and one
  satoshi, and a credit-leaf recipient's exposure is an indefinite
  freeze at the operator's discretion. Add "void vouchers and exit
  authorisations by raising a leaf" to the operator's "can" column of
  Table 1 and to spec 10.1.

### 2. Lightning receive is not free on-chain in its safe configuration, and the flow leaves out who holds the preimage

**Severity:** major.
**Location:** abstract ("repeated payments to one recipient, including
payments received over Lightning, cost nothing on-chain and never
expire"); §5.5, "The flow" ("Nothing reaches the chain [...] the
recipient need not be online when it is paid"); §5.3, "tops it up by an
amount-only increase"; §7 ("CLAIMx is FULL's alone").
**Claim:** the operator signs a cumulative voucher against a credit leaf
per receive, and nothing reaches the chain.
**Problem.** A cumulative voucher can draw at most the credit leaf's
current amount (minus `DUST_MIN` unless it drains the leaf). The
recipient's running total therefore needs a leaf funded at least that
high, and the paper offers two ways to get there. Neither is free.
- *Pre-fund.* Spec 10.3 and `design/audit/channels.md` B3 show that
  capital placed in a credit leaf beyond what has been vouched for is
  recoverable "only with the recipient's consent". An operator serving
  10,000 receive-only wallets then locks, per wallet, inbound capacity
  that it can lose to any recipient who refuses to co-sign the
  reduction. Unlike an LSP's inbound channel, that capacity does not
  come back at close.
- *Top up as credit accrues*, which is what §5.3 and spec 10.3
  recommend. Each top-up is an on-chain `REWRITE_h^x`, about 122 vB per
  credit leaf batched per cohort (`design/receive.md`, cost table), and
  under finding 1 each top-up also voids the recipient's latest voucher
  until it is re-signed.

So receiving costs either capital at risk or about 122 vB per recipient
per top-up batch. Either is a reasonable price, but the paper should
state it rather than "nothing on-chain". Separately, "obtains the
preimage" hides a choice that decides both the wallet's UX and its
trust. `design/receive.md` gives two options. In the first the operator
draws the preimage, so the payer's proof of payment shows that the
operator was paid, not the recipient. In the second the recipient draws
it and hands it over in advance, so it is not offline-receivable without
pre-shared preimages. Finally, `CLAIM^x` exists only in FULL (§7 and
Table 2), so the receive flow needs the tier with two colliding draft
opcode assignments ([A-3], [A-4]), which the abstract does not say.
**Resolution.** In §5.5, say who draws the preimage and what the payer's
receipt then proves. Give the funding choice with its cost (pre-funded
capital recoverable only by consent, or about 122 vB per top-up batch).
Qualify the abstract to "cost nothing on-chain per payment, given a
funded credit leaf, in the FULL tier". In Table 12, the "pay off-chain"
cell for LayerTree should name the operator as a party to Lightning
receive.

### 3. Unilateral recourse needs an on-chain fee UTXO, and small balances have none worth exercising

**Severity:** major.
**Location:** §5.5 ("If the operator stops cooperating, the recipient
redeems its latest voucher alone with one CLAIMx: 1,635 vB at D = 16,
about 16,350 sat at 10 sat/vB"; "A user with no on-chain funds"); §5.4
("it is also how a newcomer buys a leaf with Lightning funds"); §4.4
("saves the fee input (99 vB)"); §9; Tables 10 and 11. Spec 9.3, 7.2 rule
6, C.5.5, C.6.1, 11.2.
**Claim:** each of these is something a member can do "alone".
**Problem.** The only operation that can pay its fee out of tree value is
FULL's fee-from-payout `EXIT`. Every other recourse needs an external
input.
- `CLAIM`, `CLAIM^h`, `CLAIM^x` and `SPLIT` conserve the tree total, so
  there is no value to take a fee from.
- A credit-leaf tree must carry the exact-payout exit (§5.3), as must
  MID, MIN, CCV and every channel leaf (§4.4, §9). Spec C.6.1 forbids
  the fee-deduction exit for channel leaves.
- Spec C.5.5 says it outright: "both parties MUST hold a confirmed
  on-chain UTXO to close a channel leaf unilaterally".

The user §5.5 describes, one with no on-chain funds, therefore cannot
exercise the recourse the section offers. And a recipient with fee coins
pays `CLAIM^x` plus an exact exit, 1,635 + 1,020 = 2,655 vB, about 26,550
sat at 10 sat/vB and about 133,000 sat at 50 sat/vB. Below that a
receive has no economic unilateral recourse at all. Spec 11.2 puts the
balance at which a lone exit costs 10% at 102,000 sat at 10 sat/vB. The
paper contains no break-even figure, and "no minimum per payment beyond
`DUST_MIN` at redemption" reads as if there were none.
**Resolution.** Add one paragraph to §6, "What a member does": a member,
a voucher holder and a channel-leaf party must each keep a confirmed fee
reserve, sized for which operations. Add the break-even balances (spec
11.2) for `EXIT` and for `CLAIM^x` + `EXIT^=` at 2, 10 and 50 sat/vB.
State in §5.5 that the fallback needs fee coins. If the design wants to
serve users with no on-chain funds, a `CLAIM` variant whose claim leaf
may be smaller than the voucher's amount, with the difference leaving
output 0 as fee (the analogue of FULL's `≤` payout), would close the gap
for redemption. The exit would still need a `≤` payout, which credit
leaves exclude.

### 4. A wallet's first check is missing: recompute `m`, and know how a tree is created

**Severity:** major.
**Location:** §3.2 ("its Merkle root m identifies the rule set and is
fixed for the tree's life"); §6 ("Custody never rests with the
operator"); §4 (no creation step); §5.1 ("tree_id is a 32-byte constant
fixed when the tree is created"). Spec 6.2, 6.5, 9.1.
**Claim:** custody never rests with the operator, because every script
path needs a proof and the affected owner's signature.
**Problem.** That holds only for the taptree the member believes it is
looking at. `TreeSPK(r, m)` hides the scripts. An operator that adds one
extra tapleaf ("operator key alone spends the output") produces a tree
output indistinguishable on-chain from an honest one. Spec 9.1 says
participants MUST recompute `m` from `(D, OPERATOR_KEY, tree_id,
heights, m)` and the chosen variants before treating an output as a
LayerTree, and the credit-leaf text in §5.3 relies on the same check for
`REWRITE_h`. The paper never states the general rule, never lists the
parameters, and never says that the variants are visible only through
`m`, so that a wallet must reject unknown leaves. A developer who reads
§3.2 and §6 will skip the check that custody rests on. Tree creation is
also absent. The paper does not say:
- that a zero-value output is invalid, so the operator seeds the tree
  with a leaf of its own (spec 6.5);
- that `tree_id` is RECOMMENDED as a tagged hash of the creation
  transaction's input-0 outpoint, which is what makes it unique per
  lineage, and that a chosen constant would not be (spec 6.2);
- that the creation input must be fixed before the scripts are compiled.
**Resolution.** Add a short "Creating and recognising a tree" paragraph
at the start of §4. Name the parameters, the `tree_id` derivation and
the seed leaf, and make the recomputation of `m` (rejecting any tapleaf
not in the expected set) the first thing a member, a voucher holder and
a tower does. Qualify §6's custody sentence with it.

### 5. The channel-leaf deadline omits the counterparty's stale updates, and the fee reserve it needs

**Severity:** major.
**Location:** §9, "Deadlines and hub size" ("a channel leaf needs
cltv_expiry_delta ≥ Gexit + 3 + csv_delay + Gsweep [...] about 220
blocks, against 40 to 80 on the public network"). Spec C.4.4, C.5.5,
C.9.3; `design/audit/channels.md` B4.
**Claim:** about 220 blocks of `cltv_expiry_delta` make a channel leaf's
HTLCs safe, given `G_exit` under [C].
**Problem.** Spec C.4.4 now reads `G_exit + 1 + beta_chan + 1 +
csv_delay + 1 + G_sweep`. Each LN-Symmetry update can bind any earlier
update output, so a counterparty holding states `1..k` publishes them one
per block (TRUC prevents the honest update from chaining onto an
unconfirmed stale one). Each costs it about 313 vB, and the margin the
paper's "+ 3" provides absorbs two. At the paper's 220-block figure a
third stale update makes the offerer's timeout final first:
`tools/test_chan.py` shows it at the spec bound. The counterparty is
normally the operator, so this is the operator's lever, separate from β
on the tree output. The paper's formula has no `beta_chan` term and its
"+ 3" reads as structural.

Three smaller points.
- The defaults are about 34 (Core Lightning), 72 (LDK), 80 (lnd) and
  144 (eclair), not "40 to 80".
- The parameter that binds depends on direction. For a leaf that only
  receives it is the hub's `min_final_cltv_expiry_delta` in the invoice;
  for a leaf that pays it is the hub's `cltv_expiry_delta` on the
  leaf-facing hop.
- Neither party can close without the confirmed fee UTXO and the
  HTLC-proportional reserve of C.5.5 (finding 3).
**Resolution.** Carry `beta_chan` into §9's formula with one sentence on
what it costs the attacker per block. Say which delta applies in each
direction. Correct the public-network range. Add the fee-reserve
requirement.

### 6. Vouchers are not Ark out-of-round payments with "one difference"

**Severity:** major.
**Location:** §5, opening ("Vouchers are the LayerTree counterpart of
Ark's out-of-round payments, with one difference: a redeemed voucher is
a leaf of the tree, which its holder can exit alone, not an output that
expires with a round"); spec 10.3 ("the same trust profile as an Ark
out-of-round payment").
**Claim:** the trust is the same as Ark's, and only expiry differs.
**Problem.** In deployed Ark an out-of-round transfer is a transaction
spending the sender's VTXO, co-signed by the server. Undoing it needs
sender and server to collude, and the recipient holds a VTXO it can
unroll at once. An ordinary voucher is voidable by the issuer alone
(§5.3: `SPLIT` or a self-issued `CLAIM`), by the source's evictor once
the lease passes, and by the operator alone (finding 1). The holder's
position is a promise until a 1,617 vB redemption confirms. Two of the
paper's own statements also qualify "not an output that expires":
- the claim leaf inherits the source's evictor and a lease no later
  than the source's (§5.1), so it is evictable on the same schedule;
- the difference from Ark is that eviction pays the holder on-chain,
  where Ark expiry forfeits to the operator.

That difference is real and favourable, and it is what the paper should
claim.
**Resolution.** Rewrite the comparison. Vouchers trade Ark's
two-party collusion requirement for a one-party (issuer) voiding risk,
plus the operator's under finding 1, in exchange for a balance that
expires into an on-chain payout rather than a forfeit. The credit leaf
is the configuration that recovers Ark's property for the
operator-to-user direction. Fix spec 10.3 to match.

### 7. Lease renewal, the recurring cost of holding a position, is not priced

**Severity:** major.
**Location:** Tables 8, 10 and 11 (Appendix B); B.2 ("a leaf [...] with a
lease far in the future, blocks the sweep"); §4.5 ("renew a member by
moving it to a cohort with the new lease (an UPDATE followed by a SPLIT
of the whole balance)"); Table 11, "what expires: nothing; leases are
optional".
**Claim:** a member who leaves with its cohort pays about 160 vB over its
lifetime, and Ark's row carries "a round transaction per refresh".
**Problem.** The 158 vB sweep that the lifetime and batch figures credit
works only on leaves whose leases have run out and are aligned per
cohort. The paper's own renewal recipe (§4.5, spec 9.4) is `UPDATE` plus
a whole-balance `SPLIT`: 1,030 + 1,586 = 2,616 vB per member per renewal.
The cheaper in-place path, a cohort `REWRITE_6` at 148 vB per changed
leaf, needs every renewing member's signature, and any member who does
not sign keeps the old lease. The alignment the sweep needs then holds
only if the absent members are swept or moved, which reintroduces a
signing session that ends at a deadline, much like an Ark refresh. None
of this appears in the tables. Two further problems:
- Table 11's "leases are optional" sits beside a 158 vB batch exit that
  requires one.
- Table 8's Ark row says "plus a round transaction per refresh" but its
  86 kvB contains none.
**Resolution.** Add a renewal row with both paths (2,616 vB alone, about
148 vB per member in a cohort rewrite with every member signing), and a
per-period cost line for LayerTree and Ark at a stated lease and VTXO
lifetime. Change "leases are optional" to "a lease is the price of the
cheap batch exit", and make Table 8's Ark label match its number.

### 8. What each party stores, sends and does at a reorganisation is not in the paper

**Severity:** major.
**Location:** §6, "What a member does"; §4.1; §5; §9; no section on
reorganisations or messages. Spec 9.2, 9.6, 9.7, 10.9, 10.11, C.9.3;
`msg/join.go`, `msg/voucher.go`, `msg/proof.go`, `msg/chan.go`.
**Claim:** "A member stores its leaf and path and follows every spend of
the tree output [...] and needs nothing else to exit."
**Problem.** That holds for a member who joined by `JOIN_0` and never
holds a voucher. For everyone else the paper leaves out state that the
spec makes mandatory, and a wallet built from the paper alone would lose
funds or be unable to redeem.
- *Grafted member.* Its path inside the subtree is not on-chain. Spec
  10.9 makes a backup REQUIRED, and a member who loses it cannot exit
  unless the operator or a cohort peer supplies it.
- *Voucher holder.* It needs the voucher, `l_src`, `l_claim`, the
  source's current path (tracked from the chain as a member tracks its
  own), and either a full-balance voucher or the path of an empty
  position. A party that is not a member can build that path only by
  following the tree from creation, or by asking the operator, which is
  the party it may be falling back against.
- *Tower.* It holds the authorisation, the leaf, its path, `m` and a fee
  UTXO (spec C.9.3), and must refresh the authorisation after any leaf
  change (finding 1).
- *Reorganisations.* Spec 10.11 says vouchers, paths and roots are keyed
  by `(txid, r)` and must be rolled back. The paper never says so. Nor
  does it say that a reorged `CLAIM^h` returns the swap to the issuer's
  discretion, or that a member paying off-chain for a grafted leaf
  should wait for its usual confirmation depth.
- *Messages.* Spec 9 says message encoding is out of scope, but the Go
  implementation has TLV codecs for joins, vouchers, proofs and every
  channel message, and the paper does not mention them.
**Resolution.** Add a half-page "Implementer's state" table (party,
what it stores, what it must back up, what it re-derives from each
block, what it rolls back on a reorg), and one sentence pointing at
`msg/` for the wire formats. Appendix B's comparison could give way to
it if space is short.

### 9. Two wallet rules the paper omits: nonce discipline and source uniqueness

**Severity:** minor.
**Location:** §5.1 ("no two leaves share an owner key and nonce");
§4.4 (`EXIT^t`). Spec 9.2, 10.3.
**Problem.** Two rules the spec makes mandatory for wallets are absent.
- *Nonce discipline.* Spec 9.2 forbids rejoining any tree of a lineage
  with an `(owner_key, nonce, seq)` held before. An identical leaf
  revives every `EXIT^t` authorisation ever published for it, and a
  holder of an old one can then force the member out. The paper states
  only the within-tree uniqueness rule.
- *Source uniqueness.* Spec 10.3 has a dense-profile issuer check that
  no duplicate of its source leaf exists before signing a voucher. One
  voucher redeems against both copies.
**Resolution.** One sentence each in §5.1 and §4.4.

### 10. The chain limit the paper uses is not the one its citation describes

**Severity:** minor.
**Location:** §6 ("25 under Bitcoin Core's chain limits before version
31, at most 64 under its cluster limit since"); §6 and B.2 ("drains 25
exits per block"); §9 ("with κ = 25 [...] about 1,775 channel leaves").
**Problem.** The paper's own reference [3] is Bitcoin Core v31.1, which
by the paper's account enforces the cluster limit. Yet every throughput
and hub-sizing figure uses 25 and gives no reason. The reason is in spec
10.5: a deployment must assume the lowest limit its relay peers
enforce. B.2's "About 25 exits a block is the worst case, strangers
leaving one at a time" has two further problems.
- Strangers chain only if each sees the previous unconfirmed exit and
  re-signs over the new outpoint; without `EXIT^t` they conflict and
  replace one another rather than chain.
- That is the cooperative best case for uncoordinated exits, not the
  worst; the worst is β.
**Resolution.** State why 25 is used, and say what 64 gives once relay
peers have upgraded. Reword B.2 to say that chaining needs each exiter
to rebuild on the previous one, or a tower or operator holding `EXIT^t`
authorisations.

### 11. Channel-leaf and lifetime numbers: two labels and two sums

**Severity:** minor.
**Location:** §9, last sentence; Table 10; Tables 10 and 11.
**Problem.**
- §9: "A force-close costs about 1,681 vB, against about 680 vB for a
  simple taproot channel." Table 9 gives the channel's force close as
  530 vB; 684 is open plus force close. The comparison is right, since
  the leaf's exit materialises the funding output, but the label says
  force close against force close.
- Table 10: the LayerTree batch cells are 162 and 220. The caption's
  inputs give 3 + 158 = 161 and 61 + 158 = 219 (8,057 / 51 = 157.98).
  If `REWRITE_6`'s 162 was meant, the sums are 165 and 223.
- Table 10's "online: nobody" for LayerTree contradicts Table 11, where a
  plain `EXIT_K` needs "the owner, to build, sign and rebuild if
  outbid"; "nobody" is true only of `EXIT^t_K`.
**Resolution.** Label §9's comparison as lifetime against lifetime. Fix
the two cells. Split Table 10's LayerTree online cell by exit variant.

### 12. The trust table needs three qualifications

**Severity:** minor.
**Location:** Table 1; §6 first paragraph.
**Problem.** Three cells, and the sentence below the table, say more
than the scripts enforce.
- "Anyone cannot trigger an owner's exit": anyone holding an `EXIT^t`
  authorisation can, since it is a bearer right (§4.4).
- "Owner cannot affect any other leaf": an owner can carve a leaf into
  an empty position inside an aligned slot. That blocks a `JOIN_h` into
  the enclosing slot and delays the cohort's sweep until the carver's
  lease passes (spec 9.4, last paragraph). It affects the operator and
  every later joiner, at a cost of 1,586 vB and 330 sat per fragment.
- The operator "cannot ... change the taptree, a lease": spec 10.1 says
  "unilaterally". With the owner it can, by `UPDATE`.
- §6, "or the operator's signature for operations that only add value
  or move a cohort intact": this omits eviction, which removes a leaf on
  the evictor's signature alone, and the amount-only rewrite (finding 1).
**Resolution.** Add the qualifications. Add "occupy empty positions"
to the owner's "can" column.

### 13. `P2TR(exit_key)` is not defined, and the background suggests the wrong reading

**Severity:** minor.
**Location:** Figure 1 ("P2TR(ℓ2.exit_key)"); §2 (P2TR defined through an
internal key and a tap tweak); §4.4. Spec 2.1, 5.2.
**Problem.** Spec 2.1 defines `P2TR(k)` as `OP_1 <k>`, so `exit_key` is
the output key itself, with no BIP-86 tweak. That is what lets a channel
leaf name its funding output key. A wallet that reads §2 and writes its
BIP-86 internal key into the leaf receives an output keyed to the
untweaked key. It is spendable, but not by a signer that only produces
BIP-86 key-path signatures.
**Resolution.** One sentence in §3.1: "exit_key is the payout's output
key; a single-key wallet supplies its tweaked BIP-86 output key".

### 14. Serialised weights now exist; the body still uses the model

**Severity:** minor.
**Location:** Table 2; §10 ("+33%", "+44%"); Table 5. `spec/scripts/weights.md`.
**Problem.** Round two stated the prefix omission and handed the
measurement off. It now exists, and Table 5 prints it beside the model:
FULL `EXIT_1` is 1,030 vB, MID 1,398 and MIN 1,518. The tier premium a
developer will see on mainnet is therefore +36% and +47%, not +33% and
+44%. The difference is not large, but Table 2 is the table developers
will copy.
**Resolution.** Put the serialised figure in Table 2's last row, or give
both.

### 15. Nits

- Table 2 caption: "about 520 vB in a full depth-16 tree (§12)". §12 is
  the conclusion; the figure is in Appendix B.1.
- Figure 4's labels carry repository PR numbers ("(PR #6)", "(PR #7,
  hypothetical)").
- §9 cites BIP-431 [42] for "an ephemeral anchor". BIP-431 is TRUC. Pay
  to Anchor and ephemeral dust are Bitcoin Core policy and need their
  own citation.
- §4 opening: "Payouts are outputs 1, ..., K, each paying exactly a
  removed leaf's amount", while §4.4 allows FULL's payout to be less.
- §4.3 ends with a fragment: "FULL and MID, where the stack limit holds
  a full cohort to h = 5."
- §4.1 and Table 7 give `JOIN_8` at 679 vB as a measurement. Figure 7's
  caption says that dense points above four members are extrapolated
  from `JOIN_2` at 129 WU a level. Mark 679 (and B.3's 614) as
  estimates where they first appear.
- The abstract's "never expire" holds for credit-leaf vouchers. A plain
  voucher is unsecured once its source lease can pass (§5.3).
- §6 "What a member does" says the member "must be online to exit". With
  `EXIT^t`, it need not be. Point forward to §4.4.

## Checked, holds

- **Exit sizes.** Every `EXIT_1` cell of Table 2 and Table 4 from
  `sizes.md` plus the 946 WU skeleton: FULL 762, 891, 1,020 and 1,149;
  MID 1,355; MIN 1,473; CCV 908. Also the 129 WU per level, the tier
  premium of 10 and 14 levels, and the sparse ratios 1.75 and 2.8.
- **Transitions without a payout** (774 WU): `JOIN_0` 937, `JOIN_2` 872,
  `JOINK_2` 1,494, `UPDATE` 1,030, `UPDATE^x` 1,048, `SPLIT` 1,586,
  `CLAIM` 1,617, `CLAIM^h` 1,627, `CLAIM^x` 1,635. Also `CLAIM^x` as
  `CLAIM` plus 7 bytes of script and 64 of witness.
- **Batch and detach.** `EXIT_2` 1,684 and the 665 vB second exit;
  `EVICT_SUBTREE_4` 2,638 (13 leaves) and `EVICT_SUBTREE_6` 8,057 (51
  leaves). `DETACH_8` 780 vB, with the detached exit at 762 and payback
  at the fourth exit (3 × 258 < 780 < 4 × 258).
- **Fee-from-payout and tower.** The fee-from-payout exit at 921 vB
  (550 WU), saving 99 vB. The tower exit at 1,046 vB and "107 bytes of
  script over the exact exit": I compiled both. The exact exit is 2,097
  bytes and `EXIT^t_1` 2,204, so 107 holds; it is 103 over the `≤` exit.
- **Serialised column.** Table 5 matches `weights.md` (+10, +11, +43,
  +45, +10 vB).
- **Leaf and node format.** 116 bytes; `enc64` as the BIP-441 encoding
  of `s + 2^64`; tagged hashes with distinct voucher, hash-lock and exit
  tags. All match spec 2.1, 5.1 to 5.3.
- **`REWRITE_h` rule 3.** The exemption and its `SEQ_FINAL` exclusion,
  as §4.3 describes them, match spec 7.9 and the tests (and are the root
  of finding 1).
- **Voucher binding.** `tree_id` binding, its inheritance across
  `DETACH_h` and the single-lineage argument match spec 6.2 and 10.3.
- **Hash-locked vouchers.** The five rules of §5.4 match spec 9.6.2
  rules 1 to 5, and the order-of-settlement argument of §5.5 matches
  spec 10.3 and `design/receive.md`.
- **Hub budget.** 72 + 3 + 144 + 2 = 221 ("about 220"), and 71 × 25 =
  1,775 channel leaves. The 1,681 vB force close matches spec C.5.4's
  table (1,020 + 153 + 152 + 204 + 152).
- **Lightning baseline.** 530 = 240 + 152 + 138; 684 = 154 + 530; 308 =
  2 × 154; 197 = 43 + 154; 573 = 43 + 530.
- **Ark baseline.** 150D + 111 at D = 8, 12, 16 (1,311, 1,911, 2,511);
  radix 4 at 240 × 8 + 111 = 2,031; 1,354 and 2,554 with a 43 vB entry.
- **Deployment assumptions.** Table 3 matches spec 4.1 [A-1] to [A-6].
  CSFS (BIP-348) and `OP_CAT` (BIP-347) are tapleaf-0xC0 definitions, as
  stated. MIN's dependence on 0xC0 proposals only, and MID's and CCV's
  dependence on an `OP_TX` that no proposal defines for 0xC0, are
  stated correctly in §1 and §7.
- **Path maintenance.** A member can recompute its path from each
  transition's witness. I walked `EXIT`, `JOIN_h` (the graft's root and
  sum with the slot path), the two steps of `CLAIM` and `SPLIT`,
  `REWRITE_h` (every leaf published), `EVICT_SUBTREE_h` (the slot becomes
  `E_h`) and `DETACH_h`. It holds, with the grafted-subtree exception of
  finding 8 (spec 9.7). A light client can follow the tree: BIP-158
  basic filters include spent prevout scriptPubKeys, so the current
  `TreeSPK` matches the spending block.
- **Check counts.** 1,154 + 466 + 55 + 1,344 = 3,019 checks (the
  abstract's figure, which excludes the 220 channel-leaf and 61
  hypothetical-opcode checks). I re-ran the suites at `e16ce55`: 1,154
  FULL, 466 MID, 55 MIN, 1,344 CCV and 220 channel-leaf checks, no
  failures, matching B.9.

## What a developer would want added

1. A per-operation card (one table): the tapleaf, who signs and with
   what hash type, the witness order or a pointer to the spec section
   and the `txn/` builder, the outputs the script fixes, and what the
   other parties must verify before signing.
2. "Creating and recognising a tree": parameters, `tree_id` derivation,
   the seed leaf, and the recomputation of `m` (finding 4).
3. An implementer's state table per party, with backups and reorg
   rollback (finding 8), and a pointer to the TLV messages in `msg/`.
4. A fee-reserve and break-even paragraph: which operations need an
   external UTXO, and the balance below which each unilateral path does
   not pay for itself at 2, 10 and 50 sat/vB (finding 3).
5. The Lightning-receive flow as a message sequence: the invoice, who
   draws the preimage, the HTLC settle, the voucher, the top-up, the
   retirement and the fallback, with each step's failure mode (findings
   1 and 2).
6. Channel leaves as an implementer meets them: a new channel type
   (LN-Symmetry over `OP_TX` + CSFS, not a BOLT channel), unannounced,
   routed through the operator; what a channel tower holds (C.9.3); the
   `beta_chan` budget (finding 5); and what a splice costs (`UPDATE^x`,
   1,048 vB) against a Lightning splice transaction.
7. Lease policy for an operator: how long, how renewed, what renewal
   costs per member per period, and what a member sees when its lease
   passes (finding 7).
8. Mempool behaviour for a wallet: how to bump an exit (RBF re-sign by
   the owner, or CPFP from change or a P2A anchor), why transitions
   cannot be TRUC, and what to do when a competing transition confirms
   first.
