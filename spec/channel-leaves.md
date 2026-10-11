# Appendix C: Channel Leaves

```
Title:    LayerTree Channel Leaves
Status:   Draft (normative appendix; spec/layertree.md 9.8 summarises it)
Version:  0.5.1
Requires: spec/layertree.md 0.12.1, FULL or MID tier (section C.7)
License:  BSD-3-Clause
```

This appendix specifies **channel leaves**: LayerTree leaves whose `exit_key`
is the output key of a two-party payment channel that exists only off-chain
while the leaf is in the tree, and whose funding output materialises on-chain
only when the leaf `EXIT`s or is evicted.

Section references of the form "7.2" without a prefix are to
`spec/layertree.md`. The key words "MUST", "MUST NOT", "REQUIRED", "SHALL",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY" and "OPTIONAL" are to be
interpreted as in RFC 2119 / RFC 8174 when and only when they appear in all
capitals. Sections and paragraphs marked *(informative)* contain no
requirements.

Assumptions about under-specified external drafts are marked **[C-An]** and
collected in C.11.

## C.1 Requirements

### C.1.1 What a channel needs from a leaf

A channel leaf is an ordinary leaf (5.2) whose fields are given the following
roles. Let `U` be the leaf owner and `V` the channel counterparty (the
operator in the common case; C.6.6 covers `V ≠ operator`).

| Leaf field | Channel role |
|---|---|
| `amount` | the channel capacity `C`; the whole of it, including `V`'s share |
| `exit_key` | the BIP-341 **output key** of the channel funding output: internal key `P_chan = MuSig2(U_chan, V_chan)` tweaked by the funding taptree of C.3.2 |
| `owner_key` | `U`'s tree key: authorises `EXIT` and co-authorises `UPDATE`. Distinct from `U_chan` |
| `evictor_key` | `V_evict`, `V`'s tree key: `V`'s force-close right |
| `evict_after` | the height before which `V` may not force the channel on-chain (C.6.4) |
| `nonce` | leaf identity; enters `chan_id` (C.2.2) |
| `seq` | set to the non-claimable marker of C.6.5 |

Normatively, for a leaf to be a channel leaf:

1. `exit_key` MUST be the taproot output key of C.3.2 for the channel's
   parameters, and MUST NOT be reused across channels or across capacity
   epochs (C.5.2).
2. `amount` MUST equal the channel capacity `C` that the parties' signed
   state commits to. `C` is the sum of both parties' balances plus the value
   of every in-flight HTLC.
3. `owner_key` MUST NOT equal `U_chan`, `V_chan` or `exit_key`, and
   `evictor_key` MUST NOT equal `exit_key`. Tree-level authority and
   channel-level authority are separate powers and SHOULD use separate keys.
4. The tree MUST satisfy C.6.1 (exact owner exit) and the leaf MUST satisfy
   C.6.5 (not voucher-claimable).

### C.1.2 The core problem

The funding output does not exist while the leaf is in the tree. It comes
into existence at output 1 of the transaction that removes the leaf (7.2),
whose txid is not known in advance: it depends on the tree state at the time
of the exit, on the fee inputs, and on whether the removal is an `EXIT_1`, a
step of an `EXIT_K`, or an `EVICT_SUBTREE_h` (7.7) — in which case the output
index is not 1 but "the next unused output", i.e. anywhere in `1..2^h`.

A channel is a pair of parties holding, at all times, transactions that
unilaterally distribute the funding output according to the latest agreed
balance. Those transactions spend an outpoint `txid:k` that is unknown at the
time they must be signed. Hence:

> **Requirement R.** Every transaction of the channel that must exist before
> the funding output does MUST be authorised by a signature that does not
> commit to the prevout of the input it authorises.

### C.1.3 Why classic penalty channels cannot be pre-signed here

*(informative)* In a BOLT-3 channel each commitment transaction spends the
funding outpoint and is authorised by a BIP-340 signature over the BIP-341
signature message for that input. That message contains, unavoidably, the
input's outpoint: with `SIGHASH_ALL` through `sha_prevouts`, and with
`SIGHASH_ANYONECANPAY` through the explicit `outpoint` field. There is no
hash type that omits it. A commitment transaction therefore cannot be
produced before the exit transaction exists, and the exit transaction is
produced by one party alone at a moment of its choosing.

Three fallbacks fail:

* **Sign at exit time.** This makes the channel a 2-of-2 with an online
  requirement at precisely the moment when one party is likely to be absent
  or adversarial: if `V` declines to sign a commitment after the leaf has
  exited, `C` is frozen in the 2-of-2 forever. The leaf's whole purpose —
  that `U` may leave unilaterally — is lost.
* **Cover the outpoint with a covenant instead of a signature.** A `CTV`-style
  template commits to the spending transaction's *outputs* but the
  commitment lives in the *spent* script, so the funding script would have to
  be fixed at the current state and could not be updated. This is a
  one-state channel.
* **Penalty with rebindable signatures.** Even granting requirement R,
  revocation does not survive rebinding. A revoked commitment authorised by
  a prevout-free signature remains attachable to *any* output carrying the
  same script, so revocation would have to be enforced by making every
  commitment's script unique and by punishing per script — and the punishing
  transaction spends an output of the revoked commitment, whose txid is again
  unknown, so the penalty transaction must itself be rebindable. Worse, a
  penalty **watchtower** is indexed by commitment txid: it is handed
  `(txid_prefix, encrypted_blob)` and cannot act without knowing the txid in
  advance. For a channel leaf no commitment txid exists until the leaf exits,
  so penalty watchtowers cannot be provisioned at all.

The conclusion is that a channel leaf requires both rebindable signatures and
a state machine whose response to a stale state is *publishing a newer state*
rather than *punishing a known transaction*.

## C.2 Rebindable commitments with `OP_TX` + `OP_CHECKSIGFROMSTACK`

### C.2.1 Construction

Requirement R is met by emulating `SIGHASH_ANYPREVOUT` in script: the script
assembles the fields of the spending transaction that the signature is meant
to cover with a single `OP_TX` collation, hashes the result, and verifies a
BIP-340 signature over that hash with `OP_CHECKSIGFROMSTACK` (BIP-348). The
prevout is simply not among the selected fields.

Two selectors are defined. Both set `TXSELECT_COLLATE` so that `OP_TX` leaves
exactly one element on the stack.

| Name | Bits | Value |
|---|---|---|
| `SEL_CHAN_UPD` | `COLLATE \| VERSION \| NUM_INPUTS \| INPUT_SEQUENCE \| NUM_OUTPUTS \| OUTPUT_AMOUNT \| OUTPUT_SCRIPT \| LOCKTIME \| INPUTSELECT_CURRENT \| OUTPUTSELECT_ALL` | `0x0FC7` |
| `SEL_CHAN_SET` | `SEL_CHAN_UPD \| INPUT_AMOUNT \| INPUT_SCRIPTPUBKEY` | `0x30FC7` |

`SEL_CHAN_UPD` is the analogue of BIP-118 `SIGHASH_ANYPREVOUTANYSCRIPT`: it
commits to neither the prevout, nor the spent scriptPubKey, nor the spent
amount. `SEL_CHAN_SET` is the analogue of `SIGHASH_ANYPREVOUT`: it commits to
the spent scriptPubKey and amount but still not to the prevout.

Both selectors are constants and MUST be pushed as constants, never computed
from the witness (10.12).

**[C-A1] Collated layout.** With `COLLATE` set, the `OP_TX` draft emits the
selected fields in txid order, with `CompactSize` length prefixes for
variable-size objects and `CompactSize` for "varint or int" fields. For
`SEL_CHAN_UPD` on a transaction with one input and `k` outputs this is
assumed to be, with no separators:

```
le32(nVersion) || cs(num_inputs) || le32(nSequence_cur)
  || cs(num_outputs) || { le64(amount_j) || cs(len(spk_j)) || spk_j }_{j<k}
  || le32(nLockTime)
```

and for `SEL_CHAN_SET` the current input's `le64(amount)` and
`cs(len(spk)) || spk` are inserted directly after `le32(nSequence_cur)`, per
the per-input field order of the `OP_TX` draft. Every field is fixed-width or
length-prefixed, so the encoding is injective and no two transactions with
different committed fields produce the same blob. If the eventual `OP_TX`
specification orders or encodes these fields differently, the scripts below
are unaffected — only the off-chain signer's serialiser changes.

### C.2.2 The signed message and channel context

A raw collation is not, by itself, a safe message: the same blob would verify
under the same key in any channel with the same shape. The signed message
therefore prefixes a 32-byte **context** constant that is baked into the
script:

```
chan_id  = H_chanid( tree_id || owner_key || le32(nonce) || x(P_chan)
                       || le64(C) || le32(epoch) || le32(csv_delay) )
ctx_upd  = H_chanupd( chan_id )
ctx_set  = H_chanset( chan_id )

msg_upd  = SHA256( ctx_upd || OP_TX(SEL_CHAN_UPD) )
msg_set  = SHA256( ctx_set || OP_TX(SEL_CHAN_SET) )
```

with the tags

| Name | Value |
|---|---|
| `TAG_CHAN_ID` | `"LayerTree/chan/id"` |
| `TAG_CHAN_UPD` | `"LayerTree/chan/update"` |
| `TAG_CHAN_SET` | `"LayerTree/chan/settle"` |

`H_chanid`, `H_chanupd`, `H_chanset` are `H_tag` (2.1) with those tags. The
outer hash is a plain `SHA256` rather than a tagged hash because the tag is
already inside `ctx_*`; this saves the 64-byte prefix push in every channel
script. `ctx_*` MUST be a script constant, not a witness element.

Signers MUST include `chan_id` as specified. It binds:

* the **lineage** (`tree_id`, 6.2): a state signed for a channel in one
  tree cannot be replayed in another. `tree_id` is unique per lineage by
  construction, for the reason 7.5 gives for binding vouchers to it. The
  taptree root `m` was not enough: `m` names a rule set, and every tree
  created with the same parameters shares it (6.2), so binding `m`
  separated channels across rule sets rather than across trees. A
  `DETACH_h` (7.10) moves the leaf under a tree whose root is `m_h`, but
  the detached tree inherits `tree_id`, so `chan_id` keeps naming the tree
  the leaf is in and every signed state stays valid;
* the **leaf identity** (`owner_key`, `nonce`): 5.2 requires these to be
  unique per tree;
* the **channel key** and the **capacity**: a state signed for capacity `C`
  is unusable at any other capacity;
* the **epoch**: incremented by every splice (C.5.2), so states of an
  earlier capacity cannot be replayed after a splice;
* the **role**: `ctx_upd` and `ctx_set` are different constants, so an
  update signature can never be accepted where a settlement signature is
  required and vice versa, even though both are verified against `P_chan`.

`chan_id` deliberately does **not** commit `evict_after`, so that a lease
renewal by `UPDATE` (C.6.7) leaves every signed channel state valid.

*(informative)* The 36 bytes of `<ctx> OP_SWAP OP_CAT OP_SHA256` can be
eliminated by instead verifying against a per-role tweaked key
`P_upd = P_chan + H("upd" || chan_id)·G` and feeding the raw collation to
`OP_CHECKSIGFROMSTACK`, which BIP-348 permits (the message is not required to
be 32 bytes). This document keeps the explicit context because it is
auditable from the script alone and does not depend on tweak discipline
inside the MuSig2 session.

### C.2.3 Why `NUM_INPUTS` is committed

`NUM_INPUTS` is committed and every channel transaction has exactly one
input, so the collation fixes `num_inputs = 1`. This closes the classic
`ANYPREVOUT` half-spend: if two outputs carrying the same channel script ever
coexisted, a single transaction could consume both while paying out only one
capacity. Committing `NUM_INPUTS = 1` makes that transaction invalid
regardless of key or context reuse, and is the second line of defence behind
the `chan_id`/`exit_key` freshness rules of C.1.1 and C.5.2.

The price is that channel transactions cannot carry a fee input, so fees MUST
be exogenous (C.5.5). This is the same choice LN-Symmetry makes.

### C.2.4 Should `INPUT_AMOUNT` be committed?

The current input's amount is known in advance — it is `leaf.amount = C` for
the funding output. It is nevertheless committed **only** in `SEL_CHAN_SET`,
not in `SEL_CHAN_UPD`, for the following reason.

An update transaction must be attachable to the funding output *and* to the
update output of any earlier state (C.3.3). Those outputs carry the same
value only if update transactions are exactly zero-fee, which they are
(C.3.3), so in the design as specified an `INPUT_AMOUNT` commitment in
`SEL_CHAN_UPD` would in fact hold. It is still excluded, because:

* any future variant that pays a non-zero fee at one hop of the update chain
  (for example a 240-sat P2A anchor instead of an ephemeral 0-value one)
  gives the funding output and the update outputs different values, and an
  `INPUT_AMOUNT` commitment would make update transactions bind to the
  funding output only — silently breaking the ratchet;
* nothing is lost. The update transaction's outputs are fully committed and
  sum to `C`, so attaching it to an input worth less than `C` is invalid by
  consensus. Attaching it to an input worth more than `C` is valid by
  consensus and burns the difference to fees, but under the zero-value
  ephemeral anchor of [C-A2] it is not standard: a transaction with a dust
  output must pay no fee (Bitcoin Core's ephemeral-dust policy), so an
  update bound to a funding output of `C + 1` is one no default node
  relays, and neither party can repair it
  without the other's signature. The funding output's value is therefore
  not a matter of indifference, which is why 7.9 rule 3 withholds
  `REWRITE_h`'s amount-only exemption from a `SEQ_FINAL` leaf: without it
  the operator alone could raise a channel leaf's capacity by one satoshi
  and strand every pre-signed state at the relay layer
  (`design/audit/protocol.md`, A1).

`SEL_CHAN_SET` does commit `INPUT_AMOUNT` and `INPUT_SCRIPTPUBKEY`. The
scriptPubKey commitment is what pins a settlement transaction to the update
output of its own state: the update output's script embeds the state number
(C.3.3), so `settle_n` cannot be attached to `U_m` for `m ≠ n`, nor directly
to the funding output — which is what stops a party from skipping the
`OP_CHECKSEQUENCEVERIFY` delay.

### C.2.5 txid instability propagates

A channel transaction has exactly one input, so its txid is a function of the
prevout it is bound to. The funding outpoint is unknown; therefore the update
transaction's txid is unknown; therefore the update output's outpoint is
unknown; therefore the settlement transaction's txid is unknown. Rebinding is
not a property of the first transaction only — **every** transaction that must
be signed before the funding output exists inherits it:

| transaction | signed before funding exists? | authorisation |
|---|---|---|
| update `n` | yes | `SEL_CHAN_UPD` signature |
| settlement `n` | yes | `SEL_CHAN_SET` signature |
| HTLC resolution | **no** (C.4.2) | ordinary BIP-341 signature at spend time |
| pre-signed second-stage HTLC (optional) | yes | `SEL_CHAN_SET` signature |

The design of C.4 avoids pre-signed second-stage transactions entirely, which
is possible precisely because there is no penalty mechanism. Implementations
that do want them (to aggregate several HTLC claims into one transaction, or
to impose a delay on a claim) MUST sign them with `SEL_CHAN_SET`; the
scriptPubKey commitment then binds each second-stage transaction to the exact
HTLC output it resolves, since the HTLC output's script embeds the payment
hash and expiry.

## C.3 Channel state machine

### C.3.1 Choice: LN-Symmetry (eltoo), not penalty

Channel leaves MUST use the update/settlement state machine specified below.
The penalty construction MUST NOT be used.

*(informative)* The reasons, in order of weight:

1. **Watchtowers are impossible with penalty** (C.1.3): a penalty tower is
   indexed by the revoked commitment's txid, which does not exist until the
   leaf exits. An update tower is indexed by the funding *scriptPubKey*
   `P2TR(exit_key)`, which is a fixed 34-byte script known at channel open —
   exactly what BIP-158 block filters match on — and it needs only the latest
   two signatures, whatever the state number.
2. **No toxic state.** A channel leaf may sit in the tree for months and be
   force-closed at a moment chosen by the counterparty. Storage of per-state
   revocation secrets over that horizon, with a total-loss penalty for a
   backup restore, is a poor fit; the update machine's state is constant-size
   and idempotent.
3. **Rebinding is the update mechanism.** Requirement R is a cost in the
   penalty model and the actual mechanism in the update model: a later state
   overrides an earlier one *by being attachable to it*.
4. **Symmetric state.** Both parties hold the same update and settlement
   transactions, halving the state and removing the asymmetric-commitment
   bookkeeping that BOLT-3 needs only to support punishment.

### C.3.2 Funding output

The funding output is `P2TR(exit_key)`, with internal key
`P_chan = MuSig2(U_chan, V_chan)` (BIP-327) and a taptree containing the
single leaf `UPD_F`:

```
UPD_F  (tapleaf 0xC2, 81 bytes)        # witness: <upd_sig>
<S+1> OP_CHECKLOCKTIMEVERIFY OP_DROP   # any state n >= 1; forces timestamp range
<SEL_CHAN_UPD> OP_TX                   # upd_sig blob
<ctx_upd> OP_SWAP OP_CAT OP_SHA256     # upd_sig msg
<P_chan> OP_CHECKSIGFROMSTACK          # 1
```

with `S = 500,000,000` and `<S+1> = 0x1DCD6501`. Hence

```
T_fund   = TapLeaf(0xC2, UPD_F)
exit_key = x( lift_x(x(P_chan)) + H_TapTweak( x(P_chan) || T_fund )·G )
```

The key path spends `P_chan` cooperatively and is the ordinary cooperative
close of an already-materialised channel. The script path accepts the update
transaction of any state.

### C.3.3 Update transaction and update output

The **update transaction for state `n`** (`update_n`) is:

```
nVersion   3                   (TRUC)
nLockTime  S + n               (timestamp range; the state number)
input 0    nSequence 0xFFFFFFFD, prevout unknown at signing
output 0   amount C            spk = update output U_n (below)
output 1   amount 0            spk = OP_1 <0x4e73>   (P2A, ephemeral anchor)
witness    <upd_sig_n> <script> <control block>
```

It is authorised by a MuSig2 signature by `P_chan` over `msg_upd`. Total
output value equals `C`, so the transaction pays **zero fee** and is valid
whether it is bound to the funding output (value `C`) or to the update output
of an earlier state (also value `C`). Fees come from a child spending the
anchor (C.5.5).

`U_n` has internal key `P_chan` and a two-leaf taptree:

```
REBIND_n  (tapleaf 0xC2, 81 bytes)     # witness: <upd_sig_m>, m > n
<S+n+1> OP_CHECKLOCKTIMEVERIFY OP_DROP # only a strictly later state
<SEL_CHAN_UPD> OP_TX                   # upd_sig_m blob
<ctx_upd> OP_SWAP OP_CAT OP_SHA256     # upd_sig_m msg
<P_chan> OP_CHECKSIGFROMSTACK          # 1

SETTLE_n  (tapleaf 0xC2, 79 bytes)     # witness: <set_sig_n>
<csv_delay> OP_CHECKSEQUENCEVERIFY OP_DROP
<SEL_CHAN_SET> OP_TX                   # set_sig_n blob
<ctx_set> OP_SWAP OP_CAT OP_SHA256     # set_sig_n msg
<P_chan> OP_CHECKSIGFROMSTACK          # 1
```

The sizes are measured at `csv_delay = 144` (C.12). `SETTLE_n` is 80 bytes
under tapleaf `0xC0`, where 144 is the two-byte `CScriptNum` `9000` rather
than the one-byte BIP-441 number `90`; the other scripts are the same size
in both versions.

The ratchet is exactly the eltoo one:

* `update_m` binds to the funding output for any `m ≥ 1`, and to `U_n` iff
  `S+m ≥ S+n+1`, i.e. iff `m > n`. It can never bind to its own output.
* `settle_n` binds to `U_n` only, because `SEL_CHAN_SET` commits
  `INPUT_SCRIPTPUBKEY` and `spk(U_n)` embeds `n` through `REBIND_n`; and only
  after `csv_delay` relative blocks.
* Publishing a stale state is answered by publishing any later state on top
  of it, which restarts `csv_delay`.

Note that `U_n`'s taptree is a pure function of `(ctx_upd, ctx_set,
csv_delay, n)` and `n` is published in the clear as the update transaction's
`nLockTime`. A party that observes any update transaction on-chain can
therefore reconstruct the script and control block needed to spend its
output without any out-of-band data. Channel leaves have none of the
data-availability burden that `OP_CHECKTEMPLATEVERIFY`-based LN-Symmetry
carries (BIP-442).

### C.3.4 Settlement transaction

```
nVersion   3
nLockTime  0
input 0    nSequence = csv_delay, prevout = U_n (unknown at signing)
output 0   to_owner : amount b_U, P2TR(U_payout)
output 1   to_cp    : amount b_V, P2TR(V_payout)
output 2.. one output per non-trimmed in-flight HTLC (C.4.1)
output last amount = trimmed value (0 when nothing is trimmed), spk = OP_1 <0x4e73>   (P2A, ephemeral anchor)
witness    <set_sig_n> SETTLE_n <control block>
```

with `b_U + b_V + Σ htlc_j + trimmed = C`; the transaction is zero-fee.
Because there is no punishment, `to_owner` and `to_cp` are plain key outputs
with no relative timelock: the `csv_delay` on `U_n` is the entire dispute
window.

**Dust floor.** Every output other than the anchor MUST be at least
`DUST_CHAN`, a channel parameter agreed at opening like `evict_after`
(C.5.1) and, like it, outside `chan_id`. It MUST NOT be below the P2TR dust
threshold under Bitcoin Core's default dust relay fee, 330 sat, and that
value is RECOMMENDED. A balance or HTLC below `DUST_CHAN` MUST be omitted
from `settle_n` and its value added to the anchor output, which therefore
carries the sum of the trimmed amounts and is the 0-value ephemeral output
only when nothing is trimmed. Trimming is decided when the state is signed,
since the output set is committed. BOLT-3 trims into fees, which a zero-fee
transaction cannot do: the settlement's fee is its anchor child's (C.5.5),
and a transaction with a 0-value anchor is relayed only if it pays no fee
and carries no other dust output. A sub-dust balance beside the anchor,
which is what state 1 of every single-funded channel (C.5.1 model (ii),
`b_V = 0`) would otherwise be, is a settlement no default node relays, and
it leaves the capacity stranded at `U_n` for as long as the parties do not
cooperate (`design/audit/channels.md`, B1). The reference `settle_outputs`
and `StateProposal.Validate` in `msg/chan.go` enforce the floor (C.12).

### C.3.5 State encoding and lock-time ranges

State numbers live in `nLockTime` in the **timestamp** range, `S + n` with
`S = 500,000,000`, as in LN-Symmetry. Three lock-time regimes coexist in a
channel leaf and MUST NOT be confused:

| value | range | transaction | rule |
|---|---|---|---|
| `evict_after` | height (`< 500,000,000`, 5.2) | the `EXIT`/`EVICT_SUBTREE` that spends the **tree output** | 7.2 rule 4 |
| `S + n` | timestamp | `update_n`, which spends the **funding or update output** | C.3.3 |
| `cltv_expiry` | height | HTLC timeout sweep, which spends a **settlement output** | C.4.1 |

They never collide because they are lock times of three different
transactions. `OP_CHECKLOCKTIMEVERIFY` fails when the operand and
`nLockTime` are in different ranges (10.6), so pushing `S+n+1` in `REBIND_n`
also *forces* the update transaction into the timestamp range, which in turn
makes it always final: `S + n` seconds is a date in 1985. The state number is
bounded by `2^32 − 1 − S ≈ 3.79·10^9`, which is not a practical limit.

### C.3.6 Signing order

To advance from state `n` to `n+1` the parties MUST exchange partial
signatures in this order:

1. both sign `settle_{n+1}` (`msg_set` under `P_chan`);
2. then both sign `update_{n+1}` (`msg_upd` under `P_chan`);
3. only then may either party treat state `n+1` as current and stop using
   state `n`.

A party that holds `update_{n+1}` but not `settle_{n+1}` can move the channel
to `U_{n+1}`, from which nothing but a cooperative key-path spend can extract
the funds. A party MUST NOT send its partial signature for `update_{n+1}`
before it holds the counterparty's partial signature for `settle_{n+1}`.
Both parties MUST retain `update_n`, `settle_n` and their signatures for the
current `n` until the channel is closed.

## C.4 HTLCs and routing

### C.4.1 HTLC outputs

An HTLC offered by `X` to `Y` appears in the settlement transaction as a
P2TR output with internal key `MuSig2(X_chan, Y_chan)` (cooperative
resolution) and a two-leaf taptree:

```
HTLC_SUCCESS  (73 bytes)                     # witness: <Y_sig> <preimage>
OP_SIZE <32> OP_EQUALVERIFY OP_SHA256        # preimage is 32 bytes
<payment_hash> OP_EQUALVERIFY
<Y_claim> OP_CHECKSIG

HTLC_TIMEOUT  (40 bytes)                     # witness: <X_sig>
<cltv_expiry> OP_CHECKLOCKTIMEVERIFY OP_DROP # height range
<X_claim> OP_CHECKSIG
```

### C.4.2 No second-stage transactions are needed

*(informative)* BOLT-3 needs pre-signed HTLC-success/HTLC-timeout
transactions because the commitment is asymmetric and revocable: the claim
must be forced through an output the counterparty can punish. The update
machine has neither property, so each HTLC output is resolved by a single
ordinary transaction, signed by the claimant **at spend time**, when the
settlement txid is already known. This removes an entire tier of pre-signed,
rebindable state from the protocol; it is the main structural simplification
that C.3.1 buys. C.2.5 gives the rule for implementations that reintroduce
second-stage transactions anyway.

### C.4.3 Forwarding between channel leaves

*(informative)* With the operator as counterparty to both `A` and `B`, a
payment `A → operator → B` is:

1. `A` and the operator advance the `A`-leaf channel from state `n` to `n+1`,
   adding an offered HTLC `(payment_hash, amount + fee, cltv_expiry_A)`;
2. the operator and `B` advance the `B`-leaf channel, adding an offered HTLC
   `(payment_hash, amount, cltv_expiry_B)` with
   `cltv_expiry_A − cltv_expiry_B ≥ cltv_expiry_delta`;
3. `B` releases the preimage, the operator claims off-chain in the `A`-leaf
   channel by advancing to state `n+2`, and both HTLC outputs disappear from
   the respective settlement transactions.

Atomicity is the ordinary HTLC argument and is unchanged: the operator never
pays downstream without holding an upstream HTLC it can claim with the same
preimage. **Nothing in this flow touches the tree.** The tree output is not
spent, no LayerTree transition occurs, no Merkle proof is verified, and the
payment's latency is two channel round trips. A tree of `N` channel leaves is
therefore a payment hub of `N` channels whose on-chain footprint is one UTXO.

The same flow forwards between a channel leaf and an ordinary BOLT channel of
the operator's public Lightning node: the hash lock and the CLTV arithmetic
are identical, so a channel leaf is reachable from the public network without
any bridging construction. PTLCs (MuSig2 adaptor signatures) substitute for
HTLCs without any change to C.2 or C.3: only the settlement output scripts
change.

Compare with vouchers (7.5/9.6): a `CLAIM` voucher is also an off-chain
intra-tree payment, but it extends credit to the issuer until it is redeemed
or settled, and redeeming it is an on-chain transition. A channel-leaf
payment is final on both sides at the moment the states are exchanged and
never touches the chain. Channel leaves are the settlement-grade instrument;
vouchers are the zero-setup one.

*(informative)* The swap of 9.6.2, which pairs a channel-leaf HTLC with a
hash-locked voucher over one payment hash, is exercised end to end by
`tools/test_chan.py` (C.12): the channel is forced on-chain, the HTLC payee's
sweep publishes the preimage, and the voucher redeems second with it. The
three orderings 9.6.2 forbids (a `cltv_expiry_delta` below the budget of
C.4.4, an HTLC left waiting on a preimage that only the voucher's redemption
reveals, and an issuer advancing `seq` before the voucher is redeemed) each
leave the honest party's transaction invalid.

### C.4.4 Deadlines

The number of blocks between an in-flight HTLC's `cltv_expiry` and the moment
its owner must start going on-chain is larger for a channel leaf than for an
ordinary channel, because the funding output must first be *created*:

```
cltv_expiry_delta  >=  G_exit + 1 + beta_chan + 1 + csv_delay + 1 + G_sweep
```

where `G_exit` is the time to get an `EXIT_1` confirmed *including contention
for the tree output* (10.5, C.9.5), then one block for the update plus
`beta_chan` for the stale updates the counterparty gets confirmed ahead of
it (below), one for the settlement, `csv_delay` between them, and `G_sweep`
for the HTLC claim. With `csv_delay = 144`, a conservative `G_exit = 72` and
`beta_chan = 0`, a channel leaf needs `cltv_expiry_delta ≥ ~220` blocks
against the ~40 typical on the public network. Operators and users MUST set `cltv_expiry_delta` for channel
leaves accordingly, and MUST NOT accept forwards that leave less headroom.

`G_exit` is not a constant. It is `Delta(q)` of 10.5 under the contention
assumption [C], `Delta_L · (ceil((beta + q) / kappa) + 1)`, where `q` is
the number of leaves that may need to exit ahead of this one in the same
window, `kappa` the spends of one tree output that confirm per block under
relay policy and `beta` the conflicting spends an adversary gets confirmed
first. At `Delta_L = 1`, `G_exit = 72` therefore covers
`beta + q ≤ 71 · kappa`: about 1,775 channel leaves at `kappa = 25` and
`beta = 0`. A tree whose channel leaves outnumber that, or whose members
must outbid a contending counterparty (`beta > 0`), MUST use a larger
`G_exit`, growing by `Delta_L` for every further `kappa` leaves, and so a
larger `cltv_expiry_delta`, or be sharded or detached (C.9.5, 10.5).

`beta_chan` is the channel's own contention term. An `update_m` binds to
`U_j` for every `j < m` (C.3.3), so a counterparty holding the signed
states `1..k` can publish them one on top of the other, each in its own
block (TRUC admits one unconfirmed ancestor, so the honest `update_n` and
its anchor child cannot be chained onto an unconfirmed stale update), and
the honest update lands only after the last of them; `csv_delay` then runs
from `U_n` as before, so every stale update confirmed ahead costs the payee
exactly one block of the budget. The two blocks of margin in the bound
above absorb two; a third makes the offerer's timeout sweep final before
the payee's claim at the spec bound (C.12). A stale update in the mempool
conflicts with the honest `update_n` bound to the same output and is
replaceable under TRUC's rules, so the delay is an auction the counterparty
must win every block, at about 313 vB (an update and its anchor child) per
block of delay; `beta_chan` is bounded by fee exactly as `beta` is under
[C]. A party SHOULD hold a fee reserve in proportion to the HTLC value it
has in flight (C.5.5), SHOULD replace a pending stale update rather than
wait for it to confirm (C.9.6), and MUST count the `beta_chan` it is
prepared to outbid in its `cltv_expiry_delta`
(`design/audit/channels.md`, B4).

*(informative)* The deadline reasoning above is exercised block by block in
`tools/test_chan.py` (C.12), on a chain model that enforces BIP-65 and BIP-68.
Counting as those rules do, the payee is safe at

```
cltv_expiry_delta  =  G_exit + 1 + csv_delay + G_sweep
```

because the update confirms in the block after the exit, BIP-68 admits the
settlement in the `csv_delay`-th block after the update (so the settlement's
own block is inside `csv_delay`), and the offerer's timeout sweep, whose
`nLockTime` is `cltv_expiry`, is final first in block `cltv_expiry + 1`, so
the payee's sweep may confirm in block `cltv_expiry` itself. The bound above
therefore carries two blocks of margin. With `G_exit = 72`,
`csv_delay = 144` and `G_sweep = 2` the test confirms the payee's sweep at
`t + 219`, against a bound of 221, and at a delta of 218 shows the
offerer's refund becoming final first and the payee's claim failing. Each
stale update the counterparty confirms ahead of the honest one moves the
sweep one block later: at the bound of 221 the margin absorbs two, three
make the refund final first, and the bound with `beta_chan = 3` holds
again.

## C.5 Lifecycle

### C.5.1 Opening

A channel leaf is created by an ordinary `JOIN` (7.3) whose new leaf carries
the channel's `exit_key`. The whole channel is set up *before the leaf
exists*, which is possible only because the signatures are rebindable:

1. the parties agree `C`, the opening balances, `csv_delay`, `evict_after`,
   `epoch = 0`, and the keys of C.1.1; the operator allocates `nonce` (dense)
   or the derived position is computed (sparse);
2. they compute `chan_id`, `ctx_upd`, `ctx_set`, `UPD_F`, and hence
   `exit_key`;
3. they exchange MuSig2 signatures for `settle_1` then `update_1` (C.3.6);
4. only then do they sign their inputs to the `JOIN` transaction. A party
   MUST NOT sign a `JOIN` input funding a channel leaf before it holds both
   signatures for state 1; otherwise a leaf could exist whose `exit_key` no
   one can spend unilaterally.

The operator MAY fund a channel leaf alone with `JOIN_0`, or graft a whole
cohort of channel leaves in one `JOIN_h`. Step 3's signatures are per
channel, so a 256-leaf graft still costs one on-chain transaction (11).

**Where does the operator's balance live?** The leaf's `amount` is the whole
capacity, but the tree names only `owner_key`. Two funding models:

| | (i) dual-funded at `JOIN` | (ii) single-funded by the user |
|---|---|---|
| `C` | `b_U + b_V` | `b_U`, with `b_V = 0` |
| who supplies the funds | user and operator each add an input to the `JOIN` | user only |
| inbound liquidity for the user | immediate | none until the user has spent |
| operator capital | locked per channel for the life of the leaf, exactly as in a BOLT channel | none |
| what the operator's share is protected by | `exit_key` (the user cannot exit to itself), exact payout (C.6.1), no `CLAIM` (C.6.5) | n/a |

Model (ii) is the default and is the honest one for a hub that does not want
to price liquidity. Model (i) is what makes a channel leaf useful as a
*received-payments* endpoint, and its capital cost is not reduced by
LayerTree: only the on-chain cost of opening and closing is (C.8).

A third, intermediate model is available and has no analogue in BOLT
channels: **just-in-time liquidity by splice**. The operator adds its share
later with an `UPDATE` that raises `leaf.amount` from an operator-funded
input (C.5.2), without closing the channel and without any relative timelock.

### C.5.2 Splicing

An `UPDATE` (7.4) co-signed by `owner_key` and `OPERATOR_KEY` — which, when
the counterparty is the operator, is exactly the channel's two parties —
replaces the leaf with one of a different `amount` and `exit_key`. That is a
splice, executed in a single tree transition with no channel downtime, no
force-close, and no relative timelock.

Normatively, for a splice from `(C, epoch)` to `(C', epoch+1)`:

1. the parties MUST derive a new `chan_id` (new `C'` and `epoch`), hence new
   `ctx_*`, hence a new `exit_key`; `new_leaf.exit_key` MUST differ from
   `old_leaf.exit_key`;
2. they MUST exchange `settle_1'` and `update_1'` signatures for the new
   channel at capacity `C'` **before** either signs the `UPDATE`;
3. the state number MAY restart at 1 for the new epoch, since no state of the
   old epoch verifies under `ctx_upd'`.

In a tree created with `UPDATE^x` (7.4 rule 5) the splice additionally needs
a signature over the transition transaction by `old_leaf.exit_key`, the
funding output key of the old epoch, which the two channel parties produce
with MuSig2 under `P_chan` (taptweaked as in C.3.2) in the same session in
which they exchange the signatures of rule 2.

Splices are atomic in a sense on-chain splicing is not: only one funding
output can ever exist, so after the `UPDATE` confirms the *old* funding output
can never come into being and the old states are unreachable — there is no
period in which two versions of the channel are simultaneously live. Rule 1
is what makes this true; without it, an old state signed for a smaller `C`
would remain valid against a spliced-in funding output and publishing it
would burn the added value to fees.

### C.5.3 Cooperative close

Three forms, in increasing cost:

* **Off-chain**: the parties agree a final state in which one side holds
  everything. The leaf remains a channel leaf; nothing happens on-chain.
  Suitable for a channel that is being emptied but not retired.
* **`UPDATE` to plain leaves**: one `UPDATE` replaces the channel leaf with a
  plain leaf of `b_U` owned by the user, and the operator's `b_V` is taken as
  a decrease of the tree total (7.4 rule 3) into its own output, or added to
  an operator leaf in a following transition. One tree transition
  (≈ 840 vB at `D = 16` dense), and the user is left with a leaf that exits
  in one transaction.
* **On-chain cooperative close**: only after the funding output has already
  materialised; the key path of `P_chan` spends it in ~110 vB.

### C.5.4 Unilateral close

Either an owner `EXIT_1` (7.2 rule 3, but see C.6.1) or an eviction by the
counterparty (7.2 rule 4, `EVICT_SUBTREE_h` for a cohort). Either way the
funding output appears, at an index the counterparty does not know in
advance. **The counterparty MUST watch for a new output with scriptPubKey
`P2TR(exit_key)`, not for a particular outpoint.** Both parties, or their
watchtowers, then:

1. broadcast `update_n` for the latest `n` bound to the funding outpoint,
   with a child spending its anchor for fees;
2. if the counterparty publishes a stale `update_j`, answer by binding
   `update_n` to `U_j` (`n > j`); the `csv_delay` restarts;
3. after `csv_delay` confirmations of the surviving update output, broadcast
   `settle_n` with a fee child;
4. sweep HTLC outputs as they resolve.

Sizes and timing, at `D = 16` dense, `csv_delay = 144`, the reference tree
taptree, and no HTLCs in flight:

| step | vbytes | earliest |
|---|---|---|
| `EXIT_1` (owner or evictor), incl. fee input and change | ≈ 1,020 | `t` |
| `update_n` bound to funding (1-in, 2-out, zero fee) | 153 | `t+1` |
| anchor child for `update_n` | 152 | `t+1` |
| `settle_n` (2 payouts + anchor, zero fee) | 204 | `t+1+csv` |
| anchor child for `settle_n` | 152 | `t+1+csv` |
| **total, no HTLCs** | **≈ 1,681** | **≈ 146 blocks** |
| `update_n` bound to an earlier update output (contested) | 161 | per contest |
| `settle_n` with `h` HTLC outputs | `204 + 43h` | |
| HTLC-success sweep | 155 | after settlement |
| HTLC-timeout sweep | 138 | after `cltv_expiry` |

The channel rows are measured by `tools/test_chan.py` (C.12). The HTLC sweeps
spend a two-leaf output, so their control block is 65 bytes; version 0.2 of
this table counted a 33-byte one and gave 146 and 130 vB.

Dominated by the `EXIT`: the channel machinery itself is ≈ 660 vB, but
materialising the funding output costs about 1 kvB because it carries the
Merkle-sum proof. A force-closed channel leaf therefore costs roughly 13× a
BOLT-3 force close (~130 vB), and the difference is exactly the price of
never having had the funding output on-chain in the first place.

*(informative)* The update transaction cannot be packaged with the `EXIT`
transaction: TRUC (BIP-431) forbids a v3 transaction from spending an
unconfirmed non-v3 parent, and the `EXIT` is an ordinary v2 transition. The
update chain therefore starts one confirmation after the exit. This is the
reason `G_exit` in C.4.4 is measured to *confirmation*, not to broadcast.

### C.5.5 Fees

Channel transactions are zero-fee and their outputs are fully committed, so
neither party can raise a fee by shaving an output, and `NUM_INPUTS = 1`
forbids attaching a fee input. Fees MUST be paid by a child transaction
spending the P2A anchor. Consequently **both parties MUST hold a confirmed
on-chain UTXO** to close a channel leaf unilaterally; a user with no on-chain
coins can exit the leaf (endogenous fees are available for the `EXIT` in
principle — but see C.6.1, which forbids them for channel leaves) and cannot
drive the update chain. Wallets SHOULD maintain a fee reserve as a condition
of opening a channel leaf, and the reserve SHOULD grow with the HTLC value
the party has in flight: a counterparty can spend about 313 vB per block to
delay the settlement with stale updates (C.4.4, `beta_chan`), and the
honest party's answer is to outbid each one. The anchor carries the trimmed
value of C.3.4, 0 when nothing was trimmed; the child spends it either way.

*(informative)* An alternative that avoids the 0-value ephemeral anchor
[C-A2] is a 240-sat P2A on each update transaction, with the update output
value descending by 240 sat per state. That also enforces the state ordering
by value, but caps the number of states at `C/240` and leaks the state count;
it is not recommended.

### C.5.6 Eviction with HTLCs in flight

Eviction pays `leaf.amount` exactly to `P2TR(exit_key)` (7.2 rule 4), so
in-flight HTLCs are not lost: they are carried by the committed settlement
outputs and resolve on-chain under their own scripts. What eviction consumes
is *time*: the clock of C.4.4 starts when the evictor chooses, not when the
HTLC's owner chooses. The rules are:

* a party MUST NOT accept a new HTLC whose `cltv_expiry` leaves less than the
  budget of C.4.4;
* a party with an in-flight HTLC approaching that bound MUST force-close
  (exit or evict) rather than wait. The bound is a different one for each
  side of the HTLC:
  * the *payee's deadline*: the payee of an HTLC whose preimage it holds
    MUST start its force-close no later than the budget of C.4.4 before
    `cltv_expiry`, so that its success sweep confirms before the
    offerer's timeout sweep is final;
  * the *offerer's deadline*: the offerer of an HTLC that the payee has
    neither fulfilled nor failed MUST start its force-close no later than
    `G_exit + 1 + csv_delay + 1` blocks before `cltv_expiry`, so that the
    settlement has confirmed when the HTLC expires and its timeout sweep
    can confirm in the block after. Started later, the offerer may learn
    the preimage from the payee's sweep up to a whole budget after
    `cltv_expiry`, and the upstream HTLC it forwarded this one for would
    need a `cltv_expiry_delta` of twice the budget to stay claimable;
* an operator SHOULD NOT evict a channel leaf while HTLCs are in flight in
  that channel, and SHOULD instead fail them back first;
* `EVICT_SUBTREE_h` sweeps a whole cohort at once and therefore starts the
  clock for many channels simultaneously; operators MUST NOT sweep a cohort
  containing channel leaves with HTLCs in flight.

## C.6 Interaction with LayerTree rules

### C.6.1 Exact payout is required — the fee-deduction option MUST NOT be used

7.2 rule 3 lets an owner exit pay *less than* `leaf.amount` to
`P2TR(exit_key)`, the difference being available as fee or to other outputs.
**For a channel leaf the owner MUST NOT use this option: output 1's amount
MUST equal `leaf.amount` exactly.**

This is not merely a matter of under-funding the channel. If the funding
output carries `C' < C`, then `update_n` — whose outputs sum to `C` — is
invalid against it, and the channel can be spent only through the 2-of-2 key
path. The owner has thereby diverted `C − C'` to itself and left the
remainder hostage to a cooperative spend. When `C − C'` exceeds the owner's
own channel balance, the fee-deduction option is a **theft vector against the
counterparty's channel balance**, and in every case it is a griefing vector.

Script cannot distinguish a channel leaf, so this is a rule on participants
and on tree selection:

* a tree that hosts channel leaves SHOULD be created with an `EXIT_1` variant
  that requires an exact payout for owner exits as well as evictions — the
  behaviour the MID and MIN tiers already have (4.5). The variant changes
  `m`, so a prospective counterparty can verify from the tree identifier
  alone that the hazard is absent;
* failing that, a counterparty accepting a channel leaf in a lenient tree
  MUST treat its whole channel balance as trusted to the owner, and SHOULD
  therefore only single-fund (model (ii) of C.5.1) with `b_V = 0` and refuse
  to route into such a leaf.

C.5.5 already requires both parties to hold an on-chain fee reserve, so
requiring exogenous fees for the exit imposes no new burden.

Detaching preserves this. A `DETACH_h` (7.10) moves a cohort into a tree
of depth `h` whose script set is the parent's option set compiled at that
depth (7.10 rule 3), so a channel leaf in a detached cohort sits under the
same `EXIT_K^=` and the same `SEQ_FINAL` rule (C.6.5) as before, with the
same leaf bytes and `chan_id`; the counterparty's checks of C.9.7 hold in
the child because they held in the parent.

*(informative)* An in-band fix was considered and rejected: committing
`OUTPUT_SCRIPT` over all outputs but `OUTPUT_AMOUNT` over only a
`TXSELECT_OUTPUTSELECT_RANGE` prefix, letting the owner's own settlement
output absorb any shortfall. An uncommitted output amount can be lowered to
zero by any party that relays the transaction, and the difference taken as
fee; the cure is worse than the disease.

### C.6.2 `owner_key` versus `exit_key`

`owner_key` is the user's *tree* authority: it authorises `EXIT`, co-signs
`UPDATE`, and signs vouchers. `exit_key` is the *channel* authority. They are
deliberately different fields (5.2) and MUST be different keys for a channel
leaf: `owner_key` is a hot key that must be online to exit, `exit_key` is a
2-of-2 that must never be single-party-spendable. In a tree whose owner
exits pay exactly (`EXIT^=` of 7.2 rule 6, as in the MID, MIN and CCV
tiers), a compromise of `owner_key` costs the user an unwanted
force-close. In a lenient tree it costs the whole capacity: 7.2 rule 3
lets an owner exit pay any amount down to zero to `P2TR(exit_key)`, the
script accepts a zero payout, and the rest of the leaf goes wherever the
holder of the stolen key sends it, so `owner_key` there controls the
counterparty's balance as well as the user's (C.6.1). A tree that hosts
channel leaves SHOULD therefore use `EXIT^=`. A compromise of `U_chan`
costs at most the user's channel balance, and only with the
counterparty's cooperation.

### C.6.3 `evictor_key`

`evictor_key` MUST be `V_evict`, the counterparty's tree key, and MUST NOT be
`NUMS`: a channel in which the counterparty has no force-close right is a
channel in which the counterparty's balance is at the owner's mercy. Where
the counterparty is the operator this coincides with 9.4's recommendation
that cohort members set `evictor_key = OPERATOR_KEY`, so channel leaves fit
cohorts and `EVICT_SUBTREE_h` unchanged.

### C.6.4 `evict_after` is a deferral, not a lease — and it has teeth

The natural reading of `evict_after` is "the channel's minimum lifetime": the
counterparty cannot force the channel on-chain before that height. That
reading is correct, and it has a consequence that MUST be respected:

> While `evict_after` is in the future, the counterparty has **no** unilateral
> path to the channel funds at all. It cannot enforce an HTLC on-chain, in
> either direction, before `evict_after`.

The owner can always `EXIT`; the counterparty can only evict after the lease.
An HTLC whose `cltv_expiry` falls before `evict_after + budget` (C.4.4) is
therefore unenforceable by the counterparty, and an uncooperative owner can
simply refuse to resolve it and claim the timeout later. Routing HTLC
expiries are days, leases are months, so in practice:

* a channel leaf that forwards or receives HTLCs MUST have `evict_after` at
  or below the current block height, making the counterparty's force-close
  right unconditional as it is in any ordinary channel. 5.2 permits this;
  `evict_after = 0` with an eviction transaction of `nLockTime = 0` satisfies
  7.2 rule 4 and 10.6;
* a channel leaf with `evict_after` in the future MUST NOT carry HTLCs
  expiring before `evict_after` plus the budget of C.4.4. Such a leaf is
  usable for balance-only updates (direct payments between the two parties)
  and is a genuine "the operator cannot kick me out for `k` months"
  guarantee, at the cost of not being routable.

The user loses nothing by the first option: eviction pays `C` in full to the
funding output, so it costs the user only the off-chain position and the fee
of its own update chain, and it costs the operator an on-chain fee and the
loss of a customer.

The same reading bounds the tower-delegable exit of 7.2 rule 7. In a tree
created with `EXIT_K^t` the owner's exit authorisation is a bearer right to
publish the leaf's exact-payout exit, so the owner of a channel leaf whose
`evict_after` is in the future MUST NOT give it to the counterparty: the
counterparty could then force the funding output on-chain before the lease
ends, which is exactly what `evict_after` denies it, and could do so at
any later root since the authorisation names no transaction. For a
routing leaf with `evict_after = 0` the counterparty already evicts at
will, so handing it the authorisation grants nothing new (an eviction and
an owner exit pay the same output). The owner SHOULD give the
authorisation only to the tower that holds its latest state (C.9.3), and
MUST void it by changing the leaf (an `UPDATE`) if it wants to stay after
an exit built on it has been published, as 7.2 rule 7 requires.

### C.6.5 `seq`: channel leaves MUST NOT be voucher-claimable

A `CLAIM` (7.5) against a leaf is authorised by a signature of
`source_leaf.owner_key` alone and *reduces the source leaf's amount*. Against
a channel leaf this is a theft vector with no cure at the channel level: the
owner can issue a voucher for the counterparty's channel balance, and the
redeemed leaf's funding output can then never fund the channel (C.6.1
applies again).

A channel leaf MUST therefore be made non-claimable. The `CLAIM` script
computes `seq + 1` and fails unless the result still fits in four bytes, so
this requires no protocol change:

| tier | required `seq` | why `CLAIM` fails |
|---|---|---|
| FULL | `0xFFFFFFFF` | `4294967295 + 1` is 5 bytes under BIP-441 unsigned numerics |
| MID | `0x7FFFFFFF` | `2147483647 + 1` is 5 bytes as a `CScriptNum` |

Setting `seq` this way is consistent with 5.2's "`seq` MUST NOT wrap", and
it is also what keeps the owner's signature on every `REWRITE_h` change to
the leaf, including an amount increase (7.9 rule 3, C.2.4).
Alternatively the tree's taptree may simply omit `CLAIM`, which is visible in
`m`; a counterparty MUST verify one of the two before accepting a leaf as a
channel leaf. The `seq` marker is preferred because it is per leaf and leaves
vouchers available to the tree's plain leaves. See C.10 for the
recommendation that the base spec state this explicitly rather than leave it
as an emergent property of the `OP_1ADD`/`OP_SIZE` check.

### C.6.6 Counterparties other than the operator

A leaf may be a channel between two *users*, with `evictor_key` the second
user's key. Two consequences:

* the operator has no eviction right over the leaf, so such a leaf blocks
  `EVICT_SUBTREE_h` for its subtree (7.7). Operators SHOULD place user-to-user
  channel leaves outside cohort subtrees;
* `UPDATE` requires `owner_key` and `OPERATOR_KEY` — **not** the
  counterparty's key. The owner and the operator can therefore, together,
  splice the leaf down and strand the counterparty's channel balance. A leaf
  in a tree whose update transition is plain `UPDATE` is consequently only
  as safe as the operator's promise not to co-sign such an `UPDATE`.

  The exit-consent variant `UPDATE^x` (7.4 rule 5) closes this gap: it also
  requires a signature by `old_leaf.exit_key`, which for a channel leaf is
  the channel's funding output key, so producing it takes both parties (a
  MuSig2 signature under `P_chan`, taptweaked as in C.3.2). A tree that hosts
  user-to-user channel leaves SHOULD be created with `UPDATE^x`. Because the
  variant changes the scripts and therefore `m`, a counterparty MUST verify
  from `m` that the tree's update transition is `UPDATE^x` before it accepts
  a user-to-user channel leaf; if it is not, the residual trust described
  above stands and the counterparty MUST decide whether the operator's
  promise is acceptable.

  The cohort rewrite `REWRITE_h` (7.9) is an update transition too: rule 3
  asks only for the owner's and the operator's signatures, so a plain
  `REWRITE_h` beside `UPDATE^x` splices the leaf down exactly as plain
  `UPDATE` would. The counterparty MUST therefore also verify from `m`
  that the taptree carries no plain `REWRITE_h`, only `REWRITE_h^x`
  (7.9 rule 7) or no rewrite at all.

### C.6.7 Cohorts and lease renewal

Because `chan_id` (C.2.2) excludes `evict_after`, an `UPDATE` that renews the
lease leaves every signed channel state valid and requires no channel-level
action beyond both parties co-signing the transition. Renewal and splicing
are the same transition with different fields; only splicing (which changes
`C`) forces a new epoch and a re-signing of state.

## C.7 Tier analysis

| tier | `OP_TX` | CSFS | channel leaves |
|---|---|---|---|
| FULL | yes (`0xC2`) | yes | **yes** — as specified here |
| MID | yes (`0xC0`, **[A-5]**) | yes | **yes** — identical scripts; only `OP_CAT`, `OP_SHA256`, `OP_TX`, `OP_CHECKSIGFROMSTACK`, `OP_CHECKLOCKTIMEVERIFY`, `OP_CHECKSEQUENCEVERIFY` are used, all of which MID has |
| MIN | no | no | **no** |
| CCV (4.6) | yes (amounts) | not assumed by the tree's scripts | **yes, hosted** — the channel scripts are FULL or MID scripts in their own outputs, so they need `OP_TX` and `OP_CHECKSIGFROMSTACK` wherever they run; the CCV tree itself only pays the leaf out exactly (C.6.1 holds by construction); it may carry `CLAIM` and `CLAIM^h` as tree-creation parameters (4.6), so C.6.5 applies as in FULL, with `SEQ_FINAL` `0xFFFFFFFF` under `0xC2` numerics and `0x7FFFFFFF` under `0xC0`, or a taptree that omits both; the other rules of C.6 apply as in FULL |

The channel scripts of C.3 use no BIP-441 numerics, no splice opcode beyond
`OP_CAT`, and no EC opcode, so they are the same token lists in the FULL and
MID tiers. The tapleaf version differs (`0xC2` / `0xC0`), and so does the
encoding of a number whose minimal form differs between BIP-441 and
`CScriptNum`: `csv_delay = 144` is one byte in `SETTLE_n` under `0xC2` and two
under `0xC0` (C.3.3). The state operands `S + n + 1` are four bytes in both.

Under `0xC0` every stack element is limited to 520 bytes, and that includes
the `OP_TX` collation and `ctx || collation` after `OP_CAT`. A settlement
collation is `70 + 43k` bytes for `k` P2TR outputs beside the anchor (`156 +
43h` with both balances present and `h` HTLC outputs; a trimmed or zero
balance is an omitted output, C.3.4), so a MID channel can carry at most
seven HTLC outputs beside two balances, or eight beside one, in one state. A MID implementation MUST NOT sign a state whose settlement
collation exceeds 488 bytes: its `SETTLE_n` could never succeed, and the
state's funds would be recoverable only by the cooperative key path. FULL has
no such limit. The tier of the
channel scripts is independent of the tier of the tree that hosts the leaf —
they are different outputs — but a MID tree is the natural floor, since a MIN
tree has no `CLAIM` to defend against (C.6.5) and already requires exact
payouts (C.6.1).

**MIN has neither `OP_TX` nor `OP_CHECKSIGFROMSTACK`, so requirement R cannot
be met and channel leaves MUST NOT be used in a MIN tier deployment.** MIN's
constructive introspection (4.4) reconstructs the BIP-341 signature message,
which necessarily contains the prevout, so it cannot be turned into a
rebindable signature check. A MIN tree carries plain leaves only; a channel
can still be *opened after* an exit, by paying the exit's payout into an
ordinary funding transaction, at the cost of one extra on-chain transaction
and of both parties being online at exit time. A MIN "pre-channel" leaf whose
`exit_key` is a bare 2-of-2 is unsafe and MUST NOT be used unless the funding
taptree also contains a unilateral recovery path such as
`<T> OP_CHECKLOCKTIMEVERIFY OP_DROP <U_chan> OP_CHECKSIG`.

## C.8 Comparison with other off-chain channel hosts

*(informative)*

| | LayerTree channel leaf | Ark VTXO / "Ark channel" | Channel factory (N-party) |
|---|---|---|---|
| Materialise the funding output | **1 transaction**, ≈ 1 kvB, constant in `N` | unroll the VTXO branch: `O(log N)` transactions | publish the factory tree: `O(log N)` transactions |
| Interactive signing to create the host | none — the covenant enforces the root | all round participants sign the tree | all `N` participants sign, and re-sign for every membership change |
| One unresponsive member | affects nobody; evict after `evict_after` | round expiry forces the whole tree on-chain | blocks every factory-level update |
| Host expiry | none; per-leaf lease, renewable by `UPDATE` | per round; VTXOs must be refreshed | per factory |
| Channel lifetime | unbounded, survives lease renewal | bounded by the round; the channel must be re-created each refresh | bounded by the factory |
| Resizing a channel | `UPDATE`: one transition, no downtime, no timelock | new round | factory-level re-signing by all `N` |
| Who must be online to close | the two channel parties | the two parties, plus the tree must be unrolled | the two parties, plus the factory must be published |

Two things change the economics relative to a factory. First, the *exit is
constant size and non-interactive*: a factory's value is that `N` channels
share one output, but its cost is that every membership change is an
`N`-party signing round and every unilateral exit publishes a tree; LayerTree
keeps the shared output and pays neither. Second, the *channel graph is a
star*, not a mesh: every channel leaf is a channel with the operator, so
there is no `N`-party coordination at any layer.

What LayerTree does **not** change is liquidity. The operator's share of a
dual-funded channel leaf is locked in that leaf exactly as it would be in an
on-chain channel: `N` channels of capacity `c` still immobilise `N·c` of
operator capital, and the tree output's amount includes all of it. LayerTree
compresses the *transaction* cost of channel lifecycle events (open, splice,
close, re-open) to near zero and the *fee* cost of a force close to one
constant-size exit; it does nothing about the capital cost. Claims that a
shared UTXO makes liquidity cheaper are, here, false: the only genuine
liquidity gain is operational — model (i)/(iii) of C.5.1 let the operator
move capital between leaves with a single `UPDATE` instead of a close and a
re-open, so the same capital can be recycled far more often.

The other honest cost is C.9.5: `N` channels hosted by one UTXO close through
one UTXO.

## C.9 Security considerations

### C.9.1 Rebindable-signature replay

A `SEL_CHAN_UPD` signature commits to no prevout, no input script and no
input amount. Its entire binding to a particular channel is `ctx_upd`, so:

* `chan_id` MUST include `tree_id`, `owner_key`, `nonce`, `x(P_chan)`, `C`,
  `epoch` and `csv_delay` as specified in C.2.2; `tree_id` rather than `m`,
  because two trees can share `m` (6.2) and a detached tree keeps `tree_id`;
* `P_chan` MUST NOT be reused across channels, and `exit_key` MUST NOT be
  reused across epochs (C.5.2). Reuse plus a reorganisation that briefly
  creates two funding outputs with the same script would otherwise expose the
  half-spend of C.2.3, which `NUM_INPUTS = 1` blocks but which should not be
  relied on alone;
* `ctx_upd ≠ ctx_set` prevents the cross-role replay that would otherwise
  exist, both messages being verified under the same `P_chan`.

### C.9.2 Data availability

Both parties MUST retain `update_n`, `settle_n` and their signatures for the
current `n`. A party that loses them cannot answer a stale state and is at
the mercy of whatever the counterparty publishes — this is the update
machine's one-sided failure mode, in exchange for having no toxic state.
Backups are per channel and constant-size (two signatures, the balances and
`n`); there is nothing to accumulate.

No *script* data must be retained: C.3.3 shows that the taptree of any
published update output is a pure function of `(ctx_upd, ctx_set, csv_delay,
n)` and that `n` is published in `nLockTime`.

### C.9.3 Watchtowers

A channel-leaf watchtower is given `(P2TR(exit_key), update_n, settle_n,
signatures, an anchor-spending fee source)`. It matches the *scriptPubKey*,
so it does not need to know the outpoint, the exit transaction, or anything
about the tree; BIP-158 filters match scriptPubKeys, so a light tower works.
It is updated with one constant-size message per state and needs to keep only
the latest. It cannot steal: the transactions it holds pay the same outputs
whoever broadcasts them. A tower SHOULD also be given a fee policy and a
funded UTXO, since C.5.5 makes anchor children mandatory.

In a tree created with `EXIT_K^t` (7.2 rule 7) the same tower MAY also
hold the leaf's exit authorisation, the owner's signature over
`H_exit(tree_id || leaf)`, together with the leaf, its sibling path and
the tree's `m`. The tower can then start a unilateral close with the owner
offline, not only finish one: it builds the exact-payout exit from its
funded UTXO, rebuilds it against the new root if a competing spend
confirms first (9.7), and follows with `update_n` and `settle_n` on the
funding output the exit creates. The authorisation is a bearer exit
right (7.2 rule 7), so it SHOULD go to this tower and nobody else, and
never to the counterparty of a leased leaf (C.6.4); it is void after a
splice or lease renewal (`UPDATE` changes the leaf), so the owner hands
the tower a fresh one with each new `(update_n, settle_n)` that follows
one.

### C.9.4 Eviction griefing

With `evict_after` at or below the tip (C.6.4) the counterparty may force any
channel leaf on-chain at any time. It cannot steal — the payout is exact — but
it imposes on the owner the ≈ 660 vB of update chain, the `csv_delay` wait,
and the loss of the off-chain position. The costs to the evictor are its own
exit fee, its own locked liquidity and its reputation. This is the same
exposure as an ordinary channel counterparty's ability to force-close, with
the addition that an operator can evict *many* leaves at once with
`EVICT_SUBTREE_h` at ≈ 158–203 vB per leaf (11), which makes mass griefing
unusually cheap for the operator. Users who want a hard guarantee buy it with
a future `evict_after` and give up routing (C.6.4).

### C.9.5 Mass exit serialises through one UTXO

Every removal from the tree spends the tree output and recreates it, so
unilateral exits form a chain of spends of a single UTXO, and an exit's
latency is `Delta(q)` under the contention assumption [C] of 10.5:
`Delta_L · (ceil((beta + q) / kappa) + 1)` blocks, with `kappa` the spends
of one output that confirm per block under relay policy (25 under Bitcoin
Core's ancestor and descendant count limits before 31.0, at most 64 under
the cluster limit since, and the lower of what a deployment's relay peers
enforce, 10.5) and `beta` the conflicting spends an adversary gets
confirmed ahead of the honest one. Cooperatively (`beta = 0`, `kappa = 25`,
`Delta_L = 1`) that is about 25 channel force-closes per block, so a tree
hosting 10,000 channel leaves needs about 400 blocks, the better part of
three days, to force-close all of them, during which HTLC deadlines
continue to run (C.4.4). That figure is a cooperative-case drain time, not
a bound: the counterparty of a channel leaf is normally the operator,
which can issue competing spends of the tree output, so the budget of
C.4.4 holds only while the member can outbid them, which is what `beta`
assumes. This is the channel-leaf form of the contention problem of 10.5
and it is the strongest argument for sharding a deployment into several
trees: the exit throughput of a tree, not its depth, bounds how many
channels it should host. Operators SHOULD size trees so that
`beta + leaves ≤ (G_exit / Delta_L − 1) · kappa`, which at `beta = 0` and
`Delta_L = 1` with the budget of C.4.4 is
`leaves / kappa < cltv_expiry_delta − csv_delay − 3 − G_sweep`, and SHOULD
prefer cooperative `EXIT_K` batching whenever users are responsive.

### C.9.6 Fee bumping and pinning

Update and settlement transactions are zero-fee TRUC transactions with a P2A
anchor; each is bumped by a child. TRUC's one-child rule and its 1,000 vB
child limit bound the pinning surface: an adversary can attach a low-fee
child to the anchor, but that child is replaceable under TRUC rules. The P2A
anchor is keyless, so a watchtower or any third party can bump on a party's
behalf. Implementations MUST NOT rely on the update transaction being
package-relayed together with the `EXIT` (C.5.4).

The other pinning surface is the update chain itself. A stale `update_j`
that confirms ahead of the honest `update_n` costs the honest party one
block of its C.4.4 budget (`beta_chan`), and TRUC serialises the rounds, so
a counterparty with `k` old states can buy `k` blocks of delay at about
313 vB each. A stale update in the mempool conflicts with the honest
`update_n` bound to the same output, so an implementation SHOULD replace
it by fee rather than wait for it to confirm and rebind on top of it;
waiting hands the counterparty the block for free.

### C.9.7 Residual trust

The counterparty's channel balance inside a leaf rests on four properties
that are outside the channel protocol and MUST be checked when the leaf is
accepted: exact owner exit (C.6.1), a non-claimable `seq` or a `CLAIM`-free
taptree (C.6.5), `evictor_key` correctly set (C.6.3), and — for user-to-user
leaves only — protection against a hostile `UPDATE` (C.6.6). The first two
are verifiable from `m` and the leaf; the third from the leaf; the fourth is
now verifiable from `m` as well, since it is the presence of the `UPDATE^x`
script of 7.4 rule 5 in the taptree together with the absence of a plain
`REWRITE_h` (C.6.6; `REWRITE_h^x` of 7.9 rule 7 is fine). A tree that uses
plain `UPDATE`, or plain `REWRITE_h` beside `UPDATE^x`, leaves the fourth
property resting on the operator's promise, which is not verifiable at
all.

## C.10 Changes made to `spec/layertree.md` for this appendix

*(informative)* Version 0.6.0 of the base specification adopts items 1, 2,
3, 5, 6, 7 and 8 below (9.8, 5.1/5.2/7.5 `SEQ_FINAL`, 7.2 rule 6 `EXIT_K^=`,
5.2 `evict_after = 0`, 10.5 exit throughput, 8.1 selectors and 5.1 tags,
13.9). Version 0.6.1 adopts item 4 as 7.4 rule 5, the exit-consent variant
`UPDATE^x`; a tree created with plain `UPDATE` still carries the residual
trust of C.6.6. The list is kept for the record.

1. **9.8** should be replaced by a reference to this appendix.
2. **5.2 / 7.5**: state explicitly that a leaf with `seq = 0xFFFFFFFF` (FULL)
   or `0x7FFFFFFF` (MID) can never be the source of a `CLAIM`, and name it as
   the way to mark a leaf non-claimable. It is currently an emergent
   consequence of the `OP_1ADD` / `OP_SIZE` check in 8.6 and should be
   deliberate, tested, and identical across tiers.
3. **7.2 / 4.5**: add an `EXIT_1` variant (a tree-creation parameter) that
   requires an exact payout for owner exits as well as evictions, as MID and
   MIN already do, and note that trees hosting channel leaves should use it
   (C.6.1).
4. **7.4**: add an `UPDATE` variant that additionally requires a signature by
   `old_leaf.exit_key`, protecting any leaf whose `exit_key` is a shared key
   against an owner-plus-operator splice (C.6.6). Adopted as 7.4 rule 5,
   `UPDATE^x`.
5. **5.2**: note that `evict_after = 0` is the correct setting for a routing
   channel leaf and why (C.6.4); the current text's framing of `evict_after`
   as a lease invites the unenforceable-HTLC bug.
6. **10.5 / 11**: quantify exit throughput per tree (C.9.5) and recommend
   sharding by it.
7. **4.1 / 8.1**: register `SEL_CHAN_UPD` and `SEL_CHAN_SET` alongside the
   tree's own selectors, and state `TAG_CHAN_ID`, `TAG_CHAN_UPD`,
   `TAG_CHAN_SET` in 5.1.
8. **13**: note that hash-locked vouchers (13.6) and channel leaves compose —
   a voucher HTLC and a channel-leaf HTLC can share a payment hash, giving
   atomic swaps between the credit instrument and the settlement instrument.

## C.11 Assumptions

* **[C-A1]** The `OP_TX` collated encoding is as laid out in C.2.1. Only the
  off-chain signer's serialiser depends on this; the scripts do not.
* **[C-A2]** TRUC (BIP-431) is active and permits a single 0-value
  ("ephemeral dust") anchor output in a zero-fee transaction that is spent in
  the same package. If only 240-sat P2A outputs are relayable, use the
  descending-value variant of C.5.5 and accept its state cap.
* **[C-A3]** `OP_CHECKSIGFROMSTACK` is available in tapleaf version `0xC2`
  with the varops cost of 4.1 **[A-2]**, and `OP_TX` in `0xC0` for the MID
  tier **[A-5]**.
* **[C-A4]** BIP-327 MuSig2 is used for `P_chan`; nothing in this appendix
  depends on it beyond `P_chan` being a single x-only key that both parties
  must cooperate to sign under. A 2-of-2 `OP_CHECKSIGADD` script leaf would
  work at a cost of ~70 extra witness bytes per channel transaction.
* Sizes assume the reference script set of 6.2, eight tapleaves and so a
  129-byte control block (11.1); each doubling of the set adds 8 vB,
  `D = 16` dense, 64-byte Schnorr signatures, and P2TR payout outputs.

## C.12 Executable reference *(informative)*

Appendix C is implemented and tested alongside the tree scripts. Every
normative script claim above is backed by one of these files.

| file | contents |
|---|---|
| `tools/script_sim.py` | `OP_CHECKSEQUENCEVERIFY` (BIP-112, the script half) and `OP_TX` with `TXSELECT_COLLATE` laid out as [C-A1]; `collate()` is also the off-chain serialiser |
| `tools/layertree_chan.py` | generators for `UPD_F`, `REBIND_n` and `SETTLE_n` with stack comments, `chan_id` / `ctx_upd` / `ctx_set`, `msg_upd` / `msg_set`, the funding and update output keys, the update and settlement templates of C.3.3 and C.3.4, HTLC outputs (the C.4.1 leaves are imported from `tools/layertree_scripts.py`), and the two deadline budgets of C.4.4 |
| `tools/test_chan.py` | the whole state machine on a chain model: 220 checks |
| `script/chan.go` | the Go mirror, byte-exact against the `chan` section of `spec/golden.json` in both tapleaf versions, with `ChanCollate` and the signed messages |
| `msg/chan.go` | TLV messages: `ChanOpen` (with `DUST_CHAN`), `StateProposal` whose `Validate` applies the dust floor of C.3.4 and the `0xC0` collation limit of C.7, `StateSig` with the `SigningRound` order check of C.3.6, `HtlcAdd` with `CheckDeadline` counting the C.4.4 budget from the lease when it is later than the tip (C.6.4), `HtlcFulfill`, `HtlcFail`, `RebindAnnounce` (C.5.4) and `SpliceProposal` (C.5.2) |

The chain model under `tools/test_chan.py` keeps a UTXO set with
confirmation heights, checks each input's control block against the spent
scriptPubKey, runs the tapscript, and enforces value conservation,
`nLockTime` finality and BIP-68. Fee children of the P2A anchors are not
modelled. The test covers, in both tapleaf versions:

* **open**: a channel leaf with `seq = SEQ_FINAL` and `evict_after = 0`
  leaves a FULL tree through `EXIT_1^=` and creates `P2TR(exit_key)` with
  exactly `C`; the `update_n` signed before the exit binds both to that
  output and to the output an eviction 50 blocks later creates at another
  outpoint (requirement R); a funding output short of `C` carries no state
  (C.6.1);
* **uncontested close**: `update_n`, `settle_n` refused one block before
  `csv_delay` and accepted at it, an HTLC-success sweep with the preimage,
  and an HTLC-timeout sweep refused in block `cltv_expiry` and accepted in
  the next;
* **contested close**: a stale `update_j` is answered in the last block of
  its window by `update_n` bound to `U_j`; `settle_j` then fails on `U_j`
  (spent) and on `U_n` (`SEL_CHAN_SET` commits the spent scriptPubKey);
  `update_j` with `j < n` and `update_n` itself fail against `U_n`; and
  `settle_n` waits a full `csv_delay` from `U_n`;
* **negatives**: altered balances, `nSequence < csv_delay`, an update
  signature as a settlement witness and the reverse, each collation signed
  under the other context, states signed for a `chan_id` with another
  `tree_id`, capacity, epoch, nonce, `owner_key` or `csv_delay` (C.9.1), a
  changed `nLockTime`, `nVersion` or output, a height-range `nLockTime`
  (C.3.5), `settle_n` against the funding output, and two funding outputs
  with the same script spent by one transaction (C.2.3);
* **`tree_id` binding**: C.2.2, two trees created without `CLAIM` share `m`
  and differ in `tree_id`; the same channel parameters under each give
  different `chan_id`s and `exit_key`s, the other tree's channel state fails
  against this tree's funding output, this channel's update template signed
  under the other tree's context fails, and the state signed for the leaf's
  own `tree_id` binds;
* **dust floor**: C.3.4 on the single-funded state 1, a 329-sat balance, a
  200-sat HTLC and a sub-dust balance beside a sub-dust HTLC: each is
  trimmed into the anchor, the settlement still pays `C`, and the untrimmed
  split would have carried two dust outputs; `DUST_CHAN` is outside
  `chan_id` and refused below 330;
* **lease and evictor**: C.6.4, a channel leaf with `evict_after` in the
  future cannot be evicted before it (with `nLockTime` at the tip or at the
  lease) and can at it, while the owner exits at any time and `update_1`
  binds in every case; C.6.3, a `NUMS`-evictor channel leaf cannot be
  evicted at all;
* **epochs and renewal**: C.6.7, an `UPDATE` that renews `evict_after`
  leaves `update_n` bindable; C.5.2, after an `UPDATE` to the next epoch's
  `exit_key` the old epoch's `update_n` fails against the new funding output
  and the new epoch's binds;
* **MID numerics**: the 520-byte limit of C.7, seven HTLC outputs accepted
  and eight refused under `0xC0`;
* **deadlines**: C.4.4 and the swap of 9.6.2 as block sequences, as
  described in C.4.3 and C.4.4, and `beta_chan`: two stale updates
  confirmed ahead of the honest one are absorbed by the bound's margin,
  three make the offerer's refund final first, and the bound with
  `beta_chan = 3` holds again.

Measured sizes, `csv_delay = 144`, 64-byte signatures:

| leaf | script B (`0xC2` / `0xC0`) | stack B | control block B |
|---|---|---|---|
| `UPD_F` | 81 / 81 | 64 | 33 |
| `REBIND_n` | 81 / 81 | 64 | 65 |
| `SETTLE_n` | 79 / 80 | 64 | 65 |
| `HTLC_SUCCESS` | 73 / 73 | 96 | 65 |
| `HTLC_TIMEOUT` | 40 / 40 | 64 | 65 |

| transaction | vB |
|---|---|
| `update_n` bound to the funding output | 153 |
| `update_n` bound to `U_j` | 161 |
| `settle_n` with two HTLC outputs | 290 |
| HTLC-success sweep | 155 |
| HTLC-timeout sweep | 138 |

`SETTLE_n` under `0xC0` adds one byte and leaves the vsize rows unchanged.
