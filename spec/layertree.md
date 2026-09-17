# LayerTree: Constant-Size Exit and Eviction for Shared Bitcoin UTXOs

```
Title:    LayerTree
Layer:    Applications (requires consensus changes listed in section 4)
Status:   Draft
Version:  0.1.0
Author:   Olaoluwa Osuntokun
Created:  2026-09-17
License:  BSD-3-Clause
```

## Table of Contents

1. [Abstract](#1-abstract)
2. [Conventions](#2-conventions)
3. [Overview](#3-overview)
4. [Consensus Environment](#4-consensus-environment)
5. [Data Structures](#5-data-structures)
6. [The Tree Output](#6-the-tree-output)
7. [Transitions](#7-transitions)
8. [Reference Scripts](#8-reference-scripts)
9. [Off-Chain Protocol](#9-off-chain-protocol)
10. [Security Considerations](#10-security-considerations)
11. [Cost Analysis](#11-cost-analysis)
12. [Comparison With Related Constructions](#12-comparison-with-related-constructions)
13. [Extensions](#13-extensions)
14. [Test Vectors and Reference Code](#14-test-vectors-and-reference-code)
15. [References](#15-references)

## 1. Abstract

LayerTree is a construction in which a single Bitcoin UTXO (the *tree
output*) holds the pooled balances of many participants, while an off-chain
Merkle-sum tree commits to who owns what. The tree output is a Taproot output
whose internal key commits to the current root of that tree. Every spend of
the tree output is a covenant-enforced *state transition*: the spending
transaction must reproduce a new tree output committing to the correctly
updated root, and must pay out exactly the amounts the transition removes.

The defining property is that any participant can leave, and the operator
can remove any expired participant, with **one transaction whose size does not
depend on the number of participants**. There is no chain of pre-signed
transactions to unroll, no interactive signing round to construct a tree, and
no expiry of the shared UTXO itself. The operator cannot move funds without
the owner's signature, and the sum commitment guarantees the output can
always pay every provable leaf.

The construction requires the Great Script Restoration (BIP-440, BIP-441),
transaction introspection (`OP_TX`), `OP_CHECKSIGFROMSTACK`, and two
elliptic-curve opcodes (`OP_ECSCALARMUL`, `OP_ECPOINTADD`) proposed
alongside them.

## 2. Conventions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be
interpreted as described in RFC 2119 and RFC 8174 when, and only when, they
appear in all capitals.

Sections and paragraphs marked *(informative)* do not contain requirements.

### 2.1 Notation

* `a || b` denotes byte-string concatenation.
* `le64(n)` denotes the 8-byte little-endian encoding of the unsigned integer
  `n`, which MUST be less than 2^64. `le32(n)` is the 4-byte analogue.
* `H_tag(m) = SHA256(SHA256(tag) || SHA256(tag) || m)` is the tagged hash of
  BIP-340. The tag strings used by this document are listed in section 5.1.
* `x(P)` is the 32-byte big-endian x coordinate of the secp256k1 point `P`.
  `lift_x` is as defined in BIP-340. `G` is the generator, `n` the curve
  order.
* `P2TR(k)` is the 34-byte scriptPubKey `OP_1 <32-byte k>`, i.e.
  `0x5120 || k`.
* Stack diagrams are written bottom to top, left to right; the rightmost
  element is the top of the stack. The altstack is written after `|`.
* Script numbers follow BIP-441: arbitrary-length unsigned little-endian,
  with arithmetic results minimally encoded.
* A *node* is a pair `(hash, sum)` with `hash` a 32-byte string and `sum` an
  unsigned integer of satoshis. Its *canonical encoding* is
  `hash || le64(sum)` (40 bytes), abbreviated `sc`.

### 2.2 Roles

* **Operator**: the party that coordinates joins, allocates positions in the
  tree and holds `OPERATOR_KEY`. The operator has no ability to move or
  freeze participants' funds (section 10.1).
* **Owner**: the party controlling a leaf's `owner_key`.
* **Evictor**: the party controlling a leaf's `evictor_key`, permitted to
  force the leaf on-chain after `evict_after`. Typically the operator.

## 3. Overview

*(This section is informative.)*

### 3.1 The problem

Constructions that let many users share one UTXO (Ark, timeout trees, CTV
trees, channel factories) suffer from *on-chain transaction amplification*: to
leave unilaterally, a user must publish a path of `O(log N)` transactions,
each paying fees, and the interior of the tree must exist as pre-signed or
template-committed transactions. The operator faces the mirror problem: a
single unresponsive user forces the whole tree to be published at expiry.

The original LayerTree sketch ("A Path To Constant Space Exit" in
`design/unified-batching.md`) proposed keeping the tree purely off-chain,
committing to it from a single output, and letting a user exit by presenting
an operator-signed *voucher* plus a Merkle proof directly to the output. It
called for `OP_CAT`, `OP_CHECKSIGFROMSTACK` and elliptic-curve opcodes.

### 3.2 What this document changes

Scrutiny of the sketch against the Great Script Restoration opcode set led to
four changes, detailed in `design/review.md`:

1. **The voucher is not needed for exit.** Once the covenant enforces the
   root commitment, a Merkle proof against the on-chain root *is* the
   authorisation to withdraw the committed amount. Requiring an operator
   signature would only add a way for the operator to block exits.
   Exit is instead authorised by the *owner's* signature over the spending
   transaction, which also stops third parties from forcing a user on-chain.
   Vouchers survive as an optional transition (`CLAIM`, section 7.5) that
   lets a leaf owner pre-authorise a push payment into a new leaf.
2. **A dense, fixed-depth Merkle-sum tree replaces the 256-level MS-SMT.**
   Script has no loops; every level of a proof is unrolled in the script. A
   depth-256 sparse tree is impractical, and its non-inclusion proofs are not
   needed: joining into a position only requires proving that position
   currently holds the *empty node*, which is an ordinary inclusion proof.
3. **Sums are committed at every node and re-derived by the verifier.** This
   is what turns "the operator cannot steal" into a theorem (section 10.2):
   the tree output always holds at least the total of every leaf whose
   inclusion proof verifies.
4. **Eviction and cooperative updates are first-class transitions.** The
   operator can evict a leaf after its `evict_after` height, paying it out in
   full; owner and operator together can replace a leaf (splice, lease
   renewal, ownership transfer); the operator can graft an entire pre-built
   subtree of new members in one constant-size transaction.

### 3.3 Architecture in one picture

```
                 tree output  (P2TR, internal key = NUMS + H_state(root)*G)
                        |
        +---------------+----------------+-----------------+
        |               |                |                 |
      EXIT_1          JOIN_h           UPDATE            CLAIM        (tapleaves, v0xC2)
   owner/evictor    operator sig    owner+operator     voucher CSFS
   removes 1 leaf   grafts subtree  replaces 1 leaf   moves value between leaves

   off-chain: dense binary Merkle-sum tree, depth D, 2^D positions
              node = (hash, sum);  hash = H_node(lh || le64(ls) || rh || le64(rs))
              leaf = 116-byte record; empty leaf hash = 0x00..00, sum 0
```

Every transition spends the tree output as input 0, recreates it as output
0 with the new root and the new total, and places any payouts at output 1
onward. Extra inputs (fees, funds being joined) and extra outputs (change,
anchors) are unconstrained. The taptree of transition scripts is constant for
the life of the tree; only the internal key changes with the state. Its
Merkle root, `m`, doubles as the tree identifier.

## 4. Consensus Environment

This section lists the consensus rules this document depends on. A
deployment MUST NOT be considered conforming unless all of them are active.
Where a referenced proposal leaves a detail unspecified, the assumption made
here is stated explicitly and marked **[A-n]**; if the eventual specification
differs, the reference scripts in section 8 change mechanically but the
design does not.

### 4.1 Required

1. **BIP-341/342 Taproot and Tapscript**, with script-path spends.
2. **BIP-440 (varops budget)**: per-transaction budget of `10,000 × weight`
   units; cost formulas as specified there.
3. **BIP-441 (tapleaf version 0xC2)**: restored `OP_CAT`, `OP_SUBSTR`,
   `OP_LEFT`, `OP_RIGHT`; arbitrary-length unsigned integers; 4,000,000-byte
   stack elements; the modified success rule (a single non-zero element).
   All LayerTree scripts are tapleaf version `0xC2`.
4. **`OP_TX`** as in the draft BIP (`rustyrussell/bips`, branch
   `guilt/varops`, `bip-unknown-optx.mediawiki`, version 0.1.0), redefining
   `OP_SUCCESS189` (0xbd). Only the selector bits enumerated in section 8.1
   are used. **[A-1]** Non-collated amounts are pushed as 8-byte
   little-endian strings and scriptPubKeys as raw byte strings, as that draft
   states.
5. **`OP_CHECKSIGFROMSTACK`** as in BIP-348: pops `pk`, `msg`, `sig`; pushes
   1 on success. It is used by `CLAIM` only. **[A-2]** Its 0xC2 varops cost
   equals a signature check (500,000 units), as the "New Opcodes for Tapscript
   v2" draft states.
6. **`OP_ECSCALARMUL`**. **[A-3]** Pops one element of at most 32 bytes,
   interprets it as a big-endian scalar `s` with `0 < s < n`, and pushes the
   33-byte compressed encoding of `s·G`. Fails otherwise. Cost 500,000.
7. **`OP_ECPOINTADD`**. **[A-4]** Pops two 33-byte compressed points and
   pushes the 33-byte compressed encoding of their sum; fails if either
   encoding is invalid or the result is the point at infinity. Cost 500,000.

If the final EC opcodes use a different point or scalar encoding (for example
x-only points with a parity byte, or little-endian scalars), implementers
MUST adapt `TREE_SPK` (section 8.2) accordingly; `OP_BYTEREV` or one
additional `OP_CAT` suffices in each case.

### 4.2 Not required

* `OP_INTERNALKEY` is not used: the scripts verify the full input
  scriptPubKey instead (section 6.4), which also binds the taptree root.
* `OP_MULTI`, `OP_SEGMENT`, `OP_BYTEREV` are not used. Section 13 notes
  optimisations that would use them.
* No `OP_CHECKTEMPLATEVERIFY`, `OP_TEMPLATEHASH`, `OP_CHECKCONTRACTVERIFY`
  or `SIGHASH_ANYPREVOUT` is required by the tree itself. Section 9.8 notes
  where rebindable signatures help *leaf-level* constructions.

### 4.3 Policy assumptions

*(informative)* Relay of `0xC2` script-path spends with witnesses of a few
kilobytes is assumed to be standard once BIP-441 activates. Transitions use
exogenous fees (section 9.3); a Pay-to-Anchor (`OP_1 <0x4e73>`) output at any
index ≥ 1 (or ≥ K+1 for a K-payout transition) is compatible with all
scripts in this document.

## 5. Data Structures

### 5.1 Tags and constants

| Name | Value |
|---|---|
| `TAG_LEAF` | `"LayerTree/leaf"` |
| `TAG_NODE` | `"LayerTree/node"` |
| `TAG_STATE` | `"LayerTree/state"` |
| `TAG_VOUCHER` | `"LayerTree/voucher"` |
| `NUMS` | BIP-341 `H`: x = `50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0`, compressed `02 || x` |
| `EMPTY_LEAF_HASH` | 32 zero bytes |
| `LEAF_LEN` | 116 |

`H_leaf`, `H_node`, `H_state`, `H_voucher` denote `H_tag` with the
corresponding tag. The 64-byte tagged-hash prefixes are given in
`spec/test-vectors.json` under `tags`.

### 5.2 Leaf

A leaf is a fixed-length 116-byte record:

| Offset | Length | Field | Encoding |
|---|---|---|---|
| 0 | 8 | `amount` | `le64`, satoshis |
| 8 | 32 | `exit_key` | x-only public key; on exit the leaf is paid to `P2TR(exit_key)` |
| 40 | 32 | `owner_key` | x-only public key authorising `EXIT`, `UPDATE` and vouchers |
| 72 | 32 | `evictor_key` | x-only public key authorising eviction |
| 104 | 4 | `evict_after` | `le32` block height; eviction is valid only in a transaction with `nLockTime ≥ evict_after` |
| 108 | 8 | `seq` | `le64` sequence number, incremented by `CLAIM` |

Requirements:

* `amount` MUST be greater than 0 and less than 2^51.
* `exit_key`, `owner_key` and `evictor_key` MUST each be the x coordinate of
  a point on secp256k1 (i.e. `lift_x` succeeds).
* `evict_after` MUST be less than 500,000,000. A leaf that MUST NOT be
  evictable SHALL set `evictor_key` to a provably unspendable key; `NUMS` is
  RECOMMENDED.
* `leaf_hash = H_leaf(leaf_bytes)`; the leaf's node is `(leaf_hash, amount)`.

*(informative)* `exit_key` is deliberately distinct from `owner_key`, so a
hot key can authorise while funds land on a cold key, and so that a channel
leaf (section 9.8) can name its funding output key.

### 5.3 Nodes

The **empty leaf** is the node `E_0 = (EMPTY_LEAF_HASH, 0)`.

The **branch hash** of a left node `L = (lh, ls)` and a right node
`R = (rh, rs)` is

```
H_node(lh || le64(ls) || rh || le64(rs))
```

and the parent node is `(H_node(...), ls + rs)`. The sum of a branch is
*defined* as the sum of its children's sums; it is never an independent
input. Verifiers MUST recompute it.

The **empty node of height h**, `E_h`, is the parent of two copies of
`E_{h-1}`. `E_h` for `0 ≤ h ≤ 32` are listed in the test vectors.

### 5.4 Tree and positions

A LayerTree of **depth D** is a complete binary tree with `2^D` leaf
positions numbered `0 .. 2^D − 1`. The node at height `h` and index `i`
covers positions `[i·2^h, (i+1)·2^h)`. Unoccupied positions hold `E_0`.
Implementations SHOULD support `D` in the range 8 to 24; `D` is fixed at
tree creation (section 6.2).

The **root** is the node at height `D`, index 0. Its sum is the **total**.

### 5.5 Sibling paths

The sibling path of the node at `(h, i)` is the sequence of `D − h` pairs
`(dir_k, sib_k)` for `k = h .. D−1`, where `sib_k` is the node at
`(k, (i >> (k−h)) XOR 1)` and `dir_k = (i >> (k−h)) AND 1`, i.e. `dir_k = 1`
iff the node on the path is the *right* child at level `k`.

`fold(node, path)` recomputes the root:

```
for (dir, sib) in path (bottom up):
    node = dir ? parent(sib, node) : parent(node, sib)
return node
```

In witnesses, each level is supplied as two elements: `dir` (the empty
string for 0, `0x01` for 1, per BIP-342 `MINIMALIF`) and `sc = sib.hash ||
le64(sib.sum)`. A path whose `sc` element is not exactly 40 bytes MUST be
rejected (the scripts enforce this).

### 5.6 Root binding

The 32-byte value bound into the tree output is `root_hash` only. The total
is NOT committed separately: it is enforced to equal the tree output's amount
at every transition (section 7.1, rule 5), so `total == amount` is an
invariant of any tree output that was created by a valid transition.

## 6. The Tree Output

### 6.1 State key

For a root hash `r`, the **state tweak** is `t = int(H_state(r))`. If
`t = 0` or `t ≥ n` the state is invalid; implementations MUST reject such a
root (probability 2^-128; a colliding root can be avoided by changing any
leaf's `seq`).

The **state key** is `P = NUMS + t·G`, and the tree output's BIP-341
*internal key* is `x(P)`. Because nobody knows the discrete logarithm of
`NUMS`, the key path is unspendable: every spend of a tree output is a
script-path spend through one of the transition scripts.

### 6.2 Taptree

A tree's **taptree** contains one tapleaf (version `0xC2`) per supported
transition script, built as specified in section 8 from the tree's
parameters:

* `D`, the depth;
* `OPERATOR_KEY`, a 32-byte x-only key;
* the set of supported `JOIN` heights.

A conforming taptree MUST contain `EXIT_1`. It SHOULD contain at least one
`JOIN_h`, and MAY contain `UPDATE`, `CLAIM` and further variants (section
7.6). Scripts MUST NOT reference the taptree's own Merkle root; the scripts
receive it from the witness and verify it (section 6.4), which avoids the
circular dependency.

The Merkle root of the taptree, `m`, is the **tree identifier**. Two tree
outputs with the same `m` follow identical rules and differ only in state.

### 6.3 scriptPubKey

```
TREE_SPK(r, m) = P2TR( x( lift_x(x(NUMS + H_state(r)·G)) + H_TapTweak(x(P) || m)·G ) )
```

i.e. the ordinary BIP-341 output key for internal key `x(P)` and Merkle root
`m`. A **tree output** for state `r` is any output with scriptPubKey
`TREE_SPK(r, m)` and amount equal to the root's sum.

### 6.4 Verifying the current state in script

A transition script receives `r` and `m` in its witness and MUST verify

```
TREE_SPK(r, m) == scriptPubKey of the input being spent
```

using `OP_TX` (`SEL_IN_SPK`, section 8.1). This binds both the claimed root
and the claimed taptree. Binding `m` is security critical: if a spender
could substitute `m'`, the recreated tree output would be governed by scripts
of the spender's choosing (section 10.4).

### 6.5 Creation

A tree is created by any transaction paying `TREE_SPK(r_0, m)` with amount
equal to the sum of `r_0`. `r_0` MAY be the empty root `E_D` (amount 0 is
not a valid output, so in practice the operator seeds the tree with at least
one leaf of its own) or a root over an initial set of leaves whose owners
have verified their inclusion before funding (section 9.2).

## 7. Transitions

A **transition** is a script-path spend of a tree output. Each transition
script implements one of the transition types below. This section specifies
the rules each type enforces; section 8 gives scripts that enforce exactly
these rules.

### 7.1 Common rules

For every transition the spending transaction `tx` MUST satisfy:

1. **Position.** The tree output is spent by input 0 of `tx`.
2. **Recreation.** Output 0 of `tx` has scriptPubKey `TREE_SPK(r', m)`,
   where `r'` is the root after the transition and `m` is the taptree root
   verified against the input (section 6.4).
3. **Old-state proof.** The witness demonstrates, by `fold`, that the
   pre-transition node(s) it names are in the tree with root `r` and that
   `fold` yields sum `S` equal to the amount of input 0.
4. **New root.** `r'` is `fold` of the post-transition node(s) over the same
   sibling path(s).
5. **Conservation.** The amount of output 0 equals the sum produced by
   `fold` for `r'`.
6. **Payouts.** Where the transition type specifies payouts, output `1..K`
   have the required scriptPubKey and amount.
7. **Freedom elsewhere.** Inputs `1..` and outputs `K+1..` are unconstrained.

Rule 5 together with rule 3 means the tree output's amount always equals the
recomputed total: value can leave the tree output only through a payout
output (`EXIT`) or a cooperative decrease (`UPDATE`), and can enter only by
being added to output 0 by the spender's other inputs (`JOIN`, `UPDATE`).

*(informative)* Rule 1 ensures two tree outputs cannot be spent by the same
transaction, which would otherwise let both claim output 0. Merging trees is
out of scope.

### 7.2 EXIT

`EXIT` removes one leaf and pays it out.

Witness inputs: sibling path of the leaf position (`D` levels), `leaf`,
`sig`, `is_evict`, `r`, `m`.

Rules:

1. The old node is `(H_leaf(leaf), leaf.amount)`; the new node is `E_0`.
2. Output 1 MUST have scriptPubKey `P2TR(leaf.exit_key)`.
3. If `is_evict` is false (owner exit):
   * `sig` MUST be a valid BIP-340 signature over the BIP-341 signature hash
     of `tx` (input 0, `SIGHASH_DEFAULT` or any hash type) by
     `leaf.owner_key`;
   * output 1's amount MUST be less than or equal to `leaf.amount`. The
     difference, if any, is available to the transaction as fee or for other
     outputs; the owner consented to it by signing.
4. If `is_evict` is true (eviction):
   * `sig` MUST be a valid signature over `tx` by `leaf.evictor_key`;
   * `tx.nLockTime` MUST be at least `leaf.evict_after` and input 0's
     `nSequence` MUST enable lock-time (`OP_CHECKLOCKTIMEVERIFY` semantics);
   * output 1's amount MUST equal `leaf.amount`.
5. The recomputed total `S` equals input 0's amount, and output 0's amount
   equals `S − leaf.amount` (this follows from `fold` of `E_0`).

### 7.3 JOIN

`JOIN_h` grafts a subtree of height `h` into an empty position. `h = 0`
inserts a single leaf.

Witness inputs: sibling path of the node at height `h` (`D − h` levels),
`new_hash` (32 bytes), `new_sum` (8 bytes `le64`), `sig`, `r`, `m`.

Rules:

1. The old node is `E_h`; the new node is `(new_hash, new_sum)`.
2. `sig` MUST be a valid signature over `tx` by `OPERATOR_KEY`.
3. Output 0's amount equals `S + new_sum`. The additional value MUST be
   supplied by other inputs (or the transaction is invalid by ordinary
   consensus rules).
4. No requirement is placed on the *contents* of the grafted subtree. Each
   prospective member MUST verify their own leaf's inclusion under
   `new_hash` and the subtree's internal sum consistency along their path
   before contributing funds (section 9.2). Section 10.2 explains why this is
   sufficient.

### 7.4 UPDATE

`UPDATE` replaces one leaf with another at the same position, with the
consent of the leaf's owner and the operator.

Witness inputs: sibling path (`D` levels), `old_leaf`, `new_leaf`,
`owner_sig`, `operator_sig`, `r`, `m`.

Rules:

1. Old node `(H_leaf(old_leaf), old_leaf.amount)`; new node
   `(H_leaf(new_leaf), new_leaf.amount)`.
2. `owner_sig` MUST be valid over `tx` by `old_leaf.owner_key`;
   `operator_sig` MUST be valid over `tx` by `OPERATOR_KEY`.
3. Output 0's amount equals `S − old_leaf.amount + new_leaf.amount`. Any
   decrease is free for the transaction to spend (both signers see where it
   goes); any increase MUST be funded by other inputs.
4. `new_leaf` MAY change any field, including `owner_key` (ownership
   transfer), `evict_after` (lease renewal) and `exit_key`.

### 7.5 CLAIM

`CLAIM` executes a **voucher**: an off-chain, owner-signed instruction to
carve a new leaf out of an existing leaf's balance. It requires neither the
owner's nor the operator's participation at redemption time and is
single-use by construction.

Voucher: `voucher_sig` is a BIP-340 signature by `source_leaf.owner_key`
over

```
H_voucher( m || source_leaf || claim_leaf )
```

Witness inputs: sibling path of the *claim* position (`D` levels), sibling
path of the *source* position (`D` levels), `source_leaf`, `claim_leaf`,
`voucher_sig`, `r`, `m`.

Rules:

1. `voucher_sig` MUST verify (via `OP_CHECKSIGFROMSTACK`) under
   `source_leaf.owner_key` over the message above.
2. **Step 1** (source): old node `(H_leaf(source_leaf), source_leaf.amount)`;
   new node is the leaf `source_leaf'` identical to `source_leaf` except
   `amount' = source_leaf.amount − claim_leaf.amount` (MUST NOT underflow)
   and `seq' = source_leaf.seq + 1`. `fold` over the source path MUST yield
   `(r, S)` with `S` equal to input 0's amount; call the folded new root
   `(r_1, S_1)`.
3. **Step 2** (claim): old node `E_0`; new node
   `(H_leaf(claim_leaf), claim_leaf.amount)`. `fold` over the claim path MUST
   yield `(r_1, S_1)`; the folded new root `(r', S')` defines output 0.
4. `S' = S_1 = S`: a `CLAIM` conserves the total. Output 0's amount equals
   `S`.

*(informative)* Replay is impossible because step 1 changes the source leaf:
once redeemed, no tree state contains `source_leaf` at the source position,
so the signed message can never verify against the tree again. `seq` is
incremented so that a source leaf whose balance later returns to a previous
value still differs from every previously signed voucher. Honouring a
voucher by other means (for example a `JOIN` of the same `claim_leaf`
elsewhere) does *not* invalidate it; issuers MUST track outstanding vouchers
as liabilities until the source leaf's `seq` has advanced past them
(section 9.6).

### 7.6 Composition and variants

Transition types compose by sequencing: a script that applies transitions
`T_1 … T_K` treats the root produced by `T_i` as the current root of
`T_{i+1}`, verifies the old-state proof (rule 3) only for `T_1`, and applies
rules 2 and 5 only to the final root. `CLAIM` is the composition of an
`UPDATE`-like step and a `JOIN_0`-like step with a different authorisation.

Implementations MAY define `EXIT_K` (K owner or evictor exits paying outputs
`1..K`), or combined scripts, provided each component enforces the rules of
its type. This document defines only the single-step scripts and `CLAIM`.

Section 5.2 requires `amount > 0`. The scripts do not enforce this, and
zero-amount leaves are harmless to the total but useless:
an `EXIT` of such a leaf requires a zero-value payout output. Participants
SHOULD refuse to create or accept zero-amount leaves; an operator that finds
one MAY remove it with `UPDATE` (with the owner) or leave it in place, since
it contributes nothing to the total.

## 8. Reference Scripts

This section specifies scripts that enforce section 7. Conforming
implementations MAY use different scripts provided they enforce the same
rules; however, since `m` identifies a tree and participants must be able to
audit the taptree they join, implementations SHOULD use exactly these
scripts so that `m` can be recomputed from `(D, OPERATOR_KEY, join heights)`
alone.

The scripts are generated by `tools/layertree_scripts.py`, executed
end-to-end against the reference tree by `tools/test_scripts.py`, and listed
in full for `D = 4` under `spec/scripts/`. All pushes of numbers are minimal.

### 8.1 OP_TX selectors used

| Name | Bits | Value | Pushes |
|---|---|---|---|
| `SEL_CURR_INPUT` | `CURR_INPUT_NUMBER` | `0x8000` | current input index (minimal LE number) |
| `SEL_IN_AMOUNT` | `INPUT_AMOUNT \| INPUTSELECT_CURRENT` | `0x10800` | current input's amount (8 bytes LE) |
| `SEL_IN_SPK` | `INPUT_SCRIPTPUBKEY \| INPUTSELECT_CURRENT` | `0x20800` | current input's scriptPubKey |
| `SEL_OUT_SINGLE` | `OUTPUT_AMOUNT \| OUTPUT_SCRIPT \| OUTPUTSELECT_SINGLE` | `0x4300` | pops index; pushes amount (8 bytes LE) then scriptPubKey |

Scripts MUST push selectors as constants. They never construct a selector at
run time, so the `OP_TX` "unknown bit means success" rule cannot be
triggered by a witness.

### 8.2 Macros

**`TAGGED(prefix)`** — `[msg] → [H_tag(msg)]`

```
<prefix64> OP_SWAP OP_CAT OP_SHA256
```

**`PAD8`** — `[n] → [le64(n)]` for `n < 2^64`. (If `n` has more than 8
bytes the result is truncated; every use in this document is followed by a
check that makes truncation fail, see section 10.6.)

```
<0x0000000000000000> OP_CAT OP_8 OP_LEFT
```

**`LEAF_ACC`** — `[leaf] → [H_leaf(leaf) amount]`

```
OP_DUP OP_8 OP_LEFT OP_SWAP TAGGED(TAG_LEAF) OP_SWAP
```

**`TREE_SPK`** — `[r m] → [TREE_SPK(r, m)]`

```
OP_SWAP TAGGED(TAG_STATE)                    # m t
OP_ECSCALARMUL <NUMS33> OP_ECPOINTADD        # m P
32 OP_RIGHT                                  # m x(P)
OP_TUCK OP_SWAP OP_CAT                       # x(P) (x(P)||m)
TAGGED(TapTweak)                             # x(P) t2
OP_ECSCALARMUL                               # x(P) t2·G
OP_SWAP <0x02> OP_SWAP OP_CAT                # t2·G (02||x(P))
OP_ECPOINTADD 32 OP_RIGHT                    # x(Q)
<0x5120> OP_SWAP OP_CAT                      # scriptPubKey
```

Note `02 || x(P)` is `lift_x(x(P))`, matching BIP-341's use of the even-y
internal key.

**`PROLOGUE`** — witness top `… r m`; leaves `| m r` on the altstack.

```
<SEL_CURR_INPUT> OP_TX OP_0 OP_NUMEQUALVERIFY      # input 0
OP_2DUP TREE_SPK <SEL_IN_SPK> OP_TX OP_EQUALVERIFY  # bind (r, m) to input spk
OP_TOALTSTACK OP_TOALTSTACK                         # | m r
```

**`LEVEL`** — one Merkle-sum level for both accumulators. Before:
`dir sc T oh os nh ns` (the two witness items for this level sit directly
below `T`, the `TAG_NODE` prefix). After: `T oh' os' nh' ns'`. `(oh, os)` is
the pre-transition node, `(nh, ns)` the post-transition node.

```
OP_6 OP_ROLL OP_6 OP_ROLL                # T oh os nh ns dir sc
OP_SIZE 40 OP_EQUALVERIFY                #   sc is exactly hash||le64(sum)
OP_DUP OP_8 OP_RIGHT                     # … dir sc ss8
OP_DUP OP_TOALTSTACK                     # | ss8
OP_3 OP_ROLL OP_TUCK OP_ADD              # T oh os nh dir sc ns ns'
OP_TOALTSTACK PAD8                       # T oh os nh dir sc ns8      | ss8 ns'
OP_3 OP_ROLL OP_SWAP OP_CAT              # T oh os dir sc nc          (nc = nh||ns8)
OP_OVER OP_SWAP OP_3 OP_PICK             # T oh os dir sc sc nc dir
OP_NOTIF OP_SWAP OP_ENDIF OP_CAT         # T oh os dir sc pre_n       (dir? sc||nc : nc||sc)
OP_5 OP_PICK OP_SWAP OP_CAT OP_SHA256    # T oh os dir sc nh'
OP_TOALTSTACK                            #                            | ss8 ns' nh'
OP_FROMALTSTACK OP_FROMALTSTACK OP_FROMALTSTACK   # T oh os dir sc nh' ns' ss8
OP_5 OP_ROLL OP_TUCK OP_ADD              # T oh dir sc nh' ns' os os'
OP_TOALTSTACK PAD8                       # T oh dir sc nh' ns' os8    | os'
OP_5 OP_ROLL OP_SWAP OP_CAT              # T dir sc nh' ns' oc        (oc = oh||os8)
OP_3 OP_ROLL OP_SWAP OP_4 OP_ROLL        # T nh' ns' sc oc dir
OP_NOTIF OP_SWAP OP_ENDIF OP_CAT         # T nh' ns' pre_o
OP_3 OP_PICK OP_SWAP OP_CAT OP_SHA256    # T nh' ns' oh'
OP_FROMALTSTACK OP_2SWAP                 # T oh' os' nh' ns'
```

`LEVEL` is 88 bytes. `dir` MUST be the empty string or `0x01`; any other
encoding fails `OP_NOTIF` under `MINIMALIF`.

**`CHECK_OLD`** — `[T oh os nh ns] | … r → [T nh ns] | …`; requires
`os == amount(input 0)` and `oh == r`.

```
OP_2SWAP <SEL_IN_AMOUNT> OP_TX OP_NUMEQUALVERIFY OP_FROMALTSTACK OP_EQUALVERIFY
```

**`FINAL`** — `[T nh ns] | m → [1]`; requires output 0 to be
`(ns, TREE_SPK(nh, m))`.

```
OP_ROT OP_DROP OP_SWAP OP_FROMALTSTACK TREE_SPK      # ns spk'
OP_0 <SEL_OUT_SINGLE> OP_TX                          # ns spk' amt0 spk0
OP_ROT OP_EQUALVERIFY OP_NUMEQUAL                    # 1
```

### 8.3 EXIT_1

Witness (bottom → top):
`dir_{D-1} sc_{D-1} … dir_0 sc_0  leaf  sig  is_evict  r  m`

```
PROLOGUE                                           # leaf sig is_evict     | m r
OP_DUP OP_TOALTSTACK                               #                       | m r is_evict
OP_IF                                              # -- eviction --
  OP_OVER 104 OP_4 OP_SUBSTR OP_CHECKLOCKTIMEVERIFY OP_DROP
  OP_OVER 72 32 OP_SUBSTR                          # leaf sig evictor_key
OP_ELSE                                            # -- owner exit --
  OP_OVER 40 32 OP_SUBSTR                          # leaf sig owner_key
OP_ENDIF
OP_CHECKSIGVERIFY                                  # leaf
OP_SIZE 116 OP_EQUALVERIFY
OP_1 <SEL_OUT_SINGLE> OP_TX                        # leaf amt1 spk1
<0x5120> OP_3 OP_PICK OP_8 32 OP_SUBSTR OP_CAT     # leaf amt1 spk1 P2TR(exit_key)
OP_EQUALVERIFY                                     # leaf amt1
OP_OVER OP_8 OP_LEFT                               # leaf amt1 leaf.amount
OP_FROMALTSTACK                                    # leaf amt1 leaf.amount is_evict   | m r
OP_IF OP_NUMEQUALVERIFY OP_ELSE OP_LESSTHANOREQUAL OP_VERIFY OP_ENDIF
LEAF_ACC                                           # oh os
<TAG_NODE> OP_ROT OP_ROT                           # T oh os
<EMPTY_LEAF_HASH> OP_0                             # T oh os E_0.hash 0
LEVEL × D
CHECK_OLD FINAL
```

Size: `651 + 88·D` bytes (1,003 at `D = 4`; 2,059 at `D = 16`).

### 8.4 JOIN_h

Witness: `dir_{D-1} sc_{D-1} … dir_h sc_h  new_hash  new_sum8  sig  r  m`

```
PROLOGUE                                           # new_hash new_sum8 sig  | m r
<OPERATOR_KEY> OP_CHECKSIGVERIFY                   # new_hash new_sum8
OP_SIZE OP_8 OP_EQUALVERIFY
OP_OVER OP_SIZE 32 OP_EQUALVERIFY OP_DROP
<TAG_NODE> OP_ROT OP_ROT                           # T new_hash new_sum8
<E_h.hash> OP_0 OP_2SWAP                           # T E_h.hash 0 new_hash new_sum8
LEVEL × (D − h)
CHECK_OLD FINAL
```

`E_h.hash` is the constant from section 5.3 for the script's height.

### 8.5 UPDATE

Witness: `path(D)  old_leaf  new_leaf  owner_sig  operator_sig  r  m`

```
PROLOGUE                                           # old new osig opsig     | m r
<OPERATOR_KEY> OP_CHECKSIGVERIFY                   # old new osig
OP_2 OP_PICK 40 32 OP_SUBSTR OP_CHECKSIGVERIFY     # old new   (owner of OLD leaf)
OP_SIZE 116 OP_EQUALVERIFY
OP_SWAP OP_SIZE 116 OP_EQUALVERIFY                 # new old
<TAG_NODE> OP_ROT OP_ROT                           # T new old
OP_SWAP LEAF_ACC                                   # T new oh os
OP_ROT LEAF_ACC                                    # T oh os nh ns
LEVEL × D
CHECK_OLD FINAL
```

### 8.6 CLAIM

Witness: `claim_path(D)  source_path(D)  source_leaf  claim_leaf
voucher_sig  r  m` (the claim path is deeper in the stack because it is
consumed second).

```
<SEL_CURR_INPUT> OP_TX OP_0 OP_NUMEQUALVERIFY
OP_2DUP TREE_SPK <SEL_IN_SPK> OP_TX OP_EQUALVERIFY  # src claim vsig r m
OP_DUP OP_TOALTSTACK OP_SWAP OP_TOALTSTACK          # src claim vsig m       | m r
OP_3 OP_PICK OP_3 OP_PICK OP_CAT OP_CAT             # src claim vsig (m||src||claim)
TAGGED(TAG_VOUCHER)                                 # src claim vsig msg
OP_3 OP_PICK 40 32 OP_SUBSTR                        # src claim vsig msg src.owner_key
OP_CHECKSIGFROMSTACK OP_VERIFY                      # src claim
OP_SIZE 116 OP_EQUALVERIFY
OP_SWAP OP_SIZE 116 OP_EQUALVERIFY OP_SWAP          # src claim
OP_OVER OP_8 OP_LEFT OP_OVER OP_8 OP_LEFT OP_SUB PAD8      # src claim le64(src.amt − claim.amt)
OP_2 OP_PICK OP_8 100 OP_SUBSTR OP_CAT              # … || src[8:108]
OP_2 OP_PICK 108 OP_8 OP_SUBSTR OP_1ADD PAD8 OP_CAT # src claim src'
OP_FROMALTSTACK OP_ROT OP_TOALTSTACK OP_TOALTSTACK  # src src'              | m claim r
<TAG_NODE> OP_ROT OP_ROT                            # T src src'
OP_SWAP LEAF_ACC                                    # T src' oh os
OP_ROT LEAF_ACC                                     # T oh os nh ns
LEVEL × D                                           # (source path)
CHECK_OLD                                           # T r1 S1               | m claim
OP_FROMALTSTACK LEAF_ACC                            # T r1 S1 ch cs
OP_2SWAP OP_TOALTSTACK OP_TOALTSTACK                # T ch cs               | m S1 r1
<EMPTY_LEAF_HASH> OP_0 OP_2SWAP                     # T E_0.hash 0 ch cs
LEVEL × D                                           # (claim path)
OP_2SWAP OP_FROMALTSTACK OP_ROT OP_EQUALVERIFY      # T nh2 ns2 os2   (oh2 == r1)
OP_FROMALTSTACK OP_NUMEQUALVERIFY                   # T nh2 ns2       (os2 == S1)
FINAL
```

### 8.7 Sizes

Script sizes are `base + 88·levels`. Witness data (paths, leaves,
signatures, `r`, `m`) is `40·levels + constant`. Full tables from the
simulator, including varops consumed, are in `spec/scripts/sizes.md`; see
section 11.

## 9. Off-Chain Protocol

This section specifies the behaviour of operators and participants around
the on-chain transitions. Messages between operator and participants are
transported by any authenticated channel; their encoding is out of scope.

### 9.1 Tree creation

The operator chooses `D`, `OPERATOR_KEY` and the set of `JOIN` heights,
builds the taptree (section 6.2) and publishes `(D, OPERATOR_KEY, heights,
m)`. Participants MUST recompute `m` from the parameters before treating a
tree output as a LayerTree.

### 9.2 Joining

To add participants the operator prepares a `JOIN_h` transaction:

1. The operator chooses an empty position `(h, i)` and builds the subtree
   of new leaves, obtaining `(new_hash, new_sum)`.
2. To each prospective member `U` the operator sends: the unsigned
   transaction, `U`'s leaf, `U`'s sibling path *within the subtree*, the
   sibling path of `(h, i)` in the current tree, `r` and `m`.
3. `U` MUST verify, before signing any input: (a) input 0 spends an
   unspent output with scriptPubKey `TREE_SPK(r, m)` and amount `S`; (b)
   `fold(E_h, path) = (r, S)`; (c) `fold(U.leaf, subtree path)` equals
   `(new_hash, new_sum)`, recomputing every sum; (d) output 0 is
   `TREE_SPK(r', m)` with amount `S + new_sum`, where `r'` is `fold` of the
   new node; (e) `U`'s leaf fields are as agreed; (f) `U`'s own inputs and
   change are as agreed. `U` then signs its inputs with `SIGHASH_DEFAULT`
   (or `SIGHASH_ALL`).
4. The operator signs input 0 (`OPERATOR_KEY`) and broadcasts.

A member's funds are safe by construction: the only transaction that can
spend `U`'s input is one whose output 0 commits to a root containing `U`'s
leaf. `U` SHOULD retain the leaf, both paths, `r`, `r'` and the transaction
id (section 9.7).

The operator MAY use `JOIN_0` for a single member and MAY fund leaves
itself (for example when providing liquidity to a channel leaf).

### 9.3 Exiting and fees

An owner exits with `EXIT_1` at any time without operator involvement. The
transaction MUST pay fees exogenously (an extra input, or an anchor output
funded by an extra input) or endogenously by setting output 1's amount
below `leaf.amount`. Owners SHOULD prefer the endogenous form when they hold
no other coins.

Owners SHOULD first request a cooperative exit from the operator, who can
fold it into its next transition at lower marginal cost; a unilateral
`EXIT_1` conflicts with any pending operator transaction (section 10.5).

### 9.4 Eviction

After `leaf.evict_after`, the evictor MAY publish `EXIT_1` with `is_evict`
set, a lock time of at least `evict_after`, and output 1 paying exactly
`leaf.amount` to `P2TR(leaf.exit_key)`. The evictor pays fees. Operators
SHOULD notify owners before evicting and SHOULD offer an `UPDATE` extending
`evict_after` instead.

### 9.5 Updates

`UPDATE` is used for lease renewal, resizing (splice-in with extra inputs,
splice-out to other outputs), rotating keys, or transferring ownership. Both
signers MUST verify the full transaction before signing; the covenant
enforces only that the tree output's amount tracks the change in the leaf.

### 9.6 Vouchers

A voucher `(m, source_leaf, claim_leaf, voucher_sig)` MAY be issued by any
leaf owner to any recipient. Issuers MUST NOT issue vouchers whose amounts
sum to more than the source leaf's current amount, MUST track each issued
voucher as an outstanding liability until the source leaf's `seq` exceeds
the value at issuance, and MUST rebuild outstanding vouchers (with the new
`seq`) after any `UPDATE` or `CLAIM` on the source leaf.

A recipient MUST verify `voucher_sig`, MUST verify that `source_leaf` is
currently in the tree at some position (by obtaining and checking a path),
and SHOULD treat the voucher as settled only after (a) redeeming it via
`CLAIM`, or (b) the issuer has included `claim_leaf` via `JOIN`/`UPDATE`
and the recipient has verified inclusion. Until then the recipient bears the
risk that the issuer double-issues against the same balance; the covenant
prevents *over*-redemption, not over-issuance (section 10.3).

*(informative)* Vouchers are the LayerTree analogue of Ark's out-of-round
payments and of the original sketch's signed vouchers: an operator that
keeps a funded bond leaf can pay recipients instantly with a voucher that is
independently redeemable if the operator later disappears.

### 9.7 Data retention and proof maintenance

Every transition publishes, in its witness, the full sibling path(s) it
uses and the pre- and post-transition node(s). Consequently:

* A participant who holds their leaf and sibling path for root `r_k` can
  compute their path for `r_{k+1}` from the witness of the transition
  `r_k → r_{k+1}` alone: the only sibling that can change is the ancestor of
  the modified position at the level where the two paths diverge, and its
  new value is derivable from the witness.
* A participant who joined inside a grafted subtree additionally holds their
  path within the subtree from the join flow (section 9.2).

Participants MUST retain their current leaf and path and MUST process every
spend of the tree output (or obtain the current path from the operator and
verify it against the on-chain root). Participants that fall behind can
always catch up from the chain: no data outside the blockchain and their own
join-time proof is required to construct a valid `EXIT_1`.

Operators SHOULD serve the full tree to participants on request.

### 9.8 Channel leaves

*(informative)* A leaf whose `exit_key` is a MuSig2 aggregate of the owner
and operator (optionally with a taptree) is a *channel leaf*: the two parties
run a payment channel whose funding output does not yet exist on-chain. On
`EXIT`, the funding output materialises at output 1 with an outpoint that
depends on the exit transaction, so the channel's commitment transactions
MUST be rebindable to an unknown funding outpoint. With this document's
opcode set that is achieved LN-Symmetry style: the commitment script hashes
the relevant fields with `OP_TX` (collated `VERSION | LOCKTIME | OUTPUT_*`
for all outputs and the current input's `SEQUENCE`) and checks the channel
key's signature over the hash with `OP_CHECKSIGFROMSTACK`. `evictor_key`
set to the operator's key with a short `evict_after` gives the operator
its ordinary right to force-close.

Routing between channel leaves through the operator, and between the tree
and the public Lightning Network, is the "virtual network" of the design
notes; it is outside this document's scope.

## 10. Security Considerations

### 10.1 Trust model

| Party | Can | Cannot |
|---|---|---|
| Operator | refuse to co-sign `JOIN`/`UPDATE`; evict a leaf after its `evict_after` (paying it in full); issue vouchers against its own leaves | move, reduce, freeze or delay any other leaf; prevent an owner's `EXIT`; change the taptree; change `evict_after` unilaterally |
| Owner | `EXIT` at any time; co-sign `UPDATE`; issue vouchers against their leaf | affect any other leaf; withdraw more than their leaf's amount |
| Anyone | redeem a valid voucher (`CLAIM`); relay transitions | trigger an owner's exit; create leaves; alter amounts |

Custody is never with the operator: the tree output's key path is
unspendable (section 6.1) and every script path requires either a proof
against the committed root plus the affected owner's signature, or the
operator's signature for operations that only *add* value (`JOIN`).

### 10.2 Conservation

**Claim.** Let a tree output have amount `A` and root hash `r`. For any set
of leaves `L_1 … L_k` at distinct positions, each with a sibling path that
`fold`s to `(r, A)` with the sums recomputed at every level, the sum of the
`L_i` amounts is at most `A`.

*Proof sketch.* Consider the union of the `k` paths as a subtree `U` of the
position tree rooted at the root. For every node `v` in `U`, the verifier of
each path through `v` recomputed `v.sum` as the sum of the two children's
sums that were hashed into `v.hash`; since `v.hash` is fixed by `r` through
collision-resistant hashing, both children's `(hash, sum)` pairs are fixed.
Therefore `v.sum = sum(children)` for every `v ∈ U`, and by induction
`A = root.sum ≥ Σ_i L_i.amount` (siblings outside `U` contribute
non-negative sums, since sums are unsigned). ∎

Because rule 7.1.5 ties `A` to the recomputed total at every transition, the
invariant `A = total` holds for every tree output produced by a valid
transition, and every provable leaf can be paid. A leaf whose path does *not*
recompute consistently (an operator-constructed inconsistency) is not
provable and its "owner" was never in the tree; section 9.2 step 3(c)
requires members to detect this before funding.

### 10.3 Vouchers

`CLAIM` prevents over-*redemption* (an underflow fails the script and the
source leaf changes after each redemption) but cannot prevent an issuer from
*over-issuing* vouchers against the same balance. Recipients therefore extend
credit to the issuer until settlement (section 9.6). This is the same trust
profile as an Ark out-of-round payment and strictly better than an unsecured
IOU: the first redeemer is paid by consensus.

A voucher commits to `m`, so it cannot be replayed in another tree; it
commits to the full source leaf including `seq`, so it cannot be replayed
after any change to the source leaf.

### 10.4 Binding the taptree

Section 6.4 requires every script to verify `TREE_SPK(r, m)` against the
spent scriptPubKey. If `m` were taken from the witness unverified, a spender
could recreate the tree output under a taptree of their choosing (for
example a single `OP_TRUE` leaf) and drain it in the next transaction. The
reference scripts perform this check first (`PROLOGUE`) and reuse the
verified `m` for output 0. Implementations that replace `PROLOGUE` MUST
preserve this property; using `OP_INTERNALKEY` to check only `r` is
insufficient.

### 10.5 Concurrency and pinning

All transitions spend the same UTXO, so at most one confirms per tree per
block position and conflicting transitions are resolved by fee. An owner's
`EXIT_1` conflicts with a pending operator `JOIN`; either party can replace
the other under BIP-125 rules if it pays the required increment. An attacker
holding one leaf can therefore impose a replacement cost on the operator
once per leaf per round. Mitigations: operators SHOULD honour cooperative
exit requests promptly (removing the incentive), MAY chain several
transitions off one confirmed output within mempool descendant limits, and
SHOULD use anchor outputs so that either party can bump fees. Signatures
cover outputs, so a third party cannot alter where an exit pays.

### 10.6 Integer encodings and truncation

* Amounts and sums are unsigned. `OP_SUB` underflow fails the script, which
  is what makes over-claims and negative balances impossible.
* `PAD8` truncates values above 2^64 − 1. Every value passed to `PAD8` is
  either an amount read from the transaction (8 bytes), a sum that later
  MUST equal an 8-byte transaction amount (`CHECK_OLD`, `FINAL`), or an
  intermediate along a path whose final value is so checked. Since sums are
  monotone non-decreasing up the path, an intermediate above 2^64 forces the
  final sum above any valid amount and the script fails.
* `sc` elements MUST be exactly 40 bytes and leaves exactly 116 bytes; the
  scripts check both, so no field can be shifted.
* `evict_after` is compared by `OP_CHECKLOCKTIMEVERIFY`, which also fails if
  the lock-time types differ; since `evict_after < 500,000,000`, eviction
  transactions MUST use height-based `nLockTime`.

### 10.7 Signature coverage

Owner, evictor and operator signatures are ordinary `OP_CHECKSIG(VERIFY)`
over the transaction. `SIGHASH_DEFAULT` is RECOMMENDED. Signers that use
`SIGHASH_SINGLE`/`ANYONECANPAY` variants do so at their own risk: the
covenant constrains outputs 0 and 1 regardless, but change outputs are not
constrained by script.

Leaf keys are checked by `lift_x` at signature verification; a leaf with an
invalid `owner_key` can never `EXIT` and an invalid `exit_key` pays to an
unspendable output. Joining members MUST check their own keys (section 9.2)
and operators SHOULD validate all leaf keys before grafting.

### 10.8 Eviction

Eviction pays the leaf in full to `exit_key`; it cannot shortchange or
redirect. Its cost to the owner is loss of the off-chain position and, for
channel leaves, a forced on-chain channel. `evict_after` bounds when this
can happen and is renewable only with the owner's signature (`UPDATE`).
Owners SHOULD treat `evict_after` as a lease expiry and renew ahead of it.

### 10.9 Data availability

Section 9.7 shows that all data needed to exit is on-chain except a
participant's own leaf and join-time path. An operator that withholds data
can therefore inconvenience but not trap participants. Participants that
lose their join-time data cannot reconstruct their subtree path unless the
operator (or another member of the same subtree) provides it; backups are
REQUIRED for unilateral safety.

### 10.10 Resource limits

At `D = 16` an `EXIT_1` consumes about 4.84M varops against a budget of
roughly 40M for a transaction of its weight (section 11). Costs are
dominated by the eight EC operations and one signature check
(4.5M units); hashing and stack work contribute about 0.3M. Stack depth
peaks at 42 elements (`CLAIM`: 75) against a limit of 32,768, and no element
exceeds 40 bytes except the script itself.

### 10.11 Reorganisations

A `JOIN` that is reorganised out leaves members with signed transactions
that spend their inputs into a now-invalid tree state; those inputs remain
theirs. Members SHOULD wait for their usual confirmation depth before
treating a leaf as final. Vouchers, paths and roots are all keyed by
`(txid, r)` and MUST be rolled back with the chain.

### 10.12 OP_TX forward compatibility

Undefined selector bits make `OP_TX` succeed immediately. The reference
scripts push only constant selectors composed of defined bits and never
compute a selector from witness data, so this rule cannot be triggered.
Implementers MUST NOT parameterise selectors from the witness.

## 11. Cost Analysis

*(informative)* Figures are measured by executing the reference scripts in
the simulator (`tools/gen_listings.py` → `spec/scripts/sizes.md`). The
control block assumes a five-leaf taptree (depth 3, 129 bytes).

| D | leaves | EXIT_1 script | EXIT_1 witness data | total witness (WU) | approx. tx weight (WU) | approx. vbytes |
|---|---|---|---|---|---|---|
| 8 | 256 | 1,355 | 566 | 2,050 | ≈ 3,000 | ≈ 750 |
| 12 | 4,096 | 1,707 | 726 | 2,562 | ≈ 3,510 | ≈ 880 |
| 16 | 65,536 | 2,059 | 886 | 3,074 | ≈ 4,020 | ≈ 1,005 |
| 20 | 1,048,576 | 2,411 | 1,046 | 3,586 | ≈ 4,540 | ≈ 1,135 |

The transaction weight column adds a fee input (P2WPKH), a change output
and non-witness overhead (≈ 950 WU). Each additional level costs 130 WU
(88 script + 40 path + 2 length prefixes), independent of how many leaves
are occupied.

For comparison, a unilateral exit from a radix-2 Ark or CTV tree of `2^D`
leaves publishes `D` transactions of roughly 600 WU each (about 9,600 WU at
`D = 16`) and waits out a relative timelock at the leaf, while the operator
must publish the whole tree to reclaim expired leaves. LayerTree pays a fixed
cost of about 2,000 WU (the EC-heavy prologue, the leaf, the signature and
the transaction skeleton) plus 130 WU per level, so it breaks even near
`D = 5` (32 leaves) and is about 2.4× cheaper at `D = 16`; the gap widens
with size. The trade-off is that LayerTree requires the
larger opcode set of section 4, whereas CTV-based trees need only a template
opcode.

Varops usage is about 12% of budget at every `D` measured; the constant
term (EC operations and the signature) dominates. `OP_ECSCALARMUL` and
`OP_ECPOINTADD` are each charged as a signature check; if the final costing
is lower, headroom grows.

## 12. Comparison With Related Constructions

*(informative)*

| Property | LayerTree | Ark (rounds + VTXO tree) | Timeout trees | CTV/CCV trees (MATT-style) |
|---|---|---|---|---|
| Unilateral exit cost | 1 tx, `O(1)` in `N`, `O(D)` bytes | `O(log N)` txs | `O(log N)` txs | `O(log N)` txs |
| Operator eviction of one leaf | 1 tx after `evict_after` | not possible; whole tree expires | not possible; whole tree expires | not possible |
| Interactive tree signing | none (covenant enforces root) | all round participants (or CTV) | all participants | none |
| Shared UTXO expiry | none; per-leaf leases | per round | per tree | per design |
| Operator liquidity | none required (self-funded joins); optional for vouchers | must front the new round | must front | varies |
| Batch join | `O(1)` tx for any subtree | per round | per tree | per tree |
| Off-chain payments | channel leaves (LN) or vouchers | OOR + rounds | channels | varies |
| Opcodes | GSR + OP_TX + CSFS + EC add/mul | none (pre-signed) or CTV | none or CTV | CTV/CCV (+CAT) |

Relative to the original LayerTree sketch: the exit no longer needs the
operator's voucher (so the operator cannot withhold exits), the MS-SMT is
replaced by a dense fixed-depth sum tree that script can verify without
loops, and eviction, cooperative update, subtree grafting and single-use
vouchers are added. The sketch's "signed events drive an on-chain state
machine" model survives as `CLAIM`, and its "the contract can accept many
exits in a batch" as `EXIT_K` (section 13).

## 13. Extensions

*(informative)* None of the following is required for conformance.

1. **`EXIT_K`.** Unroll `K` exits in one script; each exit's path is
   verified against the root produced by the previous one and pays output
   `1..K`. Script size grows as `K × (651 + 88·D)`; witness as `K × ~890`.
   Useful for operator-driven batch evictions and cooperative mass exits.
2. **Higher radix.** A radix-4 sum tree halves the number of levels at the
   cost of three 40-byte siblings per level; per-level script grows but
   total witness shrinks for large `D`.
3. **Smaller `LEVEL`.** With `OP_MULTI OP_CAT` the four concatenations per
   level collapse to two; keeping `ZERO8` on the stack replaces the 9-byte
   push in `PAD8` with a 2-byte `OP_PICK`. Together these save roughly 25%.
4. **Aggregate node keys.** Storing a MuSig2 aggregate of all owner keys in
   each node (72-byte `sc`) allows a "replace subtree" transition authorised
   by one aggregate signature, giving Ark-style cooperative round updates
   for whole cohorts in one signature. This reintroduces interactive nonce
   coordination and is left for a separate document.
5. **Hash-locked vouchers.** Including a payment hash in the voucher message
   and requiring the preimage in `CLAIM` turns a voucher into an HTLC,
   enabling atomic swaps between trees, into Lightning, or with on-chain
   funds (the "loop in / loop out" flows of the design notes) and
   third-party liquidity provision: any leaf owner can service a swap by
   issuing a voucher.
6. **Nesting.** A leaf's `exit_key` may be the output key of another
   LayerTree, giving hierarchical trees with constant-size exit at each
   level.
7. **`OP_INTERNALKEY` fast path.** Where only `r` must be checked (never
   for output construction), `OP_INTERNALKEY` saves one `OP_TX` and one
   `TREE_SPK`; see the caveat in section 10.4.

## 14. Test Vectors and Reference Code

* `spec/test-vectors.json` — tag prefixes, `NUMS`, empty nodes `E_0 … E_32`,
  a depth-4 example tree (leaves, root, internal key, output key,
  scriptPubKey, all paths), and one worked vector for each transition type
  including the voucher message. Regenerate with
  `python3 tools/layertree_ref.py`.
* `tools/layertree_ref.py` — data structures, transitions and taproot
  derivation.
* `tools/layertree_scripts.py` — the scripts of section 8 as assembler
  token lists.
* `tools/script_sim.py` — a tapscript `0xC2` subset interpreter modelling
  BIP-441 numerics, `OP_TX`, `OP_CHECKSIGFROMSTACK` and the assumed EC
  opcodes, with BIP-440 varops accounting.
* `tools/test_scripts.py` — executes every script at `D = 4` and `D = 16`
  against the reference tree, including negative cases (forged leaf, stale
  root, attacker-chosen `m`, unconserved amount, underfunded join, join over
  an occupied position, early eviction, evictor shortchange, unsigned update,
  voucher replay, over-claim, wrong voucher signer). Run:
  `python3 tools/test_scripts.py`.
* `spec/scripts/` — annotated listings for `D = 4` and the size table.

The simulator is a design-validation tool, not consensus code; its `OP_TX`
and signature-hash models are simplified as documented in its header.

## 15. References

* BIP-340, BIP-341, BIP-342 — Schnorr signatures, Taproot, Tapscript.
* BIP-440 — Varops Budget For Script Runtime Constraint (Russell, Moik).
* BIP-441 — Restoration of disabled script (Tapleaf 0xC2) (Russell, Moik).
* BIP-348 — `OP_CHECKSIGFROMSTACK` (Black, Rubin).
* BIP-349 — `OP_INTERNALKEY` (Black, Rubin).
* Draft "OP_TX" and "New Opcodes for Tapscript v2" (Russell, Moik),
  `https://github.com/rustyrussell/bips/pull/1`.
* "[0/4] A Bitcoin Scripting Proposal BIP Quartet", bitcoindev,
  `https://groups.google.com/g/bitcoindev/c/GisTcPb8Jco/m/8znWcWwKAQAJ`.
* BIP-443 — `OP_CHECKCONTRACTVERIFY` (Ingala): the data-tweaked internal
  key used here follows the same pattern.
* Merkle Sum Sparse Merkle Trees, Taproot Assets BIP draft (Osuntokun).
* Ark protocol documentation (Ark Labs; Second).
* `design/unified-batching.md` — the essay in which LayerTree was first
  described; `design/review.md` — the scrutiny that produced this document.
