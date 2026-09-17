# LayerTree: Constant-Size Exit and Eviction for Shared Bitcoin UTXOs

```
Title:    LayerTree
Layer:    Applications (requires consensus changes listed in section 4)
Status:   Draft
Version:  0.6.0
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

Appendix C. [Channel Leaves](channel-leaves.md) (separate file, normative)

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
transaction introspection (`OP_TX`), `OP_CHECKSIGFROMSTACK`, and the
elliptic-curve opcodes of the "Elliptic Curve Operations for Bitcoin Script"
draft BIP (`OP_EC_POINT_ADD`, `OP_EC_POINT_MUL`, `OP_EC_POINT_X_COORD`).

Two tree profiles are specified over the same scripts: a **dense** tree with
operator-assigned positions and constant-size subtree grafting, and a
**sparse** key-addressed Merkle-sum tree (a truncated MS-SMT) with
compressed proofs, in which positions are derived from the owner's key.

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
* `enc64(n) = le64(n) || 0x01`, the 9-byte encoding used for sums inside
  node hashes. It is exactly the BIP-441 minimal little-endian encoding of
  `n + 2^64`, so a script produces it from a computed sum with a single
  `OP_ADD` (section 8.2).
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
  `hash || enc64(sum)` (41 bytes), abbreviated `sc`.

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
2. **Depth is a cost knob, and both tree shapes are specified.** Script has
   no loops, so every proof level is unrolled at 88–134 bytes of script. A
   full 256-level MS-SMT therefore costs about 35 kB of script per exit
   (section 11). The spec keeps the MS-SMT's key-addressed shape as the
   *sparse profile* at a truncated depth (32–64 levels, positions derived
   from `H(owner_key || nonce)`, empty siblings compressed away, direction
   bits derived rather than supplied), and adds a *dense profile* with
   operator-assigned positions that costs about half as much per exit and
   supports grafting whole subtrees of new members in one transaction.
   Non-inclusion proofs are ordinary inclusion proofs of the empty node in
   both profiles.
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

   off-chain: binary Merkle-sum tree, depth D, 2^D positions
              dense profile:  positions assigned by the operator
              sparse profile: position = low D bits of H_pos(owner_key || nonce)
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

**Design constraint.** LayerTree proposes no opcodes. It is a composition of
opcodes that already exist or are already proposed by others as general
primitives: the BIP-342 tapscript set, the BIP-441 restorations, `OP_TX`,
`OP_CHECKSIGFROMSTACK` and the elliptic-curve opcodes of the EC ops draft.
Section 4.3 is the complete inventory; `tools/test_scripts.py` fails if any
reference script uses an opcode outside it. Section 4.4 identifies the
irreducible subset. Where this document could have
been made cheaper by a purpose-built opcode (a Merkle-sum step, a taproot
tweak check, a loop), it deliberately is not.

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
   `OP_LEFT`, `OP_RIGHT`, `OP_AND`, `OP_DOWNSHIFT`; arbitrary-length unsigned
   integers; 4,000,000-byte stack elements; the modified success rule (a
   single non-zero element). All LayerTree scripts are tapleaf version
   `0xC2`.
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
6. **Elliptic-curve opcodes** as in the draft BIP "Elliptic Curve Operations
   for Bitcoin Script" (Osuntokun; `Roasbeef/bips` branch `ec-ops-bip`,
   bitcoin/bips PR #1945): `OP_EC_POINT_ADD` (0xbb; `[point2] [point1]` →
   `point1 + point2`), `OP_EC_POINT_MUL` (0xbc; `[scalar] [point]` with the
   scalar on top, a 32-byte big-endian scalar reduced mod `n`, and the empty
   vector standing for `G`), `OP_EC_POINT_NEGATE` (0xbd, unused here) and
   `OP_EC_POINT_X_COORD` (0xbe; 33-byte point → 32-byte x coordinate). All
   points are 33-byte compressed; the point at infinity is the empty vector.
   Costs are 10, 30, 5 and 1 sigops units respectively (BIP-342 units in
   which `OP_CHECKSIG` is 50); under BIP-440 this is 10,000 varops per unit.
   **[A-3]** The scripts assume these opcodes are available in tapleaf
   version `0xC2` with those costs. **[A-4]** That draft assigns `0xbd` to
   `OP_EC_POINT_NEGATE` and the `OP_TX` draft assigns `0xbd` to `OP_TX`;
   BIP-443 also claims `0xbb`. The final numbering is out of scope here and
   does not affect the design; the reference simulator parks `OP_TX` at
   `0xbf` as a placeholder.

### 4.2 Not required

* `OP_INTERNALKEY` is not used: the scripts verify the full input
  scriptPubKey instead (section 6.4), which also binds the taptree root.
* `OP_MULTI`, `OP_SEGMENT`, `OP_BYTEREV`, `OP_EC_POINT_NEGATE` are not
  used. Section 13 notes optimisations that would use them if they ship.
* No `OP_CHECKTEMPLATEVERIFY`, `OP_TEMPLATEHASH`, `OP_CHECKCONTRACTVERIFY`
  or `SIGHASH_ANYPREVOUT` is required by the tree itself. Section 9.8 notes
  where rebindable signatures help *leaf-level* constructions.

### 4.3 Opcode inventory

The reference scripts of section 8 use exactly the following opcodes and no
others. The "source" column names the document that defines each one.

| Source | Opcodes |
|---|---|
| BIP-342 tapscript (unchanged) | `OP_0`…`OP_16` pushes, `OP_DUP`, `OP_2DUP`, `OP_DROP`, `OP_2DROP`, `OP_NIP`, `OP_OVER`, `OP_PICK`, `OP_ROLL`, `OP_ROT`, `OP_SWAP`, `OP_2SWAP`, `OP_TUCK`, `OP_TOALTSTACK`, `OP_FROMALTSTACK`, `OP_IF`, `OP_NOTIF`, `OP_ELSE`, `OP_ENDIF`, `OP_VERIFY`, `OP_EQUAL`, `OP_EQUALVERIFY`, `OP_SIZE`, `OP_SHA256`, `OP_CHECKSIGVERIFY`, `OP_CHECKLOCKTIMEVERIFY` |
| BIP-441 (0xC2 numeric semantics) | `OP_ADD`, `OP_1ADD`, `OP_SUB`, `OP_NOT`, `OP_0NOTEQUAL`, `OP_NUMEQUAL`, `OP_NUMEQUALVERIFY`, `OP_LESSTHANOREQUAL` (arbitrary-length unsigned) |
| BIP-441 (restored) | `OP_CAT`, `OP_SUBSTR`, `OP_LEFT`, `OP_RIGHT`, `OP_AND`, `OP_DOWNSHIFT` |
| `OP_TX` draft | `OP_TX` (selectors of section 8.1 only) |
| BIP-348 | `OP_CHECKSIGFROMSTACK` (`CLAIM` only) |
| EC ops draft BIP | `OP_EC_POINT_MUL`, `OP_EC_POINT_ADD`, `OP_EC_POINT_X_COORD` |

`OP_AND` and `OP_DOWNSHIFT` are used only by the sparse profile (to read
one bit of the position hash). `OP_EC_POINT_NEGATE`, `OP_INTERNALKEY`,
`OP_MULTI`, `OP_SEGMENT`, `OP_BYTEREV`, `OP_CHECKTEMPLATEVERIFY`,
`OP_TEMPLATEHASH`, `OP_CHECKCONTRACTVERIFY` and `OP_PAIRCOMMIT` are not
required.

### 4.4 Minimal opcode set

*(informative, with measurements)* Section 4.3 lists what the reference
scripts use. This section answers a different question: what is the
smallest subset of the candidate opcodes with which LayerTree can be built
at all, using ordinary script tricks in place of convenience opcodes.

| Need | Reference scripts use | Minimal alternative | Cost of the alternative |
|---|---|---|---|
| Concatenation for hash preimages, `P2TR` construction | `OP_CAT` | none: `OP_CAT` is irreducible (`OP_PAIRCOMMIT` can hash pairs but cannot build the 34-byte scriptPubKey) | — |
| 8-byte satoshi arithmetic | BIP-441 numerics (`OP_ADD`, `OP_SUB`, `OP_NUMEQUAL`, `OP_LESSTHANOREQUAL` on arbitrary length) | none within tapleaf `0xC2`; under 4-byte `CScriptNum` one would split sums into 32-bit limbs with witness-supplied carries | — |
| Padding a computed sum to a fixed width | `2^64 OP_ADD` (`enc64`) | already minimal: no `OP_LEFT`/`OP_RIGHT`; this is why sums are hashed as `enc64` | 0 |
| Field extraction from a leaf or `sc` | `OP_SUBSTR`, `OP_LEFT`, `OP_RIGHT` | supply the fields as separate witness elements, check each with `OP_SIZE`, re-join with `OP_CAT` to hash the leaf | ≈ +17 bytes of script per level, +7 witness elements per leaf |
| Reading one bit of the position hash (sparse) | `OP_DOWNSHIFT`, `OP_AND` | supply `dir` bits in the witness; accumulate `acc += dir ? pw : 0`, `pw += pw` with `OP_IF`/`OP_ADD`; check `acc` against the low `D/8` bytes of `H_pos`, which are verified by `CAT`-joining them with the remaining bytes and comparing to the hash | ≈ +6 bytes per level, +1 witness byte per level |
| Taproot output key recomputation | `OP_EC_POINT_MUL`, `OP_EC_POINT_ADD`, `OP_EC_POINT_X_COORD` | BIP-449 `OP_TWEAKADD` (`[tweak32 pubkey32] → x(P + t·G)`), applied twice: once with `NUMS` and the state tweak, once with the resulting key and the TapTweak | −12 bytes per `TREE_SPK`; cost 50 sigops units per use vs 41 |
| Transaction introspection | `OP_TX` | `OP_CHECKSIG` with the generator as public key and a signature whose `s` equals `e + 1`, so that the script must reconstruct the BIP-341 signature message from witness-supplied serialisations of prevouts, amounts, scriptPubKeys and outputs, hash it, and pick the fields it needs from those serialisations with `OP_CAT` and `OP_SIZE` | several hundred witness bytes and about a dozen hashes per introspection; grinding the transaction until `e` has no carry into `s` |
| Signature over an arbitrary message (`CLAIM` vouchers) | `OP_CHECKSIGFROMSTACK` | none; a voucher is not a transaction signature. Drop `CLAIM` if `OP_CHECKSIGFROMSTACK` is unavailable | — |
| Owner/evictor/operator authorisation, lock time, hashing, stack work | BIP-342 | — | — |

Hence the irreducible core is **BIP-342 tapscript, the BIP-441 numeric
semantics (or tapleaf `0xC2` generally), `OP_CAT`, and one EC tweak
primitive**. `OP_TX` is replaceable in principle but not in practice, and
`OP_CHECKSIGFROMSTACK` is needed only for vouchers. Every restored splice,
bit and shift opcode is a convenience.

Section 4.5 makes the claim concrete with three complete script tiers.
Two intermediate data points are also measured: `exit_script_min` in
`tools/layertree_scripts.py` keeps the BIP-441 numerics but drops every
splice opcode and the EC point opcodes (`OP_TX` + `OP_TWEAKADD`), costing
2,378 bytes at `D = 16` against 2,101; the MIN tier drops `OP_TX` as well
and pays 3,572.

### 4.5 Opcode tiers

Every transition in this document is specified once, in section 7, and
implemented three times, against three opcode sets. A tree is created for
one tier; its tapleaf version and scripts follow from it. The tree format
(section 5) is the same in every tier, so proofs, roots and off-chain data
are interchangeable, with one numeric cap noted below.

| | **FULL** | **MID** | **MIN** |
|---|---|---|---|
| Tapleaf version | `0xC2` (BIP-441) | `0xC0` | `0xC0` |
| Numerics | arbitrary length, unsigned | `CScriptNum`, 4-byte operands | `CScriptNum`, 4-byte operands |
| Beyond BIP-342 | `OP_CAT`, `OP_SUBSTR`, `OP_LEFT`, `OP_RIGHT`, `OP_AND`, `OP_DOWNSHIFT`; `OP_TX`; `OP_CHECKSIGFROMSTACK`; `OP_EC_POINT_MUL/ADD/X_COORD` | `OP_CAT`; `OP_TX` (assumed in `0xC0`, **[A-5]**); `OP_CHECKSIGFROMSTACK`; `OP_TWEAKADD` | `OP_CAT`; `OP_TWEAKADD` |
| Introspection | `OP_TX` | `OP_TX` | constructive: the script rebuilds the BIP-341 sighash message and checks a generator-key signature with `OP_CHECKSIG` (section 4.4) |
| Leaf on the stack | one 116-byte element, fields by `OP_SUBSTR` | seven field elements, rejoined by `OP_CAT` under `OP_SIZE` checks | as MID |
| Fixed-width numbers | `2^64 OP_ADD` | `PADZ`: witness zero pad `z`, filler `w`, `z||w = 00000000`, `size(x)+size(z) = 4` | as MID |
| Sum limit per tree | none (< 2^51 by leaf rule) | every sum < 2^31 sat | every sum < 2^31 sat |
| Payout amount | owner: ≤ leaf amount; evictor: exact | exact for both | exact for both |
| Sparse positions | bit `k` of `H_pos` by `OP_DOWNSHIFT`/`OP_AND`; `D ≤ 64` typical | witness `dir` bits folded into an accumulator compared with `pos_lo` (first 4 bytes of `H_pos`, supplied split as `pos_lo || pos_hi`); `nonce` chosen so `pos_lo` is a minimal positive `CScriptNum`; `D ≤ 31` | as MID |
| `CLAIM` (vouchers) | yes | yes | no (needs `OP_CHECKSIGFROMSTACK`) |
| Channel leaves (Appendix C) | yes | yes (`OP_TX` + `OP_CHECKSIGFROMSTACK`) | no: rebindable signatures need `OP_TX`; MIN trees hold plain leaves only |
| `SEQ_FINAL` (non-claimable leaf) | `0xFFFFFFFF` | `0x7FFFFFFF` | n/a (no `CLAIM`) |
| Terminal exit (7.8) | yes | yes | no; output 0 is always the tree output |
| Transaction shape | free (input 0, outputs 0..K constrained) | free | fixed per script: two inputs, outputs `[tree', payouts…, raw extras]` |
| Spender work | none | none | grind a free field (fee input `nSequence`) until `e` ends in `0x00`: 256 hashes expected |
| Reference | `tools/layertree_scripts.py` | `tools/layertree_mid.py` | `tools/layertree_min.py` |

**[A-5]** The `OP_TX` draft defines the opcode for tapleaf `0xC2`. The MID
tier assumes it is also available (with `CScriptNum` outputs for the
"varint or int" fields) in `0xC0`; if it is not, MID collapses into MIN for
introspection and keeps `OP_CHECKSIGFROMSTACK` for vouchers.

Measured sizes at `D = 16` (dense) and `D = 31/32` (sparse), bytes of
script / witness data:

| transition | FULL D | MID D | MIN D | FULL S (32) | MID S (31) |
|---|---|---|---|---|---|
| `EXIT_1` | 2,101 / 902 | 3,299 / 978 | 3,572 / 1,175 | 5,147 / 326 | 9,274 / 796 |
| `JOIN_h` (`h = 2` dense, `h = 0` sparse) | 1,841 / 745 | 2,824 / 794 | — | 5,131 / 367 | 9,254 / 783 |
| `JOINK_2` | 3,545 / 1,525 | 5,749 / 1,637 | — | 9,773 / 606 | 17,985 / 1,433 |
| `UPDATE` | 2,137 / 1,064 | 3,407 / 1,156 | — | 5,283 / 504 | 9,393 / 1,002 |
| `CLAIM` | 3,801 / 1,658 | 6,291 / 1,832 | n/a | 9,767 / 600 | 18,241 / 1,543 |

The MID premium over FULL is about 55% of script for the dense profile and
80% for the sparse profile; almost all of it is the `PADZ` gadgets (two per
level) and the per-field size checks. MIN adds the sighash reconstruction
(about 270 bytes) on top of MID and removes `OP_TX`. The complete table,
including `EXIT_K`, `EVICT_SUBTREE_h`, both compression encodings and the
`FULL`-numerics-without-splice-opcodes data point, is
`spec/scripts/sizes.md`; per-tier listings for `D = 4` are under
`spec/scripts/`.

*(informative)* The tiers answer three different deployment questions.
FULL is what the Great Script Restoration plus the introspection, CSFS and
EC-ops candidates make possible, and is the recommended target. MID is what
a `0xC0`-only soft fork of the LNhance flavour plus `OP_CAT`, `OP_TX` and
`OP_TWEAKADD` would give: everything in this document at roughly 1.6× the
size, with a 21.47 BTC cap per tree. MIN is the existence proof that
`OP_CAT` and one tweak opcode suffice for the covenant itself, at the cost
of vouchers, terminal exits, a fixed transaction shape and a small grinding
step.

### 4.6 Policy assumptions

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
| `TAG_POS` | `"LayerTree/pos"` (sparse profile positions) |
| `NUMS` | BIP-341 `H`: x = `50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0`, compressed `02 || x` |
| `EMPTY_LEAF_HASH` | 32 zero bytes |
| `LEAF_LEN` | 116 |
| `SEQ_FINAL` | `0xFFFFFFFF` (FULL), `0x7FFFFFFF` (MID): the `seq` value that makes a leaf non-claimable (5.2, 7.5) |
| `TAG_CHAN_ID`, `TAG_CHAN_UPD`, `TAG_CHAN_SET` | `"LayerTree/chan/id"`, `"LayerTree/chan/upd"`, `"LayerTree/chan/set"` (Appendix C) |

`H_leaf`, `H_node`, `H_state`, `H_voucher`, `H_pos` denote `H_tag` with the
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
| 108 | 4 | `nonce` | `le32`, chosen at creation; with `owner_key` it identifies the leaf and, in the sparse profile, defines its position |
| 112 | 4 | `seq` | `le32`, incremented by each `CLAIM` against the leaf; MUST NOT wrap |

Requirements:

* `amount` MUST be greater than 0 and less than 2^51.
* `exit_key`, `owner_key` and `evictor_key` MUST each be the x coordinate of
  a point on secp256k1 (i.e. `lift_x` succeeds).
* `evict_after` MUST be less than 500,000,000. A leaf that MUST NOT be
  evictable SHALL set `evictor_key` to a provably unspendable key; `NUMS` is
  RECOMMENDED.
* No two leaves in a tree SHALL share the same `(owner_key, nonce)`. In the
  sparse profile this is structural (both leaves would need the same
  position). In the dense profile creators MUST choose `nonce` so that it
  holds; a uniformly random 32-bit value is RECOMMENDED, and section 10.3
  explains why it matters for vouchers.
* `leaf_hash = H_leaf(leaf_bytes)`; the leaf's node is `(leaf_hash, amount)`.
* A leaf whose `seq` equals `SEQ_FINAL` for the tree's tier is
  **non-claimable**: `CLAIM` (7.5) computes `seq + 1` and fails when the
  result does not fit in four bytes, which is the case exactly for
  `SEQ_FINAL`. Creators MUST set `seq = SEQ_FINAL` on any leaf whose
  `amount` is not the owner's alone (channel leaves, Appendix C.6.5) and MAY
  set it on any other leaf. `SEQ_FINAL` differs between tiers because MID
  interprets `0xFFFFFFFF` as a negative `CScriptNum` whose successor still
  fits; the reference tests check both values in both tiers.
* `evict_after` is a *deferral* of the evictor's right, not a guarantee to
  the evictor. A leaf that must be force-closable by its evictor at any time
  (a routing channel leaf, Appendix C.6.4) SHALL set `evict_after = 0`.

*(informative)* `exit_key` is deliberately distinct from `owner_key`, so a
hot key can authorise while funds land on a cold key, and so that a channel
leaf (section 9.8, Appendix C) can name its funding output key.

### 5.3 Nodes

The **empty leaf** is the node `E_0 = (EMPTY_LEAF_HASH, 0)`.

The **branch hash** of a left node `L = (lh, ls)` and a right node
`R = (rh, rs)` is

```
H_node(lh || enc64(ls) || rh || enc64(rs))
```

and the parent node is `(H_node(...), ls + rs)`. (`enc64` rather than
`le64` costs one byte per sum and removes the need for any truncation
opcode when a script pads a computed sum; see section 4.5.) The sum of a branch is
*defined* as the sum of its children's sums; it is never an independent
input. Verifiers MUST recompute it.

The **empty node of height h**, `E_h`, is the parent of two copies of
`E_{h-1}`. `E_h` for `0 ≤ h ≤ 32` are listed in the test vectors.

### 5.4 Tree and positions

A LayerTree of **depth D** is a complete binary tree with `2^D` leaf
positions numbered `0 .. 2^D − 1`. The node at height `h` and index `i`
covers positions `[i·2^h, (i+1)·2^h)`. Unoccupied positions hold `E_0`.
`D` is fixed at tree creation (section 6.2). A tree has one of two
**profiles**, also fixed at creation:

* **Dense (`D`)**: the operator assigns positions. Subtrees of new leaves
  may be grafted at any height (`JOIN_h`). Implementations SHOULD support
  `D` in the range 8 to 24.
* **Sparse (`S`)**: a leaf's position is derived from the leaf:

  ```
  pos(leaf) = int_le( H_pos( leaf.owner_key || le32(leaf.nonce) ) ) mod 2^D
  ```

  where `int_le` reads the 32-byte hash as a little-endian integer, so the
  direction bit at level `k` is bit `k` of the hash. Only single-leaf joins
  exist (`JOIN_0`), the root is history-independent (a function of the leaf
  set alone), and non-inclusion of `(owner_key, nonce)` is proven by an
  inclusion proof of `E_0` at its position. A position collision on join is
  detected by that proof and resolved by choosing another `nonce`.
  Implementations SHOULD support `D` in the range 32 to 64; `D = 256`
  (the full MS-SMT) is valid but costs about 35 kB of script per exit
  (section 11).

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

In witnesses of the **dense** profile, each level is supplied as two
elements: `dir` (the empty string for 0, `0x01` for 1, per BIP-342
`MINIMALIF`) and `sc = sib.hash || le64(sib.sum)`. In the **sparse** profile
only `sc` is supplied, and `sc` MAY be the empty string when the sibling is
the empty node `E_k` of that level (a *compressed* proof); the script derives
`dir` from the leaf and computes `E_k` itself. A non-empty `sc` that is not
exactly 41 bytes MUST be rejected (the scripts enforce this). A compressed
proof for a tree of `N` leaves has about `log2 N` non-empty siblings.

*(informative)* The MS-SMT BIP compresses proofs with a bitmap of empty
levels followed by only the non-empty nodes. That is the RECOMMENDED
**off-chain** wire format between operator and participants (a `ceil(D/8)`
byte bitmap plus `41·(non-empty)` bytes). **On-chain** the empty-element
form is cheaper: with a bitmap each level must extract a bit and
conditionally roll a witness element, which the reference implementation
measured at 276 bytes more script at `D = 32` and 564 more at `D = 64`,
against a saving of `D − ceil(D/8)` witness bytes. Both encodings are
implemented in `tools/layertree_scripts.py` (`COMPRESSION`); the bitmap
variant exists only to make the comparison measurable.

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

* the profile (dense or sparse);
* `D`, the depth;
* `OPERATOR_KEY`, a 32-byte x-only key;
* the set of supported `JOIN` heights (dense) and `EXIT_K` sizes.

A conforming taptree MUST contain `EXIT_1`. It SHOULD contain at least one
`JOIN_h` (`JOIN_0` in the sparse profile), and MAY contain `UPDATE`, `CLAIM`
and further variants (section 7.6). Scripts MUST NOT reference the taptree's own Merkle root; the scripts
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
     of `tx` for input 0 by `leaf.owner_key`, with a hash type that commits
     to all outputs (`SIGHASH_DEFAULT` or `SIGHASH_ALL`, with or without
     `ANYONECANPAY`). The covenant fixes output 1's script but only bounds
     its amount, so a signature that does not cover outputs would let a
     relayer divert the difference to fees;
   * output 1's amount MUST be less than or equal to `leaf.amount`. The
     difference, if any, is available to the transaction as fee or for other
     outputs; the owner consented to it by signing.
4. If `is_evict` is true (eviction):
   * `sig` MUST be a valid signature over `tx` by `leaf.evictor_key`, with
     the same hash-type requirement;
   * `tx.nLockTime` MUST be at least `leaf.evict_after` and input 0's
     `nSequence` MUST enable lock-time (`OP_CHECKLOCKTIMEVERIFY` semantics);
   * output 1's amount MUST equal `leaf.amount`.
5. The recomputed total `S` equals input 0's amount, and output 0's amount
   equals `S − leaf.amount` (this follows from `fold` of `E_0`).
6. **Exact-payout variant `EXIT_K^=`.** A tree MAY be created with `EXIT_K`
   scripts in which rule 3's inequality is replaced by equality, so that
   output `i`'s amount MUST equal `leaf.amount` for owner exits as well as
   evictions and all fees are exogenous. The variant is a tree-creation
   parameter; it changes the scripts and therefore `m`, so any party can
   tell from the tree identifier which rule applies. MID and MIN trees are
   always exact (4.5). A tree that hosts channel leaves SHOULD use the
   exact variant (Appendix C.6.1). The reference generator exposes it as
   `exit_script(…, exact=True)`; it is four bytes shorter than `EXIT_K`.

### 7.3 JOIN

`JOIN_h` grafts a subtree of height `h` into an empty position. `h = 0`
inserts a single leaf. The sparse profile supports `h = 0` only, and its
witness carries the full new leaf (so that the script can derive the
position) instead of `(new_hash, new_sum)`. **`JOINK_K`** applies `K`
single-leaf joins in sequence under one operator signature, exactly as
`EXIT_K` sequences exits (section 7.6); it is the batching primitive of the
sparse profile, whose derived positions cannot be grafted as a subtree.

Witness inputs (dense): sibling path of the node at height `h` (`D − h`
levels), `new_hash` (32 bytes), `new_sum` (8 bytes `le64`), `sig`, `r`,
`m`. Witness inputs (sparse): compressed sibling path (`D` levels),
`new_leaf`, `sig`, `r`, `m`; the old node is `E_0` at `pos(new_leaf)`.

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
   transfer), `evict_after` (lease renewal) and `exit_key`. In the sparse
   profile `pos(new_leaf)` MUST equal `pos(old_leaf)` (the script compares
   the two derived position hashes), so `owner_key` and `nonce` are in
   practice fixed; ownership transfer is done by `EXIT`+`JOIN` or `CLAIM`.

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
   and `seq' = source_leaf.seq + 1` (the script fails if `seq'` does not
   fit in 4 bytes, so a source leaf with `seq = SEQ_FINAL` can never be
   claimed; section 5.2); if `amount' = 0` the new node is `E_0` instead
   (the position becomes empty). In the sparse profile the source position is
   `pos(source_leaf)` and the claim position is `pos(claim_leaf)`. `fold` over the source path MUST yield
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
(section 9.6). The voucher binds the source leaf by content, not position,
which is why section 5.2 forbids two leaves with the same
`(owner_key, nonce)`: two identical leaves would let one voucher be redeemed
against each. In the sparse profile this cannot occur.

### 7.6 Composition and variants

Transition types compose by sequencing: a script that applies transitions
`T_1 … T_K` treats the root produced by `T_i` as the current root of
`T_{i+1}`, verifies the old-state proof (rule 3) only for `T_1`, and applies
rules 2 and 5 only to the final root. `CLAIM` is the composition of an
`UPDATE`-like step and a `JOIN_0`-like step with a different authorisation.

**`EXIT_K`** and **`JOINK_K`** apply `K` `EXIT` or single-leaf `JOIN` steps
in order. For `EXIT_K`: Step `i` (1-based) pays
output `i`, is authorised independently (owner or evictor, each with its own
`sig` and `is_evict`), and proves its leaf against the root produced by step
`i − 1` (step 1 against `r`). Steps MUST name distinct positions (a repeated
position fails, since the leaf is `E_0` after step 1). Output 0 receives the
total after all `K` removals. A taptree MAY include `EXIT_K` for any set of
`K`; section 8.3 gives the script.

**Shape-specialised multiproofs.** Sequential composition verifies each
step's full path, so `K` steps cost `K·D` levels even when the positions
share most of their paths. Because script has no loops but a taptree can
hold many leaves, a tree MAY instead include scripts whose *shape* is fixed:
the set of positions they act on is known at script-generation time, the
internal nodes of the union of paths are hashed exactly once each, and every
stack depth is static, so no runtime flags are needed. This document defines
one such shape, `EVICT_SUBTREE_h` (section 7.7); others (sibling pairs,
partially filled subtrees, multi-exit within a subtree) follow the same
construction. A general "any `K` positions" multiproof driven by witness
flags is possible but saves only witness bytes and hashing, not script,
because each unrolled step must carry both branches.

Implementations MAY define further combined scripts provided each component
enforces the rules of its type.

### 7.7 EVICT_SUBTREE_h (cohort sweep)

`EVICT_SUBTREE_h` evicts every remaining leaf of one aligned subtree of
height `h` in a single spend. It is intended for cohorts: the operator
grafts a batch of members into one aligned subtree with a common
`evict_after` (`JOIN_h`), and sweeps the subtree once the lease has
expired.

Witness inputs: sibling path of the subtree root (`D − h` levels), the
`2^h` leaf positions in position order (each either the 116-byte leaf or the
empty string for an empty position), `sig`, `r`, `m`.

Rules:

1. `sig` MUST be a valid signature over `tx` by `OPERATOR_KEY` (hash type
   as in section 7.2).
2. For every non-empty position, in position order: the leaf's
   `evictor_key` MUST equal `OPERATOR_KEY`; `tx.nLockTime` MUST be at least
   its `evict_after`; and the next unused output, starting from output 1,
   MUST pay exactly `leaf.amount` to `P2TR(leaf.exit_key)`.
3. The old node is the subtree root recomputed from the supplied leaves
   (empty positions contribute `E_0`); it MUST `fold` with the path to
   `(r, S)` with `S` equal to input 0's amount.
4. The new node is `E_h`. Output 0 is `(S − subtree sum, TREE_SPK(r', m))`
   per section 7.1, or unconstrained if `r' = E_D` (section 7.8).

A leaf whose `evictor_key` is not `OPERATOR_KEY` blocks the sweep; the
operator MUST remove it with `EXIT` (if it is evictable by some other key
it controls) or wait for its owner. Owners who do not want to be swept with
their cohort set a different evictor at join time.

### 7.8 Terminal transitions

If the post-transition root `r'` equals `E_D` (every position is empty),
rules 7.1.2 and 7.1.5 do not apply: output 0 is unconstrained, and the
transaction MUST still contain an output 0 for the payouts to be numbered
from 1. This lets the last participant leave without creating a zero-value
tree output. Only `EXIT` can produce `E_D`. Scripts MUST take this branch
only when `r' = E_D` exactly; the reference `FINAL` macro compares against
the constant `E_D` of the tree's depth.

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
| `SEL_CHAN_UPD` | `COLLATE \| VERSION \| LOCKTIME \| NUM_INPUTS \| INPUT_SEQUENCE(CURRENT) \| OUTPUT_AMOUNT \| OUTPUT_SCRIPT (all outputs)` | `0x0FC7` | one collated hash of the fields a rebindable channel signature covers (Appendix C.2) |
| `SEL_CHAN_SET` | `SEL_CHAN_UPD \| INPUT_AMOUNT(CURRENT)` | `0x30FC7` | as above plus the current input's amount (settlement transactions, Appendix C.2) |

The last two are used only by the channel scripts of Appendix C, never by
the tree scripts. Scripts MUST push selectors as constants. They never construct a selector at
run time, so the `OP_TX` "unknown bit means success" rule cannot be
triggered by a witness.

### 8.2 Macros

**`TAGGED(prefix)`** — `[msg] → [H_tag(msg)]`

```
<prefix64> OP_SWAP OP_CAT OP_SHA256
```

**`PAD8`** — `[n] → [enc64(n)]` for `n < 2^64`. A single addition: the
minimal encoding of `n + 2^64` is `le64(n) || 0x01`. (For `n ≥ 2^64` the
result is longer than 9 bytes and every use in this document is followed by
a check that then fails, see section 10.6.)

```
<2^64> OP_ADD
```

**`LE64`** — `[n] → [le64(n)]`, used only where a raw 8-byte field is
rebuilt (`CLAIM`'s new source amount): `PAD8 OP_8 OP_LEFT`.

**`LEAF_ACC`** — `[leaf] → [H_leaf(leaf) amount]`

```
OP_DUP OP_8 OP_LEFT OP_SWAP TAGGED(TAG_LEAF) OP_SWAP
```

**`TREE_SPK`** — `[r m] → [TREE_SPK(r, m)]`

```
OP_SWAP TAGGED(TAG_STATE)                    # m t
OP_0 OP_SWAP OP_EC_POINT_MUL                 # m t·G          (empty point = G)
<NUMS33> OP_EC_POINT_ADD                     # m P
OP_EC_POINT_X_COORD                          # m x(P)
OP_TUCK OP_SWAP OP_CAT                       # x(P) (x(P)||m)
TAGGED(TapTweak)                             # x(P) t2
OP_0 OP_SWAP OP_EC_POINT_MUL                 # x(P) t2·G
OP_SWAP <0x02> OP_SWAP OP_CAT                # t2·G (02||x(P))
OP_EC_POINT_ADD OP_EC_POINT_X_COORD          # x(Q)
<0x5120> OP_SWAP OP_CAT                      # scriptPubKey
```

`TREE_SPK` is 193 bytes and costs 82 sigops units (820,000 varops).

**`LEAF_POS`** (sparse) — `[leaf] → [leaf pos_hash]`

```
OP_DUP 40 32 OP_SUBSTR OP_OVER 108 OP_4 OP_SUBSTR OP_CAT TAGGED(TAG_POS)
```

**`SPARSE_SETUP`** — `[pos_hash] → [] | … pos_hash E_0.hash`; the two
altstack items are consumed level by level and dropped by `CHECK_OLD` /
`CHECK_PREV` (`SPARSE_TEARDOWN` = `OP_FROMALTSTACK OP_DROP` twice).

```
OP_TOALTSTACK <EMPTY_LEAF_HASH> OP_TOALTSTACK
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
OP_SIZE 41 OP_EQUALVERIFY                #   sc is exactly hash||enc64(sum)
OP_DUP 32 OP_8 OP_SUBSTR                 # … dir sc ss8   (the raw le64, usable as a number)
OP_DUP OP_TOALTSTACK                     # | ss8
OP_3 OP_ROLL OP_TUCK OP_ADD              # T oh os nh dir sc ns ns'
OP_TOALTSTACK PAD8                       # T oh os nh dir sc ns9      | ss8 ns'
OP_3 OP_ROLL OP_SWAP OP_CAT              # T oh os dir sc nc          (nc = nh||enc64(ns))
OP_OVER OP_SWAP OP_3 OP_PICK             # T oh os dir sc sc nc dir
OP_NOTIF OP_SWAP OP_ENDIF OP_CAT         # T oh os dir sc pre_n       (dir? sc||nc : nc||sc)
OP_5 OP_PICK OP_SWAP OP_CAT OP_SHA256    # T oh os dir sc nh'
OP_TOALTSTACK                            #                            | ss8 ns' nh'
OP_FROMALTSTACK OP_FROMALTSTACK OP_FROMALTSTACK   # T oh os dir sc nh' ns' ss8
OP_5 OP_ROLL OP_TUCK OP_ADD              # T oh dir sc nh' ns' os os'
OP_TOALTSTACK PAD8                       # T oh dir sc nh' ns' os9    | os'
OP_5 OP_ROLL OP_SWAP OP_CAT              # T dir sc nh' ns' oc        (oc = oh||enc64(os))
OP_3 OP_ROLL OP_SWAP OP_4 OP_ROLL        # T nh' ns' sc oc dir
OP_NOTIF OP_SWAP OP_ENDIF OP_CAT         # T nh' ns' pre_o
OP_3 OP_PICK OP_SWAP OP_CAT OP_SHA256    # T nh' ns' oh'
OP_FROMALTSTACK OP_2SWAP                 # T oh' os' nh' ns'
```

`LEVEL` is 88 bytes. `dir` MUST be the empty string or `0x01`; any other
encoding fails `OP_NOTIF` under `MINIMALIF`.

**`LEVEL_S(k)`** (sparse) — before: `sc T oh os nh ns | … pos E_k`; after:
`T oh' os' nh' ns' | … pos E_{k+1}`. It replaces the first two `OP_ROLL`s
of `LEVEL` with the following prologue and then continues from
`OP_SIZE 40 OP_EQUALVERIFY`:

```
OP_5 OP_ROLL                             # T oh os nh ns sc
OP_FROMALTSTACK                          # … sc E_k                 | pos
OP_SWAP OP_SIZE OP_0NOTEQUAL
OP_NOTIF OP_DROP OP_DUP <ENC0> OP_CAT OP_ENDIF    # … E_k sc   (sc := E_k||enc64(0) if empty)
OP_SWAP <ENC0> OP_CAT OP_DUP OP_CAT      # … sc (E_k||enc64(0)||E_k||enc64(0))
OP_6 OP_PICK OP_SWAP OP_CAT OP_SHA256    # … sc E_{k+1}
OP_FROMALTSTACK OP_DUP OP_TOALTSTACK     # … sc E_{k+1} pos         | pos
OP_SWAP OP_TOALTSTACK                    # … sc pos                 | pos E_{k+1}
<k> OP_DOWNSHIFT <0x01> OP_AND OP_0NOTEQUAL   # … sc dir   (bit k of pos)
OP_SWAP                                  # T oh os nh ns dir sc
```

`LEVEL_S` is 135 bytes. Because `dir` is computed, a witness cannot
place a leaf anywhere but at `pos(leaf)`.

**`CHECK_OLD`** — `[T oh os nh ns] | … r → [T nh ns] | …`; requires
`os == amount(input 0)` and `oh == r`. (Sparse: `SPARSE_TEARDOWN` is
inserted before the final `OP_FROMALTSTACK`; likewise in `CHECK_PREV`.)

```
OP_2SWAP <SEL_IN_AMOUNT> OP_TX OP_NUMEQUALVERIFY OP_FROMALTSTACK OP_EQUALVERIFY
```

**`FINAL`** — `[T nh ns] | m → [1]`; requires output 0 to be
`(ns, TREE_SPK(nh, m))` unless `nh = E_D` (section 7.7).

```
OP_ROT OP_DROP                                       # nh ns
OP_OVER <E_D.hash> OP_EQUAL
OP_IF   OP_2DROP OP_FROMALTSTACK OP_DROP OP_1        # terminal: 1
OP_ELSE OP_SWAP OP_FROMALTSTACK TREE_SPK             # ns spk'
        OP_0 <SEL_OUT_SINGLE> OP_TX                  # ns spk' amt0 spk0
        OP_ROT OP_EQUALVERIFY OP_NUMEQUAL            # 1
OP_ENDIF
```

**`CHECK_PREV`** — `[T oh os nh ns] | … nh_p ns_p → [T nh ns]`; requires
`os == ns_p` and `oh == nh_p`. Used between steps of `EXIT_K`.

```
OP_2SWAP OP_FROMALTSTACK OP_NUMEQUALVERIFY OP_FROMALTSTACK OP_EQUALVERIFY
```

### 8.3 EXIT_K

Witness (bottom → top): `block_K … block_1  r  m`, where
`block_i = dir_{D-1} sc_{D-1} … dir_0 sc_0  leaf_i  sig_i  is_evict_i`
(dense) or `block_i = sc_{D-1} … sc_0  leaf_i  sig_i  is_evict_i` (sparse).
Block 1 is nearest the top and is processed first. In the sparse profile
`LEAF_POS SPARSE_SETUP` is inserted before `LEAF_ACC` in `EXIT_BLOCK`, and
`LEVEL_S(k)` replaces `LEVEL`.

```
PROLOGUE                                           # leaf sig is_evict     | m r
EXIT_BLOCK(1)  CHECK_OLD                           # T nh ns               | m
for i in 2..K:
  OP_SWAP OP_TOALTSTACK OP_TOALTSTACK OP_DROP      # leaf sig is_evict     | m nh ns
  EXIT_BLOCK(i)  CHECK_PREV                        # T nh ns               | m
FINAL
```

**`EXIT_BLOCK(i)`** — `[path] leaf sig is_evict → T oh os nh ns` after `D`
levels; pays output `i`:

```
OP_DUP OP_TOALTSTACK                               #                       | … is_evict
OP_IF                                              # -- eviction --
  OP_OVER 104 OP_4 OP_SUBSTR OP_CHECKLOCKTIMEVERIFY OP_DROP
  OP_OVER 72 32 OP_SUBSTR                          # leaf sig evictor_key
OP_ELSE                                            # -- owner exit --
  OP_OVER 40 32 OP_SUBSTR                          # leaf sig owner_key
OP_ENDIF
OP_CHECKSIGVERIFY                                  # leaf
OP_SIZE 116 OP_EQUALVERIFY
<i> <SEL_OUT_SINGLE> OP_TX                        # leaf amt_i spk_i
<0x5120> OP_3 OP_PICK OP_8 32 OP_SUBSTR OP_CAT     # leaf amt_i spk_i P2TR(exit_key)
OP_EQUALVERIFY                                     # leaf amt_i
OP_OVER OP_8 OP_LEFT                               # leaf amt_i leaf.amount
OP_FROMALTSTACK                                    # leaf amt_i leaf.amount is_evict
OP_IF OP_NUMEQUALVERIFY OP_ELSE OP_LESSTHANOREQUAL OP_VERIFY OP_ENDIF
LEAF_ACC                                           # oh os
<TAG_NODE> OP_ROT OP_ROT                           # T oh os
<EMPTY_LEAF_HASH> OP_0                             # T oh os E_0.hash 0
LEVEL × D
```

Size of `EXIT_1`: `693 + 88·D` bytes dense (1,045 at `D = 4`; 2,101 at
`D = 16`) and `≈ 830 + 135·D` bytes sparse (5,147 at `D = 32`). Each further
step adds `~118 + 88·D` (dense) or `~130 + 135·D` (sparse) bytes of script
and `~230 + 42·D` (dense) or `~250 + 41·log2 N` (sparse) bytes of witness
data.

### 8.4 JOIN_h and JOINK_K

Witness: `block_K … block_1  sig  r  m`, with `block_i` =
`dir_{D-1} sc_{D-1} … dir_h sc_h  new_hash  new_sum8` (dense) or
`sc_{D-1} … sc_0  new_leaf` (sparse, `h = 0`); `JOIN_h` is the case
`K = 1`. The operator's signature is checked once, immediately after
`PROLOGUE`; each block then supplies its node (`LEAF_POS SPARSE_SETUP
LEAF_ACC` in the sparse profile) and runs `D − h` levels, chained through
`CHECK_OLD` for the first block and `CHECK_PREV` for the rest, as in
`EXIT_K`.

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

Witness: `path(D)  old_leaf  new_leaf  owner_sig  operator_sig  r  m`.
Sparse: after the size checks the script computes `LEAF_POS` of both leaves
and `OP_EQUALVERIFY`s them, then `LEAF_POS SPARSE_SETUP` on `old_leaf`.

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
consumed second). Sparse: `LEAF_POS SPARSE_SETUP` is applied to
`source_leaf` before the first pass and to `claim_leaf` before the second.

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
OP_OVER OP_8 OP_LEFT OP_OVER OP_8 OP_LEFT OP_SUB LE64      # src claim le64(src.amt − claim.amt)
OP_2 OP_PICK OP_8 104 OP_SUBSTR OP_CAT              # … || src[8:112]
OP_2 OP_PICK 112 OP_4 OP_SUBSTR OP_1ADD
OP_SIZE OP_4 OP_LESSTHANOREQUAL OP_VERIFY PAD4 OP_CAT   # src claim src'   (seq+1 must fit 4 bytes)
OP_FROMALTSTACK OP_ROT OP_TOALTSTACK OP_TOALTSTACK  # src src'              | m claim r
<TAG_NODE> OP_ROT OP_ROT                            # T src src'
OP_SWAP LEAF_ACC                                    # T src' oh os
OP_ROT LEAF_ACC                                     # T oh os nh ns
OP_DUP OP_NOT OP_IF OP_SWAP OP_DROP <EMPTY_LEAF_HASH> OP_SWAP OP_ENDIF   # ns == 0 → nh = E_0.hash
LEVEL × D                                           # (source path)
CHECK_OLD                                           # T r1 S1               | m claim
OP_FROMALTSTACK OP_2 OP_ROLL OP_2 OP_ROLL           # T claim r1 S1
OP_SWAP OP_TOALTSTACK OP_TOALTSTACK                 # T claim               | m r1 S1
LEAF_ACC                                            # T ch cs
<EMPTY_LEAF_HASH> OP_0 OP_2SWAP                     # T E_0.hash 0 ch cs
LEVEL × D                                           # (claim path)
OP_2SWAP OP_FROMALTSTACK OP_ROT OP_EQUALVERIFY      # T nh2 ns2 os2   (oh2 == r1)
OP_FROMALTSTACK OP_NUMEQUALVERIFY                   # T nh2 ns2       (os2 == S1)
FINAL
```

### 8.7 EVICT_SUBTREE_h

Witness: `dir_{D-1} sc_{D-1} … dir_h sc_h  leaf_{2^h−1} … leaf_0  sig  r  m`
(`leaf_0` on top; each `leaf_i` is 116 bytes or empty).

```
PROLOGUE <OPERATOR_KEY> OP_CHECKSIGVERIFY          # …leaves            | m r
OP_1 OP_TOALTSTACK <TAG_NODE>                      # T                  | m r idx
POSTORDER(h)                                       # T oh os            | m r idx
OP_FROMALTSTACK OP_DROP <E_h.hash> OP_0            # T oh os E_h 0
LEVEL × (D − h)
CHECK_OLD FINAL
```

`POSTORDER(h)` is generated recursively: `POSTORDER(0)` is `LEAF_STEP`;
`POSTORDER(k)` is `POSTORDER(k−1) POSTORDER(k−1) HASH_STEP`. The generator
tracks the number of machine elements above `T`, so every `OP_PICK` and
`OP_ROLL` depth is a constant.

**`LEAF_STEP`** — rolls the next leaf element up from below `T` and
converts it to a node, paying it out if non-empty:

```
<d+1> OP_ROLL                                      # … leaf_or_empty
OP_SIZE OP_0NOTEQUAL
OP_IF
  OP_SIZE 116 OP_EQUALVERIFY
  OP_DUP 72 32 OP_SUBSTR <OPERATOR_KEY> OP_EQUALVERIFY
  OP_DUP 104 OP_4 OP_SUBSTR OP_CHECKLOCKTIMEVERIFY OP_DROP
  OP_FROMALTSTACK OP_DUP OP_1ADD OP_TOALTSTACK     # leaf idx           | … idx+1
  <SEL_OUT_SINGLE> OP_TX                           # leaf amt spk
  <0x5120> OP_3 OP_PICK OP_8 32 OP_SUBSTR OP_CAT OP_EQUALVERIFY
  OP_OVER OP_8 OP_LEFT OP_NUMEQUALVERIFY           # leaf   (exact payout)
  LEAF_ACC                                         # oh os
OP_ELSE
  OP_DROP <EMPTY_LEAF_HASH> OP_0                   # E_0
OP_ENDIF
```

**`HASH_STEP`** — `[T … lh ls rh rs] → [T … ph ps]`:

```
OP_2 OP_PICK OP_OVER OP_ADD OP_TOALTSTACK          # lh ls rh rs        | … ps
PAD8 OP_CAT OP_SWAP PAD8 OP_ROT OP_SWAP OP_CAT OP_SWAP OP_CAT   # lh||enc64(ls)||rh||enc64(rs)
<t> OP_PICK OP_SWAP OP_CAT OP_SHA256               # ph
OP_FROMALTSTACK                                    # ph ps
```

The output index is kept on the altstack and passed to `OP_TX` dynamically,
so empty positions consume no output.

### 8.8 Sizes

Script sizes are `base + 88·levels` (dense) or `base + 135·levels`
(sparse). Witness data (paths, leaves, signatures, `r`, `m`) is
`42·levels + constant` (dense) or `41·(non-empty siblings) + levels +
constant` (sparse). Full tables from the
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

Operators SHOULD organise members into **cohorts**: a batch grafted with
`JOIN_h` into one aligned subtree, sharing an `evict_after`. An expired
cohort is swept with one `EVICT_SUBTREE_h` (section 7.7) at a small
fraction of the per-leaf cost of individual evictions (section 11).
Members who renew (`UPDATE`) before expiry, or who set a different evictor,
are not swept; a single non-evictable leaf blocks the sweep of its subtree,
so operators SHOULD require `evictor_key = OPERATOR_KEY` as a condition of
joining a cohort subtree.

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

Payment channels are layered on LayerTree as **channel leaves**: leaves
whose `exit_key` is the taproot output key of a two-party channel between
the owner and a counterparty (normally the operator). The channel exists
off-chain while the leaf is in the tree and its funding output materialises
at the payout output of the transaction that removes the leaf. Because that
outpoint is unknown in advance, channel transactions MUST be authorised by
signatures that do not commit to the prevout; the FULL and MID tiers provide
this with `OP_TX` (collating version, lock time, the current input's
sequence, and all outputs) and `OP_CHECKSIGFROMSTACK`, and the channel MUST
use the update/settlement (LN-Symmetry) state machine rather than penalties.
The MIN tier cannot host channel leaves.

The full specification is Appendix C, `spec/channel-leaves.md`, which
covers the rebindable-signature construction with exact selector values,
the state machine and its lock-time ranges, HTLCs and forwarding between
channel leaves through the operator, opening, splicing (`UPDATE`), closing
and eviction, tier applicability, comparison with Ark and factories, and
security considerations. Rules from Appendix C that bind the tree layer:

* a channel leaf's `amount` MUST equal the channel capacity and payouts to
  it MUST be exact: the owner MUST NOT use the FULL-tier fee-from-payout
  option of 7.2 rule 3, and a tree that hosts channel leaves SHOULD be
  created with the exact-payout `EXIT_K^=` variant (7.2 rule 6) so that
  the rule is enforced by script and visible in `m`;
* a channel leaf MUST have `seq = SEQ_FINAL` (5.2), so that no voucher can
  be redeemed against the capacity its signed states commit to;
* `evictor_key` SHALL be the counterparty's tree key, so eviction is the
  counterparty's force-close; a channel leaf that forwards or receives
  HTLCs SHALL set `evict_after = 0`, since the counterparty cannot enforce
  an HTLC on-chain before `evict_after`;
* lease renewal and splicing are `UPDATE`s co-signed by owner and
  operator; the channel identifier commits to the capacity epoch, so
  states of an earlier capacity cannot be replayed after a splice.

Intra-tree payments between channel leaves are ordinary HTLC or PTLC
forwards through the operator and never touch the tree output; a tree of `N`
channel leaves is a payment hub of `N` channels with one UTXO on-chain.
Routing to and from the public Lightning Network needs no bridging
construction. The "virtual network" of the design notes is this hub.

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
after any change to the source leaf. It does not commit to the source
*position*: if the same 116 bytes occurred at two positions, one voucher
could be redeemed against both, doubling the issuer's loss. Section 5.2
therefore requires unique `(owner_key, nonce)`; in the dense profile an
issuer MUST additionally check that no duplicate of its source leaf exists
before signing a voucher. In the sparse profile duplicates are impossible.

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

Because every transition spends and recreates the one tree output,
uncooperative exits are serialised through it: default mempool policy
(25 descendants) bounds a tree to roughly 25 single-leaf exits per block,
and `EXIT_K` raises that only for parties who cooperate. Operators SHOULD
size each tree by this exit throughput rather than by depth, and SHOULD
shard a deployment into several trees when the time to drain one at 25
leaves per block would exceed the time-sensitive commitments its leaves
carry (for channel leaves, Appendix C.9.5 gives the bound).

### 10.6 Integer encodings and truncation

* Amounts and sums are unsigned. `OP_SUB` underflow fails the script, which
  is what makes over-claims and negative balances impossible.
* `PAD8` produces a 10-byte string for values of 2^64 or more, so the hash
  preimage differs from any honestly built node and the proof fails; in
  addition every sum is monotone non-decreasing up the path and the final
  sum MUST equal an 8-byte transaction amount (`CHECK_OLD`, `FINAL`).
  `LE64` (used once, in `CLAIM`) truncates, but its input is a difference
  of two 8-byte amounts and cannot exceed 2^64.
* `sc` elements MUST be exactly 41 bytes and leaves exactly 116 bytes; the
  scripts check both, so no field can be shifted.
* `evict_after` is compared by `OP_CHECKLOCKTIMEVERIFY`, which also fails if
  the lock-time types differ; since `evict_after < 500,000,000`, eviction
  transactions MUST use height-based `nLockTime`.

### 10.7 Signature coverage

Owner, evictor and operator signatures are ordinary `OP_CHECKSIG(VERIFY)`
over the transaction. `EXIT` signatures MUST use `SIGHASH_DEFAULT` or
`SIGHASH_ALL` (section 7.2): with `SIGHASH_NONE` or `SIGHASH_SINGLE` the
payout amount, which the covenant only bounds from above for owner exits,
could be lowered by anyone relaying the transaction. `ANYONECANPAY` is
harmless and useful for adding a fee input later. `JOIN` and `UPDATE`
signers SHOULD use `SIGHASH_DEFAULT`; change outputs are never constrained
by script.

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

At `D = 16` (dense) an `EXIT_1` consumes about 2.48M varops against a
budget of roughly 40M for a transaction of its weight (section 11): 1.64M
for the two `TREE_SPK` evaluations (82 sigops units each), 0.5M for the
signature, and about 0.3M for hashing and stack work. The sparse profile at
`D = 32` uses 3.07M, and the 256-level tree 9.3M, still under a quarter of
budget. Stack depth peaks at 42 elements (`CLAIM`: 75; sparse `EXIT_2`: 80)
against a limit of 32,768, and no element exceeds 40 bytes except the script
itself.

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

| profile | D | positions | EXIT_1 script | EXIT_1 witness data | total witness (WU) | approx. tx weight (WU) | approx. vbytes |
|---|---|---|---|---|---|---|---|
| dense | 8 | 256 | 1,397 | 574 | 2,100 | ≈ 3,050 | ≈ 765 |
| dense | 12 | 4,096 | 1,749 | 738 | 2,616 | ≈ 3,570 | ≈ 890 |
| dense | 16 | 65,536 | 2,101 | 902 | 3,132 | ≈ 4,080 | ≈ 1,020 |
| dense | 20 | 1,048,576 | 2,453 | 1,066 | 3,648 | ≈ 4,600 | ≈ 1,150 |
| dense, minimal inventory | 16 | 65,536 | 2,378 | 886 | 3,393 | ≈ 4,340 | ≈ 1,085 |
| dense, `EVICT_SUBTREE_4` (13 leaves swept) | 16 | 65,536 | 5,281 | 2,129 | 7,539 | ≈ 8,490 | ≈ 2,120 (≈ 165 per leaf) |
| dense, `EVICT_SUBTREE_6` (51 leaves swept) | 16 | 65,536 | 16,097 | 6,455 | 22,681 | ≈ 23,630 | ≈ 5,910 (≈ 116 per leaf) |
| sparse | 32 | 2^32 | 5,147 | 326 + 41·log2 N | ≈ 6,260 (N = 65k) | ≈ 7,210 | ≈ 1,800 |
| sparse | 64 | 2^64 | 9,499 | 326 + 41·log2 N | ≈ 10,610 (N = 65k) | ≈ 11,560 | ≈ 2,890 |
| sparse | 256 | 2^256 | 35,611 | 285 + 41·log2 N | ≈ 36,680 (N = 65k) | ≈ 37,630 | ≈ 9,410 |

The transaction weight column adds a fee input (P2WPKH), a change output
and non-witness overhead (≈ 950 WU). In the dense profile each level costs
131 WU (88 script + 41 path + 2 length prefixes) regardless of occupancy. In
the sparse profile each level costs 135 WU of script plus 1 WU for an empty
sibling or 42 WU for a non-empty one, so witness data grows with `log2 N`
rather than with `D`. The minimal-inventory row (section 4.4) shows the
price of doing without the restored splice opcodes and the EC point
opcodes: about 260 WU per exit.

The sparse profile at `D = 32` costs about twice the dense profile at
`D = 16` per exit. What it buys is key-addressed positions: no slot
allocation, a history-independent root, and structural uniqueness of
leaves. The full 256-level MS-SMT is about twelve times the dense cost and
is not recommended; truncating positions to 32–64 bits loses nothing but
the ability to use a raw key as the position.

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

`EXIT_2` at `D = 16` (dense) uses 3,747 bytes of script and 1,741 of
witness data (5,617 WU in total), i.e. a second exit in the same transaction
costs about 2,490 WU against roughly 4,080 WU for a separate transaction;
in the sparse profile at `D = 32` the second exit costs about 4,950 WU.
Batching `K` exits scales linearly with no per-step EC overhead; each step
adds one signature check.

Joins batch the same way. `JOINK_2` measures 3,545 bytes of script and
1,525 of witness data at `D = 16` (dense), so a second single-leaf join in
the same transaction costs about 2,230 WU against 3,920 WU for its own
transaction; in the sparse profile at `D = 32` the figures are 9,773 and
606 bytes, about 4,880 WU per additional join against 6,580 WU standalone.
One operator signature covers the whole batch. The sparse profile's
per-leaf join cost therefore stays at roughly 5 kWU however many leaves are
batched, whereas a dense graft (`JOIN_h`) adds any number of leaves for a
constant 2 kWU; this is the decisive difference between the profiles for
bulk onboarding (see the 16M-leaf comparison in `design/review.md`, F14).

Shape-specialised multiproofs change the picture for *removals* in the same
way grafting does for additions. `EVICT_SUBTREE_h` (section 7.7) hashes the
subtree's internal nodes once and checks one signature:

| script | positions | leaves swept | script | witness | per-leaf total | sequential equivalent |
|---|---|---|---|---|---|---|
| `EVICT_SUBTREE_2` | 4 | 3 | 2,709 | 1,051 | ≈ 1,300 WU | `EXIT_4`: 7,039 B script |
| `EVICT_SUBTREE_4` | 16 | 13 | 5,281 | 2,129 | ≈ 580 WU | `EXIT_16`: 26,791 B script |
| `EVICT_SUBTREE_6` | 64 | 51 | 16,097 | 6,455 | ≈ 445 WU | `EXIT_64`: 105,847 B script |

(`D = 16`; three of every sixteen positions already empty.) Per-leaf cost
falls from about 2.5 kWU (sequential) or 4 kWU (standalone) to about
0.45 kWU, and the script grows only with the subtree, not with `D` per
leaf. This is why cohorts SHOULD be grafted into aligned subtrees with a
common lease expiry: the operator can then both add and remove a cohort in
one constant-shape transaction each.

Varops usage is 6–8% of budget for the dense profile and 8–25% for the
sparse profile; the EC operations (82 sigops units per `TREE_SPK`) and the
signature dominate at small depths, hashing at large ones.

### 11.1 Exit economics at various fee rates

*(informative)* `spec/fee-analysis.md`, generated by `tools/fee_analysis.py`
from the measured sizes, converts the table above into fees and break-even
balances at 1 to 250 sat/vB. Headlines, FULL dense `D = 16` (1,020 vB):

| fee rate | exit fee | balance for fee ≤ 1% | balance for fee ≤ 10% |
|---|---|---|---|
| 2 sat/vB | 2,040 sat | 204,000 sat | 20,400 sat |
| 10 sat/vB | 10,200 sat | 1,020,000 sat | 102,000 sat |
| 50 sat/vB | 51,000 sat | 5,100,000 sat | 510,000 sat |
| 250 sat/vB | 255,000 sat | 25,500,000 sat | 2,550,000 sat |

Depth moves the cost little (762 vB at `D = 8`, 1,149 vB at `D = 20`);
tier and profile move it more (MID +31%, MIN +43%, sparse 1.6–2.7×). The
FULL-tier endogenous fee option saves a constant 99 vB. Batching lowers the
marginal exit to 665 vB, and cohort sweeps lower eviction to 203 vB per
leaf (`EVICT_SUBTREE_4`) and 158 vB per leaf (`EVICT_SUBTREE_6`), which is
what keeps small leaves evictable at high fee rates; operators SHOULD size
cohorts and minimum leaf amounts so that a sweep stays below about 10% of
the smallest leaf at the fee-rate tail they intend to survive. Dust (330
sat) is never the binding constraint for `D ≥ 8`; the fee is.

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
| Off-chain payments | channel leaves (LN, Appendix C) or vouchers | OOR + rounds | channels | varies |
| Hosted channel: materialise funding | 1 tx, `O(1)` in `N` | unroll `O(log N)` txs | factory publish `O(log N)` txs | `O(log N)` txs |
| Opcodes | GSR + OP_TX + CSFS + EC ops BIP | none (pre-signed) or CTV | none or CTV | CTV/CCV (+CAT) |

Relative to the original LayerTree sketch: the exit no longer needs the
operator's voucher (so the operator cannot withhold exits); the MS-SMT
survives as the sparse profile with its depth truncated to 32–64 levels and
its proofs compressed, alongside a dense profile that is about half the cost
per exit and supports subtree grafting; and eviction, cooperative update
and single-use vouchers are added. The sketch's "signed events drive an on-chain state
machine" model survives as `CLAIM`, and its "the contract can accept many
exits in a batch" as `EXIT_K` (section 13).

## 13. Extensions

*(informative)* None of the following is required for conformance.

1. **Larger `K`.** `EXIT_K` (section 8.3) is defined for any `K`; the
   reference taptree includes `K ∈ {1, 2}`. Larger `K` suits operator-driven
   batch evictions and cooperative mass exits.
2. **Higher radix.** A radix-4 sum tree halves the number of levels at the
   cost of three 40-byte siblings per level; per-level script grows but
   total witness shrinks for large `D`.
3. **Smaller `LEVEL`.** With `OP_MULTI OP_CAT` the four concatenations per
   level collapse to two; keeping `ZERO8` on the stack replaces the 9-byte
   push in `PAD8` with a 2-byte `OP_PICK`. Together these save roughly 25%.
4. **More multiproof shapes.** The `POSTORDER` generator of section 8.7
   extends directly to owner-authorised mass exits within a subtree (a
   signature per leaf instead of the evictor-key equality), to sibling
   pairs, and to subtrees with a fixed pattern of empties. A runtime-shaped
   multiproof (a stack machine driven by witness flags) is also expressible
   but does not reduce script size.
5. **Aggregate node keys.** Storing a MuSig2 aggregate of all owner keys in
   each node (72-byte `sc`) allows a "replace subtree" transition authorised
   by one aggregate signature, giving Ark-style cooperative round updates
   for whole cohorts in one signature. This reintroduces interactive nonce
   coordination and is left for a separate document.
6. **Hash-locked vouchers.** Including a payment hash in the voucher message
   and requiring the preimage in `CLAIM` turns a voucher into an HTLC,
   enabling atomic swaps between trees, into Lightning, or with on-chain
   funds (the "loop in / loop out" flows of the design notes) and
   third-party liquidity provision: any leaf owner can service a swap by
   issuing a voucher.
7. **Nesting.** A leaf's `exit_key` may be the output key of another
   LayerTree, giving hierarchical trees with constant-size exit at each
   level.
8. **`OP_INTERNALKEY` fast path.** Where only `r` must be checked (never
   for output construction), `OP_INTERNALKEY` saves one `OP_TX` and one
   `TREE_SPK`; see the caveat in section 10.4.
9. **Vouchers and channel HTLCs share a hash.** A hash-locked voucher
   (item 6) and a channel-leaf HTLC (Appendix C.4) that use the same payment
   hash give an atomic swap between the credit instrument and the
   settlement instrument inside one tree, with no on-chain step.
10. **`UPDATE` with `exit_key` consent.** An `UPDATE` variant that also
   requires a signature by `old_leaf.exit_key` protects a leaf whose
   `exit_key` is a shared key against an owner-plus-operator splice; it is
   what makes user-to-user channel leaves trust-free (Appendix C.6.6).

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
* `tools/layertree_mid.py`, `tools/layertree_min.py` — the MID and MIN
  tier generators (section 4.5) with their witness helpers; `tools/test_mid.py`
  and `tools/test_min.py` execute them under tapleaf-`0xC0` semantics
  (including the `MINIMALDATA` policy checks that caught two non-minimal
  operands during development), 34 and 7 checks respectively; the MID
  checks include both `SEQ_FINAL` candidates, showing that `0xFFFFFFFF`
  *is* claimable under `CScriptNum` and `0x7FFFFFFF` is not.
* `tools/test_scripts.py` — executes every FULL-tier script in both profiles (dense
  at `D = 4` and `16`, sparse at `D = 8` and `32`) against the reference
  tree, 88 checks including negative cases (forged leaf, stale
  root, attacker-chosen `m`, unconserved amount, underfunded join, join over
  an occupied position, early eviction, evictor shortchange, unsigned update,
  voucher replay, over-claim, wrong voucher signer, stale second path in
  `EXIT_2`, shortchanged second evictee, non-terminal exit taking the
  terminal branch) and positive cases for a `CLAIM` that drains its source
  and for the terminal exit; sparse-specific cases cover a wrongly
  compressed sibling, a join at an occupied derived position and an update
  that would move a leaf; the bitmap-compressed sparse variant and the
  minimal-inventory `EXIT_1` (including a shifted field boundary), batched
  joins (`JOINK_2`, including a stale second path and an underfunded batch)
  and cohort sweeps (`EVICT_SUBTREE_2/4/6`, including a sweep before lease
  expiry, a shortchanged leaf and a non-evictable leaf) are exercised as
  well, together with the channel-leaf rules (a `CLAIM` against
  `seq = SEQ_FINAL` fails while the two neighbouring values succeed; the
  exact-payout `EXIT_1^=` variant rejects an owner shortfall and accepts an
  exact owner exit and an eviction), 234 checks in total. Run:
  `python3 tools/test_scripts.py`.
* `spec/scripts/` — annotated listings for `D = 4` (dense), `D = 8`
  (sparse), the MID and MIN tiers, and the size table covering both
  profiles, both compression encodings and all tiers.
* `spec/golden.json` — compiled scripts for every tier, the taptree root of
  the FULL `D = 4` set, a BIP-341 sighash vector and the tree scriptPubKey
  vector, produced by `tools/gen_golden.py` and consumed by the Go tests.
* `spec/channel-leaves.md` — Appendix C: payment channels hosted in leaves
  (normative for implementations that host channels; the tree layer is
  unaffected by it).
* `spec/fee-analysis.md`, `tools/fee_analysis.py` — exit and eviction cost
  at fee rates from 1 to 250 sat/vB (section 11.1).
* Go implementation (module `github.com/roasbeef/layertree`, packages
  `tree`, `script`, `txn`, `msg`): built on btcd, lnd and taproot-assets;
  every generated script is compared byte for byte with the Python output,
  and the BIP-341 signature hash computed by `txscript` is compared with the
  Python simulator's, which is what makes the MIN tier's constructive
  introspection testable.

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
* Draft "Elliptic Curve Operations for Bitcoin Script" (Osuntokun),
  `https://github.com/Roasbeef/bips/blob/ec-ops-bip/bips-ec-ops.md`,
  bitcoin/bips PR #1945.
* "[0/4] A Bitcoin Scripting Proposal BIP Quartet", bitcoindev,
  `https://groups.google.com/g/bitcoindev/c/GisTcPb8Jco/m/8znWcWwKAQAJ`.
* BIP-443 — `OP_CHECKCONTRACTVERIFY` (Ingala): the data-tweaked internal
  key used here follows the same pattern.
* Merkle Sum Sparse Merkle Trees, Taproot Assets BIP draft (Osuntokun).
* Ark protocol documentation (Ark Labs; Second).
* `design/unified-batching.md` — the essay in which LayerTree was first
  described; `design/review.md` — the scrutiny that produced this document.
