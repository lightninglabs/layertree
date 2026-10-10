# LayerTree: Constant-Size Exit and Eviction for Shared Bitcoin UTXOs

```
Title:    LayerTree
Layer:    Applications (requires consensus changes listed in section 4)
Status:   Draft
Version:  0.11.0
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

Two tree profiles are specified over the same scripts. The **dense**
tree, with operator-assigned positions and constant-size subtree grafting,
is the default profile and the one this document recommends. The
**sparse** key-addressed Merkle-sum tree (a truncated MS-SMT) with
compressed proofs, in which positions are derived from the owner's key, is
retained as the option for key-addressed registries; it costs 1.6 to 2.7
times as much per exit and cannot graft or sweep cohorts (5.4, 11).

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

Every transition spends the tree output as input 0 (the CCV tier of 4.6
reads the current input's index instead, so its tree input may sit at any
index), recreates it as output 0 with the new root and the new total, and
places any payouts at output 1 onward. Extra inputs (fees, funds being joined) and extra outputs (change,
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
   bitcoin/bips PR #1945), at commit `8df28249`, which is the revision the
   reference scripts and the simulator assume. Operands are written as
   that draft writes them, top of the stack first: `OP_EC_POINT_ADD` (0xbb;
   `[point2] [point1]` → `point1 + point2`, `point2` on top),
   `OP_EC_POINT_MUL` (0xbc; `[scalar] [point]` → `scalar · point`, the
   scalar on top and the point beneath it; the scalar is 32 bytes
   big-endian reduced mod `n`, and an empty `point` stands for `G`, so
   `<t> OP_0 OP_SWAP OP_EC_POINT_MUL` computes `t·G`, 8.2),
   `OP_EC_POINT_NEGATE` (0xbd, unused here) and `OP_EC_POINT_X_COORD`
   (0xbe; 33-byte point → 32-byte x coordinate). All points are 33-byte
   compressed; the point at infinity is the empty vector.
   Costs are 10, 30, 5 and 1 sigops units respectively (BIP-342 units in
   which `OP_CHECKSIG` is 50); under BIP-440 this is 10,000 varops per unit.
   **[A-3]** The scripts assume these opcodes are available in tapleaf
   version `0xC2` with those costs. **[A-4]** That draft assigns `0xbd` to
   `OP_EC_POINT_NEGATE` and the `OP_TX` draft assigns `0xbd` to `OP_TX`;
   BIP-443 also claims `0xbb`. The final numbering is out of scope here and
   does not affect the design; the reference simulator parks `OP_TX` at
   `0xbf` as a placeholder.
7. **`OP_CHECKCONTRACTVERIFY`** as in BIP-443 at `bitcoin/bips` commit
   `24e96e87`, the revision the CCV tier pins: redefining
   `OP_SUCCESS187` (0xbb), popping `<data> <index> <pk> <taptree>
   <mode>` (bottom to top). The CCV tier (section 4.6) uses only the
   following values: modes `-1` (`CHECK_INPUT`, no amount check), `0`
   (`CHECK_OUTPUT`, assign the input's residual amount), `2` (`DEDUCT`,
   subtract the checked output's amount from the residual); the empty
   buffer for `pk` stands for the BIP-341 `NUMS` point and `0x81` (the
   minimal encoding of `-1`) for the current input's taptree; `<data>` is
   the 32-byte root hash. **[A-6]** The BIP's sigops accounting is still
   TODO upstream; the reference simulator charges one signature check
   (500,000 varops, the cost of the taproot tweaks it performs) per call,
   and parks the opcode at `0xc1` to keep it apart from the `0xbb` the EC
   ops draft claims ([A-4]). A BIP-443 call with empty `<data>` applies
   no data tweak at all (the naked key is used as the internal key);
   LayerTree scripts always supply a non-empty `<data>` for tree outputs,
   and `CHECK_INPUT` with `taptree = -1` binds both the root and the
   taptree in one call. The amount semantics the CCV tier relies on are
   those of the BIP's pseudocode as of `bitcoin/bips` commit `24e96e87`,
   and the reference simulator implements exactly them: the three
   per-output arrays (`output_min_amount`, `output_checked_default`,
   `output_checked_deduct`) are initialised once per transaction and
   shared by every input's script; `residual_input_amount` is set to the
   current input's amount when that input's script starts; mode `0` adds
   the residual to the output's minimum, zeroes the residual and fails at
   once if the output's amount is below the accumulated minimum (the
   check is immediate, not deferred to the end of the transaction, but
   since the minimum only grows the last call decides); mode `2` fails if
   the residual is below the output's amount, then subtracts it; an
   output checked with mode `2` may not be checked again with mode `0` or
   `2`, by any input, in either order; a residual left unassigned at the
   end of an input's script is not checked (it becomes fee); a mode
   outside `-1..2` makes the script succeed. `tools/test_ccv.py` pins each
   of these rules with a direct test of the opcode. The tests cannot see
   the BIP text, so a revision of BIP-443 is caught only when the
   simulator is brought in line with it; the pinned commit above is what
   to diff against, and the tests then show which of the CCV tier's
   arguments (4.6) the revision touches.

8. **BIP-449 `OP_TWEAKADD`** (Rubin, `bip-0449.md`), defined for tapleaf
   `0xC0`: pops `tweak32 pubkey32` and pushes `x(P + t·G)`. The MID and
   MIN tiers of 4.5 use it in place of the EC opcodes; FULL and CCV do
   not. MIN needs only BIP-347 `OP_CAT` and BIP-449, both defined for
   `0xC0`, so it is the one tier whose opcodes are used in the tapleaf
   version their proposals define. Every other tier assumes some opcode
   in a leaf version its proposal does not cover: FULL assumes
   `OP_CHECKSIGFROMSTACK` and the EC opcodes in `0xC2` ([A-2], [A-3]),
   MID assumes `OP_TX` in `0xC0` ([A-5]), and CCV assumes BIP-443 in
   `0xC2` or `OP_TX` in `0xC0` ([A-5], [A-6]).

### 4.2 Not required

* `OP_INTERNALKEY` is not used: the scripts verify the full input
  scriptPubKey instead (section 6.4), which also binds the taptree root.
* `OP_MULTI`, `OP_SEGMENT`, `OP_BYTEREV`, `OP_EC_POINT_NEGATE` are not
  used. Section 13 notes optimisations that would use them if they ship.
* No `OP_CHECKTEMPLATEVERIFY`, `OP_TEMPLATEHASH` or `SIGHASH_ANYPREVOUT`
  is required by the tree itself. `OP_CHECKCONTRACTVERIFY` is not required
  by the three tiers of section 4.5; the CCV tier of section 4.6 is built
  on it. Section 9.8 notes where rebindable signatures help *leaf-level*
  constructions.

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
| BIP-443 (**[A-6]**, 4.1 item 7) | `OP_CHECKCONTRACTVERIFY` (CCV tier only, section 4.6; the CCV tier uses none of the EC ops) |

`OP_AND` and `OP_DOWNSHIFT` are used only by the sparse profile (to read
one bit of the position hash). `OP_EC_POINT_NEGATE`, `OP_INTERNALKEY`,
`OP_MULTI`, `OP_SEGMENT`, `OP_BYTEREV`, `OP_CHECKTEMPLATEVERIFY`,
`OP_TEMPLATEHASH` and `OP_PAIRCOMMIT` are not required by any tier;
`OP_CHECKCONTRACTVERIFY` is used by the CCV tier only (section 4.6),
under assumption **[A-6]**.

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
| Hash lock on a voucher (`CLAIM^h`, 7.5.1) | `OP_SHA256` | already in BIP-342; the hash lock needs no opcode beyond those `CLAIM` uses | — |
| Carving a leaf without a voucher (`SPLIT`, 7.5.2) | none beyond `EXIT` | `SPLIT` authorises with an ordinary transaction signature, so member-to-member payment does not depend on `OP_CHECKSIGFROMSTACK` at all | — |
| Owner/evictor/operator authorisation, lock time, hashing, stack work | BIP-342 | — | — |

Hence the irreducible core is **BIP-342 tapscript, the BIP-441 numeric
semantics (or tapleaf `0xC2` generally), `OP_CAT`, and one EC tweak
primitive**. `OP_TX` is replaceable in principle but not in practice, and
`OP_CHECKSIGFROMSTACK` is needed only for vouchers. Since `SPLIT` (7.5.2)
carves a leaf for another member on an ordinary transaction signature,
losing vouchers costs deferred and third-party redemption, not
member-to-member payment. Every restored splice, bit and shift opcode is a
convenience.

Section 4.5 makes the claim concrete with three complete script tiers.
Two intermediate data points are also measured: `exit_script_min` in
`tools/layertree_scripts.py` keeps the BIP-441 numerics but drops every
splice opcode and the EC point opcodes (`OP_TX` + `OP_TWEAKADD`), costing
2,378 bytes at `D = 16` against 2,101; the MIN tier drops `OP_TX` as well
and pays 3,572.

### 4.5 Opcode tiers

Every transition in this document is specified once, in section 7, and
implemented against four opcode sets: the three tiers below and the CCV
tier of section 4.6. A tree is created for one tier; its tapleaf version
and scripts follow from it. The tree format
(section 5) is the same in every tier, so proofs, roots and off-chain data
are interchangeable, with one numeric cap noted below.

| | **FULL** | **MID** | **MIN** | **CCV** (4.6) |
|---|---|---|---| ---|
| Tapleaf version | `0xC2` (BIP-441) | `0xC0` | `0xC0` | `0xC2` or `0xC0` |
| Numerics | arbitrary length, unsigned | `CScriptNum`, 4-byte operands | `CScriptNum`, 4-byte operands | as FULL (`0xC2`) or as MID (`0xC0`) |
| Beyond BIP-342 | `OP_CAT`, `OP_SUBSTR`, `OP_LEFT`, `OP_RIGHT`, `OP_AND`, `OP_DOWNSHIFT`; `OP_TX`; `OP_CHECKSIGFROMSTACK`; `OP_EC_POINT_MUL/ADD/X_COORD` | `OP_CAT`; `OP_TX` (assumed in `0xC0`, **[A-5]**); `OP_CHECKSIGFROMSTACK`; `OP_TWEAKADD` | `OP_CAT`; `OP_TWEAKADD` | `OP_CHECKCONTRACTVERIFY` (BIP-443, **[A-6]**); `OP_TX`; with `0xC2` the BIP-441 opcodes FULL uses, with `0xC0` `OP_CAT`; `OP_CHECKSIGFROMSTACK` only for `CLAIM`/`CLAIM^h`. No EC ops, no `OP_TWEAKADD` |
| Introspection | `OP_TX` | `OP_TX` | constructive: the script rebuilds the BIP-341 sighash message and checks a generator-key signature with `OP_CHECKSIG` (section 4.4) | `OP_TX` for amounts only; scriptPubKeys and the input's state by `OP_CHECKCONTRACTVERIFY` |
| Leaf on the stack | one 116-byte element, fields by `OP_SUBSTR` | seven field elements, rejoined by `OP_CAT` under `OP_SIZE` checks | as MID | as FULL (`0xC2`) or as MID (`0xC0`) |
| Fixed-width numbers | `2^64 OP_ADD` | `PADZ`: witness zero pad `z`, filler `w`, `z||w = 00000000`, `size(x)+size(z) = 4`; `NONNEG` (`OP_DUP OP_DUP OP_ABS OP_EQUALVERIFY`) on every witness-supplied number that enters a sum (a sibling sum, a leaf amount, a joined sum), since `CScriptNum` is sign-magnitude and `le32` of a value in `[2^31, 2^32)` is a negative number (10.6) | as MID | as FULL (`0xC2`) or as MID (`0xC0`) |
| Sum limit per tree | none (< 2^51 by leaf rule) | every sum < 2^31 sat, enforced: `NONNEG` keeps every term non-negative and `PADZ`'s four-byte bound every accumulator below 2^31 | as MID | as FULL (`0xC2`) or as MID (`0xC0`) |
| Payout amount | owner: ≤ leaf amount; evictor: exact | exact for both | exact for both | exact for both (4.6) |
| Sparse positions | bit `k` of `H_pos` by `OP_DOWNSHIFT`/`OP_AND`; `D ≤ 64` typical | witness `dir` bits folded into an accumulator compared with `pos_lo` (first 4 bytes of `H_pos`, supplied split as `pos_lo || pos_hi`); `nonce` chosen so `pos_lo` is a minimal positive `CScriptNum` below `2^D` (the `D`-bit accumulator is compared with all 32 bits of `pos_lo`, whose top byte is non-zero, so `25 ≤ D ≤ 31`, with `2^(31−D)` times the grinding below `D = 31`) | as MID | as FULL (`0xC2`) or as MID (`0xC0`, `25 ≤ D ≤ 31`) |
| `CLAIM` (vouchers) | yes | yes | no (needs `OP_CHECKSIGFROMSTACK`) | yes, both numerics, with `OP_CHECKSIGFROMSTACK` |
| `CLAIM^h` (hash-locked vouchers, 7.5.1) | yes | yes | no (no `CLAIM`) | yes, both numerics, as `CLAIM` |
| `SPLIT` (owner-authorised carve, 7.5.2) | yes | yes | yes, dense (8.6.2) | yes, both numerics |
| `CLAIM^x`, `CLAIM^hx` (exit-key consent, 7.5.3) | yes | not implemented | no (no `CLAIM`) | not implemented |
| `UPDATE^x` (exit-key consent) | yes | yes | no (no `UPDATE`) | yes, both numerics |
| `EVICT_SUBTREE_h` (cohort sweep, 7.7) | yes | yes, dense; bounded by the 1,000-element stack limit (below) | no | yes, dense, both numerics (`0xC0`: MID's sweep and stack bound, 4.6) |
| `REWRITE_h`, `REWRITE_h^x` (cohort rewrite, 7.9) | yes | not implemented | no | not implemented |
| `DETACH_h` (subtree detach, 7.10) | yes | not implemented | no | not implemented |
| Channel leaves (Appendix C) | yes | yes (`OP_TX` + `OP_CHECKSIGFROMSTACK`) | no: rebindable signatures need `OP_TX`; MIN trees hold plain leaves only | yes, hosted: the channel scripts of C.3 live in their own outputs and need `OP_TX` + `OP_CHECKSIGFROMSTACK` there (C.7); the tree's scripts need neither, and its exact payouts are what C.6.1 asks |
| `SEQ_FINAL` (non-claimable leaf) | `0xFFFFFFFF` | `0x7FFFFFFF` | `0x7FFFFFFF` (bars `SPLIT`) | `0xFFFFFFFF` (`0xC2`), `0x7FFFFFFF` (`0xC0`) |
| Terminal exit (7.8) | yes | yes | no; output 0 is always the tree output | yes |
| Transaction shape | free (input 0, outputs 0..K constrained) | free | fixed per script: two inputs, outputs `[tree', payouts…, raw extras]` | free (the tree input at any index, by CCV's current-input index; outputs 0..K constrained) |
| Spender work | none | none | grind a free field (fee input `nSequence`) until `e` ends in `0x00`: 256 hashes expected | none |
| Reference | `tools/layertree_scripts.py` | `tools/layertree_mid.py` | `tools/layertree_min.py` | `tools/layertree_ccv.py` |

**[A-5]** The `OP_TX` draft defines the opcode for tapleaf `0xC2`. The MID
tier assumes it is also available (with `CScriptNum` outputs for the
"varint or int" fields) in `0xC0`; if it is not, MID collapses into MIN for
introspection and keeps `OP_CHECKSIGFROMSTACK` for vouchers. MIN is the
only tier that uses every opcode in the tapleaf version its proposal
defines (BIP-347 and BIP-449, both `0xC0`); FULL, MID and CCV each assume
at least one opcode outside its proposal's leaf version (4.1 item 8).

Measured sizes at `D = 16` (dense) and `D = 31/32` (sparse), bytes of
script / witness data:

| transition | FULL D | MID D | MIN D | CCV D | FULL S (32) | MID S (31) | CCV S (32) |
|---|---|---|---|---|---|---|---|
| `EXIT_1` | 2,101 / 902 | 3,367 / 978 | 3,640 / 1,175 | 1,716 / 838 | 5,147 / 326 | 9,402 / 796 | 4,762 / 262 |
| `JOIN_h` (`h = 2` dense, `h = 0` sparse) | 1,841 / 743 | 2,884 / 794 | — | 1,456 / 679 | 5,131 / 367 | 9,382 / 783 | 4,746 / 303 |
| `JOINK_2` | 3,545 / 1,525 | 5,885 / 1,637 | — | 3,160 / 1,461 | 9,773 / 606 | 18,241 / 1,433 | 9,388 / 542 |
| `UPDATE` | 2,137 / 1,080 | 3,479 / 1,156 | — | 1,752 / 1,016 | 5,347 / 547 | 9,525 / 1,002 | 4,962 / 483 |
| `UPDATE^x` | 2,144 / 1,144 | 3,483 / 1,225 | — | 1,759 / 1,080 | 5,354 / 611 | 9,529 / 1,032 | 4,969 / 547 |
| `CLAIM` | 3,874 / 1,690 | 6,526 / 1,840 | n/a | 3,487 / 1,626 | 9,968 / 688 | 18,596 / 1,551 | 9,581 / 419 |
| `CLAIM^h` | 3,882 / 1,722 | 6,534 / 1,869 | n/a | 3,495 / 1,658 | 9,976 / 515 | 18,604 / 1,446 | 9,589 / 451 |
| `SPLIT` | 3,765 / 1,674 | 6,367 / 1,821 | 6,651 / 2,018 | 3,378 / 1,610 | 9,859 / 483 | 18,437 / 1,420 | 9,472 / 419 |
| `EVICT_SUBTREE_2` (3 of 4 swept) | 2,709 / 1,051 | 4,169 / 1,157 | — | 2,340 / 987 | — | — | — |
| `EVICT_SUBTREE_4` (13 of 16 swept) | 5,281 / 2,129 | 7,977 / 2,417 | — | 4,960 / 2,065 | — | — | — |
| `EVICT_SUBTREE_6` (51 of 64 swept) | 16,097 / 6,455 | 24,169 / 7,461 | — | 15,968 / 6,391 | — | — | — |
| `CLAIM^x` | 3,881 / 1,754 | — | n/a | — | 9,975 / 547 | — | — |
| `REWRITE_4` (16 positions, mixed) | 5,512 / 4,329 | — | — | — | n/a | n/a | n/a |
| `DETACH_8` | 1,548 / 497 | — | — | — | n/a | n/a | n/a |

The same transitions under the CCV tier's `0xC0` numerics (the MID
encoding: seven-element leaves, `PADZ`, `NONNEG`): dense `D = 16`: `EXIT_1`
3,002 / 914, `JOIN_2` 2,516 / 730, `UPDATE` 3,111 / 1,092, `UPDATE^x`
3,115 / 1,156, `CLAIM` 6,156 / 1,773, `CLAIM^h` 6,164 / 1,805, `SPLIT`
5,997 / 1,757, `EVICT_SUBTREE_2/4/6` 3,817 / 1,093, 7,673 / 2,353 and
24,057 / 7,397; sparse `D = 31`: `EXIT_1` 9,037 / 732, `JOIN_0`
9,014 / 719, `UPDATE` 9,157 / 905, `UPDATE^x` 9,161 / 969, `CLAIM`
18,226 / 1,350, `CLAIM^h` 18,234 / 1,382, `SPLIT` 18,067 / 1,356. The CCV call saves about 360 bytes of script
over MID at either profile (MID `EXIT_1` at `D = 16`: 3,367 / 978),
because the `TREE_SPK_MIN` recomputation and the spk introspection read
drop out.

At `D = 4` (dense) and `D = 8` (sparse) the `0xC2` `CLAIM` measures
1,375 / 630 and 3,071 / 419, `CLAIM^h` 1,383 / 662 and 3,079 / 451. The
voucher check costs 109 bytes of script over `SPLIT` under `0xC2`
numerics and 159 under `0xC0`, in every tier: the 33-byte `tree_id` push
is a constant of the script, and the check takes nothing but the two
leaves and the signature from the witness, which is why the CCV tier,
whose witness carries no `m`, runs the same check token for token. The
carve rule of 7.5 rule 5 costs 25 bytes under `0xC2` and 60 under
`0xC0`, where it also adds six witness elements, and the `DUST_MIN`
floor of 7.5 rule 6 a further 15 and 14 (8.6).

The MID `EVICT_SUBTREE_h` (8.7) carries each occupied position as
fourteen witness elements (the ten of a MID leaf, the minimal
`evict_after` with its `PADZ` pad, and a presence flag), each empty
position as one, and each internal node below the subtree root as one
`PADZ` pad pair. With `p` of the `2^h` positions occupied its witness is
`13p + 2^h + 2(2^h − 2) + 9(D − h) + 7` elements, and the prologue pushes
three more before any is consumed, so BIP-342's limit of 1,000 stack plus
altstack elements bounds the sweep: at `D = 16`, `h ≤ 5` fits at any
occupancy (617 elements at the peak of a full 32-leaf sweep) and `h = 6`
fits with at most 54 of its 64 positions occupied (990 at the peak). A
full 64-leaf cohort is swept as two `EVICT_SUBTREE_5` spends. The sums
stay within the tier's 2^31 cap, so the numeric limit binds nothing here.
FULL has no such bound: BIP-441 raises the element limit.

The MID premium over FULL is about 55% of script for the dense profile and
80% for the sparse profile; almost all of it is the `PADZ` gadgets (two per
level) and the per-field size checks. MIN adds the sighash reconstruction
(about 270 bytes) on top of MID and removes `OP_TX`. The complete table,
including `EXIT_K`, `EVICT_SUBTREE_h`, both compression encodings and the
`FULL`-numerics-without-splice-opcodes data point, is
`spec/scripts/sizes.md`; per-tier listings for `D = 4` are under
`spec/scripts/`.

*(informative)* The tiers answer different deployment questions. FULL is
what the Great Script Restoration plus the introspection, CSFS and EC-ops
candidates make possible, and is the recommended target. MID is what a
`0xC0`-only soft fork of the LNhance flavour plus `OP_CAT`, `OP_TX` and
`OP_TWEAKADD` would give: everything in this document at roughly 1.6× the
size, with a 21.47 BTC cap per tree. MIN is the existence proof that
`OP_CAT` and one tweak opcode suffice for the covenant itself, at the cost
of vouchers, terminal exits, a fixed transaction shape and a small grinding
step. Member-to-member payment survives in MIN as `SPLIT`. The dashes in
the MIN column mean not built, not impossible: `JOIN_h`, `UPDATE`,
`EXIT_K` and `EVICT_SUBTREE_h` follow the same constructive-sighash
construction (every output the rule constrains is assembled into the
message, the rest is raw witness) but have not been generated or
measured, and `UPDATE^x` follows `UPDATE`. A MIN tree as measured here is
therefore created with its whole membership and only ever shrinks, by
`EXIT_1` and `SPLIT`. CCV (section 4.6) is what BIP-443 adds on top of either numeric
flavour: the same transitions at a smaller script than FULL (1,716 vs
2,101 bytes for `EXIT_1` at `D = 16`) with no EC-ops dependency and `r`
and `m` gone from every witness.

### 4.6 The CCV tier

The CCV tier realises the same transitions as FULL with BIP-443
`OP_CHECKCONTRACTVERIFY` replacing every taproot-key binding. It is a
fourth tree-creation choice, not a replacement: a CCV tree's output key
is the BIP-443 data tweak of `NUMS` by the root hash rather than
`NUMS + H_state(r)·G`, so a CCV tree and a FULL tree with the same root
have different scriptPubKeys (section 6.3).

Three CCV calls per transition, in place of the scripts' key arithmetic:

* **Authenticate the current state.** After the fold produces the old
  root `oh`, one call `<oh> <-1> <> <-1> <-1> CCV` (data, index, pk,
  taptree, mode; empty pk = `NUMS`, `-1` taptree = the current input's)
  asserts the input commits to `oh` under the same taptree. The
  `os == input amount` equality of the other tiers stays.
* **Commit the next state.** `<nh> <0> <> <-1> <0> CCV` asserts output 0
  carries the new root under the same taptree and assigns the input's
  residual amount to it; `out0.amount == ns` remains one `OP_TX` read
  (rule 5 unchanged).
* **Constrain a payout.** `<> <k> <exit_key> <> <2> CCV` asserts output
  `k` is a bare P2TR to the leaf's exit key and deducts its amount from
  the residual; the exact-payout comparison remains one `OP_TX` read.

Payouts MUST be exact (spec 7.2 rule 6) for owner exits as well as
evictions; this follows from the assign mode on output 0 and is normative
for the tier: a short payout would strand its difference in the residual
and force output 0 above `ns`, breaking rule 5's equality. Fees are
exogenous, as in MID and MIN.

**Vouchers.** `CLAIM` and `CLAIM^h` check the voucher of 7.5 over the
tree's `tree_id` (6.2) exactly as the other tiers do, token for token
(8.6.2): the message never names `m`, so the CCV witness's lack of `m`
costs the tier nothing. `CLAIM` and `CLAIM^h` are the only CCV scripts
that use `OP_CHECKSIGFROMSTACK`; a CCV tree that omits them does not
depend on it, which is why they are tree-creation parameters in this
tier, like `SPLIT` and `UPDATE^x`, rather than members of the default
script set. `SPLIT` (7.5.2) needs neither `tree_id` nor
`OP_CHECKSIGFROMSTACK`: it is authorised by the source owner's
transaction signature (`OP_CHECKSIGVERIFY`), which commits to the spent
outputs and so to the tree's scriptPubKey. All three exist in both
numerics (`claim_script_ccv`, `_claim_script_ccv0`, `split_script_ccv`).
`UPDATE^x` (both numerics), terminal exits and every other transition are
unchanged. The `0xC2` `SEQ_FINAL` is FULL's `0xFFFFFFFF` and the `0xC0`
one MID's `0x7FFFFFFF`, since the carve bodies are those tiers'.

The tier needs one introspection read per constrained amount (the three
`OP_TX` calls above), so it does not remove `OP_TX`; it removes the EC ops
draft and `OP_TWEAKADD` from the dependency list. It comes in both
numerics: `0xC2` (BIP-441, the sizes above) and, with the MID tier's
encoding (seven-element leaves, `PADZ`, sums below 2^31 sat, sparse
`D ≤ 31`), `0xC0`; the CCV binding itself is numerics-independent. In
`0xC0` the tier covers every transition it covers in `0xC2`. `SPLIT` is
MID's carve body (8.6.2) with no `r` on the altstack, `CHECK_INPUT` on the
first step's old root and the assign-mode output check in place of
`FINAL`. `EVICT_SUBTREE_h` is the MID tier's element-based sweep (8.7):
the same pre-pass of leaf steps and mirrored post-order hash pass, with
each payout a `CHECK_OUTPUT|DEDUCT` call on the leaf's exit-key element at
the dynamic output index, followed by the exact `OP_TX` amount read. Its
witness is MID's minus `r` and `m` and no prologue runs, so the
1,000-element bound of 4.5 applies with one more position to spare (55 of
64 occupied positions at `h = 6`, `D = 16`).

Output 0's amount rule under several tree inputs *(informative)*. Every
CCV call in the tier names the current input (index `-1`) or a fixed
output, so two tree inputs in one transaction each require output 0 to be
their own successor: two trees in different states cannot meet at all. Two
inputs carrying the same state (the same scriptPubKey funded twice) could
otherwise share one output 0 that satisfies both `out0 == ns` checks and
strand one input's amount; BIP-443 prevents that, because the assign mode
accumulates every input's residual into one per-output minimum, so output
0 would have to carry both while equalling one `ns`. A payout output
likewise cannot be deducted by two inputs. `tools/test_ccv.py`
(`test_two_trees`) runs both cases. The terminal exit issues no output
check; with exact payouts and the input-amount equality its residual is
zero, and a residual left unassigned is in any case only fee (4.1 item 7). Reference: `tools/layertree_ccv.py` (both
profiles, both numerics), tests in `tools/test_ccv.py`, Go mirror in
`script/ccv.go`.

### 4.7 Policy assumptions

*(informative)* Relay of `0xC2` script-path spends with witnesses of a few
kilobytes and 116-byte leaf elements is assumed to be standard once
BIP-441 activates. The `0xC0` tiers are subject to today's 80-byte
witness item limit, which only MIN's `extra_outs` element can exceed
(8.11, 10.10). Transitions use exogenous fees (section 9.3); a
Pay-to-Anchor (`OP_1 <0x4e73>`) output at any index ≥ 1 (or ≥ K+1 for a
K-payout transition) is compatible with all scripts in this document.

## 5. Data Structures

### 5.1 Tags and constants

| Name | Value |
|---|---|
| `TAG_LEAF` | `"LayerTree/leaf"` |
| `TAG_NODE` | `"LayerTree/node"` |
| `TAG_STATE` | `"LayerTree/state"` |
| `TAG_VOUCHER` | `"LayerTree/voucher"` |
| `TAG_VOUCHER_H` | `"LayerTree/voucher-hashlock"` (hash-locked vouchers, 7.5.1) |
| `TAG_POS` | `"LayerTree/pos"` (sparse profile positions) |
| `TAG_TREE_ID` | `"LayerTree/tree-id"` (the RECOMMENDED `tree_id` derivation, 6.2) |
| `NUMS` | BIP-341 `H`: x = `50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0`, compressed `02 || x` |
| `EMPTY_LEAF_HASH` | 32 zero bytes |
| `LEAF_LEN` | 116 |
| `SEQ_FINAL` | `0xFFFFFFFF` (FULL), `0x7FFFFFFF` (MID, MIN): the `seq` value that makes a leaf non-claimable (5.2, 7.5) |
| `TAG_CHAN_ID`, `TAG_CHAN_UPD`, `TAG_CHAN_SET` | `"LayerTree/chan/id"`, `"LayerTree/chan/update"`, `"LayerTree/chan/settle"` (Appendix C) |

`H_leaf`, `H_node`, `H_state`, `H_voucher`, `H_voucher_h`, `H_pos` denote
`H_tag` with the
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
| 112 | 4 | `seq` | `le32`, incremented by each `CLAIM` or `SPLIT` against the leaf; MUST NOT wrap |

Requirements:

* `amount` MUST be greater than 0 and less than 2^51. A leaf written by
  `CLAIM`, `CLAIM^h`, `CLAIM^x`, `CLAIM^hx` or `SPLIT`, and the residual
  those transitions leave in the source position, MUST be at least
  `DUST_MIN` (6.2, 7.5 rule 6); the scripts enforce it. Leaves written by
  the operator-signed transitions (`JOIN`, `UPDATE`, `REWRITE_h`) SHOULD
  be at least `DUST_MIN` too, for the reason 7.8 gives.
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
  **non-claimable**: `CLAIM` (7.5) and `SPLIT` (7.5.2) compute `seq + 1`
  and fail when the result does not fit in four bytes, which is the case
  exactly for `SEQ_FINAL`. Creators MUST set `seq = SEQ_FINAL` on any
  leaf whose `amount` is not the owner's alone (channel leaves, Appendix
  C.6.5) and MAY set it on any other leaf. The same marker keeps the
  owner's signature on every change to the leaf under `REWRITE_h`: the
  amount-only exemption of 7.9 rule 3 does not reach a leaf whose `seq`
  is `SEQ_FINAL`. `SEQ_FINAL` differs between tiers because MID
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
**profiles**, also fixed at creation. Dense is the default: implementations
MUST support it, and SHOULD use it unless the deployment needs
key-addressed positions. Sparse is OPTIONAL.

* **Dense (`D`)**: the operator assigns positions. Subtrees of new leaves
  may be grafted at any height (`JOIN_h`) and swept as aligned subtrees
  (`EVICT_SUBTREE_h`). Implementations SHOULD support `D` in the range 8
  to 24.
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
  Implementations that support the sparse profile SHOULD support `D` in
  the range 32 to 64; `D = 256` (the full MS-SMT) is valid but costs
  about 35 kB of script per exit (section 11). The profile buys
  key-addressed positions, a history-independent root and structural
  uniqueness of leaves, at 1.6 to 2.7 times the dense per-exit cost
  (`design/tree-comparison.md` has the measured comparison).

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
`MINIMALIF`) and `sc = sib.hash || enc64(sib.sum)` (41 bytes). In the **sparse** profile
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
* `DUST_MIN`, the smallest amount a carve may write into a leaf or leave
  in its source (7.5 rule 6), a constant of the `CLAIM` and `SPLIT`
  scripts and never a witness element. It MUST be greater than 0. The
  RECOMMENDED value is 330 sat, the P2TR dust threshold under Bitcoin
  Core's default policy (3,000 sat/kvB over the 110 bytes of a P2TR
  output and the input that spends it): every transition that removes a
  leaf pays it to exactly one P2TR output, and a transaction that pays a
  fee and carries an output below the threshold is one no default node
  relays (7.8). Operators who size cohorts by 11.2 MAY set it higher.
* the set of supported `JOIN` heights (dense) and `EXIT_K` sizes;
* `tree_id`, a 32-byte value that every voucher against the tree binds
  (7.5) and that the `CLAIM` scripts carry as a constant (8.6), never as
  a witness element. It MUST be unique per lineage: no two trees share it
  unless one was created from the other by `DETACH_h` (7.10), and a tree
  created by `DETACH_h` MUST inherit its parent's `tree_id`. The
  RECOMMENDED value is `H_tag("LayerTree/tree-id", txid || le32(vout))`
  over the outpoint spent by input 0 of the creation transaction (`txid`
  in internal byte order), which is known before the transaction is built
  and can be spent only once, so it is unique by construction and cannot
  equal any `m`, TapBranch or TapLeaf hash. The tree output's own
  outpoint cannot serve: `m` depends on `tree_id` and the output's
  scriptPubKey on `m`. Inheritance across a detach is safe because a
  detach moves each leaf into exactly one of the two outputs, so a
  voucher's source leaf exists in one tree of the lineage only.

A conforming taptree MUST contain `EXIT_1`. It SHOULD contain at least one
`JOIN_h` (`JOIN_0` in the sparse profile), and MAY contain `UPDATE`, `CLAIM`
and further variants (section 7.6). The parameters and the chosen variants
together are the tree's **option set**; it is fixed at creation and, through
`DETACH_h` (7.10 rule 3), it is the option set of every tree in the
lineage, compiled at each tree's depth. Scripts MUST NOT reference the
taptree's own Merkle root; the scripts receive it from the witness and
verify it (section 6.4), which avoids the circular dependency.

The Merkle root of the taptree, `m`, is the **tree identifier**. Two tree
outputs with the same `m` follow identical rules and differ only in state.
`m` names a rule set rather than a tree: two trees created with the same
parameters share it. Because `tree_id` is a constant of `CLAIM`, two trees
that carry a `CLAIM` script and differ in `tree_id` have different `m` as
well, but what binds a voucher to one tree is `tree_id`, not `m` (10.3).

### 6.3 scriptPubKey

```
TREE_SPK(r, m) = P2TR( x( lift_x(x(NUMS + H_state(r)·G)) + H_TapTweak(x(P) || m)·G ) )
```

i.e. the ordinary BIP-341 output key for internal key `x(P)` and Merkle root
`m`. A **tree output** for state `r` is any output with scriptPubKey
`TREE_SPK(r, m)` and amount equal to the root's sum.

For a CCV-tier tree (section 4.6) the state key is instead the BIP-443
data tweak of `NUMS` by the root hash,

```
TREE_SPK_CCV(r, m) = P2TR( x( lift_x( x(NUMS + sha256(NUMS || r)·G) ) + H_TapTweak(x(P) || m)·G ) )
```

i.e. the output key a `CHECKCONTRACTVERIFY` call with pk = empty (NUMS),
data = `r` and taptree = `m` verifies. The data tweak is an untagged
`sha256(pk || data)` (BIP-443), not `H_state`, so a CCV tree and a FULL
tree with the same root have different scriptPubKeys: the tier is a
tree-creation parameter like the profile and the depth, and the two
encodings MUST NOT be mixed within one tree.

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
have verified their inclusion before funding (section 9.2). The outpoint
spent by the transaction's input 0 is what the RECOMMENDED `tree_id`
(6.2) is derived from, so the creator fixes that input before compiling
the scripts.

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
5. **Exit-consent variant `UPDATE^x`.** A tree MAY be created with an
   `UPDATE^x` script in place of `UPDATE`. `UPDATE^x` takes one further
   witness input, `exit_sig`, directly above `operator_sig`, which MUST be a
   valid BIP-340 signature over `tx` by `old_leaf.exit_key`, with the same
   hash-type requirement as 7.2 rule 3. Rules 1 to 4 continue to apply, so
   `UPDATE^x` requires three signatures where `UPDATE` requires two. The
   variant is a tree-creation parameter; it changes the scripts and
   therefore `m`, so any party can tell from the tree identifier which rule
   applies. A tree that hosts leaves whose `exit_key` is a key shared with a
   counterparty, in particular channel leaves, SHOULD use it: without it the
   owner and the operator can together splice such a leaf down and strand
   the counterparty's balance (Appendix C.6.6). The reference generators
   expose it as `update_script(…, exit_consent=True)`. It costs 7 bytes over
   `UPDATE` in the FULL tier (one `OP_PICK`, one `OP_SUBSTR` of the
   `exit_key` field and one `OP_CHECKSIGVERIFY`) and 4 bytes in MID, where
   the exit key already arrives as its own witness element; the witness
   grows by the 64-byte signature in both tiers.

### 7.5 CLAIM

`CLAIM` executes a **voucher**: an off-chain, owner-signed instruction to
carve a new leaf out of an existing leaf's balance. It requires neither the
owner's nor the operator's participation at redemption time and is
single-use by construction.

Voucher: `voucher_sig` is a BIP-340 signature by `source_leaf.owner_key`
over

```
H_voucher( tree_id || source_leaf || claim_leaf )
```

where `tree_id` is the tree's creation parameter of 6.2, a constant of
the script and not a witness element.

Witness inputs: sibling path of the *claim* position (`D` levels), sibling
path of the *source* position (`D` levels), `source_leaf`, `claim_leaf`,
`voucher_sig`, `r`, `m`.

Rules:

1. `voucher_sig` MUST verify (via `OP_CHECKSIGFROMSTACK`) under
   `source_leaf.owner_key` over the message above, with the script's own
   `tree_id`.
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
5. `claim_leaf.evictor_key` MUST equal `source_leaf.evictor_key`, and
   `claim_leaf.evict_after` MUST be no later than
   `source_leaf.evict_after`: nothing carved out of a leaf is harder to
   evict than the leaf itself.
6. `claim_leaf.amount` MUST be at least `DUST_MIN` (6.2), and the
   residual `amount'` of step 1 MUST be either 0 (the position becomes
   `E_0`) or at least `DUST_MIN`.

*(informative)* Rule 5 makes eviction a property of a balance rather than
of one leaf. Without it an owner facing eviction could move its balance
into a fresh leaf with a `NUMS` evictor or a far lease, and any member
could plant a `NUMS` leaf in an empty position of a cohort
and block `EVICT_SUBTREE_h` (7.7) on that cohort for good. The rule is
per balance, not per tree: a leaf the operator admitted as non-evictable
can still carve leaves of the same terms into any empty position, which
10.8 addresses. The check is two field comparisons (8.6); the Lean model
carries it as two hypotheses of `Claim` (`claim_evictable`,
`formal/README.md`).

*(informative)* Rule 6 keeps every leaf a carve writes removable by a
standard transaction. A leaf below the dust threshold can leave the tree
only through a payout output below it, which default policy relays only
in a zero-fee package whose child spends that output, and only the
leaf's owner can sign that child; so a sub-dust leaf would block
`EVICT_SUBTREE_h` on its cohort and `JOIN_h` over every subtree that
contains it for the life of the tree, at a cost to the planter of one
`SPLIT` and one satoshi. The residual case covers the member who splits
all but a satoshi of its own leaf and leaves the rest behind in its
cohort. The floor costs 15 bytes under `0xC2` and 14 under `0xC0` (8.6).
`JOIN`, `UPDATE` and `REWRITE_h` carry no such rule, since the operator
signs each of them and would be squatting its own tree (7.8). The Lean
model states the rule as `Reachable.dust` (`formal/README.md`).

*(informative)* Replay is prevented by step 1 changing the source leaf:
once redeemed, the source position holds `source_leaf'` rather than
`source_leaf`, so the signed message no longer verifies against the tree
there. Two bookkeeping rules carry the rest of the argument, and neither
is enforced by covenant. The first is 5.2's rule that no two leaves share
`(owner_key, nonce)`, which the dense profile does not check on chain:
the voucher binds the source leaf by content, not position, so two
identical leaves would let one voucher be redeemed against each (it is
the hypothesis the Lean model's non-replay theorem takes,
`formal/README.md`; in the sparse profile it holds structurally). The
second is 9.6's rule that a source leaf's `seq` only ever advances: every
carve increments it so that a source leaf whose balance later returns to
a previous value still differs from every previously signed voucher, and
an `UPDATE` or `REWRITE_h` that wound it back, which the scripts do not
forbid, would revive them. One voucher is replayable and harmless: a
self-voucher whose `claim_leaf` equals `source_leaf` for the whole amount
drains the source position and may place the identical leaf back into
it, which leaves the tree unchanged and moves no value
(`self_voucher_fixed` in the Lean model). Honouring a voucher by other
means (for example a `JOIN` of the same `claim_leaf` elsewhere) does
*not* invalidate it; issuers MUST track outstanding vouchers as
liabilities until the source leaf's `seq` has advanced past them
(section 9.6). The voucher binds `tree_id` rather than `m` because `m`
names a rule set that two trees can share, so a voucher over `m` could be
redeemed in both against identical source-leaf bytes (10.3); binding
`tree_id` also lets a voucher survive a `DETACH_h`, which preserves it
(7.10).

#### 7.5.1 CLAIM^h (hash-locked voucher)

`CLAIM^h` is `CLAIM` whose voucher additionally commits to a **payment
hash**, and whose redemption requires the preimage. It is a tree-creation
parameter: a taptree MAY include `CLAIM`, `CLAIM^h`, both or neither, and
the choice is visible in `m`.

Voucher: `voucher_sig` is a BIP-340 signature by `source_leaf.owner_key`
over

```
H_voucher_h( tree_id || source_leaf || claim_leaf || payment_hash )
```

where `payment_hash` is 32 bytes. The tag differs from `TAG_VOUCHER`, so a
plain voucher and a hash-locked voucher are disjoint instruments: neither
can be redeemed by the other's script whatever the payload.

Witness inputs: as `CLAIM`, with a 32-byte `preimage` inserted between
`voucher_sig` and `r`.

Rules: as 7.5, with rule 1 replaced by

1. `preimage` MUST be exactly 32 bytes, and `voucher_sig` MUST verify (via
   `OP_CHECKSIGFROMSTACK`) under `source_leaf.owner_key` over
   `H_voucher_h( tree_id || source_leaf || claim_leaf || SHA256(preimage) )`.

Rules 2 to 6 of 7.5 are unchanged, so `CLAIM^h` conserves the total, is
single-use, keeps the carve rule and the dust floor and empties a drained
source position exactly as `CLAIM` does.

*(informative)* The script does not compare a witness-supplied payment hash
against the preimage. It computes `SHA256(preimage)` and feeds the result
into the signed message, so a wrong preimage produces a different message
and fails as an invalid signature. This costs one `OP_SHA256` and removes
an equality check and 32 witness bytes. The 32-byte length requirement is
not needed for soundness; it bounds the hashed input and matches BOLT-3
payment preimages, so the same hash can be shared with a channel-leaf HTLC
(Appendix C.4) or with a Lightning invoice.

There is **no on-chain expiry**. Bitcoin script can require that a spend not
happen before a height, not that it happen before one, and the value backing
a voucher never leaves the source leaf, so there is nothing to refund. An
issuer who wants an outstanding voucher, plain or hash-locked, to become
void MUST advance the source leaf's `seq`, which any `CLAIM` or `SPLIT` on
that leaf does, as does an `UPDATE` that raises it. Deadlines in a swap
therefore live in the other leg: the Lightning HTLC's `cltv_expiry` or the
channel-leaf HTLC of Appendix C.4.1.
Section 9.6.1 states the resulting protocol requirements and 10.3 the
residual risks.

#### 7.5.2 SPLIT (owner-authorised carve)

`SPLIT` carves a new leaf out of an existing one on the authority of the
source leaf's **owner**, signing the spending transaction, rather than on
the authority of a voucher. Like `CLAIM^h` it is a tree-creation parameter:
a taptree MAY include any combination of `CLAIM`, `CLAIM^h` and `SPLIT`,
and the choice is visible in `m`.

Witness inputs: as `CLAIM`, with `owner_sig` in place of `voucher_sig`.

Rules: as 7.5, with rule 1 replaced by

1. `owner_sig` MUST be a valid BIP-340 signature under
   `source_leaf.owner_key` over the spending transaction, and MUST commit
   to all outputs (10.7).

Rules 2 to 6 of 7.5 are unchanged: the source leaf's amount falls by the
new leaf's amount, its `seq` advances by one, a drained source position
becomes `E_0`, the new leaf is placed at a position proven empty *after*
the source step, the total is conserved, the new leaf keeps the
source's `evictor_key` and a lease no later than the source's, and
neither the new leaf nor a non-zero residual is below `DUST_MIN`.

*(informative)* `SPLIT` is `CLAIM` with the authorisation swapped, and the
spec states it that way rather than restating the steps because the
implementations share one body. Three consequences follow.

It is not a deferred instrument. A voucher is redeemable later by whoever
holds it, without the issuer; a `SPLIT` is signed against one transaction
and is worthless outside it. The credit risk of 9.6 and the issuer's
bookkeeping obligations therefore do not arise. This is the right shape
when the sender is the party broadcasting and paying the fee, which is the
common case for a member paying a member.

It advances `seq` even though there is no voucher to retire, because
without that a `SPLIT` down and a later `UPDATE` back to the same amount
would restore a leaf byte for byte and revive any voucher signed against
it.

It needs no `OP_CHECKSIGFROMSTACK`. `CLAIM` is excluded from the MIN tier
only because that opcode is unavailable there (4.5); `SPLIT` is not, and
is the first member-to-member transition MIN supports (8.6.2). It costs
6,651 bytes of script at `D = 16`, about 1.8 times `EXIT_1`: the two fold
passes are MID's, and the sighash reconstruction is paid once.

`owner_sig` is the only thing that binds the new leaf to its recipient: the
covenant forces output 0 to commit to *some* new leaf of the right amount,
and only a signature over that output says which. Rule 1's coverage
requirement is therefore what stops a relayer rewriting the recipient
(10.7).

#### 7.5.3 CLAIM^x (exit-key consent)

`CLAIM^x` is `CLAIM` whose redemption additionally requires the consent of
the source leaf's `exit_key`, exactly as `UPDATE^x` (7.4 rule 5) adds that
consent to `UPDATE`. `CLAIM^hx` is the same addition to `CLAIM^h`. Both
are tree-creation parameters: a taptree MAY include any combination of
`CLAIM`, `CLAIM^h`, `CLAIM^x` and `CLAIM^hx`, and the choice is visible in
`m`.

Witness inputs: as `CLAIM` (or `CLAIM^h`), with one further element
`exit_sig` directly below `r`, that is, above `voucher_sig` and, in the
hash-locked form, above `preimage`.

Rules: as 7.5 (or 7.5.1), plus

7. `exit_sig` MUST be a valid BIP-340 signature over `tx` by
   `source_leaf.exit_key`, with the same hash-type requirement as 7.2
   rule 3.

Rules 1 to 6 are unchanged, so `CLAIM^x` conserves the total, is
single-use, advances `seq`, keeps the carve rule and the dust floor and
empties a drained source position exactly as `CLAIM` does; the voucher
is still required, and a transaction signature by the source owner does
not stand in for it.

*(informative)* The variant exists for the **dedicated credit leaf** of
10.3: a source leaf the issuer owns (`owner_key`) whose `exit_key` is the
recipient's. Every voucher against such a leaf pays the same recipient,
so the recipient's own redemptions carry `exit_sig` at no cost, and the
issuer cannot carve the leaf at all, not even with a voucher it signs to
itself, because it does not hold the exit key. With `UPDATE^x` and
`EXIT^=` in the same taptree, `REWRITE_h^x` in place of `REWRITE_h` or
no `REWRITE_h` at all (7.9 rule 7), and a finite lease with the operator
as evictor rather than a `NUMS` evictor (10.3: eviction pays the whole
balance to the recipient's key, while a `NUMS` evictor turns every
voucher against the leaf into a leaf no cohort can sweep), the credit
leaf's balance can only grow or be paid to its recipient, which removes
the voiding race of 10.3 for that leaf. The reference generator exposes the
variant as `claim_script(…, exit_consent=True)`. It costs 7 bytes over
`CLAIM` or `CLAIM^h` in the FULL tier, as `UPDATE^x` over `UPDATE`, and
64 bytes of witness.

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
two such shapes, `EVICT_SUBTREE_h` (section 7.7) and `REWRITE_h` (section
7.9); others (sibling pairs, partially filled subtrees) follow the same
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
tree output. `EXIT`, `EVICT_SUBTREE_h`, `REWRITE_h` and `DETACH_h` can
produce `E_D`; no other transition can. Scripts MUST take this branch
only when `r' = E_D` exactly; the reference `FINAL` macro compares against
the constant `E_D` of the tree's depth.

Section 5.2 requires `amount > 0`, and 7.5 rule 6 requires every leaf a
carve writes, and every residual it leaves, to be at least `DUST_MIN`
(6.2). Zero and sub-dust leaves are not harmless. Every transition that
removes a leaf pays it to a P2TR output of exactly its amount (7.2 rule
6, 7.7, 7.9 rule 5), and under default policy a transaction that pays a
fee and carries an output below the dust threshold is not relayed, so
such a leaf blocks `EVICT_SUBTREE_h` on its cohort and `JOIN_h` over
every subtree that contains it for as long as it sits there, and its
owner cannot exit it by a standard transaction either. The carve scripts
enforce the floor because any member can run them; `JOIN`, `UPDATE` and
`REWRITE_h` do not, because the operator signs each of them and would be
squatting its own tree. Operators SHOULD NOT co-sign a leaf below
`DUST_MIN`, since the blocked sweeps and grafts are their own. A leaf
that nevertheless exists can be removed only with its
owner's cooperation (an `UPDATE` that raises it, or a `REWRITE_h` the
owner signs) or by a miner that accepts the non-standard removal.

### 7.9 REWRITE_h (cohort rewrite)

`REWRITE_h` replaces the contents of one aligned subtree of height `h` in
a single spend, with the consent of every owner whose leaf changes and of
the operator. It is the cohort form of `UPDATE`, and with rule 5 it is
also a mass exit, a cohort join and an intra-cohort settlement: within one
transaction a position can go from a leaf to `E_0` (an exit, paid out),
from `E_0` to a leaf (a join, funded), or from one leaf to another (a
resize, renewal, key rotation or payment). It is a tree-creation
parameter: a taptree MAY include `REWRITE_h` for any set of heights, and
the choice is visible in `m`.

Witness inputs: sibling path of the subtree root (`D − h` levels); for
each of the `2^h` positions in position order an **old element** and a
**new element**, each either the 116-byte leaf at that position or the
empty string for `E_0`; for every position rule 3 names, `sig_i`; and
`sig_op`, `r`, `m`. Signatures appear only where rules 3 and 7 require
them, so an unchanged position costs its two elements and nothing else.

Rules:

1. The old node is the subtree root recomputed from the old elements
   (empty elements contribute `E_0`); it MUST `fold` with the path to
   `(r, S)` with `S` equal to input 0's amount.
2. The new node is the subtree root recomputed from the new elements, and
   `r'` is its `fold` with the same path.
3. For every position whose new element differs from its old element and
   whose old element is a leaf, `sig_i` MUST be a valid signature over
   `tx` by `old_i.owner_key` (hash type as in 7.2 rule 3), **except** that
   a position whose new element is a leaf identical to the old one in
   every field but `amount`, with `new_i.amount ≥ old_i.amount`, needs no
   signature. The exception MUST NOT apply when `old_i.seq` equals the
   tier's `SEQ_FINAL` (5.2): such a position needs `sig_i` like any other
   change. A position whose old element is `E_0` needs none.
4. `sig_op` MUST be a valid signature over `tx` by `OPERATOR_KEY`.
5. For every position whose old element is a leaf and whose new element
   is `E_0`, in position order, the next unused output starting from
   output 1 MUST pay exactly `old_i.amount` to `P2TR(old_i.exit_key)`.
6. Output 0 is `(S − Σ old amounts + Σ new amounts, TREE_SPK(r', m))` per
   7.1, or unconstrained if `r' = E_D` (7.8). Any decrease is free for the
   transaction to spend; any increase MUST be funded by other inputs.
7. **Exit-consent variant `REWRITE_h^x`.** A tree MAY be created with
   `REWRITE_h^x` in place of `REWRITE_h`. For every position for which
   rule 3 requires `sig_i`, the witness carries one further signature
   `xsig_i`, which MUST be valid over `tx` by `old_i.exit_key`. This is
   `UPDATE^x` (7.4 rule 5) applied to the cohort, and a tree whose taptree
   carries `UPDATE^x` or `CLAIM^x` (7.5.3) MUST use `REWRITE_h^x` in place
   of `REWRITE_h`, for the same reason: a plain `REWRITE_h` beside either
   reopens the splice (C.6.6) and the voiding path (10.3) they close, and
   the counterparty verifies the choice from `m`.

*(informative)* Rule 3's exception is what makes a payment between
members need only the payer's signature: the payee's leaf gains amount and
changes in no other field, so nobody can use the exception to rotate a key
or shorten a lease. The `SEQ_FINAL` exclusion is for leaves whose amount
is not the owner's alone: a channel leaf's `amount` is the capacity its
pre-signed states commit to (C.1.1), and raising it by even one satoshi
makes every update transaction pay a fee it cannot pay beside a zero-value
ephemeral anchor, so no default node relays it (C.2.4). The exclusion
costs 11 bytes per position (8.9). Rule 5 is what makes the rewrite a safe mass exit: an
owner who signs a transaction that empties its position is paid by the
covenant, and the operator cannot use the script to remove a leaf without
paying it, since removal needs that owner's signature and that payout. A
leaf nobody signs for passes through unchanged, so a cohort settles with
only the members whose leaves change taking part. The script has no lease
check: eviction remains `EVICT_SUBTREE_h`'s job.

The old and new subtrees are both published, so a cohort join by
`REWRITE_h` is grounded by construction where `JOIN_h` (7.3 rule 4) trusts
the joiners to have checked. Spec 13.4's owner multiproof
(`EXIT_SUBTREE_h`) is the special case in which every new element is
either its old element or `E_0`, and is not a separate script.

### 7.10 DETACH_h (subtree detach)

`DETACH_h` moves one aligned subtree of height `h` into a tree output of
its own. After it the cohort is a LayerTree of depth `h` whose root is the
node the members already hold proofs against, so every later transition
on the cohort pays `h` levels instead of `D`, and the cohort's output
spends independently of the parent's (10.5). It is a tree-creation
parameter and the operator's decision, like `JOIN_h`: it spends nobody's
balance and shortens every member's path. It also fixes the cohort's
supply of empty positions: a cohort detached with none, or one the
operator first fills by `JOIN_0`, leaves every partial-balance voucher
against its leaves unredeemable until a position frees, since 7.5 rule
3 places the claim leaf in an empty position (9.6, 10.1).

Witness inputs: sibling path of the subtree root (`D − h` levels),
`R_h` (32 bytes), `sum_h` (8 bytes `le64`), `sig`, `r`, `m`.

Rules:

1. The old node is `(R_h, sum_h)`; it MUST `fold` with the path to
   `(r, S)` with `S` equal to input 0's amount.
2. The new node is `E_h`. Output 0 is `(S − sum_h, TREE_SPK(r', m))` per
   7.1, or unconstrained if `r' = E_D` (7.8).
3. Output 1 MUST be `(sum_h, TREE_SPK(R_h, m_h))`, where `m_h` is a
   constant of the script: the tree identifier (6.2) of the tree of depth
   `h` created with the parent's option set, that is the same profile,
   `OPERATOR_KEY`, `tree_id`, `JOIN` heights, `EXIT_K` sizes and variants
   (exact payouts, `UPDATE^x`, the `CLAIM` forms, `SPLIT`, sweeps,
   rewrites and detaches), compiled at depth `h`; a height that does not
   fit depth `h` is dropped and nothing else is. `m_h` is fixed at tree
   creation and therefore committed to by `m`. A creator MUST NOT
   compile `m_h` from a smaller set: a cohort keeps its rules when it is
   detached, which is what lets channel leaves (Appendix C.6.1) and the
   other option-dependent guarantees survive one. The reference
   generator computes it as `detached_taptree_root(h, OPERATOR_KEY,
   tree_id, options)`, where the default options are the reference set
   of 6.2 (`EXIT_1`, `EXIT_2`, `JOIN_0`, `JOINK_2`, `UPDATE`, `CLAIM`).
4. `sig` MUST be a valid signature over `tx` by `OPERATOR_KEY`.

A member's proof in the detached tree is its proof in the parent truncated
to the lower `h` levels; no member needs new data. The detached tree's
leaves are byte for byte the parent's, so an `EXIT` from it pays the same
`P2TR(exit_key)`, and channel leaves (Appendix C) are unaffected: `chan_id`
binds the parent's `m` as a creation-time constant of the channel scripts,
not as anything a tree script re-derives. Vouchers are unaffected as
well: they bind `tree_id`, which the detached tree inherits (6.2) and
whose `CLAIM` scripts carry the same constant, so a voucher issued against
a leaf of the cohort redeems in the detached tree as issued (9.6),
provided the detached tree has an empty position for the claim leaf
when the voucher draws less than the source's whole balance.

*(informative)* Value is conserved across two tree outputs,
`S = (S − sum_h) + sum_h`; the Lean model states the second output
directly (`detach_sound`, `formal/LayerTree/Cohort.lean`) and proves that
a member's path truncated to its lower `h` levels is a valid exit proof
in the detached tree (`detach_member_payable`). The detached tree is a
depth-`h` tree in every respect, including its own `DETACH_h'` scripts
for every `h' < h` the parent carries. Rule 3 is what makes a detach
invisible to a member: the operator can move a cohort to its own output,
and it cannot change the cohort's rules, keys or balances by doing so
(10.1).

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

`UPDATE^x` (7.4 rule 5) takes the witness
`path(D)  old_leaf  new_leaf  owner_sig  operator_sig  exit_sig  r  m` and
adds one line directly after `PROLOGUE`, so that `exit_sig` is the first
witness element consumed:

```
OP_4 OP_PICK OP_8 32 OP_SUBSTR OP_CHECKSIGVERIFY   # exit_key of the OLD leaf
```

The rest of the script is byte for byte the `UPDATE` script above. In MID
the same line is `21 OP_PICK OP_CHECKSIGVERIFY`, picking the `ek` element of
the old leaf directly.

### 8.6 CLAIM

Witness: `claim_path(D)  source_path(D)  source_leaf  claim_leaf
voucher_sig  r  m` (the claim path is deeper in the stack because it is
consumed second). `<TREE_ID>` is the tree's `tree_id` (6.2), a 33-byte
push, and `<DUST_MIN>` its `DUST_MIN` (330 in the listings), a minimal
number push. The two size checks, the two field comparisons of rule 5 and
the floor of rule 6 on the claim amount are the `CARVE_RULES` macro of
`spec/scripts/structured/`, 25 bytes for rule 5 and 8 for the floor; the
floor on the residual is the `DRAIN_RULE` macro, 7 bytes over the
drained-source branch it extends.
Sparse: `LEAF_POS SPARSE_SETUP` is applied to `source_leaf` before the
first pass and to `claim_leaf` before the second.

Under `0xC0` numerics the raw `le32` `evict_after` fields are not numbers,
so, as the MID `EXIT_1` does for the lock time, the witness supplies the
minimal `evict_after` of the source and of the claim leaf with their
`PADZ` pads (six elements above the seven carve extras), the MID
`CARVE_RULES` checks each pad against the leaf's own field, compares the
two numbers, and compares the evictor-key fields by `OP_PICK`: 60 bytes
of script, plus 7 for the floor of rule 6, which compares the claim
block's amount number (bound to its field by `LEAF_JOIN`) against the
constant; `DRAIN_RULE` is the same 7 bytes as under `0xC2`. The owner key
of the source block therefore sits 31 deep under the authorisation
element, and the voucher message's picks move by six.

```
<SEL_CURR_INPUT> OP_TX OP_0 OP_NUMEQUALVERIFY
OP_2DUP TREE_SPK <SEL_IN_SPK> OP_TX OP_EQUALVERIFY  # src claim vsig r m
OP_TOALTSTACK OP_TOALTSTACK                         # src claim vsig         | m r
OP_2 OP_PICK OP_2 OP_PICK OP_CAT                    # src claim vsig (src||claim)
<TREE_ID> OP_SWAP OP_CAT                            # src claim vsig (tree_id||src||claim)
TAGGED(TAG_VOUCHER)                                 # src claim vsig msg
OP_3 OP_PICK 40 32 OP_SUBSTR                        # src claim vsig msg src.owner_key
OP_CHECKSIGFROMSTACK OP_VERIFY                      # src claim
OP_SIZE 116 OP_EQUALVERIFY
OP_SWAP OP_SIZE 116 OP_EQUALVERIFY OP_SWAP          # src claim
OP_2DUP 72 32 OP_SUBSTR OP_SWAP 72 32 OP_SUBSTR
OP_EQUALVERIFY                                      # claim.evictor_key == src.evictor_key (rule 5)
OP_2DUP 104 OP_4 OP_SUBSTR OP_SWAP 104 OP_4 OP_SUBSTR
OP_LESSTHANOREQUAL OP_VERIFY                        # claim.evict_after <= src.evict_after
<DUST_MIN> OP_OVER OP_8 OP_LEFT OP_LESSTHANOREQUAL OP_VERIFY   # DUST_MIN <= claim.amount (rule 6)
OP_OVER OP_8 OP_LEFT OP_OVER OP_8 OP_LEFT OP_SUB LE64      # src claim le64(src.amt − claim.amt)
OP_2 OP_PICK OP_8 104 OP_SUBSTR OP_CAT              # … || src[8:112]
OP_2 OP_PICK 112 OP_4 OP_SUBSTR OP_1ADD
OP_SIZE OP_4 OP_LESSTHANOREQUAL OP_VERIFY PAD4 OP_CAT   # src claim src'   (seq+1 must fit 4 bytes)
OP_FROMALTSTACK OP_ROT OP_TOALTSTACK OP_TOALTSTACK  # src src'              | m claim r
<TAG_NODE> OP_ROT OP_ROT                            # T src src'
OP_SWAP LEAF_ACC                                    # T src' oh os
OP_ROT LEAF_ACC                                     # T oh os nh ns
OP_DUP OP_NOT OP_IF OP_SWAP OP_DROP <EMPTY_LEAF_HASH> OP_SWAP   # ns == 0 → nh = E_0.hash
OP_ELSE <DUST_MIN> OP_OVER OP_LESSTHANOREQUAL OP_VERIFY OP_ENDIF   # else DUST_MIN <= ns (rule 6)
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

#### 8.6.1 CLAIM^h

Witness: as 8.6 with a 32-byte `preimage` between `voucher_sig` and `r`.
The preimage is hashed and parked on the altstack immediately, so every
stack depth in the rest of the script is as in `CLAIM`:

```
<SEL_CURR_INPUT> OP_TX OP_0 OP_NUMEQUALVERIFY
OP_2DUP TREE_SPK <SEL_IN_SPK> OP_TX OP_EQUALVERIFY  # src claim vsig pre r m
OP_TOALTSTACK OP_TOALTSTACK                         # src claim vsig pre     | m r
OP_SIZE 32 OP_EQUALVERIFY OP_SHA256 OP_TOALTSTACK   # src claim vsig         | m r phash
OP_2 OP_PICK OP_2 OP_PICK OP_CAT                    # src claim vsig (src||claim)
<TREE_ID> OP_SWAP OP_CAT                            # src claim vsig (tree_id||src||claim)
OP_FROMALTSTACK OP_CAT                              # src claim vsig (tree_id||src||claim||phash)
TAGGED(TAG_VOUCHER_H)                               # src claim vsig msg
OP_3 OP_PICK 40 32 OP_SUBSTR                        # src claim vsig msg src.owner_key
OP_CHECKSIGFROMSTACK OP_VERIFY                      # src claim
... as 8.6 from the OP_SIZE 116 check onwards, unchanged ...
```

The MID tier applies the same two insertions to 8.6's MID form. In both
tiers the variant costs 8 bytes of script over `CLAIM` (section 8.8).

#### 8.6.2 SPLIT

Witness: as 8.6 with `owner_sig` in place of `voucher_sig` and no preimage.
No voucher message is rebuilt; the owner's transaction signature is checked
in its place:

```
<SEL_CURR_INPUT> OP_TX OP_0 OP_NUMEQUALVERIFY
OP_2DUP TREE_SPK <SEL_IN_SPK> OP_TX OP_EQUALVERIFY  # src claim osig r m
OP_TOALTSTACK OP_TOALTSTACK                         # src claim osig         | m r
OP_2 OP_PICK 40 32 OP_SUBSTR                        # src claim osig src.owner_key
OP_CHECKSIGVERIFY                                   # src claim
... as 8.6 from the OP_SIZE 116 check onwards, unchanged ...
```

In the MID tier the same two lines replace the fourteen `OP_PICK`s, the
concatenations, the `tree_id` push and the tagged hash that rebuild the
voucher message, so the saving is larger there: 109 bytes in FULL and 159
in MID (section 8.8).

The MIN tier runs the MID authorisation and both steps unchanged and
replaces the four `OP_TX` reads (current input index, input scriptPubKey,
input amount, output 0) with the constructive signature message of 4.4, as
`EXIT_1` does: `TREE_SPK(r, m)` and the folded input amount go into
`sha_scriptpubkeys` and `sha_amounts`, `le64(S') || 0x22 ||
TREE_SPK(r', m)` is the first output in `sha_outputs`, and the message
fixes input index 0. The transaction shape is two inputs (the tree and one
fee input) and outputs `[tree', raw extras]`; the witness gains the nine
raw introspection elements of `EXIT_1` at its bottom. The source owner
signs after the spender has ground the fee input's `nSequence`, since the
signature covers it. Listing: `spec/scripts/MIN_SPLIT_D4.txt`.

In the CCV tier (4.6) the witness of all three carves loses `r` and `m`,
there is no prologue, the first step's old root is bound by `CHECK_INPUT`
and output 0 by the assign-mode `FINAL`. `SPLIT` keeps the two
authorisation lines above and `CLAIM` the voucher check of 8.6 from
`OP_2 OP_PICK` to `OP_VERIFY`, token for token: neither names `m`. Under
`0xC0` the message is assembled from the seven leaf elements by fourteen
`OP_PICK`s as in MID. Listings: `spec/scripts/CCV_CLAIM_D4.txt`,
`CCV_CLAIM_H_D4.txt`, `CCV0_CLAIM_D4.txt`, `CCV0_CLAIM_H_D4.txt`,
`CCV0_SPLIT_D4.txt`.

#### 8.6.3 CLAIM^x and CLAIM^hx

Witness: as 8.6 (or 8.6.1) with `exit_sig` directly below `r`. The
signature is checked first, immediately after the prologue parks `m` and
`r`, so every stack depth in the rest of the script is as in the plain
form:

```
<SEL_CURR_INPUT> OP_TX OP_0 OP_NUMEQUALVERIFY
OP_2DUP TREE_SPK <SEL_IN_SPK> OP_TX OP_EQUALVERIFY  # src claim vsig [pre] xsig r m
OP_TOALTSTACK OP_TOALTSTACK                         # src claim vsig [pre] xsig   | m r
OP_3 OP_PICK OP_8 32 OP_SUBSTR                      # src claim vsig [pre] xsig src.exit_key
OP_CHECKSIGVERIFY                                   # src claim vsig [pre]
... as 8.6 from OP_2 OP_PICK onwards (8.6.1 from OP_SIZE 32 onwards), unchanged ...
```

In `CLAIM^hx` the pick depth is `OP_4`, since the preimage sits between
`voucher_sig` and `exit_sig`. Either form costs 7 bytes over its plain
script (section 8.8), as `UPDATE^x` over `UPDATE`. Listing:
`spec/scripts/CLAIM_X_D4.txt`.

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

In the MID tier a leaf is thirteen witness elements, and rolling each one
up past the machine stack would cost about 40 bytes per position, so the
leaf steps are hoisted into a pre-pass that runs at the top of the stack
before `T` is pushed. Witness: `zf wf zi wi  levels(D − h)  pads  slot_{2^h−1}
… slot_0  sig  r  m`, where a present slot is `leaf(10) ea_num ze we 0x01`
(the exit witness of 8.3 plus a flag) and an empty one is a single empty
element:

```
PROLOGUE <OPERATOR_KEY> OP_CHECKSIGVERIFY OP_1     # … slots idx          | m r
EVICT_LEAF_STEP × 2^h                              # idx                  | m r (s sc) × 2^h
OP_DROP <TAG_NODE>                                 # T
HASH_PASS(h)                                       # T oh os              | m r
<E_h.hash> OP_0  LEVEL_MID × (D − h)  CHECK_OLD FINAL
```

`EVICT_LEAF_STEP` takes the flag (`OP_SWAP OP_IF`, so `MINIMALIF` makes it
exact); for a present leaf it checks `CLTV(ea_num)`, `PADZ(ea_num) ==
evict_after`, `evictor_key == OPERATOR_KEY` and the exact payout to the
next output as in FULL, then parks the node on the altstack as the pair
`(s, sc)` with `sc = H_leaf(leaf) || amount || 0x01`, the 41-byte form a
parent hashes (a leaf's `enc64` is its own amount field, so leaves need no
pad). An empty slot parks `(0, E_0.hash || enc64(0))`. `HASH_PASS(h)` pops
the pairs back last position first and combines them in mirrored
post-order: `[Rsc Rs Lsc Ls] → [psc ps]`, hashing `T || Lsc || Rsc`, with
`psc = ph || ENC64(ps)` taking one `PADZ` pad pair from directly below `T`
for every internal node except the subtree root. The witness lists the pad
pairs so that the first consumed is on top
(`evict_subtree_pad_nodes` in `tools/layertree_mid.py`). Listing:
`spec/scripts/MID_EVICT_SUBTREE_2_D4.txt`; the stack bound is in 4.5.

Every MID macro that takes a number from the witness into a sum
(`LEVEL_MID`'s sibling sum, `LEAF_JOIN`'s amount, the dense join block's
`new_sum`) opens with `NONNEG` (`OP_DUP OP_DUP OP_ABS OP_EQUALVERIFY`,
4.5, 10.6), so that a four-byte `CScriptNum` with its top bit set, which
`PADZ` would otherwise accept as the `le32` of a value in `[2^31, 2^32)`,
cannot enter the fold as a negative number. The MIN tier and the CCV
tier's `0xC0` scripts share these macros. The macro definitions are in
`spec/scripts/structured/MACROS_MID.txt`.

### 8.8 Sizes

Script sizes are `base + 88·levels` (dense) or `base + 135·levels`
(sparse). Witness data (paths, leaves, signatures, `r`, `m`) is
`41·levels + constant` (dense: a 40-byte sibling and a direction element
of one byte or none per level, 129 WU per level with the script) or
`41·(non-empty siblings) + levels + constant` (sparse). Full tables from the
simulator, including varops consumed, are in `spec/scripts/sizes.md`; see
section 11.

### 8.9 REWRITE_h

Witness: `dir_{D-1} sc_{D-1} … dir_h sc_h  block_{2^h−1} … block_0  sig_op
r  m`, with `block_i = [xsig_i] [sig_i] new_i old_i` (`old_0` on top;
each element is 116 bytes or empty; `sig_i` only where 7.9 rule 3
requires it, `xsig_i` only under `^x` and only where `sig_i` is present).

```
PROLOGUE <OPERATOR_KEY> OP_CHECKSIGVERIFY          # …blocks            | m r
OP_1 OP_TOALTSTACK                                 #                    | m r idx
<EMPTY_LEAF_HASH> <TAG_LEAF> <TAG_NODE>            # Z L T
POSTORDER2(h)                                      # Z L T oh os nh ns  | m r idx
OP_FROMALTSTACK OP_DROP                            # drop idx
OP_6 OP_ROLL OP_DROP OP_5 OP_ROLL OP_DROP          # T oh os nh ns      (drop Z, L)
LEVEL × (D − h)
CHECK_OLD FINAL
```

`POSTORDER2(h)` is 8.7's `POSTORDER(h)` with `REWRITE_STEP` for
`LEAF_STEP` and `HASH_STEP2` for `HASH_STEP`: every position yields four
machine elements `oh os nh ns` instead of two, and the generator's
machine depth `d` advances by four. The two constants `Z` (`E_0.hash`)
and `L` (the `TAG_LEAF` prefix) are pushed once and picked by every
position; inline they would cost 186 bytes per position.

**`REWRITE_STEP(d)`** — rolls a position's old and new elements up from
below `Z`, applies 7.9 rules 3 and 5, and converts both to nodes:

```
<d+3> OP_ROLL <d+4> OP_ROLL                        # … old new
OP_2DUP OP_EQUAL OP_NOTIF                          # -- changed --
  OP_OVER OP_SIZE OP_NIP OP_0NOTEQUAL OP_IF        # -- old is a leaf --
    OP_DUP OP_SIZE OP_NIP OP_0NOTEQUAL OP_IF       # -- new is a leaf: rewrite --
      OP_2DUP OP_8 108 OP_SUBSTR OP_SWAP OP_8 108 OP_SUBSTR OP_EQUAL   # old new same_rest
      OP_IF OP_2DUP OP_SWAP OP_8 OP_LEFT OP_SWAP OP_8 OP_LEFT OP_LESSTHANOREQUAL
      OP_OVER OP_4 OP_RIGHT <SEQ_FINAL> OP_EQUAL OP_NOT OP_BOOLAND   # … and seq != SEQ_FINAL
      OP_ELSE OP_0 OP_ENDIF                        # old new exempt   (amount-only increase)
      OP_NOTIF OWNER_AUTH(d) OP_ENDIF
    OP_ELSE                                        # -- new is empty: exit --
      OWNER_AUTH(d)
      OP_FROMALTSTACK OP_DUP OP_1ADD OP_TOALTSTACK # old new idx        | … idx+1
      <SEL_OUT_SINGLE> OP_TX                       # old new amt spk
      <0x5120> OP_4 OP_PICK OP_8 32 OP_SUBSTR OP_CAT OP_EQUALVERIFY
      OP_2 OP_PICK OP_8 OP_LEFT OP_NUMEQUALVERIFY  # old new            (exact payout)
    OP_ENDIF
  OP_ENDIF                                         # (old empty: a join, operator only)
OP_ENDIF                                           # (unchanged)
OP_SWAP ELEM_NODE(d+4, d+3)                        # new oh os
OP_ROT  ELEM_NODE(d+5, d+4)                        # oh os nh ns
```

**`OWNER_AUTH(d)`** — `<d+5> OP_ROLL OP_2 OP_PICK 40 32 OP_SUBSTR
OP_CHECKSIGVERIFY`, consuming the next witness element as the old owner's
signature; under `^x` it is followed by `<d+5> OP_ROLL OP_2 OP_PICK OP_8 32
OP_SUBSTR OP_CHECKSIGVERIFY` for the exit key.

**`ELEM_NODE(k_L, k_Z)`** — `[elem] → [h s]`:

```
OP_SIZE OP_0NOTEQUAL
OP_IF   OP_SIZE 116 OP_EQUALVERIFY
        OP_DUP OP_8 OP_LEFT OP_SWAP                # amt leaf
        <k_L> OP_PICK OP_SWAP OP_CAT OP_SHA256 OP_SWAP   # H_leaf(leaf) amt
OP_ELSE OP_DROP <k_Z> OP_PICK OP_0                 # E_0.hash 0
OP_ENDIF
```

**`HASH_STEP2(d)`** — `[T … loh los lnh lns roh ros rnh rns] → [T … poh
pos pnh pns]`: `OP_2SWAP OP_7 OP_ROLL OP_7 OP_ROLL OP_2SWAP HASH_STEP(d)
OP_2SWAP OP_5 OP_ROLL OP_5 OP_ROLL OP_2SWAP HASH_STEP(d − 2)`; the eight
nodes are on top, so only the `HASH_STEP` pick depths vary with `d`.

Because the script decides from the two elements whether to roll a
signature, the witness carries none for an unchanged position, an
amount-only increase or a join, and a witness that supplies one anyway
fails: the stray element is consumed as the next position's old element.
The `SEQ_FINAL` test reads the last four bytes of the new element, which
`same_rest` has just shown equal the old one's `seq`, so the constant
is the tier's marker and nothing comes from the witness; it is 11 bytes
per position. Listing: `spec/scripts/REWRITE_2_D8.txt`. Measured sizes
are in 11.

### 8.10 DETACH_h

Witness: `dir_{D-1} sc_{D-1} … dir_h sc_h  R_h  sum_h8  sig  r  m`. The
script is `JOIN_h` with the roles of the old and new node exchanged and one
output check added:

```
PROLOGUE <OPERATOR_KEY> OP_CHECKSIGVERIFY          # R_h sum8           | m r
OP_SIZE OP_8 OP_EQUALVERIFY
OP_OVER OP_SIZE 32 OP_EQUALVERIFY OP_DROP          # R_h sum8
OP_OVER <m_h> TREE_SPK                             # R_h sum8 TREE_SPK(R_h, m_h)
OP_1 <SEL_OUT_SINGLE> OP_TX                        # R_h sum8 spk1 amt1 spk1'
OP_ROT OP_EQUALVERIFY                              # R_h sum8 amt1
OP_OVER OP_NUMEQUALVERIFY                          # R_h sum8           (output 1 pays sum_h)
<TAG_NODE> OP_ROT OP_ROT                           # T R_h sum8
<E_h.hash> OP_0                                    # T R_h sum8 E_h.hash 0
LEVEL × (D − h)
CHECK_OLD FINAL
```

`m_h` is a 32-byte constant of the script (7.10 rule 3); the reference
generator computes it as `detached_taptree_root(h, OPERATOR_KEY, tree_id,
options)`, `TreeOptions.at_depth(h)` being the parent's option set at
depth `h`. The
script is `JOIN_h` plus 235 bytes, almost all of them the second
`TREE_SPK`. Listing: `spec/scripts/DETACH_2_D8.txt`.

### 8.11 MIN witness elements and standardness

*(informative)* The MIN tier reconstructs the BIP-341 signature message
from witness-supplied serialisations (4.5), and its `EXIT_1` and `SPLIT`
pass every output beyond the ones the script constrains as one raw
element, `extra_outs` (`tools/layertree_min.py`), which the script
concatenates into the output hash. Consensus bounds that element at 520
bytes under tapleaf `0xC0`. Policy is tighter: Bitcoin Core relays a
`0xC0` tapscript spend only if no witness item exceeds 80 bytes
(`MAX_STANDARD_TAPSCRIPT_STACK_ITEM_SIZE`, section 15). A serialised P2TR
output is 43 bytes and a Pay-to-Anchor output 13, so one P2TR change
output plus an anchor (56 bytes) fits and two P2TR change outputs (86
bytes) do not: such a MIN transaction is valid but not relayed by default
nodes today. This is a policy limit, not a consensus one; a spender keeps
`extra_outs` under 80 bytes (one change output, an anchor if any), and a
future revision of the generator could split the element per output at
the cost of one `OP_CAT` each. Every other witness element in the `0xC0`
tiers is at most 64 bytes (10.10). The simulator checks consensus limits
(520-byte elements, 1,000 stack elements) and the `MINIMALDATA` rules,
not this standardness rule.

## 9. Off-Chain Protocol

This section specifies the behaviour of operators and participants around
the on-chain transitions. Messages between operator and participants are
transported by any authenticated channel; their encoding is out of scope.

### 9.1 Tree creation

The operator chooses `D`, `OPERATOR_KEY`, `tree_id` and the set of `JOIN`
heights, builds the taptree (section 6.2) and publishes `(D, OPERATOR_KEY,
tree_id, heights, m)`. Participants MUST recompute `m` from the parameters
before treating a tree output as a LayerTree; since `CLAIM` carries
`tree_id`, a wrong `tree_id` fails that check.

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

*(informative)* A self-funded `JOIN_h` is a signing round among the
joiners. Every member signs the same transaction, and its output 0
commits to the subtree holding every new leaf, so the cohort must be
fixed before anyone signs, and a member who withdraws, changes its leaf or
never signs invalidates every other member's signature; the operator then
rebuilds the subtree and collects signatures again, with the abort and
retry exposure of a coinjoin or an Ark round. The covenant itself needs
only the operator's signature (7.3 rule 2); the round is the price of
members funding their own leaves on-chain. An operator-funded graft has
no round: the operator fronts the value and is paid off-chain, as the
next two paragraphs describe.

Because every funder signs with `SIGHASH_DEFAULT` or `SIGHASH_ALL`, a
graft with more than one funder cannot be fee-bumped by replacement
without every funder signing again. Such a graft SHOULD carry an
operator change output or a P2A anchor (4.7), so that the operator can
bump it by CPFP without a new signing round, and funders SHOULD expect
fee bumping by CPFP rather than by replacement.

The operator MAY use `JOIN_0` for a single member and MAY fund leaves
itself (for example when providing liquidity to a channel leaf, or when
selling a leaf to a member who pays off-chain).

A member who pays for its leaf off-chain has no input to sign, so step 3
does not protect it. Such a member MUST, before releasing payment, obtain
the confirmed `JOIN_h` transaction, its leaf and its path in the new tree,
and verify that output 0 is an unspent `TREE_SPK(r', m)` and that
`fold(U.leaf, path) = (r', S')`, recomputing every sum. Paying before the
graft confirms trusts the operator to graft; a hash-locked voucher
(7.5.1, 9.6.1) against a source leaf the operator already holds is the
alternative that the covenant enforces. `design/graft.md` discusses the
funding modes.

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
A sweep requires a lock time of at least the `evict_after` of every leaf
in the subtree (7.7 rule 2), so one leaf whose lease runs later holds up
the sweep of its whole cohort until that lease passes, and a leaf with
another evictor blocks it outright. Operators SHOULD therefore require
`evictor_key = OPERATOR_KEY` as a condition of joining a cohort subtree.

A renewal in place blocks the sweep the same way: a member renewed by
`UPDATE` keeps its position, and its cohort cannot be swept until the
new lease passes. Renewal SHOULD therefore relocate the leaf into a
cohort whose lease matches the new one, for example by an `UPDATE` that
renews the lease followed by a `SPLIT` of the whole balance into an
empty position of that cohort (the drained position becomes `E_0` and
the carve keeps the renewed terms, 7.5 rule 5), or by a cooperative exit
and a `JOIN_0` there. Operators SHOULD align leases per cohort.

A member whose own lease is later than a cohort's can also carve a leaf
on its own terms into one of that cohort's empty positions, by `SPLIT`
or a voucher it issues itself. 7.5 rule 5 allows this, since the carve
inherits the carver's lease, and it delays the cohort's sweep until the
carver's lease passes. Operators SHOULD keep cohort subtrees full or
detach them (7.10, 10.8).

### 9.5 Updates

`UPDATE` is used for lease renewal, resizing (splice-in with extra inputs,
splice-out to other outputs), rotating keys, or transferring ownership. Both
signers MUST verify the full transaction before signing; the covenant
enforces only that the tree output's amount tracks the change in the leaf.

### 9.6 Vouchers

A voucher `(tree_id, source_leaf, claim_leaf, voucher_sig)` MAY be issued
by any leaf owner to any recipient. Issuers MUST NOT issue vouchers whose amounts
sum to more than the source leaf's current amount, MUST track each issued
voucher as an outstanding liability until the source leaf's `seq` exceeds
the value at issuance, and MUST rebuild outstanding vouchers (with the new
`seq`) after any `UPDATE`, `CLAIM` or `SPLIT` on the source leaf. A `SPLIT`
voids every outstanding voucher against its source exactly as a `CLAIM`
does, and also lowers the balance they draw on, so the rebuilt set MUST
fit the reduced amount. A `DETACH_h` (7.10) of the subtree holding the
source leaf changes nothing: the detached tree inherits `tree_id` and the
leaf is unchanged, so outstanding vouchers redeem there as issued, given
an empty position for the claim leaf (below). Eviction is different. Once the source leaf's `evict_after` has passed,
its evictor can remove it by `EXIT_1` with `is_evict`, `EXIT_K` or
`EVICT_SUBTREE_h` (7.7), paying the whole balance to the source's
`exit_key`; every outstanding voucher against it is then void, although
the issuer did nothing, and the holder's only recourse is the issuer.

A recipient MUST verify `voucher_sig`, MUST check that `tree_id` is the
value the tree's `CLAIM` scripts carry (it is one of the published
creation parameters from which `m` is recomputed, 9.1), MUST verify that
`source_leaf` is currently in the tree at some position (by obtaining and
checking a path), MUST read the source leaf's `evictor_key` and
`evict_after`, and SHOULD treat a voucher whose source lease has passed,
or will pass before a redemption broadcast now can be expected to
confirm under the bound `Delta(q)` of 10.5, as unsecured credit. A
recipient SHOULD require an issuer's lease to run past the recipient's
own redemption deadline plus `Delta(q)`. A source leaf whose
`evictor_key` is `NUMS` or the recipient's own cannot be evicted out
from under the voucher, and one whose `exit_key` is the recipient's
(the credit leaf of 10.3) pays its whole balance to the recipient when
evicted, so for these the lease check is moot.

A voucher that draws less than the source's whole balance needs an empty
position for its claim leaf (7.5 rule 3); a full-balance voucher uses the
drained source position. The operator controls the supply of empty
positions (10.1), so a recipient SHOULD prefer a full-balance voucher,
or SHOULD verify that an empty position exists in the source's cohort
subtree, which is the whole of the tree once that cohort is detached
(7.10), and redeem before it is filled.

The recipient SHOULD treat the voucher as settled only after (a)
redeeming it via `CLAIM`, or (b) the issuer has included `claim_leaf` via `JOIN`/`UPDATE`
and the recipient has verified inclusion. Until then the recipient bears the
risk that the issuer double-issues against the same balance; the covenant
prevents *over*-redemption, not over-issuance (section 10.3).

*(informative)* Vouchers are the LayerTree analogue of Ark's out-of-round
payments and of the original sketch's signed vouchers: an operator that
keeps a funded bond leaf can pay recipients instantly with a voucher that is
independently redeemable if the operator later disappears.

#### 9.6.1 Hash-locked vouchers and exchanges

A hash-locked voucher (7.5.1) carries the obligations of 9.6 and three more.

An issuer MUST treat a hash-locked voucher as an outstanding liability from
the moment it is signed, exactly as a plain one, and MUST NOT assume it is
dead because a deadline in another protocol has passed: the covenant
enforces no deadline. To retire one, the issuer MUST advance the source
leaf's `seq` (7.5.1) and MUST NOT reuse the same `payment_hash` for a new
voucher against the same leaf until it has.

A recipient MUST NOT treat a hash-locked voucher as payment until it holds
both the voucher and a preimage, and SHOULD redeem promptly once it does,
because the issuer can invalidate the voucher at any time by advancing
`seq`.

Redeeming a hash-locked voucher publishes the preimage on-chain. A party
that holds the same `payment_hash` in another contract (a Lightning HTLC, a
channel-leaf HTLC of Appendix C.4.1, a voucher in another tree) MUST assume
the counterparty in that contract learns the preimage as soon as the
`CLAIM^h` transaction is in a block, and MUST size its own deadlines
accordingly. The shared hash orders the two legs; it does not make the
exchange atomic (9.6.2), which is why a redeemer SHOULD settle or secure
its own leg before broadcasting.

*(informative)* The canonical flow buys a leaf with off-chain funds, for a
recipient holding no on-chain Bitcoin. `A` owns a funded leaf and wants
Lightning liquidity; `B` wants a leaf. `A` draws a preimage `R`, sets
`payment_hash = SHA256(R)`, issues `B` a hash-locked voucher for the leaf,
and offers a Lightning invoice with the same hash. `B` checks the source
leaf's lease as 9.6 and 9.6.2 rule 5 require, then pays the invoice; to
settle it `A` releases `R`, which reaches `B` through the payment. `B` now
redeems the voucher. `B` cannot obtain the leaf without paying, and `A`
cannot take the payment without releasing `R`. `A` keeps the credit risk of
9.6 in the window between issuing and redemption, and `B` keeps the risk
that `A` advances `seq` first; neither is removed by the hash lock, which
orders the exchange rather than securing it. Reversing the roles (`B`
generating `R` and being paid over Lightning) swaps which side carries
which risk. Section 13 item 9 composes the same hash with a channel-leaf
HTLC, giving an exchange with no on-chain step on the channel side.

#### 9.6.2 Pairing a voucher with a channel-leaf HTLC

A `CLAIM^h` voucher is a hash-locked cheque, not an HTLC: the value stays
in the source leaf, and until the redemption confirms the issuer can void
the cheque with a conflicting `EXIT` or `SPLIT` of that leaf. Pairing it
with a channel-leaf HTLC (Appendix C.4.1) that names the same
`payment_hash` therefore gives an ordered exchange, not an atomic swap.
The order is fixed: the HTLC resolves first, its preimage enables the
voucher, and the voucher resolves second (rules 1 and 2); the voucher
holder carries the issuer risk of 9.6.1 from the moment it offers the HTLC
until its `CLAIM^h` confirms (rule 4). Both legs apply the same 32-byte
preimage discipline, so a preimage valid for one is valid for the other by
construction.

The two legs are not symmetric, and the asymmetry drives the rules below.
The HTLC leg has a deadline the chain enforces, `cltv_expiry`, after which
the offerer reclaims it. The voucher leg has none (7.5.1): it stays
redeemable until the issuer advances the source leaf's `seq`.

1. The preimage MUST be generated by the party the **HTLC** pays, not the
   party the voucher pays. That party reveals the preimage in order to
   collect the HTLC, and the revelation is what enables the voucher. If the
   voucher holder generated the preimage, it could redeem the voucher and
   never settle the HTLC.
2. The voucher MUST be the second leg to resolve. An HTLC MUST NOT be left
   waiting on a preimage that appears only when a voucher is redeemed
   on-chain, because the voucher has no deadline and the HTLC does: the
   HTLC would expire while the voucher sat unredeemed. Where this ordering
   cannot be arranged, the parties MUST use two HTLCs instead.
3. A voucher issuer MUST NOT advance the source leaf's `seq` from the
   moment an HTLC naming the same `payment_hash` is offered to it until
   either the voucher has been redeemed or that HTLC has failed or timed
   out. Settling the HTLC does not end this obligation: an issuer that
   collects the HTLC and then voids the voucher has been paid for a voucher
   the counterparty can no longer redeem. Once the HTLC has failed or timed
   out, the issuer retires the voucher as 9.6.1 requires.
4. Rule 3 binds the issuer but no script enforces it, so the voucher holder
   carries the issuer risk of 9.6.1 and 10.3 from the moment it offers the
   HTLC until its `CLAIM^h` confirms. It SHOULD therefore redeem as soon as
   it learns the preimage, and SHOULD NOT treat the swap as complete until
   the `CLAIM^h` is buried deeply enough that the issuer cannot replace it
   in a reorganisation with a transition that advances `seq`. The interval
   between learning the preimage and confirmation includes contention for
   the tree output and is governed by the bound of 10.5, not by a constant.
5. The source leaf's evictor can void the voucher without the issuer
   breaking rule 3, by evicting the source once its lease has passed
   (9.6). Before it offers the HTLC, or pays a Lightning invoice on the
   same hash as in 9.6.1, the voucher holder MUST apply the lease check
   of 9.6 to the source leaf, and SHOULD NOT proceed if the lease can
   pass before the latest time its `CLAIM^h` can be expected to confirm,
   that is, the HTLC's `cltv_expiry` plus `Delta(q)` of 10.5.

*(informative)* Under rule 2 the chain sees at most one leg. In the usual
flow the channel HTLC is settled off-chain by exchanging the preimage, and
only the voucher is redeemed on-chain, so a swap between a channel leaf and
a tree balance costs one `CLAIM^h` transaction and nothing else. Section 13
item 9 notes that both legs are specified; their composition is exercised
by `test_swap` in `tools/test_scripts.py`, which settles both with one
preimage. The deadline reasoning above is exercised block by block by
`tools/test_chan.py` (Appendix C.12): the HTLC payee's sweep reveals the
preimage, the voucher redeems second, and a delta one block below the
budget, an HTLC left waiting on the voucher, and an issuer advancing `seq`
each make the honest party's transaction fail.

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
| Operator | refuse to co-sign `JOIN`/`UPDATE`; graft new leaves into empty positions (`JOIN_h`), including leaves it funds itself; evict a leaf after its `evict_after` (paying it in full), and with it everything carved out of that leaf (7.5 rule 5); issue vouchers against its own leaves; leave a cohort with no empty position (`JOIN_0` into every gap, or `DETACH_h` of a full cohort), which makes every partial-balance voucher against the cohort's leaves unredeemable until a position frees (7.10, 9.6) | move or reduce any other leaf; delay any other leaf's exit beyond the liveness bound of 10.5 (it can contend for the tree output only by fee, like any other spender, and assumption [C] bounds what that buys); freeze any value other than what it grafts and funds itself (9.2); prevent an owner's `EXIT`; change the taptree; change `evict_after` unilaterally |
| Owner | `EXIT` at any time; co-sign `UPDATE`; issue vouchers against their leaf; carve their leaf by `SPLIT` or a voucher | affect any other leaf; withdraw more than their leaf's amount; carve out a leaf with another evictor or a later lease than their own (7.5 rule 5) |
| Anyone | redeem a valid voucher (`CLAIM`); relay transitions | trigger an owner's exit; create leaves; alter amounts |
| Operator, `DETACH_h` (7.10) | with its signature alone (7.10 rule 4), move an aligned cohort into a tree output of its own, which shortens every member's path and gives the cohort its own exit throughput (10.5) | take value from the cohort or from the parent: output 1 carries exactly the cohort's sum under the cohort's own root and output 0 the remainder (7.10 rules 1 to 3); change the cohort's rules, keys or balances: the child is the parent's option set at depth `h` (rule 3), its leaves are the parent's bytes, and its `tree_id` is inherited, so vouchers and channel states survive |

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

A hash-locked voucher (7.5.1) adds ordering, not security. It guarantees
that the holder cannot carve the leaf without the preimage, which is what
lets an off-chain leg be resolved first and the voucher second (9.6.2),
and it leaves both risks of the preceding paragraph exactly where they
were: the issuer can still
over-issue, and can still invalidate an unredeemed voucher by advancing
`seq`. Because the two forms use different tags, a plain voucher cannot be
redeemed under the hash lock and a hash-locked voucher cannot be redeemed
without one; an implementation that reused `TAG_VOUCHER` for both would let
a redeemer strip the hash lock. Redemption publishes the preimage, which
9.6.1 requires holders of the same hash elsewhere to account for.

Eviction voids vouchers too, and it is not the issuer's act. A voucher
binds the source leaf's bytes, so once the source's lease has passed its
evictor can remove the leaf (`EXIT_1` with `is_evict`, or a cohort sweep
by `EVICT_SUBTREE_h`) and every outstanding voucher against it fails
from then on. The leaf's balance goes to its `exit_key`, which for a
shared bond leaf is the issuer, not the holder, so a holder who has paid
for a voucher is left with the issuer's goodwill. 9.6 therefore has the
holder check the source lease, and an issuer whose vouchers are meant to
be secured SHOULD give its source leaf a lease that runs well past the
vouchers' expected redemption; a `NUMS` evictor also secures them, at
the cost to the operator's sweeps that 10.8 describes.

`SPLIT` (7.5.2) is one more way for an issuer to advance `seq` and so void
its own outstanding vouchers. It adds no capability: an owner could already
do the same alone by redeeming a voucher issued to itself. A recipient's
position is unchanged, and the `seq` increment `SPLIT` shares with `CLAIM`
keeps the replay argument below intact, since no sequence of `SPLIT`s and
`CLAIM`s returns a leaf to a byte string it held before. That argument
rests on two rules the covenant does not enforce: `UPDATE` (7.4) and
`REWRITE_h` (7.9) write `seq` as the owner and operator agree, so an owner
who lowers its own `seq` with the operator's help can revive a voucher it
issued (9.6 has the issuer never lower `seq`, and the loss is the
issuer's own), and 5.2's rule that no two leaves share `(owner_key,
nonce)` is what makes a redeemed source leaf unique. The formal model
states both as hypotheses of its non-replay theorem (`voucher_no_replay`,
formal/README.md).

Both risks disappear for a **dedicated credit leaf**: a source leaf the
issuer owns, whose `exit_key` is one recipient's, in a tree whose taptree
carries `CLAIM^x` (7.5.3), `UPDATE^x` (7.4 rule 5) and `EXIT^=` (7.2 rule
6), and carries `REWRITE_h^x` (7.9 rule 7) in place of `REWRITE_h` or no
`REWRITE_h` at all. Over-issuance against such a leaf has no second
victim, since every voucher pays the same recipient, who can watch the
leaf's amount in the tree. Voiding needs the leaf to change, and every
transition that could change it now requires the exit key: `CLAIM^x`,
`UPDATE^x` and `REWRITE_h^x` by rule, and `EXIT^=` because leaving pays
the whole balance to that key. Eviction also pays the whole balance to
that key, so it voids nothing the recipient is owed. Only `SPLIT`
remains, and a tree hosting credit leaves SHOULD omit it from the
taptree. The recipient's remaining exposure is the issuer's liveness,
that is, a provider that stops issuing.

A plain `REWRITE_h` beside these variants reopens the voiding path: 7.9
rule 3 asks only for the owner's and the operator's signatures, which
the issuer holds, so the issuer could rewrite the leaf down to 1 sat
and take the rest as the free decrease of 7.9 rule 6. A recipient MUST
therefore verify from `m` that the taptree carries no plain `REWRITE_h`
before treating a credit leaf as covered by the preceding paragraph.

A credit leaf that receives over Lightning sits behind an inbound HTLC
that pays the issuer, with a voucher that pays the recipient. The issuer
MUST obtain the preimage and settle the inbound HTLC before it issues or
reissues the cumulative voucher for the new running total, which is then
a plain voucher, redeemed under `CLAIM^x`. The reverse order, a
hash-locked voucher issued before the HTLC settles with the preimage held
by the recipient, breaks 9.6.2 rule 1, and on a credit leaf it cannot be
repaired afterwards: if the HTLC fails, 9.6.1 has the issuer retire the
voucher by advancing `seq`, and every transition that could advance a
credit leaf's `seq` needs the recipient's exit key, so the voucher stays
redeemable for a payment that never arrived (`design/audit/channels.md`,
B2). Settling first leaves the recipient exposed to the issuer for one
in-flight payment, the one it has settled and not yet vouched for, which
is the provider that stops issuing of the preceding paragraphs. The
hash-locked form keeps the ordering of 9.6.2, with the preimage drawn by
the issuer as the party the HTLC pays.

A credit leaf's whole amount is the recipient's on every path the issuer
can take alone: `EXIT^=` and eviction pay all of it to the recipient's
exit key, and `UPDATE^x`, `CLAIM^x` and `REWRITE_h^x` need that key to
reduce it. Capital the issuer places in a credit leaf beyond what it has
vouched for is therefore recoverable only with the recipient's consent
(`design/audit/channels.md`, B3). The issuer SHOULD fund a credit leaf
only with what it has already vouched for or is about to, and SHOULD
top it up as credit accrues, either by an amount-only increase under
`REWRITE_h^x`, which 7.9 rule 3 exempts from every signature but the
operator's for a leaf whose `seq` is not `SEQ_FINAL`, or by an
`UPDATE^x` that the recipient signs.

A credit leaf SHOULD carry a finite lease long enough for its purpose,
with the operator as evictor, rather than a `NUMS` evictor. A voucher
binds the claim leaf's bytes and not its position, so the holder of any
voucher against a `NUMS`-evictor leaf can redeem it into an empty
position of any cohort, where the carve inherits the `NUMS` evictor
(7.5 rule 5) and blocks that cohort's sweep for good (10.8). The carves
of a leased credit leaf expire with it, and its eviction costs the
recipient nothing, as above.
`design/receive.md` works through the wallet case this serves.

A voucher commits to `tree_id` (6.2), so it cannot be replayed in another
tree: `tree_id` is unique per lineage by rule, and because every `CLAIM`
script carries it as a constant, a tree with another `tree_id` has no
script that would accept the voucher. `m` alone would not do. It names a
rule set, which two trees created with the same parameters share, so a
voucher bound only to `m` would verify in both against identical
source-leaf bytes, which an owner reusing a key and nonce across trees
produces without noticing. Within a lineage a `DETACH_h` moves each leaf
into exactly one of the two outputs, so a voucher's source leaf exists in
one tree only (7.10). A voucher also commits to the full source leaf
including `seq`, so it cannot be replayed after any change to the source
leaf. It does not commit to the source
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

The CCV tier has no `PROLOGUE`: its `CHECK_INPUT` call binds the old root
to the input under the input's *own* taptree (the `-1` special value), so
the script set is authenticated natively and the witness carries neither
`r` nor `m`. The property is preserved by construction; a CCV-tier
implementation MUST NOT add a witness-supplied taptree operand anywhere
the input or output 0 is checked.

### 10.5 Concurrency, liveness and pinning

All transitions spend the same UTXO, so conflicting transitions are
resolved by fee. An owner's `EXIT_1` conflicts with a pending operator
`JOIN`; either party can replace the other under the replacement rules of
BIP-125 if it pays the required increment. An attacker holding one leaf
can therefore impose a replacement cost on the operator once per leaf per
round. Signatures cover outputs, so a third party cannot alter where an
exit pays.

How long an honest transition can be delayed is not a consequence of
consensus. The chain admits any number of valid conflicting spends of the
tree output, and a corrupt member can produce them without removing a
leaf: a `SPLIT` of its balance back and forth between two positions, or a
voucher to itself redeemed by `CLAIM`; a corrupt operator can do the same
with a `JOIN` and `EXIT` of a leaf it funds. Each confirmed spend
invalidates a pending honest transition, which must be rebuilt against the
new root (9.7). This document therefore states the exit-latency bound as
a policy assumption with two parameters it does not derive:

**[C] (contention).** At most `kappa >= 1` spends of one tree output
confirm per block, and while an honest transition is pending at the
prevailing fee rate at most `beta` conflicting spends confirm ahead of it.

`kappa` is mempool policy, not consensus: 25 under the ancestor and
descendant count limits of Bitcoin Core releases before 31.0 (section 15,
Bitcoin Core policy); at most 64 under cluster mempool, which Bitcoin Core
31.0 (April 2026) shipped in place of the chain limits and which bounds
the size and count of the connected component the tree's chain belongs
to, the old limits remaining only for wallet coin selection; a deployment
MUST assume the lower of what its relay peers enforce; and as low as 1 once any participant attaches
unconfirmed descendants to a payout or change output, which every
transition leaves free. `beta` is economic: it is bounded by the
adversary's fee budget against the honest bid and by nothing else, so
without a bound on it a unilateral exit is a fee auction. Under [C] an
honest transition with `q` honest transitions queued ahead of it takes
effect within

```
Delta(q) = Delta_L · (ceil((beta + q) / kappa) + 1)
```

blocks, where `Delta_L` is the latency of one confirmation at the chosen
fee rate. Nothing in the bound depends on the tree's membership `N`, which
a corrupt operator controls by grafting. Appendix C.4.4 consumes
`Delta(q)` as `G_exit`, and the cell "cannot delay" of 10.1 means this
bound and nothing stronger.

*(informative)* Cooperatively (`beta = 0`, `kappa = 25`, `Delta_L = 1`)
a tree drains 25 single-leaf exits per block, so 10,000 leaves leaving at
once take about 400 blocks; `EXIT_K` raises the rate only for parties who
cooperate. That throughput is a cooperative-case figure, not a guarantee.
TRUC (BIP-431) is not an option for transitions, since it caps an
unconfirmed chain at two transactions and the chain is the throughput;
pinning by a low-fee-rate ancestor on the fee input, or by descendants
hung off a payout or change output, is outside what [C] models and is
mitigated by policy (package relay, anchors), not by the scripts.

Operators SHOULD size each tree by exit throughput rather than by depth,
and SHOULD shard a deployment into several trees when the time to drain
one at `kappa` leaves per block would exceed the time-sensitive
commitments its leaves carry (for channel leaves, Appendix C.9.5 gives the
rule). Operators SHOULD honour cooperative exit requests promptly
(removing the incentive to contend), MAY chain several transitions off one
confirmed output within the chain limit, and SHOULD use anchor outputs so
that either party can bump fees.

`DETACH_h` (7.10) is sharding on demand. A detached cohort spends its own
output, so its transitions form their own unconfirmed chain and `kappa`
applies to it separately: an operator that detaches `k` cohorts raises the
deployment's cooperative exit throughput to about `kappa · (k + 1)` leaves
per block. Operators SHOULD detach a cohort when its leaves become
time-sensitive, for instance channel leaves whose HTLC deadlines are near,
rather than size every tree for the worst case in advance.

### 10.6 Integer encodings and truncation

* Amounts and sums are unsigned. `OP_SUB` underflow fails the script, which
  is what makes over-claims and negative balances impossible.
* Under `0xC0` numerics (MID, MIN, CCV with `0xC0`) `CScriptNum` is
  sign-magnitude: a four-byte operand with its top bit set is negative,
  and `PADZ` alone would accept the `le32` of a value in `[2^31, 2^32)` as
  that negative number, so a leaf amount, a joined sum or a sibling sum of
  `2^31 + 2^24` would enter the fold as `-2^24` and commit a node whose
  sum exceeds the tree output by that much. The `NONNEG` check (`OP_DUP
  OP_DUP OP_ABS OP_EQUALVERIFY`, 4.5) MUST guard every witness-supplied
  number that enters a sum; it compares the operand with its own
  re-encoded absolute value, so it also rejects a negative zero and every
  non-minimal encoding without relying on the `MINIMALDATA` policy.
  Accumulated sums are then non-negative, and `PADZ`'s four-byte bound
  keeps each below `2^31`. `evict_after` and `seq` are not sums and keep
  `PADZ` alone (`OP_CHECKLOCKTIMEVERIFY` fails on a negative operand by
  itself, and `seq`'s `CScriptNum` reading is what 5.1 and 7.5 rule 2
  describe).
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
harmless and useful for adding a fee input later. `SPLIT` signatures carry
the same requirement (7.5.2) for a stronger reason: output 0 is the only
place the new leaf's contents reach the signature, so a signature that
skipped it would let a relayer substitute its own leaf for the recipient's.
`JOIN` and `UPDATE` signers SHOULD use `SIGHASH_DEFAULT`; change outputs
are never constrained by script.

Leaf keys are checked by `lift_x` at signature verification; a leaf with an
invalid `owner_key` can never `EXIT` and an invalid `exit_key` pays to an
unspendable output. Joining members MUST check their own keys (section 9.2)
and operators SHOULD validate all leaf keys before grafting.

### 10.8 Eviction

Eviction pays the leaf in full to `exit_key`; it cannot shortchange or
redirect the leaf. It does void every outstanding voucher against the
evicted leaf, and a cohort sweep (7.7) voids every voucher against every
leaf it removes: the holders are not paid by the eviction, and the
issuer, not the evictor, owes them (9.6, 10.3). Its cost to the owner is
loss of the off-chain position and, for channel leaves, a forced
on-chain channel. `evict_after` bounds when this
can happen and is renewable only with the owner's signature (`UPDATE`).
Owners SHOULD treat `evict_after` as a lease expiry and renew ahead of it.

Carves preserve it. A leaf created by `CLAIM` or `SPLIT` keeps the
source's `evictor_key` and a lease no later than the source's (7.5 rule
5), so eviction holds per balance: no sequence of carves takes value out
from under a lease, and a member of an evictable cohort cannot block the
cohort's sweep (7.7) for good by planting a non-evictable leaf in one of
its empty positions. A member whose lease is later than the cohort's can
still delay the sweep until its own lease passes, by carving a leaf on
its own terms into an empty position of the cohort, and a member renewed
in place delays it the same way (9.4). What the rule does not reach is a leaf the operator admitted
as non-evictable, with a `NUMS` evictor or a far `evict_after`: it can
carve leaves of the same terms into any empty position, including a
cohort's. Nor is the carver always the leaf's owner: a voucher binds the
claim leaf's bytes and not its position, so whoever redeems a voucher
against such a leaf chooses the empty position its carve lands in, and
a credit leaf (10.3) has as many such redeemers as it issues vouchers.
An operator that relies on `EVICT_SUBTREE_h` SHOULD therefore admit
such leaves only where that is acceptable, SHOULD prefer a finite
`evict_after` to a `NUMS` evictor, since a finite lease still ends, and
a credit leaf SHOULD carry such a lease (10.3). It SHOULD also keep
cohort subtrees full or detach them (7.10): a full subtree has no empty
position to carve into, and a detached child can be carved into only
by its own members.

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
`D = 32` uses 3.07M against a budget of about 65M for its weight (4.7%),
and the 256-level tree 9.3M against about 376M (2.5%): the fraction falls
with depth because the budget scales with transaction weight. Stack depth
peaks at 42 elements (`CLAIM`: 75; sparse `EXIT_2`: 80) against a limit
of 32,768 (1,000 in the `0xC0` tiers, 4.5).

Element sizes, measured on the reference witnesses: in FULL and in CCV
under `0xC2` the largest witness element is the 116-byte leaf, with
everything else at most 64 bytes (a signature; a sibling is 40 bytes);
in MID, MIN and CCV under `0xC0` the leaf travels as seven field elements
and no witness element exceeds 64 bytes, except MIN's raw `extra_outs`
(8.11). The largest elements built during execution are the voucher
message of `CLAIM` (328 bytes, 360 bytes for `CLAIM^h`), the tagged node
preimage (144 bytes) and, in MIN, the reconstructed sighash message (276
bytes), all under the 520-byte element limit of `0xC0`. The
policy-relevant size is Bitcoin Core's 80-byte standardness cap on `0xC0`
tapscript witness items (section 15): the `0xC0` tiers stay under it
except as 8.11 describes, and the 116-byte leaf of the `0xC2` tiers
relies on the relay assumption of 4.7, since no standardness rule for
`0xC2` exists yet.

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
the simulator (`tools/gen_listings.py` → `spec/scripts/sizes.md`) and
priced on one transaction model. `spec/fee-analysis.md`
(`tools/fee_analysis.py`) and the paper use the same model unchanged, so
a figure that appears in more than one place is the same figure:

* **Measured witness (WU).** The script, the witness elements and a
  129-byte control block, one weight unit per byte. The control block is
  for the reference script set of 6.2, eight tapleaves and so taptree
  depth 3; 11.1 prices a larger set. The sweeps, rewrites, detach and
  variants priced below would need 16 to 32 leaves in one taptree, 8 to
  16 vB more on every spend.
* **Skeleton.** 946 WU: the tree input (41 vB), a P2WPKH fee input (41 vB
  plus 108 WU of witness), the tree output (43 vB), one P2TR payout
  (43 vB), a P2WPKH change output (31 vB), version, lock time and counts
  (10 vB), and the segwit marker and flag (2 WU). Each further payout
  adds 172 WU (43 vB). A transition with no payout (`JOIN`, `UPDATE`,
  `CLAIM`, `SPLIT`, the update case of `REWRITE_h`) is priced without one,
  774 WU; `DETACH_h` uses the slot for its second tree output. The
  FULL-tier endogenous fee form (9.3) drops the fee input and change,
  550 WU.
* **Virtual bytes.** `vB = ceil(WU / 4)`, rounded once per transaction;
  per-leaf figures divide that by the leaves that leave or change.
* **Excluded.** The witness item count and the per-item length prefixes
  (one byte per element below 253 bytes, three for the script).
  `spec/scripts/weights.md` (`tools/measure_weight.py`) serialises the
  transaction each test builds and measures what the model leaves out:
  on a dense `D = 16` `EXIT_1` it is 42 WU (10.5 vB) in FULL with 39
  witness items, 40 WU (10 vB) in CCV, but 170 WU (42.5 vB) in MID and
  179 WU (44.75 vB) in MIN, whose witnesses carry each level's sibling as
  several small elements (over 160 items); a MID sweep at `h = 6` has
  about 950 items, 955 WU of prefixes. Measured against the model, the
  owner `EXIT_1` rows are FULL dense 1,030 vB (model 1,020), FULL sparse
  `D = 32` 1,648 (1,637), MID dense 1,398 (1,355), MID sparse `D = 31`
  2,896 (2,819), MIN dense 1,518 (1,473), CCV dense 918 (908) and CCV
  sparse 1,535 (1,525). The prefixes are omitted the same way from every
  row here, in `spec/fee-analysis.md` and in the paper, so the
  comparisons between rows stand; the absolute figures are about 1% low
  in FULL and CCV and about 3% low in MID and MIN. The transaction-tree
  baseline below is a model, not a measurement, and carries no such term.

| profile | D | positions | EXIT_1 script | EXIT_1 witness data | total witness (WU) | approx. tx weight (WU) | approx. vbytes |
|---|---|---|---|---|---|---|---|
| dense | 8 | 256 | 1,397 | 574 | 2,100 | 3,046 | 762 |
| dense | 12 | 4,096 | 1,749 | 738 | 2,616 | 3,562 | 891 |
| dense | 16 | 65,536 | 2,101 | 902 | 3,132 | 4,078 | 1,020 |
| dense | 20 | 1,048,576 | 2,453 | 1,066 | 3,648 | 4,594 | 1,149 |
| dense, minimal inventory | 16 | 65,536 | 2,378 | 886 | 3,393 | 4,339 | 1,085 |
| dense, `EVICT_SUBTREE_4` (13 leaves swept) | 16 | 65,536 | 5,281 | 2,129 | 7,539 | 10,549 | 2,638 (203 per leaf) |
| dense, `EVICT_SUBTREE_6` (51 leaves swept) | 16 | 65,536 | 16,097 | 6,455 | 22,681 | 32,227 | 8,057 (158 per leaf) |
| sparse | 32 | 2^32 | 5,147 | 244 + 41·k | ≈ 6,180 (N = 2^16) | ≈ 7,120 | ≈ 1,780 |
| sparse | 64 | 2^64 | 9,499 | 244 + 41·k | ≈ 10,530 (N = 2^16) | ≈ 11,470 | ≈ 2,870 |
| sparse | 256 | 2^256 | 35,611 | 203 + 41·k | ≈ 36,600 (N = 2^16) | ≈ 37,550 | ≈ 9,390 |
| dense, CCV tier | 16 | 65,536 | 1,716 | 838 | 2,683 | 3,629 | 908 |
| sparse, CCV tier | 32 | 2^32 | 4,762 | 180 + 41·k | ≈ 5,730 (N = 2^16) | ≈ 6,670 | ≈ 1,670 |

Sparse witness sizes are a formula in `k`, the number of non-empty
siblings on the path, which is about `log2 N` for `N` members; the
measured figures in `spec/scripts/sizes.md` (326, 285 and 262 bytes) are
on a six-leaf tree with `k = 2`, and the totals here take `k = 16`.

The CCV-tier rows (section 4.6) replace the `TREE_SPK` recomputations
with `OP_CHECKCONTRACTVERIFY` calls: about 390 script bytes and 64
witness bytes saved per `EXIT_1` against FULL at `D = 16`, and no EC-ops
dependency. The `r` and `m` witness elements are gone entirely. Each CCV
call charges one sigcheck-equivalent (500,000 varops, [A-6]); an
`EXIT_1` makes two calls, within the same budget headroom as the FULL
tier's two `TREE_SPK` recomputations. A CCV `CLAIM` at `D = 16` (dense)
measures 3,487 / 1,626 bytes against FULL's 3,874 / 1,690; it is the one
CCV script that needs `OP_CHECKSIGFROMSTACK` (4.6).

The transaction weight column adds the 946 WU skeleton of the model
above. In the dense profile each level costs 129 WU regardless of
occupancy: 88 of script and 41 of witness (a 40-byte sibling node and a
direction element of one byte or none), which is the slope of the table
(516 WU per four levels); the two length prefixes those elements carry on
the wire are among the excluded bytes above. In the sparse profile each
level costs 135 WU of script plus 1 WU for an empty sibling or 42 WU for a
non-empty one, so witness data grows with `log2 N` rather than with `D`.
The minimal-inventory row (section 4.4) shows the price of doing without
the restored splice opcodes and the EC point opcodes: about 260 WU per
exit.

The sparse profile at `D = 32` costs about 1.8 times the dense profile at
`D = 16` per exit (1,780 against 1,020 vB at `N = 2^16`; 1.7 to 2.8 times
over `D = 32` to `64`), which is why dense is the default profile (5.4).
What sparse buys is key-addressed positions: no slot allocation, a
history-independent root, and structural uniqueness of leaves. The full
256-level MS-SMT costs about 17 times the dense script and 9 times the
dense transaction and is not recommended; truncating positions to 32–64
bits loses nothing but the ability to use a raw key as the position.

For comparison, a unilateral exit from a radix-2 Ark or CTV tree of `2^D`
leaves publishes `D` transactions, modelled at 150 vB each (one key-path
P2TR input and two P2TR outputs), plus a 111 vB claim of the leaf (the
same model as `spec/fee-analysis.md`), and waits out a relative timelock
at the leaf, while the operator must publish the whole tree to reclaim
expired leaves. LayerTree pays a fixed cost of about 2,000 WU, or 500 vB
(the EC-heavy prologue, the leaf, the signature and the transaction
skeleton), plus 129 WU per level, about 32 vB, so it breaks even near
`D = 3` (8 leaves) and is about 2.5 times cheaper at `D = 16` (1,020
against 2,511 vB, about 60% smaller); the gap widens with size. The model
ignores the leaf's timelock and the separate fee of each tree
transaction, which favours the tree, and the sharing of a tree's interior
transactions among exits in the same round, which favours it the other
way. The trade-off is that LayerTree requires the larger opcode set of
section 4, whereas CTV-based trees need only a template opcode.

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

| script | positions | leaves swept | script | witness | witness per leaf (WU) | tx vB per leaf | sequential equivalent |
|---|---|---|---|---|---|---|---|
| `EVICT_SUBTREE_2` | 4 | 3 | 2,709 | 1,051 | ≈ 1,300 | 432 | `EXIT_4`: 7,039 B script |
| `EVICT_SUBTREE_4` | 16 | 13 | 5,281 | 2,129 | ≈ 580 | 203 | `EXIT_16`: 26,791 B script |
| `EVICT_SUBTREE_6` | 64 | 51 | 16,097 | 6,455 | ≈ 445 | 158 | `EXIT_64`: 105,847 B script |

(`D = 16`; three of every sixteen positions already empty. The witness
column is script plus witness elements plus control block, the
transaction column prices the whole transaction on the model above with
one payout per leaf.) Per-leaf witness falls from about 2.5 kWU
(sequential) or 4 kWU (standalone) to about 0.45 kWU, and at the
transaction level from 1,020 vB (standalone `EXIT_1`) or 842 vB (per exit
in `EXIT_2`) to 203 and 158 vB; the script grows only with the subtree,
not with `D` per leaf. This is why cohorts SHOULD be grafted into aligned
subtrees with a common lease expiry: the operator can then both add a
cohort in one constant-shape transaction and remove it in one
transaction per cohort.

The MID tier's sweep (8.7) measures 4,097 / 1,157, 7,865 / 2,417 and
23,873 / 7,461 bytes of script / witness data for `h = 2, 4, 6` on the
same cohorts, about 1.5 times FULL's script and 1.1 to 1.2 times its
witness: about 615 WU of witness per leaf at `h = 6` against FULL's 445.
A full 32-leaf `EVICT_SUBTREE_5` measures 13,149 / 4,907 bytes (about
565 WU per leaf). The 1,000-element stack limit caps a MID sweep at
`D = 16` to 54 occupied positions (4.5), so a full 64-leaf cohort takes
two `EVICT_SUBTREE_5` spends.

`REWRITE_h` (section 7.9) runs the same fold over two subtrees and is the
members' counterpart: a mass exit, a batched `UPDATE` and an intra-cohort
settlement at once. Measured at `D = 16` with every position occupied
(`exit`: every leaf leaves; `update`: every key rotated; `mixed`: the
scenario of `tools/test_scripts.py`, with exits, joins, rotations,
renewals and payments, three of every seven positions empty or joining):

| script | positions | scenario | script | witness | owner sigs | tx vB | per-leaf vB |
|---|---|---|---|---|---|---|---|
| `REWRITE_2` | 4 | exit | 2,775 | 1,423 | 4 | 1,448 | 362 |
| `REWRITE_4` | 16 | exit | 5,512 | 3,501 | 16 | 3,167 | 198 |
| `REWRITE_6` | 64 | exit | 17,148 | 12,059 | 64 | 10,280 | 161 |
| `REWRITE_6` | 64 | update | 17,148 | 19,483 | 64 | 9,384 | 147 per changed leaf |
| `REWRITE_6` | 64 | mixed (51 changed, 9 exits) | 17,148 | 15,139 | 36 | 8,685 | 170 per changed leaf, 136 per position |

The transaction column prices the whole transaction on the model above:
the skeleton with one payout per exiting leaf and none in the update
case; the per-leaf column divides it by the leaves that leave or change.
The marginal costs are what the design turns on: at `h = 6` each
position costs 244 bytes of script (its `REWRITE_STEP` and its share of
the `HASH_STEP2`s) and 234 bytes of witness for its two elements, about
120 vB, an owner signature adds 16 vB, and an exit adds the 43-byte
output and drops the 117-byte new element, so an unchanged leaf costs
about 120 vB, a changed leaf about 136 vB and an exiting leaf about
150 vB. Sixty-four owners who leave together therefore pay about what
the operator pays to sweep them (`EVICT_SUBTREE_6`: 158 vB per leaf), and
a cohort that rewrites every balance pays about 147 vB per leaf against
1,030 vB for an `UPDATE` each (3,346 WU of witness on the skeleton
without a payout). `REWRITE_h^x` adds the 65-byte exit-key signature,
16 vB, to every signed position (`REWRITE_X_4`, mixed: 5,810 / 4,905
bytes).

`DETACH_h` (section 7.10) caches the shared path across transactions. At
`D = 16`, `h = 8` it costs 1,548 bytes of script and 497 of witness,
2,174 WU with the control block and 780 vB on the model above (the
skeleton's payout slot is its second tree output), and every later
`EXIT_1` from the detached tree costs the depth-8 figure of the table
above, 762 vB instead of 1,020, so it pays for itself at the fourth exit;
a cohort of 256 that all leave alone saves about a quarter. Its larger
effect is on throughput (10.5), not bytes.

Varops usage is 5.6–7.7% of budget for the dense profile (`D = 20` to
`D = 8`) and 2.5–4.7% for the sparse profile (`D = 256` to `D = 32`),
falling with depth because the BIP-440 budget is `10,000 × weight`; the EC operations (82 sigops units per `TREE_SPK`) and the
signature dominate at small depths, hashing at large ones.

### 11.1 Script-set size and the control block

*(informative)* The taptree holds one tapleaf per *compiled script*, and
because tapscript has no loops, each parameter choice compiles to different
bytes and therefore occupies its own leaf. The script set is the cross
product of transition type and parameter: one leaf per `K` in `EXIT_K` and
`JOINK_K`, one per height `h` in `JOIN_h` and `EVICT_SUBTREE_h`, plus the
single-shape transitions and any variants of 7.4 rule 5, 7.5.1 and 7.5.2.
The reference set of 6.2 is eight leaves:

```
EXIT_1  EXIT_2  JOIN_0  JOIN_2  JOINK_2  UPDATE  CLAIM  EVICT_SUBTREE_2
```

A script-path spend reveals one leaf and its Merkle path, so the control
block is `33 + 32·ceil(log2(leaves))` bytes and is paid on **every** spend,
including an `EXIT_1` that never touches a batched script:

| leaves | taptree depth | control block | vB, against the reference set |
|---|---|---|---|
| ≤ 2 | 1 | 65 B | −16 |
| ≤ 4 | 2 | 97 B | −8 |
| ≤ 8 | 3 | 129 B | 0 |
| ≤ 16 | 4 | 161 B | +8 |
| ≤ 32 | 5 | 193 B | +16 |
| ≤ 64 | 6 | 225 B | +24 |

Each doubling of the script set therefore adds 8 vB to every transition,
about 0.8% of a dense `D = 16` exit. The asymmetry runs the other way:
a batch size that is *absent* forces the fallback of `K` separate
transactions at full price, where `EXIT_2` costs 842 vB per leaf against
1,020 vB standalone and `EVICT_SUBTREE_6` costs 158 vB per leaf. Missing a
useful shape costs hundreds of virtual bytes per leaf; carrying an unused
one costs eight.

A creator is therefore better served by a generous set of powers of two
than by a minimal one. Two constraints bound it in practice, and neither is
the control block: every script in the set must be generated and audited,
and `m` is the tree's identity (6.2), so the set is fixed at creation.
Extending it later means creating a new tree and moving every member,
which is why 9.1 has participants recompute `m` from the published
parameters, making the supported shapes part of what they verify.

### 11.2 Exit economics at various fee rates

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
tier and profile move it more (MID +33%, MIN +44%, sparse 1.7 to 2.8
times at `N = 2^16`): one tier step costs as much as 10 to 14 levels of
depth. The FULL-tier endogenous fee option saves a constant 99 vB.
Batching lowers the cost of a second exit in the same transaction to
665 vB (its marginal weight rounded on its own; `EXIT_2` is 1,684 vB in
all, 842 per exit), and cohort sweeps lower eviction to 203 vB per leaf
(`EVICT_SUBTREE_4`) and 158 vB per leaf (`EVICT_SUBTREE_6`), which is
what keeps small leaves evictable at high fee rates; operators SHOULD size
cohorts and minimum leaf amounts so that a sweep stays below about 10% of
the smallest leaf at the fee-rate tail they intend to survive. Dust (330
sat) is never the binding constraint on an exit's fee for `D ≥ 8`; the
fee is. It binds elsewhere: `DUST_MIN` (6.2, 7.5 rule 6) keeps every
carved leaf and residual at or above the threshold, so that the
transaction removing it stays relayable (7.8); an operator's minimum leaf
amount is the larger of the two.

## 12. Comparison With Related Constructions

*(informative)*

| Property | LayerTree | Ark (rounds + VTXO tree) | Timeout trees | CTV/CCV trees (MATT-style) |
|---|---|---|---|---|
| Unilateral exit cost | 1 tx, `O(1)` in `N`, `O(D)` bytes | `O(log N)` txs | `O(log N)` txs | `O(log N)` txs |
| Operator eviction of one leaf | 1 tx after `evict_after`; carves inherit the lease, so it holds per balance (7.5 rule 5) | not possible; whole tree expires | not possible; whole tree expires | not possible |
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
   cost of three 41-byte siblings per level. Measured in the dense FULL
   tier (`tools/experiments/radix4.py`), a radix-4 level is 146 bytes of
   script and 123 of witness against 88 and 41, so at `D = 16` an exit
   saves about 240 bytes of script and adds about 330 of witness, a net
   loss; radix 8 is worse. The sparse profile may gain from radix 4
   because most of its siblings are empty; `design/tree-comparison.md` has the
   analysis.
3. **Smaller `LEVEL`.** With `OP_MULTI OP_CAT` the four concatenations per
   level collapse to two; keeping `ZERO8` on the stack replaces the 9-byte
   push in `PAD8` with a 2-byte `OP_PICK`. Together these save roughly 25%.
4. **More multiproof shapes.** The owner-authorised mass exit within a
   subtree is now built as `REWRITE_h` (7.9, 8.9), which also covers
   cohort joins, batched updates and intra-cohort settlement; the entry is
   kept so the numbering stays stable. The `POSTORDER` generator of 8.7
   extends likewise to sibling pairs (the `CLAIM` of a dedicated credit
   leaf and its reserved claim slot, `design/receive.md`) and to subtrees
   with a fixed pattern of empties. A runtime-shaped multiproof (a stack
   machine driven by witness flags) is also expressible but does not reduce
   script size.
5. **Aggregate node keys.** Storing a MuSig2 aggregate of all owner keys in
   each node (72-byte `sc`) allows a "replace subtree" transition authorised
   by one aggregate signature, giving Ark-style cooperative round updates
   for whole cohorts in one signature. This reintroduces interactive nonce
   coordination and is left for a separate document.
6. **Hash-locked vouchers.** Now specified as 7.5.1 (`CLAIM^h`), with the
   protocol in 9.6.1 and the security analysis in 10.3; the entry is kept so
   the numbering stays stable. It enables ordered exchanges (9.6.1, not
   atomic swaps) between trees, into Lightning, or with on-chain funds,
   and third-party liquidity provision: any leaf owner can service such an
   exchange by issuing a voucher.
7. **Nesting.** A leaf's `exit_key` may be the output key of another
   LayerTree, giving hierarchical trees with constant-size exit at each
   level.
8. **`OP_INTERNALKEY` fast path.** Where only `r` must be checked (never
   for output construction), `OP_INTERNALKEY` saves one `OP_TX` and one
   `TREE_SPK`; see the caveat in section 10.4.
9. **Vouchers and channel HTLCs share a hash.** Now specified as 9.6.2: a
   `CLAIM^h` voucher (7.5.1) and a channel-leaf HTLC (Appendix C.4.1) that
   name the same payment hash give an ordered exchange between the credit
   instrument and the settlement instrument (HTLC first, voucher second,
   issuer risk on the voucher holder until its `CLAIM^h` confirms), with
   one leg on-chain at most.
   The entry is kept so the numbering stays stable.
10. **`UPDATE` with `exit_key` consent.** Now specified as 7.4 rule 5
   (`UPDATE^x`); the entry is kept so the numbering stays stable.
11. **A `CLAIM` that credits an existing leaf.** A partial-balance
   voucher needs an empty position, whose supply the operator controls
   (10.1, 9.6). A `CLAIM` form whose second step is an amount-only
   increase of a leaf the recipient already holds, named by the voucher,
   needs no empty position and reuses the exemption test of `REWRITE_h`'s
   step (7.9 rule 3). It is also the natural shape for the sibling-pair
   claim of item 4 and `design/receive.md`. It is new script work and
   is not specified (`design/audit/protocol.md`, A5).

## 14. Test Vectors and Reference Code

* `spec/test-vectors.json` — tag prefixes, `NUMS`, empty nodes `E_0 … E_32`,
  a depth-4 example tree (leaves, root, internal key, creation outpoint
  and `tree_id`, output key, scriptPubKey, all paths), and one worked
  vector for each transition type including the voucher messages over
  `tree_id`. Regenerate with `python3 tools/layertree_ref.py`.
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
  operands during development), 268 and 55 checks respectively; the MID
  checks include both `SEQ_FINAL` candidates, showing that `0xFFFFFFFF`
  *is* claimable under `CScriptNum` and `0x7FFFFFFF` is not, the voucher
  binding of `CLAIM` and `CLAIM^h` (a wrong signer, a voucher signed for
  another `tree_id` and a voucher over `m` all fail), and the
  `UPDATE^x`, `CLAIM^h` and `SPLIT` variants of 7.4 rule 5, 7.5.1 and
  7.5.2 in both profiles, the dense `JOIN_2` negatives (occupied slot,
  no operator signature), a stale `JOINK_2` second path, and the MID
  `SPLIT` with the negatives of the FULL suite below, the carve rule of
  7.5 rule 5 (another evictor key or a later `evict_after` fails under
  `CLAIM` and `SPLIT`, and the cohort case of the FULL suite under the MID
  sweep), the dust floor of 7.5 rule 6 (a claim or split of one satoshi,
  of zero satoshis or one leaving a one-satoshi residual fails under
  `CLAIM` and `SPLIT` in both profiles, while exactly `DUST_MIN` and the
  whole balance succeed), and the cohort
  sweep `EVICT_SUBTREE_2/4/6` at `D = 16` with the FULL suite's negatives
  (a sweep before lease expiry, a shortchanged leaf, a non-evictable
  leaf) plus an occupied position presented as empty, a malformed node
  pad, a missing operator signature and a wrong `m`, a full 32-leaf
  `EVICT_SUBTREE_5`, and a full 64-leaf `EVICT_SUBTREE_6` rejected by the
  stack limit (4.5), and the sign rules of `NONNEG` (4.5, 10.6): a
  `JOIN_2` whose `new_sum`, a `JOIN_0` whose leaf amount and a `SPLIT`
  whose claim leaf amount is `2^31 + 2^24` (the negative `CScriptNum`
  `-2^24`), an `EXIT_1` whose sibling sum is, each with output 0 at the
  total the signed fold would reach, and an eviction of a leaf whose
  `evict_after` is `2^31 + 2^24` at lock time 0 (BIP-65 rejects a
  negative operand) all fail; these are the cases the byte-level audit
  of `design/audit/script.md` found accepted. The MIN checks cover `EXIT_1` and the dense `SPLIT` at
  `D = 4` and `16`: a split and a full drain succeed, and one signed by the
  operator or the recipient, an over-split, an occupied destination, a
  stale root, a recipient swapped under the owner's signature, a leaf with
  another evictor key or a later `evict_after` than the source (7.5 rule
  5), a split of one satoshi, of zero satoshis or one leaving a
  one-satoshi residual (7.5 rule 6; exactly `DUST_MIN` succeeds), an
  underfunded tree output, a wrong `e31`, each of the nine raw
  introspection pieces substituted and a claim leaf of amount
  `2^31 + 2^24` (`NONNEG`) all fail.
* `tools/layertree_ccv.py` — the CCV-tier generators (section 4.6) for
  both profiles; `tools/test_ccv.py` executes them end to end (see its
  bullet below).
* `tools/test_scripts.py` — executes every FULL-tier script in both profiles (dense
  at `D = 4` and `16`, sparse at `D = 8` and `32`) against the reference
  tree, including negative cases (forged leaf, stale
  root, attacker-chosen `m`, unconserved amount, underfunded join, join over
  an occupied position, early eviction, evictor shortchange, unsigned update,
  voucher replay, over-claim, wrong voucher signer, a voucher signed for
  another `tree_id`, a voucher over `m` in place of `tree_id`, stale
  second path in `EXIT_2`, shortchanged second evictee, non-terminal exit
  taking the terminal branch) and positive cases for a `CLAIM` that drains
  its source
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
  exact owner exit and an eviction) and the exit-consent `UPDATE^x` variant
  of 7.4 rule 5 (dense at `D = 4` and `16`, sparse at `D = 8`: a spend
  carrying all three signatures succeeds, and one whose `exit_sig` is by the
  wrong key, is garbage, is absent, or that drops the owner signature,
  fails) and the hash-locked `CLAIM^h` variant of 7.5.1 (dense at `D = 4` and
  `16`, sparse at `D = 8`: redemption with the correct preimage succeeds,
  and a wrong preimage, a preimage that is not 32 bytes, an absent preimage,
  a plain voucher signature under the hash lock, a hash-locked signature
  under plain `CLAIM`, a voucher reused for a different claim leaf, an
  over-claim, a wrong signer, a voucher for another `tree_id` and a
  voucher over `m` all fail) and the swap of 9.6.2 (one 32-byte
  preimage settling both a `CLAIM^h` and an `HTLC_SUCCESS` output of
  Appendix C.4.1, with `HTLC_SUCCESS` rejecting a wrong preimage, a
  short preimage and the offerer's signature, and `HTLC_TIMEOUT` rejecting
  a spend before `cltv_expiry` and one by the recipient) and the
  owner-authorised `SPLIT` of 7.5.2 (dense at `D = 4` and `16`, sparse at
  `D = 8`: a split signed by the source owner succeeds, and one signed by
  the operator, by the recipient, with a garbage signature, with a voucher
  signature in place of a transaction signature, over-splitting, into an
  occupied position, against a stale root, or reused for a transaction
  that swaps in a different recipient all fail, as does a split into a
  leaf with another evictor key or a later `evict_after` than the source,
  7.5 rule 5, which `CLAIM` and `CLAIM^h` reject as well, and a split of
  one satoshi, of zero satoshis or one leaving a one-satoshi residual,
  7.5 rule 6, which `CLAIM` rejects as well, while a split of exactly
  `DUST_MIN` and one of the whole balance succeed), the carve rule
  against the cohort sweep (dense at `D = 4` and `16`: a member of an
  evictable cohort cannot plant a `DUST_MIN` leaf with a `NUMS` evictor
  or a later lease in the cohort's empty position by `SPLIT`, a carve
  that keeps the member's terms lands there and `EVICT_SUBTREE_2` sweeps
  the cohort with it, and a member admitted with a `NUMS` evictor can
  still block the sweep with its own `DUST_MIN` leaf, the residual 10.8
  states) and the exit-consent
  `CLAIM^x` and `CLAIM^hx` of 7.5.3 (dense at `D = 4` and `16`, sparse at
  `D = 8`, against a dedicated credit leaf whose owner is the operator and
  whose exit key is the recipient's: the recipient's redemption with the
  voucher and its exit-key signature succeeds, and an `exit_sig` by the
  operator, a garbage or absent `exit_sig`, a witness without the voucher,
  a transaction signature in place of the voucher, the operator draining
  the leaf with a voucher to itself and, under the hash lock, a wrong
  preimage all fail), the sibling-sum binding regression test (dense at
  `D = 4` and `16`, sparse at `D = 8` and `32`: at every level, a proof
  element that keeps the sibling's hash and inflates or deflates its
  declared sum is rejected even when input 0 and output 0 are made to
  match the forged total, because `H_node` commits to both children's
  sums; the sparse cases include an explicitly supplied empty sibling
  with a non-zero sum), the cohort rewrite `REWRITE_h` of 7.9 (`h = 2`
  and `4` at `D = 16`, and `REWRITE_4^x`, each on a mixed cohort of
  exits, an unchanged leaf, a key rotation, an amount-only increase, a
  payer, a lease renewal, a join into an empty position and an empty
  position left alone: the rewrite succeeds with signatures only from
  the owners rule 3 names, and a changed leaf without its owner's
  signature, a key rotation disguised as an amount increase, a
  `SEQ_FINAL` leaf raised by one satoshi without its owner's signature
  (the same raise signed succeeds), a shortchanged exit payout, an exit paid to the wrong key, a missing
  operator signature, output 0 off by one in either direction, a stale
  path, a forged old leaf and, under `^x`, a missing or wrongly keyed
  exit signature all fail) and `DETACH_8` at `D = 16` (7.10: the detach
  succeeds and conserves the total across the two tree outputs, a
  member's old path truncated to its lower eight levels is the detached
  tree's own path for that leaf, an `EXIT_1` from the detached tree with
  it succeeds, a voucher issued while the source leaf sat in the parent
  redeems in the detached tree, which inherits `tree_id`, and output 1
  under the wrong `m_h`, output 1 shortchanged, a missing operator
  signature, output 0 keeping the subtree and an inflated subtree sum all
  fail), `DETACH_2` at `D = 8` and `DETACH_8` at `D = 16` under a parent
  created with options (exact payouts, `CLAIM^h`, `DETACH_h`; 7.10 rule
  3: the detach succeeds with output 1 under the parent's option set
  compiled at depth `h`, fails with output 1 under the reference set's
  `m_h`, and in the detached tree, whose identifier is that option set at
  depth `h`, a channel leaf's `EXIT_1^=` pays its capacity exactly and
  rejects a shortfall), and the negatives the byte-level audit of
  `design/audit/script.md` added (`test_audit_negatives` at `D = 8`: a
  non-minimal `is_evict` or `dir`, a leaf or sibling of the wrong length,
  a sibling whose `enc64` suffix is not `0x01`, a payout at the wrong
  output index, `EXIT_2` naming one position twice, an `EXIT_1^=` payout
  one sat over the leaf, `new_hash` and `new_sum` of the wrong length,
  and for `REWRITE_2` an `exit_key` change, an amount decrease or an
  amount increase with a nonce change without the owner's signature, a
  spurious signature, swapped old and new elements and a 1-byte element,
  and for `EVICT_SUBTREE_2` an occupied position presented as empty,
  swapped positions, payouts out of order and an empty position supplied
  as 116 zero bytes, all rejected), 1,054 checks in total. Run: `python3 tools/test_scripts.py`; `--subtree` adds the
  `h = 6` sweep and rewrite, `--rewrite` prints the size table of 11.
* `tools/test_ccv.py` — executes every CCV-tier script in both profiles
  and both numerics: `0xC2` at dense `D = 4`/`16` and sparse `D = 8`/`32`,
  and `0xC0` at dense `D = 4`/`16` and sparse `D = 31` (the MID tier's
  `25 ≤ D ≤ 31` limit applies, 4.5), 972 checks in total: the positive owner,
  evictor and terminal exits, subtree and single-leaf joins, batched
  joins, `UPDATE` and `EXIT_2`, cohort sweeps (`EVICT_SUBTREE_1/2` at
  `D = 4` and `EVICT_SUBTREE_2/4/6` at `D = 16`, in both numerics, over
  FULL's cohorts with the FULL suite's negatives plus a missing operator
  signature, output 0 under a wrong taptree and a payout to a tweaked
  exit key; this suite caught a `0xC2` leaf step that handed the whole
  leaf to `OP_CHECKCONTRACTVERIFY` as its key, which the earlier sweep of
  two empty positions never reached), and
  negatives for the CCV-specific failure modes (output 0 under a wrong
  taptree, output 0 with the FULL-tier key, a payout to a tweaked rather
  than bare exit key, output 0 underfunded and overfunded, a payout above
  the leaf caught by the exact-payout equality and one above the tree
  total caught by the CCV residual check) and the shared failure modes
  (forged leaf, wrong-root proofs, early eviction, evictor shortchange,
  missing operator or owner signatures, stale second paths); two tree
  inputs carrying one state, which cannot share output 0 or deduct one
  payout twice (4.6); the `UPDATE^x` variant in both numerics (exit
  signature by the wrong key, garbage or absent, owner signature absent)
  and `SPLIT` in `0xC2` at dense `D = 4`/`16` and sparse `D = 8` and in
  `0xC0` at dense `D = 4`/`16` and sparse `D = 31` (signed
  by the operator, by the recipient, with garbage or a voucher signature,
  over-splitting, into an occupied position, with output 0 below `ns`,
  with another evictor key or a later `evict_after` than the source (7.5
  rule 5), of one satoshi, of zero satoshis or leaving a one-satoshi
  residual (7.5 rule 6; exactly `DUST_MIN` and the whole balance
  succeed), or against a stale root, all fail, and in `0xC0` a recipient
  swapped under the owner's signature as well); the carve rule against
  the cohort sweep in both numerics at `D = 16`, as in the FULL suite;
  `CLAIM` and `CLAIM^h` with the
  voucher of 7.5 over `tree_id` in `0xC2` at dense `D = 4`/`16` and sparse
  `D = 8`/`32` and in `0xC0` at dense `D = 4`/`16` and sparse `D = 31`
  (redemption succeeds; a redeemed voucher replayed against the advanced
  source, a voucher reused for another claim leaf, an over-claim, a wrong
  signer, a voucher signed for another `tree_id`, a voucher over `m`
  (the FULL message), output 0 below `ns`, a claim leaf with another
  evictor key or a later `evict_after` than the source (7.5 rule 5), a
  claim of one satoshi, of zero satoshis or one leaving a one-satoshi
  residual (7.5 rule 6; exactly `DUST_MIN` succeeds), and
  the cross-form, wrong, short or absent preimage cases of the FULL suite
  all fail); the negatives of the byte-level audit
  (`test_audit_negatives_ccv` at `D = 8`: in `0xC2` output 0 over-funded
  by one sat, the tree output and the payout swapped and a payout to the
  exit key under a taptree, and in `0xC0` a `JOIN_2` whose `new_sum` is
  `2^31 + 2^24`, the `NONNEG` case of 4.5); and one direct opcode test
  for each BIP-443 amount rule of 4.1 item 7 (**[A-6]**). Run:
  `python3 tools/test_ccv.py`.
* `spec/scripts/` — annotated listings for `D = 4` (dense), `D = 8`
  (sparse), the MID and MIN tiers, the cohort scripts at `D = 8`
  (`EVICT_SUBTREE_2`, `REWRITE_2`, `DETACH_2`), and the size table
  covering both profiles, both compression encodings and all tiers.
  `spec/scripts/structured/` holds the same scripts collapsed into the
  named macros of section 8 (one call per line, with `MACROS_*.txt`
  defining each macro per tier), produced by `tools/gen_structured.py`
  and verified to expand to the same bytes.
* `spec/golden.json` — compiled scripts for every tier, the `tree_id`
  vector they are built over, the taptree root of the FULL `D = 4` set, a
  BIP-341 sighash vector and the tree scriptPubKey vector, produced by
  `tools/gen_golden.py` and consumed by the Go tests.
  The tree-creation variants have their own keys, `UPDATE_X`, `CLAIM_H` and
  `SPLIT` under `FULL/D/D4`, `FULL/S/D8`, `MID/D/D4` and `MID/S/D8`,
  `EVICT_SUBTREE_1` and `EVICT_SUBTREE_2` under `MID/D/D4`, the CCV
  tier's `0xC0` scripts under `CCV0/D/D4` (`EVICT_SUBTREE_1/2`, `SPLIT`)
  and `CCV0/S/D8` (`SPLIT`), `CLAIM` and `CLAIM_H` under `CCV/D/D4`,
  `CCV/S/D8`, `CCV0/D/D4` and `CCV0/S/D8` (every tier's `CLAIM` scripts
  are built over the `tree_id` vector, which fixes the RECOMMENDED
  derivation),
  `CLAIM_X` and `CLAIM_HX` under `FULL/D/D4` and `FULL/S/D8`,
  `REWRITE_2`, `REWRITE_X_2`, `DETACH_2`, `EXIT_1_EXACT` (7.2 rule 6)
  and `DETACH_2_HOST` (the `DETACH_2` of a parent created with exact
  payouts, `CLAIM^h` and `DETACH_2`, whose `m_h` is that option set at
  depth 2) under `FULL/D/D4`, and
  `UPDATE_X` and `SPLIT` under `CCV/D/D4` and `CCV/S/D8`, and `SPLIT`
  under `MIN/D/D4`; being parameters rather than members of the
  reference script set, all are
  excluded from the `FULL/D/D4` taptree root, which therefore does not move
  when a variant is added.
* `formal/` — a Lean 4 model of sections 5, 7 and 10.2 (core library only,
  `lake build`): the tree, `fold` and the transition rules as relations,
  with machine-checked proofs of completeness (`fold_path`), update
  correctness (`fold_setSub`), conservation (`Steps.sum`), binding
  (`fold_sound`, `root_inj`), payability (`payable`), no inflation on exit,
  and the soundness of `JOIN`, `UPDATE` and `CLAIM`, plus the encoding
  lemmas behind `enc64` and `SEQ_FINAL`. `formal/README.md` maps spec
  sections to theorem names and lists the hash assumptions. The tapscript
  bytecode is not modelled; its correspondence to the rules rests on the
  executable tests above.
* `design/p-model.md` — a design note for model-checking the off-chain
  protocol (sections 9, 10.5, Appendix C) in P.
* `spec/channel-leaves.md` — Appendix C: payment channels hosted in leaves
  (normative for implementations that host channels; the tree layer is
  unaffected by it).
* `spec/fee-analysis.md`, `tools/fee_analysis.py` — exit and eviction cost
  at fee rates from 1 to 250 sat/vB (section 11.2).
* Go implementation (module `github.com/roasbeef/layertree`, packages
  `tree`, `script`, `txn`, `msg`): built on btcd, lnd and taproot-assets;
  every generated script is compared byte for byte with the Python output,
  and the BIP-341 signature hash computed by `txscript` is compared with the
  Python simulator's, which is what makes the MIN tier's constructive
  introspection testable.

The simulator is a design-validation tool, not consensus code; its `OP_TX`
and signature-hash models are simplified as documented in its header.

## 15. References

* BIP-340, BIP-341, BIP-342, Schnorr signatures, Taproot, Tapscript.
* BIP-440, Varops Budget For Script Runtime Constraint (Russell, Moik).
* BIP-441, Restoration of disabled script (Tapleaf 0xC2) (Russell, Moik).
* BIP-348, `OP_CHECKSIGFROMSTACK` (Black, Rubin).
* BIP-349, `OP_INTERNALKEY` (Black, Rubin).
* Draft "OP_TX" and "New Opcodes for Tapscript v2" (Russell, Moik),
  `https://github.com/rustyrussell/bips/pull/1`.
* Draft "Elliptic Curve Operations for Bitcoin Script" (Osuntokun),
  `https://github.com/Roasbeef/bips/blob/ec-ops-bip/bips-ec-ops.md`,
  bitcoin/bips PR #1945; the scripts assume commit `8df28249` (4.1).
* "[0/4] A Bitcoin Scripting Proposal BIP Quartet", bitcoindev,
  `https://groups.google.com/g/bitcoindev/c/GisTcPb8Jco/m/8znWcWwKAQAJ`.
* BIP-443, `OP_CHECKCONTRACTVERIFY` (Ingala), pinned at `bitcoin/bips`
  commit `24e96e87` (4.1): the data-tweaked internal key used here follows
  the same pattern.
* BIP-449, `OP_TWEAKADD` (Rubin), `bip-0449.md`.
* Bitcoin Core mempool policy: the ancestor and descendant count limits
  (`src/policy/policy.h`, `DEFAULT_ANCESTOR_LIMIT` and
  `DEFAULT_DESCENDANT_LIMIT`, 25, deprecated since 31.0), the cluster
  limit of 64 that replaced them in 31.0, and the 80-byte tapscript
  witness item limit (`MAX_STANDARD_TAPSCRIPT_STACK_ITEM_SIZE`),
  `https://github.com/bitcoin/bitcoin/blob/v31.1/src/policy/policy.h`.
* Cluster mempool (Wuille, Daftuar, Zhao), Delving Bitcoin,
  `https://delvingbitcoin.org/t/an-overview-of-the-cluster-mempool-proposal/393`.
* BIP-125, Opt-in Full Replace-by-Fee Signaling; BIP-431, Topology
  Restrictions for Pinning (TRUC).
* Merkle Sum Sparse Merkle Trees, Taproot Assets BIP draft (Osuntokun).
* Ark protocol documentation (Ark Labs; Second).
* `design/unified-batching.md`, the essay in which LayerTree was first
  described; `design/review.md`, the scrutiny that produced this document.
