# Native state-machine opcodes: the CCV tier, and a hypothetical OP_MERKLESUMUPDATE

Issue #3. Part 1 (the CCV tier, BIP-443 `OP_CHECKCONTRACTVERIFY`) is
implemented, measured and specified (spec 4.6, PR #6). Part 2 is this
note: what a native *state-machine* opcode for this tree would look
like, specified precisely enough to measure against the RISC set, and
the honest accounting of what it buys and what it costs.

Everything about `OP_MERKLESUMUPDATE` here is HYPOTHETICAL. It is not a
candidate opcode, it is not part of any tier, and it violates the
repository's no-new-opcodes rule by construction; the simulator refuses
it unless the interpreter is constructed with `hypothetical=True`
(`tools/script_sim.py`), so no real-tier script can reach it. It exists
to answer "what would consensus give us if it understood this state
machine directly", the way MATT gestured at but never shipped.

## The four capabilities

Every LayerTree transition needs four things from script:

1. **Read the committed state** — the old root the input commits to.
2. **Commit the next state** — output 0 must carry the new root under
   the same script set.
3. **Bind amounts to script values** — the tree output's amount equals
   the root's sum, the payout equals (or is at most) the leaf's amount.
4. **Authorise over data, rebindably** — signatures over the
   transaction by keys named *inside* the state (leaf fields), and
   voucher messages that name the tree.

The RISC set covers them with: `OP_TX` + recomputed `TREE_SPK` (1),
`OP_TX` + constructed output (2), BIP-441 numerics or `PADZ` (3), and
`OP_CHECKSIG` / `OP_CHECKSIGFROMSTACK` (4). BIP-443 `OP_CHECKCONTRACTVERIFY`
absorbs (1) and (2) natively: one call binds a root to the input under
the input's own taptree, one commits output 0 with the residual amount,
one constrains a payout to a key from the state. It does not absorb
(3): the opcode ties amounts to the *input's* amount, not to
script-computed sums, so one `OP_TX` read per constrained amount
survives in the CCV tier. That is the CCV tier's shape: 1,716 B of
script for `EXIT_1` at dense D=16 against FULL's 2,101, no EC-ops
dependency, `r` and `m` gone from the witness.

What CCV cannot touch is the fold: `D` unrolled copies of the 88-byte
dense `LEVEL` macro (135 sparse), the only place the opcode set changes
the cost *class* rather than the constant. `OP_MERKLESUMUPDATE` is the
primitive that absorbs it.

## OP_MERKLESUMUPDATE (hypothetical semantics)

```
stack:  ... <proof> <old_node> <new_node>   →   ... <old_root> <new_root>

node  := hash(32) || sum(le64)                     40 bytes
proof := depth(u8)
      || position(⌈depth/8⌉ bytes, big-endian, MSB = the top level)
      || bitmap(⌈depth/8⌉ bytes, bit k = a supplied sibling at level k)
      || siblings: one node per set bit, deepest level (k = 0) first
```

Per level k from the leaf up: the sibling is the next supplied node if
bitmap bit k is set, else `E_k` (derived from `E_0 = (0^32, 0)` by the
spec's parent rule; consensus may precompute the chain); position bit k
gives the side; the parent is the spec's node hash — `H_node` over
`left.hash || enc64(left.sum) || right.hash || enc64(right.sum)` — with
the sums added. Fail on sum overflow past `2^64`, `depth` 0 or > 64, a
malformed proof, leftover sibling bytes, a position or bitmap bit above
`depth`, or a supplied sibling equal to `E_k`. The last two make the
encoding canonical: the witness is not covered by the signature hash, so
without them a relay could un-compress a spender's proof and inflate its
weight. The old and new node fold in
one pass over the same path; `new_node == old_node` degenerates to
verification. Cost: `2 * depth` node hashes, charged as BIP-440 varops
(the wordspan of an 82-byte preimage per hash).

The reference implementation is `op_msu` in `tools/script_sim.py`
(behind `hypothetical=True`); the semantics above are what it executes,
and `tools/test_msu.py`'s unit tests pin them (proof round-trips against
`layertree_ref`, the compressed and full encodings, the degeneracy, the
guard, wrong position bits, bitmap mismatches, an explicitly supplied
empty sibling, bits above the depth, leftover bytes, depth bounds,
overflow), and a quarantine test checks that the opcode is in no tier's
allowed set, no tier generator's output and no golden script.

### Why the sums must stay in the nodes

A plain Merkle root with a separately tracked total would not do.
Per-node sums are what let a member verify solvency from its own path
(root sum == output amount, every node's sum == its children's), so a
leaf is backed without seeing anyone else's leaf, and a `JOIN` graft's
claimed subtree total is checked rather than trusted (spec 10.2; the
Lean `fold_sound` binds the sums into the fold's soundness). The sum is
the state machine's invariant, so it belongs in the opcode's semantics —
including the overflow rule, which is what keeps every intermediate
sum a valid `le64` that a script can byte-compare.

## Measured (tools/layertree_msu.py, tools/test_msu.py)

The measurement compiles `EXIT_1` and `JOIN_0` against CCV + MSU in
0xC2 numerics. Two structural observations before the numbers:

* **No arithmetic at all.** The leaf amount is `le64` in the leaf's
  first 8 bytes, the roots' sums come back `le64`, `OP_TX` returns
  amounts as 8-byte strings: every amount check is `OP_EQUALVERIFY`.
  `PADZ`, the `CScriptNum` limits and the 21.47 BTC cap disappear; the
  whole covenant runs on byte strings.
* **The sparse profile stops costing extra.** A path with `N` members
  supplies about `log2 N` siblings and nothing per empty level, so
  sparse D=32 and dense D=16 converge (measured: 252 / 229 vs
  252 / 225). The key-addressed tree becomes the natural default;
  dense survives for `JOIN_h` grafting (the same opcode with a
  height-h node and a shorter path).

| | FULL | CCV | CCV + MSU | issue's estimate |
|---|---|---|---|---|
| `EXIT_1` script, dense D=16 (B) | 2,101 | 1,716 | **252** | ≈ 300 |
| `EXIT_1` witness (B) | 902 | 838 | **225** | ≈ 830 |
| `EXIT_1` sparse D=32 script | 5,147 | 4,762 | **252** | ≈ 300 |
| `JOIN_0` script (B) | 1,841 (D, h=2) | 1,456 | **237** | — |

The script is now O(1) in D: 252 bytes at every depth and profile. The
witness estimate above assumed the proof still carried D siblings; the
bitmap compression makes it `log2 N` plus the leaf and signature, which
is why the measured 225 B beats the estimate. Depth now costs about
10 vB per level of *witness* (one 40-byte sibling per non-empty level)
instead of about 32 vB of script.

47 executable checks cover both layers (opcode units and the
script-level positives/negatives: stale roots, forged leaves, payouts
above the leaf and above the tree total, wrong owner, early evict,
owner-cannot-evict, join over an occupied position, join without the
operator).

`EXIT_K` under MSU needs one call whose old/new node lists cover all K
leaves (multiproofs), which the bitmap encoding above does not express;
the natural extension is to let the bitmap name *pairs* of levels
(sibling sets per node list) or to chain K calls, with the second
call's old root required to equal the first's new root. `CLAIM` is two
chained calls; `EVICT_SUBTREE_h` needs the subtree root from its
`2^h` leaves (script-level hashing at small `h`, or a companion
`OP_MERKLESUMBUILD` for cohort sweeps).

## The honest objections

* **It bakes one tree format into consensus.** `E_k`, the parent hash
  construction, the 40-byte node encoding and the overflow rule are
  LayerTree's; a different tree or a format change forks the opcode.
  This is the standard CISC wager, and the reason the repository's rule
  is "no new opcodes" — the hypothetical is a measurement of the price
  the other side of that wager pays (a 8.3x smaller script than FULL),
  not a proposal to take it.
* **The gain is a constant factor, about 2x over CCV alone.** The proof
  must still be in the witness: MSU moves the *verification* work into
  consensus but the *data* (siblings, leaf, position) still travels.
  252 + 225 vs CCV's 1,716 + 838 is a 6.8x script reduction but only a
  3.7x total-size reduction, and the witness is irreducible below the
  information-theoretic floor.
* **CISC vs RISC.** The tier matrix exists precisely to measure this:
  FULL (RISC-plus), MID, MIN and CCV are all realizable from candidates
  on the table; MSU needs a bespoke opcode per state machine. The MATT
  vision was many state machines over one generic vector-commitment
  primitive; `OP_MERKLESUMUPDATE` as specified here is the LayerTree
  special case of it. If consensus ever takes a generic Merkle-update
  opcode, the measurement here is the benchmark it has to beat.

## The pending-leaf receive under CCV + OP_MERKLESUMUPDATE

Spec 0.14.0 adds the pending-leaf receive of `design/pending-receive.md`
to the FULL, MID and CCV tiers (MIN cannot): `CLAIM^m` and `CLAIM^hm` (7.5.4), the reclaim form of
`REWRITE_h` (7.9 rule 8) and `RECLAIM_1` (7.11). This section compiles
each of them against CCV + MSU in `0xC2` numerics
(`tools/layertree_msu.py`: `merge_script_msu`, `reclaim_script_msu`,
`rewrite_script_msu`), runs them in one taptree with the landing leaf's
`EXIT_1` (`tools/test_msu.py`, 65 checks), and prices every transaction
the design puts on chain.

### The scripts

* **`CLAIM^hm` and `CLAIM^m`.** The rules are FULL's `merge_script`
  token for token up to the two new leaves: the voucher by the source's
  owner over `tree_id`, both bodies and `X`, the target owned by the
  source's exit key and carrying the same exit key, neither leaf at
  `SEQ_FINAL`, the target not reclaimable, `d = X − target.amount ≥ 1`,
  a residual of zero or at least `DUST_MIN`. Then the four leaves become
  40-byte nodes, the old and new pair nodes are hashed in script (one
  `OP_ADD` for the pair sum, the 0x01 byte that turns a 40-byte node
  into `hash || enc64(sum)`), and one MSU call folds both from height 1.
  `CHECK_INPUT` binds the old root and output 0 is assigned the new one;
  the merge conserves the pair's total, so the assign mode's floor is
  exactly right. The `TAG_LEAF` and `TAG_NODE` prefixes are pushed once
  and picked, which is worth about 250 bytes over pushing them per use.
* **`RECLAIM_1`.** FULL's `reclaim_script` with the fold replaced:
  evictor is `RECLAIM_KEY` (the extracted key is the one the signature
  is checked against, so the constant is pushed once), `CLTV` on
  `evict_after`, the old node the leaf's, the new node `E_0`.
* **`REWRITE_h^x`, reclaim form.** FULL's post-order machine, run
  through `rewrite_machine` (the R1 and R3 rules, `RECLAIM_KEY` hoisted
  once, the transfer checked from the pair's left step), with the CCV
  tier's `DEDUCT` payout. It leaves the old and new subtree nodes, which
  become 40-byte nodes for one MSU call from height `h`.

Two binding details are new to this measurement.

* **Value that leaves the tree without a payout.** CCV's assign mode
  makes output 0 at least the input's residual, so it cannot express a
  reclaim, whose value is free for the transaction (7.9 rule 6).
  `RECLAIM_1` checks output 0 in the `DEDUCT` mode instead, which caps
  it at the residual; the byte compare `out0.amount == new_root.sum`
  pins it either way. A rewrite's net change can have either sign, so
  its witness carries one flag below the proof (empty = assign, `0x01` =
  deduct). A wrong flag fails the CCV check, a non-minimal one fails
  `MINIMALIF`, and either bound is safe under the byte compare, so the
  flag needs no further check. The CCV tier's own `REWRITE_h` has the
  same limit today: it uses assign, so a rewrite that frees value is not
  spendable there.
* **No `os == input amount` check.** As in the measured `EXIT_1` and
  `JOIN_0`, the scripts rely on the invariant that every transition pins
  output 0's amount to the new root's sum. Re-checking it would cost
  about 10 bytes per script.

### The proof of a height-h node

The opcode's empty chain starts at `E_0` whatever the height of the node
it folds (`op_msu`). A proof from height `h ≥ 1` therefore cannot omit an
empty sibling: the sibling at its level `k` is `E_{h+k}`, the opcode
would substitute `E_k`, and the fold would miss the root (pinned by a
negative in `tools/test_msu.py`; the earlier `build_proof(height=h)`
helper compressed against `E_{h+k}` and was wrong for that reason, unused
until now). Two ways out, with the same sibling count:

* a **dense tree of depth exactly `k`**, every position occupied, where
  no sibling is empty, under the opcode as specified; or
* a **start-height field** in the proof (one byte, or the depth byte's
  spare bits), so that a key-addressed tree can omit `E_{h+k}`.

The table assumes one of them. Without either, a height-`h` proof in a
depth-64 key-addressed tree carries every empty level explicitly, about
`40 (64 − k)` bytes more: 1,920 bytes at `k = 16`, 480 vB per merge or
rewrite.

### Measured

Scripts are measured at `D = 8`; none depends on `D` except through the
32-byte `E_D` constant.

| Script | CCV + MSU (B) | FULL (B) | Witness without the proof (B) |
|---|---|---|---|
| `CLAIM^hm` | 645 | 2,622 (D = 16) | 337: two leaves, flag 1, `X` 8, voucher 64, preimage 32 |
| `CLAIM^m` | 634 | 2,611 (D = 16) | 305 |
| `RECLAIM_1` | 218 | 2,131 (D = 16) | 180: leaf, signature |
| `EXIT_1` (landing leaf) | 252 | 2,101 (D = 16) | 180 |
| `REWRITE_1^x`, reclaim form | 967 | | 464 per pair transferring, 349 per pair rolling, plus `sig_op` 64 |
| `REWRITE_2^x` | 1,666 | | as above |
| `REWRITE_4^x` | 5,910 | | as above |
| `REWRITE_6^x` | 23,169 | 24,140 (D = 16) | as above |

The rewrite does not shrink much under MSU because the fold above `h` is
a small part of it; the per-position step is the large term, about 362
bytes of script per position at `h = 6`, published in every rewrite. An
earlier version of the step cost about 520; the FULL tier's optimisation
(the transfer checked once from the pair's left step, `RECLAIM_KEY`
hoisted, one body comparison) is what brought it down, and the MSU
rewrite reuses that machine.

### Whole transactions

The spec's fee model: `weight = 946 + 172 (p − 1) + 129 + script +
witness`, `vB = ceil(weight / 4)` once per transaction, witness length
prefixes excluded, `p` the payouts (one for the exit, none for the
rest, so the others start from 774 + 129 = 903 WU). The tree is
key-addressed at depth 64 with `N = 2^k` members, the scaling page's
model, built from dense pairs and cohorts: the proof of a height-`h` node
is `1 + 2 ⌈(64 − h)/8⌉ = 17` bytes of header and `k − h` occupied
siblings of 40 bytes. The settlement is the design's window close with
every pair of a height-`h` cohort active: one R3 rewrite in which every
pair transfers (before `T − G_claim`), then one R1 rewrite in which every
pair rolls its pending leaf (after `T`), divided by the `2^(h−1)` pairs.

| Transaction | `N = 2^16` | `N = 2^20` | `N = 2^32` | Formula (vB) |
|---|---|---|---|---|
| `CLAIM^hm` redemption | 626 | 666 | 786 | `ceil((1,862 + 40k) / 4)` |
| `CLAIM^m` (the operator's unlocked `U`) | 615 | 655 | 775 | `ceil((1,819 + 40k) / 4)` |
| `RECLAIM_1` | 490 | 530 | 650 | `ceil((1,318 + 40k) / 4)` |
| Landing leaf's `EXIT_1` | 541 | 581 | 701 | `381 + 10k` |
| Settlement per pair, `h = 2` (2 pairs) | 1,006.0 | 1,046.0 | 1,166.0 | two transactions of 1,035 and 977 vB at `k = 16` |
| Settlement per pair, `h = 4` (8 pairs) | 664.2 | 674.2 | 704.2 | 2,772 + 2,542 vB at `k = 16` |
| Settlement per pair, `h = 6` (32 pairs) | 586.9 | 589.4 | 596.9 | 9,851 + 8,931 vB at `k = 16` |

Derivation of the settlement at `h = 6`, `k = 16`. The transfer
transaction is 903 WU of skeleton and control block, 23,169 of script,
17 + 40 × 10 = 417 of proof, 32 × 464 = 14,848 of leaves and 64 of
`sig_op`: 39,401 WU, 9,851 vB. The roll is the same with 32 × 349 =
11,168 of leaves (`P`, `P'`, `L` and the one-byte unchanged marker for
`L`): 35,721 WU, 8,931 vB. Per pair, 587 vB, of which script is about
362 (724 bytes per pair per transaction, twice), leaves about 203, and
the rest under 25. Each further doubling of `N` adds 40 bytes to two
proofs shared by 32 pairs, 0.6 vB per pair.

What the numbers say:

* **The unilateral paths are the cheap part.** A redemption under MSU
  is 626 vB at 65,536 members against 1,136 vB for FULL's `CLAIM^hm` at
  `D = 16` under the same model, and grows 10 vB per doubling instead of
  32. `RECLAIM_1` and the landing leaf's exit are within 50 vB of each
  other.
* **The batched settlement is dominated by script, not proof.** At
  `h = 6` the rewrite costs about 587 vB per pair per window, against the
  design's first estimate of about 375 vB with R3, which priced the
  leaves and not the reclaim-form step. MSU removes the fold, which was
  never the large term here; the per-position step is. FULL pays the
  same step (24,140 bytes at `h = 6`).
* **R3 beats the unbatched settlement only at larger cohorts.** Without
  R3 a window costs a pair one `CLAIM^m` and one `RECLAIM_1`: 1,105 vB at
  `k = 16`. R3 at `h = 2` is 9% less (1,006), at `h = 4` 40% less,
  at `h = 6` 47% less. Its other advantage, needing no signature from
  the recipient, is unchanged.
* **Where the remaining bytes are.** An amount-only element (8 bytes in
  place of a republished 116-byte leaf, for a new element that differs
  from its old one only in amount) would save about 54 vB more per pair
  on the transfer; it is an encoding change to 7.9, not a script
  optimisation, and is not measured here.

### Reproducing

`python3 tools/test_msu.py` prints the measured sizes, the varops (about
1.6 M for a redemption, 4.8 M for the `h = 6` transfer) and the table
above. The quarantine test now also covers the FULL tier's pending-leaf
script set (`RECLAIM_1`, `CLAIM_M`, `CLAIM_HM`, `REWRITE_R_h`,
`REWRITE_XR_h`): none of them, and no golden script, contains
`OP_MERKLESUMUPDATE`, and none of the MSU scripts is in any tier.

## Reproducing

```
python3 tools/test_msu.py      # 126 checks: opcode units, quarantine, scripts, pending-leaf receive
python3 tools/test_ccv.py      # the CCV tier (part 1), 798 checks
```

The MSU scripts are excluded from the tier matrix (spec 4.5), from
`all_scripts()` of every tier, from the golden taptree and from every
allowed-opcode set, per the issue's constraint that the hypothetical is
for comparison only.
