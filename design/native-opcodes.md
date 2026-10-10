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

## Reproducing

```
python3 tools/test_msu.py      # 61 checks: opcode units, quarantine, scripts
python3 tools/test_ccv.py      # the CCV tier (part 1), 798 checks
```

The MSU scripts are excluded from the tier matrix (spec 4.5), from
`all_scripts()` of every tier, from the golden taptree and from every
allowed-opcode set, per the issue's constraint that the hypothetical is
for comparison only.
