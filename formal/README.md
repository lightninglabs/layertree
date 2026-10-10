# LayerTree formalisation (Lean 4)

This directory is a machine-checked model of the **covenant and tree**
layer of `spec/layertree.md`: the Merkle-sum tree of section 5, the
transition rules of section 7 and the security argument of section 10.2.
It proves that the rules the scripts enforce have the properties the
specification claims, and it makes explicit the cryptographic assumptions
those properties rest on.

It is deliberately small: about 1,900 lines of Lean, core library only, no
Mathlib. It builds in a few seconds from a bare toolchain.

The off-chain protocol (section 9, Appendix C) is a different kind of
object, an asynchronous state machine with an adversarial scheduler, and is
not formalised here. `design/p-model.md` sketches a model-checking approach
for it in P.

## Build

```
cd formal
lake build          # compiles every module and prints the axiom audit
```

The toolchain is pinned in `lean-toolchain` (Lean 4.24.0). With `elan`
installed, `lake` picks it up automatically. There are no dependencies to
fetch.

The build prints one line per headline theorem from `LayerTree/Axioms.lean`
of the form `'LayerTree.payable' depends on axioms: [propext, Quot.sound]` (the theorems that case on a `Bool` or on `Steps` also list `Classical.choice`).
Any line naming `sorryAx` means an unfinished proof; there are none.

## What is modelled

| Spec | Lean | Notes |
|---|---|---|
| 5.1 tagged hashes | `HashModel` class (`Hash.lean`) | Hash functions are parameters; collision resistance is stated as injectivity, tag separation as inequality. See *Assumptions*. |
| 5.2 leaf record | `Leaf`, `Leaf.WF` (`Leaf.lean`) | One field per record field, ranges in `WF`. |
| 5.2 / 5.3 leaf node, `E_0` | `leafNode`, `emptyLeafNode` | `leafNode none = E_0`. |
| 5.3 node hash, sums | `Node`, `parent`, `Tree.root`, `Tree.total` (`Tree.lean`) | `parent` hashes both children with their sums and adds the sums. |
| 5.4 tree, positions | `Tree d`, `Pos d h` | Depth is a type index. `Pos d 0` is a leaf position; `Pos d h` addresses a subtree of height `h` (used by `JOIN_h`). |
| 5.5 sibling path, `fold` | `Tree.pathSub`, `fold`, `combine` | Root-first in the model; the witness of section 8 is the reverse (leaf-first). |
| 5.3 `E_h` | `Tree.empty`, `Tree.emptyNode` | The constants the `JOIN_h` scripts hard-code. |
| 5.4 sparse positions | `Tree.Sparse`, `SparseJoin` (`Transitions.lean`) | `pos` is an arbitrary function of `(owner_key, nonce)`; the hash is not modelled. The script's derivation of `dir` from the leaf is `path.map Prod.fst = (pos …).dirs`. |
| 5.4 / 7.7 positions inside a subtree, published elements | `Pos.append`, `Pos.dirs`, `Tree.leaves` (`Tree.lean`) | A position inside the subtree at `p` is `p.append q`; `leaves` is the `2^h` elements in position order, which the sweep and rewrite witnesses publish. |
| 7.1 rules 3, 4 (`CHECK_OLD`, `LEVEL × D`, `FINAL`) | `Step`, `Step.valid`, `Step.WF` (`Transitions.lean`) | A step is a path, a height, an old node and a new node. `valid` is exactly what the script establishes. |
| 7.6 composition (`CHECK_PREV`) | `Steps` | Sequential chaining of steps. |
| 7.2 `EXIT_K`, 7.2 rule 6 `EXIT_K^=` | `ExitBlock`, `ExitK exact …` | `exact = true` is the exact-payout variant. |
| 7.3 `JOIN_h` | `Join` | Old node is `E_h`. |
| 7.4 `UPDATE` (and `UPDATE^x`) | `Update` | Authorisation is an opaque `Prop`; the two variants differ only in it. |
| 7.5 `CLAIM` (and 7.5.1 `CLAIM^h`, 7.5.2 `SPLIT`) | `Claim`, `claimedSource` | Two steps; the drained case becomes `E_0`. Authorisation is an opaque `Prop`, so the hash-locked variant is the same relation with the preimage check folded into it, and `SPLIT` the same relation with the owner's transaction signature in place of the voucher. |
| 7.8 terminal branch of `FINAL` | `Final`, `ExitKT` | `Final d r' out0 terminal` is the branch the script took: `r' = E_D` with output 0 free, or `out0 = r'.sum`. `ExitKT` is `ExitK` with it. |
| 7.7 `EVICT_SUBTREE_h` | `EvictSubtree`, `Tree.sweepPayouts` (`Cohort.lean`) | One step from the root of the published `Tree h` to `E_h`, with the `FINAL` branch of 7.8 and the payout list of rule 2. |
| `REWRITE_h` (`design/batching.md` Shape 2) | `Rewrite`, `Tree.rewritePayouts` | One step from the old published subtree's root to the new one's; authorisation is a predicate on positions required wherever the element changes; a leaf replaced by `E_0` is paid. |
| `DETACH_h` (`design/batching.md` Shape 3) | `Detach` | One step from the subtree node to `E_h`, with output 1 stated as a second tree output `(r₁, out1)`. |
| 6.3 / 6.4 / 10.4 root binding | `BindingModel`, `witness_root_binds`, `output_binds`, `CCVTweak`, `CCVTweak.binding`, `ccv_input_binds` (`Binding.lean`) | `TREE_SPK` injective in `(r, m)` is the hypothesis. The CCV tier's `TREE_SPK_CCV` (spec 4.6, 6.3) is built as `CCVTweak.binding`, a second `BindingModel` whose injectivity is proved from two stage hypotheses: the BIP-443 data tweak `NUMS + sha256(NUMS‖r)·G` is injective in `r`, and the taproot tweak is injective in `(P, m)`; the theorems then apply unchanged. |
| 5.3 `enc64`, 8.2 `PAD8` | `Encoding.enc64_eq_minimal` (`Encoding.lean`) | `le64 n ‖ 01` is the minimal BIP-441 encoding of `n + 2^64`. |
| 5.2 serialisation | `Encoding.serializeLeaf_inj`, `serializeNode_inj` | Fixed-width concatenation is injective under `WF`. |
| 5.1 `SEQ_FINAL` | `minimalLE_two_pow_32_length`, `scriptNum_two_pow_31_length`, `scriptNum_neg_max31_succ` | Why the marker is `0xFFFFFFFF` in FULL and `0x7FFFFFFF` in MID, and why `0xFFFFFFFF` is *claimable* in MID. |

## What is proved

The theorems, in the order the argument builds them. Every one is checked
by `lake build`; the names are the Lean identifiers.

### Tree (`Tree.lean`)

* **`root_sum`**: the sum in a root is the total of all leaf amounts below
  it. (Conservation, structural half.)
* **`fold_sum`**: folding a node up a path adds exactly the sibling sums,
  whatever node the prover starts from.
* **`fold_pathSub` / `fold_path`** (completeness): the honest path of a
  position folds its node to the tree root. Anyone holding a leaf and its
  path can produce the `CHECK_OLD` witness.
* **`fold_setSub` / `fold_set`** (update correctness): folding a *new*
  node along the *old* path yields the root of the tree with that node's
  subtree replaced. This is why every transition can reuse the one
  `LEVEL × D` loop to produce the new root.
* **`root_inj`**: two trees of the same depth with equal roots are equal.
  Uses hash injectivity at every level.
* **`eq_empty_of_root`**: a subtree whose root is `E_h` is the empty tree.
* **`fold_sound`** (binding): any node and path that fold to the root are
  the root of one of the tree's subtrees and that subtree's honest path.
  This is the only theorem that uses the collision and tag-separation
  axioms. Its corollary for leaves: a leaf node that verifies against the
  root, with a full-length path, is the leaf actually at that position,
  *with its true amount*.
* **`getSub_setSub_ne` / `get_set_ne`**: replacing one subtree leaves
  every other subtree of the same height untouched.
* **`getSub_append` / `pathSub_append` / `get_append`**: a position inside
  the subtree at `p` is `p.append q`, and its subtree, sibling path and
  leaf split at the boundary: the path is the subtree's path followed by
  the path inside it. This is what makes a member's proof reusable after
  a detach.
* **`Pos.dirs_inj` / `pathSub_dirs`**: a sibling path's direction bits are
  its position's, and the bits determine the position. A script that
  derives `dir` from the leaf therefore pins the position.
* **`leaves_inj`**: the `2^h` elements in position order determine the
  subtree, so a witness that publishes them names exactly one `Tree h`.
* **`get_empty`**: the empty tree holds no leaf anywhere.

### Transitions (`Transitions.lean`)

* **`Step.sound`**: a valid, well-formed step is a subtree replacement at a
  position of the step's height.
* **`Step.sum`**: `r'.sum + old.sum = r.sum + new.sum`.
* **`Steps.sum`**: for any sequence, `r'.sum + Σ old = r.sum + Σ new`.
  Holds unconditionally: the covenant conserves sums whether or not the
  nodes it is shown have preimages.
* **`Steps.sound`**: a sequence of grounded steps (each new node the root of
  some tree) from the root of a tree ends at the root of a tree of the same
  depth. This is the induction invariant behind section 10.2.
* **`leafStep_sound`**: a valid leaf-level step identifies a position
  holding exactly the old leaf and produces the root of the tree with that
  position rewritten.
* **`ExitK.no_inflation`**: `out0 + Σ payouts ≤ S`. No exit transaction
  creates value; the slack is the fee option of 7.2 rule 3.
* **`ExitK.exact_conservation`**: in `EXIT_K^=`, `out0 + Σ payouts = S`.
* **`ExitK.single_sound`**: an exited leaf was in the tree, output 0
  commits to the tree without it, and `out0 + amount = S`.
* **`payable`** (the headline of section 10.2): for any tree and any
  position holding a leaf, the honest witness is a valid step from the
  current root to the root of the tree without that leaf, the new sum is
  the old sum minus the leaf amount, and no other position changes.
  Together with `no_inflation` this is: *whoever holds a leaf and its path
  can always construct an accepted `EXIT` paying the leaf amount, without
  anyone's cooperation and without touching anyone else's leaf.*
* **`join_sound`**: a join fills an *empty* subtree (by `root_inj`, nothing
  but the empty tree has root `E_h`), output 0 equals `S + new.sum`, and if
  the grafted node is the root of a real subtree, output 0 commits to the
  tree with it grafted in, after which every leaf of it is `payable`.
* **`update_sound`**: an update rewrites exactly one leaf and moves the
  output amount by the amount difference.
* **`claim_sound`**: a claim conserves the total, the source position held
  the source leaf, the claim position was empty *after* the source step,
  and output 0 commits to both rewrites.
* **`terminal_no_leaf`** (7.8): any tree whose root is `E_D` holds no leaf,
  so the terminal branch of `FINAL` is reachable only when the exit removed
  the last leaf; an exit that leaves a leaf behind cannot take it.
* **`ExitKT.terminal_conservation`**: on the terminal branch the payouts
  are at most `S`, exactly `S` in `EXIT_K^=`, with no tree output; for any
  `K`, by `Steps.sum` and `E_D.sum = 0`.
* **`ExitKT.single_terminal`**: a terminal single exit's leaf was in the
  tree, every other position was already empty, and its amount was the
  whole input amount.
* **`Tree.Sparse.unique`** (5.2, structural uniqueness): in a sparse tree
  two leaves with the same `(owner_key, nonce)` are the same leaf at the
  same position.
* **`Tree.Sparse.absent`**: an `E_0` proof at the derived position is a
  proof that no leaf with that `(owner_key, nonce)` is in the tree.
* **`sparseJoin_sound`**: a sparse `JOIN_0` lands at the position derived
  from the leaf (the path's direction bits determine it), that position
  was empty, output 0 commits to the tree with the leaf there, the tree is
  sparse again, and the sum rises by the leaf amount.

### Cohort transitions (`Cohort.lean`)

* **`Tree.sweepPayouts_total`**: the sweep's payouts (every non-empty
  position in position order) sum to the subtree's sum.
* **`evictSubtree_sound`** (7.7): the committed tree held exactly the
  published elements at the published positions, output 0 commits to the
  tree with the subtree emptied, the payouts equal the subtree's sum, and
  the input amount is accounted for on either `FINAL` branch (output 0
  plus payouts, or payouts alone). Grounded by construction: the witness
  publishes the subtree.
* **`rewrite_sound`** (`REWRITE_h`): the committed tree held the old
  elements, output 0 commits to the tree with the new elements, unchanged
  positions keep their element, every other subtree of height `h` is
  untouched, `out0 + Σ old = S + Σ new` (rule 6), and the payouts never
  exceed what left the tree.
* **`rewrite_exit_conservation`**: when no new element is a leaf, output 0
  plus the payouts equals the input amount, the statement of
  `ExitK.exact_conservation` for a whole cohort.
* **`detach_sound`** (`DETACH_h`): `out0 + out1 = S` across the two outputs,
  output 0 commits to the tree with the subtree emptied, output 1 is a
  well-formed tree output of depth `h` whose root hash is the subtree's
  and whose amount is its total, and every member's path with the shared
  `D − h` upper levels dropped is that member's path in the detached tree.
* **`detach_member_payable`**: the truncated path is a valid `EXIT` step in
  the detached tree paying the leaf amount, by `payable` applied to the
  detached subtree.

### Binding (`Binding.lean`)

* **`witness_root_binds`**: if `TREE_SPK(r', m') = input scriptPubKey =
  TREE_SPK(r, m)` then `r' = r` and `m' = m`. The script verifies proofs
  against the true root under the true script set.
* **`output_binds`**: the same for output 0, so the successor output
  commits to the computed root and the same `m`.
* **`CCVTweak.binding`**, **`ccv_input_binds`**: the CCV tier's state key
  (BIP-443 data tweak of `NUMS` by the root, then the taproot tweak by `m`)
  as a second `BindingModel`. Its `treeSpk_inj` is proved, not assumed,
  from injectivity of each tweak stage, so `witness_root_binds` and
  `output_binds` hold for a CCV tree; `ccv_input_binds` is the first of
  them stated for `CHECK_INPUT` with the input's own taptree.

### Encodings (`Encoding.lean`)

* **`leBytes_inj`, `le64_inj`, `enc64_inj`**: fixed-width little-endian
  encodings are injective on their range.
* **`enc64_eq_minimal`**: `minimalLE (n + 2^64) = le64 n ‖ 01` for
  `n < 2^64`. This is what `PAD8` (`<2^64> OP_ADD`) relies on.
* **`serializeLeaf_inj`**, **`serializeNode_inj`**: the 116-byte leaf and
  the 82-byte node preimage are injective under the field bounds. With
  SHA-256 collision resistance these discharge `hLeaf_inj` and `hNode_inj`.
* **`minimalLE_two_pow_32_length = 5`**, **`minimalLE_max32_length = 4`**:
  FULL `SEQ_FINAL = 0xFFFFFFFF`.
* **`scriptNum_two_pow_31_length = 5`**, **`scriptNum_max31_length = 4`**:
  MID `SEQ_FINAL = 0x7FFFFFFF`.
* **`scriptNum_neg_max31`**, **`scriptNum_neg_max31_succ`**: `ff ff ff ff`
  is `−(2^31−1)` as a `CScriptNum` and its successor is `fe ff ff ff`, so
  `0xFFFFFFFF` is claimable in MID. This is the fact `tools/test_mid.py`
  demonstrates by execution; here it is a theorem.

## Assumptions

Everything is parametric in a `HashModel`, so the theorems hold for any
digest type and hash functions satisfying:

| Field | Meaning | Justification in the deployment |
|---|---|---|
| `hLeaf_inj` | `H_leaf` is injective on leaves | SHA-256 collision resistance + `serializeLeaf_inj` |
| `hNode_inj` | `H_node` is injective on `(lh, ls, rh, rs)` | SHA-256 collision resistance + `serializeNode_inj` |
| `hNode_ne_hLeaf`, `hNode_ne_empty`, `hLeaf_ne_empty` | digests under different tags never collide, and never equal the zero string | distinct BIP-340 tags (`LayerTree/node`, `LayerTree/leaf`); random-oracle heuristic |

The binding argument (`Binding.lean`) additionally assumes `TREE_SPK` is
injective in `(r, m)`: the discrete logarithm assumption on secp256k1 plus
collision resistance of `H_state` and `TapTweak`. For the CCV tier the
assumption is split into `CCVTweak.dataTweak_inj` (collision resistance
of the untagged SHA-256 over `NUMS ‖ r`, plus the discrete logarithm of
`NUMS`: two distinct scalars can give the same x-only key only if
`2·NUMS = −(t₁ + t₂)·G`) and `CCVTweak.tapTweak_inj` (the BIP-341
argument for `TapTweak`), and `treeSpk_inj` is derived from them.

Injectivity is the standard idealisation of collision resistance for
proofs about Merkle structures: a proof that goes through under
injectivity goes through against any adversary that cannot exhibit a
collision, because a collision is exactly the event the assumption rules
out. The model does not quantify the adversary's advantage.

## What is not modelled, and why

* **The tapscript bytecode.** The model states the rules of section 7 as
  relations on nodes and paths. That the scripts of section 8 implement
  those rules is established by execution, not proof: the Python simulator
  runs every script against the reference tree with positive and negative
  cases (`tools/test_scripts.py`, `test_mid.py`, `test_min.py`), and the Go
  generators are compared byte for byte with the Python output
  (`spec/golden.json`). A verified interpreter for the tapscript subset
  would close this gap; it is a separate project of a different size.
* **Signatures, keys, lock times.** Authorisation decides *who* may perform
  a transition, not *what* it does to the tree, so it appears as an opaque
  proposition. Nothing about conservation depends on it. This is why the
  authorisation variants of the spec (`UPDATE^x`, `CLAIM^h`, `SPLIT`) need no new
  Lean development: they instantiate the same `Prop` differently, and the
  soundness theorems apply to them verbatim. It is also the boundary of the
  model: that the *script* enforces the authorisation it claims to is shown
  by execution in `tools/test_scripts.py`, not proved here.
* **Transaction structure beyond amounts.** The theorems take the input
  amount and output amounts as parameters, as the script reads them with
  `OP_TX`. The output *scripts* (payouts to `P2TR(exit_key)`) are
  authorisation-side facts; `Payout` carries the exit key only so the
  payout rule can name it. A `DETACH_h` has two tree outputs; the model
  states the second as a root hash and an amount (`Detach.r₁_eq`,
  `Detach.out1_eq`) rather than generalising `Step`, and its taptree
  `m_h` is a `Binding.lean` fact.
* **Concurrency, mempool, reorganisations, timing.** These are the
  off-chain protocol's concerns (sections 9, 10.5, 10.11, Appendix C) and
  the subject of `design/p-model.md`.

## Three things the proofs made precise

**Grafted nodes.** `Steps.sum` needs no assumption about the nodes a step
presents; `Steps.sound` needs each new node to be the root of *some* tree
(`Step.Grounded`). Leaf-level steps are grounded by construction. A
`JOIN_h` graft is grounded only if the operator's `(new_hash, new_sum)`
has a preimage tree. If it does not, the sum is still conserved on-chain
but nothing below the node can ever be proven, so the grafted value is
frozen. This is why section 9.2 makes it a MUST for joiners to verify their
own paths inside the subtree before funding the join: the covenant
protects the *sum*, the joiners protect their *membership*.

**Drained sources in `CLAIM`.** `claim_sound` shows the claim position must
be empty *after* the source step, not before. A source drained to zero
becomes `E_0` and may therefore legitimately serve as the claim position
in the same transaction. The scripts allow this; the model shows it is
harmless.

**Published subtrees are grounded by construction.** `EvictSubtree` and
`Rewrite` take the subtree as a `Tree h` because the witness publishes
its `2^h` elements and `leaves_inj` says those elements name exactly one
tree. So a cohort join made through `REWRITE_h` carries no `JOIN_h`
caveat: the grafted value is provable the moment the transaction is, and
`Steps.sound` needs no `Grounded` hypothesis for it. `Detach` publishes
only the subtree node, but the subtree it detaches was already in the
tree, so `detach_sound` recovers it as `t.getSub p` from `fold_sound`.

## Layout

```
formal/
  lakefile.lean            Lake configuration (core library only)
  lean-toolchain           leanprover/lean4:v4.24.0
  LayerTree.lean           root module, imports everything
  LayerTree/Hash.lean      HashModel: the idealised hash assumptions
  LayerTree/Leaf.lean      Leaf, Leaf.WF, Node, leafNode
  LayerTree/Tree.lean      Tree, Pos, root, total, paths, fold, the tree theorems
  LayerTree/Transitions.lean  Step, Steps, EXIT/JOIN/UPDATE/CLAIM, the terminal branch, sparse positions
  LayerTree/Cohort.lean    EVICT_SUBTREE_h, REWRITE_h, DETACH_h on published subtrees
  LayerTree/Binding.lean   TREE_SPK binding (FULL, and CCV via CCVTweak)
  LayerTree/Encoding.lean  le64, enc64 minimality, serialisation injectivity, SEQ_FINAL
  LayerTree/Axioms.lean    #print axioms audit for the headline theorems
```
