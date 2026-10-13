import LayerTree.Hash

/-!
# Leaves and nodes

Section 5.2 of the specification defines a leaf as a 116-byte record. Here a
leaf is a structure with one field per record field. Keys are abstract:
nothing in the tree argument depends on them being curve points, only on
their being 32-byte values that serialise injectively (see
`LayerTree.Encoding`). We use `Nat` for every field and put the range
restrictions of section 5.2 into the predicate `Leaf.WF`.

The *node* of a leaf is the pair `(H_leaf(leaf), amount)` and the node of an
empty position is `E_0 = (zero digest, 0)`. Both are covered by `leafNode`
applied to an `Option Leaf`.
-/

namespace LayerTree

/-- A leaf record (section 5.2). Field order and names follow the table
there; the encodings are handled in `LayerTree.Encoding`. -/
structure Leaf where
  amount : Nat
  exitKey : Nat
  ownerKey : Nat
  evictorKey : Nat
  evictAfter : Nat
  nonce : Nat
  seq : Nat
  deriving DecidableEq, Repr

namespace Leaf

/-- The range requirements of section 5.2 that the tree argument needs.

`0 < amount` is the spec's rule that a leaf carries value; the tree
argument itself does not need it (roots bind trees outright, see
`Tree.root_inj`), but it is what makes an empty position and a zero-value
leaf distinguishable on-chain. `amount < 2^51` is generous: 2^51 satoshis
exceed the total supply, so every sum that can occur in a real tree is far
below 2^64 and `le64`/`enc64` encode it without truncation
(`Encoding.enc64_inj`). The key and lock-time bounds are the field widths. -/
structure WF (l : Leaf) : Prop where
  amount_pos : 0 < l.amount
  amount_lt : l.amount < 2 ^ 51
  exitKey_lt : l.exitKey < 2 ^ 256
  ownerKey_lt : l.ownerKey < 2 ^ 256
  evictorKey_lt : l.evictorKey < 2 ^ 256
  evictAfter_lt : l.evictAfter < 500000000
  nonce_lt : l.nonce < 2 ^ 32
  seq_lt : l.seq < 2 ^ 32

/-- `SEQ_FINAL` of section 5.1 for the FULL tier: the largest `seq` whose
successor still encodes in four bytes under BIP-441 numerics is
`0xFFFFFFFE`, so `0xFFFFFFFF` is the value no `CLAIM` or `SPLIT` can
advance (`Encoding.seqFinalFull_succ_length`). -/
def seqFinalFull : Nat := 2 ^ 32 - 1

/-- `SEQ_FINAL` for the MID and MIN tiers: `0x7FFFFFFF`, the largest
positive four-byte `CScriptNum` (`Encoding.seqFinalMid_succ_length`). -/
def seqFinalMid : Nat := 2 ^ 31 - 1

end Leaf

/-- The tree-creation parameters the carve and update scripts carry as
constants: the tier's `SEQ_FINAL` (5.1; `Leaf.seqFinalFull` or
`Leaf.seqFinalMid`) and `DUST_MIN`, the floor below which no non-empty
leaf may be written (7.5 rule 6), so that every leaf's exit output is a
standard transaction. -/
structure Params where
  seqFinal : Nat
  dustMin : Nat
  /-- `RECLAIM_KEY` (6.2), when the tree names one. A tree that does
  carries `RECLAIM_1` (7.11) and compiles its rewrites in the reclaim
  form of 7.9 rule 8; one that does not has no reclaimable leaves. -/
  reclaimKey : Option Nat := none

/-- A leaf is **reclaimable** (6.2) when the tree names `RECLAIM_KEY` and
the leaf's `evictor_key` equals it. In a tree that names none, no leaf
is. -/
def Params.Reclaimable (π : Params) (l : Leaf) : Prop := π.reclaimKey = some l.evictorKey

instance (π : Params) (l : Leaf) : Decidable (π.Reclaimable l) :=
  inferInstanceAs (Decidable (π.reclaimKey = some l.evictorKey))

/-- A tree without `RECLAIM_KEY` has no reclaimable leaf. -/
theorem Params.not_reclaimable {π : Params} (h : π.reclaimKey = none) (l : Leaf) :
    ¬ π.Reclaimable l := by
  unfold Params.Reclaimable; rw [h]; exact fun h' => Option.noConfusion h'

/-- A Merkle-sum node: a digest and the sum of all leaf amounts below it
(section 5.3). On the wire it is the 41-byte `sc = hash || enc64 sum`. -/
structure Node (H : Type) where
  hash : H
  sum : Nat
  deriving DecidableEq, Repr

/-- Nodes are determined by their two fields. -/
theorem Node.ext {H : Type} {a b : Node H} (h₁ : a.hash = b.hash) (h₂ : a.sum = b.sum) : a = b := by
  cases a; cases b; simp only at h₁ h₂; subst h₁; subst h₂; rfl

variable {H : Type} [M : HashModel Leaf H]

/-- The node of a position holding `o`: `E_0` for an empty position,
`(H_leaf(leaf), leaf.amount)` otherwise (section 5.2, 5.3). -/
def leafNode : Option Leaf → Node H
  | none => ⟨M.empty0, 0⟩
  | some l => ⟨M.hLeaf l, l.amount⟩

/-- `E_0` itself, for readability in statements. -/
def emptyLeafNode : Node H := leafNode none

@[simp] theorem leafNode_none : (leafNode none : Node H) = ⟨M.empty0, 0⟩ := rfl
@[simp] theorem leafNode_some (l : Leaf) :
    (leafNode (some l) : Node H) = ⟨M.hLeaf l, l.amount⟩ := rfl

/-- Two positions with the same leaf node hold the same contents. This is
the leaf-level binding property: the covenant only ever sees `(hash, sum)`
pairs, and this says that pair determines the leaf. -/
theorem leafNode_inj {o₁ o₂ : Option Leaf}
    (h : (leafNode o₁ : Node H) = leafNode o₂) : o₁ = o₂ := by
  cases o₁ with
  | none =>
    cases o₂ with
    | none => rfl
    | some l => exact absurd (congrArg Node.hash h).symm (M.hLeaf_ne_empty l)
  | some l₁ =>
    cases o₂ with
    | none => exact absurd (congrArg Node.hash h) (M.hLeaf_ne_empty l₁)
    | some l₂ => exact congrArg some (M.hLeaf_inj (congrArg Node.hash h))

end LayerTree
