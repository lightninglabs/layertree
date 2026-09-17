/-!
# The hash model

`spec/layertree.md` section 5 builds everything on three tagged SHA-256
hashes: `H_leaf` over the 116-byte leaf, `H_node` over the two children
(hash and sum each) and, for the empty leaf, the all-zero digest `E_0`.

We do **not** model SHA-256. Nothing in the security argument of section 10
depends on what SHA-256 computes, only on what an adversary cannot do with
it: find two different preimages of the same digest. In the *idealised* hash
model this is stated as injectivity of the hash functions on the domains the
protocol uses, together with domain separation (a node hash is never a leaf
hash and never the empty digest, which the distinct tags of section 5.1
provide).

This is the standard way to reason about Merkle constructions in a proof
assistant: a proof that goes through under injectivity goes through against
any adversary that cannot produce a collision, and a collision is exactly
the event the assumption excludes. Everything downstream is *parametric* in
the model, so the theorems hold for any concrete `H` satisfying the axioms
below.

The class carries the type `H` of digests (32-byte strings in the
deployment) and the three hash functions as fields. `Leaf` is defined in
`LayerTree.Leaf`; to avoid a dependency cycle the class is parametric in the
leaf type as well and `Leaf.lean` instantiates it.
-/

namespace LayerTree

/-- The idealised hash model.

* `H` is the digest type.
* `hLeaf` is `H_leaf(leaf_bytes)` (section 5.2). The injectivity hypothesis
  bundles two facts: SHA-256 is collision resistant, and leaf serialisation
  is injective (proved separately, `LayerTree.Encoding.Leaf.serialize_inj`).
* `hNode a sa b sb` is `H_node(a || enc64 sa || b || enc64 sb)` (section
  5.3). Injectivity again bundles collision resistance with the injectivity
  of the fixed-width `enc64` (proved in `LayerTree.Encoding`).
* `empty0` is `E_0.hash`, the 32 zero bytes.
* The three `ne` fields are domain separation: a digest produced under one
  tag is never equal to a digest produced under another tag, nor to the
  zero string. In the random-oracle idealisation these hold with
  overwhelming probability; here they are axioms of the model. -/
class HashModel (Leaf : Type) (H : outParam Type) where
  hLeaf : Leaf → H
  hNode : H → Nat → H → Nat → H
  empty0 : H
  hLeaf_inj : ∀ {l₁ l₂ : Leaf}, hLeaf l₁ = hLeaf l₂ → l₁ = l₂
  hNode_inj : ∀ {a₁ b₁ a₂ b₂ : H} {sa₁ sb₁ sa₂ sb₂ : Nat},
    hNode a₁ sa₁ b₁ sb₁ = hNode a₂ sa₂ b₂ sb₂ →
      a₁ = a₂ ∧ sa₁ = sa₂ ∧ b₁ = b₂ ∧ sb₁ = sb₂
  hNode_ne_hLeaf : ∀ (a : H) (sa : Nat) (b : H) (sb : Nat) (l : Leaf),
    hNode a sa b sb ≠ hLeaf l
  hNode_ne_empty : ∀ (a : H) (sa : Nat) (b : H) (sb : Nat),
    hNode a sa b sb ≠ empty0
  hLeaf_ne_empty : ∀ (l : Leaf), hLeaf l ≠ empty0

end LayerTree
