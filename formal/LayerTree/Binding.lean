import LayerTree.Transitions

/-!
# Binding the witness root to the tree output

Section 6 of the specification commits the root `r` to the tree output's
scriptPubKey through the taproot internal key
`P = NUMS + H_state(r)·G` and the output key `Q = P + H_taptweak(P, m)·G`,
where `m` is the taptree root that names the script set. Section 6.4
requires every script to recompute `TREE_SPK(r, m)` from the witness `r`
and `m` and compare it with the current input's scriptPubKey (`OP_TX`).
Section 10.4 explains why `m` must be included: without it the witness
could name a different script set.

The cryptographic content of that check is one property: `TREE_SPK` is
injective in `(r, m)`. In the deployment this follows from the discrete
logarithm assumption and the collision resistance of `H_state` and
`H_taptweak`; here it is a hypothesis of the model, and the theorem below
records exactly what the covenant concludes from it. This is the whole
argument of section 10.4, made explicit so that it cannot be forgotten
when the scripts change.
-/

namespace LayerTree

variable {H : Type} [M : HashModel Leaf H]

/-- The binding model: an abstract `treeSpk` from `(root hash, taptree
root)` to scriptPubKeys, assumed injective. `Spk` and `TapRoot` are
abstract; only equality on them is used. -/
structure BindingModel (H : Type) where
  TapRoot : Type
  Spk : Type
  treeSpk : H → TapRoot → Spk
  treeSpk_inj : ∀ {r₁ r₂ : H} {m₁ m₂ : TapRoot}, treeSpk r₁ m₁ = treeSpk r₂ m₂ → r₁ = r₂ ∧ m₁ = m₂

omit M in
/-- **The witness root is the committed root.** If the current input's
scriptPubKey was created as `treeSpk r m` (the tree output of section 6),
and the script finds `treeSpk r' m' = input scriptPubKey` for the witness
values `r'`, `m'`, then `r' = r` and `m' = m`: the script is checking
proofs against the true root and running under the true script set. Every
`fold_sound` application in `LayerTree.Transitions` starts from the `r`
this theorem delivers. -/
theorem witness_root_binds (B : BindingModel H) (r r' : H) (m m' : B.TapRoot)
    (hcheck : B.treeSpk r' m' = B.treeSpk r m) : r' = r ∧ m' = m :=
  B.treeSpk_inj hcheck

omit M in
/-- The same fact for the *output*: the script builds output 0's
scriptPubKey as `treeSpk r_new m` with the `m` it verified, so the next
tree output commits to exactly the root the fold computed and to the same
script set (section 7.1 rule 2). A spender cannot substitute another `m`
for the successor output without changing the scriptPubKey the covenant
requires. -/
theorem output_binds (B : BindingModel H) (rNew : H) (m m' : B.TapRoot) (rOut : H)
    (hout : B.treeSpk rOut m' = B.treeSpk rNew m) : rOut = rNew ∧ m' = m :=
  B.treeSpk_inj hout

end LayerTree
