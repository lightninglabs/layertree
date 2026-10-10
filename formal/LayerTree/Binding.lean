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

/-- The CCV tier's binding (spec 4.6, 6.3 `TREE_SPK_CCV`) as a two-stage
construction. BIP-443 builds the tree output key from the root `r` in two
tweaks: the data tweak `P = NUMS + sha256(NUMS ‖ r)·G` (`dataTweak`), then
the taproot tweak `Q = P + H_taptweak(P, m)·G` wrapped as a P2TR
scriptPubKey (`tapTweak`). Each stage carries its own injectivity
hypothesis, which is where the assumptions live:

* `dataTweak_inj`: collision resistance of the untagged SHA-256 over the
  fixed prefix `NUMS ‖ r` gives distinct scalars for distinct roots, and
  distinct scalars give distinct x-only keys unless
  `x(NUMS + t₁·G) = x(NUMS + t₂·G)` with `t₁ ≠ t₂`, which forces
  `2·NUMS = −(t₁ + t₂)·G` and so reveals the discrete logarithm of `NUMS`;
* `tapTweak_inj`: the BIP-341 argument for `TapTweak` (collision
  resistance of the tagged hash over `P ‖ m` plus the same discrete
  logarithm step), jointly in the internal key and the taptree root.

The FULL tier's `TREE_SPK` has the same shape with `H_state` in place of
the data tweak; the model does not need to distinguish them. -/
structure CCVTweak (H : Type) where
  Key : Type
  TapRoot : Type
  Spk : Type
  dataTweak : H → Key
  tapTweak : Key → TapRoot → Spk
  dataTweak_inj : ∀ {r₁ r₂ : H}, dataTweak r₁ = dataTweak r₂ → r₁ = r₂
  tapTweak_inj : ∀ {p₁ p₂ : Key} {m₁ m₂ : TapRoot},
    tapTweak p₁ m₁ = tapTweak p₂ m₂ → p₁ = p₂ ∧ m₁ = m₂

/-- **The CCV binding is a `BindingModel`.** Composing the two tweaks
gives `treeSpk r m = tapTweak (dataTweak r) m`, and its injectivity in
`(r, m)` follows from the two stage hypotheses. Hence
`witness_root_binds` and `output_binds` apply to a CCV tree unchanged:
`CHECK_INPUT` with `taptree = -1` is the input check with the input's own
`m`, and `CHECK_OUTPUT` on output 0 with `taptree = -1` is the output
check with that same `m`. -/
def CCVTweak.binding {H : Type} (C : CCVTweak H) : BindingModel H where
  TapRoot := C.TapRoot
  Spk := C.Spk
  treeSpk r m := C.tapTweak (C.dataTweak r) m
  treeSpk_inj h :=
    have hpm := C.tapTweak_inj h
    ⟨C.dataTweak_inj hpm.1, hpm.2⟩

omit M in
/-- `witness_root_binds` instantiated at the CCV binding: if `CHECK_INPUT`
accepts the folded root `oh` against an input created as the CCV tree
output for `(r, m)`, then `oh = r` and the input's taptree is `m`. -/
theorem ccv_input_binds (C : CCVTweak H) (r oh : H) (m m' : C.TapRoot)
    (hcheck : C.binding.treeSpk oh m' = C.binding.treeSpk r m) : oh = r ∧ m' = m :=
  witness_root_binds C.binding r oh m m' hcheck

end LayerTree
