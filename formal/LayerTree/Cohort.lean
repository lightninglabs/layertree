import LayerTree.Transitions

/-!
# Cohort transitions

Section 7.7 of the specification (`EVICT_SUBTREE_h`) and Shapes 2 and 3 of
`design/batching.md` (`REWRITE_h`, `DETACH_h`) act on one *aligned subtree*
of height `h` rather than on a single leaf: the witness carries the shared
path above the subtree once, and the subtree itself either as its `2^h`
published elements (sweep, rewrite) or as its root node (detach).

Each of them is one `Step` of `LayerTree.Transitions` whose old node is the
root of a published subtree, so `Step.sound` and `Steps.sum` already give
the Merkle-sum half of the argument. What this module adds is the
per-position content: the payouts a sweep or rewrite owes, that the
committed tree holds exactly the published elements at exactly the
published positions, and for a detach that the members' existing paths,
truncated to the lower `h` levels, are their proofs in the detached tree.

## Published subtrees

The `EVICT_SUBTREE_h` witness lists the `2^h` elements of the subtree in
position order, each a leaf or the empty string, and the script folds them
post-order into the subtree root. In the model the published elements are
a `Tree h` (`Tree.leaves` is the list, `Tree.leaves_inj` says the list
names exactly one tree) and the post-order fold is `Tree.root`. A step
whose old node is `u.root` for a published `u` is therefore grounded by
construction, which is what closes the opacity caveat of `JOIN_h` for
cohort joins made through `REWRITE_h`.

## Authorisation

As in `Transitions.lean`, signatures and lock-time checks are opaque
propositions. For a rewrite the authorisation is per position (the owner
of a changed leaf signs), so it is a predicate on positions of the subtree
that the structure requires at every changed position.
-/

namespace LayerTree

variable {H : Type} [M : HashModel Leaf H]

/-! ## Payouts -/

/-- A payout output: the exit key it pays (`P2TR(exit_key)`) and its
amount. The scriptPubKey itself is an authorisation-side fact; the
theorems use the amount. -/
structure Payout where
  key : Nat
  amount : Nat
  deriving DecidableEq, Repr

/-- The payout a leaf is owed when it is removed: `leaf.amount` to
`P2TR(leaf.exit_key)` (7.7 rule 2, `REWRITE_h` rule 5). -/
def Leaf.payout (l : Leaf) : Payout := ⟨l.exitKey, l.amount⟩

def payoutTotal : List Payout → Nat
  | [] => 0
  | p :: rest => p.amount + payoutTotal rest

omit M in
theorem payoutTotal_append (a b : List Payout) :
    payoutTotal (a ++ b) = payoutTotal a + payoutTotal b := by
  induction a with
  | nil => simp [payoutTotal]
  | cons p rest ih => simp [payoutTotal, ih]; omega

namespace Tree

/-- The payouts of a sweep (7.7 rule 2): every non-empty position, in
position order, pays its leaf. -/
def sweepPayouts : {h : Nat} → Tree h → List Payout
  | _, tip none => []
  | _, tip (some l) => [l.payout]
  | _, bin l r => l.sweepPayouts ++ r.sweepPayouts

/-- **The sweep's payouts sum to the subtree's sum.** -/
theorem sweepPayouts_total : {h : Nat} → (t : Tree h) → payoutTotal t.sweepPayouts = t.total
  | _, tip none => rfl
  | _, tip (some l) => by simp [sweepPayouts, payoutTotal, Leaf.payout, total]
  | _, bin l r => by
    simp [sweepPayouts, payoutTotal_append, total, sweepPayouts_total l, sweepPayouts_total r]

/-- The payouts of a rewrite (`REWRITE_h` rule 5): a position whose old
element is a leaf and whose new element is `E_0` pays that leaf, in
position order. A position that keeps a leaf, changes it for another, or
gains one pays nothing. -/
def rewritePayouts : {h : Nat} → Tree h → Tree h → List Payout
  | _, tip (some l), tip none => [l.payout]
  | _, tip _, tip _ => []
  | _, bin l₁ r₁, bin l₂ r₂ => rewritePayouts l₁ l₂ ++ rewritePayouts r₁ r₂

/-- A rewrite never pays out more than the old subtree held. -/
theorem rewritePayouts_le : {h : Nat} → (old new : Tree h) →
    payoutTotal (old.rewritePayouts new) ≤ old.total
  | _, tip (some l), tip none => by simp [rewritePayouts, payoutTotal, Leaf.payout, total]
  | _, tip (some _), tip (some _) => by simp [rewritePayouts, payoutTotal]
  | _, tip none, tip _ => by simp [rewritePayouts, payoutTotal]
  | _, bin l₁ r₁, bin l₂ r₂ => by
    simp only [rewritePayouts, payoutTotal_append, total]
    have := rewritePayouts_le l₁ l₂
    have := rewritePayouts_le r₁ r₂
    omega

/-- When the new subtree is empty the rewrite is a sweep: every old leaf
is paid, so the payouts equal the old subtree's sum. -/
theorem rewritePayouts_empty : {h : Nat} → (old : Tree h) →
    payoutTotal (old.rewritePayouts (empty h)) = old.total
  | _, tip (some l) => by simp [rewritePayouts, empty, payoutTotal, Leaf.payout, total]
  | _, tip none => by simp [rewritePayouts, empty, payoutTotal, total]
  | _, bin l r => by
    simp only [rewritePayouts, empty, payoutTotal_append, total]
    rw [rewritePayouts_empty l, rewritePayouts_empty r]

end Tree

/-! ## EVICT_SUBTREE_h (section 7.7) -/

/-- What `EVICT_SUBTREE_h` accepts (7.7 rules 1 to 4): one step whose old
node is the root of the published subtree `u` and whose new node is `E_h`;
the terminal or non-terminal `FINAL` branch for output 0 (rule 4 defers to
7.8); the payouts of rule 2; and the operator's signature, lease test and
evictor-key checks as `auth`. -/
structure EvictSubtree (auth : Prop) (d h : Nat) (r : Node H) (path : List (Bool × Node H))
    (u : Tree h) (r' : Node H) (out0 : Nat) (payouts : List Payout) (terminal : Bool) : Prop where
  steps : Steps r [Step.mk h path u.root (Tree.emptyNode h)] r'
  final : Final d r' out0 terminal
  payouts_eq : payouts = u.sweepPayouts
  authorised : auth

/-- **A sweep empties exactly the published subtree and pays it out.** The
committed tree holds the published elements at the published positions
(by `root_inj`, the published subtree *is* the subtree at that position),
output 0 commits to the tree with that subtree emptied, the payouts sum to
the subtree's sum, and the input amount is accounted for: output 0 plus
the payouts off the terminal branch, the payouts alone on it. -/
theorem evictSubtree_sound {auth : Prop} {d h : Nat} (t : Tree d) (path : List (Bool × Node H))
    (u : Tree h) (r' : Node H) (out0 : Nat) (payouts : List Payout) (terminal : Bool)
    (hwf : path.length + h = d)
    (he : EvictSubtree auth d h t.root path u r' out0 payouts terminal) :
    ∃ p : Pos d h, t.getSub p = u ∧
      (∀ q : Pos h 0, t.get (p.append q) = u.get q) ∧
      r' = (t.setSub p (Tree.empty h)).root ∧
      payoutTotal payouts = u.total ∧
      (terminal = false → out0 + payoutTotal payouts = t.root.sum) ∧
      (terminal = true → payoutTotal payouts = t.root.sum) := by
  cases he.steps with
  | cons hv hrest =>
    cases hrest
    obtain ⟨p, hold, hnew⟩ := Step.sound t (Step.mk h path u.root (Tree.emptyNode h)) r' hwf hv
    have hu : t.getSub p = u := (Tree.root_inj _ _ hold).symm
    have hpay : payoutTotal payouts = u.total := by
      rw [he.payouts_eq]; exact Tree.sweepPayouts_total u
    have hs := Step.sum _ _ _ hv
    simp only [Tree.emptyNode_sum, Tree.root_sum] at hs
    have hf := he.final
    refine ⟨p, hu, fun q => by rw [Tree.get_append, hu], hnew (Tree.empty h) rfl, hpay, ?_, ?_⟩
    · intro ht; subst ht
      have : out0 = r'.sum := hf
      rw [Tree.root_sum]; omega
    · intro ht; subst ht
      have hr : r' = Tree.emptyNode d := hf
      have h0 : r'.sum = 0 := by rw [hr]; exact Tree.emptyNode_sum d
      rw [Tree.root_sum]; omega

/-! ## REWRITE_h (`design/batching.md`, Shape 2) -/

/-- What `REWRITE_h` accepts. The witness carries the shared path above an
aligned subtree of height `h` and, for each position, an old and a new
element; `old` and `new` are the two published subtrees. Rules: (1) the
old subtree root folds with the path to the committed root and (2) the
new root is the fold of the new subtree root, together the one `Step`;
(3) every position whose element changes is authorised, with `auth` a
predicate on positions (the old leaf's owner signs); (5) the payouts are
`rewritePayouts`; (6) output 0 carries the new sum, which `Steps.sum`
turns into `S − Σ old + Σ new`. -/
structure Rewrite (h : Nat) (auth : Pos h 0 → Prop) (r : Node H) (path : List (Bool × Node H))
    (old new : Tree h) (r' : Node H) (out0 : Nat) (payouts : List Payout) : Prop where
  steps : Steps r [Step.mk h path old.root new.root] r'
  out0_eq : out0 = r'.sum
  authorised : ∀ q : Pos h 0, old.get q ≠ new.get q → auth q
  payouts_eq : payouts = old.rewritePayouts new

/-- **A rewrite replaces exactly the published subtree.** The committed
tree held the old elements at the published positions, output 0 commits to
the tree with the new elements there, positions inside the subtree whose
element did not change keep it, every subtree of height `h` elsewhere is
untouched, the output amount moves by `Σ new − Σ old` (rule 6, stated
additively), and the payouts never exceed what left the tree. -/
theorem rewrite_sound {d h : Nat} {auth : Pos h 0 → Prop} (t : Tree d)
    (path : List (Bool × Node H)) (old new : Tree h) (r' : Node H) (out0 : Nat)
    (payouts : List Payout) (hwf : path.length + h = d)
    (hr : Rewrite h auth t.root path old new r' out0 payouts) :
    ∃ p : Pos d h, t.getSub p = old ∧
      r' = (t.setSub p new).root ∧
      (∀ q : Pos h 0, t.get (p.append q) = old.get q ∧
        (t.setSub p new).get (p.append q) = new.get q) ∧
      (∀ q : Pos d h, q ≠ p → (t.setSub p new).getSub q = t.getSub q) ∧
      out0 + old.total = t.root.sum + new.total ∧
      out0 + payoutTotal payouts ≤ t.root.sum + new.total := by
  cases hr.steps with
  | cons hv hrest =>
    cases hrest
    obtain ⟨p, hold, hnew⟩ := Step.sound t (Step.mk h path old.root new.root) r' hwf hv
    have hu : t.getSub p = old := (Tree.root_inj _ _ hold).symm
    have hs := Step.sum _ _ _ hv
    simp only [Tree.root_sum] at hs
    have hle : payoutTotal payouts ≤ old.total := by
      rw [hr.payouts_eq]; exact Tree.rewritePayouts_le old new
    refine ⟨p, hu, hnew new rfl, fun q => ⟨?_, ?_⟩, fun q hq => ?_, ?_, ?_⟩
    · rw [Tree.get_append, hu]
    · rw [Tree.get_append, Tree.getSub_setSub]
    · exact Tree.getSub_setSub_ne t p q new (Ne.symm hq)
    · rw [hr.out0_eq, Tree.root_sum t]; omega
    · rw [hr.out0_eq, Tree.root_sum t]; omega

/-- **Exit-only rewrites conserve exactly.** When no new element is a leaf
(the new subtree is empty) every old leaf is paid and output 0 plus the
payouts equals the input amount: the same statement as
`ExitK.exact_conservation`, for a whole cohort at once. Needs no tree:
`Steps.sum` holds for any step list. -/
theorem rewrite_exit_conservation {h : Nat} {auth : Pos h 0 → Prop} {r r' : Node H}
    {path : List (Bool × Node H)} {old : Tree h} {out0 : Nat} {payouts : List Payout}
    (hr : Rewrite h auth r path old (Tree.empty h) r' out0 payouts) :
    out0 + payoutTotal payouts = r.sum := by
  have hs := hr.steps.sum
  simp only [oldSum, newSum, Tree.root_sum] at hs
  have hp : payoutTotal payouts = old.total := by
    rw [hr.payouts_eq]; exact Tree.rewritePayouts_empty old
  have h0 : (Tree.empty h).total = 0 := by
    rw [← Tree.root_sum]; exact Tree.emptyNode_sum h
  rw [hr.out0_eq]; omega

/-! ## DETACH_h (`design/batching.md`, Shape 3) -/

/-- What `DETACH_h` accepts. Rule 1: the old node `(R_h, sum_h)` folds with
the path to the committed root. Rule 2: the new node is `E_h` and output 0
carries the new sum. Rule 3: output 1 is a tree output whose root hash is
`R_h` and whose amount is `sum_h` (`r₁`, `out1`); its taptree `m_h` is a
binding-side fact (`LayerTree.Binding`). Rule 4: the operator signs. -/
structure Detach (auth : Prop) (h : Nat) (r : Node H) (path : List (Bool × Node H))
    (sub : Node H) (r' : Node H) (out0 : Nat) (r₁ : H) (out1 : Nat) : Prop where
  steps : Steps r [Step.mk h path sub (Tree.emptyNode h)] r'
  out0_eq : out0 = r'.sum
  r₁_eq : r₁ = sub.hash
  out1_eq : out1 = sub.sum
  authorised : auth

/-- **A detach moves a subtree into its own tree output.** Value is
conserved across the two outputs; output 0 commits to the tree with the
subtree emptied; output 1 is a well-formed tree output of depth `h`: its
root hash is that of the subtree `t.getSub p` and its amount is that
subtree's total, the invariant of section 5.6; and every member's path in
the old tree, with the shared `d − h` upper levels dropped, is that
member's path in the detached tree, holding the same leaf. -/
theorem detach_sound {auth : Prop} {d h : Nat} (t : Tree d) (path : List (Bool × Node H))
    (sub r' : Node H) (out0 : Nat) (r₁ : H) (out1 : Nat) (hwf : path.length + h = d)
    (hd : Detach auth h t.root path sub r' out0 r₁ out1) :
    ∃ p : Pos d h,
      out0 + out1 = t.root.sum ∧
      r' = (t.setSub p (Tree.empty h)).root ∧
      r₁ = (t.getSub p).root.hash ∧ out1 = (t.getSub p).total ∧
      ∀ q : Pos h 0, (t.getSub p).get q = t.get (p.append q) ∧
        (t.getSub p).path q = (t.path (p.append q)).drop (d - h) := by
  cases hd.steps with
  | cons hv hrest =>
    cases hrest
    obtain ⟨p, hold, hnew⟩ := Step.sound t (Step.mk h path sub (Tree.emptyNode h)) r' hwf hv
    have hold : sub = (t.getSub p).root := hold
    have hs := Step.sum _ _ _ hv
    simp only [Tree.emptyNode_sum] at hs
    have hlen : (t.pathSub p).length + h = d := Tree.pathSub_length t p
    refine ⟨p, ?_, hnew (Tree.empty h) rfl, ?_, ?_, fun q => ⟨(Tree.get_append t p q).symm, ?_⟩⟩
    · rw [hd.out0_eq, hd.out1_eq]; omega
    · rw [hd.r₁_eq, hold]
    · rw [hd.out1_eq, hold, Tree.root_sum]
    · unfold Tree.path
      rw [Tree.pathSub_append]
      exact (List.drop_left' (by omega)).symm

/-- **Members' proofs survive a detach.** A leaf inside the detached
subtree, with the truncated path of `detach_sound`, has a valid `EXIT`
step from the detached tree's root to the root without it, paying its
amount: `payable` applied to the detached tree. -/
theorem detach_member_payable {d h : Nat} (t : Tree d) (p : Pos d h) (q : Pos h 0) (l : Leaf)
    (hl : t.get (p.append q) = some l) :
    (leafStep ((t.path (p.append q)).drop (d - h)) (some l) none).valid
      (t.getSub p).root ((t.getSub p).set q none).root ∧
    ((t.getSub p).set q none).root.sum + l.amount = (t.getSub p).root.sum := by
  have hl' : (t.getSub p).get q = some l := by rw [← Tree.get_append]; exact hl
  have hlen := Tree.pathSub_length t p
  have hpath : (t.path (p.append q)).drop (d - h) = (t.getSub p).path q := by
    unfold Tree.path
    rw [Tree.pathSub_append]
    exact List.drop_left' (by omega)
  rw [hpath]
  have := payable (t.getSub p) q l hl'
  exact ⟨this.1, this.2.1⟩

end LayerTree
