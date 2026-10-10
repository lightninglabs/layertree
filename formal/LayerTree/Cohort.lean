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

end LayerTree
