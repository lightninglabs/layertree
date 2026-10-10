import LayerTree.Trace

/-!
# Vouchers, replay and detach

Section 7.5 argues that a voucher is single-use "because step 1 changes
the source leaf: once redeemed, no tree state contains `source_leaf` at
the source position, so the signed message can never verify against the
tree again", and 10.3 adds that `seq` is what keeps a later state from
reproducing the source bytes. This module proves the argument in the
form that is actually true, and shows where it needs hypotheses the
script does not check.

The voucher message is `H_voucher(tree_id ‖ source_leaf ‖ claim_leaf)`
(or the hash-locked form); the model keeps the three fields and not the
hash. `Voucher.Redeemable` is what the `CLAIM` script checks of the tree
apart from signatures: the script's `tree_id` constant is the voucher's,
the source leaf is in the tree byte for byte, and the carve rules hold.

## What is proved

* `voucher_no_replay`: after a redemption, the source leaf never reappears
  in any reachable tree, provided (i) the source's `(owner_key, nonce)`
  was unique in the tree (5.2), (ii) the claim leaf is not itself a copy
  of the source identity at or below the source's `seq`, and (iii) no
  later join, update or rewrite admits such a copy and no later carve
  creates one. The script checks none of (i) to (iii); they are the
  obligations 5.2, 9.6 and 10.3 place on creators and issuers, and the
  theorem says they are exactly what the single-use property rests on.
* `self_voucher_fixed`: the degenerate voucher whose claim leaf *is* the
  source leaf (full amount, same fields) carves the source to `E_0` and
  places the identical leaf back, so the tree is unchanged and the
  voucher verifies again. Replaying it moves no value, but it is a
  counterexample to the literal claim of 7.5 that the source leaf never
  recurs at the source position; hypothesis (ii) above excludes it.
* `final_never_carved`: a leaf at `SEQ_FINAL` is never a source, in the
  trace vocabulary (`claim_not_final` is the script-level statement).
* `detach_partition`, `voucher_survives_detach`: a detach moves every
  leaf of the cohort into the child and empties it in the parent, and a
  voucher redeemable against a cohort leaf is redeemable, as the same
  message, against the child and no longer against the parent. The
  child's `tree_id` is the parent's by definition (`TreeOutput.detachChild`),
  which is how the model states 6.2's inheritance rule; the script-level
  fact behind it, that the detach script's `m_h` constant compiles the
  same `tree_id`, is a creation-time property the model does not see.
-/

namespace LayerTree

/-- A voucher as its message binds it: the tree's `tree_id`, the source
leaf and the claim leaf, all by content. -/
structure Voucher where
  treeId : Nat
  src : Leaf
  claim : Leaf
  deriving DecidableEq, Repr

/-- A tree output with the lineage constant its `CLAIM` scripts carry. -/
structure TreeOutput (d : Nat) where
  treeId : Nat
  tree : Tree d

/-- What the `CLAIM` script checks of the tree for voucher `v` with the
source at `p`, signatures aside: the script's `tree_id` is the voucher's,
the source leaf is at `p` byte for byte, and the carve rules hold. The
claim position is the redeemer's choice (any position empty after the
source step, `claim_sound`) and is not part of the voucher. -/
def Voucher.Redeemable (π : Params) (v : Voucher) {d : Nat} (T : TreeOutput d) (p : Pos d 0) :
    Prop :=
  v.treeId = T.treeId ∧ T.tree.get p = some v.src ∧ CarveOk π v.src v.claim

/-- A redeemable voucher with an empty claim position is an accepted
`claim` record. -/
theorem Voucher.redeem_pre {π : Params} {d : Nat} (v : Voucher) (T : TreeOutput d) (p₁ p₂ : Pos d 0)
    (hr : v.Redeemable π T p₁)
    (hempty : (T.tree.set p₁ (claimedSource v.src v.claim.amount)).get p₂ = none) :
    (Trans.claim p₁ p₂ v.src v.claim).Pre π T.tree :=
  ⟨hr.2.1, hr.2.2, hempty⟩

/-! ## Non-replay -/

/-- **A redeemed voucher's source leaf never recurs.** Let the voucher
with source `src` be redeemed at `p₁` in `t`, placing `c` at `p₂`. If the
source identity `(owner_key, nonce)` was unique in `t`, the claim leaf
does not carry that identity with a `seq` at or below the source's, and
along the later trace nothing admitted or carved does either, then no
reachable tree holds `src` at any position: the leaf with that identity,
if present, has `seq` above `src.seq`, because the redemption advanced it
and every later carve advances it further. The voucher's message
therefore never verifies against the tree again. -/
theorem voucher_no_replay {π : Params} {d : Nat} (t : Tree d) (p₁ p₂ : Pos d 0) (src c : Leaf)
    (hpre : (Trans.claim p₁ p₂ src c).Pre π t)
    (huniq : ∀ (q : Pos d 0) (l : Leaf), t.get q = some l →
      l.ownerKey = src.ownerKey → l.nonce = src.nonce → q = p₁)
    (hc : c.SeqAbove src.ownerKey src.nonce src.seq)
    {xs : List (Trans d)} {t' : Tree d}
    (h : Reachable π ((Trans.claim p₁ p₂ src c).apply t) xs t')
    (hadm : ∀ x ∈ xs, x.Admits (Leaf.SeqAbove src.ownerKey src.nonce src.seq))
    (hcarve : ∀ x ∈ xs, x.CarveLeaf (Leaf.SeqAbove src.ownerKey src.nonce src.seq)) :
    ∀ q : Pos d 0, t'.get q ≠ some src := by
  have ht₁ : ((Trans.claim p₁ p₂ src c).apply t).All (Leaf.SeqAbove src.ownerKey src.nonce src.seq) := by
    intro q l hq
    simp only [Trans.apply, carveTree] at hq
    by_cases hq₂ : q = p₂
    · subst hq₂; rw [Tree.get_set] at hq; rw [← Option.some.inj hq]; exact hc
    · rw [Tree.get_set_ne _ p₂ q _ (Ne.symm hq₂)] at hq
      by_cases hq₁ : q = p₁
      · subst hq₁; rw [Tree.get_set] at hq
        unfold claimedSource at hq
        split at hq
        · cases hq
        · rw [← Option.some.inj hq]
          intro _ _
          simp
      · rw [Tree.get_set_ne t p₁ q _ (Ne.symm hq₁)] at hq
        intro hk hn
        exact absurd (huniq q l hq hk hn) hq₁
  have ht' := Reachable.seqAbove _ _ _ h ht₁ hadm hcarve
  intro q hq
  exact Nat.lt_irrefl _ (ht' q src hq rfl rfl)

/-- The source rewrite drains a leaf carved for its full amount. -/
theorem claimedSource_full (src : Leaf) : claimedSource src src.amount = none := by
  simp [claimedSource]

namespace Tree

theorem setSub_setSub {d h : Nat} (t : Tree d) (p : Pos d h) (s s' : Tree h) :
    (t.setSub p s).setSub p s' = t.setSub p s' := by
  induction p with
  | nil => simp [setSub]
  | cons b p ih =>
    cases t with
    | bin l r => cases b <;> simp [setSub, ih]

theorem setSub_getSub {d h : Nat} (t : Tree d) (p : Pos d h) : t.setSub p (t.getSub p) = t := by
  induction p with
  | nil => simp [setSub, getSub]
  | cons b p ih =>
    cases t with
    | bin l r => cases b <;> simp [setSub, getSub, ih]

theorem set_get {d : Nat} (t : Tree d) (p : Pos d 0) (l : Leaf) (h : t.get p = some l) :
    t.set p (some l) = t := by
  have := setSub_getSub t p
  unfold get at h
  revert h this
  generalize t.getSub p = s
  cases s with
  | tip o =>
    intro h this
    have h' : o = some l := h
    subst h'
    exact this

end Tree

/-- **The self-voucher is a fixed point.** A voucher whose claim leaf is
the source leaf itself carves the full amount (the source becomes `E_0`)
and places the identical leaf, at the now-empty source position if the
redeemer chooses it, so the tree is unchanged and the voucher is
redeemable again. No value moves. This is the one case in which the
source leaf recurs at the source position after a redemption, and the
reason `voucher_no_replay` requires the claim leaf not to carry the
source's identity at or below the source's `seq`. -/
theorem self_voucher_fixed {π : Params} {d : Nat} (t : Tree d) (p : Pos d 0) (src : Leaf)
    (hpre : (Trans.claim p p src src).Pre π t) :
    (Trans.claim p p src src).apply t = t := by
  simp only [Trans.apply, carveTree, claimedSource_full, Tree.set, Tree.setSub_setSub]
  exact Tree.set_get t p src hpre.src_at

/-- **A final leaf is never carved** (5.2): a source at the tier's
`SEQ_FINAL` fails the `seq + 1` check of every `CLAIM`, `CLAIM^h` and
`SPLIT`, so a leaf created with `seq = SEQ_FINAL` (a channel leaf,
Appendix C.6.5) can be exited or updated but never split into. -/
theorem final_never_carved {π : Params} {d : Nat} (t : Tree d) (p₁ p₂ : Pos d 0) (src c : Leaf)
    (hfinal : src.seq = π.seqFinal) :
    ¬ (Trans.claim p₁ p₂ src c).Pre π t ∧ ¬ (Trans.split p₁ p₂ src c).Pre π t :=
  ⟨fun h => absurd hfinal (Nat.ne_of_lt h.ok.seq_lt),
   fun h => absurd hfinal (Nat.ne_of_lt h.ok.seq_lt)⟩

/-! ## Detach -/

namespace TreeOutput

/-- Output 1 of a `DETACH_h`: the cohort as a tree of depth `h` with the
parent's `tree_id` (6.2, 7.10 rule 3). The inheritance is stated by
definition; it is what the detach script's `m_h` constant compiles. -/
def detachChild {d h : Nat} (T : TreeOutput d) (p : Pos d h) : TreeOutput h :=
  ⟨T.treeId, T.tree.getSub p⟩

/-- Output 0 of a `DETACH_h`: the parent with the cohort emptied. -/
def detachParent {d h : Nat} (T : TreeOutput d) (p : Pos d h) : TreeOutput d :=
  ⟨T.treeId, T.tree.setSub p (Tree.empty h)⟩

@[simp] theorem detachChild_treeId {d h : Nat} (T : TreeOutput d) (p : Pos d h) :
    (T.detachChild p).treeId = T.treeId := rfl

end TreeOutput

/-- **A detach partitions the leaves.** Every position of the cohort
holds in the child exactly what it held in the parent and is empty in
the parent afterwards, and every position outside the cohort is
untouched. So each leaf is in exactly one of the two outputs. -/
theorem detach_partition {d h : Nat} (t : Tree d) (p : Pos d h) :
    (∀ q : Pos h 0, (t.getSub p).get q = t.get (p.append q) ∧
      (t.setSub p (Tree.empty h)).get (p.append q) = none) ∧
    (∀ q : Pos d 0, (∀ q' : Pos h 0, q ≠ p.append q') →
      (t.setSub p (Tree.empty h)).get q = t.get q) := by
  refine ⟨fun q => ⟨(Tree.get_append t p q).symm, ?_⟩, fun q hq => ?_⟩
  · rw [Tree.get_append, Tree.getSub_setSub, Tree.get_empty]
  · rcases Tree.get_setSub_cases t p (Tree.empty h) q with ⟨q', hq', _⟩ | hg
    · exact absurd hq' (hq q')
    · exact hg

/-- **A voucher survives a detach, as issued.** A voucher redeemable
against a cohort leaf in the parent is redeemable against the same leaf
in the child, with the same message (`tree_id` is inherited, the leaf
bytes are the parent's), and is no longer redeemable at that position in
the parent, whose cohort is empty. The source leaf exists in one tree of
the lineage only, which is what 6.2 and 10.3 require of inheritance. -/
theorem voucher_survives_detach {π : Params} {d h : Nat} (v : Voucher) (T : TreeOutput d)
    (p : Pos d h) (q : Pos h 0) (hr : v.Redeemable π T (p.append q)) :
    v.Redeemable π (T.detachChild p) q ∧
      ¬ v.Redeemable π (T.detachParent p) (p.append q) := by
  obtain ⟨hid, hget, hok⟩ := hr
  refine ⟨⟨hid, ?_, hok⟩, fun h' => ?_⟩
  · show (T.tree.getSub p).get q = some v.src
    rw [(detach_partition T.tree p).1 q |>.1]; exact hget
  · have := h'.2.1
    show False
    rw [show (T.detachParent p).tree = T.tree.setSub p (Tree.empty h) from rfl,
      (detach_partition T.tree p).1 q |>.2] at this
    cases this

end LayerTree
