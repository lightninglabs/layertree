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

The voucher message is `H_voucher(tree_id ‖ body(source_leaf) ‖
claim_leaf)` (or the hash-locked form), where `body` is the leaf without
its `amount` field (5.2, 7.5): the six fields `exit_key`, `owner_key`,
`evictor_key`, `evict_after`, `nonce`, `seq`. The model keeps the three
fields and not the hash. `Voucher.Redeemable` is what the `CLAIM` script
checks of the tree apart from signatures: the script's `tree_id` constant
is the voucher's, some leaf at the source position has the voucher's body
(the amount is the leaf's own, whatever it is now), and the carve rules
hold against that leaf. The amount is left out of the message so that an
amount-only increase by `REWRITE_h` rule 3 (7.9), which needs no owner
signature, does not void a voucher; single use rests on `seq`, which the
body carries, and over-redemption on the carve rules against the current
amount (`voucher_survives_topup`).

## What is proved

* `voucher_no_replay`: after a redemption, no leaf with the source's
  body reappears in any reachable tree, provided (i) the source's
  `(owner_key, nonce)` was unique in the tree (5.2), (ii) the claim leaf
  is not itself a copy of the source identity at or below the source's
  `seq`, and (iii) no later join, update or rewrite admits such a copy and
  no later carve creates one. The script checks none of (i) to (iii);
  they are the obligations 5.2, 9.6 and 10.3 place on creators and
  issuers, and the theorem says they are exactly what the single-use
  property rests on. `voucher_no_replay_leaf` is the older, weaker form
  (the source leaf itself never recurs).
* `voucher_survives_topup`: a voucher redeemable against a leaf stays
  redeemable when that leaf's amount alone is raised, as `REWRITE_h`
  rule 3 permits without the owner, provided the raised residual still
  satisfies 7.5 rule 6 (zero, or at least `DUST_MIN`). The proviso is
  the one case the message cannot help: a voucher for the whole balance
  is blocked, not voided, by a top-up below `DUST_MIN`, until the
  residual reaches the floor.
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

/-- The leaf body (5.2): a leaf without its `amount`, the part of a leaf
that a voucher (7.5) and an exit authorisation (7.2 rule 7) bind. -/
structure Leaf.Body where
  exitKey : Nat
  ownerKey : Nat
  evictorKey : Nat
  evictAfter : Nat
  nonce : Nat
  seq : Nat
  deriving DecidableEq, Repr

/-- The body of a leaf: every field but `amount`. -/
def Leaf.body (l : Leaf) : Leaf.Body :=
  ⟨l.exitKey, l.ownerKey, l.evictorKey, l.evictAfter, l.nonce, l.seq⟩

/-- Changing a leaf's amount alone leaves its body unchanged. -/
@[simp] theorem Leaf.body_amount (l : Leaf) (a : Nat) : ({ l with amount := a } : Leaf).body = l.body :=
  rfl

/-- Two leaves with the same body and the same amount are the same leaf:
the body is the leaf's identity, the amount its balance. -/
theorem Leaf.eq_of_body_eq {l l' : Leaf} (hb : l.body = l'.body) (ha : l.amount = l'.amount) :
    l = l' := by
  cases l; cases l'
  cases hb
  cases ha
  rfl

/-- A voucher as its message binds it: the tree's `tree_id`, the source
leaf's body and the claim leaf, all by content. The source's amount is
not part of it. -/
structure Voucher where
  treeId : Nat
  src : Leaf.Body
  claim : Leaf
  deriving DecidableEq, Repr

/-- The voucher an issuer signs against the source leaf it holds: the
leaf's body, with the amount it carried at issuance left out. -/
def Voucher.issue (treeId : Nat) (src claim : Leaf) : Voucher :=
  ⟨treeId, src.body, claim⟩

/-- A tree output with the lineage constant its `CLAIM` scripts carry. -/
structure TreeOutput (d : Nat) where
  treeId : Nat
  tree : Tree d

/-- What the `CLAIM` script checks of the tree for voucher `v` with the
source at `p`, signatures aside: the script's `tree_id` is the voucher's,
the leaf at `p` has the voucher's body (its amount is whatever the tree
holds now), and the carve rules hold against that leaf. The claim position
is the redeemer's choice (any position empty after the source step,
`claim_sound`) and is not part of the voucher. -/
def Voucher.Redeemable (π : Params) (v : Voucher) {d : Nat} (T : TreeOutput d) (p : Pos d 0) :
    Prop :=
  v.treeId = T.treeId ∧
    ∃ l : Leaf, T.tree.get p = some l ∧ l.body = v.src ∧ CarveOk π l v.claim

/-- The voucher an issuer signs against the leaf in front of it is
redeemable there, given the carve rules. -/
theorem Voucher.issue_redeemable {π : Params} {d : Nat} (T : TreeOutput d) (p : Pos d 0)
    (src claim : Leaf) (hsrc : T.tree.get p = some src) (hok : CarveOk π src claim) :
    (Voucher.issue T.treeId src claim).Redeemable π T p :=
  ⟨rfl, src, hsrc, rfl, hok⟩

/-- A redeemable voucher with an empty claim position is an accepted
`claim` record over the leaf the tree holds. -/
theorem Voucher.redeem_pre {π : Params} {d : Nat} (v : Voucher) (T : TreeOutput d) (p₁ p₂ : Pos d 0)
    (hr : v.Redeemable π T p₁) :
    ∃ l : Leaf, T.tree.get p₁ = some l ∧ l.body = v.src ∧
      ((T.tree.set p₁ (claimedSource l v.claim.amount)).get p₂ = none →
        (Trans.claim p₁ p₂ l v.claim).Pre π T.tree) := by
  obtain ⟨_, l, hl, hb, hok⟩ := hr
  exact ⟨l, hl, hb, fun hempty => ⟨hl, hok, hempty⟩⟩

/-! ## Non-replay -/

/-- **A redeemed voucher's source body never recurs.** Let the voucher
with source `src` be redeemed at `p₁` in `t`, placing `c` at `p₂`. If the
source identity `(owner_key, nonce)` was unique in `t`, the claim leaf
does not carry that identity with a `seq` at or below the source's, and
along the later trace nothing admitted or carved does either, then no
reachable tree holds a leaf with `src`'s body at any position: the leaf
with that identity, if present, has `seq` above `src.seq`, because the
redemption advanced it and every later carve advances it further, and the
body carries `seq`. The voucher's message therefore never verifies against
the tree again, whatever amount the leaf carries. -/
theorem voucher_no_replay {π : Params} {d : Nat} (t : Tree d) (p₁ p₂ : Pos d 0) (src c : Leaf)
    (hpre : (Trans.claim p₁ p₂ src c).Pre π t)
    (huniq : ∀ (q : Pos d 0) (l : Leaf), t.get q = some l →
      l.ownerKey = src.ownerKey → l.nonce = src.nonce → q = p₁)
    (hc : c.SeqAbove src.ownerKey src.nonce src.seq)
    {xs : List (Trans d)} {t' : Tree d}
    (h : Reachable π ((Trans.claim p₁ p₂ src c).apply t) xs t')
    (hadm : ∀ x ∈ xs, x.Admits (Leaf.SeqAbove src.ownerKey src.nonce src.seq))
    (hcarve : ∀ x ∈ xs, x.CarveLeaf (Leaf.SeqAbove src.ownerKey src.nonce src.seq)) :
    ∀ (q : Pos d 0) (l : Leaf), t'.get q = some l → l.body ≠ src.body := by
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
  intro q l hq hb
  have hk : l.ownerKey = src.ownerKey := congrArg Leaf.Body.ownerKey hb
  have hn : l.nonce = src.nonce := congrArg Leaf.Body.nonce hb
  have hs : l.seq = src.seq := congrArg Leaf.Body.seq hb
  have hlt := ht' q l hq hk hn
  rw [hs] at hlt
  exact Nat.lt_irrefl _ hlt

/-- The source leaf itself never recurs: the pre-0.13.0 statement, a
special case of `voucher_no_replay` (a leaf is its own body). -/
theorem voucher_no_replay_leaf {π : Params} {d : Nat} (t : Tree d) (p₁ p₂ : Pos d 0) (src c : Leaf)
    (hpre : (Trans.claim p₁ p₂ src c).Pre π t)
    (huniq : ∀ (q : Pos d 0) (l : Leaf), t.get q = some l →
      l.ownerKey = src.ownerKey → l.nonce = src.nonce → q = p₁)
    (hc : c.SeqAbove src.ownerKey src.nonce src.seq)
    {xs : List (Trans d)} {t' : Tree d}
    (h : Reachable π ((Trans.claim p₁ p₂ src c).apply t) xs t')
    (hadm : ∀ x ∈ xs, x.Admits (Leaf.SeqAbove src.ownerKey src.nonce src.seq))
    (hcarve : ∀ x ∈ xs, x.CarveLeaf (Leaf.SeqAbove src.ownerKey src.nonce src.seq)) :
    ∀ q : Pos d 0, t'.get q ≠ some src :=
  fun q hq => voucher_no_replay t p₁ p₂ src c hpre huniq hc h hadm hcarve q src hq rfl

/-! ## Top-ups -/

/-- **A voucher survives an amount-only increase of its source.** Let `v`
be redeemable against the leaf `l` at `p`, and let `l'` be `l` with a
larger amount and nothing else changed, which is what `REWRITE_h` rule 3
(7.9) lets the operator write without the owner's signature. Then `v` is
redeemable against the tree holding `l'` at `p`, provided the residual
`l'.amount − v.claim.amount` still satisfies 7.5 rule 6 (it is zero, or at
least `DUST_MIN`). The body is unchanged, so the message is; the amount
check of the carve rules only gets easier. The proviso is the one case
the message cannot help: a voucher for the whole balance (`residual = 0`)
is blocked by a top-up below `DUST_MIN`, since the residual it leaves is
then non-zero and sub-dust, until further top-ups bring the residual to
the floor or the issuer reissues. A voucher whose residual was already at
least `DUST_MIN` survives every top-up. -/
theorem voucher_survives_topup {π : Params} {d : Nat} (v : Voucher) (T : TreeOutput d)
    (p : Pos d 0) (l : Leaf) (a : Nat)
    (hid : v.treeId = T.treeId) (hl : T.tree.get p = some l) (hb : l.body = v.src)
    (hok : CarveOk π l v.claim) (hle : l.amount ≤ a)
    (hres : v.claim.amount = a ∨ π.dustMin ≤ a - v.claim.amount) :
    v.Redeemable π ⟨T.treeId, T.tree.set p (some { l with amount := a })⟩ p := by
  refine ⟨hid, { l with amount := a }, by simp [Tree.get_set], by simpa using hb, ?_⟩
  exact { amount_le := Nat.le_trans hok.amount_le hle,
          seq_lt := hok.seq_lt,
          evictorKey_eq := hok.evictorKey_eq,
          evictAfter_le := hok.evictAfter_le,
          claim_dust := hok.claim_dust,
          residual_dust := hres }

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
the source leaf itself (`Voucher.issue tree_id src src`) carves the full
amount (the source becomes `E_0`) and places the identical leaf, at the
now-empty source position if the redeemer chooses it, so the tree is
unchanged and the voucher is redeemable again. No value moves. This is
the one case in which a leaf with the source's body recurs at the source
position after a redemption, and the reason `voucher_no_replay` requires
the claim leaf not to carry the source's identity at or below the
source's `seq`. -/
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
  obtain ⟨hid, l, hget, hb, hok⟩ := hr
  refine ⟨⟨hid, l, ?_, hb, hok⟩, fun h' => ?_⟩
  · show (T.tree.getSub p).get q = some l
    rw [(detach_partition T.tree p).1 q |>.1]; exact hget
  · obtain ⟨_, l', hl', _, _⟩ := h'
    show False
    rw [show (T.detachParent p).tree = T.tree.setSub p (Tree.empty h) from rfl,
      (detach_partition T.tree p).1 q |>.2] at hl'
    cases hl'

end LayerTree
