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

/-! ## Payouts

`Payout`, `Leaf.payout` and `payoutTotal` are defined in
`LayerTree.Transitions`, where the single-leaf `EXIT` uses them. -/

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
gains one pays nothing. In the reclaim form of rule 8 (a tree that names
`RECLAIM_KEY`) a reclaimable leaf that is emptied is reclaimed, not
paid: it needs no payout, and its amount is the transaction's to spend
(`reclaimedTotal`). In a tree without `RECLAIM_KEY` no leaf is
reclaimable and every emptied leaf is paid. -/
def rewritePayouts (π : Params) : {h : Nat} → Tree h → Tree h → List Payout
  | _, tip (some l), tip none => if π.Reclaimable l then [] else [l.payout]
  | _, tip _, tip _ => []
  | _, bin l₁ r₁, bin l₂ r₂ => rewritePayouts π l₁ l₂ ++ rewritePayouts π r₁ r₂

/-- The amounts of the reclaimable leaves a rewrite empties (7.9 rule 8,
reclaim branch): value that leaves the tree with no payout. -/
def reclaimedTotal (π : Params) : {h : Nat} → Tree h → Tree h → Nat
  | _, tip (some l), tip none => if π.Reclaimable l then l.amount else 0
  | _, tip _, tip _ => 0
  | _, bin l₁ r₁, bin l₂ r₂ => reclaimedTotal π l₁ l₂ + reclaimedTotal π r₁ r₂

/-- Without `RECLAIM_KEY` a rewrite reclaims nothing. -/
theorem reclaimedTotal_none {π : Params} (hπ : π.reclaimKey = none) :
    {h : Nat} → (old new : Tree h) → reclaimedTotal π old new = 0
  | _, tip (some l), tip none => by
    simp [reclaimedTotal, Params.not_reclaimable hπ l]
  | _, tip (some _), tip (some _) => by simp [reclaimedTotal]
  | _, tip none, tip _ => by simp [reclaimedTotal]
  | _, bin l₁ r₁, bin l₂ r₂ => by
    simp [reclaimedTotal, reclaimedTotal_none hπ l₁ l₂, reclaimedTotal_none hπ r₁ r₂]

/-- A rewrite never pays out more than the old subtree held. -/
theorem rewritePayouts_le (π : Params) : {h : Nat} → (old new : Tree h) →
    payoutTotal (old.rewritePayouts π new) ≤ old.total
  | _, tip (some l), tip none => by
    by_cases hr : π.Reclaimable l <;> simp [rewritePayouts, hr, payoutTotal, Leaf.payout, total]
  | _, tip (some _), tip (some _) => by simp [rewritePayouts, payoutTotal]
  | _, tip none, tip _ => by simp [rewritePayouts, payoutTotal]
  | _, bin l₁ r₁, bin l₂ r₂ => by
    simp only [rewritePayouts, payoutTotal_append, total]
    have := rewritePayouts_le π l₁ l₂
    have := rewritePayouts_le π r₁ r₂
    omega

/-- The old amounts at the positions that still hold a leaf after the
rewrite (kept, resized, replaced or paid between members). With
`rewritePayouts` and `reclaimedTotal` these partition the old subtree's
leaves: a position either exits and is paid, is reclaimed, or keeps a
leaf. -/
def keptTotal : {h : Nat} → Tree h → Tree h → Nat
  | _, tip (some l), tip (some _) => l.amount
  | _, tip _, tip _ => 0
  | _, bin l₁ r₁, bin l₂ r₂ => keptTotal l₁ l₂ + keptTotal r₁ r₂

/-- The payouts of a rewrite, its reclaims and its kept amounts account
for every old leaf exactly once. -/
theorem rewritePayouts_add_kept (π : Params) : {h : Nat} → (old new : Tree h) →
    payoutTotal (old.rewritePayouts π new) + old.reclaimedTotal π new + old.keptTotal new =
      old.total
  | _, tip (some l), tip none => by
    by_cases hr : π.Reclaimable l <;>
      simp [rewritePayouts, reclaimedTotal, hr, keptTotal, payoutTotal, Leaf.payout, total]
  | _, tip (some _), tip (some _) => by
    simp [rewritePayouts, reclaimedTotal, keptTotal, payoutTotal, total]
  | _, tip none, tip _ => by simp [rewritePayouts, reclaimedTotal, keptTotal, payoutTotal, total]
  | _, bin l₁ r₁, bin l₂ r₂ => by
    simp only [rewritePayouts, reclaimedTotal, keptTotal, payoutTotal_append, total]
    have := rewritePayouts_add_kept π l₁ l₂
    have := rewritePayouts_add_kept π r₁ r₂
    omega

/-- When the new subtree is empty the rewrite is a sweep: every old leaf
is paid or reclaimed, so the payouts and the reclaims together equal the
old subtree's sum. -/
theorem rewritePayouts_empty (π : Params) : {h : Nat} → (old : Tree h) →
    payoutTotal (old.rewritePayouts π (empty h)) + old.reclaimedTotal π (empty h) = old.total
  | _, tip (some l) => by
    by_cases hr : π.Reclaimable l <;>
      simp [rewritePayouts, reclaimedTotal, hr, empty, payoutTotal, Leaf.payout, total]
  | _, tip none => by simp [rewritePayouts, reclaimedTotal, empty, payoutTotal, total]
  | _, bin l r => by
    simp only [rewritePayouts, reclaimedTotal, empty, payoutTotal_append, total]
    have := rewritePayouts_empty π l
    have := rewritePayouts_empty π r
    omega

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

/-- The exemption of `REWRITE_h` rule 3: a position needs no owner
signature when its new element is a leaf identical to the old one in
every field but `amount`, with the amount not decreasing, *and* the old
leaf is not at `SEQ_FINAL`. A final leaf's amount is not its owner's
alone (5.2: channel leaves), so growing it is a change its owner must
authorise like any other. -/
def Leaf.AmountOnlyIncrease (π : Params) (old : Leaf) (o : Option Leaf) : Prop :=
  ∃ new, o = some new ∧ new = { old with amount := new.amount } ∧ old.amount ≤ new.amount ∧
    old.seq ≠ π.seqFinal

/-- The left half of the transfer of 7.9 rule 8: the old leaf is
reclaimable and its new element is the same leaf with a *lower* amount.
The script, seeing this shape at an even position, requires the odd
sibling to absorb the decrease (`Tree.Transfer`). -/
def Leaf.TransferShape (π : Params) (old : Leaf) (o : Option Leaf) : Prop :=
  π.Reclaimable old ∧
    ∃ new, o = some new ∧ new = { old with amount := new.amount } ∧ new.amount < old.amount

/-- The transfer of 7.9 rule 8 at the pair `c` of the published subtree:
the even member's old leaf `l` is reclaimable and falls in amount alone;
the odd member's old leaf `m` is not reclaimable, is owned by `l`'s exit
key, and its new element is `m` with its amount raised by exactly the
decrease. -/
def Tree.Transfer (π : Params) {h : Nat} (old new : Tree h) (c : Pos h 1) : Prop :=
  ∃ l l' m : Leaf, old.get (c.pairAt false) = some l ∧ new.get (c.pairAt false) = some l' ∧
    π.Reclaimable l ∧ l' = { l with amount := l'.amount } ∧ l'.amount < l.amount ∧
    old.get (c.pairAt true) = some m ∧ ¬ π.Reclaimable m ∧ m.ownerKey = l.exitKey ∧
    new.get (c.pairAt true) = some { m with amount := m.amount + (l.amount - l'.amount) }

/-- What `REWRITE_h` accepts. The witness carries the shared path above an
aligned subtree of height `h` and, for each position, an old and a new
element; `old` and `new` are the two published subtrees. Rules: (1) the
old subtree root folds with the path to the committed root and (2) the
new root is the fold of the new subtree root, together the one `Step`;
(3) every position whose old element is a leaf and whose element changes
is authorised, with `auth` a predicate on positions (the old leaf's owner
signs), except under `Leaf.AmountOnlyIncrease`; (5) the payouts are
`rewritePayouts`; (6) output 0 carries the new sum, which `Steps.sum`
turns into `S − Σ old + Σ new`.

Rule 8, the reclaim form (a tree that names `RECLAIM_KEY`): a position
whose old leaf is reclaimable never needs its owner. An amount-only
increase passes as rule 3; at an even position a decrease of the amount
alone is a transfer, and the odd sibling must absorb it exactly
(`transfer`); any other change is a reclaim, which needs the
transaction's lock time `lockTime` to have reached the old leaf's
`evict_after` (`deadline`) and pays nothing when the position is
emptied (`rewritePayouts`). In a tree without `RECLAIM_KEY` no leaf is
reclaimable and the two extra fields are vacuous. -/
structure Rewrite (h : Nat) (π : Params) (auth : Pos h 0 → Prop) (lockTime : Nat) (r : Node H)
    (path : List (Bool × Node H)) (old new : Tree h) (r' : Node H) (out0 : Nat)
    (payouts : List Payout) : Prop where
  steps : Steps r [Step.mk h path old.root new.root] r'
  out0_eq : out0 = r'.sum
  authorised : ∀ (q : Pos h 0) (l : Leaf), old.get q = some l → new.get q ≠ some l →
    ¬ l.AmountOnlyIncrease π (new.get q) → ¬ π.Reclaimable l → auth q
  transfer : ∀ (c : Pos h 1) (l : Leaf), old.get (c.pairAt false) = some l →
    l.TransferShape π (new.get (c.pairAt false)) → old.Transfer π new c
  deadline : ∀ (q : Pos h 0) (l : Leaf), old.get q = some l → new.get q ≠ some l →
    π.Reclaimable l → ¬ l.AmountOnlyIncrease π (new.get q) →
    (¬ ∃ c : Pos h 1, q = c.pairAt false ∧ l.TransferShape π (new.get q)) →
    l.evictAfter ≤ lockTime
  payouts_eq : payouts = old.rewritePayouts π new

/-- **A final leaf is never rewritten without its owner** (rule 3 at
`SEQ_FINAL`): a position whose old leaf has `seq = SEQ_FINAL`, is not
reclaimable, and whose element changes in any way, including a pure
amount increase, is authorised. -/
theorem rewrite_final_authorised {h : Nat} {π : Params} {auth : Pos h 0 → Prop} {lockTime : Nat}
    {r r' : Node H} {path : List (Bool × Node H)} {old new : Tree h} {out0 : Nat}
    {payouts : List Payout} (hr : Rewrite h π auth lockTime r path old new r' out0 payouts)
    (q : Pos h 0) (l : Leaf) (hl : old.get q = some l) (hfinal : l.seq = π.seqFinal)
    (hnr : ¬ π.Reclaimable l) (hne : new.get q ≠ some l) : auth q :=
  hr.authorised q l hl hne (fun ⟨_, _, _, _, hs⟩ => hs hfinal) hnr

/-- **An unsigned change of a leaf that is not reclaimable is an amount
increase on a non-final leaf.** Any such position whose old leaf changes
without its owner's authorisation keeps every other field, does not lose
amount, and was not at `SEQ_FINAL`: nobody can use the exemption to
rotate a key, shorten a lease, or touch a channel leaf. Rule 8 grants
no exemption to such a leaf, so this holds in the reclaim form too. -/
theorem rewrite_unsigned_change {h : Nat} {π : Params} {auth : Pos h 0 → Prop} {lockTime : Nat}
    {r r' : Node H} {path : List (Bool × Node H)} {old new : Tree h} {out0 : Nat}
    {payouts : List Payout} (hr : Rewrite h π auth lockTime r path old new r' out0 payouts)
    (q : Pos h 0) (l : Leaf) (hl : old.get q = some l) (hnr : ¬ π.Reclaimable l)
    (hne : new.get q ≠ some l) (hna : ¬ auth q) :
    ∃ new', new.get q = some new' ∧ new' = { l with amount := new'.amount } ∧
      l.amount ≤ new'.amount ∧ l.seq ≠ π.seqFinal := by
  by_cases he : l.AmountOnlyIncrease π (new.get q)
  · exact he
  · exact absurd (hr.authorised q l hl hne he hnr) hna

/-- **What a rewrite may do to a reclaimable leaf** (7.9 rule 8). A
changed position whose old leaf is reclaimable is one of three things:
an amount-only increase (rule 3); the even member of a pair whose
transfer the odd member absorbs exactly (`Tree.Transfer`); or a reclaim,
in which case the transaction's lock time has reached the leaf's
`evict_after`. No case needs the leaf's owner; a reclaim before the
deadline is impossible. -/
theorem rewrite_reclaimable_change {h : Nat} {π : Params} {auth : Pos h 0 → Prop}
    {lockTime : Nat} {r r' : Node H} {path : List (Bool × Node H)} {old new : Tree h}
    {out0 : Nat} {payouts : List Payout}
    (hr : Rewrite h π auth lockTime r path old new r' out0 payouts)
    (q : Pos h 0) (l : Leaf) (hl : old.get q = some l) (hrc : π.Reclaimable l)
    (hne : new.get q ≠ some l) :
    l.AmountOnlyIncrease π (new.get q) ∨
      (∃ c : Pos h 1, q = c.pairAt false ∧ old.Transfer π new c) ∨
      l.evictAfter ≤ lockTime := by
  by_cases ha : l.AmountOnlyIncrease π (new.get q)
  · exact Or.inl ha
  · by_cases ht : ∃ c : Pos h 1, q = c.pairAt false ∧ l.TransferShape π (new.get q)
    · obtain ⟨c, hq, hs⟩ := ht
      subst hq
      exact Or.inr (Or.inl ⟨c, rfl, hr.transfer c l hl hs⟩)
    · exact Or.inr (Or.inr (hr.deadline q l hl hne hrc ha ht))

/-- **A rewrite replaces exactly the published subtree.** The committed
tree held the old elements at the published positions, output 0 commits to
the tree with the new elements there, positions inside the subtree whose
element did not change keep it, every subtree of height `h` elsewhere is
untouched, the output amount moves by `Σ new − Σ old` (rule 6, stated
additively), and the payouts never exceed what left the tree. -/
theorem rewrite_sound {d h : Nat} {π : Params} {auth : Pos h 0 → Prop} {lockTime : Nat}
    (t : Tree d) (path : List (Bool × Node H)) (old new : Tree h) (r' : Node H) (out0 : Nat)
    (payouts : List Payout) (hwf : path.length + h = d)
    (hr : Rewrite h π auth lockTime t.root path old new r' out0 payouts) :
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
      rw [hr.payouts_eq]; exact Tree.rewritePayouts_le π old new
    refine ⟨p, hu, hnew new rfl, fun q => ⟨?_, ?_⟩, fun q hq => ?_, ?_, ?_⟩
    · rw [Tree.get_append, hu]
    · rw [Tree.get_append, Tree.getSub_setSub]
    · exact Tree.getSub_setSub_ne t p q new (Ne.symm hq)
    · rw [hr.out0_eq, Tree.root_sum t]; omega
    · rw [hr.out0_eq, Tree.root_sum t]; omega

/-- **A transfer moves value only into the reclaimable leaf's own
sibling** (7.9 rule 8, the transfer exemption). If the even member of
pair `c` in a rewrite has the transfer shape (a reclaimable leaf whose
amount alone falls), then in the committed tree that member held the
reclaimable leaf `l` and the odd member a leaf `m` that is not
reclaimable and is owned by `l`'s exit key; afterwards the even member
holds `l` with the lower amount and every other field unchanged, the
odd member holds `m` raised by exactly the decrease, and the pair's
total is unchanged. -/
theorem rewrite_transfer_sound {d h : Nat} {π : Params} {auth : Pos h 0 → Prop}
    {lockTime : Nat} (t : Tree d) (path : List (Bool × Node H)) (old new : Tree h) (r' : Node H)
    (out0 : Nat) (payouts : List Payout) (hwf : path.length + h = d)
    (hr : Rewrite h π auth lockTime t.root path old new r' out0 payouts) (c : Pos h 1) (l : Leaf)
    (hl : old.get (c.pairAt false) = some l) (hs : l.TransferShape π (new.get (c.pairAt false))) :
    ∃ (p : Pos d h) (l' m : Leaf),
      r' = (t.setSub p new).root ∧
      t.get (p.append (c.pairAt false)) = some l ∧ t.get (p.append (c.pairAt true)) = some m ∧
      (t.setSub p new).get (p.append (c.pairAt false)) = some l' ∧
      (t.setSub p new).get (p.append (c.pairAt true)) =
        some { m with amount := m.amount + (l.amount - l'.amount) } ∧
      π.Reclaimable l ∧ ¬ π.Reclaimable m ∧ m.ownerKey = l.exitKey ∧
      l' = { l with amount := l'.amount } ∧ l'.amount < l.amount ∧
      l'.amount + (m.amount + (l.amount - l'.amount)) = l.amount + m.amount := by
  obtain ⟨p, _, hr', hq, _⟩ := rewrite_sound t path old new r' out0 payouts hwf hr
  obtain ⟨l₀, l', m, hl₀, hl', hrc, hbody, hlt, hm, hnr, hown, hm'⟩ := hr.transfer c l hl hs
  rw [hl] at hl₀
  cases hl₀
  refine ⟨p, l', m, hr', ?_, ?_, ?_, ?_, hrc, hnr, hown, hbody, hlt, by omega⟩
  · rw [(hq _).1, hl]
  · rw [(hq _).1, hm]
  · rw [(hq _).2, hl']
  · rw [(hq _).2, hm']

/-- **Conservation of a rewrite with several exits.** Whatever mix of
exits, reclaims, joins, resizes and unchanged positions a rewrite
carries, output 0 plus the payouts (one per position that exits,
`rewritePayouts`) plus the reclaimed amounts (rule 8, free for the
transaction) plus the old amounts of the positions that keep a leaf
equals the input amount plus the new subtree's total. With no kept
positions this is `rewrite_exit_conservation`; with no exits it is rule
6. In a tree without `RECLAIM_KEY` the reclaimed amount is zero
(`Tree.reclaimedTotal_none`). -/
theorem rewrite_payout_conservation {h : Nat} {π : Params} {auth : Pos h 0 → Prop}
    {lockTime : Nat} {r r' : Node H} {path : List (Bool × Node H)} {old new : Tree h}
    {out0 : Nat} {payouts : List Payout}
    (hr : Rewrite h π auth lockTime r path old new r' out0 payouts) :
    out0 + payoutTotal payouts + old.reclaimedTotal π new + old.keptTotal new =
      r.sum + new.total := by
  have hs := hr.steps.sum
  simp only [oldSum, newSum, Tree.root_sum] at hs
  have hp := Tree.rewritePayouts_add_kept π old new
  rw [← hr.payouts_eq] at hp
  rw [hr.out0_eq]; omega

/-- **Exit-only rewrites conserve exactly.** When no new element is a leaf
(the new subtree is empty) every old leaf is paid or reclaimed, and
output 0 plus the payouts plus the reclaimed amounts equals the input
amount: the statement of `ExitK.exact_conservation` for a whole cohort
at once, the reclaimed amounts being zero without `RECLAIM_KEY`. Needs
no tree: `Steps.sum` holds for any step list. -/
theorem rewrite_exit_conservation {h : Nat} {π : Params} {auth : Pos h 0 → Prop}
    {lockTime : Nat} {r r' : Node H} {path : List (Bool × Node H)} {old : Tree h} {out0 : Nat}
    {payouts : List Payout}
    (hr : Rewrite h π auth lockTime r path old (Tree.empty h) r' out0 payouts) :
    out0 + payoutTotal payouts + old.reclaimedTotal π (Tree.empty h) = r.sum := by
  have hs := hr.steps.sum
  simp only [oldSum, newSum, Tree.root_sum] at hs
  have hp := Tree.rewritePayouts_empty π old
  rw [← hr.payouts_eq] at hp
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

/-! ## CLAIM^m (section 7.5.4) and RECLAIM_1 (section 7.11)

The pending-leaf receive of `design/pending-receive.md` adds two
single-step transitions. `CLAIM^m` (and `CLAIM^hm`, the same with a
payment hash) moves value from a source leaf into its *sibling*, raising
the sibling to an absolute amount `X`; the step is the pair's node at
height 1, so it is one `Step` of height 1 whose old and new nodes are the
roots of two published pairs. `RECLAIM_1` removes a reclaimable leaf after
its deadline with no payout. As elsewhere, signatures and the payment
hash are an opaque `auth`; the lock time of `RECLAIM_1` is a parameter,
since the claim "only after the deadline" is about it. -/

/-- The source after a merge that draws `δ` (7.5.4 rule 4): the amount
lowered by `δ` and every other field, `seq` included, unchanged; `E_0`
when drained. Unlike `claimedSource`, the body survives. -/
def mergedSource (src : Leaf) (δ : Nat) : Option Leaf :=
  if src.amount = δ then none else some { src with amount := src.amount - δ }

/-- The merged source and the draw add up to the source. -/
theorem mergedSource_total (src : Leaf) (δ : Nat) (hδ : δ ≤ src.amount) :
    (Tree.tip (mergedSource src δ)).total + δ = src.amount := by
  unfold mergedSource
  split
  · simp [Tree.total]; omega
  · simp [Tree.total]; omega

/-- The rules of 7.5.4 that relate the source `src`, the target `tgt` and
the target amount `X`, signatures aside: the target is owned by the
source's exit key (rule 2), neither leaf is at `SEQ_FINAL` (rule 2), the
target is not reclaimable (rule 2, vacuous without `RECLAIM_KEY`), the
draw `δ = X − tgt.amount` is at least 1 (rule 3) and fits in the source,
and the source's residual is zero or at least `DUST_MIN` (rule 3). That
the target is the source's *sibling* is not a field: it is the shape of
the step (one pair node at height 1). -/
structure MergeOk (π : Params) (src tgt : Leaf) (X : Nat) : Prop where
  owner_eq : tgt.ownerKey = src.exitKey
  src_not_final : src.seq ≠ π.seqFinal
  tgt_not_final : tgt.seq ≠ π.seqFinal
  tgt_not_reclaimable : ¬ π.Reclaimable tgt
  raise : tgt.amount < X
  draw_le : X - tgt.amount ≤ src.amount
  residual_dust : X - tgt.amount = src.amount ∨ π.dustMin ≤ src.amount - (X - tgt.amount)

/-- The tree after a merge at the pair `c`, source on side `b`: the source
lowered by the draw, then the target raised to `X`. -/
def mergeTree {d : Nat} (t : Tree d) (c : Pos d 1) (b : Bool) (src tgt : Leaf) (X : Nat) :
    Tree d :=
  (t.set (c.pairAt b) (mergedSource src (X - tgt.amount))).set (c.pairAt (!b))
    (some { tgt with amount := X })

/-- What `CLAIM^m` accepts (7.5.4): one step at height 1 whose old node is
the pair holding `src` on side `b` and `tgt` on the other, and whose new
node is the pair with the merged source and the target raised to `X`
(rules 4 and 5); output 0 carries the new sum; `MergeOk`; and the
voucher signature by `src.owner_key` over `tree_id`, both bodies and `X`
(and, for `CLAIM^hm`, the preimage check) as `auth`. -/
structure Merge (auth : Prop) (π : Params) (r : Node H) (path : List (Bool × Node H)) (b : Bool)
    (src tgt : Leaf) (X : Nat) (r' : Node H) (out0 : Nat) : Prop where
  ok : MergeOk π src tgt X
  steps : Steps r [Step.mk 1 path (Tree.pair b (some src) (some tgt)).root
    (Tree.pair b (mergedSource src (X - tgt.amount)) (some { tgt with amount := X })).root] r'
  out0_eq : out0 = r'.sum
  authorised : auth

/-- The sum of a pair is the sum of its members. -/
theorem Tree.pair_total (b : Bool) (s o : Option Leaf) :
    (Tree.pair b s o).total = (Tree.tip s).total + (Tree.tip o).total := by
  cases b <;> simp [Tree.pair, Tree.total] <;> omega

/-- **A merge moves value only into the source's sibling, owned by the
source's exit key** (7.5.4). Output 0 carries the input amount
unchanged; the pair's total is conserved; the source position held
`src` and its sibling held `tgt`, owned by `src.exit_key` and raised to
exactly `X`, above its old amount; the source keeps every field but its
amount (or becomes `E_0` when drained); the target changes in amount
only; and every other position is untouched. -/
theorem merge_sound {auth : Prop} {π : Params} {d : Nat} (t : Tree d) (path : List (Bool × Node H))
    (b : Bool) (src tgt : Leaf) (X : Nat) (r' : Node H) (out0 : Nat) (hwf : path.length + 1 = d)
    (hm : Merge auth π t.root path b src tgt X r' out0) :
    out0 = t.root.sum ∧ tgt.ownerKey = src.exitKey ∧ tgt.amount < X ∧
    (Tree.tip (mergedSource src (X - tgt.amount))).total + X = src.amount + tgt.amount ∧
    ∃ c : Pos d 1, t.get (c.pairAt b) = some src ∧ t.get (c.pairAt (!b)) = some tgt ∧
      r' = (mergeTree t c b src tgt X).root ∧
      (mergeTree t c b src tgt X).get (c.pairAt b) = mergedSource src (X - tgt.amount) ∧
      (mergeTree t c b src tgt X).get (c.pairAt (!b)) = some { tgt with amount := X } ∧
      ∀ q : Pos d 0, q ≠ c.pairAt b → q ≠ c.pairAt (!b) →
        (mergeTree t c b src tgt X).get q = t.get q := by
  have hok := hm.ok
  have hcons : (Tree.tip (mergedSource src (X - tgt.amount))).total + X =
      src.amount + tgt.amount := by
    have := mergedSource_total src (X - tgt.amount) hok.draw_le
    have := hok.raise
    omega
  cases hm.steps with
  | cons hv hrest =>
    cases hrest
    obtain ⟨c, hold, hnew⟩ := Step.sound t (Step.mk 1 path (Tree.pair b (some src) (some tgt)).root
      (Tree.pair b (mergedSource src (X - tgt.amount)) (some { tgt with amount := X })).root)
      r' hwf hv
    have hu : t.getSub c = Tree.pair b (some src) (some tgt) := (Tree.root_inj _ _ hold).symm
    obtain ⟨hs, ht⟩ := Tree.get_pair t c b _ _ hu
    have hr' := hnew _ rfl
    rw [Tree.setSub_pair] at hr'
    have hsum : r'.sum + (Tree.pair b (some src) (some tgt)).root.sum =
        t.root.sum + (Tree.pair b (mergedSource src (X - tgt.amount))
          (some { tgt with amount := X })).root.sum := Step.sum _ _ _ hv
    rw [Tree.root_sum (Tree.pair b _ _), Tree.root_sum (Tree.pair b _ _), Tree.pair_total,
      Tree.pair_total] at hsum
    have hne := Pos.pairAt_ne c b
    refine ⟨?_, hok.owner_eq, hok.raise, hcons, c, hs, ht, hr', ?_, ?_, ?_⟩
    · rw [hm.out0_eq]
      have e1 : (Tree.tip (some src)).total = src.amount := rfl
      have e2 : (Tree.tip (some tgt)).total = tgt.amount := rfl
      have e3 : (Tree.tip (some { tgt with amount := X })).total = X := rfl
      rw [e1, e2, e3] at hsum
      omega
    · unfold mergeTree
      rw [Tree.get_set_ne _ _ _ _ (Ne.symm hne), Tree.get_set]
    · unfold mergeTree; rw [Tree.get_set]
    · intro q hq₁ hq₂
      unfold mergeTree
      rw [Tree.get_set_ne _ _ _ _ (Ne.symm hq₂), Tree.get_set_ne _ _ _ _ (Ne.symm hq₁)]

/-- What `RECLAIM_1` accepts (7.11): the leaf is reclaimable (rule 1),
the transaction's lock time has reached its `evict_after` (rule 2), one
leaf-level step to `E_0` with output 0 carrying the new sum (rule 4),
and the signature by `RECLAIM_KEY` as `auth` (rule 3). No output is
constrained for the leaf's value. -/
structure Reclaim (auth : Prop) (π : Params) (lockTime : Nat) (r : Node H)
    (path : List (Bool × Node H)) (l : Leaf) (r' : Node H) (out0 : Nat) : Prop where
  reclaimable : π.Reclaimable l
  deadline : l.evictAfter ≤ lockTime
  step : (leafStep path (some l) none).valid r r'
  out0_eq : out0 = r'.sum
  authorised : auth

/-- **A reclaim removes one reclaimable leaf past its deadline** (7.11).
The position held the leaf, the leaf is reclaimable and its deadline has
passed, output 0 commits to the tree without it and carries the input
amount less the leaf's, and every other position is untouched. -/
theorem reclaim_sound {auth : Prop} {π : Params} {lockTime d : Nat} (t : Tree d)
    (path : List (Bool × Node H)) (l : Leaf) (r' : Node H) (out0 : Nat) (hwf : path.length = d)
    (hc : Reclaim auth π lockTime t.root path l r' out0) :
    ∃ p : Pos d 0, t.get p = some l ∧ π.Reclaimable l ∧ l.evictAfter ≤ lockTime ∧
      r' = (t.set p none).root ∧ (∀ q : Pos d 0, q ≠ p → (t.set p none).get q = t.get q) ∧
      out0 + l.amount = t.root.sum := by
  obtain ⟨p, hget, hr'⟩ := leafStep_sound t path (some l) none r'
    (by simp [Step.WF, leafStep, hwf]) hc.step
  refine ⟨p, hget, hc.reclaimable, hc.deadline, hr', fun q hq => Tree.get_set_ne t p q none
    (Ne.symm hq), ?_⟩
  have hs := Step.sum _ _ _ hc.step
  simp [leafStep] at hs
  rw [hc.out0_eq]; omega

/-- **Only a reclaimable leaf is ever reclaimed.** Every leaf of the
committed tree that is not reclaimable is in the tree output 0 commits
to, at the same position, and a tree without `RECLAIM_KEY` has no
accepted `RECLAIM_1` at all. -/
theorem reclaim_only_flagged {auth : Prop} {π : Params} {lockTime d : Nat} (t : Tree d)
    (path : List (Bool × Node H)) (l : Leaf) (r' : Node H) (out0 : Nat) (hwf : path.length = d)
    (hc : Reclaim auth π lockTime t.root path l r' out0) :
    π.reclaimKey ≠ none ∧
    ∃ p : Pos d 0, r' = (t.set p none).root ∧
      ∀ (q : Pos d 0) (l' : Leaf), t.get q = some l' → ¬ π.Reclaimable l' →
        (t.set p none).get q = some l' := by
  obtain ⟨p, hget, hrc, _, hr', hother, _⟩ := reclaim_sound t path l r' out0 hwf hc
  refine ⟨fun hn => Params.not_reclaimable hn l hrc, p, hr', fun q l' hq hnr => ?_⟩
  have hqp : q ≠ p := by
    intro hqp; subst hqp
    rw [hget] at hq; cases hq; exact hnr hrc
  rw [hother q hqp, hq]

end LayerTree
