import LayerTree.Cohort

/-!
# Traces

`Transitions.lean` and `Cohort.lean` prove each transition sound in
isolation: an accepted spend from the root of a tree `t` commits to the
root of a specific tree `t'`. This module composes those results along
a whole history of the tree output and proves the invariants the
specification claims for every reachable state.

## Two levels

* **Tree level.** A `Trans d` is a transition record in the tree's own
  vocabulary: positions, leaves and published subtrees rather than
  sibling paths and nodes. `Trans.apply` is the tree it produces and
  `Trans.Pre` the conditions the script enforces on the tree it is applied
  to (the source leaf is there, the claim position is empty after the
  source step, the carve rule, and so on). `Reachable t xs t'` chains
  records from `t` to `t'`.
* **Chain level.** `Accepts d r r'` says that one of the script relations
  accepts a spend of a tree output with root `r` producing output 0 with
  root `r'`, and `Chain r r'` chains those. `Accepts.sound` and
  `Chain.sound` are the bridge: whatever the chain accepts from the root
  of a real tree is the root of a tree reachable at the tree level, so
  every invariant proved on `Reachable` holds of every on-chain state.

## The invariants

* `Reachable.ledger`: the total moves by exactly what the records removed
  and added. Payouts are bounded by what was removed in the per-transition
  theorems (`ExitK.no_inflation`, `rewrite_sound`, `evictSubtree_sound`).
* `Reachable.all`: a property of leaves that the admitted leaves satisfy,
  that the carve rule preserves and that survives the source rewrite of a
  claim holds of every leaf in every reachable tree. Three instances:
  well-formedness (`Reachable.wf`), evictability by one key by one height
  (`Reachable.evictable`, the tree-level consequence of 7.5 rule 5), and a
  `seq` lower bound on one leaf identity (`Reachable.seqAbove`, which
  `Voucher.lean` turns into non-replay).
* `chain_state`: every on-chain root is the root of a real tree whose
  total is the committed sum and whose every leaf has an accepted `EXIT`.

A position holds at most one leaf by construction (`Tree.get` returns an
`Option Leaf`), so "no position holds two leaves" is not a theorem but
the shape of the type.
-/

namespace LayerTree

variable {H : Type} [M : HashModel Leaf H]

/-! ## Transition records -/

/-- A transition in the tree's own vocabulary. `claim` and `split` are
the same rewrite under different authorisation (7.5.2), so they share
every premise and differ only as records. -/
inductive Trans (d : Nat) : Type
  /-- `EXIT` of the leaf `l` at `p` (7.2). -/
  | exit (p : Pos d 0) (l : Leaf)
  /-- `JOIN_h` of the subtree `u` at `p` (7.3). -/
  | join {h : Nat} (p : Pos d h) (u : Tree h)
  /-- `UPDATE` of `old` to `new` at `p` (7.4). -/
  | update (p : Pos d 0) (old new : Leaf)
  /-- `CLAIM` or `CLAIM^h` of `claim` out of `src` at `p₁`, placed at `p₂` (7.5). -/
  | claim (p₁ p₂ : Pos d 0) (src claim : Leaf)
  /-- `SPLIT`, the owner-authorised carve (7.5.2). -/
  | split (p₁ p₂ : Pos d 0) (src claim : Leaf)
  /-- `EVICT_SUBTREE_h` of the subtree at `p` (7.7). -/
  | evictSubtree {h : Nat} (p : Pos d h)
  /-- `REWRITE_h` of the subtree at `p` to `new` (7.9). -/
  | rewrite {h : Nat} (p : Pos d h) (new : Tree h)
  /-- `DETACH_h` of the subtree at `p`; this is the parent's side, output 0 (7.10). -/
  | detach {h : Nat} (p : Pos d h)

/-- The carve rules of 7.5 (2 and 5) between a source and a claim leaf:
the amount fits, the source `seq` can advance, and the claim leaf keeps
the evictor and a lease no later than the source's. -/
structure CarveOk (seqFinal : Nat) (src claim : Leaf) : Prop where
  amount_le : claim.amount ≤ src.amount
  seq_lt : src.seq < seqFinal
  evictorKey_eq : claim.evictorKey = src.evictorKey
  evictAfter_le : claim.evictAfter ≤ src.evictAfter

/-- The tree after a carve: the source rewritten, then the claim leaf
placed. -/
def carveTree {d : Nat} (t : Tree d) (p₁ p₂ : Pos d 0) (src claim : Leaf) : Tree d :=
  (t.set p₁ (claimedSource src claim.amount)).set p₂ (some claim)

/-- What a carve needs of the tree: the source leaf at `p₁`, the carve
rules, and the claim position empty after the source step (`claim_sound`). -/
structure CarvePre (seqFinal : Nat) {d : Nat} (t : Tree d) (p₁ p₂ : Pos d 0) (src claim : Leaf) :
    Prop where
  src_at : t.get p₁ = some src
  ok : CarveOk seqFinal src claim
  claim_empty : (t.set p₁ (claimedSource src claim.amount)).get p₂ = none

namespace Trans

/-- The tree a record produces. Every transition's result is a function
of the record and the current tree; `Pre` says when the script accepts
it. -/
def apply : {d : Nat} → Trans d → Tree d → Tree d
  | _, .exit p _, t => t.set p none
  | _, .join p u, t => t.setSub p u
  | _, .update p _ new, t => t.set p (some new)
  | _, .claim p₁ p₂ src c, t => carveTree t p₁ p₂ src c
  | _, .split p₁ p₂ src c, t => carveTree t p₁ p₂ src c
  | _, .evictSubtree p, t => t.setSub p (Tree.empty _)
  | _, .rewrite p new, t => t.setSub p new
  | _, .detach p, t => t.setSub p (Tree.empty _)

/-- The conditions the script enforces on the current tree. Signatures and
lock times are not among them (they are opaque in the model); these are
the Merkle-sum facts `claim_sound`, `join_sound` and the other soundness
theorems deliver. A sweep, rewrite or detach has none: the published
subtree is the subtree at `p` by `root_inj`. -/
def Pre (seqFinal : Nat) : {d : Nat} → Trans d → Tree d → Prop
  | _, .exit p l, t => t.get p = some l
  | _, .join p _, t => t.getSub p = Tree.empty _
  | _, .update p old _, t => t.get p = some old
  | _, .claim p₁ p₂ src c, t => CarvePre seqFinal t p₁ p₂ src c
  | _, .split p₁ p₂ src c, t => CarvePre seqFinal t p₁ p₂ src c
  | _, .evictSubtree _, _ => True
  | _, .rewrite _ _, _ => True
  | _, .detach _, _ => True

/-- The leaf amounts a record takes out of the tree. -/
def removed : {d : Nat} → Trans d → Tree d → Nat
  | _, .exit _ l, _ => l.amount
  | _, .join _ _, _ => 0
  | _, .update _ old _, _ => old.amount
  | _, .claim _ _ _ _, _ => 0
  | _, .split _ _ _ _, _ => 0
  | _, .evictSubtree p, t => (t.getSub p).total
  | _, .rewrite p _, t => (t.getSub p).total
  | _, .detach p, t => (t.getSub p).total

/-- The leaf amounts a record brings into the tree. -/
def added : {d : Nat} → Trans d → Tree d → Nat
  | _, .exit _ _, _ => 0
  | _, .join _ u, _ => u.total
  | _, .update _ _ new, _ => new.amount
  | _, .claim _ _ _ _, _ => 0
  | _, .split _ _ _ _, _ => 0
  | _, .evictSubtree _, _ => 0
  | _, .rewrite _ new, _ => new.total
  | _, .detach _, _ => 0

/-- `P` holds of every leaf a record admits on the operator's or owner's
authority: the grafted subtree of a join, the new leaf of an update, the
new elements of a rewrite. Carve leaves are separate (`CarveLeaf`),
because the carve rule constrains them relative to the source. -/
def Admits (P : Leaf → Prop) : {d : Nat} → Trans d → Prop
  | _, .join _ u => ∀ q l, u.get q = some l → P l
  | _, .update _ _ new => P new
  | _, .rewrite _ new => ∀ q l, new.get q = some l → P l
  | _, _ => True

/-- `P` holds of the claim leaf of a carve. -/
def CarveLeaf (P : Leaf → Prop) : {d : Nat} → Trans d → Prop
  | _, .claim _ _ _ c => P c
  | _, .split _ _ _ c => P c
  | _, _ => True

end Trans

/-- `P` holds of every leaf in the tree. -/
def Tree.All (P : Leaf → Prop) {d : Nat} (t : Tree d) : Prop :=
  ∀ (q : Pos d 0) (l : Leaf), t.get q = some l → P l

/-! ## Reachability -/

/-- `Reachable seqFinal t xs t'`: the records `xs` apply in order from `t`
to `t'`, each accepted by the script on the tree it meets. -/
inductive Reachable (seqFinal : Nat) {d : Nat} : Tree d → List (Trans d) → Tree d → Prop
  | nil (t : Tree d) : Reachable seqFinal t [] t
  | cons {t t' : Tree d} {x : Trans d} {xs : List (Trans d)} :
      x.Pre seqFinal t → Reachable seqFinal (x.apply t) xs t' → Reachable seqFinal t (x :: xs) t'

theorem Reachable.append {seqFinal : Nat} {d : Nat} {t t₁ t₂ : Tree d}
    {xs ys : List (Trans d)} (h₁ : Reachable seqFinal t xs t₁) (h₂ : Reachable seqFinal t₁ ys t₂) :
    Reachable seqFinal t (xs ++ ys) t₂ := by
  induction h₁ with
  | nil => simpa using h₂
  | cons hpre _ ih => exact Reachable.cons hpre (ih h₂)

/-! ## Supporting tree lemmas -/

namespace Tree

/-- A leaf position holding `o` is the subtree `tip o`, so its total is
`o`'s amount. -/
theorem total_getSub_of_get {d : Nat} (t : Tree d) (p : Pos d 0) (o : Option Leaf)
    (h : t.get p = o) : (t.getSub p).total = (tip o).total := by
  unfold get at h
  revert h
  generalize t.getSub p = s
  cases s with
  | tip o' => intro h; simp only at h; rw [h]

theorem total_empty (h : Nat) : (empty h).total = 0 := by
  induction h with
  | zero => rfl
  | succ h ih => simp [empty, total, ih]

/-- Replacing the subtree at `p` by `u` moves the total by `u`'s total
less the old subtree's. Stated additively. Hash-free: this is the
structural half of `Step.sum`. -/
theorem total_setSub {d h : Nat} (t : Tree d) (p : Pos d h) (u : Tree h) :
    (t.setSub p u).total + (t.getSub p).total = t.total + u.total := by
  induction p with
  | nil => simp [setSub, getSub]; omega
  | cons b p ih =>
    cases t with
    | bin l r =>
      cases b
      · have := ih l u; simp [setSub, getSub, total]; omega
      · have := ih r u; simp [setSub, getSub, total]; omega

theorem total_set {d : Nat} (t : Tree d) (p : Pos d 0) (o : Option Leaf) :
    (t.set p o).total + (t.getSub p).total = t.total + (tip o).total :=
  total_setSub t p (tip o)

/-- The leaf at `q` after replacing the subtree at `p`: `u`'s leaf when `q`
is inside `p`, the old leaf otherwise. The hash-free half of
`path_maintenance`. -/
theorem get_setSub_cases {d h : Nat} (t : Tree d) (p : Pos d h) (u : Tree h) (q : Pos d 0) :
    (∃ q' : Pos h 0, q = p.append q' ∧ (t.setSub p u).get q = u.get q') ∨
    (t.setSub p u).get q = t.get q := by
  rcases Pos.fork p q with ⟨q', hq⟩ | ⟨k, c, b, p', q', hp, hq⟩
  · exact Or.inl ⟨q', hq, by rw [hq, get_append, getSub_setSub]⟩
  · right
    subst hp; subst hq
    rw [setSub_append, get_append, get_append, getSub_setSub]
    generalize t.getSub c = v
    cases v with
    | bin l r => cases b <;> simp [setSub, get, getSub]

end Tree

/-- The source leaf after a carve, as a leaf position: its amount plus the
carved amount is the source's. Hash-free form of `claimedSource_amount`. -/
theorem claimedSource_total (src : Leaf) (v : Nat) (hv : v ≤ src.amount) :
    (Tree.tip (claimedSource src v)).total + v = src.amount := by
  unfold claimedSource
  split
  · simp [Tree.total]; omega
  · simp [Tree.total]; omega

/-! ## The ledger -/

namespace Trans

/-- **One step of the ledger**: the total after a record is the total
before, less what it removed, plus what it added. -/
theorem apply_total {seqFinal : Nat} {d : Nat} (x : Trans d) (t : Tree d)
    (hpre : x.Pre seqFinal t) :
    (x.apply t).total + x.removed t = t.total + x.added t := by
  cases x with
  | exit p l =>
    have h := Tree.total_set t p none
    have h' := Tree.total_getSub_of_get t p (some l) hpre
    simp only [apply, removed, added, Tree.total] at *
    omega
  | join p u =>
    have h := Tree.total_setSub t p u
    have he : (t.getSub p).total = 0 := by
      simp only [Pre] at hpre
      rw [hpre]; exact Tree.total_empty _
    simp only [apply, removed, added] at *
    omega
  | update p old new =>
    have h := Tree.total_set t p (some new)
    have h' := Tree.total_getSub_of_get t p (some old) hpre
    simp only [apply, removed, added, Tree.total] at *
    omega
  | claim p₁ p₂ src c =>
    have h₁ := Tree.total_set t p₁ (claimedSource src c.amount)
    have h₁' := Tree.total_getSub_of_get t p₁ (some src) hpre.src_at
    have h₂ := Tree.total_set (t.set p₁ (claimedSource src c.amount)) p₂ (some c)
    have h₂' := Tree.total_getSub_of_get _ p₂ none hpre.claim_empty
    have hc := claimedSource_total src c.amount hpre.ok.amount_le
    simp only [apply, carveTree, removed, added, Tree.total] at *
    omega
  | split p₁ p₂ src c =>
    have h₁ := Tree.total_set t p₁ (claimedSource src c.amount)
    have h₁' := Tree.total_getSub_of_get t p₁ (some src) hpre.src_at
    have h₂ := Tree.total_set (t.set p₁ (claimedSource src c.amount)) p₂ (some c)
    have h₂' := Tree.total_getSub_of_get _ p₂ none hpre.claim_empty
    have hc := claimedSource_total src c.amount hpre.ok.amount_le
    simp only [apply, carveTree, removed, added, Tree.total] at *
    omega
  | @evictSubtree k p =>
    have h := Tree.total_setSub t p (Tree.empty _)
    have he := Tree.total_empty k
    simp only [apply, removed, added] at *
    omega
  | rewrite p new =>
    have h := Tree.total_setSub t p new
    simp only [apply, removed, added] at *
    omega
  | @detach k p =>
    have h := Tree.total_setSub t p (Tree.empty _)
    have he := Tree.total_empty k
    simp only [apply, removed, added] at *
    omega

end Trans

/-- The amounts a trace removes, applied in order from `t`. -/
def removedSum {d : Nat} : List (Trans d) → Tree d → Nat
  | [], _ => 0
  | x :: xs, t => x.removed t + removedSum xs (x.apply t)

/-- The amounts a trace adds, applied in order from `t`. -/
def addedSum {d : Nat} : List (Trans d) → Tree d → Nat
  | [], _ => 0
  | x :: xs, t => x.added t + addedSum xs (x.apply t)

/-- **The ledger along a trace**: the final total plus everything removed
equals the initial total plus everything added. Value leaves the tree
only through the amounts the records remove (exits, evictions, the
decrease of an update, a detached cohort) and enters only through what
they add (joins, the increase of an update, the new elements of a
rewrite); carves move nothing in or out. -/
theorem Reachable.ledger {seqFinal : Nat} {d : Nat} {t t' : Tree d} {xs : List (Trans d)}
    (h : Reachable seqFinal t xs t') : t'.total + removedSum xs t = t.total + addedSum xs t := by
  induction h with
  | nil => simp [removedSum, addedSum]
  | cons hpre _ ih =>
    have := Trans.apply_total _ _ hpre
    simp only [removedSum, addedSum]
    omega

/-! ## Leaf predicates along a trace -/

/-- **One step preserves a leaf predicate.** If `P` holds of every leaf
of `t`, of every leaf the record admits, of its carve leaf, and survives
the source rewrite of a carve (amount reduced, `seq` advanced), then `P`
holds of every leaf of the tree the record produces. -/
theorem Trans.apply_all (P : Leaf → Prop) {seqFinal : Nat} {d : Nat} (x : Trans d) (t : Tree d)
    (hpre : x.Pre seqFinal t) (ht : t.All P) (hadm : x.Admits P) (hcarve : x.CarveLeaf P)
    (hsrc : ∀ (src : Leaf) (v : Nat), v ≤ src.amount → src.seq < seqFinal → P src →
      ∀ l, claimedSource src v = some l → P l) :
    (x.apply t).All P := by
  intro q l hq
  cases x with
  | exit p l' =>
    simp only [Trans.apply] at hq
    by_cases hqp : q = p
    · subst hqp; rw [Tree.get_set] at hq; cases hq
    · rw [Tree.get_set_ne t p q none (Ne.symm hqp)] at hq; exact ht q l hq
  | join p u =>
    simp only [Trans.apply] at hq
    rcases Tree.get_setSub_cases t p u q with ⟨q', _, hg⟩ | hg
    · rw [hg] at hq; exact hadm q' l hq
    · rw [hg] at hq; exact ht q l hq
  | update p old new =>
    simp only [Trans.apply] at hq
    by_cases hqp : q = p
    · subst hqp; rw [Tree.get_set] at hq; rw [← Option.some.inj hq]; exact hadm
    · rw [Tree.get_set_ne t p q _ (Ne.symm hqp)] at hq; exact ht q l hq
  | claim p₁ p₂ src c =>
    simp only [Trans.apply, carveTree] at hq
    by_cases hq₂ : q = p₂
    · subst hq₂; rw [Tree.get_set] at hq; rw [← Option.some.inj hq]; exact hcarve
    · rw [Tree.get_set_ne _ p₂ q _ (Ne.symm hq₂)] at hq
      by_cases hq₁ : q = p₁
      · subst hq₁; rw [Tree.get_set] at hq
        exact hsrc src c.amount hpre.ok.amount_le hpre.ok.seq_lt (ht q src hpre.src_at) l hq
      · rw [Tree.get_set_ne t p₁ q _ (Ne.symm hq₁)] at hq; exact ht q l hq
  | split p₁ p₂ src c =>
    simp only [Trans.apply, carveTree] at hq
    by_cases hq₂ : q = p₂
    · subst hq₂; rw [Tree.get_set] at hq; rw [← Option.some.inj hq]; exact hcarve
    · rw [Tree.get_set_ne _ p₂ q _ (Ne.symm hq₂)] at hq
      by_cases hq₁ : q = p₁
      · subst hq₁; rw [Tree.get_set] at hq
        exact hsrc src c.amount hpre.ok.amount_le hpre.ok.seq_lt (ht q src hpre.src_at) l hq
      · rw [Tree.get_set_ne t p₁ q _ (Ne.symm hq₁)] at hq; exact ht q l hq
  | @evictSubtree k p =>
    simp only [Trans.apply] at hq
    rcases Tree.get_setSub_cases t p (Tree.empty _) q with ⟨q', _, hg⟩ | hg
    · rw [hg, Tree.get_empty] at hq; cases hq
    · rw [hg] at hq; exact ht q l hq
  | rewrite p new =>
    simp only [Trans.apply] at hq
    rcases Tree.get_setSub_cases t p new q with ⟨q', _, hg⟩ | hg
    · rw [hg] at hq; exact hadm q' l hq
    · rw [hg] at hq; exact ht q l hq
  | @detach k p =>
    simp only [Trans.apply] at hq
    rcases Tree.get_setSub_cases t p (Tree.empty _) q with ⟨q', _, hg⟩ | hg
    · rw [hg, Tree.get_empty] at hq; cases hq
    · rw [hg] at hq; exact ht q l hq

/-- **A leaf predicate holds along a trace.** The carve-leaf hypothesis is
given the tree the record meets, so that an instance may derive it from
the carve rule and the source leaf (`Reachable.evictable`) rather than
assume it. -/
theorem Reachable.all (P : Leaf → Prop) {seqFinal : Nat} {d : Nat} {t t' : Tree d}
    {xs : List (Trans d)} (h : Reachable seqFinal t xs t') (ht : t.All P)
    (hadm : ∀ x ∈ xs, x.Admits P)
    (hcarve : ∀ x ∈ xs, ∀ u : Tree d, x.Pre seqFinal u → u.All P → x.CarveLeaf P)
    (hsrc : ∀ (src : Leaf) (v : Nat), v ≤ src.amount → src.seq < seqFinal → P src →
      ∀ l, claimedSource src v = some l → P l) :
    t'.All P := by
  induction h with
  | nil => exact ht
  | cons hpre _ ih =>
    exact ih (Trans.apply_all P _ _ hpre ht (hadm _ (by simp))
        (hcarve _ (by simp) _ hpre ht) hsrc)
      (fun x hx => hadm x (by simp [hx])) (fun x hx => hcarve x (by simp [hx]))

/-- **Well-formedness is preserved** (5.2) when every admitted leaf and
every carve leaf is well formed and the tier's `SEQ_FINAL` is below
`2^32`. The source rewrite of a carve keeps the bounds by itself: the
amount falls but stays positive (a drained source is `E_0`, not a leaf),
and `seq + 1` fits because `seq < SEQ_FINAL`. -/
theorem Reachable.wf {seqFinal : Nat} (hsf : seqFinal < 2 ^ 32) {d : Nat} {t t' : Tree d}
    {xs : List (Trans d)} (h : Reachable seqFinal t xs t') (ht : t.All Leaf.WF)
    (hadm : ∀ x ∈ xs, x.Admits Leaf.WF) (hcarve : ∀ x ∈ xs, x.CarveLeaf Leaf.WF) :
    t'.All Leaf.WF := by
  refine Reachable.all Leaf.WF h ht hadm (fun x hx _ _ _ => hcarve x hx) ?_
  intro src v hv hseq hwf l hl
  unfold claimedSource at hl
  split at hl
  · cases hl
  · rw [← Option.some.inj hl]
    exact { amount_pos := by simp; omega, amount_lt := by simp; have := hwf.amount_lt; omega,
            exitKey_lt := hwf.exitKey_lt, ownerKey_lt := hwf.ownerKey_lt,
            evictorKey_lt := hwf.evictorKey_lt, evictAfter_lt := hwf.evictAfter_lt,
            nonce_lt := hwf.nonce_lt, seq_lt := by simp; omega }

/-- A leaf is evictable by key `K` from height `T` on: its evictor is `K`
and its lease ends by `T`. These are the two facts the eviction branch
of `EXIT` and the sweep check (7.2 rule 4, 7.7 rule 2); with them the
`isEvict = true` block of `exit_available` is accepted once the lock
time reaches `T`. -/
def Leaf.EvictableBy (K T : Nat) (l : Leaf) : Prop := l.evictorKey = K ∧ l.evictAfter ≤ T

/-- **Evictability is a property of the tree, not of one leaf** (7.5 rule
5 at the tree level). If every leaf of `t` is evictable by `K` from `T`
and the operator admits only such leaves (joins, updates, rewrites), then
every leaf of every reachable tree is: carves cannot escape, because the
carve rule ties the claim leaf's evictor and lease to the source's, and
the source rewrite changes neither. No hypothesis is needed about carve
leaves. -/
theorem Reachable.evictable (K T : Nat) {seqFinal : Nat} {d : Nat} {t t' : Tree d}
    {xs : List (Trans d)} (h : Reachable seqFinal t xs t') (ht : t.All (Leaf.EvictableBy K T))
    (hadm : ∀ x ∈ xs, x.Admits (Leaf.EvictableBy K T)) :
    t'.All (Leaf.EvictableBy K T) := by
  refine Reachable.all (Leaf.EvictableBy K T) h ht hadm ?_ ?_
  · intro x _ u hpre hu
    cases x with
    | claim p₁ p₂ src c =>
      have hs := hu p₁ src hpre.src_at
      exact ⟨hpre.ok.evictorKey_eq.trans hs.1, Nat.le_trans hpre.ok.evictAfter_le hs.2⟩
    | split p₁ p₂ src c =>
      have hs := hu p₁ src hpre.src_at
      exact ⟨hpre.ok.evictorKey_eq.trans hs.1, Nat.le_trans hpre.ok.evictAfter_le hs.2⟩
    | _ => trivial
  · intro src v _ _ hs l hl
    unfold claimedSource at hl
    split at hl
    · cases hl
    · rw [← Option.some.inj hl]; exact hs

/-- A leaf with identity `(k, n)` has `seq` above `s`; any other leaf
satisfies it vacuously. -/
def Leaf.SeqAbove (k n s : Nat) (l : Leaf) : Prop := l.ownerKey = k → l.nonce = n → s < l.seq

/-- **A `seq` lower bound on one identity is preserved.** Carves raise the
source's `seq`, exits and evictions remove leaves, and the hypotheses say
nothing admitted or carved reintroduces the identity at or below `s`. -/
theorem Reachable.seqAbove (k n s : Nat) {seqFinal : Nat} {d : Nat} {t t' : Tree d}
    {xs : List (Trans d)} (h : Reachable seqFinal t xs t') (ht : t.All (Leaf.SeqAbove k n s))
    (hadm : ∀ x ∈ xs, x.Admits (Leaf.SeqAbove k n s))
    (hcarve : ∀ x ∈ xs, x.CarveLeaf (Leaf.SeqAbove k n s)) :
    t'.All (Leaf.SeqAbove k n s) := by
  refine Reachable.all (Leaf.SeqAbove k n s) h ht hadm
    (fun x hx _ _ _ => hcarve x hx) ?_
  intro src v _ _ hs l hl
  unfold claimedSource at hl
  split at hl
  · cases hl
  · rw [← Option.some.inj hl]
    intro hk hn
    simp only at hk hn ⊢
    have := hs hk hn
    omega

/-! ## The chain level -/

/-- One accepted spend of a tree output with root `r`, producing output 0
with root `r'`: one of the script relations of `Transitions.lean` and
`Cohort.lean`, with the path lengths the scripts fix (`LEVEL × (D − h)`).
A `JOIN_h` additionally needs the grafted node to have a preimage
(`Step.Grounded`); the discussion under `join_sound` says why that is the
joiners' obligation and not the covenant's. The terminal branch (7.8) is
included: `r' = E_D` is the root of the empty tree, and the trace simply
has no later step. -/
inductive Accepts (seqFinal d : Nat) : Node H → Node H → Prop
  | exit {exact : Bool} {r r' : Node H} {blocks : List (ExitBlock H)} {out0 : Nat}
      {terminal : Bool} (h : ExitKT exact d r blocks r' out0 terminal)
      (hwf : ∀ b ∈ blocks, b.step.WF d) : Accepts seqFinal d r r'
  | join {auth : Prop} {h : Nat} {r r' new : Node H} {path : List (Bool × Node H)} {out0 : Nat}
      (hj : Join auth h r path new r' out0) (hwf : path.length + h = d)
      (hg : ∃ u : Tree h, u.root = new) : Accepts seqFinal d r r'
  | update {auth : Prop} {r r' : Node H} {path : List (Bool × Node H)} {old new : Leaf}
      {out0 : Nat} (hu : Update auth r path old new r' out0) (hwf : path.length = d) :
      Accepts seqFinal d r r'
  | claim {auth : Prop} {r r' : Node H} {srcPath claimPath : List (Bool × Node H)}
      {src c : Leaf} {out0 : Nat} (hc : Claim auth seqFinal r srcPath claimPath src c r' out0)
      (hwf₁ : srcPath.length = d) (hwf₂ : claimPath.length = d) : Accepts seqFinal d r r'
  | evictSubtree {auth : Prop} {h : Nat} {r r' : Node H} {path : List (Bool × Node H)}
      {u : Tree h} {out0 : Nat} {payouts : List Payout} {terminal : Bool}
      (he : EvictSubtree auth d h r path u r' out0 payouts terminal)
      (hwf : path.length + h = d) : Accepts seqFinal d r r'
  | rewrite {h : Nat} {auth : Pos h 0 → Prop} {r r' : Node H} {path : List (Bool × Node H)}
      {old new : Tree h} {out0 : Nat} {payouts : List Payout}
      (hr : Rewrite h auth r path old new r' out0 payouts) (hwf : path.length + h = d) :
      Accepts seqFinal d r r'
  | detach {auth : Prop} {h : Nat} {r r' sub : Node H} {path : List (Bool × Node H)}
      {out0 : Nat} {r₁ : H} {out1 : Nat} (hd : Detach auth h r path sub r' out0 r₁ out1)
      (hwf : path.length + h = d) : Accepts seqFinal d r r'

/-- A sequence of exit blocks from the root of `t` is a trace of `exit`
records. -/
theorem exit_blocks_reachable {seqFinal d : Nat} (t : Tree d) :
    ∀ (blocks : List (ExitBlock H)) (r' : Node H),
      Steps t.root (blocks.map ExitBlock.step) r' → (∀ b ∈ blocks, b.step.WF d) →
      ∃ (xs : List (Trans d)) (t' : Tree d), r' = t'.root ∧ Reachable seqFinal t xs t'
  | [], r', h, _ => by
    cases h; exact ⟨[], t, rfl, Reachable.nil t⟩
  | b :: rest, r', h, hwf => by
    cases h with
    | cons hv hrest =>
      obtain ⟨p, hget, hr₁⟩ := leafStep_sound t b.path (some b.leaf) none _ (hwf b (by simp)) hv
      subst hr₁
      obtain ⟨xs, t', hr', hreach⟩ :=
        exit_blocks_reachable (t.set p none) rest r' hrest (fun b hb => hwf b (by simp [hb]))
      exact ⟨.exit p b.leaf :: xs, t', hr', Reachable.cons hget hreach⟩

/-- **The bridge, one spend.** Whatever the scripts accept from the root
of a real tree commits to the root of a tree reachable from it at the
tree level. -/
theorem Accepts.sound {seqFinal d : Nat} (t : Tree d) {r' : Node H}
    (h : Accepts seqFinal d t.root r') :
    ∃ (xs : List (Trans d)) (t' : Tree d), r' = t'.root ∧ Reachable seqFinal t xs t' := by
  cases h with
  | exit h hwf => exact exit_blocks_reachable t _ _ h.steps hwf
  | join hj hwf hg =>
    obtain ⟨p, hempty, _, hnew⟩ := join_sound t _ _ _ _ hwf hj
    obtain ⟨u, hu⟩ := hg
    exact ⟨[.join p u], _, hnew u hu, Reachable.cons hempty (Reachable.nil _)⟩
  | update hu hwf =>
    obtain ⟨p, hget, hr', _⟩ := update_sound t _ _ _ _ _ hwf hu
    exact ⟨[.update p _ _], _, hr', Reachable.cons hget (Reachable.nil _)⟩
  | claim hc hwf₁ hwf₂ =>
    obtain ⟨_, p₁, p₂, hsrc, hempty, hr'⟩ := claim_sound t _ _ _ _ _ _ hwf₁ hwf₂ hc
    refine ⟨[.claim p₁ p₂ _ _], _, hr', Reachable.cons ?_ (Reachable.nil _)⟩
    exact ⟨hsrc, ⟨hc.amount_le, hc.seq_lt, hc.evictorKey_eq, hc.evictAfter_le⟩, hempty⟩
  | evictSubtree he hwf =>
    obtain ⟨p, _, _, hr', _⟩ := evictSubtree_sound t _ _ _ _ _ _ hwf he
    exact ⟨[.evictSubtree p], _, hr', Reachable.cons trivial (Reachable.nil _)⟩
  | rewrite hr hwf =>
    obtain ⟨p, _, hr', _⟩ := rewrite_sound t _ _ _ _ _ _ hwf hr
    exact ⟨[.rewrite p _], _, hr', Reachable.cons trivial (Reachable.nil _)⟩
  | detach hd hwf =>
    obtain ⟨p, _, hr', _⟩ := detach_sound t _ _ _ _ _ _ hwf hd
    exact ⟨[.detach p], _, hr', Reachable.cons trivial (Reachable.nil _)⟩

/-- A history of the tree output: zero or more accepted spends. -/
inductive Chain (seqFinal d : Nat) : Node H → Node H → Prop
  | nil (r : Node H) : Chain seqFinal d r r
  | cons {r r₁ r' : Node H} : Accepts seqFinal d r r₁ → Chain seqFinal d r₁ r' →
      Chain seqFinal d r r'

/-- **The bridge, a whole history.** Every root the chain reaches from
the root of a real tree is the root of a tree reachable from it. This is
the induction invariant of 10.2 for the actual transition set, with
`Steps.sound` as the single-spend case. -/
theorem Chain.sound {seqFinal d : Nat} (t : Tree d) {r' : Node H}
    (h : Chain seqFinal d t.root r') :
    ∃ (xs : List (Trans d)) (t' : Tree d), r' = t'.root ∧ Reachable seqFinal t xs t' := by
  generalize hr : t.root = r at h
  induction h generalizing t with
  | nil => exact ⟨[], t, hr.symm, Reachable.nil t⟩
  | cons hacc _ ih =>
    subst hr
    obtain ⟨xs₁, t₁, rfl, h₁⟩ := Accepts.sound t hacc
    obtain ⟨xs₂, t₂, hr₂, h₂⟩ := ih t₁ rfl
    exact ⟨xs₁ ++ xs₂, t₂, hr₂, h₁.append h₂⟩

/-- **Every on-chain state is a real tree whose leaves can all leave.**
For any history from the root of a tree, the current root is the root of
a reachable tree, its committed sum is that tree's total (the invariant of
5.6), and every leaf in it has an accepted `EXIT_1` paying its amount to
its exit key, with either payout rule, given the owner's signature. -/
theorem chain_state {seqFinal d : Nat} (t : Tree d) {r' : Node H}
    (h : Chain seqFinal d t.root r') :
    ∃ (xs : List (Trans d)) (t' : Tree d), r' = t'.root ∧ Reachable seqFinal t xs t' ∧
      r'.sum = t'.total ∧
      ∀ (p : Pos d 0) (l : Leaf), t'.get p = some l → ∀ (exact : Bool) (auth : Prop), auth →
        ExitK exact r' [⟨l, t'.path p, l.payout, false, auth⟩]
          (t'.set p none).root (t'.set p none).root.sum := by
  obtain ⟨xs, t', rfl, hreach⟩ := Chain.sound t h
  exact ⟨xs, t', rfl, hreach, Tree.root_sum t', fun p l hl exact auth ha =>
    exit_available exact false t' p l hl auth ha⟩

end LayerTree
