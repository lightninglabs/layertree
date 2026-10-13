import LayerTree.Voucher

/-!
# The pending-leaf receive

`design/pending-receive.md` and spec 9.6.3 build an atomic Lightning
receive out of three additions: reclaimable leaves and `RECLAIM_1` (6.2,
7.11), the merge claim `CLAIM^m` / `CLAIM^hm` (7.5.4), and the reclaim
form of `REWRITE_h` (7.9 rule 8). `Cohort.lean` states each as a script
relation and proves it sound in one transaction (`merge_sound`,
`reclaim_sound`, `reclaim_only_flagged`, `rewrite_reclaimable_change`,
`rewrite_transfer_sound`); `Trace.lean` records merges and reclaims. This
module proves what the receive relies on across a history.

* `merge_body_preserved`: a merge changes no body, so it voids no voucher
  against the source and no merge voucher against the target.
* `merge_target_monotone`, `merge_stale_rejected`: a merge raises its
  target to exactly the signed level, from strictly below it, and a merge
  voucher whose level the target has reached is not accepted. Replay of a
  spent voucher, or of an older and lower one, moves nothing.
* `merge_no_overpay`: along any trace, the merges into one target body at
  one position move at most `Xmax − level₀` plus what merges move out of
  it, where `Xmax` is the largest level signed and `level₀` the target's
  starting amount, provided nothing but a merge lowers the target's
  amount while keeping its body; and every merge into or out of it moves
  value between leaves that exit to the target's exit key.
  `merge_cycle_overpays` is the same-key cycle that reaches the bound.
* `Reachable.exit_value`: through merges and reclaims, the value held by
  the leaves that are not reclaimable and whose exit key is `K` never
  falls. This needs 7.5.4 rule 2 as it now reads: the target exits to
  the source's exit key as well as being owned by it.
-/

namespace LayerTree

/-! ## Merge vouchers -/

/-- A merge voucher (7.5.4) as its message binds it: `tree_id`, the
source's body, the target's body and the absolute target level `X`. -/
structure MergeVoucher where
  treeId : Nat
  src : Leaf.Body
  tgt : Leaf.Body
  X : Nat
  deriving DecidableEq, Repr

/-- What `CLAIM^m` checks of the tree for merge voucher `v` at the pair
`c`, source on side `b`, signatures aside: the script's `tree_id` is the
voucher's, the two members have the voucher's bodies, and the rules of
7.5.4 hold against the amounts they hold now. -/
def MergeVoucher.Redeemable (π : Params) (v : MergeVoucher) {d : Nat} (T : TreeOutput d)
    (c : Pos d 1) (b : Bool) : Prop :=
  v.treeId = T.treeId ∧
    ∃ s g : Leaf, T.tree.get (c.pairAt b) = some s ∧ s.body = v.src ∧
      T.tree.get (c.pairAt (!b)) = some g ∧ g.body = v.tgt ∧ MergeOk π s g v.X

/-- A redeemable merge voucher is an accepted `merge` record. -/
theorem MergeVoucher.redeem_pre {π : Params} {d : Nat} (v : MergeVoucher) (T : TreeOutput d)
    (c : Pos d 1) (b : Bool) (hr : v.Redeemable π T c b) :
    ∃ s g : Leaf, s.body = v.src ∧ g.body = v.tgt ∧ (Trans.merge c b s g v.X).Pre π T.tree := by
  obtain ⟨_, s, g, hs, hsb, hg, hgb, hok⟩ := hr
  exact ⟨s, g, hsb, hgb, ⟨hs, hg, hok⟩⟩

/-! ## One merge -/

/-- **A merge changes no body** (7.5.4 rule 4). After a merge the source
position holds, if anything, a leaf with the source's body and the amount
less the draw, and the target position the target's body at amount `X`.
So a carve voucher redeemable against the source before is redeemable
against the residual after, as the same message, whenever the residual
still covers it; and the merge voids nothing. -/
theorem merge_body_preserved {π : Params} {d : Nat} (T : TreeOutput d) (c : Pos d 1) (b : Bool)
    (src tgt : Leaf) (X : Nat) (hpre : (Trans.merge c b src tgt X).Pre π T.tree) :
    (∀ l, ((Trans.merge c b src tgt X).apply T.tree).get (c.pairAt b) = some l →
      l.body = src.body ∧ l.amount = src.amount - (X - tgt.amount)) ∧
    (∃ g, ((Trans.merge c b src tgt X).apply T.tree).get (c.pairAt (!b)) = some g ∧
      g.body = tgt.body ∧ g.amount = X) ∧
    ∀ v : Voucher, v.Redeemable π T (c.pairAt b) → ∀ l : Leaf,
      ((Trans.merge c b src tgt X).apply T.tree).get (c.pairAt b) = some l →
      CarveOk π l v.claim →
      v.Redeemable π ⟨T.treeId, (Trans.merge c b src tgt X).apply T.tree⟩ (c.pairAt b) := by
  have hpre : MergePre π T.tree c b src tgt X := hpre
  have hne := Pos.pairAt_ne c b
  have hsrc : ((Trans.merge c b src tgt X).apply T.tree).get (c.pairAt b) =
      mergedSource src (X - tgt.amount) := by
    simp only [Trans.apply, mergeTree]
    rw [Tree.get_set_ne _ _ _ _ (Ne.symm hne), Tree.get_set]
  have hres : ∀ l, ((Trans.merge c b src tgt X).apply T.tree).get (c.pairAt b) = some l →
      l.body = src.body ∧ l.amount = src.amount - (X - tgt.amount) := by
    intro l hl
    rw [hsrc] at hl
    unfold mergedSource at hl
    split at hl
    · cases hl
    · rw [← Option.some.inj hl]; exact ⟨rfl, rfl⟩
  refine ⟨hres, ⟨{ tgt with amount := X }, ?_, rfl, rfl⟩, ?_⟩
  · simp only [Trans.apply, mergeTree]; rw [Tree.get_set]
  · intro v hv l hl hok
    obtain ⟨hid, l₀, hl₀, hb, _⟩ := hv
    rw [hpre.src_at] at hl₀
    cases hl₀
    exact ⟨hid, l, hl, (hres l hl).1.trans hb, hok⟩

/-- The amount at position `p` attributed to body `B`: the leaf's amount
if the leaf there has body `B`, else zero. A merge voucher against `B`
can move value into `p` only while this is below its level. -/
def Tree.levelAt {d : Nat} (t : Tree d) (p : Pos d 0) (B : Leaf.Body) : Nat :=
  match t.get p with
  | some l => if l.body = B then l.amount else 0
  | none => 0

theorem Tree.levelAt_of_get {d : Nat} {t : Tree d} {p : Pos d 0} {B : Leaf.Body} {l : Leaf}
    (h : t.get p = some l) (hb : l.body = B) : t.levelAt p B = l.amount := by
  simp [Tree.levelAt, h, hb]

/-- What a record moves into position `p` under body `B` by merging: the
draw of a merge whose target is at `p` with body `B`, zero otherwise. -/
def Trans.mergedInto {d : Nat} (p : Pos d 0) (B : Leaf.Body) : Trans d → Nat
  | .merge c b _ tgt X => if c.pairAt (!b) = p ∧ tgt.body = B then X - tgt.amount else 0
  | _ => 0

/-- What a trace moves into `p` under body `B` by merging. -/
def mergedIntoSum {d : Nat} (p : Pos d 0) (B : Leaf.Body) : List (Trans d) → Nat
  | [] => 0
  | x :: xs => x.mergedInto p B + mergedIntoSum p B xs

/-- **A merge raises its target to exactly the signed level, from below.**
Before an accepted merge the target's level is below `X`; afterwards it
is `X`, with the same body; and what the merge moves is the difference. -/
theorem merge_target_monotone {π : Params} {d : Nat} (t : Tree d) (c : Pos d 1) (b : Bool)
    (src tgt : Leaf) (X : Nat) (hpre : (Trans.merge c b src tgt X).Pre π t) :
    t.levelAt (c.pairAt (!b)) tgt.body < X ∧
      ((Trans.merge c b src tgt X).apply t).levelAt (c.pairAt (!b)) tgt.body = X ∧
      (Trans.merge c b src tgt X).mergedInto (c.pairAt (!b)) tgt.body =
        X - t.levelAt (c.pairAt (!b)) tgt.body := by
  have hpre : MergePre π t c b src tgt X := hpre
  have h₀ := Tree.levelAt_of_get hpre.tgt_at rfl
  have h₁ : ((Trans.merge c b src tgt X).apply t).levelAt (c.pairAt (!b)) tgt.body = X := by
    have hg : ((Trans.merge c b src tgt X).apply t).get (c.pairAt (!b)) =
        some { tgt with amount := X } := by
      simp only [Trans.apply, mergeTree]; rw [Tree.get_set]
    exact Tree.levelAt_of_get hg (Leaf.body_amount tgt X)
  refine ⟨by rw [h₀]; exact hpre.ok.raise, h₁, ?_⟩
  simp [Trans.mergedInto, h₀]

/-- **A spent or stale merge voucher is rejected.** If the target already
holds `X` or more, no merge to level `X` is accepted, whatever the
source: replaying a redeemed voucher, or redeeming an older and lower
one after a newer, moves nothing (7.5.4 rule 3). -/
theorem merge_stale_rejected {π : Params} {d : Nat} (t : Tree d) (c : Pos d 1) (b : Bool)
    (g : Leaf) (X : Nat) (hg : t.get (c.pairAt (!b)) = some g) (hle : X ≤ g.amount) :
    ∀ src tgt : Leaf, ¬ (Trans.merge c b src tgt X).Pre π t := by
  intro src tgt hpre
  have hpre : MergePre π t c b src tgt X := hpre
  have h₁ := hpre.tgt_at
  rw [hg] at h₁
  cases h₁
  have hr := hpre.ok.raise
  omega

/-! ## Many merges -/

/-- What a record moves out of position `p` under body `B` by merging:
the draw of a merge whose source is at `p` with body `B`. -/
def Trans.mergedOutOf {d : Nat} (p : Pos d 0) (B : Leaf.Body) : Trans d → Nat
  | .merge c b src tgt X => if c.pairAt b = p ∧ src.body = B then X - tgt.amount else 0
  | _ => 0

/-- What a trace moves out of `p` under body `B` by merging. -/
def mergedOutOfSum {d : Nat} (p : Pos d 0) (B : Leaf.Body) : List (Trans d) → Nat
  | [] => 0
  | x :: xs => x.mergedOutOf p B + mergedOutOfSum p B xs

/-- Every record of a trace was accepted on some tree. -/
theorem Reachable.pre_of_mem {π : Params} {d : Nat} {t t' : Tree d} {xs : List (Trans d)}
    (h : Reachable π t xs t') : ∀ x ∈ xs, ∃ u : Tree d, x.Pre π u := by
  induction h with
  | nil => intro x hx; cases hx
  | @cons t₀ _ y _ hpre _ ih =>
    intro x hx
    rcases List.mem_cons.mp hx with rfl | hx
    · exact ⟨t₀, hpre⟩
    · exact ih x hx

/-- A merge out of the source position leaves the source's level lower by
exactly the draw. -/
theorem merge_source_level {π : Params} {d : Nat} (t : Tree d) (c : Pos d 1) (b : Bool)
    (src tgt : Leaf) (X : Nat) (hpre : (Trans.merge c b src tgt X).Pre π t) :
    ((Trans.merge c b src tgt X).apply t).levelAt (c.pairAt b) src.body + (X - tgt.amount) =
      src.amount := by
  have hpre : MergePre π t c b src tgt X := hpre
  have hne := Pos.pairAt_ne c b
  have hdl := hpre.ok.draw_le
  have hsrc : ((Trans.merge c b src tgt X).apply t).get (c.pairAt b) =
      mergedSource src (X - tgt.amount) := by
    simp only [Trans.apply, mergeTree]
    rw [Tree.get_set_ne _ _ _ _ (Ne.symm hne), Tree.get_set]
  unfold mergedSource at hsrc
  split at hsrc
  · rename_i heq
    simp [Tree.levelAt, hsrc]; omega
  · rw [Tree.levelAt_of_get (B := src.body) hsrc rfl]
    simp only
    omega

/-- **No sequence of merges pays a target more than the largest level
signed, except value that came out of it to its own key.** Fix a target
position `p` and body `B`, and let `Xmax` bound the level of every merge
into `p` under `B` along a trace. If no record other than a merge into or
out of `p` under `B` lowers the level there (`hmono`), then:

* what the merges move into `p` is at most `Xmax − level₀` plus what the
  merges move *out* of it, `level₀` being the target's starting amount;
  so with no merge out of the target, replays, stale vouchers and any
  order of redemptions together pay it at most what the largest voucher
  signed;
* every merge into or out of `p` under `B` moves value between two leaves
  that both exit to `B`'s exit key (7.5.4 rule 2: the target is owned by
  and exits to the source's exit key). Any excess over the signed level
  is therefore value that `B`'s exit key's own leaves passed back and
  forth, never value taken from another key.

`hmono` is the 7.5.4 obligation that a decrease of a target which keeps
its body advance its `seq`, for the decreases that are not merges: an
`UPDATE` or `REWRITE_h` co-signed by the target's owner. The scripts do
not check it. It also excludes a carve or exit that removes body `B`
from `p` and a later record that brings it back lower (the `seq`
monotonicity item of the README). -/
theorem merge_no_overpay {π : Params} {d : Nat} {t t' : Tree d} {xs : List (Trans d)}
    (h : Reachable π t xs t') (p : Pos d 0) (B : Leaf.Body) (Xmax : Nat)
    (hX : ∀ x ∈ xs, ∀ (c : Pos d 1) (b : Bool) (src tgt : Leaf) (X : Nat),
      x = .merge c b src tgt X → c.pairAt (!b) = p → tgt.body = B → X ≤ Xmax)
    (hmono : ∀ x ∈ xs, ∀ u : Tree d, x.Pre π u → x.mergedInto p B = 0 →
      x.mergedOutOf p B = 0 → u.levelAt p B ≤ (x.apply u).levelAt p B) :
    mergedIntoSum p B xs ≤ (Xmax - t.levelAt p B) + mergedOutOfSum p B xs ∧
    ∀ x ∈ xs, ∀ (c : Pos d 1) (b : Bool) (src tgt : Leaf) (X : Nat),
      x = .merge c b src tgt X → (c.pairAt b = p ∧ src.body = B ∨ c.pairAt (!b) = p ∧ tgt.body = B) →
      src.exitKey = B.exitKey ∧ tgt.exitKey = B.exitKey := by
  refine ⟨?_, ?_⟩
  · induction h with
    | nil => simp [mergedIntoSum]
    | @cons t₀ _ x xs hpre _ ih =>
      have ih' := ih (fun y hy => hX y (by simp [hy])) (fun y hy => hmono y (by simp [hy]))
      simp only [mergedIntoSum, mergedOutOfSum]
      by_cases hin : x.mergedInto p B = 0
      · by_cases hout : x.mergedOutOf p B = 0
        · have := hmono x (by simp) t₀ hpre hin hout
          omega
        · cases x with
          | merge c b src tgt X =>
            by_cases hcond : c.pairAt b = p ∧ src.body = B
            · obtain ⟨hp, hB⟩ := hcond
              subst hp; subst hB
              have hl₀ := Tree.levelAt_of_get (hpre : MergePre π t₀ c b src tgt X).src_at rfl
              have hl₁ := merge_source_level t₀ c b src tgt X hpre
              have hmo : (Trans.merge c b src tgt X).mergedOutOf (c.pairAt b) src.body =
                  X - tgt.amount := by simp [Trans.mergedOutOf]
              rw [hmo, hin]
              omega
            · simp [Trans.mergedOutOf, hcond] at hout
          | _ => simp [Trans.mergedOutOf] at hout
      · cases x with
        | merge c b src tgt X =>
          by_cases hcond : c.pairAt (!b) = p ∧ tgt.body = B
          · obtain ⟨hp, hB⟩ := hcond
            subst hp; subst hB
            obtain ⟨hlt, h₁, hmi⟩ := merge_target_monotone t₀ c b src tgt X hpre
            have hXle := hX _ (by simp) c b src tgt X rfl rfl rfl
            rw [h₁] at ih'
            rw [hmi]
            omega
          · simp [Trans.mergedInto, hcond] at hin
        | _ => simp [Trans.mergedInto] at hin
  · intro x hx c b src tgt X hxe hcase
    obtain ⟨u, hpre⟩ := h.pre_of_mem x hx
    subst hxe
    have hok := (hpre : MergePre π u c b src tgt X).ok
    have he := hok.exit_eq
    rcases hcase with ⟨_, hB⟩ | ⟨_, hB⟩
    · have := congrArg Leaf.Body.exitKey hB
      exact ⟨this, he.trans this⟩
    · have := congrArg Leaf.Body.exitKey hB
      exact ⟨he.symm.trans this, this⟩

/-- The parameters of the cycle example: no `RECLAIM_KEY`. -/
def cycleParams : Params := { seqFinal := 100, dustMin := 1 }

/-- **A same-key merge cycle pays a target more than its largest level,
and only out of the target itself.** Two leaves at one pair, both owned
by and exiting to one key, can each be merged into the other (7.5.4 rule
2 allows nothing else: a merge both ways needs each leaf owned by the
other's exit key, and equal exit keys then make the four keys one).
Raise the right leaf from 10 to 15 (it moves 5), merge the left leaf
back up to 12 out of the right (the right falls to 8 and keeps its
body), and replay the first voucher: it moves 7 more. The right leaf
has received 12 by merging where the largest level signed allows 5, and
the excess is exactly the 7 merged out of it, all between leaves of the
one key. Every record is accepted by the scripts. This is the case
`merge_no_overpay`'s bound allows for, and the reason it adds the
merged-out amount. -/
theorem merge_cycle_overpays :
    ∃ (t t' : Tree 1) (xs : List (Trans 1)) (p : Pos 1 0) (B : Leaf.Body),
      Reachable cycleParams t xs t' ∧
      (∀ x ∈ xs, ∀ (c : Pos 1 1) (b : Bool) (src tgt : Leaf) (X : Nat),
        x = .merge c b src tgt X → c.pairAt (!b) = p → tgt.body = B → X ≤ 15) ∧
      15 - t.levelAt p B < mergedIntoSum p B xs ∧
      mergedIntoSum p B xs = (15 - t.levelAt p B) + mergedOutOfSum p B xs ∧
      B.ownerKey = B.exitKey := by
  let A : Leaf := ⟨10, 1, 1, 0, 0, 0, 0⟩
  let Bl : Leaf := ⟨10, 1, 1, 0, 0, 1, 0⟩
  let t₀ : Tree 1 := .bin (.tip (some A)) (.tip (some Bl))
  have hnr : ∀ l, ¬ cycleParams.Reclaimable l := Params.not_reclaimable rfl
  let x₁ : Trans 1 := .merge .nil false A Bl 15
  let x₂ : Trans 1 := .merge .nil true { Bl with amount := 15 } { A with amount := 5 } 12
  let x₃ : Trans 1 := .merge .nil false { A with amount := 12 } { Bl with amount := 8 } 15
  refine ⟨t₀, x₃.apply (x₂.apply (x₁.apply t₀)), [x₁, x₂, x₃], Pos.pairAt .nil true, Bl.body,
    ?_, ?_, by decide, by decide, rfl⟩
  · refine .cons ⟨rfl, rfl, ⟨rfl, rfl, by decide, by decide, hnr _, by decide, by decide,
      by decide⟩⟩ ?_
    refine .cons ⟨rfl, rfl, ⟨rfl, rfl, by decide, by decide, hnr _, by decide, by decide,
      by decide⟩⟩ ?_
    refine .cons ⟨rfl, rfl, ⟨rfl, rfl, by decide, by decide, hnr _, by decide, by decide,
      by decide⟩⟩ ?_
    exact .nil _
  · intro x hx c b src tgt X hxe _ _
    simp only [List.mem_cons, List.not_mem_nil, or_false] at hx
    rcases hx with rfl | rfl | rfl <;> (injection hxe with _ _ _ _ h5; omega)

/-! ## Value held by an exit key -/

/-- The share of a leaf that the value invariant counts for key `K`: its
amount when it is not reclaimable and its exit key is `K`. -/
def Leaf.share (π : Params) (K : Nat) (l : Leaf) : Nat :=
  if ¬ π.Reclaimable l ∧ l.exitKey = K then l.amount else 0

/-- The sum of `f` over the leaves of a tree. -/
def Tree.totalBy (f : Leaf → Nat) : {h : Nat} → Tree h → Nat
  | _, .tip none => 0
  | _, .tip (some l) => f l
  | _, .bin l r => totalBy f l + totalBy f r

theorem Tree.totalBy_setSub (f : Leaf → Nat) {d h : Nat} (t : Tree d) (p : Pos d h)
    (u : Tree h) :
    (t.setSub p u).totalBy f + (t.getSub p).totalBy f = t.totalBy f + u.totalBy f := by
  induction p with
  | nil => simp [setSub, getSub]; omega
  | cons b p ih =>
    cases t with
    | bin l r =>
      cases b
      · have := ih l u; simp [setSub, getSub, totalBy]; omega
      · have := ih r u; simp [setSub, getSub, totalBy]; omega

theorem Tree.totalBy_getSub_of_get (f : Leaf → Nat) {d : Nat} (t : Tree d) (p : Pos d 0)
    (o : Option Leaf) (h : t.get p = o) : (t.getSub p).totalBy f = (Tree.tip o).totalBy f := by
  unfold get at h
  revert h
  generalize t.getSub p = s
  cases s with
  | tip o' => intro h; simp only at h; rw [h]

theorem Tree.totalBy_set (f : Leaf → Nat) {d : Nat} (t : Tree d) (p : Pos d 0) (o : Option Leaf) :
    (t.set p o).totalBy f + (t.getSub p).totalBy f = t.totalBy f + (Tree.tip o).totalBy f :=
  Tree.totalBy_setSub f t p (.tip o)

/-- The value held for key `K`: the amounts of the leaves that are not
reclaimable and whose exit key is `K`. Every exit of such a leaf pays
`K` (`ExitK.pays_exit_key`). -/
def Tree.heldFor (π : Params) (K : Nat) {d : Nat} (t : Tree d) : Nat := t.totalBy (Leaf.share π K)

/-- The records of the receive: merges and reclaims. -/
def Trans.IsReceive {d : Nat} : Trans d → Prop
  | .merge _ _ _ _ _ => True
  | .reclaim _ _ _ => True
  | _ => False

/-- One merge or reclaim never lowers `K`'s value. -/
theorem Trans.heldFor_step {π : Params} (K : Nat) {d : Nat} (x : Trans d) (u : Tree d)
    (hpre : x.Pre π u) (hx : x.IsReceive) :
    u.heldFor π K ≤ (x.apply u).heldFor π K := by
  unfold Tree.heldFor
  cases x with
  | merge c b src tgt X =>
    have hpre : MergePre π u c b src tgt X := hpre
    have hne := Pos.pairAt_ne c b
    have hok := hpre.ok
    have hr := hok.raise
    have hdl := hok.draw_le
    have htnr := hok.tgt_not_reclaimable
    have hex := hok.exit_eq
    have h₁ := Tree.totalBy_set (Leaf.share π K) u (c.pairAt b) (mergedSource src (X - tgt.amount))
    have h₁' := Tree.totalBy_getSub_of_get (Leaf.share π K) u _ _ hpre.src_at
    have hg : (u.set (c.pairAt b) (mergedSource src (X - tgt.amount))).get (c.pairAt (!b)) =
        some tgt := by rw [Tree.get_set_ne _ _ _ _ hne]; exact hpre.tgt_at
    have h₂ := Tree.totalBy_set (Leaf.share π K)
      (u.set (c.pairAt b) (mergedSource src (X - tgt.amount))) (c.pairAt (!b))
      (some { tgt with amount := X })
    have h₂' := Tree.totalBy_getSub_of_get (Leaf.share π K) _ _ _ hg
    have hs1 : (Tree.tip (some src)).totalBy (Leaf.share π K) =
        if ¬ π.Reclaimable src ∧ src.exitKey = K then src.amount else 0 := rfl
    have hs2 : (Tree.tip (some tgt)).totalBy (Leaf.share π K) =
        if ¬ π.Reclaimable tgt ∧ tgt.exitKey = K then tgt.amount else 0 := rfl
    have hs3 : (Tree.tip (some { tgt with amount := X })).totalBy (Leaf.share π K) =
        if ¬ π.Reclaimable tgt ∧ tgt.exitKey = K then X else 0 := rfl
    have hms : (Tree.tip (mergedSource src (X - tgt.amount))).totalBy (Leaf.share π K) =
        if ¬ π.Reclaimable src ∧ src.exitKey = K then src.amount - (X - tgt.amount) else 0 := by
      unfold mergedSource
      split
      · show 0 = _
        split <;> omega
      · rfl
    rw [h₁', hs1, hms] at h₁
    rw [h₂', hs2, hs3] at h₂
    show u.totalBy (Leaf.share π K) ≤
      ((u.set (c.pairAt b) (mergedSource src (X - tgt.amount))).set (c.pairAt (!b))
        (some { tgt with amount := X })).totalBy (Leaf.share π K)
    by_cases cs : ¬ π.Reclaimable src ∧ src.exitKey = K <;>
      by_cases ck : tgt.exitKey = K
    · rw [if_pos cs, if_pos cs] at h₁
      rw [if_pos ⟨htnr, ck⟩, if_pos ⟨htnr, ck⟩] at h₂
      omega
    · exact absurd (hex.trans cs.2) ck
    · rw [if_neg cs, if_neg cs] at h₁
      rw [if_pos ⟨htnr, ck⟩, if_pos ⟨htnr, ck⟩] at h₂
      omega
    · rw [if_neg cs, if_neg cs] at h₁
      rw [if_neg (fun h => ck h.2), if_neg (fun h => ck h.2)] at h₂
      omega
  | reclaim p l lt =>
    have h := Tree.totalBy_set (Leaf.share π K) u p none
    have h' := Tree.totalBy_getSub_of_get (Leaf.share π K) u p _ hpre.1
    have hl : (Tree.tip (some l)).totalBy (Leaf.share π K) = 0 := by
      show (if ¬ π.Reclaimable l ∧ l.exitKey = K then l.amount else 0) = 0
      rw [if_neg (fun h => h.1 hpre.2.1)]
    have h0 : (Tree.tip none).totalBy (Leaf.share π K) = 0 := rfl
    rw [h', hl] at h
    rw [h0] at h
    show u.totalBy (Leaf.share π K) ≤ (u.set p none).totalBy (Leaf.share π K)
    omega
  | _ => exact absurd hx id

/-- **No key's value falls through the receive.** Let `heldFor π K` be
the amounts of the leaves that are not reclaimable and exit to `K`.
Along any trace of merges and reclaims it never decreases. A reclaim
removes only a reclaimable leaf, so it takes nothing from any key; a
merge into a target that is not reclaimable and exits to the source's
exit key (7.5.4 rule 2) moves value within that key's leaves, or adds
to them when the source is reclaimable. -/
theorem Reachable.exit_value {π : Params} (K : Nat) {d : Nat} {t t' : Tree d}
    {xs : List (Trans d)} (h : Reachable π t xs t') (hx : ∀ x ∈ xs, x.IsReceive) :
    t.heldFor π K ≤ t'.heldFor π K := by
  induction h with
  | nil => exact Nat.le_refl _
  | @cons t₀ _ x xs hpre _ ih =>
    have := Trans.heldFor_step K x t₀ hpre (hx x (by simp))
    have := ih (fun y hy => hx y (by simp [hy]))
    omega

end LayerTree
