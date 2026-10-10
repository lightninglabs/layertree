import LayerTree.Tree

/-!
# Transitions

Section 7 of the specification defines every state transition of the tree
output as a set of rules the script checks. This module states those rules
as relations over the *abstract* objects the script manipulates (nodes,
paths, amounts) and proves what section 10.2 claims about them.

## What is and is not modelled

The scripts of section 8 do three kinds of work:

1. **Merkle-sum work**: check the old node against the committed root with
   the sibling path (`CHECK_OLD` / `CHECK_PREV`) and compute the new root
   with the same path (`LEVEL × D`, `FINAL`). This is modelled exactly, as
   `Step`, and all the theorems below are about it.
2. **Authorisation**: signature checks against keys read out of the leaf,
   and lock-time checks. These decide *who* may perform a transition, not
   *what* it does to the tree. They are abstracted as propositions
   (`Authorised`) that the theorems carry along unchanged; nothing about
   conservation depends on them.
3. **Transaction binding**: reading the current input's amount and
   scriptPubKey and the outputs' amounts and scripts with `OP_TX`. The
   theorems take the input amount `S` and the output amounts as
   parameters, exactly as the script reads them. Binding the witness root
   to the input scriptPubKey is treated in `LayerTree.Binding`.

The tapscript *bytecode* is not modelled. The link between the rules here
and the bytecode of section 8 is the executable test-suite in `tools/`
(the simulator, the golden vectors and the Go cross-checks). What this
module adds is the proof that the *rules* are the right ones: any
transition that satisfies them keeps the on-chain amount equal to the sum
of the leaves, changes exactly the intended positions, and only ever
removes a leaf that is really there.

## Naming

`r` is the root committed by the *current* tree output (`Node H`: the hash
`r` of section 6 together with the output amount `S`, which section 7.1
rule 3 requires to equal the root sum). `r'` is the root of output 0.
-/

namespace LayerTree

variable {H : Type} [M : HashModel Leaf H]

/-- One Merkle-sum step (section 7.1 rules 3 and 4): a sibling path, the
height at which it ends, and the old and new nodes there. `height` is a
script parameter in the deployment: an `EXIT`, `UPDATE` or `CLAIM` step
ends at a leaf (`height = 0`) and `JOIN_h` ends at height `h`; the script
runs exactly `D − height` levels, which is the well-formedness condition
`WF`. `valid s r r'` is exactly what the script establishes about the
step: folding the old node reaches the current root, and folding the new
node reaches the root it writes to output 0. -/
structure Step (H : Type) where
  height : Nat
  path : List (Bool × Node H)
  old : Node H
  new : Node H

namespace Step

/-- The path has one entry per level between the step's height and the
tree depth. The scripts guarantee this by construction (`LEVEL × (D − h)`). -/
def WF (d : Nat) (s : Step H) : Prop := s.path.length + s.height = d

def valid (s : Step H) (r r' : Node H) : Prop :=
  fold s.old s.path = r ∧ fold s.new s.path = r'

/-- **A step is a subtree replacement.** If the current root is that of a
real tree `t`, a valid, well-formed step's old node is the root of the
subtree at some position `p` of the step's height, and the root it
produces is the root of `t` with that subtree replaced by *any* tree whose
root is the new node. -/
theorem sound {d : Nat} (t : Tree d) (s : Step H) (r' : Node H)
    (hwf : s.WF d) (hv : s.valid t.root r') :
    ∃ p : Pos d s.height, s.old = (t.getSub p).root ∧
      ∀ (u : Tree s.height), u.root = s.new → r' = (t.setSub p u).root := by
  obtain ⟨h, p, hold, hπ⟩ := Tree.fold_sound t s.old s.path hv.1
  have hlen := Tree.pathSub_length t p
  have hh : h = s.height := by unfold WF at hwf; rw [hπ] at hwf; omega
  subst hh
  refine ⟨p, hold, fun u hu => ?_⟩
  rw [← hv.2, hπ, ← hu, Tree.fold_setSub]

/-- **Conservation of a step**: the new root's sum is the old root's sum
with the old node's sum swapped for the new node's. Stated additively so
that it holds in `Nat` without side conditions. -/
theorem sum (s : Step H) (r r' : Node H) (hv : s.valid r r') :
    r'.sum + s.old.sum = r.sum + s.new.sum := by
  have h1 := fold_sum s.old s.path
  have h2 := fold_sum s.new s.path
  rw [hv.1] at h1; rw [hv.2] at h2
  omega

/-- A step whose new node is the root of some tree of the step's height.
Every step the spec defines except a `JOIN` graft is grounded by
construction: its new node is `E_0` or a leaf node, the roots of `tip none`
and `tip (some l)`. For a graft the *joiners* establish it off-chain by
verifying their own paths inside the subtree before funding it (section
9.2 makes this a MUST); see `join_sound` and the discussion in
`formal/README.md`. -/
def Grounded (s : Step H) : Prop := ∃ u : Tree s.height, u.root = s.new

/-- A leaf-level step (height 0) is grounded whatever leaf or empty node it
writes. -/
theorem grounded_of_leaf (s : Step H) (hh : s.height = 0) (o : Option Leaf)
    (hn : s.new = leafNode o) : s.Grounded := by
  cases s with
  | mk h path old new =>
    simp only at hh hn
    subst hh; subst hn
    exact ⟨Tree.tip o, rfl⟩

end Step

/-- Sequential composition (section 7.6): `Steps r ss r'` holds when the
steps of `ss` chain from `r` to `r'`, each proving its old node against the
root the previous one produced (`CHECK_OLD` for the first, `CHECK_PREV` for
the rest). -/
inductive Steps : Node H → List (Step H) → Node H → Prop
  | nil (r : Node H) : Steps r [] r
  | cons {r r₁ r' : Node H} {s : Step H} {rest : List (Step H)} :
      s.valid r r₁ → Steps r₁ rest r' → Steps r (s :: rest) r'

/-- Sum of the old nodes of a step list. -/
def oldSum : List (Step H) → Nat
  | [] => 0
  | s :: rest => s.old.sum + oldSum rest

/-- Sum of the new nodes of a step list. -/
def newSum : List (Step H) → Nat
  | [] => 0
  | s :: rest => s.new.sum + newSum rest

/-- **Conservation of a composition**: the final root's sum is the initial
sum minus everything removed plus everything added. Holds for *any* step
list, grounded or not: the covenant conserves sums unconditionally. -/
theorem Steps.sum {r r' : Node H} {ss : List (Step H)} (h : Steps r ss r') :
    r'.sum + oldSum ss = r.sum + newSum ss := by
  induction h with
  | nil => simp [oldSum, newSum]
  | cons hv _ ih =>
    have := Step.sum _ _ _ hv
    simp only [oldSum, newSum]
    omega

/-- **A grounded composition is a real tree.** If the current root is the
root of a tree and every step is well formed and grounded, the final root
is the root of a tree of the same depth. This is the induction invariant
of section 10.2: "the on-chain root is the root of a real tree whose leaf
amounts sum to the output amount" survives every transition. -/
theorem Steps.sound {d : Nat} (t : Tree d) {r' : Node H} {ss : List (Step H)}
    (h : Steps t.root ss r') (hwf : ∀ s ∈ ss, s.WF d) (hg : ∀ s ∈ ss, s.Grounded) :
    ∃ t' : Tree d, t'.root = r' := by
  induction ss generalizing t with
  | nil => cases h; exact ⟨t, rfl⟩
  | cons s rest ih =>
    cases h with
    | cons hv hrest =>
      obtain ⟨p, _, hnew⟩ := Step.sound t s _ (hwf s (by simp)) hv
      obtain ⟨u, hu⟩ := hg s (by simp)
      have h1 := hnew u hu
      rw [h1] at hrest
      exact ih (t.setSub p u) hrest (fun s hs => hwf s (by simp [hs]))
        (fun s hs => hg s (by simp [hs]))

/-!
## The transitions of section 7

Each transition is a list of steps with constraints on the old and new
nodes. Authorisation (signatures, lock times) is carried as an opaque
proposition; the theorems never look inside it.
-/

/-- A leaf-level step: remove, insert or replace the leaf at the end of
`path`. -/
def leafStep (path : List (Bool × Node H)) (o o' : Option Leaf) : Step H :=
  ⟨0, path, leafNode o, leafNode o'⟩

/-- **Leaf-level soundness**: a valid leaf-level step whose old node is a
leaf node identifies a position holding exactly that leaf, and produces
the root of the tree with that position rewritten. -/
theorem leafStep_sound {d : Nat} (t : Tree d) (path : List (Bool × Node H))
    (o o' : Option Leaf) (r' : Node H)
    (hwf : (leafStep path o o').WF d) (hv : (leafStep path o o').valid t.root r') :
    ∃ p : Pos d 0, t.get p = o ∧ r' = (t.set p o').root := by
  obtain ⟨p, hold, hnew⟩ := Step.sound t (leafStep path o o') r' hwf hv
  refine ⟨p, ?_, hnew (Tree.tip o') rfl⟩
  unfold Tree.get
  revert hold
  cases t.getSub p with
  | tip q => intro hold; exact (leafNode_inj hold).symm

/-! ### Payouts -/

/-- A payout output as the script reads it with `OP_TX`: the x-only key
its scriptPubKey pays (`P2TR(key)`) and its amount. The key is what
7.2 rule 2, 7.7 rule 2 and 7.9 rule 5 compare with the leaf's
`exit_key`; the model carries it so that every payout theorem names the
key the output pays. -/
structure Payout where
  key : Nat
  amount : Nat
  deriving DecidableEq, Repr

/-- The payout a leaf is owed when it is removed: `leaf.amount` to
`P2TR(leaf.exit_key)` (7.2 rule 2 with rule 4, 7.7 rule 2, 7.9 rule 5). -/
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

/-! ### EXIT (section 7.2) -/

/-- One `EXIT` block: the leaf, its path, the payout output it receives
(key and amount, as the script reads output `i`), and the authorisation
(owner signature, or evictor signature plus lock time). -/
structure ExitBlock (H : Type) where
  leaf : Leaf
  path : List (Bool × Node H)
  payout : Payout
  isEvict : Bool
  authorised : Prop

/-- The step an exit block performs: the leaf becomes `E_0`. -/
def ExitBlock.step (b : ExitBlock H) : Step H := leafStep b.path (some b.leaf) none

/-- The payout rule of section 7.2: the output pays `P2TR(leaf.exit_key)`
(rule 2), and its amount is at most the leaf amount for an owner exit
(rule 3), exactly the leaf amount for an eviction (rule 4) and for every
exit in the exact variant `EXIT_K^=` (rule 6, always in MID and MIN). -/
def ExitBlock.payoutOk (exact : Bool) (b : ExitBlock H) : Prop :=
  b.payout.key = b.leaf.exitKey ∧
    if b.isEvict || exact then b.payout.amount = b.leaf.amount
    else b.payout.amount ≤ b.leaf.amount

/-- What the `EXIT_K` script accepts (sections 7.2 and 7.6): the blocks
chain from the current root to `r'`, output 0 carries `r'.sum` (rule 7.1),
and every block is authorised and pays within its rule. -/
structure ExitK (exact : Bool) (r : Node H) (blocks : List (ExitBlock H)) (r' : Node H)
    (out0 : Nat) : Prop where
  steps : Steps r (blocks.map ExitBlock.step) r'
  out0_eq : out0 = r'.sum
  payouts : ∀ b ∈ blocks, b.payoutOk exact
  auth : ∀ b ∈ blocks, b.authorised

def payoutSum : List (ExitBlock H) → Nat
  | [] => 0
  | b :: rest => b.payout.amount + payoutSum rest

def amountSum : List (ExitBlock H) → Nat
  | [] => 0
  | b :: rest => b.leaf.amount + amountSum rest

theorem oldSum_exit (blocks : List (ExitBlock H)) :
    oldSum (blocks.map ExitBlock.step) = amountSum blocks := by
  induction blocks with
  | nil => rfl
  | cons b rest ih => simp [oldSum, amountSum, ExitBlock.step, leafStep, ih]

theorem newSum_exit (blocks : List (ExitBlock H)) :
    newSum (blocks.map ExitBlock.step) = 0 := by
  induction blocks with
  | nil => rfl
  | cons b rest ih => simp [newSum, ExitBlock.step, leafStep, ih]

omit M in
theorem payoutSum_le (exact : Bool) (blocks : List (ExitBlock H))
    (h : ∀ b ∈ blocks, b.payoutOk exact) : payoutSum blocks ≤ amountSum blocks := by
  induction blocks with
  | nil => exact Nat.le_refl _
  | cons b rest ih =>
    have hb := h b (by simp)
    have hr := ih (fun b hb => h b (by simp [hb]))
    simp only [payoutSum, amountSum]
    unfold ExitBlock.payoutOk at hb
    obtain ⟨_, hb⟩ := hb
    split at hb <;> omega

omit M in
/-- **Every exit pays the leaf's exit key** (7.2 rule 2): whatever the
amount rule, the payout output's key is the leaf's `exit_key`. -/
theorem ExitBlock.payoutOk_key {exact : Bool} {b : ExitBlock H} (h : b.payoutOk exact) :
    b.payout.key = b.leaf.exitKey := h.1

/-- **No inflation on exit**: output 0 plus every payout is at most the
input amount. The difference is what section 7.2 rule 3 leaves "available
to the transaction as fee"; in the exact variant it is zero. -/
theorem ExitK.no_inflation {exact : Bool} {r r' : Node H} {blocks : List (ExitBlock H)} {out0 : Nat}
    (h : ExitK exact r blocks r' out0) : out0 + payoutSum blocks ≤ r.sum := by
  have hs := h.steps.sum
  rw [oldSum_exit, newSum_exit] at hs
  have hp := payoutSum_le exact blocks h.payouts
  have ho := h.out0_eq
  omega

omit M in
theorem payoutSum_eq (blocks : List (ExitBlock H))
    (h : ∀ b ∈ blocks, b.payoutOk true) : payoutSum blocks = amountSum blocks := by
  induction blocks with
  | nil => rfl
  | cons b rest ih =>
    have hb := h b (by simp)
    have hr := ih (fun b hb => h b (by simp [hb]))
    simp [ExitBlock.payoutOk] at hb
    simp only [payoutSum, amountSum]
    omega

/-- **The exits of an `EXIT_K` pay their leaves' exit keys**: output `i`
pays `P2TR(leaf_i.exit_key)` for every block. With `no_inflation` and
`single_sound` this is the full payout statement of 7.2: the right key,
and at most (owner) or exactly (eviction, exact variant) the amount. -/
theorem ExitK.pays_exit_key {exact : Bool} {r r' : Node H} {blocks : List (ExitBlock H)}
    {out0 : Nat} (h : ExitK exact r blocks r' out0) :
    ∀ b ∈ blocks, b.payout.key = b.leaf.exitKey :=
  fun b hb => (h.payouts b hb).1

/-- **Exact conservation in `EXIT_K^=`**: with exact payouts nothing is left
over, so every satoshi of the input is accounted for by output 0 and the
payouts. -/
theorem ExitK.exact_conservation {r r' : Node H} {blocks : List (ExitBlock H)} {out0 : Nat}
    (h : ExitK true r blocks r' out0) : out0 + payoutSum blocks = r.sum := by
  have hs := h.steps.sum
  rw [oldSum_exit, newSum_exit] at hs
  have hp := payoutSum_eq blocks h.payouts
  have ho := h.out0_eq
  omega

/-- **Every exited leaf was in the tree**: for a single `EXIT`, the leaf
sits at some position of the current tree, and output 0 commits to the
tree with that position emptied. -/
theorem ExitK.single_sound {exact : Bool} {d : Nat} (t : Tree d) (b : ExitBlock H)
    {r' : Node H} {out0 : Nat} (hwf : b.step.WF d)
    (h : ExitK exact t.root [b] r' out0) :
    ∃ p : Pos d 0, t.get p = some b.leaf ∧ r' = (t.set p none).root ∧
      out0 + b.leaf.amount = t.root.sum := by
  cases h.steps with
  | cons hv hrest =>
    cases hrest
    obtain ⟨p, hget, hr'⟩ := leafStep_sound t b.path (some b.leaf) none _ hwf hv
    refine ⟨p, hget, hr', ?_⟩
    have := Step.sum _ _ _ hv
    simp [ExitBlock.step, leafStep] at this
    rw [h.out0_eq]; omega

/-! ### Payability (section 10.2) -/

/-- **Every leaf can be paid.** For any tree and any position holding a
leaf, the honest witness (the leaf, its path, `E_0` as the new node) is a
valid step from the current root to the root of the tree without that
leaf; the new sum is the old sum minus the leaf amount; and no other
position changes. Together with `ExitK.no_inflation` this is the security
claim of section 10.2: whoever holds a leaf and its path can always
construct an accepted `EXIT` that pays the leaf amount, without anyone
else's cooperation, and without touching anyone else's leaf. -/
theorem payable {d : Nat} (t : Tree d) (p : Pos d 0) (l : Leaf) (hl : t.get p = some l) :
    (leafStep (t.path p) (some l) none).valid t.root (t.set p none).root ∧
    (t.set p none).root.sum + l.amount = t.root.sum ∧
    ∀ q, q ≠ p → (t.set p none).get q = t.get q := by
  refine ⟨⟨?_, ?_⟩, ?_, ?_⟩
  · have := Tree.fold_path t p
    rw [hl] at this
    exact this
  · exact Tree.fold_set t p none
  · have h1 := Tree.root_sum (t.set p none)
    have h2 := Tree.root_sum t
    have hs := Step.sum (leafStep (t.path p) (some l) none) t.root (t.set p none).root
      ⟨by have := Tree.fold_path t p; rw [hl] at this; exact this, Tree.fold_set t p none⟩
    simp [leafStep] at hs
    omega
  · intro q hq
    exact Tree.get_set_ne t p q none (Ne.symm hq)

/-- **The honest `EXIT_1` is accepted and pays the exit key.** `payable`
stated as an `ExitK`: for any tree, any position holding a leaf, either
payout rule and any authorisation the owner can supply (its signature),
the block made of the leaf, its honest path and the payout
`(leaf.exit_key, leaf.amount)` is an accepted single exit from the current
root to the root of the tree without the leaf, with output 0 carrying the
remaining sum. This is the form of 10.2's claim that names the key the
payout goes to. -/
theorem exit_available {d : Nat} (exact : Bool) (t : Tree d) (p : Pos d 0) (l : Leaf)
    (hl : t.get p = some l) (auth : Prop) (ha : auth) :
    ExitK exact t.root [⟨l, t.path p, l.payout, false, auth⟩]
      (t.set p none).root (t.set p none).root.sum := by
  have hv := (payable t p l hl).1
  refine ⟨Steps.cons hv (Steps.nil _), rfl, ?_, ?_⟩
  · intro b hb
    simp at hb; subst hb
    refine ⟨rfl, ?_⟩
    simp only [Leaf.payout, Bool.false_or]
    cases exact <;> simp
  · intro b hb
    simp at hb; subst hb
    exact ha

/-! ### JOIN (section 7.3) -/

/-- What `JOIN_h` accepts: one step whose old node is the hard-coded `E_h`
and whose new node is the grafted `(new_hash, new_sum)`, output 0 carrying
the new sum, and the operator's authorisation. -/
structure Join (auth : Prop) (h : Nat) (r : Node H) (path : List (Bool × Node H)) (new : Node H)
    (r' : Node H) (out0 : Nat) : Prop where
  step : (Step.mk h path (Tree.emptyNode h) new).valid r r'
  out0_eq : out0 = r'.sum
  authorised : auth

/-- **A join fills an empty subtree and adds exactly the grafted sum.** The
subtree at the position the path identifies is empty (by `root_inj`: no
non-empty tree has root `E_h`), output 0 equals the input amount plus the
grafted sum (the increase must come from other inputs, section 7.3 rule 3),
and if the grafted node is the root of a real subtree `u`, output 0 commits
to the tree with `u` grafted in, so every leaf of `u` is thereafter payable
by `payable`. If the grafted node has *no* preimage tree, the sum is still
conserved but nothing below it can ever be proven: the value is frozen.
Section 9.2 therefore requires joiners to verify their own paths inside the
subtree before funding the join. -/
theorem join_sound {auth : Prop} {d h : Nat} (t : Tree d) (path : List (Bool × Node H))
    (new r' : Node H) (out0 : Nat) (hwf : path.length + h = d)
    (hj : Join auth h t.root path new r' out0) :
    ∃ p : Pos d h, t.getSub p = Tree.empty h ∧
      out0 = t.root.sum + new.sum ∧
      ∀ u : Tree h, u.root = new → r' = (t.setSub p u).root := by
  obtain ⟨p, hold, hnew⟩ := Step.sound t (Step.mk h path (Tree.emptyNode h) new) r' hwf hj.step
  refine ⟨p, Tree.eq_empty_of_root _ hold.symm, ?_, hnew⟩
  have hs := Step.sum _ _ _ hj.step
  simp only [Tree.emptyNode_sum] at hs
  rw [hj.out0_eq]; omega

/-! ### UPDATE (section 7.4) -/

structure Update (auth : Prop) (r : Node H) (path : List (Bool × Node H)) (old new : Leaf)
    (r' : Node H) (out0 : Nat) : Prop where
  step : (leafStep path (some old) (some new)).valid r r'
  out0_eq : out0 = r'.sum
  authorised : auth

/-- **An update replaces exactly one leaf** and moves the output amount by
the difference of the two amounts. -/
theorem update_sound {auth : Prop} {d : Nat} (t : Tree d) (path : List (Bool × Node H))
    (old new : Leaf) (r' : Node H) (out0 : Nat) (hwf : path.length = d)
    (hu : Update auth t.root path old new r' out0) :
    ∃ p : Pos d 0, t.get p = some old ∧ r' = (t.set p (some new)).root ∧
      out0 + old.amount = t.root.sum + new.amount := by
  obtain ⟨p, hget, hr'⟩ := leafStep_sound t path (some old) (some new) r'
    (by simp [Step.WF, leafStep, hwf]) hu.step
  refine ⟨p, hget, hr', ?_⟩
  have hs := Step.sum _ _ _ hu.step
  simp [leafStep] at hs
  rw [hu.out0_eq]; omega

/-! ### CLAIM (section 7.5) -/

/-- The source leaf after a claim of `v`: amount reduced, `seq` advanced,
or the position emptied when drained (rule 2). -/
def claimedSource (src : Leaf) (v : Nat) : Option Leaf :=
  if src.amount = v then none
  else some { src with amount := src.amount - v, seq := src.seq + 1 }

theorem claimedSource_amount (src : Leaf) (v : Nat) (hv : v ≤ src.amount) :
    (leafNode (claimedSource src v) : Node H).sum + v = src.amount := by
  unfold claimedSource
  split
  · simp; omega
  · simp; omega

/-- What `CLAIM` accepts: the source step then the claim step (rules 2 and
3), output 0 carrying the final sum, the voucher authorisation, and the
carve rule (rule 5): the claim leaf keeps the source's evictor key and a
lease no longer than the source's, so nothing carved out of a leaf is
harder to evict than the leaf itself.

`auth` is opaque, so this structure covers both voucher forms of the spec.
Plain `CLAIM` (7.5) instantiates it with "`voucher_sig` verifies under
`src.owner_key` over `H_voucher(tree_id ‖ src ‖ claim)`"; the hash-locked
`CLAIM^h` (7.5.1) instantiates it with "`preimage` is 32 bytes and
`voucher_sig` verifies under `src.owner_key` over
`H_voucher_h(tree_id ‖ src ‖ claim ‖ SHA256(preimage))`". The hash lock changes
who may redeem and when, never what the redemption does to the tree, so
`claim_sound` below applies verbatim to both and the model needs no case
for the variant. -/
structure Claim (auth : Prop) (r : Node H) (srcPath claimPath : List (Bool × Node H))
    (src claim : Leaf) (r' : Node H) (out0 : Nat) : Prop where
  amount_le : claim.amount ≤ src.amount
  evictorKey_eq : claim.evictorKey = src.evictorKey
  evictAfter_le : claim.evictAfter ≤ src.evictAfter
  steps : Steps r [leafStep srcPath (some src) (claimedSource src claim.amount),
                   leafStep claimPath none (some claim)] r'
  out0_eq : out0 = r'.sum
  authorised : auth

/-- **A carve is never easier to keep than its source** (rule 5): whoever
may evict the source leaf at height `h` may evict the claim leaf there too,
with the same key. Eviction is therefore a property of a balance, not of
one leaf: no sequence of carves escapes it. -/
theorem claim_evictable {auth : Prop} {r r' : Node H}
    {srcPath claimPath : List (Bool × Node H)} {src claim : Leaf} {out0 : Nat}
    (hc : Claim auth r srcPath claimPath src claim r' out0)
    (h : Nat) (hsrc : src.evictAfter ≤ h) :
    claim.evictorKey = src.evictorKey ∧ claim.evictAfter ≤ h :=
  ⟨hc.evictorKey_eq, Nat.le_trans hc.evictAfter_le hsrc⟩

/-- **A claim conserves the total** (rule 4) and **rewrites exactly the
source and claim positions**: the source position held the source leaf,
the claim position was empty *after* the source step (so a drained source
may be re-used as the claim position, and nothing else), and output 0
commits to the tree with both rewritten. -/
theorem claim_sound {auth : Prop} {d : Nat} (t : Tree d) (srcPath claimPath : List (Bool × Node H))
    (src claim : Leaf) (r' : Node H) (out0 : Nat)
    (hwf₁ : srcPath.length = d) (hwf₂ : claimPath.length = d)
    (hc : Claim auth t.root srcPath claimPath src claim r' out0) :
    out0 = t.root.sum ∧
    ∃ (p₁ p₂ : Pos d 0), t.get p₁ = some src ∧
      (t.set p₁ (claimedSource src claim.amount)).get p₂ = none ∧
      r' = ((t.set p₁ (claimedSource src claim.amount)).set p₂ (some claim)).root := by
  cases hc.steps with
  | cons hv₁ hrest =>
    cases hrest with
    | cons hv₂ hnil =>
      cases hnil
      obtain ⟨p₁, hget₁, hr₁⟩ := leafStep_sound t srcPath (some src) _ _
        (by simp [Step.WF, leafStep, hwf₁]) hv₁
      subst hr₁
      obtain ⟨p₂, hget₂, hr₂⟩ := leafStep_sound _ claimPath none (some claim) _
        (by simp [Step.WF, leafStep, hwf₂]) hv₂
      refine ⟨?_, p₁, p₂, hget₁, hget₂, hr₂⟩
      have h₁ := Step.sum _ _ _ hv₁
      have h₂ := Step.sum _ _ _ hv₂
      have h₃ := claimedSource_amount (H := H) src claim.amount hc.amount_le
      simp [leafStep] at h₁ h₂
      rw [hc.out0_eq]; omega

/-! ### Terminal exit (section 7.8) -/

/-- The two branches of the `FINAL` macro (section 7.8). On the terminal
branch the script compares `r'` with the constant `E_D` of the tree's
depth and leaves output 0 unconstrained; otherwise output 0 must carry
`r'.sum` (rule 7.1.5). `terminal` is the branch the script took. -/
def Final (d : Nat) (r' : Node H) (out0 : Nat) (terminal : Bool) : Prop :=
  if terminal then r' = Tree.emptyNode d else out0 = r'.sum

/-- `EXIT_K` with the terminal branch made explicit: the same steps,
payouts and authorisation as `ExitK`, with `Final` in place of the
unconditional `out0 = r'.sum`. -/
structure ExitKT (exact : Bool) (d : Nat) (r : Node H) (blocks : List (ExitBlock H))
    (r' : Node H) (out0 : Nat) (terminal : Bool) : Prop where
  steps : Steps r (blocks.map ExitBlock.step) r'
  final : Final d r' out0 terminal
  payouts : ∀ b ∈ blocks, b.payoutOk exact
  auth : ∀ b ∈ blocks, b.authorised

/-- Off the terminal branch, `ExitKT` is `ExitK`: every earlier theorem
applies unchanged. -/
theorem ExitKT.nonterminal {exact : Bool} {d : Nat} {r r' : Node H} {blocks : List (ExitBlock H)}
    {out0 : Nat} (h : ExitKT exact d r blocks r' out0 false) : ExitK exact r blocks r' out0 :=
  ⟨h.steps, h.final, h.payouts, h.auth⟩

/-- **The terminal branch is reachable only from an empty tree.** Whatever
tree output 0 would have committed to on the terminal branch, it holds no
leaf at any position: by `root_inj` the only tree with root `E_D` is the
empty tree. This is the spec's "non-terminal exit taking the terminal
branch" negative: an `EXIT` that leaves any leaf behind cannot take it. -/
theorem terminal_no_leaf {d : Nat} {r' : Node H} {out0 : Nat} (hf : Final d r' out0 true)
    (t' : Tree d) (ht : t'.root = r') (q : Pos d 0) : t'.get q = none := by
  have h : t' = Tree.empty d := Tree.eq_empty_of_root t' (ht.trans hf)
  rw [h]; exact Tree.get_empty q

/-- **Conservation with no tree output.** On the terminal branch the
payouts account for the whole input amount: at most `S` in general (the
remainder is fee, 7.2 rule 3), exactly `S` in `EXIT_K^=`. Holds for any
`K`, by `Steps.sum` and `E_D.sum = 0`. -/
theorem ExitKT.terminal_conservation {exact : Bool} {d : Nat} {r r' : Node H}
    {blocks : List (ExitBlock H)} {out0 : Nat} (h : ExitKT exact d r blocks r' out0 true) :
    payoutSum blocks ≤ r.sum ∧ (exact = true → payoutSum blocks = r.sum) := by
  have hs := h.steps.sum
  rw [oldSum_exit, newSum_exit] at hs
  have h0 : r'.sum = 0 := by
    have hf : r' = Tree.emptyNode d := h.final
    rw [hf]; exact Tree.emptyNode_sum d
  have hp := payoutSum_le exact blocks h.payouts
  refine ⟨by omega, fun he => ?_⟩
  subst he
  have := payoutSum_eq blocks h.payouts
  omega

/-- **A terminal single exit removes the last leaf.** The exited leaf sits
at some position, every other position of the tree was already empty, the
leaf's amount is the whole input amount, and the tree output disappears:
there is no `r'.sum` for output 0 to carry. -/
theorem ExitKT.single_terminal {exact : Bool} {d : Nat} (t : Tree d) (b : ExitBlock H)
    {r' : Node H} {out0 : Nat} (hwf : b.step.WF d)
    (h : ExitKT exact d t.root [b] r' out0 true) :
    ∃ p : Pos d 0, t.get p = some b.leaf ∧ (∀ q, q ≠ p → t.get q = none) ∧
      b.leaf.amount = t.root.sum := by
  cases h.steps with
  | cons hv hrest =>
    cases hrest
    obtain ⟨p, hget, hr'⟩ := leafStep_sound t b.path (some b.leaf) none _ hwf hv
    refine ⟨p, hget, fun q hq => ?_, ?_⟩
    · rw [← Tree.get_set_ne t p q none (Ne.symm hq)]
      exact terminal_no_leaf h.final _ hr'.symm q
    · have hs := Step.sum _ _ _ hv
      have h0 : r'.sum = 0 := by
        have hf : r' = Tree.emptyNode d := h.final
        rw [hf]; exact Tree.emptyNode_sum d
      simp [ExitBlock.step, leafStep] at hs
      omega

/-! ### Sparse positions (section 5.4)

In the sparse profile a leaf's position is
`pos(leaf) = int_le(H_pos(owner_key ‖ le32(nonce))) mod 2^D`. The model
does not compute the hash: `pos` is an arbitrary function from
`(owner_key, nonce)` to leaf positions, and everything below uses only
that it is a function. The scripts derive the direction bits of the path
from the leaf, which the model states as `path.map Prod.fst = (pos …).dirs`.
-/

/-- A tree is sparse under `pos` when every leaf sits at its derived
position. The empty tree is sparse, and `sparseJoin_sound` shows a sparse
`JOIN_0` preserves it, so every tree reachable in the sparse profile is. -/
def Tree.Sparse {d : Nat} (pos : Nat → Nat → Pos d 0) (t : Tree d) : Prop :=
  ∀ (p : Pos d 0) (l : Leaf), t.get p = some l → p = pos l.ownerKey l.nonce

theorem Tree.Sparse.empty {d : Nat} (pos : Nat → Nat → Pos d 0) : (Tree.empty d).Sparse pos := by
  intro p l h; rw [Tree.get_empty] at h; cases h

/-- **Structural uniqueness** (section 5.2): in a sparse tree two leaves with
the same `(owner_key, nonce)` are the same leaf at the same position, so no
tree holds two of them. -/
theorem Tree.Sparse.unique {d : Nat} {pos : Nat → Nat → Pos d 0} {t : Tree d} (hs : t.Sparse pos)
    {p₁ p₂ : Pos d 0} {l₁ l₂ : Leaf} (h₁ : t.get p₁ = some l₁) (h₂ : t.get p₂ = some l₂)
    (hk : l₁.ownerKey = l₂.ownerKey) (hn : l₁.nonce = l₂.nonce) : p₁ = p₂ ∧ l₁ = l₂ := by
  have e₁ := hs p₁ l₁ h₁
  have e₂ := hs p₂ l₂ h₂
  have hp : p₁ = p₂ := by rw [e₁, e₂, hk, hn]
  subst hp
  rw [h₁] at h₂
  exact ⟨rfl, Option.some.inj h₂⟩

/-- **Non-inclusion by an `E_0` proof**: in a sparse tree, an empty derived
position means no leaf with that `(owner_key, nonce)` is in the tree. -/
theorem Tree.Sparse.absent {d : Nat} {pos : Nat → Nat → Pos d 0} {t : Tree d} (hs : t.Sparse pos)
    {k n : Nat} (he : t.get (pos k n) = none) (p : Pos d 0) (l : Leaf) (hl : t.get p = some l) :
    ¬ (l.ownerKey = k ∧ l.nonce = n) := by
  rintro ⟨hk, hn⟩
  have := hs p l hl
  rw [hk, hn] at this
  rw [← this] at he
  rw [hl] at he
  cases he

/-- What the sparse-profile `JOIN_0` accepts: a `Join` of the leaf node at
height 0 whose path's direction bits are those the script derives from the
leaf. -/
structure SparseJoin (auth : Prop) {d : Nat} (pos : Nat → Nat → Pos d 0) (r : Node H)
    (path : List (Bool × Node H)) (l : Leaf) (r' : Node H) (out0 : Nat) : Prop where
  join : Join auth 0 r path (leafNode (some l)) r' out0
  dirs : path.map Prod.fst = (pos l.ownerKey l.nonce).dirs

/-- **A sparse join lands at the derived position, which was empty.** The
`E_0` proof is a proof against the position `pos(leaf)` itself (the path's
direction bits determine the position, `Pos.dirs_inj`), that position held
no leaf, output 0 commits to the tree with the leaf there, the result is
again sparse, and the sum rises by the leaf amount. -/
theorem sparseJoin_sound {auth : Prop} {d : Nat} {pos : Nat → Nat → Pos d 0} (t : Tree d)
    (hs : t.Sparse pos) (path : List (Bool × Node H)) (l : Leaf) (r' : Node H) (out0 : Nat)
    (hwf : path.length = d) (hj : SparseJoin auth pos t.root path l r' out0) :
    t.get (pos l.ownerKey l.nonce) = none ∧
      r' = (t.set (pos l.ownerKey l.nonce) (some l)).root ∧
      (t.set (pos l.ownerKey l.nonce) (some l)).Sparse pos ∧
      out0 = t.root.sum + l.amount := by
  have hv₁ : fold (leafNode none) path = t.root := hj.join.step.1
  have hv₂ : fold (leafNode (some l)) path = r' := hj.join.step.2
  obtain ⟨h, p, hold, hπ⟩ := Tree.fold_sound t _ path hv₁
  have hlen := Tree.pathSub_length t p
  have hh : h = 0 := by rw [hπ] at hwf; omega
  subst hh
  have hp : p = pos l.ownerKey l.nonce := by
    apply Pos.dirs_inj
    rw [← Tree.pathSub_dirs t p, ← hπ, hj.dirs]
  subst hp
  refine ⟨?_, ?_, ?_, ?_⟩
  · unfold Tree.get
    revert hold
    cases t.getSub (pos l.ownerKey l.nonce) with
    | tip o => intro hold; exact (leafNode_inj (H := H) hold).symm
  · rw [← hv₂, hπ]; exact Tree.fold_setSub t _ (Tree.tip (some l))
  · intro q l' hq
    by_cases hqp : q = pos l.ownerKey l.nonce
    · subst hqp
      rw [Tree.get_set] at hq
      rw [Option.some.inj hq]
    · rw [Tree.get_set_ne t _ q _ (Ne.symm hqp)] at hq
      exact hs q l' hq
  · have hsum := Step.sum _ _ _ hj.join.step
    simp only [Tree.emptyNode_sum, leafNode_some] at hsum
    rw [hj.join.out0_eq]; omega

end LayerTree
