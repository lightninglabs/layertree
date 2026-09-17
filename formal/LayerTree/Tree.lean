import LayerTree.Leaf

/-!
# The Merkle-sum tree

Sections 5.3 to 5.5 of the specification define the tree, its positions,
the sibling path of a position and the `fold` the covenant scripts compute
level by level (`LEVEL` in section 8.2). This module defines all of them
and proves the four facts the security argument of section 10.2 rests on:

* `fold_path` (completeness): the honest path of a position folds to the
  root. This is why every leaf holder can always build an `EXIT`.
* `fold_setSub` (update correctness): folding the *new* node along the old
  path yields the root of the *updated* tree. This is what makes the
  script's `FINAL` output the right tree, for every transition type.
* `root_sum` and `fold_sum`: the sum carried in a node is the sum of all
  leaf amounts below it, and a fold adds exactly the sibling sums. This is
  the conservation half of section 10.2.
* `fold_sound` (binding): any node and path that fold to the root *are* a
  subtree's root and its honest path. This is the "every provable leaf is a
  real leaf" half of section 10.2, and it is the only place where the hash
  assumptions of `LayerTree.Hash` are used.

## Conventions

* Depth is a type index: `Tree d` is a perfect binary tree with `2^d`
  positions. A `Tree 0` is a single position (`tip`), empty or holding a
  leaf.
* A position is a list of directions from the root. `Pos d h` is a path
  from depth `d` down to a subtree of height `h`; `Pos d 0` addresses a
  leaf position. `cons false p` goes left, `cons true p` goes right. The
  spec's integer position `i` at depth `D` corresponds to the bits of `i`
  from most significant (top) to least significant (bottom); the spec's
  `dir` witness bit for level `k` is bit `k`, i.e. the direction taken at
  height `k`, and `dir = true` means the node being proved is the *right*
  child.
* A sibling path is a list of `(dir, sibling node)` pairs. In this module
  it is ordered **root first**. The witness of section 8 supplies the same
  pairs **leaf first**, because the script consumes the deepest level
  first; the two orders are reverses of each other and nothing below
  depends on which one the wire uses.
-/

namespace LayerTree

variable {H : Type} [M : HashModel Leaf H]

/-- A perfect binary tree of depth `d` (section 5.4). -/
inductive Tree : Nat → Type
  /-- A single position, empty (`none`) or holding a leaf. -/
  | tip : Option Leaf → Tree 0
  /-- Two subtrees of equal depth. -/
  | bin {d : Nat} : Tree d → Tree d → Tree (d + 1)

/-- A path from depth `d` to a subtree of height `h`; `Pos d 0` addresses a
leaf position. -/
inductive Pos : Nat → Nat → Type
  | nil {h : Nat} : Pos h h
  | cons {d h : Nat} : Bool → Pos d h → Pos (d + 1) h
  deriving DecidableEq

/-- A path never descends below height 0 and never ends higher than it
starts: `Pos d h` is inhabited only when `h ≤ d`. Needed to dismiss the
impossible `cons` constructor when a path is known to be at its end. -/
theorem Pos.height_le : {d h : Nat} → Pos d h → h ≤ d
  | _, _, .nil => Nat.le_refl _
  | _, _, .cons _ p => Nat.le_succ_of_le (Pos.height_le p)

/-- The parent of two nodes (section 5.3): hash both children with their
sums, and add the sums. -/
def parent (a b : Node H) : Node H :=
  ⟨M.hNode a.hash a.sum b.hash b.sum, a.sum + b.sum⟩

@[simp] theorem parent_sum (a b : Node H) : (parent a b).sum = a.sum + b.sum := rfl
@[simp] theorem parent_hash (a b : Node H) :
    (parent a b).hash = M.hNode a.hash a.sum b.hash b.sum := rfl

namespace Tree

/-- The root node of a tree (section 5.4): a leaf node at a tip, the parent
of the two child roots otherwise. -/
def root : {d : Nat} → Tree d → Node H
  | _, tip o => leafNode o
  | _, bin l r => parent l.root r.root

@[simp] theorem root_tip (o : Option Leaf) : (tip o).root = (leafNode o : Node H) := rfl
@[simp] theorem root_bin {d : Nat} (l r : Tree d) :
    (bin l r).root = (parent l.root r.root : Node H) := rfl

/-- The sum of every leaf amount in the tree. -/
def total : {d : Nat} → Tree d → Nat
  | _, tip none => 0
  | _, tip (some l) => l.amount
  | _, bin l r => l.total + r.total

/-- **Conservation, structural half**: the sum carried by the root is the
total of all leaf amounts (section 5.3). -/
theorem root_sum : {d : Nat} → (t : Tree d) → (t.root : Node H).sum = t.total
  | _, tip none => rfl
  | _, tip (some _) => rfl
  | _, bin l r => by simp [root, total, root_sum l, root_sum r]

/-- The tree with every position empty. Its root is the spec's `E_d`
(section 5.3). -/
def empty : (d : Nat) → Tree d
  | 0 => tip none
  | d + 1 => bin (empty d) (empty d)

/-- The spec's `E_h`: the root of the empty tree of height `h`. The script
generators hard-code these constants (`EMPTY_LEAF_HASH`, and `e_h` in
`join_block`). -/
def emptyNode (h : Nat) : Node H := (empty h).root

theorem emptyNode_sum (h : Nat) : (emptyNode h : Node H).sum = 0 := by
  induction h with
  | zero => rfl
  | succ h ih => simp [emptyNode, empty] at *; exact ih

/-- The subtree of height `h` addressed by `p`. -/
def getSub : {d h : Nat} → Tree d → Pos d h → Tree h
  | _, _, t, .nil => t
  | _, _, bin l r, .cons b p => getSub (if b then r else l) p

/-- The tree with the subtree at `p` replaced by `s`. -/
def setSub : {d h : Nat} → Tree d → Pos d h → Tree h → Tree d
  | _, _, _, .nil, s => s
  | _, _, bin l r, .cons b p, s => if b then bin l (setSub r p s) else bin (setSub l p s) r

/-- The sibling path of `p`, root first (section 5.5): at each level, the
direction taken and the root of the sibling *not* taken. -/
def pathSub : {d h : Nat} → Tree d → Pos d h → List (Bool × Node H)
  | _, _, _, .nil => []
  | _, _, bin l r, .cons b p => (b, (if b then l else r).root) :: pathSub (if b then r else l) p

/-- Leaf-position wrappers. -/
def get {d : Nat} (t : Tree d) (p : Pos d 0) : Option Leaf :=
  match t.getSub p with
  | tip o => o

def set {d : Nat} (t : Tree d) (p : Pos d 0) (o : Option Leaf) : Tree d :=
  t.setSub p (tip o)

def path {d : Nat} (t : Tree d) (p : Pos d 0) : List (Bool × Node H) :=
  t.pathSub p

@[simp] theorem getSub_setSub {d h : Nat} (t : Tree d) (p : Pos d h) (s : Tree h) :
    (t.setSub p s).getSub p = s := by
  induction p with
  | nil => simp [setSub, getSub]
  | cons b p ih =>
    cases t with
    | bin l r => cases b <;> simp [setSub, getSub, ih]

@[simp] theorem pathSub_setSub {d h : Nat} (t : Tree d) (p : Pos d h) (s : Tree h) :
    ((t.setSub p s).pathSub p : List (Bool × Node H)) = t.pathSub p := by
  induction p with
  | nil => simp [setSub, pathSub]
  | cons b p ih =>
    cases t with
    | bin l r => cases b <;> simp [setSub, pathSub, ih]

/-- Replacing a subtree leaves every *other* subtree of the same height
untouched. This is the "no leaf is disturbed by someone else's transition"
fact behind section 10.2. -/
theorem getSub_setSub_ne {d h : Nat} (t : Tree d) (p q : Pos d h) (s : Tree h) (hne : p ≠ q) :
    (t.setSub p s).getSub q = t.getSub q := by
  induction p with
  | nil =>
    cases q with
    | nil => exact absurd rfl hne
    | cons c q => exact absurd (Pos.height_le q) (Nat.not_succ_le_self _)
  | cons b p ih =>
    cases t with
    | bin l r =>
      cases q with
      | nil => exact absurd (Pos.height_le p) (Nat.not_succ_le_self _)
      | cons c q =>
        cases b <;> cases c <;> simp [setSub, getSub]
        · exact ih l q s (fun h => hne (h ▸ rfl))
        · exact ih r q s (fun h => hne (h ▸ rfl))

theorem get_set_ne {d : Nat} (t : Tree d) (p q : Pos d 0) (o : Option Leaf) (hne : p ≠ q) :
    (t.set p o).get q = t.get q := by
  simp [get, set, getSub_setSub_ne t p q _ hne]

@[simp] theorem get_set {d : Nat} (t : Tree d) (p : Pos d 0) (o : Option Leaf) :
    (t.set p o).get p = o := by simp [get, set]

end Tree

/-- One level of `fold` (the `LEVEL` macro of section 8.2): combine the
node being proved with its sibling in the order the direction bit gives.
`dir = true` means the proved node is the right child. -/
def combine (n : Node H) (x : Bool × Node H) : Node H :=
  if x.1 then parent x.2 n else parent n x.2

/-- Fold a node up a root-first sibling path to the root it implies
(section 5.5). Root first means the head of the list is the top level, so
the recursion folds the tail first and combines with the head last. -/
def fold (n : Node H) : List (Bool × Node H) → Node H
  | [] => n
  | x :: rest => combine (fold n rest) x

@[simp] theorem fold_nil (n : Node H) : fold n [] = n := rfl
@[simp] theorem fold_cons (n : Node H) (x : Bool × Node H) (rest : List (Bool × Node H)) :
    fold n (x :: rest) = combine (fold n rest) x := rfl

/-- **Conservation along a path**: a fold adds exactly the sibling sums.
Whatever node the prover starts from, the sum of the root it reaches is
that node's sum plus the sums it presented as siblings. -/
def sibSum : List (Bool × Node H) → Nat
  | [] => 0
  | x :: rest => x.2.sum + sibSum rest

theorem fold_sum (n : Node H) (π : List (Bool × Node H)) :
    (fold n π).sum = n.sum + sibSum π := by
  induction π with
  | nil => simp [sibSum]
  | cons x rest ih =>
    cases x with
    | mk b sib => cases b <;> simp [combine, sibSum, ih] <;> omega

namespace Tree

/-- **Completeness**: the honest path of a subtree folds its root to the
tree root. Hence every leaf holder can always produce the `CHECK_OLD`
witness of an `EXIT` (section 10.2, "every provable leaf can be paid"). -/
theorem fold_pathSub {d h : Nat} (t : Tree d) (p : Pos d h) :
    fold (t.getSub p).root (t.pathSub p) = (t.root : Node H) := by
  induction p with
  | nil => simp [getSub, pathSub]
  | cons b p ih =>
    cases t with
    | bin l r => cases b <;> simp [getSub, pathSub, combine, root, ih]

theorem fold_path {d : Nat} (t : Tree d) (p : Pos d 0) :
    fold (leafNode (t.get p)) (t.path p) = (t.root : Node H) := by
  have h := fold_pathSub t p
  unfold get path
  revert h
  cases t.getSub p with
  | tip o => intro h; simpa using h

/-- **Update correctness**: folding a *new* subtree root along the *old*
path gives the root of the tree with that subtree replaced. This is what
the scripts rely on when they compute the new root with the same
`LEVEL × D` loop that checked the old one (sections 7.1 rule 4 and 8.2). -/
theorem fold_setSub {d h : Nat} (t : Tree d) (p : Pos d h) (s : Tree h) :
    fold s.root (t.pathSub p) = ((t.setSub p s).root : Node H) := by
  induction p with
  | nil => simp [setSub, pathSub]
  | cons b p ih =>
    cases t with
    | bin l r => cases b <;> simp [setSub, pathSub, combine, ih]

theorem fold_set {d : Nat} (t : Tree d) (p : Pos d 0) (o : Option Leaf) :
    fold (leafNode o) (t.path p) = ((t.set p o).root : Node H) :=
  fold_setSub t p (tip o)

/-- **Roots bind trees**: two trees of the same depth with the same root are
the same tree. Uses `hLeaf_inj` at the tips and `hNode_inj` at every
internal level. -/
theorem root_inj : {d : Nat} → (t₁ t₂ : Tree d) → (t₁.root : Node H) = t₂.root → t₁ = t₂
  | _, tip o₁, tip o₂, h => by
    simp only [root] at h
    rw [leafNode_inj h]
  | _, bin l₁ r₁, bin l₂ r₂, h => by
    simp only [root, parent, Node.mk.injEq] at h
    obtain ⟨hl, hsl, hr, hsr⟩ := M.hNode_inj h.1
    have el : l₁ = l₂ := root_inj l₁ l₂ (Node.ext hl hsl)
    have er : r₁ = r₂ := root_inj r₁ r₂ (Node.ext hr hsr)
    rw [el, er]

/-- A subtree whose root is `E_h` is the empty tree. `JOIN_h` hard-codes
`E_h` as the old node, so this says a join only ever fills an empty
subtree (section 7.3 rule 1). -/
theorem eq_empty_of_root {h : Nat} (s : Tree h) (hs : (s.root : Node H) = emptyNode h) :
    s = empty h := root_inj s (empty h) hs

/-- **Binding (soundness)**: any node and path that fold to a tree's root
are the root of one of its subtrees and that subtree's honest path. In
particular the *sum* the prover presented is the true sum of that subtree,
and a leaf node that verifies is a leaf actually in the tree. This is the
theorem behind section 10.2 and it is the only consumer of the collision
and domain-separation axioms. -/
theorem fold_sound : {d : Nat} → (t : Tree d) → (m : Node H) → (π : List (Bool × Node H)) →
    fold m π = t.root → ∃ (h : Nat) (p : Pos d h), m = (t.getSub p).root ∧ π = t.pathSub p
  | d, t, m, [], hf => ⟨d, .nil, by simp [getSub]; simpa using hf, by simp [pathSub]⟩
  | _, tip o, m, (b, sib) :: rest, hf => by
    -- a non-empty path claims an internal node, but a tip's root is a leaf
    -- or the empty digest: domain separation rules it out.
    exfalso
    have hh := congrArg Node.hash hf
    cases o with
    | none => cases b <;> simp [combine, root, parent] at hh
        <;> exact M.hNode_ne_empty _ _ _ _ hh
    | some l => cases b <;> simp [combine, root, parent] at hh
        <;> exact M.hNode_ne_hLeaf _ _ _ _ _ hh
  | _, bin l r, m, (b, sib) :: rest, hf => by
    have hh := congrArg Node.hash hf
    have hs := congrArg Node.sum hf
    cases b with
    | false =>
      simp only [fold, combine, root, parent] at hh hs
      obtain ⟨h1, h2, h3, h4⟩ := M.hNode_inj hh
      have hfold : fold m rest = l.root := Node.ext h1 h2
      have hsib : sib = r.root := Node.ext h3 h4
      obtain ⟨h, p, hm, hπ⟩ := fold_sound l m rest hfold
      exact ⟨h, .cons false p, hm, by simp [pathSub, hπ, hsib]⟩
    | true =>
      simp only [fold, combine, root, parent] at hh hs
      obtain ⟨h1, h2, h3, h4⟩ := M.hNode_inj hh
      have hfold : fold m rest = r.root := Node.ext h3 h4
      have hsib : sib = l.root := Node.ext h1 h2
      obtain ⟨h, p, hm, hπ⟩ := fold_sound r m rest hfold
      exact ⟨h, .cons true p, hm, by simp [pathSub, hπ, hsib]⟩

/-- Soundness specialised to leaf positions: a leaf node that verifies
against the root with a path of full length `d` is the leaf at that
position. Stated with the path length so that the height is forced to 0
(a path of length `d` from depth `d` ends at a leaf). -/
theorem pathSub_length {d h : Nat} (t : Tree d) (p : Pos d h) :
    (t.pathSub p : List (Bool × Node H)).length + h = d := by
  induction p with
  | nil => simp [pathSub]
  | cons b p ih =>
    cases t with
    | bin l r =>
      cases b
      · have := ih l; simp [pathSub] at *; omega
      · have := ih r; simp [pathSub] at *; omega

end Tree

end LayerTree
