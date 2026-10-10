import LayerTree.Leaf

/-!
# Encodings

The hash model of `LayerTree.Hash` assumes that `H_leaf` and `H_node` are
injective. SHA-256 collision resistance gives injectivity of the *hash*;
this module supplies the other half, injectivity of the *serialisations*
the hashes are applied to (sections 5.2 and 5.3), together with the three
small numeric facts the scripts rely on:

* `enc64 n = le64 n || 0x01` is the minimal BIP-441 encoding of
  `n + 2^64` (section 5.3), which is what lets `PAD8` produce it with one
  `OP_ADD`;
* `SEQ_FINAL`: under BIP-441 numerics `2^32` needs five bytes, so a leaf
  with `seq = 0xFFFFFFFF` cannot be claimed (`CLAIM` checks `seq + 1` fits
  in four); under `CScriptNum` the same holds for `0x7FFFFFFF`, while
  `0xFFFFFFFF` decodes to a negative number whose successor *does* fit
  (sections 5.1, 5.2, 7.5, Appendix C.6.5).

Bytes are `Nat`s below 256; this keeps every proof inside `omega`'s
fragment (linear arithmetic with division and remainder by constants).
-/

namespace LayerTree.Encoding

/-- Little-endian, fixed width: `k` bytes of `n`. -/
def leBytes : Nat → Nat → List Nat
  | 0, _ => []
  | k + 1, n => (n % 256) :: leBytes k (n / 256)

@[simp] theorem leBytes_length (k n : Nat) : (leBytes k n).length = k := by
  induction k generalizing n with
  | zero => rfl
  | succ k ih => simp [leBytes, ih]

/-- The value a `leBytes k` string encodes. -/
def leVal : List Nat → Nat
  | [] => 0
  | b :: rest => b + 256 * leVal rest

/-- `leBytes` is a faithful encoding of every `n < 2^(8k)`. -/
theorem leVal_leBytes (k : Nat) : ∀ n, n < 2 ^ (8 * k) → leVal (leBytes k n) = n := by
  induction k with
  | zero => intro n hn; simp at hn; simp [leBytes, leVal, hn]
  | succ k ih =>
    intro n hn
    have h : n / 256 < 2 ^ (8 * k) := by
      rw [Nat.div_lt_iff_lt_mul (by omega)]
      have : 2 ^ (8 * (k + 1)) = 2 ^ (8 * k) * 256 := by
        rw [show 8 * (k + 1) = 8 * k + 8 from by omega, Nat.pow_add]
      omega
    simp [leBytes, leVal, ih (n / 256) h]
    omega

/-- **Fixed-width injectivity**: two numbers below `2^(8k)` with the same
`k`-byte little-endian encoding are equal. -/
theorem leBytes_inj (k : Nat) {n m : Nat} (hn : n < 2 ^ (8 * k)) (hm : m < 2 ^ (8 * k))
    (h : leBytes k n = leBytes k m) : n = m := by
  have := leVal_leBytes k n hn
  have := leVal_leBytes k m hm
  rw [h] at *
  omega

/-- `le64` and `le32` of the specification. -/
def le64 (n : Nat) : List Nat := leBytes 8 n
def le32 (n : Nat) : List Nat := leBytes 4 n

theorem le64_inj {n m : Nat} (hn : n < 2 ^ 64) (hm : m < 2 ^ 64) (h : le64 n = le64 m) : n = m :=
  leBytes_inj 8 hn hm h

/-! ## BIP-441 minimal unsigned numbers -/

/-- The minimal little-endian encoding of an unsigned number under BIP-441:
no trailing zero bytes, and `0` is the empty string. -/
def minimalLE (n : Nat) : List Nat :=
  if h : n = 0 then [] else (n % 256) :: minimalLE (n / 256)
decreasing_by omega

theorem minimalLE_zero : minimalLE 0 = [] := by simp [minimalLE]

theorem minimalLE_pos {n : Nat} (h : 0 < n) : minimalLE n = (n % 256) :: minimalLE (n / 256) := by
  rw [minimalLE]; simp [Nat.ne_of_gt h]

/-- **`enc64` is minimal** (section 5.3): for `n < 2^(8k)` the minimal
encoding of `n + 2^(8k)` is the `k`-byte little-endian `n` followed by a
single `0x01`. With `k = 8` this is `enc64 n = le64 n || 01`, and it is why
the script can produce `enc64` by adding `2^64` (`PAD8`). -/
theorem minimalLE_add_pow (k : Nat) : ∀ n, n < 2 ^ (8 * k) →
    minimalLE (n + 2 ^ (8 * k)) = leBytes k n ++ [1] := by
  induction k with
  | zero =>
    intro n hn
    simp at hn; subst hn
    simp [leBytes, minimalLE_pos (n := 1) (by omega), minimalLE_zero]
  | succ k ih =>
    intro n hn
    have hpow : 2 ^ (8 * (k + 1)) = 2 ^ (8 * k) * 256 := by
      rw [show 8 * (k + 1) = 8 * k + 8 from by omega, Nat.pow_add]
    have hpos : 0 < n + 2 ^ (8 * (k + 1)) := by
      have := Nat.pow_pos (n := 8 * (k + 1)) (by omega : 0 < 2); omega
    rw [minimalLE_pos hpos]
    have hmod : (n + 2 ^ (8 * (k + 1))) % 256 = n % 256 := by rw [hpow]; omega
    have hdiv : (n + 2 ^ (8 * (k + 1))) / 256 = n / 256 + 2 ^ (8 * k) := by rw [hpow]; omega
    have hlt : n / 256 < 2 ^ (8 * k) := by
      rw [Nat.div_lt_iff_lt_mul (by omega)]; omega
    rw [hmod, hdiv, ih (n / 256) hlt]
    simp [leBytes]

/-- The `enc64` of section 5.3. -/
def enc64 (n : Nat) : List Nat := le64 n ++ [1]

theorem enc64_eq_minimal (n : Nat) (hn : n < 2 ^ 64) : minimalLE (n + 2 ^ 64) = enc64 n :=
  minimalLE_add_pow 8 n hn

theorem enc64_inj {n m : Nat} (hn : n < 2 ^ 64) (hm : m < 2 ^ 64) (h : enc64 n = enc64 m) : n = m := by
  unfold enc64 at h
  exact le64_inj hn hm (List.append_inj_left h (by simp [le64]))

/-- **`SEQ_FINAL` in the FULL tier**: the minimal encoding of `2^32` has
five bytes, so `0xFFFFFFFF + 1` fails the `OP_SIZE 4 OP_LESSTHANOREQUAL`
check of the `CLAIM` script (section 8.6). -/
theorem minimalLE_two_pow_32_length : (minimalLE (2 ^ 32)).length = 5 := by
  have := minimalLE_add_pow 4 0 (by decide)
  simp at this
  rw [this]; rfl

/-- The neighbour below is claimable: `0xFFFFFFFF` itself fits in four
bytes. -/
theorem minimalLE_max32_length : (minimalLE (2 ^ 32 - 1)).length = 4 := by
  simp [minimalLE_pos (n := 2 ^ 32 - 1) (by decide), minimalLE_pos (n := (2 ^ 32 - 1) / 256) (by decide),
        minimalLE_pos (n := (2 ^ 32 - 1) / 256 / 256) (by decide),
        minimalLE_pos (n := (2 ^ 32 - 1) / 256 / 256 / 256) (by decide), minimalLE_zero]

/-! ## `CScriptNum` (the MID and MIN tiers) -/

/-- Minimal little-endian magnitude bytes of a natural number, with a
bounded recursion so that `decide` can evaluate it. -/
def magBytes (fuel : Nat) (n : Nat) : List Nat :=
  match fuel with
  | 0 => []
  | fuel + 1 => if n = 0 then [] else (n % 256) :: magBytes fuel (n / 256)

/-- The `CScriptNum` serialisation of an integer, as in Bitcoin Core: the
minimal magnitude bytes, then the sign bit set in the top byte, adding a
byte when the top magnitude byte already uses bit 7. -/
def scriptNum (z : Int) : List Nat :=
  if z = 0 then [] else
  let neg := z < 0
  let mag := magBytes 16 z.natAbs
  let top := mag.getLast? |>.getD 0
  if top ≥ 128 then mag ++ [if neg then 0x80 else 0x00]
  else mag.dropLast ++ [if neg then top + 0x80 else top]

/-- **`SEQ_FINAL` in the MID tier**: `2^31` needs five bytes as a
`CScriptNum` ... -/
theorem scriptNum_two_pow_31_length : (scriptNum (2 ^ 31)).length = 5 := by decide

/-- ... while `2^31 − 1` fits in four, so the marker is the largest
positive four-byte value. -/
theorem scriptNum_max31_length : (scriptNum (2 ^ 31 - 1)).length = 4 := by decide

/-- **Why `0xFFFFFFFF` is not a MID marker**: the four bytes `ff ff ff ff`
are the `CScriptNum` encoding of `−(2^31 − 1)`, and its successor
`−(2^31 − 2)` still encodes in four bytes (`fe ff ff ff`), so `CLAIM`
accepts it. The MID marker must therefore be `0x7FFFFFFF`
(Appendix C.6.5; `tools/test_mid.py` exercises both values). -/
theorem scriptNum_neg_max31 : scriptNum (-(2 ^ 31 - 1)) = [0xff, 0xff, 0xff, 0xff] := by decide

theorem scriptNum_neg_max31_succ : scriptNum (-(2 ^ 31 - 1) + 1) = [0xfe, 0xff, 0xff, 0xff] := by
  decide

/-! ### The `SEQ_FINAL` constants of `LayerTree.Leaf`

`Claim` (`LayerTree.Transitions`) requires `src.seq < seqFinal`, the
model's reading of "`seq + 1` must encode in four bytes". The two theorems
below say that `Leaf.seqFinalFull` and `Leaf.seqFinalMid` are the least
values for which that encoding fails in their tiers, so a leaf at
`SEQ_FINAL` is exactly the leaf that `claim_not_final` says is never a
source, and every lower `seq` has a four-byte successor. -/

/-- In FULL, `SEQ_FINAL + 1 = 2^32` needs five bytes, while `SEQ_FINAL`
itself fits in four. -/
theorem seqFinalFull_succ_length :
    (minimalLE (LayerTree.Leaf.seqFinalFull + 1)).length = 5 ∧
      (minimalLE LayerTree.Leaf.seqFinalFull).length = 4 :=
  ⟨by unfold LayerTree.Leaf.seqFinalFull; simpa using minimalLE_two_pow_32_length,
   minimalLE_max32_length⟩

/-- In MID, `SEQ_FINAL + 1 = 2^31` needs five bytes as a `CScriptNum`,
while `SEQ_FINAL` itself fits in four. -/
theorem seqFinalMid_succ_length :
    (scriptNum (LayerTree.Leaf.seqFinalMid + 1)).length = 5 ∧
      (scriptNum LayerTree.Leaf.seqFinalMid).length = 4 := by
  unfold LayerTree.Leaf.seqFinalMid
  exact ⟨by decide, by decide⟩

/-! ## `PADZ` (MID and MIN tiers, sections 4.5 and 8.2)

Without BIP-441 numerics a script cannot widen a number to a fixed-width
field, so the MID and MIN tiers take the field's value `x` as a minimal
`CScriptNum` and let the witness supply a zero pad `z` together with a
filler `w`. `PADZ` checks `z ‖ w = 00000000` and `size(x) + size(z) = 4`
and leaves `x ‖ z` on the stack. The theorems below say what that gadget
guarantees: for `x = scriptNum n` the result is `le32 n`, the pad is the
only one the gadget accepts for that `x`, and the gadget rejects every
`n ≥ 2^31`, which is where the tier's sum cap of 4.5 comes from. -/

/-- The `PADZ` gadget on stack `[x z w]`: `some (x ‖ z)` when the checks
pass, `none` when the script fails. -/
def padz (x z w : List Nat) : Option (List Nat) :=
  if z ++ w = List.replicate 4 0 ∧ x.length + z.length = 4 then some (x ++ z) else none

theorem padz_some {x z w out : List Nat} (h : padz x z w = some out) :
    z ++ w = List.replicate 4 0 ∧ x.length + z.length = 4 ∧ out = x ++ z := by
  by_cases hc : z ++ w = List.replicate 4 0 ∧ x.length + z.length = 4
  · rw [padz, if_pos hc] at h
    exact ⟨hc.1, hc.2, (Option.some.inj h).symm⟩
  · rw [padz, if_neg hc] at h
    cases h

/-- A prefix of a string of zeros is a string of zeros. -/
theorem eq_replicate_of_append_replicate : ∀ (l l' : List Nat) (n : Nat),
    l ++ l' = List.replicate n 0 → l = List.replicate l.length 0
  | [], _, _, _ => rfl
  | a :: l, l', n, h => by
    cases n with
    | zero => simp at h
    | succ n =>
      simp only [List.cons_append, List.replicate_succ, List.cons.injEq] at h
      obtain ⟨rfl, h2⟩ := h
      rw [List.length_cons, List.replicate_succ]
      exact congrArg (List.cons 0) (eq_replicate_of_append_replicate l l' n h2)

/-- **The pad is unique.** For a given `x`, `PADZ` accepts exactly one
`(z, w)`: `z` is `4 − size(x)` zero bytes and `w` the remaining zeros. A
witness therefore cannot choose a pad that changes the field. -/
theorem padz_unique {x z w z' w' out out' : List Nat} (h : padz x z w = some out)
    (h' : padz x z' w' = some out') : z = z' ∧ w = w' ∧ out = out' := by
  obtain ⟨hz, hl, rfl⟩ := padz_some h
  obtain ⟨hz', hl', rfl⟩ := padz_some h'
  have e1 := eq_replicate_of_append_replicate z w 4 hz
  have e2 := eq_replicate_of_append_replicate z' w' 4 hz'
  have hzz : z = z' := by
    rw [e1, e2]
    congr 1
    omega
  subst hzz
  refine ⟨rfl, ?_, rfl⟩
  rw [← hz'] at hz
  exact List.append_cancel_left hz

theorem leBytes_zero (k : Nat) : leBytes k 0 = List.replicate k 0 := by
  induction k with
  | zero => rfl
  | succ k ih => simp [leBytes, List.replicate_succ, ih]

theorem leBytes_four (n : Nat) :
    leBytes 4 n = [n % 256, n / 256 % 256, n / 256 / 256 % 256, n / 256 / 256 / 256 % 256] := rfl

/-- The minimal magnitude bytes of `n < 2^(8k)`, padded with zeros, are
its `k`-byte little-endian encoding. -/
theorem magBytes_pad : ∀ (k fuel n : Nat), k ≤ fuel → n < 2 ^ (8 * k) →
    ∃ j, magBytes fuel n ++ List.replicate j 0 = leBytes k n
  | 0, fuel, n, _, hn => by
    simp at hn; subst hn
    refine ⟨0, ?_⟩
    cases fuel <;> simp [magBytes, leBytes]
  | k + 1, fuel, n, hk, hn => by
    obtain ⟨f, rfl⟩ : ∃ f, fuel = f + 1 := ⟨fuel - 1, by omega⟩
    by_cases h0 : n = 0
    · subst h0
      exact ⟨k + 1, by simp [magBytes, leBytes_zero]⟩
    · have hpow : 2 ^ (8 * (k + 1)) = 2 ^ (8 * k) * 256 := by
        rw [show 8 * (k + 1) = 8 * k + 8 from by omega, Nat.pow_add]
      have hlt : n / 256 < 2 ^ (8 * k) := by
        rw [Nat.div_lt_iff_lt_mul (by omega)]; omega
      obtain ⟨j, hj⟩ := magBytes_pad k f (n / 256) (by omega) hlt
      exact ⟨j, by simp [magBytes, h0, leBytes, hj]⟩

/-- A number of at least `k + 1` bytes has at least `k + 1` magnitude
bytes (with enough fuel). -/
theorem magBytes_length_ge : ∀ (k fuel n : Nat), k < fuel → 2 ^ (8 * k) ≤ n →
    k + 1 ≤ (magBytes fuel n).length
  | 0, fuel, n, hk, hn => by
    obtain ⟨f, rfl⟩ : ∃ f, fuel = f + 1 := ⟨fuel - 1, by omega⟩
    simp at hn
    simp [magBytes, Nat.pos_iff_ne_zero.mp hn]
  | k + 1, fuel, n, hk, hn => by
    obtain ⟨f, rfl⟩ : ∃ f, fuel = f + 1 := ⟨fuel - 1, by omega⟩
    have hpow : 2 ^ (8 * (k + 1)) = 2 ^ (8 * k) * 256 := by
      rw [show 8 * (k + 1) = 8 * k + 8 from by omega, Nat.pow_add]
    have hpos : n ≠ 0 := by
      have := Nat.pow_pos (n := 8 * k) (by omega : 0 < 2); omega
    have hge : 2 ^ (8 * k) ≤ n / 256 := by
      rw [Nat.le_div_iff_mul_le (by omega)]; omega
    have := magBytes_length_ge k f (n / 256) (by omega) hge
    simp [magBytes, hpos]; omega

/-- `scriptNum` of a positive natural number: the magnitude bytes, with a
`0x00` appended when the top byte has bit 7 set. -/
theorem scriptNum_natCast (n : Nat) (hn : 0 < n) :
    scriptNum n = if 128 ≤ (magBytes 16 n).getLast?.getD 0 then magBytes 16 n ++ [0]
      else (magBytes 16 n).dropLast ++ [(magBytes 16 n).getLast?.getD 0] := by
  have hnn : ¬ ((n : Int) < 0) := Int.not_lt.mpr (Int.natCast_nonneg n)
  simp [scriptNum, Nat.pos_iff_ne_zero.mp hn, hnn]

theorem magBytes_ne_nil (fuel n : Nat) (hn : 0 < n) : magBytes (fuel + 1) n ≠ [] := by
  simp [magBytes, Nat.pos_iff_ne_zero.mp hn]

/-- If the `k`-byte encoding of `n < 2^32` ends in at least one pad byte,
`n < 2^24`. -/
theorem lt_of_pad_pos {n j : Nat} {mag : List Nat} (hj : mag ++ List.replicate j 0 = leBytes 4 n)
    (hlen : mag.length + j = 4) (hpos : 0 < j) (h32 : n < 2 ^ 32) : n < 2 ^ 24 := by
  have h3 : (mag ++ List.replicate j 0)[3]? = some 0 := by
    rw [List.getElem?_append_right (by omega), List.getElem?_replicate, if_pos (by omega)]
  rw [hj, leBytes_four] at h3
  simp at h3
  rw [show 2 ^ 32 = 4294967296 by rfl] at h32
  rw [show 2 ^ 24 = 16777216 by rfl]
  omega

/-- **`PADZ` reconstructs the field and enforces the cap.** Whenever the
gadget accepts `x = scriptNum n` with some pad, its result is `le32 n`,
and `n < 2^31`: a value of `2^31` or more has a five-byte `CScriptNum`,
which no pad brings to four. This is the fixed-width rule of 4.5 for
`evict_after`, `nonce`, `seq` and the sparse `pos_lo`, and the reason
every MID or MIN sum is below `2^31` satoshis. -/
theorem padz_scriptNum (n : Nat) {z w out : List Nat} (h : padz (scriptNum n) z w = some out) :
    out = leBytes 4 n ∧ n < 2 ^ 31 := by
  obtain ⟨hz, hl, rfl⟩ := padz_some h
  obtain ⟨m, rfl⟩ : ∃ m, z = List.replicate m 0 := ⟨_, eq_replicate_of_append_replicate z w 4 hz⟩
  simp only [List.length_replicate] at hl
  by_cases h0 : n = 0
  · subst h0
    have hs : scriptNum ((0 : Nat) : Int) = [] := by simp [scriptNum]
    rw [hs] at hl ⊢
    simp at hl
    subst hl
    rw [leBytes_zero]
    exact ⟨rfl, by decide⟩
  · have hpos := Nat.pos_of_ne_zero h0
    have hne := magBytes_ne_nil 15 n hpos
    have hmag : (magBytes 16 n).dropLast ++ [(magBytes 16 n).getLast?.getD 0] = magBytes 16 n := by
      rw [List.getLast?_eq_getLast hne, Option.getD_some]
      exact List.dropLast_concat_getLast hne
    rw [scriptNum_natCast n hpos, hmag] at hl ⊢
    by_cases h32 : n < 2 ^ 32
    · obtain ⟨j, hj⟩ := magBytes_pad 4 16 n (by omega) h32
      have hlen4 : (magBytes 16 n).length + j = 4 := by
        have := congrArg List.length hj; simpa using this
      have h31 : 2 ^ 31 = 2147483648 := rfl
      have h24 : 2 ^ 24 = 16777216 := rfl
      by_cases htop : 128 ≤ (magBytes 16 n).getLast?.getD 0
      · rw [if_pos htop] at hl ⊢
        simp at hl
        have hj1 : j = m + 1 := by omega
        subst hj1
        refine ⟨?_, ?_⟩
        · rw [← hj, List.replicate_succ]; simp
        · have := lt_of_pad_pos hj hlen4 (by omega) h32
          omega
      · rw [if_neg htop] at hl ⊢
        have hjz : (m : Nat) = j := by omega
        subst hjz
        refine ⟨hj, ?_⟩
        by_cases hj0 : (m : Nat) = 0
        · subst hj0
          simp at hj
          have hd : (leBytes 4 n).getLast?.getD 0 = n / 256 / 256 / 256 % 256 := rfl
          rw [hj, hd] at htop
          rw [show 2 ^ 32 = 4294967296 by rfl] at h32
          omega
        · have := lt_of_pad_pos hj hlen4 (by omega) h32
          omega
    · exfalso
      have h5 := magBytes_length_ge 4 16 n (by omega) (by omega)
      split at hl
      · simp at hl; omega
      · omega

/-! ## Leaf serialisation (section 5.2) -/

/-- The 116-byte leaf record: `le64 amount || be32 exit || be32 owner ||
be32 evictor || le32 evict_after || le32 nonce || le32 seq`. Keys are
32-byte big-endian x coordinates in the deployment; byte order does not
matter for injectivity, so we reuse the little-endian encoder. -/
def serializeLeaf (l : LayerTree.Leaf) : List Nat :=
  leBytes 8 l.amount ++ leBytes 32 l.exitKey ++ leBytes 32 l.ownerKey ++
  leBytes 32 l.evictorKey ++ leBytes 4 l.evictAfter ++ leBytes 4 l.nonce ++ leBytes 4 l.seq

theorem serializeLeaf_length (l : LayerTree.Leaf) : (serializeLeaf l).length = 116 := by
  simp [serializeLeaf]

/-- Peel one fixed-width field off two equal concatenations. -/
theorem append_inj_fixed {a b c d : List Nat} (hlen : a.length = c.length)
    (h : a ++ b = c ++ d) : a = c ∧ b = d :=
  ⟨List.append_inj_left h hlen, List.append_inj_right h hlen⟩

/-- **Leaf serialisation is injective** on well-formed leaves. Together
with SHA-256 collision resistance this discharges the `hLeaf_inj` field of
`LayerTree.HashModel`. -/
theorem serializeLeaf_inj {l₁ l₂ : LayerTree.Leaf} (h₁ : l₁.WF) (h₂ : l₂.WF)
    (h : serializeLeaf l₁ = serializeLeaf l₂) : l₁ = l₂ := by
  unfold serializeLeaf at h
  simp only [List.append_assoc] at h
  obtain ⟨e1, h⟩ := append_inj_fixed (by simp) h
  obtain ⟨e2, h⟩ := append_inj_fixed (by simp) h
  obtain ⟨e3, h⟩ := append_inj_fixed (by simp) h
  obtain ⟨e4, h⟩ := append_inj_fixed (by simp) h
  obtain ⟨e5, h⟩ := append_inj_fixed (by simp) h
  obtain ⟨e6, e7⟩ := append_inj_fixed (by simp) h
  have a1 := leBytes_inj 8 (by have := h₁.amount_lt; omega) (by have := h₂.amount_lt; omega) e1
  have a2 := leBytes_inj 32 h₁.exitKey_lt h₂.exitKey_lt e2
  have a3 := leBytes_inj 32 h₁.ownerKey_lt h₂.ownerKey_lt e3
  have a4 := leBytes_inj 32 h₁.evictorKey_lt h₂.evictorKey_lt e4
  have a5 := leBytes_inj 4 (by have := h₁.evictAfter_lt; omega) (by have := h₂.evictAfter_lt; omega) e5
  have a6 := leBytes_inj 4 h₁.nonce_lt h₂.nonce_lt e6
  have a7 := leBytes_inj 4 h₁.seq_lt h₂.seq_lt e7
  cases l₁; cases l₂
  simp only at a1 a2 a3 a4 a5 a6 a7
  subst a1 a2 a3 a4 a5 a6 a7
  rfl

/-! ## Node serialisation (section 5.3) -/

/-- The 82-byte preimage of `H_node`: `sc(left) || sc(right)` with
`sc = hash32 || enc64 sum`. Hashes are abstract here; we only need that
they are 32 bytes. -/
def serializeNode (lh : List Nat) (ls : Nat) (rh : List Nat) (rs : Nat) : List Nat :=
  lh ++ enc64 ls ++ rh ++ enc64 rs

/-- **Node serialisation is injective** for 32-byte hashes and sums below
`2^64`. Together with collision resistance this discharges `hNode_inj`. -/
theorem serializeNode_inj {lh₁ rh₁ lh₂ rh₂ : List Nat} {ls₁ rs₁ ls₂ rs₂ : Nat}
    (hl₁ : lh₁.length = 32) (hl₂ : lh₂.length = 32) (hr₁ : rh₁.length = 32) (hr₂ : rh₂.length = 32)
    (hs₁ : ls₁ < 2 ^ 64) (hs₂ : ls₂ < 2 ^ 64) (ht₁ : rs₁ < 2 ^ 64) (ht₂ : rs₂ < 2 ^ 64)
    (h : serializeNode lh₁ ls₁ rh₁ rs₁ = serializeNode lh₂ ls₂ rh₂ rs₂) :
    lh₁ = lh₂ ∧ ls₁ = ls₂ ∧ rh₁ = rh₂ ∧ rs₁ = rs₂ := by
  unfold serializeNode at h
  simp only [List.append_assoc] at h
  obtain ⟨e1, h⟩ := append_inj_fixed (by rw [hl₁, hl₂]) h
  obtain ⟨e2, h⟩ := append_inj_fixed (by simp [enc64, le64]) h
  obtain ⟨e3, e4⟩ := append_inj_fixed (by rw [hr₁, hr₂]) h
  exact ⟨e1, enc64_inj hs₁ hs₂ e2, e3, enc64_inj ht₁ ht₂ e4⟩

end LayerTree.Encoding
