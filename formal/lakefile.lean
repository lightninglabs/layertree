import Lake
open Lake DSL

/-!
Lake build configuration for the LayerTree formalisation.

The project deliberately depends on nothing but the Lean 4 core library:
no Mathlib, no Batteries. Everything the proofs need (`omega`, `simp`,
`decide`, the `List` and `Nat` lemmas) ships with the compiler, so the
development builds in seconds from a bare toolchain and does not pin the
repository to a Mathlib snapshot.
-/
package layertree where
  leanOptions := #[⟨`autoImplicit, false⟩]

@[default_target]
lean_lib LayerTree where
  roots := #[`LayerTree, `LayerTree.Axioms]
