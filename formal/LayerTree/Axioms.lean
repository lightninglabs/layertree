import LayerTree

/-!
# Axiom audit

`#print axioms` for the headline theorems. The expected output for each is
the three standard Lean axioms (`propext`, `Classical.choice`, `Quot.sound`)
and nothing else: in particular no `sorryAx`. The build fails if any
theorem below is missing; the CI job additionally greps this file's output
for `sorry`.
-/

open LayerTree

#print axioms Tree.fold_sound
#print axioms Tree.root_inj
#print axioms Steps.sound
#print axioms Steps.sum
#print axioms payable
#print axioms ExitK.no_inflation
#print axioms ExitK.exact_conservation
#print axioms ExitK.single_sound
#print axioms join_sound
#print axioms update_sound
#print axioms claim_sound
#print axioms claim_evictable
#print axioms terminal_no_leaf
#print axioms ExitKT.terminal_conservation
#print axioms ExitKT.single_terminal
#print axioms Tree.Sparse.unique
#print axioms Tree.Sparse.absent
#print axioms sparseJoin_sound
#print axioms Tree.sweepPayouts_total
#print axioms evictSubtree_sound
#print axioms rewrite_sound
#print axioms rewrite_exit_conservation
#print axioms detach_sound
#print axioms detach_member_payable
#print axioms witness_root_binds
#print axioms ccv_input_binds
#print axioms Encoding.serializeLeaf_inj
#print axioms Encoding.serializeNode_inj
#print axioms Encoding.enc64_eq_minimal
#print axioms Encoding.minimalLE_two_pow_32_length
#print axioms Encoding.scriptNum_two_pow_31_length
#print axioms Encoding.scriptNum_neg_max31_succ
