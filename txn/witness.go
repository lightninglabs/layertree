// Package txn builds, signs and witnesses the transactions that perform
// LayerTree transitions (spec/layertree.md sections 6, 7, 8.3-8.6 and 9).
//
// The witness builders in this file produce the *stack* part of a tapscript
// witness: the elements in bottom-to-top order, i.e. the order in which the
// interpreter pushes them before the script runs. The revealed script and the
// control block are appended by TapscriptSpend, not by these helpers.
//
// They are the Go counterpart of the witness assembly in
// tools/test_scripts.py (World.path_witness and the per-transition stacks).
package txn

import (
	"github.com/roasbeef/layertree/tree"
)

// dirElem encodes a path direction bit as a stack element: the empty element
// for a left-hand node (dir = 0) and 0x01 for a right-hand node (dir = 1).
func dirElem(right bool) []byte {
	if right {
		return []byte{0x01}
	}
	return []byte{}
}

// boolElem encodes a boolean flag (is_evict) the same way.
func boolElem(b bool) []byte { return dirElem(b) }

// DensePathWitness renders a sibling path for the dense profile: for every
// level, from the top of the path (level D-1) down to its bottom, the pair
// `dir sc`, where sc is the 41-byte node encoding hash || enc64(sum)
// (spec 5.5, 8.3). The path argument is a tree.Tree.Path result, which runs
// bottom-up, so it is emitted in reverse.
func DensePathWitness(path []tree.PathStep) [][]byte {
	out := make([][]byte, 0, 2*len(path))
	for k := len(path) - 1; k >= 0; k-- {
		out = append(out, dirElem(path[k].Dir), path[k].Sibling.Encode())
	}
	return out
}

// SparsePathWitness renders a sibling path for the sparse profile: one
// element per level, top of the path first, with the empty element standing
// in for an empty sibling E_{h+k} (spec 5.5). height is the height of the
// path's first (bottom) level; directions are not supplied because the
// sparse scripts derive them from the leaf's position.
func SparsePathWitness(path []tree.PathStep, height int) [][]byte {
	comp := tree.CompressPath(path, height)
	out := make([][]byte, 0, len(comp))
	for k := len(comp) - 1; k >= 0; k-- {
		if comp[k] == nil {
			out = append(out, []byte{})
			continue
		}
		out = append(out, comp[k])
	}
	return out
}

// ExitBlock is one EXIT_K block: the rendered path followed by the leaf, the
// signature and the is_evict flag (spec 8.3). For EXIT_1 this is the whole
// stack below `r m`; use ExitWitness for that common case.
func ExitBlock(path [][]byte, leaf *tree.Leaf, sig []byte, isEvict bool) [][]byte {
	out := make([][]byte, 0, len(path)+3)
	out = append(out, path...)
	return append(out, leaf.Serialize(), sig, boolElem(isEvict))
}

// ExitWitness is the EXIT_1 stack: path, leaf, sig, is_evict, r, m
// (spec 7.2, 8.3). path is the output of DensePathWitness or
// SparsePathWitness.
func ExitWitness(path [][]byte, leaf *tree.Leaf, sig []byte, isEvict bool,
	rootHash, merkleRoot [32]byte) [][]byte {

	return append(ExitBlock(path, leaf, sig, isEvict),
		rootHash[:], merkleRoot[:])
}

// ExitKWitness is the EXIT_K stack: block_K … block_1 r m. blocks are given
// in transition order (block 1 first, the block the script processes first);
// it is block 1 that ends up nearest the top of the stack (spec 8.3).
func ExitKWitness(blocks [][][]byte, rootHash, merkleRoot [32]byte) [][]byte {
	var out [][]byte
	for i := len(blocks) - 1; i >= 0; i-- {
		out = append(out, blocks[i]...)
	}
	return append(out, rootHash[:], merkleRoot[:])
}

// JoinWitness is the dense JOIN_h stack: path, new_hash, le64(new_sum),
// operator_sig, r, m (spec 7.3, 8.4). The path starts at height h, so it has
// D-h levels.
func JoinWitness(path [][]byte, newNode tree.Node, operatorSig []byte,
	rootHash, merkleRoot [32]byte) [][]byte {

	out := make([][]byte, 0, len(path)+5)
	out = append(out, path...)
	return append(out, newNode.Hash[:], tree.Le64(newNode.Sum), operatorSig,
		rootHash[:], merkleRoot[:])
}

// JoinLeafWitness is the sparse JOIN_0 stack: path, leaf, operator_sig, r, m
// (spec 8.4). The sparse script derives the position from the leaf itself, so
// the node is supplied as the full leaf record rather than as hash and sum.
func JoinLeafWitness(path [][]byte, leaf *tree.Leaf, operatorSig []byte,
	rootHash, merkleRoot [32]byte) [][]byte {

	out := make([][]byte, 0, len(path)+4)
	out = append(out, path...)
	return append(out, leaf.Serialize(), operatorSig, rootHash[:],
		merkleRoot[:])
}

// JoinBlock is one JOINK_K block: the rendered path followed by the node,
// either as new_hash le64(new_sum) (dense) or as the leaf record (sparse,
// leaf != nil).
func JoinBlock(path [][]byte, node tree.Node, leaf *tree.Leaf) [][]byte {
	out := make([][]byte, 0, len(path)+2)
	out = append(out, path...)
	if leaf != nil {
		return append(out, leaf.Serialize())
	}
	return append(out, node.Hash[:], tree.Le64(node.Sum))
}

// JoinKWitness is the JOINK_K stack: block_K … block_1 operator_sig r m
// (spec 8.4). blocks are given in transition order (block 1 first).
func JoinKWitness(blocks [][][]byte, operatorSig []byte,
	rootHash, merkleRoot [32]byte) [][]byte {

	var out [][]byte
	for i := len(blocks) - 1; i >= 0; i-- {
		out = append(out, blocks[i]...)
	}
	return append(out, operatorSig, rootHash[:], merkleRoot[:])
}

// UpdateWitness is the UPDATE stack: path, old_leaf, new_leaf, owner_sig,
// operator_sig, r, m (spec 7.4, 8.5). owner_sig is by the owner key of the
// OLD leaf.
func UpdateWitness(path [][]byte, oldLeaf, newLeaf *tree.Leaf,
	ownerSig, operatorSig []byte, rootHash, merkleRoot [32]byte) [][]byte {

	out := make([][]byte, 0, len(path)+6)
	out = append(out, path...)
	return append(out, oldLeaf.Serialize(), newLeaf.Serialize(), ownerSig,
		operatorSig, rootHash[:], merkleRoot[:])
}

// UpdateXWitness is the UPDATE^x stack: path, old_leaf, new_leaf, owner_sig,
// operator_sig, exit_sig, r, m (spec 7.4 rule 5, 8.5). exit_sig sits directly
// above operator_sig, so the script consumes it first; it is a signature over
// the same transaction by the exit key of the OLD leaf, as owner_sig is by
// its owner key.
func UpdateXWitness(path [][]byte, oldLeaf, newLeaf *tree.Leaf,
	ownerSig, operatorSig, exitSig []byte,
	rootHash, merkleRoot [32]byte) [][]byte {

	out := make([][]byte, 0, len(path)+7)
	out = append(out, path...)
	return append(out, oldLeaf.Serialize(), newLeaf.Serialize(), ownerSig,
		operatorSig, exitSig, rootHash[:], merkleRoot[:])
}

// ClaimWitness is the CLAIM stack: claim_path, source_path, source_leaf,
// claim_leaf, voucher_sig, r, m (spec 7.5, 8.6). The claim path sits deeper
// in the stack because the script consumes it second: the source path is
// folded first to r1, and the claim path is folded over that.
//
// voucher_sig is a BIP-340 signature by the source leaf's owner key over
// tree.VoucherMsg(m, source, claim); it is checked with
// OP_CHECKSIGFROMSTACK, so it commits to no transaction.
func ClaimWitness(claimPath, sourcePath [][]byte, sourceLeaf, claimLeaf *tree.Leaf,
	voucherSig []byte, rootHash, merkleRoot [32]byte) [][]byte {

	out := make([][]byte, 0, len(claimPath)+len(sourcePath)+5)
	out = append(out, claimPath...)
	out = append(out, sourcePath...)
	return append(out, sourceLeaf.Serialize(), claimLeaf.Serialize(),
		voucherSig, rootHash[:], merkleRoot[:])
}

// ClaimHWitness is the CLAIM^h stack: claim_path, source_path, source_leaf,
// claim_leaf, voucher_sig, preimage, r, m (spec 7.5.1, 8.6.1): CLAIM's
// stack with the 32-byte preimage between voucher_sig and r.
func ClaimHWitness(claimPath, sourcePath [][]byte, sourceLeaf,
	claimLeaf *tree.Leaf, voucherSig []byte, preimage [32]byte,
	rootHash, merkleRoot [32]byte) [][]byte {

	out := ClaimWitness(
		claimPath, sourcePath, sourceLeaf, claimLeaf, voucherSig,
		rootHash, merkleRoot,
	)
	n := len(out)
	return append(out[:n-2:n-2], preimage[:], rootHash[:], merkleRoot[:])
}

// EvictSubtreeWitness is the EVICT_SUBTREE_h stack: path (from height h),
// leaf_{2^h-1} … leaf_0, operator_sig, r, m (spec 7.7, 8.7). leaves are given
// in slot order (slot 0 first) and emitted in reverse, so that leaf_0 ends up
// nearest the top of the stack. A nil entry stands for an empty position.
func EvictSubtreeWitness(path [][]byte, leaves []*tree.Leaf, operatorSig []byte,
	rootHash, merkleRoot [32]byte) [][]byte {

	out := make([][]byte, 0, len(path)+len(leaves)+3)
	out = append(out, path...)
	for i := len(leaves) - 1; i >= 0; i-- {
		if leaves[i] == nil {
			out = append(out, []byte{})
			continue
		}
		out = append(out, leaves[i].Serialize())
	}
	return append(out, operatorSig, rootHash[:], merkleRoot[:])
}
