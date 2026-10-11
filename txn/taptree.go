package txn

import (
	"fmt"

	"github.com/roasbeef/layertree/script"
)

// TapLeaf is one transition script of a tree's taptree, under the name the
// generators use for it ("EXIT_1", "JOIN_2", "UPDATE_X", ...).
type TapLeaf struct {
	Name    string
	Script  []byte
	Version byte
}

// Hash is the leaf's BIP-341 tapleaf hash.
func (l *TapLeaf) Hash() [32]byte {
	return TapleafHash(l.Script, l.Version)
}

// TapTree is an ordered taptree of transition scripts. Its shape is the
// balanced one of script.TapTreeRoot and tools/layertree_ref.py taptree_root
// (adjacent leaves paired, an odd leaf carried up unchanged), so its root is
// the m a tree with this script set commits to (spec 6.3), and the order of
// the leaves is part of the tree's identity.
type TapTree struct {
	Leaves []TapLeaf

	hashes [][32]byte
}

// NewTapTree returns the taptree over leaves, in the given order. Leaf names
// must be unique, since the builders look scripts up by name.
func NewTapTree(leaves []TapLeaf) (*TapTree, error) {
	if len(leaves) == 0 {
		return nil, fmt.Errorf("txn: empty taptree")
	}
	t := &TapTree{Leaves: leaves, hashes: make([][32]byte, len(leaves))}
	seen := make(map[string]bool, len(leaves))
	for i := range leaves {
		if seen[leaves[i].Name] {
			return nil, fmt.Errorf("txn: duplicate taptree leaf %q",
				leaves[i].Name)
		}
		seen[leaves[i].Name] = true
		t.hashes[i] = leaves[i].Hash()
	}
	return t, nil
}

// Root is the taptree root m.
func (t *TapTree) Root() [32]byte {
	return script.TapTreeRoot(t.hashes)
}

// Find returns the index of the leaf with the given name.
func (t *TapTree) Find(name string) (int, error) {
	for i := range t.Leaves {
		if t.Leaves[i].Name == name {
			return i, nil
		}
	}
	return 0, fmt.Errorf("txn: taptree has no %s script", name)
}

// InclusionProof returns the BIP-341 inclusion proof of leaf i: the sibling
// hash at every level where leaf i's branch is paired, bottom up. A level at
// which the branch is the odd node carried up contributes nothing.
func (t *TapTree) InclusionProof(i int) []byte {
	var proof []byte
	level := append([][32]byte(nil), t.hashes...)
	for len(level) > 1 {
		if sib := i ^ 1; sib < len(level) {
			proof = append(proof, level[sib][:]...)
		}
		next := make([][32]byte, 0, (len(level)+1)/2)
		for j := 0; j+1 < len(level); j += 2 {
			next = append(next, script.TapBranch(level[j], level[j+1]))
		}
		if len(level)%2 == 1 {
			next = append(next, level[len(level)-1])
		}
		level = next
		i >>= 1
	}
	return proof
}

// FullReferenceLeaves returns the FULL-tier reference script set of a tree in
// the order tools/layertree_scripts.py all_scripts emits it: EXIT_K for each
// exitKs, JOIN_h for each joinHeights (dense) or JOIN_0 (sparse), JOINK_K for
// each joinKs, UPDATE and CLAIM. treeID is the tree's voucher binding (spec
// 6.2), a constant of CLAIM, and dustMin its DUST_MIN (zero meaning
// tree.DustMin). Tree-creation variants (UPDATE_X, CLAIM_H,
// SPLIT, EVICT_SUBTREE_h) are appended by the caller, or swapped in for the
// script they replace, exactly as the Python suites do.
func FullReferenceLeaves(depth int, operatorKey, treeID [32]byte, sparse bool,
	joinHeights, exitKs, joinKs []int, dustMin uint64) ([]TapLeaf, error) {

	all := script.FullAllScripts(
		depth, operatorKey, treeID, sparse, joinHeights, exitKs, joinKs,
		dustMin,
	)
	var names []string
	for _, k := range exitKs {
		names = append(names, fmt.Sprintf("EXIT_%d", k))
	}
	if sparse {
		joinHeights = []int{0}
	}
	for _, h := range joinHeights {
		names = append(names, fmt.Sprintf("JOIN_%d", h))
	}
	for _, k := range joinKs {
		names = append(names, fmt.Sprintf("JOINK_%d", k))
	}
	names = append(names, "UPDATE", "CLAIM")

	leaves := make([]TapLeaf, 0, len(names))
	for _, name := range names {
		leaf, err := FullLeaf(name, all[name])
		if err != nil {
			return nil, err
		}
		leaves = append(leaves, leaf)
	}
	return leaves, nil
}

// NewFullTapTree compiles the FULL-tier taptree of a tree of the given
// depth created with opts, in the order script.FullTreeOptions.Scripts
// emits it, so its Root is opts.TapTreeRoot(depth), the m of spec 6.2.
func NewFullTapTree(depth int, opts script.FullTreeOptions) (*TapTree, error) {
	return NewOptionsTapTree(depth, opts)
}

// NewOptionsTapTree compiles the taptree of a tree of the given depth
// created with opts in the tier the option set belongs to, in the order
// its Scripts emits, so its Root is opts.TapTreeRoot(depth), the m of spec
// 6.2 (m_h when depth is a DETACH_h child's).
func NewOptionsTapTree(depth int, opts Options) (*TapTree, error) {
	r, err := optionRules(opts)
	if err != nil {
		return nil, err
	}
	scripts := opts.Scripts(depth)
	leaves := make([]TapLeaf, 0, len(scripts))
	for _, s := range scripts {
		leaf, err := TierLeaf(r.tier, s.Name, s.Tokens)
		if err != nil {
			return nil, err
		}
		leaves = append(leaves, leaf)
	}
	return NewTapTree(leaves)
}

// FullLeaf assembles a FULL-tier token list into a 0xC2 taptree leaf.
func FullLeaf(name string, tokens []script.Token) (TapLeaf, error) {
	return TierLeaf(Full, name, tokens)
}

// TierLeaf assembles a token list into a taptree leaf of the tier: 0xC2
// numerics and leaf version for Full and CCV, 0xC0 for the others.
func TierLeaf(tier Tier, name string, tokens []script.Token) (TapLeaf, error) {
	if tokens == nil {
		return TapLeaf{}, fmt.Errorf("txn: no %s script %s", tier, name)
	}
	b, err := script.Assemble(tokens, tier.Mode())
	if err != nil {
		return TapLeaf{}, fmt.Errorf("txn: assemble %s: %w", name, err)
	}
	return TapLeaf{Name: name, Script: b, Version: tier.LeafVersion()}, nil
}
