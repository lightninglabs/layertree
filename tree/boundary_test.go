package tree

import (
	"fmt"
	"testing"
)

// The right endpoint of a depth-64 tree cannot be represented by uint64,
// although every position in the tree can be.
func TestTreePositionBoundaries(t *testing.T) {
	key := mustHex32(t, "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
	for _, depth := range []int{0, 1, 16, 32, 63, 64} {
		t.Run(fmt.Sprintf("depth_%d", depth), func(t *testing.T) {
			tr := New(depth)
			positions := []uint64{0}
			if depth > 0 {
				positions = append(positions, ^uint64(0)>>uint(64-depth))
			}
			if depth > 1 {
				positions = append(positions, 1, uint64(1)<<uint(depth-1))
			}
			var total uint64
			for i, pos := range positions {
				leaf := &Leaf{
					Amount:   uint64(i+1) * 100_000,
					OwnerKey: key, ExitKey: key, EvictorKey: key,
					Nonce: uint32(i + 1),
				}
				if err := leaf.Validate(); err != nil {
					t.Fatal(err)
				}
				tr.Leaves[pos] = leaf
				total += leaf.Amount
			}
			root := tr.Root()
			if root.Sum != total {
				t.Fatalf("root sum %d, want %d", root.Sum, total)
			}
			// Independently computed by tools/layertree_ref.py, whose
			// integer interval endpoints do not overflow at 2^64.
			if depth == 64 {
				want := mustHex32(t, "e55a5922fcbac3d06fea536531d57471e9e0e726a2a9e5aabfe9513fa6af668d")
				if root.Hash != want {
					t.Fatalf("depth-64 root %x differs from Python %x", root.Hash, want)
				}
			}
			for _, pos := range positions {
				leaf := tr.Leaves[pos]
				if got := tr.Subtree(0, pos); got != leaf.Node() {
					t.Fatalf("leaf at %d is missing from its subtree", pos)
				}
				path := tr.Path(pos, 0)
				folded, err := Fold(leaf.Node(), path)
				if err != nil || folded != root {
					t.Fatalf("position %d proof does not match root: %v", pos, err)
				}
				after := tr.Clone()
				delete(after.Leaves, pos)
				removed, err := Fold(EmptyLeaf, path)
				if err != nil || removed != after.Root() || removed.Sum != total-leaf.Amount {
					t.Fatalf("position %d removal does not match successor: %v", pos, err)
				}
			}
		})
	}
}
