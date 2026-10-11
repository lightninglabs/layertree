package txn

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/btcsuite/btcd/txscript"

	"github.com/roasbeef/layertree/tree"
)

// TestTapTreeGolden checks the ordered taptree against spec/golden.json:
// the FULL D = 4 reference set plus EVICT_SUBTREE_2 has the golden scripts,
// leaf hashes and root, and every leaf's inclusion proof opens the output
// key of a tree output, for every taptree size from one leaf to all of them
// (odd sizes exercise the node that is carried up unpaired).
func TestTapTreeGolden(t *testing.T) {
	g := loadGolden(t)
	var golden struct {
		TaptreeFullD4 struct {
			LeafHashes []string `json:"leaf_hashes"`
			MerkleRoot string   `json:"merkle_root"`
		} `json:"taptree_full_d4"`
	}
	raw, err := os.ReadFile(filepath.Join("..", "spec", "golden.json"))
	if err != nil {
		t.Fatalf("read golden.json: %v", err)
	}
	if err := json.Unmarshal(raw, &golden); err != nil {
		t.Fatalf("parse golden.json: %v", err)
	}
	want := golden.TaptreeFullD4

	w := newWorld(t, caseSpec{tier: Full, depth: 4, variants: []string{"EVICT_SUBTREE_2"}})
	tt := w.st.TapTree
	if len(tt.Leaves) != len(want.LeafHashes) {
		t.Fatalf("taptree has %d leaves, want %d", len(tt.Leaves),
			len(want.LeafHashes))
	}
	for i := range tt.Leaves {
		leaf := &tt.Leaves[i]
		h := leaf.Hash()
		if got := hex.EncodeToString(h[:]); got != want.LeafHashes[i] {
			t.Fatalf("leaf %d (%s) hash %s, want %s", i, leaf.Name,
				got, want.LeafHashes[i])
		}
		gs, ok := g.Scripts["FULL/D/D4/"+leaf.Name]
		if !ok || hex.EncodeToString(leaf.Script) != gs.Hex {
			t.Fatalf("%s differs from the golden script", leaf.Name)
		}
	}
	root := tt.Root()
	if got := hex.EncodeToString(root[:]); got != want.MerkleRoot {
		t.Fatalf("taptree root %s, want %s", got, want.MerkleRoot)
	}

	rootHash := sha256.Sum256([]byte("some state"))
	for n := 1; n <= len(tt.Leaves); n++ {
		sub, err := NewTapTree(tt.Leaves[:n])
		if err != nil {
			t.Fatalf("NewTapTree: %v", err)
		}
		m := sub.Root()
		spk, err := tree.ScriptPubKey(rootHash, m)
		if err != nil {
			t.Fatalf("ScriptPubKey: %v", err)
		}
		for i := 0; i < n; i++ {
			cb, err := TreeControlBlock(
				rootHash, m, sub.Leaves[i].Version,
				sub.InclusionProof(i),
			)
			if err != nil {
				t.Fatalf("TreeControlBlock: %v", err)
			}
			parsed, err := txscript.ParseControlBlock(cb)
			if err != nil {
				t.Fatalf("ParseControlBlock: %v", err)
			}
			err = txscript.VerifyTaprootLeafCommitment(
				parsed, spk[2:], sub.Leaves[i].Script,
			)
			if err != nil {
				t.Fatalf("%d leaves, leaf %d: %v", n, i, err)
			}
		}
	}

	if _, err := NewTapTree(append(tt.Leaves[:1:1], tt.Leaves[0])); err == nil {
		t.Fatal("a taptree with a repeated leaf name was accepted")
	}
}
