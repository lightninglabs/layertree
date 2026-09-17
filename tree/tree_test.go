package tree

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

type vecNode struct {
	Hash string `json:"hash"`
	Sum  uint64 `json:"sum"`
}

type vecLeaf struct {
	Amount     uint64 `json:"amount"`
	ExitKey    string `json:"exit_key"`
	OwnerKey   string `json:"owner_key"`
	EvictorKey string `json:"evictor_key"`
	EvictAfter uint32 `json:"evict_after"`
	Nonce      uint32 `json:"nonce"`
	Seq        uint32 `json:"seq"`
	Serialized string `json:"serialized"`
	LeafHash   string `json:"leaf_hash"`
}

type vectors struct {
	EmptyNodes  []vecNode `json:"empty_nodes"`
	ExampleTree struct {
		Depth        int                `json:"depth"`
		Leaves       map[string]vecLeaf `json:"leaves"`
		Root         vecNode            `json:"root"`
		InternalKey  string             `json:"internal_key"`
		MerkleRoot   string             `json:"merkle_root_placeholder"`
		OutputKey    string             `json:"output_key"`
		ScriptPubKey string             `json:"scriptPubKey"`
		Paths        map[string][]struct {
			Dir     int     `json:"dir"`
			Sibling vecNode `json:"sibling"`
			Sc      string  `json:"sc"`
		} `json:"paths"`
	} `json:"example_tree"`
	TransitionExit struct {
		Slot    uint64  `json:"slot"`
		NewRoot vecNode `json:"new_root"`
	} `json:"transition_exit"`
	TransitionClaim struct {
		SourceSlot uint64  `json:"source_slot"`
		ClaimSlot  uint64  `json:"claim_slot"`
		ClaimLeaf  vecLeaf `json:"claim_leaf"`
		VoucherMsg string  `json:"voucher_msg"`
	} `json:"transition_claim"`
	SparseExample struct {
		Depth     int               `json:"depth"`
		Positions map[string]uint64 `json:"positions"`
	} `json:"sparse_example"`
}

func mustHex32(t *testing.T, s string) [32]byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 32 {
		t.Fatalf("bad hex32 %q", s)
	}
	var out [32]byte
	copy(out[:], b)
	return out
}

func leafFromVec(t *testing.T, v vecLeaf) *Leaf {
	return &Leaf{Amount: v.Amount, ExitKey: mustHex32(t, v.ExitKey), OwnerKey: mustHex32(t, v.OwnerKey),
		EvictorKey: mustHex32(t, v.EvictorKey), EvictAfter: v.EvictAfter, Nonce: v.Nonce, Seq: v.Seq}
}

func loadVectors(t *testing.T) *vectors {
	t.Helper()
	b, err := os.ReadFile("../spec/test-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v vectors
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	return &v
}

func TestEmptyNodes(t *testing.T) {
	v := loadVectors(t)
	for h, n := range v.EmptyNodes {
		got := EmptyNode(h)
		if hex.EncodeToString(got.Hash[:]) != n.Hash || got.Sum != n.Sum {
			t.Fatalf("E_%d mismatch: got %x want %s", h, got.Hash, n.Hash)
		}
	}
}

func TestLeafAndTreeVectors(t *testing.T) {
	v := loadVectors(t)
	ex := v.ExampleTree
	tr := New(ex.Depth)
	for slot, lv := range ex.Leaves {
		l := leafFromVec(t, lv)
		if hex.EncodeToString(l.Serialize()) != lv.Serialized {
			t.Fatalf("leaf %s serialization mismatch", slot)
		}
		h := l.Hash()
		if hex.EncodeToString(h[:]) != lv.LeafHash {
			t.Fatalf("leaf %s hash mismatch", slot)
		}
		var pos uint64
		for _, c := range slot {
			pos = pos*10 + uint64(c-'0')
		}
		tr.Leaves[pos] = l
	}
	root := tr.Root()
	if hex.EncodeToString(root.Hash[:]) != ex.Root.Hash || root.Sum != ex.Root.Sum {
		t.Fatalf("root mismatch: %x/%d", root.Hash, root.Sum)
	}
	for slot, steps := range ex.Paths {
		var pos uint64
		for _, c := range slot {
			pos = pos*10 + uint64(c-'0')
		}
		path := tr.Path(pos, 0)
		if len(path) != len(steps) {
			t.Fatalf("path %s length", slot)
		}
		for k, s := range steps {
			if (path[k].Dir != (s.Dir == 1)) || hex.EncodeToString(path[k].Sibling.Encode()) != s.Sc {
				t.Fatalf("path %s level %d mismatch", slot, k)
			}
		}
		if Fold(tr.Leaves[pos].Node(), path) != root {
			t.Fatalf("fold %s != root", slot)
		}
	}
	// exit transition: fold E_0 over bob's path gives the new root
	path := tr.Path(v.TransitionExit.Slot, 0)
	nr := Fold(EmptyLeaf, path)
	if hex.EncodeToString(nr.Hash[:]) != v.TransitionExit.NewRoot.Hash || nr.Sum != v.TransitionExit.NewRoot.Sum {
		t.Fatalf("exit new root mismatch")
	}
	// taproot binding
	rootHash := mustHex32(t, ex.Root.Hash)
	ik, err := InternalKey(rootHash)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(ik.SerializeCompressed()) != ex.InternalKey {
		t.Fatalf("internal key mismatch: %x", ik.SerializeCompressed())
	}
	spk, err := ScriptPubKey(rootHash, mustHex32(t, ex.MerkleRoot))
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(spk) != ex.ScriptPubKey {
		t.Fatalf("scriptPubKey mismatch: %x", spk)
	}
	// voucher message
	src := tr.Leaves[v.TransitionClaim.SourceSlot]
	claim := leafFromVec(t, v.TransitionClaim.ClaimLeaf)
	vm := VoucherMsg(mustHex32(t, ex.MerkleRoot), src, claim)
	if hex.EncodeToString(vm[:]) != v.TransitionClaim.VoucherMsg {
		t.Fatalf("voucher msg mismatch")
	}
	// sparse positions
	for _, lv := range ex.Leaves {
		l := leafFromVec(t, lv)
		key := lv.OwnerKey[:16]
		if want, ok := v.SparseExample.Positions[key]; ok {
			if got := l.Position(v.SparseExample.Depth); got != want {
				t.Fatalf("sparse position for %s: got %d want %d", key, got, want)
			}
		}
	}
}
