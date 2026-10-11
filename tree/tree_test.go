package tree

import (
	"crypto/sha256"
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
		Depth       int                `json:"depth"`
		Leaves      map[string]vecLeaf `json:"leaves"`
		Root        vecNode            `json:"root"`
		InternalKey string             `json:"internal_key"`
		MerkleRoot  string             `json:"merkle_root_placeholder"`
		Creation    struct {
			Txid string `json:"txid"`
			Vout uint32 `json:"vout"`
		} `json:"creation_outpoint"`
		TreeID       string `json:"tree_id"`
		OutputKey    string `json:"output_key"`
		ScriptPubKey string `json:"scriptPubKey"`
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
		SourceSlot  uint64  `json:"source_slot"`
		ClaimSlot   uint64  `json:"claim_slot"`
		ClaimLeaf   vecLeaf `json:"claim_leaf"`
		VoucherMsg  string  `json:"voucher_msg"`
		Preimage    string  `json:"preimage"`
		PaymentHash string  `json:"payment_hash"`
		VoucherHMsg string  `json:"voucher_h_msg"`
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
		if folded, err := Fold(tr.Leaves[pos].Node(), path); err != nil || folded != root {
			t.Fatalf("fold %s != root (%v)", slot, err)
		}
	}
	// exit transition: fold E_0 over bob's path gives the new root
	path := tr.Path(v.TransitionExit.Slot, 0)
	nr, err := Fold(EmptyLeaf, path)
	if err != nil {
		t.Fatal(err)
	}
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
	// tree_id (spec 6.2): the RECOMMENDED derivation from the creation
	// outpoint, which the voucher messages below bind in place of m.
	treeID := TreeID(mustHex32(t, ex.Creation.Txid), ex.Creation.Vout)
	if hex.EncodeToString(treeID[:]) != ex.TreeID {
		t.Fatalf("tree_id mismatch: %x", treeID)
	}
	// voucher message
	src := tr.Leaves[v.TransitionClaim.SourceSlot]
	claim := leafFromVec(t, v.TransitionClaim.ClaimLeaf)
	vm := VoucherMsg(treeID, src, claim)
	if hex.EncodeToString(vm[:]) != v.TransitionClaim.VoucherMsg {
		t.Fatalf("voucher msg mismatch")
	}
	// hash-locked voucher message (spec 7.5.1): the payment hash in the
	// vector must be SHA256 of the vector's preimage, and the message must
	// match the reference implementation's.
	pre := mustHex32(t, v.TransitionClaim.Preimage)
	ph := sha256.Sum256(pre[:])
	if hex.EncodeToString(ph[:]) != v.TransitionClaim.PaymentHash {
		t.Fatalf("payment hash is not SHA256(preimage)")
	}
	vmh := VoucherHMsg(treeID, src, claim, ph)
	if hex.EncodeToString(vmh[:]) != v.TransitionClaim.VoucherHMsg {
		t.Fatalf("hash-locked voucher msg mismatch")
	}
	if vmh == vm {
		t.Fatalf("voucher tags collide: plain and hash-locked messages are equal")
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

// TestFoldRejectsOverflow is the probe of design/audit/go.md G1: a sibling
// whose sum is 2^64 - a + s folds with a leaf of amount a to a parent of
// sum s under wrapping arithmetic, which the Python reference (le64) and
// the FULL scripts both reject. Fold must fail on the carry.
func TestFoldRejectsOverflow(t *testing.T) {
	const amount = uint64(100_000_000)
	leaf := Node{Hash: sha256.Sum256([]byte("member")), Sum: amount}
	fake := Node{
		Hash: sha256.Sum256([]byte("fake")),
		Sum:  ^uint64(0) - amount + 1 + 330,
	}
	path := []PathStep{{Dir: false, Sibling: fake}}

	if _, err := Fold(leaf, path); err == nil {
		t.Fatalf("Fold accepted a path whose sum wraps past 2^64")
	}
	if _, err := AddSum(^uint64(0), 1); err == nil {
		t.Fatalf("AddSum accepted a carry")
	}
	if got, err := AddSum(^uint64(0)-1, 1); err != nil || got != ^uint64(0) {
		t.Fatalf("AddSum rejected 2^64 - 1: %v", err)
	}
}
