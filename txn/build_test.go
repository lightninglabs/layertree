package txn

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"

	"github.com/roasbeef/layertree/script"
	"github.com/roasbeef/layertree/tree"
)

// -- spec/test-vectors.json ------------------------------------------------

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

type vecNode struct {
	Hash string `json:"hash"`
	Sum  uint64 `json:"sum"`
}

type vecStep struct {
	Dir     int     `json:"dir"`
	Sibling vecNode `json:"sibling"`
	SC      string  `json:"sc"`
}

type testVectors struct {
	ExampleTree struct {
		Depth                 int                  `json:"depth"`
		Leaves                map[string]vecLeaf   `json:"leaves"`
		Root                  vecNode              `json:"root"`
		MerkleRootPlaceholder string               `json:"merkle_root_placeholder"`
		ScriptPubKey          string               `json:"scriptPubKey"`
		Paths                 map[string][]vecStep `json:"paths"`
	} `json:"example_tree"`
	TransitionExit struct {
		Slot       uint64    `json:"slot"`
		Leaf       vecLeaf   `json:"leaf"`
		Path       []vecStep `json:"path"`
		OldRoot    vecNode   `json:"old_root"`
		NewRoot    vecNode   `json:"new_root"`
		ExitOutput struct {
			Amount       int64  `json:"amount"`
			ScriptPubKey string `json:"scriptPubKey"`
		} `json:"exit_output"`
		NewTreeScriptPubKey string `json:"new_tree_scriptPubKey"`
	} `json:"transition_exit"`
}

func loadVectors(t *testing.T) *testVectors {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "spec", "test-vectors.json"))
	if err != nil {
		t.Fatalf("read test-vectors.json: %v", err)
	}
	var v testVectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("parse test-vectors.json: %v", err)
	}
	return &v
}

func (v *vecLeaf) parse(t *testing.T) *tree.Leaf {
	t.Helper()
	leaf, err := tree.ParseLeaf(mustHex(t, v.Serialized))
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	if got := hex.EncodeToString(leaf.Serialize()); got != v.Serialized {
		t.Fatalf("leaf round trip mismatch:\n got %s\nwant %s", got,
			v.Serialized)
	}
	if got := leaf.Hash(); hex.EncodeToString(got[:]) != v.LeafHash {
		t.Fatalf("leaf hash mismatch: got %x want %s", got[:], v.LeafHash)
	}
	return leaf
}

// exampleTree rebuilds the example tree of the vectors.
func exampleTree(t *testing.T, v *testVectors) *tree.Tree {
	t.Helper()
	tr := tree.New(v.ExampleTree.Depth)
	for slot, leaf := range v.ExampleTree.Leaves {
		pos, err := strconv.ParseUint(slot, 10, 64)
		if err != nil {
			t.Fatalf("slot %q: %v", slot, err)
		}
		tr.Leaves[pos] = leaf.parse(t)
	}
	root := tr.Root()
	if got := hex.EncodeToString(root.Hash[:]); got != v.ExampleTree.Root.Hash {
		t.Fatalf("example root mismatch:\n got %s\nwant %s", got,
			v.ExampleTree.Root.Hash)
	}
	if root.Sum != v.ExampleTree.Root.Sum {
		t.Fatalf("example root sum = %d, want %d", root.Sum,
			v.ExampleTree.Root.Sum)
	}
	return tr
}

// -- tests -----------------------------------------------------------------

// TestExitPathWitness checks that DensePathWitness renders the vector's path
// in the order spec 8.3 requires: top level first, `dir sc` per level, with
// the empty element for dir = 0.
func TestExitPathWitness(t *testing.T) {
	v := loadVectors(t)
	tr := exampleTree(t, v)
	te := &v.TransitionExit

	path := tr.Path(te.Slot, 0)
	if len(path) != len(te.Path) {
		t.Fatalf("path has %d levels, want %d", len(path), len(te.Path))
	}
	for k, step := range path {
		want := te.Path[k]
		if step.Dir != (want.Dir == 1) {
			t.Fatalf("level %d: dir = %v, want %d", k, step.Dir,
				want.Dir)
		}
		if got := hex.EncodeToString(step.Sibling.Encode()); got != want.SC {
			t.Fatalf("level %d: sc = %s, want %s", k, got, want.SC)
		}
	}

	wit := DensePathWitness(path)
	if len(wit) != 2*len(path) {
		t.Fatalf("dense path witness has %d elements, want %d",
			len(wit), 2*len(path))
	}
	for k := range path {
		// Witness element pair k covers level len(path)-1-k.
		step := te.Path[len(path)-1-k]
		wantDir := []byte{}
		if step.Dir == 1 {
			wantDir = []byte{0x01}
		}
		if !bytes.Equal(wit[2*k], wantDir) {
			t.Fatalf("witness %d: dir = %x, want %x", 2*k,
				wit[2*k], wantDir)
		}
		if got := hex.EncodeToString(wit[2*k+1]); got != step.SC {
			t.Fatalf("witness %d: sc = %s, want %s", 2*k+1, got,
				step.SC)
		}
	}

	// The sparse rendering drops the directions and blanks out the two
	// empty siblings of this path.
	sparse := SparsePathWitness(path, 0)
	if len(sparse) != len(path) {
		t.Fatalf("sparse path witness has %d elements, want %d",
			len(sparse), len(path))
	}
	for k := range sparse {
		step := te.Path[len(path)-1-k]
		empty := tree.EmptyNode(len(path) - 1 - k)
		if hex.EncodeToString(empty.Encode()) == step.SC {
			if len(sparse[k]) != 0 {
				t.Fatalf("sparse witness %d: want empty "+
					"element, got %x", k, sparse[k])
			}
			continue
		}
		if got := hex.EncodeToString(sparse[k]); got != step.SC {
			t.Fatalf("sparse witness %d: sc = %s, want %s", k, got,
				step.SC)
		}
	}
}

// TestExitTransitionVector checks the EXIT_1 state transition of the vectors:
// removing the leaf yields the vector's new root, and output 0 of the
// spending transaction is the vector's recreated tree output.
func TestExitTransitionVector(t *testing.T) {
	v := loadVectors(t)
	tr := exampleTree(t, v)
	te := &v.TransitionExit
	m := mustHash32(t, v.ExampleTree.MerkleRootPlaceholder)

	oldRoot := tr.Root()
	if got := hex.EncodeToString(oldRoot.Hash[:]); got != te.OldRoot.Hash {
		t.Fatalf("old root mismatch: %s", got)
	}
	path := tr.Path(te.Slot, 0)
	leaf := te.Leaf.parse(t)

	// Spec 7.1 rule 3: folding the leaf over its path reproduces r.
	if got, err := tree.Fold(leaf.Node(), path); err != nil || got != oldRoot {
		t.Fatalf("fold of the old leaf does not reproduce the root")
	}

	// Rule 4: folding E_0 over the same path yields r'.
	newRoot, err := tree.Fold(tree.EmptyLeaf, path)
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(newRoot.Hash[:]); got != te.NewRoot.Hash {
		t.Fatalf("new root mismatch:\n got %s\nwant %s", got,
			te.NewRoot.Hash)
	}
	if newRoot.Sum != te.NewRoot.Sum {
		t.Fatalf("new root sum = %d, want %d", newRoot.Sum,
			te.NewRoot.Sum)
	}

	// Deleting the leaf from the tree must agree with the fold.
	next := tr.Clone()
	delete(next.Leaves, te.Slot)
	if got := next.Root(); got != newRoot {
		t.Fatalf("tree root after deletion != folded root")
	}

	b := &Builder{
		Tree: TreeInput{
			Amount:     int64(oldRoot.Sum),
			RootHash:   oldRoot.Hash,
			MerkleRoot: m,
		},
		NewRoot:   newRoot.Hash,
		NewAmount: int64(newRoot.Sum),
		Payouts: []Payout{{
			ExitKey: leaf.ExitKey,
			Amount:  te.ExitOutput.Amount,
		}},
	}
	tx, err := b.Tx()
	if err != nil {
		t.Fatalf("Tx: %v", err)
	}
	if got := hex.EncodeToString(tx.TxOut[0].PkScript); got != te.NewTreeScriptPubKey {
		t.Fatalf("output 0 spk mismatch:\n got %s\nwant %s", got,
			te.NewTreeScriptPubKey)
	}
	if got := hex.EncodeToString(tx.TxOut[1].PkScript); got != te.ExitOutput.ScriptPubKey {
		t.Fatalf("output 1 spk mismatch:\n got %s\nwant %s", got,
			te.ExitOutput.ScriptPubKey)
	}
	if tx.TxOut[1].Value != te.ExitOutput.Amount {
		t.Fatalf("output 1 amount = %d, want %d", tx.TxOut[1].Value,
			te.ExitOutput.Amount)
	}

	// The tree output being spent is the example tree's scriptPubKey.
	prevOut, err := b.Tree.TxOut()
	if err != nil {
		t.Fatalf("TxOut: %v", err)
	}
	if got := hex.EncodeToString(prevOut.PkScript); got != v.ExampleTree.ScriptPubKey {
		t.Fatalf("input 0 spk mismatch:\n got %s\nwant %s", got,
			v.ExampleTree.ScriptPubKey)
	}
}

// TestBuildSignExit1 builds, signs and witnesses a complete FULL-tier EXIT_1
// transaction for the example tree, with the exiting leaf's owner key
// replaced by one we hold the private key for.
func TestBuildSignExit1(t *testing.T) {
	v := loadVectors(t)
	te := &v.TransitionExit

	// Deterministic owner key: privkey = sha256("owner").
	seed := sha256.Sum256([]byte("owner"))
	privKey, pubKey := btcec.PrivKeyFromBytes(seed[:])
	var ownerKey [32]byte
	copy(ownerKey[:], schnorr.SerializePubKey(pubKey))

	tr := exampleTree(t, v)
	bob := te.Leaf.parse(t)
	bob.OwnerKey = ownerKey
	tr.Leaves[te.Slot] = bob
	if err := bob.Validate(); err != nil {
		t.Fatalf("leaf: %v", err)
	}

	oldRoot := tr.Root()
	path := tr.Path(te.Slot, 0)
	if len(path) != v.ExampleTree.Depth {
		t.Fatalf("path has %d levels, want %d", len(path),
			v.ExampleTree.Depth)
	}
	if got, err := tree.Fold(bob.Node(), path); err != nil || got != oldRoot {
		t.Fatal("fold of the leaf does not reproduce the root")
	}
	newRoot, err := tree.Fold(tree.EmptyLeaf, path)
	if err != nil {
		t.Fatal(err)
	}
	if newRoot.Sum != te.NewRoot.Sum {
		t.Fatalf("new root sum = %d, want %d", newRoot.Sum,
			te.NewRoot.Sum)
	}

	// A single-leaf taptree: the placeholder script stands in for the
	// EXIT_1 script of spec 8.3, so the taptree root m is just its tapleaf
	// hash and the inclusion proof is empty.
	spendScript := []byte{0x51}
	leafVersion := script.ModeC2.LeafVersion()
	if leafVersion != 0xc2 {
		t.Fatalf("FULL tier leaf version = 0x%02x, want 0xc2",
			leafVersion)
	}
	leafHash := TapleafHash(spendScript, leafVersion)
	m := leafHash

	treeOutPoint := wire.OutPoint{
		Hash:  chainhash.HashH([]byte("layertree funding")),
		Index: 0,
	}
	feeOutPoint := wire.OutPoint{
		Hash:  chainhash.HashH([]byte("fee input")),
		Index: 3,
	}
	const feeAmount = 5_000
	b := &Builder{
		LockTime: 800_000,
		Tree: TreeInput{
			OutPoint:   treeOutPoint,
			Amount:     int64(oldRoot.Sum),
			RootHash:   oldRoot.Hash,
			MerkleRoot: m,
		},
		NewRoot:   newRoot.Hash,
		NewAmount: int64(newRoot.Sum),
	}
	b.AddPayout(bob.ExitKey, int64(bob.Amount))
	b.AddExtraInput(feeOutPoint, 0xfffffffe, wire.NewTxOut(
		feeAmount, append([]byte{0x00, 0x14}, make([]byte, 20)...),
	))

	tx, err := b.Tx()
	if err != nil {
		t.Fatalf("Tx: %v", err)
	}
	prevOuts, err := b.PrevOuts()
	if err != nil {
		t.Fatalf("PrevOuts: %v", err)
	}

	// Transaction shape (spec 7.1).
	if len(tx.TxIn) != 2 || len(tx.TxOut) != 2 {
		t.Fatalf("tx has %d inputs and %d outputs, want 2 and 2",
			len(tx.TxIn), len(tx.TxOut))
	}
	if tx.TxIn[0].PreviousOutPoint != treeOutPoint {
		t.Fatal("input 0 does not spend the tree output")
	}
	if tx.TxIn[0].Sequence != TreeSequence {
		t.Fatalf("input 0 sequence = %#x, want %#x",
			tx.TxIn[0].Sequence, TreeSequence)
	}
	if tx.LockTime != 800_000 {
		t.Fatalf("locktime = %d", tx.LockTime)
	}
	wantSPK, err := tree.ScriptPubKey(newRoot.Hash, m)
	if err != nil {
		t.Fatalf("ScriptPubKey: %v", err)
	}
	if !bytes.Equal(tx.TxOut[0].PkScript, wantSPK) {
		t.Fatal("output 0 is not the recreated tree output")
	}
	if tx.TxOut[0].Value != int64(newRoot.Sum) {
		t.Fatalf("output 0 amount = %d, want %d", tx.TxOut[0].Value,
			newRoot.Sum)
	}
	if !bytes.Equal(tx.TxOut[1].PkScript, tree.P2TR(bob.ExitKey)) {
		t.Fatal("output 1 is not P2TR(exit_key)")
	}
	// Conservation: the tree output plus the payout equal the old total.
	if tx.TxOut[0].Value+tx.TxOut[1].Value != int64(oldRoot.Sum) {
		t.Fatal("value is not conserved across the transition")
	}

	// Sign input 0 for the revealed leaf, and check the signature.
	sighash, err := Sighash(tx, 0, prevOuts, leafHash)
	if err != nil {
		t.Fatalf("Sighash: %v", err)
	}
	manual, err := SighashManual(tx, 0, prevOuts, leafHash)
	if err != nil {
		t.Fatalf("SighashManual: %v", err)
	}
	if !bytes.Equal(sighash, manual) {
		t.Fatal("txscript and manual sighash disagree")
	}
	sig, err := SignSchnorr(privKey, sighash)
	if err != nil {
		t.Fatalf("SignSchnorr: %v", err)
	}
	if len(sig) != 64 {
		t.Fatalf("signature is %d bytes, want 64 (SIGHASH_DEFAULT)",
			len(sig))
	}
	parsedSig, err := schnorr.ParseSignature(sig)
	if err != nil {
		t.Fatalf("parse signature: %v", err)
	}
	ownerPub, err := schnorr.ParsePubKey(bob.OwnerKey[:])
	if err != nil {
		t.Fatalf("parse owner key: %v", err)
	}
	if !parsedSig.Verify(sighash, ownerPub) {
		t.Fatal("signature does not verify against the owner key")
	}

	// Assemble the witness: spec 8.3 for D = 4, owner exit.
	stack := ExitWitness(
		DensePathWitness(path), bob, sig, false, oldRoot.Hash, m,
	)
	ctrlBlock, err := TreeControlBlock(oldRoot.Hash, m, leafVersion, nil)
	if err != nil {
		t.Fatalf("TreeControlBlock: %v", err)
	}
	err = TapscriptSpend(
		tx, 0, prevOuts, spendScript, leafVersion, ctrlBlock, stack,
	)
	if err != nil {
		t.Fatalf("TapscriptSpend: %v", err)
	}

	// 2*D path elements + leaf + sig + is_evict + r + m, then the script
	// and the control block.
	wit := tx.TxIn[0].Witness
	wantLen := 2*v.ExampleTree.Depth + 5 + 2
	if len(wit) != wantLen {
		t.Fatalf("witness has %d elements, want %d", len(wit), wantLen)
	}
	for k := 0; k < v.ExampleTree.Depth; k++ {
		step := path[len(path)-1-k]
		wantDir := []byte{}
		if step.Dir {
			wantDir = []byte{0x01}
		}
		if !bytes.Equal(wit[2*k], wantDir) {
			t.Fatalf("witness %d: dir = %x, want %x", 2*k,
				wit[2*k], wantDir)
		}
		if !bytes.Equal(wit[2*k+1], step.Sibling.Encode()) {
			t.Fatalf("witness %d: wrong sibling encoding", 2*k+1)
		}
		if len(wit[2*k+1]) != 41 {
			t.Fatalf("witness %d: sc is %d bytes, want 41", 2*k+1,
				len(wit[2*k+1]))
		}
	}
	d := 2 * v.ExampleTree.Depth
	if !bytes.Equal(wit[d], bob.Serialize()) || len(wit[d]) != tree.LeafLen {
		t.Fatal("witness: element after the path is not the leaf")
	}
	if !bytes.Equal(wit[d+1], sig) {
		t.Fatal("witness: signature not in place")
	}
	if len(wit[d+2]) != 0 {
		t.Fatal("witness: is_evict must be the empty element")
	}
	if !bytes.Equal(wit[d+3], oldRoot.Hash[:]) {
		t.Fatal("witness: root hash not in place")
	}
	if !bytes.Equal(wit[d+4], m[:]) {
		t.Fatal("witness: taptree root not in place")
	}
	if !bytes.Equal(wit[d+5], spendScript) {
		t.Fatal("witness: script not in place")
	}
	if !bytes.Equal(wit[d+6], ctrlBlock) {
		t.Fatal("witness: control block not in place")
	}
	if len(ctrlBlock) != 33 {
		t.Fatalf("control block is %d bytes, want 33 for a "+
			"single-leaf taptree", len(ctrlBlock))
	}
	if ctrlBlock[0]&0xfe != leafVersion {
		t.Fatalf("control block leaf version = 0x%02x, want 0x%02x",
			ctrlBlock[0]&0xfe, leafVersion)
	}

	// An eviction witness differs only in the is_evict flag.
	evict := ExitWitness(
		DensePathWitness(path), bob, sig, true, oldRoot.Hash, m,
	)
	if !bytes.Equal(evict[d+2], []byte{0x01}) {
		t.Fatal("is_evict must be 0x01 for an eviction")
	}
}

// TestOtherWitnessLayouts checks the element counts and ordering of the
// remaining FULL-tier witnesses (spec 8.4 - 8.6).
func TestOtherWitnessLayouts(t *testing.T) {
	v := loadVectors(t)
	tr := exampleTree(t, v)
	root := tr.Root()
	m := mustHash32(t, v.ExampleTree.MerkleRootPlaceholder)
	sig := bytes.Repeat([]byte{0xaa}, 64)
	sig2 := bytes.Repeat([]byte{0xbb}, 64)

	leaf := v.TransitionExit.Leaf.parse(t)
	path := DensePathWitness(tr.Path(5, 0))

	// JOIN_2: the path starts at height 2, so it is shorter.
	joinPath := DensePathWitness(tr.Path(2<<2, 2))
	node := tr.Subtree(2, 2)
	join := JoinWitness(joinPath, node, sig, root.Hash, m)
	if len(join) != len(joinPath)+5 {
		t.Fatalf("JOIN witness has %d elements, want %d", len(join),
			len(joinPath)+5)
	}
	if !bytes.Equal(join[len(joinPath)], node.Hash[:]) {
		t.Fatal("JOIN: new_hash not in place")
	}
	if !bytes.Equal(join[len(joinPath)+1], tree.Le64(node.Sum)) {
		t.Fatal("JOIN: le64(new_sum) not in place")
	}
	if len(join[len(joinPath)+1]) != 8 {
		t.Fatal("JOIN: new_sum must be 8 bytes")
	}

	sparseJoin := JoinLeafWitness(path, leaf, sig, root.Hash, m)
	if len(sparseJoin) != len(path)+4 {
		t.Fatalf("sparse JOIN witness has %d elements, want %d",
			len(sparseJoin), len(path)+4)
	}

	upd := UpdateWitness(path, leaf, leaf, sig, sig2, root.Hash, m)
	if len(upd) != len(path)+6 {
		t.Fatalf("UPDATE witness has %d elements, want %d", len(upd),
			len(path)+6)
	}
	if !bytes.Equal(upd[len(path)+2], sig) ||
		!bytes.Equal(upd[len(path)+3], sig2) {

		t.Fatal("UPDATE: owner_sig must precede operator_sig")
	}

	claimPath := DensePathWitness(tr.Path(0, 0))
	claim := ClaimWitness(claimPath, path, leaf, leaf, sig, root.Hash, m)
	if len(claim) != len(claimPath)+len(path)+5 {
		t.Fatalf("CLAIM witness has %d elements, want %d", len(claim),
			len(claimPath)+len(path)+5)
	}
	// The claim path sits deeper than the source path.
	if !bytes.Equal(claim[0], claimPath[0]) ||
		!bytes.Equal(claim[len(claimPath)], path[0]) {

		t.Fatal("CLAIM: claim path must be deeper than the source path")
	}

	// EXIT_2: block 1 ends up nearest the top of the stack.
	b1 := ExitBlock(path, leaf, sig, false)
	b2 := ExitBlock(path, leaf, sig2, true)
	two := ExitKWitness([][][]byte{b1, b2}, root.Hash, m)
	if len(two) != len(b1)+len(b2)+2 {
		t.Fatalf("EXIT_2 witness has %d elements, want %d", len(two),
			len(b1)+len(b2)+2)
	}
	if !bytes.Equal(two[len(b2)+len(b1)-1], []byte{}) {
		t.Fatal("EXIT_2: block 1's is_evict must sit just below r")
	}
	if !bytes.Equal(two[len(b2)-1], []byte{0x01}) {
		t.Fatal("EXIT_2: block 2 must be the deeper block")
	}
}
