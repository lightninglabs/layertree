package msg

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/roasbeef/layertree/tree"
)

// xOnlyKey returns the 32-byte x-only encoding of priv's public key.
func xOnlyKey(priv *btcec.PrivateKey) [32]byte {
	var k [32]byte
	copy(k[:], schnorr.SerializePubKey(priv.PubKey()))
	return k
}

// newTestLeaf builds a leaf with valid (schnorr-parseable) key fields,
// varying amount/nonce/seq so distinct leaves hash differently.
func newTestLeaf(t *testing.T, key [32]byte, amount uint64, nonce, seq uint32) *tree.Leaf {
	t.Helper()

	return &tree.Leaf{
		Amount:     amount,
		ExitKey:    key,
		OwnerKey:   key,
		EvictorKey: key,
		EvictAfter: 800_000,
		Nonce:      nonce,
		Seq:        seq,
	}
}

func mustKey(t *testing.T) *btcec.PrivateKey {
	t.Helper()

	priv, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	return priv
}

// TestProofRoundTrip builds a real tree, checks that a Proof built from one
// of its paths verifies against the true root and fails against a wrong
// root, and checks the TLV round trip.
func TestProofRoundTrip(t *testing.T) {
	priv := mustKey(t)
	key := xOnlyKey(priv)

	const depth = 8
	tr := tree.New(depth)
	tr.Leaves[3] = newTestLeaf(t, key, 1000, 1, 0)
	tr.Leaves[10] = newTestLeaf(t, key, 2000, 2, 0)
	tr.Leaves[200] = newTestLeaf(t, key, 3000, 3, 0)

	const pos = 10
	path := tr.Path(pos, 0)
	proof := NewProof(path, depth, 0, pos)

	root := tr.Root()
	node := tr.Leaves[pos].Node()

	if !proof.Verify(node, root) {
		t.Fatalf("proof did not verify against the true root")
	}

	wrongRoot := root
	wrongRoot.Hash[0] ^= 0xff
	if proof.Verify(node, wrongRoot) {
		t.Fatalf("proof verified against a wrong root")
	}

	var buf bytes.Buffer
	if err := proof.Encode(&buf); err != nil {
		t.Fatalf("encode: %v", err)
	}

	var decoded Proof
	if err := decoded.Decode(&buf); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if !reflect.DeepEqual(proof, &decoded) {
		t.Fatalf("round trip mismatch:\n got: %+v\nwant: %+v",
			&decoded, proof)
	}

	if !decoded.Verify(node, root) {
		t.Fatalf("decoded proof did not verify")
	}
}

// TestVoucherRoundTrip signs a voucher with a random key, checks
// Sign/Verify, the wrong-key failure path, and the TLV round trip.
func TestVoucherRoundTrip(t *testing.T) {
	sourcePriv := mustKey(t)
	sourceKey := xOnlyKey(sourcePriv)
	claimKey := xOnlyKey(mustKey(t))

	var treeID [32]byte
	copy(treeID[:], bytes.Repeat([]byte{0xab}, 32))

	v := &Voucher{
		TreeID:     treeID,
		SourceLeaf: *newTestLeaf(t, sourceKey, 5000, 7, 1),
		ClaimLeaf:  *newTestLeaf(t, claimKey, 5000, 8, 0),
	}

	// Signing with the wrong key must fail.
	if err := v.Sign(mustKey(t)); err == nil {
		t.Fatalf("expected sign with wrong key to fail")
	}

	if err := v.Sign(sourcePriv); err != nil {
		t.Fatalf("sign: %v", err)
	}
	if !v.Verify() {
		t.Fatalf("voucher did not verify after signing")
	}

	var buf bytes.Buffer
	if err := v.Encode(&buf); err != nil {
		t.Fatalf("encode: %v", err)
	}

	var decoded Voucher
	if err := decoded.Decode(&buf); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if !reflect.DeepEqual(v, &decoded) {
		t.Fatalf("round trip mismatch:\n got: %+v\nwant: %+v",
			&decoded, v)
	}
	if !decoded.Verify() {
		t.Fatalf("decoded voucher did not verify")
	}

	// A bit-flipped signature must fail verification.
	tampered := decoded
	tampered.Sig[0] ^= 0xff
	if tampered.Verify() {
		t.Fatalf("tampered voucher unexpectedly verified")
	}
}

// TestJoinOfferSingleLeaf covers a single-leaf join (SubtreePath == nil):
// the member's own leaf is grafted directly into a currently-empty leaf
// slot of the tree.
func TestJoinOfferSingleLeaf(t *testing.T) {
	priv := mustKey(t)
	key := xOnlyKey(priv)

	const depth = 8
	mainTree := tree.New(depth)
	mainTree.Leaves[3] = newTestLeaf(t, key, 1000, 1, 0)
	mainTree.Leaves[10] = newTestLeaf(t, key, 2000, 2, 0)

	const graftPos = 42 // currently empty.
	rootHash := mainTree.Root().Hash
	total := mainTree.Root().Sum

	graftPath := NewProof(mainTree.Path(graftPos, 0), depth, 0, graftPos)

	memberLeaf := newTestLeaf(t, key, 500, 99, 0)
	newNode := memberLeaf.Node()

	var treeID [32]byte
	copy(treeID[:], bytes.Repeat([]byte{0x11}, 32))

	offer := &JoinOffer{
		TreeID:      treeID,
		RootHash:    rootHash,
		Total:       total,
		Leaf:        *memberLeaf,
		SubtreePath: nil,
		GraftPath:   graftPath,
		NewNode:     newNode,
		UnsignedTx:  []byte("unsigned-tx-placeholder"),
	}

	// TLV round trip.
	var buf bytes.Buffer
	if err := offer.Encode(&buf); err != nil {
		t.Fatalf("encode: %v", err)
	}
	var decoded JoinOffer
	if err := decoded.Decode(&buf); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !reflect.DeepEqual(offer, &decoded) {
		t.Fatalf("round trip mismatch:\n got: %+v\nwant: %+v",
			&decoded, offer)
	}
	if decoded.SubtreePath != nil {
		t.Fatalf("expected nil subtree path after decode")
	}

	newRoot, err := decoded.VerifyMember(treeID)
	if err != nil {
		t.Fatalf("VerifyMember: %v", err)
	}

	expectedTree := mainTree.Clone()
	expectedTree.Leaves[graftPos] = memberLeaf
	expectedRoot := expectedTree.Root()

	if newRoot != expectedRoot {
		t.Fatalf("new root mismatch:\n got: %+v\nwant: %+v",
			newRoot, expectedRoot)
	}

	// Wrong tree id must be rejected.
	var otherID [32]byte
	copy(otherID[:], bytes.Repeat([]byte{0x22}, 32))
	if _, err := decoded.VerifyMember(otherID); err == nil {
		t.Fatalf("expected VerifyMember to reject the wrong tree id")
	}

	// A tampered NewNode must be rejected.
	tampered := decoded
	tampered.NewNode.Sum++
	if _, err := tampered.VerifyMember(treeID); err == nil {
		t.Fatalf("expected VerifyMember to reject a wrong NewNode")
	}
}

// TestJoinOfferSubtree covers a multi-leaf join (SubtreePath != nil): a
// small subtree with several leaves is grafted as a unit into a currently
// empty subtree slot.
func TestJoinOfferSubtree(t *testing.T) {
	priv := mustKey(t)
	key := xOnlyKey(priv)

	const depth = 8
	mainTree := tree.New(depth)
	mainTree.Leaves[3] = newTestLeaf(t, key, 1000, 1, 0)

	const (
		graftHeight = 2  // a 4-leaf-slot block.
		blockIdx    = 15 // currently empty in mainTree.
	)
	graftBasePos := uint64(blockIdx) << graftHeight

	rootHash := mainTree.Root().Hash
	total := mainTree.Root().Sum
	graftPath := NewProof(
		mainTree.Path(graftBasePos, graftHeight), depth, graftHeight,
		graftBasePos,
	)

	// Build the small grafted subtree with two leaves in it.
	subtree := tree.New(graftHeight)
	subtree.Leaves[0] = newTestLeaf(t, key, 111, 10, 0)
	subtree.Leaves[3] = newTestLeaf(t, key, 222, 11, 0)

	const memberLocalPos = 3
	memberLeaf := subtree.Leaves[memberLocalPos]
	newNode := subtree.Root()

	subtreePath := NewProof(
		subtree.Path(memberLocalPos, 0), graftHeight, 0, memberLocalPos,
	)

	var treeID [32]byte
	copy(treeID[:], bytes.Repeat([]byte{0x33}, 32))

	offer := &JoinOffer{
		TreeID:      treeID,
		RootHash:    rootHash,
		Total:       total,
		Leaf:        *memberLeaf,
		SubtreePath: subtreePath,
		GraftPath:   graftPath,
		NewNode:     newNode,
		UnsignedTx:  []byte("unsigned-tx-placeholder"),
	}

	var buf bytes.Buffer
	if err := offer.Encode(&buf); err != nil {
		t.Fatalf("encode: %v", err)
	}
	var decoded JoinOffer
	if err := decoded.Decode(&buf); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !reflect.DeepEqual(offer, &decoded) {
		t.Fatalf("round trip mismatch:\n got: %+v\nwant: %+v",
			&decoded, offer)
	}
	if decoded.SubtreePath == nil {
		t.Fatalf("expected non-nil subtree path after decode")
	}

	newRoot, err := decoded.VerifyMember(treeID)
	if err != nil {
		t.Fatalf("VerifyMember: %v", err)
	}

	expectedTree := mainTree.Clone()
	for localPos, leaf := range subtree.Leaves {
		expectedTree.Leaves[graftBasePos+localPos] = leaf
	}
	expectedRoot := expectedTree.Root()

	if newRoot != expectedRoot {
		t.Fatalf("new root mismatch:\n got: %+v\nwant: %+v",
			newRoot, expectedRoot)
	}

	// A tampered NewNode must be rejected by VerifyMember.
	tampered := decoded
	tampered.NewNode.Hash[0] ^= 0xff
	if _, err := tampered.VerifyMember(treeID); err == nil {
		t.Fatalf("expected VerifyMember to reject a wrong NewNode")
	}
}
