package msg

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"math/bits"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightningnetwork/lnd/tlv"
	"github.com/roasbeef/layertree/script"
	"github.com/roasbeef/layertree/tree"
	"github.com/roasbeef/layertree/txn"
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

	m, unsignedTx, expectedTree := builtJoin(
		t, mainTree, 0, graftPos, map[uint64]*tree.Leaf{0: memberLeaf},
	)

	offer := &JoinOffer{
		TaptreeRoot: m,
		RootHash:    rootHash,
		Total:       total,
		Leaf:        *memberLeaf,
		SubtreePath: nil,
		GraftPath:   graftPath,
		NewNode:     newNode,
		UnsignedTx:  unsignedTx,
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

	newRoot, err := decoded.VerifyMember(m)
	if err != nil {
		t.Fatalf("VerifyMember: %v", err)
	}
	if expectedRoot := expectedTree.Root(); newRoot != expectedRoot {
		t.Fatalf("new root mismatch:\n got: %+v\nwant: %+v",
			newRoot, expectedRoot)
	}

	// Wrong m must be rejected.
	var otherM [32]byte
	copy(otherM[:], bytes.Repeat([]byte{0x22}, 32))
	if _, err := decoded.VerifyMember(otherM); err == nil {
		t.Fatalf("expected VerifyMember to reject the wrong m")
	}

	// A tampered NewNode must be rejected.
	tampered := decoded
	tampered.NewNode.Sum++
	if _, err := tampered.VerifyMember(m); err == nil {
		t.Fatalf("expected VerifyMember to reject a wrong NewNode")
	}
}

// builtJoin is the operator's side of a join offer: it grafts leaves (keyed
// by their offset within the subtree of the given height at index) into
// mainTree with txn.BuildJoin, under a taptree compiled from the reference
// options with JOIN_0 and JOIN_2. It returns that taptree's root m, the
// serialized unsigned transaction and the tree after the graft.
func builtJoin(t *testing.T, mainTree *tree.Tree, height int, index uint64,
	leaves map[uint64]*tree.Leaf) ([32]byte, []byte, *tree.Tree) {

	t.Helper()
	var treeID [32]byte
	copy(treeID[:], bytes.Repeat([]byte{0x55}, 32))
	opts := script.FullReferenceOptions(xOnlyKey(mustKey(t)), treeID)
	opts.JoinHeights = []int{0, 2}

	treeOut := wire.OutPoint{Hash: sha256.Sum256([]byte("tree"))}
	st, err := txn.NewTreeState(mainTree, opts, treeOut)
	if err != nil {
		t.Fatalf("NewTreeState: %v", err)
	}

	// The graft is funded by one extra input (9.2 step 2) with a
	// little to spare for the fee; its script is a placeholder P2WPKH.
	var funding int64
	for _, l := range leaves {
		funding += int64(l.Amount)
	}
	spend, next, err := txn.BuildJoin(st, height, index, leaves, &txn.TxOpts{
		Inputs: []txn.ExtraInput{{
			OutPoint: wire.OutPoint{
				Hash: sha256.Sum256([]byte("funding")), Index: 1,
			},
			Sequence: txn.TreeSequence,
			PrevOut:  wire.NewTxOut(funding+1_000, p2wpkhScript()),
		}},
	})
	if err != nil {
		t.Fatalf("BuildJoin: %v", err)
	}

	var buf bytes.Buffer
	if err := spend.Tx.Serialize(&buf); err != nil {
		t.Fatalf("serialize: %v", err)
	}
	return st.TapTree.Root(), buf.Bytes(), next
}

// p2wpkhScript is a placeholder P2WPKH output script.
func p2wpkhScript() []byte {
	return append([]byte{0x00, 0x14}, make([]byte, 20)...)
}

// TestVerifyMemberChecksOutput0 is the probe of design/audit/go.md G2: an
// offer whose leaf, paths and node are all correct but whose unsigned
// transaction pays S + new_sum to a P2WPKH instead of TREE_SPK(r', m).
// A member who signed its funding input after a nil error would have
// signed a plain payment to the operator; 9.2 step 3(d) is the check that
// prevents it, and VerifyMember must make it.
func TestVerifyMemberChecksOutput0(t *testing.T) {
	key := xOnlyKey(mustKey(t))

	const depth = 8
	mainTree := tree.New(depth)
	mainTree.Leaves[3] = newTestLeaf(t, key, 1_000_000, 1, 0)

	const graftPos = 42
	memberLeaf := newTestLeaf(t, key, 50_000, 99, 0)
	m, unsignedTx, next := builtJoin(
		t, mainTree, 0, graftPos, map[uint64]*tree.Leaf{0: memberLeaf},
	)
	offer := &JoinOffer{
		TaptreeRoot: m,
		RootHash:    mainTree.Root().Hash,
		Total:       mainTree.Root().Sum,
		Leaf:        *memberLeaf,
		GraftPath:   NewProof(mainTree.Path(graftPos, 0), depth, 0, graftPos),
		NewNode:     memberLeaf.Node(),
		UnsignedTx:  unsignedTx,
	}
	if _, err := offer.VerifyMember(m); err != nil {
		t.Fatalf("VerifyMember rejected the operator's transaction: %v",
			err)
	}

	// The same transaction with output 0 paid to the operator's own
	// P2WPKH, amount unchanged.
	var tx wire.MsgTx
	if err := tx.Deserialize(bytes.NewReader(unsignedTx)); err != nil {
		t.Fatal(err)
	}
	if tx.TxOut[0].Value != int64(next.Root().Sum) {
		t.Fatalf("output 0 holds %d, want %d", tx.TxOut[0].Value,
			next.Root().Sum)
	}
	tx.TxOut[0].PkScript = p2wpkhScript()
	var buf bytes.Buffer
	if err := tx.Serialize(&buf); err != nil {
		t.Fatal(err)
	}
	stolen := *offer
	stolen.UnsignedTx = buf.Bytes()
	if _, err := stolen.VerifyMember(m); err == nil {
		t.Fatalf("VerifyMember accepted an offer whose output 0 pays " +
			"a P2WPKH")
	}

	// The right script with one satoshi missing, an empty field, a
	// field that does not parse and trailing bytes are all rejected.
	var shortTx wire.MsgTx
	if err := shortTx.Deserialize(bytes.NewReader(unsignedTx)); err != nil {
		t.Fatal(err)
	}
	shortTx.TxOut[0].Value--
	buf.Reset()
	if err := shortTx.Serialize(&buf); err != nil {
		t.Fatal(err)
	}
	short := *offer
	short.UnsignedTx = buf.Bytes()
	if _, err := short.VerifyMember(m); err == nil {
		t.Fatalf("VerifyMember accepted an output 0 one satoshi short")
	}
	for name, raw := range map[string][]byte{
		"empty":    nil,
		"garbage":  []byte("unsigned-tx-placeholder"),
		"trailing": append(append([]byte{}, unsignedTx...), 0x00),
	} {
		bad := *offer
		bad.UnsignedTx = raw
		if _, err := bad.VerifyMember(m); err == nil {
			t.Fatalf("VerifyMember accepted a %s unsigned tx", name)
		}
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

	m, unsignedTx, expectedTree := builtJoin(
		t, mainTree, graftHeight, blockIdx, subtree.Leaves,
	)

	offer := &JoinOffer{
		TaptreeRoot: m,
		RootHash:    rootHash,
		Total:       total,
		Leaf:        *memberLeaf,
		SubtreePath: subtreePath,
		GraftPath:   graftPath,
		NewNode:     newNode,
		UnsignedTx:  unsignedTx,
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

	newRoot, err := decoded.VerifyMember(m)
	if err != nil {
		t.Fatalf("VerifyMember: %v", err)
	}
	if expectedRoot := expectedTree.Root(); newRoot != expectedRoot {
		t.Fatalf("new root mismatch:\n got: %+v\nwant: %+v",
			newRoot, expectedRoot)
	}

	// A tampered NewNode must be rejected by VerifyMember.
	tampered := decoded
	tampered.NewNode.Hash[0] ^= 0xff
	if _, err := tampered.VerifyMember(m); err == nil {
		t.Fatalf("expected VerifyMember to reject a wrong NewNode")
	}
}

// wrappedSubtreeOffer is the probe of design/audit/go.md G1 as a join
// offer: the operator grafts a two-position subtree holding the member's
// 1 BTC leaf beside a sibling whose sum is 2^64 - a + 330, so that a
// wrapping fold gives the subtree a sum of 330. It returns the offer, the
// m it was made for, the subtree proof and the wrapped node.
func wrappedSubtreeOffer(t *testing.T) (*JoinOffer, [32]byte, *Proof,
	tree.Node) {

	t.Helper()
	key := xOnlyKey(mustKey(t))

	const depth = 4
	mainTree := tree.New(depth)
	mainTree.Leaves[15] = newTestLeaf(t, key, 1_000_000, 1, 0)
	rootHash, total := mainTree.Root().Hash, mainTree.Root().Sum

	const amount = uint64(100_000_000)
	member := newTestLeaf(t, key, amount, 2, 0)
	fake := tree.Node{
		Hash: sha256.Sum256([]byte("fake")),
		Sum:  ^uint64(0) - amount + 1 + 330,
	}

	// The grafted node is what tree.Parent computes with wrapping
	// arithmetic: the right hash, sum 330.
	newNode := tree.Parent(member.Node(), fake)
	if newNode.Sum != 330 {
		t.Fatalf("expected the wrapped sum 330, got %d", newNode.Sum)
	}

	// A height 1 subtree at index 2 (positions 4 and 5), currently
	// empty.
	const graftHeight, graftIdx = 1, 2
	graftPath := NewProof(
		mainTree.Path(graftIdx<<graftHeight, graftHeight), depth,
		graftHeight, graftIdx<<graftHeight,
	)
	subtreePath := &Proof{
		Depth: graftHeight, Height: 0, Position: 0,
		Bitmap: []byte{0}, Nodes: []tree.Node{fake},
	}

	var m [32]byte
	copy(m[:], bytes.Repeat([]byte{0x44}, 32))
	offer := &JoinOffer{
		TaptreeRoot: m,
		RootHash:    rootHash,
		Total:       total,
		Leaf:        *member,
		SubtreePath: subtreePath,
		GraftPath:   graftPath,
		NewNode:     newNode,
		UnsignedTx:  []byte("unsigned-tx-placeholder"),
	}
	return offer, m, subtreePath, newNode
}

// TestVerifyMemberRejectsWrappedSum is the G1 probe: VerifyMember and
// Proof.Verify must reject a path whose sums only add up modulo 2^64.
func TestVerifyMemberRejectsWrappedSum(t *testing.T) {
	offer, m, subtreePath, newNode := wrappedSubtreeOffer(t)

	if subtreePath.Verify(offer.Leaf.Node(), newNode) {
		t.Fatalf("Proof.Verify accepted a wrapping path")
	}
	if _, err := offer.VerifyMember(m); err == nil {
		t.Fatalf("VerifyMember accepted a graft whose sum wraps")
	}
}

// hostileStream is a TLV stream of one record of type typ that declares
// length bytes and carries none of them.
func hostileStream(t *testing.T, typ tlv.Type, length uint64) []byte {
	t.Helper()
	var buf bytes.Buffer
	var scratch [8]byte
	if err := tlv.WriteVarInt(&buf, uint64(typ), &scratch); err != nil {
		t.Fatal(err)
	}
	if err := tlv.WriteVarInt(&buf, length, &scratch); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// decodeGuarded runs decode and reports a panic as an error, together with
// the bytes the run allocated.
func decodeGuarded(decode func() error) (err error, allocated uint64) {
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	func() {
		defer func() {
			if r := recover(); r != nil {
				err = fmt.Errorf("panic: %v", r)
			}
		}()
		err = decode()
	}()
	runtime.ReadMemStats(&after)
	return err, after.TotalAlloc - before.TotalAlloc
}

// TestDecodeRejectsOversizedRecords is the probe of design/audit/go.md G3:
// a stream whose one record claims 2^62 bytes made every decoder panic in
// makeslice, and one claiming 2^31 made it allocate two gigabytes before
// noticing the stream was short. Every decoder must now return an error
// without allocating anything near the claim, for every variable-length
// record it has and for a record it does not know.
func TestDecodeRejectsOversizedRecords(t *testing.T) {
	const unknownType tlv.Type = 99
	decoders := []struct {
		name   string
		types  []tlv.Type
		decode func(r io.Reader) error
	}{{
		name:  "Proof",
		types: []tlv.Type{TypeProofBitmap, TypeProofNodes, unknownType},
		decode: func(r io.Reader) error {
			var p Proof
			return p.Decode(r)
		},
	}, {
		name: "JoinOffer",
		types: []tlv.Type{
			TypeJoinSubtreePath, TypeJoinGraftPath, TypeJoinUnsignedTx,
			unknownType,
		},
		decode: func(r io.Reader) error {
			var j JoinOffer
			return j.Decode(r)
		},
	}, {
		name:  "Voucher",
		types: []tlv.Type{TypeVoucherTreeID, unknownType},
		decode: func(r io.Reader) error {
			var v Voucher
			return v.Decode(r)
		},
	}}

	// Well under the 2 GB the 2^31 claim used to allocate, and above
	// the fixed buffers a decoder legitimately uses.
	const allocCeiling = 1 << 20
	for _, d := range decoders {
		for _, typ := range d.types {
			for _, length := range []uint64{1 << 62, 1 << 31} {
				stream := hostileStream(t, typ, length)
				err, allocated := decodeGuarded(func() error {
					return d.decode(bytes.NewReader(stream))
				})
				if err == nil {
					t.Errorf("%s.Decode accepted type %d claiming "+
						"2^%d bytes", d.name, typ,
						bits.Len64(length)-1)
				}
				if strings.HasPrefix(err.Error(), "panic") {
					t.Errorf("%s.Decode type %d length 2^%d: %v",
						d.name, typ, bits.Len64(length)-1, err)
				}
				if allocated > allocCeiling {
					t.Errorf("%s.Decode type %d length 2^%d "+
						"allocated %d bytes", d.name, typ,
						bits.Len64(length)-1, allocated)
				}
			}
		}
	}
}

// TestDecodeNodeRejectsLargeSum checks the second, independent G1 guard:
// a node whose sum is 2^51 or more cannot come from an honest tree (spec
// 5.2 bounds leaves below 2^51 and the supply is below it too), so the
// decoder refuses it before any fold sees it.
func TestDecodeNodeRejectsLargeSum(t *testing.T) {
	for _, sum := range []uint64{tree.MaxSum, tree.MaxSum + 1, ^uint64(0)} {
		n := tree.Node{Sum: sum}
		if _, err := decodeNode(n.Encode()); err == nil {
			t.Fatalf("decodeNode accepted a sum of %d", sum)
		}
	}
	n := tree.Node{Sum: tree.MaxSum - 1}
	if _, err := decodeNode(n.Encode()); err != nil {
		t.Fatalf("decodeNode rejected 2^51 - 1: %v", err)
	}

	// The same node inside a proof's node list is refused by Decode.
	p := &Proof{
		Depth: 1, Bitmap: []byte{0},
		Nodes: []tree.Node{{Sum: tree.MaxSum}},
	}
	var buf bytes.Buffer
	if err := p.Encode(&buf); err != nil {
		t.Fatalf("encode: %v", err)
	}
	var decoded Proof
	if err := decoded.Decode(&buf); err == nil {
		t.Fatalf("Proof.Decode accepted a node sum of 2^51")
	}
}
