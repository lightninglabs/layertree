package msg

import (
	"bytes"
	"fmt"
	"io"

	"github.com/btcsuite/btcd/wire"
	"github.com/lightningnetwork/lnd/tlv"
	"github.com/roasbeef/layertree/tree"
)

// TLV types for JoinOffer (spec 9.2).
const (
	TypeJoinTaptreeRoot tlv.Type = 0
	TypeJoinRootHash    tlv.Type = 1
	TypeJoinTotal       tlv.Type = 2
	TypeJoinLeaf        tlv.Type = 3
	TypeJoinSubtreePath tlv.Type = 4
	TypeJoinGraftPath   tlv.Type = 5
	TypeJoinNewNode     tlv.Type = 6
	TypeJoinUnsignedTx  tlv.Type = 7
)

// JoinOffer is the operator's offer to a joining member (spec 9.2): "the
// operator sends the unsigned tx, the member's leaf, the member's path
// within the grafted subtree, the path of the graft point, r and m".
type JoinOffer struct {
	// TaptreeRoot is m, the taptree root of the tree's script set (spec
	// 6.3), which names the rules the member is joining under and is
	// what TREE_SPK(r, m) commits to. It is not tree_id (6.2), the
	// voucher binding the CLAIM scripts carry: the offer does not carry
	// that, and a member learns it from the published creation
	// parameters (9.6).
	TaptreeRoot [32]byte

	// RootHash is the current (pre-graft) tree root's hash.
	RootHash [32]byte

	// Total is the current (pre-graft) tree root's sum.
	Total uint64

	// Leaf is the member's own leaf.
	Leaf tree.Leaf

	// SubtreePath is the member's leaf's path within the grafted
	// subtree. It is nil for a single-leaf join, where NewNode is just
	// the member's own leaf node.
	SubtreePath *Proof

	// GraftPath is the path, in the current (pre-graft) tree, from the
	// empty node the new subtree replaces up to the root.
	GraftPath *Proof

	// NewNode is the grafted subtree's root (hash, sum) - for a
	// single-leaf join this is the member leaf's own node.
	NewNode tree.Node

	// UnsignedTx is the serialized (wire.MsgTx) unsigned funding/graft
	// transaction.
	UnsignedTx []byte
}

// encodeEmbeddedProof serializes a Proof to a standalone byte blob suitable
// for embedding as an opaque TLV record.
func encodeEmbeddedProof(p *Proof) ([]byte, error) {
	var buf bytes.Buffer
	if err := p.Encode(&buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Encode serializes the join offer as a TLV stream. SubtreePath and
// GraftPath are embedded as nested TLV blobs; a nil SubtreePath is simply
// omitted (spec: "nil for a single-leaf join").
func (j *JoinOffer) Encode(w io.Writer) error {
	taptreeRoot, rootHash := j.TaptreeRoot, j.RootHash
	total := j.Total
	newNode := j.NewNode
	unsignedTx := j.UnsignedTx

	records := []tlv.Record{
		tlv.MakePrimitiveRecord(TypeJoinTaptreeRoot, &taptreeRoot),
		tlv.MakePrimitiveRecord(TypeJoinRootHash, &rootHash),
		tlv.MakePrimitiveRecord(TypeJoinTotal, &total),
		leafRecord(TypeJoinLeaf, &j.Leaf),
	}

	var subtreeBytes []byte
	if j.SubtreePath != nil {
		b, err := encodeEmbeddedProof(j.SubtreePath)
		if err != nil {
			return err
		}
		subtreeBytes = b
		records = append(records, boundedVarBytes(
			TypeJoinSubtreePath, &subtreeBytes, maxProofLen,
		))
	}

	var graftBytes []byte
	if j.GraftPath != nil {
		b, err := encodeEmbeddedProof(j.GraftPath)
		if err != nil {
			return err
		}
		graftBytes = b
		records = append(records, boundedVarBytes(
			TypeJoinGraftPath, &graftBytes, maxProofLen,
		))
	}

	records = append(records,
		nodeRecord(TypeJoinNewNode, &newNode),
		boundedVarBytes(TypeJoinUnsignedTx, &unsignedTx, maxTxLen),
	)

	// TypeJoinTaptreeRoot..TypeJoinUnsignedTx are strictly increasing whether
	// or not the optional SubtreePath/GraftPath records are present, so
	// records is already canonically ordered.
	stream, err := tlv.NewStream(records...)
	if err != nil {
		return err
	}

	return stream.Encode(w)
}

// Decode deserializes a join offer from a TLV stream produced by Encode.
// It reads at most maxJoinOfferLen bytes of r.
//
// The optional path records are detected by their backing slices: a
// variable-length record that was present leaves a non-nil slice (even an
// empty one), an absent record leaves nil. tlv.Stream.DecodeWithParsedTypes
// would report presence directly, but it buffers every unknown record at
// its declared length before reading it, which is the allocation this
// decoder must not make.
func (j *JoinOffer) Decode(r io.Reader) error {
	var (
		taptreeRoot, rootHash                [32]byte
		total                                uint64
		newNode                              tree.Node
		subtreeBytes, graftBytes, unsignedTx []byte
	)

	records := []tlv.Record{
		tlv.MakePrimitiveRecord(TypeJoinTaptreeRoot, &taptreeRoot),
		tlv.MakePrimitiveRecord(TypeJoinRootHash, &rootHash),
		tlv.MakePrimitiveRecord(TypeJoinTotal, &total),
		leafRecord(TypeJoinLeaf, &j.Leaf),
		boundedVarBytes(TypeJoinSubtreePath, &subtreeBytes, maxProofLen),
		boundedVarBytes(TypeJoinGraftPath, &graftBytes, maxProofLen),
		nodeRecord(TypeJoinNewNode, &newNode),
		boundedVarBytes(TypeJoinUnsignedTx, &unsignedTx, maxTxLen),
	}

	if err := decodeLimited(r, maxJoinOfferLen, records); err != nil {
		return err
	}

	j.TaptreeRoot = taptreeRoot
	j.RootHash = rootHash
	j.Total = total
	j.NewNode = newNode
	j.UnsignedTx = unsignedTx

	j.SubtreePath = nil
	if subtreeBytes != nil {
		p := &Proof{}
		if err := p.Decode(bytes.NewReader(subtreeBytes)); err != nil {
			return fmt.Errorf("msg: decoding subtree path: %w", err)
		}
		j.SubtreePath = p
	}

	j.GraftPath = nil
	if graftBytes != nil {
		p := &Proof{}
		if err := p.Decode(bytes.NewReader(graftBytes)); err != nil {
			return fmt.Errorf("msg: decoding graft path: %w", err)
		}
		j.GraftPath = p
	}

	return nil
}

// VerifyMember performs the checks of spec 9.2 step 3 that the message
// alone supports: (b) and (c), that the member's leaf folds up (via
// SubtreePath, which must have exactly GraftPath.Height levels, or directly
// if it is nil and the graft is at height 0) to NewNode, that GraftPath folds
// the empty node it replaces up to the pre-graft root (RootHash, Total),
// and that the post-graft root r' carries the sum Total + NewNode.Sum,
// every addition checked; and (d), that UnsignedTx parses and its output 0
// is TREE_SPK(r', m) holding that sum, which is what makes a self-funding
// member's input safe to sign (9.2 step 3(f)). Step 3(a), that input 0
// spends an unspent TREE_SPK(RootHash, m) holding Total, needs the chain:
// the offer carries the outpoint only inside the transaction, so the
// caller looks it up and compares. Signatures are not checked.
//
// On success it returns the post-graft root.
func (j *JoinOffer) VerifyMember(expectedM [32]byte) (tree.Node, error) {
	if j.TaptreeRoot != expectedM {
		return tree.Node{}, fmt.Errorf("msg: join offer's taptree root " +
			"is not the expected m")
	}
	if j.GraftPath == nil {
		return tree.Node{}, fmt.Errorf("msg: join offer is missing " +
			"its graft path")
	}

	// 9.2 step 3(c): the subtree path must have exactly h levels, h being
	// the graft height, so that the leaf lands at depth D in the grafted
	// tree. JOIN_h checks only the slot and the sum, so an operator could
	// otherwise graft a bare leaf, or a shallower subtree, at height h and
	// leave the leaf h levels short of the depth every transition's path
	// takes, where nothing can ever consume it. A nil path is a bare leaf,
	// which only a height-0 graft may carry.
	switch {
	case j.SubtreePath == nil && j.GraftPath.Height != 0:
		return tree.Node{}, fmt.Errorf("msg: join offer grafts a bare "+
			"leaf at height %d", j.GraftPath.Height)

	case j.SubtreePath != nil && (j.SubtreePath.Height != 0 ||
		j.SubtreePath.Depth != j.GraftPath.Height):

		return tree.Node{}, fmt.Errorf("msg: subtree path runs from "+
			"height %d to %d, want a leaf path of %d levels (the "+
			"graft height)", j.SubtreePath.Height, j.SubtreePath.Depth,
			j.GraftPath.Height)
	}

	// The member's leaf must fold, via its subtree path (or directly, in
	// a single-leaf join), to the proposed grafted subtree root.
	leafNode := j.Leaf.Node()
	switch {
	case j.SubtreePath != nil:
		if !j.SubtreePath.Verify(leafNode, j.NewNode) {
			return tree.Node{}, fmt.Errorf("msg: member leaf " +
				"does not fold to the grafted subtree root")
		}

	case leafNode != j.NewNode:
		return tree.Node{}, fmt.Errorf("msg: member leaf does not " +
			"match the grafted subtree root")
	}

	// The graft path must fold the empty node it replaces up to the
	// pre-graft root (RootHash, Total).
	preGraftRoot := tree.Node{Hash: j.RootHash, Sum: j.Total}
	emptyNode := tree.EmptyNode(int(j.GraftPath.Height))
	if !j.GraftPath.Verify(emptyNode, preGraftRoot) {
		return tree.Node{}, fmt.Errorf("msg: graft path does not " +
			"fold the empty node to the pre-graft root")
	}

	// The post-graft root is obtained by folding NewNode up that same
	// path, and must carry the expected sum.
	path, err := j.GraftPath.Path()
	if err != nil {
		return tree.Node{}, err
	}
	newRoot, err := tree.Fold(j.NewNode, path)
	if err != nil {
		return tree.Node{}, err
	}
	wantSum, err := tree.AddSum(j.Total, j.NewNode.Sum)
	if err != nil {
		return tree.Node{}, err
	}
	if newRoot.Sum != wantSum {
		return tree.Node{}, fmt.Errorf("msg: new root sum %d != "+
			"total %d + new node sum %d", newRoot.Sum, j.Total,
			j.NewNode.Sum)
	}

	// 9.2 step 3(d): output 0 of the unsigned transaction recreates the
	// tree under r' and m with the whole new total, so the only thing
	// the member's input can fund is a tree that holds its leaf.
	r := bytes.NewReader(j.UnsignedTx)
	var tx wire.MsgTx
	if err := tx.Deserialize(r); err != nil {
		return tree.Node{}, fmt.Errorf("msg: unsigned tx: %w", err)
	}
	if r.Len() != 0 {
		return tree.Node{}, fmt.Errorf("msg: unsigned tx has %d "+
			"trailing bytes", r.Len())
	}
	if len(tx.TxIn) == 0 || len(tx.TxOut) == 0 {
		return tree.Node{}, fmt.Errorf("msg: unsigned tx has no " +
			"inputs or no outputs")
	}
	wantSPK, err := tree.ScriptPubKey(newRoot.Hash, expectedM)
	if err != nil {
		return tree.Node{}, err
	}
	out0 := tx.TxOut[0]
	if !bytes.Equal(out0.PkScript, wantSPK) || out0.Value != int64(newRoot.Sum) {
		return tree.Node{}, fmt.Errorf("msg: unsigned tx output 0 is "+
			"not TREE_SPK(r', m) holding %d (spec 9.2 step 3(d))",
			newRoot.Sum)
	}

	return newRoot, nil
}
