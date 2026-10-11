package msg

import (
	"bytes"
	"fmt"
	"io"

	"github.com/lightningnetwork/lnd/tlv"
	"github.com/roasbeef/layertree/tree"
)

// TLV types for JoinOffer (spec 9.2).
const (
	TypeJoinTreeID      tlv.Type = 0
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
	// TreeID is m, the tree identifier committed into leaf and voucher
	// hashes.
	TreeID [32]byte

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
	treeID, rootHash := j.TreeID, j.RootHash
	total := j.Total
	newNode := j.NewNode
	unsignedTx := j.UnsignedTx

	records := []tlv.Record{
		tlv.MakePrimitiveRecord(TypeJoinTreeID, &treeID),
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
		records = append(records, tlv.MakeDynamicRecord(
			TypeJoinSubtreePath, &subtreeBytes,
			tlv.SizeVarBytes(&subtreeBytes), tlv.EVarBytes,
			tlv.DVarBytes,
		))
	}

	var graftBytes []byte
	if j.GraftPath != nil {
		b, err := encodeEmbeddedProof(j.GraftPath)
		if err != nil {
			return err
		}
		graftBytes = b
		records = append(records, tlv.MakeDynamicRecord(
			TypeJoinGraftPath, &graftBytes,
			tlv.SizeVarBytes(&graftBytes), tlv.EVarBytes,
			tlv.DVarBytes,
		))
	}

	records = append(records,
		nodeRecord(TypeJoinNewNode, &newNode),
		tlv.MakeDynamicRecord(
			TypeJoinUnsignedTx, &unsignedTx,
			tlv.SizeVarBytes(&unsignedTx), tlv.EVarBytes,
			tlv.DVarBytes,
		),
	)

	// TypeJoinTreeID..TypeJoinUnsignedTx are strictly increasing whether
	// or not the optional SubtreePath/GraftPath records are present, so
	// records is already canonically ordered.
	stream, err := tlv.NewStream(records...)
	if err != nil {
		return err
	}

	return stream.Encode(w)
}

// Decode deserializes a join offer from a TLV stream produced by Encode.
func (j *JoinOffer) Decode(r io.Reader) error {
	var (
		treeID, rootHash                     [32]byte
		total                                uint64
		newNode                              tree.Node
		subtreeBytes, graftBytes, unsignedTx []byte
	)

	records := []tlv.Record{
		tlv.MakePrimitiveRecord(TypeJoinTreeID, &treeID),
		tlv.MakePrimitiveRecord(TypeJoinRootHash, &rootHash),
		tlv.MakePrimitiveRecord(TypeJoinTotal, &total),
		leafRecord(TypeJoinLeaf, &j.Leaf),
		tlv.MakeDynamicRecord(
			TypeJoinSubtreePath, &subtreeBytes,
			tlv.SizeVarBytes(&subtreeBytes), tlv.EVarBytes,
			tlv.DVarBytes,
		),
		tlv.MakeDynamicRecord(
			TypeJoinGraftPath, &graftBytes,
			tlv.SizeVarBytes(&graftBytes), tlv.EVarBytes,
			tlv.DVarBytes,
		),
		nodeRecord(TypeJoinNewNode, &newNode),
		tlv.MakeDynamicRecord(
			TypeJoinUnsignedTx, &unsignedTx,
			tlv.SizeVarBytes(&unsignedTx), tlv.EVarBytes,
			tlv.DVarBytes,
		),
	}

	stream, err := tlv.NewStream(records...)
	if err != nil {
		return err
	}

	parsed, err := stream.DecodeWithParsedTypes(r)
	if err != nil {
		return err
	}

	j.TreeID = treeID
	j.RootHash = rootHash
	j.Total = total
	j.NewNode = newNode
	j.UnsignedTx = unsignedTx

	j.SubtreePath = nil
	if _, ok := parsed[TypeJoinSubtreePath]; ok {
		p := &Proof{}
		if err := p.Decode(bytes.NewReader(subtreeBytes)); err != nil {
			return fmt.Errorf("msg: decoding subtree path: %w", err)
		}
		j.SubtreePath = p
	}

	j.GraftPath = nil
	if _, ok := parsed[TypeJoinGraftPath]; ok {
		p := &Proof{}
		if err := p.Decode(bytes.NewReader(graftBytes)); err != nil {
			return fmt.Errorf("msg: decoding graft path: %w", err)
		}
		j.GraftPath = p
	}

	return nil
}

// VerifyMember performs the message-local checks of spec 9.2 step 3: that
// the member's leaf folds up (via SubtreePath, or directly if it is nil) to
// NewNode, that GraftPath folds the empty node it replaces up to the
// pre-graft root (RootHash, Total), and that the resulting post-graft root
// carries the expected sum Total + NewNode.Sum. It does not verify anything
// that requires external state, such as the unsigned tx actually matching
// the chain or any signatures.
//
// On success it returns the post-graft root.
func (j *JoinOffer) VerifyMember(expectedM [32]byte) (tree.Node, error) {
	if j.TreeID != expectedM {
		return tree.Node{}, fmt.Errorf("msg: join offer tree id " +
			"does not match the expected tree")
	}
	if j.GraftPath == nil {
		return tree.Node{}, fmt.Errorf("msg: join offer is missing " +
			"its graft path")
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

	return newRoot, nil
}
