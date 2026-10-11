package msg

import (
	"fmt"
	"io"

	"github.com/lightningnetwork/lnd/tlv"
	"github.com/roasbeef/layertree/tree"
)

// TLV types for Proof (spec 5.5 off-chain wire format).
const (
	TypeProofDepth    tlv.Type = 0
	TypeProofHeight   tlv.Type = 1
	TypeProofPosition tlv.Type = 2
	TypeProofBitmap   tlv.Type = 3
	TypeProofNodes    tlv.Type = 4
)

// Proof is the MS-SMT-style compressed sibling path described in spec 5.5:
// "the MS-SMT BIP compresses proofs with a bitmap of empty levels followed by
// only the non-empty nodes; that is the RECOMMENDED off-chain wire format
// between operator and participants (a ceil(D/8) byte bitmap plus
// 41*(non-empty) bytes)".
//
// The path runs from a node at level Height (the level of the node the proof
// is a witness for) up to level Depth (the root level). Bit k of Bitmap
// (k = 0 at the bottom) set means the sibling at level Height+k is the empty
// node E_{Height+k} and is omitted from Nodes; a clear bit means the next
// entry of Nodes (in bottom-up order) is that level's sibling.
type Proof struct {
	// Depth is the level the path folds up to (the tree/root level).
	Depth uint8

	// Height is the level of the node this proof is a witness for.
	Height uint8

	// Position is the index, at level Height, of the node this proof is
	// a witness for (i.e. the leaf position shifted right by Height).
	// Bit k of Position gives the direction (Dir) of path step k.
	Position uint64

	// Bitmap has bit k set when the sibling at level Height+k is empty.
	Bitmap []byte

	// Nodes holds the non-empty siblings, bottom-up, in the order their
	// bits are clear in Bitmap.
	Nodes []tree.Node
}

// NewProof compresses a sibling path such as the one returned by
// tree.Tree.Path into the wire format of spec 5.5. depth and height are the
// root level and the level of the node the path starts from (mirroring
// tree.Tree.Path's own height parameter), and position is the leaf-level
// position that path was built for (tree.Tree.Path(position, height)).
func NewProof(path []tree.PathStep, depth, height int, position uint64) *Proof {
	bitmap, _ := tree.BitmapPath(path, height)

	// The non-empty siblings, bottom up, are the ones tree.BitmapPath
	// leaves a clear bit for.
	nodes := make([]tree.Node, 0, len(path))
	for k, s := range path {
		if s.Sibling != tree.EmptyNode(height+k) {
			nodes = append(nodes, s.Sibling)
		}
	}

	return &Proof{
		Depth:    uint8(depth),
		Height:   uint8(height),
		Position: position >> uint(height),
		Bitmap:   bitmap,
		Nodes:    nodes,
	}
}

// Path expands the compressed proof back into a sibling path suitable for
// tree.Fold.
func (p *Proof) Path() ([]tree.PathStep, error) {
	if p.Depth < p.Height {
		return nil, fmt.Errorf("msg: proof depth %d is below its "+
			"height %d", p.Depth, p.Height)
	}

	length := int(p.Depth) - int(p.Height)
	wantBitmapLen := (length + 7) / 8
	if len(p.Bitmap) != wantBitmapLen {
		return nil, fmt.Errorf("msg: proof bitmap length %d, want %d",
			len(p.Bitmap), wantBitmapLen)
	}

	path := make([]tree.PathStep, length)
	nextNode := 0
	for k := 0; k < length; k++ {
		dir := (p.Position>>uint(k))&1 == 1
		empty := (p.Bitmap[k/8]>>uint(k%8))&1 == 1

		var sibling tree.Node
		switch {
		case empty:
			sibling = tree.EmptyNode(int(p.Height) + k)

		case nextNode < len(p.Nodes):
			sibling = p.Nodes[nextNode]
			nextNode++

		default:
			return nil, fmt.Errorf("msg: proof is missing a " +
				"non-empty sibling node")
		}

		path[k] = tree.PathStep{Dir: dir, Sibling: sibling}
	}

	if nextNode != len(p.Nodes) {
		return nil, fmt.Errorf("msg: proof has %d unused sibling "+
			"nodes", len(p.Nodes)-nextNode)
	}

	return path, nil
}

// Verify reports whether node folds up this proof's path to root. The fold
// is checked arithmetic, so a path whose sums wrap past 2^64 does not
// verify, whatever root it would wrap to.
func (p *Proof) Verify(node, root tree.Node) bool {
	path, err := p.Path()
	if err != nil {
		return false
	}
	folded, err := tree.Fold(node, path)
	return err == nil && folded == root
}

// records returns the TLV records for the proof's fields, bound to the
// passed backing variables. Encode and Decode share this so the record
// layout can't drift between the two directions.
func proofRecords(
	depth, height *uint8,
	position *uint64,
	bitmap, nodes *[]byte,
) []tlv.Record {

	return []tlv.Record{
		tlv.MakePrimitiveRecord(TypeProofDepth, depth),
		tlv.MakePrimitiveRecord(TypeProofHeight, height),
		tlv.MakePrimitiveRecord(TypeProofPosition, position),
		boundedVarBytes(TypeProofBitmap, bitmap, maxProofBitmapLen),
		boundedVarBytes(TypeProofNodes, nodes, maxProofNodesLen),
	}
}

// Encode serializes the proof as a TLV stream.
func (p *Proof) Encode(w io.Writer) error {
	depth, height, position := p.Depth, p.Height, p.Position
	bitmap := p.Bitmap
	nodes := encodeNodes(p.Nodes)

	stream, err := tlv.NewStream(proofRecords(
		&depth, &height, &position, &bitmap, &nodes,
	)...)
	if err != nil {
		return err
	}

	return stream.Encode(w)
}

// Decode deserializes a proof from a TLV stream produced by Encode. It
// reads at most maxProofLen bytes of r.
func (p *Proof) Decode(r io.Reader) error {
	var (
		depth, height  uint8
		position       uint64
		bitmap, nodesB []byte
	)

	err := decodeLimited(r, maxProofLen, proofRecords(
		&depth, &height, &position, &bitmap, &nodesB,
	))
	if err != nil {
		return err
	}

	nodes, err := decodeNodes(nodesB)
	if err != nil {
		return err
	}

	p.Depth = depth
	p.Height = height
	p.Position = position
	p.Bitmap = bitmap
	p.Nodes = nodes

	return nil
}
