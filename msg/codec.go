// Package msg implements the off-chain wire encodings of spec/layertree.md
// section 9 (join flow) and section 7.5/9.6 (vouchers), on top of lnd's TLV
// library. Every message type exposes Encode(io.Writer) / Decode(io.Reader).
package msg

import (
	"encoding/binary"
	"fmt"
	"io"

	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightningnetwork/lnd/tlv"
	"github.com/roasbeef/layertree/tree"
)

// nodeLen is the size of a tree.Node's canonical (hash || enc64(sum))
// encoding (spec 5.3, tree.Node.Encode).
const nodeLen = 41

// Size caps on what a decoder reads (design/audit/go.md G3). lnd's
// tlv.Stream.Decode is the non-P2P path: it applies no record size limit,
// and tlv.DVarBytes allocates the declared length before reading, so a
// ten-byte message could make a decoder allocate whatever it claimed.
// Every message is read through an io.LimitReader at its cap, and every
// variable-length record checks its declared length against its own cap
// before allocating.
const (
	// maxTxLen bounds a serialized transaction record. A large graft
	// can approach MAX_STANDARD_TX_WEIGHT, so the cap is the 400 kB of
	// a standard transaction rather than tlv's 65,535-byte P2P limit.
	maxTxLen = 400_000

	// maxProofBitmapLen is ceil(255 / 8): Proof.Depth is a byte, so a
	// path has at most 255 levels.
	maxProofBitmapLen = 32

	// maxProofNodesLen is 41 bytes for each of up to 255 non-empty
	// siblings, rounded up to 256.
	maxProofNodesLen = nodeLen * 256

	// maxProofLen bounds a Proof stream: its three small primitives
	// and headers, the bitmap and the node list.
	maxProofLen = 64 + maxProofBitmapLen + maxProofNodesLen

	// maxJoinOfferLen bounds a JoinOffer stream: the fixed records and
	// headers, two embedded proofs and the unsigned transaction.
	maxJoinOfferLen = 256 + 2*maxProofLen + tree.LeafLen + maxTxLen

	// maxVoucherLen bounds a Voucher stream, whose four records are all
	// fixed size (32 + 2 * 116 + 64 bytes plus headers).
	maxVoucherLen = 512
)

// boundedVarBytes is a variable-length byte record whose decoder refuses a
// declared length above max before allocating anything. Encoding is
// tlv.EVarBytes, so the wire format is the one tlv.DVarBytes reads.
func boundedVarBytes(typ tlv.Type, b *[]byte, max uint64) tlv.Record {
	decode := func(r io.Reader, val interface{}, buf *[8]byte,
		l uint64) error {

		if l > max {
			return fmt.Errorf("msg: record %d declares %d bytes, "+
				"above its cap of %d", typ, l, max)
		}
		return tlv.DVarBytes(r, val, buf, l)
	}
	return tlv.MakeDynamicRecord(
		typ, b, tlv.SizeVarBytes(b), tlv.EVarBytes, decode,
	)
}

// decodeLimited decodes recs from at most max bytes of r. An unknown
// record is skipped by reading it, so the limit also bounds a stream that
// hides its length behind a type the decoder does not know.
func decodeLimited(r io.Reader, max int64, recs []tlv.Record) error {
	s, err := tlv.NewStream(recs...)
	if err != nil {
		return err
	}
	return s.Decode(io.LimitReader(r, max))
}

// decodeNode parses a 41-byte canonical node encoding: a 32-byte hash
// followed by an 8-byte little-endian sum and a trailing 0x01 tag byte (the
// minimal BIP-441 encoding mirrored by tree.Enc64). A sum of tree.MaxSum or
// more is refused: no honest node carries one, and a path built to wrap
// the verifier's arithmetic needs one (design/audit/go.md G1).
func decodeNode(b []byte) (tree.Node, error) {
	if len(b) != nodeLen {
		return tree.Node{}, fmt.Errorf("msg: invalid node encoding "+
			"length: want %d, got %d", nodeLen, len(b))
	}
	if b[40] != 0x01 {
		return tree.Node{}, fmt.Errorf("msg: invalid node sum tag " +
			"byte")
	}

	var n tree.Node
	copy(n.Hash[:], b[:32])
	n.Sum = binary.LittleEndian.Uint64(b[32:40])
	if n.Sum >= tree.MaxSum {
		return tree.Node{}, fmt.Errorf("msg: node sum %d is not below "+
			"2^51", n.Sum)
	}

	return n, nil
}

// encodeNodes concatenates the canonical 41-byte encodings of nodes.
func encodeNodes(nodes []tree.Node) []byte {
	return fn.FlatMap(nodes, func(n tree.Node) []byte {
		return n.Encode()
	})
}

// decodeNodes splits b into nodeLen-byte chunks and parses each one, the
// inverse of encodeNodes.
func decodeNodes(b []byte) ([]tree.Node, error) {
	if len(b)%nodeLen != 0 {
		return nil, fmt.Errorf("msg: node list length %d is not a "+
			"multiple of %d", len(b), nodeLen)
	}

	nodes := make([]tree.Node, 0, len(b)/nodeLen)
	for i := 0; i < len(b); i += nodeLen {
		n, err := decodeNode(b[i : i+nodeLen])
		if err != nil {
			return nil, err
		}
		nodes = append(nodes, n)
	}

	return nodes, nil
}

// encodeLeafRecord adapts tree.Leaf.Serialize to the tlv.Encoder signature so
// a *tree.Leaf can be used directly as a fixed-size (116-byte) TLV record.
func encodeLeafRecord(w io.Writer, val interface{}, _ *[8]byte) error {
	l, ok := val.(*tree.Leaf)
	if !ok {
		return tlv.NewTypeForEncodingErr(val, "*tree.Leaf")
	}

	_, err := w.Write(l.Serialize())
	return err
}

// decodeLeafRecord adapts tree.ParseLeaf to the tlv.Decoder signature.
func decodeLeafRecord(r io.Reader, val interface{}, _ *[8]byte, l uint64) error {
	leaf, ok := val.(*tree.Leaf)
	if !ok {
		return tlv.NewTypeForDecodingErr(
			val, "*tree.Leaf", l, tree.LeafLen,
		)
	}
	if l != tree.LeafLen {
		return fmt.Errorf("msg: invalid leaf encoding length: want "+
			"%d, got %d", tree.LeafLen, l)
	}

	b := make([]byte, tree.LeafLen)
	if _, err := io.ReadFull(r, b); err != nil {
		return err
	}

	parsed, err := tree.ParseLeaf(b)
	if err != nil {
		return err
	}
	*leaf = *parsed

	return nil
}

// leafRecord returns the TLV record for a tree.Leaf-valued field.
func leafRecord(typ tlv.Type, leaf *tree.Leaf) tlv.Record {
	return tlv.MakeStaticRecord(
		typ, leaf, tree.LeafLen, encodeLeafRecord, decodeLeafRecord,
	)
}

// encodeNodeField adapts tree.Node.Encode to the tlv.Encoder signature so a
// *tree.Node can be used directly as a fixed-size (41-byte) TLV record.
func encodeNodeField(w io.Writer, val interface{}, _ *[8]byte) error {
	n, ok := val.(*tree.Node)
	if !ok {
		return tlv.NewTypeForEncodingErr(val, "*tree.Node")
	}

	_, err := w.Write(n.Encode())
	return err
}

// decodeNodeField adapts decodeNode to the tlv.Decoder signature.
func decodeNodeField(r io.Reader, val interface{}, _ *[8]byte, l uint64) error {
	n, ok := val.(*tree.Node)
	if !ok {
		return tlv.NewTypeForDecodingErr(val, "*tree.Node", l, nodeLen)
	}
	if l != nodeLen {
		return fmt.Errorf("msg: invalid node encoding length: want "+
			"%d, got %d", nodeLen, l)
	}

	b := make([]byte, nodeLen)
	if _, err := io.ReadFull(r, b); err != nil {
		return err
	}

	parsed, err := decodeNode(b)
	if err != nil {
		return err
	}
	*n = parsed

	return nil
}

// nodeRecord returns the TLV record for a tree.Node-valued field.
func nodeRecord(typ tlv.Type, n *tree.Node) tlv.Record {
	return tlv.MakeStaticRecord(
		typ, n, nodeLen, encodeNodeField, decodeNodeField,
	)
}
