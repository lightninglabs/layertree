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

// decodeNode parses a 41-byte canonical node encoding: a 32-byte hash
// followed by an 8-byte little-endian sum and a trailing 0x01 tag byte (the
// minimal BIP-441 encoding mirrored by tree.Enc64).
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
