// Package tree implements the LayerTree data structures of spec/layertree.md
// section 5: leaves, merkle-sum nodes, dense and sparse trees, sibling paths
// and the two proof compression encodings.
package tree

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math/bits"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
)

// Hash tags (spec 5.1).
const (
	TagLeaf    = "LayerTree/leaf"
	TagNode    = "LayerTree/node"
	TagState   = "LayerTree/state"
	TagVoucher = "LayerTree/voucher"
	TagPos     = "LayerTree/pos"

	// TagVoucherH tags the hash-locked voucher message (spec 7.5.1). It is
	// deliberately distinct from TagVoucher: the two voucher forms must be
	// disjoint, or a redeemer could strip the hash lock off a plain
	// voucher, or replay a hash-locked one without the preimage.
	TagVoucherH = "LayerTree/voucher-hashlock"

	// TagTreeID tags the RECOMMENDED tree_id derivation (spec 6.2).
	TagTreeID = "LayerTree/tree-id"
)

// TreeID is the RECOMMENDED tree_id of a tree (spec 6.2):
// H_tag("LayerTree/tree-id", txid || le32(vout)) over the creation outpoint,
// txid in internal byte order (tools/layertree_ref.py tree_id). Any 32-byte
// value unique to the tree's lineage works; a tree created by DETACH_h
// inherits its parent's. Every tier's CLAIM scripts carry it as a constant
// and its vouchers sign it, so a voucher binds one tree rather than the
// rule set m names.
func TreeID(txid [32]byte, vout uint32) [32]byte {
	var buf [36]byte
	copy(buf[:32], txid[:])
	binary.LittleEndian.PutUint32(buf[32:], vout)
	return TaggedHash(TagTreeID, buf[:])
}

// LeafLen is the serialized leaf size.
const LeafLen = 116

// MaxAmount bounds leaf amounts (spec 5.2).
const MaxAmount = uint64(1) << 51

// MaxSum is the largest node sum an implementation accepts from a peer. No
// honest node reaches it: 5.2 bounds every leaf below 2^51, and the total
// of any real tree is below the 2.1 * 10^15 sat of supply, which is itself
// below 2^51. A node sum at or above it can only come from a path whose
// sums were made to wrap (design/audit/go.md G1), so decoders refuse it
// before any fold sees it.
const MaxSum = MaxAmount

// MidTierMaxSum is the per-tree sum cap of the 0xC0 tiers (spec 4.5).
const MidTierMaxSum = uint64(1)<<31 - 1

// DustMin is the RECOMMENDED value of the tree-creation parameter DUST_MIN
// (spec 6.2): the smallest amount a non-operator transition may write into
// a leaf (7.5 rule 6). It is the P2TR dust threshold of Bitcoin Core's
// default policy, 3000 sat/kvB over the 110 bytes of a P2TR output and its
// spending input, since every transition that removes a leaf pays it to
// exactly one P2TR output. The carve scripts carry the tree's DUST_MIN as a
// constant; the Go generators take it as FullTreeOptions.DustMin,
// CCVTreeOptions.DustMin or a dustMin argument, and compile this value when
// it is zero.
const DustMin = uint64(330)

// Node is a merkle-sum node: a 32-byte hash and a satoshi sum.
type Node struct {
	Hash [32]byte
	Sum  uint64
}

// EmptyLeaf is E_0.
var EmptyLeaf = Node{}

// TaggedHash returns the BIP-340 tagged hash of the concatenation of msgs.
func TaggedHash(tag string, msgs ...[]byte) [32]byte {
	return *chainhash.TaggedHash([]byte(tag), msgs...)
}

// Enc64 is the sum encoding inside node hashes: le64(n) || 0x01, the
// minimal BIP-441 encoding of n + 2^64 (spec 2.1).
func Enc64(n uint64) []byte {
	var b [9]byte
	binary.LittleEndian.PutUint64(b[:8], n)
	b[8] = 1
	return b[:]
}

// Le64 returns the 8-byte little-endian encoding of n.
func Le64(n uint64) []byte {
	var b [8]byte
	binary.LittleEndian.PutUint64(b[:], n)
	return b[:]
}

// Le32 returns the 4-byte little-endian encoding of n.
func Le32(n uint32) []byte {
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], n)
	return b[:]
}

// ErrSumOverflow is returned when two sums add past 2^64 - 1. The Python
// reference's le64 raises on the same input and the FULL scripts add
// BIP-441 numbers of unbounded size, so a path that only adds up modulo
// 2^64 is provable to nobody but a wrapping verifier (design/audit/go.md
// G1).
var ErrSumOverflow = errors.New("tree: node sum overflows 2^64")

// AddSum is the checked addition every sum of a path goes through: it
// returns a + b, or ErrSumOverflow if the addition carries.
func AddSum(a, b uint64) (uint64, error) {
	sum, carry := bits.Add64(a, b, 0)
	if carry != 0 {
		return 0, ErrSumOverflow
	}
	return sum, nil
}

// parentHash is H_node(left.hash || enc64(left.sum) || right.hash ||
// enc64(right.sum)) (spec 5.3).
func parentHash(left, right Node) [32]byte {
	return TaggedHash(
		TagNode, left.Hash[:], Enc64(left.Sum), right.Hash[:],
		Enc64(right.Sum),
	)
}

// Parent hashes two children (spec 5.3). Its sum is a machine addition:
// it serves the in-memory Tree, whose leaves the holder bounded with
// Leaf.Validate, and the empty nodes, whose sums are zero. A path received
// from a peer is folded with Fold, which checks every addition.
func Parent(left, right Node) Node {
	return Node{Hash: parentHash(left, right), Sum: left.Sum + right.Sum}
}

// EmptyNode returns E_h, the node covering 2^h empty positions.
func EmptyNode(height int) Node {
	n := EmptyLeaf
	for i := 0; i < height; i++ {
		n = Parent(n, n)
	}
	return n
}

// Encode returns the canonical 41-byte encoding hash || enc64(sum) ("sc").
func (n Node) Encode() []byte {
	return append(append([]byte{}, n.Hash[:]...), Enc64(n.Sum)...)
}

// Leaf is a LayerTree leaf (spec 5.2).
type Leaf struct {
	Amount     uint64
	ExitKey    [32]byte
	OwnerKey   [32]byte
	EvictorKey [32]byte
	EvictAfter uint32
	Nonce      uint32
	Seq        uint32
}

// Serialize returns the 116-byte leaf record.
func (l *Leaf) Serialize() []byte {
	b := make([]byte, 0, LeafLen)
	b = append(b, Le64(l.Amount)...)
	b = append(b, l.ExitKey[:]...)
	b = append(b, l.OwnerKey[:]...)
	b = append(b, l.EvictorKey[:]...)
	b = append(b, Le32(l.EvictAfter)...)
	b = append(b, Le32(l.Nonce)...)
	b = append(b, Le32(l.Seq)...)
	return b
}

// ParseLeaf decodes a 116-byte record.
func ParseLeaf(b []byte) (*Leaf, error) {
	if len(b) != LeafLen {
		return nil, fmt.Errorf("leaf: want %d bytes, got %d", LeafLen, len(b))
	}
	l := &Leaf{Amount: binary.LittleEndian.Uint64(b[0:8])}
	copy(l.ExitKey[:], b[8:40])
	copy(l.OwnerKey[:], b[40:72])
	copy(l.EvictorKey[:], b[72:104])
	l.EvictAfter = binary.LittleEndian.Uint32(b[104:108])
	l.Nonce = binary.LittleEndian.Uint32(b[108:112])
	l.Seq = binary.LittleEndian.Uint32(b[112:116])
	return l, nil
}

// Validate applies the spec 5.2 requirements.
func (l *Leaf) Validate() error {
	if l.Amount == 0 || l.Amount >= MaxAmount {
		return errors.New("leaf: amount out of range")
	}
	if l.EvictAfter >= 500_000_000 {
		return errors.New("leaf: evict_after must be a block height")
	}
	for _, k := range [][32]byte{l.ExitKey, l.OwnerKey, l.EvictorKey} {
		if _, err := schnorr.ParsePubKey(k[:]); err != nil {
			return fmt.Errorf("leaf: invalid x-only key: %w", err)
		}
	}
	return nil
}

// Hash is H_leaf(serialization).
func (l *Leaf) Hash() [32]byte {
	return TaggedHash(TagLeaf, l.Serialize())
}

// Node is (H_leaf, amount).
func (l *Leaf) Node() Node {
	return Node{Hash: l.Hash(), Sum: l.Amount}
}

// PosHash is H_pos(owner_key || le32(nonce)) (sparse profile).
func (l *Leaf) PosHash() [32]byte {
	return TaggedHash(TagPos, l.OwnerKey[:], Le32(l.Nonce))
}

// Position returns the sparse-profile position: the low `depth` bits of
// the little-endian reading of PosHash.
func (l *Leaf) Position(depth int) uint64 {
	h := l.PosHash()
	v := binary.LittleEndian.Uint64(h[:8])
	if depth >= 64 {
		return v
	}
	return v & (uint64(1)<<uint(depth) - 1)
}

// PosLoMinimal reports whether the leaf's nonce is usable in a 0xC0 sparse
// tree of the given depth (spec 4.5, tools/layertree_mid.py pos_ok): the
// first 4 bytes of PosHash must be a minimal positive CScriptNum (top bit
// clear, last byte non-zero), and, since SPARSE_TEARDOWN compares the
// D-bit direction accumulator with all 32 bits of pos_lo, pos_lo must be
// below 2^depth. A non-zero last byte puts pos_lo at 2^24 or above, so the
// band is 25 <= D <= 31; at D = 31 the two conditions coincide. Outside
// the band no nonce is usable.
func (l *Leaf) PosLoMinimal(depth int) bool {
	if depth < 25 || depth > 31 {
		return false
	}
	h := l.PosHash()
	posLo := binary.LittleEndian.Uint32(h[:4])
	return h[3]&0x80 == 0 && h[3] != 0 && posLo < uint32(1)<<uint(depth)
}

// VoucherMsg is H_voucher(tree_id || source_leaf || claim_leaf), the message
// a CLAIM voucher signs (spec 7.5). It binds the tree's tree_id (6.2), not
// its taptree root m: m names a rule set, which two trees can share, and a
// detached cohort inherits tree_id, so a voucher survives a DETACH_h.
func VoucherMsg(treeID [32]byte, source, claim *Leaf) [32]byte {
	return TaggedHash(TagVoucher, treeID[:], source.Serialize(), claim.Serialize())
}

// VoucherHMsg is H_voucher_h(tree_id || source_leaf || claim_leaf ||
// payment_hash), the message a CLAIM^h voucher signs (spec 7.5.1). The
// redeemer supplies the preimage and the script recomputes the payment hash
// from it, so a wrong preimage fails as an invalid signature rather than as
// a failed comparison.
func VoucherHMsg(treeID [32]byte, source, claim *Leaf,
	paymentHash [32]byte) [32]byte {

	return TaggedHash(TagVoucherH, treeID[:], source.Serialize(),
		claim.Serialize(), paymentHash[:])
}

// PathStep is one level of a sibling path.
type PathStep struct {
	Dir     bool // true if the node on the path is the right child
	Sibling Node
}

// Tree is a complete binary merkle-sum tree of the given depth with
// explicit leaves; unoccupied positions are E_0 (spec 5.4).
type Tree struct {
	Depth  int
	Leaves map[uint64]*Leaf
}

// New returns an empty tree.
func New(depth int) *Tree {
	return &Tree{Depth: depth, Leaves: make(map[uint64]*Leaf)}
}

// Clone copies the leaf map.
func (t *Tree) Clone() *Tree {
	c := New(t.Depth)
	for k, v := range t.Leaves {
		c.Leaves[k] = v
	}
	return c
}

func (t *Tree) leafNode(pos uint64) Node {
	if l, ok := t.Leaves[pos]; ok {
		return l.Node()
	}
	return EmptyLeaf
}

func (t *Tree) hasLeafIn(lo, hi uint64) bool {
	for p := range t.Leaves {
		if p >= lo && p < hi {
			return true
		}
	}
	return false
}

// Subtree returns the node at (height, index).
func (t *Tree) Subtree(height int, index uint64) Node {
	lo, hi := index<<uint(height), (index+1)<<uint(height)
	if !t.hasLeafIn(lo, hi) {
		return EmptyNode(height)
	}
	if height == 0 {
		return t.leafNode(index)
	}
	return Parent(t.Subtree(height-1, 2*index), t.Subtree(height-1, 2*index+1))
}

// Root returns the tree root.
func (t *Tree) Root() Node {
	return t.Subtree(t.Depth, 0)
}

// Path returns the sibling path from the node at (height, pos>>height) to
// the root, bottom up (spec 5.5).
func (t *Tree) Path(pos uint64, height int) []PathStep {
	var out []PathStep
	idx := pos >> uint(height)
	for h := height; h < t.Depth; h++ {
		out = append(out, PathStep{Dir: idx&1 == 1, Sibling: t.Subtree(h, idx^1)})
		idx >>= 1
	}
	return out
}

// Fold recomputes the root from a node and its path. Every addition is
// checked: a path whose sums wrap past 2^64 fails with ErrSumOverflow
// rather than folding to a small root, since the scripts would reject it.
func Fold(node Node, path []PathStep) (Node, error) {
	for _, s := range path {
		sum, err := AddSum(node.Sum, s.Sibling.Sum)
		if err != nil {
			return Node{}, err
		}
		if s.Dir {
			node = Node{Hash: parentHash(s.Sibling, node), Sum: sum}
		} else {
			node = Node{Hash: parentHash(node, s.Sibling), Sum: sum}
		}
	}
	return node, nil
}

// CompressPath replaces empty siblings by nil (sparse profile witness
// encoding, spec 5.5). height is the height of the path's first level.
func CompressPath(path []PathStep, height int) [][]byte {
	out := make([][]byte, len(path))
	for k, s := range path {
		if s.Sibling == EmptyNode(height+k) {
			out[k] = nil
		} else {
			out[k] = s.Sibling.Encode()
		}
	}
	return out
}

// BitmapPath is the MS-SMT-style off-chain wire encoding: a bitmap with bit
// k set for an empty sibling at level k, followed by the non-empty nodes.
func BitmapPath(path []PathStep, height int) (bitmap []byte, nodes [][]byte) {
	bitmap = make([]byte, (len(path)+7)/8)
	for k, s := range path {
		if s.Sibling == EmptyNode(height+k) {
			bitmap[k/8] |= 1 << uint(k%8)
		} else {
			nodes = append(nodes, s.Sibling.Encode())
		}
	}
	return bitmap, nodes
}

// Ensure btcec is linked for key validation helpers used by callers.
var _ = btcec.S256
