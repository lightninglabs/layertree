package script

import (
	"github.com/roasbeef/layertree/tree"
)

// TapBranch is the BIP-341 branch hash of two nodes, hashed in lexicographic
// order.
func TapBranch(a, b [32]byte) [32]byte {
	for i := 0; i < 32; i++ {
		if a[i] != b[i] {
			if b[i] < a[i] {
				a, b = b, a
			}
			break
		}
	}
	return tree.TaggedHash("TapBranch", a[:], b[:])
}

// TapLeafHash is the BIP-341 tapleaf hash of a script under a leaf version.
func TapLeafHash(script []byte, version byte) [32]byte {
	return tree.TaggedHash(
		"TapLeaf", []byte{version}, compactSize(len(script)), script,
	)
}

// compactSize is Bitcoin's variable length integer encoding.
func compactSize(n int) []byte {
	switch {
	case n < 0xfd:
		return []byte{byte(n)}
	case n <= 0xffff:
		return []byte{0xfd, byte(n), byte(n >> 8)}
	case n <= 0xffffffff:
		return []byte{
			0xfe, byte(n), byte(n >> 8), byte(n >> 16), byte(n >> 24),
		}
	default:
		b := make([]byte, 9)
		b[0] = 0xff
		for i := 0; i < 8; i++ {
			b[i+1] = byte(uint64(n) >> uint(8*i))
		}
		return b
	}
}

// TapTreeRoot builds the balanced taptree over the given leaf hashes in
// order: adjacent leaves are paired, an odd leaf is carried up unchanged,
// and each pair is combined with TapBranch. This mirrors taptree_root in
// tools/layertree_ref.py, which is how the LayerTree script sets commit to
// their taptree (spec 6.3).
func TapTreeRoot(leaves [][32]byte) [32]byte {
	if len(leaves) == 0 {
		return [32]byte{}
	}
	level := make([][32]byte, len(leaves))
	copy(level, leaves)
	for len(level) > 1 {
		next := make([][32]byte, 0, (len(level)+1)/2)
		for i := 0; i+1 < len(level); i += 2 {
			next = append(next, TapBranch(level[i], level[i+1]))
		}
		if len(level)%2 == 1 {
			next = append(next, level[len(level)-1])
		}
		level = next
	}
	return level[0]
}
