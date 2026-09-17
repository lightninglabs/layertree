package script

// FULL tier: the complete opcode inventory of spec/layertree.md section 4.5
// (BIP-441 numerics, OP_CAT, OP_SUBSTR/OP_LEFT, OP_TX, OP_DOWNSHIFT/OP_AND,
// the EC point opcodes and OP_CHECKSIGFROMSTACK). This file is a direct port
// of tools/layertree_scripts.py; the transition templates themselves are
// spec section 8.
//
// Two profiles share every macro except how a proof level obtains its
// direction bit and sibling:
//
//   - dense ("D"): positions are operator assigned; the witness supplies
//     `dir sc` per level.
//   - sparse ("S"): positions are derived from the leaf
//     (H_pos(owner_key||nonce)); the witness supplies only `sc` per level,
//     with the empty string standing for an empty sibling. The script
//     derives each direction bit and the empty node of each level itself.
//
// Only the "empty element" sparse compression is ported; the MS-SMT style
// bitmap variant of the Python module (level_sparse_bitmap) is a measured
// comparison that no golden vector covers.

import (
	"crypto/sha256"
	"fmt"

	ts "github.com/btcsuite/btcd/txscript"

	"github.com/roasbeef/layertree/tree"
)

// fullTagPrefix is the BIP-340 tagged hash prefix sha256(tag)||sha256(tag).
func fullTagPrefix(tag string) []byte {
	h := sha256.Sum256([]byte(tag))
	return append(append([]byte{}, h[:]...), h[:]...)
}

// Tag prefixes and constants used by the FULL templates (spec 5.1, 8.1).
var (
	fullLeafPrefix     = fullTagPrefix(tree.TagLeaf)
	fullNodePrefix     = fullTagPrefix(tree.TagNode)
	fullStatePrefix    = fullTagPrefix(tree.TagState)
	fullVoucherPrefix  = fullTagPrefix(tree.TagVoucher)
	fullPosPrefix      = fullTagPrefix(tree.TagPos)
	fullTapTweakPrefix = fullTagPrefix("TapTweak")

	// fullNUMS33 is the compressed BIP-341 NUMS point H.
	fullNUMS33 = tree.NUMS.SerializeCompressed()

	fullZero4 = make([]byte, 4)
	fullZero8 = make([]byte, 8)

	// fullP2TRPrefix is OP_1 <32>, the first two bytes of a P2TR spk.
	fullP2TRPrefix = []byte{0x51, 0x20}

	// fullEmptyLeafHash is E_0's hash: 32 zero bytes.
	fullEmptyLeafHash = make([]byte, 32)

	// fullTwo64 is 2^64 in the minimal BIP-441 encoding (9 bytes); adding
	// it to a number n < 2^64 yields enc64(n) = le64(n)||0x01.
	fullTwo64 = []byte{0, 0, 0, 0, 0, 0, 0, 0, 1}

	// fullEnc0 is enc64(0), the encoded sum of an empty node.
	fullEnc0 = tree.Enc64(0)
)

// Leaf field offsets and lengths (spec 5.2).
const (
	fullOffAmount     = 0
	fullLenAmount     = 8
	fullOffExitKey    = 8
	fullOffOwnerKey   = 40
	fullOffEvictorKey = 72
	fullOffEvictAfter = 104
	fullLenEvictAfter = 4
	fullOffNonce      = 108
	fullLenNonce      = 4
	fullOffSeq        = 112
	fullLenSeq        = 4
	fullLeafLen       = tree.LeafLen
)

// fullCat concatenates token runs into a fresh slice.
func fullCat(parts ...[]Token) []Token {
	n := 0
	for _, p := range parts {
		n += len(p)
	}
	out := make([]Token, 0, n)
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// fullTagged hashes the top stack element under a tag prefix: [msg] -> [h].
func fullTagged(prefix []byte) []Token {
	return []Token{Data(prefix), Op(ts.OP_SWAP), Op(OP_CAT), Op(ts.OP_SHA256)}
}

// fullPad8 turns a number into its 9-byte sum encoding: [n] -> [enc64(n)].
func fullPad8() []Token { return []Token{Data(fullTwo64), Op(ts.OP_ADD)} }

// fullLE64 turns a number into le64(n) (the leaf amount field).
func fullLE64() []Token {
	return fullCat(fullPad8(), []Token{Num(8), Op(OP_LEFT)})
}

// fullPad4 turns a number into le32(n).
func fullPad4() []Token {
	return []Token{Data(fullZero4), Op(OP_CAT), Num(4), Op(OP_LEFT)}
}

// fullTreeSPK maps [root_hash m] -> [scriptPubKey of the tree output
// committing to root_hash] using the EC point opcodes (spec 6.1, 6.3).
func fullTreeSPK() []Token {
	return fullCat(
		[]Token{Op(ts.OP_SWAP)},
		fullTagged(fullStatePrefix), // m t
		[]Token{
			Op(ts.OP_0), Op(ts.OP_SWAP), Op(OP_EC_POINT_MUL), // m tG
			Data(fullNUMS33), Op(OP_EC_POINT_ADD), // m P
			Op(OP_EC_POINT_X_COORD),                    // m x(P)
			Op(ts.OP_TUCK), Op(ts.OP_SWAP), Op(OP_CAT), // x(P) (x(P)||m)
		},
		fullTagged(fullTapTweakPrefix), // x(P) t2
		[]Token{
			Op(ts.OP_0), Op(ts.OP_SWAP), Op(OP_EC_POINT_MUL), // x(P) t2G
			Op(ts.OP_SWAP), Data([]byte{0x02}), Op(ts.OP_SWAP), Op(OP_CAT), // t2G (02||x(P))
			Op(OP_EC_POINT_ADD), Op(OP_EC_POINT_X_COORD), // x(Q)
			Data(fullP2TRPrefix), Op(ts.OP_SWAP), Op(OP_CAT), // spk
		},
	)
}

// fullLeafAcc maps [leaf] -> [H_leaf(leaf) amount].
func fullLeafAcc() []Token {
	return fullCat(
		[]Token{Op(ts.OP_DUP), Num(8), Op(OP_LEFT), Op(ts.OP_SWAP)},
		fullTagged(fullLeafPrefix),
		[]Token{Op(ts.OP_SWAP)},
	)
}

// fullLeafPos maps [leaf] -> [leaf pos_hash] with
// pos_hash = H_pos(owner_key || nonce) (sparse profile, spec 5.4).
func fullLeafPos() []Token {
	return fullCat(
		[]Token{
			Op(ts.OP_DUP), Num(fullOffOwnerKey), Num(32), Op(OP_SUBSTR),
			Op(ts.OP_OVER), Num(fullOffNonce), Num(fullLenNonce), Op(OP_SUBSTR),
			Op(OP_CAT),
		},
		fullTagged(fullPosPrefix),
	)
}

// fullPrologue is the common prologue: the current input is #0 and (root, m)
// match the input scriptPubKey. Witness top is ... root m; the altstack is
// left as [m root] with root on top (spec 8.2).
func fullPrologue() []Token {
	return fullCat(
		[]Token{
			Num(SelCurrInput), Op(OP_TX), Op(ts.OP_0), Op(ts.OP_NUMEQUALVERIFY),
			Op(ts.OP_2DUP),
		},
		fullTreeSPK(),
		[]Token{
			Num(SelInSpk), Op(OP_TX), Op(ts.OP_EQUALVERIFY),
			Op(ts.OP_TOALTSTACK), Op(ts.OP_TOALTSTACK),
		},
	)
}

// fullLevelBody is the shared per-level body:
// T oh os nh ns dir sc -> T oh' os' nh' ns'.
func fullLevelBody() []Token {
	return fullCat(
		[]Token{
			Op(ts.OP_SIZE), Num(41), Op(ts.OP_EQUALVERIFY),
			Op(ts.OP_DUP), Num(32), Num(8), Op(OP_SUBSTR), // ... dir sc ss8
			Op(ts.OP_DUP), Op(ts.OP_TOALTSTACK),
			Num(3), Op(ts.OP_ROLL), Op(ts.OP_TUCK), Op(ts.OP_ADD), // ... ns ns'
			Op(ts.OP_TOALTSTACK),
		},
		fullPad8(), // T oh os nh dir sc ns8
		[]Token{
			Num(3), Op(ts.OP_ROLL), Op(ts.OP_SWAP), Op(OP_CAT), // T oh os dir sc nc
			Op(ts.OP_OVER), Op(ts.OP_SWAP), Num(3), Op(ts.OP_PICK),
			Op(ts.OP_NOTIF), Op(ts.OP_SWAP), Op(ts.OP_ENDIF), Op(OP_CAT), // pre_n
			Num(5), Op(ts.OP_PICK), Op(ts.OP_SWAP), Op(OP_CAT), Op(ts.OP_SHA256), // nh'
			Op(ts.OP_TOALTSTACK),
			Op(ts.OP_FROMALTSTACK), Op(ts.OP_FROMALTSTACK), Op(ts.OP_FROMALTSTACK),
			Num(5), Op(ts.OP_ROLL), Op(ts.OP_TUCK), Op(ts.OP_ADD), // os os'
			Op(ts.OP_TOALTSTACK),
		},
		fullPad8(), // T oh dir sc nh' ns' os8
		[]Token{
			Num(5), Op(ts.OP_ROLL), Op(ts.OP_SWAP), Op(OP_CAT), // T dir sc nh' ns' oc
			Num(3), Op(ts.OP_ROLL), Op(ts.OP_SWAP), Num(4), Op(ts.OP_ROLL),
			Op(ts.OP_NOTIF), Op(ts.OP_SWAP), Op(ts.OP_ENDIF), Op(OP_CAT), // pre_o
			Num(3), Op(ts.OP_PICK), Op(ts.OP_SWAP), Op(OP_CAT), Op(ts.OP_SHA256), // oh'
			Op(ts.OP_FROMALTSTACK), Op(ts.OP_2SWAP), // T oh' os' nh' ns'
		},
	)
}

// fullLevelDense is one dense proof level:
// dir sc T oh os nh ns -> T oh' os' nh' ns'.
func fullLevelDense() []Token {
	return fullCat(
		[]Token{Num(6), Op(ts.OP_ROLL), Num(6), Op(ts.OP_ROLL)},
		fullLevelBody(),
	)
}

// fullLevelSparse is one sparse proof level k with "empty element"
// compression: an empty `sc` means "the sibling is the empty node of this
// level" (spec 5.5).
//
// sc T oh os nh ns | ... pos E_k -> T oh' os' nh' ns' | ... pos E_{k+1}
func fullLevelSparse(k int) []Token {
	return fullCat(
		[]Token{
			Num(5), Op(ts.OP_ROLL), // T oh os nh ns sc
			Op(ts.OP_FROMALTSTACK), // ... sc E | pos
			Op(ts.OP_SWAP), Op(ts.OP_SIZE), Op(ts.OP_0NOTEQUAL),
			Op(ts.OP_NOTIF), Op(ts.OP_DROP), Op(ts.OP_DUP), Data(fullEnc0),
			Op(OP_CAT), Op(ts.OP_ENDIF), // ... E sc
			Op(ts.OP_SWAP), Data(fullEnc0), Op(OP_CAT), Op(ts.OP_DUP), Op(OP_CAT),
			Num(6), Op(ts.OP_PICK), Op(ts.OP_SWAP), Op(OP_CAT), Op(ts.OP_SHA256), // ... sc E'
			Op(ts.OP_FROMALTSTACK),              // ... sc E' pos
			Op(ts.OP_DUP), Op(ts.OP_TOALTSTACK), // | pos
			Op(ts.OP_SWAP), Op(ts.OP_TOALTSTACK), // | pos E'
			Num(int64(k)), Op(OP_DOWNSHIFT), Data([]byte{1}), Op(OP_AND),
			Op(ts.OP_0NOTEQUAL), // ... sc dir
			Op(ts.OP_SWAP),      // T oh os nh ns dir sc
		},
		fullLevelBody(),
	)
}

// fullLevels emits the proof levels from `height` up to `depth`.
func fullLevels(sparse bool, depth, height int) []Token {
	var out []Token
	for k := height; k < depth; k++ {
		if sparse {
			out = append(out, fullLevelSparse(k)...)
		} else {
			out = append(out, fullLevelDense()...)
		}
	}
	return out
}

// fullSparseSetup: [pos_hash] -> [] with the altstack gaining pos then E_0.
func fullSparseSetup() []Token {
	return []Token{
		Op(ts.OP_TOALTSTACK), Data(fullEmptyLeafHash), Op(ts.OP_TOALTSTACK),
	}
}

// fullSparseTeardown drops the sparse bookkeeping (pos, E_D) from the
// altstack, above m / m r.
func fullSparseTeardown() []Token {
	return []Token{
		Op(ts.OP_FROMALTSTACK), Op(ts.OP_DROP),
		Op(ts.OP_FROMALTSTACK), Op(ts.OP_DROP),
	}
}

// fullCheckOldRootFromAlt: [T oh os nh ns] -> [T nh ns]; requires os to be
// the input amount and oh the root committed to by the input spk.
func fullCheckOldRootFromAlt(sparse bool) []Token {
	s := []Token{
		Op(ts.OP_2SWAP), Num(SelInAmount), Op(OP_TX), Op(ts.OP_NUMEQUALVERIFY),
	}
	if sparse {
		s = append(s, fullSparseTeardown()...)
	}
	return append(s, Op(ts.OP_FROMALTSTACK), Op(ts.OP_EQUALVERIFY))
}

// fullCheckPrevRootFromAlt: [T oh os nh ns] | ... nh_prev ns_prev ->
// [T nh ns], for chained steps.
func fullCheckPrevRootFromAlt(sparse bool) []Token {
	s := []Token{Op(ts.OP_2SWAP)}
	if sparse {
		s = append(s, fullSparseTeardown()...)
	}
	return append(s,
		Op(ts.OP_FROMALTSTACK), Op(ts.OP_NUMEQUALVERIFY),
		Op(ts.OP_FROMALTSTACK), Op(ts.OP_EQUALVERIFY),
	)
}

// fullFinalOutput: [T nh ns] (alt: m) -> [1]. Output 0 is
// (ns, tree_spk(nh, m)) unless the tree drained to E_D (spec 8.3).
func fullFinalOutput(depth int) []Token {
	eD := tree.EmptyNode(depth).Hash
	return fullCat(
		[]Token{
			Op(ts.OP_ROT), Op(ts.OP_DROP),
			Op(ts.OP_OVER), Data(eD[:]), Op(ts.OP_EQUAL),
			Op(ts.OP_IF), Op(ts.OP_2DROP), Op(ts.OP_FROMALTSTACK), Op(ts.OP_DROP),
			Op(ts.OP_1),
			Op(ts.OP_ELSE), Op(ts.OP_SWAP), Op(ts.OP_FROMALTSTACK),
		},
		fullTreeSPK(),
		[]Token{
			Op(ts.OP_0), Num(SelOutSingle), Op(OP_TX), Op(ts.OP_ROT),
			Op(ts.OP_EQUALVERIFY), Op(ts.OP_NUMEQUAL), Op(ts.OP_ENDIF),
		},
	)
}

// fullExitBlock is one exit:
// [path] leaf sig is_evict | ... -> T oh os nh ns (after the levels).
func fullExitBlock(sparse bool, depth, outIndex int) []Token {
	s := []Token{
		Op(ts.OP_DUP), Op(ts.OP_TOALTSTACK), // | ... is_evict
		Op(ts.OP_IF),
		Op(ts.OP_OVER), Num(fullOffEvictAfter), Num(fullLenEvictAfter), Op(OP_SUBSTR),
		Op(ts.OP_CHECKLOCKTIMEVERIFY), Op(ts.OP_DROP),
		Op(ts.OP_OVER), Num(fullOffEvictorKey), Num(32), Op(OP_SUBSTR),
		Op(ts.OP_ELSE),
		Op(ts.OP_OVER), Num(fullOffOwnerKey), Num(32), Op(OP_SUBSTR),
		Op(ts.OP_ENDIF),
		Op(ts.OP_CHECKSIGVERIFY), // leaf
		Op(ts.OP_SIZE), Num(fullLeafLen), Op(ts.OP_EQUALVERIFY),
		Num(int64(outIndex)), Num(SelOutSingle), Op(OP_TX), // leaf out_amt out_spk
		Data(fullP2TRPrefix), Num(3), Op(ts.OP_PICK), Num(fullOffExitKey), Num(32),
		Op(OP_SUBSTR), Op(OP_CAT),
		Op(ts.OP_EQUALVERIFY),               // leaf out_amt
		Op(ts.OP_OVER), Num(8), Op(OP_LEFT), // leaf out_amt leaf_amt
		Op(ts.OP_FROMALTSTACK),                 // ... is_evict
		Op(ts.OP_IF), Op(ts.OP_NUMEQUALVERIFY), // an eviction pays out exactly
		Op(ts.OP_ELSE), Op(ts.OP_LESSTHANOREQUAL), Op(ts.OP_VERIFY), Op(ts.OP_ENDIF),
	}
	if sparse {
		s = fullCat(s, fullLeafPos(), fullSparseSetup()) // leaf | pos E_0
	}
	return fullCat(s, fullLeafAcc(), // oh os
		[]Token{
			Data(fullNodePrefix), Op(ts.OP_ROT), Op(ts.OP_ROT), // T oh os
			Data(fullEmptyLeafHash), Op(ts.OP_0), // T oh os nh ns
		},
		fullLevels(sparse, depth, 0),
	)
}

// FullExitScript is EXIT_K: k sequential exits paying outputs 1..K
// (spec 8.4).
//
// witness (bottom..top) = [block_K] ... [block_1] root m, where
// block_i = [dir sc]*D (dense) or [sc]*D (sparse), then leaf_i sig_i
// is_evict_i.
func FullExitScript(depth, k int, sparse bool) []Token {
	s := fullCat(
		fullPrologue(),
		fullExitBlock(sparse, depth, 1),
		fullCheckOldRootFromAlt(sparse), // T nh ns | m
	)
	for i := 2; i <= k; i++ {
		s = fullCat(s,
			[]Token{
				Op(ts.OP_SWAP), Op(ts.OP_TOALTSTACK), Op(ts.OP_TOALTSTACK),
				Op(ts.OP_DROP), // | m nh ns
			},
			fullExitBlock(sparse, depth, i),
			fullCheckPrevRootFromAlt(sparse),
		)
	}
	return append(s, fullFinalOutput(depth)...)
}

// fullJoinBlock is one join step. Dense:
// [path] new_hash new_sum8 -> T oh os nh ns after the levels. Sparse
// (height 0): [sc*D] leaf -> T oh os nh ns after the levels.
func fullJoinBlock(sparse bool, depth, height int) []Token {
	if !sparse {
		eH := tree.EmptyNode(height).Hash
		return fullCat(
			[]Token{
				Op(ts.OP_SIZE), Num(8), Op(ts.OP_EQUALVERIFY),
				Op(ts.OP_OVER), Op(ts.OP_SIZE), Num(32), Op(ts.OP_EQUALVERIFY),
				Op(ts.OP_DROP),
				Data(fullNodePrefix), Op(ts.OP_ROT), Op(ts.OP_ROT), // T new_h new_s8
				Data(eH[:]), Op(ts.OP_0), Op(ts.OP_2SWAP), // T E_h 0 new_h new_s8
			},
			fullLevels(false, depth, height),
		)
	}
	if height != 0 {
		panic("script: sparse join only supports height 0")
	}
	return fullCat(
		[]Token{Op(ts.OP_SIZE), Num(fullLeafLen), Op(ts.OP_EQUALVERIFY)},
		fullLeafPos(), fullSparseSetup(), // leaf | pos E_0
		fullLeafAcc(),
		[]Token{
			Data(fullNodePrefix), Op(ts.OP_ROT), Op(ts.OP_ROT), // T nh ns
			Data(fullEmptyLeafHash), Op(ts.OP_0), Op(ts.OP_2SWAP), // T E_0 0 nh ns
		},
		fullLevels(true, depth, 0),
	)
}

// FullJoinScript is JOIN_h (k = 1): graft one subtree of height h (dense) or
// insert one leaf (sparse, h = 0); JOINK_k (h = 0) is k sequential
// single-leaf insertions (spec 8.5).
//
// witness (bottom..top) = [block_k] ... [block_1] sig root m, with
// dense block = [dir sc]*(D-h) new_hash new_sum8 and
// sparse block = [sc]*D leaf.
func FullJoinScript(depth, height int, operatorKey [32]byte, sparse bool,
	k int) []Token {

	s := fullCat(
		fullPrologue(), // ... sig | m r
		[]Token{Data(operatorKey[:]), Op(ts.OP_CHECKSIGVERIFY)},
		fullJoinBlock(sparse, depth, height),
		fullCheckOldRootFromAlt(sparse),
	)
	for i := 2; i <= k; i++ {
		s = fullCat(s,
			[]Token{
				Op(ts.OP_SWAP), Op(ts.OP_TOALTSTACK), Op(ts.OP_TOALTSTACK),
				Op(ts.OP_DROP), // | m nh ns
			},
			fullJoinBlock(sparse, depth, height),
			fullCheckPrevRootFromAlt(sparse),
		)
	}
	return append(s, fullFinalOutput(depth)...)
}

// FullUpdateScript is UPDATE (spec 8.6):
// witness = [path] old_leaf new_leaf owner_sig op_sig root m.
func FullUpdateScript(depth int, operatorKey [32]byte, sparse bool) []Token {
	return fullUpdateScript(depth, operatorKey, sparse, false)
}

// FullUpdateXScript is UPDATE^x, the exit-consent variant of UPDATE
// (spec 7.4 rule 5, 8.5): witness =
// [path] old_leaf new_leaf owner_sig op_sig exit_sig root m, with exit_sig a
// signature over the same transaction by old_leaf.exit_key. It is a
// tree-creation parameter: a tree uses either UPDATE or UPDATE^x, never both.
func FullUpdateXScript(depth int, operatorKey [32]byte, sparse bool) []Token {
	return fullUpdateScript(depth, operatorKey, sparse, true)
}

// fullUpdateScript is the shared body of UPDATE and UPDATE^x.
func fullUpdateScript(depth int, operatorKey [32]byte, sparse,
	exitConsent bool) []Token {

	s := fullPrologue() // old new osig opsig [xsig] | m r
	if exitConsent {
		// exit_sig sits directly above op_sig and is consumed first.
		s = fullCat(s, []Token{
			Num(4), Op(ts.OP_PICK), Num(fullOffExitKey), Num(32),
			Op(OP_SUBSTR), Op(ts.OP_CHECKSIGVERIFY), // old new osig opsig
		})
	}
	s = fullCat(s,
		[]Token{
			Data(operatorKey[:]), Op(ts.OP_CHECKSIGVERIFY), // old new osig
			Num(2), Op(ts.OP_PICK), Num(fullOffOwnerKey), Num(32), Op(OP_SUBSTR),
			Op(ts.OP_CHECKSIGVERIFY), // old new
			Op(ts.OP_SIZE), Num(fullLeafLen), Op(ts.OP_EQUALVERIFY),
			Op(ts.OP_SWAP), Op(ts.OP_SIZE), Num(fullLeafLen), Op(ts.OP_EQUALVERIFY),
		},
	)
	if sparse {
		// Both leaves must derive the same position, and the altstack gets
		// the position re-derived from the old leaf.
		s = fullCat(s,
			fullLeafPos(), []Token{Op(ts.OP_ROT)}, fullLeafPos(),
			[]Token{Op(ts.OP_ROT), Op(ts.OP_EQUALVERIFY), Op(ts.OP_SWAP)},
			fullLeafPos(), fullSparseSetup(), // new old | pos E_0
		)
	}
	s = fullCat(s,
		[]Token{Data(fullNodePrefix), Op(ts.OP_ROT), Op(ts.OP_ROT)}, // T new old
		fullLeafAcc(), // T new oh os
		[]Token{Op(ts.OP_ROT)},
		fullLeafAcc(), // T oh os nh ns
		fullLevels(sparse, depth, 0),
		fullCheckOldRootFromAlt(sparse),
		fullFinalOutput(depth),
	)
	return s
}

// FullClaimScript is CLAIM (spec 8.7):
// witness = [claim path] [source path] src_leaf claim_leaf voucher_sig root m.
func FullClaimScript(depth int, sparse bool) []Token {
	s := fullCat(
		[]Token{
			Num(SelCurrInput), Op(OP_TX), Op(ts.OP_0), Op(ts.OP_NUMEQUALVERIFY),
			Op(ts.OP_2DUP),
		},
		fullTreeSPK(),
		[]Token{
			Num(SelInSpk), Op(OP_TX), Op(ts.OP_EQUALVERIFY),
			Op(ts.OP_DUP), Op(ts.OP_TOALTSTACK), Op(ts.OP_SWAP),
			Op(ts.OP_TOALTSTACK), // src claim vsig m | m r
			Num(3), Op(ts.OP_PICK), Num(3), Op(ts.OP_PICK), Op(OP_CAT), Op(OP_CAT),
		},
		fullTagged(fullVoucherPrefix), // src claim vsig msg
		[]Token{
			Num(3), Op(ts.OP_PICK), Num(fullOffOwnerKey), Num(32), Op(OP_SUBSTR),
			Op(OP_CHECKSIGFROMSTACK), Op(ts.OP_VERIFY), // src claim
			Op(ts.OP_SIZE), Num(fullLeafLen), Op(ts.OP_EQUALVERIFY),
			Op(ts.OP_SWAP), Op(ts.OP_SIZE), Num(fullLeafLen), Op(ts.OP_EQUALVERIFY),
			Op(ts.OP_SWAP), // src claim
			// new_src = le64(src.amt - claim.amt) || src[8:112] || le32(src.seq+1)
			Op(ts.OP_OVER), Num(8), Op(OP_LEFT), Op(ts.OP_OVER), Num(8),
			Op(OP_LEFT), Op(ts.OP_SUB),
		},
		fullLE64(),
		[]Token{
			Num(2), Op(ts.OP_PICK), Num(fullOffExitKey),
			Num(fullOffSeq - fullOffExitKey), Op(OP_SUBSTR), Op(OP_CAT),
			Num(2), Op(ts.OP_PICK), Num(fullOffSeq), Num(fullLenSeq), Op(OP_SUBSTR),
			Op(ts.OP_1ADD),
			Op(ts.OP_SIZE), Num(4), Op(ts.OP_LESSTHANOREQUAL), Op(ts.OP_VERIFY),
		},
		fullPad4(),
		[]Token{
			Op(OP_CAT), // src claim new_src
			// Park claim_leaf on the altstack underneath root: alt = m claim root.
			Op(ts.OP_FROMALTSTACK), Op(ts.OP_ROT), Op(ts.OP_TOALTSTACK),
			Op(ts.OP_TOALTSTACK), // src new_src
		},
	)
	if sparse {
		s = fullCat(s, []Token{Op(ts.OP_OVER)}, fullLeafPos(),
			[]Token{Op(ts.OP_NIP)}, fullSparseSetup()) // src new_src | .. pos E_0
	}
	s = fullCat(s,
		[]Token{
			Data(fullNodePrefix), Op(ts.OP_ROT), Op(ts.OP_ROT), // T src new_src
			Op(ts.OP_SWAP),
		},
		fullLeafAcc(), // T new_src oh os
		[]Token{Op(ts.OP_ROT)},
		fullLeafAcc(), // T oh os nh ns
		[]Token{
			Op(ts.OP_DUP), Op(ts.OP_NOT), Op(ts.OP_IF), Op(ts.OP_SWAP),
			Op(ts.OP_DROP), Data(fullEmptyLeafHash), Op(ts.OP_SWAP),
			Op(ts.OP_ENDIF), // a drained source becomes E_0
		},
		fullLevels(sparse, depth, 0),
		fullCheckOldRootFromAlt(sparse), // T nh1 ns1 | m claim
		[]Token{
			Op(ts.OP_FROMALTSTACK),                         // T nh1 ns1 claim
			Num(2), Op(ts.OP_ROLL), Num(2), Op(ts.OP_ROLL), // T claim nh1 ns1
			Op(ts.OP_SWAP), Op(ts.OP_TOALTSTACK), Op(ts.OP_TOALTSTACK),
		},
	)
	if sparse {
		s = fullCat(s, fullLeafPos(), fullSparseSetup())
	}
	return fullCat(s,
		fullLeafAcc(), // T ch cs
		[]Token{
			Data(fullEmptyLeafHash), Op(ts.OP_0), Op(ts.OP_2SWAP), // T E_0 0 ch cs
		},
		fullLevels(sparse, depth, 0),
		fullCheckPrevRootFromAlt(sparse), // T nh2 ns2 | m
		fullFinalOutput(depth),
	)
}

// ---------------------------------------------------------------------------
// Shape-specialised multiproof: EVICT_SUBTREE_h (dense profile, spec 8.8).
//
// Sweeps every leaf of an aligned subtree of height h whose leaves name the
// operator key as evictor and whose evict_after has passed. The subtree's
// 2^h - 1 internal hashes are computed once by a fixed post-order program,
// the new node is the constant E_h, and one operator signature covers the
// transaction. Already-empty positions arrive as an empty witness element
// and produce no payout. Payouts fill outputs 1.. in leaf order; the running
// output index lives on the altstack so OP_TX can take it dynamically.
// ---------------------------------------------------------------------------

// fullLeafStep: [T ... leaf_or_empty] | .. m r idx -> [T ... oh os] | .. m r idx'.
func fullLeafStep(operatorKey [32]byte) []Token {
	return fullCat(
		[]Token{
			Op(ts.OP_SIZE), Op(ts.OP_0NOTEQUAL),
			Op(ts.OP_IF),
			Op(ts.OP_SIZE), Num(fullLeafLen), Op(ts.OP_EQUALVERIFY),
			Op(ts.OP_DUP), Num(fullOffEvictorKey), Num(32), Op(OP_SUBSTR),
			Data(operatorKey[:]), Op(ts.OP_EQUALVERIFY),
			Op(ts.OP_DUP), Num(fullOffEvictAfter), Num(fullLenEvictAfter),
			Op(OP_SUBSTR),
			Op(ts.OP_CHECKLOCKTIMEVERIFY), Op(ts.OP_DROP),
			Op(ts.OP_FROMALTSTACK), Op(ts.OP_DUP), Op(ts.OP_1ADD),
			Op(ts.OP_TOALTSTACK),         // leaf idx
			Num(SelOutSingle), Op(OP_TX), // leaf amt spk
			Data(fullP2TRPrefix), Num(3), Op(ts.OP_PICK), Num(fullOffExitKey),
			Num(32), Op(OP_SUBSTR), Op(OP_CAT),
			Op(ts.OP_EQUALVERIFY),               // leaf amt
			Op(ts.OP_OVER), Num(8), Op(OP_LEFT), // exact payout
			Op(ts.OP_NUMEQUALVERIFY),
		},
		fullLeafAcc(), // oh os
		[]Token{
			Op(ts.OP_ELSE),
			Op(ts.OP_DROP), Data(fullEmptyLeafHash), Op(ts.OP_0), // E_0
			Op(ts.OP_ENDIF),
		},
	)
}

// fullHashStep: [T ... lh ls rh rs] -> [T ... ph ps]; T sits tDepth elements
// below rs.
func fullHashStep(tDepth int) []Token {
	return fullCat(
		[]Token{
			Num(2), Op(ts.OP_PICK), Op(ts.OP_OVER), Op(ts.OP_ADD),
			Op(ts.OP_TOALTSTACK), // lh ls rh rs | ps
		},
		fullPad8(),
		[]Token{Op(OP_CAT), Op(ts.OP_SWAP)}, // lh ls rc
		fullPad8(),
		[]Token{
			Op(ts.OP_ROT), Op(ts.OP_SWAP), Op(OP_CAT), // rc (lh||ls9)
			Op(ts.OP_SWAP), Op(OP_CAT), // pre
			Num(int64(tDepth - 3)), Op(ts.OP_PICK), Op(ts.OP_SWAP), Op(OP_CAT),
			Op(ts.OP_SHA256),       // ph
			Op(ts.OP_FROMALTSTACK), // ph ps
		},
	)
}

// FullEvictSubtreeScript is EVICT_SUBTREE_h (dense profile).
//
// witness (bottom..top) = [dir sc]*(D-h) leaf_{2^h-1} ... leaf_0 sig r m
// (leaf_0 on top; each leaf element is 116 bytes or empty).
func FullEvictSubtreeScript(depth, height int, operatorKey [32]byte) []Token {
	s := fullCat(
		fullPrologue(),
		[]Token{Data(operatorKey[:]), Op(ts.OP_CHECKSIGVERIFY)}, // ...leaves | m r
		[]Token{Op(ts.OP_1), Op(ts.OP_TOALTSTACK), Data(fullNodePrefix)},
	)
	// Fixed post-order program over a complete tree of height h; `d` tracks
	// the number of machine elements above T so PICK depths stay static.
	d := 0
	var gen func(h int)
	gen = func(h int) {
		if h == 0 {
			// The next leaf sits below T and the machine stack: roll it up.
			s = append(s, Num(int64(d+1)), Op(ts.OP_ROLL))
			s = append(s, fullLeafStep(operatorKey)...)
			d += 2
			return
		}
		gen(h - 1)
		gen(h - 1)
		s = append(s, fullHashStep(d)...)
		d -= 2
	}
	gen(height) // T oh os | m r idx

	eH := tree.EmptyNode(height).Hash
	return fullCat(s,
		[]Token{
			Op(ts.OP_FROMALTSTACK), Op(ts.OP_DROP), // drop idx
			Data(eH[:]), Op(ts.OP_0), // T oh os E_h 0
		},
		fullLevels(false, depth, height),
		fullCheckOldRootFromAlt(false),
		fullFinalOutput(depth),
	)
}

// FullAllScripts returns the FULL-tier taptree script set for a tree, keyed
// exactly as tools/layertree_scripts.py's all_scripts: "EXIT_%d", "JOIN_%d",
// "JOINK_%d", "UPDATE" and "CLAIM". In the sparse profile only height 0
// joins exist, so joinHeights is ignored there.
func FullAllScripts(depth int, operatorKey [32]byte, sparse bool,
	joinHeights, exitKs, joinKs []int) map[string][]Token {

	out := make(map[string][]Token)
	for _, k := range exitKs {
		out[fmt.Sprintf("EXIT_%d", k)] = FullExitScript(depth, k, sparse)
	}
	heights := joinHeights
	if sparse {
		heights = []int{0}
	}
	for _, h := range heights {
		out[fmt.Sprintf("JOIN_%d", h)] = FullJoinScript(
			depth, h, operatorKey, sparse, 1,
		)
	}
	for _, k := range joinKs {
		out[fmt.Sprintf("JOINK_%d", k)] = FullJoinScript(
			depth, 0, operatorKey, sparse, k,
		)
	}
	out["UPDATE"] = FullUpdateScript(depth, operatorKey, sparse)
	out["CLAIM"] = FullClaimScript(depth, sparse)
	return out
}
