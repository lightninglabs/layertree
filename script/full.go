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
	fullVoucherHPrefix = fullTagPrefix(tree.TagVoucherH)
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

	// fullSeqFinal is the FULL tier's non-claimable marker SEQ_FINAL
	// (spec 5.2) as the le32 seq field: REWRITE_h's amount-only
	// exemption (7.9 rule 3) does not reach a leaf carrying it.
	fullSeqFinal = tree.Le32(0xFFFFFFFF)
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
// exact is the EXIT_K^= variant (spec 7.2 rule 6): the payout must equal
// leaf.amount for owner exits as well as evictions.
func fullExitBlock(sparse bool, depth, outIndex int, exact bool) []Token {
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
		Op(ts.OP_FROMALTSTACK), // ... is_evict
	}
	if exact {
		s = append(s, Op(ts.OP_DROP), Op(ts.OP_NUMEQUALVERIFY)) // exact for both
	} else {
		s = append(s,
			Op(ts.OP_IF), Op(ts.OP_NUMEQUALVERIFY), // an eviction pays out exactly
			Op(ts.OP_ELSE), Op(ts.OP_LESSTHANOREQUAL), Op(ts.OP_VERIFY), Op(ts.OP_ENDIF),
		)
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
	return fullExitScript(depth, k, sparse, false)
}

// FullExitExactScript is EXIT_K^=, the exact-payout variant of EXIT_K
// (spec 7.2 rule 6): output i must equal leaf.amount for owner exits as
// well as evictions. It replaces EXIT_K in trees that host channel leaves
// (Appendix C.6.1) and is a tree-creation parameter
// (tools/layertree_scripts.py exit_script exact=True).
func FullExitExactScript(depth, k int, sparse bool) []Token {
	return fullExitScript(depth, k, sparse, true)
}

func fullExitScript(depth, k int, sparse, exact bool) []Token {
	s := fullCat(
		fullPrologue(),
		fullExitBlock(sparse, depth, 1, exact),
		fullCheckOldRootFromAlt(sparse), // T nh ns | m
	)
	for i := 2; i <= k; i++ {
		s = fullCat(s,
			[]Token{
				Op(ts.OP_SWAP), Op(ts.OP_TOALTSTACK), Op(ts.OP_TOALTSTACK),
				Op(ts.OP_DROP), // | m nh ns
			},
			fullExitBlock(sparse, depth, i, exact),
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

// Authorisation selectors for the carve body shared by CLAIM, CLAIM^h and
// SPLIT. They pick the authorisation check and nothing else: everything from
// the leaf size check onward is identical in all three.
const (
	authVoucher  = "voucher"  // CLAIM: a voucher signature over tree_id||src||claim
	authHashlock = "hashlock" // CLAIM^h: the same, plus SHA256(preimage)
	authOwner    = "owner"    // SPLIT: the owner's transaction signature
)

// FullClaimScript is CLAIM (spec 8.6):
// witness = [claim path] [source path] src_leaf claim_leaf voucher_sig root m.
// treeID is the tree's voucher binding (spec 6.2), a constant of the script.
func FullClaimScript(depth int, treeID [32]byte, sparse bool) []Token {
	return fullCarveScript(depth, treeID, sparse, authVoucher, false)
}

// FullClaimXScript is CLAIM^x, the exit-consent variant of CLAIM (spec
// 7.5.3): witness =
// [claim path] [source path] src_leaf claim_leaf voucher_sig exit_sig root m,
// with exit_sig a signature over the transaction by src_leaf.exit_key, as
// UPDATE^x adds to UPDATE. It is a tree-creation parameter: it makes a
// dedicated credit leaf trust-free (10.3) because the issuer, who owns the
// leaf, cannot carve it without the holder of its exit key.
func FullClaimXScript(depth int, treeID [32]byte, sparse bool) []Token {
	return fullCarveScript(depth, treeID, sparse, authVoucher, true)
}

// FullClaimHXScript is CLAIM^hx, the hash-locked voucher with exit-key
// consent (spec 7.5.3): CLAIM^h's witness with exit_sig between the preimage
// and root.
func FullClaimHXScript(depth int, treeID [32]byte, sparse bool) []Token {
	return fullCarveScript(depth, treeID, sparse, authHashlock, true)
}

// FullClaimHScript is CLAIM^h, the hash-locked voucher variant of CLAIM
// (spec 7.5.1): witness =
// [claim path] [source path] src_leaf claim_leaf voucher_sig preimage root m,
// with the signed message gaining SHA256(preimage) as a fourth field under a
// separate tag. The script never compares the payment hash against a witness
// copy; it computes it from the preimage and feeds it to the message, so a
// wrong preimage fails as a bad signature. It is a tree-creation parameter: a
// tree uses either CLAIM or CLAIM^h, never both.
func FullClaimHScript(depth int, treeID [32]byte, sparse bool) []Token {
	return fullCarveScript(depth, treeID, sparse, authHashlock, false)
}

// FullSplitScript is SPLIT (spec 7.5.2): CLAIM authorised by the owner's
// transaction signature instead of a voucher. Witness =
// [claim path] [source path] src_leaf new_leaf owner_sig root m. The steps,
// the seq increment, the drained-source rule and conservation are exactly
// CLAIM's; only the authorisation differs, which is why it shares CLAIM's
// body. Like CLAIM^h it is a tree-creation parameter and stays out of the
// reference taptree. It carries no tree_id: nothing in it signs a message.
func FullSplitScript(depth int, sparse bool) []Token {
	return fullCarveScript(depth, [32]byte{}, sparse, authOwner, false)
}

// fullCarveLeafRules opens every carve body: [src claim] -> [src claim],
// both leaves 116 bytes, and the claim leaf no easier to keep than the
// source (spec 7.5 rule 5): its evictor_key equals the source's and its
// evict_after is no later. Shared with the CCV tier
// (tools/layertree_scripts.py carve_leaf_rules).
func fullCarveLeafRules() []Token {
	return []Token{
		Op(ts.OP_SIZE), Num(fullLeafLen), Op(ts.OP_EQUALVERIFY),
		Op(ts.OP_SWAP), Op(ts.OP_SIZE), Num(fullLeafLen), Op(ts.OP_EQUALVERIFY),
		Op(ts.OP_SWAP), // src claim
		Op(ts.OP_2DUP), Num(fullOffEvictorKey), Num(32), Op(OP_SUBSTR),
		Op(ts.OP_SWAP), Num(fullOffEvictorKey), Num(32), Op(OP_SUBSTR),
		Op(ts.OP_EQUALVERIFY), // claim.evictor_key == src.evictor_key
		Op(ts.OP_2DUP), Num(fullOffEvictAfter), Num(fullLenEvictAfter), Op(OP_SUBSTR),
		Op(ts.OP_SWAP), Num(fullOffEvictAfter), Num(fullLenEvictAfter), Op(OP_SUBSTR),
		Op(ts.OP_LESSTHANOREQUAL), Op(ts.OP_VERIFY), // claim.evict_after <= src.evict_after
	}
}

// fullVoucherAuth is the voucher check of CLAIM and CLAIM^h (spec 7.5 rule
// 1, 7.5.1 rule 1), shared with the CCV tier: [src claim vsig] -> [src
// claim], with SHA256(preimage) parked on the altstack beforehand under
// hashlock. The message is H_voucher(tree_id || src || claim) with tree_id
// a constant of the script, so the check needs no copy of m
// (tools/layertree_scripts.py voucher_auth).
func fullVoucherAuth(treeID [32]byte, hashlock bool) []Token {
	s := []Token{
		Num(2), Op(ts.OP_PICK), Num(2), Op(ts.OP_PICK), Op(OP_CAT), // src claim vsig (src||claim)
		Data(treeID[:]), Op(ts.OP_SWAP), Op(OP_CAT), // (tree_id||src||claim)
	}
	prefix := fullVoucherPrefix
	if hashlock {
		s = append(s, Op(ts.OP_FROMALTSTACK), Op(OP_CAT)) // (tree_id||src||claim||phash)
		prefix = fullVoucherHPrefix
	}
	s = append(s, fullTagged(prefix)...) // src claim vsig msg
	return append(s,
		Num(3), Op(ts.OP_PICK), Num(fullOffOwnerKey), Num(32), Op(OP_SUBSTR),
		Op(OP_CHECKSIGFROMSTACK), Op(ts.OP_VERIFY), // src claim
	)
}

// fullCarveScript is the shared body of CLAIM, CLAIM^h and SPLIT: carve a new
// leaf out of an existing one. auth selects the authorisation and nothing
// else. exitConsent (CLAIM^x, CLAIM^hx) consumes one more witness element,
// exit_sig, directly below root, before anything else, checked against
// src_leaf.exit_key, so every stack depth below is as in the plain form.
// Seven bytes over the plain script, as UPDATE^x over UPDATE.
func fullCarveScript(depth int, treeID [32]byte, sparse bool, auth string,
	exitConsent bool) []Token {

	hashlock := auth == authHashlock
	s := fullPrologue() // src claim sig [pre] [xsig] | m r
	if exitConsent {
		// src is 3 deep under xsig, 4 with the preimage in between.
		srcDepth := int64(3)
		if hashlock {
			srcDepth = 4
		}
		s = fullCat(s, []Token{
			Num(srcDepth), Op(ts.OP_PICK),
			Num(fullOffExitKey), Num(32), Op(OP_SUBSTR),
			Op(ts.OP_CHECKSIGVERIFY), // src claim sig [pre]
		})
	}
	if auth == authOwner {
		// SPLIT: the owner signs the transaction, so no message is rebuilt.
		s = fullCat(s, []Token{
			Num(2), Op(ts.OP_PICK), Num(fullOffOwnerKey), Num(32),
			Op(OP_SUBSTR),            // src claim sig owner_key
			Op(ts.OP_CHECKSIGVERIFY), // src claim
		})
	} else {
		if hashlock {
			// Park SHA256(preimage) on the altstack so that every stack depth
			// below is exactly as in CLAIM.
			s = fullCat(s, []Token{
				Op(ts.OP_SIZE), Num(32), Op(ts.OP_EQUALVERIFY),
				Op(ts.OP_SHA256), Op(ts.OP_TOALTSTACK), // src claim vsig | m r phash
			})
		}
		s = fullCat(s, fullVoucherAuth(treeID, hashlock)) // src claim
	}
	// Everything below is the shared carve body: both steps and FINAL.
	// Stack on entry: src claim ; altstack: m r.
	s = fullCat(s,
		fullCarveLeafRules(),
		[]Token{
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

// ---------------------------------------------------------------------------
// Cohort rewrite: REWRITE_h (dense profile, spec 7.9, 8.9).
//
// The post-order fold of EVICT_SUBTREE_h run over two subtrees at once: for
// every position the witness supplies an old element and a new element (a
// 116-byte leaf or the empty string for E_0), the old elements fold to the
// old node, the new elements to the new node, and both fold up the shared
// path. A position whose old element is a leaf and whose new element differs
// needs a signature by the old leaf's owner_key, except when the only change
// is an increase of amount; a position whose new element is empty is an exit
// and pays the old leaf to its exit key from the next unused output. The
// operator signs once. Under the ^x creation parameter the old leaf's
// exit_key signs wherever the owner does.
//
// Signatures are consumed only where the rules require them: the next
// witness element is always directly below T and every roll depth is a
// constant, so a branch that needs a signature rolls one more element and a
// branch that does not leaves the witness untouched.
// ---------------------------------------------------------------------------

// fullElemNode: [elem] -> [h s]; a 116-byte leaf gives (H_leaf, amount), the
// empty element E_0. The TAG_LEAF prefix and E_0 are not pushed inline: the
// rewrite keeps one copy of each below T and picks them, at depth kLeaf
// (measured with `amt leaf` on top) and kEmpty (with the element dropped).
func fullElemNode(kLeaf, kEmpty int) []Token {
	return []Token{
		Op(ts.OP_SIZE), Op(ts.OP_0NOTEQUAL),
		Op(ts.OP_IF), Op(ts.OP_SIZE), Num(fullLeafLen), Op(ts.OP_EQUALVERIFY),
		Op(ts.OP_DUP), Num(8), Op(OP_LEFT), Op(ts.OP_SWAP), // amt leaf
		Num(int64(kLeaf)), Op(ts.OP_PICK), Op(ts.OP_SWAP), Op(OP_CAT),
		Op(ts.OP_SHA256), Op(ts.OP_SWAP), // h amt
		Op(ts.OP_ELSE), Op(ts.OP_DROP), Num(int64(kEmpty)), Op(ts.OP_PICK),
		Op(ts.OP_0), Op(ts.OP_ENDIF), // E_0 0
	}
}

// fullOwnerAuth: [... old new] -> [... old new], consuming the next witness
// element (at depth k) as a signature by old.owner_key, and under ^x one
// more by old.exit_key.
func fullOwnerAuth(k int, exitConsent bool) []Token {
	s := []Token{
		Num(int64(k)), Op(ts.OP_ROLL), Num(2), Op(ts.OP_PICK),
		Num(fullOffOwnerKey), Num(32), Op(OP_SUBSTR), Op(ts.OP_CHECKSIGVERIFY),
	}
	if exitConsent {
		s = append(s,
			Num(int64(k)), Op(ts.OP_ROLL), Num(2), Op(ts.OP_PICK),
			Num(fullOffExitKey), Num(32), Op(OP_SUBSTR), Op(ts.OP_CHECKSIGVERIFY),
		)
	}
	return s
}

// fullRewriteStep: [Z L T ...] with old, new and any signatures below Z ->
// [Z L T ... oh os nh ns]; the altstack's output index advances on an exit.
// d is the number of machine elements above T; Z (E_0's hash) and L (the
// TAG_LEAF prefix) sit directly below T, so the next witness element is at
// depth d+3.
func fullRewriteStep(d int, exitConsent bool) []Token {
	return fullCat(
		[]Token{
			Num(int64(d + 3)), Op(ts.OP_ROLL), Num(int64(d + 4)), Op(ts.OP_ROLL), // old new
			Op(ts.OP_2DUP), Op(ts.OP_EQUAL), Op(ts.OP_NOTIF), // changed?
			Op(ts.OP_OVER), Op(ts.OP_SIZE), Op(ts.OP_NIP), Op(ts.OP_0NOTEQUAL),
			Op(ts.OP_IF), // old is a leaf?
			Op(ts.OP_DUP), Op(ts.OP_SIZE), Op(ts.OP_NIP), Op(ts.OP_0NOTEQUAL),
			Op(ts.OP_IF), // new is a leaf: rewrite
			// Exempt from the owner signature iff new[8:] == old[8:],
			// old.amount <= new.amount and old.seq != SEQ_FINAL (7.9 rule
			// 3); same_rest makes new.seq equal old.seq.
			Op(ts.OP_2DUP), Num(fullOffExitKey), Num(fullLeafLen - fullOffExitKey),
			Op(OP_SUBSTR),
			Op(ts.OP_SWAP), Num(fullOffExitKey), Num(fullLeafLen - fullOffExitKey),
			Op(OP_SUBSTR), Op(ts.OP_EQUAL), // old new same_rest
			Op(ts.OP_IF), Op(ts.OP_2DUP), Op(ts.OP_SWAP), Num(8), Op(OP_LEFT),
			Op(ts.OP_SWAP), Num(8), Op(OP_LEFT), Op(ts.OP_LESSTHANOREQUAL),
			Op(ts.OP_OVER), Num(4), Op(OP_RIGHT), Data(fullSeqFinal),
			Op(ts.OP_EQUAL), Op(ts.OP_NOT), Op(ts.OP_BOOLAND),
			Op(ts.OP_ELSE), Op(ts.OP_0), Op(ts.OP_ENDIF), // old new exempt
			Op(ts.OP_NOTIF),
		},
		fullOwnerAuth(d+5, exitConsent),
		[]Token{Op(ts.OP_ENDIF), Op(ts.OP_ELSE)}, // new is empty: an exit
		fullOwnerAuth(d+5, exitConsent),
		[]Token{
			Op(ts.OP_FROMALTSTACK), Op(ts.OP_DUP), Op(ts.OP_1ADD),
			Op(ts.OP_TOALTSTACK),         // old new idx
			Num(SelOutSingle), Op(OP_TX), // old new amt spk
			Data(fullP2TRPrefix), Num(4), Op(ts.OP_PICK), Num(fullOffExitKey),
			Num(32), Op(OP_SUBSTR), Op(OP_CAT),
			Op(ts.OP_EQUALVERIFY), // old new amt
			Num(2), Op(ts.OP_PICK), Num(8), Op(OP_LEFT),
			Op(ts.OP_NUMEQUALVERIFY), // old new (exact payout)
			Op(ts.OP_ENDIF),
			Op(ts.OP_ENDIF), // old empty: a join, operator only
			Op(ts.OP_ENDIF), // unchanged
			Op(ts.OP_SWAP),
		},
		fullElemNode(d+4, d+3), // new oh os
		[]Token{Op(ts.OP_ROT)},
		fullElemNode(d+5, d+4), // oh os nh ns
	)
}

// fullHashStep2: [T ... loh los lnh lns roh ros rnh rns] ->
// [T ... poh pos pnh pns]; d machine elements above T. Two HASH_STEPs, the
// old pair first, then the new pair. The eight nodes sit on top, so the roll
// depths are constants; only the HASH_STEP pick depth for T varies with d.
func fullHashStep2(d int) []Token {
	return fullCat(
		[]Token{
			Op(ts.OP_2SWAP), Num(7), Op(ts.OP_ROLL), Num(7), Op(ts.OP_ROLL),
			Op(ts.OP_2SWAP), // lnh lns rnh rns loh los roh ros
		},
		fullHashStep(d), // lnh lns rnh rns poh pos
		[]Token{
			Op(ts.OP_2SWAP), Num(5), Op(ts.OP_ROLL), Num(5), Op(ts.OP_ROLL),
			Op(ts.OP_2SWAP), // poh pos lnh lns rnh rns
		},
		fullHashStep(d-2), // poh pos pnh pns
	)
}

// FullRewriteScript is REWRITE_h (spec 7.9, dense profile), and REWRITE_h^x
// with exitConsent.
//
// witness (bottom..top) = [dir sc]*(D-h) block_{2^h-1} ... block_0 sig_op r m,
// block_i = [xsig_i] [sig_i] new_i old_i (old_i on top; each element is a
// 116-byte leaf or empty; sig_i only where 7.9 rule 3 requires it, xsig_i
// only under ^x and only where sig_i is present).
func FullRewriteScript(depth, height int, operatorKey [32]byte,
	exitConsent bool) []Token {

	s := fullCat(
		fullPrologue(),
		[]Token{Data(operatorKey[:]), Op(ts.OP_CHECKSIGVERIFY)}, // ...blocks | m r
		[]Token{
			Op(ts.OP_1), Op(ts.OP_TOALTSTACK), // | m r 1
			Data(fullEmptyLeafHash), Data(fullLeafPrefix), Data(fullNodePrefix), // Z L T
		},
	)
	d := 0
	var gen func(h int)
	gen = func(h int) {
		if h == 0 {
			s = append(s, fullRewriteStep(d, exitConsent)...)
			d += 4
			return
		}
		gen(h - 1)
		gen(h - 1)
		s = append(s, fullHashStep2(d)...)
		d -= 4
	}
	gen(height) // Z L T oh os nh ns | m r idx

	return fullCat(s,
		[]Token{
			Op(ts.OP_FROMALTSTACK), Op(ts.OP_DROP), // drop idx
			Num(6), Op(ts.OP_ROLL), Op(ts.OP_DROP), Num(5), Op(ts.OP_ROLL),
			Op(ts.OP_DROP), // T oh os nh ns (drop Z, L)
		},
		fullLevels(false, depth, height),
		fullCheckOldRootFromAlt(false),
		fullFinalOutput(depth),
	)
}

// FullTreeOptions are a tree's creation parameters other than its depth
// (spec 6.2): the profile, operator key, tree_id, the JOIN heights, EXIT_K
// sizes and JOINK sizes, and the variants a taptree may carry (7.6): exact
// payouts (7.2 rule 6, in place of EXIT_K), UPDATE^x (7.4 rule 5, in place
// of UPDATE), the four CLAIM forms, SPLIT, EVICT_SUBTREE_h, REWRITE_h and
// its ^x form, and DETACH_h. Scripts compiles the set for one depth, which
// is what the parent's taptree is built from and what a DETACH_h child
// MUST be built from at depth h (7.10 rule 3): a cohort keeps its rules
// when it is detached (tools/layertree_scripts.py TreeOptions).
type FullTreeOptions struct {
	OperatorKey [32]byte
	TreeID      [32]byte
	Sparse      bool
	JoinHeights []int
	ExitKs      []int
	JoinKs      []int

	Exact          bool
	UpdateX        bool
	Claim          bool
	ClaimH         bool
	ClaimX         bool
	ClaimHX        bool
	Split          bool
	EvictHeights   []int
	RewriteHeights []int
	RewriteX       bool
	DetachHeights  []int
}

// FullReferenceOptions are the reference set of 6.2 at the heights and
// sizes the detached root used before 0.10.0: EXIT_1, EXIT_2, JOIN_0,
// JOINK_2, UPDATE and CLAIM, dense.
func FullReferenceOptions(operatorKey, treeID [32]byte) FullTreeOptions {
	return FullTreeOptions{
		OperatorKey: operatorKey, TreeID: treeID,
		JoinHeights: []int{0}, ExitKs: []int{1, 2}, JoinKs: []int{2},
		Claim: true,
	}
}

// FullNamedScript is one leaf of an option set: the generator's name for
// the script and its tokens.
type FullNamedScript struct {
	Name   string
	Tokens []Token
}

// Scripts compiles the option set for a tree of the given depth, in the
// order tools/layertree_scripts.py TreeOptions.at_depth emits it: the
// reference members first (EXIT_K, JOIN_h, JOINK_K, UPDATE, CLAIM), then
// the variants in a fixed order. Heights that do not fit the depth are
// dropped, and DETACH_h embeds the same options compiled at depth h.
func (o FullTreeOptions) Scripts(depth int) []FullNamedScript {
	var out []FullNamedScript
	add := func(name string, toks []Token) {
		out = append(out, FullNamedScript{Name: name, Tokens: toks})
	}
	for _, k := range o.ExitKs {
		add(fmt.Sprintf("EXIT_%d", k), fullExitScript(depth, k, o.Sparse, o.Exact))
	}
	heights := o.JoinHeights
	if o.Sparse {
		heights = []int{0}
	}
	for _, h := range heights {
		if h <= depth {
			add(fmt.Sprintf("JOIN_%d", h), FullJoinScript(depth, h, o.OperatorKey, o.Sparse, 1))
		}
	}
	for _, k := range o.JoinKs {
		add(fmt.Sprintf("JOINK_%d", k), FullJoinScript(depth, 0, o.OperatorKey, o.Sparse, k))
	}
	if o.UpdateX {
		add("UPDATE_X", FullUpdateXScript(depth, o.OperatorKey, o.Sparse))
	} else {
		add("UPDATE", FullUpdateScript(depth, o.OperatorKey, o.Sparse))
	}
	if o.Claim {
		add("CLAIM", FullClaimScript(depth, o.TreeID, o.Sparse))
	}
	if o.ClaimH {
		add("CLAIM_H", FullClaimHScript(depth, o.TreeID, o.Sparse))
	}
	if o.ClaimX {
		add("CLAIM_X", FullClaimXScript(depth, o.TreeID, o.Sparse))
	}
	if o.ClaimHX {
		add("CLAIM_HX", FullClaimHXScript(depth, o.TreeID, o.Sparse))
	}
	if o.Split {
		add("SPLIT", FullSplitScript(depth, o.Sparse))
	}
	if o.Sparse {
		return out
	}
	for _, h := range o.EvictHeights {
		if h <= depth {
			add(fmt.Sprintf("EVICT_SUBTREE_%d", h), FullEvictSubtreeScript(depth, h, o.OperatorKey))
		}
	}
	for _, h := range o.RewriteHeights {
		if h <= depth {
			add(fmt.Sprintf("REWRITE_%d", h), FullRewriteScript(depth, h, o.OperatorKey, false))
			if o.RewriteX {
				add(fmt.Sprintf("REWRITE_X_%d", h), FullRewriteScript(depth, h, o.OperatorKey, true))
			}
		}
	}
	for _, h := range o.DetachHeights {
		if h < depth {
			add(fmt.Sprintf("DETACH_%d", h), FullDetachScript(depth, h, o.OperatorKey, o.TapTreeRoot(h)))
		}
	}
	return out
}

// TapTreeRoot is the tree identifier m of a tree of the given depth created
// with these options (spec 6.2); for a DETACH_h child it is m_h.
func (o FullTreeOptions) TapTreeRoot(depth int) [32]byte {
	scripts := o.Scripts(depth)
	leaves := make([][32]byte, 0, len(scripts))
	for _, s := range scripts {
		leaves = append(leaves, TapLeafHash(MustAssemble(s.Tokens, ModeC2), 0xc2))
	}
	return TapTreeRoot(leaves)
}

// FullDetachedTaptreeRoot is m_h for DETACH_h (spec 7.10 rule 3): the
// parent's option set compiled for depth h, with the same operator key and
// the same tree_id. For the reference set of 6.2 pass
// FullReferenceOptions; a parent created with exact payouts, UPDATE^x,
// further CLAIM forms, SPLIT, sweeps, rewrites or detaches passes its own
// options, and the child keeps every one that fits depth h. The detached
// tree inherits tree_id, so vouchers against its leaves survive the detach
// (tools/layertree_scripts.py detached_taptree_root).
func FullDetachedTaptreeRoot(height int, opts FullTreeOptions) [32]byte {
	return opts.TapTreeRoot(height)
}

// FullDetachScript is DETACH_h (spec 7.10, dense profile): move an aligned
// subtree of height h into a tree output of its own. The old node is the
// subtree root supplied by the witness, the new node is E_h, and output 1 is
// a tree output of depth h carrying the subtree root under mH, the taptree
// root of the script set compiled for depth h, a constant of the script.
//
// witness (bottom..top) = [dir sc]*(D-h) R_h sum_h8 sig r m.
func FullDetachScript(depth, height int, operatorKey [32]byte,
	mH [32]byte) []Token {

	eH := tree.EmptyNode(height).Hash
	return fullCat(
		fullPrologue(),
		[]Token{Data(operatorKey[:]), Op(ts.OP_CHECKSIGVERIFY)}, // R_h sum8 | m r
		[]Token{
			Op(ts.OP_SIZE), Num(8), Op(ts.OP_EQUALVERIFY),
			Op(ts.OP_OVER), Op(ts.OP_SIZE), Num(32), Op(ts.OP_EQUALVERIFY),
			Op(ts.OP_DROP),              // R_h sum8
			Op(ts.OP_OVER), Data(mH[:]), // R_h sum8 R_h m_h
		},
		fullTreeSPK(), // R_h sum8 spk1
		[]Token{
			Op(ts.OP_1), Num(SelOutSingle), Op(OP_TX), // R_h sum8 spk1 amt1 spk1'
			Op(ts.OP_ROT), Op(ts.OP_EQUALVERIFY), // R_h sum8 amt1
			Op(ts.OP_OVER), Op(ts.OP_NUMEQUALVERIFY), // R_h sum8
			Data(fullNodePrefix), Op(ts.OP_ROT), Op(ts.OP_ROT), // T R_h sum8
			Data(eH[:]), Op(ts.OP_0), // T R_h sum8 E_h 0
		},
		fullLevels(false, depth, height),
		fullCheckOldRootFromAlt(false),
		fullFinalOutput(depth),
	)
}

// FullAllScripts returns the FULL-tier taptree script set for a tree, keyed
// exactly as tools/layertree_scripts.py's all_scripts: "EXIT_%d", "JOIN_%d",
// "JOINK_%d", "UPDATE" and "CLAIM". treeID is the tree's voucher binding
// (spec 6.2), which CLAIM carries as a constant. In the sparse profile only
// height 0 joins exist, so joinHeights is ignored there.
func FullAllScripts(depth int, operatorKey, treeID [32]byte, sparse bool,
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
	out["CLAIM"] = FullClaimScript(depth, treeID, sparse)
	return out
}
