package script

import (
	"github.com/btcsuite/btcd/txscript"
)

// This file ports the MID tier's pending-leaf receive from
// tools/layertree_mid.py (design/pending-receive.md): the merge claims
// CLAIM^m and CLAIM^hm (spec 7.5.4), RECLAIM_1 (7.11) and the reclaim form
// of REWRITE_h (7.9 rule 8). A tree that carries them names RECLAIM_KEY at
// creation; a leaf is reclaimable when its evictor_key is RECLAIM_KEY.

// The merge voucher tags (spec 5.1, 7.5.4), distinct from the carve
// voucher's so that no voucher of one form redeems as another.
const (
	midTagVoucherM  = "LayerTree/voucher-merge"
	midTagVoucherHM = "LayerTree/voucher-merge-hashlock"
)

var (
	midVoucherMPrefix  = midTagPrefix(midTagVoucherM)
	midVoucherHMPrefix = midTagPrefix(midTagVoucherHM)
)

// midSc pushes a leaf's 41-byte node H_leaf(amt8||rest) || amt8 || 01 from
// copies: amt8 at depth a, rest at depth r, the TAG_LEAF prefix at depth l.
// Nothing is consumed (tools/layertree_mid.py _sc).
func midSc(a, r, l int64) []Token {
	return []Token{
		Num(a), Op(txscript.OP_PICK), Num(r + 1), Op(txscript.OP_PICK),
		Op(txscript.OP_CAT),
		Num(l + 1), Op(txscript.OP_PICK), Op(txscript.OP_SWAP), Op(txscript.OP_CAT),
		Op(txscript.OP_SHA256),
		Num(a + 1), Op(txscript.OP_PICK), Data([]byte{0x01}), Op(txscript.OP_CAT),
		Op(txscript.OP_CAT),
	}
}

// midNotFinal is [.. x] -> [..]: the element at depth d is not MID's
// SEQ_FINAL as raw bytes.
func midNotFinal(d int64) []Token {
	return []Token{Num(d), Op(txscript.OP_PICK), Data(midSeqFinal),
		Op(txscript.OP_EQUAL), Op(txscript.OP_NOT), Op(txscript.OP_VERIFY)}
}

// MidMergeScript is CLAIM^m (spec 7.5.4), or CLAIM^hm with hashlock, in the
// MID tier (tools/layertree_mid.py merge_script). Dense only. reclaimKey is
// the tree's RECLAIM_KEY or nil; dustMin zero means tree.DustMin.
//
// witness (bottom..top) = zf wf zi wi [levels 1..D-1] f zr wr xn zx wx
// S(10) T(10) vsig [preimage] r m. S and T are the source and target leaf
// blocks of a pair, f (empty or 0x01) is src_is_left, X arrives as the
// minimal number xn with its PADZ pad and zr wr pad the source's residual.
func MidMergeScript(depth int, treeID [32]byte, hashlock bool,
	reclaimKey *[32]byte, dustMin uint64) []Token {

	var hl int64
	if hashlock {
		hl = 1
	}
	s := midPrologue()
	if hashlock {
		s = append(s, Op(txscript.OP_SIZE), Num(32), Op(txscript.OP_EQUALVERIFY),
			Op(txscript.OP_SHA256))
	}
	s = append(s, midRepeat([]Token{Num(23 + hl), Op(txscript.OP_PICK)}, 3)...)
	s = append(s, midLe64()...)
	s = append(s, Op(txscript.OP_DUP), Op(txscript.OP_TOALTSTACK)) // .. vsig [ph] X8 | m r X8
	if hashlock {
		s = append(s, Op(txscript.OP_SWAP), Op(txscript.OP_CAT))
	}
	s = append(s, midRepeat([]Token{Num(20), Op(txscript.OP_PICK)}, 6)...)
	s = append(s, midRepeat([]Token{Op(txscript.OP_CAT)}, 5)...) // body(S)
	s = append(s, midRepeat([]Token{Num(11), Op(txscript.OP_PICK)}, 6)...)
	s = append(s, midRepeat([]Token{Op(txscript.OP_CAT)}, 6)...) // body(S)||body(T)
	s = append(s, Op(txscript.OP_SWAP), Op(txscript.OP_CAT), Data(treeID[:]),
		Op(txscript.OP_SWAP), Op(txscript.OP_CAT))
	if hashlock {
		s = append(s, midTagged(midVoucherHMPrefix)...)
	} else {
		s = append(s, midTagged(midVoucherMPrefix)...)
	}
	s = append(s, Num(19), Op(txscript.OP_PICK), Op(OP_CHECKSIGFROMSTACK),
		Op(txscript.OP_VERIFY)) // f zr wr xn zx wx S(10) T(10)

	// Rule 2: the target belongs and exits to the source's exit key, and
	// neither leaf is final.
	s = append(s,
		Num(7), Op(txscript.OP_PICK), Num(19), Op(txscript.OP_PICK),
		Op(txscript.OP_EQUALVERIFY), // T.ok == S.ek
		Num(8), Op(txscript.OP_PICK), Num(19), Op(txscript.OP_PICK),
		Op(txscript.OP_EQUALVERIFY), // T.ek == S.ek
	)
	s = append(s, midNotFinal(3)...)
	s = append(s, midNotFinal(13)...)
	if reclaimKey != nil {
		s = append(s, Num(6), Op(txscript.OP_PICK), Data(reclaimKey[:]),
			Op(txscript.OP_EQUAL), Op(txscript.OP_NOT), Op(txscript.OP_VERIFY))
	}
	s = append(s, midLeafJoinNew()...)
	s = append(s, midRepeat([]Token{Op(txscript.OP_TOALTSTACK)}, 3)...)
	s = append(s, midLeafJoinNew()...)
	s = append(s, midRepeat([]Token{Op(txscript.OP_FROMALTSTACK)}, 3)...)

	// Rule 3: d = X - T.amount >= 1, residual 0 or >= DUST_MIN.
	s = append(s,
		Num(8), Op(txscript.OP_PICK), Op(txscript.OP_SWAP), Op(txscript.OP_SUB),
		Op(txscript.OP_DUP), Op(txscript.OP_1), Op(txscript.OP_GREATERTHANOREQUAL),
		Op(txscript.OP_VERIFY),
		Num(3), Op(txscript.OP_ROLL), Op(txscript.OP_SWAP), Op(txscript.OP_SUB),
		Op(txscript.OP_DUP), Num(10), Op(txscript.OP_PICK), Num(10), Op(txscript.OP_PICK),
	)
	s = append(s, midLe64()...)
	s = append(s, Data(midLeafPrefix), Op(txscript.OP_FROMALTSTACK))
	s = append(s, midSc(0, 4, 1)...) // nT
	s = append(s, Num(4), Op(txscript.OP_PICK), Op(txscript.OP_0NOTEQUAL),
		Op(txscript.OP_IF),
		Num(int64(dustFloor(dustMin))), Num(5), Op(txscript.OP_PICK),
		Op(txscript.OP_LESSTHANOREQUAL), Op(txscript.OP_VERIFY))
	s = append(s, midSc(3, 7, 2)...)
	s = append(s, Op(txscript.OP_ELSE), Data(midEvictE0Sc), Op(txscript.OP_ENDIF))
	s = append(s, midSc(7, 6, 3)...)
	s = append(s, midSc(10, 9, 4)...)
	s = append(s,
		Num(17), Op(txscript.OP_PICK), Op(txscript.OP_IF), Op(txscript.OP_SWAP),
		Op(txscript.OP_ENDIF), Op(txscript.OP_CAT), Op(txscript.OP_TOALTSTACK),
		Num(15), Op(txscript.OP_PICK), Op(txscript.OP_IF), Op(txscript.OP_SWAP),
		Op(txscript.OP_ENDIF), Op(txscript.OP_CAT),
		Num(4), Op(txscript.OP_PICK), Num(12), Op(txscript.OP_PICK), Op(txscript.OP_ADD),
		Op(txscript.OP_TOALTSTACK), Op(txscript.OP_TOALTSTACK),
	)
	s = append(s, midRepeat([]Token{Op(txscript.OP_2DROP)}, 7)...)
	s = append(s,
		Data(midNodePrefix), Op(txscript.OP_FROMALTSTACK), Op(txscript.OP_OVER),
		Op(txscript.OP_SWAP), Op(txscript.OP_CAT), Op(txscript.OP_SHA256),
		Op(txscript.OP_FROMALTSTACK), Op(txscript.OP_FROMALTSTACK),
		Num(3), Op(txscript.OP_PICK), Op(txscript.OP_SWAP), Op(txscript.OP_CAT),
		Op(txscript.OP_SHA256),
		Op(txscript.OP_SWAP), Op(txscript.OP_ROT), Op(txscript.OP_OVER), // T oh os nh ns
	)
	s = append(s, midLevels(false, depth, 1)...)
	s = append(s, midCheckOld(false)...)
	return append(s, midFinal(depth)...)
}

// MidReclaimScript is RECLAIM_1 (spec 7.11) in the MID tier
// (tools/layertree_mid.py reclaim_script): EXIT_1's eviction branch with
// RECLAIM_KEY in place of the evictor and no payout.
//
// witness (bottom..top) = zf wf zi wi [levels] [sparse: ok nonce plo phi]
// leaf(10) ea_num ze we sig r m.
func MidReclaimScript(depth int, reclaimKey [32]byte, sparse bool) []Token {
	s := midPrologue()
	s = append(s, Data(reclaimKey[:]), Op(txscript.OP_CHECKSIGVERIFY),
		Num(2), Op(txscript.OP_PICK), Op(txscript.OP_CHECKLOCKTIMEVERIFY),
		Op(txscript.OP_DROP))
	s = append(s, midPadz()...)
	s = append(s, Num(6), Op(txscript.OP_PICK), Op(txscript.OP_EQUALVERIFY),
		Num(6), Op(txscript.OP_PICK), Data(reclaimKey[:]), Op(txscript.OP_EQUALVERIFY))
	s = append(s, midLeafJoin()...)
	s = append(s, midTagged(midLeafPrefix)...)
	s = append(s, Op(txscript.OP_FROMALTSTACK))
	if sparse {
		s = append(s, midRoll(5, 4)...)
		s = append(s, midSparseSetup()...)
	}
	s = append(s, Data(midNodePrefix), Op(txscript.OP_ROT), Op(txscript.OP_ROT),
		Data(midEmptyLeafHash), Op(txscript.OP_0))
	s = append(s, midLevels(sparse, depth, 0)...)
	s = append(s, midCheckOld(sparse)...)
	return append(s, midFinal(depth)...)
}

// midRewriteR1 is R1 inside the reclaim-form rewrite: the next three
// witness elements are the old leaf's evict_after as a minimal number with
// its PADZ pad, checked against the lock time and the raw ea field, the
// deepest C_old item (tools/layertree_mid.py _rewrite_r1).
func midRewriteR1() []Token {
	s := []Token{Num(11), Op(txscript.OP_ROLL), Num(12), Op(txscript.OP_ROLL),
		Num(13), Op(txscript.OP_ROLL),
		Num(2), Op(txscript.OP_PICK), Op(txscript.OP_CHECKLOCKTIMEVERIFY),
		Op(txscript.OP_DROP)}
	s = append(s, midPadz()...)
	return append(s, Num(8), Op(txscript.OP_PICK), Op(txscript.OP_EQUALVERIFY))
}

// MidRewriteRScript is the reclaim form of REWRITE_h (spec 7.9 rule 8) in
// the MID tier, REWRITE_R_h, or REWRITE_XR_h with exitConsent, for a tree
// whose RECLAIM_KEY is reclaimKey; h >= 1. A position that takes R1
// carries, in place of its signatures, the old leaf's evict_after as
// we ze ea_num (tools/layertree_mid.py rewrite_script, w_reclaim).
func MidRewriteRScript(depth, height int, operatorKey [32]byte,
	exitConsent bool, reclaimKey [32]byte) []Token {

	s := midPrologue()
	s = append(s, Data(operatorKey[:]), Op(txscript.OP_CHECKSIGVERIFY))
	s = append(s, midRewriteBodyR(height, exitConsent, midRewritePay(), &reclaimKey)...)
	s = append(s, midLevels(false, depth, height)...)
	s = append(s, midCheckOld(false)...)
	return append(s, midFinal(depth)...)
}
