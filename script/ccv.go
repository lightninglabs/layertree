package script

import (
	ts "github.com/btcsuite/btcd/txscript"

	"github.com/roasbeef/layertree/tree"
)

// This file is a direct port of tools/layertree_ccv.py: the CCV tier
// (spec 4.6), i.e. the FULL tier's fold and authorization with every
// taproot-key binding replaced by BIP-443 OP_CHECKCONTRACTVERIFY calls.
// Scripts are assembled with ModeC2 (BIP-441 numerics).
//
// Everything here mirrors the Python token for token, including its
// oddities, so that the assembled bytes match spec/golden.json exactly.

// CCV modes (BIP-443, minimally encoded integers).
const (
	ccvModeCheckInput = -1
	ccvModeAssignOut  = 0
	ccvModeDeductOut  = 2
)

// ccvCheckInput: [... data] -> [...]. CHECK_INPUT on the current input
// (index -1), pk empty (the BIP-341 NUMS point), taptree -1 (the current
// input's own). The caller guarantees the data operand is the bare top of
// the stack with nothing above it; the four fixed operands go on top and
// the opcode consumes all five (tools/layertree_ccv.py ccv_check_input).
func ccvCheckInput() []Token {
	return []Token{
		Data(ccvMinus1), Data(ccvEmpty), Data(ccvMinus1), Data(ccvMinus1),
		Op(OP_CHECKCONTRACTVERIFY),
	}
}

// ccvTreeOutput: [... data] -> [...]. CHECK_OUTPUT on output outIndex in
// the assign mode (the input's residual amount flows to it), pk empty
// (NUMS), taptree -1 (the input's own): the tree output for state `data`.
// ccvFinal inlines exactly these operands; this names them, as
// tools/layertree_ccv.py ccv_tree_output does for the listings.
func ccvTreeOutput(outIndex int) []Token {
	return []Token{
		Num(int64(outIndex)), Data(ccvEmpty), Data(ccvMinus1), Num(ccvModeAssignOut),
		Op(OP_CHECKCONTRACTVERIFY),
	}
}

// ccvPayoutFixed: [... leaf] -> [... leaf]. CHECK_OUTPUT|DEDUCT on output
// outIndex as a bare P2TR to leaf.exit_key (data empty, taptree empty: no
// tweaks at all). The leaf is duplicated and parked twice; one copy is
// restored mid-sequence to extract the exit key, the other after the call
// for the amount comparison that follows.
func ccvPayoutFixed(outIndex int) []Token {
	return []Token{
		Op(ts.OP_DUP), Op(ts.OP_TOALTSTACK), // leaf            | B (dup)
		Op(ts.OP_TOALTSTACK),                 // ()              | B A
		Data(ccvEmpty), Num(int64(outIndex)), // "" idx          (data below index)
		Op(ts.OP_FROMALTSTACK),                      // "" idx B         | A
		Num(fullOffExitKey), Num(32), Op(OP_SUBSTR), // "" idx ek
		Data(ccvEmpty), Num(ccvModeDeductOut), Op(OP_CHECKCONTRACTVERIFY), // ()
		Op(ts.OP_FROMALTSTACK), // leaf (A)
	}
}

// ccvCheckOld: [T oh os nh ns] -> [T nh ns]. As fullCheckOldRootFromAlt
// with the root comparison replaced by the CCV input check: os == the
// input amount stays, then oh becomes the CCV data operand and
// CHECK_INPUT binds it to the input (tools/layertree_ccv.py
// check_old_ccv).
func ccvCheckOld(sparse bool) []Token {
	s := []Token{
		Op(ts.OP_2SWAP), Num(SelInAmount), Op(OP_TX), Op(ts.OP_NUMEQUALVERIFY), // T nh ns oh
	}
	if sparse {
		// The sparse bookkeeping (pos, E_k) sits on the altstack below the
		// fold's ns; tear it down before parking ns and nh.
		s = append(s, fullSparseTeardown()...)
	}
	s = append(s,
		Op(ts.OP_ROT), Op(ts.OP_ROT), // T oh nh ns (oh rolled to the front)
		Op(ts.OP_TOALTSTACK), // T oh nh    | [.. ns]
		Op(ts.OP_TOALTSTACK), // T oh       | [.. ns nh (nh on top)
	)
	s = append(s, ccvCheckInput()...)
	return append(s, Op(ts.OP_FROMALTSTACK), Op(ts.OP_FROMALTSTACK)) // T nh ns
}

// ccvFinal: [T nh ns] -> [1]. Output 0 is the tree output for nh (CCV
// assign mode) with amount == ns, unless nh == E_D (the terminal exit;
// no output-0 check). The equality keeps rule 5 exactly; the assign
// floor lets a JOIN fund output 0 from its other inputs.
func ccvFinal(depth int) []Token {
	eD := tree.EmptyNode(depth).Hash
	return []Token{
		Op(ts.OP_ROT), Op(ts.OP_DROP), // nh ns
		Op(ts.OP_OVER), Data(eD[:]), Op(ts.OP_EQUAL),
		Op(ts.OP_IF), Op(ts.OP_2DROP), Op(ts.OP_1),
		Op(ts.OP_ELSE),
		Op(ts.OP_TOALTSTACK), // nh        | ns
		Op(ts.OP_0), Data(ccvEmpty), Data(ccvMinus1), Num(ccvModeAssignOut),
		Op(OP_CHECKCONTRACTVERIFY), // ()   assign out0
		Op(ts.OP_FROMALTSTACK),     // ns
		// OP_TX SelOutSingle pushes [amount, spk] with the spk on top;
		// the CCV call already checked the spk, so drop it and compare
		// numerically (ns is a minimal number, the amount is le64).
		Op(ts.OP_0), Num(SelOutSingle), Op(OP_TX), Op(ts.OP_DROP), Op(ts.OP_NUMEQUALVERIFY),
		Op(ts.OP_1), Op(ts.OP_ENDIF),
	}
}

// ccvExitBlock is one exit: [path] leaf sig is_evict -> T oh os nh ns
// (after the levels). The payout scriptPubKey check is the CCV DEDUCT
// call; the amount comparison is exact (spec 7.2 rule 6; the tier's only
// payout mode).
func ccvExitBlock(sparse bool, depth, outIndex int) []Token {
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
	}
	s = append(s, ccvPayoutFixed(outIndex)...)
	s = append(s,
		// amount comparison: OP_TX SelOutSingle pushes [amount, spk];
		// drop the spk, then compare exactly.
		Num(int64(outIndex)), Num(SelOutSingle), Op(OP_TX), Op(ts.OP_DROP), // leaf out_amt
		Op(ts.OP_OVER), Num(8), Op(OP_LEFT), // leaf out_amt leaf_amt
		Op(ts.OP_FROMALTSTACK), Op(ts.OP_DROP), Op(ts.OP_NUMEQUALVERIFY), // exact for both
	)
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

// CCVExitScript is EXIT_K under the CCV tier: k sequential exits paying
// outputs 1..K. Witness (bottom..top) = [block_K] ... [block_1] with no
// root and no m (spec 4.6); block_i = [dir sc]*D (dense) or [sc]*D
// (sparse), then leaf_i sig_i is_evict_i.
func CCVExitScript(depth, k int, sparse bool) []Token {
	s := fullCat(ccvExitBlock(sparse, depth, 1), ccvCheckOld(sparse))
	for i := 2; i <= k; i++ {
		s = fullCat(s,
			[]Token{Op(ts.OP_SWAP), Op(ts.OP_TOALTSTACK), Op(ts.OP_TOALTSTACK), Op(ts.OP_DROP)},
			ccvExitBlock(sparse, depth, i),
			fullCheckPrevRootFromAlt(sparse),
		)
	}
	return fullCat(s, ccvFinal(depth))
}

// CCVJoinScript is JOIN_h / JOINK_K under the CCV tier. The join block
// and the chained-step checks are the FULL tier's; only the old-root and
// output-0 bindings are CCV calls. Witness = [block_k] ... [block_1] sig.
func CCVJoinScript(depth, height int, operatorKey [32]byte, sparse bool,
	k int) []Token {

	s := []Token{Data(operatorKey[:]), Op(ts.OP_CHECKSIGVERIFY)}
	s = fullCat(s, fullJoinBlock(sparse, depth, height), ccvCheckOld(sparse))
	for i := 2; i <= k; i++ {
		s = fullCat(s,
			[]Token{Op(ts.OP_SWAP), Op(ts.OP_TOALTSTACK), Op(ts.OP_TOALTSTACK), Op(ts.OP_DROP)},
			fullJoinBlock(sparse, depth, height),
			fullCheckPrevRootFromAlt(sparse),
		)
	}
	return fullCat(s, ccvFinal(depth))
}

// CCVUpdateXScript is UPDATE^x under the CCV tier: UPDATE with the
// exiting leaf's exit-key consent (spec 7.4 rule 5). The witness carries
// one more signature directly above the operator's, valid over the same
// transaction by old_leaf.exit_key.
func CCVUpdateXScript(depth int, operatorKey [32]byte, sparse bool) []Token {
	s := []Token{
		Op(ts.OP_4), Op(ts.OP_PICK), Num(fullOffExitKey), Num(32), Op(OP_SUBSTR),
		Op(ts.OP_CHECKSIGVERIFY), // old new osig opsig
	}
	return fullCat(s, CCVUpdateScript(depth, operatorKey, sparse))
}

// CCVUpdateScript is UPDATE under the CCV tier. Witness =
// [path] old_leaf new_leaf owner_sig op_sig, with no root and no m.
func CCVUpdateScript(depth int, operatorKey [32]byte, sparse bool) []Token {
	s := []Token{
		Data(operatorKey[:]), Op(ts.OP_CHECKSIGVERIFY),
		Op(ts.OP_2), Op(ts.OP_PICK), Num(fullOffOwnerKey), Num(32), Op(OP_SUBSTR),
		Op(ts.OP_CHECKSIGVERIFY), // old new
		Op(ts.OP_SIZE), Num(fullLeafLen), Op(ts.OP_EQUALVERIFY),
		Op(ts.OP_SWAP), Op(ts.OP_SIZE), Num(fullLeafLen), Op(ts.OP_EQUALVERIFY), // new old
	}
	if sparse {
		s = fullCat(s, fullLeafPos(), []Token{Op(ts.OP_ROT)},
			fullLeafPos(), []Token{Op(ts.OP_ROT), Op(ts.OP_EQUALVERIFY), Op(ts.OP_SWAP)},
			fullLeafPos(), fullSparseSetup())
	}
	return fullCat(s,
		[]Token{Data(fullNodePrefix), Op(ts.OP_ROT), Op(ts.OP_ROT)}, // T new old
		fullLeafAcc(), []Token{Op(ts.OP_ROT)}, fullLeafAcc(), // T oh os nh ns
		fullLevels(sparse, depth, 0),
		ccvCheckOld(sparse),
		ccvFinal(depth),
	)
}

// CCVSplitScript is SPLIT (spec 7.5.2) under the CCV tier: the
// owner-authorised carve. Witness = [claim path] [source path] src_leaf
// new_leaf owner_sig, with no root and no m. The two steps, the seq
// increment and the drained-source rule are the FULL tier's carve body;
// only the altstack bookkeeping for r and m is gone, the first step's old
// root is bound by ccvCheckOld and output 0 by ccvFinal
// (tools/layertree_ccv.py split_script_ccv). CLAIM and CLAIM^h share the
// body with the voucher check over tree_id (CCVClaimScript, spec 7.5).
func CCVSplitScript(depth int, sparse bool) []Token {
	s := []Token{
		Num(2), Op(ts.OP_PICK), Num(fullOffOwnerKey), Num(32),
		Op(OP_SUBSTR),            // src claim sig owner_key
		Op(ts.OP_CHECKSIGVERIFY), // src claim
	}
	return append(s, ccvCarveBody(depth, sparse)...)
}

// CCVClaimScript is CLAIM (spec 7.5), or CLAIM^h (7.5.1) with hashlock,
// under the CCV tier (0xC2): the FULL tier's voucher check over the tree's
// tree_id (fullVoucherAuth) on SPLIT's body. The CCV witness carries no r
// and no m, which is what lets the check be shared token for token
// (tools/layertree_ccv.py claim_script_ccv).
func CCVClaimScript(depth int, treeID [32]byte, sparse, hashlock bool) []Token {
	var s []Token
	if hashlock {
		s = append(s, Op(ts.OP_SIZE), Num(32), Op(ts.OP_EQUALVERIFY),
			Op(ts.OP_SHA256), Op(ts.OP_TOALTSTACK)) // src claim vsig | phash
	}
	s = append(s, fullVoucherAuth(treeID, hashlock)...) // src claim
	return append(s, ccvCarveBody(depth, sparse)...)
}

// CCV0ClaimScript is CLAIM or CLAIM^h under the CCV tier's 0xC0 numerics:
// MID's carve witness minus r and m, with the MID tier's voucher check over
// tree_id (midVoucherAuth) (tools/layertree_ccv.py _claim_script_ccv0).
func CCV0ClaimScript(depth int, treeID [32]byte, sparse, hashlock bool) []Token {
	var s []Token
	if hashlock {
		s = append(s, Op(ts.OP_SIZE), Num(32), Op(ts.OP_EQUALVERIFY),
			Op(ts.OP_SHA256), Op(ts.OP_TOALTSTACK))
	}
	s = append(s, midVoucherAuth(treeID, hashlock)...)
	return append(s, ccv0CarveBody(depth, sparse)...)
}

// ccvCarveBody is [src claim] -> [1] after the authorisation: the FULL
// carve body's two steps bound by CHECK_INPUT and ccvFinal
// (tools/layertree_ccv.py _carve_body_ccv).
func ccvCarveBody(depth int, sparse bool) []Token {
	s := fullCat(
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
			Op(OP_CAT),                           // src claim new_src
			Op(ts.OP_SWAP), Op(ts.OP_TOALTSTACK), // src new_src | claim
		},
	)
	if sparse {
		s = fullCat(s, []Token{Op(ts.OP_OVER)}, fullLeafPos(),
			[]Token{Op(ts.OP_NIP)}, fullSparseSetup()) // | claim pos E_0
	}
	s = fullCat(s,
		[]Token{
			Data(fullNodePrefix), Op(ts.OP_ROT), Op(ts.OP_ROT), // T src new_src
			Op(ts.OP_SWAP),
		},
		fullLeafAcc(), // T new_src oh os
		[]Token{Op(ts.OP_ROT)},
		fullLeafAcc(),   // T oh os nh ns
		fullDrainRule(), // a drained source becomes E_0, else ns >= DUST_MIN
		fullLevels(sparse, depth, 0),
		ccvCheckOld(sparse), // T nh1 ns1 | claim
		[]Token{
			Op(ts.OP_FROMALTSTACK),                         // T nh1 ns1 claim
			Num(2), Op(ts.OP_ROLL), Num(2), Op(ts.OP_ROLL), // T claim nh1 ns1
			Op(ts.OP_SWAP), Op(ts.OP_TOALTSTACK), Op(ts.OP_TOALTSTACK), // T claim | nh1 ns1
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
		fullCheckPrevRootFromAlt(sparse), // T nh2 ns2
		ccvFinal(depth),
	)
}

// CCVEvictSubtreeScript is EVICT_SUBTREE_h (dense profile) under the CCV
// tier: the FULL tier's fixed post-order program with CCV payouts. The
// running output index lives on the altstack; each payout is a DEDUCT
// call on the leaf's exit key at that index, then the OP_TX exact amount
// read using a parked copy of the index.
func CCVEvictSubtreeScript(depth, height int, operatorKey [32]byte) []Token {
	s := []Token{Data(operatorKey[:]), Op(ts.OP_CHECKSIGVERIFY)}
	s = append(s,
		Op(ts.OP_1), Op(ts.OP_TOALTSTACK), Data(fullNodePrefix), // T | 1
	)
	d := []int{0}

	leafStep := func() []Token {
		step := []Token{
			Op(ts.OP_SIZE), Op(ts.OP_0NOTEQUAL),
			Op(ts.OP_IF),
			Op(ts.OP_SIZE), Num(fullLeafLen), Op(ts.OP_EQUALVERIFY),
			Op(ts.OP_DUP), Num(fullOffEvictorKey), Num(32), Op(OP_SUBSTR),
			Data(operatorKey[:]), Op(ts.OP_EQUALVERIFY),
			Op(ts.OP_DUP), Num(fullOffEvictAfter), Num(fullLenEvictAfter), Op(OP_SUBSTR),
			Op(ts.OP_CHECKLOCKTIMEVERIFY), Op(ts.OP_DROP),
			// idx -> idx+1 on the altstack, keep a copy for the OP_TX read.
			Op(ts.OP_FROMALTSTACK), Op(ts.OP_DUP), Op(ts.OP_1ADD), Op(ts.OP_TOALTSTACK), // leaf idx
			Op(ts.OP_DUP), Op(ts.OP_TOALTSTACK), // leaf idx | copy
			// CCV: data empty, index idx, pk leaf.exit_key, taptree empty,
			// mode DEDUCT, mirroring the Python leaf_step token for token.
			Data(ccvEmpty), Op(ts.OP_SWAP), // leaf "" idx
			Num(2), Op(ts.OP_PICK), Num(fullOffExitKey), Num(32), Op(OP_SUBSTR), // leaf "" idx ek
			Data(ccvEmpty), Num(ccvModeDeductOut), Op(OP_CHECKCONTRACTVERIFY), // leaf
			Op(ts.OP_FROMALTSTACK), Num(SelOutSingle), Op(OP_TX), Op(ts.OP_DROP), // leaf amt
			Op(ts.OP_OVER), Num(8), Op(OP_LEFT), Op(ts.OP_NUMEQUALVERIFY),
		}
		// leaf_acc: [leaf] -> [H_leaf(leaf), leaf.amount], as in the FULL
		// tier's _leaf_step, then the empty-position ELSE branch.
		return fullCat(step,
			fullLeafAcc(),
			[]Token{
				Op(ts.OP_ELSE),
				Op(ts.OP_DROP), Data(fullEmptyLeafHash), Op(ts.OP_0),
				Op(ts.OP_ENDIF),
			},
		)
	}
	_ = leafStep

	var gen func(h int)
	gen = func(h int) {
		if h == 0 {
			s = append(s, Num(int64(d[0]+1)), Op(ts.OP_ROLL))
			s = append(s, leafStep()...)
			d[0] += 2
		} else {
			gen(h - 1)
			gen(h - 1)
			s = append(s, fullHashStep(d[0])...)
			d[0] -= 2
		}
	}
	gen(height)
	eH := tree.EmptyNode(height).Hash
	s = append(s,
		Op(ts.OP_FROMALTSTACK), Op(ts.OP_DROP),
		Data(eH[:]), Op(ts.OP_0),
	)
	s = fullCat(s, fullLevels(false, depth, height), ccvCheckOld(false), ccvFinal(depth))
	return s
}

// ------------------------------------------------------ 0xC0 numerics --

// ccv0CheckOld is the MID tier's CHECK_OLD with the parked-root comparison
// replaced by CHECK_INPUT on the folded old root
// (tools/layertree_ccv.py _check_old_ccv0).
func ccv0CheckOld(sparse bool) []Token {
	s := midCheckOld(sparse)
	s = append([]Token{}, s[:len(s)-2]...)
	return append(s, ccvCheckInput()...)
}

// ccv0Final is the MID tier's FINAL with output 0's scriptPubKey check
// replaced by the CCV assign call and the amount compared as bytes
// (tools/layertree_ccv.py _final_ccv0). Entry [zf wf T nh ns].
func ccv0Final(depth int) []Token {
	s := []Token{
		Op(ts.OP_ROT), Op(ts.OP_DROP),
		Op(ts.OP_OVER), Data(midEmptyNodeHash(depth)), Op(ts.OP_EQUAL),
		Op(ts.OP_IF), Op(ts.OP_2DROP), Op(ts.OP_2DROP), Op(ts.OP_1),
		Op(ts.OP_ELSE),
	}
	s = append(s, midRoll(3, 2)...)
	s = append(s, midLe64()...) // nh le64(ns)
	return append(s,
		Op(ts.OP_TOALTSTACK), // nh | le64(ns)
		Op(ts.OP_0), Data(ccvEmpty), Data(ccvMinus1), Num(ccvModeAssignOut),
		Op(OP_CHECKCONTRACTVERIFY),
		Op(ts.OP_FROMALTSTACK),
		Op(ts.OP_0), Num(SelOutSingle), Op(OP_TX), Op(ts.OP_DROP),
		Op(ts.OP_EQUALVERIFY),
		Op(ts.OP_1), Op(ts.OP_ENDIF),
	)
}

// ccv0PayEvict is the EVICT_SUBTREE payout under 0xC0, in place of
// midEvictPay: [leaf(10) idx] | .. idx' -> [leaf(10)], a CHECK_OUTPUT
// DEDUCT call on the exit-key element at the dynamic index, then the
// exact amount compare (tools/layertree_ccv.py _pay_evict_ccv0).
func ccv0PayEvict() []Token {
	return []Token{
		Op(ts.OP_DUP), Op(ts.OP_TOALTSTACK), // leaf(10) idx | .. idx' idx
		Data(ccvEmpty), Op(ts.OP_SWAP), // leaf(10) "" idx
		Num(10), Op(ts.OP_PICK), // leaf(10) "" idx ek
		Data(ccvEmpty), Num(ccvModeDeductOut), Op(OP_CHECKCONTRACTVERIFY),
		Op(ts.OP_FROMALTSTACK), Num(SelOutSingle), Op(OP_TX), Op(ts.OP_DROP),
		Num(10), Op(ts.OP_PICK), Op(ts.OP_EQUALVERIFY),
	}
}

// CCV0EvictSubtreeScript is EVICT_SUBTREE_h (dense) under the CCV tier's
// 0xC0 numerics: the MID tier's element-based sweep with a CCV DEDUCT
// payout, CHECK_INPUT for the old root and the assign-mode output check
// (tools/layertree_ccv.py _evict_subtree_script_ccv0).
func CCV0EvictSubtreeScript(depth, height int, operatorKey [32]byte) []Token {
	s := []Token{Data(operatorKey[:]), Op(ts.OP_CHECKSIGVERIFY)}
	s = append(s, midEvictBody(height, operatorKey, ccv0PayEvict())...)
	s = append(s, midLevels(false, depth, height)...)
	s = append(s, ccv0CheckOld(false)...)
	return append(s, ccv0Final(depth)...)
}

// ccv0CarveBody is MID's two carve steps bound by CCV:
// [src(10) claim(10) extras(7)] -> [1]. Shared by SPLIT, CLAIM and
// CLAIM^h under 0xC0 (tools/layertree_ccv.py _carve_body_ccv0).
func ccv0CarveBody(depth int, sparse bool) []Token {
	s := midCarveSourceAlt(depth, sparse, false)
	s = append(s, ccv0CheckOld(sparse)...)
	s = append(s, Op(ts.OP_FROMALTSTACK), Op(ts.OP_FROMALTSTACK))
	s = append(s, midCarveClaim(depth, sparse)...)
	return append(s, ccv0Final(depth)...)
}

// CCV0SplitScript is SPLIT (spec 7.5.2) under the CCV tier's 0xC0
// numerics: MID's carve witness minus r and m, authorised by src.ok's
// transaction signature (tools/layertree_ccv.py _split_script_ccv0).
func CCV0SplitScript(depth int, sparse bool) []Token {
	s := []Token{Num(midCarveOwnerDepth), Op(ts.OP_PICK), Op(ts.OP_CHECKSIGVERIFY)}
	return append(s, ccv0CarveBody(depth, sparse)...)
}

// CCVAllScripts returns the CCV-tier script set for a tree: exit_ks
// sequential exits, the join heights (dense) or JOIN_0 (sparse), the
// JOINK batch sizes, UPDATE and the EVICT_SUBTREE heights. CLAIM and
// CLAIM^h take the tree's tree_id (CCVClaimScript, spec 6.2) and, like
// SPLIT and UPDATE^x, are added at tree creation.
func CCVAllScripts(depth int, operatorKey [32]byte, sparse bool,
	joinHeights []int, exitKs []int, joinKs []int, evictHeights []int) map[string][]Token {

	out := make(map[string][]Token)
	for _, k := range exitKs {
		out[itoa("EXIT_", k)] = CCVExitScript(depth, k, sparse)
	}
	heights := joinHeights
	if sparse {
		heights = []int{0}
	}
	for _, h := range heights {
		out[itoa("JOIN_", h)] = CCVJoinScript(depth, h, operatorKey, sparse, 1)
	}
	for _, k := range joinKs {
		out[itoa("JOINK_", k)] = CCVJoinScript(depth, 0, operatorKey, sparse, k)
	}
	out["UPDATE"] = CCVUpdateScript(depth, operatorKey, sparse)
	if !sparse {
		for _, h := range evictHeights {
			if h <= depth {
				out[itoa("EVICT_SUBTREE_", h)] = CCVEvictSubtreeScript(depth, h, operatorKey)
			}
		}
	}
	return out
}

// itoa builds a script name like "EXIT_2" from a prefix and a number.
func itoa(prefix string, n int) string {
	digits := ""
	if n == 0 {
		digits = "0"
	}
	for n > 0 {
		digits = string(rune('0'+n%10)) + digits
		n /= 10
	}
	return prefix + digits
}
