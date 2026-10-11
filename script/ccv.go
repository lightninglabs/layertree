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
func ccvExitBlock(sparse bool, depth, outIndex int, tower bool,
	treeID [32]byte) []Token {

	// The authorisation is FULL's (fullExitAuth); with tower set it is
	// the EXIT_K^t one of spec 7.2 rule 7 over treeID, the tier's second
	// OP_CHECKSIGFROMSTACK user after CLAIM.
	s := fullExitAuth(tower, treeID) // leaf
	s = append(s, Op(ts.OP_SIZE), Num(fullLeafLen), Op(ts.OP_EQUALVERIFY))
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
	return ccvExitScript(depth, k, sparse, false, [32]byte{})
}

// CCVExitTowerScript is EXIT_K^t under the CCV tier (spec 7.2 rule 7):
// EXIT_K whose owner branch takes the off-chain authorisation over
// treeID, a constant of the script, in place of a transaction signature.
// A tree-creation parameter that replaces EXIT_K (tools/layertree_ccv.py
// exit_script_ccv tower=True).
func CCVExitTowerScript(depth, k int, treeID [32]byte, sparse bool) []Token {
	return ccvExitScript(depth, k, sparse, true, treeID)
}

func ccvExitScript(depth, k int, sparse, tower bool, treeID [32]byte) []Token {
	s := fullCat(ccvExitBlock(sparse, depth, 1, tower, treeID), ccvCheckOld(sparse))
	for i := 2; i <= k; i++ {
		s = fullCat(s,
			[]Token{Op(ts.OP_SWAP), Op(ts.OP_TOALTSTACK), Op(ts.OP_TOALTSTACK), Op(ts.OP_DROP)},
			ccvExitBlock(sparse, depth, i, tower, treeID),
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
// dustMin is the tree's DUST_MIN (6.2, 7.5 rule 6), zero meaning
// tree.DustMin; every CCV carve generator takes it the same way.
func CCVSplitScript(depth int, sparse bool, dustMin uint64) []Token {
	s := []Token{
		Num(2), Op(ts.OP_PICK), Num(fullOffOwnerKey), Num(32),
		Op(OP_SUBSTR),            // src claim sig owner_key
		Op(ts.OP_CHECKSIGVERIFY), // src claim
	}
	return append(s, ccvCarveBody(depth, sparse, dustMin)...)
}

// CCVClaimScript is CLAIM (spec 7.5), or CLAIM^h (7.5.1) with hashlock,
// under the CCV tier (0xC2): the FULL tier's voucher check over the tree's
// tree_id (fullVoucherAuth) on SPLIT's body. The CCV witness carries no r
// and no m, which is what lets the check be shared token for token
// (tools/layertree_ccv.py claim_script_ccv).
func CCVClaimScript(depth int, treeID [32]byte, sparse, hashlock bool,
	dustMin uint64) []Token {

	var s []Token
	if hashlock {
		s = append(s, Op(ts.OP_SIZE), Num(32), Op(ts.OP_EQUALVERIFY),
			Op(ts.OP_SHA256), Op(ts.OP_TOALTSTACK)) // src claim vsig | phash
	}
	s = append(s, fullVoucherAuth(treeID, hashlock)...) // src claim
	return append(s, ccvCarveBody(depth, sparse, dustMin)...)
}

// CCV0ClaimScript is CLAIM or CLAIM^h under the CCV tier's 0xC0 numerics:
// MID's carve witness minus r and m, with the MID tier's voucher check over
// tree_id (midVoucherAuth) (tools/layertree_ccv.py _claim_script_ccv0).
func CCV0ClaimScript(depth int, treeID [32]byte, sparse, hashlock bool,
	dustMin uint64) []Token {

	var s []Token
	if hashlock {
		s = append(s, Op(ts.OP_SIZE), Num(32), Op(ts.OP_EQUALVERIFY),
			Op(ts.OP_SHA256), Op(ts.OP_TOALTSTACK))
	}
	s = append(s, midVoucherAuth(treeID, hashlock)...)
	return append(s, ccv0CarveBody(depth, sparse, dustMin)...)
}

// ccvCarveBody is [src claim] -> [1] after the authorisation: the FULL
// carve body's two steps bound by CHECK_INPUT and ccvFinal
// (tools/layertree_ccv.py _carve_body_ccv).
func ccvCarveBody(depth int, sparse bool, dustMin uint64) []Token {
	s := fullCat(
		fullCarveLeafRules(dustMin),
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
		fullLeafAcc(),          // T oh os nh ns
		fullDrainRule(dustMin), // a drained source becomes E_0, else ns >= DUST_MIN
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
func ccv0CarveBody(depth int, sparse bool, dustMin uint64) []Token {
	s := midCarveSourceAlt(depth, sparse, false, dustMin)
	s = append(s, ccv0CheckOld(sparse)...)
	s = append(s, Op(ts.OP_FROMALTSTACK), Op(ts.OP_FROMALTSTACK))
	s = append(s, midCarveClaim(depth, sparse)...)
	return append(s, ccv0Final(depth)...)
}

// CCV0SplitScript is SPLIT (spec 7.5.2) under the CCV tier's 0xC0
// numerics: MID's carve witness minus r and m, authorised by src.ok's
// transaction signature (tools/layertree_ccv.py _split_script_ccv0).
func CCV0SplitScript(depth int, sparse bool, dustMin uint64) []Token {
	s := []Token{Num(midCarveOwnerDepth), Op(ts.OP_PICK), Op(ts.OP_CHECKSIGVERIFY)}
	return append(s, ccv0CarveBody(depth, sparse, dustMin)...)
}

// ------------------------------------------------- 0xC0 reference set --
// The CCV tier's 0xC0 EXIT_K, JOIN_h / JOINK_K and UPDATE / UPDATE^x are
// the MID tier's scripts with the two key bindings replaced by CCV calls
// and the payout check by a DEDUCT call, ports of tools/layertree_ccv.py's
// _exit_script_ccv0, _join_script_ccv0 and _update_script_ccv0. They are
// what a 0xC0 CCV tree's taptree is built from, and so what the m_h of its
// DETACH_h commits to.

// ccv0Pay is the exit-block payout under 0xC0: a CHECK_OUTPUT|DEDUCT call
// on the leaf's exit-key element (ten deep under the OP_TX pair) plus the
// exact amount compare, in place of MID's scriptPubKey check
// (tools/layertree_ccv.py _pay_ccv0).
func ccv0Pay(outIndex int) []Token {
	return []Token{
		Num(int64(outIndex)), Num(SelOutSingle), Op(OP_TX), Op(ts.OP_DROP), // leaf10 amt1
		Op(ts.OP_TOALTSTACK),                 // leaf10 | amt1
		Data(ccvEmpty), Num(int64(outIndex)), // data index
		Num(10), Op(ts.OP_PICK), // ek element (pk slot)
		Data(ccvEmpty), Num(ccvModeDeductOut), Op(OP_CHECKCONTRACTVERIFY),
		Op(ts.OP_FROMALTSTACK),                         // leaf10 amt1
		Num(10), Op(ts.OP_PICK), Op(ts.OP_EQUALVERIFY), // amt1 == leaf amt8
		Op(ts.OP_FROMALTSTACK), Op(ts.OP_DROP), // leaf10 (is_evict gone)
	}
}

// ccv0ExitBlock is MID's exit block with the payout check replaced by
// ccv0Pay (tools/layertree_ccv.py _exit_block_ccv0).
func ccv0ExitBlock(sparse bool, depth, outIndex int, tower bool,
	treeID [32]byte) []Token {

	// MID's authorisation (midExitAuth); with tower set it is the
	// EXIT_K^t one of spec 7.2 rule 7 over treeID.
	s := midExitAuth(tower, treeID)
	s = append(s, ccv0Pay(outIndex)...)
	s = append(s, midLeafJoin()...)
	s = append(s, midTagged(midLeafPrefix)...)
	s = append(s, Op(ts.OP_FROMALTSTACK))
	if sparse {
		s = append(s, midRoll(5, 4)...)
		s = append(s, midSparseSetup()...)
	}
	s = append(s, Data(midNodePrefix), Op(ts.OP_ROT), Op(ts.OP_ROT),
		Data(midEmptyLeafHash), Op(ts.OP_0))
	return append(s, midLevels(sparse, depth, 0)...)
}

// CCV0ExitScript is EXIT_K under the CCV tier's 0xC0 numerics: MID's
// chained blocks bound by CHECK_INPUT and the assign-mode output check.
// Witness: MID's minus r and m.
func CCV0ExitScript(depth, k int, sparse bool) []Token {
	return ccv0ExitScript(depth, k, sparse, false, [32]byte{})
}

// CCV0ExitTowerScript is EXIT_K^t under the CCV tier's 0xC0 numerics
// (spec 7.2 rule 7), with MID's authorisation over treeID
// (tools/layertree_ccv.py _exit_script_ccv0 tower=True).
func CCV0ExitTowerScript(depth, k int, treeID [32]byte, sparse bool) []Token {
	return ccv0ExitScript(depth, k, sparse, true, treeID)
}

func ccv0ExitScript(depth, k int, sparse, tower bool, treeID [32]byte) []Token {
	s := ccv0ExitBlock(sparse, depth, 1, tower, treeID)
	s = append(s, ccv0CheckOld(sparse)...)
	for i := 2; i <= k; i++ {
		s = append(s, Op(ts.OP_SWAP), Op(ts.OP_TOALTSTACK), Op(ts.OP_TOALTSTACK),
			Op(ts.OP_DROP))
		s = append(s, ccv0ExitBlock(sparse, depth, i, tower, treeID)...)
		s = append(s, midCheckPrev(sparse)...)
	}
	return append(s, ccv0Final(depth)...)
}

// CCV0JoinScript is JOIN_h / JOINK_K under the CCV tier's 0xC0 numerics.
func CCV0JoinScript(depth, height int, operatorKey [32]byte, sparse bool,
	k int) []Token {

	s := []Token{Data(operatorKey[:]), Op(ts.OP_CHECKSIGVERIFY)}
	s = append(s, midJoinBlock(sparse, depth, height)...)
	s = append(s, ccv0CheckOld(sparse)...)
	for i := 2; i <= k; i++ {
		s = append(s, Op(ts.OP_SWAP), Op(ts.OP_TOALTSTACK), Op(ts.OP_TOALTSTACK),
			Op(ts.OP_DROP))
		s = append(s, midJoinBlock(sparse, depth, height)...)
		s = append(s, midCheckPrev(sparse)...)
	}
	return append(s, ccv0Final(depth)...)
}

// CCV0UpdateScript is UPDATE under the CCV tier's 0xC0 numerics, and
// CCV0UpdateXScript its exit-consent form (spec 7.4 rule 5).
func CCV0UpdateScript(depth int, operatorKey [32]byte, sparse bool) []Token {
	return ccv0UpdateScript(depth, operatorKey, sparse, false)
}

// CCV0UpdateXScript is UPDATE^x under the CCV tier's 0xC0 numerics.
func CCV0UpdateXScript(depth int, operatorKey [32]byte, sparse bool) []Token {
	return ccv0UpdateScript(depth, operatorKey, sparse, true)
}

func ccv0UpdateScript(depth int, operatorKey [32]byte, sparse,
	exitConsent bool) []Token {

	var s []Token
	if exitConsent {
		s = append(s, Num(21), Op(ts.OP_PICK), Op(ts.OP_CHECKSIGVERIFY))
	}
	s = append(s, Data(operatorKey[:]), Op(ts.OP_CHECKSIGVERIFY),
		Num(18), Op(ts.OP_PICK), Op(ts.OP_CHECKSIGVERIFY))
	if sparse {
		s = append(s,
			Num(8), Op(ts.OP_PICK), Num(19), Op(ts.OP_PICK), Op(ts.OP_EQUALVERIFY),
			Num(5), Op(ts.OP_PICK), Num(16), Op(ts.OP_PICK), Op(ts.OP_EQUALVERIFY))
	}
	s = append(s, midLeafJoin()...)
	s = append(s, Op(ts.OP_TOALTSTACK))
	s = append(s, midLeafJoin()...)
	s = append(s, midTagged(midLeafPrefix)...)
	s = append(s, Op(ts.OP_FROMALTSTACK), Op(ts.OP_FROMALTSTACK),
		Op(ts.OP_FROMALTSTACK), Op(ts.OP_SWAP))
	s = append(s, midTagged(midLeafPrefix)...)
	s = append(s, Op(ts.OP_SWAP))
	if sparse {
		s = append(s, midRoll(7, 4)...)
		s = append(s, midSparseSetup()...)
	}
	s = append(s, Data(midNodePrefix))
	s = append(s, midRoll(4, 4)...)
	s = append(s, midLevels(sparse, depth, 0)...)
	s = append(s, ccv0CheckOld(sparse)...)
	return append(s, ccv0Final(depth)...)
}

// ------------------------------------------------------ DETACH_h (7.10) --

// CCVDetachScript is DETACH_h (spec 7.10) under the CCV tier (0xC2): the
// FULL tier's detach with the second output check as a CCV call. Output 1
// is checked by CHECK_OUTPUT in the DEDUCT mode with data R_h, the NUMS
// key and the taptree mH, so it is the CCV tree output of a depth-h tree
// at root R_h under the detached option set, and its amount is deducted
// from the residual output 0 then receives; the exact equality with sum_h
// is one OP_TX read. mH is the parent's option set compiled at depth h
// (7.10 rule 3, CCVDetachedTaptreeRoot).
//
// witness (bottom..top) = [dir sc]*(D-h) R_h sum_h8 sig.
func CCVDetachScript(depth, height int, operatorKey [32]byte,
	mH [32]byte) []Token {

	eH := tree.EmptyNode(height).Hash
	s := []Token{
		Data(operatorKey[:]), Op(ts.OP_CHECKSIGVERIFY), // R_h sum8
		Op(ts.OP_SIZE), Num(8), Op(ts.OP_EQUALVERIFY),
		Op(ts.OP_OVER), Op(ts.OP_SIZE), Num(32), Op(ts.OP_EQUALVERIFY),
		Op(ts.OP_DROP), // R_h sum8
		// output 1: CHECK_OUTPUT|DEDUCT, data R_h, index 1, pk empty, taptree m_h
		Op(ts.OP_OVER), Num(1), Data(ccvEmpty), Data(mH[:]), Num(ccvModeDeductOut),
		Op(OP_CHECKCONTRACTVERIFY),                           // R_h sum8
		Num(1), Num(SelOutSingle), Op(OP_TX), Op(ts.OP_DROP), // R_h sum8 amt1
		Op(ts.OP_OVER), Op(ts.OP_NUMEQUALVERIFY), // R_h sum8 (output 1 pays sum_h exactly)
		Data(fullNodePrefix), Op(ts.OP_ROT), Op(ts.OP_ROT), // T R_h sum8
		Data(eH[:]), Op(ts.OP_0), // T R_h sum8 E_h 0
	}
	return fullCat(s, fullLevels(false, depth, height), ccvCheckOld(false), ccvFinal(depth))
}

// CCV0DetachScript is DETACH_h under the CCV tier's 0xC0 numerics: the
// subtree sum arrives as a minimal number with its PADZ pad, NONNEG keeps
// it non-negative before it enters the fold, and le64 of it is compared
// with output 1's amount as bytes (tools/layertree_ccv.py
// _detach_script_ccv0).
//
// witness (bottom..top) = zf wf zi wi [levels h..D-1] R_h sum_num zs ws sig.
func CCV0DetachScript(depth, height int, operatorKey [32]byte,
	mH [32]byte) []Token {

	s := []Token{
		Data(operatorKey[:]), Op(ts.OP_CHECKSIGVERIFY), // R_h sum zs ws
		Num(2), Op(ts.OP_PICK),
	}
	s = append(s, midNonneg()...)
	s = append(s, Op(ts.OP_TOALTSTACK)) // R_h sum zs ws | sum
	s = append(s, midLe64()...)         // R_h le64(sum)
	s = append(s,
		Op(ts.OP_OVER), Op(ts.OP_SIZE), Num(32), Op(ts.OP_EQUALVERIFY), Op(ts.OP_DROP),
		Op(ts.OP_OVER), Num(1), Data(ccvEmpty), Data(mH[:]), Num(ccvModeDeductOut),
		Op(OP_CHECKCONTRACTVERIFY),                                                  // R_h le64
		Num(1), Num(SelOutSingle), Op(OP_TX), Op(ts.OP_DROP), Op(ts.OP_EQUALVERIFY), // R_h
		Op(ts.OP_FROMALTSTACK), // R_h sum
		Data(midNodePrefix), Op(ts.OP_ROT), Op(ts.OP_ROT),
		Data(midEmptyNodeHash(height)), Op(ts.OP_0), // T R_h sum E_h 0
	)
	s = append(s, midLevels(false, depth, height)...)
	s = append(s, ccv0CheckOld(false)...)
	return append(s, ccv0Final(depth)...)
}

// CCVTreeOptions are a CCV tree's creation parameters other than its depth
// (spec 6.2, 4.6): the numerics (C0 for the MID encoding), the profile,
// the operator key, tree_id, DUST_MIN, the JOIN heights, EXIT_K sizes, JOINK
// sizes and sweep heights, and the variants a CCV taptree may carry: the
// tower-delegable exit EXIT_K^t (7.2 rule 7) in place of EXIT_K, UPDATE^x
// in place of UPDATE, CLAIM and CLAIM^h, SPLIT and DETACH_h. Scripts
// compiles the set for one depth, which is what the parent's taptree is
// built from and what a DETACH_h child MUST be built from at depth h
// (7.10 rule 3; tools/layertree_ccv.py CCVTreeOptions).
type CCVTreeOptions struct {
	OperatorKey  [32]byte
	TreeID       [32]byte
	C0           bool
	Sparse       bool
	JoinHeights  []int
	ExitKs       []int
	JoinKs       []int
	EvictHeights []int

	Tower         bool
	UpdateX       bool
	Claim         bool
	ClaimH        bool
	Split         bool
	DetachHeights []int

	// DustMin is the tree's DUST_MIN (spec 6.2), carried as a constant by
	// the carve scripts (7.5 rule 6). Zero means tree.DustMin.
	DustMin uint64
}

// DustFloor is the DUST_MIN the tree's carve scripts enforce: DustMin, or
// tree.DustMin when it is zero.
func (o CCVTreeOptions) DustFloor() uint64 {
	return dustFloor(o.DustMin)
}

// CCVReferenceOptions are the set CCVAllScripts builds by default: EXIT_1,
// JOIN_0, JOINK_2, UPDATE and the sweeps at heights 1 and 2.
func CCVReferenceOptions(operatorKey [32]byte, c0 bool) CCVTreeOptions {
	return CCVTreeOptions{
		OperatorKey: operatorKey, C0: c0,
		JoinHeights: []int{0}, ExitKs: []int{1}, JoinKs: []int{2},
		EvictHeights: []int{1, 2},
	}
}

// Scripts compiles the option set for a tree of the given depth, in the
// order tools/layertree_ccv.py CCVTreeOptions.at_depth emits it: the
// reference members (EXIT_K, JOIN_h, JOINK_K, UPDATE or UPDATE_X in its
// place, EVICT_SUBTREE_h), then CLAIM, CLAIM_H, SPLIT and DETACH_h.
// Heights that do not fit the depth are dropped.
func (o CCVTreeOptions) Scripts(depth int) []FullNamedScript {
	var out []FullNamedScript
	add := func(name string, toks []Token) {
		out = append(out, FullNamedScript{Name: name, Tokens: toks})
	}
	for _, k := range o.ExitKs {
		if o.C0 {
			add(itoa("EXIT_", k), ccv0ExitScript(depth, k, o.Sparse, o.Tower, o.TreeID))
		} else {
			add(itoa("EXIT_", k), ccvExitScript(depth, k, o.Sparse, o.Tower, o.TreeID))
		}
	}
	heights := o.JoinHeights
	if o.Sparse {
		heights = []int{0}
	}
	for _, h := range heights {
		if h > depth {
			continue
		}
		if o.C0 {
			add(itoa("JOIN_", h), CCV0JoinScript(depth, h, o.OperatorKey, o.Sparse, 1))
		} else {
			add(itoa("JOIN_", h), CCVJoinScript(depth, h, o.OperatorKey, o.Sparse, 1))
		}
	}
	for _, k := range o.JoinKs {
		if o.C0 {
			add(itoa("JOINK_", k), CCV0JoinScript(depth, 0, o.OperatorKey, o.Sparse, k))
		} else {
			add(itoa("JOINK_", k), CCVJoinScript(depth, 0, o.OperatorKey, o.Sparse, k))
		}
	}
	switch {
	case o.UpdateX && o.C0:
		add("UPDATE_X", CCV0UpdateXScript(depth, o.OperatorKey, o.Sparse))
	case o.UpdateX:
		add("UPDATE_X", CCVUpdateXScript(depth, o.OperatorKey, o.Sparse))
	case o.C0:
		add("UPDATE", CCV0UpdateScript(depth, o.OperatorKey, o.Sparse))
	default:
		add("UPDATE", CCVUpdateScript(depth, o.OperatorKey, o.Sparse))
	}
	if !o.Sparse {
		for _, h := range o.EvictHeights {
			if h > depth {
				continue
			}
			if o.C0 {
				add(itoa("EVICT_SUBTREE_", h), CCV0EvictSubtreeScript(depth, h, o.OperatorKey))
			} else {
				add(itoa("EVICT_SUBTREE_", h), CCVEvictSubtreeScript(depth, h, o.OperatorKey))
			}
		}
	}
	for _, c := range []struct {
		name string
		hl   bool
		on   bool
	}{{"CLAIM", false, o.Claim}, {"CLAIM_H", true, o.ClaimH}} {
		if !c.on {
			continue
		}
		if o.C0 {
			add(c.name, CCV0ClaimScript(depth, o.TreeID, o.Sparse, c.hl, o.DustMin))
		} else {
			add(c.name, CCVClaimScript(depth, o.TreeID, o.Sparse, c.hl, o.DustMin))
		}
	}
	if o.Split {
		if o.C0 {
			add("SPLIT", CCV0SplitScript(depth, o.Sparse, o.DustMin))
		} else {
			add("SPLIT", CCVSplitScript(depth, o.Sparse, o.DustMin))
		}
	}
	if !o.Sparse {
		for _, h := range o.DetachHeights {
			if h >= depth {
				continue
			}
			mH := o.TapTreeRoot(h)
			if o.C0 {
				add(itoa("DETACH_", h), CCV0DetachScript(depth, h, o.OperatorKey, mH))
			} else {
				add(itoa("DETACH_", h), CCVDetachScript(depth, h, o.OperatorKey, mH))
			}
		}
	}
	return out
}

// TapTreeRoot is the tree identifier m of a CCV tree of the given depth
// created with these options (spec 6.2); for a DETACH_h child it is m_h.
func (o CCVTreeOptions) TapTreeRoot(depth int) [32]byte {
	scripts := o.Scripts(depth)
	mode, version := ModeC2, byte(0xc2)
	if o.C0 {
		mode, version = ModeC0, 0xc0
	}
	leaves := make([][32]byte, 0, len(scripts))
	for _, s := range scripts {
		leaves = append(leaves, TapLeafHash(MustAssemble(s.Tokens, mode), version))
	}
	return TapTreeRoot(leaves)
}

// CCVDetachedTaptreeRoot is m_h for DETACH_h under CCV (spec 7.10 rule 3):
// the parent's option set compiled for depth h in the parent's numerics
// (tools/layertree_ccv.py detached_taptree_root_ccv).
func CCVDetachedTaptreeRoot(height int, opts CCVTreeOptions) [32]byte {
	return opts.TapTreeRoot(height)
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
