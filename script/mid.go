package script

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/txscript"
	"github.com/roasbeef/layertree/tree"
)

// This file is a direct port of tools/layertree_mid.py: the MID tier
// (spec 4.6), i.e. BIP-342 tapscript with leaf-version 0xC0 semantics plus
// OP_CAT, OP_TX, OP_CHECKSIGFROMSTACK and OP_TWEAKADD. Scripts are
// assembled with ModeC0 (CScriptNum minimal number encoding).
//
// Everything here mirrors the Python token for token, including its
// oddities, so that the assembled bytes match spec/golden.json exactly.

// MidMaxSum is the largest sum a MID tree may carry: the PADZ gadget only
// handles script numbers below 2^31.
const MidMaxSum = uint64(1)<<31 - 1

// midTagPrefix is sha256(tag) || sha256(tag), the BIP-340 tagged-hash
// prefix that the scripts carry as a literal.
func midTagPrefix(tag string) []byte {
	h := sha256.Sum256([]byte(tag))
	out := make([]byte, 0, 2*sha256.Size)
	out = append(out, h[:]...)
	return append(out, h[:]...)
}

// Script constants shared by the 0xC0 tiers.
var (
	midLeafPrefix     = midTagPrefix(tree.TagLeaf)
	midNodePrefix     = midTagPrefix(tree.TagNode)
	midStatePrefix    = midTagPrefix(tree.TagState)
	midVoucherPrefix  = midTagPrefix(tree.TagVoucher)
	midVoucherHPrefix = midTagPrefix(tree.TagVoucherH)
	midPosPrefix      = midTagPrefix(tree.TagPos)
	midTaptweakPrefix = midTagPrefix("TapTweak")

	// midP2TRPrefix is the OP_1 <32> push prefix of a P2TR scriptPubKey.
	midP2TRPrefix = []byte{0x51, 0x20}

	// midNumsX is the x-only BIP-341 NUMS point H.
	midNumsX = schnorr.SerializePubKey(tree.NUMS)

	// midZero4 is four zero bytes, the PADZ target.
	midZero4 = make([]byte, 4)

	// midEnc64Suffix turns le32(x) into enc64(x) = le64(x) || 0x01.
	midEnc64Suffix = []byte{0, 0, 0, 0, 1}

	// midEnc0 is enc64(0), the encoding of a zero sum.
	midEnc0 = tree.Enc64(0)

	// midEmptyLeafHash is E_0's hash, 32 zero bytes.
	midEmptyLeafHash = make([]byte, 32)
)

// midEmptyNodeHash is the hash of E_h.
func midEmptyNodeHash(height int) []byte {
	n := tree.EmptyNode(height)
	h := n.Hash
	return h[:]
}

// midTagged hashes the top stack element under the given tag prefix.
func midTagged(prefix []byte) []Token {
	return []Token{
		Data(prefix), Op(txscript.OP_SWAP), Op(txscript.OP_CAT),
		Op(txscript.OP_SHA256),
	}
}

// midRoll repeats [n OP_ROLL] `times` times.
func midRoll(n int64, times int) []Token {
	out := make([]Token, 0, 2*times)
	for i := 0; i < times; i++ {
		out = append(out, Num(n), Op(txscript.OP_ROLL))
	}
	return out
}

// midCat concatenates token slices.
func midCat(parts ...[]Token) []Token {
	var out []Token
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// midRepeat repeats a token sequence n times.
func midRepeat(toks []Token, n int) []Token {
	out := make([]Token, 0, len(toks)*n)
	for i := 0; i < n; i++ {
		out = append(out, toks...)
	}
	return out
}

// midPadz is the PADZ gadget: [x z w] -> [le32(x)].
func midPadz() []Token {
	return []Token{
		Op(txscript.OP_OVER), Op(txscript.OP_SWAP), Op(txscript.OP_CAT),
		Data(midZero4), Op(txscript.OP_EQUALVERIFY),
		Op(txscript.OP_SIZE), Op(txscript.OP_ROT), Op(txscript.OP_SIZE),
		Op(txscript.OP_ROT), Op(txscript.OP_ADD), Num(4),
		Op(txscript.OP_NUMEQUALVERIFY),
		Op(txscript.OP_SWAP), Op(txscript.OP_CAT),
	}
}

// midEnc64 is [x z w] -> [enc64(x)].
func midEnc64() []Token {
	return append(midPadz(), Data(midEnc64Suffix), Op(txscript.OP_CAT))
}

// midLe64 is [x z w] -> [le64(x)].
func midLe64() []Token {
	return append(midPadz(), Data(midZero4), Op(txscript.OP_CAT))
}

// midTreeSpkMin is F.tree_spk_min: [r m] -> [spk] using OP_TWEAKADD.
func midTreeSpkMin() []Token {
	return midCat(
		[]Token{Op(txscript.OP_SWAP)},
		midTagged(midStatePrefix),
		[]Token{
			Data(midNumsX), Op(OP_TWEAKADD),
			Op(txscript.OP_TUCK), Op(txscript.OP_SWAP),
			Op(txscript.OP_CAT),
		},
		midTagged(midTaptweakPrefix),
		[]Token{
			Op(txscript.OP_SWAP), Op(OP_TWEAKADD),
			Data(midP2TRPrefix), Op(txscript.OP_SWAP),
			Op(txscript.OP_CAT),
		},
	)
}

// midPrologue checks that the spent input is #0 and that (root, m) match
// its scriptPubKey, leaving them on the altstack.
func midPrologue() []Token {
	return midCat(
		[]Token{
			Num(SelCurrInput), Op(OP_TX), Op(txscript.OP_0),
			Op(txscript.OP_NUMEQUALVERIFY), Op(txscript.OP_2DUP),
		},
		midTreeSpkMin(),
		[]Token{
			Num(SelInSpk), Op(OP_TX), Op(txscript.OP_EQUALVERIFY),
			Op(txscript.OP_TOALTSTACK), Op(txscript.OP_TOALTSTACK),
		},
	)
}

// midLevelWitness is the number of witness elements a level consumes.
const midLevelWitness = 9

// midLevel folds one proof level: [9 witness] T oh os nh ns -> T oh' os' nh' ns'.
func midLevel(sparse bool) []Token {
	s := midRoll(13, midLevelWitness)
	if sparse {
		s = append(s, midRoll(3, 1)...)
		s = append(s, []Token{
			Op(txscript.OP_FROMALTSTACK),
			Op(txscript.OP_SWAP), Op(txscript.OP_SIZE),
			Op(txscript.OP_0NOTEQUAL),
			Op(txscript.OP_NOTIF), Op(txscript.OP_DROP),
			Op(txscript.OP_DUP), Op(txscript.OP_ENDIF),
			Op(txscript.OP_SWAP), Data(midEnc0), Op(txscript.OP_CAT),
			Op(txscript.OP_DUP), Op(txscript.OP_CAT),
			Data(midNodePrefix), Op(txscript.OP_SWAP),
			Op(txscript.OP_CAT), Op(txscript.OP_SHA256),
			Op(txscript.OP_FROMALTSTACK), Op(txscript.OP_FROMALTSTACK),
			Num(7), Op(txscript.OP_PICK),
			Op(txscript.OP_IF), Op(txscript.OP_OVER),
			Op(txscript.OP_ADD), Op(txscript.OP_ENDIF),
			Op(txscript.OP_SWAP), Op(txscript.OP_DUP),
			Op(txscript.OP_ADD),
			Op(txscript.OP_SWAP), Op(txscript.OP_TOALTSTACK),
			Op(txscript.OP_TOALTSTACK),
			Op(txscript.OP_TOALTSTACK),
		}...)
		s = append(s, midRoll(3, 3)...)
	}
	// sibling: sc = sh || enc64(ss); keep ss
	s = append(s, Num(2), Op(txscript.OP_PICK), Op(txscript.OP_TOALTSTACK))
	s = append(s, midEnc64()...)
	s = append(s, Op(txscript.OP_CAT), Op(txscript.OP_FROMALTSTACK))
	// new accumulator
	s = append(s, Num(7), Op(txscript.OP_PICK), Op(txscript.OP_OVER),
		Op(txscript.OP_ADD), Op(txscript.OP_TOALTSTACK))
	s = append(s, midRoll(7, 1)...)
	s = append(s, midRoll(5, 2)...)
	s = append(s, midEnc64()...)
	s = append(s, midRoll(6, 1)...)
	s = append(s, Op(txscript.OP_SWAP), Op(txscript.OP_CAT))
	s = append(s, []Token{
		Num(2), Op(txscript.OP_PICK), Op(txscript.OP_SWAP), Num(4),
		Op(txscript.OP_PICK),
		Op(txscript.OP_NOTIF), Op(txscript.OP_SWAP),
		Op(txscript.OP_ENDIF), Op(txscript.OP_CAT),
		Num(8), Op(txscript.OP_PICK), Op(txscript.OP_SWAP),
		Op(txscript.OP_CAT), Op(txscript.OP_SHA256),
		Op(txscript.OP_TOALTSTACK),
	}...)
	// old accumulator
	s = append(s, []Token{
		Num(5), Op(txscript.OP_PICK), Op(txscript.OP_OVER),
		Op(txscript.OP_ADD), Op(txscript.OP_TOALTSTACK),
		Op(txscript.OP_DROP),
	}...)
	s = append(s, midRoll(4, 1)...)
	s = append(s, midRoll(4, 2)...)
	s = append(s, midEnc64()...)
	s = append(s, midRoll(3, 1)...)
	s = append(s, []Token{
		Op(txscript.OP_SWAP), Op(txscript.OP_CAT), Op(txscript.OP_ROT),
		Op(txscript.OP_NOTIF), Op(txscript.OP_SWAP),
		Op(txscript.OP_ENDIF), Op(txscript.OP_CAT),
		Op(txscript.OP_OVER), Op(txscript.OP_SWAP), Op(txscript.OP_CAT),
		Op(txscript.OP_SHA256),
		Op(txscript.OP_FROMALTSTACK), Op(txscript.OP_FROMALTSTACK),
		Op(txscript.OP_FROMALTSTACK),
	}...)
	return s
}

// midLevels repeats midLevel for levels height..depth-1.
func midLevels(sparse bool, depth, height int) []Token {
	var out []Token
	for i := height; i < depth; i++ {
		out = append(out, midLevel(sparse)...)
	}
	return out
}

// midSparseSetup verifies H_pos and primes the direction accumulator.
func midSparseSetup() []Token {
	return midCat(
		[]Token{Op(txscript.OP_2SWAP), Op(txscript.OP_CAT)},
		midTagged(midPosPrefix),
		[]Token{
			Op(txscript.OP_ROT), Op(txscript.OP_DUP),
			Op(txscript.OP_TOALTSTACK),
			Op(txscript.OP_SIZE), Num(4), Op(txscript.OP_EQUALVERIFY),
			Op(txscript.OP_ROT), Op(txscript.OP_CAT),
			Op(txscript.OP_EQUALVERIFY),
			Op(txscript.OP_0), Op(txscript.OP_TOALTSTACK),
			Op(txscript.OP_1), Op(txscript.OP_TOALTSTACK),
			Data(midEmptyLeafHash), Op(txscript.OP_TOALTSTACK),
		},
	)
}

// midSparseTeardown checks the accumulated position against pos_lo.
func midSparseTeardown() []Token {
	return []Token{
		Op(txscript.OP_FROMALTSTACK), Op(txscript.OP_DROP),
		Op(txscript.OP_FROMALTSTACK), Op(txscript.OP_DROP),
		Op(txscript.OP_FROMALTSTACK), Op(txscript.OP_FROMALTSTACK),
		Op(txscript.OP_NUMEQUALVERIFY),
	}
}

// midCheckOld checks the old root and the input amount.
func midCheckOld(sparse bool) []Token {
	s := []Token{Op(txscript.OP_2SWAP)}
	s = append(s, midRoll(6, 2)...)
	s = append(s, midLe64()...)
	s = append(s, Num(SelInAmount), Op(OP_TX), Op(txscript.OP_EQUALVERIFY))
	if sparse {
		s = append(s, midSparseTeardown()...)
	}
	return append(s, Op(txscript.OP_FROMALTSTACK), Op(txscript.OP_EQUALVERIFY))
}

// midCheckPrev chains a further transition onto the previous result.
func midCheckPrev(sparse bool) []Token {
	s := []Token{Op(txscript.OP_2SWAP)}
	if sparse {
		s = append(s, midSparseTeardown()...)
	}
	return append(s,
		Op(txscript.OP_FROMALTSTACK), Op(txscript.OP_NUMEQUALVERIFY),
		Op(txscript.OP_FROMALTSTACK), Op(txscript.OP_EQUALVERIFY))
}

// midFinal emits the new tree output, or succeeds if the tree is empty.
func midFinal(depth int) []Token {
	s := []Token{
		Op(txscript.OP_ROT), Op(txscript.OP_DROP),
		Op(txscript.OP_OVER), Data(midEmptyNodeHash(depth)),
		Op(txscript.OP_EQUAL),
		Op(txscript.OP_IF), Op(txscript.OP_2DROP), Op(txscript.OP_2DROP),
		Op(txscript.OP_FROMALTSTACK), Op(txscript.OP_DROP),
		Op(txscript.OP_1),
		Op(txscript.OP_ELSE),
	}
	s = append(s, midRoll(3, 2)...)
	s = append(s, midLe64()...)
	s = append(s, Op(txscript.OP_SWAP), Op(txscript.OP_FROMALTSTACK))
	s = append(s, midTreeSpkMin()...)
	return append(s,
		Op(txscript.OP_0), Num(SelOutSingle), Op(OP_TX),
		Op(txscript.OP_ROT), Op(txscript.OP_EQUALVERIFY),
		Op(txscript.OP_EQUAL), Op(txscript.OP_ENDIF))
}

// midLeafWitnessLen is the number of witness elements per leaf.
const midLeafWitnessLen = 10

// midFieldSizes is the (pick depth, size) table leaf_join checks.
var midFieldSizes = [7][2]int64{{0, 4}, {1, 4}, {2, 4}, {3, 32}, {4, 32}, {5, 32}, {6, 8}}

// midLeafJoin re-joins the seven leaf pieces under OP_SIZE checks.
func midLeafJoin() []Token {
	s := []Token{Num(2), Op(txscript.OP_PICK), Op(txscript.OP_TOALTSTACK)}
	s = append(s, midLe64()...)
	s = append(s, Num(7), Op(txscript.OP_PICK), Op(txscript.OP_EQUALVERIFY))
	for _, f := range midFieldSizes {
		d, size := f[0], f[1]
		if d != 0 {
			s = append(s, Num(d), Op(txscript.OP_PICK))
		} else {
			s = append(s, Op(txscript.OP_DUP))
		}
		s = append(s, Op(txscript.OP_SIZE), Num(size),
			Op(txscript.OP_EQUALVERIFY), Op(txscript.OP_DROP))
	}
	return append(s, midRepeat([]Token{Op(txscript.OP_CAT)}, 6)...)
}

// midExitBlockFull is one complete exit: authorisation, payout check, leaf
// reassembly and the proof levels.
func midExitBlockFull(sparse bool, depth, outIndex int) []Token {
	s := []Token{
		Op(txscript.OP_DUP), Op(txscript.OP_TOALTSTACK), Op(txscript.OP_IF),
		Num(3), Op(txscript.OP_PICK), Op(txscript.OP_CHECKLOCKTIMEVERIFY),
		Op(txscript.OP_DROP),
		Num(10), Op(txscript.OP_PICK), Op(txscript.OP_CHECKSIGVERIFY),
	}
	s = append(s, midPadz()...)
	s = append(s, []Token{
		Num(6), Op(txscript.OP_PICK), Op(txscript.OP_EQUALVERIFY),
		Op(txscript.OP_ELSE), Num(11), Op(txscript.OP_PICK),
		Op(txscript.OP_CHECKSIGVERIFY), Op(txscript.OP_2DROP),
		Op(txscript.OP_DROP),
		Op(txscript.OP_ENDIF),
		Num(int64(outIndex)), Num(SelOutSingle), Op(OP_TX),
		Data(midP2TRPrefix), Num(11), Op(txscript.OP_PICK),
		Op(txscript.OP_CAT), Op(txscript.OP_EQUALVERIFY),
		Num(10), Op(txscript.OP_PICK), Op(txscript.OP_EQUALVERIFY),
		Op(txscript.OP_FROMALTSTACK), Op(txscript.OP_DROP),
	}...)
	s = append(s, midLeafJoin()...)
	s = append(s, midTagged(midLeafPrefix)...)
	s = append(s, Op(txscript.OP_FROMALTSTACK))
	if sparse {
		s = append(s, midRoll(5, 4)...)
		s = append(s, midSparseSetup()...)
	}
	s = append(s, Data(midNodePrefix), Op(txscript.OP_ROT),
		Op(txscript.OP_ROT), Data(midEmptyLeafHash), Op(txscript.OP_0))
	return append(s, midLevels(sparse, depth, 0)...)
}

// MidExitScript is the MID-tier EXIT_k script for a tree of the given depth.
func MidExitScript(depth, k int, sparse bool) []Token {
	s := midPrologue()
	s = append(s, midExitBlockFull(sparse, depth, 1)...)
	s = append(s, midCheckOld(sparse)...)
	for i := 2; i <= k; i++ {
		s = append(s, Op(txscript.OP_SWAP), Op(txscript.OP_TOALTSTACK),
			Op(txscript.OP_TOALTSTACK), Op(txscript.OP_DROP))
		s = append(s, midExitBlockFull(sparse, depth, i)...)
		s = append(s, midCheckPrev(sparse)...)
	}
	return append(s, midFinal(depth)...)
}

// midJoinBlock inserts one new subtree (dense) or leaf (sparse).
func midJoinBlock(sparse bool, depth, height int) []Token {
	if !sparse {
		s := []Token{
			Op(txscript.OP_OVER), Op(txscript.OP_SIZE), Num(32),
			Op(txscript.OP_EQUALVERIFY), Op(txscript.OP_DROP),
			Data(midNodePrefix), Op(txscript.OP_ROT), Op(txscript.OP_ROT),
			Data(midEmptyNodeHash(height)), Op(txscript.OP_0),
			Op(txscript.OP_2SWAP),
		}
		return append(s, midLevels(false, depth, height)...)
	}
	s := midLeafJoin()
	s = append(s, midTagged(midLeafPrefix)...)
	s = append(s, Op(txscript.OP_FROMALTSTACK))
	s = append(s, midRoll(5, 4)...)
	s = append(s, midSparseSetup()...)
	s = append(s, Data(midNodePrefix), Op(txscript.OP_ROT),
		Op(txscript.OP_ROT), Data(midEmptyLeafHash), Op(txscript.OP_0),
		Op(txscript.OP_2SWAP))
	return append(s, midLevels(true, depth, 0)...)
}

// MidJoinScript is the MID-tier JOIN script (k chained joins).
func MidJoinScript(depth, height int, operatorKey [32]byte, sparse bool, k int) []Token {
	s := midPrologue()
	s = append(s, Data(operatorKey[:]), Op(txscript.OP_CHECKSIGVERIFY))
	s = append(s, midJoinBlock(sparse, depth, height)...)
	s = append(s, midCheckOld(sparse)...)
	for i := 2; i <= k; i++ {
		s = append(s, Op(txscript.OP_SWAP), Op(txscript.OP_TOALTSTACK),
			Op(txscript.OP_TOALTSTACK), Op(txscript.OP_DROP))
		s = append(s, midJoinBlock(sparse, depth, height)...)
		s = append(s, midCheckPrev(sparse)...)
	}
	return append(s, midFinal(depth)...)
}

// MidUpdateScript is the MID-tier UPDATE script: a cooperative leaf rewrite.
func MidUpdateScript(depth int, operatorKey [32]byte, sparse bool) []Token {
	return midUpdateScript(depth, operatorKey, sparse, false)
}

// MidUpdateXScript is the MID-tier UPDATE^x script (spec 7.4 rule 5): UPDATE
// with one more signature, directly above opsig in the witness, that MUST be
// valid over the same transaction by the old leaf's exit key. It is a
// tree-creation parameter: a tree uses either UPDATE or UPDATE^x, never both.
func MidUpdateXScript(depth int, operatorKey [32]byte, sparse bool) []Token {
	return midUpdateScript(depth, operatorKey, sparse, true)
}

// midUpdateScript is the shared body of the MID UPDATE and UPDATE^x scripts.
func midUpdateScript(depth int, operatorKey [32]byte, sparse,
	exitConsent bool) []Token {

	s := midPrologue()
	if exitConsent {
		// old.ek sits 21 elements below the exit signature.
		s = append(s, Num(21), Op(txscript.OP_PICK),
			Op(txscript.OP_CHECKSIGVERIFY))
	}
	s = append(s, Data(operatorKey[:]), Op(txscript.OP_CHECKSIGVERIFY),
		Num(18), Op(txscript.OP_PICK), Op(txscript.OP_CHECKSIGVERIFY))
	if sparse {
		s = append(s,
			Num(8), Op(txscript.OP_PICK), Num(19), Op(txscript.OP_PICK),
			Op(txscript.OP_EQUALVERIFY),
			Num(5), Op(txscript.OP_PICK), Num(16), Op(txscript.OP_PICK),
			Op(txscript.OP_EQUALVERIFY))
	}
	s = append(s, midLeafJoin()...)
	s = append(s, Op(txscript.OP_TOALTSTACK))
	s = append(s, midLeafJoin()...)
	s = append(s, midTagged(midLeafPrefix)...)
	s = append(s, Op(txscript.OP_FROMALTSTACK), Op(txscript.OP_FROMALTSTACK),
		Op(txscript.OP_FROMALTSTACK), Op(txscript.OP_SWAP))
	s = append(s, midTagged(midLeafPrefix)...)
	s = append(s, Op(txscript.OP_SWAP))
	if sparse {
		s = append(s, midRoll(7, 4)...)
		s = append(s, midSparseSetup()...)
	}
	s = append(s, Data(midNodePrefix))
	s = append(s, midRoll(4, 4)...)
	s = append(s, midLevels(sparse, depth, 0)...)
	s = append(s, midCheckOld(sparse)...)
	return append(s, midFinal(depth)...)
}

// MidClaimScript is the MID-tier CLAIM script: a voucher redemption that
// drains a source leaf into a new claim leaf.
func MidClaimScript(depth int, sparse bool) []Token {
	return midCarveScript(depth, sparse, authVoucher)
}

// MidClaimHScript is the MID-tier CLAIM^h script (spec 7.5.1): CLAIM with a
// 32-byte preimage in the witness between vsig and r, whose SHA256 is
// appended to the signed voucher message under a separate tag. The preimage
// is hashed straight into the message, so a wrong one fails as a bad
// signature. It is a tree-creation parameter: a tree uses either CLAIM or
// CLAIM^h, never both.
func MidClaimHScript(depth int, sparse bool) []Token {
	return midCarveScript(depth, sparse, authHashlock)
}

// MidSplitScript is the MID-tier SPLIT script (spec 7.5.2): CLAIM with the
// owner's transaction signature in place of the voucher, so the witness
// carries no preimage and no voucher message is rebuilt. It needs no
// OP_CHECKSIGFROMSTACK. Like CLAIM^h it is a tree-creation parameter and
// stays out of MidAllScripts.
func MidSplitScript(depth int, sparse bool) []Token {
	return midCarveScript(depth, sparse, authOwner)
}

// midCarveScript is the shared body of the MID CLAIM, CLAIM^h and SPLIT
// scripts: auth selects the authorisation and nothing else.
func midCarveScript(depth int, sparse bool, auth string) []Token {
	hashlock := auth == authHashlock
	s := []Token{
		Num(SelCurrInput), Op(OP_TX), Op(txscript.OP_0),
		Op(txscript.OP_NUMEQUALVERIFY), Op(txscript.OP_2DUP),
	}
	s = append(s, midTreeSpkMin()...)
	s = append(s, Num(SelInSpk), Op(OP_TX), Op(txscript.OP_EQUALVERIFY),
		Op(txscript.OP_DUP), Op(txscript.OP_TOALTSTACK),
		Op(txscript.OP_SWAP), Op(txscript.OP_TOALTSTACK))
	if auth == authOwner {
		// SPLIT (7.5.2): the owner signs the transaction, so no message is
		// rebuilt. Drop the spare m; src.ok then sits 25 deep, since the
		// witness holds src(10) claim(10) extras(7) below the signature and
		// the owner key is the third field of the source leaf block.
		s = append(s, Op(txscript.OP_DROP), // ... extras(7) osig
			Num(25), Op(txscript.OP_PICK), // ... osig src.ok
			Op(txscript.OP_CHECKSIGVERIFY)) // src(10) claim(10) extras(7)
	} else {
		if hashlock {
			// Park SHA256(preimage) on the altstack: every pick depth below
			// is exactly as in CLAIM.
			s = append(s, Op(txscript.OP_SWAP), Op(txscript.OP_SIZE), Num(32),
				Op(txscript.OP_EQUALVERIFY), Op(txscript.OP_SHA256),
				Op(txscript.OP_TOALTSTACK))
		}
		// voucher message m || src_leaf || claim_leaf [|| phash]
		s = append(s, midRepeat([]Token{Num(28), Op(txscript.OP_PICK)}, 7)...)
		s = append(s, midRepeat([]Token{Op(txscript.OP_CAT)}, 6)...)
		s = append(s, midRepeat([]Token{Num(19), Op(txscript.OP_PICK)}, 7)...)
		s = append(s, midRepeat([]Token{Op(txscript.OP_CAT)}, 6)...)
		s = append(s, Num(2), Op(txscript.OP_PICK), Op(txscript.OP_ROT),
			Op(txscript.OP_ROT), Op(txscript.OP_CAT), Op(txscript.OP_CAT))
		voucherPrefix := midVoucherPrefix
		if hashlock {
			s = append(s, Op(txscript.OP_FROMALTSTACK), Op(txscript.OP_CAT))
			voucherPrefix = midVoucherHPrefix
		}
		s = append(s, midTagged(voucherPrefix)...)
		s = append(s, Op(txscript.OP_ROT), Op(txscript.OP_SWAP),
			Num(27), Op(txscript.OP_PICK),
			Op(OP_CHECKSIGFROMSTACK), Op(txscript.OP_VERIFY),
			Op(txscript.OP_DROP))
	}
	// seq consistency: le32(seq_num) == src.seq
	s = append(s, Num(20), Op(txscript.OP_PICK), Num(7), Op(txscript.OP_PICK))
	s = append(s, midRoll(7, 2)...)
	s = append(s, midPadz()...)
	s = append(s, Op(txscript.OP_EQUALVERIFY))
	s = append(s, midRepeat([]Token{Op(txscript.OP_TOALTSTACK)}, 5)...)
	s = append(s, midLeafJoin()...)
	s = append(s, Op(txscript.OP_TOALTSTACK))
	s = append(s, midRepeat([]Token{Num(8), Op(txscript.OP_PICK)}, 5)...)
	s = append(s, midRepeat([]Token{Op(txscript.OP_CAT)}, 4)...)
	s = append(s, Op(txscript.OP_TOALTSTACK))
	s = append(s, midLeafJoin()...)
	s = append(s, midTagged(midLeafPrefix)...)
	s = append(s, Op(txscript.OP_FROMALTSTACK), Op(txscript.OP_DUP),
		Op(txscript.OP_FROMALTSTACK),
		Op(txscript.OP_FROMALTSTACK), Op(txscript.OP_FROMALTSTACK))
	s = append(s, midRepeat([]Token{Op(txscript.OP_FROMALTSTACK)}, 5)...)
	s = append(s, Op(txscript.OP_FROMALTSTACK), Num(7), Op(txscript.OP_PICK),
		Op(txscript.OP_TOALTSTACK), Num(6), Op(txscript.OP_PICK),
		Op(txscript.OP_TOALTSTACK), Op(txscript.OP_TOALTSTACK))
	s = append(s, midRoll(6, 1)...)
	s = append(s, Op(txscript.OP_DROP))
	s = append(s, midRoll(7, 1)...)
	s = append(s, midRoll(6, 1)...)
	s = append(s, Op(txscript.OP_SUB),
		Op(txscript.OP_DUP), Op(txscript.OP_0),
		Op(txscript.OP_GREATERTHANOREQUAL), Op(txscript.OP_VERIFY),
		Op(txscript.OP_DUP))
	s = append(s, midRoll(3, 2)...)
	s = append(s, midLe64()...)
	s = append(s, midRoll(4, 1)...)
	s = append(s, Op(txscript.OP_1ADD))
	s = append(s, midRoll(4, 2)...)
	s = append(s, midPadz()...)
	s = append(s, midRoll(3, 1)...)
	s = append(s, Op(txscript.OP_SWAP), Op(txscript.OP_CAT),
		Op(txscript.OP_CAT))
	s = append(s, midTagged(midLeafPrefix)...)
	s = append(s, Op(txscript.OP_SWAP))
	s = append(s, Op(txscript.OP_DUP), Op(txscript.OP_NOT),
		Op(txscript.OP_IF), Op(txscript.OP_SWAP), Op(txscript.OP_DROP),
		Data(midEmptyLeafHash), Op(txscript.OP_SWAP),
		Op(txscript.OP_ENDIF))
	if sparse {
		s = append(s, midRoll(7, 4)...)
		s = append(s, midSparseSetup()...)
	}
	s = append(s, Data(midNodePrefix))
	s = append(s, midRoll(4, 4)...)
	s = append(s, midLevels(sparse, depth, 0)...)
	s = append(s, midCheckOld(sparse)...)
	s = append(s, Op(txscript.OP_FROMALTSTACK), Op(txscript.OP_FROMALTSTACK))
	s = append(s, midTagged(midLeafPrefix)...)
	s = append(s, Op(txscript.OP_SWAP),
		Op(txscript.OP_2SWAP), Op(txscript.OP_SWAP),
		Op(txscript.OP_TOALTSTACK), Op(txscript.OP_TOALTSTACK))
	if sparse {
		s = append(s, midRoll(6, 4)...)
		s = append(s, midSparseSetup()...)
	}
	s = append(s, Data(midEmptyLeafHash), Op(txscript.OP_0),
		Op(txscript.OP_2SWAP))
	s = append(s, midLevels(sparse, depth, 0)...)
	s = append(s, midCheckPrev(sparse)...)
	return append(s, midFinal(depth)...)
}

// MidAllScripts builds the MID-tier script set for one profile, keyed as
// layertree_mid.all_scripts keys them.
func MidAllScripts(depth int, operatorKey [32]byte, sparse bool,
	joinHeights, exitKs, joinKs []int) map[string][]Token {

	out := make(map[string][]Token)
	for _, k := range exitKs {
		out[fmt.Sprintf("EXIT_%d", k)] = MidExitScript(depth, k, sparse)
	}
	heights := joinHeights
	if sparse {
		heights = []int{0}
	}
	for _, h := range heights {
		out[fmt.Sprintf("JOIN_%d", h)] = MidJoinScript(depth, h, operatorKey, sparse, 1)
	}
	for _, k := range joinKs {
		out[fmt.Sprintf("JOINK_%d", k)] = MidJoinScript(depth, 0, operatorKey, sparse, k)
	}
	out["UPDATE"] = MidUpdateScript(depth, operatorKey, sparse)
	out["CLAIM"] = MidClaimScript(depth, sparse)
	return out
}

// --------------------------------------------------------- witness helpers --

// MidScriptNum is the CScriptNum minimal encoding for 0 <= n < 2^31.
func MidScriptNum(n uint64) []byte {
	if n > MidMaxSum {
		panic("script: MID sum out of range")
	}
	if n == 0 {
		return []byte{}
	}
	var b []byte
	for v := n; v > 0; v >>= 8 {
		b = append(b, byte(v))
	}
	if b[len(b)-1]&0x80 != 0 {
		b = append(b, 0)
	}
	return b
}

// MidPad returns (z, w) with MidScriptNum(n)||z == le32(n) and z||w four
// zero bytes, the pair the PADZ gadget consumes.
func MidPad(n uint64) (z, w []byte) {
	k := 4 - len(MidScriptNum(n))
	return make([]byte, k), make([]byte, 4-k)
}

// MidLeafWitness is the ten-element witness encoding of a leaf.
func MidLeafWitness(l *tree.Leaf) [][]byte {
	b := l.Serialize()
	z, w := MidPad(l.Amount)
	return [][]byte{
		b[0:8], b[8:40], b[40:72], b[72:104], b[104:108], b[108:112],
		b[112:116], MidScriptNum(l.Amount), z, w,
	}
}

// MidLeafExitWitness adds the minimal evict_after and its pad.
func MidLeafExitWitness(l *tree.Leaf) [][]byte {
	z, w := MidPad(uint64(l.EvictAfter))
	return append(MidLeafWitness(l),
		MidScriptNum(uint64(l.EvictAfter)), z, w)
}

// MidLevelsWitness returns the witness items for every proof level,
// bottom..top (level D-1 first), sized against the running accumulators.
func MidLevelsWitness(path []tree.PathStep, oldNode, newNode tree.Node,
	sparse bool, height int) [][]byte {

	perLevel := make([][][]byte, 0, len(path))
	oldSum, newSum := oldNode.Sum, newNode.Sum
	for k, step := range path {
		sib := step.Sibling
		sh := append([]byte{}, sib.Hash[:]...)
		if sparse && sib == tree.EmptyNode(height+k) {
			sh = []byte{}
		}
		zs, ws := MidPad(sib.Sum)
		zn, wn := MidPad(newSum)
		zo, wo := MidPad(oldSum)
		dir := []byte{}
		if step.Dir {
			dir = []byte{1}
		}
		perLevel = append(perLevel, [][]byte{
			zo, wo, zn, wn, dir, sh, MidScriptNum(sib.Sum), zs, ws,
		})
		oldSum += sib.Sum
		newSum += sib.Sum
	}
	var items [][]byte
	for i := len(perLevel) - 1; i >= 0; i-- {
		items = append(items, perLevel[i]...)
	}
	return items
}

// MidPosWitness returns the sparse position items ok, nonce, pos_lo, pos_hi.
func MidPosWitness(l *tree.Leaf) [][]byte {
	h := l.PosHash()
	var nonce [4]byte
	binary.LittleEndian.PutUint32(nonce[:], l.Nonce)
	return [][]byte{
		append([]byte{}, l.OwnerKey[:]...), nonce[:],
		append([]byte{}, h[0:4]...), append([]byte{}, h[4:]...),
	}
}
