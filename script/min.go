package script

import (
	"encoding/hex"

	"github.com/btcsuite/btcd/txscript"
)

// This file is a direct port of tools/layertree_min.py: the MIN tier
// (spec 4.6), BIP-342 tapscript (0xC0 semantics) plus OP_CAT and
// OP_TWEAKADD only. Introspection is constructive: the script assembles
// the BIP-341 signature message itself and checks it with OP_CHECKSIG
// against the generator G, whose only valid s is e + 1.

// MinGX is the x-only encoding of the secp256k1 generator G.
var MinGX = func() []byte {
	b, err := hex.DecodeString(
		"79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
	if err != nil {
		panic(err)
	}
	return b
}()

// MinTapSighashPrefix and MinChallengePrefix are the tagged-hash prefixes
// sha256(tag)||sha256(tag) the MIN scripts carry as literals.
var (
	MinTapSighashPrefix = midTagPrefix("TapSighash")
	MinChallengePrefix  = midTagPrefix("BIP0340/challenge")
)

// minRoll repeats [n OP_ROLL] `times` times.
func minRoll(n int64, times int) []Token { return midRoll(n, times) }

// MinExitScript is the MIN-tier EXIT_1 script for the dense profile.
//
// Witness (bottom..top):
//
//	e31 sha_seqs tapleaf sha_prevouts ver lock spk_in1_ser amt_in1 extra_outs
//	zf wf zi wi [levels: 9 each] leaf(10) ea_num ze we sig is_evict r m
func MinExitScript(depth int) []Token {
	s := []Token{Op(txscript.OP_2DUP)}
	s = append(s, midTreeSpkMin()...)
	s = append(s, Op(txscript.OP_TOALTSTACK),
		Op(txscript.OP_TOALTSTACK), Op(txscript.OP_TOALTSTACK))
	// authorisation (as MID, but is_evict need not be kept)
	s = append(s, Op(txscript.OP_IF),
		Num(3), Op(txscript.OP_PICK), Op(txscript.OP_CHECKLOCKTIMEVERIFY),
		Op(txscript.OP_DROP),
		Num(10), Op(txscript.OP_PICK), Op(txscript.OP_CHECKSIGVERIFY))
	s = append(s, midPadz()...)
	s = append(s, Num(6), Op(txscript.OP_PICK), Op(txscript.OP_EQUALVERIFY),
		Op(txscript.OP_ELSE), Num(11), Op(txscript.OP_PICK),
		Op(txscript.OP_CHECKSIGVERIFY), Op(txscript.OP_2DROP),
		Op(txscript.OP_DROP),
		Op(txscript.OP_ENDIF))
	// payout serialisation out1 = amt8 || 0x22 || 0x5120 || ek -> alt
	s = append(s, Num(9), Op(txscript.OP_PICK),
		Data([]byte{0x22, 0x51, 0x20}), Op(txscript.OP_CAT),
		Num(9), Op(txscript.OP_PICK), Op(txscript.OP_CAT),
		Op(txscript.OP_TOALTSTACK))
	s = append(s, midLeafJoin()...)
	s = append(s, midTagged(midLeafPrefix)...)
	s = append(s, Op(txscript.OP_FROMALTSTACK))
	s = append(s, Data(midNodePrefix), Op(txscript.OP_ROT),
		Op(txscript.OP_ROT), Data(midEmptyLeafHash), Op(txscript.OP_0))
	s = append(s, midLevels(false, depth, 0)...)
	// ---- constructive sighash ----
	s = append(s, Op(txscript.OP_2SWAP))
	s = append(s, minRoll(6, 2)...)
	s = append(s, midLe64()...)
	s = append(s, Op(txscript.OP_FROMALTSTACK), Op(txscript.OP_FROMALTSTACK),
		Num(3), Op(txscript.OP_ROLL), Op(txscript.OP_EQUALVERIFY),
		Num(4), Op(txscript.OP_ROLL), Op(txscript.OP_DROP))
	// stack below: raw9 zf wf ; bring zf wf and pad ns
	s = append(s, Op(txscript.OP_ROT))
	s = append(s, minRoll(5, 2)...)
	s = append(s, midLe64()...)
	s = append(s, Num(3), Op(txscript.OP_ROLL), Op(txscript.OP_FROMALTSTACK))
	s = append(s, midTreeSpkMin()...)
	s = append(s, Data([]byte{0x22}), Op(txscript.OP_SWAP),
		Op(txscript.OP_CAT), Op(txscript.OP_CAT),
		Op(txscript.OP_SWAP), Op(txscript.OP_CAT))
	return append(s, minSighashTail()...)
}

// minSighashTail is the constructive introspection every MIN script ends
// with. Stack on entry: raw(9) S8 outs, where S8 is le64 of the tree
// input's amount and outs the serialisation of the leading outputs the
// script built ; altstack: .. spk0. It ends in the OP_CHECKSIG under G.
func minSighashTail() []Token {
	s := []Token{Num(2), Op(txscript.OP_ROLL), Op(txscript.OP_CAT),
		Op(txscript.OP_SHA256)}
	s = append(s, Num(2), Op(txscript.OP_ROLL), Op(txscript.OP_ROT),
		Op(txscript.OP_SWAP), Op(txscript.OP_CAT), Op(txscript.OP_SHA256))
	s = append(s, Op(txscript.OP_FROMALTSTACK), Data([]byte{0x22}),
		Op(txscript.OP_SWAP), Op(txscript.OP_CAT),
		Num(3), Op(txscript.OP_ROLL), Op(txscript.OP_CAT),
		Op(txscript.OP_SHA256))
	s = append(s, Num(3), Op(txscript.OP_ROLL), Num(4), Op(txscript.OP_ROLL),
		Data([]byte{0, 0}), Op(txscript.OP_SWAP), Op(txscript.OP_CAT),
		Op(txscript.OP_SWAP), Op(txscript.OP_CAT),
		Num(4), Op(txscript.OP_ROLL), Op(txscript.OP_CAT),
		Op(txscript.OP_ROT), Op(txscript.OP_CAT), Op(txscript.OP_SWAP),
		Op(txscript.OP_CAT),
		Num(3), Op(txscript.OP_ROLL), Op(txscript.OP_CAT),
		Op(txscript.OP_SWAP), Op(txscript.OP_CAT),
		Data([]byte{0x02, 0, 0, 0, 0}), Op(txscript.OP_CAT),
		Op(txscript.OP_SWAP), Op(txscript.OP_CAT),
		Data([]byte{0x00, 0xff, 0xff, 0xff, 0xff}), Op(txscript.OP_CAT))
	s = append(s, midTagged(MinTapSighashPrefix)...)
	gg := make([]byte, 0, 64)
	gg = append(gg, MinGX...)
	gg = append(gg, MinGX...)
	s = append(s, Data(gg), Op(txscript.OP_SWAP), Op(txscript.OP_CAT))
	s = append(s, midTagged(MinChallengePrefix)...)
	s = append(s, Op(txscript.OP_OVER), Data([]byte{0}), Op(txscript.OP_CAT),
		Op(txscript.OP_EQUALVERIFY),
		Data(MinGX), Op(txscript.OP_SWAP), Op(txscript.OP_CAT),
		Data([]byte{1}), Op(txscript.OP_CAT),
		Data(MinGX), Op(txscript.OP_CHECKSIG))
	return s
}

// MinSplitScript is the MIN-tier SPLIT (spec 7.5.2) for the dense profile:
// the MID carve, authorised by the source owner's transaction signature,
// with the OP_TX reads replaced by the constructive signature message.
//
// Witness (bottom..top):
//
//	e31 sha_seqs tapleaf sha_prevouts ver lock spk_in1_ser amt_in1 extra_outs
//	zf wf [claim levels] zi wi [src levels]
//	src(10) new(10) seq_num zq0 wq0 zq1 wq1 zs2 ws2 osig r m
//
// Outputs are [tree', <raw extra outputs>].
func MinSplitScript(depth int) []Token {
	s := []Token{Op(txscript.OP_2DUP)}
	s = append(s, midTreeSpkMin()...)
	s = append(s, Op(txscript.OP_TOALTSTACK),
		Op(txscript.OP_DUP), Op(txscript.OP_TOALTSTACK),
		Op(txscript.OP_SWAP), Op(txscript.OP_TOALTSTACK),
		Op(txscript.OP_DROP), Num(midCarveOwnerDepth), Op(txscript.OP_PICK),
		Op(txscript.OP_CHECKSIGVERIFY))
	s = append(s, midCarveSource(depth, false)...)
	// As MID check_old, but the input amount is kept for the message.
	s = append(s, Op(txscript.OP_2SWAP))
	s = append(s, minRoll(6, 2)...)
	s = append(s, midLe64()...)
	s = append(s, Op(txscript.OP_SWAP), Op(txscript.OP_FROMALTSTACK),
		Op(txscript.OP_EQUALVERIFY),
		Op(txscript.OP_FROMALTSTACK), Op(txscript.OP_FROMALTSTACK),
		Op(txscript.OP_ROT), Op(txscript.OP_TOALTSTACK))
	s = append(s, midCarveClaim(depth, false)...)
	// out0 = le64(ns2) || 0x22 || TREE_SPK(nh2, m)
	s = append(s, Op(txscript.OP_ROT), Op(txscript.OP_DROP))
	s = append(s, minRoll(3, 2)...)
	s = append(s, midLe64()...)
	s = append(s, Op(txscript.OP_SWAP), Op(txscript.OP_FROMALTSTACK),
		Op(txscript.OP_FROMALTSTACK), Op(txscript.OP_ROT),
		Op(txscript.OP_SWAP))
	s = append(s, midTreeSpkMin()...)
	s = append(s, Data([]byte{0x22}), Op(txscript.OP_SWAP),
		Op(txscript.OP_CAT), Op(txscript.OP_ROT), Op(txscript.OP_SWAP),
		Op(txscript.OP_CAT))
	return append(s, minSighashTail()...)
}
