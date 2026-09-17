package tree

import (
	"encoding/hex"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/txscript"
)

// NUMSHex is the x coordinate of the BIP-341 provably unspendable key H
// (spec 5.1). Note this is deliberately not lnd's TaprootNUMSKey, which is
// a different NUMS point derived for Lightning.
const NUMSHex = "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0"

// NUMS is H as a public key (even-y lift).
var NUMS = func() *btcec.PublicKey {
	b, _ := hex.DecodeString(NUMSHex)
	k, err := schnorr.ParsePubKey(b)
	if err != nil {
		panic(err)
	}
	return k
}()

// StateTweak is t = int(H_state(root_hash)) (spec 6.1).
func StateTweak(rootHash [32]byte) [32]byte {
	return TaggedHash(TagState, rootHash[:])
}

// InternalKey is P = NUMS + t*G, returned as a compressed public key.
func InternalKey(rootHash [32]byte) (*btcec.PublicKey, error) {
	t := StateTweak(rootHash)
	var ts btcec.ModNScalar
	if overflow := ts.SetByteSlice(t[:]); overflow || ts.IsZero() {
		return nil, ErrInvalidState
	}
	var tG, nums, sum btcec.JacobianPoint
	btcec.ScalarBaseMultNonConst(&ts, &tG)
	NUMS.AsJacobian(&nums)
	btcec.AddNonConst(&nums, &tG, &sum)
	sum.ToAffine()
	return btcec.NewPublicKey(&sum.X, &sum.Y), nil
}

// ErrInvalidState is returned when the state tweak is zero or >= n.
var ErrInvalidState = hexError("layertree: invalid state tweak")

type hexError string

func (e hexError) Error() string { return string(e) }

// OutputKey is the BIP-341 output key for the tree output in state rootHash
// with taptree merkle root m (spec 6.3).
func OutputKey(rootHash, merkleRoot [32]byte) (*btcec.PublicKey, error) {
	p, err := InternalKey(rootHash)
	if err != nil {
		return nil, err
	}
	// BIP-341 uses the even-y lift of the internal key's x coordinate.
	px, err := schnorr.ParsePubKey(schnorr.SerializePubKey(p))
	if err != nil {
		return nil, err
	}
	return txscript.ComputeTaprootOutputKey(px, merkleRoot[:]), nil
}

// ScriptPubKey is TREE_SPK(rootHash, m) = OP_1 <x(Q)>.
func ScriptPubKey(rootHash, merkleRoot [32]byte) ([]byte, error) {
	q, err := OutputKey(rootHash, merkleRoot)
	if err != nil {
		return nil, err
	}
	return txscript.NewScriptBuilder().AddOp(txscript.OP_1).
		AddData(schnorr.SerializePubKey(q)).Script()
}

// P2TR returns OP_1 <xonly> for an arbitrary 32-byte key (payout outputs).
func P2TR(xonly [32]byte) []byte {
	s, _ := txscript.NewScriptBuilder().AddOp(txscript.OP_1).AddData(xonly[:]).Script()
	return s
}

// HexKey parses a 32-byte hex x-only key into an array.
func HexKey(h string) ([32]byte, error) {
	var out [32]byte
	b, err := hex.DecodeString(h)
	if err != nil || len(b) != 32 {
		return out, hexError("bad x-only key hex")
	}
	copy(out[:], b)
	return out, nil
}
