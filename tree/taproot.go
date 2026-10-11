package tree

import (
	"crypto/sha256"
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
	return tweakNUMS(StateTweak(rootHash))
}

// CCVInternalKey is the state key of the CCV tier (spec 4.6, 6.3): the
// BIP-443 data tweak of the NUMS point by the root hash,
// NUMS + sha256(x(NUMS) || root_hash) * G, which is the key a
// CHECKCONTRACTVERIFY call with an empty pk and data root_hash verifies
// against. It is not H_state(root_hash): the data tweak is an untagged
// sha256 over the key and the data, so a CCV tree and a FULL tree with the
// same root have different outputs and the tier is a creation parameter
// (tools/layertree_ref.py ccv_internal_key).
func CCVInternalKey(rootHash [32]byte) (*btcec.PublicKey, error) {
	msg := make([]byte, 0, 64)
	msg = append(msg, schnorr.SerializePubKey(NUMS)...)
	msg = append(msg, rootHash[:]...)
	return tweakNUMS(sha256.Sum256(msg))
}

// tweakNUMS returns NUMS + t*G for a 32-byte scalar t.
func tweakNUMS(t [32]byte) (*btcec.PublicKey, error) {
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
	return tapTweak(p, merkleRoot)
}

// CCVOutputKey is the output key of a CCV-tier tree output (spec 6.3):
// CCVInternalKey(rootHash) under the BIP-341 tweak by m.
func CCVOutputKey(rootHash, merkleRoot [32]byte) (*btcec.PublicKey, error) {
	p, err := CCVInternalKey(rootHash)
	if err != nil {
		return nil, err
	}
	return tapTweak(p, merkleRoot)
}

// tapTweak applies the BIP-341 taptweak by merkleRoot to the even-y lift
// of p's x coordinate, which is the internal key BIP-341 commits to.
func tapTweak(p *btcec.PublicKey, merkleRoot [32]byte) (*btcec.PublicKey, error) {
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
	return P2TRKey(q), nil
}

// CCVScriptPubKey is TREE_SPK_CCV(rootHash, m) (spec 6.3), the tree output
// of the CCV tier (tools/layertree_ref.py tree_spk_ccv).
func CCVScriptPubKey(rootHash, merkleRoot [32]byte) ([]byte, error) {
	q, err := CCVOutputKey(rootHash, merkleRoot)
	if err != nil {
		return nil, err
	}
	return P2TRKey(q), nil
}

// P2TRKey returns OP_1 <x(q)>.
func P2TRKey(q *btcec.PublicKey) []byte {
	s, _ := txscript.NewScriptBuilder().AddOp(txscript.OP_1).
		AddData(schnorr.SerializePubKey(q)).Script()
	return s
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
