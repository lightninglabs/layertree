package txn

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"

	"github.com/roasbeef/layertree/script"
)

// The MIN tier (spec 4.5, tools/layertree_min.py) has no OP_TX: its
// scripts assemble the BIP-341 signature message of the spending
// transaction themselves, from the values they derive (the tree input's
// scriptPubKey and amount, output 0, the payout) and raw witness pieces for
// everything they do not constrain, and then demand a BIP-340 signature
// under the generator G with nonce G, whose only valid s is e + 1. Without
// arbitrary-precision arithmetic that s is formed by grinding: the spender
// varies a free field, the fee input's nSequence, until the challenge e
// ends in a zero byte, and supplies its first 31 bytes; the script appends
// 0x00 to recover e and 0x01 to form s. Expected 256 attempts.

// minGrindTries bounds the grind; 256 attempts are expected, so the bound
// is never reached by an honest run.
const minGrindTries = 1 << 20

// minFirstSequence is the nSequence the grind starts from; attempt i uses
// minFirstSequence - i, as tools/test_min.py does.
const minFirstSequence uint32 = 0xfffffffd

// minRawPieces grinds input 1's nSequence and returns the nine raw
// introspection elements a MIN script consumes, bottom to top: e31 (the
// first 31 bytes of the BIP-340 challenge under G), sha_sequences, the
// tapleaf hash, sha_prevouts, nVersion and nLockTime as le32, input 1's
// scriptPubKey with its length prefix, its amount as le64, and the
// serialisation of every output after the fixedOutputs the script builds
// itself (tools/layertree_min.py raw_pieces). The transaction must have
// exactly two inputs, the tree input and one fee input, which is the
// tier's fixed shape.
func minRawPieces(tx *wire.MsgTx, prevOuts map[wire.OutPoint]*wire.TxOut,
	leafHash [32]byte, fixedOutputs int) ([][]byte, error) {

	if len(tx.TxIn) != 2 {
		return nil, fmt.Errorf("txn: a MIN transition has exactly two "+
			"inputs, the tree input and one fee input, not %d (spec 4.5)",
			len(tx.TxIn))
	}
	if len(tx.TxOut) < fixedOutputs {
		return nil, fmt.Errorf("txn: a MIN transition has at least %d "+
			"outputs, not %d", fixedOutputs, len(tx.TxOut))
	}
	e31, err := minGrind(tx, prevOuts, leafHash)
	if err != nil {
		return nil, err
	}

	var prevouts, sequences bytes.Buffer
	for _, in := range tx.TxIn {
		op := in.PreviousOutPoint
		if err := wire.WriteOutPoint(&prevouts, 0, 0, &op); err != nil {
			return nil, err
		}
		err := binary.Write(&sequences, binary.LittleEndian, in.Sequence)
		if err != nil {
			return nil, err
		}
	}
	var extra bytes.Buffer
	for _, out := range tx.TxOut[fixedOutputs:] {
		if err := wire.WriteTxOut(&extra, 0, 0, out); err != nil {
			return nil, err
		}
	}
	fee := prevOuts[tx.TxIn[1].PreviousOutPoint]
	var spk1 bytes.Buffer
	if err := wire.WriteVarBytes(&spk1, 0, fee.PkScript); err != nil {
		return nil, err
	}
	var version, lockTime, amount [8]byte
	binary.LittleEndian.PutUint32(version[:4], uint32(tx.Version))
	binary.LittleEndian.PutUint32(lockTime[:4], tx.LockTime)
	binary.LittleEndian.PutUint64(amount[:], uint64(fee.Value))
	return [][]byte{
		e31,
		chainhash.HashB(sequences.Bytes()),
		leafHash[:],
		chainhash.HashB(prevouts.Bytes()),
		version[:4],
		lockTime[:4],
		spk1.Bytes(),
		amount[:],
		extra.Bytes(),
	}, nil
}

// minGrind varies input 1's nSequence until the BIP-340 challenge
// e = H_challenge(x(G) || x(G) || sighash) ends in a zero byte and returns
// its first 31 bytes, leaving tx with the sequence that produced them.
func minGrind(tx *wire.MsgTx, prevOuts map[wire.OutPoint]*wire.TxOut,
	leafHash [32]byte) ([]byte, error) {

	for i := uint32(0); i < minGrindTries; i++ {
		tx.TxIn[1].Sequence = minFirstSequence - i
		sighash, err := Sighash(tx, 0, prevOuts, leafHash)
		if err != nil {
			return nil, err
		}
		e := chainhash.TaggedHash(
			[]byte("BIP0340/challenge"), script.MinGX, script.MinGX, sighash,
		)
		if e[31] == 0 {
			return e[:31], nil
		}
	}
	return nil, errors.New("txn: MIN grind exhausted")
}
