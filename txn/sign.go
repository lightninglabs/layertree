package txn

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

// blankCodeSep is the code separator position written into the signature
// message when no OP_CODESEPARATOR was executed (BIP-341).
const blankCodeSep uint32 = math.MaxUint32

// Sighash returns the BIP-341 signature hash for a script-path spend of
// tx's input inputIndex with SIGHASH_DEFAULT: ext_flag = 1 (spend type
// 0x02), no annex, key version 0 and code separator position 0xffffffff.
//
// The leaf is identified by its tapleaf hash rather than by its script, so
// that the caller is free to use any tapleaf version -- LayerTree's scripts
// live in 0xC2 leaves (spec 6.2). txscript hashes the leaf version byte as
// given and never inspects it, so the 0xC2 leaves are handled exactly like
// 0xC0 ones; the option passed here simply supplies the already computed
// leaf hash.
func Sighash(tx *wire.MsgTx, inputIndex int,
	prevOuts map[wire.OutPoint]*wire.TxOut, tapleafHash [32]byte) ([]byte,
	error) {

	fetcher := txscript.NewMultiPrevOutFetcher(prevOuts)
	if err := checkPrevOuts(tx, prevOuts); err != nil {
		return nil, err
	}
	sigHashes := txscript.NewTxSigHashes(tx, fetcher)

	// CalcTapscriptSignaturehash derives the leaf hash from the TapLeaf it
	// is given; the trailing option overrides it with the hash we were
	// handed, keeping the rest of the tapscript configuration (ext_flag 1,
	// key version 0, blank code separator).
	return txscript.CalcTapscriptSignaturehash(
		sigHashes, txscript.SigHashDefault, tx, inputIndex, fetcher,
		txscript.NewTapLeaf(txscript.BaseLeafVersion, nil),
		txscript.WithBaseTapscriptVersion(blankCodeSep, tapleafHash[:]),
	)
}

// SighashMsg builds the BIP-341 signature message for the same spend, byte
// for byte as the Python simulator does (tools/script_sim.py,
// TxContext.sighash_msg):
//
//	0x00              epoch
//	0x00              hash type (SIGHASH_DEFAULT)
//	nVersion          LE4
//	nLockTime         LE4
//	sha_prevouts      sha256 of all outpoints
//	sha_amounts       sha256 of all spent amounts
//	sha_scriptpubkeys sha256 of all spent scriptPubKeys
//	sha_sequences     sha256 of all nSequences
//	sha_outputs       sha256 of all outputs
//	0x02              spend type (ext_flag 1, no annex)
//	input_index       LE4
//	tapleaf_hash
//	0x00              key version
//	0xffffffff        code separator position
func SighashMsg(tx *wire.MsgTx, inputIndex int,
	prevOuts map[wire.OutPoint]*wire.TxOut, tapleafHash [32]byte) ([]byte,
	error) {

	if inputIndex < 0 || inputIndex >= len(tx.TxIn) {
		return nil, fmt.Errorf("txn: input index %d out of range (%d "+
			"inputs)", inputIndex, len(tx.TxIn))
	}
	if err := checkPrevOuts(tx, prevOuts); err != nil {
		return nil, err
	}

	var prevouts, amounts, scripts, sequences, outputs bytes.Buffer
	for _, in := range tx.TxIn {
		op := in.PreviousOutPoint
		if err := wire.WriteOutPoint(&prevouts, 0, 0, &op); err != nil {
			return nil, err
		}
		prevOut := prevOuts[op]
		if err := binary.Write(&amounts, binary.LittleEndian, prevOut.Value); err != nil {
			return nil, err
		}
		err := wire.WriteVarBytes(&scripts, 0, prevOut.PkScript)
		if err != nil {
			return nil, err
		}
		err = binary.Write(&sequences, binary.LittleEndian, in.Sequence)
		if err != nil {
			return nil, err
		}
	}
	for _, out := range tx.TxOut {
		if err := wire.WriteTxOut(&outputs, 0, 0, out); err != nil {
			return nil, err
		}
	}

	var msg bytes.Buffer
	msg.WriteByte(0x00) // epoch
	msg.WriteByte(byte(txscript.SigHashDefault))
	if err := binary.Write(&msg, binary.LittleEndian, tx.Version); err != nil {
		return nil, err
	}
	if err := binary.Write(&msg, binary.LittleEndian, tx.LockTime); err != nil {
		return nil, err
	}
	for _, b := range []*bytes.Buffer{
		&prevouts, &amounts, &scripts, &sequences, &outputs,
	} {
		h := chainhash.HashB(b.Bytes())
		msg.Write(h)
	}
	msg.WriteByte(0x02) // spend type: ext_flag 1, annex absent
	err := binary.Write(&msg, binary.LittleEndian, uint32(inputIndex))
	if err != nil {
		return nil, err
	}
	msg.Write(tapleafHash[:])
	msg.WriteByte(0x00) // key version
	if err := binary.Write(&msg, binary.LittleEndian, blankCodeSep); err != nil {
		return nil, err
	}
	return msg.Bytes(), nil
}

// SighashManual is TaggedHash("TapSighash", SighashMsg(...)): the same digest
// as Sighash, computed without txscript. It exists so the two can be checked
// against each other and against the Python golden vector.
func SighashManual(tx *wire.MsgTx, inputIndex int,
	prevOuts map[wire.OutPoint]*wire.TxOut, tapleafHash [32]byte) ([]byte,
	error) {

	msg, err := SighashMsg(tx, inputIndex, prevOuts, tapleafHash)
	if err != nil {
		return nil, err
	}
	h := chainhash.TaggedHash(chainhash.TagTapSighash, msg)
	return h[:], nil
}

// SighashScript is Sighash for a caller that has the revealed script rather
// than its tapleaf hash.
func SighashScript(tx *wire.MsgTx, inputIndex int,
	prevOuts map[wire.OutPoint]*wire.TxOut, script []byte,
	leafVersion byte) ([]byte, error) {

	return Sighash(tx, inputIndex, prevOuts, TapleafHash(script, leafVersion))
}

// checkPrevOuts reports whether every input has a previous output.
func checkPrevOuts(tx *wire.MsgTx, prevOuts map[wire.OutPoint]*wire.TxOut) error {
	for i, in := range tx.TxIn {
		if prevOuts[in.PreviousOutPoint] == nil {
			return fmt.Errorf("txn: no prevout for input %d (%v)",
				i, in.PreviousOutPoint)
		}
	}
	return nil
}

// SignSchnorr produces the 64-byte BIP-340 signature over sighash. With
// SIGHASH_DEFAULT no hash type byte is appended, so the witness element is
// exactly 64 bytes.
func SignSchnorr(privKey *btcec.PrivateKey, sighash []byte) ([]byte, error) {
	if len(sighash) != 32 {
		return nil, fmt.Errorf("txn: sighash must be 32 bytes, got %d",
			len(sighash))
	}
	sig, err := schnorr.Sign(privKey, sighash)
	if err != nil {
		return nil, err
	}
	return sig.Serialize(), nil
}

// SignTapscript signs input inputIndex of tx for the given tapleaf.
func SignTapscript(privKey *btcec.PrivateKey, tx *wire.MsgTx, inputIndex int,
	prevOuts map[wire.OutPoint]*wire.TxOut, tapleafHash [32]byte) ([]byte,
	error) {

	sighash, err := Sighash(tx, inputIndex, prevOuts, tapleafHash)
	if err != nil {
		return nil, err
	}
	return SignSchnorr(privKey, sighash)
}
