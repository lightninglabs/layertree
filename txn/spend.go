package txn

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

// SigSlot is a position in a witness stack that holds a BIP-340 signature
// over the spending transaction (SIGHASH_DEFAULT, input 0, the revealed
// leaf) by Key. Signatures that commit to no transaction, such as a CLAIM
// voucher, are inputs to the builders and never slots.
type SigSlot struct {
	// Index is the stack index, bottom of the stack first.
	Index int

	// Key is the x-only key the script checks the signature against.
	Key [32]byte

	// Role names the signer for error messages ("owner", "operator").
	Role string
}

// Spend is a transition transaction as a builder returns it: the unsigned
// transaction, the previous outputs the signature hash needs, the revealed
// leaf with its control block, and the witness stack in bottom-to-top order
// with an empty element in every signature slot. Sign fills the slots and
// attaches the witness to input 0.
type Spend struct {
	Tx           *wire.MsgTx
	PrevOuts     map[wire.OutPoint]*wire.TxOut
	Leaf         TapLeaf
	ControlBlock []byte
	Stack        [][]byte
	Sigs         []SigSlot
}

// TapleafHash is the tapleaf hash of the revealed script.
func (s *Spend) TapleafHash() [32]byte {
	return s.Leaf.Hash()
}

// Sighash is the BIP-341 signature hash every slot signs.
func (s *Spend) Sighash() ([]byte, error) {
	return Sighash(s.Tx, 0, s.PrevOuts, s.TapleafHash())
}

// Sign is the signing helper shared by every transition: it signs the
// transaction once per slot with the private key whose x-only public key is
// the slot's key, writes the signatures into the stack, and attaches the
// script-path witness (stack, script, control block) to input 0. Keys that
// match no slot are ignored, so a caller may pass every key it holds.
func (s *Spend) Sign(keys ...*btcec.PrivateKey) error {
	sighash, err := s.Sighash()
	if err != nil {
		return err
	}
	byKey := make(map[[32]byte]*btcec.PrivateKey, len(keys))
	for _, k := range keys {
		var x [32]byte
		copy(x[:], schnorr.SerializePubKey(k.PubKey()))
		byKey[x] = k
	}
	for _, slot := range s.Sigs {
		priv, ok := byKey[slot.Key]
		if !ok {
			return fmt.Errorf("txn: no private key for the %s "+
				"signature (key %x)", slot.Role, slot.Key[:])
		}
		sig, err := SignSchnorr(priv, sighash)
		if err != nil {
			return err
		}
		s.Stack[slot.Index] = sig
	}
	return TapscriptSpend(
		s.Tx, 0, s.PrevOuts, s.Leaf.Script, s.Leaf.Version,
		s.ControlBlock, s.Stack,
	)
}

// Verify checks a signed spend as far as Go can without an interpreter for
// the proposed opcodes: the txscript and the hand-built BIP-341 signature
// hashes agree, every signature slot verifies under its key, the control
// block opens input 0's output key for the revealed leaf, and the witness on
// input 0 is exactly stack || script || control block. The covenant rules
// themselves are executed by the Python simulator (tools/script_sim.py).
func (s *Spend) Verify() error {
	leafHash := s.TapleafHash()
	sighash, err := Sighash(s.Tx, 0, s.PrevOuts, leafHash)
	if err != nil {
		return err
	}
	manual, err := SighashManual(s.Tx, 0, s.PrevOuts, leafHash)
	if err != nil {
		return err
	}
	if !bytes.Equal(sighash, manual) {
		return errors.New("txn: txscript and manual sighash disagree")
	}
	for _, slot := range s.Sigs {
		sig, err := schnorr.ParseSignature(s.Stack[slot.Index])
		if err != nil {
			return fmt.Errorf("txn: %s signature: %w", slot.Role, err)
		}
		pub, err := schnorr.ParsePubKey(slot.Key[:])
		if err != nil {
			return fmt.Errorf("txn: %s key: %w", slot.Role, err)
		}
		if !sig.Verify(sighash, pub) {
			return fmt.Errorf("txn: %s signature does not verify",
				slot.Role)
		}
	}

	cb, err := txscript.ParseControlBlock(s.ControlBlock)
	if err != nil {
		return fmt.Errorf("txn: control block: %w", err)
	}
	prevOut := s.PrevOuts[s.Tx.TxIn[0].PreviousOutPoint]
	if prevOut == nil || len(prevOut.PkScript) != 34 {
		return errors.New("txn: input 0 does not spend a taproot output")
	}
	err = txscript.VerifyTaprootLeafCommitment(
		cb, prevOut.PkScript[2:], s.Leaf.Script,
	)
	if err != nil {
		return fmt.Errorf("txn: control block: %w", err)
	}

	wit := s.Tx.TxIn[0].Witness
	if len(wit) != len(s.Stack)+2 {
		return fmt.Errorf("txn: witness has %d elements, want %d",
			len(wit), len(s.Stack)+2)
	}
	for i := range s.Stack {
		if !bytes.Equal(wit[i], s.Stack[i]) {
			return fmt.Errorf("txn: witness element %d differs "+
				"from the stack", i)
		}
	}
	if !bytes.Equal(wit[len(s.Stack)], s.Leaf.Script) ||
		!bytes.Equal(wit[len(s.Stack)+1], s.ControlBlock) {

		return errors.New("txn: witness does not end in script and " +
			"control block")
	}
	return nil
}
