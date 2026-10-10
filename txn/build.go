package txn

import (
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"

	"github.com/roasbeef/layertree/tree"
)

// TreeSequence is the nSequence of the tree input. It is below 0xffffffff so
// that nLockTime is enforced, which the eviction branches need
// (OP_CHECKLOCKTIMEVERIFY, spec 7.2), and it opts into RBF.
const TreeSequence uint32 = 0xfffffffd

// DefaultTxVersion is the version LayerTree transition transactions use.
const DefaultTxVersion int32 = 2

// TreeInput identifies the tree output being spent: its outpoint, its amount
// (which equals the sum of the root it commits to, spec 6.3) and the state it
// is in.
type TreeInput struct {
	OutPoint   wire.OutPoint
	Amount     int64
	RootHash   [32]byte
	MerkleRoot [32]byte
}

// TxOut returns the previous output of the tree input, i.e. TREE_SPK(r, m)
// with the input's amount.
func (t *TreeInput) TxOut() (*wire.TxOut, error) {
	spk, err := tree.ScriptPubKey(t.RootHash, t.MerkleRoot)
	if err != nil {
		return nil, err
	}
	return wire.NewTxOut(t.Amount, spk), nil
}

// ExtraInput is an input other than the tree output: a fee input, or the
// funding of a JOIN or UPDATE top-up. Inputs 1.. are unconstrained by the
// transition scripts (spec 7.1 rule 7), but their previous outputs are still
// needed for the BIP-341 signature hash.
type ExtraInput struct {
	OutPoint wire.OutPoint
	Sequence uint32
	PrevOut  *wire.TxOut
}

// Payout is one of the payout outputs 1..K required by a transition
// (spec 7.1 rule 6): P2TR(exit_key) with the required amount.
type Payout struct {
	ExitKey [32]byte
	Amount  int64
}

// TxOut renders the payout as a transaction output.
func (p *Payout) TxOut() *wire.TxOut {
	return wire.NewTxOut(p.Amount, tree.P2TR(p.ExitKey))
}

// Builder assembles a LayerTree transition transaction (spec 7.1):
//
//	input 0       the tree output, nSequence = TreeSequence
//	inputs 1..    fee and funding inputs, unconstrained
//	output 0      the recreated tree output, TREE_SPK(r', m)
//	outputs 1..K  the payouts the transition type requires
//	outputs K+1.. change and anything else, unconstrained
//
// The taptree root m is carried over from the input: a transition may not
// change the rules of the tree (spec 6.4, 10.4).
type Builder struct {
	// Version is the transaction version; 0 means DefaultTxVersion.
	Version int32

	// LockTime is nLockTime, which the eviction branches check against
	// the leaf's evict_after.
	LockTime uint32

	// Tree is the tree output being spent by input 0.
	Tree TreeInput

	// NewRoot is r', the root hash after the transition.
	NewRoot [32]byte

	// NewAmount is the amount of output 0, which must equal the sum of
	// r' (spec 7.1 rule 5).
	NewAmount int64

	// Payouts are outputs 1..K.
	Payouts []Payout

	// ExtraInputs are inputs 1...
	ExtraInputs []ExtraInput

	// ExtraOutputs are outputs K+1...
	ExtraOutputs []*wire.TxOut

	// Terminal, when non-nil, is output 0 in place of the recreated tree
	// output. It is only valid for a transition whose new root is E_D
	// (spec 7.8): the scripts then leave output 0 unconstrained, but it
	// must still exist so that the payouts are numbered from 1. NewRoot
	// and NewAmount are ignored.
	Terminal *wire.TxOut
}

// AddExtraInput appends a fee or funding input.
func (b *Builder) AddExtraInput(op wire.OutPoint, sequence uint32, prevOut *wire.TxOut) {
	b.ExtraInputs = append(b.ExtraInputs, ExtraInput{
		OutPoint: op, Sequence: sequence, PrevOut: prevOut,
	})
}

// AddPayout appends a payout output.
func (b *Builder) AddPayout(exitKey [32]byte, amount int64) {
	b.Payouts = append(b.Payouts, Payout{ExitKey: exitKey, Amount: amount})
}

// AddExtraOutput appends an unconstrained output.
func (b *Builder) AddExtraOutput(out *wire.TxOut) {
	b.ExtraOutputs = append(b.ExtraOutputs, out)
}

// version returns the effective transaction version.
func (b *Builder) version() int32 {
	if b.Version == 0 {
		return DefaultTxVersion
	}
	return b.Version
}

// NewTreeOut returns output 0: TREE_SPK(r', m) with the new total.
func (b *Builder) NewTreeOut() (*wire.TxOut, error) {
	spk, err := tree.ScriptPubKey(b.NewRoot, b.Tree.MerkleRoot)
	if err != nil {
		return nil, err
	}
	return wire.NewTxOut(b.NewAmount, spk), nil
}

// Tx assembles the unsigned transaction. Witnesses are attached afterwards
// with TapscriptSpend.
func (b *Builder) Tx() (*wire.MsgTx, error) {
	if b.Terminal == nil && b.NewAmount < 0 {
		return nil, errors.New("txn: negative tree output amount")
	}
	tx := wire.NewMsgTx(b.version())
	tx.LockTime = b.LockTime

	// Input 0 is always the tree output (spec 7.1 rule 1).
	tx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: b.Tree.OutPoint,
		Sequence:         TreeSequence,
	})
	for _, in := range b.ExtraInputs {
		tx.AddTxIn(&wire.TxIn{
			PreviousOutPoint: in.OutPoint,
			Sequence:         in.Sequence,
		})
	}

	// Output 0 recreates the tree (rule 2), or is the caller's output
	// after a terminal transition (spec 7.8); outputs 1..K pay out
	// (rule 6).
	treeOut := b.Terminal
	if treeOut == nil {
		var err error
		treeOut, err = b.NewTreeOut()
		if err != nil {
			return nil, err
		}
	}
	tx.AddTxOut(treeOut)
	for i := range b.Payouts {
		tx.AddTxOut(b.Payouts[i].TxOut())
	}
	for _, out := range b.ExtraOutputs {
		tx.AddTxOut(out)
	}
	return tx, nil
}

// PrevOuts returns the previous output of every input, as the BIP-341
// signature hash requires.
func (b *Builder) PrevOuts() (map[wire.OutPoint]*wire.TxOut, error) {
	treeOut, err := b.Tree.TxOut()
	if err != nil {
		return nil, err
	}
	prevOuts := map[wire.OutPoint]*wire.TxOut{b.Tree.OutPoint: treeOut}
	for _, in := range b.ExtraInputs {
		if in.PrevOut == nil {
			return nil, fmt.Errorf("txn: input %v has no prevout",
				in.OutPoint)
		}
		prevOuts[in.OutPoint] = in.PrevOut
	}
	return prevOuts, nil
}

// TapleafHash is the BIP-341 tapleaf hash
// TaggedHash("TapLeaf", version || compact_size(len(script)) || script). Any
// leaf version is accepted, including the 0xC2 version LayerTree uses
// (spec 6.2): the version byte is hashed as given.
func TapleafHash(script []byte, version byte) [32]byte {
	leaf := txscript.NewTapLeaf(
		txscript.TapscriptLeafVersion(version), script,
	)
	return [32]byte(leaf.TapHash())
}

// ControlBlock returns the BIP-341 control block for a script-path spend:
// (leafVersion | y-parity of the output key) || x(internalKey) ||
// inclusion proof.
func ControlBlock(internalKey, outputKey *btcec.PublicKey, leafVersion byte,
	inclusionProof []byte) ([]byte, error) {

	if internalKey == nil || outputKey == nil {
		return nil, errors.New("txn: nil key")
	}
	if len(inclusionProof)%chainhash.HashSize != 0 {
		return nil, fmt.Errorf("txn: inclusion proof of %d bytes is "+
			"not a whole number of nodes", len(inclusionProof))
	}
	cb := txscript.ControlBlock{
		InternalKey:     internalKey,
		OutputKeyYIsOdd: outputKey.SerializeCompressed()[0] == secpOddPrefix,
		LeafVersion:     txscript.TapscriptLeafVersion(leafVersion),
		InclusionProof:  inclusionProof,
	}
	return cb.ToBytes()
}

// secpOddPrefix is the compressed-key prefix for an odd y coordinate.
const secpOddPrefix = 0x03

// TreeControlBlock returns the control block that reveals a transition script
// of the tree in state rootHash: the internal key is the state key x(P) of
// spec 6.1 and the output key is the one committed to in TREE_SPK(r, m).
func TreeControlBlock(rootHash, merkleRoot [32]byte, leafVersion byte,
	inclusionProof []byte) ([]byte, error) {

	internalKey, err := tree.InternalKey(rootHash)
	if err != nil {
		return nil, err
	}
	// BIP-341 commits to the even-y lift of the internal key's x
	// coordinate, which is what the control block carries.
	internalKey, err = schnorr.ParsePubKey(schnorr.SerializePubKey(internalKey))
	if err != nil {
		return nil, err
	}
	outputKey, err := tree.OutputKey(rootHash, merkleRoot)
	if err != nil {
		return nil, err
	}
	return ControlBlock(internalKey, outputKey, leafVersion, inclusionProof)
}

// TapscriptSpend attaches a script-path witness to an input: the script's
// stack elements in bottom-to-top order, then the revealed script, then the
// control block (BIP-341). prevOuts is used to sanity check that the input
// really spends a v1 witness program whose key the control block opens.
func TapscriptSpend(tx *wire.MsgTx, inputIndex int,
	prevOuts map[wire.OutPoint]*wire.TxOut, script []byte,
	leafVersion byte, controlBlock []byte, stack [][]byte) error {

	if inputIndex < 0 || inputIndex >= len(tx.TxIn) {
		return fmt.Errorf("txn: input index %d out of range (%d inputs)",
			inputIndex, len(tx.TxIn))
	}
	if len(controlBlock) < txscript.ControlBlockBaseSize {
		return fmt.Errorf("txn: control block of %d bytes is too short",
			len(controlBlock))
	}
	if got := controlBlock[0] & txscript.TaprootLeafMask; got != leafVersion&txscript.TaprootLeafMask {
		return fmt.Errorf("txn: control block leaf version 0x%02x does "+
			"not match script leaf version 0x%02x", got, leafVersion)
	}
	txIn := tx.TxIn[inputIndex]
	if prevOut, ok := prevOuts[txIn.PreviousOutPoint]; ok {
		cb, err := txscript.ParseControlBlock(controlBlock)
		if err != nil {
			return fmt.Errorf("txn: control block: %w", err)
		}
		if len(prevOut.PkScript) != 34 || prevOut.PkScript[0] != txscript.OP_1 {
			return fmt.Errorf("txn: input %d does not spend a "+
				"taproot output", inputIndex)
		}
		err = txscript.VerifyTaprootLeafCommitment(
			cb, prevOut.PkScript[2:], script,
		)
		if err != nil {
			return fmt.Errorf("txn: control block does not open "+
				"the input's output key: %w", err)
		}
	}

	witness := make(wire.TxWitness, 0, len(stack)+2)
	witness = append(witness, stack...)
	witness = append(witness, script, controlBlock)
	txIn.Witness = witness
	return nil
}
