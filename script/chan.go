package script

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/roasbeef/layertree/tree"
)

// Channel-leaf scripts of spec/channel-leaves.md (Appendix C), ported from
// tools/layertree_chan.py and checked byte for byte against the "chan"
// entries of spec/golden.json. The scripts use only OP_TX,
// OP_CHECKSIGFROMSTACK, OP_CHECKLOCKTIMEVERIFY, OP_CHECKSEQUENCEVERIFY,
// OP_CAT, OP_SHA256 and BIP-342 stack opcodes, so the same token lists serve
// the FULL (0xC2) and MID (0xC0) tiers (C.7).

// OP_CHECKSEQUENCEVERIFY is BIP-112's opcode, used by SETTLE_n.
const OP_CHECKSEQUENCEVERIFY = txscript.OP_CHECKSEQUENCEVERIFY

// OP_TX selector bits used by the channel selectors (C.2.1).
const (
	txCollate        = 0x1
	txVersion        = 0x2
	txNumInputs      = 0x4
	txInputSequence  = 0x40
	txNumOutputs     = 0x80
	txOutputAmount   = 0x100
	txOutputScript   = 0x200
	txLocktime       = 0x400
	txInputCurrent   = 0x800
	txInputAmount    = 0x10000
	txInputScriptPub = 0x20000
)

// Channel constants (C.2.1, C.2.2, C.3.3, C.3.5).
const (
	// SelChanUpd is the update selector: the ANYPREVOUTANYSCRIPT
	// analogue.
	SelChanUpd = txCollate | txVersion | txNumInputs | txInputSequence |
		txNumOutputs | txOutputAmount | txOutputScript | txLocktime |
		txInputCurrent

	// SelChanSet is the settlement selector: SelChanUpd plus the spent
	// amount and scriptPubKey, the ANYPREVOUT analogue.
	SelChanSet = SelChanUpd | txInputAmount | txInputScriptPub

	// TagChanID, TagChanUpd and TagChanSet are the C.2.2 tags.
	TagChanID  = "LayerTree/chan/id"
	TagChanUpd = "LayerTree/chan/update"
	TagChanSet = "LayerTree/chan/settle"

	// ChanStateBase is S: state n is nLockTime S + n, in the timestamp
	// range (C.3.5).
	ChanStateBase = 500_000_000

	// ChanMaxState is the largest n whose REBIND_n operand S + n + 1
	// still fits in four bytes.
	ChanMaxState = 1<<32 - 1 - ChanStateBase - 1

	// ChanTxVersion is the TRUC version of update and settlement
	// transactions.
	ChanTxVersion = 3

	// ChanUpdateSequence is the update transaction's nSequence.
	ChanUpdateSequence = 0xfffffffd
)

// P2ASpk is the pay-to-anchor output script OP_1 <0x4e73>.
var P2ASpk = []byte{0x51, 0x02, 0x4e, 0x73}

// ChanParams are the inputs of chan_id (C.2.2).
type ChanParams struct {
	// TreeID is m, the tree's taptree merkle root.
	TreeID [32]byte

	// OwnerKey and Nonce identify the leaf within the tree (5.2).
	OwnerKey [32]byte
	Nonce    uint32

	// PChan is the x-only MuSig2 aggregate of the two channel keys.
	PChan [32]byte

	// Capacity is C, the leaf amount.
	Capacity uint64

	// Epoch is incremented by every splice (C.5.2).
	Epoch uint32

	// CsvDelay is the dispute window of SETTLE_n in blocks.
	CsvDelay uint32
}

// ChanID is H_chanid(m || owner_key || le32(nonce) || x(P_chan) || le64(C)
// || le32(epoch) || le32(csv_delay)).
func (p *ChanParams) ChanID() [32]byte {
	return tree.TaggedHash(TagChanID, p.TreeID[:], p.OwnerKey[:],
		tree.Le32(p.Nonce), p.PChan[:], tree.Le64(p.Capacity),
		tree.Le32(p.Epoch), tree.Le32(p.CsvDelay))
}

// CtxUpd is ctx_upd = H_chanupd(chan_id).
func (p *ChanParams) CtxUpd() [32]byte {
	id := p.ChanID()
	return tree.TaggedHash(TagChanUpd, id[:])
}

// CtxSet is ctx_set = H_chanset(chan_id).
func (p *ChanParams) CtxSet() [32]byte {
	id := p.ChanID()
	return tree.TaggedHash(TagChanSet, id[:])
}

// chanSigTail is <ctx> OP_SWAP OP_CAT OP_SHA256 <P_chan>
// OP_CHECKSIGFROMSTACK. Stack in: sig blob. Stack out: 1.
func chanSigTail(ctx, pChan [32]byte) []Token {
	return []Token{
		Data(ctx[:]), Op(txscript.OP_SWAP), Op(OP_CAT),
		Op(txscript.OP_SHA256),                   // sig msg
		Data(pChan[:]), Op(OP_CHECKSIGFROMSTACK), // 1
	}
}

// ChanRebindScript is REBIND_n (C.3.3), a leaf of the update output U_n.
// Witness: <upd_sig_m> with m > n.
func ChanRebindScript(n uint32, ctxUpd, pChan [32]byte) []Token {
	if n > ChanMaxState {
		panic("script: channel state out of range")
	}
	s := []Token{
		Num(int64(ChanStateBase) + int64(n) + 1),
		Op(txscript.OP_CHECKLOCKTIMEVERIFY), Op(txscript.OP_DROP), // sig
		Num(SelChanUpd), Op(OP_TX), // sig blob
	}
	return append(s, chanSigTail(ctxUpd, pChan)...)
}

// ChanUpdFScript is UPD_F (C.3.2), the funding taptree's single leaf: it is
// REBIND_0, so any state n >= 1 binds to the funding output.
func ChanUpdFScript(ctxUpd, pChan [32]byte) []Token {
	return ChanRebindScript(0, ctxUpd, pChan)
}

// ChanSettleScript is SETTLE_n (C.3.3), the other leaf of U_n. Witness:
// <set_sig_n>. It does not name n: SelChanSet commits the spent
// scriptPubKey, which embeds n through REBIND_n.
func ChanSettleScript(csvDelay uint32, ctxSet, pChan [32]byte) []Token {
	if csvDelay == 0 || csvDelay >= 1<<16 {
		panic("script: csv_delay out of range")
	}
	s := []Token{
		Num(int64(csvDelay)),
		Op(OP_CHECKSEQUENCEVERIFY), Op(txscript.OP_DROP), // sig
		Num(SelChanSet), Op(OP_TX), // sig blob
	}
	return append(s, chanSigTail(ctxSet, pChan)...)
}

// HtlcSuccessScript is HTLC_SUCCESS (C.4.1). Witness: <claim_sig>
// <preimage>.
func HtlcSuccessScript(paymentHash, claimKey [32]byte) []Token {
	return []Token{
		Op(txscript.OP_SIZE), Num(32), Op(txscript.OP_EQUALVERIFY),
		Op(txscript.OP_SHA256), Data(paymentHash[:]),
		Op(txscript.OP_EQUALVERIFY),
		Data(claimKey[:]), Op(txscript.OP_CHECKSIG),
	}
}

// HtlcTimeoutScript is HTLC_TIMEOUT (C.4.1). Witness: <claim_sig>.
func HtlcTimeoutScript(cltvExpiry uint32, claimKey [32]byte) []Token {
	return []Token{
		Num(int64(cltvExpiry)), Op(txscript.OP_CHECKLOCKTIMEVERIFY),
		Op(txscript.OP_DROP),
		Data(claimKey[:]), Op(txscript.OP_CHECKSIG),
	}
}

// TapOutputKey returns the x-only BIP-341 output key for an internal key
// and a list of scripts, committed with TapTreeRoot under the mode's leaf
// version.
func TapOutputKey(internal [32]byte, scripts [][]Token,
	mode Mode) ([32]byte, error) {

	var out [32]byte
	pub, err := schnorr.ParsePubKey(internal[:])
	if err != nil {
		return out, err
	}
	leaves := make([][32]byte, len(scripts))
	for i, s := range scripts {
		b, err := Assemble(s, mode)
		if err != nil {
			return out, err
		}
		leaves[i] = TapLeafHash(b, mode.LeafVersion())
	}
	root := TapTreeRoot(leaves)
	q := txscript.ComputeTaprootOutputKey(pub, root[:])
	copy(out[:], schnorr.SerializePubKey(q))

	return out, nil
}

// ChanExitKey is the leaf's exit_key: P_chan tweaked by the funding taptree
// [UPD_F] (C.3.2).
func (p *ChanParams) ChanExitKey(mode Mode) ([32]byte, error) {
	return TapOutputKey(p.PChan, [][]Token{
		ChanUpdFScript(p.CtxUpd(), p.PChan),
	}, mode)
}

// ChanUpdateOutputKey is the output key of U_n: P_chan tweaked by
// [REBIND_n, SETTLE_n] (C.3.3).
func (p *ChanParams) ChanUpdateOutputKey(n uint32,
	mode Mode) ([32]byte, error) {

	return TapOutputKey(p.PChan, [][]Token{
		ChanRebindScript(n, p.CtxUpd(), p.PChan),
		ChanSettleScript(p.CsvDelay, p.CtxSet(), p.PChan),
	}, mode)
}

// ChanCollate is OP_TX(sel) with TXSELECT_COLLATE for input idx of tx,
// whose spent output is prevOut, in the layout of C.2.1 [C-A1]. It is the
// off-chain signer's serialiser for the channel messages and supports the
// fields the two channel selectors select.
func ChanCollate(sel uint32, tx *wire.MsgTx, idx int,
	prevOut *wire.TxOut) ([]byte, error) {

	known := uint32(SelChanSet)
	if sel&^known != 0 || sel&txCollate == 0 || sel&txInputCurrent == 0 {
		return nil, fmt.Errorf("script: selector %#x not supported", sel)
	}
	if idx < 0 || idx >= len(tx.TxIn) {
		return nil, fmt.Errorf("script: input %d out of range", idx)
	}

	var b []byte
	le32 := func(v uint32) {
		b = binary.LittleEndian.AppendUint32(b, v)
	}
	le64 := func(v uint64) {
		b = binary.LittleEndian.AppendUint64(b, v)
	}
	if sel&txVersion != 0 {
		le32(uint32(tx.Version))
	}
	if sel&txNumInputs != 0 {
		b = append(b, compactSize(len(tx.TxIn))...)
	}
	if sel&txInputSequence != 0 {
		le32(tx.TxIn[idx].Sequence)
	}
	if sel&(txInputAmount|txInputScriptPub) != 0 && prevOut == nil {
		return nil, fmt.Errorf("script: selector needs the spent output")
	}
	if sel&txInputAmount != 0 {
		le64(uint64(prevOut.Value))
	}
	if sel&txInputScriptPub != 0 {
		b = append(b, compactSize(len(prevOut.PkScript))...)
		b = append(b, prevOut.PkScript...)
	}
	if sel&txNumOutputs != 0 {
		b = append(b, compactSize(len(tx.TxOut))...)
	}
	for _, o := range tx.TxOut {
		if sel&txOutputAmount != 0 {
			le64(uint64(o.Value))
		}
		if sel&txOutputScript != 0 {
			b = append(b, compactSize(len(o.PkScript))...)
			b = append(b, o.PkScript...)
		}
	}
	if sel&txLocktime != 0 {
		le32(tx.LockTime)
	}

	return b, nil
}

// ChanUpdMsg is msg_upd = SHA256(ctx_upd || OP_TX(SEL_CHAN_UPD)) for an
// update transaction's single input (C.2.2).
func ChanUpdMsg(ctxUpd [32]byte, tx *wire.MsgTx) ([32]byte, error) {
	blob, err := ChanCollate(SelChanUpd, tx, 0, nil)
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(append(ctxUpd[:], blob...)), nil
}

// ChanSetMsg is msg_set = SHA256(ctx_set || OP_TX(SEL_CHAN_SET)) for a
// settlement transaction spending prevOut (C.2.2).
func ChanSetMsg(ctxSet [32]byte, tx *wire.MsgTx,
	prevOut *wire.TxOut) ([32]byte, error) {

	blob, err := ChanCollate(SelChanSet, tx, 0, prevOut)
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(append(ctxSet[:], blob...)), nil
}
