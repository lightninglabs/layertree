package msg

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"slices"

	"github.com/btcsuite/btcd/wire"
	"github.com/lightningnetwork/lnd/tlv"
	"github.com/roasbeef/layertree/script"
)

// Channel-leaf messages (spec/channel-leaves.md, Appendix C): the channel
// parameters agreed at opening (C.5.1), state proposals and the two signing
// rounds of C.3.6, HTLC add, fulfil and fail (C.4), the rebind announcement
// that tells a counterparty or watchtower where the funding output appeared
// (C.5.4), and the splice proposal (C.5.2). Every message carries chan_id
// (C.2.2) first, so a message can never be applied to another channel or
// another epoch of the same channel.

// TLV types for ChanOpen (C.5.1 step 1).
const (
	TypeChanOpenTreeID     tlv.Type = 0
	TypeChanOpenOwnerKey   tlv.Type = 1
	TypeChanOpenNonce      tlv.Type = 2
	TypeChanOpenPChan      tlv.Type = 3
	TypeChanOpenCapacity   tlv.Type = 4
	TypeChanOpenEpoch      tlv.Type = 5
	TypeChanOpenCsvDelay   tlv.Type = 6
	TypeChanOpenEvictAfter tlv.Type = 7
	TypeChanOpenBalanceU   tlv.Type = 8
	TypeChanOpenBalanceV   tlv.Type = 9
	TypeChanOpenDustChan   tlv.Type = 10
)

// TLV types for the per-channel messages. Type 0 is always chan_id.
const (
	TypeChanID tlv.Type = 0

	TypeStateNum      tlv.Type = 1
	TypeStateBalanceU tlv.Type = 2
	TypeStateBalanceV tlv.Type = 3
	TypeStateHtlcs    tlv.Type = 4

	TypeSigRole       tlv.Type = 2
	TypeSigPartialSig tlv.Type = 3
	TypeSigNextNonce  tlv.Type = 4

	TypeHtlcID          tlv.Type = 1
	TypeHtlcOfferer     tlv.Type = 2
	TypeHtlcAmount      tlv.Type = 3
	TypeHtlcPaymentHash tlv.Type = 4
	TypeHtlcCltvExpiry  tlv.Type = 5
	TypeHtlcPreimage    tlv.Type = 2
	TypeHtlcFailReason  tlv.Type = 2

	TypeRebindOutpoint tlv.Type = 1
	TypeRebindState    tlv.Type = 2
	TypeRebindBoundTx  tlv.Type = 3

	TypeSpliceCapacity tlv.Type = 1
	TypeSpliceEpoch    tlv.Type = 2
	TypeSpliceBalanceU tlv.Type = 3
	TypeSpliceBalanceV tlv.Type = 4
)

// MuSig2 sizes (BIP-327).
const (
	PartialSigLen = 32
	PubNonceLen   = 66
)

// htlcLen is the size of one encoded Htlc inside a StateProposal.
const htlcLen = 8 + 1 + 8 + 32 + 4

// Settlement policy constants (C.3.4, C.7).
const (
	// DustP2TR is the dust threshold of a P2TR output under Bitcoin
	// Core's default dust relay fee, and the RECOMMENDED DUST_CHAN.
	DustP2TR = 330

	// SettleCollationBase and SettleCollationPerOutput give the size of
	// a settlement's SEL_CHAN_SET collation (C.2.1 [C-A1]): 70 bytes for
	// the fixed fields, the spent P2TR output and the P2A anchor, plus 43
	// bytes (le64 amount, a one-byte length and a 34-byte P2TR script)
	// for each balance or HTLC output the settlement carries. C.7's
	// 156 + 43h is this sum with both balance outputs present; a zero
	// balance is an omitted output (C.3.4) and adds nothing.
	SettleCollationBase      = 70
	SettleCollationPerOutput = 43

	// MaxSettleCollationC0 is the largest collation a MID (0xC0)
	// SETTLE_n can verify: 520 bytes less the 32-byte context (C.7).
	MaxSettleCollationC0 = 488
)

// Decoder caps for the channel messages (design/audit/go.md G3). Each
// message is read through decodeLimited at its cap and each
// variable-length record through boundedVarBytes at its own.
const (
	// maxChanFixedLen bounds every channel message whose records are all
	// fixed size: the largest, ChanOpen, is 144 bytes of values and 22
	// of headers. The remainder leaves room for unknown odd records.
	maxChanFixedLen = 512

	// maxStateHtlcs is the most HTLC outputs a settlement can carry and
	// still be standard: settle_n is 204 + 43h vbytes with both balance
	// outputs (C.5.4), 118 + 43h with neither, and a standard
	// transaction is at most 100,000 vbytes (MAX_STANDARD_TX_WEIGHT).
	// Under 0xC0 Validate allows far fewer (C.7).
	maxStateHtlcs = (100_000 - 118) / SettleCollationPerOutput

	// maxStateHtlcsLen caps TypeStateHtlcs.
	maxStateHtlcsLen = htlcLen * maxStateHtlcs

	// maxHtlcFailReasonLen caps TypeHtlcFailReason. The reason is
	// opaque to this layer; 1,024 bytes holds a BOLT-4 failure packet
	// (292 bytes) or a short diagnostic with room to spare.
	maxHtlcFailReasonLen = 1_024

	// outpointLen is the size of TypeRebindOutpoint: a txid and an
	// le32 index.
	outpointLen = 36
)

// encodeStream wraps a record list in a TLV stream.
func encodeStream(w io.Writer, recs []tlv.Record) error {
	s, err := tlv.NewStream(recs...)
	if err != nil {
		return err
	}
	return s.Encode(w)
}

// decodeChan decodes recs from at most max bytes of r and requires every
// record in recs except those listed in optional (design/audit/go.md G7):
// an absent mandatory record would otherwise decode to its zero value. The
// error names the message and the first mandatory record missing.
// Presence is tracked by wrapping each record's decoder rather than with
// tlv.Stream.DecodeWithParsedTypes, which buffers an unknown record at its
// declared length.
func decodeChan(r io.Reader, max int64, name string, recs []tlv.Record,
	optional ...tlv.Type) error {

	seen := make(map[tlv.Type]bool, len(recs))
	wrapped := make([]tlv.Record, len(recs))
	for i := range recs {
		rec := &recs[i]
		typ := rec.Type()
		wrapped[i] = tlv.MakeDynamicRecord(typ, nil, rec.Size,
			func(w io.Writer, _ interface{}, _ *[8]byte) error {
				return rec.Encode(w)
			},
			func(r io.Reader, _ interface{}, _ *[8]byte,
				l uint64) error {

				if err := rec.Decode(r, l); err != nil {
					return err
				}
				seen[typ] = true
				return nil
			},
		)
	}
	if err := decodeLimited(r, max, wrapped); err != nil {
		return err
	}

	for i := range recs {
		typ := recs[i].Type()
		if !seen[typ] && !slices.Contains(optional, typ) {
			return fmt.Errorf("msg: %s is missing mandatory record "+
				"%d", name, typ)
		}
	}
	return nil
}

// ChanOpen carries the parameters both parties agree before the channel
// leaf exists (C.5.1 step 1). Everything chan_id commits is here.
type ChanOpen struct {
	// TreeID is the host tree's tree_id (6.2), the per-lineage constant
	// chan_id binds in place of m (C.2.2); a detached tree inherits it,
	// so every signed state stays valid across DETACH_h.
	TreeID [32]byte

	// OwnerKey and Nonce are the leaf's owner_key and nonce.
	OwnerKey [32]byte
	Nonce    uint32

	// PChan is the x-only MuSig2 aggregate of U_chan and V_chan.
	PChan [32]byte

	// Capacity is C, the leaf amount.
	Capacity uint64

	// Epoch is 0 at opening and incremented by every splice.
	Epoch uint32

	// CsvDelay is the dispute window in blocks.
	CsvDelay uint32

	// EvictAfter is the leaf's evict_after; not in chan_id (C.6.7).
	EvictAfter uint32

	// BalanceU and BalanceV are the opening balances; they sum to
	// Capacity.
	BalanceU, BalanceV uint64

	// DustChan is the settlement dust floor of C.3.4: a balance or HTLC
	// output below it is omitted from settle_n and its value goes to
	// the anchor. Like EvictAfter it is a channel parameter outside
	// chan_id. It is never below DustP2TR.
	DustChan uint64
}

// Params returns the chan_id inputs.
func (c *ChanOpen) Params() *script.ChanParams {
	return &script.ChanParams{
		TreeID: c.TreeID, OwnerKey: c.OwnerKey, Nonce: c.Nonce,
		PChan: c.PChan, Capacity: c.Capacity, Epoch: c.Epoch,
		CsvDelay: c.CsvDelay,
	}
}

// ChanID is the channel's chan_id (C.2.2).
func (c *ChanOpen) ChanID() [32]byte {
	return c.Params().ChanID()
}

// Validate checks the opening balances and the C.3.5 and C.6.4 ranges.
func (c *ChanOpen) Validate() error {
	if c.BalanceU > c.Capacity ||
		c.BalanceV != c.Capacity-c.BalanceU {

		return errors.New("msg: opening balances do not sum to capacity")
	}
	if c.CsvDelay == 0 || c.CsvDelay >= 1<<16 {
		return errors.New("msg: csv_delay out of range")
	}
	if c.EvictAfter >= script.ChanStateBase {
		return errors.New("msg: evict_after must be a height")
	}
	if c.DustChan < DustP2TR {
		return fmt.Errorf("msg: dust_chan %d is below the P2TR dust "+
			"threshold %d (C.3.4)", c.DustChan, DustP2TR)
	}
	return nil
}

func (c *ChanOpen) records() []tlv.Record {
	return []tlv.Record{
		tlv.MakePrimitiveRecord(TypeChanOpenTreeID, &c.TreeID),
		tlv.MakePrimitiveRecord(TypeChanOpenOwnerKey, &c.OwnerKey),
		tlv.MakePrimitiveRecord(TypeChanOpenNonce, &c.Nonce),
		tlv.MakePrimitiveRecord(TypeChanOpenPChan, &c.PChan),
		tlv.MakePrimitiveRecord(TypeChanOpenCapacity, &c.Capacity),
		tlv.MakePrimitiveRecord(TypeChanOpenEpoch, &c.Epoch),
		tlv.MakePrimitiveRecord(TypeChanOpenCsvDelay, &c.CsvDelay),
		tlv.MakePrimitiveRecord(TypeChanOpenEvictAfter, &c.EvictAfter),
		tlv.MakePrimitiveRecord(TypeChanOpenBalanceU, &c.BalanceU),
		tlv.MakePrimitiveRecord(TypeChanOpenBalanceV, &c.BalanceV),
		tlv.MakePrimitiveRecord(TypeChanOpenDustChan, &c.DustChan),
	}
}

// Encode serializes the message as a TLV stream.
func (c *ChanOpen) Encode(w io.Writer) error { return encodeStream(w, c.records()) }

// Decode deserializes a message produced by Encode.
func (c *ChanOpen) Decode(r io.Reader) error {
	return decodeChan(r, maxChanFixedLen, "ChanOpen", c.records())
}

// Offerer says which party offered an HTLC.
type Offerer uint8

const (
	// OfferedByOwner is an HTLC offered by the leaf owner U.
	OfferedByOwner Offerer = 0

	// OfferedByCounterparty is an HTLC offered by the counterparty V.
	OfferedByCounterparty Offerer = 1
)

// Htlc is one in-flight HTLC of a state (C.4.1).
type Htlc struct {
	ID          uint64
	Offerer     Offerer
	Amount      uint64
	PaymentHash [32]byte
	CltvExpiry  uint32
}

func encodeHtlcs(hs []Htlc) []byte {
	b := make([]byte, 0, len(hs)*htlcLen)
	for _, h := range hs {
		b = binary.BigEndian.AppendUint64(b, h.ID)
		b = append(b, byte(h.Offerer))
		b = binary.BigEndian.AppendUint64(b, h.Amount)
		b = append(b, h.PaymentHash[:]...)
		b = binary.BigEndian.AppendUint32(b, h.CltvExpiry)
	}
	return b
}

func decodeHtlcs(b []byte) ([]Htlc, error) {
	if len(b)%htlcLen != 0 {
		return nil, fmt.Errorf("msg: HTLC list length %d is not a "+
			"multiple of %d", len(b), htlcLen)
	}
	var hs []Htlc
	for ; len(b) > 0; b = b[htlcLen:] {
		h := Htlc{
			ID:         binary.BigEndian.Uint64(b[0:8]),
			Offerer:    Offerer(b[8]),
			Amount:     binary.BigEndian.Uint64(b[9:17]),
			CltvExpiry: binary.BigEndian.Uint32(b[49:53]),
		}
		if h.Offerer > OfferedByCounterparty {
			return nil, errors.New("msg: invalid HTLC offerer")
		}
		copy(h.PaymentHash[:], b[17:49])
		hs = append(hs, h)
	}
	return hs, nil
}

// StateProposal proposes state n: the balances and in-flight HTLCs that
// settle_n will pay out (C.3.4). Both parties then run the signing rounds
// of C.3.6 over it. The balances are settlement outputs, so a zero
// balance is an omitted output and a nonzero one is never below the
// channel's DustChan; whatever the outputs leave of the capacity is the
// anchor's value, which carries the trimmed amounts (C.3.4).
type StateProposal struct {
	ChanID   [32]byte
	StateNum uint32
	BalanceU uint64
	BalanceV uint64
	Htlcs    []Htlc
}

// Anchor is the value settle_n's anchor output carries: the capacity less
// every balance and HTLC output. It is 0 when nothing was trimmed.
func (s *StateProposal) Anchor(capacity uint64) (uint64, error) {
	total := s.BalanceU
	for _, v := range append([]uint64{s.BalanceV}, htlcAmounts(s.Htlcs)...) {
		if total+v < total {
			return 0, errors.New("msg: state amounts overflow")
		}
		total += v
	}
	if total > capacity {
		return 0, fmt.Errorf("msg: state pays %d, capacity is %d", total,
			capacity)
	}
	return capacity - total, nil
}

// SettleCollationLen is the size of the settlement collation the state's
// outputs produce (C.7): one output per nonzero balance and per HTLC. A
// zero balance is an omitted output (C.3.4), so it is not counted.
func (s *StateProposal) SettleCollationLen() int {
	outputs := len(s.Htlcs)
	for _, b := range []uint64{s.BalanceU, s.BalanceV} {
		if b != 0 {
			outputs++
		}
	}
	return SettleCollationBase + SettleCollationPerOutput*outputs
}

// Validate checks the proposal against the channel's parameters and the
// tapleaf version of its scripts: the state number fits the lock-time
// range (C.3.5), the outputs do not exceed the capacity (C.3.4), no
// balance or HTLC output is below the dust floor (C.3.4), and under 0xC0
// the settlement collation fits SETTLE_n's 520-byte element limit (C.7).
func (s *StateProposal) Validate(open *ChanOpen, mode script.Mode) error {
	if s.StateNum == 0 || s.StateNum > script.ChanMaxState {
		return errors.New("msg: state number out of range")
	}
	if _, err := s.Anchor(open.Capacity); err != nil {
		return err
	}
	for _, b := range []uint64{s.BalanceU, s.BalanceV} {
		if b != 0 && b < open.DustChan {
			return fmt.Errorf("msg: balance output %d is below "+
				"dust_chan %d (C.3.4)", b, open.DustChan)
		}
	}
	for _, h := range s.Htlcs {
		if h.Amount < open.DustChan {
			return fmt.Errorf("msg: HTLC output %d is below dust_chan "+
				"%d (C.3.4)", h.Amount, open.DustChan)
		}
	}
	if n := s.SettleCollationLen(); mode == script.ModeC0 &&
		n > MaxSettleCollationC0 {

		return fmt.Errorf("msg: settlement collation of %d bytes "+
			"exceeds %d under tapleaf 0xC0 (C.7)", n,
			MaxSettleCollationC0)
	}
	return nil
}

func htlcAmounts(hs []Htlc) []uint64 {
	out := make([]uint64, len(hs))
	for i, h := range hs {
		out[i] = h.Amount
	}
	return out
}

func (s *StateProposal) records(htlcs *[]byte) []tlv.Record {
	return []tlv.Record{
		tlv.MakePrimitiveRecord(TypeChanID, &s.ChanID),
		tlv.MakePrimitiveRecord(TypeStateNum, &s.StateNum),
		tlv.MakePrimitiveRecord(TypeStateBalanceU, &s.BalanceU),
		tlv.MakePrimitiveRecord(TypeStateBalanceV, &s.BalanceV),
		boundedVarBytes(TypeStateHtlcs, htlcs, maxStateHtlcsLen),
	}
}

// Encode serializes the message as a TLV stream.
func (s *StateProposal) Encode(w io.Writer) error {
	htlcs := encodeHtlcs(s.Htlcs)
	return encodeStream(w, s.records(&htlcs))
}

// Decode deserializes a message produced by Encode.
func (s *StateProposal) Decode(r io.Reader) error {
	var htlcs []byte
	err := decodeChan(
		r, maxChanFixedLen+maxStateHtlcsLen, "StateProposal",
		s.records(&htlcs),
	)
	if err != nil {
		return err
	}
	s.Htlcs, err = decodeHtlcs(htlcs)
	return err
}

// SigRole is the transaction a partial signature is for.
type SigRole uint8

const (
	// RoleSettle is settle_n, signed first (C.3.6 step 1).
	RoleSettle SigRole = 0

	// RoleUpdate is update_n, signed second (C.3.6 step 2).
	RoleUpdate SigRole = 1
)

// StateSig is one party's MuSig2 partial signature in a C.3.6 round,
// together with its public nonce for the next session.
type StateSig struct {
	ChanID     [32]byte
	StateNum   uint32
	Role       SigRole
	PartialSig [PartialSigLen]byte
	NextNonce  [PubNonceLen]byte
}

func (s *StateSig) records(role *uint8, psig *[32]byte,
	nonce *[]byte) []tlv.Record {

	return []tlv.Record{
		tlv.MakePrimitiveRecord(TypeChanID, &s.ChanID),
		tlv.MakePrimitiveRecord(TypeStateNum, &s.StateNum),
		tlv.MakePrimitiveRecord(TypeSigRole, role),
		tlv.MakePrimitiveRecord(TypeSigPartialSig, psig),
		boundedVarBytes(TypeSigNextNonce, nonce, PubNonceLen),
	}
}

// Encode serializes the message as a TLV stream.
func (s *StateSig) Encode(w io.Writer) error {
	role := uint8(s.Role)
	psig := s.PartialSig
	nonce := s.NextNonce[:]
	return encodeStream(w, s.records(&role, &psig, &nonce))
}

// Decode deserializes a message produced by Encode.
func (s *StateSig) Decode(r io.Reader) error {
	var (
		role  uint8
		psig  [32]byte
		nonce []byte
	)
	err := decodeChan(
		r, maxChanFixedLen, "StateSig", s.records(&role, &psig, &nonce),
	)
	if err != nil {
		return err
	}
	if role > uint8(RoleUpdate) {
		return errors.New("msg: invalid signature role")
	}
	if len(nonce) != PubNonceLen {
		return fmt.Errorf("msg: public nonce is %d bytes, want %d",
			len(nonce), PubNonceLen)
	}
	s.Role, s.PartialSig = SigRole(role), psig
	copy(s.NextNonce[:], nonce)
	return nil
}

// SigningRound enforces the order of C.3.6 for one party advancing to
// state n: settle_n partial signatures are exchanged first, and the party
// does not release its update_n partial signature until it holds the
// counterparty's settle_n partial signature.
type SigningRound struct {
	ChanID   [32]byte
	StateNum uint32

	sent, recv [2]bool
}

// ErrSigningOrder is returned for a step C.3.6 forbids.
var ErrSigningOrder = errors.New("msg: C.3.6 signing order violated")

func (s *SigningRound) match(sig *StateSig) error {
	if sig.ChanID != s.ChanID || sig.StateNum != s.StateNum {
		return errors.New("msg: signature for another channel or state")
	}
	if sig.Role > RoleUpdate {
		return errors.New("msg: invalid signature role")
	}
	return nil
}

// Send records that the party is about to send sig. Sending the update
// partial signature before holding the counterparty's settle partial
// signature is refused.
func (s *SigningRound) Send(sig *StateSig) error {
	if err := s.match(sig); err != nil {
		return err
	}
	if sig.Role == RoleUpdate && !s.recv[RoleSettle] {
		return ErrSigningOrder
	}
	s.sent[sig.Role] = true
	return nil
}

// Receive records the counterparty's sig. An update partial signature
// before both settle partial signatures have been exchanged is refused.
func (s *SigningRound) Receive(sig *StateSig) error {
	if err := s.match(sig); err != nil {
		return err
	}
	if sig.Role == RoleUpdate && !(s.sent[RoleSettle] && s.recv[RoleSettle]) {
		return ErrSigningOrder
	}
	s.recv[sig.Role] = true
	return nil
}

// Complete reports whether state n may be treated as current (C.3.6
// step 3): both partial signatures of both transactions are held.
func (s *SigningRound) Complete() bool {
	return s.sent[RoleSettle] && s.recv[RoleSettle] &&
		s.sent[RoleUpdate] && s.recv[RoleUpdate]
}

// HtlcAdd offers an HTLC; it takes effect in the next state.
type HtlcAdd struct {
	ChanID [32]byte
	Htlc   Htlc
}

func (h *HtlcAdd) records(offerer *uint8) []tlv.Record {
	return []tlv.Record{
		tlv.MakePrimitiveRecord(TypeChanID, &h.ChanID),
		tlv.MakePrimitiveRecord(TypeHtlcID, &h.Htlc.ID),
		tlv.MakePrimitiveRecord(TypeHtlcOfferer, offerer),
		tlv.MakePrimitiveRecord(TypeHtlcAmount, &h.Htlc.Amount),
		tlv.MakePrimitiveRecord(TypeHtlcPaymentHash, &h.Htlc.PaymentHash),
		tlv.MakePrimitiveRecord(TypeHtlcCltvExpiry, &h.Htlc.CltvExpiry),
	}
}

// Encode serializes the message as a TLV stream.
func (h *HtlcAdd) Encode(w io.Writer) error {
	o := uint8(h.Htlc.Offerer)
	return encodeStream(w, h.records(&o))
}

// Decode deserializes a message produced by Encode.
func (h *HtlcAdd) Decode(r io.Reader) error {
	var o uint8
	err := decodeChan(r, maxChanFixedLen, "HtlcAdd", h.records(&o))
	if err != nil {
		return err
	}
	if o > uint8(OfferedByCounterparty) {
		return errors.New("msg: invalid HTLC offerer")
	}
	h.Htlc.Offerer = Offerer(o)
	return nil
}

// CheckDeadline enforces C.4.4 and C.6.4: the HTLC's cltv_expiry leaves
// at least budget blocks above the current height, and above the leaf's
// evict_after when that is later, since the counterparty's force-close
// clock cannot start before the lease has passed.
func (h *HtlcAdd) CheckDeadline(height, evictAfter, budget uint32) error {
	start := max(height, evictAfter)
	if uint64(h.Htlc.CltvExpiry) < uint64(start)+uint64(budget) {
		return fmt.Errorf("msg: cltv_expiry %d leaves less than %d "+
			"blocks above %d (C.4.4, C.6.4)", h.Htlc.CltvExpiry, budget,
			start)
	}
	return nil
}

// HtlcFulfill settles an HTLC off-chain with its preimage.
type HtlcFulfill struct {
	ChanID   [32]byte
	HtlcID   uint64
	Preimage [32]byte
}

func (h *HtlcFulfill) records() []tlv.Record {
	return []tlv.Record{
		tlv.MakePrimitiveRecord(TypeChanID, &h.ChanID),
		tlv.MakePrimitiveRecord(TypeHtlcID, &h.HtlcID),
		tlv.MakePrimitiveRecord(TypeHtlcPreimage, &h.Preimage),
	}
}

// Encode serializes the message as a TLV stream.
func (h *HtlcFulfill) Encode(w io.Writer) error { return encodeStream(w, h.records()) }

// Decode deserializes a message produced by Encode.
func (h *HtlcFulfill) Decode(r io.Reader) error {
	return decodeChan(r, maxChanFixedLen, "HtlcFulfill", h.records())
}

// Verify reports whether the preimage opens paymentHash: the same 32-byte
// discipline HTLC_SUCCESS and CLAIM^h apply (C.4.1, spec 7.5.1).
func (h *HtlcFulfill) Verify(paymentHash [32]byte) bool {
	return sha256.Sum256(h.Preimage[:]) == paymentHash
}

// HtlcFail removes an HTLC without payment.
type HtlcFail struct {
	ChanID [32]byte
	HtlcID uint64
	Reason []byte
}

func (h *HtlcFail) records() []tlv.Record {
	return []tlv.Record{
		tlv.MakePrimitiveRecord(TypeChanID, &h.ChanID),
		tlv.MakePrimitiveRecord(TypeHtlcID, &h.HtlcID),
		boundedVarBytes(
			TypeHtlcFailReason, &h.Reason, maxHtlcFailReasonLen,
		),
	}
}

// Encode serializes the message as a TLV stream.
func (h *HtlcFail) Encode(w io.Writer) error { return encodeStream(w, h.records()) }

// Decode deserializes a message produced by Encode. The reason is
// optional.
func (h *HtlcFail) Decode(r io.Reader) error {
	return decodeChan(
		r, maxChanFixedLen+maxHtlcFailReasonLen, "HtlcFail",
		h.records(), TypeHtlcFailReason,
	)
}

// RebindAnnounce tells the counterparty, or a watchtower, that the
// channel's funding output has materialised and which state has been bound
// to it (C.5.4). The funding outpoint is unknown until the leaf leaves the
// tree; a recipient checks that the output's scriptPubKey is
// P2TR(exit_key) rather than trusting the outpoint.
type RebindAnnounce struct {
	ChanID [32]byte

	// Outpoint is the output the update transaction spends: the funding
	// output, or the update output U_j of a stale state being answered.
	Outpoint wire.OutPoint

	// StateNum is n, the state of the bound update transaction.
	StateNum uint32

	// BoundTx is the serialized update_n bound to Outpoint, with its
	// witness. It MAY be empty when only the outpoint is announced.
	BoundTx []byte
}

func encodeOutpoint(op wire.OutPoint) [36]byte {
	var b [36]byte
	copy(b[:32], op.Hash[:])
	binary.LittleEndian.PutUint32(b[32:], op.Index)
	return b
}

func (a *RebindAnnounce) records(op *[]byte) []tlv.Record {
	return []tlv.Record{
		tlv.MakePrimitiveRecord(TypeChanID, &a.ChanID),
		boundedVarBytes(TypeRebindOutpoint, op, outpointLen),
		tlv.MakePrimitiveRecord(TypeRebindState, &a.StateNum),
		boundedVarBytes(TypeRebindBoundTx, &a.BoundTx, maxTxLen),
	}
}

// Encode serializes the message as a TLV stream.
func (a *RebindAnnounce) Encode(w io.Writer) error {
	ob := encodeOutpoint(a.Outpoint)
	op := ob[:]
	return encodeStream(w, a.records(&op))
}

// Decode deserializes a message produced by Encode. The bound transaction
// is optional; the state number must be in 1..ChanMaxState (C.3.5) so
// that ChanStateBase + StateNum cannot wrap.
func (a *RebindAnnounce) Decode(r io.Reader) error {
	var op []byte
	err := decodeChan(
		r, maxChanFixedLen+maxTxLen, "RebindAnnounce", a.records(&op),
		TypeRebindBoundTx,
	)
	if err != nil {
		return err
	}
	if len(op) != outpointLen {
		return fmt.Errorf("msg: outpoint is %d bytes, want %d", len(op),
			outpointLen)
	}
	if a.StateNum == 0 || a.StateNum > script.ChanMaxState {
		return errors.New("msg: state number out of range")
	}
	copy(a.Outpoint.Hash[:], op[:32])
	a.Outpoint.Index = binary.LittleEndian.Uint32(op[32:])
	if len(a.BoundTx) == 0 {
		a.BoundTx = nil
		return nil
	}
	var tx wire.MsgTx
	if err := tx.Deserialize(bytes.NewReader(a.BoundTx)); err != nil {
		return fmt.Errorf("msg: bound transaction: %w", err)
	}
	if len(tx.TxIn) != 1 || tx.TxIn[0].PreviousOutPoint != a.Outpoint {
		return errors.New("msg: bound transaction does not spend the " +
			"announced outpoint alone")
	}
	if tx.LockTime != script.ChanStateBase+a.StateNum {
		return errors.New("msg: bound transaction is not update_n")
	}
	return nil
}

// SpliceProposal proposes the next capacity epoch (C.5.2). The new
// channel has a new chan_id, hence new contexts and a new exit_key; the
// parties exchange settle_1 and update_1 for it before either signs the
// tree UPDATE.
type SpliceProposal struct {
	// ChanID is the current epoch's chan_id.
	ChanID [32]byte

	// NewCapacity is C' and NewEpoch is epoch + 1.
	NewCapacity uint64
	NewEpoch    uint32

	// BalanceU and BalanceV are the balances of state 1 of the new
	// epoch.
	BalanceU, BalanceV uint64
}

func (s *SpliceProposal) records() []tlv.Record {
	return []tlv.Record{
		tlv.MakePrimitiveRecord(TypeChanID, &s.ChanID),
		tlv.MakePrimitiveRecord(TypeSpliceCapacity, &s.NewCapacity),
		tlv.MakePrimitiveRecord(TypeSpliceEpoch, &s.NewEpoch),
		tlv.MakePrimitiveRecord(TypeSpliceBalanceU, &s.BalanceU),
		tlv.MakePrimitiveRecord(TypeSpliceBalanceV, &s.BalanceV),
	}
}

// Encode serializes the message as a TLV stream.
func (s *SpliceProposal) Encode(w io.Writer) error { return encodeStream(w, s.records()) }

// Decode deserializes a message produced by Encode.
func (s *SpliceProposal) Decode(r io.Reader) error {
	return decodeChan(r, maxChanFixedLen, "SpliceProposal", s.records())
}

// Apply checks the proposal against the current channel and returns the
// parameters of the new epoch (C.5.2 rules 1 and 3).
func (s *SpliceProposal) Apply(cur *ChanOpen) (*ChanOpen, error) {
	if s.ChanID != cur.ChanID() {
		return nil, errors.New("msg: splice for another channel")
	}
	if s.NewEpoch != cur.Epoch+1 {
		return nil, errors.New("msg: splice must advance the epoch by one")
	}
	next := *cur
	next.Capacity, next.Epoch = s.NewCapacity, s.NewEpoch
	next.BalanceU, next.BalanceV = s.BalanceU, s.BalanceV
	if err := next.Validate(); err != nil {
		return nil, err
	}
	return &next, nil
}
