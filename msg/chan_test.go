package msg

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"math/bits"
	"reflect"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightningnetwork/lnd/tlv"
	"github.com/roasbeef/layertree/script"
)

// chanMessage is the Encode/Decode pair every channel message implements.
type chanMessage interface {
	Encode(w io.Writer) error
	Decode(r io.Reader) error
}

func testOpen() *ChanOpen {
	priv, _ := btcec.PrivKeyFromBytes([]byte("channel-leaf P_chan test key 32b"))
	var pChan [32]byte
	copy(pChan[:], schnorr.SerializePubKey(priv.PubKey()))

	return &ChanOpen{
		TreeID:     [32]byte{1},
		OwnerKey:   [32]byte{2},
		Nonce:      7,
		PChan:      pChan,
		Capacity:   1_000_000,
		CsvDelay:   144,
		BalanceU:   600_000,
		BalanceV:   400_000,
		EvictAfter: 0,
		DustChan:   DustP2TR,
	}
}

func TestChanMessagesRoundTrip(t *testing.T) {
	open := testOpen()
	id := open.ChanID()
	preimage := [32]byte{9}
	ph := sha256.Sum256(preimage[:])

	bound := wire.NewMsgTx(script.ChanTxVersion)
	op := wire.OutPoint{Hash: [32]byte{0xaa}, Index: 3}
	bound.AddTxIn(wire.NewTxIn(&op, nil, wire.TxWitness{make([]byte, 64)}))
	bound.TxIn[0].Sequence = script.ChanUpdateSequence
	bound.AddTxOut(wire.NewTxOut(1_000_000, make([]byte, 34)))
	bound.AddTxOut(wire.NewTxOut(0, script.P2ASpk))
	bound.LockTime = script.ChanStateBase + 5
	var boundBuf bytes.Buffer
	if err := bound.Serialize(&boundBuf); err != nil {
		t.Fatal(err)
	}

	sig := &StateSig{ChanID: id, StateNum: 5, Role: RoleUpdate}
	sig.PartialSig[0], sig.NextNonce[65] = 0x11, 0x22

	cases := []struct {
		name    string
		in, out chanMessage
	}{
		{"ChanOpen", open, &ChanOpen{}},
		{"StateProposal", &StateProposal{
			ChanID: id, StateNum: 5, BalanceU: 500_000,
			BalanceV: 400_000, Htlcs: []Htlc{
				{ID: 1, Offerer: OfferedByOwner, Amount: 60_000,
					PaymentHash: ph, CltvExpiry: 800_400},
				{ID: 2, Offerer: OfferedByCounterparty,
					Amount: 40_000, CltvExpiry: 800_500},
			},
		}, &StateProposal{}},
		{"StateSig", sig, &StateSig{}},
		{"HtlcAdd", &HtlcAdd{ChanID: id, Htlc: Htlc{
			ID: 3, Offerer: OfferedByCounterparty, Amount: 1,
			PaymentHash: ph, CltvExpiry: 900_000,
		}}, &HtlcAdd{}},
		{"HtlcFulfill", &HtlcFulfill{ChanID: id, HtlcID: 3,
			Preimage: preimage}, &HtlcFulfill{}},
		{"HtlcFail", &HtlcFail{ChanID: id, HtlcID: 4,
			Reason: []byte("expiry too soon")}, &HtlcFail{}},
		{"RebindAnnounce", &RebindAnnounce{ChanID: id, Outpoint: op,
			StateNum: 5, BoundTx: boundBuf.Bytes()},
			&RebindAnnounce{}},
		{"RebindAnnounce/no tx", &RebindAnnounce{ChanID: id,
			Outpoint: op, StateNum: 5}, &RebindAnnounce{}},
		{"SpliceProposal", &SpliceProposal{ChanID: id,
			NewCapacity: 1_500_000, NewEpoch: 1, BalanceU: 600_000,
			BalanceV: 900_000}, &SpliceProposal{}},
	}
	for _, tc := range cases {
		var buf bytes.Buffer
		if err := tc.in.Encode(&buf); err != nil {
			t.Fatalf("%s: encode: %v", tc.name, err)
		}
		if err := tc.out.Decode(bytes.NewReader(buf.Bytes())); err != nil {
			t.Fatalf("%s: decode: %v", tc.name, err)
		}
		if !reflect.DeepEqual(tc.in, tc.out) {
			t.Errorf("%s: round trip mismatch\n in  %+v\n out %+v",
				tc.name, tc.in, tc.out)
		}
	}
}

func TestChanMessageValidation(t *testing.T) {
	open := testOpen()
	if err := open.Validate(); err != nil {
		t.Fatalf("valid open rejected: %v", err)
	}
	bad := *open
	bad.BalanceV++
	if bad.Validate() == nil {
		t.Error("open with balances above capacity accepted")
	}
	bad = *open
	bad.EvictAfter = script.ChanStateBase
	if bad.Validate() == nil {
		t.Error("open with a timestamp evict_after accepted")
	}
	bad = *open
	bad.DustChan = DustP2TR - 1
	if bad.Validate() == nil {
		t.Error("open with dust_chan below the P2TR threshold accepted")
	}

	// chan_id matches the script package and changes with the epoch.
	if open.ChanID() != open.Params().ChanID() {
		t.Error("ChanOpen.ChanID differs from script.ChanParams")
	}

	// C.2.2: chan_id binds the host tree's tree_id, so the same channel
	// parameters under another lineage name another channel.
	other := *open
	other.TreeID[0] ^= 1
	if other.ChanID() == open.ChanID() {
		t.Error("chan_id does not commit tree_id")
	}

	// A state pays out at most the capacity, the remainder being the
	// anchor's value (C.3.4).
	st := &StateProposal{StateNum: 1, BalanceU: 500_000, BalanceV: 400_000,
		Htlcs: []Htlc{{Amount: 100_000}}}
	if err := st.Validate(open, script.ModeC2); err != nil {
		t.Errorf("valid state rejected: %v", err)
	}
	if a, _ := st.Anchor(open.Capacity); a != 0 {
		t.Errorf("anchor of an untrimmed state is %d, want 0", a)
	}
	st.Htlcs[0].Amount++
	if st.Validate(open, script.ModeC2) == nil {
		t.Error("state paying more than capacity accepted")
	}
	st.Htlcs[0].Amount = ^uint64(0)
	if st.Validate(open, script.ModeC2) == nil {
		t.Error("overflowing state accepted")
	}
	if (&StateProposal{StateNum: 0, BalanceU: open.Capacity}).Validate(
		open, script.ModeC2) == nil {

		t.Error("state 0 accepted")
	}

	// C.3.4: a sub-dust balance or HTLC output is not a settlement output.
	// It is omitted, which is a zero balance, and its value is the
	// anchor's.
	dust := &StateProposal{StateNum: 1, BalanceU: open.Capacity - 329,
		BalanceV: 329}
	if dust.Validate(open, script.ModeC2) == nil {
		t.Error("state with a 329-sat balance output accepted")
	}
	dust.BalanceV = 0
	if err := dust.Validate(open, script.ModeC2); err != nil {
		t.Errorf("state with the 329 sat trimmed into the anchor "+
			"rejected: %v", err)
	}
	if a, _ := dust.Anchor(open.Capacity); a != 329 {
		t.Errorf("anchor carries %d, want the trimmed 329", a)
	}
	dust.Htlcs = []Htlc{{Amount: 200}}
	dust.BalanceU -= 200
	if dust.Validate(open, script.ModeC2) == nil {
		t.Error("state with a 200-sat HTLC output accepted")
	}
	single := &StateProposal{StateNum: 1, BalanceU: open.Capacity}
	if err := single.Validate(open, script.ModeC2); err != nil {
		t.Errorf("single-funded state 1 rejected: %v", err)
	}

	// C.7: under 0xC0 a settlement collation must fit 488 bytes, so at
	// most seven HTLC outputs beside two balance outputs; FULL has no
	// such limit.
	wide := &StateProposal{StateNum: 1, BalanceU: open.Capacity - 9_000,
		BalanceV: 1_000}
	for range 8 {
		wide.Htlcs = append(wide.Htlcs, Htlc{Amount: 1_000})
	}
	if n := wide.SettleCollationLen(); n != 156+43*8 {
		t.Errorf("collation of 8 HTLCs is %d bytes, want %d", n, 156+43*8)
	}
	if wide.Validate(open, script.ModeC0) == nil {
		t.Error("state with eight HTLC outputs accepted under 0xC0")
	}
	if err := wide.Validate(open, script.ModeC2); err != nil {
		t.Errorf("state with eight HTLC outputs rejected under 0xC2: %v",
			err)
	}
	wide.Htlcs = wide.Htlcs[:7]
	wide.BalanceU += 1_000
	if err := wide.Validate(open, script.ModeC0); err != nil {
		t.Errorf("state with seven HTLC outputs rejected under 0xC0: %v",
			err)
	}

	// A zero balance is an omitted output (C.3.4), so eight HTLC outputs
	// beside one balance collate to 70 + 43*9 = 457 bytes and fit 0xC0
	// (design/audit/go.md G7a).
	lone := &StateProposal{StateNum: 1, BalanceU: open.Capacity - 8_000}
	for range 8 {
		lone.Htlcs = append(lone.Htlcs, Htlc{Amount: 1_000})
	}
	if n := lone.SettleCollationLen(); n != 457 {
		t.Errorf("collation of one balance and 8 HTLCs is %d bytes, "+
			"want 457", n)
	}
	if err := lone.Validate(open, script.ModeC0); err != nil {
		t.Errorf("single-balance state with eight HTLC outputs "+
			"rejected under 0xC0: %v", err)
	}
	lone.Htlcs = append(lone.Htlcs, Htlc{Amount: 1_000})
	lone.BalanceU -= 1_000
	if lone.Validate(open, script.ModeC0) == nil {
		t.Error("single-balance state with nine HTLC outputs (500 " +
			"bytes) accepted under 0xC0")
	}

	// Fulfil checks the preimage against the payment hash.
	f := &HtlcFulfill{Preimage: [32]byte{9}}
	if !f.Verify(sha256.Sum256(f.Preimage[:])) || f.Verify([32]byte{}) {
		t.Error("HtlcFulfill.Verify")
	}

	// C.4.4: the cltv_expiry budget, measured from the tip or from the
	// lease, whichever is later (C.6.4).
	add := &HtlcAdd{Htlc: Htlc{CltvExpiry: 800_221}}
	if add.CheckDeadline(800_000, 0, 221) != nil {
		t.Error("HTLC at exactly the budget rejected")
	}
	if add.CheckDeadline(800_001, 0, 221) == nil {
		t.Error("HTLC below the budget accepted")
	}
	if add.CheckDeadline(800_000, 799_000, 221) != nil {
		t.Error("HTLC under a lease already passed rejected")
	}
	if add.CheckDeadline(800_000, 800_001, 221) == nil {
		t.Error("HTLC expiring before evict_after plus the budget accepted")
	}
	if add.CheckDeadline(100, 800_000, 221) != nil {
		t.Error("HTLC expiring at evict_after plus the budget rejected")
	}

	// C.5.2: a splice advances the epoch and yields a new chan_id.
	sp := &SpliceProposal{ChanID: open.ChanID(), NewCapacity: 1_500_000,
		NewEpoch: 1, BalanceU: 600_000, BalanceV: 900_000}
	next, err := sp.Apply(open)
	if err != nil {
		t.Fatalf("splice rejected: %v", err)
	}
	if next.ChanID() == open.ChanID() {
		t.Error("splice kept chan_id")
	}
	k0, err := open.Params().ChanExitKey(script.ModeC2)
	if err != nil {
		t.Fatal(err)
	}
	k1, err := next.Params().ChanExitKey(script.ModeC2)
	if err != nil {
		t.Fatal(err)
	}
	if k0 == k1 {
		t.Error("splice kept exit_key (C.5.2 rule 1)")
	}
	sp.NewEpoch = 2
	if _, err := sp.Apply(open); err == nil {
		t.Error("splice skipping an epoch accepted")
	}
	sp.NewEpoch, sp.ChanID = 1, [32]byte{}
	if _, err := sp.Apply(open); err == nil {
		t.Error("splice for another channel accepted")
	}

	// A rebind announcement whose transaction spends another outpoint, or
	// is not update_n, is rejected.
	tx := wire.NewMsgTx(script.ChanTxVersion)
	tx.AddTxIn(wire.NewTxIn(&wire.OutPoint{Index: 1}, nil, nil))
	tx.LockTime = script.ChanStateBase + 5
	var buf bytes.Buffer
	if err := tx.Serialize(&buf); err != nil {
		t.Fatal(err)
	}
	for _, a := range []*RebindAnnounce{
		{Outpoint: wire.OutPoint{Index: 2}, StateNum: 5, BoundTx: buf.Bytes()},
		{Outpoint: wire.OutPoint{Index: 1}, StateNum: 4, BoundTx: buf.Bytes()},
	} {
		var enc bytes.Buffer
		if err := a.Encode(&enc); err != nil {
			t.Fatal(err)
		}
		if (&RebindAnnounce{}).Decode(&enc) == nil {
			t.Errorf("inconsistent rebind announcement accepted: %+v",
				a.Outpoint)
		}
	}
}

// TestSigningRoundOrder checks C.3.6: settle_n before update_n, and no
// update partial signature leaves before the counterparty's settle partial
// signature has arrived.
func TestSigningRoundOrder(t *testing.T) {
	id := testOpen().ChanID()
	mk := func(role SigRole) *StateSig {
		return &StateSig{ChanID: id, StateNum: 2, Role: role}
	}

	r := &SigningRound{ChanID: id, StateNum: 2}
	if err := r.Send(mk(RoleUpdate)); !errors.Is(err, ErrSigningOrder) {
		t.Errorf("update sent first: %v", err)
	}
	if err := r.Send(mk(RoleSettle)); err != nil {
		t.Fatal(err)
	}
	if err := r.Receive(mk(RoleUpdate)); !errors.Is(err, ErrSigningOrder) {
		t.Errorf("update received before settle: %v", err)
	}
	if err := r.Send(mk(RoleUpdate)); !errors.Is(err, ErrSigningOrder) {
		t.Errorf("update sent before the counterparty's settle: %v", err)
	}
	if err := r.Receive(mk(RoleSettle)); err != nil {
		t.Fatal(err)
	}
	if r.Complete() {
		t.Error("complete without update signatures")
	}
	if err := r.Send(mk(RoleUpdate)); err != nil {
		t.Fatal(err)
	}
	if err := r.Receive(mk(RoleUpdate)); err != nil {
		t.Fatal(err)
	}
	if !r.Complete() {
		t.Error("round not complete after all four signatures")
	}
	other := mk(RoleSettle)
	other.StateNum = 3
	if r.Receive(other) == nil {
		t.Error("signature for another state accepted")
	}
}

// chanDecoders returns a constructor for each channel message, with its
// name.
func chanDecoders() []struct {
	name string
	msg  func() chanMessage
} {
	return []struct {
		name string
		msg  func() chanMessage
	}{
		{"ChanOpen", func() chanMessage { return &ChanOpen{} }},
		{"StateProposal", func() chanMessage { return &StateProposal{} }},
		{"StateSig", func() chanMessage { return &StateSig{} }},
		{"HtlcAdd", func() chanMessage { return &HtlcAdd{} }},
		{"HtlcFulfill", func() chanMessage { return &HtlcFulfill{} }},
		{"HtlcFail", func() chanMessage { return &HtlcFail{} }},
		{"RebindAnnounce", func() chanMessage { return &RebindAnnounce{} }},
		{"SpliceProposal", func() chanMessage { return &SpliceProposal{} }},
	}
}

// TestChanDecodeRejectsOversizedRecords is the G3 probe of
// design/audit/go.md for the channel messages: a stream whose one record
// claims 2^62 or 2^31 bytes, on every variable-length record of every
// channel message and on a record the decoder does not know, returns an
// error without allocating anything near the claim.
func TestChanDecodeRejectsOversizedRecords(t *testing.T) {
	const unknownType tlv.Type = 99
	varTypes := map[string][]tlv.Type{
		"StateProposal":  {TypeStateHtlcs},
		"StateSig":       {TypeSigNextNonce},
		"HtlcFail":       {TypeHtlcFailReason},
		"RebindAnnounce": {TypeRebindOutpoint, TypeRebindBoundTx},
	}

	const allocCeiling = 1 << 20
	for _, d := range chanDecoders() {
		types := append(varTypes[d.name], unknownType)
		for _, typ := range types {
			for _, length := range []uint64{1 << 62, 1 << 31} {
				stream := hostileStream(t, typ, length)
				err, allocated := decodeGuarded(func() error {
					return d.msg().Decode(
						bytes.NewReader(stream),
					)
				})
				switch {
				case err == nil:
					t.Errorf("%s.Decode accepted type %d "+
						"claiming 2^%d bytes", d.name, typ,
						bits.Len64(length)-1)

				case strings.HasPrefix(err.Error(), "panic"):
					t.Errorf("%s.Decode type %d length 2^%d: "+
						"%v", d.name, typ,
						bits.Len64(length)-1, err)
				}
				if allocated > allocCeiling {
					t.Errorf("%s.Decode type %d length 2^%d "+
						"allocated %d bytes", d.name, typ,
						bits.Len64(length)-1, allocated)
				}
			}
		}
	}

	// The HTLC cap admits the most HTLC outputs a standard settlement
	// can carry and refuses one more.
	full := &StateProposal{ChanID: [32]byte{1}, StateNum: 1,
		Htlcs: make([]Htlc, maxStateHtlcs)}
	var buf bytes.Buffer
	if err := full.Encode(&buf); err != nil {
		t.Fatal(err)
	}
	if err := (&StateProposal{}).Decode(&buf); err != nil {
		t.Errorf("state with %d HTLCs rejected: %v", maxStateHtlcs, err)
	}
	full.Htlcs = append(full.Htlcs, Htlc{})
	buf.Reset()
	if err := full.Encode(&buf); err != nil {
		t.Fatal(err)
	}
	if (&StateProposal{}).Decode(&buf) == nil {
		t.Errorf("state with %d HTLCs accepted", maxStateHtlcs+1)
	}
}

// splitStream parses a TLV stream into its records in order.
func splitStream(t *testing.T, b []byte) (types []uint64, vals [][]byte) {
	t.Helper()
	r := bytes.NewReader(b)
	var scratch [8]byte
	for r.Len() > 0 {
		typ, err := tlv.ReadVarInt(r, &scratch)
		if err != nil {
			t.Fatal(err)
		}
		l, err := tlv.ReadVarInt(r, &scratch)
		if err != nil {
			t.Fatal(err)
		}
		v := make([]byte, l)
		if _, err := io.ReadFull(r, v); err != nil {
			t.Fatal(err)
		}
		types, vals = append(types, typ), append(vals, v)
	}
	return types, vals
}

// TestChanDecodeRequiresMandatoryRecords is the G7c probe of
// design/audit/go.md: an empty stream decoded to a zero message, so an
// HtlcAdd with no amount, hash or expiry was well formed. Every channel
// decoder now rejects the empty stream, and a valid message with any one
// mandatory record removed, naming the record; removing an optional
// record (the HTLC failure reason, the bound transaction) still decodes.
func TestChanDecodeRequiresMandatoryRecords(t *testing.T) {
	open := testOpen()
	id := open.ChanID()
	op := wire.OutPoint{Hash: [32]byte{0xaa}, Index: 3}
	valid := map[string]chanMessage{
		"ChanOpen": open,
		"StateProposal": &StateProposal{ChanID: id, StateNum: 1,
			BalanceU: open.Capacity},
		"StateSig": &StateSig{ChanID: id, StateNum: 1},
		"HtlcAdd": &HtlcAdd{ChanID: id, Htlc: Htlc{ID: 1, Amount: 1_000,
			CltvExpiry: 800_000}},
		"HtlcFulfill": &HtlcFulfill{ChanID: id, HtlcID: 1},
		"HtlcFail": &HtlcFail{ChanID: id, HtlcID: 1,
			Reason: []byte("no")},
		"RebindAnnounce": &RebindAnnounce{ChanID: id, Outpoint: op,
			StateNum: 1},
		"SpliceProposal": &SpliceProposal{ChanID: id, NewEpoch: 1},
	}
	optional := map[string]uint64{
		"HtlcFail":       uint64(TypeHtlcFailReason),
		"RebindAnnounce": uint64(TypeRebindBoundTx),
	}

	for _, d := range chanDecoders() {
		err := d.msg().Decode(bytes.NewReader(nil))
		if err == nil || !strings.Contains(err.Error(),
			"missing mandatory record 0") {

			t.Errorf("%s.Decode(empty): %v", d.name, err)
		}

		var buf bytes.Buffer
		if err := valid[d.name].Encode(&buf); err != nil {
			t.Fatalf("%s: encode: %v", d.name, err)
		}
		types, vals := splitStream(t, buf.Bytes())
		for skip := range types {
			var stream bytes.Buffer
			var scratch [8]byte
			for i := range types {
				if i == skip {
					continue
				}
				_ = tlv.WriteVarInt(&stream, types[i], &scratch)
				_ = tlv.WriteVarInt(
					&stream, uint64(len(vals[i])), &scratch,
				)
				stream.Write(vals[i])
			}
			err := d.msg().Decode(&stream)
			opt, hasOpt := optional[d.name]
			if hasOpt && types[skip] == opt {
				if err != nil {
					t.Errorf("%s without optional record "+
						"%d rejected: %v", d.name,
						types[skip], err)
				}
				continue
			}
			want := fmt.Sprintf("missing mandatory record %d",
				types[skip])
			if err == nil || !strings.Contains(err.Error(), want) {
				t.Errorf("%s without record %d: %v", d.name,
					types[skip], err)
			}
		}
	}
}

// TestRebindAnnounceStateRange is the G7b probe of design/audit/go.md:
// ChanStateBase + StateNum wrapped in uint32, so state 2^32 - S + 5 with
// lock time 5 passed the update_n check. A state number outside
// 1..ChanMaxState (C.3.5) is now refused whether or not a bound
// transaction is attached.
func TestRebindAnnounceStateRange(t *testing.T) {
	op := wire.OutPoint{Hash: [32]byte{0xaa}, Index: 3}
	boundAt := func(lockTime uint32) []byte {
		tx := wire.NewMsgTx(script.ChanTxVersion)
		tx.AddTxIn(wire.NewTxIn(&op, nil, nil))
		tx.LockTime = lockTime
		var buf bytes.Buffer
		if err := tx.Serialize(&buf); err != nil {
			t.Fatal(err)
		}
		return buf.Bytes()
	}

	const wrapped = 1<<32 - script.ChanStateBase + 5
	cases := []struct {
		name  string
		state uint32
		tx    []byte
		ok    bool
	}{
		{"wrapped to lock time 5", wrapped, boundAt(5), false},
		{"wrapped, no tx", wrapped, nil, false},
		{"state 0", 0, boundAt(script.ChanStateBase), false},
		{"above ChanMaxState", script.ChanMaxState + 1, nil, false},
		{"ChanMaxState", script.ChanMaxState,
			boundAt(script.ChanStateBase + script.ChanMaxState), true},
	}
	for _, tc := range cases {
		a := &RebindAnnounce{Outpoint: op, StateNum: tc.state,
			BoundTx: tc.tx}
		var buf bytes.Buffer
		if err := a.Encode(&buf); err != nil {
			t.Fatal(err)
		}
		err := (&RebindAnnounce{}).Decode(&buf)
		if tc.ok && err != nil {
			t.Errorf("%s rejected: %v", tc.name, err)
		}
		if !tc.ok && err == nil {
			t.Errorf("%s accepted", tc.name)
		}
	}
}
