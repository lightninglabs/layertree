package msg

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"io"
	"reflect"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/wire"
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

	// chan_id matches the script package and changes with the epoch.
	if open.ChanID() != open.Params().ChanID() {
		t.Error("ChanOpen.ChanID differs from script.ChanParams")
	}

	// A state pays out exactly the capacity (C.3.4).
	st := &StateProposal{StateNum: 1, BalanceU: 500_000, BalanceV: 400_000,
		Htlcs: []Htlc{{Amount: 100_000}}}
	if err := st.Validate(open.Capacity); err != nil {
		t.Errorf("valid state rejected: %v", err)
	}
	st.Htlcs[0].Amount++
	if st.Validate(open.Capacity) == nil {
		t.Error("state paying more than capacity accepted")
	}
	st.Htlcs[0].Amount = ^uint64(0)
	if st.Validate(open.Capacity) == nil {
		t.Error("overflowing state accepted")
	}
	if (&StateProposal{StateNum: 0, BalanceU: open.Capacity}).Validate(
		open.Capacity) == nil {

		t.Error("state 0 accepted")
	}

	// Fulfil checks the preimage against the payment hash.
	f := &HtlcFulfill{Preimage: [32]byte{9}}
	if !f.Verify(sha256.Sum256(f.Preimage[:])) || f.Verify([32]byte{}) {
		t.Error("HtlcFulfill.Verify")
	}

	// C.4.4: the cltv_expiry budget.
	add := &HtlcAdd{Htlc: Htlc{CltvExpiry: 800_221}}
	if add.CheckDeadline(800_000, 221) != nil {
		t.Error("HTLC at exactly the budget rejected")
	}
	if add.CheckDeadline(800_001, 221) == nil {
		t.Error("HTLC below the budget accepted")
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
