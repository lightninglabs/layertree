package script

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/btcsuite/btcd/wire"
)

// goldenChanTx is one of the transaction templates of the "chan" section.
type goldenChanTx struct {
	Version     int32  `json:"version"`
	Locktime    uint32 `json:"locktime"`
	Sequence    uint32 `json:"sequence"`
	SpentAmount int64  `json:"spent_amount"`
	SpentSpk    string `json:"spent_spk"`
	Outputs     []struct {
		Amount       int64  `json:"amount"`
		ScriptPubKey string `json:"scriptPubKey"`
	} `json:"outputs"`
	Selector  uint32 `json:"selector"`
	Collation string `json:"collation"`
	Msg       string `json:"msg"`
}

// goldenChan is spec/golden.json's "chan" section.
type goldenChan struct {
	Params struct {
		M             string `json:"m"`
		OwnerKey      string `json:"owner_key"`
		Nonce         uint32 `json:"nonce"`
		PChan         string `json:"p_chan"`
		Capacity      uint64 `json:"capacity"`
		Epoch         uint32 `json:"epoch"`
		CsvDelay      uint32 `json:"csv_delay"`
		State         uint32 `json:"state"`
		PaymentHash   string `json:"payment_hash"`
		HtlcClaimKey  string `json:"htlc_claim_key"`
		HtlcRefundKey string `json:"htlc_refund_key"`
		CltvExpiry    uint32 `json:"cltv_expiry"`
	} `json:"params"`
	ChanID          string                  `json:"chan_id"`
	CtxUpd          string                  `json:"ctx_upd"`
	CtxSet          string                  `json:"ctx_set"`
	Scripts         map[string]goldenScript `json:"scripts"`
	ExitKey         string                  `json:"exit_key"`
	UpdateOutputSpk string                  `json:"update_output_spk"`
	UpdateTx        goldenChanTx            `json:"update_tx"`
	SettleTx        goldenChanTx            `json:"settle_tx"`
}

func loadGoldenChan(t *testing.T) *goldenChan {
	t.Helper()
	raw, err := os.ReadFile("../spec/golden.json")
	if err != nil {
		t.Fatalf("read golden.json: %v", err)
	}
	var g struct {
		Chan *goldenChan `json:"chan"`
	}
	if err := json.Unmarshal(raw, &g); err != nil {
		t.Fatalf("parse golden.json: %v", err)
	}
	if g.Chan == nil {
		t.Fatalf("golden.json has no chan section")
	}
	return g.Chan
}

func hex32(t *testing.T, s string) [32]byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 32 {
		t.Fatalf("bad 32-byte hex %q", s)
	}
	var out [32]byte
	copy(out[:], b)
	return out
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q", s)
	}
	return b
}

func chanParams(t *testing.T, g *goldenChan) *ChanParams {
	return &ChanParams{
		TreeID:   hex32(t, g.Params.M),
		OwnerKey: hex32(t, g.Params.OwnerKey),
		Nonce:    g.Params.Nonce,
		PChan:    hex32(t, g.Params.PChan),
		Capacity: g.Params.Capacity,
		Epoch:    g.Params.Epoch,
		CsvDelay: g.Params.CsvDelay,
	}
}

// TestChanContext checks chan_id, ctx_upd and ctx_set (C.2.2).
func TestChanContext(t *testing.T) {
	g := loadGoldenChan(t)
	p := chanParams(t, g)

	for name, got := range map[string][32]byte{
		g.ChanID: p.ChanID(), g.CtxUpd: p.CtxUpd(), g.CtxSet: p.CtxSet(),
	} {
		if hex.EncodeToString(got[:]) != name {
			t.Errorf("context mismatch: got %x want %s", got, name)
		}
	}

	// Every chan_id input is committed (C.2.2, C.9.1).
	base := p.ChanID()
	for label, mut := range map[string]func(q *ChanParams){
		"m":        func(q *ChanParams) { q.TreeID[0] ^= 1 },
		"owner":    func(q *ChanParams) { q.OwnerKey[0] ^= 1 },
		"nonce":    func(q *ChanParams) { q.Nonce++ },
		"P_chan":   func(q *ChanParams) { q.PChan[0] ^= 1 },
		"capacity": func(q *ChanParams) { q.Capacity++ },
		"epoch":    func(q *ChanParams) { q.Epoch++ },
		"csv":      func(q *ChanParams) { q.CsvDelay++ },
	} {
		q := *p
		mut(&q)
		if q.ChanID() == base {
			t.Errorf("chan_id does not commit %s", label)
		}
	}
	if p.CtxUpd() == p.CtxSet() {
		t.Error("ctx_upd equals ctx_set")
	}
}

// TestChanScriptsMatchGolden checks the channel and HTLC scripts in both
// tapleaf versions against the Python generators, byte for byte.
func TestChanScriptsMatchGolden(t *testing.T) {
	g := loadGoldenChan(t)
	p := chanParams(t, g)
	ctxU, ctxS := p.CtxUpd(), p.CtxSet()
	ph := hex32(t, g.Params.PaymentHash)
	yk, xk := hex32(t, g.Params.HtlcClaimKey), hex32(t, g.Params.HtlcRefundKey)

	scripts := map[string][]Token{
		"UPD_F": ChanUpdFScript(ctxU, p.PChan),
		fmt.Sprintf("REBIND_%d", g.Params.State): ChanRebindScript(
			g.Params.State, ctxU, p.PChan,
		),
		"SETTLE":       ChanSettleScript(p.CsvDelay, ctxS, p.PChan),
		"HTLC_SUCCESS": HtlcSuccessScript(ph, yk),
		"HTLC_TIMEOUT": HtlcTimeoutScript(g.Params.CltvExpiry, xk),
	}
	checked := 0
	for _, mode := range []Mode{ModeC2, ModeC0} {
		prefix := "C2"
		if mode == ModeC0 {
			prefix = "C0"
		}
		for name, toks := range scripts {
			key := prefix + "/" + name
			want, ok := g.Scripts[key]
			if !ok {
				t.Errorf("golden has no %s", key)
				continue
			}
			got := MustAssemble(toks, mode)
			if hex.EncodeToString(got) != want.Hex {
				t.Errorf("%s: script mismatch\n got  %x\n want %s",
					key, got, want.Hex)
			}
			if int(mode.LeafVersion()) != want.LeafVersion {
				t.Errorf("%s: leaf version %#x, want %#x", key,
					mode.LeafVersion(), want.LeafVersion)
			}
			lh := TapLeafHash(got, mode.LeafVersion())
			if hex.EncodeToString(lh[:]) != want.TapleafHash {
				t.Errorf("%s: tapleaf hash mismatch", key)
			}
			checked++
		}
	}
	if checked != len(g.Scripts) {
		t.Errorf("checked %d channel scripts, golden has %d", checked,
			len(g.Scripts))
	}

	// Measured sizes (spec C.3.2, C.3.3, C.12): SETTLE_n differs by one
	// byte between the tiers because 144 is 0x90 under BIP-441 numerics
	// and 0x9000 as a CScriptNum.
	for _, tc := range []struct {
		name string
		mode Mode
		want int
	}{
		{"UPD_F", ModeC2, 81}, {"UPD_F", ModeC0, 81},
		{"SETTLE", ModeC2, 79}, {"SETTLE", ModeC0, 80},
	} {
		if n := len(MustAssemble(scripts[tc.name], tc.mode)); n != tc.want {
			t.Errorf("%s in mode %d: %d bytes, want %d", tc.name,
				tc.mode, n, tc.want)
		}
	}
}

// TestChanOutputKeys checks exit_key (C.3.2) and the update output U_n
// (C.3.3).
func TestChanOutputKeys(t *testing.T) {
	g := loadGoldenChan(t)
	p := chanParams(t, g)

	exitKey, err := p.ChanExitKey(ModeC2)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(exitKey[:]) != g.ExitKey {
		t.Errorf("exit_key mismatch: got %x want %s", exitKey, g.ExitKey)
	}

	uKey, err := p.ChanUpdateOutputKey(g.Params.State, ModeC2)
	if err != nil {
		t.Fatal(err)
	}
	spk := append([]byte{0x51, 0x20}, uKey[:]...)
	if hex.EncodeToString(spk) != g.UpdateOutputSpk {
		t.Errorf("U_n scriptPubKey mismatch: got %x want %s", spk,
			g.UpdateOutputSpk)
	}

	// U_n is a function of n: a different state has a different key,
	// which is what pins settle_n to U_n (C.2.4).
	other, err := p.ChanUpdateOutputKey(g.Params.State+1, ModeC2)
	if err != nil {
		t.Fatal(err)
	}
	if other == uKey {
		t.Error("U_n does not depend on n")
	}
}

// chanTx rebuilds a golden transaction template as a wire.MsgTx with an
// arbitrary prevout: the channel selectors never read it.
func chanTx(t *testing.T, g goldenChanTx, prevIndex uint32) (*wire.MsgTx,
	*wire.TxOut) {

	tx := wire.NewMsgTx(g.Version)
	tx.LockTime = g.Locktime
	in := wire.NewTxIn(&wire.OutPoint{Index: prevIndex}, nil, nil)
	in.Sequence = g.Sequence
	tx.AddTxIn(in)
	for _, o := range g.Outputs {
		tx.AddTxOut(wire.NewTxOut(o.Amount, mustHex(t, o.ScriptPubKey)))
	}
	return tx, wire.NewTxOut(g.SpentAmount, mustHex(t, g.SpentSpk))
}

// TestChanCollation checks the [C-A1] collations and the signed messages
// against the Python serialiser, and that the prevout is not committed.
func TestChanCollation(t *testing.T) {
	g := loadGoldenChan(t)
	p := chanParams(t, g)

	for _, tc := range []struct {
		name string
		tx   goldenChanTx
		set  bool
	}{{"update", g.UpdateTx, false}, {"settle", g.SettleTx, true}} {
		tx, prev := chanTx(t, tc.tx, 0)
		blob, err := ChanCollate(tc.tx.Selector, tx, 0, prev)
		if err != nil {
			t.Fatal(err)
		}
		if hex.EncodeToString(blob) != tc.tx.Collation {
			t.Errorf("%s: collation mismatch\n got  %x\n want %s",
				tc.name, blob, tc.tx.Collation)
		}

		var msg [32]byte
		if tc.set {
			msg, err = ChanSetMsg(p.CtxSet(), tx, prev)
		} else {
			msg, err = ChanUpdMsg(p.CtxUpd(), tx)
		}
		if err != nil {
			t.Fatal(err)
		}
		if hex.EncodeToString(msg[:]) != tc.tx.Msg {
			t.Errorf("%s: msg mismatch: got %x want %s", tc.name, msg,
				tc.tx.Msg)
		}

		// Requirement R (C.1.2): a different prevout leaves the
		// message unchanged.
		tx2, _ := chanTx(t, tc.tx, 7)
		tx2.TxIn[0].PreviousOutPoint.Hash[0] = 0xff
		blob2, err := ChanCollate(tc.tx.Selector, tx2, 0, prev)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(blob, blob2) {
			t.Errorf("%s: collation depends on the prevout", tc.name)
		}

		// C.2.3: a second input changes NUM_INPUTS and the message.
		tx3, _ := chanTx(t, tc.tx, 0)
		tx3.AddTxIn(wire.NewTxIn(&wire.OutPoint{Index: 1}, nil, nil))
		blob3, err := ChanCollate(tc.tx.Selector, tx3, 0, prev)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Equal(blob, blob3) {
			t.Errorf("%s: collation does not commit NUM_INPUTS",
				tc.name)
		}
	}

	// Only the settlement selector commits the spent output (C.2.4).
	tx, prev := chanTx(t, g.SettleTx, 0)
	other := wire.NewTxOut(prev.Value, append([]byte{}, prev.PkScript...))
	other.PkScript[2] ^= 1
	a, _ := ChanCollate(SelChanSet, tx, 0, prev)
	b, _ := ChanCollate(SelChanSet, tx, 0, other)
	if bytes.Equal(a, b) {
		t.Error("SEL_CHAN_SET does not commit the spent scriptPubKey")
	}
	a, _ = ChanCollate(SelChanUpd, tx, 0, prev)
	b, _ = ChanCollate(SelChanUpd, tx, 0, other)
	if !bytes.Equal(a, b) {
		t.Error("SEL_CHAN_UPD commits the spent scriptPubKey")
	}
	if SelChanUpd != 0x0fc7 || SelChanSet != 0x30fc7 {
		t.Errorf("selectors %#x %#x, want 0x0fc7 0x30fc7", SelChanUpd,
			SelChanSet)
	}
}
