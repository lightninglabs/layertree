package txn

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

// goldenSighash mirrors the "sighash_vector" object of spec/golden.json,
// written by tools/gen_golden.py.
type goldenSighash struct {
	Version  int32  `json:"version"`
	LockTime uint32 `json:"locktime"`
	Inputs   []struct {
		TxID         string `json:"txid"`
		Vout         uint32 `json:"vout"`
		Amount       int64  `json:"amount"`
		ScriptPubKey string `json:"scriptPubKey"`
		Sequence     uint32 `json:"sequence"`
	} `json:"inputs"`
	Outputs []struct {
		Amount       int64  `json:"amount"`
		ScriptPubKey string `json:"scriptPubKey"`
	} `json:"outputs"`
	InputIndex  int    `json:"input_index"`
	TapleafHash string `json:"tapleaf_hash"`
	SighashMsg  string `json:"sighash_msg"`
	Sighash     string `json:"sighash"`
}

type goldenFile struct {
	Scripts map[string]struct {
		Hex         string `json:"hex"`
		LeafVersion byte   `json:"leaf_version"`
		TapleafHash string `json:"tapleaf_hash"`
	} `json:"scripts"`
	SighashVector goldenSighash `json:"sighash_vector"`
	TreeSPKVector struct {
		RootHash     string `json:"root_hash"`
		MerkleRoot   string `json:"merkle_root"`
		InternalKey  string `json:"internal_key"`
		ScriptPubKey string `json:"scriptPubKey"`
	} `json:"tree_spk_vector"`
}

func loadGolden(t *testing.T) *goldenFile {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "spec", "golden.json"))
	if err != nil {
		t.Fatalf("read golden.json: %v", err)
	}
	var g goldenFile
	if err := json.Unmarshal(raw, &g); err != nil {
		t.Fatalf("parse golden.json: %v", err)
	}
	return &g
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

func mustHash32(t *testing.T, s string) [32]byte {
	t.Helper()
	b := mustHex(t, s)
	if len(b) != 32 {
		t.Fatalf("want 32 bytes, got %d", len(b))
	}
	var out [32]byte
	copy(out[:], b)
	return out
}

// vectorTx rebuilds the transaction of the sighash vector.
func vectorTx(t *testing.T, v *goldenSighash) (*wire.MsgTx,
	map[wire.OutPoint]*wire.TxOut) {

	t.Helper()
	tx := wire.NewMsgTx(v.Version)
	tx.LockTime = v.LockTime
	prevOuts := make(map[wire.OutPoint]*wire.TxOut)
	for _, in := range v.Inputs {
		// The vector's txid is the raw 32 bytes as they appear in the
		// prevout serialization, which is exactly chainhash's internal
		// byte order: no reversal.
		hash, err := chainhash.NewHash(mustHex(t, in.TxID))
		if err != nil {
			t.Fatalf("txid: %v", err)
		}
		op := wire.OutPoint{Hash: *hash, Index: in.Vout}
		tx.AddTxIn(&wire.TxIn{
			PreviousOutPoint: op,
			Sequence:         in.Sequence,
		})
		prevOuts[op] = wire.NewTxOut(
			in.Amount, mustHex(t, in.ScriptPubKey),
		)
	}
	for _, out := range v.Outputs {
		tx.AddTxOut(wire.NewTxOut(
			out.Amount, mustHex(t, out.ScriptPubKey),
		))
	}
	return tx, prevOuts
}

// TestSighashVector checks the BIP-341 script-path SIGHASH_DEFAULT digest
// (and the message it is computed over) against the Python golden vector.
func TestSighashVector(t *testing.T) {
	g := loadGolden(t)
	v := &g.SighashVector
	tx, prevOuts := vectorTx(t, v)
	leafHash := mustHash32(t, v.TapleafHash)

	msg, err := SighashMsg(tx, v.InputIndex, prevOuts, leafHash)
	if err != nil {
		t.Fatalf("SighashMsg: %v", err)
	}
	if got := hex.EncodeToString(msg); got != v.SighashMsg {
		t.Fatalf("sighash message mismatch:\n got %s\nwant %s",
			got, v.SighashMsg)
	}

	manual, err := SighashManual(tx, v.InputIndex, prevOuts, leafHash)
	if err != nil {
		t.Fatalf("SighashManual: %v", err)
	}
	if got := hex.EncodeToString(manual); got != v.Sighash {
		t.Fatalf("manual sighash mismatch:\n got %s\nwant %s",
			got, v.Sighash)
	}

	// The txscript-backed path must produce the same digest.
	sh, err := Sighash(tx, v.InputIndex, prevOuts, leafHash)
	if err != nil {
		t.Fatalf("Sighash: %v", err)
	}
	if got := hex.EncodeToString(sh); got != v.Sighash {
		t.Fatalf("txscript sighash mismatch:\n got %s\nwant %s",
			got, v.Sighash)
	}
}

// TestSighashLeafVersions checks that txscript's tapleaf hashing and
// signature hashing are leaf-version agnostic: the 0xC2 leaves LayerTree uses
// (spec 6.2) go through the same code path as 0xC0 ones, and both agree with
// the manual BIP-341 message.
func TestSighashLeafVersions(t *testing.T) {
	g := loadGolden(t)
	tx, prevOuts := vectorTx(t, &g.SighashVector)

	// The golden file's own EXIT_1 script and its 0xC2 tapleaf hash.
	exit := g.Scripts["FULL/D/D4/EXIT_1"]
	if exit.Hex == "" {
		t.Fatal("golden.json has no FULL/D/D4/EXIT_1 script")
	}
	if exit.LeafVersion != 0xc2 {
		t.Fatalf("EXIT_1 leaf version = 0x%02x, want 0xc2",
			exit.LeafVersion)
	}
	script := mustHex(t, exit.Hex)

	for _, version := range []byte{0xc0, 0xc2} {
		leaf := txscript.NewTapLeaf(
			txscript.TapscriptLeafVersion(version), script,
		)
		leafHash := leaf.TapHash()
		if got := TapleafHash(script, version); got != [32]byte(leafHash) {
			t.Fatalf("TapleafHash disagrees with txscript at "+
				"version 0x%02x", version)
		}
		if version == 0xc2 {
			want := mustHash32(t, exit.TapleafHash)
			if [32]byte(leafHash) != want {
				t.Fatalf("0xc2 tapleaf hash mismatch:\n got "+
					"%x\nwant %x", leafHash[:], want[:])
			}
		}

		// txscript's own tapscript sighash, which derives the leaf
		// hash from the TapLeaf it is handed.
		fetcher := txscript.NewMultiPrevOutFetcher(prevOuts)
		sigHashes := txscript.NewTxSigHashes(tx, fetcher)
		want, err := txscript.CalcTapscriptSignaturehash(
			sigHashes, txscript.SigHashDefault, tx, 0, fetcher, leaf,
		)
		if err != nil {
			t.Fatalf("CalcTapscriptSignaturehash at version "+
				"0x%02x: %v", version, err)
		}

		got, err := SighashScript(tx, 0, prevOuts, script, version)
		if err != nil {
			t.Fatalf("SighashScript: %v", err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("Sighash disagrees with txscript at version "+
				"0x%02x", version)
		}
		manual, err := SighashManual(
			tx, 0, prevOuts, [32]byte(leafHash),
		)
		if err != nil {
			t.Fatalf("SighashManual: %v", err)
		}
		if !bytes.Equal(manual, want) {
			t.Fatalf("manual message disagrees with txscript at "+
				"version 0x%02x", version)
		}
	}
}

// TestTreeSPKVector checks that the scriptPubKey spent by the sighash vector
// is the tree output of spec 6.3 for the vector's state.
func TestTreeSPKVector(t *testing.T) {
	g := loadGolden(t)
	in := TreeInput{
		Amount:     g.SighashVector.Inputs[0].Amount,
		RootHash:   mustHash32(t, g.TreeSPKVector.RootHash),
		MerkleRoot: mustHash32(t, g.TreeSPKVector.MerkleRoot),
	}
	out, err := in.TxOut()
	if err != nil {
		t.Fatalf("TxOut: %v", err)
	}
	if got := hex.EncodeToString(out.PkScript); got != g.TreeSPKVector.ScriptPubKey {
		t.Fatalf("tree spk mismatch:\n got %s\nwant %s", got,
			g.TreeSPKVector.ScriptPubKey)
	}
	if got := g.SighashVector.Inputs[0].ScriptPubKey; got != g.TreeSPKVector.ScriptPubKey {
		t.Fatalf("vector input 0 spk %s is not the tree spk", got)
	}
}
