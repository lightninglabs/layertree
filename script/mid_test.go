package script

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
)

// midGolden is the decoded spec/golden.json.
type midGolden struct {
	OperatorKey string `json:"operator_key"`
	Scripts     map[string]struct {
		Hex         string `json:"hex"`
		LeafVersion int    `json:"leaf_version"`
		TapleafHash string `json:"tapleaf_hash"`
	} `json:"scripts"`
}

func midLoadGolden(t *testing.T) (*midGolden, [32]byte) {
	t.Helper()
	b, err := os.ReadFile("../spec/golden.json")
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	var g midGolden
	if err := json.Unmarshal(b, &g); err != nil {
		t.Fatalf("parse golden: %v", err)
	}
	kb, err := hex.DecodeString(g.OperatorKey)
	if err != nil || len(kb) != 32 {
		t.Fatalf("bad operator_key %q", g.OperatorKey)
	}
	var key [32]byte
	copy(key[:], kb)
	return &g, key
}

// midTapleafHash is TaggedHash("TapLeaf", version || compactsize(len) || script).
func midTapleafHash(script []byte, version byte) [32]byte {
	var buf bytes.Buffer
	buf.WriteByte(version)
	_ = wire.WriteVarInt(&buf, 0, uint64(len(script)))
	buf.Write(script)
	return *chainhash.TaggedHash([]byte("TapLeaf"), buf.Bytes())
}

// midCheckScript asserts that the tokens assemble to the golden bytes.
func midCheckScript(t *testing.T, g *midGolden, key string, toks []Token) {
	t.Helper()
	want, ok := g.Scripts[key]
	if !ok {
		t.Fatalf("golden key %q missing", key)
	}
	wantBytes, err := hex.DecodeString(want.Hex)
	if err != nil {
		t.Fatalf("%s: bad golden hex: %v", key, err)
	}
	got, err := Assemble(toks, ModeC0)
	if err != nil {
		t.Fatalf("%s: assemble: %v", key, err)
	}
	if !bytes.Equal(got, wantBytes) {
		off := len(got)
		for i := range got {
			if i >= len(wantBytes) || got[i] != wantBytes[i] {
				off = i
				break
			}
		}
		lo := off - 16
		if lo < 0 {
			lo = 0
		}
		t.Fatalf("%s: script mismatch at offset %d (got %d bytes, want %d)\n"+
			" got  ...%x\n want ...%x",
			key, off, len(got), len(wantBytes),
			got[lo:min(len(got), off+16)],
			wantBytes[lo:min(len(wantBytes), off+16)])
	}
	if want.LeafVersion != 0xc0 {
		t.Fatalf("%s: leaf version %#x, want 0xc0", key, want.LeafVersion)
	}
	h := midTapleafHash(got, byte(want.LeafVersion))
	if hex.EncodeToString(h[:]) != want.TapleafHash {
		t.Fatalf("%s: tapleaf hash %x, want %s", key, h, want.TapleafHash)
	}
}

func TestMidScriptsDenseD4(t *testing.T) {
	g, key := midLoadGolden(t)
	all := MidAllScripts(4, key, false, []int{0, 2}, []int{1}, []int{2})
	for _, name := range []string{"EXIT_1", "JOIN_0", "JOIN_2", "JOINK_2",
		"UPDATE", "CLAIM"} {

		toks, ok := all[name]
		if !ok {
			t.Fatalf("MidAllScripts missing %q", name)
		}
		midCheckScript(t, g, "MID/D/D4/"+name, toks)
	}
}

func TestMidScriptsSparseD8(t *testing.T) {
	g, key := midLoadGolden(t)
	all := MidAllScripts(8, key, true, []int{0, 2}, []int{1}, []int{2})
	if _, ok := all["JOIN_2"]; ok {
		t.Fatalf("sparse profile must only emit JOIN_0")
	}
	for _, name := range []string{"EXIT_1", "JOIN_0", "JOINK_2", "UPDATE",
		"CLAIM"} {

		toks, ok := all[name]
		if !ok {
			t.Fatalf("MidAllScripts missing %q", name)
		}
		midCheckScript(t, g, "MID/S/D8/"+name, toks)
	}
}

func TestMidDirectGenerators(t *testing.T) {
	g, key := midLoadGolden(t)
	midCheckScript(t, g, "MID/D/D4/EXIT_1", MidExitScript(4, 1, false))
	midCheckScript(t, g, "MID/D/D4/JOIN_2", MidJoinScript(4, 2, key, false, 1))
	midCheckScript(t, g, "MID/D/D4/JOINK_2", MidJoinScript(4, 0, key, false, 2))
	midCheckScript(t, g, "MID/D/D4/UPDATE", MidUpdateScript(4, key, false))
	midCheckScript(t, g, "MID/D/D4/CLAIM", MidClaimScript(4, false))
	midCheckScript(t, g, "MID/S/D8/EXIT_1", MidExitScript(8, 1, true))
	midCheckScript(t, g, "MID/S/D8/UPDATE", MidUpdateScript(8, key, true))
}
