package script

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
)

// ccvScriptFor builds the CCV-tier script named by a golden key's profile,
// depth and name, mirroring fullScriptFor.
func ccvScriptFor(profile string, depth int, name string,
	key [32]byte) ([]Token, error) {

	sparse := profile == "S"
	var n int
	switch {
	case name == "UPDATE":
		return CCVUpdateScript(depth, key, sparse), nil
	case name == "UPDATE_X":
		return nil, fmt.Errorf("UPDATE_X is a tree-creation parameter; " +
			"generated separately in TestCCVUpdateX")
	case name == "SPLIT":
		return CCVSplitScript(depth, sparse), nil
	case strings.HasPrefix(name, "EXIT_"):
		if _, err := fmt.Sscanf(name, "EXIT_%d", &n); err != nil {
			return nil, err
		}
		return CCVExitScript(depth, n, sparse), nil
	case strings.HasPrefix(name, "JOINK_"):
		if _, err := fmt.Sscanf(name, "JOINK_%d", &n); err != nil {
			return nil, err
		}
		return CCVJoinScript(depth, 0, key, sparse, n), nil
	case strings.HasPrefix(name, "JOIN_"):
		if _, err := fmt.Sscanf(name, "JOIN_%d", &n); err != nil {
			return nil, err
		}
		return CCVJoinScript(depth, n, key, sparse, 1), nil
	case strings.HasPrefix(name, "EVICT_SUBTREE_"):
		if _, err := fmt.Sscanf(name, "EVICT_SUBTREE_%d", &n); err != nil {
			return nil, err
		}
		return CCVEvictSubtreeScript(depth, n, key), nil
	}
	return nil, fmt.Errorf("unknown CCV script name %q", name)
}

// TestCCVScriptsMatchGolden assembles every CCV golden vector and checks
// the bytes and tapleaf hashes against spec/golden.json, which
// tools/gen_golden.py writes from the Python generator
// (tools/layertree_ccv.py).
func TestCCVScriptsMatchGolden(t *testing.T) {
	g, key := loadGolden(t)

	// UPDATE_X is a tree-creation parameter rather than a script the
	// all-scripts set carries, so it is excluded from the loop below and
	// compared directly against its golden entries.
	wantUpdateX := make(map[string]goldenScript)
	var checked int
	for k, want := range g.Scripts {
		if !strings.HasPrefix(k, "CCV/") {
			continue
		}
		if strings.HasSuffix(k, "/UPDATE_X") {
			wantUpdateX[k] = want
			continue
		}
		if strings.HasSuffix(k, "/CLAIM") || strings.HasSuffix(k, "/CLAIM_H") {
			// Parametrised by tree_id; checked in TestCCVClaim.
			continue
		}
		k, want := k, want
		t.Run(strings.ReplaceAll(k, "/", "_"), func(t *testing.T) {
			profile, depth, name, err := parseGoldenKey(k)
			if err != nil {
				t.Fatal(err)
			}
			toks, err := ccvScriptFor(profile, depth, name, key)
			if err != nil {
				t.Fatal(err)
			}
			got, err := Assemble(toks, ModeC2)
			if err != nil {
				t.Fatalf("assemble: %v", err)
			}
			wantBytes, err := hex.DecodeString(want.Hex)
			if err != nil {
				t.Fatalf("bad golden hex: %v", err)
			}
			if want.LeafVersion != 0xc2 {
				t.Fatalf("unexpected leaf version %#x", want.LeafVersion)
			}
			if string(got) != string(wantBytes) {
				reportMismatch(t, k, toks, got, wantBytes)
				return
			}
			lh := TapLeafHash(got, byte(want.LeafVersion))
			if hex.EncodeToString(lh[:]) != want.TapleafHash {
				t.Errorf("%s: tapleaf hash %x, want %s", k, lh,
					want.TapleafHash)
			}
		})
		checked++
	}
	if checked == 0 {
		t.Fatal("no CCV golden vectors found")
	}

	// UPDATE_X, generated directly with exit consent and compared
	// against its golden entries by profile and depth.
	for k, want := range wantUpdateX {
		profile, depth, _, err := parseGoldenKey(k)
		if err != nil {
			t.Fatal(err)
		}
		toks := CCVUpdateXScript(depth, key, profile == "S")
		got, err := Assemble(toks, ModeC2)
		if err != nil {
			t.Fatalf("assemble %s: %v", k, err)
		}
		wantBytes, err := hex.DecodeString(want.Hex)
		if err != nil {
			t.Fatalf("bad golden hex: %v", err)
		}
		if string(got) != string(wantBytes) {
			t.Errorf("%s: UPDATE_X bytes differ", k)
		}
		lh := TapLeafHash(got, byte(want.LeafVersion))
		if hex.EncodeToString(lh[:]) != want.TapleafHash {
			t.Errorf("%s: tapleaf hash %x, want %s", k, lh, want.TapleafHash)
		}
	}
	t.Logf("checked %d CCV golden scripts", checked)
}

// TestCCVClaim checks the CCV tier's CLAIM and CLAIM^h ports (spec 4.6) in
// both numerics against their golden keys, and the RECOMMENDED tree_id
// derivation against the ccv_tree_id vector the scripts were built with.
func TestCCVClaim(t *testing.T) {
	raw, err := os.ReadFile("../spec/golden.json")
	if err != nil {
		t.Fatalf("read golden.json: %v", err)
	}
	var v struct {
		CCVTreeID struct {
			Txid   string `json:"txid"`
			Vout   uint32 `json:"vout"`
			TreeID string `json:"tree_id"`
		} `json:"ccv_tree_id"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("parse golden.json: %v", err)
	}
	var txid [32]byte
	copy(txid[:], midHex(t, v.CCVTreeID.Txid))
	treeID := CCVTreeID(txid, v.CCVTreeID.Vout)
	if hex.EncodeToString(treeID[:]) != v.CCVTreeID.TreeID {
		t.Fatalf("tree_id %x, want %s", treeID, v.CCVTreeID.TreeID)
	}

	g, _ := midLoadGolden(t)
	for _, hl := range []bool{false, true} {
		name := "CLAIM"
		if hl {
			name = "CLAIM_H"
		}
		ccvCheckC2(t, g, "CCV/D/D4/"+name, CCVClaimScript(4, treeID, false, hl))
		ccvCheckC2(t, g, "CCV/S/D8/"+name, CCVClaimScript(8, treeID, true, hl))
		midCheckScript(t, g, "CCV0/D/D4/"+name, CCV0ClaimScript(4, treeID, false, hl))
		midCheckScript(t, g, "CCV0/S/D8/"+name, CCV0ClaimScript(8, treeID, true, hl))
	}
}

// ccvCheckC2 asserts that 0xC2 tokens assemble to the golden bytes.
func ccvCheckC2(t *testing.T, g *midGolden, key string, toks []Token) {
	t.Helper()
	want, ok := g.Scripts[key]
	if !ok {
		t.Fatalf("golden key %q missing", key)
	}
	got, err := Assemble(toks, ModeC2)
	if err != nil {
		t.Fatalf("%s: assemble: %v", key, err)
	}
	if hex.EncodeToString(got) != want.Hex {
		t.Fatalf("%s: script mismatch (got %d bytes, want %d)", key,
			len(got), len(want.Hex)/2)
	}
}
