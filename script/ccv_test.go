package script

import (
	"encoding/hex"
	"fmt"
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
