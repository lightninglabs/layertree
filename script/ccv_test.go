package script

import (
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"github.com/roasbeef/layertree/tree"
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
		return CCVSplitScript(depth, sparse, tree.DustMin), nil
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
	case strings.HasPrefix(name, "DETACH_"):
		if _, err := fmt.Sscanf(name, "DETACH_%d", &n); err != nil {
			return nil, err
		}
		return CCVDetachScript(depth, n, key,
			CCVDetachedTaptreeRoot(n, CCVReferenceOptions(key, false))), nil
	case strings.HasPrefix(name, "REWRITE_X_"):
		if _, err := fmt.Sscanf(name, "REWRITE_X_%d", &n); err != nil {
			return nil, err
		}
		return CCVRewriteScript(depth, n, key, true), nil
	case strings.HasPrefix(name, "REWRITE_"):
		if _, err := fmt.Sscanf(name, "REWRITE_%d", &n); err != nil {
			return nil, err
		}
		return CCVRewriteScript(depth, n, key, false), nil
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
		if strings.HasSuffix(k, "/CLAIM") || strings.HasSuffix(k, "/CLAIM_H") ||
			strings.HasSuffix(k, "/CLAIM_X") || strings.HasSuffix(k, "/CLAIM_HX") {

			// Parametrised by tree_id; checked in TestCCVClaim.
			continue
		}
		if strings.HasSuffix(k, "_TOWER") {
			// EXIT_K^t is parametrised by tree_id too; TestCCVExitTower.
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

// TestCCVClaim checks the CCV tier's CLAIM, CLAIM^h, CLAIM^x and CLAIM^hx
// ports (spec 4.6, 7.5.3) in both numerics against their golden keys, built
// over the tree_id vector every tier's golden CLAIM shares (goldenTreeID).
// The exit-consent forms cost seven bytes over their plain form under 0xC2
// (FULL's check) and four under 0xC0 (MID's), and CCVTreeOptions compiles
// them in the generator's order.
func TestCCVClaim(t *testing.T) {
	treeID := midGoldenTreeID(t)
	g, key := midLoadGolden(t)
	for _, hl := range []bool{false, true} {
		name := "CLAIM"
		if hl {
			name = "CLAIM_H"
		}
		ccvCheckC2(t, g, "CCV/D/D4/"+name, CCVClaimScript(4, treeID, false, hl, tree.DustMin))
		ccvCheckC2(t, g, "CCV/S/D8/"+name, CCVClaimScript(8, treeID, true, hl, tree.DustMin))
		midCheckScript(t, g, "CCV0/D/D4/"+name, CCV0ClaimScript(4, treeID, false, hl, tree.DustMin))
		midCheckScript(t, g, "CCV0/S/D8/"+name, CCV0ClaimScript(8, treeID, true, hl, tree.DustMin))
		ccvCheckC2(t, g, "CCV/D/D4/"+xName(hl), CCVClaimXScript(4, treeID, false, hl, tree.DustMin))
		ccvCheckC2(t, g, "CCV/S/D8/"+xName(hl), CCVClaimXScript(8, treeID, true, hl, tree.DustMin))
		midCheckScript(t, g, "CCV0/D/D4/"+xName(hl), CCV0ClaimXScript(4, treeID, false, hl, tree.DustMin))
		midCheckScript(t, g, "CCV0/S/D8/"+xName(hl), CCV0ClaimXScript(8, treeID, true, hl, tree.DustMin))
		for _, sparse := range []bool{false, true} {
			depth := 4
			if sparse {
				depth = 8
			}
			c2 := len(MustAssemble(CCVClaimXScript(depth, treeID, sparse, hl, tree.DustMin), ModeC2)) -
				len(MustAssemble(CCVClaimScript(depth, treeID, sparse, hl, tree.DustMin), ModeC2))
			c0 := len(MustAssemble(CCV0ClaimXScript(depth, treeID, sparse, hl, tree.DustMin), ModeC0)) -
				len(MustAssemble(CCV0ClaimScript(depth, treeID, sparse, hl, tree.DustMin), ModeC0))
			if c2 != 7 || c0 != 4 {
				t.Errorf("hashlock %v sparse %v: exit consent costs %d (0xC2) and %d (0xC0) bytes, want 7 and 4",
					hl, sparse, c2, c0)
			}
		}
	}
	for _, c0 := range []bool{false, true} {
		opts := CCVReferenceOptions(key, c0)
		opts.TreeID, opts.Claim, opts.ClaimX, opts.ClaimHX = treeID, true, true, true
		var names []string
		for _, s := range opts.Scripts(4) {
			names = append(names, s.Name)
		}
		want := "EXIT_1 JOIN_0 JOINK_2 UPDATE EVICT_SUBTREE_1 EVICT_SUBTREE_2 CLAIM CLAIM_X CLAIM_HX"
		if got := joinNames(names); got != want {
			t.Errorf("c0=%v: Scripts(4) = %q, want %q", c0, got, want)
		}
	}
}

func xName(hl bool) string {
	if hl {
		return "CLAIM_HX"
	}
	return "CLAIM_X"
}

// ccv0ScriptFor builds the 0xC0-numerics CCV script named by a golden
// key's profile, depth and name.
func ccv0ScriptFor(profile string, depth int, name string,
	key, treeID [32]byte) ([]Token, error) {

	sparse := profile == "S"
	var n int
	switch {
	case name == "UPDATE":
		return CCV0UpdateScript(depth, key, sparse), nil
	case name == "UPDATE_X":
		return CCV0UpdateXScript(depth, key, sparse), nil
	case name == "SPLIT":
		return CCV0SplitScript(depth, sparse, tree.DustMin), nil
	case name == "CLAIM":
		return CCV0ClaimScript(depth, treeID, sparse, false, tree.DustMin), nil
	case name == "CLAIM_H":
		return CCV0ClaimScript(depth, treeID, sparse, true, tree.DustMin), nil
	case name == "CLAIM_X":
		return CCV0ClaimXScript(depth, treeID, sparse, false, tree.DustMin), nil
	case name == "CLAIM_HX":
		return CCV0ClaimXScript(depth, treeID, sparse, true, tree.DustMin), nil
	case strings.HasSuffix(name, "_TOWER"):
		if _, err := fmt.Sscanf(name, "EXIT_%d_TOWER", &n); err != nil {
			return nil, err
		}
		return CCV0ExitTowerScript(depth, n, treeID, sparse), nil
	case strings.HasPrefix(name, "EXIT_"):
		if _, err := fmt.Sscanf(name, "EXIT_%d", &n); err != nil {
			return nil, err
		}
		return CCV0ExitScript(depth, n, sparse), nil
	case strings.HasPrefix(name, "JOINK_"):
		if _, err := fmt.Sscanf(name, "JOINK_%d", &n); err != nil {
			return nil, err
		}
		return CCV0JoinScript(depth, 0, key, sparse, n), nil
	case strings.HasPrefix(name, "JOIN_"):
		if _, err := fmt.Sscanf(name, "JOIN_%d", &n); err != nil {
			return nil, err
		}
		return CCV0JoinScript(depth, n, key, sparse, 1), nil
	case strings.HasPrefix(name, "EVICT_SUBTREE_"):
		if _, err := fmt.Sscanf(name, "EVICT_SUBTREE_%d", &n); err != nil {
			return nil, err
		}
		return CCV0EvictSubtreeScript(depth, n, key), nil
	case strings.HasPrefix(name, "DETACH_"):
		if _, err := fmt.Sscanf(name, "DETACH_%d", &n); err != nil {
			return nil, err
		}
		return CCV0DetachScript(depth, n, key,
			CCVDetachedTaptreeRoot(n, CCVReferenceOptions(key, true))), nil
	case strings.HasPrefix(name, "REWRITE_X_"):
		if _, err := fmt.Sscanf(name, "REWRITE_X_%d", &n); err != nil {
			return nil, err
		}
		return CCV0RewriteScript(depth, n, key, true), nil
	case strings.HasPrefix(name, "REWRITE_"):
		if _, err := fmt.Sscanf(name, "REWRITE_%d", &n); err != nil {
			return nil, err
		}
		return CCV0RewriteScript(depth, n, key, false), nil
	}
	return nil, fmt.Errorf("unknown CCV0 script name %q", name)
}

// TestCCVRewrite checks REWRITE_h and REWRITE_h^x under CCV in both
// numerics (spec 7.9) against the golden vectors, that CCVTreeOptions
// compiles them in the generator's order (after SPLIT, before DETACH_h) and
// keeps them in a detached child that fits them (7.10 rule 3), and that
// they stay out of CCVAllScripts as every tree-creation parameter does.
func TestCCVRewrite(t *testing.T) {
	g, key := midLoadGolden(t)
	ccvCheckC2(t, g, "CCV/D/D4/REWRITE_2", CCVRewriteScript(4, 2, key, false))
	ccvCheckC2(t, g, "CCV/D/D4/REWRITE_X_2", CCVRewriteScript(4, 2, key, true))
	midCheckScript(t, g, "CCV0/D/D4/REWRITE_2", CCV0RewriteScript(4, 2, key, false))
	midCheckScript(t, g, "CCV0/D/D4/REWRITE_X_2", CCV0RewriteScript(4, 2, key, true))
	for _, c0 := range []bool{false, true} {
		opts := CCVReferenceOptions(key, c0)
		opts.Split, opts.RewriteHeights, opts.RewriteX = true, []int{2, 3}, true
		opts.DetachHeights = []int{3}
		var names []string
		for _, s := range opts.Scripts(4) {
			names = append(names, s.Name)
		}
		want := "EXIT_1 JOIN_0 JOINK_2 UPDATE EVICT_SUBTREE_1 EVICT_SUBTREE_2 SPLIT " +
			"REWRITE_2 REWRITE_X_2 REWRITE_3 REWRITE_X_3 DETACH_3"
		if got := joinNames(names); got != want {
			t.Errorf("c0=%v: Scripts(4) = %q, want %q", c0, got, want)
		}
		// The detached child at depth 2 keeps REWRITE_2 and drops REWRITE_3.
		names = names[:0]
		for _, s := range opts.Scripts(2) {
			names = append(names, s.Name)
		}
		want = "EXIT_1 JOIN_0 JOINK_2 UPDATE EVICT_SUBTREE_1 EVICT_SUBTREE_2 SPLIT REWRITE_2 REWRITE_X_2"
		if got := joinNames(names); got != want {
			t.Errorf("c0=%v: Scripts(2) = %q, want %q", c0, got, want)
		}
	}
	set := CCVAllScripts(4, key, false, []int{0, 2}, []int{1, 2}, []int{2}, []int{1, 2})
	if _, ok := set["REWRITE_2"]; ok {
		t.Error("REWRITE_2 must stay out of CCVAllScripts")
	}
}

// TestCCV0ScriptsMatchGolden assembles every CCV0 golden vector (the CCV
// tier under 0xC0 numerics) and checks the bytes against spec/golden.json.
func TestCCV0ScriptsMatchGolden(t *testing.T) {
	g, key := midLoadGolden(t)
	treeID := midGoldenTreeID(t)
	var checked int
	for k := range g.Scripts {
		if !strings.HasPrefix(k, "CCV0/") {
			continue
		}
		profile, depth, name, err := parseGoldenKey(k)
		if err != nil {
			t.Fatal(err)
		}
		toks, err := ccv0ScriptFor(profile, depth, name, key, treeID)
		if err != nil {
			t.Fatal(err)
		}
		midCheckScript(t, g, k, toks)
		checked++
	}
	if checked < 12 {
		t.Fatalf("checked only %d CCV0 golden scripts", checked)
	}
	t.Logf("checked %d CCV0 golden scripts", checked)
}

// TestCCVExitTower checks EXIT_K^t (spec 7.2 rule 7) under CCV in both
// numerics against its golden keys, built over the tree_id vector every
// tier's golden CLAIM shares, and that CCVTreeOptions with Tower set
// compiles it in EXIT_K's place and keeps it in a detached child (7.10
// rule 3). Like CLAIM it is a tree-creation parameter and stays out of
// CCVAllScripts.
func TestCCVExitTower(t *testing.T) {
	g, key := loadGolden(t)
	treeID := goldenTreeID(t, g)
	fullCheckScript(t, g, "CCV/D/D4/EXIT_1_TOWER", CCVExitTowerScript(4, 1, treeID, false))
	fullCheckScript(t, g, "CCV/S/D8/EXIT_1_TOWER", CCVExitTowerScript(8, 1, treeID, true))
	gm, _ := midLoadGolden(t)
	midCheckScript(t, gm, "CCV0/D/D4/EXIT_1_TOWER", CCV0ExitTowerScript(4, 1, treeID, false))
	midCheckScript(t, gm, "CCV0/S/D8/EXIT_1_TOWER", CCV0ExitTowerScript(8, 1, treeID, true))

	for _, c0 := range []bool{false, true} {
		opts := CCVReferenceOptions(key, c0)
		opts.TreeID, opts.Tower = treeID, true
		mode := ModeC2
		if c0 {
			mode = ModeC0
		}
		for _, depth := range []int{4, 2} {
			got := opts.Scripts(depth)[0]
			want := CCVExitTowerScript(depth, 1, treeID, false)
			if c0 {
				want = CCV0ExitTowerScript(depth, 1, treeID, false)
			}
			if got.Name != "EXIT_1" {
				t.Fatalf("c0=%v: first leaf is %s, want EXIT_1", c0, got.Name)
			}
			if string(MustAssemble(got.Tokens, mode)) != string(MustAssemble(want, mode)) {
				t.Fatalf("c0=%v depth %d: Scripts does not emit EXIT_1^t", c0, depth)
			}
		}
		if opts.TapTreeRoot(4) == CCVReferenceOptions(key, c0).TapTreeRoot(4) {
			t.Fatalf("c0=%v: the tower options compile to the reference m", c0)
		}
	}
}

// TestCCVDetach checks DETACH_h under CCV in both numerics (spec 7.10)
// against the golden vectors, and that m_h is a constant the script
// depends on. DETACH_h is a tree-creation parameter: it stays out of
// CCVAllScripts.
func TestCCVDetach(t *testing.T) {
	g, key := midLoadGolden(t)
	mH := CCVDetachedTaptreeRoot(2, CCVReferenceOptions(key, false))
	ccvCheckC2(t, g, "CCV/D/D4/DETACH_2", CCVDetachScript(4, 2, key, mH))
	mH0 := CCVDetachedTaptreeRoot(2, CCVReferenceOptions(key, true))
	midCheckScript(t, g, "CCV0/D/D4/DETACH_2", CCV0DetachScript(4, 2, key, mH0))
	if mH == mH0 {
		t.Error("the 0xC2 and 0xC0 option sets must not share m_h")
	}
	other := CCVDetachScript(4, 2, key, [32]byte{1})
	if string(MustAssemble(other, ModeC2)) ==
		string(MustAssemble(CCVDetachScript(4, 2, key, mH), ModeC2)) {

		t.Error("DETACH_2 does not depend on m_h")
	}
	set := CCVAllScripts(4, key, false, []int{0, 2}, []int{1, 2}, []int{2}, []int{1, 2})
	if _, ok := set["DETACH_2"]; ok {
		t.Error("DETACH_2 must stay out of CCVAllScripts")
	}
	// The reference options compile to the same set CCVAllScripts builds,
	// so a parent created with them detaches into the reference m_h.
	ref := CCVReferenceOptions(key, false)
	want := CCVAllScripts(4, key, false, ref.JoinHeights, ref.ExitKs, ref.JoinKs, ref.EvictHeights)
	for _, sc := range ref.Scripts(4) {
		w, ok := want[sc.Name]
		if !ok {
			t.Fatalf("reference options emit %s, which CCVAllScripts lacks", sc.Name)
		}
		if string(MustAssemble(w, ModeC2)) != string(MustAssemble(sc.Tokens, ModeC2)) {
			t.Errorf("%s differs between CCVReferenceOptions and CCVAllScripts", sc.Name)
		}
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
