package script

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"

	ts "github.com/btcsuite/btcd/txscript"

	"github.com/roasbeef/layertree/tree"
)

// goldenScript is one entry of spec/golden.json's "scripts" map.
type goldenScript struct {
	Hex         string `json:"hex"`
	LeafVersion int    `json:"leaf_version"`
	TapleafHash string `json:"tapleaf_hash"`
}

// goldenFile is the subset of spec/golden.json this package checks.
type goldenFile struct {
	OperatorKey string `json:"operator_key"`
	TreeID      struct {
		Txid   string `json:"txid"`
		Vout   uint32 `json:"vout"`
		TreeID string `json:"tree_id"`
	} `json:"tree_id"`
	Scripts   map[string]goldenScript `json:"scripts"`
	TaptreeD4 struct {
		LeafHashes []string `json:"leaf_hashes"`
		MerkleRoot string   `json:"merkle_root"`
	} `json:"taptree_full_d4"`
}

func loadGolden(t *testing.T) (*goldenFile, [32]byte) {
	t.Helper()
	raw, err := os.ReadFile("../spec/golden.json")
	if err != nil {
		t.Fatalf("read golden.json: %v", err)
	}
	var g goldenFile
	if err := json.Unmarshal(raw, &g); err != nil {
		t.Fatalf("parse golden.json: %v", err)
	}
	kb, err := hex.DecodeString(g.OperatorKey)
	if err != nil || len(kb) != 32 {
		t.Fatalf("bad operator_key %q", g.OperatorKey)
	}
	var key [32]byte
	copy(key[:], kb)
	return &g, key
}

// goldenTreeID is the tree_id every golden CLAIM was built over, checked
// against the RECOMMENDED derivation (spec 6.2) from the vector's creation
// outpoint.
func goldenTreeID(t *testing.T, g *goldenFile) [32]byte {
	t.Helper()
	txb, err := hex.DecodeString(g.TreeID.Txid)
	if err != nil || len(txb) != 32 {
		t.Fatalf("bad tree_id txid %q", g.TreeID.Txid)
	}
	var txid [32]byte
	copy(txid[:], txb)
	id := tree.TreeID(txid, g.TreeID.Vout)
	if hex.EncodeToString(id[:]) != g.TreeID.TreeID {
		t.Fatalf("tree_id %x, want %s", id, g.TreeID.TreeID)
	}
	return id
}

// fullScriptFor builds the FULL-tier script named by a golden key's profile,
// depth and name, e.g. ("D", 4, "JOINK_2").
func fullScriptFor(profile string, depth int, name string,
	key, treeID [32]byte) ([]Token, error) {

	sparse := profile == "S"
	var n int
	switch {
	case name == "UPDATE":
		return FullUpdateScript(depth, key, sparse), nil
	case name == "UPDATE_X":
		return FullUpdateXScript(depth, key, sparse), nil
	case name == "CLAIM":
		return FullClaimScript(depth, treeID, sparse, tree.DustMin), nil
	case name == "CLAIM_H":
		return FullClaimHScript(depth, treeID, sparse, tree.DustMin), nil
	case name == "CLAIM_X":
		return FullClaimXScript(depth, treeID, sparse, tree.DustMin), nil
	case name == "CLAIM_HX":
		return FullClaimHXScript(depth, treeID, sparse, tree.DustMin), nil
	case name == "SPLIT":
		return FullSplitScript(depth, sparse, tree.DustMin), nil
	case name == "DETACH_2_HOST":
		// A channel-hosting parent (exact payouts, CLAIM^h, DETACH_2):
		// its DETACH_2 embeds that option set compiled at depth 2.
		return FullDetachScript(depth, 2, key,
			FullDetachedTaptreeRoot(2, fullHostOptions(key, treeID))), nil
	case strings.HasSuffix(name, "_EXACT"):
		if _, err := fmt.Sscanf(name, "EXIT_%d_EXACT", &n); err != nil {
			return nil, err
		}
		return FullExitExactScript(depth, n, sparse), nil
	case strings.HasPrefix(name, "EXIT_"):
		if _, err := fmt.Sscanf(name, "EXIT_%d", &n); err != nil {
			return nil, err
		}
		return FullExitScript(depth, n, sparse), nil
	case strings.HasPrefix(name, "JOINK_"):
		if _, err := fmt.Sscanf(name, "JOINK_%d", &n); err != nil {
			return nil, err
		}
		return FullJoinScript(depth, 0, key, sparse, n), nil
	case strings.HasPrefix(name, "JOIN_"):
		if _, err := fmt.Sscanf(name, "JOIN_%d", &n); err != nil {
			return nil, err
		}
		return FullJoinScript(depth, n, key, sparse, 1), nil
	case strings.HasPrefix(name, "EVICT_SUBTREE_"):
		if _, err := fmt.Sscanf(name, "EVICT_SUBTREE_%d", &n); err != nil {
			return nil, err
		}
		return FullEvictSubtreeScript(depth, n, key), nil
	case strings.HasPrefix(name, "REWRITE_X_"):
		if _, err := fmt.Sscanf(name, "REWRITE_X_%d", &n); err != nil {
			return nil, err
		}
		return FullRewriteScript(depth, n, key, true), nil
	case strings.HasPrefix(name, "REWRITE_"):
		if _, err := fmt.Sscanf(name, "REWRITE_%d", &n); err != nil {
			return nil, err
		}
		return FullRewriteScript(depth, n, key, false), nil
	case strings.HasPrefix(name, "DETACH_"):
		if _, err := fmt.Sscanf(name, "DETACH_%d", &n); err != nil {
			return nil, err
		}
		return FullDetachScript(depth, n, key,
			FullDetachedTaptreeRoot(n, FullReferenceOptions(key, treeID))), nil
	}
	return nil, fmt.Errorf("unknown script name %q", name)
}

// fullHostOptions is the option set of a tree that hosts channel leaves
// (Appendix C.6.1, 9.6.2): the reference set with exact payouts, CLAIM^h
// and DETACH_2, as the Python suite's test_detach_options builds it.
func fullHostOptions(key, treeID [32]byte) FullTreeOptions {
	o := FullReferenceOptions(key, treeID)
	o.Exact, o.ClaimH, o.DetachHeights = true, true, []int{2}
	return o
}

// parseGoldenKey splits "FULL/D/D4/EXIT_1" into its parts.
func parseGoldenKey(key string) (profile string, depth int, name string,
	err error) {

	parts := strings.Split(key, "/")
	if len(parts) != 4 {
		return "", 0, "", fmt.Errorf("malformed key %q", key)
	}
	if _, err := fmt.Sscanf(parts[2], "D%d", &depth); err != nil {
		return "", 0, "", fmt.Errorf("bad depth in %q: %w", key, err)
	}
	return parts[1], depth, parts[3], nil
}

// tokenString renders one token the way the Python disassembler would.
func tokenString(t Token) string {
	switch t.kind {
	case tokOp:
		if name, ok := opNames[t.Op]; ok {
			return name
		}
		return fmt.Sprintf("OP_0x%02x", t.Op)
	case tokNum:
		return fmt.Sprintf("<num %d>", t.Num)
	default:
		if len(t.Data) <= 8 {
			return fmt.Sprintf("<data %x>", t.Data)
		}
		return fmt.Sprintf("<data[%d] %x..>", len(t.Data), t.Data[:8])
	}
}

// opNames covers the opcodes the FULL templates emit, for diagnostics.
var opNames = map[byte]string{
	ts.OP_0: "OP_0", ts.OP_1: "OP_1", ts.OP_IF: "OP_IF",
	ts.OP_NOTIF: "OP_NOTIF", ts.OP_ELSE: "OP_ELSE", ts.OP_ENDIF: "OP_ENDIF",
	ts.OP_VERIFY: "OP_VERIFY", ts.OP_TOALTSTACK: "OP_TOALTSTACK",
	ts.OP_FROMALTSTACK: "OP_FROMALTSTACK", ts.OP_2DROP: "OP_2DROP",
	ts.OP_2DUP: "OP_2DUP", ts.OP_2SWAP: "OP_2SWAP", ts.OP_DROP: "OP_DROP",
	ts.OP_DUP: "OP_DUP", ts.OP_NIP: "OP_NIP", ts.OP_OVER: "OP_OVER",
	ts.OP_PICK: "OP_PICK", ts.OP_ROLL: "OP_ROLL", ts.OP_ROT: "OP_ROT",
	ts.OP_SWAP: "OP_SWAP", ts.OP_TUCK: "OP_TUCK", OP_CAT: "OP_CAT",
	OP_SUBSTR: "OP_SUBSTR", OP_LEFT: "OP_LEFT", OP_RIGHT: "OP_RIGHT",
	ts.OP_SIZE: "OP_SIZE", OP_AND: "OP_AND", ts.OP_EQUAL: "OP_EQUAL",
	ts.OP_EQUALVERIFY: "OP_EQUALVERIFY", ts.OP_1ADD: "OP_1ADD",
	ts.OP_NOT: "OP_NOT", ts.OP_0NOTEQUAL: "OP_0NOTEQUAL",
	ts.OP_ADD: "OP_ADD", ts.OP_SUB: "OP_SUB", OP_DOWNSHIFT: "OP_DOWNSHIFT",
	ts.OP_NUMEQUAL: "OP_NUMEQUAL", ts.OP_NUMEQUALVERIFY: "OP_NUMEQUALVERIFY",
	ts.OP_LESSTHANOREQUAL: "OP_LESSTHANOREQUAL", ts.OP_SHA256: "OP_SHA256",
	ts.OP_CHECKSIGVERIFY:       "OP_CHECKSIGVERIFY",
	ts.OP_CHECKLOCKTIMEVERIFY:  "OP_CHECKLOCKTIMEVERIFY",
	OP_TX:                      "OP_TX",
	OP_EC_POINT_ADD:            "OP_EC_POINT_ADD",
	OP_EC_POINT_MUL:            "OP_EC_POINT_MUL",
	OP_EC_POINT_X_COORD:        "OP_EC_POINT_X_COORD",
	byte(OP_CHECKSIGFROMSTACK): "OP_CHECKSIGFROMSTACK",
}

// reportMismatch prints the first differing byte offset together with the
// tokens around it in both scripts.
func reportMismatch(t *testing.T, key string, toks []Token, got, want []byte) {
	t.Helper()
	off := -1
	for i := 0; i < len(got) && i < len(want); i++ {
		if got[i] != want[i] {
			off = i
			break
		}
	}
	if off < 0 {
		off = min(len(got), len(want))
	}

	// Map every token to its byte offset in the generated script.
	offsets := make([]int, len(toks))
	cur := 0
	for i, tok := range toks {
		offsets[i] = cur
		b := MustAssemble([]Token{tok}, ModeC2)
		cur += len(b)
	}
	idx := 0
	for i := range toks {
		if offsets[i] <= off {
			idx = i
		}
	}
	lo, hi := max(0, idx-4), min(len(toks), idx+5)
	var b strings.Builder
	for i := lo; i < hi; i++ {
		marker := "  "
		if i == idx {
			marker = ">>"
		}
		fmt.Fprintf(&b, "\n  %s [%d] @%d %s", marker, i, offsets[i],
			tokenString(toks[i]))
	}
	gl, wl := min(len(got), off+8), min(len(want), off+8)
	t.Errorf("%s: script mismatch at byte %d (got %d bytes, want %d)\n"+
		"  got  ...%x\n  want ...%x\ntokens:%s",
		key, off, len(got), len(want), got[max(0, off-8):gl],
		want[max(0, off-8):wl], b.String())
}

// TestFullScriptsMatchGolden checks every FULL-tier golden vector: the
// compiled script bytes and the tapleaf hash (spec section 8).
func TestFullScriptsMatchGolden(t *testing.T) {
	g, key := loadGolden(t)
	treeID := goldenTreeID(t, g)

	var checked int
	for k, want := range g.Scripts {
		if !strings.HasPrefix(k, "FULL/") {
			continue
		}
		k, want := k, want
		t.Run(strings.ReplaceAll(k, "/", "_"), func(t *testing.T) {
			profile, depth, name, err := parseGoldenKey(k)
			if err != nil {
				t.Fatal(err)
			}
			toks, err := fullScriptFor(profile, depth, name, key, treeID)
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
			// The tapleaf hash commits to version || compactsize || script.
			lh := TapLeafHash(got, byte(want.LeafVersion))
			if hex.EncodeToString(lh[:]) != want.TapleafHash {
				t.Errorf("%s: tapleaf hash %x, want %s", k, lh,
					want.TapleafHash)
			}
		})
		checked++
	}
	if checked == 0 {
		t.Fatal("no FULL golden vectors found")
	}
	t.Logf("checked %d FULL golden scripts", checked)
}

// fullCheckScript compares one generated script against its golden vector,
// both the compiled bytes and the tapleaf hash.
func fullCheckScript(t *testing.T, g *goldenFile, key string, toks []Token) {
	t.Helper()

	want, ok := g.Scripts[key]
	if !ok {
		t.Fatalf("no golden vector for %s", key)
	}
	got, err := Assemble(toks, ModeC2)
	if err != nil {
		t.Fatalf("%s: assemble: %v", key, err)
	}
	wantBytes, err := hex.DecodeString(want.Hex)
	if err != nil {
		t.Fatalf("%s: bad golden hex: %v", key, err)
	}
	if string(got) != string(wantBytes) {
		reportMismatch(t, key, toks, got, wantBytes)
		return
	}
	lh := TapLeafHash(got, byte(want.LeafVersion))
	if hex.EncodeToString(lh[:]) != want.TapleafHash {
		t.Fatalf("%s: tapleaf hash %x, want %s", key, lh, want.TapleafHash)
	}
}

// TestFullClaimH checks the hash-locked voucher variant CLAIM^h (spec 7.5.1)
// in both profiles. Like UPDATE^x it is not part of FullAllScripts: a tree is
// created with either CLAIM or CLAIM^h, so it stays out of the reference
// taptree.
func TestFullClaimH(t *testing.T) {
	g, key := loadGolden(t)
	treeID := goldenTreeID(t, g)

	fullCheckScript(t, g, "FULL/D/D4/CLAIM_H", FullClaimHScript(4, treeID, false, tree.DustMin))
	fullCheckScript(t, g, "FULL/S/D8/CLAIM_H", FullClaimHScript(8, treeID, true, tree.DustMin))

	// The two insertions and the tag swap cost exactly eight bytes.
	for _, tc := range []struct {
		depth  int
		sparse bool
	}{{4, false}, {8, true}} {
		plain := MustAssemble(FullClaimScript(tc.depth, treeID, tc.sparse, tree.DustMin), ModeC2)
		hl := MustAssemble(FullClaimHScript(tc.depth, treeID, tc.sparse, tree.DustMin), ModeC2)
		if len(hl)-len(plain) != 8 {
			t.Errorf("depth %d sparse %v: CLAIM^h is %d bytes over CLAIM, "+
				"want 8", tc.depth, tc.sparse, len(hl)-len(plain))
		}
	}

	if _, ok := FullAllScripts(4, key, treeID, false, []int{0, 2}, []int{1, 2},
		[]int{2}, tree.DustMin)["CLAIM_H"]; ok {

		t.Error("CLAIM_H must stay out of FullAllScripts")
	}
}

// TestFullClaimX checks the exit-consent carves CLAIM^x and CLAIM^hx (spec
// 7.5.3) in both profiles. Like UPDATE^x they are tree-creation parameters
// and stay out of FullAllScripts.
func TestFullClaimX(t *testing.T) {
	g, key := loadGolden(t)
	treeID := goldenTreeID(t, g)

	fullCheckScript(t, g, "FULL/D/D4/CLAIM_X", FullClaimXScript(4, treeID, false, tree.DustMin))
	fullCheckScript(t, g, "FULL/S/D8/CLAIM_X", FullClaimXScript(8, treeID, true, tree.DustMin))
	fullCheckScript(t, g, "FULL/D/D4/CLAIM_HX", FullClaimHXScript(4, treeID, false, tree.DustMin))
	fullCheckScript(t, g, "FULL/S/D8/CLAIM_HX", FullClaimHXScript(8, treeID, true, tree.DustMin))

	// The exit-key check costs exactly seven bytes over the plain form in
	// both the plain and the hash-locked carve, as UPDATE^x over UPDATE.
	for _, tc := range []struct {
		depth  int
		sparse bool
	}{{4, false}, {8, true}} {
		plain := MustAssemble(FullClaimScript(tc.depth, treeID, tc.sparse, tree.DustMin), ModeC2)
		x := MustAssemble(FullClaimXScript(tc.depth, treeID, tc.sparse, tree.DustMin), ModeC2)
		if len(x)-len(plain) != 7 {
			t.Errorf("depth %d sparse %v: CLAIM^x is %d bytes over CLAIM, "+
				"want 7", tc.depth, tc.sparse, len(x)-len(plain))
		}
		h := MustAssemble(FullClaimHScript(tc.depth, treeID, tc.sparse, tree.DustMin), ModeC2)
		hx := MustAssemble(FullClaimHXScript(tc.depth, treeID, tc.sparse, tree.DustMin), ModeC2)
		if len(hx)-len(h) != 7 {
			t.Errorf("depth %d sparse %v: CLAIM^hx is %d bytes over CLAIM^h, "+
				"want 7", tc.depth, tc.sparse, len(hx)-len(h))
		}
	}

	set := FullAllScripts(4, key, treeID, false, []int{0, 2}, []int{1, 2}, []int{2}, tree.DustMin)
	for _, name := range []string{"CLAIM_X", "CLAIM_HX"} {
		if _, ok := set[name]; ok {
			t.Errorf("%s must stay out of FullAllScripts", name)
		}
	}
}

// TestFullSplit checks SPLIT (spec 7.5.2), the carve authorised by the
// owner's transaction signature, in both profiles. Like CLAIM^h it is a
// tree-creation parameter and stays out of FullAllScripts.
func TestFullSplit(t *testing.T) {
	g, key := loadGolden(t)
	treeID := goldenTreeID(t, g)

	fullCheckScript(t, g, "FULL/D/D4/SPLIT", FullSplitScript(4, false, tree.DustMin))
	fullCheckScript(t, g, "FULL/S/D8/SPLIT", FullSplitScript(8, true, tree.DustMin))

	// Replacing the voucher message, with its 33-byte tree_id push, and
	// OP_CHECKSIGFROMSTACK with an OP_CHECKSIGVERIFY over src.owner_key
	// saves exactly 109 bytes.
	for _, tc := range []struct {
		depth  int
		sparse bool
	}{{4, false}, {8, true}} {
		claim := MustAssemble(FullClaimScript(tc.depth, treeID, tc.sparse, tree.DustMin), ModeC2)
		split := MustAssemble(FullSplitScript(tc.depth, tc.sparse, tree.DustMin), ModeC2)
		if len(claim)-len(split) != 109 {
			t.Errorf("depth %d sparse %v: SPLIT is %d bytes under CLAIM, "+
				"want 109", tc.depth, tc.sparse, len(claim)-len(split))
		}
	}

	if _, ok := FullAllScripts(4, key, treeID, false, []int{0, 2}, []int{1, 2},
		[]int{2}, tree.DustMin)["SPLIT"]; ok {

		t.Error("SPLIT must stay out of FullAllScripts")
	}
}

// TestFullRewriteDetach checks the cohort rewrite REWRITE_h, its ^x form and
// DETACH_h (spec 7.9, 7.10) against their golden vectors. All three are
// tree-creation variants: they stay out of FullAllScripts and out of the
// reference taptree root.
func TestFullRewriteDetach(t *testing.T) {
	g, key := loadGolden(t)
	treeID := goldenTreeID(t, g)

	fullCheckScript(t, g, "FULL/D/D4/REWRITE_2",
		FullRewriteScript(4, 2, key, false))
	fullCheckScript(t, g, "FULL/D/D4/REWRITE_X_2",
		FullRewriteScript(4, 2, key, true))
	mH := FullDetachedTaptreeRoot(2, FullReferenceOptions(key, treeID))
	fullCheckScript(t, g, "FULL/D/D4/DETACH_2", FullDetachScript(4, 2, key, mH))

	// m_h is a constant of the DETACH script: a different detached script
	// set gives different bytes, so the parent's m commits to it.
	other := FullDetachScript(4, 2, key, [32]byte{1})
	if string(MustAssemble(other, ModeC2)) ==
		string(MustAssemble(FullDetachScript(4, 2, key, mH), ModeC2)) {

		t.Error("DETACH_2 does not depend on m_h")
	}

	set := FullAllScripts(4, key, treeID, false, []int{0, 2}, []int{1, 2}, []int{2}, tree.DustMin)
	for _, name := range []string{"REWRITE_2", "REWRITE_X_2", "DETACH_2"} {
		if _, ok := set[name]; ok {
			t.Errorf("%s must stay out of FullAllScripts", name)
		}
	}
}

// fullD4Order is the insertion order gen_golden.py uses for the FULL/D/D4
// taptree, i.e. all_scripts() followed by EVICT_SUBTREE_2.
var fullD4Order = []string{
	"EXIT_1", "EXIT_2", "JOIN_0", "JOIN_2", "JOINK_2", "UPDATE", "CLAIM",
	"EVICT_SUBTREE_2",
}

// TestFullTaptreeD4 rebuilds the FULL/D/D4 taptree from the generated
// scripts and checks its leaf hashes and merkle root (spec 6.3).
func TestFullTaptreeD4(t *testing.T) {
	g, key := loadGolden(t)
	treeID := goldenTreeID(t, g)

	leaves := make([][32]byte, 0, len(fullD4Order))
	for i, name := range fullD4Order {
		toks, err := fullScriptFor("D", 4, name, key, treeID)
		if err != nil {
			t.Fatal(err)
		}
		lh := TapLeafHash(MustAssemble(toks, ModeC2), 0xc2)
		if got, want := hex.EncodeToString(lh[:]),
			g.TaptreeD4.LeafHashes[i]; got != want {
			t.Fatalf("leaf %d (%s): hash %s, want %s", i, name, got, want)
		}
		leaves = append(leaves, lh)
	}
	if len(leaves) != len(g.TaptreeD4.LeafHashes) {
		t.Fatalf("leaf count %d, want %d", len(leaves),
			len(g.TaptreeD4.LeafHashes))
	}

	root := TapTreeRoot(leaves)
	if got := hex.EncodeToString(root[:]); got != g.TaptreeD4.MerkleRoot {
		t.Fatalf("merkle root %s, want %s", got, g.TaptreeD4.MerkleRoot)
	}
}

// TestFullTreeOptions checks the option set of spec 6.2 as DETACH_h uses
// it (7.10 rule 3): the reference options at depth 4 are the FULL/D/D4
// golden set in its order, EXIT_K^= matches its golden vector, the
// channel-hosting parent's DETACH_2 (exact payouts, CLAIM^h) embeds a
// different m_h from the reference one and matches the Python generator's,
// and the child set at depth 2 keeps the parent's options.
func TestFullTreeOptions(t *testing.T) {
	g, key := loadGolden(t)
	treeID := goldenTreeID(t, g)

	ref := FullReferenceOptions(key, treeID)
	ref.JoinHeights = []int{0, 2}
	for i, s := range ref.Scripts(4) {
		if want := fullD4Order[i]; s.Name != want {
			t.Fatalf("reference set leaf %d is %s, want %s", i, s.Name, want)
		}
		fullCheckScript(t, g, "FULL/D/D4/"+s.Name, s.Tokens)
	}
	fullCheckScript(t, g, "FULL/D/D4/EXIT_1_EXACT", FullExitExactScript(4, 1, false))
	fullCheckScript(t, g, "FULL/D/D4/DETACH_2_HOST",
		FullDetachScript(4, 2, key, FullDetachedTaptreeRoot(2, fullHostOptions(key, treeID))))

	host := fullHostOptions(key, treeID)
	if host.TapTreeRoot(2) == FullReferenceOptions(key, treeID).TapTreeRoot(2) {
		t.Fatal("the host options compile to the reference m_h at depth 2")
	}
	var names []string
	for _, s := range host.Scripts(2) {
		names = append(names, s.Name)
	}
	want := "EXIT_1 EXIT_2 JOIN_0 JOINK_2 UPDATE CLAIM CLAIM_H"
	if got := strings.Join(names, " "); got != want {
		t.Fatalf("host child set at depth 2 is %q, want %q", got, want)
	}
	// The child's EXIT_1 is the exact-payout form, as the parent's.
	child := host.Scripts(2)[0].Tokens
	if string(MustAssemble(child, ModeC2)) != string(MustAssemble(FullExitExactScript(2, 1, false), ModeC2)) {
		t.Fatal("the child's EXIT_1 is not the exact-payout variant")
	}
	// A deeper parent keeps DETACH_2 itself, built over the same m_h.
	for _, s := range host.Scripts(4) {
		if s.Name == "DETACH_2" {
			fullCheckScript(t, g, "FULL/D/D4/DETACH_2_HOST", s.Tokens)
		}
	}
}

// TestFullAllScripts checks that the exported set generator produces the
// same scripts under the Python naming.
func TestFullAllScripts(t *testing.T) {
	g, key := loadGolden(t)
	treeID := goldenTreeID(t, g)

	set := FullAllScripts(4, key, treeID, false, []int{0, 2}, []int{1, 2}, []int{2}, tree.DustMin)
	for name, toks := range set {
		want, ok := g.Scripts["FULL/D/D4/"+name]
		if !ok {
			t.Fatalf("no golden vector for %s", name)
		}
		if got := hex.EncodeToString(MustAssemble(toks, ModeC2)); got != want.Hex {
			t.Errorf("FULL/D/D4/%s differs from golden", name)
		}
	}
	if len(set) != 7 {
		t.Errorf("all_scripts returned %d entries, want 7", len(set))
	}

	sset := FullAllScripts(8, key, treeID, true, nil, []int{1}, []int{2}, tree.DustMin)
	for name, toks := range sset {
		want, ok := g.Scripts["FULL/S/D8/"+name]
		if !ok {
			t.Fatalf("no golden vector for sparse %s", name)
		}
		if got := hex.EncodeToString(MustAssemble(toks, ModeC2)); got != want.Hex {
			t.Errorf("FULL/S/D8/%s differs from golden", name)
		}
	}
}
