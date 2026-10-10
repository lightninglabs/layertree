package script

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/roasbeef/layertree/tree"
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

// midGoldenTreeID is the tree_id the golden CLAIM scripts were built over
// (goldenTreeID, checked there against the vector's creation outpoint).
func midGoldenTreeID(t *testing.T) [32]byte {
	t.Helper()
	g, _ := loadGolden(t)
	return goldenTreeID(t, g)
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
	all := MidAllScripts(4, key, midGoldenTreeID(t), false, []int{0, 2}, []int{1}, []int{2})
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
	all := MidAllScripts(8, key, midGoldenTreeID(t), true, []int{0, 2}, []int{1}, []int{2})
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
	midCheckScript(t, g, "MID/D/D4/CLAIM", MidClaimScript(4, midGoldenTreeID(t), false))
	midCheckScript(t, g, "MID/S/D8/EXIT_1", MidExitScript(8, 1, true))
	midCheckScript(t, g, "MID/S/D8/UPDATE", MidUpdateScript(8, key, true))
}

// TestMidUpdateX checks the exit-consent UPDATE^x variant (spec 7.4 rule 5)
// in both profiles. It is not part of MidAllScripts: a tree is created with
// either UPDATE or UPDATE^x.
func TestMidUpdateX(t *testing.T) {
	g, key := midLoadGolden(t)
	midCheckScript(t, g, "MID/D/D4/UPDATE_X", MidUpdateXScript(4, key, false))
	midCheckScript(t, g, "MID/S/D8/UPDATE_X", MidUpdateXScript(8, key, true))
}

// TestMidClaimH checks the hash-locked voucher variant CLAIM^h (spec 7.5.1)
// in both profiles. Like UPDATE^x it is not part of MidAllScripts: a tree is
// created with either CLAIM or CLAIM^h, so it stays out of the taptree.
func TestMidClaimH(t *testing.T) {
	g, key := midLoadGolden(t)
	treeID := midGoldenTreeID(t)
	midCheckScript(t, g, "MID/D/D4/CLAIM_H", MidClaimHScript(4, treeID, false))
	midCheckScript(t, g, "MID/S/D8/CLAIM_H", MidClaimHScript(8, treeID, true))

	// The two insertions and the tag swap cost exactly eight bytes.
	for _, tc := range []struct {
		depth  int
		sparse bool
	}{{4, false}, {8, true}} {
		plain := MustAssemble(MidClaimScript(tc.depth, treeID, tc.sparse), ModeC0)
		hl := MustAssemble(MidClaimHScript(tc.depth, treeID, tc.sparse), ModeC0)
		if len(hl)-len(plain) != 8 {
			t.Errorf("depth %d sparse %v: CLAIM^h is %d bytes over CLAIM, "+
				"want 8", tc.depth, tc.sparse, len(hl)-len(plain))
		}
	}

	if _, ok := MidAllScripts(4, key, treeID, false, []int{0, 2}, []int{1},
		[]int{2})["CLAIM_H"]; ok {

		t.Error("CLAIM_H must stay out of MidAllScripts")
	}
}

// TestMidSplit checks SPLIT (spec 7.5.2) in both profiles: CLAIM with the
// owner's transaction signature in place of the voucher. Like CLAIM^h it is a
// tree-creation parameter and stays out of MidAllScripts.
func TestMidSplit(t *testing.T) {
	g, key := midLoadGolden(t)
	midCheckScript(t, g, "MID/D/D4/SPLIT", MidSplitScript(4, false))
	midCheckScript(t, g, "MID/S/D8/SPLIT", MidSplitScript(8, true))

	// Dropping the voucher message reconstruction, with its 33-byte
	// tree_id push, and the OP_CHECKSIGFROMSTACK saves exactly 159 bytes.
	treeID := midGoldenTreeID(t)
	for _, tc := range []struct {
		depth  int
		sparse bool
	}{{4, false}, {8, true}} {
		claim := MustAssemble(MidClaimScript(tc.depth, treeID, tc.sparse), ModeC0)
		split := MustAssemble(MidSplitScript(tc.depth, tc.sparse), ModeC0)
		if len(claim)-len(split) != 159 {
			t.Errorf("depth %d sparse %v: SPLIT is %d bytes under CLAIM, "+
				"want 159", tc.depth, tc.sparse, len(claim)-len(split))
		}
	}

	if _, ok := MidAllScripts(4, key, midGoldenTreeID(t), false, []int{0, 2}, []int{1},
		[]int{2})["SPLIT"]; ok {

		t.Error("SPLIT must stay out of MidAllScripts")
	}
}

// TestMidEvictSubtree checks the MID EVICT_SUBTREE_h port (spec 7.7)
// against the golden vectors. Like FULL's it stays out of MidAllScripts.
func TestMidEvictSubtree(t *testing.T) {
	g, key := midLoadGolden(t)
	midCheckScript(t, g, "MID/D/D4/EVICT_SUBTREE_1",
		MidEvictSubtreeScript(4, 1, key))
	midCheckScript(t, g, "MID/D/D4/EVICT_SUBTREE_2",
		MidEvictSubtreeScript(4, 2, key))

	if _, ok := MidAllScripts(4, key, midGoldenTreeID(t), false, []int{0, 2}, []int{1},
		[]int{2})["EVICT_SUBTREE_2"]; ok {

		t.Error("EVICT_SUBTREE_2 must stay out of MidAllScripts")
	}
}

// TestCCV0Scripts checks the CCV tier's 0xC0-numerics scripts, which reuse
// the MID machinery, against their CCV0 golden keys.
func TestCCV0Scripts(t *testing.T) {
	g, key := midLoadGolden(t)
	midCheckScript(t, g, "CCV0/D/D4/EVICT_SUBTREE_1",
		CCV0EvictSubtreeScript(4, 1, key))
	midCheckScript(t, g, "CCV0/D/D4/EVICT_SUBTREE_2",
		CCV0EvictSubtreeScript(4, 2, key))
	midCheckScript(t, g, "CCV0/D/D4/SPLIT", CCV0SplitScript(4, false))
	midCheckScript(t, g, "CCV0/S/D8/SPLIT", CCV0SplitScript(8, true))
}

func midHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

func midHexAll(t *testing.T, b [][]byte) []string {
	t.Helper()
	out := make([]string, len(b))
	for i, x := range b {
		out[i] = hex.EncodeToString(x)
	}
	return out
}

// midTestLeaf mirrors the leaf the Python cross-check vectors use.
func midTestLeaf(t *testing.T) *tree.Leaf {
	t.Helper()
	l := &tree.Leaf{Amount: 50_000, EvictAfter: 123456, Nonce: 7, Seq: 3}
	copy(l.ExitKey[:], midHex(t,
		"450b7fe2e3a932976676074deeed3630f3ce40630d44e5a6efe6385b05a35e64"))
	copy(l.OwnerKey[:], midHex(t,
		"f3ddd70f56cd181074898e8ec7a923c5d9248b37fc209d0ae2fd2882c6008ff2"))
	copy(l.EvictorKey[:], midHex(t, tree.NUMSHex))
	return l
}

func TestMidScriptNumAndPad(t *testing.T) {
	nums := map[uint64]string{
		0: "", 1: "01", 16: "10", 127: "7f", 128: "8000", 255: "ff00",
		256: "0001", 0x7fff: "ff7f", 0x8000: "008000",
		0x800000: "00008000", 1<<31 - 1: "ffffff7f",
	}
	for n, want := range nums {
		if got := hex.EncodeToString(MidScriptNum(n)); got != want {
			t.Errorf("MidScriptNum(%d) = %s, want %s", n, got, want)
		}
	}
	pads := map[uint64][2]string{
		0: {"00000000", ""}, 1: {"000000", "00"}, 127: {"000000", "00"},
		128: {"0000", "0000"}, 0x8000: {"00", "000000"},
		1<<31 - 1: {"", "00000000"},
	}
	for n, want := range pads {
		z, w := MidPad(n)
		if hex.EncodeToString(z) != want[0] || hex.EncodeToString(w) != want[1] {
			t.Errorf("MidPad(%d) = (%x, %x), want (%s, %s)",
				n, z, w, want[0], want[1])
		}
	}
}

func TestMidLeafAndPosWitness(t *testing.T) {
	l := midTestLeaf(t)
	wantLeaf := []string{
		"50c3000000000000",
		"450b7fe2e3a932976676074deeed3630f3ce40630d44e5a6efe6385b05a35e64",
		"f3ddd70f56cd181074898e8ec7a923c5d9248b37fc209d0ae2fd2882c6008ff2",
		"50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0",
		"40e20100", "07000000", "03000000", "50c300", "00", "000000",
	}
	got := midHexAll(t, MidLeafWitness(l))
	if !slicesEqualStr(got, wantLeaf) {
		t.Fatalf("MidLeafWitness = %v, want %v", got, wantLeaf)
	}
	wantExit := append(append([]string{}, wantLeaf...), "40e201", "00", "000000")
	got = midHexAll(t, MidLeafExitWitness(l))
	if !slicesEqualStr(got, wantExit) {
		t.Fatalf("MidLeafExitWitness = %v, want %v", got, wantExit)
	}
	wantPos := []string{
		"f3ddd70f56cd181074898e8ec7a923c5d9248b37fc209d0ae2fd2882c6008ff2",
		"07000000", "4ea0dad6",
		"6085a8bbde8365a90c3efd8684692fba2cd9e28371926e12875eb7d3",
	}
	got = midHexAll(t, MidPosWitness(l))
	if !slicesEqualStr(got, wantPos) {
		t.Fatalf("MidPosWitness = %v, want %v", got, wantPos)
	}
}

func TestMidLevelsWitness(t *testing.T) {
	mk := func(h string, sum uint64) tree.Node {
		var n tree.Node
		copy(n.Hash[:], midHex(t, h))
		n.Sum = sum
		return n
	}
	path := []tree.PathStep{
		{Dir: false, Sibling: mk("0000000000000000000000000000000000000000000000000000000000000000", 0)},
		{Dir: true, Sibling: mk("8e81b99f94bb2ee972f179d2106fa2811ccbd2d3deb1ec424f5b25cd5b911fc1", 0)},
		{Dir: false, Sibling: mk("8005f64c4322df37fa9418b028ff1278965eee015d3eebe3ddd2aa0ab7226efe", 1_000_000)},
		{Dir: false, Sibling: mk("8424b55832dfe2401e76bc19dff9d4e3da9f700d2c521870de8993ade2c163a9", 0)},
	}
	old := midTestLeaf(t).Node()
	newNode := mk("11507a0e2f5e69d5dfa40a62a1bd7b6ee57e6bcd85c67c9b8431b36fff21c437", 60_000)

	wantDense := []string{
		"00", "000000", "00", "000000", "",
		"8424b55832dfe2401e76bc19dff9d4e3da9f700d2c521870de8993ade2c163a9",
		"", "00000000", "",
		"00", "000000", "00", "000000", "",
		"8005f64c4322df37fa9418b028ff1278965eee015d3eebe3ddd2aa0ab7226efe",
		"40420f", "00", "000000",
		"00", "000000", "00", "000000", "01",
		"8e81b99f94bb2ee972f179d2106fa2811ccbd2d3deb1ec424f5b25cd5b911fc1",
		"", "00000000", "",
		"00", "000000", "00", "000000", "",
		"0000000000000000000000000000000000000000000000000000000000000000",
		"", "00000000", "",
	}
	got := midHexAll(t, MidLevelsWitness(path, old, newNode, false, 0))
	if !slicesEqualStr(got, wantDense) {
		t.Fatalf("MidLevelsWitness dense = %v\nwant %v", got, wantDense)
	}

	wantSparse := append([]string{}, wantDense...)
	// Empty siblings are compressed to the empty string: E_3 at emitted
	// group 0, E_1 at group 2 and E_0 at group 3.
	wantSparse[5] = ""
	wantSparse[23] = ""
	wantSparse[32] = ""
	got = midHexAll(t, MidLevelsWitness(path, old, newNode, true, 0))
	if !slicesEqualStr(got, wantSparse) {
		t.Fatalf("MidLevelsWitness sparse = %v\nwant %v", got, wantSparse)
	}
}

func slicesEqualStr(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
