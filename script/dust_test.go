package script

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/roasbeef/layertree/tree"
)

// dustTestFloor is the non-default DUST_MIN the cross-check below compiles
// at (spec 6.2: an operator MAY set it above the RECOMMENDED 330).
const dustTestFloor = 1000

// dustPythonVectors are the SHA256 digests of the Python generators' carve
// scripts compiled at dust_min = 1000 over the golden tree_id, keyed as
// spec/golden.json keys its scripts. They were produced from tools/ with:
//
//	python3 -c '
//	import hashlib as h, layertree_ref as lt, layertree_scripts as F, \
//	    layertree_mid as M, layertree_min as N, layertree_ccv as CV
//	from script_sim import assemble
//	T = lt.tree_id(lt.sha256(b"creation-txid"), 0); d = 1000
//	for k, toks, mode in [
//	  ("FULL/D/D4/CLAIM", F.claim_script(4, T, "D", dust_min=d), "c2"),
//	  ("FULL/S/D8/SPLIT", F.split_script(8, "S", dust_min=d), "c2"),
//	  ("MID/D/D4/CLAIM", M.claim_script(4, T, False, dust_min=d), "c0"),
//	  ("MID/S/D8/SPLIT", M.split_script(8, True, dust_min=d), "c0"),
//	  ("MIN/D/D4/SPLIT", N.split_script(4, dust_min=d), "c0"),
//	  ("CCV/D/D4/CLAIM", CV.claim_script_ccv(4, T, "D", dust_min=d), "c2"),
//	  ("CCV0/D/D4/CLAIM", CV._claim_script_ccv0(4, T, False, dust_min=d), "c0")]:
//	  print(k, h.sha256(assemble(toks, mode)).hexdigest())'
var dustPythonVectors = map[string]string{
	"FULL/D/D4/CLAIM": "251aeabec852bed96c8a63f3b4f58d378c2e5e1deb6883eb7ac23f310feee56d",
	"FULL/S/D8/SPLIT": "740c93ed9f28966428d05caa07bc8a7953383082d0614e0bcfda3fb4ee170aa9",
	"MID/D/D4/CLAIM":  "cd615ad56fedb4a691ddf143723db22589973dac7fbabb4e6a20f4439131dd36",
	"MID/S/D8/SPLIT":  "2e6285cf5f36add8e94c387288a5d5afd44dc95aa19cca477294aa10b0c2f829",
	"MIN/D/D4/SPLIT":  "329fbadf7318c26fb6524bf3c3e887c7a568b0b3a5e9ad7e29c731ae4d3848ec",
	"CCV/D/D4/CLAIM":  "40e47113b97bdc6b5154f3508e13ca0c8996f9f7e0b9cb6dd13f9ffbea9d6b5c",
	"CCV0/D/D4/CLAIM": "d9e27b4fd03b031062367ac1293440ea1163eef2cc5eba729a526876b61d5834",
}

// dustNamed returns the tokens of the named script in an option set.
func dustNamed(t *testing.T, set []FullNamedScript, name string) []Token {
	t.Helper()
	for _, s := range set {
		if s.Name == name {
			return s.Tokens
		}
	}
	t.Fatalf("option set has no %s script", name)
	return nil
}

// TestCarveDustMinMatchesPython compiles a carve script at DUST_MIN = 1000 in
// every tier and numerics and checks it byte for byte (by digest) against
// the Python generator at the same floor. FULL and CCV go through their
// option structs, so the test also covers the threading of DustMin from
// FullTreeOptions and CCVTreeOptions into the carve body. Each script must
// also differ from its golden 330 form, or the floor was not threaded.
func TestCarveDustMinMatchesPython(t *testing.T) {
	g, key := midLoadGolden(t)
	treeID := midGoldenTreeID(t)

	full := FullTreeOptions{
		OperatorKey: key, TreeID: treeID, Claim: true,
		DustMin: dustTestFloor,
	}
	ccv := CCVTreeOptions{
		OperatorKey: key, TreeID: treeID, Claim: true,
		DustMin: dustTestFloor,
	}
	ccv0 := ccv
	ccv0.C0 = true

	cases := []struct {
		key  string
		toks []Token
		mode Mode
	}{
		{"FULL/D/D4/CLAIM", dustNamed(t, full.Scripts(4), "CLAIM"), ModeC2},
		{"FULL/S/D8/SPLIT", FullSplitScript(8, true, dustTestFloor), ModeC2},
		{"MID/D/D4/CLAIM", MidClaimScript(4, treeID, false, dustTestFloor), ModeC0},
		{"MID/S/D8/SPLIT", MidSplitScript(8, true, dustTestFloor), ModeC0},
		{"MIN/D/D4/SPLIT", MinSplitScript(4, dustTestFloor), ModeC0},
		{"CCV/D/D4/CLAIM", dustNamed(t, ccv.Scripts(4), "CLAIM"), ModeC2},
		{"CCV0/D/D4/CLAIM", dustNamed(t, ccv0.Scripts(4), "CLAIM"), ModeC0},
	}
	for _, tc := range cases {
		got, err := Assemble(tc.toks, tc.mode)
		if err != nil {
			t.Fatalf("%s: assemble: %v", tc.key, err)
		}
		sum := sha256.Sum256(got)
		if hex.EncodeToString(sum[:]) != dustPythonVectors[tc.key] {
			t.Errorf("%s at DUST_MIN %d: digest %x, Python %s",
				tc.key, dustTestFloor, sum, dustPythonVectors[tc.key])
		}
		golden, ok := g.Scripts[tc.key]
		if !ok {
			t.Fatalf("golden key %q missing", tc.key)
		}
		if golden.Hex == hex.EncodeToString(got) {
			t.Errorf("%s: the script at DUST_MIN %d equals the golden "+
				"330 script", tc.key, dustTestFloor)
		}
	}
}

// TestCarveDustMinZeroIsDefault checks that a zero DustMin compiles the
// RECOMMENDED tree.DustMin, so an options struct that leaves the field
// unset builds the golden scripts.
func TestCarveDustMinZeroIsDefault(t *testing.T) {
	treeID := midGoldenTreeID(t)
	zero := MustAssemble(FullClaimScript(4, treeID, false, 0), ModeC2)
	def := MustAssemble(FullClaimScript(4, treeID, false, tree.DustMin), ModeC2)
	if !bytes.Equal(zero, def) {
		t.Fatal("FULL CLAIM at DustMin 0 differs from tree.DustMin")
	}
	zero = MustAssemble(MidClaimScript(4, treeID, false, 0), ModeC0)
	def = MustAssemble(MidClaimScript(4, treeID, false, tree.DustMin), ModeC0)
	if !bytes.Equal(zero, def) {
		t.Fatal("MID CLAIM at DustMin 0 differs from tree.DustMin")
	}
	if got := (FullTreeOptions{}).DustFloor(); got != tree.DustMin {
		t.Fatalf("FullTreeOptions{}.DustFloor() = %d, want %d", got,
			tree.DustMin)
	}
	if got := (CCVTreeOptions{DustMin: 1000}).DustFloor(); got != 1000 {
		t.Fatalf("CCVTreeOptions.DustFloor() = %d, want 1000", got)
	}
}
