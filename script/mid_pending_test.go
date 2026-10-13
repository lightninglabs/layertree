package script

import (
	"crypto/sha256"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/roasbeef/layertree/tree"
)

// midGoldenReclaimKey is the RECLAIM_KEY the golden pending-receive scripts
// were built over: the x-only key of the secret sha256("operator-reclaim")
// (tools/gen_golden.py MID_RECLAIM_KEY).
func midGoldenReclaimKey() [32]byte {
	sk := sha256.Sum256([]byte("operator-reclaim"))
	priv, _ := btcec.PrivKeyFromBytes(sk[:])
	var out [32]byte
	copy(out[:], schnorr.SerializePubKey(priv.PubKey()))
	return out
}

// TestMidPendingReceive checks the MID pending-leaf receive ports (spec
// 7.5.4, 7.9 rule 8, 7.11) against their golden keys: CLAIM^m and CLAIM^hm,
// RECLAIM_1 in both profiles, and the reclaim form of REWRITE_2 and its ^x
// form.
func TestMidPendingReceive(t *testing.T) {
	g, key := midLoadGolden(t)
	tid := midGoldenTreeID(t)
	rk := midGoldenReclaimKey()
	midCheckScript(t, g, "MID/D/D4/CLAIM_M", MidMergeScript(4, tid, false, &rk, tree.DustMin))
	midCheckScript(t, g, "MID/D/D4/CLAIM_HM", MidMergeScript(4, tid, true, &rk, 0))
	midCheckScript(t, g, "MID/D/D4/RECLAIM_1", MidReclaimScript(4, rk, false))
	midCheckScript(t, g, "MID/S/D8/RECLAIM_1", MidReclaimScript(8, rk, true))
	midCheckScript(t, g, "MID/D/D4/REWRITE_R_2", MidRewriteRScript(4, 2, key, false, rk))
	midCheckScript(t, g, "MID/D/D4/REWRITE_XR_2", MidRewriteRScript(4, 2, key, true, rk))

	// The option set names and orders them as TreeOptions.at_depth does,
	// and a RECLAIM_KEY turns every REWRITE_h into its reclaim form.
	opts := MidTreeOptions{
		OperatorKey: key, TreeID: tid, ExitKs: []int{1}, UpdateX: true,
		ClaimX: true, RewriteHeights: []int{1, 2}, RewriteX: true,
		ReclaimKey: &rk, ClaimM: true, ClaimHM: true,
	}
	var names []string
	for _, s := range opts.Scripts(4) {
		names = append(names, s.Name)
	}
	want := []string{"EXIT_1", "UPDATE_X", "CLAIM_X", "RECLAIM_1", "CLAIM_M",
		"CLAIM_HM", "REWRITE_R_1", "REWRITE_XR_1", "REWRITE_R_2", "REWRITE_XR_2"}
	if len(names) != len(want) {
		t.Fatalf("option set %v, want %v", names, want)
	}
	for i := range want {
		if names[i] != want[i] {
			t.Fatalf("option set %v, want %v", names, want)
		}
	}
	opts.Sparse = true
	var sparse []string
	for _, s := range opts.Scripts(8) {
		sparse = append(sparse, s.Name)
	}
	if sparse[len(sparse)-1] != "RECLAIM_1" {
		t.Fatalf("sparse option set %v must end with RECLAIM_1", sparse)
	}
}
