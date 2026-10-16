package txn

import (
	"encoding/json"
	"os"
	"testing"
)

// Exercise the supported 0xC2 sparse tiers at the uint64 position boundary.
// The existing cases also test signatures, outputs and witness assembly.
func TestDepth64Transitions(t *testing.T) {
	for _, tier := range []Tier{Full, CCV} {
		for _, c := range tierCases(tier, 64, true) {
			t.Run(c.key(), func(t *testing.T) {
				w := newWorld(t, c.caseSpec)
				spend, next, err := c.build(w)
				if err != nil {
					t.Fatalf("build: %v", err)
				}
				checkSpend(t, w, w.st.Tree, spend, next)
				if c.tamper != nil {
					c.tamper(spend)
				}
				if os.Getenv("LAYERTREE_BOUNDARY_DUMP") != "" {
					sighash, err := spend.Sighash()
					if err != nil {
						t.Fatal(err)
					}
					if err := recordDump(&c, w, spend, sighash); err != nil {
						t.Fatal(err)
					}
				}
			})
		}
	}
	if path := os.Getenv("LAYERTREE_BOUNDARY_DUMP"); path != "" {
		raw, err := json.MarshalIndent(dumpCases, "", " ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, raw, 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func TestDetachRightmostSubtree(t *testing.T) {
	w := newWorld(t, caseSpec{tier: Full, depth: 64, variants: []string{"DETACH_2"}})
	w.base()
	index := ^uint64(0) >> 2
	w.cohort(2, index, false)
	want := w.st.Tree.Subtree(2, index)
	spend, host, child, err := BuildDetach(w.st, 2, index, &TxOpts{Inputs: w.fee(5_000)})
	if err != nil {
		t.Fatal(err)
	}
	checkSpend(t, w, w.st.Tree, spend, host)
	if got := child.Tree.Root(); got != want {
		t.Fatalf("child root %x/%d, want %x/%d", got.Hash, got.Sum, want.Hash, want.Sum)
	}
	if len(child.Tree.Leaves) != 4 {
		t.Fatalf("child has %d leaves, want 4", len(child.Tree.Leaves))
	}
	if got := host.Subtree(2, index); got.Sum != 0 {
		t.Fatalf("host retained detached balance %d", got.Sum)
	}
}
