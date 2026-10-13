package txn

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"testing"

	"github.com/btcsuite/btcd/wire"

	"github.com/roasbeef/layertree/script"
	"github.com/roasbeef/layertree/tree"
)

// The pending-leaf receive end to end (spec 7.5.4, 7.9 rule 8, 7.11), as
// tools/test_scripts.py's PendingWorld lays it out: a pending leaf P owned
// by the operator ("operator-owner"), paid to the recipient ("rcpt-exit"),
// reclaimable at height 700,000, and the recipient's landing leaf L at its
// sibling, owned by and exiting to the recipient. The cases run inside
// TestTransitionsEndToEnd (tierCases adds them to the FULL matrix) and the
// negatives in TestPendingRejects.

// pendingDeadline is P's evict_after, the height RECLAIM_1 and an R1
// reclaim wait for.
const pendingDeadline = 700_000

// pendingReclaimKey is the suite's RECLAIM_KEY, x(sha256("operator-reclaim")).
func pendingReclaimKey() [32]byte { return xonly(sk("operator-reclaim")) }

// pendingOptions is PendingWorld's option set: EXIT_1 (exact), JOIN_0,
// JOINK_2, CLAIM^x, RECLAIM_1, CLAIM^m, CLAIM^hm and the reclaim form of
// REWRITE_h at heights 1 and 2 with its ^x form. With exitConsent the tree
// carries UPDATE^x (the credit-leaf configuration), so its rewrites are
// REWRITE_XR_h (7.9 rule 7); without it UPDATE, and the builders accept
// REWRITE_R_h too.
func pendingOptions(opKey, treeID [32]byte, sparse,
	exitConsent bool) script.FullTreeOptions {

	rk := pendingReclaimKey()
	return script.FullTreeOptions{
		OperatorKey: opKey, TreeID: treeID, Sparse: sparse,
		ExitKs: []int{1}, JoinHeights: []int{0}, JoinKs: []int{2},
		Exact: true, UpdateX: exitConsent, ClaimX: exitConsent,
		RewriteHeights: []int{1, 2}, RewriteX: true,
		ReclaimKey: &rk, ClaimM: true, ClaimHM: true,
	}
}

// pendingLeaf is PendingWorld.pending: P, reclaimable at deadline.
func (w *world) pendingLeaf(amount uint64, deadline uint32,
	label string) *tree.Leaf {

	h := sha256.Sum256([]byte(label))
	return &tree.Leaf{
		Amount: amount, ExitKey: xonly(sk("rcpt-exit")),
		OwnerKey: xonly(sk("operator-owner")), EvictorKey: pendingReclaimKey(),
		EvictAfter: deadline, Nonce: binary.LittleEndian.Uint32(h[:4]),
	}
}

// landingLeaf is PendingWorld.landing: L, the recipient's own, evictable
// by the operator after a long lease.
func (w *world) landingLeaf(amount uint64, label string) *tree.Leaf {
	h := sha256.Sum256([]byte(label))
	rcpt := xonly(sk("rcpt-exit"))
	return &tree.Leaf{
		Amount: amount, ExitKey: rcpt, OwnerKey: rcpt,
		EvictorKey: w.opKey(), EvictAfter: 900_000,
		Nonce: binary.LittleEndian.Uint32(h[:4]),
	}
}

// pendingPair places P at 2*pair and L at 2*pair+1, and alice at 0.
func (w *world) pendingPair(pair, pAmt, lAmt uint64) (p, l *tree.Leaf) {
	p = w.pendingLeaf(pAmt, pendingDeadline, fmt.Sprintf("P%d", pair))
	l = w.landingLeaf(lAmt, fmt.Sprintf("L%d", pair))
	w.st.Tree.Leaves[2*pair] = p
	w.st.Tree.Leaves[2*pair+1] = l
	if pair != 0 {
		w.st.Tree.Leaves[0] = w.mkLeaf("alice", 50_000, nil, 0)
	}
	return p, l
}

// merge builds a CLAIM^m (or CLAIM^hm with a preimage) from srcPos into its
// sibling, raising the target to x, under a voucher by P's owner.
func merge(w *world, srcPos, x uint64, preimage *[32]byte) (*Spend,
	*tree.Tree, error) {

	src, tgt := w.st.Tree.Leaves[srcPos], w.st.Tree.Leaves[srcPos^1]
	var ph *[32]byte
	if preimage != nil {
		h := sha256.Sum256(preimage[:])
		ph = &h
	}
	vsig, err := SignMergeVoucher(
		sk("operator-owner"), w.treeID(), src, tgt, x, ph,
	)
	if err != nil {
		return nil, nil, err
	}
	return BuildMerge(w.st, srcPos, srcPos^1, x, vsig, preimage,
		&TxOpts{Inputs: w.fee(600)})
}

// settle is the R3 window settlement: 7,000 of P's 20,000 move into L,
// with the operator's signature alone.
func settle(w *world, x bool) (*Spend, *tree.Tree, error) {
	p, l := w.pendingPair(1, 20_000, 10_000)
	after := map[uint64]*tree.Leaf{
		0: withAmountSeq(p, 13_000, p.Seq),
		1: withAmountSeq(l, 17_000, l.Seq),
	}
	spend, next, err := BuildRewrite(w.st, 1, 1, after, x,
		&TxOpts{Inputs: w.fee(5_000)})
	if err == nil && len(spend.Sigs) != 1 {
		return nil, nil, fmt.Errorf("the settlement has %d signature "+
			"slots, want the operator's alone", len(spend.Sigs))
	}
	return spend, next, err
}

// pendingCases are the FULL pending-leaf receive cases at one depth and
// profile: the merges, RECLAIM_1, and the reclaim form of the rewrite
// settling, reclaiming and rolling. The sparse profile has RECLAIM_1 alone,
// since the merges and the rewrite are dense scripts.
func pendingCases(s caseSpec) []txCase {
	s.pending = true
	sx := s.withVariant("UPDATE_X")
	preimage := sha256.Sum256([]byte("receive-preimage"))
	free := func(w *world) []*wire.TxOut {
		return []*wire.TxOut{wire.NewTxOut(20_000, p2wpkh(w.t))}
	}
	reclaim := txCase{
		name: "RECLAIM_1", caseSpec: s,
		build: func(w *world) (*Spend, *tree.Tree, error) {
			p := w.pendingLeaf(20_000, pendingDeadline, "P")
			pos := w.slot(p, 2, w.st.Tree)
			w.st.Tree.Leaves[pos] = p
			a := w.mkLeaf("alice", 50_000, nil, 0)
			w.st.Tree.Leaves[w.slot(a, 0, w.st.Tree)] = a
			return BuildReclaim(w.st, pos, &TxOpts{
				LockTime: pendingDeadline, Inputs: w.fee(600),
				Outputs: free(w),
			})
		},
	}
	if s.sparse {
		return []txCase{reclaim}
	}
	return []txCase{reclaim, {
		name: "CLAIM_M", caseSpec: s,
		build: func(w *world) (*Spend, *tree.Tree, error) {
			w.pendingPair(1, 20_000, 10_000)
			return merge(w, 2, 12_500, nil)
		},
	}, {
		name: "CLAIM_M right", caseSpec: s,
		build: func(w *world) (*Spend, *tree.Tree, error) {
			p, l := w.pendingPair(2, 20_000, 10_000)
			w.st.Tree.Leaves[4], w.st.Tree.Leaves[5] = l, p
			return merge(w, 5, 13_000, nil)
		},
	}, {
		name: "CLAIM_M drain", caseSpec: s,
		build: func(w *world) (*Spend, *tree.Tree, error) {
			w.pendingPair(1, 20_000, 10_000)
			spend, next, err := merge(w, 2, 30_000, nil)
			if err == nil && next.Leaves[2] != nil {
				return nil, nil, fmt.Errorf("the drained source is not E_0")
			}
			return spend, next, err
		},
	}, {
		name: "CLAIM_HM", caseSpec: s,
		build: func(w *world) (*Spend, *tree.Tree, error) {
			w.pendingPair(1, 20_000, 10_000)
			return merge(w, 2, 13_000, &preimage)
		},
	}, {
		name: "REWRITE_R_1 transfer", caseSpec: s,
		build: func(w *world) (*Spend, *tree.Tree, error) {
			return settle(w, false)
		},
	}, {
		name: "REWRITE_XR_1 transfer", caseSpec: sx,
		build: func(w *world) (*Spend, *tree.Tree, error) {
			return settle(w, true)
		},
	}, {
		// R1: the expired pending leaf is emptied with no payout; its
		// value is the transaction's.
		name: "REWRITE_R_1 reclaim", caseSpec: s,
		build: func(w *world) (*Spend, *tree.Tree, error) {
			_, l := w.pendingPair(1, 20_000, 10_000)
			spend, next, err := BuildRewrite(w.st, 1, 1,
				map[uint64]*tree.Leaf{1: l}, false, &TxOpts{
					LockTime: pendingDeadline, Inputs: w.fee(600),
					Outputs: free(w),
				})
			if err == nil && spend.Tx.TxOut[1].Value != 20_000 {
				return nil, nil, fmt.Errorf("the reclaim paid an output " +
					"before the free one")
			}
			return spend, next, err
		},
	}, {
		// Two pairs in one rewrite under ^x: one settles, the other's
		// expired pending leaf rolls into the next window's; the
		// operator alone signs.
		name: "REWRITE_XR_2 settle+roll", caseSpec: sx,
		build: func(w *world) (*Spend, *tree.Tree, error) {
			p, l := w.pendingPair(2, 20_000, 10_000)
			pb := w.pendingLeaf(9_000, pendingDeadline, "Pb")
			lb := w.landingLeaf(4_000, "Lb")
			w.st.Tree.Leaves[6], w.st.Tree.Leaves[7] = pb, lb
			after := map[uint64]*tree.Leaf{
				0: withAmountSeq(p, 13_000, p.Seq),
				1: withAmountSeq(l, 17_000, l.Seq),
				2: w.pendingLeaf(9_000, pendingDeadline+1_008, "Pb2"),
				3: lb,
			}
			spend, next, err := BuildRewrite(w.st, 2, 1, after, true,
				&TxOpts{LockTime: pendingDeadline, Inputs: w.fee(5_000)})
			if err == nil && len(spend.Sigs) != 1 {
				return nil, nil, fmt.Errorf("the settlement has %d "+
					"signature slots, want the operator's alone",
					len(spend.Sigs))
			}
			return spend, next, err
		},
	}, {
		// The reclaim form keeps rule 5 for an ordinary leaf: bob's exit
		// in the other pair is signed by bob and paid to his exit key on
		// output 1, beside an operator-only transfer.
		name: "REWRITE_R_2 transfer+exit", caseSpec: s,
		build: func(w *world) (*Spend, *tree.Tree, error) {
			p, l := w.pendingPair(2, 20_000, 10_000)
			opKey := w.opKey()
			w.st.Tree.Leaves[6] = w.mkLeaf("bob", 125_000, &opKey, 800_000)
			after := map[uint64]*tree.Leaf{
				0: withAmountSeq(p, 13_000, p.Seq),
				1: withAmountSeq(l, 17_000, l.Seq),
			}
			spend, next, err := BuildRewrite(w.st, 2, 1, after, false,
				&TxOpts{Inputs: w.fee(5_000)})
			if err == nil && (len(spend.Sigs) != 2 ||
				spend.Tx.TxOut[1].Value != 125_000) {

				return nil, nil, fmt.Errorf("the rewrite has %d "+
					"signature slots, want bob's and the operator's, "+
					"and bob paid on output 1", len(spend.Sigs))
			}
			return spend, next, err
		},
	}}
}

// pendingReject is one input the pending builders refuse before signing,
// in a dense pending world of depth 4.
type pendingReject struct {
	name  string
	build func(w *world) error
}

// pendingRejects are the negatives of the pending-leaf builders, one per
// rule the scripts enforce.
func pendingRejects() []pendingReject {
	transfer := func(w *world, edit func(l *tree.Leaf),
		lAfter func(l *tree.Leaf) *tree.Leaf) error {

		p, l := w.pendingPair(1, 20_000, 10_000)
		edit(l)
		_, _, err := BuildRewrite(w.st, 1, 1, map[uint64]*tree.Leaf{
			0: withAmountSeq(p, 13_000, p.Seq), 1: lAfter(l),
		}, false, &TxOpts{Inputs: w.fee(5_000)})
		return err
	}
	raised := func(l *tree.Leaf) *tree.Leaf {
		return withAmountSeq(l, 17_000, l.Seq)
	}
	same := func(*tree.Leaf) {}
	mergeAfter := func(edit func(p, l *tree.Leaf), x uint64) func(w *world) error {
		return func(w *world) error {
			p, l := w.pendingPair(1, 20_000, 10_000)
			edit(p, l)
			_, _, err := merge(w, 2, x, nil)
			return err
		}
	}
	none := func(p, l *tree.Leaf) {}
	return []pendingReject{{
		name: "merge into a non-sibling",
		build: func(w *world) error {
			p, _ := w.pendingPair(1, 20_000, 10_000)
			tgt := w.landingLeaf(10_000, "L4")
			w.st.Tree.Leaves[4] = tgt
			vsig, err := SignMergeVoucher(sk("operator-owner"), w.treeID(),
				p, tgt, 13_000, nil)
			if err != nil {
				return nil
			}
			_, _, err = BuildMerge(w.st, 2, 4, 13_000, vsig, nil,
				&TxOpts{Inputs: w.fee(600)})
			return err
		},
	}, {
		name: "merge into a target the source's exit key does not own",
		build: mergeAfter(func(p, l *tree.Leaf) {
			l.OwnerKey = xonly(sk("operator-owner"))
		}, 13_000),
	}, {
		name: "merge into a target that exits to another key",
		build: mergeAfter(func(p, l *tree.Leaf) {
			l.ExitKey = xonly(sk("elsewhere-exit"))
		}, 13_000),
	}, {
		name: "merge into a reclaimable target",
		build: mergeAfter(func(p, l *tree.Leaf) {
			l.EvictorKey = pendingReclaimKey()
		}, 13_000),
	}, {
		name: "merge from a SEQ_FINAL source",
		build: mergeAfter(func(p, l *tree.Leaf) {
			p.Seq = FullSeqFinal
		}, 13_000),
	}, {
		name:  "merge with x not above the target",
		build: mergeAfter(none, 10_000),
	}, {
		name:  "merge leaving a sub-dust residual",
		build: mergeAfter(none, 29_800),
	}, {
		name:  "merge drawing more than the source holds",
		build: mergeAfter(none, 30_001),
	}, {
		name: "merge with a voucher over another x",
		build: func(w *world) error {
			p, l := w.pendingPair(1, 20_000, 10_000)
			vsig, err := SignMergeVoucher(sk("operator-owner"), w.treeID(),
				p, l, 14_000, nil)
			if err != nil {
				return nil
			}
			_, _, err = BuildMerge(w.st, 2, 3, 13_000, vsig, nil,
				&TxOpts{Inputs: w.fee(600)})
			return err
		},
	}, {
		name: "reclaim of a leaf that is not reclaimable",
		build: func(w *world) error {
			w.pendingPair(1, 20_000, 10_000)
			_, _, err := BuildReclaim(w.st, 3, &TxOpts{
				LockTime: 900_000, Inputs: w.fee(600),
			})
			return err
		},
	}, {
		name: "reclaim before the deadline",
		build: func(w *world) error {
			w.pendingPair(1, 20_000, 10_000)
			_, _, err := BuildReclaim(w.st, 2, &TxOpts{
				LockTime: pendingDeadline - 1, Inputs: w.fee(600),
			})
			return err
		},
	}, {
		name: "transfer whose sibling is raised by less",
		build: func(w *world) error {
			return transfer(w, same, func(l *tree.Leaf) *tree.Leaf {
				return withAmountSeq(l, 16_999, l.Seq)
			})
		},
	}, {
		name: "transfer whose sibling is unchanged",
		build: func(w *world) error {
			return transfer(w, same, func(l *tree.Leaf) *tree.Leaf {
				return l
			})
		},
	}, {
		name: "transfer whose sibling's body changes beside the raise",
		build: func(w *world) error {
			return transfer(w, same, func(l *tree.Leaf) *tree.Leaf {
				n := raised(l)
				n.EvictAfter++
				return n
			})
		},
	}, {
		name: "transfer into a sibling the exit key does not own",
		build: func(w *world) error {
			return transfer(w, func(l *tree.Leaf) {
				l.OwnerKey = xonly(sk("operator-owner"))
			}, raised)
		},
	}, {
		name: "transfer into a sibling that exits to another key",
		build: func(w *world) error {
			return transfer(w, func(l *tree.Leaf) {
				l.ExitKey = xonly(sk("elsewhere-exit"))
			}, raised)
		},
	}, {
		name: "transfer into a reclaimable sibling",
		build: func(w *world) error {
			return transfer(w, func(l *tree.Leaf) {
				l.EvictorKey = pendingReclaimKey()
			}, raised)
		},
	}, {
		name: "R1 reclaim in a rewrite before the deadline",
		build: func(w *world) error {
			_, l := w.pendingPair(1, 20_000, 10_000)
			_, _, err := BuildRewrite(w.st, 1, 1,
				map[uint64]*tree.Leaf{1: l}, false, &TxOpts{
					LockTime: pendingDeadline - 1, Inputs: w.fee(600),
				})
			return err
		},
	}, {
		name: "reclaim-form rewrite at height 0",
		build: func(w *world) error {
			p, _ := w.pendingPair(1, 20_000, 10_000)
			_, _, err := BuildRewrite(w.st, 0, 2, map[uint64]*tree.Leaf{
				0: withAmountSeq(p, 25_000, p.Seq),
			}, false, &TxOpts{Inputs: w.fee(10_000)})
			return err
		},
	}}
}

// TestPendingRejects checks that the pending builders refuse what the
// scripts reject, and that a tier without the scripts refuses them.
func TestPendingRejects(t *testing.T) {
	for _, c := range pendingRejects() {
		c := c
		t.Run(c.name, func(t *testing.T) {
			w := newWorld(t, caseSpec{tier: Full, depth: 4, pending: true})
			err := c.build(w)
			if err == nil {
				t.Fatal("builder accepted it")
			}
			t.Log(err)
		})
	}
	t.Run("MID refuses the pending builders", func(t *testing.T) {
		w := newWorld(t, caseSpec{tier: Mid, depth: 4})
		if _, _, err := BuildMerge(w.st, 2, 3, 13_000, nil, nil,
			nil); err == nil {

			t.Fatal("BuildMerge accepted a MID tree")
		}
		if _, _, err := BuildReclaim(w.st, 2, nil); err == nil {
			t.Fatal("BuildReclaim accepted a MID tree")
		}
	})
}
