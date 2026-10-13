package txn

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/wire"

	"github.com/roasbeef/layertree/tree"
)

// This file holds the cohort transitions of spec 7.7, 7.9 and 7.10, which
// act on an aligned subtree of height h rather than on single leaves:
// EVICT_SUBTREE_h sweeps every leaf of the subtree, REWRITE_h (and
// REWRITE_h^x) rewrites every position of the subtree in one spend, and
// DETACH_h moves the subtree into a tree output of its own. All three are
// dense-profile scripts.

// FullSeqFinal is SEQ_FINAL in the 0xC2 tiers (spec 5.2): the seq value of
// a leaf that no carve and no amount-only rewrite exemption applies to.
const FullSeqFinal uint32 = 0xFFFFFFFF

// rewriteNeedsOwner decides spec 7.9 rule 3 for one position: a position
// whose old element is a leaf and whose new element differs needs the old
// owner's signature, unless the new element is the same leaf with an
// amount no lower and the old leaf's seq is not SEQ_FINAL.
func rewriteNeedsOwner(old, new *tree.Leaf, seqFinal uint32) bool {
	if old == nil {
		return false
	}
	if new != nil && bytes.Equal(old.Serialize(), new.Serialize()) {
		return false
	}
	if new != nil && bytes.Equal(old.Body(), new.Body()) &&
		new.Amount >= old.Amount && old.Seq != seqFinal {

		return false
	}
	return true
}

// slot renders one position of a 0xC0 sweep or rewrite: a present leaf as
// its elements (with evict_after for the sweep) and a presence flag, an
// empty position as one empty element. In 0xC2 a position is the leaf
// record or the empty element.
func (r rules) slot(leaf *tree.Leaf, exit bool) [][]byte {
	if leaf == nil {
		return [][]byte{{}}
	}
	if !r.tier.elements() {
		return [][]byte{leaf.Serialize()}
	}
	return append(r.leaf(leaf, exit), []byte{0x01})
}

// rewriteMarker is the tier's "unchanged" marker (spec 7.9): a one-byte
// new element standing for the old element of the same position, 0x01 in
// the 0xC2 tiers and 0x02 under 0xC0 numerics, where 0x01 is a slot's
// presence flag.
func (r rules) rewriteMarker() []byte {
	if r.tier.elements() {
		return []byte{0x02}
	}
	return []byte{0x01}
}

// amountOnlyChange reports whether new is old with another amount and
// nothing else, the one change an amount-only element expresses (spec 7.9,
// 8.9). It is false for an unchanged leaf, which the marker covers more
// cheaply, and for a position whose old element is empty.
func amountOnlyChange(old, new *tree.Leaf) bool {
	return old != nil && new != nil && old.Amount != new.Amount &&
		bytes.Equal(old.Body(), new.Body())
}

// amountOnlyElement is the new element of a position whose leaf changes in
// its amount alone (spec 7.9): le64(a) in the 0xC2 tiers, eight bytes in
// place of 116, and under 0xC0 numerics the slot amt_num za wa 0x03, the
// amount as a minimal number with its PADZ pad and the flag 0x03, four
// elements in place of eleven. The script expands it to the old leaf with
// the amount a before any rule reads it.
func (r rules) amountOnlyElement(amount uint64) [][]byte {
	if !r.tier.elements() {
		return [][]byte{tree.Le64(amount)}
	}
	return append(r.paddedSum(amount), []byte{0x03})
}

// checkSubtree validates the (height, index) of a dense cohort transition
// against the tree.
func (st *TreeState) checkSubtree(r rules, name string, height int,
	index uint64, maxHeight int) error {

	switch {
	case r.sparse:
		return fmt.Errorf("txn: %s is a dense profile script", name)
	case height < 0 || height > maxHeight:
		return fmt.Errorf("txn: %s height %d out of range", name, height)
	case index >= uint64(1)<<uint(st.Tree.Depth-height):
		return fmt.Errorf("txn: %s index %d out of range", name, index)
	}
	return nil
}

// BuildEvictSubtree builds EVICT_SUBTREE_h (spec 7.7), dense profile only:
// sweep every leaf of the aligned subtree of height h at index, each paid
// exactly to its exit key on the next output from 1 in position order, under
// one operator signature. Every leaf must name the operator as evictor and
// opts.LockTime must have reached every evict_after. If the sweep empties
// the tree, opts.Terminal is output 0 (spec 7.8).
func BuildEvictSubtree(st *TreeState, height int, index uint64,
	opts *TxOpts) (*Spend, *tree.Tree, error) {

	r, err := st.rules()
	if err != nil {
		return nil, nil, err
	}
	name := fmt.Sprintf("EVICT_SUBTREE_%d", height)
	if err := st.checkSubtree(r, name, height, index, st.Tree.Depth); err != nil {
		return nil, nil, err
	}
	var lockTime uint32
	if opts != nil {
		lockTime = opts.LockTime
	}

	cur := st.Tree
	next := cur.Clone()
	base := index << uint(height)
	leaves := make([]*tree.Leaf, 1<<uint(height))
	var payouts []Payout
	for off := range leaves {
		pos := base + uint64(off)
		leaf := cur.Leaves[pos]
		if leaf == nil {
			continue
		}
		if leaf.EvictorKey != r.operatorKey {
			return nil, nil, fmt.Errorf("txn: the leaf at %d is not "+
				"evictable by the operator", pos)
		}
		if err := checkEvictLockTime(lockTime, leaf.EvictAfter); err != nil {
			return nil, nil, fmt.Errorf("txn: leaf at %d: %w", pos, err)
		}
		leaves[off] = leaf
		payouts = append(payouts, Payout{
			ExitKey: leaf.ExitKey, Amount: int64(leaf.Amount),
		})
		delete(next.Leaves, pos)
	}
	if len(payouts) == 0 {
		return nil, nil, errors.New("txn: the subtree is empty")
	}
	if err := r.checkTotals(cur); err != nil {
		return nil, nil, err
	}

	// Witness (spec 8.7): path (from height h), the 0xC0 node pads,
	// leaf_{2^h-1} .. leaf_0, operator_sig.
	in := st.input(r)
	body := r.inputPad(uint64(in.Amount))
	body = append(body, r.levels(
		cur.Path(base, height), height, cur.Subtree(height, index),
		tree.EmptyNode(height),
	)...)
	body = append(body, r.nodePads(height, index, cur)...)
	for i := len(leaves) - 1; i >= 0; i-- {
		body = append(body, r.slot(leaves[i], true)...)
	}
	body, sigs := operatorSlot(r, body)
	// The MID prologue pushes three elements before any is consumed
	// (spec 4.5); the CCV sweep has no prologue, its peak is lower, and
	// the same figure is a safe bound for it.
	if err := r.checkStack(name, len(body), 3); err != nil {
		return nil, nil, err
	}

	spend, err := finish(st, r, next, name, payouts, body, sigs, opts)
	if err != nil {
		return nil, nil, err
	}
	return spend, next, nil
}

// BuildRewrite builds REWRITE_h (spec 7.9), or REWRITE_h^x with exitConsent
// (rule 7), dense profile only: the aligned subtree of height h at index
// is replaced by after, which maps an offset within the subtree to the leaf
// that occupies it afterwards; an offset absent from after is empty
// afterwards, so an occupied one exits and is paid exactly to its exit key
// on the next output from 1, in position order (rule 5). The operator
// signs once; every position whose leaf changes signs by its old owner key
// (rule 3), and under ^x by its old exit key too, except an amount-only
// increase of a leaf whose seq is not SEQ_FINAL, which the operator may make
// alone. A position whose leaf is unchanged publishes it once and the
// one-byte marker in place of the new element, and one whose leaf differs
// in its amount alone publishes the amount (amountOnlyElement) in place of
// the new leaf. Any increase of the tree's
// total must come from opts.Inputs; any decrease is the transaction's to
// spend. If the rewrite empties the tree, opts.Terminal is output 0.
//
// In a tree that names RECLAIM_KEY the rewrite is the reclaim form of rule
// 8 (REWRITE_R_h, REWRITE_XR_h, h >= 1), and a reclaimable old leaf follows
// reclaimRewriteStep: an amount-only decrease at an even offset is an R3
// transfer its odd sibling must absorb exactly, and any other change but
// an amount-only increase is an R1 reclaim, which pays nothing and needs
// opts.LockTime at the leaf's evict_after. Under CCV every rewrite's
// witness starts with the output-0 mode flag of spec 4.6, which the builder
// derives from the net change (ccvModeFlag): DEDUCT when the rewrite frees
// value, assign otherwise.
func BuildRewrite(st *TreeState, height int, index uint64,
	after map[uint64]*tree.Leaf, exitConsent bool, opts *TxOpts) (*Spend,
	*tree.Tree, error) {

	r, err := st.rules()
	if err != nil {
		return nil, nil, err
	}
	// A tree that names RECLAIM_KEY carries every rewrite in its reclaim
	// form (spec 7.9 rule 8), REWRITE_R_h and REWRITE_XR_h, for h >= 1.
	reclaim := r.reclaimKey != nil
	name := fmt.Sprintf("REWRITE_%d", height)
	switch {
	case reclaim && exitConsent:
		name = fmt.Sprintf("REWRITE_XR_%d", height)
	case reclaim:
		name = fmt.Sprintf("REWRITE_R_%d", height)
	case exitConsent:
		name = fmt.Sprintf("REWRITE_X_%d", height)
	}
	if err := st.checkSubtree(r, name, height, index, st.Tree.Depth); err != nil {
		return nil, nil, err
	}
	if reclaim {
		if err := r.pendingLayout(name); err != nil {
			return nil, nil, err
		}
		if height < 1 {
			return nil, nil, errors.New("txn: the reclaim form of " +
				"REWRITE_h pairs positions, so h is at least 1 " +
				"(spec 7.9 rule 8)")
		}
	}
	var lockTime uint32
	if opts != nil {
		lockTime = opts.LockTime
	}
	// Rule 7: a taptree with UPDATE^x or CLAIM^x carries REWRITE_h^x, not
	// REWRITE_h, so that neither consent can be bypassed by the cohort form.
	if !exitConsent && r.exitConsent {
		return nil, nil, errors.New("txn: a tree with UPDATE^x or CLAIM^x " +
			"rewrites with REWRITE_h^x (spec 7.9 rule 7)")
	}

	cur := st.Tree
	n := uint64(1) << uint(height)
	base := index << uint(height)
	for off := range after {
		if off >= n {
			return nil, nil, fmt.Errorf("txn: offset %d outside a "+
				"subtree of height %d", off, height)
		}
	}

	next := cur.Clone()
	var payouts []Payout
	type slot struct {
		pos  uint64
		key  [32]byte
		role string
	}
	var blocks [][][]byte // per position, bottom..top, in position order
	var slots [][]slot    // signature slots per position, in witness order
	for off := uint64(0); off < n; off++ {
		pos := base + off
		old := cur.Leaves[pos]
		new := after[off]
		if new != nil {
			if err := new.Validate(); err != nil {
				return nil, nil, fmt.Errorf("txn: position %d: %w", pos, err)
			}
			next.Leaves[pos] = new
		} else {
			delete(next.Leaves, pos)
		}
		step, err := r.reclaimRewriteStep(cur, base, off, after, lockTime)
		if err != nil {
			return nil, nil, err
		}
		if step.payout {
			payouts = append(payouts, Payout{
				ExitKey: old.ExitKey, Amount: int64(old.Amount),
			})
		}

		// The block is [xsig] [sig] new old, bottom to top, or under
		// 0xC0 numerics an R1 position's reclaim items in place of the
		// signatures.
		var block [][]byte
		var ps []slot
		if step.reclaim {
			block = append(block, r.reclaimItems(old)...)
		}
		if step.owner {
			if exitConsent {
				block = append(block, sigPlaceholder())
				ps = append(ps, slot{pos, old.ExitKey, "exit"})
			}
			block = append(block, sigPlaceholder())
			ps = append(ps, slot{pos, old.OwnerKey, "owner"})
		}
		// The cheapest new element that says the same: the marker for an
		// unchanged leaf, the amount alone when only the amount differs
		// from the old leaf, the whole leaf otherwise.
		switch {
		case old != nil && new != nil &&
			bytes.Equal(old.Serialize(), new.Serialize()):

			block = append(block, r.rewriteMarker())
		case amountOnlyChange(old, new):
			block = append(block, r.amountOnlyElement(new.Amount)...)
		default:
			block = append(block, r.slot(new, false)...)
		}
		block = append(block, r.slot(old, false)...)
		blocks = append(blocks, block)
		slots = append(slots, ps)
	}
	if cur.Subtree(height, index) == next.Subtree(height, index) {
		return nil, nil, errors.New("txn: the rewrite changes nothing")
	}
	if err := r.checkTotals(cur, next); err != nil {
		return nil, nil, err
	}

	// Witness (spec 8.9): path, the 0xC0 node pads (new then old per
	// node), block_{n-1} .. block_0, sig_op.
	in := st.input(r)
	body := r.inputPad(uint64(in.Amount))
	body = append(body, r.levels(
		cur.Path(base, height), height, cur.Subtree(height, index),
		next.Subtree(height, index),
	)...)
	body = append(body, r.nodePads(height, index, next, cur)...)
	var sigs []SigSlot
	for i := len(blocks) - 1; i >= 0; i-- {
		for j, s := range slots[i] {
			sigs = append(sigs, SigSlot{
				Index: len(body) + j, Key: s.key,
				Role: fmt.Sprintf("position %d %s", s.pos, s.role),
			})
		}
		body = append(body, blocks[i]...)
	}
	body, opSig := operatorSlot(r, body)
	sigs = append(sigs, opSig...)

	// Under CCV every rewrite commits output 0 in the mode its bottom flag
	// names (spec 4.6), chosen here from the net change.
	bottom := r.ccvModeFlag(in.Amount, payouts, next.Root().Sum)

	// The 0xC0 pre-pass peaks four elements above the witness (spec 4.5),
	// six in the reclaim form, whose machine carries the transfer record.
	// Both figures are the simulator's maximum stack depth less the
	// witness length, measured on every dumped case of MID and CCV0
	// alike (the flag counts as witness). At D = 16 every h <= 5 fits,
	// h = 6 only at low occupancy.
	peak := 4
	if reclaim {
		peak = 6
	}
	if err := r.checkStack(name, len(bottom)+len(body), peak); err != nil {
		return nil, nil, err
	}

	spend, err := finishFramed(st, r, next, name, payouts, bottom, body,
		sigs, opts)
	if err != nil {
		return nil, nil, err
	}
	return spend, next, nil
}

// BuildDetach builds DETACH_h (spec 7.10), dense profile only: the aligned
// subtree of height h at index leaves the tree, whose output 0 keeps the
// rest, and becomes output 1, a tree output of depth h holding the subtree
// root under m_h, the tree's own option set compiled at depth h (rule 3).
// The operator signs. Returns the spend, the host tree after it, and the
// detached tree as a TreeState of its own: the cohort's leaves at their
// offsets within the subtree, the same options (so the same tier and the
// same tree_id, which is what keeps vouchers against its leaves
// redeemable), and output 1 of the spend as its outpoint. If the host is
// left empty, opts.Terminal is output 0.
func BuildDetach(st *TreeState, height int, index uint64, opts *TxOpts) (*Spend,
	*tree.Tree, *TreeState, error) {

	r, err := st.rules()
	if err != nil {
		return nil, nil, nil, err
	}
	name := fmt.Sprintf("DETACH_%d", height)
	if err := st.checkSubtree(r, name, height, index, st.Tree.Depth-1); err != nil {
		return nil, nil, nil, err
	}
	cur := st.Tree
	node := cur.Subtree(height, index)
	if node == tree.EmptyNode(height) {
		return nil, nil, nil, errors.New("txn: the subtree is empty")
	}
	if err := r.checkTotals(cur); err != nil {
		return nil, nil, nil, err
	}

	base := index << uint(height)
	host := cur.Clone()
	child := tree.New(height)
	for pos, leaf := range cur.Leaves {
		if pos >= base && pos < base+uint64(1)<<uint(height) {
			delete(host.Leaves, pos)
			child.Leaves[pos-base] = leaf
		}
	}

	// Output 1 is the detached tree output; the caller's outputs follow it.
	mH := st.Options.TapTreeRoot(height)
	spk, err := r.tier.ScriptPubKey(node.Hash, mH)
	if err != nil {
		return nil, nil, nil, err
	}
	o := TxOpts{}
	if opts != nil {
		o = *opts
	}
	o.Outputs = append([]*wire.TxOut{wire.NewTxOut(int64(node.Sum), spk)},
		o.Outputs...)

	// Witness (spec 8.10): path, R_h, sum_h (le64, or a minimal number
	// with its pad), sig.
	in := st.input(r)
	body := r.inputPad(uint64(in.Amount))
	body = append(body, r.levels(
		cur.Path(base, height), height, node, tree.EmptyNode(height),
	)...)
	body = append(body, node.Hash[:])
	body = append(body, r.paddedSum(node.Sum)...)
	body, sigs := operatorSlot(r, body)

	spend, err := finish(st, r, host, name, nil, body, sigs, &o)
	if err != nil {
		return nil, nil, nil, err
	}
	detached, err := NewTreeState(child, st.Options, wire.OutPoint{
		Hash: spend.Tx.TxHash(), Index: 1,
	})
	if err != nil {
		return nil, nil, nil, err
	}
	if detached.TapTree.Root() != mH {
		return nil, nil, nil, errors.New("txn: the detached taptree's root " +
			"is not the script's m_h")
	}
	return spend, host, detached, nil
}
