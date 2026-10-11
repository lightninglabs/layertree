package txn

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/wire"

	"github.com/roasbeef/layertree/tree"
)

// This file holds the cohort transitions of spec 7.9 and 7.10, which act
// on an aligned subtree of height h rather than on single leaves:
// REWRITE_h (and REWRITE_h^x) rewrites every position of the subtree in
// one spend, and DETACH_h moves the subtree into a tree output of its own.
// Both are dense-profile scripts.

// FullSeqFinal is SEQ_FINAL in the FULL tier (spec 5.2): the seq value of
// a leaf that no carve and no amount-only rewrite exemption applies to.
const FullSeqFinal uint32 = 0xFFFFFFFF

// rewriteMarker is the FULL tier's "unchanged" marker (spec 7.9): a
// one-byte new element standing for the old element of the same position.
var rewriteMarker = []byte{0x01}

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

// checkSubtree validates the (height, index) of a dense cohort transition
// against the tree.
func (st *TreeState) checkSubtree(name string, height int, index uint64,
	maxHeight int) error {

	switch {
	case st.Options.Sparse:
		return fmt.Errorf("txn: %s is a dense profile script", name)
	case height < 0 || height > maxHeight:
		return fmt.Errorf("txn: %s height %d out of range", name, height)
	case index >= uint64(1)<<uint(st.Tree.Depth-height):
		return fmt.Errorf("txn: %s index %d out of range", name, index)
	}
	return nil
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
// one-byte marker in place of the new element. Any increase of the tree's
// total must come from opts.Inputs; any decrease is the transaction's to
// spend. If the rewrite empties the tree, opts.Terminal is output 0.
func BuildRewrite(st *TreeState, height int, index uint64,
	after map[uint64]*tree.Leaf, exitConsent bool, opts *TxOpts) (*Spend,
	*tree.Tree, error) {

	name := fmt.Sprintf("REWRITE_%d", height)
	if exitConsent {
		name = fmt.Sprintf("REWRITE_X_%d", height)
	}
	if err := st.checkSubtree(name, height, index, st.Tree.Depth); err != nil {
		return nil, nil, err
	}
	// Rule 7: a taptree with UPDATE^x or CLAIM^x carries REWRITE_h^x, not
	// REWRITE_h, so that neither consent can be bypassed by the cohort form.
	o := st.Options
	if !exitConsent && (o.UpdateX || o.ClaimX || o.ClaimHX) {
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
	var blocks [][][]byte // per position, bottom..top, in position order
	type slot struct {
		pos  uint64
		key  [32]byte
		role string
	}
	var slots [][]slot // signature slots per position, in witness order
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
		if old != nil && new == nil {
			payouts = append(payouts, Payout{
				ExitKey: old.ExitKey, Amount: int64(old.Amount),
			})
		}

		// The block is [xsig] [sig] new old, bottom to top.
		var block [][]byte
		var ps []slot
		if rewriteNeedsOwner(old, new, FullSeqFinal) {
			if exitConsent {
				block = append(block, sigPlaceholder())
				ps = append(ps, slot{pos, old.ExitKey, "exit"})
			}
			block = append(block, sigPlaceholder())
			ps = append(ps, slot{pos, old.OwnerKey, "owner"})
		}
		switch {
		case old != nil && new != nil &&
			bytes.Equal(old.Serialize(), new.Serialize()):
			block = append(block, rewriteMarker)
		case new != nil:
			block = append(block, new.Serialize())
		default:
			block = append(block, []byte{})
		}
		if old != nil {
			block = append(block, old.Serialize())
		} else {
			block = append(block, []byte{})
		}
		blocks = append(blocks, block)
		slots = append(slots, ps)
	}
	if cur.Subtree(height, index) == next.Subtree(height, index) {
		return nil, nil, errors.New("txn: the rewrite changes nothing")
	}

	// Witness (bottom..top): path, block_{n-1} .. block_0, sig_op, r, m.
	in := st.Input()
	stack := DensePathWitness(cur.Path(base, height))
	var sigs []SigSlot
	for i := len(blocks) - 1; i >= 0; i-- {
		for j, s := range slots[i] {
			sigs = append(sigs, SigSlot{
				Index: len(stack) + j, Key: s.key,
				Role: fmt.Sprintf("position %d %s", s.pos, s.role),
			})
		}
		stack = append(stack, blocks[i]...)
	}
	sigs = append(sigs, SigSlot{
		Index: len(stack), Key: o.OperatorKey, Role: "operator",
	})
	stack = append(stack, sigPlaceholder(), in.RootHash[:], in.MerkleRoot[:])

	spend, err := finish(st, next, name, payouts, stack, sigs, opts)
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
// offsets within the subtree, the same options (so the same tree_id, which
// is what keeps vouchers against its leaves redeemable), and output 1 of
// the spend as its outpoint. If the host is left empty, opts.Terminal is
// output 0.
func BuildDetach(st *TreeState, height int, index uint64, opts *TxOpts) (*Spend,
	*tree.Tree, *TreeState, error) {

	name := fmt.Sprintf("DETACH_%d", height)
	if err := st.checkSubtree(name, height, index, st.Tree.Depth-1); err != nil {
		return nil, nil, nil, err
	}
	cur := st.Tree
	node := cur.Subtree(height, index)
	if node == tree.EmptyNode(height) {
		return nil, nil, nil, errors.New("txn: the subtree is empty")
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
	spk, err := tree.ScriptPubKey(node.Hash, mH)
	if err != nil {
		return nil, nil, nil, err
	}
	o := TxOpts{}
	if opts != nil {
		o = *opts
	}
	o.Outputs = append([]*wire.TxOut{wire.NewTxOut(int64(node.Sum), spk)},
		o.Outputs...)

	// Witness (bottom..top): path, R_h, le64(sum_h), sig, r, m.
	in := st.Input()
	stack := DensePathWitness(cur.Path(base, height))
	stack = append(stack, node.Hash[:], tree.Le64(node.Sum))
	sigs := []SigSlot{{
		Index: len(stack), Key: st.Options.OperatorKey, Role: "operator",
	}}
	stack = append(stack, sigPlaceholder(), in.RootHash[:], in.MerkleRoot[:])

	spend, err := finish(st, host, name, nil, stack, sigs, &o)
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
