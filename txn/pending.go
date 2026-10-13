package txn

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"

	"github.com/roasbeef/layertree/tree"
)

// This file holds the pending-leaf receive of design/pending-receive.md
// (spec 6.2, 7.5.4, 7.9 rule 8, 7.11, 9.6.3): the merge claims CLAIM^m and
// CLAIM^hm, the reclaim RECLAIM_1, and the per-position rules of the
// reclaim form of REWRITE_h. A tree carries them when it names a
// RECLAIM_KEY at creation; a leaf is reclaimable when its evictor_key is
// that key.
//
// Only the FULL tier's scripts exist so far. Each builder checks its rules
// in a tier-neutral way and then asks pendingLayout for the witness items
// that differ by tier; adding MID or CCV is a matter of teaching
// pendingLayout their encodings (the 0xC0 tiers' X and amounts as numbers
// with PADZ pads, CCV's missing r m, which finish already handles).

// pendingLayout refuses a pending-leaf receive transition in a tier whose
// scripts do not carry it yet.
func (r rules) pendingLayout(name string) error {
	if r.tier != Full {
		return fmt.Errorf("txn: %s is not built for the %v tier yet; "+
			"only FULL carries the pending-leaf receive scripts "+
			"(spec 7.5.4, 7.11)", name, r.tier)
	}
	return nil
}

// reclaimable reports whether a leaf is reclaimable in the tree (spec 6.2):
// the tree names a RECLAIM_KEY and the leaf's evictor_key is it.
func (r rules) reclaimable(l *tree.Leaf) bool {
	return l != nil && r.reclaimKey != nil && l.EvictorKey == *r.reclaimKey
}

// SignMergeVoucher is the source owner's merge voucher for CLAIM^m (spec
// 7.5.4), or for CLAIM^hm with a payment hash: a BIP-340 signature over
// H_voucher_m(tree_id || body(source) || body(target) || le64(x)). x is
// the absolute amount the target is raised to, so once the target holds x
// the voucher moves nothing.
func SignMergeVoucher(ownerKey *btcec.PrivateKey, treeID [32]byte, source,
	target *tree.Leaf, x uint64, paymentHash *[32]byte) ([]byte, error) {

	msg := tree.VoucherMMsg(treeID, source, target, x, paymentHash)
	return SignSchnorr(ownerKey, msg[:])
}

// BuildMerge builds CLAIM^m (spec 7.5.4), or CLAIM^hm when preimage is
// set, dense profile only: raise the leaf at tgtPos, the sibling of the
// leaf at srcPos, to x, taking the difference from the source, whose seq
// does not advance; a source drained to zero becomes E_0. The target must
// be owned by and exit to the source's exit key, neither leaf may be at
// SEQ_FINAL, the target may not be reclaimable, and the source's residual
// is zero or at least DUST_MIN. Nobody signs the transaction; the voucher
// from SignMergeVoucher is checked before anything is built.
func BuildMerge(st *TreeState, srcPos, tgtPos, x uint64, voucherSig []byte,
	preimage *[32]byte, opts *TxOpts) (*Spend, *tree.Tree, error) {

	r, err := st.rules()
	if err != nil {
		return nil, nil, err
	}
	name := "CLAIM_M"
	if preimage != nil {
		name = "CLAIM_HM"
	}
	if err := r.pendingLayout(name); err != nil {
		return nil, nil, err
	}
	cur := st.Tree
	src, tgt := cur.Leaves[srcPos], cur.Leaves[tgtPos]
	switch {
	case r.sparse:
		return nil, nil, fmt.Errorf("txn: %s is a dense profile script", name)
	case srcPos >= uint64(1)<<uint(cur.Depth):
		return nil, nil, fmt.Errorf("txn: source position %d is outside "+
			"a tree of depth %d", srcPos, cur.Depth)
	case tgtPos != srcPos^1:
		return nil, nil, fmt.Errorf("txn: the target %d is not the "+
			"sibling of the source %d (spec 7.5.4 rule 2)", tgtPos, srcPos)
	case src == nil || tgt == nil:
		return nil, nil, errors.New("txn: a merge needs a leaf at both " +
			"the source and the target")
	case tgt.OwnerKey != src.ExitKey || tgt.ExitKey != src.ExitKey:
		return nil, nil, errors.New("txn: the target must be owned by " +
			"and exit to the source's exit key (spec 7.5.4 rule 2)")
	case src.Seq == r.tier.SeqFinal() || tgt.Seq == r.tier.SeqFinal():
		return nil, nil, errors.New("txn: a merge touches no leaf at " +
			"SEQ_FINAL (spec 7.5.4 rule 2)")
	case r.reclaimable(tgt):
		return nil, nil, errors.New("txn: the target is reclaimable " +
			"(spec 7.5.4 rule 2)")
	case x <= tgt.Amount:
		return nil, nil, fmt.Errorf("txn: x %d is not above the "+
			"target's %d (spec 7.5.4 rule 3)", x, tgt.Amount)
	case x-tgt.Amount > src.Amount:
		return nil, nil, fmt.Errorf("txn: the merge draws %d from a "+
			"source of %d", x-tgt.Amount, src.Amount)
	}
	residual := src.Amount - (x - tgt.Amount)
	if dustMin := st.Options.DustFloor(); residual > 0 && residual < dustMin {
		return nil, nil, fmt.Errorf("txn: the merge leaves a residual of "+
			"%d, below DUST_MIN %d (spec 7.5.4 rule 3)", residual, dustMin)
	}
	var ph *[32]byte
	if preimage != nil {
		h := sha256.Sum256(preimage[:])
		ph = &h
	}
	msg := tree.VoucherMMsg(r.treeID, src, tgt, x, ph)
	if err := VerifySchnorr(src.OwnerKey, msg[:], voucherSig); err != nil {
		return nil, nil, fmt.Errorf("txn: merge voucher: %w", err)
	}

	next := cur.Clone()
	newTgt := *tgt
	newTgt.Amount = x
	next.Leaves[tgtPos] = &newTgt
	if residual == 0 {
		delete(next.Leaves, srcPos)
	} else {
		newSrc := *src
		newSrc.Amount = residual
		next.Leaves[srcPos] = &newSrc
	}

	// Witness (spec 7.5.4): the pair's path from height 1, the left and
	// right leaves, src_is_left, le64(x), the voucher and the preimage.
	pair := srcPos >> 1
	left, right := cur.Leaves[pair<<1], cur.Leaves[pair<<1|1]
	in := st.input(r)
	body := r.inputPad(uint64(in.Amount))
	body = append(body, r.levels(
		cur.Path(pair<<1, 1), 1, cur.Subtree(1, pair), next.Subtree(1, pair),
	)...)
	body = append(body, r.leaf(left, false)...)
	body = append(body, r.leaf(right, false)...)
	body = append(body, boolElem(srcPos&1 == 0), tree.Le64(x), voucherSig)
	if preimage != nil {
		body = append(body, preimage[:])
	}

	spend, err := finish(st, r, next, name, nil, body, nil, opts)
	if err != nil {
		return nil, nil, err
	}
	return spend, next, nil
}

// BuildReclaim builds RECLAIM_1 (spec 7.11): remove the reclaimable leaf at
// pos after its deadline and pay nothing for it, signed by RECLAIM_KEY.
// opts.LockTime must have reached the leaf's evict_after; the leaf's value
// is the transaction's to spend. If the reclaim empties the tree,
// opts.Terminal is output 0.
func BuildReclaim(st *TreeState, pos uint64, opts *TxOpts) (*Spend,
	*tree.Tree, error) {

	r, err := st.rules()
	if err != nil {
		return nil, nil, err
	}
	const name = "RECLAIM_1"
	if err := r.pendingLayout(name); err != nil {
		return nil, nil, err
	}
	leaf := st.Tree.Leaves[pos]
	switch {
	case r.reclaimKey == nil:
		return nil, nil, errors.New("txn: the tree names no RECLAIM_KEY " +
			"(spec 6.2)")
	case leaf == nil:
		return nil, nil, fmt.Errorf("txn: no leaf at position %d", pos)
	case !r.reclaimable(leaf):
		return nil, nil, fmt.Errorf("txn: the leaf at %d is not "+
			"reclaimable (spec 7.11 rule 1)", pos)
	}
	var lockTime uint32
	if opts != nil {
		lockTime = opts.LockTime
	}
	if err := checkEvictLockTime(lockTime, leaf.EvictAfter); err != nil {
		return nil, nil, fmt.Errorf("txn: reclaim: %w", err)
	}

	next := st.Tree.Clone()
	delete(next.Leaves, pos)

	// Witness (spec 7.11): path, leaf, sig by RECLAIM_KEY.
	in := st.input(r)
	body := r.inputPad(uint64(in.Amount))
	body = append(body, r.levels(
		st.Tree.Path(pos, 0), 0, leaf.Node(), tree.EmptyLeaf,
	)...)
	body = append(body, r.pos(leaf)...)
	body = append(body, r.leaf(leaf, false)...)
	sigs := []SigSlot{{
		Index: len(body), Key: *r.reclaimKey, Role: "reclaim",
	}}
	body = append(body, sigPlaceholder())

	spend, err := finish(st, r, next, name, nil, body, sigs, opts)
	if err != nil {
		return nil, nil, err
	}
	return spend, next, nil
}

// rewriteStep is how the rewrite treats one position: whether the old
// owner signs (spec 7.9 rule 3, and rule 7's exit key with it) and whether
// the old leaf is paid out (rule 5).
type rewriteStep struct {
	owner  bool
	payout bool
}

// reclaimRewriteStep decides one position of the reclaim form of REWRITE_h
// (spec 7.9 rule 8) and checks it as the script does. A position whose old
// leaf is not reclaimable follows rules 3 and 5 unchanged. One whose old
// leaf is reclaimable and changes takes no signature and no payout: an
// amount-only increase is rule 3's (unless the leaf is at SEQ_FINAL), an
// amount-only decrease at an even offset is an R3 transfer into the odd
// sibling, which must balance exactly, and every other change is an R1
// reclaim, which needs the lock time at evict_after. after holds the
// subtree's new leaves by offset, as BuildRewrite takes them.
func (r rules) reclaimRewriteStep(cur *tree.Tree, base, off uint64,
	after map[uint64]*tree.Leaf, lockTime uint32) (rewriteStep, error) {

	pos := base + off
	old, new := cur.Leaves[pos], after[off]
	if !r.reclaimable(old) {
		return rewriteStep{
			owner:  rewriteNeedsOwner(old, new, r.tier.SeqFinal()),
			payout: old != nil && new == nil,
		}, nil
	}
	if new != nil && bytes.Equal(old.Serialize(), new.Serialize()) {
		return rewriteStep{}, nil
	}
	sameBody := new != nil && bytes.Equal(old.Body(), new.Body())
	switch {
	case sameBody && new.Amount >= old.Amount && old.Seq != r.tier.SeqFinal():
		return rewriteStep{}, nil

	case sameBody && new.Amount < old.Amount && off%2 == 0:
		// R3: the odd sibling absorbs the decrease exactly.
		delta := old.Amount - new.Amount
		oR, nR := cur.Leaves[pos+1], after[off+1]
		switch {
		case oR == nil:
			return rewriteStep{}, fmt.Errorf("txn: position %d: a "+
				"transfer needs a leaf at its sibling (spec 7.9 rule 8)",
				pos)
		case r.reclaimable(oR):
			return rewriteStep{}, fmt.Errorf("txn: position %d: the "+
				"transfer's target is reclaimable (spec 7.9 rule 8)", pos)
		case oR.OwnerKey != old.ExitKey || oR.ExitKey != old.ExitKey:
			return rewriteStep{}, fmt.Errorf("txn: position %d: the "+
				"transfer's target must be owned by and exit to the "+
				"reclaimable leaf's exit key (spec 7.9 rule 8)", pos)
		case nR == nil || !bytes.Equal(nR.Body(), oR.Body()) ||
			nR.Amount != oR.Amount+delta:

			return rewriteStep{}, fmt.Errorf("txn: position %d: the "+
				"transfer of %d does not balance: its sibling must be "+
				"raised by exactly that amount and change in nothing "+
				"else (spec 7.9 rule 8)", pos, delta)
		}
		return rewriteStep{}, nil
	}

	// R1: any other change of a reclaimable leaf.
	if err := checkEvictLockTime(lockTime, old.EvictAfter); err != nil {
		return rewriteStep{}, fmt.Errorf("txn: position %d: reclaim: %w",
			pos, err)
	}
	return rewriteStep{}, nil
}
