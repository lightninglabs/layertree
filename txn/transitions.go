package txn

import (
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/wire"

	"github.com/roasbeef/layertree/tree"
)

// TreeState is a tree output as the transition builders see it: the
// off-chain tree it commits to, its profile, its taptree (whose root is m),
// the operator key its scripts embed, and the outpoint that holds it.
type TreeState struct {
	Tree        *tree.Tree
	Sparse      bool
	TapTree     *TapTree
	OperatorKey [32]byte
	OutPoint    wire.OutPoint
}

// Input returns the tree input: TREE_SPK(r, m) holding the root's sum.
func (st *TreeState) Input() TreeInput {
	root := st.Tree.Root()
	return TreeInput{
		OutPoint:   st.OutPoint,
		Amount:     int64(root.Sum),
		RootHash:   root.Hash,
		MerkleRoot: st.TapTree.Root(),
	}
}

// pathWitness renders a sibling path in the tree's profile. height is the
// height of the path's first level.
func (st *TreeState) pathWitness(path []tree.PathStep, height int) [][]byte {
	if st.Sparse {
		return SparsePathWitness(path, height)
	}
	return DensePathWitness(path)
}

// checkPos rejects a sparse-profile position that is not the one the leaf
// derives (spec 5.4): the scripts derive the position themselves, so any
// other position would fail.
func (st *TreeState) checkPos(pos uint64, leaf *tree.Leaf) error {
	if !st.Sparse {
		return nil
	}
	if want := leaf.Position(st.Tree.Depth); pos != want {
		return fmt.Errorf("txn: sparse leaf derives position %d, not %d",
			want, pos)
	}
	return nil
}

// TxOpts are the parts of a transition transaction the covenant leaves free
// (spec 7.1 rule 7): fee and funding inputs, outputs after the payouts, and
// nLockTime. Terminal is output 0 when the transition empties the tree
// (spec 7.8); it must be set exactly when the new root is E_D.
type TxOpts struct {
	LockTime uint32
	Inputs   []ExtraInput
	Outputs  []*wire.TxOut
	Terminal *wire.TxOut
}

// PlacedLeaf is a leaf and the position it occupies.
type PlacedLeaf struct {
	Pos  uint64
	Leaf *tree.Leaf
}

// sigPlaceholder is the empty element a signature slot holds until Sign.
func sigPlaceholder() []byte { return []byte{} }

// finish assembles the transaction for a transition from st to next and
// returns it as a Spend revealing the named script. payouts are outputs
// 1..K; stack and sigs are the witness stack and its signature slots.
func finish(st *TreeState, next *tree.Tree, name string, payouts []Payout,
	stack [][]byte, sigs []SigSlot, opts *TxOpts) (*Spend, error) {

	if opts == nil {
		opts = &TxOpts{}
	}
	newRoot := next.Root()
	terminal := newRoot == tree.EmptyNode(next.Depth)
	switch {
	case terminal && opts.Terminal == nil:
		return nil, errors.New("txn: the transition empties the tree; " +
			"output 0 must be supplied (spec 7.8)")
	case !terminal && opts.Terminal != nil:
		return nil, errors.New("txn: a terminal output 0 is only " +
			"allowed when the new root is E_D")
	}

	b := &Builder{
		LockTime:     opts.LockTime,
		Tree:         st.Input(),
		NewRoot:      newRoot.Hash,
		NewAmount:    int64(newRoot.Sum),
		Payouts:      payouts,
		ExtraInputs:  opts.Inputs,
		ExtraOutputs: opts.Outputs,
		Terminal:     opts.Terminal,
	}
	tx, err := b.Tx()
	if err != nil {
		return nil, err
	}
	prevOuts, err := b.PrevOuts()
	if err != nil {
		return nil, err
	}

	// The covenant only fixes output 0 and the payouts; whatever value
	// they need beyond the tree input has to come from the other inputs.
	var in, out int64
	for _, txIn := range tx.TxIn {
		in += prevOuts[txIn.PreviousOutPoint].Value
	}
	for _, txOut := range tx.TxOut {
		out += txOut.Value
	}
	if out > in {
		return nil, fmt.Errorf("txn: outputs (%d) exceed inputs (%d)",
			out, in)
	}

	idx, err := st.TapTree.Find(name)
	if err != nil {
		return nil, err
	}
	leaf := st.TapTree.Leaves[idx]
	cb, err := TreeControlBlock(
		b.Tree.RootHash, b.Tree.MerkleRoot, leaf.Version,
		st.TapTree.InclusionProof(idx),
	)
	if err != nil {
		return nil, err
	}
	return &Spend{
		Tx:           tx,
		PrevOuts:     prevOuts,
		Leaf:         leaf,
		ControlBlock: cb,
		Stack:        stack,
		Sigs:         sigs,
	}, nil
}

// ExitStep is one exit of an EXIT_K transaction (spec 7.2, 7.6).
type ExitStep struct {
	// Pos is the position of the exiting leaf.
	Pos uint64

	// Evict selects the evictor's branch: the evictor key signs, the
	// lock time must have reached evict_after and the payout is exact.
	Evict bool

	// Fee is the part of the leaf's amount an owner exit leaves to the
	// transaction (7.2 rule 3). It must be zero for an eviction and for
	// a tree with exact-payout EXIT_K^= scripts.
	Fee int64
}

// BuildExit builds EXIT_K for K = len(steps): step i removes its leaf and
// pays it to output i, proving it against the root left by step i-1. If the
// last step empties the tree, it is the terminal exit of spec 7.8 and
// opts.Terminal is output 0. Returns the spend and the tree after it.
func BuildExit(st *TreeState, steps []ExitStep, opts *TxOpts) (*Spend,
	*tree.Tree, error) {

	if len(steps) == 0 {
		return nil, nil, errors.New("txn: EXIT_K needs at least one step")
	}
	var lockTime uint32
	if opts != nil {
		lockTime = opts.LockTime
	}

	cur := st.Tree.Clone()
	blocks := make([][][]byte, len(steps))
	payouts := make([]Payout, len(steps))
	keys := make([][32]byte, len(steps))
	for i, step := range steps {
		leaf := cur.Leaves[step.Pos]
		if leaf == nil {
			return nil, nil, fmt.Errorf("txn: exit step %d: no "+
				"leaf at position %d", i+1, step.Pos)
		}
		if step.Fee < 0 || uint64(step.Fee) > leaf.Amount {
			return nil, nil, fmt.Errorf("txn: exit step %d: fee "+
				"%d out of range", i+1, step.Fee)
		}
		keys[i] = leaf.OwnerKey
		if step.Evict {
			if step.Fee != 0 {
				return nil, nil, fmt.Errorf("txn: exit step "+
					"%d: an eviction pays out exactly", i+1)
			}
			if lockTime < leaf.EvictAfter {
				return nil, nil, fmt.Errorf("txn: exit step "+
					"%d: lock time %d is before evict_after "+
					"%d", i+1, lockTime, leaf.EvictAfter)
			}
			keys[i] = leaf.EvictorKey
		}
		path := st.pathWitness(cur.Path(step.Pos, 0), 0)
		blocks[i] = ExitBlock(path, leaf, sigPlaceholder(), step.Evict)
		payouts[i] = Payout{
			ExitKey: leaf.ExitKey,
			Amount:  int64(leaf.Amount) - step.Fee,
		}
		delete(cur.Leaves, step.Pos)
	}

	// Block K is deepest, block 1 nearest the top (spec 8.3); each
	// block's signature sits two elements from its end.
	var sigs []SigSlot
	n := 0
	for i := len(blocks) - 1; i >= 0; i-- {
		n += len(blocks[i])
		role := "owner"
		if steps[i].Evict {
			role = "evictor"
		}
		sigs = append(sigs, SigSlot{
			Index: n - 2, Key: keys[i],
			Role: fmt.Sprintf("exit %d %s", i+1, role),
		})
	}
	in := st.Input()
	stack := ExitKWitness(blocks, in.RootHash, in.MerkleRoot)

	name := fmt.Sprintf("EXIT_%d", len(steps))
	spend, err := finish(st, cur, name, payouts, stack, sigs, opts)
	if err != nil {
		return nil, nil, err
	}
	return spend, cur, nil
}
