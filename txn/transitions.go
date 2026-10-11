package txn

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"math"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"

	"github.com/roasbeef/layertree/script"
	"github.com/roasbeef/layertree/tree"
)

// TreeState is a tree output as the transition builders see it: the
// off-chain tree it commits to, the creation parameters its scripts were
// compiled from, its taptree (whose root is m), and the outpoint that
// holds it.
//
// Options is what the builders consult about the rules: the profile, the
// operator key the JOIN, UPDATE and sweep scripts check, the tree_id of
// spec 6.2 that the CLAIM scripts carry as a constant and SignVoucher signs
// over, and whether the exits are the exact-payout EXIT_K^= of 7.2 rule 6
// or the tower-delegable EXIT_K^t of rule 7, whose owner steps take an
// authorisation from SignExitAuth in place of a transaction signature.
// NewTreeState compiles TapTree from Options, so the two agree by
// construction. A TreeState assembled by hand must keep them consistent:
// Options has to describe the scripts in TapTree, or the builders will
// sign what the scripts reject (design/audit/go.md G4, G8).
type TreeState struct {
	Tree     *tree.Tree
	Options  script.FullTreeOptions
	TapTree  *TapTree
	OutPoint wire.OutPoint
}

// NewTreeState returns the state of the tree output at outPoint holding tr,
// created with opts: the taptree is compiled from opts at the tree's depth,
// so its m is opts.TapTreeRoot(depth) and the tree_id its CLAIM scripts
// check is the one the builders sign vouchers over.
func NewTreeState(tr *tree.Tree, opts script.FullTreeOptions,
	outPoint wire.OutPoint) (*TreeState, error) {

	tt, err := NewFullTapTree(tr.Depth, opts)
	if err != nil {
		return nil, err
	}
	return &TreeState{
		Tree: tr, Options: opts, TapTree: tt, OutPoint: outPoint,
	}, nil
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
	if st.Options.Sparse {
		return SparsePathWitness(path, height)
	}
	return DensePathWitness(path)
}

// checkEvictLockTime rejects an nLockTime the eviction branch's
// OP_CHECKLOCKTIMEVERIFY would fail against evictAfter: one below it, or
// one that is a timestamp, since CLTV fails when its operand and nLockTime
// are of different types and 10.6 requires eviction transactions to use
// height-based nLockTime.
func checkEvictLockTime(lockTime, evictAfter uint32) error {
	if lockTime >= txscript.LockTimeThreshold {
		return fmt.Errorf("lock time %d is a timestamp; an eviction "+
			"needs a block height (spec 10.6)", lockTime)
	}
	if lockTime < evictAfter {
		return fmt.Errorf("lock time %d is before evict_after %d",
			lockTime, evictAfter)
	}
	return nil
}

// checkPos rejects a sparse-profile position that is not the one the leaf
// derives (spec 5.4): the scripts derive the position themselves, so any
// other position would fail.
func (st *TreeState) checkPos(pos uint64, leaf *tree.Leaf) error {
	if !st.Options.Sparse {
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
	// transaction (7.2 rule 3). BuildExit rejects a non-zero fee on an
	// eviction and in a tree whose Options.Exact or Options.Tower is set,
	// since EXIT_K^= (7.2 rule 6) and EXIT_K^t (rule 7) pay the whole
	// leaf.
	Fee int64

	// Auth is the owner's exit authorisation of spec 7.2 rule 7, a
	// signature from SignExitAuth, for an owner exit in a tree whose
	// Options.Tower is set: EXIT_K^t takes it in the signature slot in
	// place of a transaction signature, so the step has no slot to sign
	// and whoever holds the authorisation (a tower) builds the exit with
	// its own fee input. BuildExit requires it for an owner exit in such a
	// tree, rejects it elsewhere, and verifies it against the leaf's owner
	// key before anything is built, as it does a voucher.
	Auth []byte
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
		if step.Fee != 0 && (st.Options.Exact || st.Options.Tower) {
			return nil, nil, fmt.Errorf("txn: exit step %d: the "+
				"tree's EXIT_K^= scripts pay out exactly (spec 7.2 "+
				"rule 6)", i+1)
		}
		keys[i] = leaf.OwnerKey
		sig := sigPlaceholder()
		switch {
		case step.Evict:
			if step.Fee != 0 {
				return nil, nil, fmt.Errorf("txn: exit step "+
					"%d: an eviction pays out exactly", i+1)
			}
			if step.Auth != nil {
				return nil, nil, fmt.Errorf("txn: exit step %d: an "+
					"eviction signs the transaction; it takes no "+
					"authorisation", i+1)
			}
			err := checkEvictLockTime(lockTime, leaf.EvictAfter)
			if err != nil {
				return nil, nil, fmt.Errorf("txn: exit step %d: %w",
					i+1, err)
			}
			keys[i] = leaf.EvictorKey

		case st.Options.Tower:
			// EXIT_K^t (spec 7.2 rule 7): the owner branch takes the
			// off-chain authorisation, so there is no slot to sign.
			if step.Auth == nil {
				return nil, nil, fmt.Errorf("txn: exit step %d: the "+
					"tree's EXIT_K^t scripts take the owner's exit "+
					"authorisation (spec 7.2 rule 7)", i+1)
			}
			msg := tree.ExitAuthMsg(st.Options.TreeID, leaf)
			if err := VerifySchnorr(leaf.OwnerKey, msg[:], step.Auth); err != nil {
				return nil, nil, fmt.Errorf("txn: exit step %d: "+
					"authorisation: %w", i+1, err)
			}
			sig = step.Auth

		case step.Auth != nil:
			return nil, nil, fmt.Errorf("txn: exit step %d: an exit "+
				"authorisation needs a tree created with EXIT_K^t "+
				"(spec 7.2 rule 7)", i+1)
		}
		path := st.pathWitness(cur.Path(step.Pos, 0), 0)
		blocks[i] = ExitBlock(path, leaf, sig, step.Evict)
		payouts[i] = Payout{
			ExitKey: leaf.ExitKey,
			Amount:  int64(leaf.Amount) - step.Fee,
		}
		delete(cur.Leaves, step.Pos)
	}

	// Block K is deepest, block 1 nearest the top (spec 8.3); each
	// block's signature sits two elements from its end. An owner step
	// under EXIT_K^t carries its authorisation there already and has no
	// slot.
	var sigs []SigSlot
	n := 0
	for i := len(blocks) - 1; i >= 0; i-- {
		n += len(blocks[i])
		role := "owner"
		if steps[i].Evict {
			role = "evictor"
		} else if st.Options.Tower {
			continue
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

// BuildJoin builds JOIN_h (spec 7.3): graft the subtree of height h at
// index, whose leaves are given by their offset within the subtree, into an
// empty position. The operator signs; the value the subtree adds to output
// 0 must come from opts.Inputs. In the sparse profile h is 0, the subtree is
// one leaf, and index must be the position that leaf derives.
func BuildJoin(st *TreeState, height int, index uint64,
	leaves map[uint64]*tree.Leaf, opts *TxOpts) (*Spend, *tree.Tree,
	error) {

	cur := st.Tree
	switch {
	case height < 0 || height > cur.Depth:
		return nil, nil, fmt.Errorf("txn: join height %d out of range",
			height)
	case index >= uint64(1)<<uint(cur.Depth-height):
		return nil, nil, fmt.Errorf("txn: join index %d out of range",
			index)
	case len(leaves) == 0:
		return nil, nil, errors.New("txn: a join needs a leaf")
	case st.Options.Sparse && (height != 0 || len(leaves) != 1):
		return nil, nil, errors.New("txn: the sparse profile joins " +
			"one leaf at height 0")
	}
	if cur.Subtree(height, index) != tree.EmptyNode(height) {
		return nil, nil, fmt.Errorf("txn: subtree (%d, %d) is not "+
			"empty", height, index)
	}

	next := cur.Clone()
	var leaf *tree.Leaf
	for off, l := range leaves {
		if off >= uint64(1)<<uint(height) {
			return nil, nil, fmt.Errorf("txn: offset %d outside a "+
				"subtree of height %d", off, height)
		}
		if err := l.Validate(); err != nil {
			return nil, nil, fmt.Errorf("txn: leaf at offset %d: %w",
				off, err)
		}
		next.Leaves[index<<uint(height)+off] = l
		leaf = l
	}
	if err := st.checkPos(index, leaf); err != nil {
		return nil, nil, err
	}

	in := st.Input()
	path := st.pathWitness(cur.Path(index<<uint(height), height), height)
	var stack [][]byte
	if st.Options.Sparse {
		stack = JoinLeafWitness(
			path, leaf, sigPlaceholder(), in.RootHash, in.MerkleRoot,
		)
	} else {
		stack = JoinWitness(
			path, next.Subtree(height, index), sigPlaceholder(),
			in.RootHash, in.MerkleRoot,
		)
	}
	sigs := []SigSlot{{
		Index: len(stack) - 3, Key: st.Options.OperatorKey, Role: "operator",
	}}

	name := fmt.Sprintf("JOIN_%d", height)
	spend, err := finish(st, next, name, nil, stack, sigs, opts)
	if err != nil {
		return nil, nil, err
	}
	return spend, next, nil
}

// BuildJoinK builds JOINK_K for K = len(joins) (spec 7.3, 7.6): K
// single-leaf joins in order under one operator signature, each proven
// against the root the previous one left.
func BuildJoinK(st *TreeState, joins []PlacedLeaf, opts *TxOpts) (*Spend,
	*tree.Tree, error) {

	if len(joins) == 0 {
		return nil, nil, errors.New("txn: JOINK_K needs a leaf")
	}
	cur := st.Tree.Clone()
	blocks := make([][][]byte, len(joins))
	for i, j := range joins {
		if j.Pos >= uint64(1)<<uint(cur.Depth) {
			return nil, nil, fmt.Errorf("txn: join %d: position "+
				"%d out of range", i+1, j.Pos)
		}
		if _, ok := cur.Leaves[j.Pos]; ok {
			return nil, nil, fmt.Errorf("txn: join %d: position "+
				"%d is occupied", i+1, j.Pos)
		}
		if err := j.Leaf.Validate(); err != nil {
			return nil, nil, fmt.Errorf("txn: join %d: %w", i+1, err)
		}
		if err := st.checkPos(j.Pos, j.Leaf); err != nil {
			return nil, nil, err
		}
		path := st.pathWitness(cur.Path(j.Pos, 0), 0)
		if st.Options.Sparse {
			blocks[i] = JoinBlock(path, tree.Node{}, j.Leaf)
		} else {
			blocks[i] = JoinBlock(path, j.Leaf.Node(), nil)
		}
		cur.Leaves[j.Pos] = j.Leaf
	}

	in := st.Input()
	stack := JoinKWitness(
		blocks, sigPlaceholder(), in.RootHash, in.MerkleRoot,
	)
	sigs := []SigSlot{{
		Index: len(stack) - 3, Key: st.Options.OperatorKey, Role: "operator",
	}}

	name := fmt.Sprintf("JOINK_%d", len(joins))
	spend, err := finish(st, cur, name, nil, stack, sigs, opts)
	if err != nil {
		return nil, nil, err
	}
	return spend, cur, nil
}

// BuildUpdate builds UPDATE (spec 7.4): replace the leaf at pos with
// newLeaf, signed by the old leaf's owner and the operator. A decrease is
// free for the transaction to spend; an increase must come from
// opts.Inputs. In the sparse profile newLeaf must derive the same position.
func BuildUpdate(st *TreeState, pos uint64, newLeaf *tree.Leaf,
	opts *TxOpts) (*Spend, *tree.Tree, error) {

	return buildUpdate(st, pos, newLeaf, false, opts)
}

// BuildUpdateX builds UPDATE^x (spec 7.4 rule 5): UPDATE with a third
// signature, by the old leaf's exit key, in the slot above the operator's.
func BuildUpdateX(st *TreeState, pos uint64, newLeaf *tree.Leaf,
	opts *TxOpts) (*Spend, *tree.Tree, error) {

	return buildUpdate(st, pos, newLeaf, true, opts)
}

// buildUpdate is the shared body of BuildUpdate and BuildUpdateX.
func buildUpdate(st *TreeState, pos uint64, newLeaf *tree.Leaf,
	exitConsent bool, opts *TxOpts) (*Spend, *tree.Tree, error) {

	old := st.Tree.Leaves[pos]
	if old == nil {
		return nil, nil, fmt.Errorf("txn: no leaf at position %d", pos)
	}
	if err := newLeaf.Validate(); err != nil {
		return nil, nil, fmt.Errorf("txn: new leaf: %w", err)
	}
	if err := st.checkPos(pos, newLeaf); err != nil {
		return nil, nil, err
	}
	next := st.Tree.Clone()
	next.Leaves[pos] = newLeaf

	in := st.Input()
	path := st.pathWitness(st.Tree.Path(pos, 0), 0)
	name := "UPDATE"
	var stack [][]byte
	if exitConsent {
		name = "UPDATE_X"
		stack = UpdateXWitness(
			path, old, newLeaf, sigPlaceholder(), sigPlaceholder(),
			sigPlaceholder(), in.RootHash, in.MerkleRoot,
		)
	} else {
		stack = UpdateWitness(
			path, old, newLeaf, sigPlaceholder(), sigPlaceholder(),
			in.RootHash, in.MerkleRoot,
		)
	}

	// owner_sig and operator_sig follow the two leaves; exit_sig, when
	// present, sits directly above operator_sig.
	ownerIdx := len(path) + 2
	sigs := []SigSlot{
		{Index: ownerIdx, Key: old.OwnerKey, Role: "owner"},
		{Index: ownerIdx + 1, Key: st.Options.OperatorKey, Role: "operator"},
	}
	if exitConsent {
		sigs = append(sigs, SigSlot{
			Index: ownerIdx + 2, Key: old.ExitKey, Role: "exit",
		})
	}

	spend, err := finish(st, next, name, nil, stack, sigs, opts)
	if err != nil {
		return nil, nil, err
	}
	return spend, next, nil
}

// SignVoucher is the source owner's voucher for a CLAIM (spec 7.5): a
// BIP-340 signature over H_voucher(tree_id || body(source) || claim), treeID
// being the tree's TreeState.Options.TreeID, the constant its CLAIM scripts
// were compiled with. It commits to no transaction, so it is made
// off-chain, before any CLAIM is built, and it binds the source leaf
// without its amount, so it survives an amount-only REWRITE_h top-up of the
// source and is redeemed against the leaf's amount at that time.
func SignVoucher(ownerKey *btcec.PrivateKey, treeID [32]byte, source,
	claim *tree.Leaf) ([]byte, error) {

	msg := tree.VoucherMsg(treeID, source, claim)
	return SignSchnorr(ownerKey, msg[:])
}

// SignVoucherH is the voucher for a CLAIM^h (spec 7.5.1): a signature over
// H_voucher_h(tree_id || body(source) || claim || payment_hash).
func SignVoucherH(ownerKey *btcec.PrivateKey, treeID [32]byte, source,
	claim *tree.Leaf, paymentHash [32]byte) ([]byte, error) {

	msg := tree.VoucherHMsg(treeID, source, claim, paymentHash)
	return SignSchnorr(ownerKey, msg[:])
}

// SignExitAuth is the owner's exit authorisation for EXIT_K^t (spec 7.2
// rule 7): a BIP-340 signature over H_exit(tree_id || body(leaf)), treeID
// being the tree's TreeState.Options.TreeID, the constant its EXIT_K^t
// scripts were compiled with. It commits to no transaction, so it is made
// off-chain, once, and handed to whoever will build the exit (a tower); it
// stays valid against every later root of the lineage until the leaf
// changes in any field but its amount, which is how an owner voids it. An
// amount-only REWRITE_h top-up leaves it valid, and the exit then pays the
// leaf's current amount.
func SignExitAuth(ownerKey *btcec.PrivateKey, treeID [32]byte,
	leaf *tree.Leaf) ([]byte, error) {

	msg := tree.ExitAuthMsg(treeID, leaf)
	return SignSchnorr(ownerKey, msg[:])
}

// BuildClaim builds CLAIM (spec 7.5): carve claim out of the leaf at
// srcPos into the empty position claimPos, on the authority of a voucher
// from SignVoucher. The voucher is verified against the source owner's key
// before anything is built, since the script checks it with
// OP_CHECKSIGFROMSTACK and a redeemer holding one from the wrong issuer or
// over another tree_id would otherwise learn so on chain. Nobody signs the
// transaction, so the spend has no signature slots; fees come from
// opts.Inputs.
func BuildClaim(st *TreeState, srcPos, claimPos uint64, claim *tree.Leaf,
	voucherSig []byte, opts *TxOpts) (*Spend, *tree.Tree, error) {

	return buildCarve(st, srcPos, claimPos, claim, "CLAIM",
		func(cPath, sPath [][]byte, src *tree.Leaf, r,
			m [32]byte) ([][]byte, []SigSlot, error) {

			msg := tree.VoucherMsg(st.Options.TreeID, src, claim)
			err := VerifySchnorr(src.OwnerKey, msg[:], voucherSig)
			if err != nil {
				return nil, nil, fmt.Errorf("txn: voucher: %w", err)
			}
			return ClaimWitness(
				cPath, sPath, src, claim, voucherSig, r, m,
			), nil, nil
		}, opts)
}

// BuildClaimH builds CLAIM^h (spec 7.5.1): CLAIM under a hash-locked
// voucher from SignVoucherH, redeemed with the payment hash's preimage. The
// voucher is verified over sha256(preimage) before anything is built.
func BuildClaimH(st *TreeState, srcPos, claimPos uint64, claim *tree.Leaf,
	voucherSig []byte, preimage [32]byte, opts *TxOpts) (*Spend,
	*tree.Tree, error) {

	return buildCarve(st, srcPos, claimPos, claim, "CLAIM_H",
		func(cPath, sPath [][]byte, src *tree.Leaf, r,
			m [32]byte) ([][]byte, []SigSlot, error) {

			msg := tree.VoucherHMsg(
				st.Options.TreeID, src, claim,
				sha256.Sum256(preimage[:]),
			)
			err := VerifySchnorr(src.OwnerKey, msg[:], voucherSig)
			if err != nil {
				return nil, nil, fmt.Errorf("txn: voucher: %w", err)
			}
			return ClaimHWitness(
				cPath, sPath, src, claim, voucherSig, preimage,
				r, m,
			), nil, nil
		}, opts)
}

// BuildSplit builds SPLIT (spec 7.5.2): CLAIM's two steps authorised by the
// source owner's signature over the transaction, which takes the voucher's
// place in the stack.
func BuildSplit(st *TreeState, srcPos, newPos uint64, newLeaf *tree.Leaf,
	opts *TxOpts) (*Spend, *tree.Tree, error) {

	return buildCarve(st, srcPos, newPos, newLeaf, "SPLIT",
		func(cPath, sPath [][]byte, src *tree.Leaf, r,
			m [32]byte) ([][]byte, []SigSlot, error) {

			stack := ClaimWitness(
				cPath, sPath, src, newLeaf, sigPlaceholder(),
				r, m,
			)
			return stack, []SigSlot{{
				Index: len(stack) - 3, Key: src.OwnerKey,
				Role: "owner",
			}}, nil
		}, opts)
}

// carveStack assembles a carve's stack from the rendered claim and source
// paths, the source leaf, r and m. It runs after every carve rule has been
// checked, so it is also where a transition checks the authority it was
// handed (a voucher) against the source leaf.
type carveStack func(claimPath, sourcePath [][]byte, source *tree.Leaf,
	rootHash, merkleRoot [32]byte) ([][]byte, []SigSlot, error)

// buildCarve is the shared body of CLAIM, CLAIM^h and SPLIT (spec 7.5 rules
// 2 to 6). Step 1 lowers the source leaf by the claim's amount and advances
// its seq, emptying the position if nothing is left; step 2 places the
// claim leaf at a position that is empty after step 1. The total is
// conserved, the claim leaf keeps the source's evictor and a lease no
// longer than the source's, so eviction holds per balance, and neither the
// claim leaf nor a non-zero residual is below the tree's DUST_MIN
// (st.Options.DustFloor, the constant its scripts carry), so no carve
// leaves a leaf that only a non-standard transaction can remove.
func buildCarve(st *TreeState, srcPos, claimPos uint64, claim *tree.Leaf,
	name string, assemble carveStack, opts *TxOpts) (*Spend, *tree.Tree,
	error) {

	src := st.Tree.Leaves[srcPos]
	dustMin := st.Options.DustFloor()
	switch {
	case src == nil:
		return nil, nil, fmt.Errorf("txn: no source leaf at position "+
			"%d", srcPos)
	case claim.Amount > src.Amount:
		return nil, nil, fmt.Errorf("txn: claim of %d exceeds the "+
			"source's %d", claim.Amount, src.Amount)
	case src.Seq == math.MaxUint32:
		return nil, nil, errors.New("txn: the source leaf's seq is " +
			"final, so it cannot be carved (spec 5.2)")
	case claim.EvictorKey != src.EvictorKey:
		return nil, nil, errors.New("txn: the claim leaf must keep the " +
			"source's evictor_key (spec 7.5 rule 5)")
	case claim.EvictAfter > src.EvictAfter:
		return nil, nil, fmt.Errorf("txn: the claim leaf's evict_after "+
			"%d is later than the source's %d (spec 7.5 rule 5)",
			claim.EvictAfter, src.EvictAfter)
	case claim.Amount < dustMin:
		return nil, nil, fmt.Errorf("txn: the claim leaf's amount %d is "+
			"below DUST_MIN %d (spec 7.5 rule 6)", claim.Amount,
			dustMin)
	case src.Amount-claim.Amount > 0 &&
		src.Amount-claim.Amount < dustMin:
		return nil, nil, fmt.Errorf("txn: the carve leaves a residual of "+
			"%d, below DUST_MIN %d (spec 7.5 rule 6)",
			src.Amount-claim.Amount, dustMin)
	case claimPos >= uint64(1)<<uint(st.Tree.Depth):
		return nil, nil, fmt.Errorf("txn: claim position %d is outside "+
			"a tree of depth %d", claimPos, st.Tree.Depth)
	}
	if err := claim.Validate(); err != nil {
		return nil, nil, fmt.Errorf("txn: claim leaf: %w", err)
	}
	if err := st.checkPos(claimPos, claim); err != nil {
		return nil, nil, err
	}

	// Step 1: the source leaf.
	mid := st.Tree.Clone()
	newSrc := *src
	newSrc.Amount -= claim.Amount
	newSrc.Seq++
	if newSrc.Amount == 0 {
		delete(mid.Leaves, srcPos)
	} else {
		mid.Leaves[srcPos] = &newSrc
	}

	// Step 2: the claim leaf, proven against the root step 1 left.
	if _, ok := mid.Leaves[claimPos]; ok {
		return nil, nil, fmt.Errorf("txn: claim position %d is "+
			"occupied", claimPos)
	}
	next := mid.Clone()
	next.Leaves[claimPos] = claim

	in := st.Input()
	stack, sigs, err := assemble(
		st.pathWitness(mid.Path(claimPos, 0), 0),
		st.pathWitness(st.Tree.Path(srcPos, 0), 0),
		src, in.RootHash, in.MerkleRoot,
	)
	if err != nil {
		return nil, nil, err
	}
	spend, err := finish(st, next, name, nil, stack, sigs, opts)
	if err != nil {
		return nil, nil, err
	}
	return spend, next, nil
}

// BuildEvictSubtree builds EVICT_SUBTREE_h (spec 7.7), dense profile only:
// sweep every leaf of the aligned subtree of height h at index, each paid
// exactly to its exit key on the next output from 1 in position order, under
// one operator signature. Every leaf must name the operator as evictor and
// opts.LockTime must have reached every evict_after. If the sweep empties
// the tree, opts.Terminal is output 0 (spec 7.8).
func BuildEvictSubtree(st *TreeState, height int, index uint64,
	opts *TxOpts) (*Spend, *tree.Tree, error) {

	cur := st.Tree
	switch {
	case st.Options.Sparse:
		return nil, nil, errors.New("txn: EVICT_SUBTREE_h is a dense " +
			"profile script")
	case height < 0 || height > cur.Depth:
		return nil, nil, fmt.Errorf("txn: sweep height %d out of "+
			"range", height)
	case index >= uint64(1)<<uint(cur.Depth-height):
		return nil, nil, fmt.Errorf("txn: sweep index %d out of range",
			index)
	}
	var lockTime uint32
	if opts != nil {
		lockTime = opts.LockTime
	}

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
		if leaf.EvictorKey != st.Options.OperatorKey {
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

	in := st.Input()
	stack := EvictSubtreeWitness(
		DensePathWitness(cur.Path(base, height)), leaves,
		sigPlaceholder(), in.RootHash, in.MerkleRoot,
	)
	sigs := []SigSlot{{
		Index: len(stack) - 3, Key: st.Options.OperatorKey, Role: "operator",
	}}

	name := fmt.Sprintf("EVICT_SUBTREE_%d", height)
	spend, err := finish(st, next, name, payouts, stack, sigs, opts)
	if err != nil {
		return nil, nil, err
	}
	return spend, next, nil
}
