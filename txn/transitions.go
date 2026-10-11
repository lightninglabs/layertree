package txn

import (
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"

	"github.com/roasbeef/layertree/tree"
)

// TreeState is a tree output as the transition builders see it: the
// off-chain tree it commits to, the creation parameters its scripts were
// compiled from, its taptree (whose root is m), and the outpoint that
// holds it.
//
// Options is the option set of the tree's tier (one of
// script.FullTreeOptions, script.MidTreeOptions, script.MinTreeOptions or
// script.CCVTreeOptions), and it is what the builders consult about the
// rules: the tier itself, which fixes the leaf version, the numerics, the
// witness encoding and the tree output key; the profile; the operator key
// the JOIN, UPDATE and cohort scripts check; the tree_id of spec 6.2 that
// the CLAIM scripts carry as a constant and SignVoucher signs over; the
// DUST_MIN of 7.5 rule 6; and whether the exits are the exact-payout
// EXIT_K^= of 7.2 rule 6 or the tower-delegable EXIT_K^t of rule 7, whose
// owner steps take an authorisation from SignExitAuth in place of a
// transaction signature. NewTreeState compiles TapTree from Options, so
// the two agree by construction. A TreeState assembled by hand must keep
// them consistent: Options has to describe the scripts in TapTree, or the
// builders will sign what the scripts reject (design/audit/go.md G4, G8).
type TreeState struct {
	Tree     *tree.Tree
	Options  Options
	TapTree  *TapTree
	OutPoint wire.OutPoint
}

// NewTreeState returns the state of the tree output at outPoint holding tr,
// created with opts: the taptree is compiled from opts at the tree's depth
// in the tier opts belongs to, so its m is opts.TapTreeRoot(depth) and the
// tree_id its CLAIM scripts check is the one the builders sign vouchers
// over.
func NewTreeState(tr *tree.Tree, opts Options, outPoint wire.OutPoint) (
	*TreeState, error) {

	tt, err := NewOptionsTapTree(tr.Depth, opts)
	if err != nil {
		return nil, err
	}
	return &TreeState{
		Tree: tr, Options: opts, TapTree: tt, OutPoint: outPoint,
	}, nil
}

// rules reads the builders' rules off the tree's option set.
func (st *TreeState) rules() (rules, error) {
	return optionRules(st.Options)
}

// Tier is the tier of the tree's scripts.
func (st *TreeState) Tier() (Tier, error) {
	r, err := st.rules()
	return r.tier, err
}

// Input returns the tree input: TREE_SPK(r, m) of the tree's tier holding
// the root's sum.
func (st *TreeState) Input() (TreeInput, error) {
	r, err := st.rules()
	if err != nil {
		return TreeInput{}, err
	}
	return st.input(r), nil
}

// input is Input with the rules already read.
func (st *TreeState) input(r rules) TreeInput {
	root := st.Tree.Root()
	return TreeInput{
		OutPoint:   st.OutPoint,
		Amount:     int64(root.Sum),
		RootHash:   root.Hash,
		MerkleRoot: st.TapTree.Root(),
		Tier:       r.tier,
	}
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
// other position would fail. Under 0xC0 numerics the leaf's pos_lo must
// also be a minimal positive CScriptNum (spec 4.5), which a joiner grinds
// its nonce for; a leaf whose nonce is not usable is refused here rather
// than failed on chain.
func (st *TreeState) checkPos(r rules, pos uint64, leaf *tree.Leaf) error {
	if !r.sparse {
		return nil
	}
	if want := leaf.Position(st.Tree.Depth); pos != want {
		return fmt.Errorf("txn: sparse leaf derives position %d, not %d",
			want, pos)
	}
	if r.tier.elements() && !leaf.PosLoMinimal(st.Tree.Depth) {
		return fmt.Errorf("txn: the leaf's nonce does not give a minimal "+
			"pos_lo at depth %d, which the 0xC0 sparse scripts need "+
			"(spec 4.5)", st.Tree.Depth)
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
// 1..K; body is the witness body in the tier's encoding and sigs its
// signature slots, indexed within the body. finish frames the body for
// the tier: under 0xC0 numerics the PADZ pad of the new total goes
// underneath it, in the MIN tier the nine raw introspection pieces
// underneath that, and r m on top unless the tier is CCV.
func finish(st *TreeState, r rules, next *tree.Tree, name string,
	payouts []Payout, body [][]byte, sigs []SigSlot, opts *TxOpts) (*Spend,
	error) {

	if opts == nil {
		opts = &TxOpts{}
	}
	newRoot := next.Root()
	terminal := newRoot == tree.EmptyNode(next.Depth)
	switch {
	case terminal && r.tier == Min:
		return nil, errors.New("txn: the MIN tier's output 0 is always " +
			"a tree output, so it has no terminal form (spec 7.8)")
	case terminal && opts.Terminal == nil:
		return nil, errors.New("txn: the transition empties the tree; " +
			"output 0 must be supplied (spec 7.8)")
	case !terminal && opts.Terminal != nil:
		return nil, errors.New("txn: a terminal output 0 is only " +
			"allowed when the new root is E_D")
	}
	if err := r.checkTotals(st.Tree, next); err != nil {
		return nil, err
	}

	in := st.input(r)
	b := &Builder{
		LockTime:     opts.LockTime,
		Tree:         in,
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
	var inSum, outSum int64
	for _, txIn := range tx.TxIn {
		inSum += prevOuts[txIn.PreviousOutPoint].Value
	}
	for _, txOut := range tx.TxOut {
		outSum += txOut.Value
	}
	if outSum > inSum {
		return nil, fmt.Errorf("txn: outputs (%d) exceed inputs (%d)",
			outSum, inSum)
	}

	idx, err := st.TapTree.Find(name)
	if err != nil {
		return nil, err
	}
	leaf := st.TapTree.Leaves[idx]
	cb, err := r.tier.controlBlock(
		in.RootHash, in.MerkleRoot, leaf.Version,
		st.TapTree.InclusionProof(idx),
	)
	if err != nil {
		return nil, err
	}

	// Frame the body for the tier.
	var prefix [][]byte
	if r.tier.elements() {
		prefix = pad(newRoot.Sum)
	}
	if r.tier == Min {
		raw, err := minRawPieces(tx, prevOuts, leaf.Hash(), 1+len(payouts))
		if err != nil {
			return nil, err
		}
		prefix = append(raw, prefix...)
	}
	stack := make([][]byte, 0, len(prefix)+len(body)+2)
	stack = append(stack, prefix...)
	stack = append(stack, body...)
	if !r.tier.ccv() {
		stack = append(stack, in.RootHash[:], in.MerkleRoot[:])
	}
	for i := range sigs {
		sigs[i].Index += len(prefix)
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
	// eviction and in a tree whose exits pay the whole leaf: one created
	// with Exact or Tower in the FULL tier (EXIT_K^= of 7.2 rule 6,
	// EXIT_K^t of rule 7), and every tree of the other tiers, whose only
	// payout mode is exact.
	Fee int64

	// Auth is the owner's exit authorisation of spec 7.2 rule 7, a
	// signature from SignExitAuth, for an owner exit in a tree whose
	// Tower option is set: EXIT_K^t takes it in the signature slot in
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

	r, err := st.rules()
	if err != nil {
		return nil, nil, err
	}
	if len(steps) == 0 {
		return nil, nil, errors.New("txn: EXIT_K needs at least one step")
	}
	var lockTime uint32
	if opts != nil {
		lockTime = opts.LockTime
	}

	in := st.input(r)
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
		if step.Fee != 0 && r.exact {
			return nil, nil, fmt.Errorf("txn: exit step %d: the "+
				"tree's exits pay out exactly (spec 7.2 rule 6)", i+1)
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

		case r.tower:
			// EXIT_K^t (spec 7.2 rule 7): the owner branch takes the
			// off-chain authorisation, so there is no slot to sign.
			if step.Auth == nil {
				return nil, nil, fmt.Errorf("txn: exit step %d: the "+
					"tree's EXIT_K^t scripts take the owner's exit "+
					"authorisation (spec 7.2 rule 7)", i+1)
			}
			msg := tree.ExitAuthMsg(r.treeID, leaf)
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

		// Block i: the input pad for the first block the script runs,
		// the levels, the sparse position items, the leaf with its
		// evict_after, the signature and is_evict.
		var block [][]byte
		if i == 0 {
			block = append(block, r.inputPad(uint64(in.Amount))...)
		}
		block = append(block, r.levels(
			cur.Path(step.Pos, 0), 0, leaf.Node(), tree.EmptyLeaf,
		)...)
		block = append(block, r.pos(leaf)...)
		block = append(block, r.leaf(leaf, true)...)
		block = append(block, sig, boolElem(step.Evict))
		blocks[i] = block
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
	var body [][]byte
	var sigs []SigSlot
	for i := len(blocks) - 1; i >= 0; i-- {
		role := "owner"
		if steps[i].Evict {
			role = "evictor"
		}
		if steps[i].Evict || !r.tower {
			sigs = append(sigs, SigSlot{
				Index: len(body) + len(blocks[i]) - 2, Key: keys[i],
				Role: fmt.Sprintf("exit %d %s", i+1, role),
			})
		}
		body = append(body, blocks[i]...)
	}

	name := fmt.Sprintf("EXIT_%d", len(steps))
	spend, err := finish(st, r, cur, name, payouts, body, sigs, opts)
	if err != nil {
		return nil, nil, err
	}
	return spend, cur, nil
}

// operatorSlot appends the operator's signature placeholder to a body and
// returns the body and its slot.
func operatorSlot(r rules, body [][]byte) ([][]byte, []SigSlot) {
	slot := SigSlot{Index: len(body), Key: r.operatorKey, Role: "operator"}
	return append(body, sigPlaceholder()), []SigSlot{slot}
}

// BuildJoin builds JOIN_h (spec 7.3): graft the subtree of height h at
// index, whose leaves are given by their offset within the subtree, into an
// empty position. The operator signs; the value the subtree adds to output
// 0 must come from opts.Inputs. In the sparse profile h is 0, the subtree is
// one leaf, and index must be the position that leaf derives.
func BuildJoin(st *TreeState, height int, index uint64,
	leaves map[uint64]*tree.Leaf, opts *TxOpts) (*Spend, *tree.Tree,
	error) {

	r, err := st.rules()
	if err != nil {
		return nil, nil, err
	}
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
	case r.sparse && (height != 0 || len(leaves) != 1):
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
	if err := st.checkPos(r, index, leaf); err != nil {
		return nil, nil, err
	}
	if err := r.checkTotals(next); err != nil {
		return nil, nil, err
	}

	in := st.input(r)
	node := next.Subtree(height, index)
	body := r.inputPad(uint64(in.Amount))
	body = append(body, r.levels(
		cur.Path(index<<uint(height), height), height,
		tree.EmptyNode(height), node,
	)...)
	if r.sparse {
		body = append(body, r.pos(leaf)...)
		body = append(body, r.leaf(leaf, false)...)
	} else {
		body = append(body, node.Hash[:], r.sum(node.Sum))
	}
	body, sigs := operatorSlot(r, body)

	name := fmt.Sprintf("JOIN_%d", height)
	spend, err := finish(st, r, next, name, nil, body, sigs, opts)
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

	r, err := st.rules()
	if err != nil {
		return nil, nil, err
	}
	if len(joins) == 0 {
		return nil, nil, errors.New("txn: JOINK_K needs a leaf")
	}
	in := st.input(r)
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
		if err := st.checkPos(r, j.Pos, j.Leaf); err != nil {
			return nil, nil, err
		}
		var block [][]byte
		if i == 0 {
			block = append(block, r.inputPad(uint64(in.Amount))...)
		}
		block = append(block, r.levels(
			cur.Path(j.Pos, 0), 0, tree.EmptyLeaf, j.Leaf.Node(),
		)...)
		if r.sparse {
			block = append(block, r.pos(j.Leaf)...)
			block = append(block, r.leaf(j.Leaf, false)...)
		} else {
			h := j.Leaf.Hash()
			block = append(block, h[:], r.sum(j.Leaf.Amount))
		}
		blocks[i] = block
		cur.Leaves[j.Pos] = j.Leaf
	}
	if err := r.checkTotals(cur); err != nil {
		return nil, nil, err
	}

	// Block K is deepest, block 1 nearest the top, the operator's
	// signature above them all (spec 8.4).
	var body [][]byte
	for i := len(blocks) - 1; i >= 0; i-- {
		body = append(body, blocks[i]...)
	}
	body, sigs := operatorSlot(r, body)

	name := fmt.Sprintf("JOINK_%d", len(joins))
	spend, err := finish(st, r, cur, name, nil, body, sigs, opts)
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

	r, err := st.rules()
	if err != nil {
		return nil, nil, err
	}
	old := st.Tree.Leaves[pos]
	if old == nil {
		return nil, nil, fmt.Errorf("txn: no leaf at position %d", pos)
	}
	if err := newLeaf.Validate(); err != nil {
		return nil, nil, fmt.Errorf("txn: new leaf: %w", err)
	}
	if err := st.checkPos(r, pos, newLeaf); err != nil {
		return nil, nil, err
	}
	next := st.Tree.Clone()
	next.Leaves[pos] = newLeaf
	if err := r.checkTotals(next); err != nil {
		return nil, nil, err
	}

	// Witness: path, old leaf, new leaf, owner_sig, operator_sig and,
	// for UPDATE^x, exit_sig directly above operator_sig (spec 8.5).
	in := st.input(r)
	body := r.inputPad(uint64(in.Amount))
	body = append(body, r.levels(
		st.Tree.Path(pos, 0), 0, old.Node(), newLeaf.Node(),
	)...)
	body = append(body, r.pos(old)...)
	body = append(body, r.leaf(old, false)...)
	body = append(body, r.leaf(newLeaf, false)...)
	sigs := []SigSlot{
		{Index: len(body), Key: old.OwnerKey, Role: "owner"},
		{Index: len(body) + 1, Key: r.operatorKey, Role: "operator"},
	}
	body = append(body, sigPlaceholder(), sigPlaceholder())
	name := "UPDATE"
	if exitConsent {
		name = "UPDATE_X"
		sigs = append(sigs, SigSlot{
			Index: len(body), Key: old.ExitKey, Role: "exit",
		})
		body = append(body, sigPlaceholder())
	}

	spend, err := finish(st, r, next, name, nil, body, sigs, opts)
	if err != nil {
		return nil, nil, err
	}
	return spend, next, nil
}

// SignVoucher is the source owner's voucher for a CLAIM (spec 7.5): a
// BIP-340 signature over H_voucher(tree_id || body(source) || claim), treeID
// being the tree's tree_id, the constant its CLAIM scripts were compiled
// with. It commits to no transaction, so it is made off-chain, before any
// CLAIM is built, and it binds the source leaf without its amount, so it
// survives an amount-only REWRITE_h top-up of the source and is redeemed
// against the leaf's amount at that time.
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
// being the tree's tree_id, the constant its EXIT_K^t scripts were compiled
// with. It commits to no transaction, so it is made off-chain, once, and
// handed to whoever will build the exit (a tower); it stays valid against
// every later root of the lineage until the leaf changes in any field but
// its amount, which is how an owner voids it. An amount-only REWRITE_h
// top-up leaves it valid, and the exit then pays the leaf's current amount.
func SignExitAuth(ownerKey *btcec.PrivateKey, treeID [32]byte,
	leaf *tree.Leaf) ([]byte, error) {

	msg := tree.ExitAuthMsg(treeID, leaf)
	return SignSchnorr(ownerKey, msg[:])
}

// carveAuth renders the authorisation of a carve, the witness elements
// above the leaves (and, under 0xC0 numerics, above the extras): a
// voucher, a voucher and a preimage, an owner's signature slot, each with
// or without the exit-consent slot of 7.5.3. It runs after every carve
// rule has been checked, so it is also where a transition checks the
// authority it was handed (a voucher) against the source leaf. The slots
// it returns are indexed within the elements it returns.
type carveAuth func(r rules, src *tree.Leaf) ([][]byte, []SigSlot, error)

// voucherAuth is the authorisation of CLAIM and CLAIM^h (preimage set),
// plus the exit-consent slot of CLAIM^x and CLAIM^hx (exitConsent). The
// voucher is verified against the source owner's key before anything is
// built, since the script checks it with OP_CHECKSIGFROMSTACK and a
// redeemer holding one from the wrong issuer or over another tree_id would
// otherwise learn so on chain.
func voucherAuth(claim *tree.Leaf, voucherSig []byte, preimage *[32]byte,
	exitConsent bool) carveAuth {

	return func(r rules, src *tree.Leaf) ([][]byte, []SigSlot, error) {
		var msg [32]byte
		if preimage == nil {
			msg = tree.VoucherMsg(r.treeID, src, claim)
		} else {
			msg = tree.VoucherHMsg(
				r.treeID, src, claim, sha256.Sum256(preimage[:]),
			)
		}
		if err := VerifySchnorr(src.OwnerKey, msg[:], voucherSig); err != nil {
			return nil, nil, fmt.Errorf("txn: voucher: %w", err)
		}
		items := [][]byte{voucherSig}
		if preimage != nil {
			items = append(items, preimage[:])
		}
		var sigs []SigSlot
		if exitConsent {
			sigs = []SigSlot{{
				Index: len(items), Key: src.ExitKey, Role: "exit",
			}}
			items = append(items, sigPlaceholder())
		}
		return items, sigs, nil
	}
}

// BuildClaim builds CLAIM (spec 7.5): carve claim out of the leaf at
// srcPos into the empty position claimPos, on the authority of a voucher
// from SignVoucher. Nobody signs the transaction, so the spend has no
// signature slots; fees come from opts.Inputs.
func BuildClaim(st *TreeState, srcPos, claimPos uint64, claim *tree.Leaf,
	voucherSig []byte, opts *TxOpts) (*Spend, *tree.Tree, error) {

	return buildCarve(st, srcPos, claimPos, claim, "CLAIM",
		voucherAuth(claim, voucherSig, nil, false), opts)
}

// BuildClaimH builds CLAIM^h (spec 7.5.1): CLAIM under a hash-locked
// voucher from SignVoucherH, redeemed with the payment hash's preimage. The
// voucher is verified over sha256(preimage) before anything is built.
func BuildClaimH(st *TreeState, srcPos, claimPos uint64, claim *tree.Leaf,
	voucherSig []byte, preimage [32]byte, opts *TxOpts) (*Spend,
	*tree.Tree, error) {

	return buildCarve(st, srcPos, claimPos, claim, "CLAIM_H",
		voucherAuth(claim, voucherSig, &preimage, false), opts)
}

// BuildClaimX builds CLAIM^x (spec 7.5.3): CLAIM with one more signature
// slot, directly below r, for the source leaf's exit key over the
// transaction. It is the credit-leaf form of 10.3: the issuer owns the
// source leaf and signs the voucher, the holder of its exit key signs the
// redemption, so neither can carve the leaf alone.
func BuildClaimX(st *TreeState, srcPos, claimPos uint64, claim *tree.Leaf,
	voucherSig []byte, opts *TxOpts) (*Spend, *tree.Tree, error) {

	return buildCarve(st, srcPos, claimPos, claim, "CLAIM_X",
		voucherAuth(claim, voucherSig, nil, true), opts)
}

// BuildClaimHX builds CLAIM^hx (spec 7.5.3): CLAIM^h with the exit-key
// signature slot of CLAIM^x, which sits above the preimage.
func BuildClaimHX(st *TreeState, srcPos, claimPos uint64, claim *tree.Leaf,
	voucherSig []byte, preimage [32]byte, opts *TxOpts) (*Spend,
	*tree.Tree, error) {

	return buildCarve(st, srcPos, claimPos, claim, "CLAIM_HX",
		voucherAuth(claim, voucherSig, &preimage, true), opts)
}

// BuildSplit builds SPLIT (spec 7.5.2): CLAIM's two steps authorised by the
// source owner's signature over the transaction, which takes the voucher's
// place in the stack.
func BuildSplit(st *TreeState, srcPos, newPos uint64, newLeaf *tree.Leaf,
	opts *TxOpts) (*Spend, *tree.Tree, error) {

	return buildCarve(st, srcPos, newPos, newLeaf, "SPLIT",
		func(r rules, src *tree.Leaf) ([][]byte, []SigSlot, error) {
			return [][]byte{sigPlaceholder()}, []SigSlot{{
				Index: 0, Key: src.OwnerKey, Role: "owner",
			}}, nil
		}, opts)
}

// buildCarve is the shared body of the CLAIM forms and SPLIT (spec 7.5
// rules 2 to 6). Step 1 lowers the source leaf by the claim's amount and
// advances its seq, emptying the position if nothing is left; step 2
// places the claim leaf at a position that is empty after step 1. The
// total is conserved, the claim leaf keeps the source's evictor and a
// lease no longer than the source's, so eviction holds per balance, and
// neither the claim leaf nor a non-zero residual is below the tree's
// DUST_MIN (Options.DustFloor, the constant its scripts carry), so no carve
// leaves a leaf that only a non-standard transaction can remove.
func buildCarve(st *TreeState, srcPos, claimPos uint64, claim *tree.Leaf,
	name string, auth carveAuth, opts *TxOpts) (*Spend, *tree.Tree,
	error) {

	r, err := st.rules()
	if err != nil {
		return nil, nil, err
	}
	src := st.Tree.Leaves[srcPos]
	dustMin := st.Options.DustFloor()
	switch {
	case src == nil:
		return nil, nil, fmt.Errorf("txn: no source leaf at position "+
			"%d", srcPos)
	case claim.Amount > src.Amount:
		return nil, nil, fmt.Errorf("txn: claim of %d exceeds the "+
			"source's %d", claim.Amount, src.Amount)
	case src.Seq >= r.tier.SeqFinal():
		// At SEQ_FINAL the leaf is not carvable (5.2); beyond it, which
		// only the 0xC0 tiers' 0x7FFFFFFF leaves room for, seq is outside
		// the numbers the carve extras can carry (4.5).
		return nil, nil, fmt.Errorf("txn: the source leaf's seq 0x%08x "+
			"is not below the tier's SEQ_FINAL 0x%08x, so it cannot be "+
			"carved (spec 5.2)", src.Seq, r.tier.SeqFinal())
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
	if err := st.checkPos(r, claimPos, claim); err != nil {
		return nil, nil, err
	}

	// Step 1: the source leaf.
	mid := st.Tree.Clone()
	newSrc := *src
	newSrc.Amount -= claim.Amount
	newSrc.Seq++
	newSrcNode := tree.EmptyLeaf
	if newSrc.Amount == 0 {
		delete(mid.Leaves, srcPos)
	} else {
		mid.Leaves[srcPos] = &newSrc
		newSrcNode = newSrc.Node()
	}

	// Step 2: the claim leaf, proven against the root step 1 left.
	if _, ok := mid.Leaves[claimPos]; ok {
		return nil, nil, fmt.Errorf("txn: claim position %d is "+
			"occupied", claimPos)
	}
	next := mid.Clone()
	next.Leaves[claimPos] = claim
	if err := r.checkTotals(next); err != nil {
		return nil, nil, err
	}

	// Witness (spec 8.6): the claim path sits deeper in the stack because
	// the script consumes it second: the source path is folded first to
	// r1, and the claim path is folded over that; so it is the source
	// fold that carries the input pad.
	in := st.input(r)
	body := r.levels(mid.Path(claimPos, 0), 0, tree.EmptyLeaf, claim.Node())
	body = append(body, r.pos(claim)...)
	body = append(body, r.inputPad(uint64(in.Amount))...)
	body = append(body, r.levels(
		st.Tree.Path(srcPos, 0), 0, src.Node(), newSrcNode,
	)...)
	body = append(body, r.pos(src)...)
	body = append(body, r.leaf(src, false)...)
	body = append(body, r.leaf(claim, false)...)
	body = append(body, r.carveExtras(src, claim, newSrc.Amount)...)
	items, sigs, err := auth(r, src)
	if err != nil {
		return nil, nil, err
	}
	for i := range sigs {
		sigs[i].Index += len(body)
	}
	body = append(body, items...)

	spend, err := finish(st, r, next, name, nil, body, sigs, opts)
	if err != nil {
		return nil, nil, err
	}
	return spend, next, nil
}
