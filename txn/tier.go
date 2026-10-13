package txn

import (
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"

	"github.com/roasbeef/layertree/script"
	"github.com/roasbeef/layertree/tree"
)

// Tier is the opcode tier a tree's scripts are compiled for (spec 4.5),
// and with it everything a builder has to do differently: the tapleaf
// version and the number encoding of the scripts, how the witness carries
// leaves, sums and paths, whether the stack ends in r m or the covenant
// binds the tree output with OP_CHECKCONTRACTVERIFY, and which key the
// tree output is built from. The builders are written once against this
// value; the per-tier script generators live in package script.
type Tier uint8

const (
	// Full is the FULL tier: 0xC2 leaves, 116-byte leaf records and
	// 41-byte nodes on the stack, r m on top, TREE_SPK(r, m).
	Full Tier = iota

	// Mid is the MID tier: 0xC0 leaves, every leaf passed as its fields
	// with its amount as a minimal number and a PADZ pad, every sum
	// likewise, r m on top, TREE_SPK(r, m) (spec 4.5, 8.x).
	Mid

	// Min is the MIN tier: MID's witness for EXIT_1 and SPLIT, dense
	// profile, below nine raw introspection pieces the script assembles
	// the signature message from, and a free field ground so that the
	// BIP-340 challenge under G ends in a zero byte (spec 4.5).
	Min

	// CCV is the CCV tier under 0xC2 numerics: FULL's witness without r
	// and m, TREE_SPK_CCV(r, m) (spec 4.6).
	CCV

	// CCV0 is the CCV tier under 0xC0 numerics: MID's witness without r
	// and m, TREE_SPK_CCV(r, m).
	CCV0
)

// String names the tier as the suites and the end-to-end cases do.
func (t Tier) String() string {
	switch t {
	case Full:
		return "FULL"
	case Mid:
		return "MID"
	case Min:
		return "MIN"
	case CCV:
		return "CCV"
	case CCV0:
		return "CCV0"
	}
	return fmt.Sprintf("Tier(%d)", uint8(t))
}

// Mode is the number encoding the tier's scripts are assembled with.
func (t Tier) Mode() script.Mode {
	if t.elements() {
		return script.ModeC0
	}
	return script.ModeC2
}

// LeafVersion is the tapleaf version of the tier's scripts.
func (t Tier) LeafVersion() byte {
	return t.Mode().LeafVersion()
}

// elements reports whether the tier's witnesses carry leaves as field
// elements and numbers as minimal CScriptNums with PADZ pads, the 0xC0
// encoding of spec 4.5.
func (t Tier) elements() bool {
	return t == Mid || t == Min || t == CCV0
}

// ccv reports whether the tier binds the tree output with
// OP_CHECKCONTRACTVERIFY (spec 4.6): the stack carries no r and no m, and
// the tree output key is TREE_SPK_CCV.
func (t Tier) ccv() bool {
	return t == CCV || t == CCV0
}

// SeqFinal is the tier's SEQ_FINAL (spec 5.2, 4.5): the seq a leaf
// carries when no carve may touch it and no amount-only rewrite exemption
// applies. Under 0xC0 numerics it is 0x7FFFFFFF, the largest four-byte
// CScriptNum, since its successor does not fit the PADZ gadget.
func (t Tier) SeqFinal() uint32 {
	if t.elements() {
		return script.MidSeqFinal
	}
	return FullSeqFinal
}

// ScriptPubKey is the tree output of the tier in state rootHash under the
// taptree root m: TREE_SPK(r, m) (spec 6.3), or TREE_SPK_CCV(r, m) in the
// CCV tier.
func (t Tier) ScriptPubKey(rootHash, merkleRoot [32]byte) ([]byte, error) {
	if t.ccv() {
		return tree.CCVScriptPubKey(rootHash, merkleRoot)
	}
	return tree.ScriptPubKey(rootHash, merkleRoot)
}

// internalKey is the taproot internal key of the tier's tree output in
// state rootHash, as the control block carries it: the state key of spec
// 6.1, or the CCV tier's data-tweaked NUMS point (4.6).
func (t Tier) internalKey(rootHash [32]byte) (*btcec.PublicKey, error) {
	if t.ccv() {
		return tree.CCVInternalKey(rootHash)
	}
	return tree.InternalKey(rootHash)
}

// controlBlock returns the control block that reveals a transition script
// of a tree of this tier in state rootHash under m.
func (t Tier) controlBlock(rootHash, merkleRoot [32]byte, leafVersion byte,
	inclusionProof []byte) ([]byte, error) {

	internalKey, err := t.internalKey(rootHash)
	if err != nil {
		return nil, err
	}
	// BIP-341 commits to the even-y lift of the internal key's x
	// coordinate, which is what the control block carries.
	internalKey, err = schnorr.ParsePubKey(schnorr.SerializePubKey(internalKey))
	if err != nil {
		return nil, err
	}
	var outputKey *btcec.PublicKey
	if t.ccv() {
		outputKey, err = tree.CCVOutputKey(rootHash, merkleRoot)
	} else {
		outputKey, err = tree.OutputKey(rootHash, merkleRoot)
	}
	if err != nil {
		return nil, err
	}
	return ControlBlock(internalKey, outputKey, leafVersion, inclusionProof)
}

// Options is a tree's creation parameter set in one tier (spec 6.2): one
// of script.FullTreeOptions, script.MidTreeOptions, script.MinTreeOptions
// or script.CCVTreeOptions. Scripts is what the taptree is compiled from
// at the tree's depth, and what a DETACH_h child is compiled from at depth
// h (7.10 rule 3); TapTreeRoot is its m; DustFloor the DUST_MIN its carve
// scripts carry (7.5 rule 6).
type Options interface {
	Scripts(depth int) []script.FullNamedScript
	TapTreeRoot(depth int) [32]byte
	DustFloor() uint64
}

// rules are the creation parameters the builders consult, read off the
// option set of the tree's tier: which tier, the profile, the operator key
// the JOIN, UPDATE and cohort scripts check, the tree_id of spec 6.2 that
// the CLAIM and EXIT_K^t scripts carry as a constant, whether the exits
// pay the whole leaf (EXIT_K^= of 7.2 rule 6, and every tier but FULL),
// whether they are the tower-delegable EXIT_K^t of rule 7, and whether the
// taptree carries UPDATE^x or CLAIM^x, which 7.9 rule 7 reads.
type rules struct {
	tier        Tier
	sparse      bool
	operatorKey [32]byte
	treeID      [32]byte
	exact       bool
	tower       bool
	exitConsent bool

	// reclaimKey is the tree's RECLAIM_KEY (spec 6.2), or nil: it makes
	// the leaves that name it as evictor reclaimable, adds RECLAIM_1, and
	// puts every REWRITE_h in its reclaim form (7.9 rule 8).
	reclaimKey *[32]byte
}

// optionRules reads the rules off an option set. An option set of a type
// the builders do not know is refused rather than guessed at.
func optionRules(o Options) (rules, error) {
	switch v := o.(type) {
	case script.FullTreeOptions:
		return rules{
			tier: Full, sparse: v.Sparse, operatorKey: v.OperatorKey,
			treeID: v.TreeID, exact: v.Exact || v.Tower, tower: v.Tower,
			exitConsent: v.UpdateX || v.ClaimX || v.ClaimHX,
			reclaimKey:  v.ReclaimKey,
		}, nil
	case script.MidTreeOptions:
		return rules{
			tier: Mid, sparse: v.Sparse, operatorKey: v.OperatorKey,
			treeID: v.TreeID, exact: true, tower: v.Tower,
			exitConsent: v.UpdateX || v.ClaimX || v.ClaimHX,
		}, nil
	case script.MinTreeOptions:
		return rules{tier: Min, exact: true}, nil
	case script.CCVTreeOptions:
		tier := CCV
		if v.C0 {
			tier = CCV0
		}
		return rules{
			tier: tier, sparse: v.Sparse, operatorKey: v.OperatorKey,
			treeID: v.TreeID, exact: true, tower: v.Tower,
			exitConsent: v.UpdateX || v.ClaimX || v.ClaimHX,
		}, nil
	}
	return rules{}, fmt.Errorf("txn: unknown option set %T", o)
}

// --------------------------------------------------- witness encoding --

// The builders assemble a witness body from the parts below and hand it to
// finish, which frames it for the tier: under 0xC0 numerics the PADZ pad of
// the new total goes underneath (zf wf), the MIN tier's raw introspection
// pieces underneath that, and r m on top unless the tier is CCV. Inside the
// body a "fold" is one proof path with the items the script folds along
// it; the first fold the script runs carries, under 0xC0 numerics, the PADZ
// pad of the input amount (zi wi) in front of its levels.

// levels renders the proof levels of one fold: the sibling path from
// height upward, as dir sc pairs (dense) or compressed nodes (sparse) in
// the 0xC2 encoding, or as nine items per level with the pads sized
// against the running old and new accumulators under 0xC0 numerics
// (script.MidLevelsWitness). oldNode and newNode are the nodes the fold
// starts from; the 0xC2 encoding ignores them.
func (r rules) levels(path []tree.PathStep, height int, oldNode,
	newNode tree.Node) [][]byte {

	if r.tier.elements() {
		return script.MidLevelsWitness(path, oldNode, newNode, r.sparse, height)
	}
	if r.sparse {
		return SparsePathWitness(path, height)
	}
	return DensePathWitness(path)
}

// inputPad is zi wi, the PADZ pad of the input amount that the first fold
// of a 0xC0 script carries in front of its levels; nothing in 0xC2.
func (r rules) inputPad(inputSum uint64) [][]byte {
	if !r.tier.elements() {
		return nil
	}
	z, w := script.MidPad(inputSum)
	return [][]byte{z, w}
}

// pos renders the sparse position items ok nonce pos_lo pos_hi that follow
// a fold's levels under 0xC0 numerics in the sparse profile (the 0xC2
// scripts derive the position from the leaf record); nothing otherwise.
func (r rules) pos(leaf *tree.Leaf) [][]byte {
	if r.tier.elements() && r.sparse {
		return script.MidPosWitness(leaf)
	}
	return nil
}

// leaf renders a leaf: the 116-byte record, or under 0xC0 numerics its
// ten field elements, with the minimal evict_after and its pad appended
// when the script evicts (exit).
func (r rules) leaf(l *tree.Leaf, exit bool) [][]byte {
	switch {
	case !r.tier.elements():
		return [][]byte{l.Serialize()}
	case exit:
		return script.MidLeafExitWitness(l)
	default:
		return script.MidLeafWitness(l)
	}
}

// sum renders a node sum: le64 in 0xC2, a minimal number under 0xC0.
func (r rules) sum(n uint64) []byte {
	if r.tier.elements() {
		return script.MidScriptNum(n)
	}
	return tree.Le64(n)
}

// paddedSum renders a node sum with its PADZ pad under 0xC0 numerics
// (sum_num z w), le64 in 0xC2.
func (r rules) paddedSum(n uint64) [][]byte {
	if !r.tier.elements() {
		return [][]byte{tree.Le64(n)}
	}
	z, w := script.MidPad(n)
	return [][]byte{script.MidScriptNum(n), z, w}
}

// pad is the PADZ pad of n alone (z w).
func pad(n uint64) [][]byte {
	z, w := script.MidPad(n)
	return [][]byte{z, w}
}

// carveExtras are the thirteen extras of a 0xC0 carve witness
// (tools/layertree_mid.py w_carve_extras): the source seq as a number
// with its pad, the pad of seq + 1, the pad of the source's new amount,
// and the minimal evict_after of the source and of the claim leaf with
// their pads. Nothing in 0xC2, whose scripts read the fields out of the
// leaf records.
func (r rules) carveExtras(src, claim *tree.Leaf, newSrcAmount uint64) [][]byte {
	if !r.tier.elements() {
		return nil
	}
	var out [][]byte
	out = append(out, script.MidScriptNum(uint64(src.Seq)))
	out = append(out, pad(uint64(src.Seq))...)
	out = append(out, pad(uint64(src.Seq)+1)...)
	out = append(out, pad(newSrcAmount)...)
	out = append(out, r.paddedSum(uint64(src.EvictAfter))...)
	out = append(out, r.paddedSum(uint64(claim.EvictAfter))...)
	return out
}

// evictPadNodes lists the internal nodes below a subtree root of height h,
// as (height, index within the subtree), in the order the 0xC0 sweep's and
// rewrite's hash pass consumes their pads: right child before left, a node
// after its children, the root left out (tools/layertree_mid.py
// evict_subtree_pad_nodes). The witness lists the pad pairs in the reverse
// of this order, so the first one consumed sits nearest the top.
func evictPadNodes(height int) [][2]int {
	var out [][2]int
	var visit func(k, i int)
	visit = func(k, i int) {
		if k == 0 {
			return
		}
		visit(k-1, 2*i+1)
		visit(k-1, 2*i)
		if k < height {
			out = append(out, [2]int{k, i})
		}
	}
	visit(height, 0)
	return out
}

// nodePads renders the PADZ pads of the internal nodes of the aligned
// subtree (height, index) under 0xC0 numerics, in witness order, one pad
// per tree given for each node (the rewrite passes the new tree, then the
// old; the sweep the old alone). Nothing in 0xC2.
func (r rules) nodePads(height int, index uint64, trees ...*tree.Tree) [][]byte {
	if !r.tier.elements() {
		return nil
	}
	nodes := evictPadNodes(height)
	var out [][]byte
	for n := len(nodes) - 1; n >= 0; n-- {
		k, i := nodes[n][0], nodes[n][1]
		sub := index<<uint(height-k) + uint64(i)
		for _, t := range trees {
			out = append(out, pad(t.Subtree(k, sub).Sum)...)
		}
	}
	return out
}

// stackLimit is BIP-342's bound on stack plus altstack elements after
// every opcode, which binds the 0xC0 cohort scripts (spec 4.5).
const stackLimit = 1000

// witnessLen is the length of the framed witness stack finish will build
// from a body of bodyLen elements: the PADZ pad of the new total
// underneath under 0xC0 numerics, r m on top unless the tier is CCV.
func (r rules) witnessLen(bodyLen int) int {
	n := bodyLen
	if r.tier.elements() {
		n += 2
	}
	if !r.tier.ccv() {
		n += 2
	}
	return n
}

// checkStack rejects, under 0xC0 numerics, a cohort witness the script
// would run past the 1,000-element limit (spec 4.5, 4.6): the witness plus
// the elements the script peaks above it (peak) must fit. FULL has no such
// bound, since BIP-441 raises the element limit.
func (r rules) checkStack(name string, bodyLen, peak int) error {
	if !r.tier.elements() {
		return nil
	}
	if n := r.witnessLen(bodyLen); n+peak > stackLimit {
		return fmt.Errorf("txn: %s needs %d witness elements and peaks "+
			"%d above them, past the 1,000-element stack limit of the "+
			"0xC0 tiers (spec 4.5); split the cohort", name, n, peak)
	}
	return nil
}

// checkTotals rejects, under 0xC0 numerics, a tree total the PADZ gadget
// cannot carry (spec 4.5): every sum of a MID tree is a minimal CScriptNum
// below 2^31, and a total within the bound keeps every partial sum and
// every leaf amount within it too. Without this check the encoder would
// panic on the first oversized sum.
func (r rules) checkTotals(trees ...*tree.Tree) error {
	if !r.tier.elements() {
		return nil
	}
	for _, t := range trees {
		if s := t.Root().Sum; s > script.MidMaxSum {
			return fmt.Errorf("txn: a tree total of %d exceeds the 0xC0 "+
				"tiers' sum cap of %d (spec 4.5)", s, script.MidMaxSum)
		}
	}
	return nil
}
