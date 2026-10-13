package txn

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"

	"github.com/roasbeef/layertree/script"
	"github.com/roasbeef/layertree/tree"
)

// This file builds, signs and verifies every transition of every tier end
// to end. The scenarios mirror the Python suites (tools/test_scripts.py,
// test_mid.py, test_min.py, test_ccv.py): the same key labels (sk(label) =
// sha256(label)), the same leaves (mk_leaf), positions, amounts, fees and
// lock times. The FULL world is the FULL suite's taptree (all_scripts with
// join heights (0, 2), exit sizes (1, 2) and JOINK_2, with tree-creation
// variants appended as the suite appends them); the other tiers' worlds
// are compiled from their option sets with the same members and the
// variants folded in. The transaction's inputs use TxContext's default
// prevouts (sha256("prevout<i>"), vout i) and sequences (0xfffffffd), so a
// TxContext built from the same inputs and outputs describes the same
// transaction.
//
// pythonSighash (pins_test.go) holds, for every case, the BIP-341
// signature hash tools/script_sim.py TxContext.sighash() computes for the
// transaction the Go builder produced, with tapleaf_hash set to the
// revealed leaf (the suites themselves sign with a zero tapleaf hash, so
// their own digests are not comparable). The same run executed each signed
// Go witness with script_sim.Interp in the leaf's mode against that
// context and every one succeeded. To repeat it, run the tests with
// LAYERTREE_TXN_DUMP=<file>, which writes each case's transaction, script
// and stack as JSON, and feed the file to tools/replay_txn_dump.py, which
// rebuilds each TxContext, runs each witness through Interp and prints
// the map.

const p2wpkhHex = "00140000000000000000000000000000000000000000"

// sk is the Python suite's key derivation: the private key is sha256(label).
func sk(label string) *btcec.PrivateKey {
	seed := sha256.Sum256([]byte(label))
	priv, _ := btcec.PrivKeyFromBytes(seed[:])
	return priv
}

// xonly is the BIP-340 x-only public key of priv.
func xonly(priv *btcec.PrivateKey) [32]byte {
	var x [32]byte
	copy(x[:], schnorr.SerializePubKey(priv.PubKey()))
	return x
}

// prevOutPoint is TxContext's default prevout i: (sha256("prevout<i>"), i).
func prevOutPoint(i int) wire.OutPoint {
	return wire.OutPoint{
		Hash:  chainhash.Hash(sha256.Sum256([]byte(fmt.Sprintf("prevout%d", i)))),
		Index: uint32(i),
	}
}

// p2wpkh is the suite's placeholder fee and change script.
func p2wpkh(t *testing.T) []byte {
	return mustHex(t, p2wpkhHex)
}

// world mirrors the suites' World: one tree of a given tier, depth and
// profile with a taptree, the rules its builders read, and every private
// key the scenario created.
type world struct {
	t      *testing.T
	depth  int
	sparse bool
	op     *btcec.PrivateKey
	keys   []*btcec.PrivateKey
	st     *TreeState
	r      rules
}

// suiteTreeID is the suite's tree_id (spec 6.2): the RECOMMENDED derivation
// over the placeholder creation outpoint (sha256("creation-txid"), 0), the
// value every Python suite and the golden vectors use.
func suiteTreeID() [32]byte {
	return tree.TreeID(sha256.Sum256([]byte("creation-txid")), 0)
}

// caseSpec is what a case asks of its world: the tier, depth and profile,
// whether the exits are exact (FULL's EXIT_K^=) or tower-delegable, and the
// tree-creation variants the taptree carries beyond the reference set.
type caseSpec struct {
	tier     Tier
	depth    int
	sparse   bool
	exact    bool
	tower    bool
	variants []string

	// pending selects the pending-leaf receive world of pending_test.go
	// (FULL, MID, CCV and CCV0): pendingOptions, with UPDATE^x when the
	// variants name UPDATE_X.
	pending bool
}

// newWorld builds the world a case asks for. The FULL reference world is
// the FULL suite's taptree assembled by hand (the suite appends its
// variants beside the scripts they would replace, UPDATE_X next to UPDATE,
// a shape FullTreeOptions.Scripts does not emit); every other world is
// compiled through NewTreeState from its tier's option set.
func newWorld(t *testing.T, c caseSpec) *world {
	t.Helper()
	op := sk("operator")
	opKey, treeID := xonly(op), suiteTreeID()
	w := &world{
		t: t, depth: c.depth, sparse: c.sparse, op: op,
		keys: []*btcec.PrivateKey{op},
	}
	var opts Options
	switch {
	case c.pending:
		opts = pendingOptions(c, opKey, treeID)
		w.keys = append(w.keys, sk("operator-owner"), sk("rcpt-exit"),
			sk("operator-reclaim"))
	case c.tier == Full:
		if !c.exact && !c.tower {
			w.st = fullSuiteState(t, c, opKey, treeID)
			break
		}
		o := suiteOptions(opKey, treeID, c.sparse)
		o.Exact, o.Tower = true, c.tower
		opts = o
	case c.tier == Mid:
		opts = midOptions(opKey, treeID, c.sparse, c.tower, c.variants)
	case c.tier == Min:
		opts = script.MinTreeOptions{}
	case c.tier == CCV || c.tier == CCV0:
		opts = ccvOptions(opKey, treeID, c.tier == CCV0, c.sparse, c.tower,
			c.variants)
	default:
		t.Fatalf("no world for tier %v", c.tier)
	}
	if opts != nil {
		st, err := NewTreeState(tree.New(c.depth), opts, prevOutPoint(0))
		if err != nil {
			t.Fatalf("NewTreeState: %v", err)
		}
		if st.TapTree.Root() != opts.TapTreeRoot(c.depth) {
			t.Fatal("NewTreeState's taptree root is not the options' m")
		}
		w.st = st
	}
	r, err := w.st.rules()
	if err != nil {
		t.Fatalf("rules: %v", err)
	}
	w.r = r
	return w
}

// fullSuiteState is the FULL suite's world: the reference taptree for
// (depth, profile) with the named tree-creation variants appended, as the
// suite does for UPDATE_X, CLAIM_H, SPLIT and EVICT_SUBTREE_h, and the
// reference members as the options the builders consult.
func fullSuiteState(t *testing.T, c caseSpec, opKey, treeID [32]byte) *TreeState {
	t.Helper()
	depth, sparse := c.depth, c.sparse
	leaves, err := FullReferenceLeaves(
		depth, opKey, treeID, sparse, []int{0, 2}, []int{1, 2}, []int{2},
		tree.DustMin,
	)
	if err != nil {
		t.Fatalf("FullReferenceLeaves: %v", err)
	}
	for _, name := range c.variants {
		var toks []script.Token
		switch name {
		case "UPDATE_X":
			toks = script.FullUpdateXScript(depth, opKey, sparse)
		case "CLAIM_H":
			toks = script.FullClaimHScript(depth, treeID, sparse, tree.DustMin)
		case "CLAIM_X":
			toks = script.FullClaimXScript(depth, treeID, sparse, tree.DustMin)
		case "CLAIM_HX":
			toks = script.FullClaimHXScript(depth, treeID, sparse, tree.DustMin)
		case "SPLIT":
			toks = script.FullSplitScript(depth, sparse, tree.DustMin)
		case "EVICT_SUBTREE_2":
			toks = script.FullEvictSubtreeScript(depth, 2, opKey)
		case "EVICT_SUBTREE_4":
			toks = script.FullEvictSubtreeScript(depth, 4, opKey)
		case "REWRITE_2":
			toks = script.FullRewriteScript(depth, 2, opKey, false)
		case "REWRITE_X_2":
			toks = script.FullRewriteScript(depth, 2, opKey, true)
		case "DETACH_2":
			// m_h is the suite's option set at depth 2, which is what
			// BuildDetach compiles the child's taptree from.
			opts := suiteOptions(opKey, treeID, sparse)
			toks = script.FullDetachScript(depth, 2, opKey, opts.TapTreeRoot(2))
		default:
			t.Fatalf("unknown variant %s", name)
		}
		leaf, err := FullLeaf(name, toks)
		if err != nil {
			t.Fatalf("FullLeaf: %v", err)
		}
		leaves = append(leaves, leaf)
	}
	tt, err := NewTapTree(leaves)
	if err != nil {
		t.Fatalf("NewTapTree: %v", err)
	}
	return &TreeState{
		Tree:     tree.New(depth),
		Options:  suiteOptions(opKey, treeID, sparse),
		TapTree:  tt,
		OutPoint: prevOutPoint(0),
	}
}

// suiteOptions are the suite's reference members as creation parameters:
// EXIT_1, EXIT_2, JOIN_0, JOIN_2, JOINK_2, UPDATE and CLAIM.
func suiteOptions(opKey, treeID [32]byte, sparse bool) script.FullTreeOptions {
	return script.FullTreeOptions{
		OperatorKey: opKey, TreeID: treeID, Sparse: sparse,
		JoinHeights: []int{0, 2}, ExitKs: []int{1, 2}, JoinKs: []int{2},
		Claim: true,
	}
}

// variantHeight reads the height off a variant name such as
// "EVICT_SUBTREE_4"; -1 if the name carries none.
func variantHeight(name, prefix string) int {
	if !strings.HasPrefix(name, prefix) {
		return -1
	}
	var h int
	if _, err := fmt.Sscanf(name[len(prefix):], "%d", &h); err != nil {
		return -1
	}
	return h
}

// midOptions are the MID suite's reference members (layertree_mid
// all_scripts: EXIT_1, EXIT_2, JOIN_0, JOIN_2, JOINK_2, UPDATE, CLAIM) with
// the variants the case names folded in, as the suite swaps or appends
// them (UPDATE_X in place of UPDATE, the rest beside the reference).
func midOptions(opKey, treeID [32]byte, sparse, tower bool,
	variants []string) script.MidTreeOptions {

	o := script.MidTreeOptions{
		OperatorKey: opKey, TreeID: treeID, Sparse: sparse, Tower: tower,
		JoinHeights: []int{0, 2}, ExitKs: []int{1, 2}, JoinKs: []int{2},
		Claim: true,
	}
	for _, v := range variants {
		switch {
		case v == "UPDATE_X":
			o.UpdateX = true
		case v == "CLAIM_H":
			o.ClaimH = true
		case v == "CLAIM_X":
			o.ClaimX = true
		case v == "CLAIM_HX":
			o.ClaimHX = true
		case v == "SPLIT":
			o.Split = true
		case variantHeight(v, "EVICT_SUBTREE_") >= 0:
			o.EvictHeights = append(o.EvictHeights, variantHeight(v, "EVICT_SUBTREE_"))
		case variantHeight(v, "REWRITE_X_") >= 0:
			o.RewriteHeights = append(o.RewriteHeights, variantHeight(v, "REWRITE_X_"))
			o.RewriteX = true
		case variantHeight(v, "REWRITE_") >= 0:
			o.RewriteHeights = append(o.RewriteHeights, variantHeight(v, "REWRITE_"))
		case variantHeight(v, "DETACH_") >= 0:
			o.DetachHeights = append(o.DetachHeights, variantHeight(v, "DETACH_"))
		}
	}
	return o
}

// ccvOptions are the CCV suite's reference members (all_scripts_ccv with
// the suite's join heights (0, 2), exit sizes (1, 2) and JOINK_2) in the
// given numerics, with the case's variants folded in.
func ccvOptions(opKey, treeID [32]byte, c0, sparse, tower bool,
	variants []string) script.CCVTreeOptions {

	o := script.CCVTreeOptions{
		OperatorKey: opKey, TreeID: treeID, C0: c0, Sparse: sparse,
		Tower: tower, JoinHeights: []int{0, 2}, ExitKs: []int{1, 2},
		JoinKs: []int{2},
	}
	for _, v := range variants {
		switch {
		case v == "UPDATE_X":
			o.UpdateX = true
		case v == "CLAIM":
			o.Claim = true
		case v == "CLAIM_H":
			o.ClaimH = true
		case v == "CLAIM_X":
			o.ClaimX = true
		case v == "CLAIM_HX":
			o.ClaimHX = true
		case v == "SPLIT":
			o.Split = true
		case variantHeight(v, "EVICT_SUBTREE_") >= 0:
			o.EvictHeights = append(o.EvictHeights, variantHeight(v, "EVICT_SUBTREE_"))
		case variantHeight(v, "REWRITE_X_") >= 0:
			o.RewriteHeights = append(o.RewriteHeights, variantHeight(v, "REWRITE_X_"))
			o.RewriteX = true
		case variantHeight(v, "REWRITE_") >= 0:
			o.RewriteHeights = append(o.RewriteHeights, variantHeight(v, "REWRITE_"))
		case variantHeight(v, "DETACH_") >= 0:
			o.DetachHeights = append(o.DetachHeights, variantHeight(v, "DETACH_"))
		}
	}
	return o
}

// opKey is the world's operator key, the evictor the suite's leaves name.
// It is the option set's OPERATOR_KEY in every tier but MIN, whose option
// set has none: the MIN scripts check the evictor key out of the leaf.
func (w *world) opKey() [32]byte { return xonly(w.op) }

// treeID is the world's tree_id, as the builders read it off the option
// set.
func (w *world) treeID() [32]byte { return w.r.treeID }

// fixNonce grinds a leaf's nonce, in a 0xC0 sparse world, until its pos_lo
// is a minimal positive number (spec 4.5), as the MID suite's mk_leaf does.
func (w *world) fixNonce(leaf *tree.Leaf) {
	for w.sparse && w.r.tier.elements() && !leaf.PosLoMinimal(w.depth) {
		leaf.Nonce++
	}
}

// mkLeaf is the suite's mk_leaf: exit and owner keys from "<label>-exit"
// and "<label>-owner", the NUMS evictor unless one is given, and the nonce
// le32(sha256(label)[:4]), ground where the tier's sparse scripts need it.
func (w *world) mkLeaf(label string, amount uint64, evictor *[32]byte,
	evictAfter uint32) *tree.Leaf {

	exit, owner := sk(label+"-exit"), sk(label+"-owner")
	w.keys = append(w.keys, exit, owner)
	h := sha256.Sum256([]byte(label))
	leaf := &tree.Leaf{
		Amount:     amount,
		ExitKey:    xonly(exit),
		OwnerKey:   xonly(owner),
		EvictAfter: evictAfter,
		Nonce:      binary.LittleEndian.Uint32(h[:4]),
	}
	if evictor != nil {
		leaf.EvictorKey = *evictor
	} else {
		nums, err := tree.HexKey(tree.NUMSHex)
		if err != nil {
			w.t.Fatalf("NUMS: %v", err)
		}
		leaf.EvictorKey = nums
	}
	w.fixNonce(leaf)
	return leaf
}

// carveOf is the suite's carve_of: a leaf carved out of src, which keeps
// src's evictor_key and evict_after as spec 7.5 rule 5 requires.
func (w *world) carveOf(src *tree.Leaf, label string, amount uint64) *tree.Leaf {
	return w.mkLeaf(label, amount, &src.EvictorKey, src.EvictAfter)
}

// slot is the suite's World.slot: the derived position in the sparse
// profile, the operator-assigned one otherwise. In the sparse profile it
// advances the nonce until the position is free in every tree given, as a
// real joiner would (the suite does the same for JOINK_2).
func (w *world) slot(leaf *tree.Leaf, want uint64, trees ...*tree.Tree) uint64 {
	if !w.sparse {
		return want
	}
	for {
		pos := leaf.Position(w.depth)
		free := true
		for _, tr := range trees {
			if _, ok := tr.Leaves[pos]; ok {
				free = false
			}
		}
		if free {
			return pos
		}
		leaf.Nonce++
		w.fixNonce(leaf)
	}
}

// fee returns an extra input at TxContext's default prevout 1.
func (w *world) fee(amount int64) []ExtraInput {
	return []ExtraInput{{
		OutPoint: prevOutPoint(1),
		Sequence: TreeSequence,
		PrevOut:  wire.NewTxOut(amount, p2wpkh(w.t)),
	}}
}

// creditLeaf populates the suite's credit-leaf tree of 10.3 (test_claim_x):
// a leaf the operator owns whose exit key is the recipient's, at the last
// position, with alice at 0. Returns the credit leaf and its position.
func (w *world) creditLeaf() (*tree.Leaf, uint64) {
	recipient := sk("recipient-exit")
	w.keys = append(w.keys, recipient)
	h := sha256.Sum256([]byte("credit"))
	nums, err := tree.HexKey(tree.NUMSHex)
	if err != nil {
		w.t.Fatalf("NUMS: %v", err)
	}
	credit := &tree.Leaf{
		Amount:     1_000_000,
		ExitKey:    xonly(recipient),
		OwnerKey:   w.opKey(),
		EvictorKey: nums,
		Nonce:      binary.LittleEndian.Uint32(h[:4]),
	}
	w.fixNonce(credit)
	alice := w.mkLeaf("alice", 50_000, nil, 0)
	tr := w.st.Tree
	sCredit := w.slot(credit, uint64(1)<<w.depth-1, tr)
	tr.Leaves[sCredit] = credit
	sAlice := w.slot(alice, 0, tr)
	tr.Leaves[sAlice] = alice
	return credit, sCredit
}

// base populates the suite's starting tree: alice at 0, bob (evictable by
// the operator from height 800,000) at 5 and the operator's leaf at the
// last position.
func (w *world) base() (alice, bob, oper *tree.Leaf, sAlice, sBob,
	sOper uint64) {

	opKey := w.opKey()
	alice = w.mkLeaf("alice", 50_000, nil, 0)
	bob = w.mkLeaf("bob", 125_000, &opKey, 800_000)
	oper = w.mkLeaf("operator", 1_000_000, nil, 0)
	tr := w.st.Tree
	sAlice = w.slot(alice, 0, tr)
	tr.Leaves[sAlice] = alice
	sBob = w.slot(bob, 5, tr)
	tr.Leaves[sBob] = bob
	sOper = w.slot(oper, uint64(1)<<w.depth-1, tr)
	tr.Leaves[sOper] = oper
	return
}

// txCase is one end-to-end transition: build returns the spend and the
// tree after it.
type txCase struct {
	caseSpec
	name  string
	build func(w *world) (*Spend, *tree.Tree, error)

	// tamper, when set, edits the signed spend's stack after every Go
	// check has passed, and expectFail marks the result as one the
	// scripts must reject: the dump records it so, and the replay counts
	// it as a failure if the simulator accepts it. Only an edit no Go
	// check can see belongs here (the CCV output-0 mode flag, which the
	// signature hash does not cover).
	tamper     func(s *Spend)
	expectFail bool
}

func (c *txCase) key() string {
	profile := "D"
	if c.sparse {
		profile = "S"
	}
	return fmt.Sprintf("%v/%s/D%d/%s", c.tier, profile, c.depth, c.name)
}

// hasVariant reports whether s names the tree-creation variant.
func (s caseSpec) hasVariant(name string) bool {
	for _, v := range s.variants {
		if v == name {
			return true
		}
	}
	return false
}

// withVariant is s with one more tree-creation variant.
func (s caseSpec) withVariant(names ...string) caseSpec {
	s.variants = append(append([]string{}, s.variants...), names...)
	return s
}

// exitCases are EXIT_1 (owner and eviction), EXIT_2 and the terminal exit,
// with FULL's exact-payout and the tower-delegable variants where the tier
// has them. In FULL the owner exit leaves a fee to the transaction (7.2
// rule 3); in every other tier the payout is exact and the fee input pays.
func exitCases(s caseSpec) []txCase {
	cases := []txCase{{
		name: "EXIT_1 owner", caseSpec: s,
		build: func(w *world) (*Spend, *tree.Tree, error) {
			_, _, _, _, sBob, _ := w.base()
			if w.r.exact {
				return BuildExit(w.st, []ExitStep{{Pos: sBob}}, &TxOpts{
					Inputs:  w.fee(5_000),
					Outputs: []*wire.TxOut{wire.NewTxOut(400, p2wpkh(w.t))},
				})
			}
			return BuildExit(w.st, []ExitStep{{Pos: sBob, Fee: 1_000}},
				&TxOpts{
					Inputs: w.fee(50_000),
					Outputs: []*wire.TxOut{
						wire.NewTxOut(49_000, p2wpkh(w.t)),
					},
				})
		},
	}}
	if s.tier == Full {
		// An owner exit under EXIT_1^= (spec 7.2 rule 6): the payout is
		// the whole leaf and the fee comes from the extra input.
		exact := s
		exact.exact = true
		cases = append(cases, txCase{
			name: "EXIT_1 exact", caseSpec: exact,
			build: func(w *world) (*Spend, *tree.Tree, error) {
				_, _, _, _, sBob, _ := w.base()
				return BuildExit(w.st, []ExitStep{{Pos: sBob}},
					&TxOpts{Inputs: w.fee(5_000)})
			},
		})
	}
	if s.tier != Min {
		tower := s
		tower.tower = true
		cases = append(cases, txCase{
			// A tower's exit under EXIT_1^t (spec 7.2 rule 7): the owner
			// signed the authorisation off-chain, before the transaction
			// existed; the tower builds the exit with its own fee input
			// and signs nothing on the tree input.
			name: "EXIT_1 tower", caseSpec: tower,
			build: func(w *world) (*Spend, *tree.Tree, error) {
				_, bob, _, _, sBob, _ := w.base()
				auth, err := SignExitAuth(sk("bob-owner"), w.treeID(), bob)
				if err != nil {
					return nil, nil, err
				}
				spend, next, err := BuildExit(w.st, []ExitStep{{Pos: sBob, Auth: auth}},
					&TxOpts{Inputs: w.fee(5_000)})
				if err == nil && len(spend.Sigs) != 0 {
					return nil, nil, fmt.Errorf("a tower exit has %d "+
						"signature slots, want none", len(spend.Sigs))
				}
				return spend, next, err
			},
		}, txCase{
			// The authorisation binds the leaf without its amount (spec
			// 7.2 rule 7), so one signed before an amount-only REWRITE_h
			// top-up of the leaf still exits it, for the new amount.
			name: "EXIT_1 tower topped", caseSpec: tower,
			build: func(w *world) (*Spend, *tree.Tree, error) {
				_, bob, _, _, sBob, _ := w.base()
				auth, err := SignExitAuth(sk("bob-owner"), w.treeID(), bob)
				if err != nil {
					return nil, nil, err
				}
				topped := *bob
				topped.Amount += 500
				w.st.Tree.Leaves[sBob] = &topped
				return BuildExit(w.st, []ExitStep{{Pos: sBob, Auth: auth}},
					&TxOpts{Inputs: w.fee(5_000)})
			},
		})
	}
	cases = append(cases, txCase{
		name: "EXIT_1 evict", caseSpec: s,
		build: func(w *world) (*Spend, *tree.Tree, error) {
			_, _, _, _, sBob, _ := w.base()
			return BuildExit(w.st, []ExitStep{{Pos: sBob, Evict: true}},
				&TxOpts{LockTime: 800_000, Inputs: w.fee(5_000)})
		},
	})
	if s.tier == Min {
		// MIN has EXIT_1 alone, and its output 0 is always a tree output,
		// so there is no EXIT_2 and no terminal exit (spec 4.5).
		return cases
	}
	return append(cases, txCase{
		name: "EXIT_2 owner+evict", caseSpec: s,
		build: func(w *world) (*Spend, *tree.Tree, error) {
			w.base()
			opKey := w.opKey()
			carol := w.mkLeaf("carol", 30_000, &opKey, 900_000)
			dave := w.mkLeaf("dave", 70_000, &opKey, 900_000)
			tr := w.st.Tree
			sCarol := w.slot(carol, 8, tr)
			tr.Leaves[sCarol] = carol
			sDave := w.slot(dave, 11, tr)
			tr.Leaves[sDave] = dave
			fee := int64(300)
			if w.r.exact {
				fee = 0
			}
			return BuildExit(w.st, []ExitStep{
				{Pos: sCarol, Fee: fee},
				{Pos: sDave, Evict: true},
			}, &TxOpts{LockTime: 900_000, Inputs: w.fee(5_000)})
		},
	}, txCase{
		name: "EXIT_1 terminal", caseSpec: s,
		build: func(w *world) (*Spend, *tree.Tree, error) {
			solo := w.mkLeaf("solo", 77_000, nil, 0)
			sSolo := w.slot(solo, 2, w.st.Tree)
			w.st.Tree.Leaves[sSolo] = solo
			fee := int64(400)
			if w.r.exact {
				fee = 0
			}
			return BuildExit(w.st, []ExitStep{{Pos: sSolo, Fee: fee}},
				&TxOpts{
					Inputs:   w.fee(1_000),
					Terminal: wire.NewTxOut(600, p2wpkh(w.t)),
				})
		},
	})
}

// joinCases are JOIN_0, JOINK_2 and, in the dense profile, JOIN_2.
func joinCases(s caseSpec) []txCase {
	cases := []txCase{{
		name: "JOIN_0", caseSpec: s,
		build: func(w *world) (*Spend, *tree.Tree, error) {
			w.base()
			opKey := w.opKey()
			erin := w.mkLeaf("erin", 12_345, &opKey, 900_000)
			sErin := w.slot(erin, 9, w.st.Tree)
			return BuildJoin(w.st, 0, sErin,
				map[uint64]*tree.Leaf{0: erin},
				&TxOpts{Inputs: w.fee(int64(erin.Amount) + 500)})
		},
	}, {
		name: "JOINK_2", caseSpec: s,
		build: func(w *world) (*Spend, *tree.Tree, error) {
			w.base()
			opKey := w.opKey()
			hank := w.mkLeaf("hank", 9_000, &opKey, 900_000)
			sHank := w.slot(hank, 12, w.st.Tree)
			ivy := w.mkLeaf("ivy", 11_000, &opKey, 900_000)
			taken := tree.New(w.depth)
			taken.Leaves[sHank] = hank
			sIvy := w.slot(ivy, 13, w.st.Tree, taken)
			return BuildJoinK(w.st, []PlacedLeaf{
				{Pos: sHank, Leaf: hank},
				{Pos: sIvy, Leaf: ivy},
			}, &TxOpts{Inputs: w.fee(
				int64(hank.Amount+ivy.Amount) + 700,
			)})
		},
	}}
	if s.sparse {
		return cases
	}
	return append(cases, txCase{
		name: "JOIN_2", caseSpec: s,
		build: func(w *world) (*Spend, *tree.Tree, error) {
			w.base()
			opKey := w.opKey()
			carol := w.mkLeaf("carol", 30_000, &opKey, 900_000)
			dave := w.mkLeaf("dave", 70_000, &opKey, 900_000)
			return BuildJoin(w.st, 2, 2,
				map[uint64]*tree.Leaf{0: carol, 3: dave},
				&TxOpts{
					Inputs: w.fee(
						int64(carol.Amount+dave.Amount) + 2_000,
					),
					Outputs: []*wire.TxOut{
						wire.NewTxOut(900, p2wpkh(w.t)),
					},
				})
		},
	})
}

// withAmountSeq is the suite's Leaf.with_amount_seq: a copy of l with a new
// amount and seq.
func withAmountSeq(l *tree.Leaf, amount uint64, seq uint32) *tree.Leaf {
	c := *l
	c.Amount, c.Seq = amount, seq
	return &c
}

// wantModeFlag checks the CCV output-0 mode flag (spec 4.6) the builder
// put at the bottom of the witness: DEDUCT (0x01) or assign (empty). Other
// tiers carry none.
func wantModeFlag(w *world, spend *Spend, deduct bool) error {
	if !w.r.tier.ccv() {
		return nil
	}
	want := []byte{}
	if deduct {
		want = []byte{0x01}
	}
	if got := spend.Stack[0]; !bytes.Equal(got, want) {
		return fmt.Errorf("the mode flag is %x, want %x", got, want)
	}
	return nil
}

// wantAmountOnly checks that the builder wrote n positions of a rewrite as
// amount-only elements (spec 7.9, 8.9): n eight-byte elements in the 0xC2
// tiers, whose paths, signatures and leaves are never eight bytes, and n
// slots ending in the flag 0x03 under 0xC0 numerics.
func wantAmountOnly(w *world, spend *Spend, n int) error {
	got := 0
	for _, el := range spend.Stack {
		if w.r.tier.elements() && bytes.Equal(el, []byte{0x03}) ||
			!w.r.tier.elements() && len(el) == 8 {

			got++
		}
	}
	if got != n {
		return fmt.Errorf("%d amount-only elements, want %d", got, n)
	}
	return nil
}

// updateCases are UPDATE and UPDATE^x: alice tops her leaf up from 50,000
// to 80,000 and bumps seq, funded by a second input (assign under CCV), and
// the same with alice lowering it to 20,000, the 30,000 freed going to a
// change output (DEDUCT under CCV).
func updateCases(s caseSpec) []txCase {
	update := func(amount uint64, opts *TxOpts, deduct,
		x bool) func(w *world) (*Spend, *tree.Tree, error) {

		return func(w *world) (*Spend, *tree.Tree, error) {
			alice, _, _, sAlice, _, _ := w.base()
			alice2 := withAmountSeq(alice, amount, 1)
			o := *opts
			if o.Inputs != nil {
				o.Inputs = w.fee(30_700)
			}
			if o.Outputs != nil {
				o.Outputs = []*wire.TxOut{
					wire.NewTxOut(29_500, p2wpkh(w.t)),
				}
			}
			var (
				spend *Spend
				next  *tree.Tree
				err   error
			)
			if x {
				spend, next, err = BuildUpdateX(w.st, sAlice, alice2, &o)
			} else {
				spend, next, err = BuildUpdate(w.st, sAlice, alice2, &o)
			}
			if err == nil {
				err = wantModeFlag(w, spend, deduct)
			}
			return spend, next, err
		}
	}
	funded := &TxOpts{Inputs: []ExtraInput{{}}}
	freed := &TxOpts{Outputs: []*wire.TxOut{{}}}
	return []txCase{{
		name: "UPDATE", caseSpec: s,
		build: update(80_000, funded, false, false),
	}, {
		name: "UPDATE_X", caseSpec: s.withVariant("UPDATE_X"),
		build: update(80_000, funded, false, true),
	}, {
		name: "UPDATE decrease", caseSpec: s,
		build: update(20_000, freed, true, false),
	}, {
		name: "UPDATE_X decrease", caseSpec: s.withVariant("UPDATE_X"),
		build: update(20_000, freed, true, true),
	}}
}

// carveCases are CLAIM (partial and draining the source), CLAIM^h, CLAIM^x,
// CLAIM^hx and SPLIT; MIN has SPLIT alone. The CCV reference set has no
// CLAIM, so its CLAIM cases name it as a variant.
func carveCases(s caseSpec) []txCase {
	claim := s
	if s.tier == CCV || s.tier == CCV0 {
		claim = s.withVariant("CLAIM")
	}
	split := []txCase{{
		name: "SPLIT", caseSpec: s.withVariant("SPLIT"),
		build: func(w *world) (*Spend, *tree.Tree, error) {
			alice := w.mkLeaf("alice", 500_000, nil, 0)
			oper := w.mkLeaf("operator", 1_000_000, nil, 0)
			tr := w.st.Tree
			sAlice := w.slot(alice, 0, tr)
			tr.Leaves[sAlice] = alice
			sOper := w.slot(oper, uint64(1)<<w.depth-1, tr)
			tr.Leaves[sOper] = oper
			bob := w.carveOf(alice, "bob", 200_000)
			sBob := w.slot(bob, 3, tr)
			return BuildSplit(w.st, sAlice, sBob, bob,
				&TxOpts{Inputs: w.fee(600)})
		},
	}}
	if s.tier == Min {
		return append(split, txCase{
			name: "SPLIT drain", caseSpec: s.withVariant("SPLIT"),
			build: func(w *world) (*Spend, *tree.Tree, error) {
				alice := w.mkLeaf("alice", 500_000, nil, 0)
				oper := w.mkLeaf("operator", 1_000_000, nil, 0)
				tr := w.st.Tree
				tr.Leaves[0] = alice
				tr.Leaves[uint64(1)<<w.depth-1] = oper
				whole := w.carveOf(alice, "whole", alice.Amount)
				return BuildSplit(w.st, 0, 3, whole,
					&TxOpts{Inputs: w.fee(600)})
			},
		})
	}
	cases := []txCase{{
		name: "CLAIM", caseSpec: claim,
		build: func(w *world) (*Spend, *tree.Tree, error) {
			_, _, oper, _, _, sOper := w.base()
			frank := w.carveOf(oper, "frank", 40_000)
			sFrank := w.slot(frank, 3, w.st.Tree)
			vsig, err := SignVoucher(
				sk("operator-owner"), w.treeID(), oper, frank,
			)
			if err != nil {
				return nil, nil, err
			}
			return BuildClaim(w.st, sOper, sFrank, frank, vsig,
				&TxOpts{Inputs: w.fee(600)})
		},
	}, {
		// The voucher binds the source leaf without its amount (spec
		// 7.5), so one signed before an amount-only REWRITE_h top-up of
		// the source still redeems, against the topped-up leaf.
		name: "CLAIM topped", caseSpec: claim,
		build: func(w *world) (*Spend, *tree.Tree, error) {
			_, _, oper, _, _, sOper := w.base()
			frank := w.carveOf(oper, "frank", 40_000)
			sFrank := w.slot(frank, 3, w.st.Tree)
			vsig, err := SignVoucher(
				sk("operator-owner"), w.treeID(), oper, frank,
			)
			if err != nil {
				return nil, nil, err
			}
			topped := *oper
			topped.Amount += 500
			w.st.Tree.Leaves[sOper] = &topped
			return BuildClaim(w.st, sOper, sFrank, frank, vsig,
				&TxOpts{Inputs: w.fee(600)})
		},
	}, {
		name: "CLAIM drain", caseSpec: claim,
		build: func(w *world) (*Spend, *tree.Tree, error) {
			w.base()
			opKey := w.opKey()
			erin := w.mkLeaf("erin", 12_345, &opKey, 900_000)
			sErin := w.slot(erin, 9, w.st.Tree)
			w.st.Tree.Leaves[sErin] = erin
			gina := w.carveOf(erin, "gina", erin.Amount)
			sGina := w.slot(gina, 6, w.st.Tree)
			vsig, err := SignVoucher(
				sk("erin-owner"), w.treeID(), erin, gina,
			)
			if err != nil {
				return nil, nil, err
			}
			return BuildClaim(w.st, sErin, sGina, gina, vsig,
				&TxOpts{Inputs: w.fee(600)})
		},
	}, {
		name: "CLAIM_H", caseSpec: s.withVariant("CLAIM_H"),
		build: func(w *world) (*Spend, *tree.Tree, error) {
			_, _, oper, _, _, sOper := w.base()
			hodl := w.carveOf(oper, "hodl", 40_000)
			sHodl := w.slot(hodl, 3, w.st.Tree)
			preimage := sha256.Sum256([]byte("payment-preimage"))
			vsig, err := SignVoucherH(
				sk("operator-owner"), w.treeID(), oper, hodl,
				sha256.Sum256(preimage[:]),
			)
			if err != nil {
				return nil, nil, err
			}
			return BuildClaimH(w.st, sOper, sHodl, hodl, vsig,
				preimage, &TxOpts{Inputs: w.fee(600)})
		},
	}, {
		// The credit leaf of 10.3: the operator owns the source leaf and
		// signs the voucher, the recipient holds its exit key and signs
		// the redemption (spec 7.5.3).
		name: "CLAIM_X", caseSpec: s.withVariant("CLAIM_X"),
		build: func(w *world) (*Spend, *tree.Tree, error) {
			credit, sCredit := w.creditLeaf()
			claim := w.carveOf(credit, "recipient", 40_000)
			sClaim := w.slot(claim, 3, w.st.Tree)
			vsig, err := SignVoucher(w.op, w.treeID(), credit, claim)
			if err != nil {
				return nil, nil, err
			}
			return BuildClaimX(w.st, sCredit, sClaim, claim, vsig,
				&TxOpts{Inputs: w.fee(600)})
		},
	}, {
		name: "CLAIM_HX", caseSpec: s.withVariant("CLAIM_HX"),
		build: func(w *world) (*Spend, *tree.Tree, error) {
			credit, sCredit := w.creditLeaf()
			claim := w.carveOf(credit, "recipient", 40_000)
			sClaim := w.slot(claim, 3, w.st.Tree)
			preimage := sha256.Sum256([]byte("credit-preimage"))
			vsig, err := SignVoucherH(
				w.op, w.treeID(), credit, claim,
				sha256.Sum256(preimage[:]),
			)
			if err != nil {
				return nil, nil, err
			}
			return BuildClaimHX(w.st, sCredit, sClaim, claim, vsig,
				preimage, &TxOpts{Inputs: w.fee(600)})
		},
	}}
	return append(cases, split...)
}

// cohort populates the suite's cohort of test_evict_subtree and
// test_detach: positions base..base+2^h-1 hold c<i> leaves with a common
// lease, every fifth position from the fourth empty when gaps is set, and,
// unless the subtree is the whole tree, alice at 0 and the operator's leaf
// at the last position.
func (w *world) cohort(height int, index uint64, gaps bool) {
	opKey := w.opKey()
	base := index << uint(height)
	tr := w.st.Tree
	for i := 0; i < 1<<uint(height); i++ {
		if gaps && i%5 == 3 {
			continue
		}
		tr.Leaves[base+uint64(i)] = w.mkLeaf(
			fmt.Sprintf("c%d", i), 10_000+7*uint64(i), &opKey, 800_000,
		)
	}
	if height < w.depth {
		tr.Leaves[0] = w.mkLeaf("alice", 50_000, nil, 0)
		tr.Leaves[uint64(1)<<w.depth-1] = w.mkLeaf("operator", 1_000_000, nil, 0)
	}
}

// evictCases are EVICT_SUBTREE_2 and EVICT_SUBTREE_4 in the dense profile,
// laid out as the suite's test_evict_subtree: a cohort with a common lease
// in the subtree at index 1, every fifth position from the fourth already
// empty, alice and the operator's leaf outside it. When the subtree is the
// whole tree (h = D) there is no room outside it, so the sweep is the
// terminal transition of spec 7.8.
func evictCases(s caseSpec) []txCase {
	var cases []txCase
	for _, h := range []int{2, 4} {
		h := h
		name := fmt.Sprintf("EVICT_SUBTREE_%d", h)
		cases = append(cases, txCase{
			name: name, caseSpec: s.withVariant(name),
			build: func(w *world) (*Spend, *tree.Tree, error) {
				index := uint64(1)
				if h == w.depth {
					index = 0
				}
				w.cohort(h, index, true)
				opts := &TxOpts{
					LockTime: 800_000,
					Inputs:   w.fee(5_000),
				}
				if h == w.depth {
					opts.Terminal = wire.NewTxOut(400, p2wpkh(w.t))
				} else {
					opts.Outputs = []*wire.TxOut{
						wire.NewTxOut(400, p2wpkh(w.t)),
					}
				}
				return BuildEvictSubtree(w.st, h, index, opts)
			},
		})
	}
	return cases
}

// rewritePlan is the suite's mixed REWRITE_2 scenario over the cohort at
// index 1 (positions 4..7): position 4 exits, 5 is unchanged, 6 rotates
// its owner key and 7, empty before, is joined. Returns the contents of
// the subtree afterwards by offset and the funding the join needs (the
// exit is paid from the tree, so it frees nothing for the join).
func (w *world) rewritePlan() (map[uint64]*tree.Leaf, int64) {
	w.cohort(2, 1, false)
	tr := w.st.Tree
	delete(tr.Leaves, 7)
	opKey := w.opKey()
	rotated := *tr.Leaves[6]
	owner2 := sk("c2-owner2")
	w.keys = append(w.keys, owner2)
	rotated.OwnerKey = xonly(owner2)
	joined := w.mkLeaf("j3", 5_003, &opKey, 900_000)
	after := map[uint64]*tree.Leaf{
		1: tr.Leaves[5], 2: &rotated, 3: joined,
	}
	return after, int64(joined.Amount)
}

// rewriteCases are REWRITE_2, REWRITE_2^x and the operator's amount-only
// top-up of a cohort, dense profile.
func rewriteCases(s caseSpec) []txCase {
	rewrite := func(x bool) func(w *world) (*Spend, *tree.Tree, error) {
		return func(w *world) (*Spend, *tree.Tree, error) {
			after, funding := w.rewritePlan()
			spend, next, err := BuildRewrite(w.st, 2, 1, after, x, &TxOpts{
				Inputs:  w.fee(funding + 5_000),
				Outputs: []*wire.TxOut{wire.NewTxOut(400, p2wpkh(w.t))},
			})
			// Positions 4 and 6 sign by their owners (and under ^x by
			// their exit keys), 5 and 7 need nobody but the operator.
			want := 3
			if x {
				want = 5
			}
			if err == nil && len(spend.Sigs) != want {
				return nil, nil, fmt.Errorf("the rewrite has %d "+
					"signature slots, want %d", len(spend.Sigs), want)
			}
			// The exit's payout is deducted from the residual and the
			// join raises the sum above it: assign under CCV.
			if err == nil {
				err = wantModeFlag(w, spend, false)
			}
			return spend, next, err
		}
	}
	// decrease lowers position 4 by 3,000 (its owner signs) and exits
	// position 5, the net change below the residual: DEDUCT under CCV, the
	// freed value going to a change output (spec 7.9 rule 6).
	decrease := func(x bool) func(w *world) (*Spend, *tree.Tree, error) {
		return func(w *world) (*Spend, *tree.Tree, error) {
			w.cohort(2, 1, false)
			tr := w.st.Tree
			after := map[uint64]*tree.Leaf{
				0: withAmountSeq(tr.Leaves[4], tr.Leaves[4].Amount-3_000,
					tr.Leaves[4].Seq),
				1: nil,
				2: tr.Leaves[6],
				3: tr.Leaves[7],
			}
			spend, next, err := BuildRewrite(w.st, 2, 1, after, x, &TxOpts{
				Outputs: []*wire.TxOut{wire.NewTxOut(2_900, p2wpkh(w.t))},
			})
			if err == nil {
				err = wantModeFlag(w, spend, true)
			}
			// Position 4 is lowered in its amount alone: one element.
			if err == nil {
				err = wantAmountOnly(w, spend, 1)
			}
			return spend, next, err
		}
	}
	// whole rewrites every occupied position of the cohort the same way:
	// every owner's key rotated (update, every owner signs) or every
	// position emptied (exit, the mass exit of 7.9 rule 5).
	whole := func(exit bool) func(w *world) (*Spend, *tree.Tree, error) {
		return func(w *world) (*Spend, *tree.Tree, error) {
			w.cohort(2, 1, false)
			after := make(map[uint64]*tree.Leaf)
			if !exit {
				for off := uint64(0); off < 4; off++ {
					rotated := *w.st.Tree.Leaves[4+off]
					owner2 := sk(fmt.Sprintf("c%d-owner2", off))
					w.keys = append(w.keys, owner2)
					rotated.OwnerKey = xonly(owner2)
					after[off] = &rotated
				}
			}
			spend, next, err := BuildRewrite(w.st, 2, 1, after, false,
				&TxOpts{Inputs: w.fee(5_000)})
			if err == nil && len(spend.Sigs) != 5 {
				return nil, nil, fmt.Errorf("the rewrite has %d "+
					"signature slots, want every owner's and the "+
					"operator's", len(spend.Sigs))
			}
			return spend, next, err
		}
	}
	return []txCase{{
		name: "REWRITE_2", caseSpec: s.withVariant("REWRITE_2"),
		build: rewrite(false),
	}, {
		name: "REWRITE_2 decrease", caseSpec: s.withVariant("REWRITE_2"),
		build: decrease(false),
	}, {
		name: "REWRITE_X_2 decrease", caseSpec: s.withVariant("REWRITE_X_2"),
		build: decrease(true),
	}, {
		name: "REWRITE_X_2", caseSpec: s.withVariant("REWRITE_X_2"),
		build: rewrite(true),
	}, {
		name: "REWRITE_2 update", caseSpec: s.withVariant("REWRITE_2"),
		build: whole(false),
	}, {
		name: "REWRITE_2 exit", caseSpec: s.withVariant("REWRITE_2"),
		build: whole(true),
	}, {
		// The operator tops every leaf of the cohort up by 500 (spec 7.9
		// rule 3's exemption): no owner signs.
		name: "REWRITE_2 topup", caseSpec: s.withVariant("REWRITE_2"),
		build: func(w *world) (*Spend, *tree.Tree, error) {
			w.cohort(2, 1, false)
			after := make(map[uint64]*tree.Leaf)
			for off := uint64(0); off < 4; off++ {
				topped := *w.st.Tree.Leaves[4+off]
				topped.Amount += 500
				after[off] = &topped
			}
			spend, next, err := BuildRewrite(w.st, 2, 1, after, false,
				&TxOpts{Inputs: w.fee(4*500 + 5_000)})
			if err == nil && len(spend.Sigs) != 1 {
				return nil, nil, fmt.Errorf("the top-up has %d "+
					"signature slots, want the operator's alone",
					len(spend.Sigs))
			}
			// All four positions change in their amount alone.
			if err == nil {
				err = wantAmountOnly(w, spend, 4)
			}
			return spend, next, err
		},
	}}
}

// detachCases are DETACH_2, dense profile.
func detachCases(s caseSpec) []txCase {
	return []txCase{{
		name: "DETACH_2", caseSpec: s.withVariant("DETACH_2"),
		build: func(w *world) (*Spend, *tree.Tree, error) {
			w.cohort(2, 1, true)
			node := w.st.Tree.Subtree(2, 1)
			spend, host, child, err := BuildDetach(w.st, 2, 1, &TxOpts{
				Inputs:  w.fee(5_000),
				Outputs: []*wire.TxOut{wire.NewTxOut(400, p2wpkh(w.t))},
			})
			if err != nil {
				return nil, nil, err
			}
			// Output 1 is the detached tree: the cohort's node under
			// m_h, which is the child's own taptree root, and the
			// child's outpoint names it.
			if child.Tree.Root() != node {
				return nil, nil, errors.New("the child's root is not " +
					"the detached node")
			}
			in, err := child.Input()
			if err != nil {
				return nil, nil, err
			}
			spk, err := w.r.tier.ScriptPubKey(node.Hash, child.TapTree.Root())
			if err != nil {
				return nil, nil, err
			}
			out1 := spend.Tx.TxOut[1]
			if !bytes.Equal(out1.PkScript, spk) || out1.Value != in.Amount ||
				in.OutPoint != (wire.OutPoint{Hash: spend.Tx.TxHash(), Index: 1}) {

				return nil, nil, errors.New("output 1 is not the child " +
					"tree output")
			}
			return spend, host, nil
		},
	}}
}

// tierCases is every transition the tier can carry at one depth and
// profile: the whole matrix for FULL, MID and CCV in both numerics, EXIT_1
// and SPLIT for MIN.
func tierCases(tier Tier, depth int, sparse bool) []txCase {
	s := caseSpec{tier: tier, depth: depth, sparse: sparse}
	cases := exitCases(s)
	if tier != Min {
		cases = append(cases, joinCases(s)...)
		cases = append(cases, updateCases(s)...)
	}
	cases = append(cases, carveCases(s)...)
	if tier != Min {
		cases = append(cases, pendingCases(s)...)
	}
	if sparse || tier == Min {
		return cases
	}
	cases = append(cases, evictCases(s)...)
	cases = append(cases, rewriteCases(s)...)
	return append(cases, detachCases(s)...)
}

// profile is one depth and profile a tier is run at.
type profile struct {
	depth  int
	sparse bool
}

// tierProfiles are the depths and profiles each tier is run at: dense D =
// 4 and 16 everywhere, sparse D = 8 under 0xC2 numerics and D = 31 under
// 0xC0, where pos_lo must be a minimal positive four-byte number (spec
// 4.5), as the Python suites run them. MIN is dense only.
func tierProfiles(tier Tier) []profile {
	dense := []profile{{4, false}, {16, false}}
	switch {
	case tier == Min:
		return dense
	case tier.elements():
		return append(dense, profile{31, true})
	}
	return append(dense, profile{8, true})
}

// coveredTiers are the tiers the end-to-end suite runs.
var coveredTiers = []Tier{Full, Mid, Min, CCV, CCV0}

// allCases is every transition of every covered tier at every depth and
// profile.
func allCases() []txCase {
	var cases []txCase
	for _, tier := range coveredTiers {
		for _, p := range tierProfiles(tier) {
			cases = append(cases, tierCases(tier, p.depth, p.sparse)...)
		}
	}
	return cases
}

// dumpCase is one case as LAYERTREE_TXN_DUMP writes it.
type dumpCase struct {
	Name        string    `json:"name"`
	Tier        string    `json:"tier"`
	Depth       int       `json:"depth"`
	Sparse      bool      `json:"sparse"`
	Variants    []string  `json:"variants"`
	Version     int32     `json:"version"`
	LockTime    uint32    `json:"locktime"`
	Inputs      []dumpIn  `json:"inputs"`
	Outputs     []dumpOut `json:"outputs"`
	Script      string    `json:"script"`
	LeafVersion byte      `json:"leaf_version"`
	TapleafHash string    `json:"tapleaf_hash"`
	InternalKey string    `json:"internal_key"`
	TaptreeRoot string    `json:"taptree_root"`
	Stack       []string  `json:"stack"`
	Sighash     string    `json:"sighash"`
	Expect      string    `json:"expect,omitempty"`
}

type dumpIn struct {
	TxID         string `json:"txid"`
	Vout         uint32 `json:"vout"`
	Sequence     uint32 `json:"sequence"`
	Amount       int64  `json:"amount"`
	ScriptPubKey string `json:"scriptPubKey"`
}

type dumpOut struct {
	Amount       int64  `json:"amount"`
	ScriptPubKey string `json:"scriptPubKey"`
}

var (
	dumpMu    sync.Mutex
	dumpCases []dumpCase
)

// recordDump adds a case to the dump: the transaction, the revealed leaf,
// the input's taproot internal key and taptree root (what a node hands a
// CCV script for its -1 operands), and the signed stack.
func recordDump(c *txCase, w *world, s *Spend, sighash []byte) error {
	d := dumpCase{
		Name:        c.key(),
		Tier:        c.tier.String(),
		Depth:       c.depth,
		Sparse:      c.sparse,
		Variants:    c.variants,
		Version:     s.Tx.Version,
		LockTime:    s.Tx.LockTime,
		Script:      hex.EncodeToString(s.Leaf.Script),
		LeafVersion: s.Leaf.Version,
		Sighash:     hex.EncodeToString(sighash),
	}
	if c.expectFail {
		d.Expect = "fail"
	}
	leafHash := s.TapleafHash()
	d.TapleafHash = hex.EncodeToString(leafHash[:])
	root := w.st.Tree.Root()
	internal, err := w.r.tier.internalKey(root.Hash)
	if err != nil {
		return err
	}
	d.InternalKey = hex.EncodeToString(schnorr.SerializePubKey(internal))
	m := w.st.TapTree.Root()
	d.TaptreeRoot = hex.EncodeToString(m[:])
	for _, in := range s.Tx.TxIn {
		prev := s.PrevOuts[in.PreviousOutPoint]
		d.Inputs = append(d.Inputs, dumpIn{
			TxID:         hex.EncodeToString(in.PreviousOutPoint.Hash[:]),
			Vout:         in.PreviousOutPoint.Index,
			Sequence:     in.Sequence,
			Amount:       prev.Value,
			ScriptPubKey: hex.EncodeToString(prev.PkScript),
		})
	}
	for _, out := range s.Tx.TxOut {
		d.Outputs = append(d.Outputs, dumpOut{
			Amount:       out.Value,
			ScriptPubKey: hex.EncodeToString(out.PkScript),
		})
	}
	for _, el := range s.Stack {
		d.Stack = append(d.Stack, hex.EncodeToString(el))
	}
	dumpMu.Lock()
	dumpCases = append(dumpCases, d)
	dumpMu.Unlock()
	return nil
}

// TestTransitionsEndToEnd builds every transition with its builder, signs it
// with the shared signing helper, and verifies it: signatures, control
// block, witness layout, output 0 against the tree the builder says it
// produced, value flow, and the signature hash against the Python
// simulator's.
func TestTransitionsEndToEnd(t *testing.T) {
	dumpPath := os.Getenv("LAYERTREE_TXN_DUMP")
	for _, c := range allCases() {
		c := c
		t.Run(c.key(), func(t *testing.T) {
			w := newWorld(t, c.caseSpec)
			spend, next, err := c.build(w)
			if err != nil {
				t.Fatalf("build: %v", err)
			}

			// The builders never modify the state they are given,
			// so w.st.Tree is the tree before the transition.
			before := w.st.Tree
			checkSpend(t, w, before, spend, next)
			if c.tamper != nil {
				c.tamper(spend)
			}

			sighash, err := spend.Sighash()
			if err != nil {
				t.Fatalf("Sighash: %v", err)
			}
			if dumpPath != "" {
				if err := recordDump(&c, w, spend, sighash); err != nil {
					t.Fatalf("dump: %v", err)
				}
			}
			want, ok := pythonSighash[c.key()]
			if !ok {
				t.Fatalf("no Python sighash for %s", c.key())
			}
			if got := hex.EncodeToString(sighash); got != want {
				t.Fatalf("sighash differs from the simulator's:\n"+
					" got %s\nwant %s", got, want)
			}
		})
	}
	if dumpPath != "" {
		sort.Slice(dumpCases, func(i, j int) bool {
			return dumpCases[i].Name < dumpCases[j].Name
		})
		raw, err := json.MarshalIndent(dumpCases, "", " ")
		if err != nil {
			t.Fatalf("dump: %v", err)
		}
		if err := os.WriteFile(dumpPath, raw, 0o644); err != nil {
			t.Fatalf("dump: %v", err)
		}
	}
}

// checkSpend signs a built spend and checks everything Go can check about
// it.
func checkSpend(t *testing.T, w *world, before *tree.Tree, s *Spend,
	next *tree.Tree) {

	t.Helper()
	if err := s.Sign(w.keys...); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := s.Verify(); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	for _, slot := range s.Sigs {
		if len(s.Stack[slot.Index]) != 64 {
			t.Fatalf("%s signature is %d bytes, want 64",
				slot.Role, len(s.Stack[slot.Index]))
		}
	}
	if s.Leaf.Version != w.r.tier.LeafVersion() {
		t.Fatalf("leaf version 0x%02x, want the tier's 0x%02x",
			s.Leaf.Version, w.r.tier.LeafVersion())
	}

	// Input 0 spends the tier's tree output for the tree before the
	// transition, and, unless the tier is CCV, the witness's top two
	// elements are r and m (spec 8.2).
	oldRoot := before.Root()
	m := w.st.TapTree.Root()
	if s.Tx.TxIn[0].PreviousOutPoint != w.st.OutPoint ||
		s.Tx.TxIn[0].Sequence != TreeSequence {

		t.Fatal("input 0 is not the tree input")
	}
	prev := s.PrevOuts[w.st.OutPoint]
	wantSPK, err := w.r.tier.ScriptPubKey(oldRoot.Hash, m)
	if err != nil {
		t.Fatalf("ScriptPubKey: %v", err)
	}
	if !bytes.Equal(prev.PkScript, wantSPK) ||
		prev.Value != int64(oldRoot.Sum) {

		t.Fatal("input 0's prevout is not the tree output holding S")
	}
	n := len(s.Stack)
	if !w.r.tier.ccv() && (!bytes.Equal(s.Stack[n-2], oldRoot.Hash[:]) ||
		!bytes.Equal(s.Stack[n-1], m[:])) {

		t.Fatal("the stack does not end in r m")
	}

	// Output 0 recreates the tree the builder reports (rules 2, 4, 5),
	// unless that tree is empty (7.8).
	newRoot := next.Root()
	if newRoot != tree.EmptyNode(w.depth) {
		spk, err := w.r.tier.ScriptPubKey(newRoot.Hash, m)
		if err != nil {
			t.Fatalf("ScriptPubKey: %v", err)
		}
		if !bytes.Equal(s.Tx.TxOut[0].PkScript, spk) ||
			s.Tx.TxOut[0].Value != int64(newRoot.Sum) {

			t.Fatal("output 0 is not the tree output holding S'")
		}
	}

	// Value: the transaction pays no more than it spends, and the tree
	// output moves by exactly the leaves that left or joined.
	var in, out int64
	for _, txIn := range s.Tx.TxIn {
		in += s.PrevOuts[txIn.PreviousOutPoint].Value
	}
	for _, txOut := range s.Tx.TxOut {
		out += txOut.Value
	}
	if out > in {
		t.Fatalf("outputs %d exceed inputs %d", out, in)
	}
	var leftSum, joinedSum uint64
	for pos, l := range before.Leaves {
		if nl, ok := next.Leaves[pos]; !ok || nl != l {
			leftSum += l.Amount
		}
	}
	for pos, l := range next.Leaves {
		if ol, ok := before.Leaves[pos]; !ok || ol != l {
			joinedSum += l.Amount
		}
	}
	if oldRoot.Sum-leftSum+joinedSum != newRoot.Sum {
		t.Fatal("tree sum does not move by the changed leaves")
	}
}

// rejectCase is one input the builders refuse before signing. Its world is
// a dense tree of depth 4 (sparse depth 8 under 0xC2, 31 under 0xC0)
// unless the case says otherwise.
type rejectCase struct {
	name     string
	tier     Tier
	depth    int
	sparse   bool
	exact    bool
	tower    bool
	variants []string
	build    func(w *world) error
}

// fullRejects are the negatives every tier shares, written against the
// FULL world; rejectCases runs them in FULL and adds each tier's own.
func fullRejects() []rejectCase {
	return []rejectCase{{
		// design/audit/go.md G4: EXIT_1^= pays the whole leaf, so a
		// fee taken from the payout is a transaction no node accepts.
		name: "owner exit with a fee in an exact-payout tree", exact: true,
		build: func(w *world) error {
			_, _, _, _, sBob, _ := w.base()
			_, _, err := BuildExit(w.st, []ExitStep{{
				Pos: sBob, Fee: 1_000,
			}}, &TxOpts{Inputs: w.fee(50_000)})
			return err
		},
	}, {
		// EXIT_1^t (spec 7.2 rule 7) takes the owner's authorisation;
		// without it there is nothing to put in the owner branch.
		name: "owner exit without an authorisation in a tower tree", tower: true,
		build: func(w *world) error {
			_, _, _, _, sBob, _ := w.base()
			_, _, err := BuildExit(w.st, []ExitStep{{Pos: sBob}},
				&TxOpts{Inputs: w.fee(5_000)})
			return err
		},
	}, {
		// An authorisation over another leaf (alice's) presented for bob
		// fails the owner-key check before anything is built.
		name: "authorisation for another leaf in a tower tree", tower: true,
		build: func(w *world) error {
			alice, _, _, _, sBob, _ := w.base()
			auth, err := SignExitAuth(sk("alice-owner"), w.treeID(), alice)
			if err != nil {
				return nil
			}
			_, _, err = BuildExit(w.st, []ExitStep{{Pos: sBob, Auth: auth}},
				&TxOpts{Inputs: w.fee(5_000)})
			return err
		},
	}, {
		// An eviction signs the transaction under EXIT_1^t too.
		name: "eviction with an authorisation in a tower tree", tower: true,
		build: func(w *world) error {
			_, bob, _, _, sBob, _ := w.base()
			auth, err := SignExitAuth(sk("bob-owner"), w.treeID(), bob)
			if err != nil {
				return nil
			}
			_, _, err = BuildExit(w.st, []ExitStep{{Pos: sBob, Evict: true, Auth: auth}},
				&TxOpts{LockTime: 800_000, Inputs: w.fee(5_000)})
			return err
		},
	}, {
		// The reference EXIT_1 checks a transaction signature; an
		// authorisation in its slot is a witness the script rejects.
		name: "authorisation in a tree without EXIT_K^t",
		build: func(w *world) error {
			_, bob, _, _, sBob, _ := w.base()
			auth, err := SignExitAuth(sk("bob-owner"), w.treeID(), bob)
			if err != nil {
				return nil
			}
			_, _, err = BuildExit(w.st, []ExitStep{{Pos: sBob, Auth: auth}},
				&TxOpts{Inputs: w.fee(5_000)})
			return err
		},
	}, {
		// design/audit/go.md G5: OP_CHECKLOCKTIMEVERIFY fails when the
		// operand and nLockTime are of different types, so an
		// eviction's lock time must be a height (10.6).
		name: "eviction with a timestamp lock time",
		build: func(w *world) error {
			_, _, _, _, sBob, _ := w.base()
			_, _, err := BuildExit(w.st, []ExitStep{{
				Pos: sBob, Evict: true,
			}}, &TxOpts{LockTime: 1_000_000_000, Inputs: w.fee(5_000)})
			return err
		},
	}, {
		name:     "sweep with a timestamp lock time",
		variants: []string{"EVICT_SUBTREE_2"},
		build: func(w *world) error {
			_, _, _, _, sBob, _ := w.base()
			_, _, err := BuildEvictSubtree(w.st, 2, sBob>>2,
				&TxOpts{LockTime: 1_000_000_000, Inputs: w.fee(5_000)})
			return err
		},
	}, {
		// G5: the voucher is checked with OP_CHECKSIGFROMSTACK against
		// the source owner's key, so one signed by anyone else fails
		// on chain.
		name: "claim with a voucher from the wrong issuer",
		build: func(w *world) error {
			_, _, oper, _, _, sOper := w.base()
			frank := w.carveOf(oper, "frank", 40_000)
			vsig, err := SignVoucher(
				sk("alice-owner"), w.treeID(), oper, frank,
			)
			if err != nil {
				return err
			}
			_, _, err = BuildClaim(w.st, sOper, 3, frank, vsig,
				&TxOpts{Inputs: w.fee(600)})
			return err
		},
	}, {
		// G5: tree.Tree.Root covers positions [0, 2^D), so a claim
		// placed beyond them is folded in by the path but left out of
		// output 0.
		name: "claim into a position outside the tree",
		build: func(w *world) error {
			_, _, oper, _, _, sOper := w.base()
			frank := w.carveOf(oper, "frank", 40_000)
			vsig, err := SignVoucher(
				sk("operator-owner"), w.treeID(), oper, frank,
			)
			if err != nil {
				return err
			}
			_, _, err = BuildClaim(w.st, sOper, 1<<w.depth+3, frank,
				vsig, &TxOpts{Inputs: w.fee(600)})
			return err
		},
	}, {
		// G5: 7.3 rule 4 lets the covenant graft any leaf, so the
		// builder has to hold the 5.2 line (10.7): a zero amount and
		// an owner key with no lift_x make a leaf nobody can spend.
		name: "join of a leaf that fails 5.2",
		build: func(w *world) error {
			w.base()
			opKey := w.opKey()
			broken := w.mkLeaf("broken", 0, &opKey, 900_000)
			broken.OwnerKey = [32]byte{}
			_, _, err := BuildJoin(w.st, 0, 9,
				map[uint64]*tree.Leaf{0: broken},
				&TxOpts{Inputs: w.fee(1_000)})
			return err
		},
	}, {
		name: "eviction before evict_after",
		build: func(w *world) error {
			_, _, _, _, sBob, _ := w.base()
			_, _, err := BuildExit(w.st, []ExitStep{{
				Pos: sBob, Evict: true,
			}}, &TxOpts{LockTime: 799_999, Inputs: w.fee(5_000)})
			return err
		},
	}, {
		name: "eviction with a fee taken from the payout",
		build: func(w *world) error {
			_, _, _, _, sBob, _ := w.base()
			_, _, err := BuildExit(w.st, []ExitStep{{
				Pos: sBob, Evict: true, Fee: 1,
			}}, &TxOpts{LockTime: 800_000, Inputs: w.fee(5_000)})
			return err
		},
	}, {
		name: "exit of an empty position",
		build: func(w *world) error {
			w.base()
			_, _, err := BuildExit(w.st, []ExitStep{{Pos: 3}}, nil)
			return err
		},
	}, {
		name: "terminal exit without an output 0",
		build: func(w *world) error {
			solo := w.mkLeaf("solo", 77_000, nil, 0)
			w.st.Tree.Leaves[2] = solo
			_, _, err := BuildExit(w.st, []ExitStep{{Pos: 2}}, nil)
			return err
		},
	}, {
		name: "terminal output 0 on a non-terminal exit",
		build: func(w *world) error {
			_, _, _, sAlice, _, _ := w.base()
			_, _, err := BuildExit(w.st, []ExitStep{{Pos: sAlice}},
				&TxOpts{Terminal: wire.NewTxOut(1, p2wpkh(w.t))})
			return err
		},
	}, {
		name: "join over an occupied subtree",
		build: func(w *world) error {
			w.base()
			opKey := w.opKey()
			carol := w.mkLeaf("carol", 30_000, &opKey, 900_000)
			_, _, err := BuildJoin(w.st, 2, 0,
				map[uint64]*tree.Leaf{1: carol},
				&TxOpts{Inputs: w.fee(40_000)})
			return err
		},
	}, {
		name: "underfunded join",
		build: func(w *world) error {
			w.base()
			opKey := w.opKey()
			erin := w.mkLeaf("erin", 12_345, &opKey, 900_000)
			_, _, err := BuildJoin(w.st, 0, 9,
				map[uint64]*tree.Leaf{0: erin},
				&TxOpts{Inputs: w.fee(12_344)})
			return err
		},
	}, {
		name: "JOINK_2 naming one position twice",
		build: func(w *world) error {
			w.base()
			opKey := w.opKey()
			hank := w.mkLeaf("hank", 9_000, &opKey, 900_000)
			ivy := w.mkLeaf("ivy", 11_000, &opKey, 900_000)
			_, _, err := BuildJoinK(w.st, []PlacedLeaf{
				{Pos: 12, Leaf: hank}, {Pos: 12, Leaf: ivy},
			}, &TxOpts{Inputs: w.fee(30_000)})
			return err
		},
	}, {
		name: "claim larger than the source",
		build: func(w *world) error {
			alice, _, _, sAlice, _, _ := w.base()
			greedy := w.mkLeaf("greedy", alice.Amount+1, nil, 0)
			_, _, err := BuildClaim(w.st, sAlice, 3, greedy,
				make([]byte, 64), &TxOpts{Inputs: w.fee(600)})
			return err
		},
	}, {
		name: "claim below DUST_MIN",
		build: func(w *world) error {
			_, _, _, sAlice, _, _ := w.base()
			dust := w.mkLeaf("dust", tree.DustMin-1, nil, 0)
			_, _, err := BuildClaim(w.st, sAlice, 3, dust,
				make([]byte, 64), &TxOpts{Inputs: w.fee(600)})
			return err
		},
	}, {
		name: "split leaving a residual below DUST_MIN",
		build: func(w *world) error {
			alice, _, _, sAlice, _, _ := w.base()
			most := w.mkLeaf("most", alice.Amount-1, nil, 0)
			_, _, err := BuildSplit(w.st, sAlice, 3, most,
				&TxOpts{Inputs: w.fee(600)})
			return err
		},
	}, {
		name: "claim against a SEQ_FINAL source",
		build: func(w *world) error {
			src := w.mkLeaf("chan-src", 1_000_000, nil, 0)
			src.Seq = math.MaxUint32
			w.st.Tree.Leaves[15] = src
			claim := w.mkLeaf("claimant", 40_000, nil, 0)
			_, _, err := BuildClaim(w.st, 15, 3, claim,
				make([]byte, 64), &TxOpts{Inputs: w.fee(600)})
			return err
		},
	}, {
		name: "claim with a different evictor key",
		build: func(w *world) error {
			alice, _, _, sAlice, _, _ := w.base()
			opKey := w.opKey()
			escape := w.mkLeaf("escape", 10_000, &opKey, alice.EvictAfter)
			_, _, err := BuildClaim(w.st, sAlice, 3, escape,
				make([]byte, 64), &TxOpts{Inputs: w.fee(600)})
			return err
		},
	}, {
		name: "split with a later evict_after",
		build: func(w *world) error {
			_, bob, _, _, sBob, _ := w.base()
			later := w.mkLeaf("later", 10_000, &bob.EvictorKey,
				bob.EvictAfter+1)
			_, _, err := BuildSplit(w.st, sBob, 3, later,
				&TxOpts{Inputs: w.fee(600)})
			return err
		},
	}, {
		name: "split into an occupied position",
		build: func(w *world) error {
			_, _, _, sAlice, sBob, _ := w.base()
			carol := w.mkLeaf("carol", 10_000, nil, 0)
			_, _, err := BuildSplit(w.st, sAlice, sBob, carol,
				&TxOpts{Inputs: w.fee(600)})
			return err
		},
	}, {
		name:     "sweep before the lease expires",
		variants: []string{"EVICT_SUBTREE_2"},
		build: func(w *world) error {
			_, _, _, _, sBob, _ := w.base()
			_, _, err := BuildEvictSubtree(w.st, 2, sBob>>2,
				&TxOpts{LockTime: 799_999, Inputs: w.fee(5_000)})
			return err
		},
	}, {
		name:     "sweep over a leaf the operator cannot evict",
		variants: []string{"EVICT_SUBTREE_2"},
		build: func(w *world) error {
			w.base()
			w.st.Tree.Leaves[6] = w.mkLeaf("stubborn", 5_000, nil, 0)
			_, _, err := BuildEvictSubtree(w.st, 2, 1,
				&TxOpts{LockTime: 800_000, Inputs: w.fee(5_000)})
			return err
		},
	}, {
		// 7.9 rule 6: the join into position 7 must be funded.
		name:     "rewrite with an unfunded join",
		variants: []string{"REWRITE_2"},
		build: func(w *world) error {
			after, _ := w.rewritePlan()
			_, _, err := BuildRewrite(w.st, 2, 1, after, false,
				&TxOpts{Inputs: w.fee(1)})
			return err
		},
	}, {
		// 10.7: the covenant grafts whatever the operator signs, so the
		// builder holds the 5.2 line for a joined leaf.
		name:     "rewrite grafting a leaf that fails 5.2",
		variants: []string{"REWRITE_2"},
		build: func(w *world) error {
			after, _ := w.rewritePlan()
			after[3].Amount = 0
			_, _, err := BuildRewrite(w.st, 2, 1, after, false,
				&TxOpts{Inputs: w.fee(50_000)})
			return err
		},
	}, {
		name:     "rewrite of a position outside the subtree",
		variants: []string{"REWRITE_2"},
		build: func(w *world) error {
			after, _ := w.rewritePlan()
			after[4] = after[3]
			_, _, err := BuildRewrite(w.st, 2, 1, after, false,
				&TxOpts{Inputs: w.fee(50_000)})
			return err
		},
	}, {
		name:     "rewrite that changes nothing",
		variants: []string{"REWRITE_2"},
		build: func(w *world) error {
			w.cohort(2, 1, false)
			after := make(map[uint64]*tree.Leaf)
			for off := uint64(0); off < 4; off++ {
				after[off] = w.st.Tree.Leaves[4+off]
			}
			_, _, err := BuildRewrite(w.st, 2, 1, after, false,
				&TxOpts{Inputs: w.fee(5_000)})
			return err
		},
	}, {
		// 7.9 rule 7: beside UPDATE^x the cohort form is REWRITE_h^x.
		name:     "plain rewrite in a tree with UPDATE^x",
		variants: []string{"UPDATE_X", "REWRITE_2"},
		build: func(w *world) error {
			if w.r.tier == Full {
				// The FULL suite world appends variants rather than
				// swapping them, so compile this one from options.
				opts := suiteOptions(xonly(w.op), suiteTreeID(), false)
				opts.UpdateX, opts.RewriteHeights = true, []int{2}
				st, err := NewTreeState(tree.New(4), opts, prevOutPoint(0))
				if err != nil {
					return nil
				}
				w.st = st
				w.r, err = st.rules()
				if err != nil {
					return nil
				}
			}
			after, _ := w.rewritePlan()
			_, _, err := BuildRewrite(w.st, 2, 1, after, false,
				&TxOpts{Inputs: w.fee(50_000)})
			return err
		},
	}, {
		name:     "detach of an empty subtree",
		variants: []string{"DETACH_2"},
		build: func(w *world) error {
			w.base()
			_, _, _, err := BuildDetach(w.st, 2, 2, &TxOpts{Inputs: w.fee(5_000)})
			return err
		},
	}, {
		name:     "detach of the whole tree",
		variants: []string{"DETACH_2"},
		build: func(w *world) error {
			w.base()
			_, _, _, err := BuildDetach(w.st, 4, 0, &TxOpts{Inputs: w.fee(5_000)})
			return err
		},
	}, {
		name: "sparse update that moves the leaf", sparse: true,
		build: func(w *world) error {
			alice, _, _, sAlice, _, _ := w.base()
			moved := withAmountSeq(alice, 80_000, 1)
			moved.Nonce++
			_, _, err := BuildUpdate(w.st, sAlice, moved,
				&TxOpts{Inputs: w.fee(30_700)})
			return err
		},
	}, {
		name: "sparse join away from the derived position", sparse: true,
		build: func(w *world) error {
			opKey := w.opKey()
			erin := w.mkLeaf("erin", 12_345, &opKey, 900_000)
			pos := erin.Position(w.depth) ^ 1
			_, _, err := BuildJoin(w.st, 0, pos,
				map[uint64]*tree.Leaf{0: erin},
				&TxOpts{Inputs: w.fee(20_000)})
			return err
		},
	}}
}

// c0Rejects are the negatives of the 0xC0 encoding (spec 4.5), run in
// MID and in the CCV tier's 0xC0 numerics.
func c0Rejects(tier Tier) []rejectCase {
	return []rejectCase{{
		// A sparse leaf whose nonce gives a non-minimal pos_lo cannot be
		// proven by the 0xC0 sparse scripts; a joiner grinds its nonce.
		name: "sparse join of a leaf without a minimal pos_lo",
		tier: tier, sparse: true,
		build: func(w *world) error {
			opKey := w.opKey()
			erin := w.mkLeaf("erin", 12_345, &opKey, 900_000)
			for erin.PosLoMinimal(w.depth) {
				erin.Nonce++
			}
			_, _, err := BuildJoin(w.st, 0, erin.Position(w.depth),
				map[uint64]*tree.Leaf{0: erin},
				&TxOpts{Inputs: w.fee(20_000)})
			return err
		},
	}, {
		// Every sum of a 0xC0 tree is a minimal CScriptNum below 2^31.
		name: "join past the 0xC0 sum cap", tier: tier,
		build: func(w *world) error {
			w.base()
			opKey := w.opKey()
			whale := w.mkLeaf("whale", script.MidMaxSum, &opKey, 900_000)
			_, _, err := BuildJoin(w.st, 0, 9,
				map[uint64]*tree.Leaf{0: whale},
				&TxOpts{Inputs: w.fee(int64(script.MidMaxSum) + 500)})
			return err
		},
	}, {
		// At D = 16 a full 64-position cohort's mass exit needs 10 * 64 +
		// 64 signature-free slots beyond what the 1,000-element limit
		// leaves REWRITE_6 (spec 4.5: 10(p_o + p_n - u) + s <= 523 in MID,
		// 525 under CCV); the builder refuses it before signing.
		name: "rewrite of a full 64-position cohort past the stack limit",
		tier: tier, depth: 16, variants: []string{"REWRITE_6"},
		build: func(w *world) error {
			w.cohort(6, 1, false)
			_, _, err := BuildRewrite(w.st, 6, 1, nil, false,
				&TxOpts{Inputs: w.fee(5_000)})
			return err
		},
	}, {
		// SEQ_FINAL is 0x7FFFFFFF under 0xC0 numerics, not 0xFFFFFFFF.
		name: "claim against a 0xC0 SEQ_FINAL source", tier: tier,
		build: func(w *world) error {
			src := w.mkLeaf("chan-src", 1_000_000, nil, 0)
			src.Seq = script.MidSeqFinal
			w.st.Tree.Leaves[15] = src
			claim := w.mkLeaf("claimant", 40_000, nil, 0)
			_, _, err := BuildClaim(w.st, 15, 3, claim,
				make([]byte, 64), &TxOpts{Inputs: w.fee(600)})
			return err
		},
	}}
}

// minRejects are the MIN tier's own negatives: the tier's fixed shape
// (spec 4.5).
func minRejects() []rejectCase {
	return []rejectCase{{
		// MIN's output 0 is always a tree output.
		name: "terminal exit", tier: Min,
		build: func(w *world) error {
			solo := w.mkLeaf("solo", 77_000, nil, 0)
			w.st.Tree.Leaves[2] = solo
			_, _, err := BuildExit(w.st, []ExitStep{{Pos: 2}}, &TxOpts{
				Inputs:   w.fee(1_000),
				Terminal: wire.NewTxOut(600, p2wpkh(w.t)),
			})
			return err
		},
	}, {
		// The raw introspection pieces describe exactly one fee input.
		name: "exit with two fee inputs", tier: Min,
		build: func(w *world) error {
			_, _, _, _, sBob, _ := w.base()
			inputs := append(w.fee(5_000), ExtraInput{
				OutPoint: prevOutPoint(2), Sequence: TreeSequence,
				PrevOut: wire.NewTxOut(5_000, p2wpkh(w.t)),
			})
			_, _, err := BuildExit(w.st, []ExitStep{{Pos: sBob}},
				&TxOpts{Inputs: inputs})
			return err
		},
	}, {
		// MIN pays out exactly.
		name: "owner exit with a fee from the payout", tier: Min,
		build: func(w *world) error {
			_, _, _, _, sBob, _ := w.base()
			_, _, err := BuildExit(w.st, []ExitStep{{Pos: sBob, Fee: 1}},
				&TxOpts{Inputs: w.fee(5_000)})
			return err
		},
	}, {
		// MIN has no EXIT_2.
		name: "EXIT_2", tier: Min,
		build: func(w *world) error {
			_, _, _, sAlice, sBob, _ := w.base()
			_, _, err := BuildExit(w.st, []ExitStep{{Pos: sAlice}, {Pos: sBob}},
				&TxOpts{Inputs: w.fee(5_000)})
			return err
		},
	}}
}

// rejectCases is every negative of every covered tier: the shared list in
// FULL and again in each tier whose builders exist (the rules the builders
// hold are the same in every tier), then each tier's own.
func rejectCases() []rejectCase {
	cases := fullRejects()
	for _, tier := range coveredTiers {
		if tier == Full || tier == Min {
			continue
		}
		for _, c := range fullRejects() {
			c.tier = tier
			cases = append(cases, c)
		}
		if tier.elements() {
			cases = append(cases, c0Rejects(tier)...)
		}
	}
	for _, tier := range coveredTiers {
		if tier == Min {
			cases = append(cases, minRejects()...)
		}
	}
	return cases
}

// TestBuilderRejects checks that the builders refuse transactions the
// covenant would reject, rather than producing them.
func TestBuilderRejects(t *testing.T) {
	for _, c := range rejectCases() {
		c := c
		name := fmt.Sprintf("%v/%s", c.tier, c.name)
		t.Run(name, func(t *testing.T) {
			depth := c.depth
			switch {
			case depth != 0:
			case c.sparse && c.tier.elements():
				depth = 31
			case c.sparse:
				depth = 8
			default:
				depth = 4
			}
			w := newWorld(t, caseSpec{
				tier: c.tier, depth: depth, sparse: c.sparse,
				exact: c.exact, tower: c.tower, variants: c.variants,
			})
			err := c.build(w)
			if err == nil {
				t.Fatal("builder accepted it")
			}
			t.Log(err)
		})
	}
}

// TestBuildClaimDustMinFloor checks that buildCarve enforces the tree's own
// DUST_MIN (spec 6.2, 7.5 rule 6), read from TreeState.Options, rather than
// the RECOMMENDED constant: a 500 sat claim is refused in a tree created
// with a floor of 1,000, whose CLAIM script would reject it, and built in
// one created with 330 (design/audit/go.md G9).
func TestBuildClaimDustMinFloor(t *testing.T) {
	const claimAmt = 500

	build := func(t *testing.T, dustMin uint64) (*world, *Spend,
		*tree.Tree, error) {

		t.Helper()
		op := sk("operator")
		opts := suiteOptions(xonly(op), suiteTreeID(), false)
		opts.DustMin = dustMin
		st, err := NewTreeState(tree.New(4), opts, prevOutPoint(0))
		if err != nil {
			t.Fatalf("NewTreeState: %v", err)
		}
		r, err := st.rules()
		if err != nil {
			t.Fatalf("rules: %v", err)
		}
		w := &world{
			t: t, depth: 4, op: op, keys: []*btcec.PrivateKey{op},
			st: st, r: r,
		}
		_, _, oper, _, _, sOper := w.base()
		claim := w.carveOf(oper, "frank", claimAmt)
		vsig, err := SignVoucher(
			sk("operator-owner"), opts.TreeID, oper, claim,
		)
		if err != nil {
			t.Fatalf("SignVoucher: %v", err)
		}
		spend, next, err := BuildClaim(st, sOper, 3, claim, vsig,
			&TxOpts{Inputs: w.fee(600)})
		return w, spend, next, err
	}

	t.Run("floor 1000 rejects", func(t *testing.T) {
		w, _, _, err := build(t, 1_000)
		if err == nil {
			t.Fatal("a 500 sat claim was built in a tree whose " +
				"DUST_MIN is 1,000")
		}
		if !strings.Contains(err.Error(), "below DUST_MIN 1000") {
			t.Fatalf("unexpected error: %v", err)
		}
		// The tree's taptree is compiled at its own floor, so its m
		// is not the 330 tree's.
		def := w.st.Options.(script.FullTreeOptions)
		def.DustMin = 0
		if w.st.TapTree.Root() == def.TapTreeRoot(4) {
			t.Fatal("the 1,000 floor tree has the 330 tree's m")
		}
	})
	t.Run("floor 330 accepts", func(t *testing.T) {
		w, spend, next, err := build(t, tree.DustMin)
		if err != nil {
			t.Fatalf("BuildClaim: %v", err)
		}
		before := w.st.Tree
		checkSpend(t, w, before, spend, next)
	})
}
