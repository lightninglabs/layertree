package txn

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
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

// This file builds, signs and verifies every FULL-tier transition end to
// end. The scenarios mirror tools/test_scripts.py: the same key labels
// (sk(label) = sha256(label)), the same leaves (mk_leaf), positions,
// amounts, fees and lock times, and the same taptree (all_scripts with
// join heights (0, 2), exit sizes (1, 2) and JOINK_2, with tree-creation
// variants appended as the suite appends them). The transaction's inputs
// use TxContext's default prevouts (sha256("prevout<i>"), vout i) and
// sequences (0xfffffffd), so a TxContext built from the same inputs and
// outputs describes the same transaction.
//
// pythonSighash holds, for every case, the BIP-341 signature hash
// tools/script_sim.py TxContext.sighash() computes for the transaction the
// Go builder produced, with tapleaf_hash set to the revealed leaf (the suite
// itself signs with a zero tapleaf hash, so its own digests are not
// comparable). The same run executed each signed Go witness with
// script_sim.Interp in 0xC2 mode against that context and every one
// succeeded. To repeat it, run the tests with LAYERTREE_TXN_DUMP=<file>,
// which writes each case's transaction, script and stack as JSON, and feed
// the file to tools/replay_txn_dump.py, which rebuilds each TxContext, runs
// each witness through Interp and prints this map.

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

// world mirrors the suite's World: one tree of a given depth and profile
// with a taptree, and every private key the scenario created.
type world struct {
	t      *testing.T
	depth  int
	sparse bool
	op     *btcec.PrivateKey
	keys   []*btcec.PrivateKey
	st     *TreeState
}

// suiteTreeID is the suite's tree_id (spec 6.2): the RECOMMENDED derivation
// over the placeholder creation outpoint (sha256("creation-txid"), 0), the
// value every Python suite and the golden vectors use.
func suiteTreeID() [32]byte {
	return tree.TreeID(sha256.Sum256([]byte("creation-txid")), 0)
}

// newWorld builds the reference FULL taptree for (depth, profile) and
// appends the named tree-creation variants, as the suite does for UPDATE_X,
// CLAIM_H, SPLIT and EVICT_SUBTREE_h.
func newWorld(t *testing.T, depth int, sparse bool, variants ...string) *world {
	t.Helper()
	op := sk("operator")
	opKey := xonly(op)
	treeID := suiteTreeID()
	leaves, err := FullReferenceLeaves(
		depth, opKey, treeID, sparse, []int{0, 2}, []int{1, 2}, []int{2},
		tree.DustMin,
	)
	if err != nil {
		t.Fatalf("FullReferenceLeaves: %v", err)
	}
	for _, name := range variants {
		var toks []script.Token
		switch name {
		case "UPDATE_X":
			toks = script.FullUpdateXScript(depth, opKey, sparse)
		case "CLAIM_H":
			toks = script.FullClaimHScript(depth, treeID, sparse, tree.DustMin)
		case "SPLIT":
			toks = script.FullSplitScript(depth, sparse, tree.DustMin)
		case "EVICT_SUBTREE_2":
			toks = script.FullEvictSubtreeScript(depth, 2, opKey)
		case "EVICT_SUBTREE_4":
			toks = script.FullEvictSubtreeScript(depth, 4, opKey)
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

	// The suite appends its variants beside the scripts they would
	// replace (UPDATE_X next to UPDATE), a shape FullTreeOptions.Scripts
	// does not emit, so the taptree is assembled by hand and Options
	// describes the reference members the builders consult.
	return &world{
		t: t, depth: depth, sparse: sparse, op: op,
		keys: []*btcec.PrivateKey{op},
		st: &TreeState{
			Tree:     tree.New(depth),
			Options:  suiteOptions(opKey, treeID, sparse),
			TapTree:  tt,
			OutPoint: prevOutPoint(0),
		},
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

// newExactWorld is newWorld for a tree created with exact payouts (spec 7.2
// rule 6): the same keys and members, compiled through NewTreeState with
// Exact set, so the exits are EXIT_K^=.
func newExactWorld(t *testing.T, depth int, sparse bool) *world {
	t.Helper()
	op := sk("operator")
	opts := suiteOptions(xonly(op), suiteTreeID(), sparse)
	opts.Exact = true
	st, err := NewTreeState(tree.New(depth), opts, prevOutPoint(0))
	if err != nil {
		t.Fatalf("NewTreeState: %v", err)
	}
	if st.TapTree.Root() != opts.TapTreeRoot(depth) {
		t.Fatal("NewTreeState's taptree root is not the options' m")
	}
	return &world{
		t: t, depth: depth, sparse: sparse, op: op,
		keys: []*btcec.PrivateKey{op}, st: st,
	}
}

// mkLeaf is the suite's mk_leaf: exit and owner keys from "<label>-exit"
// and "<label>-owner", the NUMS evictor unless one is given, and the nonce
// le32(sha256(label)[:4]).
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

// base populates the suite's starting tree: alice at 0, bob (evictable by
// the operator from height 800,000) at 5 and the operator's leaf at the
// last position.
func (w *world) base() (alice, bob, oper *tree.Leaf, sAlice, sBob,
	sOper uint64) {

	opKey := w.st.Options.OperatorKey
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
	name     string
	depth    int
	sparse   bool
	exact    bool
	variants []string
	build    func(w *world) (*Spend, *tree.Tree, error)
}

// world returns the case's world: the suite's reference taptree, or the
// exact-payout one compiled through NewTreeState.
func (c *txCase) world(t *testing.T) *world {
	if c.exact {
		return newExactWorld(t, c.depth, c.sparse)
	}
	return newWorld(t, c.depth, c.sparse, c.variants...)
}

func (c *txCase) key() string {
	profile := "D"
	if c.sparse {
		profile = "S"
	}
	return fmt.Sprintf("FULL/%s/D%d/%s", profile, c.depth, c.name)
}

// exitCases are EXIT_1 (owner and eviction), EXIT_2 and the terminal exit.
func exitCases(depth int, sparse bool) []txCase {
	return []txCase{{
		name: "EXIT_1 owner", depth: depth, sparse: sparse,
		build: func(w *world) (*Spend, *tree.Tree, error) {
			_, _, _, _, sBob, _ := w.base()
			return BuildExit(w.st, []ExitStep{{Pos: sBob, Fee: 1_000}},
				&TxOpts{
					Inputs: w.fee(50_000),
					Outputs: []*wire.TxOut{
						wire.NewTxOut(49_000, p2wpkh(w.t)),
					},
				})
		},
	}, {
		// An owner exit under EXIT_1^= (spec 7.2 rule 6): the payout is
		// the whole leaf and the fee comes from the extra input.
		name: "EXIT_1 exact", depth: depth, sparse: sparse, exact: true,
		build: func(w *world) (*Spend, *tree.Tree, error) {
			_, _, _, _, sBob, _ := w.base()
			return BuildExit(w.st, []ExitStep{{Pos: sBob}},
				&TxOpts{Inputs: w.fee(5_000)})
		},
	}, {
		name: "EXIT_1 evict", depth: depth, sparse: sparse,
		build: func(w *world) (*Spend, *tree.Tree, error) {
			_, _, _, _, sBob, _ := w.base()
			return BuildExit(w.st, []ExitStep{{Pos: sBob, Evict: true}},
				&TxOpts{LockTime: 800_000, Inputs: w.fee(5_000)})
		},
	}, {
		name: "EXIT_2 owner+evict", depth: depth, sparse: sparse,
		build: func(w *world) (*Spend, *tree.Tree, error) {
			w.base()
			opKey := w.st.Options.OperatorKey
			carol := w.mkLeaf("carol", 30_000, &opKey, 900_000)
			dave := w.mkLeaf("dave", 70_000, &opKey, 900_000)
			tr := w.st.Tree
			sCarol := w.slot(carol, 8, tr)
			tr.Leaves[sCarol] = carol
			sDave := w.slot(dave, 11, tr)
			tr.Leaves[sDave] = dave
			return BuildExit(w.st, []ExitStep{
				{Pos: sCarol, Fee: 300},
				{Pos: sDave, Evict: true},
			}, &TxOpts{LockTime: 900_000, Inputs: w.fee(5_000)})
		},
	}, {
		name: "EXIT_1 terminal", depth: depth, sparse: sparse,
		build: func(w *world) (*Spend, *tree.Tree, error) {
			solo := w.mkLeaf("solo", 77_000, nil, 0)
			sSolo := w.slot(solo, 2, w.st.Tree)
			w.st.Tree.Leaves[sSolo] = solo
			return BuildExit(w.st, []ExitStep{{Pos: sSolo, Fee: 400}},
				&TxOpts{
					Inputs:   w.fee(1_000),
					Terminal: wire.NewTxOut(600, p2wpkh(w.t)),
				})
		},
	}}
}

// joinCases are JOIN_0, JOINK_2 and, in the dense profile, JOIN_2.
func joinCases(depth int, sparse bool) []txCase {
	cases := []txCase{{
		name: "JOIN_0", depth: depth, sparse: sparse,
		build: func(w *world) (*Spend, *tree.Tree, error) {
			w.base()
			opKey := w.st.Options.OperatorKey
			erin := w.mkLeaf("erin", 12_345, &opKey, 900_000)
			sErin := w.slot(erin, 9, w.st.Tree)
			return BuildJoin(w.st, 0, sErin,
				map[uint64]*tree.Leaf{0: erin},
				&TxOpts{Inputs: w.fee(int64(erin.Amount) + 500)})
		},
	}, {
		name: "JOINK_2", depth: depth, sparse: sparse,
		build: func(w *world) (*Spend, *tree.Tree, error) {
			w.base()
			opKey := w.st.Options.OperatorKey
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
	if sparse {
		return cases
	}
	return append(cases, txCase{
		name: "JOIN_2", depth: depth, sparse: sparse,
		build: func(w *world) (*Spend, *tree.Tree, error) {
			w.base()
			opKey := w.st.Options.OperatorKey
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

// updateCases are UPDATE and UPDATE^x: alice tops her leaf up from 50,000
// to 80,000 and bumps seq, funded by a second input.
func updateCases(depth int, sparse bool) []txCase {
	update := func(x bool) func(w *world) (*Spend, *tree.Tree, error) {
		return func(w *world) (*Spend, *tree.Tree, error) {
			alice, _, _, sAlice, _, _ := w.base()
			alice2 := withAmountSeq(alice, 80_000, 1)
			opts := &TxOpts{Inputs: w.fee(30_700)}
			if x {
				return BuildUpdateX(w.st, sAlice, alice2, opts)
			}
			return BuildUpdate(w.st, sAlice, alice2, opts)
		}
	}
	return []txCase{{
		name: "UPDATE", depth: depth, sparse: sparse,
		build: update(false),
	}, {
		name: "UPDATE_X", depth: depth, sparse: sparse,
		variants: []string{"UPDATE_X"},
		build:    update(true),
	}}
}

// carveCases are CLAIM (partial and draining the source), CLAIM^h and
// SPLIT.
func carveCases(depth int, sparse bool) []txCase {
	return []txCase{{
		name: "CLAIM", depth: depth, sparse: sparse,
		build: func(w *world) (*Spend, *tree.Tree, error) {
			_, _, oper, _, _, sOper := w.base()
			frank := w.carveOf(oper, "frank", 40_000)
			sFrank := w.slot(frank, 3, w.st.Tree)
			vsig, err := SignVoucher(
				sk("operator-owner"), w.st.Options.TreeID, oper, frank,
			)
			if err != nil {
				return nil, nil, err
			}
			return BuildClaim(w.st, sOper, sFrank, frank, vsig,
				&TxOpts{Inputs: w.fee(600)})
		},
	}, {
		name: "CLAIM drain", depth: depth, sparse: sparse,
		build: func(w *world) (*Spend, *tree.Tree, error) {
			w.base()
			opKey := w.st.Options.OperatorKey
			erin := w.mkLeaf("erin", 12_345, &opKey, 900_000)
			sErin := w.slot(erin, 9, w.st.Tree)
			w.st.Tree.Leaves[sErin] = erin
			gina := w.carveOf(erin, "gina", erin.Amount)
			sGina := w.slot(gina, 6, w.st.Tree)
			vsig, err := SignVoucher(
				sk("erin-owner"), w.st.Options.TreeID, erin, gina,
			)
			if err != nil {
				return nil, nil, err
			}
			return BuildClaim(w.st, sErin, sGina, gina, vsig,
				&TxOpts{Inputs: w.fee(600)})
		},
	}, {
		name: "CLAIM_H", depth: depth, sparse: sparse,
		variants: []string{"CLAIM_H"},
		build: func(w *world) (*Spend, *tree.Tree, error) {
			_, _, oper, _, _, sOper := w.base()
			hodl := w.carveOf(oper, "hodl", 40_000)
			sHodl := w.slot(hodl, 3, w.st.Tree)
			preimage := sha256.Sum256([]byte("payment-preimage"))
			vsig, err := SignVoucherH(
				sk("operator-owner"), w.st.Options.TreeID, oper, hodl,
				sha256.Sum256(preimage[:]),
			)
			if err != nil {
				return nil, nil, err
			}
			return BuildClaimH(w.st, sOper, sHodl, hodl, vsig,
				preimage, &TxOpts{Inputs: w.fee(600)})
		},
	}, {
		name: "SPLIT", depth: depth, sparse: sparse,
		variants: []string{"SPLIT"},
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
}

// evictCases are EVICT_SUBTREE_2 and EVICT_SUBTREE_4 in the dense profile,
// laid out as the suite's test_evict_subtree: a cohort with a common lease
// in the subtree at index 1, every fifth position from the fourth already
// empty, alice and the operator's leaf outside it. When the subtree is the
// whole tree (h = D) there is no room outside it, so the sweep is the
// terminal transition of spec 7.8.
func evictCases(depth int) []txCase {
	var cases []txCase
	for _, h := range []int{2, 4} {
		h := h
		name := fmt.Sprintf("EVICT_SUBTREE_%d", h)
		cases = append(cases, txCase{
			name: name, depth: depth, variants: []string{name},
			build: func(w *world) (*Spend, *tree.Tree, error) {
				opKey := w.st.Options.OperatorKey
				index := uint64(1)
				if h == w.depth {
					index = 0
				}
				base := index << uint(h)
				tr := w.st.Tree
				for i := 0; i < 1<<uint(h); i++ {
					if i%5 == 3 {
						continue
					}
					tr.Leaves[base+uint64(i)] = w.mkLeaf(
						fmt.Sprintf("c%d", i),
						10_000+7*uint64(i), &opKey, 800_000,
					)
				}
				opts := &TxOpts{
					LockTime: 800_000,
					Inputs:   w.fee(5_000),
				}
				if h == w.depth {
					opts.Terminal = wire.NewTxOut(
						400, p2wpkh(w.t),
					)
				} else {
					tr.Leaves[0] = w.mkLeaf("alice", 50_000, nil, 0)
					tr.Leaves[uint64(1)<<w.depth-1] = w.mkLeaf(
						"operator", 1_000_000, nil, 0,
					)
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

// allCases is every transition at every depth and profile covered.
func allCases() []txCase {
	var cases []txCase
	for _, p := range []struct {
		depth  int
		sparse bool
	}{{4, false}, {16, false}, {8, true}} {
		cases = append(cases, exitCases(p.depth, p.sparse)...)
		cases = append(cases, joinCases(p.depth, p.sparse)...)
		cases = append(cases, updateCases(p.depth, p.sparse)...)
		cases = append(cases, carveCases(p.depth, p.sparse)...)
		if !p.sparse {
			cases = append(cases, evictCases(p.depth)...)
		}
	}
	return cases
}

// pythonSighash is the BIP-341 digest tools/script_sim.py computes for each
// case's transaction; see the comment at the top of this file.
var pythonSighash = map[string]string{
	"FULL/D/D16/CLAIM":              "73c981f2e589ba78505254d95dcc91538ede17acba962afceb004781cac2a4fd",
	"FULL/D/D16/CLAIM drain":        "586d68da4aec87911b6a7c0b672cada17d83411d9c27711823168c02cc9ebeb8",
	"FULL/D/D16/CLAIM_H":            "28b74b62d83ad060bc086ce479bfaefcdae89fcd96e010228351e9db35a768a5",
	"FULL/D/D16/EVICT_SUBTREE_2":    "f040c9afe7870fd7c1c3f1c636d39c7b15acd8b2471c7c9113fd282d843675b1",
	"FULL/D/D16/EVICT_SUBTREE_4":    "f82b9245bb52c87d6956fab817a52e3f1e26502f579d9aec7fc86c1a65e02137",
	"FULL/D/D16/EXIT_1 evict":       "29d028b4580f662f56ff5fe46645eff034a77df9f577ee4617e498bdca350c8b",
	"FULL/D/D16/EXIT_1 exact":       "e45b6b2e4ede704658e5bbd66b451855e6b030b846e49dc75a8c6d6afcd2f3f6",
	"FULL/D/D16/EXIT_1 owner":       "f42dbba5a5f59d300b7405014e59fd3802270c429a4aa3b35126f3810fdcfba4",
	"FULL/D/D16/EXIT_1 terminal":    "60d208a09f18ec2b1e5161ee3b70f452b2173370e7c5b6766b1df88437dce826",
	"FULL/D/D16/EXIT_2 owner+evict": "14f39cc331096a30cc23d77b20ab4059c54d4d687583db3832d204f4a011505f",
	"FULL/D/D16/JOINK_2":            "22729d0a12a49869e27ec937d357b794a6d04ff389d7a0e6cd065d2d56dd093f",
	"FULL/D/D16/JOIN_0":             "f91fe7e956226364b9755e1aa993377a25dda6d675c2c6a4d0bb3ced3c961768",
	"FULL/D/D16/JOIN_2":             "85fe28a507d853da30d208a0262882f5f9741323fa402abd60039c2380f67bc0",
	"FULL/D/D16/SPLIT":              "2dc68955410870feb5adf98cfc32a7880754b9c28627c8608ce95c91229bffd1",
	"FULL/D/D16/UPDATE":             "2a3501a5d4d241f949f5a41b3731a1af89632d0820db7db1745fe14a46eb1269",
	"FULL/D/D16/UPDATE_X":           "d375a4f4a736148f2929342a7f767765e1e59f67b32773cff5c2e05987e452d3",
	"FULL/D/D4/CLAIM":               "a8824b600d5ab37bea96a55dcd4c98167829ab69b26ea66a8e8daac4084cdeaf",
	"FULL/D/D4/CLAIM drain":         "8cca97e03d11031a15b55deb97ea8ca74cd661b998a1cf8941f5841a6d9950c7",
	"FULL/D/D4/CLAIM_H":             "b9d189c5603405e063f89f519c7b83de75ae41b8958faa0a8d96c2a31570aa05",
	"FULL/D/D4/EVICT_SUBTREE_2":     "1be854c05eaf1d69f342a27a53df9bec420fb4af398d4da118ececa740e9c198",
	"FULL/D/D4/EVICT_SUBTREE_4":     "c5ea2fe56ec4745af217858b7fa48cc70d0894ff512d24b85d3c68f8e9e4cb52",
	"FULL/D/D4/EXIT_1 evict":        "8f4fa7815ec3f20de47d04b036b236fc925dd74a58864c3c0772f14df54edfca",
	"FULL/D/D4/EXIT_1 exact":        "62394321c20cc8bf28f81a8b2c91c5e13e0fdb85c06bdc9fc2f65a48cc7bf35f",
	"FULL/D/D4/EXIT_1 owner":        "2da79fd6c9fa2a7da03b091e4c3d2f62655fae5beb6bf08a7b1bfea92db446e9",
	"FULL/D/D4/EXIT_1 terminal":     "5b0d36c4beab9386a7bac57041a362fa1dc6663b48bb3d7dc71f1152ef9213ff",
	"FULL/D/D4/EXIT_2 owner+evict":  "73f44f06344f483e3f368529d357518f504fca1bb50b1247602c92cff3c3072b",
	"FULL/D/D4/JOINK_2":             "18fc7128bffeff7c48872a55df392915d55de44b895416d601b450be3ad75a47",
	"FULL/D/D4/JOIN_0":              "2a7a783552abcfcea5fb5f09cf095fdb72d842eae1527a0fe4d41223f8daed1f",
	"FULL/D/D4/JOIN_2":              "cd29c3b3449ae741684a50dca4f894311d877c4974e5cf4ea21190f60fb74385",
	"FULL/D/D4/SPLIT":               "57bf72ae39a598c4cbdd81fddea1b30cac03d524aa83c03089ba6101a10645c1",
	"FULL/D/D4/UPDATE":              "0999ea497177755a136cf8e1912712ff100fa754e1e1768e6de05d78442482dc",
	"FULL/D/D4/UPDATE_X":            "583bfca4aa4f8947be77805051575ea714d3eaae261c73cf8da1ee03a4c6a4c6",
	"FULL/S/D8/CLAIM":               "4cb2f98f1770b5f57ab56df725711f50f4f92baff9bac54e53d4697a7fc27232",
	"FULL/S/D8/CLAIM drain":         "79a6cbf06c0f87ced18de5f83d8f0b9794ad8e131f895afccfc1d8328c4c0571",
	"FULL/S/D8/CLAIM_H":             "69f5d4708e4a1962cb959a4d9fe21f668d6e381f52fa5200816786bb8cb027b9",
	"FULL/S/D8/EXIT_1 evict":        "590c70f75a01deba293abf21334501670adfb0de838219c29b540998e77d3b27",
	"FULL/S/D8/EXIT_1 exact":        "a226b12d5c108f6c1cc07e1ebe3e9972a1f6ce95b9bf9d73149d4ac842104b9c",
	"FULL/S/D8/EXIT_1 owner":        "44fb950ba3ce933f8f3660cd0709918c8da0d257a93dbe254687f6bed051fed9",
	"FULL/S/D8/EXIT_1 terminal":     "5d1511a29eff07af42dc57373e8f9a9ec9c343a7ebb6164ee9d1c2d86f62a257",
	"FULL/S/D8/EXIT_2 owner+evict":  "58728f5705a9b6d8b9b3db346a37fdfb788a2860639549815736ddccbe45b7dd",
	"FULL/S/D8/JOINK_2":             "bb24be2851385057450075fc792947106ec6271b2350933a68779ebde01981fe",
	"FULL/S/D8/JOIN_0":              "8448c92b31cc4f092956bceaf0a9069f1dea464201a9a08bee0563c1f34af735",
	"FULL/S/D8/SPLIT":               "ad1287437a83fd876895cca19f289af0e3af0bd009f1c951668ccabcb6345083",
	"FULL/S/D8/UPDATE":              "162b2bc4dbd5fb40043de7c4b47e6d1b4fcb01e741ecf73c07a74c46947b46b1",
	"FULL/S/D8/UPDATE_X":            "cf3ec3a338f9da0633d4f933affaa562a17541f19aced4a00691604084aa5829",
}

// dumpCase is one case as LAYERTREE_TXN_DUMP writes it.
type dumpCase struct {
	Name        string    `json:"name"`
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
	Stack       []string  `json:"stack"`
	Sighash     string    `json:"sighash"`
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

func recordDump(c *txCase, s *Spend, sighash []byte) {
	d := dumpCase{
		Name:        c.key(),
		Depth:       c.depth,
		Sparse:      c.sparse,
		Variants:    c.variants,
		Version:     s.Tx.Version,
		LockTime:    s.Tx.LockTime,
		Script:      hex.EncodeToString(s.Leaf.Script),
		LeafVersion: s.Leaf.Version,
		Sighash:     hex.EncodeToString(sighash),
	}
	leafHash := s.TapleafHash()
	d.TapleafHash = hex.EncodeToString(leafHash[:])
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
			w := c.world(t)
			spend, next, err := c.build(w)
			if err != nil {
				t.Fatalf("build: %v", err)
			}

			// The builders never modify the state they are given,
			// so w.st.Tree is the tree before the transition.
			before := w.st.Tree
			checkSpend(t, w, before, spend, next)

			sighash, err := spend.Sighash()
			if err != nil {
				t.Fatalf("Sighash: %v", err)
			}
			if dumpPath != "" {
				recordDump(&c, spend, sighash)
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

	// Input 0 spends TREE_SPK(r, m) for the tree before the transition,
	// and the witness's top two elements are r and m (spec 8.2).
	oldRoot := before.Root()
	m := w.st.TapTree.Root()
	if s.Tx.TxIn[0].PreviousOutPoint != w.st.OutPoint ||
		s.Tx.TxIn[0].Sequence != TreeSequence {

		t.Fatal("input 0 is not the tree input")
	}
	prev := s.PrevOuts[w.st.OutPoint]
	wantSPK, err := tree.ScriptPubKey(oldRoot.Hash, m)
	if err != nil {
		t.Fatalf("ScriptPubKey: %v", err)
	}
	if !bytes.Equal(prev.PkScript, wantSPK) ||
		prev.Value != int64(oldRoot.Sum) {

		t.Fatal("input 0's prevout is not TREE_SPK(r, m) holding S")
	}
	n := len(s.Stack)
	if !bytes.Equal(s.Stack[n-2], oldRoot.Hash[:]) ||
		!bytes.Equal(s.Stack[n-1], m[:]) {

		t.Fatal("the stack does not end in r m")
	}

	// Output 0 recreates the tree the builder reports (rules 2, 4, 5),
	// unless that tree is empty (7.8).
	newRoot := next.Root()
	if newRoot != tree.EmptyNode(w.depth) {
		spk, err := tree.ScriptPubKey(newRoot.Hash, m)
		if err != nil {
			t.Fatalf("ScriptPubKey: %v", err)
		}
		if !bytes.Equal(s.Tx.TxOut[0].PkScript, spk) ||
			s.Tx.TxOut[0].Value != int64(newRoot.Sum) {

			t.Fatal("output 0 is not TREE_SPK(r', m) holding S'")
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

// TestBuilderRejects checks that the builders refuse transactions the
// covenant would reject, rather than producing them.
func TestBuilderRejects(t *testing.T) {
	cases := []struct {
		name     string
		sparse   bool
		exact    bool
		variants []string
		build    func(w *world) error
	}{{
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
				sk("alice-owner"), w.st.Options.TreeID, oper, frank,
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
				sk("operator-owner"), w.st.Options.TreeID, oper, frank,
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
			opKey := w.st.Options.OperatorKey
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
			opKey := w.st.Options.OperatorKey
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
			opKey := w.st.Options.OperatorKey
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
			opKey := w.st.Options.OperatorKey
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
			opKey := w.st.Options.OperatorKey
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
			opKey := w.st.Options.OperatorKey
			erin := w.mkLeaf("erin", 12_345, &opKey, 900_000)
			pos := erin.Position(w.depth) ^ 1
			_, _, err := BuildJoin(w.st, 0, pos,
				map[uint64]*tree.Leaf{0: erin},
				&TxOpts{Inputs: w.fee(20_000)})
			return err
		},
	}}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			w := newWorld(t, 4, c.sparse, c.variants...)
			if c.exact {
				w = newExactWorld(t, 4, c.sparse)
			}
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
		w := &world{
			t: t, depth: 4, op: op, keys: []*btcec.PrivateKey{op},
			st: st,
		}
		_, _, oper, _, _, sOper := w.base()
		claim := w.carveOf(oper, "frank", claimAmt)
		vsig, err := SignVoucher(
			sk("operator-owner"), st.Options.TreeID, oper, claim,
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
		def := w.st.Options
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
