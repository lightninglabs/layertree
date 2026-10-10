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
			toks = script.FullClaimHScript(depth, treeID, sparse)
		case "SPLIT":
			toks = script.FullSplitScript(depth, sparse)
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
	return &world{
		t: t, depth: depth, sparse: sparse, op: op,
		keys: []*btcec.PrivateKey{op},
		st: &TreeState{
			Tree:        tree.New(depth),
			Sparse:      sparse,
			TapTree:     tt,
			OperatorKey: opKey,
			TreeID:      treeID,
			OutPoint:    prevOutPoint(0),
		},
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

	opKey := w.st.OperatorKey
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
	variants []string
	build    func(w *world) (*Spend, *tree.Tree, error)
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
			opKey := w.st.OperatorKey
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
			opKey := w.st.OperatorKey
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
			opKey := w.st.OperatorKey
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
			opKey := w.st.OperatorKey
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
				sk("operator-owner"), w.st.TreeID, oper, frank,
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
			opKey := w.st.OperatorKey
			erin := w.mkLeaf("erin", 12_345, &opKey, 900_000)
			sErin := w.slot(erin, 9, w.st.Tree)
			w.st.Tree.Leaves[sErin] = erin
			gina := w.carveOf(erin, "gina", erin.Amount)
			sGina := w.slot(gina, 6, w.st.Tree)
			vsig, err := SignVoucher(
				sk("erin-owner"), w.st.TreeID, erin, gina,
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
				sk("operator-owner"), w.st.TreeID, oper, hodl,
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
				opKey := w.st.OperatorKey
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
	"FULL/D/D16/CLAIM":              "54756f4f1ee0da0844bbbe9ff3a5a6ad488258181c71ca1babac2565d1c1decf",
	"FULL/D/D16/CLAIM drain":        "07ed6946f663888232eb0b376c2e617132dc85477ead6b43ff8be87ace550543",
	"FULL/D/D16/CLAIM_H":            "365ed6234a2e23e022390a176366e14f118af6b0c283d30f956882e23b4625e6",
	"FULL/D/D16/EVICT_SUBTREE_2":    "6b566ea16527b6295a4be6fd6365887073bdde9f6ac8200077dc9c1cd3e92872",
	"FULL/D/D16/EVICT_SUBTREE_4":    "3a880d0e746cde7939ad66667e5cce7b170a89dd140e97b8e0362610f84f5933",
	"FULL/D/D16/EXIT_1 evict":       "1bdcd2a3669c20a13d2928a63aa99a4b31a60551c72892f987c2bd04ed42f7b7",
	"FULL/D/D16/EXIT_1 owner":       "bf1f76c5c73acc8899c61db7d4cafc0b5be18da9e904f6fa732e94f036c61a7e",
	"FULL/D/D16/EXIT_1 terminal":    "c5295b497559d1491b0029faf3c94a171de8bc18512b3389afc9b14821e880b0",
	"FULL/D/D16/EXIT_2 owner+evict": "04e18a962aaa154fc2302a7e56a2818aa2887e64c3b49a302a79f982d78374fa",
	"FULL/D/D16/JOINK_2":            "fa6fd630580bc8f2ca07f7138a6590f412df02be0ead845ccff5bbfc249c7cea",
	"FULL/D/D16/JOIN_0":             "55288246c6242bcb33b7214c11c82faa0fa8a24d4b76a032d537465490445ba2",
	"FULL/D/D16/JOIN_2":             "b905bad23e173aa43e99166c1242ec906fa4c431a19dcde511b8f285f341d311",
	"FULL/D/D16/SPLIT":              "40a0f0085532d6e1b0be13fa521efd3a9ef264d92db587fef7ca046d61fe85f4",
	"FULL/D/D16/UPDATE":             "30ed8fd25b1df275dea4bc5566876c40c80c059ec9135a5cc31bbfe1f5337dad",
	"FULL/D/D16/UPDATE_X":           "b129108be7971e85a46c80afd8084d16c4588fa51f9d531135fe32b24b856a2f",
	"FULL/D/D4/CLAIM":               "25735f3d5e2b12132d8df77a47200d4b161768b435f9a82294b59cd1d8765992",
	"FULL/D/D4/CLAIM drain":         "8ccabcaa9c9f21632979cdef3e2737ceb30cc8b99bc0d103847b664a71a7002d",
	"FULL/D/D4/CLAIM_H":             "11de99baf14f3127db503131d60dfe14a526faf0455777a853cf49159a2f1d6f",
	"FULL/D/D4/EVICT_SUBTREE_2":     "7015e6b9da699f26c404551710ee0c8e7edf5dc7a509f6f94e4c543371b2d0a2",
	"FULL/D/D4/EVICT_SUBTREE_4":     "c4bdd981ced24ec277664e3df88697a6cc358caf235d3d0f806b392227477f17",
	"FULL/D/D4/EXIT_1 evict":        "0f900543752896f6774e05571b6c68d7da5356e22a87458de132746922779f5a",
	"FULL/D/D4/EXIT_1 owner":        "68ddfdcb92c6433316647b791dc2213627820a65d75415f838a46cde907ef5fe",
	"FULL/D/D4/EXIT_1 terminal":     "62198908e52cadd19a929486de9491efbba1046982548e1837e402e3271d166c",
	"FULL/D/D4/EXIT_2 owner+evict":  "adbd763b0704755c4f0bb33581be87bb8653319fe2335b16da0e97ced053b654",
	"FULL/D/D4/JOINK_2":             "41f295c233afcd3239b7f206b94d70f40052d812316f908689bbd105615816cb",
	"FULL/D/D4/JOIN_0":              "c218de4b71fd2e9ced037c338d6ba12bb2cc4fa73a3be2534d55cc8cf77f5191",
	"FULL/D/D4/JOIN_2":              "83922e516251a776e2e60c10990f7d92b18ed200fab3316520901790c8e3c8bf",
	"FULL/D/D4/SPLIT":               "2b675f2564db177a6b3b5e174068fa83d3d94d6cce9b1b18378b97c8cfa6d6e9",
	"FULL/D/D4/UPDATE":              "415f16b0d5614be7b1a534ef522c0f9c350587012dd4532770981a38d6008a79",
	"FULL/D/D4/UPDATE_X":            "e83bb578ef4d62dc5254e69a9a85daeb020a10c0107f4d737dc8a369c279b058",
	"FULL/S/D8/CLAIM":               "643efd96fef391bb3529702b0199b3344a573b05b2ae0181a946030fbb291329",
	"FULL/S/D8/CLAIM drain":         "228f1e5342784bef274ccdad7d93c1722706720388ee9f5594159fc4b644c13a",
	"FULL/S/D8/CLAIM_H":             "17c1431d8529abf0f17acc22fca204532fce402d13c266f27c73741490022683",
	"FULL/S/D8/EXIT_1 evict":        "6d1b149f4908a4d5e03fb7eed037b15cf1e151ab5201e879f5eafe21615ca918",
	"FULL/S/D8/EXIT_1 owner":        "dede1619a39785048fda3ca5adebac0a61a926ecc1a7ba535bbc983da7e35564",
	"FULL/S/D8/EXIT_1 terminal":     "dc656c1c9608bec950a559133e393cc54b60b75655d26234122076371f50581f",
	"FULL/S/D8/EXIT_2 owner+evict":  "3fbcd994e0a92650dd5deba4874d99be476b46f9798e960df144211bf7c5d7b7",
	"FULL/S/D8/JOINK_2":             "a26a6ffc26e2c8338cf84f679b1d70a67abd13420eff14b10fed1a8e29025d9b",
	"FULL/S/D8/JOIN_0":              "21c452a387fe4344f366861ad4620b0e2f6526251aef0ae0999b228218d5247c",
	"FULL/S/D8/SPLIT":               "b3c0d444ee0c633b5f15f0f4fd9afa01216e35d4c8abdb115f3dcabb1f78e7ba",
	"FULL/S/D8/UPDATE":              "b5230b111ea1c27a5388ef23829ff20b2eecd8dda51d795e9b80dd5bef1b1a24",
	"FULL/S/D8/UPDATE_X":            "9e1efed547bdb750ca7b5448bea5cf4beaf2d922ce6b9d13af51c744ffcf40c0",
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
			w := newWorld(t, c.depth, c.sparse, c.variants...)
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
		name   string
		sparse bool
		build  func(w *world) error
	}{{
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
			opKey := w.st.OperatorKey
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
			opKey := w.st.OperatorKey
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
			opKey := w.st.OperatorKey
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
			opKey := w.st.OperatorKey
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
		name: "sweep before the lease expires",
		build: func(w *world) error {
			_, _, _, _, sBob, _ := w.base()
			_, _, err := BuildEvictSubtree(w.st, 2, sBob>>2,
				&TxOpts{LockTime: 799_999, Inputs: w.fee(5_000)})
			return err
		},
	}, {
		name: "sweep over a leaf the operator cannot evict",
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
			opKey := w.st.OperatorKey
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
			w := newWorld(t, 4, c.sparse)
			err := c.build(w)
			if err == nil {
				t.Fatal("builder accepted it")
			}
			t.Log(err)
		})
	}
}
