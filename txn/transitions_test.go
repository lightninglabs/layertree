package txn

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
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
// the file to TxContext and Interp.

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

// newWorld builds the reference FULL taptree for (depth, profile) and
// appends the named tree-creation variants, as the suite does for UPDATE_X,
// CLAIM_H, SPLIT and EVICT_SUBTREE_h.
func newWorld(t *testing.T, depth int, sparse bool, variants ...string) *world {
	t.Helper()
	op := sk("operator")
	opKey := xonly(op)
	leaves, err := FullReferenceLeaves(
		depth, opKey, sparse, []int{0, 2}, []int{1, 2}, []int{2},
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
			toks = script.FullClaimHScript(depth, sparse)
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

// allCases is every transition at every depth and profile covered.
func allCases() []txCase {
	var cases []txCase
	for _, p := range []struct {
		depth  int
		sparse bool
	}{{4, false}, {16, false}, {8, true}} {
		cases = append(cases, exitCases(p.depth, p.sparse)...)
	}
	return cases
}

// pythonSighash is the BIP-341 digest tools/script_sim.py computes for each
// case's transaction; see the comment at the top of this file.
var pythonSighash = map[string]string{
	"FULL/D/D16/EXIT_1 evict":       "ce37c829f9498e3d573df2c8d0e4860b520d5b21f6855518ee0c320c44d5ca82",
	"FULL/D/D16/EXIT_1 owner":       "a7c7b2851d3a8d3d20d396daa027cd1e7256ba7f3ecd03097bdcd373ab02808f",
	"FULL/D/D16/EXIT_1 terminal":    "e625212bcdb29d2b2974496203fa5a33644c5cfe47bfe59ebd7bd61818094b51",
	"FULL/D/D16/EXIT_2 owner+evict": "f576c2b58d84f07e54fbd914bb35df49031388ae51af051a0c6ecabdc7a4fc4f",
	"FULL/D/D4/EXIT_1 evict":        "e0e0e3cb177cf844cd8469b459ec1d9ac94dc0502f3f454b6352a715eda54e6c",
	"FULL/D/D4/EXIT_1 owner":        "510bd24c7d848faa9172be058fb018ecce260ce4cb0795470c50ecb9ab6dec23",
	"FULL/D/D4/EXIT_1 terminal":     "ea05448dd87f911ea0d2d705f4c8b882b6eeb3d1f30db2fd955dbb9bc76733d8",
	"FULL/D/D4/EXIT_2 owner+evict":  "90910fb8016c9b622c310f4d40352be1b04a1448b44fbb72157e1b356bea2d77",
	"FULL/S/D8/EXIT_1 evict":        "10fdfcec310f6b26c5df5a677d2b22cbd1cd3fa9e8501965b2c4acbf18cad9f2",
	"FULL/S/D8/EXIT_1 owner":        "15e749e2dc8452e4ea8afe76c4fe9f3e66f17ff1396a90629b69084c27807f64",
	"FULL/S/D8/EXIT_1 terminal":     "d24aec9d575201584c1348dc3e027b201eef60f27e7886e8615aa374593c352e",
	"FULL/S/D8/EXIT_2 owner+evict":  "2d7b226c2a86f89d53be35e62327fc40ae5b67b963eae05dd4770efe3ebd99ed",
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
		name  string
		build func(w *world) error
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
	}}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			w := newWorld(t, 4, false)
			if err := c.build(w); err == nil {
				t.Fatal("builder accepted it")
			}
		})
	}
}
