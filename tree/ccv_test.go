package tree

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"
)

// TestCCVScriptPubKey pins the CCV tier's state key and tree output (spec
// 4.6, 6.3) to tools/layertree_ref.py's ccv_internal_key and tree_spk_ccv
// over root = sha256("root") and m = sha256("m"), and checks that they
// differ from the FULL tier's TREE_SPK of the same root and m: the CCV data
// tweak is an untagged sha256 over the key and the data, not H_state.
func TestCCVScriptPubKey(t *testing.T) {
	root := sha256.Sum256([]byte("root"))
	m := sha256.Sum256([]byte("m"))
	const (
		wantInternal = "1bfebddbd08a026683c734381078ad84495449cb021d50f48b4964b83ab6a593"
		wantSPK      = "512068dd7f6fa18435aabe5a06ca268eede52d4bdf42ec33243b28233134d91e4a9d"
		fullSPK      = "512099c94c031d36e4c527f8fc77094fe2db320dc0684ab9f4ff0ade4f1292439277"
	)
	internal, err := CCVInternalKey(root)
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(schnorr.SerializePubKey(internal)); got != wantInternal {
		t.Fatalf("CCV internal key %s, want %s", got, wantInternal)
	}
	spk, err := CCVScriptPubKey(root, m)
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(spk); got != wantSPK {
		t.Fatalf("TREE_SPK_CCV %s, want %s", got, wantSPK)
	}
	full, err := ScriptPubKey(root, m)
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(full); got != fullSPK {
		t.Fatalf("TREE_SPK %s, want %s", got, fullSPK)
	}
	if bytes.Equal(spk, full) {
		t.Fatal("the CCV and FULL tree outputs coincide")
	}
}
