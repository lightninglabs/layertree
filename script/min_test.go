package script

import (
	"testing"

	"github.com/roasbeef/layertree/tree"
)

func TestMinExitScriptD4(t *testing.T) {
	g, _ := midLoadGolden(t)
	midCheckScript(t, g, "MIN/D/D4/EXIT_1", MinExitScript(4))
}

// TestMinSplitScriptD4 checks the MIN SPLIT (spec 7.5.2) against the Python
// generator, and that it uses neither OP_TX nor OP_CHECKSIGFROMSTACK, which
// is what lets it exist in the MIN tier.
func TestMinSplitScriptD4(t *testing.T) {
	g, _ := midLoadGolden(t)
	toks := MinSplitScript(4, tree.DustMin)
	midCheckScript(t, g, "MIN/D/D4/SPLIT", toks)
	for _, tok := range toks {
		if tok.kind == tokOp &&
			(tok.Op == OP_TX || tok.Op == OP_CHECKSIGFROMSTACK) {

			t.Fatalf("MIN SPLIT uses opcode %#x", tok.Op)
		}
	}
}
