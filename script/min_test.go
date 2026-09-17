package script

import "testing"

func TestMinExitScriptD4(t *testing.T) {
	g, _ := midLoadGolden(t)
	midCheckScript(t, g, "MIN/D/D4/EXIT_1", MinExitScript(4))
}
