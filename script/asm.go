// Package script generates the LayerTree transition scripts of
// spec/layertree.md section 8 for the three opcode tiers of section 4.5.
// The generators are direct ports of tools/layertree_scripts.py,
// tools/layertree_mid.py and tools/layertree_min.py; their output is
// checked byte for byte against spec/golden.json.
package script

import (
	"fmt"

	"github.com/btcsuite/btcd/txscript"
)

// Mode selects the tapleaf number encoding used for integer pushes.
type Mode int

const (
	// ModeC2 is tapleaf 0xC2 (BIP-441): unsigned, arbitrary length, minimal LE.
	ModeC2 Mode = iota
	// ModeC0 is tapleaf 0xC0: CScriptNum minimal encoding.
	ModeC0
)

// LeafVersion returns the tapleaf version byte for the mode.
func (m Mode) LeafVersion() byte {
	if m == ModeC0 {
		return byte(txscript.BaseLeafVersion) // 0xc0
	}
	return 0xc2
}

// Opcodes beyond txscript's table: candidate opcodes as numbered by their
// proposals, with placeholders where numbering is unsettled (spec 4.1).
const (
	OP_CAT               = txscript.OP_CAT
	OP_SUBSTR            = txscript.OP_SUBSTR
	OP_LEFT              = txscript.OP_LEFT
	OP_RIGHT             = txscript.OP_RIGHT
	OP_AND               = txscript.OP_AND
	OP_DOWNSHIFT         = 0x99 // BIP-441 OP_DOWNSHIFT (née OP_RSHIFT)
	OP_EC_POINT_ADD      = 0xbb // EC ops draft BIP
	OP_EC_POINT_MUL      = 0xbc
	OP_EC_POINT_NEGATE   = 0xbd
	OP_EC_POINT_X_COORD  = 0xbe
	OP_TX                = 0xbf // OP_TX draft claims 0xbd; PLACEHOLDER to avoid the collision
	OP_TWEAKADD          = 0xc0 // BIP-449 says "0xBE or TBD"; PLACEHOLDER
	OP_INTERNALKEY       = 0xcb // BIP-349
	OP_CHECKSIGFROMSTACK = 0xcc // BIP-348
)

// OP_TX selectors (spec 8.1).
const (
	SelCurrInput = 0x8000
	SelInAmount  = 0x10800
	SelInSpk     = 0x20800
	SelOutSingle = 0x4300
)

// Token is one assembler token: an opcode byte, an integer to push, or
// raw data to push.
type Token struct {
	Op   byte
	Num  int64
	Data []byte
	kind tokKind
}

type tokKind uint8

const (
	tokOp tokKind = iota
	tokNum
	tokData
)

// Op returns an opcode token.
func Op(op byte) Token { return Token{Op: op, kind: tokOp} }

// Num returns an integer push token (encoded per Mode at assembly).
func Num(n int64) Token { return Token{Num: n, kind: tokNum} }

// Data returns a data push token.
func Data(b []byte) Token { return Token{Data: b, kind: tokData} }

// Ops maps several opcodes.
func Ops(ops ...byte) []Token {
	out := make([]Token, len(ops))
	for i, o := range ops {
		out[i] = Op(o)
	}
	return out
}

// EncodeNumC2 is the BIP-441 minimal unsigned little-endian encoding.
func EncodeNumC2(n int64) []byte {
	if n < 0 {
		panic("negative number in 0xC2 script")
	}
	var out []byte
	for v := uint64(n); v > 0; v >>= 8 {
		out = append(out, byte(v))
	}
	return out
}

// EncodeNumC0 is the CScriptNum minimal encoding.
func EncodeNumC0(n int64) []byte {
	if n == 0 {
		return nil
	}
	neg := n < 0
	v := uint64(n)
	if neg {
		v = uint64(-n)
	}
	var out []byte
	for ; v > 0; v >>= 8 {
		out = append(out, byte(v))
	}
	if out[len(out)-1]&0x80 != 0 {
		if neg {
			out = append(out, 0x80)
		} else {
			out = append(out, 0x00)
		}
	} else if neg {
		out[len(out)-1] |= 0x80
	}
	return out
}

// pushData returns the canonical push for data (same rules as the Python
// assembler: OP_0 for empty, OP_1..OP_16 for single bytes 1..16, direct
// pushes up to 75 bytes, then PUSHDATA1/2).
func pushData(d []byte) []byte {
	n := len(d)
	switch {
	case n == 0:
		return []byte{txscript.OP_0}
	case n == 1 && d[0] >= 1 && d[0] <= 16:
		return []byte{txscript.OP_1 - 1 + d[0]}
	case n <= 75:
		return append([]byte{byte(n)}, d...)
	case n <= 255:
		return append([]byte{txscript.OP_PUSHDATA1, byte(n)}, d...)
	default:
		return append([]byte{txscript.OP_PUSHDATA2, byte(n), byte(n >> 8)}, d...)
	}
}

// Assemble serialises tokens with the given number mode.
func Assemble(tokens []Token, mode Mode) ([]byte, error) {
	var out []byte
	for _, t := range tokens {
		switch t.kind {
		case tokOp:
			out = append(out, t.Op)
		case tokNum:
			if mode == ModeC0 {
				out = append(out, pushData(EncodeNumC0(t.Num))...)
			} else {
				out = append(out, pushData(EncodeNumC2(t.Num))...)
			}
		case tokData:
			out = append(out, pushData(t.Data)...)
		default:
			return nil, fmt.Errorf("script: bad token")
		}
	}
	return out, nil
}

// MustAssemble panics on error.
func MustAssemble(tokens []Token, mode Mode) []byte {
	b, err := Assemble(tokens, mode)
	if err != nil {
		panic(err)
	}
	return b
}
