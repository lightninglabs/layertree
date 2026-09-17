#!/usr/bin/env python3
"""Minimal tapscript-0xC2 simulator for validating the LayerTree scripts.

This is NOT a consensus implementation. It models exactly the subset of
opcode semantics the LayerTree scripts rely on, following BIP-441 (GSR)
numeric rules (arbitrary-length unsigned little-endian), the OP_TX draft,
BIP-348 OP_CHECKSIGFROMSTACK, and the assumed OP_ECSCALARMUL /
OP_ECPOINTADD semantics documented in spec/layertree.md section 4.

It also keeps an approximate varops tally (BIP-440/441 cost model) so the
spec's cost table can be derived from actual execution rather than guessed.
"""
import hashlib
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import layertree_ref as lt  # noqa: E402

# ---------------------------------------------------------------- opcodes --
OPS = {
    "OP_0": 0x00, "OP_PUSHDATA1": 0x4c, "OP_PUSHDATA2": 0x4d,
    "OP_IF": 0x63, "OP_NOTIF": 0x64, "OP_ELSE": 0x67, "OP_ENDIF": 0x68,
    "OP_VERIFY": 0x69, "OP_TOALTSTACK": 0x6b, "OP_FROMALTSTACK": 0x6c,
    "OP_2DROP": 0x6d, "OP_2DUP": 0x6e, "OP_2SWAP": 0x72, "OP_DROP": 0x75,
    "OP_DUP": 0x76, "OP_NIP": 0x77, "OP_OVER": 0x78, "OP_PICK": 0x79,
    "OP_ROLL": 0x7a, "OP_ROT": 0x7b, "OP_SWAP": 0x7c, "OP_TUCK": 0x7d,
    "OP_CAT": 0x7e, "OP_SUBSTR": 0x7f, "OP_LEFT": 0x80, "OP_RIGHT": 0x81,
    "OP_SIZE": 0x82, "OP_EQUAL": 0x87, "OP_EQUALVERIFY": 0x88,
    "OP_1ADD": 0x8b, "OP_1SUB": 0x8c, "OP_NOT": 0x91, "OP_0NOTEQUAL": 0x92,
    "OP_ADD": 0x93, "OP_SUB": 0x94, "OP_NUMEQUAL": 0x9c,
    "OP_NUMEQUALVERIFY": 0x9d, "OP_LESSTHAN": 0x9f,
    "OP_LESSTHANOREQUAL": 0xa1, "OP_GREATERTHANOREQUAL": 0xa2,
    "OP_SHA256": 0xa8, "OP_CHECKSIG": 0xac, "OP_CHECKSIGVERIFY": 0xad,
    "OP_CHECKLOCKTIMEVERIFY": 0xb1,
    # OP_SUCCESSx redefinitions (BIP-348, OP_TX draft, BIP-349) and
    # PLACEHOLDER numbers for the EC opcodes, which have none assigned yet.
    "OP_TX": 0xbd, "OP_CHECKSIGFROMSTACK": 0xcc, "OP_INTERNALKEY": 0xcb,
    "OP_ECSCALARMUL": 0xbe, "OP_ECPOINTADD": 0xbf,
}
for i in range(1, 17):
    OPS[f"OP_{i}"] = 0x50 + i
OPNAME = {v: k for k, v in OPS.items()}

SIGCHECK_COST = 500_000


def num_encode(n):
    """Minimal unsigned little-endian (BIP-441)."""
    if n < 0:
        raise ValueError("negative")
    if n == 0:
        return b""
    return n.to_bytes((n.bit_length() + 7) // 8, "little")


def num_decode(b):
    return int.from_bytes(b, "little")


def wordspan(n):
    return ((n + 7) // 8) * 8


class ScriptError(Exception):
    pass


# --------------------------------------------------------------- assembler --
def push(data):
    """Return script bytes pushing `data`."""
    if isinstance(data, int):
        data = num_encode(data)
    n = len(data)
    if n == 0:
        return bytes([0x00])
    if n == 1 and 1 <= data[0] <= 16:
        return bytes([0x50 + data[0]])
    if n <= 75:
        return bytes([n]) + data
    if n <= 255:
        return bytes([0x4c, n]) + data
    return bytes([0x4d]) + n.to_bytes(2, "little") + data


def assemble(tokens):
    """tokens: list of opcode-name strings, ints (numbers) or bytes (data)."""
    out = bytearray()
    for t in tokens:
        if isinstance(t, str):
            if t not in OPS:
                raise ValueError(f"unknown opcode {t}")
            out.append(OPS[t])
        else:
            out += push(t)
    return bytes(out)


def disassemble(script, names=None):
    """Human readable listing; `names` maps constant bytes -> label."""
    names = dict(names or {})
    for sel, label in ((SEL_CURR_INPUT, "SEL_CURR_INPUT"), (SEL_IN_AMOUNT, "SEL_IN_AMOUNT"),
                       (SEL_IN_SPK, "SEL_IN_SPK"), (SEL_OUT_SINGLE, "SEL_OUT_SINGLE")):
        names.setdefault(num_encode(sel), f"<{label}>")

    def fmt(d):
        if d in names:
            return names[d]
        if 0 < len(d) <= 4:
            return str(num_decode(d))
        return f"<{d.hex()}>"
    i, out = 0, []
    while i < len(script):
        op = script[i]
        i += 1
        if op == 0:
            out.append("OP_0")
        elif op <= 75:
            d = script[i:i + op]
            i += op
            out.append(fmt(d))
        elif op == 0x4c:
            n = script[i]
            d = script[i + 1:i + 1 + n]
            i += 1 + n
            out.append(fmt(d))
        elif op == 0x4d:
            n = int.from_bytes(script[i:i + 2], "little")
            d = script[i + 2:i + 2 + n]
            i += 2 + n
            out.append(fmt(d))
        else:
            out.append(OPNAME.get(op, f"OP_UNKNOWN_{op:02x}"))
    return out


# ------------------------------------------------------------- BIP-340 sigs --
def _int(b):
    return int.from_bytes(b, "big")


def schnorr_sign(msg, seckey, aux=bytes(32)):
    d0 = _int(seckey)
    assert 1 <= d0 < lt.N
    Pp = lt.point_mul(lt.G, d0)
    d = d0 if Pp[1] % 2 == 0 else lt.N - d0
    t = (d ^ _int(lt.tagged_hash("BIP0340/aux", aux))).to_bytes(32, "big")
    k0 = _int(lt.tagged_hash("BIP0340/nonce", t + lt.xonly(Pp) + msg)) % lt.N
    assert k0 != 0
    R = lt.point_mul(lt.G, k0)
    k = k0 if R[1] % 2 == 0 else lt.N - k0
    e = _int(lt.tagged_hash("BIP0340/challenge", lt.xonly(R) + lt.xonly(Pp) + msg)) % lt.N
    return lt.xonly(R) + ((k + e * d) % lt.N).to_bytes(32, "big")


def schnorr_verify(msg, pubkey_x, sig):
    if len(sig) != 64 or len(pubkey_x) != 32:
        return False
    Pp = lt.lift_x(_int(pubkey_x))
    if Pp is None:
        return False
    r, s = _int(sig[:32]), _int(sig[32:])
    if r >= lt.P or s >= lt.N:
        return False
    e = _int(lt.tagged_hash("BIP0340/challenge", sig[:32] + pubkey_x + msg)) % lt.N
    R = lt.point_add(lt.point_mul(lt.G, s), lt.point_mul(Pp, lt.N - e))
    return R is not None and R[1] % 2 == 0 and R[0] == r


def pubkey_x(seckey):
    return lt.xonly(lt.point_mul(lt.G, _int(seckey)))


# ---------------------------------------------------------------- tx model --
class TxContext:
    """Just enough of a transaction for OP_TX, CLTV and CHECKSIG."""

    def __init__(self, inputs, outputs, locktime=0, input_index=0, sequences=None):
        # inputs: list of (amount, scriptPubKey); outputs: list of (amount, scriptPubKey)
        self.inputs, self.outputs = inputs, outputs
        self.locktime, self.input_index = locktime, input_index
        self.sequences = sequences or [0xfffffffd] * len(inputs)

    def sighash(self):
        # Stand-in for the BIP-341 signature message: commits to everything
        # the LayerTree scripts care about (all inputs, outputs, locktime).
        h = hashlib.sha256()
        h.update(self.locktime.to_bytes(4, "little"))
        for (a, spk), seq in zip(self.inputs, self.sequences):
            h.update(a.to_bytes(8, "little") + lt.compact_size(len(spk)) + spk + seq.to_bytes(4, "little"))
        for a, spk in self.outputs:
            h.update(a.to_bytes(8, "little") + lt.compact_size(len(spk)) + spk)
        return lt.tagged_hash("SimSighash", h.digest())


# OP_TX selector bits (draft BIP, rustyrussell/bips guilt/varops).
TXSELECT_COLLATE = 0x1
TXSELECT_VERSION = 0x2
TXSELECT_NUM_INPUTS = 0x4
TXSELECT_INPUT_OUTPOINT_HASH = 0x8
TXSELECT_INPUT_OUTPOINT_INDEX = 0x10
TXSELECT_INPUT_SCRIPT = 0x20
TXSELECT_INPUT_SEQUENCE = 0x40
TXSELECT_NUM_OUTPUTS = 0x80
TXSELECT_OUTPUT_AMOUNT = 0x100
TXSELECT_OUTPUT_SCRIPT = 0x200
TXSELECT_LOCKTIME = 0x400
TXSELECT_INPUTSELECT_MASK = 0x1800
TXSELECT_INPUTSELECT_CURRENT = 0x800
TXSELECT_INPUTSELECT_SINGLE = 0x1000
TXSELECT_OUTPUTSELECT_MASK = 0x6000
TXSELECT_OUTPUTSELECT_CURRENT = 0x2000
TXSELECT_OUTPUTSELECT_SINGLE = 0x4000
TXSELECT_CURR_INPUT_NUMBER = 0x8000
TXSELECT_INPUT_AMOUNT = 0x10000
TXSELECT_INPUT_SCRIPTPUBKEY = 0x20000
KNOWN_BITS = 0xfffff

# Selectors used by LayerTree (spec section 8.1).
SEL_CURR_INPUT = TXSELECT_CURR_INPUT_NUMBER
SEL_IN_AMOUNT = TXSELECT_INPUT_AMOUNT | TXSELECT_INPUTSELECT_CURRENT
SEL_IN_SPK = TXSELECT_INPUT_SCRIPTPUBKEY | TXSELECT_INPUTSELECT_CURRENT
SEL_OUT_SINGLE = TXSELECT_OUTPUT_AMOUNT | TXSELECT_OUTPUT_SCRIPT | TXSELECT_OUTPUTSELECT_SINGLE


# -------------------------------------------------------------- interpreter --
class Interp:
    MAX_ELEM = 4_000_000

    def __init__(self, ctx, budget=None):
        self.ctx = ctx
        self.cost = 0
        self.budget = budget
        self.sigchecks = 0
        self.max_depth = 0

    def charge(self, units):
        self.cost += units
        if self.budget is not None and self.cost > self.budget:
            raise ScriptError("varops budget exceeded")

    def run(self, script, stack):
        st = list(stack)
        alt = []
        pc = 0
        cond = []  # execution condition stack

        def exec_ok():
            return all(cond)

        def pop():
            if not st:
                raise ScriptError("stack underflow")
            return st.pop()

        def popn():
            return num_decode(pop())

        def top(i=0):
            return st[-1 - i]

        def pushv(v):
            if len(v) > self.MAX_ELEM:
                raise ScriptError("element too large")
            st.append(bytes(v))
            self.max_depth = max(self.max_depth, len(st) + len(alt))

        while pc < len(script):
            op = script[pc]
            pc += 1
            # --- pushes ---
            if op <= 0x4d:
                if op == 0:
                    data = b""
                elif op <= 75:
                    data, pc = script[pc:pc + op], pc + op
                elif op == 0x4c:
                    n = script[pc]
                    data, pc = script[pc + 1:pc + 1 + n], pc + 1 + n
                else:
                    n = int.from_bytes(script[pc:pc + 2], "little")
                    data, pc = script[pc + 2:pc + 2 + n], pc + 2 + n
                if exec_ok():
                    pushv(data)
                continue
            if 0x51 <= op <= 0x60:
                if exec_ok():
                    pushv(bytes([op - 0x50]))
                continue
            name = OPNAME.get(op)
            if name is None:
                raise ScriptError(f"unknown opcode {op:#x}")
            # --- control flow ---
            if name in ("OP_IF", "OP_NOTIF"):
                v = False
                if exec_ok():
                    b = pop()
                    if b not in (b"", b"\x01"):
                        raise ScriptError("MINIMALIF")
                    v = (b == b"\x01")
                    if name == "OP_NOTIF":
                        v = not v
                cond.append(v)
                continue
            if name == "OP_ELSE":
                if not cond:
                    raise ScriptError("unbalanced ELSE")
                cond[-1] = not cond[-1]
                continue
            if name == "OP_ENDIF":
                if not cond:
                    raise ScriptError("unbalanced ENDIF")
                cond.pop()
                continue
            if not exec_ok():
                continue
            # --- everything else ---
            if name == "OP_VERIFY":
                a = pop()
                self.charge(wordspan(len(a)) * 2)
                if not any(a):
                    raise ScriptError("VERIFY failed")
            elif name == "OP_TOALTSTACK":
                alt.append(pop())
            elif name == "OP_FROMALTSTACK":
                if not alt:
                    raise ScriptError("altstack underflow")
                pushv(alt.pop())
            elif name == "OP_2DROP":
                pop(); pop()
            elif name == "OP_2DUP":
                a, b = top(1), top(0)
                self.charge((len(a) + len(b)) * 3)
                pushv(a); pushv(b)
            elif name == "OP_2SWAP":
                d, c, b, a = pop(), pop(), pop(), pop()
                pushv(c); pushv(d); pushv(a); pushv(b)
            elif name == "OP_DROP":
                pop()
            elif name == "OP_DUP":
                a = top()
                self.charge(len(a) * 3)
                pushv(a)
            elif name == "OP_NIP":
                a = pop(); pop(); pushv(a)
            elif name == "OP_OVER":
                a = top(1)
                self.charge(len(a) * 3)
                pushv(a)
            elif name == "OP_PICK":
                nb = pop()
                n = num_decode(nb)
                self.charge(wordspan(len(nb)) * 2)
                if n >= len(st):
                    raise ScriptError("PICK out of range")
                a = top(n)
                self.charge(len(a) * 3)
                pushv(a)
            elif name == "OP_ROLL":
                nb = pop()
                n = num_decode(nb)
                self.charge(wordspan(len(nb)) * 2 + 48 * n)
                if n >= len(st):
                    raise ScriptError("ROLL out of range")
                a = st.pop(-1 - n)
                pushv(a)
            elif name == "OP_ROT":
                c, b, a = pop(), pop(), pop()
                pushv(b); pushv(c); pushv(a)
            elif name == "OP_SWAP":
                b, a = pop(), pop()
                pushv(b); pushv(a)
            elif name == "OP_TUCK":
                b, a = pop(), pop()
                self.charge(len(b) * 3)
                pushv(b); pushv(a); pushv(b)
            elif name == "OP_CAT":
                b, a = pop(), pop()
                self.charge((len(a) + len(b)) * 3)
                pushv(a + b)
            elif name == "OP_SUBSTR":
                lb, bb, a = pop(), pop(), pop()
                ln, bg = num_decode(lb), num_decode(bb)
                self.charge((wordspan(len(lb)) + wordspan(len(bb))) * 2 + min(ln, max(len(a) - bg, 0)) * 3)
                pushv(a[bg:bg + ln])
            elif name == "OP_LEFT":
                ob, a = pop(), pop()
                self.charge(wordspan(len(ob)) * 2)
                pushv(a[:num_decode(ob)])
            elif name == "OP_RIGHT":
                ob, a = pop(), pop()
                o = num_decode(ob)
                self.charge(wordspan(len(ob)) * 2 + min(o, len(a)) * 3)
                pushv(a[-o:] if o < len(a) else a)
            elif name == "OP_SIZE":
                pushv(num_encode(len(top())))
            elif name in ("OP_EQUAL", "OP_EQUALVERIFY"):
                b, a = pop(), pop()
                if len(a) == len(b):
                    self.charge(len(a) * 2)
                eq = a == b
                if name == "OP_EQUAL":
                    pushv(b"\x01" if eq else b"")
                elif not eq:
                    raise ScriptError(f"EQUALVERIFY failed: {a.hex()} != {b.hex()}")
            elif name in ("OP_ADD", "OP_SUB", "OP_1ADD", "OP_1SUB"):
                if name in ("OP_1ADD", "OP_1SUB"):
                    b, a = b"\x01", pop()
                else:
                    b, a = pop(), pop()
                m = max(wordspan(len(a)), wordspan(len(b)))
                if name in ("OP_ADD", "OP_1ADD"):
                    self.charge(m * 9)
                    pushv(num_encode(num_decode(a) + num_decode(b)))
                else:
                    self.charge(m * 6)
                    r = num_decode(a) - num_decode(b)
                    if r < 0:
                        raise ScriptError("SUB underflow")
                    pushv(num_encode(r))
            elif name == "OP_NOT":
                a = pop(); self.charge(wordspan(len(a)) * 2)
                pushv(b"" if any(a) else b"\x01")
            elif name == "OP_0NOTEQUAL":
                a = pop(); self.charge(wordspan(len(a)) * 2)
                pushv(b"\x01" if any(a) else b"")
            elif name in ("OP_NUMEQUAL", "OP_NUMEQUALVERIFY", "OP_LESSTHAN",
                          "OP_LESSTHANOREQUAL", "OP_GREATERTHANOREQUAL"):
                b, a = pop(), pop()
                self.charge(max(wordspan(len(a)), wordspan(len(b))) * 2)
                x, y = num_decode(a), num_decode(b)
                r = {"OP_NUMEQUAL": x == y, "OP_NUMEQUALVERIFY": x == y,
                     "OP_LESSTHAN": x < y, "OP_LESSTHANOREQUAL": x <= y,
                     "OP_GREATERTHANOREQUAL": x >= y}[name]
                if name == "OP_NUMEQUALVERIFY":
                    if not r:
                        raise ScriptError(f"NUMEQUALVERIFY failed: {x} != {y}")
                else:
                    pushv(b"\x01" if r else b"")
            elif name == "OP_SHA256":
                a = pop(); self.charge(len(a) * 50)
                pushv(hashlib.sha256(a).digest())
            elif name in ("OP_CHECKSIG", "OP_CHECKSIGVERIFY"):
                pk, sig = pop(), pop()
                ok = True
                if sig != b"":
                    self.charge(SIGCHECK_COST); self.sigchecks += 1
                    if len(pk) == 32 and not schnorr_verify(self.ctx.sighash(), pk, sig):
                        raise ScriptError("CHECKSIG failed")
                else:
                    ok = False
                if name == "OP_CHECKSIG":
                    pushv(b"\x01" if ok else b"")
                elif not ok:
                    raise ScriptError("CHECKSIGVERIFY empty sig")
            elif name == "OP_CHECKSIGFROMSTACK":
                pk, msg, sig = pop(), pop(), pop()
                if len(pk) == 0:
                    raise ScriptError("CSFS empty key")
                if sig == b"":
                    pushv(b"")
                else:
                    self.charge(SIGCHECK_COST); self.sigchecks += 1
                    if len(pk) == 32 and not schnorr_verify(msg, pk, sig):
                        raise ScriptError("CSFS failed")
                    pushv(b"\x01")
            elif name == "OP_CHECKLOCKTIMEVERIFY":
                a = top()
                self.charge(wordspan(len(a)) * 2)
                v = num_decode(a)
                if v >= 1 << 32:
                    raise ScriptError("CLTV operand too large")
                if self.ctx.sequences[self.ctx.input_index] == 0xffffffff:
                    raise ScriptError("CLTV: sequence final")
                if (v < 500_000_000) != (self.ctx.locktime < 500_000_000) or self.ctx.locktime < v:
                    raise ScriptError("CLTV not satisfied")
            elif name == "OP_INTERNALKEY":
                pushv(self.ctx.internal_key)
            elif name == "OP_ECSCALARMUL":
                a = pop()
                self.charge(SIGCHECK_COST)
                if len(a) > 32:
                    raise ScriptError("scalar too long")
                s = int.from_bytes(a, "big")
                if s == 0 or s >= lt.N:
                    raise ScriptError("scalar out of range")
                pushv(lt.compress(lt.point_mul(lt.G, s)))
            elif name == "OP_ECPOINTADD":
                b, a = pop(), pop()
                self.charge(SIGCHECK_COST)
                r = lt.point_add(lt.decompress(a), lt.decompress(b))
                if r is None:
                    raise ScriptError("point at infinity")
                pushv(lt.compress(r))
            elif name == "OP_TX":
                self.op_tx(st, pop, popn, pushv)
            else:
                raise ScriptError(f"unimplemented {name}")
        if cond:
            raise ScriptError("unbalanced conditional")
        if len(st) != 1 or not any(st[0]):
            raise ScriptError(f"final stack invalid: {[x.hex() for x in st]}")
        self.charge(wordspan(len(st[0])) * 2)
        return True

    def op_tx(self, st, pop, popn, pushv):
        sel = popn()
        if sel & ~KNOWN_BITS:
            raise ScriptError("OP_TX unknown bits (would OP_SUCCESS)")
        ctx = self.ctx
        isel = sel & TXSELECT_INPUTSELECT_MASK
        if isel == TXSELECT_INPUTSELECT_CURRENT:
            inputs = [ctx.input_index]
        elif isel == TXSELECT_INPUTSELECT_SINGLE:
            i = popn()
            if i >= len(ctx.inputs):
                raise ScriptError("OP_TX input out of range")
            inputs = [i]
        elif isel == 0:
            inputs = list(range(len(ctx.inputs)))
        else:
            raise ScriptError("OP_TX range selector not modelled")
        osel = sel & TXSELECT_OUTPUTSELECT_MASK
        if osel == TXSELECT_OUTPUTSELECT_CURRENT:
            outputs = [ctx.input_index]
        elif osel == TXSELECT_OUTPUTSELECT_SINGLE:
            i = popn()
            if i >= len(ctx.outputs):
                raise ScriptError("OP_TX output out of range")
            outputs = [i]
        elif osel == 0:
            outputs = list(range(len(ctx.outputs)))
        else:
            raise ScriptError("OP_TX range selector not modelled")
        if sel & TXSELECT_COLLATE:
            raise ScriptError("COLLATE not modelled")
        outs = []
        if sel & TXSELECT_VERSION:
            outs.append((2).to_bytes(4, "little"))
        if sel & TXSELECT_NUM_INPUTS:
            outs.append(num_encode(len(ctx.inputs)))
        for i in inputs:
            amt, spk = ctx.inputs[i]
            if sel & TXSELECT_INPUT_SEQUENCE:
                outs.append(ctx.sequences[i].to_bytes(4, "little"))
            if sel & TXSELECT_INPUT_AMOUNT:
                outs.append(amt.to_bytes(8, "little"))
            if sel & TXSELECT_INPUT_SCRIPTPUBKEY:
                outs.append(spk)
        if sel & TXSELECT_NUM_OUTPUTS:
            outs.append(num_encode(len(ctx.outputs)))
        for i in outputs:
            amt, spk = ctx.outputs[i]
            if sel & TXSELECT_OUTPUT_AMOUNT:
                outs.append(amt.to_bytes(8, "little"))
            if sel & TXSELECT_OUTPUT_SCRIPT:
                outs.append(spk)
        if sel & TXSELECT_LOCKTIME:
            outs.append(ctx.locktime.to_bytes(4, "little"))
        if sel & TXSELECT_CURR_INPUT_NUMBER:
            outs.append(num_encode(ctx.input_index))
        for o in outs:
            self.charge(len(o) * 2)
            pushv(o)
