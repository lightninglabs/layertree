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
    # OP_SUCCESSx redefinitions: BIP-348 (0xcc), BIP-349 (0xcb), the EC ops
    # draft BIP (Roasbeef/bips ec-ops-bip: 0xbb..0xbe). The OP_TX draft also
    # claims 0xbd; we place OP_TX at 0xbf here as a PLACEHOLDER until the
    # collision is resolved upstream.
    "OP_TX": 0xbf, "OP_CHECKSIGFROMSTACK": 0xcc, "OP_INTERNALKEY": 0xcb,
    "OP_EC_POINT_ADD": 0xbb, "OP_EC_POINT_MUL": 0xbc,
    "OP_EC_POINT_NEGATE": 0xbd, "OP_EC_POINT_X_COORD": 0xbe,
    "OP_DOWNSHIFT": 0x99, "OP_UPSHIFT": 0x98, "OP_AND": 0x84,
    # BIP-449 OP_TWEAKADD ("0xBE or TBD"); 0xc0 PLACEHOLDER here to avoid the
    # collision with OP_EC_POINT_X_COORD.
    "OP_TWEAKADD": 0xc0, "OP_BOOLOR": 0x9b, "OP_BOOLAND": 0x9a, "OP_1NEGATE": 0x4f,
}
for i in range(1, 17):
    OPS[f"OP_{i}"] = 0x50 + i
OPNAME = {v: k for k, v in OPS.items()}

SIGCHECK_COST = 500_000
# EC ops draft BIP: sigops-budget units where OP_CHECKSIG is 50; BIP-440 makes
# a sigcheck 500,000 varops, i.e. 10,000 varops per sigops unit.
EC_ADD_COST, EC_MUL_COST, EC_NEG_COST, EC_X_COST = 100_000, 300_000, 50_000, 10_000


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
def push(data, mode="c2"):
    """Return script bytes pushing `data`. Ints are encoded as script numbers
    of the given tapleaf mode ("c2": BIP-441 unsigned LE; "c0": CScriptNum)."""
    if isinstance(data, int):
        data = scriptnum_encode(data) if mode == "c0" else num_encode(data)
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


def assemble(tokens, mode="c2"):
    """tokens: list of opcode-name strings, ints (numbers) or bytes (data)."""
    out = bytearray()
    for t in tokens:
        if isinstance(t, str):
            if t not in OPS:
                raise ValueError(f"unknown opcode {t}")
            out.append(OPS[t])
        else:
            out += push(t, mode)
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
    """Just enough of a transaction for OP_TX, CLTV and CHECKSIG.

    sighash() implements the BIP-341 signature message for a script-path
    spend with SIGHASH_DEFAULT (ext_flag = 1, no annex), so that scripts of
    the MIN tier can rebuild it, and so that the Go implementation
    (txscript.CalcTapscriptSignaturehash) produces the same digest.
    """

    def __init__(self, inputs, outputs, locktime=0, input_index=0, sequences=None,
                 prevouts=None, version=2, tapleaf_hash=bytes(32)):
        # inputs: list of (amount, scriptPubKey); outputs: list of (amount, scriptPubKey)
        self.inputs, self.outputs = inputs, outputs
        self.locktime, self.input_index = locktime, input_index
        self.sequences = sequences or [0xfffffffd] * len(inputs)
        self.prevouts = prevouts or [(hashlib.sha256(b"prevout%d" % i).digest(), i) for i in range(len(inputs))]
        self.version = version
        self.tapleaf_hash = tapleaf_hash

    # BIP-341 intermediate hashes
    def sha_prevouts(self):
        return hashlib.sha256(b"".join(txid + vout.to_bytes(4, "little") for txid, vout in self.prevouts)).digest()

    def sha_amounts(self):
        return hashlib.sha256(b"".join(a.to_bytes(8, "little") for a, _ in self.inputs)).digest()

    def sha_scriptpubkeys(self):
        return hashlib.sha256(b"".join(lt.compact_size(len(spk)) + spk for _, spk in self.inputs)).digest()

    def sha_sequences(self):
        return hashlib.sha256(b"".join(q.to_bytes(4, "little") for q in self.sequences)).digest()

    def sha_outputs(self):
        return hashlib.sha256(b"".join(a.to_bytes(8, "little") + lt.compact_size(len(spk)) + spk
                                       for a, spk in self.outputs)).digest()

    def sighash_msg(self):
        return (b"\x00" + b"\x00" + self.version.to_bytes(4, "little") + self.locktime.to_bytes(4, "little") +
                self.sha_prevouts() + self.sha_amounts() + self.sha_scriptpubkeys() + self.sha_sequences() +
                self.sha_outputs() + b"\x02" + self.input_index.to_bytes(4, "little") +
                self.tapleaf_hash + b"\x00" + b"\xff\xff\xff\xff")

    def sighash(self):
        return lt.tagged_hash("TapSighash", self.sighash_msg())


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
def scriptnum_encode(n):
    """CScriptNum minimal encoding (tapscript 0xC0)."""
    if n == 0:
        return b""
    neg = n < 0
    v = -n if neg else n
    out = bytearray()
    while v:
        out.append(v & 0xff)
        v >>= 8
    if out[-1] & 0x80:
        out.append(0x80 if neg else 0x00)
    elif neg:
        out[-1] |= 0x80
    return bytes(out)


def scriptnum_decode(b, max_size=4):
    if len(b) > max_size:
        raise ScriptError("scriptnum overflow (operand > %d bytes)" % max_size)
    if not b:
        return 0
    # MINIMALDATA (policy): reject non-minimal numeric operands
    if b[-1] & 0x7f == 0 and (len(b) == 1 or not (b[-2] & 0x80)):
        raise ScriptError("non-minimal scriptnum (MINIMALDATA policy)")
    v = int.from_bytes(b, "little")
    if b[-1] & 0x80:
        return -(v & ~(0x80 << (8 * (len(b) - 1))))
    return v


class Interp:
    MAX_ELEM = 4_000_000

    def __init__(self, ctx, budget=None, mode="c2"):
        """mode: "c2" = tapleaf 0xC2 (BIP-441 numerics), "c0" = tapleaf 0xC0 (CScriptNum)."""
        self.ctx = ctx
        self.cost = 0
        self.budget = budget
        self.sigchecks = 0
        self.max_depth = 0
        self.mode = mode
        if mode == "c0":
            self.MAX_ELEM = 520

    def n_enc(self, v):
        return scriptnum_encode(v) if self.mode == "c0" else num_encode(v)

    def n_dec(self, b):
        return scriptnum_decode(b) if self.mode == "c0" else num_decode(b)

    def charge(self, units):
        self.cost += units
        if self.budget is not None and self.cost > self.budget:
            raise ScriptError("varops budget exceeded")

    def run(self, script, stack):
        try:
            return self._run(script, stack)
        except ScriptError as e:
            tr = getattr(self, "_trace", None)
            if tr:
                raise ScriptError(f"{e}  [at pc={tr[0]} {tr[1]}; top6={tr[2]}]") from None
            raise

    def _run(self, script, stack):
        st = list(stack)
        for el in st:
            if len(el) > self.MAX_ELEM:
                raise ScriptError("witness element too large")
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
            return self.n_dec(pop())

        def top(i=0):
            return st[-1 - i]

        def pushv(v):
            if len(v) > self.MAX_ELEM:
                raise ScriptError("element too large")
            st.append(bytes(v))
            self.max_depth = max(self.max_depth, len(st) + len(alt))
            if len(st) + len(alt) > (1000 if self.mode == "c0" else 32768):
                raise ScriptError("stack size limit")

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
            if op == 0x4f:  # OP_1NEGATE (0xC0 only)
                if exec_ok():
                    if self.mode != "c0":
                        raise ScriptError("OP_1NEGATE is OP_SUCCESS in 0xC2")
                    pushv(b"\x81")
                continue
            name = OPNAME.get(op)
            if name is None:
                raise ScriptError(f"unknown opcode {op:#x}")
            self._trace = (pc - 1, name, [x.hex() for x in st[-6:]])
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
                n = self.n_dec(nb)
                self.charge(wordspan(len(nb)) * 2)
                if n >= len(st):
                    raise ScriptError("PICK out of range")
                a = top(n)
                self.charge(len(a) * 3)
                pushv(a)
            elif name == "OP_ROLL":
                nb = pop()
                n = self.n_dec(nb)
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
                if self.mode == "c0":
                    raise ScriptError("OP_SUBSTR disabled in 0xC0")
                lb, bb, a = pop(), pop(), pop()
                ln, bg = num_decode(lb), num_decode(bb)
                self.charge((wordspan(len(lb)) + wordspan(len(bb))) * 2 + min(ln, max(len(a) - bg, 0)) * 3)
                pushv(a[bg:bg + ln])
            elif name == "OP_LEFT":
                if self.mode == "c0":
                    raise ScriptError("OP_LEFT disabled in 0xC0")
                ob, a = pop(), pop()
                self.charge(wordspan(len(ob)) * 2)
                pushv(a[:num_decode(ob)])
            elif name == "OP_RIGHT":
                if self.mode == "c0":
                    raise ScriptError("OP_RIGHT disabled in 0xC0")
                ob, a = pop(), pop()
                o = num_decode(ob)
                self.charge(wordspan(len(ob)) * 2 + min(o, len(a)) * 3)
                pushv(a[-o:] if o < len(a) else a)
            elif name == "OP_SIZE":
                pushv(self.n_enc(len(top())))
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
                x, y = self.n_dec(a), self.n_dec(b)
                if name in ("OP_ADD", "OP_1ADD"):
                    self.charge(m * 9)
                    pushv(self.n_enc(x + y))
                else:
                    self.charge(m * 6)
                    r = x - y
                    if r < 0 and self.mode != "c0":
                        raise ScriptError("SUB underflow")
                    pushv(self.n_enc(r))
            elif name in ("OP_BOOLOR", "OP_BOOLAND"):
                b, a = pop(), pop()
                self.charge((wordspan(len(a)) + wordspan(len(b))) * 2)
                x, y = any(a), any(b)
                pushv(b"\x01" if ((x or y) if name == "OP_BOOLOR" else (x and y)) else b"")
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
                x, y = self.n_dec(a), self.n_dec(b)
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
                v = scriptnum_decode(a, 5) if self.mode == "c0" else num_decode(a)
                if v >= 1 << 32:
                    raise ScriptError("CLTV operand too large")
                if self.ctx.sequences[self.ctx.input_index] == 0xffffffff:
                    raise ScriptError("CLTV: sequence final")
                if (v < 500_000_000) != (self.ctx.locktime < 500_000_000) or self.ctx.locktime < v:
                    raise ScriptError("CLTV not satisfied")
            elif name == "OP_INTERNALKEY":
                pushv(self.ctx.internal_key)
            elif name == "OP_EC_POINT_ADD":
                b, a = pop(), pop()
                self.charge(EC_ADD_COST)
                r = lt.point_add(self.ec_decode(a), self.ec_decode(b))
                pushv(b"" if r is None else lt.compress(r))
            elif name == "OP_EC_POINT_MUL":
                scalar, pt = pop(), pop()
                self.charge(EC_MUL_COST)
                if len(scalar) != 32:
                    raise ScriptError("EC_POINT_MUL: scalar must be 32 bytes")
                k = int.from_bytes(scalar, "big") % lt.N
                P0 = lt.G if pt == b"" else self.ec_decode(pt)
                r = lt.point_mul(P0, k) if k else None
                pushv(b"" if r is None else lt.compress(r))
            elif name == "OP_EC_POINT_NEGATE":
                a = pop()
                self.charge(EC_NEG_COST)
                if a == b"":
                    pushv(b"")
                else:
                    P0 = self.ec_decode(a)
                    pushv(lt.compress((P0[0], (lt.P - P0[1]) % lt.P)))
            elif name == "OP_EC_POINT_X_COORD":
                a = pop()
                self.charge(EC_X_COST)
                if a == b"":
                    raise ScriptError("EC_POINT_X_COORD: infinity")
                pushv(self.ec_decode(a)[0].to_bytes(32, "big"))
            elif name == "OP_TWEAKADD":
                pk, tw = pop(), pop()
                self.charge(SIGCHECK_COST)
                if len(pk) != 32 or len(tw) != 32:
                    raise ScriptError("TWEAKADD: operands must be 32 bytes")
                t = int.from_bytes(tw, "big")
                if t >= lt.N:
                    raise ScriptError("TWEAKADD: tweak >= n")
                P0 = lt.lift_x(int.from_bytes(pk, "big"))
                if P0 is None:
                    raise ScriptError("TWEAKADD: invalid x")
                Q = lt.point_add(P0, lt.point_mul(lt.G, t)) if t else P0
                if Q is None:
                    raise ScriptError("TWEAKADD: infinity")
                pushv(Q[0].to_bytes(32, "big"))
            elif name == "OP_DOWNSHIFT":
                bits, a = popn(), pop()
                self.charge(wordspan(1) * 2 + max(len(a) - bits // 8, 0) * 3)
                v = int.from_bytes(a, "little") >> bits
                n_out = max(len(a) - bits // 8, 0)
                pushv(v.to_bytes(n_out, "little") if n_out else b"")
            elif name == "OP_AND":
                b, a = pop(), pop()
                self.charge((wordspan(len(a)) + wordspan(len(b))) * 2)
                if len(b) > len(a):
                    a, b = b, a
                pushv(bytes(x & (b[i] if i < len(b) else 0) for i, x in enumerate(a)))
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

    @staticmethod
    def ec_decode(b):
        """Decode a 33-byte compressed point per the EC ops draft BIP."""
        if len(b) != 33 or b[0] not in (2, 3):
            raise ScriptError("invalid compressed point")
        x = int.from_bytes(b[1:], "big")
        if x >= lt.P:
            raise ScriptError("x >= p")
        pt = lt.lift_x(x)
        if pt is None:
            raise ScriptError("not on curve")
        if (b[0] == 3) != (pt[1] % 2 == 1):
            pt = (pt[0], lt.P - pt[1])
        return pt

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
            outs.append(ctx.version.to_bytes(4, "little"))
        if sel & TXSELECT_NUM_INPUTS:
            outs.append(self.n_enc(len(ctx.inputs)))
        for i in inputs:
            amt, spk = ctx.inputs[i]
            if sel & TXSELECT_INPUT_SEQUENCE:
                outs.append(ctx.sequences[i].to_bytes(4, "little"))
            if sel & TXSELECT_INPUT_AMOUNT:
                outs.append(amt.to_bytes(8, "little"))
            if sel & TXSELECT_INPUT_SCRIPTPUBKEY:
                outs.append(spk)
        if sel & TXSELECT_NUM_OUTPUTS:
            outs.append(self.n_enc(len(ctx.outputs)))
        for i in outputs:
            amt, spk = ctx.outputs[i]
            if sel & TXSELECT_OUTPUT_AMOUNT:
                outs.append(amt.to_bytes(8, "little"))
            if sel & TXSELECT_OUTPUT_SCRIPT:
                outs.append(spk)
        if sel & TXSELECT_LOCKTIME:
            outs.append(ctx.locktime.to_bytes(4, "little"))
        if sel & TXSELECT_CURR_INPUT_NUMBER:
            outs.append(self.n_enc(ctx.input_index))
        for o in outs:
            self.charge(len(o) * 2)
            pushv(o)
