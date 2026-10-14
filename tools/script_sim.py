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
    "OP_1ADD": 0x8b, "OP_1SUB": 0x8c, "OP_ABS": 0x90, "OP_NOT": 0x91, "OP_0NOTEQUAL": 0x92,
    "OP_ADD": 0x93, "OP_SUB": 0x94, "OP_NUMEQUAL": 0x9c,
    "OP_NUMEQUALVERIFY": 0x9d, "OP_LESSTHAN": 0x9f,
    "OP_LESSTHANOREQUAL": 0xa1, "OP_GREATERTHANOREQUAL": 0xa2,
    "OP_SHA256": 0xa8, "OP_CHECKSIG": 0xac, "OP_CHECKSIGVERIFY": 0xad,
    "OP_CHECKLOCKTIMEVERIFY": 0xb1, "OP_CHECKSEQUENCEVERIFY": 0xb2,
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
    # BIP-443 OP_CHECKCONTRACTVERIFY redefines OP_SUCCESS187 (0xbb), which
    # the EC ops draft also claims (see [A-4]); 0xc1 is a PLACEHOLDER here to
    # keep the two apart inside the simulator. The real opcode number does not
    # affect the design (any single byte works identically).
    "OP_CHECKCONTRACTVERIFY": 0xc1,
    # HYPOTHETICAL OP_MERKLESUMUPDATE (design note design/native-opcodes.md,
    # issue #3 part 2): NOT a candidate opcode, NOT part of any tier, and
    # deliberately NOT in any tier's allowed-opcode set (tools/test_scripts.py
    # fails any real-tier script that uses it). It exists in the simulator to
    # measure what a native state-machine opcode would buy. Parked at 0xc2.
    "OP_MERKLESUMUPDATE": 0xc2,
}
for i in range(1, 17):
    OPS[f"OP_{i}"] = 0x50 + i
OPNAME = {v: k for k, v in OPS.items()}

SIGCHECK_COST = 500_000
# EC ops draft BIP: sigops-budget units where OP_CHECKSIG is 50; BIP-440 makes
# a sigcheck 500,000 varops, i.e. 10,000 varops per sigops unit.
EC_ADD_COST, EC_MUL_COST, EC_NEG_COST, EC_X_COST = 100_000, 300_000, 50_000, 10_000
# BIP-443 OP_CHECKCONTRACTVERIFY. The BIP's sigops-budget accounting is TODO
# upstream; the simulator charges one signature check (500,000 varops) per call,
# the cost of the taproot tweaks it performs (spec section 4.1 [A-6]).
CCV_COST = 500_000
# CCV modes (BIP-443: minimally encoded integers).
CCV_MODE_CHECK_INPUT = -1
CCV_MODE_CHECK_OUTPUT = 0
CCV_MODE_CHECK_OUTPUT_IGNORE_AMOUNT = 1
CCV_MODE_CHECK_OUTPUT_DEDUCT_AMOUNT = 2
# Raw byte patterns of the special values (matched on bytes, not on decoded
# numbers, so they work identically in 0xC2 and 0xC0 numerics). 0x81 is the
# minimal CScriptNum encoding of -1; 0x51..0x60 are OP_1..OP_16.
CCV_MINUS1 = b"\x81"
CCV_ZERO = b""


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


class _CcvSuccess(Exception):
    """Internal: a CCV call with an undefined mode; the input's script is
    unconditionally valid (BIP-443: OP_SUCCESSx semantics)."""


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
                 prevouts=None, version=2, tapleaf_hash=bytes(32),
                 internal_key=None, taptree_root=None):
        # inputs: list of (amount, scriptPubKey); outputs: list of (amount, scriptPubKey)
        self.inputs, self.outputs = inputs, outputs
        self.locktime, self.input_index = locktime, input_index
        self.sequences = sequences or [0xfffffffd] * len(inputs)
        self.prevouts = prevouts or [(hashlib.sha256(b"prevout%d" % i).digest(), i) for i in range(len(inputs))]
        self.version = version
        self.tapleaf_hash = tapleaf_hash
        # BIP-443 OP_CHECKCONTRACTVERIFY needs the current input's taproot
        # internal key and taptree Merkle root (the special values -1), and
        # transaction-wide amount state shared by every input's script.
        # internal_key is the 32-byte x-only internal key of the input being
        # spent (key-path spends have no taptree; the None default keeps
        # every existing caller unchanged and fails loudly if a CCV script
        # reaches for the special values without the caller supplying them).
        self.internal_key = internal_key
        self.taptree_root = taptree_root
        self.ccv_reset()  # tx-wide init: output_min_amount = [0] * n_outputs etc.

    def ccv_reset(self):
        """Transaction-wide CCV initialization (BIP-443): the three arrays.

        Called from __init__ (a fresh TxContext is a fresh transaction) and
        by tests that reuse a TxContext across multiple inputs' scripts.
        """
        n = len(self.outputs)
        self.ccv_min_amount = [0] * n
        self.ccv_checked_default = [False] * n
        self.ccv_checked_deduct = [False] * n

    def ccv_input_init(self, index):
        """Per-input CCV initialization: residual = this input's amount.

        BIP-443 runs this at the beginning of each input's script
        # evaluation. The Interp.run() entry point calls it.
        """
        self.ccv_residual = self.inputs[index][0]

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


def collate(ctx, sel, inputs=None, outputs=None):
    """OP_TX with TXSELECT_COLLATE: one element, per Appendix C.2.1 [C-A1].

    The selected fields in txid order, with CompactSize length prefixes for
    variable-size objects and CompactSize for counts:

        le32(nVersion) || cs(num_inputs) || { le32(nSequence) || le64(amount)
          || cs(len(spk)) || spk }_inputs || cs(num_outputs)
          || { le64(amount) || cs(len(spk)) || spk }_outputs || le32(nLockTime)

    Each field appears only when its bit is selected. This is also the
    off-chain signer's serialiser for the channel messages of C.2.2.
    """
    if sel & (TXSELECT_INPUT_OUTPOINT_HASH | TXSELECT_INPUT_OUTPOINT_INDEX |
              TXSELECT_INPUT_SCRIPT | TXSELECT_CURR_INPUT_NUMBER):
        raise ScriptError("COLLATE: field not modelled")
    if inputs is None:
        isel = sel & TXSELECT_INPUTSELECT_MASK
        inputs = [ctx.input_index] if isel == TXSELECT_INPUTSELECT_CURRENT else list(range(len(ctx.inputs)))
    if outputs is None:
        outputs = list(range(len(ctx.outputs)))
    cs = lt.compact_size
    out = bytearray()
    if sel & TXSELECT_VERSION:
        out += ctx.version.to_bytes(4, "little")
    if sel & TXSELECT_NUM_INPUTS:
        out += cs(len(ctx.inputs))
    for i in inputs:
        amt, spk = ctx.inputs[i]
        if sel & TXSELECT_INPUT_SEQUENCE:
            out += ctx.sequences[i].to_bytes(4, "little")
        if sel & TXSELECT_INPUT_AMOUNT:
            out += amt.to_bytes(8, "little")
        if sel & TXSELECT_INPUT_SCRIPTPUBKEY:
            out += cs(len(spk)) + spk
    if sel & TXSELECT_NUM_OUTPUTS:
        out += cs(len(ctx.outputs))
    for i in outputs:
        amt, spk = ctx.outputs[i]
        if sel & TXSELECT_OUTPUT_AMOUNT:
            out += amt.to_bytes(8, "little")
        if sel & TXSELECT_OUTPUT_SCRIPT:
            out += cs(len(spk)) + spk
    if sel & TXSELECT_LOCKTIME:
        out += ctx.locktime.to_bytes(4, "little")
    return bytes(out)


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

    def __init__(self, ctx, budget=None, mode="c2", hypothetical=False):
        """mode: "c2" = tapleaf 0xC2 (BIP-441 numerics), "c0" = tapleaf 0xC0 (CScriptNum).

        hypothetical=True additionally enables the HYPOTHETICAL
        OP_MERKLESUMUPDATE (design/native-opcodes.md): a measurement
        instrument only, never part of a tier. The flag must be passed
        explicitly by a caller that means it, so ordinary scripts fail
        loudly if they reach the opcode.
        """
        self.ctx = ctx
        self.cost = 0
        self.budget = budget
        self.sigchecks = 0
        self.max_depth = 0
        self.mode = mode
        self.hypothetical = hypothetical
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
        self._ccv_success = False
        if self.ctx is not None:
            # BIP-443 per-input init; experiments run scripts without a
            # transaction context and have no CCV state to reset.
            self.ctx.ccv_input_init(self.ctx.input_index)
        try:
            return self._run(script, stack)
        except _CcvSuccess:
            return True  # undefined CCV mode: script succeeds unconditionally
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
                pushv(a[len(a) - o:] if o < len(a) else a)  # o = 0 gives empty, o >= size gives a
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
            elif name == "OP_ABS":
                a = pop(); self.charge(wordspan(len(a)) * 2)
                pushv(self.n_enc(abs(self.n_dec(a))))
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
                if v < 0:
                    raise ScriptError("CLTV operand negative")
                if v >= 1 << 32:
                    raise ScriptError("CLTV operand too large")
                if self.ctx.sequences[self.ctx.input_index] == 0xffffffff:
                    raise ScriptError("CLTV: sequence final")
                if (v < 500_000_000) != (self.ctx.locktime < 500_000_000) or self.ctx.locktime < v:
                    raise ScriptError("CLTV not satisfied")
            elif name == "OP_CHECKSEQUENCEVERIFY":
                # BIP-112, as used by the channel scripts of Appendix C.3.3.
                # The script check only compares the operand with the input's
                # nSequence; the relative lock itself (BIP-68) is a property
                # of the block the transaction is mined in, which the chain
                # model of tools/test_chan.py enforces.
                a = top()
                self.charge(wordspan(len(a)) * 2)
                v = scriptnum_decode(a, 5) if self.mode == "c0" else num_decode(a)
                if v < 0 or v >= 1 << 32:
                    raise ScriptError("CSV operand out of range")
                if not v & (1 << 31):
                    seq = self.ctx.sequences[self.ctx.input_index]
                    if self.ctx.version < 2:
                        raise ScriptError("CSV: transaction version < 2")
                    if seq & (1 << 31):
                        raise ScriptError("CSV: input sequence disables relative lock")
                    mask = (1 << 22) | 0xffff
                    if (v & (1 << 22)) != (seq & (1 << 22)):
                        raise ScriptError("CSV: lock type mismatch")
                    if (seq & mask) < (v & mask):
                        raise ScriptError("CSV not satisfied")
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
            elif name == "OP_CHECKCONTRACTVERIFY":
                self.op_ccv(st, pop, pushv)
            elif name == "OP_MERKLESUMUPDATE":
                if not self.hypothetical:
                    raise ScriptError(
                        "OP_MERKLESUMUPDATE is a HYPOTHETICAL measurement "
                        "opcode (design/native-opcodes.md); pass "
                        "hypothetical=True to the Interp to use it")
                self.op_msu(pop, pushv)
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
            blob = collate(ctx, sel, inputs, outputs)
            self.charge(len(blob) * 2)
            pushv(blob)
            return
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

    def op_ccv(self, st, pop, pushv):
        """OP_CHECKCONTRACTVERIFY (BIP-443), pinned as spec section 4.1 [A-6].

        Stack (bottom..top): <data> <index> <pk> <taptree> <mode>; the BIP
        pops all five. The parameters are matched on their raw byte
        patterns, so the special values work identically under 0xC2 and
        0xC0 numerics: 0x81 is the minimal CScriptNum -1 everywhere.
        """
        ctx = self.ctx
        self.charge(CCV_COST)
        mode = pop()
        taptree = pop()
        pk = pop()
        index = pop()
        data = pop()

        # Mode is a minimally encoded integer; any value outside -1..2 is
        # OP_SUCCESSx (the script unconditionally succeeds). Model it as
        # "drop the five operands and succeed" by pushing 1: the caller
        # treats a non-empty stack top as success.
        def num_of(b):
            # Minimal CScriptNum decode (BIP-443 pins minimal encoding for
            # mode and index; reject non-minimal with the 0xC0 decoder).
            return scriptnum_decode(b, 4)
        try:
            mval = num_of(mode)
        except ScriptError:
            raise ScriptError("CCV: non-minimal mode operand")
        if not (CCV_MODE_CHECK_INPUT <= mval <= CCV_MODE_CHECK_OUTPUT_DEDUCT_AMOUNT):
            # Undefined mode: the opcode is OP_SUCCESSx for this input, the
            # script unconditionally succeeds. Mark the whole run as such;
            # the interpreter stops and accepts.
            self._ccv_success = True
            raise _CcvSuccess()

        # Index: -1 (0x81) or a minimally encoded non-negative integer.
        if index == CCV_MINUS1:
            idx = ctx.input_index
        else:
            idx = num_of(index)
            if idx < 0:
                raise ScriptError("CCV: negative index")

        # Taptree: 0x81 = current input's taptree; empty = no taptweak;
        # 32 bytes = a Merkle root. Anything else fails.
        if taptree == CCV_MINUS1:
            if ctx.taptree_root is None:
                raise ScriptError("CCV: input taptree not modelled")
            taptree = ctx.taptree_root
        elif taptree == b"":
            pass
        elif len(taptree) == 32:
            pass
        else:
            raise ScriptError("CCV: invalid taptree operand")

        # Naked key: empty = NUMS (BIP-341 H); 0x81 = current input
        # internal key; 32 bytes = an x-only key. Anything else fails.
        if pk == b"":
            naked = lt.NUMS_X
        elif pk == CCV_MINUS1:
            if ctx.internal_key is None:
                raise ScriptError("CCV: input internal key not modelled")
            naked = ctx.internal_key
        elif len(pk) == 32:
            naked = pk
        else:
            raise ScriptError("CCV: invalid pk operand")

        # tweak_embed_data: empty data returns the pubkey unchanged (no
        # data tweak at all); otherwise the tweak is sha256(pk||data),
        # untagged, per BIP-443.
        if data != b"":
            t = int.from_bytes(lt.sha256(naked + data), "big")
            if t >= lt.N:
                raise ScriptError("CCV: data tweak >= n")
            P = lt.lift_x(int.from_bytes(naked, "big"))
            if P is None:
                raise ScriptError("CCV: naked key has no curve point")
            Q = lt.point_add(P, lt.point_mul(lt.G, t))
            internal_key = lt.xonly(Q)
        else:
            internal_key = naked

        # TapTweak (tagged, BIP-341) unless the taptree operand is empty.
        if taptree != b"":
            t2 = int.from_bytes(lt.tagged_hash("TapTweak", internal_key + taptree), "big")
            P2 = lt.lift_x(int.from_bytes(internal_key, "big"))
            if P2 is None:
                raise ScriptError("CCV: internal key has no curve point")
            Q2 = lt.point_add(P2, lt.point_mul(lt.G, t2))
            final_key = lt.xonly(Q2)
        else:
            final_key = internal_key
        target_spk = bytes([0x51, 0x20]) + final_key

        # Bound checks and target scriptPubKey comparison.
        if mval == CCV_MODE_CHECK_INPUT:
            if idx < 0 or idx >= len(ctx.inputs):
                raise ScriptError("CCV: input index out of bounds")
            target = ctx.inputs[idx][1]
        else:
            if idx < 0 or idx >= len(ctx.outputs):
                raise ScriptError("CCV: output index out of bounds")
            target = ctx.outputs[idx][1]
            # Amount semantics (deferred state on the TxContext).
            out_amt = ctx.outputs[idx][0]
            if mval == CCV_MODE_CHECK_OUTPUT:
                if ctx.ccv_checked_deduct[idx]:
                    raise ScriptError("CCV: default after deduct on same output")
                ctx.ccv_min_amount[idx] += ctx.ccv_residual
                ctx.ccv_residual = 0
                if out_amt < ctx.ccv_min_amount[idx]:
                    raise ScriptError("CCV: output below assigned amount")
                ctx.ccv_checked_default[idx] = True
            elif mval == CCV_MODE_CHECK_OUTPUT_DEDUCT_AMOUNT:
                if ctx.ccv_residual < out_amt:
                    raise ScriptError("CCV: residual below deducted amount")
                if ctx.ccv_checked_default[idx] or ctx.ccv_checked_deduct[idx]:
                    raise ScriptError("CCV: duplicate deduct / default+deduct mix")
                ctx.ccv_residual -= out_amt
                ctx.ccv_checked_deduct[idx] = True
            # CCV_MODE_CHECK_OUTPUT_IGNORE_AMOUNT: no amount bookkeeping.
        if target != target_spk:
            raise ScriptError("CCV: target scriptPubKey mismatch")

    def op_msu(self, pop, pushv):
        """OP_MERKLESUMUPDATE (HYPOTHETICAL; design/native-opcodes.md).

        Stack: ... <proof> <old_node> <new_node>  ->  ... <old_root> <new_root>

        node  := hash(32) || sum(le64)                40 bytes (the spec's sc)
        proof := depth(u8) || position(ceil(d/8) bytes, big-endian, MSB =
                 the side at the top level; bit 0 = the leaf level)
                 || bitmap(ceil(d/8), bit k set = the sibling at level k
                 is supplied) || siblings (one 40-byte node per set bit,
                 deepest level first, i.e. level 0 first)

        Per level k, leaf up: the sibling is the next supplied node if
        bitmap bit k is set, else E_k (E_0 = (0^32, 0), E_{k+1} the parent
        of E_k with itself, precomputable by consensus); the position bit
        gives the side; the parent is the spec's node_hash with sums
        added. Fails on sum overflow, depth 0 or > 64, a malformed proof,
        leftover sibling bytes, bitmap or position bits set above the
        depth, or a supplied sibling equal to E_k: the proof encoding is
        canonical, so a relay cannot inflate a spender's witness by
        un-compressing it (the witness is not covered by the sighash). The old and new nodes fold in one pass
        over the same path; new_node == old_node degenerates to
        verification. Cost: 2*depth node hashes, charged as BIP-440
        varops (wordspan of an 82-byte preimage per hash).
        """
        new_node = pop()
        old_node = pop()
        proof = pop()
        # node decode
        def node_of(b):
            if len(b) != 40:
                raise ScriptError("MSU: node must be 40 bytes")
            return b[:32], int.from_bytes(b[32:], "little")
        onh, ons = node_of(old_node)
        nnh, nns = node_of(new_node)
        # proof decode
        if len(proof) < 1:
            raise ScriptError("MSU: empty proof")
        d = proof[0]
        if d == 0 or d > 64:
            raise ScriptError("MSU: depth out of range")
        pos_len = (d + 7) // 8
        bm_len = (d + 7) // 8
        if len(proof) < 1 + pos_len + bm_len:
            raise ScriptError("MSU: proof too short")
        pos_bytes = proof[1:1 + pos_len]
        bm_bytes = proof[1 + pos_len:1 + pos_len + bm_len]
        rest = proof[1 + pos_len + bm_len:]
        # Position, MSB first = the TOP level is the most significant
        # bit: bit (d-1) of the big-endian integer is the side at the top
        # level, bit 0 the side at the leaf level (level k's bit is k).
        pos_int = int.from_bytes(pos_bytes, "big")
        # Bitmap: bit k set = the sibling at level k (k = 0 the leaf
        # level) is supplied. The sibling list runs deepest level first,
        # i.e. in the order the fold consumes it, from k = 0 upward.
        bm_int = int.from_bytes(bm_bytes, "big")
        if pos_int >> d or bm_int >> d:
            raise ScriptError("MSU: position or bitmap bit above the depth")
        set_levels = [k for k in range(d) if (bm_int >> k) & 1]
        if len(rest) != 40 * len(set_levels):
            raise ScriptError("MSU: sibling count mismatch")
        sibs = {}
        for lvl in set_levels:
            sibs[lvl] = node_of(rest[:40])
            rest = rest[40:]
        # empty-node chain (E_0 up)
        empties = [None] * d
        e = (bytes(32), 0)
        for k in range(d):
            empties[k] = e
            e = (lt.node_hash(e, e), e[1] + e[1])
        # fold both nodes in one pass
        ohash, osum = onh, ons
        nhash, nsum = nnh, nns
        for k in range(d):
            side = (pos_int >> k) & 1
            if k in sibs:
                s = sibs[k]
                if s == empties[k]:
                    raise ScriptError("MSU: empty sibling supplied explicitly")
            else:
                s = empties[k]
            sh, ss = s
            if osum + ss >= 1 << 64 or nsum + ss >= 1 << 64:
                raise ScriptError("MSU: sum overflow")
            if side == 0:
                ohash, osum = lt.node_hash((ohash, osum), s), osum + ss
                nhash, nsum = lt.node_hash((nhash, nsum), s), nsum + ss
            else:
                ohash, osum = lt.node_hash(s, (ohash, osum)), osum + ss
                nhash, nsum = lt.node_hash(s, (nhash, nsum)), nsum + ss
            self.charge(wordspan(82) * 2)
        pushv(ohash + osum.to_bytes(8, "little"))
        pushv(nhash + nsum.to_bytes(8, "little"))
