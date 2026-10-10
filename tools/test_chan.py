#!/usr/bin/env python3
"""Appendix C (channel leaves) executed end to end in the simulator.

A small chain model sits on top of the script interpreter: it tracks a UTXO
set with confirmation heights, checks every input's taproot commitment
(control block against the spent scriptPubKey), runs the tapscript, and
enforces the parts of validity that live outside script: value
conservation, nLockTime finality (BIP-65 / BIP-113 for heights) and BIP-68
relative locks. With it the whole state machine of C.3 runs from a tree
exit to the HTLC sweeps, and the deadline arithmetic of C.4.4 and 9.6.2
runs as a sequence of blocks.

Sections:
  * open: a channel leaf exits from a FULL tree (EXIT_1^=) to its funding
    output; update_n rebinds to two different funding outpoints;
  * uncontested close: update_n, settle_n after csv_delay, HTLC sweeps;
  * contested close: a stale update_j answered by update_n bound to U_j;
  * negatives: stale states, early settlement, cross-role signatures, other
    chan_id (m, capacity, epoch), NUM_INPUTS (C.2.3), tampered fields;
  * MID numerics: the same machine under tapleaf 0xC0, and the 520-byte
    element limit on the settlement collation;
  * dust floor: C.3.4's DUST_CHAN, sub-dust balances and HTLCs trimmed into
    the anchor;
  * lease and evictor: C.6.4 (no eviction before evict_after) and C.6.3 (a
    NUMS evictor leaves the counterparty no force-close);
  * epochs and renewal: C.6.7 (a lease renewal leaves update_n bindable) and
    C.5.2 (an old epoch's update fails against the new funding output);
  * deadlines: C.4.4's budget with and without stale updates confirmed ahead
    of the honest one (beta_chan), and the voucher/HTLC swap of 9.6.2 with
    its ordering violations.
"""
import copy
import hashlib
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import layertree_chan as lc  # noqa: E402
import layertree_ref as lt  # noqa: E402
import layertree_scripts as ls  # noqa: E402
from script_sim import (Interp, ScriptError, TxContext, assemble, pubkey_x,  # noqa: E402
                        schnorr_sign)

FAILS = 0
CHECKS = 0
P2WPKH = b"\x00\x14" + bytes(20)
TREE_ID = lt.tree_id(lt.sha256(b"creation-txid"), 0)   # the suites' shared tree_id (spec 6.2)
MTP = 1_700_000_000           # median time past: any S + n lock time is final

# Appendix C.7: the channel scripts use these opcodes and nothing else.
CHAN_OPCODES = {"OP_TX", "OP_CHECKSIGFROMSTACK", "OP_CHECKLOCKTIMEVERIFY",
                "OP_CHECKSEQUENCEVERIFY", "OP_CAT", "OP_SHA256", "OP_SWAP", "OP_DROP"}
HTLC_OPCODES = {"OP_SIZE", "OP_EQUALVERIFY", "OP_SHA256", "OP_CHECKSIG",
                "OP_CHECKLOCKTIMEVERIFY", "OP_DROP"}


def check(cond, msg):
    global FAILS, CHECKS
    CHECKS += 1
    if not cond:
        FAILS += 1
        print("FAIL:", msg)


def expect_fail(fn, msg):
    global FAILS, CHECKS
    CHECKS += 1
    try:
        fn()
    except ScriptError:
        return
    FAILS += 1
    print(f"FAIL: expected failure: {msg}")


def sk(label):
    return lt.sha256(label.encode())


# ------------------------------------------------------------ chain model --
class ChainError(ScriptError):
    """A consensus failure outside script: lock times, values, commitments."""


class Tx:
    """A transaction: a TxContext (fields and spent outputs) and one witness
    per input, either (stack, script, control) or None for a fee input whose
    key-path signature is not modelled (P2WPKH only)."""

    def __init__(self, ctx, witnesses):
        assert len(witnesses) == len(ctx.inputs)
        self.ctx, self.witnesses = ctx, witnesses

    def txid(self):
        c = self.ctx
        b = c.version.to_bytes(4, "little")
        for (txid, vout), q in zip(c.prevouts, c.sequences):
            b += txid + vout.to_bytes(4, "little") + q.to_bytes(4, "little")
        for amt, spk in c.outputs:
            b += amt.to_bytes(8, "little") + lt.compact_size(len(spk)) + spk
        b += c.locktime.to_bytes(4, "little")
        return hashlib.sha256(hashlib.sha256(b).digest()).digest()

    def vsize(self):
        """BIP-141 virtual size, from the serialized sizes."""
        c = self.ctx
        base = 4 + len(lt.compact_size(len(c.inputs))) + 41 * len(c.inputs)
        base += len(lt.compact_size(len(c.outputs)))
        base += sum(8 + len(lt.compact_size(len(s))) + len(s) for _, s in c.outputs) + 4
        wit = 2
        for w in self.witnesses:
            items = [bytes(64), bytes(33)] if w is None else list(w[0]) + [w[1], w[2]]
            wit += len(lt.compact_size(len(items)))
            wit += sum(len(lt.compact_size(len(x))) + len(x) for x in items)
        return (4 * base + wit + 3) // 4


class Chain:
    def __init__(self, height):
        self.height = height
        self.utxos = {}       # (txid, vout) -> (amount, spk, conf_height)
        self._n = 0

    def fund(self, amount, spk):
        """A confirmed output from outside the model (fee coins, tree output)."""
        self._n += 1
        op = (lt.sha256(b"coin%d" % self._n), 0)
        self.utxos[op] = (amount, spk, self.height)
        return op

    def advance(self, k):
        self.height += k

    def ctx(self, prevouts, outputs, locktime=0, sequences=None, version=2):
        """A TxContext spending `prevouts`, with their amounts and scripts."""
        if any(op not in self.utxos for op in prevouts):
            raise ChainError("missing or spent input")
        inputs = [self.utxos[op][:2] for op in prevouts]
        c = TxContext(inputs, outputs, locktime=locktime, sequences=sequences, version=version)
        c.prevouts = list(prevouts)
        return c

    def bind(self, template, prevouts):
        """Attach a pre-signed template to concrete prevouts (C.2): only the
        spent outputs change, every signed field is kept."""
        c = self.ctx(prevouts, list(template.outputs), template.locktime,
                     list(template.sequences), template.version)
        return c

    def validate(self, tx, h, spent):
        c = tx.ctx
        if len(set(c.prevouts)) != len(c.prevouts):
            raise ChainError("duplicate input")
        for i, op in enumerate(c.prevouts):
            if op not in self.utxos or op in spent:
                raise ChainError("missing or spent input")
            amt, spk, conf = self.utxos[op]
            if c.inputs[i] != (amt, spk):
                raise ChainError("input does not match its prevout")
            q = c.sequences[i]
            if c.version >= 2 and not q & (1 << 31):
                if q & (1 << 22):
                    raise ChainError("time-based relative locks not modelled")
                if h - conf < q & 0xffff:
                    raise ChainError("BIP-68 relative lock not met")
        if c.locktime and any(q != 0xffffffff for q in c.sequences):
            if c.locktime < lc.S:
                if not c.locktime < h:
                    raise ChainError("nLockTime height not reached")
            elif not c.locktime < MTP:
                raise ChainError("nLockTime time not reached")
        if sum(a for a, _ in c.outputs) > sum(a for a, _ in c.inputs):
            raise ChainError("outputs exceed inputs")
        for i, w in enumerate(tx.witnesses):
            spk = c.inputs[i][1]
            if w is None:
                if spk != P2WPKH:
                    raise ChainError("unmodelled witness for a non-fee input")
                continue
            stack, script, control = w
            ver = lc.verify_control_block(spk, script, control)
            if ver is None:
                raise ChainError("control block does not commit the script")
            c.input_index = i
            c.tapleaf_hash = lt.tapleaf_hash(script, ver)
            Interp(c, mode="c2" if ver == 0xC2 else "c0").run(script, list(stack))

    def mine(self, *txs):
        """Mine txs in the next block; all or nothing. Returns their txids."""
        h, spent = self.height + 1, set()
        for tx in txs:
            self.validate(tx, h, spent)
            spent |= set(tx.ctx.prevouts)
        self.height = h
        ids = []
        for tx in txs:
            for op in tx.ctx.prevouts:
                del self.utxos[op]
            tid = tx.txid()
            for k, (amt, spk) in enumerate(tx.ctx.outputs):
                self.utxos[(tid, k)] = (amt, spk, h)
            ids.append(tid)
        return ids

    def fork(self):
        return copy.deepcopy(self)


# --------------------------------------------------------- tree fixture --
def path_witness(path):
    """Dense sibling path, leaf level first (spec 8.2)."""
    items = []
    for d, sib in reversed(path):
        items += [b"\x01" if d else b"", sib[0] + lt.enc64(sib[1])]
    return items


class TreeHost:
    """A FULL dense tree hosting channel leaves (C.6): EXIT_1 is the exact
    payout variant EXIT_1^= (C.6.1) and CLAIM^h is present for 9.6.2."""

    def __init__(self, chain, depth=4):
        self.chain, self.depth = chain, depth
        self.op_sk = sk("operator")
        self.op_pk = pubkey_x(self.op_sk)
        self.tree_id = TREE_ID
        scripts = ls.all_scripts(depth, self.op_pk, (0,), (1,), "D", tree_id=self.tree_id)
        scripts["EXIT_1"] = ls.exit_script(depth, 1, "D", exact=True)
        scripts["CLAIM_H"] = ls.claim_script(depth, self.tree_id, "D", hashlock=True)
        self.names = list(scripts)
        self.compiled = [assemble(s) for s in scripts.values()]
        self.m = lt.taptree_root([lt.tapleaf_hash(s) for s in self.compiled])
        self.tree = lt.Tree(depth)
        self.outpoint = None

    def spk(self, root=None):
        root = root or self.tree.root()
        return lt.tree_spk(root[0], self.m)

    def publish(self):
        """Fund the tree output for the current tree (its creation is out of scope)."""
        root = self.tree.root()
        self.outpoint = self.chain.fund(root[1], self.spk(root))

    def leaf_spend(self, name, root_hash):
        out = lc.TapOutput(lt.internal_key(root_hash)[1:], self.compiled)
        assert out.spk == lt.tree_spk(root_hash, self.m)
        i = self.names.index(name)
        return self.compiled[i], out.control_block(i)

    def transition(self, name, new_tree, outputs, stack_fn, fee=600, locktime=0):
        """Build and sign a transition spending the tree output; stack_fn(ctx)
        returns the witness stack once the sighash is fixed."""
        root = self.tree.root()
        fee_op = self.chain.fund(fee, P2WPKH)
        script, control = self.leaf_spend(name, root[0])
        ctx = self.chain.ctx([self.outpoint, fee_op], outputs, locktime=locktime)
        ctx.input_index, ctx.tapleaf_hash = 0, lt.tapleaf_hash(script)
        tx = Tx(ctx, [(stack_fn(ctx, root), script, control), None])
        return tx

    def commit(self, tx, new_tree):
        """After tx is mined: the tree output is output 0."""
        self.tree = new_tree
        self.outpoint = (tx.txid(), 0)

    def exit_tx(self, slot, evict=False, locktime=0):
        """EXIT_1^= of the leaf at slot: output 1 pays leaf.amount exactly."""
        leaf = self.tree.leaves[slot]
        path = self.tree.path(slot)
        t1 = lt.Tree(self.depth)
        t1.leaves = dict(self.tree.leaves)
        lt.apply_exit(t1, slot)
        r1 = t1.root()
        outputs = [(r1[1], self.spk(r1)), (leaf.amount, lt.p2tr_spk(leaf.exit_key))]
        key = self.op_sk if evict else self.owner_sk[slot]

        def stack(ctx, root):
            sig = schnorr_sign(ctx.sighash(), key)
            return path_witness(path) + [leaf.serialize(), sig, b"\x01" if evict else b"",
                                         root[0], self.m]
        return self.transition("EXIT_1", t1, outputs, stack, locktime=locktime), t1

    def claim_h_tx(self, s_src, s_new, new_leaf, vsig, preimage):
        src = self.tree.leaves[s_src]
        spath = self.tree.path(s_src)
        t1 = lt.Tree(self.depth)
        t1.leaves = dict(self.tree.leaves)
        lt.apply_claim(t1, s_src, s_new, new_leaf)
        cpath = t1.path(s_new)
        r1 = t1.root()

        def stack(ctx, root):
            return (path_witness(cpath) + path_witness(spath) + [src.serialize(), new_leaf.serialize(),
                                                                 vsig, preimage, root[0], self.m])
        return self.transition("CLAIM_H", t1, [(r1[1], self.spk(r1))], stack), t1

    def update_tx(self, slot, new_leaf, owner_key_sk):
        old = self.tree.leaves[slot]
        path = self.tree.path(slot)
        t1 = lt.Tree(self.depth)
        t1.leaves = dict(self.tree.leaves)
        t1.leaves[slot] = new_leaf
        r1 = t1.root()

        def stack(ctx, root):
            h = ctx.sighash()
            return path_witness(path) + [old.serialize(), new_leaf.serialize(),
                                         schnorr_sign(h, owner_key_sk), schnorr_sign(h, self.op_sk),
                                         root[0], self.m]
        return self.transition("UPDATE", t1, [(r1[1], self.spk(r1))], stack), t1


# ------------------------------------------------------ channel fixture --
class Party:
    """The two channel parties, acting jointly as P_chan (C.11 [C-A4])."""

    def __init__(self, ch, p_sk):
        self.ch, self.p_sk = ch, p_sk
        self.states = {}      # n -> (update template, upd_sig, settle template, set_sig)

    def sign_state(self, n, outputs):
        """C.3.6: settle_n is signed first, then update_n."""
        ch = self.ch
        st = ch.settle_tx(n, outputs)
        set_sig = schnorr_sign(lc.msg_set(ch.ctx_set, st), self.p_sk)
        ut = ch.update_tx(n)
        upd_sig = schnorr_sign(lc.msg_upd(ch.ctx_upd, ut), self.p_sk)
        self.states[n] = (ut, upd_sig, st, set_sig)
        return self.states[n]

    def update(self, chain, n, prevout, rebind_from=None, sig=None):
        """update_n bound to the funding output, or to U_j if rebind_from=j."""
        ut, upd_sig, _, _ = self.states[n]
        ctx = chain.bind(ut, [prevout])
        if rebind_from is None:
            script, control = self.ch.funding.scripts[0], self.ch.funding.control_block(0)
        else:
            u = self.ch.update_output(rebind_from)
            script, control = u.scripts[0], u.control_block(0)
        return Tx(ctx, [([sig or upd_sig], script, control)])

    def settle(self, chain, n, prevout, at_state=None, sig=None, template=None):
        """settle_n bound to U_{at_state} (default n)."""
        _, _, st, set_sig = self.states[n]
        u = self.ch.update_output(n if at_state is None else at_state)
        ctx = chain.bind(template or st, [prevout])
        return Tx(ctx, [([sig or set_sig], u.scripts[1], u.control_block(1))])


def htlc_sweep(chain, op, htlc, success, key_sk, dest, preimage=None, locktime=0, fee=500):
    amt = chain.utxos[op][0]
    ctx = chain.ctx([op], [(amt - fee, lt.p2tr_spk(dest))], locktime=locktime)
    i = 0 if success else 1
    ctx.input_index, ctx.tapleaf_hash = 0, lt.tapleaf_hash(htlc.scripts[i], lc.leaf_version(htlc.mode))
    sig = schnorr_sign(ctx.sighash(), key_sk)
    stack = [sig, preimage] if success else [sig]
    return Tx(ctx, [(stack, htlc.scripts[i], htlc.control_block(i))])


def chan_leaf(host, ch, owner_label, evict_after=0):
    """The channel leaf of C.1.1: amount C, exit_key the funding key,
    evictor the operator, seq the non-claimable marker (C.6.5)."""
    return lt.Leaf(ch.capacity, ch.exit_key, pubkey_x(sk(owner_label)), host.op_pk,
                   evict_after, ch.nonce, 0xFFFFFFFF)


def opcodes(toks):
    return {t for t in toks if isinstance(t, str)}


# ---------------------------------------------------------------- tests --
SIZES = {}


def test_state_machine(mode, verbose=True):
    chain = Chain(800_000)
    host = TreeHost(chain)
    csv = 144
    C = 1_000_000
    owner_label = "alice-owner"
    p_sk = sk("P_chan")
    p_chan = pubkey_x(p_sk)
    ch = lc.Channel(host.m, pubkey_x(sk(owner_label)), 7, p_chan, C, 0, csv, mode)
    party = Party(ch, p_sk)

    # Script inventory (C.7) and constants (C.2.2).
    for name, toks in (("UPD_F", lc.upd_f_script(ch.ctx_upd, p_chan)),
                       ("REBIND_n", lc.rebind_script(5, ch.ctx_upd, p_chan)),
                       ("SETTLE_n", lc.settle_script(csv, ch.ctx_set, p_chan))):
        bad = opcodes(toks) - CHAN_OPCODES
        check(not bad, f"{name} uses opcodes outside C.7's list: {sorted(bad)}")
        check(ch.ctx_upd in toks or ch.ctx_set in toks, f"{name} carries its context as a constant")
    check(ch.ctx_upd != ch.ctx_set, "ctx_upd and ctx_set differ (C.2.2)")
    check(lc.upd_f_script(ch.ctx_upd, p_chan) == lc.rebind_script(0, ch.ctx_upd, p_chan),
          "UPD_F is REBIND_0")
    check(len(ch.funding.scripts[0]) == 81, f"UPD_F is 81 bytes, got {len(ch.funding.scripts[0])}")

    # The tree: the channel leaf and an operator leaf (voucher source in 9.6.2).
    s_chan, s_op = 5, 12
    leaf = chan_leaf(host, ch, owner_label)
    op_leaf = lt.Leaf(2_000_000, pubkey_x(sk("op-exit")), pubkey_x(sk("operator-owner")),
                      host.op_pk, 0, 99, 0)
    host.tree.leaves = {s_chan: leaf, s_op: op_leaf}
    host.owner_sk = {s_chan: sk(owner_label)}
    host.publish()

    # C.5.1: states are signed before the leaf exists. States 1..5.
    uk, vk = pubkey_x(sk("U-payout")), pubkey_x(sk("V-payout"))
    pre1, pre2 = lt.sha256(b"htlc-1"), lt.sha256(b"htlc-2")
    x_claim, y_claim = sk("U-claim"), sk("V-claim")
    E1, E2 = 800_400, 800_500
    agg = pubkey_x(sk("htlc-agg"))
    # h1: U offers to V (V claims with pre1); h2: V offers to U (V reclaims after E2).
    h1 = lc.htlc_output(agg, lt.sha256(pre1), E1, pubkey_x(x_claim), pubkey_x(y_claim), mode)
    h2 = lc.htlc_output(agg, lt.sha256(pre2), E2, pubkey_x(y_claim), pubkey_x(x_claim), mode)
    balances = {1: (C, 0), 2: (900_000, 100_000), 3: (800_000, 200_000), 4: (700_000, 300_000)}
    for n, (bu, bv) in balances.items():
        party.sign_state(n, ch.settle_outputs(bu, bv, uk, vk))
    party.sign_state(5, ch.settle_outputs(600_000, 300_000, uk, vk, [(60_000, h1), (40_000, h2)]))
    n_last = 5

    # ---------------- open: the leaf exits to its funding output ----------------
    base = chain.fork()
    base_host = copy.copy(host)
    xtx, t1 = host.exit_tx(s_chan)
    chain.mine(xtx)
    host.commit(xtx, t1)
    fund_op = (xtx.txid(), 1)
    check(chain.utxos[fund_op][:2] == (C, lt.p2tr_spk(ch.exit_key)),
          "owner EXIT_1^= creates P2TR(exit_key) carrying exactly C")
    check(ch.funding.spk == lt.p2tr_spk(ch.exit_key), "exit_key commits UPD_F (C.3.2)")

    # Requirement R: the same update signature binds to a funding output it
    # could not have known. A different history: the operator evicts the leaf
    # 50 blocks later, so the funding outpoint has a different txid.
    alt = base.fork()
    alt_host = TreeHost(alt)
    alt_host.tree.leaves = dict(base_host.tree.leaves)
    alt_host.owner_sk = host.owner_sk
    alt_host.outpoint = base_host.outpoint
    alt.advance(50)
    etx, _ = alt_host.exit_tx(s_chan, evict=True, locktime=alt.height)
    alt.mine(etx)
    alt_fund = (etx.txid(), 1)
    check(alt_fund != fund_op and alt.utxos[alt_fund][1] == chain.utxos[fund_op][1],
          "eviction materialises the same funding script at a different outpoint")
    alt.mine(party.update(alt, n_last, alt_fund))
    check(True, "update_n signed before either exit binds to the evicted funding output")

    # C.6.1: a funding output short of C cannot carry any state.
    short = chain.fork()
    short_op = short.fund(C - 500, ch.funding.spk)
    short.advance(1)
    expect_fail(lambda: short.mine(party.update(short, n_last, short_op)),
                "update_n against a funding output below C (C.6.1)")

    # ---------------- uncontested close ----------------
    a = chain.fork()
    utx = party.update(a, n_last, fund_op)
    SIZES[(mode, "update_n (funding)")] = utx.vsize()
    a.mine(utx)
    u_op = (utx.txid(), 0)
    u_conf = a.height
    check(a.utxos[u_op][:2] == (C, ch.update_output(n_last).spk), "update_n creates U_n carrying C")
    check(a.utxos[(utx.txid(), 1)][:2] == (0, lc.P2A_SPK), "update_n carries a 0-value P2A anchor")
    stx = party.settle(a, n_last, u_op)
    SIZES[(mode, "settle_n (2 HTLCs)")] = stx.vsize()
    a.advance(csv - 2)
    expect_fail(lambda: a.mine(stx), "settle_n one block before csv_delay (BIP-68)")
    a.advance(1)
    check(a.height + 1 - u_conf == csv, "the next block is the csv_delay-th")
    # tampered settlement: move value from V to U under V's signature
    bad_out = list(stx.ctx.outputs)
    bad_out[0], bad_out[1] = (bad_out[0][0] + 1, bad_out[0][1]), (bad_out[1][0] - 1, bad_out[1][1])
    tampered = TxContext(stx.ctx.inputs, bad_out, 0, version=3, sequences=[csv])
    expect_fail(lambda: a.mine(party.settle(a, n_last, u_op, template=tampered)),
                "settle_n with altered balances")
    # nSequence below csv_delay fails in script even when signed honestly
    early = TxContext(stx.ctx.inputs, stx.ctx.outputs, 0, version=3, sequences=[csv - 1])
    early_sig = schnorr_sign(lc.msg_set(ch.ctx_set, early), p_sk)
    expect_fail(lambda: a.mine(party.settle(a, n_last, u_op, template=early, sig=early_sig)),
                "settle_n with nSequence < csv_delay (CSV)")
    stx_ids = a.mine(stx)
    check(True, "settle_n confirms csv_delay blocks after update_n")
    sid = stx_ids[0]
    check(a.utxos[(sid, 2)][1] == h1.spk and a.utxos[(sid, 3)][1] == h2.spk,
          "settlement outputs 2 and 3 are the HTLC outputs")
    # HTLC sweeps (C.4.1/C.4.2): ordinary signatures at spend time.
    wrong = htlc_sweep(a, (sid, 2), h1, True, y_claim, pubkey_x(y_claim), lt.sha256(b"no"))
    expect_fail(lambda: a.mine(wrong), "HTLC success with the wrong preimage")
    succ = htlc_sweep(a, (sid, 2), h1, True, y_claim, pubkey_x(y_claim), pre1)
    SIZES[(mode, "HTLC-success sweep")] = succ.vsize()
    a.mine(succ)
    check(True, "HTLC success sweep with the preimage")
    a.height = E2 - 1
    tmo = htlc_sweep(a, (sid, 3), h2, False, y_claim, pubkey_x(y_claim), locktime=E2)
    SIZES[(mode, "HTLC-timeout sweep")] = tmo.vsize()
    expect_fail(lambda: a.mine(tmo), "HTLC timeout in block cltv_expiry (nLockTime not final)")
    early_t = htlc_sweep(a, (sid, 3), h2, False, y_claim, pubkey_x(y_claim), locktime=E2 - 1)
    expect_fail(lambda: a.mine(early_t), "HTLC timeout with nLockTime < cltv_expiry (CLTV)")
    a.advance(1)
    a.mine(tmo)
    check(True, "HTLC timeout sweep in block cltv_expiry + 1")

    # ---------------- contested close ----------------
    b = chain.fork()
    j = 2
    stale = party.update(b, j, fund_op)
    b.mine(stale)
    uj = (stale.txid(), 0)
    uj_conf = b.height
    stale_settle = party.settle(b, j, uj)
    b.advance(csv - 2)
    expect_fail(lambda: b.mine(stale_settle), "stale settle_j inside the dispute window")
    # the answer: update_n bound to U_j, at the last block of the window
    ans = party.update(b, n_last, uj, rebind_from=j)
    SIZES[(mode, "update_n (rebind)")] = ans.vsize()
    b.mine(ans)
    check(b.height - uj_conf == csv - 1, "update_n answers in the last block of U_j's window")
    un = (ans.txid(), 0)
    expect_fail(lambda: b.mine(party.settle(b, j, uj)), "settle_j after U_j was rebound")
    expect_fail(lambda: b.mine(party.update(b, 3, un, rebind_from=n_last)), "update_j (j < n) against U_n")
    expect_fail(lambda: b.mine(party.update(b, n_last, un, rebind_from=n_last)),
                "update_n against its own output U_n")
    settle_n = party.settle(b, n_last, un)
    # the next block is the one in which settle_j would have matured
    check(b.height + 1 - uj_conf == csv, "U_j's csv_delay elapses in the next block")
    expect_fail(lambda: b.mine(settle_n), "settle_n before csv_delay restarted at U_n")
    b.advance(csv - 2)
    expect_fail(lambda: b.mine(settle_n), "settle_n one block before the restarted delay")
    b.advance(1)
    expect_fail(lambda: b.mine(party.settle(b, j, un, at_state=n_last)),
                "settle_j attached to U_n (SEL_CHAN_SET commits the spent script)")
    b.mine(settle_n)
    check(True, "settle_n after the restarted csv_delay")

    # ---------------- negatives on the funding output ----------------
    c = chain.fork()
    ut = party.states[n_last][0]
    # cross-role: an update signature where a settlement signature is required
    upd_sig = party.states[n_last][1]
    c1 = c.fork()
    c1.mine(party.update(c1, n_last, fund_op))
    un_c = next(op for op, v in c1.utxos.items() if v[1] == ch.update_output(n_last).spk)
    c1.advance(csv)
    st_tmpl = party.states[n_last][2]
    expect_fail(lambda: c1.mine(party.settle(c1, n_last, un_c, sig=upd_sig)),
                "update_n's signature as a settlement witness")
    x_sig = schnorr_sign(lt.sha256(ch.ctx_upd + lc.collate(st_tmpl, lc.SEL_CHAN_SET)), p_sk)
    expect_fail(lambda: c1.mine(party.settle(c1, n_last, un_c, sig=x_sig)),
                "settlement collation signed under ctx_upd")
    # and the reverse
    set_sig = party.states[n_last][3]
    expect_fail(lambda: c.mine(party.update(c, n_last, fund_op, sig=set_sig)),
                "settle_n's signature as an update witness")
    y_sig = schnorr_sign(lt.sha256(ch.ctx_set + lc.collate(ut, lc.SEL_CHAN_UPD)), p_sk)
    expect_fail(lambda: c.mine(party.update(c, n_last, fund_op, sig=y_sig)),
                "update collation signed under ctx_set")
    # a state signed for a different chan_id
    for label, other in (("m", lc.Channel(lt.sha256(b"other tree"), ch.owner_key, 7, p_chan, C, 0, csv, mode)),
                         ("capacity", lc.Channel(host.m, ch.owner_key, 7, p_chan, C + 1, 0, csv, mode)),
                         ("epoch", lc.Channel(host.m, ch.owner_key, 7, p_chan, C, 1, csv, mode)),
                         ("nonce", lc.Channel(host.m, ch.owner_key, 8, p_chan, C, 0, csv, mode)),
                         ("owner_key", lc.Channel(host.m, pubkey_x(sk("other-owner")), 7, p_chan, C, 0, csv, mode)),
                         ("csv_delay", lc.Channel(host.m, ch.owner_key, 7, p_chan, C, 0, csv + 1, mode))):
        check(other.chan_id != ch.chan_id, f"chan_id commits {label}")
        osig = schnorr_sign(lc.msg_upd(other.ctx_upd, ut), p_sk)
        expect_fail(lambda: c.mine(party.update(c, n_last, fund_op, sig=osig)),
                    f"update signed for a chan_id with another {label}")
        oset = schnorr_sign(lc.msg_set(other.ctx_set, st_tmpl), p_sk)
        expect_fail(lambda: c1.mine(party.settle(c1, n_last, un_c, sig=oset)),
                    f"settlement signed for a chan_id with another {label}")
    # tampered update fields
    for label, tmpl in (("nLockTime", TxContext(ut.inputs, ut.outputs, lc.S + n_last + 10, version=3,
                                                 sequences=[lc.UPDATE_SEQUENCE])),
                        ("nVersion", TxContext(ut.inputs, ut.outputs, ut.locktime, version=2,
                                               sequences=[lc.UPDATE_SEQUENCE])),
                        ("output", TxContext(ut.inputs, [ut.outputs[0], (0, P2WPKH)], ut.locktime,
                                             version=3, sequences=[lc.UPDATE_SEQUENCE]))):
        tx = party.update(c, n_last, fund_op)
        tx.ctx = c.bind(tmpl, [fund_op])
        expect_fail(lambda: c.mine(tx), f"update_n with a changed {label}")
    # C.3.5: an update signed with a height-range lock time fails CLTV
    hl = TxContext(ut.inputs, ut.outputs, 5, version=3, sequences=[lc.UPDATE_SEQUENCE])
    hsig = schnorr_sign(lc.msg_upd(ch.ctx_upd, hl), p_sk)
    htx = Tx(c.bind(hl, [fund_op]), [([hsig], ch.funding.scripts[0], ch.funding.control_block(0))])
    expect_fail(lambda: c.mine(htx), "update with a height-range nLockTime (C.3.5)")
    # settle_n cannot skip the update: SETTLE is not a leaf of T_fund
    c.advance(csv)
    u = ch.update_output(n_last)
    skip = Tx(c.bind(st_tmpl, [fund_op]), [([set_sig], u.scripts[1], ch.funding.control_block(0))])
    expect_fail(lambda: c.mine(skip), "settle_n spending the funding output directly")
    skip2 = Tx(c.bind(st_tmpl, [fund_op]), [([set_sig], u.scripts[1], u.control_block(1))])
    expect_fail(lambda: c.mine(skip2), "settle_n with U_n's control block on the funding output")
    # C.2.3: two outputs with the same channel script, one transaction
    c2 = c.fork()
    twin = c2.fund(C, ch.funding.spk)
    c2.advance(1)
    two = c2.ctx([fund_op, twin], list(ut.outputs), ut.locktime,
                 [lc.UPDATE_SEQUENCE] * 2, version=3)
    w = ([upd_sig], ch.funding.scripts[0], ch.funding.control_block(0))
    expect_fail(lambda: c2.mine(Tx(two, [w, w])), "update_n spending two funding outputs (NUM_INPUTS)")
    check(c2.mine(party.update(c2, n_last, twin)) is not None,
          "the same signature still binds to either twin alone")

    if verbose:
        lv = "0xC2" if mode == "c2" else "0xC0"
        print(f"channel state machine, tapleaf {lv}: open, uncontested, contested, negatives")
    return ch


def dust_threshold(spk):
    """Bitcoin Core's dust threshold at the default dust relay fee of 3
    sat/vB: 330 sat for a P2TR output and 240 sat for a P2A anchor, the two
    output kinds a settlement carries."""
    return {lc.P2A_SPK: lc.DUST_P2A}.get(spk, lc.DUST_CHAN)


def count_dust(outs):
    return sum(1 for amt, spk in outs if amt < dust_threshold(spk))


def test_dust_floor():
    """C.3.4: a settlement is zero-fee with an ephemeral anchor, so relay
    policy admits at most one dust output and it must be the anchor. Every
    balance or HTLC below DUST_CHAN is omitted and its value goes to the
    anchor, never to fees."""
    p_chan = pubkey_x(sk("P_chan"))
    uk, vk = pubkey_x(sk("U-payout")), pubkey_x(sk("V-payout"))
    C = 1_000_000
    ch = lc.Channel(lt.sha256(b"m"), pubkey_x(sk("o")), 1, p_chan, C, 0, 144)
    htlc = lc.htlc_output(pubkey_x(sk("agg")), lt.sha256(b"x"), 900_000, uk, vk)
    cases = (("b_V = 0", C, 0, []),
             ("b_V = 329", C - 329, 329, []),
             ("200-sat HTLC", C - 200, 0, [(200, htlc)]),
             ("329-sat HTLC beside a 329-sat balance", C - 658, 329, [(329, htlc)]))
    for label, bu, bv, htlcs in cases:
        outs = ch.settle_outputs(bu, bv, uk, vk, htlcs)
        trimmed = sum(a for a in (bu, bv) + tuple(a for a, _ in htlcs) if a < lc.DUST_CHAN)
        check(sum(a for a, _ in outs) == C, f"{label}: the trimmed settlement still pays C")
        check(outs[-1] == (trimmed, lc.P2A_SPK), f"{label}: the anchor carries the trimmed value")
        check(all(a >= lc.DUST_CHAN for a, _ in outs[:-1]),
              f"{label}: every non-anchor output is at least DUST_CHAN")
        check(count_dust(outs) <= 1, f"{label}: at most one dust output, the anchor")
        # What the audit measured: the same split with nothing trimmed has
        # two dust outputs and no default node relays it.
        untrimmed = [(bu, lt.p2tr_spk(uk)), (bv, lt.p2tr_spk(vk))] + \
            [(a, h.spk) for a, h in htlcs] + [(0, lc.P2A_SPK)]
        check(count_dust(untrimmed) >= 2, f"{label}: untrimmed, the settlement has two dust outputs")
    full = ch.settle_outputs(600_000, 340_000, uk, vk, [(60_000, htlc)])
    check(len(full) == 4 and full[-1] == (0, lc.P2A_SPK),
          "nothing trimmed: the anchor is the 0-value ephemeral output")
    # A channel parameter, not part of chan_id, and never below the P2TR
    # threshold.
    ch2 = lc.Channel(lt.sha256(b"m"), pubkey_x(sk("o")), 1, p_chan, C, 0, 144, dust_chan=546)
    check(ch2.chan_id == ch.chan_id, "dust_chan is not committed by chan_id")
    check(ch2.settle_outputs(C - 500, 500, uk, vk)[-1] == (500, lc.P2A_SPK),
          "a higher dust_chan trims a 500-sat balance into the anchor")
    try:
        lc.Channel(lt.sha256(b"m"), pubkey_x(sk("o")), 1, p_chan, C, 0, 144, dust_chan=329)
        check(False, "dust_chan below the P2TR threshold refused")
    except AssertionError:
        check(True, "dust_chan below the P2TR threshold refused")
    print("settlement dust floor: sub-dust balances and HTLCs trimmed into the anchor")


def test_mid_collation_limit():
    """C.7, measured: under tapleaf 0xC0 every stack element, including the
    OP_TX collation and ctx || collation after OP_CAT, is limited to 520
    bytes. A settlement collation is 156 + 43h bytes for two P2TR payouts,
    h P2TR HTLC outputs and the anchor, so ctx_set || collation fits for
    h <= 7 and not for h = 8. FULL has no such limit."""
    p_sk = sk("P_chan")
    p_chan = pubkey_x(p_sk)
    uk, vk = pubkey_x(sk("U-payout")), pubkey_x(sk("V-payout"))
    agg = pubkey_x(sk("htlc-agg"))
    limits = {}
    for mode in ("c2", "c0"):
        ch = lc.Channel(lt.sha256(b"m"), pubkey_x(sk("o")), 1, p_chan, 10_000_000, 0, 144, mode)
        ok_max = None
        for h in (7, 8, 30):
            htlcs = [(1_000, lc.htlc_output(agg, lt.sha256(b"%d" % i), 900_000, uk, vk, mode))
                     for i in range(h)]
            outs = ch.settle_outputs(10_000_000 - 1_000 * h - 1_000, 1_000, uk, vk, htlcs)
            st = ch.settle_tx(1, outs)
            blob = lc.collate(st, lc.SEL_CHAN_SET)
            check(len(blob) == 156 + 43 * h, f"settlement collation is 156 + 43h bytes (h={h})")
            sig = schnorr_sign(lc.msg_set(ch.ctx_set, st), p_sk)
            u = ch.update_output(1)
            try:
                Interp(st, mode=mode).run(u.scripts[1], [sig])
                ok_max = h
                ok = True
            except ScriptError:
                ok = False
            want = mode == "c2" or h <= 7
            check(ok == want, f"tapleaf {mode}: settlement with {h} HTLC outputs "
                              f"{'verifies' if want else 'exceeds 520 bytes'}")
        limits[mode] = ok_max
    print(f"settlement collation: 0xC0 verifies up to 7 HTLC outputs; 0xC2 verified {limits['c2']}")


def test_deadlines(verbose=True):
    """C.4.4 and 9.6.2 as block sequences.

    The operator V (voucher issuer, HTLC payee) draws the preimage (9.6.2
    rule 1) and issues a hash-locked voucher to the channel owner U, who
    offers V a channel HTLC for the same hash. U then stops responding, so
    V must force-close: evict, update, settle, sweep. V's on-chain sweep
    reveals the preimage, and U redeems the voucher second (rule 2).
    """
    csv, g_exit, g_sweep = 144, 72, 2
    exact = lc.cltv_budget_exact(g_exit, csv, g_sweep)
    spec = lc.cltv_budget_spec(g_exit, csv, g_sweep)
    check(spec == exact + 2, "the C.4.4 bound has two blocks of margin over the exact count")

    def scenario(delta, rule_2_violation=False, advance_seq=False, stale=0):
        chain = Chain(800_000)
        host = TreeHost(chain)
        p_sk = sk("P_chan")
        C = 1_000_000
        ch = lc.Channel(host.m, pubkey_x(sk("alice-owner")), 7, pubkey_x(p_sk), C, 0, csv)
        party = Party(ch, p_sk)
        s_chan, s_op = 5, 12
        op_leaf = lt.Leaf(2_000_000, pubkey_x(sk("op-exit")), pubkey_x(sk("operator-owner")),
                          host.op_pk, 0, 99, 0)
        host.tree.leaves = {s_chan: chan_leaf(host, ch, "alice-owner"), s_op: op_leaf}
        host.owner_sk = {s_chan: sk("alice-owner")}
        host.publish()
        # rule 1: the HTLC payee (V) generates the preimage; in the violation
        # the voucher holder (U) generates it and V waits on U's redemption
        preimage = lt.sha256(b"swap-R")
        ph = lt.sha256(preimage)
        bought = lt.Leaf(40_000, pubkey_x(sk("bought-exit")), pubkey_x(sk("bought-owner")),
                         host.op_pk, 0, 3, 0)
        s_bought = 9
        vsig = schnorr_sign(lt.voucher_h_msg(host.tree_id, op_leaf, bought, ph), sk("operator-owner"))
        t = chain.height
        E = t + delta
        u_claim, v_claim = sk("U-claim"), sk("V-claim")
        htlc = lc.htlc_output(pubkey_x(sk("agg")), ph, E, pubkey_x(u_claim), pubkey_x(v_claim))
        # stale states 1..stale are balance-only; the honest state n carries
        # the HTLC (C.4.4, beta_chan).
        n = stale + 1
        for j in range(1, n):
            party.sign_state(j, ch.settle_outputs(C - 10_000 * j, 10_000 * j,
                                                  pubkey_x(sk("U")), pubkey_x(sk("V"))))
        party.sign_state(n, ch.settle_outputs(C - 50_000, 0, pubkey_x(sk("U")), pubkey_x(sk("V")),
                                              [(50_000, htlc)]))
        log = {}
        # V evicts at tip t; contention delays confirmation by g_exit blocks
        etx, t1 = host.exit_tx(s_chan, evict=True, locktime=t)
        chain.advance(g_exit - 1)
        chain.mine(etx)
        host.commit(etx, t1)
        log["exit"] = chain.height
        # the counterparty confirms its stale updates one per block, each
        # bound to the previous one's output; the honest update_n lands on
        # the last of them (TRUC admits one unconfirmed ancestor, so the
        # rounds serialise)
        prev, prev_state = (etx.txid(), 1), None
        for j in range(1, n):
            stale_tx = party.update(chain, j, prev, rebind_from=prev_state)
            chain.mine(stale_tx)
            prev, prev_state = (stale_tx.txid(), 0), j
        utx = party.update(chain, n, prev, rebind_from=prev_state)
        chain.mine(utx)
        log["update"] = chain.height
        chain.advance(csv - 1)
        stx = party.settle(chain, n, (utx.txid(), 0))
        chain.mine(stx)
        log["settle"] = chain.height
        h_op = next(op for op, v in chain.utxos.items() if v[1] == htlc.spk)
        chain.advance(g_sweep - 1)
        tmo = htlc_sweep(chain, h_op, htlc, False, u_claim, pubkey_x(u_claim), locktime=E)
        succ = htlc_sweep(chain, h_op, htlc, True, v_claim, pubkey_x(v_claim), preimage)
        if rule_2_violation:
            # V cannot sweep: it has no preimage. U waits out the HTLC, takes
            # the refund, then redeems the voucher with its own preimage.
            chain.height = max(chain.height, E)
            chain.mine(tmo)
            log["timeout"] = chain.height
            ctx_tx, t2 = host.claim_h_tx(s_op, s_bought, bought, vsig, preimage)
            chain.mine(ctx_tx)
            host.commit(ctx_tx, t2)
            log["claim_h"] = chain.height
            log["leaked"] = ctx_tx.witnesses[0][0][-3] == preimage
            return log, E, chain, (lambda: chain.mine(succ))
        if chain.height + 1 > E:
            # deadline missed: U's refund is final before V's claim can land
            ok = True
            try:
                chain.fork().mine(tmo)
            except ScriptError:
                ok = False
            log["timeout_valid_at"] = chain.height + 1 if ok else None
            chain.mine(tmo)
            return log, E, chain, (lambda: chain.mine(succ))
        try:
            chain.fork().mine(tmo)
            log["timeout_competes"] = True
        except ScriptError:
            log["timeout_competes"] = False
        chain.mine(succ)
        log["sweep"] = chain.height
        revealed = succ.witnesses[0][0][1]
        if advance_seq:
            # rule 3 violated: V advances its leaf's seq before U redeems
            utx2, t3 = host.update_tx(s_op, op_leaf.with_amount_seq(op_leaf.amount, 1),
                                      sk("operator-owner"))
            chain.mine(utx2)
            host.commit(utx2, t3)
        ctx_tx, t2 = host.claim_h_tx(s_op, s_bought, bought, vsig, revealed)
        return log, E, chain, (lambda: (chain.mine(ctx_tx), host.commit(ctx_tx, t2)))

    for label, delta in (("C.4.4 bound", spec), ("exact budget", exact)):
        log, E, chain, redeem = scenario(delta)
        check(log["sweep"] == 800_000 + exact, f"{label}: payee's sweep lands at t + exact budget")
        check(log["sweep"] <= E and not log["timeout_competes"],
              f"{label}: the offerer's timeout is not final while the payee sweeps")
        redeem()
        check(True, f"{label}: the voucher redeems second with the preimage from the sweep (9.6.2)")
        if verbose:
            print(f"deadline [{label}] delta={delta}: exit {log['exit']}, update {log['update']}, "
                  f"settle {log['settle']}, sweep {log['sweep']} <= cltv_expiry {E}")

    log, E, chain, late_claim = scenario(exact - 1)
    check(log["timeout_valid_at"] == E + 1, "budget - 1: the offerer's timeout is final at cltv_expiry + 1")
    expect_fail(late_claim, "budget - 1: the payee's success sweep after the refund (C.4.4 violated)")

    log, E, chain, late_claim = scenario(exact, rule_2_violation=True)
    expect_fail(late_claim, "9.6.2 rule 2 violated: the HTLC waits on the voucher and expires")
    check(log["claim_h"] > E and log["leaked"],
          "the voucher redeemed after the refund, publishing the preimage too late")

    log, E, chain, redeem = scenario(exact, advance_seq=True)
    expect_fail(redeem, "9.6.2 rule 3 violated: the issuer advanced seq, the paid-for voucher is void")

    # C.4.4 beta_chan: each stale update confirmed ahead of the honest one
    # costs a block; the two blocks of margin absorb two and not three.
    log, E, chain, redeem = scenario(spec, stale=2)
    check(log["update"] == log["exit"] + 3, "two stale updates ahead: the honest update lands three blocks after the exit")
    check(log["sweep"] == E and not log["timeout_competes"],
          "C.4.4 bound, beta_chan = 2: the margin absorbs the stale updates, the sweep lands in block cltv_expiry")
    redeem()
    check(True, "C.4.4 bound, beta_chan = 2: the voucher still redeems second")
    log, E, chain, late_claim = scenario(spec, stale=3)
    check(log["timeout_valid_at"] == E + 1,
          "C.4.4 bound, beta_chan = 3: the offerer's refund is final before the payee can sweep")
    expect_fail(late_claim, "C.4.4 bound, beta_chan = 3: the payee's success sweep after the refund")
    bound3 = lc.cltv_budget_spec(g_exit, csv, g_sweep, beta_chan=3)
    check(bound3 == spec + 3, "the bound grows by one block per stale update counted")
    log, E, chain, redeem = scenario(bound3, stale=3)
    check(log["sweep"] <= E and not log["timeout_competes"],
          "the bound with beta_chan = 3 holds against three stale updates")
    redeem()
    check(True, "beta_chan = 3 bound: the voucher redeems second")
    if verbose:
        print(f"C.4.4: exact budget {exact} blocks, spec bound {spec} "
              f"(g_exit={g_exit}, csv={csv}, g_sweep={g_sweep})")


def fork_host(host):
    """A copy of the host on a fork of its chain: same scripts, same keys, its
    own tree and UTXO set."""
    h = copy.copy(host)
    h.chain = host.chain.fork()
    h.tree = copy.deepcopy(host.tree)
    return h


def test_lease_and_evictor():
    """C.6.4 and C.6.3: a channel leaf with evict_after in the future gives the
    counterparty no unilateral path until the lease passes, and a NUMS
    evictor gives it none at all; the owner can exit either leaf at any
    time, and the states signed before the exit bind afterwards."""
    chain = Chain(800_000)
    host = TreeHost(chain)
    p_sk = sk("P_chan")
    C = 1_000_000
    ch = lc.Channel(host.m, pubkey_x(sk("alice-owner")), 7, pubkey_x(p_sk), C, 0, 144)
    party = Party(ch, p_sk)
    party.sign_state(1, ch.settle_outputs(C, 0, pubkey_x(sk("U")), pubkey_x(sk("V"))))
    lease = chain.height + 100
    s_lease, s_nums = 5, 9
    host.tree.leaves = {s_lease: chan_leaf(host, ch, "alice-owner", evict_after=lease),
                        s_nums: lt.Leaf(C, ch.exit_key, pubkey_x(sk("bob-owner")), lt.NUMS_X, 0, 8,
                                        0xFFFFFFFF)}
    host.owner_sk = {s_lease: sk("alice-owner"), s_nums: sk("bob-owner")}
    host.publish()

    # C.6.4: before evict_after the counterparty cannot evict, whether it
    # sets nLockTime to the tip (CLTV fails) or to the lease (not final).
    f = fork_host(host)
    expect_fail(lambda: f.chain.mine(f.exit_tx(s_lease, evict=True, locktime=f.chain.height)[0]),
                "eviction of a channel leaf before evict_after (C.6.4)")
    expect_fail(lambda: f.chain.mine(f.exit_tx(s_lease, evict=True, locktime=lease)[0]),
                "eviction with nLockTime = evict_after before that height")
    xtx, _ = f.exit_tx(s_lease)
    f.chain.mine(xtx)
    f.chain.mine(party.update(f.chain, 1, (xtx.txid(), 1)))
    check(True, "the owner exits a leased channel leaf at any time and update_1 binds")
    # at the lease the counterparty's force-close is unconditional
    g = fork_host(host)
    g.chain.height = lease
    etx, _ = g.exit_tx(s_lease, evict=True, locktime=lease)
    g.chain.mine(etx)
    g.chain.mine(party.update(g.chain, 1, (etx.txid(), 1)))
    check(True, "at evict_after the counterparty evicts and update_1 binds to the funding output")

    # C.6.3: a NUMS evictor cannot be signed for, so the counterparty has no
    # force-close at all, now or ever.
    h = fork_host(host)
    expect_fail(lambda: h.chain.mine(h.exit_tx(s_nums, evict=True, locktime=h.chain.height)[0]),
                "eviction of a NUMS-evictor channel leaf (C.6.3)")
    h.chain.height = lease + 1_000
    expect_fail(lambda: h.chain.mine(h.exit_tx(s_nums, evict=True, locktime=h.chain.height)[0]),
                "eviction of a NUMS-evictor channel leaf, long after opening")
    xtx, _ = h.exit_tx(s_nums)
    h.chain.mine(xtx)
    check(True, "only the owner can bring a NUMS-evictor channel leaf on-chain")
    print("lease and evictor: no eviction before evict_after, none ever with a NUMS evictor")


def test_epoch_and_renewal(mode):
    """C.6.7 and C.5.2: an UPDATE that renews evict_after leaves every signed
    state bindable, because chan_id omits the lease; an UPDATE that moves the
    leaf to a new epoch's exit_key makes the old epoch's states fail against
    the new funding output and the new epoch's bind."""
    chain = Chain(800_000)
    host = TreeHost(chain)
    p_sk = sk("P_chan")
    C, csv = 1_000_000, 144
    owner = pubkey_x(sk("alice-owner"))
    ch0 = lc.Channel(host.m, owner, 7, pubkey_x(p_sk), C, 0, csv, mode)
    ch1 = lc.Channel(host.m, owner, 7, pubkey_x(p_sk), C, 1, csv, mode)
    check(ch0.chan_id != ch1.chan_id and ch0.exit_key != ch1.exit_key,
          "a new epoch gives the channel a new chan_id and a new exit_key (C.5.2)")
    p0, p1 = Party(ch0, p_sk), Party(ch1, p_sk)
    uk, vk = pubkey_x(sk("U-payout")), pubkey_x(sk("V-payout"))
    p0.sign_state(3, ch0.settle_outputs(700_000, 300_000, uk, vk))
    p1.sign_state(1, ch1.settle_outputs(700_000, 300_000, uk, vk))
    s = 5
    host.tree.leaves = {s: chan_leaf(host, ch0, "alice-owner")}
    host.owner_sk = {s: sk("alice-owner")}
    host.publish()

    # C.6.7: renewal is an UPDATE of evict_after alone.
    leaf = host.tree.leaves[s]
    renewed = lt.Leaf(leaf.amount, leaf.exit_key, leaf.owner_key, leaf.evictor_key,
                      chain.height + 1_000, leaf.nonce, leaf.seq)
    utx, t1 = host.update_tx(s, renewed, sk("alice-owner"))
    chain.mine(utx)
    host.commit(utx, t1)
    f = fork_host(host)
    xtx, _ = f.exit_tx(s)
    f.chain.mine(xtx)
    f.chain.mine(p0.update(f.chain, 3, (xtx.txid(), 1)))
    check(True, "update_n signed before a lease renewal binds to the renewed leaf's funding output (C.6.7)")

    # C.5.2: the splice moves the leaf to epoch 1's exit_key.
    spliced = lt.Leaf(leaf.amount, ch1.exit_key, leaf.owner_key, leaf.evictor_key, 0,
                      leaf.nonce, leaf.seq)
    utx2, t2 = host.update_tx(s, spliced, sk("alice-owner"))
    chain.mine(utx2)
    host.commit(utx2, t2)
    xtx2, t3 = host.exit_tx(s)
    chain.mine(xtx2)
    host.commit(xtx2, t3)
    fund1 = (xtx2.txid(), 1)
    check(chain.utxos[fund1][:2] == (C, lt.p2tr_spk(ch1.exit_key)),
          "the exit after the splice creates the new epoch's funding output")
    expect_fail(lambda: chain.mine(p0.update(chain, 3, fund1)),
                "an old epoch's update_n against the new epoch's funding output (C.5.2, C.9.1)")
    chain.mine(p1.update(chain, 1, fund1))
    check(True, "the new epoch's update_1 binds to the new funding output")
    lv = "0xC2" if mode == "c2" else "0xC0"
    print(f"epochs and renewal, tapleaf {lv}: renewal keeps states, a splice retires them")


def report_sizes():
    """Script and witness sizes (bytes) and transaction vsizes (C.5.4)."""
    p = pubkey_x(sk("P_chan"))
    ch = lc.Channel(lt.sha256(b"m"), pubkey_x(sk("o")), 1, p, 1_000_000, 0, 144)
    rows = []
    for mode in ("c2", "c0"):
        f = lc.TapOutput(p, [lc.upd_f_script(ch.ctx_upd, p)], mode)
        u = lc.TapOutput(p, [lc.rebind_script(5, ch.ctx_upd, p), lc.settle_script(144, ch.ctx_set, p)], mode)
        hh = lc.htlc_output(p, bytes(32), 900_000, p, p, mode)
        for name, out, i, stack in (("UPD_F", f, 0, 64), ("REBIND_n", u, 0, 64), ("SETTLE_n", u, 1, 64),
                                    ("HTLC_SUCCESS", hh, 0, 64 + 32), ("HTLC_TIMEOUT", hh, 1, 64)):
            sc, cb = out.scripts[i], out.control_block(i)
            rows.append((mode, name, len(sc), stack, len(cb)))
    print(f"{'leaf':14} {'tapleaf':7} {'script B':>8} {'stack B':>7} {'control B':>9}")
    for mode, name, s, st, cb in rows:
        print(f"{name:14} {'0x' + mode.upper():7} {s:8} {st:7} {cb:9}")
    for (mode, name), v in sorted(SIZES.items()):
        print(f"{name:22} 0x{mode.upper()} {v:5} vB")
    return rows


if __name__ == "__main__":
    for mode in ("c2", "c0"):
        test_state_machine(mode)
        test_epoch_and_renewal(mode)
    sz = SIZES
    check(sz[("c2", "update_n (funding)")] == 153, "update_n bound to funding is 153 vB (C.5.4)")
    check(sz[("c2", "update_n (rebind)")] == 161, "update_n bound to U_j is 161 vB (C.5.4)")
    check(sz[("c2", "settle_n (2 HTLCs)")] == 204 + 43 * 2, "settle_n with 2 HTLCs is 204 + 43h vB (C.5.4)")
    test_dust_floor()
    test_lease_and_evictor()
    test_mid_collation_limit()
    test_deadlines()
    report_sizes()
    print(f"\n{CHECKS} checks, {FAILS} failures")
    sys.exit(1 if FAILS else 0)
