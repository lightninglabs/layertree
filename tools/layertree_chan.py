#!/usr/bin/env python3
"""Channel-leaf scripts of spec/channel-leaves.md (Appendix C) as generators.

The scripts of C.3 (the funding leaf `UPD_F`, the update output's `REBIND_n`
and `SETTLE_n`) and the transaction templates of C.3.3 and C.3.4, together
with the channel context of C.2.2 and the taproot keys of C.3.2. The HTLC
output leaves of C.4.1 live in `tools/layertree_scripts.py` (spec 13.9
composes them with `CLAIM^h`) and are imported from there.

The channel scripts use only OP_TX, OP_CHECKSIGFROMSTACK, OP_CHECKLOCKTIMEVERIFY,
OP_CHECKSEQUENCEVERIFY, OP_CAT, OP_SHA256 and OP_DROP. They are the same token
lists in both tapleaf versions: `0xC2` (FULL) and `0xC0` (MID, C.7). The bytes
differ only where a number's minimal encoding differs, which for the
constants used here is `csv_delay` when its top bit is set (144 is `90` under
BIP-441 numerics and `9000` as a CScriptNum).
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import layertree_ref as lt  # noqa: E402
import layertree_scripts as ls  # noqa: E402
from script_sim import (TXSELECT_COLLATE, TXSELECT_INPUT_AMOUNT,  # noqa: E402
                        TXSELECT_INPUT_SCRIPTPUBKEY, TXSELECT_INPUT_SEQUENCE,
                        TXSELECT_INPUTSELECT_CURRENT, TXSELECT_LOCKTIME,
                        TXSELECT_NUM_INPUTS, TXSELECT_NUM_OUTPUTS,
                        TXSELECT_OUTPUT_AMOUNT, TXSELECT_OUTPUT_SCRIPT,
                        TXSELECT_VERSION, TxContext, assemble, collate)

# ------------------------------------------------------------- constants --
# C.2.1 selectors. Both collate, so OP_TX leaves exactly one element.
SEL_CHAN_UPD = (TXSELECT_COLLATE | TXSELECT_VERSION | TXSELECT_NUM_INPUTS |
                TXSELECT_INPUT_SEQUENCE | TXSELECT_NUM_OUTPUTS |
                TXSELECT_OUTPUT_AMOUNT | TXSELECT_OUTPUT_SCRIPT |
                TXSELECT_LOCKTIME | TXSELECT_INPUTSELECT_CURRENT)
SEL_CHAN_SET = SEL_CHAN_UPD | TXSELECT_INPUT_AMOUNT | TXSELECT_INPUT_SCRIPTPUBKEY
assert SEL_CHAN_UPD == 0x0FC7 and SEL_CHAN_SET == 0x30FC7

# C.2.2 tags.
TAG_CHAN_ID = "LayerTree/chan/id"
TAG_CHAN_UPD = "LayerTree/chan/update"
TAG_CHAN_SET = "LayerTree/chan/settle"

# C.3.5: state numbers live in the timestamp range of nLockTime.
S = 500_000_000
MAX_STATE = (1 << 32) - 1 - S - 1   # REBIND_n pushes S + n + 1 < 2^32

# C.3.3 / C.3.4: transaction constants.
CHAN_TX_VERSION = 3                 # TRUC (BIP-431)
UPDATE_SEQUENCE = 0xFFFFFFFD
P2A_SPK = bytes([0x51, 0x02, 0x4E, 0x73])   # OP_1 <0x4e73>, the P2A anchor

# C.3.4: the settlement dust floor. A settlement is zero-fee with a 0-value
# ephemeral anchor, so it may carry no other dust output; a balance or HTLC
# output below DUST_CHAN is omitted and its value goes to the anchor. The
# RECOMMENDED value is the P2TR dust threshold under Bitcoin Core's default
# dust relay fee. DUST_P2A is the anchor's own threshold under the same
# policy: an anchor carrying less than it is the one dust output.
DUST_CHAN = 330
DUST_P2A = 240


# ------------------------------------------------------- channel context --
def chan_id(m, owner_key, nonce, p_chan, capacity, epoch, csv_delay):
    """chan_id of C.2.2.

    H_chanid(m || owner_key || le32(nonce) || x(P_chan) || le64(C)
             || le32(epoch) || le32(csv_delay)).
    """
    assert len(m) == len(owner_key) == len(p_chan) == 32
    return lt.tagged_hash(TAG_CHAN_ID, m + owner_key + lt.le32(nonce) + p_chan +
                          lt.le64(capacity) + lt.le32(epoch) + lt.le32(csv_delay))


def ctx_upd(cid):
    """ctx_upd = H_chanupd(chan_id), the update role's script constant."""
    return lt.tagged_hash(TAG_CHAN_UPD, cid)


def ctx_set(cid):
    """ctx_set = H_chanset(chan_id), the settlement role's script constant."""
    return lt.tagged_hash(TAG_CHAN_SET, cid)


def msg_upd(ctx_u, tx):
    """msg_upd = SHA256(ctx_upd || OP_TX(SEL_CHAN_UPD)) over a TxContext."""
    return lt.sha256(ctx_u + collate(tx, SEL_CHAN_UPD))


def msg_set(ctx_s, tx):
    """msg_set = SHA256(ctx_set || OP_TX(SEL_CHAN_SET)) over a TxContext."""
    return lt.sha256(ctx_s + collate(tx, SEL_CHAN_SET))


# --------------------------------------------------------------- scripts --
def _check_sig_tail(ctx, p_chan):
    """<ctx> OP_SWAP OP_CAT OP_SHA256 <P_chan> OP_CHECKSIGFROMSTACK.

    Stack in: sig blob. Stack out: 1.
    """
    assert len(ctx) == 32 and len(p_chan) == 32
    return [ctx, "OP_SWAP", "OP_CAT", "OP_SHA256",     # sig msg
            p_chan, "OP_CHECKSIGFROMSTACK"]             # 1


def rebind_script(n, ctx_u, p_chan):
    """REBIND_n (C.3.3), a leaf of U_n. Witness: <upd_sig_m>, m > n.

    The CLTV operand S+n+1 admits only a strictly later state and forces the
    spending transaction's nLockTime into the timestamp range (C.3.5).
    """
    assert 0 <= n <= MAX_STATE
    return ([S + n + 1, "OP_CHECKLOCKTIMEVERIFY", "OP_DROP",  # sig
             SEL_CHAN_UPD, "OP_TX"]                           # sig blob
            + _check_sig_tail(ctx_u, p_chan))


def upd_f_script(ctx_u, p_chan):
    """UPD_F (C.3.2), the single leaf of the funding taptree. Witness: <upd_sig>.

    It is REBIND_0: any state n >= 1 binds to the funding output.
    """
    return rebind_script(0, ctx_u, p_chan)


def settle_script(csv_delay, ctx_s, p_chan):
    """SETTLE_n (C.3.3), a leaf of U_n. Witness: <set_sig_n>.

    The script does not name n; SEL_CHAN_SET commits the spent scriptPubKey,
    which embeds n through REBIND_n, so a settlement signed for U_n binds to
    U_n only (C.2.4).
    """
    assert 0 < csv_delay < 1 << 16
    return ([csv_delay, "OP_CHECKSEQUENCEVERIFY", "OP_DROP",  # sig
             SEL_CHAN_SET, "OP_TX"]                           # sig blob
            + _check_sig_tail(ctx_s, p_chan))


htlc_success_script = ls.htlc_success_script
htlc_timeout_script = ls.htlc_timeout_script


# ------------------------------------------------------------------ taproot --
def leaf_version(mode):
    return lt.LEAF_VERSION_GSR if mode == "c2" else 0xC0


def taptweak(internal_x, merkle_root):
    """BIP-341 output key: (x-only Q, parity of Q)."""
    t = int.from_bytes(lt.tagged_hash(lt.TAG_TAPTWEAK, internal_x + merkle_root), "big")
    assert t < lt.N
    q = lt.point_add(lt.lift_x(int.from_bytes(internal_x, "big")), lt.point_mul(lt.G, t))
    return lt.xonly(q), q[1] & 1


def taptree_path(leaf_hashes, index):
    """Merkle path (sibling hashes, leaf first) for lt.taptree_root's shape."""
    level, path, i = list(leaf_hashes), [], index
    while len(level) > 1:
        nxt = []
        for j in range(0, len(level) - 1, 2):
            nxt.append(lt.tapbranch(level[j], level[j + 1]))
        if len(level) % 2:
            nxt.append(level[-1])
        if i ^ 1 < len(level) and not (len(level) % 2 and i == len(level) - 1):
            path.append(level[i ^ 1])
        level, i = nxt, i // 2
    return path


class TapOutput:
    """A taproot output with a script tree: keys, scriptPubKey, control blocks.

    scripts are token lists (assembled in `mode`) or already compiled bytes.
    """

    def __init__(self, internal_x, scripts, mode="c2"):
        self.internal_x = internal_x
        self.mode = mode
        self.scripts = [s if isinstance(s, bytes) else assemble(s, mode) for s in scripts]
        self.leaf_hashes = [lt.tapleaf_hash(s, leaf_version(mode)) for s in self.scripts]
        self.merkle_root = lt.taptree_root(self.leaf_hashes)
        self.output_x, self.parity = taptweak(internal_x, self.merkle_root)
        self.spk = lt.p2tr_spk(self.output_x)

    def control_block(self, index):
        path = taptree_path(self.leaf_hashes, index)
        return bytes([leaf_version(self.mode) | self.parity]) + self.internal_x + b"".join(path)


def verify_control_block(spk, script, control):
    """BIP-341 script-path commitment check: does `control` commit `script`
    under the output key of `spk`? Returns the leaf version."""
    if len(control) < 33 or (len(control) - 33) % 32:
        return None
    ver, internal_x = control[0] & 0xFE, control[1:33]
    k = lt.tapleaf_hash(script, ver)
    for j in range(33, len(control), 32):
        k = lt.tapbranch(k, control[j:j + 32])
    q, parity = taptweak(internal_x, k)
    if lt.p2tr_spk(q) != spk or parity != control[0] & 1:
        return None
    return ver


# --------------------------------------------------------- the channel --
class Channel:
    """Static parameters of one channel epoch and the outputs they define.

    p_chan is the 32-byte x-only aggregate key of C.3.2. The reference uses
    the sum of the two parties' keys as a stand-in for BIP-327 key
    aggregation ([C-A4]: nothing here depends on MuSig2 beyond P_chan being
    one x-only key both parties must cooperate to sign under).
    """

    def __init__(self, m, owner_key, nonce, p_chan, capacity, epoch, csv_delay, mode="c2",
                 dust_chan=DUST_CHAN):
        self.m, self.owner_key, self.nonce = m, owner_key, nonce
        self.p_chan, self.capacity, self.epoch = p_chan, capacity, epoch
        self.csv_delay, self.mode = csv_delay, mode
        # dust_chan is a channel parameter like evict_after: agreed at
        # opening and not part of chan_id (C.3.4).
        assert dust_chan >= DUST_CHAN
        self.dust_chan = dust_chan
        self.chan_id = chan_id(m, owner_key, nonce, p_chan, capacity, epoch, csv_delay)
        self.ctx_upd = ctx_upd(self.chan_id)
        self.ctx_set = ctx_set(self.chan_id)
        self.funding = TapOutput(p_chan, [upd_f_script(self.ctx_upd, p_chan)], mode)

    @property
    def exit_key(self):
        """The leaf's exit_key: the funding output key of C.3.2."""
        return self.funding.output_x

    def update_output(self, n):
        """U_n: internal key P_chan, leaves [REBIND_n, SETTLE_n]."""
        return TapOutput(self.p_chan, [rebind_script(n, self.ctx_upd, self.p_chan),
                                       settle_script(self.csv_delay, self.ctx_set, self.p_chan)],
                         self.mode)

    # Transaction templates. TxContext carries (amount, spk) per input; the
    # prevout is not part of what is signed, which is the point of C.2.
    def update_tx(self, n, prev_amount=None, prev_spk=None):
        """update_n (C.3.3): one input, outputs [U_n (C), P2A (0)]."""
        return TxContext([(self.capacity if prev_amount is None else prev_amount,
                           prev_spk or self.funding.spk)],
                         [(self.capacity, self.update_output(n).spk), (0, P2A_SPK)],
                         locktime=S + n, sequences=[UPDATE_SEQUENCE], version=CHAN_TX_VERSION)

    def settle_outputs(self, b_u, b_v, u_payout, v_payout, htlcs=()):
        """C.3.4 outputs: to_owner, to_cp, one per HTLC, then the P2A anchor.

        htlcs: iterable of (amount, TapOutput). A balance or HTLC below
        dust_chan is omitted and its value added to the anchor (C.3.4): the
        transaction stays zero-fee, and the anchor is its one dust output
        while it stays below the anchor's own threshold.
        """
        wanted = [(b_u, lt.p2tr_spk(u_payout)), (b_v, lt.p2tr_spk(v_payout))]
        wanted += [(amt, out.spk) for amt, out in htlcs]
        outs, anchor = [], 0
        for amt, spk in wanted:
            if amt < self.dust_chan:
                anchor += amt
            else:
                outs.append((amt, spk))
        outs.append((anchor, P2A_SPK))
        assert sum(a for a, _ in outs) == self.capacity, "settlement must be zero-fee (C.3.4)"
        return outs

    def settle_tx(self, n, outputs):
        """settle_n (C.3.4): spends U_n with nSequence = csv_delay."""
        return TxContext([(self.capacity, self.update_output(n).spk)], outputs,
                         locktime=0, sequences=[self.csv_delay], version=CHAN_TX_VERSION)


def htlc_output(internal_x, payment_hash, cltv_expiry, offerer_claim, recipient_claim, mode="c2"):
    """An HTLC output of C.4.1: leaves [HTLC_SUCCESS, HTLC_TIMEOUT]."""
    return TapOutput(internal_x, [htlc_success_script(payment_hash, recipient_claim),
                                  htlc_timeout_script(cltv_expiry, offerer_claim)], mode)


# -------------------------------------------------------------- deadlines --
def cltv_budget_spec(g_exit, csv_delay, g_sweep, beta_chan=0):
    """The C.4.4 bound: G_exit + 1 + beta_chan + 1 + csv_delay + 1 + G_sweep,
    where beta_chan is the number of stale updates the counterparty gets
    confirmed ahead of the honest one."""
    return g_exit + 1 + beta_chan + 1 + csv_delay + 1 + g_sweep


def cltv_budget_exact(g_exit, csv_delay, g_sweep, beta_chan=0):
    """The smallest cltv_expiry - t at which the HTLC payee wins, counting
    blocks as BIP-65 and BIP-68 do.

    From tip t: the exit confirms in block t + g_exit, the update in the next
    block, the settlement csv_delay blocks after the update (BIP-68 counts
    the update's own block), and the sweep g_sweep blocks after that. The
    offerer's timeout sweep has nLockTime = cltv_expiry and is final first
    in block cltv_expiry + 1, so the payee is safe iff its sweep confirms in
    a block <= cltv_expiry. Every stale update confirmed ahead of the honest
    one (beta_chan) moves the update, and so the sweep, one block later.
    """
    return g_exit + 1 + beta_chan + csv_delay + g_sweep


if __name__ == "__main__":
    k = lt.sha256(b"P_chan")
    from script_sim import pubkey_x
    p = pubkey_x(k)
    ch = Channel(lt.sha256(b"m"), pubkey_x(lt.sha256(b"owner")), 7, p, 1_000_000, 0, 144)
    for name, s in (("UPD_F", upd_f_script(ch.ctx_upd, p)),
                    ("REBIND_1", rebind_script(1, ch.ctx_upd, p)),
                    ("SETTLE_n", settle_script(144, ch.ctx_set, p))):
        print(f"{name:10} {len(assemble(s, 'c2'))} B (0xC2), {len(assemble(s, 'c0'))} B (0xC0)")
