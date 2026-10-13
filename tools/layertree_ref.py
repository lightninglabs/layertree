#!/usr/bin/env python3
"""LayerTree reference implementation (spec companion).

Pure-Python, dependency-free reference for the data structures defined in
spec/layertree.md: leaf encoding, merkle-sum node hashing, dense fixed-depth
trees, proofs, state transitions, and the taproot output key derivation that
binds a root to the on-chain tree output.

It is written for clarity, not speed. Run `python3 tools/layertree_ref.py`
to regenerate spec/test-vectors.json.
"""
import hashlib
import json
import os
import sys

# --------------------------------------------------------------------------
# secp256k1 (minimal, BIP-340 style)
# --------------------------------------------------------------------------
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)


def point_add(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    if p1[0] == p2[0] and p1[1] != p2[1]:
        return None
    if p1 == p2:
        lam = (3 * p1[0] * p1[0] * pow(2 * p1[1], P - 2, P)) % P
    else:
        lam = ((p2[1] - p1[1]) * pow(p2[0] - p1[0], P - 2, P)) % P
    x3 = (lam * lam - p1[0] - p2[0]) % P
    return (x3, (lam * (p1[0] - x3) - p1[1]) % P)


def point_mul(p, n):
    r = None
    for i in range(256):
        if (n >> i) & 1:
            r = point_add(r, p)
        p = point_add(p, p)
    return r


def lift_x(x):
    if x >= P:
        return None
    y_sq = (pow(x, 3, P) + 7) % P
    y = pow(y_sq, (P + 1) // 4, P)
    if pow(y, 2, P) != y_sq:
        return None
    return (x, y if y & 1 == 0 else P - y)


def compress(pt):
    return bytes([2 if pt[1] % 2 == 0 else 3]) + pt[0].to_bytes(32, "big")


def decompress(b):
    assert len(b) == 33 and b[0] in (2, 3)
    pt = lift_x(int.from_bytes(b[1:], "big"))
    assert pt is not None
    if (b[0] == 3) != (pt[1] % 2 == 1):
        pt = (pt[0], P - pt[1])
    return pt


def xonly(pt):
    return pt[0].to_bytes(32, "big")


# --------------------------------------------------------------------------
# Hashing
# --------------------------------------------------------------------------
def sha256(b):
    return hashlib.sha256(b).digest()


def tag_prefix(tag):
    t = sha256(tag.encode())
    return t + t


def tagged_hash(tag, msg):
    return sha256(tag_prefix(tag) + msg)


TAG_LEAF = "LayerTree/leaf"
TAG_NODE = "LayerTree/node"
TAG_STATE = "LayerTree/state"
TAG_VOUCHER = "LayerTree/voucher"
TAG_VOUCHER_H = "LayerTree/voucher-hashlock"
# The exit authorisation of EXIT_K^t (spec 7.2 rule 7): a tag of its own,
# so an authorisation can never serve as a voucher nor a voucher as one.
TAG_EXIT = "LayerTree/exit"
# The merge voucher of CLAIM^m and CLAIM^hm (design/pending-receive.md,
# R2): tags of their own, so a merge voucher can never be redeemed as a
# carve nor a carve voucher as a merge.
TAG_VOUCHER_M = "LayerTree/voucher-merge"
TAG_VOUCHER_HM = "LayerTree/voucher-merge-hashlock"
TAG_POS = "LayerTree/pos"
TAG_TREE_ID = "LayerTree/tree-id"
TAG_TAPTWEAK = "TapTweak"
TAG_TAPLEAF = "TapLeaf"
TAG_TAPBRANCH = "TapBranch"

# BIP-341 provably-unspendable internal key H (x-only, even y when lifted).
NUMS_X = bytes.fromhex(
    "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0")
NUMS = lift_x(int.from_bytes(NUMS_X, "big"))
assert NUMS is not None

LEAF_VERSION_GSR = 0xC2
# DUST_MIN (spec 6.2): the smallest amount a non-operator transition may
# write into a leaf, a tree-creation parameter carried by the carve scripts
# as a constant. The RECOMMENDED value is the P2TR dust threshold of
# Bitcoin Core's default policy (3000 sat/kvB over 110 bytes), since every
# transition that removes a leaf pays it to exactly one P2TR output.
DUST_MIN = 330
EMPTY_LEAF_HASH = bytes(32)
LEAF_LEN = 116
# The leaf body (spec 5.2): the 108 bytes after the amount field, which is
# what a voucher (7.5) and an exit authorisation (7.2 rule 7) bind, so that
# an amount-only increase by REWRITE_h rule 3 voids neither.
LEAF_BODY_OFF = 8
LEAF_BODY_LEN = LEAF_LEN - LEAF_BODY_OFF


def le64(n):
    if n < 0 or n >= 1 << 64:
        raise ValueError("sum out of range")
    return n.to_bytes(8, "little")


def le32(n):
    return n.to_bytes(4, "little")


def enc64(n):
    """Sum encoding used inside node hashes: the BIP-441 minimal little-endian
    encoding of n + 2**64, i.e. le64(n) || 0x01 (always 9 bytes for n < 2**64).
    Chosen so that script can produce it with a single OP_ADD."""
    return le64(n) + b"\x01"


# --------------------------------------------------------------------------
# Leaf
# --------------------------------------------------------------------------
class Leaf:
    """A LayerTree leaf (spec section 5.2).

    amount(8) exit_key(32) owner_key(32) evictor_key(32) evict_after(4)
    nonce(4) seq(4) = 116 bytes.
    """

    def __init__(self, amount, exit_key, owner_key, evictor_key, evict_after, nonce=0, seq=0):
        assert len(exit_key) == len(owner_key) == len(evictor_key) == 32
        assert 0 <= evict_after < 500_000_000
        assert 0 <= nonce < 1 << 32 and 0 <= seq < 1 << 32
        self.amount = amount
        self.exit_key = exit_key
        self.owner_key = owner_key
        self.evictor_key = evictor_key
        self.evict_after = evict_after
        self.nonce = nonce
        self.seq = seq

    def serialize(self):
        b = (le64(self.amount) + self.exit_key + self.owner_key +
             self.evictor_key + le32(self.evict_after) + le32(self.nonce) + le32(self.seq))
        assert len(b) == LEAF_LEN
        return b

    @classmethod
    def parse(cls, b):
        assert len(b) == LEAF_LEN
        return cls(int.from_bytes(b[0:8], "little"), b[8:40], b[40:72],
                   b[72:104], int.from_bytes(b[104:108], "little"),
                   int.from_bytes(b[108:112], "little"),
                   int.from_bytes(b[112:116], "little"))

    def body(self):
        """The leaf without its amount (spec 5.2): exit_key || owner_key ||
        evictor_key || le32(evict_after) || le32(nonce) || le32(seq), 108
        bytes. Vouchers and exit authorisations sign this rather than the
        whole leaf (7.5, 7.2 rule 7), so an amount-only increase by
        REWRITE_h rule 3 leaves them valid while any other change, seq
        included, voids them."""
        return self.serialize()[LEAF_BODY_OFF:]

    def hash(self):
        return tagged_hash(TAG_LEAF, self.serialize())

    def node(self):
        return (self.hash(), self.amount)

    def with_amount_seq(self, amount, seq):
        return Leaf(amount, self.exit_key, self.owner_key, self.evictor_key,
                    self.evict_after, self.nonce, seq)

    def position(self, depth):
        """Sparse profile: low `depth` bits of int_le(H_pos(owner_key || le32(nonce)))."""
        h = tagged_hash(TAG_POS, self.owner_key + le32(self.nonce))
        return int.from_bytes(h, "little") & ((1 << depth) - 1)

    def to_json(self):
        return {
            "amount": self.amount,
            "exit_key": self.exit_key.hex(),
            "owner_key": self.owner_key.hex(),
            "evictor_key": self.evictor_key.hex(),
            "evict_after": self.evict_after,
            "nonce": self.nonce,
            "seq": self.seq,
            "serialized": self.serialize().hex(),
            "leaf_hash": self.hash().hex(),
        }


EMPTY_NODE = (EMPTY_LEAF_HASH, 0)


# --------------------------------------------------------------------------
# Nodes and trees
# --------------------------------------------------------------------------
def node_hash(left, right):
    """Merkle-sum branch hash (spec section 5.3)."""
    (lh, ls), (rh, rs) = left, right
    return tagged_hash(TAG_NODE, lh + enc64(ls) + rh + enc64(rs))


def parent(left, right):
    return (node_hash(left, right), left[1] + right[1])


def empty_node(height):
    """The node covering 2**height empty leaves."""
    n = EMPTY_NODE
    for _ in range(height):
        n = parent(n, n)
    return n


class Tree:
    """Dense binary merkle-sum tree of depth D (2**D leaf slots)."""

    def __init__(self, depth):
        self.depth = depth
        self.leaves = {}  # slot -> Leaf

    def leaf_node(self, slot):
        leaf = self.leaves.get(slot)
        return leaf.node() if leaf else EMPTY_NODE

    def subtree(self, height, index):
        """Node covering slots [index*2**height, (index+1)*2**height)."""
        lo, hi = index << height, (index + 1) << height
        if not any(lo <= s < hi for s in self.leaves):
            return empty_node(height)
        if height == 0:
            return self.leaf_node(index)
        return parent(self.subtree(height - 1, 2 * index),
                      self.subtree(height - 1, 2 * index + 1))

    def root(self):
        return self.subtree(self.depth, 0)

    def path(self, slot, height=0):
        """Sibling path from the node at (height, slot>>height) to the root.

        Returns a list of (dir, sibling_node) ordered from the bottom up,
        where dir == 1 iff the node on the path is the *right* child.
        """
        out = []
        idx = slot >> height
        for h in range(height, self.depth):
            d = idx & 1
            sib = self.subtree(h, idx ^ 1)
            out.append((d, sib))
            idx >>= 1
        return out


def fold(node, path):
    """Recompute the root from a node and its sibling path."""
    for d, sib in path:
        node = parent(sib, node) if d else parent(node, sib)
    return node


def verify_path(root, node, path):
    return fold(node, path) == root


def path_bitmap(path, height=0):
    """Sparse/bitmap: (bitmap_bytes, [sc for non-empty siblings, bottom-up])."""
    bm, nodes = 0, []
    for k, (d, sib) in enumerate(path):
        if sib == empty_node(height + k):
            bm |= 1 << k
        else:
            nodes.append(sib[0] + enc64(sib[1]))
    nbytes = (len(path) + 7) // 8
    return bm.to_bytes(nbytes, "little"), nodes


def compress_path(path, height=0):
    """Sparse profile: replace empty siblings by the empty string."""
    out = []
    for k, (d, sib) in enumerate(path):
        out.append((d, b"" if sib == empty_node(height + k) else sib[0] + enc64(sib[1])))
    return out


# --------------------------------------------------------------------------
# Taproot binding of the root (spec section 6)
# --------------------------------------------------------------------------
def state_tweak(root_hash):
    t = int.from_bytes(tagged_hash(TAG_STATE, root_hash), "big")
    assert 0 < t < N
    return t


def internal_key(root_hash):
    """P = NUMS + H_state(root_hash) * G, returned as a compressed point."""
    return compress(point_add(NUMS, point_mul(G, state_tweak(root_hash))))


def output_key(root_hash, merkle_root):
    p_x = internal_key(root_hash)[1:]
    t2 = int.from_bytes(tagged_hash(TAG_TAPTWEAK, p_x + merkle_root), "big")
    assert t2 < N
    q = point_add(lift_x(int.from_bytes(p_x, "big")), point_mul(G, t2))
    return xonly(q), (q[1] & 1)


def tree_spk(root_hash, merkle_root):
    q_x, _ = output_key(root_hash, merkle_root)
    return bytes([0x51, 0x20]) + q_x


def ccv_internal_key(root_hash):
    """CCV-tier state key (spec section 6.1 alternative): the BIP-443 data
    tweak of the BIP-341 NUMS point by the root hash, i.e. the x-only key
    NUMS + sha256(NUMS || root_hash)*G. Note this is NOT H_state(root_hash):
    the data tweak is an untagged sha256 over (pk || data), so a CCV tree and
    a FULL tree with the same root have different scriptPubKeys, and the tier
    is a tree-creation parameter."""
    t = int.from_bytes(sha256(NUMS_X + root_hash), "big")
    assert 0 < t < N
    return xonly(point_add(NUMS, point_mul(G, t)))


def tree_spk_ccv(root_hash, merkle_root):
    """Tree output scriptPubKey for the CCV tier: the output key a
    CHECKCONTRACTVERIFY call with pk=empty (NUMS), data=root_hash and
    taptree=merkle_root verifies (BIP-443: data tweak, then TapTweak)."""
    p_x = ccv_internal_key(root_hash)
    t2 = int.from_bytes(tagged_hash(TAG_TAPTWEAK, p_x + merkle_root), "big")
    assert t2 < N
    q = point_add(lift_x(int.from_bytes(p_x, "big")), point_mul(G, t2))
    return bytes([0x51, 0x20]) + xonly(q)


def p2tr_spk(xonly_key):
    return bytes([0x51, 0x20]) + xonly_key


def compact_size(n):
    if n < 253:
        return bytes([n])
    if n < 0x10000:
        return b"\xfd" + n.to_bytes(2, "little")
    return b"\xfe" + n.to_bytes(4, "little")


def tapleaf_hash(script, version=LEAF_VERSION_GSR):
    return tagged_hash(TAG_TAPLEAF, bytes([version]) + compact_size(len(script)) + script)


def tapbranch(a, b):
    if b < a:
        a, b = b, a
    return tagged_hash(TAG_TAPBRANCH, a + b)


def taptree_root(leaf_hashes):
    """Balanced-ish taptree over the given leaf hashes (in order)."""
    level = list(leaf_hashes)
    while len(level) > 1:
        nxt = []
        for i in range(0, len(level) - 1, 2):
            nxt.append(tapbranch(level[i], level[i + 1]))
        if len(level) % 2:
            nxt.append(level[-1])
        level = nxt
    return level[0]


# --------------------------------------------------------------------------
# Transitions (spec section 7) as pure functions on (tree, params)
# --------------------------------------------------------------------------
def apply_exit(tree, slot):
    leaf = tree.leaves.pop(slot)
    return leaf


def apply_join(tree, height, index, leaves):
    """Insert a subtree of leaves at (height, index). leaves: {offset: Leaf}."""
    lo = index << height
    assert tree.subtree(height, index) == empty_node(height)
    for off, leaf in leaves.items():
        assert 0 <= off < (1 << height)
        tree.leaves[lo + off] = leaf


def apply_update(tree, slot, new_leaf):
    old = tree.leaves[slot]
    tree.leaves[slot] = new_leaf
    return old


def tree_id(txid, vout):
    """The RECOMMENDED tree_id (spec 6.2): H_tag("LayerTree/tree-id", txid
    || le32(vout)) over the creation outpoint, txid in internal byte order.
    Any 32-byte value unique to the tree's lineage works; a tree created by
    DETACH_h inherits its parent's."""
    assert len(txid) == 32
    return tagged_hash(TAG_TREE_ID, txid + le32(vout))


def voucher_msg(tree_id, source_leaf, claim_leaf):
    """Voucher message (spec 7.5): H_voucher(tree_id || body(src) || claim).
    The tree_id, not m, is what binds a voucher to one tree: m names a rule
    set, which two trees can share. The source leaf is bound without its
    amount (Leaf.body), so an amount-only increase by REWRITE_h rule 3
    does not void the voucher; single use comes from seq, which every
    redemption advances, and over-redemption is stopped by the script's
    check of the claim against the leaf's current amount. The claim leaf is
    bound in full."""
    assert len(tree_id) == 32
    return tagged_hash(TAG_VOUCHER, tree_id + source_leaf.body() + claim_leaf.serialize())


def voucher_h_msg(tree_id, source_leaf, claim_leaf, payment_hash):
    """Hash-locked voucher message (spec 7.5.1).

    A separate tag keeps the two voucher forms disjoint: a plain voucher can
    never be redeemed by CLAIM_H and vice versa, whatever the payload.
    """
    assert len(tree_id) == 32 and len(payment_hash) == 32
    return tagged_hash(TAG_VOUCHER_H,
                       tree_id + source_leaf.body() + claim_leaf.serialize() + payment_hash)


def voucher_m_msg(tree_id, source_leaf, target_leaf, target_amount, payment_hash=None):
    """Merge voucher message (CLAIM^m, CLAIM^hm; design/pending-receive.md
    R2): H_voucher_m(tree_id || body(src) || body(target) || le64(X)
    [|| payment_hash]). It names the target by its body and the amount X
    the target is raised to, an absolute level: once the target holds X
    the voucher moves nothing, so a replay or an older, smaller voucher is
    harmless. The hash-locked form appends the payment hash under its own
    tag."""
    assert len(tree_id) == 32
    msg = tree_id + source_leaf.body() + target_leaf.body() + le64(target_amount)
    if payment_hash is None:
        return tagged_hash(TAG_VOUCHER_M, msg)
    assert len(payment_hash) == 32
    return tagged_hash(TAG_VOUCHER_HM, msg + payment_hash)


def apply_merge(tree, source_slot, target_slot, target_amount):
    """A merge (R2): raise the target to target_amount, taking the
    difference from the source, whose seq does not advance; a source
    drained to zero becomes E_0. The two positions are siblings."""
    assert source_slot ^ 1 == target_slot
    src, tgt = tree.leaves[source_slot], tree.leaves[target_slot]
    d = target_amount - tgt.amount
    assert 0 < d <= src.amount
    tree.leaves[target_slot] = tgt.with_amount_seq(target_amount, tgt.seq)
    if src.amount == d:
        del tree.leaves[source_slot]
    else:
        tree.leaves[source_slot] = src.with_amount_seq(src.amount - d, src.seq)


def exit_auth_msg(tree_id, leaf):
    """Exit authorisation message (spec 7.2 rule 7): H_tag("LayerTree/exit",
    tree_id || body(leaf)). An owner signs it once, off-chain; anyone
    holding the signature can build the exact-payout exit of that leaf
    against any later root of the lineage, since the message names no
    transaction. It binds the leaf without its amount (Leaf.body), so an
    amount-only increase by REWRITE_h rule 3 leaves it valid and the exit
    pays the leaf's current amount; any other change, seq included, voids
    it."""
    assert len(tree_id) == 32
    return tagged_hash(TAG_EXIT, tree_id + leaf.body())


def apply_claim(tree, source_slot, claim_slot, claim_leaf):
    """A carve (spec 7.5 rules 2, 3 and 5): the claim leaf keeps the
    source's evictor and a lease no longer than the source's."""
    src = tree.leaves[source_slot]
    assert claim_slot not in tree.leaves
    assert claim_leaf.amount <= src.amount
    assert claim_leaf.evictor_key == src.evictor_key, "7.5 rule 5: evictor_key"
    assert claim_leaf.evict_after <= src.evict_after, "7.5 rule 5: evict_after"
    tree.leaves[source_slot] = src.with_amount_seq(src.amount - claim_leaf.amount, src.seq + 1)
    tree.leaves[claim_slot] = claim_leaf
    return src


# --------------------------------------------------------------------------
# Test vectors
# --------------------------------------------------------------------------
def hx(b):
    return b.hex()


def node_json(n):
    return {"hash": hx(n[0]), "sum": n[1]}


def path_json(path):
    return [{"dir": d, "sibling": node_json(s), "sc": hx(s[0] + enc64(s[1]))} for d, s in path]


def det_key(label):
    """Deterministic valid x-only key for vectors (not for real use)."""
    i = 0
    while True:
        x = sha256(f"{label}:{i}".encode())
        if lift_x(int.from_bytes(x, "big")) is not None:
            return x
        i += 1


def build_vectors():
    vec = {"description": "LayerTree reference test vectors; see spec/layertree.md",
           "tags": {t: hx(tag_prefix(t)) for t in (TAG_LEAF, TAG_NODE, TAG_STATE, TAG_VOUCHER, TAG_VOUCHER_H,
                                                    TAG_EXIT, TAG_TREE_ID)},
           "nums_x": hx(NUMS_X), "nums_compressed": hx(compress(NUMS)),
           "empty_leaf_hash": hx(EMPTY_LEAF_HASH),
           "empty_nodes": [node_json(empty_node(h)) for h in range(0, 33)]}

    D = 4
    t = Tree(D)
    alice = Leaf(50_000, det_key("alice-exit"), det_key("alice-owner"), NUMS_X, 0, 0)
    bob = Leaf(125_000, det_key("bob-exit"), det_key("bob-owner"), det_key("operator"), 850_000, 0)
    oper = Leaf(1_000_000, det_key("operator-exit"), det_key("operator"), NUMS_X, 0, nonce=7)
    t.leaves = {0: alice, 5: bob, 15: oper}
    merkle_root = sha256(b"example taptree root (placeholder)")
    # The creation outpoint is a placeholder too; tree_id is its RECOMMENDED
    # derivation (6.2) and is what the voucher vectors below bind.
    creation_txid = sha256(b"example creation txid (placeholder)")
    tid = tree_id(creation_txid, 0)
    r0 = t.root()

    vec["example_tree"] = {
        "depth": D,
        "leaves": {str(s): l.to_json() for s, l in t.leaves.items()},
        "root": node_json(r0),
        "internal_key": hx(internal_key(r0[0])),
        "merkle_root_placeholder": hx(merkle_root),
        "creation_outpoint": {"txid": hx(creation_txid), "vout": 0},
        "tree_id": hx(tid),
        "output_key": hx(output_key(r0[0], merkle_root)[0]),
        "scriptPubKey": hx(tree_spk(r0[0], merkle_root)),
        "paths": {str(s): path_json(t.path(s)) for s in t.leaves},
    }

    # EXIT of bob (slot 5), owner-authorised.
    t1 = Tree(D)
    t1.leaves = dict(t.leaves)
    path = t1.path(5)
    apply_exit(t1, 5)
    r1 = t1.root()
    assert fold(EMPTY_NODE, path) == r1
    vec["transition_exit"] = {
        "slot": 5, "leaf": bob.to_json(), "path": path_json(path),
        "old_root": node_json(r0), "new_root": node_json(r1),
        "exit_output": {"amount": bob.amount, "scriptPubKey": hx(p2tr_spk(bob.exit_key))},
        "new_tree_scriptPubKey": hx(tree_spk(r1[0], merkle_root)),
        # EXIT_K^t (7.2 rule 7): the owner's off-chain authorisation of this
        # exit binds the leaf without its amount.
        "leaf_body": hx(bob.body()),
        "exit_auth_msg": hx(exit_auth_msg(tid, bob)),
    }

    # JOIN of a 4-leaf subtree at height 2, index 2 (slots 8..11), two leaves used.
    t2 = Tree(D)
    t2.leaves = dict(t1.leaves)
    carol = Leaf(30_000, det_key("carol-exit"), det_key("carol-owner"), det_key("operator"), 900_000, 0)
    dave = Leaf(70_000, det_key("dave-exit"), det_key("dave-owner"), det_key("operator"), 900_000, 0)
    jpath = t2.path(8, height=2)
    apply_join(t2, 2, 2, {0: carol, 3: dave})
    new_sub = t2.subtree(2, 2)
    r2 = t2.root()
    assert fold(empty_node(2), jpath) == r1 and fold(new_sub, jpath) == r2
    vec["transition_join"] = {
        "height": 2, "index": 2, "old_node": node_json(empty_node(2)),
        "new_node": node_json(new_sub), "path": path_json(jpath),
        "subtree_leaves": {"0": carol.to_json(), "3": dave.to_json()},
        "old_root": node_json(r1), "new_root": node_json(r2),
    }

    # UPDATE of alice (slot 0): amount 50_000 -> 80_000, seq 0 -> 1.
    t3 = Tree(D)
    t3.leaves = dict(t2.leaves)
    upath = t3.path(0)
    alice2 = alice.with_amount_seq(80_000, 1)
    apply_update(t3, 0, alice2)
    r3 = t3.root()
    vec["transition_update"] = {
        "slot": 0, "old_leaf": alice.to_json(), "new_leaf": alice2.to_json(),
        "path": path_json(upath), "old_root": node_json(r2), "new_root": node_json(r3),
    }

    # CLAIM: voucher from operator leaf (slot 15) creating erin (slot 3).
    # erin keeps the operator leaf's NUMS evictor and evict_after 0 (7.5
    # rule 5): a carve is never easier to keep than its source.
    t4 = Tree(D)
    t4.leaves = dict(t3.leaves)
    erin = Leaf(40_000, det_key("erin-exit"), det_key("erin-owner"), NUMS_X, 0, 0)
    spath = t4.path(15)
    src_before = t4.leaves[15]
    apply_claim(t4, 15, 3, erin)
    src_after = t4.leaves[15]
    r_mid = fold(src_after.node(), spath)
    cpath = t4.path(3)
    r4 = t4.root()
    assert fold(erin.node(), cpath) == r4
    vec["transition_claim"] = {
        "source_slot": 15, "source_leaf_before": src_before.to_json(),
        "source_leaf_after": src_after.to_json(), "source_path": path_json(spath),
        "intermediate_root": node_json(r_mid),
        "claim_slot": 3, "claim_leaf": erin.to_json(), "claim_path": path_json(cpath),
        "source_leaf_body": hx(src_before.body()),
        "voucher_msg": hx(voucher_msg(tid, src_before, erin)),
        "old_root": node_json(r3), "new_root": node_json(r4),
    }
    # Hash-locked form of the same carve (7.5.1): same steps, different
    # message. preimage is fixed so the vector is reproducible.
    claim_preimage = sha256(b"LayerTree/test/preimage")
    vec["transition_claim"]["preimage"] = hx(claim_preimage)
    vec["transition_claim"]["payment_hash"] = hx(sha256(claim_preimage))
    vec["transition_claim"]["voucher_h_msg"] = hx(
        voucher_h_msg(tid, src_before, erin, sha256(claim_preimage)))
    # Sparse profile example: positions derived from (owner_key, nonce).
    SD = 32
    sp = Tree(SD)
    sparse_leaves = [alice, bob, oper, carol, dave, erin]
    for lf in sparse_leaves:
        sp.leaves[lf.position(SD)] = lf
    vec["sparse_example"] = {
        "depth": SD,
        "positions": {lf.owner_key.hex()[:16]: lf.position(SD) for lf in sparse_leaves},
        "root": node_json(sp.root()),
        "compressed_path_bob": [{"dir": d, "sc": sc.hex()} for d, sc in compress_path(sp.path(bob.position(SD)))],
    }
    return vec


if __name__ == "__main__":
    out = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "spec", "test-vectors.json")
    v = build_vectors()
    with open(out, "w") as f:
        json.dump(v, f, indent=1)
    print(f"wrote {out}")
    print("root", v["example_tree"]["root"])
    print("spk ", v["example_tree"]["scriptPubKey"])
