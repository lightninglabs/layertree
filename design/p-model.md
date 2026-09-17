# Model checking the LayerTree off-chain protocol in P

This note proposes a P model (https://p-org.github.io/P/) of the LayerTree
off-chain protocol: joining, exiting, eviction, updates, and the channel
leaves of Appendix C. It is a design note, not a specification. It says what
would be modelled, what would be asserted, and, as honestly as possible, what
the model would not catch. Bare section numbers refer to `spec/layertree.md`;
`C.` numbers refer to `spec/channel-leaves.md`.

## 1. Why P here and not for the covenant

The covenant's claims are theorems about a hash tree: `fold` over a sibling
path yields the committed root only for the real leaf, the recomputed sum
equals the input amount so value cannot be created, a `CLAIM` cannot be
replayed because step 1 mutates the source leaf (7.1, 7.5, 10.2). They are
quantified over all depths and all leaves, and a model checker cannot prove
them, since it can only enumerate a few small trees and enumerating trees is
not what makes the argument. That is the Lean work in `formal/`. The
protocol's failures are of the opposite kind. They are interleavings: an
eviction landing between an HTLC's acceptance and its expiry (C.5.6), an
operator `JOIN` replacing an owner `EXIT` in the mempool one round before the
owner's deadline (10.5), a reorg reverting an `EXIT` after the update chain
started (C.5.4, 10.11), a watchtower waking a block late. Those live in the
space of message orderings, adversarial choices and block timing, which is
what P enumerates and what no theorem about hash trees touches. The efforts
meet in one place, section 7: the model's covenant oracle must agree with
what Lean proves and with what the scripts do.

## 2. Scope: what we check

P checks safety by assertion and liveness by hot/cold monitors under a
fairness assumption on the scheduler.

| # | Property | Kind | Source | Fairness |
|---|---|---|---|---|
| P1 | An owner holding a leaf and a path for the current root can always build an `EXIT_1` the covenant accepts | safety | 7.2, 9.7, 10.9 | no |
| P2 | The counterparty's channel balance is never payable to the owner alone | safety | C.6.1, C.6.3, C.6.5, C.6.6 | no |
| P3 | An HTLC is never accepted, nor left outstanding, without the C.4.4 budget remaining before `cltv_expiry` | safety (deadline counter) | C.4.4, C.5.6, C.6.4 | no |
| P4 | A signature for one `(chan_id, epoch)` never verifies against another channel or capacity | safety | C.9.1, C.5.2 | no |
| P5 | Eviction and cohort sweep pay every swept leaf exactly `leaf.amount` to its `exit_key` | safety | 7.2 rule 4, 7.7 rule 2, C.5.6 | no |
| P6 | The settlement that confirms is the highest state both parties fully signed | safety | C.3.3, C.3.6 | no |
| L1 | Every honest exit eventually confirms despite a Byzantine operator | liveness | 10.5, C.9.5 | yes |
| L2 | A force-close reaches settlement within `csv_delay` plus bounded contest rounds | bounded liveness | C.5.4, C.9.6 | yes |

Three honesty notes. P1 is safety only after splitting the informal "can
always exit" in two: the safety half is that no reachable state destroys the
owner's ability, since its `(leaf, path)` is either still valid or the new
path is derivable from the witness of the transition that changed it (9.7).
Getting the exit confirmed is L1.

P3 is not naturally safety either, since "resolvable before `cltv_expiry`" is
a claim about the future. The model makes it safety with an explicit deadline
counter: on acceptance the monitor records `cltv_expiry` and the worst-case
budget `G_exit + 2 + csv_delay + G_sweep` (C.4.4), then asserts every tick
that no live HTLC has `height + remaining_budget > cltv_expiry`. That is
faithful only if `G_exit` is, which is why the chain machine models the
descendant limit at all.

L1 needs fairness twice: messages eventually delivered, blocks eventually
mined. With 25 descendants per confirmed tree output a finite tree drains in
finite time, so plain "eventually" holds trivially and the statement worth
checking is the bounded form of C.9.5,
`leaves / 25 < cltv_expiry_delta - csv_delay`, tested against P3's counter.

Out of scope: fee estimation, varops (10.10), signature verification, wire
encodings, and everything the Lean development covers.

## 3. The machines

Seven machine types, two with honest and Byzantine variants. There is no
adversary machine with global powers: adversarial behaviour is the Byzantine
variants' `$` choices, the chain's choice of what confirms and whether to
reorg, the watchtower's lag, and P's scheduler.

### 3.1 Event vocabulary

| Event | Payload | Sender to receiver |
|---|---|---|
| `eNewBlock` | `(height: int)` | Chain to all |
| `eBroadcast` | `(tx: tTx)` | any to Chain |
| `eTxConfirmed` | `(tx: tTx, height: int)` | Chain to all |
| `eTxReplaced` / `eTxRejected` | `(old, by)` / `(tx, why)` | Chain to broadcaster |
| `eReorg` | `(depth: int, orphaned: seq[tTx])` | Chain to all |
| `eJoinOffer` | `(leaf, subpath, treepath, root, total)` | Operator to Owner |
| `eJoinAccept` / `eJoinRefuse` | `(sig)` / `(why)` | Owner to Operator |
| `eExitRequest` | `(pos: int)` | Owner to Operator |
| `eExitGranted` / `eExitRefused` | `(batch: int)` / `()` | Operator to Owner |
| `eUpdateProposal` / `eUpdateSig` | `(old, new)` / `(sig)` | either party to the other |
| `ePathRequest` / `ePathServe` / `ePathWithheld` | `(pos)` / `(root, path)` / `()` | Owner to Operator, and back |
| `eEvictNotice` | `(pos: int, at: int)` | Operator to Owner |
| `eChanSettleSig` / `eChanUpdateSig` | `(n, balances, htlcs, sig)` / `(n, sig)` | Party to Party |
| `eHtlcAdd` / `eHtlcFulfil` / `eHtlcFail` | `(hash, amt, cltv)` / `(preimage)` / `(hash)` | Party to Party |
| `eForceClose` | `(why: tReason)` | Party to self |
| `eTowerArm` / `eTowerSighting` | `(spk, upd, set, sigs)` / `(spk, outpoint)` | Party to Watchtower, Chain to Watchtower |

Monitor-only events, raised with `announce`: `eRootChanged`, `eExitAttempt`,
`eForceCloseStarted`, `eSettleConfirmed`, `eHtlcAccepted`, `eHtlcResolved`.

### 3.2 Chain

The chain owns height, mempool, UTXO set and reorgs, and is where the policy
limits that shape exit throughput live: the 25 descendant bound (10.5,
C.9.5), BIP-125 replacement, TRUC's one-child rule (C.9.6) and reorgs of depth
at most `k`. A participant that treats a leaf as final before its confirmation
depth (10.11) is what `Reorg` exists to catch.

```p
machine Chain {
  var height: int; var mempool: seq[tTx];
  var descendants: map[tOutpoint, int];    // cap 25 per confirmed ancestor
  start state Running {
    on eBroadcast do (tx: tTx) {
      if (Conflicts(mempool, tx)) {        // 10.5: EXIT_1 versus a pending JOIN
        if (tx.feerate > ConflictFeerate(mempool, tx) || $) { Replace(tx); }
        else { send tx.from, eTxRejected, (tx = tx, why = RBF_TOO_LOW); }
        return; }
      if (descendants[Ancestor(tx)] >= 25) { send tx.from, eTxRejected, (tx = tx, why = DESCENDANT_LIMIT); return; }
      if (tx.truc && HasChild(tx.inputs[0])) { send tx.from, eTxRejected, (tx = tx, why = TRUC_ONE_CHILD); return; }
      mempool += (sizeof(mempool), tx); }
    on eMine do { ConfirmSome(); height = height + 1;  // scheduler picks a valid prefix
      if ($) { Reorg(choose(k) + 1); }                 // 10.11, orphans return to the mempool
      announce eNewBlock, (height = height,); }
  }
}
```

### 3.3 TreeOperator

One machine, two personalities chosen at setup. The honest one serves paths,
honours cooperative exit requests (9.3), notifies before evicting (9.4) and
never sweeps a cohort with HTLCs in flight (C.5.6). None of the Byzantine
powers below is a protocol violation: they are legal operator actions whose
cost to others is what we want measured. `FrontRunWithJoin` broadcasts a
`JOIN` conflicting with any owner `EXIT_1` in the mempool, one increment above.

```p
machine TreeOperator {
  var byzantine: bool; var tree: map[int, tLeaf]; var root: tHash;
  start state Serving {
    on eExitRequest do (r: tExitRequest) {                                  // 9.3, 7.6
      if (byzantine && $) { send r.from, eExitRefused; } else { BatchExit(r.pos); } }
    on ePathRequest do (q: tPathRequest) {                                  // 10.9
      if (byzantine && $) { send q.from, ePathWithheld; }
      else { send q.from, ePathServe, (root = root, path = PathOf(q.pos)); } }
    on eUpdateProposal do (p: tUpdate) {                                    // C.6.7
      if (byzantine && $) { return; }
      send p.from, eUpdateSig, (sig = SignOperator(p),); }
    on eNewBlock do {
      if (byzantine && $) { FrontRunWithJoin(); }             // 10.5
      if (byzantine && $) { SweepCohort(choose(NCOHORTS)); }  // 7.7, C.5.6
      if (byzantine && $) { goto Stalling; } }
  }
  state Stalling { ignore eUpdateProposal, eExitRequest, ePathRequest;
                   on eNewBlock do { if ($) { goto Serving; } } }
}
```

### 3.4 Owner

Holds a leaf, a path, and enough state to rebuild that path from the witness
of any confirmed transition (9.7). The model should make it structurally
impossible for the owner to read the operator's tree: that is 10.9.

```p
machine Owner {
  var leaf: tLeaf; var pos: int; var path: tPath; var root: tHash; var deadline: int;
  start state Idle {
    on eTxConfirmed do (c: tConfirm) {                 // 9.7: rebuild from the witness
      if (TouchesTree(c.tx)) { path = RebuildPath(path, pos, c.tx.witness); root = c.tx.newroot; } }
    on eReorg do (r: tReorg) { RollBack(r); }                             // 10.11
    on eEvictNotice do (n: tEvict) { deadline = n.at; goto WantsOut; }
    on eNewBlock do (b: tBlock) { if (b.height >= deadline - MARGIN) { goto WantsOut; } }
  }
  state WantsOut {                                     // 9.3: cooperative exit first
    entry { send operator, eExitRequest, (pos = pos,); }
    on eExitRefused do { goto Exiting; }
    on eNewBlock do { if ($) { goto Exiting; } }       // patience runs out
  }
  state Exiting {
    entry { announce eExitAttempt, (pos = pos, height = Height());
            send chain, eBroadcast, (tx = BuildExit1(leaf, path, root),); }
    on eTxRejected do { goto Exiting; }                // rebuild and rebroadcast
    on eTxReplaced do { goto Exiting; }                // front-run, 10.5
    on eTxConfirmed do (c: tConfirm) { if (IsMine(c.tx)) { goto Exited; } }
  }
  state Exited { ignore eNewBlock, eTxConfirmed, eReorg; }
}
```

### 3.5 ChannelParty

Two per channel leaf, running C.3's LN-Symmetry machine with the C.3.6 signing
order made explicit, because getting it wrong is a real failure mode: a party
that sends its `update_{n+1}` partial before holding `settle_{n+1}` can be
moved to an output only cooperation can drain.

```p
machine ChannelParty {
  var n: int;                  // highest state with BOTH signatures
  var pending_settle: bool;    // holds settle_{n+1} but not update_{n+1}
  var htlcs: map[tHash, tHtlc]; var has_fee_reserve: bool; var csv_left: int;
  start state Open {
    on eHtlcAdd do (h: tHtlc) {                   // C.4.4 budget, C.6.4 lease guard
      if (h.cltv - Height() < Budget() || h.cltv < leaf.evict_after + Budget()) {
        send peer, eHtlcFail, (hash = h.hash,); return; }
      announce eHtlcAccepted, h; htlcs[h.hash] = h; goto Advancing; }
    on eTowerSighting do { goto ForceClosing; }   // C.5.4: watch the spk, not an outpoint
    on eForceClose do { goto ForceClosing; }
    on eNewBlock do (b: tBlock) { if (NearestDeadline() - b.height <= Budget()) { goto ForceClosing; } }
  }
  state Advancing {                                                // C.3.6, strictly ordered
    entry { send peer, eChanSettleSig, (n = n + 1, sig = SignSettle(n + 1)); }
    on eChanSettleSig do { pending_settle = true; send peer, eChanUpdateSig, (n = n + 1, sig = SignUpdate(n + 1)); }
    on eChanUpdateSig do { if (pending_settle) { n = n + 1; pending_settle = false; goto Open; } }
    on eForceClose do { goto ForceClosing; }                       // closes at n, not n+1
  }
  state ForceClosing {
    entry { if (!has_fee_reserve) { goto Stuck; }                  // C.5.5
            announce eForceCloseStarted, (chan = this,);
            send chain, eBroadcast, (tx = Update(n),);
            send chain, eBroadcast, (tx = AnchorChild(Update(n)),); csv_left = CSV_DELAY; }
    on eTxConfirmed do (c: tConfirm) {                             // C.5.4 step 2, contest
      if (IsStaleUpdate(c.tx)) { send chain, eBroadcast, (tx = Update(n),); csv_left = CSV_DELAY; } }
    on eNewBlock do { csv_left = csv_left - 1;
      if (csv_left <= 0) { send chain, eBroadcast, (tx = Settle(n),);
                           announce eSettleConfirmed, (chan = this, n = n); goto Closed; } }
  }
  state Stuck { ignore eNewBlock; }                                // no reserve, nothing to do
  state Closed { ignore eNewBlock; }
}
```

### 3.6 Watchtower

Armed with `(P2TR(exit_key), update_n, settle_n, sigs)` and a fee source
(C.9.3), it matches a scriptPubKey and never an outpoint, which is why the
update machine was chosen over penalties (C.3.1). Its only interesting
variable is `lag`, drawn with `choose(MAXLAG)` on each `eTowerSighting` and
decremented per block before it publishes. That one variable buys the
slow-tower scenario of section 6; nothing else is needed, since the tower
cannot steal (the transactions it holds pay the same outputs whoever
broadcasts them).

## 4. Abstraction choices

The model is worthless if it is big and dishonest if the abstraction hides the
bug. The trade-offs, with what each gives up.

| Concern | Model | Given up |
|---|---|---|
| Hashes | opaque symbolic tokens, equality only | collision resistance, preimage structure: Lean's job |
| Signatures | `(signer, message)` pairs, verification is equality | forgery, malleability, nonce reuse |
| Merkle paths | the operator either serves a path that folds to the current root or does not | the arithmetic of `fold`, sum monotonicity, compression |
| Covenant | an oracle `Accepts(tx, root)` hand written from 7.1 to 7.7 | script encoding, varops, minimal-push rules |
| Amounts | small ints, capacities 1 to 8 | the 2^51 bound, `le64` truncation (10.6) |
| Tree | `map[int, tLeaf]`, `D = 3`, 8 positions, 2 channel leaves, one height-2 cohort | everything visible only at `D = 16` or 10,000 leaves |
| Time | integer block height, one `eNewBlock` per tick | timestamp lock-time ranges (C.3.5), a script concern |
| Fees | a per-party `has_fee_reserve` bool (C.5.5) plus an int feerate for RBF ordering | fee estimation, anchor economics |
| Mempool | a sequence with a descendant counter and a TRUC child flag | ancestor limits, package relay, real eviction |
| Channel state | `n`, balances, a set of HTLCs | `ctx_upd` / `ctx_set` construction, MuSig2 |

Two warnings. The covenant oracle is a reimplementation, and a wrong oracle
proves the wrong thing; section 7 says how it is kept honest. And `D = 3` says
nothing about depth, which is fine, since nothing in section 9 or 10.5 depends
on `D`. What the model does depend on is the ratio of leaves to the per-block
bound, so that bound shrinks with the tree (8 leaves against a cap of 2) to
preserve the shape of C.9.5.

## 5. Concrete spec monitors

**S1 ExitAlwaysAuthorised** (safety, P1). *An honest owner's `EXIT_1` is never
rejected by the covenant, only by chain races it can retry out of.*

```p
spec ExitAlwaysAuthorised observes eExitAttempt, eTxRejected, eRootChanged {
  var root: tHash;
  start state Watching {
    on eRootChanged do (r: tRoot) { root = r.root; }
    on eTxRejected do (r: tRejected) {
      assert r.why != BAD_PROOF && r.why != BAD_SIG,
        format ("10.9 violated: honest exit rejected by the covenant, why={0}", r.why); }
  }
}
```

**S2 ChannelPayoutIsExact** (safety, P2 and P5). *Every payout to a channel
leaf's `exit_key` is exactly `leaf.amount`, and no transition reduces a channel
leaf without both channel parties.* Covers C.6.1, 7.2 rule 4, 7.7 rule 2 and
C.6.5. The `UPDATE` clause is the C.6.6 gap: in a tree created with `UPDATE^x`
(7.4 rule 5) `cosigned_by_exit_key` is always true and the assertion cannot
fire; in a tree created with plain `UPDATE` it reproduces the gap as a
violation rather than hiding it, which is the right outcome for a
configuration the appendix says carries residual trust.

```p
spec ChannelPayoutIsExact observes eTxConfirmed {
  var chanleaf: map[int, tLeaf];
  start state Watching {
    on eTxConfirmed do (c: tConfirm) {
      foreach (p in PayoutsToChannelLeaves(c.tx, chanleaf)) {          // EXIT and EVICT_SUBTREE
        assert p.amount == chanleaf[p.pos].amount, "C.6.1: inexact payout to a channel leaf";
        assert p.spk == P2TR(chanleaf[p.pos].exit_key), "7.2 rule 2: wrong payout script"; }
      if (c.tx.kind == UPDATE && c.tx.pos in chanleaf) {
        assert c.tx.newleaf.amount >= chanleaf[c.tx.pos].amount || c.tx.cosigned_by_exit_key,
          "C.6.6: owner plus operator spliced a channel leaf down"; }
      if (c.tx.kind == CLAIM) { assert !(c.tx.source_pos in chanleaf), "C.6.5: CLAIM against a channel leaf"; }
    }
  }
}
```

**S3 HtlcDeadlineBudget** (safety with a deadline counter, P3). *No HTLC is
accepted without the C.4.4 budget, and none survives past the point where the
budget no longer fits.* `AdvancePhase` shrinks the budget as the force-close
proceeds: all of it before the `EXIT` confirms, then `2 + csv_delay + G_sweep`,
and so on. This is where cohort eviction (C.5.6) and the 25-per-block bound
(C.9.5) become an assertion instead of prose.

```p
spec HtlcDeadlineBudget observes eHtlcAccepted, eHtlcResolved, eTxConfirmed, eNewBlock {
  var live: map[tHash, (cltv: int, chan: machine)]; var height: int;
  start state Watching {
    on eHtlcAccepted do (h: tHtlc) {
      assert h.cltv - height >= Budget(h.chan), "C.4.4: HTLC accepted without budget";
      live[h.hash] = (cltv = h.cltv, chan = h.chan); }
    on eHtlcResolved do (h: tHtlc) { live -= (h.hash); }
    on eTxConfirmed do (c: tConfirm) { AdvancePhase(c); }
    on eNewBlock do (b: tBlock) { height = b.height;
      foreach (k in keys(live)) {
        assert height + Budget(live[k].chan) <= live[k].cltv,
          format ("C.4.4 budget exhausted for {0} at height {1}", k, height); } }
  }
}
```

**S4 NoStaleSettlement** (safety, P6). *The settlement that confirms is for the
highest state both parties fully signed.* The first assertion catches the C.3.6
ordering bug on its own, before any settlement happens.

```p
spec NoStaleSettlement observes eChanSettleSig, eChanUpdateSig, eSettleConfirmed {
  var signed_settle: map[machine, int]; var complete: map[machine, int];
  start state Watching {
    on eChanSettleSig do (s: tSettleSig) { signed_settle[s.chan] = s.n; }
    on eChanUpdateSig do (u: tUpdateSig) {
      assert signed_settle[u.chan] >= u.n, "C.3.6: update_n signed before settle_n";
      complete[u.chan] = u.n; }
    on eSettleConfirmed do (s: tSettled) {
      assert s.n == complete[s.chan], "C.3.3: a state other than the latest settled"; }
  }
}
```

**S5 ExitEventuallyConfirms** (liveness, L1). *Every honest exit attempt
eventually confirms.* Hot while any exit is outstanding. Needs blocks mined
infinitely often and the BIP-125 increment, which stops the Byzantine operator
replacing forever for free.

```p
spec ExitEventuallyConfirms observes eExitAttempt, eTxConfirmed {
  var outstanding: set[int];
  start cold state Quiet {
    on eExitAttempt do (a: tAttempt) { outstanding += (a.pos); goto Pending; }
  }
  hot state Pending {
    on eExitAttempt do (a: tAttempt) { outstanding += (a.pos); }
    on eTxConfirmed do (c: tConfirm) {
      foreach (p in c.tx.payouts) { outstanding -= (p.pos); }
      if (sizeof(outstanding) == 0) { goto Quiet; } }
  }
}
```

**S6 ForceCloseTerminates** (bounded liveness, L2) has the same shape as S5:
cold `Idle`, hot `Closing` entered on `eForceCloseStarted` and left on
`eSettleConfirmed`, with a counter initialised to
`CSV_DELAY * (MAXCONTEST + 1) + SLACK` and decremented on every `eNewBlock`
under an assertion that it stays positive. The counter is what separates
"eventually" from C.5.4's timing table, and it is what a party with no fee
reserve violates by sitting in `Stuck`.

P4 (replay across `(chan_id, epoch)`, C.9.1 and C.5.2) is checked structurally
rather than by a monitor: the signature token carries its context, so
verification against a different `(C, epoch)` simply fails, and the assertion
lives in `ChannelParty`'s splice path, where C.5.2 rule 1 requires a new
`exit_key` per epoch. A monitor would only restate the type.

## 6. Scenarios to seed the scheduler with

P finds these unaided given enough state space, but the space is large and the
scenarios are known, so each gets a driver that builds the topology and then
hands over to the scheduler.

| # | Scenario | Setup | Stresses |
|---|---|---|---|
| A1 | Mass eviction of a cohort with HTLCs in flight (C.5.6) | 4 channel leaves in one height-2 subtree, 2 live HTLCs, operator calls `SweepCohort` | S3, S6 |
| A2 | Repeated `JOIN` front-running of an owner `EXIT` (10.5) | one owner in `Exiting`, operator front-runs every block | S5, and S3 for a channel leaf |
| A3 | Stale state with a slow watchtower (C.3.3, C.9.3) | V publishes `update_j`, `j < n`; tower lag up to `MAXLAG` | S4, S6 |
| A4 | `evict_after` in the future with a short HTLC (C.6.4) | `evict_after = height + 20`, HTLC `cltv = height + 10` | S3: the counterparty has no unilateral path at all |
| A5 | Reorg reverting an `EXIT` after the update chain started (C.5.4, 10.11) | force-close in progress, `k`-block reorg including the `EXIT` | S2, S4, S6 |
| A6 | Fee reserve exhaustion (C.5.5) | both parties with `has_fee_reserve = false` after the exit confirms | S6, and it should fail |

A6 is listed because a model containing only scenarios it passes is not telling
the truth. The expected outcome is a counterexample reaching `Stuck`, which is
the model restating C.5.5's requirement that both parties hold a confirmed
UTXO; the fix is to the test configuration, not the model. A4 deserves the same
treatment: set up honestly it is refused by the `Open` guard, and a deliberate
mutation of that guard should make S3 fail. A property no mutation can break is
not being checked.

## 7. What P will not show, and where it hands off

A green P run is easy to over-read, so: the model says nothing about the
following.

To Lean, in `formal/`: that `fold` binds the leaf, so a forged leaf or a stale
root cannot reproduce the committed root (7.1 rule 3, 10.2); conservation, that
rules 7.1.3 and 7.1.5 make value creation impossible for any `D`; voucher
non-replay as a property of the construction (7.5), as opposed to the model's
version, which is "the oracle refuses because we wrote it that way"; and the
`seq + 1` overflow argument for `SEQ_FINAL` (5.2, C.6.5).

To `tools/`: the oracle `Accepts(tx, root)` is a hand reading of 7.1 to 7.7 and
must be differentially tested against `tools/layertree_ref.py` on
`spec/test-vectors.json` and `spec/golden.json`. Every transition it accepts
must be one the reference builds and `tools/script_sim.py` executes, and every
negative case in `tools/test_scripts.py` (forged leaf, stale root,
attacker-chosen `m`, unconserved amount, early eviction, evictor shortchange,
voucher replay, over-claim) must be one it rejects. Without this the model
checks a protocol nobody implemented. Sizes, varops (10.10) and encodings stay
with the simulator and the Go tests. Real mempool behaviour stays with a
regtest harness: the chain machine's descendant counter is a caricature, and
the 25-per-block figure of 10.5 should be confirmed against a node.

Neither side covers two things. The operator is modelled as adversarial, not
profit maximising, which is stricter in some places and weaker in others, since
a rational griefer may pick strategies the Byzantine variant does not
enumerate. And scale: nothing here speaks to `D = 16` at 10,000 leaves. That
argument is arithmetic and belongs in C.9.5.

## 8. Layout and effort

```
formal/p/
  P.proj                  project file, source and test globs
  README.md               how to run, how to read a counterexample
  src/Common.p            types, constants, tree and budget helpers
  src/Covenant.p          Accepts(tx, root): sections 7.1 to 7.7
  src/Chain.p             blocks, mempool, RBF, TRUC, descendants, reorg
  src/Operator.p          honest and Byzantine TreeOperator
  src/Owner.p             Owner, path maintenance per 9.7
  src/Channel.p           ChannelParty (C.3, C.4) and Watchtower (C.9.3)
  spec/ExitSafety.p       S1
  spec/ChannelSafety.p    S2, S4
  spec/HtlcDeadline.p     S3
  spec/Liveness.p         S5, S6
  tst/TestDrivers.p       topologies: plain tree, channel hub, cohort
  tst/Scenarios.p         A1 to A6
  tst/TestScripts.p       test declarations binding monitors to drivers
  vectors/oracle.json     shared with tools/, differential input for Covenant.p
```

| Step | Estimate |
|---|---|
| `Common.p`, `Covenant.p`, differential harness against `tools/` | 1.5 weeks |
| `Chain.p` with policy limits and reorgs | 1 week |
| `Operator.p`, `Owner.p`, scenario A2, monitors S1 and S5 | 1 week |
| `Channel.p`, the watchtower, monitors S2, S3, S4, S6 | 2 weeks |
| Scenarios A1, A3, A4, A5, A6, state-space tuning | 1 week |
| Mutation testing of the guards, README, CI wiring | 0.5 weeks |

About seven weeks for one person who knows the spec and is learning P as they
go. The first two steps decide whether the rest is worth anything: if the
differential harness against `tools/layertree_ref.py` cannot be built cheaply,
the exercise should be reconsidered, because a covenant oracle nobody checks is
a model of a protocol nobody wrote.
