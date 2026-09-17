# Notes

Distilled from personal vault mentions of "layertree" (2025-03-09 through
2026-W38). The raw source note is copied into this repo at
`design/layertree.md` since the vault itself isn't on GitHub. The full
write-up on the underlying unified batching concept — the essay LayerTree
was named in — is copied verbatim at `design/unified-batching.md`.

## Concept origin (2025-03-09)

LayerTree first shows up in a journal entry under a broader thread on
unified batching:

- The entry point is CSFS + OP_CAT + EC_OPs, plus a batched-support voucher
  technique — the covenant primitives that let a single on-chain output
  represent, and later unbundle into, many independent off-chain
  obligations.
- Without additional soft forks, the main path forward is to partition
  state: rather than one monolithic channel/UTXO tracking everything, state
  is split across a tree of sub-states.
- Events propagate between those states via hashes or adaptor signatures —
  i.e., revealing a preimage or a signature in one branch can trigger or
  authorize a transition in another, without needing a new soft fork to wire
  them together. (Referenced against "the PR into btcd" — the specific PR
  isn't identified in the note.)
- Applications called out for this unified batching primitive:
  - Loops into and out of an account (see the transfer flows below).
  - Channel purchases.
  - Direct USDT swaps.
  - Novation for future/option DLCs (rolling an existing discreet log
    contract forward into a new one without fully unwinding on-chain).

## Design sketch (`design/layertree.md`)

The working design note (raw bullets preserved verbatim in
`design/layertree.md`) covers two open items and a supporting idea:

**1. musig2 adapter sig implementation** — flagged as a to-do, not yet
started. This is presumably the signing primitive underlying the
hash/adaptor-signature propagation described above: adaptor signatures
built on MuSig2 aggregate keys, so that revealing one party's adapted
signature both settles their leg and hands the counterparty the secret
needed to settle theirs.

**2. Transfer mechanism — hyperloop vs. self-funded factory.** The note
treats these two as nearly equivalent:

- Settlements stay inside a new channel created with a coordinator.
- The first phase is indefinite (open-ended, not time-boxed).
- This creates a new "AS" (account set) backed by a set of existing UTXOs —
  i.e., the coordinator seeds the new construct from UTXOs that already
  exist rather than requiring fresh on-chain funding.

Flows through the transfer mechanism:
- *Loop in*: enter a channel, then route over the virtual network. Concretely:
  an on-chain HTLC settles off-chain, and from there routing continues into
  the initial entrance of the public Lightning network.
- *Loop out*: the reverse — send off-chain from LN into the LayerTree
  account.

**3. Unified liquidity marketplace** — a supporting idea rather than a
separate open item:
- Lets other nodes contribute liquidity to service loop in/out swaps,
  rather than relying on a single liquidity provider.
- Goal: there should never be an instance where the system can't service a
  swap, because it can tap both off-chain and on-chain liquidity as needed.

An earlier, sparser mention (2025-06-02) lists "LAYER TREE PIPELINE" as a
priority item, paired with an unrelated blog-post idea on Reigns re: funding
for Ark batches — suggesting LayerTree was being thought about in the same
frame as Ark-style batched channel constructions.

## Status as tracked in the vault (2026)

- Captured 2026-08-20 as a post-vacation TaskNote (`finish-layertree`,
  priority high, due/scheduled 2026-09-30). The capture note itself flags
  that "finish" is ambiguous — it could mean finishing the writeup
  (the design sketch above) or finishing the musig2 adapter sig
  implementation — and says this needed to be confirmed on return before
  scheduling real time against it.
- Repeatedly flagged across weekly reviews (W34, W35, W37, W38) as one of
  three items that have been cold since 2026-08-20 (alongside
  `release-zk-tap` and `google-vuln-detection-system`), each time parked at
  a 2026-09-30 due date rather than actively worked. The W35 review notes
  these are "not 'due Monday' in any real sense; they are unscheduled work
  wearing a Monday date."
- The `strategic-threads-sept-2026` strategy doc applies a new decision
  rule — "growth is the only thing that matters" — and under that rule,
  LayerTree does not pass the growth test. It's grouped with the other two
  cold items as a candidate to demote or hand off rather than keep as an
  active personal commitment, though the doc is explicit this isn't a
  unilateral call to make.
