# Notes

Distilled from personal vault mentions of "layertree" (2025-03-09 through 2026-W38).

## Concept origin (2025-03-09)

- Emerged from work on CSFS + OP_CAT + EC_OPs and a batched-support voucher
  technique.
- Without additional soft forks, the main path is to partition state, with
  events propagating between states via hashes or adaptor signatures (see the
  PR into btcd).
- Applications of the underlying unified batching: loops into/out of an
  account, channel purchases, direct USDT swaps, and novation for
  future/option DLCs.

## Design sketch (`pages/layertree.md`)

- Open items:
  - Start on musig2 adapter sig implementation.
  - Give a birds-eye view of transfer — hyperloop vs. self-funded factory
    (not much difference between them): settlements stay in a new channel
    created with a coordinator; first phase is indefinite; creates a new
    AS (account set?) with a set of existing UTXOs.
  - Flows: loop in to a channel routes over the virtual network (on-chain
    HTLC, off-chain from there into the public network); loop out sends
    off-chain from LN into the LayerTree account.
  - Unified liquidity marketplace: lets other nodes contribute liquidity for
    loop swaps, aims for no instance where the system can't service a swap,
    taps both off-chain and on-chain liquidity.
- Earlier note (2025-06-02): flagged as a priority pipeline, paired with a
  blog post idea on Reigns re: funding for Ark batches.

## Status as tracked in the vault (2026)

- Captured 2026-08-20 as a post-vacation TaskNote (`finish-layertree`,
  priority high, due/scheduled 2026-09-30). "Finish" was ambiguous at capture
  time — could mean finishing the writeup or the musig2 adapter sig impl;
  needed confirmation on return.
- Repeatedly flagged across weekly reviews (W34, W35, W37, W38) as one of
  three items cold since 2026-08-20 (alongside `release-zk-tap` and
  `google-vuln-detection-system`), parked at a 2026-09-30 due date rather
  than actively worked.
- `strategic-threads-sept-2026` review: under the "growth is the only thing
  that matters" decision rule, this item does not pass the growth test —
  flagged as a candidate to demote or delegate rather than keep as an active
  commitment.
