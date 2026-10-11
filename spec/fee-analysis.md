# Exit economics at various fee rates

*(informative, draft)* This section quantifies the on-chain cost of exiting
a LayerTree at a range of fee rates, and compares it against the floor cost
of any on-chain payment and against an Ark/CTV-style unilateral exit. All
tables below are the literal output of `tools/fee_analysis.py`, which
parses the measured sizes in `spec/scripts/sizes.md` and applies the
transaction model stated once at the head of section 11 (measured
witness, 946 WU skeleton, 172 WU per further payout, `vB = ceil(WU / 4)`,
witness length prefixes excluded); the prose around the tables is
maintained by hand. Regenerate with:

```
python3 tools/fee_analysis.py
```

## Assumptions

State every number here explicitly; nothing below is looked up live.

* **Model.** The one stated at the head of section 11. Measured witness:
  script, witness elements and a 129-byte control block for the
  eight-leaf reference script set of 6.2 (11.1 prices larger sets, 8 vB
  per doubling). Skeleton: tree input 41 vB, P2WPKH fee input 41 vB +
  108 WU witness, tree output 43 vB, payout output 43 vB (one per exit,
  43 vB more for each additional payout in a batch), change output 31 vB,
  version/locktime/counts ~10 vB, marker+flag 2 WU. Non-witness bytes cost
  4 WU, witness bytes cost 1 WU. Exogenous-fee skeleton totals **946 WU**
  for one payout; each extra payout adds **172 WU** (43 vB). The
  FULL-tier **endogenous** fee model (fee taken out of the payout, no fee
  input, no change output) totals **550 WU** for one payout.
* **vbytes.** `vbytes = ceil(weight_WU / 4)`, rounded once per
  transaction.
* **Excluded.** The witness item count and per-item length prefixes, as
  in section 11. `spec/scripts/weights.md` measures them on serialised
  transactions: 10.5 vB on a FULL dense `D = 16` `EXIT_1` (1,030 vB
  measured against 1,020 here), 10 vB in CCV, 42.5 vB in MID (1,398
  against 1,355) and 44.75 vB in MIN (1,518 against 1,473), the `0xC0`
  tiers carrying over 160 witness items. Every row below omits them the
  same way.
* **Sparse rows.** The sparse witness figures in `spec/scripts/sizes.md`
  are measured on a six-leaf tree (two non-empty siblings), so the sparse
  rows below are `N = 6` figures. At `N = 2^16` the witness grows by about
  41 bytes per further non-empty sibling: 1,780 vB at `D = 32` and
  2,870 vB at `D = 64` (section 11).
* **Fee.** `fee_sat = vbytes * fee_rate_sat_per_vb` (fee rates: 1, 2, 5, 10,
  25, 50, 100, 250 sat/vB).
* **Dust.** P2TR dust limit assumed at 330 sat (a payout output below this
  is non-standard).
* **Ark/CTV model.** A unilateral exit from a radix-2 tree of `2^D` leaves
  is modelled as `D` transactions of ~600 WU (150 vB) each plus one
  leaf-claim transaction assumed to cost the same as a plain P2TR spend
  (~111 vB). This is a modelling simplification (section 11's own figure),
  not a measurement of any specific Ark implementation; real
  implementations may differ (e.g. batched unrolling, different leaf
  script sizes).
* **EVICT_SUBTREE leaf counts.** 13 leaves for `EVICT_SUBTREE_4` and 51 for
  `EVICT_SUBTREE_6` at `D = 16`, per section 11 (every fifth position
  already empty in the measured tree, `tools/test_scripts.py`: 3 of 16
  and 13 of 64).
* **USD figures.** Illustrative only, at a placeholder price of
  **100,000 USD/BTC** (`1 sat = $0.001`). Not a market quote; substitute
  your own price to rescale linearly.

## Weight, vbytes and fee by profile, tier and depth

| case | total witness (WU) | tx weight (WU) | vbytes | 1 sat/vB | 2 sat/vB | 5 sat/vB | 10 sat/vB | 25 sat/vB | 50 sat/vB | 100 sat/vB | 250 sat/vB |
|---|---|---|---|---|---|---|---|---|---|---|---|
| FULL dense EXIT_1, D=8 | 2100 | 3046 | 762 | 762 | 1,524 | 3,810 | 7,620 | 19,050 | 38,100 | 76,200 | 190,500 |
| FULL dense EXIT_1, D=12 | 2616 | 3562 | 891 | 891 | 1,782 | 4,455 | 8,910 | 22,275 | 44,550 | 89,100 | 222,750 |
| FULL dense EXIT_1, D=16 | 3132 | 4078 | 1020 | 1,020 | 2,040 | 5,100 | 10,200 | 25,500 | 51,000 | 102,000 | 255,000 |
| FULL dense EXIT_1, D=20 | 3648 | 4594 | 1149 | 1,149 | 2,298 | 5,745 | 11,490 | 28,725 | 57,450 | 114,900 | 287,250 |
| FULL sparse EXIT_1, D=32 | 5602 | 6548 | 1637 | 1,637 | 3,274 | 8,185 | 16,370 | 40,925 | 81,850 | 163,700 | 409,250 |
| FULL sparse EXIT_1, D=64 | 9954 | 10900 | 2725 | 2,725 | 5,450 | 13,625 | 27,250 | 68,125 | 136,250 | 272,500 | 681,250 |
| MID dense EXIT_1, D=16 | 4474 | 5420 | 1355 | 1,355 | 2,710 | 6,775 | 13,550 | 33,875 | 67,750 | 135,500 | 338,750 |
| MIN dense EXIT_1, D=16 | 4944 | 5890 | 1473 | 1,473 | 2,946 | 7,365 | 14,730 | 36,825 | 73,650 | 147,300 | 368,250 |

Illustrative USD, at 10 sat/vB and 100 sat/vB, $100,000/BTC:

| case | fee @ 10 sat/vB | ≈ USD | fee @ 100 sat/vB | ≈ USD |
|---|---|---|---|---|
| FULL dense EXIT_1, D=8 | 7,620 sat | $0.76 | 76,200 sat | $7.62 |
| FULL dense EXIT_1, D=16 | 10,200 sat | $1.02 | 102,000 sat | $10.20 |
| FULL dense EXIT_1, D=20 | 11,490 sat | $1.15 | 114,900 sat | $11.49 |
| FULL sparse EXIT_1, D=32 | 16,370 sat | $1.64 | 163,700 sat | $16.37 |
| FULL sparse EXIT_1, D=64 | 27,250 sat | $2.73 | 272,500 sat | $27.25 |
| MID dense EXIT_1, D=16 | 13,550 sat | $1.36 | 135,500 sat | $13.55 |
| MIN dense EXIT_1, D=16 | 14,730 sat | $1.47 | 147,300 sat | $14.73 |

Reading this table: depth costs about 30 WU per level of script plus witness
(the D=8 -> D=20 spread is only 762 -> 1,149 vbytes, +51%, over a 4,096x
increase in tree size); one tier step costs as much as 10 to 14 levels of
depth (MID is +33%, MIN is +44% over FULL at the same D=16); sparse costs
about 1.6-2.7x dense on the six-leaf measurement above (1.7 to 2.8x at
N = 2^16), because a sparse tree needs D=32-64 levels of proof where a
dense tree needs 8-20.

## EXIT_2: marginal cost of a second exit in the same transaction

| case | total witness (WU) | tx weight (WU) | vbytes | 1 sat/vB | 2 sat/vB | 5 sat/vB | 10 sat/vB | 25 sat/vB | 50 sat/vB | 100 sat/vB | 250 sat/vB |
|---|---|---|---|---|---|---|---|---|---|---|---|
| EXIT_1, D=16 dense (1 payout) | 3132 | 4078 | 1020 | 1,020 | 2,040 | 5,100 | 10,200 | 25,500 | 51,000 | 102,000 | 255,000 |
| EXIT_2, D=16 dense (2 payouts) | 5617 | 6735 | 1684 | 1,684 | 3,368 | 8,420 | 16,840 | 42,100 | 84,200 | 168,400 | 421,000 |

Second exit, marginal (2,485 WU of extra witness + 172 WU for its own
payout output = 2,657 WU, ≈ 665 vbytes) versus 1,020 vbytes for a
standalone `EXIT_1`:

| | marginal vbytes | 1 sat/vB | 2 sat/vB | 5 sat/vB | 10 sat/vB | 25 sat/vB | 50 sat/vB | 100 sat/vB | 250 sat/vB |
|---|---|---|---|---|---|---|---|---|---|
| second exit (marginal) | 665 | 665 | 1,330 | 3,325 | 6,650 | 16,625 | 33,250 | 66,500 | 166,250 |

Batching a second exit into the same transaction costs 665 vbytes instead
of 1,020: a 35% saving over two separate transactions, growing with `K`
since only the payout output and the leaf's own proof are marginal (no
repeated skeleton, no repeated `TREE_SPK`/prologue cost).

## EVICT_SUBTREE_h: cohort sweep, per-leaf cost

| case | leaves swept | tx weight (WU) | vbytes | vbytes/leaf | 1 sat/vB | 2 sat/vB | 5 sat/vB | 10 sat/vB | 25 sat/vB | 50 sat/vB | 100 sat/vB | 250 sat/vB |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| EVICT_SUBTREE_4, D=16 (13 leaves) | 13 | 10,549 | 2,638 | 202.9 | 202.92 | 405.85 | 1,014.62 | 2,029.23 | 5,073.08 | 10,146.15 | 20,292.31 | 50,730.77 |
| EVICT_SUBTREE_6, D=16 (51 leaves) | 51 | 32,227 | 8,057 | 158.0 | 157.98 | 315.96 | 789.90 | 1,579.80 | 3,949.51 | 7,899.02 | 15,798.04 | 39,495.10 |

(figures per row: sat per leaf at each fee rate). Per-leaf cost falls from
1,020 vbytes (standalone `EXIT_1`, D=16) to 203 vbytes (`EVICT_SUBTREE_4`,
13 leaves) to 158 vbytes (`EVICT_SUBTREE_6`, 51 leaves): a **5x-6.5x**
reduction in per-leaf fee versus individual exits, and it keeps improving
with cohort size because the sweep hashes the subtree's internal nodes
once instead of once per leaf.

## Comparison points

**(a) Plain P2TR -> P2TR.** The floor cost of any on-chain movement,
independent of any tree: ~111 vB.

| case | vbytes | 1 sat/vB | 2 sat/vB | 5 sat/vB | 10 sat/vB | 25 sat/vB | 50 sat/vB | 100 sat/vB | 250 sat/vB |
|---|---|---|---|---|---|---|---|---|---|
| plain P2TR -> P2TR | 111 | 111 | 222 | 555 | 1,110 | 2,775 | 5,550 | 11,100 | 27,750 |

**(b) Ark/CTV-style unilateral exit**, `D` transactions of ~150 vB plus a
~111 vB leaf claim (`D * 150 + 111` vbytes):

| case | D (txs) | vbytes | 1 sat/vB | 2 sat/vB | 5 sat/vB | 10 sat/vB | 25 sat/vB | 50 sat/vB | 100 sat/vB | 250 sat/vB |
|---|---|---|---|---|---|---|---|---|---|---|
| D=8 (256 leaves) | 8 | 1,311 | 1,311 | 2,622 | 6,555 | 13,110 | 32,775 | 65,550 | 131,100 | 327,750 |
| D=12 (4,096 leaves) | 12 | 1,911 | 1,911 | 3,822 | 9,555 | 19,110 | 47,775 | 95,550 | 191,100 | 477,750 |
| D=16 (65,536 leaves) | 16 | 2,511 | 2,511 | 5,022 | 12,555 | 25,110 | 62,775 | 125,550 | 251,100 | 627,750 |
| D=20 (1,048,576 leaves) | 20 | 3,111 | 3,111 | 6,222 | 15,555 | 31,110 | 77,775 | 155,550 | 311,100 | 777,750 |
| D=24 (16,777,216 leaves) | 24 | 3,711 | 3,711 | 7,422 | 18,555 | 37,110 | 92,775 | 185,550 | 371,100 | 927,750 |
| D=32 (4,294,967,296 leaves) | 32 | 4,911 | 4,911 | 9,822 | 24,555 | 49,110 | 122,775 | 245,550 | 491,100 | 1,227,750 |

At D=16, a LayerTree FULL dense exit is 1,020 vbytes against 2,511 vbytes
for the Ark-style model: **2.5x cheaper**, growing with `D` since LayerTree
adds ~30 vbytes/level and Ark adds ~150 vbytes/level (a full transaction)
per level.

## Break-even balance: fee as a fraction of the exit

Leaf amount (balance) at which the fee equals 1%, 5% or 10% of the
balance, at each fee rate.

**FULL dense EXIT_1, D=8** (762 vbytes)

| fee rate (sat/vB) | fee (sat) | balance @ 1% | balance @ 5% | balance @ 10% |
|---|---|---|---|---|
| 1 | 762 | 76,200 | 15,240 | 7,620 |
| 2 | 1,524 | 152,400 | 30,480 | 15,240 |
| 5 | 3,810 | 381,000 | 76,200 | 38,100 |
| 10 | 7,620 | 762,000 | 152,400 | 76,200 |
| 25 | 19,050 | 1,905,000 | 381,000 | 190,500 |
| 50 | 38,100 | 3,810,000 | 762,000 | 381,000 |
| 100 | 76,200 | 7,620,000 | 1,524,000 | 762,000 |
| 250 | 190,500 | 19,050,000 | 3,810,000 | 1,905,000 |

**FULL dense EXIT_1, D=16** (1,020 vbytes)

| fee rate (sat/vB) | fee (sat) | balance @ 1% | balance @ 5% | balance @ 10% |
|---|---|---|---|---|
| 1 | 1,020 | 102,000 | 20,400 | 10,200 |
| 2 | 2,040 | 204,000 | 40,800 | 20,400 |
| 5 | 5,100 | 510,000 | 102,000 | 51,000 |
| 10 | 10,200 | 1,020,000 | 204,000 | 102,000 |
| 25 | 25,500 | 2,550,000 | 510,000 | 255,000 |
| 50 | 51,000 | 5,100,000 | 1,020,000 | 510,000 |
| 100 | 102,000 | 10,200,000 | 2,040,000 | 1,020,000 |
| 250 | 255,000 | 25,500,000 | 5,100,000 | 2,550,000 |

**FULL dense EXIT_1, D=20** (1,149 vbytes)

| fee rate (sat/vB) | fee (sat) | balance @ 1% | balance @ 5% | balance @ 10% |
|---|---|---|---|---|
| 1 | 1,149 | 114,900 | 22,980 | 11,490 |
| 2 | 2,298 | 229,800 | 45,960 | 22,980 |
| 5 | 5,745 | 574,500 | 114,900 | 57,450 |
| 10 | 11,490 | 1,149,000 | 229,800 | 114,900 |
| 25 | 28,725 | 2,872,500 | 574,500 | 287,250 |
| 50 | 57,450 | 5,745,000 | 1,149,000 | 574,500 |
| 100 | 114,900 | 11,490,000 | 2,298,000 | 1,149,000 |
| 250 | 287,250 | 28,725,000 | 5,745,000 | 2,872,500 |

**FULL sparse EXIT_1, D=32** (1,637 vbytes)

| fee rate (sat/vB) | fee (sat) | balance @ 1% | balance @ 5% | balance @ 10% |
|---|---|---|---|---|
| 1 | 1,637 | 163,700 | 32,740 | 16,370 |
| 2 | 3,274 | 327,400 | 65,480 | 32,740 |
| 5 | 8,185 | 818,500 | 163,700 | 81,850 |
| 10 | 16,370 | 1,637,000 | 327,400 | 163,700 |
| 25 | 40,925 | 4,092,500 | 818,500 | 409,250 |
| 50 | 81,850 | 8,185,000 | 1,637,000 | 818,500 |
| 100 | 163,700 | 16,370,000 | 3,274,000 | 1,637,000 |
| 250 | 409,250 | 40,925,000 | 8,185,000 | 4,092,500 |

## Minimum economical leaf size

Below this leaf amount the exit is a net loss (fee >= balance) or the
payout output cannot clear the 330 sat P2TR dust limit. Exogenous: leaf
pays out in full, fee comes from elsewhere, floor = `max(fee, dust) + 1`.
Endogenous (FULL-tier owner exit only): fee is deducted from the payout,
floor = `fee + dust + 1`, computed against the endogenous transaction's own
(smaller) vbytes.

**FULL D=16, exogenous**: 1,020 vbytes. **FULL D=16, endogenous**: 921 vbytes.

| fee rate (sat/vB) | exo fee (sat) | min leaf, exogenous | endo fee (sat) | min leaf, endogenous |
|---|---|---|---|---|
| 1 | 1,020 | 1,021 | 921 | 1,252 |
| 2 | 2,040 | 2,041 | 1,842 | 2,173 |
| 5 | 5,100 | 5,101 | 4,605 | 4,936 |
| 10 | 10,200 | 10,201 | 9,210 | 9,541 |
| 25 | 25,500 | 25,501 | 23,025 | 23,356 |
| 50 | 51,000 | 51,001 | 46,050 | 46,381 |
| 100 | 102,000 | 102,001 | 92,100 | 92,431 |
| 250 | 255,000 | 255,001 | 230,250 | 230,581 |

At the fee rates operators actually see in practice (roughly 1-50 sat/vB),
the dust limit is never the binding constraint for a D=16 exit; the fee
itself is. Dust only binds at very low fee rates or very small trees (a
D=8 exit at 1 sat/vB has a fee of 762 sat, still above dust).

## Endogenous vs. exogenous fees (FULL tier owner exit)

| case | total witness (WU) | tx weight (WU) | vbytes | 1 sat/vB | 2 sat/vB | 5 sat/vB | 10 sat/vB | 25 sat/vB | 50 sat/vB | 100 sat/vB | 250 sat/vB |
|---|---|---|---|---|---|---|---|---|---|---|---|
| FULL D=16, exogenous (fee input + change) | 3132 | 4078 | 1020 | 1,020 | 2,040 | 5,100 | 10,200 | 25,500 | 51,000 | 102,000 | 255,000 |
| FULL D=16, endogenous (fee from payout) | 3132 | 3682 | 921 | 921 | 1,842 | 4,605 | 9,210 | 23,025 | 46,050 | 92,100 | 230,250 |

Saving: 396 WU, ≈ 99 vbytes per exit (a 9.7% reduction at D=16). This
saving is a constant 99 vbytes for every profile/tier/D — it comes only
from dropping the fee input (41 vB + 27 vB witness) and the change output
(31 vB), not from the transition script — so its *relative* size shrinks as
D or the sparse profile grows the script, and its *absolute* size (and
absolute sat cost at a given fee rate) never changes. An owner who holds no
other coins should always prefer the endogenous form; an owner who wants a
specific payout amount (e.g. to preserve round numbers, or because a
counterparty expects an exact value) should use the exogenous form and
supply the fee separately.

## Analysis

**Which depth/profile/tier for which balance.** At typical fee rates
(5-25 sat/vB) a FULL dense tree is economical for exits well under 100,000
sat: a D=16 exit at 10 sat/vB costs 10,200 sat, 1% of a 1,020,000 sat
(~0.01 BTC) balance. Depth barely matters (D=8 to D=20 spans 762-1,149
vbytes, +51%, across a 4,096x range of tree size) so operators should pick
D for their addressing needs, not to save fees. Tier matters much more:
MID costs +33% and MIN +44% over FULL at the same D, so a chain that has
not activated the FULL opcode set pays a real, fixed tax on every exit
regardless of tree size. The sparse profile costs 1.6x (D=32) to 2.7x
(D=64) a comparable dense exit on the six-leaf measurement (1.7x to 2.8x
at N = 2^16); use it only where key-addressed positions
(no slot allocation, history-independent root) are worth that premium —
for balances under about 20,000-50,000 sat at 10-25 sat/vB, a sparse exit
can consume more than 5% of the balance in fees. Below a few thousand
satoshis at any but the lowest fee rates, no configuration is economical.

**Batching (EXIT_K).** A second owner exit folded into the same
transaction (`EXIT_2`) costs 665 marginal vbytes against 1,020 for a
second standalone transaction: a 35% saving, and the saving's *share* of
the total grows with `K` since the per-step marginal cost (leaf + proof +
payout output) stays constant while the shared prologue and skeleton do
not repeat. Operators processing cooperative exits should batch them
whenever more than one owner exits in the same window.

**Cohort sweeps (EVICT_SUBTREE_h).** These are the largest lever in this
document: per-leaf eviction cost falls from 1,020 vbytes (standalone) to
203 vbytes (13-leaf cohort) to 158 vbytes (51-leaf cohort) — a 5x-6.5x
reduction, improving further with cohort size since only the subtree's
internal nodes are hashed once regardless of how many leaves it holds.
This is the mechanism that makes eviction viable at low leaf balances: a
1,000 sat leaf that cannot cover a 10,200 sat standalone `EXIT_1` fee at 10
sat/vB can still be swept for about 1,580-2,030 sat as part of a cohort at
the same rate.

**Recommendation.** Operators should size cohorts (subtree height `h`) and
lease durations (`evict_after`) so that, at the fee rates they expect to
prevail when the lease is likely to expire, `EVICT_SUBTREE_h`'s per-leaf
cost stays comfortably below the smallest leaf amount the tree permits.
Concretely: pick the smallest permitted leaf balance `L`, the fee-rate
tail the operator wants to survive (e.g. the 90th-percentile rate seen in
the last year), and choose `h` such that per-leaf sweep cost at that rate
is a small fraction (say <=10%) of `L`. Because per-leaf cost keeps falling
with cohort size (see the table above), erring toward larger cohorts costs
nothing but coordination and reduces the risk of an un-sweepable dust
cohort during a fee spike. Individually-evictable (non-cohort) leaves
should carry a floor balance high enough to cover a standalone `EXIT_1` at
the same tail fee rate, which is a materially higher floor.

**Versus Ark/CTV.** At the depths compared here, LayerTree's single-tx,
`O(D)`-vbyte exit is 2.2x-2.5x cheaper than the Ark/CTV model's `D`
sequential transactions (1,020 vs 2,511 vbytes at D=16), and the gap grows
linearly with `D` since Ark pays a full transaction (~150 vbytes) per
level where LayerTree pays ~30 vbytes of witness per level plus one fixed
skeleton. Ark/CTV trees also confirm over `D` blocks (one transaction at a
time, walking down), where a LayerTree exit confirms in one transaction;
this section prices vbytes only and does not price that latency or the
multi-block fee-rate exposure it implies. The trade-off, noted in spec
section 11, is opcode requirements: LayerTree's advantage requires the
larger FULL-tier opcode set, while Ark/CTV needs only `OP_CHECKTEMPLATEVERIFY`.

## Caveats

* Fees are set by market conditions at broadcast time, not by this
  document; the fee rates above are illustrative grid points, not
  forecasts.
* The Ark/CTV model (D transactions of ~150 vbytes plus a claim) is a
  simplification for order-of-magnitude comparison, not a benchmark of any
  specific deployed implementation.
* USD figures use a placeholder price of 100,000 USD/BTC and are for scale
  only.
* All figures assume the measured taptree/control-block size (the
  eight-leaf reference set of 6.2, 129 WU); a taptree with more supported
  transition scripts has a larger control block and slightly higher cost
  per exit (8 vB per doubling, 11.1).
* All figures omit the witness item count and length prefixes, measured
  in `spec/scripts/weights.md` (about 1% in FULL and CCV, about 3% in MID
  and MIN); see the assumptions above.
