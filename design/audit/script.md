# Byte-level audit of the transition scripts

Status: complete. Base: `main` at 2b3d347 (spec 0.10.0); the fix below
lands as spec 0.11.0.

## What was done

Every passing case of the four suites was taken as a starting point and
one thing was mutated at a time: a witness element (proof sibling, pad,
leaf field, machine element, signature slot), a transaction field (an
output's amount or script, the lock time, an input amount) or a number's
encoding, and the mutated spend was run through the simulator. The
probes live in `tools/test_probe.py` (`python3 tools/test_probe.py
[group ...]`; groups `midneg midpad midcltv midsparse sparse exit small
claim rewrite evict join ccv min`). Each probe prints `ACCEPT` or
`REJECT` and whether that is the outcome the rules of spec section 7
require. The probes that found rules without a negative test were
turned into suite cases (`test_audit_negatives` in `tools/test_scripts.py`,
`test_sign_rules` in `tools/test_mid.py`, `test_audit_negatives_ccv` in
`tools/test_ccv.py`, and additions to `tools/test_min.py`).

## Confirmed bugs

### 1. MID, MIN and CCV-`0xC0`: a sum of `2^31 + k` enters the fold as `-k`

`CScriptNum` is sign-magnitude. A four-byte operand with its top bit set
is negative, and `PADZ` (`[x z w] -> [le32(x)]`) only checks that
`x || z` is four bytes and `z || w` is zero. So `x = 00 00 00 81`, which
is the minimal `CScriptNum` of `-2^24`, pads to `le32(2^31 + 2^24)`: the
node that gets hashed commits to a sum of `2^31 + 2^24` while every
`OP_ADD` that sees `x` adds `-2^24`. Nothing in the MID generator checked
the sign of a witness-supplied number before it entered a sum, and the
spec's "every sum < 2^31" (4.5) was a statement about the tree, not a
check in the scripts.

Probes (`tools/test_probe.py midneg`, all `ACCEPT` before the fix, all
`REJECT` after):

* `JOIN_2` at `D = 16` with `new_sum = 00 00 00 81`: the script's new
  total is `S - 2^24`, output 0 carries `S - 2^24`, and the tree now
  commits to a subtree whose sum is `2^31 + 2^24`. The operator pockets
  `2^24` sat of the members' money and holds a subtree of leaves it never
  funded, which can later exit one by one against the tree output.
* `JOIN_0` at `D = 16` with a leaf whose amount is `2^31 + 2^24`
  (`amt_num = 00 00 00 81`, `le64(amt_num) == amt8` holds): the same,
  through `LEAF_JOIN`.
* `SPLIT` at `D = 16` with a claim leaf of amount `2^31 + 2^24`:
  `amt_new = amt_s - amt_c = amt_s + 2^24`, so the source leaf gains
  `2^24` sat with output 0 unchanged. Any owner can do this alone, since
  `SPLIT` needs only the owner's transaction signature; the claim leaf
  itself is unspendable (its exit would need a `2^31 + 2^24` sat payout)
  but the inflated source exits normally. The MIN tier's `SPLIT` and the
  CCV tier's `0xC0` scripts share the carve body and are affected the
  same way; the CCV `0xC0` `JOIN_2` was probed directly.

The witness for these probes is built with the fold the script actually
performs (`fold_signed` in `tools/test_mid.py`): once an accumulator is
negative, its node bytes are the sign-magnitude encoding padded to four
bytes, so the attacker computes the root the script will reach and puts
`TREE_SPK` of it in output 0.

What it needs: a tree created in MID, MIN or CCV with `0xC0` numerics,
and nothing else. `MINIMALDATA` does not help: `00 00 00 81` is minimal.

Fix (commit "MID: reject negative numbers before they enter a sum"):
a `NONNEG` check, `OP_DUP OP_DUP OP_ABS OP_EQUALVERIFY`, on every
witness-supplied number that enters a sum, which are exactly three
sites: the sibling sum in `LEVEL_MID` (4 bytes per level), the leaf
amount in `LEAF_JOIN` and `new_sum` in the dense join block. Every other
summed quantity is derived from those (accumulators, `amt_new`, the
sweep's internal node sums), is non-negative once they are, and is kept
below `2^31` by `PADZ`'s four-byte bound. `OP_ABS` re-encodes `|x|`
minimally, so the comparison also rejects a negative zero (`00 00 00
80`) and every non-minimal encoding without relying on the `MINIMALDATA`
policy, which makes the sum invariant consensus-grade rather than
policy-grade. `evict_after` and `seq` are not sums and keep `PADZ`
alone: `OP_CHECKLOCKTIMEVERIFY` fails on a negative operand by itself,
and `seq`'s `CScriptNum` reading is what 5.1, 7.5 rule 2 and
`formal/LayerTree/Encoding.lean` already describe. MIN and CCV-`0xC0`
inherit the check through the shared macros; FULL and CCV-`0xC2` are
unsigned by construction (BIP-441 numbers have no sign) and need
nothing. The Go mirror (`script/mid.go`, `midNonneg`) is checked byte
for byte against the regenerated `spec/golden.json`.

Cost: 4 bytes per level plus 4 per leaf or join block. MID `EXIT_1` at
`D = 16` goes from 3,299 to 3,367 bytes of script (1,338 to 1,355 vB per
exit, +33% over FULL instead of +31%); the tables in spec 4.5, 11,
`spec/scripts/sizes.md`, `spec/fee-analysis.md`, the paper and the site
were updated and the listings regenerated.

Tests: `test_sign_rules` (MID: `JOIN_2`, `JOIN_0`, `SPLIT`, a sibling sum
in `EXIT_1`, and an `evict_after` of `2^31 + 2^24`), the MIN `SPLIT`
case in `test_min.test_split`, and the CCV `0xC0` `JOIN_2` case in
`test_audit_negatives_ccv`.

### 2. Simulator: `OP_CHECKLOCKTIMEVERIFY` accepted a negative operand

BIP-65 fails the script if the lock-time operand is negative. The
simulator only rejected operands of `2^32` or more. Under MID numerics a
leaf with `evict_after >= 2^31` carries a negative `ea_num`, so the
simulator would have let the operator evict it at lock time 0 where a
real node fails. No script relied on the gap (the leaf constructor
rejects such values), but it is the kind of divergence the probes are
for. Fixed in `tools/script_sim.py`; the last case of `test_sign_rules`
pins it.

## Gaps in the reference, not in the scripts

### MID sparse trees need `25 <= D <= 31`

`SPARSE_TEARDOWN` compares the `D`-bit direction accumulator with all 32
bits of `pos_lo`, whose top byte the nonce rule makes non-zero (a
four-byte minimal positive `CScriptNum`). So `pos_lo` must also be below
`2^D`: at `D = 31` that is the top-bit-clear condition already imposed,
at `D < 31` it is `2^(31-D)` times the grinding, and below `D = 25` it
is impossible. `tools/test_probe.py midsparse` shows a nonce that passes
the old `pos_ok` rejected at `D = 28`. The spec said `D <= 31`; 4.5 now
says `25 <= D <= 31` and `pos_ok(leaf, depth)` in
`tools/layertree_mid.py` takes the depth. The scripts are right; the
nonce rule was understated.

## Rules that were already enforced

One line each, with the probe (`tools/test_probe.py` group) that showed
it. Those marked (+test) were added to the suites.

* EXIT: `is_evict` of `0x02` fails `MINIMALIF` (`exit`) (+test).
* EXIT: a 115- or 117-byte leaf fails the size check (`exit`) (+test).
* EXIT: a 40- or 42-byte sibling fails; a 41-byte sibling whose `enc64`
  suffix is not `0x01` reaches a different root (`exit`) (+test).
* EXIT: a `dir` of `0x02` or `0x00` fails `MINIMALIF` (`exit`) (+test).
* EXIT: a payout at output 2 instead of 1 fails the script check
  (`exit`) (+test).
* EXIT_2: the same position in both steps fails, since step 2 finds
  `E_0` (7.6) (`exit`) (+test).
* EXIT_1^=: an owner payout one sat over `leaf.amount` fails; a zero
  payout under plain `EXIT_1` is accepted, as 7.2 rule 3 allows (`exit`)
  (+test for the surplus).
* JOIN_h: `new_sum` of 7 or 9 bytes and `new_hash` of 31 bytes fail
  (`join`) (+test); a node `(E_h, 1000)` funded by the operator is
  accepted, as 7.3 rule 4 says; joined sums of `2^53` and `2^63` are
  accepted in FULL and a total of `2^64` or more cannot be expressed.
* CLAIM: a claim leaf identical to the source drains it and re-inserts
  it elsewhere, and the same voucher then redeems again against the
  moved leaf (`claim`): a no-op move the owner signed for, which 7.5's
  replay argument covers (the voucher binds content, not position; see
  the (owner_key, nonce) rule of 5.2).
* CLAIM: a claim leaf of amount 0 is accepted (7.8 says it is harmless);
  a claim leaf with the source's `(owner_key, nonce)` is accepted (5.2
  forbids it off chain; the script does not check it and the only party
  harmed is the issuer).
* CLAIM: `seq = SEQ_FINAL - 1` is claimable; a raw `seq` of `01 00 00
  00` (a non-minimal BIP-441 number) increments correctly (`claim`).
* REWRITE_2: an `exit_key` change, an amount decrease, and an amount
  increase with a nonce or `seq` change each fail without the owner's
  signature and pass with it (`rewrite`) (+test).
* REWRITE_2: a spurious signature under an unchanged or a join position,
  old and new elements swapped at an exit position, a 1-byte old
  element, a forged old leaf, payouts to the owner key: all fail
  (`rewrite`) (+test for the first three).
* EVICT_SUBTREE_2: an occupied position presented as empty, two leaves
  in swapped positions, payouts in the wrong order, an empty position
  supplied as 116 zero bytes: all fail; `nLockTime == evict_after`
  passes and one less fails (`evict`) (+test).
* MID: a pad `z` with a non-zero byte, a byte moved between `z` and `w`,
  a non-minimal amount number, a sibling pad with the wrong split and a
  negative-zero sibling sum all fail (`midpad`).
* CCV: output 0 over- or under-funded by one sat, the tree output and
  the payout swapped, a payout to the exit key under a taptree, a payout
  one sat short, output 0 under the un-tweaked parent key: all fail
  (`ccv`) (+test for the first three).
* MIN: every one of the nine raw introspection pieces substituted fails,
  and an input 0 amount one sat above the folded sum fails (`min`)
  (+test). Shifting a byte between the `ver` and `lock` pieces is
  accepted (the message is their concatenation), and a transaction with
  three inputs is accepted with the extra inputs' amounts and scripts
  concatenated into `amt_in1` and `spk_in1`: the "two inputs" shape of
  4.5 is what the witness builder produces, not what the script checks,
  and neither is a rule of section 7.
* FULL sparse: an empty sibling supplied explicitly as `E_k || ENC0` is
  accepted (`sparse`); 5.5 says `sc` MAY be empty, so both forms are
  valid and the compressed one is the cheaper.
* Depths 1 and 2: `JOIN_0`, `CLAIM` and `EXIT_1` run (`small`).

## What the simulator cannot answer

* `OP_SUBSTR`, `OP_LEFT` and `OP_RIGHT` out of range: the simulator
  truncates like a Python slice; BIP-441 fails the script. Every use in
  the FULL scripts is followed by an `OP_SIZE` check on the element, so
  the outcome is a failure either way, but the error is raised later in
  the simulator than it would be on chain.
* `OP_PICK` and `OP_ROLL` with a negative index under `0xC0`: not
  rejected by the simulator; on chain they fail. No script takes a pick
  depth from the witness.
* `OP_CHECKSIG` with a key that is not 32 bytes: both the simulator and
  BIP-342 treat a non-empty signature as valid (unknown key type). The
  FULL scripts take keys by `OP_SUBSTR` of a leaf whose size is checked
  afterwards, so a short leaf fails anyway; the simulator's truncating
  `OP_SUBSTR` is what would make this reachable, and BIP-441's is not.
* `MINIMALDATA` is enforced by the simulator on every numeric operand;
  on chain it is policy. `NONNEG` now covers the sums without it; the
  `PADZ`-only numbers (`evict_after`, `seq`, the sparse `pos_lo`) still
  rely on it for their encoding, which affects standardness, not safety:
  a non-minimal `seq` or `evict_after` number is compared with its leaf
  field as bytes.
* The tapleaf version and the control block: the simulator does not run
  the taproot commitment, so a `0xC0` script in a `0xC2` slot is only
  caught because the taptree root `m` would differ. On chain the control
  block carries the leaf version and the taptree hash, so the same
  property holds there for the same reason.
* `OP_EC_POINT_MUL` with a scalar of `n` or more: the simulator reduces
  it; the draft BIP may fail. A `TREE_SPK` tweak of `n` or more has
  probability about `2^-128` and makes the tree unspendable rather than
  exploitable.
* Transaction balance: the simulator does not check that inputs cover
  outputs, which the probes above never needed, since every conservation
  rule is enforced against output 0's amount, not against the inputs.

## Check counts after the audit

Before: FULL 956, MID 228, MIN 35, CCV 864, channel leaves 149, MSU 61.
After: FULL 1,017, MID 250, MIN 47, CCV 886, channel leaves 149, MSU 61
(`python3 tools/test_scripts.py`, `test_mid.py`, `test_min.py`,
`test_ccv.py`, `test_chan.py`, `test_msu.py`), all with zero failures,
and `GOTOOLCHAIN=local go test ./...` against the regenerated
`spec/golden.json`.
