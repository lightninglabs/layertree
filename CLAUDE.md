# LayerTree: guide for agents and contributors

`CLAUDE.md` and `AGENTS.md` are identical copies of this file; edit both
(`cp CLAUDE.md AGENTS.md`) so that every agent harness reads the same guide.

Read this before changing anything. It records the conventions, invariants
and gotchas that are not obvious from the code. `design/status.md` has the
current state, the decision log and the open work.

## What this repository is

A Bitcoin scaling design: one shared UTXO, an off-chain Merkle-sum tree of
leaves, and tapscript covenants that enforce every state transition so that
any participant can exit, and the operator can evict, in one constant-size
transaction. Everything here is *design plus reference implementation*; the
opcodes it relies on are proposals, not consensus.

| Layer | Where | Executable check |
|---|---|---|
| Specification (RFC 2119) | `spec/layertree.md` (base), `spec/channel-leaves.md` (Appendix C), `spec/fee-analysis.md` | none directly; every normative script claim is backed by a test below |
| Python reference + tapscript simulator | `tools/` | `python3 tools/test_scripts.py`, `test_mid.py`, `test_min.py` |
| Go implementation (btcd, lnd, taproot-assets) | `tree/`, `script/`, `txn/`, `msg/` | `GOTOOLCHAIN=local go test ./...` |
| Channel leaves (Appendix C) in executable form | `tools/layertree_chan.py`, `script/chan.go`, `msg/chan.go` | `python3 tools/test_chan.py`; the Go mirror is checked against the `chan` section of `spec/golden.json` |
| Golden vectors linking Python and Go | `spec/test-vectors.json`, `spec/golden.json` | `python3 tools/gen_golden.py && git diff --exit-code spec/golden.json spec/test-vectors.json` |
| Formal model (Lean 4, core only) | `formal/` | `cd formal && lake build` (prints the axiom audit) |
| Design history and findings | `design/review.md` (F1..F18), `design/p-model.md`, `notes.md` | none |
| Paper (LNCS) | `paper/main.tex`, `paper/appendix-*.tex`, `paper/refs.bib`, built `paper/main.pdf`, generated `paper/version.tex` | `cd paper && make` (regenerates `version.tex` from git, then `latexmk`; TeX Live with `cryptocode`, `pgfplots`, `cm-super`; `llncs.cls` and `splncs04.bst` are bundled) |

The Python tools are the executable reference; the Go code is cross-checked
against them byte for byte. The Lean model proves the *rules* of spec
section 7 are right; the tests show the *scripts* implement the rules.

## Hard constraints from the author

1. **No new opcodes.** Compose only the existing candidates listed in spec
   4.3: BIP-441 restored opcodes (tapleaf `0xC2`), `OP_TX` (Rusty Russell's
   draft), `OP_CHECKSIGFROMSTACK` (BIP-348), `OP_TWEAKADD` (BIP-449),
   the EC ops draft BIP (`OP_EC_POINT_ADD/MUL/NEGATE/X_COORD`, opcodes
   `0xbb..0xbe`, operand order `[scalar][point]`, empty vector = G), and
   `OP_CHECKCONTRACTVERIFY` (BIP-443, assumption `[A-6]`, CCV tier only).
   `tools/test_scripts.py` and `tools/test_ccv.py` fail if a script uses
   anything outside its tier's allowed set. Do not invent a selector,
   opcode or semantics to make a script shorter. The hypothetical
   `OP_MERKLESUMUPDATE` (`tools/layertree_msu.py`, `design/native-opcodes.md`)
   is a measurement, not a tier: it stays behind the simulator's
   `hypothetical=True` flag and out of every tier, `all_scripts()` and the
   golden vectors.
2. **Four tiers, one tree format.** Every transition exists in FULL
   (`0xC2`), MID (`0xC0` + CAT + OP_TX + CSFS + TWEAKADD), MIN (`0xC0` +
   CAT + TWEAKADD) and CCV (BIP-443 `OP_CHECKCONTRACTVERIFY` + OP_TX in
   place of the key arithmetic, `0xC2` or `0xC0` numerics). A change to a
   transition rule must land in all tiers that support it, or the spec
   (4.5, 4.6) must say why a tier cannot.
3. **Spec language.** RFC 2119 keywords in capitals only where normative;
   paragraphs marked *(informative)* carry no requirements. No em-dashes in
   prose. Section numbers are referenced as bare numbers ("7.2 rule 3").
4. **Commit and push to `main` frequently.** Land each coherent piece of
   work as its own commit and push it, rather than batching a session's
   output into one drop; the author wants `main` to move as the work
   happens. Push the session's working branch too, so the two stay level.
   Commits are authored solely by the repository owner, with no agent
   attribution lines. Do not open PRs unless asked.

   Frequently does not mean carelessly: a commit still has to leave the
   tree consistent. Run the checks that cover what you touched before each
   push (the matrix under "Running everything"), and keep generated files
   in the same commit as the generator change that moved them. For the
   paper, commit the sources first, then `make`, then commit the PDF with
   `version.tex`, so the stamp names the content commit and reads clean.

## Change checklists

**Changing a script or adding a variant** (any tier):
1. Edit the generator (`tools/layertree_scripts.py` FULL,
   `tools/layertree_mid.py` MID, `tools/layertree_min.py` MIN,
   `tools/layertree_ccv.py` CCV). Keep the
   stack comments (`# a b c | alt`) current; they are how the next person
   debugs depth errors.
2. Add positive and negative cases to the matching test file. Negative
   cases must target the rule you changed (wrong key, shortfall, stale
   root, missing signature).
3. Regenerate golden vectors and listings: `python3 tools/gen_golden.py`,
   `python3 tools/gen_listings.py`. Check `git diff spec/golden.json`
   contains only the entries you meant to change. **The
   `taptree_full_d4.merkle_root` vector must not change unless the
   reference script *set* changes**; tree-creation variants (`UPDATE_X`,
   exact-payout `EXIT`) are excluded from it on purpose. It has moved
   once, at spec 0.10.0, when `CLAIM` (a member of the set) changed: its
   voucher message was rebound from `m` to `tree_id` and the carve rule
   of 7.5 rule 5 was added. The root went from
   `4c41f0a6ee029f07e34656dd8030f5bcfdbff3533e508bc4e52406b64b4a9265` to
   `eff4a173a4c87afe72b378ef18e8e9ee4ffeb3e3118dd1881cf9c075fef86305`.
   The `sighash_vector`, `tree_spk_vector` and `chan` entries derive
   from it and move with it.
4. Mirror the generator in Go (`script/full.go`, `script/mid.go`,
   `script/min.go`, `script/ccv.go`) and add the golden-key comparison test. Run `gofmt -l .`.
5. Update the spec: the listing in section 8, the size table in 8.8 and
   `spec/scripts/sizes.md`, the tier matrix in 4.5, the test description in
   14, and the check counts in 14 (the suites print them). Bump the version
   in the header (`0.x.y` patch for additive, minor for rule changes).
6. If a rule of section 7 changed, update `formal/LayerTree/Transitions.lean`
   and `formal/README.md`; `lake build` must stay free of `sorryAx`.

**Changing the leaf or node format**: touch `tools/layertree_ref.py`,
`tree/tree.go`, spec 5.2/5.3, `formal/LayerTree/Leaf.lean` and
`Encoding.lean` (field widths are proof inputs), regenerate
`spec/test-vectors.json` with `python3 tools/layertree_ref.py`, and expect
every golden vector to change.

**Changing a measured number** (sizes, vbytes, fees, check counts): the
same figure appears in spec 4.5/8.8/11, `spec/scripts/sizes.md`,
`spec/fee-analysis.md`, `formal/README.md` where relevant, and the paper
(`paper/main.tex` tables and prose). Grep for the old value across all of
them. The paper's Figure 3 coordinates are literal numbers, not generated.

**Changing Appendix C**: keep the "rules that bind the tree layer" list in
spec 9.8 in sync, and check C.10 (which items the base spec has adopted).

## Gotchas that cost time before

* **Go toolchain**: always `GOTOOLCHAIN=local`. `go mod tidy` will try to
  upgrade taproot-assets to a version needing a newer Go and rewrite
  `go.mod`; pin stays at taproot-assets v0.5.1, lnd v0.18.4-beta, btcd
  v0.24.3-0.20240921052913-67b8efd3ba53.
* `lnd`'s `input.TaprootNUMSKey` is **not** the BIP-341 `H` point. The
  spec's `NUMS` is BIP-341 `H`; `tree/taproot.go` has it as `NUMSHex`.
* **MID/MIN numerics**: `CScriptNum`, 4-byte operands, `MINIMALDATA`
  policy. Raw little-endian fields (`evict_after`, `pos_lo`, `seq`) cannot
  be used as numbers; they arrive as a minimal number plus a `PADZ`
  witness pad (`[x z w]`, `z||w = 00000000`, `size(x)+size(z) = 4`). Pads
  must sit *below* the level items on the stack. Sparse nonces are ground
  until `pos_lo` is a minimal positive number.
* **`SEQ_FINAL` differs by tier**: `0xFFFFFFFF` in FULL, `0x7FFFFFFF` in
  MID, because `ff ff ff ff` is a negative `CScriptNum` whose successor
  fits in four bytes. Proven in `formal/LayerTree/Encoding.lean`, tested in
  `tools/test_mid.py`.
* **Path order**: the witness supplies sibling pairs leaf-first (level 0
  consumed first). The Lean model orders paths root-first. Same data,
  reversed.
* **Sighash**: the simulator computes the real BIP-341 message and it
  matches `txscript`; the MIN tier's constructive introspection depends on
  this. `txscript` accepts `0xC2` leaf versions, which is what makes the
  sighash cross-check possible.
* **Killing test processes**: `pkill -f` matched the shell running it
  (exit 144). Kill by PID, and run long suites under `nohup` or `timeout`.
* **Sparse profile collisions**: at small `D` two leaves can derive the
  same position; tests retry the nonce as a real joiner would.
* **Lean**: no Mathlib on purpose. Positions are `Pos d h` (depth to
  height) to avoid index arithmetic; `Pos.height_le` dismisses the
  impossible `cons` case. Use `simp [getSub, setSub, pathSub]` rather than
  `rfl` for nil cases. The toolchain is downloaded from GitHub releases; in
  a sandbox `tar --zstd` may be missing, `python3 -m zstandard` works.
  `omit M in` must come *before* a declaration's doc comment, not between
  the comment and `theorem`; the latter is a parse error. After any Lean
  edit, check `lake build`'s exit code, not a grep over its output: a
  failed module silently skips everything downstream, including the axiom
  audit in `Axioms.lean`, so a filtered log can look empty and green.
* **LaTeX**: `cryptocode`'s `pchstack`/`pcvstack` cannot sit inside
  `\resizebox`; scale the individual `\procedure` boxes with `\scalebox`
  instead. `cryptocode` defines `\enc`, so the paper's macro is `\encs`.
  Without `cm-super` installed, `microtype` fails with a font-expansion
  error on the bitmap CM fonts. Never invent an ORCID or affiliation
  detail; the author block carries only what the author supplied. FC's
  limit is 15 LNCS pages excluding references and appendices: check where
  `References` lands with `pdftotext -layout` per page, not the total
  page count. Low-resolution contact sheets misread full pages as half
  empty; count `pdftotext` lines per page instead. `\anontrue` in the
  preamble switches the author block for double-blind submission.
  `paper/review.md` is a simulated PC review of the first draft and
  `paper/review-response.md` records what each item changed, including
  the functionality-first restructure (issue #4). Appendix F
  of the paper includes every script from `spec/scripts/structured/`,
  which `tools/gen_structured.py` produces by collapsing the compiled
  scripts back into named macro calls (round-trip verified against the
  bytes); run it after any generator change, together with
  `tools/gen_listings.py`, or the paper's listings go stale.
* **Paper structure and versioning**: the body is functionality first
  (section 3 the ideal functionality, 4 the abstract protocol and its
  covenant predicates, 5 the tiers, 6 the UC theorem with inline Lean
  signatures in `leansig` listings, 7 channel composition); the full
  simulator is Appendix A. Keep the Lean signature blocks in sync with
  `formal/LayerTree/*.lean` when a theorem statement changes. Build with
  `make`, not bare `latexmk`: `make` writes `paper/version.tex` (hash,
  date, `git describe --dirty`, clean/dirty); the author block shows
  "Draft (commit <hash>)" and the running footer the describe string. Commit sources first, then `make`, then commit
  `main.pdf` with `version.tex` so the stamp names the content commit and
  reads clean. `cryptocode`'s `\procedure` body is math mode, so prose
  with `$..$` inside it fails with "Missing } inserted"; the functionality
  figure is a framed `\parbox` for that reason. A `\item[...]` label
  containing `]` must be braced. llncs's `headings` page style has an
  empty footer; the preamble patches `\ps@headings` and re-issues
  `\pagestyle{headings}` (the class runs it at load time, so a patch
  alone does nothing).
* **Post-order machines** (`EVICT_SUBTREE_h`, `REWRITE_h`): the generator
  tracks `d`, the number of machine elements above `T`. Only the depth
  at which `T` (and, in `REWRITE_h`, the hoisted `L`/`Z` constants and
  the next witness element) is picked or rolled varies with `d`; a group
  of nodes that sits on top is addressed by constants (`HASH_STEP2` rolls
  7 and 5 whatever `d` is). Parametrising a constant by `d` passes at
  `d = 8` and fails one level up, so test a new shape at `h = 2`, not
  `h = 1`.
* **Subagents** on Opus have hit session rate limits mid-task twice.
  Review their partial work with the full test matrix before committing
  rather than assuming it is unfinished or finished.

## Running everything

```
python3 tools/layertree_ref.py     # regenerate spec/test-vectors.json
python3 tools/test_scripts.py      # FULL tier, both profiles (956 checks)
python3 tools/test_mid.py          # MID tier (228 checks)
python3 tools/test_min.py          # MIN tier (35 checks)
python3 tools/test_ccv.py          # CCV tier, both profiles and numerics (864 checks)
python3 tools/test_chan.py         # Appendix C channel leaves, both tapleaf versions (149 checks)
python3 tools/test_msu.py          # hypothetical OP_MERKLESUMUPDATE, measurement only (61 checks)
python3 tools/gen_listings.py      # spec/scripts/ (flat listings, size table)
python3 tools/gen_structured.py    # spec/scripts/structured/ (macro-collapsed listings)
python3 tools/gen_golden.py        # spec/golden.json
python3 tools/fee_analysis.py      # spec/fee-analysis.md tables
GOTOOLCHAIN=local go build ./... && GOTOOLCHAIN=local go test ./... && gofmt -l .
cd formal && lake build
```

CI (`.github/workflows/ci.yml`) runs the Python suites with a golden-vector
diff check, the Go build and tests, and the Lean build.
