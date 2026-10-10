# LayerTree identity: approachable

A friendly, explainer-style identity: warm paper, one persimmon accent, rounded
shapes, large readable type, diagrams with soft fills and plain labels.
Welcoming without being childish; no mascots, no decorative gradients.

Files: `tokens.css` (the identity as CSS variables), `logo.svg`,
`logo-dark.svg`, `logo-wordmark.svg`, `logo-wordmark-dark.svg`, `sample.html`.
Swapping identities means replacing `tokens.css` only.

## Concept

LayerTree puts many people's balances in one shared Bitcoin output. An
off-chain Merkle-sum tree records who owns what, and the output's script checks
a proof against the committed root and commits the new root, so anyone can
leave in one transaction with no timelock, and the operator can neither take
nor freeze anyone's money. The identity is built from that picture: a tree that
grows from a single root point, sums that add up, and a leaf that can step out
on its own.

## Name treatment

"LayerTree", one word, capital L and T, never "Layer Tree" or "layertree" in
running prose. In the wordmark it is set in Nunito ExtraBold (800), tracking
-0.5 at 44 units, next to the mark with a gap of one root-dot diameter.
Lowercase `layertree` is for code, paths and URLs only. The wordmark SVG uses
live `<text>` with the display stack, so it falls back to a system rounded or
sans face if Nunito is absent; export outlines before using it in print.

## Logomark

A tree growing upward from one root dot (the single UTXO). Two levels of
branches end in three leaves, and a fourth leaf has drifted off to the right,
unattached: the exit. The stroke is 5 units with round caps on a 64 unit grid,
so the mark holds at 24 px (the leaves are about 3 px dots) and at 400 px.
Dot sizes shrink toward the leaves (7, 5.5, 4.5) to read as depth and to keep
small sizes legible. It is one color: `logo.svg` is ink `#2B2118`,
`logo-dark.svg` is `#F6EBDD`. Do not recolor with the accent; the accent is
for the proof path in diagrams and for actions. Clear space: half the mark's
width on all sides. Minimum size: 20 px.

## Color system

All values are exact; `tokens.css` is the source of truth.

| Role | Variable | Light | Dark |
|---|---|---|---|
| Surface (page) | `--surface` | `#FBF6EE` | `#1E1914` |
| Surface 2 (cards, figures) | `--surface-2` | `#F3EADB` | `#2A231B` |
| Ink (text) | `--ink` | `#2B2118` | `#F6EBDD` |
| Ink 2 (secondary text) | `--ink-2` | `#5C4E40` | `#CDBFAE` |
| Ink 3 (captions, edges) | `--ink-3` | `#7A6B5B` | `#A39484` |
| Accent (actions, emphasis) | `--accent` | `#C8401F` | `#EC5F38` |
| Text on accent | `--accent-ink` | `#FFFFFF` | `#1E1914` |
| Tree node | `--node` | `#2C72B8` | `#4A8FD8` |
| Node sum tint | `--node-sum` | `#DCE8F5` | `#263548` |
| Highlighted proof path | `--path` | `#C8401F` | `#EC5F38` |
| Leaf | `--leaf` | `#23916B` | `#2BA880` |
| Leaf leaving | `--leaf-exit` | `#8A4FB0` | `#AE76D4` |
| On-chain strip | `--chain` | `#9A6B12` | `#BF8519` |
| Success | `--ok` | `#2E7D4F` | `#5CC48A` |
| Warning | `--warn` | `#9A5B00` | `#F0B64A` |

Rules:

- The accent is one color, persimmon. `--path` equals `--accent` on purpose:
  the thing to follow in a picture is the same color as the thing to click.
- Soft fills are made in CSS with `color-mix(in srgb, var(--role) 16-20%,
  var(--surface-2))`, with a 2 px solid stroke in the full role color. Text
  inside nodes is always `--ink`, never the role color.
- Body text is `--ink` on `--surface` (about 14:1 light, 14:1 dark). `--ink-3`
  is for captions and non-essential detail only.
- `--ok` and `--warn` always pair with a word or icon, never color alone.
  Neither is used for categorical roles.

### Palette validation (dataviz `validate_palette.js`)

Categorical set in slot order `--node, --path, --leaf, --leaf-exit, --chain`,
run against the identity's own surfaces with `--surface`.

Light, `"#2C72B8,#C8401F,#23916B,#8A4FB0,#9A6B12" --mode light --surface "#FBF6EE"`:

```
[PASS] Lightness band         all 5 inside L 0.43-0.77
[PASS] Chroma floor           all 5 >= 0.1
[PASS] CVD separation         worst adjacent #23916B/#C8401F dE 9.1 (deutan) - tritan 7.4
[PASS] Normal-vision floor    worst adjacent #9A6B12/#8A4FB0 dE 24.1 (normal)
[PASS] Contrast vs surface    all 5 >= 3:1
```

Dark, `"#4A8FD8,#EC5F38,#2BA880,#AE76D4,#BF8519" --mode dark --surface "#1E1914"`:

```
[PASS] Lightness band         all 5 inside L 0.48-0.67
[PASS] Chroma floor           all 5 >= 0.1
[PASS] CVD separation         worst adjacent #2BA880/#EC5F38 dE 10.2 (deutan) - tritan 8.2
[PASS] Normal-vision floor    worst adjacent #BF8519/#AE76D4 dE 24.8 (normal)
[PASS] Contrast vs surface    all 5 >= 3:1
```

Fixes made along the way: a first light attempt failed the chroma floor (blue
and green too gray), and the first dark attempt sat just above the dark
lightness band; both were re-stepped to the values above. The tritan figure in
light (7.4) is in the 6-8 band, so the identity never relies on color alone:
every node carries its number, the path is also thicker (4 px vs 2 px), the
siblings are dashed, and the leaving leaf has an arrow and a label.

## Typography

- Display: **Nunito** (SIL OFL, rounded terminals), weight 800, for headings,
  the wordmark and numbers inside tree nodes. Fallback: `"Varela Round",
  ui-rounded, "SF Pro Rounded", "Hiragino Maru Gothic ProN", system-ui,
  sans-serif`.
- Body: **Atkinson Hyperlegible** (SIL OFL), weights 400 and 700, chosen for
  clear letterforms at reading sizes. Fallback: `system-ui, -apple-system,
  "Segoe UI", Roboto, "Helvetica Neue", sans-serif`.
- Mono: system mono (`ui-monospace, "SF Mono", "JetBrains Mono", Menlo,
  Consolas`), for opcodes, hashes and sizes.
- Neither web font is required; the stacks degrade cleanly. The sample loads
  none, so what you see on a machine without them is the fallback.

Scale (`--size-1` to `--size-6`): 14, 17, 21, 28, 38 px, then a fluid display
size from 40 to 68 px. Body is `--size-2` (17 px) at line height 1.6; headings
line height 1.1; measure capped near 36 rem for prose.

## Spacing and radius

Spacing (`--space-1` to `--space-6`): 8, 12, 20, 32, 52, 84 px, about 1.6x per
step. Page gutter is `--space-3` (20 px), which gives a 16 px or more gutter
at phone width. Radius is `--radius` 16 px for cards; figures use 1.5x (24 px);
tree nodes use 10 px on a 28 px tall pill; buttons and tags are fully round.
Nothing is sharp-cornered.

## Motion

- Durations: `--dur-fast` 120 ms (press, hover on buttons), `--dur` 240 ms
  (card lift, color changes), `--dur-slow` 520 ms (drawing a proof path).
- Easing: `--ease` `cubic-bezier(0.3, 0.9, 0.3, 1)`, a quick start with a soft
  landing. No bounce, no overshoot.
- What moves: a proof path draws from its leaf toward the root once, on first
  view; cards lift 3 px on hover; the exiting leaf may slide out along its
  arrow. These are the only meanings motion has: "this is the path" and "this
  leaf is leaving".
- What never moves: the root, the on-chain strip, and the sums. The one output
  is the fixed point of every picture; if a total animates it implies money is
  changing, which is a claim the diagram should make only when it is true.
- Respect `prefers-reduced-motion`: show end states, no drawing, no lift.

## The three recurring pictures

**The tree.** The root is at the bottom and the leaves are at the top, so the
tree grows out of the one output. Nodes are soft-filled rounded pills holding a
number (the sum), with a 2 px edge in `--ink-3`. Leaves use `--leaf`, interior
nodes `--node`, the root is a solid `--node` pill with `--surface` text. Depth
3 (eight leaves) is the standard teaching size; deeper trees are drawn by
repeating levels, never by shrinking nodes below 28 px tall.

**The proof path.** One path from a leaf to the root in `--path`, 4 px wide,
with the nodes on it filled with a `--path` tint and a 3 px `--path` stroke.
The siblings the script needs are outlined with a dashed `--path` stroke. The
leaf that uses the path is `--leaf-exit`, with an upward arrow and a label.
Only one path is highlighted per picture.

**The on-chain output.** A single rounded strip beneath the tree in `--chain`
(soft fill, 2 px stroke), labeled "On-chain", with a dotted line from the root.
It is always one strip, always full width of the figure, and always below the
tree. It states what it commits to ("address commits to the root") in plain
words. Everything above the strip is off-chain; the strip is the only thing
that touches Bitcoin.
