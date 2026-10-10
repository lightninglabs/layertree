# LayerTree identity: schematic

An engineering drawing for a financial primitive. The page is drafting paper with a fine grid, the labels are monospaced, strokes are precise and thin, and exactly one signal color (vermilion, the red pencil of a markup) marks the thing the reader should follow. Diagrams read like a datasheet: a numbered figure plate, a caption bar, a legend. Technical but warm: the ground is paper and bone, never black-and-neon; there is no glow, no gradient, no blur.

## Concept

LayerTree puts many people's balances under one on-chain output. Off-chain, a Merkle-sum tree records who owns what; each parent holds the sum of its children, so the root commits to every balance at once. A covenant script checks a leaf's proof against the committed root and commits the new root, so any participant can leave in one transaction, with no timelock, and the operator can neither take nor freeze anyone's money. The identity draws exactly this: a tree whose root is a single point, sums written on the nodes, a proof path traced in the signal color, and one output beneath it all.

## Name treatment

Set in lowercase monospace as `layertree`, with `layer` at weight 400 and `tree` at weight 700. The weight change is the only emphasis; the wordmark stays one color (ink, or accent on rare occasions). Never title-case it in the wordmark, never add a tagline lockup. In running prose, write LayerTree.

The mark (`logo.svg`, 32 by 32 grid) is a tree drawn as a wiring diagram. A filled dot is the root, a stem drops to an orthogonal bus, and three branches descend. Two end in filled square leaves. The third turns ninety degrees and leaves the diagram through an arrowhead: the exit. It is built from three shapes only (dot, orthogonal line, square) at one stroke width (2.2 units), so it holds at 24 px (the smallest rendered detail is about 1.6 px) and scales cleanly to 400 px. It is a single color via `currentColor`.

Files: `logo.svg` (currentColor), `logo-dark.svg` (fixed `#E9E5D8` for dark grounds where `currentColor` is unavailable, such as an `<img>`), `logo-wordmark.svg`, `logo-wordmark-dark.svg`. The wordmark text is live SVG text with the mono stack from `--font-mono`; where exact reproduction matters (print, social cards), outline it from IBM Plex Mono. Clear space is the height of one leaf square on all sides. Minimum size: 24 px for the mark, 112 px wide for the wordmark.

## Color system

Defined in `tokens.css`. Light is warm drafting paper; dark is a blue-black slate, not pure black, with bone ink.

| Role | Token | Light | Dark |
|---|---|---|---|
| Surface (page ground) | `--surface` | `#F6F3EA` | `#15191D` |
| Surface 2 (title blocks, strips) | `--surface-2` | `#ECE8DA` | `#1D2328` |
| Ink (text, rules) | `--ink` | `#1B242C` | `#E9E5D8` |
| Ink 2 (secondary text) | `--ink-2` | `#46525C` | `#B3B8B6` |
| Ink 3 (labels, hashes, edges) | `--ink-3` | `#66717B` | `#8A9298` |
| Accent (the signal) | `--accent` | `#D1481A` | `#EC6236` |
| Text on accent | `--accent-ink` | `#FFFFFF` | `#15191D` |
| Tree node outline | `--node` | `#2767AE` | `#5A8FD0` |
| Sum label on a node | `--node-sum` | `#1E4E85` | `#9DBFEA` |
| Highlighted proof path | `--path` | `#D1481A` | `#EC6236` |
| Leaf | `--leaf` | `#1D8A6A` | `#38A586` |
| Leaf that is leaving | `--leaf-exit` | `#B07A00` | `#B98418` |
| On-chain output strip | `--chain` | `#6B4E9B` | `#9B82D4` |
| Success | `--ok` | `#2E7D32` | `#5BB56A` |
| Warning | `--warn` | `#9A5B00` | `#D9A441` |

Rules. The accent is one color doing two jobs that are the same job: links and calls to action, and the proof path. If it is vermilion, the reader is meant to follow it. The grid on the page ground uses `--grid-minor` and `--grid-major` (ink at 6 and 12 percent; 5 and 10 percent in dark), a 16 px minor and 64 px major step. `--ok` and `--warn` always ship with an icon and a text label; `--warn` is a deeper brown than `--leaf-exit` so the two are not confused, and neither is colour alone. Text never wears a series colour (nodes, leaves, chain); the coloured mark beside it carries identity.

### Palette validation

Categorical set (`--node`, `--path`, `--leaf`, `--leaf-exit`, `--chain`, in that order), run with the dataviz skill's `validate_palette.js` against this identity's own surfaces:

```
node validate_palette.js "#2767AE,#D1481A,#1D8A6A,#B07A00,#6B4E9B" --mode light --surface "#F6F3EA"
node validate_palette.js "#5A8FD0,#EC6236,#38A586,#B98418,#9B82D4" --mode dark  --surface "#15191D"
```

| Check | Light | Dark |
|---|---|---|
| Lightness band | PASS (0.43 to 0.77) | PASS (0.48 to 0.67) |
| Chroma floor | PASS (all >= 0.1) | PASS |
| CVD separation (adjacent) | PASS, worst `--leaf-exit`/`--leaf` dE 8.7 (protan) | PASS, worst `--leaf`/`--path` dE 11.4 to 11.6 |
| Normal-vision floor | PASS, worst dE 17.6 | PASS, worst dE 17.1 |
| Contrast vs surface (3:1) | PASS | PASS |

Both modes: ALL CHECKS PASS. Two fixes were needed from the first draft: the first-pass blue and green failed the chroma floor in light (they read as grey) and were saturated; the first-pass dark amber sat above the lightness band and was darkened. The light worst-case CVD pair (8.7) is above the 8 target, so no secondary encoding is strictly required, but the tree always carries one anyway (dash pattern on siblings, labels on the exit and the strip).

## Typography

- Display: IBM Plex Mono, weight 700, tight tracking (-0.03em), for headings and the wordmark. One display face only, and it is the same face as the labels, so a heading reads like a title block.
- Body: IBM Plex Sans, 400 and 600.
- Mono (labels, hashes, sums, captions, figure plates): IBM Plex Mono, 400 and 700.
- Both families are open (SIL OFL), so no licence is needed. The tokens do not load them; the site may self-host them. Fallbacks: display and mono fall back to `JetBrains Mono, ui-monospace, SFMono-Regular, Menlo, Consolas, monospace`; body falls back to `Source Sans 3, ui-sans-serif, system-ui, -apple-system, "Segoe UI", sans-serif`.
- Scale (`--size-1` to `--size-6`): 0.75, 0.875, 1, 1.25, 1.75, 2.5 rem. Captions and figure plates use size 1 in uppercase mono with 0.08em tracking. Body line height 1.55; headings 1.1.
- Numbers on diagrams are always mono, and sums are written with a sigma (`Σ 44`).

## Spacing and radius

Spacing is a 4-based scale in rem: `--space-1` 0.25, `--space-2` 0.5, `--space-3` 1, `--space-4` 1.5, `--space-5` 2.5, `--space-6` 4. Layout lines up to a 16 px grid, which is also the grid drawn on the page. Radius is `--radius: 2px` everywhere: drafted corners, never pills. Borders are 1 px ink; the emphasis stroke on diagrams is 2.5 to 2.75 px. Cards have no shadow at rest; on hover they take a hard 3 px offset shadow in the accent, like a registration mark.

## Motion

Durations: `--dur-fast` 120 ms (hover and focus), `--dur` 220 ms (state changes), `--dur-slow` 480 ms (a path being drawn). Easing: `--ease` is `cubic-bezier(0.2, 0, 0, 1)`: fast start, long settle, like a pen lifting off the page.

What moves: strokes being drawn (the proof path draws from leaf to root once on load, with a 240 ms delay), colour and border changes on hover, and a short fade as the sibling nodes of a proof are revealed. What never moves: nodes, the tree layout, the logo, anything on a scroll trigger, anything that loops. Nothing bounces, springs, pulses, or glows. Under `prefers-reduced-motion: reduce` all three durations become 0 ms and the figure is shown in its final state. An animation must always have a visible resting state without animation (the sample uses `both` fill and a `from`-only keyframe for this).

## The three recurring pictures

**The tree.** A top-down tree with the root at the top. Every node is a small rectangle (76 by 38, 2 px radius) with its hash in `--ink-3` at the top and its sum in bold below (`Σ 23` for interior nodes, a plain number for leaves). Interior nodes outline in `--node` and carry their sum in `--node-sum`; leaves outline in `--leaf` and carry their balance in ink. Edges are orthogonal, one 1.25 px `--ink-3` bus per parent, never diagonal and never curved. Always include a figure plate: a caption bar in `--surface-2` (`FIG. 1`, title on the left, what is highlighted on the right), the drawing, and a legend row.

**The proof path.** The only place the accent appears inside a diagram. The nodes from the leaf to the root get a 2.5 px `--path` outline, and the edges between them thicken to 2.75 px in `--path`. The siblings the verifier needs (the proof itself) keep the accent but are drawn with a 1.5 px dashed outline, so path versus proof is legible without colour. The leaf that is leaving takes `--leaf-exit` on its outline, and a `--leaf-exit` arrow runs from it straight down to the on-chain strip, labelled with what it receives. Path direction is leaf to root and never animated the other way.

**The on-chain output.** A full-width strip beneath the tree, in `--surface-2` with a 2 px `--chain` outline, and a solid `--chain` tab at the left reading `ON-CHAIN` in tracked uppercase mono. It states what actually exists on the chain: one output, the total, and that its address encodes the root. A dotted `--chain` rail runs from the root node to the strip, meaning "commits to". The visual rule: everything above the strip is data off-chain, drawn thin and outlined; the strip is the only solid-filled shape, because it is the only thing that is real on-chain. One strip, never more, even when a diagram shows many exits.

## Files

`tokens.css` (swap-in token file), `logo.svg`, `logo-dark.svg`, `logo-wordmark.svg`, `logo-wordmark-dark.svg`, `sample.html` (self-contained, no JavaScript; open it from a local server or directly, and it imports `tokens.css`).
