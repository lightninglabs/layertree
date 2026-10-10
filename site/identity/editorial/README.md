# LayerTree identity: editorial

## Concept

LayerTree is one shared Bitcoin output whose address commits to the root of an off-chain tree of sums, so the output can check a leaf and its proof and let its owner leave in a single transaction. The identity is that of a well-set technical book: a serif page on warm paper, one oxblood spot colour, hairline rules, and diagrams that look drafted with a ruling pen, because the claim of the design is something you can check by reading. The mark is the idea in four strokes: one root point, a branching tree, the sum drawn as a single bar beneath the leaves that stay, and one hollow leaf that has left.

## Name

"LayerTree" is one word, two capitals, no space. In the wordmark, "Layer" is upright at weight 500 and "Tree" is italic at weight 400, so the name reads as a noun followed by its growth. In running prose it is set plain, never italicised, never "Layer Tree", never "LT" outside the file-name convention. The wordmark is Newsreader with the display fallback stack; the SVG names the stack rather than embedding outlines, so on a machine with none of the listed faces it falls back to Georgia.

Files: `logo.svg` (mark, adapts to light and dark through `prefers-color-scheme` when used as an `<img>`), `logo-wordmark.svg` (mark plus name, same adaptation), `logo-dark.svg` (fixed paper-white mark for placement on dark photography or fixed dark panels). Inline, use `currentColor` from a `<symbol>` as `sample.html` does. The mark is built on a 32 unit grid with a 2 unit stroke, so it holds at 24 px (1.5 px strokes) and at 400 px. Minimum size 20 px; clear space equal to the root dot's diameter (6 units) on every side.

## Colour

Warm paper and near-black ink carry the page. One accent does everything that needs emphasis. The diagram colours are separate from the accent and are only used inside pictures of the protocol.

| Token | Role | Light | Dark |
|---|---|---|---|
| `--surface` | page | `#F7F3EA` | `#15140F` |
| `--surface-2` | panels, on-chain strip fill | `#EEE8D9` | `#1F1D16` |
| `--ink` | text, rules, mark | `#1B1A17` | `#F1ECDF` |
| `--ink-2` | secondary text | `#47443B` | `#C7C1B0` |
| `--ink-3` | captions, hairline edges | `#6C675A` | `#968F7E` |
| `--accent` | links, kicker, drop cap, hover | `#B5361C` | `#EE7B5E` |
| `--accent-ink` | text on a filled accent or path | `#FFF8EE` | `#15140F` |
| `--node` | sibling node outline (a proof item) | `#2F6DB5` | `#4A87D6` |
| `--node-sum` | tint behind a sibling's amount | `#DCE5EF` | `#1E2B3F` |
| `--path` | the highlighted proof path | `#C2401F` | `#DB5E3B` |
| `--leaf` | a leaf that stays | `#8A4FA8` | `#A06AC8` |
| `--leaf-exit` | a leaf that leaves | `#B07A12` | `#B38418` |
| `--chain` | the on-chain output | `#009089` | `#1F9E97` |
| `--ok` | success | `#2E7048` | `#5FB383` |
| `--warn` | warning | `#9A6200` | `#E0A23A` |

Rules of use. Text never wears a diagram colour; amounts stay in `--ink` (or `--accent-ink` on a filled path node). Status colours are reserved and always accompany a word or glyph. Hover and focus use `--accent`, never a diagram colour. Dark mode is a separate selection, not an inversion: the paper becomes warm charcoal rather than black, and diagram hues are stepped into the dark lightness band separately.

### Palette validation

Run with the dataviz validator, categorical set in the order `--node`, `--path`, `--leaf`, `--leaf-exit`, `--chain`:

```
node validate_palette.js "#2F6DB5,#C2401F,#8A4FA8,#B07A12,#009089" --mode light --surface "#F7F3EA"
node validate_palette.js "#4A87D6,#DB5E3B,#A06AC8,#B38418,#1F9E97" --mode dark  --surface "#15140F"
```

Light: all checks pass. Lightness band 0.43 to 0.77, chroma floor met, worst adjacent CVD separation 13.0 (protan, `#009089` against `#B07A12`) with tritan 11.6, normal-vision floor 19.2, contrast against the surface at least 3:1.

Dark: all checks pass. Lightness band 0.48 to 0.67, chroma floor met, worst adjacent CVD separation 14.2 (protan) with tritan 7.8, which is inside the 6 to 8 floor band, normal-vision floor 18.6, contrast at least 3:1.

The first attempts failed (a green leaf beside the vermilion path collapsed under deuteranopia, and the blue and teal were below the chroma floor); the set was re-hued so the red and green never touch. The tritan 7.8 in dark is legal only with secondary encoding, which the identity always supplies: every category also differs in shape or stroke (filled box, tinted outlined box, thin outlined box, heavy outlined box, hatched strip) and carries a legend and direct labels. `--node-sum` is a tint, not a categorical colour, and is not part of the validated set.

## Typography

| Role | Face | Fallback stack |
|---|---|---|
| Display (`--font-display`) | Newsreader (SIL OFL) | Iowan Old Style, Palatino Linotype, Palatino, Book Antiqua, Georgia, serif |
| Body (`--font-body`) | Source Serif 4 (SIL OFL) | Charter, Iowan Old Style, Palatino Linotype, Palatino, Georgia, serif |
| Mono (`--font-mono`) | IBM Plex Mono (SIL OFL) | ui-monospace, SF Mono, Menlo, Consolas, Liberation Mono, monospace |

Display is used for the name, the headline and section and card titles only; there is one display face. Everything that is a figure, a label, a hash, an amount or a section number is mono, small, tracked 0.03 to 0.08 em, and upper-case for kickers. Faces are named, not loaded, so the identity costs no request; a site that wants the exact faces self-hosts the three OFL families. Old-style figures (`onum`) in body prose, tabular mono in diagrams.

Scale: `--size-1` 13 px (captions, labels), `--size-2` 17 px (body, line height 1.6), `--size-3` 21 px (lead, small titles), `--size-4` 26 to 34 px (section heads), `--size-5` 34 to 52 px, `--size-6` 44 to 80 px (page headline, line height 1.02, tracking -0.025 em). Measure for prose is 38 rem at most; captions 40 rem. Headlines use `text-wrap: balance`.

## Space and shape

Space is a 4 px base that widens quickly: `--space-1` 4, `--space-2` 8, `--space-3` 16, `--space-4` 32, `--space-5` 64, `--space-6` 112 px. Use the large steps between sections; the page should feel under-filled. Radius is `--radius: 2px`: drafted corners, never pills, never a card shadow. Structure comes from rules: 1 px `--ink` above a section or figure, 1 px `--ink-3` between entries. There are no filled card backgrounds and no elevation.

## Motion

Durations: `--dur-fast` 120 ms (colour on hover), `--dur` 240 ms (underline growth, rule extension), `--dur-slow` 640 ms (the one drawing event). Easing: `--ease` is `cubic-bezier(0.22, 1, 0.36, 1)`, a quick start that settles with no overshoot; nothing bounces.

What moves: the proof path draws itself once from the root to the leaf, one edge per beat at 320 ms spacing, the first time a figure appears; a hover on an entry extends a 2 px accent rule under it and shifts the title colour; a link underline thickens. What never moves: the tree's nodes, sums and layout, the on-chain strip, the mark, and anything that would imply the tree is physically changing when only a root is. State changes in diagrams are swaps of the whole picture (cross-fade at `--dur`), never tweens of numbers. `prefers-reduced-motion` removes the path drawing entirely.

## The three recurring pictures

**The tree.** Drafted, orthogonal: boxes joined by right-angle hairline connectors (stem, bar, stem), never diagonals, never curves. Every node is a small box with a mono amount; the root is slightly larger. Plain nodes are 1 px `--ink-3` outline on `--surface`. Leaves wear `--leaf` outlines. A depth dimension line with tick marks sits to one side, as in an engineering drawing, and carries the `log2 N levels` note. Hashes are never drawn; amounts are the content, since the sums are what make theft structurally impossible.

**The proof path.** The only filled shapes in the diagram. The path from the leaf to the root is `--path`, 2.5 px, with filled boxes carrying `--accent-ink` amounts. Its siblings, the items the proof supplies, are `--node` outlined on a `--node-sum` tint, so the eye reads "these four things are the entire proof". The leaf that leaves gets a heavy `--leaf-exit` outline and a single elbow arrow leaving the tree sideways with its amount: one leaf, one move.

**The on-chain output.** One wide strip beneath the tree, outlined 1.5 px `--chain`, filled `--surface-2` with a 45 degree hatch of `--chain` at 40 % opacity (the drafting convention for "section through solid material", and a secondary encoding that survives greyscale). It is labelled `ONE OUTPUT ON CHAIN`, its amount, and the key formula. A dashed `--chain` line runs from the root box down to the strip, labelled `commits to root`: the strip is always visibly one thing under many, and the only link between off-chain and on-chain is that single line. Nothing else in the diagram touches the strip.

## Files

`tokens.css` is the whole identity as custom properties; `sample.html` applies it to a slice of the explainer and imports only `tokens.css`; swapping identities means replacing `tokens.css`. Rendered checks of `sample.html` were made in light and dark at desktop width and at 375 px.
