# LayerTree explainer site

An interactive explainer for LayerTree: a landing page with the takeaway and
a step-through of a tree's life, and one page per component (the state
machine, joining, exiting, payments, swaps, eviction, batching and the opcode
tiers), each with its own step-through and links into the specification.

It is a static site with no build step: plain HTML, CSS, one JavaScript file
and inline SVG. Its one external dependency is the IBM Plex Mono and IBM Plex
Sans stylesheet from Google Fonts, linked in each page's head; the font stacks
in `css/tokens.css` fall back to system faces, so the site still reads well
offline. It loads no scripts from anywhere else.

## Opening it

From this directory:

```
python3 -m http.server 8000
```

then open <http://localhost:8000/>. The links into the specification
(`../spec/layertree.md` and so on) resolve when the server runs from the
repository root instead (`python3 -m http.server 8000` there, then
<http://localhost:8000/site/>), which is also how GitHub Pages serves it.

Opening `index.html` straight from disk works too. The animation engine is a
classic script rather than an ES module for this reason: browsers refuse to
load module scripts from `file://` URLs.

## Layout

| Path | What |
|---|---|
| `index.html` | Landing page: takeaway, the life-of-a-tree animation, links to the components, costs, what the design does not promise, where the numbers come from, and the terms used |
| `components/*.html` | One page per component, each with a two-sentence takeaway, an animation, the explanation and a "Deeper" list of spec sections and design pages |
| `css/tokens.css` | Every design token: colors for light and dark, fonts, type scale, spacing, motion durations |
| `css/site.css` | Layout and components, written only in terms of the tokens |
| `js/tree-anim.js` | The animation engine |
| `js/theme.js` | The light/dark toggle in the header |
| `assets/` | The logomark and wordmark, copied from `identity/schematic/` (the dark files recoloured to the warm ink, plus a fixed-colour `logo-light.svg` for `<img>` and the favicon) |
| `identity/` | The record of the three identity explorations (`schematic`, `editorial`, `approachable`), each with its README, tokens, logos and a sample page |

## Changing the visual identity

`css/tokens.css` is the only file an identity needs to change. `site.css` and
the SVG that `tree-anim.js` draws refer to colors, fonts, sizes and durations
only through its custom properties. Light is the default whatever the OS
prefers; the header button (`js/theme.js`) sets `data-theme="dark"` on
`<html>` and stores the choice in `localStorage` under `layertree-theme`.
A one-line script in each page's `<head>` applies a stored dark choice
before first paint, so a reload does not flash light.

## The identity

The site uses identity B, `identity/schematic/`, with the warmth of identity C,
`identity/approachable/`: B was chosen because a drafting sheet with numbered
figure plates, mono labels and one signal colour suits a design whose content
is proofs, sums and scripts, and C's cream paper, brown-black ink and slightly
softer corners and spacing were folded in so the pages read as an explainer
rather than a datasheet.

What that means on the page: a 16 px grid on cream paper; IBM Plex Mono for
headings, labels and every number in a figure, IBM Plex Sans for body text;
plates and cards ruled in ink with a caption bar (`FIG. n` from one counter
shared by step-throughs and static figures); orthogonal edges; lightly
rounded node boxes outlined in their role colour; the proof path and fold in
the signal colour (vermilion), siblings dashed; a leaving leaf outlined in
amber with an arrow down to the on-chain strip; and the strip's `ON-CHAIN`
tab as the one solid-filled shape, joined to a committed root by a dotted
rail. Text never wears a series colour.

### Palette validation

The five categorical colours are `--color-node`, `--color-accent` (the path),
`--color-leaf`, `--color-leaf-exit` and `--color-chain`, in that order. They
were checked with the dataviz skill's `validate_palette.js` against every
surface they are drawn on (`--color-bg`, `--color-surface`, and
`--color-surface-2` for the on-chain strip), in both modes:

```
node validate_palette.js "#2767AE,#D1481A,#1D8A6A,#A67300,#6B4E9B" --mode light --surface "#ede4d3"
node validate_palette.js "#5A8FD0,#EC6236,#38A586,#B98418,#9B82D4" --mode dark  --surface "#1a1612"
```

| Check | Light (`#f4ede0`, `#fbf7ef`, `#ede4d3`) | Dark (`#1a1612`, `#221d18`, `#2b251e`) |
|---|---|---|
| Lightness band | PASS (0.43 to 0.77) | PASS (0.48 to 0.67) |
| Chroma floor | PASS | PASS |
| CVD separation, adjacent | PASS, worst leaf-exit/leaf dE 9.0 (protan) | PASS, worst leaf/path dE 11.6 (deutan) |
| Normal-vision floor | PASS, worst dE 16.5 | PASS, worst dE 17.1 |
| Contrast vs surface (3:1) | PASS on all three | PASS on all three |

One fix was needed: with B's amber (`#B07A00`) the leaving-leaf colour fell
to 2.96:1 on the warmer strip surface, so it was darkened to `#A67300`, which
passes everywhere and also raises the worst CVD pair from 8.7 to 9.0. The
figures carry a secondary encoding anyway: siblings are dashed, the leaving
leaf has an arrow, and every node carries its number.

## Adding a scenario

An animation is a container that names a JSON block on the same page:

```html
<div class="tree-anim" data-scenario="my-steps"></div>
<script type="application/json" id="my-steps">
{
  "label": "What the animation shows",
  "depth": 3,
  "committed": true,
  "leaves": [{"label": "A", "amount": 5}, null, null, null, null, null, null, null],
  "steps": [
    {"title": "A proves its leaf", "caption": "...", "ops": [{"op": "path", "pos": 0}]},
    {"title": "A leaves", "caption": "...", "ops": [
      {"op": "leaf", "pos": 0, "leaf": null},
      {"op": "fold", "pos": 0},
      {"op": "chip", "id": "payA", "kind": "payout", "label": "Payout to A", "amount": 5},
      {"op": "commit"}
    ]}
  ]
}
</script>
<script src="../js/tree-anim.js"></script>
```

`depth` sets the number of slots (2<sup>depth</sup>; 3 fits a phone). `leaves`
lists the initial leaves by slot, `null` for an empty slot; a leaf has a
`label`, an `amount` and an optional short `note` shown on wide screens.
`committed: true` starts with a tree output on-chain committing to the initial
root.

Moving to step n replays the state operations of steps 1 to n, so Prev and
Next always agree. State operations:

| Operation | Effect |
|---|---|
| `{"op": "leaf", "pos": p, "leaf": {...} \| null}` | Set or empty the leaf in slot `p` |
| `{"op": "leaves", "from": p, "leaves": [...]}` | Set several consecutive slots |
| `{"op": "commit"}` | The tree output now commits to the current root |
| `{"op": "uncommit"}` | Remove the tree output |
| `{"op": "chip", "id", "kind", "label", "amount" \| "value" \| "node": [h, i]}` | Add or replace an item in the on-chain strip; `kind` is `payout`, `input`, `htlc` or `tree2`; `node` shows that node's hash and sum |
| `{"op": "unchip", "id"}`, `{"op": "clearChips"}` | Remove one item, or all, from the strip |

Highlight operations apply to their own step only:

| Operation | Effect |
|---|---|
| `{"op": "path", "pos": i, "h": 0}` | Outline the path from node `(h, i)` to the root, with its siblings dashed |
| `{"op": "fold", "pos": i, "h": 0}` | Draw the path from `(h, i)` up to the root one level at a time, in the signal colour; a `commit` or new chip in the same step appears after the fold reaches the root |
| `{"op": "region", "h": h, "i": i, "label"}` | Shade the subtree under node `(h, i)` |
| `{"op": "badge", "pos": p \| "node": [h, i], "text", "kind"}` | A label under a leaf or above a node; `kind` is `sig`, `voucher`, `hash` or `bad` |
| `{"op": "link", "from": p, "to": q, "text"}` | An arrow between two leaves, for off-chain payments |
| `{"op": "mark", "nodes": [[h, i], ...], "kind": "bad"}` | Mark nodes, for a check that fails |
| `{"op": "checks", "items": [{"text", "state": "ok" \| "fail" \| "pending"}]}` | A list of checks under the caption |

Two things are derived rather than declared. A slot that held a leaf before
the current step and is empty after it is drawn as a leaf leaving, with an
arrow down to the on-chain strip. A tree output whose root matches the
current root is joined to the root by a dotted rail; a root not yet
committed has none.

Every animation has Prev and Next buttons, a dot per step, and keyboard
control (left and right arrows, Home, End) when the figure has focus. Each
step's title and caption are announced to screen readers, and the SVG carries
a text description of the tree and the on-chain strip. With
`prefers-reduced-motion` the same steps change state instantly.

## Numbers

Every size quoted on the site comes from `spec/scripts/sizes.md`, spec
section 11, `spec/fee-analysis.md` or the design pages under `design/`; the
landing page's "Where the numbers come from" section says which. When those
figures change, grep the pages for the old value.
