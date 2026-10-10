# LayerTree explainer site

An interactive explainer for LayerTree: a landing page with the takeaway and
a step-through of a tree's life, and one page per component (the state
machine, joining, exiting, payments, swaps, eviction, batching and the opcode
tiers), each with its own step-through and links into the specification.

It is a static site with no build step and no dependencies: plain HTML, CSS,
one JavaScript file and inline SVG. It loads no fonts or scripts from
anywhere else.

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
| `js/tree-anim.js` | The animation engine, the only JavaScript on the site |

## Changing the visual identity

`css/tokens.css` is the only file an identity needs to change. `site.css` and
the SVG that `tree-anim.js` draws refer to colors, fonts, sizes and durations
only through its custom properties. Dark mode follows
`prefers-color-scheme`, and a page can force a theme with
`data-theme="light"` or `data-theme="dark"` on `<html>`.

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
| `{"op": "fold", "pos": i, "h": 0}` | Pulse the path from `(h, i)` upward one level at a time; a `commit` or new chip in the same step appears after the fold reaches the root |
| `{"op": "region", "h": h, "i": i, "label"}` | Shade the subtree under node `(h, i)` |
| `{"op": "badge", "pos": p \| "node": [h, i], "text", "kind"}` | A label under a leaf or above a node; `kind` is `sig`, `voucher`, `hash` or `bad` |
| `{"op": "link", "from": p, "to": q, "text"}` | An arrow between two leaves, for off-chain payments |
| `{"op": "mark", "nodes": [[h, i], ...], "kind": "bad"}` | Mark nodes, for a check that fails |
| `{"op": "checks", "items": [{"text", "state": "ok" \| "fail" \| "pending"}]}` | A list of checks under the caption |

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
