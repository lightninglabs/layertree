/*
 * tree-anim.js: the step-through animation used on every page.
 *
 * It draws a small binary Merkle-sum tree as SVG: leaves are boxes with a
 * label and an amount, each internal node shows the sum of its children,
 * and the root shows a short hash and the total. Beneath the tree an
 * "on-chain" strip shows the tree output (the root it commits to and its
 * amount) and any other outputs or inputs of the current transaction.
 *
 * A page declares a scenario as JSON and points a container at it:
 *
 *   <div class="tree-anim" data-scenario="exit-steps"></div>
 *   <script type="application/json" id="exit-steps">{ ... }</script>
 *
 * The scenario format is documented in site/README.md. In short, a scenario
 * has a depth, initial leaves and a list of steps; each step has a title, a
 * caption and a list of operations. Operations that change state (a leaf,
 * the committed root, the chips in the on-chain strip) accumulate from step
 * to step; operations that only highlight (a proof path, a fold, a badge, a
 * region, a list of checks) apply to the step that names them. Moving to
 * step n replays the state operations of steps 0 to n, so Prev and Next are
 * exact inverses.
 *
 * This file is a classic script rather than an ES module so that the pages
 * also work when opened straight from disk: browsers refuse to load module
 * scripts from file:// URLs. It defines window.TreeAnim and mounts every
 * [data-scenario] container when the page loads.
 */
(function () {
  'use strict';

  var NS = 'http://www.w3.org/2000/svg';
  var instances = 0;

  // ------------------------------------------------------------------
  // Tree model.
  // ------------------------------------------------------------------

  // fnv hashes a string to 32 bits. The displayed "root hash" is the low
  // 16 bits: it is not a real commitment, only a value that changes
  // whenever any leaf below it changes, which is the property the figure
  // has to show.
  function fnv(s) {
    var h = 0x811c9dc5;
    for (var i = 0; i < s.length; i++) {
      h ^= s.charCodeAt(i);
      h = Math.imul(h, 0x01000193) >>> 0;
    }
    return h >>> 0;
  }

  function hex4(n) {
    return ('0000' + (n & 0xffff).toString(16)).slice(-4);
  }

  function fmt(n) {
    return typeof n === 'number' ? n.toLocaleString('en-US') : String(n);
  }

  function copyLeaf(l) {
    return l ? { label: l.label, amount: l.amount, note: l.note || '' } : null;
  }

  // levels[h][i] is the node at height h and index i: its sum, its hash,
  // and whether every position below it is empty.
  function computeLevels(leaves, depth) {
    var levels = [leaves.map(function (l) {
      return l
        ? { sum: l.amount, hash: fnv(l.label + '|' + l.amount + '|' + (l.note || '')), empty: false }
        : { sum: 0, hash: 0, empty: true };
    })];
    for (var h = 1; h <= depth; h++) {
      var prev = levels[h - 1], cur = [];
      for (var i = 0; i < prev.length / 2; i++) {
        var a = prev[2 * i], b = prev[2 * i + 1];
        var empty = a.empty && b.empty;
        cur.push({
          sum: a.sum + b.sum,
          hash: empty ? 0 : fnv(a.hash + ',' + b.hash + ',' + h),
          empty: empty
        });
      }
      levels.push(cur);
    }
    return levels;
  }

  function rootOf(st) {
    var levels = computeLevels(st.leaves, st.depth);
    var r = levels[st.depth][0];
    return { hash: r.hash, sum: r.sum, empty: r.empty };
  }

  function rootLabel(r) {
    return r.empty ? 'empty' : hex4(r.hash);
  }

  // The nodes from (h, i) up to the root, and the sibling of each one
  // below the root.
  function pathNodes(h, i, depth) {
    var nodes = [], sibs = [];
    for (var k = h; k <= depth; k++) {
      var idx = i >> (k - h);
      nodes.push([k, idx]);
      if (k < depth) sibs.push([k, idx ^ 1]);
    }
    return { nodes: nodes, sibs: sibs };
  }

  // ------------------------------------------------------------------
  // Replaying a scenario to a step.
  // ------------------------------------------------------------------

  function initialState(sc) {
    var n = 1 << sc.depth;
    var leaves = [];
    for (var i = 0; i < n; i++) leaves.push(copyLeaf((sc.leaves || [])[i]));
    var st = {
      depth: sc.depth,
      leaves: leaves,
      chips: (sc.chips || []).map(function (c) { return Object.assign({}, c); }),
      committed: null
    };
    if (sc.committed) st.committed = rootOf(st);
    return st;
  }

  function emptyView() {
    return {
      paths: [], folds: [], regions: [], badges: [], links: [], marks: [],
      checks: null, commitNow: false, newChips: {}, delay: 0
    };
  }

  // applyStep mutates st with the step's state operations and, when
  // current is true, fills view with its highlight operations.
  function applyStep(st, step, current, view) {
    var ops = step.ops || [];
    // The commit and any new outputs appear after the longest fold of the
    // step has reached the root.
    var foldLen = 0;
    ops.forEach(function (op) {
      if (op.op === 'fold') foldLen = Math.max(foldLen, st.depth - (op.h || 0) + 1);
    });
    ops.forEach(function (op) {
      switch (op.op) {
        case 'leaf':
          st.leaves[op.pos] = copyLeaf(op.leaf);
          break;
        case 'leaves':
          op.leaves.forEach(function (l, j) { st.leaves[op.from + j] = copyLeaf(l); });
          break;
        case 'commit':
          st.committed = rootOf(st);
          if (current) view.commitNow = true;
          break;
        case 'uncommit':
          st.committed = null;
          break;
        case 'chip': {
          var chip = { id: op.id, kind: op.kind || 'payout', label: op.label, value: op.value };
          if (op.node) {
            var lv = computeLevels(st.leaves, st.depth)[op.node[0]][op.node[1]];
            chip.value = 'root ' + (lv.empty ? 'empty' : hex4(lv.hash)) + ' · ' + fmt(lv.sum);
          } else if (typeof op.amount === 'number') {
            chip.value = fmt(op.amount);
          }
          st.chips = st.chips.filter(function (c) { return c.id !== op.id; });
          st.chips.push(chip);
          if (current) view.newChips[op.id] = true;
          break;
        }
        case 'unchip':
          st.chips = st.chips.filter(function (c) { return c.id !== op.id; });
          break;
        case 'clearChips':
          st.chips = [];
          break;
        default:
          if (!current) break;
          if (op.op === 'path') view.paths.push(op);
          else if (op.op === 'fold') view.folds.push(op);
          else if (op.op === 'region') view.regions.push(op);
          else if (op.op === 'badge') view.badges.push(op);
          else if (op.op === 'link') view.links.push(op);
          else if (op.op === 'mark') view.marks.push(op);
          else if (op.op === 'checks') view.checks = op.items;
      }
    });
    if (current) view.delay = foldLen;
  }

  function stateAt(sc, idx) {
    var st = initialState(sc);
    var view = emptyView();
    for (var k = 0; k <= idx; k++) applyStep(st, sc.steps[k], k === idx, view);
    return { st: st, view: view };
  }

  // ------------------------------------------------------------------
  // SVG drawing.
  // ------------------------------------------------------------------

  function svgEl(name, attrs, text) {
    var e = document.createElementNS(NS, name);
    if (attrs) {
      Object.keys(attrs).forEach(function (k) {
        if (attrs[k] !== undefined && attrs[k] !== null) e.setAttribute(k, attrs[k]);
      });
    }
    if (text !== undefined) e.textContent = text;
    return e;
  }

  // Approximate advance width of monospace text, in pixels.
  function textW(s, size) {
    return String(s).length * size * 0.61;
  }

  function geometry(width, depth) {
    var pad = 10;
    var n = 1 << depth;
    var slot = (width - 2 * pad) / n;
    var leafW = Math.min(84, slot - 6);
    var wideLeaf = leafW >= 58;
    var g = {
      W: width, pad: pad, n: n, slot: slot, depth: depth,
      leafW: leafW, leafH: wideLeaf ? 50 : 38, wideLeaf: wideLeaf,
      nodeH: 32, rootH: 44, gap: 64, top: 8
    };
    g.cx = function (h, i) { return pad + (i * (1 << h) + (1 << h) / 2) * slot; };
    g.y = function (h) { return g.top + (depth - h) * g.gap; };
    g.boxW = function (h) {
      if (h === 0) return leafW;
      if (h === depth) return Math.min(178, width - 2 * pad);
      return Math.max(40, Math.min(86, slot * (1 << h) - 10));
    };
    g.boxH = function (h) { return h === 0 ? g.leafH : (h === depth ? g.rootH : g.nodeH); };
    g.bandTop = g.y(0) + g.leafH + 8;
    g.chainTop = g.bandTop + 60;
    return g;
  }

  function key(h, i) { return h + ':' + i; }

  function render(inst, animate) {
    var sc = inst.sc;
    var res = stateAt(sc, inst.idx);
    var st = res.st, view = res.view;
    var width = Math.round(Math.max(300, Math.min(780, inst.stage.clientWidth || 640)));
    var g = geometry(width, st.depth);
    var levels = computeLevels(st.leaves, st.depth);
    var root = levels[st.depth][0];
    var pending = st.committed
      ? (st.committed.hash !== root.hash || st.committed.sum !== root.sum)
      : !root.empty;

    // Classify nodes by the highlights of this step.
    var cls = {}, delays = {}, pathEdges = {}, onPath = {};
    function add(k, c) { cls[k] = (cls[k] || '') + ' ' + c; }
    var pns = view.paths.map(function (p) { return pathNodes(p.h || 0, p.pos, st.depth); });
    pns.forEach(function (pn) {
      pn.nodes.forEach(function (nd, j) {
        var k = key(nd[0], nd[1]);
        if (!onPath[k]) add(k, 'is-path');
        onPath[k] = true;
        if (j > 0) pathEdges[k + '>' + key(pn.nodes[j - 1][0], pn.nodes[j - 1][1])] = true;
      });
    });
    // With two proofs shown at once, a node on either path is drawn as a
    // path node even where it is also the other proof's sibling.
    pns.forEach(function (pn) {
      pn.sibs.forEach(function (nd) {
        var k = key(nd[0], nd[1]);
        if (!onPath[k] && (cls[k] || '').indexOf('is-sib') < 0) add(k, 'is-sib');
      });
    });
    view.folds.forEach(function (f) {
      var pn = pathNodes(f.h || 0, f.pos, st.depth);
      pn.nodes.forEach(function (nd, j) {
        var k = key(nd[0], nd[1]);
        add(k, 'is-fold');
        delays[k] = j;
        if (j > 0) pathEdges[k + '>' + key(pn.nodes[j - 1][0], pn.nodes[j - 1][1])] = true;
      });
    });
    view.marks.forEach(function (m) {
      (m.nodes || []).forEach(function (nd) { add(key(nd[0], nd[1]), 'is-' + (m.kind || 'path')); });
    });

    var svg = svgEl('svg', {
      xmlns: NS, role: 'img', viewBox: '0 0 ' + width + ' 100',
      'aria-label': describe(st, root, pending)
    });
    var arrowId = 'ta-arrow-' + inst.uid;
    var defs = svgEl('defs');
    var marker = svgEl('marker', {
      id: arrowId, viewBox: '0 0 10 10', refX: 9, refY: 5,
      markerWidth: 7, markerHeight: 7, orient: 'auto-start-reverse'
    });
    marker.appendChild(svgEl('path', { d: 'M0,0 L10,5 L0,10 z', 'class': 'arrowhead' }));
    defs.appendChild(marker);
    svg.appendChild(defs);

    // Regions sit behind everything else.
    view.regions.forEach(function (r) {
      var span = (1 << r.h) * g.slot;
      var x = g.pad + r.i * span + 2;
      var y = g.y(r.h) - 6;
      var grp = svgEl('g', { 'class': 'region' });
      grp.appendChild(svgEl('rect', {
        x: x, y: y, width: span - 4, height: g.y(0) + g.leafH + 6 - y, rx: 6
      }));
      // The label sits just below the region's top node, clear of its box.
      if (r.label) grp.appendChild(svgEl('text', { x: x + 5, y: g.y(r.h) + g.boxH(r.h) + 14 }, r.label));
      svg.appendChild(grp);
    });

    // Edges.
    for (var h = 1; h <= st.depth; h++) {
      for (var i = 0; i < levels[h].length; i++) {
        for (var c = 0; c < 2; c++) {
          var ci = 2 * i + c;
          var isPath = pathEdges[key(h, i) + '>' + key(h - 1, ci)];
          svg.appendChild(svgEl('line', {
            'class': 'edge' + (isPath ? ' is-path' : ''),
            x1: g.cx(h, i), y1: g.y(h) + g.boxH(h),
            x2: g.cx(h - 1, ci), y2: g.y(h - 1)
          }));
        }
      }
    }

    // Nodes.
    for (h = 0; h <= st.depth; h++) {
      for (i = 0; i < levels[h].length; i++) {
        svg.appendChild(drawNode(g, h, i, levels[h][i], st, cls[key(h, i)] || '', delays[key(h, i)], pending));
      }
    }

    // Badges and links in the band under the leaves. A badge that would
    // overlap one already placed moves one row further from its node.
    var placed = [];
    view.badges.forEach(function (b) {
      var bh = b.node ? b.node[0] : 0, bi = b.node ? b.node[1] : b.pos;
      var x = g.cx(bh, bi);
      var w = textW(b.text, 11) + 12;
      x = Math.max(g.pad + w / 2, Math.min(width - g.pad - w / 2, x));
      var y = bh === 0 ? g.bandTop : g.y(bh) - 20;
      var step = bh === 0 ? 20 : -20;
      var hits = function (p) {
        return x - w / 2 < p.x + p.w + 2 && p.x - 2 < x + w / 2 && Math.abs(p.y - y) < 18;
      };
      while (placed.some(hits)) y += step;
      placed.push({ x: x - w / 2, y: y, w: w });
      var grp = svgEl('g', { 'class': 'badge k-' + (b.kind || 'sig') });
      grp.appendChild(svgEl('rect', { x: x - w / 2, y: y, width: w, height: 18, rx: 9 }));
      grp.appendChild(svgEl('text', { x: x, y: y + 13, 'text-anchor': 'middle' }, b.text));
      svg.appendChild(grp);
    });
    view.links.forEach(function (l) {
      var x1 = g.cx(0, l.from), x2 = g.cx(0, l.to);
      var y = g.bandTop + 20;
      var grp = svgEl('g', { 'class': 'link' });
      grp.appendChild(svgEl('path', {
        d: 'M' + x1 + ',' + y + ' Q' + ((x1 + x2) / 2) + ',' + (y + 30) + ' ' + x2 + ',' + y,
        'marker-end': 'url(#' + arrowId + ')'
      }));
      if (l.text) {
        var lx = (x1 + x2) / 2, lw = textW(l.text, 11);
        lx = Math.max(g.pad + lw / 2, Math.min(width - g.pad - lw / 2, lx));
        grp.appendChild(svgEl('text', { x: lx, y: y + 34, 'text-anchor': 'middle' }, l.text));
      }
      svg.appendChild(grp);
    });

    // The on-chain strip.
    var chainH = drawChain(svg, g, st, view);
    var totalH = g.chainTop + chainH + 6;
    svg.setAttribute('viewBox', '0 0 ' + width + ' ' + totalH);
    svg.setAttribute('width', width);
    svg.setAttribute('height', totalH);

    inst.stage.innerHTML = '';
    inst.stage.appendChild(svg);
    inst.root.classList.toggle('no-anim', !animate);
    updatePanel(inst, view);
  }

  function drawNode(g, h, i, node, st, extra, delay, pending) {
    var x = g.cx(h, i), y = g.y(h), w = g.boxW(h), bh = g.boxH(h);
    var isRoot = h === st.depth;
    var c = 'node' + (h === 0 ? ' is-leaf' : '') + (isRoot ? ' is-root' : '') +
      (node.empty ? ' is-empty' : '') + (isRoot && pending ? ' is-pending' : '') + extra;
    var grp = svgEl('g', { 'class': c });
    if (delay !== undefined) grp.setAttribute('style', '--i:' + delay);
    grp.appendChild(svgEl('rect', { x: x - w / 2, y: y, width: w, height: bh, rx: isRoot ? 8 : 5 }));
    if (h === 0) {
      var leaf = st.leaves[i];
      if (leaf) {
        // A label wider than a narrow leaf is compressed to fit rather than clipped.
        var fit = textW(leaf.label, 12.5) > w - 6 ? { textLength: w - 6, lengthAdjust: 'spacingAndGlyphs' } : {};
        grp.appendChild(svgEl('text', Object.assign({ x: x, y: y + 16, 'text-anchor': 'middle', 'class': 't-b' }, fit), leaf.label));
        grp.appendChild(svgEl('text', { x: x, y: y + 31, 'text-anchor': 'middle', 'class': 'val' }, fmt(leaf.amount)));
        if (leaf.note && g.wideLeaf) {
          grp.appendChild(svgEl('text', { x: x, y: y + 44, 'text-anchor': 'middle', 'class': 't-sm' }, leaf.note));
        }
      } else {
        grp.appendChild(svgEl('text', { x: x, y: y + (g.wideLeaf ? 29 : 23), 'text-anchor': 'middle', 'class': 't-sm' },
          g.wideLeaf ? 'empty' : '∅'));
      }
    } else if (isRoot) {
      var tag = (pending && !node.empty ? 'new root ' : 'root ') + rootLabel(node);
      grp.appendChild(svgEl('text', { x: x, y: y + 17, 'text-anchor': 'middle', 'class': 't-sm root-tag' }, tag));
      grp.appendChild(svgEl('text', { x: x, y: y + 35, 'text-anchor': 'middle', 'class': 't-lg val' }, 'Σ ' + fmt(node.sum)));
    } else {
      grp.appendChild(svgEl('text', { x: x, y: y + 21, 'text-anchor': 'middle', 'class': 'val' + (node.empty ? ' t-muted' : '') },
        fmt(node.sum)));
    }
    return grp;
  }

  function drawChain(svg, g, st, view) {
    var x0 = g.pad, y0 = g.chainTop, W = g.W - 2 * g.pad;
    var grp = svgEl('g', { 'class': 'chain' });
    var bg = svgEl('rect', { 'class': 'chain-bg', x: x0, y: y0, width: W, height: 10, rx: 6 });
    grp.appendChild(bg);
    grp.appendChild(svgEl('text', { 'class': 'chain-title', x: x0 + 10, y: y0 + 16 }, 'ON-CHAIN'));

    var chips = [];
    if (st.committed) {
      chips.push({ id: '__tree', kind: 'tree', label: 'Tree output',
        value: 'root ' + rootLabel(st.committed) + ' · ' + fmt(st.committed.sum), commit: view.commitNow });
    } else {
      chips.push({ id: '__tree', kind: 'none', label: 'No tree output', value: '' });
    }
    st.chips.forEach(function (c) { chips.push(c); });

    var x = x0 + 10, y = y0 + 24, rowH = 44, chipH = 38;
    chips.forEach(function (c) {
      var w = Math.max(textW(c.label, 11), textW(c.value || '', 12.5)) + 18;
      w = Math.min(w, W - 20);
      if (x + w > x0 + W - 10 && x > x0 + 10) { x = x0 + 10; y += rowH; }
      var cg = svgEl('g', { 'class': 'chip k-' + c.kind + (c.commit ? ' is-commit' : '') + (view.newChips[c.id] ? ' is-new' : '') });
      if (c.commit || view.newChips[c.id]) cg.setAttribute('style', '--i:' + view.delay);
      cg.appendChild(svgEl('rect', { x: x, y: y, width: w, height: chipH, rx: 5 }));
      cg.appendChild(svgEl('text', { x: x + 9, y: y + 15, 'class': 't-sm' }, c.label));
      if (c.value) cg.appendChild(svgEl('text', { x: x + 9, y: y + 31, 'class': 't-b' }, c.value));
      grp.appendChild(cg);
      x += w + 8;
    });
    var h = (y + chipH + 10) - y0;
    bg.setAttribute('height', h);
    svg.appendChild(grp);
    return h;
  }

  // A text description of the figure for screen readers.
  function describe(st, root, pending) {
    var parts = st.leaves.map(function (l, i) {
      return 'slot ' + (i + 1) + ' ' + (l ? l.label + ' ' + fmt(l.amount) : 'empty');
    });
    var s = 'Tree of ' + st.leaves.length + ' slots: ' + parts.join(', ') + '. Root ' +
      rootLabel(root) + ', total ' + fmt(root.sum) + (pending ? ', not yet on-chain' : '') + '. On-chain: ';
    s += st.committed ? 'tree output committing to root ' + rootLabel(st.committed) + ' with ' + fmt(st.committed.sum)
      : 'no tree output';
    st.chips.forEach(function (c) { s += '; ' + c.label + (c.value ? ' ' + c.value : ''); });
    return s + '.';
  }

  // ------------------------------------------------------------------
  // Controls and captions.
  // ------------------------------------------------------------------

  function updatePanel(inst, view) {
    var n = inst.sc.steps.length, step = inst.sc.steps[inst.idx];
    inst.count.textContent = 'Step ' + (inst.idx + 1) + ' of ' + n;
    inst.title.textContent = step.title || '';
    inst.caption.textContent = step.caption || '';
    inst.checks.innerHTML = '';
    inst.checks.hidden = !view.checks;
    (view.checks || []).forEach(function (c) {
      var li = document.createElement('li');
      li.setAttribute('data-state', c.state || 'pending');
      var hidden = document.createElement('span');
      hidden.className = 'ta-check-state';
      hidden.textContent = { ok: 'Holds: ', fail: 'Fails: ', pending: 'Not checked yet: ' }[c.state || 'pending'];
      li.appendChild(hidden);
      li.appendChild(document.createTextNode(c.text));
      inst.checks.appendChild(li);
    });
    inst.prev.disabled = inst.idx === 0;
    inst.next.disabled = inst.idx === n - 1;
    inst.dots.forEach(function (d, j) {
      if (j === inst.idx) d.setAttribute('aria-current', 'step');
      else d.removeAttribute('aria-current');
      d.classList.toggle('is-done', j < inst.idx);
    });
  }

  function mount(host, sc) {
    var inst = { sc: sc, idx: 0, uid: ++instances };
    host.innerHTML = '';

    var root = document.createElement('div');
    root.className = 'ta';
    root.tabIndex = 0;
    root.setAttribute('role', 'group');
    root.setAttribute('aria-roledescription', 'step-through animation');
    root.setAttribute('aria-label', (sc.label || 'Animation') + '. Use the left and right arrow keys to change step.');
    inst.root = root;

    inst.stage = document.createElement('div');
    inst.stage.className = 'ta-stage';
    root.appendChild(inst.stage);

    var panel = document.createElement('div');
    panel.className = 'ta-panel';
    var live = document.createElement('div');
    live.setAttribute('aria-live', 'polite');
    inst.count = document.createElement('p');
    inst.count.className = 'ta-count';
    inst.title = document.createElement('p');
    inst.title.className = 'ta-title';
    inst.caption = document.createElement('p');
    inst.caption.className = 'ta-caption';
    inst.checks = document.createElement('ol');
    inst.checks.className = 'ta-checks';
    live.appendChild(inst.count);
    live.appendChild(inst.title);
    live.appendChild(inst.caption);
    live.appendChild(inst.checks);
    panel.appendChild(live);
    root.appendChild(panel);

    var controls = document.createElement('div');
    controls.className = 'ta-controls';
    inst.prev = button('Prev', 'Previous step');
    inst.next = button('Next', 'Next step');
    var dots = document.createElement('ol');
    dots.className = 'ta-dots';
    inst.dots = sc.steps.map(function (s, j) {
      var li = document.createElement('li');
      var b = document.createElement('button');
      b.type = 'button';
      b.className = 'ta-dot';
      b.setAttribute('aria-label', 'Step ' + (j + 1) + ': ' + (s.title || ''));
      b.addEventListener('click', function () { go(j); });
      li.appendChild(b);
      dots.appendChild(li);
      return b;
    });
    controls.appendChild(inst.prev);
    controls.appendChild(dots);
    controls.appendChild(inst.next);
    root.appendChild(controls);

    var legend = document.createElement('p');
    legend.className = 'ta-legend';
    legend.innerHTML = '<span class="lg-path">proof path or fold</span>' +
      '<span class="lg-sib">sibling supplied by the proof</span>' +
      '<span class="lg-pending">root not yet on-chain</span>' +
      '<span class="lg-chain">on-chain outputs</span>';
    root.appendChild(legend);

    host.appendChild(root);

    function button(text, label) {
      var b = document.createElement('button');
      b.type = 'button';
      b.className = 'ta-btn';
      b.textContent = text;
      b.setAttribute('aria-label', label);
      return b;
    }

    function go(j) {
      j = Math.max(0, Math.min(sc.steps.length - 1, j));
      if (j === inst.idx) return;
      // Animate forward moves only; stepping back shows the earlier state at once.
      var forward = j > inst.idx;
      inst.idx = j;
      render(inst, forward);
    }

    inst.prev.addEventListener('click', function () { go(inst.idx - 1); });
    inst.next.addEventListener('click', function () { go(inst.idx + 1); });
    root.addEventListener('keydown', function (e) {
      var t = e.target;
      if (t !== root && t.tagName !== 'BUTTON') return;
      var to = { ArrowRight: inst.idx + 1, ArrowLeft: inst.idx - 1, Home: 0, End: sc.steps.length - 1 }[e.key];
      if (to === undefined) return;
      e.preventDefault();
      go(to);
    });

    var lastW = 0;
    if (typeof ResizeObserver === 'function') {
      new ResizeObserver(function () {
        var w = inst.stage.clientWidth;
        if (Math.abs(w - lastW) > 4) { lastW = w; render(inst, false); }
      }).observe(inst.stage);
    }
    render(inst, true);
    lastW = inst.stage.clientWidth;
    return inst;
  }

  function mountAll() {
    var hosts = document.querySelectorAll('[data-scenario]');
    Array.prototype.forEach.call(hosts, function (host) {
      var src = document.getElementById(host.getAttribute('data-scenario'));
      try {
        mount(host, JSON.parse(src.textContent));
      } catch (err) {
        host.textContent = 'The animation could not load: ' + err.message;
      }
    });
  }

  window.TreeAnim = { mount: mount, stateAt: stateAt, computeLevels: computeLevels };

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', mountAll);
  else mountAll();
})();
