// Scaling page: the cost model, the two line charts and the size calculator.
//
// Every curve is a formula in k = log2(members), anchored on measured sizes
// (components/scaling.html, "How the numbers are made"). Charts are drawn
// as SVG whose colours come from CSS classes, so they follow the theme.
(function () {
  "use strict";

  var SVGNS = "http://www.w3.org/2000/svg";

  // vbytes of one unilateral exit, by design, for a tree of 2^k members.
  var MODEL = {
    // CCV plus the Merkle-sum opcode, sparse depth 64: a 331.75 vB
    // skeleton, control block and 252-byte script, plus a witness of
    // 197 bytes and one 40-byte sibling per occupied level.
    lt: function (k) { return 381 + 10 * k; },
    // FULL tier, dense profile, depth k: 762, 1,020 and 1,149 vB measured
    // at depths 8, 16 and 20, 32.25 vB per level.
    full: function (k) { return Math.ceil(504 + 32.25 * k); },
    // Transaction tree (Ark or CTV model): k transactions of 150 vB and a
    // 111 vB claim.
    ark: function (k) { return 150 * k + 111; },
    // Lightning force close: commitment, anchor child and sweep.
    ln: function () { return 530; },
    // A bare single-owner output spent with one input and one output.
    bare: function () { return 111; }
  };

  var TXS = {
    lt: function () { return 1; },
    full: function () { return 1; },
    ark: function (k) { return k + 1; },
    ln: function () { return 3; },
    bare: function () { return 1; }
  };

  var NAMES = {
    lt: "LayerTree, CCV + Merkle-sum opcode",
    full: "LayerTree, FULL tier",
    ark: "Transaction tree (Ark model)",
    ln: "Lightning force close",
    bare: "Bare output"
  };

  var BLOCK_VB = 1000000;

  function fmt(n) { return Math.round(n).toLocaleString("en-US"); }

  function sup(n) {
    return String(n).replace(/[0-9]/g, function (d) { return "\u2070\u00b9\u00b2\u00b3\u2074\u2075\u2076\u2077\u2078\u2079"[d]; });
  }

  function members(k) {
    if (k < 20) return fmt(Math.pow(2, k));
    if (k < 30) return (Math.pow(2, k) / 1e6).toLocaleString("en-US", { maximumFractionDigits: 1 }) + " million";
    return (Math.pow(2, k) / 1e9).toLocaleString("en-US", { maximumFractionDigits: 1 }) + " billion";
  }

  function el(name, attrs, text) {
    var node = document.createElementNS(SVGNS, name);
    for (var a in attrs) node.setAttribute(a, attrs[a]);
    if (text !== undefined) node.textContent = text;
    return node;
  }

  // A line chart over k = 4..32. opts.y is {log, min, max, ticks, label}.
  function lineChart(svg, opts) {
    var W = 680, H = 320, L = 58, R = 150, T = 14, B = 46;
    var kMin = 4, kMax = 32;
    var pw = W - L - R, ph = H - T - B;
    svg.setAttribute("viewBox", "0 0 " + W + " " + H);

    function x(k) { return L + (k - kMin) / (kMax - kMin) * pw; }
    function y(v) {
      var f = opts.y.log
        ? (Math.log(v) - Math.log(opts.y.min)) / (Math.log(opts.y.max) - Math.log(opts.y.min))
        : (v - opts.y.min) / (opts.y.max - opts.y.min);
      return T + ph - f * ph;
    }

    var grid = el("g", { "class": "ch-grid" });
    opts.y.ticks.forEach(function (v) {
      grid.appendChild(el("line", { x1: L, x2: L + pw, y1: y(v), y2: y(v) }));
      grid.appendChild(el("text", { x: L - 8, y: y(v) + 4, "text-anchor": "end", "class": "ch-tick" }, fmt(v)));
    });
    [4, 8, 12, 16, 20, 24, 28, 32].forEach(function (k) {
      grid.appendChild(el("line", { x1: x(k), x2: x(k), y1: T, y2: T + ph, "class": k === 16 ? "ch-mark" : "" }));
      var tick = el("text", { x: x(k), y: T + ph + 18, "text-anchor": "middle", "class": "ch-tick" }, "2");
      tick.appendChild(el("tspan", { dy: -5, "font-size": "0.8em" }, String(k)));
      grid.appendChild(tick);
    });
    grid.appendChild(el("text", { x: L + pw / 2, y: H - 6, "text-anchor": "middle", "class": "ch-label" }, "members in one tree (log scale)"));
    grid.appendChild(el("text", { x: 14, y: T + ph / 2, "text-anchor": "middle", "class": "ch-label",
      transform: "rotate(-90 14 " + (T + ph / 2) + ")" }, opts.y.label));
    svg.appendChild(grid);

    // End labels sit in the right margin; nudge apart any that collide.
    var ends = [];
    opts.series.forEach(function (s) {
      var d = "";
      for (var k = kMin; k <= kMax; k++) {
        d += (k === kMin ? "M" : "L") + x(k).toFixed(1) + " " + y(s.fn(k)).toFixed(1);
      }
      svg.appendChild(el("path", { d: d, "class": "ch-line s-" + s.key + (s.dash ? " is-dash" : "") }));
      ends.push({ key: s.key, y: y(s.fn(kMax)), text: s.label + "  " + fmt(s.fn(kMax)) });
    });
    ends.sort(function (a, b) { return a.y - b.y; });
    for (var i = 1; i < ends.length; i++) {
      if (ends[i].y - ends[i - 1].y < 13) ends[i].y = ends[i - 1].y + 13;
    }
    ends.forEach(function (e) {
      svg.appendChild(el("text", { x: L + pw + 8, y: e.y + 4, "class": "ch-end s-" + e.key }, e.text));
    });
  }

  var exitSvg = document.getElementById("chart-exit");
  if (exitSvg) {
    lineChart(exitSvg, {
      y: { log: true, min: 100, max: 5500, ticks: [100, 200, 500, 1000, 2000, 5000], label: "vB to leave alone (log scale)" },
      series: [
        { key: "ark", label: "Ark model", fn: MODEL.ark },
        { key: "full", label: "FULL tier", fn: MODEL.full, dash: true },
        { key: "lt", label: "LayerTree", fn: MODEL.lt },
        { key: "ln", label: "LN force close", fn: MODEL.ln },
        { key: "bare", label: "Bare spend", fn: MODEL.bare }
      ]
    });
  }

  var txSvg = document.getElementById("chart-txs");
  if (txSvg) {
    lineChart(txSvg, {
      y: { log: false, min: 0, max: 34, ticks: [0, 5, 10, 15, 20, 25, 30], label: "transactions to leave" },
      series: [
        { key: "ark", label: "Ark model", fn: TXS.ark },
        { key: "ln", label: "Lightning", fn: TXS.ln },
        { key: "lt", label: "LayerTree", fn: TXS.lt }
      ]
    });
  }

  // The calculator: one row per design at the chosen size and fee rate.
  var calc = document.getElementById("calc");
  if (calc) {
    var range = calc.querySelector("#calc-k");
    var rate = calc.querySelector("#calc-rate");
    var out = calc.querySelector("#calc-n");
    var body = calc.querySelector("tbody");
    var note = calc.querySelector("#calc-note");
    var order = ["lt", "full", "ark", "ln", "bare"];
    var WAIT = {
      lt: function () { return "1"; },
      full: function () { return "1"; },
      ark: function (k) { return k + " + leaf timelock"; },
      ln: function () { return "about 145"; },
      bare: function () { return "1"; }
    };

    function render() {
      var k = Number(range.value);
      var r = Number(rate.value);
      out.textContent = members(k) + " members (2" + sup(k) + ")";
      range.setAttribute("aria-valuetext", members(k) + " members");
      body.textContent = "";
      order.forEach(function (key) {
        var v = MODEL[key](k);
        var tr = document.createElement("tr");
        if (key === "lt") tr.className = "is-ours";
        [NAMES[key], fmt(v), String(TXS[key](k)), WAIT[key](k), fmt(v * r), fmt(Math.floor(BLOCK_VB / v))]
          .forEach(function (cell, i) {
            var td = document.createElement(i === 0 ? "th" : "td");
            if (i === 0) td.setAttribute("scope", "row");
            if (i > 0) td.className = "num";
            td.textContent = cell;
            tr.appendChild(td);
          });
        body.appendChild(tr);
      });
      note.textContent = "At this size the transaction tree's exit is " +
        (MODEL.ark(k) / MODEL.lt(k)).toFixed(1) + " times LayerTree's and the FULL tier's " +
        (MODEL.full(k) / MODEL.lt(k)).toFixed(1) + " times. LayerTree's is " +
        (MODEL.lt(k) / MODEL.ln(k)).toFixed(2) + " times a Lightning force close and " +
        (MODEL.lt(k) / MODEL.bare(k)).toFixed(1) + " times a bare spend.";
    }

    range.addEventListener("input", render);
    rate.addEventListener("change", render);
    render();
  }
})();
