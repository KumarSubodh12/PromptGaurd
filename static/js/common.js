/* PromptGuard shared helpers.
 *
 * Security rule for this whole front end: text that comes from a scanned document is untrusted. It is only ever put on
 * the page through textContent / createTextNode (via h()), never through innerHTML, and the CSP forbids inline script
 * and inline style attributes, so styling goes through CSS classes, data attributes and CSS custom properties.
 */
(function () {
  "use strict";

  const SVG_NS = "http://www.w3.org/2000/svg";

  // ------------------------------------------------------------------ DOM
  function applyAttrs(el, attrs) {
    for (const [k, v] of Object.entries(attrs || {})) {
      if (v === null || v === undefined || v === false) continue;
      if (k === "class") el.setAttribute("class", v);
      else if (k === "text") el.textContent = v;
      else if (k === "data") for (const [dk, dv] of Object.entries(v)) el.dataset[dk] = dv;
      else if (k === "vars") for (const [vk, vv] of Object.entries(v)) el.style.setProperty(vk, vv);
      else if (k === "on") for (const [ev, fn] of Object.entries(v)) el.addEventListener(ev, fn);
      else if (k === "value") el.value = v;
      else if (k === "checked" || k === "disabled" || k === "selected" || k === "open") el[k] = !!v;
      else el.setAttribute(k, v === true ? "" : v);
    }
  }
  function append(el, kids) {
    for (const c of kids.flat(Infinity)) {
      if (c === null || c === undefined || c === false) continue;
      el.append(c.nodeType ? c : document.createTextNode(String(c)));
    }
  }
  function h(tag, attrs, ...kids) {
    const el = document.createElement(tag);
    applyAttrs(el, attrs);
    append(el, kids);
    return el;
  }
  function s(tag, attrs, ...kids) {
    const el = document.createElementNS(SVG_NS, tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (v === null || v === undefined || v === false) continue;
      if (k === "text") el.textContent = v;
      else if (k === "vars") for (const [vk, vv] of Object.entries(v)) el.style.setProperty(vk, vv);
      else if (k === "on") for (const [ev, fn] of Object.entries(v)) el.addEventListener(ev, fn);
      else el.setAttribute(k, v);
    }
    append(el, kids);
    return el;
  }
  const $ = (sel, root) => (root || document).querySelector(sel);
  const $$ = (sel, root) => Array.from((root || document).querySelectorAll(sel));
  function clear(el) { while (el.firstChild) el.removeChild(el.firstChild); return el; }
  function mount(el, ...kids) { clear(el); append(el, kids); return el; }

  // ------------------------------------------------------------------ network
  async function api(path, opts) {
    const o = Object.assign({ headers: {} }, opts || {});
    if (o.json !== undefined) {
      o.method = o.method || "POST";
      o.headers["Content-Type"] = "application/json";
      o.body = JSON.stringify(o.json);
      delete o.json;
    }
    let resp;
    try { resp = await fetch(path, o); }
    catch (e) { throw new Error("Could not reach the PromptGuard server. Is it still running?"); }
    let data = null;
    try { data = await resp.json(); } catch (e) { /* not JSON */ }
    if (!resp.ok) throw new Error((data && data.error) || `The request failed (${resp.status}).`);
    return data;
  }
  let _meta = null;
  async function meta() { if (!_meta) _meta = await api("/api/meta"); return _meta; }

  // ------------------------------------------------------------------ formatting
  const BANDS = [[0, 30, "Low", "#22C55E"], [30, 60, "Medium", "#EAB308"], [60, 80, "High", "#F59E0B"], [80, 101, "Critical", "#EF4444"]];
  function bandOf(score) { return BANDS.find(b => score >= b[0] && score < b[1]) || BANDS[0]; }
  function pill(label) { return h("span", { class: "pill", data: { band: label }, text: label }); }
  function fmtDate(iso) {
    const d = new Date(iso);
    if (isNaN(d)) return iso || "";
    return d.toLocaleString(undefined, { day: "numeric", month: "short", year: "numeric", hour: "2-digit", minute: "2-digit" });
  }
  function fmtBytes(n) { return n < 1024 ? `${n} B` : n < 1048576 ? `${(n / 1024).toFixed(1)} KB` : `${(n / 1048576).toFixed(1)} MB`; }
  const pct = (x, d = 0) => (x === null || x === undefined ? "n/a" : `${(x * 100).toFixed(d)}%`);
  const num = (x, d = 3) => (x === null || x === undefined ? "n/a" : Number(x).toFixed(d));
  const plural = (n, one, many) => `${n} ${n === 1 ? one : (many || one + "s")}`;

  // ------------------------------------------------------------------ invisible characters
  // Hidden text is the point of some attacks, so the viewer must make it visible instead of hiding it again.
  const INVISIBLE_RX = /[​-‏‪-‮⁠-⁤⁦-⁩­﻿᠎]|[\u{E0000}-\u{E007F}]/u;
  const INVISIBLE_RUN = /([​-‏‪-‮⁠-⁤⁦-⁩­﻿᠎]|[\u{E0000}-\u{E007F}])+/gu;
  function describeRun(run) {
    const cps = Array.from(run);
    if (cps.every(c => c.codePointAt(0) >= 0xE0000 && c.codePointAt(0) <= 0xE007F)) {
      const decoded = cps.map(c => { const v = c.codePointAt(0) - 0xE0000; return v >= 32 && v < 127 ? String.fromCharCode(v) : ""; }).join("");
      const shown = decoded.length > 70 ? decoded.slice(0, 70) + "…" : decoded;
      return { chip: `hidden text: ${shown}`, plain: `[hidden text: ${decoded}]` };
    }
    const names = cps.map(c => "U+" + c.codePointAt(0).toString(16).toUpperCase().padStart(4, "0"));
    const uniq = Array.from(new Set(names));
    const label = uniq.length === 1 ? (cps.length > 1 ? `${uniq[0]} ×${cps.length}` : uniq[0]) : `${cps.length} invisible characters`;
    return { chip: label, plain: `[${names.join(" ")}]` };
  }
  /** DOM nodes for a piece of untrusted text, with every run of invisible characters shown as a visible chip. */
  function visibleNodes(text) {
    const out = [];
    let last = 0;
    text.replace(INVISIBLE_RUN, (run, _g, offset) => {
      if (offset > last) out.push(document.createTextNode(text.slice(last, offset)));
      const d = describeRun(run);
      out.push(h("span", { class: "inv", title: d.plain, text: d.chip }));
      last = offset + run.length;
      return run;
    });
    if (last < text.length) out.push(document.createTextNode(text.slice(last)));
    return out;
  }
  /** Plain-string version for places that cannot hold elements. */
  function visibleText(text) { return text.replace(INVISIBLE_RUN, run => describeRun(run).plain); }
  const hasInvisible = text => INVISIBLE_RX.test(text);
  const isAllInvisible = text => text.length > 0 && text.replace(INVISIBLE_RUN, "") === "";

  // ------------------------------------------------------------------ feedback
  let toastTimer = null;
  function toast(message, kind) {
    $$(".toast").forEach(t => t.remove());
    const t = h("div", { class: "toast" + (kind === "error" ? " error" : ""), role: kind === "error" ? "alert" : "status", text: message });
    document.body.append(t);
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => t.remove(), kind === "error" ? 7000 : 3500);
  }
  function confirmDialog(title, body, okLabel) {
    return new Promise(resolve => {
      const dlg = h("dialog", { "aria-labelledby": "dlg-title" });
      dlg.style.setProperty("width", "min(460px, 92vw)");
      const finish = v => { dlg.close(); resolve(v); };
      dlg.append(h("h2", { id: "dlg-title", text: title }), h("p", { class: "muted", text: body }),
        h("div", { class: "row mt" },
          h("button", { class: "btn btn-danger", type: "button", text: okLabel || "Delete", on: { click: () => finish(true) } }),
          h("button", { class: "btn btn-ghost", type: "button", text: "Cancel", on: { click: () => finish(false) } })));
      dlg.addEventListener("close", () => { dlg.remove(); resolve(false); });
      document.body.append(dlg);
      dlg.showModal();
    });
  }
  function modal(title, content) {
    const dlg = h("dialog", { "aria-labelledby": "modal-title" });
    dlg.append(h("div", { class: "row between" }, h("h2", { id: "modal-title", text: title }),
      h("button", { class: "btn btn-ghost btn-sm", type: "button", text: "Close", on: { click: () => { dlg.close(); dlg.remove(); } } })), h("div", { class: "mt" }, content));
    dlg.addEventListener("close", () => dlg.remove());
    document.body.append(dlg);
    dlg.showModal();
    return dlg;
  }
  async function copyText(text) {
    try { await navigator.clipboard.writeText(text); toast("Copied."); }
    catch (e) { toast("Copying is blocked in this browser. Select the text and copy it by hand.", "error"); }
  }
  function downloadText(filename, text) {
    const url = URL.createObjectURL(new Blob([text], { type: "text/plain;charset=utf-8" }));
    const a = h("a", { href: url, download: filename });
    document.body.append(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 2000);
  }

  // ------------------------------------------------------------------ risk gauge
  function gauge(score, colour, label) {
    const R = 82, C = 2 * Math.PI * R;
    const arc = s("circle", { class: "arc", cx: 95, cy: 95, r: R, "stroke-dasharray": C.toFixed(2), "stroke-dashoffset": C.toFixed(2) });
    const root = h("div", { class: "gauge", role: "img", "aria-label": `${label || "Risk"} score ${score} out of 100`, vars: { "--gc": colour } },
      s("svg", { viewBox: "0 0 190 190" }, s("circle", { class: "track", cx: 95, cy: 95, r: R }), arc),
      h("div", { class: "readout" }, h("span", { class: "score", text: String(score) }), h("span", { class: "of", text: "out of 100" })));
    requestAnimationFrame(() => requestAnimationFrame(() => arc.setAttribute("stroke-dashoffset", (C * (1 - Math.min(100, score) / 100)).toFixed(2))));
    return root;
  }
  function updateGauge(root, score, colour) {
    const R = 82, C = 2 * Math.PI * R;
    root.style.setProperty("--gc", colour);
    $(".score", root).textContent = String(score);
    $(".arc", root).setAttribute("stroke-dashoffset", (C * (1 - Math.min(100, score) / 100)).toFixed(2));
    root.setAttribute("aria-label", `Risk score ${score} out of 100`);
  }
  function bandScale() {
    return h("div", null,
      h("div", { class: "band-scale", "aria-hidden": "true" }, ...BANDS.map(b => h("i", { vars: { background: b[3], width: `${Math.min(100, b[1]) - b[0]}%` } }))),
      h("div", { class: "band-labels" }, h("span", { text: "0 Low" }), h("span", { text: "30 Medium" }), h("span", { text: "60 High" }), h("span", { text: "80 Critical" })));
  }

  // ------------------------------------------------------------------ charts (small, dependency-free SVG)
  const PALETTE = ["#38BDF8", "#8B5CF6", "#F59E0B", "#22C55E", "#F472B6", "#2DD4BF", "#EF4444", "#A3E635"];
  function emptyChart(msg) { return h("div", { class: "chart-empty", text: msg || "Nothing to show yet." }); }

  /** items: [{label, value, colour}] */
  function donut(items, centreLabel) {
    const total = items.reduce((a, b) => a + b.value, 0);
    if (!total) return emptyChart();
    const R = 62, SW = 22, C = 2 * Math.PI * R;
    let acc = 0;
    const segs = items.filter(i => i.value > 0).map(i => {
      const len = (i.value / total) * C;
      const c = s("circle", { cx: 85, cy: 85, r: R, fill: "none", stroke: i.colour, "stroke-width": SW,
        "stroke-dasharray": `${Math.max(0, len - 1.5).toFixed(2)} ${(C - Math.max(0, len - 1.5)).toFixed(2)}`, "stroke-dashoffset": (-acc).toFixed(2) },
        s("title", { text: `${i.label}: ${i.value}` }));
      acc += len;
      return c;
    });
    const svg = s("svg", { viewBox: "0 0 170 170", role: "img", "aria-label": items.map(i => `${i.label} ${i.value}`).join(", ") },
      s("g", { transform: "rotate(-90 85 85)" }, ...segs),
      s("text", { class: "donut-num", x: 85, y: 91, "text-anchor": "middle", text: String(total) }),
      s("text", { x: 85, y: 108, "text-anchor": "middle", text: centreLabel || "total" }));
    const legend = h("div", { class: "chart-legend" }, ...items.map(i => h("span", null, h("i", { class: "swatch", vars: { "--c": i.colour, background: i.colour } }), i.label, h("b", { text: String(i.value) }))));
    return h("div", { class: "donut-wrap chart" }, svg, legend);
  }

  /** rows: [{label, value, colour?, display?, cat?}], max optional */
  function hbars(rows, opts) {
    opts = opts || {};
    if (!rows.length) return emptyChart(opts.empty);
    const max = opts.max || Math.max(...rows.map(r => r.value), 1);
    return h("div", { class: "hbars" }, ...rows.map(r =>
      h("div", { class: "hbar", data: r.cat ? { cat: r.cat } : null },
        h("span", { text: r.label }),
        h("span", { class: "bar" }, h("i", { vars: Object.assign({ "--w": String(Math.max(0, Math.min(100, (r.value / max) * 100))) }, r.colour ? { "--c": r.colour } : {}) })),
        h("span", { class: "v", text: r.display !== undefined ? r.display : String(r.value) }))));
  }

  /** Line chart for a series of {x: label, y: number|null}. */
  function lineChart(points, opts) {
    opts = opts || {};
    const W = 640, H = 220, L = 38, Rr = 10, T = 12, B = 28;
    const vals = points.filter(p => p.y !== null);
    if (!vals.length) return emptyChart(opts.empty || "No scans in this period yet.");
    const ymax = opts.ymax || Math.max(10, Math.ceil(Math.max(...vals.map(p => p.y)) / 10) * 10);
    const X = i => L + (points.length === 1 ? (W - L - Rr) / 2 : (i * (W - L - Rr)) / (points.length - 1));
    const Y = v => T + (H - T - B) * (1 - v / ymax);
    const kids = [];
    for (let g = 0; g <= 4; g++) {
      const v = (ymax * g) / 4;
      kids.push(s("line", { class: "grid-line", x1: L, x2: W - Rr, y1: Y(v), y2: Y(v) }), s("text", { x: L - 8, y: Y(v) + 4, "text-anchor": "end", text: String(Math.round(v)) }));
    }
    const step = Math.ceil(points.length / 6);
    points.forEach((p, i) => { if (i % step === 0 || i === points.length - 1) kids.push(s("text", { x: X(i), y: H - 8, "text-anchor": "middle", text: p.x })); });
    let d = "", pen = false;
    points.forEach((p, i) => { if (p.y === null) { pen = false; return; } d += `${pen ? "L" : "M"}${X(i).toFixed(1)} ${Y(p.y).toFixed(1)} `; pen = true; });
    kids.push(s("path", { d, fill: "none", stroke: opts.colour || "#38BDF8", "stroke-width": 2.4, "stroke-linejoin": "round", "stroke-linecap": "round" }));
    points.forEach((p, i) => { if (p.y !== null) kids.push(s("circle", { cx: X(i), cy: Y(p.y), r: 3.6, fill: opts.colour || "#38BDF8" }, s("title", { text: `${p.x}: ${p.y}${p.note ? " (" + p.note + ")" : ""}` }))); });
    return h("div", { class: "chart" }, s("svg", { viewBox: `0 0 ${W} ${H}`, role: "img", "aria-label": opts.label || "Line chart" }, ...kids));
  }

  /** Vertical bars: items [{label, value}] */
  function columnChart(items, opts) {
    opts = opts || {};
    if (!items.some(i => i.value > 0)) return emptyChart(opts.empty || "No scans in this period yet.");
    const W = 640, H = 200, L = 30, T = 10, B = 28;
    const max = Math.max(3, ...items.map(i => i.value));
    const bw = (W - L) / items.length;
    const kids = [];
    for (let g = 0; g <= 3; g++) {
      const v = Math.round((max * g) / 3);
      const y = T + (H - T - B) * (1 - g / 3);
      kids.push(s("line", { class: "grid-line", x1: L, x2: W, y1: y, y2: y }), s("text", { x: L - 6, y: y + 4, "text-anchor": "end", text: String(v) }));
    }
    const step = Math.ceil(items.length / 6);
    items.forEach((it, i) => {
      const hgt = ((H - T - B) * it.value) / max;
      kids.push(s("rect", { x: L + i * bw + 2, y: H - B - hgt, width: Math.max(2, bw - 4), height: hgt, rx: 2, fill: opts.colour || "#8B5CF6" }, s("title", { text: `${it.label}: ${it.value}` })));
      if (i % step === 0 || i === items.length - 1) kids.push(s("text", { x: L + i * bw + bw / 2, y: H - 8, "text-anchor": "middle", text: it.label }));
    });
    return h("div", { class: "chart" }, s("svg", { viewBox: `0 0 ${W} ${H}`, role: "img", "aria-label": opts.label || "Bar chart" }, ...kids));
  }


  /** Grouped vertical bars. categories: [label]; series: [{name, colour, values:[0..1]}] (values are fractions, shown as %). */
  function groupedBars(categories, series, opts) {
    opts = opts || {};
    const W = 900, H = 280, L = 40, T = 16, B = 34, gw = (W - L - 10) / categories.length;
    const bw = Math.min(26, (gw - 14) / series.length);
    const kids = [];
    for (let g = 0; g <= 4; g++) {
      const v = g / 4, y = T + (H - T - B) * (1 - v);
      kids.push(s("line", { class: "grid-line", x1: L, x2: W - 10, y1: y, y2: y }), s("text", { x: L - 8, y: y + 4, "text-anchor": "end", text: `${Math.round(v * 100)}%` }));
    }
    categories.forEach((c, ci) => {
      const x0 = L + ci * gw + (gw - bw * series.length) / 2;
      series.forEach((se, si) => {
        const v = se.values[ci];
        if (v === null || v === undefined) return;
        const hgt = (H - T - B) * Math.max(0, Math.min(1, v));
        kids.push(s("rect", { x: x0 + si * bw + 1, y: H - B - hgt, width: Math.max(2, bw - 2), height: hgt, rx: 2, fill: se.colour },
          s("title", { text: `${se.name}, ${c}: ${(v * 100).toFixed(1)}%` })));
      });
      kids.push(s("text", { x: L + ci * gw + gw / 2, y: H - 12, "text-anchor": "middle", text: c }));
    });
    const legend = h("div", { class: "legend mt" }, ...series.map(se => h("span", null, h("i", { class: "swatch", vars: { background: se.colour } }), se.name)));
    return h("div", { class: "chart" }, s("svg", { viewBox: `0 0 ${W} ${H}`, role: "img", "aria-label": opts.label || "Grouped bar chart" }, ...kids), legend);
  }

  function emptyState(title, body, action) {
    return h("div", { class: "empty" }, h("h3", { text: title }), h("p", { text: body }), action ? h("div", { class: "mt" }, action) : null);
  }

  window.PG = {
    h, s, $, $$, clear, mount, api, meta, bandOf, pill, fmtDate, fmtBytes, pct, num, plural, BANDS, PALETTE,
    visibleNodes, visibleText, hasInvisible, isAllInvisible, toast, confirmDialog, modal, copyText, downloadText,
    gauge, updateGauge, bandScale, donut, hbars, lineChart, columnChart, groupedBars, emptyState, emptyChart,
  };
})();
