/* Results page. Everything that comes from the scanned document goes through textContent (see common.js). */
(function () {
  "use strict";
  const { h, s, $, $$, mount, clear, api, meta, bandOf, pill, fmtDate, pct, num, plural, visibleNodes, visibleText, toast,
    confirmDialog, copyText, downloadText, gauge, updateGauge, bandScale } = PG;

  const sid = document.body.dataset.sid;
  const WEAK = new Set(["style_break", "ml_flagged"]);
  const STATUS = { reachable: "#EF4444", blocked: "#22C55E", text_only: "#F59E0B" };
  const SHORT = { send_messages: "Send messages", private_data: "Read private data", web_fetch: "Open web links", run_code: "Run code",
    write_data: "Edit files and records", payments: "Make payments", render_images: "Render remote images" };

  let M, scan, R, byId = {}, selected = null, showDisc = false, cps = [];
  let blastState = null;                       // what-if state: {blast, risk, profile, caps}

  const clip = (t, n) => (t.length > n ? t.slice(0, n - 1) + "…" : t);
  const catLabel = k => (M.categories[k] ? M.categories[k].label : k);

  // ------------------------------------------------------------------ top of page
  function renderHeader() {
    $("#title").textContent = scan.name || "Scan results";
    document.title = `${scan.name || "Scan"} · PromptGuard`;
    mount($("#meta"),
      h("span", null, "Scanned ", h("b", { text: fmtDate(scan.created_at) })),
      h("span", null, "Scan ID ", h("b", { class: "mono", text: scan.id })),
      h("span", null, h("b", { text: R.stats.chars.toLocaleString() }), " characters, ", h("b", { text: R.stats.words.toLocaleString() }), " words"),
      h("span", null, "Analysed in ", h("b", { text: `${R.stats.seconds}s` })));

    const notes = [];
    for (const n of R.input_notes || []) notes.push(h("div", { class: "notice warn", text: n }));
    if (!scan.text_stored) notes.push(h("div", { class: "notice", text: "The original text was not stored for this scan (see Settings), so the highlighted view, the sanitised copy and the red-team test are unavailable. The findings below still show the flagged passages." }));
    mount($("#notes"), ...notes);
  }

  function renderOverall() {
    const risk = R.risk;
    const g = gauge(risk.score, risk.colour, "Risk");
    g.id = "main-gauge";
    const worst = R.blast.worst_case;
    mount($("#overall"),
      h("div", { class: "panel-head" }, h("h2", { id: "overall-h", text: "Overall Risk Assessment" })),
      g,
      h("div", { class: "row between mt" }, h("div", null, h("div", { class: "num", text: `Risk Score: ${risk.score}/100` }), h("div", { class: "muted", text: `Risk Category: ${risk.category}` })),
        pill(risk.category)),
      h("div", { class: "two-scores" },
        h("div", null, h("b", { class: "num", text: `${R.content_threat.score}` }), h("span", { text: "Content threat, on its own" })),
        h("div", null, h("b", { class: "num", text: pct(R.confidence) }), h("span", { text: "Detection confidence" }))),
      h("p", { class: "dim mt", text: worst ? "No agent profile was chosen, so the exposure score assumes the worst case. Pick one in the Blast Radius section below." : `Exposure on this agent: ${R.blast.profile_label}.` }),
      bandScale());
  }

  function renderSummary() {
    const order = Object.keys(M.categories);
    const max = Math.max(1, ...order.map(k => R.summary[k] || 0));
    const methods = Object.entries(R.methods).filter(([, v]) => v).map(([k, v]) => h("span", { class: "tag", text: `${M.method_labels[k] || k}: ${v}` }));
    mount($("#summary"),
      h("div", { class: "panel-head" }, h("h2", { id: "summary-h", text: "Detection Summary" }),
        h("span", { class: "sub", text: `${plural(R.stats.visible_findings, "finding")}, ${R.stats.discounted_findings} discounted by context` })),
      h("div", { class: "catbars" }, ...order.map(k => {
        const n = R.summary[k] || 0;
        return h("div", { class: "catbar" + (n ? "" : " zero"), data: { cat: k } },
          h("span", { text: catLabel(k) }), h("span", { class: "bar" }, h("i", { vars: { "--w": String((n / max) * 100) } })), h("b", { class: "num", text: String(n) }));
      })),
      methods.length ? h("div", { class: "row mt" }, h("span", { class: "dim", text: "Found by" }), ...methods) : null,
      R.stats.discounted_findings ? h("p", { class: "dim mt", text: `${plural(R.stats.discounted_findings, "rule match", "rule matches")} looked harmless in context (quotes, security discussion, prohibitions) and are not counted. You can show them in the viewer.` }) : null);
  }

  // ------------------------------------------------------------------ highlighted viewer
  function visibleHighlights() {
    const list = R.highlights.filter(x => showDisc || !x.discounted).sort((a, b) => a.start - b.start).map(x => Object.assign({}, x, { ids: x.ids.slice() }));
    // A run of hidden characters can be split into several highlight pieces. Show it as one chip instead of several.
    const out = [];
    for (const hl of list) {
      const prev = out[out.length - 1];
      if (prev && prev.end === hl.start && PG.isAllInvisible(cps.slice(prev.start, prev.end).join("")) && PG.isAllInvisible(cps.slice(hl.start, hl.end).join(""))) {
        prev.end = hl.end; prev.ids = Array.from(new Set(prev.ids.concat(hl.ids)));
        if (hl.p > prev.p) { prev.p = hl.p; prev.category = hl.category; }
      } else out.push(hl);
    }
    return out;
  }

  function pickId(ids) { return ids.slice().sort((a, b) => (byId[b] ? byId[b].p : 0) - (byId[a] ? byId[a].p : 0))[0]; }

  function renderLegend() {
    const present = new Set(R.findings.filter(f => showDisc || !f.discounted).map(f => f.category));
    mount($("#legend"), ...Object.keys(M.categories).filter(k => present.has(k)).map(k => h("span", { data: { cat: k } }, h("i"), catLabel(k))));
    const nd = R.stats.discounted_findings;
    $("#disc-toggle").classList.toggle("hidden", !nd);
    $("#disc-label").textContent = `Show ${plural(nd, "match", "matches")} discounted by context`;
  }

  function renderDoc() {
    const doc = $("#doc");
    clear(doc);
    if (!scan.text_stored) { doc.append(h("p", { class: "muted", text: "The original text was not stored for this scan." })); return; }
    let pos = 0;
    for (const hl of visibleHighlights()) {
      if (hl.start < pos) continue;
      if (hl.start > pos) for (const n of visibleNodes(cps.slice(pos, hl.start).join(""))) doc.append(n);
      const f = byId[pickId(hl.ids)];
      const mark = h("mark", { class: "hl" + (hl.discounted ? " discounted" : ""), data: { cat: hl.category, ids: hl.ids.join(",") }, tabindex: "0", role: "button",
        "aria-label": `${f ? f.category_label : "Finding"}: open explanation`,
        on: { click: () => select(pickId(hl.ids), false), keydown: e => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); select(pickId(hl.ids), false); } } } },
        ...visibleNodes(cps.slice(hl.start, hl.end).join("")));
      doc.append(mark);
      pos = hl.end;
    }
    if (pos < cps.length) for (const n of visibleNodes(cps.slice(pos).join(""))) doc.append(n);
    paintSelection();
  }

  function paintSelection() {
    $$("mark.hl").forEach(m => m.classList.toggle("selected", selected !== null && m.dataset.ids.split(",").includes(String(selected))));
    $$(".fitem").forEach(b => b.setAttribute("aria-pressed", String(Number(b.dataset.id) === selected)));
  }

  function scrollToMark() {
    const mark = $$("mark.hl.selected")[0];
    if (!mark) return;
    const doc = $("#doc"), a = mark.getBoundingClientRect(), b = doc.getBoundingClientRect();
    doc.scrollTop += a.top - b.top - b.height / 3;
  }

  // ------------------------------------------------------------------ findings list and explanation
  function shown() { return R.findings.filter(f => showDisc || !f.discounted).sort((a, b) => Number(a.discounted) - Number(b.discounted) || b.score - a.score); }

  function renderList() {
    const list = shown();
    $("#flist-count").textContent = plural(list.length, "item");
    mount($("#flist"), ...(list.length ? list.map(f => h("button", { type: "button", class: "fitem" + (f.discounted ? " discounted" : ""), data: { cat: f.category, id: f.id },
      "aria-pressed": "false", on: { click: () => select(f.id, true) } },
      h("span", { class: "bar" }),
      h("div", null, h("div", { class: "t", text: clip(visibleText(f.text).replace(/\s+/g, " "), 60) }),
        h("div", { class: "k", text: `${f.category_label}${f.discounted ? ", discounted by context" : ""}` })),
      pill(f.band))) : [h("p", { class: "muted", text: "No suspicious instructions were found." })]));
  }

  function row(label, ...content) { return [h("dt", { text: label }), h("dd", null, ...content)]; }

  function renderDetail() {
    const box = $("#detail");
    const f = selected === null ? null : byId[selected];
    if (!f) {
      mount(box, h("div", { class: "detail" }, h("p", { class: "muted", text: R.findings.length ? "Select a highlighted passage or a finding to see why it was flagged, how it was found and what to do." : "Nothing in this content looked like an instruction aimed at an AI." }),
        R.findings.length ? null : h("p", { class: "dim mt", text: "That is not a guarantee. PromptGuard does not catch every attack." })));
      return;
    }
    const path = R.blast.paths.find(p => p.finding_ids.includes(f.id));
    const dl = h("dl", null,
      ...row("What was detected", h("div", { class: "quote" }, ...visibleNodes(f.text))),
      ...row("Why it was flagged", h("div", { text: f.explanation }),
        f.reasons.length ? h("ul", { class: "reasons" }, ...f.reasons.map(r => h("li", { text: r }))) : null),
      ...row("Detection method", `${f.method_label}${f.rule_id ? `, rule ${f.rule_id}` : ""}`,
        f.via === "deobfuscated" ? h("div", { class: "dim", text: "Found only after hidden characters, look-alike letters or spacing were cleaned up." }) : null,
        f.ml_p !== null && f.ml_p !== undefined ? h("div", { class: "dim", text: `Text classifier estimate for this passage: ${pct(f.ml_p)}` }) : null),
      ...row("Severity", `${f.band}, ${f.score}/100`, f.severity ? h("span", { class: "dim", text: ` (rule severity ${f.severity}/10)` }) : null),
      f.context_label ? row("Context", f.context_label) : [],
      path ? row("On your agent", pill2(path.status), " ", h("span", { text: path.label })) : [],
      ...row("What to do", f.action));
    mount(box, h("div", { class: "detail", data: { cat: f.category } },
      h("div", { class: "row between" }, h("h3", { text: `${f.id}. ${f.name}` }), pill(f.band)),
      f.discounted ? h("div", { class: "notice mt", text: "A rule matched this text, but the context makes it look harmless, so it is not counted in the score." }) : null,
      dl));
  }

  function pill2(status) { return h("span", { class: `pill ${status}`, text: { reachable: "Reachable", blocked: "Blocked", text_only: "Works anywhere" }[status] }); }

  function select(id, scroll) {
    selected = id;
    renderDetail();
    paintSelection();
    if (scroll) scrollToMark();
  }

  // ------------------------------------------------------------------ blast radius
  function pathDiagram(blast, content) {
    const paths = blast.paths.slice(0, 8);
    const ROW = 60, H = Math.max(130, paths.length * ROW + 20), W = 760, mid = H / 2;
    const cap = id => SHORT[id] || (blast.all_capabilities[id] || id);
    const defs = s("defs", null, ...Object.entries(STATUS).map(([k, c]) =>
      s("marker", { id: `ah-${k}`, viewBox: "0 0 10 10", refX: 8, refY: 5, markerWidth: 7, markerHeight: 7, orient: "auto" }, s("path", { d: "M1 1L9 5L1 9", fill: "none", stroke: c, "stroke-width": 1.8, "stroke-linecap": "round", "stroke-linejoin": "round" }))));
    const kids = [defs];
    const b = bandOf(content);
    kids.push(s("rect", { x: 6, y: mid - 38, width: 150, height: 76, rx: 12, fill: "#16233B", stroke: b[3], "stroke-width": 2 }),
      s("text", { x: 81, y: mid - 8, "text-anchor": "middle", "font-size": 14, "font-weight": 700, fill: "#F8FAFC", text: "This content" }),
      s("text", { x: 81, y: mid + 16, "text-anchor": "middle", "font-size": 12.5, fill: b[3], text: `threat ${content}/100` }));
    paths.forEach((p, i) => {
      const cy = 10 + i * ROW + ROW / 2, c = STATUS[p.status];
      const dash = p.status === "blocked" ? "6 5" : null;
      kids.push(s("path", { d: `M156 ${mid} C 190 ${mid}, 190 ${cy}, 226 ${cy}`, fill: "none", stroke: c, "stroke-width": 2, "stroke-dasharray": dash }));
      kids.push(s("rect", { x: 226, y: cy - 21, width: 270, height: 42, rx: 9, fill: "#0D1628", stroke: c, "stroke-width": 1.5 }),
        s("text", { x: 238, y: cy + 5, "font-size": 13, fill: "#F8FAFC", text: clip(p.label, 38) }));
      let right;
      if (p.status === "reachable") right = `Agent can: ${p.have.map(cap).join(" or ")}`;
      else if (p.status === "blocked") right = `Missing: ${p.needs_ids.map(cap).join(" or ")}`;
      else right = "Needs only text output";
      kids.push(s("line", { x1: 496, y1: cy, x2: 548, y2: cy, stroke: c, "stroke-width": 2, "stroke-dasharray": dash, "marker-end": p.status === "blocked" ? null : `url(#ah-${p.status})` }));
      if (p.status === "blocked") kids.push(s("path", { d: `M514 ${cy - 7} L528 ${cy + 7} M528 ${cy - 7} L514 ${cy + 7}`, stroke: c, "stroke-width": 2.4, "stroke-linecap": "round" }));
      kids.push(s("rect", { x: 548, y: cy - 21, width: 206, height: 42, rx: 9, fill: "#0D1628", stroke: c, "stroke-width": 1.5, "stroke-dasharray": dash }),
        s("text", { x: 560, y: cy + 5, "font-size": 12.5, fill: "#DCE4F0", text: clip(right, 30) }));
    });
    const counts = ["reachable", "blocked", "text_only"].map(k => paths.filter(p => p.status === k).length);
    return s("svg", { class: "paths-svg", viewBox: `0 0 ${W} ${H}`, role: "img",
      "aria-label": `Attack paths from this content: ${counts[0]} reachable, ${counts[1]} blocked, ${counts[2]} that work without any tool.` }, ...kids);
  }

  function renderBlast() {
    const st = blastState, b = st.blast, content = R.content_threat.score;
    const sel = h("select", { class: "input inline-select", id: "bp", "aria-label": "Agent profile" },
      ...Object.entries(M.profiles).map(([id, p]) => h("option", { value: id, text: p.label, selected: id === st.profile })));
    sel.addEventListener("change", () => recompute(sel.value, sel.value === "custom" ? st.caps : [], "bp"));
    const capBox = st.profile === "custom" ? h("div", { class: "capgrid mt", role: "group", "aria-label": "Agent capabilities" },
      ...Object.entries(M.capabilities).map(([id, label]) => h("label", { class: "chip" },
        h("input", { type: "checkbox", id: `cap-${id}`, value: id, checked: st.caps.includes(id), on: { change: () => recompute("custom", $$("#blast .capgrid input:checked").map(i => i.value), `cap-${id}`) } }), h("span", { text: label })))) : null;

    const ex = st.risk;
    const reach = b.worst_case ? "worst case, every capability assumed" : `${Math.round(b.reach * 100)}% of the attack paths are open`;
    const side = h("div", { class: "stack" },
      h("div", null, h("div", { class: "row" }, h("span", { class: "num", text: `Exposure ${ex.score}/100` }), pill(ex.category)),
        h("p", { class: "dim", text: `Content threat ${content} × agent multiplier ${b.multiplier.toFixed(2)}. ${reach}.` })),
      b.paths.length ? h("ul", { class: "paths" }, ...b.paths.map(p => h("li", { class: "path" }, h("span", { text: p.label }), pill2(p.status),
        h("small", { text: p.status === "reachable" ? `The agent has: ${p.have.map(c => b.all_capabilities[c]).join("; ").toLowerCase()}.`
          : p.status === "blocked" ? `Needs: ${p.needs.join(" or ").toLowerCase()}. The agent has none of these.` : "No tool is needed. A reply is enough." }))))
        : h("p", { class: "muted", text: "Nothing in this content asks the AI to do anything specific, so there are no attack paths to trace." }),
      ...b.standing_risk.map(t => h("div", { class: "notice warn", text: t })),
      ...b.mitigations.map(t => h("div", { class: "notice", text: t })));

    mount($("#blast"),
      h("div", { class: "panel-head" }, h("h2", { id: "blast-h", text: "Blast Radius" }), h("span", { class: "sub", text: "What this content could do on a particular AI agent" })),
      h("div", { class: "row" }, h("label", { for: "bp", class: "muted", text: "Agent profile" }), sel),
      capBox,
      h("div", { class: "blast mt" }, h("div", null, b.paths.length ? pathDiagram(b, content) : null, b.paths.length > 8 ? h("p", { class: "dim", text: `Showing 8 of ${b.paths.length} paths. The list lists all.` }) : null), side),
      h("p", { class: "rule-note", text: "Try other profiles to see how the same content scores for an agent with fewer tools. The multipliers are design choices made for this project and have not been validated against real incidents." }));
    // keep keyboard focus on the control that was just used
    if (st.focus) { const el = document.getElementById(st.focus); if (el) el.focus(); st.focus = null; }
  }

  async function recompute(profile, caps, focus) {
    try {
      const out = await api(`/api/scans/${sid}/blast`, { json: { profile, custom_caps: caps } });
      blastState = { blast: out.blast, risk: out.risk, profile, caps, focus };
      renderBlast();
    } catch (e) { toast(e.message, "error"); }
  }

  // ------------------------------------------------------------------ breakdown, recommendations
  function renderBreakdown() {
    const cs = R.contributions;
    const max = Math.max(0.0001, ...cs.map(c => c.contribution));
    const strong = R.signals.rule_strong;
    mount($("#breakdown"),
      h("div", { class: "panel-head" }, h("h2", { id: "bd-h", text: "Why this score" }), h("span", { class: "sub", text: "how much each signal added" })),
      h("div", { class: "breakdown" }, ...cs.map(c => h("div", { class: "brow", title: `signal ${c.value.toFixed(2)} × weight ${c.weight.toFixed(2)}` },
        h("span", { text: c.label }), h("span", { class: "bar" }, h("i", { vars: { "--w": String((c.contribution / max) * 100) } })), h("span", { class: "num dim", text: c.contribution.toFixed(2) })))),
      h("p", { class: "rule-note", text: "The signals are combined by a logistic model fitted on a validation set, which also learned how heavily to weigh each one. Bars show weight × signal strength." }),
      strong > 0 ? h("p", { class: "rule-note", text: `A high-severity rule match that survived the context check (confidence ${strong.toFixed(2)}) sets a floor of ${(0.9 * strong).toFixed(2)} under the final probability. This floor was added after testing showed the model underweighted obvious rule matches.` }) : null,
      !R.style.applicable ? h("p", { class: "rule-note", text: `The style-break check was skipped: ${R.style.reason}.` }) : null);
    mount($("#recs"),
      h("div", { class: "panel-head" }, h("h2", { id: "recs-h", text: "Recommended Actions" })),
      h("ul", { class: "recs" }, ...R.recommendations.map(r => h("li", { text: r }))));
  }

  // ------------------------------------------------------------------ safe copy
  function renderSanitize() {
    const root = $("#sanitize");
    const candidates = R.findings.filter(f => !f.discounted && f.end > f.start);
    const defaults = new Set(candidates.filter(f => f.p >= 0.3 && !WEAK.has(f.category)).map(f => f.id));
    if (!scan.text_stored || !candidates.length) {
      mount(root, h("div", { class: "panel-head" }, h("h2", { id: "san-h", text: "Safe Copy" })),
        h("p", { class: "muted", text: !scan.text_stored ? "The original text was not stored, so a sanitised copy cannot be built." : "There is nothing flagged to remove. Your original was not changed." }));
      return;
    }
    const modeBox = ["remove", "quarantine"].map(v => h("label", { class: "switch" }, h("input", { type: "radio", name: "smode", value: v, checked: v === "remove" }),
      h("span", null, h("b", { text: v === "remove" ? "Remove" : "Quarantine" }), h("div", { class: "dim", text: v === "remove" ? "Replace each flagged passage with a visible placeholder." : "Keep the passage but wrap it in a marker that tells a reader to treat it as untrusted data." }))));
    const list = h("div", { class: "stack" }, ...candidates.map(f => h("label", { class: "switch" },
      h("input", { type: "checkbox", value: String(f.id), checked: defaults.has(f.id) }),
      h("span", null, h("b", { text: `${f.id}. ${f.category_label}` }), " ", h("span", { class: "dim", text: clip(visibleText(f.text).replace(/\s+/g, " "), 90) })))));
    const out = h("div", { id: "san-out", class: "mt", "aria-live": "polite" });
    const go = h("button", { class: "btn btn-primary", type: "button", text: "Build sanitised copy" });
    go.addEventListener("click", async () => {
      go.disabled = true;
      try {
        const res = await api(`/api/scans/${sid}/sanitize`, { json: {
          mode: $("input[name=smode]:checked", root).value, ids: $$("input[type=checkbox][value]:checked", list).map(i => Number(i.value)), strip_hidden: $("#strip").checked } });
        renderSanitized(out, res);
      } catch (e) { toast(e.message, "error"); }
      go.disabled = false;
    });
    mount(root,
      h("div", { class: "panel-head" }, h("h2", { id: "san-h", text: "Safe Copy" }), h("span", { class: "sub", text: "your original is never changed" })),
      h("div", { class: "grid cols-2" }, h("div", { class: "stack" }, h("span", { class: "lab", text: "How to handle flagged passages" }), ...modeBox,
        h("label", { class: "switch" }, h("input", { type: "checkbox", id: "strip" }), h("span", null, h("b", { text: "Also remove invisible characters" }), h("div", { class: "dim", text: "Zero-width and tag characters are deleted from the whole copy." })))),
        h("div", { class: "stack" }, h("span", { class: "lab", text: "Passages to include" }), list)),
      h("div", { class: "row mt" }, go), out);
  }

  function renderSanitized(out, res) {
    const rc = res.recheck;
    const name = (scan.name || "document").replace(/\.[A-Za-z0-9]+$/, "").replace(/[^\w.-]+/g, "_");
    mount(out,
      h("div", { class: "notice ok" }, h("div", { class: "row" }, h("b", { text: "Scanned again:" }), pill(bandOf(rc.score_before)[2]), h("span", { class: "num", text: `${rc.score_before}` }), "to", pill(rc.category_after), h("span", { class: "num", text: `${rc.score_after}` }),
        h("span", { class: "dim", text: `${plural(rc.findings_before, "finding")} before, ${rc.findings_after} after` }))),
      rc.remaining.length ? h("div", { class: "notice warn mt" }, h("b", { text: "Still flagged in the copy: " }), rc.remaining.map(r => `${r.category_label} (${r.score}) "${clip(visibleText(r.text), 60)}"`).join("; ")) : null,
      h("p", { class: "rule-note", text: res.limitation }),
      h("div", { class: "diff" }, ...res.changes.slice(0, 12).flatMap(c => [
        h("div", { class: "del" }, "Before: ", ...visibleNodes(clip(c.before, 240))), h("div", { class: "add" }, "After: ", ...visibleNodes(clip(c.after, 240)))])),
      res.changes.length > 12 ? h("p", { class: "dim", text: `${res.changes.length - 12} more changes are in the copy.` }) : null,
      h("pre", { class: "out" }, ...visibleNodes(res.text)),
      h("div", { class: "row mt" },
        h("button", { class: "btn btn-secondary btn-sm", type: "button", text: "Copy sanitised text", on: { click: () => copyText(res.text) } }),
        h("button", { class: "btn btn-secondary btn-sm", type: "button", text: "Download as .txt", on: { click: () => downloadText(`${name}-sanitised.txt`, res.text) } })));
  }

  // ------------------------------------------------------------------ red team
  function renderRedTeam() {
    const root = $("#redteam");
    const out = h("div", { class: "mt", "aria-live": "polite" });
    const go = h("button", { class: "btn btn-secondary", type: "button", text: "Attack this detector" });
    const flagged = R.findings.some(f => !f.discounted);
    go.disabled = !flagged || !scan.text_stored;
    go.addEventListener("click", async () => {
      go.disabled = true; go.textContent = "Attacking...";
      try {
        const f = selected !== null && byId[selected] && !byId[selected].discounted ? selected : undefined;
        renderFuzz(out, await api(`/api/scans/${sid}/fuzz`, { json: { finding_id: f } }));
      } catch (e) { toast(e.message, "error"); }
      go.disabled = false; go.textContent = "Attack this detector";
    });
    mount(root,
      h("div", { class: "panel-head" }, h("h2", { id: "rt-h", text: "Red-team Test" }), h("span", { class: "sub", text: "can the flagged passage be disguised?" })),
      h("p", { class: "muted", text: "PromptGuard rewrites the selected finding in 14 ways (hidden characters, typos, synonyms, base64, translation, hiding it in HTML and others) and runs each version through the full detector. A version counts as a miss when its content-threat score falls below 30." }),
      h("div", { class: "row mt" }, go, h("span", { class: "dim", text: flagged ? "Select a finding first to choose which one to attack. Otherwise the strongest is used." : "This scan has nothing flagged to attack." })), out);
  }

  function renderFuzz(out, res) {
    const rows = res.rows.slice().sort((a, b) => Number(a.detected) - Number(b.detected) || a.score - b.score);
    mount(out,
      h("div", { class: res.evaded ? "notice warn" : "notice ok" },
        h("b", { text: `${res.evaded} of ${res.tested} rewrites got past the detector` }), ` (${pct(res.evasion_rate)}). The unmodified passage scored ${res.baseline_score}.`,
        h("div", { class: "dim", text: `Attacked: "${clip(visibleText(res.finding.text).replace(/\s+/g, " "), 110)}"` })),
      h("div", { class: "table-wrap mt" }, h("table", { class: "data" },
        h("thead", null, h("tr", null, ["Rewrite", "Score", "Result", "Preview"].map((t, i) => h("th", { class: i === 1 ? "num" : "", text: t })))),
        h("tbody", null, ...rows.map(r => h("tr", null, h("td", null, r.label, " ", h("span", { class: "tag", text: r.family })),
          h("td", { class: "num", text: String(r.score) }), h("td", null, h("span", { class: `pill ${r.detected ? "blocked" : "reachable"}`, text: r.detected ? "Caught" : "Missed" })),
          h("td", { class: "muted" }, h("span", { class: "mono", text: clip(visibleText(r.preview).replace(/\s+/g, " "), 90) }))))))),
      h("p", { class: "rule-note", text: res.note }));
  }

  // ------------------------------------------------------------------ boot
  async function main() {
    try {
      [M, scan] = await Promise.all([meta(), api(`/api/scans/${sid}`)]);
    } catch (e) { mount($("#notes"), h("div", { class: "notice error", text: e.message })); return; }
    R = scan.result;
    R.findings.forEach(f => (byId[f.id] = f));
    cps = scan.text_stored ? Array.from(scan.text) : [];
    blastState = { blast: R.blast, risk: R.risk, profile: R.blast.profile in M.profiles ? R.blast.profile : "unknown", caps: scan.custom_caps || [] };

    renderHeader(); renderOverall(); renderSummary(); renderLegend(); renderDoc(); renderList(); renderDetail();
    renderBlast(); renderBreakdown(); renderSanitize(); renderRedTeam();

    $("#show-disc").addEventListener("change", e => {
      showDisc = e.target.checked;
      if (!showDisc && selected !== null && byId[selected] && byId[selected].discounted) selected = null;
      renderLegend(); renderDoc(); renderList(); renderDetail();
    });
    $("#delete").addEventListener("click", async () => {
      if (!(await confirmDialog("Delete this scan?", "The stored text and report for this scan will be removed from this computer. This cannot be undone.", "Delete scan"))) return;
      try { await api(`/api/scans/${sid}`, { method: "DELETE" }); location.href = "/history"; } catch (e) { toast(e.message, "error"); }
    });
    // open the strongest finding so the explanation panel is never empty on arrival
    const first = shown().find(f => !f.discounted);
    if (first) select(first.id, false);
  }
  main();
})();
