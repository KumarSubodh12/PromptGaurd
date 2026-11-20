(function () {
  "use strict";
  const { h, $, $$, mount, api, meta, pill, fmtDate, plural, toast, confirmDialog, modal, emptyState } = PG;
  let M, rows = [], picked = new Set(), timer = null;

  function updateButtons() {
    $("#compare").disabled = picked.size !== 2;
    $("#compare").textContent = picked.size === 2 ? "Compare selected" : picked.size ? `Pick one more to compare` : "Compare selected";
    $("#delete-all").disabled = rows.length === 0 && !$("#q").value;
  }

  function render() {
    $("#count").textContent = plural(rows.length, "scan");
    if (!rows.length) {
      mount($("#table"), $("#q").value ? emptyState("No match", "No scan has that name.") : emptyState("No scans yet", "Scans you run will be listed here.", h("a", { class: "btn btn-primary btn-sm", href: "/scan", text: "New scan" })));
      updateButtons(); return;
    }
    mount($("#table"), h("table", { class: "data" },
      h("thead", null, h("tr", null, h("th", { text: "Compare" }), ...["Document", "Scanned", "Risk", "Findings", "Agent profile", ""].map((t, i) => h("th", { class: i === 3 ? "num" : "", text: t })))),
      h("tbody", null, ...rows.map(r => h("tr", null,
        h("td", null, h("input", { type: "checkbox", "aria-label": `Select ${r.name} for comparison`, checked: picked.has(r.id), on: { change: e => {
          if (e.target.checked) { if (picked.size >= 2) { e.target.checked = false; toast("Compare works on two scans. Untick one first."); return; } picked.add(r.id); } else picked.delete(r.id);
          updateButtons(); } } })),
        h("td", null, h("a", { class: "link-row", href: `/scan/${r.id}`, text: r.name || "Untitled" })),
        h("td", { class: "muted", text: fmtDate(r.created_at) }),
        h("td", null, h("span", { class: "score-cell" }, h("span", { class: "num", text: String(r.risk_score) }), pill(r.category))),
        h("td", { class: "num", text: String(r.n_findings) }),
        h("td", { class: "muted", text: M.profiles[r.profile] ? M.profiles[r.profile].label : r.profile }),
        h("td", null, h("div", { class: "row" },
          h("a", { class: "btn btn-secondary btn-sm", href: `/scan/${r.id}`, text: "View report" }),
          h("button", { class: "btn btn-ghost btn-sm", type: "button", "aria-label": `Delete ${r.name}`, text: "Delete", on: { click: () => del(r) } }))))))));
    updateButtons();
  }

  async function load() {
    try { rows = await api("/api/scans?q=" + encodeURIComponent($("#q").value.trim())); picked = new Set([...picked].filter(id => rows.some(r => r.id === id))); render(); }
    catch (e) { mount($("#table"), h("div", { class: "notice error", text: e.message })); }
  }

  async function del(r) {
    if (!(await confirmDialog("Delete this scan?", `"${r.name}" and its report will be removed from this computer.`, "Delete scan"))) return;
    try { await api(`/api/scans/${r.id}`, { method: "DELETE" }); picked.delete(r.id); toast("Scan deleted."); load(); } catch (e) { toast(e.message, "error"); }
  }

  $("#delete-all").addEventListener("click", async () => {
    if (!(await confirmDialog("Delete all scans?", "Every stored scan, its text and its report will be removed from this computer. This cannot be undone.", "Delete everything"))) return;
    try { const r = await api("/api/scans", { method: "DELETE" }); picked.clear(); toast(`${plural(r.deleted, "scan")} deleted.`); $("#q").value = ""; load(); } catch (e) { toast(e.message, "error"); }
  });
  $("#q").addEventListener("input", () => { clearTimeout(timer); timer = setTimeout(load, 200); });

  // ---------------------------------------------------------------- compare
  $("#compare").addEventListener("click", async () => {
    const ids = [...picked];
    try {
      const [a, b] = await Promise.all(ids.map(id => api(`/api/scans/${id}`)));
      const [older, newer] = a.created_at <= b.created_at ? [a, b] : [b, a];
      const keys = Object.keys(M.categories).filter(k => (older.result.summary[k] || 0) || (newer.result.summary[k] || 0));
      const col = sc => h("div", { class: "panel flat" }, h("h3", { text: sc.name }), h("p", { class: "dim", text: fmtDate(sc.created_at) }),
        h("div", { class: "row mt" }, h("span", { class: "big", text: String(sc.result.risk.score) }), pill(sc.result.risk.category)),
        h("p", { class: "muted mt", text: `Content threat ${sc.result.content_threat.score}. Agent profile: ${sc.result.blast.profile_label}. ${plural(sc.result.stats.visible_findings, "finding")}.` }));
      const delta = newer.result.risk.score - older.result.risk.score;
      const sentence = delta === 0 ? "Both scans have the same risk score." : `The newer scan scores ${Math.abs(delta)} ${delta > 0 ? "higher" : "lower"} than the older one.`;
      modal("Compare scans", h("div", null,
        h("div", { class: "cmp" }, col(older), col(newer)), h("p", { class: "mt", text: sentence }),
        keys.length ? h("div", { class: "table-wrap mt" }, h("table", { class: "data" },
          h("thead", null, h("tr", null, h("th", { text: "Category" }), h("th", { class: "num", text: "Older" }), h("th", { class: "num", text: "Newer" }), h("th", { class: "num", text: "Change" }))),
          h("tbody", null, ...keys.map(k => { const x = older.result.summary[k] || 0, y = newer.result.summary[k] || 0, d = y - x;
            return h("tr", null, h("td", { text: M.categories[k].label }), h("td", { class: "num", text: String(x) }), h("td", { class: "num", text: String(y) }),
              h("td", { class: "num " + (d > 0 ? "delta-up" : d < 0 ? "delta-down" : "dim"), text: d > 0 ? `+${d}` : String(d) })); })))) : h("p", { class: "muted mt", text: "Neither scan has findings." })));
    } catch (e) { toast(e.message, "error"); }
  });

  (async function () { try { M = await meta(); } catch (e) { M = { profiles: {}, categories: {} }; } load(); })();
})();
