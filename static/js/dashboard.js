(function () {
  "use strict";
  const { h, $, mount, api, pill, fmtDate, pct, num, donut, hbars, emptyState, bandOf, meta } = PG;

  function stat(label, value, note, colour) {
    return h("div", { class: "stat", vars: { "--sc": colour } },
      h("div", { class: "value", text: value }), h("div", { class: "label", text: label }), note ? h("div", { class: "note", text: note }) : null);
  }

  async function main() {
    let st, ev = null, m;
    try { [st, m] = await Promise.all([api("/api/stats"), meta()]); }
    catch (e) { mount($("#stats"), h("div", { class: "notice error", text: e.message })); return; }
    try { ev = await api("/api/evaluation"); } catch (e) { /* evaluation is optional here */ }

    mount($("#stats"),
      stat("Total scans", String(st.total_scans), st.total_scans ? "stored on this computer" : "none yet", "#38BDF8"),
      stat("Suspicious documents", String(st.suspicious_documents), st.total_scans ? `risk score 30 or higher, ${pct(st.suspicious_documents / st.total_scans)} of scans` : "risk score 30 or higher", "#F59E0B"),
      stat("High-risk findings", String(st.high_risk_findings), "findings scored 60 or higher", "#EF4444"),
      stat("Average detection confidence", st.avg_confidence === null ? "n/a" : pct(st.avg_confidence), "over scans that had findings", "#8B5CF6"));

    const bandColour = Object.fromEntries(m.bands.map(b => [b.label, b.colour]));
    const dist = Object.entries(st.risk_distribution).map(([label, value]) => ({ label, value, colour: bandColour[label] }));
    mount($("#risk-donut"), st.total_scans ? donut(dist, "scans") : emptyState("No scans yet", "Scan a document and its risk band will show up here.",
      h("a", { class: "btn btn-primary btn-sm", href: "/scan", text: "Run the first scan" })));

    const cats = Object.entries(st.category_keys).sort((a, b) => b[1] - a[1])
      .map(([k, v]) => ({ label: m.categories[k].label, value: v, cat: k }));
    mount($("#cat-bars"), hbars(cats, { empty: "No findings yet." }));

    const rec = st.recent;
    mount($("#recent"), rec.length ? h("table", { class: "data" },
      h("thead", null, h("tr", null, ["Document", "Scanned", "Risk", "Score", "Findings", "Status"].map((t, i) => h("th", { class: i >= 3 && i < 5 ? "num" : "", text: t })))),
      h("tbody", null, ...rec.map(r => h("tr", null,
        h("td", null, h("a", { class: "link-row", href: `/scan/${r.id}`, text: r.name || "Untitled" })),
        h("td", { class: "muted", text: fmtDate(r.created_at) }),
        h("td", null, pill(r.category)),
        h("td", { class: "num", text: String(r.risk_score) }),
        h("td", { class: "num", text: String(r.n_findings) }),
        h("td", { class: "muted", text: r.status }))))) : emptyState("Nothing scanned yet", "Recent scans will be listed here.", h("a", { class: "btn btn-secondary btn-sm", href: "/scan", text: "New scan" })));

    if (ev) {
      const hy = ev.test.metrics.hybrid, ch = ev.challenge.metrics.hybrid;
      mount($("#accuracy-note"),
        h("div", { class: "panel-head" }, h("h2", { text: "How accurate is the detector?" }), h("a", { href: "/research", text: "Full evaluation" })),
        h("p", { class: "muted", text: `On the ${ev.dataset.splits.test.n} held-out documents of our synthetic test set, the combined detector reached F1 ${num(hy.f1, 2)} (precision ${num(hy.precision, 2)}, recall ${num(hy.recall, 2)}, false-positive rate ${pct(hy.fpr)}). On a 70-item hand-written challenge set it reached F1 ${num(ch.f1, 2)}. These numbers come from generated data, not from real attacks, so treat them as a comparison between methods and not as a promise about real-world accuracy.` }));
    } else {
      $("#accuracy-note").remove();
    }
  }
  main();
})();
