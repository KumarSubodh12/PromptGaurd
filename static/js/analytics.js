(function () {
  "use strict";
  const { h, $, mount, api, meta, donut, hbars, lineChart, columnChart, groupedBars, emptyState, pct, PALETTE } = PG;

  async function main() {
    let st, m, ev = null;
    try { [st, m] = await Promise.all([api("/api/stats"), meta()]); } catch (e) { mount($("#empty"), h("div", { class: "notice error", text: e.message })); return; }
    try { ev = await api("/api/evaluation"); } catch (e) { /* optional */ }

    if (!st.total_scans) mount($("#empty"), h("div", { class: "notice mt", text: "You have not scanned anything yet, so the charts about your own scans are empty. The accuracy chart below comes from the research evaluation and does not depend on your scans." }));

    const bs = st.benign_vs_suspicious;
    mount($("#bs"), st.total_scans ? donut([{ label: "Benign", value: bs.benign, colour: "#22C55E" }, { label: "Suspicious", value: bs.suspicious, colour: "#EF4444" }], "scans") : PG.emptyChart("No scans yet."));
    mount($("#cats"), hbars(Object.entries(st.category_keys).sort((a, b) => b[1] - a[1]).map(([k, v]) => ({ label: m.categories[k].label, value: v, cat: k })), { empty: "No findings yet." }));
    mount($("#methods"), hbars(Object.entries(st.methods).sort((a, b) => b[1] - a[1]).map(([k, v], i) => ({ label: k, value: v, colour: PALETTE[i % PALETTE.length] })), { empty: "No findings yet." }));

    if (ev) {
      const ks = Object.keys(ev.methods), mt = ev.test.metrics;
      mount($("#acc"),
        groupedBars(["Precision", "Recall", "F1"], ks.map((k, i) => ({ name: ev.methods[k], colour: PALETTE[i], values: [mt[k].precision, mt[k].recall, mt[k].f1] })), { label: "Precision, recall and F1 for each detection method" }),
        h("p", { class: "rule-note", text: `Measured on ${ev.dataset.splits.test.n} synthetic test documents. The confidence intervals overlap, so differences in F1 between methods are not statistically clear.` }));
    } else mount($("#acc"), PG.emptyChart("No evaluation file found. Run scripts/train_and_evaluate.py."));

    const days = st.trend.map(t => ({ x: t.date.slice(5), y: t.avg_score, note: `${t.scans} scans` }));
    mount($("#trend"), lineChart(days, { ymax: 100, label: "Average risk score per day" }));
    mount($("#volume"), columnChart(st.trend.map(t => ({ label: t.date.slice(5), value: t.scans })), { label: "Scans per day" }));
  }
  main();
})();
