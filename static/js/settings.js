(function () {
  "use strict";
  const { h, $, mount, api, meta, pill, toast, confirmDialog, plural } = PG;

  async function main() {
    let m;
    try { m = await meta(); } catch (e) { toast(e.message, "error"); return; }
    $("#store").checked = !!m.settings.store_text;
    mount($("#profile"), ...Object.entries(m.profiles).map(([id, p]) => h("option", { value: id, text: p.label })));
    $("#profile").value = m.settings.default_profile;

    mount($("#bands"), h("table", { class: "data" }, h("thead", null, h("tr", null, h("th", { text: "Risk score" }), h("th", { text: "Category" }))),
      h("tbody", null, ...m.bands.map(b => h("tr", null, h("td", { class: "num", text: `${b.min} to ${b.max === 100 ? 100 : b.max - 1}` }), h("td", null, pill(b.label)))))));

    const info = m.models.info || {};
    const rows = [["Text classifier (TF-IDF + Logistic Regression)", m.models.tfidf], ["Contextual classifier", m.models.context], ["Stacked combiner", m.models.stacker]];
    mount($("#models"), h("dl", { class: "kv" }, ...rows.flatMap(([k, ok]) => [h("dt", { text: k }), h("dd", { text: ok ? "loaded" : "not loaded, built-in fallback scoring is used" })]),
      ...Object.entries(info).filter(([, v]) => ["string", "number", "boolean"].includes(typeof v)).flatMap(([k, v]) => [h("dt", { text: k.replace(/_/g, " ") }), h("dd", { text: String(v) })])),
      !m.models.tfidf ? h("div", { class: "notice warn mt", text: "No trained model was found. Run: python scripts/train_and_evaluate.py" }) : null);

    $("#save").addEventListener("click", async () => {
      try { await api("/api/settings", { json: { store_text: $("#store").checked, default_profile: $("#profile").value } }); toast("Settings saved."); }
      catch (e) { toast(e.message, "error"); }
    });
    $("#wipe").addEventListener("click", async () => {
      if (!(await confirmDialog("Delete all scans?", "Every stored scan, its text and its report will be removed from this computer. This cannot be undone.", "Delete everything"))) return;
      try { const r = await api("/api/scans", { method: "DELETE" }); toast(`${plural(r.deleted, "scan")} deleted.`); } catch (e) { toast(e.message, "error"); }
    });
  }
  main();
})();
