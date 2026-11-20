/* Research page: reads /api/evaluation and shows it without rounding the story in the project's favour. */
(function () {
  "use strict";
  const { h, $, mount, api, pct, num, plural, groupedBars, hbars, PALETTE } = PG;

  const METRIC_COLS = [["accuracy", "Accuracy"], ["precision", "Precision"], ["recall", "Recall"], ["f1", "F1"], ["fpr", "False-positive rate"], ["fnr", "False-negative rate"]];
  const ABLATION_LABELS = {
    full: "All signals (shipped)", without_audience: "Without audience mismatch", without_style: "Without style break", without_unicode: "Without hidden-text signal",
    without_novel_modules: "Without audience and style", rules_context_only: "Rules with context only", rules_and_tfidf: "Rules and TF-IDF only", without_evidence_floor: "Without the evidence floor",
  };
  const KIND_LABELS = {
    benign_plain: "Plain text", benign_educational: "Security article", benign_quoted: "Quotes an attack", benign_imperative: "Ordinary instructions", benign_long: "Long, mixed", benign_multilingual: "Other languages",
    mal_direct: "Direct attack", mal_paraphrase: "Paraphrased attack", mal_role: "Role manipulation", mal_tool: "Tool or data abuse", mal_audience: "Addresses the AI", mal_obfuscated: "Obfuscated", mal_long: "Buried in long text", mal_multilingual: "Other languages",
  };
  const clip = (t, n) => (t.length > n ? t.slice(0, n - 1) + "…" : t);

  let E;

  function finding(kind, strong, rest) { return h("li", { class: kind }, h("b", { text: strong }), " ", rest); }
  const th = (t, c) => h("th", { class: c || "", text: t });

  // ------------------------------------------------------------------ key findings, generated from the data
  function keyFindings() {
    const t = E.test, M = E.methods, hy = t.metrics.hybrid, out = [];
    const ci = k => t.bootstrap_95ci[k].f1;
    const overlap = Object.keys(M).filter(k => k !== "hybrid").every(k => ci(k)[1] >= ci("hybrid")[0]);
    out.push(finding("good", `The combined detector scored best on the synthetic test set (F1 ${num(hy.f1, 2)}, AUC ${num(t.auc.hybrid, 2)}).`,
      `Keyword rules reached F1 ${num(t.metrics.rules_keyword.f1, 2)} and AUC ${num(t.auc.rules_keyword, 2)}. ${overlap ? `The 95% intervals for F1 overlap for every method (combined detector ${num(ci("hybrid")[0], 2)} to ${num(ci("hybrid")[1], 2)}), so F1 alone does not prove it is better. AUC separates them more clearly.` : ""}`));

    out.push(finding("good", `Context is what removes false alarms.`,
      `Keyword rules flagged ${pct(t.metrics.rules_keyword.fpr)} of harmless documents and TF-IDF flagged ${pct(t.metrics.tfidf_lr.fpr)}. Adding context and the other signals brought that to ${pct(hy.fpr)}. Security articles and quoted attacks are the cases where keywords alone fail most (${pct(t.per_kind.benign_quoted.rules_keyword)} of quoted-attack documents were flagged by keywords, ${pct(t.per_kind.benign_quoted.hybrid)} by the combined detector).`));

    const chm = E.challenge.metrics, best = Object.keys(chm).reduce((a, b) => (chm[b].f1 > chm[a].f1 ? b : a));
    if (best !== "hybrid") out.push(finding("warn", `On the hand-written challenge set the combined detector was not the best.`,
      `${E.methods[best]} reached F1 ${num(chm[best].f1, 2)} against ${num(chm.hybrid.f1, 2)} for the combined detector, though the combined detector had fewer false alarms (${pct(chm.hybrid.fpr)}). With only ${E.challenge.n} items this is a warning, not a conclusion, but it means the advantage on the synthetic set may not carry over.`));

    const para = t.per_kind.mal_paraphrase, rv = t.review_threshold.per_kind.mal_paraphrase;
    out.push(finding("bad", `Paraphrased attacks are the main weakness.`,
      `With no attack keywords the combined detector caught ${pct(para.hybrid)} at the 0.5 cutoff (TF-IDF caught ${pct(para.tfidf_lr)}). At a review threshold of ${t.review_threshold.threshold} it flags ${pct(rv)} of them, at the cost of ${pct(t.review_threshold.metrics.fpr)} false alarms.`));

    const p5 = hy.precision_at_5pct_prevalence;
    out.push(finding("warn", `Base rates matter.`, `If only 5% of documents were attacks, the combined detector's precision would be about ${pct(p5)}, so roughly ${pct(1 - p5)} of its alerts would be false. The test set is about half malicious, which flatters precision.`));

    const ops = E.fuzzer.before.by_operator.hybrid, weak = Object.entries(ops).filter(([, v]) => v.rate >= 0.25 && v.n >= 10).sort((a, b) => b[1].rate - a[1].rate);
    const label = n => (E.fuzzer.operators.find(o => o.name === n) || { label: n }).label;
    if (weak.length) out.push(finding("bad", `The self-attacking fuzzer found real evasions.`, `Share of disguised attacks that got past the combined detector: ${weak.map(([n, v]) => `${label(n).toLowerCase()} ${pct(v.rate)}`).join(", ")}. Character-level tricks (hidden characters, look-alike letters, spacing) were all caught because the text is cleaned before matching.`));

    const hd = E.fuzzer.hardening;
    if (hd.test_metrics_after.f1 < hd.test_metrics_before.f1) out.push(finding("bad", `Retraining on the disguised attacks made the detector worse, so it was not shipped.`,
      `Using ${hd.train_mutants.toLocaleString()} generated variants, F1 went from ${num(hd.test_metrics_before.f1, 2)} to ${num(hd.test_metrics_after.f1, 2)} and false alarms from ${pct(hd.test_metrics_before.fpr)} to ${pct(hd.test_metrics_after.fpr)}. The shipped model is the un-hardened baseline.`));

    const ab = E.ablation;
    out.push(finding("", `Audience mismatch helped, style break did not.`,
      `Removing the audience signal lowered detection of text addressed to an AI from ${pct(ab.full.mal_audience)} to ${pct(ab.without_audience.mal_audience)} and raised false alarms on security articles from ${pct(ab.full.benign_educational)} to ${pct(ab.without_audience.benign_educational)}, while overall F1 hardly moved (${num(ab.full.f1, 3)} against ${num(ab.without_audience.f1, 3)}). The style-break signal got a weight of ${num(E.stacker.weights.style_p, 1)} in the combined model, and removing it changed nothing.`));

    const ev = ab.full.f1 - ab.without_evidence_floor.f1;
    out.push(finding("warn", `One design change was made after seeing test-set results.`, `The combined model gave rule matches too little weight, so an "evidence floor" was added: a strong rule match that survives the context check sets a minimum score. It raised F1 by ${num(ev, 2)} here, but it was chosen after looking at errors, so the improvement is optimistic.`));
    return out;
  }

  // ------------------------------------------------------------------ method comparison
  const SETS = () => [
    { id: "test", label: `Synthetic test (${E.dataset.splits.test.n})`, metrics: E.test.metrics, auc: E.test.auc, ci: E.test.bootstrap_95ci, note: "Held-out documents from a generated dataset. Templates, topics and payloads were kept apart between training and test." },
    { id: "challenge", label: `Hand-written challenge (${E.challenge.n})`, metrics: E.challenge.metrics, auc: null, ci: null, note: E.challenge.note },
    { id: "long", label: "Long documents", metrics: E.test.long_documents, auc: null, ci: null, note: "The subset of the test set where a short attack is buried in a long document." },
  ];
  function renderCompare(setId) {
    const set = SETS().find(s => s.id === setId), ks = Object.keys(E.methods);
    mount($("#set-tabs"), ...SETS().map(s => h("button", { type: "button", role: "tab", "aria-selected": String(s.id === setId), text: s.label, on: { click: () => renderCompare(s.id) } })));
    $("#set-note").textContent = set.note;
    mount($("#cmp-chart"), groupedBars(METRIC_COLS.map(c => c[1]), ks.map((k, i) => ({ name: E.methods[k], colour: PALETTE[i], values: METRIC_COLS.map(c => set.metrics[k][c[0]]) })), { label: "Metrics for each method" }));
    const hasAuc = !!set.auc;
    mount($("#cmp-table"), h("table", { class: "data" },
      h("thead", null, h("tr", null, th("Method"), ...METRIC_COLS.map(c => th(c[1], "num")), hasAuc ? th("AUC", "num") : null, th("Precision at 5% attacks", "num"))),
      h("tbody", null, ...ks.map(k => { const m = set.metrics[k];
        return h("tr", null, h("td", { text: E.methods[k] }), ...METRIC_COLS.map(c => h("td", { class: "num", text: num(m[c[0]], 3), title: set.ci && c[0] === "f1" ? `95% interval ${set.ci[k].f1[0]} to ${set.ci[k].f1[1]}` : null })),
          hasAuc ? h("td", { class: "num", text: num(set.auc[k], 3) }) : null, h("td", { class: "num", text: num(m.precision_at_5pct_prevalence, 2) })); }))),
      set.ci ? h("p", { class: "rule-note", text: `95% intervals for F1 (hover a value): ${ks.map(k => `${E.methods[k]} ${set.ci[k].f1[0]} to ${set.ci[k].f1[1]}`).join("; ")}. They come from a cluster bootstrap over template groups.` }) : null);
  }

  // ------------------------------------------------------------------ per-kind heat table
  function renderKinds() {
    const ks = Object.keys(E.methods), pk = E.test.per_kind;
    const cell = (v, label) => {
      const good = label === 1 ? v : 1 - v;                       // how good this result is, whichever way round the metric runs
      const td = h("td", { class: good >= .75 ? "good" : good < .5 ? "bad" : "", text: pct(v) });
      td.style.setProperty("--v", String(good >= .75 ? good : 1 - good));
      return td;
    };
    const rows = Object.entries(pk).map(([kind, v]) => h("tr", null, h("td", { class: "name" }, KIND_LABELS[kind] || kind, " ", h("span", { class: "dim", text: `n=${v.n}` })), ...ks.map(k => cell(v[k], v.label))));
    const mal = rows.filter((_, i) => Object.values(pk)[i].label === 1), ben = rows.filter((_, i) => Object.values(pk)[i].label === 0);
    const head = h("thead", null, h("tr", null, th("Kind"), ...ks.map(k => th(E.methods[k].replace(" + Logistic Regression", "").replace(" (stacked, all signals)", ""), "c"))));
    const sec = t => h("tr", null, h("td", { class: "name", colspan: String(ks.length + 1) }, h("b", { text: t })));
    mount($("#kinds"), h("table", { class: "heat" }, head, h("tbody", null, sec("Malicious: share detected"), ...mal, sec("Benign: share wrongly flagged"), ...ben)));
  }

  function renderBands() {
    const b = E.bands_on_test;
    mount($("#bands"), h("p", { class: "muted", text: "Share of test documents in each risk band that really were malicious. If the bands mean anything, this should rise from Low to Critical." }),
      hbars(Object.entries(b).map(([k, v]) => ({ label: `${k} (${v.n} docs)`, value: v.share_malicious * 100, display: pct(v.share_malicious), colour: { Low: "#22C55E", Medium: "#EAB308", High: "#F59E0B", Critical: "#EF4444" }[k] })), { max: 100 }));
    mount($("#calib"), h("table", { class: "data" }, h("thead", null, h("tr", null, th("Flag at score"), th("Precision", "num"), th("Recall", "num"), th("False-positive rate", "num"), th("Flagged", "num"))),
      h("tbody", null, ...E.calibration.map(c => h("tr", null, h("td", { class: "num", text: `${c.threshold}+` }), h("td", { class: "num", text: num(c.precision, 2) }), h("td", { class: "num", text: num(c.recall, 2) }), h("td", { class: "num", text: num(c.fpr, 2) }), h("td", { class: "num", text: String(c.flagged) }))))));
  }

  function renderAblation() {
    const A = E.ablation;
    const cols = [["precision", "Precision"], ["recall", "Recall"], ["f1", "F1"], ["fpr", "False-positive rate"], ["mal_audience", "AI-addressed attacks caught"], ["mal_paraphrase", "Paraphrases caught"], ["benign_educational", "Security articles flagged"]];
    mount($("#ablation"), h("table", { class: "data" }, h("thead", null, h("tr", null, th("Variant"), ...cols.map(c => th(c[1], "num")))),
      h("tbody", null, ...Object.keys(ABLATION_LABELS).filter(k => A[k]).map(k => h("tr", null, h("td", { text: ABLATION_LABELS[k] }), ...cols.map(c => h("td", { class: "num", text: num(A[k][c[0]], 3) })))))));
    $("#ablation-note").textContent = "Each variant retrains the combined model without that signal and scores the same test documents once. Differences of a few hundredths are within the noise of a test set this size.";
  }

  // ------------------------------------------------------------------ fuzzer
  function renderFuzz() {
    const F = E.fuzzer, ks = Object.keys(E.methods), before = F.before.by_operator, after = F.after.by_operator;
    const cell = (v, held) => { if (!v || v.n < 5) return h("td", { class: "na", text: v ? `n=${v.n}` : "n/a", title: "Too few detected seeds to report a rate." });
      const td = h("td", { class: v.rate >= .25 ? "bad" : "good", text: pct(v.rate), title: `${v.evaded} of ${v.n} evaded` }); td.style.setProperty("--v", String(v.rate >= .25 ? Math.min(1, v.rate) : Math.max(0, 1 - v.rate * 2))); return td; };
    mount($("#fuzz"), h("table", { class: "heat" },
      h("thead", null, h("tr", null, th("Disguise"), ...ks.map(k => th(E.methods[k].replace(" + Logistic Regression", "").replace(" (stacked, all signals)", ""), "c")), th("Combined detector after retraining", "c"))),
      h("tbody", null, ...F.operators.map(op => h("tr", null, h("td", { class: "name" }, op.label, op.name === F.held_out_operator ? h("span", { class: "tag", text: "held out from retraining" }) : null),
        ...ks.map(k => cell(before[k][op.name])), cell(after.hybrid[op.name]))))));
    const hd = F.hardening, shipped = E.shipped_models;
    mount($("#fuzz-note"), h("p", { class: "rule-note", text: F.note + ` ${F.seeds} attack passages and ${F.mutants.toLocaleString()} disguised versions were tested. Hover a cell for the counts. Cells with fewer than 5 detected seeds are not reported.` }),
      h("div", { class: "notice mt" }, h("b", { text: "Retraining on the disguised versions: " }),
        `F1 ${num(hd.test_metrics_before.f1, 3)} to ${num(hd.test_metrics_after.f1, 3)}, precision ${num(hd.test_metrics_before.precision, 2)} to ${num(hd.test_metrics_after.precision, 2)}, false-positive rate ${pct(hd.test_metrics_before.fpr)} to ${pct(hd.test_metrics_after.fpr)}. ${shipped === "baseline" ? "The baseline model is the one shipped. The hardened one is saved as promptguard_hardened.joblib for anyone who wants to inspect it." : "The hardened model is the one shipped."}`));
  }

  // ------------------------------------------------------------------ errors and interpretation
  function renderErrors() {
    const list = (items, total) => h("ol", { class: "errlist" }, ...items.slice(0, 8).map(e => h("li", null,
      h("div", null, h("span", { class: `pill ${e.label ? "reachable" : "text_only"}`, text: e.label ? "Missed attack" : "False alarm" }), " ", h("span", { class: "dim", text: `scored ${e.score}${e.kind ? ", " + (KIND_LABELS[e.kind] || e.kind) : ""}` })),
      h("div", { class: "quote", text: clip(e.text.replace(/\s+/g, " "), 300) }))));
    mount($("#errors"),
      h("details", { class: "fold", open: true }, h("summary", { text: `Synthetic test set: ${E.test.hybrid_error_count} errors, 8 shown` }), h("div", { class: "fold-body" }, list(E.test.hybrid_errors))),
      h("details", { class: "fold" }, h("summary", { text: `Challenge set: ${E.challenge.hybrid_errors.length} errors` }), h("div", { class: "fold-body" }, list(E.challenge.hybrid_errors))),
      h("p", { class: "rule-note", text: "Scores are 0 to 100. A score of 50 or more counts as flagged." }));
  }

  function renderInterp() {
    const terms = E.interpretability.tfidf_top_terms.slice(0, 12), coefs = E.interpretability.context_coefficients;
    const maxT = Math.max(...terms.map(t => t[1])), maxC = Math.max(...coefs.map(c => Math.abs(c[1])));
    mount($("#interp"),
      h("h3", { text: "Words that push the text classifier toward 'attack'" }),
      h("div", { class: "mt" }, hbars(terms.map(t => ({ label: t[0], value: t[1], display: num(t[1], 1) })), { max: maxT })),
      h("p", { class: "rule-note", text: "Words such as 'you', 'this' and 'system' rank highly because the training attacks were addressed to the reader. A real attack written in another style may not use them, which is one reason the classifier alone is not trusted." }),
      h("h3", { class: "mt-lg", text: "What the context model weighs" }),
      h("div", { class: "mt" }, hbars(coefs.map(c => ({ label: c[0].replace(/_/g, " "), value: Math.abs(c[1]), display: (c[1] > 0 ? "+" : "") + num(c[1], 1), colour: c[1] > 0 ? "#EF4444" : "#22C55E" })), { max: maxC })),
      h("p", { class: "rule-note", text: "Red raises the chance that a matched phrase is an attack, green lowers it. Being quoted or part of a discussion lowers it the most." }));
  }

  function renderDataset() {
    const D = E.dataset, kinds = Object.entries(D.kinds);
    mount($("#dataset"),
      h("p", { class: "muted", text: `${D.rows.toLocaleString()} generated documents in ${D.groups} template groups. Training ${D.splits.train.n} (${D.splits.train.malicious} malicious), validation ${D.splits.val.n} (${D.splits.val.malicious}), test ${D.splits.test.n} (${D.splits.test.malicious}). Groups never cross splits (${D.leaky_groups} leaking). Data fingerprint ${E.dataset_sha}, generated ${E.generated.slice(0, 10)}.` }),
      h("div", { class: "row mt" }, ...kinds.map(([k, n]) => h("span", { class: "tag", text: `${KIND_LABELS[k] || k}: ${n}` }))),
      h("p", { class: "rule-note", text: "The dataset is synthetic: it was written by combining hand-made templates, topics and attack payloads, not collected from real incidents. The benign half is deliberately full of hard cases (security articles, quoted attacks, ordinary instructions), which inflates the false-positive rate of keyword methods compared with ordinary web text. Use these numbers to compare methods with each other, not to predict real-world accuracy." }));
  }

  function renderLimits() {
    const li = t => h("li", { text: t });
    mount($("#limits"), h("div", { class: "grid cols-2" },
      h("div", null, h("h3", { text: "Limitations" }), h("ul", { class: "recs mt" }, ...[
        "PromptGuard does not find every prompt injection attack and never claims to. A clean result is not a guarantee.",
        "Test data is synthetic and the benign half is unusually hard. Real traffic would behave differently.",
        "Test-set sizes are small. Intervals are wide and several method differences are not statistically clear.",
        "The evidence floor was added after looking at test-set errors, so its gain is optimistic.",
        "Risk bands and blast-radius multipliers are design choices. Nobody has validated them against real incidents.",
        "Paraphrased attacks, attacks in images, and attacks that need no instruction-like wording are weak spots.",
        "The context check can itself be abused: wrapping an attack in quotation marks lowers its score.",
      ].map(li))),
      h("div", null, h("h3", { text: "Related work, and why we do not claim novelty" }), h("ul", { class: "recs mt" }, ...[
        "Style discontinuity as a signal of injected text has been studied before (arXiv 2604.18248), so the style-break check is an application of a known idea.",
        "The 'lethal trifecta' (private data, untrusted content, a way to send data out) and capability-based agent designs such as CaMeL already reason about what an injected instruction can reach. The blast-radius score here is a simple, unvalidated version of that thinking.",
        "Papers on evading prompt-injection detectors (for example arXiv 2504.11168 and arXiv 2602.00750) cover the same ground as the fuzzer.",
        "Whether the combination of these four checks in one local tool is new has not been established by a literature review. Check the references before citing any of this.",
      ].map(li)))));
  }

  async function main() {
    try { E = await api("/api/evaluation"); }
    catch (e) { mount($("#loading"), h("div", { class: "notice error", text: e.message })); return; }
    $("#loading").remove();
    $("#page").classList.remove("hidden");
    $("#honesty").textContent = `These results come from ${E.synthetic ? "a synthetic dataset" : "the dataset"} and a small hand-written challenge set. PromptGuard will not claim to detect every attack, and whether any of its ideas is new has not been verified. The numbers show how the methods compare on this data. They are not a promise about real-world performance.`;
    mount($("#findings"), ...keyFindings());
    renderCompare("test"); renderKinds(); renderBands(); renderAblation(); renderFuzz(); renderErrors(); renderInterp(); renderDataset(); renderLimits();
  }
  main();
})();
