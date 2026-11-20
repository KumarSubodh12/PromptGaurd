(function () {
  "use strict";
  const { h, $, $$, mount, clear, api, meta, fmtBytes, toast } = PG;

  const STAGES = ["Extracting content", "Preprocessing text", "Checking suspicious patterns", "Running contextual analysis", "Generating security report"];
  let M = null, file = null, busy = false;

  const text = $("#text"), counter = $("#counter"), err = $("#error");

  function mode() { return $("#tab-upload").getAttribute("aria-selected") === "true" ? "upload" : "paste"; }
  function setTab(which) {
    for (const t of ["paste", "upload"]) {
      $(`#tab-${t}`).setAttribute("aria-selected", String(t === which));
      $(`#pane-${t}`).classList.toggle("hidden", t !== which);
    }
    updateCounter();
  }
  $("#tab-paste").addEventListener("click", () => setTab("paste"));
  $("#tab-upload").addEventListener("click", () => setTab("upload"));
  for (const id of ["tab-paste", "tab-upload"]) {
    $("#" + id).addEventListener("keydown", e => {
      if (e.key === "ArrowRight" || e.key === "ArrowLeft") { const to = id === "tab-paste" ? "upload" : "paste"; setTab(to); $("#tab-" + to).focus(); }
    });
  }

  function updateCounter() {
    if (mode() === "paste") {
      const n = text.value.length, words = (text.value.trim().match(/\S+/g) || []).length;
      counter.textContent = n ? `${n.toLocaleString()} characters, ${words.toLocaleString()} words` : "";
    } else counter.textContent = file ? fmtBytes(file.size) : "";
  }
  let lastSample = null;
  text.addEventListener("input", () => { if (text.value !== lastSample) delete text.dataset.name; updateCounter(); showError(""); });

  function showError(msg) { err.textContent = msg; err.classList.toggle("hidden", !msg); }

  // ---------------------------------------------------------------- file handling
  const drop = $("#dropzone"), input = $("#file");
  drop.addEventListener("click", () => input.click());
  drop.addEventListener("keydown", e => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); input.click(); } });
  input.addEventListener("change", () => chooseFile(input.files[0]));
  for (const ev of ["dragenter", "dragover"]) drop.addEventListener(ev, e => { e.preventDefault(); drop.classList.add("over"); });
  for (const ev of ["dragleave", "drop"]) drop.addEventListener(ev, e => { e.preventDefault(); drop.classList.remove("over"); });
  drop.addEventListener("drop", e => chooseFile(e.dataTransfer.files[0]));

  function chooseFile(f) {
    showError("");
    if (!f) return;
    const limit = (M ? M.limits.max_upload_mb : 5) * 1024 * 1024;
    if (f.size > limit) { file = null; renderFile(); showError(`That file is ${fmtBytes(f.size)}. The limit is ${fmtBytes(limit)}.`); return; }
    if (!/\.(txt|md|pdf|docx|html?|eml|csv|json)$/i.test(f.name)) { file = null; renderFile(); showError("That file type is not supported. Use TXT, PDF, DOCX, HTML or EML."); return; }
    file = f;
    renderFile();
    updateCounter();
  }
  function renderFile() {
    const box = $("#fileinfo");
    box.classList.toggle("hidden", !file);
    if (!file) { clear(box); return; }
    const ext = (file.name.split(".").pop() || "").toUpperCase();
    mount(box, h("span", { class: "tag", text: ext }),
      h("div", { class: "grow" }, h("div", { text: file.name, class: "mono" }), h("div", { class: "dim", text: `${fmtBytes(file.size)}. Contents are checked when you analyse.` })),
      h("button", { type: "button", class: "btn btn-ghost btn-sm", text: "Remove", on: { click: () => { file = null; input.value = ""; renderFile(); updateCounter(); } } }));
  }

  // ---------------------------------------------------------------- profile and capabilities
  function renderCaps(selected) {
    const box = $("#caps");
    mount(box, ...Object.entries(M.capabilities).map(([id, label]) =>
      h("label", { class: "chip" }, h("input", { type: "checkbox", value: id, checked: selected.includes(id) }), h("span", { text: label }))));
  }
  function profileChanged() {
    const id = $("#profile").value;
    const p = M.profiles[id];
    $("#caps").classList.toggle("hidden", id !== "custom");
    if (id === "custom") renderCaps($$("#caps input:checked").map(i => i.value));
    const names = p.capabilities.map(c => M.capabilities[c]);
    $("#profile-hint").textContent = id === "unknown" ? "No profile chosen. PromptGuard assumes the AI can do everything, which gives the highest exposure score."
      : id === "custom" ? "Tick what your AI can do."
      : names.length ? `Can: ${names.join("; ").toLowerCase()}.` : "No tools. It can only produce text.";
  }
  $("#profile").addEventListener("change", profileChanged);

  // ---------------------------------------------------------------- samples
  async function loadSamples() {
    const list = await api("/api/samples");
    mount($("#samples"), ...list.map(s => h("button", { type: "button", class: "sample", on: { click: () => {
      setTab("paste"); text.value = s.text; lastSample = s.text; text.dataset.name = s.name; updateCounter(); showError("");
    } } }, h("b", { text: s.title }), h("span", { text: s.expect }))));
  }

  // ---------------------------------------------------------------- submit
  function showProgress() {
    const ol = $("#stages");
    mount(ol, ...STAGES.map(s => h("li", { text: s })));
    $("#progress").classList.remove("hidden");
    let i = 0;
    const items = $$("li", ol);
    items[0].className = "active";
    return {
      step() { if (i < items.length - 1) { items[i].className = "done"; i++; items[i].className = "active"; } },
      finish() { items.forEach(li => (li.className = "done")); },
      stop() { $("#progress").classList.add("hidden"); },
    };
  }
  const pause = ms => new Promise(r => setTimeout(r, ms));

  $("#scan-form").addEventListener("submit", async e => {
    e.preventDefault();
    if (busy) return;
    showError("");
    const profile = $("#profile").value;
    const caps = $$("#caps input:checked").map(i => i.value);
    let req;
    if (mode() === "upload") {
      if (!file) { showError("Choose a file first, or switch to Paste text."); return; }
      const fd = new FormData();
      fd.append("file", file);
      fd.append("profile", profile);
      fd.append("custom_caps", caps.join(","));
      req = { method: "POST", body: fd };
    } else {
      if (!text.value.trim()) { showError("Paste some text first, or try one of the examples."); text.focus(); return; }
      req = { json: { text: text.value, name: text.dataset.name || "Pasted text", profile, custom_caps: caps } };
    }
    busy = true;
    $("#go").disabled = true;
    const prog = showProgress();
    // The server answers in one call, the stages are paced so that the person can see what is being done.
    const ticker = setInterval(() => prog.step(), 260);
    try {
      const [res] = await Promise.all([api("/api/scan", req), pause(1200)]);
      clearInterval(ticker);
      prog.finish();
      await pause(250);
      location.href = `/scan/${res.id}`;
    } catch (ex) {
      clearInterval(ticker);
      prog.stop();
      showError(ex.message);
      busy = false;
      $("#go").disabled = false;
    }
  });

  $("#clear").addEventListener("click", () => {
    text.value = ""; delete text.dataset.name; file = null; input.value = ""; renderFile(); updateCounter(); showError("");
    $("#progress").classList.add("hidden");
  });

  (async function init() {
    try {
      M = await meta();
      mount($("#profile"), ...Object.entries(M.profiles).map(([id, p]) => h("option", { value: id, text: p.label })));
      $("#profile").value = M.settings.default_profile in M.profiles ? M.settings.default_profile : "unknown";
      profileChanged();
      $("#accepted").textContent = `TXT, PDF, DOCX, HTML or EML, up to ${M.limits.max_upload_mb} MB`;
      await loadSamples();
    } catch (ex) { showError(ex.message); }
    updateCounter();
  })();
})();
