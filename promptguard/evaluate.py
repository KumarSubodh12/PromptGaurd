"""Research evaluation: trains the models and measures every method on the same
held-out data.

Methods compared (all decide at probability / score 0.5):
  rules_keyword  any rule matches (context ignored): the keyword-only baseline
  rules_context  rule findings after contextual discounting
  tfidf_lr       TF-IDF + Logistic Regression
  context_lr     Logistic Regression over contextual features
  hybrid         stacked combination of every signal, incl. the novel modules

Honesty notes
-------------
* The default dataset is synthetic (see data/banks.py). Treat the numbers as a
  test of the pipeline, not as evidence of real-world accuracy.
* Confidence intervals come from a cluster bootstrap over template / topic
  groups, which is wider (and more honest) than resampling single rows.
"""
from __future__ import annotations

import csv
import datetime as dt
import hashlib
import random
import re
import time
from collections import defaultdict

import numpy as np
from sklearn.metrics import roc_auc_score

from . import fuzzer
from .config import DATA_DIR, SEED
from .ml import SIGNAL_LABELS, SIGNALS, ContextClassifier, Models, Stacker, TfidfDetector
from .pipeline import EVIDENCE_FLOOR, Analyzer
from .preprocess import preprocess

METHODS = {
    "rules_keyword": "Rule-based (keywords only)",
    "rules_context": "Rules + context heuristics",
    "tfidf_lr": "TF-IDF + Logistic Regression",
    "context_lr": "Contextual classifier",
    "hybrid": "Hybrid (stacked, all signals)",
}
CLEAN_SEED_KINDS = {"mal_direct", "mal_role", "mal_tool", "mal_audience", "mal_paraphrase", "mal_long"}
BENIGN_MUTATORS = ["padding", "html_hidden", "quote_markup", "typos", "synonym"]
HELD_OUT_OP = "translate_uncovered"          # never used for hardening
LONG_KINDS = {"mal_long", "benign_long"}


# --------------------------------------------------------------------------- data
def load_rows(path=DATA_DIR / "dataset.csv") -> list[dict]:
    with open(path, encoding="utf-8", newline="") as f:
        rows = list(csv.DictReader(f))
    for r in rows:
        r["label"] = int(r["label"])
    return rows


def _key(t: str) -> str:
    return re.sub(r"\W+", "", t.lower())


def tfidf_training_set(rows: list[dict]) -> tuple[list[str], list[int]]:
    """Whole short documents, the labelled evidence sentence, and individual
    benign sentences. (With only document-level labels, whole documents are used.)"""
    X: list[str] = []
    y: list[int] = []
    for r in rows:
        t, lab, ev = r["text"], r["label"], r.get("evidence", "")
        if len(t) <= 700:
            X.append(t)
            y.append(lab)
        if lab == 1 and ev:
            X.append(ev)
            y.append(1)
        if r.get("no_sent") or r["kind"] == "mal_obfuscated":
            continue
        if lab == 0 or ev:
            evk = _key(ev) if ev else ""
            for s in preprocess(t).segments:
                k = _key(s.norm)
                if len(k) < 12:
                    continue
                if lab == 1 and (k in evk or evk in k or (evk and evk[:40] in k)):
                    continue
                X.append(s.norm)
                y.append(0)
    return X, y


# --------------------------------------------------------------------------- fitting
def compute_cores(az: Analyzer, texts: list[str]) -> list:
    return [az.core(t) for t in texts]


def fit_base_models(rows: list[dict], cores: list) -> tuple[TfidfDetector, ContextClassifier]:
    X, y = tfidf_training_set(rows)
    tfidf = TfidfDetector().fit(X, y)
    ctx = ContextClassifier().fit([c.ctx_features for c in cores], [r["label"] for r in rows])
    return tfidf, ctx


def signals_with(cores: list, tfidf: TfidfDetector, ctx: ContextClassifier) -> list[dict]:
    ml = [tfidf.score_doc(c.doc)["p"] for c in cores]
    cp = ctx.proba([c.ctx_features for c in cores])
    out = []
    for c, m, p in zip(cores, ml, cp):
        s = dict(c.signals)
        s["ml_p"], s["ctx_p"] = float(m), float(p)
        out.append(s)
    return out


def decide(sigs: list[dict], stack: Stacker, floor: bool = True) -> tuple[dict[str, np.ndarray], dict[str, np.ndarray]]:
    k = EVIDENCE_FLOOR if floor else 0.0
    sc = {
        "rules_keyword": np.array([s["rule_raw"] for s in sigs]),
        "rules_context": np.array([s["rule_ctx"] for s in sigs]),
        "tfidf_lr": np.array([s["ml_p"] for s in sigs]),
        "context_lr": np.array([s["ctx_p"] for s in sigs]),
        "hybrid": np.array([max(stack.predict(s), k * s.get("rule_strong", 0.0)) for s in sigs]),
    }
    return {m: v >= 0.5 for m, v in sc.items()}, sc


# --------------------------------------------------------------------------- metrics
def metrics(y, pred) -> dict:
    y = np.asarray(y, int)
    p = np.asarray(pred, bool)
    tp = int(((y == 1) & p).sum())
    fp = int(((y == 0) & p).sum())
    tn = int(((y == 0) & ~p).sum())
    fn = int(((y == 1) & ~p).sum())
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
    fpr = fp / (fp + tn) if fp + tn else 0.0
    fnr = fn / (fn + tp) if fn + tp else 0.0

    def ppv(pi: float) -> float:
        d = rec * pi + fpr * (1 - pi)
        return rec * pi / d if d > 0 else 0.0

    return {"accuracy": (tp + tn) / max(len(y), 1), "precision": prec, "recall": rec, "f1": f1, "fpr": fpr, "fnr": fnr,
            "tp": tp, "fp": fp, "tn": tn, "fn": fn, "precision_at_5pct_prevalence": ppv(0.05),
            "precision_at_1pct_prevalence": ppv(0.01)}


def cluster_bootstrap(y, preds: dict[str, np.ndarray], groups: list[str], n: int = 1000, seed: int = SEED) -> dict:
    y = np.asarray(y, int)
    ug = sorted(set(groups))
    gi = {g: i for i, g in enumerate(ug)}
    idx = np.array([gi[g] for g in groups])
    out: dict[str, dict] = {}
    rng = np.random.default_rng(seed)
    draws = rng.integers(0, len(ug), size=(n, len(ug)))
    for m, p in preds.items():
        p = np.asarray(p, bool)
        counts = np.zeros((len(ug), 4))
        masks = [(y == 1) & p, (y == 0) & p, (y == 0) & ~p, (y == 1) & ~p]   # tp, fp, tn, fn
        for k, mask in enumerate(masks):
            counts[:, k] = np.bincount(idx, weights=mask.astype(float), minlength=len(ug))
        tot = counts[draws].sum(axis=1)
        tp, fp, tn, fn = tot[:, 0], tot[:, 1], tot[:, 2], tot[:, 3]
        with np.errstate(divide="ignore", invalid="ignore"):
            prec = np.where(tp + fp > 0, tp / (tp + fp), 0)
            rec = np.where(tp + fn > 0, tp / (tp + fn), 0)
            f1 = np.where(prec + rec > 0, 2 * prec * rec / (prec + rec), 0)
            fpr = np.where(fp + tn > 0, fp / (fp + tn), 0)
        q = lambda a: [round(float(np.percentile(a, 2.5)), 4), round(float(np.percentile(a, 97.5)), 4)]
        out[m] = {"f1": q(f1), "recall": q(rec), "fpr": q(fpr)}
    return out


def auc(y, score) -> float | None:
    y = np.asarray(y)
    if len(set(y.tolist())) < 2:
        return None
    return float(roc_auc_score(y, np.asarray(score, float)))


def per_kind(rows: list[dict], preds: dict[str, np.ndarray]) -> dict:
    kinds = sorted({r["kind"] for r in rows})
    out = {}
    for k in kinds:
        idx = [i for i, r in enumerate(rows) if r["kind"] == k]
        out[k] = {"n": len(idx), "label": rows[idx[0]]["label"],
                  **{m: round(float(np.asarray(p)[idx].mean()), 4) for m, p in preds.items()}}
    return out


# --------------------------------------------------------------------------- mutants
def make_mutants(seeds: list[dict], ops: list[str], rng: random.Random, label: int) -> list[dict]:
    out = []
    for i, s in enumerate(seeds):
        base = s["evidence"] if label == 1 else s["text"]
        for op in ops:
            m = fuzzer.mutate(base, op, rng)
            if m is not None:
                out.append({"text": m, "label": label, "evidence": m if label == 1 else "", "kind": f"aug:{op}",
                            "op": op, "seed": i, "no_sent": True, "group": s["group"]})
    return out


# --------------------------------------------------------------------------- main
def run_all(log=print, quick: bool = False) -> tuple[Models, Models, dict]:
    t0 = time.time()
    rng = random.Random(SEED)
    rows = load_rows()
    ds_hash = hashlib.sha256((DATA_DIR / "dataset.csv").read_bytes()).hexdigest()[:12]
    split = {s: [r for r in rows if r["split"] == s] for s in ("train", "val", "test")}
    az = Analyzer(Models())
    log(f"dataset {len(rows)} rows: " + ", ".join(f"{s}={len(v)}" for s, v in split.items()))

    cores = {}
    for s, rs in split.items():
        cores[s] = compute_cores(az, [r["text"] for r in rs])
        log(f"  analysed {s}: {len(rs)} docs ({time.time() - t0:.0f}s)")

    y = {s: [r["label"] for r in rs] for s, rs in split.items()}

    # ---- baseline models
    tfidf, ctx = fit_base_models(split["train"], cores["train"])
    sig_val = signals_with(cores["val"], tfidf, ctx)
    stack = Stacker().fit(sig_val, y["val"])
    meta = {"trained": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"), "dataset_sha": ds_hash,
            "n_train": len(split["train"]), "hardened": False}
    base = Models(tfidf, ctx, stack, meta)

    sig_test = signals_with(cores["test"], tfidf, ctx)
    dec, sc = decide(sig_test, stack)
    ytest = y["test"]
    groups = [r["group"] for r in split["test"]]

    report: dict = {
        "generated": meta["trained"], "dataset_sha": ds_hash, "synthetic": True,
        "dataset": {
            "rows": len(rows),
            "splits": {s: {"n": len(rs), "malicious": sum(r["label"] for r in rs)} for s, rs in split.items()},
            "kinds": {k: sum(1 for r in rows if r["kind"] == k) for k in sorted({r["kind"] for r in rows})},
            "groups": len({r["group"] for r in rows}), "leaky_groups": 0,
        },
        "methods": {m: METHODS[m] for m in METHODS},
        "test": {
            "metrics": {m: metrics(ytest, dec[m]) for m in METHODS},
            "auc": {m: auc(ytest, sc[m]) for m in METHODS},
            "bootstrap_95ci": cluster_bootstrap(ytest, dec, groups, n=300 if quick else 1000),
            "per_kind": per_kind(split["test"], dec),
        },
    }
    long_idx = [i for i, r in enumerate(split["test"]) if r["kind"] in LONG_KINDS]
    report["test"]["long_documents"] = {m: metrics([ytest[i] for i in long_idx], dec[m][long_idx]) for m in METHODS}

    # ---- single-signal AUC (does each novel signal carry information on its own?)
    sig_auc = {}
    for s in SIGNALS:
        vals = [x[s] for x in sig_test]
        sig_auc[s] = {"label": SIGNAL_LABELS[s], "all": auc(ytest, vals),
                      "long": auc([ytest[i] for i in long_idx], [vals[i] for i in long_idx])}
    report["test"]["signal_auc"] = sig_auc

    # ---- ablation: re-fit the stacker on validation with signal subsets
    ablations = {
        "full": SIGNALS,
        "without_audience": [s for s in SIGNALS if s != "aud_p"],
        "without_style": [s for s in SIGNALS if s != "style_p"],
        "without_unicode": [s for s in SIGNALS if s != "obf_p"],
        "without_novel_modules": [s for s in SIGNALS if s not in ("aud_p", "style_p")],
        "rules_context_only": ["rule_ctx"],
        "rules_and_tfidf": ["rule_ctx", "ml_p"],
    }
    abl = {}
    kind_idx = lambda ks: [i for i, r in enumerate(split["test"]) if r["kind"] in ks]
    for name, sigset in ablations.items():
        st = Stacker(sigset).fit(sig_val, y["val"])
        pred = np.array([max(st.predict(s), EVIDENCE_FLOOR * s.get("rule_strong", 0.0)) >= 0.5 for s in sig_test])
        entry = {"signals": sigset, **{k: v for k, v in metrics(ytest, pred).items() if k in ("f1", "recall", "fpr", "precision")}}
        for label, ks in (("mal_audience", {"mal_audience"}), ("mal_paraphrase", {"mal_paraphrase"}),
                          ("mal_long", {"mal_long"}), ("benign_long", {"benign_long"}),
                          ("mal_obfuscated", {"mal_obfuscated"}), ("benign_educational", {"benign_educational"})):
            ii = kind_idx(ks)
            entry[label] = round(float(pred[ii].mean()), 4) if ii else None
        abl[name] = entry
    nf_dec, _ = decide(sig_test, stack, floor=False)
    abl["without_evidence_floor"] = {
        "signals": SIGNALS, **{k: v for k, v in metrics(ytest, nf_dec["hybrid"]).items() if k in ("f1", "recall", "fpr", "precision")},
        **{label: round(float(nf_dec["hybrid"][kind_idx({label})].mean()), 4) if kind_idx({label}) else None
           for label in ("mal_audience", "mal_paraphrase", "mal_long", "benign_long", "mal_obfuscated", "benign_educational")},
    }
    report["ablation"] = abl

    # ---- stacker, calibration of the risk bands
    report["stacker"] = {"intercept": round(stack.intercept, 3),
                         "weights": {s: round(float(c), 3) for s, c in zip(stack.signals, stack.coef)}}
    probs = sc["hybrid"]
    cal = []
    for thr in (10, 20, 30, 40, 50, 60, 70, 80, 90):
        pred = probs * 100 >= thr
        m = metrics(ytest, pred)
        cal.append({"threshold": thr, "precision": m["precision"], "recall": m["recall"], "fpr": m["fpr"], "flagged": int(pred.sum())})
    report["calibration"] = cal
    review = probs * 100 >= 30
    report["test"]["review_threshold"] = {
        "threshold": 30, "metrics": metrics(ytest, review),
        "per_kind": {k: v["hybrid_at_30"] for k, v in per_kind(split["test"], {"hybrid_at_30": review}).items()},
        "note": "Score >= 30 is the 'Medium' band: flag for human review rather than block.",
    }
    bands = {}
    for name, lo, hi in (("Low", 0, 30), ("Medium", 30, 60), ("High", 60, 80), ("Critical", 80, 101)):
        sel = [(probs[i] * 100 >= lo) and (probs[i] * 100 < hi) for i in range(len(probs))]
        n = sum(sel)
        mal = sum(1 for i, s in enumerate(sel) if s and ytest[i] == 1)
        bands[name] = {"n": n, "malicious": mal, "share_malicious": round(mal / n, 4) if n else None}
    report["bands_on_test"] = bands
    report["interpretability"] = {
        "tfidf_top_terms": tfidf.top_terms(20),
        "context_coefficients": ctx.coefficients()[:12],
    }

    # ---- errors on the test set, for the Research page
    errs = []
    for i, r in enumerate(split["test"]):
        if bool(dec["hybrid"][i]) != bool(r["label"]):
            errs.append({"kind": r["kind"], "label": r["label"], "score": round(float(probs[i]) * 100),
                         "text": r["text"][:240]})
    report["test"]["hybrid_errors"] = errs[:25]
    report["test"]["hybrid_error_count"] = len(errs)

    # ---- independent hand-written challenge set
    ch = load_rows(DATA_DIR / "challenge_set.csv")
    ch_cores = compute_cores(az, [r["text"] for r in ch])
    ch_sig = signals_with(ch_cores, tfidf, ctx)
    ch_dec, ch_sc = decide(ch_sig, stack)
    ych = [r["label"] for r in ch]
    report["challenge"] = {
        "n": len(ch), "metrics": {m: metrics(ych, ch_dec[m]) for m in METHODS},
        "hybrid_errors": [{"label": r["label"], "score": round(float(ch_sc["hybrid"][i]) * 100), "text": r["text"][:200]}
                          for i, r in enumerate(ch) if bool(ch_dec["hybrid"][i]) != bool(r["label"])],
        "hybrid_at_30": metrics(ych, ch_sc["hybrid"] * 100 >= 30),
        "note": "35 malicious + 35 benign, hand-written, never used for tuning. Far too small for tight estimates.",
    }
    log(f"  baseline evaluated ({time.time() - t0:.0f}s)")

    # ====================================================== fuzzing + hardening
    train_seeds = [r for r in split["train"] if r["kind"] in CLEAN_SEED_KINDS and r["evidence"]]
    val_seeds = [r for r in split["val"] if r["kind"] in CLEAN_SEED_KINDS and r["evidence"]]
    test_seeds = [r for r in split["test"] if r["kind"] in CLEAN_SEED_KINDS and r["evidence"]]
    harden_ops = [o for o in fuzzer.OPERATORS if o != HELD_OUT_OP]
    all_ops = list(fuzzer.OPERATORS)

    def sample(lst, n):
        return rng.sample(lst, min(n, len(lst)))

    n_train_seeds = 60 if quick else 220
    aug_train = (make_mutants(sample(train_seeds, n_train_seeds), harden_ops, rng, 1)
                 + make_mutants(sample([r for r in split["train"] if r["label"] == 0], 80 if quick else 300), BENIGN_MUTATORS, rng, 0))
    aug_val = (make_mutants(sample(val_seeds, 30 if quick else 80), harden_ops, rng, 1)
               + make_mutants(sample([r for r in split["val"] if r["label"] == 0], 40 if quick else 120), BENIGN_MUTATORS, rng, 0))
    mut_test = make_mutants(test_seeds, all_ops, rng, 1)
    mut_test_benign = make_mutants([r for r in split["test"] if r["label"] == 0], BENIGN_MUTATORS, rng, 0)
    log(f"  fuzzing: {len(mut_test)} malicious test mutants, {len(mut_test_benign)} benign; "
        f"hardening on {len(aug_train)} train mutants")

    aug_train_cores = compute_cores(az, [r["text"] for r in aug_train])
    aug_val_cores = compute_cores(az, [r["text"] for r in aug_val])
    mt_cores = compute_cores(az, [r["text"] for r in mut_test])
    mb_cores = compute_cores(az, [r["text"] for r in mut_test_benign])
    seed_cores = compute_cores(az, [r["evidence"] for r in test_seeds])
    log(f"  mutants analysed ({time.time() - t0:.0f}s)")

    # hardened models: train + mutated train, stacker on val + mutated val
    tfidf_h, ctx_h = fit_base_models(split["train"] + aug_train, cores["train"] + aug_train_cores)
    sig_val_h = signals_with(cores["val"] + aug_val_cores, tfidf_h, ctx_h)
    stack_h = Stacker().fit(sig_val_h, y["val"] + [r["label"] for r in aug_val])
    hard = Models(tfidf_h, ctx_h, stack_h, {**meta, "hardened": True, "n_mutants": len(aug_train)})

    def fuzz_report(models: Models) -> dict:
        t, c, s = models.tfidf, models.ctx, models.stack
        seed_dec, _ = decide(signals_with(seed_cores, t, c), s)
        mt_dec, _ = decide(signals_with(mt_cores, t, c), s)
        mb_dec, _ = decide(signals_with(mb_cores, t, c), s)
        res = {m: {} for m in METHODS}
        for m in METHODS:
            for op in all_ops:
                idx = [i for i, r in enumerate(mut_test) if r["op"] == op and seed_dec[m][r["seed"]]]
                n_all = sum(1 for r in mut_test if r["op"] == op)
                ev = int(sum(1 for i in idx if not mt_dec[m][i]))
                res[m][op] = {"n": len(idx), "evaded": ev, "rate": round(ev / len(idx), 4) if idx else None,
                              "n_mutants": n_all}
        benign = {m: round(float(np.mean(mb_dec[m])), 4) for m in METHODS}
        clean = {m: round(float(np.mean(seed_dec[m])), 4) for m in METHODS}
        return {"by_operator": res, "benign_mutant_fpr": benign, "clean_seed_detection": clean}

    before = fuzz_report(base)
    after = fuzz_report(hard)
    dec_h, sc_h = decide(signals_with(cores["test"], tfidf_h, ctx_h), stack_h)
    report["fuzzer"] = {
        "operators": [{"name": o.name, "label": o.label, "family": o.family, "description": o.description}
                      for o in fuzzer.OPERATORS.values()],
        "seeds": len(test_seeds), "mutants": len(mut_test), "held_out_operator": HELD_OUT_OP,
        "before": before, "after": after,
        "hardening": {"train_mutants": len(aug_train),
                      "test_metrics_before": metrics(ytest, dec["hybrid"]),
                      "test_metrics_after": metrics(ytest, dec_h["hybrid"])},
        "note": "Evasion rate = share of mutants that are NOT detected, among mutants whose clean seed WAS detected by "
                "that method. The held-out operator was never used for hardening.",
    }
    f1_b, f1_a = report["fuzzer"]["hardening"]["test_metrics_before"], report["fuzzer"]["hardening"]["test_metrics_after"]
    ship_hardened = f1_a["f1"] >= f1_b["f1"] - 0.01 and f1_a["fpr"] <= f1_b["fpr"] + 0.01
    report["shipped_models"] = "hardened" if ship_hardened else "baseline"
    log(f"  done in {time.time() - t0:.0f}s; shipping {report['shipped_models']} models")
    return base, hard, report
