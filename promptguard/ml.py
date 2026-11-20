"""Stages 4-5: supervised models.

TfidfDetector      word + character TF-IDF features, Logistic Regression.
ContextClassifier  Logistic Regression over the *contextual* features produced
                   by the rule and context engines (not over raw text).
Stacker            a small Logistic Regression that combines every signal into
                   the final probability; coefficients are constrained to be
                   non-negative so each signal can only add evidence.
"""
from __future__ import annotations

import math
from dataclasses import dataclass
from pathlib import Path

import joblib
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import FeatureUnion

from .config import MODEL_DIR, RULE_CATEGORIES
from .context import FEATURE_NAMES as CTX_NAMES
from .preprocess import Doc, _segment

MODEL_PATH = MODEL_DIR / "promptguard.joblib"
MAX_SEGMENTS = 1500
ML_FLAG_P = 0.5


class TfidfDetector:
    def __init__(self, C: float = 4.0):
        self.vec = FeatureUnion([
            ("word", TfidfVectorizer(ngram_range=(1, 2), min_df=2, sublinear_tf=True)),
            ("char", TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), min_df=3, sublinear_tf=True)),
        ])
        self.clf = LogisticRegression(C=C, max_iter=4000, class_weight="balanced")

    def fit(self, texts: list[str], y) -> "TfidfDetector":
        self.clf.fit(self.vec.fit_transform(texts), np.asarray(y))
        return self

    def proba(self, texts: list[str]) -> np.ndarray:
        if not texts:
            return np.zeros(0)
        return self.clf.predict_proba(self.vec.transform(texts))[:, 1]

    def top_terms(self, n: int = 15) -> list[tuple[str, float]]:
        names = self.vec.get_feature_names_out()
        coef = self.clf.coef_[0]
        idx = np.argsort(coef)[::-1][:n]
        return [(str(names[i]).split("__", 1)[-1], float(coef[i])) for i in idx]

    def score_doc(self, doc: Doc) -> dict:
        """Score each sentence, each pair of sentences, and the whole text.

        Returns the document probability (max over all candidates) and the
        sentence-level hits that should be highlighted.
        """
        segs = doc.segments[:MAX_SEGMENTS]
        cands: list[tuple[str, tuple[int, int] | None]] = [(s.norm, (s.start, s.end)) for s in segs]
        n_seg = len(cands)
        for a, b in zip(segs, segs[1:]):
            cands.append((a.norm + " " + b.norm, None))
        if doc.deobf.text != doc.norm.text:
            for s in _segment(doc.deobf)[:MAX_SEGMENTS]:
                os_, oe = doc.deobf.to_orig(s.nstart, s.nend)
                cands.append((s.norm, (os_, oe)))
        if len(doc.norm.text) <= 4000 and doc.norm.text:
            cands.append((doc.norm.text, None))
        if not cands:
            return {"p": 0.0, "hits": []}
        probs = self.proba([c[0] for c in cands])
        hits = []
        for (text, span), p in zip(cands, probs):
            if span is not None and p >= ML_FLAG_P:
                hits.append({"start": span[0], "end": span[1], "p": float(p), "text": text})
        # keep the highest-probability hit per overlapping region
        hits.sort(key=lambda h: -h["p"])
        kept: list[dict] = []
        for h in hits:
            if not any(h["start"] < k["end"] and k["start"] < h["end"] for k in kept):
                kept.append(h)
        kept.sort(key=lambda h: h["start"])
        return {"p": float(probs.max()), "hits": kept}


class ContextClassifier:
    """Supervised model over contextual features of the rule findings."""

    NAMES = (["max_severity", "max_severity_x_context", "log_findings", "mean_factor", "categories", "deobfuscated_only"]
             + [f"cat_{c}" for c in RULE_CATEGORIES] + [f"top_{n}" for n in CTX_NAMES])

    def __init__(self, C: float = 1.0):
        self.clf = LogisticRegression(C=C, max_iter=3000, class_weight="balanced")

    @staticmethod
    def featurize(rule_findings: list) -> list[float]:
        """``rule_findings``: objects with .category .severity .ctx (ContextInfo) .via"""
        n = len(RULE_CATEGORIES) + len(CTX_NAMES) + 6
        if not rule_findings:
            return [0.0] * n
        sev = [f.severity / 10 for f in rule_findings]
        scored = [(f.severity / 10 * f.ctx.factor, f) for f in rule_findings]
        top = max(scored, key=lambda t: t[0])[1]
        cats = {c: 0.0 for c in RULE_CATEGORIES}
        for f in rule_findings:
            cats[f.category] = max(cats[f.category], f.severity / 10 * min(1.0, f.ctx.factor))
        return (
            [max(sev), max(s for s, _ in scored), math.log1p(len(rule_findings)),
             float(np.mean([f.ctx.factor for f in rule_findings])),
             sum(1 for v in cats.values() if v > 0.2) / len(RULE_CATEGORIES),
             float(all(f.via == "deobfuscated" for f in rule_findings))]
            + [cats[c] for c in RULE_CATEGORIES]
            + top.ctx.as_features()
        )

    def fit(self, X, y) -> "ContextClassifier":
        self.clf.fit(np.asarray(X), np.asarray(y))
        return self

    def proba(self, X) -> np.ndarray:
        return self.clf.predict_proba(np.asarray(X))[:, 1]

    def coefficients(self) -> list[tuple[str, float]]:
        return sorted(zip(self.NAMES, map(float, self.clf.coef_[0])), key=lambda t: -abs(t[1]))


SIGNALS = ["rule_ctx", "ml_p", "ctx_p", "aud_p", "style_p", "obf_p"]
SIGNAL_LABELS = {
    "rule_ctx": "Rule engine with context",
    "ml_p": "TF-IDF + Logistic Regression",
    "ctx_p": "Contextual classifier",
    "aud_p": "Audience mismatch",
    "style_p": "Style break",
    "obf_p": "Hidden or obfuscated text",
}


class Stacker:
    """Combines the per-method signals into one probability."""

    def __init__(self, signals: list[str] | None = None, C: float = 2.0):
        self.signals = list(signals or SIGNALS)
        self.C = C
        self.clf: LogisticRegression | None = None
        self.coef = np.zeros(len(self.signals))
        self.intercept = 0.0

    def _X(self, rows: list[dict]) -> np.ndarray:
        return np.array([[r.get(s, 0.0) for s in self.signals] for r in rows], dtype=float)

    def fit(self, rows: list[dict], y) -> "Stacker":
        keep = list(range(len(self.signals)))
        X = self._X(rows)
        y = np.asarray(y)
        for _ in range(len(self.signals)):
            clf = LogisticRegression(C=self.C, max_iter=3000, class_weight="balanced")
            clf.fit(X[:, keep], y)
            neg = [k for k, c in zip(keep, clf.coef_[0]) if c < 0]
            if not neg:
                break
            keep = [k for k in keep if k not in neg]
            if not keep:
                break
        coef = np.zeros(len(self.signals))
        if keep:
            coef[keep] = clf.coef_[0]
            self.intercept = float(clf.intercept_[0])
        else:
            self.intercept = 0.0
        self.coef = coef
        return self

    def predict(self, row: dict) -> float:
        z = self.intercept + float(sum(c * row.get(s, 0.0) for c, s in zip(self.coef, self.signals)))
        return 1.0 / (1.0 + math.exp(-max(-30.0, min(30.0, z))))

    def contributions(self, row: dict) -> list[dict]:
        out = []
        for c, s in zip(self.coef, self.signals):
            v = row.get(s, 0.0)
            out.append({"signal": s, "label": SIGNAL_LABELS[s], "value": round(float(v), 3),
                        "weight": round(float(c), 3), "contribution": round(float(c * v), 3)})
        return out


def fallback_probability(sig: dict) -> float:
    """Used before models are trained: a transparent noisy-OR of the signals."""
    p = 1.0
    for key, w in (("rule_ctx", 1.0), ("ml_p", 0.9), ("ctx_p", 0.8), ("aud_p", 0.7), ("style_p", 0.25), ("obf_p", 0.9)):
        p *= 1.0 - w * sig.get(key, 0.0)
    return 1.0 - p


@dataclass
class Models:
    tfidf: TfidfDetector | None = None
    ctx: ContextClassifier | None = None
    stack: Stacker | None = None
    meta: dict | None = None

    def save(self, path: Path = MODEL_PATH) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump({"tfidf": self.tfidf, "ctx": self.ctx, "stack": self.stack, "meta": self.meta}, path)

    @staticmethod
    def load(path: Path = MODEL_PATH) -> "Models":
        if not path.exists():
            return Models()
        d = joblib.load(path)
        return Models(d.get("tfidf"), d.get("ctx"), d.get("stack"), d.get("meta"))
