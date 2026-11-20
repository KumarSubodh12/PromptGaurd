"""Novel module 2: Style-break detector.

Injected text is usually written by a different author, for a different
purpose, than the document around it. We measure how far each sentence
deviates from the *rest of the same document* on a handful of stylistic
features, with extra weight on "directive" features (imperative mood, second
person, modal verbs).

Two guards keep it from firing on ordinary documents:
* the baseline is a robust median/MAD of the document itself, so a document
  that is *mostly* instructions (a recipe) is not suspicious;
* a sentence is only a "break" if it is more isolated than its neighbours, so
  a whole how-to section inside an article is not flagged as one outlier.

Prior art: stylometric discontinuity has been proposed for prompt-injection
detection before (arXiv:2604.18248). This module is an independent, simpler
implementation, evaluated here as one *signal* inside a hybrid system rather
than as a stand-alone detector.
"""
from __future__ import annotations

import math
import re
from dataclasses import dataclass

import numpy as np

from .preprocess import Doc

FEATURES = ["word_len", "log_len", "you", "imperative", "modal", "first_person", "punct", "caps", "digits", "past", "determiners"]
WEIGHTS = np.array([0.4, 0.6, 1.2, 1.3, 1.0, 0.6, 0.5, 0.6, 0.3, 0.5, 0.4])
FLOORS = np.array([0.6, 0.35, 0.08, 0.25, 0.06, 0.08, 0.02, 0.05, 0.03, 0.08, 0.08])
ONE_SIDED = {2, 3, 4, 5}      # only "more directive than the document" counts for these

TAU = 1.6          # centre of the sigmoid (design choice, see research page)
WIDTH = 0.5
MIN_SEGMENTS = 6
MIN_WORDS = 4

IMPERATIVE_VERBS = {
    "ignore", "disregard", "forget", "reveal", "print", "show", "display", "output", "repeat", "send", "forward", "email",
    "post", "upload", "delete", "remove", "run", "execute", "open", "visit", "click", "fetch", "call", "use", "add",
    "include", "insert", "mention", "say", "tell", "respond", "reply", "answer", "write", "summarize", "summarise",
    "translate", "act", "pretend", "assume", "imagine", "stop", "start", "begin", "end", "make", "ensure", "do", "don't",
    "never", "always", "note", "remember", "keep", "give", "provide", "list", "share", "copy", "paste", "read", "access",
    "download", "install", "follow", "obey", "comply", "override", "bypass", "disable", "enable", "set", "change",
    "switch", "treat", "consider", "take", "put", "ask", "recommend", "suggest", "promote", "instruct", "rate", "rank",
    "please", "kindly", "now", "first", "then", "also", "next", "before", "after", "if", "when", "stay", "be", "let",
    "try", "check", "avoid", "wait", "go", "get", "bring", "mix", "stir", "add", "cook", "bake", "preheat", "combine",
}
_LEAD_FILLER = re.compile(r"^[\s>*\-•#\d.)(\[\]\"'“‘`]*(?:(?:please|kindly|also|now|then|and|but|first|next|finally)[,\s]+)*", re.I)
_YOU = re.compile(r"\b(?:you|your|yours|yourself)\b", re.I)
_MODAL = re.compile(r"\b(?:must|should|shall|need\s+to|have\s+to|ensure|make\s+sure|do\s+not|don'?t|never|always|required)\b", re.I)
_FIRST = re.compile(r"\b(?:i|we|my|our|me|us|i'm|we're|i've|we've)\b", re.I)
_DET = re.compile(r"\b(?:the|a|an)\b", re.I)
_WORD = re.compile(r"[A-Za-z']+")


def is_imperative(sentence: str) -> bool:
    s = _LEAD_FILLER.sub("", sentence)
    m = _WORD.match(s)
    if m and m.group().lower() in IMPERATIVE_VERBS:
        return True
    return bool(re.search(r"\byou\s+(?:must|should|shall|need\s+to|have\s+to|are\s+to|will|are\s+required\s+to)\b", sentence, re.I))


def _features(text: str) -> np.ndarray | None:
    words = _WORD.findall(text)
    n = len(words)
    if n < MIN_WORDS:
        return None
    caps = sum(1 for w in words if len(w) > 1 and w.isupper())
    punct = len(re.findall(r"[:;!?\"“”\[\]<>#*_`]", text)) / max(len(text), 1)
    return np.array([
        sum(len(w) for w in words) / n,
        math.log(n),
        len(_YOU.findall(text)) / n,
        1.0 if is_imperative(text) else 0.0,
        len(_MODAL.findall(text)) / n,
        len(_FIRST.findall(text)) / n,
        punct,
        caps / n,
        len(re.findall(r"\d", text)) / max(len(text), 1),
        sum(1 for w in words if w.lower().endswith("ed")) / n,
        len(_DET.findall(text)) / n,
    ])


@dataclass
class StyleResult:
    applicable: bool
    scores: dict[int, dict]          # segment id -> {"d": distance, "s": isolated distance, "p": probability}
    reason: str = ""

    def max_p(self) -> float:
        return max((v["p"] for v in self.scores.values()), default=0.0) if self.applicable else 0.0


def _sigmoid(x: float) -> float:
    return 1.0 / (1.0 + math.exp(-x))


def analyze_style(doc: Doc) -> StyleResult:
    feats: list[tuple[int, np.ndarray]] = []
    for seg in doc.segments:
        f = _features(seg.norm)
        if f is not None:
            feats.append((seg.id, f))
    if len(feats) < MIN_SEGMENTS:
        return StyleResult(False, {}, f"needs at least {MIN_SEGMENTS} sentences of 4+ words to build a baseline")

    X = np.vstack([f for _, f in feats])
    med = np.median(X, axis=0)
    mad = np.median(np.abs(X - med), axis=0) * 1.4826
    scale = np.maximum(mad, FLOORS)
    Z = np.clip((X - med) / scale, -6, 6)
    for j in range(Z.shape[1]):
        if j in ONE_SIDED:
            Z[:, j] = np.maximum(Z[:, j], 0)
    d = np.sqrt((WEIGHTS * Z ** 2).sum(axis=1) / WEIGHTS.sum())

    out: dict[int, dict] = {}
    for k, (sid, _) in enumerate(feats):
        nb = [d[k - 1]] if k > 0 else []
        if k + 1 < len(d):
            nb.append(d[k + 1])
        s = d[k] - 0.5 * (max(nb) if nb else 0.0)
        out[sid] = {"d": float(d[k]), "s": float(s), "p": float(_sigmoid((s - TAU) / WIDTH))}
    return StyleResult(True, out)
