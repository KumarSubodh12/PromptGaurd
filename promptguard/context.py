"""Stage 4: contextual analysis.

A keyword match tells us *what words are present*. This module asks what the
sentence is actually doing: is it a command, a quotation, a security
discussion, a prohibition, an edit instruction aimed at a human reader?

The result is a transparent multiplier (``factor``) with the human-readable
reasons behind it, plus a feature vector used by the supervised contextual
classifier (``ml.ContextClassifier``).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from .preprocess import Doc
from .rules import Rule, RuleHit
from .style import is_imperative

_YOU = re.compile(r"\b(?:you|your|yours|yourself)\b", re.I)
_AI_WORDS = re.compile(
    r"\b(?:ai|a\.i\.|llm|llms|language\s+models?|chatbots?|assistants?|agents?|gpt|chatgpt|claude|gemini|copilot|model)\b", re.I)

_DISCUSS = [
    r"prompt[\s-]+injection", r"injection\s+attacks?", r"\battack(?:s|er|ers)?\b", r"\bmalicious\b", r"\bexamples?\b",
    r"for\s+example", r"e\.g\.", r"such\s+as", r"\bphrases?\b", r"\bpayloads?\b", r"\bresearchers?\b", r"\bpapers?\b",
    r"\bstud(?:y|ies)\b", r"\bowasp\b", r"\bvulnerab\w+", r"\bjailbreaks?\b", r"\bdefen[cs]e\w*", r"\bmitigat\w+",
    r"\bdetect\w*", r"\bsecurity\b", r"\bknown\s+as\b", r"\bis\s+called\b", r"\btechniques?\b", r"\bdemonstrat\w+",
    r"\bhijack\w*", r"\bfilter\w*", r"\bblocked\b", r"\bflagged\b", r"\bclassif\w+", r"\badversar\w+", r"\bred[\s-]team\w*",
    r"\bcommon(?:ly)?\b", r"\btypical(?:ly)?\b", r"\bbenchmark\w*", r"\bsanitiz\w+|\bsanitis\w+", r"\buntrusted\b",
]
_DISCUSS_RE = [re.compile(p, re.I) for p in _DISCUSS]

_INTRO_CUE = re.compile(
    r"(?:such\s+as|for\s+example|e\.g\.?|i\.e\.?|the\s+(?:phrase|string|text|sentence|command|prompt|payload|message|words?|line|input)|"
    r"(?:attackers?|hackers?|adversar(?:y|ies)|authors?|researchers?|users?)\s+(?:might|may|could|can|would|often|typically|will)?\s*"
    r"(?:write|type|include|insert|embed|use|say|put|inject|enter|craft|hide|add)\w*|"
    r"\bwrote\b|\bwrites\b|\bwritten\b|\breads\b|\bsays\b|\bsaid\b|\bstates?\b|\bstating\b|\blike\b|\bcalled\b|\blabell?ed\b|"
    r"known\s+as|\bdubbed\b|\bsamples?\b|\bpayload\b|\bquoted?\b|\bquoting\b|\breported\b|\blogged\b|\bblocked\b|"
    r"\bflagged\b|\bdetected\b|\bexamples?\b|\bentry\b)[\s:,\-–—]*[\"'“‘`(\[]?\s*$",
    re.I,
)
_PROHIBIT = re.compile(
    r"(?:do\s+not|don'?t|never|must\s+not|should\s+not|shouldn'?t|cannot|can'?t|avoid|refrain\s+from|not\s+to|"
    r"no\s+one\s+should|please\s+do\s+not)\s*(?:\w+\s+){0,2}$", re.I)
_DOC_REF = re.compile(
    r"\b(?:my|our|his|her|their)\s+(?:earlier|previous|last|prior)\s+(?:email|message|note|text|draft|reply|post|comment|mail|request|question)\b|"
    r"\bwhat\s+i\s+(?:said|wrote|told|mentioned)\b|"
    r"\bthe\s+(?:previous|earlier|above|last|prior)\s+(?:paragraph|sentence|section|chapter|figure|table|draft|version|email|message|"
    r"numbers|entry|page|slide|invoice|quote|estimate)\b", re.I)
_HUMAN_CUES = re.compile(
    r"\b(?:dear\s+[A-Z]\w+|hi\s+[A-Z]\w+|thanks|thank\s+you|regards|sincerely|best\s*,|cheers|team|colleagues|everyone|customers|"
    r"students|please\s+find\s+attached|see\s+you|by\s+(?:monday|tuesday|wednesday|thursday|friday|eod|end\s+of\s+day)|meeting|"
    r"invoice|deadline|office|manager|client|vendor|finance|hr\b|payroll|schedule)\b", re.I)


@dataclass
class ContextInfo:
    imperative: bool = False
    second_person: int = 0
    quoted: bool = False
    intro: bool = False
    discuss: int = 0
    prohibition: bool = False
    doc_ref: bool = False
    human_cues: int = 0
    ai_addressed: bool = False
    factor: float = 1.0
    label: str = "directive"
    reasons: list[str] = field(default_factory=list)

    def as_features(self) -> list[float]:
        return [
            float(self.imperative), float(self.second_person > 0), float(self.quoted), float(self.intro),
            min(self.discuss, 4) / 4.0, float(self.prohibition), float(self.doc_ref),
            float(self.human_cues >= 2), float(self.ai_addressed),
        ]


FEATURE_NAMES = ["imperative", "second_person", "quoted", "intro_cue", "discussion", "prohibition", "doc_reference",
                 "human_correspondence", "ai_addressed"]


def _inside_quotes(text: str, start: int, end: int, fences: list[tuple[int, int]]) -> bool:
    if any(a <= start and end <= b for a, b in fences):
        return True
    line_start = text.rfind("\n", 0, start) + 1
    line_end = text.find("\n", end)
    line_end = len(text) if line_end < 0 else line_end
    line = text[line_start:line_end]
    if line.lstrip().startswith(">"):
        return True
    before = text[line_start:start]
    after = text[end:line_end]
    if before.count("`") % 2 == 1 and "`" in after:
        return True
    if before.count('"') % 2 == 1 and '"' in after:
        return True
    if before.count("“") > before.count("”") and "”" in after:
        return True
    if before.count("‘") > before.count("’") and "’" in after and len(after) < 400:
        return True
    return False


def discussion_score(text: str) -> int:
    return sum(1 for rx in _DISCUSS_RE if rx.search(text))


def analyze_hit(doc: Doc, hit: RuleHit, ai_overlap: bool) -> ContextInfo:
    """Compute the context of one rule match."""
    rule: Rule = hit.rule
    seg = doc.segments[doc.seg_at(hit.start)] if doc.segments else None
    norm = doc.norm.text
    # locate the match in the norm view for position-sensitive checks
    ns = seg.nstart if seg else 0
    ne = seg.nend if seg else len(norm)
    sentence = norm[ns:ne]
    window_lo = max(0, doc.segments[seg.id - 1].nstart if seg and seg.id > 0 else ns)
    window_hi = doc.segments[seg.id + 1].nend if seg and seg.id + 1 < len(doc.segments) else ne
    window = norm[window_lo:window_hi]

    # position of the matched text inside the norm view
    m_text = doc.original[hit.start:hit.end]
    probe = re.sub(r"\s+", " ", m_text).strip()
    pos = norm.find(probe, ns, ne + 5) if probe else -1
    if pos < 0:
        pos = ns
    m_end = pos + max(len(probe), 1)
    before = norm[max(ns, pos - 90):pos]

    c = ContextInfo()
    c.imperative = is_imperative(sentence)
    c.second_person = len(_YOU.findall(sentence))
    c.quoted = _inside_quotes(norm, pos, m_end, doc.fences)
    c.intro = bool(_INTRO_CUE.search(before))
    c.discuss = discussion_score(window)
    c.prohibition = bool(_PROHIBIT.search(norm[max(ns, pos - 32):pos]))
    c.doc_ref = bool(_DOC_REF.search(sentence))
    c.human_cues = len(_HUMAN_CUES.findall(window))
    c.ai_addressed = ai_overlap or (bool(_AI_WORDS.search(sentence)) and c.second_person > 0)

    f = 1.0
    why = c.reasons
    if c.prohibition and rule.negation_sensitive:
        f *= 0.12
        why.append("phrased as a prohibition (\"never/do not ...\"), not as a request")
    if c.doc_ref:
        f *= 0.10
        why.append("refers to an earlier part of the message or document, not to AI instructions")
    if c.quoted and c.intro:
        f *= 0.12
        why.append("quoted and introduced as an example")
    elif c.quoted:
        f *= 0.45
        why.append("inside quotation marks, a quote block or a code block")
    elif c.intro:
        f *= 0.50
        why.append("introduced with wording that marks it as an example or report")
    if not c.ai_addressed:
        if c.discuss >= 3:
            f *= 0.25
            why.append("surrounding text discusses prompt injection or security")
        elif c.discuss == 2:
            f *= 0.45
            why.append("surrounding text reads like a discussion of attacks or examples")
        elif c.discuss == 1:
            f *= 0.80
    if (c.human_cues >= 2 and not c.ai_addressed
            and rule.category in ("unauthorised_action", "info_extraction")):
        f *= 0.55
        why.append("reads like ordinary correspondence between people")
    if c.ai_addressed:
        f = min(1.5, f * 1.35)
        why.append("addressed to an AI system")
    if c.imperative or c.second_person:
        f *= 1.10
    else:
        f *= 0.75
        why.append("not phrased as a command")
    c.factor = max(0.03, min(f, 1.5))

    if c.factor >= 0.8:
        c.label = "directive"
    elif c.quoted or c.intro:
        c.label = "quoted example"
    elif c.prohibition:
        c.label = "prohibition"
    elif c.doc_ref:
        c.label = "ordinary edit instruction"
    elif c.discuss >= 1:
        c.label = "security discussion"
    else:
        c.label = "uncertain"
    return c
