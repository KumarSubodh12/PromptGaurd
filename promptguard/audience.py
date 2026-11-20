"""Novel module 1: Audience Mismatch detector.

Idea: ordinary documents are written for *human* readers. A sentence that
speaks directly to an AI system ("Note to AI assistants:", "If you are a
language model ...", "AI-generated summaries must ...") has no business in a
document meant for people, and an AI that obeys it is being addressed by a
stranger. The signal is strongest when the AI-directed text is also followed
by a command, or is hidden from human readers (HTML comment, CSS-hidden text).

The detector scores *who the text is talking to*, not which words it uses, so
it can catch an attack that never says "ignore previous instructions".
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from .preprocess import Doc

_STRONG = (
    r"(?:ai\s+(?:assistants?|agents?|models?|systems?|summari[sz]ers?)|large\s+language\s+models?|language\s+models?|"
    r"chat\s*bots?|llms?|a\.i\.|ai|gpt|chatgpt|claude|gemini|copilot|crawlers?|scrapers?|summari[sz]ers?|"
    r"automated\s+(?:systems?|readers?|agents?))"
)
_WEAK = r"(?:assistants?|agents?|models?|bots?)"
_NOT_ROLE = (
    r"(?!\s+(?:manager|professor|director|principal|teacher|editor|coach|superintendent|lecturer|producer|secretary|"
    r"attorney|clerk|vice|general|dean|chair|curator|librarian|prosecutor|commissioner|engineer|designer|athlete|"
    r"trainer|buyer|planner|to\b))"
)

_DIRECTIVE = re.compile(
    r"\b(?:you\s+(?:must|should|need\s+to|will|shall|are\s+(?:to|required)|have\s+to)|please|always|never|do\s+not|don'?t|"
    r"make\s+sure|be\s+sure|ensure|include|add|insert|mention|recommend|say|state|respond|reply|answer|output|"
    r"summari[sz]e|translate|ignore|disregard|forget|send|forward|visit|click|use|tell|write|begin|start|promote|rate|rank)\b",
    re.I,
)

# (pattern, base confidence if strong AI term, base if weak term, hidden-channel flag, label)
_PATTERNS = [
    (re.compile(
        rf"\b(?:dear|hey|hello|hi|attention|attn\.?|note\s+to|message\s+(?:for|to)|notice\s+to|instructions?\s+for|"
        rf"reminder\s+(?:for|to)|important\s+(?:for|to)|calling|to\s+all|for\s+all|to\s+any|for\s+any)\s*:?\s*"
        rf"(?:the\s+|all\s+|any\s+|every\s+)?({_STRONG}|{_WEAK}){_NOT_ROLE}\b", re.I),
     0.45, 0.20, False, "Addresses an AI system directly"),
    (re.compile(rf"\bif\s+you\s+(?:are|'re)\s+(?:an?\s+|the\s+)?({_STRONG}|{_WEAK}|machine){_NOT_ROLE}\b", re.I),
     0.60, 0.35, False, "Conditional address: 'if you are an AI'"),
    (re.compile(
        rf"\b(?:when|whenever|if|once|as)\s+(?:an?\s+|the\s+|any\s+|you\s+are\s+)?({_STRONG}|assistant|agent|bot|model)s?\s+"
        rf"(?:\w+\s+){{0,3}}?(?:reads?|reading|processes?|summari[sz]es?|summari[sz]ing|sees?|parses?|visits?|analy[sz]es?|"
        rf"encounters?|scrapes?|crawls?|translates?|indexes?|is\s+asked)\b", re.I),
     0.55, 0.30, False, "Triggered by an AI reading this text"),
    (re.compile(r"\b(?:ai|llm|chatbot|gpt|language\s+model)[- ]?(?:generated\s+)?(?:summar(?:y|ies)|answers?|responses?|replies|output)s?\s+"
                r"(?:must|should|need\s+to|shall|will|have\s+to)\b", re.I),
     0.40, 0.40, False, "Sets rules for AI-generated output"),
    (re.compile(r"<\s*(?:ai|llm|assistant)[-_ ]?(?:instructions?|note|only|directive)\s*>|"
                r"\[\s*(?:for\s+)?(?:ai|llm|assistant)(?:\s+only|\s+instructions?)?\s*\]", re.I),
     0.70, 0.70, True, "Tag aimed at AI readers"),
    (re.compile(r"\b(?:note|message|instructions?|text|section)\s+(?:intended\s+|meant\s+|written\s+)?(?:only\s+)?for\s+"
                r"(?:ai|llms?|automated|machine|bots?|crawlers?)\w*", re.I),
     0.65, 0.65, True, "Text declared to be for machines only"),
    (re.compile(r"\b(?:not\s+(?:meant|intended)\s+for\s+humans?|humans?\s+(?:should|need|can)\s*(?:not|n'?t)\s+(?:read|see)|"
                r"(?:invisible|hidden)\s+(?:to|from)\s+(?:humans?|users?|readers?))\b", re.I),
     0.50, 0.50, True, "Says it is hidden from human readers"),
]

_STRONG_RE = re.compile(rf"^{_STRONG}$", re.I)

_HTML_COMMENT = re.compile(r"<!--(?P<inner>.*?)-->", re.S)
_HIDDEN_STYLE = re.compile(
    r"<(?P<tag>[a-z0-9]+)[^>]*\bstyle\s*=\s*[\"'][^\"']*(?:display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0|"
    r"opacity\s*:\s*0|color\s*:\s*(?:#fff(?:fff)?\b|white\b)|position\s*:\s*absolute[^\"']*left\s*:\s*-\d{3,})[^\"']*[\"'][^>]*>"
    r"(?P<inner>.*?)</(?P=tag)\s*>", re.S | re.I)


@dataclass
class AudienceHit:
    start: int
    end: int
    p: float
    label: str
    hidden: bool
    strong: bool
    directive: bool


def _has_directive(text: str) -> bool:
    return bool(_DIRECTIVE.search(text))


def find_audience_hits(doc: Doc) -> list[AudienceHit]:
    hits: list[AudienceHit] = []
    text = doc.norm.text
    for rx, p_strong, p_weak, hidden, label in _PATTERNS:
        for m in rx.finditer(text):
            term = m.group(1) if rx.groups else m.group()
            strong = bool(term and _STRONG_RE.match(term.strip())) if rx.groups else True
            base = p_strong if strong else p_weak
            tail = text[m.start():m.end() + 220]
            directive = _has_directive(tail[m.end() - m.start():])
            p = base + (0.30 if directive else 0.0) + (0.10 if hidden else 0.0)
            s, e = doc.norm.to_orig(m.start(), m.end())
            hits.append(AudienceHit(s, e, min(p, 0.95), label, hidden, strong, directive))

    # Text a human reader would not see (HTML comments, CSS-hidden blocks)
    orig = doc.original
    for rx, what in ((_HTML_COMMENT, "HTML comment"), (_HIDDEN_STYLE, "CSS-hidden text")):
        for m in rx.finditer(orig):
            inner = m.group("inner")
            words = re.findall(r"\w+", inner)
            if len(words) < 6:
                continue
            s, e = m.start("inner"), m.end("inner")
            strong_ai = bool(re.search(rf"\b{_STRONG}\b", inner, re.I))
            directive = _has_directive(inner)
            p = 0.20 + (0.30 if strong_ai else 0.0) + (0.30 if directive else 0.0)
            if p < 0.35:
                continue
            hits.append(AudienceHit(s, e, min(p, 0.95), f"Hidden from human readers ({what}) and addressed to an AI",
                                    True, strong_ai, directive))
    hits.sort(key=lambda h: (h.start, -h.p))
    return hits
