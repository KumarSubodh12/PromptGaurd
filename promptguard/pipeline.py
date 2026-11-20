"""The detection pipeline: preprocessing -> rules -> context -> models ->
novel modules -> risk score -> explainable report.

``Analyzer.core(text)`` does the heavy work once and exposes the raw signals.
``Analyzer.finish(core, ...)`` turns them into the full report, so the
evaluation scripts can reuse one pass for every method and ablation.
"""
from __future__ import annotations

import re
import time
from dataclasses import dataclass, field, asdict

from . import audience, blast, context, rules, style
from .config import (ACTIVE_P, CATEGORIES, DISCOUNT_P, METHODS, RULE_CATEGORIES, risk_band)
from .ml import ContextClassifier, Models, TfidfDetector, fallback_probability
from .preprocess import Doc, preprocess

VERSION = "1.0.0"

# Strong rule evidence (severity >= 9 *after* context discounting) sets a floor
# under the final probability, so the learned signals can never outvote it.
# Added after seeing that the stacker under-weighted rules (see README).
EVIDENCE_FLOOR = 0.90
STRONG_SEVERITY = 9

ACTIONS = {
    "instruction_override": "Treat this passage as untrusted content. Do not let it control the AI assistant; remove it, or pass it on only as quoted data.",
    "info_extraction": "Do not let the AI answer this request. Check that the AI cannot read secrets it could be tricked into disclosing.",
    "role_manipulation": "Ignore any role change requested inside external content. Keep the assistant's role fixed by your own instructions.",
    "unauthorised_action": "Block the action. Require human approval for sending data, deleting, running code or paying, and check where any link really goes.",
    "behaviour_manipulation": "Do not let external text change the AI's task or hide its actions from the user.",
    "audience_mismatch": "Content meant for people should not speak to an AI. Treat this passage as untrusted and strip it before processing.",
    "style_break": "This sentence reads very differently from the rest of the document. Review it by hand; on its own it is a weak signal.",
    "obfuscation": "Reveal or remove the hidden characters and read what they spell out before using the text.",
    "ml_flagged": "A statistical model found this passage instruction-like, but no rule matched. Review it by hand.",
}


@dataclass
class Finding:
    id: int
    category: str
    method: str
    name: str
    start: int
    end: int
    text: str
    segment: int
    severity: int
    p: float
    intent: str | None
    explanation: str
    action: str
    reasons: list[str] = field(default_factory=list)
    context_label: str = ""
    rule_id: str | None = None
    lang: str | None = None
    via: str = "text"
    discounted: bool = False
    ml_p: float | None = None
    ctx: object | None = None          # ContextInfo for rule findings (not serialised)

    def to_dict(self) -> dict:
        d = asdict(self)
        d.pop("ctx", None)
        d["category_label"] = CATEGORIES[self.category][0]
        d["method_label"] = METHODS.get(self.method, self.method)
        d["score"] = round(self.p * 100)
        d["band"] = risk_band(self.p * 100)[0]
        return d


@dataclass
class Core:
    doc: Doc
    findings: list[Finding]
    signals: dict
    rule_hits: int
    style_result: style.StyleResult
    aud_hits: list
    ctx_features: list[float]
    seconds: float = 0.0


def _noisy_or(ps) -> float:
    q = 1.0
    for p in ps:
        q *= 1.0 - min(max(p, 0.0), 0.999)
    return 1.0 - q


def _overlap(a0, a1, b0, b1) -> bool:
    return a0 < b1 and b0 < a1


class Analyzer:
    def __init__(self, models: Models | None = None, use_novel: bool = True):
        self.models = models or Models()
        self.use_novel = use_novel

    # ------------------------------------------------------------------ core
    def core(self, text: str, hidden_spans: list[tuple[int, int]] | None = None) -> Core:
        """``hidden_spans``: character ranges of ``text`` that the file format marks
        as hidden (e.g. Word "hidden" text), supplied by the extractor."""
        t0 = time.perf_counter()
        text = text.lstrip("\ufeff")
        doc = preprocess(text)
        findings: list[Finding] = []

        aud_hits = audience.find_audience_hits(doc) if self.use_novel else []
        aud_segments = {doc.seg_at(a.start) for a in aud_hits if a.p >= 0.4}

        # ---- rule engine + context
        rule_findings: list[Finding] = []
        hits = rules.find_hits(doc)
        for h in hits:
            ai_overlap = doc.seg_at(h.start) in aud_segments
            ctx = context.analyze_hit(doc, h, ai_overlap)
            p = h.rule.severity / 10 * ctx.factor
            if h.via == "deobfuscated":
                p *= 1.1
            p = min(p, 0.98)
            reasons = list(ctx.reasons)
            if h.via == "deobfuscated":
                reasons.append("only matched after hidden characters, look-alike letters or spacing were removed")
            f = Finding(
                id=0, category=h.rule.category, method="rule", name=h.rule.name, start=h.start, end=h.end,
                text=doc.original[h.start:h.end], segment=doc.seg_at(h.start), severity=h.rule.severity, p=p,
                intent=h.intent, explanation=h.rule.explain, action=ACTIONS[h.rule.category], reasons=reasons,
                context_label=ctx.label, rule_id=h.rule.id, lang=h.rule.lang if h.rule.lang != "en" else None,
                via=h.via, discounted=p < DISCOUNT_P, ctx=ctx,
            )
            rule_findings.append(f)
        findings.extend(rule_findings)

        # ---- TF-IDF model
        ml_p = 0.0
        if self.models.tfidf is not None:
            res = self.models.tfidf.score_doc(doc)
            ml_p = res["p"]
            for hit in res["hits"]:
                over = [f for f in rule_findings if _overlap(hit["start"], hit["end"], f.start, f.end)]
                if over:
                    for f in over:
                        f.ml_p = max(f.ml_p or 0.0, hit["p"])
                    continue
                findings.append(Finding(
                    id=0, category="ml_flagged", method="tfidf", name="Instruction-like passage (statistical model)",
                    start=hit["start"], end=hit["end"], text=doc.original[hit["start"]:hit["end"]],
                    segment=doc.seg_at(hit["start"]), severity=round(hit["p"] * 10), p=min(hit["p"], 0.98), intent="override_behaviour",
                    explanation="The TF-IDF classifier rates this passage as similar to known injection text, although no rule matched.",
                    action=ACTIONS["ml_flagged"], context_label="model-flagged", ml_p=hit["p"],
                ))

        # ---- audience mismatch (novel)
        aud_p = 0.0
        for a in aud_hits:
            seg = doc.segments[doc.seg_at(a.start)] if doc.segments else None
            p = a.p
            reasons: list[str] = []
            if seg is not None and not a.hidden:
                window = doc.norm.text[max(0, seg.nstart - 200):seg.nend + 200]
                disc = context.discussion_score(window)
                if disc >= 3:
                    p *= 0.35
                    reasons.append("surrounding text discusses prompt injection or security")
                elif disc == 2:
                    p *= 0.6
                if context._inside_quotes(doc.norm.text, seg.nstart, min(seg.nstart + 3, seg.nend), doc.fences):
                    p *= 0.5
                    reasons.append("inside a quote block or code block")
            if a.directive:
                reasons.append("followed by a command")
            if a.hidden:
                reasons.append("hidden from human readers")
            f = Finding(
                id=0, category="audience_mismatch", method="audience", name=a.label, start=a.start, end=a.end,
                text=doc.original[a.start:a.end], segment=doc.seg_at(a.start), severity=round(p * 10), p=min(p, 0.95),
                intent="override_behaviour" if (a.directive or a.hidden) else None,
                explanation="This text speaks to an AI system inside content written for human readers.",
                action=ACTIONS["audience_mismatch"], reasons=reasons, context_label="addressed to AI",
                discounted=p < DISCOUNT_P,
            )
            findings.append(f)
            aud_p = max(aud_p, f.p)

        # ---- style break (novel)
        style_res = style.analyze_style(doc) if self.use_novel else style.StyleResult(False, {})
        style_p = style_res.max_p()
        if style_res.applicable:
            for sid, sc in style_res.scores.items():
                if sc["p"] >= 0.5:
                    seg = doc.segments[sid]
                    findings.append(Finding(
                        id=0, category="style_break", method="style", name="Writing style differs from the rest of the document",
                        start=seg.start, end=seg.end, text=seg.text, segment=sid, severity=round(sc["p"] * 10),
                        p=min(sc["p"] * 0.6, 0.6), intent=None,
                        explanation=f"This sentence deviates from the document's typical style (distance {sc['d']:.1f}, isolated distance {sc['s']:.1f}).",
                        action=ACTIONS["style_break"], context_label="style outlier",
                    ))

        # ---- hidden / obfuscated characters
        obf_p = self._unicode_findings(doc, findings)
        for a, b in hidden_spans or []:
            if b > a:
                findings.append(Finding(
                    id=0, category="obfuscation", method="unicode", name="Text hidden by the document format",
                    start=a, end=b, text=doc.original[a:b], segment=doc.seg_at(a), severity=6, p=0.55, intent=None,
                    explanation="This text is formatted as hidden, so readers do not see it, but it is still extracted. "
                                "An AI that reads the file would read it.",
                    action=ACTIONS["obfuscation"], context_label="hidden text"))
                obf_p = max(obf_p, 0.55)
        if any(f.via == "deobfuscated" and f.p >= ACTIVE_P for f in rule_findings):
            obf_p = max(obf_p, 0.6)

        # ---- ids, ordering, discount flag
        findings.sort(key=lambda f: (f.start, -f.p))
        for i, f in enumerate(findings, 1):
            f.id = i
            f.discounted = f.p < DISCOUNT_P

        # ---- signals
        by_seg: dict[int, list[Finding]] = {}
        for f in rule_findings:
            by_seg.setdefault(f.segment, []).append(f)
        seg_scores = []
        for fs in by_seg.values():
            cats = {f.category for f in fs if f.p >= DISCOUNT_P}
            seg_scores.append(min(0.99, max(f.p for f in fs) + 0.08 * max(0, len(cats) - 1)))
        rule_ctx = _noisy_or(seg_scores)

        ctx_feats = ContextClassifier.featurize(rule_findings)
        ctx_p = 0.0
        if self.models.ctx is not None:
            ctx_p = float(self.models.ctx.proba([ctx_feats])[0])

        rule_strong = max((f.p for f in rule_findings if f.severity >= STRONG_SEVERITY), default=0.0)
        signals = {
            "rule_raw": 1.0 if rule_findings else 0.0,
            "rule_strong": rule_strong,
            "rule_ctx": rule_ctx, "ml_p": ml_p, "ctx_p": ctx_p,
            "aud_p": aud_p, "style_p": style_p, "obf_p": obf_p,
        }
        return Core(doc, findings, signals, len(rule_findings), style_res, aud_hits, ctx_feats,
                    time.perf_counter() - t0)

    # ------------------------------------------------------------ unicode
    def _unicode_findings(self, doc: Doc, findings: list[Finding]) -> float:
        flags, text = doc.flags, doc.original
        best = 0.0

        def add(name, start, end, sev, p, why, label="hidden characters"):
            nonlocal best
            findings.append(Finding(
                id=0, category="obfuscation", method="unicode", name=name, start=start, end=end,
                text=text[start:end], segment=doc.seg_at(start), severity=sev, p=p, intent=None,
                explanation=why, action=ACTIONS["obfuscation"], context_label=label,
            ))
            best = max(best, p)

        if flags["tag_chars"]:
            pos = flags["tag_chars"]
            decoded = "".join(chr(ord(text[i]) - 0xE0000) for i in pos if 0xE0020 <= ord(text[i]) <= 0xE007E)
            add("Invisible Unicode tag characters", pos[0], pos[-1] + 1, 9, 0.95,
                f"{len(pos)} invisible characters hide a message that reads: \"{decoded[:160]}\". People cannot see it, but an AI can.",
                "invisible text")
        zw = flags["zero_width_in_word"]
        if zw:
            add("Zero-width characters inside words", zw[0], zw[-1] + 1, 5, 0.6 if len(zw) > 1 else 0.35,
                f"{len(zw)} zero-width character(s) sit between letters. This breaks up keywords so simple filters miss them.")
        for start in flags["homoglyph"]:
            m = re.match(r"\w+", text[start:])
            end = start + (len(m.group()) if m else 1)
            add("Look-alike letters from another alphabet", start, end, 5, 0.6,
                "A word mixes Latin letters with look-alike Cyrillic or Greek letters, a common way to dodge keyword filters.")
        if flags["bidi"]:
            b = flags["bidi"]
            add("Text-direction override characters", b[0], b[-1] + 1, 5, 0.5,
                "Bidirectional control characters can make text display differently from how it is stored.")
        if len(flags["fullwidth"]) >= 3:
            b = flags["fullwidth"]
            add("Full-width letters", b[0], b[-1] + 1, 3, 0.3,
                "Full-width Latin letters look like normal text but defeat simple keyword matching.")
        return best

    # ------------------------------------------------------------- scoring
    def hybrid_probability(self, signals: dict) -> float:
        p = self.models.stack.predict(signals) if self.models.stack is not None else fallback_probability(signals)
        return max(p, EVIDENCE_FLOOR * signals.get("rule_strong", 0.0))

    def finish(self, core: Core, profile: str = "unknown", custom_caps: list[str] | None = None,
               name: str = "Pasted text") -> dict:
        doc, findings, sig = core.doc, core.findings, core.signals
        p_content = self.hybrid_probability(sig)
        content = round(100 * p_content)

        blast_res = blast.assess(findings, profile, custom_caps)
        exposure = min(100, round(content * blast_res["multiplier"]))
        score = exposure
        label, colour = risk_band(score)
        c_label, c_colour = risk_band(content)

        visible = [f for f in findings if not f.discounted]
        summary = {c: 0 for c in CATEGORIES}
        for f in visible:
            summary[f.category] += 1
        methods = {m: 0 for m in METHODS}
        for f in visible:
            methods[f.method] = methods.get(f.method, 0) + 1

        confidence = max((f.p for f in visible), default=0.0)
        contrib = self.models.stack.contributions(sig) if self.models.stack is not None else []

        return {
            "version": VERSION,
            "name": name,
            "risk": {"score": score, "category": label, "colour": colour},
            "content_threat": {"score": content, "category": c_label, "colour": c_colour},
            "confidence": round(confidence, 3),
            "signals": {k: round(v, 4) for k, v in sig.items()},
            "contributions": contrib,
            "findings": [f.to_dict() for f in findings],
            "summary": summary,
            "methods": methods,
            "highlights": build_highlights(findings),
            "blast": blast_res,
            "style": {
                "applicable": core.style_result.applicable,
                "reason": core.style_result.reason,
            },
            "stats": {
                "chars": len(doc.original), "words": doc.word_count(), "segments": len(doc.segments),
                "visible_findings": len(visible), "discounted_findings": len(findings) - len(visible),
                "seconds": round(core.seconds, 3),
            },
            "recommendations": recommendations(visible, blast_res, label),
            "models_loaded": {
                "tfidf": self.models.tfidf is not None, "context": self.models.ctx is not None,
                "stacker": self.models.stack is not None,
            },
        }

    def analyze(self, text: str, profile: str = "unknown", custom_caps: list[str] | None = None,
                name: str = "Pasted text", hidden_spans: list[tuple[int, int]] | None = None) -> dict:
        return self.finish(self.core(text, hidden_spans), profile, custom_caps, name)


def build_highlights(findings: list[Finding]) -> list[dict]:
    """Non-overlapping character ranges, each pointing at every finding that covers it."""
    fs = [f for f in findings if f.end > f.start]
    if not fs:
        return []
    points = sorted({f.start for f in fs} | {f.end for f in fs})
    out: list[dict] = []
    for a, b in zip(points, points[1:]):
        cov = [f for f in fs if f.start <= a and f.end >= b]
        if not cov:
            continue
        top = max(cov, key=lambda f: (not f.discounted, f.p))
        item = {"start": a, "end": b, "ids": [f.id for f in cov], "category": top.category,
                "p": round(top.p, 3), "discounted": all(f.discounted for f in cov)}
        if out and out[-1]["end"] == a and out[-1]["ids"] == item["ids"] and out[-1]["category"] == item["category"]:
            out[-1]["end"] = b
        else:
            out.append(item)
    return out


def recommendations(visible: list[Finding], blast_res: dict, band: str) -> list[str]:
    recs: list[str] = []
    if not visible:
        recs.append("No suspicious instructions were found. That is not a guarantee: unknown attacks can still slip past any detector.")
        recs.append("Keep treating external content as data, never as instructions.")
        return recs
    cats = {f.category for f in visible}
    recs.append("Treat every highlighted passage as untrusted content.")
    recs.append("Do not interpret external text as trusted system instructions.")
    recs.append("Review the content before sending it to an AI assistant.")
    if cats & {"unauthorised_action", "info_extraction"} or any(p["status"] == "reachable" for p in blast_res["paths"]):
        recs.append("Avoid granting the AI more tool permissions than this task needs, and ask for human approval before it sends, deletes, runs or pays.")
    recs.extend(blast_res["mitigations"][:4])
    if "obfuscation" in cats:
        recs.append("Remove the hidden or look-alike characters, then scan the text again.")
    if band in ("High", "Critical"):
        recs.append("Do not pass this content to an AI agent that has access to private data or outbound channels.")
    recs.append("Removing the flagged text does not guarantee the rest of the document is safe.")
    return recs
