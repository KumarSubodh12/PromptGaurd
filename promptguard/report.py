"""PDF security report (ReportLab, no external services)."""
from __future__ import annotations

import io
import unicodedata
from datetime import datetime
from xml.sax.saxutils import escape

from reportlab.graphics.shapes import Circle, Drawing, String
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import KeepTogether, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from .config import CATEGORIES
from .sanitize import LIMITATION

NAVY = colors.HexColor("#0B1120")
PANEL = colors.HexColor("#111C30")
BLUE = colors.HexColor("#38BDF8")
GREY = colors.HexColor("#64748B")
LINE = colors.HexColor("#CBD5E1")


def pdf_text(s: str, limit: int | None = None) -> str:
    """Make arbitrary text safe for the built-in Helvetica font.

    Invisible or unprintable characters are written out as [U+XXXX] so that
    hidden text is visible in the report rather than silently dropped.
    """
    out = []
    for ch in s:
        cp = ord(ch)
        if ch in "\n\t" or 32 <= cp < 127 or 160 <= cp <= 255:
            out.append(ch)
        elif unicodedata.category(ch) in ("Cf", "Cc", "Co", "Cn", "Zs") or 0xE0000 <= cp <= 0xE007F:
            out.append(f"[U+{cp:04X}]")
        else:
            out.append("?")
    t = "".join(out).replace("\t", " ")
    if limit and len(t) > limit:
        t = t[:limit].rstrip() + " ..."
    return escape(t).replace("\n", "<br/>")


def _gauge(score: int, label: str, colour: str) -> Drawing:
    d = Drawing(70, 70)
    d.add(Circle(35, 35, 32, fillColor=colors.white, strokeColor=colors.HexColor(colour), strokeWidth=5))
    d.add(String(35, 33, str(score), fontName="Helvetica-Bold", fontSize=22, textAnchor="middle", fillColor=NAVY))
    d.add(String(35, 19, "/ 100", fontName="Helvetica", fontSize=8, textAnchor="middle", fillColor=GREY))
    return d


def build_pdf(scan: dict) -> bytes:
    res = scan["result"]
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=18 * mm, rightMargin=18 * mm, topMargin=20 * mm, bottomMargin=18 * mm,
                            title=f"PromptGuard report {scan['id']}", author="PromptGuard")
    ss = getSampleStyleSheet()
    h1 = ParagraphStyle("h1", parent=ss["Title"], fontName="Helvetica-Bold", fontSize=22, textColor=NAVY, alignment=0, spaceAfter=2)
    h2 = ParagraphStyle("h2", parent=ss["Heading2"], fontName="Helvetica-Bold", fontSize=13, textColor=NAVY, spaceBefore=14, spaceAfter=6)
    body = ParagraphStyle("body", parent=ss["BodyText"], fontName="Helvetica", fontSize=9.5, leading=13)
    small = ParagraphStyle("small", parent=body, fontSize=8.5, leading=11, textColor=colors.HexColor("#334155"))
    mono = ParagraphStyle("mono", parent=small, fontName="Courier", fontSize=8, leading=10, backColor=colors.HexColor("#F1F5F9"))

    story: list = []
    story.append(Paragraph("PromptGuard security report", h1))
    story.append(Paragraph("Indirect prompt injection analysis", ParagraphStyle("sub", parent=body, textColor=GREY)))
    story.append(Spacer(1, 8))

    created = scan["created_at"].replace("T", " ").replace("+00:00", " UTC")
    meta = [
        ["Scan ID", scan["id"], "Scan date", created],
        ["Document", Paragraph(pdf_text(scan["name"] or "", 90), small), "Length", f"{res['stats']['chars']:,} characters, {res['stats']['words']:,} words"],
        ["Agent profile", res["blast"]["profile_label"], "Engine", f"PromptGuard {res['version']}"],
    ]
    t = Table(meta, colWidths=[24 * mm, 62 * mm, 24 * mm, 62 * mm])
    t.setStyle(TableStyle([("FONTNAME", (0, 0), (-1, -1), "Helvetica"), ("FONTSIZE", (0, 0), (-1, -1), 8.5),
                           ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"), ("FONTNAME", (2, 0), (2, -1), "Helvetica-Bold"),
                           ("TEXTCOLOR", (0, 0), (-1, -1), colors.HexColor("#1E293B")),
                           ("LINEBELOW", (0, 0), (-1, -1), 0.4, LINE), ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                           ("BOTTOMPADDING", (0, 0), (-1, -1), 4), ("TOPPADDING", (0, 0), (-1, -1), 4)]))
    story.append(t)
    story.append(Spacer(1, 12))

    risk, content = res["risk"], res["content_threat"]
    verdict = ParagraphStyle("verdict", parent=body, fontSize=15, leading=18, textColor=colors.HexColor(risk["colour"]), fontName="Helvetica-Bold")
    explain = (f"Content threat {content['score']}/100 ({content['category']}). "
               + ("On this agent profile the exposure is " + f"{risk['score']}/100." if not res["blast"]["worst_case"]
                  else "No agent profile was chosen, so the worst case is assumed."))
    box = Table([[_gauge(risk["score"], risk["category"], risk["colour"]),
                  [Paragraph(f"{risk['category']} risk", verdict), Spacer(1, 3), Paragraph(pdf_text(explain), body),
                   Spacer(1, 3), Paragraph(f"{res['stats']['visible_findings']} finding(s); "
                                           f"{res['stats']['discounted_findings']} rule match(es) discounted by context.", small)]]],
                colWidths=[30 * mm, 140 * mm])
    box.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "MIDDLE"), ("BOX", (0, 0), (-1, -1), 0.6, LINE),
                             ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F8FAFC")), ("LEFTPADDING", (0, 0), (-1, -1), 8)]))
    story.append(box)

    story.append(Paragraph("Detection summary", h2))
    rows = [["Category", "Findings"]] + [[CATEGORIES[k][0], str(v)] for k, v in res["summary"].items() if v]
    if len(rows) == 1:
        rows.append(["No findings", "0"])
    t = Table(rows, colWidths=[110 * mm, 30 * mm], hAlign="LEFT")
    t.setStyle(TableStyle([("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"), ("FONTSIZE", (0, 0), (-1, -1), 9),
                           ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#E2E8F0")), ("LINEBELOW", (0, 0), (-1, -1), 0.3, LINE),
                           ("ALIGN", (1, 0), (1, -1), "RIGHT")]))
    story.append(t)

    blast = res["blast"]
    if blast["paths"]:
        story.append(Paragraph("Blast radius on this agent", h2))
        story.append(Paragraph(pdf_text(
            f"Profile: {blast['profile_label']}. " + ("Worst case assumed (all capabilities)." if blast["worst_case"] else
                                                      f"Reach {blast['reach']:.0%}, exposure multiplier {blast['multiplier']:.2f}.")), small))
        story.append(Spacer(1, 4))
        label = {"reachable": "Reachable", "blocked": "Blocked", "text_only": "Works anywhere"}
        rows = [["What the content tries to do", "Status", "Needs"]]
        for p in blast["paths"]:
            rows.append([Paragraph(pdf_text(p["label"]), small), label[p["status"]],
                         Paragraph(pdf_text(" or ".join(p["needs"]) or "nothing, it only needs text output"), small)])
        t = Table(rows, colWidths=[70 * mm, 28 * mm, 72 * mm])
        t.setStyle(TableStyle([("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"), ("FONTSIZE", (0, 0), (-1, -1), 8.5),
                               ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#E2E8F0")),
                               ("LINEBELOW", (0, 0), (-1, -1), 0.3, LINE), ("VALIGN", (0, 0), (-1, -1), "TOP")]))
        story.append(t)
        for s in blast["standing_risk"]:
            story.append(Paragraph("&bull; " + pdf_text(s), small))

    story.append(Paragraph("Flagged text and explanations", h2))
    shown = [f for f in res["findings"] if not f["discounted"]]
    if not shown:
        story.append(Paragraph("No suspicious instructions were found.", body))
    for f in shown[:60]:
        head = (f"<b>#{f['id']} {escape(f['category_label'])}</b> &nbsp; {escape(f['band'])} ({f['score']}/100) &nbsp; "
                f"<font color='#64748B'>{escape(f['method_label'])}</font>")
        reasons = ("<br/>Context: " + pdf_text("; ".join(f["reasons"]))) if f["reasons"] else ""
        block = [Paragraph(head, body), Spacer(1, 2), Paragraph(pdf_text(f["text"], 260), mono), Spacer(1, 3),
                 Paragraph(pdf_text(f["explanation"]) + reasons, small),
                 Paragraph("<b>Suggested action:</b> " + pdf_text(f["action"]), small), Spacer(1, 8)]
        story.append(KeepTogether(block))
    if len(shown) > 60:
        story.append(Paragraph(f"{len(shown) - 60} more finding(s) are not listed here.", small))

    disc = [f for f in res["findings"] if f["discounted"]]
    if disc:
        story.append(Paragraph("Matches discounted by context", h2))
        story.append(Paragraph("A rule matched these passages, but the surrounding context suggests they are harmless "
                               "(quotations, security discussion, prohibitions, ordinary correspondence).", small))
        for f in disc[:15]:
            story.append(Paragraph(f"&bull; {pdf_text(f['text'], 120)} <font color='#64748B'>({pdf_text('; '.join(f['reasons'][:2]) or f['context_label'])})</font>", small))

    story.append(Paragraph("Recommendations", h2))
    for r in res["recommendations"]:
        story.append(Paragraph("&bull; " + pdf_text(r), body))

    story.append(Paragraph("Limitations", h2))
    for line in (LIMITATION,
                 "PromptGuard reports indicators, not proof. The same wording can appear in harmless security articles, quotations and ordinary instructions.",
                 "Risk bands (0-29 Low, 30-59 Medium, 60-79 High, 80-100 Critical) are configurable design choices, not scientifically established values.",
                 "No detector finds every prompt injection attack. See the Research page for measured failure modes."):
        story.append(Paragraph("&bull; " + escape(line), small))

    def footer(canvas, d):
        canvas.saveState()
        canvas.setFont("Helvetica", 7.5)
        canvas.setFillColor(GREY)
        canvas.drawString(18 * mm, 10 * mm, f"PromptGuard report {scan['id']}  |  generated {datetime.now().strftime('%Y-%m-%d %H:%M')}")
        canvas.drawRightString(A4[0] - 18 * mm, 10 * mm, f"Page {d.page}")
        canvas.setStrokeColor(BLUE)
        canvas.setLineWidth(1.2)
        canvas.line(18 * mm, A4[1] - 12 * mm, A4[0] - 18 * mm, A4[1] - 12 * mm)
        canvas.restoreState()

    doc.build(story, onFirstPage=footer, onLaterPages=footer)
    return buf.getvalue()
