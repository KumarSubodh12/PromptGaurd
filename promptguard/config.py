"""Central configuration for PromptGuard.

All thresholds here are *design choices*, not scientifically established
values. The Research page shows how they behave on the evaluation data.
"""
from __future__ import annotations

from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
MODEL_DIR = BASE_DIR / "models"
INSTANCE_DIR = BASE_DIR / "instance"
DB_PATH = INSTANCE_DIR / "promptguard.db"

# --- input validation -------------------------------------------------------
MAX_UPLOAD_BYTES = 5 * 1024 * 1024          # 5 MB per file
MAX_TEXT_CHARS = 400_000                    # hard cap on analysed text
MAX_PDF_PAGES = 200
MAX_DOCX_UNCOMPRESSED = 40 * 1024 * 1024    # zip-bomb guard
ALLOWED_EXTENSIONS = {".txt", ".md", ".pdf", ".docx", ".eml", ".html", ".htm"}

# --- risk scale (configurable, to be calibrated on research data) -----------
RISK_BANDS = [
    (0, 30, "Low", "#22C55E"),
    (30, 60, "Medium", "#EAB308"),
    (60, 80, "High", "#F59E0B"),
    (80, 101, "Critical", "#EF4444"),
]


def risk_band(score: float) -> tuple[str, str]:
    """Return (label, colour) for a 0-100 score."""
    for lo, hi, label, colour in RISK_BANDS:
        if lo <= score < hi:
            return label, colour
    return RISK_BANDS[-1][2], RISK_BANDS[-1][3]


# A finding whose confidence is below DISCOUNT_P is shown as "discounted":
# a rule matched, but the context says it is probably harmless.
DISCOUNT_P = 0.20
# Findings at or above ACTIVE_P count towards Blast Radius reasoning.
ACTIVE_P = 0.30

# --- finding categories (label, highlight colour, underline style) ----------
CATEGORIES = {
    "instruction_override": ("Instruction Override", "#EF4444", "solid"),
    "info_extraction": ("Information Extraction", "#8B5CF6", "dotted"),
    "role_manipulation": ("Role Manipulation", "#F59E0B", "dashed"),
    "unauthorised_action": ("Suspicious Action", "#38BDF8", "double"),
    "behaviour_manipulation": ("Behaviour Manipulation", "#F472B6", "wavy"),
    "audience_mismatch": ("Audience Mismatch", "#2DD4BF", "solid"),
    "style_break": ("Style Break", "#94A3B8", "dashed"),
    "obfuscation": ("Hidden or Obfuscated Text", "#A3E635", "dotted"),
    "ml_flagged": ("Model-flagged Passage", "#F0ABFC", "wavy"),
}

RULE_CATEGORIES = [
    "instruction_override",
    "info_extraction",
    "role_manipulation",
    "unauthorised_action",
    "behaviour_manipulation",
]

# Detection methods (used for the "method comparison" chart)
METHODS = {
    "rule": "Rule engine",
    "tfidf": "TF-IDF + Logistic Regression",
    "audience": "Audience-mismatch detector",
    "style": "Style-break detector",
    "unicode": "Unicode / hidden-text check",
}

SEED = 20260101
