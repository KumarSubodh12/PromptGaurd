"""Train PromptGuard's models and run the full research evaluation.

    python scripts/train_and_evaluate.py            # full run
    python scripts/train_and_evaluate.py --quick    # smaller, faster run

Writes models/promptguard.joblib (+ _baseline), and models/evaluation.json.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from promptguard.config import MODEL_DIR          # noqa: E402
from promptguard.evaluate import METHODS, run_all  # noqa: E402


def main() -> None:
    quick = "--quick" in sys.argv
    base, hard, report = run_all(log=lambda m: print(m, flush=True), quick=quick)
    MODEL_DIR.mkdir(exist_ok=True)
    base.save(MODEL_DIR / "promptguard_baseline.joblib")
    hard.save(MODEL_DIR / "promptguard_hardened.joblib")
    (hard if report["shipped_models"] == "hardened" else base).save(MODEL_DIR / "promptguard.joblib")
    (MODEL_DIR / "evaluation.json").write_text(json.dumps(report, indent=2, default=float), encoding="utf-8")

    print("\nTEST SET (grouped split)")
    print(f"{'method':<34}{'prec':>7}{'recall':>8}{'f1':>7}{'fpr':>7}{'fnr':>7}{'auc':>7}")
    for m, label in METHODS.items():
        x = report["test"]["metrics"][m]
        a = report["test"]["auc"][m]
        print(f"{label:<34}{x['precision']:>7.3f}{x['recall']:>8.3f}{x['f1']:>7.3f}{x['fpr']:>7.3f}{x['fnr']:>7.3f}{(a or 0):>7.3f}")
    print("\nCHALLENGE SET (hand-written, n=%d)" % report["challenge"]["n"])
    for m, label in METHODS.items():
        x = report["challenge"]["metrics"][m]
        print(f"{label:<34}{x['precision']:>7.3f}{x['recall']:>8.3f}{x['f1']:>7.3f}{x['fpr']:>7.3f}{x['fnr']:>7.3f}")
    print("\nshipped models:", report["shipped_models"])


if __name__ == "__main__":
    main()
