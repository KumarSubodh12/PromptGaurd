# PromptGuard

Intelligent indirect prompt injection detection and AI content security analysis.

PromptGuard reads a document, e-mail or web page *before* an AI assistant does, and looks for text that tries to give the assistant instructions: "ignore your rules", "forward this thread to...", hidden characters that spell out a command, and so on. It runs completely on your own computer. No text is sent to any outside service and no paid API is used.

> **Read this first.** PromptGuard does not detect every prompt injection attack and does not claim to. All accuracy numbers below come from a **synthetic** dataset plus a small hand-written challenge set. They are good for comparing methods with each other, not for predicting real-world accuracy. Whether any of the four added ideas is new has **not** been established (see "Novelty" below).

## Run it

```bash
pip install -r requirements.txt      # Python 3.10 or newer
python app.py                        # or ./run.sh (Linux/macOS), run.bat (Windows)
# open http://127.0.0.1:5000
```

The server binds to `127.0.0.1` only. A trained model is included (`models/promptguard.joblib`). To rebuild the dataset, retrain and re-run every experiment (this can take several minutes):

```bash
python scripts/build_dataset.py
python scripts/train_and_evaluate.py          # add --quick for a fast, smaller run
python -m pytest -q tests                     # 59 tests
```

The Research Evaluation page and the dashboard read `models/evaluation.json`, so after retraining they show the new numbers automatically.

## What it does

| Stage | What happens | Code |
|---|---|---|
| 1. Input | Paste text or upload TXT, PDF, DOCX, HTML, EML. Files are parsed, never executed. Type, magic bytes, size, zip-bomb and page limits are checked. Hidden (invisible) text in DOCX is kept and flagged. | `extract.py` |
| 2. Preprocess | Invisible characters, tag characters, bidi controls, look-alike (homoglyph) and full-width letters are normalised; leet-speak, spaced letters and separators get a second de-obfuscated view; text is split into sentences. Every character keeps a map back to the original, so highlights land on the exact original text. | `preprocess.py` |
| 3. Rules | About 40 rules in five categories: instruction override, information extraction, role manipulation, unauthorised action, behaviour manipulation, plus English, Spanish, French, German, Hinglish and Hindi phrasing. | `rules.py` |
| 4. Context | The same words are treated differently when quoted, discussed in a security article, prohibited ("never ignore previous instructions"), or written as an instruction to the reader. Every discount is written down as a reason. | `context.py` |
| 5. Machine learning | TF-IDF (word and character n-grams) + Logistic Regression, a context classifier, and a stacking layer that combines all signals. | `ml.py` |
| 6. Risk score | 0 to 100. Bands: 0-29 Low, 30-59 Medium, 60-79 High, 80-100 Critical. The bands are configurable design choices (`config.py`), not scientific values. | `pipeline.py`, `config.py` |
| 7. Explanation | For every finding: what was found, why, which method, how severe, what to do. PDF report with ReportLab. | `pipeline.py`, `report.py` |
| 8. Safe handling | A sanitised *copy* (remove or quarantine) built from the findings you choose, every change listed, then scanned again. The original is never changed. | `sanitize.py` |

Pages: Landing, Dashboard (Overview, New Scan, Scan History, Detection Analytics, Research Evaluation, Settings), New Scan, Results, History (with compare and delete), Research. Scan history lives in SQLite (`instance/`).

## The four added ideas, and how they actually did

You asked for something that has not been made before. I looked: **I cannot honestly claim that.** Related work exists for each idea (next section). What follows is what each idea does on this project's own data, including where it does not help.

1. **Blast radius** (`blast.py`). The same content is scored for a chosen agent profile (chat only, e-mail assistant, coding agent, browsing agent, custom capabilities). Each finding implies an *intent* (send a message, read private data, run code, ...). The module marks each attack path as reachable, blocked, or text-only for that agent, detects the "lethal trifecta" (private data + untrusted content + a way out) and multiplies the content threat by an agent factor. *Status:* works as designed. The multipliers are my own choices and are not validated against real incidents. "Unknown" profile assumes the worst case.
2. **Audience mismatch** (`audience.py`). Text that talks to an AI inside content written for people. *Result:* removing it lowered detection of AI-addressed attacks from 100% to 69% on the synthetic test set and doubled false alarms on security articles (9% to 18%); overall F1 barely moved. Useful, with a small test set.
3. **Style break** (`style.py`). Robust (median/MAD) distance of each sentence from its neighbours. *Result:* weak. The stacker gave it weight 0 and it is not a good document-level verdict (AUC about 0.53-0.64). It does point at the injected sentence: it was the top outlier in about 49% of long test documents versus about 10% by chance. It is kept for localisation only.
4. **Self-attacking fuzzer** (`fuzzer.py`). 14 mutation operators (zero-width characters, look-alike letters, leet, spaced letters, separators, full-width, typos, synonyms, padding, hidden HTML, quote markup, base64, translation). *Result:* it found real gaps in the combined detector: base64-wrapped attacks (100% evasion, because the rule engine sees them but the stacker does not trust them), quote-markup (about 73%: the context discount can be abused), and smaller leaks for typos, synonyms and uncovered translations. Character-level tricks were all caught. Retraining on 3,095 mutants made the detector *worse* (F1 0.852 to 0.769, false-positive rate 8.4% to 15.5%), so **the shipped model is the un-hardened baseline**. The hardened model is saved as `promptguard_hardened.joblib` for inspection.

## Measured results (synthetic data)

Test split: 328 documents (173 malicious), grouped so that templates, topics and attack payloads never cross between train, validation and test.

| Method | Precision | Recall | F1 | False-positive rate | AUC |
|---|---|---|---|---|---|
| Rules, keywords only | 0.68 | 0.73 | 0.70 | 0.39 | 0.67 |
| Rules + context | 0.88 | 0.64 | 0.74 | 0.10 | 0.77 |
| TF-IDF + Logistic Regression | 0.72 | 0.85 | 0.78 | 0.36 | 0.81 |
| Context classifier | 0.85 | 0.71 | 0.77 | 0.14 | 0.81 |
| **Combined (shipped)** | **0.91** | **0.80** | **0.85** | **0.08** | **0.93** |

* The 95% cluster-bootstrap interval for the combined detector's F1 is 0.72 to 0.93, and it overlaps every other method's interval. **F1 alone does not separate the methods; AUC does.**
* On the 70-item **hand-written challenge set** (never used for tuning) the combined detector scored F1 0.77, *below* TF-IDF alone (0.85), with fewer false alarms. The advantage seen on the synthetic test set does not carry over cleanly.
* Paraphrased attacks with no attack keywords are the main weakness: 0% detected at the 0.5 cutoff (they land in the Medium band, so a review threshold of 30 catches about 62% at a higher false-alarm rate).
* If only 5% of documents were attacks, the combined detector's precision would be about 0.33, so most alerts would be false.

Everything is in `models/evaluation.json` and on the Research Evaluation page, including per-kind results, ablation, calibration, errors and fuzz results.

## Things you should know before trusting any of this

* **The dataset is synthetic** (`data/`, built by `scripts/build_dataset.py` from hand-written templates, topics and payload banks). The benign half is deliberately hard (security articles, quoted attacks, ordinary instructions), which inflates the false-positive rate of keyword methods. Real traffic would behave differently. An early version leaked attack phrases across splits and gave inflated scores (F1 0.95); that was found and fixed, and the numbers above are from the fixed version.
* **The evidence floor was added after looking at test errors.** The stacker under-weighted obvious rule matches (a `curl ... | sh` command scored 10). I added a floor (a strong rule match that survives the context check sets a minimum score). It raised test F1 from 0.815 to 0.852 with no change in false positives, but because I chose it after seeing errors, that gain is optimistic. Some challenge-set misses were deliberately *not* fixed so the set stays an honest check.
* **Context is also an attack surface.** Wrapping an attack in quotation marks lowers its score; the fuzzer shows it.
* Sanitising removes what PromptGuard found. It cannot make the rest of a document safe, and the interface says so.
* The scanned text is untrusted. The interface only ever shows it through `textContent`, and the Content-Security-Policy forbids inline scripts and styles. Hidden characters are shown as visible chips, never silently dropped.

## Novelty: what I found and what I could not verify

* Style discontinuity as an injection signal appears in prior work (arXiv 2604.18248).
* The "lethal trifecta" framing and capability-based agent designs (for example CaMeL) already reason about what an injected instruction can reach, so blast radius is a simple, unvalidated cousin of that thinking.
* Evasion of prompt-injection detectors is studied in, for example, arXiv 2504.11168 and arXiv 2602.00750, which overlaps with the fuzzer.
* I did not do a full literature review. Please check these references yourself before citing them, and before calling any part of this a contribution. A safer wording for a report is "candidate contributions, evaluated on synthetic data".

## Using real data

Put your own labelled examples in a CSV with the columns of `data/dataset.csv` (`id`, `text`, `label` 0/1, `kind`, `group`, `split`, `lang`, and `evidence`, the attack sentence for malicious rows, which the sentence-level model and the fuzzer use) and run `python scripts/train_and_evaluate.py`. Keep documents from the same source in the same `group` so they stay in one split. Public prompt-injection datasets can be used the same way; check their licences first.

## Notes

* Fonts (Bricolage Grotesque, Source Serif 4) load from Google Fonts. Offline, the browser falls back to system fonts and everything still works. To avoid the external request, download the fonts into `static/` and change the two lines in `templates/base.html` and the `font-src`/`style-src` entries in `app.py`.
* The brief mentions Chart.js. The charts here are small dependency-free SVG helpers (`static/js/common.js`), which keeps the strict Content-Security-Policy and works offline.
* PDF text extraction uses PyMuPDF if installed, otherwise `pypdf`. Scanned PDFs need OCR first.
* Layout of the code: `app.py` (Flask routes), `promptguard/` (analysis), `templates/` + `static/` (interface), `scripts/`, `data/`, `models/`, `tests/`.
