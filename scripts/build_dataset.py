"""Build the synthetic research dataset with a *grouped* 70/15/15 split.

    python scripts/build_dataset.py

Outputs data/dataset.csv and data/challenge_set.csv.

Grouping: every sample has a ``group`` (a topic or a template). All samples of
one group land in the same split, so a template seen in training never shows
up in validation or test. Context sentences are drawn only from topics that
belong to the same split.
"""
from __future__ import annotations

import csv
import random
import re
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "data"))

import banks as B                       # noqa: E402
from challenge import BENIGN as CH_B, MALICIOUS as CH_M  # noqa: E402
from promptguard import fuzzer          # noqa: E402
from promptguard.config import SEED     # noqa: E402

rng = random.Random(SEED)
rows: list[dict] = []
seen: set[str] = set()


def key(t: str) -> str:
    return re.sub(r"\s+", " ", t.lower())


def add(text: str, label: int, kind: str, group: str, split: str, lang: str = "en", evidence: str = "") -> None:
    text = text.strip()
    k = key(text)
    if not text or k in seen:
        return
    seen.add(k)
    rows.append({"text": text, "label": label, "kind": kind, "group": group, "split": split, "lang": lang,
                 "evidence": evidence.strip() if label == 1 else ""})


PSPLIT: dict[int, dict] = {}
TSPLIT: dict[str, dict] = {}


def pick(seq, split: str):
    """Choose from the part of a phrase bank that belongs to ``split``.

    Payloads, 'act' clauses and quoted attack strings are partitioned across
    train / val / test, so test samples contain attack wording that training
    never saw (not just unseen templates).
    """
    k = id(seq)
    if k not in PSPLIT:
        PSPLIT[k] = assign(range(len(seq)))
    return rng.choice([x for i, x in enumerate(seq) if PSPLIT[k][i] == split])


def pick_template(kind: str, templates, split: str):
    return rng.choice([t for i, t in enumerate(templates) if TSPLIT[kind][i] == split])


def assign(groups) -> dict:
    items = list(groups)
    rng.shuffle(items)
    n = len(items)
    n_test = max(1, round(n * 0.15))
    n_val = max(1, round(n * 0.15))
    return {g: ("test" if i < n_test else "val" if i < n_test + n_val else "train") for i, g in enumerate(items)}


def slots(attacker: bool) -> dict:
    return dict(
        mail=rng.choice(B.MAILS_ATTACKER if attacker else B.MAILS_BENIGN), email=rng.choice(B.MAILS_BENIGN),
        url=rng.choice(B.URLS_ATTACKER if attacker else B.URLS_BENIGN), acct=rng.choice(B.ACCOUNTS),
        brand=rng.choice(B.BRANDS), persona=rng.choice(B.PERSONAS), part=rng.choice(B.PARTS), err=rng.choice(B.ERRS),
        thing=rng.choice(B.THINGS), value=rng.choice(B.VALUES), secret=rng.choice(B.SECRETS), org=rng.choice(B.ORGS),
        doc=rng.choice(B.DOCS), day=rng.choice(B.DAYS), files=rng.choice(B.FILES), cmd=rng.choice(B.CMDS),
        room=rng.choice(B.ROOMS), role=rng.choice(B.ROLES), portal=rng.choice(B.PORTALS), setting=rng.choice(B.SETTINGS),
        os=rng.choice(B.OSES), person=rng.choice(B.PERSONS), item=rng.choice(B.ITEMS), device=rng.choice(B.DEVICES),
        fname=rng.choice(B.FNAMES), time=rng.choice(B.TIMES), amt=rng.choice(B.AMTS), n=rng.randint(100, 999),
    )


def fill(tpl: str, attacker: bool) -> str:
    return tpl.format_map(slots(attacker))


def cap_payload(tpl: str, payload: str) -> str:
    """Capitalise the payload unless it follows a comma in the template."""
    if re.search(r",\s*\{payload\}", tpl):
        return payload
    return payload[0].upper() + payload[1:]


# ------------------------------------------------------------------ splits
topic_split = assign(range(len(B.TOPICS)))
topics_in = {s: [t for t, sp in topic_split.items() if sp == s] for s in ("train", "val", "test")}
lang_names = sorted({l for l, _ in B.MULTILINGUAL_MALICIOUS} | {l for l, _ in B.MULTILINGUAL_BENIGN})
lang_split = assign(lang_names)


def topic_sentences(split: str) -> list[str]:
    return [s for t in topics_in[split] for s in B.TOPICS[t]]


def with_context(core: str, split: str, p: float = 0.55) -> str:
    if rng.random() > p:
        return core
    pool = topic_sentences(split)
    before = " ".join(rng.sample(pool, rng.randint(0, 2)))
    after = " ".join(rng.sample(pool, rng.randint(0, 2)))
    sep = rng.choice([" ", "\n\n", "\n"])
    return sep.join(x for x in (before, core, after) if x)


def ctx2(core: str, split: str, p: float = 0.55) -> tuple[str, str]:
    """Return (text with benign context, the malicious core on its own)."""
    return with_context(core, split, p), core


def template_kind(templates, kind, label, per, builder, prefix="") -> list[tuple[str, str]]:
    """Generate ``per`` samples for every template; returns [(split, group)] pairs."""
    tsplit = assign(range(len(templates)))
    TSPLIT[kind] = tsplit
    for i, tpl in enumerate(templates):
        split = tsplit[i]
        for _ in range(per):
            res = builder(tpl, split)
            text, ev = res if isinstance(res, tuple) else (res, "")
            add(text, label, kind, f"{prefix}{kind}:{i}", split, evidence=ev)
    return list(tsplit.items())


# ================================================================== BENIGN
# plain topics
for t, sp in topic_split.items():
    for _ in range(26):
        k = rng.randint(3, 5)
        start = rng.randint(0, len(B.TOPICS[t]) - k)
        sents = B.TOPICS[t][start:start + k] if rng.random() < 0.6 else rng.sample(B.TOPICS[t], k)
        add(" ".join(sents), 0, "benign_plain", f"topic:{t}", sp)

# benign instructional hard negatives
template_kind(B.BENIGN_IMPERATIVE, "benign_imperative", 0, 7,
              lambda tpl, sp: with_context(fill(tpl, False), sp, 0.45))

# educational discussions that quote attack phrases (hard negatives)
edu_split = assign(range(len(B.EDU_TEMPLATES)))
for i, tpl in enumerate(B.EDU_TEMPLATES):
    for _ in range(12):
        atk = pick(B.ATK_FRAMES, edu_split[i]).format_map(slots(True))
        add(with_context(tpl.format(atk=atk), edu_split[i], 0.4), 0, "benign_educational", f"edu:{i}", edu_split[i])
concept_split = assign(range(len(B.EDU_CONCEPTS)))
for i, c in enumerate(B.EDU_CONCEPTS):
    for _ in range(7):
        others = rng.sample([x for j, x in enumerate(B.EDU_CONCEPTS) if concept_split[j] == concept_split[i] and j != i],
                            k=min(rng.randint(1, 2), max(0, sum(1 for j in range(len(B.EDU_CONCEPTS)) if concept_split[j] == concept_split[i]) - 1)))
        body = " ".join([c] + others)
        add(with_context(body, concept_split[i], 0.4), 0, "benign_educational", f"concept:{i}", concept_split[i])

# quoted attack strings
template_kind(B.QUOTED_TEMPLATES, "benign_quoted", 0, 12,
              lambda tpl, sp: with_context(tpl.format(atk=pick(B.ATK_FRAMES, sp).format_map(slots(True)), n=rng.randint(100, 999)), sp, 0.4))

# benign multilingual
for lang, s in B.MULTILINGUAL_BENIGN:
    for _ in range(3):
        add(with_context(s, lang_split[lang], 0.4), 0, "benign_multilingual", f"lang:{lang}", lang_split[lang], lang)


def long_doc(primary: int, split: str, insert: str | None, form: str = "inline") -> str:
    sents = list(rng.sample(B.TOPICS[primary], rng.randint(6, 9)))
    others = [s for t in topics_in[split] if t != primary for s in B.TOPICS[t]]
    if others:
        sents += rng.sample(others, min(len(others), rng.randint(0, 4)))
    rng.shuffle(sents)
    if insert:
        pos = rng.randint(1, len(sents) - 1)
        if form == "inline":
            sents.insert(pos, insert)
        elif form == "ps":
            sents.append("P.S. " + insert)
        elif form == "comment":
            sents.insert(pos, f"<!-- {insert} -->")
        elif form == "footnote":
            sents.append(f"[1] {insert}")
        elif form == "paragraph":
            sents.insert(pos, "\n\n" + insert + "\n\n")
    out, run = [], 0
    for s in sents:
        out.append(s)
        run += 1
        if run >= rng.randint(3, 4) and "\n\n" not in s:
            out.append("\n\n")
            run = 0
    return re.sub(r"[ ]*\n\n[ ]*", "\n\n", " ".join(out)).replace(" \n\n", "\n\n").strip()


# benign long documents: with a how-to section, a hard negative, or a quoted example
for t, sp in topic_split.items():
    for j in range(11):
        mode = j % 4
        ins = None
        if mode == 1:
            ins = fill(pick_template("benign_imperative", B.BENIGN_IMPERATIVE, sp), False)
        elif mode == 2:
            ins = pick_template("benign_quoted", B.QUOTED_TEMPLATES, sp).format(atk=pick(B.ATK_FRAMES, sp).format_map(slots(True)), n=rng.randint(100, 999))
        elif mode == 3:
            howto = [s for tt in topics_in[sp] for s in B.TOPICS[tt] if s.split()[0] in
                     ("Preheat", "Whisk", "Fold", "Pour", "Bake", "Create", "Run", "Start", "Buy", "Try", "Pack", "Drink", "Stretch", "Let", "Serve", "Talk", "Students")]
            ins = " ".join(rng.sample(howto, min(len(howto), 3))) if howto else None
        add(long_doc(t, sp, ins, rng.choice(["inline", "paragraph"])), 0, "benign_long", f"topic:{t}", sp)

# ================================================================== MALICIOUS
direct_rows: list[dict] = []


def direct_text(opener: str, split: str) -> str:
    pay = pick(B.PAYLOADS, split).format_map(slots(True))
    core = f"{opener} {pay}"
    core = rng.choice(B.PREFIXES) + core + rng.choice(B.SUFFIXES)
    return ctx2(core, split)


osplit = assign(range(len(B.OPENERS)))
for i, op in enumerate(B.OPENERS):
    for _ in range(22):
        txt, ev = direct_text(op, osplit[i])
        add(txt, 1, "mal_direct", f"opener:{i}", osplit[i], evidence=ev)

template_kind(B.ROLE_TEMPLATES, "mal_role", 1, 9,
              lambda tpl, sp: ctx2(rng.choice(B.PREFIXES) + tpl.format_map({**slots(True), "payload": cap_payload(tpl, pick(B.PAYLOADS, sp).format_map(slots(True)))}), sp))
template_kind(B.TOOL_TEMPLATES, "mal_tool", 1, 8,
              lambda tpl, sp: ctx2(rng.choice(B.PREFIXES) + fill(tpl, True) + rng.choice(B.SUFFIXES), sp))
template_kind(B.AUDIENCE_TEMPLATES, "mal_audience", 1, 9,
              lambda tpl, sp: ctx2(fill(tpl, True), sp, 0.7))
template_kind(B.PARAPHRASE_TEMPLATES, "mal_paraphrase", 1, 9,
              lambda tpl, sp: ctx2(tpl.format_map({**slots(True), "act": pick(B.ACTS, sp).format_map(slots(True))}), sp, 0.6))

for lang, s in B.MULTILINGUAL_MALICIOUS:
    for _ in range(3):
        add(with_context(rng.choice(B.PREFIXES) + s, lang_split[lang], 0.5), 1, "mal_multilingual", f"lang:{lang}", lang_split[lang], lang, evidence=s)

# malicious sentence hidden inside a long document
def mal_sentence(sp: str) -> str:
    r = rng.random()
    if r < 0.35:
        ops = [o for i, o in enumerate(B.OPENERS) if osplit[i] == sp]
        return f"{rng.choice(ops)} {pick(B.PAYLOADS, sp)}".format_map(slots(True))
    if r < 0.55:
        return fill(pick_template("mal_tool", B.TOOL_TEMPLATES, sp), True)
    if r < 0.78:
        return fill(pick_template("mal_audience", B.AUDIENCE_TEMPLATES, sp), True)
    return pick_template("mal_paraphrase", B.PARAPHRASE_TEMPLATES, sp).format_map(
        {**slots(True), "act": pick(B.ACTS, sp).format_map(slots(True))})


for t, sp in topic_split.items():
    for j in range(13):
        form = ["inline", "inline", "paragraph", "ps", "comment", "footnote"][j % 6]
        ms = mal_sentence(sp)
        add(long_doc(t, sp, ms, form), 1, "mal_long", f"topic:{t}", sp, evidence=ms)

# obfuscated copies of direct / tool / audience samples (character-level operators)
pool = [r for r in rows if r["kind"] in ("mal_direct", "mal_tool", "mal_audience") and "<!--" not in r["text"]]
for sp in ("train", "val", "test"):
    cands = [r for r in pool if r["split"] == sp]
    for r in rng.sample(cands, round(0.2 * len(cands))):
        ops = rng.sample(fuzzer.CHARACTER_OPS, rng.choice([1, 1, 2]))
        out = fuzzer.compose(r["text"], ops, rng)
        ev = fuzzer.compose(r["evidence"], ops, rng) if r["evidence"] else None
        if out:
            add(out, 1, "mal_obfuscated", r["group"], sp, evidence=ev or r["evidence"])

# ------------------------------------------------------------------ write
out_dir = ROOT / "data"
for i, r in enumerate(rows):
    r["id"] = i + 1
with open(out_dir / "dataset.csv", "w", newline="", encoding="utf-8") as f:
    w = csv.DictWriter(f, fieldnames=["id", "text", "label", "kind", "group", "split", "lang", "evidence"])
    w.writeheader()
    w.writerows(rows)
with open(out_dir / "challenge_set.csv", "w", newline="", encoding="utf-8") as f:
    w = csv.DictWriter(f, fieldnames=["id", "text", "label", "kind"])
    w.writeheader()
    for i, t in enumerate(CH_M):
        w.writerow({"id": i + 1, "text": t, "label": 1, "kind": "challenge_malicious"})
    for i, t in enumerate(CH_B):
        w.writerow({"id": 100 + i + 1, "text": t, "label": 0, "kind": "challenge_benign"})

print(f"{len(rows)} samples -> data/dataset.csv")
by = Counter((r["split"], r["label"]) for r in rows)
for sp in ("train", "val", "test"):
    print(f"  {sp:<5} benign={by[(sp, 0)]:>4}  malicious={by[(sp, 1)]:>4}")
print("by kind:", dict(Counter(r["kind"] for r in rows)))
groups = {}
for r in rows:
    groups.setdefault(r["group"], set()).add(r["split"])
leaky = [g for g, s in groups.items() if len(s) > 1]
print("groups split across more than one set:", len(leaky), leaky[:5])
