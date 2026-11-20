"""Stage 2: text preprocessing.

The key idea is that every normalised *view* of the text keeps a character
map back to the original text. Rules run on the cleaned views, but findings
are highlighted at their exact position in what the user submitted.

Views
-----
norm   : NFKC, invisible characters removed, mixed-script homoglyphs folded,
         whitespace collapsed.
deobf  : norm + leetspeak folded, spaced-out letters re-joined, separators
         inside words removed. Used only to *find* obfuscated text.
"""
from __future__ import annotations

import bisect
import re
import unicodedata
from dataclasses import dataclass, field

ZERO_WIDTH = set("​‌‍⁠⁡⁢⁣⁤﻿­᠎‎‏")
BIDI = set("‪‫‬‭‮⁦⁧⁨⁩")

# Cyrillic / Greek look-alikes -> Latin. Only folded inside words that already
# mix Latin letters with these characters, so genuine Russian or Greek text is
# left alone.
HOMOGLYPHS = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x",
    "і": "i", "ѕ": "s", "ј": "j", "ԁ": "d", "һ": "h", "ԛ": "q", "ѵ": "v",
    "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M", "Н": "H", "О": "O",
    "Р": "P", "С": "C", "Т": "T", "Х": "X", "І": "I", "Ѕ": "S", "Ј": "J",
    "ο": "o", "ν": "v", "ι": "i", "α": "a", "ρ": "p", "τ": "t", "υ": "u",
    "Α": "A", "Β": "B", "Ε": "E", "Ζ": "Z", "Η": "H", "Ι": "I", "Κ": "K",
    "Μ": "M", "Ν": "N", "Ο": "O", "Ρ": "P", "Τ": "T", "Υ": "Y", "Χ": "X",
}

LEET = {"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s", "!": "i", "|": "i"}

# Words used to re-segment spaced-out letters ("i g n o r e  a l l ...").
_LEXICON = sorted(
    {
        "ignore", "disregard", "forget", "override", "previous", "prior", "earlier", "above",
        "all", "any", "instructions", "instruction", "rules", "prompt", "system", "reveal",
        "secret", "confidential", "password", "send", "now", "you", "your", "are", "the",
        "and", "to", "new", "from", "act", "as", "dan", "print", "show", "hidden", "output",
        "do", "not", "tell", "user", "email", "everything", "follow", "these", "instead",
    },
    key=len,
    reverse=True,
)

_SPACED_RE = re.compile(r"(?<![A-Za-z])(?:[A-Za-z][ \-_.*]){4,}[A-Za-z](?![A-Za-z])")
_INTRA_SEP_RE = re.compile(r"(?<=[A-Za-z])[\-_.*·•](?=[A-Za-z])")
_LEET_TOKEN_RE = re.compile(r"[A-Za-z0-9@$|][A-Za-z0-9@$!|]*")
_FENCE_RE = re.compile(r"```.*?```", re.S)
_ABBREV = {"dr", "mr", "mrs", "ms", "vs", "etc", "e.g", "i.e", "fig", "no", "st", "prof", "inc", "ltd", "approx"}
_SENT_RE = re.compile(r"[.!?…][\"')\]”’]*\s+(?=[A-Z0-9\"'(\[#>*•\-“‘<])")


@dataclass
class View:
    text: str
    map: list[int]

    def to_orig(self, s: int, e: int) -> tuple[int, int]:
        """Map a [s, e) span in this view back to the original text."""
        if not self.map:
            return 0, 0
        s = max(0, min(s, len(self.map) - 1))
        e = max(s + 1, min(e, len(self.map)))
        return self.map[s], self.map[e - 1] + 1


@dataclass
class Segment:
    id: int
    para: int
    start: int          # original-text offsets
    end: int
    text: str           # original slice (for display)
    norm: str           # normalised text (for analysis)
    nstart: int         # offsets inside the norm view
    nend: int


@dataclass
class Doc:
    original: str
    norm: View
    deobf: View
    segments: list[Segment]
    flags: dict[str, list[int]]
    fences: list[tuple[int, int]] = field(default_factory=list)  # code-fence spans (norm offsets)
    _starts: list[int] = field(default_factory=list)

    def seg_at(self, orig_pos: int) -> int:
        """Index of the segment containing an original-text offset."""
        if not self._starts:
            return 0
        i = bisect.bisect_right(self._starts, orig_pos) - 1
        return max(0, min(i, len(self.segments) - 1))

    def word_count(self) -> int:
        return len(re.findall(r"\w+", self.norm.text))


def _initial_pairs(text: str, flags: dict[str, list[int]]) -> list[tuple[str, int]]:
    pairs: list[tuple[str, int]] = []
    n = len(text)
    for i, ch in enumerate(text):
        cp = ord(ch)
        if ch in ZERO_WIDTH:
            prev = text[i - 1] if i > 0 else ""
            nxt = text[i + 1] if i + 1 < n else ""
            # soft hyphens and direction marks are common in PDFs and RTL text: strip, don't flag
            if (ch in "​‌‍⁠﻿"
                    and prev.isascii() and prev.isalpha() and nxt.isascii() and nxt.isalpha()):
                flags["zero_width_in_word"].append(i)
            continue
        if ch in BIDI:
            flags["bidi"].append(i)
            continue
        if 0xE0000 <= cp <= 0xE007F:  # Unicode "tag" block: invisible ASCII smuggling
            flags["tag_chars"].append(i)
            if 0xE0020 <= cp <= 0xE007E:
                pairs.append((chr(cp - 0xE0000), i))
            continue
        if unicodedata.category(ch) == "Cc" and ch not in "\n\t\r":
            continue
        if 0xFF21 <= cp <= 0xFF5A:  # full-width Latin letters
            flags["fullwidth"].append(i)
        for c in unicodedata.normalize("NFKC", ch):
            pairs.append((c, i))
    return pairs


def _fold_homoglyphs(pairs: list[tuple[str, int]], flags: dict[str, list[int]]) -> list[tuple[str, int]]:
    s = "".join(c for c, _ in pairs)
    chars = [c for c, _ in pairs]
    for m in re.finditer(r"\w+", s):
        tok = m.group()
        if any(c.isascii() and c.isalpha() for c in tok) and any(c in HOMOGLYPHS for c in tok):
            flags["homoglyph"].append(pairs[m.start()][1])
            for k in range(m.start(), m.end()):
                chars[k] = HOMOGLYPHS.get(chars[k], chars[k])
    return [(chars[k], pairs[k][1]) for k in range(len(pairs))]


def _collapse_ws(pairs: list[tuple[str, int]]) -> list[tuple[str, int]]:
    out: list[tuple[str, int]] = []
    for c, i in pairs:
        if c == "\r":
            continue
        if c.isspace() and c != "\n":
            if out and out[-1][0] in (" ", "\n"):
                continue
            out.append((" ", i))
        elif c == "\n":
            if out and out[-1][0] == " ":
                out.pop()
            out.append(("\n", i))
        else:
            out.append((c, i))
    while out and out[-1][0] in " \n":
        out.pop()
    while out and out[0][0] in " \n":
        out.pop(0)
    return out


def _view(pairs: list[tuple[str, int]]) -> View:
    return View("".join(c for c, _ in pairs), [i for _, i in pairs])


def _deobfuscate(norm: View) -> View:
    chars = list(norm.text)
    mp = list(norm.map)
    s = norm.text

    # 1. leetspeak inside tokens that also contain letters
    for m in _LEET_TOKEN_RE.finditer(s):
        end = m.end()
        while end > m.start() and s[end - 1] in "!$|@":
            end -= 1
        tok = s[m.start():end]
        letters = sum(c.isalpha() for c in tok)
        if letters >= 2 and any(c in LEET for c in tok) and not tok.isdigit():
            for k in range(m.start(), end):
                if chars[k] in LEET:
                    chars[k] = LEET[chars[k]]

    # 2. spaced-out letters: "i g n o r e  a l l" -> "ignore all"
    s = "".join(chars)
    out_c: list[str] = []
    out_m: list[int] = []
    last = 0
    for m in _SPACED_RE.finditer(s):
        out_c.extend(chars[last:m.start()])
        out_m.extend(mp[last:m.start()])
        letters = [(chars[k], mp[k]) for k in range(m.start(), m.end()) if chars[k].isalpha()]
        joined = "".join(c.lower() for c, _ in letters)
        j = 0
        while j < len(letters):
            hit = next((w for w in _LEXICON if joined.startswith(w, j)), None)
            if hit:
                for k in range(len(hit)):
                    out_c.append(letters[j + k][0])
                    out_m.append(letters[j + k][1])
                out_c.append(" ")
                out_m.append(letters[j + len(hit) - 1][1])
                j += len(hit)
            else:
                out_c.append(letters[j][0])
                out_m.append(letters[j][1])
                j += 1
        last = m.end()
    out_c.extend(chars[last:])
    out_m.extend(mp[last:])

    # 3. separators inside words: "ig-nore" -> "ignore"
    s = "".join(out_c)
    drop = {m.start() for m in _INTRA_SEP_RE.finditer(s)}
    final_c = [c for k, c in enumerate(out_c) if k not in drop]
    final_m = [x for k, x in enumerate(out_m) if k not in drop]
    return View("".join(final_c), final_m)


def _segment(norm: View) -> list[Segment]:
    text = norm.text
    segs: list[Segment] = []
    para = 0
    prev_end = 0
    for line_m in re.finditer(r"[^\n]+", text):
        ls, line = line_m.start(), line_m.group()
        if ls > 0 and text.count("\n", prev_end, ls) >= 2:
            para += 1
        prev_end = line_m.end()
        bounds = [0]
        for m in _SENT_RE.finditer(line):
            before = line[:m.start() + 1].rsplit(None, 1)
            last_tok = before[-1].lower().rstrip(".") if before else ""
            if last_tok in _ABBREV:
                continue
            bounds.append(m.end())
        bounds.append(len(line))
        for a, b in zip(bounds, bounds[1:]):
            piece = line[a:b]
            lead = len(piece) - len(piece.lstrip())
            piece_s = piece.strip()
            if not piece_s:
                continue
            ns = ls + a + lead
            ne = ns + len(piece_s)
            os_, oe = norm.to_orig(ns, ne)
            segs.append(Segment(len(segs), para, os_, oe, "", piece_s, ns, ne))
    return segs


def preprocess(text: str) -> Doc:
    """Normalise ``text`` and split it into position-preserving segments."""
    text = text.lstrip("﻿")
    flags: dict[str, list[int]] = {
        "zero_width_in_word": [], "bidi": [], "tag_chars": [], "homoglyph": [], "fullwidth": [],
    }
    pairs = _initial_pairs(text, flags)
    pairs = _fold_homoglyphs(pairs, flags)
    pairs = _collapse_ws(pairs)
    norm = _view(pairs)
    deobf = _deobfuscate(norm)
    segs = _segment(norm)
    for s in segs:
        s.text = text[s.start:s.end]
    fences = [(m.start(), m.end()) for m in _FENCE_RE.finditer(norm.text)]
    doc = Doc(text, norm, deobf, segs, flags, fences)
    doc._starts = [s.start for s in segs]
    return doc
