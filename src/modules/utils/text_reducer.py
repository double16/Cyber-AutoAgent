from __future__ import annotations

import re
from dataclasses import dataclass
from difflib import SequenceMatcher
from typing import Iterable, List, Tuple

_TAG_RE = re.compile(r"^\s*\[(?P<tag>[A-Z_]+)\]\s*")
_WS_RE = re.compile(r"\s+")
_WORD_RE = re.compile(r"\w+")
_URL_RE = re.compile(r"https?://\S+")


def collapse_first_repeated_sequence(s: str) -> str:
    """
    Remove duplicate sequences at the beginning of a string.
    Example:
        This is a duplicate. This is a duplicate. This is a duplicate. This is a duplicate.
        ->
        This is a duplicate.
    """
    # Tokenize words and keep spans into original string
    words: List[str] = []
    spans: List[Tuple[int, int]] = []
    for m in _WORD_RE.finditer(s):
        words.append(m.group(0))
        spans.append((m.start(), m.end()))
    n = len(words)
    if n < 2:
        return s

    # Find first immediately repeated block starting at i of size k
    for i in range(n - 1):
        max_k = (n - i) // 2
        for k in range(1, max_k + 1):
            block = words[i:i + k]
            # Must repeat immediately
            if words[i + k:i + 2 * k] != block:
                continue
            # And from i to the end, it must be *only* repetitions of block
            tail = words[i:]
            if len(tail) % k != 0:
                continue
            reps = len(tail) // k
            if all(tail[j * k:(j + 1) * k] == block for j in range(reps)):
                # OK to collapse: keep prefix + one copy of the block (+ its trailing punctuation)
                end = spans[i + k - 1][1]
                j = end
                # include trailing punctuation directly after the block (stop at whitespace or word char/_)
                while j < len(s) and not s[j].isspace() and not s[j].isalnum() and s[j] != '_':
                    j += 1
                return s[:j]
            # Otherwise, unrepeated words exist at the end → do not dedupe
            return s
    return s


# Helper: split into logical "lines" or units (prefer lines, fallback to punctuation for long blobs)
def _split_into_units(text: str, *, long_line_threshold: int = 600, few_lines_threshold: int = 3) -> List[str]:
    """Split input into logical 'lines'.

    Prefer existing line breaks. If the input is only a few very long lines,
    split by sentence-ending punctuation (. ! ?) instead.

    IMPORTANT: Do not split on bracket tags like [OBSERVATION]; they do not imply line breaks.
    """
    # First, respect explicit line breaks.
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    if not lines:
        return []

    # If we only have a few very long lines, treat it as a blob and split by punctuation.
    if len(lines) <= few_lines_threshold and any(len(ln) >= long_line_threshold for ln in lines):
        blob = " ".join(lines)
        # Avoid splitting inside URLs by collapsing them first.
        blob = _URL_RE.sub("<url>", blob)
        parts = re.split(r"(?<=[.!?])\s+|(?<=[;:])\s+(?=(?:\[|[A-Z0-9]))", blob)
        return [p.strip() for p in parts if p and p.strip()]

    return lines


def _normalize(s: str) -> str:
    s = s.strip()
    # Fix common malformed tag prefix like: "OBSERVATION] ..." -> "[OBSERVATION] ..."
    if re.match(r"^[A-Z_]+\]\s+", s) and not s.startswith("["):
        s = "[" + s
    s = s.lower()
    s = _WS_RE.sub(" ", s)
    # Normalize obvious tokens like URLs/hosts/ports to reduce false uniqueness
    s = re.sub(r"https?://\S+", "<url>", s)
    s = re.sub(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", "<ip>", s)
    s = re.sub(r"\b\d{2,5}\b", "<num>", s)
    return s


def _tokens(s: str) -> List[str]:
    s = _normalize(s)
    # Keep words and a few meaningful symbols
    return re.findall(r"[a-z0-9_<>]+", s)


def _jaccard(a: List[str], b: List[str]) -> float:
    sa, sb = set(a), set(b)
    if not sa and not sb:
        return 1.0
    if not sa or not sb:
        return 0.0
    return len(sa & sb) / len(sa | sb)


def _similarity(a: str, b: str) -> float:
    # "Loose uniqueness": max of token overlap and character-level similarity
    ta, tb = _tokens(a), _tokens(b)
    jac = _jaccard(ta, tb)
    seq = SequenceMatcher(None, _normalize(a), _normalize(b)).ratio()
    return max(jac, seq)


def _tag(line: str) -> str:
    m = _TAG_RE.match(line.strip())
    return (m.group("tag") if m else "").upper()


def _priority(line: str) -> int:
    """
    Higher wins when two lines are near-duplicates.
    Tune priorities as needed.
    """
    t = _tag(line)
    if t == "CRITICAL":
        return 100
    if t == "HIGH":
        return 90
    if t == "OBSERVATION":
        return 50
    return 10


@dataclass
class ReduceResult:
    kept_lines: List[str]
    removed_count: int

    def to_text(self) -> str:
        return "\n".join(self.kept_lines)


def reduce_lines_lossy(
        text: str,
        *,
        similarity_threshold: float = 0.86,
        max_lines: int | None = None,
        keep_last_if_tagged: bool = True,
) -> ReduceResult:
    """
    Reduce near-duplicate lines using a "loose uniqueness" score.

    - Keeps higher-priority lines ([CRITICAL] > [OBSERVATION] > untagged).
    - Treats lines as duplicates if similarity >= similarity_threshold.
    - If max_lines is set, will keep the most "unique" lines until that limit.

    Returns ReduceResult with kept_lines and removed_count.

    Example:
    result = reduce_lines_loose(text_blob, similarity_threshold=0.88, max_lines=8)
    print(result.to_text())
    print("Removed:", result.removed_count)
    """
    raw_lines = [ln.rstrip() for ln in _split_into_units(text)]
    if not raw_lines:
        return ReduceResult([], 0)

    # Optionally protect a tagged "summary" line at the end
    protected_last: str | None = None
    if keep_last_if_tagged and _tag(raw_lines[-1]):
        protected_last = raw_lines.pop()

    kept: List[str] = []
    removed = 0

    def add_or_replace(line: str) -> None:
        nonlocal removed
        for i, existing in enumerate(kept):
            if _similarity(line, existing) >= similarity_threshold:
                # Near-duplicate: keep the better one
                if _priority(line) > _priority(existing) or len(line) > len(existing):
                    kept[i] = line
                removed += 1
                return
        kept.append(line)

    for ln in raw_lines:
        add_or_replace(ln)

    # Re-append protected last line if it isn't a near-duplicate of something kept
    if protected_last is not None:
        dup = any(_similarity(protected_last, k) >= similarity_threshold for k in kept)
        if not dup:
            kept.append(protected_last)
        else:
            removed += 1

    # If caller wants a hard cap, keep the most unique set (greedy)
    if max_lines is not None and len(kept) > max_lines:
        # Sort by priority first so important items are seeded
        candidates = sorted(kept, key=lambda s: (-_priority(s), -len(s)))
        selected: List[str] = []
        for c in candidates:
            if len(selected) >= max_lines:
                break
            if not selected:
                selected.append(c)
                continue
            # Require it to be "different enough" from everything selected
            if all(_similarity(c, s) < similarity_threshold for s in selected):
                selected.append(c)
        # If we still didn't hit max_lines (rare), fill remaining by priority
        if len(selected) < max_lines:
            for c in candidates:
                if len(selected) >= max_lines:
                    break
                if c not in selected:
                    selected.append(c)
        removed += (len(kept) - len(selected))
        kept = selected

    return ReduceResult(kept_lines=kept, removed_count=removed)
