from __future__ import annotations

import re
import shlex
from typing import List

from .models import NormalizedCommand, Segment


_CHAIN_SPLIT = re.compile(r"(\|\||&&|;|\||\bthen\b|\bdo\b)")


def _split_pipeline(raw: str) -> List[str]:
    parts: List[str] = []
    buf = []
    i = 0
    in_single = False
    in_double = False
    while i < len(raw):
        ch = raw[i]
        if ch == "'" and not in_double:
            in_single = not in_single
            buf.append(ch)
            i += 1
            continue
        if ch == '"' and not in_single:
            in_double = not in_double
            buf.append(ch)
            i += 1
            continue
        if not in_single and not in_double:
            two = raw[i:i+2]
            if two in ("&&", "||"):
                parts.append("".join(buf).strip())
                buf = []
                i += 2
                continue
            if ch in "|;\n":
                parts.append("".join(buf).strip())
                buf = []
                i += 1
                continue
        buf.append(ch)
        i += 1
    tail = "".join(buf).strip()
    if tail:
        parts.append(tail)
    return [p for p in parts if p]


def normalize(raw: str) -> NormalizedCommand:
    raw = raw.strip()
    parts = _split_pipeline(raw)

    segments: List[Segment] = []
    for p in parts:
        try:
            tokens = shlex.split(p, posix=True)
        except ValueError:
            tokens = p.split()
        segments.append(Segment(raw=p, tokens=tokens))

    has_pipe = "|" in raw and not _is_pipe_only_in_quotes(raw)
    has_chain = "&&" in raw or "||" in raw or ";" in raw
    has_cmd_sub = bool(re.search(r"\$\(", raw)) or bool(re.search(r"`[^`]+`", raw)) or "<(" in raw

    return NormalizedCommand(
        raw=raw,
        segments=segments,
        has_pipe=has_pipe,
        has_chain=has_chain,
        has_command_substitution=has_cmd_sub,
    )


def _is_pipe_only_in_quotes(raw: str) -> bool:
    in_single = False
    in_double = False
    for ch in raw:
        if ch == "'" and not in_double:
            in_single = not in_single
        elif ch == '"' and not in_single:
            in_double = not in_double
        elif ch == "|" and not in_single and not in_double:
            return False
    return True
