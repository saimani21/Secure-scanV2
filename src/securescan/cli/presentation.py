from __future__ import annotations

import unicodedata

DEFAULT_TERMINAL_TEXT_LIMIT = 512
MAX_TERMINAL_TEXT_LIMIT = 4_096


def terminal_text(value: object, *, limit: int = DEFAULT_TERMINAL_TEXT_LIMIT) -> str:
    """Render untrusted text without terminal control or direction injection."""

    if type(limit) is not int or not 1 <= limit <= MAX_TERMINAL_TEXT_LIMIT:
        raise ValueError("Terminal text limit is invalid")
    text = str(value)
    rendered: list[str] = []
    used = 0
    truncated = False
    for character in text:
        replacement = _visible_character(character)
        if used + len(replacement) > limit:
            truncated = True
            break
        rendered.append(replacement)
        used += len(replacement)
    if truncated:
        if used == limit:
            rendered[-1:] = ["…"]
        else:
            rendered.append("…")
    return "".join(rendered)


def _visible_character(character: str) -> str:
    codepoint = ord(character)
    if unicodedata.category(character).startswith("C"):
        return f"\\u{codepoint:04x}" if codepoint <= 0xFFFF else f"\\U{codepoint:08x}"
    return character
