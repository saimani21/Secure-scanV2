from __future__ import annotations

import re
from collections.abc import Iterable

_CVE = re.compile(r"CVE-[0-9]{4}-[0-9]{4,19}\Z", re.ASCII)


def validate_cve_id(value: object) -> str:
    """Return an exact canonical CVE identity or reject it without coercion."""

    if not isinstance(value, str) or _CVE.fullmatch(value) is None:
        raise ValueError("invalid CVE identity")
    return value


def exact_cve_aliases(aliases: Iterable[object]) -> tuple[str, ...]:
    """Select only exact CVEs supplied by the authoritative OSV aliases field."""

    if isinstance(aliases, (str, bytes)):
        raise ValueError("OSV aliases must be a collection")
    result = set()
    for alias in aliases:
        try:
            result.add(validate_cve_id(alias))
        except ValueError:
            continue
    return tuple(sorted(result))
