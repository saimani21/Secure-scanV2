from __future__ import annotations

import json
import re

from securescan.scanners.semgrep.models import (
    ParsedSemgrepOutput,
    SemgrepOutputMalformedError,
)
from securescan.scanners.semgrep.ruleset import TrustedSemgrepRuleset

_SCHEMA_VERSION = "securescan-semgrep-sanitized-v1"
_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_CWE_ID_PATTERN = re.compile(r"CWE-[1-9][0-9]{0,5}\Z", re.ASCII)
_SEVERITIES = frozenset({"high", "medium", "low", "informational"})


def build_sanitized_semgrep_evidence(
    parsed: ParsedSemgrepOutput,
    *,
    scanner_id: str,
    ruleset: TrustedSemgrepRuleset,
) -> bytes:
    """Build canonical SecureScan-owned evidence from normalized Semgrep facts."""
    if (
        not isinstance(parsed, ParsedSemgrepOutput)
        or not isinstance(scanner_id, str)
        or not scanner_id
        or not isinstance(ruleset, TrustedSemgrepRuleset)
    ):
        raise SemgrepOutputMalformedError

    results: list[dict[str, object]] = []
    for finding in parsed.findings:
        start_column = finding.properties.get("start_column")
        end_column = finding.properties.get("end_column")
        severity = finding.native_severity
        if (
            not isinstance(finding.rule_id, str)
            or not finding.rule_id
            or not isinstance(finding.path, str)
            or not finding.path
            or not isinstance(finding.start_line, int)
            or isinstance(finding.start_line, bool)
            or finding.start_line < 1
            or not isinstance(finding.end_line, int)
            or isinstance(finding.end_line, bool)
            or finding.end_line < 1
            or not isinstance(start_column, int)
            or isinstance(start_column, bool)
            or start_column < 1
            or not isinstance(end_column, int)
            or isinstance(end_column, bool)
            or end_column < 1
            or severity not in _SEVERITIES
            or not isinstance(finding.fingerprint, str)
            or _SHA256_PATTERN.fullmatch(finding.fingerprint) is None
            or any(
                not isinstance(cwe_id, str)
                or _CWE_ID_PATTERN.fullmatch(cwe_id) is None
                for cwe_id in finding.cwe_ids
            )
        ):
            raise SemgrepOutputMalformedError
        results.append(
            {
                "end": {"column": end_column, "line": finding.end_line},
                "fingerprint": finding.fingerprint,
                "metadata": {"cwe": list(finding.cwe_ids)},
                "path": finding.path,
                "rule_id": finding.rule_id,
                "severity": severity,
                "start": {"column": start_column, "line": finding.start_line},
            }
        )

    document = {
        "results": results,
        "ruleset": {"id": ruleset.ruleset_id, "version": ruleset.version},
        "scanner_id": scanner_id,
        "schema_version": _SCHEMA_VERSION,
        "summary": {
            "accepted_findings": parsed.accepted_result_count,
            "analysis_gaps": len(parsed.analysis_gaps),
            "duplicate_findings": parsed.duplicate_result_count,
            "rejected_findings": parsed.rejected_result_count,
        },
    }
    try:
        return json.dumps(
            document,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise SemgrepOutputMalformedError from exc
