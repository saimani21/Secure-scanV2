from __future__ import annotations

import re
from dataclasses import dataclass
from typing import TYPE_CHECKING

from securescan.domain.models import AnalysisGap, Observation

if TYPE_CHECKING:
    from securescan.scanners.semgrep.ruleset import TrustedSemgrepRuleset

_SAFE_BASENAME_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z", re.ASCII)
_MEBIBYTE = 1024 * 1024


class SemgrepAdapterError(RuntimeError):
    """Base class for fixed-message Semgrep failures."""


class InvalidSemgrepRulesetError(SemgrepAdapterError, ValueError):
    def __init__(self) -> None:
        super().__init__("Trusted Semgrep ruleset is invalid")


class InvalidSemgrepScanPlanError(SemgrepAdapterError, ValueError):
    def __init__(self) -> None:
        super().__init__("Trusted Semgrep scan plan is invalid")


class SemgrepExecutionError(SemgrepAdapterError):
    def __init__(self) -> None:
        super().__init__("Semgrep sandbox execution failed")


class SemgrepOutputMissingError(SemgrepAdapterError):
    def __init__(self) -> None:
        super().__init__("Semgrep result output is missing")


class SemgrepOutputTooLargeError(SemgrepAdapterError):
    def __init__(self) -> None:
        super().__init__("Semgrep result output exceeded its size limit")


class SemgrepOutputMalformedError(SemgrepAdapterError):
    def __init__(self) -> None:
        super().__init__("Semgrep result output is malformed")


class SemgrepFindingNormalizationError(SemgrepAdapterError):
    def __init__(self) -> None:
        super().__init__("Semgrep finding could not be normalized")


class SemgrepWorkspaceCleanupError(SemgrepAdapterError):
    def __init__(self) -> None:
        super().__init__("Semgrep workspace could not be removed")


@dataclass(frozen=True, slots=True)
class SemgrepScanPlan:
    ruleset: TrustedSemgrepRuleset
    result_filename: str = "semgrep-results.json"
    maximum_result_bytes: int = 33_554_432
    maximum_findings: int = 100_000

    def __post_init__(self) -> None:
        from securescan.scanners.semgrep.ruleset import TrustedSemgrepRuleset

        filename = self.result_filename
        if (
            not isinstance(self.ruleset, TrustedSemgrepRuleset)
            or not isinstance(filename, str)
            or filename != "semgrep-results.json"
            or _SAFE_BASENAME_PATTERN.fullmatch(filename) is None
            or filename in {".", ".."}
            or "/" in filename
            or "\\" in filename
            or not isinstance(self.maximum_result_bytes, int)
            or isinstance(self.maximum_result_bytes, bool)
            or not _MEBIBYTE <= self.maximum_result_bytes <= 256 * _MEBIBYTE
            or not isinstance(self.maximum_findings, int)
            or isinstance(self.maximum_findings, bool)
            or not 1 <= self.maximum_findings <= 1_000_000
        ):
            raise InvalidSemgrepScanPlanError


@dataclass(frozen=True, slots=True)
class ParsedSemgrepOutput:
    findings: tuple[Observation, ...]
    analysis_gaps: tuple[AnalysisGap, ...]
    raw_result_count: int
    accepted_result_count: int
    rejected_result_count: int
    duplicate_result_count: int
    semgrep_error_count: int
    output_version: str | None
