from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from dataclasses import dataclass
from typing import Any

from securescan.source.components import ComponentizedRepositoryInventory
from securescan.source.enums import (
    AnalysisCapability,
    SourceFileFlag,
    SourceFileRole,
    SourceSupportState,
)

_POLICY_STREAM_VERSION = b"securescan-source-support-policy-v0.2.5\0"
_ASSESSMENT_STREAM_VERSION = b"securescan-source-language-support-v0.2.5\0"
_REASON_CODE_PATTERN = re.compile(r"[A-Z][A-Z0-9_]{1,127}\Z", re.ASCII)
_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_MAX_LANGUAGE_CHARACTERS = 100


class SourceSupportPolicyError(RuntimeError):
    """Raised when source support policy evaluation cannot complete."""

    def __init__(self) -> None:
        super().__init__("Source support policy operation failed")


class InvalidSourceSupportPolicyError(SourceSupportPolicyError, ValueError):
    """Raised when a source support policy contract is invalid."""

    def __init__(self) -> None:
        RuntimeError.__init__(self, "Source support policy is invalid")


class SourceSupportCorrelationError(SourceSupportPolicyError):
    """Raised when trusted language facts cannot be correlated safely."""

    def __init__(self) -> None:
        RuntimeError.__init__(self, "Source support correlation failed")


def _valid_language(language: object) -> bool:
    if (
        not isinstance(language, str)
        or language != language.strip()
        or not 1 <= len(language) <= _MAX_LANGUAGE_CHARACTERS
        or any(unicodedata.category(character) == "Cc" for character in language)
    ):
        return False
    try:
        language.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return True


def _valid_reason_code(reason_code: object) -> bool:
    return (
        isinstance(reason_code, str)
        and _REASON_CODE_PATTERN.fullmatch(reason_code) is not None
    )


def _valid_state_and_reason(
    state: object,
    reason_code: object,
) -> bool:
    return (
        isinstance(state, SourceSupportState)
        and (reason_code is None or _valid_reason_code(reason_code))
        and (state is not SourceSupportState.UNSUPPORTED or reason_code is not None)
    )


def _canonical_digest(domain: bytes, data: dict[str, Any]) -> str:
    payload = json.dumps(
        data,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    digest = hashlib.sha256()
    digest.update(domain)
    digest.update(payload)
    return digest.hexdigest()


@dataclass(frozen=True, slots=True)
class LanguageSupportRule:
    language: str
    support_state: SourceSupportState
    reason_code: str | None = None

    def __post_init__(self) -> None:
        if not _valid_language(self.language) or not _valid_state_and_reason(
            self.support_state,
            self.reason_code,
        ):
            raise InvalidSourceSupportPolicyError

    def canonical_data(self) -> dict[str, str | None]:
        return {
            "language": self.language,
            "reason_code": self.reason_code,
            "support_state": self.support_state.value,
        }


@dataclass(frozen=True, slots=True)
class CapabilitySupportRule:
    capability: AnalysisCapability
    support_state: SourceSupportState
    reason_code: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(
            self.capability,
            AnalysisCapability,
        ) or not _valid_state_and_reason(self.support_state, self.reason_code):
            raise InvalidSourceSupportPolicyError

    def canonical_data(self) -> dict[str, str | None]:
        return {
            "capability": self.capability.value,
            "reason_code": self.reason_code,
            "support_state": self.support_state.value,
        }


@dataclass(frozen=True, slots=True, kw_only=True)
class SourceSupportPolicy:
    language_rules: tuple[LanguageSupportRule, ...] = ()
    capability_rules: tuple[CapabilitySupportRule, ...] = ()
    default_language_state: SourceSupportState = SourceSupportState.DETECTED
    default_language_reason_code: str | None = (
        "LANGUAGE_DETECTED_NO_DECLARED_SUPPORT"
    )
    default_capability_state: SourceSupportState = SourceSupportState.DETECTED
    default_capability_reason_code: str | None = (
        "CAPABILITY_DETECTED_NO_DECLARED_SUPPORT"
    )
    schema_version: str = "0.2.5"

    def __post_init__(self) -> None:
        if (
            self.schema_version != "0.2.5"
            or not isinstance(self.language_rules, tuple)
            or any(
                not isinstance(rule, LanguageSupportRule)
                for rule in self.language_rules
            )
            or self.language_rules
            != tuple(
                sorted(
                    self.language_rules,
                    key=lambda rule: rule.language.casefold(),
                )
            )
            or len({rule.language.casefold() for rule in self.language_rules})
            != len(self.language_rules)
            or not isinstance(self.capability_rules, tuple)
            or any(
                not isinstance(rule, CapabilitySupportRule)
                for rule in self.capability_rules
            )
            or self.capability_rules
            != tuple(
                sorted(
                    self.capability_rules,
                    key=lambda rule: rule.capability.value,
                )
            )
            or len({rule.capability for rule in self.capability_rules})
            != len(self.capability_rules)
            or not _valid_state_and_reason(
                self.default_language_state,
                self.default_language_reason_code,
            )
            or not _valid_state_and_reason(
                self.default_capability_state,
                self.default_capability_reason_code,
            )
        ):
            raise InvalidSourceSupportPolicyError

    def canonical_data(self) -> dict[str, Any]:
        return {
            "capability_rules": [
                rule.canonical_data() for rule in self.capability_rules
            ],
            "default_capability_reason_code": (
                self.default_capability_reason_code
            ),
            "default_capability_state": self.default_capability_state.value,
            "default_language_reason_code": self.default_language_reason_code,
            "default_language_state": self.default_language_state.value,
            "language_rules": [
                rule.canonical_data() for rule in self.language_rules
            ],
            "schema_version": self.schema_version,
        }

    def policy_digest(self) -> str:
        return _canonical_digest(_POLICY_STREAM_VERSION, self.canonical_data())

    def language_rule_for(self, language: str) -> LanguageSupportRule:
        if not _valid_language(language):
            raise InvalidSourceSupportPolicyError
        identity = language.casefold()
        for rule in self.language_rules:
            if rule.language.casefold() == identity:
                return rule
        return LanguageSupportRule(
            language=language,
            support_state=self.default_language_state,
            reason_code=self.default_language_reason_code,
        )

    def capability_rule_for(
        self,
        capability: AnalysisCapability,
    ) -> CapabilitySupportRule:
        if not isinstance(capability, AnalysisCapability):
            raise InvalidSourceSupportPolicyError
        for rule in self.capability_rules:
            if rule.capability is capability:
                return rule
        return CapabilitySupportRule(
            capability=capability,
            support_state=self.default_capability_state,
            reason_code=self.default_capability_reason_code,
        )


@dataclass(frozen=True, slots=True)
class RepositoryLanguageDecision:
    language: str
    file_count: int
    source_file_count: int
    generated_file_count: int
    vendored_file_count: int
    test_file_count: int
    support_state: SourceSupportState
    reason_code: str | None = None

    def __post_init__(self) -> None:
        counts = (
            self.source_file_count,
            self.generated_file_count,
            self.vendored_file_count,
            self.test_file_count,
        )
        if (
            not _valid_language(self.language)
            or isinstance(self.file_count, bool)
            or not isinstance(self.file_count, int)
            or self.file_count < 1
            or any(
                isinstance(count, bool)
                or not isinstance(count, int)
                or not 0 <= count <= self.file_count
                for count in counts
            )
            or not _valid_state_and_reason(self.support_state, self.reason_code)
        ):
            raise ValueError("Repository language decision is invalid")

    def canonical_data(self) -> dict[str, str | int | None]:
        return {
            "file_count": self.file_count,
            "generated_file_count": self.generated_file_count,
            "language": self.language,
            "reason_code": self.reason_code,
            "source_file_count": self.source_file_count,
            "support_state": self.support_state.value,
            "test_file_count": self.test_file_count,
            "vendored_file_count": self.vendored_file_count,
        }


@dataclass(frozen=True, slots=True, kw_only=True)
class RepositoryLanguageSupportAssessment:
    repository_digest: str
    languages: tuple[RepositoryLanguageDecision, ...]
    policy_digest: str
    schema_version: str = "0.2.5"

    def __post_init__(self) -> None:
        if (
            self.schema_version != "0.2.5"
            or not isinstance(self.repository_digest, str)
            or _SHA256_PATTERN.fullmatch(self.repository_digest) is None
            or not isinstance(self.policy_digest, str)
            or _SHA256_PATTERN.fullmatch(self.policy_digest) is None
            or not isinstance(self.languages, tuple)
            or any(
                not isinstance(language, RepositoryLanguageDecision)
                for language in self.languages
            )
            or self.languages
            != tuple(
                sorted(
                    self.languages,
                    key=lambda language: language.language.casefold(),
                )
            )
            or len(
                {language.language.casefold() for language in self.languages}
            )
            != len(self.languages)
        ):
            raise ValueError("Repository language support assessment is invalid")

    @property
    def language_count(self) -> int:
        return len(self.languages)

    def canonical_data(self) -> dict[str, Any]:
        return {
            "language_count": self.language_count,
            "languages": [language.canonical_data() for language in self.languages],
            "policy_digest": self.policy_digest,
            "repository_digest": self.repository_digest,
            "schema_version": self.schema_version,
        }

    def assessment_digest(self) -> str:
        return _canonical_digest(
            _ASSESSMENT_STREAM_VERSION,
            self.canonical_data(),
        )


def assess_repository_language_support(
    inventory: ComponentizedRepositoryInventory,
    policy: SourceSupportPolicy,
) -> RepositoryLanguageSupportAssessment:
    if not isinstance(
        inventory,
        ComponentizedRepositoryInventory,
    ) or not isinstance(policy, SourceSupportPolicy):
        raise SourceSupportPolicyError

    counts_by_language: dict[str, dict[str, str | int]] = {}
    for file in inventory.files:
        language = file.language
        if language is None:
            continue
        if not _valid_language(language):
            raise SourceSupportCorrelationError
        identity = language.casefold()
        counts = counts_by_language.get(identity)
        if counts is None:
            counts = {
                "file_count": 0,
                "generated_file_count": 0,
                "language": language,
                "source_file_count": 0,
                "test_file_count": 0,
                "vendored_file_count": 0,
            }
            counts_by_language[identity] = counts
        elif counts["language"] != language:
            raise SourceSupportCorrelationError

        counts["file_count"] += 1
        if file.role is SourceFileRole.SOURCE:
            counts["source_file_count"] += 1
        if SourceFileFlag.GENERATED in file.flags:
            counts["generated_file_count"] += 1
        if SourceFileFlag.VENDORED in file.flags:
            counts["vendored_file_count"] += 1
        if SourceFileFlag.TEST in file.flags:
            counts["test_file_count"] += 1

    decisions: list[RepositoryLanguageDecision] = []
    for identity in sorted(counts_by_language):
        counts = counts_by_language[identity]
        language = counts["language"]
        if not isinstance(language, str):
            raise SourceSupportCorrelationError
        rule = policy.language_rule_for(language)
        decisions.append(
            RepositoryLanguageDecision(
                language=language,
                file_count=int(counts["file_count"]),
                source_file_count=int(counts["source_file_count"]),
                generated_file_count=int(counts["generated_file_count"]),
                vendored_file_count=int(counts["vendored_file_count"]),
                test_file_count=int(counts["test_file_count"]),
                support_state=rule.support_state,
                reason_code=rule.reason_code,
            )
        )

    return RepositoryLanguageSupportAssessment(
        repository_digest=inventory.repository_digest,
        languages=tuple(decisions),
        policy_digest=policy.policy_digest(),
    )
