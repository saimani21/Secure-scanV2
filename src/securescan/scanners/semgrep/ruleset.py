from __future__ import annotations

import hashlib
import os
import re
import secrets
import unicodedata
from dataclasses import dataclass
from importlib.resources import files
from pathlib import Path

from securescan.scanners.semgrep.models import InvalidSemgrepRulesetError

_RULESET_ID_PATTERN = re.compile(r"[a-z][a-z0-9._-]{0,63}\Z", re.ASCII)
_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_MAX_RULESET_BYTES = 2 * 1024 * 1024
_RULES_FILENAME = ".securescan-semgrep-rules.yml"
_RESULTS_FILENAME = "semgrep-results.json"


def _bounded_text(value: object, maximum: int) -> bool:
    return (
        isinstance(value, str)
        and value == value.strip()
        and 1 <= len(value) <= maximum
        and not any(
            unicodedata.category(character).startswith("C") for character in value
        )
    )


@dataclass(frozen=True, slots=True)
class TrustedSemgrepRuleset:
    ruleset_id: str
    display_name: str
    version: str
    content: bytes
    sha256: str

    def __post_init__(self) -> None:
        if (
            not isinstance(self.ruleset_id, str)
            or _RULESET_ID_PATTERN.fullmatch(self.ruleset_id) is None
            or not _bounded_text(self.display_name, 128)
            or not _bounded_text(self.version, 64)
            or not isinstance(self.content, bytes)
            or not 1 <= len(self.content) <= _MAX_RULESET_BYTES
            or b"\0" in self.content
            or not isinstance(self.sha256, str)
            or _SHA256_PATTERN.fullmatch(self.sha256) is None
            or hashlib.sha256(self.content).hexdigest() != self.sha256
        ):
            raise InvalidSemgrepRulesetError

    def materialize(self, output_directory: Path) -> Path:
        try:
            output = output_directory.resolve(strict=True)
            if (
                not output.is_dir()
                or output.is_symlink()
                or output_directory != output
            ):
                raise OSError
            rules_path = output / _RULES_FILENAME
            results_path = output / _RESULTS_FILENAME
            if os.path.lexists(rules_path) or os.path.lexists(results_path):
                raise FileExistsError

            temporary_path = output / f".semgrep-rules-{secrets.token_hex(16)}"
            descriptor = os.open(
                temporary_path,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                0o600,
            )
            try:
                remaining = memoryview(self.content)
                while remaining:
                    written = os.write(descriptor, remaining)
                    if written <= 0:
                        raise OSError
                    remaining = remaining[written:]
                os.fsync(descriptor)
                os.fchmod(descriptor, 0o444)
            finally:
                os.close(descriptor)
            try:
                os.link(temporary_path, rules_path, follow_symlinks=False)
            finally:
                temporary_path.unlink(missing_ok=True)
            if rules_path.stat(follow_symlinks=False).st_nlink != 1:
                rules_path.unlink(missing_ok=True)
                raise OSError
            return rules_path
        except InvalidSemgrepRulesetError:
            raise
        except Exception as exc:
            raise InvalidSemgrepRulesetError from exc


def load_baseline_ruleset() -> TrustedSemgrepRuleset:
    content = (
        files("securescan.scanners.semgrep")
        .joinpath("rules", "securescan-python-baseline-v2.yml")
        .read_bytes()
    )
    return TrustedSemgrepRuleset(
        ruleset_id="securescan-python-baseline-v2",
        display_name="SecureScan Python Baseline v2",
        version="2",
        content=content,
        sha256=hashlib.sha256(content).hexdigest(),
    )


SEMGREP_RULES_FILENAME = _RULES_FILENAME
SEMGREP_RESULTS_FILENAME = _RESULTS_FILENAME
