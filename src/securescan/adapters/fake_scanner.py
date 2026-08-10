from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import sys
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

from securescan.adapters.base import ToolAdapter
from securescan.domain.enums import ObservationType, TargetType
from securescan.domain.models import ExecutionPlan, Observation, OutputValidation, TargetProfile

FAKE_SCHEMA: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "type": "object",
    "required": ["schema_version", "tool", "observations", "warnings"],
    "properties": {
        "schema_version": {"const": "1.0"},
        "tool": {"const": "fake-scanner"},
        "observations": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["rule_id", "message"],
                "properties": {
                    "rule_id": {"type": "string", "minLength": 1},
                    "message": {"type": "string", "minLength": 1},
                    "path": {"type": ["string", "null"]},
                    "line": {"type": ["integer", "null"], "minimum": 1},
                    "severity": {"type": ["string", "null"]},
                    "cwe": {"type": ["string", "null"]},
                },
                "additionalProperties": False,
            },
        },
        "warnings": {"type": "array", "items": {"type": "string"}},
    },
    "additionalProperties": False,
}

_SECRET_PATTERN = re.compile(rb"SECURESCAN_TEST_SECRET=[A-Za-z0-9._-]+")


class FakeScannerAdapter(ToolAdapter):
    adapter_id = "fake-scanner"
    adapter_version = "1.0.0"
    tool_version = "1.0.0"

    def __init__(self, hmac_key: str = "development-only-key") -> None:
        self._hmac_key = hmac_key.encode("utf-8")
        self._validator = Draft202012Validator(FAKE_SCHEMA)

    def probe(self) -> bool:
        return True

    def supports(self, profile: TargetProfile) -> bool:
        return profile.target_type is TargetType.SOURCE_REPOSITORY

    def build_plan(self, profile: TargetProfile, **options: Any) -> ExecutionPlan:
        mode = str(options.get("mode", "findings"))
        timeout_seconds = int(options.get("timeout_seconds", 5))
        max_output_bytes = int(options.get("max_output_bytes", 262_144))
        command = [sys.executable, "-m", "securescan.fake_tool", "--mode", mode]
        if mode == "timeout":
            command.extend(["--seconds", str(options.get("sleep_seconds", 10))])
        if mode == "oversized":
            command.extend(["--bytes", str(options.get("bytes", max_output_bytes * 2))])
        source_root = str(Path(__file__).resolve().parents[2])
        existing_pythonpath = os.environ.get("PYTHONPATH", "")
        pythonpath = (
            source_root
            if not existing_pythonpath
            else f"{source_root}{os.pathsep}{existing_pythonpath}"
        )
        return ExecutionPlan(
            adapter_id=self.adapter_id,
            command=command,
            cwd=profile.path,
            environment={"PYTHONPATH": pythonpath},
            timeout_seconds=timeout_seconds,
            max_output_bytes=max_output_bytes,
        )

    def sanitize(self, native_output: bytes) -> bytes:
        def replacement(match: re.Match[bytes]) -> bytes:
            value = match.group(0).split(b"=", 1)[1]
            digest = hmac.new(self._hmac_key, value, hashlib.sha256).hexdigest()[:16]
            return f"SECURESCAN_TEST_SECRET=[REDACTED:{digest}]".encode()

        return _SECRET_PATTERN.sub(replacement, native_output)

    def validate_output(self, native_output: bytes) -> OutputValidation:
        try:
            payload = json.loads(native_output.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            return OutputValidation(valid=False, error=f"Invalid JSON output: {exc}")

        errors = sorted(self._validator.iter_errors(payload), key=lambda error: list(error.path))
        if errors:
            return OutputValidation(valid=False, error=errors[0].message)

        return OutputValidation(
            valid=True,
            schema_version=payload["schema_version"],
            warnings=list(payload["warnings"]),
        )

    def parse(self, native_output: bytes) -> list[Observation]:
        payload = json.loads(native_output.decode("utf-8"))
        observations: list[Observation] = []
        for item in payload["observations"]:
            observation = Observation(
                producer=self.adapter_id,
                observation_type=ObservationType.TEST_OBSERVATION,
                rule_id=item["rule_id"],
                message=item["message"],
                native_severity=item.get("severity"),
                path=item.get("path"),
                start_line=item.get("line"),
                end_line=item.get("line"),
                cwe_ids=[item["cwe"]] if item.get("cwe") else [],
            )
            observation.fingerprint = self.fingerprint(observation)
            observations.append(observation)
        return observations

    def fingerprint(self, observation: Observation) -> str:
        identity = "\x1f".join(
            [
                self.adapter_id,
                observation.rule_id,
                observation.path or "",
                str(observation.start_line or ""),
                observation.message.strip().lower(),
            ]
        )
        return hashlib.sha256(identity.encode("utf-8")).hexdigest()
