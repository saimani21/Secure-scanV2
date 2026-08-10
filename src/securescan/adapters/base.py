from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from securescan.domain.models import (
    ExecutionPlan,
    Observation,
    OutputValidation,
    TargetProfile,
)


class ToolAdapter(ABC):
    adapter_id: str
    adapter_version: str
    tool_version: str

    @abstractmethod
    def probe(self) -> bool:
        """Return whether the tool is available in the current environment."""

    @abstractmethod
    def supports(self, profile: TargetProfile) -> bool:
        """Return whether the adapter supports the target profile."""

    @abstractmethod
    def build_plan(self, profile: TargetProfile, **options: Any) -> ExecutionPlan:
        """Build an immutable execution plan using argument arrays, never shell strings."""

    @abstractmethod
    def sanitize(self, native_output: bytes) -> bytes:
        """Remove sensitive values before persistence."""

    @abstractmethod
    def validate_output(self, native_output: bytes) -> OutputValidation:
        """Validate the tool-native output contract."""

    @abstractmethod
    def parse(self, native_output: bytes) -> list[Observation]:
        """Convert validated native output into direct observations."""

    @abstractmethod
    def fingerprint(self, observation: Observation) -> str:
        """Create a tool-specific stable observation identity."""
