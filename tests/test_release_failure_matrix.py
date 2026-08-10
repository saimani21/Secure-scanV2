from __future__ import annotations

import re
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
MATRIX = REPOSITORY_ROOT / "docs" / "core-v0.1-failure-matrix.md"
CHECKLIST = REPOSITORY_ROOT / "RELEASE_CHECKLIST.md"
_TEST_REFERENCE = re.compile(r"`(tests/[^`]+\.py)::(test_[a-zA-Z0-9_]+)`")


def test_failure_matrix_references_existing_test_modules_and_names() -> None:
    matrix = MATRIX.read_text(encoding="utf-8")
    references = _TEST_REFERENCE.findall(matrix)

    assert references
    for relative_module, test_name in references:
        module = REPOSITORY_ROOT / relative_module
        assert module.is_file(), relative_module
        assert re.search(rf"^def {re.escape(test_name)}\(", module.read_text(), re.MULTILINE)


def test_failure_matrix_covers_required_security_invariants() -> None:
    matrix = MATRIX.read_text(encoding="utf-8").lower()
    required_terms = (
        "symlink",
        "hardlink",
        "special file",
        "bounded intake",
        "immutable image",
        "network disabled",
        "non-root",
        "read-only root",
        "read-only source",
        "writable output",
        "bounded output",
        "timeout cleanup",
        "cancellation cleanup",
        "json size bounded",
        "manifest-bound path",
        "analysis gap",
        "deduplicated",
        "stable identity",
        "atomic result commit",
        "fencing",
        "database cleanup",
        "report privacy",
    )

    assert all(term in matrix for term in required_terms)


def test_release_checklist_contains_all_required_commands_and_gates() -> None:
    checklist = CHECKLIST.read_text(encoding="utf-8")
    required = (
        "ruff check .",
        "python -m compileall",
        "pytest",
        "SECURESCAN_REQUIRE_POSTGRES_TESTS=1",
        "SECURESCAN_REQUIRE_DOCKER_TESTS=1",
        "SECURESCAN_REQUIRE_SEMGREP_TESTS=1",
        "SECURESCAN_REQUIRE_RELEASE_TESTS=1",
        "PostgreSQL schema cleanup",
        "Managed-container cleanup",
        "Workspace cleanup",
        "f4a8c2d17b65",
        "No new dependency",
        "No migration",
        "No Git requirement",
        "Backup created",
        "Limitations reviewed",
    )

    assert all(item in checklist for item in required)
    assert checklist.count("- [ ]") >= len(required)
