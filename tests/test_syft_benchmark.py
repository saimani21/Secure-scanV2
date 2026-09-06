from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import pytest

from securescan.benchmarks.syft_inventory import (
    build_controlled_report,
    canonical_json,
    corpus_identity,
)
from securescan.scanners.syft import (
    SYFT_CONFIG_SHA256,
    SYFT_EXECUTABLE_SHA256,
    canonical_syft_binding_artifact,
    canonical_syft_contract,
    create_default_syft_binding,
)

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "benchmarks/syft/controlled-s1-evidence.json"
BINDING = ROOT / "benchmarks/syft/syft-binding-v1.json"
CONTRACT = ROOT / "benchmarks/syft/contract-v1.json"


def test_controlled_evidence_is_sanitized_and_frozen() -> None:
    payload = EVIDENCE.read_bytes()
    document = json.loads(payload)
    assert document["schema_version"] == "securescan-syft-controlled-evidence-s1"
    assert document["package_count"] == 10
    assert document["package_type_counts"] == {"go-module": 1, "npm": 2, "python": 7}
    assert document["zero_package_fixture"] == {"completed": True, "package_count": 0}
    assert document["repeatability"] == {
        "normalized_structural_evidence_equal": True,
        "runs": 2,
    }
    assert document["maturity_recommendation"] == "scannable"
    assert hashlib.sha256(payload).hexdigest() == (
        "ec1dad7520c99cae66cdfb0de0100fc895576356ad917da30dcceba805ed2bc4"
    )
    forbidden = (b"/home/", b"/tmp/", b'"metadata"', b'"stdout"', b'"stderr"')
    assert not any(value in payload for value in forbidden)


def test_corpus_identity_and_fixture_scope_are_frozen() -> None:
    digest, paths = corpus_identity(ROOT / "benchmarks/syft/corpus")
    assert digest == "e7689c1b63cd6826cf15c0f732972ddfd57b8e70d725e657792be74e5fa81293"
    assert ".syft.yaml" in paths
    assert "empty/.keep" in paths
    assert "python/requirements.txt" in paths
    assert "python/poetry.lock" in paths
    assert "npm/package-lock.json" in paths
    assert "go/go.mod" in paths
    assert "scope/vendor/requirements.txt" in paths
    assert "near-miss/requirements.txt.bak" in paths


def test_binding_artifact_is_canonical_and_has_no_runtime_path() -> None:
    payload = BINDING.read_bytes()
    document = json.loads(payload)
    assert document["scanner_id"] == "syft"
    assert document["scanner_version"] == "1.51.0"
    assert document["execution"]["mode"] == "directory"
    assert document["process"]["inner_timeout_seconds"] is None
    assert document["process"]["outer_timeout_seconds"] == 300
    assert document["process"]["stdout_limit_bytes"] == 100 * 1024 * 1024
    assert document["configuration"]["network_enrichment"] is False
    assert document["configuration"]["network_requested"] is False
    assert document["configuration"]["os_egress_sandbox"] is False
    assert document["normalization"]["purl"] == {
        "distribution": "packageurl-python",
        "version": "0.17.6",
    }
    assert document["claims"]["vulnerability_or_cve"] is False
    assert b"/home/" not in payload
    assert b"/tmp/" not in payload
    assert hashlib.sha256(payload).hexdigest() == (
        "d71c73832a8c3104b67e2fc2a81d186a94bc59f6a8d2a07dfd3d5a1bca0cd155"
    )


def test_s1_contract_freezes_inventory_only_claims() -> None:
    payload = CONTRACT.read_bytes()
    document = json.loads(payload)
    assert document["capability"] == "package_inventory"
    assert document["claims"] == {
        "dependency_semantics": False,
        "inventory_current_snapshot": True,
        "reachability": False,
        "vulnerability_or_cve": False,
    }
    assert document["support_state"] == "scannable"
    assert document["execution"]["inner_timeout_seconds"] is None
    assert document["execution"]["outer_timeout_seconds"] == 300
    assert document["execution"]["stdout_limit_bytes"] == 100 * 1024 * 1024
    assert document["normalization"]["purl"] == {
        "distribution": "packageurl-python",
        "version": "0.17.6",
    }
    assert hashlib.sha256(payload).hexdigest() == (
        "d84eff7a0f2ba5b3fc88370e0f7a64811abf320577e7e089c4a804afdc64974c"
    )


def test_static_s1_evidence_chain_replays_without_executing_syft() -> None:
    binding = create_default_syft_binding((ROOT / ".venv-syft-1.51/bin/syft").resolve())
    binding_document = json.loads(BINDING.read_bytes())
    contract_document = json.loads(CONTRACT.read_bytes())
    evidence_document = json.loads(EVIDENCE.read_bytes())
    assert BINDING.read_bytes() == canonical_syft_binding_artifact(binding)
    assert CONTRACT.read_bytes() == canonical_syft_contract(binding)
    assert binding_document["configuration"]["sha256"] == SYFT_CONFIG_SHA256
    assert binding_document["binding_digest"] == binding.binding_digest()
    assert contract_document["scanner"]["config_sha256"] == SYFT_CONFIG_SHA256
    assert contract_document["scanner"]["binding_digest"] == binding.binding_digest()
    assert evidence_document["binding"]["config_sha256"] == SYFT_CONFIG_SHA256
    assert evidence_document["binding"]["binding_digest"] == binding.binding_digest()
    assert evidence_document["binding"]["executable_sha256"] == SYFT_EXECUTABLE_SHA256
    assert evidence_document["binding"]["executable_sha256"] == binding_document["executable"][
        "sha256"
    ]
    assert evidence_document["binding"]["scanner_version"] == "1.51.0"
    assert evidence_document["corpus_digest"] == corpus_identity(
        ROOT / "benchmarks/syft/corpus"
    )[0]


@pytest.mark.skipif(
    "SECURESCAN_SYFT_EXECUTABLE" not in os.environ,
    reason="trusted Syft real-binary replay is opt-in",
)
def test_controlled_evidence_replays_byte_for_byte_with_opt_in_binary() -> None:
    executable = Path(os.environ["SECURESCAN_SYFT_EXECUTABLE"])
    actual = canonical_json(build_controlled_report(ROOT, executable))
    assert actual == EVIDENCE.read_bytes()
