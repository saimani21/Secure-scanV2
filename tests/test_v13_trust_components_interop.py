from __future__ import annotations

import json
from contextlib import contextmanager
from types import SimpleNamespace

import pytest
from jsonschema import Draft7Validator
from test_unified_evidence_models import _report
from typer.testing import CliRunner
from unified_evidence_fixtures import RUN_ID

from securescan.cli import main as cli_main
from securescan.evidence import (
    ComponentKind,
    PackageComponentPayload,
    SecureScanComponent,
    build_component_ref,
)
from securescan.product_core.component_identity import (
    ComponentIdentityError,
    package_identity,
)
from securescan.product_core.interoperability import (
    CYCLONEDX_SPEC_VERSION,
    _cyclonedx_document,
    _toolchain_manifest,
    canonical_export_json,
)
from securescan.product_core.verified_read import VerifiedPublishedRun


def _component(
    *, name: str, version: str | None, package_type: str, purl: str | None
) -> SecureScanComponent:
    package_key = {
        "python": "1",
        "npm": "2",
        "go-module": "3",
        "apk": "4",
    }[package_type] * 64
    return SecureScanComponent(
        component_ref=build_component_ref(ComponentKind.PACKAGE, package_key),
        component_kind=ComponentKind.PACKAGE,
        native_component_identity=package_key,
        payload=PackageComponentPayload(
            package_key=package_key,
            package_name=name,
            package_version=version,
            package_type=package_type,
            purl=purl,
        ),
    )


@pytest.mark.parametrize(
    ("component", "expected"),
    (
        (
            _component(name="PyYAML", version="5.3.1", package_type="python", purl=None),
            "pkg:pypi/pyyaml@5.3.1",
        ),
        (
            _component(name="@scope/pkg", version="1.0.0", package_type="npm", purl=None),
            "pkg:npm/%40scope/pkg@1.0.0",
        ),
        (
            _component(
                name="github.com/example/mod",
                version="v1.2.3",
                package_type="go-module",
                purl=None,
            ),
            "pkg:golang/github.com/example/mod@v1.2.3",
        ),
    ),
)
def test_representative_purls_are_derived_deterministically(
    component: SecureScanComponent, expected: str
) -> None:
    first = package_identity(component)
    second = package_identity(component)
    assert first == second
    assert first.purl == expected
    assert first.identity_source == "derived_purl"


def test_unprovable_purl_uses_explicit_securescan_fallback() -> None:
    identity = package_identity(
        _component(name="libssl", version=None, package_type="apk", purl=None)
    )
    assert identity.purl is None
    assert identity.identity_source == "securescan_package_key"
    assert identity.bom_ref.startswith("urn:securescan:component:")


def test_contradictory_observed_purl_fails_closed() -> None:
    component = _component(
        name="PyYAML",
        version="5.3.1",
        package_type="python",
        purl="pkg:pypi/pyyaml@6.0.0",
    )
    with pytest.raises(ComponentIdentityError):
        package_identity(component)


def test_cyclonedx_17_is_deterministic_unique_and_schema_shaped() -> None:
    report = _report()
    verified = VerifiedPublishedRun(
        run_id=RUN_ID,
        target_id="00000000-0000-4000-8000-00000000b001",
        project_id="00000000-0000-4000-8000-00000000b002",
        lineage_id=None,
        report_artifact_sha256="a" * 64,
        report_artifact_size_bytes=len(report.canonical_json()),
        report=report,
    )
    document = _cyclonedx_document(verified)
    schema = {
        "type": "object",
        "required": [
            "$schema",
            "bomFormat",
            "specVersion",
            "serialNumber",
            "version",
            "metadata",
            "components",
        ],
        "additionalProperties": False,
        "properties": {
            "$schema": {"const": "http://cyclonedx.org/schema/bom-1.7.schema.json"},
            "bomFormat": {"const": "CycloneDX"},
            "specVersion": {"const": "1.7"},
            "serialNumber": {"pattern": "^urn:uuid:[0-9a-f-]{36}$"},
            "version": {"type": "integer", "minimum": 1},
            "metadata": {"type": "object"},
            "components": {"type": "array"},
        },
    }
    Draft7Validator(schema).validate(document)
    assert document["specVersion"] == CYCLONEDX_SPEC_VERSION
    assert canonical_export_json(document) == canonical_export_json(
        _cyclonedx_document(verified)
    )
    refs = [item["bom-ref"] for item in document["components"]]
    assert refs == sorted(set(refs))
    assert "dependencies" not in document
    assert b"/home/" not in canonical_export_json(document)


def test_toolchain_manifest_is_evidence_derived_deterministic_and_path_free() -> None:
    report = _report()
    verified = VerifiedPublishedRun(
        run_id=RUN_ID,
        target_id="00000000-0000-4000-8000-00000000b001",
        project_id="00000000-0000-4000-8000-00000000b002",
        lineage_id=None,
        report_artifact_sha256="a" * 64,
        report_artifact_size_bytes=len(report.canonical_json()),
        report=report,
    )
    parent = SimpleNamespace(
        plan_digest="c" * 64,
        planning_snapshot_sha256="d" * 64,
        profile_digest="b" * 64,
        roster_digest="e" * 64,
    )
    executions = (
        SimpleNamespace(
            adapter_id="syft",
            adapter_version="1.0.0",
            tool_version="1.32.0",
        ),
        SimpleNamespace(
            adapter_id="syft",
            adapter_version="1.0.0",
            tool_version="1.32.0",
        ),
    )
    authority = SimpleNamespace(
        canonical_data=lambda: {
            "analyzer_id": "syft-source-v1",
            "authority": "syft",
            "capability": "package_inventory",
            "contract_digest": "f" * 64,
            "contract_kind": "source-binding",
            "implementation_version": "1",
        }
    )
    node = SimpleNamespace(
        analyzer_id="syft-source-v1",
        authority=SimpleNamespace(value="syft"),
        capability=SimpleNamespace(value="package_inventory"),
        contract_digest="f" * 64,
        node_id="9" * 64,
    )
    snapshot = SimpleNamespace(
        roster=SimpleNamespace(authorities=(authority,)), nodes=(node,)
    )
    first = _toolchain_manifest(  # type: ignore[arg-type]
        verified, parent, executions, snapshot
    )
    second = _toolchain_manifest(  # type: ignore[arg-type]
        verified, parent, executions, snapshot
    )
    assert first == second
    assert first["execution_identities"][0]["accepted_execution_count"] == 2
    assert first["planned_nodes"][0]["binding_digest"] == "f" * 64
    assert first["limitations"] == [
        "ENRY_RUN_IDENTITY_NOT_PERSISTED_IN_FROZEN_PLANNING_EVIDENCE"
    ]
    rendered = canonical_export_json(first)
    assert b"/home/" not in rendered
    assert len(first["manifest_sha256"]) == 64


def test_exports_do_not_contain_duplicate_json_keys() -> None:
    document = json.loads(canonical_export_json(_cyclonedx_document(
        VerifiedPublishedRun(
            run_id=RUN_ID,
            target_id="00000000-0000-4000-8000-00000000b001",
            project_id="00000000-0000-4000-8000-00000000b002",
            lineage_id=None,
            report_artifact_sha256="a" * 64,
            report_artifact_size_bytes=len(_report().canonical_json()),
            report=_report(),
        )
    )))
    assert document["bomFormat"] == "CycloneDX"


def test_cyclonedx_and_toolchain_cli_are_machine_readable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cyclonedx = {"bomFormat": "CycloneDX", "specVersion": "1.7"}
    manifest = {
        "authorities": [],
        "manifest_sha256": "a" * 64,
        "run_id": RUN_ID,
    }

    @contextmanager
    def factory():
        yield SimpleNamespace(
            interoperability=SimpleNamespace(
                cyclonedx=lambda *, run_id: cyclonedx,
                toolchain_manifest=lambda *, run_id: manifest,
            )
        )

    monkeypatch.setattr(cli_main, "create_source_cli_services", factory)
    sbom = CliRunner().invoke(
        cli_main.app, ["sbom", RUN_ID, "--format", "cyclonedx-json"]
    )
    toolchain = CliRunner().invoke(cli_main.app, ["toolchain", RUN_ID, "--json"])
    assert sbom.exit_code == toolchain.exit_code == 0
    assert json.loads(sbom.stdout) == cyclonedx
    assert json.loads(toolchain.stdout) == manifest


def test_sbom_cli_rejects_unimplemented_spdx(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    @contextmanager
    def factory():
        yield SimpleNamespace(interoperability=pytest.fail("service should not be created"))

    monkeypatch.setattr(cli_main, "create_source_cli_services", factory)
    result = CliRunner().invoke(cli_main.app, ["sbom", RUN_ID, "--format", "spdx-json"])
    assert result.exit_code == 2
    assert json.loads(result.stderr)["error"]["code"] == "EXPORT_INVALID"
