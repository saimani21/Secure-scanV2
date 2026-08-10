from __future__ import annotations

from securescan.domain.enums import ExecutionOutcome, RunStatus


def test_findings_are_normalized(service, adapter, target):
    report = service.run(adapter, target, mode="findings")
    assert report.status is RunStatus.COMPLETED
    assert report.executions[0].outcome is ExecutionOutcome.SUCCEEDED_WITH_OBSERVATIONS
    assert len(report.observations) == 1
    assert report.observations[0].fingerprint
    assert report.analysis_gaps == []


def test_zero_results_are_not_failure(service, adapter, target):
    report = service.run(adapter, target, mode="zero")
    assert report.status is RunStatus.COMPLETED
    assert report.executions[0].outcome is ExecutionOutcome.SUCCEEDED_NO_OBSERVATIONS


def test_warning_is_preserved(service, adapter, target):
    report = service.run(adapter, target, mode="warning")
    assert report.executions[0].outcome is ExecutionOutcome.SUCCEEDED_WITH_WARNINGS
    assert report.executions[0].warnings == ["Controlled warning"]


def test_nonzero_exit_can_still_contain_valid_results(service, adapter, target):
    report = service.run(adapter, target, mode="nonzero-valid")
    assert report.executions[0].exit_code == 1
    assert report.executions[0].outcome is ExecutionOutcome.SUCCEEDED_WITH_OBSERVATIONS


def test_timeout_becomes_analysis_gap(service, adapter, target):
    report = service.run(adapter, target, mode="timeout", timeout_seconds=1, sleep_seconds=5)
    assert report.status is RunStatus.PARTIAL
    assert report.executions[0].outcome is ExecutionOutcome.TIMEOUT
    assert report.analysis_gaps[0].code == "TIMEOUT"


def test_malformed_output_is_not_clean(service, adapter, target):
    report = service.run(adapter, target, mode="malformed")
    assert report.status is RunStatus.PARTIAL
    assert report.executions[0].outcome is ExecutionOutcome.INVALID_OUTPUT
    assert report.observations == []


def test_wrong_schema_is_not_clean(service, adapter, target):
    report = service.run(adapter, target, mode="wrong-schema")
    assert report.executions[0].outcome is ExecutionOutcome.INVALID_OUTPUT


def test_oversized_output_is_stopped(service, adapter, target):
    report = service.run(adapter, target, mode="oversized", max_output_bytes=4096, bytes=500_000)
    assert report.executions[0].outcome is ExecutionOutcome.OUTPUT_LIMIT_EXCEEDED
