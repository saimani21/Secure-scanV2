from securescan.benchmarks.intelligence_v15 import characterize


def test_bounded_intelligence_performance_envelope() -> None:
    result = characterize((100, 1_000, 10_000))
    largest = result["scales"][-1]
    assert largest["relationships"] == 10_000
    assert largest["kev_parse_seconds"] < 15
    assert largest["epss_parse_seconds"] < 15
    assert largest["exact_cve_correlation_seconds"] < 5
    assert largest["finding_intelligence_projection_seconds"] < 5
    assert largest["threat_assessment_identity_seconds"] < 10
    assert largest["run_assurance_aggregation_seconds"] < 5
    assert largest["policy_decision_proof_seconds"] < 10
    assert result["largest_import"]["kev_import_seconds"] < 20
    assert result["largest_import"]["epss_import_seconds"] < 20
    assert result["largest_import"]["sql_statement_count"] <= 10
