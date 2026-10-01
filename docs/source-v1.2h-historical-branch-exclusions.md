# V1.2H historical branch-lock exclusions

These are historical benchmark provenance checks, not current-branch H product tests. They were run on `source/v1.2H-unified-product-experience` on 2026-10-01. Of 86 collected tests in the three named files, 25 passed and the 61 exact tests below failed or errored at a frozen `source/v0.3-semgrep` branch assertion before their own benchmark assertion. Their test result was not counted as an H product regression. No benchmark implementation or frozen evidence was changed.

The separately failing acquisition test also enters `_verify_f5b2r2_git_boundary`, which requires that same historical branch. The H branch cannot satisfy these identity checks by design; all other scanner/adapter/parser regression tests remain in the selected H gate.

The branch-lock proof is module-specific:

- Gitleaks maturity: `verify_f5_baseline` checks the current Git branch against the frozen `_BRANCH = "source/v0.3-semgrep"` before building or verifying the maturity artifact (`src/securescan/benchmarks/gitleaks_maturity.py`).
- Python SAST maturity: `verify_baseline` raises `F2F branch binding is invalid` on any other branch (`src/securescan/benchmarks/python_sast_maturity.py`).
- Python SAST real-world evaluation: `load_frozen_inputs` calls `verify_git_baseline`, which raises `F2E5 branch binding is invalid` on any other branch (`src/securescan/benchmarks/python_sast_realworld_evaluation.py`).
- Gitleaks acquisition: `verify_gitleaks_realworld_acquisition` enters `_verify_f5b2r2_git_boundary`, which requires the same historical branch (`src/securescan/benchmarks/gitleaks_realworld_acquisition.py`).

The 61 maturity failures/errors were captured as exact pytest node IDs in `/tmp/securescan-v12h-historical-branch-tests.xml`; every failure or setup error reached one of those branch guards before its own benchmark assertion. The acquisition assertion is the separate 62nd exclusion. The 25 independent tests in those same files passed and remain counted in the release-relevant set. No scanner parser/adapter test was excluded.

Of 14 initial environment-gated skips in the partitioned non-PostgreSQL run, 13 were rerun successfully with the pinned local Syft, Semgrep, Gitleaks, and Docker prerequisites. The one remaining classified opt-in skip is `tests/test_checkov_benchmark.py::test_second_hash_locked_environment_reproduces_normalized_report`. It requires a separately prepared second Checkov launcher through `SECURESCAN_CHECKOV_SECOND_EXECUTABLE`, which was not supplied. It is not a silent test failure or a claim that the second environment was validated.

## Exact excluded test IDs

- `tests/test_gitleaks_realworld_acquisition.py::test_acquired_manifest_is_canonical_digest_bound_and_verified`
- `tests/test_gitleaks_maturity.py::test_f5c_and_f5d_tags_resolve_to_exact_frozen_commit_and_are_ancestral`
- `tests/test_gitleaks_maturity.py::test_final_matrix_has_exact_claim_states`
- `tests/test_gitleaks_maturity.py::test_final_supported_and_limitation_language_is_exact`
- `tests/test_gitleaks_maturity.py::test_maturity_remains_scannable_and_benchmarked_gate_is_explicit`
- `tests/test_gitleaks_maturity.py::test_exact_frozen_evidence_is_reconciled_without_reinterpretation`
- `tests/test_gitleaks_maturity.py::test_generator_invokes_only_controlled_git_subprocesses`
- `tests/test_gitleaks_maturity.py::test_generator_is_deterministic_safe_and_does_not_mutate_frozen_evidence`
- `tests/test_gitleaks_maturity.py::test_recorded_final_capability_is_exact_canonical_replay`
- `tests/test_gitleaks_maturity.py::test_final_artifact_schema_and_frozen_baseline_are_explicit`
- `tests/test_python_sast_maturity.py::test_exact_f2e5_baseline_tag_and_ancestry`
- `tests/test_python_sast_maturity.py::test_every_frozen_file_identity_mismatch_fails_closed[benchmarks/python_sast/initial-v0.3e-baseline.json]`
- `tests/test_python_sast_maturity.py::test_every_frozen_file_identity_mismatch_fails_closed[benchmarks/python_sast/manifest.json]`
- `tests/test_python_sast_maturity.py::test_every_frozen_file_identity_mismatch_fails_closed[benchmarks/python_sast_external/external-evaluation-report.json]`
- `tests/test_python_sast_maturity.py::test_every_frozen_file_identity_mismatch_fails_closed[benchmarks/python_sast_external/external-evaluation-review.json]`
- `tests/test_python_sast_maturity.py::test_every_frozen_file_identity_mismatch_fails_closed[benchmarks/python_sast_external/rule-claim-conformance-audit-v2.json]`
- `tests/test_python_sast_maturity.py::test_every_frozen_file_identity_mismatch_fails_closed[benchmarks/python_sast_external/rule-claims-v2.json]`
- `tests/test_python_sast_maturity.py::test_every_frozen_file_identity_mismatch_fails_closed[benchmarks/python_sast_realworld/applicability-proposal-v2.json]`
- `tests/test_python_sast_maturity.py::test_every_frozen_file_identity_mismatch_fails_closed[benchmarks/python_sast_realworld/applicability-review-v2.json]`
- `tests/test_python_sast_maturity.py::test_every_frozen_file_identity_mismatch_fails_closed[benchmarks/python_sast_realworld/applicability-summary-v2.json]`
- `tests/test_python_sast_maturity.py::test_every_frozen_file_identity_mismatch_fails_closed[benchmarks/python_sast_realworld/realworld-evaluation-report-v2.json]`
- `tests/test_python_sast_maturity.py::test_every_frozen_file_identity_mismatch_fails_closed[benchmarks/python_sast_realworld/realworld-evaluation-review-v2.json]`
- `tests/test_python_sast_maturity.py::test_every_frozen_file_identity_mismatch_fails_closed[src/securescan/scanners/semgrep/rules/securescan-python-baseline-v2.yml]`
- `tests/test_python_sast_maturity.py::test_generator_invokes_only_controlled_git_subprocesses`
- `tests/test_python_sast_maturity.py::test_generator_does_not_mutate_frozen_evidence`
- `tests/test_python_sast_maturity.py::test_all_17_rules_are_accounted_with_required_fields`
- `tests/test_python_sast_maturity.py::test_coverage_and_evidence_strength_are_conservative`
- `tests/test_python_sast_maturity.py::test_exact_frozen_metrics_are_copied_without_promotion`
- `tests/test_python_sast_maturity.py::test_realworld_representation_is_exact`
- `tests/test_python_sast_maturity.py::test_supported_and_prohibited_claim_boundaries`
- `tests/test_python_sast_maturity.py::test_maturity_is_in_defined_project_vocabulary`
- `tests/test_python_sast_maturity.py::test_generation_is_canonical_and_deterministic`
- `tests/test_python_sast_maturity.py::test_recorded_artifacts_match_the_generator`
- `tests/test_python_sast_maturity.py::test_artifacts_have_no_timestamps_host_paths_or_mutable_head`
- `tests/test_python_sast_realworld_evaluation.py::test_exact_f2e1_f2e4_and_baseline_bindings`
- `tests/test_python_sast_realworld_evaluation.py::test_v2_case_relation_and_revision_accounting_is_exact`
- `tests/test_python_sast_realworld_evaluation.py::test_yt_dlp_is_a_scoring_relation`
- `tests/test_python_sast_realworld_evaluation.py::test_historical_v1_applicability_is_not_loaded_for_scoring`
- `tests/test_python_sast_realworld_evaluation.py::test_any_f2e4_evidence_file_identity_mismatch_fails_closed[rule-claims-v2.json]`
- `tests/test_python_sast_realworld_evaluation.py::test_any_f2e4_evidence_file_identity_mismatch_fails_closed[rule-claim-conformance-audit-v2.json]`
- `tests/test_python_sast_realworld_evaluation.py::test_any_f2e4_evidence_file_identity_mismatch_fails_closed[applicability-proposal-v2.json]`
- `tests/test_python_sast_realworld_evaluation.py::test_any_f2e4_evidence_file_identity_mismatch_fails_closed[applicability-summary-v2.json]`
- `tests/test_python_sast_realworld_evaluation.py::test_any_f2e4_evidence_file_identity_mismatch_fails_closed[applicability-review-v2.json]`
- `tests/test_python_sast_realworld_evaluation.py::test_actual_projection_contains_all_26_logical_revisions`
- `tests/test_python_sast_realworld_evaluation.py::test_scanner_nonzero_failure_and_timeout`
- `tests/test_python_sast_realworld_evaluation.py::test_location_containment_satisfies_only_the_exact_relation`
- `tests/test_python_sast_realworld_evaluation.py::test_same_rule_outside_region_does_not_satisfy_relation`
- `tests/test_python_sast_realworld_evaluation.py::test_wrong_rule_inside_region_is_cross_rule_and_does_not_satisfy`
- `tests/test_python_sast_realworld_evaluation.py::test_revision_expectation_classifications[True-True-TP]`
- `tests/test_python_sast_realworld_evaluation.py::test_revision_expectation_classifications[True-False-FN]`
- `tests/test_python_sast_realworld_evaluation.py::test_revision_expectation_classifications[False-False-TN]`
- `tests/test_python_sast_realworld_evaluation.py::test_revision_expectation_classifications[False-True-FP]`
- `tests/test_python_sast_realworld_evaluation.py::test_should_discriminate_success_and_failure`
- `tests/test_python_sast_realworld_evaluation.py::test_not_expected_to_discriminate_persistence`
- `tests/test_python_sast_realworld_evaluation.py::test_outside_case_observation_remains_non_scoring`
- `tests/test_python_sast_realworld_evaluation.py::test_cve_detection_and_case_family_accounting`
- `tests/test_python_sast_realworld_evaluation.py::test_deterministic_claim_metrics_and_per_rule_results`
- `tests/test_python_sast_realworld_evaluation.py::test_report_binds_all_frozen_f2e4_provenance`
- `tests/test_python_sast_realworld_evaluation.py::test_review_includes_failures_observations_and_successes`
- `tests/test_python_sast_realworld_evaluation.py::test_report_has_no_host_paths_source_bodies_snippets_or_timestamps`
- `tests/test_python_sast_realworld_evaluation.py::test_repeated_report_and_review_bytes_are_identical`
- `tests/test_python_sast_realworld_evaluation.py::test_scanner_failure_accounting_never_becomes_clean`

Reason for every ID above: the frozen benchmark verifier asserts the historical branch identity, whereas this release is intentionally on the V1.2H branch. These exclusions do not waive scanner, parser, adapter, or H product tests. Never reclassify a different failure as historical without checking its traceback.
