# Core v0.1 failure-mode acceptance matrix

Status `covered` means the named automated test exists. Release-marked tests require the
strict local integration environment.

| Invariant | Failure or attack | Expected behavior | Exact test | Status |
|---|---|---|---|---|
| Valid source root | Missing, relative, protected, or symlink root | Reject with sanitized error | `tests/test_repository_workspace_security.py::test_source_validation_rejects_relative_missing_symlink_and_protected_paths` | covered |
| No symlink intake | Symlink file or directory | Reject snapshot | `tests/test_repository_workspace_security.py::test_intake_rejects_symlink_files_and_directories` | covered |
| No hardlink intake | Hardlink or duplicate inode | Reject snapshot | `tests/test_repository_workspace_security.py::test_intake_rejects_hardlinks_and_duplicate_inodes` | covered |
| Regular files only | FIFO, socket, or special file | Reject snapshot | `tests/test_repository_workspace_security.py::test_intake_rejects_fifo_socket_and_other_special_entries` | covered |
| Bounded intake | File count, individual, or total size exceeded | Abort and clean staging | `tests/test_repository_workspace_security.py::test_intake_enforces_file_count_single_file_and_total_limits` | covered |
| Trusted lookup | Unknown or metadata-controlled adapter | Fixed sanitized failure | `tests/test_trusted_adapter_registry.py::test_unknown_adapter_error_is_fixed_and_sanitized` | covered |
| Immutable image | Mutable image tag supplied | Reject definition | `tests/test_trusted_adapter_registry.py::test_docker_adapter_requires_digest_pinned_image` | covered |
| Network disabled | Scanner attempts network use | Container has no network | `tests/test_docker_sandbox_integration.py::test_docker_container_security_configuration_is_enforced` | covered |
| Non-root container | Scanner inspects identity | UID/GID are non-root | `tests/test_docker_sandbox_integration.py::test_docker_container_security_configuration_is_enforced` | covered |
| Read-only root | Scanner writes root filesystem | Write fails | `tests/test_docker_sandbox_integration.py::test_docker_container_security_configuration_is_enforced` | covered |
| Read-only source | Scanner writes source | Write fails | `tests/test_docker_sandbox_integration.py::test_docker_source_is_read_only_and_output_is_writable` | covered |
| Writable output | Scanner writes output | Dedicated output accepts write | `tests/test_docker_sandbox_integration.py::test_docker_source_is_read_only_and_output_is_writable` | covered |
| Bounded output | Stdout or stderr floods | Stop and classify bounded result | `tests/test_cancellable_process_executor.py::test_output_limit_is_bounded_and_stops_process` | covered |
| Safe create | Docker create fails | Do not start; sanitize failure | `tests/test_docker_sandbox_executor.py::test_executor_create_failure_does_not_start_container` | covered |
| Timeout cleanup | Container exceeds timeout | Stop, kill if needed, and remove | `tests/test_docker_sandbox_executor.py::test_executor_timeout_stops_kills_and_removes_container` | covered |
| Cancellation cleanup | Cancellation requested | Stop before completion and remove | `tests/test_docker_sandbox_executor.py::test_executor_cancellation_stops_container_before_reporting_completion` | covered |
| Container cleanup | Normal execution completes | Remove managed container | `tests/test_docker_sandbox_executor.py::test_executor_creates_starts_inspects_and_removes_container` | covered |
| JSON document valid | Malformed top-level JSON | Sanitized invalid-output failure | `tests/test_semgrep_parser.py::test_parser_rejects_malformed_top_level_documents` | covered |
| JSON size bounded | Oversized result file | Output-limit classification | `tests/test_semgrep_adapter.py::test_adapter_rejects_nonzero_missing_malformed_and_oversized_output` | covered |
| Output required | Result file absent | Sanitized retryable failure | `tests/test_semgrep_adapter.py::test_adapter_rejects_nonzero_missing_malformed_and_oversized_output` | covered |
| Finding isolated | One result malformed | Reject item or record bounded gap | `tests/test_semgrep_parser.py::test_parser_rejects_or_gaps_malformed_individual_results` | covered |
| Manifest-bound path | Finding names outside path | Reject finding and record gap | `tests/test_semgrep_parser.py::test_parser_maps_only_paths_present_in_repository_manifest` | covered |
| Diagnostics explicit | Semgrep diagnostic emitted | Convert to analysis gap | `tests/test_semgrep_parser.py::test_parser_converts_scanner_errors_to_analysis_gaps` | covered |
| Deduplicated evidence | Duplicate finding emitted | Keep one canonical finding | `tests/test_semgrep_parser.py::test_parser_deduplicates_and_sorts_findings_deterministically` | covered |
| Stable identity | Same finding parsed again | Same SecureScan fingerprint | `tests/test_semgrep_parser.py::test_parser_computes_stable_securescan_fingerprints` | covered |
| Atomic result commit | Execution insert fails | Roll back job, run, report, and execution | `tests/test_job_result_commit.py::test_result_commit_rolls_back_execution_job_run_and_report_together` | covered |
| One terminal winner | Cancellation races commitment | Exactly one terminal write wins | `tests/test_postgres_fault_race_hardening.py::test_postgres_cancellation_racing_success_commit_has_one_terminal_winner` | covered |
| Coherent lease race | Heartbeat races recovery | State and run aggregate match winner | `tests/test_postgres_fault_race_hardening.py::test_postgres_heartbeat_racing_expired_lease_recovery_is_coherent` | covered |
| Fencing | Recovered old worker commits | Stale token cannot overwrite new attempt | `tests/test_postgres_worker_cycle.py::test_postgres_recovery_and_new_lease_fence_old_worker_cycle` | covered |
| Database cleanup | Strict release completes | PostgreSQL public schema is reset | `tests/test_core_v01_release_integration.py::test_core_v01_release_gate_cleans_all_resources` | release |
| Report privacy | Hostile runtime values supplied | Public evidence omits sensitive values | `tests/test_release_report.py::test_release_json_report_is_canonical_and_hides_sensitive_values` | covered |
