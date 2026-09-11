from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import pytest
from sqlalchemy import inspect, select, text
from sqlalchemy.exc import IntegrityError

from securescan.config import Settings
from securescan.domain.enums import (
    JobFailureCategory,
    JobStatus,
    RunStatus,
    TargetType,
)
from securescan.jobs.mappers import job_record_from_row
from securescan.persistence.database import (
    AnalysisRunRow,
    JobRow,
    ProjectRow,
    TargetRow,
    ToolExecutionRow,
    create_session_factory,
    initialize_database,
)


def database_settings(tmp_path: Path) -> Settings:
    return Settings(
        database_url=f"sqlite:///{tmp_path / 'jobs.db'}",
        artifact_root=tmp_path / "artifacts",
    )


def test_session_factory_creates_parent_for_file_backed_sqlite(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "missing" / "nested" / "securescan.db"
    settings = Settings(
        database_url=f"sqlite:///{database_path}",
        artifact_root=tmp_path / "artifacts",
    )
    assert not database_path.parent.exists()

    engine, _ = create_session_factory(settings)
    try:
        with engine.connect() as connection:
            assert connection.scalar(text("SELECT 1")) == 1
        assert database_path.parent.is_dir()
        assert database_path.is_file()
    finally:
        engine.dispose()


def test_session_factory_preserves_sqlite_memory_without_directory_creation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    mkdir_calls: list[Path] = []
    original_mkdir = Path.mkdir

    def record_mkdir(path: Path, *args, **kwargs) -> None:
        mkdir_calls.append(path)
        original_mkdir(path, *args, **kwargs)

    monkeypatch.setattr(Path, "mkdir", record_mkdir)
    settings = Settings(
        database_url="sqlite:///:memory:", artifact_root=tmp_path / "artifacts"
    )

    engine, _ = create_session_factory(settings)
    try:
        with engine.connect() as connection:
            assert connection.scalar(text("SELECT 1")) == 1
        assert mkdir_calls == []
    finally:
        engine.dispose()


def create_run(session) -> AnalysisRunRow:
    project = ProjectRow(
        name="Job persistence test",
    )

    target = TargetRow(
        project=project,
        target_type=TargetType.SOURCE_REPOSITORY.value,
        content_digest="a" * 64,
        source_path="/tmp/repository",
    )

    run = AnalysisRunRow(
        target=target,
        status=RunStatus.QUEUED.value,
    )

    session.add(run)
    session.flush()

    return run


def create_job(session, run: AnalysisRunRow, key_character: str) -> JobRow:
    job = JobRow(
        run=run,
        adapter_id="fake-scanner",
        idempotency_key=key_character * 64,
    )
    session.add(job)
    session.flush()
    return job


def create_execution(
    run: AnalysisRunRow,
    *,
    job_id: str | None = None,
    attempt_number: int | None = None,
    failure_category: str | None = None,
    retryable: bool | None = None,
) -> ToolExecutionRow:
    return ToolExecutionRow(
        run=run,
        job_id=job_id,
        attempt_number=attempt_number,
        adapter_id="fake-scanner",
        tool_version="1.0.0",
        adapter_version="1.0.0",
        outcome="succeeded_no_observations",
        exit_code=0,
        duration_ms=25,
        warning_json=[],
        failure_category=failure_category,
        retryable=retryable,
    )


def test_initialize_database_creates_jobs_table(
    tmp_path: Path,
):
    settings = database_settings(tmp_path)
    initialize_database(settings)

    engine, _ = create_session_factory(settings)
    inspector = inspect(engine)

    assert "jobs" in inspector.get_table_names()

    expected_columns = {
        "id",
        "run_id",
        "adapter_id",
        "status",
        "priority",
        "attempt_count",
        "max_attempts",
        "available_at",
        "leased_by",
        "lease_token",
        "lease_expires_at",
        "heartbeat_at",
        "cancel_requested",
        "cancel_requested_at",
        "idempotency_key",
        "payload_json",
        "last_error",
        "created_at",
        "updated_at",
        "started_at",
        "finished_at",
    }

    actual_columns = {
        column["name"]
        for column in inspector.get_columns("jobs")
    }

    assert expected_columns <= actual_columns

    check_constraints = {
        constraint["name"] for constraint in inspector.get_check_constraints("jobs")
    }
    assert check_constraints >= {
        "ck_jobs_priority_nonnegative",
        "ck_jobs_attempt_count_nonnegative",
        "ck_jobs_max_attempts_positive",
        "ck_jobs_attempt_count_within_limit",
        "ck_jobs_status",
        "ck_jobs_cancel_timestamp_requires_flag",
    }
    unique_constraints = {
        constraint["name"] for constraint in inspector.get_unique_constraints("jobs")
    }
    assert "uq_jobs_idempotency_key" in unique_constraints
    indexes = {index["name"] for index in inspector.get_indexes("jobs")}
    assert indexes >= {"ix_jobs_cancel_reap", "ix_jobs_claim", "ix_jobs_run_id"}


def test_job_defaults_are_persisted(
    tmp_path: Path,
):
    settings = database_settings(tmp_path)
    initialize_database(settings)

    _, session_factory = create_session_factory(settings)

    with session_factory() as session:
        run = create_run(session)

        job = JobRow(
            run=run,
            adapter_id="fake-scanner",
            idempotency_key="1" * 64,
            payload_json={
                "mode": "findings",
            },
        )

        session.add(job)
        session.commit()
        session.refresh(job)

        assert job.status == JobStatus.SUBMITTED.value
        assert job.priority == 100
        assert job.attempt_count == 0
        assert job.max_attempts == 3
        assert job.cancel_requested is False
        assert job.cancel_requested_at is None
        assert job.lease_token is None
        assert job.created_at is not None
        assert job.updated_at is not None
        assert job.available_at is not None
        assert job.run_id == run.id

        lease_token = str(uuid4())
        job.lease_token = lease_token
        session.commit()
        session.expire(job)

        assert job.lease_token == lease_token


def test_cancellation_request_timestamp_is_persisted(
    tmp_path: Path,
):
    settings = database_settings(tmp_path)
    initialize_database(settings)
    _, session_factory = create_session_factory(settings)
    requested_at = datetime(2036, 1, 2, 3, 4, 5, tzinfo=UTC)

    with session_factory() as session:
        run = create_run(session)
        job = JobRow(
            run=run,
            adapter_id="fake-scanner",
            idempotency_key="c" * 64,
            cancel_requested=True,
            cancel_requested_at=requested_at,
        )
        session.add(job)
        session.commit()
        session.refresh(job)

        assert job.cancel_requested is True
        assert job.cancel_requested_at is not None
        assert job.cancel_requested_at.replace(tzinfo=UTC) == requested_at


def test_cancellation_timestamp_without_flag_is_rejected(
    tmp_path: Path,
):
    settings = database_settings(tmp_path)
    initialize_database(settings)
    _, session_factory = create_session_factory(settings)

    with session_factory() as session:
        run = create_run(session)
        session.add(
            JobRow(
                run=run,
                adapter_id="fake-scanner",
                idempotency_key="d" * 64,
                cancel_requested=False,
                cancel_requested_at=datetime(2036, 1, 2, 3, 4, 5, tzinfo=UTC),
            )
        )

        with pytest.raises(IntegrityError):
            session.commit()

        session.rollback()


def test_job_record_mapper_restores_utc_timezone_after_sqlite_round_trip(
    tmp_path: Path,
) -> None:
    settings = database_settings(tmp_path)
    initialize_database(settings)
    engine, session_factory = create_session_factory(settings)
    base_timestamp = datetime(2043, 2, 3, 4, 5, 6, tzinfo=UTC)
    expected_timestamps = {
        "available_at": base_timestamp,
        "lease_expires_at": base_timestamp + timedelta(seconds=1),
        "heartbeat_at": base_timestamp + timedelta(seconds=2),
        "cancel_requested_at": base_timestamp + timedelta(seconds=3),
        "created_at": base_timestamp + timedelta(seconds=4),
        "updated_at": base_timestamp + timedelta(seconds=5),
        "started_at": base_timestamp + timedelta(seconds=6),
        "finished_at": base_timestamp + timedelta(seconds=7),
    }

    try:
        with session_factory.begin() as session:
            run = create_run(session)
            job = JobRow(
                run=run,
                adapter_id="fake-scanner",
                idempotency_key="e" * 64,
                cancel_requested=True,
                **expected_timestamps,
            )
            session.add(job)
            session.flush()
            job_id = job.id

        with session_factory() as session:
            persisted = session.get(JobRow, job_id)
            assert persisted is not None
            for field_name in expected_timestamps:
                persisted_timestamp = getattr(persisted, field_name)
                assert persisted_timestamp is not None
                assert (
                    persisted_timestamp.tzinfo is None
                    or persisted_timestamp.utcoffset() is None
                )

            record = job_record_from_row(persisted)

        for field_name, expected_timestamp in expected_timestamps.items():
            mapped_timestamp = getattr(record, field_name)
            assert mapped_timestamp is not None
            assert mapped_timestamp.tzinfo is not None
            assert mapped_timestamp.utcoffset() is not None
            assert mapped_timestamp.utcoffset() == timedelta(0)
            assert mapped_timestamp.replace(tzinfo=None) == expected_timestamp.replace(
                tzinfo=None
            )

        assert record.cancel_requested_at is not None
        assert record.finished_at is not None
        assert record.cancel_requested_at.isoformat().endswith("+00:00")
        assert record.finished_at.isoformat().endswith("+00:00")
    finally:
        engine.dispose()


def test_duplicate_idempotency_key_is_rejected(
    tmp_path: Path,
):
    settings = database_settings(tmp_path)
    initialize_database(settings)

    _, session_factory = create_session_factory(settings)

    with session_factory() as session:
        run = create_run(session)

        session.add_all(
            [
                JobRow(
                    run=run,
                    adapter_id="fake-scanner",
                    idempotency_key="2" * 64,
                ),
                JobRow(
                    run=run,
                    adapter_id="fake-scanner",
                    idempotency_key="2" * 64,
                ),
            ]
        )

        with pytest.raises(IntegrityError):
            session.commit()

        session.rollback()


def test_invalid_job_status_is_rejected(
    tmp_path: Path,
):
    settings = database_settings(tmp_path)
    initialize_database(settings)

    _, session_factory = create_session_factory(settings)

    with session_factory() as session:
        run = create_run(session)

        session.add(
            JobRow(
                run=run,
                adapter_id="fake-scanner",
                status="teleported",
                idempotency_key="3" * 64,
            )
        )

        with pytest.raises(IntegrityError):
            session.commit()

        session.rollback()


@pytest.mark.parametrize(
    ("attempt_count", "max_attempts"),
    [
        (-1, 3),
        (0, 0),
        (4, 3),
    ],
)
def test_invalid_attempt_configuration_is_rejected(
    tmp_path: Path,
    attempt_count: int,
    max_attempts: int,
):
    settings = database_settings(tmp_path)
    initialize_database(settings)

    _, session_factory = create_session_factory(settings)

    with session_factory() as session:
        run = create_run(session)

        key_material = f"{attempt_count}:{max_attempts}"
        idempotency_key = (
            key_material.encode()
            .hex()
            .ljust(64, "0")[:64]
        )

        session.add(
            JobRow(
                run=run,
                adapter_id="fake-scanner",
                attempt_count=attempt_count,
                max_attempts=max_attempts,
                idempotency_key=idempotency_key,
            )
        )

        with pytest.raises(IntegrityError):
            session.commit()

        session.rollback()


def test_unknown_run_id_is_rejected(
    tmp_path: Path,
):
    settings = database_settings(tmp_path)
    initialize_database(settings)

    _, session_factory = create_session_factory(settings)

    with session_factory() as session:
        session.add(
            JobRow(
                run_id="00000000-0000-0000-0000-000000000000",
                adapter_id="fake-scanner",
                idempotency_key="4" * 64,
            )
        )

        with pytest.raises(IntegrityError):
            session.commit()

        session.rollback()


def test_tool_execution_attempt_identity_supports_historical_and_current_rows(
    tmp_path: Path,
) -> None:
    settings = database_settings(tmp_path)
    initialize_database(settings)
    _, session_factory = create_session_factory(settings)

    with session_factory.begin() as session:
        run = create_run(session)
        job = create_job(session, run, "5")
        historical_execution = create_execution(run)
        current_execution = create_execution(
            run,
            job_id=job.id,
            attempt_number=1,
        )
        session.add_all([historical_execution, current_execution])
        session.flush()
        historical_id = historical_execution.id
        current_id = current_execution.id
        run_id = run.id
        job_id = job.id

    with session_factory() as session:
        executions = {
            execution.id: execution
            for execution in session.scalars(select(ToolExecutionRow)).all()
        }
        assert executions[historical_id].run_id == run_id
        assert executions[historical_id].job_id is None
        assert executions[historical_id].attempt_number is None
        assert executions[historical_id].failure_category is None
        assert executions[historical_id].retryable is None
        assert executions[current_id].run_id == run_id
        assert executions[current_id].job_id == job_id
        assert executions[current_id].attempt_number == 1
        assert executions[current_id].failure_category is None
        assert executions[current_id].retryable is None


def test_duplicate_tool_execution_job_attempt_is_rejected(
    tmp_path: Path,
) -> None:
    settings = database_settings(tmp_path)
    initialize_database(settings)
    _, session_factory = create_session_factory(settings)

    with session_factory() as session:
        run = create_run(session)
        job = create_job(session, run, "6")
        session.add_all(
            [
                create_execution(run, job_id=job.id, attempt_number=1),
                create_execution(run, job_id=job.id, attempt_number=1),
            ]
        )

        with pytest.raises(IntegrityError):
            session.commit()
        session.rollback()


def test_nonpositive_tool_execution_attempt_is_rejected(
    tmp_path: Path,
) -> None:
    settings = database_settings(tmp_path)
    initialize_database(settings)
    _, session_factory = create_session_factory(settings)

    with session_factory() as session:
        run = create_run(session)
        job = create_job(session, run, "7")
        session.add(create_execution(run, job_id=job.id, attempt_number=0))

        with pytest.raises(IntegrityError):
            session.commit()
        session.rollback()


@pytest.mark.parametrize(
    ("failure_category", "retryable"),
    [
        (category, index % 2 == 0)
        for index, category in enumerate(JobFailureCategory)
    ],
)
def test_valid_tool_execution_failure_metadata_is_persisted(
    tmp_path: Path,
    failure_category: JobFailureCategory,
    retryable: bool,
) -> None:
    settings = database_settings(tmp_path)
    initialize_database(settings)
    _, session_factory = create_session_factory(settings)

    with session_factory.begin() as session:
        run = create_run(session)
        job = create_job(session, run, "8")
        execution = create_execution(
            run,
            job_id=job.id,
            attempt_number=1,
            failure_category=failure_category.value,
            retryable=retryable,
        )
        session.add(execution)
        session.flush()
        execution_id = execution.id

    with session_factory() as session:
        execution = session.get(ToolExecutionRow, execution_id)
        assert execution is not None
        assert execution.failure_category == failure_category.value
        assert execution.retryable is retryable


def test_invalid_tool_execution_failure_category_is_rejected(
    tmp_path: Path,
) -> None:
    settings = database_settings(tmp_path)
    initialize_database(settings)
    _, session_factory = create_session_factory(settings)

    with session_factory() as session:
        run = create_run(session)
        job = create_job(session, run, "9")
        session.add(
            create_execution(
                run,
                job_id=job.id,
                attempt_number=1,
                failure_category="unstructured_failure",
                retryable=True,
            )
        )

        with pytest.raises(IntegrityError):
            session.commit()
        session.rollback()
