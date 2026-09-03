from __future__ import annotations

import ast
import hashlib
import json
import os
import re
from collections import Counter, defaultdict
from dataclasses import replace
from pathlib import Path

import pytest

from securescan.benchmarks import gitleaks_corpus
from securescan.benchmarks.gitleaks_contract import (
    GITLEAKS_BENCHMARK_CONTRACT_SHA256,
    GITLEAKS_BINDING_ARTIFACT_SHA256,
    GITLEAKS_BINDING_DIGEST,
    GitleaksBenchmarkExpectation,
    GitleaksBenchmarkSourceType,
    load_benchmark_manifest,
)
from securescan.benchmarks.gitleaks_corpus import (
    GITLEAKS_CORPUS_CASE_COUNT,
    GITLEAKS_CORPUS_CORE_CASE_COUNT,
    GITLEAKS_CORPUS_DIGEST,
    GITLEAKS_CORPUS_MANIFEST_PATH,
    GITLEAKS_CORPUS_MANIFEST_SHA256,
    GITLEAKS_CORPUS_PLAN_PATH,
    GITLEAKS_CORPUS_PLAN_SHA256,
    GITLEAKS_CORPUS_RULE_IDS,
    GITLEAKS_CORPUS_SCOPE_CASE_COUNT,
    GITLEAKS_V04F1_BASELINE_COMMIT,
    GITLEAKS_V04F1_BASELINE_TAG,
    corpus_plan_sha256,
    generate_gitleaks_corpus,
    load_gitleaks_corpus_plan,
    materialize_gitleaks_benchmark,
    verify_gitleaks_benchmark,
)
from securescan.scanners.gitleaks.parser import GitleaksDetectionKind

ROOT = Path(__file__).parent.parent
PLAN_PATH = ROOT / GITLEAKS_CORPUS_PLAN_PATH
MANIFEST_PATH = ROOT / GITLEAKS_CORPUS_MANIFEST_PATH
GENERATOR_PATH = ROOT / "src/securescan/benchmarks/gitleaks_corpus.py"


def _plan_document() -> dict[str, object]:
    document = json.loads(PLAN_PATH.read_text(encoding="utf-8"))
    assert isinstance(document, dict)
    return document


def _write_plan(tmp_path: Path, document: dict[str, object]) -> Path:
    path = tmp_path / "corpus-plan-v1.json"
    path.write_text(
        json.dumps(
            document,
            allow_nan=False,
            ensure_ascii=True,
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    return path


def _cases(document: dict[str, object]) -> list[dict[str, object]]:
    cases = document["cases"]
    assert isinstance(cases, list)
    assert all(isinstance(case, dict) for case in cases)
    return cases  # type: ignore[return-value]


def _case(
    document: dict[str, object],
    case_id: str,
) -> dict[str, object]:
    return next(case for case in _cases(document) if case["case_id"] == case_id)


def _generated_bytes(root: Path) -> dict[str, bytes]:
    corpus = root / "corpus"
    return {
        path.relative_to(corpus).as_posix(): path.read_bytes()
        for path in sorted(corpus.rglob("*"))
        if path.is_file()
    }


def test_corpus_plan_identity_and_canonical_bytes_are_frozen() -> None:
    plan = load_gitleaks_corpus_plan(PLAN_PATH)

    assert plan.baseline_commit == GITLEAKS_V04F1_BASELINE_COMMIT
    assert plan.baseline_commit == "c19e3d0ac78ccc4ab504eeab03c989d1b803acb0"
    assert plan.baseline_tag == GITLEAKS_V04F1_BASELINE_TAG
    assert plan.contract_sha256 == GITLEAKS_BENCHMARK_CONTRACT_SHA256
    assert plan.binding_digest == GITLEAKS_BINDING_DIGEST
    assert plan.binding_artifact_sha256 == GITLEAKS_BINDING_ARTIFACT_SHA256
    assert PLAN_PATH.read_bytes() == plan.canonical_json()
    assert corpus_plan_sha256(plan) == GITLEAKS_CORPUS_PLAN_SHA256
    assert hashlib.sha256(PLAN_PATH.read_bytes()).hexdigest() == (
        "0090cd7d140034f715bc9d060465ea69284f63b3a33ab917479b1264fa542a10"
    )


def test_corpus_plan_has_exact_relation_accounting() -> None:
    plan = load_gitleaks_corpus_plan(PLAN_PATH)
    core = tuple(case for case in plan.cases if not case.case_id.startswith("scope-"))
    scope = tuple(case for case in plan.cases if case.case_id.startswith("scope-"))

    assert len(plan.cases) == GITLEAKS_CORPUS_CASE_COUNT == 48
    assert len(core) == GITLEAKS_CORPUS_CORE_CASE_COUNT == 42
    assert len(scope) == GITLEAKS_CORPUS_SCOPE_CASE_COUNT == 6
    assert {case.rule_id for case in core} == set(GITLEAKS_CORPUS_RULE_IDS)
    assert tuple(case.case_id for case in plan.cases) == tuple(
        sorted(case.case_id for case in plan.cases)
    )
    assert len({case.case_id for case in plan.cases}) == 48
    assert len({case.relative_path for case in plan.cases}) == 48

    counts: dict[str, Counter[GitleaksBenchmarkExpectation]] = defaultdict(Counter)
    for case in core:
        counts[case.rule_id][case.expectation] += 1
        assert case.detection_kind is (
            GitleaksDetectionKind.PATH
            if case.rule_id == "pkcs12-file"
            else GitleaksDetectionKind.CONTENT
        )

    assert all(
        count == Counter(
            {
                GitleaksBenchmarkExpectation.EXPECTED_MATCH: 3,
                GitleaksBenchmarkExpectation.EXPECTED_NO_MATCH: 3,
            }
        )
        for count in counts.values()
    )


def test_corpus_plan_has_exact_scope_relations() -> None:
    plan = load_gitleaks_corpus_plan(PLAN_PATH)
    actual = {
        case.case_id: (case.rule_id, case.expectation)
        for case in plan.cases
        if case.case_id.startswith("scope-")
    }

    assert actual == {
        "scope-docs-positive": (
            "github-pat",
            GitleaksBenchmarkExpectation.EXPECTED_MATCH,
        ),
        "scope-generated-positive": (
            "github-pat",
            GitleaksBenchmarkExpectation.EXPECTED_MATCH,
        ),
        "scope-node-modules-allowlisted": (
            "github-pat",
            GitleaksBenchmarkExpectation.EXPECTED_NO_MATCH,
        ),
        "scope-tests-positive": (
            "github-pat",
            GitleaksBenchmarkExpectation.EXPECTED_MATCH,
        ),
        "scope-unknown-extension-positive": (
            "github-pat",
            GitleaksBenchmarkExpectation.EXPECTED_MATCH,
        ),
        "scope-vendor-allowlisted": (
            "github-pat",
            GitleaksBenchmarkExpectation.EXPECTED_NO_MATCH,
        ),
    }


def test_source_types_and_descriptions_are_deterministic() -> None:
    plan = load_gitleaks_corpus_plan(PLAN_PATH)

    for case in plan.cases:
        if case.case_id.startswith("scope-"):
            expected = GitleaksBenchmarkSourceType.PROJECT_OWNED_SCOPE_SENTINEL
        elif case.rule_id == "pkcs12-file":
            expected = GitleaksBenchmarkSourceType.PROJECT_OWNED_BINARY_PATH
        elif case.expectation is GitleaksBenchmarkExpectation.EXPECTED_NO_MATCH:
            expected = GitleaksBenchmarkSourceType.PROJECT_OWNED_NEAR_MISS
        else:
            expected = GitleaksBenchmarkSourceType.PROJECT_OWNED_SYNTHETIC
        assert case.source_type is expected
        assert case.description == (
            f"Pre-scan {case.rule_id} relation using recipe "
            f"{case.fixture_recipe}."
        )


def _recipe_candidate(recipe_name: str) -> bytes:
    recipe = gitleaks_corpus._CORE_RECIPES[recipe_name]
    return recipe.payload.rstrip(b"\n").splitlines()[-1].rsplit(b" ", 1)[-1]


def test_aws_positive_recipes_match_frozen_static_shape() -> None:
    pattern = re.compile(
        rb"(?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16}\Z"
    )
    expected = {
        "aws-akia-high-entropy": b"AKIA7Q2W4E6R3T5Y7U2P",
        "aws-asia-high-entropy": b"ASIA3Z5X7C2V4B6N3M5K",
        "aws-abia-high-entropy": b"ABIA2P4O6I7U3Y5T2R4E",
    }

    assert {
        recipe_name: _recipe_candidate(recipe_name)
        for recipe_name in expected
    } == expected
    assert all(pattern.fullmatch(candidate) for candidate in expected.values())


def test_aws_negative_recipes_isolate_one_static_boundary_each() -> None:
    pattern = re.compile(
        rb"(?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16}\Z"
    )
    wrong_prefix = _recipe_candidate("aws-wrong-prefix")
    wrong_length = _recipe_candidate("aws-wrong-length")
    example = _recipe_candidate("aws-explicit-example-suffix")

    assert wrong_prefix == b"ZZIA7Q2W4E6R3T5Y7U2P"
    assert re.fullmatch(rb"ZZIA[A-Z2-7]{16}", wrong_prefix)
    assert pattern.fullmatch(wrong_prefix) is None
    assert wrong_length == b"AKIA7Q2W4E6R3T5Y7U2"
    assert re.fullmatch(rb"AKIA[A-Z2-7]{15}", wrong_length)
    assert pattern.fullmatch(wrong_length) is None
    assert example == b"AKIA7Q2W4E6R2EXAMPLE"
    assert pattern.fullmatch(example)
    assert example.endswith(b"EXAMPLE")


def test_entropy_sensitive_recipe_intent_is_statically_enforced() -> None:
    for recipe_name, threshold in (
        gitleaks_corpus._ENTROPY_FLOOR_BY_RECIPE.items()
    ):
        payload = (
            gitleaks_corpus._SCOPE_PAYLOAD
            if recipe_name == gitleaks_corpus._SCOPE_RECIPE_NAME
            else gitleaks_corpus._CORE_RECIPES[recipe_name].payload
        )
        value = gitleaks_corpus._last_fixture_line(payload)
        subject = gitleaks_corpus._entropy_subject(recipe_name, value)
        assert gitleaks_corpus._shannon_entropy(subject) >= threshold

    for recipe_name, threshold in (
        gitleaks_corpus._ENTROPY_CEILING_BY_RECIPE.items()
    ):
        payload = gitleaks_corpus._CORE_RECIPES[recipe_name].payload
        value = gitleaks_corpus._last_fixture_line(payload)
        subject = gitleaks_corpus._entropy_subject(recipe_name, value)
        assert gitleaks_corpus._shannon_entropy(subject) < threshold


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("baseline_commit", "0" * 40),
        ("baseline_tag", "wrong-tag"),
        ("benchmark_id", "wrong-benchmark"),
        ("binding_artifact_sha256", "0" * 64),
        ("binding_digest", "0" * 64),
        ("case_count", 47),
        ("contract_sha256", "0" * 64),
        ("scanner_id", "other-scanner"),
        ("scanner_version", "0.0.0"),
        ("schema_version", "wrong-schema"),
    ),
)
def test_plan_rejects_wrong_frozen_metadata(
    tmp_path: Path,
    field: str,
    value: object,
) -> None:
    document = _plan_document()
    document[field] = value

    with pytest.raises(ValueError, match="corpus plan is invalid"):
        load_gitleaks_corpus_plan(_write_plan(tmp_path, document))


@pytest.mark.parametrize("operation", ("missing", "extra"))
def test_plan_rejects_wrong_top_level_fields(
    tmp_path: Path,
    operation: str,
) -> None:
    document = _plan_document()
    if operation == "missing":
        del document["contract_sha256"]
    else:
        document["unexpected"] = True

    with pytest.raises(ValueError, match="corpus plan is invalid"):
        load_gitleaks_corpus_plan(_write_plan(tmp_path, document))


@pytest.mark.parametrize(
    ("mutation", "case_id"),
    (
        ("duplicate-id", "aws-access-token-negative-02"),
        ("duplicate-path", "aws-access-token-negative-02"),
        ("unknown-rule", "aws-access-token-negative-01"),
        ("wrong-expectation", "aws-access-token-positive-01"),
        ("wrong-kind", "pkcs12-file-positive-01"),
        ("wrong-source-type", "github-pat-positive-01"),
        ("unknown-recipe", "github-pat-positive-01"),
        ("duplicate-recipe", "github-pat-positive-02"),
        ("missing-recipe", "github-pat-positive-01"),
        ("wrong-scope-expectation", "scope-docs-positive"),
    ),
)
def test_plan_rejects_invalid_case_relations(
    tmp_path: Path,
    mutation: str,
    case_id: str,
) -> None:
    document = _plan_document()
    case = _case(document, case_id)
    if mutation == "duplicate-id":
        case["case_id"] = "aws-access-token-negative-01"
    elif mutation == "duplicate-path":
        case["relative_path"] = "corpus/aws-access-token/negative-01.txt"
    elif mutation == "unknown-rule":
        case["rule_id"] = "unexpected-detector"
    elif mutation == "wrong-expectation":
        case["expectation"] = "EXPECTED_NO_MATCH"
    elif mutation == "wrong-kind":
        case["detection_kind"] = "CONTENT"
    elif mutation == "wrong-source-type":
        case["source_type"] = "PROJECT_OWNED_NEAR_MISS"
    elif mutation == "unknown-recipe":
        case["fixture_recipe"] = "unknown-recipe"
    elif mutation == "duplicate-recipe":
        case["fixture_recipe"] = "github-pat-high-entropy-a"
    elif mutation == "missing-recipe":
        del case["fixture_recipe"]
    else:
        case["expectation"] = "EXPECTED_NO_MATCH"

    with pytest.raises(ValueError, match="corpus plan is invalid"):
        load_gitleaks_corpus_plan(_write_plan(tmp_path, document))


@pytest.mark.parametrize(
    "relative_path",
    (
        "corpus/../escape.txt",
        "corpus\\escape.txt",
        "https://example.invalid/case.txt",
        "/corpus/absolute.txt",
        "corpus//empty.txt",
    ),
)
def test_plan_rejects_malformed_paths(
    tmp_path: Path,
    relative_path: str,
) -> None:
    document = _plan_document()
    _case(document, "github-pat-positive-01")["relative_path"] = relative_path

    with pytest.raises(ValueError, match="corpus plan is invalid"):
        load_gitleaks_corpus_plan(_write_plan(tmp_path, document))


def test_plan_rejects_noncanonical_case_order(tmp_path: Path) -> None:
    document = _plan_document()
    _cases(document).reverse()

    with pytest.raises(ValueError, match="corpus plan is invalid"):
        load_gitleaks_corpus_plan(_write_plan(tmp_path, document))


def test_generator_is_byte_deterministic_across_repeated_generation(
    tmp_path: Path,
) -> None:
    plan = load_gitleaks_corpus_plan(PLAN_PATH)
    first = tmp_path / "first"
    second = tmp_path / "second"
    first.mkdir()
    second.mkdir()

    first_hashes = generate_gitleaks_corpus(plan, first.resolve())
    repeated_hashes = generate_gitleaks_corpus(plan, first.resolve())
    second_hashes = generate_gitleaks_corpus(plan, second.resolve())

    assert first_hashes == repeated_hashes == second_hashes
    assert _generated_bytes(first) == _generated_bytes(second)
    assert len(first_hashes) == 48


def test_generator_creates_only_declared_paths(tmp_path: Path) -> None:
    plan = load_gitleaks_corpus_plan(PLAN_PATH)
    benchmark_root = tmp_path / "gitleaks"
    benchmark_root.mkdir()

    generate_gitleaks_corpus(plan, benchmark_root.resolve())

    assert set(_generated_bytes(benchmark_root)) == {
        Path(case.relative_path).relative_to("corpus").as_posix()
        for case in plan.cases
    }
    assert not (benchmark_root / "corpus/.git").exists()


def test_generator_rejects_preexisting_unexpected_file(tmp_path: Path) -> None:
    plan = load_gitleaks_corpus_plan(PLAN_PATH)
    benchmark_root = tmp_path / "gitleaks"
    benchmark_root.mkdir()
    generate_gitleaks_corpus(plan, benchmark_root.resolve())
    (benchmark_root / "corpus/unlisted.txt").write_text(
        "unlisted\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="generation is invalid"):
        generate_gitleaks_corpus(plan, benchmark_root.resolve())


def test_generator_rejects_symlinked_output_root(tmp_path: Path) -> None:
    plan = load_gitleaks_corpus_plan(PLAN_PATH)
    real_root = tmp_path / "real"
    real_root.mkdir()
    linked_root = tmp_path / "linked"
    linked_root.symlink_to(real_root, target_is_directory=True)

    with pytest.raises(ValueError, match="generation is invalid"):
        generate_gitleaks_corpus(plan, linked_root.absolute())


def test_generator_rejects_symlinked_intermediate_directory(
    tmp_path: Path,
) -> None:
    plan = load_gitleaks_corpus_plan(PLAN_PATH)
    benchmark_root = tmp_path / "gitleaks"
    corpus = benchmark_root / "corpus"
    corpus.mkdir(parents=True)
    external = tmp_path / "external"
    external.mkdir()
    (corpus / "aws-access-token").symlink_to(
        external,
        target_is_directory=True,
    )

    with pytest.raises(ValueError, match="generation is invalid"):
        generate_gitleaks_corpus(plan, benchmark_root.resolve())


def test_generator_has_no_entropy_network_or_external_execution() -> None:
    source = GENERATOR_PATH.read_text(encoding="utf-8")
    tree = ast.parse(source)
    forbidden_imports = {
        "random",
        "secrets",
        "socket",
        "subprocess",
        "time",
        "urllib",
        "uuid",
    }
    imported = {
        alias.name.split(".", 1)[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    } | {
        node.module.split(".", 1)[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module is not None
    }
    calls = {
        node.func.attr
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
    }

    assert imported.isdisjoint(forbidden_imports)
    assert calls.isdisjoint({"Popen", "run", "system"})
    assert "shell=True" not in source
    assert "openssl" not in source.lower()


@pytest.mark.parametrize(
    ("recipe_name", "payload"),
    (
        ("github-pat-high-entropy-a", b""),
        ("github-pat-high-entropy-a", b"ghp_too-short\n"),
        (
            "aws-akia-high-entropy",
            b"aws_access_key_id = AKIA7Q2W4E6R8T3Y5U7P\n",
        ),
    ),
)
def test_generator_rejects_invalid_recipe_output(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    recipe_name: str,
    payload: bytes,
) -> None:
    plan = load_gitleaks_corpus_plan(PLAN_PATH)
    recipe = gitleaks_corpus._CORE_RECIPES[recipe_name]
    monkeypatch.setitem(
        gitleaks_corpus._CORE_RECIPES,
        recipe_name,
        replace(recipe, payload=payload),
    )
    benchmark_root = tmp_path / "gitleaks"
    benchmark_root.mkdir()

    with pytest.raises(ValueError, match="generation is invalid"):
        generate_gitleaks_corpus(plan, benchmark_root.resolve())


def test_private_key_and_pkcs12_fixtures_are_nonoperational(
    tmp_path: Path,
) -> None:
    plan = load_gitleaks_corpus_plan(PLAN_PATH)
    benchmark_root = tmp_path / "gitleaks"
    benchmark_root.mkdir()
    generate_gitleaks_corpus(plan, benchmark_root.resolve())
    generated = _generated_bytes(benchmark_root)

    private_cases = {
        path: payload
        for path, payload in generated.items()
        if path.startswith("private-key/")
    }
    positives = {
        path: payload
        for path, payload in private_cases.items()
        if "/positive-" in f"/{path}"
    }
    assert len(private_cases) == 6
    assert all(b"SYNTHETIC-NONCRYPTO" in payload for payload in positives.values())
    assert all(payload.count(b"-----BEGIN") == 1 for payload in positives.values())
    assert all(payload.count(b"-----END") == 1 for payload in positives.values())

    pkcs12_cases = {
        path: payload
        for path, payload in generated.items()
        if path.startswith("pkcs12-file/")
    }
    assert len(pkcs12_cases) == 6
    assert all(b"-----BEGIN PRIVATE KEY-----" not in payload for payload in pkcs12_cases.values())
    assert all(b"-----BEGIN CERTIFICATE-----" not in payload for payload in pkcs12_cases.values())
    assert pkcs12_cases["pkcs12-file/positive-01.p12"] == b""
    assert pkcs12_cases["pkcs12-file/positive-02.pfx"] == b""


def test_materialized_manifest_is_canonical_and_frozen() -> None:
    manifest = verify_gitleaks_benchmark(ROOT.resolve())

    assert len(manifest.cases) == 48
    assert manifest.corpus_digest == GITLEAKS_CORPUS_DIGEST
    assert hashlib.sha256(MANIFEST_PATH.read_bytes()).hexdigest() == (
        GITLEAKS_CORPUS_MANIFEST_SHA256
    )
    assert MANIFEST_PATH.read_bytes() == manifest.canonical_json()
    assert load_benchmark_manifest(MANIFEST_PATH) == manifest


def test_materialization_replays_byte_identically(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    plan_path = repository / GITLEAKS_CORPUS_PLAN_PATH
    plan_path.parent.mkdir(parents=True)
    plan_path.write_bytes(PLAN_PATH.read_bytes())

    first = materialize_gitleaks_benchmark(repository.resolve())
    first_manifest = (repository / GITLEAKS_CORPUS_MANIFEST_PATH).read_bytes()
    first_files = _generated_bytes(plan_path.parent)
    second = materialize_gitleaks_benchmark(repository.resolve())

    assert first == second
    assert first_manifest == MANIFEST_PATH.read_bytes()
    assert first_files == _generated_bytes(plan_path.parent)
    assert verify_gitleaks_benchmark(repository.resolve()) == first


def test_manifest_rejects_changed_missing_unlisted_and_symlinked_files(
    tmp_path: Path,
) -> None:
    repository = tmp_path / "repository"
    plan_path = repository / GITLEAKS_CORPUS_PLAN_PATH
    plan_path.parent.mkdir(parents=True)
    plan_path.write_bytes(PLAN_PATH.read_bytes())
    materialize_gitleaks_benchmark(repository.resolve())
    case_path = plan_path.parent / "corpus/github-pat/positive-01.txt"

    case_path.write_bytes(b"changed\n")
    with pytest.raises(ValueError, match="corpus is invalid"):
        verify_gitleaks_benchmark(repository.resolve())

    material = _generated_bytes(ROOT / "benchmarks/gitleaks")
    case_path.write_bytes(material["github-pat/positive-01.txt"])
    case_path.unlink()
    with pytest.raises(ValueError, match="corpus is invalid"):
        verify_gitleaks_benchmark(repository.resolve())

    case_path.write_bytes(material["github-pat/positive-01.txt"])
    (plan_path.parent / "corpus/unlisted.txt").write_bytes(b"unlisted\n")
    with pytest.raises(ValueError, match="corpus is invalid"):
        verify_gitleaks_benchmark(repository.resolve())

    (plan_path.parent / "corpus/unlisted.txt").unlink()
    case_path.unlink()
    case_path.symlink_to(tmp_path / "external-file")
    with pytest.raises(ValueError, match="corpus is invalid"):
        verify_gitleaks_benchmark(repository.resolve())


def test_manifest_rejects_symlinked_corpus_directory(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    plan_path = repository / GITLEAKS_CORPUS_PLAN_PATH
    plan_path.parent.mkdir(parents=True)
    plan_path.write_bytes(PLAN_PATH.read_bytes())
    materialize_gitleaks_benchmark(repository.resolve())
    corpus = plan_path.parent / "corpus"
    moved = tmp_path / "moved-corpus"
    os.replace(corpus, moved)
    corpus.symlink_to(moved, target_is_directory=True)

    with pytest.raises(ValueError, match="corpus is invalid"):
        verify_gitleaks_benchmark(repository.resolve())


def test_manifest_contains_only_prescan_metadata() -> None:
    payload = MANIFEST_PATH.read_bytes()
    document = json.loads(payload)
    forbidden_keys = {
        "findings",
        "fingerprint",
        "match",
        "metrics",
        "observations",
        "precision",
        "raw_stderr",
        "raw_stdout",
        "recall",
        "results",
        "secret",
        "tp",
        "fp",
        "fn",
        "tn",
    }

    def keys(value: object) -> set[str]:
        if isinstance(value, dict):
            return {str(key).lower() for key in value} | set().union(
                *(keys(item) for item in value.values())
            )
        if isinstance(value, list):
            return set().union(*(keys(item) for item in value))
        return set()

    assert keys(document).isdisjoint(forbidden_keys)
    for fixture in (ROOT / "benchmarks/gitleaks/corpus").rglob("*"):
        if fixture.is_file() and fixture.stat().st_size:
            assert fixture.read_bytes() not in payload
