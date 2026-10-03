from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager

from fastapi import FastAPI
from fastapi.testclient import TestClient

from securescan.api.product_release_routes import get_product_service, router
from securescan.product_release import AIContextBuilder, AIResponse, DisabledProvider

RUN_ID = "00000000-0000-4000-8000-00000000a501"


class _Service:
    def dashboard(self, **scope):
        return {
            "decision": "PASS",
            "scope": scope,
            "proof": {"decisions": []},
            "findings": [],
            "coverage": {"complete": True},
            "delta": {"comparison_status": "COMPLETE"},
            "threat": {},
            "governance": {},
            "intelligence": {"bundle_id": scope["bundle_id"]},
            "proof_id": scope["proof_id"],
        }

    def knowledge_card(self, **scope):
        return {
            "finding_id": scope["finding_id"],
            "policy_decisions": [],
            "limitations": [],
        }


class _Provider:
    def explain(self, **_):
        return AIResponse(
            answer="Bounded answer",
            evidence_refs=(),
            limitations=("No exploitability claim.",),
            generated_by_model="mock",
        )


@contextmanager
def _client(provider) -> Iterator[TestClient]:
    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[get_product_service] = lambda: _Service()
    app.state.ai_provider = provider
    app.state.ai_context_builder = AIContextBuilder()
    app.state.ai_allow_source_snippets = False
    with TestClient(app) as client:
        yield client


def _query() -> str:
    return "project_id=p&lineage_id=l&bundle_id=" + "a" * 64 + "&proof_id=" + "b" * 64


def test_dashboard_and_html_are_same_origin_read_surfaces() -> None:
    with _client(DisabledProvider()) as client:
        response = client.get(f"/v1/assurance/runs/{RUN_ID}?{_query()}")
        assert response.status_code == 200
        assert response.json()["decision"] == "PASS"
        report = client.get(f"/v1/assurance/runs/{RUN_ID}/assessment.html?{_query()}")
        assert report.status_code == 200
        assert report.headers["x-content-type-options"] == "nosniff"
        assert "default-src 'none'" in report.headers["content-security-policy"]


def test_disabled_ai_is_quietly_unavailable_without_breaking_dashboard() -> None:
    with _client(DisabledProvider()) as client:
        response = client.post(
            f"/v1/assurance/runs/{RUN_ID}/assistant",
            json={
                "project_id": "p",
                "lineage_id": "l",
                "bundle_id": "a" * 64,
                "proof_id": "b" * 64,
                "task": "SUMMARIZE_RUN",
                "question": "Summarize this run.",
            },
        )
        assert response.status_code == 503
        assert response.json() == {"detail": "AI Assistant is not configured"}
        assert client.get(f"/v1/assurance/runs/{RUN_ID}?{_query()}").status_code == 200


def test_mocked_ai_response_is_labeled_and_contains_no_provider_secret() -> None:
    with _client(_Provider()) as client:
        response = client.post(
            f"/v1/assurance/runs/{RUN_ID}/assistant",
            json={
                "project_id": "p",
                "lineage_id": "l",
                "bundle_id": "a" * 64,
                "proof_id": "b" * 64,
                "task": "SUMMARIZE_RUN",
                "question": "Summarize this run.",
            },
        )
        assert response.status_code == 200
        assert response.json()["label"] == "AI-generated explanation"
        assert response.json()["answer"] == "Bounded answer"
        assert "OPENAI_API_KEY" not in response.text


def test_assistant_rejects_unknown_task_and_oversized_question() -> None:
    with _client(_Provider()) as client:
        base = {
            "project_id": "p",
            "lineage_id": "l",
            "bundle_id": "a" * 64,
            "proof_id": "b" * 64,
            "question": "ok",
        }
        assert (
            client.post(
                f"/v1/assurance/runs/{RUN_ID}/assistant",
                json={**base, "task": "MUTATE_POLICY"},
            ).status_code
            == 422
        )
        assert (
            client.post(
                f"/v1/assurance/runs/{RUN_ID}/assistant",
                json={**base, "task": "SUMMARIZE_RUN", "question": "x" * 2_001},
            ).status_code
            == 422
        )
