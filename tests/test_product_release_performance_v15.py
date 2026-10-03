from __future__ import annotations

from securescan.benchmarks.product_release_v15 import characterize, controlled_dashboard
from securescan.product_release.presentation import render_assessment_html


def test_large_product_projection_is_bounded_deterministic_and_fast() -> None:
    dashboard = controlled_dashboard(500)
    assert render_assessment_html(dashboard) == render_assessment_html(dashboard)
    result = characterize()
    assert result["finding_count"] == 500
    assert result["output_bytes"]["ai_context"] < 64 * 1024
    assert max(result["median_ms"].values()) < 2_000
