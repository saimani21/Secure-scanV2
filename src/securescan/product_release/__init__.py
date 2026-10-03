"""V1.5 product surfaces over the frozen assurance core."""

from .ai import (
    AIContextBuilder,
    AIProviderError,
    AIResponse,
    AITask,
    DisabledProvider,
    OpenAIProvider,
)
from .models import CIResult, ProductAssuranceError
from .presentation import render_assessment_html, render_ci_summary
from .service import ProductAssuranceService

__all__ = [
    "AIContextBuilder",
    "AIProviderError",
    "AIResponse",
    "AITask",
    "CIResult",
    "DisabledProvider",
    "OpenAIProvider",
    "ProductAssuranceError",
    "ProductAssuranceService",
    "render_assessment_html",
    "render_ci_summary",
]
