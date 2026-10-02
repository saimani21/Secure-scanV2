"""Immutable vulnerability-intelligence ingestion and assurance projections."""

from .assurance import (
    AssuranceService,
    FindingIntelligence,
    PolicyDecisionProof,
    RunAssuranceView,
    ThreatPolicySpec,
)
from .cve import exact_cve_aliases, validate_cve_id
from .ingestion import (
    IntelligenceIngestionError,
    parse_epss_snapshot,
    parse_kev_snapshot,
    parse_nvd_enrichment,
)
from .models import (
    EpssState,
    IntelligenceBundle,
    IntelligenceSnapshot,
    IntelligenceSource,
    KevState,
    NvdEnrichment,
    ThreatAssessment,
)
from .service import IntelligenceService

__all__ = [
    "EpssState",
    "AssuranceService",
    "FindingIntelligence",
    "IntelligenceBundle",
    "IntelligenceIngestionError",
    "IntelligenceService",
    "IntelligenceSnapshot",
    "IntelligenceSource",
    "KevState",
    "NvdEnrichment",
    "PolicyDecisionProof",
    "RunAssuranceView",
    "ThreatAssessment",
    "ThreatPolicySpec",
    "exact_cve_aliases",
    "parse_epss_snapshot",
    "parse_kev_snapshot",
    "parse_nvd_enrichment",
    "validate_cve_id",
]
