# SecureScan Source V1.5 demo runbook

Prerequisites: a ready isolated V1.5.1 operator deployment, one durable project,
one controlled vulnerable repository, an explicitly promoted baseline, an
eligible intelligence bundle, and a threat-policy JSON file. This is a 5-10
minute product tour after scanners and fixtures are prepared.

Select the private application profile with
`export SECURESCAN_OPERATOR_PROFILE=/path/to/operator.profile`, then use
`securescan system config` and `securescan doctor`. Do not source the profile;
SecureScan loads its versioned JSON automatically.

1. Run `securescan ci REPOSITORY --project-id ... --bundle-id ... --policy ...`.
2. Copy the candidate run/proof IDs from `ci-result.json`.
3. Open the run's Assurance Dashboard with `bundle` and `proof` query values.
4. Show Security Delta, coverage, governance, policy result, and proof reasons.
5. Open a dependency Knowledge Card; show OSV/CVE/NVD/CVSS/KEV/EPSS provenance.
6. Open a SAST card; show CWE guidance and the bounded verification playbook.
7. Show expected FAIL and distinguish it from operational ERROR.
8. Inspect `decision-proof.json`, `results.sarif`, `sbom.cdx.json`, and `summary.md`.
9. Open/print `assessment.html`.
10. Optional only: if AI is configured, ask “Why did this release fail?” and
    point out the `AI-generated explanation` label.
11. Remove the controlled issue, rescan, and show lifecycle and delta changes.
12. Re-evaluate policy and show the fixture's expected PASS.

Baseline promotion is a separate explicit operator action and must not occur in
this flow. For an intelligence-only demonstration, select a newer controlled
bundle for the unchanged verified run, create a new append-only assessment and
proof, and show that the original assessment/proof and finding identity remain.

Never use public repositories or live threat feeds as mandatory demo evidence.
