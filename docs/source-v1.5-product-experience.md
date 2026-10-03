# SecureScan Source V1.5 product experience

The V1.5 Web UI extends the dependency-free same-origin console. It does not
accept repository uploads. Open a verified run using a selected immutable
bundle and policy proof:

```text
/scans/<run-id>/assurance?bundle=<bundle-id>&proof=<proof-id>
```

The Assurance Dashboard shows PASS/FAIL/ERROR, Security Delta, coverage and
gaps, governance, exact CVE relationships, KEV membership, EPSS policy hits,
bundle/snapshot provenance, and deterministic DecisionProof reasons. It reads
the same `ProductAssuranceService` projection used by CI and the report.

Finding Knowledge Cards add exact per-finding context without changing finding
identity. Dependency cards show component/advisory/CVE relationships and typed
NVD/KEV/EPSS evidence. SAST, secret, and configuration findings remain
`NOT_APPLICABLE` for threat evidence unless verified evidence says otherwise.

Verification playbooks are bounded guidance. Supported CWE classes provide
manual checks and expected secure behavior; dependency and secret findings use
category-specific safe checks. A playbook never claims that a vulnerability is
exploitable, a credential has been revoked, or a proposed patch is correct.

`assessment.html` is deterministic, self-contained, escaped, and print-friendly.
It includes executive scope, coverage/limitations, policy, delta, intelligence,
technical findings, governance, proof identity, and explicit boundaries. It
contains no scripts and the API applies a restrictive CSP. AI is not required
and authoritative reports never depend on generated prose.

The UI renders untrusted evidence with DOM `textContent`; the HTML and Markdown
renderers escape hostile values. Browser code calls only same-origin SecureScan
endpoints.

`DISAPPEARANCE != RESOLUTION`, `FINDING != EXPLOITABILITY`,
`SEVERITY != BUSINESS RISK`, and `GUIDANCE != PATCH`.
