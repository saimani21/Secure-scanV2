# SecureScan Source V1.5 optional AI Security Assistant

AI is disabled by default and is never part of deterministic evidence, finding
identity, lifecycle, governance, baseline, intelligence, policy, or exit-code
decisions. With AI disabled, scanning, CI, API, dashboard, reports, SARIF,
CycloneDX, and DecisionProof remain fully functional.

Optional installation and server configuration:

```bash
pip install 'securescan-core[ai]'
export SECURESCAN_AI_ENABLED=true
export SECURESCAN_AI_MODEL='<approved Responses API model>'
export OPENAI_API_KEY='<injected secret>'
```

The key is read only by the server process and is not placed in settings,
browser JavaScript, HTML, logs, report artifacts, or AI context. The browser
never calls OpenAI. If any setting or optional SDK is absent, only the assistant
is unavailable.

`AIContextBuilder` accepts only bounded authoritative read models, strips raw,
snippet, credential, API-key, and secret fields, redacts common credential bait,
and caps serialized context at 64 KiB. Source snippets remain disabled by
default. V1.5 has no product path that sends arbitrary repository contents.

The provider uses the OpenAI Responses API with `store=False`, no tools, one
bounded response, and structured JSON validation. Returned evidence references
are intersected with identifiers that were actually supplied. Provider errors,
timeouts, malformed output, or invented references cannot change the
authoritative decision.

Allowed tasks are explanation, policy explanation, CVSS/KEV/EPSS explanation,
remediation considerations, verification help, run summary, and draft report
text. Output is always labeled `AI-generated explanation` and must distinguish
verified evidence, deterministic guidance, and model suggestions.

The enforced invariant catalog is `AI-001` through `AI-012` in
[`security-invariants.md`](security-invariants.md). In short:
`AI EXPLANATION != SECURITY AUTHORITY`.
