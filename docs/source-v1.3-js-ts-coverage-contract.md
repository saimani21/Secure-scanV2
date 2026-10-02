# SecureScan Source v1.3 JavaScript and TypeScript coverage contract

## Scope

SecureScan Source v1.3 adds bounded Semgrep SAST coverage for source files that
the frozen Enry profile identifies as JavaScript or TypeScript. That includes
`.js`, `.jsx`, `.ts`, and `.tsx` syntax when Enry reports the corresponding
language. Python coverage remains the frozen 17-rule Python baseline v2.

The production `securescan-source-baseline-v3` ruleset is deterministic: it is
the unchanged Python baseline v2 plus the separate
`securescan-javascript-typescript-v1.yml` rule pack. Its identity is recorded in
the Semgrep binding and in S4 provenance.

Applicability requires all of the following:

- Enry classified the file as Python, JavaScript, or TypeScript;
- the language policy is in an executable support state;
- the source SAST capability is in an executable support state;
- the file is text and is not marked binary; and
- the frozen path-selection policy did not exclude it.

A merely detected language is not scanned. Unsupported-only repositories do
not acquire a source SAST surface. The current production path-selection policy
does not exclude generated, vendored, or test files; they remain in declared
scope and are reported truthfully rather than silently omitted.

## Validated rule pack

| Rule | Intent | CWE | Validated positive | Explicit limitation |
|---|---|---:|---|---|
| `securescan.javascript.dynamic-eval` | Observe dynamic `eval` | CWE-95 | non-literal argument | Does not prove attacker control or reachability |
| `securescan.javascript.child-process-exec` | Observe `child_process.exec` and `execSync` | CWE-78 | Node child-process command execution | Does not model wrappers, sanitization, or attacker control |
| `securescan.javascript.child-process-shell` | Observe explicit `shell: true` | CWE-78 | spawn/execFile shell mode | Does not prove command injection |
| `securescan.javascript.request-derived-redirect` | Observe a direct Express-style request value used as a redirect target | CWE-601 | `query`, `params`, or `body` member passed directly | No interprocedural flow or allow-list reasoning |
| `securescan.javascript.sql-template-query` | Observe template interpolation passed directly to `query` or `execute` | CWE-89 | interpolated template query | Does not prove the interpolated value is hostile or the API executes SQL |
| `securescan.javascript.request-derived-path` | Observe a direct request value used in `path.join` or `path.resolve` | CWE-22 | `query` or `params` member passed directly | No interprocedural flow, canonicalization, or traversal exploitability claim |

Every rule has a deterministic positive, safe, and near-miss fixture. The
bounded corpus covers JavaScript, TypeScript, JSX, and TSX parsing. Semgrep Core
1.145.0 produced exactly six expected findings across 18 fixtures, with no
scanner errors and no safe or near-miss match. The release gate repeats this
against the pinned production image and declared Semgrep 1.171.0 tool identity.

## Product and lifecycle behavior

JS/TS findings use the existing Semgrep parser, sanitizer, canonical S4 native
identity, Product Core index, lifecycle, guidance, governance, suppression,
baseline, Security Delta, policy, API, CLI, JSON, SARIF, and Web UI paths. There
is no JS/TS-specific fingerprint or UI model.

V1.3 uses the additive `SOURCE_SAST` planning capability and
`semgrep-source-v1` analyzer identity. `PYTHON_SAST` remains decodable for
historical V1.2 evidence but is not emitted by new plans. Because the v3
binding and ruleset digest differ from V1.2, the existing lifecycle comparator
marks the contract boundary non-comparable and withholds absence-based
resolution. No lifecycle code or schema migration is introduced.

## Third-language decision

Go and Java SAST are deferred. Neither can meet the same V1.3 bar—bounded
project-owned rules, deterministic applicability, representative validation,
identity evidence, and full regression proof—without materially extending the
release risk. SecureScan does not count scanner breadth as product support.

## Non-claims

This contract does not claim full JavaScript or TypeScript vulnerability
coverage, taint reachability, exploitability, framework completeness,
interprocedural analysis, or absence of vulnerabilities when no rule matches.
