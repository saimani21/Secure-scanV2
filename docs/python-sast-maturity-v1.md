# Python SAST maturity decision v1

Decision: `SCANNABLE`

SecureScan retains `PYTHON_SAST` at `SCANNABLE`. This means the frozen
17-rule Python baseline has deterministic production execution and bounded
evidence-backed behavior. It does not mean comprehensive Python SAST coverage.

## Evidence summary

- F1 controlled local: `TP=51 FP=0 FN=0 TN=51 precision=1.0000 recall=1.0000 F1=1.0000` across 102 relations; 17/17 rules represented.
- F2D external synthetic: `TP=400 FP=0 FN=0 TN=179 precision=1.0000 recall=1.0000 F1=1.0000` across 579 frozen historical-v1 expectations.
- F2E5 corrected real world: `TP=11 FP=0 FN=0 TN=3 precision=1.0000 recall=1.0000 F1=1.0000` across 14 expectations; 7/7 applicable vulnerable CVEs detected.
- Real-world representation: 4/17 rules; 13/17 have no applicable real-world evidence in the current corpus.

Perfect bounded results do not establish universal precision, recall, or
vulnerability detection.

## Maturity reasoning

- The frozen production path is deterministic and has evidence-backed parsing, execution, provenance, and rule behavior.
- All 17 rules have controlled local evidence, but only 10 have any frozen external synthetic evidence and that evidence uses historical-v1 claim expectations.
- Only 4 of 17 rules have claim-applicable real-world CVE evidence in the current bounded corpus.
- No frozen project policy defines a BENCHMARKED promotion gate satisfied by these inputs, so bounded perfect metrics do not authorize promotion.
- SCANNABLE records production-ready deterministic execution for this supported baseline without claiming comprehensive Python vulnerability coverage.

## Supported claims

- SecureScan provides deterministic Python SAST using 17 frozen project-owned Semgrep rules.
- The supported rules cover selected dangerous APIs and explicit insecure Python patterns within their frozen syntactic claims.
- All 17 rules have positive and negative evidence in the controlled project-owned handcrafted local benchmark.
- Frozen historical-v1 external synthetic expectations produced 400 TP, 0 FP, 0 FN, and 179 TN.
- The corrected real-world evaluation detected all 7 claim-applicable vulnerable CVEs in the frozen 13-CVE corpus.
- Only 4 of 17 rules currently have applicable real-world CVE evidence.
- Analysis failures and gaps are reported separately and cannot be treated as clean.

## Prohibited claims

- 100% Python vulnerability detection
- complete Python SAST coverage
- all CWE coverage
- all CVE detection
- taint analysis
- reachability analysis
- exploitability analysis
- attacker-control proof
- interprocedural dataflow analysis
- zero false positives in arbitrary repositories
- zero false negatives in arbitrary repositories
- equivalence to CodeQL or commercial enterprise SAST
- universal 1.0000 precision or recall

## Rule evidence matrix

| Rule | CWEs | Claim class | Production | Local + | Local - | External + | External - | Real-world CVEs | Discrimination | Limitations | Strength |
|---|---:|---|---|---:|---:|---:|---:|---:|---|---|---|
| `securescan.python.dangerous-eval` | 94, 95 | dangerous-api-observation | FROZEN_PRODUCTION_RULE | 3 | 3 | 106 | 0 | 2 | should 0/0; persistent 2/2 | syntactic call and static-string exclusion only; no binding, taint, or reachability claim | CONTROLLED_PLUS_REAL_WORLD |
| `securescan.python.dangerous-exec` | 94, 95 | dangerous-api-observation | FROZEN_PRODUCTION_RULE | 3 | 3 | 34 | 0 | 0 | should 0/0; persistent 0/0 | syntactic call and static-string exclusion only; no binding, taint, or reachability claim | CONTROLLED_PLUS_EXTERNAL |
| `securescan.python.flask-debug-enabled` | 489 | explicit-insecure-pattern | FROZEN_PRODUCTION_RULE | 3 | 3 | 0 | 0 | 0 | should 0/0; persistent 0/0 | same-or-ancestor-scope constructor sequence and literal true only; no binding, deployment, alias-flow, or interprocedural identity claim | CONTROLLED_ONLY |
| `securescan.python.insecure-tempfile-mktemp` | 377 | dangerous-api-observation | FROZEN_PRODUCTION_RULE | 3 | 3 | 0 | 0 | 0 | should 0/0; persistent 0/0 | canonical call surface plus Semgrep import equivalence; no binding, race exploitability, or attacker-control claim | CONTROLLED_ONLY |
| `securescan.python.jinja-autoescape-disabled` | 79 | explicit-insecure-pattern | FROZEN_PRODUCTION_RULE | 3 | 3 | 0 | 5 | 0 | should 0/0; persistent 0/0 | canonical constructor surface and literal false only; no binding, template-flow, or rendering-context claim | CONTROLLED_PLUS_EXTERNAL |
| `securescan.python.jwt-signature-verification-disabled` | 347 | explicit-insecure-pattern | FROZEN_PRODUCTION_RULE | 3 | 3 | 0 | 0 | 0 | should 0/0; persistent 0/0 | canonical call surface and inline literal dictionary entry only; no binding, token-flow, or unrelated validation-option claim | CONTROLLED_ONLY |
| `securescan.python.lxml-resolve-entities` | 611 | explicit-insecure-pattern | FROZEN_PRODUCTION_RULE | 3 | 3 | 60 | 60 | 0 | should 0/0; persistent 0/0 | canonical constructor surface and literal true only; no binding, XML source-flow, or parser-object dataflow claim | CONTROLLED_PLUS_EXTERNAL |
| `securescan.python.os-popen` | 78 | dangerous-api-observation | FROZEN_PRODUCTION_RULE | 3 | 3 | 0 | 0 | 0 | should 0/0; persistent 0/0 | canonical call surface plus Semgrep import equivalence; no binding, taint, or reachability claim | CONTROLLED_ONLY |
| `securescan.python.os-system` | 78 | dangerous-api-observation | FROZEN_PRODUCTION_RULE | 3 | 3 | 20 | 0 | 1 | should 1/1; persistent 0/0 | canonical call surface plus Semgrep import equivalence; no binding, taint, or reachability claim | CONTROLLED_PLUS_REAL_WORLD |
| `securescan.python.paramiko-autoaddpolicy` | 295 | explicit-insecure-pattern | FROZEN_PRODUCTION_RULE | 3 | 3 | 0 | 0 | 0 | should 0/0; persistent 0/0 | method name and policy-constructor surface only; no SSHClient receiver identity, binding, or object-flow claim | CONTROLLED_ONLY |
| `securescan.python.requests-session-verify-false` | 295 | explicit-insecure-pattern | FROZEN_PRODUCTION_RULE | 3 | 3 | 0 | 0 | 0 | should 0/0; persistent 0/0 | same-scope lexical assignment sequence and literal false only; no binding, alias-flow, or interprocedural object-identity claim | CONTROLLED_ONLY |
| `securescan.python.requests-verify-false` | 295 | explicit-insecure-pattern | FROZEN_PRODUCTION_RULE | 3 | 3 | 60 | 60 | 0 | should 0/0; persistent 0/0 | literal verify keyword and eight-name call family only; no binding, TLS reachability, or transport claim | CONTROLLED_PLUS_EXTERNAL |
| `securescan.python.sql-fstring-execute` | 89 | direct-interpolation-sink | FROZEN_PRODUCTION_RULE | 3 | 3 | 0 | 14 | 0 | should 0/0; persistent 0/0 | direct call argument shape only; no SQL sink identity, taint, variable tracking, or interprocedural claim | CONTROLLED_PLUS_EXTERNAL |
| `securescan.python.ssl-unverified-context` | 295 | explicit-insecure-pattern | FROZEN_PRODUCTION_RULE | 3 | 3 | 0 | 0 | 0 | should 0/0; persistent 0/0 | canonical call surface plus Semgrep import equivalence; no binding, TLS reachability, or transport claim | CONTROLLED_ONLY |
| `securescan.python.subprocess-shell-true` | 78 | explicit-insecure-pattern | FROZEN_PRODUCTION_RULE | 3 | 3 | 47 | 14 | 1 | should 1/1; persistent 0/0 | literal shell keyword and five-name call family only; no binding, command taint, or reachability claim | CONTROLLED_PLUS_REAL_WORLD |
| `securescan.python.unsafe-pickle-load` | 502 | dangerous-api-observation | FROZEN_PRODUCTION_RULE | 3 | 3 | 44 | 0 | 3 | should 1/1; persistent 2/2 | canonical call surface plus Semgrep import equivalence; no binding, serialized-data taint, or reachability claim | CONTROLLED_PLUS_REAL_WORLD |
| `securescan.python.unsafe-yaml-load` | 502 | explicit-insecure-pattern | FROZEN_PRODUCTION_RULE | 3 | 3 | 29 | 26 | 0 | should 0/0; persistent 0/0 | enumerated call and loader shapes only; no binding, deserialization taint, or object-flow claim; FullLoader remains outside the frozen claim | CONTROLLED_PLUS_EXTERNAL |

Rules without real-world representation are classified as
`NO_APPLICABLE_REAL_WORLD_EVIDENCE_IN_CURRENT_CORPUS`; they are not failed
rules or false negatives.

## Limitations

- Every precision, recall, and F1 value applies only to its frozen scored relations.
- F2D is synthetic historical evidence under the v1 claim contract and is not complete proof of current production semantics.
- Only four production rules have applicable real-world CVE evidence in the current 13-CVE corpus.
- Rules without applicable real-world evidence are unrepresented, not failed rules or false negatives.
- Several rules intentionally detect dangerous API use without proving attacker control, reachability, or exploitability.
- The ruleset provides no general taint or interprocedural dataflow analysis.
- Related CVEs and repeated project families do not provide fully independent diversity.

## Next required evidence

- Claim-applicable real-world cases for the 13 currently unrepresented rules.
- Broader independent project and vulnerability-family diversity with frozen pre-scan expectations.
- An explicit approved promotion policy defining BENCHMARKED and PRODUCT_SUPPORTED evidence thresholds.
- Upgrade-specific replay evidence whenever the scanner or production ruleset identity changes.
