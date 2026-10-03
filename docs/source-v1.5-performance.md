# SecureScan Source V1.5 intelligence performance characterization

Status: Prompt 1 bounded characterization, 2026-10-02

This is a measured envelope, not an unlimited scalability claim. The harness is
`python -m securescan.benchmarks.intelligence_v15`; its regression gate is
`tests/test_intelligence_performance_v15.py`.

## Environment

- Python 3.12.3
- 11th Gen Intel Core i5-1135G7, 4 cores / 8 threads
- 7.6 GiB RAM
- one local process
- SQLite for the import-persistence/query-count measurement
- peak process RSS: 147,888 KiB

## Results

| CVE relationships | KEV parse | EPSS parse | exact-CVE correlation | Finding Intelligence projection | assessment identities | Run Assurance aggregation | decision-proof serialization |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 100 | 0.0224 s | 0.0012 s | 0.0001 s | 0.0000 s | 0.0011 s | 0.0000 s | 0.0002 s |
| 1,000 | 0.0653 s | 0.0043 s | 0.0008 s | 0.0003 s | 0.0053 s | 0.0001 s | 0.0012 s |
| 10,000 | 0.6087 s | 0.0421 s | 0.0105 s | 0.0033 s | 0.0524 s | 0.0012 s | 0.0105 s |

At 10,000 relationships the generated KEV document was 2,870,103 bytes, the
compressed EPSS document was 25,861 bytes, and the deterministic proof document
was 1,650,087 bytes. Actual immutable import plus CAS persistence took 1.553 s
for KEV and 0.186 s for EPSS, using four SQL statements total for both imports.

The harness deliberately measures bounded normalized transforms. Production
`FindingIntelligence`, `ThreatAssessment`, `RunAssuranceView`, and
`PolicyDecisionProof` integrity behavior is separately exercised against real
service/database state; the synthetic scale loops do not claim end-to-end UI or
network throughput.

## Prompt 2 product-surface characterization

Measured on 2026-10-03 with Python 3.12.3 under WSL2 Linux
6.6.87.1 (`python -m securescan.benchmarks.product_release_v15`). The controlled
dashboard contained 500 findings; the bounded AI context contained 50 compact
finding summaries. Values are medians of 25 in-process iterations and exclude
scanner and external-provider network time.

| Operation | Median |
| --- | ---: |
| deterministic HTML assessment | 2.185 ms |
| deterministic Markdown CI summary | 0.015 ms |
| DecisionProof JSON serialization | 0.002 ms |
| bounded AI context build | 0.870 ms |
| AI context serialization | 0.064 ms |

The 500-finding HTML was 115,197 bytes; the CI summary was 629 bytes; the
50-finding AI context was 12,884 bytes against the enforced 64 KiB cap. Peak
process RSS observed by the harness was 78,484 KiB. These measurements
characterize SecureScan-owned presentation overhead, not database latency,
scanner throughput, browser paint time, or OpenAI latency.
