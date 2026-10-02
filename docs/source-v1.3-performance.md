# SecureScan Source v1.3 performance characterization

## Method and environment

The reproducible harness is `scripts/source_v13_performance.py`. It creates
only disposable directories and a disposable SQLite database. It measures the
real managed-workspace intake, inventory, coverage/profile construction,
planning, CAS-backed published-S4 verification, Product Core indexing,
Product View, Security Delta, policy and CycloneDX code paths.

The repository-shape portion deliberately does not execute scanners or call an
external service. Enry classification is replaced by a deterministic
in-process classifier so the measurement isolates SecureScan-owned work. The
Product Core portion uses the fixed controlled S4 fixture (one delta finding),
not a report scaled to the repository file counts. These numbers are therefore
characterization evidence, not end-to-end scanner throughput promises.

Command:

```bash
python scripts/source_v13_performance.py --include-large
```

Measured on Linux 6.6.87.1 under WSL2, x86-64, Python 3.12.3. Values below are
from the October 2, 2026 release-candidate run and should be remeasured on a
target deployment rather than treated as an SLA.

## Repository-shape results

| Shape | Files | Bytes | Intake | Inventory | Profile | Plan |
|---|---:|---:|---:|---:|---:|---:|
| Small | 1,000 | 32,000 | 0.147 s | 0.148 s | 0.207 s | 0.051 s |
| Medium | 10,000 | 320,000 | 1.939 s | 1.896 s | 2.343 s | 0.644 s |
| Large | 50,000 | 1,600,000 | 5.900 s | 11.078 s | 15.601 s | 3.933 s |
| Pathological | 1,000 | 687,270 | 0.132 s | 0.287 s | 0.454 s | 0.207 s |

The pathological shape uses 16 bounded directory levels and a 64 KiB line in
every hundredth file. All four cases completed and produced one deterministic
repository-level Source SAST plan entry. Whole-process peak RSS across the
complete run was 196,368 KiB.

## Product Core sample

The fixed controlled S4 sample measured:

| Operation | Result |
|---|---:|
| Product Core indexing | 0.030 s |
| Product View | 0.025 s |
| Security Delta | 0.021 s |
| Policy evaluation | 0.054 s |
| CycloneDX 1.7 export | 0.000033 s |
| CycloneDX output | 763 bytes |
| CAS artifact storage | 35,294 bytes |
| SQLite database | 487,424 bytes |

The deliberately partial controlled report yielded Security Delta `PARTIAL`
and policy `ERROR`, preserving unknown-as-not-clean semantics.

## Tested envelope and limits

SecureScan-owned intake/profile/planning completed at the requested 50,000-file
target in this environment. This does not establish scanner throughput at that
scale, PostgreSQL capacity, concurrent-user latency, or a production resource
guarantee. Scanner containers keep their existing time, memory, process,
stdout, stderr and temporary-storage bounds. Enry keeps its existing bounded
batch size and payload limits; repository file sampling remains bounded.

The product model currently proves package inventory, not dependency graph
edges, so the harness does not fabricate a huge or deep dependency graph and
CycloneDX omits a `dependencies` section. Governance and suppression history
APIs retain their 200-event page maximum. Unicode/path bounds, malformed
evidence, finding limits, lifecycle/event integrity, large output handling and
resource containment are exercised by the hostile and parser regression suites.
