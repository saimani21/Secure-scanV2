# Syft S1 controlled inventory evidence

SecureScan Source S1 pins Syft 1.51.0 for package/component inventory of the
immutable current Source projection. Syft inventories package evidence; a
future S2 may correlate normalized coordinates with OSV. S1 performs no
vulnerability or CVE matching.

## Trusted execution

The official `syft_1.51.0_linux_amd64.tar.gz` archive has SHA-256
`2a2e837a2c8d59ec9af5472ee22d3b04ee463c4e44476ecf993fd1e5ab6ebc7f`.
The extracted executable has SHA-256
`5a8b71e94f4607973145f02e27e01d50b9f7c7bc41e38d40b39606ad138b43b5`.
The frozen configuration has SHA-256
`4cf5feb873a8eef91b81d9869c95f0b317357ef3e8c7aa4b859f60f435770875`.
Production requires an explicitly supplied absolute executable and never uses
PATH lookup.

The exact scan contract is:

```text
<absolute-syft> scan <absolute-immutable-projection-root>
  --from dir
  --base-path <absolute-immutable-projection-root>
  --output syft-json
  --config <absolute-trusted-securescan-config>
  --quiet
  --parallelism 4
```

The child environment is empty. Syft exposes no native timeout for this command,
so the inner timeout is null and the process executor enforces an outer timeout
of 300 seconds. Stdout is bounded to 100 MiB and stderr to 64 KiB. The
configuration disables update checks, enrichment, archive traversal, remote
license searches, Java network use, Go package tooling/cache lookup, excludes,
and persistent cache use. No network-dependent operation is requested, but S1
does not claim an OS-level egress sandbox. Registry and image sources are not
permitted.

## Evidence and scope

`controlled-s1-evidence.json` is deterministic sanitized evidence from two
real pinned-binary runs over the project-owned corpus. It records normalized
identities, locations, used catalogers, counts, a zero-package fixture completion,
and structural repeatability. It excludes raw scanner output, arbitrary Syft
metadata, host and temporary paths, environment, and timestamps. The artifact
does not report accuracy metrics because the corpus characterizes structural
behavior rather than exhaustive package ground truth.

Directory defaults are requested, and the complete descriptor-provided
`used` cataloger list is recorded. A used cataloger is not a claim that it
found a package or inspected every selected byte. SecureScan supplies every
selected projection file—including test, documentation, generated, vendor,
dependency, unknown-language, and binary paths—while Syft decides which
evidence its catalogers understand.

The normalized `package_key` hashes type, name, version, and PURL. It excludes
paths, projection identity, Syft artifact IDs, host state, and time. The
`package_observation_id` hashes that key with the cataloger and sorted location
set. Equal package coordinates can therefore retain separate structural
observations.

Supported: current-snapshot inventory completion and exact normalized evidence
reported by pinned Syft. Limited: ecosystem/cataloger coverage and missing
versions/PURLs, which remain unresolved rather than inferred. Unsupported:
dependency kind, installation, imports, runtime use, reachability, exhaustive
discovery, advisory matching, vulnerability, CVE status, builds, package
installation, repository execution, images, registries, containers, and
network enrichment. Maturity is `PACKAGE_INVENTORY = SCANNABLE`, not
`BENCHMARKED`.

Run the controlled check or replay with:

```text
scripts/run-syft-s1.sh check
scripts/run-syft-s1.sh report
```
