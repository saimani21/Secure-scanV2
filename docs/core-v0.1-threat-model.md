# Core v0.1 threat model

## Trusted

- SecureScan application code and application-owned Semgrep ruleset
- the configured Docker daemon and container runtime
- the administrator-selected digest-pinned scanner image
- the PostgreSQL service and migration history

## Untrusted

- repository contents, filenames, directory structure, and hostile paths
- scanner JSON, messages, diagnostics, metadata, and process output
- job payload metadata and attempts to override trusted adapter configuration
- concurrent workers, stale leases, cancellation races, and recovery races

The design responds with deterministic snapshotting, manifest-bound paths, bounded
inputs and outputs, immutable trusted definitions, a locked-down container policy,
fencing tokens, atomic transactions, sanitized errors, and explicit analysis gaps.

## Explicitly out of scope

- a compromised Docker daemon or malicious host administrator
- a malicious digest-pinned image deliberately selected by an administrator
- kernel or container-runtime vulnerabilities
- remote repository authentication, cloning, or archive intake
- multi-tenant cloud isolation and distributed-worker deployment
- full Semgrep rule coverage, multi-language coverage, or broad SAST accuracy

Repository analysis does not replace manual review or a complete, maintained security
ruleset.
