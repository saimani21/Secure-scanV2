# SecureScan Source V1.3 component identity

## Existing evidence identity

Syft normalizes an observed PURL with `packageurl-python` and constructs `package_key` from the
exact tuple `(package_type, package_name, package_version, purl)`. S4 preserves that key as the
native package identity and derives `component_ref` from it. V1.3 does not rewrite any of these
frozen identities.

Package observation identity remains distinct from package identity: the observation also binds
the cataloger and normalized locations. OSV findings point to the S4 package component and cannot
create a new component.

## Interoperability mapping

For export, `InteroperablePackageIdentity` applies this deterministic order:

1. use an observed canonical PURL when its supported ecosystem, name, and version agree with the
   S4 coordinates;
2. otherwise derive a PURL only for an exact version in a supported mapping;
3. otherwise retain an explicit SecureScan package-key fallback and omit PURL.

Supported deterministic derivations are:

| Syft package type | PURL type | Name rule |
| --- | --- | --- |
| `python` | `pypi` | PEP 503-style canonical package name through the frozen OSV mapper |
| `npm` | `npm` | preserve package name; split a leading `@scope/name` into namespace/name |
| `go-module` | `golang` | split the module path at its final slash |

A missing version never becomes an invented version. Unsupported ecosystems remain valid S4
components but receive no synthesized PURL.

## Stable references and duplicates

CycloneDX `bom-ref` is `urn:securescan:component:<S4 component_ref>`. The document root is
`urn:securescan:run:<run_id>`. Component ordering is by `bom-ref`, and duplicate references fail
closed. Because S4 already rejects duplicate `component_ref` values, this preserves one component
per authoritative identity.

The CycloneDX serial number is UUIDv5 over run ID plus verified report-artifact digest. Repeating
an export of the same published run is byte-stable. A different artifact cannot silently retain
the same serial number.

## Relationship boundary

Current S4 proves that packages were observed in the repository scan. It does not prove package
manager direct/transitive edges. V1.3 exports the component inventory and omits `dependencies`
rather than representing every observed package as a direct dependency. A future graph may be
added only from evidence that records and verifies those edges.

SPDX export is intentionally deferred. CycloneDX 1.7 JSON is the single Prompt 1 SBOM format.
