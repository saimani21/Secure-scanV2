# Source v0.10 Product Core

## PC1: logical lineage and finding occurrence index

PC1 adds a thin query index over the already-published S4 report. The canonical
S4 document in the final content-addressed artifact and `AnalysisRun.report_json`
remains authoritative. Product Core does not copy evidence, components,
scanner-native output, or complete finding documents.

A `source_target_lineage` is an explicit server-owned identity for Source runs
that belong to the same logical target across content revisions. It is linked
to a Project for ownership, but it is never inferred from a project name,
repository path, target name, content digest, Git metadata, or filesystem
location. Each published run is attached once, receives a sequence under a
lineage-row lock, and records the immediately preceding lineage run explicitly.

After S6D publication, one transaction verifies the terminal orchestration,
published report, frozen schema, artifact digest and size, canonical CAS bytes,
published JSON, run identity, and the report rebuilt through the frozen typed S4
assembly boundary. It then writes compact finding occurrences and marks the run
indexed atomically. Repeating an exact operation is idempotent; changed report,
membership, predecessor, or occurrence material fails closed.

Occurrences reuse S4 `finding_id` exactly and contain only authority, category,
native identity schema, optional severity, canonical subject/primary-location
summaries, report SHA, and ordinal. Expected S4 identity churn from moved spans,
changed package versions, changed resource identity, or changed native identity
is preserved. PC1 adds no fuzzy or cross-run fingerprint.

The index does not store source snippets, secrets, stdout/stderr, raw HTTP,
absolute workspace paths, native reports, Evidence objects, Component objects,
or package inventories. Rich data is loaded from authoritative S4 evidence when
needed.

PC1 does not implement finding lifecycle, first/last seen state, resolution,
priority, API, CLI, reporting UI, or final-report changes. Those remain later
Product Core slices.
