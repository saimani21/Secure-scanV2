# ADR-001: Modular monolith with a separate scan worker

## Status
Accepted for Version 0.1.

## Decision
Use one Python codebase and one relational domain model. Keep scanner execution behind an executor interface and run the eventual worker separately from the public API.

## Rationale
This keeps transactions, schemas, and debugging simple while preventing scanner-specific code from entering the API layer. It also leaves a clean seam for future remote Android, binary, and sandbox workers.
