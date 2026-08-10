# ADR-002: Preserve sanitized native output before normalization

## Status
Accepted for Version 0.1.

## Decision
A scanner's output is sanitized, validated, hashed, and stored before it is parsed into observations.

## Rationale
Parsers evolve. Preserving sanitized native reports enables auditing, parser regression tests, and re-normalization without rerunning expensive tools.
