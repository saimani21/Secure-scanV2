# ADR-003: Scanner failure is never a clean result

## Status
Accepted for Version 0.1.

## Decision
Timeouts, invalid output, unsupported targets, and unavailable tools create explicit analysis gaps and make the overall run partial.

## Rationale
A failed analyzer provides no evidence that a target is secure.
