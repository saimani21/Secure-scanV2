# SecureScan Source V1.1C Web UI 2.0

## Status

V1.1C0 is the approved UI/API architecture and design contract. V1.1C1 is the
first implementation checkpoint: design tokens, application shell, explicit
browser routing, readiness presentation, and accessibility foundations. Product
pages remain intentionally unimplemented until their later checkpoints.

V1.1C is not frozen or complete.

## Architecture

The web product remains a dependency-free, same-origin interface:

```text
FastAPI
    -> packaged HTML shell
    -> first-party ES modules
    -> first-party CSS
    -> existing frozen read APIs
```

There is no frontend framework, Node production process, external asset, font
CDN, frontend container, or browser build pipeline. JavaScript is split by
responsibility into bootstrap, API, router, state, formatting, and component
modules. CSS is split into tokens, base rules, shell layout, and view primitives.

## Explicit frontend routes

The server returns the same shell only for these allowlisted routes:

```text
/
/projects
/projects/{project UUID}
/scans
/scans/{run UUID}
/scans/{run UUID}/findings
/scans/{run UUID}/dependencies
/scans/{run UUID}/coverage
/scans/{run UUID}/gaps
/scans/{run UUID}/report
```

Project and run identifiers are validated as UUIDs by FastAPI and as canonical
UUIDs by the browser router. There is no wildcard SPA route. API, health, and
asset paths are explicitly excluded from browser routing. Native same-origin
anchors use `pushState`; `popstate` restores back/forward navigation, and every
allowlisted deep link can be refreshed directly.

## Design system

The active visual system uses the approved graphite surfaces, thin borders,
system typography, technical monospace values, restrained acid-lime accent,
4/7/10 pixel radii, and no normal content shadow. The only shadow token belongs
to the mobile navigation drawer. Gradients, backdrop blur, glass effects, neon,
large rounded cards, decorative security imagery, gauges, and fake scores are
not part of the system.

The desktop sidebar is 232 pixels. The intermediate layout uses a 72-pixel
compact sidebar. Below 768 pixels, navigation becomes an accessible modal drawer
with focus containment, Escape handling, focus restoration, and an inert
background. Interactive targets are at least 40 pixels and reduced-motion
preferences disable the short layout transitions.

## Security invariants

- Every API and repository-derived string is untrusted display text.
- DOM content is constructed with `textContent`, safe properties, and explicit
  elements; HTML injection and dynamic code execution APIs are prohibited.
- The browser performs only same-origin GET requests in C1.
- The shell consumes only `GET /health/ready`; a structured 503 response remains
  a truthful not-ready state, while no response is shown as unavailable.
- The CSP remains self-only without `unsafe-inline` or `unsafe-eval`.
- Frontend assets are served from an explicit filename allowlist.
- Shell and asset responses use `Cache-Control: no-cache` so an upgrade cannot
  retain incompatible modules under stable filenames.
- Route changes abort pending requests and generation guards prevent late
  responses from mutating a newer route.

## Trusted-host boundary

The browser remains read-only for repository intake. It does not accept local
paths, uploads, source content, or arbitrary Git URLs. Repository preparation
and scan submission remain trusted-host CLI operations. C1 contains no project,
scan, finding, dependency, coverage, gap, or report read implementation beyond
truthful route shells.

## Checkpoint plan

```text
C1  design system, shell, routing
C2  overview, projects, project history, scans
C3  scan overview and progress
C4  findings and detail
C5  dependencies and detail
C6  coverage, gaps, report
C7  responsive, accessibility, hostile-input hardening
C8  isolated E2E, visual acceptance, final freeze
```

Later phases must continue to present frozen Product Core truth. They may format
or group exact returned values, but must not infer security state, fabricate
remediation or lifecycle history, count advisory aliases as vulnerabilities, or
turn partial, failed, unknown, or not-applicable states into zero.
