# SecureScan Source V1.1C Web UI 2.0

## Status

V1.1C0 is the approved UI/API architecture and design contract. V1.1C1
established design tokens, the application shell, explicit browser routing,
readiness presentation, and accessibility foundations. V1.1C2 added real
Overview, Projects, Project Detail, and Global Scans navigation while preserving
the frozen read API and Product Core contracts. V1.1C3 adds the real Scan
Overview and authoritative Analysis stage progress. Findings, dependencies,
coverage detail, gaps, and reports remain later checkpoints.

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
- The browser performs only same-origin GET requests.
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
and scan submission remain trusted-host CLI operations. C3 adds no browser
mutation and does not fetch findings, dependencies, coverage detail, gaps, or
reports.

## C2 product navigation

The Overview independently loads the first project and global scan pages. It
shows only the authoritative `total` values returned by those pages, a bounded
project subset in API order, and the first six global scan rows in API order.
Projects and scans fail independently, so one available resource remains usable
when the other is unavailable.

The Projects page uses native project links and `total`, `limit`, and `offset`
for Previous/Next pagination. Its empty state gives the exact trusted-host
project-creation command and does not claim browser creation.

Project Detail loads project identity and project scan history in parallel. The
first newest-first history row is shown as Latest scan; history rows use the
lineage-relative label `Sequence N`, never a project-global scan number. The
scan command is copied as plain text with a literal repository placeholder and
only the canonical route UUID:

```text
securescan scan /path/to/repository \
  --project-id <canonical-project-uuid>
```

The browser does not inspect a filesystem, accept a path or Git URL, upload
source, submit a scan, or execute this command.

Global Scans remains a lean navigation projection. It does not fetch scan
detail, findings, dependencies, coverage, gaps, stages, or reports. Project
names are joined by walking at most four 50-project catalog pages for the
project IDs visible on the current scan page. Resolved names are cached in
memory; an unresolved or unavailable project degrades only that row to
`Project unavailable`.

### Initial-load API bounds

| Page | Worst-case initial requests |
| --- | ---: |
| Overview | 5: one projects page, one scans page, and at most three additional project-name pages |
| Projects | 1 project page |
| Project Detail | 2 in parallel: project identity and project scan history |
| Global Scans | 5: one scans page and at most four project-name pages |

Each pagination action makes one new primary page request. Global scan
pagination may additionally make the same bounded project-name lookup, reduced
by the in-memory cache. There is no per-scan detail enrichment.

C2 intentionally provides no global finding count, vulnerability count,
coverage score, risk score, or running-scan count. A first page is never summed
or relabeled as a global security aggregate.

## C3 scan overview and analysis progress

`/scans/{run UUID}` reads the frozen scan summary and stage roster in parallel.
It resolves the project name from the C2 in-memory cache or one direct project
read, then presents a human-readable project link without hiding the technical
identifiers. The stable page shell contains product status, a compact summary,
the semantic ordered stage roster, and a native disclosure for technical scan
details.

Product status and stage progress are separate fixed allowlists. The five
authority/capability pairs map to SAST, Secrets, Package inventory, Dependency
vulnerabilities, and Configuration security; an unrecognized pair remains
`Unknown analysis` from `Unknown authority`. Execution progress never substitutes
for coverage. Before publication, findings, coverage, and gaps are `Pending`
even when a pre-publication transport value is zero. After publication, counts
are shown only when they are nonnegative integers, coverage uses the exact
boolean, and priority counts appear only after indexing and only for returned
known priority keys. Null, absent, malformed, and unknown values never become
zero.

Nonterminal states are `QUEUED`, `RUNNING`,
`PUBLISHED_PENDING_FINALIZATION`, and `BLOCKED_BY_PREDECESSOR`. They use one
chained five-second timeout after the previous refresh settles. Each cycle makes
exactly two parallel reads: scan summary and stages. The single in-flight refresh
promise prevents overlap; the route generation and `AbortController` cancel work
on navigation. `COMPLETED`, `CANCELLED`, and `FAILED` stop polling. Contained
region updates preserve scroll, focus, and an open Technical details disclosure.

Summary failure is route-level. Stage and project failures are isolated, and a
later transient polling failure preserves the last successful content with a
restrained safe warning. Raw API bodies are never rendered.

### Scan-page API bounds

| Situation | Maximum requests |
| --- | ---: |
| Initial load | 3: one summary, one stage roster, and zero or one project lookup |
| Polling cycle | 2: one summary and one stage roster |
| Manual refresh | 2, plus one project lookup only while project context is unresolved |

No C4-C6 resource is preloaded.

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
