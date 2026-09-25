# SecureScan Source V1.1C Web UI 2.0

## Status

V1.1C0 is the approved UI/API architecture and design contract. V1.1C1
established design tokens, the application shell, explicit browser routing,
readiness presentation, and accessibility foundations. V1.1C2 added real
Overview, Projects, Project Detail, and Global Scans navigation while preserving
the frozen read API and Product Core contracts. V1.1C3 added the real Scan
Overview and authoritative Analysis stage progress. V1.1C4 adds the real
Findings workspace and evidence-backed finding detail. V1.1C5 adds the package
inventory, dependency-evaluation workspace, and canonical advisory detail.
Coverage detail, gaps, and reports remain later checkpoints.

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

## C4 findings workspace and detail

`/scans/{run UUID}/findings` is an evidence workspace, not a second Scan
Overview. It loads one authoritative, server-paginated findings page and keeps
the list usable while an optional detail is selected. The desktop layout uses a
42/58 split between the dense finding list and detail. At 768–1199 pixels the
detail is a native modal dialog with browser focus containment, Escape support,
and focus restoration. Below 768 pixels selection switches to a dedicated
detail view with a native Back to findings control.

Priority, category, lifecycle, and authority are exact allowlisted server
filters. Changing a server filter resets the offset and selection, preserves
the other valid filters, updates bounded query state, aborts the older request,
and issues exactly one new findings-page request. Pagination is also
authoritative and clears a stale selection. The optional Search this page field
is explicitly local to the currently loaded page; it searches only safe
rendered title, authority, category, location, and narrow subject candidates.
It makes no API call and never presents its match count as a global filtered
total.

Finding IDs are canonical 64-character lowercase hexadecimal identities.
Selection uses durable native links of this form:

```text
/scans/{run UUID}/findings?finding={finding ID}
```

Back/forward navigation therefore restores filters, offset, and selection. If
an exact selected ID is not in the current page, the UI says so and does not
crawl other pages or pretend the finding is loaded.

### Authority-specific presentation

Summary rows derive a narrow safe identity only from the public finding
summary. Detail titles are upgraded only after strict report correlation:

| Authority | Evidence-backed detail title | Additional exact fields |
| --- | --- | --- |
| Semgrep | rule-match `message` | rule ID and CWE identifiers |
| Gitleaks | secret-observation `rule_id` | rule ID and detection kind |
| Checkov | policy-observation `check_name` | check ID and resource |
| OSV | advisory-group `canonical_advisory_id` | package name/version and PURL |

Unknown or malformed subjects use fixed category fallbacks; structured values
are never stringified into the page. Repository paths, messages, rule names,
resources, package values, advisory strings, and reason codes remain untrusted
text. Long and bidi-looking values are isolated and wrapped. Gitleaks detail
does not expose a secret value or raw scanner artifact.

SecureScan priority and scanner severity remain separate labeled facts.
`UNRANKED` is rendered as `Priority not assigned`, not as a low severity.
Lifecycle is the exact current `NEW`, `EXISTING`, `RESOLVED`, or `REOPENED`
state. C4 does not fabricate a lifecycle timeline, remediation, CVSS score,
exploitability, confidence, reachability, business impact, or analyst
disposition.

### Lazy report and exact evidence correlation

The verified report is not requested when the findings page loads. The first
selection of a finding present in the current page triggers one report request;
concurrent selections share that request, and later selections reuse the same
object for the current run and route generation. Navigating away aborts and
invalidates the cache.

Detail correlation requires exactly one report finding with the selected
`finding_id`, the same authority and category, and a nonempty set of primary
evidence references. Every reference must resolve exactly and have the same
authority. Package detail additionally requires one exact component reference.
There is no path, title, similarity, or fuzzy fallback. A mismatch degrades only
the detail to `Technical evidence unavailable`; it does not destroy the summary
list.

### Findings API bounds and failure states

| Interaction | Maximum requests |
| --- | ---: |
| Initial findings load without a selection | 1 findings-page request; 0 report requests |
| First valid selection | 1 lazy report request |
| Later selection in the same route generation | 0 report requests |
| Server filter or pagination action | 1 findings-page request |
| Current-page search | 0 requests |
| Selected ID absent from the loaded page | 0 report or page-crawl requests |

A global empty response says only that completed analyses reported no findings
and directs the operator to Coverage before interpreting it as clean. A
filter-empty response is a distinct `No matching findings` state. A 404 is
`Scan not found`; a 409 is `Findings not ready` with its safe allowlisted code
and a Scan Overview link; a 503 is a fail-closed `Findings unavailable` state,
never zero. Report failure leaves the list and selected summary functional.
Raw API errors are not rendered.

## C5 dependency workspace and advisory detail

`/scans/{run UUID}/dependencies` uses only the frozen Product Core dependency
projection. It does not call OSV, parse manifests, infer package coordinates, or
recompute advisory identity. One returned `advisories[]` element is one
canonical advisory group; CVE, GHSA, other aliases, and OSV record IDs remain
attributes and never inflate the known-vulnerability count.

The list is server-paginated and ordered by the backend. Search is explicitly
limited to the loaded page and safe package identity, ecosystem, PURL, location,
and canonical advisory strings. Selection uses a bounded 64-character component
reference in query state. A component outside the current page is not fetched by
crawling other pages. Desktop uses the established 42/58 split, tablet a native
modal drawer, and mobile a dedicated detail state with focus restoration and a
Back to dependencies action.

Dependency truth is rendered exhaustively:

| Evaluation | Exact count | Presentation |
| --- | ---: | --- |
| `COMPLETE` | positive | exact known-vulnerability count |
| `COMPLETE` | zero | `0 known vulnerabilities` |
| `PARTIAL` | `null` | `Unknown`; observed canonical advisories shown separately |
| `FAILED` | `null` | `Unknown` |
| `NOT_APPLICABLE` | `null` | `N/A` |

Detail shows only returned package identity, repository-relative observation
locations, evaluation, exact count, and canonical advisories. Advisory priority
is labeled `SecureScan priority`; `UNRANKED` becomes `Priority not assigned`.
Fixed events use the factual label `Fixed versions reported by advisory`, never
an upgrade or remediation recommendation. OSV record IDs, finding IDs,
component references, and evaluation reason codes remain secondary technical
evidence. Nullable PURLs and versions remain visibly unavailable rather than
being synthesized.

Initial load and every pagination action make exactly one dependency request.
Search and detail selection make zero requests. Empty, 409, and 503 states are
distinct and never imply that dependencies are secure. All API strings remain
text-only, bidi-isolated where technical, and safely wrapped.

## C6 coverage, gaps, and verified report

`/scans/{run UUID}/coverage` always starts from the authoritative five-stage
roster. Execution progress and published coverage are separate labeled facts.
Detailed outcomes retain the exact frozen states `COMPLETE`,
`COMPLETE_WITH_FINDINGS`, `COMPLETE_WITH_SUPPRESSIONS`, `PARTIAL`, `FAILED`,
and `NOT_APPLICABLE`; no percentage or security score is derived. Scope arrays,
reason codes, and counts remain behind Technical scope disclosure. A 409 from
the coverage endpoint becomes pending publication while the execution roster
remains visible. Other coverage-detail failures stay local and never become a
global zero.

`/scans/{run UUID}/gaps` renders the authoritative, server-paginated gap
projection. Each row identifies the fixed capability and authority, exact safe
reason code, primary scope value, optional returned message, and secondary
technical scope. Empty means only that SecureScan published no analysis gap;
the page explicitly does not claim full coverage. Pagination performs one
bounded gaps request per page, and all returned strings remain inert text.

`/scans/{run UUID}/report` is a human evidence workspace backed by six bounded,
parallel reads: summary, stages, detailed coverage, the first six gaps, the
verified report, and one dependency page entry used only for the authoritative
package total. Its Summary, Analysis coverage, Findings, Dependencies, Analysis
gaps, and Provenance sections do not reconstruct canonical totals or infer
package-vulnerability counts. Failure of one independent resource stays local.
If the verified report is unavailable, the human sections remain but the page
states that canonical raw evidence is unavailable rather than fabricating it.

Raw evidence is serialized once with `JSON.stringify(..., null, 2)` and placed
into a native `pre` by `textContent`. Copy uses plain text. Download creates an
`application/json` Blob with a static run-UUID-derived filename. Print invokes
the browser and a restrained print stylesheet removes navigation and controls,
uses black-on-white content, and preserves readable evidence sections. There
are no external export services or PDF generators.

## C7 complete-UI hardening

Every approved route now has a registered product renderer; the checkpoint
shell and all future-phase placeholder copy have been removed. History API
navigation, direct deep links, refresh, modified clicks, new-tab links, and
back/forward restoration are covered by an executable navigation contract.
Route-generation cancellation and the per-workspace request guards continue to
prevent late reads from overwriting the current route.

The complete frontend remains GET-only, same-origin, framework-free, and free
of HTML-injection or dynamic-code sinks. Error copy never exposes response
bodies, and empty, filtered-empty, pending, unavailable, failed, unknown, and
not-applicable states remain distinct. Long paths, package identifiers, aliases,
Unicode and bidi-looking values wrap as isolated text. Security headers retain
the strict self-only CSP with no inline script/style exceptions, framing,
objects, referrers, or browser permissions.

Accessibility hardening preserves the skip link, semantic landmarks and table
captions, current-page navigation, native details and dialogs, focus trapping
and restoration, Escape behavior, 40-pixel controls, visible focus, live status,
and reduced-motion behavior. The muted text token was raised minimally to
`#808881`, making every active normal-text token at least WCAG AA against every
active graphite surface. No theme redesign was introduced.

All ten routes were rendered and measured at 1920, 1366, 1280, 1024, 768, 767,
and 390 CSS pixels. The 70-route/width matrix had no document-level horizontal
overflow. Representative desktop, compact-sidebar, breakpoint, and true 390px
captures were reviewed for hierarchy, wrapping, table transformation, spacing,
and restrained accent use. No external assets, decorative dashboards, gradients,
glass effects, or AI-style visual elements were added.

## Checkpoint plan

```text
C1  design system, shell, routing
C2  overview, projects, project history, scans
C3  scan overview and progress
C4  findings and detail
C5  dependencies and detail
C6  coverage, gaps, report (complete checkpoint)
C7  responsive, accessibility, hostile-input hardening (complete checkpoint)
C8  isolated E2E, visual acceptance, final freeze
```

Later phases must continue to present frozen Product Core truth. They may format
or group exact returned values, but must not infer security state, fabricate
remediation or lifecycle history, count advisory aliases as vulnerabilities, or
turn partial, failed, unknown, or not-applicable states into zero.
