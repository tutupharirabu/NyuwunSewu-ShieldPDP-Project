# Progressive Dashboard Loading + HTTP Caching — Design

**Date:** 2026-06-12
**Status:** Implemented (Stage 1 + Stage 2)
**Approach:** C (hybrid) + Pillar 4 (browser HTTP cache)

## Problem

The dashboard (`frontend/src/pages/dashboard.tsx:1326`) fetches **8 API endpoints
in one `Promise.all`** and **re-polls all of them every 30s**
(`usePoll(refresh, 30000)`). Consequences observed in a real HAR capture over the
Tailscale link (`vps-ece41005.tail25f2a6.ts.net`):

- `/api/scans?limit=50` returned **2.94 MB** (99% was `stats.diagnostics` from one
  failed scan), uncompressed, taking **~50s** in `receive`. *(Already mitigated:
  diagnostics stripped from the list response + GZip middleware added.)*
- Every API response has **no cache headers** (`cache-control=None`, `etag=None`),
  so each poll and each full page reload re-downloads the entire body.
- The slowest endpoint in the `Promise.all` blocks the **entire** dashboard render.
- Other pages (findings, reports, targets…) refetch the same data on navigation
  because the dashboard does not seed their cache keys.

The dashboard genuinely *renders* almost all 8 sources (it is an executive
aggregator), so the fix is not "fetch fewer endpoints" but "fetch them at the
right time, make each fetch cheap, and pre-warm caches for other pages."

## Goals

1. Dashboard renders critical widgets ASAP; heavier panels stream in without
   blocking.
2. Stop re-polling everything every 30s; poll only live data, at sane intervals.
3. Make each network request cheap (or skippable) via browser HTTP caching that
   survives full page reloads and new tabs.
4. Pre-warm data for other features ("gradually prepare the rest") so navigation
   feels instant.

## Non-goals

- No change to *what* the dashboard displays (same panels, same correctness).
- No server-side dashboard aggregation (approach A) — deferred.
- No new client data-fetching library (e.g. React Query) — reuse existing
  `useApi` / `usePoll` / module-level `apiCache`.
- Do **not** trim `findings` to a tiny limit: Privacy Exposure & coverage% are
  computed over the `findings` array client-side, so trimming changes semantics.
  Only `auditLogs` (feed-only) is trimmed.

## Cache layering (mental model)

| Layer | Where | Role | Survives reload? |
|-------|-------|------|------------------|
| HTTP cache (Pillar 4) | browser disk | makes each request cheap (304) or skippable (max-age) | ✅ yes, + across tabs |
| `apiCache` (existing) | SPA memory, SWR | instant render on in-session navigation | ❌ no |
| Tiers (Pillar 1–3) | fetch orchestration | controls *when / how often* to ask | — |

Tiers decide *when* to ask; HTTP cache decides *how expensive* each ask is. Today
the bottom layer is empty.

---

## Stage 1 — Backend HTTP caching (no client changes)

A single FastAPI middleware gives every JSON GET an `ETag` and a
`Cache-Control` policy. This benefits the **current** app immediately, before any
frontend refactor.

### Component: `app/middleware/http_cache.py`

For `GET` responses with status `200` and a JSON body:

1. Compute a **weak ETag** = hash (e.g. `sha1`) of the response body bytes →
   `ETag: W/"<hash>"`.
2. If the request's `If-None-Match` matches → return **`304 Not Modified`** with an
   empty body, preserving `ETag`, `Cache-Control`, and `Vary` headers.
3. Set `Cache-Control` **only if the endpoint did not already set one**
   (endpoint-controlled override wins).
4. Always set `Vary: Authorization` (data is per-user) — appended to the existing
   `Vary: Origin`.

Default policy when the endpoint sets nothing: `Cache-Control: private, no-cache`
(must revalidate every time → cheap 304 when unchanged, full body only on change).

**Skip** the middleware for: non-GET methods, non-200, streaming/file responses,
auth mutation endpoints, and any response already marked `no-store`.

### Per-endpoint Cache-Control policy

| Endpoint(s) | Policy | Rationale |
|-------------|--------|-----------|
| `/api/dashboard`, `/api/scans`, `/api/scans/{id}`, `/api/scans/{id}/endpoints`, `/api/findings` | `private, no-cache` + ETag | live data; revalidate → 304 when unchanged. Directly kills the repeated big-body transfer. |
| `/api/reports`, `/api/audit-logs`, `/api/compliance`, `/api/targets`, `/api/projects`, `/api/remediations` | `private, max-age=30` + ETag | tolerate ~30s staleness; browser serves from disk with **zero** server round-trip; survives reload. |
| `/api/auth/me` | `private, no-cache` + ETag | small, sensitive-ish; always revalidate. |
| Non-GET / mutations | `no-store` | never cache. |

`max-age` default = **30s** (tunable constant).

### Security caveats (must-haves)

- Always `private`, **never `public`** — a shared proxy must not cache one user's
  data and serve it to another.
- `Vary: Authorization` so different tokens never collide in the browser cache.
- ETag is computed over the already-serialized body (a few ms even at ~3 MB), so
  no extra DB work; only network is saved (which is the bottleneck).

### Client note (no change required)

`frontend/src/lib/api.ts:54` already uses `fetch` with the **default cache mode**
(no `no-store`, no cache-busting). Browser revalidation is transparent: on a 304
the browser returns the cached `200` body, so `response.json()` still works
unchanged.

### Stage 1 testing

`tests/test_http_cache.py` (pytest + httpx, matching existing suite):
- GET returns an `ETag` and the expected `Cache-Control` per endpoint class.
- Repeat GET with `If-None-Match: <etag>` → `304`, empty body.
- After data changes → new `ETag`, `200` with body.
- `Vary` includes `Authorization`.
- Non-GET → `no-store`, no ETag.

---

## Stage 2 — Frontend tiered fetch + idle prefetch

### Tiers (in `frontend/src/pages/dashboard.tsx`)

| Tier | Endpoints | Timing | Drives |
|------|-----------|--------|--------|
| 1 — critical | `dashboard()`, `scans()` | render immediately; **poll 30s** | KPI cards, Recent Scans |
| 2 — panels | `findings(100)`, `remediations()`, `compliance()`, `targets()` | after first paint; **poll ~90s** | Privacy/Compliance/Remediation panels, ExposurePath |
| 3 — feed only | `auditLogs(limit=20)`, `reports()` | once on idle; **no poll** | Security Activity Feed, presence flags |

Each panel renders its own skeleton until its tier resolves. Tiers are independent:
a failed Tier-2/3 fetch shows that panel empty/skeleton and does not break others
(retain existing `.catch(() => [])`).

### Component: `frontend/src/hooks/use-dashboard-data.ts` (new)

Extracts the fetch orchestration out of the 51 KB `dashboard.tsx`. Returns
progressive data plus per-tier readiness, e.g.:

```ts
{
  data: Partial<DashboardData>,
  ready: { tier1: boolean; tier2: boolean; tier3: boolean },
  error: string | null,
  refresh: () => void,
}
```

Implemented with the existing `useApi` (per tier) + `usePoll` (per-tier interval).
After Tier 1 is ready, schedule idle prefetch.

### Idle prefetch (Pillar: "prepare the rest")

After Tier 1 paints, via `requestIdleCallback` (fallback `setTimeout`), warm the
**page cache keys** with their **full** shapes:

- `api.findings()` (default limit 500) → `primeApiCache("findings", …)`
- `api.targets()` → `primeApiCache("targets", …)`
- `api.projects()` → `primeApiCache("projects", …)`

With Stage 1's `max-age`, these also land in the browser disk cache, so the warmth
persists across reloads. Navigating to findings/targets/projects then renders
instantly (SWR revalidates in the background).

### Supporting changes

- `frontend/src/hooks/use-api.ts`: export `primeApiCache(key: string, value: unknown)`
  to write into the existing module-level `apiCache`.
- `frontend/src/lib/api.ts`: add optional `limit` to `auditLogs(targetId?, limit?)`
  (server already supports `?limit=`).

### Stage 2 testing

- Unit: `primeApiCache(key, value)` then `useApi(loader, [], key)` renders cached
  value without a loading state.
- Manual (Network panel): Tier 1 fires first; Tier 2/3 stagger; repeated polls
  return `304`; navigating to findings/targets shows cache hits, no full refetch.

---

## Files touched

**Stage 1 (backend):**
- `app/middleware/http_cache.py` (new)
- `app/main.py` (register middleware)
- a few API modules where an endpoint opts into `max-age` (set its own
  `Cache-Control`)
- `tests/test_http_cache.py` (new)

**Stage 2 (frontend):**
- `frontend/src/hooks/use-dashboard-data.ts` (new)
- `frontend/src/hooks/use-api.ts` (export `primeApiCache`)
- `frontend/src/lib/api.ts` (`limit` on `auditLogs`)
- `frontend/src/pages/dashboard.tsx` (consume hook, progressive render)

## Open questions

- `max-age` value: default 30s. Acceptable, or prefer 60s for the "stable" group?
- Whether `/api/remediations` belongs in the `max-age` group or the `no-cache`
  group (it has a live SLA panel). Default: `max-age=30`.
