# cloudsforge-hub-api

[![ci](https://github.com/cloudsforge-online/micro-hub-api/actions/workflows/ci.yml/badge.svg)](https://github.com/cloudsforge-online/micro-hub-api/actions/workflows/ci.yml) [![TypeScript](https://img.shields.io/badge/TypeScript-strict%20ESM-3178C6?logo=typescript&logoColor=white)](./tsconfig.base.json) [![node](https://img.shields.io/badge/node-%3E%3D22-5FA04E?logo=nodedotjs&logoColor=white)](./package.json) [![licence](https://img.shields.io/badge/licence-MIT-blue)](./LICENSE)

The Forge Hub backend-for-frontend. It composes the dashboard from seven services in one
authenticated call, degrades one tile at a time, and **owns no state**.

Design authority: [`ecosystem/03-repository-responsibilities.md`](https://github.com/cloudsforge-online/micro-docs/blob/main/ecosystem/03-repository-responsibilities.md)

Per AD-05 in `docs/ecosystem/02-target-architecture.md`: Hub is a separate application from the
identity service because "a dashboard tweak redeploys the token issuer" otherwise, and it is a BFF
rather than a fat client because ten cross-origin round trips with ten token exchanges is "a bad
first paint and a CORS matrix that nobody can reason about". The BFF makes it one request, one
cache policy, **and one place to degrade gracefully when an upstream is down**.

## The one rule

> A field that exists only here is a bug.

There is no database, no migration, no outbox and no job runner. Everything served is fetched from
the service that owns it and held in an in-process cache with a stated TTL. Losing the whole cache
costs one slow request. If the dashboard needs a value nobody owns, the fix is a route on the
owning service — which is what the gap list at the bottom of this file is for.

## Routes

| Route | What it is |
| --- | --- |
| `GET /v1/dashboard` | The composition. Eleven tiles, seven upstreams, one 200. |
| `GET /v1/portfolio` | Balances × prices, sorted, with allocation and a pricing timestamp. |
| `GET /v1/activity` | A pass-through to the activity feed, cursor preserved verbatim. |
| `GET /v1/search` | Wallets, transactions, tokens and activity, per-group degradation. |
| `GET /v1/next-actions` | The "needs you" cards on their own, for a client that polls them. |
| `GET /livez` `GET /readyz` `GET /metrics` | Rule 4. |

Every route requires a **user** token. A service token is refused: this surface composes an
authority larger than any single upstream grants, and there is no such thing as a service's
dashboard. An operator with the `admin` role may pass `?userId=`.

## The tile

Every tile in every response carries its own status.

```jsonc
{
  "status": "ok",           // ok | degraded | unavailable
  "upstream": "wallet",
  "reason": null,           // never null when status is not ok; never an upstream response body
  "cached": false,          // true whenever the value came from cache, fresh or stale
  "ageMs": null,            // how old the cached value is
  "data": []                // never null, never absent — the empty value when unavailable
}
```

- `ok` — a fresh answer, possibly a cache hit inside its TTL (`cached: true`, with an age).
- `degraded` — data, but not current data: a stale cache entry served through an outage, or a
  portfolio with balances and no prices. Always with a reason.
- `unavailable` — nothing. `data` holds the empty value so a client renders an empty state.

`TILE_SOURCES` in `src/dashboard.ts` records which upstreams feed which tile, as data. The
degradation suite reads it, so a tile that quietly acquires a second dependency fails the build.

## Caching

TTLs are per upstream and each is documented with its reason in `src/upstreams.ts`. Balances are
3 seconds; the wallet registry is 60; entitlements are 5 minutes. A stale window (longer, and also
bounded) lets a value be served through an outage — **always as `degraded`, never as `ok`**,
because a cache that hides an outage is worse than no cache.

## Metrics

`hub_dashboard_ms`, `hub_tile_status_total{tile,status}`, `hub_upstream_ms{service}`,
`hub_cache_hits_total{upstream}`, plus the standard RED set.

Alert on `hub_tile_status_total`, not on the HTTP error rate. A dashboard serving 200s with one
dead tile is healthy in `http_requests_total` by design, so the signal has to live in the tile
counter.

## Tests

`pnpm test` — no database, no service running, no network. Seven fake upstreams boot on ephemeral
ports and the tests kill them.

The exit criterion is the seven degradation tests in `src/dashboard.test.ts`: one per upstream,
each asserting a 200, the affected tiles marked with a reason, and — the half that catches
regressions — **every unaffected tile still `ok`**.

## Gaps: routes this dashboard needs that do not exist

Each of these is a place where the honest behaviour today is a degraded tile or an absent card.
None is worked around, because working around a missing route is how a BFF acquires state.

1. **`notify` is not wired.** `GET /notifications?userId=&unread=true` exists on the notify service
   behind `notify:read`, but notify is not one of this service's seven upstreams, so the
   `notifications` tile is permanently `unavailable` with that stated reason. Wiring it is one env
   var, one client and about ten lines. It is deliberately *not* synthesised from activity records:
   activity is a narrative, a notification is an addressed message with a read state notify owns.
2. **Identity has no service-readable security route.** `GET /auth/me` and `GET /mfa/factors` are
   guarded by `authenticateUser`, which refuses a service token outright, so this service forwards
   the caller's own bearer. The consequence: an operator drawing another user's dashboard gets an
   `unavailable` security tile rather than a wrong one. A
   `GET /internal/users/:id/security` returning MFA state and session count for a service token
   holding `identity:read` removes the exception and the forwarding both.
3. **No upstream accepts a text query.** `GET /feed` filters by category and product, `GET
   /v1/wallets` by origin; there is no transaction search at all. `/v1/search` therefore filters a
   bounded page in this process and reports `truncated` honestly. A `q=` on each of those three
   turns `src/search.ts` into a fan-out and a merge.
4. **`trade` and `market` do not exist.** The reference layout in design-system.md §6 shows a
   "Bot paused" card and an "Offer on your listing" card. Neither service is in the estate, so
   neither card is built. What stands in for them comes from services that do exist: a past-due
   subscription, an account freeze and a stuck withdrawal.
5. **Minted token decimals are unreachable.** A `TOKEN:<urn>` ledger balance cannot be formatted or
   valued, because decimals are chosen at deploy time and `assetDecimals` refuses to guess. The
   holding is shown with a null amount and a stated reason. A `GET /tokens/:urn` on the mint
   service returning decimals and a symbol fixes it.
6. **Wallet does not expose required confirmation depth.** `DepositCreditView` carries
   `confirmations` but not the depth it is counting towards, so the "41/60" on a deposit card reads
   the depth from `@cloudsforge/contracts-chain` — correct, because it is the same pinned contract
   wallet credits against, but it means hub-api pins that package for one constant. A
   `confirmationsRequired` field on the credit view would remove the dependency.
7. **Pricing's own client disagrees with pricing.** Unrelated to this service but found while
   reading: `wallet/src/pricingclient.ts` calls `GET /v1/quotes`, which pricing does not serve —
   the rate board is `GET /rates`. Worth a look before the next deploy of either.

---

## Provenance

The code in this repository was written by **Claude Opus 5** and **Claude Fable 5**, assets
generated with **FLUX 2 Pro**, under human direction and review.
