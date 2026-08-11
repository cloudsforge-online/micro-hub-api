/**
 * The HTTP surface.
 *
 * Plain `node:http`, following the template. The parts that matter — request ids, RED metrics, the
 * child logger, the error shape, the auth-fault mapping — are framework-independent, and the four
 * health handlers are what CI checks for (rule 4 of docs/ecosystem/03 §2).
 *
 * The one decision that is easy to get backwards is the auth-fault mapping. A bad token is 401. A
 * verifier that could not reach the JWKS is **503**, never 401 — answering 401 there signs every
 * user in the estate out because the identity service is having a bad minute.
 *
 * ── This service refuses a service token ───────────────────────────────────────────────────────
 *
 * Every route below requires a *user* principal. A BFF is a view for a human being holding a
 * session; there is no such thing as a service's dashboard, and accepting a service token here
 * would create a route by which any credential in the estate could read any user's portfolio,
 * wallets, security state and activity in one call. That is a much larger authority than any of
 * the eight upstreams grants individually, and it would exist only because this service composes
 * them. An operator with the `admin` role may name `?userId=`, which is the one supported way to
 * look at somebody else's dashboard — and even then the security tile degrades rather than
 * forwarding the operator's own identity as if it were the subject's.
 *
 * ── Why nothing here returns 500 for an upstream fault ─────────────────────────────────────────
 *
 * `composeDashboard` resolves whatever happens. A route that caught its result and turned a
 * degraded page into a 503 would undo the entire design.
 */

import {
  createServer as createHttpServer,
  type IncomingMessage,
  type Server,
  type ServerResponse,
} from 'node:http'
import {
  ForbiddenError,
  TokenError,
  bearerFrom,
  isAdmin,
  statusFor,
  type Principal,
} from '@cloudsforge/auth'
import type { Lifecycle } from '@cloudsforge/lifecycle'
import { Metrics, newRequestId, type Logger } from '@cloudsforge/telemetry'
import type { TtlCache } from './cache.ts'
import { composeDashboard, type DashboardDeps } from './dashboard.ts'
import { buildNextActions, type FactorSummary, type NextActions } from './nextactions.ts'
import { composePortfolioTile } from './dashboard.ts'
import { search } from './search.ts'
import { loadTile, NotComposableError, type Tile, type TileDeps } from './tiles.ts'
import {
  CACHE,
  PAGE,
  type ActivityPage,
  type ActivityRecord,
  type DepositCredit,
  type LedgerBalance,
  type PolicyFreeze,
  type PricingRate,
  type Upstreams,
  type WithdrawalRecord,
} from './upstreams.ts'

/** The verifier as this file needs it. An interface, so a test does not need a JWKS. */
export interface PrincipalVerifier {
  principal(token: string): Promise<Principal>
}

export interface ServerDeps {
  readonly lifecycle: Lifecycle
  readonly logger: Logger
  readonly metrics: Metrics
  readonly verifier: PrincipalVerifier
  readonly upstreams: Upstreams
  readonly cache: TtlCache
  readonly dashboardDeadlineMs: number
  /** Injected clock, so cache ages and elapsed times are deterministic under test. */
  readonly now?: () => number
  readonly beforeScrape?: () => Promise<void>
}

/**
 * Domain metrics, declared rather than inferred from a log line — AD-20.
 *
 * `hub_tile_status_total` is the one to alert on, and its shape is the reason: `{tile, status}`
 * distinguishes "the wallet tile has been unavailable for ten minutes" from "the page is down",
 * which a single request-level error rate cannot. A dashboard serving 200s with one dead tile
 * looks perfectly healthy in `http_requests_total`, and that is by design — so the signal has to
 * live here.
 */
export function registerServiceMetrics(metrics: Metrics): Metrics {
  return metrics
    .register({
      name: 'hub_dashboard_ms',
      help: 'Wall-clock time to compose a dashboard, including every upstream call',
      kind: 'histogram',
      // Bucketed around the deadline rather than around the happy path: what an operator needs to
      // see is the shoulder forming at the budget, not the shape of the fast case.
      buckets: [25, 50, 100, 250, 500, 1_000, 2_000, 3_000, 5_000],
    })
    .register({
      name: 'hub_tile_status_total',
      help: 'Tiles composed, by tile and outcome',
      kind: 'counter',
      labels: ['tile', 'status'],
    })
    .register({
      name: 'hub_upstream_ms',
      help: 'Time spent in one upstream call attempt that reached the peer',
      kind: 'histogram',
      labels: ['service'],
      buckets: [5, 10, 25, 50, 100, 250, 500, 1_000, 2_000, 5_000],
    })
    /**
     * ══════════════════════════════════════════════════════════════════════════════════════════
     * **THE ONE SERIES THAT CAN TELL A DEAD CREDENTIAL FROM A DEAD PEER.**
     *
     * Until this existed, everything hub-api recorded about an outbound call was a duration
     * labelled by service. A duration cannot say whether a call failed, let alone how — so a
     * revoked service credential, a peer refusing us, and a peer that is genuinely down were all
     * the same three-millisecond observation on `hub_upstream_ms`, and the credential case looked
     * BETTER than healthy because a call that never left the process is fast.
     *
     * `outcome` is `ResultEvent`'s union from `@cloudsforge/http`, and `token_unavailable` is the
     * member that matters here: it is the one value describing a call that did not happen, raised
     * when this process could not mint a service token. On the testnet estate on 2026-08-10 that
     * exact fault was reported to operators for hours as the indexer being unreachable, and the
     * remedy printed beside it sent them to a healthy service (micro-org#351). A reason code only
     * ends that if an operator can select on it, and selecting means a label.
     *
     * `circuit_open` is here for the same reason and is worth its own alert: it means this process
     * refused its own call, so it will not appear in the peer's logs at all.
     *
     * **The label list is not decoration.** `@cloudsforge/telemetry` drops any label a spec does
     * not declare — silently until 1.0.1, which is how ledger's identical counter has been writing
     * `outcome` into nothing since it was written. Adding a member to that union without adding it
     * here loses it.
     * ══════════════════════════════════════════════════════════════════════════════════════════
     */
    .register({
      name: 'hub_upstream_calls_total',
      help: 'Upstream call attempts, by service and by how the attempt ended',
      kind: 'counter',
      labels: ['service', 'outcome'],
    })
    .register({
      name: 'hub_cache_hits_total',
      help: 'Tiles served from cache, fresh or stale, by upstream',
      kind: 'counter',
      labels: ['upstream'],
    })
}

/**
 * An inbound request id is trusted only if it is safe to put in a log line and echo in a header.
 * Anything else is replaced rather than rejected — an unvalidated value here is a header-injection
 * and a log-forgery primitive at once.
 */
const SAFE_REQUEST_ID = /^[A-Za-z0-9_-]{1,64}$/

/** Long enough for an address or a transaction hash, short enough not to be a payload. */
const MAX_QUERY_LENGTH = 128

interface Reply {
  readonly status: number
  readonly body?: unknown
  readonly text?: string
  readonly contentType?: string
}

interface RequestContext {
  readonly req: IncomingMessage
  readonly url: URL
  readonly requestId: string
  readonly log: Logger
}

interface Route {
  readonly method: string
  readonly path: string
  readonly handle: (ctx: RequestContext, deps: ServerDeps) => Promise<Reply>
}

export function createServer(deps: ServerDeps): Server {
  const routes = buildRoutes()
  let inFlight = 0

  return createHttpServer((req, res) => {
    const startedAt = process.hrtime.bigint()
    const presented = headerOf(req, 'x-request-id')
    const requestId = presented && SAFE_REQUEST_ID.test(presented) ? presented : newRequestId()

    // Echoed before anything can fail, so even a 500 carries the id the user will quote.
    res.setHeader('x-request-id', requestId)

    const url = new URL(req.url ?? '/', `http://${headerOf(req, 'host') ?? 'localhost'}`)
    const route = routes.find((r) => r.method === (req.method ?? 'GET') && r.path === url.pathname)
    // Unmatched paths collapse to one label. Using the raw path would let any caller mint
    // unbounded time series and take the scrape target down with cardinality.
    const routeLabel = route ? route.path : 'unmatched'

    const log = deps.logger.child({ requestId, method: req.method ?? 'GET', route: routeLabel })

    inFlight += 1
    deps.metrics.set('http_requests_in_flight', inFlight)

    const finish = (status: number) => {
      inFlight -= 1
      deps.metrics.set('http_requests_in_flight', inFlight)
      const durationMs = Number(process.hrtime.bigint() - startedAt) / 1e6
      deps.metrics.increment('http_requests_total', {
        method: req.method ?? 'GET',
        route: routeLabel,
        status: String(status),
      })
      deps.metrics.observe('http_request_duration_ms', durationMs, {
        method: req.method ?? 'GET',
        route: routeLabel,
      })
    }

    void handle(route, { req, url, requestId, log }, deps)
      .then((reply) => {
        send(res, reply, requestId)
        finish(reply.status)
      })
      .catch((err: unknown) => {
        // Reaching here means the error mapping itself failed. Answer, then say so loudly.
        log.error('request handler threw after mapping', { err })
        send(res, errorReply(500, 'internal', 'the request could not be completed', requestId), requestId)
        finish(500)
      })
  })
}

async function handle(route: Route | undefined, ctx: RequestContext, deps: ServerDeps): Promise<Reply> {
  if (!route) {
    return errorReply(404, 'not_found', `no route for ${ctx.req.method} ${ctx.url.pathname}`, ctx.requestId)
  }
  try {
    return await route.handle(ctx, deps)
  } catch (err) {
    // `statusFor` is the whole point: it is the one place that decides what an auth failure means,
    // so five services cannot disagree about it again.
    const authStatus = statusFor(err)
    if (authStatus === 401) {
      // The reason is logged, never returned — "signature verification failed" versus "expired"
      // tells an attacker which half of a forged token to fix.
      ctx.log.info('unauthenticated request', { err })
      return errorReply(401, 'unauthenticated', 'a valid bearer token is required', ctx.requestId)
    }
    if (authStatus === 403) {
      const required = err instanceof ForbiddenError ? err.required : 'unknown'
      ctx.log.info('forbidden request', { required })
      return errorReply(403, 'forbidden', `missing required authority: ${required}`, ctx.requestId)
    }
    if (authStatus === 503) {
      ctx.log.error('token verifier unavailable', { err })
      return errorReply(503, 'verifier_unavailable', 'authentication is temporarily unavailable', ctx.requestId)
    }
    if (err instanceof BadRequestError) {
      return errorReply(400, 'bad_request', err.message, ctx.requestId)
    }
    ctx.log.error('unhandled request failure', { err })
    return errorReply(500, 'internal', 'the request could not be completed', ctx.requestId)
  }
}

function buildRoutes(): Route[] {
  return [
    {
      method: 'GET',
      path: '/livez',
      /**
       * Static, deliberately. Liveness answers one question — should this process be killed and
       * restarted — and a liveness probe that consults a dependency restarts a healthy process
       * every time an upstream blinks. For a service whose entire job is calling eight upstreams,
       * that would be a restart loop driven by somebody else's deploy.
       */
      handle: async (_ctx, deps) => ({ status: 200, body: deps.lifecycle.livez() }),
    },
    {
      method: 'GET',
      path: '/readyz',
      handle: async (_ctx, deps) => {
        const report = await deps.lifecycle.readyz()
        // 503 is what removes this replica from the balancer. Every upstream probe here is soft:
        // this service is *designed* to serve with an upstream down, so a hard probe on one would
        // take the whole dashboard out of rotation to avoid showing one degraded tile.
        return {
          status: report.ready ? 200 : 503,
          body: { ...report, circuits: deps.upstreams.circuitStates() },
        }
      },
    },
    {
      method: 'GET',
      path: '/metrics',
      handle: async (ctx, deps) => {
        try {
          await deps.beforeScrape?.()
        } catch (err) {
          // A gauge that could not be sampled is a stale gauge. Failing the scrape instead would
          // lose every other metric too, and blind the dashboard at the moment it is needed.
          ctx.log.warn('gauge refresh failed; serving the previous values', { err })
        }
        return {
          status: 200,
          text: deps.metrics.render(),
          contentType: 'text/plain; version=0.0.4; charset=utf-8',
        }
      },
    },

    {
      method: 'GET',
      path: '/v1/dashboard',
      handle: async (ctx, deps) => {
        const subject = await resolveSubject(ctx, deps)
        const done = deps.lifecycle.track()
        try {
          const dashboard = await composeDashboard(dashboardDeps(deps), {
            userId: subject.userId,
            bearer: subject.forwardableBearer,
            requestId: ctx.requestId,
          })
          // Logged at info with the degraded list rather than at warn: a degraded dashboard is a
          // normal, expected, successful response, and logging it as a problem would drown the
          // one case that is a problem.
          ctx.log.info('dashboard composed', {
            userId: subject.userId,
            elapsedMs: dashboard.elapsedMs,
            degraded: dashboard.degraded,
          })
          return { status: 200, body: dashboard }
        } finally {
          done()
        }
      },
    },

    {
      method: 'GET',
      path: '/v1/portfolio',
      handle: async (ctx, deps) => {
        const subject = await resolveSubject(ctx, deps)
        const tileDeps = tileDepsOf(deps)
        const done = deps.lifecycle.track()
        try {
          const [balances, prices] = await Promise.all([
            loadTile<readonly LedgerBalance[]>(tileDeps, {
              tile: 'portfolio',
              upstream: 'ledger',
              key: `ledger:balances:${subject.userId}`,
              ...CACHE.ledgerBalances,
              empty: [],
              load: () => deps.upstreams.ledgerBalances(subject.userId, ctx.requestId),
            }),
            loadTile<readonly PricingRate[]>(tileDeps, {
              tile: 'prices',
              upstream: 'pricing',
              key: 'pricing:rates',
              ...CACHE.pricingRates,
              empty: [],
              load: () => deps.upstreams.pricingRates(ctx.requestId),
            }),
          ])
          // Never a bare number. The tile carries the status, the reason, whether it was cached
          // and how old it is; the payload carries `pricedAt` and `pricingComplete`.
          return { status: 200, body: { portfolio: composePortfolioTile(balances, prices) } }
        } finally {
          done()
        }
      },
    },

    {
      method: 'GET',
      path: '/v1/activity',
      /**
       * A pass-through, with the cursor preserved exactly as activity issued it.
       *
       * The cursor is opaque and stays opaque: it is activity's keyset position, this service does
       * not parse it, and re-encoding it would create a second cursor format that has to be kept
       * in step with the first for ever.
       *
       * Only the first page is cached. A cursored page is fetched once by one client walking a
       * feed, so caching it would fill the map with entries nobody reads again — and a cached
       * *middle* page is the one that goes subtly wrong when new records arrive at the head.
       */
      handle: async (ctx, deps) => {
        const subject = await resolveSubject(ctx, deps)
        const limit = readLimit(ctx, PAGE.activity)
        const cursor = ctx.url.searchParams.get('cursor')
        const done = deps.lifecycle.track()
        try {
          const tile = await loadTile<ActivityPage>(tileDepsOf(deps), {
            tile: 'activity',
            upstream: 'activity',
            key:
              cursor === null
                ? `activity:page:${subject.userId}:${limit}`
                : `activity:uncached:${subject.userId}:${cursor}:${limit}`,
            ttlMs: cursor === null ? CACHE.activityFeed.ttlMs : 0,
            staleMs: cursor === null ? CACHE.activityFeed.staleMs : 0,
            empty: { records: [], nextCursor: null },
            load: () => deps.upstreams.activityFeed(subject.userId, limit, cursor, ctx.requestId),
          })
          return {
            status: 200,
            body: {
              records: tile.data.records,
              nextCursor: tile.data.nextCursor,
              status: tile.status,
              reason: tile.reason,
              cached: tile.cached,
              ageMs: tile.ageMs,
            },
          }
        } finally {
          done()
        }
      },
    },

    {
      method: 'GET',
      path: '/v1/search',
      handle: async (ctx, deps) => {
        const subject = await resolveSubject(ctx, deps)
        const query = ctx.url.searchParams.get('q') ?? ''
        if (query.trim().length === 0) {
          throw new BadRequestError('q is required and must not be empty')
        }
        if (query.length > MAX_QUERY_LENGTH) {
          throw new BadRequestError(`q must be at most ${MAX_QUERY_LENGTH} characters`)
        }
        const done = deps.lifecycle.track()
        try {
          const results = await search(
            { ...tileDepsOf(deps), upstreams: deps.upstreams },
            { userId: subject.userId, query, requestId: ctx.requestId },
          )
          return { status: 200, body: results }
        } finally {
          done()
        }
      },
    },

    {
      method: 'GET',
      path: '/v1/next-actions',
      /**
       * The "needs you" cards on their own, for a client that polls them more often than it
       * reloads the whole dashboard. Same loaders, same cache keys, same degradation: a card whose
       * source is down is absent, and `missing[]` says which source and why.
       */
      handle: async (ctx, deps) => {
        const subject = await resolveSubject(ctx, deps)
        const tileDeps = tileDepsOf(deps)
        const done = deps.lifecycle.track()
        try {
          const [deposits, withdrawals, security, freezes, subscriptions] = await Promise.all([
            loadTile<readonly DepositCredit[]>(tileDeps, {
              tile: 'deposits',
              upstream: 'wallet',
              key: `wallet:deposits:pending:${subject.userId}`,
              ...CACHE.walletDeposits,
              empty: [],
              load: async () =>
                (await deps.upstreams.walletDeposits(subject.userId, ctx.requestId)).filter(
                  (credit) => !credit.credited,
                ),
            }),
            loadTile<readonly WithdrawalRecord[]>(tileDeps, {
              tile: 'withdrawals',
              upstream: 'wallet',
              key: `wallet:withdrawals:active:${subject.userId}`,
              ...CACHE.walletWithdrawals,
              empty: [],
              load: async () =>
                (await deps.upstreams.walletWithdrawals(subject.userId, ctx.requestId)).filter(
                  (withdrawal) =>
                    withdrawal.state !== 'settled' &&
                    withdrawal.state !== 'failed' &&
                    withdrawal.state !== 'refunded' &&
                    withdrawal.state !== 'cancelled',
                ),
            }),
            loadTile<FactorSummary | null>(tileDeps, {
              tile: 'security',
              upstream: 'identity',
              key: `identity:factors:${subject.userId}`,
              ...CACHE.identitySecurity,
              empty: null,
              load: async () => {
                if (subject.forwardableBearer === null) {
                  throw new NotComposableError(
                    'identity exposes no service-readable route for the security state of ' +
                      'another user; a service token is refused by /mfa/factors',
                  )
                }
                return deps.upstreams.identityFactors(subject.forwardableBearer, ctx.requestId)
              },
            }),
            loadTile<readonly PolicyFreeze[]>(tileDeps, {
              tile: 'restrictions',
              upstream: 'policy',
              key: `policy:freezes:${subject.userId}`,
              ...CACHE.policyFreezes,
              empty: [],
              load: () => deps.upstreams.policyFreezes(subject.userId, ctx.requestId),
            }),
            loadTile<readonly import('./upstreams.ts').BillingSubscription[]>(tileDeps, {
              tile: 'entitlements',
              upstream: 'billing',
              key: `billing:subscriptions:${subject.userId}`,
              ...CACHE.billingEntitlements,
              empty: [],
              load: () => deps.upstreams.billingSubscriptions(subject.userId, ctx.requestId),
            }),
          ])

          const actions: NextActions = buildNextActions({
            deposits,
            withdrawals,
            factors: security,
            freezes,
            subscriptions,
          })
          return { status: 200, body: actions }
        } finally {
          done()
        }
      },
    },
  ]
}

/* ------------------------------------------------------------------ auth */

interface Subject {
  readonly userId: string
  /** The caller's own token, but only when the caller *is* the subject. See `resolveSubject`. */
  readonly forwardableBearer: string | null
}

/**
 * Who this request is for, and whether their own token may be forwarded to identity.
 *
 * A user acts for themselves and their token is forwardable. An operator with the `admin` role may
 * name any user, and their token is *not* forwardable, because it authenticates the operator: sent
 * to `/auth/me` it would return the operator's account and the tile would present it as the
 * subject's. A service token is refused outright — see the file header for why a BFF must not
 * accept one.
 */
async function resolveSubject(ctx: RequestContext, deps: ServerDeps): Promise<Subject> {
  const token = bearerFrom(headerOf(ctx.req, 'authorization'))
  // A missing token is a token fault, so it takes the same 401 path as a bad one rather than being
  // a separate branch that can drift away from it.
  if (!token) throw new TokenError('no bearer token presented', 'missing')

  const principal = await deps.verifier.principal(token)
  if (principal.kind !== 'user') {
    throw new ForbiddenError('a user session (this surface does not accept a service token)')
  }

  const requested = ctx.url.searchParams.get('userId')
  if (requested === null || requested === principal.userId) {
    return { userId: principal.userId, forwardableBearer: token }
  }
  if (!isAdmin(principal)) throw new ForbiddenError('acting for another user')
  return { userId: requested, forwardableBearer: null }
}

/* ------------------------------------------------------------------ plumbing */

function tileDepsOf(deps: ServerDeps): TileDeps {
  // Built conditionally because `exactOptionalPropertyTypes` distinguishes an absent `now` from a
  // present `undefined`, and the difference decides whether the default clock is used.
  return deps.now
    ? { cache: deps.cache, metrics: deps.metrics, logger: deps.logger, now: deps.now }
    : { cache: deps.cache, metrics: deps.metrics, logger: deps.logger }
}

function dashboardDeps(deps: ServerDeps): DashboardDeps {
  return {
    ...tileDepsOf(deps),
    upstreams: deps.upstreams,
    dashboardDeadlineMs: deps.dashboardDeadlineMs,
  }
}

class BadRequestError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'BadRequestError'
  }
}

function readLimit(ctx: RequestContext, fallback: number): number {
  const raw = ctx.url.searchParams.get('limit')
  if (raw === null) return fallback
  const value = Number(raw)
  // Bounded above because the limit is forwarded to an upstream: an unbounded one here is an
  // unbounded query there, reachable by anyone with a session.
  if (!Number.isInteger(value) || value < 1 || value > 100) {
    throw new BadRequestError('limit must be a whole number between 1 and 100')
  }
  return value
}

/**
 * The error shape, identical on every failure and always carrying the request id.
 *
 * The id in the body rather than only in the header is what makes a support conversation work: a
 * user can read back what their browser showed them, and it joins to the log line, the trace and
 * the Lantern issue.
 */
function errorReply(status: number, code: string, message: string, requestId: string): Reply {
  return { status, body: { error: { code, message, requestId } } }
}

function send(res: ServerResponse, reply: Reply, requestId: string): void {
  if (res.writableEnded) return
  const payload = reply.text ?? `${JSON.stringify(reply.body ?? {})}\n`
  res.writeHead(reply.status, {
    'content-type': reply.contentType ?? 'application/json; charset=utf-8',
    'content-length': Buffer.byteLength(payload),
    'x-request-id': requestId,
    // Every answer here is a point-in-time composition of somebody else's state, and each tile
    // already carries its own age. A shared cache holding it would add a second, invisible,
    // unlabelled staleness on top — the exact thing `cached`/`ageMs` exist to make impossible.
    'cache-control': 'no-store',
  })
  res.end(payload)
}

function headerOf(req: IncomingMessage, name: string): string | undefined {
  const value = req.headers[name]
  return Array.isArray(value) ? value[0] : value
}

/** Re-exported so `index.ts` and the tests import one name for the tile contract. */
export type { Tile, ActivityRecord }
