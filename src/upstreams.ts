/**
 * The seven upstreams, as this service actually calls them.
 *
 * Every type below was read off the peer's `src/server.ts`, not off a shared client library and
 * not off an expectation. Where a route this dashboard obviously wants does not exist, that is
 * recorded here in a comment rather than papered over with a derived value, because the fix is a
 * route on the owning service and a comment is how the next person finds that out.
 *
 * ── Why a client per upstream, and a credential per upstream ───────────────────────────────────
 *
 * One `HttpClient` per peer, because `@cloudsforge/http` scopes its circuit breaker to the client
 * instance. A shared client would give the estate one breaker: pricing having a bad minute would
 * open the circuit on the ledger, and the dashboard would lose every tile over one sick peer —
 * the precise cascade the per-tile design exists to prevent.
 *
 * One token per peer, because AD-05 says so and because this service is the highest-fan-out
 * surface in the estate. `HUB_WALLET_TOKEN` carries `wallet:read` and nothing else, so an attacker
 * who reaches this process's environment gets six read credentials rather than one credential that
 * can move money.
 *
 * ── Identity is the exception, and it is not a shortcut ────────────────────────────────────────
 *
 * `GET /auth/me` and `GET /mfa/factors` are guarded by identity's `authenticateUser`, which
 * explicitly refuses a service token: "a service token accepted where a user token was expected
 * makes `sub` — a service name — look like a user id". No credential this service could hold would
 * reach them. So identity is called with the *caller's own* bearer, forwarded verbatim, which is
 * safe in the narrow sense that matters: identity issued that token, it is being returned to its
 * issuer, and it authorises exactly the user whose dashboard is being drawn — never more.
 *
 * What would remove the exception: a service-readable `GET /internal/users/:id/security` on
 * identity, returning MFA state and session count for a service token holding `identity:read`.
 * Until it exists, an operator loading another user's dashboard cannot see that user's security
 * tile, and the tile degrades rather than lying. That is a listed gap, not a design.
 *
 * ── The TTL table ──────────────────────────────────────────────────────────────────────────────
 *
 * Each value is stated with the reason for it, because an unexplained TTL is a number nobody dares
 * change. The rule behind all of them: the TTL is shorter than the interval at which the
 * underlying fact can change *and matter*. The stale window — how long a value may be served after
 * the upstream stops answering, always labelled `degraded` — is uniformly longer, because a stale
 * labelled number beats a hole, and it is bounded so a long outage ends in a hole rather than in
 * an ancient number.
 */

import { HttpClient } from '@cloudsforge/http'
import type { AssetCode, Network } from '@cloudsforge/contracts-chain'
import type { LedgerAssetCode } from '@cloudsforge/contracts-money'
import type { Metrics } from '@cloudsforge/telemetry'
import type { Env } from './env.ts'

/* ------------------------------------------------------------------ cache policy */

export interface CachePolicy {
  readonly ttlMs: number
  readonly staleMs: number
}

/**
 * How long each upstream's answer stays good, and how long it may be served after that upstream
 * stops answering.
 *
 * The spread across these is deliberate and is the argument for caching at all: the surface
 * registry changes daily and the balances change per transaction, so one global TTL would either
 * make wallets needlessly expensive or make money needlessly wrong.
 */
// Declared as a literal rather than as `Record<string, CachePolicy>`: under
// `noUncheckedIndexedAccess` an index signature makes every lookup `CachePolicy | undefined`, so a
// spread of `...CACHE.ledgerBalances` would silently become optional and a missing TTL would type-
// check. `satisfies` keeps the shape checked and the keys exact.
export const CACHE = Object.freeze({
  /**
   * Balances. 3 seconds — effectively "collapse a burst", not "cache".
   *
   * A balance is the number a user watches change after they press a button. Anything longer and
   * the dashboard shows the state before their own action, which reads as the action having
   * failed. Three seconds still absorbs the double-load a page refresh produces and the parallel
   * hit from `/v1/dashboard` and `/v1/portfolio` when both are open.
   */
  ledgerBalances: Object.freeze({ ttlMs: 3_000, staleMs: 60_000 }),

  /**
   * Deposits in flight. 5 seconds — the confirmation counter is the thing the user is watching
   * tick, and a stalled counter is indistinguishable from a stalled deposit. The stale window is
   * short for the same reason: a confirmation count from two minutes ago is actively misleading
   * about how much longer there is to wait.
   */
  walletDeposits: Object.freeze({ ttlMs: 5_000, staleMs: 60_000 }),

  /** Withdrawals in flight. 5 seconds, and for the same reason as deposits. */
  walletWithdrawals: Object.freeze({ ttlMs: 5_000, staleMs: 60_000 }),

  /**
   * The wallet registry. 60 seconds.
   *
   * Every field in it — label, primary flag, lifecycle state, origin — changes only by an
   * explicit user action, and one that happens on a different page. A minute of staleness costs a
   * user nothing; the alternative costs the wallet service a query per dashboard load per user.
   */
  walletRegistry: Object.freeze({ ttlMs: 60_000, staleMs: 15 * 60_000 }),

  /**
   * Prices. 15 seconds.
   *
   * Bounded *below* by honesty rather than by cost: the response carries pricing's own `quotedAt`,
   * so a cached rate does not misreport when the market was observed. Bounded above by the
   * oracle's own round time — caching a quote for longer than pricing takes to replace it means
   * the timestamp we print is systematically older than the one available for the asking.
   */
  pricingRates: Object.freeze({ ttlMs: 15_000, staleMs: 5 * 60_000 }),

  /**
   * Activity. 10 seconds. The feed is a preview of the last four entries (design-system §6 rule 4)
   * and the full feed is its own page, so ten seconds of lag on a preview is invisible — while the
   * feed is the single most-read query in the estate and worth collapsing.
   */
  activityFeed: Object.freeze({ ttlMs: 10_000, staleMs: 5 * 60_000 }),

  /**
   * MFA and account state. 30 seconds.
   *
   * Short despite changing rarely, because of what it drives: the "2FA is not enabled" card. A
   * user who has just enabled MFA and still sees the card believes the enrolment failed, and the
   * support cost of that is far above the cost of the call.
   */
  identitySecurity: Object.freeze({ ttlMs: 30_000, staleMs: 10 * 60_000 }),

  /**
   * Entitlements and subscriptions. 5 minutes.
   *
   * The longest TTL here, and the safest: billing already serves `active` and `confersAccess`
   * computed at an explicit instant, so this cache holds a decision rather than a number, and a
   * subscription's period boundary is a date rather than a moment. Nothing a user does on this
   * dashboard changes it.
   */
  billingEntitlements: Object.freeze({ ttlMs: 5 * 60_000, staleMs: 30 * 60_000 }),

  /**
   * Freezes. 30 seconds.
   *
   * A freeze is a safety signal, and the direction of error is asymmetric: showing a freeze that
   * has just been cleared is a moment of confusion, while failing to show one that has just been
   * applied is a user who does not understand why their withdrawal was refused. Short, therefore,
   * and with a stale window that keeps it visible through a policy outage.
   */
  policyFreezes: Object.freeze({ ttlMs: 30_000, staleMs: 10 * 60_000 }),
}) satisfies Readonly<Record<string, CachePolicy>>

/* ------------------------------------------------------------------ wire types */

/** `ledger` — `GET /accounts/:subject/balances`. Mirrors `BalanceView` in ledger/src/accounts.ts. */
export interface LedgerBalance {
  readonly accountId: string
  readonly subject: string
  readonly assetCode: LedgerAssetCode
  readonly purpose: string
  readonly type: string
  readonly status: string
  /** Smallest units, as a decimal string. Never a JSON number: it is a 78-bit quantity. */
  readonly amount: string
  readonly asOfEntryId: string | null
  readonly updatedAt: string | null
}

/** `wallet` — `GET /v1/wallets`. Mirrors `WalletRecord` in wallet/src/wallets.ts. */
export interface WalletRecord {
  readonly id: string
  readonly userId: string
  readonly origin: 'managed' | 'external' | 'watch'
  readonly chain: AssetCode
  readonly network: Network
  readonly address: string
  readonly label: string | null
  readonly isPrimary: boolean
  readonly status: 'provisioning' | 'active' | 'frozen' | 'exported' | 'retiring' | 'retired'
  readonly custodyKeyUrn: string | null
  readonly createdAt: string
  readonly verifiedAt: string | null
  readonly exportedAt: string | null
  readonly retiredAt: string | null
}

/** `wallet` — `GET /v1/deposits/credits`. Mirrors `DepositCreditView` in wallet/src/deposits.ts. */
export interface DepositCredit {
  readonly id: string
  readonly assetCode: string
  readonly amount: string
  readonly amountFormatted: string
  readonly chain: string
  readonly network: string
  readonly txHash: string
  readonly txUrn: string
  readonly explorerUrl: string | null
  readonly confirmations: number
  readonly credited: boolean
}

/** `wallet` — `GET /v1/withdrawals`. Mirrors `WithdrawalRecord` in wallet/src/withdrawals.ts. */
export interface WithdrawalRecord {
  readonly id: string
  readonly userId: string
  readonly chain: string
  readonly network: string
  readonly assetCode: string
  readonly destination: string
  readonly amount: string
  readonly amountFormatted: string
  readonly fee: string
  readonly net: string
  readonly netFormatted: string
  readonly state:
    | 'requested'
    | 'reserved'
    | 'queued'
    | 'settling'
    | 'settled'
    | 'stuck'
    | 'failed'
    | 'refunded'
    | 'cancelled'
  readonly txHash: string | null
  readonly failureReason: string | null
  readonly requestedAt: string
  readonly updatedAt: string
}

/** `identity` — `GET /auth/me`. */
export interface IdentityMe {
  readonly user: {
    readonly id: string
    readonly email: string
    readonly emailVerifiedAt: string | null
    readonly handle: string
    readonly status: string
    readonly roles: readonly string[]
    readonly createdAt: string
    readonly lastSeenAt: string | null
  }
  readonly session: { readonly id: string; readonly amr: readonly string[] }
  readonly organisations: readonly { readonly id: string; readonly name: string }[]
}

/** `identity` — `GET /mfa/factors`. */
export interface IdentityFactors {
  readonly factors: readonly {
    readonly id: string
    readonly kind: string
    readonly label: string
    readonly status: string
    readonly lastUsedAt: string | null
    readonly createdAt: string
  }[]
  readonly recoveryCodesRemaining: number
}

/** `billing` — `GET /internal/entitlements/:userId`. */
export interface BillingEntitlement {
  readonly id: string
  readonly sku: string
  readonly scope: string
  readonly source: string
  readonly grantedAt: string
  readonly expiresAt: string | null
  readonly active: boolean
}

/** `billing` — `GET /subscriptions`. */
export interface BillingSubscription {
  readonly id: string
  readonly productId: string
  readonly status: string
  readonly currentPeriodEnd: string | null
  readonly cancelAt: string | null
  readonly scope: string
  readonly confersAccess: boolean
}

/** `activity` — `GET /feed`. Mirrors `toWire` in activity/src/server.ts. */
export interface ActivityRecord {
  readonly id: string
  readonly userId: string | null
  readonly occurredAt: string
  readonly category: string
  readonly type: string
  readonly subjectUrn: string
  readonly summary: string
  readonly amount: string | null
  readonly assetCode: string | null
  readonly product: string
  readonly visibility: string
}

export interface ActivityPage {
  readonly records: readonly ActivityRecord[]
  readonly nextCursor: string | null
}

/** `pricing` — `GET /rates`. Mirrors `RateView` in pricing/src/quotes.ts. */
export interface PricingRate {
  readonly asset: AssetCode
  readonly source: string
  readonly usable: boolean
  readonly reason?: string
  /** When the market observation was made. The field the whole dashboard hangs off — §6 rule 1. */
  readonly quotedAt: string | null
  readonly ageSeconds: number | null
  /** USD per whole coin at `RATE_SCALE`, as a decimal string. Null when there is no usable quote. */
  readonly usdScaled: string | null
  readonly usd: string | null
}

/** `policy` — `GET /subjects/:subject/freezes`. Mirrors `Freeze` in policy/src/freezes.ts. */
export interface PolicyFreeze {
  readonly id: string
  readonly subject: string
  readonly scope: string
  readonly reason: string
  readonly createdAt: string
  readonly clearedAt: string | null
  readonly clearancesRequired: number
}

/* ------------------------------------------------------------------ the port */

/**
 * The upstreams as the composition layer sees them.
 *
 * An interface, so `dashboard.ts` can be tested with in-memory fakes that fail on demand, and so
 * nothing above this line knows an HTTP client exists. Every method may reject; nothing above
 * catches selectively, because `loadTile` catches everything and turns it into a status.
 */
export interface Upstreams {
  ledgerBalances(userId: string, requestId: string): Promise<readonly LedgerBalance[]>
  walletRegistry(userId: string, requestId: string): Promise<readonly WalletRecord[]>
  walletDeposits(userId: string, requestId: string): Promise<readonly DepositCredit[]>
  walletWithdrawals(userId: string, requestId: string): Promise<readonly WithdrawalRecord[]>
  /** Takes the caller's bearer, not a service token. See the file header. */
  identityMe(bearer: string, requestId: string): Promise<IdentityMe>
  identityFactors(bearer: string, requestId: string): Promise<IdentityFactors>
  billingEntitlements(userId: string, requestId: string): Promise<readonly BillingEntitlement[]>
  billingSubscriptions(userId: string, requestId: string): Promise<readonly BillingSubscription[]>
  activityFeed(
    userId: string,
    limit: number,
    cursor: string | null,
    requestId: string,
  ): Promise<ActivityPage>
  pricingRates(requestId: string): Promise<readonly PricingRate[]>
  policyFreezes(userId: string, requestId: string): Promise<readonly PolicyFreeze[]>
  /** Breaker state per upstream, for `/readyz` and for the operator who asks "is it us". */
  circuitStates(): Readonly<Record<string, string>>
}

/** How many rows each list read asks for. See `dashboard.ts` for why the dashboard asks for few. */
export const PAGE = Object.freeze({
  wallets: 50,
  deposits: 25,
  withdrawals: 25,
  activity: 25,
  entitlements: 50,
  subscriptions: 20,
})

export interface HttpUpstreamOptions {
  readonly env: Env
  readonly metrics: Metrics
  /** Test seam. Production uses the global. */
  readonly fetch?: typeof globalThis.fetch
}

/**
 * Build the seven clients.
 *
 * `defaultRetries: 1` rather than the package default of 2. A retry costs the tile part of its
 * budget, and the dashboard would rather have six tiles now than seven tiles late — one retry
 * covers the single dropped connection, which is what retries are actually for, and the breaker
 * covers the case where retrying is pointless.
 */
export function httpUpstreams(options: HttpUpstreamOptions): Upstreams {
  const { env, metrics } = options
  const circuit = { threshold: env.circuitThreshold, resetMs: env.circuitResetMs }

  const make = (name: string, baseUrl: string, token?: string): HttpClient =>
    new HttpClient({
      baseUrl,
      name,
      defaultDeadlineMs: env.upstreamDeadlineMs,
      defaultRetries: 1,
      circuit,
      ...(token !== undefined ? { token: () => token } : {}),
      ...(options.fetch ? { fetch: options.fetch } : {}),
      // The per-attempt timing. Recorded here rather than around the call so a retried request
      // shows two observations, which is what makes "slow because we retried" separable from
      // "slow because the peer is slow".
      onResult: (event) => {
        metrics.observe('hub_upstream_ms', event.durationMs, { service: event.upstream })
      },
    })

  const ledger = make('ledger', env.upstreams.ledger, env.tokens.ledger)
  const wallet = make('wallet', env.upstreams.wallet, env.tokens.wallet)
  // No token: every call carries the caller's own, per request. See the file header.
  const identity = make('identity', env.upstreams.identity)
  const billing = make('billing', env.upstreams.billing, env.tokens.billing)
  const activity = make('activity', env.upstreams.activity, env.tokens.activity)
  const pricing = make('pricing', env.upstreams.pricing, env.tokens.pricing)
  const policy = make('policy', env.upstreams.policy, env.tokens.policy)

  return {
    async ledgerBalances(userId, requestId) {
      // `user:<uuid>` percent-encoded whole: the colon is a path-segment delimiter in some
      // proxies, and ledger decodes the segment before parsing it.
      const subject = encodeURIComponent(`user:${userId}`)
      const body = await ledger.get<{ balances: readonly LedgerBalance[] }>(
        `/accounts/${subject}/balances`,
        { requestId },
      )
      return body.balances
    },

    async walletRegistry(userId, requestId) {
      const body = await wallet.get<{ wallets: readonly WalletRecord[] }>(
        `/v1/wallets?userId=${encodeURIComponent(userId)}&limit=${PAGE.wallets}`,
        { requestId },
      )
      return body.wallets
    },

    async walletDeposits(userId, requestId) {
      const body = await wallet.get<{ credits: readonly DepositCredit[] }>(
        `/v1/deposits/credits?userId=${encodeURIComponent(userId)}&limit=${PAGE.deposits}`,
        { requestId },
      )
      return body.credits
    },

    async walletWithdrawals(userId, requestId) {
      const body = await wallet.get<{ withdrawals: readonly WithdrawalRecord[] }>(
        `/v1/withdrawals?userId=${encodeURIComponent(userId)}&limit=${PAGE.withdrawals}`,
        { requestId },
      )
      return body.withdrawals
    },

    async identityMe(bearer, requestId) {
      return identity.get<IdentityMe>('/auth/me', {
        headers: { authorization: `Bearer ${bearer}` },
        requestId,
      })
    },

    async identityFactors(bearer, requestId) {
      return identity.get<IdentityFactors>('/mfa/factors', {
        headers: { authorization: `Bearer ${bearer}` },
        requestId,
      })
    },

    async billingEntitlements(userId, requestId) {
      // The service-token route, not `GET /entitlements`. Billing refuses a user token here on
      // purpose — "a route that quietly accepted both would make the scoped-token boundary
      // decorative" — and this service holds exactly the token it names.
      const body = await billing.get<{ entitlements: readonly BillingEntitlement[] }>(
        `/internal/entitlements/${encodeURIComponent(userId)}?limit=${PAGE.entitlements}`,
        { requestId },
      )
      return body.entitlements
    },

    async billingSubscriptions(userId, requestId) {
      const body = await billing.get<{ subscriptions: readonly BillingSubscription[] }>(
        `/subscriptions?userId=${encodeURIComponent(userId)}&limit=${PAGE.subscriptions}`,
        { requestId },
      )
      return body.subscriptions
    },

    async activityFeed(userId, limit, cursor, requestId) {
      const query = new URLSearchParams({ userId, limit: String(limit) })
      if (cursor) query.set('cursor', cursor)
      const body = await activity.get<{
        records: readonly ActivityRecord[]
        nextCursor?: string
      }>(`/feed?${query.toString()}`, { requestId })
      // Normalised to `null` here rather than left absent. Activity omits the key on the last
      // page; a client that reads `nextCursor === undefined` and one that reads `=== null` are two
      // clients, and this is the layer whose job it is to make them one.
      return { records: body.records, nextCursor: body.nextCursor ?? null }
    },

    async pricingRates(requestId) {
      const body = await pricing.get<{ rates: readonly PricingRate[] }>('/rates', { requestId })
      return body.rates
    },

    async policyFreezes(userId, requestId) {
      const subject = encodeURIComponent(`user:${userId}`)
      const body = await policy.get<{ freezes: readonly PolicyFreeze[] }>(
        `/subjects/${subject}/freezes`,
        { requestId },
      )
      return body.freezes
    },

    circuitStates() {
      return {
        ledger: ledger.circuitState,
        wallet: wallet.circuitState,
        identity: identity.circuitState,
        billing: billing.circuitState,
        activity: activity.circuitState,
        pricing: pricing.circuitState,
        policy: policy.circuitState,
      }
    },
  }
}
