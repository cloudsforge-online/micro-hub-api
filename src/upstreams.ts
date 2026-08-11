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
import {
  ServiceTokenProvider,
  ServiceTokenUnavailableError,
  type ProviderEvent,
} from '@cloudsforge/auth'
import type { AssetCode, Network } from '@cloudsforge/contracts-chain'
import type { LedgerAssetCode } from '@cloudsforge/contracts-money'
import type { Metrics } from '@cloudsforge/telemetry'
import type { LiveScope } from '@cloudsforge/contracts-auth'
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
  /**
   * The six token providers, so `/readyz` can report the credential.
   *
   * Every entry is `null` when no credential is configured, which is the state
   * `serviceTokenProbe` fails on. They are exposed rather than hidden because a dashboard whose
   * tiles are all `unavailable` should say WHY on the readiness endpoint, not only in a log.
   */
  readonly tokenProviders: UpstreamProviders
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
  readonly onTokenEvent?: (event: ProviderEvent) => void
}

/**
 * The exact scope each peer is asked for, and nothing wider.
 *
 * These are the six scope sets the six retired `HUB_*_TOKEN` variables carried, read off the
 * tokens the estate bootstrap actually minted rather than inferred. They stay separate because
 * this is the highest fan-out surface in the estate: an attacker who reaches this process's memory
 * should find six narrow read tokens, not one that can move money. That is AD-05, and dropping to
 * a single whole-allowlist token would quietly trade it away.
 *
 * Identity is absent by construction: `GET /auth/me` and `GET /mfa/factors` refuse a service token
 * outright, so those calls carry the caller's own bearer. See the file header.
 *
 * ── `satisfies`, NOT AN ANNOTATION, AND THAT IS LOAD-BEARING TWICE ───────────────────────────
 *
 * These are OUTBOUND demands — what hub-api presents to each peer — and that direction had never
 * been checked by anything. `service-ci.yml`'s scope audit reads a repository's INBOUND route
 * gates, which is how `micro-market` came to declare `policy:evaluate` and `micro-wallet`
 * `custody:address`, neither of which has ever been a registry key, for the life of both
 * services. `micro-deploy`'s `derive-grants.mjs` reads this object into
 * `IDENTITY_SERVICE_TOKEN_GRANTS`, and identity validates that list against the registry at
 * import and REFUSES TO START on a name it does not know: a dead identity container, so no tokens
 * for anybody rather than one broken tile.
 *
 * `LiveScope` rather than `Scope` because `Scope` is `keyof typeof SCOPES` — every registered key,
 * DEPRECATED ones included — and identity will not mint a deprecated scope either.
 * `LiveScope = Exclude<Scope, DeprecatedScope>`, with `DeprecatedScope` computed FROM `SCOPES` by
 * a conditional type over the `deprecated` field rather than hand-listed
 * (`contracts/packages/auth/src/index.ts`), so it cannot drift from the registry.
 *
 * It has to be `satisfies` rather than a type annotation, because this object's KEYS are also a
 * type: `UpstreamProviders` below is `Record<keyof typeof UPSTREAM_SCOPES, …>`. Annotating this
 * `Record<string, readonly LiveScope[]>` would widen that key set to `string`, and every peer
 * lookup in this file would stop being checked — trading a narrow win on the values for a much
 * larger loss on the keys. `satisfies` checks the values and keeps the literal keys.
 *
 * ── AND WHY EACH INNER ARRAY CARRIES `as const` ──────────────────────────────────────────────
 *
 * **The clause that stood here before checked nothing.** It read
 * `satisfies Record<string, readonly string[]>`, and `Object.freeze(['ledger:read'])` is typed
 * `readonly string[]` — the array literal is widened, because `Object.freeze` gives it no const
 * context. So the clause asserted `readonly string[]` against `readonly string[]`: true for every
 * possible value, including `'poilcy:decide'`. Six outbound demands at the estate's highest
 * fan-out surface looked type-checked and were not, which is exactly the shape that let
 * `policy:evaluate` and `custody:address` ship in two sibling services.
 *
 * `as const` is what makes the elements literal types, and therefore what makes the `satisfies`
 * above capable of failing at all. Without it, swapping any scope here for a name that does not
 * exist still compiles. Verified by doing precisely that, in both directions — an unregistered
 * scope and a registered-but-deprecated one — before and after.
 */
export const UPSTREAM_SCOPES = Object.freeze({
  ledger: Object.freeze(['ledger:read'] as const),
  wallet: Object.freeze(['wallet:read'] as const),
  billing: Object.freeze(['billing:read'] as const),
  activity: Object.freeze(['notify:read'] as const),
  pricing: Object.freeze(['pricing:read'] as const),
  policy: Object.freeze(['policy:decide'] as const),
}) satisfies Record<string, readonly LiveScope[]>

/** The providers, exposed so `/readyz` can report the credential and a test can drive them. */
export type UpstreamProviders = Readonly<
  Record<keyof typeof UPSTREAM_SCOPES, ServiceTokenProvider | null>
>

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

  /**
   * One provider per peer, all from the SAME credential, each narrowed to that peer's scope.
   *
   * Six providers rather than one is deliberate: a single whole-allowlist token would be one
   * string in this process's memory that reads wallets, ledgers, billing and policy at once. Six
   * exchanges every ten minutes against identity is a trivial cost for keeping AD-05's separation.
   */
  const providers: UpstreamProviders = Object.freeze(
    Object.fromEntries(
      Object.entries(UPSTREAM_SCOPES).map(([peer, scopes]) => [
        peer,
        env.identityCredential
          ? new ServiceTokenProvider({
              identityUrl: env.upstreams.identity,
              credential: env.identityCredential,
              scopes,
              ...(options.fetch ? { fetch: options.fetch } : {}),
              ...(options.onTokenEvent ? { onEvent: options.onTokenEvent } : {}),
            })
          : null,
      ]),
    ),
  ) as UpstreamProviders

  /**
   * Rejects rather than resolving `undefined` when there is no credential. `HttpClient` omits the
   * header entirely for `undefined`, so the request would go out unauthenticated and come back
   * 401 — telling an operator that the peer rejected hub-api, when the truth is that nobody
   * configured hub-api. `ServiceTokenUnavailableError` is 503 under `statusFor`, which is what a
   * tile reports as `unavailable` rather than as a signed-out user.
   */
  const tokenFrom = (provider: ServiceTokenProvider | null) => (): Promise<string> =>
    provider
      ? provider.token()
      : Promise.reject(new ServiceTokenUnavailableError('no identity credential is configured'))

  const make = (name: string, baseUrl: string, provider?: ServiceTokenProvider | null): HttpClient =>
    new HttpClient({
      baseUrl,
      name,
      defaultDeadlineMs: env.upstreamDeadlineMs,
      defaultRetries: 1,
      circuit,
      ...(provider !== undefined ? { token: tokenFrom(provider) } : {}),
      // `authorizedFetch` catches a 401 from the peer, re-mints and replays once — the schedule
      // rests on this process's clock and the peer's expiry on the peer's.
      ...(provider?.authorizedFetch
        ? { fetch: provider.authorizedFetch }
        : options.fetch
          ? { fetch: options.fetch }
          : {}),
      // The per-attempt timing. Recorded here rather than around the call so a retried request
      // shows two observations, which is what makes "slow because we retried" separable from
      // "slow because the peer is slow".
      //
      // **THE COUNTER IS NOT A DUPLICATE OF THE HISTOGRAM.** A duration says how long something
      // took, never whether it worked, so until this counter existed a revoked service credential
      // and a healthy upstream were the same observation on `hub_upstream_ms` — and the credential
      // case looked FASTER, because a call that never left the process costs nothing. See
      // `hub_upstream_calls_total` in `server.ts` for the estate incident that is written from.
      //
      // And the two attempts that never reached the peer are kept OUT of the latency histogram.
      // `circuit_open` reports `durationMs: 0` for a call this process refused itself, and
      // `token_unavailable` reports what the token supplier spent, not what a peer did. Feeding
      // either into `hub_upstream_ms` moves the p99 in the direction of "healthy" at exactly the
      // moment nothing is being served, which is a check that cannot fail. Everything else stays:
      // a timeout and a transport error both spent real time against a real socket.
      onResult: (event) => {
        metrics.increment('hub_upstream_calls_total', {
          service: event.upstream,
          outcome: event.outcome,
        })
        if (event.outcome !== 'circuit_open' && event.outcome !== 'token_unavailable') {
          metrics.observe('hub_upstream_ms', event.durationMs, { service: event.upstream })
        }
      },
    })

  const ledger = make('ledger', env.upstreams.ledger, providers.ledger)
  const wallet = make('wallet', env.upstreams.wallet, providers.wallet)
  // No token: every call carries the caller's own, per request. See the file header.
  const identity = make('identity', env.upstreams.identity)
  const billing = make('billing', env.upstreams.billing, providers.billing)
  const activity = make('activity', env.upstreams.activity, providers.activity)
  const pricing = make('pricing', env.upstreams.pricing, providers.pricing)
  const policy = make('policy', env.upstreams.policy, providers.policy)

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
    tokenProviders: providers,
  }
}
