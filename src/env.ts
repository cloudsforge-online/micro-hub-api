/**
 * Configuration, validated at import.
 *
 * Rule 9 of docs/ecosystem/03 §2 — "a repo declares the variables it needs; the deploy provides
 * exactly those" — is a property of this file. Every variable the service reads is named here and
 * nowhere else, so the deploy manifest can be derived from it.
 *
 * Two things are worth reading twice.
 *
 * **There is no database URL, and there must never be one.** This service composes; it does not
 * remember. A connection string here would be the first step towards a table holding a stale copy
 * of a balance the ledger owns.
 *
 * **There are six upstream tokens, not one.** AD-05 gives the reason a BFF exists at all, and one
 * of them is that "separating them lets Hub's BFF hold a *scoped* service credential per upstream
 * rather than being trusted with everything". One shared credential is the `PAY_SERVICE_TOKEN`
 * shape the estate is trying to be rid of: it makes a compromise of the most exposed surface in
 * the estate — this one, the fan-out — a compromise of all seven peers at once. Six tokens are six
 * rotations, and that cost is the point.
 *
 * Identity has no token here, deliberately. `GET /auth/me` and `GET /mfa/factors` are guarded by
 * `authenticateUser`, which refuses a service token outright, so there is no credential this
 * service could hold that would reach them. Identity is called with the caller's own bearer,
 * forwarded. See `upstreams.ts` for why that is safe and what route would replace it.
 */

import { hostname } from 'node:os'

/**
 * The service's own name. A constant rather than a variable: it is a property of the repository,
 * not of the deployment.
 */
export const SERVICE = 'hub-api'

/** Raised by `loadEnv`. Distinct so a caller can tell configuration from every other failure. */
export class EnvError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'EnvError'
  }
}

/**
 * Values that must never be accepted. The list holds the strings that actually appear in this
 * repository's `.env.example` and in compose files, because those are the ones that get copied
 * into a deployment by someone in a hurry.
 */
const PLACEHOLDERS = new Set([
  'changeme',
  'change-me',
  'placeholder',
  'secret',
  'dev-secret',
  'dev-service-token',
  'replace-with-a-real-secret',
  'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx',
])

type Source = Readonly<Record<string, string | undefined>>

function required(source: Source, name: string): string {
  const value = source[name]?.trim()
  if (!value) throw new EnvError(`${name} is required — ${SERVICE} refuses to start without it`)
  return value
}

function requiredSecret(source: Source, name: string, minLength = 24): string {
  const value = required(source, name)
  if (PLACEHOLDERS.has(value.toLowerCase())) {
    throw new EnvError(`${name} is set to a known placeholder — generate a real secret`)
  }
  // Length is a proxy for entropy and the only one available here. It is set above the point at
  // which a human-chosen string is plausible, so a memorable password fails this check too.
  if (value.length < minLength) {
    throw new EnvError(`${name} must be at least ${minLength} characters (got ${value.length})`)
  }
  return value
}

/**
 * A secret that may be absent, but must be real if present.
 *
 * The distinction matters for the identity credential: absent is a deployment that has not been
 * given one yet and is reported by `/readyz`; a short placeholder is a deployment that believes it
 * HAS one, and would fail on its first call to a peer with a 401 that reads as "the peer rejected
 * hub-api" rather than "nobody set this variable".
 */
function optionalSecret(source: Source, name: string, minLength = 24): string | null {
  const value = source[name]?.trim()
  if (!value) return null
  if (PLACEHOLDERS.has(value.toLowerCase())) {
    throw new EnvError(`${name} is set to a known placeholder — generate a real secret`)
  }
  if (value.length < minLength) {
    throw new EnvError(`${name} must be at least ${minLength} characters (got ${value.length})`)
  }
  return value
}

function optional(source: Source, name: string, fallback: string): string {
  const value = source[name]?.trim()
  return value && value.length > 0 ? value : fallback
}

function integer(source: Source, name: string, fallback: number, min: number, max: number): number {
  const raw = source[name]?.trim()
  if (!raw) return fallback
  const value = Number(raw)
  if (!Number.isInteger(value) || value < min || value > max) {
    throw new EnvError(`${name} must be a whole number between ${min} and ${max} (got ${raw})`)
  }
  return value
}

/** Where every upstream lives. Named by service so a log line naming one is unambiguous. */
export interface UpstreamUrls {
  readonly ledger: string
  readonly wallet: string
  readonly identity: string
  readonly billing: string
  readonly activity: string
  readonly pricing: string
  readonly policy: string
}

export interface Env {
  readonly port: number
  readonly env: string
  readonly version: string
  readonly logLevel: 'debug' | 'info' | 'warn' | 'error'
  readonly identityJwksUrl: string
  readonly identityIssuer: string
  readonly upstreams: UpstreamUrls
  /**
   * **The one long-lived credential this service exchanges for six short-lived tokens.**
   *
   * It replaces `HUB_LEDGER_TOKEN`, `HUB_WALLET_TOKEN`, `HUB_BILLING_TOKEN`,
   * `HUB_ACTIVITY_TOKEN`, `HUB_PRICING_TOKEN` and `HUB_POLICY_TOKEN` — six 600-second tokens
   * (identity/src/tokens.ts:28) read once at boot. Ten minutes into any deployment all six expired
   * and every tile on the dashboard went `unavailable`; nothing could re-mint them, because
   * minting requires the `admin` role.
   *
   * ONE SECRET, STILL SIX NARROW TOKENS. The six variables existed because they carry different
   * scopes — this is the highest fan-out surface in the estate, and `wallet:read` and nothing else
   * is the whole point of AD-05. That separation is kept: identity reads the service off the
   * credential ROW and never off the request, so one credential mints everything hub-api is
   * allowed, and the scope set is a request parameter rather than a second secret. Six providers,
   * six caches, six narrow tokens, one revocable secret.
   *
   * Identity is still absent by construction — see the file header. Its two routes refuse a
   * service token, so those calls carry the caller's own bearer.
   *
   * OPTIONAL, so the image can BOOT for CI's `/livez` smoke test, whose environment is fixed in a
   * workflow file. The absence is not silent: `/readyz` reports `identity-credential` as a HARD
   * failure and every upstream call fails closed with 503.
   */
  readonly identityCredential: string | null
  /** Whether any of the six retired `HUB_*_TOKEN` variables is still set. Reported at boot. */
  readonly legacyServiceTokenPresent: boolean
  /**
   * The ceiling on a whole dashboard request.
   *
   * The dashboard's budget is the slowest tile, not the sum: the fan-out is concurrent, so seven
   * upstreams at 400ms each cost 400ms, and this number is what a single pathological upstream is
   * allowed to cost. Past it the tile is `unavailable` and the page is still served.
   */
  readonly dashboardDeadlineMs: number
  /**
   * The default ceiling on one upstream call, retries included. Necessarily below the dashboard
   * deadline: an upstream allowed to spend the whole budget could make the deadline unreachable
   * for every other tile if the fan-out ever became sequential.
   */
  readonly upstreamDeadlineMs: number
  /** Consecutive transport or 5xx faults before an upstream's breaker opens. */
  readonly circuitThreshold: number
  /** How long a breaker stays open before letting one probe through. */
  readonly circuitResetMs: number
  /**
   * Names this replica in logs. Defaults to the hostname, which is the container id under compose
   * and the pod name under Kubernetes — in both cases the thing an operator would search for.
   */
  readonly instanceId: string
}

const LEVELS = new Set(['debug', 'info', 'warn', 'error'])

/**
 * Pure over its source so the failure paths are testable without mutating the process. The eager
 * export below is what makes the service fail fast.
 */
export function loadEnv(source: Source = process.env, hostname = ''): Env {
  const logLevel = optional(source, 'LOG_LEVEL', 'info')
  if (!LEVELS.has(logLevel)) {
    throw new EnvError(`LOG_LEVEL must be one of debug, info, warn, error (got ${logLevel})`)
  }

  const dashboardDeadlineMs = integer(source, 'HUB_DASHBOARD_DEADLINE_MS', 2_500, 100, 30_000)
  const upstreamDeadlineMs = integer(source, 'HUB_UPSTREAM_DEADLINE_MS', 1_500, 50, 30_000)
  if (upstreamDeadlineMs > dashboardDeadlineMs) {
    // Caught here rather than at the call site because the failure it produces is subtle: the
    // dashboard would appear to work and would simply never degrade, because no tile could ever
    // reach its own deadline before the page had already given up on it.
    throw new EnvError(
      `HUB_UPSTREAM_DEADLINE_MS (${upstreamDeadlineMs}) must not exceed ` +
        `HUB_DASHBOARD_DEADLINE_MS (${dashboardDeadlineMs})`,
    )
  }

  return {
    port: integer(source, 'PORT', 4000, 1, 65_535),
    env: optional(source, 'NODE_ENV', 'development'),
    version: optional(source, 'CLOUDSFORGE_TAG', 'dev'),
    logLevel: logLevel as Env['logLevel'],
    identityJwksUrl: required(source, 'IDENTITY_JWKS_URL'),
    identityIssuer: required(source, 'IDENTITY_ISSUER'),
    upstreams: {
      ledger: required(source, 'LEDGER_URL'),
      wallet: required(source, 'WALLET_URL'),
      identity: required(source, 'IDENTITY_URL'),
      billing: required(source, 'BILLING_URL'),
      activity: required(source, 'ACTIVITY_URL'),
      pricing: required(source, 'PRICING_URL'),
      policy: required(source, 'POLICY_URL'),
    },
    // Not `requiredSecret`: see the field comment. The absence is caught by `/readyz`, which is a
    // check that can fail, rather than by a boot CI cannot perform.
    identityCredential: optionalSecret(source, 'HUB_API_IDENTITY_CREDENTIAL'),
    legacyServiceTokenPresent: [
      'HUB_LEDGER_TOKEN',
      'HUB_WALLET_TOKEN',
      'HUB_BILLING_TOKEN',
      'HUB_ACTIVITY_TOKEN',
      'HUB_PRICING_TOKEN',
      'HUB_POLICY_TOKEN',
    ].some((name) => (source[name]?.trim() ?? '').length > 0),
    dashboardDeadlineMs,
    upstreamDeadlineMs,
    circuitThreshold: integer(source, 'HUB_CIRCUIT_THRESHOLD', 5, 1, 100),
    circuitResetMs: integer(source, 'HUB_CIRCUIT_RESET_MS', 10_000, 100, 300_000),
    instanceId: optional(source, 'INSTANCE_ID', hostname || 'unknown'),
  }
}

/**
 * The checks above run at import, before the logger exists, so an uncaught throw reaches the
 * container as a bare V8 stack: not JSON, no level, no service name. The collector drops it and
 * the only symptom an operator gets is a container that exits instantly.
 *
 * So emit one structured fatal line by hand. It is built from a literal rather than routed through
 * the telemetry package: nothing that can itself fail may sit between a configuration error and
 * the report of it. The message is the one `loadEnv` produced, which by construction never
 * contains a value.
 */
function fatalConfig(err: unknown): never {
  const message = err instanceof Error ? err.message : String(err)
  process.stderr.write(
    `${JSON.stringify({
      time: new Date().toISOString(),
      level: 'fatal',
      service: SERVICE,
      step: 'env',
      msg: `startup failed at: env — ${message}`,
    })}\n`,
  )
  process.exit(1)
}

export const env: Env = (() => {
  try {
    return loadEnv(process.env, hostname())
  } catch (err) {
    fatalConfig(err)
  }
})()
