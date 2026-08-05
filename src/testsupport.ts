/**
 * Local fakes for the seven upstreams.
 *
 * **Real HTTP servers, not stubbed clients.** Every test in this repository boots seven
 * `node:http` listeners and points the real `HttpClient` at them. Stubbing the `Upstreams`
 * interface would be quicker and would test nothing that matters: the behaviours under test —
 * a deadline expiring, a breaker opening after repeated transport faults, a connection refused
 * because a peer is gone — all live *below* that interface, in the client. A fake that returns a
 * rejected promise proves the tile catches an error; a socket that is not there proves the system
 * degrades.
 *
 * Nothing here requires a service running, a database, or a network. Every listener binds
 * 127.0.0.1 on an ephemeral port.
 *
 * `kill()` closes the listener, so the next request is refused at the transport rather than
 * answered with a 503. That is the harsher of the two failure modes and the one that behaves
 * differently: a 4xx is the peer deciding, a 503 is the peer struggling, and a closed socket is
 * the peer being absent — only the last two trip the breaker.
 */

import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http'
import type { AddressInfo } from 'node:net'
import { setTimeout as delay } from 'node:timers/promises'
import { SignJWT, generateKeyPair } from 'jose'
import { AUDIENCE, Verifier } from '@cloudsforge/auth'
import { Logger, Metrics, registerHttpMetrics } from '@cloudsforge/telemetry'
import { Lifecycle } from '@cloudsforge/lifecycle'
import { TtlCache } from './cache.ts'
import { httpUpstreams, type Upstreams } from './upstreams.ts'
import { createServer as createHubServer, registerServiceMetrics } from './server.ts'
import type { Env } from './env.ts'

export const ISSUER = 'https://identity.test'
export const USER_ID = '00000000-0000-4000-8000-00000000beef'
export const OTHER_USER_ID = '00000000-0000-4000-8000-0000000000aa'

const keys = await generateKeyPair('RS256', { extractable: true })

/** A user token, signed by a key the test verifier trusts. */
export function signUser(userId = USER_ID, roles: readonly string[] = ['player']): Promise<string> {
  return new SignJWT({ sub: userId, handle: 'ash', roles })
    .setProtectedHeader({ alg: 'RS256', kid: 'k1' })
    .setIssuedAt()
    .setIssuer(ISSUER)
    .setAudience(AUDIENCE)
    .setExpirationTime('15m')
    .sign(keys.privateKey)
}

/** A service token, used only to prove this surface refuses one. */
export function signService(service = 'trade', scopes: readonly string[] = ['hub:read']): Promise<string> {
  return new SignJWT({ sub: `service:${service}`, scopes })
    .setProtectedHeader({ alg: 'RS256', kid: 'k1' })
    .setIssuedAt()
    .setIssuer(ISSUER)
    .setAudience(AUDIENCE)
    .setExpirationTime('15m')
    .sign(keys.privateKey)
}

/** A real `Verifier` over a local key set. Nothing here stubs the decision under test. */
export function testVerifier(): Verifier {
  return new Verifier({
    jwksUrl: 'http://unused',
    issuer: ISSUER,
    keySet: (async () => keys.publicKey) as never,
  })
}

/* ------------------------------------------------------------------ fixtures */

/** Shaped exactly as the peer serves it — see the wire types in `upstreams.ts`. */
export const FIXTURES = {
  ledgerBalances: [
    {
      accountId: 'a1',
      subject: `user:${USER_ID}`,
      assetCode: 'SHARD',
      purpose: 'available',
      type: 'liability',
      status: 'open',
      amount: '124800',
      asOfEntryId: 'e1',
      updatedAt: '2026-07-30T14:22:00.000Z',
    },
    {
      accountId: 'a2',
      subject: `user:${USER_ID}`,
      assetCode: 'EMBER',
      purpose: 'available',
      // 3 EMBER, 18 decimals.
      amount: '3000000000000000000',
      type: 'liability',
      status: 'open',
      asOfEntryId: 'e2',
      updatedAt: '2026-07-30T14:22:00.000Z',
    },
    {
      accountId: 'a3',
      subject: `user:${USER_ID}`,
      assetCode: 'EMBER',
      purpose: 'reserved',
      amount: '1000000000000000000',
      type: 'liability',
      status: 'open',
      asOfEntryId: 'e3',
      updatedAt: '2026-07-30T14:22:00.000Z',
    },
    {
      accountId: 'a4',
      subject: `user:${USER_ID}`,
      assetCode: 'BTC',
      purpose: 'available',
      // 0.5 BTC, 8 decimals.
      amount: '50000000',
      type: 'liability',
      status: 'open',
      asOfEntryId: 'e4',
      updatedAt: '2026-07-30T14:22:00.000Z',
    },
  ],

  pricingRates: [
    {
      asset: 'BTC',
      source: 'market',
      usable: true,
      // The older of the two observations, so it is the one `pricedAt` must report.
      quotedAt: '2026-07-30T14:20:00.000Z',
      ageSeconds: 120,
      usdScaled: '60000000000',
      usd: '60000',
    },
    {
      asset: 'EMBER',
      source: 'administered',
      usable: true,
      quotedAt: '2026-07-30T14:22:00.000Z',
      ageSeconds: 0,
      usdScaled: '2000000',
      usd: '2',
    },
    {
      asset: 'XRP',
      source: 'market',
      usable: false,
      reason: 'quote is 900s old, past the 600s maximum',
      quotedAt: '2026-07-30T14:07:00.000Z',
      ageSeconds: 900,
      usdScaled: null,
      usd: null,
    },
  ],

  wallets: [
    {
      id: 'w1',
      userId: USER_ID,
      origin: 'managed',
      chain: 'EMBER',
      network: 'mainnet',
      address: 'ember1q4f2',
      label: 'Main',
      isPrimary: true,
      status: 'active',
      custodyKeyUrn: 'cf:custody:key:1',
      createdAt: '2026-01-01T00:00:00.000Z',
      verifiedAt: null,
      exportedAt: null,
      retiredAt: null,
    },
    {
      id: 'w2',
      userId: USER_ID,
      origin: 'external',
      chain: 'ETH',
      network: 'mainnet',
      address: '0x8a00000000000000000000000000000000000c31',
      label: null,
      isPrimary: false,
      status: 'active',
      custodyKeyUrn: null,
      createdAt: '2026-02-01T00:00:00.000Z',
      verifiedAt: '2026-02-01T00:10:00.000Z',
      exportedAt: null,
      retiredAt: null,
    },
    {
      id: 'w3',
      userId: USER_ID,
      origin: 'managed',
      chain: 'BTC',
      network: 'mainnet',
      address: 'bc1q9k2',
      label: 'Cold',
      isPrimary: false,
      // The lifecycle state §6 rule 3 insists must be visible in the list.
      status: 'exported',
      custodyKeyUrn: 'cf:custody:key:3',
      createdAt: '2026-03-01T00:00:00.000Z',
      verifiedAt: null,
      exportedAt: '2026-06-01T00:00:00.000Z',
      retiredAt: null,
    },
  ],

  deposits: [
    {
      id: 'd1',
      assetCode: 'EMBER',
      amount: '500000000000000000',
      amountFormatted: '0.5',
      chain: 'EMBER',
      network: 'mainnet',
      txHash: '0xdeadbeef',
      txUrn: 'cf:chain:ember:mainnet:0xdeadbeef',
      explorerUrl: null,
      confirmations: 41,
      credited: false,
    },
    {
      id: 'd2',
      assetCode: 'BTC',
      amount: '10000000',
      amountFormatted: '0.1',
      chain: 'BTC',
      network: 'mainnet',
      txHash: 'abc123',
      txUrn: 'cf:chain:btc:mainnet:abc123',
      explorerUrl: null,
      confirmations: 6,
      credited: true,
    },
  ],

  withdrawals: [
    {
      id: 'x1',
      userId: USER_ID,
      chain: 'EMBER',
      network: 'mainnet',
      assetCode: 'EMBER',
      destination: 'ember1qdest',
      amount: '1000000000000000000',
      amountFormatted: '1',
      fee: '0',
      net: '1000000000000000000',
      netFormatted: '1',
      state: 'settling',
      txHash: null,
      failureReason: null,
      requestedAt: '2026-07-30T13:00:00.000Z',
      updatedAt: '2026-07-30T13:05:00.000Z',
    },
    {
      id: 'x2',
      userId: USER_ID,
      chain: 'BTC',
      network: 'mainnet',
      assetCode: 'BTC',
      destination: 'bc1qdest',
      amount: '20000000',
      amountFormatted: '0.2',
      fee: '0',
      net: '20000000',
      netFormatted: '0.2',
      state: 'stuck',
      txHash: null,
      failureReason: 'broadcast accepted, no confirmation after 6 hours',
      requestedAt: '2026-07-30T06:00:00.000Z',
      updatedAt: '2026-07-30T12:00:00.000Z',
    },
    {
      id: 'x3',
      userId: USER_ID,
      chain: 'ETH',
      network: 'mainnet',
      assetCode: 'ETH',
      destination: '0xdest',
      amount: '1000000000000000000',
      amountFormatted: '1',
      fee: '0',
      net: '1000000000000000000',
      netFormatted: '1',
      state: 'settled',
      txHash: '0xsettled',
      failureReason: null,
      requestedAt: '2026-07-01T00:00:00.000Z',
      updatedAt: '2026-07-01T00:10:00.000Z',
    },
  ],

  activity: [
    {
      id: 'r1',
      userId: USER_ID,
      occurredAt: '2026-07-30T14:02:00.000Z',
      category: 'market',
      type: 'listing.sold',
      subjectUrn: 'cf:market:listing:1',
      summary: 'Listing sold',
      amount: '240',
      assetCode: 'SHARD',
      product: 'market',
      visibility: 'user',
    },
    {
      id: 'r2',
      userId: USER_ID,
      occurredAt: '2026-07-30T13:48:00.000Z',
      category: 'money',
      type: 'deposit.confirmed',
      subjectUrn: 'cf:chain:ember:mainnet:0xdeadbeef',
      summary: 'Deposit confirmed',
      amount: '500000000000000000',
      assetCode: 'EMBER',
      product: 'wallet',
      visibility: 'user',
    },
  ],

  identityMe: {
    user: {
      id: USER_ID,
      email: 'ash@example.test',
      emailVerifiedAt: '2026-01-01T00:00:00.000Z',
      handle: 'ash',
      status: 'active',
      roles: ['player'],
      createdAt: '2026-01-01T00:00:00.000Z',
      lastSeenAt: '2026-07-30T14:00:00.000Z',
    },
    session: { id: 's1', amr: ['pwd'] },
    organisations: [{ id: 'o1', name: 'Ash' }],
  },

  /** No active factor, which is what raises the "2FA is not enabled" card. */
  identityFactors: { factors: [], recoveryCodesRemaining: 0 },

  entitlements: [
    {
      id: 'ent1',
      sku: 'worlds.plot',
      scope: 'platform',
      source: 'purchase',
      grantedAt: '2026-05-01T00:00:00.000Z',
      expiresAt: null,
      active: true,
    },
  ],

  subscriptions: [
    {
      id: 'sub1',
      productId: 'p1',
      status: 'past_due',
      currentPeriodEnd: '2026-07-28T00:00:00.000Z',
      cancelAt: null,
      scope: 'platform',
      confersAccess: true,
    },
  ],

  freezes: [
    {
      id: 'f1',
      subject: `user:${USER_ID}`,
      scope: 'withdrawal',
      reason: 'reconciliation drift exceeded for BTC',
      createdAt: '2026-07-30T09:00:00.000Z',
      clearedAt: null,
      clearancesRequired: 2,
    },
  ],
} as const

/* ------------------------------------------------------------------ the fake estate */

export type UpstreamName =
  | 'ledger'
  | 'wallet'
  | 'identity'
  | 'billing'
  | 'activity'
  | 'pricing'
  | 'policy'

export const UPSTREAM_NAMES: readonly UpstreamName[] = Object.freeze([
  'ledger',
  'wallet',
  'identity',
  'billing',
  'activity',
  'pricing',
  'policy',
])

type Handler = (url: URL) => { status: number; body: unknown } | null

/** One fake peer: a listener, a route table, and the controls a test needs to break it. */
export class FakeService {
  readonly name: UpstreamName
  readonly #handler: Handler
  #server: Server | undefined
  #port = 0
  /** Requests served since construction. Lets a test prove a cache hit made no call. */
  calls = 0
  /** Milliseconds to stall before answering. Used for the deadline test. */
  latencyMs = 0
  /** When set, every request answers this status instead of routing. */
  failWith: number | null = null

  constructor(name: UpstreamName, handler: Handler) {
    this.name = name
    this.#handler = handler
  }

  get url(): string {
    return `http://127.0.0.1:${this.#port}`
  }

  get alive(): boolean {
    return this.#server !== undefined
  }

  async start(port = 0): Promise<void> {
    const server = createServer((req, res) => void this.#respond(req, res))
    await new Promise<void>((resolve) => server.listen(port, '127.0.0.1', () => resolve()))
    this.#server = server
    this.#port = (server.address() as AddressInfo).port
  }

  /** Close the listener. The next call is refused at the transport, as a dead peer would be. */
  async kill(): Promise<void> {
    const server = this.#server
    if (!server) return
    this.#server = undefined
    await new Promise<void>((resolve) => {
      server.close(() => resolve())
      server.closeAllConnections()
    })
  }

  /** Bring it back on the same port, so a client that cached the URL reconnects. */
  async revive(): Promise<void> {
    if (this.#server) return
    await this.start(this.#port)
  }

  async #respond(req: IncomingMessage, res: ServerResponse): Promise<void> {
    this.calls += 1
    if (this.latencyMs > 0) await delay(this.latencyMs)
    if (this.failWith !== null) {
      res.writeHead(this.failWith, { 'content-type': 'application/json' })
      res.end(JSON.stringify({ error: { code: 'upstream_unwell' } }))
      return
    }
    const url = new URL(req.url ?? '/', 'http://fake')
    const reply = this.#handler(url)
    if (!reply) {
      res.writeHead(404, { 'content-type': 'application/json' })
      res.end(JSON.stringify({ error: { code: 'not_found' } }))
      return
    }
    const payload = JSON.stringify(reply.body)
    res.writeHead(reply.status, {
      'content-type': 'application/json',
      'content-length': Buffer.byteLength(payload),
    })
    res.end(payload)
  }
}

export interface Estate {
  readonly services: Readonly<Record<UpstreamName, FakeService>>
  close(): Promise<void>
}

/** Boot all seven peers. Every route below was read off the peer's own `server.ts`. */
export async function startEstate(): Promise<Estate> {
  const services: Record<UpstreamName, FakeService> = {
    ledger: new FakeService('ledger', (url) =>
      /^\/accounts\/[^/]+\/balances$/.test(url.pathname)
        ? { status: 200, body: { subject: `user:${USER_ID}`, balances: FIXTURES.ledgerBalances } }
        : null,
    ),
    wallet: new FakeService('wallet', (url) => {
      if (url.pathname === '/v1/wallets') return { status: 200, body: { wallets: FIXTURES.wallets, nextCursor: null } }
      if (url.pathname === '/v1/deposits/credits') {
        return { status: 200, body: { credits: FIXTURES.deposits, nextCursor: null } }
      }
      if (url.pathname === '/v1/withdrawals') {
        return { status: 200, body: { withdrawals: FIXTURES.withdrawals, nextCursor: null } }
      }
      return null
    }),
    identity: new FakeService('identity', (url) => {
      // The credential exchange. Every peer client now obtains its token here rather than reading
      // one from the environment, so the fake identity has to be able to mint — a fixture that
      // could not would leave the whole suite exercising a path production does not take.
      //
      // The token it answers with is opaque to this estate: the fake peers below accept any
      // bearer, because what these tests are about is composition and degradation, not the peers'
      // own authorisation. `servicetoken.test.ts` is where a REAL Verifier decides.
      if (url.pathname === '/service-tokens/exchange') {
        return {
          status: 201,
          body: {
            token: 'hub-api-test-token-0000000000000000',
            service: 'hub-api',
            scopes: [],
            expiresIn: 600,
          },
        }
      }
      if (url.pathname === '/auth/me') return { status: 200, body: FIXTURES.identityMe }
      if (url.pathname === '/mfa/factors') return { status: 200, body: FIXTURES.identityFactors }
      return null
    }),
    billing: new FakeService('billing', (url) => {
      if (url.pathname.startsWith('/internal/entitlements/')) {
        return { status: 200, body: { at: '2026-07-30T14:22:00.000Z', entitlements: FIXTURES.entitlements } }
      }
      if (url.pathname === '/subscriptions') {
        return { status: 200, body: { subscriptions: FIXTURES.subscriptions } }
      }
      return null
    }),
    activity: new FakeService('activity', (url) => {
      if (url.pathname !== '/feed') return null
      const limit = Number(url.searchParams.get('limit') ?? '25')
      const cursor = url.searchParams.get('cursor')
      // Keyset paging over the fixture, so the cursor round-trip is real rather than asserted
      // against a constant. `nextCursor` is *omitted* on the last page, exactly as activity's own
      // `toPage` does — the shape this service normalises to `null`.
      const start = cursor ? FIXTURES.activity.findIndex((r) => r.id === cursor) + 1 : 0
      const page = FIXTURES.activity.slice(start, start + limit)
      const more = start + limit < FIXTURES.activity.length
      const last = page[page.length - 1]
      return {
        status: 200,
        body: { records: page, ...(more && last ? { nextCursor: last.id } : {}) },
      }
    }),
    pricing: new FakeService('pricing', (url) =>
      url.pathname === '/rates' ? { status: 200, body: { rates: FIXTURES.pricingRates, spreadBps: 50 } } : null,
    ),
    policy: new FakeService('policy', (url) =>
      /^\/subjects\/[^/]+\/freezes$/.test(url.pathname)
        ? { status: 200, body: { freezes: FIXTURES.freezes } }
        : null,
    ),
  }

  await Promise.all(UPSTREAM_NAMES.map((name) => services[name].start()))
  return {
    services,
    close: async () => {
      await Promise.all(UPSTREAM_NAMES.map((name) => services[name].kill()))
    },
  }
}

/**
 * An `Env` pointing at a running fake estate.
 *
 * This builds an `Env` DIRECTLY rather than through `loadEnv`, so the credential below never faces
 * `@cloudsforge/secrets`' `assertServiceCredential`. That is deliberate and it is the seam these
 * tests are about: composition and degradation, not the peers' own authorisation — each peer
 * already tests that for itself, and the fakes do not inspect the bearer at all. `env.test.ts` is
 * where the guard on that variable is exercised.
 */
export function estateEnv(estate: Estate, overrides: Partial<Env> = {}): Env {
  const url = (name: UpstreamName) => estate.services[name].url
  // A real-shaped credential: ServiceTokenProvider refuses anything not prefixed `cfsc_`,
  // because a container handed a TOKEN where a credential belongs is the defect it exists to
  // prevent, arriving ten minutes later.
  const token = 'cfsc_a-test-credential-that-does-not-expire'
  return {
    port: 0,
    env: 'test',
    version: 'test',
    logLevel: 'error',
    identityJwksUrl: 'http://127.0.0.1:1/.well-known/jwks.json',
    identityIssuer: ISSUER,
    upstreams: {
      ledger: url('ledger'),
      wallet: url('wallet'),
      identity: url('identity'),
      billing: url('billing'),
      activity: url('activity'),
      pricing: url('pricing'),
      policy: url('policy'),
    },
    identityCredential: token,
    legacyServiceTokenPresent: false,
    dashboardDeadlineMs: 2_000,
    upstreamDeadlineMs: 1_000,
    circuitThreshold: 5,
    circuitResetMs: 10_000,
    instanceId: 'test',
    ...overrides,
  }
}

/* ------------------------------------------------------------------ the service under test */

export interface Harness {
  readonly url: string
  readonly estate: Estate
  readonly metrics: Metrics
  readonly cache: TtlCache
  readonly upstreams: Upstreams
  readonly lifecycle: Lifecycle
}

export interface HarnessOptions {
  readonly env?: Partial<Env>
  readonly now?: () => number
  readonly cache?: TtlCache
}

/**
 * Boot the whole service — real router, real verifier, real HTTP clients — against a fake estate,
 * hand it to the test, and tear both down.
 */
export async function withHub(
  options: HarnessOptions,
  fn: (h: Harness) => Promise<void>,
): Promise<void> {
  const estate = await startEstate()
  const env = estateEnv(estate, options.env ?? {})
  const metrics = registerServiceMetrics(registerHttpMetrics(new Metrics()))
  const cache = options.cache ?? new TtlCache(options.now ? { now: options.now } : {})
  const upstreams = httpUpstreams({ env, metrics })
  const lifecycle = new Lifecycle({ cacheMs: 0 })
  // Logs are discarded rather than silenced, so a serialisation failure in a log line would still
  // surface as a thrown error rather than being hidden by a null logger.
  const logger = new Logger({ service: 'hub-api-test', sink: () => {} })

  const server = createHubServer({
    lifecycle,
    logger,
    metrics,
    verifier: testVerifier(),
    upstreams,
    cache,
    dashboardDeadlineMs: env.dashboardDeadlineMs,
    ...(options.now ? { now: options.now } : {}),
  })
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', () => resolve()))
  lifecycle.markReady()
  const { port } = server.address() as AddressInfo

  try {
    await fn({ url: `http://127.0.0.1:${port}`, estate, metrics, cache, upstreams, lifecycle })
  } finally {
    await new Promise<void>((resolve) => server.close(() => resolve()))
    await estate.close()
  }
}

/** `GET` against the harness with a signed user token. */
export async function get(h: Harness, path: string, token?: string): Promise<Response> {
  const bearer = token ?? (await signUser())
  return fetch(`${h.url}${path}`, { headers: { authorization: `Bearer ${bearer}` } })
}
