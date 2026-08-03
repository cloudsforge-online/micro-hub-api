/**
 * **The ten-minute cliff, end to end, through the wiring this service actually uses.**
 *
 * `@cloudsforge/auth` proves the provider in isolation. This file proves the ADOPTION.
 *
 *     token: () => token        // upstreams.ts, six times, before this change
 *
 * Six strings read once at boot from tokens that expire in 600 seconds
 * (identity/src/tokens.ts:28), which nothing could re-mint because minting required the `admin`
 * role. Ten minutes into every deployment all six died at once and every tile on the dashboard
 * went `unavailable` — the widest blast radius of the defect anywhere in the estate, because this
 * is the surface a user actually looks at.
 *
 * WHY THIS SUITE COULD NOT SEE IT. Every other test here builds clients against a fake estate and
 * calls them immediately, so a token is never asked to survive its own lifetime. **A test that
 * mints a token and immediately uses it proves nothing about this defect.** The tests below move a
 * simulated clock eleven minutes past a token already held, assert it is REFUSED BY A REAL
 * `Verifier`, and only then assert a tile still renders.
 *
 * They go through the real `httpUpstreams`, not a hand-rolled provider: "the provider is correct"
 * and "the provider is wired in" are separate failures, and only the second was ever the bug.
 */

import { test, mock } from 'node:test'
import assert from 'node:assert/strict'
import { SignJWT, generateKeyPair } from 'jose'
import { AUDIENCE, Verifier, serviceTokenProbe } from '@cloudsforge/auth'
import { Metrics } from '@cloudsforge/telemetry'
import { UPSTREAM_SCOPES, httpUpstreams } from './upstreams.ts'
import type { Env } from './env.ts'

const ISSUER = 'https://identity.test'
const IDENTITY = 'http://identity:4000'
const CREDENTIAL = 'cfsc_a-long-lived-credential-that-does-not-expire'

/** identity/src/tokens.ts:28. Unchanged by this fix, and it must stay unchanged. */
const SERVICE_TTL_SECONDS = 600

const T0 = Date.UTC(2026, 7, 3, 12, 0, 0)

function clockAt(ms: number): void {
  mock.timers.reset()
  mock.timers.enable({ apis: ['Date'], now: new Date(T0 + ms) })
}

interface World {
  readonly fetch: typeof globalThis.fetch
  /** The scope set each exchange asked for, in order. */
  scopeRequests: string[][]
  peerCalls: Array<{ token: string | null; status: number }>
  identityDown: boolean
}

/**
 * A real identity and a real peer. Identity signs RS256 with a 600-second expiry against the
 * simulated clock and ECHOES BACK the scopes it was asked for; the peer hands whatever it is given
 * to a real `Verifier` and answers 401 when jose says the token is bad. Nothing decides expiry by
 * hand — deciding it by hand is how a test comes to agree with the code it is checking.
 */
async function world(): Promise<World> {
  const { publicKey, privateKey } = await generateKeyPair('RS256', { extractable: true })
  const keySet = (async () => publicKey) as never
  const verifier = new Verifier({ jwksUrl: 'http://unused', issuer: ISSUER, keySet })
  let jti = 0

  const self: World = {
    scopeRequests: [],
    peerCalls: [],
    identityDown: false,
    fetch: (async (input, init) => {
      const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url

      if (url.endsWith('/service-tokens/exchange')) {
        if (self.identityDown) throw new TypeError('fetch failed: ECONNREFUSED')
        if (new Headers(init?.headers).get('authorization') !== `Bearer ${CREDENTIAL}`) {
          return new Response('{"error":"unauthenticated"}', { status: 401 })
        }
        const body = JSON.parse(String(init?.body ?? '{}')) as { scopes?: string[] }
        const scopes = body.scopes ?? []
        self.scopeRequests.push(scopes)
        // RS256 is deterministic, so a jti is what makes two tokens minted at the same simulated
        // instant different strings. identity mints a uuidv7 per token.
        const token = await new SignJWT({ typ: 'service', scopes, jti: `t-${++jti}` })
          .setProtectedHeader({ alg: 'RS256', kid: 'k1' })
          .setIssuedAt()
          .setIssuer(ISSUER)
          .setAudience(AUDIENCE)
          .setSubject('service:hub-api')
          .setExpirationTime(Math.floor(Date.now() / 1000) + SERVICE_TTL_SECONDS)
          .sign(privateKey)
        return new Response(
          JSON.stringify({ token, service: 'hub-api', scopes, expiresIn: SERVICE_TTL_SECONDS }),
          { status: 201, headers: { 'content-type': 'application/json' } },
        )
      }

      if (self.peerCalls.length > 32) throw new Error('the 401 replay is looping')
      const presented =
        new Headers(init?.headers).get('authorization')?.replace(/^Bearer /, '') ?? null
      if (presented === null) {
        self.peerCalls.push({ token: null, status: 401 })
        return new Response('{"error":"unauthenticated"}', { status: 401 })
      }
      try {
        await verifier.principal(presented)
        self.peerCalls.push({ token: presented, status: 200 })
        return new Response(JSON.stringify({ rates: [] }), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        })
      } catch {
        self.peerCalls.push({ token: presented, status: 401 })
        return new Response('{"error":"unauthenticated"}', { status: 401 })
      }
    }) as typeof globalThis.fetch,
  }
  return self
}

/** `httpUpstreams`, not a hand-rolled client — the whole point of the file. */
function upstreamsFor(w: World, credential: string | null) {
  const at = (name: string) => `http://${name}:4000`
  const env = {
    port: 0,
    env: 'test',
    version: 'test',
    logLevel: 'error',
    identityJwksUrl: 'http://unused',
    identityIssuer: ISSUER,
    upstreams: {
      ledger: at('ledger'),
      wallet: at('wallet'),
      identity: IDENTITY,
      billing: at('billing'),
      activity: at('activity'),
      pricing: at('pricing'),
      policy: at('policy'),
    },
    identityCredential: credential,
    legacyServiceTokenPresent: false,
    dashboardDeadlineMs: 2_000,
    upstreamDeadlineMs: 1_000,
    circuitThreshold: 5,
    circuitResetMs: 10_000,
    instanceId: 'test',
  } as unknown as Env
  return httpUpstreams({ env, metrics: new Metrics(), fetch: w.fetch })
}

/* ────────────────────────────────────────────────────────────────────────────────────────────────
 * THE REGRESSION TEST.
 * ──────────────────────────────────────────────────────────────────────────────────────────────── */

test('a tile still renders ELEVEN MINUTES after boot — the ten-minute cliff', async (t) => {
  const w = await world()
  t.after(() => mock.timers.reset())

  clockAt(0)
  const upstreams = upstreamsFor(w, CREDENTIAL)

  // T+0. Every existing test in this repository stops looking here, and everything is fine.
  await upstreams.pricingRates('req-1')
  const atBoot = w.peerCalls.at(-1)?.token
  assert.equal(w.peerCalls.at(-1)?.status, 200)
  assert.ok(atBoot)

  // T+11min.
  clockAt((SERVICE_TTL_SECONDS + 60) * 1000)

  // FIRST — the cliff reproduced against a real verifier, which is also the OLD SEAM modelled
  // exactly: `token: () => token` is a supplier that returns the same string for ever.
  const stale = await w.fetch('http://pricing:4000/rates', {
    headers: { authorization: `Bearer ${atBoot}` },
  })
  assert.equal(stale.status, 401, 'the token held at boot MUST be dead by now')

  // SECOND — the fix, through the wiring `src/index.ts` uses.
  await upstreams.pricingRates('req-2')
  assert.equal(w.peerCalls.at(-1)?.status, 200, 'the tile must still render past the first expiry')
  assert.notEqual(w.peerCalls.at(-1)?.token, atBoot, 'and on a genuinely new token')
})

test('the six peers get six SEPARATE narrow tokens from the one credential', async (t) => {
  const w = await world()
  t.after(() => mock.timers.reset())
  clockAt(0)

  const upstreams = upstreamsFor(w, CREDENTIAL)
  // Two peers, so two exchanges with two different scope sets. A single whole-allowlist token
  // would be ONE string in this process's memory that reads wallets, ledgers, billing and policy
  // at once — which is exactly the property AD-05 exists to deny, and this is the estate's
  // highest fan-out surface.
  await upstreams.pricingRates('req-1')
  await upstreams.policyFreezes('user-1', 'req-2').catch(() => {})

  assert.equal(w.scopeRequests.length, 2, 'the peers must not share one token')
  assert.deepEqual(w.scopeRequests[0], [...UPSTREAM_SCOPES.pricing])
  assert.deepEqual(w.scopeRequests[1], [...UPSTREAM_SCOPES.policy])
  // Never the whole allowlist, and never empty — an empty scope list asks identity for everything.
  for (const requested of w.scopeRequests) {
    assert.equal(requested.length, 1, `asked for ${requested.length} scopes: ${requested.join()}`)
  }
})

test('an unreachable identity is a 503, never an unauthenticated peer call', async (t) => {
  const w = await world()
  t.after(() => mock.timers.reset())
  clockAt(0)

  const upstreams = upstreamsFor(w, CREDENTIAL)
  await upstreams.pricingRates('req-1')

  w.identityDown = true
  clockAt((SERVICE_TTL_SECONDS + 60) * 1000)
  const before = w.peerCalls.length

  await assert.rejects(() => upstreams.pricingRates('req-2'))
  // The peer was never dialled. Sending the expired token, or none, would produce a 401 from a
  // healthy pricing — and on this surface a 401 is the shape that reads as "the user is signed
  // out", which is precisely the misattribution `Verifier` refuses to make inbound.
  assert.equal(w.peerCalls.length, before, 'nothing stale or unauthenticated was sent')
})

test('with no credential the service is NOT ready, and every tile fails closed', async (t) => {
  const w = await world()
  t.after(() => mock.timers.reset())
  clockAt(0)

  const upstreams = upstreamsFor(w, null)
  for (const [peer, provider] of Object.entries(upstreams.tokenProviders)) {
    assert.equal(provider, null, `${peer} built a provider without a credential`)
  }

  const probe = serviceTokenProbe(upstreams.tokenProviders.ledger)
  assert.equal(probe.kind, 'hard')
  assert.equal((await probe.check()).state, 'fail', 'an unconfigured replica must not take traffic')

  await assert.rejects(() => upstreams.pricingRates('req-1'))
  assert.equal(w.peerCalls.length, 0, 'and nothing was sent unauthenticated')
})
