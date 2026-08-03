/**
 * Configuration. `loadEnv` is pure over its source, so every failure path is testable without
 * mutating the process.
 */

import { test } from 'node:test'
import assert from 'node:assert/strict'

const CREDENTIAL = 'cfsc_a-long-lived-credential-that-does-not-expire'

/**
 * A valid environment, applied to the process before `./env.ts` is imported.
 *
 * The import itself is a test: `env.ts` validates eagerly and calls `process.exit(1)` on a bad
 * configuration, so if these values were not sufficient this file would not run at all. The
 * failure cases below go through `loadEnv`, which is pure over its source and therefore testable
 * without a child process.
 */
const BASE: Record<string, string> = {
  IDENTITY_JWKS_URL: 'http://127.0.0.1:4001/.well-known/jwks.json',
  IDENTITY_ISSUER: 'http://127.0.0.1:4001',
  LEDGER_URL: 'http://127.0.0.1:4002',
  WALLET_URL: 'http://127.0.0.1:4003',
  IDENTITY_URL: 'http://127.0.0.1:4001',
  BILLING_URL: 'http://127.0.0.1:4004',
  ACTIVITY_URL: 'http://127.0.0.1:4005',
  PRICING_URL: 'http://127.0.0.1:4006',
  POLICY_URL: 'http://127.0.0.1:4007',
}
for (const [key, value] of Object.entries(BASE)) process.env[key] = value

const { EnvError, SERVICE, env, loadEnv } = await import('./env.ts')
const { UPSTREAM_SCOPES } = await import('./upstreams.ts')

test('a complete environment loads, and importing the module did not exit', () => {
  assert.equal(SERVICE, 'hub-api')
  assert.equal(env.upstreams.ledger, BASE['LEDGER_URL'])
  assert.equal(env.identityCredential, null, 'not in BASE — it is optional by design')
})

test('the defaults are the documented ones', () => {
  const env = loadEnv(BASE, 'host-1')
  assert.equal(env.port, 4000)
  assert.equal(env.dashboardDeadlineMs, 2_500)
  assert.equal(env.upstreamDeadlineMs, 1_500)
  assert.equal(env.circuitThreshold, 5)
  assert.equal(env.instanceId, 'host-1')
})

test('a missing variable names itself', () => {
  const { WALLET_URL: _omitted, ...without } = BASE
  assert.throws(() => loadEnv(without), (err: unknown) => {
    assert.ok(err instanceof EnvError)
    assert.match(err.message, /WALLET_URL/)
    return true
  })
})

test('there are six upstream SCOPE SETS and no seventh', () => {
  // This used to assert six token VARIABLES. There is now one credential and six scope sets, which
  // is the same separation held one layer down: identity reads the service off the credential row,
  // so the scope set is a request parameter rather than a second secret.
  //
  // Identity is still absent by construction, because `/auth/me` and `/mfa/factors` refuse a
  // service token outright. A seventh scope set would be one that cannot be used, and a credential
  // nobody can use is one nobody rotates.
  assert.deepEqual(Object.keys(UPSTREAM_SCOPES).sort(), [
    'activity',
    'billing',
    'ledger',
    'policy',
    'pricing',
    'wallet',
  ])
  // Each is exactly one scope, and none of them is a wildcard: this is the highest fan-out surface
  // in the estate, so a token here reads one thing or it is too wide.
  for (const [peer, scopes] of Object.entries(UPSTREAM_SCOPES)) {
    assert.equal(scopes.length, 1, `${peer} asks for more than one scope`)
    assert.doesNotMatch(scopes[0] ?? '', /\*/, `${peer} asks for a wildcard scope`)
  }
})

test('a placeholder credential is refused outright', () => {
  // A default secret in source is not convenient, it is catastrophic: a placeholder that boots is
  // a placeholder that reaches production.
  assert.throws(
    () => loadEnv({ ...BASE, HUB_API_IDENTITY_CREDENTIAL: 'changeme' }),
    /HUB_API_IDENTITY_CREDENTIAL is set to a known placeholder/,
  )
})

test('a short credential is refused', () => {
  // HUB_POLICY_TOKEN was the subject here; it is retired, and the credential that replaced all six
  // takes the same length floor for the same reason.
  assert.throws(
    () => loadEnv({ ...BASE, HUB_API_IDENTITY_CREDENTIAL: 'short' }),
    /at least 24 characters/,
  )
})

test('an upstream deadline above the page budget is refused at boot', () => {
  // Caught here because the failure it produces is silent: the dashboard would appear to work and
  // would simply never degrade, because no tile could reach its own deadline first.
  assert.throws(
    () => loadEnv({ ...BASE, HUB_UPSTREAM_DEADLINE_MS: '5000', HUB_DASHBOARD_DEADLINE_MS: '1000' }),
    /must not exceed/,
  )
})

test('a non-integer deadline is refused rather than coerced', () => {
  assert.throws(() => loadEnv({ ...BASE, HUB_DASHBOARD_DEADLINE_MS: '2.5' }), /whole number/)
  assert.throws(() => loadEnv({ ...BASE, PORT: '70000' }), /between 1 and 65535/)
})

test('no database url is read, and none may be added', () => {
  // The constraint this service is built around, asserted rather than assumed: a connection string
  // here would be the first step towards a table holding a stale copy of somebody else truth.
  const env = loadEnv(BASE)
  assert.ok(!('databaseUrl' in env), 'hub-api owns no state and must read no connection string')
})

/* ────────────────────────────────────────────────────────────────────────────────────────────────
 * The one credential that replaced six tokens.
 * ──────────────────────────────────────────────────────────────────────────────────────────────── */

test('the identity credential is read, and its absence is a null rather than a throw', () => {
  assert.equal(
    loadEnv({ ...BASE, HUB_API_IDENTITY_CREDENTIAL: CREDENTIAL }).identityCredential,
    CREDENTIAL,
  )
  // Absent must LOAD — the image has to boot without one so the CI smoke test can read /livez —
  // and is caught by the hard `identity-credential` readiness probe instead.
  assert.equal(loadEnv(BASE).identityCredential, null)
})

test('any of the six retired tokens being set is reported rather than obeyed', () => {
  assert.equal(loadEnv(BASE).legacyServiceTokenPresent, false)
  for (const name of [
    'HUB_LEDGER_TOKEN',
    'HUB_WALLET_TOKEN',
    'HUB_BILLING_TOKEN',
    'HUB_ACTIVITY_TOKEN',
    'HUB_PRICING_TOKEN',
    'HUB_POLICY_TOKEN',
  ]) {
    const env = loadEnv({ ...BASE, [name]: 'a-real-looking-token-of-sufficient-length' })
    assert.equal(env.legacyServiceTokenPresent, true, `${name} was not noticed`)
    // And it confers nothing: setting it must not make the service look configured.
    assert.equal(env.identityCredential, null)
  }
})
