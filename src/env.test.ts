/**
 * Configuration. `loadEnv` is pure over its source, so every failure path is testable without
 * mutating the process.
 */

import { test } from 'node:test'
import assert from 'node:assert/strict'

const TOKEN = 'hub-api-test-token-0000000000000000'

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
  HUB_LEDGER_TOKEN: TOKEN,
  HUB_WALLET_TOKEN: TOKEN,
  HUB_BILLING_TOKEN: TOKEN,
  HUB_ACTIVITY_TOKEN: TOKEN,
  HUB_PRICING_TOKEN: TOKEN,
  HUB_POLICY_TOKEN: TOKEN,
}
for (const [key, value] of Object.entries(BASE)) process.env[key] = value

const { EnvError, SERVICE, env, loadEnv } = await import('./env.ts')

test('a complete environment loads, and importing the module did not exit', () => {
  assert.equal(SERVICE, 'hub-api')
  assert.equal(env.upstreams.ledger, BASE['LEDGER_URL'])
  assert.equal(env.tokens.pricing, TOKEN)
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

test('there are six upstream tokens and no seventh', () => {
  // Identity is called with the caller's own bearer, because `/auth/me` and `/mfa/factors` refuse
  // a service token outright. A `HUB_IDENTITY_TOKEN` would be a credential that cannot be used,
  // and a credential nobody can use is one nobody rotates.
  const env = loadEnv(BASE)
  assert.deepEqual(Object.keys(env.tokens).sort(), [
    'activity',
    'billing',
    'ledger',
    'policy',
    'pricing',
    'wallet',
  ])
})

test('a placeholder credential is refused outright', () => {
  // A default secret in source is not convenient, it is catastrophic: a placeholder that boots is
  // a placeholder that reaches production.
  assert.throws(
    () => loadEnv({ ...BASE, HUB_PRICING_TOKEN: 'changeme' }),
    /HUB_PRICING_TOKEN is set to a known placeholder/,
  )
})

test('a short credential is refused', () => {
  assert.throws(() => loadEnv({ ...BASE, HUB_POLICY_TOKEN: 'short' }), /at least 24 characters/)
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
