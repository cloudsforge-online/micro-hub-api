/**
 * The composition root.
 *
 * Everything this service is made of is constructed here, once, in an order that is not arbitrary.
 * It is shorter than the template's by four steps, and each absence is deliberate rather than
 * unfinished:
 *
 *   - **No pool, no schema assertion, no migrator.** This service owns no table. There is nothing
 *     to migrate and nothing to assert, because there is no state here whose shape could be wrong.
 *   - **No job runner and no outbox.** It produces no events: it has no state changes to announce,
 *     and an event emitted by a read-only composition would be an event about somebody else's
 *     domain, published by a service with no authority over it.
 *
 * What replaces them is one object: the cache. Losing it costs a slow request and nothing more,
 * which is the property that makes this service safe to restart at any moment, scale to any
 * replica count, and deploy without a migration window.
 *
 * Traces are exported by the OpenTelemetry SDK loaded ahead of this module —
 * `NODE_OPTIONS=--import @opentelemetry/auto-instrumentations-node/register` in the deploy, which
 * reads `OTEL_EXPORTER_OTLP_ENDPOINT` and friends from the environment itself. That is why no
 * `OTEL_*` variable appears in `src/env.ts`: the service does not read them, so under rule 9 it
 * must not declare them.
 */

import { Verifier } from '@cloudsforge/auth'
import { Lifecycle, httpProbe, installSignalHandlers } from '@cloudsforge/lifecycle'
import { Logger, Metrics, registerHttpMetrics } from '@cloudsforge/telemetry'
import { TtlCache } from './cache.ts'
import { SERVICE, env } from './env.ts'
import { createServer, registerServiceMetrics } from './server.ts'
import { httpUpstreams } from './upstreams.ts'

// 1. Environment. Importing `./env.ts` validated it; a missing or placeholder secret has already
//    exited with a structured line naming the variable. Nothing below may run first, because every
//    step after this reads configuration.
//
// 2. Telemetry, before anything that can fail. A logger that exists before the clients means a
//    client's construction failure is a structured, searchable, redacted line rather than a bare
//    V8 stack the collector drops.
const logger = new Logger({
  service: SERVICE,
  level: env.logLevel,
  version: env.version,
  env: env.env,
})
const metrics = registerServiceMetrics(registerHttpMetrics(new Metrics()))
logger.info('starting', {
  version: env.version,
  dashboardDeadlineMs: env.dashboardDeadlineMs,
  upstreamDeadlineMs: env.upstreamDeadlineMs,
})

// 3. The upstream clients, before the Lifecycle, because the readiness report closes over their
//    breaker state. One client per peer: `@cloudsforge/http` scopes its circuit breaker to the
//    client, so sharing one would let a sick pricing service open the circuit on the ledger.
const upstreams = httpUpstreams({ env, metrics })

// 4. The cache. In-process and per-replica, on purpose. A shared cache (Redis, say) would be a
//    stateful dependency for a stateless service and would make an outage of *it* an outage of
//    the dashboard — which is precisely the coupling this service exists to avoid. Per-replica
//    caching costs a slightly lower hit rate and buys a component that cannot fail.
const cache = new TtlCache()

// 5. The Lifecycle and its probes, before the routes, because `/readyz` is a route and it needs
//    something to report.
const lifecycle = new Lifecycle({
  // Must exceed one load-balancer probe interval or the balancer is still sending traffic when
  // the process stops accepting it.
  drainDelayMs: 5_000,
  drainTimeoutMs: 25_000,
  onStateChange: (state) => logger.info('lifecycle state', { state }),
})

// Every probe here is soft, and that is the whole readiness policy of this service.
//
// A hard probe on an upstream would take this replica out of the balancer whenever a peer was
// unwell — which is to say, it would turn a page with one degraded tile into no page at all. The
// dashboard is designed to serve through exactly that condition, so readiness must not contradict
// it. The JWKS probe is soft for the estate-wide reason: making it hard means one identity blip
// removes every service from its balancer at once, which is a cascade, not a safety measure.
lifecycle
  .addProbe(httpProbe('identity-jwks', env.identityJwksUrl, { kind: 'soft' }))
  .addProbe(httpProbe('ledger', `${env.upstreams.ledger.replace(/\/+$/, '')}/livez`, { kind: 'soft' }))
  .addProbe(httpProbe('wallet', `${env.upstreams.wallet.replace(/\/+$/, '')}/livez`, { kind: 'soft' }))
  .addProbe(httpProbe('pricing', `${env.upstreams.pricing.replace(/\/+$/, '')}/livez`, { kind: 'soft' }))
  .addProbe(httpProbe('activity', `${env.upstreams.activity.replace(/\/+$/, '')}/livez`, { kind: 'soft' }))

// 6. Routes. Constructed after the Lifecycle so the health handlers report real state, and after
//    the clients so a route never lazily constructs one on first request.
const verifier = new Verifier({ jwksUrl: env.identityJwksUrl, issuer: env.identityIssuer })
const server = createServer({
  lifecycle,
  logger,
  metrics,
  verifier,
  upstreams,
  cache,
  dashboardDeadlineMs: env.dashboardDeadlineMs,
  // Cache occupancy is sampled at scrape time rather than on a timer. There is no `setInterval` in
  // this repository, and CI greps for one — rule 8.
  beforeScrape: async () => {
    metrics.set('hub_cache_entries', cache.size)
  },
})

metrics.register({
  name: 'hub_cache_entries',
  help: 'Entries currently held in the in-process tile cache',
  kind: 'gauge',
})

// 7. Listen. A socket that accepts before its dependencies exist is a socket that answers 500.
await new Promise<void>((resolve, reject) => {
  server.once('error', reject)
  server.listen(env.port, () => resolve())
})
logger.info('listening', { port: env.port })

// 8. Ready. Only now: the state moves `starting → ready`, `/readyz` starts answering 200, and the
//    balancer is allowed to send traffic. Flipping this before `listen()` would advertise a
//    replica that has no socket.
lifecycle.markReady()

// 9. Signal handlers, last of all. Installing them earlier means a SIGTERM arriving mid-boot
//    drains a service that was never ready. Hooks run in reverse registration order.
lifecycle.onShutdown(
  () =>
    new Promise<void>((resolve) => {
      server.close(() => resolve())
      // Idle keep-alive sockets hold the server open past the drain budget. Closing them is what
      // makes `server.close()` a bounded operation rather than a wait on the slowest client.
      server.closeIdleConnections()
    }),
)

installSignalHandlers(lifecycle)
