/**
 * The "needs you" cards, as pure functions over tiles.
 *
 * The dashboard suite proves they degrade over real sockets. This one proves the rules: a verb on
 * every card, a stable id, an ordering that does not shuffle, and — the one that matters — an
 * absent card rather than a broken one when its source is down (§6 rule 2).
 */

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { CHAINS, RETIRED_ASSETS } from '@cloudsforge/contracts-chain'
import { buildNextActions, type NextActionInputs } from './nextactions.ts'
import { okTile, unavailableTile, type Tile } from './tiles.ts'
import type {
  BillingSubscription,
  DepositCredit,
  PolicyFreeze,
  WithdrawalRecord,
} from './upstreams.ts'

const deposit = (over: Partial<DepositCredit> = {}): DepositCredit => ({
  id: 'd1',
  assetCode: 'EMBER',
  amount: '500000000000000000',
  amountFormatted: '0.5',
  chain: 'EMBER',
  network: 'mainnet',
  txHash: '0xabc',
  txUrn: 'cf:chain:ember:mainnet:0xabc',
  explorerUrl: null,
  confirmations: 41,
  credited: false,
  ...over,
})

const withdrawal = (over: Partial<WithdrawalRecord> = {}): WithdrawalRecord => ({
  id: 'x1',
  userId: 'u1',
  chain: 'BTC',
  network: 'mainnet',
  assetCode: 'BTC',
  destination: 'bc1q',
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
  ...over,
})

const freeze = (over: Partial<PolicyFreeze> = {}): PolicyFreeze => ({
  id: 'f1',
  subject: 'user:u1',
  scope: 'withdrawal',
  reason: 'reconciliation drift exceeded',
  createdAt: '2026-07-30T09:00:00.000Z',
  clearedAt: null,
  clearancesRequired: 2,
  ...over,
})

const subscription = (over: Partial<BillingSubscription> = {}): BillingSubscription => ({
  id: 'sub1',
  productId: 'p1',
  status: 'past_due',
  currentPeriodEnd: null,
  cancelAt: null,
  scope: 'platform',
  confersAccess: true,
  ...over,
})

function inputs(over: Partial<NextActionInputs> = {}): NextActionInputs {
  return {
    deposits: okTile('wallet', [] as readonly DepositCredit[]),
    withdrawals: okTile('wallet', [] as readonly WithdrawalRecord[]),
    // A healthy account by default — MFA on, codes in hand — so that a test asserting on one card
    // is not silently also asserting on the security card.
    factors: okTile('identity', { factors: [{ status: 'active' }], recoveryCodesRemaining: 10 }),
    freezes: okTile('policy', [] as readonly PolicyFreeze[]),
    subscriptions: okTile('billing', [] as readonly BillingSubscription[]),
    ...over,
  }
}

test('an unconfirmed deposit becomes a card with its progress against the contract depth', () => {
  const { actions } = buildNextActions(inputs({ deposits: okTile('wallet', [deposit()]) }))
  const card = actions[0]
  assert.equal(card?.kind, 'deposit_confirming')
  assert.equal(card?.verb, 'Track')
  assert.equal(card?.href, '/wallet/deposits/d1')
  // 60 is EMBER's confirmation depth in contracts-chain — the same constant wallet and settlement
  // credit against, never a number this service chose.
  assert.deepEqual(card?.progress, { done: 41, total: 60, etaMinutes: 5 })
})

test('a credited deposit raises nothing', () => {
  const { actions } = buildNextActions(
    inputs({ deposits: okTile('wallet', [deposit({ credited: true })]) }),
  )
  assert.deepEqual(actions, [])
})

test('only a stuck withdrawal raises a card, and it is critical', () => {
  // `stuck` is the only non-terminal failure state: the reservation is held and the payment's fate
  // is unknown, so the money is neither the user's nor gone.
  const { actions } = buildNextActions(
    inputs({
      withdrawals: okTile('wallet', [
        withdrawal(),
        withdrawal({ id: 'x2', state: 'settling' }),
        withdrawal({ id: 'x3', state: 'settled' }),
      ]),
    }),
  )
  assert.equal(actions.length, 1)
  assert.equal(actions[0]?.id, 'withdrawal_stuck:x1')
  assert.equal(actions[0]?.severity, 'critical')
})

test('no active factor raises the 2FA card', () => {
  const { actions } = buildNextActions(
    inputs({ factors: okTile('identity', { factors: [{ status: 'pending' }], recoveryCodesRemaining: 8 }) }),
  )
  assert.equal(actions[0]?.kind, 'mfa_disabled')
  assert.equal(actions[0]?.verb, 'Enable')
})

test('low recovery codes are raised only once MFA is actually on', () => {
  // Two cards competing for one action would let the wrong one win.
  const off = buildNextActions(
    inputs({ factors: okTile('identity', { factors: [], recoveryCodesRemaining: 0 }) }),
  )
  assert.deepEqual(off.actions.map((a) => a.kind), ['mfa_disabled'])

  const on = buildNextActions(
    inputs({ factors: okTile('identity', { factors: [{ status: 'active' }], recoveryCodesRemaining: 1 }) }),
  )
  assert.deepEqual(on.actions.map((a) => a.kind), ['recovery_codes_low'])
})

test('a cleared freeze raises nothing', () => {
  const { actions } = buildNextActions(
    inputs({ freezes: okTile('policy', [freeze({ clearedAt: '2026-07-30T10:00:00.000Z' })]) }),
  )
  assert.deepEqual(actions, [])
})

test('only a past-due subscription raises a card', () => {
  const { actions } = buildNextActions(
    inputs({
      subscriptions: okTile('billing', [subscription(), subscription({ id: 's2', status: 'active' })]),
    }),
  )
  assert.equal(actions.length, 1)
  assert.equal(actions[0]?.id, 'subscription_past_due:sub1')
})

test('the past-due card names no asset at all, because this service cannot know which one', () => {
  // micro-org #227. This card said "Top up Shards to keep access." for as long as SHARD had been
  // retired — `RETIRED_ASSETS` in contracts/packages/chain/src/index.ts — telling a user whose
  // renewal had just failed to acquire an asset the estate no longer issues.
  //
  // The replacement is not "say EMBER" even though EMBER is what a renewal really settles in
  // (`settlementAsset` in billing/src/env.ts, pinned by billing/src/env.test.ts). A
  // `BillingSubscription` carries no asset and no amount, so any denomination on this card is a
  // constant copied out of another service's environment — right until billing changes it, and
  // wrong silently afterwards, which is exactly how the Shards string outlived the retirement.
  //
  // Asserted against `CHAINS` rather than against the one word that was wrong: a test that only
  // forbade "Shards" would pass the day somebody typed "EMBER" here instead, and that string would
  // be a second copy of billing's configuration living in a BFF that owns no state.
  const { actions } = buildNextActions(
    inputs({ subscriptions: okTile('billing', [subscription()]) }),
  )
  const card = actions.find((a) => a.kind === 'subscription_past_due')
  assert.ok(card, 'a past-due subscription must raise a card')
  assert.equal(card.detail, 'Top up your balance to keep access.')

  const copy = `${card.title} ${card.detail} ${card.verb}`.toLowerCase()
  for (const asset of Object.keys(CHAINS)) {
    assert.equal(
      copy.includes(asset.toLowerCase()),
      false,
      `the past-due card names ${asset}; it is built from a record that carries no asset`,
    )
  }
  // And the retired one specifically, spelled out so a reader of a failure knows which defect
  // came back. `RETIRED_ASSETS` is the authority; 'Shards' is only its display spelling.
  for (const retired of RETIRED_ASSETS) {
    assert.equal(copy.includes(retired.toLowerCase()), false, `the past-due card names ${retired}`)
  }
})

test('a card whose source is down is absent, not broken, and the source is recorded', () => {
  const { actions, missing } = buildNextActions(
    inputs({
      deposits: unavailableTile('wallet', [] as readonly DepositCredit[], 'wallet could not be reached'),
      freezes: okTile('policy', [freeze()]),
    }),
  )
  assert.deepEqual(actions.map((a) => a.kind), ['account_frozen'])
  assert.deepEqual(missing, [{ source: 'wallet', reason: 'wallet could not be reached' }])
})

test('a degraded source still produces its cards', () => {
  // Stale is not absent. A freeze from thirty seconds ago is still a freeze, and hiding it would
  // be the cache making a safety decision.
  const stale: Tile<readonly PolicyFreeze[]> = {
    status: 'degraded',
    upstream: 'policy',
    reason: 'policy could not be reached; showing a cached value',
    cached: true,
    ageMs: 45_000,
    data: [freeze()],
  }
  const { actions, missing } = buildNextActions(inputs({ freezes: stale }))
  assert.equal(actions.length, 1)
  assert.deepEqual(missing, [])
})

test('cards are ordered critical, warning, info, and stably within each', () => {
  const { actions } = buildNextActions(
    inputs({
      deposits: okTile('wallet', [deposit()]),
      withdrawals: okTile('wallet', [withdrawal()]),
      factors: okTile('identity', { factors: [], recoveryCodesRemaining: 0 }),
      freezes: okTile('policy', [freeze()]),
      subscriptions: okTile('billing', [subscription()]),
    }),
  )
  assert.deepEqual(
    actions.map((a) => a.severity),
    ['critical', 'critical', 'warning', 'warning', 'info'],
  )
  // Ids are derived from the subject, never from a counter, so a dismissal survives a refresh.
  assert.deepEqual(
    actions.map((a) => a.id),
    [
      'account_frozen:f1',
      'withdrawal_stuck:x1',
      'mfa_disabled',
      'subscription_past_due:sub1',
      'deposit_confirming:d1',
    ],
  )
})

test('a deposit in an asset with no known depth policy still appears, without a fraction', () => {
  const { actions } = buildNextActions(
    inputs({ deposits: okTile('wallet', [deposit({ assetCode: 'DOGE', confirmations: 3 })]) }),
  )
  assert.equal(actions[0]?.detail, '3 confirmations so far')
  assert.equal(actions[0]?.progress, null, '"3/0" is worse than no fraction')
})
