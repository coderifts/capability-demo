'use strict';

/**
 * The adapter SPI — one contract, three strengths.
 *
 * The load-bearing test is that the three implementations are NOT interchangeable and say so.
 * A contract whose weakest adapter reports the same `consumed: true` as its strongest would let a
 * caller pick HTTP and believe it had Postgres's guarantee, which is the confusion the SPI exists
 * to remove. So the assertions check the STRENGTH each one declares, not just the boolean.
 */

const { test, describe } = require('node:test');
const assert = require('node:assert/strict');

const { STRENGTH, REASON, isConsumeOnceResult } = require('../src/adapter-spi');
const pg = require('../src/atomic');
const git = require('../src/git-atomic');
const http = require('../src/http-atomic');

const INPUT = { jti: 'jti-spi-1', target: '/articles/7' };

describe('every adapter implements the contract', () => {
  test('all three export consumeOnce', () => {
    for (const [name, m] of [['postgres', pg], ['git', git], ['http', http]]) {
      assert.equal(typeof m.consumeOnce, 'function', `${name} does not implement the SPI`);
    }
  });

  test('all three return a conforming result', async () => {
    for (const [name, m] of [['postgres', pg], ['git', git], ['http', http]]) {
      const r = await m.consumeOnce(INPUT);
      assert.ok(isConsumeOnceResult(r), `${name} returned a non-conforming result: ${JSON.stringify(r)}`);
    }
  });
});

describe('the strengths are DIFFERENT, and each declares its own', () => {
  test('postgres is ATOMIC_TRANSACTION', async () => {
    assert.equal((await pg.consumeOnce(INPUT)).strength, STRENGTH.ATOMIC_TRANSACTION);
  });

  test('git is EXCLUSIVE_REF_CAS', async () => {
    assert.equal((await git.consumeOnce({ ...INPUT, target: 'refs/heads/x' })).strength, STRENGTH.EXCLUSIVE_REF_CAS);
  });

  test('http is INDETERMINATE, and returns consumed:false — not a hopeful true', async () => {
    const r = await http.consumeOnce(INPUT);
    assert.equal(r.strength, STRENGTH.INDETERMINATE);
    assert.equal(r.consumed, false);
    assert.equal(r.reason, REASON.NO_CROSS_RESOURCE_LEDGER);
  });

  test('no two adapters report the same strength', async () => {
    const s = await Promise.all([
      pg.consumeOnce(INPUT), git.consumeOnce({ ...INPUT, target: 'refs/heads/x' }), http.consumeOnce(INPUT),
    ]);
    const strengths = s.map((r) => r.strength);
    assert.equal(new Set(strengths).size, 3, `strengths collapsed: ${strengths.join(', ')}`);
  });
});

describe('shared input validation cannot drift between the three', () => {
  for (const [name, m, target] of [['postgres', pg, '/a'], ['git', git, 'refs/heads/x'], ['http', http, '/a']]) {
    test(`${name}: a missing jti is refused with a named reason`, async () => {
      const r = await m.consumeOnce({ target });
      assert.equal(r.consumed, false);
      assert.equal(r.reason, REASON.MISSING_JTI);
    });

    test(`${name}: a missing target is refused with a named reason`, async () => {
      const r = await m.consumeOnce({ jti: 'j' });
      assert.equal(r.consumed, false);
      assert.equal(r.reason, REASON.MISSING_TARGET);
    });

    test(`${name}: an expired grant is refused`, async () => {
      const r = await m.consumeOnce({ jti: 'j', target, expires_at: '2000-01-01T00:00:00Z' });
      assert.equal(r.consumed, false);
      assert.equal(r.reason, REASON.EXPIRED);
    });

    test(`${name}: an UNPARSEABLE expiry is treated as expired, never as absent`, async () => {
      // A caller who meant to bound the grant and mistyped must not get an unbounded one.
      const r = await m.consumeOnce({ jti: 'j', target, expires_at: 'not-a-date' });
      assert.equal(r.consumed, false);
      assert.equal(r.reason, REASON.EXPIRED);
    });
  }
});

describe('the shape guard is not vacuous', () => {
  test('it refuses results that omit what the contract requires', () => {
    assert.equal(isConsumeOnceResult(null), false);
    assert.equal(isConsumeOnceResult({ consumed: true }), false, 'a result with no strength must not pass');
    assert.equal(isConsumeOnceResult({ consumed: false, strength: STRENGTH.INDETERMINATE }), false,
      'consumed:false with no reason must not pass');
    assert.equal(isConsumeOnceResult({ consumed: true, strength: 'INVENTED' }), false,
      'an undeclared strength must not pass');
  });
});
