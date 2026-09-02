'use strict';

/**
 * Three sources, one truth: the JSON contract, the SPI code, and the prose tables.
 *
 * The failure this prevents is the one it already caught. docs/adapter-spi.md claimed the SPI
 * strengths were "the same split" as the enforcement-profile names and listed three of the four
 * profiles — which made http's same-resource guarantee (ENFORCING_EXCLUSIVE_HTTP_CAS) disappear
 * from the page. Nothing was checking the two tables against each other, so a sentence that read
 * well was wrong for as long as nobody re-derived it.
 *
 * The two axes are asserted SEPARATELY here, because conflating them is exactly what went wrong:
 * `strength` is about single use, `profile` is about the write path, and http legitimately has one
 * of the first and two of the second.
 */

const { test, describe } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const { STRENGTH } = require('../src/adapter-spi');
const pg = require('../src/atomic');
const git = require('../src/git-atomic');
const http = require('../src/http-atomic');

const ROOT = path.join(__dirname, '..', '..');
const CONTRACT = JSON.parse(fs.readFileSync(path.join(ROOT, 'docs', 'adapter-strength.v1.json'), 'utf8'));
const SPI_MD = fs.readFileSync(path.join(ROOT, 'docs', 'adapter-spi.md'), 'utf8');
const ISO_MD = fs.readFileSync(path.join(ROOT, 'docs', 'host-isolation.md'), 'utf8');

const byId = Object.fromEntries(CONTRACT.adapters.map((a) => [a.adapter_id, a]));
const IMPL = { postgres: pg, git, http };
const TARGET = { postgres: '/articles/7', git: 'refs/heads/x', http: '/a' };

describe('the JSON contract is well-formed', () => {
  test('it declares its spec and every adapter carries the full field set', () => {
    assert.equal(CONTRACT.spec, 'coderifts.adapter-strength.v1');
    for (const a of CONTRACT.adapters) {
      for (const f of ['adapter_id', 'strength', 'single_use_mechanism', 'profile', 'does_not_promise']) {
        assert.ok(a[f] !== undefined && a[f] !== '', `${a.adapter_id} is missing ${f}`);
      }
      assert.ok(Array.isArray(a.profile) && a.profile.length > 0, `${a.adapter_id}: profile must be a non-empty list`);
      assert.ok(a.does_not_promise.length > 20, `${a.adapter_id}: does_not_promise must say something`);
    }
  });

  test('every declared strength is one the SPI code defines', () => {
    const declared = new Set(Object.values(STRENGTH));
    for (const a of CONTRACT.adapters) {
      assert.ok(declared.has(a.strength), `${a.adapter_id}: ${a.strength} is not a strength the code defines`);
    }
    assert.deepEqual(Object.keys(CONTRACT.strengths).sort(), [...declared].sort(),
      'the JSON strength glossary and the code enum must list the same values');
  });
});

describe('AXIS 1 — the JSON agrees with what the SPI code actually returns', () => {
  for (const id of Object.keys(IMPL)) {
    test(`${id}: consumeOnce reports the strength the JSON declares`, async () => {
      const r = await IMPL[id].consumeOnce({ jti: 'jti-contract-1', target: TARGET[id] });
      assert.equal(r.strength, byId[id].strength,
        `${id}: code says ${r.strength}, contract says ${byId[id].strength}`);
    });
  }

  test('the INDETERMINATE adapter still returns consumed:false — the JSON is not aspirational', async () => {
    const r = await IMPL.http.consumeOnce({ jti: 'j', target: '/a' });
    assert.equal(byId.http.strength, STRENGTH.INDETERMINATE);
    assert.equal(r.consumed, false);
  });
});

describe('AXIS 2 — the profile names in the JSON are the constants the adapters export', () => {
  test('git and http profile constants match the JSON', () => {
    assert.deepEqual(byId.git.profile, [git.GIT_PROFILE]);
    assert.deepEqual(byId.http.profile.slice().sort(),
      [http.HTTP_PROFILE, http.HTTP_CROSS_RESOURCE].sort());
  });

  test('http carries BOTH profiles — the omission this test exists for', () => {
    // Listing only INDETERMINATE_HTTP_CAS is what made the same-resource guarantee vanish.
    assert.equal(byId.http.profile.length, 2);
    assert.ok(byId.http.profile.includes('ENFORCING_EXCLUSIVE_HTTP_CAS'));
    assert.ok(byId.http.profile.includes('INDETERMINATE_HTTP_CAS'));
  });

  test('every profile name in the JSON appears in the host-isolation table', () => {
    for (const a of CONTRACT.adapters) {
      for (const p of a.profile) {
        assert.ok(ISO_MD.includes(p), `${p} is in the JSON but not in host-isolation.md`);
      }
    }
  });
});

describe('the prose pages carry the same values', () => {
  for (const a of CONTRACT.adapters) {
    test(`${a.adapter_id}: its strength appears in adapter-spi.md`, () => {
      assert.ok(SPI_MD.includes(a.strength), `${a.strength} is missing from adapter-spi.md`);
    });
  }

  test('adapter-spi.md no longer calls the two axes the same split', () => {
    // The corrected wording, pinned: this is the sentence that was wrong.
    assert.ok(!/same split the enforcement-profile names carry/.test(SPI_MD));
    assert.match(SPI_MD, /NOT the same thing as the enforcement-profile names/);
  });

  test('adapter-spi.md names ALL FOUR profiles, not three', () => {
    for (const p of ['ENFORCING_ATOMIC', 'ENFORCING_EXCLUSIVE_REF_CAS',
      'ENFORCING_EXCLUSIVE_HTTP_CAS', 'INDETERMINATE_HTTP_CAS']) {
      assert.ok(SPI_MD.includes(p), `adapter-spi.md omits ${p}`);
    }
  });

  test('no two adapters share a strength — the distinction survives all three sources', () => {
    const s = CONTRACT.adapters.map((a) => a.strength);
    assert.equal(new Set(s).size, s.length);
  });
});
