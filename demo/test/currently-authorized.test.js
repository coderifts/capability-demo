'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const ROOT = path.join(__dirname, '..', '..');
const BIN = path.join(ROOT, 'examples', 'currently-authorized', 'run.js');

describe('currently-authorized — one call, one screen', () => {
  it('prints currently_authorized true then false and exits 0', () => {
    const r = spawnSync(process.execPath, [BIN], { encoding: 'utf8', cwd: ROOT });
    assert.equal(r.status, 0, r.stdout + r.stderr);
    assert.match(r.stdout, /ALLOW\s+currently_authorized: true\s+GRANT_CURRENT/);
    assert.match(r.stdout, /BLOCK\s+currently_authorized: false\s+GRANT_SCOPE_MISMATCH/);
    assert.match(r.stdout, /OK  authorized vs blocked on one screen/);
  });
});
