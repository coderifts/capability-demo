'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const { parseCli, PKG } = require('../bin/prove-all.js');

function parse(...args) {
  return parseCli(['node', 'prove-all.js', ...args]);
}

describe('parseCli (1880) — before any initialization', () => {
  it('--help and -h', () => {
    assert.equal(parse('--help').help, true);
    assert.equal(parse('-h').help, true);
    assert.equal(parse('--help').error, null);
  });

  it('--version and -V', () => {
    assert.equal(parse('--version').version, true);
    assert.equal(parse('-V').version, true);
    assert.equal(PKG.version, require('../package.json').version);
  });

  it('unknown argument is an error, not a full run', () => {
    const o = parse('--not-a-flag');
    assert.equal(o.unknown, '--not-a-flag');
    assert.match(o.error, /unrecognized argument --not-a-flag/);
  });

  it('--check requires a file', () => {
    assert.match(parse('--check').error, /--check <transcript\.json>/);
    assert.equal(parse('--check', 't.json').check, 't.json');
  });

  it('contradictory git-target flags are refused', () => {
    assert.match(parse('--git-target', '--no-git-target').error, /contradictory/);
  });
});
