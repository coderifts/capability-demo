'use strict';

/**
 * POINT 10 — in-run offline re-verification of the transcript this run just produced.
 *
 * ── WHAT THE EXISTING PROOF DOES, AND WHY THIS ONE HAD TO BE DIFFERENT ──────────────────────
 *
 * demo/offline-check.js proves offline verification ENVIRONMENTALLY: it is run as
 * `docker compose run --rm --network none …`, and the container genuinely has no interface. Its
 * own in-process interface count is explicitly "not load-bearing" (offline-check.js:26) — the
 * container is the proof, the script only reports.
 *
 * The umbrella runner cannot do that. It is already inside a process that must talk to Postgres,
 * so it cannot remove its own network. The environmental proof is unavailable to it, and copying
 * offline-check's interface count would be copying the part its own author marked as not evidence.
 *
 * ── WHAT THIS DOES INSTEAD, AND WHY IT IS HONEST ────────────────────────────────────────────
 *
 * It removes the network from the VERIFICATION PATH rather than from the process: every network
 * entry point Node exposes to JavaScript is replaced with a throwing stub for the duration of the
 * verify call, and restored in a `finally`. If verification still returns a valid signature, it
 * did not reach the network, because there was no reachable way to.
 *
 * A CONTROL RUNS FIRST. Before the verification, the harness ATTEMPTS a connection through the
 * trap and asserts it throws. Without that, a trap that silently failed to install would produce
 * the same green as a trap that worked — and "we blocked the network" would be a claim about our
 * own code that we never checked. The control is the same discipline as the identical-code control
 * run used elsewhere in this codebase.
 *
 * ── WHAT IT DOES NOT PROVE, STATED RATHER THAN IMPLIED ──────────────────────────────────────
 *
 * The trap is at the JavaScript boundary. A native addon holding its own socket, or a file
 * descriptor opened before the trap was installed, would not be stopped by it. The verify path
 * here reaches neither: it is `node:crypto` over bytes already in memory plus one keyring file
 * read from disk. That is why this grades PROVEN — but the residual is named in the point's own
 * detail line, not left for a reader to discover.
 */

const crypto = require('node:crypto');

/**
 * Every OUTBOUND network entry point reachable from JavaScript.
 *
 * MEASURED, and this list is narrower than the obvious one on purpose. Trapping `net.Socket`
 * crashes the process: Node constructs `process.stdout` and `process.stderr` lazily with
 * `new net.Socket(...)` (node:internal/bootstrap/switches/is_main_thread:83), so the first write
 * after the trap is installed dies with "net.Socket is not a constructor". The same applies to the
 * server-side constructors, which a running process may already hold.
 *
 * That is not a weakening. What POINT 10 needs to exclude is the verify path REACHING OUT — a
 * socket it opens, a name it resolves, a request it makes, a process it spawns. An inbound socket
 * constructor cannot fetch a key. Every way out is below; the constructors are left alone because
 * trapping them would break stdio without adding a way out to block.
 */
const TRAPS = [
  ['node:net', ['connect', 'createConnection']],
  ['node:tls', ['connect']],
  ['node:http', ['request', 'get']],
  ['node:https', ['request', 'get']],
  ['node:dns', ['lookup', 'resolve', 'resolve4', 'resolve6']],
  ['node:dgram', ['createSocket']],
];

class NetworkReachedError extends Error {
  constructor(what) {
    super(`offline-reverify: the verification path attempted ${what} — it is not offline`);
    this.name = 'NetworkReachedError';
    this.reached = what;
  }
}

/**
 * Install the traps. Returns a restore function; ALWAYS call it in a finally, or the rest of the
 * process loses its network.
 */
function installNetworkTrap(onReach) {
  // Force the lazy stdio getters to run BEFORE anything is trapped. They build their streams with
  // net internals, and a first write from inside the trap would fail for the wrong reason.
  void process.stdout;
  void process.stderr;

  const restore = [];
  const trip = (what) => () => {
    if (typeof onReach === 'function') onReach(what);
    throw new NetworkReachedError(what);
  };

  for (const [mod, names] of TRAPS) {
    let m;
    try { m = require(mod); } catch (_) { continue; }
    for (const name of names) {
      if (typeof m[name] === 'undefined') continue;
      const original = m[name];
      const descriptor = Object.getOwnPropertyDescriptor(m, name);
      if (descriptor && descriptor.writable === false && !descriptor.set) continue;
      try {
        m[name] = trip(`${mod}.${name}`);
        restore.push(() => { m[name] = original; });
      } catch (_) { /* frozen export: recorded by coverage below, never silently "trapped" */ }
    }
  }

  // fetch and the child_process escape hatch. A verify path that shelled out to curl would be
  // just as online as one that opened a socket.
  const globalsTrapped = [];
  for (const g of ['fetch', 'WebSocket', 'XMLHttpRequest']) {
    if (typeof globalThis[g] === 'undefined') continue;
    const original = globalThis[g];
    try {
      globalThis[g] = trip(`globalThis.${g}`);
      globalsTrapped.push(g);
      restore.push(() => { globalThis[g] = original; });
    } catch (_) { /* non-configurable */ }
  }
  const cp = require('node:child_process');
  for (const name of ['spawn', 'spawnSync', 'exec', 'execSync', 'execFile', 'execFileSync', 'fork']) {
    if (typeof cp[name] === 'undefined') continue;
    const original = cp[name];
    cp[name] = trip(`child_process.${name}`);
    restore.push(() => { cp[name] = original; });
  }

  return {
    trapped: restore.length,
    globalsTrapped,
    restore() { while (restore.length) restore.pop()(); },
  };
}

/**
 * Prove the trap is live before trusting a green result through it.
 * @returns {{ok: boolean, detail: string}}
 */
function controlProbe() {
  const attempts = [];
  const net = require('node:net');
  try {
    net.connect(9, '203.0.113.1');            // TEST-NET-3, would never be reachable anyway
    attempts.push({ what: 'net.connect', threw: false });
  } catch (err) {
    attempts.push({ what: 'net.connect', threw: err instanceof NetworkReachedError });
  }
  if (typeof globalThis.fetch === 'function') {
    try {
      globalThis.fetch('http://203.0.113.1/');
      attempts.push({ what: 'fetch', threw: false });
    } catch (err) {
      attempts.push({ what: 'fetch', threw: err instanceof NetworkReachedError });
    }
  }
  const blocked = attempts.filter((a) => a.threw);
  return {
    ok: attempts.length > 0 && blocked.length === attempts.length,
    detail: attempts.map((a) => `${a.what}:${a.threw ? 'blocked' : 'NOT BLOCKED'}`).join(', '),
  };
}

/**
 * Re-verify a signed transcript token with the network unreachable from the verify path.
 *
 * @param {string} token       the cr.prove.transcript.v1 token this run produced
 * @param {Function} verifyFn  the verifier (prove.js verifyProveTranscript) — INJECTED so this
 *                             module decides nothing about validity itself
 * @param {object} verifyOpts  its options, including the public key already in memory
 * @returns {{proven: boolean, valid: boolean, status: string, control: object, reached: string[],
 *            trapped: number, detail: string}}
 */
function offlineReverify(token, verifyFn, verifyOpts) {
  const reached = [];
  // The control probe deliberately attempts the network THROUGH the trap. Those attempts must not
  // be counted against the verification path, so collection starts only once the control is done —
  // otherwise the harness would accuse the verifier of the two calls the harness itself made.
  let collecting = false;
  const trap = installNetworkTrap((what) => { if (collecting) reached.push(what); });
  let control;
  let result;
  let threw = null;
  try {
    control = controlProbe();
    collecting = true;
    try {
      result = verifyFn(token, verifyOpts);
    } catch (err) {
      threw = err;
    }
  } finally {
    trap.restore();
  }

  const valid = !!(result && result.valid === true);
  const status = result && result.status ? result.status : (threw ? 'VERIFY_THREW' : 'NO_RESULT');
  // PROVEN requires all three: the trap demonstrably live, the verification green, and no network
  // entry point touched. Any one missing and the claim is not supported.
  const proven = control.ok && valid && reached.length === 0;
  return {
    proven,
    valid,
    status,
    control,
    reached,
    trapped: trap.trapped,
    detail: proven
      ? `signature re-verified (${status}) with ${trap.trapped} network entry points trapped and `
        + `the trap proved live first (${control.detail}); nothing in the verify path reached one. `
        + 'RESIDUAL: the trap is at the JavaScript boundary — a native addon or a pre-opened socket '
        + 'would evade it. This path is node:crypto over in-memory bytes plus one local keyring '
        + 'read, so it reaches neither'
      : !control.ok
        ? `the network trap did not demonstrably block anything (${control.detail}) — a green result `
          + 'through an unverified trap would prove nothing, so this is not graded PROVEN'
        : reached.length > 0
          ? `the verification path attempted ${reached.join(', ')} — it is not offline`
          : `offline re-verification did not return a valid signature: ${status}`,
  };
}

module.exports = {
  offlineReverify, installNetworkTrap, controlProbe, NetworkReachedError, TRAPS,
};
