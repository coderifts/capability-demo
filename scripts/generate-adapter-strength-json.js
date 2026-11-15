#!/usr/bin/env node
'use strict';

/**
 * Vendor `docs/adapter-strength.v1.json` to the public website (1207 remainder).
 *
 * ── WHY THIS FILE IS THE ONE WORTH PUBLISHING ───────────────────────────────────────────────
 *
 * It is the machine-readable form of the two-axis adapter table: what `consumeOnce` guarantees
 * about SINGLE USE (`strength`), and what the write path guarantees about compare-and-swap
 * (`profile`). A consumer deciding whether to trust an adapter needs both, and needs them joined —
 * which is exactly why the source publishes them in one document rather than two.
 *
 * A prose page can be read; this can be diffed. That is the difference between a claim a reader
 * has to take on trust and one their CI can check.
 *
 * ── THE PATTERN, DELIBERATELY THE SAME AS grant-versions ────────────────────────────────────
 *
 * Header + the source document VERBATIM. The body is not reformatted, re-keyed or summarised: a
 * vendored document that says something slightly different from the one the team follows is worse
 * than no public copy, and "slightly different" is what editing for presentation produces.
 *
 * JSON cannot carry a comment line, so the provenance goes in a `$vendored` key rather than above
 * the document. Same information, same obligation — it names the generator and the source, so a
 * reader who wants the authoritative copy knows where to look.
 *
 * NO TIMESTAMP in the output. `--check` is a full-file byte compare, and a generated timestamp
 * would make every check fail for a reason that has nothing to do with drift.
 *
 *   node scripts/generate-adapter-strength-json.js            write to the website checkout
 *   node scripts/generate-adapter-strength-json.js --check    exit 1 on drift
 *   node scripts/generate-adapter-strength-json.js --out PATH
 */

const fs = require('node:fs');
const path = require('node:path');

const REPO = path.join(__dirname, '..');
const SOURCE = path.join(REPO, 'docs', 'adapter-strength.v1.json');

const USAGE = `usage: node scripts/generate-adapter-strength-json.js [--out <path>] [--check]

  --out <path>   Where to write. Default: $CODERIFTS_WEBSITE_DIR/schemas/adapter-strength.v1.json
                 (or $HOME/coderifts-website/schemas/adapter-strength.v1.json).
  --check        Exit 0 if the target is byte-identical to a fresh generation; 1 on drift.
  Unrecognized arguments exit 1 — never silently ignored.

  Source: docs/adapter-strength.v1.json in THIS repo. The published copy is that document
  verbatim under a provenance key — edit the source, never the published copy.
`;

const PROVENANCE = {
  generator: 'capability-demo scripts/generate-adapter-strength-json.js',
  source: 'capability-demo docs/adapter-strength.v1.json',
  rule: 'Generated. Do not hand-edit: edit the source and re-run the generator. This copy is the '
    + 'source document verbatim plus this key.',
};

/**
 * The published document: the source, verbatim, plus `$vendored`.
 *
 * `$vendored` is inserted FIRST so a reader opening the file sees the provenance before the data —
 * the same position the markdown pattern puts its HTML comment in.
 */
function render(sourceText) {
  const doc = JSON.parse(sourceText);
  return `${JSON.stringify({ $vendored: PROVENANCE, ...doc }, null, 2)}\n`;
}

function defaultOut() {
  const base = process.env.CODERIFTS_WEBSITE_DIR
    || path.join(process.env.HOME || '', 'coderifts-website');
  return path.join(base, 'schemas', 'adapter-strength.v1.json');
}

function parseArgs(argv) {
  const out = { outPath: null, check: false };
  for (let i = 0; i < argv.length; i += 1) {
    const a = argv[i];
    if (a === '--check') { out.check = true; continue; }
    if (a === '--out') {
      out.outPath = argv[i + 1];
      if (!out.outPath) throw new Error('--out needs a path');
      i += 1;
      continue;
    }
    if (a === '--help' || a === '-h') { out.help = true; continue; }
    // Strict: an unrecognised flag is a mistake, and silently ignoring it would run something the
    // caller did not ask for.
    throw new Error(`unrecognized argument: ${a}`);
  }
  return out;
}

function main(argv) {
  let args;
  try {
    args = parseArgs(argv);
  } catch (err) {
    process.stderr.write(`${err.message}\n\n${USAGE}`);
    return 1;
  }
  if (args.help) { process.stdout.write(USAGE); return 0; }

  if (!fs.existsSync(SOURCE)) {
    process.stderr.write(`source document not found at ${SOURCE}\n`);
    return 1;
  }
  let rendered;
  try {
    rendered = render(fs.readFileSync(SOURCE, 'utf8'));
  } catch (err) {
    process.stderr.write(`source is not valid JSON: ${err.message}\n`);
    return 1;
  }

  const target = args.outPath || defaultOut();

  if (args.check) {
    if (!fs.existsSync(target)) {
      process.stderr.write(`adapter-strength: the published copy is missing at ${target}\n`
        + '  regenerate: node scripts/generate-adapter-strength-json.js\n');
      return 1;
    }
    if (fs.readFileSync(target, 'utf8') !== rendered) {
      process.stderr.write('adapter-strength: DRIFT — the published copy and '
        + 'docs/adapter-strength.v1.json disagree.\n'
        + '  regenerate: node scripts/generate-adapter-strength-json.js\n');
      return 1;
    }
    process.stdout.write(`adapter-strength.v1.json up to date (${target})\n`);
    return 0;
  }

  fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.writeFileSync(target, rendered);
  process.stdout.write(`wrote ${target}\n`);
  return 0;
}

module.exports = { render, PROVENANCE, SOURCE, defaultOut };

if (require.main === module) process.exit(main(process.argv.slice(2)));
