#!/usr/bin/env node
/**
 * Import human-approved CMS hospice identities into ProviderExternalIdentity.
 *
 * DRY RUN BY DEFAULT. Running this with no flags performs zero database writes.
 * Writes require an explicit --write and can never be enabled implicitly.
 *
 * The authorization artifact is data/cms-hospice-identity-decisions.csv, the
 * tracked record of human decisions. Only rows with decision === "approve"
 * become identities; reject and needs_research rows are never imported.
 *
 * The importer refuses to reassign an externalId from one Provider to another,
 * refuses to overwrite, and never deletes. If any planned row conflicts with
 * what is already in the database, it performs ZERO writes rather than a
 * partial import - the whole plan is computed before anything is written, and
 * the writes themselves run in one transaction.
 *
 *   node scripts/import-cms-hospice-identities.js                 dry run
 *   node scripts/import-cms-hospice-identities.js --no-db         file-only dry run
 *   node scripts/import-cms-hospice-identities.js --write         write (explicit)
 *   node scripts/import-cms-hospice-identities.js --allow-multi <providerId>
 *
 * The production/shadow guard runs in EVERY mode that opens a connection, not
 * just --write, because a read-only dry run against production is still a
 * production connection. --no-db skips it by never touching a database at all.
 */
const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');

const ROOT = path.join(__dirname, '..');
const DECISIONS = path.join(ROOT, 'data', 'cms-hospice-identity-decisions.csv');
const EXPECTED_SOURCE = 'cms_hospice';
const EXPECTED_IDENTIFIER_TYPE = 'ccn';

// Defence in depth. We only ever test against a disposable local database in
// this phase; this guard exists so a stray environment variable cannot turn a
// routine --write into a production mutation.
const FORBIDDEN_IDENTIFIERS = [
  'besthospice_db',                  // production database name
  'dpg-d5hhmb4hg0os7380cecg-a',      // production host id
  'besthospice-shadow-2'             // shadow database
];
const FORBIDDEN_HOST_PATTERNS = /render\.com|\.rds\.amazonaws\.com|supabase\.co|neon\.tech/i;

const argv = process.argv.slice(2);
const opts = { write: false, noDb: false, allowMulti: new Set(), file: null };
for (let i = 0; i < argv.length; i++) {
  const a = argv[i];
  if (a === '--write') opts.write = true;
  else if (a === '--no-db') opts.noDb = true;
  else if (a === '--allow-multi') opts.allowMulti.add(argv[++i]);
  else if (a === '--file') opts.file = argv[++i];
  else if (a.startsWith('--')) { console.error(`Unknown flag: ${a}`); process.exit(2); }
  else opts.file = a;
}
const file = opts.file || DECISIONS;

// ---- csv ------------------------------------------------------------------
// Hand-rolled so nothing coerces a CCN's leading zeros into a number.
function parseCsv(text) {
  const out = []; let row = []; let cur = ''; let q = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (q) { if (c === '"') { if (text[i + 1] === '"') { cur += '"'; i++; } else q = false; } else cur += c; }
    else if (c === '"') q = true;
    else if (c === ',') { row.push(cur); cur = ''; }
    else if (c === '\n') { row.push(cur); out.push(row); row = []; cur = ''; }
    else if (c !== '\r') cur += c;
  }
  if (cur !== '' || row.length) { row.push(cur); out.push(row); }
  const head = out.shift() || [];
  return out.filter((r) => r.some((v) => v !== ''))
            .map((r) => Object.fromEntries(head.map((h, i) => [h, (r[i] ?? '').trim()])));
}

// Never let a connection string reach the terminal or a log. Prisma's own
// errors embed host and user details, and this is the one path where an
// unredacted URL could surface.
const redact = (t) => String(t == null ? '' : t)
  .replace(/\b[a-z]+:\/\/[^\s"'`)]+/gi, '<redacted-url>')
  .replace(/(password|pgpassword)\s*[=:]\s*\S+/gi, '$1=<redacted>');
// Known production/shadow identifiers are scrubbed from output as well. A bare
// local host:port stays visible because it is what makes a failure debuggable.
const scrub = (t) => FORBIDDEN_IDENTIFIERS.reduce(
  (acc, id) => acc.replace(new RegExp(id.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'gi'), '<redacted-identifier>'),
  redact(t));

const fail = (msg) => { console.error(`\n${redact(msg)}`); process.exit(1); };

// ---- 1. the decision validator is the gate ---------------------------------
function runValidator() {
  const args = [path.join(__dirname, 'validate-cms-identity-decisions.js'), file];
  opts.allowMulti.forEach((p) => args.push('--allow-multi', p));
  const r = spawnSync(process.execPath, args, { encoding: 'utf8' });
  if (r.status !== 0) {
    console.error('Decision file failed validation. Nothing was read or written.\n');
    console.error(scrub((r.stdout || '') + (r.stderr || '')));
    process.exit(1);
  }
  return (r.stdout || '').trim();
}

// ---- 2. build the intended identity rows -----------------------------------
function buildIntended() {
  if (!fs.existsSync(file)) fail(`Decision file not found: ${file}`);
  const rows = parseCsv(fs.readFileSync(file, 'utf8'));
  const approved = rows.filter((r) => r.decision === 'approve');
  const errors = [];

  const providers = new Map(
    JSON.parse(fs.readFileSync(path.join(ROOT, 'reports', 'cms-raw', 'bh-providers.json'), 'utf8'))
      .providers.map((p) => [p.id, p]));

  const seenPair = new Map();
  const perProvider = new Map();
  const intended = approved.map((r, i) => {
    const at = `${r.providerName || r.providerId} / ${r.externalId || '(blank)'}`;
    if (!r.providerId) errors.push(`${at}: missing providerId`);
    if (!r.source) errors.push(`${at}: missing source`);
    if (!r.identifierType) errors.push(`${at}: missing identifierType`);
    if (!r.externalId) errors.push(`${at}: approved row has a blank externalId`);
    else if (!/^[0-9A-Z]{6}$/.test(r.externalId)) errors.push(`${at}: malformed CCN "${r.externalId}"`);
    if (r.source !== EXPECTED_SOURCE) errors.push(`${at}: source must be "${EXPECTED_SOURCE}"`);
    if (r.identifierType !== EXPECTED_IDENTIFIER_TYPE) errors.push(`${at}: identifierType must be "${EXPECTED_IDENTIFIER_TYPE}"`);

    const p = providers.get(r.providerId);
    if (!p) errors.push(`${at}: unknown provider ${r.providerId}`);
    else if (String(p.careType || '').toLowerCase() !== 'hospice') {
      errors.push(`${at}: provider careType is "${p.careType}", not hospice`);
    }

    const key = `${r.source}|${r.externalId}`;
    if (seenPair.has(key)) errors.push(`${at}: duplicate source+externalId also on row ${seenPair.get(key) + 1}`);
    else seenPair.set(key, i);

    if (!perProvider.has(r.providerId)) perProvider.set(r.providerId, new Set());
    perProvider.get(r.providerId).add(r.externalId);

    const conf = r.confidenceAtReview === '' ? null : Number(r.confidenceAtReview);
    if (conf !== null && !(conf >= 0 && conf <= 1)) errors.push(`${at}: confidenceAtReview "${r.confidenceAtReview}" is out of range`);
    const verifiedAt = r.reviewedAt ? new Date(r.reviewedAt) : null;
    if (r.reviewedAt && Number.isNaN(verifiedAt.getTime())) errors.push(`${at}: reviewedAt "${r.reviewedAt}" is not a valid date`);

    return {
      providerId: r.providerId,
      providerName: r.providerName,
      source: r.source,
      externalId: r.externalId,
      identifierType: r.identifierType,
      confidence: conf,
      verifiedAt,
      verifiedBy: r.reviewedBy || null
    };
  });

  perProvider.forEach((ids, pid) => {
    if (ids.size > 1 && !opts.allowMulti.has(pid)) {
      errors.push(`Provider ${pid} has ${ids.size} approved identities (${[...ids].join(', ')}). Pass --allow-multi ${pid} if intended.`);
    }
  });

  if (errors.length) {
    console.error('\nApproved rows failed importer validation:');
    errors.forEach((e) => console.error(`  ERROR  ${e}`));
    fail(`FAILED — ${errors.length} error(s). Zero writes performed.`);
  }
  // Deterministic order so dry-run output diffs cleanly between runs.
  intended.sort((a, b) => a.source.localeCompare(b.source) || a.externalId.localeCompare(b.externalId));
  return intended;
}

// ---- 3. production guard ----------------------------------------------------
// Runs before PrismaClient is ever constructed, in EVERY mode that would open a
// connection - not just --write. A read-only dry run against production is
// still a production connection, and that is the likeliest accident: someone
// runs a "harmless" dry run with production credentials loaded. Use --no-db for
// a file-only run that never reaches this check.
function assertNotProduction(url, action) {
  const verb = `Refusing to ${action}`;
  if (!url) fail(`${verb}: DATABASE_URL is not set.`);
  const hay = String(url).toLowerCase();
  const hit = FORBIDDEN_IDENTIFIERS.find((id) => hay.includes(id.toLowerCase()));
  if (hit) {
    fail(`${verb}: DATABASE_URL matches a forbidden identifier ("${hit}").\n` +
         '  This importer is only for disposable local databases in this phase.\n' +
         '  Use --no-db for a file-only dry run that never touches a database.');
  }
  if (FORBIDDEN_HOST_PATTERNS.test(hay)) {
    fail(`${verb}: DATABASE_URL points at what looks like a hosted/managed database.\n` +
         '  This importer is only for disposable local databases in this phase.\n' +
         '  Use --no-db for a file-only dry run that never touches a database.');
  }
}

// ---- 4. classify against the database ---------------------------------------
async function classify(prisma, intended) {
  const existing = await prisma.providerExternalIdentity.findMany({
    where: { OR: intended.map((r) => ({ source: r.source, externalId: r.externalId })) }
  });
  const byPair = new Map(existing.map((e) => [`${e.source}|${e.externalId}`, e]));

  // Identities the provider already holds for this source, so a second one is
  // surfaced rather than silently added.
  const providerIds = [...new Set(intended.map((r) => r.providerId))];
  const held = await prisma.providerExternalIdentity.findMany({
    where: { providerId: { in: providerIds }, source: EXPECTED_SOURCE }
  });
  const heldByProvider = new Map();
  held.forEach((h) => {
    if (!heldByProvider.has(h.providerId)) heldByProvider.set(h.providerId, []);
    heldByProvider.get(h.providerId).push(h);
  });

  return intended.map((r) => {
    const cur = byPair.get(`${r.source}|${r.externalId}`);
    if (cur) {
      if (cur.providerId !== r.providerId) {
        return { ...r, action: 'CONFLICT',
          why: `${r.source}/${r.externalId} already belongs to provider ${cur.providerId}; refusing to reassign` };
      }
      const drift = [];
      if (cur.identifierType !== r.identifierType) drift.push(`identifierType ${cur.identifierType} != ${r.identifierType}`);
      if (cur.verifiedBy !== r.verifiedBy) drift.push('verifiedBy differs');
      return { ...r, action: 'UNCHANGED', why: drift.length ? `matches on identity; ${drift.join('; ')}` : 'already matches the approved mapping' };
    }
    const others = (heldByProvider.get(r.providerId) || []).filter((h) => h.externalId !== r.externalId);
    if (others.length && !opts.allowMulti.has(r.providerId)) {
      return { ...r, action: 'CONFLICT',
        why: `provider already holds ${r.source}/${others.map((o) => o.externalId).join(', ')}; a Provider record holds one address` };
    }
    return { ...r, action: 'CREATE', why: 'no existing identity for this source+externalId' };
  });
}

// ---- 5. output ---------------------------------------------------------------
function printPlan(plan, mode) {
  const c = plan.reduce((a, r) => { a[r.action] = (a[r.action] || 0) + 1; return a; }, {});
  console.log(`\nPlan (${mode}) — ${plan.length} approved identit${plan.length === 1 ? 'y' : 'ies'}`);
  console.log('-'.repeat(136));
  console.log(`  ${'providerId'.padEnd(38)}${'providerName'.padEnd(26)}${'source'.padEnd(13)}${'extId'.padEnd(8)}${'type'.padEnd(6)}${'conf'.padEnd(6)}${'verifiedAt'.padEnd(26)}${'verifiedBy'.padEnd(18)}action`);
  console.log('-'.repeat(136));
  for (const r of plan) {
    const nm = r.providerName.length > 24 ? r.providerName.slice(0, 23) + '…' : r.providerName;
    console.log(`  ${r.providerId.padEnd(38)}${nm.padEnd(26)}${r.source.padEnd(13)}${r.externalId.padEnd(8)}${String(r.identifierType).padEnd(6)}` +
      `${(r.confidence === null ? '-' : r.confidence.toFixed(2)).padEnd(6)}` +
      `${(r.verifiedAt ? r.verifiedAt.toISOString() : '-').padEnd(26)}${String(r.verifiedBy || '-').padEnd(18)}${r.action}`);
  }
  console.log('-'.repeat(136));
  console.log(`  CREATE ${c.CREATE || 0}   UNCHANGED ${c.UNCHANGED || 0}   CONFLICT ${c.CONFLICT || 0}`);
  if (plan.some((r) => r.unverified)) {
    console.log('  NOTE: the database was not inspected, so CREATE here means "not yet checked",');
    console.log('        not "confirmed absent". Run without --no-db against a database to classify.');
  }
  const bad = plan.filter((r) => r.action === 'CONFLICT');
  if (bad.length) {
    console.log('\n  CONFLICTS:');
    bad.forEach((r) => console.log(`    ${r.source}/${r.externalId} -> ${r.providerId}: ${r.why}`));
  }
  return c;
}

// ---- main ---------------------------------------------------------------------
(async () => {
  console.log(runValidator());
  const intended = buildIntended();
  console.log(`\napproved identities selected: ${intended.length}  (reject and needs_research rows are never imported)`);

  const url = process.env.DATABASE_URL;
  if (opts.noDb || (!url && !opts.write)) {
    if (!url && !opts.noDb) console.log('DATABASE_URL is not set — running a file-only dry run.');
    const plan = intended.map((r) => ({ ...r, action: 'CREATE', unverified: true, why: 'database not inspected' }));
    printPlan(plan, 'file-only dry run, ZERO writes');
    console.log('\nDRY RUN — no database was contacted and nothing was written.');
    return;
  }

  // Any path past here opens a database connection, so the guard applies to the
  // DB-inspecting dry run exactly as it does to --write.
  assertNotProduction(url, opts.write ? 'write' : 'open a database connection');

  const { PrismaClient } = require('@prisma/client');
  const prisma = new PrismaClient();
  try {
    const plan = await classify(prisma, intended);
    const counts = printPlan(plan, opts.write ? 'WRITE MODE' : 'dry run, ZERO writes');
    const conflicts = plan.filter((r) => r.action === 'CONFLICT');

    if (!opts.write) {
      console.log(`\nDRY RUN — nothing was written. Re-run with --write to apply ${counts.CREATE || 0} create(s).`);
      if (conflicts.length) { console.log('Conflicts present: --write would refuse and write nothing.'); process.exitCode = 1; }
      return;
    }

    if (conflicts.length) {
      fail(`Refusing to write: ${conflicts.length} conflict(s) in the plan. ZERO rows written.`);
    }

    const creates = plan.filter((r) => r.action === 'CREATE');
    if (!creates.length) {
      console.log('\nNothing to create — every approved identity already matches. No transaction opened.');
      return;
    }

    console.log('\n' + '*'.repeat(72));
    console.log(`*  WRITE MODE ACTIVE — inserting ${creates.length} ProviderExternalIdentity row(s)`);
    console.log('*'.repeat(72));

    await prisma.$transaction(creates.map((r) => prisma.providerExternalIdentity.create({
      data: {
        providerId: r.providerId,
        source: r.source,
        externalId: r.externalId,
        identifierType: r.identifierType,
        confidence: r.confidence,
        verifiedAt: r.verifiedAt,
        verifiedBy: r.verifiedBy
      }
    })));

    const total = await prisma.providerExternalIdentity.count();
    console.log(`\nWROTE ${creates.length} row(s) in one transaction. ProviderExternalIdentity now holds ${total} row(s).`);
  } finally {
    if (typeof prisma !== 'undefined') await prisma.$disconnect().catch(() => {});
  }
})().catch((e) => {
  // Prisma wraps transaction failures and often leaves `message` empty, which
  // would make a rolled-back import look like a silent crash.
  const detail = [e && e.message, e && e.meta && JSON.stringify(e.meta), e && e.code && `code ${e.code}`]
    .filter(Boolean).join(' | ') || String(e);
  const safe = scrub(detail).split('\n').filter(Boolean).slice(-4).join('\n  ');
  console.error(`\nImport FAILED — transaction rolled back, ZERO rows written.\n  ${safe}`);
  process.exit(1);
});
