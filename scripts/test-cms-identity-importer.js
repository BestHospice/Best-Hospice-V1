#!/usr/bin/env node
/**
 * Tests for scripts/import-cms-hospice-identities.js.
 *
 * File-level tests always run. Database tests run only when TEST_DATABASE_URL
 * is set, and that URL must be a disposable local database - the test truncates
 * and reseeds tables. It refuses anything that looks like production.
 *
 *   node scripts/test-cms-identity-importer.js
 *   TEST_DATABASE_URL=postgresql://user@localhost:5432/bh_importer_test \
 *     node scripts/test-cms-identity-importer.js
 */
const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');

const ROOT = path.join(__dirname, '..');
const IMPORTER = path.join(__dirname, 'import-cms-hospice-identities.js');
const DECISIONS = path.join(ROOT, 'data', 'cms-hospice-identity-decisions.csv');
const TMP = path.join(require('os').tmpdir(), 'cms-importer-tests');

let pass = 0, fail = 0;
const ok = (cond, label, detail) => {
  if (cond) { pass++; console.log(`    ok   ${label}`); }
  else { fail++; console.log(`  FAIL   ${label}${detail ? `\n           ${detail}` : ''}`); }
};
const section = (t) => console.log(`\n--- ${t} ---`);

function run(args, env) {
  return spawnSync(process.execPath, [IMPORTER, ...args], {
    encoding: 'utf8', env: { ...process.env, ...env }
  });
}
function parseCounts(out) {
  const m = out.match(/CREATE (\d+)\s+UNCHANGED (\d+)\s+CONFLICT (\d+)/);
  return m ? { CREATE: +m[1], UNCHANGED: +m[2], CONFLICT: +m[3] } : null;
}
function readDecisions() {
  const t = fs.readFileSync(DECISIONS, 'utf8');
  const out = []; let row = [], cur = '', q = false;
  for (let i = 0; i < t.length; i++) { const c = t[i];
    if (q) { if (c === '"') { if (t[i+1] === '"') { cur += '"'; i++; } else q = false; } else cur += c; }
    else if (c === '"') q = true;
    else if (c === ',') { row.push(cur); cur = ''; }
    else if (c === '\n') { row.push(cur); out.push(row); row = []; cur = ''; }
    else if (c !== '\r') cur += c; }
  if (cur !== '' || row.length) { row.push(cur); out.push(row); }
  const head = out.shift();
  return { head, rows: out.filter(r => r.some(v => v !== '')).map(r => Object.fromEntries(head.map((h,i)=>[h, r[i] ?? '']))) };
}
function writeCsv(file, head, rows) {
  const esc = (v) => `"${String(v ?? '').replace(/"/g, '""')}"`;
  fs.writeFileSync(file, [head.join(','), ...rows.map(r => head.map(h => esc(r[h])).join(','))].join('\n') + '\n');
}

fs.mkdirSync(TMP, { recursive: true });
const { head, rows } = readDecisions();
const approved = rows.filter(r => r.decision === 'approve');

// ============================ A. DRY RUN =====================================
section('A. dry run');
{
  const r = run(['--no-db']);
  ok(r.status === 0, 'default (no --write) exits 0');
  ok(!/WRITE MODE ACTIVE/.test(r.stdout), 'write mode is NOT activated implicitly');
  ok(/DRY RUN/.test(r.stdout), 'output states DRY RUN');
  ok(/no database was contacted and nothing was written/.test(r.stdout), 'reports zero writes');
  const c = parseCounts(r.stdout);
  ok(c && c.CREATE === 13, 'exactly 13 approved rows selected', c && `got CREATE=${c.CREATE}`);
  ok(/approved identities selected: 13/.test(r.stdout), 'selection count reported as 13');
  const rejCcns = rows.filter(r2 => r2.decision === 'reject').map(r2 => r2.externalId);
  const nrIds = rows.filter(r2 => r2.decision === 'needs_research').map(r2 => r2.providerId);
  const planLines = r.stdout.split('\n').filter(l => /cms_hospice/.test(l));
  ok(planLines.length === 13, 'plan prints exactly 13 rows', `got ${planLines.length}`);
  // a rejected pairing must never appear as a planned row for that provider
  const rejPairs = rows.filter(r2 => r2.decision === 'reject').map(r2 => [r2.providerId, r2.externalId]);
  ok(!rejPairs.some(([pid, ccn]) => planLines.some(l => l.includes(pid) && l.includes(ccn))),
     'rejected provider+CCN pairings excluded');
  ok(!nrIds.some(id => planLines.some(l => l.includes(id))), 'needs_research providers excluded');
  ok(rejCcns.length === 3 && nrIds.length === 6, 'fixture sanity: 3 reject, 6 needs_research');
}

// ============================ B. FIELD MAPPING ================================
section('B. field mapping');
{
  const r = run(['--no-db']);
  const lz = approved.filter(a => a.externalId.startsWith('0'));
  ok(lz.length > 0, `fixture has leading-zero CCNs (${lz.length})`);
  ok(lz.every(a => new RegExp(`\\s${a.externalId}\\s`).test(r.stdout)),
     'leading zeros preserved verbatim in the plan');
  ok(!/\s31593\s|\s1562\s/.test(r.stdout), 'no CCN was coerced to a number');
  const a0 = approved.find(a => a.externalId === '031598');
  const iso = new Date(a0.reviewedAt).toISOString();
  ok(r.stdout.includes(iso), 'reviewedAt -> verifiedAt', `expected ${iso}`);
  ok(r.stdout.includes(a0.reviewedBy), 'reviewedBy -> verifiedBy');
  ok(new RegExp(`${a0.externalId}\\s+ccn\\s+${Number(a0.confidenceAtReview).toFixed(2)}`).test(r.stdout),
     'confidenceAtReview -> confidence');
  ok(/cms_hospice/.test(r.stdout) && /\sccn\s/.test(r.stdout), 'source and identifierType carried through');
}

// ============================ C. VALIDATION ===================================
section('C. validation rejects bad approved rows');
{
  const mk = (name, mutate) => {
    const copy = rows.map(r => ({ ...r }));
    mutate(copy);
    const f = path.join(TMP, `${name}.csv`);
    writeCsv(f, head, copy);
    return run(['--no-db', '--file', f]);
  };
  const find = (c, ccn) => c.find(r => r.decision === 'approve' && r.externalId === ccn);

  let r = mk('blank_ccn', c => { find(c, '031598').externalId = ''; });
  ok(r.status !== 0, 'blank approved CCN fails');
  ok(/blank externalId|approve requires an externalId/.test(r.stdout + r.stderr), '  …with a blank-externalId error');

  r = mk('malformed_ccn', c => { find(c, '031598').externalId = '31598'; });
  ok(r.status !== 0, 'malformed CCN fails');
  ok(/not a 6-character CCN|malformed CCN/.test(r.stdout + r.stderr), '  …with a CCN-format error');

  r = mk('dupe_pair', c => { find(c, '031716').externalId = '031598'; });
  ok(r.status !== 0, 'duplicate source+externalId fails');
  ok(/approved for 2 different Providers|duplicate/.test(r.stdout + r.stderr), '  …with a duplicate/unique error');

  r = mk('unknown_provider', c => { find(c, '031598').providerId = '00000000-0000-0000-0000-000000000000'; });
  ok(r.status !== 0, 'unknown provider fails');
  ok(/not a known Provider|unknown provider/.test(r.stdout + r.stderr), '  …with an unknown-provider error');

  const homeId = JSON.parse(fs.readFileSync(path.join(ROOT, 'reports', 'cms-raw', 'bh-providers.json'), 'utf8'))
    .providers.find(p => p.careType !== 'hospice').id;
  r = mk('non_hospice', c => { find(c, '031598').providerId = homeId; });
  ok(r.status !== 0, 'non-hospice provider fails');
  ok(/not hospice/.test(r.stdout + r.stderr), '  …with a careType error');

  r = mk('multi_identity', c => { find(c, '031716').providerId = find(c, '031598').providerId; });
  ok(r.status !== 0, 'two approved identities for one provider fails without --allow-multi');
  ok(/allow-multi/.test(r.stdout + r.stderr), '  …and names the --allow-multi override');
}

// ============================ G. PRODUCTION GUARD =============================
section('G. production guard — every DB-touching mode');
{
  const forbidden = [
    ['production database name', 'postgresql://u:secretpw@some-host:5432/besthospice_db'],
    ['production host id',       'postgresql://u:secretpw@dpg-d5hhmb4hg0os7380cecg-a.oregon-postgres.render.com:5432/x'],
    ['shadow database',          'postgresql://u:secretpw@localhost:5432/besthospice-shadow-2'],
    ['hosted host pattern',      'postgresql://u:secretpw@abc.neon.tech:5432/anything']
  ];

  // A. the DB-inspecting dry run (no flags) must refuse before connecting.
  for (const [label, url] of forbidden) {
    const r = run([], { DATABASE_URL: url });
    const out = r.stdout + r.stderr;
    ok(r.status !== 0, `A. dry run refuses ${label}`);
    ok(/Refusing to open a database connection/.test(out), `  …before opening a connection (${label})`);
    ok(!/Plan \(dry run/.test(out), `  …and never reaches the DB plan (${label})`);
    ok(!out.includes('secretpw') && !out.includes(url), `  …without leaking credentials or the URL (${label})`);
  }

  // B. --write must still refuse the same patterns.
  for (const [label, url] of forbidden) {
    const r = run(['--write'], { DATABASE_URL: url });
    const out = r.stdout + r.stderr;
    ok(r.status !== 0, `B. --write refuses ${label}`);
    ok(/Refusing to write/.test(out), `  …with an explicit refusal (${label})`);
    ok(!out.includes('secretpw') && !out.includes(url), `  …without leaking credentials or the URL (${label})`);
    ok(!/WRITE MODE ACTIVE/.test(out), `  …and never enters write mode (${label})`);
  }

  // C. --no-db is file-only, so a forbidden URL is irrelevant: it never connects.
  for (const [label, url] of forbidden) {
    const r = run(['--no-db'], { DATABASE_URL: url });
    const out = r.stdout + r.stderr;
    ok(r.status === 0, `C. --no-db succeeds despite ${label} in DATABASE_URL`);
    ok(/no database was contacted/.test(out), `  …and states no database was contacted (${label})`);
    ok(!/Refusing to/.test(out), `  …without tripping the guard (${label})`);
  }

  const r = run(['--write'], { DATABASE_URL: '' });
  ok(r.status !== 0 && /DATABASE_URL is not set/.test(r.stdout + r.stderr), '--write refuses an unset DATABASE_URL');
}

// ============================ DATABASE TESTS ==================================
const DB = process.env.TEST_DATABASE_URL;
(async () => {
  if (!DB) {
    console.log('\n--- D/E/F. database tests: SKIPPED (set TEST_DATABASE_URL to a disposable local database) ---');
  } else if (/besthospice_db|dpg-d5hhmb4hg0os7380cecg-a|besthospice-shadow-2|render\.com|neon\.tech|supabase\.co/i.test(DB)) {
    console.log('\n  FAIL   TEST_DATABASE_URL looks like production/shadow — refusing to run database tests');
    fail++;
  } else {
    const { PrismaClient } = require('@prisma/client');
    const prisma = new PrismaClient({ datasources: { db: { url: DB } } });
    const providers = JSON.parse(fs.readFileSync(path.join(ROOT, 'reports', 'cms-raw', 'bh-providers.json'), 'utf8')).providers;
    const byId = new Map(providers.map(p => [p.id, p]));
    const needed = [...new Set(approved.map(a => a.providerId))];

    const seedProviders = async (ids) => {
      await prisma.$executeRawUnsafe('TRUNCATE TABLE "ProviderExternalIdentity", "Provider" CASCADE');
      for (const id of ids) {
        const p = byId.get(id);
        await prisma.provider.create({ data: {
          id: p.id, name: p.name, email: p.email, phone: p.phone, address: p.address,
          city: p.city, state: p.state, zip: p.zip, lat: Number(p.lat), lon: Number(p.lon),
          serviceRadiusKm: Number(p.serviceRadiusKm), careType: p.careType
        }});
      }
    };
    const count = () => prisma.providerExternalIdentity.count();

    try {
      section('D. idempotency against a disposable database');
      await seedProviders(needed);
      ok(await count() === 0, 'identity table starts empty');

      let r = run([], { DATABASE_URL: DB });
      let c = parseCounts(r.stdout);
      ok(r.status === 0 && c.CREATE === 13 && c.UNCHANGED === 0 && c.CONFLICT === 0,
         'dry run against empty DB: 13 CREATE', JSON.stringify(c));
      ok(await count() === 0, 'dry run wrote ZERO rows');

      r = run(['--write'], { DATABASE_URL: DB });
      c = parseCounts(r.stdout);
      ok(r.status === 0 && c.CREATE === 13, 'first --write: 13 CREATE', JSON.stringify(c));
      ok(/WRITE MODE ACTIVE/.test(r.stdout), 'first --write announces write mode conspicuously');
      ok(await count() === 13, 'table holds 13 rows', `got ${await count()}`);

      r = run(['--write'], { DATABASE_URL: DB });
      c = parseCounts(r.stdout);
      ok(r.status === 0 && c.UNCHANGED === 13 && c.CREATE === 0,
         'second --write: 13 UNCHANGED, 0 CREATE', JSON.stringify(c));
      ok(await count() === 13, 'total row count still 13 (no duplicates)', `got ${await count()}`);

      const stored = await prisma.providerExternalIdentity.findMany({ orderBy: { externalId: 'asc' } });
      ok(stored.every(s => /^[0-9A-Z]{6}$/.test(s.externalId)), 'stored CCNs are 6-char strings');
      ok(stored.some(s => s.externalId.startsWith('0')), 'stored CCNs retain leading zeros');
      ok(stored.every(s => s.source === 'cms_hospice' && s.identifierType === 'ccn'), 'source/identifierType stored correctly');
      ok(stored.every(s => s.verifiedAt instanceof Date && s.verifiedBy === 'Crawford Outland'), 'verifiedAt/verifiedBy populated');
      ok(stored.every(s => s.createdAt instanceof Date && s.updatedAt instanceof Date), 'createdAt/updatedAt database-managed');

      section('E. conflict safety');
      await seedProviders(needed);
      const victim = approved.find(a => a.externalId === '031598');
      const wrongProvider = needed.find(id => id !== victim.providerId);
      await prisma.providerExternalIdentity.create({ data: {
        providerId: wrongProvider, source: 'cms_hospice', externalId: '031598', identifierType: 'ccn'
      }});
      ok(await count() === 1, 'seeded one conflicting identity');
      r = run(['--write'], { DATABASE_URL: DB });
      c = parseCounts(r.stdout);
      ok(r.status !== 0, 'importer exits non-zero on conflict');
      ok(c && c.CONFLICT >= 1, 'conflict detected in the plan', JSON.stringify(c));
      ok(/Refusing to write/.test(r.stdout + r.stderr), 'refuses to write');
      ok(/refusing to reassign/.test(r.stdout), 'names the reassignment it refused');
      ok(await count() === 1, 'ZERO new rows written', `got ${await count()}`);

      section('F. transaction safety (no partial import)');
      // Seed every provider except one. That row passes file validation but its
      // INSERT violates the foreign key, so the whole transaction must roll back.
      await seedProviders(needed.slice(0, -1));
      ok(await count() === 0, 'identity table empty before forced-failure run');
      r = run(['--write'], { DATABASE_URL: DB });
      ok(r.status !== 0, 'importer exits non-zero when an insert fails');
      const after = await count();
      ok(after === 0, 'ZERO rows written — transaction rolled back, no partial import', `got ${after}`);
      ok(!/WROTE \d+ row/.test(r.stdout), 'does not claim a successful write');
    } finally {
      await prisma.$disconnect().catch(() => {});
    }
  }

  fs.rmSync(TMP, { recursive: true, force: true });
  console.log(`\n${'='.repeat(60)}`);
  console.log(fail === 0 ? `PASSED — ${pass} assertions` : `FAILED — ${fail} of ${pass + fail} assertions failed`);
  process.exit(fail === 0 ? 0 : 1);
})();
