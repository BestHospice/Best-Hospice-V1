#!/usr/bin/env node
/**
 * Tests for scripts/import-cms-hospice-data.js.
 *
 * Archive-validation, normalization and guard tests run offline against
 * synthetic fixture archives. Ingestion semantics run against a DISPOSABLE
 * PostgreSQL database with the full active migration chain applied.
 *
 *   TEST_DATABASE_URL=postgresql://user@localhost:5432/bh_ingest_test \
 *     node scripts/test-cms-hospice-ingestion.js
 */
const fs = require('fs');
const os = require('os');
const path = require('path');
const zlib = require('zlib');
const crypto = require('crypto');
const { spawnSync } = require('child_process');

const ROOT = path.join(__dirname, '..');
const SCRIPT = path.join(__dirname, 'import-cms-hospice-data.js');
const REG = JSON.parse(fs.readFileSync(path.join(ROOT, 'data', 'cms-dataset-registry.json'), 'utf8'));
const HOSP = Object.fromEntries(REG.datasets.filter(d => d.source === 'hospice').map(d => [d.logicalKey, d]));
const DB_SOURCE = REG.sources.hospice.externalIdentitySource;

let pass = 0, fail = 0;
const ok = (c, label, detail) => {
  if (c) { pass++; console.log(`    ok   ${label}`); }
  else { fail++; console.log(`  FAIL   ${label}${detail ? `\n           ${detail}` : ''}`); }
};
const section = t => console.log(`\n--- ${t} ---`);
const sha256 = b => crypto.createHash('sha256').update(b).digest('hex');
const TMP = fs.mkdtempSync(path.join(os.tmpdir(), 'cms-ingest-tests-'));

// ---- fixture archive builder ----------------------------------------------
const csv = (head, rows) => [head.join(','), ...rows.map(r => head.map(h => `"${String(r[h] ?? '').replace(/"/g,'""')}"`).join(','))].join('\n') + '\n';

function buildArchive({ key, facilities, zips, layout = 'v2', mutate = null, capturedAt = '2026-08-27T20:21:08.919Z' }) {
  const root = fs.mkdtempSync(path.join(TMP, 'arc-'));
  const dir = layout === 'v2' ? path.join(root, 'hospice', key) : path.join(root, key);
  fs.mkdirSync(dir, { recursive: true });
  const files = {};
  const write = (logicalKey, head, rows) => {
    const raw = Buffer.from(csv(head, rows), 'utf8');
    fs.writeFileSync(path.join(dir, `${logicalKey}.csv.gz`), zlib.gzipSync(raw));
    files[logicalKey] = { source: 'hospice', logicalKey, datasetId: HOSP[logicalKey].datasetId,
      title: HOSP[logicalKey].expectedTitle, modified: key,
      sourceUrl: 'https://data.cms.gov/x.csv', rawBytes: raw.length,
      gzipBytes: 0, sha256Raw: sha256(raw), rowCount: rows.length,
      headers: head, archivedAt: capturedAt };
  };
  write('general', HOSP.general.expectedHeaders, facilities);
  write('zip', HOSP.zip.expectedHeaders, zips);
  for (const k of ['provider','cahps_provider','state','national']) write(k, HOSP[k].expectedHeaders, []);
  const mf = { releaseKey: key, source: 'hospice', schemaVersion: 2, capturedAt,
    catalog: 'https://data.cms.gov/x', datasetCount: Object.keys(files).length,
    expectedDatasetCount: 6, status: 'complete', skipped: [], rowCountDeltas: [], note: 'fixture', files };
  if (mutate) mutate(mf, dir);
  fs.writeFileSync(path.join(dir, 'manifest.json'), JSON.stringify(mf, null, 2));
  return { root, dir, key };
}

const G = HOSP.general.expectedHeaders;
const Z = HOSP.zip.expectedHeaders;
const facility = (ccn, over = {}) => ({
  [G[0]]: ccn, 'Facility Name': `HOSPICE ${ccn}`, 'Address Line 1': '1 MAIN ST', 'Address Line 2': '-',
  'City/Town': 'PHOENIX', 'State': 'AZ', 'ZIP Code': '85016', 'County/Parish': 'MARICOPA',
  'Telephone Number': '(602) 555-0100', 'CMS Region': '9', 'Ownership Type': 'For-Profit',
  'Certification Date': '08/05/2011', ...over });
const zrow = (ccn, zip) => ({ 'State': 'AZ', [Z[1]]: ccn, 'ZIP Code': zip });

function run(args, env = {}) {
  return spawnSync(process.execPath, [SCRIPT, ...args], { encoding: 'utf8', env: { ...process.env, ...env } });
}
const runArc = (arc, args, env = {}) => run(args, { CMS_ARCHIVE_DIR: arc.root, ...env });

// ============================ ARCHIVE VALIDATION ============================
section('archive validation');
{
  const good = buildArchive({ key: '2026-08-19', facilities: [facility('031598')], zips: [zrow('031598','85016')] });
  let r = runArc(good, ['--release','2026-08-19','--no-db']);
  ok(r.status === 0, '1. complete valid archive accepted', r.stderr.slice(0,200));
  ok(/no database was contacted/.test(r.stdout), '   …and --no-db contacts no database');
  const shown = (r.stdout.match(/manifest sha256   : (\S+)/) || [])[1];
  ok(/^[a-f0-9]{64}$/.test(shown || ''), '10. manifest hash matches ^[a-f0-9]{64}$ (real SHA-256, lowercase hex)', `got ${shown} len ${(shown||'').length}`);
  ok((shown || '').length === 64, '10a. manifest hash is exactly 64 characters');
  ok(shown === sha256(fs.readFileSync(path.join(good.dir,'manifest.json'))),
     '10b. manifest hash is over the EXACT stored bytes (node crypto)');
  {
    const sys = spawnSync('shasum', ['-a','256', path.join(good.dir,'manifest.json')], { encoding:'utf8' });
    const sysHash = (sys.stdout || '').trim().split(/\s+/)[0];
    ok(sysHash === shown, '10d. independently verified with the system shasum -a 256', `system=${sysHash}`);
    const reserialised = sha256(Buffer.from(JSON.stringify(JSON.parse(fs.readFileSync(path.join(good.dir,'manifest.json'),'utf8')))));
    ok(reserialised !== shown, '10e. hash is of RAW bytes, not re-serialised JSON');
  }

  // --- Archive V2 is required; legacy V1 is refused, never reconstructed ---
  const legacy = buildArchive({ key:'2026-08-19', facilities:[facility('031598')], zips:[zrow('031598','85016')],
    mutate:(m)=>{ delete m.schemaVersion; delete m.source; delete m.status; delete m.datasetCount;
                  for (const f of Object.values(m.files)) { delete f.headers; delete f.rowCount; } } });
  r = runArc(legacy, ['--release','2026-08-19','--no-db']);
  ok(r.status !== 0, 'V1. a legacy pre-V2 manifest is REFUSED');
  ok(/Archive V2 manifest required for CMS ingestion/.test(r.stdout+r.stderr), '   …with the explicit V2-required message');
  for (const fact of ['schemaVersion','source','status','datasetCount','files.general.headers'])
    ok(new RegExp(fact.replace(/\./g,'\\.')).test(r.stdout+r.stderr), `   …naming the missing fact "${fact}"`);
  ok(!/DERIVED|derive/i.test(r.stdout+r.stderr), '   …and never claims to derive anything');
  {
    const src = fs.readFileSync(SCRIPT,'utf8');
    ok(!/\bDERIVED\b/.test(src), 'V2. no derivation language remains in the importer source');
    ok(!/note\.push\(/.test(src), '    …and no derivation NOTEs are emitted');
    ok(/Archive V2 manifest required/.test(src), '    …the V2 requirement is stated in code');
  }

  const v1DatasetCount = buildArchive({ key:'2026-08-19', facilities:[facility('031598')], zips:[zrow('031598','85016')],
    mutate:(m)=>{ delete m.datasetCount; } });
  r = runArc(v1DatasetCount, ['--release','2026-08-19','--no-db']);
  ok(r.status !== 0 && /datasetCount/.test(r.stdout+r.stderr), 'V3. a manifest missing only datasetCount is refused, not inferred');

  const noHeaders = buildArchive({ key:'2026-08-19', facilities:[facility('031598')], zips:[zrow('031598','85016')],
    mutate:(m)=>{ delete m.files.general.headers; } });
  r = runArc(noHeaders, ['--release','2026-08-19','--no-db']);
  ok(r.status !== 0 && /files\.general\.headers/.test(r.stdout+r.stderr), 'V4. a manifest missing recorded headers is refused');

  const noMf = buildArchive({ key: '2026-08-19', facilities: [facility('031598')], zips: [] });
  fs.unlinkSync(path.join(noMf.dir, 'manifest.json'));
  r = runArc(noMf, ['--release','2026-08-19','--no-db']);
  ok(r.status !== 0, '2. missing manifest rejected');

  const badJson = buildArchive({ key: '2026-08-19', facilities: [facility('031598')], zips: [] });
  fs.writeFileSync(path.join(badJson.dir,'manifest.json'), '{ not json');
  r = runArc(badJson, ['--release','2026-08-19','--no-db']);
  ok(r.status !== 0 && /not valid JSON/.test(r.stderr+r.stdout), '3. malformed manifest rejected');

  const wrongSrc = buildArchive({ key:'2026-08-19', facilities:[facility('031598')], zips:[], mutate:(m)=>{m.source='home-health';} });
  r = runArc(wrongSrc, ['--release','2026-08-19','--no-db']);
  ok(r.status !== 0 && /source is "home-health"/.test(r.stdout+r.stderr), '4. wrong source rejected');

  const incomplete = buildArchive({ key:'2026-08-19', facilities:[facility('031598')], zips:[], mutate:(m)=>{m.status='incomplete';} });
  r = runArc(incomplete, ['--release','2026-08-19','--no-db']);
  ok(r.status !== 0 && /status is "incomplete"/.test(r.stdout+r.stderr), '5. incomplete manifest rejected');

  const noZip = buildArchive({ key:'2026-08-19', facilities:[facility('031598')], zips:[], mutate:(m,d)=>{ delete m.files.zip; fs.unlinkSync(path.join(d,'zip.csv.gz')); } });
  r = runArc(noZip, ['--release','2026-08-19','--no-db']);
  ok(r.status !== 0 && /required dataset "zip"/.test(r.stdout+r.stderr), '6. missing required dataset rejected');

  const badGz = buildArchive({ key:'2026-08-19', facilities:[facility('031598')], zips:[] });
  fs.writeFileSync(path.join(badGz.dir,'zip.csv.gz'), Buffer.from('not gzip at all'));
  r = runArc(badGz, ['--release','2026-08-19','--no-db']);
  ok(r.status !== 0 && /could not be decompressed/.test(r.stdout+r.stderr), '7. corrupted gzip rejected');

  const badSum = buildArchive({ key:'2026-08-19', facilities:[facility('031598')], zips:[], mutate:(m)=>{ m.files.general.sha256Raw='0'.repeat(64); } });
  r = runArc(badSum, ['--release','2026-08-19','--no-db']);
  ok(r.status !== 0 && /checksum mismatch/.test(r.stdout+r.stderr), '8. raw CSV checksum mismatch rejected');

  const wrongKey = buildArchive({ key:'2026-08-19', facilities:[facility('031598')], zips:[], mutate:(m)=>{ m.releaseKey='2026-01-01'; } });
  r = runArc(wrongKey, ['--release','2026-08-19','--no-db']);
  ok(r.status !== 0 && /does not match archive directory/.test(r.stdout+r.stderr), '9. wrong release key rejected',
     `exit=${r.status} err=${JSON.stringify((r.stderr||'').slice(0,200))}`);

  const badHdr = buildArchive({ key:'2026-08-19', facilities:[facility('031598')], zips:[] });
  { const raw = Buffer.from(csv(G.map((h,i)=>i===1?'Renamed':h), [facility('031598')]),'utf8');
    fs.writeFileSync(path.join(badHdr.dir,'general.csv.gz'), zlib.gzipSync(raw));
    const m = JSON.parse(fs.readFileSync(path.join(badHdr.dir,'manifest.json'),'utf8'));
    m.files.general.sha256Raw = sha256(raw);
    fs.writeFileSync(path.join(badHdr.dir,'manifest.json'), JSON.stringify(m,null,2)); }
  r = runArc(badHdr, ['--release','2026-08-19','--no-db']);
  ok(r.status !== 0 && /header does not match/.test(r.stdout+r.stderr), '10c. header drift rejected');
  ok(/recorded in the manifest/.test(r.stdout+r.stderr), '    …by the manifest-recorded headers (the stricter check, which fires first)');
}

// ============================ IDENTIFIERS / NORMALIZATION ===================
section('identifiers and normalization');
{
  const arc = buildArchive({ key:'2026-08-19', zips:[zrow('001500','01234'), zrow('A01500','85016')],
    facilities:[
      facility('001500', { 'County/Parish':'-', 'Telephone Number':'-', 'Ownership Type':'', 'ZIP Code':'01234' }),
      facility('A01500'),
      facility('BAD',   { 'Facility Name':'X' }),
      facility('031600',{ 'Certification Date':'not-a-date' }),
      facility('031601',{ 'State':'' })
    ] });
  const r = runArc(arc, ['--release','2026-08-19','--no-db','--json', path.join(TMP,'norm.json')]);
  ok(r.status === 0, 'archive with some invalid rows still validates (rows are skipped, not fatal)');
  const rep = JSON.parse(fs.readFileSync(path.join(TMP,'norm.json'),'utf8'));
  ok(rep.facilities.valid === 2, '16. malformed required rows are skipped', JSON.stringify(rep.facilities));
  ok(rep.facilities.invalid === 3, '   …and counted (malformed CCN, bad date, missing state)');
  const why = rep.facilities.invalidSamples.map(s=>s.why).join(' | ');
  ok(/malformed CCN "BAD"/.test(why), '   …reporting the malformed CCN');
  ok(/unparseable Certification Date/.test(why), '   …reporting the unparseable date');
  ok(/State/.test(why), '   …reporting the missing state');
}

// ============================ CLI CONTRACT ==================================
section('cli contract');
{
  const arc = buildArchive({ key:'2026-08-19', facilities:[facility('031598')], zips:[zrow('031598','85016')] });
  const prod = 'postgresql://u:secretpw@h:5432/besthospice_db';
  const bad = [
    [['--release'],                          '--release with no value'],
    [['--release','--no-db'],                '--release swallowing the next flag'],
    [['--json'],                             '--json with no value'],
    [['--json','--write'],                   '--json swallowing the next flag'],
    [['--nope'],                             'an unknown flag'],
    [['--release','2026-08-19','--no-db','--write'], '--no-db together with --write'],
  ];
  for (const [args, label] of bad) {
    // A production URL is set deliberately: a usage error must be decided before
    // anything looks at a database at all.
    const r = runArc(arc, args, { DATABASE_URL: prod });
    const out = r.stdout + r.stderr;
    ok(r.status === 2, `46. ${label} exits 2`, `status ${r.status}`);
    ok(/^Usage error:/m.test(out), `    …reported as a usage error (${label})`);
    ok(!/ARCHIVE\n|RELEASE|PrismaClient|ECONNREFUSED/.test(out),
       `    …and no archive is read and no database client is built (${label})`);
    ok(!out.includes('secretpw'), `    …no credential leaked (${label})`);
  }
  const r = runArc(arc, ['--release','2026-08-19','--json', path.join(TMP,'cli.json'), '--no-db']);
  ok(r.status === 0, '47. a well-formed value-taking flag pair still works');
  const rep = JSON.parse(fs.readFileSync(path.join(TMP,'cli.json'),'utf8'));
  ok(Array.isArray(rep.serviceAreas.orphanCcns), '   …and the JSON report carries the orphan CCN list');
  // The doc claims the orphan CCN list is JSON-only; prove the console omits it.
  const withOrphans = buildArchive({ key:'2026-08-19', facilities:[facility('031598')],
    zips:[zrow('031598','85016'), zrow('777777','85016')] });
  const r3 = runArc(withOrphans, ['--release','2026-08-19','--no-db']);
  ok(/distinct orphan CCNs/.test(r3.stdout), '48. console reports the orphan CCN COUNT');
  ok(!/\b777777\b/.test(r3.stdout), '   …but never lists the orphan CCNs themselves without --json');
}

// ============================ CALENDAR DATES ================================
section('calendar dates');
{
  const dates = [['02/29/2024', true, '2024-02-29'], ['02/29/2023', false], ['02/30/2024', false],
                 ['04/31/2023', false], ['12/31/2024', true, '2024-12-31'], ['13/01/2024', false],
                 ['00/10/2024', false], ['01/00/2024', false], ['8/5/2011', false]];
  // Run under two very different offsets. A date rule that depends on the host
  // timezone would disagree between them.
  for (const TZ of ['UTC', 'Pacific/Kiritimati']) {
    const arc = buildArchive({ key:'2026-08-19',
      facilities: dates.map(([d], i) => facility(String(31000 + i).padStart(6,'0'), { 'Certification Date': d })),
      zips: dates.map(([], i) => zrow(String(31000 + i).padStart(6,'0'), '85016')) });
    const out = path.join(TMP, `dates-${TZ.replace(/\W/g,'')}.json`);
    const r = runArc(arc, ['--release','2026-08-19','--no-db','--json', out], { TZ });
    ok(r.status === 0, `49. calendar-date fixture validates under TZ=${TZ}`, r.stderr.slice(0,200));
    const rep = JSON.parse(fs.readFileSync(out,'utf8'));
    const wantValid = dates.filter(d => d[1]).length;
    ok(rep.facilities.valid === wantValid,
       `   …${wantValid} real calendar dates accepted under TZ=${TZ}`, JSON.stringify(rep.facilities));
    ok(rep.facilities.invalid === dates.length - wantValid,
       `   …${dates.length - wantValid} impossible/malformed dates rejected under TZ=${TZ}`);
    const why = rep.facilities.invalidSamples.map(x => x.why).join(' | ');
    for (const [d, valid] of dates) if (!valid) {
      ok(new RegExp(d.replace(/\//g,'\\/')).test(why), `   …"${d}" named as unparseable under TZ=${TZ}`);
    }
  }
}

// ============================ PRODUCTION GUARD ==============================
section('production safety');
{
  const arc = buildArchive({ key:'2026-08-19', facilities:[facility('031598')], zips:[zrow('031598','85016')] });
  const urls = [['production db name','postgresql://u:secretpw@h:5432/besthospice_db'],
                ['production host id','postgresql://u:secretpw@dpg-d5hhmb4hg0os7380cecg-a.x:5432/y'],
                ['shadow db','postgresql://u:secretpw@localhost:5432/besthospice-shadow-2'],
                ['hosted host','postgresql://u:secretpw@a.neon.tech:5432/z'],
                // Representations a plain substring test on the raw string missed.
                ['percent-encoded db name','postgresql://u:secretpw@localhost:5432/besthospice%5Fdb'],
                ['mixed case host id','postgresql://u:secretpw@DPG-D5HHMB4HG0OS7380CECG-A.x:5432/y'],
                ['identifier in query params','postgresql://u:secretpw@localhost:5432/x?options=besthospice_db'],
                ['whitespace padded','  postgresql://u:secretpw@localhost:5432/besthospice_db  '],
                ['not a parseable url','definitely not a url besthospice-shadow-2 secretpw'],
                ['fully encoded url','postgres%3A%2F%2Fu%3Asecretpw%40h%2Fbesthospice_db']];
  for (const [label,url] of urls) {
    for (const mode of [[],['--write']]) {
      const r = runArc(arc, ['--release','2026-08-19',...mode], { DATABASE_URL: url });
      const out = r.stdout + r.stderr;
      ok(r.status !== 0, `41/42. ${label} refused in ${mode.length?'--write':'dry-run'} mode`);
      ok(!out.includes('secretpw') && !out.includes(url), `      …no credential leaked (${label})`);
    }
  }
  const r2 = runArc(arc, ['--release','2026-08-19','--no-db'], { DATABASE_URL: urls[0][1] });
  ok(r2.status === 0 && /no database was contacted/.test(r2.stdout),
     '44. --no-db never touches a database even with a production URL set');
  const src = fs.readFileSync(SCRIPT,'utf8');
  ok(/guardCandidates/.test(src) && /decodeURIComponent/.test(src) && /new URL\(/.test(src),
     '   …the guard inspects raw, decoded and parsed forms of the URL');
  ok(!/force.?prod|allow.?prod|skip.?guard|--unsafe/i.test(src), '45. no undocumented production bypass exists');
  ok(!/assertNotProduction\([^)]*\)\s*;?\s*\/\/\s*skip/i.test(src), '   …guard is not conditionally disabled');
}

// ============================ PRODUCTION AUTHORIZATION ======================
// The token is derived from public, immutable release facts. It is not a secret
// and not authentication - it exists so an accidental, stale or copy-pasted
// production run is impossible. Every assertion below therefore recomputes the
// expected value independently of the importer.
const AUTH_OP = 'cms-hospice-production-ingest';
const authToken = (source, releaseKey, manifestSha256) =>
  sha256(Buffer.from(`${AUTH_OP}\nsource=${source}\nreleaseKey=${releaseKey}\nmanifestSha256=${manifestSha256}\n`, 'utf8'));
const manifestHashOf = (arc) => sha256(fs.readFileSync(path.join(arc.dir, 'manifest.json')));
const tokenFromHelper = (arc, key, env = {}) => {
  const r = runArc(arc, ['--release', key, '--print-production-authorization'], env);
  const m = (r.stdout + r.stderr).match(/^\s*token\s*:\s*([0-9a-f]{64})\s*$/m);
  return { r, token: m && m[1] };
};

section('production authorization — token derivation');
{
  const arc = buildArchive({ key:'2026-08-19', facilities:[facility('031598')], zips:[zrow('031598','85016')] });
  const prodUrl = 'postgresql://u:secretpw@dpg-d5hhmb4hg0os7380cecg-a.x:5432/besthospice_db';

  // The helper must never touch a database, even with a production URL present.
  const { r, token } = tokenFromHelper(arc, '2026-08-19', { DATABASE_URL: prodUrl });
  const out = r.stdout + r.stderr;
  ok(r.status === 0, '54. --print-production-authorization succeeds on a valid V2 archive', r.stderr.slice(0,200));
  ok(/^[0-9a-f]{64}$/.test(token || ''), '   …prints exactly 64 lowercase hex characters', String(token));
  ok(/no database was contacted/i.test(out), '   …and states no database was contacted');
  ok(!/PrismaClient|ECONNREFUSED|does not exist on the database server/.test(out),
     '55. helper constructs no Prisma client even with a production DATABASE_URL set');
  ok(!out.includes('secretpw') && !out.includes(prodUrl), '   …and leaks no credential');

  const expected = authToken(DB_SOURCE, '2026-08-19', manifestHashOf(arc));
  ok(token === expected, '56. token equals an INDEPENDENTLY recomputed sha256 of the canonical string', `${token} vs ${expected}`);
  const again = tokenFromHelper(arc, '2026-08-19').token;
  ok(again === token, '   …and is deterministic across runs');

  // Sensitivity: changing any single fact must change the token.
  const arcOther = buildArchive({ key:'2026-05-01', facilities:[facility('031598')], zips:[zrow('031598','85016')] });
  const tOther = tokenFromHelper(arcOther, '2026-05-01').token;
  ok(tOther && tOther !== token, '57. token is release-sensitive');
  const arcTamper = buildArchive({ key:'2026-08-19', facilities:[facility('031598',{'Facility Name':'OTHER'})], zips:[zrow('031598','85016')] });
  const tTamper = tokenFromHelper(arcTamper, '2026-08-19').token;
  ok(tTamper && tTamper !== token, '   …manifest-sensitive');
  ok(authToken('cms_home_health', '2026-08-19', manifestHashOf(arc)) !== token, '   …source-sensitive');
  ok(authToken(DB_SOURCE, '2026-08-19', manifestHashOf(arc)) === token, '   …and stable for the same facts');

  // A token can only be produced for an archive that already passes validation.
  const v1 = buildArchive({ key:'2026-08-19', facilities:[facility('031598')], zips:[zrow('031598','85016')],
    mutate: (mf) => { delete mf.schemaVersion; delete mf.status; } });
  const rv1 = runArc(v1, ['--release','2026-08-19','--print-production-authorization']);
  ok(rv1.status !== 0 && !/token\s*:/.test(rv1.stdout),
     '58. helper refuses to derive a token for a non-V2 archive');
}

section('production authorization — target classification');
{
  const arc = buildArchive({ key:'2026-08-19', facilities:[facility('031598')], zips:[zrow('031598','85016')] });
  const good = authToken(DB_SOURCE, '2026-08-19', manifestHashOf(arc));
  const wrongRelease  = authToken(DB_SOURCE, '2026-05-01', manifestHashOf(arc));
  const wrongManifest = authToken(DB_SOURCE, '2026-08-19', 'f'.repeat(64));
  const wrongSource   = authToken('cms_home_health', '2026-08-19', manifestHashOf(arc));

  const P  = 'postgresql://u:secretpw@localhost:5432/besthospice_db';
  const P2 = 'postgresql://u:secretpw@dpg-d5hhmb4hg0os7380cecg-a.oregon-postgres.render.com:5432/x';
  const PE = 'postgresql://u:secretpw@localhost:5432/besthospice%5Fdb';
  const SH = 'postgresql://u:secretpw@localhost:5432/besthospice-shadow-2';
  const SH2= 'postgresql://u:secretpw@besthospice-shadow-2.oregon-postgres.render.com:5432/x';
  const UNK= 'postgresql://u:secretpw@a.neon.tech:5432/z';

  const attempt = (url, extra) => {
    const r = runArc(arc, ['--release','2026-08-19', ...extra], { DATABASE_URL: url });
    return { r, out: r.stdout + r.stderr };
  };
  const refused = (url, extra, label, needle) => {
    const { r, out } = attempt(url, extra);
    ok(r.status !== 0, label, `status ${r.status}`);
    if (needle) ok(needle.test(out), `   …${needle.source.slice(0,44)}`);
    ok(!/PRODUCTION TARGET AUTHORIZED/.test(out), '   …never prints the authorization banner');
    ok(!out.includes('secretpw') && !out.includes(url), '   …no credential leaked');
    ok(!out.includes(good), '   …and never discloses the expected token');
  };

  refused(P,  [],                                     '59. production + NO authorization refused', /points at the production database/);
  refused(P,  ['--write'],                            '60. production + --write + no authorization refused', /points at the production database/);
  refused(P,  ['--production-authorization', wrongRelease],  '61. production + wrong-RELEASE token refused', /does not match this release/);
  refused(P,  ['--production-authorization', wrongManifest], '62. production + wrong-MANIFEST token refused', /does not match this release/);
  refused(P,  ['--production-authorization', wrongSource],   '63. production + cms_home_health token refused', /does not match this release/);
  refused(P2, [],                                     '64. production HOST id + no authorization refused', /points at the production database/);
  refused(PE, [],                                     '65. percent-encoded production + no authorization refused', /points at the production database/);

  // Shadow and unrecognised hosted databases have NO authorization path at all.
  refused(SH,  ['--production-authorization', good], '66. shadow + CORRECT production token STILL refused', /shadow database/);
  refused(SH2, ['--production-authorization', good], '   …shadow by host name too', /shadow database/);
  refused(UNK, ['--production-authorization', good], '67. unrecognised hosted db + correct token STILL refused', /unrecognised hosted/);
  {
    const { out } = attempt(SH, ['--production-authorization', good]);
    ok(/no\s+\n?\s*authorization that permits it|there is no/i.test(out),
       '   …and says plainly that no authorization permits the shadow database');
  }

  // Non-production is completely unaffected: no token required, same old failure.
  const { r: rl } = attempt('postgresql://u:secretpw@localhost:5432/some_disposable_db', []);
  ok(!/production|authorization/i.test((rl.stdout+rl.stderr).split('\n')[1] || ''),
     '68. a non-production URL still needs no authorization at all');

  // Shape errors are decided before anything reads an archive or a database.
  for (const [args, label] of [
    [['--production-authorization'],                        'missing value'],
    [['--production-authorization','--write'],              'next flag swallowed'],
    [['--production-authorization','NOTHEX'],               'non-hex token'],
    [['--production-authorization', good.slice(0,63)],      '63-character token'],
    [['--production-authorization', good.toUpperCase()],    'uppercase hex token'],
    [['--no-db','--production-authorization', good],        '--no-db with a token'],
    [['--print-production-authorization','--write'],        'helper with --write'],
    [['--print-production-authorization','--production-authorization', good], 'helper consuming a token'],
  ]) {
    const r = runArc(arc, ['--release','2026-08-19', ...args], { DATABASE_URL: P });
    ok(r.status === 2, `69. usage error (exit 2): ${label}`, `status ${r.status}`);
    ok(/^Usage error:/m.test(r.stdout + r.stderr), `    …reported as a usage error (${label})`);
  }

  // No generic bypass may exist.
  const src = fs.readFileSync(SCRIPT, 'utf8');
  ok(!/--force-prod|--allow-prod|--skip-prod-guard|--unsafe|--override\b/.test(src),
     '70. no generic production bypass flag exists');
  ok(/SHADOW_IDENTIFIERS/.test(src) && /HOSTED_HOST_PATTERNS/.test(src),
     '   …shadow and unrecognised hosts are classified separately from production');
  ok(!/SHADOW[\s\S]{0,400}productionAuthorization/.test(src.slice(src.indexOf('function assertTargetAllowed'))),
     '   …the shadow branch has no authorization path');
}

section('production authorization — realistic connection-string shapes');
{
  const arc = buildArchive({ key:'2026-08-19', facilities:[facility('031598')], zips:[zrow('031598','85016')] });
  const good = authToken(DB_SOURCE, '2026-08-19', manifestHashOf(arc));

  // Realistic URL shapes built from Render metadata. Passwords are FAKE and every
  // case below is refused by the guard before a Prisma client is constructed, so
  // no connection is ever attempted.
  const FAKE = 'FAKEFAKEFAKE';
  const PROD_HOST = 'dpg-d5hhmb4hg0os7380cecg-a';
  const SHAD_HOST = 'dpg-d60g7h0gjchc73f306j0-a';
  const DB1_HOST  = 'dpg-d5mll40gjchc738qg230-a';
  const ext = (h) => `${h}.virginia-postgres.render.com`;

  // `probeToken` marks the shapes that may be re-run WITH a correct token. Every
  // refused class is safe to probe because the guard fires before a Prisma client
  // exists, so no connection is possible. The one authorizable class is probed
  // ONLY via the internal host form, which does not resolve outside Render - the
  // external production hostname is real and must never be dialled from a test.
  const shapes = [
    ['production external',    `postgresql://besthospice_db_user:${FAKE}@${ext(PROD_HOST)}/besthospice_db`,            /points at the production database/, false],
    ['production internal',    `postgresql://besthospice_db_user:${FAKE}@${PROD_HOST}/besthospice_db`,                  /points at the production database/, true],
    ['shadow external',        `postgresql://besthospice_shadow_2_user:${FAKE}@${ext(SHAD_HOST)}/besthospice_shadow_2`, /points at the shadow database/, true],
    ['shadow internal',        `postgresql://besthospice_shadow_2_user:${FAKE}@${SHAD_HOST}/besthospice_shadow_2`,      /points at the shadow database/, true],
    ['shadow display name',    `postgresql://u:${FAKE}@localhost:5432/besthospice-shadow-2`,                            /points at the shadow database/, true],
    ['unknown Render internal',`postgresql://fake:fake@dpg-aaaaaaaaaaaaaaaaaaaa-a/example`,                             /unrecognised hosted/, true],
    ['db1 external',           `postgresql://besthospice_db1_user:${FAKE}@${ext(DB1_HOST)}/besthospice_db1`,            /unrecognised hosted/, true],
    ['db1 internal',           `postgresql://besthospice_db1_user:${FAKE}@${DB1_HOST}/besthospice_db1`,                 /unrecognised hosted/, true],
    ['percent-encoded shadow', `postgresql://u:${FAKE}@localhost:5432/besthospice%5Fshadow%5F2`,                        /points at the shadow database/, true],
  ];
  for (const [label, url, expected, probeToken] of shapes) {
    // Without a token first…
    let r = runArc(arc, ['--release','2026-08-19','--write'], { DATABASE_URL: url });
    let out = r.stdout + r.stderr;
    ok(r.status !== 0, `71. ${label} refused with no authorization`, `status ${r.status}`);
    ok(expected.test(out), `    …classified correctly (${expected.source.slice(0,34)})`);
    ok(!out.includes(FAKE) && !out.includes(url), '    …no credential leaked');

    if (!probeToken) continue;

    // …and with a CORRECT production token. Only the real production database may
    // ever be authorized; shadow, db1 and unknown Render hosts must stay refused.
    r = runArc(arc, ['--release','2026-08-19','--production-authorization', good, '--write'], { DATABASE_URL: url });
    out = r.stdout + r.stderr;
    const isProd = /production database/.test(String(expected));
    if (isProd) {
      // Authorization is granted; the run then fails on DNS because the internal
      // Render hostname does not resolve here. That is the intended outcome.
      ok(/PRODUCTION TARGET AUTHORIZED/.test(out), `72. ${label} IS authorizable (the one known production db)`);
      ok(!/Refusing to/.test(out), '    …authorized rather than refused');
    } else {
      ok(r.status !== 0 && !/PRODUCTION TARGET AUTHORIZED/.test(out),
         `72. ${label} is NOT authorizable even with a correct production token`, `status ${r.status}`);
      ok(expected.test(out), '    …and still reports the same refusal reason');
    }
    ok(!out.includes(FAKE), '    …no credential leaked');
  }

  // Exact identity must survive normalization: besthospice_db1 is NOT besthospice_db.
  const src = fs.readFileSync(SCRIPT, 'utf8');
  ok(/function containsIdentifier/.test(src) && /\[\^a-z0-9\]/.test(src),
     '73. identifiers are matched on boundaries, not as bare substrings');
  ok(/RENDER_HOST_ID_RE/.test(src) && /isRenderHost/.test(src),
     '   …and Render internal host ids are detected on the parsed hostname');
  ok(/besthospice_shadow_2/.test(src) && /dpg-d60g7h0gjchc73f306j0-a/.test(src),
     '74. the real shadow database name and host id are classified as SHADOW');
  {
    // Check the LISTS, not the whole file: db1 is named in an explanatory comment,
    // which is not the same as being an authorizable identifier.
    const lists = (src.match(/const (SHADOW|PRODUCTION)_IDENTIFIERS = \[[\s\S]*?\];/g) || []).join('\n');
    ok(lists.length > 0, '75. identifier lists are present');
    ok(!/besthospice_db1|db1/.test(lists), '   …and db1 appears in NO authorizable identifier list');
    ok(/besthospice_shadow_2/.test(lists) && /dpg-d60g7h0gjchc73f306j0-a/.test(lists),
       '   …while the real shadow name and host id ARE listed');
  }
  // A local database merely NAMED like a Render host must stay non-production.
  {
    const r = runArc(arc, ['--release','2026-08-19'], { DATABASE_URL: 'postgresql://me@localhost:5432/dpg-scratch-a' });
    const out = r.stdout + r.stderr;
    ok(!/production database|shadow database|unrecognised hosted/.test(out),
       '76. a LOCAL database merely named like a Render host id stays non-production');
  }
}

// ============================ DATABASE SEMANTICS ============================
const DB = process.env.TEST_DATABASE_URL;
(async () => {
  if (!DB) { console.log('\n--- database tests SKIPPED (set TEST_DATABASE_URL) ---'); return finish(); }
  if (/besthospice_db|dpg-d5hhmb4hg0os7380cecg-a|besthospice-shadow-2|render\.com/i.test(DB)) {
    console.log('  FAIL   TEST_DATABASE_URL looks like production'); fail++; return finish();
  }
  const { PrismaClient } = require('@prisma/client');
  const prisma = new PrismaClient({ datasources: { db: { url: DB } } });
  const reset = () => prisma.$executeRawUnsafe('TRUNCATE TABLE "CmsFacilityServiceArea","CmsFacility","CmsRelease" CASCADE');
  const counts = async () => ({
    rel: await prisma.cmsRelease.count(), fac: await prisma.cmsFacility.count(),
    sa: await prisma.cmsFacilityServiceArea.count() });

  try {
    // ---------- FIRST RELEASE ----------
    section('first release');
    await reset();
    const a1 = buildArchive({ key:'2026-05-01',
      facilities:[facility('031598'), facility('A01500',{'Facility Name':'OLD NAME'})],
      zips:[zrow('031598','85016'), zrow('031598','85017'), zrow('A01500','85018'), zrow('999999','85019')] });
    let r = runArc(a1, ['--release','2026-05-01','--write'], { DATABASE_URL: DB });
    ok(r.status === 0, 'first release ingests', r.stderr.slice(0,300));
    let c = await counts();
    ok(c.rel === 1, '17. CmsRelease created once', JSON.stringify(c));
    ok(c.fac === 2, '   two facilities created');
    ok(c.sa === 3, '29. orphan ZIP row skipped, not fatal (3 of 4 stored)', JSON.stringify(c));
    ok(/ORPHAN rows \(unknown CCN\) :\s+1/.test(r.stdout), '30. orphan count reported');
    ok(/distinct orphan CCNs      :\s+1/.test(r.stdout), '   distinct orphan CCNs reported');
    ok(!(await prisma.cmsFacility.findFirst({ where: { ccn: '999999' } })), '31. no placeholder facility created');
    const rel1 = await prisma.cmsRelease.findFirst();
    const f1 = await prisma.cmsFacility.findMany();
    ok(f1.every(f => f.firstSeenReleaseId === rel1.id && f.lastSeenReleaseId === rel1.id), '18. facility firstSeen = lastSeen = release');
    const s1 = await prisma.cmsFacilityServiceArea.findMany();
    ok(s1.every(s => s.firstSeenReleaseId === rel1.id && s.lastSeenReleaseId === rel1.id), '19. service area firstSeen = lastSeen = release');
    ok(f1.every(f => f.source === DB_SOURCE) && s1.every(s => s.source === DB_SOURCE), '39. all rows are cms_hospice');
    const lz = f1.find(f => f.ccn === '031598');
    ok(lz.ccn === '031598', '11. leading-zero CCN survives');
    ok(!!f1.find(f => f.ccn === 'A01500'), '12. alphanumeric CCN survives');
    ok(s1.every(s => typeof s.zip === 'string' && s.zip.length === 5), '13. ZIP survives as String');
    const norm = await prisma.cmsFacility.findFirst({ where: { ccn: '031598' } });
    ok(norm.address === '1 MAIN ST', '14. "-" Address Line 2 sentinel normalised away');
    ok(norm.certificationDate.toISOString().slice(0,10) === '2011-08-05', '15. certification date parsed to the exact DATE',
       String(norm.certificationDate));

    // ---------- SECOND, LATER RELEASE ----------
    section('second, later release');
    const a2 = buildArchive({ key:'2026-08-19',
      facilities:[facility('031598',{'Facility Name':'RENAMED HOSPICE','City/Town':'TUCSON'}), facility('031700')],
      zips:[zrow('031598','85016'), zrow('031598','85020'), zrow('031700','85021')] });
    r = runArc(a2, ['--release','2026-08-19','--write'], { DATABASE_URL: DB });
    ok(r.status === 0, 'later release ingests', r.stderr.slice(0,300));
    const rel2 = await prisma.cmsRelease.findFirst({ where: { releaseKey: '2026-08-19' } });
    const kept = await prisma.cmsFacility.findFirst({ where: { ccn: '031598' } });
    ok(kept.firstSeenReleaseId === rel1.id, '20. existing facility firstSeen preserved');
    ok(kept.lastSeenReleaseId === rel2.id, '21. existing facility lastSeen moves forward');
    ok(kept.name === 'RENAMED HOSPICE' && kept.city === 'TUCSON', '22. descriptive fields updated to the latest release');
    ok(!!(await prisma.cmsFacility.findFirst({ where: { ccn: '031700' } })), '23. new facility created');
    const gone = await prisma.cmsFacility.findFirst({ where: { ccn: 'A01500' } });
    ok(gone && gone.lastSeenReleaseId === rel1.id, '24. facility absent from the newer release retained with its OLD lastSeen');
    const facId = kept.id;
    const keptSa = await prisma.cmsFacilityServiceArea.findFirst({ where: { facilityId: facId, zip: '85016' } });
    ok(keptSa.firstSeenReleaseId === rel1.id, '25. existing service area firstSeen preserved');
    ok(keptSa.lastSeenReleaseId === rel2.id, '26. existing service area lastSeen moves forward');
    ok(!!(await prisma.cmsFacilityServiceArea.findFirst({ where: { facilityId: facId, zip: '85020' } })), '27. new service area created');
    const oldSa = await prisma.cmsFacilityServiceArea.findFirst({ where: { facilityId: facId, zip: '85017' } });
    ok(oldSa && oldSa.lastSeenReleaseId === rel1.id, '28. disappeared service area retained with its OLD lastSeen');
    ok((await prisma.cmsFacility.count()) === 3, '   nothing deleted: 3 facilities total');

    // ---------- IDEMPOTENCY ----------
    section('idempotency');
    const before = await counts();
    r = runArc(a2, ['--release','2026-08-19','--write'], { DATABASE_URL: DB });
    const after = await counts();
    ok(r.status === 0 && JSON.stringify(before) === JSON.stringify(after), '32. exact rerun produces zero duplicate rows', JSON.stringify(after));
    ok(/release           : UNCHANGED/.test(r.stdout), '33. rerun reports the release UNCHANGED');
    ok(/No transaction opened/.test(r.stdout), '   …and opens no transaction');

    const tampered = buildArchive({ key:'2026-08-19',
      facilities:[facility('031598',{'Facility Name':'DIFFERENT ARCHIVE'})], zips:[zrow('031598','85016')] });
    r = runArc(tampered, ['--release','2026-08-19','--write'], { DATABASE_URL: DB });
    const after2 = await counts();
    ok(r.status !== 0, '34. same release with a different manifest checksum CONFLICTS');
    ok(/manifestSha256 differs/.test(r.stdout+r.stderr), '   …naming the checksum difference');
    ok(JSON.stringify(after) === JSON.stringify(after2), '   …and writes zero rows');

    // ---------- CHRONOLOGY ----------
    section('chronology');
    const older = buildArchive({ key:'2026-01-01', facilities:[facility('031598')], zips:[zrow('031598','85016')] });
    r = runArc(older, ['--release','2026-01-01','--write'], { DATABASE_URL: DB });
    ok(r.status !== 0 && /CHRONOLOGY VIOLATION/.test(r.stdout+r.stderr), '35. older-than-latest release rejected');
    ok(JSON.stringify(await counts()) === JSON.stringify(after), '   …with zero writes');
    const newer = buildArchive({ key:'2026-11-01', facilities:[facility('031598')], zips:[zrow('031598','85016')] });
    r = runArc(newer, ['--release','2026-11-01','--write'], { DATABASE_URL: DB });
    ok(r.status === 0, '37. later release accepted');
    ok((await prisma.cmsRelease.count()) === 3, '   three releases now recorded');

    // ---------- SUPERSEDED RELEASE MAY NOT BE REPLAYED ----------
    // Regression: an already-ingested release that a later release has superseded
    // is an OUT-OF-ORDER attempt, not an idempotent re-run. Replaying it used to
    // drag lastSeenReleaseId backwards and restore stale descriptive values.
    section('superseded release refusal');
    await reset();
    const supA = buildArchive({ key:'2026-05-01',
      facilities:[facility('031598', { 'City/Town':'PHOENIX', 'Facility Name':'A NAME' })],
      zips:[zrow('031598','85016'), zrow('031598','85017')] });
    const supB = buildArchive({ key:'2026-08-19',
      facilities:[facility('031598', { 'City/Town':'TUCSON', 'Facility Name':'B NAME' })],
      zips:[zrow('031598','85016'), zrow('031598','85020')] });

    ok(runArc(supA, ['--release','2026-05-01','--write'], { DATABASE_URL: DB }).status === 0, 'S1. release A ingested');
    const supRelA = await prisma.cmsRelease.findFirst({ where: { releaseKey: '2026-05-01' } });
    let supFac = await prisma.cmsFacility.findFirst({ where: { ccn: '031598' } });
    ok(supFac.lastSeenReleaseId === supRelA.id && supFac.city === 'PHOENIX', '   …A is current');

    ok(runArc(supB, ['--release','2026-08-19','--write'], { DATABASE_URL: DB }).status === 0, 'S2. later release B ingested');
    const supRelB = await prisma.cmsRelease.findFirst({ where: { releaseKey: '2026-08-19' } });
    supFac = await prisma.cmsFacility.findFirst({ where: { ccn: '031598' } });
    ok(supFac.lastSeenReleaseId === supRelB.id && supFac.city === 'TUCSON' && supFac.name === 'B NAME',
       '   …B is now current and descriptive fields are B values');

    // Full snapshot of everything the replay could corrupt.
    const snapshot = async () => ({
      counts: await counts(),
      releases: (await prisma.cmsRelease.findMany({ orderBy:{releaseKey:'asc'},
        select:{ id:true, releaseKey:true, manifestSha256:true, datasetCount:true } })),
      // updatedAt is deliberately INCLUDED: a refused run must not touch it either.
      facilities: await prisma.cmsFacility.findMany({ orderBy:{ccn:'asc'} }),
      serviceAreas: await prisma.cmsFacilityServiceArea.findMany({ orderBy:[{zip:'asc'}],
        select:{ facilityId:true, zip:true, firstSeenReleaseId:true, lastSeenReleaseId:true } })
    });
    const supBefore = await snapshot();

    // (a) --write must be refused
    r = runArc(supA, ['--release','2026-05-01','--write'], { DATABASE_URL: DB });
    let out = r.stdout + r.stderr;
    ok(r.status !== 0, 'S3. replaying superseded release A with --write exits non-zero', `status ${r.status}`);
    ok(/CHRONOLOGY VIOLATION/.test(out), '   …with a clear older-than-latest chronology error');
    ok(/SUPERSEDED/.test(out), '   …explicitly naming it as superseded, not an idempotent re-run');
    ok(/2026-08-19/.test(out) && /2026-05-01/.test(out), '   …naming both the requested and the latest release');
    // The plan line "chronology : same release (idempotent re-run)" must never be
    // reached. The error text is allowed to say it is NOT an idempotent re-run.
    ok(!/same release \(idempotent re-run\)/.test(out), '   …and the plan never labels it an idempotent re-run');
    ok(!/PLAN {2}\(/.test(out), '   …refused before any plan is printed');

    const afterWrite = await snapshot();
    ok(JSON.stringify(supBefore.counts) === JSON.stringify(afterWrite.counts),
       'S4. CmsRelease / CmsFacility / CmsFacilityServiceArea counts unchanged', JSON.stringify(afterWrite.counts));
    ok(JSON.stringify(supBefore) === JSON.stringify(afterWrite),
       '   …entire relevant DB state byte-identical to the pre-attempt snapshot');
    const facAfter = await prisma.cmsFacility.findFirst({ where: { ccn: '031598' } });
    ok(facAfter.firstSeenReleaseId === supRelA.id, '   …facility firstSeen unchanged (still A)');
    ok(facAfter.lastSeenReleaseId === supRelB.id, '   …facility lastSeen still B, not rewound');
    ok(facAfter.city === 'TUCSON' && facAfter.name === 'B NAME', '   …descriptive fields still B values');
    const sa16 = await prisma.cmsFacilityServiceArea.findFirst({ where:{ facilityId: facAfter.id, zip:'85016' } });
    ok(sa16.lastSeenReleaseId === supRelB.id, '   …shared service-area lastSeen not rewound');
    const sa17 = await prisma.cmsFacilityServiceArea.findFirst({ where:{ facilityId: facAfter.id, zip:'85017' } });
    ok(sa17.lastSeenReleaseId === supRelA.id, '   …A-only service area keeps its historical A lastSeen');
    const madeCurrentUnderA = await prisma.cmsFacility.count({ where:{ lastSeenReleaseId: supRelA.id } });
    ok(madeCurrentUnderA === 0, '   …no facility was made current under A');

    // (b) the DB-backed DRY RUN must refuse it too, and must not call it idempotent
    r = runArc(supA, ['--release','2026-05-01'], { DATABASE_URL: DB });
    out = r.stdout + r.stderr;
    ok(r.status !== 0, 'S5. DB-backed dry run of a superseded release is also refused', `status ${r.status}`);
    ok(/CHRONOLOGY VIOLATION/.test(out), '   …with the same chronology error');
    ok(!/same release \(idempotent re-run\)/.test(out), '   …and does NOT report it as an idempotent re-run');
    ok(JSON.stringify(await snapshot()) === JSON.stringify(supBefore), '   …still zero writes');

    // (c) --no-db cannot know DB chronology and stays archive-validation-only
    r = runArc(supA, ['--release','2026-05-01','--no-db'], { DATABASE_URL: DB });
    ok(r.status === 0 && /no database was contacted/.test(r.stdout),
       'S6. --no-db remains archive-validation-only and is unaffected by DB chronology');

    // (d) the genuine idempotent path — rerunning the LATEST release — still works
    r = runArc(supB, ['--release','2026-08-19','--write'], { DATABASE_URL: DB });
    ok(r.status === 0, 'S7. exact rerun of the LATEST release B still succeeds');
    ok(/release           : UNCHANGED/.test(r.stdout), '   …reported UNCHANGED');
    ok(/No transaction opened/.test(r.stdout), '   …and opens no transaction');
    ok(JSON.stringify(await snapshot()) === JSON.stringify(supBefore), '   …with zero row changes');

    // (e) same latest release, different manifest, still CONFLICTs
    const supBTampered = buildArchive({ key:'2026-08-19',
      facilities:[facility('031598', { 'City/Town':'TUCSON', 'Facility Name':'TAMPERED' })],
      zips:[zrow('031598','85016'), zrow('031598','85020')] });
    r = runArc(supBTampered, ['--release','2026-08-19','--write'], { DATABASE_URL: DB });
    ok(r.status !== 0 && /manifestSha256 differs/.test(r.stdout+r.stderr),
       'S8. latest release B with a changed manifest still CONFLICTs');
    ok(JSON.stringify(await snapshot()) === JSON.stringify(supBefore), '   …with zero writes');

    // (f) a never-ingested older release is still refused, and says so plainly
    const supNever = buildArchive({ key:'2026-02-01', facilities:[facility('031598')], zips:[zrow('031598','85016')] });
    r = runArc(supNever, ['--release','2026-02-01','--write'], { DATABASE_URL: DB });
    out = r.stdout + r.stderr;
    ok(r.status !== 0 && /CHRONOLOGY VIOLATION/.test(out), 'S9. never-ingested older release still refused');
    ok(!/SUPERSEDED/.test(out), '   …and is not mislabelled as superseded');
    ok(JSON.stringify(await snapshot()) === JSON.stringify(supBefore), '   …with zero writes');

    // (g) the in-transaction check is the authoritative one and is unconditional
    {
      const src3 = fs.readFileSync(SCRIPT,'utf8');
      const tx3 = src3.slice(src3.indexOf('await prisma.$transaction(async (tx) => {'));
      ok(!/if \(!cur && newest/.test(tx3),
         'S10. the in-transaction chronology check is no longer conditioned on !cur');
      const iLock3 = tx3.indexOf('pg_advisory_xact_lock');
      const iChron3 = tx3.indexOf('newest.releaseKey > arc.releaseKey');
      ok(iLock3 > -1 && iChron3 > -1 && iLock3 < iChron3,
         '    …and the advisory lock is still acquired before it');
    }

    // ---------- SOURCE CONSISTENCY ----------
    section('source consistency');
    const rels = await prisma.cmsRelease.findMany();
    ok(rels.every(x => x.source === DB_SOURCE), '38a. every CmsRelease is cms_hospice');
    const xs = await prisma.$queryRawUnsafe(
      `SELECT count(*)::int AS n FROM "CmsFacility" f JOIN "CmsRelease" r ON r.id=f."lastSeenReleaseId" WHERE r.source<>f.source`);
    ok(xs[0].n === 0, '38b. no facility links to a release of another source');
    const xs2 = await prisma.$queryRawUnsafe(
      `SELECT count(*)::int AS n FROM "CmsFacilityServiceArea" s JOIN "CmsFacility" f ON f.id=s."facilityId" WHERE f.source<>s.source`);
    ok(xs2[0].n === 0, '38c. no service area links to a facility of another source');

    // ---------- TRANSACTION ROLLBACK ----------
    section('transaction rollback');
    await reset();
    const base = buildArchive({ key:'2026-05-01', facilities:[facility('031598')], zips:[zrow('031598','85016')] });
    ok(runArc(base, ['--release','2026-05-01','--write'], { DATABASE_URL: DB }).status === 0, 'baseline release ingested');
    const pre = await counts();
    // Force a mid-transaction failure: a CHECK constraint that the second
    // release's service-area insert must violate.
    await prisma.$executeRawUnsafe(`ALTER TABLE "CmsFacilityServiceArea" ADD CONSTRAINT tmp_fail CHECK (zip <> '85099')`);
    const boom = buildArchive({ key:'2026-09-01', facilities:[facility('031598'), facility('031800')],
      zips:[zrow('031598','85016'), zrow('031800','85099')] });
    r = runArc(boom, ['--release','2026-09-01','--write'], { DATABASE_URL: DB });
    const post = await counts();
    ok(r.status !== 0, '40. induced mid-transaction failure exits non-zero');
    ok(/ROLLED BACK|rolled back/i.test(r.stdout+r.stderr), '   …and says the transaction rolled back');
    ok(JSON.stringify(pre) === JSON.stringify(post),
       '   …release, facility AND service-area changes ALL rolled back', `${JSON.stringify(pre)} vs ${JSON.stringify(post)}`);
    ok(!(await prisma.cmsRelease.findFirst({ where: { releaseKey: '2026-09-01' } })), '   …no orphan CmsRelease left behind');
    await prisma.$executeRawUnsafe(`ALTER TABLE "CmsFacilityServiceArea" DROP CONSTRAINT tmp_fail`);

    // ---------- CONCURRENCY ----------
    section('concurrent ingestion');
    await reset();
    const cBase = buildArchive({ key:'2026-05-01', facilities:[facility('031598')], zips:[zrow('031598','85016')] });
    ok(runArc(cBase, ['--release','2026-05-01','--write'], { DATABASE_URL: DB }).status === 0,
       'concurrency baseline release ingested');
    // Two DIFFERENT later releases launched together. Without the per-source
    // advisory lock both pass the chronology re-check under READ COMMITTED
    // (neither can see the other's uncommitted CmsRelease) and commit order, not
    // releaseKey, decides the surviving lastSeenReleaseId.
    const cA = buildArchive({ key:'2026-09-01', facilities:[facility('031598',{'City/Town':'A_CITY'})],
      zips:[zrow('031598','85016'), zrow('031598','85030')] });
    const cB = buildArchive({ key:'2026-10-01', facilities:[facility('031598',{'City/Town':'B_CITY'})],
      zips:[zrow('031598','85016'), zrow('031598','85040')] });
    const { spawn } = require('child_process');
    const launch = (arc, key) => new Promise(res => {
      const c = spawn(process.execPath, [SCRIPT, '--release', key, '--write'],
        { encoding:'utf8', env: { ...process.env, CMS_ARCHIVE_DIR: arc.root, DATABASE_URL: DB } });
      let out = '';
      c.stdout.on('data', d => { out += d; }); c.stderr.on('data', d => { out += d; });
      c.on('close', code => res({ code, out }));
    });
    const [rA, rB] = await Promise.all([launch(cA,'2026-09-01'), launch(cB,'2026-10-01')]);
    const okCount = [rA, rB].filter(x => x.code === 0).length;
    ok(okCount >= 1, '50. at least one concurrent ingestion succeeds', `A=${rA.code} B=${rB.code}`);
    const relsC = await prisma.cmsRelease.findMany({ orderBy: { releaseKey: 'asc' } });
    ok(relsC.length === 1 + okCount, '   …exactly one CmsRelease per successful run, no partial releases',
       relsC.map(x=>x.releaseKey).join(','));
    // Whatever interleaving occurred, the invariant must hold: lastSeen points at
    // the NEWEST release actually committed, never at an older one.
    const newestKey = relsC[relsC.length - 1].releaseKey;
    const newestRel = relsC[relsC.length - 1];
    const fC = await prisma.cmsFacility.findFirst({ where: { ccn: '031598' } });
    ok(fC.lastSeenReleaseId === newestRel.id,
       '51. facility lastSeenReleaseId is the NEWEST committed release, not the last committer',
       `lastSeen=${(relsC.find(x=>x.id===fC.lastSeenReleaseId)||{}).releaseKey} newest=${newestKey}`);
    ok(fC.city === (newestKey === '2026-10-01' ? 'B_CITY' : 'A_CITY'),
       '   …and descriptive fields come from that newest release', `city=${fC.city}`);
    const saNewest = await prisma.cmsFacilityServiceArea.findFirst({ where: { facilityId: fC.id, zip: '85016' } });
    ok(saNewest.lastSeenReleaseId === newestRel.id, '52. shared service area also carries the newest release');
    const xsC = await prisma.$queryRawUnsafe(
      `SELECT count(*)::int AS n FROM "CmsFacilityServiceArea" s
         JOIN "CmsRelease" r ON r.id = s."lastSeenReleaseId"
        WHERE r."releaseKey" > $1`, newestKey);
    ok(xsC[0].n === 0, '   …no row references a release newer than the newest committed one');
    ok(/advisory_xact_lock/.test(fs.readFileSync(SCRIPT,'utf8')),
       '53. serialisation uses a transaction-scoped advisory lock (no lock table, no app mutex)');
    {
      const src2 = fs.readFileSync(SCRIPT,'utf8');
      const tx = src2.slice(src2.indexOf('await prisma.$transaction(async (tx) => {'));
      const iLock = tx.indexOf('pg_advisory_xact_lock');
      const iChron = tx.indexOf('tx.cmsRelease.findUnique');
      ok(iLock > -1 && iChron > -1 && iLock < iChron,
         '   …acquired as the FIRST statement, before the chronology re-check');
    }

    // ---------- AUTHORIZED PRODUCTION-CLASSIFIED TARGET ----------
    // No production credential and no test-only guard seam. The classifier is
    // purely string-based, so a LOCAL database literally named "besthospice_db"
    // is classified PRODUCTION by the real guard while being entirely disposable.
    // Every branch below therefore runs through the genuine code path.
    section('authorized production-classified target');
    {
      const prodName = 'besthospice_db';
      const prodUrl = DB.replace(/\/[^/?]+(\?|$)/, `/${prodName}$1`);
      let ready = false;
      try {
        await prisma.$executeRawUnsafe(`DROP DATABASE IF EXISTS "${prodName}"`);
        await prisma.$executeRawUnsafe(`CREATE DATABASE "${prodName}"`);
        const mig = spawnSync('npx', ['prisma','migrate','deploy','--schema','prisma/schema.prisma'],
          { encoding:'utf8', cwd: ROOT, env: { ...process.env, DATABASE_URL: prodUrl } });
        ready = mig.status === 0;
        if (!ready) console.log(`  (migrate deploy failed: ${String(mig.stderr).slice(0,160)})`);
      } catch (e) { console.log(`  (could not create the production-classified database: ${e.message.slice(0,120)})`); }

      if (!ready) {
        console.log('  SKIPPED — could not provision a production-classified local database');
      } else {
        const arc = buildArchive({ key:'2026-08-19',
          facilities:[facility('031598'), facility('A01500')],
          zips:[zrow('031598','85016'), zrow('031598','85017'), zrow('A01500','85018')] });
        const good = authToken(DB_SOURCE, '2026-08-19', manifestHashOf(arc));
        const pc = new PrismaClient({ datasources: { db: { url: prodUrl } } });
        const pcounts = async () => ({
          rel: await pc.cmsRelease.count(), fac: await pc.cmsFacility.count(),
          sa: await pc.cmsFacilityServiceArea.count() });
        try {
          ok(JSON.stringify(await pcounts()) === '{"rel":0,"fac":0,"sa":0}', 'P0. production-classified target starts empty');

          // The classifier really does treat it as production: no token, refused.
          let rp = runArc(arc, ['--release','2026-08-19','--write'], { DATABASE_URL: prodUrl });
          ok(rp.status !== 0 && /points at the production database/.test(rp.stdout+rp.stderr),
             'P1. the real guard classifies this local target as PRODUCTION');
          ok(JSON.stringify(await pcounts()) === '{"rel":0,"fac":0,"sa":0}', '   …and wrote nothing');

          // 5. correct token + DRY RUN -> connects, plans, writes nothing.
          rp = runArc(arc, ['--release','2026-08-19','--production-authorization', good], { DATABASE_URL: prodUrl });
          ok(rp.status === 0, 'P2. correct authorization + dry run succeeds', rp.stderr.slice(0,200));
          ok(/PRODUCTION TARGET AUTHORIZED/.test(rp.stdout), '   …prints the authorization banner');
          ok(/READ-ONLY PLANNING \(no --write\)/.test(rp.stdout), '   …and states the mode is read-only planning');
          ok(/DRY RUN — ZERO WRITES/.test(rp.stdout), '   …still a dry run');
          ok(/facilities        : CREATE 2/.test(rp.stdout), '   …and produced a real plan');
          ok(JSON.stringify(await pcounts()) === '{"rel":0,"fac":0,"sa":0}',
             'P3. authorization alone writes NOTHING — it never implies --write');

          // 6. correct token + --write -> the ordinary write path, all checks intact.
          rp = runArc(arc, ['--release','2026-08-19','--production-authorization', good, '--write'], { DATABASE_URL: prodUrl });
          ok(rp.status === 0, 'P4. correct authorization + --write reaches the normal write path', rp.stderr.slice(0,300));
          ok(/WRITE \(--write supplied\)/.test(rp.stdout), '   …banner states WRITE mode');
          ok(/WRITE MODE ACTIVE/.test(rp.stdout) && /INGESTED release 2026-08-19/.test(rp.stdout), '   …and ingested in one transaction');
          const pc1 = await pcounts();
          ok(pc1.rel === 1 && pc1.fac === 2 && pc1.sa === 3, '   …with the expected rows', JSON.stringify(pc1));

          // Every ordinary invariant still applies behind the authorization.
          rp = runArc(arc, ['--release','2026-08-19','--production-authorization', good, '--write'], { DATABASE_URL: prodUrl });
          ok(rp.status === 0 && /release           : UNCHANGED/.test(rp.stdout) && /No transaction opened/.test(rp.stdout),
             'P5. idempotency still holds behind authorization');
          ok(JSON.stringify(await pcounts()) === JSON.stringify(pc1), '   …zero duplicate rows');

          const tampered = buildArchive({ key:'2026-08-19', facilities:[facility('031598',{'City/Town':'ELSEWHERE'})], zips:[zrow('031598','85016')] });
          const tamperTok = authToken(DB_SOURCE, '2026-08-19', manifestHashOf(tampered));
          rp = runArc(tampered, ['--release','2026-08-19','--production-authorization', tamperTok, '--write'], { DATABASE_URL: prodUrl });
          ok(rp.status !== 0 && /manifestSha256 differs/.test(rp.stdout+rp.stderr),
             'P6. manifest CONFLICT still refuses even with a token valid for that archive');
          ok(JSON.stringify(await pcounts()) === JSON.stringify(pc1), '   …zero writes');

          const older = buildArchive({ key:'2026-05-01', facilities:[facility('031598')], zips:[zrow('031598','85016')] });
          const olderTok = authToken(DB_SOURCE, '2026-05-01', manifestHashOf(older));
          rp = runArc(older, ['--release','2026-05-01','--production-authorization', olderTok, '--write'], { DATABASE_URL: prodUrl });
          ok(rp.status !== 0 && /CHRONOLOGY VIOLATION/.test(rp.stdout+rp.stderr),
             'P7. chronology still refuses an older release even with a correct token for it');
          ok(JSON.stringify(await pcounts()) === JSON.stringify(pc1), '   …zero writes');
        } finally {
          await pc.$disconnect().catch(()=>{});
          await prisma.$executeRawUnsafe(`DROP DATABASE IF EXISTS "${prodName}"`).catch(()=>{});
        }
      }
    }

    // ---------- NON-PRODUCTION + UNNECESSARY TOKEN ----------
    // A token is meaningless against a non-production target. It must be ignored
    // outright: it may not make the target look production-like, may not print an
    // approval banner, and may not change --write semantics.
    section('non-production with an unnecessary token');
    await reset();
    {
      const arc = buildArchive({ key:'2026-05-01', facilities:[facility('031598')], zips:[zrow('031598','85016')] });
      const correct = authToken(DB_SOURCE, '2026-05-01', manifestHashOf(arc));
      const bogus = 'a'.repeat(64);

      for (const [label, tok] of [['a correct-for-this-release token', correct], ['a well-formed but wrong token', bogus]]) {
        await reset();
        let r = runArc(arc, ['--release','2026-05-01','--production-authorization', tok], { DATABASE_URL: DB });
        let out = r.stdout + r.stderr;
        ok(r.status === 0, `N1. non-production dry run succeeds with ${label}`, r.stderr.slice(0,200));
        ok(!/PRODUCTION TARGET AUTHORIZED/.test(out), '   …prints no authorization banner');
        ok(!/production database|shadow database|unrecognised hosted/.test(out), '   …the target is not treated as production-like');
        ok(/DRY RUN — ZERO WRITES/.test(out), '   …--write semantics unchanged: still a dry run');
        const c0 = await counts();
        ok(c0.rel === 0 && c0.fac === 0 && c0.sa === 0, '   …and wrote nothing', JSON.stringify(c0));

        // The token also does not block or alter an ordinary authorized-by-default write.
        r = runArc(arc, ['--release','2026-05-01','--production-authorization', tok, '--write'], { DATABASE_URL: DB });
        ok(r.status === 0 && /INGESTED release 2026-05-01/.test(r.stdout),
           `N2. non-production --write behaves normally with ${label}`, r.stderr.slice(0,200));
        ok(!/PRODUCTION TARGET AUTHORIZED/.test(r.stdout+r.stderr), '   …still no authorization banner');
        const c1 = await counts();
        ok(c1.rel === 1 && c1.fac === 1 && c1.sa === 1, '   …with the ordinary rows', JSON.stringify(c1));
      }
      await reset();
    }

    // ---------- DRY RUN CANNOT WRITE ----------
    section('dry run');
    await reset();
    const d = buildArchive({ key:'2026-05-01', facilities:[facility('031598')], zips:[zrow('031598','85016')] });
    r = runArc(d, ['--release','2026-05-01'], { DATABASE_URL: DB });
    const dc = await counts();
    ok(r.status === 0 && dc.rel === 0 && dc.fac === 0 && dc.sa === 0, '43. default dry run writes ZERO rows', JSON.stringify(dc));
    ok(/DRY RUN — ZERO WRITES/.test(r.stdout) && /nothing was written/.test(r.stdout), '   …and says so plainly');
  } finally {
    await prisma.$disconnect().catch(()=>{});
  }
  finish();
})().catch(e => { console.error('\nharness failed:', e.message); process.exit(1); });

function finish() {
  fs.rmSync(TMP, { recursive: true, force: true });
  console.log(`\n${'='.repeat(60)}`);
  console.log(fail === 0 ? `PASSED — ${pass} assertions` : `FAILED — ${fail} of ${pass+fail} assertions failed`);
  process.exit(fail === 0 ? 0 : 1);
}
