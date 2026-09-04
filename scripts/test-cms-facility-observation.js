#!/usr/bin/env node
/**
 * Guards CmsFacilityObservation — the append-only per-release facility history
 * added by migration 20260904212702_add_cms_facility_observation.
 *
 * Like scripts/test-cms-hospice-ingestion.js, this EXECUTES THE REAL CODE: the
 * real importer (scripts/import-cms-hospice-data.js) and the real seed script
 * (scripts/seed-cms-facility-observations.js) are spawned against synthetic
 * archives and a disposable database. Nothing here reimplements ingestion.
 *
 * Every CCN, name, address and ZIP is SYNTHETIC. No production identifier appears
 * anywhere, and the database phase refuses to run against anything that looks
 * like production.
 *
 *   node scripts/test-cms-facility-observation.js
 *   TEST_DATABASE_URL=postgresql://localhost:5432/bh_obs_test \
 *     node scripts/test-cms-facility-observation.js
 */
const fs = require('fs');
const os = require('os');
const path = require('path');
const zlib = require('zlib');
const crypto = require('crypto');
const { spawnSync } = require('child_process');

const ROOT = path.join(__dirname, '..');
const SCRIPT = path.join(ROOT, 'scripts', 'import-cms-hospice-data.js');
const SEED = path.join(ROOT, 'scripts', 'seed-cms-facility-observations.js');
const IMPORTER_SRC = fs.readFileSync(SCRIPT, 'utf8');
const SEED_SRC = fs.readFileSync(SEED, 'utf8');
const SCHEMA_SRC = fs.readFileSync(path.join(ROOT, 'prisma', 'schema.prisma'), 'utf8');
const MIGRATION_DIR = '20260904212702_add_cms_facility_observation';
const MIGRATION_SRC = fs.readFileSync(path.join(ROOT, 'prisma', 'migrations', MIGRATION_DIR, 'migration.sql'), 'utf8');
const HOSP = (() => {
  const reg = require(path.join(ROOT, 'data', 'cms-dataset-registry.json'));
  const arr = Array.isArray(reg.datasets) ? reg.datasets : reg;
  const out = {};
  arr.filter((d) => d.source === 'hospice').forEach((d) => { out[d.logicalKey] = d; });
  return out;
})();
const DB_SOURCE = 'cms_hospice';

let pass = 0, fail = 0;
const ok = (c, label, detail) => {
  console.log(`  ${c ? 'ok  ' : 'FAIL'} ${label}${c || !detail ? '' : `  — ${detail}`}`);
  c ? pass++ : fail++;
};
const section = (t) => console.log(`\n--- ${t} ---`);
const sha256 = (b) => crypto.createHash('sha256').update(b).digest('hex');
const TMP = fs.mkdtempSync(path.join(os.tmpdir(), 'cms-obs-tests-'));

// ---- fixture archive builder (same shape as the ingestion harness) ---------
const csv = (head, rows) => [head.join(','), ...rows.map((r) => head.map((h) => `"${String(r[h] ?? '').replace(/"/g, '""')}"`).join(','))].join('\n') + '\n';

function buildArchive({ key, facilities, zips, capturedAt = '2026-08-27T20:21:08.919Z', modifiedOverride = null }) {
  const root = fs.mkdtempSync(path.join(TMP, 'arc-'));
  const dir = path.join(root, 'hospice', key);
  fs.mkdirSync(dir, { recursive: true });
  const files = {};
  const write = (logicalKey, head, rows) => {
    const raw = Buffer.from(csv(head, rows), 'utf8');
    fs.writeFileSync(path.join(dir, `${logicalKey}.csv.gz`), zlib.gzipSync(raw));
    files[logicalKey] = { source: 'hospice', logicalKey, datasetId: HOSP[logicalKey].datasetId,
      title: HOSP[logicalKey].expectedTitle, modified: modifiedOverride || key,
      sourceUrl: 'https://data.cms.gov/x.csv', rawBytes: raw.length,
      gzipBytes: 0, sha256Raw: sha256(raw), rowCount: rows.length,
      headers: head, archivedAt: capturedAt };
  };
  write('general', HOSP.general.expectedHeaders, facilities);
  write('zip', HOSP.zip.expectedHeaders, zips);
  for (const k of ['provider', 'cahps_provider', 'state', 'national']) write(k, HOSP[k].expectedHeaders, []);
  const mf = { releaseKey: key, source: 'hospice', schemaVersion: 2, capturedAt,
    catalog: 'https://data.cms.gov/x', datasetCount: Object.keys(files).length,
    expectedDatasetCount: 6, status: 'complete', skipped: [], rowCountDeltas: [], note: 'fixture', files };
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
const runArc = (arc, args, env = {}) => spawnSync(process.execPath, [SCRIPT, ...args],
  { encoding: 'utf8', env: { ...process.env, CMS_ARCHIVE_DIR: arc.root, ...env } });
const runSeed = (args, env = {}) => spawnSync(process.execPath, [SEED, ...args],
  { encoding: 'utf8', env: { ...process.env, ...env } });

// ================== STATIC / SOURCE-LEVEL GUARANTEES =======================
section('A. migration and schema shape');
ok(/CREATE TABLE "CmsFacilityObservation"/.test(MIGRATION_SRC), 'A1. migration creates CmsFacilityObservation');
ok(/CREATE UNIQUE INDEX "CmsFacilityObservation_facilityId_releaseId_key"/.test(MIGRATION_SRC),
   'A2. unique index is on (facilityId, releaseId)');
ok(/CREATE INDEX "CmsFacilityObservation_source_releaseId_idx"/.test(MIGRATION_SRC), 'A3. (source, releaseId) index present');
ok(/CREATE INDEX "CmsFacilityObservation_source_releaseId_ownershipType_idx"/.test(MIGRATION_SRC),
   'A4. (source, releaseId, ownershipType) index present');
ok(/FOREIGN KEY \("facilityId", "source"\) REFERENCES "CmsFacility"\("id", "source"\)/.test(MIGRATION_SRC),
   'A5. composite FK to CmsFacility(id, source) — source isolation enforced by the DB');
ok(/FOREIGN KEY \("releaseId", "source"\) REFERENCES "CmsRelease"\("id", "source"\)/.test(MIGRATION_SRC),
   'A6. composite FK to CmsRelease(id, source) — source isolation enforced by the DB');
ok(!/\bDROP\b/i.test(MIGRATION_SRC), 'A7. migration contains no DROP');
// "ON DELETE RESTRICT" is a foreign-key action, not a data deletion, so the check
// targets actual statements rather than the bare keyword.
ok(!/\bDELETE\s+FROM\b/i.test(MIGRATION_SRC) && !/\bTRUNCATE\b/i.test(MIGRATION_SRC),
   'A8. migration contains no DELETE FROM / TRUNCATE statement');
ok(/ON DELETE RESTRICT/.test(MIGRATION_SRC),
   'A8b. FKs are ON DELETE RESTRICT — deleting a release can never erase its observations');
ok(!/\bINSERT\b/i.test(MIGRATION_SRC), 'A9. migration contains no seed data');
{
  // Additive only: the sole ALTERs are ADD CONSTRAINT on the NEW table.
  const alters = MIGRATION_SRC.match(/ALTER TABLE "([^"]+)"[^;]*/g) || [];
  const nonNew = alters.filter((s) => !/ALTER TABLE "CmsFacilityObservation" ADD CONSTRAINT/.test(s));
  ok(nonNew.length === 0, 'A10. every ALTER targets only the new table (ADD CONSTRAINT)', JSON.stringify(nonNew).slice(0, 200));
}
ok(/certificationDate" DATE/.test(MIGRATION_SRC), 'A11. certificationDate is DATE, matching CmsFacility');
ok(/model CmsFacilityObservation/.test(SCHEMA_SRC), 'A12. schema declares the model');
ok(/observations\s+CmsFacilityObservation\[\]/.test(SCHEMA_SRC), 'A13. CmsFacility back-relation added');
ok(/facilityObservations\s+CmsFacilityObservation\[\]/.test(SCHEMA_SRC), 'A14. CmsRelease back-relation added');

section('negative controls — invariants that must NOT regress');
ok(/@@unique\(\[facilityId, releaseId\]\)/.test(SCHEMA_SRC),
   'N1. observation uniqueness INCLUDES releaseId (dropping it would collapse history to one row per facility)');
ok(/ON CONFLICT \("facilityId","releaseId"\) DO UPDATE SET/.test(IMPORTER_SRC),
   'N2. importer conflict target is (facilityId, releaseId), so a new release cannot update an older observation');
ok(!/ON CONFLICT \("facilityId"\) DO UPDATE/.test(IMPORTER_SRC),
   'N3. importer does NOT upsert observations on facilityId alone');
ok(!/--force|--allow-production|--unsafe|--skip-guard/.test(IMPORTER_SRC),
   'N4. no chronology/production bypass flag was introduced into the importer');
// Behavioural rather than textual: the seed's doc comment deliberately NAMES the
// flags it refuses, so a grep would false-positive. Prove the parser rejects them.
for (const flag of ['--force', '--allow-production', '--unsafe', '--skip-guard']) {
  const rr = spawnSync(process.execPath, [SEED, flag], { encoding: 'utf8' });
  ok(rr.status !== 0 && /Unknown argument/.test(String(rr.stderr)),
     `N5. seed rejects "${flag}" as an unknown argument (no bypass exists)`);
}
ok(!/a === '--force'|a === '--allow-production'|a === '--unsafe'|a === '--skip-guard'/.test(SEED_SRC),
   'N5e. no bypass flag is wired into the seed argument parser');
ok(/is OLDER than the latest ingested/.test(IMPORTER_SRC), 'N6. chronology guard message still present');
ok(/chronology violation detected inside the transaction/.test(IMPORTER_SRC),
   'N7. in-transaction chronology re-check still present');
{
  // CmsFacility must remain current-state: uniqueness and brackets untouched.
  ok(/@@unique\(\[source, ccn\]\)/.test(SCHEMA_SRC), 'N8. CmsFacility @@unique([source, ccn]) unchanged');
  ok(/firstSeenReleaseId String/.test(SCHEMA_SRC), 'N9. firstSeenReleaseId retained');
  ok(/lastSeenReleaseId  String/.test(SCHEMA_SRC) || /lastSeenReleaseId\s+String/.test(SCHEMA_SRC),
     'N10. lastSeenReleaseId retained');
}
ok(!/CmsServiceAreaObservation/.test(SCHEMA_SRC) && !/CmsServiceAreaObservation/.test(MIGRATION_SRC),
   'N11. CmsServiceAreaObservation was NOT added (deferred by decision)');
{
  // The seed must write exactly one table. Scan its raw SQL for other targets.
  const writes = (SEED_SRC.match(/INSERT INTO "([A-Za-z]+)"|UPDATE "([A-Za-z]+)"|DELETE FROM "([A-Za-z]+)"/g) || []);
  const tables = [...new Set(writes.map((w) => (w.match(/"([A-Za-z]+)"/) || [])[1]))];
  ok(tables.length === 1 && tables[0] === 'CmsFacilityObservation',
     'N12. seed contains raw writes to CmsFacilityObservation ONLY', JSON.stringify(tables));
  ok(!/prisma\.(cmsFacility|cmsFacilityServiceArea|cmsFacilityMeasure|provider|providerExternalIdentity)\.(create|update|upsert|delete)/i.test(SEED_SRC),
     'N13. seed makes no Prisma write call against any other model');
}
{
  // The observation write must not consult CMS `modified`. May->August proved a
  // modified-date bump can accompany byte-identical content, so content history
  // must never be gated on it.
  const block = (IMPORTER_SRC.match(/Append-only history[\s\S]*?const sRows/) || [''])[0];
  ok(block.length > 0, 'N14. observation write block is locatable');
  ok(!/modified/.test(block), 'N15. observation write never consults CMS `modified` (a bumped date != changed content)');
  ok(/fac\.facilities\.values\(\)/.test(block), 'N16. observation values come from the PARSED ARCHIVE, not from CmsFacility');
  ok(!/ccnToId[\s\S]{0,40}lastSeen/.test(block), 'N17. observation values are not derived by diffing current state');
}
{
  // County/ownership semantics that future diff consumers must honour.
  ok(/case-insensitiv/i.test(SCHEMA_SRC), 'N18. schema documents that county must be compared case-insensitively');
  ok(/COVERAGE REGRESSION/.test(SCHEMA_SRC), 'N19. schema documents ownership value->null as coverage regression, not a change');
  ok(!/toUpperCase|toLowerCase|normali[sz]e/.test((IMPORTER_SRC.match(/Append-only history[\s\S]*?const sRows/) || [''])[0]),
     'N20. importer stores county/ownership RAW — no normalisation at write time');
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
  const reset = () => prisma.$executeRawUnsafe(
    'TRUNCATE TABLE "CmsFacilityObservation","CmsFacilityServiceArea","CmsFacilityMeasure","CmsFacility","CmsRelease" CASCADE');
  const relByKey = async (k) => prisma.cmsRelease.findFirst({ where: { releaseKey: k } });
  const obsFor = async (ccn) => prisma.$queryRawUnsafe(
    `SELECT o.*, r."releaseKey" FROM "CmsFacilityObservation" o
     JOIN "CmsRelease" r ON r.id = o."releaseId"
     WHERE o.ccn = $1 ORDER BY r."releaseKey" ASC`, ccn);

  try {
    // ---------- B. first release ----------
    section('B. first release');
    await reset();
    const a1 = buildArchive({ key: '2026-05-01',
      facilities: [facility('031598'), facility('A01500', { 'Ownership Type': 'Non-Profit' })],
      zips: [zrow('031598', '85016'), zrow('A01500', '85018')] });
    let r = runArc(a1, ['--release', '2026-05-01', '--write'], { DATABASE_URL: DB });
    ok(r.status === 0, 'B1. first release ingests', String(r.stderr).slice(0, 300));
    let n = await prisma.cmsFacilityObservation.count();
    ok(n === 2, 'B2. one observation per facility', `got ${n}`);
    const o1 = (await obsFor('031598'))[0];
    ok(o1 && o1.name === 'HOSPICE 031598' && o1.city === 'PHOENIX' && o1.zip === '85016',
       'B3. observation equals the parsed facility values');
    ok(o1 && o1.address === '1 MAIN ST', 'B4. Address Line 2 "-" sentinel dropped, same as current state');
    ok(o1 && o1.county === 'MARICOPA' && o1.ownershipType === 'For-Profit', 'B5. county/ownership stored raw');
    ok(o1 && o1.certificationDate instanceof Date
       && o1.certificationDate.toISOString().slice(0, 10) === '2011-08-05', 'B6. certificationDate parsed to the published date');
    ok(o1 && o1.source === DB_SOURCE, 'B7. observation carries the DB source namespace');
    ok(/CmsFacilityObservation 2/.test(r.stdout), 'B8. run summary reports the observation count');

    // ---------- C-H. second release ----------
    section('C-H. second release attribute history');
    const a2 = buildArchive({ key: '2026-08-19',
      facilities: [
        facility('031598'),                                             // unchanged
        facility('A01500', { 'Ownership Type': 'For-Profit' }),          // ownership v->v
        facility('061111', { 'Ownership Type': '-' }),                   // new, ownership null
      ],
      zips: [zrow('031598', '85016'), zrow('A01500', '85018'), zrow('061111', '85019')] });
    r = runArc(a2, ['--release', '2026-08-19', '--write'], { DATABASE_URL: DB });
    ok(r.status === 0, 'C1. second release ingests', String(r.stderr).slice(0, 300));
    const h598 = await obsFor('031598');
    ok(h598.length === 2, 'C2. unchanged facility gains a SECOND observation', `got ${h598.length}`);
    ok(h598[0].releaseKey === '2026-05-01' && h598[1].releaseKey === '2026-08-19', 'C3. one per release, in order');
    ok(h598[0].name === 'HOSPICE 031598' && h598[0].city === 'PHOENIX',
       'C4. the FIRST observation is unchanged by the second release');
    const hA = await obsFor('A01500');
    ok(hA.length === 2 && hA[0].ownershipType === 'Non-Profit' && hA[1].ownershipType === 'For-Profit',
       'D1. ownership value->value: both values preserved per release');
    ok(h598[0].certificationDate.toISOString().slice(0, 10) === '2011-08-05'
       && h598[1].certificationDate.toISOString().slice(0, 10) === '2011-08-05',
       'H1. unchanged certificationDate preserved in both snapshots');

    // ownership value -> null, name, address/city/zip
    const a3 = buildArchive({ key: '2026-09-30',
      facilities: [
        facility('031598', { 'Facility Name': 'RENAMED HOSPICE', 'Address Line 1': '99 OTHER AVE',
          'City/Town': 'TUCSON', 'ZIP Code': '85701', 'County/Parish': 'Pima' }),
        facility('A01500', { 'Ownership Type': 'Not Available' }),       // ownership v->null
        facility('061111', { 'Ownership Type': '-' })
      ],
      zips: [zrow('031598', '85016'), zrow('A01500', '85018'), zrow('061111', '85019')] });
    r = runArc(a3, ['--release', '2026-09-30', '--write'], { DATABASE_URL: DB });
    ok(r.status === 0, 'E0. third release ingests', String(r.stderr).slice(0, 300));
    const hA3 = await obsFor('A01500');
    ok(hA3.length === 3 && hA3[1].ownershipType === 'For-Profit' && hA3[2].ownershipType === null,
       'E1. ownership value->null: prior value preserved, null preserved exactly as published');
    const h5983 = await obsFor('031598');
    ok(h5983.length === 3 && h5983[1].name === 'HOSPICE 031598' && h5983[2].name === 'RENAMED HOSPICE',
       'F1. name change: both values preserved');
    ok(h5983[1].address === '1 MAIN ST' && h5983[2].address === '99 OTHER AVE'
       && h5983[1].city === 'PHOENIX' && h5983[2].city === 'TUCSON'
       && h5983[1].zip === '85016' && h5983[2].zip === '85701',
       'G1. address/city/zip change: both values preserved');
    ok(h5983[1].county === 'MARICOPA' && h5983[2].county === 'Pima',
       'G2. county casing stored VERBATIM (consumers must compare case-insensitively)');

    // ---------- I-J. presence and the gap ----------
    section('I-J. presence history and the R1/R2/R3 gap');
    const a4 = buildArchive({ key: '2026-10-31',
      facilities: [facility('031598'), facility('061111')],             // A01500 absent
      zips: [zrow('031598', '85016'), zrow('061111', '85019')] });
    r = runArc(a4, ['--release', '2026-10-31', '--write'], { DATABASE_URL: DB });
    ok(r.status === 0, 'I0. fourth release ingests', String(r.stderr).slice(0, 300));
    const hA4 = await obsFor('A01500');
    ok(hA4.length === 3, 'I1. absent facility gains NO new observation', `got ${hA4.length}`);
    ok(!hA4.some((o) => o.releaseKey === '2026-10-31'), 'I2. no observation exists for the release it was absent from');
    ok(hA4[0].releaseKey === '2026-05-01', 'I3. its earlier observations remain');
    ok((await prisma.cmsFacility.findFirst({ where: { ccn: 'A01500' } })) !== null,
       'I4. the current-state row is still retained (existing behaviour unchanged)');

    const a5 = buildArchive({ key: '2026-11-30',
      facilities: [facility('031598'), facility('061111'), facility('A01500', { 'Ownership Type': 'Other' })],
      zips: [zrow('031598', '85016'), zrow('061111', '85019'), zrow('A01500', '85018')] });
    r = runArc(a5, ['--release', '2026-11-30', '--write'], { DATABASE_URL: DB });
    ok(r.status === 0, 'J0. fifth release ingests (facility reappears)', String(r.stderr).slice(0, 300));
    const hA5 = await obsFor('A01500');
    const keys = hA5.map((o) => o.releaseKey);
    ok(keys.includes('2026-05-01') && keys.includes('2026-11-30'), 'J1. observations exist for the present releases');
    ok(!keys.includes('2026-10-31'), 'J2. NO observation for the release it was absent from');
    ok(keys.length === 4, 'J3. exactly 4 observations across 5 releases — the GAP is representable', JSON.stringify(keys));
    {
      const cur = await prisma.cmsFacility.findFirst({ where: { ccn: 'A01500' } });
      const first = await relByKey('2026-05-01');
      ok(cur.firstSeenReleaseId === first.id,
         'J4. current-state firstSeen still points at R1 — proving brackets ALONE cannot express the gap');
    }

    // ---------- K. idempotent rerun ----------
    section('K. same-release rerun');
    const before = await prisma.cmsFacilityObservation.count();
    r = runArc(a5, ['--release', '2026-11-30', '--write'], { DATABASE_URL: DB });
    ok(r.status === 0, 'K1. rerunning the same release succeeds', String(r.stderr).slice(0, 300));
    const after = await prisma.cmsFacilityObservation.count();
    ok(after === before, 'K2. observation count unchanged — rerun created no duplicates', `${before} -> ${after}`);

    // ---------- L. chronology guard ----------
    section('L. older-release ingest still refused');
    const older = buildArchive({ key: '2026-06-15',
      facilities: [facility('031598')], zips: [zrow('031598', '85016')] });
    r = runArc(older, ['--release', '2026-06-15', '--write'], { DATABASE_URL: DB });
    ok(r.status !== 0, 'L1. an older release is rejected by the normal path');
    ok(/CHRONOLOGY VIOLATION/.test(r.stdout + r.stderr), 'L2. refused with the chronology message');
    ok((await prisma.cmsFacilityObservation.count()) === after, 'L3. the refused run wrote no observations');
    ok(!(await relByKey('2026-06-15')), 'L4. no CmsRelease row was created for the refused release');

    // ---------- N/O. constraints ----------
    section('N-O. database-enforced constraints');
    {
      const f = await prisma.cmsFacility.findFirst({ where: { ccn: '031598' } });
      const rel = await relByKey('2026-11-30');
      let threw = null;
      try {
        await prisma.$executeRawUnsafe(
          `INSERT INTO "CmsFacilityObservation" ("id","facilityId","source","releaseId","ccn","name","address","city","state","zip","createdAt")
           VALUES ($1,$2,$3,$4,$5,'X','X','X','AZ','85016',NOW())`,
          crypto.randomUUID(), f.id, DB_SOURCE, rel.id, '031598');
      } catch (e) { threw = e; }
      ok(threw !== null, 'O1. a duplicate (facilityId, releaseId) is refused by the DB, not by app logic');
      // Assert the SQLSTATE, not prose: 23505 is unique_violation. Prisma reports it
      // as `Code: 23505 ... already exists`, which no word-match would reliably catch.
      ok(threw && /Code: `?23505`?/.test(threw.message),
         'O2. …and it is specifically SQLSTATE 23505 (unique_violation)', String(threw && threw.message).slice(0, 160));
      ok(threw && /\("facilityId", "releaseId"\)/.test(threw.message),
         'O2b. …raised by the (facilityId, releaseId) key specifically');
    }
    {
      // Source isolation: an observation may not claim a source its release lacks.
      const f = await prisma.cmsFacility.findFirst({ where: { ccn: '031598' } });
      const rel = await relByKey('2026-11-30');
      let threw = null;
      try {
        await prisma.$executeRawUnsafe(
          `INSERT INTO "CmsFacilityObservation" ("id","facilityId","source","releaseId","ccn","name","address","city","state","zip","createdAt")
           VALUES ($1,$2,'cms_home_health',$3,$4,'X','X','X','AZ','85016',NOW())`,
          crypto.randomUUID(), f.id, rel.id, '031598');
      } catch (e) { threw = e; }
      ok(threw !== null, 'N-DB1. cross-source observation refused by the composite FK');
      const bad = await prisma.$queryRawUnsafe(
        `SELECT count(*)::int AS n FROM "CmsFacilityObservation" o
         JOIN "CmsFacility" f ON f.id = o."facilityId" WHERE f.source <> o.source`);
      ok(Number(bad[0].n) === 0, 'N-DB2. no observation disagrees with its facility source');
      const bad2 = await prisma.$queryRawUnsafe(
        `SELECT count(*)::int AS n FROM "CmsFacilityObservation" o
         JOIN "CmsRelease" r ON r.id = o."releaseId" WHERE r.source <> o.source`);
      ok(Number(bad2[0].n) === 0, 'N-DB3. no observation disagrees with its release source');
    }

    // ---------- M. source isolation across families ----------
    section('M. source isolation');
    {
      const perSource = await prisma.$queryRawUnsafe(
        `SELECT source, count(*)::int AS n FROM "CmsFacilityObservation" GROUP BY source`);
      ok(perSource.length === 1 && perSource[0].source === DB_SOURCE,
         'M1. hospice ingestion produced observations for cms_hospice only', JSON.stringify(perSource));
    }

    // ---------- P-T. August baseline seed ----------
    section('P-T. August baseline seed');
    await reset();
    const aug = buildArchive({ key: '2026-08-19',
      facilities: [facility('031598'), facility('A01500', { 'Ownership Type': 'Non-Profit', 'County/Parish': 'Pima' })],
      zips: [zrow('031598', '85016'), zrow('A01500', '85018')] });
    r = runArc(aug, ['--release', '2026-08-19', '--write'], { DATABASE_URL: DB });
    ok(r.status === 0, 'P0. single-release baseline DB prepared', String(r.stderr).slice(0, 300));
    // Remove the importer's own observations so the seed is exercised from scratch.
    await prisma.$executeRawUnsafe('DELETE FROM "CmsFacilityObservation"');
    ok((await prisma.cmsFacilityObservation.count()) === 0, 'P1. observations cleared for the seed test');

    const facBefore = await prisma.$queryRawUnsafe('SELECT md5(string_agg(t::text, \'|\' ORDER BY t.ccn)) AS h FROM "CmsFacility" t');
    const saBefore = await prisma.cmsFacilityServiceArea.count();
    const measBefore = await prisma.cmsFacilityMeasure.count();
    const provBefore = await prisma.provider.count();

    let s = runSeed(['--database-url', DB]);
    ok(s.status === 0, 'P2. seed dry run succeeds', String(s.stderr).slice(0, 300));
    ok(/DRY RUN complete\. ZERO writes/.test(s.stdout), 'P3. dry run is the default and writes nothing');
    ok((await prisma.cmsFacilityObservation.count()) === 0, 'P4. dry run wrote no observations');

    s = runSeed(['--database-url', DB, '--write']);
    ok(s.status === 0, 'P5. seed --write succeeds', String(s.stderr).slice(0, 400));
    const seeded = await prisma.cmsFacilityObservation.count();
    ok(seeded === 2, 'P6. observation count equals the eligible CmsFacility count', `got ${seeded}`);
    {
      const sa = (await obsFor('A01500'))[0];
      ok(sa.ownershipType === 'Non-Profit' && sa.county === 'Pima' && sa.city === 'PHOENIX' && sa.zip === '85016',
         'P7. seeded values equal current CmsFacility values exactly');
      const rel = await relByKey('2026-08-19');
      ok(sa.releaseId === rel.id, 'P8. seeded observations point at the 2026-08-19 release');
      ok(sa.source === DB_SOURCE, 'P9. seeded observations carry the right source');
    }

    s = runSeed(['--database-url', DB, '--write']);
    ok(s.status === 0, 'Q1. seed rerun succeeds');
    ok((await prisma.cmsFacilityObservation.count()) === 2, 'Q2. seed rerun is idempotent — still 2 observations');

    const facAfter = await prisma.$queryRawUnsafe('SELECT md5(string_agg(t::text, \'|\' ORDER BY t.ccn)) AS h FROM "CmsFacility" t');
    ok(facBefore[0].h === facAfter[0].h, 'S1. seed did NOT mutate any CmsFacility row (full-row checksum identical)');
    ok((await prisma.cmsFacilityServiceArea.count()) === saBefore, 'T1. seed did not mutate CmsFacilityServiceArea');
    ok((await prisma.cmsFacilityMeasure.count()) === measBefore, 'T2. seed did not mutate CmsFacilityMeasure');
    ok((await prisma.provider.count()) === provBefore, 'T3. seed did not mutate Provider');

    // R. refusals
    section('R. seed refusals');
    s = runSeed([]);
    ok(s.status !== 0 && /--database-url is required/.test(s.stderr), 'R1. refuses without an explicit --database-url');
    s = runSeed(['--database-url', 'postgresql://u@x.neon.tech/db']);
    ok(s.status !== 0 && /unrecognised hosted/.test(s.stderr), 'R2. refuses an unrecognised hosted target before connecting');
    {
      // Two releases -> the single-release precondition must fail closed.
      const nxt = buildArchive({ key: '2026-12-31',
        facilities: [facility('031598'), facility('A01500')],
        zips: [zrow('031598', '85016'), zrow('A01500', '85018')] });
      const rr = runArc(nxt, ['--release', '2026-12-31', '--write'], { DATABASE_URL: DB });
      ok(rr.status === 0, 'R3. a second release ingests (setting up the refusal)');
      s = runSeed(['--database-url', DB, '--write']);
      ok(s.status !== 0, 'R4. seed REFUSES once more than one release exists');
      ok(/exactly one ingested release/.test(s.stderr), 'R5. …and explains why a DB-derived baseline is then unsound');
    }
    {
      await reset();
      s = runSeed(['--database-url', DB, '--write']);
      ok(s.status !== 0 && /no cms_hospice CmsRelease with releaseKey 2026-08-19/.test(s.stderr),
         'R6. seed refuses when the expected baseline release is missing');
    }
    {
      // A release exists but is the wrong key.
      const wrong = buildArchive({ key: '2026-07-01',
        facilities: [facility('031598')], zips: [zrow('031598', '85016')] });
      const rr = runArc(wrong, ['--release', '2026-07-01', '--write'], { DATABASE_URL: DB });
      ok(rr.status === 0, 'R7. a non-baseline release ingests');
      s = runSeed(['--database-url', DB, '--write']);
      ok(s.status !== 0 && /releaseKey 2026-08-19 exists/.test(s.stderr), 'R8. seed refuses the wrong release key');
    }

    await reset();
  } catch (e) {
    console.log('  FAIL   database phase threw: ' + (e.message || e)); fail++;
  } finally {
    await prisma.$disconnect();
  }
  finish();
})();

function finish() {
  console.log(`\n${fail ? 'FAILED' : 'PASSED'} — ${pass} passed, ${fail} failed`);
  process.exit(fail ? 1 : 0);
}
