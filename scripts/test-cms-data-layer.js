#!/usr/bin/env node
/**
 * Invariant and fixture tests for the CMS data layer foundation:
 * CmsRelease, CmsFacility, CmsFacilityServiceArea.
 *
 * Requires a DISPOSABLE local database with the active migration chain applied.
 * Refuses anything that looks like production. Truncates the Cms* tables it uses.
 *
 *   TEST_DATABASE_URL=postgresql://user@localhost:5432/bh_cmslayer_test \
 *     node scripts/test-cms-data-layer.js
 */
const fs = require('fs');
const path = require('path');
const zlib = require('zlib');

const ROOT = path.join(__dirname, '..');
const DB = process.env.TEST_DATABASE_URL;
const SRC_HOSPICE = 'cms_hospice';
const SRC_HOME = 'cms_home_health';

let pass = 0, fail = 0;
const ok = (c, label, detail) => {
  if (c) { pass++; console.log(`    ok   ${label}`); }
  else { fail++; console.log(`  FAIL   ${label}${detail ? `\n           ${detail}` : ''}`); }
};
const section = (t) => console.log(`\n--- ${t} ---`);
const rejects = async (fn) => { try { await fn(); return null; } catch (e) { return e; } };
const isUnique = (e) => e && (e.code === 'P2002' || /unique constraint/i.test(e.message));
const isFk = (e) => e && (e.code === 'P2003' || e.code === 'P2025' || /foreign key/i.test(e.message));

if (!DB) { console.error('TEST_DATABASE_URL is required (a disposable local database).'); process.exit(2); }
if (/besthospice_db|dpg-d5hhmb4hg0os7380cecg-a|besthospice-shadow-2|render\.com|neon\.tech|supabase\.co/i.test(DB)) {
  console.error('TEST_DATABASE_URL looks like production or shadow — refusing.'); process.exit(2);
}

// ---- tiny CSV reader; never coerces a CCN or ZIP ---------------------------
function parseCsv(text) {
  const out = []; let row = [], cur = '', q = false;
  for (let i = 0; i < text.length; i++) { const c = text[i];
    if (q) { if (c === '"') { if (text[i+1] === '"') { cur += '"'; i++; } else q = false; } else cur += c; }
    else if (c === '"') q = true;
    else if (c === ',') { row.push(cur); cur = ''; }
    else if (c === '\n') { row.push(cur); out.push(row); row = []; cur = ''; }
    else if (c !== '\r') cur += c; }
  if (cur !== '' || row.length) { row.push(cur); out.push(row); }
  const head = out.shift();
  return out.filter(r => r.some(v => v !== '')).map(r => Object.fromEntries(head.map((h,i)=>[h, r[i] ?? ''])));
}
const NA = new Set(['', '-', 'Not Available', 'Not Applicable', 'N/A']);
const val = (v) => (NA.has(String(v ?? '').trim()) ? null : String(v).trim());
// CMS publishes MM/DD/YYYY, date-only.
const certDate = (v) => { const s = val(v); if (!s) return null;
  const m = s.match(/^(\d{2})\/(\d{2})\/(\d{4})$/); return m ? new Date(`${m[3]}-${m[1]}-${m[2]}T00:00:00Z`) : null; };

(async () => {
  const { PrismaClient } = require('@prisma/client');
  const prisma = new PrismaClient({ datasources: { db: { url: DB } } });
  // Disposable database: clear everything this test touches so repeated runs are
  // idempotent. Provider/ProviderExternalIdentity are included because the
  // logical-join checks seed them.
  const reset = () => prisma.$executeRawUnsafe(
    'TRUNCATE TABLE "CmsFacilityServiceArea", "CmsFacility", "CmsRelease", '
    + '"ProviderExternalIdentity", "Provider" CASCADE');
  const mkRelease = (source, releaseKey, extra = {}) => prisma.cmsRelease.create({ data: {
    source, releaseKey, capturedAt: new Date('2026-08-27T20:21:08Z'),
    datasetCount: 6, manifestSha256: 'a'.repeat(64), ...extra } });
  const mkFacility = (rel, source, ccn, extra = {}) => prisma.cmsFacility.create({ data: {
    source, ccn, name: 'Test', address: '1 Main', city: 'Phoenix', state: 'AZ', zip: '85016',
    firstSeenReleaseId: rel.id, lastSeenReleaseId: rel.id, ...extra } });

  try {
    // ==================== CmsRelease ====================
    section('CmsRelease invariants');
    await reset();
    const relH = await mkRelease(SRC_HOSPICE, '2026-08-19');
    ok(!!relH.id, 'a release can be created');
    ok(relH.ingestedAt instanceof Date, 'ingestedAt defaults to now()');
    ok(isUnique(await rejects(() => mkRelease(SRC_HOSPICE, '2026-08-19'))),
       'duplicate (source, releaseKey) is REJECTED');
    const relSameKey = await mkRelease(SRC_HOME, '2026-08-19');
    ok(!!relSameKey.id, 'the SAME releaseKey under a DIFFERENT source is allowed');
    ok(relSameKey.source === SRC_HOME, '  …and keeps its own source');
    const relHome = await mkRelease(SRC_HOME, '2026-06-10');
    ok((await prisma.cmsRelease.count()) === 3, 'three releases coexist');

    // ==================== CmsFacility ====================
    section('CmsFacility invariants');
    const f1 = await mkFacility(relH, SRC_HOSPICE, '031598');
    ok(f1.ccn === '031598', 'leading-zero CCN survives exactly', f1.ccn);
    ok(isUnique(await rejects(() => mkFacility(relH, SRC_HOSPICE, '031598'))),
       'duplicate (source, ccn) is REJECTED');
    const f2 = await mkFacility(relHome, SRC_HOME, '031598');
    ok(f2.source === SRC_HOME && f2.ccn === '031598',
       'the SAME ccn under a DIFFERENT source is allowed (namespaces are per-source)');
    const fAlpha = await mkFacility(relH, SRC_HOSPICE, 'A01500');
    ok(fAlpha.ccn === 'A01500', 'ALPHANUMERIC CCN survives (24% of hospice CCNs are A#####)');
    const fZeroZip = await mkFacility(relH, SRC_HOSPICE, '001521', { zip: '01234', state: 'MA' });
    ok(fZeroZip.zip === '01234', 'leading-zero ZIP survives exactly', fZeroZip.zip);
    const counts = await prisma.cmsFacility.groupBy({ by: ['source'], _count: true });
    ok(counts.length === 2, 'hospice and home-health facilities coexist in one table',
       JSON.stringify(counts.map(c => [c.source, c._count])));
    const nullable = await mkFacility(relH, SRC_HOSPICE, '099999',
      { county: null, phone: null, ownershipType: null, certificationDate: null });
    ok(nullable.county === null && nullable.phone === null && nullable.ownershipType === null
       && nullable.certificationDate === null,
       'county/phone/ownershipType/certificationDate are nullable (home health has no county; both use sentinels)');

    // ==================== CmsFacilityServiceArea ====================
    section('CmsFacilityServiceArea invariants');
    const sa = await prisma.cmsFacilityServiceArea.create({ data: {
      facilityId: f1.id, source: f1.source, zip: '85016', firstSeenReleaseId: relH.id, lastSeenReleaseId: relH.id } });
    ok(!!sa.id, 'a service area can be created');
    ok(isUnique(await rejects(() => prisma.cmsFacilityServiceArea.create({ data: {
      facilityId: f1.id, source: f1.source, zip: '85016', firstSeenReleaseId: relH.id, lastSeenReleaseId: relH.id } }))),
       'duplicate (facilityId, zip) is REJECTED');
    await prisma.cmsFacilityServiceArea.create({ data: {
      facilityId: fAlpha.id, source: fAlpha.source, zip: '85016', firstSeenReleaseId: relH.id, lastSeenReleaseId: relH.id } });
    const serving = await prisma.cmsFacilityServiceArea.count({ where: { zip: '85016' } });
    ok(serving === 2, 'the same ZIP may belong to many facilities', String(serving));
    const zsa = await prisma.cmsFacilityServiceArea.create({ data: {
      facilityId: f1.id, source: f1.source, zip: '01234', firstSeenReleaseId: relH.id, lastSeenReleaseId: relH.id } });
    ok(zsa.zip === '01234', 'leading-zero service ZIP survives exactly');
    const mine = await prisma.cmsFacilityServiceArea.count({ where: { facilityId: f1.id } });
    ok(mine === 2, 'a facility may serve many ZIPs', String(mine));

    // ==================== relations ====================
    section('relation integrity and delete protection');
    ok(isFk(await rejects(() => prisma.cmsFacility.create({ data: {
      source: SRC_HOSPICE, ccn: '000001', name: 'x', address: 'x', city: 'x', state: 'AZ', zip: '85016',
      firstSeenReleaseId: '00000000-0000-0000-0000-000000000000', lastSeenReleaseId: relH.id } }))),
      'an invalid firstSeenReleaseId is REJECTED');
    ok(isFk(await rejects(() => prisma.cmsFacility.create({ data: {
      source: SRC_HOSPICE, ccn: '000002', name: 'x', address: 'x', city: 'x', state: 'AZ', zip: '85016',
      firstSeenReleaseId: relH.id, lastSeenReleaseId: '00000000-0000-0000-0000-000000000000' } }))),
      'an invalid lastSeenReleaseId is REJECTED');
    ok(isFk(await rejects(() => prisma.cmsFacilityServiceArea.create({ data: {
      facilityId: '00000000-0000-0000-0000-000000000000', source: SRC_HOSPICE, zip: '85016',
      firstSeenReleaseId: relH.id, lastSeenReleaseId: relH.id } }))),
      'an invalid facilityId is REJECTED');

    const beforeF = await prisma.cmsFacility.count();
    ok(isFk(await rejects(() => prisma.cmsRelease.delete({ where: { id: relH.id } }))),
       'deleting a release referenced by facilities is BLOCKED (history protected)');
    ok((await prisma.cmsFacility.count()) === beforeF, '  …and no facility was removed');
    const beforeSA = await prisma.cmsFacilityServiceArea.count();
    ok(isFk(await rejects(() => prisma.cmsFacility.delete({ where: { id: f1.id } }))),
       'deleting a facility referenced by service areas is BLOCKED');
    ok((await prisma.cmsFacilityServiceArea.count()) === beforeSA, '  …and no service area was removed');
    const relUnused = await mkRelease(SRC_HOSPICE, '2099-01-01');
    await prisma.cmsRelease.delete({ where: { id: relUnused.id } });
    ok(true, 'an unreferenced release CAN be deleted (Restrict, not immovable)');

    // ==================== cross-source integrity ====================
    section('cross-source references are REJECTED by the database');
    ok(isFk(await rejects(() => prisma.cmsFacility.create({ data: {
      source: SRC_HOSPICE, ccn: 'X00001', name: 'x', address: 'x', city: 'x', state: 'AZ', zip: '85016',
      firstSeenReleaseId: relHome.id, lastSeenReleaseId: relHome.id } }))),
      'CASE A: a cms_hospice facility CANNOT reference a cms_home_health release');
    ok(isFk(await rejects(() => prisma.cmsFacility.create({ data: {
      source: SRC_HOSPICE, ccn: 'X00002', name: 'x', address: 'x', city: 'x', state: 'AZ', zip: '85016',
      firstSeenReleaseId: relH.id, lastSeenReleaseId: relHome.id } }))),
      'CASE C: firstSeen and lastSeen releases CANNOT straddle two sources');
    ok(isFk(await rejects(() => prisma.cmsFacilityServiceArea.create({ data: {
      facilityId: f1.id, source: SRC_HOSPICE, zip: '85999',
      firstSeenReleaseId: relHome.id, lastSeenReleaseId: relHome.id } }))),
      'CASE B: a hospice service area CANNOT reference a cms_home_health release');
    ok(isFk(await rejects(() => prisma.cmsFacilityServiceArea.create({ data: {
      facilityId: f1.id, source: SRC_HOME, zip: '85998',
      firstSeenReleaseId: relHome.id, lastSeenReleaseId: relHome.id } }))),
      'a service area CANNOT claim a source different from its facility');
    {
      const okSa = await prisma.cmsFacilityServiceArea.create({ data: {
        facilityId: f2.id, source: f2.source, zip: '99501',
        firstSeenReleaseId: relHome.id, lastSeenReleaseId: relHome.id } });
      ok(okSa.source === SRC_HOME, 'a same-source home-health service area IS accepted');
    }

    // ==================== ProviderExternalIdentity unchanged ====================
    section('ProviderExternalIdentity behaviour is unchanged');
    const cols = await prisma.$queryRawUnsafe(
      `SELECT column_name FROM information_schema.columns WHERE table_name='ProviderExternalIdentity' ORDER BY ordinal_position`);
    ok(cols.length === 10, 'still exactly 10 columns', String(cols.length));
    const fks = await prisma.$queryRawUnsafe(
      `SELECT c.conname FROM pg_constraint c JOIN pg_class t ON t.oid=c.conrelid
       WHERE c.contype='f' AND t.relname='ProviderExternalIdentity'`);
    ok(fks.length === 1 && fks[0].conname === 'ProviderExternalIdentity_providerId_fkey',
       'still exactly ONE foreign key, to Provider — no FK was added to CmsFacility',
       JSON.stringify(fks));
    const p = await prisma.provider.create({ data: { name: 'Fixture Hospice', email: 'f@example.test',
      address: '1 Main', city: 'Phoenix', state: 'AZ', zip: '85016', lat: 33.4, lon: -112, serviceRadiusKm: 40 } });
    const pei = await prisma.providerExternalIdentity.create({ data: {
      providerId: p.id, source: SRC_HOSPICE, externalId: '031598', identifierType: 'ccn',
      confidence: 0.9, verifiedAt: new Date(), verifiedBy: 'test' } });
    ok(pei.externalId === '031598', 'an identity row can still be created with a leading-zero CCN');
    ok(isUnique(await rejects(() => prisma.providerExternalIdentity.create({ data: {
      providerId: p.id, source: SRC_HOSPICE, externalId: '031598', identifierType: 'ccn' } }))),
      'unique (source, externalId) is still enforced');

    // the logical join, exercised without a foreign key
    const joined = await prisma.$queryRawUnsafe(
      `SELECT pei."externalId", f.name AS facility_name
       FROM "ProviderExternalIdentity" pei
       JOIN "CmsFacility" f ON f.source = pei.source AND f.ccn = pei."externalId"`);
    ok(joined.length === 1 && joined[0].externalId === '031598',
       'the LOGICAL join ProviderExternalIdentity(source, externalId) = CmsFacility(source, ccn) resolves');
    const orphan = await prisma.providerExternalIdentity.create({ data: {
      providerId: p.id, source: SRC_HOSPICE, externalId: 'ZZ9999', identifierType: 'ccn' } });
    ok(!!orphan.id,
       'an identity may exist with NO ingested CmsFacility — the reason there is no FK');

    // ==================== fixtures from real CMS files ====================
    section('representative fixtures from real archived CMS files');
    await reset();
    const rH = await mkRelease(SRC_HOSPICE, '2026-08-19');
    const rHH = await mkRelease(SRC_HOME, '2026-06-10');

    const hosp = parseCsv(fs.readFileSync(path.join(ROOT, 'reports/cms-raw/general.csv'), 'utf8'));
    const hrow = hosp.find(r => r['CMS Certification Number (CCN)'] === '031598') || hosp[0];
    const hf = await prisma.cmsFacility.create({ data: {
      source: SRC_HOSPICE, ccn: hrow['CMS Certification Number (CCN)'],
      name: hrow['Facility Name'],
      address: [val(hrow['Address Line 1']), val(hrow['Address Line 2'])].filter(Boolean).join(', '),
      city: hrow['City/Town'], state: hrow['State'], zip: hrow['ZIP Code'].slice(0, 5),
      county: val(hrow['County/Parish']), phone: val(hrow['Telephone Number']),
      ownershipType: val(hrow['Ownership Type']), certificationDate: certDate(hrow['Certification Date']),
      firstSeenReleaseId: rH.id, lastSeenReleaseId: rH.id } });
    console.log(`       hospice  ${hf.ccn}  ${hf.name}`);
    console.log(`                ${hf.address}, ${hf.city}, ${hf.state} ${hf.zip} | ${hf.county} | ${hf.phone}`);
    console.log(`                ownership=${hf.ownershipType} certified=${hf.certificationDate && hf.certificationDate.toISOString().slice(0,10)}`);
    ok(hf.ccn === hrow['CMS Certification Number (CCN)'], 'hospice CCN round-trips byte-identical');
    ok(hf.zip === hrow['ZIP Code'].slice(0,5), 'hospice ZIP round-trips byte-identical');
    ok(hf.certificationDate instanceof Date, 'MM/DD/YYYY parsed into a DATE column');

    const hh = parseCsv(zlib.gunzipSync(fs.readFileSync(
      path.join(ROOT, 'reports/cms-archive/home-health/2026-06-10/agencies.csv.gz'))).toString('utf8'));
    const arow = hh.find(r => r['CMS Certification Number (CCN)'].startsWith('0')) || hh[0];
    const af = await prisma.cmsFacility.create({ data: {
      source: SRC_HOME, ccn: arow['CMS Certification Number (CCN)'],
      name: arow['Provider Name'], address: arow['Address'], city: arow['City/Town'],
      state: arow['State'], zip: arow['ZIP Code'].slice(0, 5),
      county: null,                       // the home-health file has no county column
      phone: val(arow['Telephone Number']), ownershipType: val(arow['Type of Ownership']),
      certificationDate: certDate(arow['Certification Date']),
      firstSeenReleaseId: rHH.id, lastSeenReleaseId: rHH.id } });
    console.log(`       home-hlth ${af.ccn}  ${af.name}`);
    console.log(`                ${af.address}, ${af.city}, ${af.state} ${af.zip} | county=${af.county} | ${af.phone}`);
    console.log(`                ownership=${af.ownershipType} certified=${af.certificationDate && af.certificationDate.toISOString().slice(0,10)}`);
    ok(af.ccn === arow['CMS Certification Number (CCN)'] && af.ccn.startsWith('0'),
       'home-health leading-zero CCN round-trips byte-identical');
    ok(af.county === null, 'home-health county is null (no such column in the source)');
    ok(af.source !== hf.source && (await prisma.cmsFacility.count()) === 2,
       'both families coexist with independent sources');

    const zips = parseCsv(fs.readFileSync(path.join(ROOT, 'reports/cms-raw/zip.csv'), 'utf8'))
      .filter(r => r['CMS Certification Number (CCN)'] === hf.ccn).slice(0, 25);
    for (const z of zips) {
      await prisma.cmsFacilityServiceArea.create({ data: {
        facilityId: hf.id, source: hf.source, zip: z['ZIP Code'].slice(0, 5),
        firstSeenReleaseId: rH.id, lastSeenReleaseId: rH.id } });
    }
    const stored = await prisma.cmsFacilityServiceArea.findMany({ where: { facilityId: hf.id }, orderBy: { zip: 'asc' } });
    console.log(`       service ZIPs for ${hf.ccn}: ${stored.length} -> ${stored.slice(0,8).map(s=>s.zip).join(', ')}…`);
    ok(stored.length === zips.length && zips.length > 0, `${zips.length} real service ZIPs stored`);
    ok(stored.every(s => s.zip.length === 5), 'every stored ZIP is 5 characters');
    ok(stored.map(s => s.zip).sort().join() === zips.map(z => z['ZIP Code'].slice(0,5)).sort().join(),
       'service ZIPs round-trip byte-identical');
    const q = await prisma.cmsFacilityServiceArea.findMany({ where: { zip: stored[0].zip }, include: { facility: true } });
    ok(q.length >= 1 && q[0].facility.ccn === hf.ccn, '"which facilities serve ZIP X" resolves through the relation');

    section('current vs historical service-area semantics (no `active` flag)');
    {
      const rH2 = await mkRelease(SRC_HOSPICE, '2026-11-01');
      await prisma.cmsFacility.update({ where: { id: hf.id }, data: { lastSeenReleaseId: rH2.id } });
      const latest = await prisma.cmsRelease.findFirst({ where: { source: SRC_HOSPICE }, orderBy: { releaseKey: 'desc' } });
      ok(latest.releaseKey === '2026-11-01', 'the latest release for a source is identifiable by releaseKey');
      const cur = await prisma.cmsFacilityServiceArea.count({
        where: { source: SRC_HOSPICE, zip: stored[0].zip, lastSeenReleaseId: latest.id } });
      const hist = await prisma.cmsFacilityServiceArea.count({
        where: { source: SRC_HOSPICE, zip: stored[0].zip, NOT: { lastSeenReleaseId: latest.id } } });
      ok(cur === 0 && hist === 1, 'a service area not refreshed in the latest release reads as HISTORICAL',
         `current=${cur} historical=${hist}`);
      await prisma.cmsFacilityServiceArea.updateMany({ where: { facilityId: hf.id }, data: { lastSeenReleaseId: rH2.id } });
      const cur2 = await prisma.cmsFacilityServiceArea.count({
        where: { source: SRC_HOSPICE, zip: stored[0].zip, lastSeenReleaseId: latest.id } });
      ok(cur2 === 1, 'once refreshed in the latest release it reads as CURRENT again');
    }
  } finally {
    await prisma.$disconnect().catch(() => {});
  }

  console.log(`\n${'='.repeat(60)}`);
  console.log(fail === 0 ? `PASSED — ${pass} assertions` : `FAILED — ${fail} of ${pass + fail} assertions failed`);
  process.exit(fail === 0 ? 0 : 1);
})().catch((e) => { console.error('\ntest harness failed:', e.message); process.exit(1); });
