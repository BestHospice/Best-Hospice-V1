#!/usr/bin/env node
/**
 * Guards Competitor Intelligence V1 Phase A — the competitor landscape service.
 *
 * Overlap arithmetic, ordering, quality-availability counting, partner-badge
 * suppression and query boundedness are proven against real rows in a disposable
 * PostgreSQL database. Module-level invariants that cannot be observed from the
 * outside (no writes, no consumer-routing dependency, no fuzzy matching, no
 * proprietary score field) are proven by source inspection.
 *
 * Every CCN, ZIP, provider and facility name here is SYNTHETIC. CCN 121509,
 * ISLANDS HOSPICE, Vrablic's Home and the Hawaii account appear nowhere.
 *
 *   TEST_DATABASE_URL=postgresql://user@localhost:5432/bh_competitors_test \
 *     node scripts/test-cms-hospice-competitors.js
 */
const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const SRC = fs.readFileSync(path.join(ROOT, 'cms-hospice-competitors.js'), 'utf8');
// Comments are stripped before any pattern match. Otherwise this suite would be
// asserting against its own module's prose instead of its behaviour.
const CODE = SRC.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '');
const MREG = require(path.join(ROOT, 'data', 'cms-hospice-quality-measures.json'));
// The partner rule now lives in ONE module. Its structural guarantees are
// asserted where the rule actually is, not where it used to be inlined.
const BADGE_SRC = fs.readFileSync(path.join(ROOT, 'cms-partner-badge.js'), 'utf8');
const BADGE_CODE = BADGE_SRC.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '');
const { buildProviderCmsCompetitors, CMS_COMPETITOR_STATUS: S, COMPETITOR_SOURCE } =
  require(path.join(ROOT, 'cms-hospice-competitors.js'));
const { buildProviderCmsMarket } = require(path.join(ROOT, 'cms-hospice-market.js'));

let pass = 0, fail = 0;
const ok = (c, label, detail) => {
  console.log(`  ${c ? 'ok  ' : 'FAIL'} ${label}${c || !detail ? '' : `  — ${detail}`}`);
  c ? pass++ : fail++;
};
const section = (t) => console.log(`\n--- ${t} ---`);

// Every key in a nested structure, so forbidden FIELDS are caught by name rather
// than by substring. Disclaimer prose is allowed to contain the word "score";
// a field called score is not.
const allKeys = (v, out = new Set()) => {
  if (Array.isArray(v)) v.forEach((x) => allKeys(x, out));
  else if (v && typeof v === 'object') {
    for (const k of Object.keys(v)) { out.add(k); allKeys(v[k], out); }
  }
  return out;
};

// The 5-key contract, written out here INDEPENDENTLY of the implementation so
// the assertion is a real check and not a restatement of the code under test.
const contractOrder = (list) => list.slice().sort((a, b) =>
  b.sharedZipCount - a.sharedZipCount
  || b.providerOverlapPct - a.providerOverlapPct
  || b.competitorOverlapPct - a.competitorOverlapPct
  || a.name.localeCompare(b.name)
  || a.ccn.localeCompare(b.ccn));

// ============================ STATIC AUDIT ===================================
section('A. reuse, isolation and safety by construction');
{
  ok(/require\('\.\/cms-hospice-market'\)/.test(CODE),
     'A1. the service REUSES cms-hospice-market as the single market definition');
  ok(/buildProviderCmsMarket\(prisma, providerId\)/.test(CODE),
     'A2. …and calls it rather than reimplementing the overlap query');
  ok(!/CmsFacilityServiceArea/.test(CODE),
     'A3. it never re-derives service-area overlap itself');
  ok(!/require\('\.\/server/.test(CODE) && !/require\('\.\.\/server/.test(CODE),
     'A4. it does not import server.js');
  for (const dep of ['consumer-lead-eligibility', 'cms-provider-resolver', 'cms-hospice-quality']) {
    ok(!new RegExp(`require\\('\\./${dep}'\\)`).test(CODE), `A5. no direct dependency on ${dep}`);
  }
  const requires = (CODE.match(/require\('[^']+'\)/g) || []).sort();
  ok(JSON.stringify(requires) === JSON.stringify(
       ["require('./cms-hospice-market')", "require('./cms-partner-badge')"]),
     'A6. exactly two dependencies — the market definition and the partner rule',
     requires.join(' '));

  for (const [re, label] of [
    [/serviceRadiusKm|serviceZipCodes|haversine|distance|mileage/, 'no distance/radius/coverage logic'],
    [/billingMode|subscriptionStatus|planTier|stripe|receiveClientLeads/i, 'no billing, plan or lead input'],
    [/ownershipType/, 'no ownership data in V1'],
    [/INSERT|UPDATE|DELETE|TRUNCATE|\.create\(|\.update\(|\.delete\(|\.upsert\(|executeRaw/,
      'no writes of any kind']
  ]) ok(!re.test(CODE), `A7. ${label}`);

  // Matching predicates are audited where they actually live - inside the SQL
  // text and inside the Prisma filter. A blanket search over the whole module
  // would trip on `name: c.name`, which PROJECTS a name rather than matching on
  // one, and would pass while proving nothing.
  const SQL = (SRC.match(/\$queryRaw`([\s\S]*?)`/) || ['', ''])[1];
  // The partner filter is audited where the rule now lives.
  const PARTNER = (BADGE_SRC.match(/prisma\.providerExternalIdentity\.findMany\(\{[\s\S]*?\n  \}\);/) || [''])[0];
  ok(SQL.length > 200 && PARTNER.length > 100,
     'A7b. both query sites were located for auditing', `sql ${SQL.length} / partner ${PARTNER.length}`);
  for (const [re, label] of [
    [/ILIKE|similarity|levenshtein|soundex|~\*/i, 'no fuzzy SQL matching'],
    [/f\.name/, 'the enrichment query never matches on facility name'],
    [/f\.city|f\.state/, 'the enrichment query never matches on city or state'],
    [/f\.zip\s*=|sa\.zip/, 'the enrichment query never matches on ZIP']
  ]) ok(!re.test(SQL), `A7c. ${label}`);
  ok(/WHERE f\.source = \$\{source\} AND f\.ccn = ANY\(\$\{ccns\}::text\[\]\)/.test(SQL),
     'A7d. competitor facilities are selected by (source, ccn) and nothing else');
  ok(!/name|city|state|\bzip\b|lat|lon|radius/i.test(PARTNER),
     'A7e. the partner lookup never matches on name, city, state or ZIP');

  for (const bad of ['121509', 'ISLANDS HOSPICE', 'c3f7379c', 'Vrablic', 'besthospice_db', 'dpg-']) {
    ok(!SRC.includes(bad), `A8. no production identifier "${bad}"`);
  }
  ok(/COMPETITOR_SOURCE = 'cms_hospice'/.test(CODE), 'A9. the source is pinned to cms_hospice');

  ok(!/for\s*\([^)]*\)\s*\{[^}]*await prisma/.test(CODE)
     && !/\.map\(\s*async/.test(CODE)
     && !/forEach\(\s*async/.test(CODE)
     && !/while\s*\([^)]*\)\s*\{[^}]*await prisma/.test(CODE),
     'A10. no query inside any loop — N+1 is structurally impossible');
  const raws = (CODE.match(/prisma\.\$queryRaw/g) || []).length;
  const finds = (CODE.match(/prisma\.\w+\.findMany|prisma\.\w+\.findFirst|prisma\.\w+\.findUnique|prisma\.\w+\.count/g) || []).length;
  ok(raws === 1, 'A11. exactly ONE bulk enrichment SQL query', String(raws));
  // The partner lookup is now the shared rule's single query, not a second copy
  // of it living here.
  ok(finds === 0, 'A12. no independent Prisma model access remains in this service', String(finds));
  ok(!/providerExternalIdentity/i.test(CODE),
     'A12b. …and no independent ProviderExternalIdentity partner query at all');
  ok((CODE.match(/verifiedPartnerCcns\(prisma, source, ccns\)/g) || []).length === 1,
     'A12c. …the badge is resolved by the SHARED rule, once, in bulk');
  ok((BADGE_CODE.match(/prisma\.\w+\.findMany/g) || []).length === 1,
     'A13. the shared rule contributes exactly one bounded round trip',
     String((BADGE_CODE.match(/prisma\.\w+\.findMany/g) || []).length));
  ok(raws + 1 === 2, 'A13b. so the service still costs exactly 2 round trips of its own');
  ok(!/\$queryRawUnsafe|queryRawUnsafe/.test(CODE),
     'A14. parameterised tagged templates only — no queryRawUnsafe');
  const interpolated = new Set(
    (SRC.match(/\$queryRaw`[\s\S]*?`/g) || []).join('').match(/\$\{[^}]+\}/g) || []);
  ok([...interpolated].every((x) => /^\$\{(source|ccns)\}$/.test(x)),
     'A15. only source and ccns are interpolated, both as bound parameters', [...interpolated].join(' '));

  ok(/m\.suppressed\s*=\s*FALSE/.test(CODE) && /m\."valueNumeric"\s+IS NOT NULL/.test(CODE),
     'A16. "published" uses the existing Quality semantics (not suppressed AND value present)');
  ok(/d\.surfaced\s*=\s*TRUE/.test(CODE), 'A17. only surfaced measures are counted');
  ok(/ORDER BY r\."releaseKey" DESC/.test(CODE) && /EXISTS \(/.test(CODE),
     'A18. the newest release CONTAINING measurements is selected, not simply the newest');
  ok(!/\.sort\(/.test(CODE), 'A19. the service never re-sorts — My Market ordering is preserved');
  ok(/verifiedAt: \{ not: null \}/.test(BADGE_CODE),
     'A20. the shared rule requires a human-accepted identity');
  ok(/provider: \{ internalRole: null \}/.test(BADGE_CODE),
     'A21. …and excludes internal accounts IN SQL');
  ok(/IDENTIFIER_TYPE_BY_SOURCE = Object\.freeze\(\{ cms_hospice: 'ccn' \}\)/.test(BADGE_CODE)
     && /identifierType,/.test(BADGE_CODE),
     'A22. …scoped to the CCN identifier this source publishes');
  ok(/select: \{ externalId: true \}/.test(BADGE_CODE),
     'A23. …projecting externalId ONLY — no Provider field can leak');
  ok((BADGE_CODE.match(/require\(/g) || []).length === 0,
     'A23b. …from a pure leaf module with zero dependencies');
  ok(!/INSERT|UPDATE|DELETE|\.create\(|\.update\(|\.delete\(/.test(BADGE_CODE),
     'A23c. …that is read-only');
  ok(/require\('\.\/cms-partner-badge'\)/.test(
       fs.readFileSync(path.join(ROOT, 'cms-hospice-competitor-detail.js'), 'utf8')),
     'A23d. …and the head-to-head detail service resolves the badge through the SAME rule');
  ok(!/sharedZips/.test(CODE.replace(/sharedZipCount/g, '')),
     'A24. sharedZips is never read into the landscape output');
  for (const forbidden of ['score', 'rank', 'ranking', 'grade', 'percentile', 'marketShare',
                           'patientVolume', 'referralVolume', 'revenue', 'utilization', 'composite']) {
    ok(!new RegExp(`\\b${forbidden}\\s*:`, 'i').test(CODE),
       `A25. no "${forbidden}" field is produced`);
  }
}

// ============================ DATABASE BEHAVIOUR =============================
const DB = process.env.TEST_DATABASE_URL;
(async () => {
  if (!DB) { console.log('\n--- database tests SKIPPED (set TEST_DATABASE_URL) ---'); return finish(); }
  if (/besthospice_db|besthospice_shadow|render\.com|dpg-/i.test(DB)) {
    console.log('  FAIL   TEST_DATABASE_URL looks like production or shadow'); fail++; return finish();
  }
  const { PrismaClient } = require('@prisma/client');
  const prisma = new PrismaClient({ datasources: { db: { url: DB } } });
  const uuid = () => require('crypto').randomUUID();

  const SRC_NAME = COMPETITOR_SOURCE;
  const OTHER_SRC = 'cms_home_health';
  const R_OLD = 'rel-c-2026-07-01';   // has measurements
  const R_MID = 'rel-c-2026-08-19';   // has measurements — the quality release
  const R_NEW = 'rel-c-2026-09-01';   // roster only, NO measurements
  const CODES = MREG.measures.map((m) => m.measureCode);
  const UNSURFACED = 'X_UNSURFACED_01';

  const clean = () => prisma.$executeRawUnsafe(
    'TRUNCATE TABLE "CmsFacilityMeasure","CmsMeasureDefinition","CmsFacilityServiceArea","CmsFacility",'
    + '"CmsRelease","ProviderExternalIdentity","Provider" CASCADE');

  const release = (id, key, src = SRC_NAME) => prisma.$executeRawUnsafe(
    `INSERT INTO "CmsRelease" ("id","source","releaseKey","capturedAt","ingestedAt","datasetCount")
     VALUES ($1,$2,$3,($3||'T00:00:00Z')::timestamptz,NOW(),6)`, id, src, key);

  const definitions = async () => {
    for (const m of MREG.measures) {
      await prisma.$executeRawUnsafe(
        `INSERT INTO "CmsMeasureDefinition" ("id","source","measureCode","cmsMeasureName","shortLabel",
           "dimension","family","valueKind","direction","scaleMin","scaleMax","decimals","unitLabel",
           "denominatorCode","surfaced","createdAt","updatedAt")
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,TRUE,NOW(),NOW())`,
        uuid(), SRC_NAME, m.measureCode, m.cmsMeasureName, m.shortLabel, m.dimension,
        m.family, m.valueKind, m.direction, m.scaleMin, m.scaleMax, m.decimals, m.unitLabel,
        m.denominatorCode);
    }
    // A definition CMS publishes but Best Hospice does not surface. It must not
    // move surfacedMeasureCount and its values must not be counted as published.
    await prisma.$executeRawUnsafe(
      `INSERT INTO "CmsMeasureDefinition" ("id","source","measureCode","cmsMeasureName","shortLabel",
         "dimension","family","valueKind","direction","decimals","surfaced","createdAt","updatedAt")
       VALUES ($1,$2,$3,'Synthetic unsurfaced measure','Unsurfaced','other','other','percent',
               'higher_better',1,FALSE,NOW(),NOW())`, uuid(), SRC_NAME, UNSURFACED);
  };

  const facility = async (ccn, name, zips, opts = {}) => {
    const src = opts.source || SRC_NAME;
    const first = opts.firstSeen || (src === SRC_NAME ? R_OLD : 'rel-c-hh');
    const last = opts.lastSeen || (src === SRC_NAME ? R_NEW : 'rel-c-hh');
    const id = `fac-${src}-${ccn}`;
    await prisma.$executeRawUnsafe(
      `INSERT INTO "CmsFacility" ("id","source","ccn","name","address","city","state","zip",
         "firstSeenReleaseId","lastSeenReleaseId","createdAt","updatedAt")
       VALUES ($1,$2,$3,$4,'1 Synthetic Rd',$5,'ZZ',$6,$7,$8,NOW(),NOW())`,
      id, src, ccn, name, opts.city || 'Testville', opts.zip || '90001', first, last);
    for (const z of zips) {
      await prisma.$executeRawUnsafe(
        `INSERT INTO "CmsFacilityServiceArea" ("id","facilityId","source","zip",
           "firstSeenReleaseId","lastSeenReleaseId","createdAt")
         VALUES ($1,$2,$3,$4,$5,$5,NOW())`, uuid(), id, src, z, first);
    }
    return id;
  };

  // value === null AND suppressed === false  -> CMS published nothing usable
  // value !== null AND suppressed === true   -> CMS withheld it despite a value
  // Both must be excluded from publishedMeasureCount, and for different reasons.
  const measure = (facId, code, value, suppressed, releaseId = R_MID) => prisma.$executeRawUnsafe(
    `INSERT INTO "CmsFacilityMeasure" ("id","facilityId","source","measureCode","releaseId",
       "valueNumeric","valueRaw","suppressed","footnoteCodes","createdAt","updatedAt")
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9::text[],NOW(),NOW())`,
    uuid(), facId, SRC_NAME, code, releaseId,
    value, value === null ? 'Not Available' : String(value), suppressed, suppressed ? ['1'] : []);

  const provider = (id, over = {}) => prisma.$executeRawUnsafe(
    `INSERT INTO "Provider" ("id","name","email","address","city","state","zip","lat","lon",
       "serviceRadiusKm","careType","internalRole","createdAt","updatedAt")
     VALUES ($1,$2,$3,'1 Main St',$4,'ZZ',$5,33,-112,100,$6,$7,NOW(),NOW())`,
    id, over.name || `Provider ${id}`, `${id}@example.test`, over.city || 'Testville',
    over.zip || '90001', over.careType || 'hospice', over.internalRole || null);

  const identity = (providerId, ccn, over = {}) => prisma.$executeRawUnsafe(
    `INSERT INTO "ProviderExternalIdentity" ("id","providerId","source","externalId","identifierType",
       "verifiedAt","verifiedBy","createdAt","updatedAt")
     VALUES ($1,$2,$3,$4,$5,$6,'test-suite',NOW(),NOW())`,
    uuid(), providerId, SRC_NAME, ccn,
    over.identifierType === undefined ? 'ccn' : over.identifierType,
    over.verifiedAt === undefined ? new Date('2026-08-31T00:00:00Z') : over.verifiedAt);

  const rowCounts = async () => {
    const [r] = await prisma.$queryRawUnsafe(
      `SELECT (SELECT count(*) FROM "CmsFacility")::int a,
              (SELECT count(*) FROM "CmsFacilityServiceArea")::int b,
              (SELECT count(*) FROM "CmsFacilityMeasure")::int c,
              (SELECT count(*) FROM "CmsMeasureDefinition")::int d,
              (SELECT count(*) FROM "Provider")::int e,
              (SELECT count(*) FROM "ProviderExternalIdentity")::int f,
              (SELECT count(*) FROM "CmsRelease")::int g`);
    return JSON.stringify(r);
  };

  try {
    // ===================== B. main fixture ==============================
    await clean();
    await release(R_OLD, '2026-07-01'); await release(R_MID, '2026-08-19');
    await release(R_NEW, '2026-09-01'); await release('rel-c-hh', '2026-08-19', OTHER_SRC);
    await definitions();

    const OWN = 'X80000', B = 'X80002', C = 'X80003', D = 'X80004', E = 'X80005';
    const T1 = 'X80006', T2 = 'X80007';
    const ownId = await facility(OWN, 'OWN HOSPICE', ['71111', '71112', '71113', '71114']);
    const bId = await facility(B, 'BRAVO HOSPICE', ['71111', '71112', '71113'], { zip: '90002' });
    const cId = await facility(C, 'CHARLIE HOSPICE', ['71113', '71114', '72222'], { zip: '90003' });
    await facility(D, 'DELTA HOSPICE', ['73333']);                        // no shared ZIP
    await facility(E, 'ECHO OTHER SOURCE', ['71111', '71112'], { source: OTHER_SRC });
    const t1Id = await facility(T1, 'IDENTICAL NAME HOSPICE', ['71111']);
    const t2Id = await facility(T2, 'IDENTICAL NAME HOSPICE', ['71111']);

    // Quality availability fixture, all on R_MID unless stated.
    for (const code of CODES) await measure(bId, code, 50, false);        // 10 published
    await measure(bId, UNSURFACED, 50, false);                            // must not count
    for (const code of CODES.slice(0, 4)) await measure(cId, code, 50, false);   // 4 published
    for (const code of CODES.slice(4, 6)) await measure(cId, code, 99, true);    // suppressed WITH a value
    await measure(cId, CODES[6], null, false);                            // no value, not suppressed
    // Same hospice, OLDER release, nearly everything published. If the service
    // read the wrong release C would look like 9 of 10.
    for (const code of CODES.slice(0, 9)) await measure(cId, code, 50, false, R_OLD);
    for (const code of CODES.slice(0, 3)) await measure(ownId, code, 50, false);

    await provider('p-own'); await identity('p-own', OWN);
    // Partner badge fixture.
    await provider('p-partner', { name: 'Bravo Partner Org' }); await identity('p-partner', B);
    await provider('p-unver'); await identity('p-unver', C, { verifiedAt: null });
    await provider('p-internal', { name: 'internal reference', internalRole: 'cms_reference' });
    await identity('p-internal', T1);
    // Exact name/city/ZIP twin of T2's facility, with NO identity row at all.
    await provider('p-lookalike', { name: 'IDENTICAL NAME HOSPICE', city: 'Testville', zip: '90001' });

    const r = await buildProviderCmsCompetitors(prisma, 'p-own');
    const m = await buildProviderCmsMarket(prisma, 'p-own');
    const byCcn = new Map(r.competitors.map((x) => [x.ccn, x]));

    section('B. market identity — one definition of "competitor"');
    ok(r.status === S.RESOLVED, '1a. the landscape resolves', r.status);
    ok(JSON.stringify(r.competitors.map((x) => x.ccn).sort())
       === JSON.stringify(m.competitors.map((x) => x.ccn).sort()),
       '1b. competitor CCN set EXACTLY matches My Market', r.competitors.map((x) => x.ccn).join(','));
    ok(r.competitors.length === m.competitors.length && r.competitors.length === 4,
       '1c. same competitor count as My Market', `${r.competitors.length} vs ${m.competitors.length}`);
    ok(!byCcn.has(OWN), '2. the provider\'s OWN facility is excluded');
    ok(!byCcn.has(D), '3a. a facility with zero shared ZIPs is excluded');
    ok(!byCcn.has(E), '3b. a same-ZIP facility from ANOTHER CMS source is excluded');
    ok(r.competitors.every((x) => x.source === SRC_NAME), '3c. every competitor is cms_hospice');
    const twins = r.competitors.filter((x) => x.name === 'IDENTICAL NAME HOSPICE');
    ok(twins.length === 2, '4a. two facilities with IDENTICAL names stay distinct', String(twins.length));
    ok(twins[0].ccn === T1 && twins[1].ccn === T2, '4b. …identified by CCN, never merged by name',
       twins.map((t) => t.ccn).join(','));

    section('B. overlap arithmetic');
    ok(byCcn.get(B).sharedZipCount === 3, '5a. B sharedZipCount = 3', String(byCcn.get(B).sharedZipCount));
    ok(byCcn.get(C).sharedZipCount === 2, '5b. C sharedZipCount = 2', String(byCcn.get(C).sharedZipCount));
    ok(byCcn.get(T1).sharedZipCount === 1, '5c. T1 sharedZipCount = 1');
    ok(r.competitors.every((x) => x.providerZipCount === 4), '6. providerZipCount = 4 on every row');
    ok(byCcn.get(B).competitorZipCount === 3 && byCcn.get(C).competitorZipCount === 3
       && byCcn.get(T1).competitorZipCount === 1,
       '7. competitorZipCount reflects each competitor\'s FULL CMS footprint');
    ok(byCcn.get(B).providerOverlapPct === 75.00, '8a. B providerOverlapPct = 75.00',
       String(byCcn.get(B).providerOverlapPct));
    ok(byCcn.get(C).providerOverlapPct === 50.00, '8b. C providerOverlapPct = 50.00');
    ok(byCcn.get(T1).providerOverlapPct === 25.00, '8c. T1 providerOverlapPct = 25.00');
    ok(byCcn.get(B).competitorOverlapPct === 100.00, '9a. B competitorOverlapPct = 100.00');
    ok(byCcn.get(C).competitorOverlapPct === 66.67,
       '9b. C competitorOverlapPct = 66.67 — 2dp, deterministic', String(byCcn.get(C).competitorOverlapPct));
    ok(byCcn.get(B).providerOverlapPct === m.competitors.find((x) => x.ccn === B).providerOverlapPct
       && byCcn.get(C).competitorOverlapPct === m.competitors.find((x) => x.ccn === C).competitorOverlapPct,
       '9c. percentages are IDENTICAL to My Market\'s — one precision convention');
    ok(byCcn.get(B).zip === '90002' && byCcn.get(C).zip === '90003',
       '9d. the facility ZIP comes through the enrichment query',
       `${byCcn.get(B).zip}/${byCcn.get(C).zip}`);

    section('B. landscape');
    ok(r.landscape.providerZipCount === 4, '9e. providerZipCount = 4');
    ok(r.landscape.overlappingFacilityCount === 4, '9f. overlappingFacilityCount = 4',
       String(r.landscape.overlappingFacilityCount));
    ok(r.landscape.totalSharedZipRelationships === 7, '9g. totalSharedZipRelationships = 7',
       String(r.landscape.totalSharedZipRelationships));
    ok(r.landscape.highestOverlapSharedZipCount === 3, '9h. highestOverlapSharedZipCount = 3');
    ok(r.landscape.topCompetitorSharedZipCount === r.competitors[0].sharedZipCount
       && r.landscape.topCompetitorSharedZipCount === 3,
       '9i. topCompetitorSharedZipCount is the FIRST row in the table',
       String(r.landscape.topCompetitorSharedZipCount));
    ok(r.landscape.topCompetitorProviderOverlapPct === r.competitors[0].providerOverlapPct
       && r.landscape.topCompetitorProviderOverlapPct === 75.00,
       '9j. topCompetitorProviderOverlapPct matches that same row');
    ok(r.landscape.averageCompetitorsPerProviderZip
       === m.market.averageCompetitorsPerProviderZip,
       '9k. averageCompetitorsPerProviderZip is My Market\'s, unmodified');

    section('B. quality availability — a count of what CMS released');
    ok(byCcn.get(B).qualityAvailability.publishedMeasureCount === 10,
       '17a. B publishedMeasureCount = 10', String(byCcn.get(B).qualityAvailability.publishedMeasureCount));
    ok(byCcn.get(C).qualityAvailability.publishedMeasureCount === 4,
       '17b. C publishedMeasureCount = 4 (4 published, 2 suppressed, 1 valueless)',
       String(byCcn.get(C).qualityAvailability.publishedMeasureCount));
    ok(byCcn.get(T1).qualityAvailability.publishedMeasureCount === 0,
       '17c. a hospice CMS published nothing for = 0, and is still listed');
    ok(r.competitors.every((x) => x.qualityAvailability.surfacedMeasureCount === CODES.length),
       '18a. surfacedMeasureCount = the surfaced definition count', String(CODES.length));
    ok(r.landscape.surfacedMeasureCount === CODES.length,
       '18b. the shared "of Y" denominator is exposed once on the landscape');
    ok(byCcn.get(B).qualityAvailability.publishedMeasureCount === 10,
       '18c. an UNSURFACED measure CMS published is not counted (B would be 11)');
    ok(byCcn.get(C).qualityAvailability.publishedMeasureCount !== 6,
       '19. a suppressed measure that still carries a value does NOT count');
    ok(byCcn.get(C).qualityAvailability.publishedMeasureCount !== 5,
       '20. a non-suppressed measure with a NULL value does NOT count');
    ok(byCcn.get(C).qualityAvailability.publishedMeasureCount !== 9,
       '21a. the OLDER release is not used', String(byCcn.get(C).qualityAvailability.publishedMeasureCount));
    ok(r.freshness.qualityRelease && r.freshness.qualityRelease.releaseKey === '2026-08-19',
       '21b. quality release = newest release CONTAINING measurements',
       r.freshness.qualityRelease && r.freshness.qualityRelease.releaseKey);
    ok(r.freshness.latestIngestedRelease.releaseKey === '2026-09-01',
       '21c. …while the newest ingested roster release is reported separately as 2026-09-01',
       r.freshness.latestIngestedRelease.releaseKey);
    ok(r.freshness.qualityRelease.releaseKey !== r.freshness.latestIngestedRelease.releaseKey,
       '40. a market/quality release skew is represented honestly, not collapsed');
    ok(r.freshness.currentInLatestRelease === true,
       '40b. …and roster freshness still comes from the resolver unchanged');

    section('B. Best Hospice partner badge');
    ok(byCcn.get(B).bestHospicePartner === true,
       '23. verified identity + non-internal Provider => true');
    ok(byCcn.get(C).bestHospicePartner === false,
       '24. UNVERIFIED identity => false');
    ok(byCcn.get(T1).bestHospicePartner === false,
       '25. internal cms_reference provider => false  (CCN 121509 class of defect)');
    ok(byCcn.get(T2).bestHospicePartner === false, '26. no identity at all => false');
    ok(byCcn.get(T2).name === 'IDENTICAL NAME HOSPICE',
       '27a. …even though a Provider row shares its exact name, city and ZIP');
    ok(r.competitors.filter((x) => x.bestHospicePartner).length === 1,
       '27b. exactly ONE partner badge in the whole response',
       String(r.competitors.filter((x) => x.bestHospicePartner).length));
    ok(r.competitors.every((x) => typeof x.bestHospicePartner === 'boolean'),
       '28a. the badge is a boolean on every row');

    section('B. response shape and leakage');
    ok(JSON.stringify(Object.keys(r).sort())
       === JSON.stringify(['competitors', 'detail', 'facility', 'freshness',
                           'landscape', 'methodology', 'provider', 'status']),
       '28b. top-level keys are exactly the designed set', Object.keys(r).join(','));
    const wantKeys = ['bestHospicePartner', 'ccn', 'city', 'competitorOverlapPct', 'competitorZipCount',
                      'name', 'providerOverlapPct', 'providerZipCount', 'qualityAvailability',
                      'sharedZipCount', 'source', 'state', 'zip'];
    ok(r.competitors.every((x) => JSON.stringify(Object.keys(x).sort()) === JSON.stringify(wantKeys)),
       '28c. competitor rows carry exactly 13 designed fields', Object.keys(r.competitors[0]).join(','));
    ok(JSON.stringify(Object.keys(r.provider).sort()) === '["id","name"]',
       '28d. provider payload is only id and name', Object.keys(r.provider).join(','));
    const blob = JSON.stringify(r);
    for (const leak of ['email', 'stripe', 'billingMode', 'subscriptionStatus', 'planTier',
                        'internalRole', 'providerLoginEmail', 'serviceRadiusKm', 'serviceZipCodes',
                        'receiveClientLeads', 'verifiedBy', 'p-partner', 'Bravo Partner Org']) {
      ok(!blob.includes(leak), `28e. no "${leak}" anywhere in the response`);
    }
    ok(!blob.includes('sharedZips'), '32. list output contains NO sharedZips[]');
    ok(!/"measureCode"|"valueNumeric"|"valueRaw"|"direction"|"footnoteCodes"|"suppressed"/.test(blob),
       '33. list output contains NO per-measure quality objects');
    const keys = allKeys(r);
    for (const forbidden of ['score', 'rank', 'ranking', 'grade', 'percentile', 'marketShare',
                             'patientVolume', 'referralVolume', 'revenue', 'utilization', 'payment',
                             'composite', 'verdict', 'favorable']) {
      ok(![...keys].some((k) => k.toLowerCase() === forbidden.toLowerCase()),
         `41. no "${forbidden}" field in the output`);
    }
    ok(r.methodology && /not a quality score/.test(r.methodology.qualityAvailabilityMeaning),
       '41b. quality availability is explicitly disclaimed as NOT a score');
    ok(/market intelligence only/.test(r.methodology.consumerLeadSeparation)
       && /does not determine which providers receive/.test(r.methodology.consumerLeadSeparation),
       '41c. CMS service area is explicitly separated from consumer enquiries');
    ok(r.methodology.notRepresenting.includes('market share')
       && r.methodology.notRepresenting.includes('patient volume')
       && r.methodology.notRepresenting.includes('revenue'),
       '41d. the notRepresenting disclaimer names market share, volume and revenue');
    ok(/never affect this order/.test(r.methodology.ordering),
       '41e. the methodology states quality never affects ordering');

    section('B. read-only');
    const before = await rowCounts();
    const again = await buildProviderCmsCompetitors(prisma, 'p-own');
    const after = await rowCounts();
    ok(before === after, '44a. the service performs NO database writes', `${before} -> ${after}`);
    ok(JSON.stringify(again) === JSON.stringify(r), '44b. output is byte-stable across calls');
    const [cov] = await prisma.$queryRawUnsafe(
      `SELECT count(*)::int n FROM "Provider"
       WHERE "serviceZipCodes" IS NOT NULL OR "serviceRadiusKm" <> 100`);
    ok(cov.n === 0, '43. no CmsFacilityServiceArea data reached Provider coverage fields', String(cov.n));

    // ===================== ordering ladder ==============================
    section('D. ordering — objective geographic overlap only');
    await clean();
    await release(R_OLD, '2026-07-01'); await release(R_MID, '2026-08-19'); await release(R_NEW, '2026-09-01');
    await definitions();
    const OWN2 = 'X81000';
    const ownZips = Array.from({ length: 10 }, (_, i) => `7500${i}`.slice(-5));
    const own2 = await facility(OWN2, 'OWN HOSPICE TWO', ownZips);
    // shared 8, footprint 8   -> 80.00 / 100.00
    await facility('X81001', 'ALPHA HOSPICE', ownZips.slice(0, 8));
    // shared 8, footprint 10  -> 80.00 /  80.00   (loses on competitorOverlapPct)
    await facility('X81002', 'BRAVO HOSPICE', [...ownZips.slice(0, 8), '76001', '76002']);
    // shared 5, footprint 5, names differ -> name ASC decides
    await facility('X81003', 'AAA HOSPICE', ownZips.slice(0, 5));
    await facility('X81004', 'ZZZ HOSPICE', ownZips.slice(0, 5));
    // shared 3, footprint 3, IDENTICAL names -> CCN ASC decides. The lower CCN is
    // inserted SECOND so insertion order cannot accidentally produce the answer.
    const mirrorHi = await facility('X81006', 'MIRROR HOSPICE', ownZips.slice(0, 3));
    await facility('X81005', 'MIRROR HOSPICE', ownZips.slice(0, 3));
    await provider('p-own2'); await identity('p-own2', OWN2);

    const o = await buildProviderCmsCompetitors(prisma, 'p-own2');
    const order = o.competitors.map((x) => x.ccn);
    ok(JSON.stringify(order) === JSON.stringify(['X81001', 'X81002', 'X81003', 'X81004', 'X81005', 'X81006']),
       '10-14. the full 5-key tie-break ladder resolves exactly as specified', order.join(','));
    ok(o.competitors[0].sharedZipCount === 8 && o.competitors[2].sharedZipCount === 5
       && o.competitors[4].sharedZipCount === 3,
       '10. sharedZipCount DESC is the primary key',
       o.competitors.map((x) => x.sharedZipCount).join(','));
    let nonIncreasing = true;
    for (let i = 1; i < o.competitors.length; i++) {
      const a = o.competitors[i - 1], b = o.competitors[i];
      if (a.sharedZipCount === b.sharedZipCount && b.providerOverlapPct > a.providerOverlapPct) nonIncreasing = false;
    }
    ok(nonIncreasing, '11. providerOverlapPct never increases within a sharedZipCount tie');
    ok(o.competitors[0].ccn === 'X81001' && o.competitors[0].competitorOverlapPct === 100
       && o.competitors[1].competitorOverlapPct === 80,
       '12. competitorOverlapPct DESC breaks a sharedZipCount tie',
       `${o.competitors[0].competitorOverlapPct} then ${o.competitors[1].competitorOverlapPct}`);
    ok(o.competitors[2].name === 'AAA HOSPICE' && o.competitors[3].name === 'ZZZ HOSPICE',
       '13. facility name ASC breaks a fully numeric tie',
       `${o.competitors[2].name} then ${o.competitors[3].name}`);
    ok(o.competitors[4].ccn === 'X81005' && o.competitors[5].ccn === 'X81006',
       '14. CCN ASC breaks an identical-name tie', `${o.competitors[4].ccn} then ${o.competitors[5].ccn}`);
    ok(JSON.stringify(o.competitors.map((x) => x.ccn))
       === JSON.stringify(contractOrder(o.competitors).map((x) => x.ccn)),
       '15a. the emitted order satisfies the 5-key contract, checked independently');
    const o2 = await buildProviderCmsCompetitors(prisma, 'p-own2');
    ok(JSON.stringify(o2.competitors.map((x) => x.ccn)) === JSON.stringify(order),
       '15b. ordering is deterministic across calls');
    const mo = await buildProviderCmsMarket(prisma, 'p-own2');
    ok(JSON.stringify(mo.competitors.map((x) => x.ccn)) === JSON.stringify(order),
       '15c. …and identical to My Market\'s order — the two features cannot disagree');

    // Quality is loaded AFTER ordering is fixed, so give the LAST row a full
    // sweep and the FIRST row nothing. If quality touched the sort, this flips.
    for (const code of CODES) await measure(mirrorHi, code, 99, false);
    const o3 = await buildProviderCmsCompetitors(prisma, 'p-own2');
    ok(JSON.stringify(o3.competitors.map((x) => x.ccn)) === JSON.stringify(order),
       '16a. adding quality data does NOT change competitor ordering', o3.competitors.map((x) => x.ccn).join(','));
    ok(o3.competitors[5].qualityAvailability.publishedMeasureCount === 10
       && o3.competitors[0].qualityAvailability.publishedMeasureCount === 0,
       '16b. …and the quality difference really is there — 10 published on the LAST row, 0 on the first',
       `${o3.competitors[0].qualityAvailability.publishedMeasureCount} first / `
       + `${o3.competitors[5].qualityAvailability.publishedMeasureCount} last`);
    ok(o3.competitors[0].sharedZipCount > o3.competitors[5].sharedZipCount,
       '16c. …the first row still leads on overlap alone');

    // ===================== edge states ==================================
    section('E. edge states — fail closed, never invent');
    await clean();
    await release(R_OLD, '2026-07-01'); await release(R_MID, '2026-08-19');
    await release(R_NEW, '2026-09-01'); await definitions();
    const solo = 'X82001';
    await facility(solo, 'SOLO HOSPICE', ['79001', '79002']);
    await facility('X82002', 'FAR HOSPICE', ['79999']);
    await facility('X82003', 'EMPTY AREA HOSPICE', []);
    await provider('p-solo'); await identity('p-solo', solo);
    await provider('p-noident');
    await provider('p-multi'); await identity('p-multi', 'X82090'); await identity('p-multi', 'X82091');
    await provider('p-pall', { careType: 'palliative' }); await identity('p-pall', 'X82092');
    await provider('p-homecare', { careType: 'home-care' }); await identity('p-homecare', 'X82093');
    await provider('p-orphan'); await identity('p-orphan', 'X82099');
    await provider('p-empty'); await identity('p-empty', 'X82003');

    for (const [pid, want, label] of [
      ['p-noident', S.NO_VERIFIED_IDENTITY, '34. no verified identity -> no_verified_identity'],
      ['p-multi', S.MULTIPLE_VERIFIED_IDENTITIES, '35. two identities -> multiple_verified_identities'],
      ['p-pall', S.UNSUPPORTED_CARE_TYPE, '36a. palliative -> unsupported_care_type'],
      ['p-homecare', S.UNSUPPORTED_CARE_TYPE, '36b. home-care -> unsupported_care_type (no hospice default)'],
      ['p-orphan', S.FACILITY_NOT_FOUND, '36c. verified identity, no ingested facility -> facility_not_found'],
      ['p-empty', S.NO_SERVICE_AREA, '37a. zero CMS service ZIPs -> no_service_area'],
      ['nope-nope', S.PROVIDER_NOT_FOUND, '36d. unknown provider -> provider_not_found']
    ]) {
      const e = await buildProviderCmsCompetitors(prisma, pid);
      ok(e.status === want, label, e.status);
      ok(e.competitors === null && e.landscape === null && e.methodology === null,
         `    …${want} carries no competitor payload`);
    }
    const eEmpty = await buildProviderCmsCompetitors(prisma, 'p-empty');
    ok(eEmpty.facility && eEmpty.facility.ccn === 'X82003',
       '37b. …the resolved facility is still reported');
    ok(!JSON.stringify(eEmpty).includes('79001') && eEmpty.landscape === null,
       '37c. …and no market is invented from city, state or radius');

    const zero = await buildProviderCmsCompetitors(prisma, 'p-solo');
    ok(zero.status === S.RESOLVED, '38a. zero overlapping hospices is a RESOLVED market, not an error', zero.status);
    ok(Array.isArray(zero.competitors) && zero.competitors.length === 0,
       '38b. …competitors is an empty ARRAY, not null');
    ok(zero.landscape.overlappingFacilityCount === 0 && zero.landscape.providerZipCount === 2
       && zero.landscape.topCompetitorSharedZipCount === 0
       && zero.landscape.topCompetitorProviderOverlapPct === 0,
       '38c. …the landscape reports honest zeros', JSON.stringify(zero.landscape));
    ok(zero.methodology !== null && zero.landscape.surfacedMeasureCount === CODES.length,
       '38d. …and the surfaced denominator is still known with no competitors');

    // Missing quality release: overlap intelligence must survive intact.
    await prisma.$executeRawUnsafe('TRUNCATE TABLE "CmsFacilityMeasure"');
    const own3 = await facility('X82010', 'PAIR HOSPICE A', ['78001', '78002']);
    await facility('X82011', 'PAIR HOSPICE B', ['78001']);
    await provider('p-pair'); await identity('p-pair', 'X82010');
    const noQ = await buildProviderCmsCompetitors(prisma, 'p-pair');
    ok(noQ.status === S.RESOLVED && noQ.competitors.length === 1,
       '39a. with NO quality release the overlap landscape still resolves', noQ.status);
    ok(noQ.competitors[0].sharedZipCount === 1 && noQ.competitors[0].providerOverlapPct === 50,
       '39b. …overlap intelligence is fully preserved');
    ok(noQ.competitors[0].qualityAvailability === null,
       '39c. …qualityAvailability is null, NOT a fabricated "0 of 10"',
       JSON.stringify(noQ.competitors[0].qualityAvailability));
    ok(noQ.freshness.qualityRelease === null, '39d. …and freshness.qualityRelease is null');
    ok(noQ.freshness.latestIngestedRelease !== null,
       '39e. …while the roster release is still reported');
    await measure(own3, CODES[0], 1, false);   // restore a release with measurements
    const someQ = await buildProviderCmsCompetitors(prisma, 'p-pair');
    ok(someQ.competitors[0].qualityAvailability !== null
       && someQ.competitors[0].qualityAvailability.publishedMeasureCount === 0,
       '39f. once a release carries measurements, a genuine 0 of 10 is reported',
       JSON.stringify(someQ.competitors[0].qualityAvailability));

    // ===================== performance ==================================
    section('F. bounded query count with hundreds of competitors');
    await clean();
    await release(R_OLD, '2026-07-01'); await release(R_MID, '2026-08-19');
    await release(R_NEW, '2026-09-01'); await definitions();
    const bigOwn = await facility('X83000', 'SCALE OWN HOSPICE', ['77001', '77002', '77003']);
    for (const code of CODES) await measure(bigOwn, code, 42, false);
    await provider('p-scale'); await identity('p-scale', 'X83000');
    const bulk = async (from, to) => {
      await prisma.$executeRawUnsafe(
        `INSERT INTO "CmsFacility" ("id","source","ccn","name","address","city","state","zip",
           "firstSeenReleaseId","lastSeenReleaseId","createdAt","updatedAt")
         SELECT 'fac-scale-'||i, $1, 'S'||lpad(i::text,5,'0'), 'SCALE HOSPICE '||i,
                '1 Synthetic Rd','Testville','ZZ','90001',$2,$2,NOW(),NOW()
         FROM generate_series($3::int,$4::int) AS i`, SRC_NAME, R_MID, from, to);
      await prisma.$executeRawUnsafe(
        `INSERT INTO "CmsFacilityServiceArea" ("id","facilityId","source","zip",
           "firstSeenReleaseId","lastSeenReleaseId","createdAt")
         SELECT 'sa-scale-'||i, 'fac-scale-'||i, $1, '77001', $2,$2,NOW()
         FROM generate_series($3::int,$4::int) AS i`, SRC_NAME, R_MID, from, to);
      // Every third scale hospice gets a full sweep of published measures, so the
      // enrichment join has real work to do at both sizes.
      await prisma.$executeRawUnsafe(
        `INSERT INTO "CmsFacilityMeasure" ("id","facilityId","source","measureCode","releaseId",
           "valueNumeric","valueRaw","suppressed","footnoteCodes","createdAt","updatedAt")
         SELECT 'fm-scale-'||i||'-'||c, 'fac-scale-'||i, $1, c, $2, 55,'55',FALSE,'{}'::text[],NOW(),NOW()
         FROM generate_series($3::int,$4::int) AS i,
              unnest($5::text[]) AS c
         WHERE i % 3 = 0`, SRC_NAME, R_MID, from, to, CODES);
    };
    await bulk(1, 5);

    const counted = new PrismaClient({ datasources: { db: { url: DB } },
      log: [{ emit: 'event', level: 'query' }] });
    let n = 0; counted.$on('query', () => { n += 1; });
    await counted.$queryRawUnsafe('SELECT 1');
    // Prisma emits 'query' events asynchronously, so the counter can be short by
    // one if it is read in the same tick a promise settles. Flush before sampling.
    const settle = () => new Promise((res) => setTimeout(res, 50));
    n = 0; const small = await buildProviderCmsCompetitors(counted, 'p-scale');
    await settle(); const tripsSmall = n;
    await bulk(6, 325);
    n = 0; const big = await buildProviderCmsCompetitors(counted, 'p-scale');
    await settle(); const tripsBig = n;
    await counted.$disconnect().catch(() => {});

    ok(small.competitors.length === 5 && big.competitors.length === 325,
       '30. the competitor population really did grow',
       `${small.competitors.length} -> ${big.competitors.length}`);
    ok(tripsSmall === tripsBig, '29a. DB round trips are CONSTANT as competitors grow — no N+1',
       `${tripsSmall} vs ${tripsBig}`);
    ok(tripsBig === 11, '29b. a resolved landscape costs exactly 11 round trips',
       `${tripsBig} round trips`);
    ok(tripsBig <= 12, '29c. …within the 9 (My Market) + 2 (enrichment, partners) budget');
    ok(big.competitors.every((x) => x.qualityAvailability !== null),
       '22a. every one of 325 competitors has a quality availability count');
    const swept = big.competitors.filter((x) => x.qualityAvailability.publishedMeasureCount === 10).length;
    ok(swept === 108, '22b. …counted correctly at scale (every third hospice)', String(swept));
    ok(!JSON.stringify(big).includes('sharedZips'),
       '32b. a 325-competitor payload still contains NO sharedZips[]');
    ok(!/"measureCode"|"valueNumeric"/.test(JSON.stringify(big)),
       '33b. …and NO per-measure objects — 325 x 10 comparisons are not shipped');
    ok(JSON.stringify(big).length < 200000,
       '33c. …the payload stays small enough for an initial page load',
       `${JSON.stringify(big).length} bytes for 325 competitors`);
    ok(big.landscape.overlappingFacilityCount === 325
       && big.landscape.topCompetitorSharedZipCount === 1,
       '30b. the landscape scales with the real population', JSON.stringify(big.landscape));

    await clean();
  } finally {
    await prisma.$disconnect().catch(() => {});
  }
  finish();
})().catch((e) => { console.error('\nharness failed:', e.stack || e.message); process.exit(1); });

function finish() {
  console.log(`\n${'='.repeat(60)}`);
  console.log(fail === 0 ? `PASSED — ${pass} assertions` : `FAILED — ${fail} of ${pass + fail} assertions failed`);
  process.exit(fail === 0 ? 0 : 1);
}
