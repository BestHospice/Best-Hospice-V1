#!/usr/bin/env node
/**
 * Guards Competitor Intelligence V1 Phase C — head-to-head CMS quality
 * comparison, and the overlap-set authorization boundary that protects it.
 *
 * Authorization, release pinning, direction-aware comparison, suppression
 * semantics, summary arithmetic and query boundedness are proven against real
 * rows in a disposable PostgreSQL database. Invariants that cannot be observed
 * from outside — no writes, no fuzzy matching, no consumer-routing dependency,
 * no proprietary score — are proven by source inspection.
 *
 * Every CCN, ZIP, provider and facility name here is SYNTHETIC. CCN 121509,
 * ISLANDS HOSPICE, Vrablic's Home and the Hawaii account appear nowhere.
 *
 *   TEST_DATABASE_URL=postgresql://user@localhost:5432/bh_competitors_test \
 *     node scripts/test-cms-hospice-competitor-detail.js
 */
const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const SRC = fs.readFileSync(path.join(ROOT, 'cms-hospice-competitor-detail.js'), 'utf8');
// Comments stripped before any pattern match, so this suite asserts against the
// module's behaviour rather than against its own prose.
const CODE = SRC.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '');
const BADGE_SRC = fs.readFileSync(path.join(ROOT, 'cms-partner-badge.js'), 'utf8');
const BADGE_CODE = BADGE_SRC.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '');
const MREG = require(path.join(ROOT, 'data', 'cms-hospice-quality-measures.json'));
const {
  buildProviderCmsCompetitorDetail, CMS_COMPETITOR_DETAIL_STATUS: S, COMPARISON, CCN_PATTERN,
  LOWER_IS_BETTER_NOTE, compareValues, comparisonSentence
} = require(path.join(ROOT, 'cms-hospice-competitor-detail.js'));
const { verifiedPartnerCcns } = require(path.join(ROOT, 'cms-partner-badge.js'));
const { DIRECTION } = require(path.join(ROOT, 'cms-hospice-quality.js'));

let pass = 0, fail = 0;
const ok = (c, label, detail) => {
  console.log(`  ${c ? 'ok  ' : 'FAIL'} ${label}${c || !detail ? '' : `  — ${detail}`}`);
  c ? pass++ : fail++;
};
const section = (t) => console.log(`\n--- ${t} ---`);
const allKeys = (v, out = new Set()) => {
  if (Array.isArray(v)) v.forEach((x) => allKeys(x, out));
  else if (v && typeof v === 'object') { for (const k of Object.keys(v)) { out.add(k); allKeys(v[k], out); } }
  return out;
};

// ============================ STATIC AUDIT ===================================
section('A. reuse, isolation and safety by construction');
{
  ok(/require\('\.\/cms-hospice-market'\)/.test(CODE),
     'A1. the detail service REUSES cms-hospice-market — one competitor definition');
  ok(/buildProviderCmsMarket\(prisma, providerId\)/.test(CODE),
     'A2. …calling it rather than re-deriving overlap');
  ok(!/CmsFacilityServiceArea/.test(CODE),
     'A3. it never queries the service-area table itself');
  ok(/require\('\.\/cms-hospice-quality'\)/.test(CODE) && /\{ DIRECTION \}/.test(CODE),
     'A4. direction constants are IMPORTED from the quality module, never re-declared');
  ok(/require\('\.\/cms-partner-badge'\)/.test(CODE),
     'A5. the partner badge comes from the shared rule module');
  ok(!/require\('\.\/server/.test(CODE) && !/require\('\.\.\/server/.test(CODE),
     'A6. it does not import server.js');
  ok(!/require\('\.\/consumer-lead-eligibility'\)/.test(CODE),
     'A7. no dependency on the consumer lead path');
  const requires = (CODE.match(/require\('[^']+'\)/g) || []).sort();
  ok(JSON.stringify(requires) === JSON.stringify(
       ["require('./cms-hospice-market')", "require('./cms-hospice-quality')", "require('./cms-partner-badge')"]),
     'A8. exactly three dependencies, all local leaf modules', requires.join(' '));

  for (const [re, label] of [
    [/serviceRadiusKm|serviceZipCodes|haversine|distance|mileage/, 'no distance, radius or coverage logic'],
    [/billingMode|subscriptionStatus|planTier|stripe|receiveClientLeads|email/i, 'no billing, plan, lead or contact data'],
    [/INSERT|UPDATE |DELETE |TRUNCATE|\.create\(|\.update\(|\.delete\(|\.upsert\(|executeRaw/, 'no writes of any kind'],
    [/ownershipType/, 'no ownership data']
  ]) ok(!re.test(CODE), `A9. ${label}`);
  for (const bad of ['121509', 'ISLANDS HOSPICE', 'c3f7379c', 'Vrablic', 'besthospice_db', 'dpg-']) {
    ok(!SRC.includes(bad), `A10. no production identifier "${bad}"`);
  }

  ok(!/for\s*\([^)]*\)\s*\{[^}]*await prisma/.test(CODE) && !/\.map\(\s*async/.test(CODE)
     && !/forEach\(\s*async/.test(CODE) && !/while\s*\([^)]*\)\s*\{[^}]*await prisma/.test(CODE),
     'A11. no query inside any loop — N+1 is structurally impossible');
  const raws = (CODE.match(/prisma\.\$queryRaw/g) || []).length;
  ok(raws === 1, 'A12. exactly ONE bulk SQL query in the detail service', String(raws));
  ok(!/prisma\.\w+\.find/.test(CODE),
     'A13. …and no direct Prisma model access — the badge goes through the shared rule');
  ok(!/\$queryRawUnsafe|queryRawUnsafe/.test(CODE), 'A14. no queryRawUnsafe');
  const SQL = (SRC.match(/\$queryRaw`([\s\S]*?)`/) || ['', ''])[1];
  const interpolated = new Set(SQL.match(/\$\{[^}]+\}/g) || []);
  ok([...interpolated].every((x) => /^\$\{(source|ownCcn|ccn)\}$/.test(x)),
     'A15. only source, ownCcn and ccn are interpolated, all bound', [...interpolated].join(' '));
  for (const [re, label] of [
    [/ILIKE|similarity|levenshtein|soundex|~\*/i, 'no fuzzy SQL matching'],
    [/f\.name|f\.city|f\.state/, 'never matches a facility on name, city or state']
  ]) ok(!re.test(SQL), `A16. ${label}`);

  ok(/m\.suppressed = FALSE|suppressed === false/.test(CODE)
     && /valueNumeric !== null/.test(CODE),
     'A17. published means not suppressed AND a value present');
  ok(/d\.surfaced = TRUE/.test(SQL), 'A18. only surfaced measures are compared');
  ok(/ORDER BY r\."releaseKey" DESC/.test(SQL) && /EXISTS \(/.test(SQL),
     'A19. the newest release CONTAINING measurements is selected');
  ok(/pm\."releaseId" = \(SELECT id FROM rel\)/.test(SQL)
     && /cm\."releaseId" = \(SELECT id FROM rel\)/.test(SQL),
     'A20. BOTH facility joins read the SAME release id — pinning is structural');
  // Three references in total and no more: the EXISTS that picks the release,
  // then one per facility join. Any fourth would be a second release entering
  // the comparison.
  const relRefs = SQL.match(/\w+\."releaseId" = [^\s]+( id)?/g) || [];
  ok(relRefs.length === 3 && /m\."releaseId" = r\.id/.test(SQL)
     && !/"releaseId" = \$\{/.test(SQL) && !/"releaseId" IN|"releaseId" = ANY/.test(SQL),
     'A20b. …and the ONLY other release reference is the one that selects it',
     relRefs.join(' | '));
  ok(/ORDER BY d\."measureCode" ASC/.test(SQL),
     'A21. deterministic measure order, never by who looks better');
  ok(!/\.sort\(/.test(CODE), 'A22. nothing is re-sorted in JavaScript');

  ok(/competitorEntry = market\.competitors\.find/.test(CODE),
     'A23. authorization looks the CCN up in the provider\'s OWN market');
  ok(CODE.indexOf('COMPETITOR_NOT_IN_MARKET') < CODE.indexOf('prisma.$queryRaw'),
     'A24. …and fails closed BEFORE any quality query runs');
  ok(/CCN_PATTERN = \/\^\[0-9A-Z\]\{6\}\$\//.test(CODE),
     'A25. the CCN pattern is exactly /^[0-9A-Z]{6}$/');
  ok(CODE.indexOf('CCN_PATTERN.test') < CODE.indexOf('buildProviderCmsMarket(prisma, providerId)'),
     'A26. …validated before the database is touched at all');
  ok(!/toUpperCase|toLowerCase|\.trim\(\)/.test(CODE.split('CCN_PATTERN.test')[0].slice(-600)),
     'A27. …and never silently normalised into validity');

  // Substring, NOT \b: a field called qualityScore is exactly the composite this
  // feature must not have, and \bscore would sail straight past it.
  // ONE documented exception: methodology.noProprietaryScore is the DISCLAIMER
  // saying no score exists. It is prose, not a metric.
  const SCORE_DISCLAIMER = 'noProprietaryScore';
  const scrubbed = CODE.split(SCORE_DISCLAIMER).join('__disclaimer__');
  for (const forbidden of ['score', 'rank', 'grade', 'percentile', 'composite', 'index',
                           'winner', 'loser', 'marketShare', 'overall']) {
    ok(!new RegExp(`[A-Za-z]*${forbidden}[A-Za-z]*\\s*:`, 'i').test(scrubbed),
       `A28. no field name containing "${forbidden}" is produced`);
  }
  ok(/noProprietaryScore:/.test(CODE),
     'A28b. …and the one allowed exception is the no-score DISCLAIMER itself');
  for (const word of ['winner', 'loser', 'beats', 'stronger', 'weaker', 'superior', 'inferior']) {
    ok(!new RegExp(word, 'i').test(CODE), `A29. the word "${word}" appears nowhere in the code`);
  }

  section('A. the shared partner rule');
  ok(/verifiedAt: \{ not: null \}/.test(BADGE_CODE), 'A30. verified identities only');
  ok(/provider: \{ internalRole: null \}/.test(BADGE_CODE), 'A31. internal accounts excluded IN SQL');
  ok(/identifierType,/.test(BADGE_CODE) && /IDENTIFIER_TYPE_BY_SOURCE/.test(BADGE_CODE),
     'A32. scoped to the identifier type the source publishes');
  ok(/select: \{ externalId: true \}/.test(BADGE_CODE),
     'A33. projects externalId ONLY — no Provider field can leak');
  ok(!/name|city|state|\bzip\b|lat|lon|radius/i.test(BADGE_CODE.replace(/IDENTIFIER_TYPE_BY_SOURCE/g, '')),
     'A34. no name, city, state or ZIP matching anywhere in the rule');
  ok((BADGE_CODE.match(/require\(/g) || []).length === 0, 'A35. the rule module is a pure leaf — zero requires');
  ok(!/INSERT|UPDATE|DELETE|\.create\(|\.update\(|\.delete\(/.test(BADGE_CODE), 'A36. read-only');

  section('A. pure comparison functions');
  ok(compareValues(80, 60, DIRECTION.HIGHER_BETTER) === COMPARISON.PROVIDER_HIGHER, 'A37. higher_better, provider larger');
  ok(compareValues(40, 70, DIRECTION.HIGHER_BETTER) === COMPARISON.COMPETITOR_HIGHER, 'A38. higher_better, competitor larger');
  ok(compareValues(10, 30, DIRECTION.LOWER_BETTER) === COMPARISON.PROVIDER_HIGHER, 'A39. lower_better, provider SMALLER is favourable');
  ok(compareValues(40, 20, DIRECTION.LOWER_BETTER) === COMPARISON.COMPETITOR_HIGHER, 'A40. lower_better, competitor smaller');
  ok(compareValues(5, 5, DIRECTION.HIGHER_BETTER) === COMPARISON.SAME
     && compareValues(5, 5, DIRECTION.LOWER_BETTER) === COMPARISON.SAME, 'A41. equal values tie in both directions');
  ok(compareValues(null, 5, DIRECTION.HIGHER_BETTER) === COMPARISON.UNAVAILABLE
     && compareValues(5, null, DIRECTION.LOWER_BETTER) === COMPARISON.UNAVAILABLE
     && compareValues(null, null, DIRECTION.HIGHER_BETTER) === COMPARISON.UNAVAILABLE,
     'A42. a missing value on either side is UNAVAILABLE, never a comparison');
  ok(compareValues(0, 5, DIRECTION.HIGHER_BETTER) === COMPARISON.COMPETITOR_HIGHER,
     'A43. a genuine zero is a real value and is compared normally');
  ok(comparisonSentence(COMPARISON.PROVIDER_HIGHER, DIRECTION.HIGHER_BETTER) === 'Your value is higher'
     && comparisonSentence(COMPARISON.COMPETITOR_HIGHER, DIRECTION.HIGHER_BETTER) === "Competitor's value is higher"
     && comparisonSentence(COMPARISON.PROVIDER_HIGHER, DIRECTION.LOWER_BETTER) === 'Your value is lower'
     && comparisonSentence(COMPARISON.COMPETITOR_HIGHER, DIRECTION.LOWER_BETTER) === "Competitor's value is lower"
     && comparisonSentence(COMPARISON.SAME, DIRECTION.HIGHER_BETTER) === 'Same value'
     && comparisonSentence(COMPARISON.UNAVAILABLE, DIRECTION.LOWER_BETTER) === 'Not comparable',
     'A44. comparison wording describes the NUMBERS and follows direction');
  ok(LOWER_IS_BETTER_NOTE === 'Lower is better for this measure.',
     'A45. the direction note matches Quality Intelligence verbatim', LOWER_IS_BETTER_NOTE);
  ok(CCN_PATTERN.test('121509') && CCN_PATTERN.test('A1B2C3') && CCN_PATTERN.test('000001')
     && !CCN_PATTERN.test('a1b2c3') && !CCN_PATTERN.test('12345') && !CCN_PATTERN.test('1234567')
     && !CCN_PATTERN.test('12-345') && !CCN_PATTERN.test(' 12345') && !CCN_PATTERN.test(''),
     'A46. the CCN pattern accepts only six digits/uppercase letters');
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

  const SRC_NAME = 'cms_hospice';
  const R_OLD = 'rel-d-old', R_MID = 'rel-d-mid', R_NEW = 'rel-d-new';
  const UNSURFACED = 'X_UNSURFACED_D1';

  // Real shipped definitions, so the directions under test are the ones deployed.
  const CODES = MREG.measures.map((m) => m.measureCode).sort();
  const HI = MREG.measures.filter((m) => m.direction === 'higher_better').map((m) => m.measureCode).sort();
  const LO = MREG.measures.filter((m) => m.direction === 'lower_better').map((m) => m.measureCode).sort();

  const clean = () => prisma.$executeRawUnsafe(
    'TRUNCATE TABLE "CmsFacilityMeasure","CmsMeasureDefinition","CmsFacilityServiceArea","CmsFacility",'
    + '"CmsRelease","ProviderExternalIdentity","Provider" CASCADE');
  const release = (id, key) => prisma.$executeRawUnsafe(
    `INSERT INTO "CmsRelease" (id,source,"releaseKey","capturedAt","ingestedAt","datasetCount")
     VALUES ($1,$2,$3,($3||'T00:00:00Z')::timestamptz,NOW(),6)`, id, SRC_NAME, key);
  const definitions = async () => {
    for (const m of MREG.measures) {
      await prisma.$executeRawUnsafe(
        `INSERT INTO "CmsMeasureDefinition" (id,source,"measureCode","cmsMeasureName","shortLabel",
           dimension,family,"valueKind",direction,"scaleMin","scaleMax",decimals,"unitLabel",
           "denominatorCode",surfaced,"createdAt","updatedAt")
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,TRUE,NOW(),NOW())`,
        uuid(), SRC_NAME, m.measureCode, m.cmsMeasureName, m.shortLabel, m.dimension, m.family,
        m.valueKind, m.direction, m.scaleMin, m.scaleMax, m.decimals, m.unitLabel, m.denominatorCode);
    }
    await prisma.$executeRawUnsafe(
      `INSERT INTO "CmsMeasureDefinition" (id,source,"measureCode","cmsMeasureName","shortLabel",
         dimension,family,"valueKind",direction,decimals,surfaced,"createdAt","updatedAt")
       VALUES ($1,$2,$3,'Synthetic unsurfaced','Unsurfaced','other','other','percent','higher_better',1,FALSE,NOW(),NOW())`,
      uuid(), SRC_NAME, UNSURFACED);
  };
  const facility = async (ccn, name, zips, zip = '90001') => {
    const id = 'fac-' + ccn;
    await prisma.$executeRawUnsafe(
      `INSERT INTO "CmsFacility" (id,source,ccn,name,address,city,state,zip,
         "firstSeenReleaseId","lastSeenReleaseId","createdAt","updatedAt")
       VALUES ($1,$2,$3,$4,'1 Synthetic Rd','Testville','ZZ',$5,$6,$7,NOW(),NOW())`,
      id, SRC_NAME, ccn, name, zip, R_OLD, R_NEW);
    for (const z of zips) {
      await prisma.$executeRawUnsafe(
        `INSERT INTO "CmsFacilityServiceArea" (id,"facilityId",source,zip,
           "firstSeenReleaseId","lastSeenReleaseId","createdAt")
         VALUES ($1,$2,$3,$4,$5,$5,NOW())`, uuid(), id, SRC_NAME, z, R_OLD);
    }
    return id;
  };
  // value null + suppressed false  -> CMS published nothing usable
  // value present + suppressed true -> CMS withheld it despite holding a value
  const measure = (facId, code, value, suppressed, rel = R_MID) => prisma.$executeRawUnsafe(
    `INSERT INTO "CmsFacilityMeasure" (id,"facilityId",source,"measureCode","releaseId",
       "valueNumeric","valueRaw",suppressed,"footnoteCodes","periodStart","periodEnd","createdAt","updatedAt")
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9::text[],'2023-01-01'::date,'2024-12-31'::date,NOW(),NOW())`,
    uuid(), facId, SRC_NAME, code, rel, value, value === null ? 'Not Available' : String(value),
    suppressed, suppressed ? ['1'] : []);
  const provider = (id, over = {}) => prisma.$executeRawUnsafe(
    `INSERT INTO "Provider" (id,name,email,address,city,state,zip,lat,lon,
       "serviceRadiusKm","careType","internalRole","createdAt","updatedAt")
     VALUES ($1,$2,$3,'1 Main St','Testville','ZZ','90001',33,-112,100,$4,$5,NOW(),NOW())`,
    id, over.name || 'Provider ' + id, id + '@example.test', over.careType || 'hospice',
    over.internalRole || null);
  const identity = (pid, ccn, over = {}) => prisma.$executeRawUnsafe(
    `INSERT INTO "ProviderExternalIdentity" (id,"providerId",source,"externalId","identifierType",
       "verifiedAt","verifiedBy","createdAt","updatedAt")
     VALUES ($1,$2,$3,$4,$5,$6,'test-suite',NOW(),NOW())`,
    uuid(), pid, SRC_NAME, ccn, over.identifierType === undefined ? 'ccn' : over.identifierType,
    over.verifiedAt === undefined ? new Date('2026-08-31T00:00:00Z') : over.verifiedAt);
  const rowCounts = async () => {
    const [r] = await prisma.$queryRawUnsafe(
      `SELECT (SELECT count(*) FROM "CmsFacility")::int a,(SELECT count(*) FROM "CmsFacilityMeasure")::int b,
              (SELECT count(*) FROM "Provider")::int c,(SELECT count(*) FROM "ProviderExternalIdentity")::int d,
              (SELECT count(*) FROM "CmsFacilityServiceArea")::int e`);
    return JSON.stringify(r);
  };

  const OWN = 'D70000', RIVAL = 'D70001', T1 = 'D70002', T2 = 'D70003';
  const INTERNALC = 'D70004', PARTNERC = 'D70005', FAR = 'D70009';
  const OWN2 = 'D70010', FULL = 'D70011';

  try {
    await clean();
    await release(R_OLD, '2026-07-01'); await release(R_MID, '2026-08-19'); await release(R_NEW, '2026-09-01');
    await definitions();

    const ownId = await facility(OWN, 'OWN HOSPICE', ['81001', '81002', '81003', '81004']);
    const rivalId = await facility(RIVAL, 'RIVAL HOSPICE', ['81001', '81002'], '90222');
    const t1Id = await facility(T1, 'IDENTICAL NAME HOSPICE', ['81001']);
    const t2Id = await facility(T2, 'IDENTICAL NAME HOSPICE', ['81001']);
    const intId = await facility(INTERNALC, 'INTERNAL-LINKED HOSPICE', ['81001']);
    const partId = await facility(PARTNERC, 'PARTNER HOSPICE', ['81001']);
    await facility(FAR, 'FAR HOSPICE', ['89999']);           // valid CCN, shares nothing

    // Ten scenarios across the ten surfaced measures, one per comparison shape.
    const [H1, H2, H3, H4, H5, H6, H7] = HI;
    const [L1, L2, L3] = LO;
    await measure(ownId, H1, 80, false);   await measure(rivalId, H1, 60, false);   // provider_higher
    await measure(ownId, H2, 40, false);   await measure(rivalId, H2, 70, false);   // competitor_higher
    await measure(ownId, H3, 50, false);   await measure(rivalId, H3, 50, false);   // same
    await measure(ownId, H4, 99, true);    await measure(rivalId, H4, 50, false);   // provider suppressed
    await measure(ownId, H5, 50, false);   await measure(rivalId, H5, 99, true);    // competitor suppressed
    await measure(ownId, H6, null, false); await measure(rivalId, H6, 50, false);   // provider no value
    await measure(ownId, H7, 50, false);   await measure(rivalId, H7, null, false); // competitor no value
    await measure(ownId, L1, 10, false);   await measure(rivalId, L1, 30, false);   // lower_better provider
    await measure(ownId, L2, 40, false);   await measure(rivalId, L2, 20, false);   // lower_better competitor
    // L3: neither hospice has a row at all in the pinned release.
    // The unsurfaced definition IS published for both and must never appear.
    await measure(ownId, UNSURFACED, 10, false); await measure(rivalId, UNSURFACED, 90, false);
    // The OLDER release contradicts the newer one on two measures. If the wrong
    // release were read, H2 would flip and L3 would become comparable.
    await measure(ownId, H2, 90, false, R_OLD);  await measure(rivalId, H2, 10, false, R_OLD);
    await measure(ownId, L3, 5, false, R_OLD);   await measure(rivalId, L3, 9, false, R_OLD);

    await provider('p-own'); await identity('p-own', OWN);
    await provider('p-partner', { name: 'Partner Org' }); await identity('p-partner', PARTNERC);
    await provider('p-internal', { name: 'internal reference', internalRole: 'cms_reference' });
    await identity('p-internal', INTERNALC);
    await provider('p-unver'); await identity('p-unver', T1, { verifiedAt: null });
    await provider('p-noident');
    await provider('p-pall', { careType: 'palliative' }); await identity('p-pall', 'D70099');

    const r = await buildProviderCmsCompetitorDetail(prisma, 'p-own', RIVAL);
    const byCode = new Map((r.measures || []).map((m) => [m.measureCode, m]));

    section('B. authorization — the overlap set is the boundary');
    ok(r.status === S.RESOLVED, '1. a competitor inside the overlap set resolves', r.status);
    ok(r.competitor.ccn === RIVAL && r.provider.ccn === OWN,
       '1b. …identifying both hospices by CCN');
    for (const bad of ['abc123', '12345', '1234567', '12-345', ' D7000', 'd70001', '', 'D7000!', '汉字汉字']) {
      const e = await buildProviderCmsCompetitorDetail(prisma, 'p-own', bad);
      ok(e.status === S.INVALID_CCN, `3. malformed CCN ${JSON.stringify(bad)} rejected`, e.status);
      ok(e.measures === null && e.overlap === null, '    …carrying no comparison payload');
    }
    for (const v of [null, undefined, 123456, {}, ['D70001']]) {
      const e = await buildProviderCmsCompetitorDetail(prisma, 'p-own', v);
      ok(e.status === S.INVALID_CCN, `3b. non-string CCN ${JSON.stringify(v)} rejected`, e.status);
    }
    const far = await buildProviderCmsCompetitorDetail(prisma, 'p-own', FAR);
    ok(far.status === S.COMPETITOR_NOT_IN_MARKET,
       '2. a VALID CCN outside the overlap set fails closed', far.status);
    ok(far.measures === null && far.overlap === null && far.competitor === null,
       '2b. …and no quality data, name or overlap leaks about it');
    const ghost = await buildProviderCmsCompetitorDetail(prisma, 'p-own', 'ZZ9999');
    ok(ghost.status === S.COMPETITOR_NOT_IN_MARKET,
       '4. a CCN with no CMS facility at all is refused the same way', ghost.status);
    const self = await buildProviderCmsCompetitorDetail(prisma, 'p-own', OWN);
    ok(self.status === S.COMPETITOR_NOT_IN_MARKET,
       '5. the provider cannot compare itself with itself', self.status);
    // The caller's OWN facility is still named, exactly as My Market does on a
    // fail-closed state - that is their own data. What must not leak is anything
    // about the hospice they were refused, or about the rest of their market.
    const refused = JSON.stringify(far) + JSON.stringify(ghost);
    ok(!/FAR HOSPICE|D70009|ZZ9999|81001|sharedZips|RIVAL/.test(refused),
       '7. a refused request reveals nothing about the refused hospice or the market',
       refused.slice(0, 80));
    ok(far.provider && far.provider.ccn === OWN,
       '7b. …while the caller\'s own CMS identity is still reported back');

    const twin1 = await buildProviderCmsCompetitorDetail(prisma, 'p-own', T1);
    const twin2 = await buildProviderCmsCompetitorDetail(prisma, 'p-own', T2);
    ok(twin1.status === S.RESOLVED && twin2.status === S.RESOLVED
       && twin1.competitor.ccn === T1 && twin2.competitor.ccn === T2
       && twin1.competitor.name === twin2.competitor.name,
       '6. same-name hospices stay distinct — resolved by CCN, never by name');

    for (const [pid, want, label] of [
      ['p-noident', S.NO_VERIFIED_IDENTITY, '8. unresolved provider identity fails closed'],
      ['p-pall', S.UNSUPPORTED_CARE_TYPE, '8b. non-CMS care type fails closed'],
      ['nope-nope', S.PROVIDER_NOT_FOUND, '8c. unknown provider fails closed']
    ]) {
      const e = await buildProviderCmsCompetitorDetail(prisma, pid, RIVAL);
      ok(e.status === want, label, e.status);
      ok(e.measures === null && e.competitor === null, '    …with no competitor payload');
    }

    section('B. quality release pinning');
    ok(r.freshness.qualityRelease && r.freshness.qualityRelease.releaseKey === '2026-08-19',
       '11. the newest release CONTAINING measurements is used, not 2026-09-01',
       r.freshness.qualityRelease && r.freshness.qualityRelease.releaseKey);
    ok(r.freshness.latestIngestedRelease.releaseKey === '2026-09-01',
       '11b. …while the newest roster release is reported separately');
    ok(byCode.get(H2).comparison === COMPARISON.COMPETITOR_HIGHER,
       '12. both facilities are pinned to ONE release — the older release would flip this',
       byCode.get(H2).comparison);
    ok(byCode.get(L3).comparison === COMPARISON.UNAVAILABLE
       && byCode.get(L3).providerValue === null && byCode.get(L3).competitorValue === null,
       '12b. …and a measure only present in the older release stays unavailable');

    section('B. direction-aware comparison');
    ok(byCode.get(H1).comparison === COMPARISON.PROVIDER_HIGHER
       && byCode.get(H1).comparisonText === 'Your value is higher',
       '13. higher_better, provider larger => provider favourable', byCode.get(H1).comparisonText);
    ok(byCode.get(H2).comparisonText === "Competitor's value is higher",
       '14. higher_better, competitor larger', byCode.get(H2).comparisonText);
    ok(byCode.get(L1).comparison === COMPARISON.PROVIDER_HIGHER
       && byCode.get(L1).comparisonText === 'Your value is lower',
       '15. lower_better, provider SMALLER => provider favourable, worded as lower',
       byCode.get(L1).comparisonText);
    ok(byCode.get(L2).comparison === COMPARISON.COMPETITOR_HIGHER
       && byCode.get(L2).comparisonText === "Competitor's value is lower",
       '16. lower_better, competitor smaller', byCode.get(L2).comparisonText);
    ok(byCode.get(L1).providerValue < byCode.get(L1).competitorValue,
       '15b. …and on that measure the provider\'s NUMBER really is the smaller one',
       `${byCode.get(L1).providerValue} vs ${byCode.get(L1).competitorValue}`);
    ok(byCode.get(H3).comparison === COMPARISON.SAME && byCode.get(H3).comparisonText === 'Same value',
       '17. exactly equal values tie');
    ok(byCode.get(L1).directionNote === LOWER_IS_BETTER_NOTE && byCode.get(L1).lowerIsBetter === true,
       '15c. a lower-is-better measure carries the direction note');
    ok(byCode.get(H1).directionNote === null && byCode.get(H1).lowerIsBetter === false,
       '13b. …and a higher-is-better measure does not');
    ok(r.measures.every((m) => m.direction === (MREG.measures.find((x) => x.measureCode === m.measureCode) || {}).direction),
       '13c. every direction comes from the definition, never inferred from the values');

    section('B. suppression is never zero and never compared');
    for (const [code, label] of [
      [H4, '18. provider suppressed => unavailable'],
      [H5, '19. competitor suppressed => unavailable'],
      [H6, '20. provider value null => unavailable'],
      [H7, '21. competitor value null => unavailable'],
      [L3, '21b. neither hospice published => unavailable']
    ]) {
      const m = byCode.get(code);
      ok(m.comparison === COMPARISON.UNAVAILABLE, label, m.comparison);
      ok(m.comparisonText === 'Not comparable', '    …worded as not comparable');
    }
    ok(byCode.get(H4).providerValue === null && byCode.get(H4).providerPublished === false
       && byCode.get(H4).providerSuppressed === true,
       '18b. a suppressed value is withheld from the payload, not passed through');
    ok(byCode.get(H4).competitorValue === 50 && byCode.get(H4).competitorPublished === true,
       '18c. …while the other hospice\'s published value is still reported');
    ok(!r.measures.some((m) => m.providerValue === 0 || m.competitorValue === 0),
       '18d. nothing missing was turned into a zero');
    ok(!byCode.has(UNSURFACED) && r.measures.length === CODES.length,
       '22. unsurfaced definitions are excluded', `${r.measures.length} of ${CODES.length}`);
    ok(JSON.stringify(r.measures.map((m) => m.measureCode)) === JSON.stringify(CODES),
       '22b. measures come back in deterministic measureCode order');

    section('B. summary counts reconcile exactly');
    const cs = r.comparisonSummary;
    ok(cs.providerFavorableCount === 2, '23. providerFavorableCount = 2', String(cs.providerFavorableCount));
    ok(cs.competitorFavorableCount === 2, '23b. competitorFavorableCount = 2', String(cs.competitorFavorableCount));
    ok(cs.tiedCount === 1, '23c. tiedCount = 1', String(cs.tiedCount));
    ok(cs.unavailableCount === 5, '24. unavailableCount = 5', String(cs.unavailableCount));
    ok(cs.comparableMeasureCount === cs.providerFavorableCount + cs.competitorFavorableCount + cs.tiedCount,
       '23d. comparable = provider + competitor + tied', JSON.stringify(cs));
    ok(cs.surfacedMeasureCount === cs.comparableMeasureCount + cs.unavailableCount,
       '23e. surfaced = comparable + unavailable');
    ok(cs.surfacedMeasureCount === r.measures.length && cs.surfacedMeasureCount === 10,
       '23f. surfaced = the number of measure rows returned');
    const keys = allKeys(r);
    // Substring again. `qualityScore`.toLowerCase() !== 'score', so an exact-match
    // check would report a clean bill of health on a composite score.
    for (const forbidden of ['score', 'rank', 'grade', 'percentile', 'composite', 'index',
                             'winner', 'loser', 'overall', 'marketshare', 'patientvolume']) {
      const hit = [...keys].filter((k) => k !== 'noProprietaryScore'
        && k.toLowerCase().includes(forbidden));
      ok(hit.length === 0, `25. no field name containing "${forbidden}" anywhere in the response`,
         hit.join(','));
    }
    ok([...keys].length > 30, '25c. …checked against a response with real fields in it',
       String([...keys].length));
    ok(r.methodology.noProprietaryScore && /does not calculate an overall competitor score/
        .test(r.methodology.noProprietaryScore),
       '25d. …and the sole exception really is the disclaimer, not a metric');
    ok(!/winner|loser|beats|stronger hospice|weaker hospice|superior|inferior|overall better/i
        .test(JSON.stringify(r)), '25b. no winner or loser language in the payload');

    section('B. overlap truth and partner badge');
    ok(r.overlap.sharedZipCount === 2 && r.overlap.providerZipCount === 4
       && r.overlap.competitorZipCount === 2,
       '1c. overlap counts come from My Market unchanged', JSON.stringify(r.overlap).slice(0, 90));
    ok(r.overlap.providerOverlapPct === 50 && r.overlap.competitorOverlapPct === 100,
       '1d. …and so do both percentages');
    ok(JSON.stringify(r.overlap.sharedZips) === JSON.stringify(['81001', '81002']),
       '1e. sharedZips IS exposed here, sorted — the one place it belongs',
       JSON.stringify(r.overlap.sharedZips));
    ok(r.competitor.officeZip === '90222', '1f. the competitor office ZIP is returned', r.competitor.officeZip);
    const partner = await buildProviderCmsCompetitorDetail(prisma, 'p-own', PARTNERC);
    ok(partner.competitor.bestHospicePartner === true,
       '10a. a verified, non-internal identity badges');
    const internal = await buildProviderCmsCompetitorDetail(prisma, 'p-own', INTERNALC);
    ok(internal.competitor.bestHospicePartner === false,
       '10. an INTERNAL cms_reference identity never badges  (the 121509 class of defect)');
    ok(twin1.competitor.bestHospicePartner === false, '10b. an UNVERIFIED identity never badges');
    ok(twin2.competitor.bestHospicePartner === false, '10c. no identity at all => false');
    ok(r.competitor.bestHospicePartner === false, '10d. …and nothing is invented for the rival');
    const badgeSet = await verifiedPartnerCcns(prisma, SRC_NAME, [PARTNERC, INTERNALC, T1, T2, RIVAL]);
    ok(badgeSet.size === 1 && badgeSet.has(PARTNERC),
       '10e. the shared rule agrees exactly, in one bulk call', [...badgeSet].join(','));
    ok((await verifiedPartnerCcns(prisma, 'cms_home_health', [PARTNERC])).size === 0,
       '10f. …and an unmodelled source badges nothing');

    section('B. privacy');
    const blob = JSON.stringify(partner);
    for (const leak of ['email', 'stripe', 'billingMode', 'subscriptionStatus', 'planTier',
                        'internalRole', 'serviceRadiusKm', 'serviceZipCodes', 'receiveClientLeads',
                        'verifiedBy', 'p-partner', 'Partner Org', 'providerLoginEmail', 'phone']) {
      ok(!blob.includes(leak), `9. no "${leak}" in the detail response`);
    }
    // Coordinates by FIELD NAME: "lat" is a substring of "calculate" in the
    // methodology prose, so a blob search would be meaningless here.
    const partnerKeys = allKeys(partner);
    for (const k of ['lat', 'lon', 'latitude', 'longitude', 'address', 'providerId', 'id']) {
      ok(![...partnerKeys].some((x) => x.toLowerCase() === k),
         `9a. no "${k}" field in the detail response`);
    }
    ok(JSON.stringify(Object.keys(r.provider).sort()) === '["ccn","name","source"]',
       '9b. the provider block is CMS identity only', Object.keys(r.provider).join(','));
    ok(JSON.stringify(Object.keys(r.competitor).sort())
       === '["bestHospicePartner","ccn","city","name","officeZip","source","state"]',
       '9c. the competitor block carries exactly the designed fields',
       Object.keys(r.competitor).join(','));

    section('B. read-only');
    const before = await rowCounts();
    const again = await buildProviderCmsCompetitorDetail(prisma, 'p-own', RIVAL);
    const after = await rowCounts();
    ok(before === after, '9d. the service performs NO database writes', `${before} -> ${after}`);
    ok(JSON.stringify(again) === JSON.stringify(r), '9e. output is byte-stable across calls');

    section('B. zero comparable, all comparable, no quality release');
    const none = await buildProviderCmsCompetitorDetail(prisma, 'p-own', T2);
    ok(none.status === S.RESOLVED && none.comparisonSummary.comparableMeasureCount === 0
       && none.comparisonSummary.unavailableCount === 10,
       '14e. a hospice CMS published nothing for => zero comparable, still resolved',
       JSON.stringify(none.comparisonSummary));
    ok(none.measures.length === 10 && none.measures.every((m) => m.comparison === COMPARISON.UNAVAILABLE),
       '14f. …every surfaced measure is still listed, all not comparable');
    ok(none.overlap.sharedZipCount === 1,
       '14g. …and the overlap context is fully preserved');

    const own2 = await facility(OWN2, 'SECOND OWN HOSPICE', ['82001', '82002']);
    const fullId = await facility(FULL, 'FULLY PUBLISHED HOSPICE', ['82001']);
    for (const code of CODES) { await measure(own2, code, 60, false); await measure(fullId, code, 40, false); }
    await provider('p-own2'); await identity('p-own2', OWN2);
    const all = await buildProviderCmsCompetitorDetail(prisma, 'p-own2', FULL);
    ok(all.comparisonSummary.comparableMeasureCount === 10 && all.comparisonSummary.unavailableCount === 0,
       '15e. two fully published hospices compare on all ten measures',
       JSON.stringify(all.comparisonSummary));
    ok(all.comparisonSummary.providerFavorableCount === HI.length
       && all.comparisonSummary.competitorFavorableCount === LO.length,
       '15f. …split exactly by direction: 60 vs 40 favours the provider on higher-is-better only',
       `${all.comparisonSummary.providerFavorableCount}/${all.comparisonSummary.competitorFavorableCount}`);

    await prisma.$executeRawUnsafe('TRUNCATE TABLE "CmsFacilityMeasure"');
    const noRel = await buildProviderCmsCompetitorDetail(prisma, 'p-own', RIVAL);
    ok(noRel.status === S.RESOLVED && noRel.freshness.qualityRelease === null,
       '5e. with no measurement-bearing release the comparison still resolves', noRel.status);
    ok(noRel.measures.length === 10 && noRel.measures.every((m) => m.comparison === COMPARISON.UNAVAILABLE)
       && noRel.comparisonSummary.comparableMeasureCount === 0,
       '5f. …all measures not comparable, none fabricated as zero');
    ok(noRel.overlap.sharedZipCount === 2,
       '5g. …and overlap intelligence is untouched by the missing quality data');
    for (const code of CODES) { await measure(ownId, code, 70, false); await measure(rivalId, code, 70, false); }

    section('B. bounded query count');
    {
      const counted = new PrismaClient({ datasources: { db: { url: DB } },
        log: [{ emit: 'event', level: 'query' }] });
      let n = 0; counted.$on('query', () => { n += 1; });
      await counted.$queryRawUnsafe('SELECT 1');
      const settle = () => new Promise((res) => setTimeout(res, 60));
      n = 0; await buildProviderCmsCompetitorDetail(counted, 'p-own', RIVAL); await settle();
      const base = n;
      // More competitors and more shared ZIP codes must not cost more queries.
      await prisma.$executeRawUnsafe(
        `INSERT INTO "CmsFacility" (id,source,ccn,name,address,city,state,zip,
           "firstSeenReleaseId","lastSeenReleaseId","createdAt","updatedAt")
         SELECT 'fac-bulk-'||i,$1,'B'||lpad(i::text,5,'0'),'BULK '||i,'1 R','Testville','ZZ','90001',
                $2,$3,NOW(),NOW() FROM generate_series(1,200) i`, SRC_NAME, R_OLD, R_NEW);
      await prisma.$executeRawUnsafe(
        `INSERT INTO "CmsFacilityServiceArea" (id,"facilityId",source,zip,
           "firstSeenReleaseId","lastSeenReleaseId","createdAt")
         SELECT 'sa-bulk-'||i||'-'||z,'fac-bulk-'||i,$1,z,$2,$2,NOW()
         FROM generate_series(1,200) i, unnest(ARRAY['81001','81002','81003','81004']) z`, SRC_NAME, R_OLD);
      n = 0; const big = await buildProviderCmsCompetitorDetail(counted, 'p-own', RIVAL); await settle();
      const grown = n;
      ok(base === grown, '28. round trips are CONSTANT as competitors and shared ZIPs grow',
         `${base} vs ${grown}`);
      ok(grown === 11, '26. a resolved comparison costs exactly 11 round trips', `${grown} round trips`);
      ok(big.overlap.sharedZips.length === 2,
         '28b. …and the requested competitor\'s own overlap is unchanged');
      // Fewer surfaced measures must not change the count either.
      await prisma.$executeRawUnsafe(
        `UPDATE "CmsMeasureDefinition" SET surfaced = FALSE WHERE source = $1 AND "measureCode" = ANY($2::text[])`,
        SRC_NAME, CODES.slice(3));
      n = 0; const few = await buildProviderCmsCompetitorDetail(counted, 'p-own', RIVAL); await settle();
      ok(few.measures.length === 3, '27a. the surfaced measure count really did change',
         String(few.measures.length));
      ok(n === grown, '27. …and the round-trip count did NOT — no query per measure', `${n} vs ${grown}`);
      await prisma.$executeRawUnsafe(
        `UPDATE "CmsMeasureDefinition" SET surfaced = TRUE WHERE source = $1 AND "measureCode" <> $2`,
        SRC_NAME, UNSURFACED);
      n = 0; const one = await buildProviderCmsCompetitorDetail(counted, 'p-own', T1); await settle();
      ok(one.competitor.ccn === T1 && !JSON.stringify(one).includes(RIVAL),
         '29. only the REQUESTED competitor is returned — no other hospice appears');
      ok(n === grown, '29b. …at the same bounded cost', `${n} vs ${grown}`);
      await counted.$disconnect().catch(() => {});
    }

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
