#!/usr/bin/env node
/**
 * Guards Quality Intelligence V1 — the quality calculation service.
 *
 * Orientation, suppression, peer thresholds and market reuse are proven against
 * real rows in disposable PostgreSQL. Endpoint wiring is checked by source
 * inspection, because this repo has no HTTP harness (same limitation as the CMS
 * resolver and My Market suites).
 *
 * Every CCN, facility name, ZIP and provider id here is SYNTHETIC. The measure
 * DEFINITIONS are the real shipped ones, read from
 * data/cms-hospice-quality-measures.json, so the tests exercise the directions
 * we actually deploy rather than a convenient copy of them.
 *
 *   TEST_DATABASE_URL=postgresql://user@localhost:5432/bh_quality_test \
 *     node scripts/test-cms-hospice-quality.js
 */
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const ROOT = path.join(__dirname, '..');
const SRC = fs.readFileSync(path.join(ROOT, 'server.js'), 'utf8');
const Q_SRC = fs.readFileSync(path.join(ROOT, 'cms-hospice-quality.js'), 'utf8');
const Q_CODE = Q_SRC.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '');
const MREG = require(path.join(ROOT, 'data', 'cms-hospice-quality-measures.json'));
const { buildProviderCmsQuality, CMS_QUALITY_STATUS: S, VERDICT, MIN_COMPARABLE_PEERS,
        CAHPS_UNPUBLISHED_MESSAGE } = require(path.join(ROOT, 'cms-hospice-quality.js'));
const { buildProviderCmsMarket } = require(path.join(ROOT, 'cms-hospice-market.js'));

let pass = 0, fail = 0;
const ok = (c, label, detail) => {
  console.log(`  ${c ? 'ok  ' : 'FAIL'} ${label}${c || !detail ? '' : `  — ${detail}`}`);
  c ? pass++ : fail++;
};
const section = (t) => console.log(`\n--- ${t} ---`);

// ============================ STATIC AUDIT ===================================
section('service structure — reuse, no second market definition, no writes');
{
  ok(/require\('\.\/cms-hospice-market'\)/.test(Q_CODE),
     '1. the quality service REUSES the My Market module');
  ok(/buildProviderCmsMarket\(prisma, providerId\)/.test(Q_CODE),
     '   …and calls it rather than reimplementing the overlap query');
  ok(!/CmsFacilityServiceArea/.test(Q_CODE),
     '2. it never queries CmsFacilityServiceArea itself — there is ONE market definition');
  ok(!/providerExternalIdentity|ProviderExternalIdentity/.test(Q_CODE),
     '3. it never queries ProviderExternalIdentity directly — one identity path');

  for (const [re, label] of [
    [/ILIKE|ilike|similarity|levenshtein|soundex/, 'no fuzzy SQL matching'],
    [/serviceRadiusKm|haversine|distance|mileage/, 'no distance/radius logic'],
    [/billingMode|subscriptionStatus|planTier|stripe/i, 'no billing or subscription input'],
    [/internalRole|isInternalProvider/, 'no internalRole special-casing'],
    [/INSERT|UPDATE |DELETE|\.create\(|\.update\(|\.delete\(|\.upsert\(/, 'no writes'],
    [/121509|ISLANDS HOSPICE|ACCENTCARE|Vrablic|besthospice_db|dpg-/i, 'no production identifier']
  ]) ok(!re.test(Q_CODE), `4. ${label}`);

  // The Phase 1 finding, enforced in code.
  ok(!/_PERCENTILE/.test(Q_CODE),
     '5. the service never reads a CMS _PERCENTILE field as a quality rank');
  ok(/percentile_cont\(0\.5\)/.test(Q_CODE),
     '   …it computes its own median from the provider\'s own peer set instead');

  ok(!/for\s*\([^)]*\)\s*\{[^}]*await prisma/.test(Q_CODE)
     && !/\.map\(\s*async/.test(Q_CODE)
     && !/forEach\(\s*async/.test(Q_CODE),
     '6. no query inside any loop — N+1 is structurally impossible');
  ok((Q_CODE.match(/prisma\.\$queryRaw/g) || []).length === 3,
     '7. exactly three aggregate SQL queries beyond My Market\'s',
     String((Q_CODE.match(/prisma\.\$queryRaw/g) || []).length));
  ok(!/\$queryRawUnsafe|executeRawUnsafe/.test(Q_CODE),
     '8. parameterised tagged templates only — no queryRawUnsafe');

  ok(/suppressed = FALSE AND m\."valueNumeric" IS NOT NULL/.test(Q_SRC),
     '9. only unsuppressed, non-null observations enter a peer denominator');
  ok(/f\.ccn <> \$\{ownCcn\}|f\.ccn <> /.test(Q_SRC),
     '10. the provider\'s own facility is excluded from the peer set explicitly');
  ok(/MIN_COMPARABLE_PEERS_FLOOR = 5/.test(Q_SRC),
     '11. the minimum comparable peer count has a hard floor of 5 in code');
  ok(/Math\.max\(\s*MIN_COMPARABLE_PEERS_FLOOR/.test(Q_SRC),
     '   …which the registry cannot lower');
  ok(MIN_COMPARABLE_PEERS === 5, '12. the effective minimum is 5', String(MIN_COMPARABLE_PEERS));

  ok(/composite|Best Hospice Quality Score|qualityScore/i.test(Q_CODE) === false
     || /no proprietary Best Hospice composite/i.test(Q_SRC),
     '13. no proprietary composite quality score is computed');
  ok(!/qualityScore|compositeScore|bhScore/.test(Q_CODE),
     '   …and no such field is emitted');
}

section('authenticated endpoint wiring');
{
  const route = SRC.match(/app\.get\('\/api\/provider-intelligence\/quality'[\s\S]*?\n\}\);/);
  ok(!!route, '14. /api/provider-intelligence/quality exists');
  ok(route && /requireProviderAuth/.test(route[0]), '15. it requires provider authentication');
  ok(route && /getProviderContext\(req\.providerUserId\)/.test(route[0]),
     '16. provider identity comes from the bearer token');
  ok(route && !/req\.(params|query|body)/.test(route[0]),
     '17. it accepts NO providerId from path, query or body — a session cannot be overridden');
  ok(route && /buildProviderCmsQuality\(prisma, ctx\.providerId\)/.test(route[0]),
     '18. it calls the shared quality service for the authenticated provider only');
  ok(route && !/create|update|delete|upsert/.test(route[0]), '19. read-only');
  ok(route && /res\.status\(401\)/.test(route[0]), '20. an unresolvable session gets 401, not data');

  const publicRoutes = SRC.match(/app\.get\('\/api\/public[\s\S]{0,400}/g) || [];
  ok(!publicRoutes.some((r) => /quality|Quality/.test(r)), '21. no public quality endpoint exists');
  ok(!/app\.get\('\/api\/provider-intelligence\/quality\/:/.test(SRC),
     '22. there is no parameterised quality route');

  const caps = SRC.match(/function providerIntelligenceCapabilities[\s\S]*?\n\}/);
  ok(caps && /cmsQuality: CMS_QUALITY_INTELLIGENCE_ENABLED/.test(caps[0]),
     '23. cmsQuality is gated on the release switch before care type is even consulted');
  ok(caps && /cmsRatings: cmsState/.test(caps[0]) && /cahps: cmsState/.test(caps[0]),
     '24. cmsRatings and cahps capabilities are UNCHANGED by this phase');
  ok(caps && /cmsMarketOverlap: cmsCovered/.test(caps[0]),
     '25. the My Market capability is unchanged');
  ok(caps && !/normalizeCareType/.test(caps[0]),
     '26. capability derivation still does not go through normalizeCareType');
}

// ============================ DATABASE TESTS =================================
const DB = process.env.TEST_DATABASE_URL;
(async () => {
  section('database-backed calculation');
  if (!DB) { console.log('\n--- database tests SKIPPED (set TEST_DATABASE_URL) ---'); return finish(); }
  if (/besthospice_db|besthospice_shadow|render\.com|dpg-/i.test(DB)) {
    console.log('  FAIL   TEST_DATABASE_URL looks like production or shadow'); fail++; return finish();
  }
  const { PrismaClient } = require('@prisma/client');
  const prisma = new PrismaClient({ datasources: { db: { url: DB } } });

  const REL = 'rel-q-test';
  const SRC_NAME = 'cms_hospice';
  const OWN = 'T00000';
  const PEER = ['T00001', 'T00002', 'T00003', 'T00004', 'T00005', 'T00006'];
  const FAR = 'T00099';                       // shares NO ZIP: must never be a peer
  const PROV = 'prov-q-test';

  const clean = () => prisma.$executeRawUnsafe(
    'TRUNCATE TABLE "CmsFacilityMeasure","CmsMeasureDefinition","CmsFacilityServiceArea","CmsFacility",'
    + '"CmsRelease","ProviderExternalIdentity","Provider" CASCADE');

  const facility = async (ccn, zips) => {
    const id = `fac-${ccn}`;
    await prisma.$executeRawUnsafe(
      `INSERT INTO "CmsFacility" ("id","source","ccn","name","address","city","state","zip",
         "firstSeenReleaseId","lastSeenReleaseId","createdAt","updatedAt")
       VALUES ($1,$2,$3,$4,'1 Synthetic Rd','Testville','ZZ','90001',$5,$5,NOW(),NOW())`,
      id, SRC_NAME, ccn, `SYNTHETIC FACILITY ${ccn}`, REL);
    for (const z of zips) {
      await prisma.$executeRawUnsafe(
        `INSERT INTO "CmsFacilityServiceArea" ("id","facilityId","source","zip",
           "firstSeenReleaseId","lastSeenReleaseId","createdAt")
         VALUES ($1,$2,$3,$4,$5,$5,NOW())`, crypto.randomUUID(), id, SRC_NAME, z, REL);
    }
    return id;
  };
  // value === null means "CMS suppressed it": stored as a row, never as a zero.
  const measure = (facId, code, value) => prisma.$executeRawUnsafe(
    `INSERT INTO "CmsFacilityMeasure" ("id","facilityId","source","measureCode","releaseId",
       "valueNumeric","valueRaw","suppressed","footnoteCodes","periodStart","periodEnd","createdAt","updatedAt")
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9::text[],'2023-01-01'::date,'2024-12-31'::date,NOW(),NOW())`,
    crypto.randomUUID(), facId, SRC_NAME, code, REL,
    value, value === null ? 'Not Available' : String(value), value === null, value === null ? ['1'] : []);

  try {
    await clean();
    await prisma.$executeRawUnsafe(
      `INSERT INTO "CmsRelease" ("id","source","releaseKey","capturedAt","ingestedAt","datasetCount","manifestSha256")
       VALUES ($1,$2,'2099-01-01',NOW(),NOW(),6,$3)`, REL, SRC_NAME, 'f'.repeat(64));

    // The real shipped definitions, so the directions under test are the ones we deploy.
    for (const m of MREG.measures) {
      await prisma.$executeRawUnsafe(
        `INSERT INTO "CmsMeasureDefinition" ("id","source","measureCode","cmsMeasureName","shortLabel",
           "dimension","family","valueKind","direction","scaleMin","scaleMax","decimals","unitLabel",
           "denominatorCode","surfaced","createdAt","updatedAt")
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,TRUE,NOW(),NOW())`,
        crypto.randomUUID(), SRC_NAME, m.measureCode, m.cmsMeasureName, m.shortLabel, m.dimension,
        m.family, m.valueKind, m.direction, m.scaleMin, m.scaleMax, m.decimals, m.unitLabel,
        m.denominatorCode);
    }

    const ownId = await facility(OWN, ['90001', '90002', '90003', '90004']);
    const peerIds = [];
    for (const c of PEER) peerIds.push(await facility(c, ['90001', '90005']));
    const farId = await facility(FAR, ['99999']);

    await prisma.$executeRawUnsafe(
      `INSERT INTO "Provider" (id,name,email,address,city,state,zip,lat,lon,"serviceRadiusKm","updatedAt","careType")
       VALUES ($1,'Synthetic Provider','synthetic@example.invalid','1 Synthetic Rd','Testville','ZZ','90001',
               0,0,50,NOW(),'hospice')`, PROV);
    await prisma.$executeRawUnsafe(
      `INSERT INTO "ProviderExternalIdentity" (id,"providerId",source,"externalId","identifierType",
         confidence,"verifiedAt","verifiedBy","updatedAt")
       VALUES ($1,$2,$3,$4,'ccn',0.99,NOW(),'Synthetic Test',NOW())`,
      crypto.randomUUID(), PROV, SRC_NAME, OWN);

    // ---- scenario 1 ----
    // higher-is-better, EXACTLY 5 comparable peers (the boundary that enables comparison)
    await measure(ownId, 'H_012_09_OBSERVED', 80);
    const hi = [10, 20, 30, 90, 95];
    for (let i = 0; i < 5; i++) await measure(peerIds[i], 'H_012_09_OBSERVED', hi[i]);
    await measure(peerIds[5], 'H_012_09_OBSERVED', null);          // suppressed: excluded
    await measure(farId, 'H_012_09_OBSERVED', 1);                  // non-overlapping: excluded

    // lower-is-better, 5 comparable peers
    await measure(ownId, 'H_012_02_OBSERVED', 20);
    const lo = [10, 30, 40, 50, 60];
    for (let i = 0; i < 5; i++) await measure(peerIds[i], 'H_012_02_OBSERVED', lo[i]);

    // lower-is-better with EXACTLY 4 comparable peers (the boundary that suppresses)
    await measure(ownId, 'H_012_03_OBSERVED', 5);
    const four = [10, 20, 30, 40];
    for (let i = 0; i < 4; i++) await measure(peerIds[i], 'H_012_03_OBSERVED', four[i]);
    await measure(peerIds[4], 'H_012_03_OBSERVED', null);
    await measure(peerIds[5], 'H_012_03_OBSERVED', null);

    // an exact tie on the median
    await measure(ownId, 'H_012_00_OBSERVED', 7);
    const tie = [5, 6, 7, 8, 9];
    for (let i = 0; i < 5; i++) await measure(peerIds[i], 'H_012_00_OBSERVED', tie[i]);

    // provider row ABSENT entirely; peers have values
    for (let i = 0; i < 5; i++) await measure(peerIds[i], 'H_011_01_OBSERVED', 50 + i * 10);

    // provider row PRESENT but suppressed; peers have values
    await measure(ownId, 'H_008_01_OBSERVED', null);
    for (let i = 0; i < 5; i++) await measure(peerIds[i], 'H_008_01_OBSERVED', 50 + i * 10);

    // lower-is-better where the provider is WORSE
    await measure(ownId, 'H_012_04_OBSERVED', 90);
    for (let i = 0; i < 5; i++) await measure(peerIds[i], 'H_012_04_OBSERVED', 10 + i * 10);

    // higher-is-better where the provider is WORSE
    await measure(ownId, 'H_012_10_OBSERVED', 10);
    for (let i = 0; i < 5; i++) await measure(peerIds[i], 'H_012_10_OBSERVED', 50 + i * 10);

    const q = await buildProviderCmsQuality(prisma, PROV);
    const M = Object.fromEntries((q.measures || []).map((m) => [m.measureCode, m]));

    section('resolution and market reuse');
    ok(q.status === S.RESOLVED, '27. a matched hospice with quality data resolves', q.status);
    ok(q.facility.ccn === OWN, '28. it resolves to the provider\'s own CMS facility');
    const mk = await buildProviderCmsMarket(prisma, PROV);
    ok(q.peerContext.overlappingFacilityCount === mk.market.overlappingFacilityCount,
       '29. the peer count EQUALS My Market\'s overlapping-hospice count',
       `${q.peerContext.overlappingFacilityCount} vs ${mk.market.overlappingFacilityCount}`);
    ok(q.peerContext.overlappingFacilityCount === 6,
       '30. all six ZIP-overlapping facilities are peers', String(q.peerContext.overlappingFacilityCount));
    ok(q.peerContext.providerZipCount === 4, '31. the provider ZIP count matches My Market');
    ok(q.freshness.qualityRelease.releaseKey === '2099-01-01',
       '32. the quality release is reported', q.freshness.qualityRelease.releaseKey);

    section('higher-is-better orientation');
    {
      const m = M.H_012_09_OBSERVED;
      ok(m.direction === 'higher_better', '33. the measure is higher-is-better', m.direction);
      ok(m.provider.value === 80, '34. the provider value is returned');
      ok(m.peers.comparableCount === 5,
         '35. EXACTLY 5 comparable peers — the suppressed one and the non-overlapping one are excluded',
         String(m.peers.comparableCount));
      ok(m.peers.median === 30, '36. the peer median is computed from the 5 comparable peers', String(m.peers.median));
      ok(m.comparisonAllowed === true, '37. exactly 5 peers ENABLES the comparison');
      ok(m.verdict === VERDICT.ABOVE, '38. 80 vs median 30 is positionally above', m.verdict);
      ok(m.favorable === true, '39. above the median on a higher-is-better measure is FAVOURABLE');
      ok(m.favorablePeerCount === 3,
         '40. the provider is higher than 3 of the 5 comparable peers', String(m.favorablePeerCount));
      ok(m.differenceFromPeerMedian === 50, '41. the difference from the peer median is signed and exact');
    }

    section('lower-is-better orientation — the inversion that must not be got wrong');
    {
      const m = M.H_012_02_OBSERVED;
      ok(m.direction === 'lower_better', '42. the measure is lower-is-better', m.direction);
      ok(m.peers.median === 40, '43. the peer median is 40', String(m.peers.median));
      ok(m.verdict === VERDICT.BELOW, '44. 20 vs median 40 is positionally BELOW', m.verdict);
      ok(m.favorable === true,
         '45. below the median on a lower-is-better measure is FAVOURABLE — verdict and favourability diverge');
      ok(m.favorablePeerCount === 4,
         '46. the provider is lower than 4 of the 5 comparable peers', String(m.favorablePeerCount));
      ok(m.differenceFromPeerMedian === -20, '47. the signed difference is negative');

      const w = M.H_012_04_OBSERVED;
      ok(w.direction === 'lower_better' && w.verdict === VERDICT.ABOVE,
         '48. a lower-is-better measure above the median is positionally above', w.verdict);
      ok(w.favorable === false, '49. …and is UNFAVOURABLE');
      const h = M.H_012_10_OBSERVED;
      ok(h.direction === 'higher_better' && h.verdict === VERDICT.BELOW && h.favorable === false,
         '50. a higher-is-better measure below the median is unfavourable');
    }

    section('minimum comparable peers');
    {
      const m = M.H_012_03_OBSERVED;
      ok(m.peers.comparableCount === 4, '51. exactly 4 comparable peers', String(m.peers.comparableCount));
      ok(m.verdict === VERDICT.INSUFFICIENT_PEERS, '52. 4 peers SUPPRESSES the comparison', m.verdict);
      ok(m.comparisonAllowed === false, '53. comparisonAllowed is false');
      ok(m.provider.value === 5, '54. the provider\'s own CMS value is STILL returned');
      ok(m.peers.median === null, '55. no peer median is published at 4 peers');
      ok(m.peers.min === null && m.peers.max === null,
         '   …and no peer range is published either');
      ok(m.peers.lowerThanProvider === null && m.peers.higherThanProvider === null,
         '   …and no directional peer counts are published');
      ok(m.peers.comparableCount === 4,
         '   …only the peer COUNT survives, so the UI can explain why');
      ok(m.favorable === null, '56. no favourability is claimed');
      ok(m.differenceFromPeerMedian === null, '57. no difference from median is claimed');
    }

    section('ties');
    {
      const m = M.H_012_00_OBSERVED;
      ok(m.provider.value === 7 && m.peers.median === 7, '58. the provider value equals the peer median');
      ok(m.verdict === VERDICT.AT, '59. an exact tie is at_peer_median', m.verdict);
      ok(m.favorable === null, '60. a tie claims neither better nor worse');
      ok(m.peers.equalToProvider === 1, '61. the tied peer is counted', String(m.peers.equalToProvider));
      ok(m.differenceFromPeerMedian === 0, '62. the difference is exactly zero');
      ok(!q.strengths.includes('H_012_00_OBSERVED') && !q.areasToReview.includes('H_012_00_OBSERVED'),
         '63. a tie appears in neither strengths nor areas to review');
    }

    section('missing and suppressed data is never zero');
    {
      const absent = M.H_011_01_OBSERVED;
      ok(absent.provider.value === null, '64. a measure with NO provider row yields a null value, not 0');
      ok(absent.provider.published === false, '   …and is marked unpublished');
      ok(absent.verdict === VERDICT.NOT_PUBLISHED, '65. its verdict is not_published', absent.verdict);
      ok(absent.peers === null, '66. no peer statistics are computed for it');
      ok(absent.favorable === null && absent.comparisonAllowed === false, '67. no comparison is claimed');

      const supp = M.H_008_01_OBSERVED;
      ok(supp.provider.value === null, '68. a SUPPRESSED provider row yields a null value, not 0');
      ok(supp.provider.suppressed === true, '   …and preserves the suppression flag');
      ok(supp.provider.valueRaw === 'Not Available', '69. the raw CMS text is preserved verbatim');
      ok(JSON.stringify(supp.provider.footnoteCodes) === '["1"]', '70. the CMS footnote is preserved');
      ok(supp.verdict === VERDICT.NOT_PUBLISHED, '71. its verdict is not_published');
      ok(!q.strengths.includes('H_008_01_OBSERVED') && !q.areasToReview.includes('H_008_01_OBSERVED'),
         '72. an unpublished measure is never ranked');

      // The suppressed peer on H_012_09 must not have been counted as a 0.
      ok(M.H_012_09_OBSERVED.peers.min === 10,
         '73. a suppressed PEER is excluded rather than counted as 0',
         String(M.H_012_09_OBSERVED.peers.min));
    }

    section('own facility and non-overlapping facilities excluded');
    {
      const m = M.H_012_09_OBSERVED;
      ok(m.peers.max === 95, '74. the provider\'s own value (80) is not in the peer maximum path');
      ok(m.peers.comparableCount === 5,
         '75. the peer count excludes the provider itself — 6 peers, 5 with published values');
      ok(m.peers.min !== 1, '76. the NON-overlapping facility\'s value (1) is excluded');
      const all = q.measures.every((x) => !x.peers || x.peers.comparableCount <= 6);
      ok(all, '77. no measure has more peers than the overlapping-facility count');
    }

    section('summary, strengths and areas to review');
    {
      ok(q.summary.careIndex && q.summary.careIndex.value === 7,
         '78. the collapsed-card Care Index comes from real CMS data');
      ok(q.summary.careIndex.scaleMax === 10, '79. its scale is 10');
      ok(q.summary.surfacedMeasureCount === MREG.measures.length,
         '80. every surfaced measure is reported', String(q.summary.surfacedMeasureCount));
      // Six measures carry a provider value; H_012_03 has only 4 comparable peers,
      // so exactly five are comparable.
      ok(q.summary.comparedMeasureCount === 5,
         '81. exactly the comparable measures are counted as compared', String(q.summary.comparedMeasureCount));
      // Eight measures have provider rows or peers; H_011_01 has no provider row
      // and H_008_01's is suppressed, so six are published.
      ok(q.summary.publishedMeasureCount === 6,
         '82. published counts the provider\'s own non-suppressed values', String(q.summary.publishedMeasureCount));
      ok(q.strengths.length + q.areasToReview.length + 1 === q.summary.comparedMeasureCount,
         '83. strengths + areas to review + the tie account for every compared measure',
         `${q.strengths.length}+${q.areasToReview.length}+1 vs ${q.summary.comparedMeasureCount}`);
      ok(q.strengths.every((c) => M[c].favorable === true),
         '84. every strength is direction-aware favourable');
      ok(q.areasToReview.every((c) => M[c].favorable === false),
         '85. every area to review is direction-aware unfavourable');
      ok(q.strengths.includes('H_012_02_OBSERVED'),
         '86. a lower-is-better measure BELOW the median is listed as a STRENGTH');
      ok(q.areasToReview.includes('H_012_04_OBSERVED'),
         '87. a lower-is-better measure ABOVE the median is listed as an AREA TO REVIEW');
      ok(q.summary.favorableCount === q.strengths.length
         && q.summary.unfavorableCount === q.areasToReview.length,
         '88. the summary counts agree with the lists');
    }

    section('methodology and disclaimers');
    {
      const m = q.methodology;
      ok(/Comparisons are calculated by Best Hospice from CMS-published measures/.test(m.peerDefinition),
         '89. the methodology states Best Hospice computes the comparison');
      ok(/CMS-reported service ZIP codes/.test(m.peerDefinition),
         '90. …from hospices sharing the provider\'s CMS-reported service ZIP codes');
      for (const claim of ['market share', 'patient volume', 'referral relationships', 'causation',
        'a proprietary Best Hospice quality rating']) {
        ok(m.notRepresenting.includes(claim), `91. the methodology disclaims "${claim}"`);
      }
      ok(m.minimumComparablePeers === 5, '92. the methodology publishes the 5-peer threshold');
      ok(/rank the raw measure value|carry no correction/.test(m.cmsPercentileExcluded),
         '93. the methodology explains why CMS percentiles are not used');
    }

    section('conditional family caregiver experience — ABSENT');
    {
      const dim = q.dimensions.find((d) => d.conditional === true);
      ok(!!dim, '94. the conditional dimension is returned even with no data');
      ok(dim.anyPublished === false, '95. it reports that nothing was published');
      ok(dim.message === CAHPS_UNPUBLISHED_MESSAGE,
         '96. it carries the exact agreed sentence', dim.message);
      ok(dim.message === 'CMS has not published a family caregiver survey result for this hospice.',
         '   …verbatim');
      ok(M.SUMMARY_STAR_RATING.verdict === VERDICT.NOT_PUBLISHED
         && M.SUMMARY_STAR_RATING.provider.value === null,
         '97. the star rating is not_published with a null value, never 0');
      ok(M.RECOMMEND_TBV.verdict === VERDICT.NOT_PUBLISHED, '98. the recommend measure is not_published');
    }

    section('conditional family caregiver experience — PRESENT');
    {
      await measure(ownId, 'SUMMARY_STAR_RATING', 4);
      for (let i = 0; i < 5; i++) await measure(peerIds[i], 'SUMMARY_STAR_RATING', i + 1);
      await measure(ownId, 'RECOMMEND_TBV', 88);
      for (let i = 0; i < 5; i++) await measure(peerIds[i], 'RECOMMEND_TBV', 60 + i * 5);
      const q2 = await buildProviderCmsQuality(prisma, PROV);
      const M2 = Object.fromEntries(q2.measures.map((m) => [m.measureCode, m]));
      const dim = q2.dimensions.find((d) => d.conditional === true);
      ok(dim.anyPublished === true, '99. the dimension now reports published data');
      ok(dim.message === null, '100. and carries no "not published" message');
      ok(M2.SUMMARY_STAR_RATING.provider.value === 4, '101. the star rating is returned');
      ok(M2.SUMMARY_STAR_RATING.peers.median === 3, '102. its peer median is computed', String(M2.SUMMARY_STAR_RATING.peers.median));
      ok(M2.SUMMARY_STAR_RATING.favorable === true, '103. 4 stars above a 3-star median is favourable');
      ok(M2.RECOMMEND_TBV.favorable === true, '104. 88% above a 70% median is favourable');
      ok(q2.summary.comparedMeasureCount === 7, '105. the compared count grows to include both CAHPS measures',
         String(q2.summary.comparedMeasureCount));
    }

    section('fail-closed states');
    {
      await prisma.$executeRawUnsafe(
        `INSERT INTO "Provider" (id,name,email,address,city,state,zip,lat,lon,"serviceRadiusKm","updatedAt","careType")
         VALUES ('prov-q-al','Synthetic AL','al@example.invalid','2 Synthetic Rd','Testville','ZZ','90001',
                 0,0,50,NOW(),'assisted-living')`);
      await prisma.$executeRawUnsafe(
        `INSERT INTO "Provider" (id,name,email,address,city,state,zip,lat,lon,"serviceRadiusKm","updatedAt","careType")
         VALUES ('prov-q-noid','Synthetic NoId','noid@example.invalid','3 Synthetic Rd','Testville','ZZ','90001',
                 0,0,50,NOW(),'hospice')`);
      await prisma.$executeRawUnsafe(
        `INSERT INTO "Provider" (id,name,email,address,city,state,zip,lat,lon,"serviceRadiusKm","updatedAt","careType")
         VALUES ('prov-q-dup','Synthetic Dup','dup@example.invalid','4 Synthetic Rd','Testville','ZZ','90001',
                 0,0,50,NOW(),'hospice')`);
      for (const ccn of ['T00001', 'T00002']) {
        await prisma.$executeRawUnsafe(
          `INSERT INTO "ProviderExternalIdentity" (id,"providerId",source,"externalId","identifierType",
             confidence,"verifiedAt","verifiedBy","updatedAt")
           VALUES ($1,'prov-q-dup',$2,$3,'ccn',0.9,NOW(),'Synthetic Test',NOW())`,
          crypto.randomUUID(), SRC_NAME, ccn);
      }

      for (const [id, want, label] of [
        [null, S.PROVIDER_NOT_FOUND, 'no provider id'],
        ['nope', S.PROVIDER_NOT_FOUND, 'an unknown provider id'],
        ['prov-q-al', S.UNSUPPORTED_CARE_TYPE, 'an unsupported care type'],
        ['prov-q-noid', S.NO_VERIFIED_IDENTITY, 'a hospice with no verified identity'],
        ['prov-q-dup', S.MULTIPLE_VERIFIED_IDENTITIES, 'a hospice with two verified identities']
      ]) {
        const r = await buildProviderCmsQuality(prisma, id);
        ok(r.status === want, `106. ${label} -> ${want}`, r.status);
        ok(r.measures === null && r.summary === null && r.dimensions === null,
           `     …and returns NO measures, summary or dimensions`);
        ok(r.strengths === null && r.areasToReview === null, '     …and no strengths or areas to review');
      }

      // A verified identity with no ingested facility.
      await prisma.$executeRawUnsafe(
        `INSERT INTO "Provider" (id,name,email,address,city,state,zip,lat,lon,"serviceRadiusKm","updatedAt","careType")
         VALUES ('prov-q-nofac','Synthetic NoFac','nf@example.invalid','5 Synthetic Rd','Testville','ZZ','90001',
                 0,0,50,NOW(),'hospice')`);
      await prisma.$executeRawUnsafe(
        `INSERT INTO "ProviderExternalIdentity" (id,"providerId",source,"externalId","identifierType",
           confidence,"verifiedAt","verifiedBy","updatedAt")
         VALUES ($1,'prov-q-nofac',$2,'T99999','ccn',0.9,NOW(),'Synthetic Test',NOW())`,
        crypto.randomUUID(), SRC_NAME);
      const nf = await buildProviderCmsQuality(prisma, 'prov-q-nofac');
      ok(nf.status === S.FACILITY_NOT_FOUND, '107. a verified identity with no ingested facility fails closed', nf.status);

      // No quality data at all for the source.
      await prisma.$executeRawUnsafe('DELETE FROM "CmsFacilityMeasure"');
      const nq = await buildProviderCmsQuality(prisma, PROV);
      ok(nq.status === S.NO_QUALITY_DATA, '108. no ingested quality release fails closed', nq.status);
      ok(nq.measures === null && nq.summary === null,
         '   …with no measures and no summary — nothing to expand');
    }

    section('bounded query count — no N+1 as the peer set grows');
    {
      // Rebuild scenario 1, then add 60 more overlapping peers with measurements.
      for (let i = 0; i < 5; i++) await measure(peerIds[i], 'H_012_09_OBSERVED', hi[i]);
      await measure(ownId, 'H_012_09_OBSERVED', 80);

      const counted = new PrismaClient({ datasources: { db: { url: DB } },
        log: [{ emit: 'event', level: 'query' }] });
      let n = 0;
      counted.$on('query', () => { n++; });
      // Prisma emits query events asynchronously, so let them settle before sampling.
      const settle = () => new Promise((r) => setTimeout(r, 50));

      await buildProviderCmsQuality(counted, PROV); await settle();
      n = 0;
      await buildProviderCmsQuality(counted, PROV); await settle();
      const small = n;
      const smallPeers = (await buildProviderCmsQuality(counted, PROV)).peerContext.overlappingFacilityCount;
      await settle();

      for (let i = 0; i < 60; i++) {
        const id = await facility(`T1${String(i).padStart(4, '0')}`, ['90001']);
        await measure(id, 'H_012_09_OBSERVED', 40 + (i % 20));
      }
      n = 0;
      const big = await buildProviderCmsQuality(counted, PROV); await settle();
      const bigCount = n;

      ok(big.peerContext.overlappingFacilityCount > smallPeers,
         '109. the peer population really did grow', `${smallPeers} -> ${big.peerContext.overlappingFacilityCount}`);
      ok(big.measures.find((m) => m.measureCode === 'H_012_09_OBSERVED').peers.comparableCount > 5,
         '110. the extra peers really are being compared');
      ok(small === bigCount,
         '111. DB round trips are CONSTANT as the peer set grows — no N+1', `${small} vs ${bigCount}`);
      ok(bigCount <= 14,
         '112. a full quality resolution stays within a small bounded query budget', `${bigCount} round trips`);
      await counted.$disconnect().catch(() => {});
    }

    await clean();
  } finally {
    await prisma.$disconnect().catch(() => {});
  }
  finish();
})().catch((e) => { console.error('\nharness failed:', e.message, '\n', e.stack); process.exit(1); });

function finish() {
  console.log(`\n${'='.repeat(60)}`);
  console.log(fail === 0 ? `PASSED — ${pass} assertions` : `FAILED — ${fail} of ${pass + fail} assertions failed`);
  process.exit(fail === 0 ? 0 : 1);
}
