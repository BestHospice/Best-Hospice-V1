#!/usr/bin/env node
/**
 * Guards My Market Phase 1 — CMS hospice service-area overlap.
 *
 * Overlap arithmetic and exclusion rules are proven against real rows in
 * disposable PostgreSQL. Endpoint wiring is checked by source inspection, because
 * this repo has no HTTP harness (same limitation as the CMS resolver suite).
 *
 * Every CCN and ZIP here is SYNTHETIC. CCN 121509, ISLANDS HOSPICE and the Hawaii
 * account appear nowhere.
 *
 *   TEST_DATABASE_URL=postgresql://user@localhost:5432/bh_market_test \
 *     node scripts/test-cms-hospice-market.js
 */
const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const SRC = fs.readFileSync(path.join(ROOT, 'server.js'), 'utf8');
const MARKET_SRC = fs.readFileSync(path.join(ROOT, 'cms-hospice-market.js'), 'utf8');
const MARKET_CODE = MARKET_SRC.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '');
const { buildProviderCmsMarket, CMS_MARKET_STATUS: S } = require(path.join(ROOT, 'cms-hospice-market.js'));

let pass = 0, fail = 0;
const ok = (c, label, detail) => {
  console.log(`  ${c ? 'ok  ' : 'FAIL'} ${label}${c || !detail ? '' : `  — ${detail}`}`);
  c ? pass++ : fail++;
};
const section = (t) => console.log(`\n--- ${t} ---`);

// ============================ STATIC AUDIT ===================================
section('reuse, no fuzzy matching, no production identifiers');
{
  ok(/require\('\.\/cms-provider-resolver'\)/.test(MARKET_CODE),
     '1. the market service REUSES cms-provider-resolver');
  ok(/resolveProviderCmsContext\(prisma, providerId\)/.test(MARKET_CODE),
     '   …and calls the resolver rather than reimplementing identity lookup');
  ok(!/providerExternalIdentity/i.test(MARKET_CODE),
     '2. it never queries ProviderExternalIdentity directly');
  for (const [re, label] of [
    [/ILIKE|ilike|similarity|levenshtein|soundex/, 'no fuzzy SQL matching'],
    [/f\.name\s*=|name\s*ILIKE/, 'no facility-name matching'],
    [/f\.city\s*=|f\.state\s*=/, 'no city/state market fallback'],
    [/serviceRadiusKm|haversine|distance|mileage/, 'no distance/radius logic'],
    [/billingMode|subscriptionStatus|planTier|stripe/i, 'no billing or subscription input'],
    [/internalRole|isInternalProvider/, 'no internalRole special-casing'],
    [/INSERT|UPDATE|DELETE|create\(|update\(|delete\(/, 'no writes']
  ]) ok(!re.test(MARKET_CODE), `3. ${label}`);
  for (const bad of ['121509', 'ISLANDS HOSPICE', 'c3f7379c', 'Vrablic', 'besthospice_db', 'dpg-']) {
    ok(!MARKET_SRC.includes(bad), `4. no production identifier "${bad}"`);
  }
  ok(/cms_hospice/.test(MARKET_CODE) && /MARKET_SOURCE/.test(MARKET_CODE),
     '5. the market source is pinned to cms_hospice');
  // Bounded query count: no loop may issue a query.
  ok(!/for\s*\([^)]*\)\s*\{[^}]*await prisma/.test(MARKET_CODE)
     && !/\.map\(\s*async/.test(MARKET_CODE)
     && !/forEach\(\s*async/.test(MARKET_CODE),
     '6. no query inside any loop — N+1 is structurally impossible');
  // Bounded, constant query count. Three appear in source: the two aggregates,
  // plus the as-of validation query. The DEFAULT path runs exactly TWO - it
  // derives the release anchor inline in an `anchor` CTE - so no shipped module's
  // query budget changed. Only as-of mode runs the third, and only as-of mode
  // needs it: it is the one case where a CALLER supplies a release id that may
  // not exist, and it must fail closed rather than silently return a zeroed
  // market. Assertion 6 remains the structural N+1 guard.
  ok((MARKET_CODE.match(/prisma\.\$queryRaw/g) || []).length === 3,
     '7. three SQL queries in source — two aggregates + the as-of validation',
     String((MARKET_CODE.match(/prisma\.\$queryRaw/g) || []).length));
  ok(!/\$queryRawUnsafe|queryRawUnsafe/.test(MARKET_CODE),
     '8. parameterised tagged templates only — no queryRawUnsafe');
  ok(!/\$\{(?!source|ccn|asOfReleaseKey|asOfReleaseId)/.test(MARKET_SRC.match(/\$queryRaw`[\s\S]*?`/g).join('')),
     '   …and only source/ccn/asOfReleaseKey/asOfReleaseId are interpolated, all bound parameters');
}

section('authenticated endpoint wiring');
{
  const route = SRC.match(/app\.get\('\/api\/provider-intelligence\/my-market'[\s\S]*?\n\}\);/);
  ok(!!route, '9. /api/provider-intelligence/my-market exists');
  ok(route && /requireProviderAuth/.test(route[0]), '10. it requires provider authentication');
  ok(route && /getProviderContext\(req\.providerUserId\)/.test(route[0]),
     '11. provider identity comes from the bearer token');
  ok(route && !/req\.(params|query|body)/.test(route[0]),
     '12. it accepts NO providerId from path, query or body');
  ok(route && /buildProviderCmsMarket\(prisma, ctx\.providerId\)/.test(route[0]),
     '13. it calls the shared market service for the authenticated provider only');
  ok(route && !/create|update|delete|upsert/.test(route[0]), '14. read-only');
  const publicRoutes = SRC.match(/app\.get\('\/api\/public[\s\S]{0,400}/g) || [];
  ok(!publicRoutes.some((r) => /market|Market|cms|Cms/.test(r)), '15. no public market endpoint exists');
}

section('Market Intelligence capabilities unchanged');
{
  const caps = SRC.match(/function providerIntelligenceCapabilities[\s\S]*?\n\}/)[0];
  const cmsState = caps.match(/const cmsState = [\s\S]*?;\n/);
  ok(cmsState && !/'available'/.test(cmsState[0]), '16. cmsState still cannot yield available');
  for (const m of ['competitorBenchmarking', 'geographicDemand', 'marketOpportunity', 'reports']) {
    ok(new RegExp(`${m}: \\{\\s*\\n\\s*status: 'coming_soon'`).test(caps), `17. ${m} still coming_soon`);
  }
  const html = fs.readFileSync(path.join(ROOT, 'provider-intelligence.html'), 'utf8');
  // Phase 2 deliberately wires My Market into the UI. The raw resolver endpoint
  // stays unconsumed, and no capability above was flipped.
  ok(/\/api\/provider-intelligence\/my-market/.test(html),
     '18. provider-intelligence.html consumes the My Market endpoint (Phase 2)');
  ok(!/cms-context/.test(html), '   …and still does not consume the raw resolver endpoint');
}

// ============================ DATABASE BEHAVIOUR =============================
const DB = process.env.TEST_DATABASE_URL;
(async () => {
  if (!DB) { console.log('\n--- database tests SKIPPED (set TEST_DATABASE_URL) ---'); return finish(); }
  if (/besthospice_db|dpg-d5hhmb4hg0os7380cecg-a|besthospice_shadow_2|dpg-d60g7h0gjchc73f306j0-a|render\.com/i.test(DB)) {
    console.log('  FAIL   TEST_DATABASE_URL looks like production or shadow'); fail++; return finish();
  }
  const { PrismaClient } = require('@prisma/client');
  const prisma = new PrismaClient({ datasources: { db: { url: DB } } });
  const uuid = () => require('crypto').randomUUID();

  const CCN = { A: 'M70001', B: 'M70002', C: 'M70003', D: 'M70004', E: 'M70005',
                TWIN1: 'M70006', TWIN2: 'M70007', EMPTY: 'M70008' };
  let relH, relHH;

  const mkProvider = (id, over = {}) => prisma.provider.create({ data: {
    id, name: `Provider ${id}`, email: `${id}@example.test`, address: '1 Main St',
    city: 'Testville', state: 'AZ', zip: '85001', lat: 33, lon: -112,
    serviceRadiusKm: 100, careType: 'hospice', ...over } });
  const mkIdentity = (providerId, ccn, over = {}) => prisma.providerExternalIdentity.create({ data: {
    id: uuid(), providerId, source: 'cms_hospice', externalId: ccn, identifierType: 'ccn',
    verifiedAt: new Date('2026-08-31T00:00:00Z'), verifiedBy: 'test-suite', ...over } });
  const mkFacility = async (ccn, name, zips, src = 'cms_hospice', city = 'Testville', state = 'AZ') => {
    const rel = src === 'cms_hospice' ? relH : relHH;
    const f = await prisma.cmsFacility.create({ data: { id: uuid(), source: src, ccn, name,
      address: '9 Fixture Way', city, state, zip: '85001',
      firstSeenReleaseId: rel.id, lastSeenReleaseId: rel.id } });
    for (const zip of zips) {
      await prisma.cmsFacilityServiceArea.create({ data: { id: uuid(), facilityId: f.id,
        source: src, zip, firstSeenReleaseId: rel.id, lastSeenReleaseId: rel.id } });
    }
    return f;
  };

  try {
    await prisma.$executeRawUnsafe(
      'TRUNCATE TABLE "CmsFacilityServiceArea","CmsFacility","CmsRelease","ProviderExternalIdentity","Provider" CASCADE');
    relH = await prisma.cmsRelease.create({ data: { id: uuid(), source: 'cms_hospice',
      releaseKey: '2026-08-19', capturedAt: new Date('2026-08-19T00:00:00Z'), datasetCount: 6 } });
    relHH = await prisma.cmsRelease.create({ data: { id: uuid(), source: 'cms_home_health',
      releaseKey: '2026-08-19', capturedAt: new Date('2026-08-19T00:00:00Z'), datasetCount: 5 } });

    // The fixture from the brief.
    await mkFacility(CCN.A, 'FACILITY A', ['11111', '11112', '11113', '11114']);
    await mkFacility(CCN.B, 'FACILITY B', ['11111', '11112', '11113']);
    await mkFacility(CCN.C, 'FACILITY C', ['11113', '11114', '22222']);
    await mkFacility(CCN.D, 'FACILITY D', ['33333']);
    await mkFacility(CCN.E, 'FACILITY E OTHER SOURCE', ['11111', '11112', '11113', '11114'], 'cms_home_health');

    await mkProvider('p-a'); await mkIdentity('p-a', CCN.A);
    const m = await buildProviderCmsMarket(prisma, 'p-a');

    section('database: the brief fixture');
    ok(m.status === S.RESOLVED, '19. market resolves', m.status);
    ok(m.market.providerZipCount === 4, '20. providerZipCount = 4', String(m.market.providerZipCount));
    ok(m.market.overlappingFacilityCount === 2, '21. overlappingFacilityCount = 2', String(m.market.overlappingFacilityCount));
    ok(m.market.totalSharedZipRelationships === 5, '22. totalSharedZipRelationships = 5', String(m.market.totalSharedZipRelationships));
    ok(m.market.highestOverlapSharedZipCount === 3, '23. highestOverlapSharedZipCount = 3', String(m.market.highestOverlapSharedZipCount));
    ok(m.market.averageCompetitorsPerProviderZip === 1.25, '24. averageCompetitorsPerProviderZip = 1.25',
       String(m.market.averageCompetitorsPerProviderZip));

    const ccns = m.competitors.map((c) => c.ccn);
    ok(!ccns.includes(CCN.A), '25. the provider\'s OWN facility is excluded');
    ok(!ccns.includes(CCN.D), '26. a facility with zero shared ZIPs is excluded');
    ok(!ccns.includes(CCN.E), '27. a same-ZIP facility from ANOTHER CMS source is excluded');
    ok(!m.competitors.some((c) => c.source !== 'cms_hospice'), '   …every competitor is cms_hospice');

    const B = m.competitors.find((c) => c.ccn === CCN.B);
    const C = m.competitors.find((c) => c.ccn === CCN.C);
    ok(B && B.sharedZipCount === 3, '28. B sharedZipCount = 3', B && String(B.sharedZipCount));
    ok(B && B.providerZipCount === 4, '29. B providerZipCount = 4');
    ok(B && B.competitorZipCount === 3, '30. B competitorZipCount = 3', B && String(B.competitorZipCount));
    ok(B && B.providerOverlapPct === 75.00, '31. B providerOverlapPct = 75.00', B && String(B.providerOverlapPct));
    ok(B && B.competitorOverlapPct === 100.00, '32. B competitorOverlapPct = 100.00', B && String(B.competitorOverlapPct));
    ok(C && C.sharedZipCount === 2, '33. C sharedZipCount = 2', C && String(C.sharedZipCount));
    ok(C && C.competitorZipCount === 3, '34. C competitorZipCount = 3');
    ok(C && C.providerOverlapPct === 50.00, '35. C providerOverlapPct = 50.00', C && String(C.providerOverlapPct));
    ok(C && C.competitorOverlapPct === 66.67, '36. C competitorOverlapPct = 66.67 (2dp, deterministic)',
       C && String(C.competitorOverlapPct));
    ok(JSON.stringify(B.sharedZips) === JSON.stringify(['11111', '11112', '11113']),
       '37. B sharedZips sorted deterministically', JSON.stringify(B && B.sharedZips));
    ok(JSON.stringify(C.sharedZips) === JSON.stringify(['11113', '11114']),
       '38. C sharedZips sorted deterministically', JSON.stringify(C && C.sharedZips));
    ok(ccns[0] === CCN.B && ccns[1] === CCN.C, '39. ranked by sharedZipCount DESC', ccns.join(','));
    ok(JSON.stringify(m.zipDensity) === JSON.stringify([
      { zip: '11111', competitorCount: 1 }, { zip: '11112', competitorCount: 1 },
      { zip: '11113', competitorCount: 2 }, { zip: '11114', competitorCount: 1 }]),
      '40. per-ZIP density correct and ordered', JSON.stringify(m.zipDensity));
    ok(m.competitors.every((c) => typeof c.sharedZips[0] === 'string'), '41. ZIPs remain strings');

    section('database: identity distinctness and no name dedupe');
    await mkFacility(CCN.TWIN1, 'IDENTICAL NAME HOSPICE', ['11111']);
    await mkFacility(CCN.TWIN2, 'IDENTICAL NAME HOSPICE', ['11111']);
    const m2 = await buildProviderCmsMarket(prisma, 'p-a');
    const twins = m2.competitors.filter((c) => c.name === 'IDENTICAL NAME HOSPICE');
    ok(twins.length === 2, '42. two facilities with IDENTICAL names stay distinct', String(twins.length));
    ok(twins[0].ccn !== twins[1].ccn, '   …identified by CCN, never by name');
    ok(twins[0].ccn === CCN.TWIN1 && twins[1].ccn === CCN.TWIN2,
       '43. equal-rank ties break by name then CCN ascending', twins.map((t) => t.ccn).join(','));

    section('database: fail-closed states');
    const cases = [];
    await mkProvider('p-none');
    cases.push(['p-none', S.NO_VERIFIED_IDENTITY, '44. no identity -> no_verified_identity']);
    await mkProvider('p-unver'); await mkIdentity('p-unver', 'M70100', { verifiedAt: null });
    cases.push(['p-unver', S.NO_VERIFIED_IDENTITY, '45. unverified identity -> no_verified_identity']);
    await mkProvider('p-ambig'); await mkIdentity('p-ambig', 'M70101'); await mkIdentity('p-ambig', 'M70102');
    cases.push(['p-ambig', S.MULTIPLE_VERIFIED_IDENTITIES, '46. two identities -> multiple_verified_identities']);
    await mkProvider('p-orph'); await mkIdentity('p-orph', 'M70199');
    cases.push(['p-orph', S.FACILITY_NOT_FOUND, '47. no ingested facility -> facility_not_found']);
    await mkProvider('p-pall', { careType: 'palliative' }); await mkIdentity('p-pall', 'M70103');
    cases.push(['p-pall', S.UNSUPPORTED_CARE_TYPE, '48. palliative -> unsupported_care_type']);
    await mkProvider('p-home', { careType: 'home-care' }); await mkIdentity('p-home', 'M70104');
    cases.push(['p-home', S.UNSUPPORTED_CARE_TYPE, '49. home-care -> unsupported_care_type (no hospice default)']);
    cases.push(['nope', S.PROVIDER_NOT_FOUND, '50. unknown provider -> provider_not_found']);
    for (const [pid, want, label] of cases) {
      const r = await buildProviderCmsMarket(prisma, pid);
      ok(r.status === want, label, r.status);
      ok(r.competitors === null && r.market === null && r.zipDensity === null,
         `    …${want} carries no market payload`);
    }

    await mkFacility(CCN.EMPTY, 'NO SERVICE AREA HOSPICE', []);
    await mkProvider('p-empty'); await mkIdentity('p-empty', CCN.EMPTY);
    const rEmpty = await buildProviderCmsMarket(prisma, 'p-empty');
    ok(rEmpty.status === S.NO_SERVICE_AREA, '51. zero service ZIPs -> no_service_area', rEmpty.status);
    ok(rEmpty.competitors === null, '   …and no market is invented from city/state');
    ok(rEmpty.facility !== null && rEmpty.facility.ccn === CCN.EMPTY,
       '   …but the resolved facility is still reported');

    section('database: internalRole neutrality');
    const baseline = await buildProviderCmsMarket(prisma, 'p-a');
    await prisma.providerExternalIdentity.deleteMany({ where: { providerId: 'p-a' } });
    await mkProvider('p-int', { internalRole: 'cms_reference', name: 'test' });
    await mkIdentity('p-int', CCN.A);
    const internal = await buildProviderCmsMarket(prisma, 'p-int');
    ok(internal.status === S.RESOLVED, '52. cms_reference provider resolves a market', internal.status);
    ok(JSON.stringify(internal.market) === JSON.stringify(baseline.market)
       && JSON.stringify(internal.competitors) === JSON.stringify(baseline.competitors)
       && JSON.stringify(internal.zipDensity) === JSON.stringify(baseline.zipDensity),
       '53. internal and normal providers get IDENTICAL market intelligence');
    await mkProvider('p-int2', { internalRole: 'cms_reference' });
    const noIdent = await buildProviderCmsMarket(prisma, 'p-int2');
    ok(noIdent.status === S.NO_VERIFIED_IDENTITY,
       '54. cms_reference alone grants NO market access', noIdent.status);

    section('database: no leakage, freshness, determinism');
    ok(JSON.stringify(Object.keys(internal.provider).sort()) === '["id","name"]',
       '55. provider payload is only id and name', Object.keys(internal.provider).join(','));
    const blob = JSON.stringify(internal);
    for (const leak of ['email', 'stripe', 'billingMode', 'subscriptionStatus', 'planTier',
                        'internalRole', 'providerLoginEmail', 'serviceRadiusKm', 'verifiedBy']) {
      ok(!blob.includes(leak), `56. no "${leak}" anywhere in the response`);
    }
    ok(internal.freshness && internal.freshness.lastSeen.releaseKey === '2026-08-19'
       && internal.freshness.currentInLatestRelease === true,
       '57. freshness comes from the resolver unchanged', JSON.stringify(internal.freshness));
    const again = await buildProviderCmsMarket(prisma, 'p-int');
    ok(JSON.stringify(again) === JSON.stringify(internal), '58. output is byte-stable across calls');

    section('database: bounded query count (N+1 guard)');
    {
      // Count real round trips, then double the competitor population and count
      // again. If the count grows with competitors, the implementation is N+1.
      const counted = new PrismaClient({ datasources: { db: { url: DB } },
        log: [{ emit: 'event', level: 'query' }] });
      let n = 0; counted.$on('query', () => { n += 1; });
      for (let i = 0; i < 12; i++) await mkFacility(`M713${String(i).padStart(2, '0')}`, `SCALE ${i}`, ['11111', '11112']);
      await counted.$queryRawUnsafe('SELECT 1');
      // Prisma emits 'query' events asynchronously, so the counter can be short
      // by one if it is read in the same tick the promise settles. Flush the
      // event loop before sampling, or this assertion flakes.
      const settle = () => new Promise((r) => setTimeout(r, 50));
      n = 0; const small = await buildProviderCmsMarket(counted, 'p-int');
      await settle();
      const roundTripsSmall = n;
      for (let i = 12; i < 40; i++) await mkFacility(`M713${String(i).padStart(2, '0')}`, `SCALE ${i}`, ['11111', '11112']);
      n = 0; const big = await buildProviderCmsMarket(counted, 'p-int');
      await settle();
      const roundTripsBig = n;
      ok(big.competitors.length > small.competitors.length,
         '59. the competitor population really did grow',
         `${small.competitors.length} -> ${big.competitors.length}`);
      ok(roundTripsSmall === roundTripsBig,
         '60. DB round trips are CONSTANT as competitors grow — no N+1',
         `${roundTripsSmall} vs ${roundTripsBig}`);
      ok(roundTripsBig <= 12,
         '61. a successful market resolution stays within a small bounded query budget',
         `${roundTripsBig} round trips`);
      await counted.$disconnect().catch(() => {});
    }

    // ================= CURRENT-MARKET RELEASE PREDICATE =================
    // My Market answers "which CMS facilities CURRENTLY overlap my market?".
    //
    // CmsFacilityServiceArea rows are never deleted when a facility stops
    // appearing in CMS - "current" is a query, not a stored flag - so without a
    // latest-release predicate a facility that has left the roster keeps its
    // persisted service-area rows and is still counted as a current competitor.
    // With one release that is unobservable, because every row's
    // lastSeenReleaseId IS the latest release. It only appears from the second
    // ingest onward, which is why this is fixed before the next one.
    section('current-market release predicate (two releases)');
    {
      await prisma.$executeRawUnsafe(
        'TRUNCATE TABLE "CmsFacilityServiceArea","CmsFacility","CmsRelease","ProviderExternalIdentity","Provider" CASCADE');

      const r1 = await prisma.cmsRelease.create({ data: { id: uuid(), source: 'cms_hospice',
        releaseKey: '2026-05-01', capturedAt: new Date('2026-05-01T00:00:00Z'), datasetCount: 6 } });
      const r2 = await prisma.cmsRelease.create({ data: { id: uuid(), source: 'cms_hospice',
        releaseKey: '2026-08-19', capturedAt: new Date('2026-08-19T00:00:00Z'), datasetCount: 6 } });

      // firstSeen/lastSeen are set explicitly here, exactly as the importer would
      // leave them: the upsert advances lastSeenReleaseId for facilities present
      // in the new release and leaves it untouched for those absent from it.
      const mkAt = async (ccn, name, zips, firstRel, lastRel) => {
        const f = await prisma.cmsFacility.create({ data: { id: uuid(), source: 'cms_hospice',
          ccn, name, address: '1 MAIN ST', city: 'PHOENIX', state: 'AZ', zip: '85016',
          county: 'MARICOPA', phone: '(602) 555-0100', ownershipType: 'For-Profit',
          firstSeenReleaseId: firstRel.id, lastSeenReleaseId: lastRel.id } });
        for (const zip of zips) {
          await prisma.cmsFacilityServiceArea.create({ data: { id: uuid(), facilityId: f.id,
            source: 'cms_hospice', zip, firstSeenReleaseId: firstRel.id, lastSeenReleaseId: lastRel.id } });
        }
        return f;
      };

      const OWNC = 'M72000';   // the provider's own facility, present in both
      const AC = 'M72001';     // present R1 and R2  -> CURRENT competitor
      const BC = 'M72002';     // present R1, ABSENT R2 -> roster-departed
      const NC = 'M72003';     // first appears in R2 -> CURRENT competitor
      await mkAt(OWNC, 'OWN HOSPICE', ['11111', '11112'], r1, r2);
      await mkAt(AC, 'FACILITY A CURRENT', ['11111', '11112'], r1, r2);
      await mkAt(BC, 'FACILITY B DEPARTED', ['11111', '11112'], r1, r1);
      await mkAt(NC, 'FACILITY N NEW IN R2', ['11111'], r2, r2);

      await mkProvider('p-pred'); await mkIdentity('p-pred', OWNC);
      const m = await buildProviderCmsMarket(prisma, 'p-pred');
      const ccns = m.competitors.map((c) => c.ccn);

      ok(m.status === S.RESOLVED, '62. two-release market resolves', m.status);
      ok(ccns.includes(AC), '63. a facility present in the latest release is INCLUDED');
      ok(ccns.includes(NC), '64. a facility first appearing in the latest release is INCLUDED');
      // THE DEFECT. Pre-fix this fails: B is counted despite having left the roster.
      ok(!ccns.includes(BC),
         '65. a roster-departed facility whose OLD service-area rows remain is EXCLUDED',
         `competitors = ${ccns.join(',')}`);
      ok(m.market.overlappingFacilityCount === 2,
         '66. overlappingFacilityCount counts only current facilities',
         String(m.market.overlappingFacilityCount));
      ok(m.market.totalSharedZipRelationships === 3,
         '67. totalSharedZipRelationships excludes departed overlap (2 + 1)',
         String(m.market.totalSharedZipRelationships));
      ok(m.market.highestOverlapSharedZipCount === 2,
         '68. highestOverlapSharedZipCount excludes the departed facility',
         String(m.market.highestOverlapSharedZipCount));
      {
        const z11111 = m.zipDensity.find((z) => z.zip === '11111');
        const z11112 = m.zipDensity.find((z) => z.zip === '11112');
        ok(z11111 && z11111.competitorCount === 2,
           '69. zipDensity 11111 counts only current competitors (A + N)',
           z11111 && String(z11111.competitorCount));
        ok(z11112 && z11112.competitorCount === 1,
           '70. zipDensity 11112 counts only current competitors (A)',
           z11112 && String(z11112.competitorCount));
      }
      ok(m.market.averageCompetitorsPerProviderZip === 1.5,
         '71. averageCompetitorsPerProviderZip reflects current density only',
         String(m.market.averageCompetitorsPerProviderZip));
      ok(!ccns.includes(OWNC), '72. the provider\'s own facility is still excluded');

      // HISTORY IS NOT DELETED. The correction is a read-time predicate; the
      // departed facility and its service-area rows must remain stored, because
      // CmsFacilityObservation-based change detection depends on them.
      const bRow = await prisma.cmsFacility.findFirst({ where: { ccn: BC } });
      ok(bRow != null, '73. the roster-departed facility row is RETAINED, not deleted');
      ok(bRow.lastSeenReleaseId === r1.id,
         '74. …and still carries its OLD lastSeenReleaseId', bRow && bRow.lastSeenReleaseId);
      const bSas = await prisma.cmsFacilityServiceArea.count({ where: { facilityId: bRow.id } });
      ok(bSas === 2, '75. its historical service-area rows are RETAINED', String(bSas));
      const bSaStale = await prisma.cmsFacilityServiceArea.count({
        where: { facilityId: bRow.id, lastSeenReleaseId: r1.id } });
      ok(bSaStale === 2, '76. …still stamped with the older release', String(bSaStale));

      // NEGATIVE CONTROL. The predicate must be load-bearing, not incidental:
      // advance B's rows to the latest release and it must reappear.
      await prisma.$executeRawUnsafe(
        `UPDATE "CmsFacilityServiceArea" SET "lastSeenReleaseId" = $1 WHERE "facilityId" = $2`,
        r2.id, bRow.id);
      await prisma.$executeRawUnsafe(
        `UPDATE "CmsFacility" SET "lastSeenReleaseId" = $1 WHERE id = $2`, r2.id, bRow.id);
      const m2 = await buildProviderCmsMarket(prisma, 'p-pred');
      ok(m2.competitors.map((c) => c.ccn).includes(BC),
         '77. CONTROL: once its rows carry the latest release, B is included again',
         m2.competitors.map((c) => c.ccn).join(','));
      ok(m2.market.overlappingFacilityCount === 3,
         '78. CONTROL: the count moves to 3, proving the predicate decided it',
         String(m2.market.overlappingFacilityCount));

      // Latest-release selection must not come from CMS `modified`, and must not
      // be able to pick a release that no current row references - that would
      // zero the market. A newer release with NO facility/service-area rows must
      // be ignored entirely.
      await prisma.cmsRelease.create({ data: { id: uuid(), source: 'cms_hospice',
        releaseKey: '2026-12-31', capturedAt: new Date('2026-12-31T00:00:00Z'), datasetCount: 6 } });
      const m3 = await buildProviderCmsMarket(prisma, 'p-pred');
      ok(m3.status === S.RESOLVED && m3.market.overlappingFacilityCount === 3,
         '79. a newer release with NO current rows does not zero the market',
         `${m3.status} / ${m3.market && m3.market.overlappingFacilityCount}`);
      ok(!/modified/.test(MARKET_CODE),
         '80. latest-release selection never consults CMS `modified`');
    }

    // ============== AS-OF RELEASE MEMBERSHIP (interval semantics) ==========
    // Same algorithm, different anchor: "current" is just "as of the latest
    // represented release". These prove the interval predicate directly, on
    // service-area rows stamped per release exactly as the importer leaves them.
    section('as-of release market membership');
    {
      await prisma.$executeRawUnsafe(
        'TRUNCATE TABLE "CmsFacilityServiceArea","CmsFacility","CmsRelease","ProviderExternalIdentity","Provider" CASCADE');

      const r1 = await prisma.cmsRelease.create({ data: { id: uuid(), source: 'cms_hospice',
        releaseKey: '2026-05-01', capturedAt: new Date('2026-05-01T00:00:00Z'), datasetCount: 6 } });
      const r2 = await prisma.cmsRelease.create({ data: { id: uuid(), source: 'cms_hospice',
        releaseKey: '2026-08-19', capturedAt: new Date('2026-08-19T00:00:00Z'), datasetCount: 6 } });
      const rHH = await prisma.cmsRelease.create({ data: { id: uuid(), source: 'cms_home_health',
        releaseKey: '2026-08-19', capturedAt: new Date('2026-08-19T00:00:00Z'), datasetCount: 5 } });

      const mkAt = async (ccn, zips, firstRel, lastRel) => {
        const f = await prisma.cmsFacility.create({ data: { id: uuid(), source: 'cms_hospice',
          ccn, name: 'H ' + ccn, address: '1 MAIN ST', city: 'PHOENIX', state: 'AZ', zip: '85016',
          county: 'MARICOPA', ownershipType: 'For-Profit',
          firstSeenReleaseId: firstRel.id, lastSeenReleaseId: lastRel.id } });
        for (const zip of zips) {
          await prisma.cmsFacilityServiceArea.create({ data: { id: uuid(), facilityId: f.id,
            source: 'cms_hospice', zip, firstSeenReleaseId: firstRel.id, lastSeenReleaseId: lastRel.id } });
        }
        return f;
      };

      const O = 'M73000';          // own, spans R1-R2
      const SPAN = 'M73001';       // firstSeen R1, lastSeen R2  -> both
      const ONLY1 = 'M73002';      // firstSeen R1, lastSeen R1  -> R1 only
      const ONLY2 = 'M73003';      // firstSeen R2, lastSeen R2  -> R2 only
      await mkAt(O, ['11111', '11112'], r1, r2);
      await mkAt(SPAN, ['11111', '11112'], r1, r2);
      await mkAt(ONLY1, ['11111', '11112'], r1, r1);
      await mkAt(ONLY2, ['11111'], r2, r2);
      await mkProvider('p-asof'); await mkIdentity('p-asof', O);

      const at = async (opts) => {
        const m = await buildProviderCmsMarket(prisma, 'p-asof', opts);
        return { status: m.status, ccns: (m.competitors || []).map((c) => c.ccn).sort(), m };
      };

      const cur = await at(undefined);
      const a1 = await at({ asOfReleaseId: r1.id });
      const a2 = await at({ asOfReleaseId: r2.id });

      ok(cur.status === S.RESOLVED && JSON.stringify(cur.ccns) === JSON.stringify([SPAN, ONLY2].sort()),
         '81. DEFAULT (current) = spanning + latest-only; the R1-only facility is excluded',
         cur.ccns.join(','));
      ok(JSON.stringify(a1.ccns) === JSON.stringify([ONLY1, SPAN].sort()),
         '82. as-of R1 = spanning + R1-only; the R2-only facility is excluded', a1.ccns.join(','));
      ok(JSON.stringify(a2.ccns) === JSON.stringify([SPAN, ONLY2].sort()),
         '83. as-of R2 = spanning + R2-only; the R1-only facility is excluded', a2.ccns.join(','));
      ok(JSON.stringify(a2.ccns) === JSON.stringify(cur.ccns),
         '84. as-of the latest represented release == the default answer (one algorithm)');
      ok(a1.ccns.includes(ONLY1) && !a2.ccns.includes(ONLY1),
         '85. firstSeen=R1,lastSeen=R1 → included as-of R1, EXCLUDED as-of R2');
      ok(!a1.ccns.includes(ONLY2) && a2.ccns.includes(ONLY2),
         '86. firstSeen=R2,lastSeen=R2 → EXCLUDED as-of R1, included as-of R2');
      ok(a1.ccns.includes(SPAN) && a2.ccns.includes(SPAN),
         '87. firstSeen=R1,lastSeen=R2 → included at BOTH');
      {
        const union = [...new Set([...a1.ccns, ...a2.ccns])].sort();
        ok(JSON.stringify(union) === JSON.stringify([ONLY1, ONLY2, SPAN].sort()),
           '88. union(as-of R1, as-of R2) is the full comparison universe', union.join(','));
      }
      // Fail closed. A caller asking about a release we cannot honour must get an
      // error, never a silent fall back to a different question's answer.
      {
        const bad = await at({ asOfReleaseId: '00000000-0000-0000-0000-000000000000' });
        ok(bad.status === S.INVALID_AS_OF_RELEASE,
           '89. a nonexistent asOfReleaseId FAILS CLOSED', bad.status);
        ok(bad.m.market === null && bad.m.competitors === null,
           '90. …and returns no market rather than current-market data');
        const wrongSource = await at({ asOfReleaseId: rHH.id });
        ok(wrongSource.status === S.INVALID_AS_OF_RELEASE,
           '91. an asOfReleaseId from ANOTHER CMS source FAILS CLOSED', wrongSource.status);
      }
      // An observation-less / history-only newer release must not become the
      // current anchor, which would match no row and zero the market.
      {
        await prisma.cmsRelease.create({ data: { id: uuid(), source: 'cms_hospice',
          releaseKey: '2027-01-31', capturedAt: new Date('2027-01-31T00:00:00Z'), datasetCount: 6 } });
        const after = await at(undefined);
        ok(after.status === S.RESOLVED && JSON.stringify(after.ccns) === JSON.stringify([SPAN, ONLY2].sort()),
           '92. a newer release no service-area row references does NOT zero the market',
           `${after.status} / ${after.ccns.join(',')}`);
      }
      // Release ordering must come from releaseKey, never from id ordering.
      {
        const orderBys = MARKET_CODE.match(/ORDER BY [^\n)]*/g) || [];
        const idOrdered = orderBys.filter((o) => /\bid\b|ReleaseId/.test(o));
        ok(/ORDER BY r\."releaseKey" DESC/.test(MARKET_CODE),
           '93. the release anchor is ordered by releaseKey DESC');
        ok(idOrdered.length === 0,
           '93b. no ORDER BY keys on a release id — UUIDs carry no chronology',
           JSON.stringify(idOrdered));
      }
      // History is read, never rewritten.
      {
        const total = await prisma.cmsFacilityServiceArea.count();
        ok(total === 7, '94. no service-area row was deleted or added by any query', String(total));
        const stale = await prisma.cmsFacilityServiceArea.count({
          where: { lastSeenReleaseId: r1.id } });
        ok(stale === 2, '95. the R1-only rows are still stamped at R1', String(stale));
      }
    }

    await prisma.$executeRawUnsafe(
      'TRUNCATE TABLE "CmsFacilityServiceArea","CmsFacility","CmsRelease","ProviderExternalIdentity","Provider" CASCADE');
  } finally {
    await prisma.$disconnect().catch(() => {});
  }
  finish();
})().catch((e) => { console.error('\nharness failed:', e.message); process.exit(1); });

function finish() {
  console.log(`\n${'='.repeat(60)}`);
  console.log(fail === 0 ? `PASSED — ${pass} assertions` : `FAILED — ${fail} of ${pass + fail} assertions failed`);
  process.exit(fail === 0 ? 0 : 1);
}
