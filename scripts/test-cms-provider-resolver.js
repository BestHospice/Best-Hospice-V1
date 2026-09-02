#!/usr/bin/env node
/**
 * Guards the Provider -> ProviderExternalIdentity -> CmsFacility ->
 * CmsFacilityServiceArea resolver.
 *
 * The resolver is a plain module, so its behaviour is tested for real against
 * disposable PostgreSQL rather than by matching source strings. The endpoint
 * wiring is checked by source inspection, because this repo has no HTTP harness
 * (see scripts/test-service-routing.js for the same constraint).
 *
 * All CCNs here are SYNTHETIC. The real Hawaii reference account and CCN 121509
 * appear nowhere: linkage is a separate authorized production step.
 *
 *   TEST_DATABASE_URL=postgresql://user@localhost:5432/bh_resolver_test \
 *     node scripts/test-cms-provider-resolver.js
 */
const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const SRC = fs.readFileSync(path.join(ROOT, 'server.js'), 'utf8');
const RESOLVER_SRC = fs.readFileSync(path.join(ROOT, 'cms-provider-resolver.js'), 'utf8');
const { resolveProviderCmsContext, cmsSourceForCareType, CMS_RESOLVER_STATUS: S } =
  require(path.join(ROOT, 'cms-provider-resolver.js'));

// Comment-stripped source. The resolver's comments deliberately NAME the things
// it must not do (normalizeCareType, internalRole, fuzzy matching) in order to
// explain their absence; a mention is not a call site.
const RESOLVER_CODE = RESOLVER_SRC.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '');

let pass = 0, fail = 0;
const ok = (c, label, detail) => {
  console.log(`  ${c ? 'ok  ' : 'FAIL'} ${label}${c || !detail ? '' : `  — ${detail}`}`);
  c ? pass++ : fail++;
};
const section = (t) => console.log(`\n--- ${t} ---`);

// Synthetic CCNs. 6 chars, matching the shape the ingester validates.
const CCN_A = 'T90001';
const CCN_B = 'T90002';
const CCN_ORPHAN = 'T90999';

// ============================ CARE TYPE MAPPING ==============================
section('careType -> CMS source mapping');
{
  ok(cmsSourceForCareType('hospice') === 'cms_hospice', '1. hospice maps to cms_hospice');
  ok(cmsSourceForCareType('hospice-care') === 'cms_hospice', '   hospice-care maps to cms_hospice');
  ok(cmsSourceForCareType('HOSPICE') === 'cms_hospice', '   mapping is case-insensitive');
  for (const t of ['palliative', 'palliative-care', 'home', 'home-care', 'home-health',
                   'assisted-living', 'nonsense', '', null, undefined]) {
    ok(cmsSourceForCareType(t) === null, `2. "${t}" is UNSUPPORTED — no default to hospice`);
  }
  ok(!/normalizeCareType/.test(RESOLVER_CODE),
     '3. the resolver never CALLS normalizeCareType() (which falls back to hospice)');
  ok(/normalizeCareType/.test(RESOLVER_SRC),
     '   …and documents why it is deliberately avoided');
  ok(/home-health is intentionally ABSENT/.test(RESOLVER_SRC),
     '4. home-health absence is documented, not accidental');
}

// ============================ NO FUZZY FALLBACK ==============================
section('no fuzzy fallback exists in the resolver');
{
  const code = RESOLVER_CODE;
  for (const [re, label] of [
    [/contains|startsWith|endsWith|mode:\s*'insensitive'/, 'no partial/insensitive matching'],
    [/name:\s*\{/, 'never queries CmsFacility by name'],
    [/city:\s*\{|state:\s*\{/, 'never queries CmsFacility by city/state'],
    [/findFirst\(\s*\{\s*where:\s*\{\s*ccn/, 'never picks a facility by CCN alone'],
    [/create\(|createMany|upsert|update\(|delete\(/, 'never writes anything']
  ]) ok(!re.test(code), `5. ${label}`);
  ok(/source_ccn/.test(code), '6. the facility join uses the composite (source, ccn) key');
  ok(!/121509/.test(RESOLVER_SRC) && !/121509/.test(SRC), '7. CCN 121509 appears in no production code');
  ok(!/internalRole|isInternalProvider/.test(code),
     '8. the resolver CODE has no internalRole special-casing (comments explain the absence)');
  ok(/internalRole has NO effect/i.test(RESOLVER_SRC),
     '   …and that absence is documented deliberately');
  ok(!/c3f7379c/.test(RESOLVER_SRC) && !/c3f7379c/.test(SRC), '   no hard-coded provider id');
}

// ============================ ENDPOINT WIRING ================================
section('authenticated endpoint wiring');
{
  const route = SRC.match(/app\.get\('\/api\/provider-intelligence\/cms-context'[\s\S]*?\n\}\);/);
  ok(!!route, '9. /api/provider-intelligence/cms-context exists');
  ok(route && /requireProviderAuth/.test(route[0]), '10. it requires provider authentication');
  ok(route && /getProviderContext\(req\.providerUserId\)/.test(route[0]),
     '11. the provider id comes from the bearer token, not the request');
  ok(route && !/req\.(params|query|body)/.test(route[0]),
     '12. it accepts NO providerId from path, query or body — cross-provider access impossible');
  ok(route && /resolveProviderCmsContext\(prisma, ctx\.providerId\)/.test(route[0]),
     '13. it calls the shared resolver with the authenticated provider only');
  ok(route && !/create|update|delete|upsert/.test(route[0]), '14. the endpoint writes nothing');
  // No public route may expose CMS context.
  const publicRoutes = SRC.match(/app\.get\('\/api\/public[\s\S]{0,400}/g) || [];
  ok(!publicRoutes.some((r) => /cms|Cms/.test(r)), '15. no /api/public route exposes CMS context');
  ok((SRC.match(/resolveProviderCmsContext/g) || []).length === 2,
     '16. the resolver has exactly one runtime call site (plus its import)');
}

// ============================ CAPABILITIES UNTOUCHED =========================
section('Market Intelligence capabilities unchanged');
{
  const caps = SRC.match(/function providerIntelligenceCapabilities[\s\S]*?\n\}/)[0];
  ok(/cmsQuality: cmsState/.test(caps) && /cmsRatings: cmsState/.test(caps) && /cahps: cmsState/.test(caps),
     '17. cmsQuality / cmsRatings / cahps still bind to cmsState');
  const cmsState = caps.match(/const cmsState = [\s\S]*?;\n/);
  ok(cmsState && !/'available'/.test(cmsState[0]), '18. cmsState still cannot yield available');
  for (const m of ['competitorBenchmarking', 'geographicDemand', 'marketOpportunity', 'reports']) {
    ok(new RegExp(`${m}: \\{\\s*\\n\\s*status: 'coming_soon'`).test(caps), `   ${m} still coming_soon`);
  }
  ok(!/cms-context/.test(fs.readFileSync(path.join(ROOT, 'provider-intelligence.html'), 'utf8')),
     '19. provider-intelligence.html does NOT consume the new endpoint yet');
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

  const mkProvider = (id, over = {}) => prisma.provider.create({ data: {
    id, name: `Provider ${id}`, email: `${id}@example.test`, address: '1 Main St',
    city: 'Testville', state: 'AZ', zip: '85001', lat: 33, lon: -112,
    serviceRadiusKm: 100, careType: 'hospice', ...over } });
  const mkIdentity = (providerId, ccn, over = {}) => prisma.providerExternalIdentity.create({ data: {
    id: uuid(), providerId, source: 'cms_hospice', externalId: ccn, identifierType: 'ccn',
    verifiedAt: new Date('2026-08-31T00:00:00Z'), verifiedBy: 'test-suite', confidence: 1, ...over } });

  try {
    await prisma.$executeRawUnsafe(
      'TRUNCATE TABLE "CmsFacilityServiceArea","CmsFacility","CmsRelease","ProviderExternalIdentity","Provider" CASCADE');

    // Two releases so "current in latest release" is a real comparison.
    const relOld = await prisma.cmsRelease.create({ data: { id: uuid(), source: 'cms_hospice',
      releaseKey: '2026-05-01', capturedAt: new Date('2026-05-01T00:00:00Z'), datasetCount: 6 } });
    const relNew = await prisma.cmsRelease.create({ data: { id: uuid(), source: 'cms_hospice',
      releaseKey: '2026-08-19', capturedAt: new Date('2026-08-19T00:00:00Z'), datasetCount: 6 } });
    // A same-CCN facility in ANOTHER source, to prove the join is source-qualified.
    const relOther = await prisma.cmsRelease.create({ data: { id: uuid(), source: 'cms_home_health',
      releaseKey: '2026-08-19', capturedAt: new Date('2026-08-19T00:00:00Z'), datasetCount: 5 } });

    const facA = await prisma.cmsFacility.create({ data: { id: uuid(), source: 'cms_hospice', ccn: CCN_A,
      name: 'SYNTHETIC HOSPICE A', address: '9 Fixture Way', city: 'Testville', state: 'AZ', zip: '85001',
      county: 'MARICOPA', phone: '(602) 555-0000', ownershipType: 'For-Profit',
      firstSeenReleaseId: relOld.id, lastSeenReleaseId: relNew.id } });
    await prisma.cmsFacility.create({ data: { id: uuid(), source: 'cms_home_health', ccn: CCN_A,
      name: 'DECOY HOME HEALTH SAME CCN', address: '1 Decoy', city: 'Elsewhere', state: 'TX', zip: '75001',
      firstSeenReleaseId: relOther.id, lastSeenReleaseId: relOther.id } });
    for (const zip of ['85004', '85001', '85003']) {
      await prisma.cmsFacilityServiceArea.create({ data: { id: uuid(), facilityId: facA.id,
        source: 'cms_hospice', zip, firstSeenReleaseId: relOld.id, lastSeenReleaseId: relNew.id } });
    }
    // A second facility with its own ZIPs, to prove service areas are scoped.
    const facB = await prisma.cmsFacility.create({ data: { id: uuid(), source: 'cms_hospice', ccn: CCN_B,
      name: 'SYNTHETIC HOSPICE B', address: '2 Other', city: 'Testville', state: 'AZ', zip: '85002',
      firstSeenReleaseId: relOld.id, lastSeenReleaseId: relOld.id } });
    await prisma.cmsFacilityServiceArea.create({ data: { id: uuid(), facilityId: facB.id,
      source: 'cms_hospice', zip: '99999', firstSeenReleaseId: relOld.id, lastSeenReleaseId: relOld.id } });

    section('database: fail-closed states');
    let r = await resolveProviderCmsContext(prisma, 'no-such-provider');
    ok(r.status === S.PROVIDER_NOT_FOUND, '20. unknown provider id -> provider_not_found', r.status);
    ok(r.facility === null && r.identity === null, '   …and carries no facility or identity');
    r = await resolveProviderCmsContext(prisma, null);
    ok(r.status === S.PROVIDER_NOT_FOUND, '   null provider id is handled without throwing');

    await mkProvider('p-noident');
    r = await resolveProviderCmsContext(prisma, 'p-noident');
    ok(r.status === S.NO_VERIFIED_IDENTITY, '21. hospice provider, no identity -> no_verified_identity', r.status);

    await mkProvider('p-unverified');
    await mkIdentity('p-unverified', 'T90003', { verifiedAt: null });
    r = await resolveProviderCmsContext(prisma, 'p-unverified');
    ok(r.status === S.NO_VERIFIED_IDENTITY, '22. UNVERIFIED identity -> no_verified_identity', r.status);

    await mkProvider('p-orphan');
    await mkIdentity('p-orphan', CCN_ORPHAN);
    r = await resolveProviderCmsContext(prisma, 'p-orphan');
    ok(r.status === S.FACILITY_NOT_FOUND, '23. verified identity, no ingested facility -> facility_not_found', r.status);
    ok(r.facility === null, '   …and no facility is guessed');

    await mkProvider('p-ambig');
    await mkIdentity('p-ambig', 'T90010');
    await mkIdentity('p-ambig', 'T90011');
    r = await resolveProviderCmsContext(prisma, 'p-ambig');
    ok(r.status === S.MULTIPLE_VERIFIED_IDENTITIES, '24. two verified identities -> fail closed', r.status);
    ok(r.identity === null, '   …no arbitrary "first identity wins"');

    for (const ct of ['palliative', 'home-care', 'assisted-living', 'wat']) {
      const id = `p-ct-${ct}`;
      await mkProvider(id, { careType: ct });
      await mkIdentity(id, `T9${String(Math.abs(ct.length * 7 + 100)).padStart(4, '0')}`);
      const rr = await resolveProviderCmsContext(prisma, id);
      ok(rr.status === S.UNSUPPORTED_CARE_TYPE,
         `25. careType "${ct}" -> unsupported_care_type even WITH a verified identity`, rr.status);
    }

    section('database: successful resolution');
    await mkProvider('p-normal');
    await mkIdentity('p-normal', CCN_A);
    r = await resolveProviderCmsContext(prisma, 'p-normal');
    ok(r.status === S.RESOLVED, '26. verified identity + facility -> resolved', r.status);
    ok(r.facility.ccn === CCN_A && r.facility.name === 'SYNTHETIC HOSPICE A',
       '27. the correct facility resolves', JSON.stringify(r.facility && r.facility.ccn));
    ok(r.facility.source === 'cms_hospice',
       '28. source-qualified: the same CCN in cms_home_health was NOT chosen', r.facility.source);
    ok(JSON.stringify(r.serviceArea.zips) === JSON.stringify(['85001', '85003', '85004']),
       '29. service areas are the facility\'s own, in deterministic ZIP order', JSON.stringify(r.serviceArea.zips));
    ok(r.serviceArea.zipCount === 3, '30. zipCount matches');
    ok(!r.serviceArea.zips.includes('99999'), '31. another facility\'s service area does not leak in');
    ok(r.identity.externalId === CCN_A && r.identity.source === 'cms_hospice' && r.identity.identifierType === 'ccn',
       '32. the identity is echoed back accurately');
    ok(r.freshness.firstSeen.releaseKey === '2026-05-01' && r.freshness.lastSeen.releaseKey === '2026-08-19',
       '33. firstSeen/lastSeen release keys are correct',
       JSON.stringify([r.freshness.firstSeen, r.freshness.lastSeen]));
    ok(r.freshness.latestIngestedRelease.releaseKey === '2026-08-19' && r.freshness.currentInLatestRelease === true,
       '34. facility is reported CURRENT in the latest ingested release');

    // A facility last seen in an older release is not current.
    await mkProvider('p-stale');
    await mkIdentity('p-stale', CCN_B);
    r = await resolveProviderCmsContext(prisma, 'p-stale');
    ok(r.status === S.RESOLVED && r.freshness.currentInLatestRelease === false,
       '35. a facility last seen in an older release is NOT current', String(r.freshness.currentInLatestRelease));

    section('database: internalRole has no effect on identity semantics');
    await mkProvider('p-internal-noident', { internalRole: 'cms_reference' });
    r = await resolveProviderCmsContext(prisma, 'p-internal-noident');
    ok(r.status === S.NO_VERIFIED_IDENTITY,
       '36. internalRole alone does NOT grant CMS resolution', r.status);

    // A CCN is globally exclusive: @@unique([source, externalId]) means two
    // providers cannot claim the same facility. To compare like with like, hand
    // the SAME identity from the normal provider to the internal one.
    const rNormal = await resolveProviderCmsContext(prisma, 'p-stale');
    ok(rNormal.status === S.RESOLVED, '   baseline: the normal provider resolves CCN_B');
    await prisma.providerExternalIdentity.deleteMany({ where: { providerId: 'p-stale' } });
    await mkProvider('p-internal', { internalRole: 'cms_reference', name: 'test', city: 'Honolulu', state: 'HI' });
    await mkIdentity('p-internal', CCN_B);
    const rInternal = await resolveProviderCmsContext(prisma, 'p-internal');
    ok(rInternal.status === S.RESOLVED,
       '37. internal cms_reference WITH a verified identity resolves', rInternal.status);
    ok(JSON.stringify(rInternal.facility) === JSON.stringify(rNormal.facility)
       && JSON.stringify(rInternal.serviceArea) === JSON.stringify(rNormal.serviceArea)
       && JSON.stringify(rInternal.freshness) === JSON.stringify(rNormal.freshness),
       '38. internal and normal providers get byte-identical CMS context for the SAME facility');
    ok(JSON.stringify(rInternal.identity) === JSON.stringify(rNormal.identity),
       '   …and an identical identity projection');
    // Losing the identity must immediately stop resolution, internal or not.
    const rStripped = await resolveProviderCmsContext(prisma, 'p-stale');
    ok(rStripped.status === S.NO_VERIFIED_IDENTITY,
       '   …while the provider that gave it up stops resolving at once');
    ok(!('internalRole' in rInternal.provider),
       '39. internalRole is not exposed in the resolver output');

    section('database: no raw row leakage');
    const provKeys = Object.keys(rInternal.provider).sort().join(',');
    ok(provKeys === 'careType,city,id,name,state', '40. provider projection is exactly the whitelist', provKeys);
    for (const leak of ['email', 'stripeCustomerId', 'stripeSubscriptionId', 'billingMode',
                        'subscriptionStatus', 'planTier', 'providerLoginEmail', 'internalRole']) {
      ok(!(leak in rInternal.provider), `   …no ${leak}`);
    }
    ok(!('id' in rInternal.facility), '41. facility projection omits the internal uuid');
    ok(!('verifiedBy' in rInternal.identity), '42. identity projection omits verifiedBy');

    section('database: determinism');
    const a = await resolveProviderCmsContext(prisma, 'p-normal');
    const b = await resolveProviderCmsContext(prisma, 'p-normal');
    ok(JSON.stringify(a) === JSON.stringify(b), '43. repeated resolution is byte-stable');

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
