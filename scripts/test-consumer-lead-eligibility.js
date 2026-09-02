#!/usr/bin/env node
/**
 * Guards the consumer lead eligibility invariant:
 *
 *   A consumer's information may reach a provider only when the SERVER
 *   independently confirms that provider is public/non-internal, has
 *   receiveClientLeads = true, is billing-eligible, and geographically covers
 *   the consumer under the Best Hospice coverage rules.
 *
 * Provider careType is intentionally NOT part of eligibility, and there are
 * assertions below that PIN that as product intent so a future "fix" that adds
 * care-type filtering fails the suite rather than silently narrowing the network.
 *
 * The rule itself is pure, so most of this needs no database. Endpoint wiring is
 * checked by source inspection (this repo has no HTTP harness), and the eligibility
 * pipeline is additionally exercised against real rows in disposable PostgreSQL.
 *
 * Every provider id, CCN, email and ZIP here is SYNTHETIC.
 *
 *   TEST_DATABASE_URL=postgresql://user@localhost:5432/bh_lead_test \
 *     node scripts/test-consumer-lead-eligibility.js
 */
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const ROOT = path.join(__dirname, '..');
const SRC = fs.readFileSync(path.join(ROOT, 'server.js'), 'utf8');
const SRC_CODE = SRC.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '');
const CLIENT = fs.readFileSync(path.join(ROOT, 'search-results.js'), 'utf8');
const HELPER_SRC = fs.readFileSync(path.join(ROOT, 'consumer-lead-eligibility.js'), 'utf8');
const HELPER_CODE = HELPER_SRC.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '');
const E = require(path.join(ROOT, 'consumer-lead-eligibility.js'));

let pass = 0, fail = 0;
const ok = (c, label, detail) => {
  console.log(`  ${c ? 'ok  ' : 'FAIL'} ${label}${c || !detail ? '' : `  — ${detail}`}`);
  c ? pass++ : fail++;
};
const section = (t) => console.log(`\n--- ${t} ---`);

// A synthetic provider in downtown Phoenix, eligible unless overridden.
const PHX = { lat: 33.4484, lon: -112.0740 };
const prov = (o) => Object.assign({
  id: 'p-' + Math.random().toString(36).slice(2, 8),
  internalRole: null, receiveClientLeads: true, billingMode: 'free', subscriptionStatus: null,
  careType: 'hospice', lat: PHX.lat, lon: PHX.lon, serviceRadiusKm: 96.6, serviceZipCodes: ''
}, o);
const loc = (o) => Object.assign({ zip: '85004', lat: PHX.lat, lon: PHX.lon }, o);

// ============================ FLAGS =========================================
section('flag eligibility');
{
  ok(E.isProviderEligibleForConsumerLead(prov(), loc()) === true,
     '1. a public, opted-in, free provider covering the ZIP is eligible');

  ok(E.isProviderEligibleForConsumerLead(prov({ internalRole: 'cms_reference' }), loc()) === false,
     '2. internal provider REJECTED (internalRole = cms_reference)');
  ok(E.isProviderEligibleForConsumerLead(prov({ internalRole: 'anything' }), loc()) === false,
     '   …any non-null internalRole is rejected');

  ok(E.isProviderEligibleForConsumerLead(prov({ receiveClientLeads: false }), loc()) === false,
     '3. receiveClientLeads = false REJECTED');
  ok(E.isProviderEligibleForConsumerLead(prov({ receiveClientLeads: undefined }), loc()) === false,
     '   …and a missing flag is rejected, not assumed true');

  ok(E.isProviderEligibleForConsumerLead(prov({ billingMode: 'off' }), loc()) === false,
     '4. billingMode = off REJECTED');
  for (const st of ['past_due', 'canceled', 'unpaid', 'incomplete', '', null, undefined]) {
    ok(E.isProviderEligibleForConsumerLead(prov({ billingMode: 'billed', subscriptionStatus: st }), loc()) === false,
       `5. billed + subscriptionStatus ${JSON.stringify(st)} REJECTED`);
  }
  ok(E.isProviderEligibleForConsumerLead(prov({ billingMode: 'billed', subscriptionStatus: 'active' }), loc()) === true,
     '6. billed + active ACCEPTED');
  ok(E.isProviderEligibleForConsumerLead(prov({ billingMode: 'billed', subscriptionStatus: 'trialing' }), loc()) === true,
     '7. billed + trialing ACCEPTED');
  ok(E.isProviderEligibleForConsumerLead(prov({ billingMode: 'free' }), loc()) === true,
     '8. free ACCEPTED');

  // An internal provider must stay out even with every other flag switched on -
  // the accident the internalRole column exists to survive.
  ok(E.isProviderEligibleForConsumerLead(
       prov({ internalRole: 'cms_reference', receiveClientLeads: true, billingMode: 'billed', subscriptionStatus: 'active' }),
       loc()) === false,
     '9. internal is rejected even with receiveClientLeads=true and an active subscription');
  ok(Object.keys(E.CONSUMER_LEAD_ELIGIBLE_WHERE)[0] === 'internalRole',
     '   …and internalRole is the FIRST key of the Prisma fragment');
}

// ============================ GEOGRAPHY =====================================
section('geographic coverage');
{
  ok(E.providerCoversLocation(prov(), loc()) === true, '10. radius mode, 0 km away: covered');
  // ~40 km and ~150 km north of Phoenix
  ok(E.providerCoversLocation(prov(), loc({ lat: 33.81, lon: -112.074 })) === true,
     '11. radius mode, inside the radius: covered');
  ok(E.providerCoversLocation(prov(), loc({ lat: 34.80, lon: -112.074 })) === false,
     '12. radius mode, outside the radius: NOT covered');

  ok(E.providerCoversLocation(prov({ serviceRadiusKm: 5 }), loc({ lat: 33.81, lon: -112.074 })) === false,
     '13. a provider’s own smaller radius narrows the match');
  ok(E.providerCoversLocation(prov({ serviceRadiusKm: 100000 }), loc({ lat: 40.71, lon: -74.00 })) === false,
     '14. a provider’s huge radius is CLAMPED to the consumer radius, not honoured');
  ok(E.providerCoversLocation(prov({ serviceRadiusKm: 0 }), loc()) === true,
     '15. radius 0 falls back to the standard consumer radius (matches the browser)');
  ok(E.providerCoversLocation(prov({ serviceRadiusKm: null }), loc()) === true,
     '   …and so does a null radius');

  // FAIL CLOSED
  ok(E.providerCoversLocation(prov(), loc({ lat: null, lon: null })) === false,
     '16. missing consumer coordinates FAIL CLOSED for a radius-mode provider');
  ok(E.providerCoversLocation(prov(), loc({ lat: undefined, lon: undefined })) === false,
     '   …undefined too');
  ok(E.providerCoversLocation(prov(), loc({ lat: NaN, lon: NaN })) === false, '   …NaN too');
  ok(E.providerCoversLocation(prov({ lat: null, lon: null }), loc()) === false,
     '17. a provider with no coordinates FAILS CLOSED in radius mode');
  ok(E.providerCoversLocation(prov(), null) === false, '18. a null location covers nothing');
  ok(E.providerCoversLocation(null, loc()) === false, '   …and a null provider covers nothing');

  // ZIP LIST IS EXCLUSIVE
  ok(E.providerCoversLocation(prov({ serviceZipCodes: '85004,85006' }), loc()) === true,
     '19. ZIP list containing the ZIP: covered');
  ok(E.providerCoversLocation(prov({ serviceZipCodes: '85006,85007' }), loc()) === false,
     '20. ZIP list NOT containing the ZIP: NOT covered even though the provider is 0 km away');
  ok(E.providerCoversLocation(prov({ serviceZipCodes: '85006', serviceRadiusKm: 96.6 }), loc()) === false,
     '   …a configured ZIP list is EXCLUSIVE: the radius is ignored entirely');
  ok(E.providerCoversLocation(prov({ serviceZipCodes: '85004', serviceRadiusKm: 0 }),
       loc({ lat: null, lon: null })) === true,
     '21. a ZIP-list provider still matches when geocoding failed (no coordinates needed)');
  ok(E.providerCoversLocation(prov({ serviceZipCodes: '   ' }), loc()) === true,
     '22. a blank ZIP list is not a list — radius mode applies');
  ok(E.providerCoversLocation(prov({ serviceZipCodes: 'abcde,1234' }), loc()) === true,
     '   …and a list with no valid 5-digit ZIP is not a list either');

  // parser
  ok(JSON.stringify(E.parseServiceZipCodes('85001, 85002;85003\n85004\t85005 85006'))
     === JSON.stringify(['85001', '85002', '85003', '85004', '85005', '85006']),
     '23. every separator a provider might type is accepted');
  ok(JSON.stringify(E.parseServiceZipCodes('1234,123456,abcde,85001')) === JSON.stringify(['85001']),
     '24. only well-formed 5-digit ZIPs survive');
  ok(JSON.stringify(E.parseServiceZipCodes(null)) === '[]', '   …null yields an empty list');
}

// ============================ PRODUCT INTENT: NO CARE TYPE ==================
section('care type is intentionally NOT an eligibility input');
{
  // These assertions exist to PIN product intent. Best Hospice deliberately routes
  // a consumer request to all eligible nearby partners regardless of care type,
  // because families often do not know which level of care they need. If someone
  // later adds care-type filtering, these fail on purpose.
  ok(!/careType/.test(HELPER_CODE), '25. the eligibility module never reads careType');
  ok(E.isProviderEligibleForConsumerLead(prov({ careType: 'home' }), loc()) === true,
     '26. a HOME CARE provider is eligible for a request from a hospice-oriented funnel');
  for (const ct of ['hospice', 'hospice-care', 'home', 'home-care', 'palliative', 'palliative-care', '', null, 'anything-else']) {
    ok(E.isProviderEligibleForConsumerLead(prov({ careType: ct }), loc()) === true,
       `27. careType ${JSON.stringify(ct)} does not affect eligibility`);
  }
  ok(E.isProviderEligibleForConsumerLead.length === 2,
     '28. the eligibility function takes (provider, location) only — no care-type parameter',
     String(E.isProviderEligibleForConsumerLead.length));
  ok(!('careType' in E.CONSUMER_LEAD_ELIGIBLE_WHERE),
     '29. the Prisma fragment carries no careType key');
}

// ============================ NO CMS DEPENDENCY =============================
section('CMS data never grants consumer lead eligibility');
{
  ok(!/CmsFacilityServiceArea|CmsFacility|CmsRelease|CmsMeasure|cmsFacility|cmsRelease/.test(HELPER_CODE),
     '30. the eligibility module references no Cms* table or model');
  ok(!/require\(/.test(HELPER_CODE.replace(/module\.exports[\s\S]*/, '')),
     '31. it is a leaf module — it requires nothing, so it cannot reach CMS data');
  ok(!/ccn|CCN/.test(HELPER_CODE), '32. it has no notion of a CCN');
  const notify = SRC_CODE.match(/app\.post\('\/api\/notify'[\s\S]*?\n\}\);/);
  ok(notify && !/Cms|cmsFacility|cmsRelease/.test(notify[0]),
     '33. /api/notify touches no CMS table');
  const dr = SRC_CODE.match(/app\.post\('\/api\/discharge-referral'[\s\S]*?\n\}\);/);
  ok(dr && !/Cms|cmsFacility|cmsRelease/.test(dr[0]),
     '34. /api/discharge-referral touches no CMS table');
}

// ============================ /api/notify WIRING ============================
section('/api/notify — client ids may only narrow');
{
  const r = SRC.match(/app\.post\('\/api\/notify'[\s\S]*?\n\}\);/);
  const code = r ? r[0].replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '') : '';
  ok(!!r, '35. the endpoint exists');

  ok(/const requestedIds = \[\.\.\.new Set\(providers\.map/.test(code),
     '36. the client list is collected as CANDIDATE ids');
  ok(/where: \{ id: \{ in: requestedIds \}, \.\.\.CONSUMER_LEAD_ELIGIBLE_WHERE \}/.test(code),
     '37. eligibility is re-queried from the DB, scoped by `in:` — ids can only NARROW');
  ok(/const consumerLocation = await resolveConsumerLocation\(zip\)/.test(code),
     '38. geography is re-established SERVER-side from the submitted ZIP');
  ok(/candidates\.filter\(\(p\) => providerCoversLocation\(p, consumerLocation\)\)/.test(code),
     '39. …using the canonical coverage rule');

  // The old shape must be gone.
  ok(!/rawToList/.test(code), '40. the old trust-the-client list is gone');
  ok(!/disabledClientSet|disabledClientLeads/.test(code), '41. the old blocklist query is gone');

  // Contact details must come from the database.
  ok(!/p\.email \|\| ''/.test(code) || !/providerRecord/.test(code),
     '42. no client-supplied email fallback remains');
  ok(!/providerRecord/.test(code), '   …and the second provider lookup is gone');
  ok(/String\(p\.email \|\| ''\)\.trim\(\),\s*\n\s*String\(p\.secondaryContactEmail \|\| ''\)\.trim\(\)/.test(code),
     '43. recipient emails come from the DB row selected by the eligibility query');
  ok(/providerPhone: p\.phone \|\| ''/.test(code), '44. the provider phone comes from the DB row');
  ok(/select: \{[\s\S]{0,300}secondaryContactEmail: true[\s\S]{0,300}serviceZipCodes: true/.test(code),
     '45. the eligibility query selects the contact and coverage columns it needs');

  ok(/if \(!toList\.length\)/.test(code) && /waitlisted: true, notified: 0/.test(code),
     '46. zero eligible providers falls through to New Territory Outreach');
  ok(/notified: jobs\.length/.test(code), '47. the success response reports an authoritative `notified` count');
  ok(!/careType.*(filter|where|in:)/.test(code) && !/careType: /.test(code.replace(/careType: careTypeText/g, '')),
     '48. NO careType filter was introduced');
  ok(/careType: careTypeText/.test(code),
     '   …while the requested care type is still passed to providers as context');
}

section('/api/notify — geocode failure cannot broadcast');
{
  const r = SRC_CODE.match(/async function resolveConsumerLocation[\s\S]*?\n\}/);
  ok(!!r, '49. resolveConsumerLocation exists');
  ok(r && /lat: geo \? geo\.lat : null, lon: geo \? geo\.lon : null/.test(r[0]),
     '50. a geocode failure yields null coordinates, not a default point');
  // null coordinates + the coverage rule = nobody matches by radius.
  const radiusProviders = [prov(), prov({ serviceRadiusKm: 5 }), prov({ serviceRadiusKm: 100000 })];
  const matched = radiusProviders.filter((p) => E.providerCoversLocation(p, loc({ lat: null, lon: null })));
  ok(matched.length === 0,
     '51. with no coordinates, ZERO radius-mode providers are covered — no broadcast is possible',
     String(matched.length));
  const zipProvider = prov({ serviceZipCodes: '85004' });
  ok(E.providerCoversLocation(zipProvider, loc({ lat: null, lon: null })) === true,
     '52. …and only providers with an explicit ZIP list can still match, which NARROWS the set');
  const cache = SRC_CODE.match(/async function geocodeZipCentroid[\s\S]*?\n\}/);
  ok(cache && /if \(result\) \{/.test(cache[0]),
     '53. only successful geocodes are cached, so an outage cannot pin a permanent null');
}

// ============================ /api/search/providers =========================
section('/api/search/providers — same rule, so display matches routing');
{
  const r = SRC_CODE.match(/app\.get\('\/api\/search\/providers'[\s\S]*?\n\}\);/);
  ok(!!r, '54. the endpoint exists');
  ok(r && /where: \{ \.\.\.PUBLIC_PROVIDER_WHERE, \.\.\.CONSUMER_LEAD_ELIGIBLE_WHERE \}/.test(r[0]),
     '55. it applies the same eligibility rule as /api/notify');
  ok(r && !/careType: /.test(r[0].replace(/careType: true/g, '')),
     '56. …and still applies no careType filter');
  ok(r && /careType: true/.test(r[0]),
     '   …while still returning careType so the page can LABEL each provider');

  // The marketing/directory feed must NOT be narrowed.
  const pub = SRC_CODE.match(/app\.get\('\/api\/public\/providers'[\s\S]*?\n\}\);/);
  ok(!!pub, '57. /api/public/providers exists');
  ok(pub && !/CONSUMER_LEAD_ELIGIBLE_WHERE/.test(pub[0]),
     '58. /api/public/providers is UNAFFECTED — a paused provider still appears in the directory');
  ok(pub && /PUBLIC_PROVIDER_WHERE/.test(pub[0]),
     '   …and still excludes internal accounts');
  // Four code references: the import, plus exactly three consumers - /api/notify,
  // /api/search/providers and /api/discharge-referral. A fifth would mean a new,
  // untested consumer of the eligibility rule.
  const eligRefs = (SRC_CODE.match(/CONSUMER_LEAD_ELIGIBLE_WHERE/g) || []).length;
  ok(eligRefs === 4, '59. the eligibility fragment has exactly three consumers plus its import',
     String(eligRefs));
  ok((SRC_CODE.match(/require\('\.\/consumer-lead-eligibility'\)/g) || []).length === 1,
     '   …imported in exactly one place');
}

// ============================ /api/discharge-referral =======================
section('/api/discharge-referral — fail closed, ZIP lists honoured');
{
  const r = SRC.match(/app\.post\('\/api\/discharge-referral'[\s\S]*?\n\}\);/);
  const code = r ? r[0].replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '') : '';
  ok(!!r, '60. the endpoint exists');

  ok(!/nearbyProviders = geo/.test(code) && !/: allProviders;/.test(code),
     '61. the fail-open "notify every public provider" fallback is GONE');
  ok(!/allProviders/.test(code), '   …and the variable no longer exists here');
  ok(/unroutedReason = 'geocode_failed'/.test(code),
     '62. a geocode failure is recorded as a reason and notifies ZERO providers');
  ok(/where: CONSUMER_LEAD_ELIGIBLE_WHERE/.test(code),
     '63. it applies public/internal + receiveClientLeads + billing eligibility');
  ok(/providerCoversLocation\(p, patientLocation\)/.test(code),
     '64. …and the canonical coverage rule, so serviceZipCodes is honoured as exclusive');
  ok(/serviceZipCodes: true/.test(code), '   …and it now selects serviceZipCodes at all');
  ok(/unroutedReason = 'no_eligible_provider_covers_zip'/.test(code),
     '65. no eligible provider covering the ZIP also notifies zero and is recorded');
  ok(/DISCHARGE_REFERRAL_UNROUTED/.test(code) && /logAdminAction/.test(code),
     '66. the manual-routing condition is admin-logged through the existing mechanism');
  ok(/needs manual routing/.test(r[0]) && /contact@besthospice\.com/.test(code),
     '67. …and emailed to the team');
  ok(code.indexOf('INSERT INTO "DischargeReferral"') < code.indexOf('sendDischargeReferralNotifications'),
     '68. the referral row is PERSISTED before any provider routing is attempted');
  ok(/status,\s*source\)/.test(r[0]) && /'new','discharge_planner'/.test(code),
     '   …with status "new", so it is preserved for manual handling');

  // care type stays context
  ok(!/careType: care_type,[\s\S]{0,80}where/.test(code) && !/care_type.*(filter|in:)/.test(code),
     '69. NO careType eligibility filter on discharge referrals');
  ok(/careType: careTypeLabel/.test(code),
     '70. …and the requested care type IS included in the provider notification');
  ok(/Care type requested:/.test(r[0]),
     '71. …and in the admin manual-routing alert');
  ok(/careType: care_type/.test(code), '   …and in the admin action log');
  ok(/DISCHARGE_CARE_LABELS/.test(SRC_CODE) && /unsure: 'Unsure/.test(SRC),
     '72. the care-type labels are shared, including the "Unsure" option');
}

// ============================ BROWSER / SERVER EQUIVALENCE ==================
section('browser and server coverage semantics agree');
{
  // The browser cannot require a server module, so search-results.js keeps its own
  // copy of the coverage rule. This proves the two agree, which is the only
  // available defence against them drifting apart.
  const grab = (name) => {
    const m = CLIENT.match(new RegExp(`function ${name}\\([\\s\\S]*?\\n\\}`));
    if (!m) throw new Error('could not extract ' + name);
    return m[0];
  };
  const clientFns = new Function(
    `${grab('parseServiceZipCodes')}\n${grab('haversineKm')}\n${grab('providerMatchesCoverage')}\n`
    + 'return { parseServiceZipCodes, haversineKm, providerMatchesCoverage };')();

  ok(typeof clientFns.providerMatchesCoverage === 'function',
     '73. the browser coverage function was extracted');

  const zipLists = ['', '   ', '85004', '85006', '85004,85006', '85006;85007', '85004\n85009', 'abcde'];
  const radii = [0, null, 5, 40, 96.6, 100000];
  const points = [
    { zip: '85004', lat: 33.4484, lon: -112.0740 },   // 0 km
    { zip: '85004', lat: 33.8100, lon: -112.0740 },   // ~40 km
    { zip: '85004', lat: 34.8000, lon: -112.0740 },   // ~150 km
    { zip: '85006', lat: 33.4484, lon: -112.0740 },   // 0 km, different ZIP
    { zip: '99999', lat: 33.4484, lon: -112.0740 }    // 0 km, unlisted ZIP
  ];
  let compared = 0, divergent = 0;
  const CONSUMER_RADIUS = E.CONSUMER_LEAD_RADIUS_KM;
  for (const zips of zipLists) {
    for (const radius of radii) {
      for (const pt of points) {
        const p = prov({ serviceZipCodes: zips, serviceRadiusKm: radius });
        const distance = clientFns.haversineKm(pt.lat, pt.lon, p.lat, p.lon);
        const clientSays = clientFns.providerMatchesCoverage(p, distance, CONSUMER_RADIUS, pt.zip);
        const serverSays = E.providerCoversLocation(p, pt);
        compared++;
        if (clientSays !== serverSays) {
          divergent++;
          if (divergent <= 3) {
            console.log(`       divergence: zips=${JSON.stringify(zips)} radius=${radius} pt=${pt.zip} `
              + `client=${clientSays} server=${serverSays}`);
          }
        }
      }
    }
  }
  ok(compared === zipLists.length * radii.length * points.length,
     `74. the equivalence matrix ran (${compared} combinations)`);
  ok(divergent === 0, '75. browser and server agree on EVERY combination', `${divergent} divergent`);

  // the ZIP parsers must agree too
  let parseDiff = 0;
  for (const v of ['85001, 85002;85003\n85004\t85005', '', '   ', 'abcde', '1234,85001', null, undefined]) {
    if (JSON.stringify(clientFns.parseServiceZipCodes(v)) !== JSON.stringify(E.parseServiceZipCodes(v))) parseDiff++;
  }
  ok(parseDiff === 0, '76. the browser and server ZIP parsers agree', `${parseDiff} differ`);

  // haversine agreement with server.js's own copy
  const serverHav = new Function(
    `${(SRC.match(/function haversineKm\([\s\S]*?\n\}/) || [''])[0]}\nreturn haversineKm;`)();
  let havDiff = 0;
  for (const pt of points) {
    if (Math.abs(serverHav(pt.lat, pt.lon, PHX.lat, PHX.lon) - clientFns.haversineKm(pt.lat, pt.lon, PHX.lat, PHX.lon)) > 1e-9) havDiff++;
  }
  ok(havDiff === 0, '77. server.js and the browser compute identical distances');
}

section('billing rule: in-memory twin agrees with the Prisma fragment');
{
  // Not a substitute for the database test below, but it proves the two
  // formulations of the billing rule were written to the same spec.
  const modes = ['free', 'off', 'billed', 'somethingnew'];
  const statuses = ['active', 'trialing', 'past_due', 'canceled', '', null];
  let checked = 0;
  for (const m of modes) {
    for (const st of statuses) {
      const p = prov({ billingMode: m, subscriptionStatus: st });
      const expected = m === 'off' ? false : m === 'billed' ? (st === 'active' || st === 'trialing') : true;
      ok(E.isBillingEligible(p) === expected,
         `78. billingMode=${m} status=${JSON.stringify(st)} -> ${expected}`);
      checked++;
    }
  }
  ok(checked === modes.length * statuses.length, `   …${checked} combinations checked`);
}

// ============================ DATABASE ======================================
const DB = process.env.TEST_DATABASE_URL;
(async () => {
  section('database: the real eligibility pipeline');
  if (!DB) { console.log('  (skipped: set TEST_DATABASE_URL)'); return finish(); }
  if (/besthospice_db|besthospice_shadow|render\.com|dpg-/i.test(DB)) {
    console.log('  FAIL   TEST_DATABASE_URL looks like production or shadow'); fail++; return finish();
  }
  const { PrismaClient } = require('@prisma/client');
  const prisma = new PrismaClient({ datasources: { db: { url: DB } } });
  const clean = () => prisma.$executeRawUnsafe('TRUNCATE TABLE "Provider" CASCADE');

  const insert = (id, o) => prisma.$executeRawUnsafe(
    `INSERT INTO "Provider" (id,name,email,address,city,state,zip,lat,lon,"serviceRadiusKm","updatedAt",
       "careType","internalRole","receiveClientLeads","billingMode","subscriptionStatus","serviceZipCodes")
     VALUES ($1,$2,$3,'1 Synthetic Rd','Testville','ZZ','85004',$4,$5,$6,NOW(),$7,$8,$9,$10,$11,$12)`,
    id, `Synthetic ${id}`, `${id}@example.invalid`,
    o.lat === undefined ? PHX.lat : o.lat, o.lon === undefined ? PHX.lon : o.lon,
    o.serviceRadiusKm === undefined ? 96.6 : o.serviceRadiusKm,
    o.careType || 'hospice', o.internalRole || null,
    o.receiveClientLeads === undefined ? true : o.receiveClientLeads,
    o.billingMode || 'free', o.subscriptionStatus || null, o.serviceZipCodes || '');

  try {
    await clean();
    await insert('ok-hospice', {});
    await insert('ok-home', { careType: 'home' });
    await insert('ok-billed', { billingMode: 'billed', subscriptionStatus: 'active' });
    await insert('no-internal', { internalRole: 'cms_reference' });
    await insert('no-optout', { receiveClientLeads: false });
    await insert('no-billoff', { billingMode: 'off' });
    await insert('no-lapsed', { billingMode: 'billed', subscriptionStatus: 'past_due' });
    await insert('no-faraway', { lat: 40.7128, lon: -74.0060 });                    // New York
    await insert('ok-ziplist', { serviceZipCodes: '85004,85006', serviceRadiusKm: 0 });
    await insert('no-ziplist-other', { serviceZipCodes: '85006', serviceRadiusKm: 0 });

    // This is exactly the shape /api/notify uses.
    const runPipeline = async (requestedIds, location) => {
      const candidates = await prisma.provider.findMany({
        where: { id: { in: requestedIds }, ...E.CONSUMER_LEAD_ELIGIBLE_WHERE },
        select: { id: true, lat: true, lon: true, serviceRadiusKm: true, serviceZipCodes: true }
      });
      return candidates.filter((p) => E.providerCoversLocation(p, location)).map((p) => p.id).sort();
    };
    const ALL = ['ok-hospice', 'ok-home', 'ok-billed', 'no-internal', 'no-optout', 'no-billoff',
                 'no-lapsed', 'no-faraway', 'ok-ziplist', 'no-ziplist-other'];

    const eligible = await runPipeline(ALL, loc());
    ok(JSON.stringify(eligible) === JSON.stringify(['ok-billed', 'ok-home', 'ok-hospice', 'ok-ziplist']),
       '79. the pipeline admits exactly the eligible providers', eligible.join(','));
    ok(eligible.includes('ok-home'),
       '80. a HOME CARE provider is admitted — cross-care-type routing is preserved');

    // Client ids may narrow but never expand.
    ok((await runPipeline(['no-internal'], loc())).length === 0,
       '81. a client-supplied INTERNAL provider id cannot expand eligibility');
    ok((await runPipeline(['no-optout'], loc())).length === 0,
       '82. a client-supplied OPTED-OUT provider id cannot expand eligibility');
    ok((await runPipeline(['no-faraway'], loc())).length === 0,
       '83. a client-supplied OUT-OF-AREA provider id cannot expand eligibility');
    ok((await runPipeline(['no-billoff', 'no-lapsed'], loc())).length === 0,
       '84. client-supplied billing-ineligible ids cannot expand eligibility');
    ok((await runPipeline(['no-ziplist-other'], loc())).length === 0,
       '85. a ZIP-list provider is not reachable for a ZIP outside its list, though 0 km away');
    const narrowed = await runPipeline(['ok-hospice'], loc());
    ok(JSON.stringify(narrowed) === JSON.stringify(['ok-hospice']),
       '86. a narrower client list narrows the result');
    ok((await runPipeline([], loc())).length === 0, '87. an empty client list yields nobody');
    ok((await runPipeline(['does-not-exist'], loc())).length === 0,
       '88. an unknown id yields nobody');

    // Geocode failure.
    const noGeo = await runPipeline(ALL, { zip: '85004', lat: null, lon: null });
    ok(JSON.stringify(noGeo) === JSON.stringify(['ok-ziplist']),
       '89. GEOCODE FAILURE notifies only explicit-ZIP-list providers — never all providers',
       noGeo.join(','));
    ok(noGeo.length < eligible.length,
       '90. …which is strictly fewer than a successful geocode', `${noGeo.length} < ${eligible.length}`);

    // The discharge-referral shape: same rule, no client id list at all.
    const dischargeEligible = (await prisma.provider.findMany({
      where: E.CONSUMER_LEAD_ELIGIBLE_WHERE,
      select: { id: true, lat: true, lon: true, serviceRadiusKm: true, serviceZipCodes: true }
    })).filter((p) => E.providerCoversLocation(p, loc())).map((p) => p.id).sort();
    ok(JSON.stringify(dischargeEligible) === JSON.stringify(['ok-billed', 'ok-home', 'ok-hospice', 'ok-ziplist']),
       '91. discharge referrals use the same rule, honouring ZIP lists', dischargeEligible.join(','));
    const dischargeNoGeo = (await prisma.provider.findMany({
      where: E.CONSUMER_LEAD_ELIGIBLE_WHERE,
      select: { id: true, lat: true, lon: true, serviceRadiusKm: true, serviceZipCodes: true }
    })).filter((p) => E.providerCoversLocation(p, { zip: '85004', lat: null, lon: null }));
    ok(dischargeNoGeo.length === 1,
       '92. a discharge referral with a failed geocode reaches at most explicit-ZIP providers, not everyone',
       String(dischargeNoGeo.length));

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
