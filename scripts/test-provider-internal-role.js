#!/usr/bin/env node
/**
 * Guards Provider.internalRole.
 *
 * The invariant: a provider with a non-null internalRole is excluded from every
 * public and business behaviour, while KEEPING authenticated dashboard access.
 * Exercising the real provider experience is the entire point of such an
 * account, so a test that simply blocked it everywhere would defeat the purpose.
 *
 * Two layers, because no route-level harness exists in this repo (see
 * scripts/test-service-routing.js for the same reasoning):
 *
 *   1. the real predicates are extracted from server.js and executed against
 *      real rows in PostgreSQL, so exclusion is proven, not asserted
 *   2. source inspection pins each gate to its call site, so a future edit that
 *      drops one is caught
 *
 *   node scripts/test-provider-internal-role.js
 *   TEST_DATABASE_URL=postgresql://user@localhost:5432/bh_role_test \
 *     node scripts/test-provider-internal-role.js
 */
const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const SRC = fs.readFileSync(path.join(ROOT, 'server.js'), 'utf8');
const SCHEMA = fs.readFileSync(path.join(ROOT, 'prisma', 'schema.prisma'), 'utf8');
const LEAD_RULE = fs.readFileSync(path.join(ROOT, 'consumer-lead-eligibility.js'), 'utf8');

let pass = 0, fail = 0;
const ok = (cond, label, detail) => {
  console.log(`  ${cond ? 'ok  ' : 'FAIL'} ${label}${cond || !detail ? '' : `  — ${detail}`}`);
  cond ? pass++ : fail++;
};
const section = (t) => console.log(`\n--- ${t} ---`);

// ---- extract the real definitions out of server.js -------------------------
function extract(re, label) {
  const m = SRC.match(re);
  if (!m) { ok(false, `could not locate ${label} in server.js`); return ''; }
  return m[0];
}
const isInternalProviderSrc = extract(/const isInternalProvider = [^\n]*;/, 'isInternalProvider');
const publicWhereSrc = extract(/const PUBLIC_PROVIDER_WHERE = [^\n]*;/, 'PUBLIC_PROVIDER_WHERE');
const publicSqlSrc = extract(/const PUBLIC_PROVIDER_SQL = [^\n]*;/, 'PUBLIC_PROVIDER_SQL');
const internalSqlSrc = extract(/const INTERNAL_PROVIDER_SQL = [^\n]*;/, 'INTERNAL_PROVIDER_SQL');
const { isInternalProvider, PUBLIC_PROVIDER_WHERE, PUBLIC_PROVIDER_SQL, INTERNAL_PROVIDER_SQL } =
  eval(`(function(){${[isInternalProviderSrc, publicWhereSrc, publicSqlSrc, internalSqlSrc].join('\n')}
    return { isInternalProvider, PUBLIC_PROVIDER_WHERE, PUBLIC_PROVIDER_SQL, INTERNAL_PROVIDER_SQL };})()`);

// ============================ SCHEMA =========================================
section('schema');
{
  const model = SCHEMA.match(/model Provider \{[\s\S]*?\n\}/)[0];
  ok(/internalRole\s+String\?/.test(model), '1. Provider.internalRole exists and is a nullable String');
  ok(!/internalRole\s+Boolean/.test(model), '   …not a Boolean, so future internal types need no new column');
  ok(!/internalRole[^\n]*@default/.test(model), '   …has no default, so existing providers stay NULL with no backfill');
  const pei = SCHEMA.match(/model ProviderExternalIdentity \{[\s\S]*?\n\}/)[0];
  ok(!/internalRole|isTest|isReference|purpose/.test(pei),
     '2. ProviderExternalIdentity gained no test/reference semantics');
  ok(/@@unique\(\[source, externalId\]\)/.test(pei), '   …and its identity uniqueness is unchanged');
}

// ============================ HELPER SEMANTICS ===============================
section('central helper semantics');
{
  ok(isInternalProvider({ internalRole: 'cms_reference' }) === true, '3. non-null internalRole is internal');
  ok(isInternalProvider({ internalRole: null }) === false, '   NULL is a normal provider');
  ok(isInternalProvider({}) === false, '   absent field is a normal provider');
  ok(isInternalProvider(null) === false, '   null provider is not internal (no throw)');
  ok(isInternalProvider(undefined) === false, '   undefined provider is not internal (no throw)');
  // Empty string errs toward exclusion: the three forms must agree, and all key
  // off NULL, so '' is internal. Fail-safe direction.
  ok(isInternalProvider({ internalRole: '' }) === true, '4. empty string is treated as INTERNAL (fail-safe)');
  ok(JSON.stringify(PUBLIC_PROVIDER_WHERE) === '{"internalRole":null}',
     '5. PUBLIC_PROVIDER_WHERE is a single non-OR key so it composes into any where', JSON.stringify(PUBLIC_PROVIDER_WHERE));
  ok(!('OR' in PUBLIC_PROVIDER_WHERE), '   …and cannot collide with an existing OR clause');
  ok(PUBLIC_PROVIDER_SQL === '"internalRole" IS NULL', '6. PUBLIC_PROVIDER_SQL matches the Prisma fragment');
  ok(INTERNAL_PROVIDER_SQL === '"internalRole" IS NOT NULL', '   INTERNAL_PROVIDER_SQL is its exact complement');
}

// ============================ GATE PRESENCE ==================================
section('gate presence at each call site');
{
  const gates = [
      // Consumer lead eligibility moved from a raw-SQL blocklist to the positive
      // Prisma allowlist in consumer-lead-eligibility.js. The guarantee is unchanged
      // and stricter: internalRole is still the FIRST condition, now expressed as an
      // equality a query cannot accidentally satisfy.
      [/where: \{ id: \{ in: requestedIds \}, \.\.\.CONSUMER_LEAD_ELIGIBLE_WHERE \}/,
        'A. client lead eligibility is re-derived server-side, scoped to the requested ids'],
    [/"receiveJobLeads", "internalRole" FROM "Provider"/, 'B. job lead fan-out selects internalRole'],
    [/if \(isInternalProvider\(p\)\) return false;[\s\S]{0,120}activelyHiring === false/, '   …and rejects internal before activelyHiring/receiveJobLeads'],
    [/async function fetchAllProviders\(\) \{\s*\n\s*const providers = await prisma\.provider\.findMany\(\{\s*\n\s*where: PUBLIC_PROVIDER_WHERE,/, 'C. fetchAllProviders is public-only'],
    [/async function providersByLocation[\s\S]{0,300}\.\.\.PUBLIC_PROVIDER_WHERE,/, 'C. providersByLocation is public-only'],
    [/prisma\.provider\.findMany\(\{ where: PUBLIC_PROVIDER_WHERE, select: \{ city: true, state: true, careType: true \} \}\)/, 'D/E. sitemap location enumeration is public-only'],
    [/where: \{ \.\.\.PUBLIC_PROVIDER_WHERE, state: \{ equals: state, mode: 'insensitive' \}, careType: normalizeCareType\(service\) \}/, 'D. /:service/:state page is public-only'],
    [/where: \{ \.\.\.PUBLIC_PROVIDER_WHERE, careType: normalizeCareType\(service\) \}, select: \{ state: true \}/, 'D. /:service hub is public-only'],
    [/where: \{ \.\.\.PUBLIC_PROVIDER_WHERE, id: \{ startsWith: frag \} \}/, 'F. /provider/:slug is public-only (404 for internal)'],
    [/function renderProviderSchema\(provider\) \{[\s\S]{0,300}if \(isInternalProvider\(provider\)\) return null;/, 'G. renderProviderSchema returns null for internal'],
    [/const schema = renderProviderSchema\(p\);\s*\n\s*if \(schema\) jsonLd\.push\(schema\);/, 'G. JSON-LD emitter drops nulls'],
    [/if \(isInternalProvider\(provider\)\) \{\s*\n\s*return res\.status\(403\)[\s\S]{0,120}subscription/, 'H. Stripe checkout refuses internal accounts'],
    [/\/api\/providers\/email\/checkout[\s\S]{0,900}if \(isInternalProvider\(provider\)\)/, 'H. BOTH checkout entry points are gated (id and email)']
  ];
  gates.forEach(([re, label], i) => ok(re.test(SRC), `${7 + i}. ${label}`));
    // The shared consumer-lead rule must keep internalRole first, for the same
    // reason the old raw SQL did: an internal account stays excluded even if
    // receiveClientLeads is later flipped back to true by hand.
    ok(/const CONSUMER_LEAD_ELIGIBLE_WHERE = Object\.freeze\(\{\s*\n\s*internalRole: null,\s*\n\s*receiveClientLeads: true,/.test(LEAD_RULE),
       '   A. the shared consumer-lead rule lists internalRole FIRST, then receiveClientLeads');
    ok(/internalRole != null\) return false;/.test(LEAD_RULE),
       '   A. …and its in-memory twin rejects any non-null internalRole');
  ok((SRC.match(/PUBLIC_PROVIDER_WHERE/g) || []).length >= 12,
     '19. every public provider collection carries the public-only filter',
     `${(SRC.match(/PUBLIC_PROVIDER_WHERE/g) || []).length} usages`);
}

// ============================ DASHBOARD MUST STAY OPEN =======================
section('authenticated dashboard access is NOT gated');
{
  // The account exists to exercise the real provider experience, so the gate
  // must be absent here. Proving absence is as important as proving presence.
  const dashRoutes = [
    ["/api/provider/me", /app\.(get|post)\('\/api\/provider[^']*'/],
    ['provider-intelligence', /provider-intelligence/]
  ];
  const capabilityFn = SRC.match(/function providerIntelligenceCapabilities\(provider\)[\s\S]*?\n\}/);
  ok(!!capabilityFn, '20. providerIntelligenceCapabilities() still exists');
  ok(capabilityFn && !/internalRole|isInternalProvider/.test(capabilityFn[0]),
     '21. Market Intelligence capabilities do NOT branch on internalRole — internal accounts keep access');
  const intelRoute = SRC.match(/app\.get\('\/provider-intelligence[\s\S]{0,600}/);
  ok(!intelRoute || !/isInternalProvider/.test(intelRoute[0]),
     '22. the Market Intelligence route is not blocked for internal accounts');
  ok(!/hasProviderSession[\s\S]{0,200}isInternalProvider/.test(SRC),
     '23. provider session/auth does not reject internal accounts');
  // Stripe WEBHOOK handling must stay untouched so real providers keep resolving.
  const webhook = SRC.match(/const providerIdForSubscription = async \(subscription\)[\s\S]*?\n  \};/);
  ok(webhook && !/isInternalProvider|internalRole/.test(webhook[0]),
     '24. Stripe webhook resolution is untouched (real providers unaffected)');
}

// ============================ AUTH-SELECTOR SEPARATION =======================
section('public list vs dashboard account-selection bootstrap');
{
  const pubRoute = SRC.match(/app\.get\('\/api\/public\/providers'[\s\S]*?\n\}\);/);
  const authRoute = SRC.match(/app\.get\('\/api\/provider-auth\/providers'[\s\S]*?\n\}\);/);
  ok(!!pubRoute, 'S1. /api/public/providers still exists');
  ok(!!authRoute, 'S2. /api/provider-auth/providers exists');
  ok(pubRoute && /where: PUBLIC_PROVIDER_WHERE/.test(pubRoute[0]),
     'S3. the PUBLIC endpoint is still fail-closed (internal excluded)');
  ok(authRoute && !/PUBLIC_PROVIDER_WHERE/.test(authRoute[0]),
     'S4. the auth selector deliberately does NOT filter internal accounts');
  // Minimal response shape: strictly less than the public endpoint.
  ok(authRoute && /select: \{ id: true, name: true \}/.test(authRoute[0]),
     'S5. the auth selector returns ONLY id and name');
  for (const leak of ['email', 'phone', 'billingMode', 'subscriptionStatus', 'stripeCustomerId',
                      'internalRole', 'serviceZipCodes', 'planTier', 'lat', 'lon']) {
    ok(authRoute && !new RegExp(`${leak}: true`).test(authRoute[0]),
       `   …does not expose ${leak}`);
  }
  // The dashboard must have moved off the public endpoint.
  const dash = fs.readFileSync(path.join(ROOT, 'provider-dashboard.html'), 'utf8');
  ok(!/\/api\/public\/providers/.test(dash),
     'S6. provider-dashboard.html no longer fetches the public provider list');
  ok(/\/api\/provider-auth\/providers/.test(dash),
     'S7. provider-dashboard.html fetches the auth-scoped selector');
  ok(/opt\.value = p\.id;/.test(dash) && /opt\.textContent = p\.name;/.test(dash),
     'S8. the selector still reads exactly id and name — no shape change');
  ok(/function getSelectedProviderId\(\)[\s\S]{0,120}provider-select'\)\.value/.test(dash),
     'S9. getSelectedProviderId() is unchanged and still yields the provider id');
  // Public pages must stay on the public endpoint.
  for (const f of ['index.html', 'hospice-az.html', 'home-care-az.html',
                   'home-care-landing.html', 'home-care-search.html']) {
    const html = fs.readFileSync(path.join(ROOT, f), 'utf8');
    ok(/\/api\/public\/providers/.test(html), `S10. ${f} still uses the PUBLIC endpoint`);
    ok(!/\/api\/provider-auth\/providers/.test(html), `    …and not the auth selector`);
  }
  // Auth endpoints themselves must remain ungated.
  const signup = SRC.match(/app\.post\('\/api\/provider-auth\/signup-start'[\s\S]*?\n\}\);/);
  const login = SRC.match(/app\.post\('\/api\/provider-auth\/login'[\s\S]*?\n\}\);/);
  ok(signup && !/isInternalProvider|internalRole/.test(signup[0]),
     'S11. signup-start does not reject internal accounts');
  ok(login && !/isInternalProvider|internalRole/.test(login[0]),
     'S12. login does not reject internal accounts');
}

// ============================ NO CMS COUPLING ================================
section('no CMS coupling was introduced');
{
  // Strip comments first: the helper block deliberately NAMES the model to
  // explain why internalRole exists instead of it. A mention is not a consumer.
  const code = SRC.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '');
  ok(!/prisma\.providerExternalIdentity|externalIdentities\s*:/.test(code),
     '25. server.js still has zero ProviderExternalIdentity CODE usage (comments excepted)');
  // Scoped to what a CONSUMER looks like - a Prisma accessor or a quoted SQL
  // table name - and evaluated on the comment-stripped source, for the same
  // reason as assertion 25. server.js legitimately NAMES these models in
  // comments (the Quality release gate explains which migration it is waiting
  // for), and it passes `prisma` into cms-hospice-market.js and
  // cms-hospice-quality.js, which are the only modules that query them.
  ok(!/prisma\.(cmsFacility|cmsRelease|cmsFacilityServiceArea|cmsMeasureDefinition|cmsFacilityMeasure)\b/i.test(code)
     && !/"Cms[A-Za-z]+"/.test(code),
     '26. server.js still queries no CMS table directly — not even the two new quality tables');
  const caps = SRC.match(/function providerIntelligenceCapabilities[\s\S]*?\n\}/)[0];
  // cmsRatings and cahps must still bind to cmsState, and cmsState itself must
  // only ever produce coming_soon or not_applicable. cmsMarketOverlap and
  // cmsQuality are legitimately available for hospices - those datasets are
  // ingested - and bestHospiceLeadAnalytics is our own referral data, not CMS.
  ok(/cmsQuality: CMS_QUALITY_INTELLIGENCE_ENABLED/.test(caps),
     '27. cmsQuality binds to the release gate, falling back to cmsState when OFF');
  ok(/\n      : cmsState,/.test(caps), '   …and the OFF branch is cmsState verbatim');
  ok(/cmsRatings: cmsState/.test(caps) && /cahps: cmsState/.test(caps),
     '   …and cmsRatings / cahps still bind to cmsState');
  const cmsState = caps.match(/const cmsState = [\s\S]*?;\n/);
  ok(cmsState && !/'available'/.test(cmsState[0]),
     '   …and cmsState can only yield coming_soon or not_applicable');
  ok(!/121509/.test(SRC) && !/121509/.test(SCHEMA), '28. CCN 121509 appears nowhere');
}

// ============================ DATABASE PROOF =================================
const DB = process.env.TEST_DATABASE_URL;
(async () => {
  if (!DB) { console.log('\n--- database tests SKIPPED (set TEST_DATABASE_URL) ---'); return finish(); }
  if (/besthospice_db|dpg-d5hhmb4hg0os7380cecg-a|besthospice_shadow_2|dpg-d60g7h0gjchc73f306j0-a|render\.com/i.test(DB)) {
    console.log('  FAIL   TEST_DATABASE_URL looks like production or shadow'); fail++; return finish();
  }
  const { PrismaClient } = require('@prisma/client');
  const prisma = new PrismaClient({ datasources: { db: { url: DB } } });
  const mk = (over) => ({
    id: over.id, name: over.name, email: `${over.id}@example.test`,
    address: '1 Main St', city: 'Honolulu', state: 'HI', zip: '96813',
    lat: 21.3, lon: -157.8, serviceRadiusKm: 100, careType: 'hospice', ...over
  });
  try {
    section('database: the real predicates against real rows');
    await prisma.$executeRawUnsafe('TRUNCATE TABLE "ProviderExternalIdentity", "Provider" CASCADE');

    // A normal provider, and an internal one deliberately left in the MOST
    // dangerous configuration: every opt-in flag on, billing on the default.
    await prisma.provider.create({ data: mk({ id: 'normal-1', name: 'Normal Hospice',
      receiveClientLeads: true, receiveJobLeads: true, activelyHiring: true, billingMode: 'free' }) });
    await prisma.provider.create({ data: mk({ id: 'internal-1', name: 'test',
      internalRole: 'cms_reference',
      receiveClientLeads: true, receiveJobLeads: true, activelyHiring: true, billingMode: 'free' }) });

    ok((await prisma.provider.count()) === 2, '29. two providers seeded');
    const normal = await prisma.provider.findUnique({ where: { id: 'normal-1' } });
    const internal = await prisma.provider.findUnique({ where: { id: 'internal-1' } });
    ok(normal.internalRole === null, '30. a normal provider has internalRole = NULL with no backfill');
    ok(internal.internalRole === 'cms_reference', '   the internal account carries cms_reference');

    // 2. client leads — the EXACT production predicate
    const excluded = await prisma.$queryRawUnsafe(
      `SELECT id FROM "Provider"
       WHERE ${INTERNAL_PROVIDER_SQL}
          OR "receiveClientLeads" = false
          OR "billingMode" = 'off'
          OR ("billingMode" = 'billed' AND COALESCE("subscriptionStatus", '') NOT IN ('active', 'trialing'))`);
    const exSet = new Set(excluded.map((r) => r.id));
    ok(exSet.has('internal-1'),
       '31. internal provider EXCLUDED from client leads despite receiveClientLeads=true, billingMode=free');
    ok(!exSet.has('normal-1'), '32. normal provider is NOT excluded — existing behaviour preserved');

    // 3. job leads — the EXACT production filter
    const jobRows = await prisma.$queryRawUnsafe(
      `SELECT id, "activelyHiring", "receiveJobLeads", "internalRole" FROM "Provider"`);
    const jobMatched = jobRows.filter((p) => {
      if (isInternalProvider(p)) return false;
      if (p.activelyHiring === false) return false;
      if (p.receiveJobLeads === false) return false;
      return true;
    }).map((p) => p.id);
    ok(!jobMatched.includes('internal-1'),
       '33. internal provider EXCLUDED from job leads despite receiveJobLeads=true, activelyHiring=true');
    ok(jobMatched.includes('normal-1'), '34. normal provider still receives job leads');

    // 4/5/6. every public collection
    const publicAll = await prisma.provider.findMany({ where: PUBLIC_PROVIDER_WHERE });
    ok(publicAll.length === 1 && publicAll[0].id === 'normal-1',
       '35. public provider listing contains only the normal provider');
    const byLoc = await prisma.provider.findMany({
      where: { ...PUBLIC_PROVIDER_WHERE, state: { equals: 'HI', mode: 'insensitive' }, careType: 'hospice' } });
    ok(byLoc.length === 1 && byLoc[0].id === 'normal-1',
       '36. location page for Honolulu, HI excludes the internal provider');
    const locs = await prisma.provider.findMany({ where: PUBLIC_PROVIDER_WHERE, select: { city: true, state: true, careType: true } });
    ok(locs.length === 1, '37. location-page/sitemap enumeration counts only public providers');

    // 6b. an internal-only city must not create a location page at all
    await prisma.provider.create({ data: mk({ id: 'internal-2', name: 'test-2', city: 'Hilo',
      internalRole: 'cms_reference' }) });
    const hilo = await prisma.provider.findMany({
      where: { ...PUBLIC_PROVIDER_WHERE, city: { equals: 'Hilo', mode: 'insensitive' } } });
    ok(hilo.length === 0, '38. a city whose ONLY provider is internal yields no public location page');

    // 7. public detail route lookup
    const slugLookup = await prisma.provider.findFirst({
      where: { ...PUBLIC_PROVIDER_WHERE, id: { startsWith: 'internal-1'.slice(0, 8) } } });
    ok(slugLookup === null, '39. /provider/:slug lookup returns nothing for an internal provider (404)');
    const slugNormal = await prisma.provider.findFirst({
      where: { ...PUBLIC_PROVIDER_WHERE, id: { startsWith: 'normal-1'.slice(0, 8) } } });
    ok(slugNormal !== null, '40. /provider/:slug still resolves a normal provider');

    // 9/11. dashboard-side reads must still see the internal account
    const dash = await prisma.provider.findUnique({ where: { id: 'internal-1' } });
    ok(dash !== null && dash.name === 'test',
       '41. the internal account is still readable by id — dashboard access is unaffected');
    const adminAll = await prisma.provider.findMany();
    ok(adminAll.length === 3, '42. admin/unfiltered reads still see every provider', String(adminAll.length));

    // 10. backward compatibility
    ok(Object.prototype.hasOwnProperty.call(normal, 'internalRole'),
       '43. the new column serializes on existing provider shapes');
    ok(normal.internalRole === null, '   …as null, so no consumer sees a behaviour change');

    // The core invariant: hidden publicly, selectable for auth.
    section('database: public list excludes internal, auth selector includes it');
    const publicList = await prisma.provider.findMany({
      where: PUBLIC_PROVIDER_WHERE, orderBy: { name: 'asc' }, select: { id: true, name: true, email: true } });
    const authList = await prisma.provider.findMany({
      orderBy: { name: 'asc' }, select: { id: true, name: true } });
    const pubIds = publicList.map((p) => p.id);
    const authIds = authList.map((p) => p.id);
    ok(!pubIds.includes('internal-1'), 'A1. internal provider ABSENT from /api/public/providers');
    ok(authIds.includes('internal-1'), 'A2. internal provider PRESENT in the auth selector');
    ok(pubIds.includes('normal-1'), 'A3. normal provider present in the public list');
    ok(authIds.includes('normal-1'), 'A4. normal provider present in the auth selector');
    ok(Object.keys(authList[0]).sort().join(',') === 'id,name',
       'A5. auth selector rows carry ONLY id and name', Object.keys(authList[0]).join(','));
    ok(!Object.keys(authList[0]).includes('email'), '   …no email, unlike the public endpoint');
    // Login needs the id it selected to still resolve and link.
    const loginTarget = await prisma.provider.findUnique({ where: { id: 'internal-1' } });
    ok(loginTarget !== null && loginTarget.internalRole === 'cms_reference',
       'A6. the selected internal id still resolves for signup-start/login');

    await prisma.$executeRawUnsafe('TRUNCATE TABLE "ProviderExternalIdentity", "Provider" CASCADE');
    const peiCount = await prisma.providerExternalIdentity.count();
    ok(peiCount === 0, '44. no ProviderExternalIdentity row was created by any of this');
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
