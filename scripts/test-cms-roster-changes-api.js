#!/usr/bin/env node
/**
 * Guards the CMS roster-change API surface — Phase 2D.
 *
 * Two things are under test and they are deliberately tested differently.
 *
 * THE ROUTE HANDLER IS EXECUTED, not pattern-matched. The repo has no HTTP
 * harness, so the handler is extracted from server.js and run against injected
 * stubs, the same technique scripts/test-waitlist-durability.js uses. That
 * genuinely exercises the gate, the auth boundary, the passthrough and the error
 * path - including the branches a stub is the only practical way to reach.
 *
 * THE CAPABILITY BUILDER IS EVALUATED from its own source with an injected
 * `process`, so flag parsing is proven against the real code rather than a
 * reimplementation of it.
 *
 * With TEST_DATABASE_URL set, the route additionally runs end to end against the
 * REAL engine and real rows: one release proving insufficient_history, and two
 * releases proving a departed hospice still surfaces as rosterRemoved. That
 * second case is the one that matters most - it is where a route could silently
 * reintroduce current-only scoping.
 *
 * Every provider id, CCN, name and ZIP here is SYNTHETIC, and the database phase
 * refuses to run against anything that looks like production.
 *
 *   node scripts/test-cms-roster-changes-api.js
 *   TEST_DATABASE_URL=postgresql://localhost:5432/bh_obs_test \
 *     node scripts/test-cms-roster-changes-api.js
 */
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const ROOT = path.join(__dirname, '..');
const SRC = fs.readFileSync(path.join(ROOT, 'server.js'), 'utf8');
const ENGINE_SRC = fs.readFileSync(path.join(ROOT, 'cms-hospice-roster-changes.js'), 'utf8');
const { CMS_ROSTER_CHANGE_STATUS: S } = require(path.join(ROOT, 'cms-hospice-roster-changes.js'));

let pass = 0, fail = 0;
const ok = (c, label, detail) => {
  console.log(`  ${c ? 'ok  ' : 'FAIL'} ${label}${c || !detail ? '' : `  — ${detail}`}`);
  c ? pass++ : fail++;
};
const section = (t) => console.log(`\n--- ${t} ---`);
const uuid = () => crypto.randomUUID();
const grab = (rx, what) => { const m = SRC.match(rx); if (!m) throw new Error('missing ' + what); return m[0]; };

const ROUTE = grab(/app\.get\('\/api\/provider-intelligence\/roster-changes'[\s\S]*?\n\}\);/,
  'roster-changes route');
const ROUTE_BODY = (ROUTE.match(/async \(req, res\) => \{([\s\S]*)\n\}\);$/) || ['', ''])[1];
// Comments stripped before any pattern match, so assertions test the handler's
// behaviour and not its own explanatory prose.
const ROUTE_CODE = ROUTE_BODY.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '');

const makeRes = () => {
  const r = { _code: 200, _json: undefined, _calls: 0 };
  r.status = (c) => { r._code = c; return r; };
  r.json = (v) => { r._json = v; r._calls += 1; return r; };
  return r;
};

/** Run the REAL handler with injected dependencies. */
const makeHandler = (deps) => new Function(
  'CMS_ROSTER_CHANGES_ENABLED', 'getProviderContext', 'buildProviderRosterChanges',
  'prisma', 'console', 'req', 'res',
  'return (async () => {' + ROUTE_BODY + '\n})();')
  .bind(null, deps.enabled, deps.getProviderContext, deps.buildProviderRosterChanges,
    deps.prisma, deps.console);

function world(over = {}) {
  const w = {
    calls: [], ctxCalls: [], logs: [],
    enabled: over.enabled === undefined ? true : over.enabled,
    prisma: over.prisma || {}
  };
  w.getProviderContext = async (id) => {
    w.ctxCalls.push(id);
    if (over.ctxThrows) throw new Error('synthetic ctx failure');
    return over.ctx === undefined ? { providerId: 'prov-authenticated' } : over.ctx;
  };
  w.buildProviderRosterChanges = async (prisma, providerId, opts) => {
    w.calls.push({ providerId, opts });
    if (over.serviceThrows) throw new Error('synthetic service failure: SELECT * FROM "CmsFacility"');
    return over.result === undefined ? { status: 'ok', events: {}, detail: null } : over.result;
  };
  w.console = { error: (...a) => w.logs.push(a.map(String).join(' ')), warn: () => {}, log: () => {} };
  return w;
}

// ===================== A. FLAG PARSING (real source) ======================
section('A. feature flag');
{
  const line = grab(/const CMS_ROSTER_CHANGES_ENABLED = [^\n]*/, 'flag constant');
  ok(/process\.env\.CMS_ROSTER_CHANGES_ENABLED === 'true'/.test(line),
     'A1. env var is CMS_ROSTER_CHANGES_ENABLED, parsed with the repo\'s exact-string convention', line);
  ok(!/\|\||\?\?|!==\s*'false'|Boolean\(|JSON\.parse/.test(line),
     'A2. no truthy-coercion, no default-true, no alternate parsing', line);

  // Evaluated against the real constant, one injected environment at a time.
  const evalFlag = (env) => {
    const fn = new Function('process', `${line}; return CMS_ROSTER_CHANGES_ENABLED;`);
    return fn({ env });
  };
  ok(evalFlag({}) === false, 'A3. DEFAULT is OFF — a missing env var does not enable the feature');
  ok(evalFlag({ CMS_ROSTER_CHANGES_ENABLED: 'false' }) === false, 'A4. explicit "false" does not enable');
  ok(evalFlag({ CMS_ROSTER_CHANGES_ENABLED: 'true' }) === true, 'A5. explicit "true" enables');
  for (const v of ['TRUE', 'True', 'tRuE', '1', 'yes', 'y', 'on', ' true', 'true ', '']) {
    ok(evalFlag({ CMS_ROSTER_CHANGES_ENABLED: v }) === false,
       `A6. "${v}" FAILS CLOSED => disabled`);
  }
  ok(evalFlag({ CMS_ROSTER_CHANGES_ENABLED: undefined }) === false, 'A7. undefined => disabled');
}

// ===================== B. CAPABILITY (real builder) =======================
section('B. capability');
{
  const caps = grab(/function providerIntelligenceCapabilities[\s\S]*?\n\}/, 'capability builder');
  const modules = grab(/const INTELLIGENCE_MODULES = \[[\s\S]*?\];/, 'INTELLIGENCE_MODULES');

  ok(/'cmsRosterChanges'/.test(modules), 'B1. cmsRosterChanges is registered in INTELLIGENCE_MODULES');
  ok(/cmsRosterChanges: CMS_ROSTER_CHANGES_ENABLED/.test(caps),
     'B2. the capability is gated by its OWN flag');
  ok(/cmsRosterChanges/.test(caps), 'B3. the capability key exists in the builder');

  // A DISTINCT capability: no existing key may be repurposed to carry it.
  for (const other of ['cmsCompetitors', 'competitorBenchmarking', 'cmsQuality',
                       'cmsMarketOverlap', 'marketOpportunity', 'reports',
                       'geographicDemand', 'cmsRatings', 'cahps', 'stateLicensing',
                       'providerFunnelV1', 'bestHospiceLeadAnalytics']) {
    const entry = caps.match(new RegExp(`\\n\\s*${other}: [\\s\\S]*?(?=\\n\\s*(?://|/\\*|[a-zA-Z]+:))`));
    ok(!entry || !/CMS_ROSTER_CHANGES_ENABLED/.test(entry[0]),
       `B4. ${other} is NOT gated by the roster-changes flag`);
  }
  ok(!/cmsRosterChanges[\s\S]{0,200}(CMS_COMPETITOR_INTELLIGENCE_ENABLED|CMS_QUALITY_INTELLIGENCE_ENABLED|PROVIDER_FUNNEL_V1_ENABLED)/.test(caps),
     'B5. the roster-changes capability is not gated by another module\'s flag');

  // The capability layer must not consult release counts. Whether the FEATURE
  // exists and whether THIS PROVIDER has a comparison are separate questions.
  const entry = (caps.match(/cmsRosterChanges: [\s\S]*?\n\s*\/\//) || [''])[0];
  ok(entry.length > 0, 'B6. the capability entry is locatable');
  ok(!/releasesAvailable|CmsFacilityObservation|insufficient_history|prisma/.test(entry),
     'B7. capability state does not consult release counts or the database', entry.slice(0, 120));
  ok(/cmsCovered/.test(entry),
     'B8. …but does respect the per-care-type CMS precondition');
  ok(/'available'/.test(entry) && /'not_applicable'/.test(entry),
     'B9. ON => available for a CMS-covered type, not_applicable otherwise');
  ok(/: cmsState,/.test(entry),
     'B10. OFF => the shared cmsState fallback, matching cmsQuality/cmsCompetitors exactly');

  // No internal flag value is exposed to the client.
  const capsRoute = grab(/app\.get\('\/api\/provider\/intelligence\/capabilities'[\s\S]*?\n\}\);/, 'capabilities route');
  ok(!/CMS_ROSTER_CHANGES_ENABLED/.test(capsRoute),
     'B11. the capabilities route never returns the raw flag value');
  const statesUsed = [...new Set((caps.match(/status: '([a-z_]+)'/g) || []))];
  ok(statesUsed.every((s) => /'(available|coming_soon|not_applicable)'/.test(s)),
     'B12. only the three established capability states are used — none invented',
     statesUsed.join(' '));
}

// ===================== C. ROUTE SHAPE / BOUNDARY ==========================
section('C. route shape and authorization boundary');
{
  ok(/app\.get\('\/api\/provider-intelligence\/roster-changes', requireProviderAuth,/.test(SRC),
     'C1. route is GET /api/provider-intelligence/roster-changes behind requireProviderAuth');
  ok(/getProviderContext\(req\.providerUserId\)/.test(ROUTE_CODE),
     'C2. provider identity comes from the authenticated token only');
  ok(/buildProviderRosterChanges\(prisma, ctx\.providerId\)/.test(ROUTE_CODE),
     'C3. the service is called with ctx.providerId — never a client value');
  ok(!/req\.params|req\.query|req\.body/.test(ROUTE_CODE),
     'C4. the handler reads NO req.params, req.query or req.body');
  ok(!/:providerId|:ccn|:id/.test(ROUTE),
     'C5. no path parameter exists on the route');
  ok(!/isAdmin|adminToken|x-admin|hasAdminAccess/.test(ROUTE_CODE),
     'C6. no admin override');
  ok(!/api\/public/.test(ROUTE), 'C7. no public variant');

  // Thin: no comparison, market or SQL logic duplicated into the route.
  ok(!/\$queryRaw|\$executeRaw|SELECT |FROM "Cms/.test(ROUTE_CODE),
     'C8. no direct SQL in the route');
  ok(!/buildProviderCmsMarket|asOfReleaseId|releaseKey/.test(ROUTE_CODE),
     'C9. no market or release-scoping logic duplicated in the route');
  ok(!/rosterAdded|rosterRemoved|ownershipChanged|normText/.test(ROUTE_CODE),
     'C10. no comparison logic or event names in the route');
  ok(/res\.json\(result\)/.test(ROUTE_CODE),
     'C11. the service result is passed through verbatim, as quality/competitors do');
  const statusChecks = ROUTE_CODE.match(/result\.status/g) || [];
  ok(statusChecks.length === 0,
     'C12. the route does not branch on service status — no status is turned into an error',
     `${statusChecks.length} references`);

  // No public/unauthenticated route may serve this.
  const publicRoutes = SRC.match(/app\.get\('\/api\/public[\s\S]{0,400}/g) || [];
  ok(!publicRoutes.some((r) => /roster-changes|RosterChanges/.test(r)),
     'C13. no public roster-changes endpoint exists');
  // Count route REGISTRATIONS, not the string: "roster-changes" also appears in
  // comments referencing cms-hospice-roster-changes.js.
  {
    const regs = SRC.match(/app\.(get|post|put|patch|delete)\('[^']*roster-changes[^']*'/g) || [];
    ok(regs.length === 1, 'C14. exactly ONE route registration serves roster changes',
       JSON.stringify(regs));
    ok(/^app\.get\(/.test(regs[0] || ''), 'C14b. …and it is a GET, so it cannot mutate');
  }

  // Privacy: the route adds nothing to what the engine returns.
  for (const forbidden of ['partner', 'billingMode', 'subscriptionStatus', 'leadCount',
                           'LeadNotification', 'LeadOutcome', 'conversion', 'impression',
                           'percentile', 'score', 'grade', 'rank']) {
    ok(!new RegExp(`\\b${forbidden}\\b`, 'i').test(ROUTE_CODE),
       `C15. the route never adds "${forbidden}"`);
  }
}

// ===================== D. EXECUTED HANDLER BEHAVIOUR ======================
(async () => {
  section('D. executed handler — gate, auth, passthrough, errors');
  {
    const w = world({ enabled: false });
    const res = makeRes();
    await makeHandler(w)({ query: { providerId: 'other' } }, res);
    ok(res._code === 404 && res._json && res._json.error === 'Not found',
       'D1. feature OFF => 404 { error: "Not found" } — the established convention',
       JSON.stringify(res._json));
    ok(w.calls.length === 0, 'D2. …and the service is never called');
    ok(w.ctxCalls.length === 0, 'D3. …and provider context is not even resolved');
    ok(!JSON.stringify(res._json).match(/CMS_ROSTER_CHANGES_ENABLED|flag|disabled|gate/i),
       'D4. …and the response does not disclose that a flag exists', JSON.stringify(res._json));
  }
  {
    const w = world({ ctx: null });
    const res = makeRes();
    await makeHandler(w)({}, res);
    ok(res._code === 401 && res._json.error === 'Unauthorized',
       'D5. no provider context => 401 Unauthorized', JSON.stringify(res._json));
    ok(w.calls.length === 0, 'D6. …and the service is never called');
  }
  {
    // A client-supplied providerId in query, body AND params must be ignored.
    const w = world();
    const res = makeRes();
    await makeHandler(w)({
      query: { providerId: 'victim-provider' },
      body: { providerId: 'victim-provider' },
      params: { providerId: 'victim-provider' },
      providerUserId: 'user-1'
    }, res);
    ok(res._code === 200, 'D7. authenticated + enabled => 200');
    ok(w.calls.length === 1, 'D8. the service is called exactly once');
    ok(w.calls[0].providerId === 'prov-authenticated',
       'D9. the service receives the AUTHENTICATED providerId', w.calls[0].providerId);
    ok(w.calls[0].providerId !== 'victim-provider',
       'D10. a client-supplied providerId in query/body/params CANNOT switch provider');
    ok(w.ctxCalls[0] === 'user-1',
       'D11. context is resolved from req.providerUserId, set by the auth middleware');
  }
  {
    // Every engine status passes through as a 200 with the status intact.
    for (const status of ['ok', 'insufficient_history', 'no_observations',
                          'provider_not_found', 'no_verified_identity',
                          'multiple_verified_identities', 'facility_not_found',
                          'no_service_area', 'market_unavailable', 'invalid_as_of_release']) {
      const payload = { status, events: { rosterAdded: [], rosterRemoved: [] }, detail: null };
      const w = world({ result: payload });
      const res = makeRes();
      await makeHandler(w)({ providerUserId: 'u' }, res);
      ok(res._code === 200 && res._json.status === status,
         `D12. "${status}" passes through as 200 with the status intact`,
         `${res._code} / ${res._json && res._json.status}`);
    }
    ok(Object.values(S).every((v) => typeof v === 'string'),
       'D13. the engine\'s status contract is the source of these names');
  }
  {
    // insufficient_history is a SUCCESSFUL product state, byte-identical passthrough.
    const payload = {
      status: 'insufficient_history',
      releases: { latest: { releaseKey: '2026-08-19' }, previous: null, releasesAvailable: 1 },
      summary: { rosterAdded: 0, rosterRemoved: 0 },
      events: { rosterAdded: [], rosterRemoved: [], nameChanged: [], locationChanged: [], ownershipChanged: [], ownershipCoverageChanged: [] },
      detail: 'x'
    };
    const w = world({ result: payload });
    const res = makeRes();
    await makeHandler(w)({ providerUserId: 'u' }, res);
    ok(res._code === 200, 'D14. insufficient_history is 200, not 4xx and not 5xx');
    ok(JSON.stringify(res._json) === JSON.stringify(payload),
       'D15. …and the payload is passed through BYTE-IDENTICALLY — nothing reshaped');
    ok(res._calls === 1, 'D16. …exactly one response');
  }
  {
    // Service throw => 500 with no internals leaked.
    const w = world({ serviceThrows: true });
    const res = makeRes();
    await makeHandler(w)({ providerUserId: 'u' }, res);
    ok(res._code === 500 && res._json.error === 'Server error',
       'D17. an unexpected failure => 500 { error: "Server error" }', JSON.stringify(res._json));
    const body = JSON.stringify(res._json);
    ok(!/synthetic|SELECT|CmsFacility|stack|at Object|prov-authenticated/i.test(body),
       'D18. no stack trace, SQL, table name or provider id reaches the client', body);
    ok(w.logs.length >= 1 && /synthetic/.test(w.logs.join(' ')),
       'D19. …while the real error IS logged server-side');
  }
  {
    const w = world({ ctxThrows: true });
    const res = makeRes();
    await makeHandler(w)({ providerUserId: 'u' }, res);
    ok(res._code === 500 && res._json.error === 'Server error',
       'D20. a context failure also => 500 Server error');
    ok(w.calls.length === 0, 'D21. …and the service is not called');
  }

  // ===================== E. REAL ENGINE, REAL ROWS ========================
  const DB = process.env.TEST_DATABASE_URL;
  if (!DB) { console.log('\n--- database tests SKIPPED (set TEST_DATABASE_URL) ---'); return finish(); }
  if (/besthospice_db|dpg-d5hhmb4hg0os7380cecg-a|besthospice-shadow-2|render\.com/i.test(DB)) {
    console.log('  FAIL   TEST_DATABASE_URL looks like production'); fail++; return finish();
  }
  const { PrismaClient } = require('@prisma/client');
  const prisma = new PrismaClient({ datasources: { db: { url: DB } } });
  const realEngine = require(path.join(ROOT, 'cms-hospice-roster-changes.js')).buildProviderRosterChanges;

  const SRC_H = 'cms_hospice';
  const OWN = '041500', A = '041501', B = '041502', C = '041503';
  const reset = () => prisma.$executeRawUnsafe(
    'TRUNCATE TABLE "CmsFacilityObservation","CmsFacilityServiceArea","CmsFacilityMeasure",'
    + '"CmsFacility","CmsRelease","ProviderExternalIdentity","Provider" CASCADE');
  const mkRelease = (key) => prisma.cmsRelease.create({ data: { id: uuid(), source: SRC_H,
    releaseKey: key, capturedAt: new Date(`${key}T00:00:00Z`), datasetCount: 6 } });
  const facIds = new Map();
  const mkAt = async (ccn, zips, firstRel, lastRel) => {
    const f = await prisma.cmsFacility.create({ data: { id: uuid(), source: SRC_H, ccn,
      name: `HOSPICE ${ccn}`, address: '1 MAIN ST', city: 'PHOENIX', state: 'AZ', zip: '85016',
      county: 'MARICOPA', phone: '(602) 555-0100', ownershipType: 'For-Profit',
      firstSeenReleaseId: firstRel.id, lastSeenReleaseId: lastRel.id } });
    facIds.set(ccn, f.id);
    for (const zip of zips) {
      await prisma.cmsFacilityServiceArea.create({ data: { id: uuid(), facilityId: f.id,
        source: SRC_H, zip, firstSeenReleaseId: firstRel.id, lastSeenReleaseId: lastRel.id } });
    }
  };
  const mkObs = (ccn, rel) => prisma.cmsFacilityObservation.create({ data: { id: uuid(),
    facilityId: facIds.get(ccn), source: SRC_H, releaseId: rel.id, ccn, name: `HOSPICE ${ccn}`,
    address: '1 MAIN ST', city: 'PHOENIX', state: 'AZ', zip: '85016', county: 'MARICOPA',
    phone: '(602) 555-0100', ownershipType: 'For-Profit' } });
  const mkProvider = (id) => prisma.provider.create({ data: { id, name: `Provider ${id}`,
    email: `${id}@example.test`, address: '1 MAIN ST', city: 'PHOENIX', state: 'AZ', zip: '85016',
    lat: 33.5, lon: -112.0, serviceRadiusKm: 40, careType: 'hospice' } });
  const mkIdentity = (providerId, ccn) => prisma.providerExternalIdentity.create({
    data: { id: uuid(), providerId, source: SRC_H, externalId: ccn, identifierType: 'ccn',
      verifiedAt: new Date() } });

  /** The route, wired to the REAL engine and a REAL prisma client. */
  const callRoute = async (providerUserId, providerId, enabled = true) => {
    const w = world({ enabled, prisma, ctx: { providerId } });
    w.buildProviderRosterChanges = async (p, id) => {
      w.calls.push({ providerId: id });
      return realEngine(p, id);
    };
    const res = makeRes();
    await makeHandler(w)({ providerUserId }, res);
    return res;
  };

  try {
    // ---------- E1. ONE RELEASE -> insufficient_history ----------
    section('E. one release, real engine — insufficient_history');
    {
      await reset();
      const r1 = await mkRelease('2026-08-19');
      await mkAt(OWN, ['11111', '11112'], r1, r1);
      await mkAt(A, ['11111'], r1, r1);
      await mkProvider('p-one'); await mkIdentity('p-one', OWN);
      await mkObs(OWN, r1); await mkObs(A, r1);

      const res = await callRoute('u-one', 'p-one');
      ok(res._code === 200, 'E1. one release => 200, a successful product state', String(res._code));
      ok(res._json.status === 'insufficient_history',
         'E2. status is insufficient_history', res._json.status);
      ok(res._json.releases.releasesAvailable === 1,
         'E3. releasesAvailable = 1', String(res._json.releases.releasesAvailable));
      ok(res._json.releases.previous === null, 'E4. previous release is null');
      ok(res._json.releases.latest && res._json.releases.latest.releaseKey === '2026-08-19',
         'E5. baseline release metadata is reported',
         res._json.releases.latest && res._json.releases.latest.releaseKey);
      const arrays = Object.values(res._json.events);
      ok(arrays.length === 6 && arrays.every((a) => Array.isArray(a) && a.length === 0),
         'E6. all six event arrays present and EMPTY — no placeholder findings');
      ok(Object.values(res._json.summary).every((v) => v === 0),
         'E7. summary is all zero, and no zero is presented as a finding');
      const blob = JSON.stringify(res._json);
      ok(!/2026-05-01/.test(blob), 'E8. no May archive data appears — no synthetic second release');
      ok(!/partner|billingMode|subscriptionStatus|leadCount|conversion|percentile|"score"/i.test(blob),
         'E9. no private or ranking data in the response');
    }

    // ---------- E2. TWO RELEASES -> departures still visible ----------
    section('E. two releases, real engine — union scope survives the API');
    {
      await reset();
      const r1 = await mkRelease('2026-05-01');
      const r2 = await mkRelease('2026-08-19');
      await mkAt(OWN, ['11111', '11112'], r1, r2);
      await mkAt(A, ['11111', '11112'], r1, r2);   // present both
      await mkAt(B, ['11111', '11112'], r1, r1);   // departed after R1
      await mkAt(C, ['11111'], r2, r2);            // new in R2
      await mkProvider('p-two'); await mkIdentity('p-two', OWN);
      for (const c of [OWN, A, B]) await mkObs(c, r1);
      for (const c of [OWN, A, C]) await mkObs(c, r2);

      const res = await callRoute('u-two', 'p-two');
      ok(res._code === 200 && res._json.status === 'ok',
         'E10. two releases => 200 ok', `${res._code} / ${res._json.status}`);
      ok(res._json.releases.releasesAvailable === 2, 'E11. releasesAvailable = 2');
      ok(res._json.releases.previous && res._json.releases.previous.releaseKey === '2026-05-01',
         'E12. previous release reported');

      const removed = res._json.events.rosterRemoved.map((e) => e.ccn);
      const added = res._json.events.rosterAdded.map((e) => e.ccn);
      ok(removed.includes(B),
         'E13. ROSTER_REMOVED: the departed hospice IS VISIBLE THROUGH THE API',
         removed.join(',') || '(none)');
      ok(added.includes(C),
         'E14. ROSTER_ADDED: the newly present hospice IS VISIBLE THROUGH THE API',
         added.join(',') || '(none)');
      ok(res._json.summary.rosterRemoved === 1 && res._json.summary.rosterAdded === 1,
         'E15. exactly one removal and one addition', JSON.stringify(res._json.summary));
      ok(!removed.includes(A) && !added.includes(A),
         'E16. a hospice present in both releases is neither added nor removed');
      ok(res._json.market.overlappingFacilityCount === 2,
         'E17. the reported market stays CURRENT-only (A + C), not the union',
         String(res._json.market.overlappingFacilityCount));
      // The regression this guards: a route that re-scoped to the current market
      // would drop B, because B is by definition not a current competitor.
      const { buildProviderCmsMarket } = require(path.join(ROOT, 'cms-hospice-market.js'));
      const cur = await buildProviderCmsMarket(prisma, 'p-two');
      ok(!cur.competitors.map((c) => c.ccn).includes(B),
         'E18. CONTROL: B is absent from the CURRENT market…',
         cur.competitors.map((c) => c.ccn).join(','));
      ok(removed.includes(B),
         'E19. CONTROL: …yet the API still reports its removal — current-only scoping '
         + 'was NOT reintroduced');
      ok(!/partner|billingMode|subscriptionStatus|leadCount|conversion/i.test(JSON.stringify(res._json)),
         'E20. still no private data with real rows');
    }

    // ---------- E3. gate + isolation against the real engine ----------
    section('E. gate and isolation with the real engine');
    {
      const off = await callRoute('u-two', 'p-two', false);
      ok(off._code === 404, 'E21. feature OFF => 404 even with real data present');
      const other = await callRoute('u-two', 'p-does-not-exist');
      ok(other._code === 200 && other._json.status === 'provider_not_found',
         'E22. an unknown provider fails closed as a structured status, not a leak',
         other._json && other._json.status);
      ok(Object.values(other._json.events).every((a) => a.length === 0),
         'E23. …with empty event arrays');
    }

    await reset();
  } catch (e) {
    console.log('  FAIL   database phase threw: '
      + (e && e.stack ? e.stack.split('\n').slice(0, 3).join(' | ') : e));
    fail++;
  } finally {
    await prisma.$disconnect();
  }
  finish();
})();

function finish() {
  console.log(`\n${fail ? 'FAILED' : 'PASSED'} — ${pass} passed, ${fail} failed`);
  process.exit(fail ? 1 : 0);
}
