#!/usr/bin/env node
/**
 * Guards Competitor Intelligence V1 Phase B — the endpoint, the capability and
 * the provider-visible Competitors UI.
 *
 * The repo has no HTTP harness and no DOM library. Rather than pattern-matching
 * templates, this suite EXECUTES the real code: the route handler is extracted
 * from server.js and run against injected stubs, the capability function is
 * evaluated from its own source, and the render functions are extracted from
 * provider-intelligence.html and run against a small DOM stub, so the assertions
 * read the HTML the page actually produced.
 *
 * With TEST_DATABASE_URL set, the handler is additionally run end to end against
 * the real service and real rows in a disposable PostgreSQL database.
 *
 * Every CCN, ZIP, provider and facility name here is SYNTHETIC. CCN 121509,
 * ISLANDS HOSPICE, Vrablic's Home and the Hawaii account appear nowhere.
 *
 *   node scripts/test-provider-competitors-ui.js
 *   TEST_DATABASE_URL=postgresql://user@localhost:5432/bh_competitors_test \
 *     node scripts/test-provider-competitors-ui.js
 */
const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const SRC = fs.readFileSync(path.join(ROOT, 'server.js'), 'utf8');
const PAGE = fs.readFileSync(path.join(ROOT, 'provider-intelligence.html'), 'utf8');
const SCRIPT_BODY = PAGE.match(/<script>([\s\S]*?)<\/script>/)[1];

let pass = 0, fail = 0;
const ok = (c, label, detail) => {
  console.log(`  ${c ? 'ok  ' : 'FAIL'} ${label}${c || !detail ? '' : `  — ${detail}`}`);
  c ? pass++ : fail++;
};
const section = (t) => console.log(`\n--- ${t} ---`);
// Expanding Competitors is asynchronous: the click awaits the lazy load before
// opening. Yield to the event loop before reading the resulting state.
const tick = () => new Promise((r) => setTimeout(r, 0));
const grab = (rx, label) => { const m = SRC.match(rx); if (!m) throw new Error('missing ' + label); return m[0]; };

// ---- capability model, executed from server.js source ----------------------
const CAPS_SRC = [grab(/const INTELLIGENCE_MODULES = \[[\s\S]*?\n\];/, 'modules'),
  grab(/const CMS_QUALITY_PROVIDER_TYPES = new Set\([^)]*\);/, 'cms types'),
  grab(/const KNOWN_INTELLIGENCE_TYPES = \{[\s\S]*?\n\};/, 'known types'),
  grab(/const TYPE_LABELS = \{[^}]*\};/, 'labels'),
  grab(/const CMS_QUALITY_INTELLIGENCE_ENABLED = [^\n]*/, 'quality release gate'),
  grab(/const CMS_COMPETITOR_INTELLIGENCE_ENABLED = [^\n]*/, 'competitor release gate'),
  grab(/function providerIntelligenceCapabilities\(provider\) \{[\s\S]*?\n\}/, 'fn')].join('\n');
// `process` is injected, so every gate assertion below evaluates the expression
// server.js actually ships rather than a convenient copy of it.
const buildCaps = (env) => new Function('process',
  CAPS_SRC + '\nreturn { providerIntelligenceCapabilities, INTELLIGENCE_MODULES };')({ env: env || {} });
// `env: {}` is the production default: the variable is simply not set.
const capsMod = buildCaps({});
const capsOff = capsMod.providerIntelligenceCapabilities;
const caps = buildCaps({ CMS_COMPETITOR_INTELLIGENCE_ENABLED: 'true' }).providerIntelligenceCapabilities;
const CAP_ON = { cmsCompetitors: { status: 'available' } };
const CAP_OFF = { cmsCompetitors: { status: 'coming_soon' } };

// ---- the route handler, executed with injected stubs -----------------------
const ROUTE = grab(/app\.get\('\/api\/provider-intelligence\/competitors'[\s\S]*?\n\}\);/, 'competitors route');
const DETAIL_ROUTE = grab(/app\.get\('\/api\/provider-intelligence\/competitors\/:ccn'[\s\S]*?\n\}\);/, 'detail route');
const HANDLER_BODY = ROUTE.match(/async \(req, res\) => \{([\s\S]*)\n\}\);$/)[1];
const makeHandler = (getProviderContext, buildProviderCmsCompetitors, prismaStub, gateOn) =>
  new Function('CMS_COMPETITOR_INTELLIGENCE_ENABLED', 'getProviderContext',
    'buildProviderCmsCompetitors', 'prisma', 'console', 'req', 'res',
    'return (async () => {' + HANDLER_BODY + '\n})();')
    .bind(null, gateOn === undefined ? true : gateOn,
      getProviderContext, buildProviderCmsCompetitors, prismaStub, { error() {} });
const makeRes = () => {
  const r = { _code: 200, _json: undefined };
  r.status = (c) => { r._code = c; return r; };
  r.json = (v) => { r._json = v; return r; };
  return r;
};

// ---- minimal DOM stub ------------------------------------------------------
const TOGGLE_LABEL = { 'comp-toggle': 'comp-toggle-label', 'q-toggle': 'q-toggle-label',
                       'mm-toggle': 'mm-toggle-label' };
function makeDom() {
  const els = {};
  const tbodies = {};
  const mk = (id) => (els[id] = {
    id, innerHTML: '', textContent: '', value: '', hidden: false, onclick: null, oninput: null,
    tagName: 'BUTTON', dataset: {}, _attrs: {}, _listeners: {}, _focused: 0,
    _classes: new Set(),
    classList: { add(c) { els[id]._classes.add(c); }, remove(c) { els[id]._classes.delete(c); },
                 contains(c) { return els[id]._classes.has(c); },
                 toggle(c, on) { const set = els[id]._classes;
                   const want = on === undefined ? !set.has(c) : !!on;
                   if (want) set.add(c); else set.delete(c); return want; } },
    setAttribute(k, v) { this._attrs[k] = v; },
    getAttribute(k) { return this._attrs[k]; },
    addEventListener(ev, fn) { (this._listeners[ev] = this._listeners[ev] || []).push(fn); },
    // Real DOM click() fires BOTH the onclick property and addEventListener
    // handlers. The reveal control assigns .onclick so it replaces rather than
    // accumulates across re-renders.
    click() {
      if (typeof this.onclick === 'function') this.onclick();
      (this._listeners.click || []).forEach((f) => f());
    },
    // Typing into the filter: set .value, then fire the handler the page bound.
    type(v) { this.value = v; if (typeof this.oninput === 'function') this.oninput(); },
    querySelector(sel) {
      if (sel === 'tbody') return (tbodies[id] = tbodies[id] || { innerHTML: '' });
      if (sel === '[data-toggle-label]') return els[TOGGLE_LABEL[id]] || null;
      return null;
    },
    focus() { this._focused += 1; },
    getBoundingClientRect() { return { top: 10 }; },
    scrollIntoView() { this._scrolled = true; }
  });
  ['comp-card', 'comp-summary', 'comp-status', 'comp-toggle', 'comp-toggle-label', 'comp-detail',
   'comp-collapse', 'comp-body', 'comp-fresh', 'comp-fresh-quality', 'comp-primary',
   'comp-overlap-count', 'comp-overlap-note', 'comp-top-block', 'comp-top-list', 'comp-top-empty',
   'comp-top-note', 'comp-coverage', 'comp-list-block', 'comp-list-hint', 'comp-filter-wrap',
   'comp-filter', 'comp-filter-count', 'comp-table', 'comp-more', 'comp-empty', 'comp-note',
   'comp-landscape-view', 'comp-h2h-view', 'comp-back', 'comp-h2h-title', 'comp-h2h-ccns',
   'comp-h2h-status', 'comp-h2h-body', 'comp-h2h-overlap', 'comp-h2h-overlap-note',
   'comp-h2h-summary', 'comp-h2h-summary-note', 'comp-h2h-table-hint', 'comp-h2h-table',
   'comp-h2h-note',
   'q-card', 'q-summary', 'q-status', 'q-toggle', 'q-toggle-label', 'q-detail', 'q-collapse', 'q-body',
   'mm-card', 'mm-summary', 'mm-toggle', 'mm-toggle-label', 'mm-detail', 'mm-collapse',
   'cms-market-status', 'cms-market-body'].forEach(mk);
  // Fidelity: an element the markup ships with `hidden` must START hidden here
  // too, or the stub would silently mask a view that the page never reveals.
  Object.keys(els).forEach((id) => {
    const tag = PAGE.match(new RegExp('<[^>]*id="' + id + '"[^>]*>'));
    if (tag && /\shidden(\s|>|=)/.test(tag[0])) els[id].hidden = true;
  });
  // Fires the page's DELEGATED click listener on #comp-table with a synthetic
  // event target, exercising the real closest()-based dispatch rather than
  // calling the handler directly.
  const fireCompare = (ccn) => {
    const target = {
      closest(sel) {
        if (sel !== '[data-compare-ccn]') return null;
        return ccn === null ? null : { getAttribute: (k) => (k === 'data-compare-ccn' ? ccn : null) };
      }
    };
    (els['comp-table']._listeners.click || []).forEach((f) => f({ target }));
  };
  return {
    els, tbodies, fireCompare,
    document: {
      getElementById: (id) => els[id] || mk(id),
      querySelector: (sel) => {
        if (sel === '#comp-table tbody') return (tbodies['comp-table'] = tbodies['comp-table'] || { innerHTML: '' });
        if (sel === '#comp-h2h-table tbody') return (tbodies['comp-h2h-table'] = tbodies['comp-h2h-table'] || { innerHTML: '' });
        if (sel === '#cms-density tbody') return (tbodies.density = tbodies.density || { innerHTML: '' });
        return null;
      }
    }
  };
}

function loadRenderers(dom, apiImpl) {
  const names = ['COMPETITOR_MESSAGES', 'COMPETITOR_FALLBACK', 'COMPETITOR_ERROR', 'COMPETITOR_PAGE',
                 'COMPETITOR_FILTER_MIN', 'COMPETITOR_ZERO_OVERLAP', 'competitorsNotActivated',
                 'competitorsMessage', 'competitorQualityText', 'renderCompetitorLandscape',
                 'renderCompetitorTable', 'renderCompetitorNote', 'initCompetitorsAccordion',
                 'initCompetitors', 'ensureCompetitorsLoaded', 'toggleCompetitors',
                 'renderCompetitorsData', 'COMPETITOR_PROMPT', 'COMPETITOR_LOADING',
                 'openCompetitorDetail', 'renderCompetitorDetail', 'initCompetitorCompare',
                 'showCompetitorLandscape', 'showCompetitorH2H', 'h2hValue',
                 'COMPETITOR_DETAIL_ERROR', 'COMPETITOR_DETAIL_MESSAGES', 'COMPETITOR_DETAIL_LOADING',
                 'INTEL_ACCORDION', 'initMyMarketAccordion',
                 'initQualityAccordion', 'esc', 'num', 'pctText', 'placeText', 'friendlyReleaseDate'];
  const start = SCRIPT_BODY.indexOf('  // ---- intelligence detail accordion');
  const end = SCRIPT_BODY.indexOf('  // ---- section navigation ----');
  if (start < 0 || end < 0) throw new Error('could not locate the renderer block');
  const fn = new Function('document', 'callApi', 'window',
    `${SCRIPT_BODY.slice(start, end)}\nreturn { ${names.join(', ')} };`);
  return fn(dom.document, apiImpl, { innerHeight: 800 });
}

// ---- synthetic fixture -----------------------------------------------------
const competitor = (o) => Object.assign({
  source: 'cms_hospice', ccn: 'U70001', name: 'SYNTHETIC HOSPICE', city: 'Testville', state: 'ZZ',
  zip: '90001', sharedZipCount: 4, providerZipCount: 8, competitorZipCount: 6,
  providerOverlapPct: 50, competitorOverlapPct: 66.67,
  qualityAvailability: { publishedMeasureCount: 7, surfacedMeasureCount: 10 },
  bestHospicePartner: false
}, o);

const landscape = (o) => Object.assign({
  providerZipCount: 8, overlappingFacilityCount: 3, totalSharedZipRelationships: 9,
  averageCompetitorsPerProviderZip: 1.13, highestOverlapSharedZipCount: 4,
  topCompetitorSharedZipCount: 4, topCompetitorProviderOverlapPct: 50, surfacedMeasureCount: 10
}, o);

const response = (o) => Object.assign({
  status: 'resolved',
  provider: { id: 'prov-synthetic', name: 'Synthetic Provider' },
  facility: { source: 'cms_hospice', ccn: 'U70000', name: 'SYNTHETIC OWN HOSPICE', city: 'Testville', state: 'ZZ' },
  landscape: landscape(),
  competitors: [competitor()],
  freshness: {
    source: 'cms_hospice', firstSeen: null, lastSeen: null,
    latestIngestedRelease: { releaseKey: '2026-09-01', capturedAt: null },
    currentInLatestRelease: true,
    qualityRelease: { releaseKey: '2026-08-19', capturedAt: null }
  },
  methodology: {
    competitorDefinition: 'A competitor here is a synthetic definition supplied by the fixture.',
    notRepresenting: ['market share']
  },
  detail: null
}, o);

const many = (n) => Array.from({ length: n }, (_, i) => competitor({
  ccn: 'U8' + String(i).padStart(4, '0'),
  name: 'SYNTHETIC HOSPICE ' + String(i).padStart(3, '0'),
  city: i % 2 ? 'Northtown' : 'Southtown',
  state: i % 3 ? 'ZZ' : 'YY',
  sharedZipCount: n - i,
  providerOverlapPct: Math.round(((n - i) / 8) * 10000) / 100
}));

// ============================ A. ENDPOINT ====================================
section('A. endpoint wiring and isolation');
{
  ok(/app\.get\('\/api\/provider-intelligence\/competitors'/.test(SRC),
     '1a. GET /api/provider-intelligence/competitors exists');
  ok(/requireProviderAuth/.test(ROUTE), '1b. it requires provider authentication');
  ok(/getProviderContext\(req\.providerUserId\)/.test(ROUTE),
     '2. provider identity comes from the bearer token');
  ok(!/req\.(params|query|body)/.test(ROUTE),
     '3a. it accepts NO providerId from path, query or body');
  ok(/app\.get\('\/api\/provider-intelligence\/competitors\/:ccn'/.test(SRC),
     '3b. the Phase C head-to-head route exists');
  ok(DETAIL_ROUTE && /requireProviderAuth/.test(DETAIL_ROUTE),
     '3c. …behind provider authentication');
  ok(DETAIL_ROUTE && /getProviderContext\(req\.providerUserId\)/.test(DETAIL_ROUTE),
     '3d. …with the provider identity still from the bearer token');
  ok(DETAIL_ROUTE && !/req\.(query|body)/.test(DETAIL_ROUTE)
     && (DETAIL_ROUTE.match(/req\.params/g) || []).length === 1
     && /req\.params\.ccn/.test(DETAIL_ROUTE),
     '3e. …and req.params.ccn as the ONLY request input — never a providerId');
  ok(DETAIL_ROUTE && /buildProviderCmsCompetitorDetail\(prisma, ctx\.providerId, req\.params\.ccn\)/.test(DETAIL_ROUTE),
     '3f. …passing the token provider and the requested CCN to the service');
  ok(DETAIL_ROUTE && /if \(!CMS_COMPETITOR_INTELLIGENCE_ENABLED\) return res\.status\(404\)/.test(DETAIL_ROUTE)
     && DETAIL_ROUTE.indexOf('CMS_COMPETITOR_INTELLIGENCE_ENABLED') < DETAIL_ROUTE.indexOf('getProviderContext'),
     '3g. …gated by the SAME release gate, checked before provider context');
  ok((SRC.match(/const CMS_COMPETITOR_INTELLIGENCE_ENABLED =/g) || []).length === 1,
     '3h. …and there is only ONE competitor gate in server.js');
  {
    const logic = DETAIL_ROUTE.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '');
    ok(!/\.map\(|\.filter\(|\.sort\(|for\s*\(/.test(logic),
       '3i. …and the detail handler is thin, transforming nothing');
    ok(/res\.json\(result\)/.test(logic), '3j. …returning the service result verbatim');
  }
  ok(/buildProviderCmsCompetitors\(prisma, ctx\.providerId\)/.test(ROUTE),
     '4a. it calls the shared service for the authenticated provider only');
  ok(/res\.json\(result\)/.test(ROUTE),
     '4b. the service result is returned verbatim — the handler reshapes nothing');
  const logic = ROUTE.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '');
  ok(!/\.map\(|\.filter\(|\.sort\(|for\s*\(|delete /.test(logic),
     '4c. the handler contains no transformation of its own — it is thin');
  ok(!/create|update|delete|upsert|executeRaw/.test(logic), '4d. read-only');
  ok(/require\('\.\/cms-hospice-competitors'\)/.test(SRC),
     '4e. server.js imports the Phase A service');
  for (const [re, label] of [
    [/Lead|lead/, 'no lead handling'], [/notify/i, 'no notification handling'],
    [/serviceZipCodes|serviceRadiusKm/, 'no consumer coverage fields'],
    [/billingMode|planTier|stripe|email/i, 'no billing, plan or contact data']
  ]) ok(!re.test(logic), `11a. ${label} in the competitors route`);
  const consumerRoutes = SRC.match(/app\.(get|post)\('\/api\/(notify|search\/providers|public\/providers)'[\s\S]{0,3000}?\n\}\);/g) || [];
  ok(consumerRoutes.length >= 2 && !consumerRoutes.some((r) => /Competitor|competitors/i.test(r)),
     '11b. no consumer routing endpoint references competitor intelligence',
     `${consumerRoutes.length} consumer routes inspected`);
}

section('A. handler behaviour, executed');
(async () => {
  const payload = response();
  let sawProviderId = null;
  const h = makeHandler(
    async (uid) => (uid === 'user-1' ? { providerId: 'prov-from-token', provider: {} } : null),
    async (_p, pid) => { sawProviderId = pid; return payload; },
    {});
  let res = makeRes();
  await h({ providerUserId: 'user-1', params: { providerId: 'someone-else' },
            query: { providerId: 'someone-else' }, body: { providerId: 'someone-else' } }, res);
  ok(res._code === 200 && res._json === payload,
     '4f. a resolved response is passed through byte-identically');
  ok(sawProviderId === 'prov-from-token',
     '2b. the service is called with the TOKEN provider id, never one from the request',
     String(sawProviderId));

  res = makeRes();
  await h({ providerUserId: 'nobody' }, res);
  ok(res._code === 401 && res._json && res._json.error === 'Unauthorized',
     '1c. an unknown provider user gets 401 and no payload');

  const boom = makeHandler(async () => ({ providerId: 'p' }),
    async () => { throw new Error('synthetic failure'); }, {});
  res = makeRes();
  await boom({ providerUserId: 'u' }, res);
  ok(res._code === 500 && res._json && res._json.error === 'Server error',
     '4g. a service failure returns a generic 500');
  ok(!JSON.stringify(res._json).includes('synthetic failure'),
     '4h. …and never leaks the internal error text');

  for (const status of ['no_verified_identity', 'multiple_verified_identities', 'unsupported_care_type',
                        'no_service_area', 'facility_not_found', 'provider_not_found', 'market_unavailable']) {
    const unresolved = { status, provider: null, facility: null, landscape: null,
                         competitors: null, freshness: null, methodology: null, detail: 'x' };
    const hh = makeHandler(async () => ({ providerId: 'p' }), async () => unresolved, {});
    const r2 = makeRes();
    await hh({ providerUserId: 'u' }, r2);
    ok(r2._code === 200 && r2._json.status === status && r2._json.competitors === null,
       `5. ${status} propagates as a structured status, not an error`, String(r2._code));
  }

  const zero = response({ competitors: [], landscape: landscape({ overlappingFacilityCount: 0,
    totalSharedZipRelationships: 0, highestOverlapSharedZipCount: 0,
    topCompetitorSharedZipCount: 0, topCompetitorProviderOverlapPct: 0 }) });
  const hz = makeHandler(async () => ({ providerId: 'p' }), async () => zero, {});
  const rz = makeRes();
  await hz({ providerUserId: 'u' }, rz);
  ok(rz._code === 200 && rz._json.status === 'resolved' && Array.isArray(rz._json.competitors)
     && rz._json.competitors.length === 0,
     '6. zero overlap is a RESOLVED 200 with an empty array, not an error');

  runCapabilityAndUi();
})().catch((e) => { console.error('\nhandler harness failed:', e.stack || e.message); process.exit(1); });

// ============================ B. CAPABILITY ==================================
function runCapabilityAndUi() {
  section('B. Competitors capability');
  {
    for (const ct of ['hospice', 'hospice-care']) {
      const c = caps({ careType: ct });
      ok(c.cmsCompetitors.status === 'available',
         `13. resolved hospice care type "${ct}" => cmsCompetitors available`, c.cmsCompetitors.status);
      ok(!!c.cmsCompetitors.reason, '13b. …with a plain-language reason');
    }
    // 14 is the same capability answer: the capability is a PRECONDITION about
    // the care type, and a hospice with no overlapping competitor is still a
    // fully resolved market. The zero state is rendered, not hidden. Proven in
    // the UI section below.
    ok(caps({ careType: 'hospice' }).cmsCompetitors.status === 'available',
       '14. a hospice with zero competitors keeps the module available');
    for (const ct of ['palliative', 'palliative-care', 'home', 'home-care', 'assisted-living', '', null]) {
      const c = caps({ careType: ct });
      ok(c.cmsCompetitors.status === 'not_applicable',
         `17. non-CMS-applicable care type "${ct}" => not_applicable`, c.cmsCompetitors.status);
    }
    ok(!/available/.test(JSON.stringify(caps({ careType: 'home-care' }).cmsCompetitors)),
       '17b. …and never yields available for an unmodelled type');
    ok(capsOff({ careType: 'hospice' }).cmsCompetitors.status === 'coming_soon',
       '17g. …and with the release gate at its default the module is Coming soon',
       capsOff({ careType: 'hospice' }).cmsCompetitors.status);
    ok(caps({ careType: 'hospice' }).competitorBenchmarking.status === 'coming_soon',
       '17c. competitorBenchmarking stays coming_soon — head-to-head and trends are not built');
    ok(capsMod.INTELLIGENCE_MODULES.includes('cmsCompetitors'),
       '17d. cmsCompetitors is a registered intelligence module');
    const before = caps({ careType: 'hospice' });
    ok(before.cmsMarketOverlap.status === 'available' && before.cmsQuality.status === 'coming_soon',
       '17e. My Market and Quality capability logic is unchanged (gate OFF default)',
       `${before.cmsMarketOverlap.status}/${before.cmsQuality.status}`);
  }

  // Statuses 15, 16 and 18 are decided by the ENDPOINT, not the capability -
  // identity resolution needs the database and the capability function is
  // synchronous, exactly as for My Market and Quality. What must be true is that
  // the provider is never SHOWN an available Competitors module in those states:
  // no numbers, no summary and nothing to expand.
  section('B. unresolved states are not presented as available');
  {
    for (const [status, label] of [
      ['no_verified_identity', '15. unresolved identity'],
      ['multiple_verified_identities', '16. multiple verified identities'],
      ['no_service_area', '18. no CMS service area'],
      ['facility_not_found', '18b. facility not found'],
      ['provider_not_found', '18c. provider not found']
    ]) {
      const dom = makeDom();
      const R = loadRenderers(dom, async () => ({ status }));
      R.initCompetitorsAccordion();
      R.competitorsMessage(status);
      const e = dom.els;
      ok(e['comp-body'].hidden === true && e['comp-toggle'].hidden === true
         && e['comp-summary'].hidden === true && e['comp-detail'].hidden === true,
         `${label} => no metrics, no summary, nothing to expand`);
      ok(e['comp-status'].hidden === false && e['comp-status'].textContent.length > 20
         && e['comp-status'].textContent !== status,
         `    …and a plain-language reason, never the raw status code`,
         e['comp-status'].textContent.slice(0, 44));
    }
    const dom = makeDom();
    const R = loadRenderers(dom, async () => { throw new Error('should not be called'); });
    R.initCompetitorsAccordion();
    R.competitorsNotActivated();
    ok(dom.els['comp-card'].hidden === true,
       '17f. a non-CMS care type hides the compact card entirely');
  }

  // ============================ C. UI ========================================
  section('C. compact card and accordion');
  {
    const dom = makeDom();
    const data = response({ competitors: many(3), landscape: landscape({ overlappingFacilityCount: 3,
      topCompetitorSharedZipCount: 3, topCompetitorProviderOverlapPct: 37.5 }) });
    const R = loadRenderers(dom, async (p) => {
      if (p !== '/api/provider-intelligence/competitors') throw new Error('unexpected path ' + p);
      return data;
    });
    R.initMyMarketAccordion(); R.initQualityAccordion(); R.initCompetitorsAccordion();
    R.initCompetitors(CAP_ON);
    return R.ensureCompetitorsLoaded().then(async () => {
      const e = dom.els;
      ok(e['comp-card'].hidden === false, '19a. the compact card is revealed');
      ok(e['comp-summary'].hidden === false && /3 overlapping hospices/.test(e['comp-summary'].textContent),
         '19b. the compact card shows a live overlapping-hospice count', e['comp-summary'].textContent);
      ok(/top shares 3 ZIPs/.test(e['comp-summary'].textContent),
         '19c. …the top competitor shared-ZIP count', e['comp-summary'].textContent);
      ok(/37\.50% of your footprint/.test(e['comp-summary'].textContent),
         '19d. …and the top competitor share of the footprint');
      ok(e['comp-summary'].textContent.split('·').length === 2,
         '19e. …and is not overloaded — two facts', e['comp-summary'].textContent);
      ok(e['comp-status'].hidden === true, '19f. the loading status is cleared');
      ok(e['comp-toggle'].hidden === false, '19g. the expand control appears');

      ok(e['comp-detail'].hidden === true, '20a. the detail starts collapsed');
      e['comp-toggle'].click(); await tick();
      ok(e['comp-detail'].hidden === false, '20b. View insights expands Competitors');
      ok(e['comp-toggle'].getAttribute('aria-expanded') === 'true', '20c. …and reports it to assistive tech');
      ok(e['comp-toggle-label'].textContent === 'Hide competitor insights',
         '20d. …and the control relabels', e['comp-toggle-label'].textContent);
      e['comp-toggle'].click(); await tick();
      ok(e['comp-detail'].hidden === true, '21a. Hide insights collapses it');
      ok(e['comp-toggle-label'].textContent === 'View competitor insights', '21b. …and relabels back');
      e['comp-toggle'].click(); await tick();
      e['comp-collapse'].click(); await tick();
      ok(e['comp-detail'].hidden === true, '21c. the in-panel Hide control also collapses it');

      R.INTEL_ACCORDION.open('myMarket');
      ok(R.INTEL_ACCORDION.isOpen('myMarket') && !R.INTEL_ACCORDION.isOpen('competitors'),
         '22a. opening My Market closes Competitors');
      R.INTEL_ACCORDION.open('quality');
      ok(R.INTEL_ACCORDION.isOpen('quality') && !R.INTEL_ACCORDION.isOpen('myMarket'),
         '22b. opening Quality closes My Market');
      R.INTEL_ACCORDION.open('competitors');
      ok(R.INTEL_ACCORDION.isOpen('competitors') && !R.INTEL_ACCORDION.isOpen('quality')
         && !R.INTEL_ACCORDION.isOpen('myMarket'),
         '22c. opening Competitors closes both of the others — one module at a time');
      // Lazy-load and release-gate coverage runs next; the list tests follow it.
      runLazyAndGateTests();
    });
  }
}

function runLazyAndGateTests() {
  // ============================ F. LAZY LOAD =================================
  section('F. Competitors is lazy: nothing is requested until asked for');
  {
    // A counting fetch. Every assertion below reads the real call count made by
    // the page's own code path, not an inferred one.
    const makeCounter = (impl) => {
      const c = { n: 0, paths: [] };
      c.api = async (p) => { c.n += 1; c.paths.push(p); return impl(p); };
      return c;
    };

    // 1. page initialization makes zero Competitors API calls
    const c1 = makeCounter(async () => response());
    const d1 = makeDom();
    const R1 = loadRenderers(d1, c1.api);
    R1.initCompetitorsAccordion();
    R1.initCompetitors(CAP_ON);
    ok(c1.n === 0, 'L1. page initialization makes ZERO Competitors API calls', String(c1.n));
    ok(d1.els['comp-card'].hidden === false && d1.els['comp-toggle'].hidden === false,
       'L1b. …the compact card and its expand control are still offered');
    ok(d1.els['comp-status'].textContent === R1.COMPETITOR_PROMPT
       && /Select View competitor insights/.test(d1.els['comp-status'].textContent),
       'L1c. …showing static capability copy, not a loading state',
       d1.els['comp-status'].textContent);
    ok(d1.els['comp-summary'].hidden === true && d1.els['comp-body'].hidden === true,
       'L1d. …with no summary and no report body');
    ok(!/\d/.test(d1.els['comp-status'].textContent) && d1.els['comp-summary'].textContent === ''
       && d1.els['comp-overlap-count'].textContent === '',
       'L1e. …and NO fake metrics anywhere on the card');

    // 2. first expansion makes exactly one
    d1.els['comp-toggle'].click();
    return tick().then(() => tick()).then(async () => {
      ok(c1.n === 1, 'L2. the first expansion makes EXACTLY one request', String(c1.n));
      ok(c1.paths[0] === '/api/provider-intelligence/competitors',
         'L2b. …to the competitors endpoint', c1.paths.join(','));
      ok(d1.els['comp-detail'].hidden === false, 'L2c. …and the module expands');
      ok(d1.els['comp-body'].hidden === false && d1.els['comp-summary'].hidden === false,
         'L2d. …rendering the live summary and the report');
      // The count comes from landscape.overlappingFacilityCount, which the fixture
      // sets to 3 while carrying one competitor row - so this also proves the copy
      // reads the API's own landscape rather than competitors.length.
      ok(d1.els['comp-summary'].textContent
         === '3 overlapping hospices · top shares 4 ZIPs (50.00% of your footprint)',
         'L2e. …from the response, not a placeholder', d1.els['comp-summary'].textContent);
      ok(d1.els['comp-overlap-count'].textContent === '3'
         || d1.els['comp-overlap-count'].textContent === String(response().landscape.overlappingFacilityCount),
         'L2f. …the Competitive Landscape is populated', d1.els['comp-overlap-count'].textContent);
      ok((d1.tbodies['comp-table'].innerHTML.match(/<tr>/g) || []).length === 1,
         'L2g. …and Most Overlapping Competitors is populated');

      // 3. collapse / reopen must not refetch
      d1.els['comp-toggle'].click(); await tick();
      ok(d1.els['comp-detail'].hidden === true && c1.n === 1,
         'L3. collapsing makes no additional call', String(c1.n));
      d1.els['comp-toggle'].click(); await tick();
      ok(d1.els['comp-detail'].hidden === false && c1.n === 1,
         'L3b. reopening makes no additional call — the result is cached', String(c1.n));
      d1.els['comp-collapse'].click(); await tick();
      d1.els['comp-toggle'].click(); await tick();
      ok(c1.n === 1, 'L3c. …and still none after a third open/close cycle', String(c1.n));

      // 4. the other two modules must not trigger Competitors
      const c4 = makeCounter(async () => response());
      const d4 = makeDom();
      const R4 = loadRenderers(d4, c4.api);
      R4.initMyMarketAccordion(); R4.initQualityAccordion(); R4.initCompetitorsAccordion();
      R4.initCompetitors(CAP_ON);
      R4.INTEL_ACCORDION.open('myMarket');
      R4.INTEL_ACCORDION.open('quality');
      d4.els['mm-toggle'].click(); d4.els['q-toggle'].click();
      await tick();
      ok(c4.n === 0, 'L4. opening My Market or Quality triggers NO Competitors request', String(c4.n));
      ok(d4.els['comp-detail'].hidden === true, 'L4b. …and does not expand Competitors');

      // 5. a failed request is retryable and is never cached as success
      let failures = 2;
      const c5 = makeCounter(async () => {
        if (failures-- > 0) throw new Error('synthetic network failure');
        return response();
      });
      const d5 = makeDom();
      const R5 = loadRenderers(d5, c5.api);
      R5.initCompetitorsAccordion(); R5.initCompetitors(CAP_ON);
      d5.els['comp-toggle'].click(); await tick(); await tick();
      ok(c5.n === 1 && d5.els['comp-detail'].hidden === true,
         'L5. a failed request leaves the module collapsed', `${c5.n} call(s)`);
      ok(d5.els['comp-status'].hidden === false && d5.els['comp-status']._classes.has('is-error')
         && /Select View competitor insights to try again/.test(d5.els['comp-status'].textContent),
         'L5b. …showing a neutral, explicitly retryable error',
         d5.els['comp-status'].textContent);
      ok(!/synthetic network failure/.test(d5.els['comp-status'].textContent),
         'L5c. …that never leaks the transport error');
      ok(d5.els['comp-toggle'].hidden === false, 'L5d. …and the retry control stays live');
      ok(d5.els['comp-body'].hidden === true && d5.els['comp-summary'].hidden === true,
         'L5e. …with no partial report left on screen');
      d5.els['comp-toggle'].click(); await tick(); await tick();
      ok(c5.n === 2, 'L5f. a second click DOES retry — a failure is never cached', String(c5.n));
      d5.els['comp-toggle'].click(); await tick(); await tick();
      ok(c5.n === 3 && d5.els['comp-detail'].hidden === false,
         'L5g. …and the retry that succeeds renders the module', String(c5.n));
      ok(d5.els['comp-status']._classes.has('is-error') === false,
         'L5h. …clearing the error state');
      d5.els['comp-toggle'].click(); await tick();
      d5.els['comp-toggle'].click(); await tick();
      ok(c5.n === 3, 'L5i. …after which it is cached like any other success', String(c5.n));

      // 6. a structured unresolved status is a real answer and is cached
      for (const status of ['no_verified_identity', 'multiple_verified_identities', 'no_service_area']) {
        const c6 = makeCounter(async () => ({ status, provider: null, facility: null,
          landscape: null, competitors: null, freshness: null, methodology: null, detail: null }));
        const d6 = makeDom();
        const R6 = loadRenderers(d6, c6.api);
        R6.initCompetitorsAccordion(); R6.initCompetitors(CAP_ON);
        d6.els['comp-toggle'].click(); await tick(); await tick();
        ok(c6.n === 1 && d6.els['comp-detail'].hidden === true && d6.els['comp-body'].hidden === true,
           `L6. ${status} renders the neutral reason and does not expand`, String(c6.n));
        await R6.ensureCompetitorsLoaded();
        await R6.ensureCompetitorsLoaded();
        await R6.toggleCompetitors(d6.els['comp-toggle']);
        ok(c6.n === 1, `L6b. …and is CACHED — repeated attempts do not refetch`, String(c6.n));
        ok(d6.els['comp-status'].textContent.length > 20
           && d6.els['comp-status'].textContent !== status,
           '    …with plain language, never the raw status code');
      }

      // 7. resolved zero overlap is cached the same way
      const c7 = makeCounter(async () => response({ competitors: [],
        landscape: landscape({ overlappingFacilityCount: 0, totalSharedZipRelationships: 0,
          highestOverlapSharedZipCount: 0, topCompetitorSharedZipCount: 0,
          topCompetitorProviderOverlapPct: 0 }) }));
      const d7 = makeDom();
      const R7 = loadRenderers(d7, c7.api);
      R7.initCompetitorsAccordion(); R7.initCompetitors(CAP_ON);
      d7.els['comp-toggle'].click(); await tick(); await tick();
      ok(c7.n === 1 && d7.els['comp-detail'].hidden === false,
         'L7. a resolved zero-overlap market expands on one request', String(c7.n));
      ok(d7.els['comp-empty'].hidden === false
         && d7.els['comp-empty'].textContent === R7.COMPETITOR_ZERO_OVERLAP,
         'L7b. …showing the neutral zero-overlap sentence');
      d7.els['comp-toggle'].click(); await tick();
      d7.els['comp-toggle'].click(); await tick();
      d7.els['comp-toggle'].click(); await tick();
      ok(c7.n === 1, 'L7c. …and is cached across repeated open/close', String(c7.n));

      // 8. filtering and revealing are purely local
      const c8 = makeCounter(async () => response({ competitors: many(40),
        landscape: landscape({ overlappingFacilityCount: 40 }) }));
      const d8 = makeDom();
      const R8 = loadRenderers(d8, c8.api);
      R8.initCompetitorsAccordion(); R8.initCompetitors(CAP_ON);
      d8.els['comp-toggle'].click(); await tick(); await tick();
      ok(c8.n === 1, 'L8. a 40-competitor market loads on one request', String(c8.n));
      d8.els['comp-more'].click();
      d8.els['comp-filter'].type('HOSPICE 03');
      d8.els['comp-filter'].type('U80005');
      d8.els['comp-filter'].type('northtown');
      d8.els['comp-filter'].type('');
      d8.els['comp-more'].click();
      await tick();
      ok(c8.n === 1, 'L8b. filtering and revealing make ZERO further API calls', String(c8.n));
      ok((d8.tbodies['comp-table'].innerHTML.match(/<tr>/g) || []).length === 40,
         'L8c. …and still operate on the full cached result');

      runGateTests();
    });
  }
}

// ============================ G. RELEASE GATE ================================
function runGateTests() {
  section('G. CMS_COMPETITOR_INTELLIGENCE_ENABLED parsing');
  {
    const gate = grab(/const CMS_COMPETITOR_INTELLIGENCE_ENABLED = [^\n]*/, 'gate');
    ok(/process\.env\.CMS_COMPETITOR_INTELLIGENCE_ENABLED === 'true'/.test(gate),
       'G1. the gate is an exact === comparison against the lowercase string "true"', gate.trim());
    ok(!/\|\|\s*true|!==|toLowerCase|Boolean\(|trim\(/.test(gate),
       'G2. …with no default-on, no case folding and no trimming');
    ok(/CMS_COMPETITOR_INTELLIGENCE_ENABLED/.test(SRC.match(/const CMS_QUALITY_INTELLIGENCE_ENABLED[\s\S]{0,2400}/)[0]),
       'G3. …declared beside the Quality gate, following the same discipline');

    const st = (v) => buildCaps(v === undefined ? {} : { CMS_COMPETITOR_INTELLIGENCE_ENABLED: v })
      .providerIntelligenceCapabilities({ careType: 'hospice' }).cmsCompetitors.status;
    ok(st('true') === 'available', 'G4. "true" => ENABLED', st('true'));
    for (const bad of ['TRUE', 'True', 'tRuE', '1', 'yes', 'y', 'on', 'ON', 'enabled', 'false',
                       'FALSE', 'null', 'undefined', '', '  ', ' true', 'true ', 'true\n',
                       '"true"', "'true'", 'truthy']) {
      ok(st(bad) !== 'available', `G5. ${JSON.stringify(bad)} FAILS CLOSED => disabled`, st(bad));
    }
    ok(st(undefined) !== 'available', 'G6. a MISSING variable fails closed => disabled', st(undefined));
    ok(st(undefined) === 'coming_soon',
       'G7. …and yields the ordinary Coming soon card, not an error', st(undefined));

    // The gate must move Competitors and nothing else.
    for (const v of [undefined, 'true', 'TRUE', 'nonsense']) {
      const c = buildCaps(v === undefined ? {} : { CMS_COMPETITOR_INTELLIGENCE_ENABLED: v })
        .providerIntelligenceCapabilities({ careType: 'hospice' });
      ok(c.cmsMarketOverlap.status === 'available' && c.cmsQuality.status === 'coming_soon'
         && c.competitorBenchmarking.status === 'coming_soon',
         `G8. gate ${JSON.stringify(v)} leaves My Market, Quality and competitorBenchmarking untouched`,
         `${c.cmsMarketOverlap.status}/${c.cmsQuality.status}/${c.competitorBenchmarking.status}`);
    }
    const qOn = buildCaps({ CMS_QUALITY_INTELLIGENCE_ENABLED: 'true' })
      .providerIntelligenceCapabilities({ careType: 'hospice' });
    ok(qOn.cmsQuality.status === 'available' && qOn.cmsCompetitors.status === 'coming_soon',
       'G9. the two gates are independent — Quality ON does not enable Competitors',
       `${qOn.cmsQuality.status}/${qOn.cmsCompetitors.status}`);
    ok(caps({ careType: 'hospice' }).cmsCompetitors.status === 'available'
       && caps({ careType: 'home-care' }).cmsCompetitors.status === 'not_applicable',
       'G10. gate ON restores the full Phase B capability behaviour');
  }

  section('G. gate OFF: the endpoint returns no competitor data');
  {
    const gate = ROUTE.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '');
    ok(/if \(!CMS_COMPETITOR_INTELLIGENCE_ENABLED\) return res\.status\(404\)/.test(gate),
       'G11. the route checks the gate and 404s, as the quality route does');
    ok(gate.indexOf('CMS_COMPETITOR_INTELLIGENCE_ENABLED')
       < gate.indexOf('buildProviderCmsCompetitors'),
       'G12. …BEFORE the service is ever called');
    ok(!/CMS_COMPETITOR_INTELLIGENCE_ENABLED/.test(
        fs.readFileSync(path.join(ROOT, 'cms-hospice-competitors.js'), 'utf8')),
       'G13. the Phase A service knows nothing about the gate');
    for (const f of ['cms-hospice-market.js', 'cms-hospice-quality.js', 'consumer-lead-eligibility.js']) {
      ok(!/CMS_COMPETITOR_INTELLIGENCE_ENABLED/.test(fs.readFileSync(path.join(ROOT, f), 'utf8')),
         `G13b. …and so does ${f}`);
    }

    return (async () => {
      let serviceCalled = 0;
      const off = makeHandler(async () => ({ providerId: 'p', provider: {} }),
        async () => { serviceCalled += 1; return response(); }, {}, false);
      const r = makeRes();
      await off({ providerUserId: 'u' }, r);
      ok(r._code === 404 && r._json && r._json.error === 'Not found',
         'G14. gate OFF => 404 Not found', `${r._code} ${JSON.stringify(r._json)}`);
      ok(serviceCalled === 0, 'G15. …the competitor service is never invoked', String(serviceCalled));
      const blob = JSON.stringify(r._json);
      for (const leak of ['competitors', 'landscape', 'ccn', 'sharedZip', 'bestHospicePartner',
                          'qualityAvailability', 'resolved', 'no_verified_identity']) {
        ok(!blob.includes(leak), `G16. …and no "${leak}" is returned`);
      }
      ok(!/status/.test(blob),
         'G17. …not even a structured fail-closed status, which would imply the feature is live');

      const on = makeHandler(async () => ({ providerId: 'p', provider: {} }),
        async () => response(), {}, true);
      const r2 = makeRes();
      await on({ providerUserId: 'u' }, r2);
      ok(r2._code === 200 && r2._json.status === 'resolved',
         'G18. gate ON => the Phase B endpoint behaviour is unchanged');

      section('G. gate OFF: the page offers nothing and requests nothing');
      let calls = 0;
      const dom = makeDom();
      const R = loadRenderers(dom, async () => { calls += 1; return response(); });
      R.initCompetitorsAccordion();
      R.initCompetitors(capsOff({ careType: 'hospice' }));
      ok(calls === 0, 'G19. gate OFF => the page makes ZERO Competitors requests', String(calls));
      ok(dom.els['comp-card'].hidden === true,
         'G20. …the compact Competitors card is not shown at all');
      ok(dom.els['comp-toggle'].hidden === true,
         'G21. …there is NO live "View competitor insights" affordance');
      ok(dom.els['comp-body'].hidden === true && dom.els['comp-summary'].hidden === true
         && dom.els['comp-detail'].hidden === true,
         'G22. …and no report, summary or expanded panel');
      ok(dom.els['comp-status'].textContent === '',
         'G23. …not even a loading or prompt line', dom.els['comp-status'].textContent);
      dom.els['comp-toggle'].click();
      await tick(); await tick();
      ok(calls === 0,
         'G24. …and clicking the hidden control still requests nothing before it is activated',
         String(calls));
      ok(/initCompetitors\(data\.capabilities \|\| \{\}\);/.test(PAGE)
         && !/loadCmsCompetitors/.test(PAGE),
         'G25. page start() initialises Competitors without loading it');
      ok(/loadCmsMarket\(data\.capabilities \|\| \{\}\);/.test(PAGE)
         && /loadCmsQuality\(data\.capabilities \|\| \{\}\);/.test(PAGE),
         'G26. …while My Market and Quality keep their existing eager load');
      // The page's OWN start() body, not just the renderer block. Nothing in it
      // may reach the network for Competitors - only initialise the card.
      const startBody = SCRIPT_BODY.match(/\(async function start\(\) \{[\s\S]*?\n  \}\)\(\);/)[0];
      ok(/initCompetitors\(/.test(startBody),
         'G27. start() initialises the Competitors card');
      for (const forbidden of ['ensureCompetitorsLoaded', 'fetchCompetitorsOnce', 'toggleCompetitors',
                               'loadCmsCompetitors', 'renderCompetitorsData',
                               "/api/provider-intelligence/competitors"]) {
        ok(startBody.indexOf(forbidden) < 0,
           `G28. …and start() never calls ${forbidden} — the module cannot load eagerly`);
      }
      ok(/loadCmsMarket\(/.test(startBody) && /loadCmsQuality\(/.test(startBody),
         'G29. …while start() still eagerly loads My Market and Quality');

      await runHeadToHeadTests();
      runListTests();
    })();
  }
}

function renderList(list, extra) {
  const dom = makeDom();
  const R = loadRenderers(dom, async () => response(Object.assign({ competitors: list }, extra || {})));
  R.initCompetitorsAccordion();
  R.renderCompetitorTable(list);
  return { dom, R, body: () => dom.tbodies['comp-table'].innerHTML };
}

function runListTests() {
  section('C. competitor list: paging and filtering');
  {
    const big = many(40);
    const t = renderList(big);
    const rows = (h) => (h.match(/<tr>/g) || []).length;
    ok(rows(t.body()) === 10, '23. the first 10 competitors are shown by default', String(rows(t.body())));
    ok(t.dom.els['comp-more'].hidden === false
       && t.dom.els['comp-more'].textContent === 'Show 30 more',
       '24a. a reveal control offers the remainder in place', t.dom.els['comp-more'].textContent);
    t.dom.els['comp-more'].click();
    ok(rows(t.body()) === 40, '24b. revealing shows every competitor', String(rows(t.body())));
    ok(t.dom.els['comp-more'].hidden === true, '24c. …and the control disappears');

    const ten = renderList(many(10));
    ok((ten.body().match(/<tr>/g) || []).length === 10 && ten.dom.els['comp-more'].hidden === true,
       '25a. exactly 10 competitors need no reveal control');
    const eleven = renderList(many(11));
    ok(eleven.dom.els['comp-more'].hidden === false
       && eleven.dom.els['comp-more'].textContent === 'Show 1 more',
       '25b. 11 competitors do', eleven.dom.els['comp-more'].textContent);

    ok(renderList(many(25)).dom.els['comp-filter-wrap'].hidden === true,
       '26a. 25 competitors is not enough to earn a filter');
    ok(t.dom.els['comp-filter-wrap'].hidden === false,
       '26b. 40 competitors is — the filter appears');

    const f = renderList(big);
    f.dom.els['comp-filter'].type('HOSPICE 007');
    ok((f.body().match(/<tr>/g) || []).length === 1 && /HOSPICE 007/.test(f.body()),
       '26c. the filter matches CMS facility name', String((f.body().match(/<tr>/g) || []).length));
    ok(/Showing 1 of 1 matching, from 40/.test(f.dom.els['comp-filter-count'].textContent),
       '26d. …and reports how much of the list is showing',
       f.dom.els['comp-filter-count'].textContent);
    f.dom.els['comp-filter'].type('U80012');
    ok((f.body().match(/<tr>/g) || []).length === 1 && /U80012/.test(f.body()),
       '27. the filter matches CCN');
    f.dom.els['comp-filter'].type('northtown');
    const nrows = (f.body().match(/<tr>/g) || []).length;
    ok(nrows === 10 && /Northtown/.test(f.body()) && !/Southtown/.test(f.body()),
       '28a. the filter matches city, case-insensitively, and re-pages to 10', String(nrows));
    ok(/Showing 10 of 20 matching, from 40/.test(f.dom.els['comp-filter-count'].textContent),
       '28b. …and the reveal control applies to the filtered subset',
       f.dom.els['comp-filter-count'].textContent);
    f.dom.els['comp-filter'].type('YY');
    ok((f.body().match(/<tr>/g) || []).length === 10 && /YY/.test(f.body()),
       '28c. the filter matches state');
    f.dom.els['comp-filter'].type('zzzz-no-such-hospice');
    ok(/No hospice in your CMS overlap matches that search/.test(f.body())
       && f.dom.els['comp-more'].hidden === true,
       '28d. an empty result says so plainly and offers nothing to reveal');
    f.dom.els['comp-filter'].type('');
    ok((f.body().match(/<tr>/g) || []).length === 10,
       '28e. clearing the filter restores the full ranked list at page one');
    ok(!/sort|Sort/.test(f.body()), '28f. the list offers no sort control — backend order is authoritative');

    // Behavioural proof that the API's ranking survives rendering: the fixture is
    // deliberately ordered so CMS publication count runs OPPOSITE to overlap. If
    // the page ever re-sorted on quality, the emitted row order would invert.
    const byApi = [
      competitor({ ccn: 'U71001', name: 'FIRST BY OVERLAP', sharedZipCount: 9,
                   qualityAvailability: { publishedMeasureCount: 0, surfacedMeasureCount: 10 } }),
      competitor({ ccn: 'U71002', name: 'SECOND BY OVERLAP', sharedZipCount: 5,
                   qualityAvailability: { publishedMeasureCount: 5, surfacedMeasureCount: 10 } }),
      competitor({ ccn: 'U71003', name: 'THIRD BY OVERLAP', sharedZipCount: 1,
                   qualityAvailability: { publishedMeasureCount: 10, surfacedMeasureCount: 10 } })
    ];
    const o = renderList(byApi);
    const emitted = (o.body().match(/<td class="n">(U7100\d)<\/td>/g) || [])
      .map((c) => c.replace(/[^U0-9]/g, ''));
    ok(JSON.stringify(emitted) === JSON.stringify(['U71001', 'U71002', 'U71003']),
       '28g. rendered row order is the API order exactly, with quality running opposite',
       emitted.join(','));
  }

  section('C. competitor row content and labelling');
  {
    const list = [
      competitor({ ccn: 'U70011', name: 'IDENTICAL NAME HOSPICE', city: 'Alpha', state: 'ZZ',
                   zip: '90011', sharedZipCount: 6, providerOverlapPct: 75, competitorOverlapPct: 60,
                   qualityAvailability: { publishedMeasureCount: 8, surfacedMeasureCount: 10 },
                   bestHospicePartner: true }),
      competitor({ ccn: 'U70012', name: 'IDENTICAL NAME HOSPICE', city: 'Beta', state: 'YY',
                   zip: null, sharedZipCount: 2, providerOverlapPct: 25, competitorOverlapPct: 10,
                   qualityAvailability: { publishedMeasureCount: 0, surfacedMeasureCount: 10 } }),
      competitor({ ccn: 'U70013', name: 'NO QUALITY HOSPICE', qualityAvailability: null })
    ];
    const t = renderList(list);
    const html = t.body();

    ok(/>Office ZIP</.test(PAGE) && !/>ZIP<\/th>/.test(PAGE.match(/<table class="q-table comp-table"[\s\S]*?<\/thead>/)[0]),
       '29a. the facility ZIP column header is exactly "Office ZIP"');
    ok(!/<th scope="col">ZIP/.test(PAGE.match(/id="comp-table"[\s\S]*?<\/thead>/)[0]),
       '29b. …and never a plain "ZIP" in this table');
    ok(/CMS's facility ZIP is the hospice office address/.test(PAGE),
       '29c. …with the reason recorded next to it');

    ok(/U70011/.test(html) && /U70012/.test(html),
       '30a. two facilities with IDENTICAL names both appear');
    ok((html.match(/IDENTICAL NAME HOSPICE/g) || []).length === 2,
       '30b. …neither is merged away');
    ok(/<td class="n">U70011<\/td>/.test(html) && /<td class="n">U70012<\/td>/.test(html),
       '30c. …and each carries its own CCN on screen');

    ok(/CMS published 8 of 10 measures/.test(html),
       '31a. publication copy is explicit, never a bare "8 of 10"');
    ok(!/>8 of 10</.test(html), '31b. …and the bare form appears nowhere');
    ok(/CMS quality data unavailable/.test(html),
       '32a. a null qualityAvailability reads "CMS quality data unavailable"');
    ok(!/0 of 0/.test(html), '32b. …never a fabricated "0 of 0"');
    ok(/CMS published 0 of 10 measures/.test(html),
       '33a. a genuine zero is stated plainly as 0 of 10');
    const qaCells = html.match(/<span class="comp-qa">[^<]*<\/span>/g) || [];
    ok(qaCells.length === 3, '33b. every row carries the publication cell', String(qaCells.length));
    ok(!/comp-qa [a-z]/.test(html) && !/class="[^"]*(favorable|unfavorable|is-bad|warn|danger)/.test(html),
       '33c. publication count is styled neutrally — never as bad performance');

    ok((html.match(/comp-partner">Best Hospice partner</g) || []).length === 1,
       '34a. the partner badge renders exactly once, for the one true row',
       String((html.match(/Best Hospice partner/g) || []).length));
    ok(/U70011[\s\S]*?/.test(html) && html.indexOf('Best Hospice partner') < html.indexOf('U70012'),
       '34b. …on the correct competitor');
    ok(!/partner[^<]*false/i.test(html), '34c. nothing is rendered for a false badge');

    // Phase C: Compare is now a real control on every row, carrying the CCN it
    // will request. It is never disabled and never a placeholder.
    ok((html.match(/class="comp-compare" data-compare-ccn="/g) || []).length === 3,
       '35. every competitor row carries a real Compare control',
       String((html.match(/comp-compare/g) || []).length));
    ok(/data-compare-ccn="U70011"/.test(html) && /data-compare-ccn="U70013"/.test(html),
       '35a. …each bound to its own CCN, never to a name');
    ok(!/disabled/.test(html) && !/coming soon/i.test(html)
       && !/Compare soon/i.test(html),
       '35b. …live, not a disabled placeholder');
    ok(/<th scope="col">Compare<\/th>/.test(PAGE), '35c. …under a Compare column header');

    ok(/<td class="n">—<\/td>/.test(html), '9. a competitor with no office ZIP shows an em dash');
    ok(/Alpha, ZZ/.test(html) && /Beta, YY/.test(html), '30d. location renders as city, state');
    ok(/75\.00%/.test(html) && /60\.00%/.test(html),
       '30e. both percentages render to the API precision');
  }

  section('C. landscape, zero overlap and freshness');
  {
    const dom = makeDom();
    const R = loadRenderers(dom, async () => null);
    const l = landscape({ overlappingFacilityCount: 12, providerZipCount: 90,
      totalSharedZipRelationships: 140, averageCompetitorsPerProviderZip: 1.56,
      topCompetitorSharedZipCount: 30, topCompetitorProviderOverlapPct: 33.33 });
    R.renderCompetitorLandscape(l, competitor({ ccn: 'U70099', name: 'TOP SYNTHETIC HOSPICE',
      sharedZipCount: 30, providerOverlapPct: 33.33 }));
    ok(dom.els['comp-overlap-count'].textContent === '12',
       '1u. the headline is the overlapping-hospice count', dom.els['comp-overlap-count'].textContent);
    ok(/90 CMS-reported service ZIP codes/.test(dom.els['comp-overlap-note'].textContent),
       '2u. …explained against the provider\'s own CMS footprint');
    ok(/>30</.test(dom.els['comp-top-list'].innerHTML)
       && /33\.33%/.test(dom.els['comp-top-list'].innerHTML),
       '3u. the top competitor block carries shared ZIPs and share of footprint',
       dom.els['comp-top-list'].innerHTML.slice(0, 70));
    ok(dom.els['comp-top-note'].textContent === 'TOP SYNTHETIC HOSPICE · CCN U70099',
       '4u. …and names the hospice with its CCN', dom.els['comp-top-note'].textContent);
    ok(/Your CMS service ZIP codes/.test(dom.els['comp-coverage'].innerHTML)
       && />90</.test(dom.els['comp-coverage'].innerHTML),
       '5u. the demoted coverage row carries the CMS service ZIP count');
    const shown = dom.els['comp-coverage'].innerHTML;
    ok(!/market share|patient volume|referral volume|revenue|rank|grade|score/i.test(
        shown + dom.els['comp-top-list'].innerHTML + dom.els['comp-overlap-note'].textContent),
       '38a. the landscape makes no market-share, volume, rank, grade or score claim');

    // Zero overlap
    const z = makeDom();
    const RZ = loadRenderers(z, async () => response({ competitors: [], landscape: landscape({
      overlappingFacilityCount: 0, totalSharedZipRelationships: 0, highestOverlapSharedZipCount: 0,
      topCompetitorSharedZipCount: 0, topCompetitorProviderOverlapPct: 0 }) }));
    RZ.initCompetitorsAccordion(); RZ.initCompetitors(CAP_ON);
    return RZ.ensureCompetitorsLoaded().then(() => {
      const e = z.els;
      ok(e['comp-body'].hidden === false && e['comp-toggle'].hidden === false,
         '36a. zero overlap still renders an expandable module');
      ok(e['comp-empty'].hidden === false
         && e['comp-empty'].textContent
            === 'No other Medicare-certified hospice shares a CMS-reported service ZIP with you in the current CMS data.',
         '36b. …with the exact neutral zero-overlap sentence', e['comp-empty'].textContent);
      ok(!/no competition|No competition|nobody|none nearby/i.test(e['comp-empty'].textContent),
         '36c. …and it is never called "no competition"');
      ok(e['comp-table'].hidden === true && e['comp-more'].hidden === true
         && e['comp-filter-wrap'].hidden === true,
         '36d. …no empty table, filter or reveal control is left on screen');
      ok(e['comp-overlap-count'].textContent === '0',
         '36e. …the landscape reports an honest zero');
      ok(e['comp-top-empty'].hidden === false && e['comp-top-note'].textContent === '',
         '36f. …and no top competitor is invented');
      ok(e['comp-summary'].textContent === 'No overlapping hospices in the current CMS data',
         '36g. …the compact summary says so neutrally', e['comp-summary'].textContent);

      // Freshness: two releases, never collapsed
      const f = makeDom();
      const RF = loadRenderers(f, async () => response());
      RF.initCompetitorsAccordion(); RF.initCompetitors(CAP_ON);
      return RF.ensureCompetitorsLoaded().then(() => {
        ok(f.els['comp-fresh'].hidden === false && /Sep 1, 2026/.test(f.els['comp-fresh'].textContent),
           '40a. the CMS facility release date is shown', f.els['comp-fresh'].textContent);
        ok(f.els['comp-fresh-quality'].hidden === false
           && /Aug 19, 2026/.test(f.els['comp-fresh-quality'].textContent),
           '40b. the CMS quality release date is shown SEPARATELY',
           f.els['comp-fresh-quality'].textContent);
        ok(f.els['comp-fresh'].textContent !== f.els['comp-fresh-quality'].textContent,
           '40c. …the two dates are never collapsed into one');

        // Quality release unavailable: the list must still render.
        const nq = makeDom();
        const RN = loadRenderers(nq, async () => response({
          competitors: [competitor({ qualityAvailability: null })],
          freshness: Object.assign({}, response().freshness, { qualityRelease: null }) }));
        RN.initCompetitorsAccordion(); RN.initCompetitors(CAP_ON);
        return RN.ensureCompetitorsLoaded().then(() => {
          ok(nq.els['comp-body'].hidden === false && nq.els['comp-table'].hidden === false,
             '6u. a missing quality release still renders the overlap list');
          ok(/CMS quality data unavailable for this snapshot/.test(nq.els['comp-fresh-quality'].textContent),
             '6v. …and says so in the freshness line', nq.els['comp-fresh-quality'].textContent);
          ok(/CMS quality data unavailable/.test(nq.tbodies['comp-table'].innerHTML),
             '6w. …and in every row, with no fabricated zero');
          runStaticTests();
        });
      });
    });
  }
}

function runStaticTests() {
  section('D. attribution, methodology and honesty');
  {
    const dom = makeDom();
    const R = loadRenderers(dom, async () => null);
    R.renderCompetitorNote(response());
    const note = dom.els['comp-note'].textContent;
    for (const [needle, label] of [
      ['CMS publishes the facility and service-area information', '39a. CMS is named as the publisher'],
      ['Best Hospice calculates the overlap counts and percentages', '39b. Best Hospice is named as the calculator'],
      ['A competitor here is a synthetic definition supplied by the fixture.',
        '39c. the competitor definition comes from the API, not a second copy in the page'],
      ['supply and footprint proxy', '39d. overlap is described as a supply proxy'],
      ['does not prove actual referral competition', '39e. …and explicitly not proof of referral competition'],
      ['patient volume or market share', '39f. …nor of volume or market share'],
      ['do NOT determine Best Hospice consumer lead eligibility',
        '40u. CMS service ZIPs are separated from consumer lead eligibility'],
      ['Lead eligibility still uses your Best Hospice provider coverage rules',
        '40v. …and the real basis for eligibility is named'],
      ['not a quality score', '40w. the publication count is disclaimed as not a score'],
      ['does not calculate an overall competitor score, rank or grade',
        '40x. no proprietary competitor score, rank or grade is claimed']
    ]) ok(note.indexOf(needle) >= 0, label);

    const dom2 = makeDom();
    const R2 = loadRenderers(dom2, async () => null);
    R2.renderCompetitorNote({ methodology: null });
    ok(/A competitor here means another Medicare-certified hospice/.test(dom2.els['comp-note'].textContent),
       '39g. a missing API methodology still yields the mandatory statements');

    const panel = PAGE.match(/data-section="Competitors"[\s\S]*?id="mi-competitors-grid"/)[0];
    ok(/Reported by CMS/.test(panel) && /Best Hospice comparison/.test(panel),
       '39h. both attribution chips are present in the panel');
    ok((panel.match(/q-prov cms/g) || []).length >= 1 && (panel.match(/q-prov bh/g) || []).length >= 3,
       '39i. …the mixed-source list block carries BOTH chips',
       `${(panel.match(/q-prov cms/g) || []).length} cms / ${(panel.match(/q-prov bh/g) || []).length} bh`);
  }

  section('D. no fabricated data, no forbidden language');
  {
    const panel = PAGE.match(/data-section="Competitors"[\s\S]*?id="mi-competitors-grid"/)[0];
    const script = SCRIPT_BODY.slice(SCRIPT_BODY.indexOf('  // ---- CMS Competitors'),
                                    SCRIPT_BODY.indexOf('  // ---- section navigation ----'));
    // Placeholders only: no digit may sit in a value slot in the static markup.
    ok(/id="comp-overlap-count">&mdash;</.test(panel),
       '41a. the headline metric ships as a placeholder, not an example number');
    ok(!/\d+(\.\d+)?%/.test(panel), '41b. no example percentage in the static panel');
    ok(!/\b[A-Z]\d{5}\b|\b\d{6}\b/.test(panel), '41c. no example CCN in the static panel');
    for (const bad of ['121509', 'ISLANDS HOSPICE', 'Vrablic', 'AccentCare', '96813', '96740']) {
      ok(!panel.includes(bad) && !script.includes(bad),
         `41d. no production identifier "${bad}"`);
    }
    // The methodology deliberately NEGATES these words; a claim would state them.
    // Scope the check to the rendering code that produces metrics and rows.
    // Comments stripped, for the same reason: the rendering code explains that
    // "the API ranks purely by CMS service-area overlap", which is a statement
    // ABOUT the ordering, not a rank this page emits.
    const rendering = script.slice(script.indexOf('function renderCompetitorLandscape'),
                                   script.indexOf('function renderCompetitorNote'))
      .replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '');
    for (const bad of ['market share', 'patient volume', 'referral volume', 'revenue',
                       'rank', 'grade', 'score', 'percentile', 'utilization']) {
      ok(!new RegExp(bad, 'i').test(rendering), `38b. no "${bad}" in the rendered landscape or list`);
    }
    ok(!/Math\.(random|round\(.*\/)/.test(rendering.replace(/Math\.min/g, '')),
       '41e. no metric is computed or invented in the page — every number comes from the API');
    ok(!/\.sort\(/.test(script), '38c. the page never re-sorts the competitor list');
  }

  section('D. responsive and accessible');
  {
    ok(/<div class="q-table-wrap">\s*<table class="q-table comp-table"/.test(PAGE),
       '42a. the 8-column table scrolls horizontally rather than overflowing');
    ok(/\.q-snapshot \{ grid-template-columns:minmax\(0,1fr\); \}/.test(PAGE)
       && /@media \(max-width:760px\)/.test(PAGE),
       '42b. the landscape snapshot collapses to one column on a phone');
    ok(/@media \(max-width:600px\)[\s\S]*?\.comp-filter \{ max-width:none; \}/.test(PAGE),
       '42c. the filter goes full width on a phone');
    ok(/class="sr-only" for="comp-filter"/.test(PAGE), '42d. the filter has a screen-reader label');
    ok(/<caption class="sr-only">Hospices that share/.test(PAGE), '42e. the table has a caption');
    ok(/id="comp-status" role="status"/.test(PAGE) && /id="comp-filter-count" role="status"/.test(PAGE),
       '42f. status and filter-count regions are announced');
    ok(/aria-controls="comp-detail"/.test(PAGE) && /aria-expanded="false"/.test(PAGE),
       '42g. the expand control is wired for assistive tech');
    ok(/<th scope="col">/.test(PAGE.match(/id="comp-table"[\s\S]*?<\/thead>/)[0]),
       '42h. every column header is scoped');
  }

  maybeDatabase();
}

// ============================ E. END TO END ==================================
function maybeDatabase() {
  const DB = process.env.TEST_DATABASE_URL;
  if (!DB) { console.log('\n--- end-to-end database tests SKIPPED (set TEST_DATABASE_URL) ---'); return finish(); }
  if (/besthospice_db|besthospice_shadow|render\.com|dpg-/i.test(DB)) {
    console.log('  FAIL   TEST_DATABASE_URL looks like production or shadow'); fail++; return finish();
  }
  section('E. the real handler over the real service and real rows');
  const { PrismaClient } = require('@prisma/client');
  const { buildProviderCmsCompetitors } = require(path.join(ROOT, 'cms-hospice-competitors.js'));
  const MREG = require(path.join(ROOT, 'data', 'cms-hospice-quality-measures.json'));
  const prisma = new PrismaClient({ datasources: { db: { url: DB } } });
  const uuid = () => require('crypto').randomUUID();
  const S = 'cms_hospice', REL = 'rel-e2e';

  (async () => {
    try {
      await prisma.$executeRawUnsafe(
        'TRUNCATE TABLE "CmsFacilityMeasure","CmsMeasureDefinition","CmsFacilityServiceArea","CmsFacility",'
        + '"CmsRelease","ProviderExternalIdentity","Provider" CASCADE');
      await prisma.$executeRawUnsafe(
        `INSERT INTO "CmsRelease" (id,source,"releaseKey","capturedAt","ingestedAt","datasetCount")
         VALUES ($1,$2,'2026-08-19',NOW(),NOW(),6)`, REL, S);
      for (const m of MREG.measures) {
        await prisma.$executeRawUnsafe(
          `INSERT INTO "CmsMeasureDefinition" (id,source,"measureCode","cmsMeasureName","shortLabel",
             dimension,family,"valueKind",direction,decimals,surfaced,"createdAt","updatedAt")
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,TRUE,NOW(),NOW())`,
          uuid(), S, m.measureCode, m.cmsMeasureName, m.shortLabel, m.dimension, m.family,
          m.valueKind, m.direction, m.decimals);
      }
      const fac = async (ccn, name, zips) => {
        const id = 'fac-' + ccn;
        await prisma.$executeRawUnsafe(
          `INSERT INTO "CmsFacility" (id,source,ccn,name,address,city,state,zip,
             "firstSeenReleaseId","lastSeenReleaseId","createdAt","updatedAt")
           VALUES ($1,$2,$3,$4,'1 Synthetic Rd','Testville','ZZ','90001',$5,$5,NOW(),NOW())`,
          id, S, ccn, name, REL);
        for (const z of zips) {
          await prisma.$executeRawUnsafe(
            `INSERT INTO "CmsFacilityServiceArea" (id,"facilityId",source,zip,
               "firstSeenReleaseId","lastSeenReleaseId","createdAt")
             VALUES ($1,$2,$3,$4,$5,$5,NOW())`, uuid(), id, S, z, REL);
        }
        return id;
      };
      const prov = (id, over = {}) => prisma.$executeRawUnsafe(
        `INSERT INTO "Provider" (id,name,email,address,city,state,zip,lat,lon,
           "serviceRadiusKm","careType","internalRole","createdAt","updatedAt")
         VALUES ($1,$2,$3,'1 Main St','Testville','ZZ','90001',33,-112,100,$4,$5,NOW(),NOW())`,
        id, over.name || 'Provider ' + id, id + '@example.test', over.careType || 'hospice',
        over.internalRole || null);
      const ident = (pid, ccn) => prisma.$executeRawUnsafe(
        `INSERT INTO "ProviderExternalIdentity" (id,"providerId",source,"externalId","identifierType",
           "verifiedAt","verifiedBy","createdAt","updatedAt")
         VALUES ($1,$2,$3,$4,'ccn',NOW(),'test-suite',NOW(),NOW())`, uuid(), pid, S, ccn);

      await fac('V70000', 'E2E OWN HOSPICE', ['76001', '76002', '76003', '76004']);
      await fac('V70001', 'E2E RIVAL HOSPICE', ['76001', '76002']);
      const internalFac = await fac('V70002', 'E2E INTERNAL-LINKED HOSPICE', ['76001']);
      await fac('V70003', 'E2E LONELY HOSPICE', ['79999']);
      await prov('e2e-own'); await ident('e2e-own', 'V70000');
      // A verified identity on an INTERNAL account — the live 121509 shape.
      await prov('e2e-internal', { name: 'internal reference', internalRole: 'cms_reference' });
      await ident('e2e-internal', 'V70002');
      await prov('e2e-solo'); await fac('V70010', 'E2E SOLO HOSPICE', ['78001']);
      await ident('e2e-solo', 'V70010');
      await prov('e2e-noident');
      for (const code of MREG.measures.map((m) => m.measureCode).slice(0, 6)) {
        await prisma.$executeRawUnsafe(
          `INSERT INTO "CmsFacilityMeasure" (id,"facilityId",source,"measureCode","releaseId",
             "valueNumeric","valueRaw",suppressed,"footnoteCodes","createdAt","updatedAt")
           VALUES ($1,$2,$3,$4,$5,50,'50',FALSE,'{}'::text[],NOW(),NOW())`,
          uuid(), internalFac, S, code, REL);
      }

      const h = makeHandler(
        async (uid) => ({ providerId: uid.replace(/^user:/, ''), provider: {} }),
        buildProviderCmsCompetitors, prisma);

      let res = makeRes();
      await h({ providerUserId: 'user:e2e-own' }, res);
      const body = res._json;
      ok(res._code === 200 && body.status === 'resolved',
         '4i. the endpoint resolves a real provider end to end', body.status);
      ok(body.competitors.length === 2, '4j. …returning the real competitor set',
         String(body.competitors.length));
      const blob = JSON.stringify(body);
      ok(!blob.includes('sharedZips'), '7. the endpoint response contains NO sharedZips[]');
      ok(!/"measureCode"|"valueNumeric"|"valueRaw"|"direction"|"suppressed"/.test(blob),
         '8. …and NO per-measure quality objects');
      for (const leak of ['email', 'stripe', 'billingMode', 'planTier', 'internalRole',
                          'serviceRadiusKm', 'serviceZipCodes', 'verifiedBy', 'e2e-internal',
                          'internal reference']) {
        ok(!blob.includes(leak), `9. …and no "${leak}"`);
      }
      const internalRow = body.competitors.find((c) => c.ccn === 'V70002');
      ok(internalRow && internalRow.bestHospicePartner === false,
         '10a. a hospice linked to the INTERNAL reference account carries no partner badge',
         internalRow && String(internalRow.bestHospicePartner));
      ok(body.competitors.every((c) => c.bestHospicePartner === false),
         '10b. …and no badge is invented for anyone else');
      ok(internalRow && internalRow.qualityAvailability
         && internalRow.qualityAvailability.publishedMeasureCount === 6,
         '10c. …while its CMS quality availability is still reported honestly',
         internalRow && JSON.stringify(internalRow.qualityAvailability));

      res = makeRes(); await h({ providerUserId: 'user:e2e-solo' }, res);
      ok(res._code === 200 && res._json.status === 'resolved' && res._json.competitors.length === 0,
         '6b. a zero-overlap provider gets a resolved 200 with an empty array');
      res = makeRes(); await h({ providerUserId: 'user:e2e-noident' }, res);
      ok(res._code === 200 && res._json.status === 'no_verified_identity'
         && res._json.competitors === null,
         '5b. an unmatched provider gets a structured status through the endpoint', res._json.status);

      // Round trips through the ROUTE, not just the service.
      const counted = new PrismaClient({ datasources: { db: { url: DB } },
        log: [{ emit: 'event', level: 'query' }] });
      let n = 0; counted.$on('query', () => { n += 1; });
      await counted.$queryRawUnsafe('SELECT 1');
      const settle = () => new Promise((r) => setTimeout(r, 60));
      const hc = makeHandler(async (uid) => ({ providerId: uid, provider: {} }),
        buildProviderCmsCompetitors, counted);
      n = 0; await hc({ providerUserId: 'e2e-own' }, makeRes()); await settle();
      const small = n;
      await prisma.$executeRawUnsafe(
        `INSERT INTO "CmsFacility" (id,source,ccn,name,address,city,state,zip,
           "firstSeenReleaseId","lastSeenReleaseId","createdAt","updatedAt")
         SELECT 'fac-bulk-'||i,$1,'W'||lpad(i::text,5,'0'),'E2E BULK '||i,'1 R','Testville','ZZ','90001',
                $2,$2,NOW(),NOW() FROM generate_series(1,200) i`, S, REL);
      await prisma.$executeRawUnsafe(
        `INSERT INTO "CmsFacilityServiceArea" (id,"facilityId",source,zip,
           "firstSeenReleaseId","lastSeenReleaseId","createdAt")
         SELECT 'sa-bulk-'||i,'fac-bulk-'||i,$1,'76001',$2,$2,NOW() FROM generate_series(1,200) i`, S, REL);
      n = 0; const bigRes = makeRes(); await hc({ providerUserId: 'e2e-own' }, bigRes); await settle();
      const big = n;
      await counted.$disconnect().catch(() => {});
      ok(bigRes._json.competitors.length === 202, '12a. the competitor population really did grow',
         String(bigRes._json.competitors.length));
      ok(small === big && big === 11,
         '12b. the endpoint stays at 11 bounded round trips — the route adds none',
         `${small} vs ${big}`);
      ok(!JSON.stringify(bigRes._json).includes('sharedZips'),
         '12c. …and a 202-competitor payload still carries no sharedZips[]');

      await prisma.$executeRawUnsafe(
        'TRUNCATE TABLE "CmsFacilityMeasure","CmsMeasureDefinition","CmsFacilityServiceArea","CmsFacility",'
        + '"CmsRelease","ProviderExternalIdentity","Provider" CASCADE');
    } finally {
      await prisma.$disconnect().catch(() => {});
    }
    finish();
  })().catch((e) => { console.error('\ne2e harness failed:', e.stack || e.message); process.exit(1); });
}

async function runHeadToHeadTests() {
  // ============================ H. HEAD TO HEAD ==============================
  section('H. Compare: lazy per competitor, cached per CCN');
  {
    const detail = (o) => Object.assign({
      status: 'resolved',
      provider: { source: 'cms_hospice', ccn: 'U70000', name: 'SYNTHETIC OWN HOSPICE' },
      competitor: { source: 'cms_hospice', ccn: 'U80000', name: 'SYNTHETIC RIVAL HOSPICE',
                    city: 'Northtown', state: 'ZZ', officeZip: '90222', bestHospicePartner: false },
      overlap: { sharedZipCount: 4, providerZipCount: 8, competitorZipCount: 6,
                 providerOverlapPct: 50, competitorOverlapPct: 66.67,
                 sharedZips: ['70001', '70002', '70003', '70004'] },
      comparisonSummary: { surfacedMeasureCount: 5, comparableMeasureCount: 3,
                           providerFavorableCount: 1, competitorFavorableCount: 1,
                           tiedCount: 1, unavailableCount: 2 },
      measures: [
        { measureCode: 'M_HI_UP', displayName: 'Synthetic upward measure', direction: 'higher_better',
          decimals: 1, unitLabel: '%', providerValue: 80, competitorValue: 60,
          providerPublished: true, competitorPublished: true, comparison: 'provider_higher',
          comparisonText: 'Your value is higher', lowerIsBetter: false, directionNote: null },
        { measureCode: 'M_HI_DN', displayName: 'Synthetic second measure', direction: 'higher_better',
          decimals: 1, unitLabel: '%', providerValue: 40, competitorValue: 70,
          providerPublished: true, competitorPublished: true, comparison: 'competitor_higher',
          comparisonText: "Competitor's value is higher", lowerIsBetter: false, directionNote: null },
        { measureCode: 'M_LO', displayName: 'Synthetic downward measure', direction: 'lower_better',
          decimals: 1, unitLabel: '%', providerValue: 10, competitorValue: 10,
          providerPublished: true, competitorPublished: true, comparison: 'same',
          comparisonText: 'Same value', lowerIsBetter: true,
          directionNote: 'Lower is better for this measure.' },
        { measureCode: 'M_SUP', displayName: 'Synthetic suppressed measure', direction: 'higher_better',
          decimals: 0, unitLabel: null, providerValue: null, competitorValue: 5,
          providerPublished: false, competitorPublished: true, comparison: 'unavailable',
          comparisonText: 'Not comparable', lowerIsBetter: false, directionNote: null },
        { measureCode: 'M_ZERO', displayName: 'Synthetic zero measure', direction: 'lower_better',
          decimals: 0, unitLabel: 'of 10', providerValue: 0, competitorValue: null,
          providerPublished: true, competitorPublished: false, comparison: 'unavailable',
          comparisonText: 'Not comparable', lowerIsBetter: true,
          directionNote: 'Lower is better for this measure.' }
      ],
      freshness: response().freshness,
      methodology: {
        comparisonDefinition: 'SYNTHETIC comparison definition from the fixture.',
        peerMedianDistinction: 'SYNTHETIC peer-median distinction from the fixture.',
        suppression: 'SYNTHETIC suppression statement from the fixture.',
        direction: 'SYNTHETIC direction statement from the fixture.',
        noProprietaryScore: 'SYNTHETIC no-score statement from the fixture.',
        consumerLeadSeparation: 'SYNTHETIC consumer lead separation from the fixture.'
      },
      detail: null
    }, o);

    const mount = async (impl) => {
      const c = { n: 0, paths: [] };
      const dom = makeDom();
      const R = loadRenderers(dom, async (p) => { c.n += 1; c.paths.push(p); return impl(p); });
      R.initMyMarketAccordion(); R.initQualityAccordion(); R.initCompetitorsAccordion();
      R.initCompetitors(CAP_ON);
      dom.els['comp-toggle'].click(); await tick(); await tick();
      return { c, dom, R };
    };
    const listOf3 = [
      competitor({ ccn: 'U80000', name: 'SYNTHETIC RIVAL HOSPICE' }),
      competitor({ ccn: 'U80001', name: 'SECOND RIVAL HOSPICE' }),
      competitor({ ccn: 'U80002', name: 'THIRD RIVAL HOSPICE' })
    ];
    const api = (p) => (p === '/api/provider-intelligence/competitors'
      ? response({ competitors: listOf3, landscape: landscape({ overlappingFacilityCount: 3 }) })
      : detail({ competitor: Object.assign({}, detail().competitor,
          { ccn: p.split('/').pop(), name: 'HOSPICE ' + p.split('/').pop() }) }));

    const m = await mount(api);
    ok(m.c.n === 1, 'H1. loading the landscape is still ONE request', String(m.c.n));
    ok(m.dom.els['comp-landscape-view'].hidden === false
       && m.dom.els['comp-h2h-view'].hidden === true,
       'H2. the landscape is the view on open, comparison hidden');

    // 31. one detail request per Compare click
    m.dom.fireCompare('U80000'); await tick(); await tick();
    ok(m.c.n === 2 && m.c.paths[1] === '/api/provider-intelligence/competitors/U80000',
       'H3. Compare issues exactly ONE request, for that CCN only', m.c.paths.join(' '));
    ok(m.dom.els['comp-h2h-view'].hidden === false
       && m.dom.els['comp-landscape-view'].hidden === true,
       'H4. …and the comparison replaces the landscape inside the module');
    ok(m.dom.els['comp-detail'].hidden === false,
       'H5. …without leaving the Competitors module');
    ok(m.dom.els['comp-h2h-body'].hidden === false && m.dom.els['comp-h2h-status'].hidden === true,
       'H6. …rendering the comparison, not a loading state');

    // 32. same CCN cached
    m.dom.els['comp-back'].click();
    ok(m.dom.els['comp-landscape-view'].hidden === false
       && m.dom.els['comp-h2h-view'].hidden === true,
       'H7. Back to competitors returns to the landscape');
    ok(m.c.n === 2, 'H8. …with NO refetch of the landscape', String(m.c.n));
    ok((m.dom.tbodies['comp-table'].innerHTML.match(/<tr>/g) || []).length === 3,
       'H9. …and the cached list is still rendered');
    m.dom.fireCompare('U80000'); await tick(); await tick();
    ok(m.c.n === 2, 'H10. re-comparing the SAME hospice makes no new request', String(m.c.n));
    ok(m.dom.els['comp-h2h-body'].hidden === false, 'H11. …and renders straight from cache');

    // 33. a second CCN costs exactly one more
    m.dom.fireCompare('U80001'); await tick(); await tick();
    ok(m.c.n === 3 && m.c.paths[2] === '/api/provider-intelligence/competitors/U80001',
       'H12. a DIFFERENT hospice costs exactly one new request', m.c.paths.join(' '));
    m.dom.fireCompare('U80000'); await tick(); await tick();
    m.dom.fireCompare('U80001'); await tick(); await tick();
    ok(m.c.n === 3, 'H13. …after which switching between the two is free', String(m.c.n));
    m.dom.fireCompare(null); await tick();
    ok(m.c.n === 3, 'H14. a click that is not on a Compare control does nothing');

    // 20 / 46. reopening the module returns to the landscape, nothing refetched
    m.dom.fireCompare('U80000'); await tick(); await tick();
    m.dom.els['comp-toggle'].click(); await tick();
    m.dom.els['comp-toggle'].click(); await tick();
    ok(m.dom.els['comp-landscape-view'].hidden === false
       && m.dom.els['comp-h2h-view'].hidden === true,
       'H15. collapsing and reopening returns to the landscape, not mid-comparison');
    ok(m.c.n === 3, 'H16. …refetching neither the landscape nor any comparison', String(m.c.n));
    m.dom.fireCompare('U80000'); await tick(); await tick();
    ok(m.c.n === 3, 'H17. …and the comparison cache survived the collapse', String(m.c.n));

    // 34 / 35. transport failure is retryable and never cached
    let boom = 2;
    const f = await mount((p) => {
      if (p === '/api/provider-intelligence/competitors') {
        return Promise.resolve(response({ competitors: listOf3 }));
      }
      if (boom-- > 0) return Promise.reject(new Error('synthetic detail failure'));
      return Promise.resolve(detail());
    });
    f.dom.fireCompare('U80000'); await tick(); await tick();
    ok(f.c.n === 2 && f.dom.els['comp-h2h-body'].hidden === true,
       'H18. a failed comparison renders no partial report', String(f.c.n));
    ok(f.dom.els['comp-h2h-status']._classes.has('is-error')
       && /Go back and select Compare to try again/.test(f.dom.els['comp-h2h-status'].textContent),
       'H19. …showing a neutral, explicitly retryable error',
       f.dom.els['comp-h2h-status'].textContent);
    ok(!/synthetic detail failure/.test(f.dom.els['comp-h2h-status'].textContent),
       'H20. …that never leaks the transport error');
    f.dom.fireCompare('U80000'); await tick(); await tick();
    ok(f.c.n === 3, 'H21. a retry DOES re-request — a failure is never cached', String(f.c.n));
    f.dom.fireCompare('U80000'); await tick(); await tick();
    ok(f.c.n === 4 && f.dom.els['comp-h2h-body'].hidden === false,
       'H22. …and the retry that succeeds renders the comparison', String(f.c.n));
    f.dom.fireCompare('U80000'); await tick(); await tick();
    ok(f.c.n === 4, 'H23. …after which it is cached like any other success', String(f.c.n));

    // a structured unavailable response IS cached
    const u = await mount((p) => (p === '/api/provider-intelligence/competitors'
      ? Promise.resolve(response({ competitors: listOf3 }))
      : Promise.resolve({ status: 'competitor_not_in_market', provider: null, competitor: null,
          overlap: null, comparisonSummary: null, measures: null, freshness: null,
          methodology: null, detail: null })));
    u.dom.fireCompare('U80002'); await tick(); await tick();
    ok(u.c.n === 2 && u.dom.els['comp-h2h-body'].hidden === true,
       'H24. a structured unavailable status renders a reason, not a report');
    ok(/does not share a CMS-reported service ZIP code/.test(u.dom.els['comp-h2h-status'].textContent)
       && u.dom.els['comp-h2h-status'].textContent !== 'competitor_not_in_market',
       'H25. …in plain language, never the raw status code',
       u.dom.els['comp-h2h-status'].textContent);
    u.dom.fireCompare('U80002'); await tick(); await tick();
    u.dom.fireCompare('U80002'); await tick(); await tick();
    ok(u.c.n === 2, 'H26. …and IS cached — repeated attempts do not refetch', String(u.c.n));

    section('H. comparison hierarchy and measure table');
    const d = makeDom();
    const RD = loadRenderers(d, async () => null);
    RD.renderCompetitorDetail(detail());
    const head = d.els['comp-h2h-title'].innerHTML;
    ok(/SYNTHETIC OWN HOSPICE/.test(head) && /SYNTHETIC RIVAL HOSPICE/.test(head)
       && /class="comp-vs">vs</.test(head),
       'H27. the header reads "your hospice vs competitor"', head);
    ok(/Your CCN U70000/.test(d.els['comp-h2h-ccns'].innerHTML)
       && /Their CCN U80000/.test(d.els['comp-h2h-ccns'].innerHTML),
       'H28. …with BOTH CCNs shown clearly', d.els['comp-h2h-ccns'].innerHTML);
    ok(/Northtown, ZZ/.test(d.els['comp-h2h-ccns'].innerHTML)
       && /Office ZIP 90222/.test(d.els['comp-h2h-ccns'].innerHTML),
       'H29. …plus location and Office ZIP, still never a plain "ZIP"');
    ok(!/Best Hospice partner/.test(d.els['comp-h2h-ccns'].innerHTML),
       'H30. no partner badge when the API says false');
    RD.renderCompetitorDetail(detail({ competitor: Object.assign({}, detail().competitor,
      { bestHospicePartner: true }) }));
    ok(/Best Hospice partner/.test(d.els['comp-h2h-ccns'].innerHTML),
       'H31. …and exactly one when it says true');
    RD.renderCompetitorDetail(detail());

    const ov = d.els['comp-h2h-overlap'].innerHTML;
    ok(/Shared CMS service ZIP codes/.test(ov) && />4</.test(ov)
       && /50\.00%/.test(ov) && /66\.67%/.test(ov),
       'H32. overlap context shows shared ZIPs and both footprint shares', ov.slice(0, 100));
    ok(/not market share, patient volume or referral competition/
        .test(d.els['comp-h2h-overlap-note'].textContent),
       'H33. …explicitly labelled service-area overlap, not market share',
       d.els['comp-h2h-overlap-note'].textContent);

    const sum = d.els['comp-h2h-summary'].innerHTML;
    for (const [lbl, n] of [['Comparable measures', 3], ['Your values favorable on', 1],
                            ['Competitor values favorable on', 1], ['Same', 1], ['Unavailable', 2]]) {
      ok(new RegExp('<span class="n">' + n + '</span><span class="lbl">' + lbl).test(sum),
         `H34. summary: ${lbl} = ${n}`);
    }
    ok(!/strength|review|even|favorable">|is-good|is-bad/.test(sum),
       'H35. every summary count is styled identically — no scoreboard colouring', sum.slice(0, 90));
    ok(/does not combine them into an overall score, rank or grade/
        .test(d.els['comp-h2h-summary-note'].textContent),
       'H36. …and the note says the counts are not combined into a score');
    ok(/neither hospice is described as better overall/.test(d.els['comp-h2h-summary-note'].textContent),
       'H37. …nor is either hospice called better overall');

    const rows = d.tbodies['comp-h2h-table'].innerHTML;
    ok((rows.match(/<tr>/g) || []).length === 5,
       'H38. every surfaced measure gets a row, comparable or not',
       String((rows.match(/<tr>/g) || []).length));
    const order = (rows.match(/Synthetic [a-z]+ measure/g) || []);
    ok(order[0] === 'Synthetic upward measure' && order[4] === 'Synthetic zero measure',
       'H39. …in the API order, never re-sorted by who looks better', order.join(' | '));
    ok(/Your value is higher/.test(rows) && /Competitor&#39;s value is higher/.test(rows)
       && /Same value/.test(rows),
       'H40. comparison wording is descriptive of the numbers');
    ok((rows.match(/Not comparable/g) || []).length === 2,
       'H41. …and unavailable measures read "Not comparable"');
    ok((rows.match(/Not published/g) || []).length === 2,
       'H42. a value CMS did not publish reads "Not published"',
       String((rows.match(/Not published/g) || []).length));
    ok(!/>0<\/td>|>0%</.test(rows.replace(/>0 of 10</g, '')),
       'H43. …and is NEVER shown as zero');
    ok(/<td class="n">0 of 10<\/td>/.test(rows),
       'H44. while a genuine published zero IS shown, with its unit', 'M_ZERO row');
    ok(/80%/.test(rows) && /66\.67|60%/.test(rows),
       'H45. units are preserved on published values');
    ok((rows.match(/Lower is better for this measure\./g) || []).length === 2,
       'H46. the lower-is-better note appears on exactly the two such measures',
       String((rows.match(/Lower is better for this measure\./g) || []).length));
    // The brand name is stripped first: "Best Hospice" is who we are, not a claim
    // that one hospice is best. Matching it would pass while proving nothing.
    const spoken = (rows + sum + d.els['comp-h2h-summary-note'].textContent)
      .replace(/Best Hospice/g, 'BH');
    for (const bad of ['winner', 'loser', 'beats', 'best', 'worst', 'stronger', 'weaker',
                       'superior', 'inferior', 'overall better', 'wins', 'lost']) {
      ok(!new RegExp(bad, 'i').test(spoken), `H47. no "${bad}" language anywhere in the comparison`);
    }
    ok(!/class="q-chip|favorable|unfavorable/.test(rows),
       'H48. no coloured win/loss chips — the comparison column is plain text');

    const note = d.els['comp-h2h-note'].textContent;
    for (const needle of ['SYNTHETIC comparison definition', 'SYNTHETIC peer-median distinction',
                          'SYNTHETIC suppression statement', 'SYNTHETIC direction statement',
                          'SYNTHETIC no-score statement', 'SYNTHETIC consumer lead separation']) {
      ok(note.indexOf(needle) >= 0, `H49. methodology "${needle.slice(10, 34)}" comes from the API`);
    }
    RD.renderCompetitorDetail(detail({ methodology: null }));
    const fb = d.els['comp-h2h-note'].textContent;
    ok(/Missing values are never treated as zero/.test(fb)
       && /does not determine which providers receive Best Hospice consumer enquiries/.test(fb)
       && /does not calculate an overall competitor score, rank or grade/.test(fb),
       'H50. …and a missing methodology still yields the mandatory statements');

    section('H. head-to-head under the release gate');
    let gcalls = 0;
    const g = makeDom();
    const RG = loadRenderers(g, async () => { gcalls += 1; return detail(); });
    RG.initCompetitorsAccordion();
    RG.initCompetitors(capsOff({ careType: 'hospice' }));
    g.fireCompare('U80000'); await tick(); await tick();
    ok(gcalls === 0, 'H51. gate OFF => Compare issues no detail request', String(gcalls));
    ok(g.els['comp-h2h-view'].hidden === true && g.els['comp-card'].hidden === true,
       'H52. …and there is no visible Compare control to reach at all');
    await RG.openCompetitorDetail('U80000'); await tick();
    ok(gcalls === 0, 'H53. …even called directly, the activation guard refuses', String(gcalls));

    section('H. accordion still governs the module');
    const a = await mount(api);
    a.dom.fireCompare('U80000'); await tick(); await tick();
    ok(a.dom.els['comp-h2h-view'].hidden === false, 'H54. a comparison is open');
    a.R.INTEL_ACCORDION.open('quality');
    ok(a.R.INTEL_ACCORDION.isOpen('quality') && !a.R.INTEL_ACCORDION.isOpen('competitors'),
       'H55. opening Quality still closes Competitors, comparison and all');
    a.R.INTEL_ACCORDION.open('myMarket');
    ok(!a.R.INTEL_ACCORDION.isOpen('competitors'), 'H56. …and so does opening My Market');
    a.dom.els['comp-toggle'].click(); await tick();
    ok(a.R.INTEL_ACCORDION.isOpen('competitors')
       && a.dom.els['comp-landscape-view'].hidden === false,
       'H57. reopening Competitors lands on the cached landscape');
    ok(a.c.n === 2, 'H58. …with nothing refetched', String(a.c.n));

    section('H. static: no forbidden language, no second gate');
    {
      const panel = PAGE.match(/data-section="Competitors"[\s\S]*?id="mi-competitors-grid"/)[0]
        .replace(/<!--[\s\S]*?-->/g, '');
      const script = SCRIPT_BODY.slice(SCRIPT_BODY.indexOf('  // ---- head-to-head detail'),
                                      SCRIPT_BODY.indexOf('  // ---- lazy load, cached'))
        .replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '');
      for (const bad of ['winner', 'loser', 'beats', 'stronger', 'weaker', 'superior', 'inferior',
                         'market share', 'patient volume', 'referral volume', 'revenue',
                         'score', 'rank', 'grade', 'percentile']) {
        ok(!new RegExp(bad, 'i').test(panel), `H59. no "${bad}" in the comparison markup`);
      }
      ok(!/\.sort\(/.test(script), 'H60. the comparison view never sorts the measures');
      ok(!/Math\.round|\/ *2|composite/.test(script),
         'H61. …and computes no metric of its own — every number comes from the API');
      ok(/data-compare-ccn/.test(script) && /closest\('\[data-compare-ccn\]'\)/.test(script),
         'H62. Compare uses ONE delegated listener keyed on the CCN');
      ok(/competitorsActivated/.test(script), 'H63. …behind the same activation guard');
      ok(/encodeURIComponent\(ccn\)/.test(script), 'H64. the CCN is encoded into the request path');
      ok(!/\d+(\.\d+)?%/.test(panel) && !/\b[A-Z]\d{5}\b/.test(panel),
         'H65. no example percentage or CCN in the static comparison markup');
      ok(/<caption class="sr-only">Your CMS-published measures/.test(PAGE)
         && /id="comp-h2h-status" role="status"/.test(PAGE),
         'H66. the comparison table is captioned and its status announced');
      ok(/<div class="q-table-wrap">\s*<table class="q-table" id="comp-h2h-table"/.test(PAGE),
         'H67. …and scrolls horizontally rather than overflowing on a phone');
    }
  }
}

function finish() {
  console.log(`\n${'='.repeat(60)}`);
  console.log(fail === 0 ? `PASSED — ${pass} assertions` : `FAILED — ${fail} of ${pass + fail} assertions failed`);
  process.exit(fail === 0 ? 0 : 1);
}
