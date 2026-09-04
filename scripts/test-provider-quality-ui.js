#!/usr/bin/env node
/**
 * Guards the provider-visible Quality Intelligence UI.
 *
 * The repo has no DOM library, so the render functions are extracted from
 * provider-intelligence.html and executed against a small DOM stub. The
 * assertions read the HTML the code actually produced rather than
 * pattern-matching the template.
 *
 * No production value is hard-coded anywhere. Fixtures are synthetic, and the
 * suite asserts that the real production quality numbers never appear in the
 * page source.
 *
 *   node scripts/test-provider-quality-ui.js
 */
const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const SRC = fs.readFileSync(path.join(ROOT, 'server.js'), 'utf8');
const PAGE = fs.readFileSync(path.join(ROOT, 'provider-intelligence.html'), 'utf8');
const SCRIPT_BODY = PAGE.match(/<script>([\s\S]*?)<\/script>/)[1];
const { CAHPS_UNPUBLISHED_MESSAGE } = require(path.join(ROOT, 'cms-hospice-quality.js'));

let pass = 0, fail = 0;
const ok = (c, label, detail) => {
  console.log(`  ${c ? 'ok  ' : 'FAIL'} ${label}${c || !detail ? '' : `  — ${detail}`}`);
  c ? pass++ : fail++;
};
const section = (t) => console.log(`\n--- ${t} ---`);

// ---- capability model, executed from server.js source ----------------------
const grab = (rx, label) => { const m = SRC.match(rx); if (!m) throw new Error('missing ' + label); return m[0]; };
// The capability source INCLUDING the real release-gate expression. `process` is
// injected, so every gate test below evaluates the expression server.js actually
// ships rather than a convenient copy of it.
const CAPS_SRC = [grab(/const INTELLIGENCE_MODULES = \[[\s\S]*?\n\];/, 'modules'),
   grab(/const CMS_QUALITY_PROVIDER_TYPES = new Set\([^)]*\);/, 'cms types'),
   grab(/const KNOWN_INTELLIGENCE_TYPES = \{[\s\S]*?\n\};/, 'known types'),
   grab(/const TYPE_LABELS = \{[^}]*\};/, 'labels'),
   grab(/const CMS_QUALITY_INTELLIGENCE_ENABLED = [^\n]*/, 'quality release gate'),
   grab(/const CMS_COMPETITOR_INTELLIGENCE_ENABLED = [^\n]*/, 'competitor release gate'),
   grab(/function providerIntelligenceCapabilities\(provider\) \{[\s\S]*?\n\}/, 'fn')].join('\n');
const buildCaps = (env) => new Function('process',
  CAPS_SRC + '\nreturn { providerIntelligenceCapabilities, INTELLIGENCE_MODULES };')({ env: env || {} });
// `env: {}` is the production default: the variable is simply not set.
const capsFn = buildCaps({});
const caps = capsFn.providerIntelligenceCapabilities;
// Gate ON, for the activated-behaviour assertions.
const capsOn = buildCaps({ CMS_QUALITY_INTELLIGENCE_ENABLED: 'true' }).providerIntelligenceCapabilities;

// ---- minimal DOM stub ------------------------------------------------------
const TOGGLE_LABEL = { 'q-toggle': 'q-toggle-label', 'mm-toggle': 'mm-toggle-label' };
function makeDom() {
  const els = {};
  const tbodies = {};
  const mk = (id) => (els[id] = {
    id, innerHTML: '', textContent: '', hidden: false, onclick: null,
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
    // handlers. The reveal control assigns .onclick deliberately, so that it
    // replaces rather than accumulates across re-renders.
    click() {
      if (typeof this.onclick === 'function') this.onclick();
      (this._listeners.click || []).forEach((f) => f());
    },
    querySelector(sel) {
      if (sel === 'tbody') return (tbodies[id] = tbodies[id] || { innerHTML: '' });
      if (sel === '[data-toggle-label]') return els[TOGGLE_LABEL[id]] || null;
      return null;
    },
    focus() { this._focused += 1; },
    getBoundingClientRect() { return { top: 10 }; },
    scrollIntoView() { this._scrolled = true; }
  });
  ['q-card', 'q-summary', 'q-status', 'q-toggle', 'q-toggle-label', 'q-detail', 'q-collapse',
   'q-body', 'q-primary', 'q-care-index', 'q-care-index-note', 'q-verdicts-block', 'q-verdict-list',
   'q-verdict-empty', 'q-verdict-note', 'q-coverage',
   'q-cms-table', 'q-bench-table', 'q-bench-hint', 'q-strengths',
   'q-strengths-empty', 'q-strengths-more', 'q-strengths-hint',
   'q-review', 'q-review-empty', 'q-review-more', 'q-review-hint',
   'q-cahps', 'q-cahps-block', 'q-fresh', 'q-note',
   'cms-market-status', 'cms-market-body', 'cms-metrics', 'cms-profile', 'cms-competitors',
   'cms-comp-more', 'cms-competitors-block', 'cms-density-more', 'cms-density-block', 'cms-fresh',
   'mm-card', 'mm-summary', 'mm-toggle', 'mm-toggle-label', 'mm-detail', 'mm-collapse'].forEach(mk);
  return {
    els, tbodies,
    document: {
      getElementById: (id) => els[id] || mk(id),
      querySelector: (sel) => (sel === '#cms-density tbody' ? (tbodies.density = tbodies.density || { innerHTML: '' }) : null)
    }
  };
}

function loadRenderers(dom, apiImpl) {
  const names = ['QUALITY_MESSAGES', 'QUALITY_FALLBACK', 'QUALITY_ERROR', 'verdictChip', 'fmtNum',
                 'fmtValue', 'fmtPeriod', 'peerSplit', 'comparisonSentence', 'qualityMessage', 'renderQualityMetrics',
                 'renderQualityCms', 'renderQualityBench', 'renderQualityCahps',
                 'peerPositionCount', 'prioritizeTakeaways', 'renderTakeaways', 'TAKEAWAY_DEFAULT',
                 'renderQualityNote', 'initQualityAccordion', 'loadCmsQuality',
                 'INTEL_ACCORDION', 'initMyMarketAccordion', 'esc', 'num', 'friendlyReleaseDate'];
  const start = SCRIPT_BODY.indexOf('  // ---- intelligence detail accordion');
  const end = SCRIPT_BODY.indexOf('  // ---- section navigation ----');
  if (start < 0 || end < 0) throw new Error('could not locate the renderer block');
  const body = SCRIPT_BODY.slice(start, end);
  const fn = new Function('document', 'callApi', 'window',
    `${body}\nreturn { ${names.join(', ')} };`);
  return fn(dom.document, apiImpl, { innerHeight: 800 });
}

// ---- synthetic fixture -----------------------------------------------------
const measure = (o) => Object.assign({
  measureCode: 'X', cmsMeasureName: 'Synthetic CMS Measure', shortLabel: 'Synthetic measure',
  dimension: 'careIndex', family: 'hci', valueKind: 'percent', direction: 'higher_better',
  decimals: 1, unitLabel: '%', scaleMin: 0, scaleMax: 100,
  period: { start: '2023-01-01', end: '2024-12-31' },
  provider: { value: null, valueRaw: null, published: false, suppressed: false,
              denominator: null, starRating: null, footnoteCodes: [] },
  peers: null, verdict: 'not_published', favorable: null, favorablePeerCount: null,
  differenceFromPeerMedian: null, comparisonAllowed: false
}, o);

const M_HIGH = measure({
  measureCode: 'Q_HIGH', shortLabel: 'Synthetic upward measure', direction: 'higher_better',
  dimension: 'staffing',
  provider: { value: 80, valueRaw: '80', published: true, suppressed: false, denominator: 1200,
              starRating: null, footnoteCodes: [] },
  peers: { comparableCount: 25, median: 30, min: 10, max: 95, lowerThanProvider: 19,
           higherThanProvider: 6, equalToProvider: 0 },
  verdict: 'above_peer_median', favorable: true, favorablePeerCount: 19,
  differenceFromPeerMedian: 50, comparisonAllowed: true
});
const M_LOW = measure({
  measureCode: 'Q_LOW', shortLabel: 'Synthetic downward measure', direction: 'lower_better',
  dimension: 'nursingContinuity',
  provider: { value: 20, valueRaw: '20', published: true, suppressed: false, denominator: 900,
              starRating: null, footnoteCodes: [] },
  peers: { comparableCount: 11, median: 40, min: 10, max: 60, lowerThanProvider: 1,
           higherThanProvider: 9, equalToProvider: 1 },
  verdict: 'below_peer_median', favorable: true, favorablePeerCount: 9,
  differenceFromPeerMedian: -20, comparisonAllowed: true
});
const M_BAD = measure({
  measureCode: 'Q_BAD', shortLabel: 'Synthetic weak measure', direction: 'lower_better',
  dimension: 'liveDischarge',
  provider: { value: 90, valueRaw: '90', published: true, suppressed: false, denominator: null,
              starRating: null, footnoteCodes: ['2', '5'] },
  peers: { comparableCount: 12, median: 30, min: 10, max: 95, lowerThanProvider: 11,
           higherThanProvider: 1, equalToProvider: 0 },
  verdict: 'above_peer_median', favorable: false, favorablePeerCount: 1,
  differenceFromPeerMedian: 60, comparisonAllowed: true
});
const M_FEW = measure({
  measureCode: 'Q_FEW', shortLabel: 'Synthetic thin measure', dimension: 'finalDays',
  provider: { value: 55, valueRaw: '55', published: true, suppressed: false, denominator: null,
              starRating: null, footnoteCodes: [] },
  peers: { comparableCount: 4, median: null, min: null, max: null, lowerThanProvider: null,
           higherThanProvider: null, equalToProvider: null },
  verdict: 'insufficient_peers'
});
const M_SUPP = measure({
  measureCode: 'Q_SUPP', shortLabel: 'Synthetic withheld measure', dimension: 'admissionAssessment',
  provider: { value: null, valueRaw: 'Not Available', published: false, suppressed: true,
              denominator: null, starRating: null, footnoteCodes: ['11'] },
  verdict: 'not_published'
});
const M_STAR = measure({
  measureCode: 'Q_STAR', shortLabel: 'Synthetic caregiver rating', dimension: 'familyExperience',
  valueKind: 'stars', unitLabel: 'of 5 stars', decimals: 0, scaleMin: 1, scaleMax: 5,
  period: { start: '2023-10-01', end: '2025-09-30' },
  verdict: 'not_published'
});

const RESOLVED = {
  status: 'resolved',
  provider: { id: 'prov-synth', name: 'Synthetic Provider' },
  facility: { source: 'cms_hospice', ccn: 'T90001', name: 'SYNTHETIC HOSPICE ALPHA',
              city: 'Testville', state: 'ZZ' },
  summary: { careIndex: { measureCode: 'Q_CI', value: 8, scaleMax: 10, unitLabel: 'of 10',
                          comparisonAllowed: true },
             surfacedMeasureCount: 6, publishedMeasureCount: 4, comparedMeasureCount: 3,
             favorableCount: 2, unfavorableCount: 1 },
  dimensions: [
    { key: 'staffing', label: 'Weekend and Near-Death Staffing', blurb: 'b', conditional: false,
      measureCodes: ['Q_HIGH'], anyPublished: true, message: null },
    { key: 'familyExperience', label: 'Family Caregiver Experience', blurb: 'b', conditional: true,
      measureCodes: ['Q_STAR'], anyPublished: false, message: CAHPS_UNPUBLISHED_MESSAGE }
  ],
  measures: [M_HIGH, M_LOW, M_BAD, M_FEW, M_SUPP, M_STAR],
  strengths: ['Q_HIGH', 'Q_LOW'],
  areasToReview: ['Q_BAD'],
  peerContext: { definition: 'd', providerZipCount: 19, overlappingFacilityCount: 25,
                 minimumComparablePeers: 5 },
  freshness: { qualityRelease: { releaseKey: '2026-08-19', capturedAt: null },
               latestIngestedRelease: { releaseKey: '2026-08-19' } },
  methodology: {
    peerDefinition: "Comparisons are calculated by Best Hospice from CMS-published measures across hospices sharing this provider's CMS-reported service ZIP codes.",
    minimumComparablePeers: 5,
    suppression: 's',
    notRepresenting: ['market share', 'patient volume', 'referral relationships', 'causation',
                      'a proprietary Best Hospice quality rating'],
    cmsPercentileExcluded: 'p'
  },
  detail: null
};
const clone = (o) => JSON.parse(JSON.stringify(o));

// ============================ CAPABILITY MODEL ===============================
section('release gate — default OFF, and OFF for anything unexpected');
{
  ok(/CMS_QUALITY_INTELLIGENCE_ENABLED/.test(SRC), 'G1. the gate exists in server.js');
  ok(/const CMS_QUALITY_INTELLIGENCE_ENABLED = process\.env\.CMS_QUALITY_INTELLIGENCE_ENABLED === 'true';/.test(SRC),
     "G2. it is a strict === 'true' comparison, matching LEAD_STATUS_NUDGE_ENABLED");
  ok(!/CMS_QUALITY_INTELLIGENCE_ENABLED\s*!==?\s*'false'/.test(SRC),
     'G3. it is NOT an opt-out — absence cannot enable the feature');
  ok(!/\|\|\s*true/.test(grab(/const CMS_QUALITY_INTELLIGENCE_ENABLED = [^\n]*/, 'gate')),
     'G4. there is no default-on fallback');

  // ABSENT
  ok(caps({ careType: 'hospice' }).cmsQuality.status === 'coming_soon',
     'G5. gate ABSENT -> a hospice sees Quality as coming_soon',
     caps({ careType: 'hospice' }).cmsQuality.status);
  ok(caps({ careType: 'hospice-care' }).cmsQuality.status === 'coming_soon',
     '    …and so does the hospice-care alias');

  // Byte-identical to the pre-feature reason string, which is what makes the
  // card read exactly as it did before Quality Intelligence V1 existed.
  ok(caps({ careType: 'hospice' }).cmsQuality.reason
     === 'Medicare publishes this for hospices. We are preparing per-provider matching.',
     'G6. gate OFF reuses the ORIGINAL cmsState copy verbatim',
     caps({ careType: 'hospice' }).cmsQuality.reason);
  const h0 = caps({ careType: 'hospice' });
  ok(h0.cmsQuality.status === h0.cmsRatings.status && h0.cmsQuality.reason === h0.cmsRatings.reason,
     'G7. gate OFF makes cmsQuality indistinguishable from the other unbuilt CMS cards');

  // EXPLICIT FALSE
  for (const v of ['false', 'FALSE', 'False', '0', 'off', 'no']) {
    ok(buildCaps({ CMS_QUALITY_INTELLIGENCE_ENABLED: v }).providerIntelligenceCapabilities(
      { careType: 'hospice' }).cmsQuality.status === 'coming_soon',
       `G8. gate = ${JSON.stringify(v)} -> coming_soon`);
  }

  // MALFORMED / UNEXPECTED — every one of these must fail CLOSED.
  for (const v of ['TRUE', 'True', 'tRuE', '1', 'on', 'ON', 'yes', 'y', 'enabled', 'true ', ' true',
                   'true\n', '"true"', "'true'", 'null', 'undefined', '', '  ', 'truthy', 'True.']) {
    const st = buildCaps({ CMS_QUALITY_INTELLIGENCE_ENABLED: v }).providerIntelligenceCapabilities(
      { careType: 'hospice' }).cmsQuality.status;
    ok(st === 'coming_soon', `G9. malformed gate ${JSON.stringify(v)} FAILS CLOSED -> coming_soon`, st);
  }

  // ON
  ok(capsOn({ careType: 'hospice' }).cmsQuality.status === 'available',
     'G10. gate = "true" + hospice -> available',
     capsOn({ careType: 'hospice' }).cmsQuality.status);
  ok(capsOn({ careType: 'hospice-care' }).cmsQuality.status === 'available',
     '    …and the hospice-care alias too');
  ok(/CMS-published hospice quality measures for your CCN/.test(capsOn({ careType: 'hospice' }).cmsQuality.reason),
     'G11. …with the Quality V1 reason copy');
  for (const t of ['palliative', 'home', 'home-care', 'assisted_living', '', null, undefined]) {
    ok(capsOn({ careType: t }).cmsQuality.status === 'not_applicable',
       `G12. gate ON + careType ${JSON.stringify(t)} -> the existing not_applicable behaviour`,
       capsOn({ careType: t }).cmsQuality.status);
  }

  // My Market must be untouched by the gate, in BOTH positions.
  for (const [c, label] of [[caps, 'OFF'], [capsOn, 'ON']]) {
    ok(c({ careType: 'hospice' }).cmsMarketOverlap.status === 'available',
       `G13. gate ${label}: My Market is still available for hospices`);
    ok(c({ careType: 'palliative' }).cmsMarketOverlap.status === 'not_applicable',
       `     …and still not_applicable for palliative`);
  }
  ok(JSON.stringify(caps({ careType: 'hospice' }).cmsMarketOverlap)
     === JSON.stringify(capsOn({ careType: 'hospice' }).cmsMarketOverlap),
     'G14. the gate changes NOTHING about the My Market capability');

  // And nothing else moves in either position.
  for (const [c, label] of [[caps, 'OFF'], [capsOn, 'ON']]) {
    const h = c({ careType: 'hospice' });
    for (const [mod, want] of [['cmsMarketOverlap', 'available'], ['bestHospiceLeadAnalytics', 'available'],
                               ['cmsRatings', 'coming_soon'], ['cahps', 'coming_soon'],
                               ['competitorBenchmarking', 'coming_soon'], ['marketOpportunity', 'coming_soon'],
                               ['geographicDemand', 'coming_soon'], ['reports', 'coming_soon'],
                               ['stateLicensing', 'not_applicable']]) {
      ok(h[mod].status === want, `G15. gate ${label}: ${mod} unchanged (${want})`, h[mod].status);
    }
  }
  const offAll = caps({ careType: 'hospice' });
  const onAll = capsOn({ careType: 'hospice' });
  const differing = Object.keys(onAll).filter((k) => JSON.stringify(offAll[k]) !== JSON.stringify(onAll[k]));
  ok(differing.length === 1 && differing[0] === 'cmsQuality',
     'G16. cmsQuality is the ONLY capability the gate can change', differing.join(', '));

  ok(capsFn.INTELLIGENCE_MODULES.includes('cmsQuality'),
     'G17. cmsQuality is still a declared intelligence module in both positions');
  for (const st of Object.values(caps({ careType: 'hospice' })).map((v) => v.status)) {
    ok(['available', 'coming_soon', 'not_applicable'].includes(st), `G18. "${st}" is a valid capability state`);
  }
}

section('release gate — the endpoint refuses to serve while OFF');
{
  const route = SRC.match(/app\.get\('\/api\/provider-intelligence\/quality'[\s\S]*?\n\}\);/);
  ok(!!route, 'G19. the quality route exists');
  ok(route && /if \(!CMS_QUALITY_INTELLIGENCE_ENABLED\) return res\.status\(404\)/.test(route[0]),
     'G20. it returns 404 while the gate is OFF, not a structured quality status');
  // Comment-stripped: the handler's own comment NAMES no_quality_data to explain
  // why 404 was chosen over it, so an unscoped match would fail on the very
  // reasoning it is checking for.
  const routeCode = route ? route[0].replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '') : '';
  ok(!/no_quality_data/.test(routeCode),
     'G21. …so it can never EMIT the misleading "not published" state before activation');
  // Authentication must not be weakened: the gate check sits INSIDE the handler,
  // after requireProviderAuth has already run.
  ok(route && /requireProviderAuth/.test(route[0]), 'G22. authentication is still required');
  ok(route && route[0].indexOf('requireProviderAuth')
     < route[0].indexOf('CMS_QUALITY_INTELLIGENCE_ENABLED'),
     'G23. the gate is checked AFTER authentication — auth is not weakened');
  ok(route && route[0].indexOf('CMS_QUALITY_INTELLIGENCE_ENABLED')
     < route[0].indexOf('getProviderContext'),
     'G24. …and before any provider data is loaded');
  ok(route && !/req\.(params|query|body)/.test(route[0]),
     'G25. the gate introduced no request-controlled input');
  // The gate must not be reachable as a per-request override.
  ok(!/req\.[a-zA-Z.]*CMS_QUALITY|query\.gate|headers\['x-quality/i.test(SRC),
     'G26. the gate cannot be flipped per request by a caller');
  // Four CODE references and no more: the const declaration (which names both the
  // binding and the env var), the capability, and the endpoint. A fifth would
  // mean the gate had grown a second, untested consumer.
  const SRC_CODE = SRC.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '');
  const gateRefs = (SRC_CODE.match(/CMS_QUALITY_INTELLIGENCE_ENABLED/g) || []).length;
  ok(gateRefs === 4,
     'G27. the gate has exactly three code consumers: its definition, the capability, the endpoint',
     String(gateRefs));
  ok((SRC_CODE.match(/process\.env\.CMS_QUALITY_INTELLIGENCE_ENABLED/g) || []).length === 1,
     '   …and the environment variable is read in exactly ONE place');
}

// ============================ PAGE WIRING ====================================
section('page wiring');
{
  ok(/callApi\('\/api\/provider-intelligence\/quality'\)/.test(PAGE),
     '7. the page requests the quality endpoint through callApi, which attaches the provider JWT');
  const body = PAGE.slice(PAGE.indexOf('async function loadCmsQuality'),
                          PAGE.indexOf('  // ---- section navigation ----'));
  ok(!/providerId/.test(body),
     '8. loadCmsQuality passes NO providerId — the session decides whose data is shown');
  ok(!/\?\s*providerId|&providerId/.test(PAGE), '9. no providerId is ever put in a query string');
  const qBlock = PAGE.slice(PAGE.indexOf('  // ---- CMS Quality Intelligence'),
                            PAGE.indexOf('  // ---- section navigation ----'));
  // Scoped to the constructs that would actually surface one. The block DOES
  // mention percentiles - in the methodology note that discloses they are not
  // used - so an unscoped "does not contain" assertion would pass for the wrong
  // reason and would also fail on the required disclosure.
  ok(!/_PERCENTILE/.test(qBlock),
     '10. the UI never names a CMS _PERCENTILE measure code');
  ok(!/\.percentile|percentileRank|\bpercentile\s*[:=]/i.test(qBlock),
     '   …and never reads a percentile field off the payload');
  ok(/rank the raw measure value/.test(qBlock),
     '   …while the methodology note DOES disclose that CMS percentiles are unused');
  ok(/initQualityAccordion\(\);/.test(PAGE) && /loadCmsQuality\(data\.capabilities \|\| \{\}\);/.test(PAGE),
     '11. the module is initialised and loaded on page start');
  // Three since Competitor Intelligence V1 Phase B added the Competitors
  // module. Quality must remain exactly one of them and must not have gained a
  // second registration of its own.
  ok((PAGE.match(/INTEL_ACCORDION\.register\(/g) || []).length === 3,
     '12. exactly three modules register with the accordion',
     String((PAGE.match(/INTEL_ACCORDION\.register\(/g) || []).length));
  ok((PAGE.match(/INTEL_ACCORDION\.register\('quality'/g) || []).length === 1,
     '12b. …and Quality registers exactly once');

  // No real production value may be baked into the page.
  for (const v of ['121509', 'ISLANDS HOSPICE', 'ACCENTCARE', '031609', 'QUALITY HOSPICE CARE',
                   '3.65', '84.21', 'Bristol', 'Vrablic']) {
    ok(!PAGE.includes(v), `13. no production value "${v}" is hard-coded in the page`);
  }
}

section('markup: the seven expanded sections and the provenance labels');
{
  for (const [id, label] of [
    ['q-card', 'compact Quality card'], ['q-summary', 'live summary line'],
    ['q-toggle', 'View quality insights trigger'], ['q-detail', 'expanded report panel'],
    ['q-collapse', 'Hide quality insights trigger'],
    ['q-primary', '1a. quality snapshot — primary CMS metric'],
    ['q-care-index', '1b. …its Care Index value element'],
    ['q-verdicts-block', '1c. quality snapshot — Best Hospice comparison summary'],
    ['q-verdict-list', '1d. …its verdict tally'],
    ['q-coverage', '1e. quality snapshot — data coverage'],
    ['q-cms-block', '2. CMS-measured performance'], ['q-bench-block', '3. peer benchmarks'],
    ['q-strengths-block', '4. key relative strengths'], ['q-strengths-more', '4b. …its reveal-more control'],
    ['q-review-block', '5. areas to review'], ['q-review-more', '5b. …its reveal-more control'],
    ['q-cahps-block', '6. family caregiver experience'], ['q-note', '7. methodology and freshness']
  ]) ok(PAGE.includes(`id="${id}"`), `14. ${label} is present (#${id})`);

  ok(/aria-expanded="false" aria-controls="q-detail"/.test(PAGE),
     '15. the trigger declares its collapsed state and target for assistive tech');
  ok(/<section class="cms-market" id="q-detail"[^>]*hidden>/.test(PAGE),
     '16. the expanded report starts hidden');
  // Fail-closed markup: a script failure, or an inactive release gate, leaves the
  // ordinary Coming soon card rather than a half-built Quality panel.
  ok(/<div class="mi-card q-card" id="q-card" hidden>/.test(PAGE),
     '16b. the compact Quality card also starts hidden in the markup');
  ok(/>View quality insights</.test(PAGE), '17. the exact expand label is used');
  ok(/Hide quality insights/.test(PAGE), '18. the exact collapse label is used');
  ok((PAGE.match(/Reported by CMS/g) || []).length >= 2,
     '19. "Reported by CMS" labels the CMS-sourced sections');
  ok((PAGE.match(/Best Hospice comparison/g) || []).length >= 3,
     '20. "Best Hospice comparison" labels every derived section');
  ok(/q-prov cms/.test(PAGE) && /q-prov bh/.test(PAGE),
     '21. the two provenance labels are visually distinct classes');
  ok(!/Best Hospice quality (score|rating)/i.test(PAGE),
     '22. the page never claims a Best Hospice quality score or rating of its own');
  ok(/\.q-chip\.favorable/.test(PAGE) && /\.q-chip\.unfavorable/.test(PAGE),
     '23. the comparison chip is styled by FAVOURABILITY, not by numeric position');
  ok(!/\.q-chip\.above_peer_median|above_peer_median\s*\?/.test(PAGE),
     '24. no styling or wording is keyed off the positional verdict');
}

// ============================ RENDERED OUTPUT ================================
section('rendered output: real values, direction-aware language');
{
  const dom = makeDom();
  let fetches = 0;
  const R = loadRenderers(dom, async () => { fetches += 1; return clone(RESOLVED); });
  R.initQualityAccordion();

  ok(dom.els['q-detail'].hidden === true, '25. the report is collapsed before any interaction');
  ok(dom.els['q-toggle'].getAttribute('aria-expanded') === 'false', '26. aria-expanded starts false');
}

let R, dom;
(async () => {
  dom = makeDom();
  let fetches = 0;
  R = loadRenderers(dom, async () => { fetches += 1; return clone(RESOLVED); });
  R.initQualityAccordion();
  R.initMyMarketAccordion();
  await R.loadCmsQuality({ cmsQuality: { status: 'available' } });

  ok(fetches === 1, '27. exactly one request is made', String(fetches));
  ok(dom.els['q-body'].hidden === false, '28. the report body is populated');
  ok(dom.els['q-toggle'].hidden === false, '29. the expand trigger becomes available');
  ok(dom.els['q-detail'].hidden === true,
     '30. …but the report stays COLLAPSED until the provider asks for it');

  section('collapsed summary uses real CMS data');
  {
    const t = dom.els['q-summary'].textContent;
    ok(dom.els['q-summary'].hidden === false, '31. the summary line is shown');
    ok(/Care Index: 8 of 10/.test(t), '32. it states the real CMS Care Index', t);
    ok(/3 measures compared/.test(t), '33. it states the real compared-measure count', t);
    ok(!/%/.test(t), '34. it invents no percentage');
    ok(t === 'Care Index: 8 of 10 · 3 measures compared',
       '35. the exact agreed summary shape is produced', t);

    // With no CMS Care Index the summary must not fabricate one.
    const d2 = makeDom();
    const noCi = clone(RESOLVED); noCi.summary.careIndex = null;
    const R2 = loadRenderers(d2, async () => noCi);
    R2.initQualityAccordion();
    await R2.loadCmsQuality({ cmsQuality: { status: 'available' } });
    ok(!/Care Index/.test(d2.els['q-summary'].textContent),
       '36. an unpublished Care Index is omitted from the summary, not shown as 0');
    ok(/3 measures compared/.test(d2.els['q-summary'].textContent),
       '   …and the remaining real fact is still shown');
    ok(/Not published by CMS/.test(d2.els['q-care-index'].textContent),
       '37. the primary metric says "Not published by CMS" rather than showing a zero',
       d2.els['q-care-index'].textContent);
    ok(!/0 \/ 10/.test(d2.els['q-care-index'].textContent)
       && d2.els['q-care-index'].textContent.trim()[0] !== '0',
       '   …and never renders 0 or 0 / 10');
    ok(d2.els['q-care-index'].classList.contains('is-unpublished'),
       '   …and is styled as unpublished rather than as a headline number');
    ok(/does not calculate a replacement/.test(d2.els['q-care-index-note'].textContent),
       '   …and states that Best Hospice invents no replacement');
  }

  section('CMS-measured performance section');
  {
    const h = dom.tbodies['q-cms-table'].innerHTML;
    ok(/Synthetic upward measure/.test(h), '38. each measure is listed');
    ok(/Synthetic CMS Measure/.test(h), '39. CMS\'s own measure name is shown alongside our label');
    ok(/80%/.test(h), '40. the published value is rendered with its unit');
    ok(/Sample size 1,200/.test(h), '41. the CMS denominator is shown as a sample size');
    ok(/CMS footnote 11/.test(h), '42. CMS footnotes are surfaced');
    ok(/CMS footnote 2, 5/.test(h), '43. a multi-valued footnote is shown as both codes');
    ok(/Not published by CMS/.test(h), '44. a withheld measure says so');
    ok(!/>0</.test(h.replace(/[0-9]{4}/g, '')), '45. no measure row renders a bare 0');
    ok(/Jan 1, 2023 – Dec 31, 2024/.test(h), '46. the measurement period is shown in full');
    ok(/Oct 1, 2023 – Sep 30, 2025/.test(h),
       '47. a measure with a DIFFERENT period shows its own, not the release date');
  }

  section('peer benchmark section: transparent count and median language');
  {
    const h = dom.tbodies['q-bench-table'].innerHTML;
    ok(/Your result was higher than 19 of 25 comparable hospices\./.test(h),
       '48. a higher-is-better measure leads with "higher than X of N"');
    ok(/Your result was lower than 9 of 11 comparable hospices\./.test(h),
       '49. a LOWER-is-better measure leads with "lower than X of N" — direction-aware');
    ok(/Lower is better for this measure\./.test(h),
       '49b. …and says so explicitly for lower-is-better measures');
    ok(!/Higher is better for this measure/.test(h),
       '49c. …but that note is NOT added mechanically to higher-is-better measures');
    ok(/11 of 12 comparable hospices reported a lower value\./.test(h),
       '49d. when most peers do better, the sentence leads with THEIR count');
    ok(!/than 0 of|of 0 of/.test(h),
       '49e. no "than 0 of N" phrasing survives');
    ok(!/overlapping hospices with a published score/.test(h),
       '49f. the old awkward phrasing is gone');
    ok(/Stronger than the peer median/.test(h), '50. a favourable measure is called stronger');
    ok(/Weaker than the peer median/.test(h), '51. an unfavourable measure is called weaker');
    // The only permitted use of "better" is the direction note, which is qualified
    // ("for this measure"). A provider is never called better or worse than peers.
    const hNoDirNote = h.split('Lower is better for this measure.').join('');
    ok(!/better|worse/i.test(hNoDirNote),
       '52. "better"/"worse" appear ONLY in the qualified direction note');
    ok(/Not enough comparable hospices/.test(h),
       '53. a measure below the peer threshold says so instead of comparing');
    ok(/Not published by CMS/.test(h), '54. an unpublished measure says so');

    // The thin measure must show its own value but no comparison.
    const row = h.split(/<tr[^>]*>/).find((r) => /Synthetic thin measure/.test(r));
    ok(/55%/.test(row), '55. the thin measure still shows the provider\'s own CMS value');
    ok(!/higher than|lower than/.test(row), '56. …but makes no count claim');
    ok((row.match(/<td class="n">—<\/td>/g) || []).length >= 1,
       '57. …and shows a dash for the withheld median');
    ok(!/median[^<]*0/.test(row), '58. …and never a zero median');

    const hint = dom.els['q-bench-hint'].textContent;
    ok(/At least 5 are required before any comparison is shown/.test(hint),
       '59. the 5-peer rule is stated to the provider', hint);
    ok(/shares at least one of your CMS service ZIP codes/.test(hint),
       '60. the peer definition matches My Market\'s');
  }

  section('strengths and areas to review');
  {
    const s = dom.els['q-strengths'].innerHTML;
    const r = dom.els['q-review'].innerHTML;
    ok(/Synthetic upward measure/.test(s) && /Synthetic downward measure/.test(s),
       '61. both favourable measures are listed as strengths');
    ok(/Synthetic downward measure/.test(s) && !/Synthetic downward measure/.test(r),
       '62. a lower-is-better measure BELOW the median is a strength, not an area to review');
    ok(/Synthetic weak measure/.test(r), '63. the unfavourable measure is an area to review');
    ok(!/Synthetic weak measure/.test(s), '   …and is not also a strength');
    ok(/Your result was lower than 9 of 11 comparable hospices\./.test(s),
       '64. each entry carries its own natural-language comparison sentence');
    ok(/Lower is better for this measure\./.test(s),
       '64b. …including the direction note where it applies');
    ok(!/overlapping hospices with a published score/.test(s + r),
       '64c. neither list repeats the old awkward phrasing');
    ok(dom.els['q-strengths-empty'].hidden === true, '65. the empty-state text is hidden when there is data');

    const d3 = makeDom();
    const none = clone(RESOLVED); none.strengths = []; none.areasToReview = [];
    const R3 = loadRenderers(d3, async () => none);
    R3.initQualityAccordion();
    await R3.loadCmsQuality({ cmsQuality: { status: 'available' } });
    ok(d3.els['q-strengths'].hidden === true && d3.els['q-strengths-empty'].hidden === false,
       '66. with no strengths the list is hidden and a plain sentence shown');
    ok(!/0/.test(d3.els['q-strengths-empty'].textContent), '   …and it contains no fabricated zero');
  }

  section('conditional family caregiver experience');
  {
    const h = dom.els['q-cahps'].innerHTML;
    ok(h.includes(CAHPS_UNPUBLISHED_MESSAGE),
       '67. an unpublished CAHPS result shows the exact agreed sentence');
    ok(h.includes('CMS has not published a family caregiver survey result for this hospice.'),
       '   …verbatim');
    ok(!/0|—/.test(h), '68. it shows no zero and no bare dash');
    ok(dom.els['q-cahps-block'].hidden === false, '69. the section is still rendered, not removed');

    const d4 = makeDom();
    const withCahps = clone(RESOLVED);
    withCahps.dimensions[1].anyPublished = true;
    withCahps.dimensions[1].message = null;
    const star = withCahps.measures.find((m) => m.measureCode === 'Q_STAR');
    star.provider = { value: 4, valueRaw: '4', published: true, suppressed: false,
                      denominator: null, starRating: 4, footnoteCodes: [] };
    star.peers = { comparableCount: 9, median: 3, min: 1, max: 5, lowerThanProvider: 6,
                   higherThanProvider: 2, equalToProvider: 1 };
    star.verdict = 'above_peer_median'; star.favorable = true; star.favorablePeerCount = 6;
    star.differenceFromPeerMedian = 1; star.comparisonAllowed = true;
    const R4 = loadRenderers(d4, async () => withCahps);
    R4.initQualityAccordion();
    await R4.loadCmsQuality({ cmsQuality: { status: 'available' } });
    const h4 = d4.els['q-cahps'].innerHTML;
    ok(/4 of 5 stars/.test(h4), '70. a published star rating is shown with its unit', h4.slice(0, 120));
    ok(/Your result was higher than 6 of 9 comparable hospices\./.test(h4),
       '71. …with its own natural-language comparison sentence');
    ok(/One reported the same value as yours\./.test(h4),
       '71b. …and the tied peer is stated rather than ignored');
    ok(!h4.includes(CAHPS_UNPUBLISHED_MESSAGE), '72. …and the not-published sentence is gone');
  }

  section('methodology');
  {
    const t = dom.els['q-note'].textContent;
    ok(/Comparisons are calculated by Best Hospice from CMS-published measures/.test(t),
       '73. the note states Best Hospice computes the comparison');
    ok(/CMS-reported service ZIP codes/.test(t), '74. …from CMS-reported service ZIP codes');
    for (const claim of ['market share', 'patient volume', 'referral relationships', 'causation',
                         'a proprietary Best Hospice quality rating']) {
      ok(t.includes(claim), `75. the note disclaims "${claim}"`);
    }
    ok(/never treated as zero/.test(t), '76. the note explains suppression handling');
    ok(/rank the raw measure value/.test(t), '77. the note explains why CMS percentiles are unused');
    ok(/CMS quality data current through Aug 19, 2026/.test(dom.els['q-fresh'].textContent),
       '78. freshness reports the quality release date', dom.els['q-fresh'].textContent);
  }

  section('accordion: only one intelligence module open at a time');
  {
    ok(R.INTEL_ACCORDION.isOpen('quality') === false, '79. quality starts closed');
    dom.els['q-toggle'].click();
    ok(R.INTEL_ACCORDION.isOpen('quality') === true, '80. the trigger opens it');
    ok(dom.els['q-detail'].hidden === false, '   …and the panel is revealed');
    ok(dom.els['q-toggle'].getAttribute('aria-expanded') === 'true', '81. aria-expanded becomes true');
    ok(dom.els['q-toggle-label'].textContent === 'Hide quality insights',
       '82. the trigger label flips to the collapse wording', dom.els['q-toggle-label'].textContent);

    R.INTEL_ACCORDION.open('myMarket');
    ok(R.INTEL_ACCORDION.isOpen('quality') === false,
       '83. opening My Market CLOSES Quality — only one module is expanded at a time');
    ok(dom.els['q-detail'].hidden === true, '   …and the quality panel is hidden again');
    ok(dom.els['q-toggle'].getAttribute('aria-expanded') === 'false', '84. its aria-expanded resets');
    ok(dom.els['q-toggle-label'].textContent === 'View quality insights', '85. and its label resets');

    R.INTEL_ACCORDION.open('quality');
    ok(R.INTEL_ACCORDION.isOpen('myMarket') === false,
       '86. and the reverse: opening Quality closes My Market');
    dom.els['q-collapse'].click();
    ok(R.INTEL_ACCORDION.isOpen('quality') === false, '87. the collapse button closes it');
    ok(dom.els['q-toggle']._focused > 0, '88. focus returns to the trigger, not into an empty region');
    dom.els['q-toggle'].click();
    dom.els['q-toggle'].click();
    ok(R.INTEL_ACCORDION.isOpen('quality') === false, '89. the trigger toggles both ways');
  }

  section('fail-closed rendering: no fake zeros, nothing to expand');
  {
    const STATUSES = ['unsupported_care_type', 'no_verified_identity', 'multiple_verified_identities',
      'facility_not_found', 'no_service_area', 'market_unavailable', 'provider_not_found',
      'no_quality_data'];
    for (const st of STATUSES) {
      const d = makeDom();
      const Rx = loadRenderers(d, async () => ({ status: st, measures: null, summary: null,
        dimensions: null, strengths: null, areasToReview: null }));
      Rx.initQualityAccordion();
      await Rx.loadCmsQuality({ cmsQuality: { status: 'available' } });
      const msg = d.els['q-status'].textContent;
      ok(!!R.QUALITY_MESSAGES[st], `90. ${st} has provider-facing copy`);
      ok(msg === R.QUALITY_MESSAGES[st], `    …and it is what the card shows`, msg);
      ok(msg !== st && !/_/.test(msg), '    …never the raw status code');
      ok(d.els['q-body'].hidden === true, '    …the report body stays hidden');
      ok(d.els['q-toggle'].hidden === true, '    …there is nothing to expand');
      ok(d.els['q-summary'].hidden === true && d.els['q-summary'].textContent === '',
         '    …and no summary numbers are shown');
      ok(!/\b0\b/.test(msg), '    …and the copy contains no fabricated zero');
    }

    const d = makeDom();
    const Rx = loadRenderers(d, async () => { throw new Error('network'); });
    Rx.initQualityAccordion();
    await Rx.loadCmsQuality({ cmsQuality: { status: 'available' } });
    ok(d.els['q-status'].textContent === R.QUALITY_ERROR, '91. a request failure shows the retry message');
    ok(d.els['q-status'].classList.contains('is-error'), '   …styled as an error');
    ok(d.els['q-body'].hidden === true, '   …with no report body');

    // The release gate, as the provider experiences it. cmsQuality = coming_soon
    // is exactly what the capability model returns while the gate is OFF.
    for (const [cap, label] of [
      [{ cmsQuality: { status: 'coming_soon' } }, 'gate OFF (coming_soon)'],
      [{ cmsQuality: { status: 'not_applicable' } }, 'unsupported care type'],
      [{}, 'capability absent entirely'],
      [null, 'no capabilities at all']
    ]) {
      const d2 = makeDom();
      let called = 0;
      const R2 = loadRenderers(d2, async () => { called += 1; return clone(RESOLVED); });
      R2.initQualityAccordion();
      await R2.loadCmsQuality(cap);
      ok(called === 0, `92. ${label}: NO request is made`, String(called));
      ok(d2.els['q-card'].hidden === true,
         `    …the compact Quality card is REMOVED, leaving the ordinary Coming soon card`);
      ok(d2.els['q-detail'].hidden === true, '    …the report is hidden');
      ok(d2.els['q-toggle'].hidden === true, '    …there is nothing to expand');
      ok(d2.els['q-status'].textContent === '' && d2.els['q-status'].hidden === true,
         '    …and NO status message is shown', JSON.stringify(d2.els['q-status'].textContent));
      // The specific misleading sentence this gate exists to prevent.
      ok(!/Medicare has not published/.test(d2.els['q-status'].textContent)
         && !/Medicare does not publish/.test(d2.els['q-status'].textContent),
         '    …in particular no "Medicare has not published" claim');
      ok(d2.els['q-summary'].textContent === '', '    …and no summary numbers');
    }

    // Contrast: an AVAILABLE capability does reveal the card.
    const d5 = makeDom();
    const R5 = loadRenderers(d5, async () => clone(RESOLVED));
    R5.initQualityAccordion();
    await R5.loadCmsQuality({ cmsQuality: { status: 'available' } });
    ok(d5.els['q-card'].hidden === false, '93. an available capability REVEALS the compact card');
    ok(d5.els['q-toggle'].hidden === false, '   …and offers the expand control');
  }

  section('value formatting');
  {
    ok(R.fmtValue({ unitLabel: '%' }, 80) === '80%', '94. a percentage renders with a trailing %');
    ok(R.fmtValue({ unitLabel: 'of 10' }, 8) === '8 of 10', '95. an index renders with its scale');
    ok(R.fmtValue({ unitLabel: 'of 5 stars' }, 4) === '4 of 5 stars', '96. a star rating renders its unit');
    ok(R.fmtValue({ unitLabel: '%' }, null) === '—', '97. a null value renders as a dash, never 0');
    ok(R.fmtValue({ unitLabel: '%' }, undefined) === '—', '   …and so does undefined');
    ok(R.fmtNum(95.8300000000001) === '95.83', '98. float noise is rounded away');
    ok(R.fmtNum(10) === '10', '99. an integer renders without a decimal point');
    ok(R.verdictChip({ verdict: 'below_peer_median', favorable: true }).cls === 'favorable',
       '100. the chip follows FAVOURABILITY even when the position is "below"');
    ok(R.verdictChip({ verdict: 'above_peer_median', favorable: false }).cls === 'unfavorable',
       '101. …and even when the position is "above"');
    ok(R.verdictChip({ verdict: 'at_peer_median', favorable: null }).cls === 'even',
       '102. a tie gets its own neutral chip');
    ok(R.verdictChip({ verdict: 'insufficient_peers' }).cls === 'none',
       '103. an uncomparable measure gets a neutral chip');
  }

  section('comparison language: the full direction and tie matrix');
  {
    // Built directly from the three counts the API returns, which partition
    // comparableCount exactly. Every case the copy has to survive is here.
    const cmp = (o) => R.comparisonSentence(Object.assign({
      shortLabel: 'Synthetic measure', direction: 'higher_better', comparisonAllowed: true,
      provider: { value: 50, published: true },
      peers: { comparableCount: 10, median: 50, lowerThanProvider: 5, higherThanProvider: 5, equalToProvider: 0 }
    }, o));
    const P = (n, lower, higher, equal, extra) => Object.assign(
      { peers: { comparableCount: n, median: 50, lowerThanProvider: lower,
                 higherThanProvider: higher, equalToProvider: equal } }, extra || {});

    // ---- higher_better ----
    ok(cmp(P(10, 7, 3, 0, { provider: { value: 80, published: true } }))
       === 'Your result was higher than 7 of 10 comparable hospices.',
       '104. higher_better, provider ABOVE the median');
    ok(cmp(P(10, 2, 8, 0, { provider: { value: 20, published: true } }))
       === '8 of 10 comparable hospices reported a higher value.',
       '105. higher_better, provider BELOW the median — leads with the peers ahead');
    ok(cmp(P(9, 3, 0, 6, { provider: { value: 50, published: true } }))
       === 'Your result was higher than 3 of 9 comparable hospices. 6 reported the same value as yours.',
       '106. higher_better, provider EQUAL to the median — ties are stated');

    // ---- lower_better: the inversion ----
    ok(cmp(P(9, 4, 5, 0, { direction: 'lower_better', provider: { value: 10, published: true } }))
       === 'Your result was lower than 5 of 9 comparable hospices. Lower is better for this measure.',
       '107. lower_better, provider BELOW the median (the good side)');
    ok(cmp(P(9, 8, 1, 0, { direction: 'lower_better', provider: { value: 90, published: true } }))
       === '8 of 9 comparable hospices reported a lower value. Lower is better for this measure.',
       '108. lower_better, provider ABOVE the median (the bad side)');
    ok(cmp(P(8, 2, 0, 6, { direction: 'lower_better', provider: { value: 50, published: true } }))
       === '2 of 8 comparable hospices reported a lower value. 6 reported the same value as yours. Lower is better for this measure.',
       '109. lower_better, provider EQUAL to the median — ties stated, direction noted',
       cmp(P(8, 2, 0, 6, { direction: 'lower_better', provider: { value: 50, published: true } })));

    // ---- zero peers beaten / all peers beaten ----
    ok(cmp(P(10, 0, 10, 0)) === 'All 10 comparable hospices reported a higher value.',
       '110. provider higher than ZERO peers, none tied -> the "All N" form is exact');
    ok(cmp(P(10, 10, 0, 0)) === 'Your result was higher than all 10 comparable hospices.',
       '111. provider higher than ALL peers');
    // On a lower-is-better measure the peers AHEAD are the ones with lower values,
    // so "the provider beat zero peers" is lowerThanProvider = N, higherThanProvider = 0.
    ok(cmp(P(9, 9, 0, 0, { direction: 'lower_better' }))
       === 'All 9 comparable hospices reported a lower value. Lower is better for this measure.',
       '112. lower_better, provider lower than ZERO peers');
    ok(cmp(P(9, 0, 9, 0, { direction: 'lower_better' }))
       === 'Your result was lower than all 9 comparable hospices. Lower is better for this measure.',
       '113. lower_better, provider lower than ALL peers');

    // ---- NO FALSE "ALL" WHEN TIES EXIST ----
    const tie1 = cmp(P(10, 0, 8, 2));
    ok(!/^All 10/.test(tie1),
       '114. with 2 tied peers the sentence does NOT claim "All 10"', tie1);
    ok(tie1 === '8 of 10 comparable hospices reported a higher value. 2 reported the same value as yours.',
       '115. …it reports 8 of 10 and names the 2 ties', tie1);
    const tie2 = cmp(P(9, 8, 0, 1));
    ok(!/all 9/i.test(tie2), '116. with 1 tied peer it does NOT claim "all 9"', tie2);
    ok(/One reported the same value as yours\./.test(tie2),
       '117. …a single tie is written as "One", not "1"', tie2);
    ok(cmp(P(7, 0, 0, 7)) === 'All 7 comparable hospices reported the same value as yours.',
       '118. every peer tied is its own exact statement');
    ok(cmp(P(10, 5, 5, 0)) === 'Your result was higher than 5 of 10 comparable hospices.',
       '119. an exact half-and-half split leads with the provider');

    // ---- the counts must partition comparableCount ----
    for (const [n, lo, hi, eq] of [[10, 7, 3, 0], [9, 3, 0, 6], [10, 0, 8, 2], [7, 0, 0, 7]]) {
      ok(lo + hi + eq === n, `120. fixture counts partition comparableCount (${lo}+${hi}+${eq}=${n})`);
    }

    // ---- suppressed / not published / below the threshold ----
    ok(R.comparisonSentence({ comparisonAllowed: false, direction: 'higher_better',
         provider: { value: null, published: false, suppressed: true }, peers: null }) === '',
       '121. a SUPPRESSED provider measure produces no comparison sentence');
    ok(R.comparisonSentence({ comparisonAllowed: false, direction: 'higher_better',
         provider: { value: 55, published: true },
         peers: { comparableCount: 4, median: null, lowerThanProvider: null,
                  higherThanProvider: null, equalToProvider: null } }) === '',
       '122. FEWER THAN 5 comparable peers produces no comparison sentence');
    ok(R.comparisonSentence(null) === '' && R.comparisonSentence({}) === '',
       '123. a missing measure produces no sentence rather than throwing');

    // ---- peerSplit orientation comes from the stored direction, never the numbers ----
    const hi = R.peerSplit({ direction: 'higher_better',
      peers: { comparableCount: 10, lowerThanProvider: 7, higherThanProvider: 3, equalToProvider: 0 } });
    ok(hi.behind === 7 && hi.ahead === 3 && hi.betterWord === 'higher',
       '124. higher_better: peers with LOWER values are the ones behind');
    const lo = R.peerSplit({ direction: 'lower_better',
      peers: { comparableCount: 10, lowerThanProvider: 7, higherThanProvider: 3, equalToProvider: 0 } });
    ok(lo.behind === 3 && lo.ahead === 7 && lo.betterWord === 'lower',
       '125. lower_better: the SAME counts invert — peers with HIGHER values are behind');
    ok(!/provider\.value|median/.test(R.peerSplit.toString()),
       '126. peerSplit never looks at the provider value or the median — direction only');

    // ---- CMS vs Best Hospice attribution is preserved ----
    ok(!/CMS (reports|published|says)/i.test(cmp(P(10, 7, 3, 0))),
       '127. the comparison sentence never attributes the comparison to CMS');
    ok(!/percentile|score of|rating of/i.test(cmp(P(10, 7, 3, 0))),
       '128. …and invents no percentile or score');
  }

  section('Task 2: snapshot hierarchy — primary CMS metric vs comparison summary');
  {
    // A fixture matching the live CCN 121509 shape: 10 compared measures split
    // 3 favourable / 6 unfavourable / 1 tied, Care Index 10 of 10.
    const build = (verdicts, careIndexValue) => {
      const ms = verdicts.map((fav, i) => measure({
        measureCode: 'Q_' + i, shortLabel: 'Synthetic measure ' + i,
        dimension: i === 0 ? 'careIndex' : 'staffing',
        provider: { value: 50, valueRaw: '50', published: true, suppressed: false,
                    denominator: null, starRating: null, footnoteCodes: [] },
        peers: { comparableCount: 12, median: 40, min: 10, max: 90,
                 lowerThanProvider: 8, higherThanProvider: 3, equalToProvider: 1 },
        verdict: fav === null ? 'at_peer_median' : (fav ? 'above_peer_median' : 'below_peer_median'),
        favorable: fav, favorablePeerCount: 8, differenceFromPeerMedian: 10,
        comparisonAllowed: true
      }));
      const d = clone(RESOLVED);
      d.measures = ms;
      d.strengths = ms.filter((m) => m.favorable === true).map((m) => m.measureCode);
      d.areasToReview = ms.filter((m) => m.favorable === false).map((m) => m.measureCode);
      d.summary.careIndex = careIndexValue === null ? null
        : { measureCode: 'Q_0', value: careIndexValue, scaleMax: 10, unitLabel: 'of 10', comparisonAllowed: true };
      d.summary.surfacedMeasureCount = 10;
      d.summary.publishedMeasureCount = 10;
      d.summary.comparedMeasureCount = ms.filter((m) => m.comparisonAllowed).length;
      d.peerContext.overlappingFacilityCount = 10;
      return d;
    };
    const LIVE = [true, true, true, false, false, false, false, false, false, null];

    const d = makeDom();
    const Rx = loadRenderers(d, async () => build(LIVE, 10));
    Rx.initQualityAccordion();
    await Rx.loadCmsQuality({ cmsQuality: { status: 'available' } });

    // ---- 1 & 2: the Care Index is primary and CMS-attributed ----
    ok(d.els['q-care-index'].textContent === '10 / 10',
       '129. the Care Index renders as its own primary value', d.els['q-care-index'].textContent);
    ok(!d.els['q-care-index'].classList.contains('is-unpublished'),
       '130. …styled as a published headline number');
    ok(/Published by Medicare for your CCN/.test(d.els['q-care-index-note'].textContent),
       '131. the Care Index is explicitly attributed to CMS/Medicare');
    ok(/not a Best Hospice rating/.test(d.els['q-care-index-note'].textContent),
       '132. …and explicitly disclaimed as NOT a Best Hospice rating');
    ok(/Reported by CMS/.test(PAGE.slice(PAGE.indexOf('id="q-primary"') - 400, PAGE.indexOf('id="q-care-index"'))),
       '133. the primary block carries the "Reported by CMS" provenance label');
    // The Care Index must NOT sit in the same element as the counts any more.
    const cov = d.els['q-coverage'].innerHTML;
    ok(!/Care Index/.test(cov),
       '134. the Care Index is NOT rendered among the measure-count metrics');
    ok(!/10 \/ 10/.test(cov), '   …and its "10 / 10" form does not appear in the coverage row');

    // ---- 3, 4, 5: the verdict tally ----
    const vl = d.els['q-verdict-list'].innerHTML;
    ok(/<span class="n">3<\/span><span class="lbl">Relative strengths<\/span>/.test(vl),
       '135. 3 relative strengths');
    ok(/<span class="n">6<\/span><span class="lbl">Areas to review<\/span>/.test(vl),
       '136. 6 areas to review');
    ok(/<span class="n">1<\/span><span class="lbl">At peer median<\/span>/.test(vl),
       '137. 1 at peer median');
    ok(/Across 10 measures with a peer comparison\./.test(d.els['q-verdict-note'].textContent),
       '138. 3 + 6 + 1 = 10, the compared-measure count', d.els['q-verdict-note'].textContent);
    ok(/Best Hospice comparison/.test(PAGE.slice(PAGE.indexOf('id="q-verdicts-block"') - 200,
        PAGE.indexOf('id="q-verdict-list"'))),
       '139. the tally is attributed to Best Hospice comparison, not CMS');
    ok(d.els['q-verdict-empty'].hidden === true, '140. the neutral state is hidden when comparisons exist');

    // measures without a valid comparison must not enter the tally
    const withUncomparable = build(LIVE, 10);
    withUncomparable.measures.push(measure({
      measureCode: 'Q_FEW', shortLabel: 'Thin measure', comparisonAllowed: false, favorable: null,
      verdict: 'insufficient_peers',
      provider: { value: 55, valueRaw: '55', published: true, suppressed: false,
                  denominator: null, starRating: null, footnoteCodes: [] },
      peers: { comparableCount: 4, median: null, min: null, max: null,
               lowerThanProvider: null, higherThanProvider: null, equalToProvider: null }
    }));
    withUncomparable.measures.push(measure({
      measureCode: 'Q_SUP', shortLabel: 'Withheld measure', comparisonAllowed: false, favorable: null,
      verdict: 'not_published',
      provider: { value: null, valueRaw: 'Not Available', published: false, suppressed: true,
                  denominator: null, starRating: null, footnoteCodes: ['11'] }
    }));
    const d3 = makeDom();
    const R3 = loadRenderers(d3, async () => withUncomparable);
    R3.initQualityAccordion();
    await R3.loadCmsQuality({ cmsQuality: { status: 'available' } });
    ok(/<span class="n">1<\/span><span class="lbl">At peer median<\/span>/.test(d3.els['q-verdict-list'].innerHTML),
       '141. an insufficient-peer measure and a suppressed measure do NOT inflate the tie count');
    ok(/Across 10 measures with a peer comparison\./.test(d3.els['q-verdict-note'].textContent),
       '142. …and the total stays at the 10 comparable measures',
       d3.els['q-verdict-note'].textContent);

    // singular labels
    const d4 = makeDom();
    const R4 = loadRenderers(d4, async () => build([true, false, null], 7));
    R4.initQualityAccordion();
    await R4.loadCmsQuality({ cmsQuality: { status: 'available' } });
    ok(/<span class="lbl">Relative strength<\/span>/.test(d4.els['q-verdict-list'].innerHTML),
       '143. a single strength is labelled in the singular');
    ok(/<span class="lbl">Area to review<\/span>/.test(d4.els['q-verdict-list'].innerHTML),
       '144. …and so is a single area to review');
    ok(/Across 3 measures with a peer comparison\./.test(d4.els['q-verdict-note'].textContent),
       '145. the total follows the fixture');

    // ---- 6: zero comparisons -> neutral state, never "0 · 0 · 0" ----
    const d5 = makeDom();
    const none = build([], 10);
    none.measures = [measure({ measureCode: 'Q_NONE', shortLabel: 'Thin', comparisonAllowed: false,
      verdict: 'insufficient_peers',
      provider: { value: 55, valueRaw: '55', published: true, suppressed: false,
                  denominator: null, starRating: null, footnoteCodes: [] },
      peers: { comparableCount: 3, median: null, min: null, max: null,
               lowerThanProvider: null, higherThanProvider: null, equalToProvider: null } })];
    none.strengths = []; none.areasToReview = []; none.summary.comparedMeasureCount = 0;
    const R5 = loadRenderers(d5, async () => none);
    R5.initQualityAccordion();
    await R5.loadCmsQuality({ cmsQuality: { status: 'available' } });
    ok(d5.els['q-verdict-empty'].hidden === false,
       '146. zero comparisons shows the neutral state');
    ok(d5.els['q-verdict-empty'].textContent === 'No peer comparisons available',
       '147. …with the exact agreed wording', d5.els['q-verdict-empty'].textContent);
    ok(d5.els['q-verdict-list'].hidden === true && d5.els['q-verdict-list'].innerHTML === '',
       '148. …and the tally is removed, not rendered as zeros');
    ok(!/0.*Relative strength|Relative strengths.*0/.test(d5.els['q-verdict-list'].innerHTML),
       '149. …so no misleading "0 strengths · 0 areas to review · 0 at peer median"');
    ok(/at least 5 overlapping hospices/.test(d5.els['q-verdict-note'].textContent),
       '150. …and the reason cites the existing minimum-comparable-peer rule',
       d5.els['q-verdict-note'].textContent);

    // ---- 7: missing Care Index never becomes zero ----
    const d6 = makeDom();
    const R6 = loadRenderers(d6, async () => build(LIVE, null));
    R6.initQualityAccordion();
    await R6.loadCmsQuality({ cmsQuality: { status: 'available' } });
    ok(d6.els['q-care-index'].textContent === 'Not published by CMS',
       '151. a missing Care Index says so', d6.els['q-care-index'].textContent);
    ok(!/\b0\b/.test(d6.els['q-care-index'].textContent),
       '152. …and never renders a zero');
    ok(d6.els['q-care-index'].classList.contains('is-unpublished'),
       '153. …and is de-emphasised rather than shown as a headline');
    ok(/Best Hospice does not calculate a replacement/.test(d6.els['q-care-index-note'].textContent),
       '154. …and states that no replacement is invented');
    ok(d6.els['q-verdict-list'].hidden === false,
       '155. the comparison summary still renders when only the Care Index is missing');

    // ---- 8: no proprietary score / rating / grade / ranking / percentile ----
    const snapshotText = [d.els['q-care-index'].textContent, d.els['q-care-index-note'].textContent,
      d.els['q-verdict-list'].innerHTML, d.els['q-verdict-note'].textContent,
      d.els['q-verdict-empty'].textContent, d.els['q-coverage'].innerHTML].join(' ');
    for (const bad of ['quality score', 'overall score', 'percentile', 'grade', 'ranking', 'ranked',
                                              'best hospice score', 'out of 100', 'we rate', 'our rating']) {
      ok(!new RegExp(bad, 'i').test(snapshotText), `156. the snapshot never says "${bad}"`);
    }
    ok((snapshotText.match(/rating/gi) || []).length === 1
       && /not a Best Hospice rating/.test(snapshotText),
       '157. the only use of "rating" is the disclaimer that this is NOT one');

    // ---- 9: the data-currency indicator survives ----
    ok(/CMS quality data current through Aug 19, 2026/.test(d.els['q-fresh'].textContent),
       '158. the CMS data-current-through date is still shown', d.els['q-fresh'].textContent);
    ok(d.els['q-fresh'].hidden === false, '159. …and is visible');

    // ---- C: coverage row labels are unambiguous ----
    ok(/CMS measures available/.test(cov), '160. coverage: "CMS measures available"');
    ok(/10 of 10/.test(cov), '   …rendered as 10 of 10');
    ok(/Measures compared/.test(cov), '161. coverage: "Measures compared"');
    ok(/Overlapping hospices/.test(cov), '162. coverage: "Overlapping hospices"');
    ok(!/Measures CMS published for you|Measures with a peer comparison/.test(cov),
       '163. the old ambiguous labels are gone');

    // zero overlapping hospices must not crash or read oddly
    const d7 = makeDom();
    const solo = build([], 10);
    solo.measures = []; solo.strengths = []; solo.areasToReview = [];
    solo.summary.comparedMeasureCount = 0; solo.summary.publishedMeasureCount = 0;
    solo.peerContext.overlappingFacilityCount = 0;
    const R7 = loadRenderers(d7, async () => solo);
    R7.initQualityAccordion();
    await R7.loadCmsQuality({ cmsQuality: { status: 'available' } });
    ok(/Overlapping hospices/.test(d7.els['q-coverage'].innerHTML)
       && /class="v">0</.test(d7.els['q-coverage'].innerHTML),
       '164. zero overlapping hospices renders as 0 in the coverage row, not a crash');
    ok(d7.els['q-verdict-empty'].hidden === false,
       '165. …and the comparison summary falls back to the neutral state');

    // ---- 11: responsive markup / CSS ----
    ok(/\.q-snapshot \{ display:grid;[\s\S]{0,200}minmax\(0,1fr\) minmax\(0,1fr\)/.test(PAGE),
       '166. the snapshot is a two-column grid using minmax(0,1fr) so long values cannot overflow');
    ok(/@media \(max-width:760px\) \{\s*\n\s*\.q-snapshot \{ grid-template-columns:minmax\(0,1fr\); \}/.test(PAGE),
       '167. …and stacks to one column on narrow screens');
    ok(/\.q-primary-value \{[^}]*font-size:clamp\(/.test(PAGE),
       '168. the headline value uses clamp() so it scales instead of overflowing');
    ok(/\.q-coverage \{ display:grid;[\s\S]{0,160}repeat\(auto-fit,minmax\(160px,1fr\)\)/.test(PAGE),
       '169. the coverage row reflows with auto-fit rather than a fixed column count');
    ok(/\.q-primary, \.q-verdicts-block \{[^}]*min-width:0/.test(PAGE),
       '170. grid children carry min-width:0, the usual cause of grid overflow');
    ok(/overflow-wrap:anywhere/.test(PAGE.slice(PAGE.indexOf('.q-primary-value'), PAGE.indexOf('.q-primary-note'))),
       '171. a long primary value wraps rather than pushing the layout wide');
    // the pre-existing mobile rules must still be present
    ok(/@media \(max-width:600px\) \{[\s\S]{0,400}\.cms-metrics/.test(PAGE),
       '172. the pre-existing 600px mobile block is untouched');
  }

  section('Task 3: executive takeaway prioritisation');
  {
    // A measure with explicit peer counts. `scaleMin`/`scaleMax` and
    // `differenceFromPeerMedian` are populated on purpose so the tests can prove
    // the ordering does NOT consult them.
    const M = (code, label, direction, value, median, n, lower, higher, equal, scale) => measure({
      measureCode: code, shortLabel: label, direction: direction,
      scaleMin: (scale || [0, 100])[0], scaleMax: (scale || [0, 100])[1],
      differenceFromPeerMedian: Math.round((value - median) * 100) / 100,
      unitLabel: (scale && scale[1] === 5) ? 'of 5 stars' : '%',
      provider: { value: value, valueRaw: String(value), published: true, suppressed: false,
                  denominator: null, starRating: null, footnoteCodes: [] },
      peers: { comparableCount: n, median: median, min: null, max: null,
               lowerThanProvider: lower, higherThanProvider: higher, equalToProvider: equal },
      favorable: value === median ? null : (direction === 'lower_better' ? value < median : value > median),
      verdict: value === median ? 'at_peer_median'
        : (value > median ? 'above_peer_median' : 'below_peer_median'),
      comparisonAllowed: true
    });
    const idx = (ms) => { const o = {}; ms.forEach((m, i) => { o[m.measureCode] = i; }); return o; };
    const map = (ms) => { const o = {}; ms.forEach((m) => { o[m.measureCode] = m; }); return o; };
    const order = (ms, side) => R.prioritizeTakeaways(ms.map((m) => m.measureCode), map(ms), side, idx(ms))
      .map((m) => m.measureCode);

    // ---- 1 & 3: strengths, higher_better, ordered by peers outperformed ----
    let ms = [
      M('A', 'A', 'higher_better', 60, 50, 10, 3, 7, 0),   // behind 3/10 = 0.30
      M('B', 'B', 'higher_better', 60, 50, 10, 9, 1, 0),   // behind 9/10 = 0.90
      M('C', 'C', 'higher_better', 60, 50, 10, 6, 4, 0)    // behind 6/10 = 0.60
    ];
    ok(JSON.stringify(order(ms, 'strength')) === JSON.stringify(['B', 'C', 'A']),
       '173. strengths ordered by the proportion of peers the provider outperformed',
       order(ms, 'strength').join(','));

    // ---- 2 & 4: areas to review, lower_better, ordered by peers that outperformed ----
    ms = [
      M('A', 'A', 'lower_better', 60, 50, 10, 2, 8, 0),    // ahead = lower = 2/10 = 0.20
      M('B', 'B', 'lower_better', 60, 50, 10, 8, 2, 0),    // ahead = lower = 8/10 = 0.80
      M('C', 'C', 'lower_better', 60, 50, 10, 5, 5, 0)     // ahead = lower = 5/10 = 0.50
    ];
    ok(JSON.stringify(order(ms, 'review')) === JSON.stringify(['B', 'C', 'A']),
       '174. areas to review ordered by the proportion of peers that outperformed the provider',
       order(ms, 'review').join(','));
    // the SAME counts must invert between directions
    const hi = [M('X', 'X', 'higher_better', 60, 50, 10, 8, 2, 0)];
    const lo = [M('X', 'X', 'lower_better', 40, 50, 10, 8, 2, 0)];
    ok(R.peerPositionCount(hi[0], 'strength') === 8 && R.peerPositionCount(lo[0], 'strength') === 2,
       '175. direction inverts which side counts as outperformed');
    ok(!/provider\.value|peers\.median|differenceFromPeerMedian/.test(R.peerPositionCount.toString()),
       '176. peerPositionCount never infers direction from the value or the median');

    // ---- 5: comparableCount normalisation ----
    ms = [
      M('P8OF10', 'P8OF10', 'higher_better', 60, 50, 10, 8, 2, 0),  // 8/10 = 0.800
      M('P7OF8', 'P7OF8', 'higher_better', 60, 50, 8, 7, 1, 0)      // 7/8  = 0.875
    ];
    ok(JSON.stringify(order(ms, 'strength')) === JSON.stringify(['P7OF8', 'P8OF10']),
       '177. 7 of 8 outranks 8 of 10 — the proportion decides, not the raw count',
       order(ms, 'strength').join(','));
    ms = [
      M('P7OF9', 'P7OF9', 'higher_better', 60, 50, 9, 7, 2, 0),     // 7/9 = 0.778
      M('P8OF10b', 'P8OF10b', 'higher_better', 60, 50, 10, 8, 2, 0) // 8/10 = 0.800
    ];
    ok(JSON.stringify(order(ms, 'strength')) === JSON.stringify(['P8OF10b', 'P7OF9']),
       '178. …and 8 of 10 outranks 7 of 9, where the proportions dictate that');

    // ---- 6: tie-break by directional count ----
    ms = [
      M('SMALL', 'SMALL', 'higher_better', 60, 50, 4, 2, 2, 0),     // 2/4 = 0.5, count 2
      M('BIG', 'BIG', 'higher_better', 60, 50, 12, 6, 6, 0)         // 6/12 = 0.5, count 6
    ];
    // (comparableCount 4 is below the threshold in production, but the API would
    //  not mark it comparisonAllowed; here both are comparable by construction so
    //  the tie-break itself can be tested in isolation.)
    ok(JSON.stringify(order(ms, 'strength')) === JSON.stringify(['BIG', 'SMALL']),
       '179. equal proportions are broken by the larger directional peer count',
       order(ms, 'strength').join(','));

    // ---- 7: stable existing measure order as the final tie-break ----
    ms = [
      M('H_012_02_OBSERVED', 'Gaps', 'lower_better', 53.8, 54.3, 9, 4, 5, 0),   // behind 5/9
      M('H_012_03_OBSERVED', 'Early', 'lower_better', 8.5, 8.8, 9, 4, 5, 0)     // behind 5/9
    ];
    ok(JSON.stringify(order(ms, 'strength'))
       === JSON.stringify(['H_012_02_OBSERVED', 'H_012_03_OBSERVED']),
       '180. identical proportion AND count falls back to the existing measure order');
    // reversing the incoming order reverses the result: the tie-break really is
    // the supplied order, not something derived from the numbers
    const rev = [ms[1], ms[0]];
    ok(JSON.stringify(order(rev, 'strength'))
       === JSON.stringify(['H_012_03_OBSERVED', 'H_012_02_OBSERVED']),
       '181. …and that order is the one supplied, not recomputed from values');

    // ---- 8 & 9: the raw numeric gap is NOT used, across unlike units ----
    // Star rating: 1 star off a 1-5 scale = 0.25 normalised gap, but only 7 of 8
    // peers ahead. Percentage: 10.5 points off 0-100 = 0.105 gap, but ALL 10
    // peers ahead. The old normalized-gap ordering put the star measure first.
    ms = [
      M('STAR', 'Family caregiver survey rating', 'higher_better', 3, 4, 8, 0, 7, 1, [1, 5]),
      M('PCT', 'Would definitely recommend', 'higher_better', 79, 89.5, 10, 0, 10, 0)
    ];
    ok(JSON.stringify(order(ms, 'review')) === JSON.stringify(['PCT', 'STAR']),
       '182. a 10-of-10 peer position outranks a larger star-scale gap',
       order(ms, 'review').join(','));
    ok(!/differenceFromPeerMedian|scaleMin|scaleMax|Math\.abs/.test(R.prioritizeTakeaways.toString()),
       '183. prioritizeTakeaways never reads the numeric gap or the measure scale');
    ok(!/differenceFromPeerMedian|scaleMin|scaleMax/.test(R.peerPositionCount.toString()),
       '184. …and neither does peerPositionCount');
    // an index gap and a percentage gap must not be weighed against each other
    ms = [
      M('IDX', 'Care Index', 'higher_better', 4, 9, 10, 1, 9, 0, [0, 10]),   // gap 5/10 = 0.50, 9/10 ahead
      M('PCT2', 'A percentage', 'higher_better', 10, 90, 10, 0, 10, 0)       // gap 80/100 = 0.80, 10/10 ahead
    ];
    ok(JSON.stringify(order(ms, 'review')) === JSON.stringify(['PCT2', 'IDX']),
       '185. index and percentage gaps are never compared as magnitudes');

    // ---- 17 & 18: uncomparable measures excluded; ties handled ----
    const withBad = [
      M('OK1', 'OK1', 'higher_better', 60, 50, 10, 9, 1, 0),
      Object.assign(M('FEW', 'FEW', 'higher_better', 60, 50, 4, 3, 1, 0), { comparisonAllowed: false }),
      Object.assign(M('SUP', 'SUP', 'higher_better', 0, 50, 10, 0, 10, 0),
        { comparisonAllowed: false, provider: { value: null, valueRaw: 'Not Available',
          published: false, suppressed: true, denominator: null, starRating: null, footnoteCodes: ['11'] } }),
      Object.assign(M('NOPEERS', 'NOPEERS', 'higher_better', 60, 50, 0, 0, 0, 0), {}),
      M('OK2', 'OK2', 'higher_better', 60, 50, 10, 4, 6, 0)
    ];
    const kept = order(withBad, 'strength');
    ok(JSON.stringify(kept) === JSON.stringify(['OK1', 'OK2']),
       '186. uncomparable, suppressed and zero-peer measures are excluded from takeaways', kept.join(','));
    const allTied = [M('TIED', 'TIED', 'higher_better', 50, 50, 7, 0, 0, 7)];
    ok(R.peerPositionCount(allTied[0], 'strength') === 0
       && R.peerPositionCount(allTied[0], 'review') === 0,
       '187. an all-tied measure has zero peers on either side');

    // ---- 10, 11, 12, 13: default cap and reveal-more ----
    const many = [
      M('R1', 'R1', 'higher_better', 40, 50, 10, 0, 10, 0),
      M('R2', 'R2', 'higher_better', 40, 50, 10, 1, 9, 0),
      M('R3', 'R3', 'higher_better', 40, 50, 10, 2, 8, 0),
      M('R4', 'R4', 'higher_better', 40, 50, 10, 3, 7, 0),
      M('R5', 'R5', 'higher_better', 40, 50, 10, 4, 6, 0),
      M('S1', 'S1', 'higher_better', 60, 50, 10, 9, 1, 0),
      M('S2', 'S2', 'higher_better', 60, 50, 10, 8, 2, 0),
      M('S3', 'S3', 'higher_better', 60, 50, 10, 7, 3, 0),
      M('S4', 'S4', 'higher_better', 60, 50, 10, 6, 4, 0)
    ];
    const dm = makeDom();
    const big = clone(RESOLVED);
    big.measures = many;
    big.strengths = many.filter((m) => m.favorable === true).map((m) => m.measureCode);
    big.areasToReview = many.filter((m) => m.favorable === false).map((m) => m.measureCode);
    big.summary.comparedMeasureCount = many.length;
    const Rm = loadRenderers(dm, async () => big);
    Rm.initQualityAccordion();
    await Rm.loadCmsQuality({ cmsQuality: { status: 'available' } });

    ok(R.TAKEAWAY_DEFAULT === 3, '188. the default cap is 3', String(R.TAKEAWAY_DEFAULT));
    ok((dm.els['q-strengths'].innerHTML.match(/<li>/g) || []).length === 3,
       '189. at most 3 strengths are shown by default');
    ok((dm.els['q-review'].innerHTML.match(/<li>/g) || []).length === 3,
       '190. at most 3 areas to review are shown by default');
    ok(/S1[\s\S]*S2[\s\S]*S3/.test(dm.els['q-strengths'].innerHTML)
       && !/S4/.test(dm.els['q-strengths'].innerHTML),
       '191. …and they are the highest-priority three');
    ok(/R1[\s\S]*R2[\s\S]*R3/.test(dm.els['q-review'].innerHTML)
       && !/R4|R5/.test(dm.els['q-review'].innerHTML),
       '192. …in both sections');
    ok(dm.els['q-strengths-more'].hidden === false
       && dm.els['q-strengths-more'].textContent === 'Show 1 more',
       '193. a reveal control appears when more qualify', dm.els['q-strengths-more'].textContent);
    ok(dm.els['q-review-more'].textContent === 'Show 2 more',
       '194. …counting exactly how many remain', dm.els['q-review-more'].textContent);
    dm.els['q-review-more'].click();
    ok((dm.els['q-review'].innerHTML.match(/<li>/g) || []).length === 5,
       '195. clicking it reveals the rest in place, with no reload');
    ok(dm.els['q-review-more'].hidden === true,
       '196. …and the control disappears once everything is shown');
    ok(/R4[\s\S]*R5/.test(dm.els['q-review'].innerHTML),
       '197. …including the lowest-priority entries');

    // <= 3 qualifying: no control at all
    ok(dom.els['q-strengths-more'].hidden === true,
       '198. no reveal control when 3 or fewer qualify');

    // ---- 14, 15, 16: neutral states ----
    const dn = makeDom();
    const noStrength = clone(RESOLVED);
    noStrength.strengths = [];
    const Rn = loadRenderers(dn, async () => noStrength);
    Rn.initQualityAccordion();
    await Rn.loadCmsQuality({ cmsQuality: { status: 'available' } });
    ok(dn.els['q-strengths'].hidden === true && dn.els['q-strengths-empty'].hidden === false,
       '199. no strengths shows the neutral state, not an empty list');
    ok(/No measure is above the overlapping-hospice median/.test(dn.els['q-strengths-empty'].textContent),
       '200. …with product language, and no fabricated zero',
       dn.els['q-strengths-empty'].textContent);
    ok(dn.els['q-strengths-more'].hidden === true, '201. …and no reveal control');
    ok(dn.els['q-strengths-hint'].hidden === true, '202. …and no attribution hint on an empty section');

    const dr = makeDom();
    const noReview = clone(RESOLVED);
    noReview.areasToReview = [];
    const Rr = loadRenderers(dr, async () => noReview);
    Rr.initQualityAccordion();
    await Rr.loadCmsQuality({ cmsQuality: { status: 'available' } });
    ok(dr.els['q-review'].hidden === true && dr.els['q-review-empty'].hidden === false,
       '203. no areas to review shows the neutral state');
    ok(/No measure falls below the overlapping-hospice median/.test(dr.els['q-review-empty'].textContent),
       '204. …with product language');

    // zero valid comparisons anywhere
    const dz = makeDom();
    const none = clone(RESOLVED);
    none.measures = [Object.assign(M('NONE', 'NONE', 'higher_better', 55, 50, 4, 2, 2, 0),
      { comparisonAllowed: false, verdict: 'insufficient_peers' })];
    none.strengths = []; none.areasToReview = []; none.summary.comparedMeasureCount = 0;
    const Rz = loadRenderers(dz, async () => none);
    Rz.initQualityAccordion();
    await Rz.loadCmsQuality({ cmsQuality: { status: 'available' } });
    ok(dz.els['q-strengths-empty'].textContent === 'No peer comparisons available'
       && dz.els['q-review-empty'].textContent === 'No peer comparisons available',
       '205. with no valid comparisons at all, both sections use the no-comparisons state',
       dz.els['q-strengths-empty'].textContent);

    // ---- 22: attribution ----
    const hint = dm.els['q-strengths-hint'].textContent;
    ok(/Values are CMS-published/.test(hint), '206. the section states values are CMS-published');
    ok(/peer median, the comparison and the order these appear in are calculated by Best Hospice/.test(hint),
       '207. …and that the median, comparison and ORDER are Best Hospice calculations', hint);
    ok(/Best Hospice comparison/.test(PAGE.slice(PAGE.indexOf('id="q-strengths-block"'),
        PAGE.indexOf('id="q-strengths"'))),
       '208. the strengths block carries the Best Hospice provenance chip');
    ok(/Best Hospice comparison/.test(PAGE.slice(PAGE.indexOf('id="q-review-block"'),
        PAGE.indexOf('id="q-review"'))),
       '209. …and so does the areas-to-review block');
    ok(!/CMS (identifies|found|flags|considers)/i.test(hint + dm.els['q-strengths'].innerHTML),
       '210. nothing implies CMS identifies strengths or areas to review');

    // ---- 21: no score / rank / percentile language, and no clinical causation ----
    const takeawayText = [dm.els['q-strengths'].innerHTML, dm.els['q-review'].innerHTML,
      dm.els['q-strengths-hint'].textContent, dm.els['q-review-hint'].textContent,
      dm.els['q-strengths-more'].textContent, dm.els['q-review-more'].textContent].join(' ');
    for (const bad of ['percentile', 'quality score', 'overall score', 'grade', 'rank', 'ranked',
                       'ranking', 'priority score', 'weighted', 'composite', 'out of 100']) {
      ok(!new RegExp(bad, 'i').test(takeawayText), `211. takeaways never say "${bad}"`);
    }
    for (const bad of ['improve', 'increase', 'you should', 'needs work', 'dissatisfied',
                       'because', 'caused', 'poor care', 'we recommend']) {
      ok(!new RegExp(bad, 'i').test(takeawayText), `212. takeaways make no causal or clinical claim ("${bad}")`);
    }

    // ---- item shape: measure, value vs median, evidence sentence ----
    const first = dm.els['q-review'].innerHTML.split('</li>')[0];
    ok(/class="q-measure">R1</.test(first), '213. each takeaway names the measure');
    ok(/class="k">Yours<\/span><span class="v">/.test(first), '214. …shows the provider value');
    ok(/class="k">Peer median<\/span><span class="v">/.test(first), '215. …and the peer median');
    ok(/class="q-sentence">All 10 comparable hospices reported a higher value\./.test(first),
       '216. …and reuses Task 1\'s tie-safe evidence sentence verbatim', first.slice(0, 200));
  }

  console.log(`\n${'='.repeat(60)}`);
  console.log(fail === 0 ? `PASSED — ${pass} assertions` : `FAILED — ${fail} of ${pass + fail} assertions failed`);
  process.exit(fail === 0 ? 0 : 1);
})().catch((e) => { console.error('\nharness failed:', e.message, '\n', e.stack); process.exit(1); });
