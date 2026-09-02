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
                 contains(c) { return els[id]._classes.has(c); } },
    setAttribute(k, v) { this._attrs[k] = v; },
    getAttribute(k) { return this._attrs[k]; },
    addEventListener(ev, fn) { (this._listeners[ev] = this._listeners[ev] || []).push(fn); },
    click() { (this._listeners.click || []).forEach((f) => f()); },
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
   'q-body', 'q-metrics', 'q-cms-table', 'q-bench-table', 'q-bench-hint', 'q-strengths',
   'q-strengths-empty', 'q-review', 'q-review-empty', 'q-cahps', 'q-cahps-block', 'q-fresh', 'q-note',
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
                 'fmtValue', 'fmtPeriod', 'countSentence', 'qualityMessage', 'renderQualityMetrics',
                 'renderQualityCms', 'renderQualityBench', 'renderQualityList', 'renderQualityCahps',
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
  ok((PAGE.match(/INTEL_ACCORDION\.register\(/g) || []).length === 2,
     '12. exactly two modules register with the accordion',
     String((PAGE.match(/INTEL_ACCORDION\.register\(/g) || []).length));

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
    ['q-collapse', 'Hide quality insights trigger'], ['q-metrics', '1. quality snapshot'],
    ['q-cms-block', '2. CMS-measured performance'], ['q-bench-block', '3. peer benchmarks'],
    ['q-strengths-block', '4. relative strengths'], ['q-review-block', '5. areas to review'],
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
    ok(/Not published/.test(d2.els['q-metrics'].innerHTML),
       '37. the snapshot card says "Not published" rather than showing a zero');
    ok(!/>0 \/ 10</.test(d2.els['q-metrics'].innerHTML), '   …and never renders 0 / 10');
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
    ok(/is higher than 19 of 25 overlapping hospices with a published score/.test(h),
       '48. a higher-is-better measure uses "higher than X of N"');
    ok(/is lower than 9 of 11 overlapping hospices with a published score/.test(h),
       '49. a LOWER-is-better measure uses "lower than X of N" — direction-aware wording');
    ok(/Stronger than the peer median/.test(h), '50. a favourable measure is called stronger');
    ok(/Weaker than the peer median/.test(h), '51. an unfavourable measure is called weaker');
    ok(!/better|worse/i.test(h), '52. the words "better"/"worse" are never used unqualified');
    ok(/Not enough comparable hospices/.test(h),
       '53. a measure below the peer threshold says so instead of comparing');
    ok(/Not published by CMS/.test(h), '54. an unpublished measure says so');

    // The thin measure must show its own value but no comparison.
    const row = h.split('<tr>').find((r) => /Synthetic thin measure/.test(r));
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
    ok(/is lower than 9 of 11/.test(s), '64. each entry carries its own count sentence');
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
    ok(/is higher than 6 of 9 overlapping hospices/.test(h4), '71. …with its own count sentence');
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

  console.log(`\n${'='.repeat(60)}`);
  console.log(fail === 0 ? `PASSED — ${pass} assertions` : `FAILED — ${fail} of ${pass + fail} assertions failed`);
  process.exit(fail === 0 ? 0 : 1);
})().catch((e) => { console.error('\nharness failed:', e.message, '\n', e.stack); process.exit(1); });
