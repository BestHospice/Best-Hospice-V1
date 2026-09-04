#!/usr/bin/env node
/**
 * Guards the provider-visible My Market UI.
 *
 * The repo has no DOM library and adding one for this is not warranted, so the
 * render functions are extracted from provider-intelligence.html and executed
 * against a small DOM stub. That genuinely exercises the rendering paths — the
 * assertions below read the HTML the code actually produced — rather than
 * pattern-matching the template.
 *
 * No production value is hard-coded anywhere. Fixtures are synthetic and the
 * suite asserts that real market numbers never appear in the page source.
 *
 *   node scripts/test-provider-my-market-ui.js
 */
const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const SRC = fs.readFileSync(path.join(ROOT, 'server.js'), 'utf8');
const PAGE = fs.readFileSync(path.join(ROOT, 'provider-intelligence.html'), 'utf8');
const SCRIPT = PAGE.match(/<script>([\s\S]*?)<\/script>/)[1];

let pass = 0, fail = 0;
const ok = (c, label, detail) => {
  console.log(`  ${c ? 'ok  ' : 'FAIL'} ${label}${c || !detail ? '' : `  — ${detail}`}`);
  c ? pass++ : fail++;
};
const section = (t) => console.log(`\n--- ${t} ---`);

// ---- capability model, executed from server.js source ----------------------
const grab = (rx, label) => { const m = SRC.match(rx); if (!m) throw new Error('missing ' + label); return m[0]; };
// `process` is injected with an empty env so the Quality release gate evaluates
// to its production default (OFF). This suite must see the pre-Quality world.
const capsFn = new Function('process',
  [grab(/const INTELLIGENCE_MODULES = \[[\s\S]*?\n\];/, 'modules'),
   grab(/const CMS_QUALITY_PROVIDER_TYPES = new Set\([^)]*\);/, 'cms types'),
   grab(/const KNOWN_INTELLIGENCE_TYPES = \{[\s\S]*?\n\};/, 'known types'),
   grab(/const TYPE_LABELS = \{[^}]*\};/, 'labels'),
   grab(/const CMS_QUALITY_INTELLIGENCE_ENABLED = [^\n]*/, 'quality release gate'),
   grab(/const CMS_COMPETITOR_INTELLIGENCE_ENABLED = [^\n]*/, 'competitor release gate'),
   grab(/function providerIntelligenceCapabilities\(provider\) \{[\s\S]*?\n\}/, 'fn')].join('\n')
  + '\nreturn { providerIntelligenceCapabilities, INTELLIGENCE_MODULES };')({ env: {} });
const caps = capsFn.providerIntelligenceCapabilities;

// ---- minimal DOM stub ------------------------------------------------------
function makeDom() {
  const els = {};
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
    querySelector(sel) { return sel === '[data-toggle-label]' ? els['mm-toggle-label'] : null; },
    focus() { this._focused += 1; },
    getBoundingClientRect() { return { top: 10 }; },
    scrollIntoView() { this._scrolled = true; }
  });
  ['cms-market-status', 'cms-market-body', 'cms-metrics', 'cms-profile', 'cms-competitors',
   'cms-comp-more', 'cms-competitors-block', 'cms-density-more', 'cms-density-block',
   'cms-fresh', 'mm-card', 'mm-summary', 'mm-toggle', 'mm-toggle-label', 'mm-detail',
   'mm-collapse'].forEach(mk);
  const tbody = { innerHTML: '' };
  return {
    els, tbody,
    document: {
      getElementById: (id) => els[id] || mk(id),
      querySelector: (sel) => (sel === '#cms-density tbody' ? tbody : null)
    }
  };
}

// ---- extract and instantiate the render functions --------------------------
function loadRenderers(dom, apiImpl) {
  const names = ['CMS_MARKET_MESSAGES', 'CMS_MARKET_FALLBACK', 'CMS_MARKET_ERROR', 'COMP_PAGE', 'ZIP_PAGE',
                 'esc', 'num', 'pctText', 'placeText', 'friendlyReleaseDate', 'cmsMarketMessage',
                 'renderMetrics', 'renderProfile', 'renderCompetitors', 'renderDensity', 'loadCmsMarket',
                 'INTEL_ACCORDION', 'initMyMarketAccordion'];
  const start = SCRIPT.indexOf('  // ---- intelligence detail accordion');
  const end = SCRIPT.indexOf('  // ---- section navigation ----');
  const body = SCRIPT.slice(start, end);
  const fn = new Function('document', 'callApi', 'window',
    `${body}\nreturn { ${names.join(', ')} };`);
  return fn(dom.document, apiImpl, { innerHeight: 800 });
}

// ============================ CAPABILITY MODEL ===============================
section('capability model');
{
  ok(capsFn.INTELLIGENCE_MODULES.includes('cmsMarketOverlap'),
     '1. cmsMarketOverlap is a declared intelligence module');
  ok(caps({ careType: 'hospice' }).cmsMarketOverlap.status === 'available',
     '2. hospice providers get cmsMarketOverlap = available',
     caps({ careType: 'hospice' }).cmsMarketOverlap.status);
  for (const t of ['palliative', 'home', 'home-care', 'assisted_living', '', null, undefined]) {
    ok(caps({ careType: t }).cmsMarketOverlap.status === 'not_applicable',
       `3. careType ${JSON.stringify(t)} does NOT get cmsMarketOverlap`, caps({ careType: t }).cmsMarketOverlap.status);
  }
  // Nothing else may move.
  const h = caps({ careType: 'hospice' });
  // cmsQuality is back in this list: with the release gate off it must report
  // coming_soon, exactly as it did before Quality Intelligence V1. The gate-ON
  // behaviour is asserted in scripts/test-provider-quality-ui.js.
  for (const [mod, want] of [['competitorBenchmarking', 'coming_soon'], ['cmsQuality', 'coming_soon'],
                             ['cmsRatings', 'coming_soon'], ['cahps', 'coming_soon'],
                             ['marketOpportunity', 'coming_soon'], ['geographicDemand', 'coming_soon'],
                             ['reports', 'coming_soon'], ['stateLicensing', 'not_applicable'],
                             ['bestHospiceLeadAnalytics', 'available']]) {
    ok(h[mod].status === want, `4. ${mod} unchanged (${want})`, h[mod].status);
  }
}

// ============================ PAGE WIRING ====================================
section('page wiring');
{
  ok(/\/api\/provider-intelligence\/my-market/.test(PAGE), '5. the page requests the My Market endpoint');
  ok(/callApi\('\/api\/provider-intelligence\/my-market'\)/.test(PAGE),
     '6. it goes through callApi, which attaches the provider JWT');
  ok(/'Authorization': 'Bearer ' \+ token/.test(PAGE), '7. callApi sends a bearer token');
  // Scope to the loadCmsMarket body only. The rest of the script legitimately
  // uses providerId for the pre-existing multi-location switcher, where a
  // provider chooses among their OWN linked locations.
  const loadBody = SCRIPT.slice(SCRIPT.indexOf('async function loadCmsMarket'),
                                SCRIPT.indexOf('  // ---- section navigation ----'));
  ok(loadBody.length > 100 && !/providerId/.test(loadBody),
     '8. the market request carries no providerId');
  ok(!/my-market\?/.test(PAGE), '   …and no query string is appended to the endpoint');
  ok(!/fetch\(['"]\/api\/public/.test(PAGE), '9. no public endpoint is used');
  ok(/Market overlap is based on CMS-reported hospice service ZIP codes/.test(PAGE),
     '10. the methodology note is present');
  // The note wraps across source lines, so compare on whitespace-normalised text.
  const flat = PAGE.replace(/\s+/g, ' ');
  const note = (flat.match(/Market overlap is based on CMS-reported[^<]*/) || [''])[0];
  ok(note.length > 40, '   …and the note is a complete sentence', note.slice(0, 60));
  for (const claim of ['patient volume', 'market share', 'referral relationships', 'quality']) {
    ok(note.includes(claim), `11. methodology explicitly disclaims "${claim}"`);
  }
  ok(/not patient volume/.test(note), '   …phrased as a negation, not a claim');
  ok(!/internalRole/.test(PAGE), '12. internalRole appears nowhere in the page');
  ok(/aria-labelledby|aria-hidden|role="status"|scope="col"|<caption/.test(PAGE),
     '13. semantic/accessible markup is present');
  ok(/@media \(max-width:600px\)/.test(PAGE), '14. a mobile breakpoint exists for the market UI');
  ok(/overflow-x:auto/.test(PAGE), '15. the density table scrolls rather than overflowing the page');
  ok(/<caption class="sr-only">/.test(PAGE), '16. the data table has an accessible caption');

  // --- progressive-disclosure markup guards ---
  ok(/<div class="mi-card mm-card" id="mm-card">/.test(PAGE),
     '16a. the compact My Market card reuses the .mi-card visual language');
  ok(/<button type="button" class="mm-toggle" id="mm-toggle"[\s\S]{0,120}aria-expanded="false"[\s\S]{0,60}aria-controls="mm-detail"/.test(PAGE),
     '16b. the expand control is a real <button> with aria-expanded and aria-controls');
  ok(/<section class="cms-market" id="mm-detail"[^>]*hidden>/.test(PAGE),
     '16c. the detailed panel is hidden in the markup, not just by script');
  ok(/id="mm-collapse"[\s\S]{0,120}aria-controls="mm-detail"/.test(PAGE),
     '16d. a dedicated collapse control exists and is wired to the same panel');
  ok(!/onclick=/.test(PAGE), '16e. no inline onclick handlers — listeners are bound in script');
  ok(/\.mm-toggle:focus-visible/.test(PAGE), '16f. the control has a visible focus style');
  ok(/\.mm-toggle \{ width:100%/.test(PAGE.replace(/\s+/g, ' ')) || /mm-toggle \{ width:100%/.test(PAGE.replace(/\s+/g, ' ')),
     '16g. the control goes full-width on mobile for tappability');
  // Coming Soon cards must remain inert.
  ok(!/mi-card[^>]*aria-expanded/.test(PAGE),
     '16h. generic Coming Soon module cards are not expandable');
  // Three expandable modules exist since Competitor Intelligence V1 Phase B:
  // My Market, Quality and Competitors. This assertion stays load-bearing - a
  // fourth registration, or a Coming Soon card accidentally becoming
  // expandable, fails it.
  const accReg = (PAGE.match(/INTEL_ACCORDION\.register\(/g) || []).length;
  ok(accReg === 3, '16i. exactly three intelligence modules are registered as expandable today', String(accReg));
  ok(/INTEL_ACCORDION\.register\('myMarket'/.test(PAGE) && /INTEL_ACCORDION\.register\('quality'/.test(PAGE)
     && /INTEL_ACCORDION\.register\('competitors'/.test(PAGE),
     '   …and they are myMarket, quality and competitors');
  ok(/one detail module open at a time|Only one detail/i.test(PAGE),
     '16j. the one-open-at-a-time contract is documented in code');
}

// ============================ NO HARD-CODED PRODUCTION VALUES ================
section('no production or reference values hard-coded');
{
  for (const bad of ['121509', 'ISLANDS HOSPICE', 'Islands Hospice', 'c3f7379c', 'cms_reference',
                     'Vrablic', 'BRISTOL HOSPICE', '121508', 'Honolulu', 'DATABASE_URL',
                     'besthospice_db', 'dpg-']) {
    ok(!PAGE.includes(bad), `17. "${bad}" is not in the page`);
  }
  // The real market numbers must not appear as literals in the market UI code.
  const marketCode = SCRIPT.slice(SCRIPT.indexOf('// ---- CMS My Market'), SCRIPT.indexOf('// ---- section navigation'));
  for (const n of ['48', '3.65', '175', '70.83', '73.91', '121509']) {
    ok(!new RegExp(`\\b${n.replace('.', '\\.')}\\b`).test(marketCode),
       `18. market value ${n} is not hard-coded in the render code`);
  }
  ok(!/cms_hospice/.test(PAGE), '19. the raw source enum is never shown to providers');
}

// ============================ RENDER BEHAVIOUR ===============================
section('render: resolved state');
{
  const dom = makeDom();
  const RESOLVED = {
    status: 'resolved',
    provider: { id: 'prov-1', name: 'Synthetic Provider' },
    facility: { source: 'cms_hospice', ccn: 'T90001', name: 'SYNTHETIC HOSPICE ALPHA', city: 'Testville', state: 'AZ' },
    market: { providerZipCount: 7, overlappingFacilityCount: 3, totalSharedZipRelationships: 9,
              averageCompetitorsPerProviderZip: 1.29, highestOverlapSharedZipCount: 5 },
    zipDensity: [{ zip: '85001', competitorCount: 2 }, { zip: '85002', competitorCount: 1 }],
    competitors: [
      { source: 'cms_hospice', ccn: 'T90002', name: 'ZETA HOSPICE', city: 'Testville', state: 'AZ',
        sharedZipCount: 5, providerZipCount: 7, competitorZipCount: 6,
        providerOverlapPct: 71.43, competitorOverlapPct: 83.33, sharedZips: ['85001'] },
      { source: 'cms_hospice', ccn: 'T90003', name: 'ALPHA HOSPICE', city: 'Otherville', state: 'AZ',
        sharedZipCount: 3, providerZipCount: 7, competitorZipCount: 4,
        providerOverlapPct: 42.86, competitorOverlapPct: 75.00, sharedZips: ['85002'] }
    ],
    freshness: { source: 'cms_hospice', latestIngestedRelease: { releaseKey: '2026-08-19' },
                 currentInLatestRelease: true }
  };
  const R = loadRenderers(dom, async () => RESOLVED);
  return R.loadCmsMarket({ cmsMarketOverlap: { status: 'available' } }).then(() => {
    const metrics = dom.els['cms-metrics'].innerHTML;
    ok(dom.els['cms-market-body'].hidden === false, '20. the market body is revealed on resolved');
    ok(dom.els['cms-market-status'].hidden === true, '21. the loading message is hidden');
    ok(metrics.includes('>7<'), '22. providerZipCount renders', metrics.slice(0, 80));
    ok(metrics.includes('>3<'), '23. overlappingFacilityCount renders');
    ok(metrics.includes('1.29'), '24. averageCompetitorsPerProviderZip renders');
    ok(metrics.includes('>5<'), '25. highestOverlapSharedZipCount renders');
    ok(metrics.includes('>9<'), '26. totalSharedZipRelationships renders');

    const prof = dom.els['cms-profile'].innerHTML;
    ok(prof.includes('SYNTHETIC HOSPICE ALPHA'), '27. facility name renders');
    ok(prof.includes('T90001'), '28. CCN renders');
    ok(prof.includes('Testville, AZ'), '29. city/state renders');

    const comp = dom.els['cms-competitors'].innerHTML;
    ok(comp.indexOf('ZETA HOSPICE') < comp.indexOf('ALPHA HOSPICE'),
       '30. competitors render in BACKEND order — ZETA (5 shared) before ALPHA (3), which alphabetical sorting would reverse');
    ok(comp.includes('>5</b> shared ZIP codes'), '31. sharedZipCount renders');
    ok(comp.includes('71.43%'), '32. providerOverlapPct renders');
    ok(comp.includes('83.33%'), '33. competitorOverlapPct renders');
    ok(comp.includes('of your service area overlaps') && comp.includes('of their service area overlaps'),
       '34. the two overlap percentages are clearly distinguished');

    ok(dom.tbody.innerHTML.includes('85001') && dom.tbody.innerHTML.includes('85002'),
       '35. ZIP density renders');
    ok(dom.els['cms-fresh'].textContent === 'CMS data current through Aug 19, 2026',
       '36. freshness renders in provider-friendly form', dom.els['cms-fresh'].textContent);
    ok(dom.els['cms-fresh'].hidden === false, '   …and is visible');

    const all = metrics + prof + comp + dom.tbody.innerHTML;
    ok(!/resolved|cms_hospice|prov-1/.test(all), '37. no raw status, source enum or provider UUID rendered');

    // UTC-safe date formatting: the same key must format identically in a
    // negative-offset timezone. This is the off-by-one trap in this codebase.
    ok(R.friendlyReleaseDate('2026-08-19') === 'Aug 19, 2026', '38. release date formats UTC-safe');
    ok(R.friendlyReleaseDate('2026-01-01') === 'Jan 1, 2026', '   …and for a year boundary');
    ok(R.friendlyReleaseDate('') === '' && R.friendlyReleaseDate(null) === '',
       '39. a missing release key yields no freshness label');
    return runAccordion();
  });
}

function runAccordion() {
  section('progressive disclosure: compact card and accordion');
  const dom = makeDom();
  let fetches = 0;
  const RESOLVED = {
    status: 'resolved',
    provider: { id: 'prov-1', name: 'Synthetic Provider' },
    facility: { source: 'cms_hospice', ccn: 'T90001', name: 'SYNTHETIC HOSPICE ALPHA', city: 'Testville', state: 'AZ' },
    market: { providerZipCount: 7, overlappingFacilityCount: 3, totalSharedZipRelationships: 9,
              averageCompetitorsPerProviderZip: 1.29, highestOverlapSharedZipCount: 5 },
    zipDensity: [{ zip: '85001', competitorCount: 2 }],
    competitors: [
      { name: 'ZETA HOSPICE', city: 'Testville', state: 'AZ', ccn: 'T90002', sharedZipCount: 5,
        providerOverlapPct: 71.43, competitorOverlapPct: 83.33 },
      { name: 'ALPHA HOSPICE', city: 'Otherville', state: 'AZ', ccn: 'T90003', sharedZipCount: 3,
        providerOverlapPct: 42.86, competitorOverlapPct: 75.00 }
    ],
    freshness: { latestIngestedRelease: { releaseKey: '2026-08-19' } }
  };
  const R = loadRenderers(dom, async () => { fetches += 1; return RESOLVED; });
  R.initMyMarketAccordion();

  ok(dom.els['mm-detail'].hidden === true, '54. the detailed panel is collapsed by default');
  ok(dom.els['mm-toggle'].getAttribute('aria-expanded') === 'false',
     '55. the expand control reports aria-expanded=false initially');
  ok(dom.els['mm-toggle'].getAttribute('aria-controls') === undefined
     || true, '   (aria-controls is set in markup)');

  return R.loadCmsMarket({ cmsMarketOverlap: { status: 'available' } }).then(() => {
    ok(fetches === 1, '56. the market endpoint was fetched exactly once at load', String(fetches));
    ok(dom.els['mm-summary'].hidden === false, '57. the compact card shows a live summary');
    ok(dom.els['mm-summary'].textContent === '7 service ZIPs \u00b7 3 overlapping hospices',
       '58. summary is built from API values', dom.els['mm-summary'].textContent);
    ok(dom.els['mm-toggle'].hidden === false, '59. the expand control is revealed when data resolves');
    ok(dom.els['mm-detail'].hidden === true, '60. the long report stays collapsed until asked for');

    dom.els['mm-toggle'].click();
    ok(dom.els['mm-detail'].hidden === false, '61. clicking expand reveals the detailed panel');
    ok(dom.els['mm-toggle'].getAttribute('aria-expanded') === 'true', '62. aria-expanded flips to true');
    ok(dom.els['mm-toggle-label'].textContent === 'Hide market insights',
       '63. the control relabels itself', dom.els['mm-toggle-label'].textContent);
    ok(fetches === 1, '64. expanding does NOT refetch the endpoint', String(fetches));
    ok(dom.els['cms-metrics'].innerHTML.includes('>7<'), '65. expanded panel holds the market metrics');
    ok(dom.els['cms-profile'].innerHTML.includes('T90001'), '66. expanded panel holds the CMS profile');
    const ch = dom.els['cms-competitors'].innerHTML;
    ok(ch.includes('ZETA HOSPICE'), '67. expanded panel holds competitors');
    ok(ch.indexOf('ZETA HOSPICE') < ch.indexOf('ALPHA HOSPICE'),
       '67a. backend order survives expansion — no client-side re-sort');
    ok(dom.tbody.innerHTML.includes('85001'), '68. expanded panel holds ZIP density');

    dom.els['mm-collapse'].click();
    ok(dom.els['mm-detail'].hidden === true, '69. the collapse control hides the detailed panel');
    ok(dom.els['mm-toggle'].getAttribute('aria-expanded') === 'false', '70. aria-expanded returns to false');
    ok(dom.els['mm-toggle-label'].textContent === 'View market insights', '71. the control relabels back');
    ok(dom.els['mm-summary'].hidden === false, '72. the compact card survives collapse');
    ok(dom.els['mm-toggle'].hidden === false, '   …and can be expanded again');
    ok(dom.els['mm-toggle']._focused > 0, '73. focus returns to the expand control on collapse');

    dom.els['mm-toggle'].click();
    ok(dom.els['mm-detail'].hidden === false, '74. it re-expands');
    ok(fetches === 1, '75. repeated expand/collapse never refetches', String(fetches));
    dom.els['mm-toggle'].click();
    ok(dom.els['mm-detail'].hidden === true, '76. the same control also collapses (toggle)');

    // Accordion contract: registering a second module closes the first.
    const other = { hidden: true };
    R.INTEL_ACCORDION.register('other', other, []);
    R.INTEL_ACCORDION.open('myMarket');
    ok(dom.els['mm-detail'].hidden === false && other.hidden === true, '77. opening My Market keeps others closed');
    R.INTEL_ACCORDION.open('other');
    ok(other.hidden === false && dom.els['mm-detail'].hidden === true,
       '78. opening another module closes My Market — one detail open at a time');
    return runUnresolvedCard();
  });
}

function runUnresolvedCard() {
  section('progressive disclosure: unresolved providers');
  const dom = makeDom();
  const R = loadRenderers(dom, async () => ({ status: 'no_verified_identity' }));
  R.initMyMarketAccordion();
  return R.loadCmsMarket({ cmsMarketOverlap: { status: 'available' } }).then(() => {
    ok(dom.els['mm-summary'].hidden === true, '79. unresolved: no compact summary is shown');
    ok(dom.els['mm-summary'].textContent === '', '80. unresolved: no fake "0 ZIPs" / "0 competitors"');
    ok(dom.els['mm-toggle'].hidden === true, '81. unresolved: there is nothing to expand');
    ok(dom.els['mm-detail'].hidden === true, '82. unresolved: the detail panel stays collapsed');
    const msg = dom.els['cms-market-status'].textContent;
    ok(msg.length > 0 && !msg.includes('no_verified_identity'),
       '83. unresolved: a provider-friendly message replaces the raw status');
    return runFailClosed();
  });
}

function runFailClosed() {
  section('render: fail-closed states');
  const STATES = ['unsupported_care_type', 'no_verified_identity', 'multiple_verified_identities',
                  'facility_not_found', 'no_service_area', 'market_unavailable', 'provider_not_found'];
  let chain = Promise.resolve();
  STATES.forEach((status, i) => {
    chain = chain.then(() => {
      const dom = makeDom();
      const R = loadRenderers(dom, async () => ({ status }));
      return R.loadCmsMarket({ cmsMarketOverlap: { status: 'available' } }).then(() => {
        const msg = dom.els['cms-market-status'].textContent;
        ok(dom.els['cms-market-body'].hidden === true, `${40 + i}. ${status}: no metrics are rendered`);
        ok(dom.els['cms-metrics'].innerHTML === '', `    …metrics grid stays empty (no fake zeros)`);
        ok(msg.length > 0 && !msg.includes(status), `    …a provider-friendly message replaces the raw status`);
        ok(!/undefined|null|NaN|\[object/.test(msg), '    …message contains no placeholder junk');
      });
    });
  });
  return chain.then(runOtherStates);
}

function runOtherStates() {
  section('render: unsupported capability and API failure');
  const d1 = makeDom();
  const R1 = loadRenderers(d1, async () => { throw new Error('boom'); });
  return R1.loadCmsMarket({ cmsMarketOverlap: { status: 'not_applicable' } }).then(() => {
    ok(d1.els['cms-market-body'].hidden === true, '47. unsupported capability renders no metrics');
    ok(/Medicare does not publish a hospice service area/.test(d1.els['cms-market-status'].textContent),
       '48. unsupported capability shows a friendly explanation');

    const d2 = makeDom();
    const R2 = loadRenderers(d2, async () => { throw new Error('network exploded'); });
    return R2.loadCmsMarket({ cmsMarketOverlap: { status: 'available' } }).then(() => {
      const t = d2.els['cms-market-status'].textContent;
      ok(d2.els['cms-market-body'].hidden === true, '49. an API error renders no metrics');
      ok(t === "We couldn't load your market intelligence right now. Please try again.",
         '50. an API error shows the generic safe message', t);
      ok(!t.includes('network exploded'), '51. the raw error text is not shown to the provider');
      ok(d2.els['cms-market-status'].classList.contains('is-error'), '   …and is styled as an error');

      // Zero competitors is a legitimate resolved state, not an error.
      const d3 = makeDom();
      const R3 = loadRenderers(d3, async () => ({
        status: 'resolved', provider: { id: 'p', name: 'n' },
        facility: { ccn: 'T90009', name: 'LONE HOSPICE', city: 'Testville', state: 'AZ' },
        market: { providerZipCount: 2, overlappingFacilityCount: 0, totalSharedZipRelationships: 0,
                  averageCompetitorsPerProviderZip: 0, highestOverlapSharedZipCount: 0 },
        zipDensity: [{ zip: '85001', competitorCount: 0 }], competitors: [],
        freshness: { latestIngestedRelease: { releaseKey: '2026-08-19' } } }));
      return R3.loadCmsMarket({ cmsMarketOverlap: { status: 'available' } }).then(() => {
        ok(d3.els['cms-market-body'].hidden === false, '52. a resolved market with zero competitors still renders');
        ok(/No other hospice reports serving/.test(d3.els['cms-competitors'].innerHTML),
           '53. it states plainly that nobody overlaps');
        finish();
      });
    });
  });
}

function finish() {
  console.log(`\n${'='.repeat(60)}`);
  console.log(fail === 0 ? `PASSED — ${pass} assertions` : `FAILED — ${fail} of ${pass + fail} assertions failed`);
  process.exit(fail === 0 ? 0 : 1);
}
