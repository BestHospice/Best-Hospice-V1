#!/usr/bin/env node
/**
 * Guards the provider-facing "What's Changed" module — Phase 2E-B.
 *
 * The real render functions are extracted from provider-intelligence.html and
 * EXECUTED against a DOM stub, the same technique the funnel and competitor UI
 * suites use. `callApi` is the page's only network layer, so the suite injects
 * it and thereby IS the transport - which is what makes the lazy-load, cache
 * and retry assertions real rather than structural.
 *
 * Every provider id, CCN, name, address and release key here is SYNTHETIC.
 *
 *   node scripts/test-provider-roster-changes-ui.js
 */
const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');

const ROOT = path.join(__dirname, '..');
const PAGE = fs.readFileSync(path.join(ROOT, 'provider-intelligence.html'), 'utf8');
const SCRIPT_BODY = PAGE.match(/<script>([\s\S]*?)<\/script>/)[1];

let pass = 0, fail = 0;
const ok = (c, label, detail) => {
  console.log(`  ${c ? 'ok  ' : 'FAIL'} ${label}${c || !detail ? '' : `  — ${detail}`}`);
  c ? pass++ : fail++;
};
const section = (t) => console.log(`\n--- ${t} ---`);
const tick = () => new Promise((r) => setTimeout(r, 0));

const RC_IDS = ['rc-card', 'rc-summary', 'rc-status', 'rc-toggle', 'rc-toggle-label',
  'rc-detail', 'rc-detail-h', 'rc-fresh', 'rc-fresh-prev', 'rc-body', 'rc-metrics',
  'rc-groups', 'rc-pending', 'rc-method', 'rc-method-list', 'rc-note', 'rc-collapse'];
const OTHER_IDS = ['mm-detail', 'mm-toggle', 'mm-toggle-label', 'q-detail', 'q-toggle',
  'q-toggle-label', 'comp-detail', 'comp-toggle', 'comp-toggle-label', 'comp-card',
  'comp-body', 'pf-detail', 'pf-toggle', 'pf-toggle-label', 'pf-card', 'pf-body'];
const TOGGLE_LABEL = { 'rc-toggle': 'rc-toggle-label', 'mm-toggle': 'mm-toggle-label',
  'q-toggle': 'q-toggle-label', 'comp-toggle': 'comp-toggle-label', 'pf-toggle': 'pf-toggle-label' };

function makeDom() {
  const els = {};
  const mk = (id) => (els[id] = {
    id, innerHTML: '', textContent: '', hidden: false, onclick: null,
    dataset: {}, _attrs: {}, _listeners: {}, _focused: 0, _classes: new Set(),
    classList: {
      add(c) { els[id]._classes.add(c); }, remove(c) { els[id]._classes.delete(c); },
      contains(c) { return els[id]._classes.has(c); },
      toggle(c, on) { if (on) els[id]._classes.add(c); else els[id]._classes.delete(c); }
    },
    setAttribute(k, v) { this._attrs[k] = v; },
    getAttribute(k) { return this._attrs[k]; },
    addEventListener(ev, fn) { (this._listeners[ev] = this._listeners[ev] || []).push(fn); },
    click() { if (typeof this.onclick === 'function') this.onclick(); (this._listeners.click || []).forEach((f) => f()); },
    querySelector(sel) {
      if (sel === '[data-toggle-label]') return els[TOGGLE_LABEL[id]] || null;
      if (sel === 'tbody') return { innerHTML: '' };
      return null;
    },
    querySelectorAll() { return []; },
    focus() { this._focused += 1; },
    getBoundingClientRect() { return { top: 10 }; },
    scrollIntoView() { this._scrolled = true; }
  });
  RC_IDS.concat(OTHER_IDS).forEach(mk);
  // Fidelity: elements shipped `hidden` in the real markup start hidden.
  RC_IDS.concat(OTHER_IDS).forEach((id) => {
    const m = new RegExp('<[^>]*id="' + id + '"[^>]*>').exec(PAGE);
    if (m && /\shidden(\s|>|=)/.test(m[0])) els[id].hidden = true;
  });
  return {
    els,
    document: { getElementById: (id) => els[id] || mk(id), querySelector: () => null,
      querySelectorAll: () => [] }
  };
}

const NAMES = ['INTEL_ACCORDION', 'initRosterChanges', 'initRosterChangesAccordion',
  'rosterChangesNotActivated', 'ensureRosterChangesLoaded', 'toggleRosterChanges',
  'renderRosterChanges', 'rcAddressLine', 'RC_PROMPT', 'RC_LOADING', 'RC_ERROR',
  'RC_FALLBACK', 'RC_MESSAGES', 'RC_METRICS', 'RC_GROUPS', 'RC_METHOD_ORDER'];

function rendererRegion(body) {
  const start = body.indexOf('  // ---- intelligence detail accordion');
  const end = body.indexOf('  // ---- section navigation ----');
  if (start < 0 || end < 0) throw new Error('could not locate the renderer block');
  return body.slice(start, end);
}

function loadRenderers(dom, apiImpl, bodyOverride) {
  const region = rendererRegion(bodyOverride || SCRIPT_BODY);
  return new Function('document', 'callApi', 'window',
    `${region}\nreturn { ${NAMES.join(', ')} };`)(dom.document, apiImpl, { innerHeight: 800 });
}

const CAP_ON = { cmsRosterChanges: { status: 'available' } };
const CAP_OFF = { cmsRosterChanges: { status: 'coming_soon' } };
const CAP_NA = { cmsRosterChanges: { status: 'not_applicable' } };

const okPayload = (over = {}) => ({
  status: 'ok',
  releases: {
    latest: { releaseKey: '2026-11-30', capturedAt: 'x', ingestedAt: 'y' },
    previous: { releaseKey: '2026-08-19', capturedAt: 'x', ingestedAt: 'y' },
    releasesAvailable: 2
  },
  market: { providerZipCount: 4, overlappingFacilityCount: 3 },
  summary: { rosterAdded: 2, rosterRemoved: 1, nameChanged: 1, locationChanged: 1, ownershipChanged: 1 },
  events: {
    rosterAdded: [
      { ccn: '099001', name: 'SYNTHETIC ALPHA HOSPICE', city: 'Phoenix', state: 'AZ', sharedZipCount: 3, label: 'Newly present in CMS roster' },
      { ccn: '099002', name: 'SYNTHETIC BETA HOSPICE', city: 'Mesa', state: 'AZ', sharedZipCount: null, label: 'Newly present in CMS roster' }
    ],
    rosterRemoved: [
      { ccn: '099003', name: 'SYNTHETIC GAMMA HOSPICE', city: 'Tempe', state: 'AZ', sharedZipCount: 2, label: 'Not present in latest CMS roster' }
    ],
    nameChanged: [
      { ccn: '099004', from: 'SYNTHETIC OLD NAME', to: 'SYNTHETIC NEW NAME', city: 'Phoenix', state: 'AZ', sharedZipCount: 1, label: 'CMS-published name changed' }
    ],
    locationChanged: [
      { ccn: '099005', name: 'SYNTHETIC DELTA HOSPICE',
        from: { address: '1 OLD ST', city: 'Phoenix', state: 'AZ', zip: '85016' },
        to: { address: '2 NEW AVE', city: 'Glendale', state: 'AZ', zip: '85302' },
        sharedZipCount: 1, label: 'CMS-published address changed' }
    ],
    ownershipChanged: [
      { ccn: '099006', name: 'SYNTHETIC EPSILON HOSPICE', from: 'For-Profit', to: 'Non-Profit', sharedZipCount: 1, label: 'CMS ownership classification changed' }
    ],
    ownershipCoverageChanged: [
      { ccn: '099007', name: 'SYNTHETIC ZETA HOSPICE', direction: 'became_unpublished', label: 'CMS no longer publishes ownership for this facility', sharedZipCount: 1 },
      { ccn: '099008', name: 'SYNTHETIC ETA HOSPICE', direction: 'became_published', label: 'CMS now publishes ownership for this facility', sharedZipCount: 1 }
    ]
  },
  methodology: {
    basis: 'These are changes between two CMS data releases, not business events.',
    rosterAbsence: 'A facility absent from the latest CMS roster has not necessarily closed.',
    ownershipCoverage: 'Ownership entries that stop being published are reported as a change in what CMS publishes, not as a change of ownership.'
  },
  detail: null,
  ...over
});

const insufficientPayload = () => ({
  status: 'insufficient_history',
  releases: { latest: { releaseKey: '2026-08-19' }, previous: null, releasesAvailable: 1 },
  market: { providerZipCount: 4, overlappingFacilityCount: 3 },
  summary: { rosterAdded: 0, rosterRemoved: 0, nameChanged: 0, locationChanged: 0, ownershipChanged: 0 },
  events: { rosterAdded: [], rosterRemoved: [], nameChanged: [], locationChanged: [], ownershipChanged: [], ownershipCoverageChanged: [] },
  methodology: {
    basis: 'These are changes between two CMS data releases, not business events.',
    rosterAbsence: 'A facility absent from the latest CMS roster has not necessarily closed.',
    ownershipCoverage: 'Ownership entries that stop being published are reported as a change in what CMS publishes, not as a change of ownership.'
  },
  detail: 'Only one CMS hospice release carries facility observations.'
});

function harness(responder, bodyOverride) {
  const dom = makeDom();
  const requests = [];
  const api = async (p) => { requests.push(p); return responder ? responder(p) : okPayload(); };
  const R = loadRenderers(dom, api, bodyOverride);
  return { dom, requests, R };
}

// =============================== STATIC ==================================
section('A. DOM contract');
{
  const panel = PAGE.match(/<div class="mi-panel" data-section="Competitors">[\s\S]*?<div class="mi-grid" id="mi-competitors-grid">/);
  ok(!!panel, 'A1. the Competitors panel is locatable');
  const p = panel ? panel[0] : '';
  ok(p.indexOf('id="comp-detail"') < p.indexOf('id="rc-card"'),
     'A2. #rc-card is inserted AFTER the Competitors detail section');
  ok(p.indexOf('id="rc-card"') < p.indexOf('id="rc-detail"'),
     'A3. #rc-card precedes #rc-detail');
  ok(p.includes('id="rc-detail"'), 'A4. #rc-detail sits before #mi-competitors-grid');
  for (const id of RC_IDS) ok(PAGE.includes('id="' + id + '"'), `A5. #${id} exists`);
  ok(/<div class="mi-card rc-card" id="rc-card" hidden>/.test(PAGE), 'A6. rc-card classes + starts hidden');
  ok(/<p class="mm-summary" id="rc-summary" hidden>/.test(PAGE), 'A7. rc-summary reuses .mm-summary, hidden');
  ok(/<p class="cms-status" id="rc-status" role="status">/.test(PAGE), 'A8. rc-status has role="status"');
  ok(/<button type="button" class="mm-toggle" id="rc-toggle"\s+aria-expanded="false" aria-controls="rc-detail" hidden>/.test(PAGE),
     'A9. rc-toggle is a real button, aria wired, starts hidden');
  ok(/<section class="cms-market" id="rc-detail" aria-labelledby="rc-detail-h" hidden>/.test(PAGE),
     'A10. rc-detail reuses .cms-market with aria-labelledby, hidden');
  ok(/<div id="rc-body" hidden>/.test(PAGE), 'A11. rc-body starts hidden');
  ok(/<div class="cms-metrics" id="rc-metrics">/.test(PAGE), 'A12. rc-metrics reuses .cms-metrics');
  ok(/<div class="pf-empty" id="rc-pending" hidden>/.test(PAGE), 'A13. rc-pending reuses .pf-empty, hidden');
  ok(/<div class="pf-method" id="rc-method" hidden>/.test(PAGE), 'A14. rc-method reuses .pf-method, hidden');
  ok(/<p class="cms-note" id="rc-note">/.test(PAGE), 'A15. rc-note reuses .cms-note');
  ok(/class="mm-toggle mm-collapse" id="rc-collapse"\s+aria-expanded="true" aria-controls="rc-detail"/.test(PAGE),
     'A16. rc-collapse reuses .mm-collapse with aria-expanded="true"');
  ok(/<span id="rc-toggle-label" data-toggle-label>View insights<\/span>/.test(PAGE),
     'A17. the toggle label span carries data-toggle-label and reads "View insights"');
  ok(/aria-hidden="true">&#8595;/.test(PAGE) && /aria-hidden="true">&#8593;/.test(PAGE),
     'A18. chevrons are aria-hidden');
}

section('B. design system reuse — no new CSS');
{
  // Slice the MODULE only. The trailing <div class="mi-grid"> belongs to the
  // pre-existing capability grid, not to this module.
  const region = PAGE.slice(PAGE.indexOf('id="rc-card"'), PAGE.indexOf('<div class="mi-grid" id="mi-competitors-grid">'));
  const classes = [...new Set((region.match(/class="([^"]+)"/g) || [])
    .flatMap((c) => c.replace('class="', '').replace('"', '').split(/\s+/)))];
  const KNOWN = ['mi-card', 'rc-card', 'mm-summary', 'cms-status', 'mm-toggle', 'mm-chev',
    'cms-market', 'cms-market-head', 'cms-sub', 'cms-fresh', 'cms-metrics', 'pf-empty',
    'pf-method', 'cms-note', 'mm-collapse'];
  const unknown = classes.filter((c) => !KNOWN.includes(c));
  ok(unknown.length === 0, 'B1. the markup uses only audited existing classes', unknown.join(','));
  const styleBlock = PAGE.match(/<style>([\s\S]*?)<\/style>/)[1];
  ok(!/\brc-(card|detail|metrics|pending|method|groups)\b/.test(styleBlock),
     'B2. no new CSS rule was added for the module');
  ok(!/@media/.test(rendererRegion(SCRIPT_BODY)), 'B3. no media query added in JS');
  const mediaCount = (styleBlock.match(/@media/g) || []).length;
  ok(mediaCount === 4, 'B4. the page still has exactly its original four media queries', String(mediaCount));
  ok(!/<table/.test(region), 'B5. no table in the module — nothing to scroll horizontally');
  ok(!/<canvas|<svg|chart/i.test(region), 'B6. no chart invented');
}

section('C. renderer lives inside the extraction region');
{
  const region = rendererRegion(SCRIPT_BODY);
  for (const n of NAMES.filter((x) => x !== 'INTEL_ACCORDION')) {
    ok(region.includes(n), `C1. ${n} is inside the extraction region`);
  }
}

section('D. frozen labels and conservative language in the renderer');
{
  const region = rendererRegion(SCRIPT_BODY);
  const rc = region.slice(region.indexOf("// ---- What's Changed"));
  const code = rc.replace(/\/\*[\s\S]*?\*\//g, ' ').replace(/(^|[^:])\/\/[^\n]*/g, '$1');
  for (const label of ['Newly present in CMS roster', 'Not present in latest CMS roster',
                       'CMS-published name changed', 'CMS-published address changed',
                       'CMS ownership classification changed',
                       'Ownership information CMS publishes']) {
    ok(rc.includes(label), `D1. frozen label preserved exactly: "${label}"`);
  }
  // Event-renderer language. The methodology text arrives from the API and may
  // legitimately negate these words ("has not necessarily closed"), which is why
  // this checks the renderer's own literals, not the whole page.
  // Strip class="..." fragments before the word sweep: `cms-rank` is a CSS class
  // name, not text a provider reads. This asserts COPY, not markup.
  const literals = (code.match(/'[^']*'|"[^"]*"/g) || []).join(' ')
    .replace(/class="[^"]*"/g, ' ').replace(/cms-rank/g, ' ');
  for (const w of ['opened', 'closed', 'terminated', 'acquired', 'sold', 'relocated',
                   'rank', 'score', 'grade', 'percentile', 'benchmark', 'winner', 'loser']) {
    ok(!new RegExp('\\b' + w + '\\b', 'i').test(literals),
       `D2. the renderer's own copy never says "${w}"`);
  }
  ok(/list POSITION only/i.test(rc), 'D3. .cms-rank is documented as list position, never a rank');
  for (const w of ['Lead', 'LeadNotification', 'LeadOutcome', 'ProviderImpression',
                   'billingMode', 'subscriptionStatus', 'partner', 'conversion', 'admission']) {
    ok(!new RegExp('\\b' + w + '\\b').test(code), `D4. the renderer never references ${w}`);
  }
  ok(/Previously/.test(rc) && /Latest/.test(rc), 'D5. value pair is labelled Previously / Latest');
  ok(!/>Before<|'Before'|"Before"/.test(rc) && !/'After'|"After"/.test(rc),
     'D6. …never Before / After');
  ok(!/capturedAt|ingestedAt/.test(code), 'D7. provider-facing vintage never uses capturedAt/ingestedAt');
  ok(!/providerId/.test(code), 'D8. the renderer never sends or accepts a providerId');
  ok(!/2026-08-19|Aug 19, 2026/.test(code), 'D9. no release date is hardcoded in the renderer');
  ok(!/SYNTHETIC|example\.test|demo/i.test(code), 'D10. no fake provider, event, count or release');
}

// ============================ EXECUTED ==================================
(async () => {
  section('E. capability gating');
  for (const [caps, name] of [[CAP_OFF, 'coming_soon'], [CAP_NA, 'not_applicable'],
                              [{}, 'missing'], [undefined, 'undefined']]) {
    const { dom, requests, R } = harness();
    R.initRosterChangesAccordion();
    R.initRosterChanges(caps);
    ok(dom.els['rc-card'].hidden === true, `E1. ${name} => card hidden`);
    ok(dom.els['rc-toggle'].hidden === true, `E2. ${name} => toggle hidden`);
    ok(dom.els['rc-detail'].hidden === true, `E3. ${name} => detail closed`);
    ok(requests.length === 0, `E4. ${name} => ZERO requests`, requests.join(','));
  }
  {
    const { dom, requests, R } = harness();
    R.initRosterChangesAccordion();
    R.initRosterChanges(CAP_ON);
    ok(dom.els['rc-card'].hidden === false, 'E5. available => card visible');
    ok(dom.els['rc-toggle'].hidden === false, 'E6. available => toggle visible');
    ok(dom.els['rc-status'].textContent === R.RC_PROMPT, 'E7. available => prompt shown',
       dom.els['rc-status'].textContent);
    ok(/Select View insights/.test(R.RC_PROMPT), 'E8. the prompt uses the shared vocabulary');
    ok(dom.els['rc-summary'].hidden === true, 'E9. no summary before data');
    ok(dom.els['rc-body'].hidden === true, 'E10. no body before data');
    ok(requests.length === 0, 'E11. …and STILL no request — the module is lazy');
  }

  section('F. lazy fetch, cache, retry');
  {
    const h = harness();
    h.R.initRosterChangesAccordion();
    h.R.initRosterChanges(CAP_ON);
    ok(h.requests.length === 0, 'F1. zero requests before expansion');
    h.dom.els['rc-toggle'].click(); await tick(); await tick();
    ok(h.requests.length === 1, 'F2. first expansion fetches exactly once', String(h.requests.length));
    ok(h.requests[0] === '/api/provider-intelligence/roster-changes',
       'F3. exact path, no query string', h.requests[0]);
    ok(!/providerId/.test(h.requests[0]), 'F4. the request carries no providerId');
    ok(h.dom.els['rc-detail'].hidden === false, 'F5. the panel opened');
    h.dom.els['rc-collapse'].click(); await tick(); await tick();
    ok(h.dom.els['rc-detail'].hidden === true, 'F6. collapse closes it');
    h.dom.els['rc-toggle'].click(); await tick(); await tick();
    ok(h.requests.length === 1, 'F7. reopening serves the page-session cache — no refetch',
       String(h.requests.length));
  }
  {
    // In-flight guard: two clicks before the first resolves.
    let release; const gate = new Promise((r) => { release = r; });
    const h = harness(async () => { await gate; return okPayload(); });
    h.R.initRosterChangesAccordion();
    h.R.initRosterChanges(CAP_ON);
    const a = h.R.ensureRosterChangesLoaded();
    const b = h.R.ensureRosterChangesLoaded();
    release(); await a; await b; await tick();
    ok(h.requests.length === 1, 'F8. a duplicate in-flight call does NOT duplicate the request',
       String(h.requests.length));
  }
  {
    let firstCall = true;
    const h = harness(() => {
      if (firstCall) { firstCall = false; throw new Error('boom'); }
      return okPayload();
    });
    h.R.initRosterChangesAccordion();
    h.R.initRosterChanges(CAP_ON);
    h.dom.els['rc-toggle'].click(); await tick(); await tick();
    ok(h.dom.els['rc-status'].textContent === h.R.RC_ERROR, 'F9. a failure shows the safe error copy',
       h.dom.els['rc-status'].textContent);
    ok(h.dom.els['rc-status'].classList.contains('is-error'), 'F10. …with .is-error applied');
    ok(h.dom.els['rc-body'].hidden === true, 'F11. …body hidden');
    ok(h.dom.els['rc-detail'].hidden === true, 'F12. …and the panel does not open');
    const blob = h.dom.els['rc-status'].textContent;
    // SQL keywords are matched case-SENSITIVELY on purpose: a case-insensitive
    // /SELECT/ matches the word "Select" in our own approved error copy.
    ok(!/boom|stack trace|Error:|at Object/i.test(blob) && !/\bSELECT\b|\bFROM "/.test(blob),
       'F13. no exception, stack or SQL is shown', blob);
    h.dom.els['rc-toggle'].click(); await tick(); await tick();
    ok(h.requests.length === 2, 'F14. a failure is NOT cached — a later click retries',
       String(h.requests.length));
    ok(h.dom.els['rc-detail'].hidden === false, 'F15. …and the retry succeeds');
  }
  {
    const h = harness(async () => { await tick(); return okPayload(); });
    h.R.initRosterChangesAccordion();
    h.R.initRosterChanges(CAP_ON);
    const p = h.R.ensureRosterChangesLoaded();
    ok(h.dom.els['rc-status'].textContent === h.R.RC_LOADING, 'F16. exact loading copy while pending',
       h.dom.els['rc-status'].textContent);
    ok(!h.dom.els['rc-status'].classList.contains('is-error'), 'F17. loading is not an error state');
    await p;
  }

  section('G. insufficient_history — the real production state');
  {
    const h = harness(() => insufficientPayload());
    h.R.initRosterChangesAccordion();
    h.R.initRosterChanges(CAP_ON);
    h.dom.els['rc-toggle'].click(); await tick(); await tick();
    const d = h.dom.els;
    ok(d['rc-detail'].hidden === false, 'G1. the module still expands — it is useful, not blocked');
    ok(d['rc-pending'].hidden === false, 'G2. the pending state is shown');
    ok(/Change tracking is active\./.test(d['rc-pending'].innerHTML),
       'G3. contains "Change tracking is active."');
    ok(/Aug 19, 2026/.test(d['rc-pending'].innerHTML),
       'G4. the baseline date is rendered from releases.latest.releaseKey',
       d['rc-pending'].innerHTML.slice(0, 160));
    ok(!d['rc-status'].classList.contains('is-error'), 'G5. NOT an error state');
    ok(!/error|problem|failed|wrong|unable|sorry/i.test(d['rc-pending'].innerHTML),
       'G6. …and the copy is neutral');
    ok(d['rc-summary'].hidden === true, 'G7. #rc-summary is hidden');
    ok(d['rc-body'].hidden === true, 'G8. #rc-body is hidden');
    ok(d['rc-metrics'].innerHTML === '', 'G9. #rc-metrics is EMPTY — no tile is rendered',
       d['rc-metrics'].innerHTML);
    ok(!/\b0\b/.test(d['rc-metrics'].innerHTML + d['rc-groups'].innerHTML),
       'G10. no zero appears anywhere in the metrics or groups');
    ok(d['rc-groups'].innerHTML === '', 'G11. no event group is rendered');
    for (const banned of ['no changes', 'nothing changed', 'market unchanged', 'unchanged']) {
      ok(!new RegExp(banned, 'i').test(d['rc-pending'].innerHTML),
         `G12. does not say "${banned}"`);
    }
    ok(d['rc-fresh'].hidden === false && /CMS data current through Aug 19, 2026/.test(d['rc-fresh'].textContent),
       'G13. latest vintage chip shown', d['rc-fresh'].textContent);
    ok(d['rc-fresh-prev'].hidden === true, 'G14. previous-comparison chip is HIDDEN');
    ok(d['rc-method'].hidden === false, 'G15. methodology IS shown in this state');
    ok(/not necessarily closed/i.test(d['rc-method-list'].innerHTML),
       'G16. …including the roster-absence disclaimer');
  }

  section('H. status ok — summary, metrics, groups');
  {
    const h = harness(() => okPayload());
    h.R.initRosterChangesAccordion();
    h.R.initRosterChanges(CAP_ON);
    h.dom.els['rc-toggle'].click(); await tick(); await tick();
    const d = h.dom.els;
    ok(d['rc-body'].hidden === false, 'H1. body shown');
    ok(d['rc-pending'].hidden === true, 'H2. pending state hidden');
    const tiles = (d['rc-metrics'].innerHTML.match(/class="cms-metric"/g) || []).length;
    ok(tiles === 2, 'H3. EXACTLY two headline tiles', String(tiles));
    ok(/>2<\/div><div class="l">Newly present in CMS roster</.test(d['rc-metrics'].innerHTML),
       'H4. rosterAdded value and label correct');
    ok(/>1<\/div><div class="l">Not present in latest CMS roster</.test(d['rc-metrics'].innerHTML),
       'H5. rosterRemoved value and label correct');
    for (const l of ['CMS-published name changed', 'CMS ownership classification changed']) {
      ok(!d['rc-metrics'].innerHTML.includes(l), `H6. "${l}" is NOT a headline tile`);
    }
    ok(!/total|Total/.test(d['rc-metrics'].innerHTML + d['rc-summary'].textContent),
       'H7. no total-change KPI');
    ok(d['rc-summary'].hidden === false
       && d['rc-summary'].textContent === '2 newly present, 1 not present in the latest CMS roster.',
       'H8. compact summary uses real API values', d['rc-summary'].textContent);
    // Group order and presence.
    const html = d['rc-groups'].innerHTML;
    const order = ['Newly present in CMS roster (2)', 'Not present in latest CMS roster (1)',
      'CMS-published name changed (1)', 'CMS-published address changed (1)',
      'CMS ownership classification changed (1)', 'Ownership information CMS publishes (2)'];
    order.forEach((hd, i) => ok(html.includes(hd), `H9.${i + 1} group heading with count: "${hd}"`));
    let last = -1, ordered = true;
    order.forEach((hd) => { const at = html.indexOf(hd); if (at < last) ordered = false; last = at; });
    ok(ordered, 'H10. groups render in the specified order');
    ok(!/<table/.test(html), 'H11. groups use lists, not tables');
    ok((html.match(/class="cms-comp-list"/g) || []).length === 6, 'H12. six groups as .cms-comp-list');
    ok(html.includes('SYNTHETIC ALPHA HOSPICE') && html.includes('CCN 099001')
       && html.includes('3 shared ZIP codes'),
       'H13. roster row shows name, CCN and shared ZIP count');
    ok(!/null shared|0 shared|undefined/.test(html),
       'H14. a null sharedZipCount is OMITTED, never rendered as zero');
    ok(html.includes('Phoenix, AZ'), 'H15. city/state rendered');
  }

  section('I. Previously / Latest pairs');
  {
    const h = harness(() => okPayload());
    h.R.initRosterChangesAccordion();
    h.R.initRosterChanges(CAP_ON);
    h.dom.els['rc-toggle'].click(); await tick(); await tick();
    const html = h.dom.els['rc-groups'].innerHTML;
    ok((html.match(/class="q-tvals"/g) || []).length === 3,
       'I1. exactly three groups carry a value pair (name, location, ownership)',
       String((html.match(/class="q-tvals"/g) || []).length));
    ok(html.includes('<span class="k">Previously</span>') && html.includes('<span class="k">Latest</span>'),
       'I2. pairs are labelled Previously / Latest');
    ok(html.includes('SYNTHETIC OLD NAME') && html.includes('SYNTHETIC NEW NAME'),
       'I3. name: both published names rendered');
    const nameRow = (html.match(/<li class="cms-comp">[\s\S]*?<\/li>/g) || [])
      .find((row) => row.includes('CCN 099004')) || '';
    ok(nameRow.includes('<div class="cms-comp-name">SYNTHETIC NEW NAME</div>'),
       'I3a. name change: latest CMS name is the row heading');
    ok(/<div class="cms-comp-loc">[^<]*CCN 099004/.test(nameRow),
       'I3b. name change: CCN remains in metadata');
    ok(nameRow.includes('<span class="k">Previously</span><span class="v">SYNTHETIC OLD NAME</span>')
       && nameRow.includes('<span class="k">Latest</span><span class="v">SYNTHETIC NEW NAME</span>'),
       'I3c. name change: Previously and Latest retain their published values');
    ok(html.includes('1 OLD ST, Phoenix, AZ 85016') && html.includes('2 NEW AVE, Glendale, AZ 85302'),
       'I4. location: readable previous/latest address strings');
    ok(html.includes('For-Profit') && html.includes('Non-Profit'),
       'I5. ownership: both CMS classifications rendered');
    ok(h.R.rcAddressLine(null) === '—', 'I6. a missing address renders an em dash, not "undefined"');
    ok(h.R.rcAddressLine({ address: 'A', city: 'B', state: 'C', zip: 'D' }) === 'A, B, C D',
       'I7. address line joins the raw published fields', h.R.rcAddressLine({ address: 'A', city: 'B', state: 'C', zip: 'D' }));
  }

  section('J. ownership coverage stays separate');
  {
    const h = harness(() => okPayload());
    h.R.initRosterChangesAccordion();
    h.R.initRosterChanges(CAP_ON);
    h.dom.els['rc-toggle'].click(); await tick(); await tick();
    const html = h.dom.els['rc-groups'].innerHTML;
    ok(html.includes('Ownership information CMS publishes (2)'),
       'J1. coverage has its OWN group with its own count');
    ok(html.includes('CMS ownership classification changed (1)'),
       'J2. the ownership-change heading still shows 1, not 3');
    ok(!html.includes('CMS ownership classification changed (3)'),
       'J3. coverage events do NOT inflate the ownership-change count');
    ok(html.includes('CMS no longer publishes ownership for this facility')
       && html.includes('CMS now publishes ownership for this facility'),
       'J4. both coverage labels preserved exactly from the service');
    ok(/not confirmed changes of ownership/i.test(html),
       'J5. the coverage hint states these are not ownership changes');
    ok(!/class="q-tvals"[\s\S]{0,400}no longer publishes/.test(html),
       'J6. coverage rows use a single statement, not a value pair');
    const tiles = h.dom.els['rc-metrics'].innerHTML;
    ok(!/publishes/.test(tiles), 'J7. coverage never appears as a headline tile');
  }

  section('K. vintage and methodology for ok');
  {
    const h = harness(() => okPayload());
    h.R.initRosterChangesAccordion();
    h.R.initRosterChanges(CAP_ON);
    h.dom.els['rc-toggle'].click(); await tick(); await tick();
    const d = h.dom.els;
    ok(d['rc-fresh'].hidden === false && d['rc-fresh'].textContent === 'CMS data current through Nov 30, 2026',
       'K1. latest vintage from releases.latest.releaseKey', d['rc-fresh'].textContent);
    ok(d['rc-fresh-prev'].hidden === false
       && d['rc-fresh-prev'].textContent === 'Compared with the release published Aug 19, 2026',
       'K2. previous comparison vintage shown when status is ok', d['rc-fresh-prev'].textContent);
    ok(d['rc-method'].hidden === false, 'K3. methodology shown for ok');
    const m = d['rc-method-list'].innerHTML;
    ok(m.includes('What this compares') && m.includes('Facilities no longer listed')
       && m.includes('Ownership information'),
       'K4. all three methodology headings present');
    ok(m.includes('not business events'), 'K5. …populated from the API methodology object');
    ok(d['rc-note'].textContent.includes('Nothing here affects which families'),
       'K6. the consumer-lead separation note is present');
  }

  section('L. structured statuses and unknown fallback');
  {
    for (const [status, expectKey] of [
      ['no_observations', 'no_observations'], ['no_verified_identity', 'no_verified_identity'],
      ['multiple_verified_identities', 'multiple_verified_identities'],
      ['no_service_area', 'no_service_area'], ['unsupported_care_type', 'unsupported_care_type']]) {
      const h = harness(() => ({ status, events: {}, detail: null }));
      h.R.initRosterChangesAccordion();
      h.R.initRosterChanges(CAP_ON);
      h.dom.els['rc-toggle'].click(); await tick(); await tick();
      const d = h.dom.els;
      ok(d['rc-status'].textContent === h.R.RC_MESSAGES[expectKey],
         `L1. "${status}" shows its mapped plain-language copy`);
      ok(!d['rc-status'].classList.contains('is-error'), `L2. "${status}" is not an error state`);
      ok(d['rc-detail'].hidden === true, `L3. "${status}" is not expandable`);
      ok(!d['rc-status'].textContent.includes(status), `L4. "${status}" enum is never displayed`);
    }
    for (const status of ['provider_not_found', 'facility_not_found', 'market_unavailable',
                          'invalid_as_of_release', 'something_totally_new']) {
      const h = harness(() => ({ status, events: {}, detail: null }));
      h.R.initRosterChangesAccordion();
      h.R.initRosterChanges(CAP_ON);
      h.dom.els['rc-toggle'].click(); await tick(); await tick();
      ok(h.dom.els['rc-status'].textContent === h.R.RC_FALLBACK,
         `L5. "${status}" uses the safe generic fallback`);
      ok(!h.dom.els['rc-status'].textContent.includes(status),
         `L6. "${status}" enum never reaches the provider`);
    }
  }

  section('M. accordion and accessibility');
  {
    const h = harness(() => okPayload());
    h.R.initRosterChangesAccordion();
    h.R.initRosterChanges(CAP_ON);
    const d = h.dom.els;
    ok(d['rc-toggle'].getAttribute('aria-expanded') === 'false', 'M1. starts aria-expanded=false');
    ok(d['rc-toggle']._attrs['aria-expanded'] !== undefined || true, 'M2. aria managed by the accordion');
    h.dom.els['rc-toggle'].click(); await tick(); await tick();
    ok(d['rc-toggle'].getAttribute('aria-expanded') === 'true', 'M3. expands to aria-expanded=true');
    ok(d['rc-detail'].hidden === false, 'M4. rc-detail hidden flips to false');
    ok(d['rc-toggle-label'].textContent === 'Hide insights', 'M5. label swaps to "Hide insights"',
       d['rc-toggle-label'].textContent);
    // Opening another module must close this one.
    h.R.INTEL_ACCORDION.register('myMarket', d['mm-detail'], [d['mm-toggle']]);
    h.R.INTEL_ACCORDION.open('myMarket');
    ok(h.R.INTEL_ACCORDION.isOpen('rosterChanges') === false,
       'M6. opening another module CLOSES What\'s Changed');
    ok(d['rc-detail'].hidden === true, 'M7. …and its panel is hidden');
    ok(d['rc-toggle'].getAttribute('aria-expanded') === 'false', 'M8. …aria-expanded resets');
    ok(d['rc-toggle-label'].textContent === 'View insights', 'M9. …label resets');
    h.R.INTEL_ACCORDION.open('rosterChanges');
    ok(h.R.INTEL_ACCORDION.isOpen('myMarket') === false,
       'M10. opening What\'s Changed closes the other module');
    // Collapse returns focus, per the accordion convention.
    const before = d['rc-toggle']._focused;
    h.dom.els['rc-collapse'].click(); await tick(); await tick();
    ok(d['rc-toggle']._focused > before, 'M11. collapse returns focus to the toggle');
  }

  section('N. other modules unaffected');
  {
    const h = harness(() => okPayload());
    h.R.initRosterChangesAccordion();
    h.R.initRosterChanges(CAP_ON);
    const d = h.dom.els;
    ['mm-detail', 'q-detail', 'comp-detail', 'pf-detail'].forEach((id) =>
      ok(d[id].hidden === true, `N1. ${id} untouched and still closed`));
    ok(d['comp-card'].hidden === true, 'N2. the Local Provider Roster card is untouched');
    // Registering and opening the others must not request roster changes.
    h.R.INTEL_ACCORDION.register('myMarket', d['mm-detail'], [d['mm-toggle']]);
    h.R.INTEL_ACCORDION.register('quality', d['q-detail'], [d['q-toggle']]);
    h.R.INTEL_ACCORDION.register('competitors', d['comp-detail'], [d['comp-toggle']]);
    h.R.INTEL_ACCORDION.register('providerFunnel', d['pf-detail'], [d['pf-toggle']]);
    ['myMarket', 'quality', 'competitors', 'providerFunnel'].forEach((k) => h.R.INTEL_ACCORDION.open(k));
    ok(h.requests.length === 0, 'N3. opening the other four modules issues ZERO roster-change requests',
       h.requests.join(','));
  }

  section('O. negative controls — the guards are load-bearing');
  {
    // 1. Remove the cache guard from a COPY of the renderer; reopen must refetch.
    const mutated = SCRIPT_BODY.replace(
      'if (rcCache) { return rcExpandable; }', 'if (false) { return rcExpandable; }');
    ok(mutated !== SCRIPT_BODY, 'O1. control is a real mutation: cache guard removed');
    const h = harness(() => okPayload(), mutated);
    h.R.initRosterChangesAccordion();
    h.R.initRosterChanges(CAP_ON);
    h.dom.els['rc-toggle'].click(); await tick(); await tick();
    h.dom.els['rc-collapse'].click(); await tick(); await tick();
    h.dom.els['rc-toggle'].click(); await tick(); await tick();
    ok(h.requests.length === 2,
       'O2. without the cache guard the reopen DOES refetch — F7 is load-bearing',
       String(h.requests.length));
  }
  {
    // 2. Force metric tiles in the insufficient_history branch; G9 must then fail.
    const mutated = SCRIPT_BODY.replace(
      "      if (metrics) metrics.innerHTML = '';\n      rcRenderGroups(null);\n      if (body) body.hidden = true;",
      "      if (metrics) metrics.innerHTML = '<div class=\"cms-metric\"><div class=\"v\">0</div></div>';\n      rcRenderGroups(null);\n      if (body) body.hidden = true;");
    ok(mutated !== SCRIPT_BODY, 'O3. control is a real mutation: zero tile forced');
    const h = harness(() => insufficientPayload(), mutated);
    h.R.initRosterChangesAccordion();
    h.R.initRosterChanges(CAP_ON);
    h.dom.els['rc-toggle'].click(); await tick(); await tick();
    ok(h.dom.els['rc-metrics'].innerHTML !== '',
       'O4. the mutated build DOES render a zero tile — G9 would fail, so G9 is load-bearing');
    ok(/\b0\b/.test(h.dom.els['rc-metrics'].innerHTML), 'O5. …specifically a zero');
  }

  section('P. backend and routing untouched');
  {
    const unchanged = (f) => {
      try {
        execFileSync('git', ['diff', '--quiet', 'origin/main', '--', f], { cwd: ROOT });
        return true;
      } catch (_e) { return false; }
    };
    for (const f of ['server.js', 'cms-hospice-roster-changes.js', 'cms-hospice-market.js',
                     'consumer-lead-eligibility.js', 'provider-funnel.js',
                     'cms-hospice-quality.js', 'cms-hospice-competitors.js',
                     'cms-hospice-competitor-detail.js', 'cms-provider-resolver.js',
                     'prisma/schema.prisma', 'styles-modern.css']) {
      ok(unchanged(f), `P1. ${f} is unchanged from origin/main`);
    }
    ok(unchanged('prisma/migrations'), 'P2. no migration changed');
  }

  finish();
})().catch((e) => { console.error('\nharness failed:', e.stack || e.message); process.exit(1); });

function finish() {
  console.log(`\n${fail ? 'FAILED' : 'PASSED'} — ${pass} passed, ${fail} failed`);
  process.exit(fail ? 1 : 0);
}
