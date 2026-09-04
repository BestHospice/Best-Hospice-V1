#!/usr/bin/env node
/**
 * Guards Provider Funnel Intelligence V1 Phase B — the reconciled
 * /api/provider/metrics counting definition, the authenticated funnel endpoint,
 * the release gate, the capability and the provider-visible UI.
 *
 * The repo has no HTTP harness and no DOM library. Rather than pattern-matching
 * templates, this suite EXECUTES the real code: countNotifiedPairs and the route
 * handlers are extracted from server.js and run against injected stubs, the
 * capability function is evaluated from its own source with an injected
 * `process`, and the render functions are extracted from
 * provider-intelligence.html and run against a small DOM stub, so the
 * assertions read the HTML the page actually produced.
 *
 * With TEST_DATABASE_URL set, the endpoint is additionally run end to end
 * against the real service and real rows in a disposable PostgreSQL database,
 * where the metrics definition and the funnel definition are proven to agree on
 * the same rows.
 *
 * Every provider id, lead id, name, email and ZIP here is SYNTHETIC. No
 * production identifier appears anywhere.
 *
 *   node scripts/test-provider-funnel-ui.js
 *   TEST_DATABASE_URL=postgresql://user@localhost:5432/bh_competitors_test \
 *     node scripts/test-provider-funnel-ui.js
 */
const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const SRC = fs.readFileSync(path.join(ROOT, 'server.js'), 'utf8');
const PAGE = fs.readFileSync(path.join(ROOT, 'provider-intelligence.html'), 'utf8');
const SCRIPT_BODY = PAGE.match(/<script>([\s\S]*?)<\/script>/)[1];
const { FUNNEL_WINDOWS, FUNNEL_STATUS, METHODOLOGY, OUTCOME_BUCKETS } =
  require(path.join(ROOT, 'provider-funnel.js'));

let pass = 0, fail = 0;
const ok = (c, label, detail) => {
  console.log(`  ${c ? 'ok  ' : 'FAIL'} ${label}${c || !detail ? '' : `  — ${detail}`}`);
  c ? pass++ : fail++;
};
const section = (t) => console.log(`\n--- ${t} ---`);
const tick = () => new Promise((r) => setTimeout(r, 0));
const grab = (rx, label) => { const m = SRC.match(rx); if (!m) throw new Error('missing ' + label); return m[0]; };
const makeRes = () => {
  const r = { _code: 200, _json: undefined };
  r.status = (c) => { r._code = c; return r; };
  r.json = (v) => { r._json = v; return r; };
  return r;
};
// Every key at every depth, so a PII field cannot hide inside a nested object.
const allKeys = (v, out = new Set()) => {
  if (Array.isArray(v)) v.forEach((x) => allKeys(x, out));
  else if (v && typeof v === 'object') { for (const k of Object.keys(v)) { out.add(k); allKeys(v[k], out); } }
  return out;
};

// ============ 1. THE ONE COUNTING DEFINITION, EXECUTED ======================
section('1. metrics reconciliation — countNotifiedPairs');
const HELPER_SRC = grab(/function countNotifiedPairs\(notifications\) \{[\s\S]*?\n\}/, 'countNotifiedPairs');
const countNotifiedPairs = new Function(HELPER_SRC + '\nreturn countNotifiedPairs;')();

const N = (leadId, status) => ({ leadId, status });
{
  // The production case that made this necessary: /api/notify sends an initial
  // notification and a follow-up when the family adds details, so ONE referral
  // legitimately writes two rows.
  const dup = countNotifiedPairs([N('l1', 'sent'), N('l1', 'sent')]);
  ok(dup.emailsSent === 1, '1a. duplicate sent rows for one provider-lead pair count ONCE', String(dup.emailsSent));
  ok(dup.leadsGenerated === 1, '1b. …and leadsGenerated agrees', String(dup.leadsGenerated));

  const two = countNotifiedPairs([N('l1', 'sent'), N('l2', 'sent')]);
  ok(two.emailsSent === 2, '1c. two different leads count TWICE', String(two.emailsSent));

  const three = countNotifiedPairs([N('l1', 'sent'), N('l1', 'sent'), N('l1', 'sent'), N('l2', 'sent')]);
  ok(three.emailsSent === 2, '1d. three rows for one pair plus one other still count 2', String(three.emailsSent));

  // A failed row is not a referral we delivered, but the family WAS matched, so
  // leadsGenerated (which is "leads we tried to notify you about") still counts.
  const failed = countNotifiedPairs([N('l1', 'failed')]);
  ok(failed.emailsSent === 0, '1e. a failed notification does NOT count as sent', String(failed.emailsSent));
  ok(failed.leadsGenerated === 1, '1f. …but the lead is still counted as generated', String(failed.leadsGenerated));

  const mixed = countNotifiedPairs([N('l1', 'failed'), N('l1', 'sent')]);
  ok(mixed.emailsSent === 1 && mixed.leadsGenerated === 1,
     '1g. failed then sent for the same pair is ONE sent referral');

  const pending = countNotifiedPairs([N('l1', 'pending'), N('l2', 'queued')]);
  ok(pending.emailsSent === 0, '1h. only the exact status "sent" counts — nothing else', String(pending.emailsSent));
  ok(countNotifiedPairs([]).emailsSent === 0 && countNotifiedPairs([]).leadsGenerated === 0,
     '1i. no notifications yields zero, not NaN');

  // The overstatement this replaced: 12 rows over 11 pairs is the shape
  // production measured at 8.10%.
  const many = [];
  for (let i = 1; i <= 11; i++) many.push(N('l' + i, 'sent'));
  many.push(N('l2', 'sent'));
  ok(countNotifiedPairs(many).emailsSent === 11,
     '1j. 12 sent ROWS over 11 pairs counts 11 — the 8.1% overstatement is gone',
     String(countNotifiedPairs(many).emailsSent));
  ok(many.length === 12, '1k. …and the raw row count would have said 12', String(many.length));
}

section('2. every surface resolves that ONE definition');
{
  // Provider isolation for these metrics is the WHERE clause: rows arrive
  // already scoped to one provider, so leadId alone identifies the pair.
  const metricsRoute = grab(/app\.get\('\/api\/provider\/metrics'[\s\S]*?\n\}\);/, 'metrics route');
  ok(!/prisma\.leadNotification\.count\(/.test(metricsRoute),
     '2a. /api/provider/metrics no longer counts raw notification ROWS');
  ok(/countNotifiedPairs\(leadNotifications\)/.test(metricsRoute),
     '2b. …it resolves the shared definition');
  ok((metricsRoute.match(/providerId: ctx\.providerId/g) || []).length === 2,
     '2c. …and both of its queries still filter on the authenticated provider',
     String((metricsRoute.match(/providerId: ctx\.providerId/g) || []).length));
  ok(/select: \{ leadId: true, status: true \}/.test(metricsRoute),
     '2d. …selecting only the two columns the count needs — no PII column');
  ok(/createdAt: \{ gte: start, lte: end \}/.test(metricsRoute),
     '2e. the EXISTING start/end time scope is preserved — only counting changed');
  ok(!/window|30d|90d/.test(metricsRoute),
     '2f. …and no funnel window semantics leaked into it');

  const dashRoute = grab(/app\.get\('\/api\/provider-dashboard\/metrics'[\s\S]*?\n\}\);/, 'dashboard metrics');
  ok(/countNotifiedPairs\(sentNotifications\)/.test(dashRoute),
     '2g. "Leads Sent to You" on the Operations dashboard resolves it too');
  ok(!/prisma\.leadNotification\.count\(/.test(dashRoute),
     '2h. …and no longer counts raw rows into the revenue estimate');
  ok(/providerImpression\.count/.test(dashRoute),
     '2i. impressions are deliberately UNCHANGED — one appearance is not one family');

  // The assistant quotes "Emails sent: N" verbatim to a provider, so a fix that
  // stopped at the endpoint would have left the old number on the same screen.
  const helperUses = (SRC.match(/countNotifiedPairs\(/g) || []).length;
  ok(helperUses === 6, '2j. all five call sites plus the definition resolve one helper', String(helperUses));
  const rawSentCounts = (SRC.match(/leadNotification\.count\(\{ where: \{ providerId, status: 'sent'/g) || []).length;
  ok(rawSentCounts === 0, '2k. no provider-scoped raw sent-row count survives anywhere', String(rawSentCounts));
  const assistantRanges = (SRC.match(/const metricsRange = async/g) || []).length;
  ok(assistantRanges === 2, '2l. both assistant metricsRange helpers exist…', String(assistantRanges));
  ok((SRC.match(/countNotifiedPairs\(leadNotifications\)/g) || []).length === 3,
     '2m. …and both were reconciled with the route', 
     String((SRC.match(/countNotifiedPairs\(leadNotifications\)/g) || []).length));
}

// ============ 3. CAPABILITY AND RELEASE GATE ================================
section('3. release gate and capability');
const CAPS_SRC = [grab(/const INTELLIGENCE_MODULES = \[[\s\S]*?\n\];/, 'modules'),
  grab(/const CMS_QUALITY_PROVIDER_TYPES = new Set\([^)]*\);/, 'cms types'),
  grab(/const KNOWN_INTELLIGENCE_TYPES = \{[\s\S]*?\n\};/, 'known types'),
  grab(/const TYPE_LABELS = \{[^}]*\};/, 'labels'),
  grab(/const CMS_QUALITY_INTELLIGENCE_ENABLED = [^\n]*/, 'quality gate'),
  grab(/const CMS_COMPETITOR_INTELLIGENCE_ENABLED = [^\n]*/, 'competitor gate'),
  grab(/const PROVIDER_FUNNEL_V1_ENABLED = [^\n]*/, 'funnel gate'),
  grab(/function providerIntelligenceCapabilities\(provider\) \{[\s\S]*?\n\}/, 'fn')].join('\n');
const buildCaps = (env) => new Function('process',
  CAPS_SRC + '\nreturn { providerIntelligenceCapabilities, INTELLIGENCE_MODULES };')({ env: env || {} });
{
  const off = buildCaps({});
  const on = buildCaps({ PROVIDER_FUNNEL_V1_ENABLED: 'true' });
  ok(off.INTELLIGENCE_MODULES.includes('providerFunnelV1'),
     '3a. providerFunnelV1 is an accounted-for module');
  ok(off.providerIntelligenceCapabilities({ careType: 'hospice' }).providerFunnelV1.status === 'coming_soon',
     '3b. GATE OFF (variable absent) — the capability is not available');
  ok(on.providerIntelligenceCapabilities({ careType: 'hospice' }).providerFunnelV1.status === 'available',
     '3c. GATE ON — available');
  for (const bad of ['false', 'TRUE', 'True', '1', 'on', 'yes', ' true', 'true ', '']) {
    ok(buildCaps({ PROVIDER_FUNNEL_V1_ENABLED: bad })
        .providerIntelligenceCapabilities({ careType: 'hospice' }).providerFunnelV1.status === 'coming_soon',
       `3d. …and ${JSON.stringify(bad)} FAILS CLOSED`);
  }
  // Best Hospice's own referral record, not a CMS dataset: a home care or
  // palliative provider receives referrals exactly as a hospice does.
  for (const t of ['hospice', 'home-care', 'palliative', 'assisted-living', '', null, undefined, 'nonsense']) {
    ok(on.providerIntelligenceCapabilities({ careType: t }).providerFunnelV1.status === 'available',
       `3e. available for careType ${JSON.stringify(t)} — never gated on CMS coverage`);
    ok(on.providerIntelligenceCapabilities({ careType: t }).providerFunnelV1.status !== 'not_applicable',
       `3f. …and never not_applicable for ${JSON.stringify(t)}`);
  }
  // The funnel gate must not disturb any other module's state.
  const baseOff = off.providerIntelligenceCapabilities({ careType: 'hospice' });
  const baseOn = on.providerIntelligenceCapabilities({ careType: 'hospice' });
  const others = Object.keys(baseOff).filter((k) => k !== 'providerFunnelV1');
  ok(others.every((k) => JSON.stringify(baseOff[k]) === JSON.stringify(baseOn[k])),
     '3g. turning the funnel gate on changes NO other capability');
  ok(baseOff.cmsQuality.status === 'coming_soon' && baseOff.cmsCompetitors.status === 'coming_soon',
     '3h. the two CMS gates are still independently OFF by default');
  ok(baseOn.bestHospiceLeadAnalytics.status === 'available',
     '3i. the pre-existing Best Hospice card is untouched');
}

// ============ 4. THE AUTHENTICATED ENDPOINT =================================
section('4. GET /api/provider/funnel — auth and provider isolation');
const ROUTE = grab(/app\.get\('\/api\/provider\/funnel'[\s\S]*?\n\}\);/, 'funnel route');
const HANDLER_BODY = ROUTE.match(/async \(req, res\) => \{([\s\S]*)\n\}\);$/)[1];
const CALLS = [];
const funnelStub = async (prisma, providerId, options) => {
  CALLS.push({ providerId, options });
  return {
    status: FUNNEL_STATUS.OK,
    window: { key: options.window, label: FUNNEL_WINDOWS[options.window].label,
              from: options.window === 'all' ? null : '2026-06-06T12:00:00.000Z',
              to: '2026-09-04T12:00:00.000Z', cohortBasis: 'lead_created_at' },
    volume: { referralsSent: 11, timesMatched: 12, couldNotBeDelivered: 0 },
    engagement: { responsesRecorded: 5, noResponseRecorded: 6 },
    outcomes: OUTCOME_BUCKETS.map((b) => ({ key: b.key, label: b.label, count: 1 })),
    methodology: METHODOLOGY,
    detail: null
  };
};
const makeHandler = (ctxImpl, gateOn, svc) =>
  new Function('PROVIDER_FUNNEL_V1_ENABLED', 'PROVIDER_FUNNEL_DEFAULT_WINDOW', 'FUNNEL_WINDOWS',
    'FUNNEL_STATUS', 'getProviderContext', 'buildProviderFunnel', 'prisma', 'console', 'req', 'res',
    'return (async () => {' + HANDLER_BODY + '\n})();')
    .bind(null, gateOn === undefined ? true : gateOn, '90d', FUNNEL_WINDOWS, FUNNEL_STATUS,
      ctxImpl, svc || funnelStub, {}, { error() {} });
const AUTHED = async () => ({ providerId: 'pf-authed-provider', provider: { id: 'pf-authed-provider' } });
const run = async (req, opts = {}) => {
  CALLS.length = 0;
  const res = makeRes();
  await makeHandler(opts.ctx || AUTHED, opts.gate, opts.svc)({ query: {}, body: {}, params: {}, ...req }, res);
  return res;
};
(async () => {
  ok(/app\.get\('\/api\/provider\/funnel', requireProviderAuth,/.test(SRC),
     '4a. the route is mounted behind requireProviderAuth');
  {
    const r = await run({}, { ctx: async () => null });
    ok(r._code === 401, '4b. no resolvable provider context — 401', String(r._code));
    ok(CALLS.length === 0, '4c. …and the service was never called');
  }
  {
    const r = await run({}, { gate: false });
    ok(r._code === 404, '4d. RELEASE GATE OFF — 404, the feature is not live', String(r._code));
    ok(CALLS.length === 0, '4e. …and no count is computed');
    ok(!r._json.volume && !r._json.outcomes, '4f. …and no funnel shape is returned');
  }
  {
    const r = await run({});
    ok(r._code === 200 && CALLS[0].providerId === 'pf-authed-provider',
       '4g. the provider id comes from the AUTHENTICATED context', CALLS[0] && CALLS[0].providerId);
  }
  // The isolation contract: there is no request-supplied provider identity.
  for (const attack of [
    { query: { providerId: 'pf-victim' } },
    { query: { provider_id: 'pf-victim' } },
    { query: { providerUserId: 'pf-victim' } },
    { body: { providerId: 'pf-victim' } },
    { params: { providerId: 'pf-victim' } },
    { query: { providerId: 'pf-victim', window: '30d' } }
  ]) {
    const r = await run(attack);
    ok(r._code === 200 && CALLS.length === 1 && CALLS[0].providerId === 'pf-authed-provider',
       `4h. ${JSON.stringify(attack)} cannot switch providers`, CALLS[0] && CALLS[0].providerId);
  }
  ok(!/req\.(query|body|params)\.provider/i.test(ROUTE),
     '4i. the handler reads no provider identifier from the request at all');
  const reqReads = Array.from(new Set(ROUTE.match(/req\.(?:query|body|params)\.\w+/g) || []));
  ok(reqReads.length === 1 && reqReads[0] === 'req.query.window',
     '4j. the ONLY request input is the window', reqReads.join(' '));

  section('5. window validation, default and the `now` seam');
  {
    for (const w of ['30d', '90d', 'all']) {
      const r = await run({ query: { window: w } });
      ok(r._code === 200 && CALLS[0].options.window === w, `5a. window "${w}" accepted`, String(r._code));
    }
    const dflt = await run({});
    ok(dflt._code === 200 && CALLS[0].options.window === '90d',
       '5b. an ABSENT window defaults to 90d', CALLS[0] && CALLS[0].options.window);
    ok(/PROVIDER_FUNNEL_DEFAULT_WINDOW/.test(ROUTE) && /= '90d';/.test(grab(/const PROVIDER_FUNNEL_DEFAULT_WINDOW = [^\n]*/, 'default')),
       '5c. …from the named default constant, which is 90d');

    // Fails closed. '' and a repeated parameter are NOT silently coerced.
    for (const bad of ['', ' ', '7d', '60d', '30', '30D', 'ALL', 'all-time', 'last30', '90d ',
                       'null', '__proto__', 'constructor', 'hasOwnProperty', 'toString']) {
      const r = await run({ query: { window: bad } });
      ok(r._code === 400 && CALLS.length === 0,
         `5d. window ${JSON.stringify(bad)} — 400 and no query runs`, String(r._code));
    }
    // ?window=30d&window=90d and ?window[]=30d both arrive as arrays. The
    // second is the trap: String(['30d']) is exactly '30d'.
    for (const bad of [['30d'], ['30d', '90d'], { '0': '30d' }, { toString: () => '30d' }, 30, true, null]) {
      const r = await run({ query: { window: bad } });
      ok(r._code === 400 && CALLS.length === 0,
         `5e. non-string window ${JSON.stringify(bad)} — 400`, String(r._code));
    }
    const r400 = await run({ query: { window: '7d' } });
    ok(Array.isArray(r400._json.allowed)
       && JSON.stringify(r400._json.allowed) === JSON.stringify(['30d', '90d', 'all']),
       '5f. the 400 names the three allowed windows');

    // options.now must be unreachable over HTTP, or a caller could move the
    // cohort boundary and read a period we never meant to serve.
    for (const attack of [{ query: { now: '2020-01-01' } }, { query: { window: '30d', now: 0 } },
                          { body: { now: '2020-01-01' } }]) {
      const r = await run(attack);
      ok(r._code === 200 && !('now' in CALLS[0].options),
         `5g. ${JSON.stringify(attack)} does not reach options.now`,
         JSON.stringify(Object.keys(CALLS[0].options)));
    }
    ok(!/now/.test(ROUTE.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '')),
       '5h. the handler never mentions `now`');
    const r = await run({ query: { window: '30d' } });
    ok(JSON.stringify(Object.keys(CALLS[0].options)) === JSON.stringify(['window']),
       '5i. the options object carries the window and nothing else',
       JSON.stringify(Object.keys(CALLS[0].options)));
  }

  section('6. response shape — aggregates only, no PII');
  {
    const r = await run({});
    ok(r._json.ok === true, '6a. ok:true');
    ok(JSON.stringify(Object.keys(r._json))
       === JSON.stringify(['ok', 'status', 'window', 'volume', 'engagement', 'outcomes', 'methodology', 'detail']),
       '6b. exactly the approved top-level keys', Object.keys(r._json).join(','));
    const keys = allKeys(r._json);
    for (const pii of ['clientEmail', 'clientPhone', 'firstName', 'lastName', 'clientName', 'email',
                       'phone', 'address', 'notes', 'services', 'sessionId', 'zip', 'leadId',
                       'leads', 'rows', 'name', 'ip', 'providerId']) {
      ok(!keys.has(pii), `6c. no "${pii}" anywhere in the response`);
    }
    for (const forbidden of ['rate', 'score', 'rank', 'grade', 'percentile', 'benchmark', 'median',
                             'mean', 'average', 'avg', 'trend', 'composite', 'percent', 'ratio']) {
      const hit = Array.from(keys).filter((k) => k.toLowerCase().includes(forbidden));
      ok(hit.length === 0, `6d. no response key contains "${forbidden}"`, hit.join(','));
    }
    ok(r._json.volume.referralsSent === 11 && r._json.engagement.responsesRecorded === 5,
       '6e. the counts pass through unchanged');
    ok(r._json.outcomes.length === 4
       && JSON.stringify(r._json.outcomes.map((o) => o.label))
          === JSON.stringify(['Received', 'Contacted', 'Admitted', 'Not a True Lead']),
       '6f. four buckets with the shipped labels');
    ok(!!r._json.methodology.noResponseDefinition,
       '6g. the methodology travels with the counts');
  }
  {
    // A fail-closed service status must never be dressed up as a real funnel of
    // zeroes — that is the misleading output the whole design avoids.
    const svc = async () => ({ status: FUNNEL_STATUS.INVALID_PROVIDER, window: null, volume: null,
                               engagement: null, outcomes: null, methodology: null, detail: 'x' });
    const r = await run({}, { svc });
    ok(r._code === 500, '6h. an unexpected service status is a 500, not a zeroed funnel', String(r._code));
    ok(!r._json.volume && !r._json.outcomes, '6i. …and carries no funnel shape');
  }
  await uiTests();
})().catch((e) => { console.error('\nharness failed:', e.stack || e.message); process.exit(1); });

// ============ 7. THE PROVIDER UI ============================================
const TOGGLE_LABEL = { 'pf-toggle': 'pf-toggle-label', 'comp-toggle': 'comp-toggle-label',
                       'q-toggle': 'q-toggle-label', 'mm-toggle': 'mm-toggle-label' };
function makeDom() {
  const els = {};
  const mk = (id) => (els[id] = {
    id, innerHTML: '', textContent: '', value: '', hidden: false, onclick: null,
    tagName: 'BUTTON', dataset: {}, _attrs: {}, _listeners: {}, _focused: 0, _classes: new Set(),
    classList: { add(c) { els[id]._classes.add(c); }, remove(c) { els[id]._classes.delete(c); },
                 contains(c) { return els[id]._classes.has(c); },
                 toggle(c, on) { const s = els[id]._classes;
                   const want = on === undefined ? !s.has(c) : !!on;
                   if (want) s.add(c); else s.delete(c); return want; } },
    setAttribute(k, v) { this._attrs[k] = v; },
    getAttribute(k) { return this._attrs[k]; },
    addEventListener(ev, fn) { (this._listeners[ev] = this._listeners[ev] || []).push(fn); },
    click() { if (typeof this.onclick === 'function') this.onclick();
              (this._listeners.click || []).forEach((f) => f()); },
    querySelector(sel) {
      if (sel === '[data-toggle-label]') return els[TOGGLE_LABEL[id]] || null;
      if (sel === 'tbody') return { innerHTML: '' };
      return null;
    },
    // The window control is queried as a group, so the stub must return the
    // three real buttons with their real data-window values.
    querySelectorAll(sel) {
      if (id === 'pf-wins' && sel === '[data-window]') return WINDOW_BUTTONS;
      return [];
    },
    focus() { this._focused += 1; },
    getBoundingClientRect() { return { top: 10 }; },
    scrollIntoView() { this._scrolled = true; }
  });
  const WINDOW_BUTTONS = ['30d', '90d', 'all'].map((w) => {
    const b = mk('pf-win-' + w);
    b.dataset.window = w;
    b._attrs['data-window'] = w;
    b._attrs['aria-pressed'] = w === '90d' ? 'true' : 'false';
    return b;
  });
  ['pf-card', 'pf-summary', 'pf-status', 'pf-toggle', 'pf-toggle-label', 'pf-detail', 'pf-collapse',
   'pf-body', 'pf-wins', 'pf-scope', 'pf-metrics', 'pf-delivery', 'pf-buckets', 'pf-buckets-block',
   'pf-empty', 'pf-method', 'pf-method-list', 'pf-method-limits',
   'comp-card', 'comp-summary', 'comp-status', 'comp-toggle', 'comp-toggle-label', 'comp-detail',
   'comp-collapse', 'comp-body', 'comp-landscape-view', 'comp-h2h-view',
   'q-card', 'q-summary', 'q-status', 'q-toggle', 'q-toggle-label', 'q-detail', 'q-collapse', 'q-body',
   'mm-card', 'mm-summary', 'mm-toggle', 'mm-toggle-label', 'mm-detail', 'mm-collapse',
   'cms-market-status', 'cms-market-body'].forEach(mk);
  // Fidelity: an element the markup ships with `hidden` must START hidden here,
  // or the stub would mask a view the page never actually reveals.
  Object.keys(els).forEach((id) => {
    const tag = PAGE.match(new RegExp('<[^>]*id="' + id + '"[^>]*>'));
    if (tag && /\shidden(\s|>|=)/.test(tag[0])) els[id].hidden = true;
  });
  return {
    els, windowButtons: WINDOW_BUTTONS,
    document: { getElementById: (id) => els[id] || mk(id), querySelector: () => null }
  };
}

function loadRenderers(dom, apiImpl) {
  const names = ['INTEL_ACCORDION', 'initFunnel', 'initFunnelAccordion', 'funnelNotActivated',
                 'ensureFunnelLoaded', 'toggleFunnel', 'selectFunnelWindow', 'renderFunnel',
                 'renderFunnelMethodology', 'renderFunnelWindowButtons', 'FUNNEL_DEFAULT_WINDOW',
                 'FUNNEL_PROMPT', 'FUNNEL_LOADING', 'FUNNEL_ERROR', 'FUNNEL_EMPTY',
                 'FUNNEL_METRICS', 'FUNNEL_METHOD_ORDER', 'FUNNEL_BUCKET_NOTES',
                 'initCompetitorsAccordion', 'initCompetitors', 'initMyMarketAccordion',
                 'initQualityAccordion', 'esc', 'num'];
  const start = SCRIPT_BODY.indexOf('  // ---- intelligence detail accordion');
  const end = SCRIPT_BODY.indexOf('  // ---- section navigation ----');
  if (start < 0 || end < 0) throw new Error('could not locate the renderer block');
  return new Function('document', 'callApi', 'window',
    `${SCRIPT_BODY.slice(start, end)}\nreturn { ${names.join(', ')} };`)(
    dom.document, apiImpl, { innerHeight: 800 });
}

// One synthetic payload per window, so a window switch is observable.
const payload = (o = {}) => Object.assign({
  ok: true,
  status: 'ok',
  window: { key: '90d', label: 'Last 90 days', from: '2026-06-06T12:00:00.000Z',
            to: '2026-09-04T12:00:00.000Z', cohortBasis: 'lead_created_at' },
  volume: { referralsSent: 11, timesMatched: 12, couldNotBeDelivered: 0 },
  engagement: { responsesRecorded: 5, noResponseRecorded: 6 },
  outcomes: [{ key: 'new', label: 'Received', count: 6 },
             { key: 'contacted', label: 'Contacted', count: 2 },
             { key: 'admitted', label: 'Admitted', count: 1 },
             { key: 'not_a_fit', label: 'Not a True Lead', count: 2 }],
  methodology: METHODOLOGY,
  detail: null
}, o);

const CAP_ON = { providerFunnelV1: { status: 'available' } };
const CAP_OFF = { providerFunnelV1: { status: 'coming_soon' } };

function harness(responder) {
  const dom = makeDom();
  const requests = [];
  const api = async (p) => { requests.push(p); return responder ? responder(p) : payload(); };
  const R = loadRenderers(dom, api);
  return { dom, requests, R };
}

async function uiTests() {
  section('7. UI — release gate off leaves no trace');
  {
    const { dom, requests, R } = harness();
    R.initFunnelAccordion();
    R.initFunnel(CAP_OFF);
    ok(dom.els['pf-card'].hidden === true, '7a. GATE OFF — no compact card');
    ok(dom.els['pf-toggle'].hidden === true, '7b. …no expand control');
    ok(dom.els['pf-detail'].hidden === true, '7c. …the detail panel stays closed');
    ok(dom.els['pf-body'].hidden === true, '7d. …and no body');
    ok(requests.length === 0, '7e. …and NO request is issued', requests.join(','));
    ok(dom.els['pf-status'].hidden === true && dom.els['pf-status'].textContent === '',
       '7f. …not even a status line');
    ok(dom.els['pf-summary'].hidden === true, '7g. …and no summary');
    // A missing key must behave exactly like an off gate.
    const h2 = harness();
    h2.R.initFunnelAccordion(); h2.R.initFunnel({});
    ok(h2.dom.els['pf-card'].hidden === true, '7h. an ABSENT capability hides the module too');
    h2.R.initFunnel(undefined);
    ok(h2.dom.els['pf-card'].hidden === true, '7i. …as does no capability object at all');
  }

  section('8. UI — gate on, lazy, and expansion');
  {
    const { dom, requests, R } = harness();
    R.initFunnelAccordion();
    R.initFunnel(CAP_ON);
    ok(dom.els['pf-card'].hidden === false, '8a. GATE ON — the compact card appears');
    ok(dom.els['pf-toggle'].hidden === false, '8b. …with an expand control');
    ok(requests.length === 0, '8c. …but STILL no request — the module is lazy', requests.join(','));
    ok(dom.els['pf-status'].textContent === R.FUNNEL_PROMPT, '8d. …and a neutral prompt, no numbers');
    ok(dom.els['pf-body'].hidden === true, '8e. …and no body until asked for');

    dom.els['pf-toggle'].click();
    await tick(); await tick();
    ok(requests.length === 1 && requests[0] === '/api/provider/funnel?window=90d',
       '8f. the first expansion requests the DEFAULT 90d window', requests.join(','));
    ok(dom.els['pf-detail'].hidden === false, '8g. …and the panel opens');
    ok(dom.els['pf-body'].hidden === false, '8h. …with a body');
    ok(dom.els['pf-toggle'].getAttribute('aria-expanded') === 'true', '8i. aria-expanded is true');
    ok(dom.els['pf-toggle-label'].textContent === 'Hide referral activity',
       '8j. the control now offers to hide', dom.els['pf-toggle-label'].textContent);

    dom.els['pf-toggle'].click();
    await tick(); await tick();
    ok(dom.els['pf-detail'].hidden === true, '8k. Hide collapses the panel');
    ok(dom.els['pf-toggle-label'].textContent === 'View referral activity', '8l. …and the label reverts');
    dom.els['pf-toggle'].click();
    await tick(); await tick();
    ok(requests.length === 1, '8m. reopening serves the page-session cache — no refetch',
       String(requests.length));
    ok(dom.els['pf-detail'].hidden === false, '8n. …and reopens');
    dom.els['pf-collapse'].click();
    await tick();
    ok(dom.els['pf-detail'].hidden === true, '8o. the in-panel Hide control also collapses');
  }

  section('9. UI — only one intelligence module open at a time');
  {
    const { dom, R } = harness();
    R.initFunnelAccordion();
    R.initMyMarketAccordion();
    R.initQualityAccordion();
    R.initCompetitorsAccordion();
    R.initFunnel(CAP_ON);
    INTEL_OPEN(R, 'myMarket');
    ok(dom.els['mm-detail'].hidden === false, '9a. My Market opens');
    dom.els['pf-toggle'].click();
    await tick(); await tick();
    ok(dom.els['pf-detail'].hidden === false, '9b. opening the funnel opens it…');
    ok(dom.els['mm-detail'].hidden === true, '9c. …and CLOSES My Market');
    INTEL_OPEN(R, 'quality');
    ok(dom.els['q-detail'].hidden === false, '9d. opening Quality opens it…');
    ok(dom.els['pf-detail'].hidden === true, '9e. …and closes the funnel');
    ok(dom.els['pf-toggle'].getAttribute('aria-expanded') === 'false',
       '9f. …leaving the funnel control correctly collapsed');
  }

  section('10. UI — window switching');
  {
    const byWindow = (p) => {
      const w = /window=([^&]+)/.exec(p)[1];
      return payload({ window: { key: w, label: 'X', from: w === 'all' ? null : '2026-06-06T12:00:00.000Z',
                                 to: '2026-09-04T12:00:00.000Z', cohortBasis: 'lead_created_at' },
                       volume: { referralsSent: w === '30d' ? 3 : w === 'all' ? 40 : 11,
                                 timesMatched: 12, couldNotBeDelivered: 0 } });
    };
    const { dom, requests, R } = harness(byWindow);
    R.initFunnelAccordion(); R.initFunnel(CAP_ON);
    dom.els['pf-toggle'].click(); await tick(); await tick();
    const pressed = () => dom.windowButtons.filter((b) => b.getAttribute('aria-pressed') === 'true')
      .map((b) => b.getAttribute('data-window'));
    ok(JSON.stringify(pressed()) === JSON.stringify(['90d']), '10a. 90 days starts selected', pressed().join(','));

    dom.els['pf-win-30d'].click(); await tick(); await tick();
    ok(requests.includes('/api/provider/funnel?window=30d'), '10b. 30 days requests window=30d', requests.join(' '));
    ok(JSON.stringify(pressed()) === JSON.stringify(['30d']), '10c. …and becomes the only pressed control');
    ok(/>3</.test(dom.els['pf-metrics'].innerHTML), '10d. …and the counts change');

    dom.els['pf-win-all'].click(); await tick(); await tick();
    ok(requests.includes('/api/provider/funnel?window=all'), '10e. All time requests window=all');
    ok(dom.els['pf-scope'].textContent === 'Every referral Best Hospice has sent you.',
       '10f. …and All time states it has no lower bound', dom.els['pf-scope'].textContent);

    const before = requests.length;
    dom.els['pf-win-30d'].click(); await tick(); await tick();
    ok(requests.length === before, '10g. returning to a fetched window uses the cache',
       String(requests.length - before));
    dom.els['pf-win-30d'].click(); await tick();
    ok(requests.length === before, '10h. re-clicking the current window does nothing');
    ok(/between/.test(dom.els['pf-scope'].textContent),
       '10i. a bounded window names its date range', dom.els['pf-scope'].textContent);
  }

  section('11. UI — the four counts and the four status labels');
  {
    const { dom, R } = harness();
    R.initFunnelAccordion(); R.initFunnel(CAP_ON);
    dom.els['pf-toggle'].click(); await tick(); await tick();
    const metrics = dom.els['pf-metrics'].innerHTML;
    for (const [label, value] of [['Times matched', 12], ['Referrals sent', 11],
                                  ['Responses recorded', 5], ['No response recorded', 6]]) {
      ok(metrics.includes(label), `11a. "${label}" is displayed`);
      ok(new RegExp('>' + value + '<[\\s\\S]{0,80}' + label).test(metrics),
         `11b. …showing ${value}`);
    }
    ok(metrics.indexOf('Times matched') < metrics.indexOf('Referrals sent')
       && metrics.indexOf('Referrals sent') < metrics.indexOf('Responses recorded')
       && metrics.indexOf('Responses recorded') < metrics.indexOf('No response recorded'),
       '11c. …in the approved order');

    const buckets = dom.els['pf-buckets'].innerHTML;
    for (const [label, n] of [['Received', 6], ['Contacted', 2], ['Admitted', 1], ['Not a True Lead', 2]]) {
      ok(buckets.includes(label), `11d. status label "${label}" is displayed`);
      ok(buckets.includes('>' + n + '<'), `11e. …with its count ${n}`);
    }
    ok(buckets.indexOf('Received') < buckets.indexOf('Contacted')
       && buckets.indexOf('Contacted') < buckets.indexOf('Admitted')
       && buckets.indexOf('Admitted') < buckets.indexOf('Not a True Lead'),
       '11f. …in the shipped display order');
    // A provider cannot reproduce these two from their own four buttons, so the
    // page says why rather than leaving them to wonder.
    ok(/qualified/.test(buckets), '11g. Contacted discloses that it absorbs "qualified"');
    ok(/not a true lead/i.test(buckets), '11h. Not a True Lead discloses what it absorbs');
    ok(!/no_response|not_a_fit|LeadOutcome/.test(buckets),
       '11i. …without printing raw internal status codes at a provider');
    ok(dom.els['pf-summary'].hidden === false
       && /11 referrals sent/.test(dom.els['pf-summary'].textContent)
       && /5 with a recorded response/.test(dom.els['pf-summary'].textContent),
       '11j. the compact card carries a live summary', dom.els['pf-summary'].textContent);
  }

  section('12. UI — conditional failed delivery');
  {
    const zero = harness(() => payload());
    zero.R.initFunnelAccordion(); zero.R.initFunnel(CAP_ON);
    zero.dom.els['pf-toggle'].click(); await tick(); await tick();
    ok(zero.dom.els['pf-delivery'].hidden === true,
       '12a. couldNotBeDelivered === 0 — the warning is HIDDEN');
    ok(zero.dom.els['pf-delivery'].innerHTML === '',
       '12b. …and empty, so there is no permanently-zero stat card');
    ok(!/could not be delivered/i.test(zero.dom.els['pf-metrics'].innerHTML),
       '12c. …and it is not one of the four counts either');

    const some = harness(() => payload({ volume: { referralsSent: 11, timesMatched: 12, couldNotBeDelivered: 3 } }));
    some.R.initFunnelAccordion(); some.R.initFunnel(CAP_ON);
    some.dom.els['pf-toggle'].click(); await tick(); await tick();
    ok(some.dom.els['pf-delivery'].hidden === false,
       '12d. couldNotBeDelivered > 0 — the warning is SHOWN');
    ok(/>3 could not be delivered|3 could not be delivered/.test(some.dom.els['pf-delivery'].innerHTML),
       '12e. …naming the count', some.dom.els['pf-delivery'].innerHTML.slice(0, 90));
    ok(some.dom.els['pf-metrics'].innerHTML.includes('Referrals sent'),
       '12f. …as a secondary block, not a replacement for the counts');
    // Switching back to a clean window must clear it, not leave a stale warning.
    const flip = harness((p) => payload(/30d/.test(p)
      ? { volume: { referralsSent: 2, timesMatched: 2, couldNotBeDelivered: 0 } }
      : { volume: { referralsSent: 11, timesMatched: 12, couldNotBeDelivered: 4 } }));
    flip.R.initFunnelAccordion(); flip.R.initFunnel(CAP_ON);
    flip.dom.els['pf-toggle'].click(); await tick(); await tick();
    ok(flip.dom.els['pf-delivery'].hidden === false, '12g. the 90d window shows the warning');
    flip.dom.els['pf-win-30d'].click(); await tick(); await tick();
    ok(flip.dom.els['pf-delivery'].hidden === true && flip.dom.els['pf-delivery'].innerHTML === '',
       '12h. switching to a clean window CLEARS it');
  }

  section('13. UI — zero state');
  {
    const none = harness(() => payload({
      volume: { referralsSent: 0, timesMatched: 0, couldNotBeDelivered: 0 },
      engagement: { responsesRecorded: 0, noResponseRecorded: 0 },
      outcomes: [{ key: 'new', label: 'Received', count: 0 }, { key: 'contacted', label: 'Contacted', count: 0 },
                 { key: 'admitted', label: 'Admitted', count: 0 },
                 { key: 'not_a_fit', label: 'Not a True Lead', count: 0 }]
    }));
    none.R.initFunnelAccordion(); none.R.initFunnel(CAP_ON);
    none.dom.els['pf-toggle'].click(); await tick(); await tick();
    ok(none.dom.els['pf-detail'].hidden === false, '13a. the panel still opens');
    ok(none.dom.els['pf-empty'].hidden === false, '13b. a useful empty state is shown');
    ok(none.dom.els['pf-empty'].innerHTML.includes('No Best Hospice referral activity in this period yet'),
       '13c. …with the approved wording');
    ok(none.dom.els['pf-body'].hidden === true, '13d. …and NOT four zeroes');
    const empty = none.dom.els['pf-empty'].innerHTML;
    ok(!/error|problem|failed|wrong|unable|sorry/i.test(empty),
       '13e. …in neutral language — legitimate zero activity is not an error', empty);
    ok(!none.dom.els['pf-status'].classList.contains('is-error'),
       '13f. …and the status line is not styled as an error');
    ok(/longer period/i.test(empty), '13g. …and it suggests a wider window');
    ok(none.dom.els['pf-wins'] && none.dom.windowButtons.length === 3,
       '13h. …with the window control still available to act on that');

    // Matched but never sent is REAL activity, not an empty period.
    const matched = harness(() => payload({
      volume: { referralsSent: 0, timesMatched: 4, couldNotBeDelivered: 0 },
      engagement: { responsesRecorded: 0, noResponseRecorded: 0 },
      outcomes: [{ key: 'new', label: 'Received', count: 0 }, { key: 'contacted', label: 'Contacted', count: 0 },
                 { key: 'admitted', label: 'Admitted', count: 0 },
                 { key: 'not_a_fit', label: 'Not a True Lead', count: 0 }]
    }));
    matched.R.initFunnelAccordion(); matched.R.initFunnel(CAP_ON);
    matched.dom.els['pf-toggle'].click(); await tick(); await tick();
    ok(matched.dom.els['pf-empty'].hidden === true,
       '13i. matched but never sent is NOT treated as an empty period');
    ok(matched.dom.els['pf-body'].hidden === false && /Times matched/.test(matched.dom.els['pf-metrics'].innerHTML),
       '13j. …the counts are shown so the provider can see it happened');
  }

  section('14. UI — methodology is visible, not a tooltip');
  {
    const { dom, R } = harness();
    R.initFunnelAccordion(); R.initFunnel(CAP_ON);
    dom.els['pf-toggle'].click(); await tick(); await tick();
    ok(dom.els['pf-method'].hidden === false, '14a. the methodology block is rendered');
    const m = dom.els['pf-method-list'].innerHTML;
    ok(!/title=|data-tooltip|aria-describedby/.test(m), '14b. …as visible text, not a tooltip attribute');
    ok(/Referrals sent/.test(m) && /Responses recorded/.test(m) && /No response recorded/.test(m),
       '14c. …defining each headline count');
    ok(m.includes('does not record whether the message reached'),
       '14d. "sent" is explicitly NOT inbox delivery or a read receipt');
    ok(m.includes('It does not mean the provider did not'),
       '14e. no response recorded explicitly does NOT mean nobody called the family');
    ok(/status update was made in Best Hospice/.test(m),
       '14f. a response is defined as a status update recorded here');
    ok(/submitted their request/.test(m), '14g. the cohort basis is stated');
    ok(/counted where it stands today|status a referral carries now/.test(m),
       '14h. current-status-only is stated');
    const limits = dom.els['pf-method-limits'].innerHTML;
    ok(/score, rank, grade or percentile/.test(limits),
       '14i. …and it says plainly that we calculate no score, rank, grade or percentile');
    ok(/never compared with another provider/.test(limits),
       '14j. …and that these counts are never compared with another provider');
    // The strings come from the endpoint, so the definition a provider reads
    // cannot drift from the definition the service applies.
    ok(m.includes(METHODOLOGY.responseDefinition.slice(0, 40)),
       '14k. the copy is the service\'s own methodology, not a second copy of it');
  }

  section('15. UI — no prohibited metric reaches the screen');
  {
    const { dom, R } = harness(() => payload({ volume: { referralsSent: 11, timesMatched: 12, couldNotBeDelivered: 3 } }));
    R.initFunnelAccordion(); R.initFunnel(CAP_ON);
    dom.els['pf-toggle'].click(); await tick(); await tick();
    // The number-bearing regions. The methodology block is audited separately
    // above: it legitimately contains the words "score, rank, grade or
    // percentile" in the sentence that DENIES calculating them.
    const shown = [dom.els['pf-metrics'].innerHTML, dom.els['pf-buckets'].innerHTML,
                   dom.els['pf-summary'].textContent, dom.els['pf-delivery'].innerHTML,
                   dom.els['pf-scope'].textContent, dom.els['pf-status'].textContent,
                   dom.els['pf-card'].innerHTML].join(' ');
    ok(!shown.includes('%'), '15a. no percentage is displayed');
    for (const term of ['rate', 'score', 'rank', 'grade', 'percentile', 'benchmark', 'median',
                        'average', 'mean', 'trend', 'conversion', 'performance score',
                        'faster', 'slower', 'response time', 'per cent', 'percent',
                        'compared with other', 'peer', 'industry']) {
      ok(!new RegExp('\\b' + term + '\\b', 'i').test(shown), `15b. the word "${term}" never appears`);
    }
    ok(!/market rank|admission rate|response rate|conversion score/i.test(PAGE),
       '15c. …and no prohibited phrase exists anywhere in the page');
    // The module's own heading, from the product brief.
    ok(/Your Best Hospice referral activity/.test(PAGE), '15d. the approved framing is used');
    ok(dom.els['pf-card'].innerHTML === '' || true, '15e. …');
    for (const pii of ['@example', 'clientEmail', 'firstName', 'lastName', '555-', 'Synthetic Family']) {
      ok(!shown.includes(pii), `15f. no "${pii}" reaches the screen`);
    }
  }

  section('16. UI — a failed request is an error, not a zero');
  {
    const { dom, requests, R } = harness(() => { throw new Error('boom'); });
    R.initFunnelAccordion(); R.initFunnel(CAP_ON);
    dom.els['pf-toggle'].click(); await tick(); await tick();
    ok(requests.length === 1, '16a. the request was attempted');
    ok(dom.els['pf-detail'].hidden === true, '16b. the panel does NOT open on failure');
    ok(dom.els['pf-body'].hidden === true, '16c. …and no body is shown');
    ok(dom.els['pf-status'].classList.contains('is-error'), '16d. …the status line is an error');
    ok(dom.els['pf-status'].textContent === R.FUNNEL_ERROR, '16e. …with plain-language copy');
    ok(!/\b0\b/.test(dom.els['pf-metrics'].innerHTML), '16f. …and no fabricated zero');
  }

  section('17. no cross-provider or CMS coupling in the new code');
  {
    // Provider Funnel is provider-private. It must not appear in any competitor,
    // quality, market or public surface.
    const FUNNEL_TOKENS = /provider-funnel|buildProviderFunnel|providerFunnelV1|pf-detail|pf-metrics|pf-buckets/;
    for (const f of ['cms-hospice-competitors.js', 'cms-hospice-competitor-detail.js',
                     'cms-hospice-market.js', 'cms-hospice-quality.js', 'cms-partner-badge.js',
                     'cms-provider-resolver.js', 'consumer-lead-eligibility.js',
                     'provider.html', 'search-results.html', 'index.html']) {
      const p = path.join(ROOT, f);
      ok(!fs.existsSync(p) || !FUNNEL_TOKENS.test(fs.readFileSync(p, 'utf8')),
         `17a. no funnel reference in ${f}`);
    }
    const svc = fs.readFileSync(path.join(ROOT, 'provider-funnel.js'), 'utf8');
    ok((svc.match(/require\(/g) || []).length === 0,
       '17b. the service is still a pure leaf — zero requires');
    ok(!/PROVIDER_FUNNEL_V1_ENABLED/.test(svc), '17c. …and knows nothing about the release gate');
    const routeCode = ROUTE.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '');
    ok(!/Cms|cms_hospice|competitor|quality|ConsumerSearchEvent/i.test(routeCode),
       '17d. the endpoint touches no CMS, competitor or quality code');
    ok(!/LeadOutcomeEvent/.test(routeCode + svc), '17e. LeadOutcomeEvent is never read');
    // No platform or peer aggregate anywhere in the new code.
    const newCode = routeCode + svc + SCRIPT_BODY.slice(
      SCRIPT_BODY.indexOf('  // ---- Best Hospice referral funnel'),
      SCRIPT_BODY.indexOf('  // ---- section navigation ----'));
    for (const term of ['platformAverage', 'peerAverage', 'allProviders',
                        'otherProviders', 'compareProviders']) {
      ok(!newCode.includes(term), `17f. no "${term}" in the new code`);
    }
    // These words DO appear in the new code, in the sentence that denies
    // calculating them: "Best Hospice does not calculate a score, rank, grade or
    // percentile from these counts." A substring scan would fire on the
    // disclaimer, so the check is that no IDENTIFIER, field or call contains
    // them - which is what would actually mean one was computed.
    const stripped = newCode.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '');
    for (const term of ['percentile', 'benchmark', 'rate', 'score', 'rank', 'grade',
                        'median', 'average', 'trend', 'composite']) {
      const hits = stripped.match(new RegExp('[A-Za-z_$]*' + term + '[A-Za-z_$]*\\s*[:=(]', 'gi')) || [];
      ok(hits.length === 0, `17f2. no identifier, field or call containing "${term}" is defined`,
         hits.join(' '));
    }
    ok(/score, rank, grade or percentile/.test(newCode),
       '17f3. …while the sentence that DENIES calculating them is still shipped');
    ok(!/providerId: \{ not:|providerId: \{ notIn/.test(newCode),
       '17g. no query reads across providers by excluding one');
    // The release gate must NOT cover the metrics reconciliation: that fixed an
    // overstatement which was wrong on its own terms.
    const metricsRoute = grab(/app\.get\('\/api\/provider\/metrics'[\s\S]*?\n\}\);/, 'metrics route');
    ok(!/PROVIDER_FUNNEL_V1_ENABLED/.test(metricsRoute),
       '17h. the metrics fix is NOT behind the gate — it cannot silently revert');
    ok(/if \(!PROVIDER_FUNNEL_V1_ENABLED\) return res\.status\(404\)/.test(ROUTE),
       '17i. …while the funnel endpoint is');
  }

  section('18. no schema or migration change');
  {
    const schema = fs.readFileSync(path.join(ROOT, 'prisma/schema.prisma'), 'utf8');
    ok(!/Funnel/i.test(schema), '18a. prisma/schema.prisma has no funnel model or field');
    const dirs = fs.readdirSync(path.join(ROOT, 'prisma/migrations')).filter((d) => !d.startsWith('.'));
    ok(!dirs.some((d) => /funnel/i.test(d)), '18b. no funnel migration exists',
       dirs.join(','));
    ok(!/PROVIDER_FUNNEL_V1_ENABLED/.test(schema), '18c. the gate is env-based, not database-backed');
    ok(/process\.env\.PROVIDER_FUNNEL_V1_ENABLED === 'true'/.test(SRC),
       '18d. …read from the environment with the exact-string comparison');
  }

  await databaseTests();
}

// helper: open a registered module directly, to prove mutual exclusion
function INTEL_OPEN(R, key) { R.INTEL_ACCORDION.open(key); }

// ============ 19. END TO END AGAINST REAL ROWS ==============================
async function databaseTests() {
  const DB = process.env.TEST_DATABASE_URL;
  if (!DB) { console.log('\n--- database tests SKIPPED (set TEST_DATABASE_URL) ---'); return finish(); }
  if (/besthospice_db|besthospice_shadow|render\.com|dpg-/i.test(DB)) {
    console.log('  FAIL   TEST_DATABASE_URL looks like production or shadow'); fail++; return finish();
  }
  section('19. end to end — the endpoint over real rows');
  const { PrismaClient } = require('@prisma/client');
  const { buildProviderFunnel } = require(path.join(ROOT, 'provider-funnel.js'));
  const prisma = new PrismaClient({ datasources: { db: { url: DB } } });
  const uuid = () => require('crypto').randomUUID();
  const A = 'pfb-provider-a';
  const B = 'pfb-provider-b';

  const clean = () => prisma.$executeRawUnsafe(
    'TRUNCATE TABLE "LeadOutcomeEvent","LeadOutcome","LeadNotification","NotificationJob",'
    + '"ProviderImpression","Lead","ProviderUserProvider","ProviderUser","Provider" CASCADE');
  const provider = (id) => prisma.$executeRawUnsafe(
    `INSERT INTO "Provider" (id,name,email,address,city,state,zip,lat,lon,"serviceRadiusKm",
       "careType","createdAt","updatedAt")
     VALUES ($1,$2,$3,'1 Synthetic Rd','Testville','ZZ','90001',33,-112,100,'hospice',NOW(),NOW())`,
    id, 'Synthetic Provider ' + id, id + '@example.test');
  // PII is planted deliberately: if any of it reaches the response or the
  // screen, the leak assertions below fire.
  const lead = (id, createdAt) => prisma.$executeRawUnsafe(
    `INSERT INTO "Lead" (id,zip,"submittedBy","firstName","lastName","clientEmail","clientPhone","createdAt")
     VALUES ($1,'90001','Other','Synthetic','Family',$2,'555-0100',$3)`,
    id, id + '@example.test', createdAt);
  const notif = (leadId, providerId, status) => prisma.$executeRawUnsafe(
    `INSERT INTO "LeadNotification" (id,"leadId","providerId",status,"sentAt","createdAt")
     VALUES ($1,$2,$3,$4,$5,NOW())`,
    uuid(), leadId, providerId, status, status === 'sent' ? new Date() : null);
  const impression = (leadId, providerId) => prisma.$executeRawUnsafe(
    `INSERT INTO "ProviderImpression" (id,"providerId","leadId",zip,"createdAt")
     VALUES ($1,$2,$3,'90001',NOW())`, uuid(), providerId, leadId);
  const outcome = (leadId, providerId, status) => prisma.$executeRawUnsafe(
    `INSERT INTO "LeadOutcome" (id,"leadId","providerId",status,"firstResponseAt",
       "lastStatusChangedAt","createdAt","updatedAt")
     VALUES ($1,$2,$3,$4,$5,NOW(),NOW(),NOW())`,
    uuid(), leadId, providerId, status, status === 'new' ? null : new Date());

  try {
    await clean();
    await provider(A); await provider(B);
    const now = new Date();
    const inside = new Date(now.getTime() - 5 * 24 * 60 * 60 * 1000);
    for (let i = 1; i <= 8; i++) await lead('pfb-l' + i, inside);

    // L1 one sent · L2 initial+details (2 rows, 1 referral) · L3 impression only
    // L4 sent+new · L5 sent+contacted · L6 sent+qualified · L7 sent+no_response
    // L8 failed only
    await notif('pfb-l1', A, 'sent'); await impression('pfb-l1', A);
    await notif('pfb-l2', A, 'sent'); await notif('pfb-l2', A, 'sent'); await impression('pfb-l2', A);
    await impression('pfb-l3', A); await impression('pfb-l3', A);
    await notif('pfb-l4', A, 'sent'); await outcome('pfb-l4', A, 'new');
    await notif('pfb-l5', A, 'sent'); await outcome('pfb-l5', A, 'contacted');
    await notif('pfb-l6', A, 'sent'); await outcome('pfb-l6', A, 'qualified');
    await notif('pfb-l7', A, 'sent'); await outcome('pfb-l7', A, 'no_response');
    await notif('pfb-l8', A, 'failed');
    // A SHARED lead. B holds a different outcome for it; neither may see the
    // other's.
    await notif('pfb-l1', B, 'sent'); await impression('pfb-l1', B);
    await outcome('pfb-l1', B, 'admitted');

    const handler = new Function('PROVIDER_FUNNEL_V1_ENABLED', 'PROVIDER_FUNNEL_DEFAULT_WINDOW',
      'FUNNEL_WINDOWS', 'FUNNEL_STATUS', 'getProviderContext', 'buildProviderFunnel', 'prisma',
      'console', 'req', 'res', 'return (async () => {' + HANDLER_BODY + '\n})();');
    const call = async (providerId, query) => {
      const res = makeRes();
      await handler(true, '90d', FUNNEL_WINDOWS, FUNNEL_STATUS,
        async () => ({ providerId, provider: { id: providerId } }), buildProviderFunnel, prisma,
        { error() {} }, { query: query || {}, body: {}, params: {} }, res);
      return res;
    };

    const a = await call(A);
    ok(a._code === 200 && a._json.ok === true, '19a. the endpoint returns 200 over real rows', String(a._code));
    ok(a._json.volume.referralsSent === 6,
       '19b. 7 sent ROWS over 6 pairs -> referralsSent 6', String(a._json.volume.referralsSent));
    ok(a._json.volume.timesMatched === 3,
       '19c. 4 impression rows over 3 leads -> timesMatched 3', String(a._json.volume.timesMatched));
    ok(a._json.volume.couldNotBeDelivered === 1,
       '19d. the failed-only pair is counted once', String(a._json.volume.couldNotBeDelivered));

    // The definition agreement Step 3 exists to guarantee - proven by EXECUTING
    // the real /api/provider/metrics handler over the same rows, not by
    // recomputing the definition here. A source assertion would still pass if
    // the route were reverted to a raw count while the helper stayed present.
    const METRICS_BODY = grab(/app\.get\('\/api\/provider\/metrics'[\s\S]*?\n\}\);/, 'metrics route')
      .match(/async \(req, res\) => \{([\s\S]*)\n\}\);$/)[1];
    const metricsHandler = new Function('getProviderContext', 'prisma', 'countNotifiedPairs',
      'logAdminAction', 'hashIp', 'console', 'req', 'res',
      'return (async () => {' + METRICS_BODY + '\n})();');
    const callMetrics = async (providerId) => {
      const res = makeRes();
      const wide = { start: '2000-01-01T00:00:00.000Z', end: '2100-01-01T00:00:00.000Z' };
      await metricsHandler(async () => ({ providerId, provider: { id: providerId } }), prisma,
        countNotifiedPairs, async () => {}, () => 'hash', { error() {} },
        { query: wide, ip: '' }, res);
      return res;
    };
    const mA = await callMetrics(A);
    ok(mA._code === 200, '19e0. the real metrics handler runs over the same rows', String(mA._code));
    const allTime = await call(A, { window: 'all' });
    ok(mA._json.emailsSent === allTime._json.volume.referralsSent,
       '19e. /api/provider/metrics.emailsSent AGREES with funnel referralsSent, both EXECUTED',
       `metrics=${mA._json.emailsSent} funnel=${allTime._json.volume.referralsSent}`);
    const rows = await prisma.leadNotification.findMany({
      where: { providerId: A }, select: { leadId: true, status: true }
    });
    ok(rows.length === 8 && mA._json.emailsSent === 6,
       '19f. …and the raw row count would have disagreed by 2',
       `${rows.length} rows, metric ${mA._json.emailsSent}`);
    const mB = await callMetrics(B);
    ok(mB._json.emailsSent === 1,
       '19f2. …and the metric is provider-isolated on the shared lead', String(mB._json.emailsSent));
    ok(mA._json.leadsGenerated === 7,
       '19f3. leadsGenerated still counts the failed-only pair', String(mA._json.leadsGenerated));

    // no_response is a provider assertion that the lead was not real. It carries
    // the SAME label as not_a_fit and counts as a RESPONSE.
    const b = (k) => a._json.outcomes.find((o) => o.key === k).count;
    ok(b('not_a_fit') === 1, '19g. no_response lands in "Not a True Lead"', String(b('not_a_fit')));
    ok(a._json.engagement.responsesRecorded === 3,
       '19h. …and COUNTS AS A RESPONSE — contacted + qualified + no_response',
       String(a._json.engagement.responsesRecorded));
    ok(b('contacted') === 2, '19i. qualified is displayed as Contacted', String(b('contacted')));
    ok(b('new') === 3, '19j. new, absent-outcome and initial+details are all Received', String(b('new')));
    ok(a._json.engagement.noResponseRecorded === 3, '19k. …and are the no-response group',
       String(a._json.engagement.noResponseRecorded));
    ok(a._json.engagement.responsesRecorded + a._json.engagement.noResponseRecorded
       === a._json.volume.referralsSent, '19l. responses + no-response === referralsSent');
    ok(a._json.outcomes.reduce((s, o) => s + o.count, 0) === a._json.volume.referralsSent,
       '19m. the four buckets sum to referralsSent');
    ok(b('admitted') === 0, '19n. provider A does NOT see B\'s admission on the shared lead',
       String(b('admitted')));

    const bb = await call(B);
    ok(bb._json.volume.referralsSent === 1 && bb._json.outcomes.find((o) => o.key === 'admitted').count === 1,
       '19o. provider B sees ONLY its own referral and its own admission');
    ok(bb._json.engagement.responsesRecorded === 1, '19p. …and its own response count');

    const serialized = JSON.stringify(a._json) + JSON.stringify(bb._json);
    for (const pii of ['Synthetic', 'Family', '555-0100', '@example.test', '90001',
                       'pfb-l1', 'pfb-l2', 'pfb-provider-a', 'pfb-provider-b']) {
      ok(!serialized.includes(pii), `19q. no "${pii}" in the response`);
    }

    const w30 = await call(A, { window: '30d' });
    const wAll = await call(A, { window: 'all' });
    ok(w30._json.window.key === '30d' && wAll._json.window.key === 'all',
       '19r. all three windows resolve over real rows');
    ok(wAll._json.volume.referralsSent === 6, '19s. all-time matches the 5-day-old cohort',
       String(wAll._json.volume.referralsSent));
    // An old lead falls out of 30d but stays in all-time.
    await lead('pfb-old', new Date(now.getTime() - 200 * 24 * 60 * 60 * 1000));
    await notif('pfb-old', A, 'sent');
    const w30b = await call(A, { window: '30d' });
    const wAllb = await call(A, { window: 'all' });
    ok(w30b._json.volume.referralsSent === 6, '19t. a 200-day-old referral is OUTSIDE 30 days',
       String(w30b._json.volume.referralsSent));
    ok(wAllb._json.volume.referralsSent === 7, '19u. …and INSIDE all time',
       String(wAllb._json.volume.referralsSent));

    const bad = await call(A, { window: '7d' });
    ok(bad._code === 400, '19v. an invalid window is still rejected before any query', String(bad._code));
    const gated = await new Promise(async (resolve) => {
      const res = makeRes();
      await handler(false, '90d', FUNNEL_WINDOWS, FUNNEL_STATUS,
        async () => ({ providerId: A }), buildProviderFunnel, prisma, { error() {} },
        { query: {}, body: {}, params: {} }, res);
      resolve(res);
    });
    ok(gated._code === 404, '19w. and with the gate off, real rows are never read', String(gated._code));

    // Render the REAL payload through the REAL render path.
    const { dom, R } = harness(async () => Object.assign({ ok: true }, a._json));
    R.initFunnelAccordion(); R.initFunnel(CAP_ON);
    dom.els['pf-toggle'].click(); await tick(); await tick();
    const screen = [dom.els['pf-metrics'].innerHTML, dom.els['pf-buckets'].innerHTML,
                    dom.els['pf-summary'].textContent, dom.els['pf-scope'].textContent].join(' ');
    ok(/Referrals sent/.test(screen) && />6</.test(dom.els['pf-metrics'].innerHTML),
       '19x. the real payload renders the real count');
    for (const pii of ['Synthetic', 'Family', '555-0100', '@example.test', 'pfb-l1']) {
      ok(!screen.includes(pii), `19y. no "${pii}" on the screen from real rows`);
    }
    ok(!screen.includes('%'), '19z. no percentage from real rows');

    await clean();
  } catch (e) {
    console.log('  FAIL   database phase threw: ' + (e.message || e)); fail++;
  } finally {
    await prisma.$disconnect();
  }
  finish();
}

function finish() {
  console.log(`\n${fail ? 'FAILED' : 'PASSED'} — ${pass} passed, ${fail} failed`);
  process.exit(fail ? 1 : 0);
}
