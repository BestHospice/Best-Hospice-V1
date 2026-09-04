#!/usr/bin/env node
/**
 * Guards the Market Intelligence shell.
 *
 * Two things this exists to catch:
 *   1. a module card referencing a capability the server never returns, which
 *      would render as an undefined state
 *   2. fabricated metrics leaking into the shell - the one thing the brief is
 *      most explicit about, and the easiest to do by accident when filling in
 *      a card that looks empty
 */
const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const SRC = fs.readFileSync(path.join(ROOT, 'server.js'), 'utf8');
const PAGE = fs.readFileSync(path.join(ROOT, 'provider-intelligence.html'), 'utf8');

let fail = 0;
const ok = (cond, msg) => { console.log(`  ${cond ? 'ok  ' : 'FAIL'} ${msg}`); if (!cond) fail++; };

// ---- capability model -----------------------------------------------------
const grab = (rx, label) => {
  const m = SRC.match(rx);
  if (!m) { console.log(`  FAIL could not find ${label} in server.js`); fail++; return ''; }
  return m[0];
};
const capsSrc = [
  grab(/const INTELLIGENCE_MODULES = \[[\s\S]*?\n\];/, 'INTELLIGENCE_MODULES'),
  grab(/const CMS_QUALITY_PROVIDER_TYPES = new Set\([^)]*\);/, 'CMS_QUALITY_PROVIDER_TYPES'),
  grab(/const KNOWN_INTELLIGENCE_TYPES = \{[\s\S]*?\n\};/, 'KNOWN_INTELLIGENCE_TYPES'),
  grab(/const TYPE_LABELS = \{[^}]*\};/, 'TYPE_LABELS'),
  grab(/const CMS_QUALITY_INTELLIGENCE_ENABLED = [^\n]*/, 'quality release gate'),
  grab(/const CMS_COMPETITOR_INTELLIGENCE_ENABLED = [^\n]*/, 'competitor release gate'),
  grab(/function providerIntelligenceCapabilities\(provider\) \{[\s\S]*?\n\}/, 'capability fn')
].join('\n');
// `process` is injected so the REAL gate expression is evaluated against a
// controlled environment. Empty env = gate absent = the production default.
const { providerIntelligenceCapabilities: caps, INTELLIGENCE_MODULES: MODS } =
  new Function('process', `${capsSrc}\nreturn { providerIntelligenceCapabilities, INTELLIGENCE_MODULES };`)({ env: {} });

console.log('capability model:');
const VALID = new Set(['available', 'coming_soon', 'not_applicable']);
for (const type of ['hospice', 'palliative', 'home', 'assisted_living', '', null]) {
  const c = caps({ careType: type });
  const missing = MODS.filter((m) => !c[m]);
  const bad = MODS.filter((m) => c[m] && !VALID.has(c[m].status));
  ok(!missing.length && !bad.length,
    `every module has a valid status for careType=${JSON.stringify(type)}` +
    (missing.length ? ` (missing: ${missing})` : '') + (bad.length ? ` (bad status: ${bad})` : ''));
}

// An unmodelled provider type must not inherit hospice's datasets. This is the
// bug the first draft had: normalizeCareType() falls back to 'hospice', which
// would have told an assisted-living provider that Medicare publishes hospice
// quality data about them.
for (const type of ['assisted_living', 'adult_day_care', '', null, undefined]) {
  const c = caps({ careType: type });
  ok(c.cmsQuality.status === 'not_applicable',
    `unmodelled type ${JSON.stringify(type)} gets no CMS quality`);
}
// Quality Intelligence V1 ships behind CMS_QUALITY_INTELLIGENCE_ENABLED, which
// defaults OFF. With the gate absent the capability is byte-identical to what it
// was before the feature existed. The gate-ON behaviour is covered in
// scripts/test-provider-quality-ui.js.
ok(caps({ careType: 'hospice' }).cmsQuality.status === 'coming_soon',
  'hospice gets CMS quality as coming_soon while the release gate is off');
ok(caps({ careType: 'home' }).cmsQuality.status === 'not_applicable', 'home care gets no CMS quality');
ok(caps({ careType: 'hospice' }).bestHospiceLeadAnalytics.status === 'available',
  'our own lead analytics are available now');

// ---- page wiring ----------------------------------------------------------
console.log('\nshell wiring:');
const sectionsFromJs = [...PAGE.matchAll(/'([A-Za-z ]+)':\s*\[/g)]
  .map((m) => m[1]).filter((n) => /^[A-Z]/.test(n));
const panelAttrs = [...PAGE.matchAll(/data-section="([^"]+)"/g)].map((m) => m[1]);
ok(panelAttrs.length === 6, `six section panels in the markup (found ${panelAttrs.length})`);
ok(JSON.stringify(sectionsFromJs) === JSON.stringify(panelAttrs),
  `MODULES keys match the panels in DOM order`);

const usedCaps = [...PAGE.matchAll(/cap:\s*'([a-zA-Z]+)'/g)].map((m) => m[1]);
const unknown = [...new Set(usedCaps)].filter((c) => !MODS.includes(c));
ok(!unknown.length, `every card references a real capability${unknown.length ? ` (unknown: ${unknown})` : ''}`);

const gridIds = [...PAGE.matchAll(/id="(mi-[a-z]+-grid)"/g)].map((m) => m[1]);
const mappedIds = [...PAGE.matchAll(/'(mi-[a-z]+-grid)'/g)].map((m) => m[1]);
ok(gridIds.every((id) => mappedIds.includes(id)), 'every grid element has a section mapped to it');

// ---- no fabricated data ---------------------------------------------------
// Only the shell's own copy is checked, not the CSS or the script plumbing.
console.log('\nno fabricated provider data:');
const bodyText = PAGE
  .replace(/<style[\s\S]*?<\/style>/g, '')
  .replace(/<script[\s\S]*?<\/script>/g, '')
  .replace(/<[^>]+>/g, ' ');
const cardCopy = [...PAGE.matchAll(/(?:title|body):\s*'([^']*)'/g)].map((m) => m[1]).join(' ');
const surface = `${bodyText} ${cardCopy}`;
const FABRICATED = [
  [/#\d+\s+of\s+\d+/i, 'a market ranking like "#8 of 37"'],
  [/\b\d+(\.\d+)?\s*stars?\b/i, 'a star rating'],
  [/\b\d{1,3}%\s*(recommend|conversion|of families)/i, 'a percentage claim'],
  [/\btop\s+\d{1,3}%/i, 'a percentile claim'],
  [/\b\d+\s+(inquiries|admissions|competitors)\b/i, 'a count of inquiries, admissions or competitors'],
  [/\$\s?\d[\d,]*/, 'a dollar figure']
];
FABRICATED.forEach(([rx, what]) => {
  const m = surface.match(rx);
  ok(!m, `no ${what}${m ? ` — found "${m[0].trim()}"` : ''}`);
});
ok(/name="robots" content="noindex/.test(PAGE), 'the page is noindex');
ok(/included with your Best Hospice provider subscription/i.test(PAGE),
  'states that intelligence is included in the subscription');
ok(/provider-dashboard-home\.html/.test(PAGE) && /aria-current="page"/.test(PAGE),
  'platform switch links back to Operations and marks the current area');

console.log(fail ? `\nFAILED (${fail})` : '\nPASSED');
process.exit(fail ? 1 : 0);
