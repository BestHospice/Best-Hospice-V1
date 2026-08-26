#!/usr/bin/env node
/**
 * Verifies that service pages only ever list providers of the matching care
 * type, and predicts the provider count for every service/location page from
 * the live inventory so the deploy can be validated against a fixed table.
 *
 * Pure-function test: it extracts the care-type helpers out of server.js source
 * rather than booting the app, which needs a database.
 *
 *   node scripts/test-service-routing.js              (uses cached inventory)
 *   node scripts/test-service-routing.js --predict    (also prints the table)
 */
const fs = require('fs');
const path = require('path');

const SRC = fs.readFileSync(path.join(__dirname, '..', 'server.js'), 'utf8');
let fail = 0;
const ok = (cond, msg) => { console.log(`  ${cond ? 'ok  ' : 'FAIL'} ${msg}`); if (!cond) fail++; };

// ---- extract the pure helpers from server.js ------------------------------
function extract(re, label) {
  const m = SRC.match(re);
  if (!m) { console.log(`  FAIL could not locate ${label} in server.js`); fail++; return ''; }
  return m[0];
}
const src = [
  extract(/const normalizeCareType = \(value\) => \{[\s\S]*?\n\};/, 'normalizeCareType'),
  extract(/const SERVICE_KEY_BY_CARE_TYPE = \{[\s\S]*?\n\};/, 'SERVICE_KEY_BY_CARE_TYPE'),
  extract(/const serviceKeyForCareType = [^\n]*;/, 'serviceKeyForCareType')
].join('\n');
const { normalizeCareType, serviceKeyForCareType } =
  new Function(`${src}\nreturn { normalizeCareType, serviceKeyForCareType };`)();

console.log('care-type helpers:');
ok(normalizeCareType('hospice-care') === 'hospice', "normalizeCareType('hospice-care') -> hospice");
ok(normalizeCareType('home-care') === 'home', "normalizeCareType('home-care') -> home");
ok(normalizeCareType('palliative-care') === 'palliative', "normalizeCareType('palliative-care') -> palliative");
ok(normalizeCareType('home') === 'home', "stored short form 'home' survives");
ok(serviceKeyForCareType('home') === 'home-care', "serviceKeyForCareType('home') -> home-care");
ok(serviceKeyForCareType('palliative') === 'palliative-care', "serviceKeyForCareType('palliative') -> palliative-care");
ok(serviceKeyForCareType('hospice') === 'hospice-care', "serviceKeyForCareType('hospice') -> hospice-care");
for (const k of ['hospice', 'palliative', 'home']) {
  ok(normalizeCareType(serviceKeyForCareType(k)) === k, `round-trip ${k} -> ${serviceKeyForCareType(k)} -> ${k}`);
}

// ---- the defects this test exists to prevent regressing -------------------
console.log('\nregression guards in server.js:');
ok(/async function providersByLocation\(city, state, careType\)/.test(SRC),
  'providersByLocation takes a careType argument');
ok(/providersByLocation\(slugCity, stateCode, normalizeCareType\(service\)\)/.test(SRC),
  'city route passes the requested service through as careType');
ok(/where: \{ state: \{ equals: state, mode: 'insensitive' \}, careType: normalizeCareType\(service\) \}/.test(SRC),
  'state route filters by careType');
ok(!/careType === 'home-care'/.test(SRC),
  "no comparison of stored careType against the '-care' suffixed form");
ok(!/\$\{CANONICAL_DOMAIN\}\/\$\{careType\}\//.test(SRC),
  'provider page builds its city URL from a service key, not a raw careType');

// ---- sitemap / noindex consistency --------------------------------------
// The defect: home-care location URLs were submitted in two sitemaps while
// every one of them rendered <meta robots="noindex">. Both facts must come
// from the same predicate so they cannot drift apart again.
console.log('\nsitemap / noindex consistency:');
ok(/const INDEXABLE_LOCATION_SERVICES = new Set/.test(SRC),
  'a single INDEXABLE_LOCATION_SERVICES set exists');
ok(!/noindex: serviceKey !== /.test(SRC),
  'no renderer hardcodes its own indexability comparison');
ok((SRC.match(/noindex: !serviceLocationIndexable\(serviceKey\)/g) || []).length === 2,
  'both location renderers (city, state) derive noindex from the predicate');
ok((SRC.match(/if \(!serviceLocationIndexable\(serviceKey\)\) continue;/g) || []).length === 2,
  'both sitemap builders skip services whose location pages are noindex');
{
  const set = SRC.match(/const INDEXABLE_LOCATION_SERVICES = new Set\(\[([^\]]*)\]\)/);
  const keys = set ? set[1].split(',').map((x) => x.trim().replace(/['"]/g, '')).filter(Boolean) : [];
  ok(keys.length === 1 && keys[0] === 'hospice-care',
    `only hospice-care location pages are indexable (found: ${keys.join(', ') || 'none'})`);
}

// ---- predicted outcome per page ------------------------------------------
const invPath = path.join(__dirname, '..', 'reports', 'cms-raw', 'bh-providers.json');
if (!fs.existsSync(invPath)) {
  console.log('\n(no cached inventory at reports/cms-raw/bh-providers.json; skipping prediction)');
} else {
  const providers = JSON.parse(fs.readFileSync(invPath, 'utf8')).providers;
  const slug = (s) => String(s || '').toLowerCase().trim().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');
  const pages = new Map();
  const bump = (url) => pages.set(url, (pages.get(url) || 0) + 1);
  const places = new Set();
  for (const p of providers) {
    const st = (p.state || '').toLowerCase();
    if (!st) continue;
    const key = serviceKeyForCareType(p.careType);
    bump(`/${key}/${st}`);
    places.add(st);
    if (p.city) { bump(`/${key}/${slug(p.city)}-${st}`); places.add(`${slug(p.city)}-${st}`); }
  }
  // Every place x every service: what will each page show?
  let zeroed = 0, kept = 0;
  const rows = [];
  for (const place of [...places].sort()) {
    for (const key of ['hospice-care', 'palliative-care', 'home-care']) {
      const url = `/${key}/${place}`;
      const after = pages.get(url) || 0;
      const before = providers.filter((p) => {
        const st = (p.state || '').toLowerCase();
        return place === st || place === `${slug(p.city)}-${st}`;
      }).length;
      if (before && !after) zeroed++;
      if (after) kept++;
      if (before !== after) rows.push({ url, before, after });
    }
  }
  console.log(`\npredicted page outcomes from ${providers.length} providers:`);
  console.log(`  pages that will list providers:            ${kept}`);
  console.log(`  pages dropping to zero providers:          ${zeroed}`);
  console.log(`  pages whose provider count changes at all: ${rows.length}`);
  if (process.argv.includes('--predict')) {
    console.log('\n  url                                        before  after');
    rows.sort((a, b) => a.url.localeCompare(b.url))
      .forEach((r) => console.log(`  ${r.url.padEnd(42)} ${String(r.before).padStart(6)} ${String(r.after).padStart(6)}`));
  }
}

console.log(fail ? `\nFAILED (${fail})` : '\nPASSED');
process.exit(fail ? 1 : 0);
