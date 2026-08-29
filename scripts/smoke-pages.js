#!/usr/bin/env node
/**
 * Post-deploy smoke test: fetch one URL of every page type and assert it
 * returns 200 with the content that type is supposed to have.
 *
 * This exists because `node --check` validates syntax and nothing else. A
 * `const` used above its own declaration inside a render function parses
 * cleanly and throws only when the function runs, which took every city page
 * to a 500 in production while every local check passed.
 *
 *   node scripts/smoke-pages.js                     against production
 *   node scripts/smoke-pages.js http://localhost:3000
 */
const BASE = (process.argv[2] || 'https://www.besthospice.com').replace(/\/$/, '');

// [path, expected status, a string the response must contain]
const CASES = [
  ['/',                                      200, '<title>'],
  ['/search.html',                           200, 'search-form'],
  ['/search-results.html',                   200, 'optional-details-card'],
  // location pages: city and state, with providers and without, all three services
  ['/hospice-care/tucson-az',                200, 'Hospice Care in Tucson'],
  ['/hospice-care/salem-or',                 200, 'Hospice Care in Salem'],
  ['/hospice-care/mesa-az',                  200, 'Hospice Care in Mesa'],
  ['/hospice-care/ut',                       200, 'Hospice Care in Utah'],
  ['/hospice-care/az',                       200, 'Hospice Care in Arizona'],
  ['/home-care/az',                          200, 'Home Care in Arizona'],
  ['/home-care/mesa-az',                     200, 'Home Care in Mesa'],
  ['/palliative-care/az',                    200, 'Palliative Care in Arizona'],
  ['/palliative-care/mesa-az',               200, 'Palliative Care in Mesa'],
  // service hubs
  ['/hospice-care',                          200, 'Hospice Care'],
  ['/home-care',                             200, 'Home Care'],
  // guides: explicitly routed, catch-all routed, and the .html redirect
  ['/guides/medicare-hospice-coverage',      200, 'Medicare'],
  ['/guides/hospice-care-phoenix-arizona',   200, 'Phoenix'],
  ['/guides/medicare-hospice-coverage.html', 301, null],
  ['/guides/',                               200, '<title>'],
  // CMS enrichment must render where enabled and nowhere else
  ['/hospice-care/tucson-az',                200, 'The hospice market in Tucson'],
  ['/hospice-care/scottsdale-az',            200, '<title>'],
  // sitemaps and robots
  ['/sitemap.xml',                           200, '<urlset'],
  ['/sitemap-locations.xml',                 200, '<urlset'],
  ['/sitemap-pages.xml',                     200, '<urlset'],
  ['/robots.txt',                            200, 'Sitemap:'],
  ['/llms.txt',                              200, 'Best Hospice'],
  // provider-facing
  ['/provider.html',                         200, 'Partner'],
  ['/provider-billing.html',                 200, 'Partner'],
  ['/discharge-planners.html',               200, 'Partner listing']
];

// Things that must NOT appear anywhere, checked on the pages we fetch.
const FORBIDDEN = [
  ['⭐', 'star tier badge'],
  ['v-badge', 'unconditional Verified badge']
];

const get = (url) => new Promise((resolve) => {
  const lib = url.startsWith('https') ? require('https') : require('http');
  lib.get(url, { headers: { 'User-Agent': 'BestHospice-smoke/1.0' } }, (res) => {
    const chunks = [];
    res.on('data', (c) => chunks.push(c));
    res.on('end', () => resolve({ status: res.statusCode, body: Buffer.concat(chunks).toString('utf8') }));
  }).on('error', (e) => resolve({ status: 0, body: String(e.message) }));
});

(async () => {
  let fail = 0;
  console.log(`smoke test against ${BASE}\n`);
  for (const [p, wantStatus, mustContain] of CASES) {
    const r = await get(BASE + p);
    const statusOk = r.status === wantStatus;
    const bodyOk = !mustContain || r.body.includes(mustContain);
    const forbidden = r.status === 200
      ? FORBIDDEN.filter(([s]) => r.body.includes(s)).map(([, l]) => l)
      : [];
    const ok = statusOk && bodyOk && !forbidden.length;
    if (!ok) fail++;
    let why = '';
    if (!statusOk) why = ` got ${r.status}, want ${wantStatus}`;
    else if (!bodyOk) why = ` missing "${mustContain}"`;
    else if (forbidden.length) why = ` contains ${forbidden.join(', ')}`;
    console.log(`  ${ok ? 'ok  ' : 'FAIL'} ${p}${why}`);
  }
  console.log(fail ? `\nFAILED (${fail} of ${CASES.length})` : `\nPASSED (${CASES.length} checks)`);
  process.exit(fail ? 1 : 0);
})();
