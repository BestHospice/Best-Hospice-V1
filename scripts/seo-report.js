#!/usr/bin/env node
/**
 * Reproducible read-only SEO report.
 *
 * Replaces the ad-hoc analysis used in Sprints 1-2 so future windows are
 * measured identically. Writes to a dated directory and never overwrites an
 * existing one, so reports/baseline-2026-08-25/ stays intact.
 *
 * Usage:
 *   node scripts/seo-report.js                    last 90 days
 *   node scripts/seo-report.js --days 28
 *   node scripts/seo-report.js --start 2026-01-01 --end 2026-03-31
 *   node scripts/seo-report.js --label post-migration
 *
 * Emits:
 *   gsc-pages.csv, gsc-queries.csv, gsc-page-query.csv
 *   ctr-by-position.csv, rank-buckets.csv
 *   cannibalization.csv, serp-opportunities.csv
 *   homepage-brand-queries.csv, medicare-guide-queries.csv
 *   summary.md
 */
require('dotenv').config({ path: require('os').homedir() + '/.crawford_keys' });
const https = require('https');
const fs = require('fs');
const path = require('path');

const SITE = 'sc-domain:besthospice.com';
const BASE = 'https://www.besthospice.com';
const HOME = BASE + '/';
const MEDICARE = BASE + '/guides/medicare-hospice-coverage';

// ---- page purpose. Search visibility alone does not make a page valuable, so
// ---- utility/legal/auth pages are excluded from growth opportunity scoring.
const EXCLUDE_FROM_OPPORTUNITY = [
  /\/(terms|privacy|cookie-policy|refund-policy)(\.html)?$/i,
  /provider-dashboard/i, /\/admin/i, /login|signin|sign-in/i,
  /\/account/i, /\/unsubscribe/i, /provider-billing/i
];
const isExcluded = (url) => EXCLUDE_FROM_OPPORTUNITY.some((rx) => rx.test(url));

function pageType(url) {
  const p = url.replace(BASE, '') || '/';
  if (p === '/') return 'homepage';
  if (/^\/(hospice-care|palliative-care|home-care)\/[a-z]{2}$/.test(p)) return 'state';
  if (/^\/(hospice-care|palliative-care|home-care)\/[a-z-]+-[a-z]{2}$/.test(p)) return 'city';
  if (/^\/(hospice-care|palliative-care|home-care)$/.test(p)) return 'service-hub';
  if (/^\/guides\//.test(p)) return 'guide';
  if (/^\/provider\//.test(p)) return 'provider';
  if (/^\/(states|cities)\//.test(p)) return 'legacy-static';
  if (isExcluded(url)) return 'utility';
  return 'other';
}

const args = process.argv.slice(2);
const arg = (name, dflt) => { const i = args.indexOf('--' + name); return i === -1 ? dflt : args[i + 1]; };
const ago = (n) => { const d = new Date(); d.setDate(d.getDate() - n); return d.toISOString().slice(0, 10); };
const days = Number(arg('days', 90));
const END = arg('end', ago(1));
const START = arg('start', ago(days));
const LABEL = arg('label', `report-${END}-${days}d`);

const OUT = path.join(__dirname, '..', 'reports', LABEL);
if (fs.existsSync(OUT)) {
  console.error(`Refusing to overwrite existing report directory: ${OUT}\nPass a different --label.`);
  process.exit(1);
}

function token() {
  const b = `client_id=${process.env.GSC_CLIENT_ID}&client_secret=${process.env.GSC_CLIENT_SECRET}` +
            `&refresh_token=${process.env.GSC_REFRESH_TOKEN}&grant_type=refresh_token`;
  return new Promise((res, rej) => {
    const r = https.request({ hostname: 'oauth2.googleapis.com', path: '/token', method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Content-Length': Buffer.byteLength(b) } },
      (x) => { let d = ''; x.on('data', (c) => { d += c; }); x.on('end', () => {
        try { const j = JSON.parse(d); j.access_token ? res(j.access_token) : rej(new Error(d.slice(0, 200))); }
        catch (e) { rej(new Error(d.slice(0, 200))); } }); });
    r.on('error', rej); r.write(b); r.end();
  });
}
function query(tok, body) {
  const b = JSON.stringify(body);
  return new Promise((res, rej) => {
    const r = https.request({ hostname: 'searchconsole.googleapis.com',
      path: `/webmasters/v3/sites/${encodeURIComponent(SITE)}/searchAnalytics/query`, method: 'POST',
      headers: { Authorization: `Bearer ${tok}`, 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(b) } },
      (x) => { let d = ''; x.on('data', (c) => { d += c; }); x.on('end', () => {
        try { const j = JSON.parse(d); j.error ? rej(new Error(j.error.message)) : res(j); }
        catch (e) { rej(new Error(d.slice(0, 200))); } }); });
    r.on('error', rej); r.write(b); r.end();
  });
}
const cell = (v) => { const s = String(v == null ? '' : v); return /[",\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s; };
function write(name, header, rows) {
  fs.writeFileSync(path.join(OUT, name), [header.join(','), ...rows.map((r) => r.map(cell).join(','))].join('\n') + '\n');
  console.log(`  ${name} (${rows.length} rows)`);
}

(async () => {
  if (!process.env.GSC_REFRESH_TOKEN) { console.error('GSC_REFRESH_TOKEN missing'); process.exit(1); }
  fs.mkdirSync(OUT, { recursive: true });
  const tok = await token();
  console.log(`Search Console ${SITE}\n  window ${START} .. ${END}\n  output reports/${LABEL}\n`);

  const pull = (dims, filters) => query(tok, {
    startDate: START, endDate: END, dimensions: dims, rowLimit: 25000, dataState: 'all',
    ...(filters ? { dimensionFilterGroups: [{ filters }] } : {})
  });

  const [pages, queries, pq, brand, medicare] = await Promise.all([
    pull(['page']), pull(['query']), pull(['page', 'query']),
    pull(['query'], [{ dimension: 'page', operator: 'equals', expression: HOME }]),
    pull(['query'], [{ dimension: 'page', operator: 'equals', expression: MEDICARE }])
  ]);

  // The apex/HTTP homepage variants are tracked separately by decision, not
  // fixed at the edge. See reports/seo-technical-notes.md. If the HTTP URL
  // stops ranking independently, no action is needed.
  const HOMEPAGE_VARIANTS = ['http://besthospice.com/', 'https://besthospice.com/', HOME];
  const variantRows = HOMEPAGE_VARIANTS.map((u) => {
    const r = (pages.rows || []).find((x) => x.keys[0] === u);
    return [u, r ? r.impressions : 0, r ? r.clicks : 0, r ? r.position.toFixed(1) : '', r ? 'yes' : 'no'];
  });

  const P = pages.rows || [];
  write('gsc-pages.csv', ['url', 'page_type', 'excluded_from_opportunity', 'clicks', 'impressions', 'ctr_pct', 'position'],
    P.map((r) => [r.keys[0], pageType(r.keys[0]), isExcluded(r.keys[0]) ? 'yes' : 'no', r.clicks, r.impressions, (r.ctr * 100).toFixed(2), r.position.toFixed(1)]));
  write('gsc-queries.csv', ['query', 'clicks', 'impressions', 'ctr_pct', 'position'],
    (queries.rows || []).map((r) => [r.keys[0], r.clicks, r.impressions, (r.ctr * 100).toFixed(2), r.position.toFixed(1)]));
  write('gsc-page-query.csv', ['url', 'query', 'clicks', 'impressions', 'position'],
    (pq.rows || []).map((r) => [r.keys[0], r.keys[1], r.clicks, r.impressions, r.position.toFixed(1)]));
  write('homepage-brand-queries.csv', ['query', 'is_brand', 'clicks', 'impressions', 'position'],
    (brand.rows || []).map((r) => [r.keys[0], /best\s*hospice|besthospice/i.test(r.keys[0]) ? 'yes' : 'no', r.clicks, r.impressions, r.position.toFixed(1)]));
  write('homepage-variants.csv', ['url', 'impressions', 'clicks', 'position', 'present_in_index'], variantRows);
  write('medicare-guide-queries.csv', ['query', 'clicks', 'impressions', 'position'],
    (medicare.rows || []).map((r) => [r.keys[0], r.clicks, r.impressions, r.position.toFixed(1)]));

  const BUCKETS = [['1-3', 1, 4], ['4-5', 4, 6], ['6-10', 6, 11], ['11-15', 11, 16],
                   ['16-20', 16, 21], ['21-30', 21, 31], ['31-50', 31, 51], ['51+', 51, 1e9]];
  write('ctr-by-position.csv', ['bucket', 'urls', 'impressions', 'clicks', 'ctr_pct'],
    BUCKETS.map(([l, lo, hi]) => {
      const sel = P.filter((r) => r.position >= lo && r.position < hi);
      const imp = sel.reduce((a, r) => a + r.impressions, 0);
      const clk = sel.reduce((a, r) => a + r.clicks, 0);
      return [l, sel.length, imp, clk, imp ? (clk / imp * 100).toFixed(3) : '0'];
    }));
  write('rank-buckets.csv', ['bucket', 'urls'],
    BUCKETS.map(([l, lo, hi]) => [l, P.filter((r) => r.position >= lo && r.position < hi).length]));

  const byQuery = new Map();
  for (const r of (pq.rows || [])) {
    if (!byQuery.has(r.keys[1])) byQuery.set(r.keys[1], []);
    byQuery.get(r.keys[1]).push(r);
  }
  const cann = [...byQuery.entries()].filter(([, v]) => v.length > 1)
    .sort((a, b) => b[1].reduce((s, x) => s + x.impressions, 0) - a[1].reduce((s, x) => s + x.impressions, 0));
  write('cannibalization.csv', ['query', 'competing_urls', 'total_impressions', 'best_position', 'urls'],
    cann.map(([q, v]) => [q, v.length, v.reduce((s, x) => s + x.impressions, 0),
      Math.min(...v.map((x) => x.position)).toFixed(1),
      v.sort((a, b) => b.impressions - a.impressions).map((x) => `${x.keys[0].replace(BASE, '')} (p${x.position.toFixed(1)}, ${x.impressions})`).join(' | ')]));

  const topQ = new Map();
  for (const [q, v] of byQuery) for (const r of v) {
    const k = r.keys[0];
    if (!topQ.has(k)) topQ.set(k, []);
    topQ.get(k).push({ q, i: r.impressions, p: r.position });
  }
  const tier = (pos, imp) => (pos >= 4 && pos <= 10 && imp >= 30) ? 'A'
    : (pos >= 11 && pos <= 20 && imp >= 30) ? 'B'
    : (pos >= 21 && pos <= 30 && imp >= 50) ? 'C'
    : (pos > 30 && imp >= 200) ? 'D' : '';
  const opps = P.filter((r) => !isExcluded(r.keys[0]) && pageType(r.keys[0]) !== 'legacy-static')
    .map((r) => ({ r, t: tier(r.position, r.impressions) })).filter((x) => x.t)
    .map(({ r, t }) => {
      const w = t === 'A' ? 1 : t === 'B' ? 0.75 : t === 'C' ? 0.5 : 0.3;
      const qs = (topQ.get(r.keys[0]) || []).sort((a, b) => b.i - a.i).slice(0, 3);
      return [t, r.keys[0].replace(BASE, ''), pageType(r.keys[0]), r.impressions, r.clicks,
        r.position.toFixed(1), (r.ctr * 100).toFixed(2),
        qs.map((x) => `${x.q} (${x.i} imp, p${x.p.toFixed(1)})`).join(' | '),
        (r.impressions * w / Math.max(r.position, 1) * 100).toFixed(1)];
    }).sort((a, b) => Number(b[8]) - Number(a[8]));
  write('serp-opportunities.csv',
    ['tier', 'url', 'page_type', 'impressions', 'clicks', 'position', 'ctr_pct', 'top_queries', 'score'], opps);

  const imp = P.reduce((a, r) => a + r.impressions, 0);
  const clk = P.reduce((a, r) => a + r.clicks, 0);
  fs.writeFileSync(path.join(OUT, 'summary.md'),
`# SEO report — ${LABEL}

Window: **${START} → ${END}** (${days} days). Source: Search Console \`${SITE}\`.
Generated by \`scripts/seo-report.js\`, read-only.

| metric | value |
|---|---|
| URLs with impressions | ${P.length} |
| impressions | ${imp} |
| clicks | ${clk} |
| CTR | ${imp ? (clk / imp * 100).toFixed(2) : '0'}% |
| URLs with >=1 click | ${P.filter((r) => r.clicks > 0).length} |
| URLs with impressions, 0 clicks | ${P.filter((r) => r.impressions > 0 && r.clicks === 0).length} |
| cannibalised queries (>1 of our URLs) | ${cann.length} |
| opportunity pages (utility excluded) | ${opps.length} |

## Rank distribution
${BUCKETS.map(([l, lo, hi]) => `- ${l}: ${P.filter((r) => r.position >= lo && r.position < hi).length} URLs`).join('\n')}

Utility, legal, auth and legacy-static URLs are excluded from opportunity
scoring: search visibility alone does not make a page strategically valuable.
`);
  console.log(`  summary.md\n\nDone. ${P.length} URLs, ${imp} impressions, ${clk} clicks.`);
})().catch((e) => { console.error('FAILED:', e.message); process.exit(1); });
