#!/usr/bin/env node
/**
 * Read-only Search Console pull for the SEO audit.
 * Scope used is webmasters.readonly. Nothing is written to Search Console.
 *
 * Writes:
 *   reports/gsc-pages.csv       page-level performance
 *   reports/gsc-queries.csv     query-level performance
 *   reports/gsc-page-query.csv  page x query, for cannibalisation analysis
 */
require('dotenv').config({ path: require('os').homedir() + '/.crawford_keys' });
const https = require('https');
const fs = require('fs');
const path = require('path');

const SITE = 'sc-domain:besthospice.com';
const OUT = path.join(__dirname, '..', 'reports');

function token() {
  const b = `client_id=${process.env.GSC_CLIENT_ID}&client_secret=${process.env.GSC_CLIENT_SECRET}` +
            `&refresh_token=${process.env.GSC_REFRESH_TOKEN}&grant_type=refresh_token`;
  return new Promise((resolve, reject) => {
    const r = https.request({ hostname: 'oauth2.googleapis.com', path: '/token', method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Content-Length': Buffer.byteLength(b) } },
      (res) => { let d = ''; res.on('data', c => d += c); res.on('end', () => {
        try { const j = JSON.parse(d); j.access_token ? resolve(j.access_token) : reject(new Error(d.slice(0, 300))); }
        catch (e) { reject(new Error(d.slice(0, 300))); } }); });
    r.on('error', reject); r.write(b); r.end();
  });
}

function query(tok, body) {
  const b = JSON.stringify(body);
  return new Promise((resolve, reject) => {
    const r = https.request({ hostname: 'searchconsole.googleapis.com',
      path: `/webmasters/v3/sites/${encodeURIComponent(SITE)}/searchAnalytics/query`, method: 'POST',
      headers: { Authorization: `Bearer ${tok}`, 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(b) } },
      (res) => { let d = ''; res.on('data', c => d += c); res.on('end', () => {
        try { resolve(JSON.parse(d)); } catch (e) { reject(new Error(d.slice(0, 300))); } }); });
    r.on('error', reject); r.write(b); r.end();
  });
}

const ago = (n) => { const d = new Date(); d.setDate(d.getDate() - n); return d.toISOString().slice(0, 10); };
const csv = (v) => { const s = String(v == null ? '' : v); return /[",\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s; };
const write = (name, header, rows) => {
  const p = path.join(OUT, name);
  fs.writeFileSync(p, [header.join(','), ...rows.map(r => r.map(csv).join(','))].join('\n') + '\n');
  console.log(`  wrote ${path.relative(process.cwd(), p)} (${rows.length} rows)`);
};

(async () => {
  if (!process.env.GSC_REFRESH_TOKEN) { console.error('GSC_REFRESH_TOKEN missing'); process.exit(1); }
  const tok = await token();
  const start90 = ago(90), start250 = ago(250), end = ago(1);
  fs.mkdirSync(OUT, { recursive: true });

  const pull = (dims, startDate, rowLimit = 25000) =>
    query(tok, { startDate, endDate: end, dimensions: dims, rowLimit, dataState: 'all' });

  console.log(`Search Console: ${SITE}`);
  console.log(`  90-day window  ${start90} .. ${end}`);
  console.log(`  long window    ${start250} .. ${end}\n`);

  const [p90, p250, q90, pq90] = await Promise.all([
    pull(['page'], start90),
    pull(['page'], start250),
    pull(['query'], start90),
    pull(['page', 'query'], start90)
  ]);
  for (const [name, r] of [['pages90', p90], ['pages250', p250], ['queries90', q90], ['pageQuery90', pq90]]) {
    if (r.error) { console.error(`  API error on ${name}: ${r.error.message}`); process.exit(1); }
  }

  const long = new Map((p250.rows || []).map(r => [r.keys[0], r]));
  const pageRows = (p90.rows || []).map(r => {
    const l = long.get(r.keys[0]);
    return [r.keys[0], r.clicks, r.impressions, (r.ctr * 100).toFixed(2), r.position.toFixed(1),
            l ? l.clicks : 0, l ? l.impressions : 0, l ? l.position.toFixed(1) : ''];
  });
  write('gsc-pages.csv',
    ['url', 'clicks_90d', 'impressions_90d', 'ctr_90d_pct', 'position_90d', 'clicks_250d', 'impressions_250d', 'position_250d'],
    pageRows);

  write('gsc-queries.csv', ['query', 'clicks_90d', 'impressions_90d', 'ctr_90d_pct', 'position_90d'],
    (q90.rows || []).map(r => [r.keys[0], r.clicks, r.impressions, (r.ctr * 100).toFixed(2), r.position.toFixed(1)]));

  write('gsc-page-query.csv', ['url', 'query', 'clicks_90d', 'impressions_90d', 'position_90d'],
    (pq90.rows || []).map(r => [r.keys[0], r.keys[1], r.clicks, r.impressions, r.position.toFixed(1)]));

  // ---- summary ----
  const rows = p90.rows || [];
  const tot = (f) => rows.reduce((a, r) => a + r[f], 0);
  const bucket = (lo, hi) => rows.filter(r => r.position >= lo && r.position < hi).length;
  console.log('\n90-day totals');
  console.log(`  URLs with impressions : ${rows.length}`);
  console.log(`  impressions           : ${tot('impressions')}`);
  console.log(`  clicks                : ${tot('clicks')}`);
  console.log(`  URLs with >=1 click   : ${rows.filter(r => r.clicks > 0).length}`);
  console.log(`  URLs impressions,0 clk: ${rows.filter(r => r.impressions > 0 && r.clicks === 0).length}`);
  console.log('\nposition buckets (URLs, 90d avg)');
  console.log(`  1-3    : ${bucket(1, 4)}`);
  console.log(`  4-10   : ${bucket(4, 11)}`);
  console.log(`  11-20  : ${bucket(11, 21)}`);
  console.log(`  21-50  : ${bucket(21, 51)}`);
  console.log(`  51+    : ${rows.filter(r => r.position >= 51).length}`);

  // cannibalisation: one query, several of our URLs
  const byQuery = new Map();
  for (const r of (pq90.rows || [])) {
    const q = r.keys[1];
    if (!byQuery.has(q)) byQuery.set(q, []);
    byQuery.get(q).push({ url: r.keys[0], impressions: r.impressions, clicks: r.clicks, position: r.position });
  }
  const clusters = [...byQuery.entries()].filter(([, v]) => v.length > 1)
    .sort((a, b) => b[1].reduce((s, x) => s + x.impressions, 0) - a[1].reduce((s, x) => s + x.impressions, 0));
  console.log(`\ncannibalisation: ${clusters.length} queries with more than one of our URLs`);
  for (const [q, urls] of clusters.slice(0, 10)) {
    console.log(`  "${q}" — ${urls.length} URLs`);
    urls.sort((a, b) => b.impressions - a.impressions).slice(0, 4).forEach(u =>
      console.log(`      p${u.position.toFixed(1)} imp ${u.impressions} clk ${u.clicks}  ${u.url.replace('https://www.besthospice.com', '')}`));
  }
  console.log('');
})().catch(e => { console.error('FAILED:', e.message); process.exit(1); });
