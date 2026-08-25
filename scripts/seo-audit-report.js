#!/usr/bin/env node
/**
 * Sprint 1 audit report builder. Read-only.
 *
 * Crawls the live sitemap URLs plus static SEO pages, joins Search Console
 * data from scripts/seo-gsc-audit.js, measures content similarity, and emits:
 *   reports/seo-audit-before.csv
 *   reports/location-content-similarity.csv
 *
 * Recommendations are advisory. Nothing is deleted, redirected or noindexed.
 */
const fs = require('fs');
const path = require('path');
const https = require('https');

const BASE = 'https://www.besthospice.com';
const OUT = path.join(__dirname, '..', 'reports');
const CONCURRENCY = 6;

const csvOut = (v) => { const s = String(v == null ? '' : v); return /[",\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s; };

function readCsv(name) {
  const p = path.join(OUT, name);
  if (!fs.existsSync(p)) return [];
  const lines = fs.readFileSync(p, 'utf8').trim().split('\n');
  const head = lines.shift().split(',');
  return lines.map((l) => {
    const cells = l.match(/("([^"]|"")*"|[^,]*)/g).filter((_, i) => i % 2 === 0);
    const o = {};
    head.forEach((h, i) => { o[h] = (cells[i] || '').replace(/^"|"$/g, '').replace(/""/g, '"'); });
    return o;
  });
}

function get(url, depth = 0) {
  return new Promise((resolve) => {
    if (depth > 4) return resolve({ status: 0, html: '', finalUrl: url });
    const req = https.get(url, { headers: { 'User-Agent': 'BestHospice-SEOAudit/1.0' }, timeout: 25000 }, (res) => {
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        res.resume();
        return resolve(get(new URL(res.headers.location, url).toString(), depth + 1)
          .then((r) => ({ ...r, status: r.status, redirectedFrom: url })));
      }
      let d = '';
      res.on('data', (c) => { d += c; });
      res.on('end', () => resolve({ status: res.statusCode, html: d, finalUrl: url }));
    });
    req.on('error', () => resolve({ status: 0, html: '', finalUrl: url }));
    req.on('timeout', () => { req.destroy(); resolve({ status: 0, html: '', finalUrl: url }); });
  });
}

const pick = (html, rx) => { const m = rx.exec(html); return m ? m[1].trim() : ''; };

function analyse(url, html, status) {
  const noScript = html.replace(/<script\b(?![^>]*ld\+json)[\s\S]*?<\/script>/gi, ' ').replace(/<style[\s\S]*?<\/style>/gi, ' ');
  const text = noScript.replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim();
  const title = pick(html, /<title>([\s\S]*?)<\/title>/i);
  const desc = pick(html, /<meta[^>]+name=["']description["'][^>]+content=["']([^"']*)["']/i);
  const h1 = pick(noScript, /<h1[^>]*>([\s\S]*?)<\/h1>/i).replace(/<[^>]+>/g, '').trim();
  const canonical = pick(html, /<link[^>]+rel=["']canonical["'][^>]+href=["']([^"']*)["']/i);
  const ldTypes = [...html.matchAll(/"@type"\s*:\s*"([^"]+)"/g)].map((m) => m[1]);
  const leaks = [...new Set((noScript.match(/\{[a-zA-Z][a-zA-Z0-9_]{2,24}\}/g) || []))]
    .filter((t) => t !== '{search_term_string}');
  const phones = [...new Set(text.match(/\(\d{3}\)\s?\d{3}-\d{4}/g) || [])];
  const internal = [...new Set([...html.matchAll(/href=["'](\/[^"'#?]*)/g)].map((m) => m[1]))];

  let type = 'other';
  const p = url.replace(BASE, '');
  if (p === '/' ) type = 'homepage';
  else if (/^\/(hospice-care|palliative-care|home-care)\/[a-z]{2}$/.test(p)) type = 'state-dynamic';
  else if (/^\/(hospice-care|palliative-care|home-care)\/[a-z-]+-[a-z]{2}$/.test(p)) type = 'city-dynamic';
  else if (/^\/(hospice-care|palliative-care|home-care)$/.test(p)) type = 'service-hub';
  else if (/^\/states\//.test(p)) type = 'state-static';
  else if (/^\/cities\//.test(p)) type = 'city-static';
  else if (/^\/guides\//.test(p)) type = 'guide';
  else if (/^\/provider/.test(p)) type = 'provider';

  const svc = (p.match(/^\/(hospice-care|palliative-care|home-care)\b/) || [])[1] || '';
  const st = (p.match(/^\/(?:hospice-care|palliative-care|home-care)\/(?:[a-z-]+-)?([a-z]{2})$/) || [])[1] || '';
  const city = (p.match(/^\/(?:hospice-care|palliative-care|home-care)\/([a-z-]+)-[a-z]{2}$/) || [])[1] || '';

  return { url, path: p, type, service: svc, state: st, city, status,
    title, titleLen: title.length, desc, descLen: desc.length, h1,
    words: text.split(' ').filter(Boolean).length, canonical,
    ld: [...new Set(ldTypes)].join('|'), leaks: leaks.join('|'),
    providerCount: phones.length, internalOut: internal.length, text };
}

async function crawl(urls) {
  const out = [];
  let i = 0;
  await Promise.all(Array.from({ length: CONCURRENCY }, async () => {
    while (i < urls.length) {
      const idx = i++;
      const u = urls[idx];
      const r = await get(u);
      out[idx] = analyse(u, r.html, r.status);
      if (out.length && idx % 25 === 0) process.stderr.write(`  crawled ${idx + 1}/${urls.length}\r`);
    }
  }));
  return out;
}

function similarity(a, b) {
  const norm = (t) => t.toLowerCase().replace(/[^a-z ]+/g, ' ').split(/\s+/).filter((w) => w.length > 3);
  const A = new Set(norm(a)), B = new Set(norm(b));
  if (!A.size || !B.size) return 0;
  let inter = 0;
  for (const w of A) if (B.has(w)) inter += 1;
  return inter / new Set([...A, ...B]).size;
}

function recommend(p, gsc, maxSim) {
  const imp = gsc ? Number(gsc.impressions_90d || 0) : 0;
  const clk = gsc ? Number(gsc.clicks_90d || 0) : 0;
  const pos = gsc ? Number(gsc.position_90d || 0) : 0;
  const reasons = [];
  if (p.status !== 200) return ['DELETE', `HTTP ${p.status}`];
  if (p.leaks) reasons.push(`leaks ${p.leaks}`);

  const isLocation = /^(state|city)-/.test(p.type);
  if (isLocation) {
    if (p.providerCount === 0) reasons.push('no provider listings');
    if (maxSim >= 0.9) reasons.push(`${Math.round(maxSim * 100)}% similar to another location page`);
    if (imp === 0) reasons.push('no impressions in 90d');
  }
  if (clk > 0) return ['KEEP', `${clk} clicks in 90d${reasons.length ? '; ' + reasons.join('; ') : ''}`];
  if (imp > 0 && pos > 0 && pos <= 30) return ['IMPROVE', `position ${pos} on ${imp} impressions — real signal${reasons.length ? '; ' + reasons.join('; ') : ''}`];
  if (isLocation && maxSim >= 0.9 && p.providerCount === 0 && imp < 20) {
    return ['CONSOLIDATE', reasons.join('; ') || 'near-duplicate with no providers'];
  }
  if (isLocation && p.providerCount === 0 && imp === 0) return ['NOINDEX', reasons.join('; ') || 'no providers, no impressions'];
  if (imp > 0) return ['IMPROVE', `position ${pos} on ${imp} impressions${reasons.length ? '; ' + reasons.join('; ') : ''}`];
  return ['NOINDEX', reasons.join('; ') || 'no search signal'];
}

(async () => {
  fs.mkdirSync(OUT, { recursive: true });
  const gscPages = new Map(readCsv('gsc-pages.csv').map((r) => [r.url.replace(/\/$/, '') || r.url, r]));

  // URL set: live sitemaps + static SEO files
  const sitemapUrls = new Set();
  for (const sm of ['sitemap-pages.xml', 'sitemap-locations.xml', 'sitemap-providers.xml']) {
    const r = await get(`${BASE}/${sm}`);
    [...r.html.matchAll(/<loc>(.*?)<\/loc>/g)].forEach((m) => sitemapUrls.add(m[1]));
  }
  for (const dir of ['states', 'cities']) {
    const d = path.join(__dirname, '..', dir);
    if (fs.existsSync(d)) fs.readdirSync(d).filter((f) => f.endsWith('.html'))
      .forEach((f) => sitemapUrls.add(`${BASE}/${dir}/${f.replace(/\.html$/, '')}`));
  }
  const urls = [...sitemapUrls];
  console.log(`Crawling ${urls.length} URLs...`);
  const pages = await crawl(urls);
  process.stderr.write('\n');

  // similarity among location pages
  const locs = pages.filter((p) => /^(state|city)-/.test(p.type) && p.status === 200);
  const simRows = [];
  const maxSim = new Map();
  for (let a = 0; a < locs.length; a += 1) {
    for (let b = a + 1; b < locs.length; b += 1) {
      const s = similarity(locs[a].text, locs[b].text);
      if (s >= 0.8) {
        simRows.push([locs[a].path, locs[b].path, `${locs[a].type} / ${locs[b].type}`, s.toFixed(3),
          s >= 0.95 ? 'substantially identical' : s >= 0.9 ? 'near-identical' : 'heavily overlapping',
          `${locs[a].providerCount}/${locs[b].providerCount} provider listings`,
          s >= 0.95 ? 'CONSOLIDATE or differentiate with real local data' : 'differentiate with real local data']);
      }
      if (s > (maxSim.get(locs[a].path) || 0)) maxSim.set(locs[a].path, s);
      if (s > (maxSim.get(locs[b].path) || 0)) maxSim.set(locs[b].path, s);
    }
  }
  simRows.sort((x, y) => Number(y[3]) - Number(x[3]));
  fs.writeFileSync(path.join(OUT, 'location-content-similarity.csv'),
    ['url_a,url_b,page_types,similarity,duplicate_sections,provider_listings,recommendation',
      ...simRows.map((r) => r.map(csvOut).join(','))].join('\n') + '\n');
  console.log(`  wrote reports/location-content-similarity.csv (${simRows.length} pairs >=0.80)`);

  // titles / descriptions / h1 duplication
  const count = (arr) => arr.reduce((m, v) => m.set(v, (m.get(v) || 0) + 1), new Map());
  const tC = count(pages.map((p) => p.title)), dC = count(pages.map((p) => p.desc)), hC = count(pages.map((p) => p.h1));

  const header = ['url','page_type','service','state','city','http_status','indexable','canonical','sitemap',
    'title','title_len','meta_description','description_len','h1','word_count','provider_listings',
    'internal_outbound','structured_data','duplicate_title','duplicate_description','duplicate_h1',
    'max_similarity','template_leak','impressions_90d','clicks_90d','ctr_90d_pct','position_90d',
    'recommendation','rationale'];
  const rows = pages.map((p) => {
    const g = gscPages.get(p.url.replace(/\/$/, '')) || gscPages.get(p.url);
    const ms = maxSim.get(p.path) || 0;
    const [rec, why] = recommend(p, g, ms);
    return [p.url, p.type, p.service, p.state, p.city, p.status, p.status === 200 ? 'yes' : 'no',
      p.canonical, sitemapUrls.has(p.url) ? 'yes' : 'no',
      p.title, p.titleLen, p.desc, p.descLen, p.h1, p.words, p.providerCount, p.internalOut, p.ld,
      tC.get(p.title) > 1 ? 'yes' : 'no', dC.get(p.desc) > 1 ? 'yes' : 'no', hC.get(p.h1) > 1 ? 'yes' : 'no',
      ms ? ms.toFixed(3) : '', p.leaks || '',
      g ? g.impressions_90d : 0, g ? g.clicks_90d : 0, g ? g.ctr_90d_pct : '', g ? g.position_90d : '',
      rec, why];
  });
  fs.writeFileSync(path.join(OUT, 'seo-audit-before.csv'),
    [header.join(','), ...rows.map((r) => r.map(csvOut).join(','))].join('\n') + '\n');
  console.log(`  wrote reports/seo-audit-before.csv (${rows.length} rows)`);

  const recCount = count(rows.map((r) => r[27]));
  console.log('\nrecommendations');
  [...recCount.entries()].sort((a, b) => b[1] - a[1]).forEach(([k, v]) => console.log(`  ${String(k).padEnd(12)} ${v}`));
  console.log('\nby page type');
  [...count(pages.map((p) => p.type)).entries()].sort((a, b) => b[1] - a[1]).forEach(([k, v]) => console.log(`  ${String(k).padEnd(16)} ${v}`));
  const leaking = pages.filter((p) => p.leaks);
  console.log(`\ntemplate leaks: ${leaking.length} pages`);
  console.log(`non-200: ${pages.filter((p) => p.status !== 200).length}`);
  console.log(`location pages with zero provider listings: ${locs.filter((p) => p.providerCount === 0).length} of ${locs.length}`);
  console.log(`duplicate titles: ${[...tC.values()].filter((v) => v > 1).length} groups`);
  console.log(`missing canonical: ${pages.filter((p) => p.status === 200 && !p.canonical).length}`);
  console.log('');
})().catch((e) => { console.error('FAILED:', e.message); process.exit(1); });
