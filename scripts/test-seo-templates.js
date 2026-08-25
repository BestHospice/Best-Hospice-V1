#!/usr/bin/env node
/**
 * SEO template leak test.
 *
 * Why this exists: serviceConfig fields can contain the same placeholder more
 * than once. String.replace with a string pattern only substitutes the first
 * occurrence, so {stateName} and {cityState} reached production on every
 * hospice-care location page. This test fails if that class of bug returns.
 *
 * Two modes:
 *   node scripts/test-seo-templates.js
 *       Static check. No database or network. Verifies every serviceConfig
 *       placeholder is rendered through fillTemplate, and that fillTemplate
 *       replaces all occurrences.
 *
 *   node scripts/test-seo-templates.js --live https://www.besthospice.com
 *       Fetches representative routes and inspects rendered HTML: body,
 *       <title>, meta description, OpenGraph, canonical, JSON-LD, breadcrumbs
 *       and headings.
 */

const fs = require('fs');
const path = require('path');
const https = require('https');
const http = require('http');

const SERVER = path.join(__dirname, '..', 'server.js');
const PLACEHOLDER = /\{(stateName|cityState|city|state)\}/g;
// Any template syntax that must never appear in rendered SEO output.
// schema.org SearchAction legitimately contains {search_term_string} in its
// target template, so it must not be reported as a leak.
const ALLOWED_TOKENS = new Set(['{search_term_string}']);
const LEAK_PATTERNS = [
  { name: '{var}', rx: /\{[a-zA-Z][a-zA-Z0-9_]{2,24}\}/g },
  { name: '${var}', rx: /\$\{[a-zA-Z][a-zA-Z0-9_.]{2,30}\}/g },
  { name: '{{var}}', rx: /\{\{\s*[a-zA-Z][a-zA-Z0-9_.]{2,30}\s*\}\}/g },
  { name: '[VAR]', rx: /\[[A-Z][A-Z_]{2,20}\]/g }
];

const failures = [];
const fail = (msg) => failures.push(msg);
const ok = (msg) => console.log(`  ok   ${msg}`);

// ---------------------------------------------------------------- static mode

function staticCheck() {
  const src = fs.readFileSync(SERVER, 'utf8');

  if (!/function fillTemplate\(/.test(src)) {
    fail('fillTemplate() is missing from server.js');
    return;
  }
  ok('fillTemplate() is present');

  // The global flag is the actual fix. Without it only the first occurrence
  // is substituted, which is the original defect.
  const fn = src.slice(src.indexOf('function fillTemplate('));
  const body = fn.slice(0, fn.indexOf('\n}\n') + 3);
  if (!/\/g|\/gi/.test(body)) {
    fail('fillTemplate() does not use a global regex, so repeated placeholders will leak');
  } else {
    ok('fillTemplate() substitutes every occurrence');
  }

  // No render site may still use single-occurrence string replace.
  const single = src.match(/\.replace\('\{(stateName|cityState|city|state)\}'/g) || [];
  if (single.length) {
    fail(`${single.length} render site(s) still use single-occurrence .replace('{...}')`);
  } else {
    ok("no single-occurrence .replace('{...}') remains");
  }

  // Every serviceConfig field carrying a placeholder must be rendered through
  // fillTemplate somewhere.
  const cfgStart = src.indexOf('const serviceConfig = {');
  let depth = 0;
  let i = cfgStart;
  for (; i < src.length; i += 1) {
    if (src[i] === '{') depth += 1;
    else if (src[i] === '}') { depth -= 1; if (depth === 0) break; }
  }
  const cfg = src.slice(cfgStart, i + 1);
  const fieldsWithPlaceholders = new Set();
  for (const m of cfg.matchAll(/^\s{4}(\w+):\s*([\s\S]*?)(?=^\s{4}\w+:|\n\s{2}\},)/gm)) {
    if (PLACEHOLDER.test(m[2])) fieldsWithPlaceholders.add(m[1]);
    PLACEHOLDER.lastIndex = 0;
  }
  if (!fieldsWithPlaceholders.size) {
    ok('no serviceConfig field contains placeholders');
  }
  for (const field of fieldsWithPlaceholders) {
    const rendered = new RegExp(`service\\.${field}\\b`).test(src);
    const wrapped = new RegExp(`fillTemplate\\(\\s*service\\.${field}\\b`).test(src);
    if (rendered && !wrapped) fail(`serviceConfig.${field} contains placeholders but is rendered without fillTemplate`);
    else if (wrapped) ok(`serviceConfig.${field} is rendered through fillTemplate`);
  }
}

// ------------------------------------------------------------------ live mode

function get(url, depth = 0) {
  return new Promise((resolve, reject) => {
    if (depth > 4) return reject(new Error('too many redirects'));
    const mod = url.startsWith('https') ? https : http;
    const req = mod.get(url, { headers: { 'User-Agent': 'BestHospice-SEOTest/1.0' }, timeout: 20000 }, (res) => {
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        res.resume();
        return resolve(get(new URL(res.headers.location, url).toString(), depth + 1));
      }
      let data = '';
      res.on('data', (c) => { data += c; });
      res.on('end', () => resolve({ status: res.statusCode, html: data }));
    });
    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('timeout')); });
  });
}

// Pull out only the parts Google reads, so live JS template literals in
// <script> blocks are not mistaken for leaks.
function seoSurfaces(html) {
  const noScript = html.replace(/<script\b(?![^>]*application\/ld\+json)[\s\S]*?<\/script>/gi, ' ')
                       .replace(/<style\b[\s\S]*?<\/style>/gi, ' ');
  const pick = (rx) => (html.match(rx) || []).join(' ');
  return {
    body: noScript.replace(/<[^>]+>/g, ' '),
    title: pick(/<title>[\s\S]*?<\/title>/gi),
    description: pick(/<meta[^>]+name=["']description["'][^>]*>/gi),
    opengraph: pick(/<meta[^>]+property=["']og:[^"']+["'][^>]*>/gi),
    canonical: pick(/<link[^>]+rel=["']canonical["'][^>]*>/gi),
    jsonld: pick(/<script[^>]+application\/ld\+json[^>]*>[\s\S]*?<\/script>/gi),
    headings: pick(/<h[1-3][^>]*>[\s\S]*?<\/h[1-3]>/gi),
    breadcrumb: pick(/<div class="breadcrumb"[\s\S]*?<\/div>/gi)
  };
}

async function liveCheck(base) {
  const routes = [
    '/hospice-care/az', '/hospice-care/phoenix-az',
    '/palliative-care/az', '/palliative-care/phoenix-az',
    '/home-care/az', '/home-care/phoenix-az',
    '/hospice-care', '/palliative-care', '/home-care'
  ];
  for (const route of routes) {
    let res;
    try { res = await get(base.replace(/\/$/, '') + route); }
    catch (err) { fail(`${route} — request failed: ${err.message}`); continue; }
    if (res.status !== 200) { fail(`${route} — HTTP ${res.status}`); continue; }

    const surfaces = seoSurfaces(res.html);
    const found = [];
    for (const [where, text] of Object.entries(surfaces)) {
      for (const { name, rx } of LEAK_PATTERNS) {
        const hits = [...new Set(text.match(rx) || [])].filter((h) => !ALLOWED_TOKENS.has(h));
        if (hits.length) found.push(`${where}:${hits.join(',')}`);
      }
    }
    // A lowercase city in the title was the other production defect.
    const titleCity = /<title>[^<]*?\bin ([a-z][a-z ]+),/.exec(surfaces.title);
    if (titleCity) found.push(`title:uncapitalised city "${titleCity[1]}"`);

    if (found.length) fail(`${route} — ${found.join(' | ')}`);
    else ok(`${route} clean`);
  }
}

// ---------------------------------------------------------------------- main

(async () => {
  const liveIdx = process.argv.indexOf('--live');
  console.log('SEO template leak test\n');
  console.log('static checks:');
  staticCheck();
  if (liveIdx !== -1) {
    const base = process.argv[liveIdx + 1] || 'https://www.besthospice.com';
    console.log(`\nlive checks against ${base}:`);
    await liveCheck(base);
  }
  console.log('');
  if (failures.length) {
    console.error(`FAILED — ${failures.length} problem(s):`);
    failures.forEach((f) => console.error(`  - ${f}`));
    process.exit(1);
  }
  console.log('PASSED — no unresolved template variables');
})();
