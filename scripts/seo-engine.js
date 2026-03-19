#!/usr/bin/env node
/**
 * Best Hospice SEO Engine
 * - Pulls data from Google Search Console
 * - Analyzes competitor pages
 * - Generates actionable SEO recommendations
 *
 * Usage:
 *   node scripts/seo-engine.js              # Full run
 *   node scripts/seo-engine.js --gsc        # GSC data only
 *   node scripts/seo-engine.js --compete    # Competitor analysis only
 *   node scripts/seo-engine.js --report     # Show last saved report
 */

const { google } = require('googleapis');
const https = require('https');
const http = require('http');
const fs = require('fs');
const path = require('path');

// ─── Config ────────────────────────────────────────────────────────────────

const KEY_FILE = path.join(__dirname, '..', 'best-hospice-seo-40ab22f23d70.json');
const SITE_URL = 'sc-domain:besthospice.com';
const SITE_BASE_URL = 'https://www.besthospice.com';
const REPORT_FILE = path.join(__dirname, '..', 'seo-report.json');

const COMPETITORS = [
  { name: 'A Place For Mom', url: 'https://www.aplaceformom.com/hospice-care' },
  { name: 'Care.com', url: 'https://www.care.com/senior-care/hospice-care' },
  { name: 'Caring.com', url: 'https://www.caring.com/local/hospice-care' },
  { name: 'VITAS', url: 'https://www.vitas.com' },
  { name: 'Crossroads Hospice', url: 'https://www.crossroadshospice.com' },
];

// Target keywords to track
const TARGET_KEYWORDS = [
  'hospice care near me',
  'best hospice',
  'hospice services',
  'home hospice care',
  'hospice finder',
  'hospice care',
  'hospice providers',
  'end of life care',
  'palliative care near me',
  'hospice care cost',
];

// ─── GSC Auth ───────────────────────────────────────────────────────────────

async function getGSCClient() {
  const auth = new google.auth.GoogleAuth({
    keyFile: KEY_FILE,
    scopes: ['https://www.googleapis.com/auth/webmasters.readonly'],
  });
  const client = await auth.getClient();
  return google.searchconsole({ version: 'v1', auth: client });
}

// ─── GSC Data Pull ──────────────────────────────────────────────────────────

async function pullGSCData() {
  console.log('\n📊 Pulling Google Search Console data...\n');

  const gsc = await getGSCClient();

  const endDate = new Date();
  const startDate = new Date();
  startDate.setDate(endDate.getDate() - 90); // Last 90 days

  const fmt = (d) => d.toISOString().split('T')[0];

  // 1. Top queries
  // 0. Totals (accurate — query-level data has anonymized clicks for low-traffic terms)
  const totalsRes = await gsc.searchanalytics.query({
    siteUrl: SITE_URL,
    requestBody: { startDate: fmt(startDate), endDate: fmt(endDate) },
  });
  const totals = totalsRes.data.rows && totalsRes.data.rows[0] || { clicks: 0, impressions: 0, ctr: 0, position: 0 };

  const queryRes = await gsc.searchanalytics.query({
    siteUrl: SITE_URL,
    requestBody: {
      startDate: fmt(startDate),
      endDate: fmt(endDate),
      dimensions: ['query'],
      rowLimit: 100,
    },
  });

  // 2. Top pages
  const pageRes = await gsc.searchanalytics.query({
    siteUrl: SITE_URL,
    requestBody: {
      startDate: fmt(startDate),
      endDate: fmt(endDate),
      dimensions: ['page'],
      rowLimit: 50,
    },
  });

  // 3. Queries by device
  const deviceRes = await gsc.searchanalytics.query({
    siteUrl: SITE_URL,
    requestBody: {
      startDate: fmt(startDate),
      endDate: fmt(endDate),
      dimensions: ['device'],
      rowLimit: 10,
    },
  });

  const queries = queryRes.data.rows || [];
  const pages = pageRes.data.rows || [];
  const devices = deviceRes.data.rows || [];

  // Categorize queries
  const quickWins = queries.filter(r => r.position >= 5 && r.position <= 20 && r.impressions > 10);
  const lowCTR = queries.filter(r => r.position <= 10 && r.ctr < 0.05 && r.impressions > 20);
  const notRanking = TARGET_KEYWORDS.filter(kw =>
    !queries.find(r => r.keys[0].toLowerCase().includes(kw.toLowerCase()))
  );

  const gscData = {
    pulledAt: new Date().toISOString(),
    dateRange: { start: fmt(startDate), end: fmt(endDate) },
    summary: {
      totalQueries: queries.length,
      totalClicks: totals.clicks,
      totalImpressions: totals.impressions,
      avgPosition: totals.position ? totals.position.toFixed(1) : 'N/A',
      avgCTR: totals.ctr ? (totals.ctr * 100).toFixed(2) + '%' : '0.00%',
    },
    topQueries: queries.slice(0, 20).map(r => ({
      query: r.keys[0],
      clicks: r.clicks,
      impressions: r.impressions,
      ctr: (r.ctr * 100).toFixed(2) + '%',
      position: r.position.toFixed(1),
    })),
    topPages: pages.slice(0, 20).map(r => ({
      page: r.keys[0],
      clicks: r.clicks,
      impressions: r.impressions,
      ctr: (r.ctr * 100).toFixed(2) + '%',
      position: r.position.toFixed(1),
    })),
    devices: devices.map(r => ({
      device: r.keys[0],
      clicks: r.clicks,
      impressions: r.impressions,
      ctr: (r.ctr * 100).toFixed(2) + '%',
      position: r.position.toFixed(1),
    })),
    opportunities: {
      quickWins: quickWins.slice(0, 15).map(r => ({
        query: r.keys[0],
        position: r.position.toFixed(1),
        impressions: r.impressions,
        clicks: r.clicks,
        note: 'Ranking pos 5-20 — small content improvements could push to page 1',
      })),
      lowCTR: lowCTR.slice(0, 10).map(r => ({
        query: r.keys[0],
        position: r.position.toFixed(1),
        ctr: (r.ctr * 100).toFixed(2) + '%',
        impressions: r.impressions,
        note: 'Good position but low CTR — improve title/meta description',
      })),
      notRanking: notRanking.map(kw => ({
        query: kw,
        note: 'Target keyword not appearing in top 100 — needs content or page targeting this term',
      })),
    },
  };

  console.log(`✅ GSC data pulled`);
  console.log(`   Total queries tracked: ${gscData.summary.totalQueries}`);
  console.log(`   Total clicks (90d):    ${gscData.summary.totalClicks}`);
  console.log(`   Total impressions:     ${gscData.summary.totalImpressions}`);
  console.log(`   Avg position:          ${gscData.summary.avgPosition}`);
  console.log(`   Quick win keywords:    ${gscData.opportunities.quickWins.length}`);
  console.log(`   Low CTR keywords:      ${gscData.opportunities.lowCTR.length}`);
  console.log(`   Missing keywords:      ${gscData.opportunities.notRanking.length}`);

  return gscData;
}

// ─── Page Fetch ─────────────────────────────────────────────────────────────

function fetchPage(url, timeout = 10000) {
  return new Promise((resolve) => {
    const lib = url.startsWith('https') ? https : http;
    const start = Date.now();
    let req;
    try {
      req = lib.get(url, {
        headers: {
          'User-Agent': 'Mozilla/5.0 (compatible; SEO-Analyzer/1.0)',
          'Accept': 'text/html',
        },
        timeout,
      }, (res) => {
        // Follow one redirect
        if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
          fetchPage(res.headers.location, timeout).then(resolve);
          return;
        }
        let body = '';
        res.on('data', chunk => body += chunk);
        res.on('end', () => resolve({ ok: true, body, status: res.statusCode, ms: Date.now() - start }));
      });
      req.on('error', (e) => resolve({ ok: false, error: e.message }));
      req.on('timeout', () => { req.destroy(); resolve({ ok: false, error: 'timeout' }); });
    } catch (e) {
      resolve({ ok: false, error: e.message });
    }
  });
}

// ─── HTML Analyzer ──────────────────────────────────────────────────────────

function analyzePage(html, url) {
  const get = (pattern) => { const m = html.match(pattern); return m ? m[1].trim() : null; };
  const getAll = (pattern) => { const matches = []; let m; const re = new RegExp(pattern, 'gi'); while ((m = re.exec(html)) !== null) matches.push(m[1].trim()); return matches; };
  const count = (pattern) => (html.match(new RegExp(pattern, 'gi')) || []).length;

  const title = get(/<title[^>]*>([^<]+)<\/title>/i);
  const metaDesc = get(/<meta[^>]*name=["']description["'][^>]*content=["']([^"']+)["']/i)
    || get(/<meta[^>]*content=["']([^"']+)["'][^>]*name=["']description["']/i);

  const h1s = getAll(/<h1[^>]*>([^<]+)<\/h1>/);
  const h2s = getAll(/<h2[^>]*>([^<]+)<\/h2>/);
  const h3s = getAll(/<h3[^>]*>([^<]+)<\/h3>/);

  const canonical = get(/<link[^>]*rel=["']canonical["'][^>]*href=["']([^"']+)["']/i);
  const hasSchema = /<script[^>]*type=["']application\/ld\+json["']/i.test(html);
  const schemaTypes = getAll(/"@type"\s*:\s*"([^"]+)"/);
  const imgCount = count(/<img /);
  const imgNoAlt = count(/<img(?![^>]*alt=)[^>]*>/);
  const internalLinks = (html.match(/href=["'][^"']*["']/gi) || []).length;
  const wordCount = html.replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').split(' ').filter(w => w.length > 3).length;

  // Check for local SEO signals
  const hasNAP = /\d{3}[-.\s]\d{3}[-.\s]\d{4}/.test(html); // phone number
  const hasAddress = /(street|ave|blvd|suite|st\.|avenue)/i.test(html);
  const hasFAQ = /<[^>]*faq[^>]*>/i.test(html) || /frequently asked/i.test(html);
  const hasBreadcrumb = /breadcrumb/i.test(html);
  const hasReviews = /review|rating|stars/i.test(html);

  return {
    title,
    titleLength: title ? title.length : 0,
    metaDesc,
    metaDescLength: metaDesc ? metaDesc.length : 0,
    h1s,
    h2Count: h2s.length,
    h2s: h2s.slice(0, 8),
    h3Count: h3s.length,
    canonical,
    hasSchema,
    schemaTypes: [...new Set(schemaTypes)],
    imgCount,
    imgNoAlt,
    internalLinks,
    wordCount,
    hasNAP,
    hasAddress,
    hasFAQ,
    hasBreadcrumb,
    hasReviews,
  };
}

// ─── Competitor Analysis ─────────────────────────────────────────────────────

async function analyzeCompetitors() {
  console.log('\n🔍 Analyzing competitors...\n');

  const results = [];

  for (const comp of COMPETITORS) {
    process.stdout.write(`   Fetching ${comp.name}... `);
    const res = await fetchPage(comp.url);

    if (!res.ok) {
      console.log(`❌ failed (${res.error})`);
      results.push({ name: comp.name, url: comp.url, error: res.error });
      continue;
    }

    const analysis = analyzePage(res.body, comp.url);
    console.log(`✅ ${res.ms}ms`);

    results.push({
      name: comp.name,
      url: comp.url,
      loadTimeMs: res.ms,
      ...analysis,
    });
  }

  return results;
}

// ─── Your Site Analysis ──────────────────────────────────────────────────────

const LOCAL_ROOT = path.join(__dirname, '..');

async function analyzeOwnSite() {
  console.log('\n🏠 Analyzing besthospice.com (local files)...\n');

  const pagesToCheck = [
    { name: 'Homepage',        url: `${SITE_BASE_URL}/`,            localFile: 'index.html' },
    { name: 'Search',          url: `${SITE_BASE_URL}/search.html`, localFile: 'search.html' },
    { name: 'Why Best Hospice',url: `${SITE_BASE_URL}/why.html`,    localFile: 'why.html' },
    { name: 'FAQ/Blog',        url: `${SITE_BASE_URL}/faq-blog.html`, localFile: 'faq-blog.html' },
    { name: 'Education',       url: `${SITE_BASE_URL}/education.html`, localFile: 'education.html' },
    { name: 'Medicare Guide',  url: `${SITE_BASE_URL}/guides/medicare-hospice-coverage`, localFile: 'guides/medicare-hospice-coverage.html' },
  ];

  const results = [];
  for (const page of pagesToCheck) {
    process.stdout.write(`   Reading ${page.name}... `);
    const filePath = path.join(LOCAL_ROOT, page.localFile);
    if (!fs.existsSync(filePath)) {
      console.log(`❌ file not found`);
      results.push({ ...page, error: 'file not found' });
      continue;
    }
    const html = fs.readFileSync(filePath, 'utf8');
    const analysis = analyzePage(html, page.url);
    console.log(`✅`);
    results.push({ ...page, ...analysis });
  }

  return results;
}

// ─── Recommendation Engine ───────────────────────────────────────────────────

function generateRecommendations(gscData, ownPages, competitors) {
  const recs = [];

  // ── From GSC data ──
  if (gscData.opportunities.quickWins.length > 0) {
    recs.push({
      priority: 'HIGH',
      category: 'Quick Wins',
      title: `${gscData.opportunities.quickWins.length} keywords ranking positions 5-20`,
      detail: 'These keywords already have traction. Adding more content, internal links, and improving page depth for these queries could push them to page 1.',
      keywords: gscData.opportunities.quickWins.slice(0, 5).map(k => `"${k.query}" (pos ${k.position})`),
      action: 'Create or expand content pages targeting these exact queries. Add them to H1/H2 tags and meta descriptions.',
    });
  }

  if (gscData.opportunities.lowCTR.length > 0) {
    recs.push({
      priority: 'HIGH',
      category: 'Click-Through Rate',
      title: `${gscData.opportunities.lowCTR.length} keywords ranking well but getting low clicks`,
      detail: 'You are visible on Google but users are not clicking. The title or meta description is not compelling enough.',
      keywords: gscData.opportunities.lowCTR.slice(0, 5).map(k => `"${k.query}" (pos ${k.position}, CTR ${k.ctr})`),
      action: 'Rewrite title tags and meta descriptions for these pages. Add numbers, urgency, or a clear value proposition (e.g. "Find Top-Rated Hospice Care Near You — Free & Instant").',
    });
  }

  if (gscData.opportunities.notRanking.length > 0) {
    recs.push({
      priority: 'MEDIUM',
      category: 'Missing Keywords',
      title: `${gscData.opportunities.notRanking.length} target keywords you are not ranking for at all`,
      detail: 'These are high-value hospice search terms with no presence in your top 100 results.',
      keywords: gscData.opportunities.notRanking.map(k => `"${k.query}"`),
      action: 'Create dedicated landing pages or blog posts targeting each of these terms.',
    });
  }

  // ── From own site analysis ──
  for (const page of ownPages) {
    if (page.error) continue;

    if (!page.metaDesc) {
      recs.push({
        priority: 'HIGH',
        category: 'On-Page SEO',
        title: `Missing meta description on ${page.name}`,
        detail: 'Meta descriptions appear in Google search results and directly impact CTR.',
        action: `Add a compelling 150-160 character meta description to ${page.url}`,
      });
    } else if (page.metaDescLength > 160) {
      recs.push({
        priority: 'MEDIUM',
        category: 'On-Page SEO',
        title: `Meta description too long on ${page.name} (${page.metaDescLength} chars)`,
        action: `Shorten meta description to under 160 characters on ${page.url}`,
      });
    }

    if (!page.h1s || page.h1s.length === 0) {
      recs.push({
        priority: 'HIGH',
        category: 'On-Page SEO',
        title: `Missing H1 tag on ${page.name}`,
        action: `Add a single H1 tag with your primary keyword to ${page.url}`,
      });
    }

    if (page.imgNoAlt > 0) {
      recs.push({
        priority: 'MEDIUM',
        category: 'Accessibility & SEO',
        title: `${page.imgNoAlt} images missing alt text on ${page.name}`,
        action: `Add descriptive alt text to all images on ${page.url}`,
      });
    }

    if (!page.hasSchema) {
      recs.push({
        priority: 'HIGH',
        category: 'Schema Markup',
        title: `No structured data (schema) on ${page.name}`,
        detail: 'Schema markup helps Google understand your content and can generate rich results (stars, FAQs, etc.) in search.',
        action: `Add LocalBusiness + MedicalOrganization schema to ${page.url}`,
      });
    }

    if (!page.hasFAQ) {
      recs.push({
        priority: 'MEDIUM',
        category: 'Schema Markup',
        title: `No FAQ section detected on ${page.name}`,
        detail: 'FAQ sections with FAQPage schema can take up significantly more Google SERP real estate.',
        action: `Add an FAQ section with FAQPage schema markup to ${page.url}`,
      });
    }

    if (page.wordCount < 500) {
      recs.push({
        priority: 'MEDIUM',
        category: 'Content Depth',
        title: `Thin content on ${page.name} (~${page.wordCount} words)`,
        detail: 'Competitors typically have 1000-3000 words on key landing pages. More content = more keyword coverage.',
        action: `Expand ${page.url} with more detailed information about hospice services, process, and FAQs.`,
      });
    }
  }

  // ── From competitor comparison ──
  const competitorSchemaTypes = [...new Set(competitors.flatMap(c => c.schemaTypes || []))];
  const yourSchemaTypes = ownPages.flatMap(p => p.schemaTypes || []);
  const missingSchema = competitorSchemaTypes.filter(t => !yourSchemaTypes.includes(t));

  if (missingSchema.length > 0) {
    recs.push({
      priority: 'MEDIUM',
      category: 'Schema Markup',
      title: `Competitors using schema types you are not: ${missingSchema.join(', ')}`,
      action: `Implement these schema types across relevant pages.`,
    });
  }

  const avgCompetitorWords = Math.round(
    competitors.filter(c => c.wordCount).reduce((s, c) => s + c.wordCount, 0) /
    competitors.filter(c => c.wordCount).length
  );

  const avgYourWords = Math.round(
    ownPages.filter(p => p.wordCount).reduce((s, p) => s + p.wordCount, 0) /
    ownPages.filter(p => p.wordCount).length
  );

  if (avgYourWords < avgCompetitorWords * 0.6) {
    recs.push({
      priority: 'HIGH',
      category: 'Content Gap',
      title: `Your pages average ~${avgYourWords} words vs competitors ~${avgCompetitorWords} words`,
      detail: 'Content depth is a major ranking factor. Competitors are winning partly because they have much more content.',
      action: 'Systematically expand your core pages with more detailed, helpful content about hospice care.',
    });
  }

  const competitorsWithReviews = competitors.filter(c => c.hasReviews).length;
  if (competitorsWithReviews > 0 && !ownPages.some(p => p.hasReviews)) {
    recs.push({
      priority: 'HIGH',
      category: 'Trust Signals',
      title: `${competitorsWithReviews}/${competitors.length} competitors show reviews/ratings — you do not`,
      detail: 'Reviews and star ratings in search results significantly increase CTR.',
      action: 'Add testimonials with Review schema markup to homepage and key landing pages.',
    });
  }

  // Sort by priority
  const order = { HIGH: 0, MEDIUM: 1, LOW: 2 };
  recs.sort((a, b) => order[a.priority] - order[b.priority]);

  return recs;
}

// ─── Report Printer ──────────────────────────────────────────────────────────

function printReport(report) {
  const { gscData, recommendations, competitors, ownPages } = report;

  console.log('\n' + '═'.repeat(70));
  console.log('  BEST HOSPICE — SEO REPORT');
  console.log(`  Generated: ${new Date(report.generatedAt).toLocaleString()}`);
  console.log('═'.repeat(70));

  console.log('\n📊 SEARCH CONSOLE SUMMARY (last 90 days)');
  console.log(`   Clicks:       ${gscData.summary.totalClicks}`);
  console.log(`   Impressions:  ${gscData.summary.totalImpressions}`);
  console.log(`   Avg Position: ${gscData.summary.avgPosition}`);
  console.log(`   Avg CTR:      ${gscData.summary.avgCTR}`);

  console.log('\n🔑 TOP 10 QUERIES');
  gscData.topQueries.slice(0, 10).forEach((q, i) => {
    console.log(`   ${String(i+1).padStart(2)}. "${q.query}" — ${q.clicks} clicks, pos ${q.position}`);
  });

  console.log('\n🏆 COMPETITOR SNAPSHOT');
  competitors.filter(c => !c.error).forEach(c => {
    console.log(`\n   ${c.name}`);
    console.log(`   Title: ${c.title || 'N/A'}`);
    console.log(`   H1: ${c.h1s && c.h1s[0] ? c.h1s[0] : 'N/A'}`);
    console.log(`   Words: ~${c.wordCount || 0} | Schema: ${c.schemaTypes && c.schemaTypes.length ? c.schemaTypes.join(', ') : 'none'}`);
    console.log(`   Has FAQ: ${c.hasFAQ ? '✅' : '❌'} | Has Reviews: ${c.hasReviews ? '✅' : '❌'} | Has Breadcrumbs: ${c.hasBreadcrumb ? '✅' : '❌'}`);
  });

  console.log('\n🎯 RECOMMENDATIONS (' + recommendations.length + ' total)');
  recommendations.forEach((rec, i) => {
    const icon = rec.priority === 'HIGH' ? '🔴' : rec.priority === 'MEDIUM' ? '🟡' : '🟢';
    console.log(`\n   ${icon} [${rec.priority}] ${rec.category}: ${rec.title}`);
    if (rec.detail) console.log(`      ${rec.detail}`);
    if (rec.keywords) console.log(`      Keywords: ${rec.keywords.join(' | ')}`);
    console.log(`      ➜ ${rec.action}`);
  });

  console.log('\n' + '═'.repeat(70));
  console.log(`  Full report saved to: seo-report.json`);
  console.log('═'.repeat(70) + '\n');
}

// ─── Main ────────────────────────────────────────────────────────────────────

async function main() {
  const args = process.argv.slice(2);
  const gscOnly = args.includes('--gsc');
  const competeOnly = args.includes('--compete');
  const showReport = args.includes('--report');

  if (showReport) {
    if (!fs.existsSync(REPORT_FILE)) {
      console.log('No saved report found. Run without --report first.');
      process.exit(1);
    }
    const report = JSON.parse(fs.readFileSync(REPORT_FILE, 'utf8'));
    printReport(report);
    return;
  }

  console.log('\n🚀 Best Hospice SEO Engine starting...');

  let gscData = null;
  let competitors = [];
  let ownPages = [];

  if (!competeOnly) {
    gscData = await pullGSCData();
  }

  if (!gscOnly) {
    competitors = await analyzeCompetitors();
    ownPages = await analyzeOwnSite();
  }

  if (!gscData) {
    // Load saved GSC data if running compete-only
    if (fs.existsSync(REPORT_FILE)) {
      gscData = JSON.parse(fs.readFileSync(REPORT_FILE, 'utf8')).gscData;
    } else {
      gscData = { summary: {}, topQueries: [], topPages: [], devices: [], opportunities: { quickWins: [], lowCTR: [], notRanking: [] } };
    }
  }

  const recommendations = generateRecommendations(gscData, ownPages, competitors);

  const report = {
    generatedAt: new Date().toISOString(),
    gscData,
    competitors,
    ownPages,
    recommendations,
  };

  fs.writeFileSync(REPORT_FILE, JSON.stringify(report, null, 2));
  printReport(report);
}

main().catch(err => {
  console.error('\n❌ Error:', err.message);
  if (err.message.includes('invalid_grant') || err.message.includes('unauthorized')) {
    console.error('   → Check that the service account has been added to Google Search Console');
    console.error('   → Go to GSC → Settings → Users and permissions → Add seo-reader@best-hospice-seo.iam.gserviceaccount.com');
  }
  process.exit(1);
});
