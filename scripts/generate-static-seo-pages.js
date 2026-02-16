require('dotenv').config();
const fs = require('fs/promises');
const path = require('path');
const { PrismaClient } = require('@prisma/client');

const prisma = new PrismaClient();
const ROOT = path.resolve(__dirname, '..');
const CANONICAL_DOMAIN = 'https://www.besthospice.com';

const STATE_NAMES = {
  al: 'Alabama', ak: 'Alaska', az: 'Arizona', ar: 'Arkansas', ca: 'California', co: 'Colorado', ct: 'Connecticut',
  de: 'Delaware', fl: 'Florida', ga: 'Georgia', hi: 'Hawaii', id: 'Idaho', il: 'Illinois', in: 'Indiana', ia: 'Iowa',
  ks: 'Kansas', ky: 'Kentucky', la: 'Louisiana', me: 'Maine', md: 'Maryland', ma: 'Massachusetts', mi: 'Michigan',
  mn: 'Minnesota', ms: 'Mississippi', mo: 'Missouri', mt: 'Montana', ne: 'Nebraska', nv: 'Nevada', nh: 'New Hampshire',
  nj: 'New Jersey', nm: 'New Mexico', ny: 'New York', nc: 'North Carolina', nd: 'North Dakota', oh: 'Ohio', ok: 'Oklahoma',
  or: 'Oregon', pa: 'Pennsylvania', ri: 'Rhode Island', sc: 'South Carolina', sd: 'South Dakota', tn: 'Tennessee', tx: 'Texas',
  ut: 'Utah', vt: 'Vermont', va: 'Virginia', wa: 'Washington', wv: 'West Virginia', wi: 'Wisconsin', wy: 'Wyoming'
};

function slugify(value) {
  return String(value || '')
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '');
}

function esc(value) {
  return String(value || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function formatCareType(careType) {
  const v = String(careType || '').toLowerCase();
  if (v === 'palliative') return 'Palliative Care';
  if (v === 'home') return 'Home Care';
  return 'Hospice Care';
}

function normalizeState(state) {
  const raw = String(state || '').trim();
  if (!raw) return '';
  const lower = raw.toLowerCase();
  if (STATE_NAMES[lower]) return STATE_NAMES[lower];
  if (raw.length === 2 && STATE_NAMES[raw.toLowerCase()]) return STATE_NAMES[raw.toLowerCase()];
  return raw.replace(/\b\w/g, (m) => m.toUpperCase());
}

function navHtml() {
  return `
    <div class="hero-top">
      <div class="brand">
        <img src="/BestHospiceandHomeHealthNew.png" alt="Best Hospice and Home Health logo" class="brand-logo">
      </div>
      <button class="menu-toggle" aria-label="Toggle menu" aria-expanded="false">
        <span></span><span></span><span></span>
      </button>
      <div class="top-links" id="topLinks">
        <a class="pill" href="/provider.html">Are you a hospice provider? <u>Click here</u> to join BestHospice.com</a>
        <a class="pill ghost-pill" href="/why.html">Who We Are</a>
        <a class="pill ghost-pill" href="/provider-dashboard.html">Provider Dashboard</a>
        <a class="pill ghost-pill" href="/provider-billing.html">Provider Billing</a>
        <a class="pill ghost-pill" href="/locations.html">Locations We Currently Serve</a>
        <a class="pill ghost-pill" href="/cities.html">Browse Cities</a>
        <a class="pill ghost-pill" href="/faq-blog.html">FAQ & Blog Posts</a>
        <a class="pill ghost-pill" href="/education.html">Education Hub</a>
        <a class="pill ghost-pill" href="/contact.html">Contact Us</a>
      </div>
    </div>
  `;
}

function footerHtml() {
  return `
    <footer class="site-footer">
      <div class="footer-inner">
        <div class="footer-brand">Best Hospice and Home Health</div>
        <div class="footer-meta">Contact: contact@besthospice.com • United States</div>
        <div class="footer-links">
          <a href="/privacy.html">Privacy Policy</a>
          <a href="/terms.html">Terms of Service</a>
          <a href="/refund-policy.html">Refund & Cancellation Policy</a>
          <a href="/provider-billing.html">Provider Billing</a>
          <a href="/sitemap.html">HTML Sitemap</a>
        </div>
      </div>
    </footer>
  `;
}

function menuScript() {
  return `
    <script>
      (() => {
        const toggle = document.querySelector('.menu-toggle');
        const links = document.getElementById('topLinks');
        if (!toggle || !links) return;
        toggle.addEventListener('click', () => {
          const open = links.classList.toggle('open');
          toggle.setAttribute('aria-expanded', open ? 'true' : 'false');
        });
      })();
    </script>
  `;
}

function baseLayout({ title, metaDescription, canonicalPath, heroTitle, heroTagline, bodyHtml }) {
  const canonical = `${CANONICAL_DOMAIN}${canonicalPath}`;
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>${esc(title)}</title>
  <meta name="description" content="${esc(metaDescription)}" />
  <link rel="canonical" href="${esc(canonical)}" />
  <link rel="stylesheet" href="/styles-modern.css" />
</head>
<body>
  <div class="page-shell">
    <header class="hero">
      ${navHtml()}
      <div class="hero-body" style="grid-template-columns:1fr;">
        <div class="hero-text">
          <h1>${esc(heroTitle)}</h1>
          <p class="tagline">${esc(heroTagline)}</p>
        </div>
      </div>
    </header>

    <main>
      ${bodyHtml}
    </main>

    ${footerHtml()}
  </div>
  ${menuScript()}
</body>
</html>`;
}

function stateSort(a, b) {
  return a.localeCompare(b, 'en', { sensitivity: 'base' });
}

async function generateCityPages() {
  const cityOutputDir = path.join(ROOT, 'cities');
  const blogOutputDir = path.join(ROOT, 'blog');
  await fs.mkdir(cityOutputDir, { recursive: true });
  await fs.mkdir(blogOutputDir, { recursive: true });

  const providers = await prisma.provider.findMany({
    select: {
      id: true,
      name: true,
      address: true,
      city: true,
      state: true,
      phone: true,
      website: true
    },
    orderBy: [{ state: 'asc' }, { city: 'asc' }, { name: 'asc' }]
  });

  const cityMap = new Map();
  for (const p of providers) {
    const city = String(p.city || '').trim();
    const stateRaw = String(p.state || '').trim();
    if (!city || !stateRaw) continue;

    const state = normalizeState(stateRaw);
    const cityKey = `${city.toLowerCase()}|${state.toLowerCase()}`;
    if (!cityMap.has(cityKey)) {
      const filename = `${slugify(city)}-${slugify(state)}.html`;
      cityMap.set(cityKey, {
        city,
        state,
        filename,
        providers: []
      });
    }
    cityMap.get(cityKey).providers.push(p);
  }

  const cities = Array.from(cityMap.values()).sort((a, b) => {
    const stateCmp = stateSort(a.state, b.state);
    if (stateCmp !== 0) return stateCmp;
    return stateSort(a.city, b.city);
  });

  for (const cityData of cities) {
    const cityTitle = `${cityData.city}, ${cityData.state}`;
    const providerListHtml = cityData.providers
      .map((p) => {
        const websiteBlock = p.website
          ? `<p><a href="${esc(p.website)}" target="_blank" rel="noopener">Website</a></p>`
          : '';
        const phoneBlock = p.phone ? `<p>Phone: ${esc(p.phone)}</p>` : '';
        return `
          <article class="lead-item" style="padding:16px; margin-bottom:10px;">
            <h3 style="margin:0 0 6px;">${esc(p.name)}</h3>
            <p style="margin:0 0 6px;"><strong>Care Type:</strong> ${esc(formatCareType(p.careType || 'hospice'))}</p>
            <p style="margin:0 0 6px;">${esc(p.address)}</p>
            ${phoneBlock}
            ${websiteBlock}
          </article>
        `;
      })
      .join('\n');

    const body = `
      <section class="card" style="padding:18px;">
        <h2 style="margin:0 0 8px;">Find Local Providers</h2>
        <p style="margin:0;">Families in ${esc(cityTitle)} can compare verified hospice, palliative, and home care providers below. Contact providers directly and choose the best fit for your needs.</p>
      </section>

      <section class="card" style="padding:18px; margin-top:14px;">
        <h2 style="margin:0 0 10px;">Providers Serving ${esc(cityTitle)}</h2>
        ${providerListHtml || '<p>No providers listed for this city yet.</p>'}
      </section>

      <section class="card" style="padding:18px; margin-top:14px;">
        <h2 style="margin:0 0 8px;">Explore More</h2>
        <div style="display:flex; flex-wrap:wrap; gap:8px;">
          <a class="pill ghost-pill" href="/hospice-care">Hospice Care</a>
          <a class="pill ghost-pill" href="/palliative-care">Palliative Care</a>
          <a class="pill ghost-pill" href="/home-care">Home Care</a>
          <a class="pill ghost-pill" href="/cities.html">Browse All Cities</a>
        </div>
      </section>
    `;

    const html = baseLayout({
      title: `Hospice & Home Care Providers in ${cityTitle} | Best Hospice`,
      metaDescription: `Find verified hospice, palliative, and home care providers in ${cityTitle}. Connect with trusted local providers. 100% free for families.`,
      canonicalPath: `/cities/${cityData.filename}`,
      heroTitle: `Hospice and Home Care Providers in ${cityTitle}`,
      heroTagline: `Compare trusted local providers in ${cityTitle}.`,
      bodyHtml: body
    });

    await fs.writeFile(path.join(cityOutputDir, cityData.filename), html, 'utf8');
  }

  const groupedStates = new Map();
  for (const cityData of cities) {
    if (!groupedStates.has(cityData.state)) groupedStates.set(cityData.state, []);
    groupedStates.get(cityData.state).push(cityData);
  }

  const stateSections = Array.from(groupedStates.keys())
    .sort(stateSort)
    .map((stateName) => {
      const links = groupedStates
        .get(stateName)
        .sort((a, b) => stateSort(a.city, b.city))
        .map((entry) => `<li><a href="/cities/${esc(entry.filename)}">${esc(entry.city)}, ${esc(stateName)}</a></li>`)
        .join('');
      return `
        <section class="card" style="padding:18px; margin-top:14px;">
          <h2 style="margin:0 0 10px;">${esc(stateName)}</h2>
          <ul style="margin:0; padding-left:18px; display:grid; gap:6px;">${links}</ul>
        </section>
      `;
    })
    .join('\n');

  const citiesPage = baseLayout({
    title: 'Browse Cities | Best Hospice and Home Health',
    metaDescription: 'Browse all cities with active Best Hospice and Home Health providers. Direct links to local hospice, palliative, and home care pages.',
    canonicalPath: '/cities.html',
    heroTitle: 'Browse Cities We Serve',
    heroTagline: 'Direct links to city pages, grouped alphabetically by state.',
    bodyHtml: `
      <section class="card" style="padding:18px;">
        <h2 style="margin:0 0 8px;">Cities with active providers</h2>
        <p style="margin:0;">All city pages below are crawlable HTML and include local provider listings.</p>
      </section>
      ${stateSections || '<section class="card" style="padding:18px; margin-top:14px;"><p>No city pages generated yet.</p></section>'}
    `
  });

  await fs.writeFile(path.join(ROOT, 'cities.html'), citiesPage, 'utf8');

  const blogPosts = prisma.blogPost
    ? await prisma.blogPost.findMany({
        select: {
          id: true,
          title: true,
          body: true,
          authorCity: true,
          authorState: true,
          createdAt: true,
          comments: {
            select: {
              body: true,
              authorCity: true,
              authorState: true,
              createdAt: true
            },
            orderBy: { createdAt: 'asc' }
          }
        },
        orderBy: { createdAt: 'desc' }
      })
    : [];

  const blogLinks = [];
  for (const post of blogPosts) {
    const slug = `${slugify(post.title)}-${post.id.slice(0, 8)}.html`;
    blogLinks.push({
      title: post.title,
      href: `/blog/${slug}`
    });

    const commentsHtml = (post.comments || []).length
      ? post.comments
          .map((c) => `
            <article class="lead-item" style="padding:12px; margin-top:8px;">
              <p style="margin:0 0 6px;">${esc(c.body)}</p>
              <p class="note" style="margin:0;">${esc(c.authorCity)}, ${esc(c.authorState)} • ${new Date(c.createdAt).toLocaleDateString('en-US')}</p>
            </article>
          `)
          .join('')
      : '<p>No comments yet.</p>';

    const blogHtml = baseLayout({
      title: `${post.title} | Best Hospice Blog`,
      metaDescription: `Read: ${post.title}. Community guidance from Best Hospice and Home Health.`,
      canonicalPath: `/blog/${slug}`,
      heroTitle: post.title,
      heroTagline: `Posted from ${post.authorCity}, ${post.authorState} on ${new Date(post.createdAt).toLocaleDateString('en-US')}`,
      bodyHtml: `
        <section class="card" style="padding:18px;">
          <h2 style="margin:0 0 10px;">Post</h2>
          <p style="margin:0; white-space:pre-wrap;">${esc(post.body)}</p>
        </section>
        <section class="card" style="padding:18px; margin-top:14px;">
          <h2 style="margin:0 0 10px;">Comments</h2>
          ${commentsHtml}
        </section>
      `
    });

    await fs.writeFile(path.join(blogOutputDir, slug), blogHtml, 'utf8');
  }

  const serviceLinks = [
    '/hospice-care',
    '/palliative-care',
    '/home-care',
    '/guides/hospice-care',
    '/guides/palliative-care',
    '/guides/home-care',
    '/guides/how-to-choose-hospice-provider',
    '/guides/medicare-hospice-coverage',
    '/guides/when-is-it-time-for-hospice',
    '/guides/hospice-vs-palliative-care',
    '/guides/home-health-care-costs',
    '/education.html',
    '/faq-blog.html'
  ];

  const cityLinks = cities.map((c) => ({ title: `${c.city}, ${c.state}`, href: `/cities/${c.filename}` }));

  const sitemapHtml = baseLayout({
    title: 'HTML Sitemap | Best Hospice and Home Health',
    metaDescription: 'Crawlable HTML sitemap linking city pages, service pages, and blog posts.',
    canonicalPath: '/sitemap.html',
    heroTitle: 'HTML Sitemap',
    heroTagline: 'Direct links for search engines and users.',
    bodyHtml: `
      <section class="card" style="padding:18px;">
        <h2 style="margin:0 0 10px;">Service Pages</h2>
        <ul style="margin:0; padding-left:18px; display:grid; gap:6px;">
          ${serviceLinks.map((href) => `<li><a href="${href}">${href}</a></li>`).join('')}
        </ul>
      </section>

      <section class="card" style="padding:18px; margin-top:14px;">
        <h2 style="margin:0 0 10px;">City Pages</h2>
        <ul style="margin:0; padding-left:18px; display:grid; gap:6px; max-height:560px; overflow:auto;">
          ${cityLinks.map((l) => `<li><a href="${l.href}">${esc(l.title)}</a></li>`).join('') || '<li>No city pages yet</li>'}
        </ul>
      </section>

      <section class="card" style="padding:18px; margin-top:14px;">
        <h2 style="margin:0 0 10px;">Blog Posts</h2>
        <ul style="margin:0; padding-left:18px; display:grid; gap:6px;">
          ${blogLinks.map((l) => `<li><a href="${l.href}">${esc(l.title)}</a></li>`).join('') || '<li><a href="/faq-blog.html">FAQ & Blog Posts</a></li>'}
        </ul>
      </section>
    `
  });

  await fs.writeFile(path.join(ROOT, 'sitemap.html'), sitemapHtml, 'utf8');

  return {
    providerCount: providers.length,
    cityCount: cities.length,
    blogCount: blogPosts.length
  };
}

(async () => {
  try {
    const result = await generateCityPages();
    console.log(`Generated static SEO pages: ${result.cityCount} city pages, ${result.blogCount} blog pages, ${result.providerCount} providers.`);
  } catch (err) {
    console.error('Failed generating static SEO pages:', err);
    process.exitCode = 1;
  } finally {
    await prisma.$disconnect();
  }
})();
