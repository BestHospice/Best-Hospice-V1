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

function normalizeState(state) {
  const raw = String(state || '').trim();
  if (!raw) return '';
  const lower = raw.toLowerCase();
  if (STATE_NAMES[lower]) return STATE_NAMES[lower];
  if (raw.length === 2 && STATE_NAMES[raw.toLowerCase()]) return STATE_NAMES[raw.toLowerCase()];
  return raw.replace(/\b\w/g, (m) => m.toUpperCase());
}

function normalizeCareTypeKey(careType) {
  const v = String(careType || '').toLowerCase();
  if (v === 'palliative' || v === 'palliative-care') return 'palliative';
  if (v === 'home' || v === 'home-care') return 'home';
  return 'hospice';
}

function formatCareType(careType) {
  if (careType === 'palliative') return 'Palliative Care';
  if (careType === 'home') return 'Home Care';
  return 'Hospice Care';
}

function stateSort(a, b) {
  return a.localeCompare(b, 'en', { sensitivity: 'base' });
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

function baseLayout({ title, metaDescription, canonicalPath, heroTitle, heroTagline, bodyHtml, extraHead = '' }) {
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
  ${extraHead}
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

    <main>${bodyHtml}</main>

    ${footerHtml()}
  </div>
  ${menuScript()}
</body>
</html>`;
}

function breadcrumbSchema(items) {
  return {
    '@context': 'https://schema.org',
    '@type': 'BreadcrumbList',
    itemListElement: items.map((item, idx) => ({
      '@type': 'ListItem',
      position: idx + 1,
      name: item.name,
      item: `${CANONICAL_DOMAIN}${item.url}`
    }))
  };
}

function cityFaqSchema(city, state) {
  const qs = [
    {
      q: `How much does hospice cost in ${state}?`,
      a: `Hospice in ${state} is often covered by Medicare when eligibility criteria are met. Costs for home care and palliative care can vary by service type and insurance plan.`
    },
    {
      q: `What does Medicare cover for hospice in ${city}?`,
      a: 'Medicare typically covers core hospice services such as nursing support, comfort medications related to the terminal diagnosis, and medical equipment when patients qualify.'
    },
    {
      q: `How do I know if a provider in ${city} is legitimate?`,
      a: 'Verify state licensing, Medicare certification where applicable, service area fit, and response reliability. Ask each provider to confirm credentials and accepted payers.'
    },
    {
      q: `Can I switch hospice providers in ${state}?`,
      a: 'Yes. Families can generally change providers if the current fit is not meeting care expectations.'
    }
  ];
  return {
    '@context': 'https://schema.org',
    '@type': 'FAQPage',
    mainEntity: qs.map((item) => ({
      '@type': 'Question',
      name: item.q,
      acceptedAnswer: { '@type': 'Answer', text: item.a }
    }))
  };
}

async function generateStaticPages() {
  const cityOutputDir = path.join(ROOT, 'cities');
  const stateOutputDir = path.join(ROOT, 'states');
  const blogOutputDir = path.join(ROOT, 'blog');
  await fs.mkdir(cityOutputDir, { recursive: true });
  await fs.mkdir(stateOutputDir, { recursive: true });
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

  const careTypeByProviderId = new Map();
  try {
    const careTypeRows = await prisma.$queryRawUnsafe('SELECT "id", "careType" FROM "Provider"');
    if (Array.isArray(careTypeRows)) {
      for (const row of careTypeRows) {
        careTypeByProviderId.set(String(row.id), normalizeCareTypeKey(row.careType));
      }
    }
  } catch (_err) {
    // Use hospice fallback if column/model is unavailable.
  }

  const cityMap = new Map();
  const stateMap = new Map();
  for (const p of providers) {
    const city = String(p.city || '').trim();
    const stateName = normalizeState(p.state || '');
    if (!city || !stateName) continue;
    const careType = careTypeByProviderId.get(String(p.id)) || 'hospice';

    const cityKey = `${city.toLowerCase()}|${stateName.toLowerCase()}`;
    if (!cityMap.has(cityKey)) {
      cityMap.set(cityKey, {
        city,
        state: stateName,
        filename: `${slugify(city)}-${slugify(stateName)}.html`,
        providers: [],
        careTypes: new Set()
      });
    }
    const cityRecord = cityMap.get(cityKey);
    cityRecord.providers.push({ ...p, careType });
    cityRecord.careTypes.add(careType);

    const stateKey = stateName.toLowerCase();
    if (!stateMap.has(stateKey)) {
      stateMap.set(stateKey, {
        state: stateName,
        filename: `${slugify(stateName)}.html`,
        cities: new Map(),
        providers: []
      });
    }
    const stateRecord = stateMap.get(stateKey);
    stateRecord.providers.push({ ...p, careType, city });
    if (!stateRecord.cities.has(city.toLowerCase())) {
      stateRecord.cities.set(city.toLowerCase(), cityRecord.filename);
    }
  }

  const cities = Array.from(cityMap.values()).sort((a, b) => {
    const stateCmp = stateSort(a.state, b.state);
    if (stateCmp !== 0) return stateCmp;
    return stateSort(a.city, b.city);
  });

  const stateList = Array.from(stateMap.values()).sort((a, b) => stateSort(a.state, b.state));

  for (const cityData of cities) {
    const cityTitle = `${cityData.city}, ${cityData.state}`;
    const stateRecord = stateMap.get(cityData.state.toLowerCase());
    const stateFile = stateRecord ? stateRecord.filename : `${slugify(cityData.state)}.html`;
    const relatedCities = cities
      .filter((c) => c.state === cityData.state && c.city !== cityData.city)
      .slice(0, 5);

    const providerListHtml = cityData.providers
      .map((p) => {
        const websiteBlock = p.website ? `<p><a href="${esc(p.website)}" target="_blank" rel="noopener">Website - click here</a></p>` : '';
        const phoneBlock = p.phone ? `<p>Phone: ${esc(p.phone)}</p>` : '';
        return `
          <article class="lead-item" style="padding:16px; margin-bottom:10px;">
            <h3 style="margin:0 0 6px;">${esc(p.name)}</h3>
            <p style="margin:0 0 6px;"><strong>Care Type:</strong> ${esc(formatCareType(p.careType))}</p>
            <p style="margin:0 0 6px;">${esc(p.address || `${cityData.city}, ${cityData.state}`)}</p>
            ${phoneBlock}
            ${websiteBlock}
          </article>
        `;
      })
      .join('\n');

    const breadcrumbs = [
      { name: 'Home', url: '/' },
      { name: 'Browse Cities', url: '/cities.html' },
      { name: cityData.state, url: `/states/${stateFile}` },
      { name: cityData.city, url: `/cities/${cityData.filename}` }
    ];

    const breadcrumbHtml = `<nav aria-label="Breadcrumb" style="margin:0 0 12px;"><a href="/">Home</a> &gt; <a href="/cities.html">Browse Cities</a> &gt; <a href="/states/${stateFile}">${esc(cityData.state)}</a> &gt; <span>${esc(cityData.city)}</span></nav>`;

    const body = `
      <section class="card" style="padding:18px;">
        ${breadcrumbHtml}
        <p style="margin:0 0 10px;">Finding hospice care in ${esc(cityData.city)} can feel overwhelming when families need answers quickly. Best Hospice and Home Health helps families compare verified providers in one place, with no cost or obligation. Our platform is designed to reduce confusion by showing local agencies that serve ${esc(cityData.city)} and nearby communities. We verify core provider details, including service coverage and contact information, so families can focus on fit and responsiveness. If your loved one needs hospice, palliative, or home care, the list below gives you a direct path to providers in ${esc(cityData.city)}. Families can contact multiple agencies, compare availability, and choose the provider that best matches clinical needs, insurance, and communication preferences.</p>
      </section>

      <section class="card" style="padding:18px; margin-top:14px;">
        <h2 style="margin:0 0 8px;">Understanding Hospice and Home Care in ${esc(cityData.city)}</h2>
        <p style="margin:0 0 10px;">Hospice care supports patients and families when comfort becomes the primary goal of care. Services often include nursing support, symptom management, caregiver guidance, and emotional support. Home care generally helps with daily living needs at home, while palliative care can support symptom relief at any stage of serious illness. Together, these services help families keep loved ones safe, comfortable, and supported in familiar surroundings.</p>
        <p style="margin:0;">Coverage depends on service type and payer. In ${esc(cityData.state)}, Medicare may cover hospice when eligibility criteria are met, and other services may be covered through Medicaid or private insurance depending on plan terms. The providers below serve ${esc(cityData.city)} and surrounding areas and can help confirm eligibility and expected costs.</p>
      </section>

      <section class="card" style="padding:18px; margin-top:14px;">
        <h2 style="margin:0 0 8px;">How to Choose a Provider in ${esc(cityData.city)}</h2>
        <p style="margin:0 0 10px;">When comparing providers, ask how quickly intake can begin, what support is available after hours, and whether they routinely serve your neighborhood. Verification matters: families should confirm licensing, Medicare certification when relevant, and payer acceptance before enrollment. Strong providers communicate clearly, set realistic expectations, and respond quickly when needs change.</p>
        <p style="margin:0;">Review provider reputation, ask direct questions about care approach, and compare more than one agency whenever possible. The right provider is the one that combines clinical fit with clear communication and reliable follow-through.</p>
      </section>

      <section class="card" style="padding:18px; margin-top:14px;">
        <h2 style="margin:0 0 10px;">Providers Serving ${esc(cityTitle)}</h2>
        ${providerListHtml || '<p>No providers listed for this city yet.</p>'}
      </section>

      <section class="card" style="padding:18px; margin-top:14px;">
        <h2 style="margin:0 0 8px;">Frequently Asked Questions</h2>
        <p style="margin:0 0 8px;"><strong>How much does hospice cost in ${esc(cityData.state)}?</strong><br>Hospice is often covered by Medicare when eligibility criteria are met; additional costs depend on care setting and payer details.</p>
        <p style="margin:0 0 8px;"><strong>What does Medicare cover for hospice in ${esc(cityData.city)}?</strong><br>Medicare generally covers core hospice services such as nursing care, comfort medications tied to terminal diagnosis, and medical equipment.</p>
        <p style="margin:0 0 8px;"><strong>How do I know if a provider in ${esc(cityData.city)} is legitimate?</strong><br>Verify licensing, coverage area, response reliability, and accepted insurance before enrolling.</p>
        <p style="margin:0;"><strong>Can I switch hospice providers in ${esc(cityData.state)}?</strong><br>Yes, families can generally switch providers if care fit is not meeting expectations.</p>
      </section>

      <section class="card" style="padding:18px; margin-top:14px;">
        <h2 style="margin:0 0 8px;">Related Cities in ${esc(cityData.state)}</h2>
        <ul style="margin:0 0 10px; padding-left:18px; display:grid; gap:6px;">
          ${relatedCities.length ? relatedCities.map((c) => `<li><a href="/cities/${c.filename}">${esc(c.city)}, ${esc(c.state)}</a></li>`).join('') : '<li>More cities coming soon.</li>'}
        </ul>
        <a class="pill ghost-pill" href="/states/${stateFile}">See all ${esc(cityData.state)} providers</a>
      </section>
    `;

    const schemas = [breadcrumbSchema(breadcrumbs), cityFaqSchema(cityData.city, cityData.state)];
    const extraHead = `<script type="application/ld+json">${JSON.stringify(schemas)}</script>`;

    const html = baseLayout({
      title: `Hospice & Home Care Providers in ${cityTitle} | Best Hospice`,
      metaDescription: `Find verified hospice, palliative, and home care providers in ${cityTitle}. Connect with trusted local providers. 100% free for families, no obligation.`,
      canonicalPath: `/cities/${cityData.filename}`,
      heroTitle: `Hospice and Home Care Providers in ${cityTitle}`,
      heroTagline: `Compare trusted local providers in ${cityTitle}.`,
      bodyHtml: body,
      extraHead
    });

    await fs.writeFile(path.join(cityOutputDir, cityData.filename), html, 'utf8');
  }

  // state pages
  for (const stateData of stateList) {
    const uniqueCities = Array.from(stateData.cities.entries())
      .map(([cityLower, filename]) => ({ city: cityLower.replace(/\b\w/g, (m) => m.toUpperCase()), filename }))
      .sort((a, b) => stateSort(a.city, b.city));
    const cityLinks = uniqueCities.map((c) => `<li><a href="/cities/${c.filename}">${esc(c.city)}, ${esc(stateData.state)}</a></li>`).join('');

    const body = `
      <section class="card" style="padding:18px;">
        <h2 style="margin:0 0 8px;">Finding Hospice and Home Care in ${esc(stateData.state)}</h2>
        <p style="margin:0 0 10px;">Families across ${esc(stateData.state)} use Best Hospice and Home Health to compare verified local providers quickly and clearly. Whether you are seeking hospice, palliative care, or home care support, this page helps you navigate city-level options with direct links and current provider coverage. Our platform is built to reduce stress by putting trusted options in one place so families can make informed decisions without sales pressure.</p>
        <p style="margin:0;">Use the city links below to view local provider pages and contact agencies directly.</p>
      </section>

      <section class="card" style="padding:18px; margin-top:14px;">
        <h2 style="margin:0 0 8px;">Medicare and Medicaid Information in ${esc(stateData.state)}</h2>
        <p style="margin:0;">Coverage varies by care type and payer. Medicare often covers hospice when eligibility criteria are met. Medicaid and private insurance coverage may vary across plans and services. Providers can confirm what is covered before care begins.</p>
      </section>

      <section class="card" style="padding:18px; margin-top:14px;">
        <h2 style="margin:0 0 10px;">Cities We Serve in ${esc(stateData.state)}</h2>
        <ul style="margin:0; padding-left:18px; display:grid; gap:6px;">${cityLinks}</ul>
      </section>

      <section class="card" style="padding:18px; margin-top:14px;">
        <h2 style="margin:0 0 8px;">Coverage Snapshot</h2>
        <p style="margin:0;">We currently serve ${stateData.providers.length} verified providers across ${uniqueCities.length} cities in ${esc(stateData.state)}.</p>
      </section>
    `;

    const html = baseLayout({
      title: `Hospice & Home Care Providers in ${stateData.state} | Best Hospice`,
      metaDescription: `Find verified hospice and home care providers across ${stateData.state}. Browse providers by city. 100% free for families.`,
      canonicalPath: `/states/${stateData.filename}`,
      heroTitle: `Hospice and Home Care Providers in ${stateData.state}`,
      heroTagline: `Browse verified provider coverage across ${stateData.state}.`,
      bodyHtml: body
    });

    await fs.writeFile(path.join(stateOutputDir, stateData.filename), html, 'utf8');
  }

  const groupedByCareType = {
    hospice: new Map(),
    palliative: new Map(),
    home: new Map()
  };

  for (const cityData of cities) {
    for (const careType of cityData.careTypes) {
      if (!groupedByCareType[careType]) continue;
      if (!groupedByCareType[careType].has(cityData.state)) groupedByCareType[careType].set(cityData.state, []);
      groupedByCareType[careType].get(cityData.state).push(cityData);
    }
  }

  const careTypeSections = [
    { key: 'hospice', title: 'Hospice Care' },
    { key: 'palliative', title: 'Palliative Care' },
    { key: 'home', title: 'Home Care' }
  ]
    .map((group) => {
      const states = Array.from(groupedByCareType[group.key].keys()).sort(stateSort);
      if (!states.length) return '';
      const stateBlocks = states
        .map((stateName) => {
          const entries = groupedByCareType[group.key].get(stateName).sort((a, b) => stateSort(a.city, b.city));
          const links = entries
            .map((entry) => `<li><a href="/cities/${entry.filename}">${esc(entry.city)}, ${esc(stateName)}</a></li>`)
            .join('');
          const stateFile = stateMap.get(stateName.toLowerCase())?.filename || `${slugify(stateName)}.html`;
          return `
            <div style="margin-top:12px;">
              <h3 style="margin:0 0 8px;">${esc(stateName)}</h3>
              <ul style="margin:0 0 10px; padding-left:18px; display:grid; gap:6px;">${links}</ul>
              <a class="pill ghost-pill" href="/states/${stateFile}">See all ${esc(stateName)} providers</a>
            </div>
          `;
        })
        .join('\n');
      return `
        <section class="card" style="padding:18px; margin-top:14px;">
          <h2 style="margin:0 0 8px;">${group.title}</h2>
          ${stateBlocks}
        </section>
      `;
    })
    .join('\n');

  const citiesPage = baseLayout({
    title: 'Browse Cities | Best Hospice and Home Health',
    metaDescription: 'Browse all cities with active Best Hospice and Home Health providers. Direct links to local hospice, palliative, and home care pages.',
    canonicalPath: '/cities.html',
    heroTitle: 'Browse Cities We Serve',
    heroTagline: 'Direct links to city pages grouped by care type and state.',
    bodyHtml: `
      <section class="card" style="padding:18px;">
        <h2 style="margin:0 0 8px;">Cities with active providers</h2>
        <p style="margin:0;">Browse city pages by care type below.</p>
      </section>
      ${careTypeSections || '<section class="card" style="padding:18px; margin-top:14px;"><p>No city pages generated yet.</p></section>'}
    `
  });
  await fs.writeFile(path.join(ROOT, 'cities.html'), citiesPage, 'utf8');

  // Optional blog static pages if blog model exists
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
            select: { body: true, authorCity: true, authorState: true, createdAt: true },
            orderBy: { createdAt: 'asc' }
          }
        },
        orderBy: { createdAt: 'desc' }
      })
    : [];

  const blogLinks = [];
  for (const post of blogPosts) {
    const slug = `${slugify(post.title)}-${post.id.slice(0, 8)}.html`;
    blogLinks.push({ title: post.title, href: `/blog/${slug}` });
    const commentsHtml = (post.comments || []).length
      ? post.comments
          .map((c) => `<article class="lead-item" style="padding:12px; margin-top:8px;"><p style="margin:0 0 6px;">${esc(c.body)}</p><p class="note" style="margin:0;">${esc(c.authorCity)}, ${esc(c.authorState)} • ${new Date(c.createdAt).toLocaleDateString('en-US')}</p></article>`)
          .join('')
      : '<p>No comments yet.</p>';

    const html = baseLayout({
      title: `${post.title} | Best Hospice Blog`,
      metaDescription: `Read: ${post.title}. Community guidance from Best Hospice and Home Health.`,
      canonicalPath: `/blog/${slug}`,
      heroTitle: post.title,
      heroTagline: `Posted from ${post.authorCity}, ${post.authorState} on ${new Date(post.createdAt).toLocaleDateString('en-US')}`,
      bodyHtml: `<section class="card" style="padding:18px;"><h2 style="margin:0 0 10px;">Post</h2><p style="margin:0; white-space:pre-wrap;">${esc(post.body)}</p></section><section class="card" style="padding:18px; margin-top:14px;"><h2 style="margin:0 0 10px;">Comments</h2>${commentsHtml}</section>`
    });

    await fs.writeFile(path.join(blogOutputDir, slug), html, 'utf8');
  }

  const serviceLinks = [
    '/hospice-care', '/palliative-care', '/home-care',
    '/guides/hospice-care', '/guides/palliative-care', '/guides/home-care',
    '/guides/how-to-choose-hospice-provider', '/guides/medicare-hospice-coverage',
    '/guides/when-is-it-time-for-hospice', '/guides/hospice-vs-palliative-care',
    '/guides/home-health-care-costs', '/education.html', '/faq-blog.html'
  ];

  const cityLinks = cities.map((c) => ({ title: `${c.city}, ${c.state}`, href: `/cities/${c.filename}` }));
  const stateLinks = stateList.map((s) => ({ title: s.state, href: `/states/${s.filename}` }));

  const sitemapHtml = baseLayout({
    title: 'HTML Sitemap | Best Hospice and Home Health',
    metaDescription: 'Crawlable HTML sitemap linking city pages, state pages, service pages, and blog posts.',
    canonicalPath: '/sitemap.html',
    heroTitle: 'HTML Sitemap',
    heroTagline: 'Direct links for search engines and users.',
    bodyHtml: `
      <section class="card" style="padding:18px;">
        <h2 style="margin:0 0 10px;">Service Pages</h2>
        <ul style="margin:0; padding-left:18px; display:grid; gap:6px;">${serviceLinks.map((href) => `<li><a href="${href}">${href}</a></li>`).join('')}</ul>
      </section>
      <section class="card" style="padding:18px; margin-top:14px;">
        <h2 style="margin:0 0 10px;">State Pages</h2>
        <ul style="margin:0; padding-left:18px; display:grid; gap:6px;">${stateLinks.map((l) => `<li><a href="${l.href}">${esc(l.title)}</a></li>`).join('') || '<li>No state pages yet</li>'}</ul>
      </section>
      <section class="card" style="padding:18px; margin-top:14px;">
        <h2 style="margin:0 0 10px;">City Pages</h2>
        <ul style="margin:0; padding-left:18px; display:grid; gap:6px; max-height:560px; overflow:auto;">${cityLinks.map((l) => `<li><a href="${l.href}">${esc(l.title)}</a></li>`).join('') || '<li>No city pages yet</li>'}</ul>
      </section>
      <section class="card" style="padding:18px; margin-top:14px;">
        <h2 style="margin:0 0 10px;">Blog Posts</h2>
        <ul style="margin:0; padding-left:18px; display:grid; gap:6px;">${blogLinks.map((l) => `<li><a href="${l.href}">${esc(l.title)}</a></li>`).join('') || '<li><a href="/faq-blog.html">FAQ & Blog Posts</a></li>'}</ul>
      </section>
    `
  });
  await fs.writeFile(path.join(ROOT, 'sitemap.html'), sitemapHtml, 'utf8');

  return {
    providerCount: providers.length,
    cityCount: cities.length,
    stateCount: stateList.length,
    blogCount: blogPosts.length
  };
}

(async () => {
  try {
    const result = await generateStaticPages();
    console.log(`Generated static SEO pages: ${result.cityCount} city pages, ${result.stateCount} state pages, ${result.blogCount} blog pages, ${result.providerCount} providers.`);
  } catch (err) {
    console.error('Failed generating static SEO pages:', err);
    process.exitCode = 1;
  } finally {
    await prisma.$disconnect();
  }
})();
