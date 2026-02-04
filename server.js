require('dotenv').config();
const express = require('express');
const path = require('path');
const crypto = require('crypto');
const { v4: uuid } = require('uuid');
const fetch = (...args) => import('node-fetch').then(({ default: fetch }) => fetch(...args));
const { PrismaClient } = require('@prisma/client');
const { sendProviderNotifications, sendTestEmail, sendGenericEmail, emailEnabled } = require('./email');
const { sendProviderSms, smsEnabled } = require('./sms');
const Stripe = require('stripe');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const prisma = new PrismaClient();
const stripe = process.env.STRIPE_SECRET_KEY ? Stripe(process.env.STRIPE_SECRET_KEY) : null;

const PORT = process.env.PORT || 8080;
const ADMIN_TOKEN_ADD = process.env.ADMIN_TOKEN_ADD || 'TimetoProvideHelp12!';
const ADMIN_TOKEN_REMOVE = process.env.ADMIN_TOKEN_REMOVE || 'this221isHow45!toRemove398Them34!';
const ADMIN_TOKEN_DASH = process.env.ADMIN_TOKEN_DASH || 'lookForProviders177Now73!';
const ADMIN_TOKEN_AUDIT = process.env.ADMIN_TOKEN_AUDIT || ADMIN_TOKEN_DASH;
const TURNSTILE_SECRET_KEY = process.env.TURNSTILE_SECRET_KEY || process.env.TURNSTILE_SECRET || '';
const TURNSTILE_BYPASS = process.env.TURNSTILE_BYPASS === 'true';
const TURNSTILE_SITE_KEY = process.env.TURNSTILE_SITE_KEY || '';
const RATE_LIMIT_PER_WINDOW = 5;
const RATE_LIMIT_WINDOW_MS = 2 * 60 * 60 * 1000; // 2 hours
const IP_SALT = process.env.IP_SALT || 'besthospice-salt';
const EMAIL_ENABLED = emailEnabled();
const PROVIDER_JWT_SECRET = process.env.PROVIDER_JWT_SECRET || 'change-this-provider-secret';
const DASHBOARD_VERIFY_URL = process.env.DASHBOARD_VERIFY_URL || 'https://www.besthospice.com/provider-dashboard.html';
const PROVIDER_PLAN_DEFAULT = 'active';
const normalizePlanTier = (value) => {
  const tier = String(value || '').trim().toLowerCase();
  if (tier === 'verified' || tier === 'featured' || tier === 'priority') return tier;
  if (tier === 'market_leader' || tier === 'advanced') return 'priority';
  if (tier === 'growth_plus') return 'featured';
  if (tier === 'growth' || tier === 'starter') return 'verified';
  return 'verified';
};
const PROVIDER_MONTHLY_RATE = 250;
const PLAN_NOTIFY_DELAY_MS = { priority: 0, featured: 60 * 1000, verified: 120 * 1000 };
const JOB_POLL_MS = 5000;
const JOB_LOCK_TIMEOUT_MS = 5 * 60 * 1000;
const JOB_MAX_ATTEMPTS = 3;
const JOB_RETRY_DELAY_MS = 5 * 60 * 1000;

// --- SEO / programmatic helpers ---
const slugify = (str) =>
  String(str || '')
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 80);

const serviceConfig = {
  'hospice-care': {
    name: 'Hospice Care',
    direct:
      'Hospice care in {cityState} focuses on comfort, dignity, and quality of life when curative treatment is no longer the focus. Families want fast access to compassionate teams, clear communication, and dependable support at home or in a facility.',
    cost: 'Most hospice care in {stateName} is covered by Medicare and many private insurers. Out-of-pocket costs are often limited to supplies or room-and-board in certain facilities. Providers typically handle eligibility and coverage checks for you.',
    eligibility:
      'Hospice is chosen when comfort is the priority. Families look for relief from pain, breathlessness, anxiety, and a clear plan for the final stages. A licensed provider confirms eligibility and coordinates services.',
    faq: [
      ['What does hospice mean?', 'Hospice centers on comfort, dignity, and family support near the end of life.'],
      ['Is hospice only at home?', 'Hospice can be provided at home, in assisted living, or in inpatient facilities.'],
      ['How fast can care start?', 'Many providers can begin services within 24–48 hours after eligibility is confirmed.'],
      ['Does Medicare cover hospice?', 'Yes, Medicare typically covers hospice services; many private plans do as well.'],
      ['Who is on the hospice team?', 'Nurses, aides, social workers, chaplains, and physicians collaborate to support the family.']
    ]
  },
  'palliative-care': {
    name: 'Palliative Care',
    direct:
      'Palliative care in {cityState} supports comfort and quality of life at any stage of serious illness, alongside curative treatments. Families want symptom relief, care coordination, and emotional support without stopping ongoing care.',
    cost: 'Coverage for palliative care in {stateName} varies by insurer and plan. Many services are covered under standard medical benefits; providers can verify your specific benefits.',
    eligibility:
      'Palliative care is appropriate at any stage of serious illness when extra support for symptoms, stress, or decision-making is needed. A licensed provider confirms eligibility.',
    faq: [
      ['How is palliative different from hospice?', 'Palliative can be provided at any stage alongside treatments; hospice is for when comfort is the primary goal.'],
      ['Can I keep my current doctors?', 'Yes. Palliative teams coordinate with your existing doctors to support you.'],
      ['What symptoms can palliative help with?', 'Pain, breathlessness, nausea, fatigue, anxiety, and more.'],
      ['Is palliative covered by insurance?', 'Many plans cover palliative visits; providers can check your benefits.'],
      ['Does palliative require stopping treatment?', 'No. You can continue treatments while receiving palliative support.']
    ]
  },
  'home-care': {
    name: 'Home Care',
    direct:
      'Home care in {cityState} focuses on daily living support so people can remain at home. Families seek help with bathing, mobility, meals, companionship, and basic health oversight.',
    cost: 'Home care coverage in {stateName} depends on insurance and service type. Some services are private-pay; others may be covered under long-term care or specific medical benefits.',
    eligibility:
      'Home care is chosen when daily living help is needed. A provider will clarify which services are available and how they are funded.',
    faq: [
      ['What does home care include?', 'Help with bathing, dressing, meals, light housekeeping, mobility, and companionship.'],
      ['Is home care medical?', 'Non-medical home care focuses on daily living support; some agencies also offer skilled services.'],
      ['How often can visits occur?', 'Visits can range from a few hours to live-in support, depending on your needs and agency.'],
      ['Is home care covered?', 'Some policies cover parts of home care; many services are private-pay. Agencies can verify benefits.'],
      ['Can I combine home care with hospice or palliative?', 'Yes, daily living support can complement hospice or palliative teams.']
    ]
  }
};

const stateNameMap = {
  al: 'Alabama', ak: 'Alaska', az: 'Arizona', ar: 'Arkansas', ca: 'California', co: 'Colorado', ct: 'Connecticut',
  de: 'Delaware', fl: 'Florida', ga: 'Georgia', hi: 'Hawaii', id: 'Idaho', il: 'Illinois', in: 'Indiana', ia: 'Iowa',
  ks: 'Kansas', ky: 'Kentucky', la: 'Louisiana', me: 'Maine', md: 'Maryland', ma: 'Massachusetts', mi: 'Michigan',
  mn: 'Minnesota', ms: 'Mississippi', mo: 'Missouri', mt: 'Montana', ne: 'Nebraska', nv: 'Nevada', nh: 'New Hampshire',
  nj: 'New Jersey', nm: 'New Mexico', ny: 'New York', nc: 'North Carolina', nd: 'North Dakota', oh: 'Ohio', ok: 'Oklahoma',
  or: 'Oregon', pa: 'Pennsylvania', ri: 'Rhode Island', sc: 'South Carolina', sd: 'South Dakota', tn: 'Tennessee', tx: 'Texas',
  ut: 'Utah', vt: 'Vermont', va: 'Virginia', wa: 'Washington', wv: 'West Virginia', wi: 'Wisconsin', wy: 'Wyoming'
};

function formatDateISO(dt = new Date()) {
  return dt.toISOString().split('T')[0];
}
// Basic PHI keyword detector (lightweight guardrail)
function maybePhi(text) {
  if (!text) return false;
  const lower = text.toLowerCase();
  const phiKeywords = ['diagnosis', 'medication', 'prescription', 'ssn', 'social security', 'mrn', 'medical record', 'hipaa', 'treatment', 'symptom', 'disease', 'blood pressure'];
  return phiKeywords.some((k) => lower.includes(k));
}

// Stripe webhook needs raw body
app.post('/api/stripe/webhook', express.raw({ type: 'application/json' }), async (req, res) => {
  if (!stripe || !process.env.STRIPE_WEBHOOK_SECRET) {
    return res.status(500).send('Stripe not configured');
  }
  const sig = req.headers['stripe-signature'];
  let event;
  try {
    event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET);
  } catch (err) {
    console.error('Stripe webhook signature verification failed', err);
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  try {
    if (event.type === 'checkout.session.completed') {
      const session = event.data.object;
      const providerId = session.metadata?.providerId;
      if (providerId) {
        await prisma.provider.update({
          where: { id: providerId },
          data: { featured: true }
        });
      }
    }
    res.json({ received: true });
  } catch (err) {
    console.error('Stripe webhook handling failed', err);
    res.status(500).send('Webhook handler error');
  }
});

app.use(express.json());
app.use(express.static(__dirname));

// Provider auth helper
function requireProviderAuth(req, res, next) {
  const auth = req.headers['authorization'];
  if (!auth || !auth.toLowerCase().startsWith('bearer ')) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  const token = auth.slice(7);
  try {
    const payload = jwt.verify(token, PROVIDER_JWT_SECRET);
    req.providerUserId = payload.sub;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

async function getProviderContext(providerUserId) {
  if (!providerUserId) return null;
  const user = await prisma.providerUser.findUnique({
    where: { id: providerUserId },
    include: {
      activeProvider: true,
      links: {
        include: { provider: true }
      }
    }
  });
  if (!user || !user.links || !user.links.length) return null;
  let providerId = user.activeProviderId;
  if (!providerId) {
    providerId = user.links[0].providerId;
    await prisma.providerUser.update({ where: { id: user.id }, data: { activeProviderId: providerId } });
  }
  const provider = user.links.find((l) => l.providerId === providerId)?.provider;
  if (!provider) return null;
  return {
    providerId,
    provider,
    providerUserId: user.id,
    providers: user.links.map((l) => l.provider)
  };
}

function hashIp(ip) {
  return crypto.createHash('sha256').update(`${IP_SALT}:${ip || ''}`).digest('hex');
}

function buildClientName(first, last) {
  return [first || '', last || ''].filter(Boolean).join(' ').trim() || 'Not provided';
}

async function claimNotificationJobs(limit = 10) {
  const now = new Date();
  const expiredLock = new Date(now.getTime() - JOB_LOCK_TIMEOUT_MS);
  const candidates = await prisma.notificationJob.findMany({
    where: {
      status: 'pending',
      runAt: { lte: now },
      OR: [{ lockedAt: null }, { lockedAt: { lt: expiredLock } }]
    },
    orderBy: { runAt: 'asc' },
    take: limit
  });
  if (!candidates.length) return [];
  const ids = candidates.map((c) => c.id);
  await prisma.notificationJob.updateMany({
    where: { id: { in: ids }, status: 'pending' },
    data: { status: 'processing', lockedAt: now }
  });
  return prisma.notificationJob.findMany({
    where: { id: { in: ids }, status: 'processing', lockedAt: now }
  });
}

async function processNotificationJob(job) {
  const payload = job.payload || {};
  const providerEmail = payload.providerEmail;
  const providerPhone = payload.providerPhone;
  let emailResult = { status: 'failed', error: 'Missing provider email' };

  if (providerEmail) {
    try {
      const results = await sendProviderNotifications({
        clientZip: payload.clientZip,
        requestSubmittedBy: payload.requestSubmittedBy,
        careDaysAndTimes: payload.careDaysAndTimes,
        services: payload.services,
        funding: payload.funding,
        otherDetails: payload.otherDetails,
        clientEmail: payload.clientEmail,
        clientPhone: payload.clientPhone,
        clientName: payload.clientName,
        providers: [{ id: job.providerId, email: providerEmail }],
        nearbyProviders: [{ id: job.providerId, email: providerEmail }]
      });
      emailResult = results?.[0] || { status: 'failed', error: 'SendGrid returned no result' };
    } catch (err) {
      console.error('Email notification failed', err);
      emailResult = { status: 'failed', error: err.message || 'send failed' };
    }
  }

  if (smsEnabled() && providerPhone) {
    const smsBody = [
      `Best Hospice lead (ZIP ${payload.clientZip})`,
      `Submitted by: ${payload.requestSubmittedBy}`,
      `Care: ${payload.careDaysAndTimes}`,
      `Funding: ${payload.funding || 'Not specified'}`,
      `Contact: ${payload.clientName}, ${payload.clientEmail}, ${payload.clientPhone}`,
      `Please reach out promptly.`
    ].join('\n');
    try {
      await sendProviderSms(providerPhone, smsBody);
    } catch (err) {
      console.error('SMS send failed for', providerPhone, err);
    }
  }

  if (emailResult && emailResult.email) {
    const status = emailResult.status === 'sent' ? 'sent' : 'failed';
    await prisma.leadNotification.create({
      data: {
        id: uuid(),
        leadId: job.leadId,
        providerId: job.providerId,
        status,
        sendgridMessageId: emailResult.messageId || null,
        errorMessage: emailResult.error || null,
        sentAt: status === 'sent' ? new Date() : null
      }
    });
    if (status === 'sent') {
      await prisma.provider.update({
        where: { id: job.providerId },
        data: { leadCount: { increment: 1 } }
      });
    }
  }

  if (emailResult.status === 'sent') {
    await prisma.notificationJob.update({
      where: { id: job.id },
      data: { status: 'sent', lastError: null }
    });
    return;
  }

  const nextAttempts = (job.attempts || 0) + 1;
  if (nextAttempts < JOB_MAX_ATTEMPTS) {
    await prisma.notificationJob.update({
      where: { id: job.id },
      data: {
        status: 'pending',
        attempts: nextAttempts,
        lastError: emailResult.error || 'send failed',
        lockedAt: null,
        runAt: new Date(Date.now() + JOB_RETRY_DELAY_MS)
      }
    });
  } else {
    await prisma.notificationJob.update({
      where: { id: job.id },
      data: {
        status: 'failed',
        attempts: nextAttempts,
        lastError: emailResult.error || 'send failed'
      }
    });
  }
}

let jobWorkerRunning = false;
async function runNotificationWorker() {
  if (jobWorkerRunning) return;
  jobWorkerRunning = true;
  try {
    const jobs = await claimNotificationJobs(25);
    for (const job of jobs) {
      await processNotificationJob(job);
    }
  } catch (err) {
    console.error('Notification worker error', err);
  } finally {
    jobWorkerRunning = false;
  }
}

setInterval(() => {
  runNotificationWorker().catch(() => {});
}, JOB_POLL_MS);

async function rateLimit(req, res, next) {
  try {
    const ipHash = hashIp(req.ip || '');
    const cutoff = new Date(Date.now() - RATE_LIMIT_WINDOW_MS);
    const count = await prisma.rateLimitEvent.count({
      where: {
        ipHash,
        createdAt: { gte: cutoff }
      }
    });
    if (count >= RATE_LIMIT_PER_WINDOW) {
      return res.status(429).json({ error: 'Too many submissions. Please try again later.' });
    }
    await prisma.rateLimitEvent.create({ data: { id: uuid(), ipHash } });
    next();
  } catch (err) {
    console.error('Rate limit check failed', err);
    res.status(500).json({ error: 'Server error' });
  }
}

async function verifyTurnstile(token, ip) {
  if (TURNSTILE_BYPASS) return { success: true, bypass: true };
  if (!TURNSTILE_SECRET_KEY) return { success: false, error: 'Missing TURNSTILE_SECRET_KEY' };
  if (!token) return { success: false, error: 'Missing captcha token' };
  const form = new URLSearchParams();
  form.append('secret', TURNSTILE_SECRET_KEY);
  form.append('response', token);
  if (ip) form.append('remoteip', ip);
  try {
    const resp = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: form.toString()
    });
    if (!resp.ok) return { success: false, error: 'Turnstile verify request failed' };
    const data = await resp.json();
    return data;
  } catch (err) {
    console.error('Turnstile verify failed', err);
    return { success: false, error: 'Turnstile verify exception' };
  }
}

async function geocodeAddress(addressString) {
  const headers = { 'Accept-Language': 'en', 'User-Agent': 'BestHospice/1.0 (admin@besthospice.com)' };
  const queries = [
    {
      url: `https://nominatim.openstreetmap.org/search?format=json&q=${encodeURIComponent(addressString)}&limit=1`,
      parse: async (resp) => {
        const data = await resp.json();
        if (Array.isArray(data) && data.length) {
          return { lat: Number(data[0].lat), lon: Number(data[0].lon) };
        }
        return null;
      }
    },
    {
      url: `https://photon.komoot.io/api/?q=${encodeURIComponent(addressString)}&limit=1`,
      parse: async (resp) => {
        const data = await resp.json();
        if (data && Array.isArray(data.features) && data.features.length) {
          const coords = data.features[0]?.geometry?.coordinates;
          if (Array.isArray(coords) && coords.length >= 2) {
            return { lon: Number(coords[0]), lat: Number(coords[1]) };
          }
        }
        return null;
      }
    }
  ];

  for (const q of queries) {
    try {
      const response = await fetch(q.url, { headers });
      if (!response.ok) continue;
      const result = await q.parse(response);
      if (result && !Number.isNaN(result.lat) && !Number.isNaN(result.lon)) {
        return result;
      }
    } catch (err) {
      console.error('Geocode provider failed', err);
      continue;
    }
  }
  return null;
}

async function logAdminAction(adminIdentifier, action, targetId, metadata, ipHash) {
  try {
    await prisma.adminAuditLog.create({
      data: {
        id: uuid(),
        adminIdentifier,
        action,
        targetType: 'provider',
        targetId,
        metadataJson: metadata ? JSON.stringify(metadata) : null,
        ipHash: ipHash || null
      }
    });
  } catch (err) {
    console.error('Audit log failed', err);
  }
}

// ---------- SEO helper functions ----------
const CANONICAL_DOMAIN = process.env.DOMAIN || 'https://www.besthospice.com';

function providerSlug(provider) {
  return `${slugify(provider.name || 'provider')}-${(provider.id || '').slice(0, 8)}`;
}

function cityStateString(city, state) {
  const stateName = stateNameMap[(state || '').toLowerCase()] || (state || '').toUpperCase();
  return [city, stateName].filter(Boolean).join(', ');
}

async function fetchAllProviders() {
  return prisma.provider.findMany({
    select: {
      id: true,
      name: true,
      address: true,
      city: true,
      state: true,
      zip: true,
      phone: true,
      website: true,
      email: true,
      featured: true,
      createdAt: true
    }
  });
}

async function providersByLocation(city, state) {
  return prisma.provider.findMany({
    where: {
      city: { equals: city, mode: 'insensitive' },
      state: { equals: state, mode: 'insensitive' }
    },
    orderBy: { featured: 'desc' }
  });
}

function renderBreadcrumbList(items) {
  return {
    '@context': 'https://schema.org',
    '@type': 'BreadcrumbList',
    itemListElement: items.map((item, idx) => ({
      '@type': 'ListItem',
      position: idx + 1,
      name: item.name,
      item: item.url
    }))
  };
}

function renderFAQSchema(faqs) {
  return {
    '@context': 'https://schema.org',
    '@type': 'FAQPage',
    mainEntity: faqs.map(([q, a]) => ({
      '@type': 'Question',
      name: q,
      acceptedAnswer: { '@type': 'Answer', text: a }
    }))
  };
}

function renderProviderSchema(provider) {
  return {
    '@context': 'https://schema.org',
    '@type': 'MedicalOrganization',
    name: provider.name,
    url: `${CANONICAL_DOMAIN}/provider/${providerSlug(provider)}`,
    address: provider.address,
    telephone: provider.phone || undefined,
    areaServed: provider.state || undefined
  };
}

function nearbyCityLinks(city, state) {
  if (!city || !state) return [];
  return [
    { name: `More providers in ${state.toUpperCase()}`, url: `${CANONICAL_DOMAIN}/hospice-care/${state.toLowerCase()}` },
    { name: `Palliative care in ${city}, ${state.toUpperCase()}`, url: `${CANONICAL_DOMAIN}/palliative-care/${slugify(city)}-${state.toLowerCase()}` },
    { name: `Home care in ${city}, ${state.toUpperCase()}`, url: `${CANONICAL_DOMAIN}/home-care/${slugify(city)}-${state.toLowerCase()}` }
  ];
}

function renderProviderList(providers) {
  if (!providers?.length) {
    return '<p>No providers listed yet for this area. We are expanding our network—check back soon.</p>';
  }
  return providers
    .map(
      (p) => `
      <div class="provider-card">
        <h3>${p.name}</h3>
        <p>${p.address}</p>
        <p>${p.phone ? `Phone: ${p.phone}` : ''}</p>
        ${p.website ? `<p><a href="${p.website}" rel="nofollow">Website</a></p>` : ''}
      </div>`
    )
    .join('\n');
}

function renderComparisonTable() {
  return `
    <table class="compare">
      <thead><tr><th></th><th>Hospice</th><th>Palliative</th><th>Home Care</th></tr></thead>
      <tbody>
        <tr><td>When used</td><td>Comfort near end of life</td><td>Any stage of serious illness</td><td>Daily living support</td></tr>
        <tr><td>Can include medical team</td><td>Yes</td><td>Yes</td><td>Sometimes (skilled visits)</td></tr>
        <tr><td>Works with curative treatment</td><td>No</td><td>Yes</td><td>Yes</td></tr>
      </tbody>
    </table>
  `;
}

function renderTrustBlock(dateStr) {
  return `
    <section class="trust">
      <h2>Reviewed for clarity</h2>
      <p>Reviewed by the Best Hospice Clinical Review Team.</p>
      <p>Last updated: ${dateStr}</p>
      <p>Sources: Medicare.gov, CMS, NIH.</p>
    </section>
  `;
}

function renderPageHTML({ title, description, canonical, breadcrumbItems, body, faqSchema, providerSchemas = [] }) {
  const jsonLd = [];
  if (breadcrumbItems?.length) jsonLd.push(renderBreadcrumbList(breadcrumbItems));
  if (faqSchema) jsonLd.push(faqSchema);
  if (providerSchemas?.length) {
    providerSchemas.forEach((p) => jsonLd.push(renderProviderSchema(p)));
  }
  return `<!DOCTYPE html>
  <html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>${title}</title>
    <meta name="description" content="${description}" />
    <link rel="canonical" href="${canonical}" />
    <link rel="stylesheet" href="/styles-modern.css" />
    <!-- Meta Pixel Code --><script>!function(f,b,e,v,n,t,s){if(f.fbq)return;n=f.fbq=function(){n.callMethod?n.callMethod.apply(n,arguments):n.queue.push(arguments)};if(!f._fbq)f.fbq=n;n.push=n;n.loaded=!0;n.version='2.0';n.queue=[];t=b.createElement(e);t.async=!0;t.src=v;s=b.getElementsByTagName(e)[0];s.parentNode.insertBefore(t,s)}(window,document,'script','https://connect.facebook.net/en_US/fbevents.js'); fbq('init', '4311998169024976'); fbq('track', 'PageView');</script><noscript> <img height="1" width="1" src="https://www.facebook.com/tr?id=4311998169024976&ev=PageView&noscript=1"/></noscript><!-- End Meta Pixel Code -->
    <script type="application/ld+json">${JSON.stringify(jsonLd)}</script>
  </head>
  <body class="seo-page">
    <header><a href="/index.html">Best Hospice</a></header>
    <main>${body}</main>
    <footer><p>Best Hospice — connecting families to trusted hospice, palliative, and home care providers.</p></footer>
  </body>
  </html>`;
}

function renderCityPage({ serviceKey, city, state, providers = [] }) {
  const service = serviceConfig[serviceKey];
  const cityState = cityStateString(city, state);
  const stateName = stateNameMap[(state || '').toLowerCase()] || (state || '').toUpperCase();
  const title = `${service.name} in ${cityState} | Providers, Cost & Eligibility`;
  const description = `${service.name} options in ${cityState}. Providers, costs, and what to expect.`;
  const canonical = `${CANONICAL_DOMAIN}/${serviceKey}/${slugify(city)}-${(state || '').toLowerCase()}`;
  const breadcrumbItems = [
    { name: 'Home', url: `${CANONICAL_DOMAIN}/index.html` },
    { name: service.name, url: `${CANONICAL_DOMAIN}/${serviceKey}` },
    { name: stateName, url: `${CANONICAL_DOMAIN}/${serviceKey}/${(state || '').toLowerCase()}` },
    { name: cityState, url: canonical }
  ];
  const faqSchema = renderFAQSchema(service.faq || []);
  const providerSchemas = providers.slice(0, 10);

  const body = `
    <section>
      <h1>${service.name} in ${cityState}: Providers, Cost & Eligibility</h1>
      <p>${service.direct.replace('{cityState}', cityState)}</p>
      <div class="direct-answer">
        <strong>Direct answer:</strong> ${service.direct.replace('{cityState}', cityState)}
      </div>
    </section>
    <section>
      <h2>${service.name} Providers in ${cityState}</h2>
      ${renderProviderList(providers)}
    </section>
    <section>
      <h2>Cost & Coverage</h2>
      <p>${service.cost.replace('{stateName}', stateName)}</p>
    </section>
    <section>
      <h2>When to Choose ${service.name}</h2>
      <p>${service.eligibility}</p>
    </section>
    <section>
      <h2>Compare Hospice, Palliative, and Home Care</h2>
      ${renderComparisonTable()}
    </section>
    <section>
      <h2>FAQs</h2>
      <ul>${(service.faq || [])
        .map(([q, a]) => `<li><strong>${q}</strong><br>${a}</li>`)
        .join('')}</ul>
    </section>
    ${renderTrustBlock(formatDateISO())}
    <section>
      <h3>Explore more</h3>
      <ul>
        ${nearbyCityLinks(city, state)
          .map((l) => `<li><a href="${l.url}">${l.name}</a></li>`)
          .join('')}
      </ul>
    </section>
  `;
  return renderPageHTML({ title, description, canonical, breadcrumbItems, body, faqSchema, providerSchemas });
}

function renderStatePage({ serviceKey, state, providers = [] }) {
  const service = serviceConfig[serviceKey];
  const stateName = stateNameMap[(state || '').toLowerCase()] || (state || '').toUpperCase();
  const title = `${service.name} in ${stateName} | Providers, Cost & Eligibility`;
  const description = `${service.name} options across ${stateName}. Providers, costs, and what to expect.`;
  const canonical = `${CANONICAL_DOMAIN}/${serviceKey}/${(state || '').toLowerCase()}`;
  const breadcrumbItems = [
    { name: 'Home', url: `${CANONICAL_DOMAIN}/index.html` },
    { name: service.name, url: `${CANONICAL_DOMAIN}/${serviceKey}` },
    { name: stateName, url: canonical }
  ];
  const faqSchema = renderFAQSchema(service.faq || []);
  const providerSchemas = providers.slice(0, 10);
  const cities = Array.from(new Set(providers.map((p) => p.city))).filter(Boolean).slice(0, 20);
  const body = `
    <section>
      <h1>${service.name} in ${stateName}</h1>
      <p>${service.direct.replace('{cityState}', stateName)}</p>
    </section>
    <section>
      <h2>Top Providers in ${stateName}</h2>
      ${renderProviderList(providers.slice(0, 20))}
    </section>
    <section>
      <h2>Browse cities in ${stateName}</h2>
      <ul>${cities
        .map((c) => `<li><a href="${CANONICAL_DOMAIN}/${serviceKey}/${slugify(c)}-${(state || '').toLowerCase()}">${c}, ${state.toUpperCase()}</a></li>`)
        .join('')}</ul>
    </section>
    <section>
      <h2>Cost & Coverage</h2>
      <p>${service.cost.replace('{stateName}', stateName)}</p>
    </section>
    <section>
      <h2>When to Choose ${service.name}</h2>
      <p>${service.eligibility}</p>
    </section>
    <section>
      <h2>Compare Hospice, Palliative, and Home Care</h2>
      ${renderComparisonTable()}
    </section>
    <section>
      <h2>FAQs</h2>
      <ul>${(service.faq || [])
        .map(([q, a]) => `<li><strong>${q}</strong><br>${a}</li>`)
        .join('')}</ul>
    </section>
    ${renderTrustBlock(formatDateISO())}
  `;
  return renderPageHTML({ title, description, canonical, breadcrumbItems, body, faqSchema, providerSchemas });
}

function renderHubPage({ serviceKey }) {
  const service = serviceConfig[serviceKey];
  const title = `${service.name} | How It Works, Eligibility, Costs`;
  const description = `${service.name} basics, costs, and eligibility. Find providers near you.`;
  const canonical = `${CANONICAL_DOMAIN}/${serviceKey}`;
  const breadcrumbItems = [
    { name: 'Home', url: `${CANONICAL_DOMAIN}/index.html` },
    { name: service.name, url: canonical }
  ];
  const faqSchema = renderFAQSchema(service.faq || []);
  const body = `
    <section>
      <h1>${service.name}</h1>
      <p>${service.direct.replace('{cityState}', 'your area')}</p>
    </section>
    <section>
      <h2>Find providers by state</h2>
      <ul>${Object.keys(stateNameMap)
        .map((s) => `<li><a href="${CANONICAL_DOMAIN}/${serviceKey}/${s}">${stateNameMap[s]}</a></li>`)
        .join('')}</ul>
    </section>
    <section>
      <h2>Cost & Coverage</h2>
      <p>${service.cost.replace('{stateName}', 'your state')}</p>
    </section>
    <section>
      <h2>When to Choose ${service.name}</h2>
      <p>${service.eligibility}</p>
    </section>
    <section>
      <h2>FAQs</h2>
      <ul>${(service.faq || [])
        .map(([q, a]) => `<li><strong>${q}</strong><br>${a}</li>`)
        .join('')}</ul>
    </section>
    ${renderComparisonTable()}
    ${renderTrustBlock(formatDateISO())}
  `;
  return renderPageHTML({ title, description, canonical, breadcrumbItems, body, faqSchema, providerSchemas: [] });
}

function renderProviderPage(provider) {
  const slug = providerSlug(provider);
  const cityState = cityStateString(provider.city, provider.state);
  const title = `${provider.name} | Hospice, Palliative, Home Care in ${cityState}`;
  const description = `${provider.name} serves ${cityState}. Contact info, address, and services.`;
  const canonical = `${CANONICAL_DOMAIN}/provider/${slug}`;
  const breadcrumbItems = [
    { name: 'Home', url: `${CANONICAL_DOMAIN}/index.html` },
    { name: cityState, url: `${CANONICAL_DOMAIN}/hospice-care/${slugify(provider.city)}-${(provider.state || '').toLowerCase()}` },
    { name: provider.name, url: canonical }
  ];
  const faqSchema = renderFAQSchema([
    ['How do I contact this provider?', `Phone: ${provider.phone || 'Not provided'}. Website: ${provider.website || 'Not provided'}.`],
    ['Where are they located?', provider.address || `${cityState}`]
  ]);
  const body = `
    <section>
      <h1>${provider.name}</h1>
      <p>${provider.address || cityState}</p>
      ${provider.phone ? `<p>Phone: ${provider.phone}</p>` : ''}
      ${provider.website ? `<p><a href="${provider.website}" rel="nofollow">Website</a></p>` : ''}
      <p>Serving hospice, palliative, and home care needs in ${cityState}.</p>
    </section>
    ${renderTrustBlock(formatDateISO())}
  `;
  return renderPageHTML({ title, description, canonical, breadcrumbItems, body, faqSchema, providerSchemas: [provider] });
}
function toSubmittedBy(relationship) {
  if (relationship === 'me') return 'TheClient';
  if (relationship === 'loved-one') return 'A_Loved_One';
  return 'Other';
}

app.get('/api/providers', async (_req, res) => {
  const providers = await prisma.provider.findMany({
    select: {
      id: true,
      name: true,
      email: true,
      phone: true,
      website: true,
      address: true,
      city: true,
      state: true,
      zip: true,
      lat: true,
      lon: true,
      serviceRadiusKm: true,
      featured: true,
      planTier: true,
      leadCount: true,
      createdAt: true,
      updatedAt: true
    }
  });
  res.json(providers);
});

// Create a checkout session using provider email (case-insensitive)
app.post('/api/providers/email/checkout', async (req, res) => {
  if (!stripe || !process.env.STRIPE_SUCCESS_URL || !process.env.STRIPE_CANCEL_URL) {
    return res.status(500).json({ error: 'Stripe is not fully configured.' });
  }
  const { email, plan } = req.body || {};
  if (!email) return res.status(400).json({ error: 'Email is required' });
  try {
    const provider = await prisma.provider.findFirst({
      where: { email: { equals: email, mode: 'insensitive' } }
    });
    if (!provider) return res.status(404).json({ error: 'Provider not found' });

    const planPrices = {
      verified: process.env.STRIPE_PRICE_ID_VERIFIED || process.env.STRIPE_PRICE_ID_GROWTH,
      featured: process.env.STRIPE_PRICE_ID_FEATURED || process.env.STRIPE_PRICE_ID_ADVANCED,
      priority: process.env.STRIPE_PRICE_ID_PRIORITY || process.env.STRIPE_PRICE_ID_MARKET_LEADER
    };
    const normalizedPlan = normalizePlanTier(plan);
    const priceId = planPrices[normalizedPlan] || process.env.STRIPE_PRICE_ID;
    if (!priceId) {
      return res.status(500).json({ error: 'Stripe price is not configured.' });
    }

    const customer = await stripe.customers.create({
      email: provider.email,
      name: provider.name
    });

    const session = await stripe.checkout.sessions.create({
      mode: 'subscription',
      customer: customer.id,
      line_items: [{ price: priceId, quantity: 1 }],
      success_url: process.env.STRIPE_SUCCESS_URL,
      cancel_url: process.env.STRIPE_CANCEL_URL,
      metadata: { providerId: provider.id, plan: normalizedPlan || 'verified' }
    });
    res.json({ url: session.url });
  } catch (err) {
    console.error('Email checkout session failed', err);
    res.status(500).json({ error: 'Checkout session failed' });
  }
});

app.get('/api/config/turnstile', (_req, res) => {
  if (!TURNSTILE_SITE_KEY) return res.status(500).json({ error: 'Turnstile site key not configured' });
  res.json({ siteKey: TURNSTILE_SITE_KEY });
});

// Provider identity
app.get('/api/provider/me', requireProviderAuth, async (req, res) => {
  try {
    const ctx = await getProviderContext(req.providerUserId);
    if (!ctx) return res.status(401).json({ error: 'Unauthorized' });
    const planStatus = ctx.provider?.planStatus || 'active';
    res.json({
      ok: true,
      providerId: ctx.providerId,
      providerName: ctx.provider?.name || '',
      providerEmail: ctx.provider?.email || '',
      planStatus
    });
    await logAdminAction('provider_user', 'PROVIDER_AI_ACCOUNT', ctx.providerId, {}, hashIp(req.ip || ''));
  } catch (err) {
    console.error('Provider me failed', err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/providers/secure', async (req, res) => {
  const token = req.headers['x-admin-token'];
  if (token !== ADMIN_TOKEN_DASH) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  const providers = await prisma.provider.findMany();
  res.json(providers);
});

app.post('/api/providers/:id/checkout', async (req, res) => {
  if (!stripe || !process.env.STRIPE_SUCCESS_URL || !process.env.STRIPE_CANCEL_URL) {
    return res.status(500).json({ error: 'Stripe is not fully configured.' });
  }
  const providerId = req.params.id;
  const { plan } = req.body || {};
  try {
    const provider = await prisma.provider.findUnique({ where: { id: providerId } });
    if (!provider) return res.status(404).json({ error: 'Provider not found' });

    const planPrices = {
      verified: process.env.STRIPE_PRICE_ID_VERIFIED || process.env.STRIPE_PRICE_ID_GROWTH,
      featured: process.env.STRIPE_PRICE_ID_FEATURED || process.env.STRIPE_PRICE_ID_ADVANCED,
      priority: process.env.STRIPE_PRICE_ID_PRIORITY || process.env.STRIPE_PRICE_ID_MARKET_LEADER
    };
    const normalizedPlan = normalizePlanTier(plan);
    const priceId = planPrices[normalizedPlan] || process.env.STRIPE_PRICE_ID;
    if (!priceId) {
      return res.status(500).json({ error: 'Stripe price is not configured.' });
    }

    const customer = await stripe.customers.create({
      email: provider.email,
      name: provider.name
    });

    const session = await stripe.checkout.sessions.create({
      mode: 'subscription',
      customer: customer.id,
      line_items: [{ price: priceId, quantity: 1 }],
      success_url: process.env.STRIPE_SUCCESS_URL,
      cancel_url: process.env.STRIPE_CANCEL_URL,
      metadata: { providerId: provider.id, plan: normalizedPlan || 'verified' }
    });
    res.json({ url: session.url });
  } catch (err) {
    console.error('Create checkout session failed', err);
    res.status(500).json({ error: 'Checkout session failed' });
  }
});

app.post('/api/providers', async (req, res) => {
  const token = req.headers['x-admin-token'];
  const adminIdentifier = token === ADMIN_TOKEN_ADD ? 'add_token' : token === ADMIN_TOKEN_REMOVE ? 'remove_token' : 'unknown';
  if (token !== ADMIN_TOKEN_ADD && token !== ADMIN_TOKEN_REMOVE) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  const {
    name,
    address,
    city,
    state,
    zip,
    lat,
    lon,
    serviceRadiusKm,
    serviceRadiusMiles,
    email,
    providerLoginEmail,
    phone,
    website,
    featured = false,
    planTier
    ,
  } = req.body || {};
  if (!name || !address || !city || !state || !zip || !email) {
    return res.status(400).json({ error: 'Missing required fields (name, address, city, state, zip, email).' });
  }
  const radiusKmFromMiles = serviceRadiusMiles ? Number(serviceRadiusMiles) * 1.60934 : undefined;
  let latVal = lat !== undefined ? Number(lat) : undefined;
  let lonVal = lon !== undefined ? Number(lon) : undefined;
  const fullAddress = `${address}, ${city}, ${state} ${zip}`;
  if ((latVal === undefined || Number.isNaN(latVal) || lonVal === undefined || Number.isNaN(lonVal))) {
    try {
      const geo = await geocodeAddress(fullAddress);
      if (!geo) return res.status(400).json({ error: 'Could not geocode address. Please check address details.' });
      latVal = geo.lat;
      lonVal = geo.lon;
    } catch (err) {
      console.error('Geocode failed', err);
      return res.status(400).json({ error: 'Address lookup failed. Try again.' });
    }
  }
  try {
    const normalizedEmail = String(email).trim();
    const normalizedLoginEmail = String(providerLoginEmail || '').trim() || normalizedEmail;
    const provider = await prisma.provider.create({
      data: {
        id: uuid(),
        name,
        email: normalizedEmail,
        providerLoginEmail: normalizedLoginEmail,
        phone: phone || '',
        website: website || '',
        address: fullAddress,
        city,
        state,
        zip,
        lat: latVal,
        lon: lonVal,
        serviceRadiusKm: radiusKmFromMiles !== undefined ? radiusKmFromMiles : Number(serviceRadiusKm) || 96.6,
        featured: Boolean(featured),
        planTier: normalizePlanTier(planTier)
      }
    });
    await logAdminAction(adminIdentifier, 'PROVIDER_ADD', provider.id, { name: provider.name, email: provider.email }, hashIp(req.ip || ''));
    res.json({ ok: true, provider });
  } catch (err) {
    console.error('Create provider failed', err);
    res.status(500).json({ error: 'Create provider failed' });
  }
});

// Update provider (admin)
app.put('/api/providers/:id', async (req, res) => {
  const token = req.headers['x-admin-token'];
  if (token !== ADMIN_TOKEN_REMOVE && token !== ADMIN_TOKEN_DASH) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  const id = req.params.id;
  const {
    name,
    address,
    city,
    state,
    zip,
    lat,
    lon,
    serviceRadiusKm,
    serviceRadiusMiles,
    email,
    providerLoginEmail,
    phone,
    website,
    featured,
    planTier
  } = req.body || {};
  const data = {};
  if (name !== undefined) data.name = String(name).trim();
  if (email !== undefined) data.email = String(email).trim();
  if (providerLoginEmail !== undefined) {
    const normalizedLoginEmail = String(providerLoginEmail).trim();
    if (normalizedLoginEmail) {
      data.providerLoginEmail = normalizedLoginEmail;
    }
  }
  if (phone !== undefined) data.phone = String(phone).trim();
  if (website !== undefined) data.website = String(website).trim();
  if (address !== undefined || city !== undefined || state !== undefined || zip !== undefined) {
    const a = address !== undefined ? String(address).trim() : undefined;
    const c = city !== undefined ? String(city).trim() : undefined;
    const s = state !== undefined ? String(state).trim() : undefined;
    const z = zip !== undefined ? String(zip).trim() : undefined;
    if (a !== undefined && c !== undefined && s !== undefined && z !== undefined) {
      const suffix = `, ${c}, ${s} ${z}`;
      data.address = a.endsWith(suffix) ? a : `${a}${suffix}`;
      data.city = c;
      data.state = s;
      data.zip = z;
    }
  }
  if (lat !== undefined && lat !== '') {
    const n = Number(lat);
    if (!Number.isNaN(n)) data.lat = n;
  }
  if (lon !== undefined && lon !== '') {
    const n = Number(lon);
    if (!Number.isNaN(n)) data.lon = n;
  }
  if (serviceRadiusMiles !== undefined && serviceRadiusMiles !== '') {
    const n = Number(serviceRadiusMiles);
    if (!Number.isNaN(n) && n >= 0) data.serviceRadiusKm = n * 1.60934;
  } else if (serviceRadiusKm !== undefined && serviceRadiusKm !== '') {
    const n = Number(serviceRadiusKm);
    if (!Number.isNaN(n) && n >= 0) data.serviceRadiusKm = n;
  }
  if (featured !== undefined) data.featured = Boolean(featured);
  if (planTier !== undefined && planTier !== '') data.planTier = normalizePlanTier(planTier);

  if (!Object.keys(data).length) return res.status(400).json({ error: 'No changes provided' });
  try {
    const provider = await prisma.provider.update({ where: { id }, data });
    res.json({ ok: true, provider });
  } catch (err) {
    console.error('Update provider failed', err);
    res.status(500).json({ error: 'Update provider failed' });
  }
});

app.delete('/api/providers/:id', async (req, res) => {
  const token = req.headers['x-admin-token'];
  if (token !== ADMIN_TOKEN_REMOVE) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  const id = req.params.id;
  try {
    const provider = await prisma.provider.findUnique({ where: { id } });
    if (!provider) return res.status(404).json({ error: 'Provider not found' });
    await prisma.$transaction([
      prisma.leadNotification.deleteMany({ where: { providerId: id } }),
      prisma.providerImpression.deleteMany({ where: { providerId: id } }),
      prisma.provider.delete({ where: { id } })
    ]);
    await logAdminAction('remove_token', 'PROVIDER_REMOVE', id, { name: provider.name }, hashIp(req.ip || ''));
    res.json({ ok: true });
  } catch (err) {
    console.error('Remove failed', err);
    res.status(500).json({ error: 'Remove failed' });
  }
});

app.post('/api/notify', rateLimit, async (req, res) => {
  if (!EMAIL_ENABLED) return res.status(500).json({ error: 'Email not configured' });
  try {
    const { zip, answers, providers, captchaToken } = req.body || {};
    if (!zip || !answers || !Array.isArray(providers) || !providers.length) {
      return res.status(400).json({ error: 'Missing zip, answers, or providers list' });
    }
    const captchaResult = await verifyTurnstile(captchaToken, req.ip);
    if (!captchaResult.success) {
      return res.status(403).json({ error: 'Captcha verification failed.', details: captchaResult['error-codes'] || captchaResult.error });
    }

    const toList = providers.filter((p) => !!p.email && !!p.id);
    if (!toList.length) return res.status(400).json({ error: 'No provider emails to notify' });

    const requestSubmittedBy = toSubmittedBy(answers.relationship);
    const careDays = answers.frequency?.days?.length ? answers.frequency.days.join(', ') : 'Not specified';
    const careTimes = answers.frequency?.times?.length ? answers.frequency.times.join(', ') : 'Not specified';
    const careDaysAndTimes = `Days: ${careDays}; Times: ${careTimes}`;
    const services = Array.isArray(answers.services) && answers.services.length ? answers.services : ['Not specified'];
    const funding = answers.funding || 'Not specified';
    const otherDetails = answers.moreDetails || 'Not provided';
    const clientEmail = answers.contactEmail || 'Not provided';
    const clientPhone = answers.contactPhone || 'Not provided';
    const clientFirst = answers.fullName?.first || '';
    const clientLast = answers.fullName?.last || '';
    const clientName = buildClientName(clientFirst, clientLast);

    const lead = await prisma.lead.create({
      data: {
        id: uuid(),
        zip,
        submittedBy: requestSubmittedBy,
        careDays,
        careTimes,
        services: Array.isArray(services) ? services.join('; ') : `${services}`,
        clientEmail,
        clientPhone,
        firstName: clientFirst || null,
        lastName: clientLast || null
      }
    });

    // Log impressions
    const impressionData = toList
      .filter((p) => !!p.id)
      .map((p) => ({
        id: uuid(),
        providerId: p.id,
        leadId: lead.id,
        zip
      }));
    if (impressionData.length) await prisma.providerImpression.createMany({ data: impressionData });

    const providerIds = toList.map((p) => p.id).filter(Boolean);
    let tierMap = new Map();
    if (providerIds.length) {
      const tiers = await prisma.provider.findMany({
        where: { id: { in: providerIds } },
        select: { id: true, planTier: true }
      });
      tierMap = new Map(tiers.map((t) => [t.id, t.planTier]));
    }

    const jobs = toList.map((p) => {
      const planTier = normalizePlanTier(p.planTier || tierMap.get(p.id));
      const delayMs = PLAN_NOTIFY_DELAY_MS[planTier] ?? PLAN_NOTIFY_DELAY_MS.verified;
      return {
        id: uuid(),
        leadId: lead.id,
        providerId: p.id,
        runAt: new Date(Date.now() + delayMs),
        status: 'pending',
        payload: {
          clientZip: zip,
          requestSubmittedBy,
          careDaysAndTimes,
          services,
          funding,
          otherDetails,
          clientEmail,
          clientPhone,
          clientName,
          providerEmail: p.email,
          providerPhone: p.phone || '',
          planTier
        }
      };
    });

    if (jobs.length) {
      await prisma.notificationJob.createMany({ data: jobs });
    }

    res.json({ ok: true, queued: true, sent: jobs.length });
  } catch (err) {
    console.error('Notify failed', err);
    res.status(500).json({ error: 'Notify failed' });
  }
});

app.post('/api/admin/verify', (req, res) => {
  const token = req.headers['x-admin-token'];
  if (token !== ADMIN_TOKEN_REMOVE) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  res.json({ ok: true });
});

app.get('/api/admin/audit', async (req, res) => {
  const token = req.headers['x-admin-token'];
  if (token !== ADMIN_TOKEN_AUDIT) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  const logs = await prisma.adminAuditLog.findMany({
    orderBy: { createdAt: 'desc' },
    take: 200
  });
  res.json(logs);
});

app.post('/api/test-email', async (_req, res) => {
  if (!EMAIL_ENABLED) return res.status(500).json({ error: 'Email not configured' });
  try {
    await sendTestEmail('admin@besthospice.com');
    res.json({ ok: true });
  } catch (err) {
    console.error('Test email failed', err);
    res.status(500).json({ error: 'Test email failed' });
  }
});

// Provider auth: signup start via provider login email
app.post('/api/provider-auth/signup-start', async (req, res) => {
  const { providerEmail, providerId } = req.body || {};
  if (!providerEmail || !providerId) return res.status(400).json({ error: 'Provider and email required' });
  const normEmail = String(providerEmail).trim().toLowerCase();
  try {
    const provider = await prisma.provider.findUnique({ where: { id: providerId } });
    if (!provider) return res.status(404).json({ error: 'Provider not found' });
    const loginEmail = String(provider.providerLoginEmail || provider.email || '').trim().toLowerCase();
    if (!loginEmail || loginEmail !== normEmail) {
      return res.status(400).json({ error: 'Email must match the provider login email' });
    }

    let user = await prisma.providerUser.findUnique({ where: { email: normEmail } });
    if (!user) {
      user = await prisma.providerUser.create({
        data: { id: uuid(), email: normEmail, passwordHash: '', activeProviderId: provider.id }
      });
    }

    // Ensure link to the chosen provider
    const existingLink = await prisma.providerUserProvider.findFirst({
      where: { providerUserId: user.id, providerId: provider.id }
    });
    if (!existingLink) {
      await prisma.providerUserProvider.create({
        data: { id: uuid(), providerUserId: user.id, providerId: provider.id }
      });
    }
    if (!user.activeProviderId) {
      await prisma.providerUser.update({ where: { id: user.id }, data: { activeProviderId: provider.id } });
    }

    const code = String(Math.floor(100000 + Math.random() * 900000));
    const expiresAt = new Date(Date.now() + 48 * 60 * 60 * 1000);
    await prisma.providerUser.update({
      where: { email: normEmail },
      data: { verifyCode: code, verifyCodeExpiresAt: expiresAt }
    });

    if (!EMAIL_ENABLED) {
      return res.status(500).json({ error: 'Email not configured. Please contact support.' });
    }
    try {
      const html = `
        <div style="font-family: Arial, sans-serif; line-height:1.5; color:#111">
          <p>You requested access to the Best Hospice Provider Dashboard for <strong>${provider.name}</strong>.</p>
          <p>Please copy this one-time code and paste it in the dashboard to finish creating your password:</p>
          <p style="font-size:22px; font-weight:800; letter-spacing:2px;">${code}</p>
          <p>Open: <a href="${DASHBOARD_VERIFY_URL}">${DASHBOARD_VERIFY_URL}</a> and use the code above. Codes expire in 48 hours.</p>
        </div>
      `;
      await sendGenericEmail(normEmail, 'Finish setting up your Best Hospice dashboard', html);
    } catch (err) {
      console.error('Send invite email failed', err);
      return res.status(500).json({ error: 'Failed to send signup email.' });
    }
    res.json({ ok: true, message: 'Check your email for the signup token.' });
  } catch (err) {
    console.error('Signup start failed', err);
    res.status(500).json({ error: 'Signup start failed' });
  }
});

// Provider auth: complete signup with code + password
app.post('/api/provider-auth/complete', async (req, res) => {
  const { email, code, password } = req.body || {};
  if (!email || !code || !password) return res.status(400).json({ error: 'Email, code, and password are required' });
  if (String(password).length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters' });
  const normEmail = String(email).trim().toLowerCase();
  try {
    const user = await prisma.providerUser.findUnique({ where: { email: normEmail } });
    if (!user || !user.verifyCode || !user.verifyCodeExpiresAt) {
      return res.status(400).json({ error: 'Invalid or missing code' });
    }
    if (user.verifyCode !== String(code).trim()) {
      return res.status(400).json({ error: 'Invalid code' });
    }
    if (new Date() > user.verifyCodeExpiresAt) {
      return res.status(400).json({ error: 'Code expired. Please start signup again.' });
    }

    const passwordHash = await bcrypt.hash(String(password), 10);
    const updated = await prisma.providerUser.update({
      where: { id: user.id },
      data: {
        passwordHash,
        emailVerifiedAt: new Date(),
        verifyCode: null,
        verifyCodeExpiresAt: null
      }
    });
    const authToken = jwt.sign({ sub: updated.id }, PROVIDER_JWT_SECRET, { expiresIn: '7d' });
    res.json({ ok: true, token: authToken });
  } catch (err) {
    console.error('Complete signup failed', err);
    res.status(400).json({ error: 'Invalid or expired code' });
  }
});

// Provider auth: login
app.post('/api/provider-auth/login', async (req, res) => {
  const { email, password, providerId } = req.body || {};
  if (!email || !password || !providerId) return res.status(400).json({ error: 'Provider, email and password required' });
  const normEmail = String(email).trim().toLowerCase();
  try {
    const user = await prisma.providerUser.findUnique({
      where: { email: normEmail },
      include: { links: { include: { provider: true } } }
    });
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });
    const ok = await bcrypt.compare(String(password), user.passwordHash);
    if (!ok) return res.status(401).json({ error: 'Invalid credentials' });
    const linked = user.links.find((l) => l.providerId === providerId);
    if (!linked) return res.status(403).json({ error: 'Email is not linked to that provider' });
    const token = jwt.sign({ sub: user.id }, PROVIDER_JWT_SECRET, { expiresIn: '7d' });
    // pick an active provider if none set
    if (!user.activeProviderId) {
      await prisma.providerUser.update({ where: { id: user.id }, data: { activeProviderId: providerId } });
    } else if (user.activeProviderId !== providerId) {
      await prisma.providerUser.update({ where: { id: user.id }, data: { activeProviderId: providerId } });
    }
    res.json({ ok: true, token });
  } catch (err) {
    console.error('Login failed', err);
    res.status(500).json({ error: 'Login failed' });
  }
});

// Public list of providers for signup/login dropdown
app.get('/api/public/providers', async (_req, res) => {
  const providers = await prisma.provider.findMany({
    orderBy: { name: 'asc' },
    select: { id: true, name: true, email: true }
  });
  res.json({ providers });
});

// List provider locations for logged-in user
app.get('/api/provider/locations', requireProviderAuth, async (req, res) => {
  const user = await prisma.providerUser.findUnique({
    where: { id: req.providerUserId },
    include: { links: { include: { provider: true } } }
  });
  if (!user) return res.status(401).json({ error: 'Unauthorized' });
  const providers = (user.links || []).map((l) => ({
    id: l.provider.id,
    name: l.provider.name,
    address: l.provider.address,
    email: l.provider.email
  }));
  res.json({ providers, activeProviderId: user.activeProviderId });
});

// Select active provider for logged-in user
app.post('/api/provider/select', requireProviderAuth, async (req, res) => {
  const { providerId } = req.body || {};
  if (!providerId) return res.status(400).json({ error: 'providerId required' });
  const link = await prisma.providerUserProvider.findFirst({
    where: { providerUserId: req.providerUserId, providerId }
  });
  if (!link) return res.status(403).json({ error: 'Not linked to that provider' });
  await prisma.providerUser.update({ where: { id: req.providerUserId }, data: { activeProviderId: providerId } });
  res.json({ ok: true });
});

// Provider leads count since date
app.get('/api/provider/leads/count', requireProviderAuth, async (req, res) => {
  try {
    const ctx = await getProviderContext(req.providerUserId);
    if (!ctx) return res.status(401).json({ error: 'Unauthorized' });
    const sinceParam = req.query.since;
    const since = sinceParam ? new Date(String(sinceParam)) : null;
    if (!since || isNaN(since.getTime())) return res.status(400).json({ error: 'Invalid since date' });

    const notifications = await prisma.leadNotification.findMany({
      where: { providerId: ctx.providerId, createdAt: { gte: since } },
      select: { leadId: true }
    });
    const distinctLeadIds = new Set(notifications.map((n) => n.leadId));
    await logAdminAction('provider_user', 'PROVIDER_AI_LEAD_COUNT', ctx.providerId, { since: since.toISOString() }, hashIp(req.ip || ''));
    res.json({ ok: true, since: since.toISOString().split('T')[0], count: distinctLeadIds.size });
  } catch (err) {
    console.error('Lead count failed', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Provider leads list since date (safe fields only, paginated)
app.get('/api/provider/leads', requireProviderAuth, async (req, res) => {
  try {
    const ctx = await getProviderContext(req.providerUserId);
    if (!ctx) return res.status(401).json({ error: 'Unauthorized' });
    const sinceParam = req.query.since;
    const limit = Math.min(parseInt(req.query.limit || '10', 10), 200);
    const page = Math.max(parseInt(req.query.page || '1', 10), 1);
    const skip = (page - 1) * limit;
    const since = sinceParam ? new Date(String(sinceParam)) : null;
    if (!since || isNaN(since.getTime())) return res.status(400).json({ error: 'Invalid since date' });

    const [notifs, total] = await Promise.all([
      prisma.leadNotification.findMany({
        where: { providerId: ctx.providerId, createdAt: { gte: since } },
        orderBy: { createdAt: 'desc' },
        skip,
        take: limit,
        select: {
          lead: {
            select: {
              id: true,
              createdAt: true,
              zip: true,
              submittedBy: true,
              clientEmail: true,
              clientPhone: true,
              firstName: true,
              lastName: true
            }
          }
        }
      }),
      prisma.leadNotification.count({ where: { providerId: ctx.providerId, createdAt: { gte: since } } })
    ]);
    const leads = notifs
      .map((n) => n.lead)
      .filter(Boolean)
      .map((l) => ({
        leadId: l.id,
        createdAt: l.createdAt,
        zip: l.zip,
        submittedBy: l.submittedBy,
        clientEmail: l.clientEmail || '',
        clientPhone: l.clientPhone || '',
        clientName: [l.firstName, l.lastName].filter(Boolean).join(' ').trim()
      }));
    await logAdminAction('provider_user', 'PROVIDER_AI_LEAD_LIST', ctx.providerId, { since: since.toISOString(), returned: leads.length }, hashIp(req.ip || ''));
    res.json({ ok: true, since: since.toISOString().split('T')[0], leads, total, page, pageSize: limit });
  } catch (err) {
    console.error('Lead list failed', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Provider metrics in date range
app.get('/api/provider/metrics', requireProviderAuth, async (req, res) => {
  try {
    const ctx = await getProviderContext(req.providerUserId);
    if (!ctx) return res.status(401).json({ error: 'Unauthorized' });
    const startParam = req.query.start;
    const endParam = req.query.end;
    const start = startParam ? new Date(String(startParam)) : null;
    const end = endParam ? new Date(String(endParam)) : null;
    if (!start || isNaN(start.getTime()) || !end || isNaN(end.getTime())) {
      return res.status(400).json({ error: 'Invalid start/end date' });
    }

    const [impressions, emailsSent, leadNotifications] = await Promise.all([
      prisma.providerImpression.count({
        where: { providerId: ctx.providerId, createdAt: { gte: start, lte: end } }
      }),
      prisma.leadNotification.count({
        where: { providerId: ctx.providerId, status: 'sent', createdAt: { gte: start, lte: end } }
      }),
      prisma.leadNotification.findMany({
        where: { providerId: ctx.providerId, createdAt: { gte: start, lte: end } },
        select: { leadId: true }
      })
    ]);
    const leadsGenerated = new Set(leadNotifications.map((n) => n.leadId)).size;

    await logAdminAction(
      'provider_user',
      'PROVIDER_AI_METRICS',
      ctx.providerId,
      { start: start.toISOString(), end: end.toISOString() },
      hashIp(req.ip || '')
    );
    res.json({
      ok: true,
      start: start.toISOString().split('T')[0],
      end: end.toISOString().split('T')[0],
      impressions,
      emailsSent,
      leadsGenerated
    });
  } catch (err) {
    console.error('Provider metrics failed', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Provider spend since date (flat monthly rate for now)
app.get('/api/provider/spend', requireProviderAuth, async (req, res) => {
  try {
    const sinceParam = req.query.since;
    const since = sinceParam ? new Date(String(sinceParam)) : null;
    if (!since || isNaN(since.getTime())) return res.status(400).json({ error: 'Invalid since date' });
    const today = new Date();
    const diffDays = Math.max(0, (today - since) / (1000 * 60 * 60 * 24));
    const months = Math.max(1, Math.ceil(diffDays / 30));
    const totalSpend = months * PROVIDER_MONTHLY_RATE;
    res.json({
      ok: true,
      since: since.toISOString().split('T')[0],
      monthlyRate: PROVIDER_MONTHLY_RATE,
      months,
      totalSpend
    });
  } catch (err) {
    console.error('Provider spend failed', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Provider auth: link account to a provider via login email
app.post('/api/provider-auth/link', requireProviderAuth, async (req, res) => {
  const { providerEmail } = req.body || {};
  if (!providerEmail) return res.status(400).json({ error: 'providerEmail required' });
  try {
    const user = await prisma.providerUser.findUnique({ where: { id: req.providerUserId } });
    if (!user) return res.status(401).json({ error: 'Unauthorized' });
    const provider = await prisma.provider.findFirst({
      where: {
        OR: [
          { providerLoginEmail: { equals: providerEmail.trim(), mode: 'insensitive' } },
          { email: { equals: providerEmail.trim(), mode: 'insensitive' } }
        ]
      }
    });
    if (!provider) return res.status(404).json({ error: 'Provider with that email not found' });
    // prevent linking to a different provider if already linked
    if (user.providerId && user.providerId !== provider.id) {
      return res.status(400).json({ error: 'Account already linked to a different provider' });
    }
    await prisma.providerUser.update({
      where: { id: user.id },
      data: { providerId: provider.id }
    });
    res.json({ ok: true, providerId: provider.id, providerName: provider.name });
  } catch (err) {
    console.error('Link failed', err);
    res.status(500).json({ error: 'Link failed' });
  }
});

// Provider dashboard metrics
app.get('/api/provider-dashboard/metrics', requireProviderAuth, async (req, res) => {
  try {
    const ctx = await getProviderContext(req.providerUserId);
    if (!ctx) return res.status(401).json({ error: 'Unauthorized' });
    if (!ctx.providerId || !ctx.provider) {
      return res.status(400).json({ error: 'No provider linked yet' });
    }
    const providerId = ctx.providerId;
    const [totalNotifications, totalImpressions, notifications30d, impressions30d] = await Promise.all([
      prisma.leadNotification.count({ where: { providerId, status: 'sent' } }),
      prisma.providerImpression.count({ where: { providerId } }),
      prisma.leadNotification.count({
        where: {
          providerId,
          status: 'sent',
          createdAt: { gte: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000) }
        }
      }),
      prisma.providerImpression.count({
        where: { providerId, createdAt: { gte: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000) } }
      })
    ]);
    res.json({
      ok: true,
      provider: { id: ctx.provider.id, name: ctx.provider.name, email: ctx.provider.email },
      metrics: {
        totalNotifications,
        totalImpressions,
        notifications30d,
        impressions30d
      }
    });
  } catch (err) {
    console.error('Metrics failed', err);
    res.status(500).json({ error: 'Metrics failed' });
  }
});

// Provider billing portal (Stripe checkout for selected plan)
app.post('/api/provider/billing', requireProviderAuth, async (req, res) => {
  if (!stripe || !process.env.STRIPE_SECRET_KEY) {
    return res.status(500).json({ error: 'Billing is not configured yet.' });
  }
  try {
    const ctx = await getProviderContext(req.providerUserId);
    if (!ctx) return res.status(401).json({ error: 'Unauthorized' });
    const planTier = normalizePlanTier(ctx.provider?.planTier || 'verified');
    const priceMap = {
      verified: process.env.STRIPE_PRICE_ID_VERIFIED,
      featured: process.env.STRIPE_PRICE_ID_FEATURED,
      priority: process.env.STRIPE_PRICE_ID_PRIORITY
    };
    const priceId = priceMap[planTier];
    if (!priceId || !process.env.STRIPE_SUCCESS_URL || !process.env.STRIPE_CANCEL_URL) {
      return res.status(500).json({ error: 'Stripe is not fully configured.' });
    }

    const customerEmail = ctx.provider?.providerLoginEmail || ctx.provider?.email || undefined;
    const customer = await stripe.customers.create({
      email: customerEmail,
      name: ctx.provider?.name || undefined,
      metadata: { providerId: ctx.providerId, planTier }
    });

    const session = await stripe.checkout.sessions.create({
      mode: 'subscription',
      customer: customer.id,
      line_items: [{ price: priceId, quantity: 1 }],
      success_url: process.env.STRIPE_SUCCESS_URL,
      cancel_url: process.env.STRIPE_CANCEL_URL,
      metadata: { providerId: ctx.providerId, planTier }
    });
    res.json({ ok: true, url: session.url });
  } catch (err) {
    console.error('Billing portal failed', err);
    res.status(500).json({ error: 'Billing portal failed' });
  }
});

// AI chat endpoint (rich intents for client and provider)
app.post('/api/ai/chat', async (req, res) => {
  const { message, turnstileToken } = req.body || {};
  if (!message) return res.status(400).json({ error: 'message required' });

  const text = String(message || '').trim();
  const lower = text.toLowerCase();

  const parseDateLoose = (input) => {
    if (!input) return null;
    const iso = input.match(/\d{4}-\d{2}-\d{2}/);
    if (iso) return new Date(iso[0]);
    const monthWord = /(jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec|january|february|march|april|may|june|july|august|september|october|november|december)/i;
    if (monthWord.test(input)) {
      const parsed = Date.parse(input);
      if (!Number.isNaN(parsed)) return new Date(parsed);
    }
    if (input.includes('last week')) return new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
    if (input.includes('last month')) return new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
    const parsed = Date.parse(input);
    return Number.isNaN(parsed) ? null : new Date(parsed);
  };

  const navigation = {
    home: '/index.html',
    questionnaire: '/index.html',
    providerLogin: '/provider-dashboard.html',
    providerHome: '/provider-dashboard-home.html'
  };

  const providerHints = /(provider|hospice provider|agency|administrator|admin|i am a provider|we are a provider|run a hospice|agency owner)/i;
  const clientHints = /(client|family|loved one|patient|looking for care|need hospice)/i;

  let providerCtx = null;
  const auth = req.headers['authorization'];
  if (auth && auth.toLowerCase().startsWith('bearer ')) {
    try {
      const token = auth.slice(7);
      const payload = jwt.verify(token, PROVIDER_JWT_SECRET);
      providerCtx = await getProviderContext(payload.sub);
    } catch (err) {
      providerCtx = null;
    }
  }

  const hintedProvider = providerHints.test(lower) || lower.includes('provider') || lower.includes('sign in') || lower.includes('log in') || lower.includes('login') || lower.includes('create an account');
  const hintedClient = clientHints.test(lower);

  let mode = 'client';
  if (providerCtx) {
    mode = 'provider_authed';
  } else if (hintedProvider) {
    mode = 'provider_public';
  } else if (hintedClient) {
    mode = 'client';
  }

  if (maybePhi(text)) {
    return res.json({
      reply: 'Please don’t share private medical details here. Best Hospice helps connect you with licensed providers who can collect that information securely.',
      navigateTo: navigation.home
    });
  }

  const careIntentPattern = /(hospice vs|palliative vs|difference between hospice|hospice and palliative|hospice or palliative|home care|homecare|what is hospice care|what is palliative care|what is home care|what kind of care do i need|which care do i need)/i;
  if (careIntentPattern.test(lower)) {
    let reply =
      'Here’s a quick, plain-language breakdown:\n' +
      '• Hospice care: Focuses on comfort, dignity, and quality of life when curative treatment is no longer the focus. Can be at home, assisted living, or in a facility. Often includes nursing visits, comfort support, emotional/spiritual support, and family/caregiver support.\n' +
      '• Palliative care: Focuses on comfort and quality of life at any stage of a serious illness, and can be provided alongside curative treatments. Often includes comfort support, care coordination, and emotional support.\n' +
      '• Home care (non-hospice): Focuses on help with daily living at home (bathing/dressing help, meals, light household tasks, companionship) rather than medical end-of-life care.\n' +
      'In simple terms: Hospice focuses on comfort near end of life; palliative care focuses on comfort at any stage; home care focuses on daily living support.';
    if (lower.includes('which') || lower.includes('do i need')) {
      reply += '\nChoosing the right type of care is something a licensed provider should help with. Best Hospice can connect you with providers who can guide that decision.';
    }
    reply += '\nIf you’d like, I can help you start finding providers near you.';
    return res.json({ reply, navigateTo: null });
  }

  if (mode === 'client' && !TURNSTILE_BYPASS && TURNSTILE_SECRET_KEY) {
    const captcha = await verifyTurnstile(turnstileToken, req.ip);
    if (!captcha.success) return res.status(403).json({ error: 'Captcha verification failed.' });
  }

  const startGreeting = (rolePrompt = true) =>
    rolePrompt
      ? 'Hi, I’m Abel. Are you here as a Client/Family member looking for hospice, palliative, or home care, or as a Hospice Provider?'
      : 'Hi, I’m Abel. How can I help today?';

  const leadCountSince = async (sinceDate, providerId) => {
    const notifs = await prisma.leadNotification.findMany({
      where: { providerId, createdAt: { gte: sinceDate } },
      select: { leadId: true }
    });
    return new Set(notifs.map((n) => n.leadId)).size;
  };
  const leadCountAll = async (providerId) => {
    const notifs = await prisma.leadNotification.findMany({
      where: { providerId },
      select: { leadId: true }
    });
    return new Set(notifs.map((n) => n.leadId)).size;
  };
  const leadListSince = async (sinceDate, providerId, limit = 50) => {
    const notifs = await prisma.leadNotification.findMany({
      where: { providerId, createdAt: { gte: sinceDate } },
      orderBy: { createdAt: 'desc' },
      take: limit,
      select: { lead: { select: { id: true, createdAt: true, zip: true, submittedBy: true } } }
    });
    return notifs
      .map((n) => n.lead)
      .filter(Boolean)
      .map((l) => ({ leadId: l.id, createdAt: l.createdAt, zip: l.zip, submittedBy: l.submittedBy }));
  };
  const metricsRange = async (start, end, providerId) => {
    const [impressions, emailsSent, leadNotifications] = await Promise.all([
      prisma.providerImpression.count({ where: { providerId, createdAt: { gte: start, lte: end } } }),
      prisma.leadNotification.count({ where: { providerId, status: 'sent', createdAt: { gte: start, lte: end } } }),
      prisma.leadNotification.findMany({ where: { providerId, createdAt: { gte: start, lte: end } }, select: { leadId: true } })
    ]);
    const leadsGenerated = new Set(leadNotifications.map((n) => n.leadId)).size;
    return { impressions, emailsSent, leadsGenerated };
  };
  const spendSince = async (sinceDate) => {
    const diffDays = Math.max(0, (Date.now() - sinceDate.getTime()) / (1000 * 60 * 60 * 24));
    const months = Math.max(1, Math.ceil(diffDays / 30));
    return { monthlyRate: PROVIDER_MONTHLY_RATE, months, totalSpend: months * PROVIDER_MONTHLY_RATE };
  };
  const iso = (d) => d.toISOString().split('T')[0];

  // ---------- CLIENT / FAMILY MODE ----------
  if (mode === 'client') {
    if (/^(hi|hello|help|best hospice|i have a question)/i.test(lower)) {
      return res.json({ reply: startGreeting(), navigateTo: navigation.home });
    }

    if (lower.includes('cost') || lower.includes('price') || lower.includes('free')) {
      return res.json({
        reply: 'Best Hospice is free for families. Providers pay to participate; families can search, answer a few guided questions, and contact providers at no cost.',
        navigateTo: navigation.home
      });
    }
    if (lower.includes('sell') && lower.includes('data')) {
      return res.json({
        reply: 'We do not sell your data. We only share your details with nearby providers to connect you to care quickly, and we discourage sharing sensitive medical information here.',
        navigateTo: navigation.home
      });
    }
    if (lower.includes('security') || lower.includes('secure') || lower.includes('captcha')) {
      return res.json({
        reply: 'We use CAPTCHA/Turnstile and other safeguards to protect users and their data. Please avoid sharing private medical details here; providers will handle sensitive information securely.',
        navigateTo: navigation.home
      });
    }
    if (lower.includes('stripe')) {
      return res.json({
        reply: 'Stripe is our secure payment partner for provider billing. It uses industry-standard encryption to help keep payment data safe.',
        navigateTo: navigation.home
      });
    }

    if (lower.includes('best hospice') || lower.includes('what is this website') || lower.includes('who are you')) {
      return res.json({
        reply: 'Best Hospice connects families to nearby licensed hospice providers. Enter your ZIP and answer a few guided questions; we match you to providers within about 60 miles and alert them so they can reach out quickly. Families are not charged for using the site.',
        navigateTo: navigation.home
      });
    }

    if (lower.includes('palliative')) {
      return res.json({
        reply: 'Palliative care focuses on quality of life and symptom relief at any stage of serious illness. Hospice is palliative care when curative treatments are no longer pursued. Want to start finding providers near you?',
        navigateTo: navigation.home
      });
    }
    if (lower.includes('hospice')) {
      return res.json({
        reply: 'Hospice care emphasizes comfort, dignity, and support for patients and families—focusing on symptom relief and emotional support. I can guide you to start the questionnaire to see nearby providers.',
        navigateTo: navigation.home
      });
    }

    if (lower.includes('start') || lower.includes('find care') || lower.includes('need hospice') || lower.includes('find hospice')) {
      return res.json({
        reply: 'To begin, click “Start Questionnaire” on the home page, enter your ZIP code, and answer the guided questions. We’ll show nearby providers and notify them so they can reach out.',
        navigateTo: navigation.home
      });
    }

    if (lower.includes('zip')) {
      return res.json({
        reply: 'We use your ZIP code to find providers within roughly 60 miles. If you’re unsure of the ZIP, use the nearest known ZIP and providers can adjust with you later.',
        navigateTo: navigation.home
      });
    }

    if (lower.includes('questionnaire') || lower.includes('type of care') || lower.includes('continuous care') || lower.includes('not sure')) {
      return res.json({
        reply: 'Choose options that best match your situation—like nursing/symptom support, home health aide help, equipment coordination, or emotional/spiritual support. If unsure, pick the closest fit; providers can refine details later.',
        navigateTo: navigation.home
      });
    }

    if (lower.includes('after') && lower.includes('questionnaire')) {
      return res.json({
        reply: 'After you complete the questionnaire, you’ll see nearby providers on the map and list. You can contact them directly, and notified providers may also reach out to you.',
        navigateTo: navigation.home
      });
    }

    if (lower.includes('legit') || lower.includes('real hospice') || lower.includes('make money') || lower.includes('how do you make money')) {
      return res.json({
        reply: 'Providers on Best Hospice are real hospice agencies. Best Hospice is a referral platform—providers pay to participate, and families are not charged.',
        navigateTo: navigation.home
      });
    }

    return res.json({
      reply: 'I can explain hospice, palliative, or home care, how Best Hospice works, or guide you to start the questionnaire. Would you like to learn more, or begin finding providers?',
      navigateTo: navigation.home
    });
  }

  // ---------- PROVIDER PUBLIC ----------
  if (mode === 'provider_public') {
    if (/^(hi|hello|help|best hospice|i have a question)/i.test(lower)) {
      return res.json({
        reply: 'Welcome, hospice provider. You can learn how leads work, view pricing, or create your account. Would you like to sign in or create an account?',
        navigateTo: navigation.providerLogin
      });
    }

    if (lower.includes('create') && lower.includes('account')) {
      return res.json({
        reply: 'To create a provider account, you must be a registered hospice provider. Please email provider@besthospice.com and we will assist with onboarding.',
        navigateTo: navigation.providerLogin
      });
    }

    if (lower.includes('sign in') || lower.includes('log in')) {
      return res.json({
        reply: 'To sign in, open the Provider Dashboard login page. If you don’t have access yet, email provider@besthospice.com for onboarding.',
        navigateTo: navigation.providerLogin
      });
    }

    if (lower.includes('best hospice') || lower.includes('how does this help')) {
      return res.json({
        reply: 'Best Hospice connects families who submit care requests with providers in their area. We alert providers promptly so you can respond fast, and your dashboard shows your performance.',
        navigateTo: navigation.providerLogin
      });
    }

    if (lower.includes('cost') || lower.includes('pricing') || lower.includes('contract') || lower.includes('price')) {
      return res.json({
        reply: 'Best Hospice is subscription-based for providers (no long-term lock-in). You can sign up and manage billing in your Provider Dashboard.',
        navigateTo: navigation.providerLogin
      });
    }

    if (lower.includes('join') || lower.includes('sign up') || lower.includes('onboard')) {
      return res.json({
        reply: 'To join, create your Provider account, add your service area, and complete billing. You’ll start receiving leads once you’re live.',
        navigateTo: navigation.providerLogin
      });
    }

    return res.json({
      reply: 'I can help you sign in, create your account, or explain how leads work. Would you like to sign in or create a Provider account?',
      navigateTo: navigation.providerLogin
    });
  }

  // ---------- PROVIDER AUTHED ----------
  try {
    if (!providerCtx) return res.status(401).json({ error: 'Unauthorized' });
    const providerId = providerCtx.providerId;
    const providerName = providerCtx.provider?.name || 'your listing';

    if (/^(hi|hello|help|best hospice|i have a question)/i.test(lower)) {
      return res.json({
        reply: 'Hi! I can help with lead counts, lead lists, performance, billing, spend, estimated revenue, ROI, or navigation. What do you want to do first?',
        navigateTo: navigation.providerHome
      });
    }

    if (clientHints.test(lower) && !providerHints.test(lower)) {
      return res.json({
        reply: 'You’re signed in as a provider. To use the client flow, please log out or open a separate session for the questionnaire.',
        navigateTo: navigation.providerHome
      });
    }

    if (lower.includes('best hospice')) {
      return res.json({
        reply: 'Best Hospice connects families to nearby hospice providers quickly. Families enter a ZIP, answer guided questions, and we alert providers so they can respond fast. Your dashboard shows leads, performance, and billing.',
        navigateTo: navigation.providerHome
      });
    }
    if (lower.includes('stripe')) {
      return res.json({
        reply: 'Stripe is our secure payment provider. Billing and subscription payments are processed through Stripe using industry-standard encryption.',
        navigateTo: navigation.providerHome
      });
    }
    if (lower.includes('security') || lower.includes('secure') || lower.includes('captcha')) {
      return res.json({
        reply: 'We use safeguards like Turnstile/CAPTCHA and Stripe for billing security. Avoid sharing PHI here—providers should collect sensitive details directly from families.',
        navigateTo: navigation.providerHome
      });
    }

    if (lower.includes('billing') || lower.includes('invoice') || lower.includes('paid') || lower.includes('subscription')) {
      return res.json({
        reply: 'Open your Provider Dashboard, go to Billing/Manage Billing, then open Invoice History to see paid invoices and totals. Tell me what you see and I’ll help interpret it.',
        navigateTo: navigation.providerHome
      });
    }

    if (lower.includes('how much') && lower.includes('made')) {
      return res.json({
        reply: 'Do you want (1) lead counts, (2) how much you’ve paid Best Hospice, or (3) estimated revenue from leads?',
        navigateTo: navigation.providerHome
      });
    }

    if (lower.includes('lead count') || (lower.includes('lead') && lower.includes('how many'))) {
      const sinceDate = parseDateLoose(text);
      if (!sinceDate) {
        return res.json({
          reply: 'For lead counts, tell me “lead count since YYYY-MM-DD” or a natural date (e.g., “since March 1”).',
          navigateTo: navigation.providerHome
        });
      }
      const countSince = await leadCountSince(sinceDate, providerId);
      const countAll = await leadCountAll(providerId);
      await logAdminAction('provider_user', 'PROVIDER_AI_LEAD_COUNT', providerId, { since: iso(sinceDate) }, hashIp(req.ip || ''));
      return res.json({
        reply: `Leads since ${iso(sinceDate)}: ${countSince}. All-time leads: ${countAll}.`,
        navigateTo: navigation.providerHome
      });
    }

    if (lower.includes('show') && lower.includes('lead')) {
      const sinceDate = parseDateLoose(text) || new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
      const leads = await leadListSince(sinceDate, providerId, 50);
      await logAdminAction('provider_user', 'PROVIDER_AI_LEAD_LIST', providerId, { since: iso(sinceDate), returned: leads.length }, hashIp(req.ip || ''));
      return res.json({
        reply: `Here are your leads since ${iso(sinceDate)} (showing up to 50).`,
        data: leads,
        navigateTo: navigation.providerHome
      });
    }

    if (lower.includes('metric') || lower.includes('performance') || lower.includes('impression')) {
      const start = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
      const end = new Date();
      const m = await metricsRange(start, end, providerId);
      await logAdminAction('provider_user', 'PROVIDER_AI_METRICS', providerId, { start: iso(start), end: iso(end) }, hashIp(req.ip || ''));
      return res.json({
        reply: `Last 30 days — Impressions: ${m.impressions}, Emails sent: ${m.emailsSent}, Leads: ${m.leadsGenerated}.`,
        navigateTo: navigation.providerHome
      });
    }

    if (lower.includes('spend') || lower.includes('paid') || lower.includes('paying')) {
      const explicitDate = parseDateLoose(text);
      const sinceDate = explicitDate || new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
      const spend = await spendSince(sinceDate);
      await logAdminAction('provider_user', 'PROVIDER_AI_METRICS', providerId, { spendSince: iso(sinceDate), totalSpend: spend.totalSpend }, hashIp(req.ip || ''));
      return res.json({
        reply: `Since ${iso(sinceDate)}, at $${PROVIDER_MONTHLY_RATE}/month, estimated spend is $${spend.totalSpend.toLocaleString()}.`,
        data: spend,
        navigateTo: navigation.providerHome
      });
    }

    if (lower.includes('revenue') || lower.includes('profit') || lower.includes('roi')) {
      const countAll = await leadCountAll(providerId);
      const estimateRevenue = countAll * 8000;
      const firstNotif = await prisma.leadNotification.findFirst({
        where: { providerId },
        orderBy: { createdAt: 'asc' },
        select: { createdAt: true }
      });
      const sinceDate = firstNotif?.createdAt ? new Date(firstNotif.createdAt) : new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
      const monthMatch = text.match(/(\d+)\s*month/);
      const overrideMonths = monthMatch ? Math.max(1, parseInt(monthMatch[1], 10)) : null;
      const spend = overrideMonths
        ? { monthlyRate: PROVIDER_MONTHLY_RATE, months: overrideMonths, totalSpend: overrideMonths * PROVIDER_MONTHLY_RATE }
        : await spendSince(sinceDate);
      const net = estimateRevenue - spend.totalSpend;
      await logAdminAction('provider_user', 'PROVIDER_AI_REVENUE_ESTIMATE', providerId, { leads: countAll, estimateRevenue, spend: spend.totalSpend, net }, hashIp(req.ip || ''));
      return res.json({
        reply: `Estimated revenue: ~$${estimateRevenue.toLocaleString()}. Estimated spend (at $${PROVIDER_MONTHLY_RATE}/mo): ~$${spend.totalSpend.toLocaleString()}. Estimated net: ~$${net.toLocaleString()}. Update conversions and months in your dashboard to refine this.`,
        navigateTo: navigation.providerHome
      });
    }

    if (lower.includes('account') || lower.includes('profile') || lower.includes('plan')) {
      await logAdminAction('provider_user', 'PROVIDER_AI_ACCOUNT', providerId, {}, hashIp(req.ip || ''));
      return res.json({
        reply: `Your account is active for ${providerName}. I can help you navigate leads, billing, or performance.`,
        data: { providerId, providerName, providerEmail: providerCtx.provider?.email || '', planStatus: providerCtx.provider?.planStatus || PROVIDER_PLAN_DEFAULT },
        navigateTo: navigation.providerHome
      });
    }

    if (lower.includes('not getting leads') || lower.includes('something wrong') || lower.includes('help')) {
      return res.json({
        reply: 'Let’s check your recent impressions and leads in the dashboard. If numbers look low, confirm your service area and that your listing is live. I can also flag support if needed.',
        navigateTo: navigation.providerHome
      });
    }

    return res.json({
      reply: 'I can help with lead counts (with dates), lead lists, performance, billing/spend, estimated revenue, ROI, or navigation. What would you like to do?',
      navigateTo: navigation.providerHome
    });
  } catch (err) {
    console.error('AI chat failed', err);
    res.status(500).json({ error: 'AI chat failed' });
  }
});


// ---------- Programmatic SEO pages ----------
const SERVICE_KEYS = Object.keys(serviceConfig);

app.get('/:service(hospice-care|palliative-care|home-care)/:city-:state', async (req, res) => {
  try {
    const { service, city, state } = req.params;
    const cityName = (city || '').replace(/-/g, ' ');
    const stateCode = (state || '').toLowerCase();
    const providers = await providersByLocation(cityName, stateCode);
    const html = renderCityPage({ serviceKey: service, city: cityName, state: stateCode, providers });
    res.send(html);
  } catch (err) {
    console.error('City page failed', err);
    res.status(500).send('Server error');
  }
});

app.get('/:service(hospice-care|palliative-care|home-care)/:state([a-z]{2})', async (req, res) => {
  try {
    const { service, state } = req.params;
    const providers = await prisma.provider.findMany({
      where: { state: { equals: state, mode: 'insensitive' } },
      orderBy: { featured: 'desc' }
    });
    const html = renderStatePage({ serviceKey: service, state, providers });
    res.send(html);
  } catch (err) {
    console.error('State page failed', err);
    res.status(500).send('Server error');
  }
});

app.get('/:service(hospice-care|palliative-care|home-care)', async (req, res) => {
  try {
    const { service } = req.params;
    if (!SERVICE_KEYS.includes(service)) return res.status(404).send('Not found');
    const html = renderHubPage({ serviceKey: service });
    res.send(html);
  } catch (err) {
    console.error('Hub page failed', err);
    res.status(500).send('Server error');
  }
});

app.get('/provider/:slug', async (req, res) => {
  try {
    const { slug } = req.params;
    const frag = (slug || '').split('-').pop();
    const provider = await prisma.provider.findFirst({
      where: { id: { startsWith: frag } }
    });
    if (!provider) return res.status(404).send('Provider not found');
    const html = renderProviderPage(provider);
    res.send(html);
  } catch (err) {
    console.error('Provider page failed', err);
    res.status(500).send('Server error');
  }
});

app.get('/sitemap.xml', async (_req, res) => {
  const serviceUrls = SERVICE_KEYS.map((s) => `${CANONICAL_DOMAIN}/${s}`);
  const locSitemap = `${CANONICAL_DOMAIN}/sitemap-locations.xml`;
  const provSitemap = `${CANONICAL_DOMAIN}/sitemap-providers.xml`;
  const body = `<?xml version="1.0" encoding="UTF-8"?>
<sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
${[locSitemap, provSitemap].map((u) => `<sitemap><loc>${u}</loc></sitemap>`).join('\n')}
${serviceUrls.map((u) => `<sitemap><loc>${u}</loc></sitemap>`).join('\n')}
</sitemapindex>`;
  res.type('text/xml').send(body);
});

app.get('/sitemap-locations.xml', async (_req, res) => {
  const providers = await fetchAllProviders();
  const seen = new Set();
  const urls = [];
  for (const p of providers) {
    if (!p.city || !p.state) continue;
    const key = `${p.city.toLowerCase()}-${p.state.toLowerCase()}`;
    if (seen.has(key)) continue;
    seen.add(key);
    SERVICE_KEYS.forEach((s) => {
      urls.push(`${CANONICAL_DOMAIN}/${s}/${slugify(p.city)}-${p.state.toLowerCase()}`);
    });
  }
  const body = `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
${urls.map((u) => `<url><loc>${u}</loc></url>`).join('\n')}
</urlset>`;
  res.type('text/xml').send(body);
});

app.get('/sitemap-providers.xml', async (_req, res) => {
  const providers = await fetchAllProviders();
  const urls = providers.map((p) => `${CANONICAL_DOMAIN}/provider/${providerSlug(p)}`);
  const body = `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
${urls.map((u) => `<url><loc>${u}</loc></url>`).join('\n')}
</urlset>`;
  res.type('text/xml').send(body);
});

app.get('/robots.txt', (_req, res) => {
  res.type('text/plain').send(`User-agent: *
Disallow: /api
Disallow: /admin
Disallow: /provider-dashboard
Sitemap: ${CANONICAL_DOMAIN}/sitemap.xml
`);
});

app.listen(PORT, () => {
  console.log(`Best Hospice server running on http://localhost:${PORT}`);
  if (!EMAIL_ENABLED) {
    console.log('Email not configured: set SENDGRID_API_KEY and SENDGRID_FROM_EMAIL (optional: SENDGRID_REPLY_TO)');
  }
});
