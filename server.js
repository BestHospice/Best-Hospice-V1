require('dotenv').config();
const express = require('express');
const path = require('path');
const crypto = require('crypto');
const { v4: uuid } = require('uuid');
const fetch = (...args) => import('node-fetch').then(({ default: fetch }) => fetch(...args));
const { PrismaClient } = require('@prisma/client');
const { sendProviderNotifications, sendTestEmail, emailEnabled } = require('./email');
const Stripe = require('stripe');

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

function hashIp(ip) {
  return crypto.createHash('sha256').update(`${IP_SALT}:${ip || ''}`).digest('hex');
}

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
      leadCount: true,
      createdAt: true,
      updatedAt: true
    }
  });
  res.json(providers);
});

// Create a checkout session using provider email (case-insensitive)
app.post('/api/providers/email/checkout', async (req, res) => {
  if (!stripe || !process.env.STRIPE_PRICE_ID || !process.env.STRIPE_SUCCESS_URL || !process.env.STRIPE_CANCEL_URL) {
    return res.status(500).json({ error: 'Stripe is not fully configured.' });
  }
  const { email } = req.body || {};
  if (!email) return res.status(400).json({ error: 'Email is required' });
  try {
    const provider = await prisma.provider.findFirst({
      where: { email: { equals: email, mode: 'insensitive' } }
    });
    if (!provider) return res.status(404).json({ error: 'Provider not found' });

    const customer = await stripe.customers.create({
      email: provider.email,
      name: provider.name
    });

    const session = await stripe.checkout.sessions.create({
      mode: 'subscription',
      customer: customer.id,
      line_items: [{ price: process.env.STRIPE_PRICE_ID, quantity: 1 }],
      success_url: process.env.STRIPE_SUCCESS_URL,
      cancel_url: process.env.STRIPE_CANCEL_URL,
      metadata: { providerId: provider.id }
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

app.get('/api/providers/secure', async (req, res) => {
  const token = req.headers['x-admin-token'];
  if (token !== ADMIN_TOKEN_DASH) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  const providers = await prisma.provider.findMany();
  res.json(providers);
});

app.post('/api/providers/:id/checkout', async (req, res) => {
  if (!stripe || !process.env.STRIPE_PRICE_ID || !process.env.STRIPE_SUCCESS_URL || !process.env.STRIPE_CANCEL_URL) {
    return res.status(500).json({ error: 'Stripe is not fully configured.' });
  }
  const providerId = req.params.id;
  try {
    const provider = await prisma.provider.findUnique({ where: { id: providerId } });
    if (!provider) return res.status(404).json({ error: 'Provider not found' });

    const customer = await stripe.customers.create({
      email: provider.email,
      name: provider.name
    });

    const session = await stripe.checkout.sessions.create({
      mode: 'subscription',
      customer: customer.id,
      line_items: [{ price: process.env.STRIPE_PRICE_ID, quantity: 1 }],
      success_url: process.env.STRIPE_SUCCESS_URL,
      cancel_url: process.env.STRIPE_CANCEL_URL,
      metadata: { providerId: provider.id }
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
    phone,
    website,
    featured = false
    ,
    accountEmail,
    accountPassword
  } = req.body || {};
  if (!name || !address || !city || !state || !zip || !email) {
    return res.status(400).json({ error: 'Missing required fields (name, address, city, state, zip, email).' });
  }
  const acctEmail = (accountEmail || '').trim();
  const acctPassword = accountPassword ? String(accountPassword) : '';
  if ((acctEmail && !acctPassword) || (!acctEmail && acctPassword)) {
    return res.status(400).json({ error: 'Provide both account email and account password to set up dashboard access.' });
  }
  let accountPasswordHash = null;
  if (acctEmail && acctPassword) {
    if (acctPassword.length < 8) {
      return res.status(400).json({ error: 'Dashboard password must be at least 8 characters.' });
    }
    accountPasswordHash = crypto.createHash('sha256').update(acctPassword).digest('hex');
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
    const provider = await prisma.provider.create({
      data: {
        id: uuid(),
        name,
        email,
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
        accountEmail: acctEmail || null,
        accountPasswordHash,
        accountEmailVerified: false
      }
    });
    await logAdminAction(adminIdentifier, 'PROVIDER_ADD', provider.id, { name: provider.name, email: provider.email }, hashIp(req.ip || ''));
    res.json({ ok: true, provider });
  } catch (err) {
    console.error('Create provider failed', err);
    res.status(500).json({ error: 'Create provider failed' });
  }
});

app.delete('/api/providers/:id', async (req, res) => {
  const token = req.headers['x-admin-token'];
  if (token !== ADMIN_TOKEN_REMOVE) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  const id = req.params.id;
  try {
    const provider = await prisma.provider.delete({ where: { id } });
    await logAdminAction('remove_token', 'PROVIDER_REMOVE', id, { name: provider.name }, hashIp(req.ip || ''));
    res.json({ ok: true });
  } catch (err) {
    console.error('Remove failed', err);
    res.status(404).json({ error: 'Provider not found' });
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

    const toList = providers.filter((p) => !!p.email);
    if (!toList.length) return res.status(400).json({ error: 'No provider emails to notify' });

    const requestSubmittedBy = toSubmittedBy(answers.relationship);
    const careDays = answers.frequency?.days?.length ? answers.frequency.days.join(', ') : 'Not specified';
    const careTimes = answers.frequency?.times?.length ? answers.frequency.times.join(', ') : 'Not specified';
    const careDaysAndTimes = `Days: ${careDays}; Times: ${careTimes}`;
    const services = Array.isArray(answers.services) && answers.services.length ? answers.services : ['Not specified'];
    const clientEmail = answers.contactEmail || 'Not provided';
    const clientPhone = answers.contactPhone || 'Not provided';
    const clientName = [answers.firstName, answers.lastName].filter(Boolean).join(' ').trim() || 'Not provided';

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
        firstName: answers.firstName || null,
        lastName: answers.lastName || null
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

    const results = await sendProviderNotifications({
      clientZip: zip,
      requestSubmittedBy,
      careDaysAndTimes,
      services,
      clientEmail,
      clientPhone,
      clientName,
      providers: toList,
      nearbyProviders: toList
    });

    // Log notifications
    const notificationsData = results.map((r) => ({
      id: uuid(),
      leadId: lead.id,
      providerId:
        r.providerId ||
        toList.find(
          (p) =>
            p.id && p.email && r.email && p.email.trim().toLowerCase() === r.email.trim().toLowerCase()
        )?.id ||
        '',
      status: r.status === 'sent' ? 'sent' : 'failed',
      sendgridMessageId: r.messageId || null,
      errorMessage: r.error || null,
      sentAt: r.status === 'sent' ? new Date() : null
    })).filter((n) => n.providerId);

    if (notificationsData.length) {
      await prisma.leadNotification.createMany({ data: notificationsData });
      // Increment provider lead counts for successful sends
      const sentCounts = notificationsData
        .filter((n) => n.status === 'sent')
        .reduce((acc, n) => {
          acc[n.providerId] = (acc[n.providerId] || 0) + 1;
          return acc;
        }, {});
      const updates = Object.entries(sentCounts).map(([providerId, count]) =>
        prisma.provider.update({
          where: { id: providerId },
          data: { leadCount: { increment: count } }
        })
      );
      if (updates.length) await prisma.$transaction(updates);
    }

    res.json({ ok: true, sent: results.filter((r) => r.status === 'sent').length, results });
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

app.listen(PORT, () => {
  console.log(`Best Hospice server running on http://localhost:${PORT}`);
  if (!EMAIL_ENABLED) {
    console.log('Email not configured: set SENDGRID_API_KEY and SENDGRID_FROM_EMAIL (optional: SENDGRID_REPLY_TO)');
  }
});
