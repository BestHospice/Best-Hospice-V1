require('dotenv').config();
const express = require('express');
const path = require('path');
const crypto = require('crypto');
const { v4: uuid } = require('uuid');
const fetch = (...args) => import('node-fetch').then(({ default: fetch }) => fetch(...args));
const { PrismaClient } = require('@prisma/client');
const { sendProviderNotifications, sendTestEmail, sendGenericEmail, emailEnabled } = require('./email');
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
    include: { provider: true }
  });
  if (!user || !user.providerId) return null;
  return { providerId: user.providerId, provider: user.provider, providerUserId: user.id };
}

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
        featured: Boolean(featured)
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

// Provider auth: signup start via provider public email
app.post('/api/provider-auth/signup-start', async (req, res) => {
  const { providerEmail } = req.body || {};
  if (!providerEmail) return res.status(400).json({ error: 'Provider email required' });
  const normEmail = String(providerEmail).trim().toLowerCase();
  try {
    const provider = await prisma.provider.findFirst({
      where: { email: { equals: normEmail, mode: 'insensitive' } }
    });
    if (!provider) return res.status(404).json({ error: 'Provider with that email not found' });

    let user = await prisma.providerUser.findUnique({ where: { email: normEmail } });
    if (!user) {
      user = await prisma.providerUser.create({
        data: { id: uuid(), email: normEmail, providerId: provider.id, passwordHash: '' }
      });
    } else if (!user.providerId) {
      await prisma.providerUser.update({ where: { id: user.id }, data: { providerId: provider.id } });
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
    res.json({ ok: true, token: authToken, providerId: updated.providerId });
  } catch (err) {
    console.error('Complete signup failed', err);
    res.status(400).json({ error: 'Invalid or expired code' });
  }
});

// Provider auth: login
app.post('/api/provider-auth/login', async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
  const normEmail = String(email).trim().toLowerCase();
  try {
    const user = await prisma.providerUser.findUnique({ where: { email: normEmail } });
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });
    const ok = await bcrypt.compare(String(password), user.passwordHash);
    if (!ok) return res.status(401).json({ error: 'Invalid credentials' });
    const token = jwt.sign({ sub: user.id }, PROVIDER_JWT_SECRET, { expiresIn: '7d' });
    res.json({ ok: true, token, providerId: user.providerId });
  } catch (err) {
    console.error('Login failed', err);
    res.status(500).json({ error: 'Login failed' });
  }
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

// Provider leads list since date (safe fields only)
app.get('/api/provider/leads', requireProviderAuth, async (req, res) => {
  try {
    const ctx = await getProviderContext(req.providerUserId);
    if (!ctx) return res.status(401).json({ error: 'Unauthorized' });
    const sinceParam = req.query.since;
    const limit = Math.min(parseInt(req.query.limit || '50', 10), 200);
    const since = sinceParam ? new Date(String(sinceParam)) : null;
    if (!since || isNaN(since.getTime())) return res.status(400).json({ error: 'Invalid since date' });

    const notifs = await prisma.leadNotification.findMany({
      where: { providerId: ctx.providerId, createdAt: { gte: since } },
      orderBy: { createdAt: 'desc' },
      take: limit,
      select: {
        lead: {
          select: {
            id: true,
            createdAt: true,
            zip: true,
            submittedBy: true
          }
        }
      }
    });
    const leads = notifs
      .map((n) => n.lead)
      .filter(Boolean)
      .map((l) => ({
        leadId: l.id,
        createdAt: l.createdAt,
        zip: l.zip,
        submittedBy: l.submittedBy
      }));
    await logAdminAction('provider_user', 'PROVIDER_AI_LEAD_LIST', ctx.providerId, { since: since.toISOString(), returned: leads.length }, hashIp(req.ip || ''));
    res.json({ ok: true, since: since.toISOString().split('T')[0], leads });
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

// Provider auth: link account to a provider via public email
app.post('/api/provider-auth/link', requireProviderAuth, async (req, res) => {
  const { providerEmail } = req.body || {};
  if (!providerEmail) return res.status(400).json({ error: 'providerEmail required' });
  try {
    const user = await prisma.providerUser.findUnique({ where: { id: req.providerUserId } });
    if (!user) return res.status(401).json({ error: 'Unauthorized' });
    const provider = await prisma.provider.findFirst({
      where: { email: { equals: providerEmail.trim(), mode: 'insensitive' } }
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

// Provider billing portal (Stripe portal session)
app.post('/api/provider/billing', requireProviderAuth, async (req, res) => {
  if (!stripe || !process.env.STRIPE_SECRET_KEY) {
    return res.status(500).json({ error: 'Billing is not configured yet.' });
  }
  try {
    const ctx = await getProviderContext(req.providerUserId);
    if (!ctx) return res.status(401).json({ error: 'Unauthorized' });
    const customer = await stripe.customers.create({
      email: ctx.provider?.email || undefined,
      name: ctx.provider?.name || undefined,
      metadata: { providerId: ctx.providerId }
    });
    const session = await stripe.billingPortal.sessions.create({
      customer: customer.id,
      return_url: 'https://www.besthospice.com/provider-dashboard-home.html'
    });
    res.json({ ok: true, url: session.url });
  } catch (err) {
    console.error('Billing portal failed', err);
    res.status(500).json({ error: 'Billing portal failed' });
  }
});

// AI chat endpoint (provider/client minimal)
app.post('/api/ai/chat', async (req, res) => {
  const { message, mode, turnstileToken } = req.body || {};
  if (!message || !mode) return res.status(400).json({ error: 'message and mode required' });

  const nav = (path) => ({ reply: '', navigateTo: path });

  if (mode === 'client') {
    const captcha = await verifyTurnstile(turnstileToken, req.ip);
    if (!captcha.success) return res.status(403).json({ error: 'Captcha verification failed.' });
    return res.json({ reply: 'Please start with the questionnaire to find nearby providers.', navigateTo: '/questionnaire' });
  }

  if (mode !== 'provider') return res.status(400).json({ error: 'Unsupported mode' });

  try {
    const auth = req.headers['authorization'];
    if (!auth || !auth.toLowerCase().startsWith('bearer ')) return res.status(401).json({ error: 'Unauthorized' });
    const token = auth.slice(7);
    const payload = jwt.verify(token, PROVIDER_JWT_SECRET);
    const ctx = await getProviderContext(payload.sub);
    if (!ctx) return res.status(401).json({ error: 'Unauthorized' });

    const text = String(message).toLowerCase();
    const today = new Date();
    const iso = (d) => d.toISOString().split('T')[0];

    const leadCountSince = async (sinceDate) => {
      const notifs = await prisma.leadNotification.findMany({
        where: { providerId: ctx.providerId, createdAt: { gte: sinceDate } },
        select: { leadId: true }
      });
      return new Set(notifs.map((n) => n.leadId)).size;
    };

    const leadListSince = async (sinceDate, limit = 50) => {
      const notifs = await prisma.leadNotification.findMany({
        where: { providerId: ctx.providerId, createdAt: { gte: sinceDate } },
        orderBy: { createdAt: 'desc' },
        take: limit,
        select: { lead: { select: { id: true, createdAt: true, zip: true, submittedBy: true } } }
      });
      return notifs
        .map((n) => n.lead)
        .filter(Boolean)
        .map((l) => ({ leadId: l.id, createdAt: l.createdAt, zip: l.zip, submittedBy: l.submittedBy }));
    };

    const metricsRange = async (start, end) => {
      const [impressions, emailsSent, leadNotifications] = await Promise.all([
        prisma.providerImpression.count({ where: { providerId: ctx.providerId, createdAt: { gte: start, lte: end } } }),
        prisma.leadNotification.count({ where: { providerId: ctx.providerId, status: 'sent', createdAt: { gte: start, lte: end } } }),
        prisma.leadNotification.findMany({ where: { providerId: ctx.providerId, createdAt: { gte: start, lte: end } }, select: { leadId: true } })
      ]);
      const leadsGenerated = new Set(leadNotifications.map((n) => n.leadId)).size;
      return { impressions, emailsSent, leadsGenerated };
    };

    // Billing intent
    if (text.includes('billing')) {
      return res.json({ reply: 'Opening billing portal for you.', navigateTo: '/provider/billing' });
    }

    // Lead count intent
    if (text.includes('lead') && text.includes('since')) {
      const match = text.match(/\\d{4}-\\d{2}-\\d{2}/);
      const sinceDate = match ? new Date(match[0]) : new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
      const count = await leadCountSince(sinceDate);
      await logAdminAction('provider_user', 'PROVIDER_AI_LEAD_COUNT', ctx.providerId, { since: iso(sinceDate) }, hashIp(req.ip || ''));
      return res.json({ reply: `Leads since ${iso(sinceDate)}: ${count}`, navigateTo: '/provider/leads' });
    }

    // Lead list intent
    if (text.includes('show') && text.includes('lead')) {
      const match = text.match(/\\d{4}-\\d{2}-\\d{2}/);
      const sinceDate = match ? new Date(match[0]) : new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
      const leads = await leadListSince(sinceDate, 50);
      await logAdminAction('provider_user', 'PROVIDER_AI_LEAD_LIST', ctx.providerId, { since: iso(sinceDate), returned: leads.length }, hashIp(req.ip || ''));
      return res.json({ reply: `Here are your leads since ${iso(sinceDate)}.`, data: leads, navigateTo: '/provider/leads' });
    }

    // Metrics intent
    if (text.includes('metric') || text.includes('performance')) {
      const start = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
      const end = today;
      const m = await metricsRange(start, end);
      await logAdminAction('provider_user', 'PROVIDER_AI_METRICS', ctx.providerId, { start: iso(start), end: iso(end) }, hashIp(req.ip || ''));
      return res.json({
        reply: `Last 30 days: Impressions ${m.impressions}, Emails sent ${m.emailsSent}, Leads ${m.leadsGenerated}.`,
        navigateTo: '/provider/leads'
      });
    }

    // Account intent
    if (text.includes('account') || text.includes('plan')) {
      await logAdminAction('provider_user', 'PROVIDER_AI_ACCOUNT', ctx.providerId, {}, hashIp(req.ip || ''));
      return res.json({
        reply: `Your account is active for ${ctx.provider?.name || 'your listing'}.`,
        data: { providerId: ctx.providerId, providerName: ctx.provider?.name || '', providerEmail: ctx.provider?.email || '', planStatus: ctx.provider?.planStatus || PROVIDER_PLAN_DEFAULT }
      });
    }

    return res.json({ reply: 'Ask me for lead counts, lead lists, performance, billing, or account status.', navigateTo: '/provider/dashboard' });
  } catch (err) {
    console.error('AI chat failed', err);
    res.status(500).json({ error: 'AI chat failed' });
  }
});

app.listen(PORT, () => {
  console.log(`Best Hospice server running on http://localhost:${PORT}`);
  if (!EMAIL_ENABLED) {
    console.log('Email not configured: set SENDGRID_API_KEY and SENDGRID_FROM_EMAIL (optional: SENDGRID_REPLY_TO)');
  }
});
