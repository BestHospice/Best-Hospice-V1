require('dotenv').config();
const express = require('express');
const path = require('path');
const crypto = require('crypto');
const { v4: uuid } = require('uuid');
const fetch = (...args) => import('node-fetch').then(({ default: fetch }) => fetch(...args));
const { PrismaClient } = require('@prisma/client');
const { sendProviderNotifications, sendTestEmail, emailEnabled } = require('./email');

const app = express();
const prisma = new PrismaClient();

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
  const url = `https://nominatim.openstreetmap.org/search?format=json&q=${encodeURIComponent(addressString)}&limit=1`;
  const response = await fetch(url, { headers: { 'Accept-Language': 'en', 'User-Agent': 'BestHospice/1.0' } });
  if (!response.ok) throw new Error('Geocoding failed');
  const data = await response.json();
  if (!Array.isArray(data) || !data.length) return null;
  return { lat: Number(data[0].lat), lon: Number(data[0].lon) };
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
  const providers = await prisma.provider.findMany();
  res.json(providers);
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
