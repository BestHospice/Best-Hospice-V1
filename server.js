require('dotenv').config();
const express = require('express');
const path = require('path');
const crypto = require('crypto');
const fs = require('fs');
const { v4: uuid } = require('uuid');
const { PrismaClient } = require('@prisma/client');
const { sendProviderNotifications, sendLeadStatusNudgeEmail, sendTestEmail, sendGenericEmail, sendJobSeekerNotification, sendDischargeReferralNotifications, emailEnabled } = require('./email');
const { sendProviderSms, smsEnabled } = require('./sms');
const Stripe = require('stripe');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const Anthropic = require('@anthropic-ai/sdk');
const cron = require('node-cron');
const { runNewsletterPipeline, verifyUnsubscribeToken } = require('./newsletter-pipeline');

const app = express();
const prisma = new PrismaClient();
const stripe = process.env.STRIPE_SECRET_KEY ? Stripe(process.env.STRIPE_SECRET_KEY) : null;
const anthropic = process.env.ANTHROPIC_API_KEY ? new Anthropic() : null;
app.set('trust proxy', true);

function getRequiredSecret(name) {
  const configured = String(process.env[name] || '').trim();
  if (configured) return configured;
  if (process.env.NODE_ENV === 'production') {
    throw new Error(`${name} must be configured in production`);
  }
  const ephemeral = crypto.randomBytes(32).toString('hex');
  console.warn(`${name} is not configured; using an ephemeral development-only value.`);
  return ephemeral;
}

const PORT = process.env.PORT || 8080;
const YOUTUBE_CHANNEL_ID = String(process.env.YOUTUBE_CHANNEL_ID || '').trim();
const ADMIN_TOKEN_ADD = getRequiredSecret('ADMIN_TOKEN_ADD');
const ADMIN_TOKEN_REMOVE = getRequiredSecret('ADMIN_TOKEN_REMOVE');
const ADMIN_TOKEN_DASH = getRequiredSecret('ADMIN_TOKEN_DASH');
const ADMIN_TOKEN_AUDIT = String(process.env.ADMIN_TOKEN_AUDIT || '').trim() || ADMIN_TOKEN_DASH;
// Admin credentials must come from the environment. These previously fell back
// to a default email and a bcrypt hash committed in this repo, so a missing env
// var silently re-enabled a password anyone with repo access could extract.
// A sentinel is used outside production rather than an empty string, so nothing
// can ever match by comparing blank to blank.
const ADMIN_CREDENTIAL_DISABLED = '__admin_credentials_not_configured__';
const requireAdminCredential = (name) => {
  const value = String(process.env[name] || '').trim();
  if (value) return value;
  if (process.env.NODE_ENV === 'production') {
    throw new Error(`${name} must be configured in production`);
  }
  console.warn(`${name} is not configured; admin email/password login is disabled in this environment.`);
  return ADMIN_CREDENTIAL_DISABLED;
};
const ADMIN_LOGIN_EMAIL = requireAdminCredential('ADMIN_LOGIN_EMAIL').toLowerCase();
const ADMIN_PASSWORD_HASH = requireAdminCredential('ADMIN_PASSWORD_HASH');
const ADMIN_CREDENTIALS_READY = ADMIN_LOGIN_EMAIL !== ADMIN_CREDENTIAL_DISABLED
  && ADMIN_PASSWORD_HASH !== ADMIN_CREDENTIAL_DISABLED;
const ADMIN_SESSION_COOKIE = 'bh_admin_session_v2';
const ADMIN_PROTECTED_PAGES = new Set([
  '/admin-menu.html',
  '/admin-add.html',
  '/admin-manage.html',
  '/admin-dashboard.html',
  '/admin-provider-detail.html',
  '/admin-main.html',
  '/admin-audit.html',
  '/admin-newsletter.html',
  '/admin-territory.html',
  '/admin-hiring.html',
  '/admin-discharge-leads.html',
  '/admin-testimonials.html',
  '/admin-provider-notifications.html'
]);

function isAdminMainToken(token) {
  return token === ADMIN_TOKEN_DASH || token === ADMIN_TOKEN_AUDIT;
}
function parseCookies(req) {
  const raw = String(req.headers.cookie || '');
  return raw.split(';').reduce((acc, part) => {
    const idx = part.indexOf('=');
    if (idx <= 0) return acc;
    const key = part.slice(0, idx).trim();
    const value = part.slice(idx + 1).trim();
    if (!key) return acc;
    try {
      acc[key] = decodeURIComponent(value);
    } catch (_err) {
      acc[key] = value;
    }
    return acc;
  }, {});
}
function getAdminSession(req) {
  const token = parseCookies(req)[ADMIN_SESSION_COOKIE];
  if (!token) return null;
  try {
    const payload = jwt.verify(token, ADMIN_SESSION_SECRET);
    if (payload?.type !== 'admin_session') return null;
    if (!ADMIN_CREDENTIALS_READY) return null;
    if (String(payload.email || '').trim().toLowerCase() !== ADMIN_LOGIN_EMAIL) return null;
    return payload;
  } catch (_err) {
    return null;
  }
}
function setAdminSessionCookie(res, token) {
  const secure = process.env.NODE_ENV === 'production';
  const cookieParts = [
    `${ADMIN_SESSION_COOKIE}=${encodeURIComponent(token)}`,
    'Path=/',
    'HttpOnly',
    'SameSite=Lax',
    'Max-Age=43200'
  ];
  if (secure) cookieParts.push(`Domain=${process.env.COOKIE_DOMAIN || '.besthospice.com'}`);
  if (secure) cookieParts.push('Secure');
  res.setHeader('Set-Cookie', cookieParts.join('; '));
}
function clearAdminSessionCookie(res) {
  const secure = process.env.NODE_ENV === 'production';
  const cookieParts = [
    `${ADMIN_SESSION_COOKIE}=`,
    'Path=/',
    'HttpOnly',
    'SameSite=Lax',
    'Max-Age=0'
  ];
  if (secure) cookieParts.push(`Domain=${process.env.COOKIE_DOMAIN || '.besthospice.com'}`);
  if (secure) cookieParts.push('Secure');
  res.setHeader('Set-Cookie', cookieParts.join('; '));
}
function hasAdminAccess(req, scopes = []) {
  if (getAdminSession(req)) return true;
  const token = String(req.headers['x-admin-token'] || '').trim();
  return scopes.some((scope) => {
    if (scope === 'add') return token === ADMIN_TOKEN_ADD;
    if (scope === 'remove') return token === ADMIN_TOKEN_REMOVE;
    if (scope === 'dash') return token === ADMIN_TOKEN_DASH;
    if (scope === 'audit') return token === ADMIN_TOKEN_AUDIT;
    if (scope === 'main') return isAdminMainToken(token);
    return false;
  });
}
const TURNSTILE_SECRET_KEY = process.env.TURNSTILE_SECRET_KEY || process.env.TURNSTILE_SECRET || '';
const TURNSTILE_BYPASS = process.env.TURNSTILE_BYPASS === 'true';
const TURNSTILE_SITE_KEY = process.env.TURNSTILE_SITE_KEY || '';
const RATE_LIMIT_PER_WINDOW = 5;
const RATE_LIMIT_WINDOW_MS = 2 * 60 * 60 * 1000; // 2 hours
const AUTH_RATE_LIMIT_PER_WINDOW = 10;
const AUTH_RATE_LIMIT_WINDOW_MS = 60 * 60 * 1000; // 1 hour
const CHAT_RATE_LIMIT = 20; // max Abel messages per IP per hour
const CHAT_RATE_WINDOW_MS = 60 * 60 * 1000; // 1 hour
const ADMIN_LOGIN_FAILED_LIMIT = 5;
const ADMIN_LOGIN_FAILED_WINDOW_MS = 60 * 60 * 1000; // 1 hour
const AUTH_RATE_LIMIT_BYPASS_IPS = new Set(
  String(process.env.AUTH_RATE_LIMIT_BYPASS_IPS || '')
    .split(',')
    .map((ip) => ip.trim())
    .filter(Boolean)
);
const IP_SALT = process.env.IP_SALT || 'besthospice-salt';
const chatRateLimitMap = new Map(); // ipHash -> { count, windowStart }
function checkChatRateLimit(ipHash) {
  const now = Date.now();
  const entry = chatRateLimitMap.get(ipHash);
  if (!entry || now - entry.windowStart > CHAT_RATE_WINDOW_MS) {
    chatRateLimitMap.set(ipHash, { count: 1, windowStart: now });
    return true;
  }
  if (entry.count >= CHAT_RATE_LIMIT) return false;
  entry.count++;
  return true;
}
const EMAIL_ENABLED = emailEnabled();
const NEWSLETTER_FROM_EMAIL = process.env.NEWSLETTER_FROM_EMAIL || 'no-reply@besthospice.com';
const NEWSLETTER_UNSUBSCRIBE_SECRET = process.env.NEWSLETTER_UNSUBSCRIBE_SECRET || '';
const PROVIDER_JWT_SECRET = getRequiredSecret('PROVIDER_JWT_SECRET');
const ADMIN_SESSION_SECRET = getRequiredSecret('ADMIN_SESSION_SECRET');
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
const normalizeCheckoutPlan = (value) => {
  const plan = String(value || '').trim().toLowerCase();
  if (plan === 'verified' || plan === 'featured' || plan === 'priority') return plan;
  if (plan === '5locenterprise' || plan === 'enterprise' || plan === 'enterprise5' || plan === '5loc') return '5locenterprise';
  if (plan === '10locenterprise' || plan === 'enterprise10' || plan === '10loc') return '10locenterprise';
  return 'verified';
};
const normalizeCareType = (value) => {
  const type = String(value || '').trim().toLowerCase();
  if (type === 'hospice' || type === 'hospice-care') return 'hospice';
  if (type === 'palliative' || type === 'palliative-care') return 'palliative';
  if (type === 'home' || type === 'home-care') return 'home';
  return 'hospice';
};
const normalizeZipCodeList = (value) => {
  const asString = Array.isArray(value) ? value.join(',') : String(value || '');
  const zips = asString
    .split(/[\s,;\n\r\t]+/)
    .map((z) => z.trim())
    .filter((z) => /^\d{5}$/.test(z));
  return Array.from(new Set(zips));
};
const zipCodesToStorage = (value) => {
  const zips = normalizeZipCodeList(value);
  return zips.length ? zips.join(',') : null;
};
const normalizeTusconText = (value) => String(value || '').replace(/\bTuscon\b/gi, 'Tucson');
const normalizeProviderCitySpelling = (provider) => {
  if (!provider || typeof provider !== 'object') return provider;
  return {
    ...provider,
    city: normalizeTusconText(provider.city),
    address: normalizeTusconText(provider.address)
  };
};

async function fixTusconProviderData() {
  try {
    await prisma.$executeRawUnsafe(`UPDATE "Provider" SET city='Tucson' WHERE city='Tuscon'`);
    await prisma.$executeRawUnsafe(`UPDATE "Provider" SET address=REPLACE(address,'Tuscon','Tucson') WHERE address LIKE '%Tuscon%'`);
  } catch (err) {
    console.error('Tuscon->Tucson data fix skipped', err?.message || err);
  }
}
const PROVIDER_MONTHLY_RATE = 250;
const PROVIDER_TIER_RATES = { verified: 250, featured: 375, priority: 500 };
// Assumed revenue to a provider per admitted client. Estimate only; used in Abel's ROI answers.
// Defaults for Abel's ROI math, matching the dashboard calculator's starting values.
const DEFAULT_REVENUE_PER_CLIENT_MONTH = 1000;
const DEFAULT_MONTHS_PER_CLIENT = 3;
// The provider dashboard already prices by tier (planToPrice in provider-dashboard-home.html).
// Abel must agree with it, or a priority provider is quoted the verified rate.
const providerRateForTier = (planTier) => PROVIDER_TIER_RATES[normalizePlanTier(planTier)] || PROVIDER_MONTHLY_RATE;
const providerRateById = async (providerId) => {
  if (!providerId) return PROVIDER_MONTHLY_RATE;
  try {
    const provider = await prisma.provider.findUnique({ where: { id: providerId }, select: { planTier: true } });
    return providerRateForTier(provider?.planTier);
  } catch (err) {
    console.error('providerRateById failed, using default rate', err?.message || err);
    return PROVIDER_MONTHLY_RATE;
  }
};
// Admin-confirmed admissions for a provider - the same source the admin dashboard counts.
const providerAdmittedCount = async (providerId) => {
  if (!providerId) return 0;
  try {
    await ensureLeadAdminStatusColumns();
    const rows = await prisma.$queryRaw`
      SELECT COUNT(*)::int AS n FROM "Lead"
      WHERE "adminStatus" = 'admitted' AND "adminProviderId" = ${providerId}
    `;
    return Number(rows?.[0]?.n || 0);
  } catch (err) {
    console.error('providerAdmittedCount failed', err?.message || err);
    return 0;
  }
};
const PLAN_NOTIFY_DELAY_MS = { priority: 0, featured: 60 * 1000, verified: 120 * 1000 };
// Mirrors getPlanRank in search-results.js so listing order matches everywhere.
const PLAN_RANK = { priority: 3, featured: 2, verified: 1 };
// One step down per cancellation; verified is the floor.
const PROVIDER_TIER_DEMOTION = { priority: 'featured', featured: 'verified', verified: 'verified' };
const planRank = (planTier) => PLAN_RANK[normalizePlanTier(planTier)] || 1;
const byPlanThenName = (a, b) => {
  const rank = planRank(b.planTier) - planRank(a.planTier);
  if (rank !== 0) return rank;
  const feat = (b.featured ? 1 : 0) - (a.featured ? 1 : 0);
  if (feat !== 0) return feat;
  return String(a.name || '').localeCompare(String(b.name || ''));
};
const JOB_POLL_MS = 5000;
const JOB_LOCK_TIMEOUT_MS = 5 * 60 * 1000;
const JOB_MAX_ATTEMPTS = 3;
const JOB_RETRY_DELAY_MS = 5 * 60 * 1000;
const BLOG_VERIFICATION_WINDOW_MS = 24 * 60 * 60 * 1000;
const LEAD_STATUS_SIGNING_SECRET = process.env.LEAD_STATUS_SIGNING_SECRET || PROVIDER_JWT_SECRET;
const LEAD_STATUS_NUDGE_DELAY_MS = 7 * 24 * 60 * 60 * 1000;
const LEAD_STATUS_NUDGE_ENABLED = process.env.LEAD_STATUS_NUDGE_ENABLED === 'true';
const LEAD_OUTCOME_VALUES = ['new', 'contacted', 'qualified', 'admitted', 'not_a_fit', 'no_response'];
const LEAD_OUTCOME_LABELS = {
  new: 'Received',
  contacted: 'Contacted',
  qualified: 'Contacted',
  admitted: 'Admitted',
  not_a_fit: 'Not a True Lead',
  no_response: 'Not a True Lead'
};

let newsletterTableReady = false;
async function ensureNewsletterSubscribersTable() {
  if (newsletterTableReady) return;
  await prisma.$executeRawUnsafe(`
    CREATE TABLE IF NOT EXISTS newsletter_subscribers (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      email TEXT NOT NULL UNIQUE,
      source TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);
  await prisma.$executeRawUnsafe(`
    CREATE INDEX IF NOT EXISTS idx_newsletter_subscribers_email
    ON newsletter_subscribers(email)
  `);
  newsletterTableReady = true;
}

let websiteEventsTableReady = false;
async function ensureWebsiteEventsTable() {
  if (websiteEventsTableReady) return;
  await prisma.$executeRawUnsafe(`
    CREATE TABLE IF NOT EXISTS website_events (
      id TEXT PRIMARY KEY,
      viewer_id TEXT NOT NULL,
      session_id TEXT NOT NULL,
      event_type TEXT NOT NULL,
      path TEXT NOT NULL,
      referrer TEXT,
      duration_ms INTEGER,
      scroll_depth INTEGER,
      event_value TEXT,
      metadata_json TEXT,
      user_agent TEXT,
      ip_hash TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);
  await prisma.$executeRawUnsafe(`CREATE INDEX IF NOT EXISTS idx_website_events_created_at ON website_events(created_at)`);
  await prisma.$executeRawUnsafe(`CREATE INDEX IF NOT EXISTS idx_website_events_event_type ON website_events(event_type)`);
  await prisma.$executeRawUnsafe(`CREATE INDEX IF NOT EXISTS idx_website_events_viewer_id ON website_events(viewer_id)`);
  await prisma.$executeRawUnsafe(`CREATE INDEX IF NOT EXISTS idx_website_events_session_id ON website_events(session_id)`);
  websiteEventsTableReady = true;
}

let waitlistTableReady = false;
async function ensureTestimonialsTable() {
  await prisma.$executeRawUnsafe(`
    CREATE TABLE IF NOT EXISTS "Testimonial" (
      id TEXT PRIMARY KEY,
      quote TEXT NOT NULL,
      author_name TEXT NOT NULL,
      author_title TEXT,
      active BOOLEAN NOT NULL DEFAULT true,
      display_order INT NOT NULL DEFAULT 0,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);
  await prisma.$executeRawUnsafe(`ALTER TABLE "Testimonial" ADD COLUMN IF NOT EXISTS "status" TEXT NOT NULL DEFAULT 'approved'`);
  await prisma.$executeRawUnsafe(`ALTER TABLE "Testimonial" ADD COLUMN IF NOT EXISTS "provider_id" TEXT`);
  await prisma.$executeRawUnsafe(`ALTER TABLE "Testimonial" ADD COLUMN IF NOT EXISTS "reviewed_at" TIMESTAMPTZ`);
}

async function ensureWaitlistTable() {
  if (waitlistTableReady) return;
  await prisma.$executeRawUnsafe(`
    CREATE TABLE IF NOT EXISTS "WaitlistRequest" (
      "id" TEXT NOT NULL,
      "zip" TEXT NOT NULL,
      "contactEmail" TEXT,
      "contactPhone" TEXT,
      "timeline" TEXT,
      "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
      CONSTRAINT "WaitlistRequest_pkey" PRIMARY KEY ("id")
    )
  `);
  waitlistTableReady = true;
}

let dischargeReferralTableReady = false;
async function ensureDischargeReferralTable() {
  if (dischargeReferralTableReady) return;
  await prisma.$executeRawUnsafe(`
    CREATE TABLE IF NOT EXISTS "DischargeReferral" (
      "id" TEXT NOT NULL,
      "planner_name" TEXT,
      "planner_title" TEXT,
      "planner_email" TEXT,
      "planner_phone" TEXT,
      "facility" TEXT,
      "patient_first" TEXT,
      "patient_last" TEXT,
      "patient_zip" TEXT,
      "care_type" TEXT,
      "urgency" TEXT,
      "insurance" TEXT,
      "notes" TEXT,
      "status" TEXT NOT NULL DEFAULT 'new',
      "source" TEXT NOT NULL DEFAULT 'discharge_planner',
      "submitted_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
      CONSTRAINT "DischargeReferral_pkey" PRIMARY KEY ("id")
    )
  `);
  dischargeReferralTableReady = true;
}

let jobLeadTableReady = false;
async function ensureJobLeadTable() {
  if (jobLeadTableReady) return;
  await prisma.$executeRawUnsafe(`
    CREATE TABLE IF NOT EXISTS "JobLead" (
      "id" TEXT NOT NULL,
      "zip" TEXT NOT NULL,
      "name" TEXT,
      "email" TEXT,
      "phone" TEXT,
      "role" TEXT,
      "licensed" TEXT,
      "availability" TEXT,
      "timeline" TEXT,
      "experience" TEXT,
      "openToMultiple" TEXT,
      "notifiedProviderIds" TEXT,
      "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
      CONSTRAINT "JobLead_pkey" PRIMARY KEY ("id")
    )
  `);
  await prisma.$executeRawUnsafe(`
    ALTER TABLE "Provider" ADD COLUMN IF NOT EXISTS "activelyHiring" BOOLEAN NOT NULL DEFAULT TRUE
  `);
  await prisma.$executeRawUnsafe(`
    ALTER TABLE "Provider" ADD COLUMN IF NOT EXISTS "receiveClientLeads" BOOLEAN NOT NULL DEFAULT TRUE
  `);
  await prisma.$executeRawUnsafe(`
    ALTER TABLE "Provider" ADD COLUMN IF NOT EXISTS "receiveJobLeads" BOOLEAN NOT NULL DEFAULT TRUE
  `);
  jobLeadTableReady = true;
}

function haversineKm(lat1, lon1, lat2, lon2) {
  const toRad = (v) => (v * Math.PI) / 180;
  const R = 6371;
  const dLat = toRad(lat2 - lat1);
  const dLon = toRad(lon2 - lon1);
  const a = Math.sin(dLat / 2) ** 2 + Math.cos(toRad(lat1)) * Math.cos(toRad(lat2)) * Math.sin(dLon / 2) ** 2;
  return R * 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
}

let leadSessionColumnReady = false;
let leadAdminStatusColumnReady = false;
async function ensureLeadSessionColumn() {
  if (leadSessionColumnReady) return;
  await prisma.$executeRawUnsafe(`ALTER TABLE "Lead" ADD COLUMN IF NOT EXISTS "sessionId" TEXT`);
  await prisma.$executeRawUnsafe(`CREATE INDEX IF NOT EXISTS idx_lead_session_id ON "Lead"("sessionId")`);
  leadSessionColumnReady = true;
}

let providerStripeColumnsReady = false;
async function ensureProviderStripeColumns() {
  if (providerStripeColumnsReady) return;
  await prisma.$executeRawUnsafe(`ALTER TABLE "Provider" ADD COLUMN IF NOT EXISTS "stripeCustomerId" TEXT`);
  await prisma.$executeRawUnsafe(`ALTER TABLE "Provider" ADD COLUMN IF NOT EXISTS "stripeSubscriptionId" TEXT`);
  await prisma.$executeRawUnsafe(`ALTER TABLE "Provider" ADD COLUMN IF NOT EXISTS "subscriptionStatus" TEXT`);
  await prisma.$executeRawUnsafe(`ALTER TABLE "Provider" ADD COLUMN IF NOT EXISTS "currentPeriodEnd" TIMESTAMP`);
  // billingMode defaults to 'free' so every provider that already exists is
  // grandfathered and can never be gated by accident.
  await prisma.$executeRawUnsafe(`ALTER TABLE "Provider" ADD COLUMN IF NOT EXISTS "billingMode" TEXT NOT NULL DEFAULT 'free'`);
  providerStripeColumnsReady = true;
}

// A provider is one of three things, and nothing is time-based:
//   free     - comped, receives leads, never billed
//   billed   - expected to pay; Stripe decides whether they are current
//   off      - switched off by hand, receives nothing
// billingMode defaults to 'free', so every provider that already exists keeps
// receiving leads and only an explicit change can ever stop that.
const providerBillingState = (row) => {
  const mode = String(row?.billingMode || 'free').toLowerCase();

  if (mode === 'off') {
    return { state: 'off', label: 'Off — No Leads', leadsAllowed: false };
  }
  if (mode === 'free') {
    return { state: 'free', label: 'Free Version', leadsAllowed: true };
  }
  if (SUBSCRIPTION_ON_STATUSES.has(String(row?.subscriptionStatus || '').toLowerCase())) {
    return { state: 'paying', label: 'Paying Customer', leadsAllowed: true };
  }
  // Billed but Stripe does not show them current.
  return { state: 'off', label: 'Not Paying — No Leads', leadsAllowed: false };
};

// Newer Stripe API versions moved current_period_end onto the subscription items.
const subscriptionPeriodEnd = (subscription) => {
  if (!subscription) return null;
  if (Number.isFinite(subscription.current_period_end)) return subscription.current_period_end;
  const item = subscription.items?.data?.[0];
  return Number.isFinite(item?.current_period_end) ? item.current_period_end : null;
};

// Stripe statuses that mean the provider is genuinely paying right now.
const SUBSCRIPTION_ON_STATUSES = new Set(['active', 'trialing']);
const SUBSCRIPTION_WARN_STATUSES = new Set(['past_due', 'incomplete']);
const subscriptionBannerState = (status) => {
  const value = String(status || '').trim().toLowerCase();
  if (SUBSCRIPTION_ON_STATUSES.has(value)) return 'on';
  if (SUBSCRIPTION_WARN_STATUSES.has(value)) return 'warn';
  return 'off';
};

async function ensureLeadAdminStatusColumns() {
  if (leadAdminStatusColumnReady) return;
  await prisma.$executeRawUnsafe(`ALTER TABLE "Lead" ADD COLUMN IF NOT EXISTS "adminStatus" TEXT`);
  await prisma.$executeRawUnsafe(`ALTER TABLE "Lead" ADD COLUMN IF NOT EXISTS "adminProviderId" TEXT`);
  leadAdminStatusColumnReady = true;
}

// --- SEO / programmatic helpers ---
const slugify = (str) =>
  String(str || '')
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 80);

const serviceConfig = {
  'hospice-care': {
    localNotes: 'Families in {stateName} often need hospice care that can start quickly, with in-home options, reliable after-hours nursing support, and clear guidance on Medicare eligibility and coverage. When comparing providers in {stateName}, ask how fast intake can begin, whether care is available on weekends and overnight, and how the team communicates with family members who live out of state.',
    name: 'Hospice Care',
    direct:
      'Hospice care in {cityState} focuses on comfort, dignity, and quality of life when curative treatment is no longer the goal. Families in {cityState} need fast access to compassionate nursing teams, clear communication about what Medicare covers, and dependable support whether care is provided at home, in assisted living, or in an inpatient facility.',
    cost: 'Most hospice care in {stateName} is covered by Medicare Part A and many private insurers. Medicare typically covers nursing visits, comfort medications, medical equipment, aide services, social work, and counseling at little to no out-of-pocket cost. Out-of-pocket costs are generally limited to room-and-board in certain facility settings. Providers verify insurance eligibility and explain costs before services begin.',
    eligibility:
      'Hospice care is appropriate when a physician certifies a terminal illness with a prognosis of 6 months or less and the patient chooses comfort-focused over curative care. Common qualifying conditions include advanced cancer, end-stage heart or lung disease, late-stage dementia, kidney failure, and ALS. Families can also ask a provider to conduct a free eligibility review.',
    faq: [
      ['What does hospice care mean?', 'Hospice care centers on comfort, dignity, and quality of life for patients nearing the end of life. Instead of curative treatment, hospice focuses on pain and symptom relief, emotional support, and family guidance.'],
      ['Is hospice care only provided at home?', 'No. Hospice care can be provided at home, in an assisted living facility, in a nursing home, or in a dedicated inpatient hospice facility. Most families prefer home-based hospice when possible.'],
      ['How quickly can hospice care start?', 'Many providers can begin services within 24–48 hours after a physician certifies eligibility. In urgent situations, some agencies offer same-day intake.'],
      ['Does Medicare cover hospice care costs?', 'Yes. Medicare Part A covers most hospice services at little to no out-of-pocket cost, including nursing visits, medications for symptom control, medical equipment, and counseling. Eligibility requires a terminal diagnosis with a 6-month prognosis.'],
      ['Who is on the hospice care team?', 'A hospice team typically includes registered nurses, physicians, home health aides, social workers, chaplains, and bereavement counselors — all working together to support both the patient and the family.'],
      ['How do I find hospice care providers near me?', 'Enter your ZIP code on BestHospice.com to instantly view verified hospice care providers in your area at no cost to your family.'],
      ['What is the difference between hospice and palliative care?', 'Hospice care is for patients who have stopped curative treatment and have a prognosis of 6 months or less. Palliative care can begin at any stage of illness alongside curative treatment, focusing on symptom relief and quality of life.'],
      ['Can a patient leave hospice care?', 'Yes. Patients can revoke hospice benefits at any time and return to curative treatment. They can re-enroll in hospice later if eligibility criteria are met again.']
    ]
  },
  'palliative-care': {
    localNotes: 'In {stateName}, palliative care is commonly used alongside treatment to manage pain, symptoms, and care coordination close to home.',
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
    localNotes: 'Home care in {stateName} is frequently used for daily living support, respite for caregivers, and help with mobility and meals.',
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

const HUB_LONGFORM_CONTENT = {
  'hospice-care': {
    title: 'Hospice Care Guide: What It Is, Who Needs It, and How to Choose',
    intro: [
      'Hospice care is specialized, comfort-focused support for people living with a terminal illness when the goal of care shifts from cure to quality of life. Families often hear the word hospice during one of the most emotional periods of their lives, and many are unsure what it really means. In practice, hospice is a coordinated care model that helps patients stay comfortable and supported while helping loved ones make informed decisions and avoid unnecessary stress.',
      'Hospice is not abandonment of care. It is active care with a different priority. Instead of repeated hospital visits and aggressive treatment side effects, the hospice model prioritizes pain relief, symptom management, dignity, and family support. Many families report that hospice gave them a clearer plan, better communication, and more peaceful time together at home.',
      'Best Hospice and Home Health helps families compare verified providers by location so they can quickly find agencies with the right coverage area, care philosophy, and communication style.'
    ],
    sections: [
      {
        heading: 'Who Hospice Care Is For',
        paragraphs: [
          'Hospice is most often appropriate when a doctor believes a patient may have six months or less to live if the illness follows its typical course. Common conditions include advanced cancer, end-stage heart or lung disease, late-stage dementia, kidney failure, and neurologic conditions such as ALS.',
          'Eligibility is based on medical criteria and physician certification, but the family decision is just as important. Hospice is usually the right fit when treatment burden outweighs benefit, symptoms are difficult to control, and the patient wants comfort-focused support.',
          'Choosing hospice does not lock a patient in forever. A patient can revoke hospice if they want to return to curative treatment, and can re-enroll later if eligibility criteria are met again.'
        ]
      },
      {
        heading: 'What Hospice Services Include',
        paragraphs: [
          'A hospice care plan is delivered by an interdisciplinary team that may include a physician, registered nurse, hospice aide, social worker, chaplain, bereavement counselor, and trained volunteers. Together they manage pain and symptoms while supporting emotional, practical, and spiritual needs.',
          'Typical services include nursing visits, comfort medications related to the terminal diagnosis, durable medical equipment such as oxygen or a hospital bed, aide support for personal care, caregiver training, and 24/7 on-call support for urgent symptom changes.',
          'Hospice can be delivered in multiple settings: private home, assisted living, skilled nursing, hospice house, or inpatient unit. Most families prefer home-based hospice when feasible because it keeps routines and surroundings familiar.'
        ]
      },
      {
        heading: 'How to Choose the Right Hospice Provider',
        paragraphs: [
          'Families should compare more than one provider whenever possible. Ask how quickly intake can happen, whether nurses are available after hours, how often routine visits occur, and how emergencies are handled overnight or on weekends.',
          'Quality signals include clear communication, realistic care planning, responsive call-back times, and strong caregiver education. It is also important to ask if the agency has experience with your loved one’s diagnosis, whether they coordinate medication delivery quickly, and how they support family grief before and after loss.',
          'Use provider profiles to verify service area, phone and website contact details, and available care types. A strong provider relationship starts with fast response and transparent expectations.'
        ]
      },
      {
        heading: 'Medicare and Hospice Coverage',
        paragraphs: [
          'For most eligible beneficiaries, Medicare Part A covers hospice care with minimal out-of-pocket cost. Coverage usually includes nursing services, hospice aide support, social work, chaplain services, comfort medications tied to the terminal diagnosis, and medical equipment.',
          'Medicare hospice benefit periods include two 90-day periods followed by unlimited 60-day recertification periods as long as eligibility continues. Patients may have small copays in limited scenarios, but most core hospice services are fully covered.',
          'Private insurance and Medicaid may also cover hospice care, but benefits vary by plan and state. A quality provider verifies coverage quickly and explains exactly what is and is not included before services begin.'
        ]
      },
      {
        heading: 'Common Questions Families Ask',
        paragraphs: [
          'Families often ask whether hospice means giving up. In reality, hospice means changing the goal from cure to comfort while still receiving intensive support. Others ask whether hospice can start too early; most providers say earlier enrollment improves comfort and reduces crisis-driven decisions.',
          'Another frequent concern is whether care can continue if a patient lives beyond six months. The answer is yes if recertification shows continued eligibility. Families also ask whether they can change agencies; they can. Patients and representatives maintain choice.',
          'The best next step is usually to speak with a provider directly, review response expectations, and confirm how the team will support both patient comfort and caregiver resilience.'
        ]
      }
    ]
  },
  'palliative-care': {
    title: 'Palliative Care Guide: Symptom Relief, Care Coordination, and Coverage',
    intro: [
      'Palliative care is specialized medical support for people with serious illness at any stage, including during active treatment. The focus is relief of pain, symptoms, stress, and decision burden. Unlike hospice, palliative care does not require stopping curative treatment.',
      'Many families benefit from palliative care earlier than they expect. When symptoms are controlled and communication improves, patients often feel stronger and more informed. Palliative teams help coordinate specialists, clarify treatment goals, and reduce emergency utilization.',
      'Best Hospice and Home Health helps families locate palliative-capable providers and compare options in their state and city.'
    ],
    sections: [
      {
        heading: 'How Palliative Care Differs from Hospice',
        paragraphs: [
          'Both hospice and palliative care prioritize comfort and quality of life, but they are not the same program. Hospice is generally for end-of-life care when curative treatment is no longer pursued. Palliative care can begin at diagnosis and run alongside chemotherapy, dialysis, heart failure treatment, or other curative plans.',
          'A practical way to think about this is timing and treatment intent. Palliative care is an added layer of support during serious illness. Hospice is a full care model when comfort becomes the primary goal.'
        ]
      },
      {
        heading: 'Who Benefits Most from Palliative Care',
        paragraphs: [
          'Patients with cancer, COPD, congestive heart failure, kidney disease, neurologic illness, dementia, and other complex conditions often benefit from palliative services. Frequent hospitalizations, uncontrolled symptoms, and caregiver burnout are strong indicators it is time to request a palliative consult.',
          'Palliative teams are especially helpful when families face hard choices or conflicting specialist recommendations. They translate complex medical options into clear tradeoffs and align care plans with patient values.'
        ]
      },
      {
        heading: 'What Palliative Teams Actually Do',
        paragraphs: [
          'Core services include advanced symptom management, medication optimization, goals-of-care conversations, psychosocial support, and care coordination across clinics, hospitals, and home settings.',
          'Palliative clinicians also support advance care planning such as healthcare proxy, advance directive, and code-status conversations. This planning reduces confusion during urgent events and helps families feel prepared.'
        ]
      },
      {
        heading: 'Insurance Coverage and Cost Expectations',
        paragraphs: [
          'Coverage depends on where and how services are delivered. Hospital and clinic-based palliative consults are often billed under standard medical benefits, including Medicare Part B and many private plans. Home-based palliative programs may vary by insurer and region.',
          'Because benefit design differs, families should confirm copays, visit limits, telehealth availability, and referral requirements. Providers can usually help verify this before ongoing care begins.'
        ]
      },
      {
        heading: 'How to Get Started',
        paragraphs: [
          'Ask your current physician directly for a palliative care referral and explain the symptoms or care-planning gaps you want help with. You can also contact local providers to confirm service area and intake timelines.',
          'When comparing options, ask about response times, after-hours access, care team composition, and coordination with your existing doctors. Fast communication and clear handoffs are key quality markers.'
        ]
      }
    ]
  },
  'home-care': {
    title: 'Home Care Guide: Types, Costs, Insurance, and Provider Selection',
    intro: [
      'Home care helps people remain safe and supported in familiar surroundings. Families often use home care after hospitalization, during chronic illness, or when day-to-day tasks become difficult for an older adult living at home.',
      'The most common source of confusion is the difference between non-medical home care and skilled home health care. These are different service models, billed differently, and delivered by different staff types.',
      'Best Hospice and Home Health helps families compare local home care options by city and state so they can match services to need and budget.'
    ],
    sections: [
      {
        heading: 'Non-Medical Home Care vs. Skilled Home Health',
        paragraphs: [
          'Non-medical home care includes support with activities of daily living such as bathing, dressing, meal preparation, companionship, mobility support, and respite for family caregivers. These services are usually arranged directly and often paid privately.',
          'Skilled home health care is clinical care ordered by a physician and delivered by licensed clinicians such as RNs and therapists. It may include wound care, medication management, physical therapy, and post-acute monitoring.'
        ]
      },
      {
        heading: 'Typical Home Care Costs',
        paragraphs: [
          'Costs vary by geography, schedule, and service complexity. Non-medical care is commonly billed hourly, while skilled visits are often billed per visit and may be covered when eligibility requirements are met.',
          'Families should ask for a written rate sheet, minimum-hour rules, overtime/holiday pricing, and cancellation terms. Transparent agencies provide clear documentation and avoid surprise billing.'
        ]
      },
      {
        heading: 'What Insurance May Cover',
        paragraphs: [
          'Medicare usually covers skilled home health when criteria are met, but generally does not cover long-duration custodial support such as routine bathing or meal prep without a skilled need. Medicaid coverage varies by state and waiver availability.',
          'Long-term care insurance may cover non-medical services depending on policy terms. Families should request pre-authorization guidance and direct insurer verification from the provider when possible.'
        ]
      },
      {
        heading: 'How to Choose a Home Care Provider',
        paragraphs: [
          'Ask about caregiver screening, supervision, backup coverage, and continuity plans when a regular caregiver is unavailable. Reliability and consistency are often more important than a small hourly price difference.',
          'Confirm whether the provider can scale from part-time to higher-intensity schedules if needs change. Strong agencies can adapt care plans quickly and coordinate with hospice or palliative teams when appropriate.'
        ]
      },
      {
        heading: 'When Home Care Is Not Enough',
        paragraphs: [
          'If safety risks become severe, nighttime needs increase beyond available support, or medical complexity rises sharply, families may need higher-acuity options. In those cases, a provider can help evaluate facility-based care or layered services.',
          'Early planning is essential. Reviewing backup pathways before a crisis helps families avoid rushed decisions and maintain continuity for the patient.'
        ]
      }
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

const EASTERN_HOUR_FORMATTER = new Intl.DateTimeFormat('en-US', {
  timeZone: 'America/New_York',
  hour: '2-digit',
  minute: '2-digit',
  hour12: false
});
const EASTERN_WEEKDAY_FORMATTER = new Intl.DateTimeFormat('en-US', {
  timeZone: 'America/New_York',
  weekday: 'short'
});

function getEasternHalfHourSlot(dateValue) {
  if (!dateValue) return null;
  const date = new Date(dateValue);
  if (Number.isNaN(date.getTime())) return null;
  const parts = EASTERN_HOUR_FORMATTER.formatToParts(date);
  const hourText = parts.find((p) => p.type === 'hour')?.value || '';
  const minuteText = parts.find((p) => p.type === 'minute')?.value || '';
  const hour = Number.parseInt(hourText, 10);
  const minute = Number.parseInt(minuteText, 10);
  if (!Number.isFinite(hour) || hour < 0 || hour > 23) return null;
  if (!Number.isFinite(minute) || minute < 0 || minute > 59) return null;
  return (hour * 2) + (minute >= 30 ? 1 : 0);
}

function getEasternWeekdayIndex(dateValue) {
  if (!dateValue) return null;
  const date = new Date(dateValue);
  if (Number.isNaN(date.getTime())) return null;
  const day = EASTERN_WEEKDAY_FORMATTER.format(date);
  const map = { Sun: 0, Mon: 1, Tue: 2, Wed: 3, Thu: 4, Fri: 5, Sat: 6 };
  return map[day] ?? null;
}

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

function normalizeStateLabel(value) {
  const raw = String(value || '').trim();
  if (!raw) return '';
  const lower = raw.toLowerCase();
  if (stateNameMap[lower]) return stateNameMap[lower];
  if (raw.length === 2 && stateNameMap[raw.toLowerCase()]) return stateNameMap[raw.toLowerCase()];
  return raw.replace(/\b\w/g, (m) => m.toUpperCase());
}

function stateCandidatesFromSlug(stateSlug) {
  const slug = String(stateSlug || '').trim().toLowerCase();
  if (!slug) return [];
  const directName = stateNameMap[slug];
  if (directName) return [slug, slug.toUpperCase(), directName];
  const byName = Object.entries(stateNameMap).find(([, name]) => slugify(name) === slug);
  if (byName) return [byName[0], byName[0].toUpperCase(), byName[1]];
  return [slug, slug.toUpperCase(), slug];
}

// Stripe webhook needs raw body
// Each Stripe webhook destination has its own signing secret. Pick up every
// env var whose name starts with STRIPE_WEBHOOK_SECRET, whatever the suffix or
// its casing, so adding a destination only means adding a variable.
const stripeWebhookSecrets = () => Object.keys(process.env)
  .filter((k) => k.toUpperCase().startsWith('STRIPE_WEBHOOK_SECRET'))
  .sort()
  .map((k) => String(process.env[k] || '').trim())
  .filter((v) => v.startsWith('whsec_'));

app.post('/api/stripe/webhook', express.raw({ type: 'application/json' }), async (req, res) => {
  const secrets = stripeWebhookSecrets();
  if (!stripe || !secrets.length) {
    return res.status(500).send('Stripe not configured');
  }
  const sig = req.headers['stripe-signature'];
  let event = null;
  let lastErr = null;
  for (const secret of secrets) {
    try {
      event = stripe.webhooks.constructEvent(req.body, sig, secret);
      break;
    } catch (err) {
      lastErr = err;
    }
  }
  if (!event) {
    console.error(`Stripe webhook signature verification failed against ${secrets.length} secret(s)`, lastErr);
    return res.status(400).send(`Webhook Error: ${lastErr ? lastErr.message : 'signature mismatch'}`);
  }

  try {
    await ensureProviderStripeColumns();

    const setSubscription = async (providerId, fields) => {
      if (!providerId) return;
      await prisma.$executeRawUnsafe(
        `UPDATE "Provider"
         SET "stripeCustomerId" = COALESCE($1, "stripeCustomerId"),
             "stripeSubscriptionId" = COALESCE($2, "stripeSubscriptionId"),
             "subscriptionStatus" = COALESCE($3, "subscriptionStatus"),
             "currentPeriodEnd" = COALESCE($4, "currentPeriodEnd")
         WHERE "id" = $5`,
        fields.customerId || null,
        fields.subscriptionId || null,
        fields.status || null,
        fields.periodEnd ? new Date(fields.periodEnd * 1000) : null,
        providerId
      );
    };

    // Stripe only sends the provider id on the checkout session, so later
    // subscription events are resolved back through the stored ids.
    const providerIdForSubscription = async (subscription) => {
      const fromMetadata = subscription?.metadata?.providerId;
      if (fromMetadata) return fromMetadata;
      const rows = await prisma.$queryRaw`
        SELECT id FROM "Provider"
        WHERE "stripeSubscriptionId" = ${String(subscription?.id || '')}
           OR "stripeCustomerId" = ${String(subscription?.customer || '')}
        LIMIT 1
      `;
      return rows?.[0]?.id || null;
    };

    if (event.type === 'checkout.session.completed') {
      const session = event.data.object;
      const providerId = session.metadata?.providerId;
      if (providerId) {
        let status = 'active';
        let periodEnd = null;
        if (session.subscription && stripe) {
          try {
            const sub = await stripe.subscriptions.retrieve(String(session.subscription));
            status = sub.status || 'active';
            periodEnd = subscriptionPeriodEnd(sub);
          } catch (subErr) {
            console.error('Could not retrieve subscription after checkout', subErr?.message || subErr);
          }
        }
        await setSubscription(providerId, {
          customerId: session.customer ? String(session.customer) : null,
          subscriptionId: session.subscription ? String(session.subscription) : null,
          status,
          periodEnd
        });
        // Record the plan that was actually bought. Previously every checkout set
        // featured = true, which ranked a $250 Verified listing like a $500 Priority one.
        const purchasedTier = normalizePlanTier(session.metadata?.planTier || session.metadata?.plan);
        await prisma.provider.update({
          where: { id: providerId },
          data: { planTier: purchasedTier, featured: purchasedTier !== 'verified' }
        });
      }
    } else if (event.type === 'customer.subscription.updated' || event.type === 'customer.subscription.created') {
      const sub = event.data.object;
      const providerId = await providerIdForSubscription(sub);
      await setSubscription(providerId, {
        customerId: sub.customer ? String(sub.customer) : null,
        subscriptionId: sub.id ? String(sub.id) : null,
        status: sub.status || null,
        periodEnd: subscriptionPeriodEnd(sub)
      });
    } else if (event.type === 'customer.subscription.deleted') {
      const sub = event.data.object;
      const providerId = await providerIdForSubscription(sub);
      if (providerId) {
        await prisma.$executeRawUnsafe(
          `UPDATE "Provider" SET "subscriptionStatus" = 'canceled' WHERE "id" = $1`,
          providerId
        );
        // Cancelling drops the listing one tier, so ranking follows payment.
        const current = await prisma.provider.findUnique({
          where: { id: providerId },
          select: { planTier: true }
        });
        const demoted = PROVIDER_TIER_DEMOTION[normalizePlanTier(current?.planTier)] || 'verified';
        await prisma.provider.update({
          where: { id: providerId },
          data: { planTier: demoted, featured: demoted !== 'verified' }
        });
        await logAdminAction(
          'system', 'PROVIDER_TIER_DEMOTED', providerId,
          { from: normalizePlanTier(current?.planTier), to: demoted, reason: 'subscription canceled' },
          hashIp(req.ip || '')
        );
      }
    } else if (event.type === 'invoice.payment_failed' || event.type === 'invoice.paid') {
      const invoice = event.data.object;
      if (invoice.subscription && stripe) {
        try {
          const sub = await stripe.subscriptions.retrieve(String(invoice.subscription));
          const providerId = await providerIdForSubscription(sub);
          await setSubscription(providerId, {
            customerId: sub.customer ? String(sub.customer) : null,
            subscriptionId: sub.id ? String(sub.id) : null,
            status: sub.status || null,
            periodEnd: subscriptionPeriodEnd(sub)
          });
        } catch (invErr) {
          console.error('Could not sync subscription from invoice event', invErr?.message || invErr);
        }
      }
    }
    res.json({ received: true });
  } catch (err) {
    console.error('Stripe webhook handling failed', err);
    res.status(500).send('Webhook handler error');
  }
});

app.use(express.json());
app.use(express.urlencoded({ extended: false }));

app.get('/healthz', (_req, res) => res.status(200).send('ok'));

app.use((_req, res, next) => {
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  next();
});

app.use((req, res, next) => {
  const hostHeader = String(req.headers['x-forwarded-host'] || req.headers.host || '').split(',')[0].trim();
  const host = hostHeader.replace(/:\d+$/, '');
  let proto = (req.headers['x-forwarded-proto'] || req.protocol || '').split(',')[0].trim();
  const cfVisitor = String(req.headers['cf-visitor'] || '').trim();
  if (cfVisitor && !proto) {
    try {
      proto = JSON.parse(cfVisitor).scheme || proto;
    } catch (_err) {
      // Ignore malformed Cloudflare visitor header.
    }
  }
  if (host && host.includes('besthospice.com')) {
    const needsRedirect = host !== CANONICAL_HOST || proto !== CANONICAL_PROTOCOL;
    if (needsRedirect && (req.method === 'GET' || req.method === 'HEAD')) {
      return res.redirect(301, `${CANONICAL_DOMAIN}${req.originalUrl}`);
    }
  }
  return next();
});

app.use((req, res, next) => {
  if ((req.method !== 'GET' && req.method !== 'HEAD') || !ADMIN_PROTECTED_PAGES.has(req.path)) {
    return next();
  }
  if (getAdminSession(req)) return next();
  const nextPath = encodeURIComponent(req.originalUrl || req.path || '/admin.html');
  return res.redirect(302, `/admin.html?next=${nextPath}`);
});

app.get('/api/admin/session', (req, res) => {
  const session = getAdminSession(req);
  if (!session) return res.status(401).json({ error: 'Unauthorized' });
  return res.json({ ok: true, email: session.email });
});

async function handleAdminLogin(req, res, { redirectOnSuccess = false } = {}) {
  const email = String(req.body?.email || '').trim().toLowerCase();
  const password = String(req.body?.password || '');
  const nextPathRaw = String(req.body?.next || req.query?.next || '').trim();
  const safeNextPath = nextPathRaw.startsWith('/') ? nextPathRaw : '/admin-menu.html';
  const fail = (status, error) => {
    if (redirectOnSuccess) {
      return res.redirect(302, `/admin.html?error=${encodeURIComponent(error)}&next=${encodeURIComponent(safeNextPath)}`);
    }
    return res.status(status).json({ error });
  };
  try {
    const failedCount = await getAdminFailedLoginCount(req);
    if (failedCount >= ADMIN_LOGIN_FAILED_LIMIT) {
      return fail(429, 'Too many failed admin login attempts. Please try again later.');
    }
    if (!email || !password) {
      return fail(400, 'Email and password are required');
    }
    if (!ADMIN_CREDENTIALS_READY) {
      return res.status(500).json({ error: 'Admin login is not configured on this server.' });
    }
    if (email !== ADMIN_LOGIN_EMAIL) {
      await recordAdminFailedLogin(req);
      return fail(401, 'Invalid credentials');
    }
    const ok = await bcrypt.compare(password, ADMIN_PASSWORD_HASH);
    if (!ok) {
      await recordAdminFailedLogin(req);
      return fail(401, 'Invalid credentials');
    }
    const token = jwt.sign(
      { type: 'admin_session', email: ADMIN_LOGIN_EMAIL },
      ADMIN_SESSION_SECRET,
      { expiresIn: '12h' }
    );
    setAdminSessionCookie(res, token);
    if (redirectOnSuccess) {
      return res.redirect(302, safeNextPath || '/admin.html');
    }
    return res.json({ ok: true, email: ADMIN_LOGIN_EMAIL });
  } catch (err) {
    console.error('Admin login failed', err);
    return fail(500, 'Server error');
  }
}

app.post('/api/admin/login', async (req, res) => {
  return handleAdminLogin(req, res, { redirectOnSuccess: false });
});

app.post('/admin/login', async (req, res) => {
  return handleAdminLogin(req, res, { redirectOnSuccess: true });
});

app.post('/api/admin/logout', (req, res) => {
  clearAdminSessionCookie(res);
  return res.json({ ok: true });
});

// Dynamic city/state pages (server-rendered from live DB for automatic updates)
app.get('/cities.html', async (_req, res) => {
  try {
    const providers = await prisma.provider.findMany({
      select: {
        city: true,
        state: true,
        careType: true
      }
    });

    const grouped = {
      hospice: new Map(),
      palliative: new Map(),
      home: new Map()
    };

    for (const p of providers) {
      const city = String(p.city || '').trim();
      const stateLabel = normalizeStateLabel(p.state);
      if (!city || !stateLabel) continue;
      const careType = normalizeCareType(p.careType);
      if (!grouped[careType].has(stateLabel)) grouped[careType].set(stateLabel, new Set());
      grouped[careType].get(stateLabel).add(city);
    }

    const sectionHtml = (key, title) => {
      const stateNames = Array.from(grouped[key].keys()).sort((a, b) => a.localeCompare(b));
      if (!stateNames.length) {
        return `<section class="card content-section"><h2>${title}</h2><p class="text-muted">No cities listed yet.</p></section>`;
      }
      return `
        <section class="card content-section">
          <h2>${title}</h2>
          ${stateNames
            .map((stateName) => {
              const cityLinks = Array.from(grouped[key].get(stateName))
                .sort((a, b) => a.localeCompare(b))
                .map((city) => `<li><a href="/cities/${slugify(city)}-${slugify(stateName)}">${city}, ${stateName}</a></li>`)
                .join('');
              return `
                <h3 class="mt-sm">${stateName}</h3>
                <ul class="link-list">
                  ${Array.from(grouped[key].get(stateName))
                    .sort((a, b) => a.localeCompare(b))
                    .map((city) => `<li><a href="/cities/${slugify(city)}-${slugify(stateName)}">${city}, ${stateName}<svg viewBox="0 0 20 20" aria-hidden="true"><path d="M7 4l6 6-6 6"/></svg></a></li>`)
                    .join('')}
                </ul>`;
            })
            .join('')}
        </section>
      `;
    };

    const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Browse Cities We Serve | Best Hospice and Home Health</title>
  <meta name="description" content="Browse cities with active hospice, palliative, and home care providers listed on Best Hospice and Home Health." />
  <link rel="canonical" href="${CANONICAL_DOMAIN}/cities.html" />
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Lora:ital,wght@0,400;0,600;1,400&family=DM+Sans:opsz,wght@9..40,300;9..40,400;9..40,500;9..40,600&display=swap" rel="stylesheet">
  <link rel="stylesheet" href="/styles-modern.css" />
  <link rel="stylesheet" href="/styles/main.css" />
  <script src="/abel-chat.js" defer></script>
  <script src="/cookie-consent.js" defer></script>
  <script src="/analytics-tracker.js" defer></script>
  <script src="/marketing-consent-loader.js" defer></script>
</head>
<body>
  <div class="page-shell">
    <header class="hero page-hero">
      <div class="hero-top site-nav">
        <div class="brand">
          <img src="/BestHospiceandHomeHealthNew.png" alt="Best Hospice and Home Health logo" class="brand-logo">
        </div>
        <button class="menu-toggle" aria-label="Toggle menu" aria-expanded="false">
          <span></span><span></span><span></span>
        </button>
        <div class="top-links" id="topLinks">
          <a class="pill ghost-pill" href="/">Main Menu</a>
          <a class="pill ghost-pill" href="/locations.html">Locations We Currently Serve</a>
          <a class="pill ghost-pill" href="/cities.html">Browse Cities</a>
          <a class="pill ghost-pill" href="/education.html">Education Hub</a>
          <a class="pill ghost-pill" href="/search.html">Search</a>
        </div>
      </div>
      <div class="hero-inner">
        <div class="hero-chip"><span class="hero-chip-dot"></span>City Directory</div>
        <div class="hero-text">
          <h1>Browse Cities We Serve</h1>
          <p class="hero-sub">Direct links to city pages grouped by care type and state.</p>
        </div>
      </div>
    </header>
    <main class="page-wrap" style="position:relative;z-index:0;padding-top:32px; padding-bottom:56px;">
      ${sectionHtml('hospice', 'Hospice Care')}
      ${sectionHtml('palliative', 'Palliative Care')}
      ${sectionHtml('home', 'Home Care')}
    </main>
    <footer class="site-footer" style="position:static !important; display:block !important; clear:both !important; width:100% !important; margin-top:32px !important; z-index:1 !important;">
      <div class="footer-inner">
        <div class="footer-brand">Best Hospice and Home Health</div>
        <div class="footer-meta">Contact: contact@besthospice.com • United States</div>
        <div class="footer-links">
          <a href="/privacy.html">Privacy Policy</a>
          <a href="/cookie-policy.html">Cookie Policy</a>
          <a href="/terms.html">Terms of Service</a>
          <a href="/refund-policy.html">Refund & Cancellation Policy</a>
          <a href="/provider-billing.html">Provider Billing</a>
          <a href="/sitemap.html">HTML Sitemap</a>
        </div>
      </div>
    </footer>
  </div>
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
</body>
</html>`;
    res.send(html);
  } catch (err) {
    console.error('Dynamic cities page failed', err);
    res.status(500).send('Server error');
  }
});

app.get('/states/:state.html', (req, res) => {
  const { state } = req.params;
  return res.redirect(301, `/states/${state}`);
});

app.get('/states/:state', async (req, res) => {
  try {
    const stateSlug = req.params.state;
    const candidates = stateCandidatesFromSlug(stateSlug);
    const providers = await prisma.provider.findMany({
      where: {
        OR: candidates.map((candidate) => ({
          state: { equals: candidate, mode: 'insensitive' }
        }))
      },
      select: { name: true, city: true, state: true, phone: true, website: true, address: true, careType: true },
      orderBy: [{ city: 'asc' }, { name: 'asc' }]
    });
    if (!providers.length) {
      const rawSlug = stateSlug.replace(/-/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase());
      return res.status(200).send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Hospice & Home Care Providers in ${rawSlug} | Best Hospice</title>
  <meta name="description" content="Best Hospice and Home Health is expanding to ${rawSlug}. Find verified hospice, palliative care, and home care providers near you. 100% free for families." />
  <link rel="canonical" href="${CANONICAL_DOMAIN}/states/${stateSlug}" />
  <link rel="stylesheet" href="/styles-modern.css" />
  <link rel="stylesheet" href="/styles/main.css" />
  <script src="/abel-chat.js" defer></script>
</head>
<body>
  <div class="page-shell">
    <header class="hero">
      <div class="hero-top">
        <div class="brand"><img src="/BestHospiceandHomeHealthNew.png" alt="Best Hospice and Home Health logo" class="brand-logo"></div>
        <button class="menu-toggle" aria-label="Toggle menu" aria-expanded="false"><span></span><span></span><span></span></button>
        <div class="top-links" id="topLinks">
          <a class="pill ghost-pill" href="/">Main Menu</a>
          <a class="pill ghost-pill" href="/locations.html">All Locations</a>
          <a class="pill ghost-pill" href="/search.html">Find Providers</a>
        </div>
      </div>
      <div class="hero-body" style="grid-template-columns:1fr;">
        <div class="hero-text">
          <h1>Hospice and Home Care in ${rawSlug}</h1>
          <p class="tagline">We are actively expanding our verified provider network to ${rawSlug}. In the meantime, we can still help your family find care.</p>
        </div>
      </div>
    </header>
    <main>
      <section class="card" style="padding:24px; margin-bottom:18px; text-align:center;">
        <h2 style="margin:0 0 10px;">We are growing to ${rawSlug}</h2>
        <p style="margin:0 0 16px; color:#5b6474;">Our team is verifying providers in ${rawSlug} now. Search below to see what is currently available near you, or contact us directly and we will help you find the right care.</p>
        <a href="/search.html" class="button" style="font-size:1rem; padding:12px 28px; margin-right:10px;">Search Providers Near Me</a>
        <a href="/contact.html" class="button ghost-pill" style="font-size:1rem; padding:12px 28px;">Contact Us for Help</a>
      </section>
      <section class="card" style="padding:18px; margin-bottom:18px;">
        <h2 style="margin:0 0 8px;">What Best Hospice and Home Health Does</h2>
        <p style="margin:0 0 10px;">We connect families with verified hospice, palliative care, and home care providers — at no cost to families, with no referral commissions, and no sales pressure.</p>
        <p style="margin:0;">Enter your ZIP code to instantly see verified providers near you. If we do not have providers in your area yet, we will let you know as soon as we do.</p>
      </section>
      <section class="card" style="padding:18px;">
        <h2 style="margin:0 0 8px;">Need Help Now?</h2>
        <p style="margin:0 0 10px;">Call us at <a href="tel:+12057391592">(205) 739-1592</a> or email <a href="mailto:contact@besthospice.com">contact@besthospice.com</a> and our team will help you find the right care in ${rawSlug}.</p>
        <p style="margin:0;">You can also search <a href="https://www.medicare.gov/care-compare" target="_blank" rel="noopener">Medicare Care Compare</a> for Medicare-certified hospice providers in your area.</p>
      </section>
    </main>
    <footer class="site-footer">
      <div class="footer-inner">
        <div class="footer-brand">Best Hospice and Home Health</div>
        <div class="footer-meta">Contact: contact@besthospice.com &bull; United States</div>
        <div class="footer-links">
          <a href="/privacy.html">Privacy Policy</a>
          <a href="/terms.html">Terms of Service</a>
        </div>
      </div>
    </footer>
  </div>
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
</body>
</html>`);
    }

    const stateName = normalizeStateLabel(providers[0].state);
    const cityMap = new Map();
    for (const p of providers) {
      const city = String(p.city || '').trim();
      if (!city) continue;
      if (!cityMap.has(city)) cityMap.set(city, []);
      cityMap.get(city).push(p);
    }

    const cityListHtml = Array.from(cityMap.keys())
      .sort((a, b) => a.localeCompare(b))
      .map((city) => `<li><a href="/cities/${slugify(city)}-${slugify(stateName)}">${city}, ${stateName}</a></li>`)
      .join('');

    const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Hospice & Home Care Providers in ${stateName} | Best Hospice</title>
  <meta name="description" content="Find verified hospice and home care providers across ${stateName}. Browse providers by city. 100% free for families." />
  <link rel="canonical" href="${CANONICAL_DOMAIN}/states/${slugify(stateName)}" />
  <link rel="stylesheet" href="/styles-modern.css" />
  <script src="/abel-chat.js" defer></script>
</head>
<body>
  <div class="page-shell">
    <header class="hero">
      <div class="hero-top">
        <div class="brand"><img src="/BestHospiceandHomeHealthNew.png" alt="Best Hospice and Home Health logo" class="brand-logo"></div>
        <button class="menu-toggle" aria-label="Toggle menu" aria-expanded="false"><span></span><span></span><span></span></button>
        <div class="top-links" id="topLinks">
          <a class="pill ghost-pill" href="/">Main Menu</a>
          <a class="pill ghost-pill" href="/cities.html">Browse Cities</a>
          <a class="pill ghost-pill" href="/search.html">Find Providers</a>
        </div>
      </div>
      <div class="hero-body" style="grid-template-columns:1fr;">
        <div class="hero-text">
          <h1>Hospice and Home Care Providers in ${stateName}</h1>
          <p class="tagline">We currently serve ${providers.length} verified providers across ${cityMap.size} cities in ${stateName}.</p>
        </div>
      </div>
    </header>
    <main>
      <section class="card" style="padding:18px;">
        <h2 style="margin:0 0 10px;">Cities We Serve in ${stateName}</h2>
        <ul style="margin:0; padding-left:18px; display:grid; gap:6px;">${cityListHtml}</ul>
      </section>
    </main>
  </div>
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
</body>
</html>`;
    res.send(html);
  } catch (err) {
    console.error('Dynamic state page failed', err);
    res.status(500).send('Server error');
  }
});

app.get('/cities/:city-:state.html', (req, res) => {
  const { city, state } = req.params;
  return res.redirect(301, `/cities/${city}-${state}`);
});

app.get('/cities/:city-:state', async (req, res) => {
  try {
    const citySlug = String(req.params.city || '').toLowerCase();
    const stateSlug = String(req.params.state || '').toLowerCase();
    const candidates = stateCandidatesFromSlug(stateSlug);
    const providersByState = await prisma.provider.findMany({
      where: {
        OR: candidates.map((candidate) => ({
          state: { equals: candidate, mode: 'insensitive' }
        }))
      },
      orderBy: [{ city: 'asc' }, { name: 'asc' }]
    });
    const providers = providersByState.filter((p) => slugify(p.city) === citySlug);
    if (!providers.length) return res.status(404).send('City not found');

    const city = providers[0].city;
    const stateCode = String(providers[0].state || '').toLowerCase();
    return res.redirect(301, `/hospice-care/${slugify(city)}-${stateCode}`);
  } catch (err) {
    console.error('Dynamic city page redirect failed', err);
    res.status(500).send('Server error');
  }
});

// Newsletter unsubscribe (must be before /:issueSlug)
app.get('/newsletter/unsubscribe', async (req, res) => {
  const email = String(req.query.email || '').trim().toLowerCase();
  const token = String(req.query.token || '').trim();
  if (!email || !token) {
    return res.status(400).send('<html><body style="font-family:sans-serif;max-width:480px;margin:60px auto;padding:16px;"><h2>Invalid unsubscribe link</h2><p>This link is missing required parameters. <a href="/">Return home</a></p></body></html>');
  }
  if (!verifyUnsubscribeToken(email, token)) {
    return res.status(400).send('<html><body style="font-family:sans-serif;max-width:480px;margin:60px auto;padding:16px;"><h2>Invalid unsubscribe link</h2><p>This link is not valid or has already been used. <a href="/">Return home</a></p></body></html>');
  }
  try {
    await ensureNewsletterSubscribersTable();
    await prisma.$executeRawUnsafe(`DELETE FROM newsletter_subscribers WHERE email = $1`, email);
    return res.send('<html><body style="font-family:sans-serif;max-width:480px;margin:60px auto;padding:16px;"><h2 style="color:#0f766e;">You\'ve been unsubscribed</h2><p>Your email address has been removed from The Best Hospice Brief. You will not receive any further emails.</p><p><a href="/">Return to BestHospice.com</a></p></body></html>');
  } catch (err) {
    console.error('Unsubscribe failed', err);
    return res.status(500).send('<html><body style="font-family:sans-serif;max-width:480px;margin:60px auto;padding:16px;"><h2>Something went wrong</h2><p>We could not process your unsubscribe request. Please try again or email contact@besthospice.com.</p></body></html>');
  }
});

// Newsletter pages (extensionless routes)
app.get('/reviews', (_req, res) => {
  res.sendFile(path.join(__dirname, 'reviews.html'));
});

app.get('/newsletter', (_req, res) => {
  res.sendFile(path.join(__dirname, 'newsletter', 'index.html'));
});
app.get('/newsletter/:issueSlug', (req, res) => {
  const issueSlug = String(req.params.issueSlug || '').trim().toLowerCase();
  if (!/^[a-z0-9-]+$/.test(issueSlug)) return res.status(404).send('Not found');
  const pagePath = path.join(__dirname, 'newsletter', `${issueSlug}.html`);
  if (!fs.existsSync(pagePath)) return res.status(404).send('Not found');
  return res.sendFile(pagePath);
});

app.get('/', (_req, res) => {
  return res.sendFile(path.join(__dirname, 'index.html'));
});

app.get('/BestHospiceSite.html', (_req, res) => {
  return res.redirect(301, '/');
});

const BLOCKED_STATIC_EXTENSIONS = new Set([
  '.env',
  '.csv',
  '.xlsx',
  '.xls',
  '.numbers',
  '.ppt',
  '.pptx',
  '.key',
  '.mov',
  '.mp4',
  '.sql',
  '.db',
  '.sqlite',
  '.sqlite3',
  '.bak',
  '.zip',
  '.tar',
  '.gz'
]);
const BLOCKED_STATIC_BASENAMES = new Set(['.env', '.ds_store', 'readme.md']);
const rootStatic = express.static(__dirname, {
  dotfiles: 'deny',
  fallthrough: true,
  index: false,
  setHeaders: (res, filePath) => {
    if (filePath.endsWith('.html')) {
      res.setHeader('Cache-Control', 'public, max-age=0, must-revalidate');
    } else if (/\.(css|js|png|jpg|jpeg|gif|ico|svg|woff2?|ttf|eot|webp)$/.test(filePath)) {
      res.setHeader('Cache-Control', 'public, max-age=3600, stale-while-revalidate=86400');
    }
  }
});

app.use((req, res, next) => {
  if (req.method !== 'GET' && req.method !== 'HEAD') return next();
  let requestPath = '/';
  try {
    requestPath = decodeURIComponent(req.path || '/');
  } catch (_err) {
    return res.status(400).send('Bad request');
  }
  const normalized = path.posix.normalize(requestPath);
  const basename = path.posix.basename(normalized).toLowerCase();
  const ext = path.posix.extname(normalized).toLowerCase();
  if (normalized.includes('/.') || basename.startsWith('.') || BLOCKED_STATIC_BASENAMES.has(basename) || BLOCKED_STATIC_EXTENSIONS.has(ext)) {
    return res.status(404).send('Not found');
  }
  return rootStatic(req, res, next);
});

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

function normalizeLeadOutcomeStatus(value) {
  const v = String(value || '').trim().toLowerCase().replace(/[\s-]+/g, '_');
  if (v === 'notfit' || v === 'not_a_fit') return 'not_a_fit';
  if (v === 'noresponse' || v === 'no_response') return 'no_response';
  if (LEAD_OUTCOME_VALUES.includes(v)) return v;
  return '';
}

function leadOutcomeLabel(value) {
  const key = normalizeLeadOutcomeStatus(value) || 'new';
  return LEAD_OUTCOME_LABELS[key] || 'New';
}

function createLeadStatusActionToken({ leadId, providerId, status }) {
  return jwt.sign(
    { type: 'lead_status_action', leadId, providerId, status: normalizeLeadOutcomeStatus(status) || 'new' },
    LEAD_STATUS_SIGNING_SECRET,
    { expiresIn: '30d' }
  );
}

async function upsertLeadOutcomeStatus({ leadId, providerId, nextStatus, changedBy = 'provider' }) {
  const status = normalizeLeadOutcomeStatus(nextStatus);
  if (!status) throw new Error('Invalid lead status');

  const existing = await prisma.leadOutcome.findUnique({
    where: { leadId_providerId: { leadId, providerId } }
  });
  const now = new Date();

  if (!existing) {
    const firstResponseAt = status === 'new' ? null : now;
    const created = await prisma.leadOutcome.create({
      data: {
        id: uuid(),
        leadId,
        providerId,
        status,
        firstResponseAt,
        lastStatusChangedAt: now,
        events: {
          create: {
            id: uuid(),
            fromStatus: null,
            toStatus: status,
            changedBy,
            changedAt: now
          }
        }
      }
    });
    return created;
  }

  if (existing.status === status) return existing;

  const firstResponseAt = existing.firstResponseAt || (status === 'new' ? null : now);
  const updated = await prisma.leadOutcome.update({
    where: { id: existing.id },
    data: {
      status,
      firstResponseAt,
      lastStatusChangedAt: now,
      events: {
        create: {
          id: uuid(),
          fromStatus: existing.status,
          toStatus: status,
          changedBy,
          changedAt: now
        }
      }
    }
  });
  return updated;
}

function normalizeEmail(email) {
  return String(email || '').trim().toLowerCase();
}

function uniqueEmails(items) {
  const out = [];
  const seen = new Set();
  for (const raw of items || []) {
    const email = String(raw || '').trim();
    if (!email) continue;
    const key = email.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(email);
  }
  return out;
}

function normalizeCityState(value) {
  return String(value || '').trim();
}

function generateCode() {
  return String(Math.floor(100000 + Math.random() * 900000));
}

async function isEmailVerifiedForBlog(email, city, state) {
  const normEmail = normalizeEmail(email);
  const normCity = normalizeCityState(city);
  const normState = normalizeCityState(state);
  if (!normEmail || !normCity || !normState) return false;
  const since = new Date(Date.now() - BLOG_VERIFICATION_WINDOW_MS);
  const record = await prisma.blogEmailVerification.findFirst({
    where: {
      email: normEmail,
      city: normCity,
      state: normState,
      verifiedAt: { gte: since }
    },
    orderBy: { verifiedAt: 'desc' }
  });
  return Boolean(record);
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
  const isStatusNudge = String(payload.jobType || '').toLowerCase() === 'lead_status_nudge';
  if (isStatusNudge && !LEAD_STATUS_NUDGE_ENABLED) {
    await prisma.notificationJob.update({
      where: { id: job.id },
      data: { status: 'skipped', lastError: 'Lead follow-up nudges are paused' }
    });
    return;
  }
  const providerEmail = payload.providerEmail;
  const providerEmails = uniqueEmails(
    Array.isArray(payload.providerEmails)
      ? payload.providerEmails
      : (providerEmail ? [providerEmail] : [])
  );
  const providerPhone = payload.providerPhone;
  let emailResult = { status: 'failed', error: 'Missing provider email' };

  if (isStatusNudge) {
    if (!providerEmails.length) {
      emailResult = { status: 'failed', error: 'Missing provider email' };
    } else {
      try {
        const statusLinks = LEAD_OUTCOME_VALUES.filter((s) => s !== 'new').map((status) => ({
          status,
          label: leadOutcomeLabel(status),
          url: `${CANONICAL_DOMAIN}/api/provider/lead-status/quick?token=${encodeURIComponent(
            createLeadStatusActionToken({ leadId: job.leadId, providerId: job.providerId, status })
          )}`
        }));
        const nudgeResults = await sendLeadStatusNudgeEmail({
          providers: [{ id: job.providerId, emails: providerEmails }],
          lead: {
            zip: payload.clientZip,
            timeline: payload.timeline,
            clientEmail: payload.clientEmail,
            clientPhone: payload.clientPhone
          },
          statusLinks
        });
        const sent = (nudgeResults || []).find((r) => r.status === 'sent');
        emailResult = sent || (nudgeResults || [])[0] || { status: 'failed', error: 'No result from nudge email send' };
      } catch (err) {
        console.error('Lead status nudge send failed', err);
        emailResult = { status: 'failed', error: err.message || 'nudge send failed' };
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
    const permanentFailure = Boolean(emailResult?.permanentFailure);
    if (!permanentFailure && nextAttempts < JOB_MAX_ATTEMPTS) {
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
    return;
  }

  if (providerEmails.length) {
    try {
      const results = await sendProviderNotifications({
        notificationType: payload.notificationType || 'initial',
        clientZip: payload.clientZip,
        timeline: payload.timeline,
        providerCount: payload.providerCount,
        requestSubmittedBy: payload.requestSubmittedBy,
        careDaysAndTimes: payload.careDaysAndTimes,
        services: payload.services,
        funding: payload.funding,
        otherDetails: payload.otherDetails,
        clientEmail: payload.clientEmail,
        clientPhone: payload.clientPhone,
        clientName: payload.clientName,
        whoNeedsCare: payload.whoNeedsCare,
        careType: payload.careType,
        additionalNotes: payload.additionalNotes,
        providers: [{ id: job.providerId, email: providerEmails[0], emails: providerEmails }],
        nearbyProviders: [{ id: job.providerId, email: providerEmails[0] }]
      });
      const sent = (results || []).find((r) => r.status === 'sent');
      if (sent) {
        emailResult = sent;
      } else {
        const firstFailure = (results || [])[0];
        emailResult = firstFailure || { status: 'failed', error: 'SendGrid returned no result' };
      }
    } catch (err) {
      console.error('Email notification failed', err);
      emailResult = { status: 'failed', error: err.message || 'send failed' };
    }
  }

  if (smsEnabled() && providerPhone) {
    const smsBody = [
      `Best Hospice and Home Health lead (ZIP ${payload.clientZip})`,
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
      if ((payload.notificationType || 'initial') !== 'details') {
        await prisma.provider.update({
          where: { id: job.providerId },
          data: { leadCount: { increment: 1 } }
        });
      }
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
  // Do not retry lead notifications automatically; duplicate retries confuse providers
  // and can spam the same lead. Mark failed once and surface the error in admin.
  await prisma.notificationJob.update({
    where: { id: job.id },
    data: {
      status: 'failed',
      attempts: nextAttempts,
      lastError: emailResult.error || 'send failed'
    }
  });
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
    const requestIp = req.ip || '';
    if (requestIp && AUTH_RATE_LIMIT_BYPASS_IPS.has(requestIp)) return next();
    const ipHash = hashIp(requestIp);
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

async function authRateLimit(req, res, next) {
  try {
    const requestIp = String(req.ip || '').trim();
    if (requestIp && AUTH_RATE_LIMIT_BYPASS_IPS.has(requestIp)) {
      return next();
    }
    const ipHash = hashIp(`auth:${req.ip || ''}`);
    const cutoff = new Date(Date.now() - AUTH_RATE_LIMIT_WINDOW_MS);
    const count = await prisma.rateLimitEvent.count({
      where: {
        ipHash,
        createdAt: { gte: cutoff }
      }
    });
    if (count >= AUTH_RATE_LIMIT_PER_WINDOW) {
      return res.status(429).json({ error: 'Too many authentication attempts. Please try again later.' });
    }
    await prisma.rateLimitEvent.create({ data: { id: uuid(), ipHash } });
    next();
  } catch (err) {
    console.error('Auth rate limit check failed', err);
    res.status(500).json({ error: 'Server error' });
  }
}

async function getAdminFailedLoginCount(req) {
  const requestIp = String(req.ip || '').trim();
  if (requestIp && AUTH_RATE_LIMIT_BYPASS_IPS.has(requestIp)) {
    return 0;
  }
  const ipHash = hashIp(`admin-auth-fail:${requestIp}`);
  const cutoff = new Date(Date.now() - ADMIN_LOGIN_FAILED_WINDOW_MS);
  return prisma.rateLimitEvent.count({
    where: {
      ipHash,
      createdAt: { gte: cutoff }
    }
  });
}

async function recordAdminFailedLogin(req) {
  const requestIp = String(req.ip || '').trim();
  if (requestIp && AUTH_RATE_LIMIT_BYPASS_IPS.has(requestIp)) {
    return;
  }
  const ipHash = hashIp(`admin-auth-fail:${requestIp}`);
  await prisma.rateLimitEvent.create({ data: { id: uuid(), ipHash } });
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
const CANONICAL_URL = new URL(CANONICAL_DOMAIN);
const CANONICAL_HOST = CANONICAL_URL.host;
const CANONICAL_PROTOCOL = CANONICAL_URL.protocol.replace(':', '');

function providerSlug(provider) {
  return `${slugify(provider.name || 'provider')}-${(provider.id || '').slice(0, 8)}`;
}

function cityStateString(city, state) {
  const stateName = stateNameMap[(state || '').toLowerCase()] || (state || '').toUpperCase();
  return [city, stateName].filter(Boolean).join(', ');
}

async function fetchAllProviders() {
  const providers = await prisma.provider.findMany({
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
  return providers.map(normalizeProviderCitySpelling);
}

async function providersByLocation(city, state) {
  const legacyCity = city.replace(/\bTucson\b/i, 'Tuscon');
  const results = await prisma.provider.findMany({
    where: {
      OR: [
        { city: { equals: city, mode: 'insensitive' } },
        { city: { equals: legacyCity, mode: 'insensitive' } }
      ],
      state: { equals: state, mode: 'insensitive' }
    },
  });
  return results.map(normalizeProviderCitySpelling).sort(byPlanThenName);
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

function escapeHtml(value) {
  return String(value || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function renderSimpleFaqItems(faqs = []) {
  if (!Array.isArray(faqs) || !faqs.length) return '<p class="text-muted">No FAQs available right now.</p>';
  return `
    <div class="faq-simple-list">
      ${faqs
        .map(
          ([q, a]) => `
        <article class="faq-simple-item">
          <h3>${escapeHtml(q)}</h3>
          <p>${escapeHtml(a)}</p>
        </article>
      `
        )
        .join('')}
    </div>
  `;
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
  const cityName = slugify(city);
  const stateCode = state.toLowerCase();
  return [
    { name: `More providers in ${state.toUpperCase()}`, url: `${CANONICAL_DOMAIN}/hospice-care/${state.toLowerCase()}` },
    { name: `Palliative care in ${city}, ${state.toUpperCase()}`, url: `${CANONICAL_DOMAIN}/palliative-care/${slugify(city)}-${state.toLowerCase()}` },
    { name: `Home care in ${city}, ${state.toUpperCase()}`, url: `${CANONICAL_DOMAIN}/home-care/${cityName}-${stateCode}` },
    { name: `Browse cities in ${state.toUpperCase()}`, url: `${CANONICAL_DOMAIN}/cities.html` }
  ];
}

function renderProviderList(providers) {
  if (!providers?.length) {
    return '<p class="text-muted">No providers listed yet for this area. We are expanding our network—check back soon.</p>';
  }
  return providers
    .map(
      (p) => `
      <article class="provider-card">
        <div class="v-badge"><span class="v-dot"></span>Verified</div>
        <h3 class="provider-name">${p.name}</h3>
        <div class="provider-details">
          ${p.address ? `<div class="p-row">${p.address}</div>` : ''}
          ${p.phone ? `<div class="p-row">Phone: ${p.phone}</div>` : ''}
          ${p.website ? `<div class="p-row"><a class="p-link" href="${p.website}" target="_blank" rel="noopener">Website — click here to see the business home page</a></div>` : ''}
        </div>
      </article>`
    )
    .join('\n');
}

function renderComparisonTable() {
  return `
    <div style="overflow-x:auto;-webkit-overflow-scrolling:touch;width:100%;max-width:100%;">
      <table class="compare-table" aria-label="Compare hospice, palliative, and home care">
        <thead>
          <tr>
            <th>Category</th>
            <th>Hospice</th>
            <th>Palliative</th>
            <th>Home Care</th>
          </tr>
        </thead>
        <tbody>
          <tr><td>When used</td><td>Comfort near end of life</td><td>Any stage of serious illness</td><td>Daily living support</td></tr>
          <tr><td>Can include medical team</td><td><span class="tag-yes">Yes</span></td><td><span class="tag-yes">Yes</span></td><td><span class="tag-yes">Sometimes</span></td></tr>
          <tr><td>Works with curative treatment</td><td><span class="tag-no">No</span></td><td><span class="tag-yes">Yes</span></td><td><span class="tag-yes">Yes</span></td></tr>
        </tbody>
      </table>
    </div>
  `;
}

function renderTrustBlock(dateStr) {
  return `
    <section class="s-card">
      <h3>Reviewed for clarity</h3>
      <p class="text-small">Reviewed by the Best Hospice and Home Health Clinical Review Team.</p>
      <p class="text-small"><strong>Last updated:</strong> ${dateStr}</p>
      <p class="text-small">Sources: Medicare.gov, CMS, NIH.</p>
    </section>
  `;
}

function renderPageHTML({ title, description, canonical, breadcrumbItems, body, faqSchema, providerSchemas = [], noindex = false, articleSchema = null }) {
  const jsonLd = [];
  if (breadcrumbItems?.length) jsonLd.push(renderBreadcrumbList(breadcrumbItems));
  if (articleSchema) jsonLd.push(articleSchema);
  if (faqSchema) jsonLd.push(faqSchema);
  if (providerSchemas?.length) {
    providerSchemas.forEach((p) => jsonLd.push(renderProviderSchema(p)));
  }
  return `<!DOCTYPE html>
  <html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <!-- Google tag (gtag.js) -->
    <script async src="https://www.googletagmanager.com/gtag/js?id=AW-17909571702"></script>
    <script>
      window.dataLayer = window.dataLayer || [];
      function gtag(){dataLayer.push(arguments);}
      gtag('js', new Date());
      gtag('config', 'AW-17909571702');
    </script>
    <title>${title}</title>
    <meta name="description" content="${description}" />
    ${noindex ? '<meta name="robots" content="noindex, follow" />' : ''}
    <link rel="canonical" href="${canonical}" />
    <meta property="og:type" content="website" />
    <meta property="og:url" content="${canonical}" />
    <meta property="og:title" content="${title}" />
    <meta property="og:description" content="${description}" />
    <meta property="og:image" content="https://www.besthospice.com/BestHospiceandHomeHealthNew.png" />
    <meta name="twitter:card" content="summary_large_image" />
    <meta name="twitter:title" content="${title}" />
    <meta name="twitter:description" content="${description}" />
    <meta name="twitter:image" content="https://www.besthospice.com/BestHospiceandHomeHealthNew.png" />
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Lora:ital,wght@0,400;0,600;1,400&family=DM+Sans:opsz,wght@9..40,300;9..40,400;9..40,500;9..40,600&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="/styles-modern.css" />
    <!-- Keep main.css last so it overrides base page styles -->
    <link rel="stylesheet" href="/styles/main.css" />
    <script src="/abel-chat.js" defer></script>
    <script type="application/ld+json">${JSON.stringify(jsonLd)}</script>
  </head>
  <body class="seo-page">
    <div class="page-shell">
      <header class="hero">
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
      </header>
      ${body}
    </div>
    <footer class="site-footer">
      <div class="footer-inner">
        <div class="footer-brand">Best Hospice and Home Health</div>
        <div class="footer-meta">Contact: contact@besthospice.com • United States</div>
        <div class="footer-links">
          <a href="/privacy.html">Privacy Policy</a>
          <a href="/cookie-policy.html">Cookie Policy</a>
          <a href="/terms.html">Terms of Service</a>
          <a href="/refund-policy.html">Refund & Cancellation Policy</a>
          <a href="/provider-billing.html">Provider Billing</a>
          <a href="/sitemap.html">HTML Sitemap</a>
        </div>
      </div>
    </footer>
    <script>
      (() => {
        const toggle = document.querySelector('.menu-toggle');
        const links = document.getElementById('topLinks');
        if (toggle && links) {
          toggle.addEventListener('click', () => {
            const open = links.classList.toggle('open');
            toggle.setAttribute('aria-expanded', open ? 'true' : 'false');
          });
        }

      })();
    </script>
    <!-- Meta Pixel Code -->
    <script>
    !function(f,b,e,v,n,t,s)
    {if(f.fbq)return;n=f.fbq=function(){n.callMethod?
    n.callMethod.apply(n,arguments):n.queue.push(arguments)};
    if(!f._fbq)f._fbq=n;n.push=n;n.loaded=!0;n.version='2.0';
    n.queue=[];t=b.createElement(e);t.async=!0;
    t.src=v;s=b.getElementsByTagName(e)[0];
    s.parentNode.insertBefore(t,s)}(window, document,'script',
    'https://connect.facebook.net/en_US/fbevents.js');
    fbq('init', '1447731666875537');
    fbq('track', 'PageView');
    </script>
    <noscript><img height="1" width="1" style="display:none"
    src="https://www.facebook.com/tr?id=1447731666875537&ev=PageView&noscript=1"
    /></noscript>
    <!-- End Meta Pixel Code -->
  </body>
  </html>`;
}

function renderCityPage({ serviceKey, city, state, providers = [] }) {
  const service = serviceConfig[serviceKey];
  const cityState = cityStateString(city, state);
  const stateName = stateNameMap[(state || '').toLowerCase()] || (state || '').toUpperCase();
  const providerCount = providers.length;
  const providerLine = providerCount
    ? `We currently list ${providerCount} ${providerCount === 1 ? 'provider' : 'providers'} in ${cityState}.`
    : `We are actively expanding coverage in ${cityState}.`;
  const localResources = `Local resources in ${cityState} often include hospital care coordinators, Medicare counseling, and caregiver support groups. Providers can guide you to the right local options.`;
  const title = `${service.name} in ${cityState} | Verified Providers & Medicare Coverage`;
  const description = `Find verified ${service.name.toLowerCase()} providers in ${cityState}. Compare local options, Medicare coverage, and costs. Free for families — no referral fees.`;
  const canonical = `${CANONICAL_DOMAIN}/${serviceKey}/${slugify(city)}-${(state || '').toLowerCase()}`;
  const breadcrumbItems = [
    { name: 'Home', url: `${CANONICAL_DOMAIN}/` },
    { name: service.name, url: `${CANONICAL_DOMAIN}/${serviceKey}` },
    { name: stateName, url: `${CANONICAL_DOMAIN}/${serviceKey}/${(state || '').toLowerCase()}` },
    { name: cityState, url: canonical }
  ];
  const faqSchema = renderFAQSchema(service.faq || []);
  const providerSchemas = providers.slice(0, 10);
  const articleSchema = {
    '@context': 'https://schema.org',
    '@type': 'Article',
    headline: `${service.name} in ${cityState}: Providers, Cost & Eligibility`,
    description,
    url: canonical,
    dateModified: formatDateISO(),
    publisher: { '@type': 'Organization', name: 'Best Hospice and Home Health', url: 'https://www.besthospice.com' }
  };
  const cityFaqItems = (service.faq || [])
    .map(
      ([q, a]) => `
                <div class="faq-simple-item faq-item">
                  <h3>${escapeHtml(q)}</h3>
                  <p>${escapeHtml(a)}</p>
                </div>
              `
    )
    .join('');

  const body = `
    <div class="breadcrumb">
      <a href="/">Home</a><span>></span>
      <a href="/${serviceKey}">${service.name}</a><span>></span>
      <a href="/${serviceKey}/${(state || '').toLowerCase()}">${stateName}</a><span>></span>
      ${cityState}
    </div>
    <section class="page-hero">
      <div class="hero-inner">
        <div class="hero-chip"><span class="hero-chip-dot"></span>Verified Local Providers</div>
        <h1>${service.name} in ${cityState}: Providers, Cost & Eligibility</h1>
        <p class="hero-sub">${service.direct.replace('{cityState}', cityState)}</p>
        <div class="hero-btns">
          <a class="btn-primary" href="/search.html">Find matched providers now</a>
          <a class="btn-outline" href="/${serviceKey}/${(state || '').toLowerCase()}">Explore ${stateName}</a>
        </div>
        <div class="hero-trust">
          <div class="trust-pill">Commission-free platform</div>
          <div class="trust-pill">No family referral fees</div>
          <div class="trust-pill">Verified provider directory</div>
        </div>
      </div>
    </section>
    <main class="page-wrap" style="position:relative;z-index:0;">
      <div class="two-col">
        <div class="left-col">
          <section class="content-section">
            <h2>Local overview</h2>
            <p>${providerLine}</p>
            <p>${localResources}</p>
          </section>
          <section class="content-section">
            <h2>${service.name} Providers in ${cityState}</h2>
            <div class="provider-stack">
              ${renderProviderList(providers)}
            </div>
          </section>
          <section class="content-section">
            <h2>Cost & Coverage</h2>
            <p>${service.cost.replace('{stateName}', stateName)}</p>
          </section>
          <section class="content-section">
            <h2>When to Choose ${service.name}</h2>
            <p>${service.eligibility}</p>
          </section>
          <section class="content-section">
            <h2>Local note for ${cityState}</h2>
            <p>${service.localNotes ? service.localNotes.replace('{stateName}', stateName) : ''}</p>
          </section>
          <section class="content-section">
            <h2>Compare Hospice, Palliative, and Home Care</h2>
            ${renderComparisonTable()}
          </section>
          <section class="content-section faq-section">
            <h2>FAQs</h2>
            <div class="faq-simple-list faq-list">
              ${cityFaqItems}
            </div>
          </section>
        </div>
        <aside class="page-sidebar">
          <section class="s-card featured">
            <h3>Need care now?</h3>
            <p>Connect with verified providers in minutes. Free for families and commission-free.</p>
            <a class="btn-sidebar" href="/search.html">Start your search</a>
          </section>
          <section class="s-card">
            <h3>Quick facts</h3>
            <ul class="cov-list">
              <li class="cov-row"><span class="cov-label">City</span><span>${cityState}</span></li>
              <li class="cov-row"><span class="cov-label">Providers listed</span><span>${providerCount}</span></li>
              <li class="cov-row"><span class="cov-label">Service</span><span>${service.name}</span></li>
            </ul>
          </section>
          ${renderTrustBlock(formatDateISO())}
          <section class="s-card">
            <h3>Explore more</h3>
            <ul class="link-list">
              ${nearbyCityLinks(city, state)
                .map((l) => `<li><a href="${l.url}">${l.name}<svg viewBox="0 0 20 20" aria-hidden="true"><path d="M7 4l6 6-6 6"/></svg></a></li>`)
                .join('')}
            </ul>
          </section>
        </aside>
      </div>
    </main>
  `;
  return renderPageHTML({ title, description, canonical, breadcrumbItems, body, faqSchema, providerSchemas, noindex: serviceKey !== 'hospice-care', articleSchema: serviceKey === 'hospice-care' ? articleSchema : null });
}

function renderStatePage({ serviceKey, state, providers = [] }) {
  const service = serviceConfig[serviceKey];
  const stateName = stateNameMap[(state || '').toLowerCase()] || (state || '').toUpperCase();
  const stateCode = (state || '').toLowerCase();
  const stateIntro = stateCode === 'az'
    ? `Arizona is home to over 1.8 million residents aged 65 and older, representing one of the fastest-growing senior populations in the United States. The Phoenix metro area alone accounts for more than 65% of the state's hospice utilization, with Tucson, Scottsdale, and Mesa also seeing significant demand. Arizona's warm climate attracts retirees year-round, making access to quality hospice, palliative, and home care a critical need for families across the state. Medicare covers the majority of hospice services in Arizona, and the state's ALTCS program provides additional support for qualifying low-income seniors.`
    : service.direct.replace('{cityState}', stateName);
  const title = `${service.name} in ${stateName} | Verified Providers & Medicare Coverage`;
  const description = `Find verified ${service.name.toLowerCase()} providers across ${stateName}. Compare local options, Medicare coverage, and costs. Free for families — no referral fees.`;
  const canonical = `${CANONICAL_DOMAIN}/${serviceKey}/${stateCode}`;
  const breadcrumbItems = [
    { name: 'Home', url: `${CANONICAL_DOMAIN}/` },
    { name: service.name, url: `${CANONICAL_DOMAIN}/${serviceKey}` },
    { name: stateName, url: canonical }
  ];
  const faqSchema = renderFAQSchema(service.faq || []);
  const providerSchemas = providers.slice(0, 10);
  const normalizedProviders = providers.map(normalizeProviderCitySpelling);
  const cities = Array.from(new Set(normalizedProviders.map((p) => p.city))).filter(Boolean).slice(0, 20);
  const body = `
    <div class="breadcrumb">
      <a href="/">Home</a><span>></span>
      <a href="/${serviceKey}">${service.name}</a><span>></span>
      ${stateName}
    </div>
    <section class="page-hero">
      <div class="hero-inner">
        <div class="hero-chip"><span class="hero-chip-dot"></span>${stateName}</div>
        <h1>${service.name} in ${stateName}</h1>
        <p class="hero-sub">${stateIntro}</p>
      </div>
    </section>
    <main class="page-wrap" style="position:relative;z-index:0;padding-top:48px; padding-bottom:56px;">
      <section class="content-section">
        <h2>Top Providers in ${stateName}</h2>
        <div class="provider-stack">${renderProviderList(normalizedProviders.slice(0, 20))}</div>
      </section>
      <section class="content-section">
        <h2>Browse cities in ${stateName}</h2>
        <ul class="link-list">${cities
          .map((c) => `<li><a href="${CANONICAL_DOMAIN}/${serviceKey}/${slugify(c)}-${stateCode}">${c}, ${state.toUpperCase()}<svg viewBox="0 0 20 20" aria-hidden="true"><path d="M7 4l6 6-6 6"/></svg></a></li>`)
          .join('')}</ul>
      </section>
      <section class="content-section">
        <h2>Cost & Coverage</h2>
        <p>${service.cost.replace('{stateName}', stateName)}</p>
      </section>
      <section class="content-section">
        <h2>When to Choose ${service.name}</h2>
        <p>${service.eligibility}</p>
      </section>
      <section class="content-section">
        <h2>Local note for ${stateName}</h2>
        <p>${service.localNotes ? service.localNotes.replace('{stateName}', stateName) : ''}</p>
      </section>
      <section class="content-section">
        <h2>Compare Hospice, Palliative, and Home Care</h2>
        ${renderComparisonTable()}
      </section>
      <section class="content-section">
        <h2>FAQs</h2>
        ${renderSimpleFaqItems(service.faq || [])}
      </section>
      ${renderTrustBlock(formatDateISO())}
    </main>
  `;
  return renderPageHTML({ title, description, canonical, breadcrumbItems, body, faqSchema, providerSchemas, noindex: serviceKey !== 'hospice-care' });
}

function renderHubPage({ serviceKey, states = [] }) {
  const service = serviceConfig[serviceKey];
  const longGuide = HUB_LONGFORM_CONTENT[serviceKey];
  const titleMap = {
    'hospice-care': 'Find Verified Hospice Care Providers Near You | Best Hospice',
    'palliative-care': 'Find Verified Palliative Care Providers | Best Hospice',
    'home-care': 'Find Verified Home Care Providers Near You | Best Hospice'
  };
  const title = titleMap[serviceKey] || `${service.name}: Guide, Eligibility, Costs & Providers`;
  const description = `Comprehensive ${service.name.toLowerCase()} guide covering who needs it, Medicare coverage, costs, and how to choose providers near you.`;
  const canonical = `${CANONICAL_DOMAIN}/${serviceKey}`;
  const breadcrumbItems = [
    { name: 'Home', url: `${CANONICAL_DOMAIN}/` },
    { name: service.name, url: canonical }
  ];
  const faqSchema = renderFAQSchema(service.faq || []);
  const body = `
    <div class="breadcrumb">
      <a href="/">Home</a><span>></span>
      ${service.name}
    </div>
    <section class="page-hero">
      <div class="hero-inner">
        <div class="hero-chip"><span class="hero-chip-dot"></span>Care Guide</div>
        <h1>${service.name}</h1>
        <p class="hero-sub">${service.direct.replace('{cityState}', 'your area')}</p>
        <div class="hero-btns">
          <a class="btn-primary" href="/search.html">Find matched providers now</a>
          <a class="btn-outline" href="/cities.html">Browse cities</a>
        </div>
        <div class="hero-trust">
          <div class="trust-pill">Verified provider directory</div>
          <div class="trust-pill">No family referral fees</div>
          <div class="trust-pill">Commission-free platform</div>
        </div>
      </div>
    </section>
    <main class="page-wrap" style="position:relative;z-index:0;">
      <div class="two-col">
        <div>
          <section class="content-section">
            <h2>${longGuide?.title || `${service.name} Guide`}</h2>
            ${(longGuide?.intro || []).map((paragraph) => `<p>${paragraph}</p>`).join('')}
          </section>
          <section class="content-section">
            <h2>Find providers by state</h2>
            ${states.length
              ? `<div class="card-grid">
                  ${states
                    .map((s) => `<a class="card" href="${CANONICAL_DOMAIN}/${serviceKey}/${s}" style="text-decoration:none;"><h3>${stateNameMap[s] || s.toUpperCase()}</h3><p class="text-small">View providers and local resources</p></a>`)
                    .join('')}
                </div>`
              : '<p class="text-muted">We are adding coverage in new states. Check back soon.</p>'}
          </section>
          <section class="content-section">
            <h2>Cost & Coverage</h2>
            <p>${service.cost.replace('{stateName}', 'your state')}</p>
          </section>
          <section class="content-section">
            <h2>When to Choose ${service.name}</h2>
            <p>${service.eligibility}</p>
          </section>
          <section class="content-section">
            <h2>Local note</h2>
            <p>${service.localNotes ? service.localNotes.replace('{stateName}', 'your state') : ''}</p>
          </section>
          ${(longGuide?.sections || [])
            .map(
              (section) => `
            <section class="content-section">
              <h2>${section.heading}</h2>
              ${(section.paragraphs || []).map((paragraph) => `<p>${paragraph}</p>`).join('')}
            </section>
          `
            )
            .join('')}
          <section class="content-section">
            <h2>Compare Hospice, Palliative, and Home Care</h2>
            ${renderComparisonTable()}
          </section>
          <section class="content-section">
            <h2>FAQs</h2>
            ${renderSimpleFaqItems(service.faq || [])}
          </section>
        </div>
        <aside class="page-sidebar">
          <section class="s-card featured">
            <h3>Need care now?</h3>
            <p>Connect with verified providers in minutes. Free for families and commission-free.</p>
            <a class="btn-sidebar" href="/search.html">Start your search</a>
          </section>
          <section class="s-card">
            <h3>Quick links</h3>
            <ul class="link-list">
              <li><a href="/cities.html">Browse all cities<svg viewBox="0 0 20 20" aria-hidden="true"><path d="M7 4l6 6-6 6"/></svg></a></li>
              <li><a href="/locations.html">Locations we serve<svg viewBox="0 0 20 20" aria-hidden="true"><path d="M7 4l6 6-6 6"/></svg></a></li>
              <li><a href="/education.html">Education Hub<svg viewBox="0 0 20 20" aria-hidden="true"><path d="M7 4l6 6-6 6"/></svg></a></li>
            </ul>
          </section>
          ${renderTrustBlock(formatDateISO())}
        </aside>
      </div>
    </main>
  `;
  return renderPageHTML({ title, description, canonical, breadcrumbItems, body, faqSchema, providerSchemas: [] });
}

function renderProviderPage(provider) {
  const slug = providerSlug(provider);
  const cityState = cityStateString(provider.city, provider.state);
  const careType = (provider.careType || 'hospice-care').toLowerCase();

  // Care-type-specific content blocks
  const careLabel = careType === 'home-care' ? 'home care' : careType === 'palliative-care' ? 'palliative care' : 'hospice care';
  const careServiceList = careType === 'home-care'
    ? 'personal care assistance, bathing and grooming support, meal preparation, medication reminders, housekeeping, companionship, transportation, and respite care for family caregivers'
    : careType === 'palliative-care'
    ? 'symptom and pain management, care coordination, emotional and psychological support, social work services, chaplain services, and family counseling'
    : 'nursing visits, pain and symptom management, medication delivery, medical equipment, social work services, chaplain services, aide support, and bereavement counseling for the family';
  const careGoal = careType === 'home-care'
    ? 'helping individuals live safely and comfortably at home'
    : careType === 'palliative-care'
    ? 'improving quality of life for patients with serious illness at any stage'
    : 'providing comfort-focused end-of-life support to patients and their families';
  const cityServiceUrl = `${CANONICAL_DOMAIN}/${careType}/${slugify(provider.city)}-${(provider.state || '').toLowerCase()}`;

  const title = `${provider.name} | ${careLabel.replace(/\b\w/g, c => c.toUpperCase())} in ${cityState}`;
  const description = `${provider.name} can offer ${careLabel} services in ${cityState}. View contact information, address, and services offered.`;
  const canonical = `${CANONICAL_DOMAIN}/provider/${slug}`;
  const breadcrumbItems = [
    { name: 'Home', url: `${CANONICAL_DOMAIN}/` },
    { name: cityState, url: cityServiceUrl },
    { name: provider.name, url: canonical }
  ];
  const faqSchema = renderFAQSchema([
    ['How do I contact this provider?', `Phone: ${provider.phone || 'Not provided'}. Website: ${provider.website || 'Not provided'}.`],
    ['Where is this provider located?', provider.address ? `${provider.address}, ${cityState}` : cityState],
    [`What services can ${provider.name} offer?`, `${provider.name} can offer ${careLabel} services in ${cityState}, including ${careServiceList}.`],
    [`Does ${provider.name} accept Medicare?`, `Most ${careLabel} providers listed on BestHospice.com are Medicare-certified. Contact ${provider.name} directly to confirm coverage for your specific situation.`],
    [`How do I get started with ${provider.name}?`, `You can reach ${provider.name} by phone${provider.phone ? ' at ' + provider.phone : ''} or through the contact form on BestHospice.com. Intake typically begins within 24–48 hours of your first call.`]
  ]);

  const body = `
    <section class="card" style="padding:18px;">
      <h1 style="margin:0 0 6px;">${escapeHtml(provider.name)}</h1>
      <p style="margin:0 0 4px; color:var(--text-muted);">${careLabel.replace(/\b\w/g, c => c.toUpperCase())} · ${cityState}</p>
      ${provider.address ? `<p style="margin:0 0 10px;">${escapeHtml(provider.address)}, ${cityState}</p>` : `<p style="margin:0 0 10px;">${cityState}</p>`}
      <div style="display:flex; flex-wrap:wrap; gap:8px; margin-top:10px;">
        ${provider.phone ? `<a class="pill" href="tel:${provider.phone.replace(/\D/g,'')}">${escapeHtml(provider.phone)}</a>` : ''}
        ${provider.website ? `<a class="pill ghost-pill" href="${escapeHtml(provider.website)}" rel="nofollow noopener" target="_blank">Visit Website</a>` : ''}
        <a class="pill ghost-pill" href="/search.html">Find More Providers</a>
      </div>
    </section>

    <section class="card" style="padding:18px; margin-top:14px;">
      <h2 style="margin:0 0 10px;">About ${escapeHtml(provider.name)}</h2>
      <p style="margin:0 0 10px;">${escapeHtml(provider.name)} can offer ${careLabel} services to patients and families in ${cityState}. Their focus is on ${careGoal}.</p>
      <p style="margin:0;">Services can include ${careServiceList}.</p>
    </section>

    <section class="card" style="padding:18px; margin-top:14px;">
      <h2 style="margin:0 0 10px;">Coverage area</h2>
      <p style="margin:0 0 10px;">${escapeHtml(provider.name)} is based in ${cityState} and serves patients in the surrounding area. Contact them directly to confirm whether they serve your specific location.</p>
      <a class="pill ghost-pill" href="${cityServiceUrl}">View all ${careLabel} providers in ${cityState}</a>
    </section>

    <section class="card" style="padding:18px; margin-top:14px;">
      <h2 style="margin:0 0 10px;">Frequently Asked Questions</h2>
      <details class="faq-item"><summary>How do I contact ${escapeHtml(provider.name)}?</summary><p>${provider.phone ? 'Call them at ' + escapeHtml(provider.phone) + '.' : ''} ${provider.website ? 'You can also visit their website for more information.' : ''} You can also search for providers near you on BestHospice.com.</p></details>
      <details class="faq-item"><summary>What services can ${escapeHtml(provider.name)} offer?</summary><p>${escapeHtml(provider.name)} can offer ${careLabel} services in ${cityState}, including ${careServiceList}.</p></details>
      <details class="faq-item"><summary>Does ${escapeHtml(provider.name)} accept Medicare?</summary><p>Most ${careLabel} providers listed on BestHospice.com are Medicare-certified. Contact ${escapeHtml(provider.name)} directly to confirm coverage for your specific situation.</p></details>
      <details class="faq-item"><summary>How do I get started?</summary><p>Reach out to ${escapeHtml(provider.name)} directly${provider.phone ? ' at ' + escapeHtml(provider.phone) : ''}. Intake for ${careLabel} typically begins within 24–48 hours of your first contact.</p></details>
    </section>

    <section class="card" style="padding:18px; margin-top:14px; text-align:center;">
      <h2 style="margin:0 0 8px;">Compare more providers near you</h2>
      <p style="margin:0 0 14px;">BestHospice.com lists verified ${careLabel} providers across the country. Enter your ZIP code to find and compare options near you — free for families, no referral fees.</p>
      <a href="/search.html" class="button" style="font-size:1rem; padding:12px 28px;">Find Providers Near Me</a>
    </section>
    ${renderTrustBlock(formatDateISO())}
  `;
  return renderPageHTML({ title, description, canonical, breadcrumbItems, body, faqSchema, providerSchemas: [provider], noindex: true });
}
function toSubmittedBy(relationship) {
  if (relationship === 'me') return 'TheClient';
  if (relationship === 'loved-one') return 'A_Loved_One';
  if (relationship === 'spouse') return 'A_Loved_One';
  return 'Other';
}

function relationshipLabel(relationship) {
  if (relationship === 'me' || relationship === 'TheClient') return 'Myself';
  if (relationship === 'loved-one' || relationship === 'A_Loved_One') return 'Parent/Loved One';
  if (relationship === 'spouse') return 'Spouse';
  return 'Other';
}

app.get('/api/providers', async (req, res) => {
  if (!hasAdminAccess(req, ['add', 'remove', 'dash', 'audit', 'main'])) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  const providers = await prisma.provider.findMany({
    select: {
      id: true,
      name: true,
      email: true,
      secondaryContactEmail: true,
      phone: true,
      website: true,
      address: true,
      city: true,
      state: true,
      zip: true,
      lat: true,
      lon: true,
      serviceRadiusKm: true,
      serviceZipCodes: true,
      featured: true,
      planTier: true,
      careType: true,
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
      priority: process.env.STRIPE_PRICE_ID_PRIORITY || process.env.STRIPE_PRICE_ID_MARKET_LEADER,
      '5locenterprise': process.env.STRIPE_PRICE_ID_5LOCEnterprise,
      '10locenterprise': process.env.STRIPE_PRICE_ID_10LOCEnterprise
    };
    const normalizedPlan = normalizeCheckoutPlan(plan);
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

app.get('/api/geocode', async (req, res) => {
  const zip = String(req.query.zip || '').trim();
  if (!/^\d{5}$/.test(zip)) return res.status(400).json({ error: 'Invalid ZIP code' });
  try {
    const url = `https://nominatim.openstreetmap.org/search?format=json&postalcode=${encodeURIComponent(zip)}&countrycodes=us&limit=1&addressdetails=1`;
    const response = await fetch(url, { headers: { 'Accept-Language': 'en', 'User-Agent': 'BestHospice/1.0 (contact@besthospice.com)' } });
    if (!response.ok) return res.status(502).json({ error: 'Geocoding service unavailable' });
    const data = await response.json();
    if (!data.length) return res.status(404).json({ error: 'ZIP code not found' });
    const place = data[0];
    res.json({ lat: parseFloat(place.lat), lon: parseFloat(place.lon), label: place.display_name });
  } catch (err) {
    res.status(502).json({ error: 'Geocoding failed' });
  }
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
  if (!hasAdminAccess(req, ['dash'])) {
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
      priority: process.env.STRIPE_PRICE_ID_PRIORITY || process.env.STRIPE_PRICE_ID_MARKET_LEADER,
      '5locenterprise': process.env.STRIPE_PRICE_ID_5LOCEnterprise,
      '10locenterprise': process.env.STRIPE_PRICE_ID_10LOCEnterprise
    };
    const normalizedPlan = normalizeCheckoutPlan(plan);
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
  const adminIdentifier = getAdminSession(req)
    ? 'admin_session'
    : token === ADMIN_TOKEN_ADD
      ? 'add_token'
      : token === ADMIN_TOKEN_REMOVE
        ? 'remove_token'
        : 'unknown';
  if (!hasAdminAccess(req, ['add', 'remove'])) {
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
    serviceZipCodes,
    email,
    secondaryContactEmail,
    providerLoginEmail,
    phone,
    website,
    featured = false,
    planTier,
    careType,
    activelyHiring,
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
    const normalizedSecondaryEmail = String(secondaryContactEmail || '').trim() || null;
    const normalizedLoginEmail = String(providerLoginEmail || '').trim() || normalizedEmail;
    const provider = await prisma.provider.create({
      data: {
        id: uuid(),
        name,
        email: normalizedEmail,
        secondaryContactEmail: normalizedSecondaryEmail,
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
        serviceZipCodes: zipCodesToStorage(serviceZipCodes),
        featured: Boolean(featured),
        activelyHiring: activelyHiring !== false,
        planTier: normalizePlanTier(planTier),
        careType: normalizeCareType(careType)
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
  if (!hasAdminAccess(req, ['remove', 'dash'])) {
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
    serviceZipCodes,
    email,
    secondaryContactEmail,
    providerLoginEmail,
    phone,
    website,
    featured,
    planTier,
    careType,
    activelyHiring
  } = req.body || {};
  const data = {};
  if (name !== undefined) data.name = String(name).trim();
  if (email !== undefined) data.email = String(email).trim();
  if (secondaryContactEmail !== undefined) {
    const normalizedSecondary = String(secondaryContactEmail || '').trim();
    data.secondaryContactEmail = normalizedSecondary || null;
  }
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
  if (serviceZipCodes !== undefined) {
    data.serviceZipCodes = zipCodesToStorage(serviceZipCodes);
  }
  if (featured !== undefined) data.featured = Boolean(featured);
  if (activelyHiring !== undefined) data.activelyHiring = activelyHiring !== false;
  if (planTier !== undefined && planTier !== '') data.planTier = normalizePlanTier(planTier);
  if (careType !== undefined && careType !== '') data.careType = normalizeCareType(careType);

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
  if (!hasAdminAccess(req, ['remove'])) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  const id = req.params.id;
  try {
    const provider = await prisma.provider.findUnique({ where: { id } });
    if (!provider) return res.status(404).json({ error: 'Provider not found' });
    await prisma.$transaction([
      prisma.providerUser.updateMany({ where: { activeProviderId: id }, data: { activeProviderId: null } }),
      prisma.providerUserProvider.deleteMany({ where: { providerId: id } }),
      prisma.leadOutcomeEvent.deleteMany({ where: { leadOutcome: { providerId: id } } }),
      prisma.leadOutcome.deleteMany({ where: { providerId: id } }),
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
    const { mode, leadId, zip, answers, providers, captchaToken, sessionId } = req.body || {};
    const normalizedSessionId = String(sessionId || '').trim().slice(0, 128) || null;
    const notifyMode = String(mode || 'initial').toLowerCase() === 'details' ? 'details' : 'initial';
    if (!zip || !answers || !Array.isArray(providers) || !providers.length) {
      return res.status(400).json({ error: 'Missing zip, answers, or providers list' });
    }
    if (notifyMode === 'initial' && captchaToken) {
      const captchaResult = await verifyTurnstile(captchaToken, req.ip);
      if (!captchaResult.success && !captchaResult.bypass) {
        return res.status(403).json({ error: 'Captcha verification failed.', details: captchaResult['error-codes'] || captchaResult.error });
      }
    }

    const rawToList = providers.filter((p) => !!p.id);
    if (!rawToList.length) return res.status(400).json({ error: 'No providers to notify' });
    await ensureJobLeadTable();
    await ensureProviderStripeColumns();
    // Excluded if notifications are switched off, if billing is switched off, or
    // if they are billed but Stripe does not show them current. Providers on the
    // default 'free' mode are never excluded here.
    const disabledClientLeads = await prisma.$queryRawUnsafe(
      `SELECT id FROM "Provider"
       WHERE "receiveClientLeads" = false
          OR "billingMode" = 'off'
          OR ("billingMode" = 'billed' AND COALESCE("subscriptionStatus", '') NOT IN ('active', 'trialing'))`
    );
    const disabledClientSet = new Set(disabledClientLeads.map((r) => r.id));
    const toList = rawToList.filter((p) => !disabledClientSet.has(p.id));

    // Every nearby provider is switched off, lapsed, or not receiving leads.
    // Route the family into New Territory Outreach rather than failing on them:
    // they get a real response and it becomes a recruitment signal.
    if (!toList.length) {
      if (notifyMode === 'details') {
        return res.json({ ok: true, waitlisted: true, notified: 0 });
      }
      const wlZip = String(zip || '').trim();
      const wlEmail = String(answers?.contactEmail || '').trim() || 'Not provided';
      const wlPhone = String(answers?.contactPhone || '').trim() || 'Not provided';
      const wlTimeline = String(answers?.timeline || '').trim() || 'Not specified';
      try {
        await ensureWaitlistTable();
        await prisma.waitlistRequest.create({
          data: {
            id: uuid(),
            zip: wlZip,
            contactEmail: wlEmail,
            contactPhone: wlPhone,
            timeline: wlTimeline
          }
        });
      } catch (wlErr) {
        console.error('Waitlist save failed for uncovered notify', wlErr);
      }
      try {
        await sendGenericEmail(
          'contact@besthospice.com',
          `Coverage request for ZIP ${wlZip} (no available providers)`,
          `<div style="font-family: Arial, Helvetica, sans-serif; line-height:1.6; color:#222;">
             <p>A client at zipcode ${wlZip} requested care, but every matching provider is currently switched off, lapsed, or not receiving leads.</p>
             <p><strong>Client Email:</strong> ${wlEmail}<br />
             <strong>Client Phone:</strong> ${wlPhone}<br />
             <strong>When Care Is Needed:</strong> ${wlTimeline}</p>
             <p>This has been added to New Territory Outreach.</p>
           </div>`
        );
      } catch (mailErr) {
        console.error('Coverage-gap email failed', mailErr);
      }
      await logAdminAction(
        'system', 'NOTIFY_NO_AVAILABLE_PROVIDERS', wlZip,
        { matched: rawToList.length, excluded: rawToList.length },
        hashIp(req.ip || '')
      );
      return res.json({ ok: true, waitlisted: true, notified: 0 });
    }

    // Deduplicate: block exact same email + phone + timeline within 24 hours
    if (notifyMode === 'initial') {
      const dedupEmail = String(answers.contactEmail || '').trim().toLowerCase();
      const dedupPhone = String(answers.contactPhone || '').trim();
      const dedupTimeline = String(answers.timeline || '').trim();
      if (dedupEmail && dedupPhone && dedupTimeline) {
        const cutoff = new Date(Date.now() - 24 * 60 * 60 * 1000);
        const existing = await prisma.lead.findFirst({
          where: {
            clientEmail: dedupEmail,
            clientPhone: dedupPhone,
            careDays: dedupTimeline,
            createdAt: { gte: cutoff }
          }
        });
        if (existing) {
          return res.json({ ok: true, deduplicated: true });
        }
      }
    }

    let requestSubmittedBy = toSubmittedBy(answers.relationship);
    let careDays = answers.timeline || 'Not specified';
    let careTimes = 'Not specified';
    let careDaysAndTimes = `Timeline: ${careDays}`;
    let services = Array.isArray(answers.services) && answers.services.length ? answers.services : [];
    let careTypeSelections = Array.isArray(answers.careType) && answers.careType.length ? answers.careType : [];
    let servicePayload = [...services, ...careTypeSelections.map((c) => `Care Type: ${c}`)];
    let funding = answers.funding || 'Not specified';
    let otherDetails = answers.moreDetails || '';
    let clientEmail = answers.contactEmail || 'Not provided';
    let clientPhone = answers.contactPhone || 'Not provided';
    let clientFirst = answers.fullName?.first || '';
    let clientLast = answers.fullName?.last || '';
    let clientName = buildClientName(clientFirst, clientLast);
    let whoNeedsCare = relationshipLabel(answers.relationship || requestSubmittedBy);
    let careTypeText = careTypeSelections.join(', ') || 'Not sure';
    let additionalNotes = otherDetails || 'Not provided';

    let lead;
    if (notifyMode === 'details') {
      if (!leadId) return res.status(400).json({ error: 'Missing leadId for details mode' });
      const existingLead = await prisma.lead.findUnique({ where: { id: leadId } });
      if (!existingLead) return res.status(404).json({ error: 'Lead not found' });
      lead = existingLead;

      requestSubmittedBy = toSubmittedBy(answers.relationship) || existingLead.submittedBy || 'Other';
      careDays = answers.timeline || existingLead.careDays || 'Not specified';
      careTimes = existingLead.careTimes || 'Not specified';
      careDaysAndTimes = `Timeline: ${careDays}`;
      clientEmail = answers.contactEmail || existingLead.clientEmail || 'Not provided';
      clientPhone = answers.contactPhone || existingLead.clientPhone || 'Not provided';
      clientFirst = answers.fullName?.first || existingLead.firstName || '';
      clientLast = answers.fullName?.last || existingLead.lastName || '';
      clientName = buildClientName(clientFirst, clientLast);
      whoNeedsCare = relationshipLabel(answers.relationship || requestSubmittedBy);
      careTypeSelections = Array.isArray(answers.careType) && answers.careType.length ? answers.careType : [];
      careTypeText = careTypeSelections.join(', ') || 'Not sure';
      additionalNotes = answers.moreDetails || 'Not provided';
      services = Array.isArray(answers.services) ? answers.services : [];
      servicePayload = [...services, ...careTypeSelections.map((c) => `Care Type: ${c}`)];

      const mergedServices = [
        existingLead.services || '',
        whoNeedsCare ? `Who needs care: ${whoNeedsCare}` : '',
        careTypeText ? `Care Type: ${careTypeText}` : '',
        additionalNotes ? `Additional notes: ${additionalNotes}` : ''
      ].filter(Boolean).join('; ');

      await prisma.lead.update({
        where: { id: lead.id },
        data: {
          submittedBy: requestSubmittedBy,
          careDays,
          services: mergedServices,
          clientEmail,
          clientPhone,
          firstName: clientFirst || null,
          lastName: clientLast || null
        }
      });
      if (normalizedSessionId) {
        await ensureLeadSessionColumn();
        await prisma.$executeRawUnsafe(
          `UPDATE "Lead" SET "sessionId" = COALESCE("sessionId", $1) WHERE id = $2`,
          normalizedSessionId,
          lead.id
        );
      }
    } else {
      if (!answers.timeline || !answers.contactEmail) {
        return res.status(400).json({ error: 'Missing timeline or contact email' });
      }
      lead = await prisma.lead.create({
        data: {
          id: uuid(),
          zip,
          submittedBy: requestSubmittedBy,
          careDays,
          careTimes,
          services: `Initial lead request; Timeline: ${careDays}`,
          clientEmail,
          clientPhone,
          firstName: clientFirst || null,
          lastName: clientLast || null
        }
      });
      if (normalizedSessionId) {
        await ensureLeadSessionColumn();
        await prisma.$executeRawUnsafe(
          `UPDATE "Lead" SET "sessionId" = $1 WHERE id = $2`,
          normalizedSessionId,
          lead.id
        );
      }

      const impressionData = toList
        .filter((p) => !!p.id)
        .map((p) => ({
          id: uuid(),
          providerId: p.id,
          leadId: lead.id,
          zip
        }));
      if (impressionData.length) await prisma.providerImpression.createMany({ data: impressionData });
    }

    const providerIds = toList.map((p) => p.id).filter(Boolean);
    let providerMap = new Map();
    if (providerIds.length) {
      const providerRecords = await prisma.provider.findMany({
        where: { id: { in: providerIds } },
        select: { id: true, planTier: true, email: true, secondaryContactEmail: true, phone: true }
      });
      providerMap = new Map(providerRecords.map((p) => [p.id, p]));
    }

    const jobs = toList
      .map((p) => {
      const providerRecord = providerMap.get(p.id);
      const recipientEmails = uniqueEmails([
        String(providerRecord?.email || p.email || '').trim(),
        String(providerRecord?.secondaryContactEmail || '').trim()
      ]);
      if (!recipientEmails.length) return null;
      const planTier = normalizePlanTier(p.planTier || providerRecord?.planTier);
      const delayMs = PLAN_NOTIFY_DELAY_MS[planTier] ?? PLAN_NOTIFY_DELAY_MS.verified;
      return {
        id: uuid(),
        leadId: lead.id,
        providerId: p.id,
        runAt: new Date(Date.now() + delayMs),
        status: 'pending',
        payload: {
          clientZip: zip,
          notificationType: notifyMode,
          timeline: careDays,
          providerCount: toList.length,
          requestSubmittedBy,
          careDaysAndTimes,
          services: servicePayload,
          funding,
          otherDetails,
          clientEmail,
          clientPhone,
          clientName,
          whoNeedsCare,
          careType: careTypeText,
          additionalNotes,
          providerEmail: recipientEmails[0],
          providerEmails: recipientEmails,
          providerPhone: providerRecord?.phone || p.phone || '',
          planTier
        }
      };
    })
      .filter(Boolean);

    if (jobs.length) {
      await prisma.notificationJob.createMany({ data: jobs });
      if (notifyMode === 'initial') {
        const uniqueProviderIds = Array.from(new Set(jobs.map((j) => j.providerId).filter(Boolean)));
        if (uniqueProviderIds.length) {
          const now = new Date();
          const leadOutcomesData = uniqueProviderIds.map((providerId) => ({
            id: uuid(),
            leadId: lead.id,
            providerId,
            status: 'new',
            lastStatusChangedAt: now
          }));
          await prisma.leadOutcome.createMany({ data: leadOutcomesData, skipDuplicates: true });

          const createdOutcomes = await prisma.leadOutcome.findMany({
            where: { leadId: lead.id, providerId: { in: uniqueProviderIds } },
            select: { id: true }
          });
          if (createdOutcomes.length) {
            await prisma.leadOutcomeEvent.createMany({
              data: createdOutcomes.map((o) => ({
                id: uuid(),
                leadOutcomeId: o.id,
                fromStatus: null,
                toStatus: 'new',
                changedBy: 'system',
                changedAt: now
              }))
            });
          }

          if (LEAD_STATUS_NUDGE_ENABLED) {
            const nudgeJobs = jobs.map((j) => ({
              id: uuid(),
              leadId: j.leadId,
              providerId: j.providerId,
              runAt: new Date(Date.now() + LEAD_STATUS_NUDGE_DELAY_MS),
              status: 'pending',
              payload: {
                ...j.payload,
                jobType: 'lead_status_nudge'
              }
            }));
            await prisma.notificationJob.createMany({ data: nudgeJobs });
          }
        }
      }
    }

    res.json({ ok: true, queued: true, sent: jobs.length, leadId: lead.id, mode: notifyMode });
  } catch (err) {
    console.error('Notify failed', err);
    res.status(500).json({ error: 'Notify failed' });
  }
});

app.post('/api/waitlist/notify', rateLimit, async (req, res) => {
  if (!EMAIL_ENABLED) return res.status(500).json({ error: 'Email not configured' });
  try {
    const { zip, timeline, contactEmail, contactPhone } = req.body || {};
    const rawZip = String(zip || '').trim();
    const zipMatch = rawZip.match(/\d{5}/);
    const safeZip = zipMatch ? zipMatch[0] : (rawZip || 'unknown');
    const safeTimeline = String(timeline || '').trim() || 'Not specified';
    const safeContactEmail = String(contactEmail || '').trim() || 'Not provided';
    const safeContactPhone = String(contactPhone || '').trim() || 'Not provided';

    const targetEmail = 'contact@besthospice.com';
    const subject = `Coverage request for ZIP ${safeZip}`;
    const html = `
      <div style="font-family: Arial, Helvetica, sans-serif; line-height:1.6; color:#222;">
        <p>A client at zipcode ${safeZip} has requested care but is unable to get in touch because no providers are nearby.</p>
        <p><strong>Client Email:</strong> ${safeContactEmail}<br />
        <strong>Client Phone:</strong> ${safeContactPhone}<br />
        <strong>When Care Is Needed:</strong> ${safeTimeline}</p>
        <p>We are working on their behalf to find care as soon as possible.</p>
        <p>Thank you for your time and we are here for you and your family.</p>
        <p><em>Because your loved ones deserve the best, period.</em></p>
      </div>
    `;
    await sendGenericEmail(targetEmail, subject, html);
    // Save to DB for New Territory Outreach reporting (fire-and-forget)
    ensureWaitlistTable()
      .then(() => prisma.waitlistRequest.create({
        data: { id: uuid(), zip: safeZip, contactEmail: safeContactEmail || null, contactPhone: safeContactPhone || null, timeline: safeTimeline || null }
      }))
      .catch((err) => console.error('WaitlistRequest save failed', err));
    res.json({ ok: true });
  } catch (err) {
    console.error('Waitlist notify failed', err);
    res.status(500).json({ error: 'Could not submit notification request' });
  }
});

app.post('/api/analytics/event', async (req, res) => {
  try {
    const ua = String(req.headers['user-agent'] || '');
    if (/bot|spider|crawl|preview|facebookexternalhit|headless|lighthouse/i.test(ua)) {
      return res.json({ ok: true, skipped: 'bot' });
    }
    const viewerId = String(req.body?.viewerId || '').trim().slice(0, 128);
    const sessionId = String(req.body?.sessionId || '').trim().slice(0, 128);
    const eventType = String(req.body?.eventType || '').trim().toLowerCase().slice(0, 64);
    const pathName = String(req.body?.path || '').trim().slice(0, 255);
    const referrer = String(req.body?.referrer || '').trim().slice(0, 512) || null;
    const durationMsRaw = Number(req.body?.durationMs);
    const scrollDepthRaw = Number(req.body?.scrollDepth);
    const eventValue = String(req.body?.eventValue || '').trim().slice(0, 255) || null;
    const metadata = req.body?.metadata && typeof req.body.metadata === 'object' ? req.body.metadata : null;

    if (!viewerId || !sessionId || !eventType || !pathName) {
      return res.status(400).json({ error: 'Missing analytics fields' });
    }

    const allowedEvents = new Set([
      'page_view',
      'page_exit',
      'click',
      'scroll',
      'form_submit_initial',
      'form_submit_details',
      'search_results_loaded',
      'consent_granted',
      'consent_declined'
    ]);
    if (!allowedEvents.has(eventType)) {
      return res.status(400).json({ error: 'Unsupported event type' });
    }

    const durationMs = Number.isFinite(durationMsRaw) && durationMsRaw >= 0 ? Math.round(durationMsRaw) : null;
    const scrollDepth = Number.isFinite(scrollDepthRaw)
      ? Math.max(0, Math.min(100, Math.round(scrollDepthRaw)))
      : null;
    const metadataJson = metadata ? JSON.stringify(metadata).slice(0, 4000) : null;

    await ensureWebsiteEventsTable();
    await prisma.$executeRawUnsafe(
      `INSERT INTO website_events
        (id, viewer_id, session_id, event_type, path, referrer, duration_ms, scroll_depth, event_value, metadata_json, user_agent, ip_hash, created_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, NOW())`,
      uuid(),
      viewerId,
      sessionId,
      eventType,
      pathName,
      referrer,
      durationMs,
      scrollDepth,
      eventValue,
      metadataJson,
      ua.slice(0, 1024) || null,
      hashIp(req.ip || '')
    );
    res.json({ ok: true });
  } catch (err) {
    console.error('Analytics event ingest failed', err);
    res.status(500).json({ error: 'Could not ingest analytics event' });
  }
});

app.get('/api/newsletter/issues', (req, res) => {
  try {
    const schedulePath = path.join(__dirname, 'newsletter', 'schedule.json');
    if (!fs.existsSync(schedulePath)) return res.json({ issues: [] });
    const schedule = JSON.parse(fs.readFileSync(schedulePath, 'utf8'));
    res.json({ issues: schedule.issues || [] });
  } catch (err) {
    res.json({ issues: [] });
  }
});

app.post('/api/newsletter/subscribe', rateLimit, async (req, res) => {
  if (req.body?.website) return res.json({ ok: true, message: 'Subscribed successfully.' });
  try {
    const name = String(req.body?.name || '').trim();
    const email = String(req.body?.email || '').trim().toLowerCase();
    if (!name) return res.status(400).json({ error: 'Name is required' });
    if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return res.status(400).json({ error: 'Valid email is required' });
    }
    await ensureNewsletterSubscribersTable();
    await prisma.$executeRawUnsafe(
      `INSERT INTO newsletter_subscribers (id, name, email, source, created_at, updated_at)
       VALUES ($1, $2, $3, $4, NOW(), NOW())
       ON CONFLICT (email) DO UPDATE
       SET name = EXCLUDED.name,
           source = EXCLUDED.source,
           updated_at = NOW()`,
      uuid(),
      name,
      email,
      'newsletter-index'
    );
    res.json({ ok: true, message: 'Subscribed successfully.' });
  } catch (err) {
    console.error('Newsletter subscribe failed', err);
    res.status(500).json({ error: 'Could not subscribe right now' });
  }
});

app.get('/api/admin/newsletter/subscribers', async (req, res) => {
  if (!hasAdminAccess(req, ['add', 'remove', 'dash', 'audit', 'main'])) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  try {
    await ensureNewsletterSubscribersTable();
    const rows = await prisma.$queryRawUnsafe(
      `SELECT id, name, email, created_at FROM newsletter_subscribers ORDER BY created_at DESC`
    );
    res.json({ subscribers: rows });
  } catch (err) {
    console.error('Failed to fetch newsletter subscribers', err);
    res.status(500).json({ error: 'Could not fetch subscribers' });
  }
});

app.delete('/api/admin/newsletter/subscribers/:id', async (req, res) => {
  if (!hasAdminAccess(req, ['add', 'remove', 'dash', 'audit', 'main'])) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  const id = String(req.params.id || '').trim();
  if (!id) return res.status(400).json({ error: 'Missing id' });
  try {
    await ensureNewsletterSubscribersTable();
    const rows = await prisma.$queryRawUnsafe(
      `SELECT id, email FROM newsletter_subscribers WHERE id = $1`, id
    );
    if (!rows.length) return res.status(404).json({ error: 'Subscriber not found' });
    await prisma.$executeRawUnsafe(`DELETE FROM newsletter_subscribers WHERE id = $1`, id);
    await logAdminAction(
      getAdminSession(req)?.email || 'admin_token',
      'NEWSLETTER_SUBSCRIBER_DELETE',
      id,
      { email: rows[0].email },
      hashIp(req.ip || '')
    );
    res.json({ ok: true });
  } catch (err) {
    console.error('Failed to delete newsletter subscriber', err);
    res.status(500).json({ error: 'Could not delete subscriber' });
  }
});

app.post('/api/admin/newsletter/send-now', async (req, res) => {
  if (!hasAdminAccess(req, ['add', 'remove', 'dash', 'audit', 'main'])) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  try {
    await logAdminAction(
      getAdminSession(req)?.email || 'admin_token',
      'NEWSLETTER_MANUAL_SEND',
      'pipeline',
      { triggeredAt: new Date().toISOString() },
      hashIp(req.ip || '')
    );
    const result = await runNewsletterPipeline(prisma, { force: true });
    res.json({ ok: true, ...result });
  } catch (err) {
    console.error('Newsletter pipeline failed', err);
    res.status(500).json({ error: err.message || 'Pipeline failed' });
  }
});

app.get('/api/admin/main/analytics', async (req, res) => {
  if (!hasAdminAccess(req, ['main'])) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  try {
    const fromRaw = String(req.query.from || '').trim();
    const toRaw = String(req.query.to || '').trim();
    const from = fromRaw ? new Date(`${fromRaw}T00:00:00.000Z`) : new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
    const to = toRaw ? new Date(`${toRaw}T23:59:59.999Z`) : new Date();
    if (Number.isNaN(from.getTime()) || Number.isNaN(to.getTime())) {
      return res.status(400).json({ error: 'Invalid date range' });
    }

    const hasLeadOutcomeModel = Boolean(prisma.leadOutcome && typeof prisma.leadOutcome.findMany === 'function');
    const [totalLeadsAllTime, leadsRange, allTimeLeadsForHours, allTimeSentNotifications, allLeadOutcomes] = await Promise.all([
      prisma.lead.count(),
      prisma.lead.findMany({
        where: { createdAt: { gte: from, lte: to } },
        orderBy: { createdAt: 'desc' },
        select: {
          id: true,
          zip: true,
          createdAt: true,
          submittedBy: true,
          services: true,
          clientEmail: true,
          clientPhone: true,
          firstName: true,
          lastName: true
        }
      }),
      prisma.lead.findMany({
        select: { createdAt: true }
      }),
      prisma.leadNotification.findMany({
        where: { status: 'sent' },
        select: {
          providerId: true,
          leadId: true,
          provider: {
            select: {
              id: true,
              name: true,
              phone: true,
              email: true,
              providerLoginEmail: true
            }
          }
        }
      }),
      hasLeadOutcomeModel
        ? prisma.leadOutcome.findMany({
            include: {
              provider: {
                select: {
                  id: true,
                  name: true,
                  state: true,
                  careType: true
                }
              },
              lead: {
                select: {
                  id: true,
                  createdAt: true,
                  services: true,
                  zip: true
                }
              }
            }
          })
        : Promise.resolve([])
    ]);

    const leadIds = leadsRange.map((l) => l.id);
    const notificationsRange = leadIds.length
      ? await prisma.leadNotification.count({ where: { leadId: { in: leadIds }, status: 'sent' } })
      : 0;
    const impressionsRange = leadIds.length
      ? await prisma.providerImpression.count({ where: { leadId: { in: leadIds } } })
      : 0;
    const sentJobsRange = leadIds.length
      ? await prisma.notificationJob.findMany({
          where: { leadId: { in: leadIds }, status: 'sent' },
          select: { payload: true }
        })
      : [];
    let initialEmailsSentInRange = 0;
    let additionalEmailsSentInRange = 0;
    sentJobsRange.forEach((job) => {
      const mode = String(job?.payload?.notificationType || 'initial').toLowerCase();
      if (mode === 'details' || mode === 'additional') additionalEmailsSentInRange += 1;
      else initialEmailsSentInRange += 1;
    });
    if (!sentJobsRange.length && notificationsRange > 0) {
      initialEmailsSentInRange = notificationsRange;
      additionalEmailsSentInRange = 0;
    }

    const timelineMap = new Map();
    const careTypeMap = { hospice: 0, palliative: 0, home: 0, notSure: 0 };
    const submittedByMap = { TheClient: 0, A_Loved_One: 0, Other: 0 };
    const zipCountMap = new Map();

    const parseCareTypes = (servicesText) => {
      const lower = String(servicesText || '').toLowerCase();
      const hits = new Set();
      if (lower.includes('care type: hospice')) hits.add('hospice');
      if (lower.includes('care type: palliative')) hits.add('palliative');
      if (lower.includes('care type: home')) hits.add('home');
      if (!hits.size) {
        if (lower.includes('hospice')) hits.add('hospice');
        if (lower.includes('palliative')) hits.add('palliative');
        if (lower.includes('home care') || lower.includes('homecare')) hits.add('home');
      }
      if (!hits.size) hits.add('notSure');
      return Array.from(hits);
    };

    leadsRange.forEach((lead) => {
      const day = new Date(lead.createdAt).toISOString().slice(0, 10);
      timelineMap.set(day, (timelineMap.get(day) || 0) + 1);
      const careTypes = parseCareTypes(lead.services);
      careTypes.forEach((key) => {
        if (key === 'notSure') careTypeMap.notSure += 1;
        else careTypeMap[key] += 1;
      });
      const submittedBy = lead.submittedBy || 'Other';
      if (submittedByMap[submittedBy] == null) submittedByMap.Other += 1;
      else submittedByMap[submittedBy] += 1;
      const zip = String(lead.zip || '').trim();
      if (zip) zipCountMap.set(zip, (zipCountMap.get(zip) || 0) + 1);
    });

    const notifsForCentroid = leadIds.length
      ? await prisma.leadNotification.findMany({
          where: { leadId: { in: leadIds } },
          select: {
            leadId: true,
            sentAt: true,
            createdAt: true,
            lead: { select: { zip: true } },
            provider: { select: { lat: true, lon: true } }
          }
        })
      : [];
    const clientNeedTimesAllTime = Array.from({ length: 48 }, (_, slot) => ({ slot, count: 0 }));
    const clientNeedDaysAllTime = [
      { day: 'Sun', count: 0 },
      { day: 'Mon', count: 0 },
      { day: 'Tue', count: 0 },
      { day: 'Wed', count: 0 },
      { day: 'Thu', count: 0 },
      { day: 'Fri', count: 0 },
      { day: 'Sat', count: 0 }
    ];
    allTimeLeadsForHours.forEach((row) => {
      const slot = getEasternHalfHourSlot(row.createdAt);
      if (slot >= 0 && slot <= 47) clientNeedTimesAllTime[slot].count += 1;
      const weekdayIdx = getEasternWeekdayIndex(row.createdAt);
      if (weekdayIdx >= 0 && weekdayIdx <= 6) clientNeedDaysAllTime[weekdayIdx].count += 1;
    });

    const providerClientMap = new Map();
    allTimeSentNotifications.forEach((row) => {
      if (!row.providerId) return;
      const providerName = row.provider?.name || 'Unknown provider';
      const current = providerClientMap.get(row.providerId) || {
        providerId: row.providerId,
        providerName,
        providerPhone: row.provider?.phone || '',
        providerEmail: row.provider?.email || '',
        providerLoginEmail: row.provider?.providerLoginEmail || '',
        leadIds: new Set()
      };
      if (!current.providerPhone && row.provider?.phone) current.providerPhone = row.provider.phone;
      if (!current.providerEmail && row.provider?.email) current.providerEmail = row.provider.email;
      if (!current.providerLoginEmail && row.provider?.providerLoginEmail) current.providerLoginEmail = row.provider.providerLoginEmail;
      if (row.leadId) current.leadIds.add(row.leadId);
      providerClientMap.set(row.providerId, current);
    });
    const providerClientRanking = Array.from(providerClientMap.values())
      .map((entry) => ({
        providerId: entry.providerId,
        providerName: entry.providerName,
        providerPhone: entry.providerPhone || '',
        providerEmail: entry.providerEmail || '',
        providerLoginEmail: entry.providerLoginEmail || '',
        clientsGenerated: entry.leadIds.size
      }))
      .sort((a, b) => {
        if (b.clientsGenerated !== a.clientsGenerated) return b.clientsGenerated - a.clientsGenerated;
        return a.providerName.localeCompare(b.providerName);
      });

    const providerOutcomeMap = new Map();
    const admitByCareType = {};
    const admitByGeography = {};
    const staleNoUpdateLeads = [];
    let totalFirstContactHours = 0;
    let totalFirstContactCount = 0;
    const noUpdateCutoff = Date.now() - (7 * 24 * 60 * 60 * 1000);

    const parsePrimaryCareType = (servicesText) => {
      const lower = String(servicesText || '').toLowerCase();
      if (lower.includes('care type: hospice')) return 'Hospice';
      if (lower.includes('care type: palliative')) return 'Palliative';
      if (lower.includes('care type: home')) return 'Home Care';
      if (lower.includes('hospice')) return 'Hospice';
      if (lower.includes('palliative')) return 'Palliative';
      if (lower.includes('home')) return 'Home Care';
      return 'Not sure';
    };

    allLeadOutcomes.forEach((row) => {
      const providerId = row.providerId;
      const providerName = row.provider?.name || 'Unknown provider';
      const providerState = row.provider?.state || 'Unknown';
      const status = normalizeLeadOutcomeStatus(row.status) || 'new';
      const current = providerOutcomeMap.get(providerId) || {
        providerId,
        providerName,
        total: 0,
        admitted: 0
      };
      current.total += 1;
      if (status === 'admitted') current.admitted += 1;
      providerOutcomeMap.set(providerId, current);

      const careTypeLabel = parsePrimaryCareType(row.lead?.services);
      if (!admitByCareType[careTypeLabel]) admitByCareType[careTypeLabel] = { total: 0, admitted: 0 };
      admitByCareType[careTypeLabel].total += 1;
      if (status === 'admitted') admitByCareType[careTypeLabel].admitted += 1;

      if (!admitByGeography[providerState]) admitByGeography[providerState] = { total: 0, admitted: 0 };
      admitByGeography[providerState].total += 1;
      if (status === 'admitted') admitByGeography[providerState].admitted += 1;

      if (row.firstResponseAt && row.lead?.createdAt) {
        const hours = (new Date(row.firstResponseAt).getTime() - new Date(row.lead.createdAt).getTime()) / (1000 * 60 * 60);
        if (Number.isFinite(hours) && hours >= 0) {
          totalFirstContactHours += hours;
          totalFirstContactCount += 1;
        }
      }

      if (status === 'new' && row.lead?.createdAt && new Date(row.lead.createdAt).getTime() <= noUpdateCutoff) {
        staleNoUpdateLeads.push({
          leadId: row.leadId,
          providerId: row.providerId,
          providerName,
          providerState,
          zip: row.lead.zip || '',
          createdAt: row.lead.createdAt,
          ageDays: Math.floor((Date.now() - new Date(row.lead.createdAt).getTime()) / (1000 * 60 * 60 * 24))
        });
      }
    });

    const conversionByProvider = Array.from(providerOutcomeMap.values())
      .map((row) => ({
        providerId: row.providerId,
        providerName: row.providerName,
        leads: row.total,
        admitted: row.admitted,
        conversionRatePct: row.total ? Number(((row.admitted / row.total) * 100).toFixed(1)) : 0
      }))
      .sort((a, b) => {
        if (b.conversionRatePct !== a.conversionRatePct) return b.conversionRatePct - a.conversionRatePct;
        return b.leads - a.leads;
      });

    const admitRateByCareType = Object.entries(admitByCareType)
      .map(([label, row]) => ({
        label,
        leads: row.total,
        admitted: row.admitted,
        admitRatePct: row.total ? Number(((row.admitted / row.total) * 100).toFixed(1)) : 0
      }))
      .sort((a, b) => b.admitRatePct - a.admitRatePct);

    const admitRateByGeography = Object.entries(admitByGeography)
      .map(([state, row]) => ({
        geography: state,
        leads: row.total,
        admitted: row.admitted,
        admitRatePct: row.total ? Number(((row.admitted / row.total) * 100).toFixed(1)) : 0
      }))
      .sort((a, b) => b.admitRatePct - a.admitRatePct);

    const avgTimeToFirstContactHours = totalFirstContactCount
      ? Number((totalFirstContactHours / totalFirstContactCount).toFixed(2))
      : null;

    const aggregateHeatPoints = (rows = []) => {
      const leadCentroidMap = new Map();
      for (const row of rows) {
        const zip = String(row?.lead?.zip || row?.zip || '').trim();
        const lat = Number(row?.provider?.lat);
        const lon = Number(row?.provider?.lon);
        if (!zip || !Number.isFinite(lat) || !Number.isFinite(lon)) continue;
        const curr = leadCentroidMap.get(row.leadId) || { zip, count: 0, lat: 0, lon: 0 };
        curr.count += 1;
        curr.lat += lat;
        curr.lon += lon;
        leadCentroidMap.set(row.leadId, curr);
      }

      const heatZipMap = new Map();
      for (const cent of leadCentroidMap.values()) {
        if (!cent.count) continue;
        const key = String(cent.zip || '').trim();
        const curr = heatZipMap.get(key) || { zip: key, count: 0, latAcc: 0, lonAcc: 0, n: 0 };
        curr.count += 1;
        curr.latAcc += (cent.lat / cent.count);
        curr.lonAcc += (cent.lon / cent.count);
        curr.n += 1;
        heatZipMap.set(key, curr);
      }

      return Array.from(heatZipMap.values())
        .map((z) => ({
          zip: z.zip,
          count: z.count,
          lat: z.latAcc / z.n,
          lon: z.lonAcc / z.n
        }))
        .filter((z) => Number.isFinite(z.lat) && Number.isFinite(z.lon));
    };

    let heatPoints = aggregateHeatPoints(notifsForCentroid);
    if (!heatPoints.length && leadIds.length) {
      const impressionRows = await prisma.providerImpression.findMany({
        where: { leadId: { in: leadIds } },
        select: {
          leadId: true,
          lead: { select: { zip: true } },
          provider: { select: { lat: true, lon: true } }
        }
      });
      heatPoints = aggregateHeatPoints(impressionRows);
    }
    if (!heatPoints.length) {
      const leadZipsInRange = Array.from(new Set(
        leadsRange
          .map((l) => String(l.zip || '').trim())
          .filter(Boolean)
      ));
      if (leadZipsInRange.length) {
        const impressionRowsByZip = await prisma.providerImpression.findMany({
          where: {
            zip: { in: leadZipsInRange },
            createdAt: { gte: from, lte: to }
          },
          select: {
            zip: true,
            provider: { select: { lat: true, lon: true } }
          }
        });
        heatPoints = aggregateHeatPoints(impressionRowsByZip);
      }
    }

    const timeline = Array.from(timelineMap.entries())
      .map(([date, count]) => ({ date, count }))
      .sort((a, b) => a.date.localeCompare(b.date));

    const topZips = Array.from(zipCountMap.entries())
      .map(([zip, count]) => ({ zip, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 15);

    const recentLeadRows = leadsRange.slice(0, 200);
    const recentLeadIds = recentLeadRows.map((l) => l.id);
    const notificationRows = recentLeadIds.length
      ? await prisma.leadNotification.findMany({
          where: { leadId: { in: recentLeadIds } },
          orderBy: [{ createdAt: 'asc' }],
          select: {
            leadId: true,
            status: true,
            sentAt: true,
            createdAt: true,
            errorMessage: true,
            provider: {
              select: {
                id: true,
                name: true,
                email: true,
                phone: true,
                city: true,
                state: true
              }
            }
          }
        })
      : [];
    const recentOutcomes = recentLeadIds.length && hasLeadOutcomeModel
      ? await prisma.leadOutcome.findMany({
          where: { leadId: { in: recentLeadIds } },
          select: {
            leadId: true,
            providerId: true,
            status: true,
            lastStatusChangedAt: true,
            firstResponseAt: true
          }
        })
      : [];
    const outcomeByLeadProvider = new Map(
      recentOutcomes.map((o) => [`${o.leadId}|${o.providerId}`, o])
    );
    const notificationsByLeadId = new Map();
    notificationRows.forEach((n) => {
      const arr = notificationsByLeadId.get(n.leadId) || [];
      const outcomeKey = `${n.leadId}|${n.provider?.id || ''}`;
      const outcome = outcomeByLeadProvider.get(outcomeKey);
      const outcomeStatus = normalizeLeadOutcomeStatus(outcome?.status) || 'new';
      arr.push({
        status: n.status || 'unknown',
        sentAt: n.sentAt || n.createdAt,
        errorMessage: n.errorMessage || '',
        outcomeStatus,
        outcomeStatusLabel: leadOutcomeLabel(outcomeStatus),
        outcomeUpdatedAt: outcome?.lastStatusChangedAt || null,
        firstResponseAt: outcome?.firstResponseAt || null,
        provider: n.provider
          ? {
              id: n.provider.id,
              name: n.provider.name || 'Unknown provider',
              email: n.provider.email || '',
              phone: n.provider.phone || '',
              city: n.provider.city || '',
              state: n.provider.state || ''
            }
          : null
      });
      notificationsByLeadId.set(n.leadId, arr);
    });

    const recentLeads = recentLeadRows.map((l) => ({
      id: l.id,
      createdAt: l.createdAt,
      zip: l.zip,
      submittedBy: l.submittedBy,
      services: l.services || '',
      clientName: buildClientName(l.firstName, l.lastName),
      clientEmail: l.clientEmail || '',
      clientPhone: l.clientPhone || '',
      notifications: notificationsByLeadId.get(l.id) || []
    }));
    staleNoUpdateLeads.sort((a, b) => b.ageDays - a.ageDays);

    // LeadOutcome rows are per lead+provider, so collapse to one row per lead
    // and keep how many providers were notified about it.
    const staleNoUpdateByLead = [];
    const staleSeen = new Map();
    staleNoUpdateLeads.forEach((row) => {
      const existing = staleSeen.get(row.leadId);
      if (existing) {
        existing.providerCount += 1;
        return;
      }
      const entry = { ...row, providerCount: 1 };
      staleSeen.set(row.leadId, entry);
      staleNoUpdateByLead.push(entry);
    });

    let uniqueViewersInRange = 0;
    let uniqueViewersAllTime = 0;
    let pageViewsInRange = 0;
    let sessionsInRange = 0;
    let pagesPerSession = 0;
    let avgEngagementSeconds = 0;
    let avgScrollDepthPct = 0;
    let eventCounts = {};
    let topPages = [];
    let topReferrers = [];
    let websiteAccessTimesEt = Array.from({ length: 48 }, (_, slot) => ({ slot, count: 0 }));
    let websiteAccessDaysEt = [
      { day: 'Sun', count: 0 },
      { day: 'Mon', count: 0 },
      { day: 'Tue', count: 0 },
      { day: 'Wed', count: 0 },
      { day: 'Thu', count: 0 },
      { day: 'Fri', count: 0 },
      { day: 'Sat', count: 0 }
    ];
    let websiteEngagementByDate = [];
    try {
      await ensureWebsiteEventsTable();
      const [
        uniqueViewersRangeRows,
        uniqueViewersAllRows,
        pageViewsRangeRows,
        sessionsRangeRows,
        avgEngagementRows,
        avgScrollRows,
        topPagesRows,
        topReferrersRows,
        eventCountsRows,
        accessTimesRows,
        accessDaysRows,
        engagementByDateRows
      ] = await Promise.all([
        prisma.$queryRaw`SELECT COUNT(DISTINCT viewer_id)::bigint AS count FROM website_events WHERE created_at >= ${from} AND created_at <= ${to}`,
        prisma.$queryRaw`SELECT COUNT(DISTINCT viewer_id)::bigint AS count FROM website_events`,
        prisma.$queryRaw`SELECT COUNT(*)::bigint AS count FROM website_events WHERE event_type = 'page_view' AND created_at >= ${from} AND created_at <= ${to}`,
        prisma.$queryRaw`SELECT COUNT(DISTINCT session_id)::bigint AS count FROM website_events WHERE created_at >= ${from} AND created_at <= ${to}`,
        prisma.$queryRaw`SELECT AVG(duration_ms)::float AS avg_ms FROM website_events WHERE event_type = 'page_exit' AND duration_ms IS NOT NULL AND created_at >= ${from} AND created_at <= ${to}`,
        prisma.$queryRaw`SELECT AVG(max_scroll)::float AS avg_scroll FROM (SELECT session_id, MAX(COALESCE(scroll_depth, 0))::float AS max_scroll FROM website_events WHERE created_at >= ${from} AND created_at <= ${to} GROUP BY session_id) t`,
        prisma.$queryRaw`SELECT path, COUNT(*)::bigint AS views FROM website_events WHERE event_type = 'page_view' AND created_at >= ${from} AND created_at <= ${to} GROUP BY path ORDER BY views DESC LIMIT 12`,
        prisma.$queryRaw`SELECT COALESCE(NULLIF(referrer, ''), '(direct)') AS referrer, COUNT(*)::bigint AS views FROM website_events WHERE event_type = 'page_view' AND created_at >= ${from} AND created_at <= ${to} GROUP BY referrer ORDER BY views DESC LIMIT 8`,
        prisma.$queryRaw`SELECT event_type, COUNT(*)::bigint AS total FROM website_events WHERE created_at >= ${from} AND created_at <= ${to} GROUP BY event_type`,
        prisma.$queryRaw`SELECT ((EXTRACT(HOUR FROM (created_at AT TIME ZONE 'America/New_York'))::int * 2) + (EXTRACT(MINUTE FROM (created_at AT TIME ZONE 'America/New_York'))::int / 30))::int AS slot, COUNT(*)::bigint AS total FROM website_events WHERE event_type = 'page_view' AND created_at >= ${from} AND created_at <= ${to} GROUP BY slot ORDER BY slot ASC`,
        prisma.$queryRaw`SELECT EXTRACT(DOW FROM (created_at AT TIME ZONE 'America/New_York'))::int AS dow, COUNT(*)::bigint AS total FROM website_events WHERE event_type = 'page_view' AND created_at >= ${from} AND created_at <= ${to} GROUP BY dow ORDER BY dow ASC`,
        prisma.$queryRaw`SELECT TO_CHAR((created_at AT TIME ZONE 'America/New_York')::date, 'YYYY-MM-DD') AS day, SUM(CASE WHEN event_type = 'page_view' THEN 1 ELSE 0 END)::bigint AS page_views, COUNT(DISTINCT session_id)::bigint AS sessions, AVG(CASE WHEN event_type = 'page_exit' AND duration_ms IS NOT NULL THEN duration_ms END)::float AS avg_ms FROM website_events WHERE created_at >= ${from} AND created_at <= ${to} GROUP BY (created_at AT TIME ZONE 'America/New_York')::date ORDER BY day ASC`
      ]);

      uniqueViewersInRange = Number(uniqueViewersRangeRows?.[0]?.count || 0);
      uniqueViewersAllTime = Number(uniqueViewersAllRows?.[0]?.count || 0);
      pageViewsInRange = Number(pageViewsRangeRows?.[0]?.count || 0);
      sessionsInRange = Number(sessionsRangeRows?.[0]?.count || 0);
      const avgEngagementMs = Number(avgEngagementRows?.[0]?.avg_ms || 0);
      const avgMaxScrollDepth = Number(avgScrollRows?.[0]?.avg_scroll || 0);
      eventCounts = (eventCountsRows || []).reduce((acc, row) => {
        const key = String(row.event_type || '');
        acc[key] = Number(row.total || 0);
        return acc;
      }, {});
      topPages = (topPagesRows || []).map((row) => ({
        path: String(row.path || '/'),
        views: Number(row.views || 0)
      }));
      topReferrers = (topReferrersRows || []).map((row) => ({
        referrer: String(row.referrer || '(direct)'),
        views: Number(row.views || 0)
      }));
      const slotCounts = Array.from({ length: 48 }, () => 0);
      (accessTimesRows || []).forEach((row) => {
        const slot = Number(row.slot);
        if (Number.isInteger(slot) && slot >= 0 && slot < 48) {
          slotCounts[slot] = Number(row.total || 0);
        }
      });
      websiteAccessTimesEt = slotCounts.map((count, slot) => ({ slot, count }));
      const dayCounts = Array.from({ length: 7 }, () => 0);
      (accessDaysRows || []).forEach((row) => {
        const dow = Number(row.dow);
        if (Number.isInteger(dow) && dow >= 0 && dow <= 6) {
          dayCounts[dow] = Number(row.total || 0);
        }
      });
      websiteAccessDaysEt = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'].map((day, idx) => ({
        day,
        count: dayCounts[idx]
      }));
      websiteEngagementByDate = (engagementByDateRows || []).map((row) => {
        const avgMs = Number(row.avg_ms || 0);
        return {
          date: String(row.day || ''),
          pageViews: Number(row.page_views || 0),
          sessions: Number(row.sessions || 0),
          avgEngagementSeconds: Number.isFinite(avgMs) ? Number((avgMs / 1000).toFixed(1)) : 0
        };
      });
      pagesPerSession = sessionsInRange ? Number((pageViewsInRange / sessionsInRange).toFixed(2)) : 0;
      avgEngagementSeconds = Number((avgEngagementMs / 1000).toFixed(1));
      avgScrollDepthPct = Number(avgMaxScrollDepth.toFixed(1));
    } catch (webAnalyticsErr) {
      console.error('Website analytics query failed (continuing with lead analytics)', webAnalyticsErr?.message || webAnalyticsErr);
    }

    // Admin-confirmed admit rates (uses adminStatus on Lead, not provider-reported LeadOutcome)
    let confirmedAdmitsAllTime = 0;
    let adminConversionByProvider = [];
    const adminAdmitByCareType = {};
    const adminAdmitByGeography = {};
    try {
      await ensureLeadAdminStatusColumns();
      const [allLeadsForRates, allLeadsForTotal] = await Promise.all([
        prisma.$queryRawUnsafe(`
          SELECT l.id, l.services, l."adminStatus", l."adminProviderId", p.state AS "providerState"
          FROM "Lead" l
          LEFT JOIN "Provider" p ON p.id = l."adminProviderId"
        `),
        prisma.$queryRawUnsafe(`SELECT id, services, zip FROM "Lead"`)
      ]);
      confirmedAdmitsAllTime = allLeadsForRates.filter(r => r.adminStatus === 'admitted').length;
      // Build totals per care type and geography from ALL leads
      allLeadsForTotal.forEach(l => {
        const ct = parsePrimaryCareType(l.services);
        if (!adminAdmitByCareType[ct]) adminAdmitByCareType[ct] = { total: 0, admitted: 0 };
        adminAdmitByCareType[ct].total += 1;
      });
      // Add admitted counts
      allLeadsForRates.filter(r => r.adminStatus === 'admitted').forEach(l => {
        const ct = parsePrimaryCareType(l.services);
        if (adminAdmitByCareType[ct]) adminAdmitByCareType[ct].admitted += 1;
        const geo = l.providerState || 'Unknown';
        if (!adminAdmitByGeography[geo]) adminAdmitByGeography[geo] = { total: 0, admitted: 0 };
        adminAdmitByGeography[geo].admitted += 1;
      });
      // Geography totals: use all leads, match state from any sent notification
      const notifStateRows = await prisma.$queryRawUnsafe(`
        SELECT DISTINCT ln."leadId", p.state
        FROM "LeadNotification" ln
        JOIN "Provider" p ON p.id = ln."providerId"
        WHERE ln.status = 'sent'
      `);
      const leadStateMap = new Map();
      notifStateRows.forEach(r => { if (!leadStateMap.has(r.leadId)) leadStateMap.set(r.leadId, r.state); });
      allLeadsForTotal.forEach(l => {
        const geo = leadStateMap.get(l.id) || 'Unknown';
        if (!adminAdmitByGeography[geo]) adminAdmitByGeography[geo] = { total: 0, admitted: 0 };
        adminAdmitByGeography[geo].total += 1;
      });

      // Conversion by provider: leads sent to each provider vs admin-confirmed admits for that provider
      const providerLeadCounts = new Map();
      allTimeSentNotifications.forEach(n => {
        if (!n.providerId) return;
        const name = n.provider?.name || 'Unknown';
        const cur = providerLeadCounts.get(n.providerId) || { providerId: n.providerId, providerName: name, leadIds: new Set(), admitted: 0 };
        cur.leadIds.add(n.leadId);
        providerLeadCounts.set(n.providerId, cur);
      });
      allLeadsForRates.filter(r => r.adminStatus === 'admitted' && r.adminProviderId).forEach(l => {
        const entry = providerLeadCounts.get(l.adminProviderId);
        if (entry) entry.admitted += 1;
      });
      adminConversionByProvider = Array.from(providerLeadCounts.values())
        .map(row => ({
          providerId: row.providerId,
          providerName: row.providerName,
          leads: row.leadIds.size,
          admitted: row.admitted,
          conversionRatePct: row.leadIds.size ? Number(((row.admitted / row.leadIds.size) * 100).toFixed(1)) : 0
        }))
        .sort((a, b) => b.conversionRatePct - a.conversionRatePct || b.leads - a.leads);
    } catch (admitErr) {
      console.error('Admin admit rate calc failed (continuing)', admitErr?.message || admitErr);
    }

    const adminAdmitRateByCareType = Object.entries(adminAdmitByCareType)
      .map(([label, row]) => ({ label, leads: row.total, admitted: row.admitted, admitRatePct: row.total ? Number(((row.admitted / row.total) * 100).toFixed(1)) : 0 }))
      .sort((a, b) => b.admitted - a.admitted || b.leads - a.leads);

    const adminAdmitRateByGeography = Object.entries(adminAdmitByGeography)
      .filter(([geo]) => geo !== 'Unknown' || adminAdmitByGeography[geo]?.total > 0)
      .map(([geography, row]) => ({ geography, leads: row.total, admitted: row.admitted, admitRatePct: row.total ? Number(((row.admitted / row.total) * 100).toFixed(1)) : 0 }))
      .sort((a, b) => b.admitted - a.admitted || b.leads - a.leads);

    let dischargeReferralsAllTime = 0;
    let dischargeReferralsInRange = 0;
    try {
      await ensureDischargeReferralTable();
      const [drAllTime, drInRange] = await Promise.all([
        prisma.$queryRawUnsafe(`SELECT COUNT(*)::int AS count FROM "DischargeReferral"`),
        prisma.$queryRawUnsafe(`SELECT COUNT(*)::int AS count FROM "DischargeReferral" WHERE submitted_at >= $1 AND submitted_at <= $2`, from, to)
      ]);
      dischargeReferralsAllTime = Number(drAllTime?.[0]?.count || 0);
      dischargeReferralsInRange = Number(drInRange?.[0]?.count || 0);
    } catch (drErr) {
      console.error('Discharge referral count failed (continuing)', drErr?.message || drErr);
    }

    res.json({
      ok: true,
      from: from.toISOString().slice(0, 10),
      to: to.toISOString().slice(0, 10),
      totals: {
        leadsAllTime: totalLeadsAllTime,
        leadsInRange: leadsRange.length,
        notificationsSentInRange: notificationsRange,
        initialEmailsSentInRange,
        additionalEmailsSentInRange,
        impressionsInRange: impressionsRange,
        avgNotificationsPerLead: leadsRange.length ? Number((notificationsRange / leadsRange.length).toFixed(2)) : 0,
        avgTimeToFirstContactHours,
        noUpdateLeadsCount: staleNoUpdateByLead.length,
        uniqueViewersInRange,
        uniqueViewersAllTime,
        pageViewsInRange,
        sessionsInRange,
        pagesPerSession,
        avgEngagementSeconds,
        avgScrollDepthPct,
        dischargeReferralsAllTime,
        dischargeReferralsInRange,
        confirmedAdmitsAllTime
      },
      breakdowns: {
        careTypes: careTypeMap,
        submittedBy: submittedByMap,
        topZips,
        clientNeedTimesAllTime,
        clientNeedDaysAllTime,
        providerClientRanking,
        conversionByProvider: adminConversionByProvider.length ? adminConversionByProvider : conversionByProvider,
        admitRateByCareType: adminAdmitRateByCareType,
        admitRateByGeography: adminAdmitRateByGeography,
        noUpdateLeads: staleNoUpdateByLead,
        topPages,
        topReferrers,
        websiteAccessTimesEt,
        websiteAccessDaysEt,
        websiteEngagementByDate,
        webEventCounts: eventCounts
      },
      timeline,
      heatPoints,
      recentLeads
    });
  } catch (err) {
    console.error('Admin main analytics failed', err);
    res.status(500).json({ error: 'Failed to load analytics' });
  }
});

app.get('/api/admin/main/verify', (req, res) => {
  if (!hasAdminAccess(req, ['main'])) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  res.json({ ok: true });
});

// Read-only weekly funnel aggregates (sessions -> pageviews -> form starts/completes -> leads -> admits).
// Honors ?from=YYYY-MM-DD&to=YYYY-MM-DD; defaults to the last 90 days when omitted.
// PATCH /api/admin/provider-billing-mode/:id — comp a provider, or start their
// paid-trial countdown. Does not touch Stripe; this is our own bookkeeping.
app.patch('/api/admin/provider-billing-mode/:id', async (req, res) => {
  if (!hasAdminAccess(req, ['main'])) return res.status(401).json({ error: 'Unauthorized' });
  const mode = String(req.body?.mode || '').trim().toLowerCase();
  if (!['free', 'billed', 'off'].includes(mode)) {
    return res.status(400).json({ error: 'mode must be free, billed, or off' });
  }
  try {
    await ensureProviderStripeColumns();
    await prisma.$executeRawUnsafe(
      `UPDATE "Provider" SET "billingMode" = $1 WHERE "id" = $2`,
      mode, req.params.id
    );
    await logAdminAction(
      'admin', 'PROVIDER_BILLING_MODE', req.params.id,
      { mode }, hashIp(req.ip || '')
    );
    res.json({ ok: true, mode });
  } catch (err) {
    console.error('Provider billing mode update failed', err);
    res.status(500).json({ error: 'Could not update billing mode.' });
  }
});

// Read-only subscription roster for admin: who is actually paying.
app.get('/api/admin/main/subscriptions', async (req, res) => {
  if (!hasAdminAccess(req, ['main'])) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  try {
    await ensureProviderStripeColumns();
    const rows = await prisma.$queryRaw`
      SELECT id, name, email, "planTier", "subscriptionStatus",
             "currentPeriodEnd", "stripeCustomerId", "stripeSubscriptionId",
             "billingMode", "receiveClientLeads"
      FROM "Provider"
      ORDER BY name ASC
    `;

    const providers = rows.map((r) => {
      const state = subscriptionBannerState(r.subscriptionStatus);
      const tier = normalizePlanTier(r.planTier);
      const billing = providerBillingState(r);
      return {
        id: r.id,
        name: r.name,
        email: r.email || '',
        planTier: tier,
        monthlyRate: providerRateForTier(tier),
        status: r.subscriptionStatus || null,
        state,
        currentPeriodEnd: r.currentPeriodEnd || null,
        hasStripeCustomer: Boolean(r.stripeCustomerId),
        hasSubscription: Boolean(r.stripeSubscriptionId),
        billingMode: String(r.billingMode || 'free').toLowerCase(),
        billingState: billing.state,
        billingLabel: billing.label,
        // Notifications can be switched off independently of billing, so the
        // marker has to account for both or it would lie.
        notificationsOn: r.receiveClientLeads !== false,
        leadsAllowed: billing.leadsAllowed && r.receiveClientLeads !== false
      };
    });

    const paying = providers.filter((p) => p.state === 'on');
    const atRisk = providers.filter((p) => p.state === 'warn');
    const off = providers.filter((p) => p.state === 'off');

    res.json({
      ok: true,
      totals: {
        providers: providers.length,
        paying: paying.length,
        atRisk: atRisk.length,
        off: off.length,
        freeVersion: providers.filter((p) => p.billingState === 'free').length,
        switchedOff: providers.filter((p) => p.billingState === 'off').length,
        // Committed monthly revenue from providers Stripe reports as paying.
        monthlyRecurring: paying.reduce((sum, p) => sum + p.monthlyRate, 0)
      },
      providers
    });
  } catch (err) {
    console.error('Admin subscriptions failed', err);
    res.status(500).json({ error: 'Failed to load subscriptions' });
  }
});

app.get('/api/admin/funnel-stats', async (req, res) => {
  if (!hasAdminAccess(req, ['main'])) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  try {
    await ensureWebsiteEventsTable();
    await ensureLeadAdminStatusColumns();

    const fromRaw = String(req.query.from || '').trim();
    const toRaw = String(req.query.to || '').trim();
    const from = fromRaw ? new Date(`${fromRaw}T00:00:00.000Z`) : new Date(Date.now() - 90 * 24 * 60 * 60 * 1000);
    const to = toRaw ? new Date(`${toRaw}T23:59:59.999Z`) : new Date();
    if (Number.isNaN(from.getTime()) || Number.isNaN(to.getTime())) {
      return res.status(400).json({ error: 'Invalid date range' });
    }

    const [eventRows, leadRows] = await Promise.all([
      prisma.$queryRaw`
        SELECT
          TO_CHAR(date_trunc('week', (created_at AT TIME ZONE 'America/New_York')), 'YYYY-MM-DD') AS week_start,
          COUNT(DISTINCT session_id)::int AS sessions,
          COUNT(*) FILTER (WHERE event_type = 'page_view')::int AS pageviews,
          COUNT(*) FILTER (WHERE event_type = 'form_submit_initial')::int AS form_starts,
          COUNT(*) FILTER (WHERE event_type = 'form_submit_details')::int AS form_completes
        FROM website_events
        WHERE created_at >= ${from} AND created_at <= ${to}
        GROUP BY 1
        ORDER BY 1 ASC
      `,
      prisma.$queryRaw`
        SELECT
          TO_CHAR(date_trunc('week', ("createdAt" AT TIME ZONE 'America/New_York')), 'YYYY-MM-DD') AS week_start,
          COUNT(*)::int AS leads,
          COUNT(*) FILTER (WHERE "adminStatus" = 'admitted')::int AS admits
        FROM "Lead"
        WHERE "createdAt" >= ${from} AND "createdAt" <= ${to}
        GROUP BY 1
        ORDER BY 1 ASC
      `
    ]);

    const weekMap = new Map();
    eventRows.forEach((r) => {
      weekMap.set(r.week_start, {
        weekStart: r.week_start,
        sessions: Number(r.sessions || 0),
        pageviews: Number(r.pageviews || 0),
        formStarts: Number(r.form_starts || 0),
        formCompletes: Number(r.form_completes || 0),
        leads: 0,
        admits: 0
      });
    });
    leadRows.forEach((r) => {
      const cur = weekMap.get(r.week_start) || {
        weekStart: r.week_start,
        sessions: 0,
        pageviews: 0,
        formStarts: 0,
        formCompletes: 0,
        leads: 0,
        admits: 0
      };
      cur.leads = Number(r.leads || 0);
      cur.admits = Number(r.admits || 0);
      weekMap.set(r.week_start, cur);
    });

    const weeks = Array.from(weekMap.values())
      .sort((a, b) => a.weekStart.localeCompare(b.weekStart))
      .map((w) => ({
        ...w,
        sessionToLeadPct: w.sessions ? Number((w.leads / w.sessions * 100).toFixed(2)) : 0,
        startToCompletePct: w.formStarts ? Number((w.formCompletes / w.formStarts * 100).toFixed(2)) : 0,
        admitRatePct: w.leads ? Number((w.admits / w.leads * 100).toFixed(2)) : 0
      }));

    res.json({
      ok: true,
      from: from.toISOString().slice(0, 10),
      to: to.toISOString().slice(0, 10),
      weeks
    });
  } catch (err) {
    console.error('Admin funnel stats failed', err);
    res.status(500).json({ error: 'Failed to load funnel stats' });
  }
});

app.get('/api/admin/no-provider-leads', async (req, res) => {
  if (!hasAdminAccess(req, ['main'])) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  try {
    const leads = await prisma.lead.findMany({
      where: { notifications: { none: { status: 'sent' } } },
      orderBy: { createdAt: 'desc' },
      take: 500,
      select: {
        id: true, zip: true, submittedBy: true, careDays: true,
        services: true, clientEmail: true, clientPhone: true,
        firstName: true, lastName: true, createdAt: true
      }
    });

    // Geocode unique ZIPs (Nominatim rate-limit: 1 req/s)
    const uniqueZips = [...new Set(leads.map((l) => l.zip).filter(Boolean))];
    const zipCoords = {};
    for (const zip of uniqueZips) {
      try {
        const geo = await geocodeAddress(`${zip}, USA`);
        if (geo) zipCoords[zip] = { lat: geo.lat, lon: geo.lon };
      } catch (_) { /* skip */ }
      await new Promise((r) => setTimeout(r, 1100));
    }

    const zipCountMap = {};
    leads.forEach((l) => { if (l.zip) zipCountMap[l.zip] = (zipCountMap[l.zip] || 0) + 1; });
    const heatPoints = Object.entries(zipCountMap)
      .filter(([zip]) => zipCoords[zip])
      .map(([zip, count]) => ({ zip, count, lat: zipCoords[zip].lat, lon: zipCoords[zip].lon }));

    res.json({ leads, heatPoints });
  } catch (err) {
    console.error('No-provider leads failed', err);
    res.status(500).json({ error: 'Failed to load data' });
  }
});

// GET /api/admin/providers/active-emails?minLeads=3 — emails of providers with >= minLeads leads sent
app.get('/api/admin/providers/active-emails', async (req, res) => {
  if (!hasAdminAccess(req, ['main'])) return res.status(401).json({ error: 'Unauthorized' });
  const minLeads = Math.max(1, parseInt(req.query.minLeads || '3', 10));
  try {
    const rows = await prisma.$queryRawUnsafe(`
      SELECT p.id, p.name, p.email, p."secondaryContactEmail", COUNT(DISTINCT ln."leadId")::int AS lead_count
      FROM "Provider" p
      JOIN "LeadNotification" ln ON ln."providerId" = p.id AND ln.status = 'sent'
      GROUP BY p.id, p.name, p.email, p."secondaryContactEmail"
      HAVING COUNT(DISTINCT ln."leadId") >= $1
      ORDER BY lead_count DESC, p.name ASC
    `, minLeads);
    res.json({ providers: rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/admin/client-emails — all unique client emails from leads + discharge referrals
app.get('/api/admin/client-emails', async (req, res) => {
  if (!hasAdminAccess(req, ['main'])) return res.status(401).json({ error: 'Unauthorized' });
  try {
    const [leadEmails, dischargeEmails] = await Promise.all([
      prisma.lead.findMany({ select: { clientEmail: true }, where: { clientEmail: { not: null } } }),
      prisma.$queryRawUnsafe(`SELECT planner_email AS email FROM "DischargeReferral" WHERE planner_email IS NOT NULL AND planner_email <> ''`)
    ]);
    const all = new Set();
    leadEmails.forEach(r => { if (r.clientEmail && r.clientEmail !== 'Not provided') all.add(r.clientEmail.trim().toLowerCase()); });
    dischargeEmails.forEach(r => { if (r.email) all.add(r.email.trim().toLowerCase()); });
    res.json({ emails: [...all].sort() });
  } catch (err) {
    res.status(500).json({ error: 'Failed to load emails' });
  }
});

// GET /api/admin/provider-notifications — all providers grouped by state with notification settings
app.get('/api/admin/provider-notifications', async (req, res) => {
  if (!hasAdminAccess(req, ['main'])) return res.status(401).json({ error: 'Unauthorized' });
  try {
    await ensureJobLeadTable();
    const rows = await prisma.$queryRawUnsafe(
      `SELECT id, name, city, state, email, "receiveClientLeads", "receiveJobLeads" FROM "Provider" ORDER BY state ASC, name ASC`
    );
    res.json({ providers: rows });
  } catch (err) {
    res.status(500).json({ error: 'Failed to load providers' });
  }
});

// PATCH /api/admin/provider-notifications/:id — toggle client/job leads for a provider
app.patch('/api/admin/provider-notifications/:id', async (req, res) => {
  if (!hasAdminAccess(req, ['main'])) return res.status(401).json({ error: 'Unauthorized' });
  const { id } = req.params;
  const { field, value } = req.body || {};
  if (!['receiveClientLeads', 'receiveJobLeads'].includes(field)) return res.status(400).json({ error: 'Invalid field' });
  if (typeof value !== 'boolean') return res.status(400).json({ error: 'value must be boolean' });
  try {
    await ensureJobLeadTable();
    await prisma.$executeRawUnsafe(
      `UPDATE "Provider" SET "${field}" = $1 WHERE id = $2`,
      value, id
    );
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: 'Failed to update provider' });
  }
});

app.get('/api/admin/territory/leads', async (req, res) => {
  if (!hasAdminAccess(req, ['main'])) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  try {
    await ensureWaitlistTable();
    const requests = await prisma.waitlistRequest.findMany({
      orderBy: { createdAt: 'desc' },
      take: 500
    });

    const uniqueZips = [...new Set(requests.map((r) => r.zip).filter(Boolean))];
    const zipCoords = {};
    for (const zip of uniqueZips) {
      try {
        const geo = await geocodeAddress(`${zip}, USA`);
        if (geo) zipCoords[zip] = { lat: geo.lat, lon: geo.lon };
      } catch (_) { /* skip */ }
      await new Promise((r) => setTimeout(r, 1100));
    }

    const zipCountMap = {};
    requests.forEach((r) => { if (r.zip) zipCountMap[r.zip] = (zipCountMap[r.zip] || 0) + 1; });
    const heatPoints = Object.entries(zipCountMap)
      .filter(([zip]) => zipCoords[zip])
      .map(([zip, count]) => ({ zip, count, lat: zipCoords[zip].lat, lon: zipCoords[zip].lon }));

    res.json({ requests, heatPoints });
  } catch (err) {
    console.error('Territory leads failed', err);
    res.status(500).json({ error: 'Failed to load data' });
  }
});

app.delete('/api/admin/territory/leads/:id', async (req, res) => {
  if (!hasAdminAccess(req, ['main'])) return res.status(401).json({ error: 'Unauthorized' });
  try {
    await ensureWaitlistTable();
    await prisma.waitlistRequest.delete({ where: { id: req.params.id } });
    res.json({ ok: true });
  } catch (err) {
    console.error('Territory lead delete failed', err);
    res.status(500).json({ error: 'Could not delete.' });
  }
});

app.post('/api/job-notify', rateLimit, async (req, res) => {
  if (!EMAIL_ENABLED) return res.status(500).json({ error: 'Email not configured' });
  try {
    const { zip, name, email, phone, role, licensed, availability, timeline, experience, openToMultiple } = req.body || {};
    if (!zip || !email || !role) return res.status(400).json({ error: 'Missing zip, email, or role' });
    const zipMatch = String(zip || '').match(/\d{5}/);
    if (!zipMatch) return res.status(400).json({ error: 'Invalid ZIP code' });
    const safeZip = zipMatch[0];

    await ensureJobLeadTable();

    const geo = await geocodeAddress(`${safeZip}, USA`);
    if (!geo) return res.status(400).json({ error: 'Could not locate that ZIP code. Please check and try again.' });

    const allProviders = await prisma.$queryRawUnsafe(
      `SELECT id, email, "secondaryContactEmail", lat, lon, "serviceRadiusKm", "serviceZipCodes", "activelyHiring", "receiveJobLeads" FROM "Provider"`
    );

    const matchedProviders = allProviders.filter((p) => {
      if (p.activelyHiring === false) return false;
      if (p.receiveJobLeads === false) return false;
      const serviceZips = String(p.serviceZipCodes || '').split(',').map((z) => z.trim()).filter(Boolean);
      if (serviceZips.includes(safeZip)) return true;
      const radiusKm = Number(p.serviceRadiusKm) || 0;
      if (radiusKm <= 0) return false;
      return haversineKm(geo.lat, geo.lon, p.lat, p.lon) <= radiusKm;
    });

    const notifiedIds = matchedProviders.map((p) => p.id).join(',');
    await prisma.$executeRawUnsafe(
      `INSERT INTO "JobLead" ("id","zip","name","email","phone","role","licensed","availability","timeline","experience","openToMultiple","notifiedProviderIds","createdAt") VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,NOW())`,
      uuid(), safeZip,
      String(name || '').trim() || null,
      String(email || '').trim() || null,
      String(phone || '').trim() || null,
      String(role || '').trim() || null,
      String(licensed || '').trim() || null,
      String(availability || '').trim() || null,
      String(timeline || '').trim() || null,
      String(experience || '').trim() || null,
      String(openToMultiple || '').trim() || null,
      notifiedIds || null
    );

    for (const p of matchedProviders) {
      const recipientEmails = [String(p.email || '').trim(), String(p.secondaryContactEmail || '').trim()]
        .filter(Boolean)
        .filter((e, i, arr) => arr.indexOf(e) === i);
      if (!recipientEmails.length) continue;
      sendJobSeekerNotification({
        providerEmails: recipientEmails,
        candidateName: String(name || '').trim(),
        candidatePhone: String(phone || '').trim(),
        candidateEmail: String(email || '').trim(),
        zip: safeZip,
        role: String(role || '').trim(),
        licensed: String(licensed || '').trim(),
        availability: String(availability || '').trim(),
        timeline: String(timeline || '').trim(),
        experience: String(experience || '').trim(),
        openToMultiple: String(openToMultiple || '').trim()
      }).catch((err) => console.error('Job seeker notification failed for provider', p.id, err));
    }

    res.json({ ok: true, notifiedCount: matchedProviders.length });
  } catch (err) {
    console.error('Job notify failed', err);
    res.status(500).json({ error: 'Failed to process job seeker submission' });
  }
});

app.get('/api/admin/hiring/leads', async (req, res) => {
  if (!hasAdminAccess(req, ['main'])) return res.status(401).json({ error: 'Unauthorized' });
  try {
    await ensureJobLeadTable();
    const leads = await prisma.$queryRawUnsafe('SELECT * FROM "JobLead" ORDER BY "createdAt" DESC LIMIT 500');

    // Geocode unique ZIPs for heat map
    const uniqueZips = [...new Set((leads || []).map((l) => l.zip).filter(Boolean))];
    const zipCoords = {};
    for (const zip of uniqueZips) {
      try {
        const geo = await geocodeAddress(`${zip}, USA`);
        if (geo) zipCoords[zip] = { lat: geo.lat, lon: geo.lon };
      } catch (_) { /* skip */ }
      await new Promise((r) => setTimeout(r, 1100));
    }
    const zipCountMap = {};
    (leads || []).forEach((l) => { if (l.zip) zipCountMap[l.zip] = (zipCountMap[l.zip] || 0) + 1; });
    const heatPoints = Object.entries(zipCountMap)
      .filter(([zip]) => zipCoords[zip])
      .map(([zip, count]) => ({ zip, count, lat: zipCoords[zip].lat, lon: zipCoords[zip].lon }));

    // Build providers map for "View notified providers" feature
    const allProviderIds = new Set();
    (leads || []).forEach((l) => {
      String(l.notifiedProviderIds || '').split(',').map((s) => s.trim()).filter(Boolean).forEach((id) => allProviderIds.add(id));
    });
    let providersMap = {};
    if (allProviderIds.size) {
      const providerRows = await prisma.provider.findMany({
        where: { id: { in: [...allProviderIds] } },
        select: { id: true, name: true, email: true }
      });
      providerRows.forEach((p) => { providersMap[p.id] = { name: p.name, email: p.email }; });
    }

    res.json({ leads: leads || [], heatPoints, providers: providersMap });
  } catch (err) {
    console.error('Admin hiring leads failed', err);
    res.status(500).json({ error: 'Failed to load data' });
  }
});

app.delete('/api/admin/hiring/leads/:id', async (req, res) => {
  if (!hasAdminAccess(req, ['main'])) return res.status(401).json({ error: 'Unauthorized' });
  const id = String(req.params.id || '').trim();
  if (!id) return res.status(400).json({ error: 'Missing id' });
  try {
    await ensureJobLeadTable();
    await prisma.$executeRawUnsafe('DELETE FROM "JobLead" WHERE "id" = $1', id);
    res.json({ ok: true });
  } catch (err) {
    console.error('Admin hiring lead delete failed', err);
    res.status(500).json({ error: 'Failed to delete lead' });
  }
});

app.get('/api/provider/job-seekers', requireProviderAuth, async (req, res) => {
  try {
    const ctx = await getProviderContext(req.providerUserId);
    if (!ctx) return res.status(401).json({ error: 'Unauthorized' });
    await ensureJobLeadTable();
    const leads = await prisma.$queryRawUnsafe(
      `SELECT * FROM "JobLead" WHERE "notifiedProviderIds" LIKE $1 ORDER BY "createdAt" DESC LIMIT 100`,
      `%${ctx.providerId}%`
    );
    const hiringRows = await prisma.$queryRawUnsafe(
      `SELECT "activelyHiring" FROM "Provider" WHERE "id" = $1 LIMIT 1`,
      ctx.providerId
    );
    const activelyHiring = hiringRows[0]?.activelyHiring !== false;
    res.json({ leads: leads || [], activelyHiring });
  } catch (err) {
    console.error('Provider job seekers failed', err);
    res.status(500).json({ error: 'Failed to load job seeker data' });
  }
});

app.patch('/api/provider/actively-hiring', requireProviderAuth, async (req, res) => {
  try {
    const ctx = await getProviderContext(req.providerUserId);
    if (!ctx) return res.status(401).json({ error: 'Unauthorized' });
    await ensureJobLeadTable();
    const enabled = req.body?.enabled !== false;
    await prisma.$executeRawUnsafe(`UPDATE "Provider" SET "activelyHiring" = $1 WHERE "id" = $2`, enabled, ctx.providerId);
    res.json({ ok: true, activelyHiring: enabled });
  } catch (err) {
    console.error('Actively hiring toggle failed', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Provider self-service coverage. A lead matches on a service ZIP OR inside the
// radius, so at least one of the two must stay active or the provider gets nothing.
const PROVIDER_MAX_RADIUS_MILES = 200;
const PROVIDER_MAX_SERVICE_ZIPS = 300;

app.patch('/api/provider/coverage', requireProviderAuth, async (req, res) => {
  try {
    const ctx = await getProviderContext(req.providerUserId);
    if (!ctx) return res.status(401).json({ error: 'Unauthorized' });

    const mode = String(req.body?.mode || '').trim().toLowerCase();
    if (!['radius', 'zips', 'both'].includes(mode)) {
      return res.status(400).json({ error: 'mode must be radius, zips, or both' });
    }

    const wantsRadius = mode === 'radius' || mode === 'both';
    const wantsZips = mode === 'zips' || mode === 'both';

    let radiusKm = 0;
    if (wantsRadius) {
      const miles = Number(req.body?.radiusMiles);
      if (!Number.isFinite(miles) || miles <= 0) {
        return res.status(400).json({ error: 'Enter a radius greater than 0 miles.' });
      }
      if (miles > PROVIDER_MAX_RADIUS_MILES) {
        return res.status(400).json({ error: `Radius cannot exceed ${PROVIDER_MAX_RADIUS_MILES} miles.` });
      }
      radiusKm = miles * 1.60934;
    }

    let zipStorage = null;
    if (wantsZips) {
      const zips = normalizeZipCodeList(req.body?.zipCodes);
      if (!zips.length) {
        return res.status(400).json({ error: 'Enter at least one valid 5-digit ZIP code.' });
      }
      if (zips.length > PROVIDER_MAX_SERVICE_ZIPS) {
        return res.status(400).json({ error: `Enter at most ${PROVIDER_MAX_SERVICE_ZIPS} ZIP codes.` });
      }
      zipStorage = zips.join(',');
    }

    if (!radiusKm && !zipStorage) {
      return res.status(400).json({ error: 'Keep either a radius or ZIP codes active, or you will stop receiving leads.' });
    }

    const updated = await prisma.provider.update({
      where: { id: ctx.providerId },
      data: { serviceRadiusKm: radiusKm, serviceZipCodes: zipStorage },
      select: { serviceRadiusKm: true, serviceZipCodes: true }
    });

    await logAdminAction(
      'provider_user',
      'PROVIDER_COVERAGE_UPDATE',
      ctx.providerId,
      { mode, serviceRadiusKm: updated.serviceRadiusKm, serviceZipCodes: updated.serviceZipCodes },
      hashIp(req.ip || '')
    );

    res.json({
      ok: true,
      serviceRadiusKm: updated.serviceRadiusKm,
      serviceZipCodes: updated.serviceZipCodes
    });
  } catch (err) {
    console.error('Provider coverage update failed', err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.delete('/api/admin/main/website-events', async (req, res) => {
  if (!hasAdminAccess(req, ['main'])) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  const confirmation = String(req.body?.confirmation || '').trim();
  if (confirmation !== 'CLEAR_WEBSITE_EVENTS') {
    return res.status(400).json({ error: 'Confirmation phrase required.' });
  }
  try {
    await ensureWebsiteEventsTable();
    const deletedCount = await prisma.$executeRawUnsafe('DELETE FROM website_events');
    res.json({ ok: true, deletedCount: Number(deletedCount || 0) });
  } catch (err) {
    console.error('Admin website-events clear failed', err);
    res.status(500).json({ error: 'Failed to clear website analytics data' });
  }
});

app.delete('/api/admin/main/leads/:id', async (req, res) => {
  if (!hasAdminAccess(req, ['main'])) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  const leadId = String(req.params.id || '').trim();
  if (!leadId) {
    return res.status(400).json({ error: 'Missing lead id' });
  }
  try {
    const lead = await prisma.lead.findUnique({ where: { id: leadId }, select: { id: true } });
    if (!lead) return res.status(404).json({ error: 'Lead not found' });

    await prisma.$transaction([
      prisma.notificationJob.deleteMany({ where: { leadId } }),
      prisma.leadOutcomeEvent.deleteMany({ where: { leadOutcome: { leadId } } }),
      prisma.leadOutcome.deleteMany({ where: { leadId } }),
      prisma.providerImpression.deleteMany({ where: { leadId } }),
      prisma.leadNotification.deleteMany({ where: { leadId } }),
      prisma.lead.delete({ where: { id: leadId } })
    ]);

    await prisma.provider.updateMany({ data: { leadCount: 0 } });
    const grouped = await prisma.leadNotification.groupBy({
      by: ['providerId'],
      where: { status: 'sent' },
      _count: { _all: true }
    });
    for (const row of grouped) {
      await prisma.provider.update({
        where: { id: row.providerId },
        data: { leadCount: row._count._all || 0 }
      });
    }

    res.json({ ok: true, deletedLeadId: leadId });
  } catch (err) {
    console.error('Admin lead delete failed', err);
    res.status(500).json({ error: 'Failed to delete lead' });
  }
});

// GET /api/admin/main/leads-all — all leads with name, zip, date, admin status, and notified providers
app.get('/api/admin/main/leads-all', async (req, res) => {
  if (!hasAdminAccess(req, ['main'])) return res.status(401).json({ error: 'Unauthorized' });
  try {
    await ensureLeadAdminStatusColumns();
    const [leads, providers] = await Promise.all([
      prisma.$queryRawUnsafe(`
        SELECT l.id, l."firstName", l."lastName", l.zip, l."clientEmail", l."createdAt",
               l."adminStatus", l."adminProviderId"
        FROM "Lead" l
        ORDER BY l."createdAt" DESC
      `),
      prisma.provider.findMany({ select: { id: true, name: true, state: true }, orderBy: [{ state: 'asc' }, { name: 'asc' }] })
    ]);
    res.json({ leads, providers });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// PATCH /api/admin/main/leads/:id/admin-status — set adminStatus and optional adminProviderId
app.patch('/api/admin/main/leads/:id/admin-status', async (req, res) => {
  if (!hasAdminAccess(req, ['main'])) return res.status(401).json({ error: 'Unauthorized' });
  const leadId = String(req.params.id || '').trim();
  const { status, providerId } = req.body || {};
  const allowed = ['admitted', 'no_update', 'bad_lead', null];
  if (!allowed.includes(status)) return res.status(400).json({ error: 'Invalid status' });
  try {
    await ensureLeadAdminStatusColumns();
    await prisma.$executeRawUnsafe(
      `UPDATE "Lead" SET "adminStatus" = $1, "adminProviderId" = $2 WHERE id = $3`,
      status, status === 'admitted' ? (providerId || null) : null, leadId
    );
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Blog: email verification start
app.post('/api/blog/verify/start', async (req, res) => {
  try {
    const { email, city, state, captchaToken } = req.body || {};
    const normEmail = normalizeEmail(email);
    const normCity = normalizeCityState(city);
    const normState = normalizeCityState(state);
    if (!normEmail || !normCity || !normState) {
      return res.status(400).json({ error: 'Email, city, and state are required' });
    }
    const captchaResult = await verifyTurnstile(captchaToken, req.ip);
    if (!captchaResult.success) {
      return res.status(403).json({ error: 'Captcha verification failed.', details: captchaResult['error-codes'] || captchaResult.error });
    }
    const code = generateCode();
    const expiresAt = new Date(Date.now() + 30 * 60 * 1000);
    await prisma.blogEmailVerification.create({
      data: { id: uuid(), email: normEmail, city: normCity, state: normState, code, expiresAt }
    });
    const html = `
      <div style="font-family: Arial, sans-serif; line-height:1.5; color:#111">
        <p>Your Best Hospice and Home Health verification code:</p>
        <p style="font-size:22px; font-weight:800; letter-spacing:2px;">${code}</p>
        <p>Enter this code to create a blog post or comment. Codes expire in 30 minutes.</p>
      </div>
    `;
    await sendGenericEmail(normEmail, 'Best Hospice and Home Health verification code', html);
    res.json({ ok: true, message: 'Verification code sent.' });
  } catch (err) {
    console.error('Blog verify start failed', err);
    res.status(500).json({ error: 'Failed to send verification code' });
  }
});

// Blog: email verification confirm
app.post('/api/blog/verify/confirm', async (req, res) => {
  try {
    const { email, city, state, code } = req.body || {};
    const normEmail = normalizeEmail(email);
    const normCity = normalizeCityState(city);
    const normState = normalizeCityState(state);
    const normCode = String(code || '').trim();
    if (!normEmail || !normCity || !normState || !normCode) {
      return res.status(400).json({ error: 'Email, city, state, and code are required' });
    }
    const record = await prisma.blogEmailVerification.findFirst({
      where: {
        email: normEmail,
        city: normCity,
        state: normState,
        code: normCode,
        expiresAt: { gte: new Date() }
      },
      orderBy: { createdAt: 'desc' }
    });
    if (!record) return res.status(400).json({ error: 'Invalid or expired code' });
    await prisma.blogEmailVerification.update({
      where: { id: record.id },
      data: { verifiedAt: new Date() }
    });
    res.json({ ok: true, message: 'Email verified.' });
  } catch (err) {
    console.error('Blog verify confirm failed', err);
    res.status(500).json({ error: 'Verification failed' });
  }
});

// Blog: list posts with comment counts
app.get('/api/blog/posts', async (_req, res) => {
  try {
    const posts = await prisma.blogPost.findMany({
      orderBy: { createdAt: 'desc' },
      take: 50,
      include: { comments: true }
    });
    const data = posts.map((p) => ({
      id: p.id,
      title: p.title,
      body: p.body,
      authorCity: p.authorCity,
      authorState: p.authorState,
      createdAt: p.createdAt,
      commentCount: p.comments.length,
      comments: p.comments.map((c) => ({
        id: c.id,
        body: c.body,
        authorCity: c.authorCity,
        authorState: c.authorState,
        createdAt: c.createdAt,
        authorEmail: c.authorEmail
      }))
    }));
    res.json({ ok: true, posts: data });
  } catch (err) {
    console.error('Blog list failed', err);
    res.status(500).json({ error: 'Failed to load posts' });
  }
});

// Blog: create post
app.post('/api/blog/posts', async (req, res) => {
  try {
    const { title, body, email, city, state, captchaToken } = req.body || {};
    if (!title || !body) return res.status(400).json({ error: 'Title and body are required' });
    const normEmail = normalizeEmail(email);
    const normCity = normalizeCityState(city);
    const normState = normalizeCityState(state);
    if (!normEmail || !normCity || !normState) {
      return res.status(400).json({ error: 'Email, city, and state are required' });
    }
    const captchaResult = await verifyTurnstile(captchaToken, req.ip);
    if (!captchaResult.success) {
      return res.status(403).json({ error: 'Captcha verification failed.', details: captchaResult['error-codes'] || captchaResult.error });
    }
    const verified = await isEmailVerifiedForBlog(normEmail, normCity, normState);
    if (!verified) return res.status(403).json({ error: 'Email not verified for posting' });
    const post = await prisma.blogPost.create({
      data: {
        id: uuid(),
        title: String(title).trim(),
        body: String(body).trim(),
        authorEmail: normEmail,
        authorCity: normCity,
        authorState: normState
      }
    });
    res.json({ ok: true, postId: post.id });
  } catch (err) {
    console.error('Blog post create failed', err);
    res.status(500).json({ error: 'Failed to create post' });
  }
});

// Blog: create comment
app.post('/api/blog/posts/:id/comments', async (req, res) => {
  try {
    const { body, email, city, state, captchaToken } = req.body || {};
    if (!body) return res.status(400).json({ error: 'Comment is required' });
    const normEmail = normalizeEmail(email);
    const normCity = normalizeCityState(city);
    const normState = normalizeCityState(state);
    if (!normEmail || !normCity || !normState) {
      return res.status(400).json({ error: 'Email, city, and state are required' });
    }
    const captchaResult = await verifyTurnstile(captchaToken, req.ip);
    if (!captchaResult.success) {
      return res.status(403).json({ error: 'Captcha verification failed.', details: captchaResult['error-codes'] || captchaResult.error });
    }
    const verified = await isEmailVerifiedForBlog(normEmail, normCity, normState);
    if (!verified) return res.status(403).json({ error: 'Email not verified for commenting' });
    const postId = req.params.id;
    const comment = await prisma.blogComment.create({
      data: {
        id: uuid(),
        postId,
        body: String(body).trim(),
        authorEmail: normEmail,
        authorCity: normCity,
        authorState: normState
      }
    });
    res.json({ ok: true, commentId: comment.id });
  } catch (err) {
    console.error('Blog comment failed', err);
    res.status(500).json({ error: 'Failed to add comment' });
  }
});

// Admin: delete blog comment
app.delete('/api/admin/blog/comments/:id', async (req, res) => {
  const token = req.headers['x-admin-token'];
  const adminIdentifier = getAdminSession(req)
    ? 'admin_session'
    : token === ADMIN_TOKEN_DASH
      ? 'dash_token'
      : token === ADMIN_TOKEN_AUDIT
        ? 'audit_token'
        : 'unknown';
  if (!hasAdminAccess(req, ['dash', 'audit'])) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  const commentId = req.params.id;
  try {
    const existing = await prisma.blogComment.findUnique({ where: { id: commentId } });
    if (!existing) {
      return res.status(404).json({ error: 'Comment not found' });
    }
    await prisma.blogComment.delete({ where: { id: commentId } });
    await logAdminAction(adminIdentifier, 'BLOG_COMMENT_DELETE', commentId, { postId: existing.postId }, hashIp(req.ip || ''));
    res.json({ ok: true });
  } catch (err) {
    console.error('Admin comment delete failed', err);
    res.status(500).json({ error: 'Failed to delete comment' });
  }
});

// Admin: delete blog post (and comments)
app.delete('/api/admin/blog/posts/:id', async (req, res) => {
  const token = req.headers['x-admin-token'];
  const adminIdentifier = getAdminSession(req)
    ? 'admin_session'
    : token === ADMIN_TOKEN_DASH
      ? 'dash_token'
      : token === ADMIN_TOKEN_AUDIT
        ? 'audit_token'
        : 'unknown';
  if (!hasAdminAccess(req, ['dash', 'audit'])) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  const postId = req.params.id;
  try {
    const existing = await prisma.blogPost.findUnique({ where: { id: postId } });
    if (!existing) {
      return res.status(404).json({ error: 'Post not found' });
    }
    await prisma.$transaction([
      prisma.blogComment.deleteMany({ where: { postId } }),
      prisma.blogPost.delete({ where: { id: postId } })
    ]);
    await logAdminAction(adminIdentifier, 'BLOG_POST_DELETE', postId, { title: existing.title }, hashIp(req.ip || ''));
    res.json({ ok: true });
  } catch (err) {
    console.error('Admin blog delete failed', err);
    res.status(500).json({ error: 'Failed to delete post' });
  }
});

app.get('/api/admin/audit', async (req, res) => {
  if (!hasAdminAccess(req, ['audit'])) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  const logs = await prisma.adminAuditLog.findMany({
    orderBy: { createdAt: 'desc' },
    take: 200
  });
  res.json(logs);
});

// Admin: provider lead details
app.get('/api/admin/providers/:id/leads', async (req, res) => {
  if (!hasAdminAccess(req, ['dash', 'audit'])) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  const providerId = req.params.id;
  const limit = Math.min(parseInt(req.query.limit || '25', 10), 200);
  try {
    const notifs = await prisma.leadNotification.findMany({
      where: { providerId },
      orderBy: { createdAt: 'desc' },
      take: limit,
      select: {
        createdAt: true,
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
    });
    const leads = notifs.map((n) => ({
      leadId: n.lead?.id || '',
      createdAt: n.lead?.createdAt || n.createdAt,
      zip: n.lead?.zip || '',
      submittedBy: n.lead?.submittedBy || '',
      clientEmail: n.lead?.clientEmail || '',
      clientPhone: n.lead?.clientPhone || '',
      clientName: buildClientName(n.lead?.firstName, n.lead?.lastName)
    }));
    res.json({ ok: true, leads });
  } catch (err) {
    console.error('Admin provider leads failed', err);
    res.status(500).json({ error: 'Failed to load provider leads' });
  }
});

app.post('/api/test-email', async (req, res) => {
  if (!hasAdminAccess(req, ['main'])) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
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
app.post('/api/provider-auth/signup-start', authRateLimit, async (req, res) => {
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
          <p>You requested access to the Best Hospice and Home Health Provider Dashboard for <strong>${provider.name}</strong>.</p>
          <p>Please copy this one-time code and paste it in the dashboard to finish creating your password:</p>
          <p style="font-size:22px; font-weight:800; letter-spacing:2px;">${code}</p>
          <p>Open: <a href="${DASHBOARD_VERIFY_URL}">${DASHBOARD_VERIFY_URL}</a> and use the code above. Codes expire in 48 hours.</p>
        </div>
      `;
      await sendGenericEmail(normEmail, 'Finish setting up your Best Hospice and Home Health dashboard', html);
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
app.post('/api/provider-auth/complete', authRateLimit, async (req, res) => {
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
app.post('/api/provider-auth/login', authRateLimit, async (req, res) => {
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

// Public provider data for search results page
app.get('/api/search/providers', async (_req, res) => {
  try {
    const providers = await prisma.provider.findMany({
      orderBy: { name: 'asc' },
      select: {
        id: true, name: true, email: true, phone: true, website: true,
        address: true, city: true, state: true, zip: true,
        lat: true, lon: true, serviceRadiusKm: true,
        serviceZipCodes: true, planTier: true, careType: true
      }
    });
    res.json({ providers });
  } catch (err) {
    res.status(500).json({ error: 'Failed to load providers' });
  }
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

    const distinctLeadRows = await prisma.leadNotification.findMany({
      where: { providerId: ctx.providerId, createdAt: { gte: since } },
      distinct: ['leadId'],
      orderBy: { createdAt: 'desc' },
      select: { leadId: true }
    });
    const allLeadIds = distinctLeadRows.map((r) => r.leadId).filter(Boolean);
    const total = allLeadIds.length;
    const leadIds = allLeadIds.slice(skip, skip + limit);

    const leadRows = leadIds.length
      ? await prisma.lead.findMany({
          where: { id: { in: leadIds } },
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
        })
      : [];
    const leadById = new Map(leadRows.map((l) => [l.id, l]));
    const outcomes = leadIds.length
      ? await prisma.leadOutcome.findMany({
          where: { providerId: ctx.providerId, leadId: { in: leadIds } },
          select: { leadId: true, status: true, firstResponseAt: true, lastStatusChangedAt: true }
        })
      : [];
    const outcomeByLeadId = new Map(outcomes.map((o) => [o.leadId, o]));

    const leads = leadIds.map((id) => leadById.get(id)).filter(Boolean).map((l) => {
      const outcome = outcomeByLeadId.get(l.id);
      const status = normalizeLeadOutcomeStatus(outcome?.status) || 'new';
      return {
        leadId: l.id,
        createdAt: l.createdAt,
        zip: l.zip,
        submittedBy: l.submittedBy,
        clientEmail: l.clientEmail || '',
        clientPhone: l.clientPhone || '',
        clientName: [l.firstName, l.lastName].filter(Boolean).join(' ').trim(),
        outcomeStatus: status,
        outcomeStatusLabel: leadOutcomeLabel(status),
        outcomeUpdatedAt: outcome?.lastStatusChangedAt || l.createdAt,
        firstResponseAt: outcome?.firstResponseAt || null
      };
    });
    await logAdminAction('provider_user', 'PROVIDER_AI_LEAD_LIST', ctx.providerId, { since: since.toISOString(), returned: leads.length }, hashIp(req.ip || ''));
    res.json({ ok: true, since: since.toISOString().split('T')[0], leads, total, page, pageSize: limit });
  } catch (err) {
    console.error('Lead list failed', err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.patch('/api/provider/leads/:leadId/status', requireProviderAuth, async (req, res) => {
  try {
    const ctx = await getProviderContext(req.providerUserId);
    if (!ctx) return res.status(401).json({ error: 'Unauthorized' });
    const leadId = String(req.params.leadId || '').trim();
    const nextStatus = normalizeLeadOutcomeStatus(req.body?.status);
    if (!leadId) return res.status(400).json({ error: 'leadId required' });
    if (!nextStatus) return res.status(400).json({ error: 'Invalid status' });

    const notification = await prisma.leadNotification.findFirst({
      where: { providerId: ctx.providerId, leadId },
      select: { id: true }
    });
    if (!notification) return res.status(404).json({ error: 'Lead not found for this provider' });

    const updated = await upsertLeadOutcomeStatus({
      leadId,
      providerId: ctx.providerId,
      nextStatus,
      changedBy: 'provider_dashboard'
    });

    await logAdminAction(
      'provider_user',
      'PROVIDER_LEAD_STATUS_UPDATE',
      ctx.providerId,
      { leadId, status: nextStatus },
      hashIp(req.ip || '')
    );

    res.json({
      ok: true,
      leadId,
      status: normalizeLeadOutcomeStatus(updated.status) || 'new',
      statusLabel: leadOutcomeLabel(updated.status),
      updatedAt: updated.lastStatusChangedAt,
      firstResponseAt: updated.firstResponseAt || null
    });
  } catch (err) {
    console.error('Provider lead status update failed', err);
    res.status(500).json({ error: 'Could not update lead status' });
  }
});

app.get('/api/provider/lead-status/quick', async (req, res) => {
  const token = String(req.query.token || '').trim();
  if (!token) return res.status(400).send('Missing token.');

  try {
    const payload = jwt.verify(token, LEAD_STATUS_SIGNING_SECRET);
    if (!payload || payload.type !== 'lead_status_action') {
      return res.status(400).send('Invalid token.');
    }
    const leadId = String(payload.leadId || '').trim();
    const providerId = String(payload.providerId || '').trim();
    const nextStatus = normalizeLeadOutcomeStatus(payload.status);
    if (!leadId || !providerId || !nextStatus) {
      return res.status(400).send('Invalid status action.');
    }

    const notification = await prisma.leadNotification.findFirst({
      where: { leadId, providerId },
      select: { id: true }
    });
    if (!notification) {
      return res.status(404).send('Lead was not found for this provider.');
    }

    const updated = await upsertLeadOutcomeStatus({
      leadId,
      providerId,
      nextStatus,
      changedBy: 'email_quick_link'
    });

    const statusText = leadOutcomeLabel(updated.status);
    res.set('Content-Type', 'text/html; charset=utf-8');
    return res.send(`
      <!doctype html>
      <html lang="en">
      <head><meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/></head>
      <body style="font-family:Arial,sans-serif;padding:24px;color:#0f172a;">
        <h2 style="margin:0 0 10px;">Lead status updated</h2>
        <p style="margin:0 0 12px;">This lead is now marked as <strong>${statusText}</strong>.</p>
        <p style="margin:0 0 18px;">You can continue managing lead updates in your provider dashboard.</p>
        <a href="${CANONICAL_DOMAIN}/provider-dashboard-home.html" style="display:inline-block;padding:10px 14px;border-radius:10px;background:#0f766e;color:#fff;text-decoration:none;font-weight:700;">Open Provider Dashboard</a>
      </body>
      </html>
    `);
  } catch (err) {
    return res.status(400).send('Link expired or invalid.');
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

// Provider spend since date, priced from the provider's plan tier
app.get('/api/provider/spend', requireProviderAuth, async (req, res) => {
  try {
    const sinceParam = req.query.since;
    const since = sinceParam ? new Date(String(sinceParam)) : null;
    if (!since || isNaN(since.getTime())) return res.status(400).json({ error: 'Invalid since date' });
    const ctx = await getProviderContext(req.providerUserId);
    if (!ctx) return res.status(401).json({ error: 'Unauthorized' });
    const today = new Date();
    const diffDays = Math.max(0, (today - since) / (1000 * 60 * 60 * 24));
    const months = Math.max(1, Math.ceil(diffDays / 30));
    const monthlyRate = providerRateForTier(ctx.provider?.planTier);
    const totalSpend = months * monthlyRate;
    res.json({
      ok: true,
      since: since.toISOString().split('T')[0],
      monthlyRate,
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
    await ensureProviderStripeColumns();
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
    // The Stripe columns are added by raw SQL, so the typed client cannot see them.
    const subRows = await prisma.$queryRaw`
      SELECT "subscriptionStatus", "currentPeriodEnd", "stripeSubscriptionId"
      FROM "Provider" WHERE "id" = ${providerId} LIMIT 1
    `;
    const subRow = subRows?.[0] || {};
    const subscriptionStatus = subRow.subscriptionStatus || null;

    res.json({
      ok: true,
      provider: {
        id: ctx.provider.id,
        name: ctx.provider.name,
        email: ctx.provider.email,
        planTier: ctx.provider.planTier || 'verified',
        serviceRadiusKm: ctx.provider.serviceRadiusKm || 0,
        serviceZipCodes: ctx.provider.serviceZipCodes || null
      },
      subscription: {
        status: subscriptionStatus,
        state: subscriptionBannerState(subscriptionStatus),
        currentPeriodEnd: subRow.currentPeriodEnd || null,
        hasSubscription: Boolean(subRow.stripeSubscriptionId)
      },
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
    const enteredMonthly = Number.parseInt(String(req.body?.monthlySubscription || ''), 10);
    let planTier = 'verified';
    if (enteredMonthly === 375) planTier = 'featured';
    else if (enteredMonthly === 500) planTier = 'priority';
    else if (enteredMonthly === 250) planTier = 'verified';
    else planTier = 'verified';
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
// ---------- Abel AI Chat (Claude-powered) ----------

const ABEL_PROVIDER_TOOLS = [
  {
    name: 'get_lead_count',
    description: 'Get the number of leads for this provider, optionally since a specific date.',
    input_schema: {
      type: 'object',
      properties: {
        since_date: { type: 'string', description: 'ISO date (YYYY-MM-DD). Omit for all-time count.' }
      },
      required: []
    }
  },
  {
    name: 'get_lead_list',
    description: 'Get a list of recent leads for this provider.',
    input_schema: {
      type: 'object',
      properties: {
        since_date: { type: 'string', description: 'ISO date (YYYY-MM-DD). Defaults to 30 days ago.' },
        limit: { type: 'number', description: 'Max leads to return. Defaults to 20, max 50.' }
      },
      required: []
    }
  },
  {
    name: 'get_metrics',
    description: 'Get performance metrics: impressions, emails sent, and leads generated for a date range.',
    input_schema: {
      type: 'object',
      properties: {
        start_date: { type: 'string', description: 'Start date (YYYY-MM-DD). Defaults to 30 days ago.' },
        end_date: { type: 'string', description: 'End date (YYYY-MM-DD). Defaults to today.' }
      },
      required: []
    }
  },
  {
    name: 'get_spend_estimate',
    description: 'Get estimated subscription spend on Best Hospice and Home Health since a date.',
    input_schema: {
      type: 'object',
      properties: {
        since_date: { type: 'string', description: 'ISO date. Defaults to 30 days ago.' }
      },
      required: []
    }
  },
  {
    name: 'get_revenue_estimate',
    description: 'Estimate revenue and ROI. Ask the provider for their own numbers first; every parameter is optional and falls back to a stated default.',
    input_schema: {
      type: 'object',
      properties: {
        revenue_per_client_per_month: { type: 'number', description: 'What one admitted client is worth per month to this provider.' },
        months_per_client: { type: 'number', description: 'Average months a client stays on service.' },
        converted_clients: { type: 'number', description: 'How many of the leads sent actually became clients. Defaults to admin-confirmed admissions.' }
      },
      required: []
    }
  },
  {
    name: 'get_account_info',
    description: 'Get the provider account info: name, email, plan status, provider ID.',
    input_schema: { type: 'object', properties: {}, required: [] }
  }
];

async function executeAbelTool(toolName, toolInput, providerCtx) {
  const providerId = providerCtx.providerId;
  const iso = (d) => d.toISOString().split('T')[0];
  const parseDate = (str, defaultDaysAgo = 30) => {
    if (!str) return new Date(Date.now() - defaultDaysAgo * 24 * 60 * 60 * 1000);
    const d = new Date(str);
    return isNaN(d.getTime()) ? new Date(Date.now() - defaultDaysAgo * 24 * 60 * 60 * 1000) : d;
  };

  const leadCountSince = async (sinceDate) => {
    const notifs = await prisma.leadNotification.findMany({
      where: { providerId, createdAt: { gte: sinceDate } },
      select: { leadId: true }
    });
    return new Set(notifs.map((n) => n.leadId)).size;
  };
  const leadCountAll = async () => {
    const notifs = await prisma.leadNotification.findMany({ where: { providerId }, select: { leadId: true } });
    return new Set(notifs.map((n) => n.leadId)).size;
  };
  const leadListSince = async (sinceDate, limit = 20) => {
    const notifs = await prisma.leadNotification.findMany({
      where: { providerId, createdAt: { gte: sinceDate } },
      orderBy: { createdAt: 'desc' },
      take: Math.min(limit, 50),
      select: { lead: { select: { id: true, createdAt: true, zip: true, submittedBy: true } } }
    });
    return notifs.map((n) => n.lead).filter(Boolean)
      .map((l) => ({ leadId: l.id, createdAt: l.createdAt, zip: l.zip, submittedBy: l.submittedBy }));
  };
  const metricsRange = async (start, end) => {
    const [impressions, emailsSent, leadNotifications] = await Promise.all([
      prisma.providerImpression.count({ where: { providerId, createdAt: { gte: start, lte: end } } }),
      prisma.leadNotification.count({ where: { providerId, status: 'sent', createdAt: { gte: start, lte: end } } }),
      prisma.leadNotification.findMany({ where: { providerId, createdAt: { gte: start, lte: end } }, select: { leadId: true } })
    ]);
    return { impressions, emailsSent, leadsGenerated: new Set(leadNotifications.map((n) => n.leadId)).size };
  };
  const spendSince = async (sinceDate) => {
    const diffDays = Math.max(0, (Date.now() - sinceDate.getTime()) / (1000 * 60 * 60 * 24));
    const months = Math.max(1, Math.ceil(diffDays / 30));
    const monthlyRate = await providerRateById(providerId);
    return { monthlyRate, months, totalSpend: months * monthlyRate };
  };

  switch (toolName) {
    case 'get_lead_count': {
      const countAll = await leadCountAll();
      if (toolInput.since_date) {
        const sinceDate = parseDate(toolInput.since_date);
        const countSince = await leadCountSince(sinceDate);
        return `Leads since ${toolInput.since_date}: ${countSince}. All-time leads: ${countAll}.`;
      }
      return `All-time leads: ${countAll}.`;
    }
    case 'get_lead_list': {
      const sinceDate = parseDate(toolInput.since_date, 30);
      const leads = await leadListSince(sinceDate, toolInput.limit || 20);
      return JSON.stringify({ since: iso(sinceDate), count: leads.length, leads });
    }
    case 'get_metrics': {
      const start = parseDate(toolInput.start_date, 30);
      const end = toolInput.end_date ? new Date(toolInput.end_date) : new Date();
      const m = await metricsRange(start, end);
      return `From ${iso(start)} to ${iso(end)}: Impressions: ${m.impressions}, Emails sent: ${m.emailsSent}, Leads generated: ${m.leadsGenerated}.`;
    }
    case 'get_spend_estimate': {
      const sinceDate = parseDate(toolInput.since_date, 30);
      const spend = await spendSince(sinceDate);
      return `Estimated spend since ${iso(sinceDate)}: $${spend.totalSpend.toLocaleString()} ($${spend.monthlyRate}/month × ${spend.months} months).`;
    }
    case 'get_revenue_estimate': {
      const countAll = await leadCountAll();
      const admits = await providerAdmittedCount(providerId);

      const perMonthRaw = Number(toolInput?.revenue_per_client_per_month);
      const monthsRaw = Number(toolInput?.months_per_client);
      const convertedRaw = Number(toolInput?.converted_clients);

      const perMonthGiven = Number.isFinite(perMonthRaw) && perMonthRaw > 0;
      const monthsGiven = Number.isFinite(monthsRaw) && monthsRaw > 0;
      const convertedGiven = Number.isFinite(convertedRaw) && convertedRaw >= 0;

      const perMonth = perMonthGiven ? perMonthRaw : DEFAULT_REVENUE_PER_CLIENT_MONTH;
      const months = monthsGiven ? monthsRaw : DEFAULT_MONTHS_PER_CLIENT;
      const converted = convertedGiven ? convertedRaw : admits;
      const clientValue = perMonth * months;

      const estimatedRevenue = converted * clientValue;
      const potentialRevenue = countAll * clientValue;
      const firstNotif = await prisma.leadNotification.findFirst({
        where: { providerId }, orderBy: { createdAt: 'asc' }, select: { createdAt: true }
      });
      const sinceDate = firstNotif?.createdAt ? new Date(firstNotif.createdAt) : new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
      const spend = await spendSince(sinceDate);
      const net = estimatedRevenue - spend.totalSpend;

      const assumed = [];
      if (!perMonthGiven) assumed.push(`revenue per client per month ($${perMonth.toLocaleString()})`);
      if (!monthsGiven) assumed.push(`average months per client (${months})`);
      if (!convertedGiven) assumed.push(`converted clients (${converted}, from admin-confirmed admissions)`);

      return JSON.stringify({
        leadsSent: countAll,
        confirmedAdmissions: admits,
        convertedClientsUsed: converted,
        revenuePerClientPerMonth: perMonth,
        monthsPerClient: months,
        valuePerClient: clientValue,
        estimatedRevenue,
        potentialRevenueIfAllConverted: potentialRevenue,
        monthlySubscription: spend.monthlyRate,
        monthsBilled: spend.months,
        estimatedSpend: spend.totalSpend,
        estimatedNet: net,
        assumedDefaultsFor: assumed,
        note: assumed.length
          ? 'Tell the provider which figures were assumed and offer to recalculate with their own numbers.'
          : 'All figures came from the provider.'
      });
    }
    case 'get_account_info': {
      return JSON.stringify({
        providerId: providerCtx.providerId,
        providerName: providerCtx.provider?.name || '',
        providerEmail: providerCtx.provider?.email || '',
        planStatus: providerCtx.provider?.planStatus || 'active'
      });
    }
    default:
      return 'Unknown tool.';
  }
}

async function handleAbelWithClaude(req, res) {
  const { message, turnstileToken, history = [] } = req.body || {};
  const text = String(message || '').trim();

  if (maybePhi(text)) {
    return res.json({
      reply: "Please don't share private medical details here. Best Hospice and Home Health connects you with licensed providers who can handle that information securely.",
      navigateTo: null,
      navigateLabel: null
    });
  }

  // Only JWT validation can set provider_authed — never keyword guessing
  let providerCtx = null;
  const auth = req.headers['authorization'];
  if (auth && auth.toLowerCase().startsWith('bearer ')) {
    try {
      const payload = jwt.verify(auth.slice(7), PROVIDER_JWT_SECRET);
      providerCtx = await getProviderContext(payload.sub);
    } catch (_err) { /* invalid token — treat as client */ }
  }

  let mode = providerCtx ? 'provider_authed' : 'client';

  // If the user has identified as a provider in this conversation, shift context even without a JWT
  if (mode === 'client') {
    const allText = (Array.isArray(history) ? history : []).map((m) => String(m.content || '')).join(' ') + ' ' + text;
    if (/\b(i am a provider|i'?m a provider|im a provider|we are a provider|we'?re a provider|i run a hospice|i own a hospice|my agency|our agency|my hospice|our hospice|i represent a|we represent a)\b/i.test(allText)) {
      mode = 'provider_public';
    }
  }

  if (mode === 'client' && !TURNSTILE_BYPASS && TURNSTILE_SECRET_KEY) {
    const captcha = await verifyTurnstile(turnstileToken, req.ip);
    if (!captcha.success) return res.status(403).json({ error: 'Captcha verification failed.' });
  }

  // IP rate limit — skip for authenticated providers (paying customers)
  if (mode !== 'provider_authed') {
    const ipHash = hashIp(req.ip || '');
    if (!checkChatRateLimit(ipHash)) {
      return res.status(429).json({ error: 'Too many messages. Please try again in an hour.' });
    }
  }

  const NAV_INSTRUCTION = `
NAVIGATION: When your response would benefit from sending the user to a specific page, append exactly one line at the very end in this format (nothing after it):
[NAVIGATE:/path/here|Friendly button label]

Available pages and when to use them:
- [NAVIGATE:/index.html|Start the questionnaire] — finding providers, starting a search, entering a ZIP code
- [NAVIGATE:/provider-dashboard.html|Provider login] — provider login, signing in, creating a provider account
- [NAVIGATE:/education.html|Learn about care options] — general education about care types
- [NAVIGATE:/why.html|About Best Hospice] — about the platform, mission, how it works
- [NAVIGATE:/contact.html|Contact us] — contact, questions for the team
- [NAVIGATE:/locations.html|View all locations] — what states/cities are covered
- [NAVIGATE:/faq-blog.html|FAQ & Blog] — frequently asked questions, blog posts
State pages (use when user asks about a specific state):
- [NAVIGATE:/states/arizona.html|Hospice providers in Arizona]
- [NAVIGATE:/states/texas.html|Hospice providers in Texas]
- [NAVIGATE:/states/california.html|Hospice providers in California]
- [NAVIGATE:/states/georgia.html|Hospice providers in Georgia]
- [NAVIGATE:/states/alabama.html|Hospice providers in Alabama]
- [NAVIGATE:/states/colorado.html|Hospice providers in Colorado]
- [NAVIGATE:/states/maryland.html|Hospice providers in Maryland]
- [NAVIGATE:/states/new-jersey.html|Hospice providers in New Jersey]
- [NAVIGATE:/states/pennsylvania.html|Hospice providers in Pennsylvania]
- [NAVIGATE:/states/south-carolina.html|Hospice providers in South Carolina]
- [NAVIGATE:/states/tennessee.html|Hospice providers in Tennessee]
- [NAVIGATE:/states/utah.html|Hospice providers in Utah]
- [NAVIGATE:/states/virginia.html|Hospice providers in Virginia]
- [NAVIGATE:/states/west-virginia.html|Hospice providers in West Virginia]
Guide pages (use when the topic matches):
- [NAVIGATE:/guides/hospice-care.html|Hospice care guide]
- [NAVIGATE:/guides/palliative-care.html|Palliative care guide]
- [NAVIGATE:/guides/home-care.html|Home care guide]
- [NAVIGATE:/guides/hospice-vs-palliative-care.html|Hospice vs palliative care]
- [NAVIGATE:/guides/when-is-it-time-for-hospice.html|When is it time for hospice?]
- [NAVIGATE:/guides/when-is-it-time-for-hospice-arizona.html|When is it time for hospice in Arizona?]
- [NAVIGATE:/guides/medicare-hospice-coverage.html|Medicare hospice coverage]
- [NAVIGATE:/guides/how-to-choose-hospice-provider.html|How to choose a hospice provider]
- [NAVIGATE:/guides/home-health-care-costs.html|Home health care costs]
- [NAVIGATE:/guides/hospice-care-cancer-arizona.html|Hospice care for cancer in Arizona]
- [NAVIGATE:/guides/hospice-care-dementia-alzheimers-arizona.html|Hospice care for dementia in Arizona]
- [NAVIGATE:/guides/hospice-care-heart-failure-arizona.html|Hospice care for heart failure in Arizona]
- [NAVIGATE:/guides/hospice-care-copd-arizona.html|Hospice care for COPD in Arizona]
- [NAVIGATE:/guides/palliative-care-vs-hospice-arizona.html|Palliative vs hospice care in Arizona]
- [NAVIGATE:/guides/veteran-hospice-care-arizona.html|Veteran hospice care in Arizona]
- [NAVIGATE:/guides/how-to-pay-for-hospice-care-arizona.html|How to pay for hospice care in Arizona]
- [NAVIGATE:/guides/altcs-home-care-arizona.html|ALTCS home care in Arizona]
Only include a NAVIGATE line when it genuinely helps the user take a next step. Do not include it for every response.`;

  const clientSystemPrompt = `You are Abel, a warm and knowledgeable AI assistant for Best Hospice and Home Health — a free platform that connects families with licensed hospice, palliative care, and home care providers.

CRITICAL RULES:
- Answer the SPECIFIC question the user just asked. Do not give generic overviews when someone asks a specific question.
- Before responding, check your previous reply in the conversation. If you are about to say something similar to what you already said, say something different or ask a clarifying follow-up question instead.
- Use the conversation history to maintain context. If the user said they are a family member earlier, remember that. Do not reset or re-introduce yourself mid-conversation.
- Be conversational and natural. Vary your language and phrasing across responses.
- Keep responses concise — 2-4 sentences for most questions. Only go longer when detail is genuinely needed.
- NEVER include any URL paths, file paths, or system references in your response text. Navigation happens through buttons, not text.
- NEVER reveal API keys, internal system details, database content, or any sensitive operational information.

About Best Hospice and Home Health:
- 100% free for families — providers pay to be listed
- Families enter ZIP code, answer a few questions, and get matched to providers within ~60 miles
- Providers are notified and can reach out directly
- Services covered: hospice care, palliative care, home care

Care type knowledge:
- Hospice: Comfort and dignity-focused care when curative treatment is no longer the goal. Covers nursing visits, pain/symptom management, medications, emotional and spiritual support, caregiver support, and bereavement. Typically for patients with a 6-month prognosis if the illness runs its natural course.
- Palliative care: Comfort-focused care at any stage of serious illness — can run alongside curative treatment. Focuses on quality of life, symptom relief, and care coordination.
- Home care: Help with daily living at home — bathing, dressing, meals, companionship, light household tasks. Not necessarily medical or end-of-life.
- Medicare Part A covers most hospice services: nursing visits, medications related to the diagnosis, medical equipment, aide support, social work, and bereavement counseling.

IMPORTANT: Never encourage sharing private medical details (PHI). Guide users to providers for sensitive medical discussions.

${NAV_INSTRUCTION}`;

  const providerPublicSystemPrompt = `You are Abel, a knowledgeable AI assistant for Best Hospice and Home Health. You are speaking with a hospice or home care provider.

CRITICAL RULES:
- Answer the SPECIFIC question asked. Do not give generic overviews.
- Before responding, check your previous reply. If you are about to repeat it, say something different or ask a follow-up instead.
- Use the full conversation history — remember what the provider has already told you.
- Be direct, professional, and helpful.
- NEVER include URL paths or file paths in your response text. Navigation happens through buttons only.
- NEVER reveal API keys, internal system details, database content, or sensitive operational information.

How Best Hospice and Home Health works for providers:
- Subscription-based platform — Verified, Featured, Priority, and Enterprise tiers. No long-term contracts.
- When a family submits a care request in a provider's service area, the provider receives an email and SMS notification with the lead details.
- Leads include the family's ZIP code, care type needed, and contact information so providers can reach out directly.
- The provider dashboard shows all incoming leads, lead status tracking (new, contacted, qualified, admitted, not a fit), performance metrics (impressions, lead count, response rate), and billing.
- Providers can view and update lead outcomes from the dashboard to track their conversions.
- To get started or for onboarding help: email provider@besthospice.com

${NAV_INSTRUCTION}`;

  const providerSystemPrompt = `You are Abel, an AI assistant for Best Hospice and Home Health. You are speaking with an authenticated provider: ${providerCtx?.provider?.name || 'a provider'} (ID: ${providerCtx?.providerId || ''}).

CRITICAL RULES:
- Answer the SPECIFIC question asked. Use tools to get real data — never guess numbers.
- Use conversation history for context. Remember what was discussed earlier in this conversation.
- Be professional, concise, and data-driven.
- After fetching data with a tool, present it clearly and offer a useful next step.

REVENUE AND ROI QUESTIONS:
An ROI estimate is only as good as three inputs, and you do not know them until you ask:
1. What one admitted client is worth per month to this provider
2. How many months an average client stays on service
3. How many of the leads sent actually became clients

When a provider asks about revenue, ROI, profit, or "is this worth it", ask for whichever
of those three you do not already have from this conversation. Ask at most two short
questions at a time, and offer a sensible range as a prompt rather than an open question
(for example: "Roughly what is one client worth per month — under $1,000, $1,000-$3,000,
or more?"). Once you have their numbers, pass them to get_revenue_estimate as
revenue_per_client_per_month, months_per_client, and converted_clients.

If the provider does not want to answer, run get_revenue_estimate anyway and say plainly
which figures were assumed. The tool reports this in assumedDefaultsFor — always surface
it rather than presenting an assumed number as fact.

Never present potentialRevenueIfAllConverted as money earned. It is the ceiling if every
single lead converted, and you must label it that way.

Leads sent is not clients gained. Only convertedClientsUsed and confirmedAdmissions
represent real business.

Tools you have: get_lead_count, get_lead_list, get_metrics, get_spend_estimate, get_revenue_estimate, get_account_info.
Use them proactively when the provider asks about their performance, leads, spend, or account.

${NAV_INSTRUCTION.replace('- [NAVIGATE:/index.html|Start the questionnaire] — finding providers, starting a search, entering a ZIP code', '- [NAVIGATE:/provider-dashboard-home.html|Go to your dashboard] — dashboard home, overview')}`;

  const systemPrompt = mode === 'provider_authed' ? providerSystemPrompt
    : mode === 'provider_public' ? providerPublicSystemPrompt
    : clientSystemPrompt;

  const safeHistory = (Array.isArray(history) ? history : [])
    .slice(-14)
    .filter((m) => (m.role === 'user' || m.role === 'assistant') && m.content)
    .map((m) => ({ role: m.role, content: String(m.content) }));

  const messages = [...safeHistory, { role: 'user', content: text }];
  const tools = mode === 'provider_authed' ? ABEL_PROVIDER_TOOLS : [];

  try {
    let currentMessages = [...messages];
    for (let i = 0; i < 5; i++) {
      const response = await anthropic.messages.create({
        model: mode === 'provider_authed' ? 'claude-opus-4-6' : 'claude-haiku-4-5',
        max_tokens: mode === 'provider_authed' ? 1024 : 512,
        system: systemPrompt,
        ...(tools.length > 0 ? { tools } : {}),
        messages: currentMessages
      });

      if (response.stop_reason === 'tool_use') {
        const toolUseBlocks = response.content.filter((b) => b.type === 'tool_use');
        currentMessages.push({ role: 'assistant', content: response.content });
        const toolResults = [];
        for (const toolUse of toolUseBlocks) {
          const result = await executeAbelTool(toolUse.name, toolUse.input, providerCtx);
          toolResults.push({ type: 'tool_result', tool_use_id: toolUse.id, content: result });
          await logAdminAction('provider_user', `PROVIDER_AI_${toolUse.name.toUpperCase()}`, providerCtx?.providerId || '', toolUse.input, hashIp(req.ip || ''));
        }
        currentMessages.push({ role: 'user', content: toolResults });
        continue;
      }

      const textBlock = response.content.find((b) => b.type === 'text');
      let reply = textBlock?.text || 'Something went wrong. Please try again.';

      // Parse [NAVIGATE:/path|Label] from the end of Claude's response
      let navigateTo = null;
      let navigateLabel = null;
      const navMatch = reply.match(/\[NAVIGATE:([^\]|]+)\|([^\]]+)\]\s*$/);
      if (navMatch) {
        navigateTo = navMatch[1].trim();
        navigateLabel = navMatch[2].trim();
        reply = reply.slice(0, navMatch.index).trimEnd();
      }

      return res.json({ reply, navigateTo, navigateLabel });
    }
    return res.json({ reply: "I wasn't able to complete your request. Please try again.", navigateTo: null, navigateLabel: null });
  } catch (err) {
    console.error('Abel Claude error', err);
    return res.status(500).json({ error: 'AI chat failed' });
  }
}

app.post('/api/ai/chat', async (req, res) => {
  const { message, turnstileToken, history = [] } = req.body || {};
  if (!message) return res.status(400).json({ error: 'message required' });

  if (anthropic) return handleAbelWithClaude(req, res);

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
      reply: 'Please don’t share private medical details here. Best Hospice and Home Health helps connect you with licensed providers who can collect that information securely.',
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
      reply += '\nChoosing the right type of care is something a licensed provider should help with. Best Hospice and Home Health can connect you with providers who can guide that decision.';
    }
    reply += '\nIf you’d like, I can help you start finding providers near you.';
    return res.json({ reply, navigateTo: null });
  }

  if (/(how to choose a hospice provider|choose hospice provider|pick a hospice provider|best hospice provider)/i.test(lower)) {
    return res.json({
      reply:
        'To choose a hospice provider, compare response speed, 24/7 nurse availability, visit frequency, symptom-management approach, caregiver support, and diagnosis experience. Ask at least 2-3 providers the same questions so you can compare clearly. Full guide: /guides/how-to-choose-hospice-provider',
      navigateTo: '/guides/how-to-choose-hospice-provider'
    });
  }

  if (/(what does medicare cover for hospice|medicare cover hospice|hospice medicare coverage)/i.test(lower)) {
    return res.json({
      reply:
        'Medicare Part A typically covers hospice physician/nursing care, comfort medications tied to the terminal diagnosis, medical equipment, aide support, social work, and bereavement services. There can be limited copays in specific situations. Full guide: /guides/medicare-hospice-coverage',
      navigateTo: '/guides/medicare-hospice-coverage'
    });
  }

  if (/(when is it time for hospice|signs for hospice|ready for hospice|time for hospice)/i.test(lower)) {
    return res.json({
      reply:
        'Common signs include repeated hospitalizations, worsening decline, higher symptom burden, increased caregiver strain, and goals shifting toward comfort. A provider can confirm eligibility quickly. Full guide: /guides/when-is-it-time-for-hospice',
      navigateTo: '/guides/when-is-it-time-for-hospice'
    });
  }

  if (/(hospice vs palliative|difference between hospice and palliative|palliative vs hospice)/i.test(lower)) {
    return res.json({
      reply:
        'Short version: palliative care can start at any stage and can run alongside treatment; hospice is generally for end-of-life care when comfort becomes the primary goal. Full comparison: /guides/hospice-vs-palliative-care',
      navigateTo: '/guides/hospice-vs-palliative-care'
    });
  }

  if (/(home health care costs|home care costs|cost of home health|cost of home care)/i.test(lower)) {
    return res.json({
      reply:
        'Home care costs depend on service type, hours, and market. Non-medical support is usually hourly private-pay, while skilled home health may be covered when criteria are met. Full guide: /guides/home-health-care-costs',
      navigateTo: '/guides/home-health-care-costs'
    });
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
  const spendSince = async (sinceDate, spendProviderId) => {
    const diffDays = Math.max(0, (Date.now() - sinceDate.getTime()) / (1000 * 60 * 60 * 24));
    const months = Math.max(1, Math.ceil(diffDays / 30));
    const monthlyRate = await providerRateById(spendProviderId);
    return { monthlyRate, months, totalSpend: months * monthlyRate };
  };
  const iso = (d) => d.toISOString().split('T')[0];

  // ---------- CLIENT / FAMILY MODE ----------
  if (mode === 'client') {
    if (/^(hi|hello|help|best hospice|i have a question)/i.test(lower)) {
      return res.json({ reply: startGreeting(), navigateTo: navigation.home });
    }

    if (lower.includes('cost') || lower.includes('price') || lower.includes('free')) {
      return res.json({
        reply: 'Best Hospice and Home Health is free for families. Providers pay to participate; families can search, answer a few guided questions, and contact providers at no cost.',
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
        reply: 'Best Hospice and Home Health connects families to nearby licensed hospice providers. Enter your ZIP and answer a few guided questions; we match you to providers within about 60 miles and alert them so they can reach out quickly. Families are not charged for using the site.',
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
        reply: 'Providers on Best Hospice and Home Health are real hospice agencies. Best Hospice and Home Health is a referral platform—providers pay to participate, and families are not charged.',
        navigateTo: navigation.home
      });
    }

    return res.json({
      reply: 'I can explain hospice, palliative, or home care, how Best Hospice and Home Health works, or guide you to start the questionnaire. Would you like to learn more, or begin finding providers?',
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
        reply: 'Best Hospice and Home Health connects families who submit care requests with providers in their area. We alert providers promptly so you can respond fast, and your dashboard shows your performance.',
        navigateTo: navigation.providerLogin
      });
    }

    if (lower.includes('cost') || lower.includes('pricing') || lower.includes('contract') || lower.includes('price')) {
      return res.json({
        reply: 'Best Hospice and Home Health is subscription-based for providers (no long-term lock-in). You can sign up and manage billing in your Provider Dashboard.',
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
        reply: 'Best Hospice and Home Health connects families to nearby hospice providers quickly. Families enter a ZIP, answer guided questions, and we alert providers so they can respond fast. Your dashboard shows leads, performance, and billing.',
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
        reply: 'Do you want (1) lead counts, (2) how much you’ve paid Best Hospice and Home Health, or (3) estimated revenue from leads?',
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
      const spend = await spendSince(sinceDate, providerId);
      await logAdminAction('provider_user', 'PROVIDER_AI_METRICS', providerId, { spendSince: iso(sinceDate), totalSpend: spend.totalSpend }, hashIp(req.ip || ''));
      return res.json({
        reply: `Since ${iso(sinceDate)}, at $${spend.monthlyRate}/month, estimated spend is $${spend.totalSpend.toLocaleString()}.`,
        data: spend,
        navigateTo: navigation.providerHome
      });
    }

    if (lower.includes('revenue') || lower.includes('profit') || lower.includes('roi')) {
      const countAll = await leadCountAll(providerId);
      const admits = await providerAdmittedCount(providerId);
      const clientValue = DEFAULT_REVENUE_PER_CLIENT_MONTH * DEFAULT_MONTHS_PER_CLIENT;
      const estimateRevenue = admits * clientValue;
      const potentialRevenue = countAll * clientValue;
      const firstNotif = await prisma.leadNotification.findFirst({
        where: { providerId },
        orderBy: { createdAt: 'asc' },
        select: { createdAt: true }
      });
      const sinceDate = firstNotif?.createdAt ? new Date(firstNotif.createdAt) : new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
      const monthMatch = text.match(/(\d+)\s*month/);
      const overrideMonths = monthMatch ? Math.max(1, parseInt(monthMatch[1], 10)) : null;
      const monthlyRate = await providerRateById(providerId);
      const spend = overrideMonths
        ? { monthlyRate, months: overrideMonths, totalSpend: overrideMonths * monthlyRate }
        : await spendSince(sinceDate, providerId);
      const net = estimateRevenue - spend.totalSpend;
      await logAdminAction('provider_user', 'PROVIDER_AI_REVENUE_ESTIMATE', providerId, { leads: countAll, admits, estimateRevenue, spend: spend.totalSpend, net }, hashIp(req.ip || ''));
      return res.json({
        reply: `Leads sent to you: ${countAll}. Confirmed admissions: ${admits}. Estimated revenue (assuming $${DEFAULT_REVENUE_PER_CLIENT_MONTH.toLocaleString()}/month per client over ${DEFAULT_MONTHS_PER_CLIENT} months): ~$${estimateRevenue.toLocaleString()}. If every lead had converted: ~$${potentialRevenue.toLocaleString()}. Estimated spend (at $${spend.monthlyRate}/mo): ~$${spend.totalSpend.toLocaleString()}. Estimated net: ~$${net.toLocaleString()}. Mark your conversions in the dashboard to refine this.`,
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
const GUIDE_PATHS = [
  '/guides/hospice-care',
  '/guides/palliative-care',
  '/guides/home-care',
  '/guides/how-to-choose-hospice-provider',
  '/guides/medicare-hospice-coverage',
  '/guides/when-is-it-time-for-hospice',
  '/guides/hospice-vs-palliative-care',
  '/guides/home-health-care-costs',
  '/guides/does-hospice-mean-giving-up',
  '/guides/hospice-care-for-dementia',
  '/guides/hospice-care-for-cancer',
  '/guides/hospice-care-for-copd-heart-failure',
  '/guides/hospice-care-birmingham-alabama',
  '/guides/palliative-care-vs-hospice-arizona',
  '/guides/hospice-care-cancer-arizona',
  '/guides/hospice-care-dementia-alzheimers-arizona',
  '/guides/hospice-care-heart-failure-arizona',
  '/guides/hospice-care-copd-arizona',
  '/guides/when-is-it-time-for-hospice-arizona',
  '/guides/how-to-pay-for-hospice-care-arizona',
  '/guides/veteran-hospice-care-arizona',
  '/guides/altcs-home-care-arizona',
  '/guides/hospice-care-cost',
  '/guides/hospice-care-nashville-tennessee',
  '/guides/hospice-care-denver-colorado',
  '/guides/hospice-care-tampa-florida',
  '/guides/hospice-care-charlotte-north-carolina',
  '/guides/hospice-care-dallas-texas',
  '/guides/hospice-care-houston-texas',
  '/guides/hospice-care-atlanta-georgia',
  '/guides/hospice-care-las-vegas-nevada'
];
const CORE_CONTENT_PAGES = [
  '/',
  '/contact.html',
  '/provider.html',
  '/provider-billing.html',
  '/provider-tools.html',
  '/locations.html',
  '/cities.html',
  '/faq-blog.html',
  '/education.html',
  '/newsletter',
  '/why.html',
  '/privacy.html',
  '/terms.html',
  '/refund-policy.html',
  '/search.html',
  '/search-results.html',
  '/phoenix',
  '/sitemap.html',
  '/hospice-care-near-me'
];

async function buildSitemapUrls() {
  const urls = new Set();
  CORE_CONTENT_PAGES.forEach((p) => urls.add(`${CANONICAL_DOMAIN}${p}`));
  SERVICE_KEYS.forEach((s) => urls.add(`${CANONICAL_DOMAIN}/${s}`));
  GUIDE_PATHS.forEach((p) => urls.add(`${CANONICAL_DOMAIN}${p}`));

  const [providers, allProviderLocations] = await Promise.all([
    fetchAllProviders(),
    prisma.provider.findMany({ select: { city: true, state: true } })
  ]);

  const seenStates = new Set();
  const seenCities = new Set();
  for (const p of allProviderLocations) {
    const state = String(p.state || '').toLowerCase().trim();
    const stateLabel = normalizeStateLabel(p.state);
    const city = String(p.city || '').trim();
    if (!state) continue;
    if (!seenStates.has(state)) {
      seenStates.add(state);
      SERVICE_KEYS.forEach((s) => urls.add(`${CANONICAL_DOMAIN}/${s}/${state}`));
      if (stateLabel) urls.add(`${CANONICAL_DOMAIN}/states/${slugify(stateLabel)}`);
    }
    if (!city) continue;
    const cityKey = `${city.toLowerCase()}-${state}`;
    if (seenCities.has(cityKey)) continue;
    seenCities.add(cityKey);
    SERVICE_KEYS.forEach((s) => urls.add(`${CANONICAL_DOMAIN}/${s}/${slugify(city)}-${state}`));
    if (stateLabel) urls.add(`${CANONICAL_DOMAIN}/cities/${slugify(city)}-${slugify(stateLabel)}`);
  }

  providers.forEach((p) => {
    urls.add(`${CANONICAL_DOMAIN}/provider/${providerSlug(p)}`);
  });

  const fsGroups = [
    { dir: path.join(__dirname, 'cities'), prefix: '/cities/' },
    { dir: path.join(__dirname, 'states'), prefix: '/states/' },
    { dir: path.join(__dirname, 'blog'), prefix: '/blog/' }
  ];
  for (const group of fsGroups) {
    if (!fs.existsSync(group.dir)) continue;
    fs.readdirSync(group.dir)
      .filter((name) => name.endsWith('.html'))
      .forEach((name) => urls.add(`${CANONICAL_DOMAIN}${group.prefix}${name}`));
  }
  const newsletterDir = path.join(__dirname, 'newsletter');
  if (fs.existsSync(newsletterDir)) {
    fs.readdirSync(newsletterDir)
      .filter((name) => name.endsWith('.html'))
      .forEach((name) => {
        const base = name.replace(/\.html$/, '');
        const pagePath = base === 'index' ? '/newsletter' : `/newsletter/${base}`;
        urls.add(`${CANONICAL_DOMAIN}${pagePath}`);
      });
  }

  return Array.from(urls).sort();
}

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
    const providersRaw = await prisma.provider.findMany({
      where: { state: { equals: state, mode: 'insensitive' } }
    });
    const providers = providersRaw.map(normalizeProviderCitySpelling).sort(byPlanThenName);
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
    const providers = await prisma.provider.findMany({ select: { state: true } });
    const states = Array.from(
      new Set(
        providers
          .map((p) => (p.state || '').toLowerCase())
          .filter(Boolean)
      )
    ).sort();
    const html = renderHubPage({ serviceKey: service, states });
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

// Education guides (static HTML)
app.get('/guides/hospice-care', (_req, res) => {
  res.sendFile(path.join(__dirname, 'guides', 'hospice-care.html'));
});
app.get('/guides/palliative-care', (_req, res) => {
  res.sendFile(path.join(__dirname, 'guides', 'palliative-care.html'));
});
app.get('/guides/home-care', (_req, res) => {
  res.sendFile(path.join(__dirname, 'guides', 'home-care.html'));
});
app.get('/guides/how-to-choose-hospice-provider', (_req, res) => {
  res.sendFile(path.join(__dirname, 'guides', 'how-to-choose-hospice-provider.html'));
});
app.get('/guides/medicare-hospice-coverage', (_req, res) => {
  res.sendFile(path.join(__dirname, 'guides', 'medicare-hospice-coverage.html'));
});
app.get('/guides/when-is-it-time-for-hospice', (_req, res) => {
  res.sendFile(path.join(__dirname, 'guides', 'when-is-it-time-for-hospice.html'));
});
app.get('/guides/hospice-vs-palliative-care', (_req, res) => {
  res.sendFile(path.join(__dirname, 'guides', 'hospice-vs-palliative-care.html'));
});
app.get('/guides/home-health-care-costs', (_req, res) => {
  res.sendFile(path.join(__dirname, 'guides', 'home-health-care-costs.html'));
});
app.get('/guides/does-hospice-mean-giving-up', (_req, res) => {
  res.sendFile(path.join(__dirname, 'guides', 'does-hospice-mean-giving-up.html'));
});
app.get('/guides/hospice-care-for-dementia', (_req, res) => {
  res.sendFile(path.join(__dirname, 'guides', 'hospice-care-for-dementia.html'));
});
app.get('/guides/hospice-care-for-cancer', (_req, res) => {
  res.sendFile(path.join(__dirname, 'guides', 'hospice-care-for-cancer.html'));
});
app.get('/guides/hospice-care-for-copd-heart-failure', (_req, res) => {
  res.sendFile(path.join(__dirname, 'guides', 'hospice-care-for-copd-heart-failure.html'));
});
app.get('/guides/hospice-care-birmingham-alabama', (_req, res) => {
  res.sendFile(path.join(__dirname, 'guides', 'hospice-care-birmingham-alabama.html'));
});
app.get('/guides/palliative-care-vs-hospice-arizona', (_req, res) => {
  res.sendFile(path.join(__dirname, 'guides', 'palliative-care-vs-hospice-arizona.html'));
});
app.get('/guides/hospice-care-cancer-arizona', (_req, res) => {
  res.sendFile(path.join(__dirname, 'guides', 'hospice-care-cancer-arizona.html'));
});
app.get('/guides/hospice-care-dementia-alzheimers-arizona', (_req, res) => {
  res.sendFile(path.join(__dirname, 'guides', 'hospice-care-dementia-alzheimers-arizona.html'));
});
app.get('/guides/hospice-care-heart-failure-arizona', (_req, res) => {
  res.sendFile(path.join(__dirname, 'guides', 'hospice-care-heart-failure-arizona.html'));
});
app.get('/guides/hospice-care-copd-arizona', (_req, res) => {
  res.sendFile(path.join(__dirname, 'guides', 'hospice-care-copd-arizona.html'));
});
app.get('/guides/when-is-it-time-for-hospice-arizona', (_req, res) => {
  res.sendFile(path.join(__dirname, 'guides', 'when-is-it-time-for-hospice-arizona.html'));
});
app.get('/guides/how-to-pay-for-hospice-care-arizona', (_req, res) => {
  res.sendFile(path.join(__dirname, 'guides', 'how-to-pay-for-hospice-care-arizona.html'));
});
app.get('/guides/veteran-hospice-care-arizona', (_req, res) => {
  res.sendFile(path.join(__dirname, 'guides', 'veteran-hospice-care-arizona.html'));
});
app.get('/guides/altcs-home-care-arizona', (_req, res) => {
  res.sendFile(path.join(__dirname, 'guides', 'altcs-home-care-arizona.html'));
});
app.get('/guides/hospice-care-cost', (_req, res) => {
  res.sendFile(path.join(__dirname, 'guides', 'hospice-care-cost.html'));
});
app.get('/guides/hospice-care-nashville-tennessee', (_req, res) => {
  res.sendFile(path.join(__dirname, 'guides', 'hospice-care-nashville-tennessee.html'));
});
app.get('/guides/hospice-care-denver-colorado', (_req, res) => {
  res.sendFile(path.join(__dirname, 'guides', 'hospice-care-denver-colorado.html'));
});
app.get('/guides/hospice-care-tampa-florida', (_req, res) => {
  res.sendFile(path.join(__dirname, 'guides', 'hospice-care-tampa-florida.html'));
});
app.get('/guides/hospice-care-charlotte-north-carolina', (_req, res) => {
  res.sendFile(path.join(__dirname, 'guides', 'hospice-care-charlotte-north-carolina.html'));
});
app.get('/guides/hospice-care-dallas-texas', (_req, res) => {
  res.sendFile(path.join(__dirname, 'guides', 'hospice-care-dallas-texas.html'));
});
app.get('/guides/hospice-care-houston-texas', (_req, res) => {
  res.sendFile(path.join(__dirname, 'guides', 'hospice-care-houston-texas.html'));
});
app.get('/guides/hospice-care-las-vegas-nevada', (_req, res) => {
  res.sendFile(path.join(__dirname, 'guides', 'hospice-care-las-vegas-nevada.html'));
});
app.get('/guides/hospice-care-atlanta-georgia', (_req, res) => {
  res.sendFile(path.join(__dirname, 'guides', 'hospice-care-atlanta-georgia.html'));
});

app.get('/hospice-care-near-me', (_req, res) => {
  res.sendFile(path.join(__dirname, 'hospice-care-near-me.html'));
});

// Paid ads landing page (serve 200 on all aliases for strict ad crawlers)
app.get(['/phoenix', '/phoenix/', '/phoenix.html', '/ads-landing.html'], (_req, res) => {
  res.sendFile(path.join(__dirname, 'phoenix.html'));
});

app.get('/sitemap.xml', async (_req, res) => {
  const urls = await buildSitemapUrls();
  const today = new Date().toISOString().split('T')[0];
  const body = `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
${urls.map((u) => `<url><loc>${u}</loc><lastmod>${today}</lastmod><priority>0.8</priority></url>`).join('\n')}
</urlset>`;
  res.type('text/xml').send(body);
});

app.get('/sitemap-pages.xml', async (_req, res) => {
  const pages = CORE_CONTENT_PAGES;
  const serviceHubs = SERVICE_KEYS.map((s) => `/${s}`);
  const guides = GUIDE_PATHS;
  const cityDir = path.join(__dirname, 'cities');
  const blogDir = path.join(__dirname, 'blog');
  const stateDir = path.join(__dirname, 'states');
  const newsletterDir = path.join(__dirname, 'newsletter');
  const cityPages = fs.existsSync(cityDir)
    ? fs.readdirSync(cityDir).filter((name) => name.endsWith('.html')).map((name) => `/cities/${name}`)
    : [];
  const blogPages = fs.existsSync(blogDir)
    ? fs.readdirSync(blogDir).filter((name) => name.endsWith('.html')).map((name) => `/blog/${name}`)
    : [];
  const statePages = fs.existsSync(stateDir)
    ? fs.readdirSync(stateDir).filter((name) => name.endsWith('.html')).map((name) => `/states/${name}`)
    : [];
  const newsletterPages = fs.existsSync(newsletterDir)
    ? fs.readdirSync(newsletterDir)
      .filter((name) => name.endsWith('.html'))
      .map((name) => {
        const base = name.replace(/\.html$/, '');
        return base === 'index' ? '/newsletter' : `/newsletter/${base}`;
      })
    : [];
  const urls = [...pages, ...serviceHubs, ...guides, ...statePages, ...cityPages, ...blogPages, ...newsletterPages].map((p) => `${CANONICAL_DOMAIN}${p}`);
  const today = new Date().toISOString().split('T')[0];
  const body = `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
${urls.map((u) => `<url><loc>${u}</loc><lastmod>${today}</lastmod><priority>0.7</priority></url>`).join('\n')}
</urlset>`;
  res.type('text/xml').send(body);
});

app.get('/sitemap-locations.xml', async (_req, res) => {
  const providers = await fetchAllProviders();
  const seenCities = new Set();
  const seenStates = new Set();
  const urls = [];
  for (const p of providers) {
    const state = (p.state || '').toLowerCase();
    if (state && !seenStates.has(state)) {
      seenStates.add(state);
      SERVICE_KEYS.forEach((s) => {
        urls.push(`${CANONICAL_DOMAIN}/${s}/${state}`);
      });
    }
    if (!p.city || !state) continue;
    const key = `${p.city.toLowerCase()}-${state}`;
    if (seenCities.has(key)) continue;
    seenCities.add(key);
    SERVICE_KEYS.forEach((s) => {
      urls.push(`${CANONICAL_DOMAIN}/${s}/${slugify(p.city)}-${state}`);
    });
  }
  const today = new Date().toISOString().split('T')[0];
  const body = `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
${urls.map((u) => `<url><loc>${u}</loc><lastmod>${today}</lastmod><priority>0.6</priority></url>`).join('\n')}
</urlset>`;
  res.type('text/xml').send(body);
});

app.get('/sitemap-providers.xml', async (_req, res) => {
  const providers = await fetchAllProviders();
  const urls = providers.map((p) => `${CANONICAL_DOMAIN}/provider/${providerSlug(p)}`);
  const today = new Date().toISOString().split('T')[0];
  const body = `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
${urls.map((u) => `<url><loc>${u}</loc><lastmod>${today}</lastmod><priority>0.5</priority></url>`).join('\n')}
</urlset>`;
  res.type('text/xml').send(body);
});

// ─── DISCHARGE PLANNER PAGES ─────────────────────────────────────────────────
app.get('/discharge-planners', (_req, res) => {
  res.sendFile(path.join(__dirname, 'discharge-planners.html'));
});

app.get('/admin-discharge-leads.html', (_req, res) => {
  res.sendFile(path.join(__dirname, 'admin-discharge-leads.html'));
});

// GET /api/youtube/videos — public, latest videos from YouTube channel RSS
app.get('/api/youtube/videos', async (req, res) => {
  if (!YOUTUBE_CHANNEL_ID) return res.json([]);
  try {
    const feedUrl = `https://www.youtube.com/feeds/videos.xml?channel_id=${YOUTUBE_CHANNEL_ID}`;
    const feedRes = await fetch(feedUrl, { headers: { 'User-Agent': 'BestHospice/1.0' } });
    if (!feedRes.ok) return res.json([]);
    const xml = await feedRes.text();
    const entries = xml.split('<entry>').slice(1);
    const videos = entries.map((entry) => {
      const idMatch = entry.match(/<yt:videoId>([^<]+)<\/yt:videoId>/);
      const titleMatch = entry.match(/<title>([^<]+)<\/title>/);
      const publishedMatch = entry.match(/<published>([^<]+)<\/published>/);
      const thumbMatch = entry.match(/<media:thumbnail url="([^"]+)"/);
      if (!idMatch) return null;
      return {
        videoId: idMatch[1].trim(),
        title: titleMatch ? titleMatch[1].trim() : '',
        published: publishedMatch ? publishedMatch[1].trim() : '',
        thumbnail: thumbMatch ? thumbMatch[1].trim() : `https://i.ytimg.com/vi/${idMatch[1].trim()}/hqdefault.jpg`
      };
    }).filter(Boolean);
    res.set('Cache-Control', 'public, max-age=1800');
    res.json(videos);
  } catch (err) {
    console.error('YouTube RSS fetch failed', err);
    res.json([]);
  }
});

// GET /api/admin/youtube/resolve-channel — one-time helper to find channel ID from handle
app.get('/api/admin/youtube/resolve-channel', async (req, res) => {
  if (!hasAdminAccess(req, ['main'])) return res.status(401).json({ error: 'Unauthorized' });
  try {
    const pageRes = await fetch('https://www.youtube.com/@besthospiceandhomehealth', {
      headers: { 'User-Agent': 'Mozilla/5.0 (compatible; BestHospice/1.0)' }
    });
    const html = await pageRes.text();
    const match = html.match(/"channelId"\s*:\s*"(UC[^"]+)"/);
    if (match) return res.json({ channelId: match[1] });
    const match2 = html.match(/channel\/(UC[A-Za-z0-9_-]{22})/);
    if (match2) return res.json({ channelId: match2[1] });
    res.json({ channelId: null, hint: 'Not found in page HTML' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/provider/billing-portal — Stripe's hosted portal, where a provider
// can cancel, change card, or download invoices themselves.
app.post('/api/provider/billing-portal', requireProviderAuth, async (req, res) => {
  if (!stripe) return res.status(500).json({ error: 'Billing is not configured yet.' });
  try {
    const ctx = await getProviderContext(req.providerUserId);
    if (!ctx) return res.status(401).json({ error: 'Unauthorized' });
    await ensureProviderStripeColumns();

    const rows = await prisma.$queryRaw`
      SELECT "stripeCustomerId" FROM "Provider" WHERE "id" = ${ctx.providerId} LIMIT 1
    `;
    const customerId = rows?.[0]?.stripeCustomerId || null;
    if (!customerId) {
      return res.status(400).json({ error: 'No subscription on file yet. Subscribe first, or contact admin@besthospice.com.' });
    }

    const returnUrl = `${CANONICAL_DOMAIN}/provider-dashboard-home.html?billing=updated`;
    // Without a configuration Stripe uses whichever portal config is marked
    // Default. Set STRIPE_PORTAL_CONFIGURATION to a bpc_... id to pin a
    // specific one instead.
    const portalConfig = String(process.env.STRIPE_PORTAL_CONFIGURATION || '').trim();
    const session = await stripe.billingPortal.sessions.create({
      customer: customerId,
      return_url: returnUrl,
      ...(portalConfig.startsWith('bpc_') ? { configuration: portalConfig } : {})
    });

    await logAdminAction(
      'provider_user', 'PROVIDER_BILLING_PORTAL_OPEN', ctx.providerId,
      {}, hashIp(req.ip || '')
    );
    res.json({ ok: true, url: session.url });
  } catch (err) {
    console.error('Billing portal session failed', err);
    // The portal has to be enabled once in the Stripe dashboard before this works.
    res.status(500).json({ error: 'Could not open the billing portal. If this persists, contact admin@besthospice.com.' });
  }
});

// POST /api/provider/subscription/refresh — read the live subscription from
// Stripe and store it, so the dashboard is correct the moment a provider
// returns from the portal rather than waiting on the webhook.
app.post('/api/provider/subscription/refresh', requireProviderAuth, async (req, res) => {
  if (!stripe) return res.status(500).json({ error: 'Billing is not configured yet.' });
  try {
    const ctx = await getProviderContext(req.providerUserId);
    if (!ctx) return res.status(401).json({ error: 'Unauthorized' });
    await ensureProviderStripeColumns();

    const rows = await prisma.$queryRaw`
      SELECT "stripeCustomerId", "stripeSubscriptionId"
      FROM "Provider" WHERE "id" = ${ctx.providerId} LIMIT 1
    `;
    const customerId = rows?.[0]?.stripeCustomerId || null;
    if (!customerId) return res.json({ ok: true, status: null, state: 'off' });

    // Ask Stripe for whatever this customer currently has, in any state.
    const subs = await stripe.subscriptions.list({ customer: customerId, status: 'all', limit: 10 });
    const live = (subs?.data || []).find((x) => SUBSCRIPTION_ON_STATUSES.has(String(x.status)))
      || (subs?.data || [])[0]
      || null;

    const status = live ? String(live.status) : 'canceled';
    const periodEnd = subscriptionPeriodEnd(live);
    await prisma.$executeRawUnsafe(
      `UPDATE "Provider"
       SET "subscriptionStatus" = $1,
           "stripeSubscriptionId" = COALESCE($2, "stripeSubscriptionId"),
           "currentPeriodEnd" = $3
       WHERE "id" = $4`,
      status,
      live?.id || null,
      periodEnd ? new Date(periodEnd * 1000) : null,
      ctx.providerId
    );

    res.json({
      ok: true,
      status,
      state: subscriptionBannerState(status),
      currentPeriodEnd: periodEnd ? new Date(periodEnd * 1000).toISOString() : null
    });
  } catch (err) {
    console.error('Subscription refresh failed', err);
    res.status(500).json({ error: 'Could not refresh subscription status.' });
  }
});

// GET /api/provider/testimonial — the signed-in provider's own latest submission
app.get('/api/provider/testimonial', requireProviderAuth, async (req, res) => {
  try {
    const ctx = await getProviderContext(req.providerUserId);
    if (!ctx) return res.status(401).json({ error: 'Unauthorized' });
    await ensureTestimonialsTable();
    const rows = await prisma.$queryRaw`
      SELECT id, quote, author_name, author_title, status, created_at, reviewed_at
      FROM "Testimonial"
      WHERE provider_id = ${ctx.providerId}
      ORDER BY created_at DESC
      LIMIT 1
    `;
    res.json({ ok: true, testimonial: rows?.[0] || null });
  } catch (err) {
    console.error('Provider testimonial fetch failed', err);
    res.status(500).json({ error: 'Could not load your testimonial.' });
  }
});

// POST /api/provider/testimonial — submit for admin approval
app.post('/api/provider/testimonial', requireProviderAuth, async (req, res) => {
  try {
    const ctx = await getProviderContext(req.providerUserId);
    if (!ctx) return res.status(401).json({ error: 'Unauthorized' });
    await ensureTestimonialsTable();

    const quote = String(req.body?.quote || '').trim();
    const authorName = String(req.body?.author_name || '').trim();
    if (!quote || !authorName) {
      return res.status(400).json({ error: 'Please include your testimonial and your name.' });
    }
    if (quote.length > 600) {
      return res.status(400).json({ error: 'Please keep your testimonial under 600 characters.' });
    }

    // One in-flight submission per provider; resubmitting replaces it.
    const pending = await prisma.$queryRaw`
      SELECT id FROM "Testimonial"
      WHERE provider_id = ${ctx.providerId} AND status = 'pending'
      LIMIT 1
    `;
    if (pending?.length) {
      return res.status(409).json({ error: 'You already have a testimonial awaiting review.' });
    }

    // author_title is set from the listing, not user input, so a provider
    // cannot attribute a quote to somebody else.
    const id = uuid();
    await prisma.$executeRawUnsafe(
      `INSERT INTO "Testimonial" (id, quote, author_name, author_title, active, display_order, status, provider_id)
       VALUES ($1,$2,$3,$4,false,0,'pending',$5)`,
      id, quote, authorName, ctx.provider?.name || '', ctx.providerId
    );

    await logAdminAction(
      'provider_user', 'PROVIDER_TESTIMONIAL_SUBMIT', ctx.providerId,
      { testimonialId: id }, hashIp(req.ip || '')
    );

    res.json({ ok: true, id, status: 'pending' });
  } catch (err) {
    console.error('Provider testimonial submit failed', err);
    res.status(500).json({ error: 'Could not submit your testimonial.' });
  }
});

// PATCH /api/admin/testimonials/:id/status — approve or deny a submission
app.patch('/api/admin/testimonials/:id/status', async (req, res) => {
  if (!hasAdminAccess(req, ['add', 'remove', 'dash', 'audit', 'main'])) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  const status = String(req.body?.status || '').trim().toLowerCase();
  if (!['approved', 'denied', 'pending'].includes(status)) {
    return res.status(400).json({ error: 'status must be approved, denied, or pending' });
  }
  try {
    await ensureTestimonialsTable();
    // Approving publishes it; anything else takes it off the banner.
    await prisma.$executeRawUnsafe(
      `UPDATE "Testimonial" SET status = $1, active = $2, reviewed_at = NOW() WHERE id = $3`,
      status, status === 'approved', req.params.id
    );
    await logAdminAction(
      'admin', 'TESTIMONIAL_REVIEW', req.params.id,
      { status }, hashIp(req.ip || '')
    );
    res.json({ ok: true, status });
  } catch (err) {
    console.error('Testimonial review failed', err);
    res.status(500).json({ error: 'Could not update testimonial status.' });
  }
});

// GET /api/testimonials — public, active testimonials for home page
app.get('/api/testimonials', async (req, res) => {
  try {
    await ensureTestimonialsTable();
    const rows = await prisma.$queryRawUnsafe(
      `SELECT id, quote, author_name, author_title FROM "Testimonial"
       WHERE active = true AND status = 'approved'
       ORDER BY display_order ASC, created_at ASC`
    );
    res.json(rows);
  } catch (err) {
    console.error('Testimonials fetch failed', err);
    res.json([]);
  }
});

// GET /api/admin/testimonials — all testimonials
app.get('/api/admin/testimonials', async (req, res) => {
  if (!hasAdminAccess(req, ['add', 'remove', 'dash', 'audit', 'main'])) return res.status(401).json({ error: 'Unauthorized' });
  try {
    await ensureTestimonialsTable();
    const rows = await prisma.$queryRawUnsafe(`SELECT * FROM "Testimonial" ORDER BY display_order ASC, created_at ASC`);
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: 'Could not load testimonials.' });
  }
});

// POST /api/admin/testimonials — create
app.post('/api/admin/testimonials', async (req, res) => {
  if (!hasAdminAccess(req, ['add', 'remove', 'dash', 'audit', 'main'])) return res.status(401).json({ error: 'Unauthorized' });
  const { quote, author_name, author_title, display_order } = req.body || {};
  if (!quote || !author_name) return res.status(400).json({ error: 'quote and author_name are required.' });
  try {
    await ensureTestimonialsTable();
    const id = uuid();
    await prisma.$executeRawUnsafe(
      `INSERT INTO "Testimonial" (id, quote, author_name, author_title, active, display_order) VALUES ($1,$2,$3,$4,true,$5)`,
      id, String(quote).trim(), String(author_name).trim(), String(author_title || '').trim(), Number(display_order) || 0
    );
    res.json({ ok: true, id });
  } catch (err) {
    res.status(500).json({ error: 'Could not create testimonial.' });
  }
});

// PATCH /api/admin/testimonials/:id — update
app.patch('/api/admin/testimonials/:id', async (req, res) => {
  if (!hasAdminAccess(req, ['add', 'remove', 'dash', 'audit', 'main'])) return res.status(401).json({ error: 'Unauthorized' });
  const { quote, author_name, author_title, active, display_order } = req.body || {};
  try {
    await ensureTestimonialsTable();
    await prisma.$executeRawUnsafe(
      `UPDATE "Testimonial" SET quote=$1, author_name=$2, author_title=$3, active=$4, display_order=$5 WHERE id=$6`,
      String(quote).trim(), String(author_name).trim(), String(author_title || '').trim(),
      Boolean(active), Number(display_order) || 0, req.params.id
    );
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: 'Could not update testimonial.' });
  }
});

// DELETE /api/admin/testimonials/:id — delete
app.delete('/api/admin/testimonials/:id', async (req, res) => {
  if (!hasAdminAccess(req, ['add', 'remove', 'dash', 'audit', 'main'])) return res.status(401).json({ error: 'Unauthorized' });
  try {
    await ensureTestimonialsTable();
    await prisma.$executeRawUnsafe(`DELETE FROM "Testimonial" WHERE id=$1`, req.params.id);
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: 'Could not delete testimonial.' });
  }
});

// POST /api/discharge-referral — submit a discharge planner referral
app.post('/api/discharge-referral', async (req, res) => {
  if (req.body?.website) return res.json({ ok: true });
  try {
    await ensureDischargeReferralTable();
    const {
      planner_name, planner_title, planner_email, planner_phone,
      facility, patient_first, patient_last, patient_zip,
      care_type, urgency, insurance, notes, captchaToken
    } = req.body || {};
    if (!planner_name || !planner_email || !facility || !patient_first || !patient_last || !patient_zip || !care_type || !urgency) {
      return res.status(400).json({ error: 'Missing required fields.' });
    }
    if (captchaToken) {
      const captchaResult = await verifyTurnstile(captchaToken, req.ip);
      if (!captchaResult.success && !captchaResult.bypass) {
        return res.status(403).json({ error: 'Captcha verification failed.' });
      }
    }
    const id = uuid();
    await prisma.$executeRawUnsafe(
      `INSERT INTO "DischargeReferral" (id, planner_name, planner_title, planner_email, planner_phone, facility, patient_first, patient_last, patient_zip, care_type, urgency, insurance, notes, status, source)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,'new','discharge_planner')`,
      id,
      String(planner_name || '').trim(),
      String(planner_title || '').trim(),
      String(planner_email || '').trim().toLowerCase(),
      String(planner_phone || '').trim(),
      String(facility || '').trim(),
      String(patient_first || '').trim(),
      String(patient_last || '').trim(),
      String(patient_zip || '').trim(),
      String(care_type || '').trim(),
      String(urgency || '').trim(),
      String(insurance || '').trim(),
      String(notes || '').trim()
    );
    if (EMAIL_ENABLED && planner_email) {
      const careLabels = { hospice: 'Hospice Care', home_health: 'Home Health Care', palliative: 'Palliative Care', unsure: 'Unsure — Needs Guidance' };
      const urgencyLabels = { immediate: 'Immediate (today/tomorrow)', within_week: 'Within the week', planning_ahead: 'Planning ahead (2+ weeks)' };
      const html = `<div style="font-family:sans-serif;max-width:560px;">
        <h2 style="color:#0f2744;">Referral Received — Best Hospice & Home Health</h2>
        <p>Hi ${String(planner_name).split(' ')[0]},</p>
        <p>We've received your referral for <strong>${String(patient_first).trim()} ${String(patient_last).trim()}</strong> (ZIP: ${String(patient_zip).trim()}).</p>
        <p><strong>Care type:</strong> ${careLabels[care_type] || care_type}<br>
        <strong>Urgency:</strong> ${urgencyLabels[urgency] || urgency}</p>
        <p>We'll match this patient with verified providers in their area within 24 hours. You'll be kept informed as the referral progresses.</p>
        <p>Thank you for trusting Best Hospice & Home Health.<br><br>— The Best Hospice Team</p>
      </div>`;
      sendGenericEmail(String(planner_email).trim().toLowerCase(), 'Referral Received — Best Hospice & Home Health', html).catch(() => {});
    }
    // Notify providers in the patient's area
    if (EMAIL_ENABLED) {
      try {
        const geo = await geocodeAddress(`${String(patient_zip).trim()}, USA`).catch(() => null);
        const allProviders = await prisma.provider.findMany({
          select: { id: true, email: true, secondaryContactEmail: true, lat: true, lon: true, serviceRadiusKm: true }
        });
        const nearbyProviders = geo
          ? allProviders.filter((p) => {
              const radiusKm = Number(p.serviceRadiusKm) || 96.6;
              return haversineKm(geo.lat, geo.lon, p.lat, p.lon) <= radiusKm;
            })
          : allProviders;
        const providerList = nearbyProviders.map((p) => ({
          id: p.id,
          emails: [p.email, p.secondaryContactEmail].filter(Boolean)
        }));
        if (providerList.length) {
          sendDischargeReferralNotifications({
            patientName: `${String(patient_first).trim()} ${String(patient_last).trim()}`,
            patientZip: String(patient_zip).trim(),
            careType: String(care_type).trim(),
            urgency: String(urgency).trim(),
            plannerName: String(planner_name).trim(),
            plannerTitle: String(planner_title || '').trim(),
            plannerEmail: String(planner_email).trim(),
            plannerPhone: String(planner_phone || '').trim(),
            facility: String(facility).trim(),
            insurance: String(insurance || '').trim(),
            notes: String(notes || '').trim(),
            providers: providerList
          }).catch((err) => console.error('Discharge referral provider notifications failed', err));
        }
      } catch (err) {
        console.error('Could not fetch providers for discharge referral notification', err);
      }
    }
    res.json({ ok: true });
  } catch (err) {
    console.error('Discharge referral failed', err);
    res.status(500).json({ error: 'Could not submit referral. Please try again.' });
  }
});

// GET /api/admin/discharge-referrals — list all referrals (admin only)
app.get('/api/admin/discharge-referrals', async (req, res) => {
  if (!hasAdminAccess(req, ['add', 'remove', 'dash', 'audit', 'main'])) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  try {
    await ensureDischargeReferralTable();
    const rows = await prisma.$queryRawUnsafe(
      `SELECT * FROM "DischargeReferral" ORDER BY submitted_at DESC`
    );
    res.json(rows);
  } catch (err) {
    console.error('Discharge referrals fetch failed', err);
    res.status(500).json({ error: 'Could not load referrals.' });
  }
});

// DELETE /api/admin/discharge-referrals/:id — delete a referral (admin only)
app.delete('/api/admin/discharge-referrals/:id', async (req, res) => {
  if (!hasAdminAccess(req, ['add', 'remove', 'dash', 'audit', 'main'])) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  try {
    await ensureDischargeReferralTable();
    await prisma.$executeRawUnsafe(`DELETE FROM "DischargeReferral" WHERE id = $1`, req.params.id);
    res.json({ ok: true });
  } catch (err) {
    console.error('Discharge referral delete failed', err);
    res.status(500).json({ error: 'Could not delete referral.' });
  }
});

// PATCH /api/admin/discharge-referrals/:id/status — update referral status (admin only)
app.patch('/api/admin/discharge-referrals/:id/status', async (req, res) => {
  if (!hasAdminAccess(req, ['add', 'remove', 'dash', 'audit', 'main'])) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  const { id } = req.params;
  const status = String(req.body?.status || '').trim().toLowerCase();
  if (!['new', 'contacted', 'matched', 'closed'].includes(status)) {
    return res.status(400).json({ error: 'Invalid status. Must be new, contacted, matched, or closed.' });
  }
  try {
    await ensureDischargeReferralTable();
    await prisma.$executeRawUnsafe(
      `UPDATE "DischargeReferral" SET status = $1 WHERE id = $2`,
      status, id
    );
    res.json({ ok: true });
  } catch (err) {
    console.error('Discharge referral status update failed', err);
    res.status(500).json({ error: 'Could not update status.' });
  }
});

app.get('/robots.txt', (_req, res) => {
  res.type('text/plain').send(`User-agent: *
Allow: /
Sitemap: ${CANONICAL_DOMAIN}/sitemap.xml
Sitemap: ${CANONICAL_DOMAIN}/sitemap-pages.xml
Sitemap: ${CANONICAL_DOMAIN}/sitemap-locations.xml
Sitemap: ${CANONICAL_DOMAIN}/sitemap-providers.xml
`);
});

app.get('/llms.txt', (_req, res) => {
  res.sendFile(path.join(__dirname, 'llms.txt'));
});

app.get('/llms', (_req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'llms.html'));
});

Promise.all([
  ensureWaitlistTable(),
  ensureJobLeadTable(),
  ensureDischargeReferralTable(),
  ensureTestimonialsTable()
]).catch((err) => console.error('Table setup failed:', err)).finally(() => {
  app.listen(PORT, () => {
    console.log(`Best Hospice and Home Health server running on http://localhost:${PORT}`);
    fixTusconProviderData();
    if (!EMAIL_ENABLED) {
      console.log('Email not configured: set SENDGRID_API_KEY and SENDGRID_FROM_EMAIL (optional: SENDGRID_REPLY_TO)');
    }
    if (!NEWSLETTER_UNSUBSCRIBE_SECRET) {
      console.warn('NEWSLETTER_UNSUBSCRIBE_SECRET is not set. Newsletter unsubscribe tokens will use an insecure default. Set this env var in production.');
    }
    // Newsletter cron: every other Tuesday at 13:00 ET (18:00 UTC)
    cron.schedule('0 18 * * 2', () => {
      runNewsletterPipeline(prisma).catch((err) => {
        console.error('Newsletter cron pipeline error:', err.message);
      });
    }, { timezone: 'UTC' });
  });
});
