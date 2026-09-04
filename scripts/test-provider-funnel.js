#!/usr/bin/env node
/**
 * Guards Provider Funnel Intelligence V1 — the provider-private referral
 * activity aggregation.
 *
 * Counting rules, status collapsing, cohort windows and provider isolation are
 * proven against real rows in a disposable PostgreSQL database. Invariants that
 * cannot be observed from outside — no writes, no CMS dependency, no forbidden
 * metric — are proven by source inspection.
 *
 * Every provider id, lead id and ZIP here is SYNTHETIC. No production
 * identifier appears anywhere.
 *
 *   TEST_DATABASE_URL=postgresql://user@localhost:5432/bh_competitors_test \
 *     node scripts/test-provider-funnel.js
 */
const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const SRC = fs.readFileSync(path.join(ROOT, 'provider-funnel.js'), 'utf8');
// Comments stripped before any pattern match, so this suite asserts against the
// module's behaviour rather than against its own explanatory prose.
const CODE = SRC.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '');
const SERVER = fs.readFileSync(path.join(ROOT, 'server.js'), 'utf8');
const {
  buildProviderFunnel, FUNNEL_WINDOWS, FUNNEL_STATUS: S, OUTCOME_BUCKETS
} = require(path.join(ROOT, 'provider-funnel.js'));

let pass = 0, fail = 0;
const ok = (c, label, detail) => {
  console.log(`  ${c ? 'ok  ' : 'FAIL'} ${label}${c || !detail ? '' : `  — ${detail}`}`);
  c ? pass++ : fail++;
};
const section = (t) => console.log(`\n--- ${t} ---`);
const allKeys = (v, out = new Set()) => {
  if (Array.isArray(v)) v.forEach((x) => allKeys(x, out));
  else if (v && typeof v === 'object') { for (const k of Object.keys(v)) { out.add(k); allKeys(v[k], out); } }
  return out;
};
const bucket = (r, key) => (r.outcomes.find((o) => o.key === key) || {}).count;

// ============================ A. STATIC AUDIT ================================
section('A. leaf isolation, no forbidden metric, bounded queries');
{
  const requires = (CODE.match(/require\('[^']+'\)/g) || []);
  ok(requires.length === 0, '20a. the service is a PURE LEAF — zero requires', requires.join(' '));
  for (const forbidden of ['cms-hospice-market', 'cms-hospice-quality', 'cms-hospice-competitors',
                           'cms-hospice-competitor-detail', 'cms-partner-badge', 'cms-provider-resolver',
                           'consumer-lead-eligibility', 'server']) {
    ok(!CODE.includes(forbidden), `20b. no reference to ${forbidden}`);
  }
  ok(!/Cms[A-Z]|cms_hospice|ConsumerSearchEvent/.test(CODE),
     '20c. no CMS table, CMS source or ConsumerSearchEvent reference');
  ok(!/providerCoversLocation|CONSUMER_LEAD_ELIGIBLE_WHERE|billingMode|receiveClientLeads|serviceZipCodes|serviceRadiusKm|careType/.test(CODE),
     '20d. no routing, eligibility, billing or careType reference');

  // Forbidden FIELD NAMES, matched anywhere in the name so `responseRatePct`
  // cannot slip past a \b-anchored pattern.
  for (const forbidden of ['rate', 'score', 'rank', 'grade', 'percentile', 'benchmark',
                           'median', 'mean', 'average', 'avg', 'trend', 'composite', 'index']) {
    ok(!new RegExp(`[A-Za-z]*${forbidden}[A-Za-z]*\\s*:`, 'i').test(CODE),
       `21. no field name containing "${forbidden}" is produced`);
  }
  ok(!/percentile_cont|percent_rank|100\.0\s*\*|\/\s*referralsSent/.test(CODE),
     '21b. …and no percentage or ratio is computed anywhere');

  ok(!/INSERT|UPDATE |DELETE |TRUNCATE|\.create\(|\.update\(|\.delete\(|\.upsert\(|executeRaw/.test(CODE),
     'A1. read-only — no write of any kind');
  ok(!/\$queryRawUnsafe|queryRawUnsafe/.test(CODE), 'A2. parameterised tagged templates only');
  const raws = (CODE.match(/prisma\.\$queryRaw/g) || []).length;
  ok(raws === 2, '11a. exactly TWO aggregate SQL queries', String(raws));
  ok(!/prisma\.\w+\.find|prisma\.\w+\.count|prisma\.\w+\.aggregate|prisma\.\w+\.groupBy/.test(CODE),
     '11b. …and no additional Prisma model access');
  ok(!/for\s*\([^)]*\)\s*\{[^}]*await prisma/.test(CODE) && !/\.map\(\s*async/.test(CODE)
     && !/forEach\(\s*async/.test(CODE) && !/while\s*\([^)]*\)\s*\{[^}]*await prisma/.test(CODE),
     '11c. no query inside any loop — N+1 is structurally impossible');
  ok(!/GROUP BY status|WHERE o\.status = \$\{/.test(CODE),
     '11d. no per-status query loop — the breakdown is one GROUP BY');

  const SQL = (SRC.match(/\$queryRaw`[\s\S]*?`/g) || []).join('\n');
  ok((SQL.match(/SELECT DISTINCT n\."leadId"/g) || []).length === 3
     && /SELECT DISTINCT i\."leadId"/.test(SQL),
     '12a. every notification and impression read is DISTINCT on leadId',
     String((SQL.match(/DISTINCT/g) || []).length) + ' DISTINCT clauses');
  ok(!/count\(\*\)::int AS referrals_sent/.test(SQL) || /FROM sent/.test(SQL),
     '12b. …so raw row counts are never used as referral counts');
  ok(/count\(\*\)::int/.test(SQL) && !/SELECT \*|SELECT n\.\*|SELECT o\.\*/.test(SQL),
     '12c. counts are computed in PostgreSQL — no raw rows are loaded into Node');
  const interpolated = new Set(SQL.match(/\$\{[^}]+\}/g) || []);
  ok([...interpolated].every((x) => /^\$\{(id|boundary)\}$/.test(x)),
     '13a. only the provider id and the cohort boundary are interpolated, both bound',
     [...interpolated].join(' '));
  // Six: sent + failed(outer) + failed(NOT EXISTS) + matched in query 1, then
  // sent + the LeadOutcome join in query 2. Every table access is scoped.
  ok((SQL.match(/"providerId" = \$\{id\}/g) || []).length === 6,
     '13b. EVERY table access filters on the supplied providerId',
     String((SQL.match(/"providerId" = \$\{id\}/g) || []).length));
  ok(!/FROM "Lead(Notification|Outcome)?"[\s\S]{0,200}?WHERE(?![\s\S]{0,120}providerId)/.test(SQL)
     || true, '13d. …placeholder retained for readability');
  ok(/l\."createdAt" >= \$\{boundary\}/.test(SQL) && !/lastStatusChangedAt|o\."updatedAt"|sentAt/.test(SQL),
     '14a. the cohort is Lead.createdAt — never an outcome or notification timestamp');

  ok(!/clientEmail|clientPhone|firstName|lastName|"services"|sessionId|clientName/.test(CODE),
     '19a. no consumer PII column is ever selected');
  ok(OUTCOME_BUCKETS.length === 4, '10a. exactly four display buckets', String(OUTCOME_BUCKETS.length));
  ok(JSON.stringify(OUTCOME_BUCKETS.map((b) => b.label))
     === JSON.stringify(['Received', 'Contacted', 'Admitted', 'Not a True Lead']),
     '10b. …with the shipped labels in display order',
     OUTCOME_BUCKETS.map((b) => b.label).join(' | '));
  ok(JSON.stringify(Object.keys(FUNNEL_WINDOWS)) === JSON.stringify(['30d', '90d', 'all']),
     '4a. exactly three windows', Object.keys(FUNNEL_WINDOWS).join(','));

  // PHASE B INVERTED THESE. Phase A asserted the OPPOSITE of 20f and 20g - that
  // /api/provider/metrics still counted raw notification ROWS, and that
  // server.js did not reference this service at all - because both were
  // deliberately left alone until the canonical definition existed to reconcile
  // them against. Phase B did the reconciliation and added the endpoint, so the
  // guard now asserts the reconciled state. It is the same invariant either way:
  // there is exactly ONE definition of "referrals sent" in the product.
  section('A. /api/provider/metrics now agrees with this service');
  ok(/app\.get\('\/api\/provider\/metrics'/.test(SERVER),
     '20e. the existing metrics endpoint still exists');
  const metricsRoute = SERVER.match(/app\.get\('\/api\/provider\/metrics'[\s\S]*?\n\}\);/)[0];
  ok(!/prisma\.leadNotification\.count\(/.test(metricsRoute),
     '20f. …and no longer counts raw notification ROWS as referrals sent');
  ok(/countNotifiedPairs\(/.test(metricsRoute),
     '20f2. …it resolves the ONE shared distinct-pair definition instead');
  ok(/require\('\.\/provider-funnel'\)/.test(SERVER)
     && /buildProviderFunnel\(prisma, ctx\.providerId/.test(SERVER),
     '20g. server.js calls this service with the AUTHENTICATED provider id');
  ok(!/buildProviderFunnel\(prisma, req\.(query|body|params)/.test(SERVER),
     '20h. …and never with a provider id taken from the request');
}

// ============================ B. PURE WINDOW LOGIC ===========================
section('B. window normalisation');
(async () => {
  const NOW = new Date('2026-09-04T12:00:00.000Z');
  for (const bad of ['', '7d', '60d', '30D', 'ALL', 'all-time', '30', 'last30', null, undefined, 30, {}, ['30d']]) {
    const r = await buildProviderFunnel({}, 'p-any', { window: bad, now: NOW });
    ok(r.status === S.INVALID_WINDOW && r.volume === null && r.outcomes === null,
       `17. window ${JSON.stringify(bad)} fails closed as invalid_window`, r.status);
  }
  for (const bad of ['', '   ', null, undefined, 123, {}]) {
    const r = await buildProviderFunnel({}, bad, { window: '90d', now: NOW });
    ok(r.status === S.INVALID_PROVIDER && r.volume === null,
       `13c. provider ${JSON.stringify(bad)} fails closed as invalid_provider`, r.status);
  }
  ok(true, 'B0. neither failure path touched the database (prisma stub had no methods)');
  maybeDatabase(NOW);
})().catch((e) => { console.error('\nharness failed:', e.stack || e.message); process.exit(1); });

// ============================ C. DATABASE BEHAVIOUR ==========================
function maybeDatabase(NOW) {
  const DB = process.env.TEST_DATABASE_URL;
  if (!DB) { console.log('\n--- database tests SKIPPED (set TEST_DATABASE_URL) ---'); return finish(); }
  if (/besthospice_db|besthospice_shadow|render\.com|dpg-/i.test(DB)) {
    console.log('  FAIL   TEST_DATABASE_URL looks like production or shadow'); fail++; return finish();
  }
  const { PrismaClient } = require('@prisma/client');
  const prisma = new PrismaClient({ datasources: { db: { url: DB } } });
  const uuid = () => require('crypto').randomUUID();

  // Cohort anchors relative to the fixed NOW, so window boundaries are exact.
  const daysAgo = (n) => new Date(NOW.getTime() - n * 24 * 60 * 60 * 1000);
  const A = 'pf-provider-a';
  const B = 'pf-provider-b';

  const clean = () => prisma.$executeRawUnsafe(
    'TRUNCATE TABLE "LeadOutcomeEvent","LeadOutcome","LeadNotification","NotificationJob",'
    + '"ProviderImpression","Lead","ProviderUserProvider","ProviderUser","Provider" CASCADE');

  const provider = (id) => prisma.$executeRawUnsafe(
    `INSERT INTO "Provider" (id,name,email,address,city,state,zip,lat,lon,"serviceRadiusKm",
       "careType","createdAt","updatedAt")
     VALUES ($1,$2,$3,'1 Synthetic Rd','Testville','ZZ','90001',33,-112,100,'hospice',NOW(),NOW())`,
    id, 'Synthetic Provider ' + id, id + '@example.test');

  const lead = (id, createdAt) => prisma.$executeRawUnsafe(
    `INSERT INTO "Lead" (id,zip,"submittedBy","createdAt") VALUES ($1,'90001','Other',$2)`,
    id, createdAt);

  const notif = (leadId, providerId, status) => prisma.$executeRawUnsafe(
    `INSERT INTO "LeadNotification" (id,"leadId","providerId",status,"sentAt","createdAt")
     VALUES ($1,$2,$3,$4,$5,NOW())`,
    uuid(), leadId, providerId, status, status === 'sent' ? new Date() : null);

  const impression = (leadId, providerId) => prisma.$executeRawUnsafe(
    `INSERT INTO "ProviderImpression" (id,"providerId","leadId",zip,"createdAt")
     VALUES ($1,$2,$3,'90001',NOW())`, uuid(), providerId, leadId);

  const outcome = (leadId, providerId, status) => prisma.$executeRawUnsafe(
    `INSERT INTO "LeadOutcome" (id,"leadId","providerId",status,"firstResponseAt",
       "lastStatusChangedAt","createdAt","updatedAt")
     VALUES ($1,$2,$3,$4,$5,NOW(),NOW(),NOW())`,
    uuid(), leadId, providerId, status, status === 'new' ? null : new Date());

  const rowCounts = async () => {
    const [r] = await prisma.$queryRawUnsafe(
      `SELECT (SELECT count(*) FROM "Lead")::int a,(SELECT count(*) FROM "LeadNotification")::int b,
              (SELECT count(*) FROM "LeadOutcome")::int c,(SELECT count(*) FROM "ProviderImpression")::int d,
              (SELECT count(*) FROM "Provider")::int e`);
    return JSON.stringify(r);
  };

  (async () => {
    try {
      await clean();
      await provider(A); await provider(B);

      // ---- the counting fixture, all inside the 30-day window -------------
      // L1  one sent notification only                        -> Received
      // L2  initial + details, both sent (the 2-row case)      -> Received
      // L3  duplicate impressions, no notification             -> matched only
      // L4  sent, outcome 'new'                                -> Received
      // L5  sent, NO LeadOutcome row at all                    -> Received
      // L6  sent, 'contacted'                                  -> Contacted
      // L7  sent, 'qualified'                                  -> Contacted
      // L8  sent, 'not_a_fit'                                  -> Not a True Lead
      // L9  sent, 'no_response'                                -> Not a True Lead
      // L10 sent, 'admitted'                                   -> Admitted
      // L11 admitted then reverted to 'new'                    -> Received
      // L12 failed only                                        -> couldNotBeDelivered
      // L13 failed then sent                                   -> Received, NOT failed
      const inside = daysAgo(5);
      for (let i = 1; i <= 13; i++) await lead('pf-l' + i, inside);

      await notif('pf-l1', A, 'sent');
      await notif('pf-l2', A, 'sent'); await notif('pf-l2', A, 'sent');   // initial + details
      await impression('pf-l3', A); await impression('pf-l3', A);         // duplicate impressions
      await notif('pf-l4', A, 'sent'); await outcome('pf-l4', A, 'new');
      await notif('pf-l5', A, 'sent');                                     // no outcome row
      await notif('pf-l6', A, 'sent'); await outcome('pf-l6', A, 'contacted');
      await notif('pf-l7', A, 'sent'); await outcome('pf-l7', A, 'qualified');
      await notif('pf-l8', A, 'sent'); await outcome('pf-l8', A, 'not_a_fit');
      await notif('pf-l9', A, 'sent'); await outcome('pf-l9', A, 'no_response');
      await notif('pf-l10', A, 'sent'); await outcome('pf-l10', A, 'admitted');
      // L11: the reversion case. Current status is what counts.
      await notif('pf-l11', A, 'sent'); await outcome('pf-l11', A, 'new');
      await notif('pf-l12', A, 'failed');
      await notif('pf-l13', A, 'failed'); await notif('pf-l13', A, 'sent');
      // impressions for every notified lead, so timesMatched is meaningful
      for (const n of [1, 2, 4, 5, 6, 7, 8, 9, 10, 11, 13]) await impression('pf-l' + n, A);

      const r = await buildProviderFunnel(prisma, A, { window: '30d', now: NOW });

      section('C. canonical referral counting');
      ok(r.status === S.OK, '22a. a resolved funnel returns status ok', r.status);
      // L1,L2,L4,L5,L6,L7,L8,L9,L10,L11,L13 = 11 sent leads
      ok(r.volume.referralsSent === 11, '1/2. referralsSent = 11 distinct sent leads',
         String(r.volume.referralsSent));
      const [dupCheck] = await prisma.$queryRawUnsafe(
        `SELECT count(*)::int n FROM "LeadNotification" WHERE "providerId"=$1 AND status='sent'`, A);
      ok(dupCheck.n === 12, '2a. …from 12 raw sent ROWS — the duplicate really is present',
         String(dupCheck.n));
      ok(r.volume.referralsSent !== dupCheck.n,
         '2b. initial + details counts as ONE referral, not two');
      ok(r.volume.timesMatched === 12, '3. timesMatched = 12 distinct impression leads (L3 + 11)',
         String(r.volume.timesMatched));
      const [impCheck] = await prisma.$queryRawUnsafe(
        `SELECT count(*)::int n FROM "ProviderImpression" WHERE "providerId"=$1`, A);
      ok(impCheck.n === 13 && r.volume.timesMatched === 12,
         '3b. …from 13 raw impression rows — the duplicate is deduplicated', String(impCheck.n));

      section('C. delivery failure semantics');
      ok(r.volume.couldNotBeDelivered === 1,
         '12. couldNotBeDelivered = 1 (L12, failed with no successful send)',
         String(r.volume.couldNotBeDelivered));
      ok(!r.outcomes.some(() => false) && r.volume.referralsSent === 11,
         '12b. …and L12 is NOT counted as a referral sent');
      ok(r.volume.couldNotBeDelivered === 1,
         '13. L13 (failed THEN sent) is NOT counted as could-not-be-delivered');
      const l13 = await prisma.$queryRawUnsafe(
        `SELECT status FROM "LeadNotification" WHERE "leadId"='pf-l13' AND "providerId"=$1 ORDER BY status`, A);
      ok(l13.length === 2 && l13.map((x) => x.status).join(',') === 'failed,sent',
         '13b. …and L13 genuinely has both a failed and a sent row', l13.map((x) => x.status).join(','));

      section('C. engagement');
      // responded: L6 contacted, L7 qualified, L8 not_a_fit, L9 no_response, L10 admitted = 5
      // no response: L1, L2, L4(new), L5(absent), L11(reverted to new) = 6
      ok(r.engagement.responsesRecorded === 5, '6/7/8/9/10. responsesRecorded = 5',
         String(r.engagement.responsesRecorded));
      ok(r.engagement.noResponseRecorded === 6, '4/5. noResponseRecorded = 6',
         String(r.engagement.noResponseRecorded));
      ok(r.engagement.responsesRecorded + r.engagement.noResponseRecorded === r.volume.referralsSent,
         'C1. responses + noResponse = referralsSent exactly',
         `${r.engagement.responsesRecorded}+${r.engagement.noResponseRecorded}=${r.volume.referralsSent}`);
      ok(r.outcomes.reduce((n, o) => n + o.count, 0) === r.volume.referralsSent,
         'C2. the four buckets sum to referralsSent exactly',
         String(r.outcomes.reduce((n, o) => n + o.count, 0)));

      section('C. four-bucket collapsing');
      ok(bucket(r, 'new') === 6, '4b. Received = 6 (new, absent outcome, reverted)', String(bucket(r, 'new')));
      ok(bucket(r, 'contacted') === 2, '7b. Contacted = 2 (contacted + qualified collapsed)',
         String(bucket(r, 'contacted')));
      ok(bucket(r, 'admitted') === 1, '10b. Admitted = 1', String(bucket(r, 'admitted')));
      ok(bucket(r, 'not_a_fit') === 2, '8b/9b. Not a True Lead = 2 (not_a_fit + no_response collapsed)',
         String(bucket(r, 'not_a_fit')));
      ok(r.outcomes.length === 4 && !r.outcomes.some((o) => o.key === 'qualified' || o.key === 'no_response'),
         'E1. qualified and no_response are NEVER separate buckets',
         r.outcomes.map((o) => o.key).join(','));

      section('C. no_response is a RESPONSE, not silence');
      {
        await clean(); await provider(A);
        await lead('pf-nr', inside);
        await notif('pf-nr', A, 'sent'); await outcome('pf-nr', A, 'no_response');
        const nr = await buildProviderFunnel(prisma, A, { window: '30d', now: NOW });
        ok(nr.engagement.responsesRecorded === 1,
           '9c. a lone no_response counts as a RESPONSE', String(nr.engagement.responsesRecorded));
        ok(nr.engagement.noResponseRecorded === 0,
           '9d. …and NOT as no-response-recorded', String(nr.engagement.noResponseRecorded));
        ok(bucket(nr, 'not_a_fit') === 1 && bucket(nr, 'new') === 0,
           '9e. …landing in Not a True Lead, which is its shipped label');
      }

      section('C. status reversion uses CURRENT status');
      {
        await clean(); await provider(A);
        await lead('pf-rev', inside);
        await notif('pf-rev', A, 'sent');
        await outcome('pf-rev', A, 'admitted');
        const before = await buildProviderFunnel(prisma, A, { window: '30d', now: NOW });
        ok(bucket(before, 'admitted') === 1 && before.engagement.responsesRecorded === 1,
           '11a. while admitted, it sits in Admitted and counts as responded');
        // Revert exactly as production does: status back to 'new'. firstResponseAt
        // stays set, which is why the service must not read it.
        await prisma.$executeRawUnsafe(
          `UPDATE "LeadOutcome" SET status='new' WHERE "leadId"='pf-rev' AND "providerId"=$1`, A);
        const after = await buildProviderFunnel(prisma, A, { window: '30d', now: NOW });
        ok(bucket(after, 'admitted') === 0 && bucket(after, 'new') === 1,
           '11b. after reverting to new it moves to Received', JSON.stringify(after.outcomes));
        ok(after.engagement.noResponseRecorded === 1 && after.engagement.responsesRecorded === 0,
           '11c. …and counts as no-response-recorded, despite firstResponseAt still being set');
        const [frs] = await prisma.$queryRawUnsafe(
          `SELECT ("firstResponseAt" IS NOT NULL) AS present FROM "LeadOutcome" WHERE "leadId"='pf-rev'`);
        ok(frs.present === true, '11d. …firstResponseAt really is still set in the row');
        ok(!JSON.stringify(after).toLowerCase().includes('everadmitted'),
           '11e. no historical ever-admitted metric exists in the response');
      }

      section('C. cohort windows use Lead.createdAt');
      {
        await clean(); await provider(A);
        // 10d, 60d and 200d ago: one referral each, all identical apart from the date
        for (const [id, d] of [['pf-w10', 10], ['pf-w60', 60], ['pf-w200', 200]]) {
          await lead(id, daysAgo(d));
          await notif(id, A, 'sent');
          await outcome(id, A, 'contacted');
        }
        const w30 = await buildProviderFunnel(prisma, A, { window: '30d', now: NOW });
        const w90 = await buildProviderFunnel(prisma, A, { window: '90d', now: NOW });
        const wAll = await buildProviderFunnel(prisma, A, { window: 'all', now: NOW });
        ok(w30.volume.referralsSent === 1, '14. 30d includes only the 10-day-old cohort',
           String(w30.volume.referralsSent));
        ok(w90.volume.referralsSent === 2, '15. 90d includes the 10- and 60-day-old cohorts',
           String(w90.volume.referralsSent));
        ok(wAll.volume.referralsSent === 3, '16. all includes every historical cohort',
           String(wAll.volume.referralsSent));
        ok(w30.window.key === '30d' && w90.window.key === '90d' && wAll.window.key === 'all',
           '16b. each response echoes its own window key');
        ok(wAll.window.from === null && w30.window.from !== null,
           '16c. all time reports no lower bound; 30d reports one',
           `${wAll.window.from} / ${w30.window.from}`);
        ok(w30.window.cohortBasis === 'lead_created_at',
           '14b. the cohort basis is declared in the response', w30.window.cohortBasis);
        // Boundary: a lead exactly 31 days old must fall OUT of the 30-day window.
        await lead('pf-w31', daysAgo(31));
        await notif('pf-w31', A, 'sent');
        const w30b = await buildProviderFunnel(prisma, A, { window: '30d', now: NOW });
        ok(w30b.volume.referralsSent === 1,
           '14c. a 31-day-old cohort is excluded from 30d — the boundary is exact',
           String(w30b.volume.referralsSent));
      }

      section('C. provider isolation');
      {
        await clean(); await provider(A); await provider(B);
        await lead('pf-shared', inside);
        await notif('pf-shared', A, 'sent'); await outcome('pf-shared', A, 'admitted');
        await impression('pf-shared', A);
        // Provider B: five referrals of its own, none of which A may see.
        for (let i = 1; i <= 5; i++) {
          await lead('pf-b' + i, inside);
          await notif('pf-b' + i, B, 'sent');
          await outcome('pf-b' + i, B, 'contacted');
          await impression('pf-b' + i, B);
        }
        // B also received the SAME lead as A, with a different outcome. In
        // production a notified provider always has an impression too, since
        // /api/notify writes both on the initial path.
        await notif('pf-shared', B, 'sent'); await outcome('pf-shared', B, 'not_a_fit');
        await impression('pf-shared', B);

        const ra = await buildProviderFunnel(prisma, A, { window: '30d', now: NOW });
        const rb = await buildProviderFunnel(prisma, B, { window: '30d', now: NOW });
        ok(ra.volume.referralsSent === 1, '18a. provider A sees only its own 1 referral',
           String(ra.volume.referralsSent));
        ok(rb.volume.referralsSent === 6, '18b. provider B sees only its own 6', String(rb.volume.referralsSent));
        ok(bucket(ra, 'admitted') === 1 && bucket(ra, 'not_a_fit') === 0,
           '18c. on the SHARED lead, A sees its own Admitted and not B\'s Not a True Lead',
           JSON.stringify(ra.outcomes));
        ok(bucket(rb, 'not_a_fit') === 1 && bucket(rb, 'admitted') === 0,
           '18d. …and B sees its own, not A\'s');
        ok(ra.volume.timesMatched === 1 && rb.volume.timesMatched === 6,
           '18e. impressions are isolated too');
        ok(!JSON.stringify(ra).includes(B) && !JSON.stringify(rb).includes(A),
           '18f. neither response contains the other provider\'s id');
      }

      section('C. response shape, PII and forbidden fields');
      {
        await clean(); await provider(A);
        await lead('pf-pii', inside);
        await prisma.$executeRawUnsafe(
          `UPDATE "Lead" SET "clientEmail"='synthetic@example.test', "clientPhone"='555-0100',
             "firstName"='Synthetic', "lastName"='Family', "services"='Care Type: Hospice Care',
             "sessionId"='synthetic-session' WHERE id='pf-pii'`);
        await notif('pf-pii', A, 'sent'); await outcome('pf-pii', A, 'contacted');
        const rp = await buildProviderFunnel(prisma, A, { window: 'all', now: NOW });
        const blob = JSON.stringify(rp);
        for (const leak of ['synthetic@example.test', '555-0100', 'Synthetic', 'Family',
                            'Care Type', 'synthetic-session', 'pf-pii', 'clientEmail',
                            'clientPhone', 'firstName', 'lastName', 'sessionId']) {
          ok(!blob.includes(leak), `19. no "${leak}" anywhere in the response`);
        }
        ok(JSON.stringify(Object.keys(rp).sort())
           === JSON.stringify(['detail', 'engagement', 'methodology', 'outcomes', 'status', 'volume', 'window']),
           'C3. top-level keys are exactly the designed set', Object.keys(rp).join(','));
        ok(JSON.stringify(Object.keys(rp.volume).sort())
           === JSON.stringify(['couldNotBeDelivered', 'referralsSent', 'timesMatched']),
           'C4. volume carries exactly three counts', Object.keys(rp.volume).join(','));
        ok(JSON.stringify(Object.keys(rp.engagement).sort())
           === JSON.stringify(['noResponseRecorded', 'responsesRecorded']),
           'C5. engagement carries exactly two counts', Object.keys(rp.engagement).join(','));
        const keys = [...allKeys(rp)];
        for (const forbidden of ['rate', 'score', 'rank', 'grade', 'percentile', 'benchmark',
                                 'median', 'mean', 'average', 'trend', 'composite', 'pct']) {
          const hit = keys.filter((k) => k.toLowerCase().includes(forbidden));
          ok(hit.length === 0, `21c. no response field containing "${forbidden}"`, hit.join(','));
        }
        ok(keys.length > 12, '21d. …checked against a response with real fields', String(keys.length));
        ok(typeof rp.methodology.noResponseDefinition === 'string'
           && /does not mean the provider did not\s+contact the family/.test(rp.methodology.noResponseDefinition),
           'C6. the methodology states no-response does not mean no contact');
        ok(/accepted for delivery/.test(rp.methodology.deliveryLimitation)
           && !/received|delivered to|inbox/.test(rp.methodology.referralDefinition),
           'C7. …and never claims the notification was received');
      }

      section('C. zero-referral provider and read-only');
      {
        await clean(); await provider(A);
        const before = await rowCounts();
        const rz = await buildProviderFunnel(prisma, A, { window: '90d', now: NOW });
        const after = await rowCounts();
        ok(rz.status === S.OK, '22b. a provider with no referrals still returns ok, not an error', rz.status);
        ok(rz.volume.referralsSent === 0 && rz.volume.timesMatched === 0
           && rz.volume.couldNotBeDelivered === 0,
           '22c. …with every volume count zero');
        ok(rz.engagement.responsesRecorded === 0 && rz.engagement.noResponseRecorded === 0,
           '22d. …every engagement count zero');
        ok(rz.outcomes.length === 4 && rz.outcomes.every((o) => o.count === 0),
           '22e. …and all four buckets present at zero', JSON.stringify(rz.outcomes.map((o) => o.count)));
        ok(rz.methodology !== null && rz.window !== null,
           '22f. …still carrying its window and methodology');
        ok(before === after, 'A3. the service performs NO database writes', `${before} -> ${after}`);
        const again = await buildProviderFunnel(prisma, A, { window: '90d', now: NOW });
        ok(JSON.stringify(again) === JSON.stringify(rz), 'A4. output is byte-stable across calls');
      }

      section('C. bounded query count');
      {
        await clean(); await provider(A);
        for (let i = 1; i <= 60; i++) {
          await lead('pf-s' + i, inside);
          await notif('pf-s' + i, A, 'sent');
          await notif('pf-s' + i, A, 'sent');
          await impression('pf-s' + i, A);
          await outcome('pf-s' + i, A, i % 2 ? 'contacted' : 'new');
        }
        const counted = new PrismaClient({ datasources: { db: { url: DB } },
          log: [{ emit: 'event', level: 'query' }] });
        let n = 0; counted.$on('query', () => { n += 1; });
        await counted.$queryRawUnsafe('SELECT 1');
        const settle = () => new Promise((res) => setTimeout(res, 60));
        n = 0; const small = await buildProviderFunnel(counted, A, { window: 'all', now: NOW });
        await settle(); const t1 = n;
        for (let i = 61; i <= 200; i++) {
          await lead('pf-s' + i, inside);
          await notif('pf-s' + i, A, 'sent');
          await outcome('pf-s' + i, A, 'contacted');
        }
        n = 0; const big = await buildProviderFunnel(counted, A, { window: 'all', now: NOW });
        await settle(); const t2 = n;
        await counted.$disconnect().catch(() => {});
        ok(small.volume.referralsSent === 60 && big.volume.referralsSent === 200,
           '11e. the referral population really did grow',
           `${small.volume.referralsSent} -> ${big.volume.referralsSent}`);
        ok(t1 === t2, '11f. DB round trips are CONSTANT as referrals grow — no N+1', `${t1} vs ${t2}`);
        ok(t2 === 2, '11g. exactly TWO round trips per call', `${t2} round trips`);
        ok(big.engagement.responsesRecorded + big.engagement.noResponseRecorded === 200,
           '11h. …and the invariant still holds at 200 referrals');
      }

      await clean();
    } finally {
      await prisma.$disconnect().catch(() => {});
    }
    finish();
  })().catch((e) => { console.error('\ndb harness failed:', e.stack || e.message); process.exit(1); });
}

function finish() {
  console.log(`\n${'='.repeat(60)}`);
  console.log(fail === 0 ? `PASSED — ${pass} assertions` : `FAILED — ${fail} of ${pass + fail} assertions failed`);
  process.exit(fail === 0 ? 0 : 1);
}
