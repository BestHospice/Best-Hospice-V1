#!/usr/bin/env node
/**
 * Guards the durability of POST /api/waitlist/notify.
 *
 * A family reaching the New Territory Outreach form has been told no provider is
 * available near them and is asking Best Hospice to retain their request. The
 * database row is therefore the COMMITMENT, and email is only a notification.
 * This suite exists to keep those two facts from swapping places again.
 *
 * The repo has no HTTP harness, so the real handler is extracted from server.js
 * and executed against injected stubs. That genuinely exercises the ordering and
 * the failure paths - which stubs are the only practical way to reach - rather
 * than pattern-matching the source. With TEST_DATABASE_URL set it additionally
 * runs the handler against the real Prisma client and a real row.
 *
 *   node scripts/test-waitlist-durability.js
 *   TEST_DATABASE_URL=postgresql://user@localhost:5432/bh_competitors_test \
 *     node scripts/test-waitlist-durability.js
 */
const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');

const ROOT = path.join(__dirname, '..');
const SRC = fs.readFileSync(path.join(ROOT, 'server.js'), 'utf8');

let pass = 0, fail = 0;
const ok = (c, label, detail) => {
  console.log(`  ${c ? 'ok  ' : 'FAIL'} ${label}${c || !detail ? '' : `  — ${detail}`}`);
  c ? pass++ : fail++;
};
const section = (t) => console.log(`\n--- ${t} ---`);
const tick = () => new Promise((r) => setTimeout(r, 0));

// ---- extract the real handler ----------------------------------------------
const ROUTE = (SRC.match(/app\.post\('\/api\/waitlist\/notify'[\s\S]*?\n\}\);/) || [''])[0];
if (!ROUTE) { console.error('could not locate the waitlist route'); process.exit(1); }
const BODY = (ROUTE.match(/async \(req, res\) => \{([\s\S]*)\n\}\);$/) || ['', ''])[1];
// Comments stripped before any pattern match, so the suite asserts against the
// handler's behaviour and not against its own explanatory prose.
const CODE = BODY.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '');

const makeHandler = (deps) => new Function(
  'EMAIL_ENABLED', 'ensureWaitlistTable', 'prisma', 'uuid', 'sendGenericEmail', 'console',
  'req', 'res', 'return (async () => {' + BODY + '\n})();')
  .bind(null, deps.EMAIL_ENABLED, deps.ensureWaitlistTable, deps.prisma, deps.uuid,
    deps.sendGenericEmail, deps.console);

const makeRes = () => {
  const r = { _code: 200, _json: undefined, _calls: 0 };
  r.status = (c) => { r._code = c; return r; };
  r.json = (v) => { r._json = v; r._calls += 1; return r; };
  return r;
};

// A stub world where every dependency records what happened to it.
function world(over = {}) {
  const w = {
    created: [], emails: [], logs: [], ensureCalls: 0,
    EMAIL_ENABLED: over.EMAIL_ENABLED === undefined ? true : over.EMAIL_ENABLED,
    uuid: () => 'fixed-uuid-0001'
  };
  w.ensureWaitlistTable = async () => {
    w.ensureCalls += 1;
    if (over.ensureThrows) throw new Error('synthetic ensure failure');
  };
  w.prisma = {
    waitlistRequest: {
      create: async (args) => {
        if (over.createThrows) throw new Error('synthetic database failure');
        w.created.push(args.data);
        return { id: args.data.id };
      }
    }
  };
  w.sendGenericEmail = async (to, subject, html) => {
    w.emails.push({ to, subject, html });
    if (over.emailThrows) throw new Error('synthetic SendGrid failure');
    return { ok: true };
  };
  w.console = {
    error: (...a) => w.logs.push(['error', a.map(String).join(' ')]),
    warn: (...a) => w.logs.push(['warn', a.map(String).join(' ')]),
    log: () => {}
  };
  return w;
}

const BODY_OK = {
  zip: '85001', timeline: 'Within a week',
  contactEmail: 'family@example.test', contactPhone: '555-0100'
};

// ============================ A. STRUCTURE ===================================
section('A. ordering and structure of the handler');
{
  ok(/await prisma\.waitlistRequest\.create\(/.test(CODE),
     '7a. the WaitlistRequest create is AWAITED');
  ok(!/waitlistRequest\.create\([\s\S]*?\)\s*\.then\(/.test(CODE)
     && !/\.then\(\(\) => prisma\.waitlistRequest\.create/.test(CODE),
     '7b. …not chained off a .then()');
  ok(!/ensureWaitlistTable\(\)\s*\n?\s*\.then\(/.test(CODE),
     '7c. …and ensureWaitlistTable is not used as a detached promise chain');
  ok(/await ensureWaitlistTable\(\);/.test(CODE),
     '7d. ensureWaitlistTable is awaited, so a failure fails closed');
  const iCreate = CODE.indexOf('waitlistRequest.create');
  const iEmailGate = CODE.indexOf('EMAIL_ENABLED');
  const iSend = CODE.indexOf('sendGenericEmail');
  const iRes = CODE.indexOf('res.json({ ok: true })');
  const iZip = CODE.indexOf('/^\\d{5}$/');
  ok(iZip >= 0 && iZip < iCreate, '8a. the ZIP is validated before anything is persisted');
  ok(iCreate < iEmailGate, '8b. persistence happens BEFORE the EMAIL_ENABLED check', `${iCreate} < ${iEmailGate}`);
  ok(iCreate < iSend, '8c. persistence happens BEFORE the email is sent');
  ok(iCreate < iRes, '8d. persistence happens BEFORE the success response');
  ok(iRes < iSend, '6a. the consumer is answered before the third-party email round trip');
  ok(/\.catch\(\(err\) => console\.error\(/.test(CODE) && iSend < CODE.lastIndexOf('.catch('),
     '6b. the post-response email has a rejection handler — no unhandled rejection');
  ok(!/await sendGenericEmail/.test(CODE),
     '6c. …and the email is not awaited, so it cannot delay or fail the response');
  ok(!/'unknown'/.test(CODE) && !/"unknown"/.test(CODE),
     '5a. the literal "unknown" ZIP fallback is gone');
  ok(!/match\(\/\\d\{5\}\/\)/.test(CODE),
     '5b. …and the loose "five digits anywhere" extraction is gone');
  ok(!/Cms|cms_hospice|CmsFacility/.test(CODE),
     '14. no Cms* reference anywhere in the waitlist path');
  ok(!/careType|serviceZipCodes|serviceRadiusKm|billingMode|receiveClientLeads|internalRole/.test(CODE),
     '10a. the handler touches no eligibility, coverage or billing field');
  ok(/rateLimit/.test(ROUTE), '10b. the existing rate limiter is still applied');
}

// ============================ B. BEHAVIOUR ===================================
(async () => {
  section('B. valid ZIP, email enabled, email succeeds');
  {
    const w = world();
    const res = makeRes();
    await makeHandler(w)({ body: { ...BODY_OK } }, res);
    await tick();
    ok(w.created.length === 1, '1a. exactly one durable row is created', String(w.created.length));
    ok(res._code === 200 && res._json && res._json.ok === true, '1b. the consumer receives success');
    ok(res._calls === 1, '1c. …exactly once');
    ok(w.emails.length === 1 && w.emails[0].to === 'contact@besthospice.com',
       '1d. the notification email is sent');
    ok(w.emails[0].subject === 'Coverage request for ZIP 85001',
       '1e. …with the ZIP in the subject', w.emails[0].subject);
    ok(w.created[0].zip === '85001', '9a. zip persisted exactly as submitted');
    ok(w.created[0].contactEmail === 'family@example.test', '9b. contactEmail preserved');
    ok(w.created[0].contactPhone === '555-0100', '9c. contactPhone preserved');
    ok(w.created[0].timeline === 'Within a week', '9d. timeline preserved');
    ok(w.created[0].id === 'fixed-uuid-0001', '9e. the id comes from uuid()');
    ok(Object.keys(w.created[0]).sort().join(',') === 'contactEmail,contactPhone,id,timeline,zip',
       '9f. exactly the five intended columns are written', Object.keys(w.created[0]).join(','));
  }

  section('B. valid ZIP, EMAIL_ENABLED = false');
  {
    const w = world({ EMAIL_ENABLED: false });
    const res = makeRes();
    await makeHandler(w)({ body: { ...BODY_OK } }, res);
    await tick();
    ok(w.created.length === 1,
       '2a. the row is STILL created when email is not configured', String(w.created.length));
    ok(res._code === 200 && res._json.ok === true, '2b. the consumer still receives success');
    ok(w.emails.length === 0, '2c. no email is attempted', String(w.emails.length));
    ok(w.logs.some(([lvl, m]) => lvl === 'warn' && /not configured/.test(m)),
       '2d. …and the situation is logged, not silently swallowed',
       JSON.stringify(w.logs));
    ok(res._code !== 500, '8e. email configuration no longer produces a 500');
  }

  section('B. valid ZIP, email provider throws');
  {
    const w = world({ emailThrows: true });
    const res = makeRes();
    await makeHandler(w)({ body: { ...BODY_OK } }, res);
    await tick(); await tick();
    ok(w.created.length === 1, '3a. the durable row remains after an email failure');
    ok(res._code === 200 && res._json.ok === true,
       '3b. the consumer still receives success, because the commitment was recorded');
    ok(w.emails.length === 1, '3c. the email really was attempted');
    ok(w.logs.some(([lvl, m]) => lvl === 'error' && /request is stored/.test(m)),
       '3d. the failure is logged and observable', JSON.stringify(w.logs));
    ok(!/synthetic SendGrid failure/.test(JSON.stringify(res._json)),
       '3e. …and the transport error never reaches the consumer');
  }

  section('B. database persistence failure');
  {
    const w = world({ createThrows: true });
    const res = makeRes();
    await makeHandler(w)({ body: { ...BODY_OK } }, res);
    await tick();
    ok(w.created.length === 0, '4a. no row exists');
    ok(res._code === 500, '4b. an error response is returned', String(res._code));
    ok(!(res._json && res._json.ok === true), '4c. success is NOT claimed', JSON.stringify(res._json));
    ok(w.emails.length === 0, '4d. NO email is attempted — we retained nothing to notify about');
    ok(w.logs.some(([lvl, m]) => lvl === 'error' && /persistence failed/.test(m)),
       '4e. the failure is logged');
    ok(!/synthetic database failure/.test(JSON.stringify(res._json)),
       '4f. the internal error text is not leaked');
  }

  section('B. ensureWaitlistTable failure also fails closed');
  {
    const w = world({ ensureThrows: true });
    const res = makeRes();
    await makeHandler(w)({ body: { ...BODY_OK } }, res);
    await tick();
    ok(res._code === 500 && w.created.length === 0 && w.emails.length === 0,
       '4g. a table-preparation failure returns 500, stores nothing and sends nothing');
  }

  section('B. ZIP validation');
  {
    for (const [label, zip] of [
      ['missing', undefined], ['null', null], ['empty', ''], ['whitespace', '   '],
      ['four digits', '8500'], ['six digits', '850012'],
      ['embedded in text', 'my zip is 85001 ok'], ['ZIP+4', '85001-1234'],
      ['letters', 'ABCDE'], ['unknown', 'unknown'],
      // A JSON NUMBER cannot represent a leading-zero ZIP: 01234 arrives as
      // 1234. It must be rejected rather than stored as a 4-digit value.
      ['numeric with a lost leading zero', 1234],
      ['object', { zip: '85001' }], ['array', ['85001']], ['boolean', true]
    ]) {
      const w = world();
      const res = makeRes();
      await makeHandler(w)({ body: { ...BODY_OK, zip } }, res);
      await tick();
      const isMissing = label === 'missing' || label === 'null' || label === 'empty' || label === 'whitespace';
      ok(res._code === 400 && w.created.length === 0 && w.emails.length === 0,
         `${isMissing ? '6' : '5'}. ${label} ZIP => 400, no row, no email`,
         `code ${res._code}, rows ${w.created.length}, emails ${w.emails.length}`);
    }
    // A trimmable but otherwise exact ZIP is still accepted.
    const w = world();
    const res = makeRes();
    await makeHandler(w)({ body: { ...BODY_OK, zip: '  85001  ' } }, res);
    await tick();
    ok(res._code === 200 && w.created.length === 1 && w.created[0].zip === '85001',
       '5c. surrounding whitespace is trimmed, not rejected', w.created[0] && w.created[0].zip);
    ok(!w.created.some((c) => c.zip === 'unknown'),
       '5d. no row anywhere in this suite was stored with zip "unknown"');
    // A leading-zero ZIP sent as a STRING must survive intact - the common case
    // for the whole US north-east.
    {
      const wz = world(); const rz = makeRes();
      await makeHandler(wz)({ body: { ...BODY_OK, zip: '01234' } }, rz);
      await tick();
      ok(rz._code === 200 && wz.created.length === 1 && wz.created[0].zip === '01234',
         '5f. a leading-zero ZIP string is accepted and preserved exactly',
         wz.created[0] && wz.created[0].zip);
    }
    // A JSON number that is already a full five digits is the same ZIP, so
    // coercing it is correct rather than pedantic.
    {
      const wn = world(); const rn = makeRes();
      await makeHandler(wn)({ body: { ...BODY_OK, zip: 85001 } }, rn);
      await tick();
      ok(rn._code === 200 && wn.created.length === 1 && wn.created[0].zip === '85001'
         && typeof wn.created[0].zip === 'string',
         '5g. a numeric 5-digit ZIP is canonicalised to a string, not rejected',
         wn.created[0] && JSON.stringify(wn.created[0].zip));
    }
  }

  section('B. optional fields default as before');
  {
    const w = world();
    const res = makeRes();
    await makeHandler(w)({ body: { zip: '85001' } }, res);
    await tick();
    ok(res._code === 200 && w.created.length === 1, '9g. only the ZIP is genuinely required');
    ok(w.created[0].timeline === 'Not specified'
       && w.created[0].contactEmail === 'Not provided'
       && w.created[0].contactPhone === 'Not provided',
       '9h. …and the existing placeholder defaults are preserved exactly',
       JSON.stringify(w.created[0]));
  }
  {
    const w = world();
    await makeHandler(w)({}, makeRes()).catch((e) => { w.threw = e; });
    ok(!w.threw, '9i. a completely absent body does not throw');
  }

  section('C. no consumer-routing code was changed');
  {
    let diff = '';
    try {
      diff = execFileSync('git', ['diff', '-U0', 'origin/main', '--', 'server.js'],
        { cwd: ROOT, encoding: 'utf8' });
    } catch (_e) { diff = ''; }
    const changed = diff.split('\n').filter((l) => /^[+-][^+-]/.test(l));
    const FORBIDDEN = ['CONSUMER_LEAD_ELIGIBLE_WHERE', 'providerCoversLocation',
                       'isProviderEligibleForConsumerLead', 'careType', 'billingMode',
                       'receiveClientLeads', 'serviceZipCodes', 'serviceRadiusKm',
                       'internalRole', 'buildProviderCms', 'Cms'];

    // The previous version of this block asserted `changed.length > 0` and then
    // inspected the diff. That only held while this change was UNMERGED: once it
    // landed on origin/main there was no diff left, and the assertion failed for
    // a reason that had nothing to do with routing safety. It also allow-listed
    // the whole tree to `server.js` plus test scripts, so any unrelated feature
    // branch that added a file broke it too.
    //
    // Both were proxies for one invariant: THE WAITLIST ROUTE MUST NOT TOUCH
    // CONSUMER LEAD ROUTING. That is now asserted directly, three ways, none of
    // which depends on this change being unmerged or on what else a branch holds.

    // (1) The load-bearing check: the LIVE waitlist route mentions no routing
    //     identifier. True on any branch, merged or not, forever.
    for (const forbidden of FORBIDDEN) {
      ok(!CODE.includes(forbidden), `10c. the live waitlist route mentions no ${forbidden}`);
    }

    // (2) No file that DECIDES consumer eligibility differs from origin/main. A
    //     deny-list of the deciding files, not an allow-list of the tree: an
    //     allow-list is what made the old assertion brittle.
    const ROUTING_FILES = ['consumer-lead-eligibility.js', 'prisma/schema.prisma',
                           'prisma/migrations', 'cms-hospice-market.js', 'cms-hospice-quality.js',
                           'cms-hospice-competitors.js', 'cms-hospice-competitor-detail.js',
                           'cms-partner-badge.js', 'cms-provider-resolver.js'];
    let routingChanged = [];
    try {
      routingChanged = execFileSync('git',
        ['diff', '--name-only', 'origin/main', '--'].concat(ROUTING_FILES),
        { cwd: ROOT, encoding: 'utf8' }).split('\n').filter(Boolean);
    } catch (_e) { routingChanged = ['<git diff unavailable>']; }
    ok(routingChanged.length === 0,
       '10d. no file that decides consumer eligibility differs from origin/main',
       routingChanged.join(' '));

    // (3) If server.js DOES differ, no changed line may mention a routing
    //     identifier. Skipped honestly when there is no diff, because (1)
    //     already covers the merged state.
    if (changed.length > 0) {
      for (const forbidden of FORBIDDEN) {
        ok(!changed.some((l) => l.includes(forbidden)),
           `10e. no changed server.js line mentions ${forbidden}`);
      }
    } else {
      ok(true, '10e. server.js matches origin/main — this change is merged, so (1) is the check');
    }

    // (4) And the route still does the durable thing this suite exists to guard.
    ok(/await prisma\.waitlistRequest\.create\(/.test(CODE),
       '10f. the live route still persists the request durably');
    const elig = fs.readFileSync(path.join(ROOT, 'consumer-lead-eligibility.js'), 'utf8');
    ok(!/waitlist/i.test(elig), '13a. consumer-lead-eligibility.js has no waitlist coupling');
    const notify = (SRC.match(/app\.post\('\/api\/notify'[\s\S]*?\n\}\);/) || [''])[0];
    ok(notify.length > 500 && !/careType.*(filter|where|in:)/.test(notify),
       '13b. /api/notify candidate selection remains cross-care-type');
    ok(/waitlisted: true, notified: 0/.test(notify),
       '13c. …and its own zero-provider fall-through is unchanged');
  }

  maybeDatabase();
})().catch((e) => { console.error('\nharness failed:', e.stack || e.message); process.exit(1); });

// ============================ D. REAL DATABASE ===============================
function maybeDatabase() {
  const DB = process.env.TEST_DATABASE_URL;
  if (!DB) { console.log('\n--- database test SKIPPED (set TEST_DATABASE_URL) ---'); return finish(); }
  if (/besthospice_db|besthospice_shadow|render\.com|dpg-/i.test(DB)) {
    console.log('  FAIL   TEST_DATABASE_URL looks like production or shadow'); fail++; return finish();
  }
  section('D. the real handler against a real Prisma client and a real row');
  const { PrismaClient } = require('@prisma/client');
  const prisma = new PrismaClient({ datasources: { db: { url: DB } } });
  (async () => {
    try {
      await prisma.$executeRawUnsafe('TRUNCATE TABLE "WaitlistRequest"');
      const emails = [];
      const w = world();
      w.prisma = prisma;
      w.uuid = () => require('crypto').randomUUID();
      w.sendGenericEmail = async (...a) => { emails.push(a); return { ok: true }; };
      const res = makeRes();
      await makeHandler(w)({ body: { zip: '90210', timeline: 'Immediately',
        contactEmail: 'real@example.test', contactPhone: '555-0199' } }, res);
      await tick();
      const rows = await prisma.waitlistRequest.findMany();
      ok(res._json && res._json.ok === true, '1f. the real handler returns success');
      ok(rows.length === 1, '1g. …and the row is genuinely in the database', String(rows.length));
      ok(rows[0].zip === '90210' && rows[0].timeline === 'Immediately'
         && rows[0].contactEmail === 'real@example.test' && rows[0].contactPhone === '555-0199',
         '1h. …with every field persisted exactly', JSON.stringify(rows[0]).slice(0, 120));
      ok(rows[0].createdAt instanceof Date, '1i. …and createdAt defaulted');

      // Email disabled: the row must still land, in the real database.
      await prisma.$executeRawUnsafe('TRUNCATE TABLE "WaitlistRequest"');
      const w2 = world({ EMAIL_ENABLED: false });
      w2.prisma = prisma; w2.uuid = () => require('crypto').randomUUID();
      const res2 = makeRes();
      await makeHandler(w2)({ body: { zip: '10001' } }, res2);
      await tick();
      const rows2 = await prisma.waitlistRequest.findMany();
      ok(res2._json && res2._json.ok === true && rows2.length === 1 && rows2[0].zip === '10001',
         '2e. with email disabled the row still lands in the real database', String(rows2.length));

      // Invalid ZIP writes nothing, for real.
      await prisma.$executeRawUnsafe('TRUNCATE TABLE "WaitlistRequest"');
      const w3 = world(); w3.prisma = prisma; w3.uuid = () => require('crypto').randomUUID();
      const res3 = makeRes();
      await makeHandler(w3)({ body: { zip: 'unknown' } }, res3);
      await tick();
      ok(res3._code === 400 && (await prisma.waitlistRequest.count()) === 0,
         '5e. an invalid ZIP leaves the real table empty');
      await prisma.$executeRawUnsafe('TRUNCATE TABLE "WaitlistRequest"');
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
