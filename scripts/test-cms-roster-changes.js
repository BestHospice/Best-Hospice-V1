#!/usr/bin/env node
/**
 * Guards cms-hospice-roster-changes.js — the CMS roster/facility change
 * derivation engine ("What's Changed", Phase 2B).
 *
 * The suite EXECUTES THE REAL MODULE against real rows in a disposable
 * PostgreSQL database. Nothing is stubbed or reimplemented: observations are
 * inserted directly, then buildProviderRosterChanges() is called and its actual
 * output is asserted. The pure normalisation helpers are additionally exercised
 * in isolation, which needs no database.
 *
 * Every CCN, name, address, ZIP and provider id here is SYNTHETIC. No
 * production identifier appears anywhere, and the database phase refuses to run
 * against anything that looks like production.
 *
 * NEGATIVE CONTROLS. Several assertions exist to prove a guard is load-bearing
 * rather than incidentally satisfied: the county suppression, the ownership
 * null handling, the release-selection EXISTS filter and the "no descriptive
 * read from CmsFacility" rule are each shown to change behaviour when the
 * condition they guard is violated.
 *
 *   node scripts/test-cms-roster-changes.js
 *   TEST_DATABASE_URL=postgresql://localhost:5432/bh_obs_test \
 *     node scripts/test-cms-roster-changes.js
 */
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const ROOT = path.join(__dirname, '..');
const MOD = require(path.join(ROOT, 'cms-hospice-roster-changes.js'));
const SRC = fs.readFileSync(path.join(ROOT, 'cms-hospice-roster-changes.js'), 'utf8');
/**
 * The module's own comments DOCUMENT the boundaries it observes, so they name
 * the very things the module must not do ("never reads Lead...", "no fuzzy
 * matching", "nothing consults `modified`"). Grepping raw source would there-
 * fore false-positive on the documentation. These assertions test EXECUTABLE
 * CODE, with comments removed. Provider-facing strings survive the strip and
 * are asserted separately in section C.
 */
const CODE_ONLY = SRC
  .replace(/\/\*[\s\S]*?\*\//g, ' ')      // block comments, incl. the header and all ///
  .replace(/(^|[^:])\/\/[^\n]*/g, '$1');  // line comments; the guard avoids URLs like http://
const {
  buildProviderRosterChanges, CMS_ROSTER_CHANGE_STATUS: S, ROSTER_CHANGE_LABELS,
  COVERAGE_DIRECTION, normText, normState, normZip, normOwnership
} = MOD;

let pass = 0, fail = 0;
const ok = (c, label, detail) => {
  console.log(`  ${c ? 'ok  ' : 'FAIL'} ${label}${c || !detail ? '' : `  — ${detail}`}`);
  c ? pass++ : fail++;
};
const section = (t) => console.log(`\n--- ${t} ---`);
const uuid = () => crypto.randomUUID();

// ======================= STATIC / PURE GUARANTEES ==========================
section('A. status contract');
for (const k of ['OK', 'INSUFFICIENT_HISTORY', 'PROVIDER_NOT_FOUND', 'NO_VERIFIED_IDENTITY',
                 'FACILITY_NOT_FOUND', 'NO_SERVICE_AREA']) {
  ok(typeof S[k] === 'string' && S[k].length > 0, `A1. status enum exposes ${k}`);
}
ok(Object.isFrozen(S), 'A2. status enum is frozen');
ok(S.OK === 'ok' && S.INSUFFICIENT_HISTORY === 'insufficient_history', 'A3. status values follow repo snake_case');
{
  // Inherited upstream statuses must be byte-identical to the resolver's, or a
  // caller mapping one module's status would silently mis-handle another's.
  const { CMS_MARKET_STATUS } = require(path.join(ROOT, 'cms-hospice-market.js'));
  const drift = Object.keys(CMS_MARKET_STATUS).filter((k) => S[k] !== CMS_MARKET_STATUS[k]);
  ok(drift.length === 0, 'A4. every upstream status is inherited verbatim (no drift)', drift.join(','));
}

section('B. no certification event exists');
ok(!/CERTIFICATION_DATE_CHANGED/.test(CODE_ONLY), 'B1. CERTIFICATION_DATE_CHANGED appears nowhere in the code');
ok(!Object.keys(ROSTER_CHANGE_LABELS).some((k) => /certif/i.test(k)),
   'B2. no certification label is exposed');

section('C. banned terminology in provider-facing constants');
{
  const BANNED = ['closed', 'close down', 'went out of business', 'opened', 'acquired',
                  'sold', 'terminated', 'relocated', 'moved', 'lost coverage',
                  'expanded coverage', 'started operating', 'new business'];

  // Event LABELS are the words a provider reads as the finding itself. Not one
  // banned term may appear in them, in any form.
  const labels = JSON.stringify(ROSTER_CHANGE_LABELS);
  for (const word of BANNED) {
    ok(!new RegExp(`\\b${word}\\b`, 'i').test(labels), `C1. "${word}" absent from event labels`);
  }

  // METHODOLOGY is different: its whole job is to DENY the strong readings, so it
  // must be allowed to name one in order to negate it — "has not necessarily
  // closed" is required copy. So every banned term is still refused here EXCEPT
  // where it appears inside an explicit negation, which C1c pins exactly.
  const methodology = JSON.stringify(MOD.METHODOLOGY);
  const NEGATION_ALLOWED = new Set(['closed']);
  for (const word of BANNED.filter((w) => !NEGATION_ALLOWED.has(w))) {
    ok(!new RegExp(`\\b${word}\\b`, 'i').test(methodology),
       `C1b. "${word}" absent from methodology (no negated use is needed)`);
  }
  {
    // Every occurrence of "closed" must be negated. Strip the sanctioned phrase
    // and no bare occurrence may remain.
    const stripped = methodology.replace(/not necessarily closed/gi, '');
    ok(!/\bclosed\b/i.test(stripped),
       'C1c. "closed" appears ONLY inside "not necessarily closed"', stripped.match(/.{0,40}closed.{0,40}/i));
  }
  ok(/not necessarily closed/i.test(MOD.METHODOLOGY.rosterAbsence),
     'C2. methodology states roster absence is not closure');
  ok(/not as a change of ownership/i.test(MOD.METHODOLOGY.ownershipCoverage),
     'C3. methodology states unpublished ownership is not an ownership change');
  ok(/not business events/i.test(MOD.METHODOLOGY.basis),
     'C4. methodology states these are release differences, not business events');
}

section('D. privacy boundary (static)');
for (const forbidden of ['Lead', 'LeadNotification', 'LeadOutcome', 'providerFunnel',
                         'buildProviderFunnel', 'partner', 'billingMode', 'subscriptionStatus',
                         'receiveClientLeads', 'conversion']) {
  ok(!new RegExp(`\\b${forbidden}\\b`).test(CODE_ONLY), `D1. module code never references ${forbidden}`);
}
ok(!/cms-partner-badge/.test(CODE_ONLY), 'D2. module does not require cms-partner-badge');
ok(!/CONSUMER_LEAD|providerCoversLocation|isProviderEligible/.test(CODE_ONLY),
   'D3. module touches no consumer lead eligibility symbol');

section('E. no reimplemented market, no CmsFacility descriptive read');
ok(/require\('\.\/cms-hospice-market'\)/.test(CODE_ONLY), 'E1. reuses cms-hospice-market');
ok(/buildProviderCmsMarket\(prisma, providerId\)/.test(CODE_ONLY), 'E2. calls buildProviderCmsMarket');
ok(!/CmsFacilityServiceArea/.test(CODE_ONLY), 'E3. no second overlap/ZIP query exists in this module');
{
  // The attribute deltas must come from observations only. A descriptive column
  // selected FROM CmsFacility would defeat the whole point of the history table.
  const facilitySelects = CODE_ONLY.match(/FROM\s+"CmsFacility"[^O]/g) || [];
  ok(facilitySelects.length === 0,
     'E4. module never selects FROM "CmsFacility" (only CmsFacilityObservation)',
     JSON.stringify(facilitySelects));
  ok(/FROM "CmsFacilityObservation"/.test(CODE_ONLY), 'E5. reads FROM CmsFacilityObservation');
}
ok(!/modified/.test(CODE_ONLY), 'E6. code never consults CMS `modified` (a bumped date != changed content)');
ok(!/levenshtein|similarity|fuzzy|soundex/i.test(CODE_ONLY), 'E7. no fuzzy matching in code');
ok(!/\bSTREET\b|\bAVENUE\b|\bBOULEVARD\b|\bLLC\b|\bINC\b/.test(CODE_ONLY),
   'E8. no abbreviation expansion or corporate-suffix stripping');

section('F. normalisation helpers (pure)');
ok(normText('  Foo   Bar  ') === 'FOO BAR', 'F1. trims and collapses whitespace, uppercases');
ok(normText('ST. MARY, INC') === 'ST MARY INC', 'F2. removes periods and commas');
ok(normText('') === null && normText(null) === null && normText('.') === null,
   'F3. empty result becomes null');
ok(normText('A B') === normText('a  b.'), 'F4. cosmetic-only differences compare equal');
ok(normText('CHOIICE HOSPICE') !== normText('CHOICE HOSPICE'), 'F5. a real spelling change is NOT suppressed');
ok(normText('HOSPICE LLC') !== normText('HOSPICE INC'),
   'F6. a corporate-form change is NOT suppressed (deliberately conservative)');
ok(normState(' az ') === 'AZ', 'F7. state trims + uppercases');
ok(normZip('85016') === '85016' && normZip(' 85016 ') === '85016', 'F8. zip compares stored value');
ok(normOwnership(null) === null, 'F9. ownership null STAYS null');
ok(normOwnership('') === null && normOwnership('   ') === null, 'F10. ownership empty becomes null');
ok(normOwnership('For-Profit') === normOwnership('FOR-PROFIT'),
   'F11. ownership is case-folded (the ~5,109 false-positive guard)');
ok(normOwnership('For-Profit') !== normOwnership('Non-Profit'), 'F12. a real ownership value change survives');

// ============================ DATABASE PHASE ==============================
const DB = process.env.TEST_DATABASE_URL;
(async () => {
  if (!DB) { console.log('\n--- database tests SKIPPED (set TEST_DATABASE_URL) ---'); return finish(); }
  if (/besthospice_db|dpg-d5hhmb4hg0os7380cecg-a|besthospice-shadow-2|render\.com/i.test(DB)) {
    console.log('  FAIL   TEST_DATABASE_URL looks like production'); fail++; return finish();
  }
  const { PrismaClient } = require('@prisma/client');
  const prisma = new PrismaClient({ datasources: { db: { url: DB } } });

  const SRC_H = 'cms_hospice';
  const OWN = '031500';           // the provider's own facility
  const C1 = '031501', C2 = '031502', C3 = '031503', C4 = '031504';
  const FAR = '031599';           // no shared ZIP — must never appear

  const reset = () => prisma.$executeRawUnsafe(
    'TRUNCATE TABLE "CmsFacilityObservation","CmsFacilityServiceArea","CmsFacilityMeasure",'
    + '"CmsFacility","CmsRelease","ProviderExternalIdentity","Provider" CASCADE');

  const mkRelease = (key) => prisma.cmsRelease.create({
    data: { id: uuid(), source: SRC_H, releaseKey: key,
      capturedAt: new Date(`${key}T00:00:00Z`), datasetCount: 6 } });

  const facIds = new Map();
  const mkFacility = async (ccn, name, zips, rel) => {
    const f = await prisma.cmsFacility.create({ data: { id: uuid(), source: SRC_H, ccn,
      name, address: '1 MAIN ST', city: 'PHOENIX', state: 'AZ', zip: '85016',
      county: 'MARICOPA', phone: '(602) 555-0100', ownershipType: 'For-Profit',
      firstSeenReleaseId: rel.id, lastSeenReleaseId: rel.id } });
    facIds.set(ccn, f.id);
    for (const zip of zips) {
      await prisma.cmsFacilityServiceArea.create({ data: { id: uuid(), facilityId: f.id,
        source: SRC_H, zip, firstSeenReleaseId: rel.id, lastSeenReleaseId: rel.id } });
    }
    return f;
  };

  /** Insert one observation. Only `over` fields deviate from the default record. */
  const mkObs = (ccn, rel, over = {}) => prisma.cmsFacilityObservation.create({
    data: {
      id: uuid(), facilityId: facIds.get(ccn), source: SRC_H, releaseId: rel.id, ccn,
      name: `HOSPICE ${ccn}`, address: '1 MAIN ST', city: 'PHOENIX', state: 'AZ',
      zip: '85016', county: 'MARICOPA', phone: '(602) 555-0100',
      ownershipType: 'For-Profit', ...over
    } });

  const mkProvider = (id, careType = 'hospice') => prisma.provider.create({
    data: { id, name: `Provider ${id}`, email: `${id}@example.test`, address: '1 MAIN ST',
      city: 'PHOENIX', state: 'AZ', zip: '85016', lat: 33.5, lon: -112.0,
      serviceRadiusKm: 40, careType } });
  const mkIdentity = (providerId, ccn) => prisma.providerExternalIdentity.create({
    data: { id: uuid(), providerId, source: SRC_H, externalId: ccn,
      identifierType: 'ccn', verifiedAt: new Date() } });

  /** The standard world: own + 4 competitors sharing ZIPs, 1 far-away facility. */
  const buildWorld = async () => {
    await reset();
    const r1 = await mkRelease('2026-05-01');
    const r2 = await mkRelease('2026-08-19');
    await mkFacility(OWN, 'OWN HOSPICE', ['11111', '11112'], r1);
    await mkFacility(C1, `HOSPICE ${C1}`, ['11111', '11112'], r1);   // 2 shared
    await mkFacility(C2, `HOSPICE ${C2}`, ['11111'], r1);            // 1 shared
    await mkFacility(C3, `HOSPICE ${C3}`, ['11112'], r1);            // 1 shared
    await mkFacility(C4, `HOSPICE ${C4}`, ['11111'], r1);            // 1 shared
    await mkFacility(FAR, 'FAR HOSPICE', ['99999'], r1);             // 0 shared
    await mkProvider('p-1');
    await mkIdentity('p-1', OWN);
    return { r1, r2 };
  };

  try {
    // ---------- G. one release only ----------
    section('G. one observation release → INSUFFICIENT_HISTORY');
    {
      const { r2 } = await buildWorld();
      for (const c of [OWN, C1, C2, C3, C4, FAR]) await mkObs(c, r2);
      const res = await buildProviderRosterChanges(prisma, 'p-1');
      ok(res.status === S.INSUFFICIENT_HISTORY, 'G1. status is insufficient_history', res.status);
      ok(res.releases.releasesAvailable === 1, 'G2. releasesAvailable = 1', String(res.releases.releasesAvailable));
      ok(res.releases.latest && res.releases.latest.releaseKey === '2026-08-19',
         'G3. baseline/latest release metadata is reported');
      ok(res.releases.previous === null, 'G4. previous release is null');
      const arrays = Object.values(res.events);
      ok(arrays.length === 6 && arrays.every((a) => Array.isArray(a) && a.length === 0),
         'G5. every event array is present and EMPTY');
      ok(Object.values(res.summary).every((v) => v === 0),
         'G6. summary is all zero — and no zero is presented as a finding');
      ok(res.methodology && typeof res.methodology.rosterAbsence === 'string',
         'G7. methodology is still returned so the caller can explain the state');
      ok(!('total' in res.summary) && !('totalChanges' in res.summary),
         'G8. no misleading total-changes KPI exists');
    }

    // ---------- H. a release with ZERO observations is skipped ----------
    section('H. release with zero observations is not a comparison endpoint');
    {
      const { r2 } = await buildWorld();
      const r3 = await mkRelease('2026-12-31');       // newest, but NO observations
      for (const c of [OWN, C1, C2, C3, C4, FAR]) await mkObs(c, r2);
      const res = await buildProviderRosterChanges(prisma, 'p-1');
      ok(res.status === S.INSUFFICIENT_HISTORY,
         'H1. an observation-less newer release does not create a comparison', res.status);
      ok(res.releases.latest.releaseKey === '2026-08-19',
         'H2. latest is the newest release WITH observations, not the newest release',
         res.releases.latest.releaseKey);
      // NEGATIVE CONTROL: give r3 observations and the same call must now compare.
      for (const c of [OWN, C1, C2, C3, C4, FAR]) await mkObs(c, r3);
      const res2 = await buildProviderRosterChanges(prisma, 'p-1');
      ok(res2.status === S.OK, 'H3. control: once r3 HAS observations, comparison happens', res2.status);
      ok(res2.releases.latest.releaseKey === '2026-12-31' && res2.releases.previous.releaseKey === '2026-08-19',
         'H4. control: endpoints are the two newest releases WITH observations',
         `${res2.releases.latest.releaseKey} vs ${res2.releases.previous.releaseKey}`);
    }

    // ---------- I. two releases, no changes ----------
    section('I. two releases, nothing changed');
    {
      const { r1, r2 } = await buildWorld();
      for (const c of [OWN, C1, C2, C3, C4, FAR]) { await mkObs(c, r1); await mkObs(c, r2); }
      const res = await buildProviderRosterChanges(prisma, 'p-1');
      ok(res.status === S.OK, 'I1. status ok', res.status);
      ok(res.releases.releasesAvailable === 2, 'I2. releasesAvailable = 2');
      const arrays = Object.values(res.events);
      ok(arrays.every((a) => a.length === 0), 'I3. EVERY event array is empty',
         JSON.stringify(res.summary));
      ok(res.market.overlappingFacilityCount === 4, 'I4. market scoping found the 4 overlapping facilities',
         String(res.market.overlappingFacilityCount));
      ok(res.market.providerZipCount === 2, 'I5. providerZipCount from the market builder');
    }

    // ---------- J. roster added / removed ----------
    section('J. ROSTER_ADDED / ROSTER_REMOVED');
    {
      const { r1, r2 } = await buildWorld();
      for (const c of [OWN, C1, C2, C3, FAR]) await mkObs(c, r1);   // C4 absent in r1
      for (const c of [OWN, C1, C2, C4, FAR]) await mkObs(c, r2);   // C3 absent in r2
      const res = await buildProviderRosterChanges(prisma, 'p-1');
      ok(res.summary.rosterAdded === 1 && res.events.rosterAdded[0].ccn === C4,
         'J1. ROSTER_ADDED: present in latest, absent in previous', JSON.stringify(res.summary));
      ok(res.summary.rosterRemoved === 1 && res.events.rosterRemoved[0].ccn === C3,
         'J2. ROSTER_REMOVED: present in previous, absent in latest');
      ok(res.events.rosterAdded[0].label === ROSTER_CHANGE_LABELS.rosterAdded
         && /Newly present in CMS roster/.test(res.events.rosterAdded[0].label),
         'J3. added carries the defensible label');
      ok(res.events.rosterRemoved[0].label === 'Not present in latest CMS roster',
         'J4. removed carries the defensible label — never "closed"');
      const added = res.events.rosterAdded[0], removed = res.events.rosterRemoved[0];
      ok(added.name && added.city && added.state && added.sharedZipCount === 1,
         'J5. added carries ccn/name/city/state/sharedZipCount', JSON.stringify(added));
      ok(removed.name && removed.city && removed.state && removed.sharedZipCount === 1,
         'J6. removed carries context from its LAST observed release', JSON.stringify(removed));
      ok(!res.events.rosterAdded.some((e) => e.ccn === FAR)
         && !res.events.rosterRemoved.some((e) => e.ccn === FAR),
         'J7. a facility with no shared ZIP never appears');
      ok(!res.events.rosterAdded.some((e) => e.ccn === OWN),
         'J8. the provider\'s own facility is out of scope (market events only)');
    }

    // ---------- K. present → absent → present ----------
    section('K. present R1 → absent R2 → present R3');
    {
      await reset();
      const r1 = await mkRelease('2026-05-01');
      const r2 = await mkRelease('2026-08-19');
      const r3 = await mkRelease('2026-11-30');
      await mkFacility(OWN, 'OWN HOSPICE', ['11111'], r1);
      await mkFacility(C1, `HOSPICE ${C1}`, ['11111'], r1);
      await mkProvider('p-1'); await mkIdentity('p-1', OWN);
      await mkObs(OWN, r1); await mkObs(C1, r1);
      await mkObs(OWN, r2);                       // C1 absent in r2
      await mkObs(OWN, r3); await mkObs(C1, r3);

      const r23 = await buildProviderRosterChanges(prisma, 'p-1');
      ok(r23.releases.latest.releaseKey === '2026-11-30'
         && r23.releases.previous.releaseKey === '2026-08-19',
         'K1. compares the two newest observation releases');
      ok(r23.summary.rosterAdded === 1 && r23.events.rosterAdded[0].ccn === C1,
         'K2. the re-appearance is reported as newly present in R2→R3',
         JSON.stringify(r23.summary));
      ok(r23.summary.rosterRemoved === 0, 'K3. …and not simultaneously reported as removed');
      // The gap itself is representable: 2 observations across 3 releases.
      const n = await prisma.cmsFacilityObservation.count({ where: { ccn: C1 } });
      ok(n === 2, 'K4. the gap is representable — 2 observations across 3 releases', String(n));
    }

    // ---------- L. ownership ----------
    section('L. OWNERSHIP_CHANGED and publication coverage');
    {
      const { r1, r2 } = await buildWorld();
      await mkObs(OWN, r1); await mkObs(OWN, r2);
      // C1: value -> different value  => OWNERSHIP_CHANGED
      await mkObs(C1, r1, { ownershipType: 'For-Profit' });
      await mkObs(C1, r2, { ownershipType: 'Non-Profit' });
      // C2: value -> null  => coverage, NOT a change
      await mkObs(C2, r1, { ownershipType: 'For-Profit' });
      await mkObs(C2, r2, { ownershipType: null });
      // C3: null -> value  => coverage, NOT a change
      await mkObs(C3, r1, { ownershipType: null });
      await mkObs(C3, r2, { ownershipType: 'For-Profit' });
      // C4: null -> null  => no event at all
      await mkObs(C4, r1, { ownershipType: null });
      await mkObs(C4, r2, { ownershipType: null });
      await mkObs(FAR, r1); await mkObs(FAR, r2);

      const res = await buildProviderRosterChanges(prisma, 'p-1');
      ok(res.summary.ownershipChanged === 1, 'L1. exactly ONE ownership change (value→value only)',
         JSON.stringify(res.summary));
      const oc = res.events.ownershipChanged[0];
      ok(oc.ccn === C1 && oc.from === 'For-Profit' && oc.to === 'Non-Profit',
         'L2. raw FROM/TO preserved', JSON.stringify(oc));
      ok(oc.label === 'CMS ownership classification changed',
         'L3. wording is a classification change, never "acquired"/"sold"');
      ok(!res.events.ownershipChanged.some((e) => e.ccn === C2),
         'L4. value→null is NOT an ownership change');
      ok(!res.events.ownershipChanged.some((e) => e.ccn === C3),
         'L5. null→value is NOT an ownership change');
      ok(!res.events.ownershipChanged.some((e) => e.ccn === C4)
         && !res.events.ownershipCoverageChanged.some((e) => e.ccn === C4),
         'L6. null→null produces NO event of any kind');
      const cov = res.events.ownershipCoverageChanged;
      ok(cov.length === 2, 'L7. both coverage transitions reported separately', String(cov.length));
      const unpub = cov.find((e) => e.ccn === C2), pub = cov.find((e) => e.ccn === C3);
      ok(unpub && unpub.direction === COVERAGE_DIRECTION.BECAME_UNPUBLISHED
         && unpub.direction === 'became_unpublished', 'L8. value→null → became_unpublished');
      ok(pub && pub.direction === 'became_published', 'L9. null→value → became_published');
      ok(unpub && /no longer publishes ownership/.test(unpub.label),
         'L10. unpublished wording is about what CMS publishes');
      ok(!('ownershipCoverageChanged' in res.summary),
         'L11. summary EXCLUDES coverage transitions entirely');
      ok(res.summary.ownershipChanged === 1 && cov.length === 2,
         'L12. NEGATIVE CONTROL: folding coverage in would have reported 3, not 1');
      ok(res.methodology.diagnostics.ownershipCoverageChanged === 2,
         'L13. coverage count is available as a diagnostic, not a change');
    }

    // ---------- M. ownership recasing ----------
    section('M. ownership recasing only → no false event');
    {
      const { r1, r2 } = await buildWorld();
      await mkObs(OWN, r1); await mkObs(OWN, r2);
      for (const c of [C1, C2, C3, C4, FAR]) {
        await mkObs(c, r1, { ownershipType: 'For-Profit' });
        await mkObs(c, r2, { ownershipType: 'FOR-PROFIT' });     // wholesale recase
      }
      const res = await buildProviderRosterChanges(prisma, 'p-1');
      ok(res.summary.ownershipChanged === 0,
         'M1. a wholesale ownership recase produces ZERO ownership changes',
         JSON.stringify(res.summary));
      ok(res.events.ownershipCoverageChanged.length === 0, 'M2. …and no coverage events either');
      // NEGATIVE CONTROL: a genuinely different value in the same shape DOES fire.
      await prisma.$executeRawUnsafe(
        `UPDATE "CmsFacilityObservation" SET "ownershipType" = 'GOVERNMENT'
         WHERE ccn = $1 AND "releaseId" = $2`, C1, r2.id);
      const res2 = await buildProviderRosterChanges(prisma, 'p-1');
      ok(res2.summary.ownershipChanged === 1,
         'M3. control: a real value change in the same casing DOES fire', JSON.stringify(res2.summary));
    }

    // ---------- N. name ----------
    section('N. NAME_CHANGED');
    {
      const { r1, r2 } = await buildWorld();
      await mkObs(OWN, r1); await mkObs(OWN, r2);
      await mkObs(C1, r1, { name: 'ADVOCATE HOSPICE' });
      await mkObs(C1, r2, { name: 'COPPER SKY HOSPICE' });          // genuine
      await mkObs(C2, r1, { name: 'SOUTHERNCARE N. BIRMINGHAM' });
      await mkObs(C2, r2, { name: 'SOUTHERNCARE N BIRMINGHAM' });   // punctuation only
      await mkObs(C3, r1, { name: 'AVEANNA  HOSPICE' });
      await mkObs(C3, r2, { name: 'AVEANNA HOSPICE' });             // whitespace only
      await mkObs(C4, r1, { name: 'Mercy Hospice' });
      await mkObs(C4, r2, { name: 'MERCY HOSPICE' });               // case only
      await mkObs(FAR, r1); await mkObs(FAR, r2);
      const res = await buildProviderRosterChanges(prisma, 'p-1');
      ok(res.summary.nameChanged === 1, 'N1. only the genuine rename is reported',
         JSON.stringify(res.events.nameChanged.map((e) => e.ccn)));
      const nc = res.events.nameChanged[0];
      ok(nc.ccn === C1 && nc.from === 'ADVOCATE HOSPICE' && nc.to === 'COPPER SKY HOSPICE',
         'N2. raw FROM/TO preserved', JSON.stringify(nc));
      ok(nc.city === 'PHOENIX' && nc.state === 'AZ', 'N3. city/state context included');
      ok(nc.label === 'CMS-published name changed', 'N4. wording is about what CMS published');
      ok(res.summary.locationChanged === 0, 'N5. a name change alone is not a location change');
    }

    // ---------- O. location ----------
    section('O. LOCATION_CHANGED');
    {
      const { r1, r2 } = await buildWorld();
      await mkObs(OWN, r1); await mkObs(OWN, r2);
      await mkObs(C1, r1, { address: '13416 N 32ND ST' });
      await mkObs(C1, r2, { address: '13416 N 32ND ST, SUITE 105' });   // material
      await mkObs(C2, r1, { address: '4858 E BASELINE RD,' });
      await mkObs(C2, r2, { address: '4858 E BASELINE RD' });           // punctuation only
      await mkObs(C3, r1, { city: 'PHOENIX', zip: '85018' });
      await mkObs(C3, r2, { city: 'GLENDALE', zip: '85302' });          // city + zip
      await mkObs(C4, r1, { state: 'AZ' });
      await mkObs(C4, r2, { state: 'NV' });                             // state
      await mkObs(FAR, r1); await mkObs(FAR, r2);
      const res = await buildProviderRosterChanges(prisma, 'p-1');
      const ccns = res.events.locationChanged.map((e) => e.ccn).sort();
      ok(res.summary.locationChanged === 3, 'O1. three material location changes', JSON.stringify(ccns));
      ok(!ccns.includes(C2), 'O2. punctuation-only address change is suppressed');
      ok(ccns.includes(C1) && ccns.includes(C3) && ccns.includes(C4),
         'O3. suite addition, city+zip, and state each fire');
      const lc = res.events.locationChanged.find((e) => e.ccn === C3);
      ok(lc.from.city === 'PHOENIX' && lc.to.city === 'GLENDALE'
         && lc.from.zip === '85018' && lc.to.zip === '85302',
         'O4. raw FROM/TO location object preserved', JSON.stringify(lc));
      ok(lc.from.address != null && lc.to.state != null,
         'O5. from/to carry address, city, state and zip together');
      ok(lc.label === 'CMS-published address changed',
         'O6. wording is about the published address — never "relocated"');
      ok(!('county' in lc.from) && !('county' in lc.to),
         'O7. county is not part of the location payload');
    }

    // ---------- P. county must never trigger location ----------
    section('P. county recasing/change alone → NO LOCATION_CHANGED (negative control)');
    {
      const { r1, r2 } = await buildWorld();
      await mkObs(OWN, r1); await mkObs(OWN, r2);
      for (const c of [C1, C2, C3, C4, FAR]) {
        await mkObs(c, r1, { county: 'Maricopa' });
        await mkObs(c, r2, { county: 'MARICOPA' });        // the wholesale recase
      }
      const res = await buildProviderRosterChanges(prisma, 'p-1');
      ok(res.summary.locationChanged === 0,
         'P1. a wholesale county recase produces ZERO location changes',
         JSON.stringify(res.summary));
      ok(res.methodology.diagnostics.countyOnlyDifferences === 0,
         'P2. a pure recase is not even counted as a county difference (normalised equal)',
         String(res.methodology.diagnostics.countyOnlyDifferences));

      // A DIFFERENT county, address unchanged: still not a location change,
      // but it IS visible as a diagnostic so the suppression stays auditable.
      const { r1: s1, r2: s2 } = await buildWorld();
      await mkObs(OWN, s1); await mkObs(OWN, s2);
      for (const c of [C1, C2, C3, C4, FAR]) {
        await mkObs(c, s1, { county: 'MARICOPA' });
        await mkObs(c, s2, { county: 'PIMA' });
      }
      const res2 = await buildProviderRosterChanges(prisma, 'p-1');
      ok(res2.summary.locationChanged === 0,
         'P3. a genuinely different county with an unchanged address is still NOT a location change',
         JSON.stringify(res2.summary));
      ok(res2.methodology.diagnostics.countyOnlyDifferences === 4,
         'P4. …and is surfaced as a diagnostic for the 4 in-market facilities',
         String(res2.methodology.diagnostics.countyOnlyDifferences));
      ok(res2.events.locationChanged.length === 0 && res2.events.nameChanged.length === 0,
         'P5. no other event is manufactured by a county difference');
    }

    // ---------- Q. determinism + raw preservation ----------
    section('Q. deterministic ordering');
    {
      const { r1, r2 } = await buildWorld();
      await mkObs(OWN, r1); await mkObs(OWN, r2);
      // C1 has 2 shared ZIPs; C2/C3/C4 have 1 each. All four get a name change.
      for (const c of [C1, C2, C3, C4]) {
        await mkObs(c, r1, { name: `OLD ${c}` });
        await mkObs(c, r2, { name: `NEW ${c}` });
      }
      await mkObs(FAR, r1); await mkObs(FAR, r2);
      const a = await buildProviderRosterChanges(prisma, 'p-1');
      const b = await buildProviderRosterChanges(prisma, 'p-1');
      ok(JSON.stringify(a.events) === JSON.stringify(b.events),
         'Q1. two identical calls return byte-identical event arrays');
      const order = a.events.nameChanged.map((e) => e.ccn);
      ok(order[0] === C1, 'Q2. highest sharedZipCount first', order.join(','));
      ok(JSON.stringify(order.slice(1)) === JSON.stringify([C2, C3, C4].sort()),
         'Q3. ties broken by CCN ascending — no two entries can compare equal', order.join(','));
    }

    // ---------- R. fails closed ----------
    section('R. identity failures fail closed');
    {
      await buildWorld();
      const res = await buildProviderRosterChanges(prisma, 'does-not-exist');
      ok(res.status === S.PROVIDER_NOT_FOUND, 'R1. unknown provider → provider_not_found', res.status);
      ok(Object.values(res.events).every((a) => a.length === 0), 'R2. …with empty event arrays');
    }
    {
      const { r2 } = await buildWorld();
      await mkProvider('p-noid');                      // no ProviderExternalIdentity
      const res = await buildProviderRosterChanges(prisma, 'p-noid');
      ok(res.status === S.NO_VERIFIED_IDENTITY, 'R3. no verified CMS identity → fails closed', res.status);
      ok(Object.values(res.events).every((a) => a.length === 0), 'R4. …with empty event arrays');
      ok(res.summary.rosterAdded === 0, 'R5. …and no fabricated findings');
    }
    {
      await reset();
      const r1 = await mkRelease('2026-05-01');
      await mkFacility(OWN, 'OWN', [], r1);            // no service area
      await mkProvider('p-nozip'); await mkIdentity('p-nozip', OWN);
      const res = await buildProviderRosterChanges(prisma, 'p-nozip');
      ok(res.status === S.NO_SERVICE_AREA, 'R6. no CMS service area → no_service_area', res.status);
    }

    // ---------- S. output surface carries no private data ----------
    section('S. output surface (runtime)');
    {
      const { r1, r2 } = await buildWorld();
      for (const c of [OWN, C1, C2, C3, C4, FAR]) { await mkObs(c, r1); await mkObs(c, r2); }
      await mkObs(C1, r2, {}).catch(() => {});          // idempotent duplicate is rejected; ignore
      const res = await buildProviderRosterChanges(prisma, 'p-1');
      const allKeys = (v, out = new Set()) => {
        if (Array.isArray(v)) v.forEach((x) => allKeys(x, out));
        else if (v && typeof v === 'object') for (const k of Object.keys(v)) { out.add(k); allKeys(v[k], out); }
        return out;
      };
      const keys = [...allKeys(res)];
      for (const forbidden of ['leadId', 'leadCount', 'conversion', 'conversionRatePct', 'admitted',
                               'partner', 'isPartner', 'billingMode', 'subscriptionStatus',
                               'receiveClientLeads', 'referralsSent', 'timesMatched',
                               'certificationDate']) {
        ok(!keys.includes(forbidden), `S1. response exposes no "${forbidden}" key`);
      }
      const blob = JSON.stringify(res);
      ok(!/certificationDate/.test(blob), 'S2. certificationDate appears nowhere in the response');
      ok(res.detail === null, 'S3. detail is null on success');
      ok(typeof res.releases.latest.capturedAt !== 'undefined'
         && typeof res.releases.latest.ingestedAt !== 'undefined',
         'S4. release metadata carries capturedAt + ingestedAt');
    }

    await reset();
  } catch (e) {
    console.log('  FAIL   database phase threw: ' + (e && e.stack ? e.stack.split('\n').slice(0, 3).join(' | ') : e));
    fail++;
  } finally {
    await prisma.$disconnect();
  }
  finish();
})();

function finish() {
  console.log(`\n${fail ? 'FAILED' : 'PASSED'} — ${pass} passed, ${fail} failed`);
  process.exit(fail ? 1 : 0);
}
