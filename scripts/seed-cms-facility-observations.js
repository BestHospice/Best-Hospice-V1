#!/usr/bin/env node
/**
 * One-time baseline seed for CmsFacilityObservation.
 *
 * WHY THIS EXISTS, AND WHY IT IS SAFE TO DERIVE FROM THE DATABASE
 * CmsFacilityObservation is append-only history written by the facility importer
 * from each release's parsed archive. That covers every FUTURE release, but the
 * one release already in the database has no observations, so history would
 * otherwise begin empty and the first release-over-release comparison would need
 * two more ingests.
 *
 * A database-derived seed is exact ONLY while the source has exactly one ingested
 * release. In that state every CmsFacility row necessarily carries
 * firstSeenReleaseId = lastSeenReleaseId = that release, and nothing has
 * overwritten its descriptive columns, so current state IS that release's
 * published state verbatim. This script therefore asserts that precondition and
 * REFUSES if it does not hold - after a second ingest, current state is no longer
 * a faithful snapshot of the baseline release and the archive would be the only
 * honest source.
 *
 * WHAT IT WRITES
 * CmsFacilityObservation rows only. It never writes CmsFacility,
 * CmsFacilityServiceArea, CmsFacilityMeasure, CmsRelease, Provider or
 * ProviderExternalIdentity, and it contains no UPDATE or DELETE against any other
 * table. Verified by scripts/test-cms-facility-observation.js, which greps this
 * source for writes to other tables.
 *
 * DRY RUN IS THE DEFAULT. Without --write nothing is written.
 *
 * TARGET SAFETY. DATABASE_URL is never used implicitly: --database-url is
 * required, so a stale shell env cannot decide the target. Classification and
 * release-scoped authorization reuse cms-ingest-guard.js, the same interlock the
 * two importers use. There is NO generic bypass: no --force, --allow-production,
 * --unsafe or --skip-guard exists here. The shadow database is never permitted.
 * A production seed additionally requires a token scoped to THIS operation and
 * THIS release; an importer token does not authorize it.
 *
 *   node scripts/seed-cms-facility-observations.js \
 *     --database-url postgresql://localhost:5432/bh_dev
 *   node scripts/seed-cms-facility-observations.js \
 *     --database-url postgresql://localhost:5432/bh_dev --write
 *   node scripts/seed-cms-facility-observations.js \
 *     --database-url <url> --print-production-authorization
 */
const path = require('path');
const crypto = require('crypto');
const guard = require(path.join(__dirname, '..', 'cms-ingest-guard.js'));

// Scoped so a facility-ingest or quality-ingest token can never authorize a seed.
const AUTHORIZATION_OPERATION = 'cms-facility-observation-seed';

// The baseline this script exists to seed. Deliberately hardcoded: this is a
// one-time backfill of one known release, not a general-purpose loader. Seeding
// any other release from mutable current state would be unsound.
const EXPECTED_SOURCE = 'cms_hospice';
const EXPECTED_RELEASE_KEY = '2026-08-19';

function fail(msg) {
  console.error('');
  console.error(msg);
  process.exit(1);
}
function usage(msg) {
  if (msg) console.error(`\n${msg}`);
  console.error('\n  node scripts/seed-cms-facility-observations.js --database-url <url> [--write]');
  console.error('  node scripts/seed-cms-facility-observations.js --database-url <url> --print-production-authorization\n');
  process.exit(1);
}

const argv = process.argv.slice(2);
const opts = { write: false, databaseUrl: null, productionAuthorization: null, printAuthorization: false };
const takeValue = (flag, i) => {
  const v = argv[i + 1];
  if (v === undefined) usage(`${flag} requires a value.`);
  if (String(v).startsWith('--')) usage(`${flag} requires a value, but got the flag "${v}".`);
  return v;
};
for (let i = 0; i < argv.length; i++) {
  const a = argv[i];
  if (a === '--write') opts.write = true;
  else if (a === '--database-url') { opts.databaseUrl = takeValue('--database-url', i); i++; }
  else if (a === '--production-authorization') { opts.productionAuthorization = takeValue('--production-authorization', i); i++; }
  else if (a === '--print-production-authorization') opts.printAuthorization = true;
  else usage(`Unknown argument "${a}".`);
}
if (!opts.databaseUrl) {
  usage('--database-url is required. This script never reads DATABASE_URL implicitly, so a\n'
    + 'stale environment variable cannot silently choose the target database.');
}
if (opts.productionAuthorization != null && !guard.AUTHORIZATION_TOKEN_RE.test(opts.productionAuthorization)) {
  usage('--production-authorization must be exactly 64 lowercase hexadecimal characters.');
}
if (opts.printAuthorization && opts.write) {
  usage('--print-production-authorization never writes. Remove --write.');
}
if (opts.printAuthorization && opts.productionAuthorization != null) {
  usage('--print-production-authorization computes a token; it does not consume one.');
}

// ---- target guard, phase 1: PURE, BEFORE ANY CONNECTION --------------------
// classifyTarget needs no database, so the two classes that have NO authorization
// path are refused before a client is ever constructed. A forbidden target must
// not even be connected to, let alone read.
function assertTargetConnectable(url) {
  const target = guard.classifyTarget(url);
  if (target.kind === 'SHADOW') {
    fail('Refusing to connect: --database-url points at the shadow database '
      + `("${target.matched}").\n`
      + '  The shadow database is never a valid target and there is no authorization\n'
      + '  that permits it. No connection was opened. ZERO writes.');
  }
  if (target.kind === 'HOSTED_UNKNOWN') {
    fail('Refusing to connect: --database-url points at an unrecognised hosted/managed\n'
      + '  database. Only a disposable local database, or the one known production\n'
      + '  database with a release-scoped authorization, is a valid target. There is no\n'
      + '  authorization for an unrecognised host. No connection was opened. ZERO writes.');
  }
  return target;
}

// ---- target guard, phase 2: authorization to WRITE -------------------------
// Reached only for NON_PRODUCTION or PRODUCTION. The production token is derived
// from the release's stored manifestSha256, so a read is unavoidable before it can
// be checked; the read is harmless and no write has happened yet.
function assertTargetAllowed(url, action, facts, token) {
  const verb = `Refusing to ${action}`;
  const target = guard.classifyTarget(url);

  if (target.kind === 'PRODUCTION') {
    if (token == null) {
      fail(`${verb}: --database-url points at the production database.\n`
        + '  Production is refused by default. A deliberate one-time OBSERVATION SEED\n'
        + `  requires --production-authorization <64-hex>, scoped to\n`
        + `  operation=${AUTHORIZATION_OPERATION}, source=${facts.dbSource},\n`
        + `  releaseKey=${facts.releaseKey} and that release's exact manifestSha256.\n`
        + '  An importer token does NOT authorize this step. Compute it with:\n'
        + '    node scripts/seed-cms-facility-observations.js --database-url <url> \\\n'
        + '      --print-production-authorization\n'
        + '  Authorization permits the connection only. Writing still requires --write.\n'
        + '  ZERO writes.');
    }
    if (!guard.tokenMatches(token, guard.authorizationToken(facts))) {
      fail(`${verb}: the supplied --production-authorization does not match this release.\n`
        + `  It must be derived from operation=${AUTHORIZATION_OPERATION}, source=${facts.dbSource},\n`
        + `  releaseKey=${facts.releaseKey} and that release's exact manifestSha256. A token\n`
        + '  for any other operation, release, manifest or source is rejected. ZERO writes.');
    }
    console.log('');
    console.log('!'.repeat(72));
    console.log(`!  PRODUCTION TARGET AUTHORIZED for ${facts.dbSource} OBSERVATION SEED ${facts.releaseKey}`);
    console.log('!  Authorization is scoped to this operation and release only.');
    console.log(`!  Mode: ${action === 'write' ? 'WRITE (--write supplied)' : 'READ-ONLY PLANNING (no --write)'}`);
    console.log('!'.repeat(72));
    console.log('');
  }
  return target;
}

(async () => {
  // Refuse forbidden targets BEFORE constructing a client.
  const targetClass = assertTargetConnectable(opts.databaseUrl);

  const { PrismaClient } = require(path.join(__dirname, '..', 'node_modules', '@prisma', 'client'));
  const prisma = new PrismaClient({ datasources: { db: { url: opts.databaseUrl } } });
  const t0 = Date.now();
  try {
    console.log('='.repeat(78));
    console.log(`CmsFacilityObservation baseline seed  (${opts.write ? 'WRITE MODE' : 'DRY RUN — ZERO WRITES'})`);
    console.log('='.repeat(78));
    console.log(`  target class      : ${targetClass.kind}`);
    console.log(`  expected baseline : ${EXPECTED_SOURCE} / ${EXPECTED_RELEASE_KEY}`);

    // ---- precondition 1: the exact baseline release must exist -------------
    const releases = await prisma.cmsRelease.findMany({
      where: { source: EXPECTED_SOURCE },
      orderBy: { releaseKey: 'asc' },
      select: { id: true, releaseKey: true, manifestSha256: true }
    });
    const rel = releases.find((r) => r.releaseKey === EXPECTED_RELEASE_KEY);
    if (!rel) {
      fail(`Refusing to seed: no ${EXPECTED_SOURCE} CmsRelease with releaseKey ${EXPECTED_RELEASE_KEY} exists.\n`
        + `  Found: ${releases.length ? releases.map((r) => r.releaseKey).join(', ') : '(none)'}\n`
        + '  This script seeds exactly one known baseline release. ZERO writes.');
    }

    // ---- precondition 2: EXACTLY ONE release for this source ---------------
    // This is what makes current state a faithful snapshot. With two or more
    // releases the descriptive columns may already have been overwritten, so a
    // DB-derived seed would silently attribute newer values to the older release.
    if (releases.length !== 1) {
      fail(`Refusing to seed: ${EXPECTED_SOURCE} has ${releases.length} ingested releases `
        + `(${releases.map((r) => r.releaseKey).join(', ')}).\n`
        + '  A database-derived baseline is exact ONLY with exactly one ingested release,\n'
        + '  because CmsFacility descriptive columns are overwritten in place on each\n'
        + '  ingest. With more than one release the archive is the only honest source and\n'
        + '  this seed must not be used. ZERO writes.');
    }

    const facts = {
      operation: AUTHORIZATION_OPERATION,
      dbSource: EXPECTED_SOURCE,
      releaseKey: rel.releaseKey,
      manifestSha256: rel.manifestSha256
    };
    if (opts.printAuthorization) {
      console.log('');
      console.log('  Production authorization for THIS operation and release:');
      console.log(`    operation      : ${AUTHORIZATION_OPERATION}`);
      console.log(`    source         : ${facts.dbSource}`);
      console.log(`    releaseKey     : ${facts.releaseKey}`);
      console.log(`    manifestSha256 : ${facts.manifestSha256 == null ? '(null)' : facts.manifestSha256}`);
      console.log(`    token          : ${guard.authorizationToken(facts)}`);
      console.log('');
      console.log('  This token authorizes the CONNECTION only. Writing still requires --write.');
      return;
    }

    assertTargetAllowed(opts.databaseUrl, opts.write ? 'write' : 'plan', facts, opts.productionAuthorization);

    // ---- precondition 3: every facility must belong to the baseline --------
    const total = await prisma.cmsFacility.count({ where: { source: EXPECTED_SOURCE } });
    const carrying = await prisma.cmsFacility.count({
      where: { source: EXPECTED_SOURCE, firstSeenReleaseId: rel.id, lastSeenReleaseId: rel.id }
    });
    if (total !== carrying) {
      fail(`Refusing to seed: ${total - carrying} of ${total} ${EXPECTED_SOURCE} facilities do NOT carry\n`
        + `  firstSeenReleaseId = lastSeenReleaseId = ${rel.releaseKey}.\n`
        + '  That contradicts the single-release baseline assumption, so current state is\n'
        + '  not a faithful snapshot of this release. ZERO writes.');
    }
    if (total === 0) {
      fail(`Refusing to seed: ${EXPECTED_SOURCE} has zero CmsFacility rows. Nothing to baseline. ZERO writes.`);
    }

    const existing = await prisma.cmsFacilityObservation.count({
      where: { source: EXPECTED_SOURCE, releaseId: rel.id }
    });
    const foreign = await prisma.cmsFacilityObservation.count({
      where: { source: EXPECTED_SOURCE, releaseId: { not: rel.id } }
    });

    console.log(`  releases (source) : 1  -> ${rel.releaseKey}  (single-release precondition OK)`);
    console.log(`  facilities        : ${total}  (all carry firstSeen = lastSeen = this release)`);
    console.log(`  observations now  : ${existing} for this release, ${foreign} for other releases`);
    console.log(`  plan              : UPSERT ${total} observations for ${rel.releaseKey}`);
    console.log(`                      (idempotent on (facilityId, releaseId); no other table is written)`);

    if (!opts.write) {
      console.log('\nDRY RUN complete. ZERO writes. Re-run with --write to apply.');
      return;
    }

    // ---- write -------------------------------------------------------------
    // Values are copied verbatim from current state, which precondition 2 and 3
    // prove is this release's published state. No normalisation is applied: the
    // history layer stores facts exactly as CMS published them.
    const rows = await prisma.cmsFacility.findMany({
      where: { source: EXPECTED_SOURCE },
      select: {
        id: true, ccn: true, name: true, address: true, city: true, state: true, zip: true,
        county: true, phone: true, ownershipType: true, certificationDate: true
      }
    });

    let written = 0;
    await prisma.$transaction(async (tx) => {
      for (let i = 0; i < rows.length; i += 500) {
        const chunk = rows.slice(i, i + 500);
        const params = []; const tuples = [];
        chunk.forEach((f) => {
          const b = params.length;
          params.push(crypto.randomUUID(), f.id, EXPECTED_SOURCE, rel.id, f.ccn,
            f.name, f.address, f.city, f.state, f.zip, f.county, f.phone, f.ownershipType,
            f.certificationDate ? f.certificationDate.toISOString().slice(0, 10) : null);
          tuples.push(`($${b + 1},$${b + 2},$${b + 3},$${b + 4},$${b + 5},$${b + 6},$${b + 7},$${b + 8},$${b + 9},$${b + 10},$${b + 11},$${b + 12},$${b + 13},$${b + 14}::date,NOW())`);
        });
        await tx.$executeRawUnsafe(
          `INSERT INTO "CmsFacilityObservation" ("id","facilityId","source","releaseId","ccn","name","address","city","state","zip","county","phone","ownershipType","certificationDate","createdAt")
           VALUES ${tuples.join(',')}
           ON CONFLICT ("facilityId","releaseId") DO UPDATE SET
             "ccn"=EXCLUDED."ccn", "name"=EXCLUDED."name", "address"=EXCLUDED."address",
             "city"=EXCLUDED."city", "state"=EXCLUDED."state", "zip"=EXCLUDED."zip",
             "county"=EXCLUDED."county", "phone"=EXCLUDED."phone",
             "ownershipType"=EXCLUDED."ownershipType",
             "certificationDate"=EXCLUDED."certificationDate"`, ...params);
        written += chunk.length;
      }

      // Postconditions inside the transaction.
      const after = await tx.cmsFacilityObservation.count({ where: { source: EXPECTED_SOURCE, releaseId: rel.id } });
      if (after !== total) {
        throw new Error(`postcondition: ${after} observations for ${rel.releaseKey}, expected ${total}`);
      }
      const mismatched = await tx.$queryRaw`
        SELECT count(*)::int AS n
        FROM "CmsFacilityObservation" o
        JOIN "CmsFacility" f ON f.id = o."facilityId"
        WHERE o."releaseId" = ${rel.id} AND f.source <> o.source`;
      if (Number(mismatched[0].n) !== 0) {
        throw new Error(`postcondition: ${mismatched[0].n} observations disagree with their facility's source`);
      }
    }, { timeout: 600000, maxWait: 60000 });

    const finalCount = await prisma.cmsFacilityObservation.count({ where: { source: EXPECTED_SOURCE, releaseId: rel.id } });
    console.log(`\nSEEDED ${written} observations for ${EXPECTED_SOURCE} / ${rel.releaseKey} `
      + `in one transaction (${((Date.now() - t0) / 1000).toFixed(1)}s).`);
    console.log(`  CmsFacilityObservation for this release: ${finalCount}`);
    console.log('  CmsFacility, CmsFacilityServiceArea, CmsFacilityMeasure: NOT written.');
  } finally {
    await prisma.$disconnect().catch(() => {});
  }
})().catch((e) => {
  console.error('\nFAILED: ' + (e && e.message ? e.message : e));
  process.exit(1);
});
