'use strict';
/**
 * My Market Phase 1 — CMS hospice service-area overlap.
 *
 * MARKET DEFINITION
 * A hospice provider's market is the set of ZIP codes its resolved CmsFacility
 * serves, exactly as CMS publishes them in CmsFacilityServiceArea.
 *
 * COMPETITOR DEFINITION
 * Another CmsFacility with source = cms_hospice that serves at least one of
 * those ZIPs. The provider's own facility is excluded, and so is every facility
 * from any other CMS source.
 *
 * WHAT THIS IS NOT
 * Overlap is a supply proxy, nothing more. It does not imply referral
 * relationships, patient volume, geographic exclusivity, or quality. It is not
 * derived from mileage, city, county, state, provider-name similarity, Best
 * Hospice coverage radius, Best Hospice lead geography, or any fuzzy match.
 * Nothing here consults Best Hospice subscription or payment status.
 *
 * Identity must resolve first. This module reuses cms-provider-resolver.js
 * rather than reimplementing Provider -> ProviderExternalIdentity -> CmsFacility,
 * so there is exactly one identity path in the codebase and no fuzzy fallback.
 *
 * Provider.internalRole has no effect here, exactly as in the resolver.
 *
 * SNAPSHOT SEMANTICS
 * CmsFacility and CmsFacilityServiceArea are current state, updated in place as
 * CMS republishes. This is therefore the market according to the CURRENT ingested
 * snapshot. No historical reconstruction is attempted and no history table exists.
 *
 * "CURRENT" IS A QUERY, NOT A STORED FLAG
 * Service-area rows are NEVER deleted when a facility stops appearing in CMS;
 * the ingest only advances lastSeenReleaseId for rows present in the new
 * release. A row is therefore current when its lastSeenReleaseId is the latest
 * release for its source, and historical otherwise. Both competitor queries
 * below apply that predicate, so a facility that has left the roster keeps its
 * persisted rows but stops being counted as a current competitor.
 *
 * Without the predicate the market silently overstates itself from the second
 * ingest onward - measured on the two archived hospice releases, 242 facilities
 * left the roster while their service-area rows remained. With a single ingested
 * release the predicate is a no-op, because every row's lastSeenReleaseId IS the
 * latest release, which is exactly why the defect was invisible until now.
 *
 * THE LATEST RELEASE IS DERIVED FROM THE SERVICE-AREA ROWS THEMSELVES - the
 * highest releaseKey among releases actually referenced by a service-area row
 * for this source - NOT from the newest CmsRelease row. A CmsRelease can exist
 * that no current row references: releases are created by the facility importer,
 * but a future history-only backfill could add one, and a quality ingest can lag
 * the roster. Selecting the newest CmsRelease unconditionally would then match no
 * row and zero the market. Deriving it from the rows makes an empty selection
 * impossible by construction. CMS `modified` is never consulted: the two
 * archived releases carried byte-identical zip.csv content while CMS advanced
 * `modified` by about four months.
 *
 * TWO QUESTIONS, ONE ALGORITHM
 * buildProviderCmsMarket(prisma, providerId, { asOfReleaseId }) answers either:
 *
 *   default        - "which CMS facilities CURRENTLY overlap this market?"
 *                    Used by My Market, Quality, Competitors, Competitor detail.
 *   asOfReleaseId  - "which overlapped this market as represented at release R?"
 *                    Used by cms-hospice-roster-changes.js, which calls it once
 *                    per comparison endpoint and unions the two competitor sets.
 *
 * There is deliberately no second market implementation. Both modes run the SAME
 * interval predicate and differ only in which releaseKey they anchor to, so
 * "current" is simply "as of the latest represented release". That equivalence is
 * why a departed facility drops out of the default answer: its interval ends
 * before the current anchor.
 *
 * WHY THE UNION MATTERS. A current-membership set can never contain a facility
 * whose defining property is that it is no longer current, so scoping historical
 * comparison to the current market would make ROSTER_REMOVED permanently
 * invisible. The change engine therefore scopes to
 * union(market as-of previous, market as-of latest).
 *
 * SERVICE-AREA HISTORY IS AN INTERVAL, NOT A SNAPSHOT. CmsFacilityServiceArea
 * stores one contiguous firstSeen/lastSeen interval per (facility, ZIP), so
 * as-of membership is exact only for contiguous presence. A ZIP present at R1,
 * absent at R2 and present again at R3 collapses into a single R1-R3 interval and
 * would be reported as present at R2. That limitation is real and is NOT hidden:
 * faithful per-release ZIP history needs CmsServiceAreaObservation, deliberately
 * deferred because the two archived releases carried byte-identical zip.csv
 * content, so no real release has yet demonstrated the need. Roster-departure
 * visibility does not depend on it - a departed facility's rows retain a
 * lastSeen of the previous release, which is exactly what the union relies on.
 *
 * The provider's OWN service-area rows are deliberately left unfiltered. The
 * `own` CTE must agree with providerZipCount, which the resolver derives without
 * a release predicate; filtering only one of the two would make the provider's
 * own ZIP count disagree with the overlap computed from it. A provider whose own
 * facility has left the roster is already reported through
 * freshness.currentInLatestRelease.
 */
const { resolveProviderCmsContext, CMS_RESOLVER_STATUS } = require('./cms-provider-resolver');

// The only source this phase serves. Kept explicit so a future home-health market
// is an addition, not a loosening.
const MARKET_SOURCE = 'cms_hospice';

const CMS_MARKET_STATUS = Object.freeze({
  ...CMS_RESOLVER_STATUS,
  NO_SERVICE_AREA: 'no_service_area',
  MARKET_UNAVAILABLE: 'market_unavailable',
  /// An `asOfReleaseId` was supplied that does not exist, or belongs to another
  /// source. Fails closed: a caller asking about a release we cannot honour gets
  /// an error, never a silent fall back to the current market, which would be a
  /// different answer to a different question.
  INVALID_AS_OF_RELEASE: 'invalid_as_of_release'
});

// One documented precision for every percentage in this module: 2 decimal places,
// half-up on the scaled integer. Deterministic across platforms.
const pct = (numerator, denominator) =>
  denominator > 0 ? Math.round((numerator / denominator) * 10000) / 100 : 0;
const round2 = (value) => Math.round(value * 100) / 100;

const emptyMarket = (status, resolved, detail) => ({
  status,
  provider: resolved && resolved.provider ? { id: resolved.provider.id, name: resolved.provider.name } : null,
  facility: resolved && resolved.facility
    ? { source: resolved.facility.source, ccn: resolved.facility.ccn, name: resolved.facility.name,
        city: resolved.facility.city, state: resolved.facility.state }
    : null,
  market: null,
  zipDensity: null,
  competitors: null,
  freshness: (resolved && resolved.freshness) || null,
  detail
});

/**
 * @param prisma      a PrismaClient
 * @param providerId  the ONLY authoritative input. Care type, CMS source, CCN,
 *                    facility and service area are all derived from the database.
 */
async function buildProviderCmsMarket(prisma, providerId, options = {}) {
  const asOfReleaseId = options && options.asOfReleaseId != null ? options.asOfReleaseId : null;
  const resolved = await resolveProviderCmsContext(prisma, providerId);

  // Propagate the resolver's own states verbatim rather than collapsing them into
  // one ambiguous failure: "we have not matched you yet" and "your identity is
  // ambiguous" are different things to a human.
  if (resolved.status !== CMS_RESOLVER_STATUS.RESOLVED) {
    return emptyMarket(resolved.status, resolved, resolved.detail);
  }
  if (resolved.facility.source !== MARKET_SOURCE) {
    return emptyMarket(CMS_MARKET_STATUS.MARKET_UNAVAILABLE, resolved,
      `Market overlap is not implemented for source "${resolved.facility.source}".`);
  }

  const ownZips = resolved.serviceArea.zips;
  const providerZipCount = ownZips.length;
  if (providerZipCount === 0) {
    // No service area means no market. Deliberately NOT substituted with the
    // facility's city or state, which would invent a market CMS never published.
    return emptyMarket(CMS_MARKET_STATUS.NO_SERVICE_AREA, resolved,
      'This facility has no CMS service-area ZIP codes in the current snapshot.');
  }

  const source = resolved.facility.source;
  const ccn = resolved.facility.ccn;

  // ---- which release the membership question is asked "as of" -------------
  // Both modes run the SAME interval predicate below; they differ only in which
  // releaseKey they anchor to.
  //
  // DEFAULT (no option): the latest release ACTUALLY REPRESENTED by a
  // service-area row for this source - not the newest CmsRelease row. A
  // CmsRelease can exist that no current row references (a future history-only
  // backfill, or a quality ingest that lags the roster); anchoring to it would
  // match nothing and zero the market. Deriving the anchor from the rows makes an
  // empty anchor impossible whenever any row exists.
  //
  // AS-OF: the caller's release, which must exist AND belong to this source.
  // Both are validated, and a bad value FAILS CLOSED rather than silently
  // falling back to current - a caller asking about a release we cannot honour
  // must get an error, not a different answer to a different question.
  //
  // releaseKey is the ordering key throughout. Release ids are UUIDs and carry no
  // chronology, so they are never compared.
  // The anchor key is NULL in default mode and the aggregate queries derive it
  // inline, so the DEFAULT path costs no extra round trip - the shipped modules'
  // query budgets are unchanged. Only as-of mode pays one validation query, and
  // only as-of mode needs it: that is the single case where a CALLER supplies a
  // release id that might not exist or might belong to another source.
  let asOfReleaseKey = null;
  if (asOfReleaseId != null) {
    const [row] = await prisma.$queryRaw`
      SELECT r."releaseKey" AS release_key
      FROM "CmsRelease" r
      WHERE r.id = ${asOfReleaseId} AND r.source = ${source}
    `;
    if (!row) {
      return emptyMarket(CMS_MARKET_STATUS.INVALID_AS_OF_RELEASE, resolved,
        `No "${source}" CmsRelease exists with id "${asOfReleaseId}".`);
    }
    asOfReleaseKey = row.release_key;
  }

  // ---- overlap, in ONE aggregate query ------------------------------------
  // Raw SQL is used deliberately. The whole computation is a set operation:
  // self-join CmsFacilityServiceArea on zip, group by facility, count. Expressing
  // it in Prisma would mean pulling every matching service-area row into Node and
  // grouping there, or issuing one query per competitor - an N+1 over a table that
  // already holds ~342k rows. @@index([source, zip]) is exactly the index this
  // join wants, and the denormalised source column keeps it a single-table scan.
  //
  // Every value is parameterised through the tagged template. No caller input is
  // interpolated into SQL text.
  const competitorRows = await prisma.$queryRaw`
    WITH anchor AS (
      SELECT COALESCE(
        ${asOfReleaseKey}::text,
        (SELECT r."releaseKey"
         FROM "CmsFacilityServiceArea" sa
         JOIN "CmsRelease" r ON r.id = sa."lastSeenReleaseId" AND r.source = sa.source
         WHERE sa.source = ${source}
         ORDER BY r."releaseKey" DESC
         LIMIT 1)
      ) AS key
    ),
    own AS (
      SELECT f.id AS fid, sa.zip
      FROM "CmsFacility" f
      JOIN "CmsFacilityServiceArea" sa
        ON sa."facilityId" = f.id AND sa.source = f.source
      WHERE f.source = ${source} AND f.ccn = ${ccn}
    ),
    own_facility AS (SELECT DISTINCT fid FROM own),
    shared AS (
      SELECT sa."facilityId" AS fid, sa.zip
      FROM "CmsFacilityServiceArea" sa
      JOIN "CmsRelease" fr ON fr.id = sa."firstSeenReleaseId" AND fr.source = sa.source
      JOIN "CmsRelease" lr ON lr.id = sa."lastSeenReleaseId"  AND lr.source = sa.source
      JOIN own ON own.zip = sa.zip
      WHERE sa.source = ${source}
        AND sa."facilityId" <> (SELECT fid FROM own_facility)
        AND fr."releaseKey" <= (SELECT key FROM anchor)
        AND lr."releaseKey" >= (SELECT key FROM anchor)
    ),
    totals AS (
      SELECT sa."facilityId" AS fid, count(*)::int AS total
      FROM "CmsFacilityServiceArea" sa
      JOIN "CmsRelease" fr ON fr.id = sa."firstSeenReleaseId" AND fr.source = sa.source
      JOIN "CmsRelease" lr ON lr.id = sa."lastSeenReleaseId"  AND lr.source = sa.source
      WHERE sa.source = ${source}
        AND sa."facilityId" IN (SELECT DISTINCT fid FROM shared)
        AND fr."releaseKey" <= (SELECT key FROM anchor)
        AND lr."releaseKey" >= (SELECT key FROM anchor)
      GROUP BY sa."facilityId"
    )
    SELECT f.ccn                                   AS ccn,
           f.name                                  AS name,
           f.city                                  AS city,
           f.state                                 AS state,
           count(*)::int                           AS shared_zip_count,
           array_agg(shared.zip ORDER BY shared.zip) AS shared_zips,
           totals.total                            AS competitor_zip_count
    FROM shared
    JOIN "CmsFacility" f ON f.id = shared.fid AND f.source = ${source}
    JOIN totals ON totals.fid = shared.fid
    GROUP BY f.ccn, f.name, f.city, f.state, totals.total
  `;

  // ---- per-ZIP density, in ONE aggregate query ----------------------------
  const densityRows = await prisma.$queryRaw`
    WITH anchor AS (
      SELECT COALESCE(
        ${asOfReleaseKey}::text,
        (SELECT r."releaseKey"
         FROM "CmsFacilityServiceArea" sa
         JOIN "CmsRelease" r ON r.id = sa."lastSeenReleaseId" AND r.source = sa.source
         WHERE sa.source = ${source}
         ORDER BY r."releaseKey" DESC
         LIMIT 1)
      ) AS key
    ),
    own AS (
      SELECT f.id AS fid, sa.zip
      FROM "CmsFacility" f
      JOIN "CmsFacilityServiceArea" sa
        ON sa."facilityId" = f.id AND sa.source = f.source
      WHERE f.source = ${source} AND f.ccn = ${ccn}
    ),
    own_facility AS (SELECT DISTINCT fid FROM own)
    SELECT own.zip AS zip,
           count(sa."facilityId")::int AS competitor_count
    FROM own
    LEFT JOIN "CmsFacilityServiceArea" sa
      ON sa.zip = own.zip
     AND sa.source = ${source}
     AND sa."facilityId" <> (SELECT fid FROM own_facility)
     AND EXISTS (
       SELECT 1
       FROM "CmsRelease" f2, "CmsRelease" l2
       WHERE f2.id = sa."firstSeenReleaseId" AND f2.source = sa.source
         AND l2.id = sa."lastSeenReleaseId"  AND l2.source = sa.source
         AND f2."releaseKey" <= (SELECT key FROM anchor)
         AND l2."releaseKey" >= (SELECT key FROM anchor))
    GROUP BY own.zip
    ORDER BY own.zip ASC
  `;

  const competitors = competitorRows.map((r) => {
    const sharedZipCount = Number(r.shared_zip_count);
    const competitorZipCount = Number(r.competitor_zip_count);
    return {
      source,
      ccn: r.ccn,
      name: r.name,
      city: r.city,
      state: r.state,
      sharedZipCount,
      providerZipCount,
      competitorZipCount,
      providerOverlapPct: pct(sharedZipCount, providerZipCount),
      competitorOverlapPct: pct(sharedZipCount, competitorZipCount),
      // Already ordered by the array_agg ORDER BY; the schema's
      // @@unique([facilityId, zip]) rules out duplicates, so no dedupe is needed.
      sharedZips: r.shared_zips
    };
  });

  // Deterministic ranking. sharedZipCount is an integer and is the primary
  // signal, so ties are broken before any float comparison decides an order.
  competitors.sort((a, b) =>
    b.sharedZipCount - a.sharedZipCount
    || b.providerOverlapPct - a.providerOverlapPct
    || b.competitorOverlapPct - a.competitorOverlapPct
    || a.name.localeCompare(b.name)
    || a.ccn.localeCompare(b.ccn));

  const zipDensity = densityRows.map((r) => ({ zip: r.zip, competitorCount: Number(r.competitor_count) }));
  const totalSharedZipRelationships = competitors.reduce((n, c) => n + c.sharedZipCount, 0);
  const densitySum = zipDensity.reduce((n, z) => n + z.competitorCount, 0);

  return {
    status: CMS_MARKET_STATUS.RESOLVED,
    provider: { id: resolved.provider.id, name: resolved.provider.name },
    facility: {
      source: resolved.facility.source, ccn: resolved.facility.ccn, name: resolved.facility.name,
      city: resolved.facility.city, state: resolved.facility.state
    },
    market: {
      providerZipCount,
      overlappingFacilityCount: competitors.length,
      totalSharedZipRelationships,
      averageCompetitorsPerProviderZip: round2(densitySum / providerZipCount),
      highestOverlapSharedZipCount: competitors.length ? competitors[0].sharedZipCount : 0
    },
    zipDensity,
    competitors,
    freshness: resolved.freshness,
    detail: null
  };
}

module.exports = { buildProviderCmsMarket, CMS_MARKET_STATUS, MARKET_SOURCE };
